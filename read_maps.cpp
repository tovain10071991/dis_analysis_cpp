#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>
#include <gelf.h>
#include <fcntl.h>
#include <udis86.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/wait.h>

#include <fstream>
#include <iomanip>
#include <iostream>

#include "mnemonic.h"
#include "sec_index.h"

using namespace std;

/*******************************************************
 * 类型定义
 *******************************************************/
typedef Elf32_Addr UINT_T;
typedef unsigned int UINT_T;
typedef unsigned short USHORT_T;
typedef Elf32_Half USHORT_T;

typedef struct loc_info {
	UINT_T addr;
	UINT_T offset;
	UINT_T size;
} loc_info;

/*******************************************************
 * 宏定义
 *******************************************************/
#define is_branch(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Icall || ud_insn_mnemonic(ud_obj)==UD_Iiretw || ud_insn_mnemonic(ud_obj)==UD_Iiretd || ud_insn_mnemonic(ud_obj)==UD_Iiretq || (ud_insn_mnemonic(ud_obj)>=UD_Ijo && ud_insn_mnemonic(ud_obj)<=UD_Ijmp) || ud_insn_mnemonic(ud_obj)==UD_Iret || ud_insn_mnemonic(ud_obj)==UD_Iretf)

#define SET_SEC_INFO(name) \
	if(!strcmp(sec_name+1, #name)){ \
		sec_info[name].addr = shdr.sh_addr; \
		sec_info[name].offset = shdr.sh_offset; \
		sec_info[name].size = shdr.sh_size; \
		continue; \
	}

/*******************************************************
 * 全局变量
 *******************************************************/
loc_info sec_info[index_max];

UINT_T breakpoint;		//断点地址
UINT_T diff;			//代码地址与文件偏移的差值
struct user_regs_struct regs;
//用于libelf的变量
int input;
Elf* elf;
GElf_Ehdr ehdr;
GElf_Phdr phdr;
GElf_Shdr shdr;
Elf_Scn* scn;
size_t shdrstrndx;		//节名符号表索引
GElf_Shdr shdrstr;		//节名符号表头项
//用于liibudis的变量
UINT_T* ud_buf;
ud_t ud_obj;
const ud_operand_t* ud_opr;
//输出文件
ofstream fdis;
ofstream fsec_info;


/*******************************************************
 * get_sec_info()
 *******************************************************/
void get_sec_info()
{
	sec_info[entry].addr = ehdr.e_entry;

	int i;
	for(i=0;i<ehdr.e_phnum;i++)
	{
		gelf_getphdr(elf, i, &phdr);
		if(sec_info[entry].addr>=phdr.p_vaddr&&sec_info[entry].addr<=phdr.p_vaddr+phdr.p_memsz)
			break;
	}
	//定位包含代码的segment
	sec_info[entry].offset = sec_info[entry].addr-(phdr.p_vaddr-phdr.p_offset);	

	//初始化各种偏移和地址
	//初始化shdrstrndx
	elf_getshdrstrndx(elf, &shdrstrndx);
	//初始化shdrstr
	Elf_Scn* shdrstrscn = elf_getscn(elf, shdrstrndx);
	gelf_getshdr(shdrstrscn, &shdrstr);
	//找到各种表并初始化地址
	scn=NULL;
	while((scn=elf_nextscn(elf, scn))!=NULL)
	{
		gelf_getshdr(scn, &shdr);
		char* sec_name;
		sec_name = elf_strptr(elf, shdrstrndx, shdr.sh_name);
		SET_SEC_INFO(dynsym)
		SET_SEC_INFO(init)
		SET_SEC_INFO(plt)
		SET_SEC_INFO(text)
		SET_SEC_INFO(fini)
		SET_SEC_INFO(got)
		SET_SEC_INFO(data)
		if(!strcmp(sec_name+1, "got.plt")){
			sec_info[got_plt].addr = shdr.sh_addr;
			sec_info[got_plt].offset = shdr.sh_offset;
			sec_info[got_plt].size = shdr.sh_size;
			continue;
		}
	}
	for(int i=0;i<index_max;i++)
		fsec_info << sec_info[i].addr << "\t" << sec_info[i].offset << "\t" << sec_info[i].size << endl;
	return;
}

/*******************************************************
 * set_break_recover()
 *******************************************************/
void set_break_recover(int pid, UINT_T addr)
{
	//设置断点
	//将addr的头一个字节(第一个字的低字节)换成0xCC
	breakpoint=ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
	UINT_T temp = breakpoint & 0xFFFFFF00 | 0xCC;
	ptrace(PTRACE_POKETEXT, pid, addr, temp);

	//执行子进程
	ptrace(PTRACE_CONT, pid, 0, 0);
	wait(NULL);
	printf("meet breakpoint: ");

	//恢复断点
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	//软件断点会在断点的下一个字节停住,所以还要将EIP向前恢复一个字节
	regs.eip-=1;
	printf("0x%lx\n", regs.eip);
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	ptrace(PTRACE_POKETEXT, pid, regs.eip, breakpoint);
}

/*******************************************************
 * set_buf()
 *******************************************************/
inline void set_buf(int pid, UINT_T addr)
{
	int i;
	for(i=0;i<5;i++)
		ud_buf[i]=ptrace(PTRACE_PEEKTEXT, pid, addr+i*sizeof(UINT_T), 0);
	ud_set_input_buffer(&ud_obj, (uint8_t*)ud_buf, 5*sizeof(UINT_T));
	ud_set_pc(&ud_obj, addr);
}

/*******************************************************
 * plt_handler()
 *******************************************************/
UINT_T plt_handler(int pid, UINT_T addr)
{
	//反汇编得到目标地址所在的.got.plt表中偏移
	int i;
	for(i=0;i<6;i++)
		ud_buf[i]=ptrace(PTRACE_PEEKTEXT, pid, addr+i*sizeof(UINT_T), 0);
	ud_set_input_buffer(&ud_obj, (uint8_t*)ud_buf, 6);
	ud_set_pc(&ud_obj, addr);
	ud_disassemble(&ud_obj);
	fdis << "0x" << setiosflags(ios::left)<< setw(8) << ud_insn_off(&ud_obj) << "\t"
		   << setw(8) << ud_insn_hex(&ud_obj) << "\t"
		   << setw(20) << mnemonic_name[ud_insn_mnemonic(&ud_obj)] << "\t"
		   << setw(20) << ud_insn_asm(&ud_obj) << endl;

	ud_opr = ud_insn_opr(&ud_obj, 0);

	printf("got_plt: %x\n",sec_info[got_plt].addr);

	UINT_T org;
	org = ptrace(PTRACE_PEEKDATA, pid, ud_opr->lval.sdword, 0);
	printf("org: %x\n", org);
	UINT_T real;
	while(1){
		ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
		real = ptrace(PTRACE_PEEKTEXT, pid, ud_opr->lval.sdword, 0);
		if(real!=0xffffffff&&real!=org)
		{
			printf("real: %x\n", real);
			break;
		}
	}
	return real;
}

/*******************************************************
 * direct_branch_handler()
 *******************************************************/
UINT_T direct_branch_handler(int pid)
{
	//判断地址是不是.plt段
	UINT_T target = ud_insn_off(&ud_obj)+ud_insn_len(&ud_obj)+ud_opr->lval.sdword;
	if(target>=sec_info[plt].addr&&target<=sec_info[plt].addr+sec_info[plt].size)
		return plt_handler(pid, target);
	else
		return target;
}

inline void par_process(int pid)
{
	wait(NULL);

	//设置文件描述符
	input = open("/bin/ls", O_RDONLY, 0);
	fdis.open("ls.dis");
	fsec_info.open("sec.info");
	fdis << hex;
	fsec_info << hex;
	cout << hex;
	
	//初始化libelf
	elf_version(EV_CURRENT);
	elf = elf_begin(input, ELF_C_READ, NULL);
	gelf_getehdr(elf, &ehdr);

	//读取各种地址
	get_sec_info();

	//跳过前面ld的初始化,直到主模块入口q
	set_break_recover(pid, sec_info[entry].addr);

	//初始化libudis
	ud_buf = (UINT_T*)malloc(5*sizeof(UINT_T));
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_ATT);

	//读和设置缓冲
	set_buf(pid, sec_info[entry].addr);

	UINT_T old_addr=0;
	UINT_T old_size=0;
	while (ud_disassemble(&ud_obj))
	{
		if(ud_insn_mnemonic(&ud_obj)==UD_Iinvalid)
		{
			set_buf(pid, old_addr+old_size);
			continue;
		}
		fdis << "0x" << setiosflags(ios::left)<< setw(8) << ud_insn_off(&ud_obj) << "\t"
			   << setw(8) << ud_insn_hex(&ud_obj) << "\t"
			   << setw(20) << mnemonic_name[ud_insn_mnemonic(&ud_obj)] << "\t"
			   << setw(20) << ud_insn_asm(&ud_obj) << endl;
		if(is_branch(&ud_obj))
		{
			if(ud_insn_mnemonic(&ud_obj)==UD_Iret)
			{
				exit(-1);
			}
			//判断是直接还是间接分支
			ud_opr = ud_insn_opr(&ud_obj, 0);
			if(ud_opr->type==UD_OP_JIMM)
			{

				UINT_T addr = direct_branch_handler(pid);
				cout << "target addr: 0x" << addr << endl;
				set_buf(pid, addr);
				continue;
			}
			else
			{
				exit(-1);
			}
		}
		old_addr = ud_insn_off(&ud_obj);
		old_size = ud_insn_len(&ud_obj);
	}

	//反汇编到分支指令,在这里设置断点
	set_break_recover(pid, ud_insn_off(&ud_obj));

}


/*******************************************************
 * main()
 *******************************************************/
int main()
{
	int pid;

	//fork进程
	if((pid=fork())==0)
	{
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execl("/bin/ls", "ls", NULL);
	}
	else
	{
		//父进程的工作
		par_process(pid);
	}
	return 0;
}

