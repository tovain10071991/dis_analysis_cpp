#include "dbg.h"
#include <sys/ptrace.h> 
#include <sys/wait.h>
#include <cstring>		//memcpy
#include <stdlib.h>
#include <iomanip>
#include "mnem.h"
#include <iostream>
#include <vector>
#include <err.h>
#include <errno.h>
#include "skycer.h"
#include <cstring>

using namespace std;
using namespace skyin;

/*******************************************************
 * Debugger::Debugger() - Debugger对象的构造函数,初始化libudis86,执行跳过ld直到进程主模块入口,初始化模块信息,初始化污点信息
 * process - 被跟踪进程的Process对象
 *******************************************************/
Debugger::Debugger(Process* process):
		process(process),
		traceEnd(0)
{
	process->debugger = this;
	//初始化libudis
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_ATT);
	//初始化xed
	xed_state_zero(&xedState);
	xed_state_init2(&xedState, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
	xed_tables_init();
	contBreak(process->modules[0]->ehdr.e_entry);
	process->initModules();
	taint = new Taint();
	getArgv();
	//首先读入第一个trace
	readTrace();
	readTrace2();
}

/*******************************************************
 * Debugger::readData() - 读进程空间数据,保存到data指向的缓冲区中
 * addr - 读数据的基址
 * size - 读数据的字节数
 * data - 指向待保存数据的缓冲区
 * 返回值 - 成功返回true
 *******************************************************/
bool Debugger::readData(UINT_T addr, size_t size, void* data)
{
	int status;
	UINT_T ret;
	size_t ts = (size+4)/4;
	UINT_T* tmp = (UINT_T*)malloc(ts*4);
	if(tmp==NULL)
		errx(-1, "malloc: fail to allocate tmp in readata()\n");
	for(UINT_T i=0;i<ts;i++)
	{
		PTRACEASSERT(PTRACE_PEEKDATA, process->pid, addr+4*i, 0, "read to tmp", "readData");
		*(tmp+i) = ret;
	}
	memcpy(data, tmp, size);
	free(tmp);
	return true;
}

/*******************************************************
 * Debugger::readTrace() - 读一个trace,以分支指令结尾,跟新寄存器上下文信息和读写内存记录,更新污点信息
 * 返回值 - 读取成功返回true,执行结束返回false
 *******************************************************/
bool Debugger::readTrace()
{
	size_t traceSize = TRACEMIN;
	void* tmpTrace = malloc(TRACEMIN);
	if(tmpTrace==NULL)
		errx(-1, "malloc: fail to allocate tmpTrace in readTrace()");
	readData(process->regs.eip, TRACEMIN, tmpTrace);
	ud_set_input_buffer(&ud_obj, (uint8_t*)tmpTrace, TRACEMIN);
	ud_set_pc(&ud_obj, process->regs.eip);
	trace  = realloc(trace, traceSize);
	memcpy(trace, tmpTrace, traceSize);
	UINT_T oldAddr=0;
	UINT_T oldSize=0;
	while (1)
	{
		if(!ud_disassemble(&ud_obj)||ud_insn_mnemonic(&ud_obj)==UD_Iinvalid)
		{
			if(oldAddr==0)
			{
				printf("Maybe have finished\n");
				return false;
			}
			readData(oldAddr+oldSize, TRACEMIN, tmpTrace);
			ud_set_input_buffer(&ud_obj, (uint8_t*)tmpTrace, TRACEMIN);
			ud_set_pc(&ud_obj, oldAddr+oldSize);
			traceSize += TRACEMIN;
			trace= realloc(trace, traceSize);
			memcpy((void*)((UINT_T)trace+traceSize-TRACEMIN), tmpTrace, TRACEMIN);
			continue;
		}
		fdis << "0x" << setiosflags(ios::left)<< setw(8) << (UINT_T)ud_insn_off(&ud_obj) << "\t"
			 << setw(22) << ud_insn_hex(&ud_obj) << "\t"
			 << setw(10) << ud_lookup_mnemonic(ud_insn_mnemonic(&ud_obj)) << "\t"
			 << ud_insn_asm(&ud_obj) << endl;
		//根据每条指令的内存/寄存器读写更新污点信息

		if(isBranch(&ud_obj))
		{
			traceEnd = ud_insn_off(&ud_obj);
			free(tmpTrace);
			return true;
		}
		oldAddr = ud_insn_off(&ud_obj);
		oldSize = ud_insn_len(&ud_obj);
	}
}

/*******************************************************
 * Debugger::readTrace() - 读一个trace,以分支指令结尾,跟新寄存器上下文信息和读写内存记录,更新污点信息
 * 返回值 - 读取成功返回true,执行结束返回false
 *******************************************************/
bool Debugger::readTrace2()
{
	UINT_T lenSum = 0;
	int insLen = 15;
	size_t traceSize = TRACEMIN;
	void* tmpTrace = malloc(TRACEMIN);
	char decoded_buf[50] = "";
	UINT_T addr = process->regs.eip;
	xed_decoded_inst_t decodedInst;
	xed_decoded_inst_zero_set_mode(&decodedInst, &xedState);
	readData(addr, TRACEMIN, tmpTrace);
	trace = realloc(trace, traceSize);
	memcpy(trace, tmpTrace, traceSize);
	while(1)
	{
		insLen = traceSize-lenSum>=15?15:traceSize-lenSum;
		xed_decoded_inst_zero_keep_mode(&decodedInst);
		xed_decode(&decodedInst, (xed_uint8_t*)((UINT_T)trace+lenSum), insLen);
		if(!(xed_decoded_inst_valid(&decodedInst)))
		{
			readData(addr, TRACEMIN, tmpTrace);
			traceSize = lenSum+TRACEMIN;
			trace = realloc(trace, traceSize);
			memcpy((void*)((UINT_T)trace+lenSum), tmpTrace, TRACEMIN);
			continue;
		}
		xed_format_context(XED_SYNTAX_ATT, &decodedInst, decoded_buf, 49, addr, 0, 0);
		fdis2 << "0x" << addr << "\t" << decoded_buf << endl;
		xed_category_enum_t cate = xed_decoded_inst_get_category(&decodedInst);
		if(cate==XED_CATEGORY_COND_BR||cate==XED_CATEGORY_CALL||cate==XED_CATEGORY_RET||cate==XED_CATEGORY_SYSCALL||cate==XED_CATEGORY_SYSRET||cate==XED_CATEGORY_UNCOND_BR)
			break;
		lenSum += xed_decoded_inst_get_length(&decodedInst);
		addr += xed_decoded_inst_get_length(&decodedInst);
	}
	return true;
}

/*******************************************************
 * Debugger::updateTrace() - 执行上一个trace,读取下一个trace
 * 返回值 - 读取成功返回true
 *******************************************************/
bool Debugger::updateTrace()
{
	if(!contBreak(traceEnd))
		return false;

	singleStep();
	readTrace2();
	return readTrace();
}

/*******************************************************
 * Debugger::contBreak() - 执行到addr
 * addr - 断点地址
 * 返回值 - 执行成功返回true
 *******************************************************/
bool Debugger::contBreak(UINT_T addr)
{
	int status;
	UINT_T ret;
	UINT_T dr0, dr6, dr7;
	dr0 = addr;
	PTRACEASSERT(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), 0, "read to var dr7", "contBreak");
	dr7 = ret|0x01;
	PTRACEASSERT(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7, "write to reg dr7", "contBreak");
	PTRACEASSERT(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[0]), dr0, "write to reg dr0", "contBreak");
	do {
		PTRACEASSERT(PTRACE_CONT, process->pid, 0, 0, "continue tracee", "contBreak");
		WAITASSERT("contBreak");
		PTRACEASSERT(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[6]), 0, "read to var dr6", "contBreak");
		dr6 = ret;
	} while(!(dr6&0x1));
	PTRACEASSERT(PTRACE_GETREGS, process->pid, NULL, &process->regs, "get regs", "contBreak");
	fdebugger << "meet breakpoint: 0x" << process->regs.eip << endl;
	PTRACEASSERT(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), 0, "read to var dr7", "contBreak");
	dr7 = ret&0xfffffffe;
	PTRACEASSERT(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7, "write to reg dr7", "contBreak");
	return true;
}

/*******************************************************
 * Debugger::singleStep() - 单步执行
 * 返回值 - 执行成功返回true
 *******************************************************/
bool Debugger::singleStep()
{
	int status;
	UINT_T ret;
	UINT_T eip;
	PTRACEASSERT(PTRACE_SINGLESTEP, process->pid, 0, 0, "single step", "singleStep");
	WAITASSERT("singleStep");
	PTRACEASSERT(PTRACE_PEEKUSER, process->pid, offsetof(struct user_regs_struct, eip), 0, "read to var eip", "singleStep");
	eip = ret;
	//如果指令在.plt段,就跳过
	for(vector<Process::Module*>::iterator iter=process->modules.begin();iter!=process->modules.end();++iter)
	{
		if(eip>=(*iter)->pltAddr && eip<=(*iter)->pltAddr+(*iter)->pltSize)
		{
			//反汇编得到目标地址所在的.got.plt表中偏移
			void* pltIns = malloc(6);

			if(pltIns==NULL)
				errx(-1, "malloc: fail to allocate pltIns\n");
			readData(eip, 6, pltIns);
			ud_set_input_buffer(&ud_obj, (uint8_t*)pltIns, 6);
			ud_set_pc(&ud_obj, eip);
			ud_disassemble(&ud_obj);

			fdis << "0x" << setiosflags(ios::left)<< setw(8) << ud_insn_off(&ud_obj) << "\t"
				 << setw(22) << ud_insn_hex(&ud_obj) << "\t"
				 << setw(10) << ud_lookup_mnemonic(ud_insn_mnemonic(&ud_obj)) << "\t"
				 << ud_insn_asm(&ud_obj) << endl;

			ud_opr = ud_insn_opr(&ud_obj, 0);
			//plt跳转是内存寻址, ud_opr->base是寄存器号
			UINT_T target = 0;
			if(ud_opr->base!=UD_NONE)
			{
				target = (*iter)->gotPltAddr;
			}
			target = target + ud_opr->lval.sdword + ud_opr->index*ud_opr->scale;
			UINT_T real;
			readData(target, 4, &real);
			if(real==ud_insn_off(&ud_obj)+6)
			{
				contWrite(target);
				readData(target, 4, &real);
			}
			contBreak(real);
			break;
		}
	}
	PTRACEASSERT(PTRACE_GETREGS, process->pid, NULL, &process->regs, "get regs", "singleStep");
	return true;
}

/*******************************************************
 * Debugger::contWrite() - 设置观察点后执行
 * addr - 被观察的数据地址
 * 返回值 - 执行成功返回true
 *******************************************************/
bool Debugger::contWrite(UINT_T addr)
{
	int status;
	UINT_T ret;
	UINT_T dr1, dr6, dr7;
	dr1 = addr;
	PTRACEASSERT(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), 0, "read to var dr7", "contWrite");
	dr7 = ret|0x00100104;
	PTRACEASSERT(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7, "write to reg dr7", "contWrite");
	PTRACEASSERT(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[1]), dr1, "write to reg dr1", "contWrite");
	do {
		PTRACEASSERT(PTRACE_CONT, process->pid, 0, 0, "continue tracee", "contWrite");
		WAITASSERT("contWrite");
		PTRACEASSERT(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[6]), 0, "read to var dr6", "contWrite");
		dr6 = ret;
	} while(!(dr6&0x2));
	PTRACEASSERT(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7, "read to var dr1", "contWrite");
	dr7 = ret&0xfffffffb;
	PTRACEASSERT(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7, "write to reg dr7", "contWrite");
	PTRACEASSERT(PTRACE_GETREGS, process->pid, NULL, &process->regs, "get regs", "singleStep");
	return true;
}

/*******************************************************
 * Debugger::getArgv() - 读取命令行传入参数
 *******************************************************/
void Debugger::getArgv()
{
	size_t strMin = 3;
	size_t strSize = 1;
	UINT_T mainArgc, mainArgvPtr;
	char* mainArgv = NULL;
	char* tmpStr = (char*)malloc(strMin+1);
	tmpStr[strMin] = '\0';
	readData(process->regs.esp, 4, &mainArgc);
	fargv << "main's argc: 0x" << mainArgc << endl;
	for(UINT_T i=0; i<mainArgc; i++)
	{
		readData(process->regs.esp+4+4*i, 4, &mainArgvPtr);
		do {
			readData(mainArgvPtr+strSize-1, strMin, tmpStr);
			strSize += strMin;
			mainArgv = (char*)realloc(mainArgv, strSize);
			memcpy((char*)((UINT_T)mainArgv+strSize-1-strMin), tmpStr, strMin);
			mainArgv[strSize-1] = '\0';
		} while(strlen(mainArgv)==strSize-1);
		fargv << "main's argv " << i << " : " << mainArgv <<  "\t0x" << mainArgvPtr  << " ~ 0x"<<  mainArgvPtr+strlen(mainArgv) << endl;
		taint->addMem(mainArgvPtr, mainArgvPtr+strlen(mainArgv)+1);
	}
	free(mainArgv);
	free(tmpStr);
}
