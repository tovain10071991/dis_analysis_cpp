#include "dbg.h"
#include <sys/ptrace.h> 
#include <sys/wait.h>
#include <cstring>		//memcpy
#include <stdlib.h>
#include <iomanip>
#include "mnem.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace skyin;

Debugger::Debugger(Process* process):
		process(process),
		traceEnd(0)
{
	process->debugger = this;
	//初始化libudis
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_ATT);
	contBreak(process->modules[0]->ehdr.e_entry);
	readTrace();
}

void Debugger::readData(UINT_T addr, size_t size, void* data)
{
	size_t ts = (size+4)/4;
	UINT_T* tmp = (UINT_T*)malloc(ts*4);
	for(UINT_T i=0;i<ts;i++)
	{
		*(tmp+i) = ptrace(PTRACE_PEEKDATA, process->pid, addr+4*i, 0);
	}
	memcpy(data, tmp, size);
	free(tmp);
}

bool Debugger::readTrace()
{
	size_t traceSize = TRACEMIN;
	void* tmpTrace = malloc(TRACEMIN);
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
				printf("Error\n");
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
			 << setw(12) << ud_insn_hex(&ud_obj) << "\t"
			 << setw(20) << mnemonic_name[ud_insn_mnemonic(&ud_obj)] << "\t"
			 << ud_insn_asm(&ud_obj) << endl;
		outputOpr();
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

bool Debugger::updateTrace()
{
	contBreak(traceEnd);
	singleStep();
	return readTrace();
}

void Debugger::contBreak(UINT_T addr)
{
	UINT_T dr0, dr6, dr7;
	dr0 = addr;
	dr7 = ptrace(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), 0);
	dr7 |= 0x01;
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7);
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[0]), dr0);
	do {
		ptrace(PTRACE_CONT, process->pid, 0, 0);
		wait(NULL);
		dr6 = ptrace(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[6]), 0);
	} while(!(dr6&0x1));
	ptrace(PTRACE_GETREGS, process->pid, NULL, &process->regs);
	fdebugger << "meet breakpoint: 0x" << process->regs.eip << endl;
	dr7 = ptrace(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), 0);
	dr7 &= 0xfffffffe;
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7);
}

void Debugger::singleStep()
{
	ptrace(PTRACE_SINGLESTEP, process->pid, 0, 0);
	UINT_T eip = 0xffffffff;
	while(eip == 0xffffffff)
	{
		eip = ptrace(PTRACE_PEEKUSER, process->pid, offsetof(struct user_regs_struct, eip), 0);
	}
	//如果指令在.plt段,就跳过
	for(vector<Process::Module*>::iterator iter=process->modules.begin();iter!=process->modules.end();++iter)
	{
		if(eip>=(*iter)->pltAddr && eip<=(*iter)->pltAddr+(*iter)->pltSize)
		{
			//反汇编得到目标地址所在的.got.plt表中偏移
			void* pltIns = malloc(6);
			readData(eip, 6, pltIns);
			ud_set_input_buffer(&ud_obj, (uint8_t*)pltIns, 6);
			ud_set_pc(&ud_obj, eip);
			ud_disassemble(&ud_obj);

			fdis << "0x" << setiosflags(ios::left)<< setw(8) << ud_insn_off(&ud_obj) << "\t"
				 << setw(12) << ud_insn_hex(&ud_obj) << "\t"
				 << setw(20) << mnemonic_name[ud_insn_mnemonic(&ud_obj)] << "\t"
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
	ptrace(PTRACE_GETREGS, process->pid, NULL, &process->regs);
}

void Debugger::contWrite(UINT_T addr)
{
	UINT_T dr1, dr6, dr7;
	dr1 = addr;
	dr7 = ptrace(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), 0);
	dr7 |= 0x00100104;
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7);
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[1]), dr1);
	UINT_T tmp = ptrace(PTRACE_PEEKDATA, process->pid, addr, 0);
	do {
		ptrace(PTRACE_CONT, process->pid, 0, 0);
		do {
			wait(NULL);
			dr6 = ptrace(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[6]), 0);
		} while(!(dr6&0x2));
		tmp = ptrace(PTRACE_PEEKDATA, process->pid, addr, 0);
	} while(tmp==0xffffffff);
	dr7 = ptrace(PTRACE_PEEKUSER, process->pid, offsetof(struct user, u_debugreg[7]), 0);
	dr7 &= 0xfffffffb;
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7);
	ptrace(PTRACE_GETREGS, process->pid, NULL, &process->regs);
}

void Debugger::outputOpr()
{
	fdis <<	"\ttype\tsize\tbase\tindex\tscale\toffset\tlval" << endl;
	for(UINT_T i=0;1;i++)
	{
		if((ud_opr=ud_insn_opr(&ud_obj, i))==NULL)
			break;
		fdis << i << "\t" << ud_opr->type << "\t" << (UINT_T)ud_opr->size << "\t"
			 << ud_opr->base << "\t" << ud_opr->index << "\t"
			 << (UINT_T)ud_opr->scale << "\t" << (UINT_T)ud_opr->offset << "\t"
			 << ud_opr->lval.sdword << endl;
	}
	fdis << endl;

}
