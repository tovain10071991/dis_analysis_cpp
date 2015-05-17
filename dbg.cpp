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
	taint = new Taint();
	getArgv();
	readTrace();
}

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
			 << setw(12) << ud_insn_hex(&ud_obj) << "\t"
			 << setw(20) << mnemonic_name[ud_insn_mnemonic(&ud_obj)] << "\t"
			 << ud_insn_asm(&ud_obj) << endl;
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
	if(!contBreak(traceEnd))
		return false;

	singleStep();
	return readTrace();
}

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

bool Debugger::singleStep()
{
	int status;
	UINT_T ret;
	UINT_T eip;
	PTRACEASSERT(PTRACE_SINGLESTEP, process->pid, 0, 0, "single step", "singleStep");
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
	PTRACEASSERT(PTRACE_GETREGS, process->pid, NULL, &process->regs, "get regs", "singleStep");
	return true;
}

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
