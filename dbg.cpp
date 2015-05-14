#include "dbg.h"

#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <fstream>
#include <iostream>

using namespace skyin;

Debugger::Debugger(Process* process):
		process(process),
		breakpoint(0)
//		mainModule(mainModule)
{
	process->debugger=this;
	setBreakRecoverH(process->mainModule->ehdr.e_entry);
}

void Debugger::setBreakRecover(UINT_T addr)
{
	//设置断点
	//将addr的头一个字节(第一个字的低字节)换成0xCC
	breakpoint=ptrace(PTRACE_PEEKTEXT, process->pid, addr, 0);
	ptrace(PTRACE_GETREGS, process->pid, 0, &process->regs);
	UINT_T temp = breakpoint & 0xFFFFFF00 | 0xCC;
	ptrace(PTRACE_POKETEXT, process->pid, addr, temp);

	//执行子进程
	ptrace(PTRACE_CONT, process->pid, 0, 0);
	wait(NULL);
	printf("meet breakpoint: ");

	//恢复断点
	ptrace(PTRACE_GETREGS, process->pid, NULL, &process->regs);
	//软件断点会在断点的下一个字节停住,所以还要将EIP向前恢复一个字节
	process->regs.eip-=1;
	printf("0x%lx\n", process->regs.eip);
	ptrace(PTRACE_SETREGS, process->pid, NULL, &process->regs);
	ptrace(PTRACE_POKETEXT, process->pid, process->regs.eip, breakpoint);
}

void Debugger::setBreakRecoverH(UINT_T addr)
{
	UINT_T dr0, dr7;
	dr7 = 0x1;
	dr0 = addr;
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[7]), dr7);
	ptrace(PTRACE_POKEUSER, process->pid, offsetof(struct user, u_debugreg[0]), dr0);
	ptrace(PTRACE_CONT, process->pid, 0, 0);
	wait(NULL);
	ptrace(PTRACE_GETREGS, process->pid, NULL, &process->regs);
	cout << "meet breakpointH: 0x" << process->regs.eip << endl;
}

void Debugger::readData(UINT_T addr, size_t size, void* data)
{
	size_t ts = (size+4)/4;
	UINT_T* tmp = (UINT_T*)malloc(ts*4);
	for(int i=0;i<ts;i++)
	{
		*(tmp+i) = ptrace(PTRACE_PEEKDATA, process->pid, addr+4*i, 0);
	}
	memcpy(data, tmp, size);
	free(tmp);
}

void Debugger::singleStep()
{
	UINT_T oldEip = process->regs.eip;
	ptrace(PTRACE_SINGLESTEP, process->pid, 0, 0);
	while(oldEip == process->regs.eip)
	{
		ptrace(PTRACE_GETREGS, process->pid, NULL, &process->regs);
	}
	std::cout << "single: 0x" << process->regs.eip << endl;
	
}
