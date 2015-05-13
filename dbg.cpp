#include "dbg.h"

#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <fstream> 

using namespace skyin;

Debugger::Debugger(Process* process):
		process(process),
		breakpoint(0)
//		mainModule(mainModule)
{
	regs={0};
	process->debugger=this;
	setBreakRecover(process->mainModule->ehdr.e_entry);
}

void Debugger::setBreakRecover(UINT_T addr)
{
	//设置断点
	//将addr的头一个字节(第一个字的低字节)换成0xCC
	breakpoint=ptrace(PTRACE_PEEKTEXT, process->pid, addr, 0);
	ptrace(PTRACE_GETREGS, process->pid, 0, &regs);
	UINT_T temp = breakpoint & 0xFFFFFF00 | 0xCC;
	ptrace(PTRACE_POKETEXT, process->pid, addr, temp);

	//执行子进程
	ptrace(PTRACE_CONT, process->pid, 0, 0);
	wait(NULL);
	printf("meet breakpoint: ");

	//恢复断点
	ptrace(PTRACE_GETREGS, process->pid, NULL, &regs);
	//软件断点会在断点的下一个字节停住,所以还要将EIP向前恢复一个字节
	regs.eip-=1;
	printf("0x%lx\n", regs.eip);
	ptrace(PTRACE_SETREGS, process->pid, NULL, &regs);
	ptrace(PTRACE_POKETEXT, process->pid, regs.eip, breakpoint);
}

void Debugger::readData(UINT_T addr, size_t size, void* data)
{
	size_t ts = (size+4)/4;
	UINT_T* tmp = (UINT_T*)malloc(ts*4);
	for(int i=0;i<ts;i++)
	{
		*(tmp+i) = ptrace(PTRACE_PEEKDATA, process->pid, addr+4*i, 0);
	}
	printf("\n");
	memcpy(data, tmp, size);
	free(tmp);
}

void Debugger::contBranch()
{
	
}
