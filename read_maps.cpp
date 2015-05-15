#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <iostream>
#include "proc.h"
#include "dbg.h"
#include <stdlib.h>

using namespace std;
using namespace skyin;

ofstream fmodule;
ofstream fdebugger;
ofstream fdis;

/*******************************************************
 * par_process()
 *******************************************************/
inline void par_process(int pid, string inputPath)
{
	wait(NULL);

	fmodule.open("module.out");
	fdebugger.open("debugger.out");
	fdis.open("dis.out");
	fmodule	<< hex;
	fdebugger << hex;
	fdis << hex;
	cout << hex;
	elf_version(EV_CURRENT);

	Process* process = new Process(pid, inputPath);
	Debugger* debugger = new Debugger(process);
	process->initModules();
	while(debugger->updateTrace());
//	while(debugger->readTrace())
//	{
//		debugger->disassemble();
//	}

	ptrace(PTRACE_CONT, pid, 0, 0);
	wait(NULL);
}

/*******************************************************
 * main()
 *******************************************************/
int main()
{
	int pid;
	string inputPath("/bin/ls");
	//fork进程
	pid=fork();
	if(pid==0)
	{
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execl(inputPath.c_str(), "tracee", NULL);
	}
	else if(pid>0)
	{
		//父进程的工作
		par_process(pid, inputPath);
	}
	else
	{
		perror("fork");
		exit(-1);
	}
	return 0;
}
