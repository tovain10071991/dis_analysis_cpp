#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <iostream>
#include "proc.h"
#include "dbg.h"
#include <stdlib.h>
#include <errno.h>
#include  <err.h>	//err()
#include "skycer.h"

using namespace std;
using namespace skyin;

extern int errno;
ofstream fmodule;
ofstream fdebugger;
ofstream fdis;
ofstream fargv;
ofstream ftaint;

/*******************************************************
 * par_process()
 *******************************************************/
inline bool parProcess(int pid, string inputPath)
{
	int status;
	UINT_T ret;
	cout << hex;
	cerr << hex;
	WAITASSERT("parProcess");
	fmodule.open("module.out");
	fdebugger.open("debugger.out");
	fdis.open("dis.out");
	fargv.open("argv.out");
	ftaint.open("taint.out");
	fmodule	<< hex;
	fdebugger << hex;
	fdis << hex;
	fargv << hex;
	ftaint << hex;

	if(elf_version(EV_CURRENT)==EV_NONE)
		errx(elf_errno(), "elf_version in parProcess(): %s\n", elf_errmsg(elf_errno()));
	Process* process = new Process(pid, inputPath);
	Debugger* debugger = new Debugger(process);
	process->initModules();
	while(debugger->updateTrace());

	PTRACEASSERT(PTRACE_CONT, pid, 0, 0, "continue tracee", "parProcess");
	WAITASSERT("parProcess");
	return true;
}

/*******************************************************
 * main()
 *******************************************************/
int main(int argc, char** argv)
{
	int pid;
	if(argc <2)
		errx(-1, "arguments fault");
	string inputPath(argv[1]);
	errno = 0;
	//fork进程
	pid=fork();
	if(pid==0)
	{
		if(ptrace(PTRACE_TRACEME, 0, 0, 0)==-1)
		{
			err(errno, "be traced in child");
		}
		if(execv(inputPath.c_str(), argv+1)==-1)
			err(errno, "execv in child");
	}
	else if(pid>0)
	{
		//父进程的工作
		return parProcess(pid, inputPath);
	}
	else
		err(errno, "fork in main()");
}
