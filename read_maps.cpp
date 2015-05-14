#include <sys/ptrace.h>	//ptrace
#include <unistd.h>		//fork, execve
#include <stdio.h>		//perror
#include <stdlib.h>		//exit
#include <sys/wait.h>	//wait
#include <string>		//string
#include <gelf.h>		//elf_version
#include <iostream>
#include <fstream>

//#include "type"
#include "file.h"			//文件类
#include "dbg.h"			//调试器类
#include "any.h"			//分析类
#include "proc.h"			//进程类

using namespace std;
using namespace skyin;

/*******************************************************
 * par_process()
 *******************************************************/
inline void par_process(int pid, string inputPath)
{
	wait(NULL);
	//初始化各种类
	File* file = new File();
	//初始化libelf
	elf_version(EV_CURRENT);
	//初始化进程类,读进程入口地址
	Process* process = new Process(pid, inputPath);
	//初始化调试器类,执行跳过ld
	Debugger* debugger = new Debugger(process);
	Analyser* analyser = new Analyser(debugger, file);
	//获取已装载模块的信息
	process->initModules();

	while(1)
	{		
		analyser->updateTrace();
//		debugger->contTrace();
	}
//	analyser->disassemble();

	//以trace为粒度，每执行一个trace，就进行反汇编
	//先读取一个trace,再分析,再执行
//	while(1)
//	{
		
//		debugger.contBranch();
//		analyser.disassemble();
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
