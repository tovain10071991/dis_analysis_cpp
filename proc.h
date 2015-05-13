#ifndef _PROC_H_
#define _PROC_H_

#include <map>
#include "dbg.h"
#include "type.h"
#include <string>
#include <gelf.h>
#include <sys/user.h>

namespace skyin {

class Debugger;

class Process {
	friend class Debugger;
private:
	class Module {
	public:
		std::string		path;
		Elf*		elf;
		GElf_Ehdr	ehdr;
		UINT_T		baseAddr;
		UINT_T		gotPltAddr;
		UINT_T		pltAddr;
		size_t		pltSize;
		Module(UINT_T base, std::string path);
//		Module(int fd, std::string path);
	private:
		void initInfo(int fd);
	};
	int mainFd;	//用于elf
	int pid;
	Module* mainModule;
	std::map<UINT_T, Module*> modules;
	Debugger* debugger;
	struct user_regs_struct regs;
public:
	Process(int pid, std::string inputPath);
	void initModules();
};

}

#endif
