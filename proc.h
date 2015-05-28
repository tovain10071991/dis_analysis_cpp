#ifndef _PROC_H_
#define _PROC_H_

#include <string>
#include <gelf.h>
#include <vector>
#include <sys/user.h>
#include "type.h"
#include <fstream>
#include "dbg.h"

using namespace std;

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
		size_t		size;
		UINT_T		gotPltAddr;
		UINT_T		pltAddr;
		size_t		pltSize;
	public:
		Module(UINT_T base, std::string path);
	};
	int pid;
	Debugger* debugger;
	vector<Module*> modules;
	struct user_regs_struct regs;
	ofstream fmodule;
public:
	Process(int pid, string mainPath);
	void initModules();
};

}

#endif
