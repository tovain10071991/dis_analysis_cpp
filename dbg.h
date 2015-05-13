#ifndef _DBG_H_
#define _DBG_H_

#include <sys/user.h>
#include "type.h"
#include "proc.h"

namespace skyin {

class Process;

class Debugger {
private:
	UINT_T breakpoint;				//断点地址
	struct user_regs_struct regs;
	Process* process;
//	ModuleInfo* mainModule;
	void setBreakRecover(UINT_T addr);
public:
	Debugger(Process* process);

	void readData(UINT_T addr, size_t size);
	void readData(UINT_T addr, size_t size, void* data);
	void contBranch();
};

}
#endif
