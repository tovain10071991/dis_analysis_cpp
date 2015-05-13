#ifndef _DBG_H_
#define _DBG_H_

#include "type.h"
#include "proc.h"

namespace skyin {

class Process;

class Debugger {
	friend class Analyser;
private:
	UINT_T breakpoint;				//断点地址
	Process* process;
//	ModuleInfo* mainModule;
	void setBreakRecover(UINT_T addr);
public:
	Debugger(Process* process);
	void readData(UINT_T addr, size_t size, void* data);
	void singalStep();
};

}
#endif
