#ifndef _ANY_H_
#define _ANY_H_

#include "dbg.h"

namespace skyin {

class Debugger;

class Analyser {
private:
	void* trace;
	Debugger* debugger;
public:
	Analyser(Debugger* debugger);
	void readTrace();
//	void disassemble();
};

}

#endif
