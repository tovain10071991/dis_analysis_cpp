#ifndef _DBG_H_
#define _DBG_H_

#include "proc.h"
#include "type.h"
#include <fstream>
#include <udis86.h>

using namespace std;

#define traceMin 10

#define isBranch(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Icall || ud_insn_mnemonic(ud_obj)==UD_Iiretw || ud_insn_mnemonic(ud_obj)==UD_Iiretd || ud_insn_mnemonic(ud_obj)==UD_Iiretq || (ud_insn_mnemonic(ud_obj)>=UD_Ijo && ud_insn_mnemonic(ud_obj)<=UD_Ijmp) || ud_insn_mnemonic(ud_obj)==UD_Iret || ud_insn_mnemonic(ud_obj)==UD_Iretf)

extern ofstream fdebugger;
extern ofstream fdis;

namespace skyin {

class Process;

class Debugger {
private:
	Process* process;
	void* trace;
	UINT_T traceEnd;
	ud_t ud_obj;
	const ud_operand_t* ud_opr;
	void contBreak(UINT_T addr);
	void contWrite(UINT_T addr);
	void singleStep();
	bool readTrace();
public:
	Debugger(Process* process);
	void readData(UINT_T addr, size_t size, void* data);
	bool updateTrace();
};

}

#endif
