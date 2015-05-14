#ifndef _ANY_H_
#define _ANY_H_

#include "file.h"
#include "proc.h"
#include "dbg.h"
#include <udis86.h>
#include <utility>

namespace skyin {

#define isBranch(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Icall || ud_insn_mnemonic(ud_obj)==UD_Iiretw || ud_insn_mnemonic(ud_obj)==UD_Iiretd || ud_insn_mnemonic(ud_obj)==UD_Iiretq || (ud_insn_mnemonic(ud_obj)>=UD_Ijo && ud_insn_mnemonic(ud_obj)<=UD_Ijmp) || ud_insn_mnemonic(ud_obj)==UD_Iret || ud_insn_mnemonic(ud_obj)==UD_Iretf)

#define isRet(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Iiretw || ud_insn_mnemonic(ud_obj)==UD_Iiretd || ud_insn_mnemonic(ud_obj)==UD_Iiretq || ud_insn_mnemonic(ud_obj)==UD_Iret || ud_insn_mnemonic(ud_obj)==UD_Iretf)

#define isUnconditionalBranch(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Ijmp || ud_insn_mnemonic(ud_obj)==UD_Icall)

class Debugger;
class Process;
class File;

class Analyser {
private:
	void* trace;
	std::pair<UINT_T, UINT_T> branch;	//当前trace的分支地址与目标
	Debugger* debugger;
	ud_t ud_obj;
	const ud_operand_t* ud_opr;
	Process* process;
	File* file;
	UINT_T directBranchHandler();
	UINT_T pltHandler(UINT_T addr);
public:
	Analyser(Debugger* debugger, File* file);
//	void readTrace();
	void readTrace(UINT_T addr);
	void updateTrace();
	void disassemble();
};

}

#endif
