#ifndef _DBG_H_
#define _DBG_H_

#include "proc.h"
#include "type.h"
#include <fstream>
#include <udis86.h>
#include <map>

extern "C" {
#include "xed-interface.h"
}

using namespace std;
using namespace skyin;

#define TRACEMIN 30		//至少不小于最长指令的长度,否则那条长指令永远也无法成功读取和反汇编
#define REGNOMAX UD_OP_CONST		//基于udis86

#define isBranch(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Icall || ud_insn_mnemonic(ud_obj)==UD_Iiretw || ud_insn_mnemonic(ud_obj)==UD_Iiretd || ud_insn_mnemonic(ud_obj)==UD_Iiretq || (ud_insn_mnemonic(ud_obj)>=UD_Ijo && ud_insn_mnemonic(ud_obj)<=UD_Ijmp) || ud_insn_mnemonic(ud_obj)==UD_Iret || ud_insn_mnemonic(ud_obj)==UD_Iretf)

extern ofstream fdebugger;
extern ofstream fdis;
extern ofstream ftaint;
extern ofstream fargv;
extern ofstream fdis2;

namespace skyin {

class Process;

class Debugger {
private:
	class Taint {
	public:
		map<UINT_T, UINT_T> taintMem;	//基址-尾址+1
		bool taintReg[REGNOMAX];		//寄存器号,true表示为脏
		Taint();
		UINT_T addMem(UINT_T start, UINT_T end);
		void delMem(UINT_T start, UINT_T end);
		bool isTaintMem(UINT_T addr);
	};
	Process* process;
	void* trace;
	void* trace2;
	UINT_T traceEnd;
	UINT_T traceEnd2;
	ud_t ud_obj;
	const ud_operand_t* ud_opr;
	xed_state_t xedState;
	Taint* taint;
	bool contBreak(UINT_T addr);
	bool contWrite(UINT_T addr);
	bool singleStep();
	bool readTrace();
	bool readTrace2();
	void getArgv();
	void outputOpr();
public:
	Debugger(Process* process);
	bool readData(UINT_T addr, size_t size, void* data);
	bool updateTrace();
};

}

#endif
