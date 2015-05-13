#include "any.h"
#include "mnem.h"
#include <stdlib.h>
#include <fstream>
#include <iomanip>
#include <vector>
#include "proc.h"

using namespace skyin;
using namespace std;

Analyser::Analyser(Debugger* debugger, File* file):
		debugger(debugger),
		process(debugger->process),
		file(file)
{
	trace = malloc(50);
	//初始化libudis
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_ATT);
}

void Analyser::readTrace()
{
	debugger->readData(process->regs.eip, 50, trace);
	ud_set_input_buffer(&ud_obj, (uint8_t*)trace, 50);
	ud_set_pc(&ud_obj, process->regs.eip);
	disassemble();
}

void Analyser::disassemble()
{
	while (ud_disassemble(&ud_obj))
	{
		if(ud_insn_mnemonic(&ud_obj)==UD_Iinvalid)
		{
			exit(-1);
		}
		file->disOutput << "0x" << setiosflags(ios::left)<< setw(8) << ud_insn_off(&ud_obj) << "\t"
						<< setw(8) << ud_insn_hex(&ud_obj) << "\t"
						<< setw(20) << mnemonic_name[ud_insn_mnemonic(&ud_obj)] << "\t"
						<< ud_insn_asm(&ud_obj) << endl;
		if(isBranch(&ud_obj))
		{
			branch.first = ud_insn_off(&ud_obj);
			ud_opr = ud_insn_opr(&ud_obj, 0);
			if(isUnconditionalBranch(&ud_obj))
			{
				branch.second = directBranchHandler();
			}
		}
	}
}

UINT_T Analyser::directBranchHandler()
{
	//判断地址是不是.plt段,先判断目标地址是哪个模块中的
	UINT_T target = ud_insn_off(&ud_obj)+ud_insn_len(&ud_obj)+ud_opr->lval.sdword;
	for(vector<Process::Module*>::iterator iter=process->modules.begin();iter!=process->modules.end();++iter)
	{
		if(target>=(*iter)->pltAddr&&target<=(*iter)->pltAddr+(*iter)->pltSize)
			return pltHandler(target);
	}
	return target;
}

UINT_T Analyser::pltHandler(UINT_T addr)
{
	//反汇编得到目标地址所在的.got.plt表中偏移
	void* pltIns = malloc(6);
	debugger->readData(addr, 6, pltIns);
	ud_set_input_buffer(&ud_obj, (uint8_t*)pltIns, 6);
	ud_set_pc(&ud_obj, process->regs.eip);
	ud_disassemble(&ud_obj);

	file->disOutput << "0x" << setiosflags(ios::left)<< setw(8) << ud_insn_off(&ud_obj) << "\t"
					<< setw(8) << ud_insn_hex(&ud_obj) << "\t"
					<< setw(20) << mnemonic_name[ud_insn_mnemonic(&ud_obj)] << "\t"
					<< ud_insn_asm(&ud_obj) << endl;

	ud_opr = ud_insn_opr(&ud_obj, 0);

	UINT_T org;
	debugger->readData(ud_opr->lval.sdword, 4, &org);
	printf("org: %x\n", org);
	UINT_T real;
	while(1){
		debugger->singalStep();
		debugger->readData(ud_opr->lval.sdword, 4, &real);
		if(real!=0xffffffff&&real!=org)
		{
			printf("real: %x\n", real);
			break;
		}
	}
	return real;
}
