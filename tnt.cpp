#include "dbg.h"

using namespace std;
using namespace skyin;

extern 

Debugger::Taint::Taint()
{
	for(int i=0;i<REGNOMAX;i++)
		taintReg[i] = false;
	taintMem[0]=0;
	taintMem[0xffffffff]=0xffffffff;
}

UINT_T Debugger::Taint::addMem(UINT_T start, UINT_T end)
{
	ftaint << "add mem: 0x" << start << " ~ 0x" << end-1 << endl;
	//先与前项合并
	map<UINT_T, UINT_T>::iterator preIter;
	map<UINT_T, UINT_T>::iterator iter = taintMem.begin();
	for(;iter!=taintMem.end();++iter)
	{
		if((*iter).first>start)
			break;
		preIter = iter;
	}
	UINT_T tmp = (*iter).first;
	if(start<=(*preIter).second)
	{
		(*preIter).second = end>(*preIter).second?end:(*preIter).second;
	}
	else
	{
		taintMem[start] = end;
		preIter = taintMem.find(start);
		iter = taintMem.find(tmp);
	}
	//与后项合并
	if((*preIter).second>=(*iter).first)
	{
		(*preIter).second = (*preIter).second>(*iter).second?(*preIter).second:(*iter).second;
		taintMem.erase(iter);
	}
	return (*preIter).first;
}

void Debugger::Taint::delMem(UINT_T start, UINT_T end)
{
	UINT_T tmp = addMem(start, end);
	map<UINT_T, UINT_T>::iterator iter = taintMem.find(tmp);
	if((*iter).second>end)
		taintMem[end] = (*iter).second;
	iter = taintMem.find(tmp);
	if((*iter).first==start)
		taintMem.erase(iter);
	(*iter).second = start;
}
