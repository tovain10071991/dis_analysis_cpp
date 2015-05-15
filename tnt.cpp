#include "dbg.h"

using namespace std;
using namespace skyin;

Debugger::Taint::Taint()
{
	for(int i=0;i<REGNOMAX;i++)
		taintReg[i] = false;
	taintMem[0]=0;
	taintMem[0xffffffff]=0xffffffff;
}

void Debugger::Taint::addMem(UINT_T start, UINT_T end)
{
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
}
