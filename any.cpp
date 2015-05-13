#include "any.h"
#include <stdlib.h>

using namespace skyin;

Analyser::Analyser(Debugger* debugger):
		debugger(debugger)
{
	trace = malloc(50);
}

void Analyser::readTrace()
{
	
}
