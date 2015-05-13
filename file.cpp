#include "file.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>

using namespace std;

namespace skyin {

File::File():
		disOutput("disOutput.out"),
		modulesInfo("modulesInfo.out")
{
	disOutput << hex;
	modulesInfo << hex;
	cout << hex;
}

}
