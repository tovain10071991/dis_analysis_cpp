#ifndef _FILE_H_
#define _FILE_H_

#include <fstream>
#include "any.h"

using namespace std;

namespace skyin {

class Analyser;

class File {
	friend class Analyser;
private:
	ofstream disOutput;
	ofstream modulesInfo;
public:
	File();
};

}

#endif
