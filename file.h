#ifndef _FILE_H_
#define _FILE_H_

#include <fstream>

using namespace std;

namespace skyin {

class File {
private:
	ofstream disOutput;
	ofstream modulesInfo;
public:
	File();
};

}

#endif
