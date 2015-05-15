#include "proc.h"
#include <fcntl.h>
#include <cstring>
#include <sys/stat.h>
#include <link.h>
#include <stdlib.h>


using namespace std;
using namespace skyin;

Process::Process(int pid, string mainPath):
		pid(pid)
{
	Module* mainModule = new Module(0, mainPath);
	modules.push_back(mainModule);
}

void Process::initModules()
{
	//从主模块获取链接信息
	struct link_map* lm = (struct link_map*)malloc(sizeof(struct link_map));
	struct link_map* lmPtr;
	debugger->readData(modules[0]->gotPltAddr+4, 4, &lmPtr);
	debugger->readData((UINT_T)lmPtr, sizeof(struct link_map), lm);
	while((lmPtr=lm->l_next)!=NULL)
	{
		debugger->readData((UINT_T)lmPtr, sizeof(struct link_map), lm);
		char name[50];
		debugger->readData((UINT_T)lm->l_name, 50, name);
		if(!strcmp(name,""))
			continue;
		string path(name);
		Module* module = new Module(lm->l_addr, path);
		modules.push_back(module);
	}
	fmodule << "baseAddr\tpltAddr\tgotPlatAddr\tname\n";
	for(vector<Module*>::iterator iter=modules.begin();iter!=modules.end();++iter)
		fmodule << (*iter)->baseAddr << "\t" << (*iter)->pltAddr << "\t" << (*iter)->gotPltAddr << "\t" << (*iter)->path << endl;
}

Process::Module::Module(UINT_T base, string path):
		path(path),
		baseAddr(base)
{
	int fd = open(path.c_str(), O_RDONLY, 0);
	struct stat st;
	fstat(fd, &st);
	size = st.st_size;
	elf = elf_begin(fd, ELF_C_READ, NULL);
	gelf_getehdr(elf, &ehdr);
	//从section查找.plt基址和大小和.got.plt表基址
	Elf_Scn* scn = NULL;
	GElf_Shdr shdr;
	char* secName;
	size_t		shdrstrndx;		//节名符号表索引
	elf_getshdrstrndx(elf, &shdrstrndx);
	while((scn=elf_nextscn(elf, scn))!=NULL)
	{
		gelf_getshdr(scn, &shdr);
		if(shdr.sh_type==SHT_DYNAMIC)
		{
			Elf_Data* data = elf_getdata(scn, NULL);
			Elf32_Dyn dyn;
			for(UINT_T i=0;i<data->d_size;i+=sizeof(Elf32_Dyn))
			{
				memcpy(&dyn, (void*)((UINT_T)data->d_buf+i), sizeof(Elf32_Dyn));
				if(dyn.d_tag==DT_PLTGOT)
				{
					gotPltAddr = dyn.d_un.d_ptr+baseAddr;
					continue;
				}
			}
		}
		secName = elf_strptr(elf, shdrstrndx, shdr.sh_name);
		if(!strcmp(secName, ".plt")){
			pltAddr = shdr.sh_addr+baseAddr;
			pltSize = shdr.sh_size;
			continue;
		}
	}
}
