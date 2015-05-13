#include "proc.h"
#include "file.h"
#include <gelf.h>
#include <string>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include <iostream>
#include <link.h>

using namespace std;
using namespace skyin;

Process::Process(int pid, string inputPath):
		pid(pid),
		modules()
{
	//先找到进程入口吧
	mainModule = new Module(0, inputPath);
	modules[0] = mainModule;
}

void Process::initModules()
{
	//从主模块获取链接信息
	struct link_map* lm = (struct link_map*)malloc(sizeof(struct link_map));
	UINT_T lmPtr;
	debugger->readData(mainModule->gotPltAddr+4, 4, &lmPtr);
	debugger->readData(lmPtr, sizeof(struct link_map), lm);
	cout << lmPtr << endl;
	while((lm=lm->l_next)!=NULL)
	{
		if(!strcmp(lm->l_name,""))
			continue;
		cout << lm->l_addr << "\t" << lm->l_name << endl;
		string path(lm->l_name);
		Module* module = new Module(lm->l_addr, path);
		modules[lm->l_addr] = module;
	}
}

void Process::Module::initInfo(int fd)
{
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
					cout << ".got.plt: 0x" << gotPltAddr << endl;
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

Process::Module::Module(UINT_T base, string path):
		baseAddr(base),
		path(path)
{
	int fd = open(path.c_str(), O_RDONLY, 0);
	elf = elf_begin(fd, ELF_C_READ, NULL);
	initInfo(fd);
}
