#include "proc.h"
#include <fcntl.h>
#include <cstring>
#include <sys/stat.h>
#include <link.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>


using namespace std;
using namespace skyin;

/*******************************************************
 * Process::Process() - Process对象的构造函数,绑定主模块的Module对象
 * pid - 被跟踪子进程的pid
 * mainPath - 主模块的文件路径
 *******************************************************/
Process::Process(int pid, string mainPath):
		pid(pid)
{
	fmodule.open("module.out");
	fmodule	<< hex;
	Module* mainModule = new Module(0, mainPath);
	modules.push_back(mainModule);
}

/*******************************************************
 * Process::initModules() - 初始化所有已加载模块,在(由Debugger)跳过ld执行到主模块的入口处之后调用,通过链接信息读取已加载模块的信息,一次创建Module对象,加进Process::modules向量中
 *******************************************************/
void Process::initModules()
{
	//从主模块获取链接信息
	struct link_map* lm = (struct link_map*)malloc(sizeof(struct link_map));
	if(lm==NULL)
		errx(-1, "malloc: fail to allocate link_map\n");
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

/*******************************************************
 * Process::Module::Module() - Module对象的构造函数,主要从模块对应文件中从读取ELF信息,顺便输出
 * base - 模块在进程空间的基址,主模块的基址显示为0
 * path - 模块对应的可执行文件路径
 *******************************************************/
Process::Module::Module(UINT_T base, string path):
		path(path),
		baseAddr(base)
{
	errno = 0;
	int fd = open(path.c_str(), O_RDONLY, 0);
	if(fd == -1)
		err(errno, "open");
	struct stat st;
	errno = 0;
	if(fstat(fd, &st)==-1)
		err(errno, "fstat");
	size = st.st_size;
	if((elf = elf_begin(fd, ELF_C_READ, NULL))==NULL)
		errx(elf_errno(), "%s elf_begin: %s\n", path.c_str(), elf_errmsg(elf_errno()));
	if(gelf_getehdr(elf, &ehdr)==NULL)
		errx(elf_errno(), "%s gelf_getehdr: %s\n", path.c_str(), elf_errmsg(elf_errno()));
	//从section查找.plt基址和大小和.got.plt表基址
	Elf_Scn* scn = NULL;
	GElf_Shdr shdr;
	char* secName;
	size_t		shdrstrndx;		//节名符号表索引
	if(elf_getshdrstrndx(elf, &shdrstrndx)==-1)
		errx(elf_errno(), "%s elf_getshdrstrndx: %s\n", path.c_str(), elf_errmsg(elf_errno()));
	while((scn=elf_nextscn(elf, scn))!=NULL)
	{
		if(gelf_getshdr(scn, &shdr)==NULL)
			errx(elf_errno(), "%s gelf_getshdr: %s\n", path.c_str(), elf_errmsg(elf_errno()));
		if(shdr.sh_type==SHT_DYNAMIC)
		{
			Elf_Data* data = elf_getdata(scn, NULL);
			if(data==NULL)
				errx(elf_errno(), "%s elf_getdata: %s\n", path.c_str(), elf_errmsg(elf_errno()));
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
		if((secName = elf_strptr(elf, shdrstrndx, shdr.sh_name))==NULL)
			errx(elf_errno(), "%s elf_strptr: %s\n", path.c_str(), elf_errmsg(elf_errno()));
		if(!strcmp(secName, ".plt")){
			pltAddr = shdr.sh_addr+baseAddr;
			pltSize = shdr.sh_size;
			continue;
		}
	}
}
