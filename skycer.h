#ifndef _SKYCER_H_
#define _SKYCER_H_

#include "type.h"

using namespace skyin;
/*
#define WAITASSERT(func) \
	do { \
		errno = 0; \
		if(wait(&status)==-1) \
			err(errno, "======wait in %s", func); \
		if(WIFEXITED(status)&&WIFSTOPPED(status)&&WIFSIGNALED(status)) \
			cerr << "normally exit and stop and sig" << endl; \
		if(WIFEXITED(status)&&WIFSTOPPED(status)) \
			cerr << "normally exit and stop" << endl; \
		if(WIFEXITED(status)&&WIFSIGNALED(status)) \
			cerr << "normally exit and sig" << endl; \
		if(WIFSTOPPED(status)&&WIFSIGNALED(status)) \
			cerr << "stop and sig" << endl; \
		if(WIFEXITED(status)) \
		{ \
			cout << "======tracee normally exit in " << func << "(): " << WEXITSTATUS(status) << endl; \
			return false;\
		}\
		if(WIFSTOPPED(status)) \
			cerr << "stop: " << WSTOPSIG(status) << endl; \
		if(WIFSTOPPED(status)&&WSTOPSIG(status)!=SIGTRAP&&WSTOPSIG(status)!=SIGCHLD) \
			errx(-1, "======don't hanlder this STOPSIG in the beginning of %s(): %d", func, WSTOPSIG(status)); \
		if(WIFSIGNALED(status)) \
			errx(-1, "======don't hanlder this TERMSIG in the beginning of %s(): %d", func, WTERMSIG(status)); \
	} while(0)
*/
#define WAITASSERT(func) \
	do { \
		errno = 0; \
		if(wait(&status)==-1) \
			err(errno, "======wait in %s", func); \
		if(WIFEXITED(status)) \
		{ \
			cout << "======tracee normally exit in " << func << "(): " << WEXITSTATUS(status) << endl; \
			return false;\
		}\
		if(WIFSTOPPED(status)&&WSTOPSIG(status)!=SIGTRAP) \
			errx(-1, "======don't hanlder this STOPSIG in the beginning of %s(): %d", func, WSTOPSIG(status)); \
		if(WIFSIGNALED(status)) \
			errx(-1, "======don't hanlder this TERMSIG in the beginning of %s(): %d", func, WTERMSIG(status)); \
	} while(0)

#define PTRACEASSERT(req, pid, addr, data, event, func) \
	do { \
		errno = 0; \
		while((ret=ptrace(req, pid, addr, data))==0xffffffff&&errno!=0) \
		{ \
			if(errno==ESRCH) \
			{ \
				WAITASSERT(func); \
				warn("======warn: %s in %s()", event, func); \
				errno = 0; \
				continue; \
			} \
			else \
				err(errno, "======%s in %s()", event, func); \
		} \
	} while(0)

#endif
