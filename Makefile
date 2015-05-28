#export LD_LIBRARY_PATH=/home/user/Documents/udis86-1.7.2/build/lib

UDIS86_INCLUDE := /home/user/Documents/udis86-1.7.2/build/include/
ELF_INCLUDE := /home/user/Documents/libelf-0.8.13/build/include/
UDIS86_LIBRARY := /home/user/Documents/udis86-1.7.2/build/lib/
ELF_LIBRARY := /home/user/Documents/libelf-0.8.13/build/lib/
XED_INCLUDE := /home/user/Documents/pin-2.14-71313-gcc.4.4.7-linux/extras/xed-ia32/include/

XED_STATIC := /home/user/Documents/pin-2.14-71313-gcc.4.4.7-linux/extras/xed-ia32/lib/libxed.a

INCLUDE := -I $(XED_INCLUDE) -I $(UDIS86_INCLUDE) -I $(ELF_INCLUDE) 
LIB := -L $(UDIS86_LIBRARY) -L $(ELF_LIBRARY)
CXXFLAGS := -c -Wall -g $(INCLUDE) -D_GNU_SOURCE -std=c++11
LDFLAGS := -lelf -ludis86 -ldl

EXECUTE := skycer
SOURCE := $(wildcard *.cpp)
OBJECT := $(SOURCE:.cpp=.o)
OUTPUT := $(wildcard *out)

all:  $(EXECUTE)

$(EXECUTE): $(OBJECT)
	$(CXX) $(LIB) -o $(EXECUTE) $(OBJECT) $(XED_STATIC) $(LDFLAGS)

$(OBJECT): $(SOURCE)

clean:
	rm $(EXECUTE) $(OBJECT) $(OUTPUT)
