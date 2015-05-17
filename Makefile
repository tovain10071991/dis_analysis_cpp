#export LD_LIBRARY_PATH=/home/user/Documents/udis86-1.7.2/build/lib

UDIS86_INCLUDE := /home/user/Documents/udis86-1.7.2/build/include/
ELF_INCLUDE := /home/user/Documents/libelf-0.8.13/build/include/
UDIS86_LIBRARY := /home/user/Documents/udis86-1.7.2/build/lib/
ELF_LIBRARY := /home/user/Documents/libelf-0.8.13/build/lib/

CXXFLAGS := -c -Wall -g -I $(UDIS86_INCLUDE) -I $(ELF_INCLUDE) -D_GNU_SOURCE -std=c++11
INCLUDE := -I $(UDIS86_INCLUDE) -I $(ELF_INCLUDE)
LIB := -L $(UDIS86_LIBRARY) -L $(ELF_LIBRARY)
LDFLAGS := -ludis86 -lelf -ldl

EXECUTE := skycer
SOURCE := $(wildcard *.cpp)
OBJECT := $(SOURCE:.cpp=.o)
OUTPUT := $(wildcard *out)

all:  $(EXECUTE)

$(EXECUTE): $(OBJECT)
	$(CXX) $(INCLUDE) $(LIB) -o $(EXECUTE) $(OBJECT) $(LDFLAGS)

$(OBJECT): $(SOURCE)

clean:
	rm $(EXECUTE) $(OBJECT) $(OUTPUT)
