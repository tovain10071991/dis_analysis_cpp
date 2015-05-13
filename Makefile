#export LD_LIBRARY_PATH=/home/user/Documents/udis86-1.7.2/build/lib

UDIS86_INCLUDE := /home/user/Documents/udis86-1.7.2/build/include/
ELF_INCLUDE := /home/user/Documents/libelf-0.8.13/build/include/
UDIS86_LIBRARY := /home/user/Documents/udis86-1.7.2/build/lib/
ELF_LIBRARY := /home/user/Documents/libelf-0.8.13/build/lib/

CXXFLAGS := -c -g -I $(UDIS86_INCLUDE) -I $(ELF_INCLUDE) -D_GNU_SOURCE -std=c++11
LDFLAGS := -I $(UDIS86_INCLUDE) -I $(ELF_INCLUDE) -L $(UDIS86_LIBRARY) -L $(ELF_LIBRARY)

EXECUTE := read_maps
SOURCE := $(wildcard *.cpp)
OBJECT := $(SOURCE:.cpp=.o)
OUTPUT := $(wildcard *.out)

all:  $(EXECUTE)

$(EXECUTE): $(OBJECT)
	$(CXX) $(LDFLAGS) -o $(EXECUTE) $(OBJECT) -ludis86 -lelf -ldl

$(OBJECT): $(SOURCE)

clean:
	rm $(EXECUTE) $(OBJECT) $(OUTPUT) core
