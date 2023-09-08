DYNINST_PATH	:= /<PATH-TO>/dyninst/install
DYNINST_INC_PATH		:= ${DYNINST_PATH}/include
DYNINST_LIB_PATH		:= ${DYNINST_PATH}/lib

Z3_PATH	:= /<PATH-TO>/z3
Z3_INC_PATH		:= ${Z3_PATH}/include
Z3_LIB_PATH		:= ${Z3_PATH}

INC_PATH := -I${DYNINST_INC_PATH}
INC_PATH += -I${Z3_INC_PATH}

LIB_PATH := -L${DYNINST_LIB_PATH}
LIB_PATH += -L${Z3_LIB_PATH}

CC		:= g++
CPPFLAGS	:=-fPIC -c -std=c++11 
LDFLAGS= '-Wl,--rpath=${DYNINST_LIB_PATH}:${Z3_PATH}' '-Wl,--dynamic-linker=/<PATH-TO>/oasis/u-loader/build-glibc/elf/ld.so'
DEP = -lz3 -lparseAPI -linstructionAPI -lsymtabAPI -ldynDwarf -lelf -ldynElf -lcommon -lsymLite 

ifeq (${DEBUG}, 1)
	CPPFLAGS	+= -O3 -g -ggdb3  -DDEBUG
else
	CPPFLAGS	+= -O3
endif

CPPS	:= centralhub.cpp VMState.cpp CPUState.cpp MemState.cpp thinctrl.cpp symexec.cpp conexec.cpp oprand.cpp Expr.cpp EFlagsManager.cpp Z3Handler.cpp SymList.cpp pageTable.cpp HistoryTree.cpp Analyze.cpp AnaCtrl.cpp
OBJS	:= $(patsubst %.cpp,%.o,${CPPS})

all: liboasis.so

$(OBJS):%.o:%.cpp
	$(CC) $(CPPFLAGS) $(INC_PATH) $^ -o $@

liboasis.so: ${OBJS}	
	$(CC) --shared $^ -o $@ $(LIB_PATH) $(LDFLAGS) $(DEP) -std=c++11

clean:
	rm -rf ${OBJS}
