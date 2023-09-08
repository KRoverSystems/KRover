CFLAGS = -O3 -fpic -pie -std=c++0x -fno-stack-protector 
DYNINST_PATH	:= /<PATH-TO>/dyninst/install
DYNINST_INC_PATH		:= ${DYNINST_PATH}/include
DYNINST_LIB_PATH		:= ${DYNINST_PATH}/lib

Z3_PATH	:= /<PATH-TO>/z3
Z3_INC_PATH		:= ${Z3_PATH}/include
Z3_LIB_PATH		:= ${Z3_PATH}/libz3.so
KSE_PATH 		:= /<PATH-TO>/KRover

LOADER_PATH		:= /<PATH-TO>/u-loader/install
STDLIB_PATH 	:= ${LOADER_PATH}/lib
STDINC_PATH 	:= ${LOADER_PATH}/include

INC = -I${KSE_PATH}
LIB = -L${KSE_PATH}

INC += -I${STDINC_PATH}
INC += -I${DYNINST_INC_PATH}
INC += -I${Z3_INC_PATH}

LIB += -L${STDLIB_PATH}
LIB += -L${DYNINST_LIB_PATH}
LIB += -L${Z3_LIB_PATH}

LDFLAGS= '-Wl,--rpath=${DYNINST_LIB_PATH}:${Z3_PATH}:${KSE_PATH}:${STDLIB_PATH}' '-Wl,--dynamic-linker=/<PATH-TO>/oasis/u-loader/build-glibc/elf/ld.so'

DEP = -loasis 
testtest: main.cpp
	g++ -o testtest main.cpp $(CFLAGS) $(LDFLAGS) $(INC) $(LIB) $(DEP)
clean:
	rm testtest
