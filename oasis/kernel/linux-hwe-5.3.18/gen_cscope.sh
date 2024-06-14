#!/bin/bash

LNX=$(pwd)
#echo "$LNX"
echo "Finding relavant source files..." 	
find  $LNX                                                                \
	-path "$LNX/arch/*" ! -path "$LNX/arch/x86*" -prune -o               \
	-path "$LNX/include/asm-*" ! -path "$LNX/include/asm-generic*" ! -path "$LNX/include/asm-x86*" -prune -o \
	-path "$LNX/tmp*" -prune -o                                           \
	-path "$LNX/Documentation*" -prune -o                                 \
	-path "$LNX/scripts*" -prune -o                                       \
	-path "$LNX/debian*" -prune -o                                       \
	-path "$LNX/certs*" -prune -o                                       \
	-path "$LNX/LICENSES*" -prune -o                                       \
    -name "*.[chxsS]" -print > $LNX/cscope.files
echo "Building cscope database..."
time cscope -q -k -b -i cscope.files

exit 0
