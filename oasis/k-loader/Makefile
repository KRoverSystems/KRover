CFLAGS_elf.o := -O0
obj-m += ld.o

ld-objs += entry.o elf.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
