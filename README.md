# KRover
KRover is a Symbolic Execution Engine for Dynamic Kernel Analysis. This document will guide you through the setup of the necessary infrastructure and dependant systems needed to for the execution of KRover.

# Included packages
This package includes the following software packages.
1. KRover: KRover symbolic execution engine.
2. oasis : OASIS infrastructure on which KRover is executed. OASIS consists of the following components.
2.1 kernel : A lnux kernel with modified KVM.
2.2 k-loader : A LKM that acts as a kernel loader.
2.3 u-loader : Modified libc to satisfy specific loading/address space requirements.
2.4 oasis-lib : A collection of binaries enabling specific OASIS features such as EFI: execution flow instruentation.
2.5 launcher : System launcher, launches oasis and KRover.

# Instructions for system setup
First step is to setup the OASIS infrastructure. If you need more information abount OASIS design, features and EFI, refer to our OASIS paper from SP21: "A novel dynamic analysis infrastructure to instrument untrusted execution flow across user-kernel spaces".

## Platform
OASIS needs to run on a bare-metal machine with the customzed kernel specified above. The target kernel which will be analyzed using KRover would be executed in a VM. We recomment a host machine with Ubuntu. If your current Ubuntu does not match with the following requirements or you do not want to disturb your current working environment, you can consider creating a new partition and installing a separate Ubuntu OS. Then your machine becomes a dual-boot Ubuntu system, do the following things in the new Ubuntu. It's also okay to skip the step if there is no conflict.

## Requirements
1. Host OS: Ubuntu 18.04; Kernel version: linux 5.4.X.
2. binutils: 2.30
3. gcc:7.5.0
4. [Install kvm and its related virt-manager toolchain](https://linuxize.com/post/how-to-install-kvm-on-ubuntu-18-04/)
5. [Install a VM with linux 5.4.X using virt-manager](https://www.tecmint.com/create-virtual-machines-in-kvm-using-virt-manager/4/)
6. Clone the KRover repo on to host.
```
git clone https://github.com/KRoverSystems/KRover.git
```

## Compiling and installing the OASIS kernel.

### install the required compilers and other tools
```
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev
```

### Update oasis-lib path in imee.h
Go to oasis/kernel/linux-hwe-5.3.18/virt/kvm/imee.h
Update the constant, KROVER_OASIS_LIB_PATH accordingly.

### configuring the kernel
confirm *CONFIG_X86_SMAP is not set* in the .config file. if *CONFIG_X86_SMAP = y*, change it to *CONFIG_X86_SMAP = n*.
```
cd oasis/kernel/linux-hwe-5.3.18
grep CONFIG_X86_SMAP .config
```  
load and save the .config file, then exit.
```
make menuconfig 
```
### compile the linux kernel as debian packages
```
make -j8 deb-pkg
cd ../ && ls -la
```
There would be four *.deb packages generated.

### install the new kernel
```
sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb 
sudo dpkg -i linux-image-5.3.18-dbg_5.3.18-1_amd64.deb
sudo dpkg -i linux-libc-dev_5.3.18-1_amd64.deb   
sudo dpkg -i linux-headers-5.3.18_5.3.18-1_amd64.deb 
```
    
### reboot and enter into the new kernel 5.3.18
During boot procedure, remember to select Advanced options for ..., then select 5.3.18 kernel, which is the modified oasis kernel we just installed.

## Compiling and installing the k-loader

### Create a symbolic link to imee.h in kernel
Go to oasis/k-loader/configure.sh and update the path to kernel's imee.h accordingly. 
execute configure.sh to create a symbolic link to imee.h .

### compile & install
```
make && sudo insmod ld.ko
```

## Building and installing the u-loader (Customized linker)

### Build then install
```
cd oasis/u-loader/
mkdir build-glibc
mkdir install
cd build-glibc
../glibc-2.27/configure --prefix=/<PATH-TO>/oasis/u-loader/install
make -j6 CFLAGS="-O2 -U_FORTIFY_SOURCE -fno-stack-protector"
make install
```
## oasis-lib

oasis-lib includes a collection of prebuilt binaries in the form of .so files. These are a collection of gates that fascilitate EFI-execution flow switches(Eg: switch between a target kernel thread and KRover). Use the .so files as-is. Re-compiling may change the ofsets between certain functions( or the start offcet of a certain function) within a given .so file causing oasis to malfunction.

## Build the launcher

### Update KRover binary path
Go to oasis/launcher/oasis-launcher.c and update the constant, KROVER_PATH accordingly.
Executable KRover binary named "testtest" should be available in KRover/loader/ directory.
Go to oasis/launcher/ and run compile.sh to generate the launcher binary.

# Building KRover

## Dependant libraries
KRover uses dyninst for binary instruction dissassembly and Z3 for constraint evaluation.

### Build dyninst

Download dyninst (https://github.com/dyninst/dyninst)



