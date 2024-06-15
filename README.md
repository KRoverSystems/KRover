# KRover
KRover is a Symbolic Execution Engine for Dynamic Kernel Analysis. This document will guide you through the setup of the necessary infrastructure and dependant systems needed to for the execution of KRover. Happy KRoving !!!

# Included packages
This package includes the following software packages.
### KRover: 
1. KRover symbolic execution engine.
### oasis
OASIS infrastructure on which KRover is executed. OASIS consists of the following components.
2. kernel : A lnux kernel with modified KVM.
3. k-loader : A LKM that acts as a kernel loader.
4. u-loader : Modified libc to satisfy specific loading/address space requirements.
5. oasis-lib : A collection of binaries enabling specific OASIS features such as EFI: execution flow instruentation.
6. launcher : System launcher, launches oasis and KRover.

# Instructions for system setup
First step is to setup the OASIS infrastructure. If you need more information abount OASIS design, features and EFI, refer to our OASIS paper from SP21: "A novel dynamic analysis infrastructure to instrument untrusted execution flow across user-kernel spaces".

## Platform
OASIS needs to run on a bare-metal machine with the customzed kernel specified above. The target kernel which will be analyzed using KRover would be executed in a VM. We recomment a host machine with Ubuntu. If your current Ubuntu does not match with the following requirements or you do not want to disturb your current working environment, you can consider creating a new partition and installing a separate Ubuntu OS. Then your machine becomes a dual-boot Ubuntu system, do the following things in the new Ubuntu. It's also okay to skip the step if there is no conflict.

## Requirements
1. Host OS: Ubuntu 18.04; Kernel version: linux 5.4.X.
2. binutils: 2.30
3. gcc:7.5.0
4. [Install kvm and its related virt-manager toolchain](https://linuxize.com/post/how-to-install-kvm-on-ubuntu-18-04/)

## Setup a guest VM
1. [Install a VM with linux 5.4.X using virt-manager](https://www.tecmint.com/create-virtual-machines-in-kvm-using-virt-manager/4/)
2. Configure the guestVM: disable ASLR permanently
[reference](https://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization)
Add a file /etc/sysctl.d/01-disable-aslr.conf containing:
```
kernel.randomize_va_space = 0
```
3. Configure the guestVM: disable pti through boot option
add 'nopti' after 'quite splash' in /etc/default/grub, then 
```
sudo update-grub2
```

## Clone the KRover repo on to host.
```
git clone https://github.com/KRoverSystems/KRover.git
```

## Building and installing the OASIS kernel.

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
make -j`nproc` deb-pkg
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
you may choose to update /etc/default/grub or /boot/grub/grub.cfg to make the 5.3.18 as the default kernel whenever reboot, to avoid the above troublesome selectings. 

### disable ASLR permanently
[reference](https://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization)
Add a file /etc/sysctl.d/01-disable-aslr.conf containing:
```
kernel.randomize_va_space = 0
```
### disable pti through boot option
add 'nopti' after 'quite splash' in /etc/default/grub, then 
```
sudo update-grub2
```

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
make -j`nproc` CFLAGS="-O2 -U_FORTIFY_SOURCE -fno-stack-protector"
make install
```
## oasis-lib

oasis-lib includes a collection of prebuilt binaries in the form of .so files. These are a collection of gates that fascilitate EFI-execution flow switches(Eg: switch between a target kernel thread and KRover). Use the .so files as-is. Re-compiling may change the ofsets between certain functions( or the start offcet of a certain function) within a given .so file causing oasis to malfunction.

## Build the launcher

### Update KRover binary path
Go to oasis/launcher/oasis-launcher.c and update the constant, KROVER_PATH accordingly.
Executable KRover binary named "testtest" should be available in KRover/loader/ directory.
Go to oasis/launcher/ and run compile.sh to generate the launcher binary named, oasis-auncher.


# Dependant libraries for KRover
KRover uses dyninst for binary instruction dissassembly and Z3 for constraint evaluation.

## dyninst dependancies
```
sudo apt install libiberty-dev
```
    Install cmake version > 3.13
```
sudo apt install texlive-full
```

## Build dyninst
```
        git clone https://github.com/dyninst/dyninst.git
        cd dyninst
        git checkout -b V12 v12.0.0
        cd ..
        mkdir dyninst_build && cd dyninst_build
        cmake ../dyninst -DCMAKE_INSTALL_PREFIX=`pwd`/../install -DSTERILE_BUILD=OFF
        make -j`nproc`
        make install
```

## Build Z3

Download and install Microsoft Z3 version 4.8.14 .
Follow the instructions provided by the Z3 team.
(https://github.com/Z3Prover/z3/tree/z3-4.8.14)
 
# Building KRover

## Update Makefiles
Update the all missing paths in the two Makefiles in KRover (DYNINST_PATH, Z3_PATH etc.)

## Update run script
Update run-Krover.sh with the path to oasis-launcher

## Build KRover
```
cd KRover
./build-KRover.sh
```
KRover executable binary named, testtest will be generated in KRover/loader/ directory.

# Symbolic execution of a syscall handler
This is a POC of how you can use KRover to symbolically execute a Linux syscall handler.

## Build target
We have included a POC target user space program, poc.c in "targets" directory. Copy this into the target guest VM and build the poc.c
```
gcc poc.c -o target
```

## Extract syscall handler addresses from the guest VM
Execute the following command in the target VM to obtain the list of syscall handler addresses from the target kernel.
```
sudo cat /proc/kallsyms >> ksyms.txt
```
Then, copy the contents of ksyms.txt in to KRover/stc-files/kern_syms.txt .

## KRover configurations and functionality
The following details are specific to the execution of the selected poc where we are trying to symbolically execute the getpriority syscall of the target kernel.

### User analyzer
The user can leverage KRover as a library to write their own sinple user analyser. A POC analyzer to suppport the symbolic execution of getpriority is included in Analyze.cpp.

### Selection of the syscall
The simple user analyzer included in Analyze.cpp, supports the symbolic execution of more that 50 system calls. The user can select the syscall handler name in "void CAnalyze::setupScallAnalysis()". To support the POC, we have set the syscall handler name for get_priority by selecting the kernel symbol name "__x64_sys_getpriority" in "void  Analyze::setupScallAnalysis()". The corresponding VA of the syscall handler is available in KRover/stc-files/kern_syms.txt .

### Installation of the int3 breakpoint 
The POC user analyzer installs an int3 breakpoint at the start of the getpriority syscall handler in bool CAnalyze::beginAnalysis(ulong addr). The API, "InstallINT3Probe()" is used for this purpose.

### Symbolization
The POC user analyzer uses "defineSymbolsForScalls()" API to symbolize some syscall arguments passed to the syscall handler of getpriority. KRover supports both register and memory symbols.

### POC Analysis sequence
The analysis sequence anabled by the POC user analyzer is as follows.
1. main.cpp : Once the target thred is captured, controlled is passed to the user analyzer in Analyze.cpp to find the address of the getpriority syscall and install an int3 breakpoint at its start.
2. main.cpp > to_native : Captured target VM thread is dispatched for naive execution. i.e. the target thread is executed in onsite environment directly on hardware(out of KRover). 
3. Once the target's native exection reaches the installed int3 breakpoint( at the syscall handler of getpriority), the int3 exception handler(main.cpp > int3_store_context() > int3_handler() ) receives control.
4. The int3 exception handler, int3_handler() passes control back to the user analyzer.
"execState->processAt()".
5. The POC analysis program("CAnalyze::beginAnalysis()" ) dispatches the target thread to thin controller("m_Thin->processFunction(addr)" ) for symbolic execution.
6. Thin controller single steps the syscall handler and conduct symbolic execution.
7. The POC analyzer terminates the analysis once the execution reaches the end of the syscall handler( See CAnalyze::onEndOfInsExec() ), and path constrains are provided for the user.
8. A sample symbolic execution trace for the symbolic execution of the syscall handler of getpriority is available in target/poc_getpriority.trace .

# Executing KRover
Make sure to have the k-loader installed in advance (If not done already).
1. On target VM, Execute the poc target program
Go to the directory of the poc.c,
```
./target
```
3. Then on host, launch onsite environment and execute KRover as follows.
Go to KRover's directory,
```
./run-KRover.sh
```