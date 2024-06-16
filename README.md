#  ⌘ KRover ⌘
KRover is a Symbolic Execution Engine for Dynamic Kernel Analysis. This document will guide you through the setup of the necessary infrastructure and dependent systems needed for the execution of KRover. 

Happy KRoving !!!

## Included packages
This includes the following software packages.
### KRover: 
1. KRover: Symbolic execution engine.
### oasis: 
KRover is executed on OASIS infrastructure. OASIS consists of the following components.

2. kernel: A Linux kernel with modified KVM.
3. k-loader: A LKM that acts as a kernel loader.
4. u-loader: Modified libc to satisfy specific loading/address space requirements.
5. oasis-lib: A collection of binaries enabling specific OASIS features such as EFI: execution flow instrumentation.
6. launcher: System launcher, launches oasis and KRover.
#
#
# ⌘ Instructions for system setup ⌘
KRover executes on OASIS infrastructure. Thus, the first step is to set up the OASIS infrastructure. If you need more information about OASIS design and features, refer to our OASIS paper: "A novel dynamic analysis infrastructure to instrument untrusted execution flow across user-kernel spaces(IEEE SP21)".

## 1. Platform
OASIS needs to run on a bare-metal machine with the customized kernel specified above. The target kernel which will be analyzed using KRover would be executed in a VM. We recommend a host machine with Ubuntu. If your current Ubuntu does not match the following requirements or you do not want to disturb your current working environment, you can consider creating a new partition and installing a separate Ubuntu OS. Then your machine becomes a dual-boot Ubuntu system, do the following things in the new Ubuntu.

## 2. Requirements
1. Host OS: Ubuntu 18.04; Kernel version: Linux 5.4.X.
2. binutils: 2.30
3. gcc:7.5.0
4. [Install KVM and its related virt-manager toolchain](https://linuxize.com/post/how-to-install-kvm-on-ubuntu-18-04/)

## 3. Setup a guest VM
3.1. [Install a VM with Linux 5.4.X using virt-manager](https://www.tecmint.com/create-virtual-machines-in-kvm-using-virt-manager/4/)

3.2. Configure the guest VM: disable ASLR permanently
[reference](https://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization)
Add a file /etc/sysctl.d/01-disable-aslr.conf containing:
```
kernel.randomize_va_space = 0
```
3.3. Configure the guest VM: disable pti through the boot option
add 'nopti' after 'quite splash' in /etc/default/grub, then 
```
sudo update-grub2
```

## 4. Clone the KRover repo onto the host.
```
git clone https://github.com/KRoverSystems/KRover.git
```

## 5. Building and installing the OASIS kernel.

### 5.1 Install the required compilers and other tools
```
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev
```

### 5.2 Update oasis-lib path in imee.h
Go to oasis/kernel/linux-hwe-5.3.18/virt/kvm/imee.h
Update the constant, KROVER_OASIS_LIB_PATH accordingly. In this repo, the oasis-lib is available in oasis/oasis-lib/KRover-OASIS-Lib( See step 8 for more info.)

### 5.3 Configuring the kernel
confirm *CONFIG_X86_SMAP is not set* in the .config file. if *CONFIG_X86_SMAP = y*, change it to *CONFIG_X86_SMAP = n*.
```
cd oasis/kernel/Linux-hwe-5.3.18
grep CONFIG_X86_SMAP .config
```  
load and save the .config file, then exit.
```
make menuconfig 
```
### 5.4 Compile the Linux kernel as Debian packages
```
make -j`nproc` deb-pkg
cd ../ && ls -la
```
There would be four *.deb packages generated.

### 5.5 Install the new kernel
```
sudo dpkg -i Linux-image-5.3.18_5.3.18-1_amd64.deb 
sudo dpkg -i Linux-image-5.3.18-dbg_5.3.18-1_amd64.deb
sudo dpkg -i Linux-libc-dev_5.3.18-1_amd64.deb   
sudo dpkg -i Linux-headers-5.3.18_5.3.18-1_amd64.deb 
```
    
### 5.6 Reboot and enter into the new kernel 5.3.18
During the boot procedure, remember to select Advanced options for ..., then select 5.3.18 kernel, which is the modified oasis kernel we just installed.
you may choose to update /etc/default/grub or /boot/grub/grub.cfg to make the newly installed 5.3.18 kernel the default kernel whenever rebooting, to avoid the above troublesome selectings. 

### 5.7 Disable ASLR permanently
[reference](https://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization)
Add a file /etc/sysctl.d/01-disable-aslr.conf containing:
```
kernel.randomize_va_space = 0
```
### 5.8 Disable pti through the boot option
add 'nopti' after 'quite splash' in /etc/default/grub, then 
```
sudo update-grub2
```

## 6. Compiling and installing the k-loader

### 6.1 Create a symbolic link to imee.h in kernel
Go to oasis/k-loader/configure.sh and update the path to kernel's imee.h accordingly. 
Execute configure.sh to create a symbolic link to imee.h .

### 6.2 compile & install
```
make && sudo insmod ld.ko
```

## 7. Building and installing the u-loader (Customized linker)

### 7.1 Build then install
```
cd oasis/u-loader/
mkdir build-glibc
mkdir install
cd build-glibc
../KRover-u-loader/configure --prefix=/<PATH-TO>/oasis/u-loader/install
make -j`nproc` CFLAGS="-O2 -U_FORTIFY_SOURCE -fno-stack-protector"
make install
```
## 8. Use of oasis-lib

### 8.1 Notes 
oasis-lib includes a collection of prebuilt binaries in the form of .so files. These are a collection of gates that facilitate EFI-execution flow switches(Eg: switch between a target kernel thread and KRover). Use the .so files as-is. Re-compiling may change the offsets between certain functions( or the start offset of a certain function) within a given .so file causing oasis to malfunction.

### 8.2 Permission update
add x permission for the data_page file in springboard.
```
sudo chmod +x /<PATH-TO>/oasis/oasis-lib/KRover-OASIS-Lib/springboard/data_page
```

## 9. Build the launcher

### 9.1 Update KRover binary path
Go to oasis/launcher/oasis-launcher.c and update the constant, KROVER_PATH accordingly.
Once KRover is built later, an executable KRover binary named "testtest" will be available in KRover/loader/ directory.
Go to oasis/launcher/ and run compile.sh to generate the launcher binary named, oasis-launcher.


## 10. Install dependent libraries for KRover
KRover uses Dyninst for binary instruction disassembly and Z3 for constraint evaluation.

### 10.1 Dyninst dependencies
```
sudo apt install libiberty-dev
```
 Install cmake version > 3.13
```
sudo apt install texlive-full
```

### 10.2 Build dyninst
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

### 10.3 Build Z3

Download and install Microsoft Z3 version 4.8.14
Follow the instructions provided by the Z3 team.
(https://github.com/Z3Prover/z3/tree/z3-4.8.14)
 
## 11. Building KRover

### 11.1 Update Makefiles
Update all incomplete paths in the two Makefiles in KRover (DYNINST_PATH, Z3_PATH, etc.)

### 11.2 Update run script
Update run-Krover.sh with the path to oasis-launcher

### 11.3 Build KRover
```
cd KRover
./build-KRover.sh
```
KRover executable binary named, testtest will be generated in KRover/loader/ directory.
#
#
#  ⌘ POC example ⌘
This is a POC of how you can use KRover to symbolically execute a Linux syscall handler.

## 1. Build target
We have included a POC target user space program, poc.c in the "poc" directory. Copy this into the target guest VM and build the poc.c
```
gcc -fno-stack-protector poc.c -o target
```

## 2. Extract syscall handler addresses from the guest VM
Execute the following command in the target VM to obtain the list of syscall handler addresses from the target kernel.
```
sudo cat /proc/kallsyms >> ksyms.txt
```
Then, copy the contents of ksyms.txt into KRover/stc-files/kern_syms.txt .

## 3. KRover configurations and functionality
The following details are specific to the execution of the selected POC where we are trying to symbolically execute the getpriority syscall of the target kernel.

### 3.1 User analyzer
The user can leverage KRover as a library to write their own simple user analyzer. A POC analyzer to support the symbolic execution of getpriority is included in Analyze.cpp.

### 3.2 Selection of the syscall
The sample user analyzer included in Analyze.cpp, supports the symbolic execution of a selected system call. The user can select the syscall handler name in "CAnalyze::setupScallAnalysis()". To support the POC, we have set the syscall handler name for getpriority by selecting the corresponding kernel symbol name "__x64_sys_getpriority" in "Analyze::setupScallAnalysis()". The corresponding VA of the syscall handler is available in KRover/stc-files/kern_syms.txt .

### 3.3 Installation of the int3 breakpoint 
The POC user analyzer installs an int3 breakpoint at the start of the getpriority syscall handler in "CAnalyze::beginAnalysis()". The API, "InstallINT3Probe()" is used for this purpose.

### 3.4 Symbolization
The POC user analyzer uses the "defineSymbolsForScalls()" API to symbolize some syscall arguments passed to the syscall handler of getpriority. KRover supports both register and memory symbols.

### 3.5 POC analysis sequence
The analysis sequence enabled by the POC user analyzer is as follows.
1. main.cpp : Once the target thread is captured, control is passed to the user analyzer in Analyze.cpp to find the address of the getpriority syscall and install an int3 breakpoint at its start.
2. main.cpp > to_native(): Captured target VM thread is dispatched for naive execution. i.e. the target thread is executed in the onsite environment directly on the hardware(out of KRover). 
3. Once the target's native execution reaches the installed int3 breakpoint( at the syscall handler of getpriority), the int3 exception handler(main.cpp > int3_store_context() > int3_handler() ) receives control.
4. The int3 exception handler, int3_handler() passes control back to the user analyzer.
"execState->processAt()".
5. The POC analysis program("CAnalyze::beginAnalysis()" ) dispatches the target thread to thin controller("m_Thin->processFunction(addr)" ) for symbolic execution.
6. Thin controller single steps the syscall handler and conducts symbolic execution.
7. The POC analyzer terminates the analysis once the execution reaches the end of the syscall handler( See CAnalyze::onEndOfInsExec() ), and path constraints are provided for the user.
8. A sample symbolic execution trace for the symbolic execution of the syscall handler of getpriority is available in poc/poc_getpriority.trace .

## 3.6 Executing KRover
Make sure to have the k-loader installed in advance (If not done already). The execution includes two sequential steps as follows.
1. On the target VM, Execute the poc target program. Go to the directory of the poc.c,
```
./target
```
2. Next, on the host, launch the onsite environment and execute KRover as follows.
Go to KRover's directory,
```
./run-KRover.sh
```
