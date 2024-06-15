#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/kvm.h>
#include <cpuid.h>

/*Note: the launcher identifies KRover binary by its name "testtest"*/
#define KROVER_PATH "/FULL-PATH-TO>/KRover/loader/testtest"

struct arg_blk
{
    int instrum_flag;
    int pl_switch;
    unsigned long exit_gate_addr;
    unsigned long syscall_gate_addr;
    unsigned long syscall_gate_pa;
    unsigned long t_idt_va;
    unsigned long t_gdt_va;
    unsigned long t_tss_va;
    unsigned long t_idt_pa;
    unsigned long t_gdt_pa;
    unsigned long t_tss_pa;
    unsigned long t_tss1_pa;
    unsigned long t_tss2_pa;
    unsigned long stack_addr;
    unsigned long root_pt_addr;
    unsigned long shar_va;
    unsigned long shar_pa;
    unsigned long ana_t_tss_va;
    unsigned long ana_t_tss_pa;
    unsigned long ana_t_gdt_va;
    unsigned long ana_t_gdt_pa;
    unsigned long ana_t_idt_va;
    unsigned long ana_t_idt_pa;
    unsigned long ana_pf_c_code;
    unsigned long ana_pf_stack;
    // unsigned long virt_exec_area;
    // unsigned long virt_exec_phys_addr;
    unsigned long vcpu_fd;
    unsigned long syscall_flag;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rax;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
// QHQHQHQHQHQHQ add    
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long rbx;
    unsigned long rbp;
    unsigned long rss;
    unsigned long rflags;
    unsigned long rfs;
    unsigned long rgs;
    unsigned long rcs;
    unsigned long xcr0;
    pid_t pid;
// QHQHQHQHQHQHQ ----------------------------  
    unsigned long rcx;
    unsigned long ret_rax;
    unsigned long sstub_entry;
    unsigned long hard_cr3;
};

struct arg_blk args;

int kvm, vmfd, vcpufd;
struct kvm_run *run;
size_t mmap_size;
// QHQHQHQHQ
// add :

/*
 * List of XSAVE features Linux knows about:
 */
enum xfeature {
	XFEATURE_FP,
	XFEATURE_SSE,
	/*
	 * Values above here are "legacy states".
	 * Those below are "extended states".
	 */
	XFEATURE_YMM,
	XFEATURE_BNDREGS,
	XFEATURE_BNDCSR,
	XFEATURE_OPMASK,
	XFEATURE_ZMM_Hi256,
	XFEATURE_Hi16_ZMM,
	XFEATURE_PT_UNIMPLEMENTED_SO_FAR,
	XFEATURE_PKRU,

	XFEATURE_MAX,
};

#define XFEATURE_MASK_FP		(1 << XFEATURE_FP)
#define XFEATURE_MASK_SSE		(1 << XFEATURE_SSE)
#define XFEATURE_MASK_YMM		(1 << XFEATURE_YMM)
#define XFEATURE_MASK_BNDREGS		(1 << XFEATURE_BNDREGS)
#define XFEATURE_MASK_BNDCSR		(1 << XFEATURE_BNDCSR)
#define XFEATURE_MASK_OPMASK		(1 << XFEATURE_OPMASK)
#define XFEATURE_MASK_ZMM_Hi256		(1 << XFEATURE_ZMM_Hi256)
#define XFEATURE_MASK_Hi16_ZMM		(1 << XFEATURE_Hi16_ZMM)
#define XFEATURE_MASK_PT		(1 << XFEATURE_PT_UNIMPLEMENTED_SO_FAR)
#define XFEATURE_MASK_PKRU		(1 << XFEATURE_PKRU)

#define XFEATURE_MASK_FPSSE		(XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#define XFEATURE_MASK_AVX512		(XFEATURE_MASK_OPMASK \
					 | XFEATURE_MASK_ZMM_Hi256 \
					 | XFEATURE_MASK_Hi16_ZMM)

#define FIRST_EXTENDED_XFEATURE	XFEATURE_YMM
unsigned char q_tmp [4096] ;
struct kvm_cpuid2 *cpuid2 = (struct kvm_cpuid2 *)(void*)q_tmp ;

struct kvm_xcrs xcrs ;

//QHQQHQHQQHQ --------------

int main(int argc, char *argv[])
{

    const u_int8_t code[] = {
        0xf4,
    };
    int ret;
        
    cpu_set_t cpuset;
    CPU_ZERO (&cpuset);
    CPU_SET (2, &cpuset);
    sched_setaffinity (0, sizeof (cpuset), &cpuset);

    kvm = open("/dev/kvm", O_RDWR);
    printf ("kvm: %d\n", kvm);
    if (kvm == -1)
        err(1, "/dev/kvm");
    ret = ioctl (kvm, KVM_GET_API_VERSION, NULL);
    
    vmfd = ioctl (kvm, KVM_CREATE_VM, (unsigned long)0);
    
    /* change FD_CLOEXEC flag */
    int flags = fcntl (vmfd, F_GETFD);
    // printf ("vmfd: %d, flags: %lx\n", vmfd, flags);
    fcntl (vmfd, F_SETFD, 0);
    // flags = fcntl(vmfd, F_GETFD);
    // printf ("after reset, vmfd: %d, flags: %lx\n", vmfd, flags);
    /* / */

    u_int8_t* memory;
    memory = mmap (NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!memory)
        err (1, "allocating guest memory");
    // printf ("address of user memory: %p\n", memory);

    memcpy (memory, code, sizeof (code));

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0x1000,
        .memory_size = 0x1000,
        .userspace_addr = (u_int64_t)memory,
    };
    ret = ioctl (vmfd, KVM_SET_USER_MEMORY_REGION, &region);

    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
    if (vcpufd == -1)
        err(1, "KVM_CREATE_VCPU");
    /* change FD_CLOEXEC flag */
    flags = fcntl (vcpufd, F_GETFD);
    fcntl(vcpufd, F_SETFD, 0);
    printf ("vmfd: %d, vcpufd: %d. \n", vmfd, vcpufd);

    /* Map the shared kvm_run structure and following data.  */
    ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    mmap_size = ret;
    printf ("vcpu size: %x\n", ret);
    if (mmap_size < sizeof(*run))
        err(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (!run)
        err(1, "mmap vcpu");

// QHQHQHQHQ
// add:
    cpuid2->nent = 4000 / sizeof(cpuid2->entries[0]) ;
    printf ("before KVM_GET_SUPPORTED_CPUID, set nent as %d. \n\n", cpuid2->nent) ;
    ret = ioctl (kvm, KVM_GET_SUPPORTED_CPUID, cpuid2) ;
    printf ("KVM_GET_SUPPORTED_CPUID: return %d\n", ret) ;
    if (ret >= 0) {
	printf ("KVM_GET_SUPPORTED_CPUID, nent = %d\n", cpuid2->nent);
	for (int i = 0; i < cpuid2->nent; i++) {
        unsigned int eax, ebx, ecx, edx;
	    if(cpuid2->entries[i].function == 0x80000002 || cpuid2->entries[i].function == 0x80000003 || cpuid2->entries[i].function == 0x80000004) {
		__get_cpuid(cpuid2->entries[i].function,
		&cpuid2->entries[i].eax, &cpuid2->entries[i].ebx, &cpuid2->entries[i].ecx, &cpuid2->entries[i].edx) ; 
		
		// printf ("()()()()()\n") ;
	    }
        __get_cpuid_count(cpuid2->entries[i].function,cpuid2->entries[i].index, &eax, &ebx, &ecx, &edx) ;
	}
    }
    ret = ioctl (vcpufd, KVM_SET_CPUID2, cpuid2) ;
    
    ret = ioctl (kvm, KVM_GET_EMULATED_CPUID, cpuid2) ;
    if (ret >= 0) {
	for (int i = 0; i < cpuid2->nent; i++) {
	    //printf ("\n%03d, \tFunction: 0x%08x, index: 0x%08x, Flags: 0x%08x, \n\tEAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n",
		//i, cpuid2->entries[i].function, cpuid2->entries[i].index, cpuid2->entries[i].flags, 
		//cpuid2->entries[i].eax, cpuid2->entries[i].ebx, cpuid2->entries[i].ecx, cpuid2->entries[i].edx);
	}
    }

    ret = ioctl (kvm, KVM_CHECK_EXTENSION, KVM_CAP_XSAVE) ;
    ret = ioctl (kvm, KVM_CHECK_EXTENSION, KVM_CAP_XCRS) ;

    xcrs.nr_xcrs = KVM_MAX_XCRS ;
    ret = ioctl (vcpufd, KVM_GET_XCRS, &xcrs) ;
    if (ret >= 0) {
	for (int i = 0; i < xcrs.nr_xcrs; i++) {
	    printf ("\n%03d, xcr: 0x%08x, reserved: 0x%08x,  value: 0x%016llx\n",
		i, xcrs.xcrs[i].xcr, xcrs.xcrs[i].reserved, xcrs.xcrs[i].value);
	}
    }
    xcrs.nr_xcrs = 1 ;
    xcrs.xcrs[0].value |= 0x1f; //XFEATURE_MASK_AVX512 | XFEATURE_MASK_YMM | XFEATURE_MASK_SSE;
    ret = ioctl (vcpufd, KVM_SET_XCRS, &xcrs) ;
    printf("KVM_SET_XCRS returns %d\n", ret) ;
    
    xcrs.nr_xcrs = KVM_MAX_XCRS ;
    ret = ioctl (vcpufd, KVM_GET_XCRS, &xcrs) ;
    //printf ("again, KVM_GET_XCRS : return %d\n", ret) ;
    if (ret >= 0) {
	//printf ("KVM_GET_XCRS : nr_xcrs %d, flags 0x%x\n", xcrs.nr_xcrs, xcrs.flags) ;
	//for (int i = 0; i < xcrs.nr_xcrs; i++) {
	//    printf ("\n%03d, xcr: 0x%08x, value: 0x%016llx\n",
	//	i, xcrs.xcrs[i].xcr, xcrs.xcrs[i].value);
	//}
	//printf ("\n\nKVM_GET_XCRS print done.\n\n") ;	
    }
	
// QHQHQHQHQH ----------


    /* pass the vcpufd to run_imee */
    args.instrum_flag = 1;
    args.vcpu_fd = vcpufd;
    args.hard_cr3 = strtol(argv[1], NULL, 16);
    printf ("ready to run, hard_cr3: %lx. \n", args.hard_cr3);

    ret = ioctl(vcpufd, 0xAEB0, &args);
    if (ret == -1)
    {
        printf ("ret of 0xAEB0: %d. \n", ret);
        err(1, "KVM_OASIS_SETUP");
    }
    printf ("get guest context done !!!, sizeof arg_blk: %lx\n", sizeof(args));

    pid_t fpid = fork();
    if (!fpid) /* this is child process */
    {
        printf ("this is child process, pid: %d. \n", fpid);
        cpu_set_t cpuset;
        CPU_ZERO (&cpuset);
        CPU_SET (2, &cpuset);
        sched_setaffinity (0, sizeof (cpuset), &cpuset);
        
        char *ex_args[] = {KROVER_PATH, NULL, NULL};

        execve(ex_args[0], ex_args, NULL);
        printf ("execute failed. \n");
    }
    else
    {
        printf ("child process id: %d. \n", fpid);
        wait (NULL); /* wait till the child terminates */
    }
    
out:  
    ret = ioctl(vcpufd, 0xAEB2);
    printf ("OASIS stop: %d, exit reason: %d. \n", ret, run->exit_reason);
    
    return ret;
}
