#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/binfmts.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <asm/current.h>
#include <asm/desc.h>
#include <linux/mman.h>

#include "imee.h"

extern unsigned long UK_OFFSET;
extern struct arg_blk imee_arg;
extern unsigned long host_syscall_entry;

int my_load_elf_binary(struct linux_binprm *bprm);

void* old_loader_start;

unsigned char inst_stub[5];
unsigned char old_bytes[5];

unsigned long non_fix_mmap;
// int mmap_idx;

void old_loader_addr_init (void)
{
    old_loader_start = (void*) kallsyms_lookup_name("load_elf_binary");
    return;
}
// 
void print_bytes (void* p, int len)
{
    int i = 0;
    for ( ; i < len; i ++)
    {
        unsigned char* pp = (unsigned char*) p;
        printk ("%02x ", pp[i]);
    }
    printk ("\n");
    return;
}

void clear_WP_bit (void)
{
    unsigned long cr0;

    asm volatile ("movq %%cr0, %0;":"=r"(cr0)::);
    printk (KERN_ERR "changing CR0 from %X\n", cr0);
    cr0 &= ~(1 << 16);
    printk (KERN_ERR "to %X, WP_bit cleared.\n", cr0);
    asm volatile ("movq %0, %%cr0;"::"r"(cr0):);
}

void set_WP_bit (void)
{
    unsigned long cr0;

    asm volatile ("movq %%cr0, %0;":"=r"(cr0)::);
    printk (KERN_ERR "changing CR0 from %X\n", cr0);
    cr0 |= (1 << 16);
    printk (KERN_ERR "to %X, WP_bit set\n", cr0);
    asm volatile ("movq %0, %%cr0;"::"r"(cr0):);
}

int proc_filter (struct linux_binprm *bprm)
{
    // printk ("invoked. comm : %s. pid: %d \n", current->comm, current->pid);
    // printk ("bprm->filename: %s .\n", bprm->filename);
    if (strstr(bprm->filename, "testtest"))
    {
        printk ("testtest process. \n");
        int ret = my_load_elf_binary(bprm);
        // unsigned long* temp_rsp;
        // asm volatile("movq %%rsp, %0; \n\t"
        //         :"=m"(temp_rsp)::);
        // int i =0;
        // for (i; i<40; i ++)
        // {
        //     printk ("rsp: %p, content: %lx. \n", temp_rsp, *temp_rsp);
        //     temp_rsp ++;
        // }
        return ret;
    }
    else
        return 1;
}

static void branch (void);
asm (" .text");
asm (" .type    branch, @function");
asm ("branch: \n");
asm ("pushfq \n");
asm ("pushq %rax \n");
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rbp \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r10 \n");
asm ("pushq %r11 \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("callq proc_filter \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rbp \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rdx \n");
asm ("popq %rcx \n");
asm ("popq %rbx \n");

asm ("cmp $0x0, %rax \n");
asm ("je 1f \n");

asm ("popq %rax \n");
asm ("popfq \n");
asm ("retq \n");

asm ("1: \n");
asm ("addq $0x18, %rsp \n");
asm ("retq \n");

void elf_mod (void)
{
    old_loader_addr_init ();
    printk ("old code: ");
    print_bytes (old_loader_start, 26);
    printk ("addr of my_load_elf_binary: %px\n", branch);
    printk ("addr of old load_elf_binary: %px\n", old_loader_start);

    unsigned long offset = ((char*) branch) - ((char*) old_loader_start + 5);
    printk ("offset: %lx\n", offset);
    // inst_stub[0] = 0xe9;
    inst_stub[0] = 0xe8;
    inst_stub[1] = (offset >> 0) & 0xFF;
    inst_stub[2] = (offset >> 8) & 0xFF;
    inst_stub[3] = (offset >> 16) & 0xFF;
    inst_stub[4] = (offset >> 24) & 0xFF;
    printk ("inst_stub: ");
    print_bytes (inst_stub, 5);

    memcpy (old_bytes, old_loader_start, 5);
    memcpy (old_loader_start, inst_stub, 5);
    return;
}

int vcpu_entry(void);
int vcpu_reentry(void);
//?during interrupt, whehter swapgs by hardware? if not, swapgs before jump to
//system_call entry?
void syscall_bounce (void)
{
    unsigned long syscall_idx;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    unsigned long arg6;
    unsigned long ret_addr;
    unsigned long save_eflags;
    unsigned long rsp;
    syscall_idx = imee_arg.rax;
    arg1 = imee_arg.rdi;
    arg2 = imee_arg.rsi;
    arg3 = imee_arg.rdx;
    arg4 = imee_arg.r10;
    arg5 = imee_arg.r8;
    arg6 = imee_arg.r9;
    ret_addr = imee_arg.rip;
    save_eflags = imee_arg.r11;
    rsp = imee_arg.rsp;

    /* just for syscall performance testing */
    // if (syscall_idx == 0x27)
    // {
    //     unsigned long long t1;
    //     t1 = rdtsc();
    //     printk ("just before getpid handler, t1: %llx, t0: %llx, t1-t0: %d\n", t1, arg2, t1-arg2);
    // }
    /* / */
    /* TODO: it is likely issued by libc/ld in its initialization stage, since
     * the mmap addr is NULL, kernel is not assured to create the map within
     * the designed 512GB range, so I use this ugly solution ..... */
    if (syscall_idx == 9 && arg1 == NULL)
    {
        printk ("---------------------it is a non-fixed addr mmap with size: %lx. third-six args: %lx, %lx, %lx, %lx. \n", arg2, arg3, arg4, arg5, arg6);
        // if (mmap_idx == 1)
        // {
        //     mmap_idx ++;
        //     arg1 = 0x7ffff7ff6000;
        //     arg4 |= MAP_FIXED;
        //     printk ("adjust mmap addr as: %lx. \n", arg1);
        // }
        arg1 = non_fix_mmap;
        arg4 |= MAP_FIXED;
        printk ("adjust mmap addr as: %lx. \n", arg1);
        non_fix_mmap += ((arg2 + 0xfff) & ~0xfff);
        if (non_fix_mmap >= non_fix_mmap_end)
        {
            printk ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!address range for non-fixed mmap used up, terminate process. \n");
            syscall_idx = 231;
            arg1 = 0;
        }
        // if (arg2 == 0x2000)
        // {
        //     printk ("---------------------it is a 0x2000 sized non-fixed mmap. adjust it into a fixed mmap.\n");
        //     arg1 = 0x7ffff7ff9000;
        //     arg4 |= MAP_FIXED;
        // }
        // // else
        // // {
        // //     printk ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!unexpected non-fixed mmap, terminate process. \n");
        // //     syscall_idx = 231;
        // //     arg1 = 0;
        // // }
    }
    // DBG ("host_syscall_entry in syscall_bounce: %lx. \n", host_syscall_entry);

    asm volatile ("movq %0, %%rax; \n\t"
            "movq %1, %%rdi; \n\t"
            "movq %2, %%rsi; \n\t"
            "movq %3, %%rdx; \n\t"
            "movq %4, %%r10; \n\t"
            "movq %5, %%r8; \n\t"
            "movq %6, %%r9; \n\t"
            "movq %7, %%rcx; \n\t"
            "movq %8, %%r11; \n\t"
            "pushf; \n\t"
            "popq %%rbx; \n\t"
            "and $0xc8ff, %%rbx; \n\t"
            "pushq %%rbx; \n\t"
            "popf; \n\t"
            "movq %10, %%rbx; \n\t"
            "movq %9, %%rsp; \n\t"
            "swapgs; \n\t"//switch gs to user space gs before jump to system call entry 
            // "movq $0xffffffff817142b0, %%rbx; \n\t"
            "jmpq *%%rbx; \n\t"
            ::"m"(syscall_idx),"m"(arg1),"m"(arg2),"m"(arg3),"m"(arg4),"m"(arg5),"m"(arg6),"m"(ret_addr),"m"(save_eflags),"m"(rsp), "m"(host_syscall_entry):"%rax","%rdi","%rsi","%rdx","%r10","%r8","%r9","%rcx","%r11","%rsp");
    return;
}

static void clear_bp (void)
{
    asm volatile ("pushq %%rax; \n\t"
            "movq $0x0, %%rax; \n\t"
            "movq %%rax, %%DR0; \n\t"
            "movq $0x400, %%rax; \n\t"
            "movq %%rax, %%DR7; \n\t"
            "movq $0xfffe0ff0, %%rax; \n\t"
            "movq %%rax, %%DR6; \n\t"
            "popq %%rax; \n\t"
            :::"%rax");
    return;
}

// static void read_bp (void)
// {
//     unsigned long dr7, dr0;
//     asm volatile ("pushq %%rax; \n\t"
//             "movq %%DR7, %%rax; \n\t"
//             "movq %%rax, %0; \n\t"
//             "movq %%DR0, %%rax; \n\t"
//             "movq %%rax, %1; \n\t"
//             "popq %%rax; \n\t"
//             :"=m"(dr7), "=m"(dr0)::"%rax");
//     DBG ("initial value for DR7: %lx, DR0: %lx\n", dr7, dr0);
//     return;
// }

void noinline set_bp (unsigned long dr0, unsigned long dr7)
{
    asm volatile ("pushq %%rax; \n\t"
            "movq %0, %%rax; \n\t"
            "movq %%rax, %%DR0; \n\t"
            "movq %1, %%rax; \n\t"
            "movq %%rax, %%DR7; \n\t"
            "popq %%rax; \n\t"
            ::"m"(dr0), "m"(dr7):"%rax");
    // printk ("now dr0: %lx, dr7: %lx\n", dr0, dr7);
    return 0;
}


noinline unsigned long rdfsbase(void)
{
    volatile unsigned long fsbase = 0;
    volatile unsigned long cr4_old = 0;
    volatile unsigned long cr4_new = 0 ;

    asm volatile ("pushq %%rax; \n\t"
            "movq %%cr4, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            "or   $0x10000,%%rax \n\t"
            "movq %%rax, %%cr4; \n\t"
            "movq %%cr4, %%rax; \n\t"
            "movq %%rax, %1; \n\t"
            "rdfsbase %%rax; \n\t"
            "movq %%rax, %2; \n\t"
            "movq %0, %%rax; \n\t"
            //"movq %%rax, %%cr4; \n\t"
            "popq %%rax; \n\t"
            :"=m"(cr4_old), "=m"(cr4_new), "=m"(fsbase)
            ::"%rax");


    //printk ("cr4 old: 0x%lx, new: 0x%x, fsbase:0x%lx\n", cr4_old, cr4_new, fsbase) ;

    //*((unsigned long*)(0x86919128)) = 0 ;
    return fsbase;
}

noinline unsigned long rdgsbase(void)
{
    volatile unsigned long gsbase = 0;
    volatile unsigned long cr4_old = 0;
    volatile unsigned long cr4_new = 0 ;

    asm volatile ("pushq %%rax; \n\t"
            "movq %%cr4, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            "or   $0x10000,%%rax \n\t"
            "movq %%rax, %%cr4; \n\t"
            "movq %%cr4, %%rax; \n\t"
            "movq %%rax, %1; \n\t"
            "rdgsbase %%rax; \n\t"
            "movq %%rax, %2; \n\t"
            "movq %0, %%rax; \n\t"
            //"movq %%rax, %%cr4; \n\t"
            "popq %%rax; \n\t"
            :"=m"(cr4_old), "=m"(cr4_new), "=m"(gsbase)
            ::"%rax");


    //printk ("cr4 old: 0x%lx, new: 0x%x, gsbase:0x%lx, fsbase_stack:0x%lx\n", cr4_old, cr4_new, gsbase) ;

    //*((unsigned long*)(0x86919128)) = 0 ;
    return gsbase;
}

noinline unsigned long rdxcr0(void)
{
    volatile unsigned int xcr0_h = 0;
    volatile unsigned int xcr0_l = 0;

    asm volatile ("pushq %%rax; \n\t"
            "pushq %%rcx; \n\t"
            "pushq %%rdx; \n\t"
            "movq $0, %%rcx; \n\t"
            "xgetbv; \n\t"
            "mov %%eax, %1; \n\t"
            "mov %%edx, %0; \n\t"
            "popq %%rdx; \n\t"
            "popq %%rcx; \n\t"
            "popq %%rax; \n\t"
            :"=m"(xcr0_h), "=m"(xcr0_l)
            ::"%rax");


    printk ("xcr0_h: 0x%x, xcr0_l: 0x%x\n", xcr0_h, xcr0_l) ;

    //*((unsigned long*)(0x86919128)) = 0 ;
    return ((unsigned long)xcr0_h<<32) | (unsigned long)xcr0_l;
}

/*
static unsigned long rdfsbase(void)
{
    volatile unsigned long fsbase = 0;

    // read fs register.
    asm volatile("rdfsbase %0" : "=r" (fsbase) :: "memory");

    return fsbase;
}
*/
#define DB_HANDLER_STACK_RSS_OFFSET   20 
#define DB_HANDLER_STACK_RSP_OFFSET   19 
#define DB_HANDLER_STACK_RFLAG_OFFSET 18 
#define DB_HANDLER_STACK_RCS_OFFSET   17 
#define DB_HANDLER_STACK_RIP_OFFSET   16 
#define DB_HANDLER_STACK_RBX_OFFSET   15 
#define DB_HANDLER_STACK_RBP_OFFSET   14 
#define DB_HANDLER_STACK_R12_OFFSET   13 
#define DB_HANDLER_STACK_R13_OFFSET   12 
#define DB_HANDLER_STACK_R14_OFFSET   11 
#define DB_HANDLER_STACK_R15_OFFSET   10 
#define DB_HANDLER_STACK_RCX_OFFSET   9  
#define DB_HANDLER_STACK_R11_OFFSET   8  
#define DB_HANDLER_STACK_RAX_OFFSET   7  
#define DB_HANDLER_STACK_RDI_OFFSET   6  
#define DB_HANDLER_STACK_RSI_OFFSET   5  
#define DB_HANDLER_STACK_RDX_OFFSET   4  
#define DB_HANDLER_STACK_R8_OFFSET    3  
#define DB_HANDLER_STACK_R9_OFFSET    2  
#define DB_HANDLER_STACK_R10_OFFSET   1  
//#define DB_HANDLER_STACK_R11_OFFSET   0  

// int isDR1 (void) {
//     unsigned long dr6 = 0, dr7 = 0 ;
// 
//     asm volatile ("movq %%DR6, %%rax; \n\t"
//         "movq %%rax, %0; \n\t"
//         "movq %%DR7, %%rax; \n\t"
//         "movq %%rax, %1; \n\t"
//         :"=m"(dr6),"=m"(dr7)::"%rax");
// 
//     if (dr6 & 0x2) { // db1 status bit is set.
//         if (dr7 & 0x4) { // db1 is enabled.
//             return 1 ;
//         }
//     }
//     return 0 ;
// }

static int isDR1 (void);
asm (" .text");
asm (".globl NO_DR1");
asm (" .type    isDR1, @function");
asm ("isDR1: \n");
asm ("mov    %DR6,%rax\n");
asm ("testb   $0x2,%al\n");
asm ("je      NO_DR1\n");
asm ("mov    %DR7,%rax\n");
asm ("testb  $0x4,%al\n");
asm ("je      NO_DR1\n");
asm ("mov     $1, %rax\n");
asm ("retq \n");
asm ("NO_DR1:\n");
asm ("mov     $0, %rax\n");
asm ("retq \n");

void EnableDR1(int bEn) {
    unsigned long dr1, dr7, dr6 = 0xfffe0ff0;

    asm volatile ("movq %%DR1, %%rax; \n\t"
        "movq %%rax, %0; \n\t"
        "movq %%DR7, %%rax; \n\t"
        "movq %%rax, %1; \n\t"
        :"=m"(dr1),"=m"(dr7)::"%rax");

    if(bEn) 
        dr7 |= 0x404 ;
    else {
        dr1 = 0 ;
        dr7 &= ~0x4 ;
        dr7 |= 0x400 ;
    }

    asm volatile ("movq %0, %%rax; \n\t"
        "movq %%rax, %%DR1; \n\t"
        "mfence; \n\t"
        "movq %1, %%rax; \n\t"
        "movq %%rax, %%DR7; \n\t"
        "movq %2, %%rax; \n\t"
        "movq %%rax, %%DR6; \n\t"
        ::"m"(dr1), "m"(dr7), "m"(dr6):"%rax");
        smp_mb();
}
void adjust_mmap_arg (unsigned long *rsp)
{
    unsigned long *rip  = &rsp[DB_HANDLER_STACK_RIP_OFFSET];

    // first 5 bytes are : callq <__fentry__>, no use.
    *rip = (*rip) + 5 ;
    
    if (strstr(current->comm, "testtest")) {
        unsigned long *rdi = (unsigned long*)rsp[DB_HANDLER_STACK_RDI_OFFSET], 
            *arg1, *arg2, *arg3, *arg4, *arg5, *arg6 ;

        printk ("adjust_mmap_arg: rdi is: %lx. \n", (unsigned long)rdi);

        // this is come from disassembe code of __X64_sys_mmap.
        // we should change it with pt_regs.
        arg1 = &rdi[0x70/8] ; 
        arg2 = &rdi[0x68/8] ;
        arg3 = &rdi[0x60/8] ;
        arg4 = &rdi[0x38/8] ;
        arg5 = &rdi[0x48/8] ;
        arg6 = &rdi[0x40/8] ;

        if (*arg1 == 0) {

            printk ("adjust_mmap_arg: it is a non-fixed addr mmap with size: %lx. \n", *arg2);

            *arg1 = non_fix_mmap;
            *arg4 |= MAP_FIXED;
            printk ("adjust mmap addr as: %lx. \n", *arg1);
            non_fix_mmap += ((*arg2 + 0xfff) & ~0xfff);
            if (non_fix_mmap >= non_fix_mmap_end)
            {
                printk ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!address range for non-fixed mmap used up, terminate process. \n");

                *arg1 = 0;
            }
        } else if (*arg1<user_start || *arg1>user_end) {
            printk ("adjust_mmap_arg: mmap address 0x%lx out of range. 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx   \n", 
                *arg1, *arg2, *arg3, *arg4, *arg5, *arg6, *rip);
            // int i = 0 ;
            // for (i = 0; i <= 0x70; i+=8) {
            //     printk ("adjust_mmap_arg: 0x%x\t\t0x%lx\n\n", i, rdi[i/8]) ;
            // }
            // 
            // for (i = 0; i <= 20; i++) {
            //     printk ("adjust_mmap_arg stack: 0x%x\t\t0x%lx\n\n", i, rsp[i]) ;
            // }
        }
    }
}

void enter_vcpu (unsigned long arg, unsigned long *rsp)
{
    int r;
    unsigned long dr_s, dr_z;

    // QHQHQHQQHQ add (if/else, if part.)
    if (isDR1()) {
        // this is mmap. dr1 hit.
        printk ("this is a DR1, %lx \n", rsp[DB_HANDLER_STACK_RIP_OFFSET]);
        adjust_mmap_arg(rsp) ;
        
        EnableDR1(1) ;

        return ;
    }
    
    asm ("swapgs \n");

    clear_bp();
    // DBG ("bp triggered, rax: %lx \n", arg);

    // dr0.
    if (strstr(current->comm, "testtest"))
    {
        if (imee_arg.syscall_flag == 0)//this is return from execve // or mmap in uloader.
        {            
            // QHQHQHQHQH
            // move this to elf.c, when setup break point.            
            /* init non_fix_mmap */
            // non_fix_mmap = non_fix_mmap_start;
            // QHQHQHQHQHQH            
            /* / */

            // QHQQHQHQHQHQ add
            // disable dr1, uloader finished, we go on-site, don't need trap mmap.
            EnableDR1(false) ;

            imee_arg.rss          = rsp[DB_HANDLER_STACK_RSS_OFFSET  ];
            imee_arg.rsp          = rsp[DB_HANDLER_STACK_RSP_OFFSET  ];
            imee_arg.rflags       = rsp[DB_HANDLER_STACK_RFLAG_OFFSET];
            imee_arg.rcs          = rsp[DB_HANDLER_STACK_RCS_OFFSET  ];
            imee_arg.rip          = rsp[DB_HANDLER_STACK_RIP_OFFSET  ];
            imee_arg.rbx          = rsp[DB_HANDLER_STACK_RBX_OFFSET  ];
            imee_arg.rbp          = rsp[DB_HANDLER_STACK_RBP_OFFSET  ];
            imee_arg.r12          = rsp[DB_HANDLER_STACK_R12_OFFSET  ];
            imee_arg.r13          = rsp[DB_HANDLER_STACK_R13_OFFSET  ];
            imee_arg.r14          = rsp[DB_HANDLER_STACK_R14_OFFSET  ];
            imee_arg.r15          = rsp[DB_HANDLER_STACK_R15_OFFSET  ];
            imee_arg.rcx          = rsp[DB_HANDLER_STACK_RCX_OFFSET  ];
            imee_arg.r11          = rsp[DB_HANDLER_STACK_R11_OFFSET  ];
            imee_arg.rax          = rsp[DB_HANDLER_STACK_RAX_OFFSET  ];
            imee_arg.rdi          = rsp[DB_HANDLER_STACK_RDI_OFFSET  ];
            imee_arg.rsi          = rsp[DB_HANDLER_STACK_RSI_OFFSET  ];
            imee_arg.rdx          = rsp[DB_HANDLER_STACK_RDX_OFFSET  ];
            imee_arg.r8           = rsp[DB_HANDLER_STACK_R8_OFFSET   ];
            imee_arg.r9           = rsp[DB_HANDLER_STACK_R9_OFFSET   ];
            imee_arg.r10          = rsp[DB_HANDLER_STACK_R10_OFFSET  ];
            //            imee_arg.r11          = rsp[DB_HANDLER_STACK_R11_OFFSET  ];

            imee_arg.rfs  = rdfsbase() ;
            imee_arg.rgs  = rdgsbase() ;
            imee_arg.xcr0  = rdxcr0() ;

            DBG("rfs: 0x%lx, xcr0: 0x%lx\n", imee_arg.rfs, imee_arg.xcr0) ;
            //DBG("enter_vcpu() -> stack: 0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx\n",
            //   rsp[16] ,rsp[17] ,rsp[18] ,rsp[19] ,rsp[20] ,rsp[20] ) ;

            //*((unsigned long*)(0x86919128)) = 0 ;
            //DBG("enter_vcpu() -> stack: 0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx",
             //  rsp[16] ,rsp[17] ,rsp[18] ,rsp[19] ,rsp[20] ,rsp[21] ) ;
            // QHQHQHQHQHQ------------------------
            r = vcpu_entry();
            printk ("return from first time vcpu enter, r = %d\n", r);
            if (r == -2)//this is vmcall due to syscall in dota mode
            {
                dr_s = 0x401;
                dr_z = imee_arg.rip;
                set_bp(dr_z, dr_s);
                syscall_bounce ();
            }
            else 
            {
                printk ("onsite process should exit due to unexpected error, returned r: %d from vcpu_entry \n", r);
                /* sth went wrong in oasis life cycle, free oasis related objects and issue exit syscall directly? */
                imee_arg.rax = 231;
                imee_arg.rdi = 0;
                syscall_bounce ();
                // arg2 = imee_arg.rsi;
                // arg3 = imee_arg.rdx;
                // arg4 = imee_arg.r10;
                // arg5 = imee_arg.r8;
                // arg6 = imee_arg.r9;
                // ret_addr = imee_arg.rip;
                // save_eflags = imee_arg.r11;
                // rsp = imee_arg.rsp;
            }
        }
        else if (imee_arg.syscall_flag == 1)//this is return from syscall iuused from dota mode, as syscall_flag is set as 1 in the very first vcpu_entry
        {
            if (imee_arg.rax == 0xc || imee_arg.rax == 0x9 || imee_arg.rax == 30)//brk; mmap; shmat;
            {
                // if (arg == 0xffffffffffffffff)//return error in these syscall handling
                if (arg > user_end || arg < user_start)//return error in these syscall handling
                {
                    printk ("mmap/brk/shmat return pointer outside of user address range. return: %lx, user_start: %lx, user_end: %lx. \n", arg, user_start, user_end);
                    imee_arg.ret_rax = arg;
                }
                else
                {
                    // DBG ("arg: %lx. \n", arg);
                    imee_arg.ret_rax = arg + UK_OFFSET;
                }
            }
            else//for brk, the return value is 0/-1, not true?
            {
                if (imee_arg.rax == 19 || imee_arg.rax == 20)//readv; writev; the adjusted memory should be adjusted back
                {
                    unsigned long iov_ptr_addr;
                    // unsigned long iov_addr;
                    iov_ptr_addr = imee_arg.rsi;
                    // iov_addr = *((unsigned long *) iov_ptr_addr);
                    *((unsigned long*)iov_ptr_addr) += UK_OFFSET;
                }

                else if (imee_arg.rax == 46 || imee_arg.rax == 47)//sendmsg; recvmsg;
                {
                    unsigned long* msghdr_addr;
                    unsigned long msg_name_addr;
                    unsigned long msg_iov_ptr_addr;
                    unsigned long msg_iov_addr;
                    unsigned long msg_control_addr;
                    msghdr_addr = imee_arg.rsi;
                    msg_name_addr = msghdr_addr;
                    msg_iov_ptr_addr = msghdr_addr + 0x2;
                    msg_iov_addr = *((unsigned long*) msg_iov_ptr_addr);
                    msg_control_addr = msghdr_addr + 0x4;
                    *((unsigned long*)msg_name_addr) += UK_OFFSET;
                    *((unsigned long*)msg_iov_ptr_addr) += UK_OFFSET;
                    *((unsigned long*)msg_control_addr) += UK_OFFSET;
                    *((unsigned long*)msg_iov_addr) += UK_OFFSET;
                }
                // printk ("return value for brk: %lx\n", arg);
                //
                //for debug
                else if (imee_arg.rax == 51)//getsockname
                {
                    unsigned long* temp_ptr;
                    temp_ptr = imee_arg.rsi;
                    printk ("temp_ptr: %p, content: %lx\n", temp_ptr, *temp_ptr);
                    temp_ptr ++;
                    printk ("temp_ptr: %p, content: %lx\n", temp_ptr, *temp_ptr);
                }

                imee_arg.ret_rax = arg;
            }
            printk ("return from syscall handling, ret value: %lx. \n", imee_arg.ret_rax);
            r = vcpu_reentry();
            // printk("when return from dota mode, cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
            // r = -5;
            // return;
            if (r == -2)
            {
                if (imee_arg.rax != 231)//set bp if not exit_group syscall
                {
                    dr_s = 0x401;
                    dr_z = imee_arg.rip;
                    set_bp(dr_z, dr_s); 
                }
                syscall_bounce ();
            }
            else 
            {
                printk ("onsite process should exit due to unexpected error, returned r: %d from vcpu_reentry \n", r);
                /* sth went wrong in oasis life cycle, free oasis related objects and issue exit syscall directly? */
                imee_arg.rax = 231;
                imee_arg.rdi = 0;
                syscall_bounce ();
                // arg2 = imee_arg.rsi;
                // arg3 = imee_arg.rdx;
                // arg4 = imee_arg.r10;
                // arg5 = imee_arg.r8;
                // arg6 = imee_arg.r9;
                // ret_addr = imee_arg.rip;
                // save_eflags = imee_arg.r11;
                // rsp = imee_arg.rsp;
            }
        }
    }
    clear_bp();
    asm ("swapgs \n");
// out:
    return;
}
 //wtf? : adjust_imee_vcpu: rip=0x7f00000009f0, 0x7f00000009f0, rsp=0x2b, rdx=0x7f7ff7ddf2c0
static void debug_handler (void);
asm (" .text");
asm (" .type    debug_handler, @function");
asm ("debug_handler: \n");
// asm ("cli \n");
// asm ("swapgs \n");
                                                                // #define DB_HANDLER_STACK_RSS_OFFSET   20   rsp[20]=SS
                                                                // #define DB_HANDLER_STACK_RSP_OFFSET   19   rsp[19]=RSP                                                                
                                                                // #define DB_HANDLER_STACK_RFLAG_OFFSET 18   rsp[18]=RFLAGS  
                                                                // #define DB_HANDLER_STACK_RCS_OFFSET   17   rsp[17]=CS
                                                                // #define DB_HANDLER_STACK_RIP_OFFSET   16   rsp[16]=RIP
asm ("pushq %rbx \n");                                          // #define DB_HANDLER_STACK_RBX_OFFSET   15   rsp[15] 
asm ("pushq %rbp \n");                                          // #define DB_HANDLER_STACK_RBP_OFFSET   14   rsp[14]
asm ("pushq %r12 \n");                                          // #define DB_HANDLER_STACK_R12_OFFSET   13   rsp[13]
asm ("pushq %r13 \n");                                          // #define DB_HANDLER_STACK_R13_OFFSET   12   rsp[12]
asm ("pushq %r14 \n");                                          // #define DB_HANDLER_STACK_R14_OFFSET   11   rsp[11]
asm ("pushq %r15 \n");                                          // #define DB_HANDLER_STACK_R15_OFFSET   10   rsp[10]
asm ("pushq %rcx \n");//save user space rip                     // #define DB_HANDLER_STACK_RCX_OFFSET   9    rsp[9]
asm ("pushq %r11 \n");//save user space eflags                  // #define DB_HANDLER_STACK_R11_OFFSET   8    rsp[8]
asm ("pushq %rax \n");//save return value of syscall            // #define DB_HANDLER_STACK_RAX_OFFSET   7    rsp[7]
asm ("pushq %rdi \n");                                          // #define DB_HANDLER_STACK_RDI_OFFSET   6    rsp[6]
asm ("pushq %rsi \n");                                          // #define DB_HANDLER_STACK_RSI_OFFSET   5    rsp[5]
asm ("pushq %rdx \n");                                          // #define DB_HANDLER_STACK_RDX_OFFSET   4    rsp[4]
asm ("pushq %r8 \n");                                           // #define DB_HANDLER_STACK_R8_OFFSET    3    rsp[3]
asm ("pushq %r9 \n");                                           // #define DB_HANDLER_STACK_R9_OFFSET    2    rsp[2]
asm ("pushq %r10 \n");                                          // #define DB_HANDLER_STACK_R10_OFFSET   1    rsp[1]
asm ("pushq %r11 \n");                                          // #define DB_HANDLER_STACK_R11_OFFSET   0    rsp[0]
asm ("movq %rsp, %rsi \n") ;
asm ("movq %rax, %rdi \n");//the arg of deter should be passed in register
asm ("callq enter_vcpu \n");
// // asm ("callq new_handler \n");
// asm ("movq $0x400, %rax \n");
// asm ("movq %rax, %DR7 \n");
// asm ("movq $0x0, %rax \n");
// asm ("movq %rax, %DR0 \n");
// asm ("movq $0xfffe0ff0, %rax \n");
// asm ("movq %rax, %DR6 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");
asm ("popq %r11 \n");
asm ("popq %rcx \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
//asm ("swapgs \n");
// asm ("sti \n");
asm ("iretq \n");

unsigned long* idt;
unsigned long old_debug_desc;
void debug_mod (void)
{
    unsigned char idtr[10];
    gate_desc s;

    asm ("sidt %0":"=m"(idtr)::);

    idt = (unsigned long*)(*(unsigned long*)(idtr + 2));
    DBG ("idt: %lx\n", *idt);
    
    old_debug_desc = idt[3];
    DBG ("old_debug_desc: %lx\n", old_debug_desc);
    old_debug_desc = idt[2];
    DBG ("old_debug_desc: %lx\n", old_debug_desc);
    pack_gate (&s, GATE_INTERRUPT, (unsigned long) debug_handler, 0, 3, __KERNEL_CS);//0:dpl; 3:ist;
    printk ("new_debug_desc: %lx\n", *((unsigned long*)(&s)));
    idt[0x1*2] = *((unsigned long*) (&s));
    // //idt[0x1*2 + 1] = 0x00000000ffffffffUL;
    // unsigned long cr3;
    // asm volatile("movq %%cr3, %%rax; \n\t"
    //         "movq %%rax, %0; \n\t"
    //         :"=m"(cr3)::"%rax");
    // // printk ("----------------------cr3 in insmod breakpoint: %lx\n", cr3);
    return;
}

//pp-s @Hq
extern void    init_linux_binfmt (void) ;
//pp-e

int init ( void)
{

    // WP bit may be getting into our way...
    clear_WP_bit ();
    
    //pp-s @Hq
    init_linux_binfmt () ;
    //pp-e

    elf_mod ();


    debug_mod ();

    /* init non-fix-mmap */
    // non_fix_mmap = non_fix_mmap_start;
    // mmap_idx = 1;

    set_WP_bit ();

    printk ("backup old code: ");
    print_bytes (old_bytes, 5);
    printk ("new loader code: ");
    print_bytes (old_loader_start, 5);

    // now crash..

    return 0;
}

void clean ( void )
{
    clear_WP_bit ();
    memcpy (old_loader_start, old_bytes, 5);
    DBG ("recover old_loader_code. \n");
    
    idt[2] = old_debug_desc;
    DBG ("recover debug_desc as: %lx\n", idt[2]);
    
    set_WP_bit ();
}

MODULE_LICENSE ("GPL");
module_init (init);
module_exit (clean);
