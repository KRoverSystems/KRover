#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <link.h>
#include <linux/types.h>
#include <iostream>
#include <fstream>
#include <asm/ptrace.h>

#include "centralhub.h"
#include "CPUState.h"
#include "dyn_regs.h"
#include "defines.h"
#include "AnaCtrl.h"
#include "CodeSource.h"
#include "InstructionDecoder.h"
#include "Instruction.h"

using namespace Dyninst;
using namespace Dyninst::x86_64;
using namespace ParseAPI;
using namespace InstructionAPI;

/* definition from Target VM */
#define __START_KERNEL_MAP 0xffffffff80000000
#define PAGE_OFFSET 0xffff888000000000


struct shar_arg
{
    volatile unsigned long flag;//1: ready to receive analysis request; 2: a new analysis request issued by guest hyp; 3: analysis request handling done. 
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long rcx;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
    unsigned long r10;
    unsigned long rax;
    unsigned long eflags;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rbx;
    unsigned long rbp;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long fs_base;
    unsigned long gs_base;
    unsigned long msr_kernel_gs_base;
    unsigned long gdt;
    unsigned long idt;
    unsigned long tss_base;
    unsigned long tss_pg_off;
    unsigned long g_syscall_entry;
    unsigned long pf_entry;
    unsigned long int3_entry;
    unsigned long cr0;
    unsigned long cr2;
    unsigned long cr3;
    unsigned long cr4;
    unsigned long efer;
    unsigned long apic_base_addr;
    unsigned long apic_access_addr;
    unsigned long io_bitmap_a_addr;
    unsigned long io_bitmap_b_addr;
    unsigned long msr_bitmap_addr;
    unsigned long tsc_offset;
    unsigned long exit_reason;
    unsigned long exit_qualification;
    unsigned long inst_len;
    unsigned long event_flag;
    unsigned long entry_intr_info;
    unsigned long user_flag;
    volatile unsigned long guest_timeout_flag;
    volatile unsigned long exit_wrong_flag;
    volatile unsigned long cross_page_flag;
    unsigned long idtr_base;
    unsigned long idtr_limit_u16;
};
struct shar_arg* ei_shar_args;

/* the following two structs is set for load and store convinience */
struct target_context {
    unsigned long eflags;//eflags::rsp are saved on fixed ana stack
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r9;
    unsigned long r8;
    unsigned long r10;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long rsp;
    unsigned long rip;//The rip::rcx need to be copied from board_ctx
    unsigned long rax;
    unsigned long rcx;
};
volatile struct target_context* target_ctx;

//the region to temporaly store target's rax & rcx
struct board_context {
    unsigned long t_db_handler;                             //f98
    unsigned long t_ve_handler;                             //fa0
    unsigned long t_int3_handler;                            //fa8
    unsigned long entry_gate;                               //fb0
    unsigned long pf_handler;                               //fb8
    unsigned long syscall_handler;                          //fc0
    // unsigned long ret_handler;//normal ret from malloc/free //fc8
    unsigned long reserved1;
    unsigned long syscall_exit_handler;//i.e., sysret handler  //fd0
    // unsigned long reserved2;
    // unsigned long rdi;//since malloc&free only have one arg
    unsigned long rcx;                                      //fd8
    unsigned long rax;                                      //fe0
    // unsigned long rsp;
    unsigned long rip;                                      //fe8
};
volatile struct board_context* board_ctx;
    
unsigned long exit_gate_va;
unsigned long idt_va;
unsigned long gdt_va;
unsigned long tss_va;
unsigned long data_page;
unsigned long root_pt_va;
// unsigned long hyp_shar_mem;
// unsigned long klee_shar_mem;
unsigned long ana_t_tss;
unsigned long ana_t_gdt;
unsigned long ana_t_idt;
unsigned long* virt_exce_area;
unsigned long ana_stack;
/* Target #PF uses its original stack as in the guest VM, while #VE, #INT3, #DB
 * use oaais_lib's data page as stack since these event should be transparent to
 * the guest VM */
// unsigned long t_pf_stack;
unsigned long t_int3_stack;
// unsigned long t_ve_stack;
// unsigned long t_db_stack;
unsigned long entry_gate;
unsigned long exit_gate;
unsigned long syscall_exit_gate;
unsigned long t_fsbase;
unsigned long nme_fsbase;
unsigned long* gdt_base;
unsigned long uk_offset;

ExecState* execState;

unsigned long native_start_t = 0;
unsigned long int3_start_t = 0;
unsigned long int3_count = 0;

struct MacReg machRegs;

void native_to_SE_ctx_switch();
void SE_to_native_ctx_switch();

/*========================================================*/
static __attribute__ ((noinline)) unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long) lo | ((unsigned long long) hi << 32));
}

void write_fs (unsigned long base)
{
    asm volatile ("movq %0, %%rax; \n\t"
            "wrfsbase %%rax; \n\t"
            ::"m"(base):"%rax");
    return;
}

unsigned long read_fs (void)
{
    unsigned long base;
    asm volatile (
            "rdfsbase %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            ::"m"(base):"%rax");
    return base;
}

void write_gs (unsigned long base)
{
    asm volatile ("movq %0, %%rax; \n\t"
            "wrgsbase %%rax; \n\t"
            ::"m"(base):"%rax");
    return;
}

unsigned long read_gs (void)
{
    unsigned long base;
    asm volatile (
            "rdgsbase %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            ::"m"(base):"%rax");
    return base;
}
unsigned long rdmsr (unsigned long idx)
{
    unsigned long value;
    unsigned long high, low;
    asm volatile ("mov %2, %%ecx; \n\t"
            "rdmsr; \n\t"
            "mov %%edx, %0; \n\t"
            "mov %%eax, %1; \n\t"
            :"=m"(high), "=m"(low):"m"(idx):"%eax","%edx","%ecx");
    value = ((high << 32) & 0xffffffff00000000) | (low & 0xffffffff);
    return value;
}
void wrmsr (unsigned long idx, unsigned long value)
{
    unsigned long high, low;
    high = (value >> 32) & 0xffffffff;
    low = value & 0xffffffff;
    asm volatile ("mov %2, %%ecx; \n\t"
            "mov %0, %%edx; \n\t"
            "mov %1, %%eax; \n\t"
            "wrmsr; \n\t"
            ::"m"(high), "m"(low), "m"(idx):"%eax","%edx","%ecx");
    return;
}
unsigned long rd_cr0 (void)
{
    unsigned long cr0;
    asm volatile ("mov %%cr0, %%rax; \n\t"
            "mov %%rax, %0; \n\t"
            :"=m"(cr0)::"%rax");
    return cr0;
}
unsigned long rd_cr2 (void)
{
    unsigned long cr2;
    asm volatile ("mov %%cr2, %%rax; \n\t"
            "mov %%rax, %0; \n\t"
            :"=m"(cr2)::"%rax");
    return cr2;
}
unsigned long rd_cr4 (void)
{
    unsigned long cr4;
    asm volatile ("mov %%cr4, %%rax; \n\t"
            "mov %%rax, %0; \n\t"
            :"=m"(cr4)::"%rax");
    return cr4;
}
void wr_cr0 (unsigned long cr0)
{
    asm volatile (
            "mov %0, %%rax; \n\t"
            "mov %%rax, %%cr0; \n\t"
            ::"m"(cr0):"%rax");
    return;
}
void wr_cr2 (unsigned long cr2)
{
    asm volatile (
            "mov %0, %%rax; \n\t"
            "mov %%rax, %%cr2; \n\t"
            ::"m"(cr2):"%rax");
    return;
}
void wr_cr4 (unsigned long cr4)
{
    asm volatile (
            "mov %0, %%rax; \n\t"
            "mov %%rax, %%cr4; \n\t"
            ::"m"(cr4):"%rax");
    return;
}

void switch_to_ring0 (void)
{
    void* mem = malloc (10);
    asm volatile ("movq %%rsp, %%rdx; \n\t"
            "movq %0, %%rdi; \n\t"
            "movq $0xffff, %%rsi; \n\t"
            "movq %%rsi, (%%rdi); \n\t"
            "movq $0x63, 0x8(%%rdi); \n\t"
            "REX.W lcall *(%%rdi); \n\t"
            "movq %%rdx, %%rsp; \n\t"
            ::"m"(mem):"%rdi","%rsi", "%rdx");
    return;
}

void restore_user_privilege (void)
{
    asm volatile (
            "movq %%rsp, %%rdi; \n\t"
            "pushq $0x2b; \n\t"
            "pushq %%rdi; \n\t"
            "pushfq; \n\t"
            "lea 0x5(%%rip), %%rdi; \n\t"
            "pushq $0x33; \n\t"
            "pushq %%rdi; \n\t"
            "iretq; \n\t"
            :::"%rdi");
    return;
}


void func(void)
{
    asm volatile ("" : );
    return;
}

/* This call cate is used by analyser to escalate privilege from user to kernel */
void init_call_gate ()
{
    unsigned long* temp_gdt;
    unsigned long call_gate_entry;
    unsigned long call_gate_addr;

    call_gate_addr = (unsigned long) func;
    // temp_gdt = (unsigned long*) shar_args->gdtr;
    temp_gdt = gdt_base;
    call_gate_entry = (call_gate_addr & 0xffff) | (0x10 << 16) | ((unsigned long) (0xec00) << 32) | (((call_gate_addr >> 16) & 0xffff) << 48);
    temp_gdt[12] = call_gate_entry;
    call_gate_entry = (call_gate_addr >> 32) & 0xffffffff;
    temp_gdt[13] = call_gate_entry;
    
    asm volatile ("clflush (%0)" :: "r"(&(temp_gdt[12])));
    
    return;
}

extern "C" void nme_pf_handler (unsigned long, unsigned long*);
extern bool AllowPGWrite (unsigned long VA) ;
static unsigned long saved_rss, saved_rsp, saved_rflags, saved_rcs, saved_rip, saved_err, saved_rax, saved_cr2, saved_rdx ;

void nme_pf_handler (unsigned long cr2, unsigned long* pf_stack)
{
    unsigned long *tmp = pf_stack;

    if (tmp[2] > 0x7effffffffffUL && tmp[2] < 0x7f7fffffffffUL) {
      
        asm volatile ("mov $0xdcbadcba, %rax; \n\t"
             "vmcall; \n\t");
    }

    tmp = (unsigned long *)((((unsigned long)tmp) + 0xFFF) & (~0xFFFUL)) ;
    saved_rss       = tmp[-1] ;
    saved_rsp       = tmp[-2] ;
    saved_rflags    = tmp[-3] ;
    saved_rcs       = tmp[-4] ;
    saved_rip       = tmp[-5] ;
    saved_err       = tmp[-6] ;

    saved_rax       = tmp[-7] ;
    saved_cr2       = tmp[-8] ;
    saved_rdx       = tmp[-9] ;

    printf ("at nme_pf_handler, cr2: %016lx, rip: %016lx. \n", cr2, saved_rip);

    AllowPGWrite (cr2) ;
    tmp[-1] = saved_rss         ;
    tmp[-2] = saved_rsp         ;
    tmp[-3] = saved_rflags      ;
    tmp[-4] = saved_rcs         ;
    tmp[-5] = saved_rip         ;
    tmp[-6] = saved_err         ;
    tmp[-7] = saved_rax         ;
    tmp[-8] = saved_cr2         ;
    tmp[-9] = saved_rdx         ;  
        
    return;
}

extern "C" void pf_store_context (void);
void pf_store_context (void);
asm (" .text");
asm (" .type    pf_store_context, @function");
asm ("pf_store_context: \n");
asm ("mfence \n") ;
asm ("movq %rsp, %rax \n");
asm ("movq $0x7f7fffffe000, %rsp \n");//switch to analyser's secure stack
asm ("pushq %rax \n"); // save pf handler rsp in nme stack
asm ("pushq %rdi \n");// 6 syscall args
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");//the rest of user context
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushq %rcx \n");
asm ("movq %cr2, %rdi \n");//pass cr2 as 1st arg 
asm ("movq %rax, %rsi \n");// pass pf rsp as 2rd arg
asm ("movsd %xmm0, -0x10(%rsp) \n");
asm ("movsd %xmm1, -0x20(%rsp) \n");
asm ("movsd %xmm2, -0x30(%rsp) \n");
asm ("movsd %xmm3, -0x40(%rsp) \n");
asm ("movsd %xmm4, -0x50(%rsp) \n");
asm ("movsd %xmm5, -0x60(%rsp) \n");
asm ("movsd %xmm6, -0x70(%rsp) \n");
asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("sub $0x90, %rsp \n");

asm ("callq nme_pf_handler \n");

asm ("add $0x90, %rsp \n");
asm ("movsd -0x10(%rsp), %xmm0 \n");
asm ("movsd -0x20(%rsp), %xmm1 \n");
asm ("movsd -0x30(%rsp), %xmm2 \n");
asm ("movsd -0x40(%rsp), %xmm3 \n");
asm ("movsd -0x50(%rsp), %xmm4 \n");
asm ("movsd -0x60(%rsp), %xmm5 \n");
asm ("movsd -0x70(%rsp), %xmm6 \n");
asm ("movsd -0x80(%rsp), %xmm7 \n");
asm ("popq %rcx \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");//restore to pf stack
asm ("movq %rax, %rsp \n");
asm ("popq %rdx \n");
asm ("popq %rdx \n");
asm ("popq %rax \n");
asm ("popq %rax \n");
asm ("add $0x8, %rsp \n");
asm ("iretq \n");

extern "C" void t_syscall_intercepter (void);
void t_syscall_intercepter (void)
{
    ei_shar_args->fs_base = read_fs();
    write_fs(nme_fsbase);
    printf ("syscall index: %lu. ....., rsp: %lx. \n", board_ctx->rax, target_ctx->rsp);
    board_ctx->rcx = syscall_exit_gate; 
    board_ctx->rip = ei_shar_args->g_syscall_entry;
    write_fs(ei_shar_args->fs_base);
    
    return;
}

extern "C" void syscall_store_context (void);
void syscall_store_context (void);
asm (" .text");
asm (" .type    syscall_store_context, @function");
asm ("syscall_store_context: \n");
asm ("movq %rsp, %rax \n"); 
asm ("movq $0x7f7fffffecc0, %rsp \n");//switch to analyser's secure stack
asm ("pushq %rax \n");// save target rsp in nme stack
asm ("pushq %rdi \n");// 6 syscall args
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");//the rest of user context
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushf \n");
asm ("movsd %xmm0, -0x10(%rsp) \n");
asm ("movsd %xmm1, -0x20(%rsp) \n");
asm ("movsd %xmm2, -0x30(%rsp) \n");
asm ("movsd %xmm3, -0x40(%rsp) \n");
asm ("movsd %xmm4, -0x50(%rsp) \n");
asm ("movsd %xmm5, -0x60(%rsp) \n");
asm ("movsd %xmm6, -0x70(%rsp) \n");
asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("sub $0x90, %rsp \n");

asm ("callq t_syscall_intercepter \n");

asm ("add $0x90, %rsp \n");
asm ("movsd -0x10(%rsp), %xmm0 \n");
asm ("movsd -0x20(%rsp), %xmm1 \n");
asm ("movsd -0x30(%rsp), %xmm2 \n");
asm ("movsd -0x40(%rsp), %xmm3 \n");
asm ("movsd -0x50(%rsp), %xmm4 \n");
asm ("movsd -0x60(%rsp), %xmm5 \n");
asm ("movsd -0x70(%rsp), %xmm6 \n");
asm ("movsd -0x80(%rsp), %xmm7 \n");
asm ("popf \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");//restore target rsp into rax
asm ("movq %rax, %rsp \n");
asm ("movq $0x7f1000905fb0, %rax \n");//addr of entry_gate
asm ("jmpq *(%rax) \n");

extern "C" void t_syscall_exit (void);
void t_syscall_exit()
{
    ei_shar_args->fs_base = read_fs();
    write_fs(nme_fsbase);
    printf ("syscall ret value: %lx. \n", board_ctx->rax);
    asm volatile ("movq $0xfff, %rax; \n\t"
            "vmcall; \n\t");
    
    write_fs (ei_shar_args->fs_base);
    return;    
}

extern "C" void syscall_exit_store_context (void);
void syscall_exit_store_context (void);
asm (" .text");
asm (" .type    syscall_exit_store_context, @function");
asm ("syscall_exit_store_context: \n");
asm ("movq %rsp, %rax \n"); 
asm ("movq $0x7f7fffffecc0, %rsp \n");//switch to analyser's secure stack
asm ("pushq %rax \n");// save target rsp in nme stack
asm ("pushq %rdi \n");// 6 syscall args
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");//the rest of user context
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushf \n");
asm ("movsd %xmm0, -0x10(%rsp) \n");
asm ("movsd %xmm1, -0x20(%rsp) \n");
asm ("movsd %xmm2, -0x30(%rsp) \n");
asm ("movsd %xmm3, -0x40(%rsp) \n");
asm ("movsd %xmm4, -0x50(%rsp) \n");
asm ("movsd %xmm5, -0x60(%rsp) \n");
asm ("movsd %xmm6, -0x70(%rsp) \n");
asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("sub $0x90, %rsp \n");

asm ("callq t_syscall_exit \n");

asm ("add $0x90, %rsp \n");
asm ("movsd -0x10(%rsp), %xmm0 \n");
asm ("movsd -0x20(%rsp), %xmm1 \n");
asm ("movsd -0x30(%rsp), %xmm2 \n");
asm ("movsd -0x40(%rsp), %xmm3 \n");
asm ("movsd -0x50(%rsp), %xmm4 \n");
asm ("movsd -0x60(%rsp), %xmm5 \n");
asm ("movsd -0x70(%rsp), %xmm6 \n");
asm ("movsd -0x80(%rsp), %xmm7 \n");
asm ("popf \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");//restore target rsp into rax
asm ("movq %rax, %rsp \n");
asm ("vmcall \n");

static void clear_dr(int idx) ;
extern "C" void int3_handler (void);
void int3_handler(void)
{
    ei_shar_args->fs_base = read_fs();
    write_fs (nme_fsbase);

    unsigned long* int3_stack_ptr = (unsigned long*)(t_int3_stack - 0x28);
    unsigned long saved_rip, saved_rsp, saved_rflags;
    unsigned long* t_stack_ptr;
    saved_rip = int3_stack_ptr[0];
    saved_rip -= 1;// for int3, saved rip is the rip next to int3
    saved_rsp = int3_stack_ptr[3];
    saved_rflags = int3_stack_ptr[2];
    
    printf("int3 BP triggered ...\n");
    
    target_ctx->rax = board_ctx->rax;
    target_ctx->rcx = board_ctx->rcx;
    target_ctx->rip = saved_rip + 0x5; 
    target_ctx->rsp = saved_rsp;
    target_ctx->eflags = saved_rflags;

    native_to_SE_ctx_switch();
    execState->SynRegsFromNative(&machRegs);
    execState->processAt(int3_start_t); //give control to the analyzer

    execState->SynRegsToNative(&machRegs);
    SE_to_native_ctx_switch();
    board_ctx->rax = target_ctx->rax; 
    board_ctx->rcx = target_ctx->rcx; 
    board_ctx->rip = target_ctx->rip; 
    write_fs (ei_shar_args->fs_base);
    
    return;
}

extern "C" void int3_store_context (void);
void int3_store_context (void);
asm (" .text");
asm (" .type    int3_store_context, @function");
asm ("int3_store_context: \n");
asm ("movq %rsp, %rax \n"); 
asm ("movq $0x7f7fffffecc0, %rsp \n");//switch to analyser's secure stack
asm ("pushq %rax \n");// save target rsp in nme stack
asm ("pushq %rdi \n");// 6 syscall args
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");//the rest of user context
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushf \n");
asm ("movsd %xmm0, -0x10(%rsp) \n");
asm ("movsd %xmm1, -0x20(%rsp) \n");
asm ("movsd %xmm2, -0x30(%rsp) \n");
asm ("movsd %xmm3, -0x40(%rsp) \n");
asm ("movsd %xmm4, -0x50(%rsp) \n");
asm ("movsd %xmm5, -0x60(%rsp) \n");
asm ("movsd %xmm6, -0x70(%rsp) \n");
asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("sub $0x98, %rsp \n");//To ensure the stack 16-byte aligned

asm ("callq int3_handler \n");

asm ("add $0x98, %rsp \n");
asm ("movsd -0x10(%rsp), %xmm0 \n");
asm ("movsd -0x20(%rsp), %xmm1 \n");
asm ("movsd -0x30(%rsp), %xmm2 \n");
asm ("movsd -0x40(%rsp), %xmm3 \n");
asm ("movsd -0x50(%rsp), %xmm4 \n");
asm ("movsd -0x60(%rsp), %xmm5 \n");
asm ("movsd -0x70(%rsp), %xmm6 \n");
asm ("movsd -0x80(%rsp), %xmm7 \n");
asm ("popf \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");//restore target rsp into rax
asm ("movq %rax, %rsp \n");
asm ("movq $0x7f1000905fb0, %rax \n");//addr of entry_gate
asm ("jmpq *(%rax) \n");

static void read_dr (void)
{
    unsigned long dr0, dr1, dr2, dr3, dr7;
    asm volatile ("movq %%DR0, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            "movq %%DR1, %%rax; \n\t"
            "movq %%rax, %1; \n\t"
            "movq %%DR2, %%rax; \n\t"
            "movq %%rax, %2; \n\t"
            "movq %%DR3, %%rax; \n\t"
            "movq %%rax, %3; \n\t"
            "movq %%DR7, %%rax; \n\t"
            "movq %%rax, %4; \n\t"
            :"=m"(dr0),"=m"(dr1),"=m"(dr2),"=m"(dr3),"=m"(dr7)::"%rax");
    printf ("dr0: %lx, dr1: %lx, dr2: %lx, dr3: %lx, dr7: %lx. \n", dr0, dr1, dr2, dr3, dr7);
    return;
}

/* no need to clear dr0-dr3, disable through dr7 */
static void clear_dr(int idx)
{
    unsigned long dr7;
    switch (idx)
    {
        case 0:
            dr7 = 0xfff0fffc;
            break;
        case 1:
            dr7 = 0xff0ffff3;
            break;
        case 2: 
            dr7 = 0xf0ffffcf;
            break;
        case 3: 
            dr7 = 0x0fffff3f;
            break;
        default: 
            asm volatile ("mov $0xabcdabcd, %rax; \n\t"
                    "vmcall; \n\t");
            break;
    }

    asm volatile (
            "mov %0, %%rbx; \n\t"
            "mov %%DR7, %%rax; \n\t"
            "and %%rbx, %%rax; \n\t"
            "mov %%rax, %%DR7; \n\t"
            ::"m"(dr7):"%rax","%rbx");
    return;
}

static __attribute__ ((noinline)) void set_dr3(int size, unsigned long addr)
{
    int dr7;
    /* bit 26-27 control the size to monitor */
    switch (size)
    {
        case 1:
            dr7 = 0;
            break;
        case 2: 
            dr7 = 0x40000000; 
            break;
        case 4: 
            dr7 = 0xc0000000;
            break;
        case 8:
            dr7 = 0x80000000;
            break;
        default: 
            asm volatile ("mov $0xabcdabcd, %rax; \n\t"
                    "vmcall; \n\t");
            break;
    }
    /* bit 6 enables dr1, bit 28-29 control operations to monitor (both rw) */
    dr7 |= 0x30000040;
            
    asm volatile (
            "movq %0, %%rax; \n\t"
            "movq %%rax, %%DR3; \n\t"
            "movq %1, %%rbx; \n\t"
            "mov %%DR7, %%eax; \n\t"
            "or %%ebx, %%eax; \n\t"
            "mov %%eax, %%DR7; \n\t"
            ::"m"(addr), "m"(dr7):"%rax", "%rbx");
    return;
}

static __attribute__ ((noinline)) void set_dr2(int size, unsigned long addr)
{
    int dr7;
    /* bit 26-27 control the size to monitor */
    switch (size)
    {
        case 1:
            dr7 = 0;
            break;
        case 2: 
            dr7 = 0x4000000; 
            break;
        case 4: 
            dr7 = 0xc000000;
            break;
        case 8:
            dr7 = 0x8000000;
            break;
        default: 
            asm volatile ("mov $0xabcdabcd, %rax; \n\t"
                    "vmcall; \n\t");
            break;
    }
    /* bit 4 enables dr1, bit 24-25 control operations to monitor (both rw) */
    dr7 |= 0x3000010;
            
    asm volatile (
            "movq %0, %%rax; \n\t"
            "movq %%rax, %%DR2; \n\t"
            "movq %1, %%rbx; \n\t"
            "mov %%DR7, %%eax; \n\t"
            "or %%ebx, %%eax; \n\t"
            "mov %%eax, %%DR7; \n\t"
            ::"m"(addr), "m"(dr7):"%rax", "%rbx");
    return;
}

static __attribute__ ((noinline)) void set_dr1(int size, unsigned long addr)
{
    int dr7;
    /* bit 22-23 control the size to monitor */
    switch (size)
    {
        case 1:
            dr7 = 0;
            break;
        case 2: 
            dr7 = 0x400000; 
            break;
        case 4: 
            dr7 = 0xc00000;
            break;
        case 8:
            dr7 = 0x800000;
            break;
        default: 
            asm volatile ("mov $0xabcdabcd, %rax; \n\t"
                    "vmcall; \n\t");
            break;
    }
    /* bit 2 enables dr1, bit 20-21 control operations to monitor (both rw) */
    dr7 |= 0x300004;
            
    asm volatile (
            "movq %0, %%rax; \n\t"
            "movq %%rax, %%DR1; \n\t"
            "movq %1, %%rbx; \n\t"
            "mov %%DR7, %%eax; \n\t"
            "or %%ebx, %%eax; \n\t"
            "mov %%eax, %%DR7; \n\t"
            ::"m"(addr), "m"(dr7):"%rax", "%rbx");
    return;
}

static __attribute__ ((noinline)) void set_dr0(int size, unsigned long addr)
{
    int dr7;
    /* bit 18-19 control the size to monitor */
    switch (size)
    {
        case 1:
            dr7 = 0;
            break;
        case 2: 
            dr7 = 0x40000; 
            break;
        case 4: 
            dr7 = 0xc0000;
            break;
        case 8:
            dr7 = 0x80000;
            break;
        default: 
            asm volatile ("mov $0xabcdabcd, %rax; \n\t"
                    "vmcall; \n\t");
            break;
    }
    /* bit 0 enables dr0, bit 16-17 control operations to monitor (both rw) */
    dr7 |= 0x30001;
            
    asm volatile (
            "movq %0, %%rax; \n\t"
            "movq %%rax, %%DR0; \n\t"
            "movq %1, %%rbx; \n\t"
            "mov %%DR7, %%eax; \n\t"
            "or %%ebx, %%eax; \n\t"
            "mov %%eax, %%DR7; \n\t"
            ::"m"(addr), "m"(dr7):"%rax", "%rbx");

    return;
}

extern "C" void db_handler (void);
void db_handler(void)
{
    asm volatile("movq $0x99999, %%rax; \n\t"
            "vmcall; \n\t"
            :::"%rax");
    
    // oasis engine to save T and load SE context
    native_to_SE_ctx_switch();
    execState->SynRegsFromNative(&machRegs);
    execState->DBHandler();
    execState->SynRegsToNative(&machRegs);
    SE_to_native_ctx_switch();

    return;
}

extern "C" void db_store_context (void);
void db_store_context (void);
asm (" .text");
asm (" .type    db_store_context, @function");
asm ("db_store_context: \n");
asm ("movq $0xabcdabcd, %rax \n");
asm ("vmcall \n");
asm ("movq %rsp, %rax \n"); 
asm ("movq $0x7f7fffffecc0, %rsp \n");//switch to analyser's secure stack
asm ("pushq %rax \n");// save target rsp in nme stack
asm ("pushq %rdi \n");// 6 syscall args
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");//the rest of user context
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushf \n");
asm ("movsd %xmm0, -0x10(%rsp) \n");
asm ("movsd %xmm1, -0x20(%rsp) \n");
asm ("movsd %xmm2, -0x30(%rsp) \n");
asm ("movsd %xmm3, -0x40(%rsp) \n");
asm ("movsd %xmm4, -0x50(%rsp) \n");
asm ("movsd %xmm5, -0x60(%rsp) \n");
asm ("movsd %xmm6, -0x70(%rsp) \n");
asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("sub $0x98, %rsp \n");//To ensure the stack 16-byte aligned

asm ("callq db_handler \n");

asm ("add $0x98, %rsp \n");
asm ("movsd -0x10(%rsp), %xmm0 \n");
asm ("movsd -0x20(%rsp), %xmm1 \n");
asm ("movsd -0x30(%rsp), %xmm2 \n");
asm ("movsd -0x40(%rsp), %xmm3 \n");
asm ("movsd -0x50(%rsp), %xmm4 \n");
asm ("movsd -0x60(%rsp), %xmm5 \n");
asm ("movsd -0x70(%rsp), %xmm6 \n");
asm ("movsd -0x80(%rsp), %xmm7 \n");
asm ("popf \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");//restore target rsp into rax
asm ("movq %rax, %rsp \n");
asm ("movq $0x7f1000905fb0, %rax \n");//addr of entry_gate
asm ("jmpq *(%rax) \n");

/* perm: 0 -- recover RW bits; 1 -- clear RW bits */
void update_t_ept_perm (int perm, unsigned long ker_addr)
{
    unsigned long gpa;
    ker_addr &= ~0xFFFUL;
    if (ker_addr < __START_KERNEL_MAP)
        gpa = ker_addr - PAGE_OFFSET;
    else
        gpa = ker_addr - __START_KERNEL_MAP;
    printf ("intercept VE page, va: %lx, gpa: %lx. \n", ker_addr, gpa);

    asm volatile (
            "movq %0, %%rdx; \n\t"
            "movq %1, %%rcx; \n\t"
            "movq %2, %%rbx; \n\t"
            "movq $0xdcba, %%rax; \n\t"
            "vmcall; \n\t"
            ::"m"(ker_addr), "m"(gpa), "m"(perm):"%rax","%rbx","%rcx","%rdx");
    return;
}

int determ_sym_mem(unsigned long addr)
{
    if (addr == 0)//belong to sym mem
        return 1;
    else
        return 0;
}

extern "C" void ve_handler (void);
void ve_handler(void)
{
    asm volatile("movq $0x99999, %%rax; \n\t"
            "vmcall; \n\t"
            :::"%rax");

    // oasis engine to save T and load SE context
    native_to_SE_ctx_switch();
    execState->SynRegsFromNative(&machRegs);    
    execState->SynRegsToNative(&machRegs);
    SE_to_native_ctx_switch();

    return;
}

extern "C" void ve_store_context (void);
void ve_store_context (void);
asm (" .text");
asm (" .type    ve_store_context, @function");
asm ("ve_store_context: \n");
asm ("movq $0xabcdabcd, %rax \n");
asm ("vmcall \n");
asm ("movq %rsp, %rax \n"); 
asm ("movq $0x7f7fffffecc0, %rsp \n");//switch to analyser's secure stack
asm ("pushq %rax \n");// save target rsp in nme stack
asm ("pushq %rdi \n");// 6 syscall args
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");//the rest of user context
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushf \n");
asm ("movsd %xmm0, -0x10(%rsp) \n");
asm ("movsd %xmm1, -0x20(%rsp) \n");
asm ("movsd %xmm2, -0x30(%rsp) \n");
asm ("movsd %xmm3, -0x40(%rsp) \n");
asm ("movsd %xmm4, -0x50(%rsp) \n");
asm ("movsd %xmm5, -0x60(%rsp) \n");
asm ("movsd %xmm6, -0x70(%rsp) \n");
asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("sub $0x98, %rsp \n");//To ensure the stack 16-byte aligned

asm ("callq ve_handler \n");

asm ("add $0x98, %rsp \n");
asm ("movsd -0x10(%rsp), %xmm0 \n");
asm ("movsd -0x20(%rsp), %xmm1 \n");
asm ("movsd -0x30(%rsp), %xmm2 \n");
asm ("movsd -0x40(%rsp), %xmm3 \n");
asm ("movsd -0x50(%rsp), %xmm4 \n");
asm ("movsd -0x60(%rsp), %xmm5 \n");
asm ("movsd -0x70(%rsp), %xmm6 \n");
asm ("movsd -0x80(%rsp), %xmm7 \n");
asm ("popf \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");//restore target rsp into rax
asm ("movq %rax, %rsp \n");
asm ("movq $0x7f1000905fb0, %rax \n");//addr of entry_gate
asm ("jmpq *(%rax) \n");
/* /========================================================*/

void init_global_var ()
{
    void* temp;
    uk_offset = 0xffffff8000000000;
    exit_gate_va =  0x7f9000900000+uk_offset;
    idt_va = 0x7f9000901000 + uk_offset;
    gdt_va = 0x7f9000902000 + uk_offset;
    tss_va = 0x7f9000903000 + uk_offset;
    data_page = 0x7f9000905000 + uk_offset;//a writable data page
    t_int3_stack = data_page + 0x1000 - 0x200;//#INT3 uses part of oasis_lib's data page as its stack
    execState->m_emeta->t_int3_stack = data_page + 0x1000 - 0x200;//#INT3 uses part of oasis_lib's data page as its stack
    execState->m_emeta->t_ve_stack = t_int3_stack;//#VE shares the same stack as #INT3 
    execState->m_emeta->t_db_stack = t_int3_stack;//#DB sahres the same stack as #INT3 
    root_pt_va = 0x7f9000906000 + uk_offset;
    ei_shar_args = (struct shar_arg*)(0x7f90000907000 + uk_offset);
    ana_t_tss = 0x7f9000908000 + uk_offset;//0x200 is guest_tss_page_offset
    ana_t_gdt = 0x7f9000909000 + uk_offset;
    ana_t_idt = 0x7f900090a000 + uk_offset;
    execState->m_emeta->virt_exce_area = (unsigned long*)(0x7f900090c000 + uk_offset);
    ana_stack = 0x7fffffffecc0 + uk_offset;
    entry_gate = exit_gate_va + 0x261;
    exit_gate = exit_gate_va + 0x292;
    syscall_exit_gate = exit_gate_va + 0x2fd;

    target_ctx = (struct target_context*)(ana_stack - 0x78);
    board_ctx = (struct board_context*)(data_page + 0xf98);
    board_ctx->syscall_handler = (unsigned long)syscall_store_context;
    board_ctx->syscall_exit_handler = (unsigned long)syscall_exit_store_context;
    board_ctx->t_int3_handler = (unsigned long)int3_store_context;
    board_ctx->t_ve_handler = (unsigned long)ve_store_context;
    board_ctx->t_db_handler = (unsigned long)db_store_context;
    board_ctx->pf_handler = (unsigned long)pf_store_context;
    board_ctx->entry_gate = entry_gate;

    nme_fsbase = read_fs();
    printf ("nme_fsbase: %lx. \n", nme_fsbase);
    unsigned long* tmp_ptr = (unsigned long*)0x555555755010 ;
    
    /* initialize addr_gdt_base, addr_tss_base */
    unsigned char gdtr[10];
    unsigned long tss_base0, tss_base1, tss_base2;
    asm ("sgdt %0; \n\t"
            :"=m"(gdtr)
            :
            :);
    gdt_base = (unsigned long*)(*(unsigned long*)(gdtr + 2));
    printf ("gdt base: %lx. \n", (unsigned long)gdt_base);

    init_call_gate();
    
    /* check root pt entry */
    unsigned long test_addr = 0x555555554700;
    int idx = test_addr >> 39;
    unsigned long* root_pt_ptr = (unsigned long*)root_pt_va;
    printf ("idx: %d, entry: %lx. \n", idx, root_pt_ptr[idx]);
    root_pt_ptr[idx] &= 0xFFFFFFFFF;

    return;
}

void init_t_ctx()
{
    machRegs.regs.r8 = ei_shar_args->r8; 
    machRegs.regs.r9 = ei_shar_args->r9;
    machRegs.regs.r10 = ei_shar_args->r10; 
    machRegs.regs.r11 = ei_shar_args->r11;
    machRegs.regs.r12 = ei_shar_args->r12;
    machRegs.regs.r13 = ei_shar_args->r13;
    machRegs.regs.r14 = ei_shar_args->r14;
    machRegs.regs.r15 = ei_shar_args->r15;
    machRegs.regs.rax = ei_shar_args->rax;
    machRegs.regs.rbx = ei_shar_args->rbx;
    machRegs.regs.rcx = ei_shar_args->rcx;
    machRegs.regs.rdx = ei_shar_args->rdx;
    machRegs.regs.rsi = ei_shar_args->rsi;
    machRegs.regs.rdi = ei_shar_args->rdi;
    machRegs.regs.rbp = ei_shar_args->rbp;
    machRegs.regs.rsp = ei_shar_args->rsp;
    machRegs.regs.rip = ei_shar_args->rip;
    machRegs.regs.eflags = ei_shar_args->eflags;
    assert(ei_shar_args->msr_kernel_gs_base != 0);
    assert(ei_shar_args->fs_base != 0);
    machRegs.fs_base = ei_shar_args->fs_base;
    machRegs.gs_base = ei_shar_args->msr_kernel_gs_base;
    return;
}

void native_to_SE_ctx_switch()
{
    machRegs.regs.r8 = target_ctx->r8; 
    machRegs.regs.r9 = target_ctx->r9;
    machRegs.regs.r10 = target_ctx->r10; 
    machRegs.regs.r11 = target_ctx->r11;
    machRegs.regs.r12 = target_ctx->r12;
    machRegs.regs.r13 = target_ctx->r13;
    machRegs.regs.r14 = target_ctx->r14;
    machRegs.regs.r15 = target_ctx->r15;
    machRegs.regs.rax = target_ctx->rax;
    machRegs.regs.rbx = target_ctx->rbx;
    machRegs.regs.rcx = target_ctx->rcx;
    machRegs.regs.rdx = target_ctx->rdx;
    machRegs.regs.rsi = target_ctx->rsi;
    machRegs.regs.rdi = target_ctx->rdi;
    machRegs.regs.rbp = target_ctx->rbp;
    machRegs.regs.rsp = target_ctx->rsp;
    machRegs.regs.rip = target_ctx->rip;
    machRegs.regs.eflags = target_ctx->eflags;
    assert(ei_shar_args->msr_kernel_gs_base != 0);
    assert(ei_shar_args->fs_base != 0);
    machRegs.fs_base = ei_shar_args->fs_base;
    machRegs.gs_base = ei_shar_args->msr_kernel_gs_base;
    return;
}

void SE_to_native_ctx_switch()
{
    target_ctx->r8 = machRegs.regs.r8; 
    target_ctx->r9 = machRegs.regs.r9;
    target_ctx->r10 = machRegs.regs.r10; 
    target_ctx->r11 = machRegs.regs.r11;
    target_ctx->r12 = machRegs.regs.r12;
    target_ctx->r13 = machRegs.regs.r13;
    target_ctx->r14 = machRegs.regs.r14;
    target_ctx->r15 = machRegs.regs.r15;
    target_ctx->rax = machRegs.regs.rax;
    target_ctx->rbx = machRegs.regs.rbx;
    target_ctx->rcx = machRegs.regs.rcx;
    target_ctx->rdx = machRegs.regs.rdx;
    target_ctx->rsi = machRegs.regs.rsi;
    target_ctx->rdi = machRegs.regs.rdi;
    target_ctx->rbp = machRegs.regs.rbp;
    target_ctx->rsp = machRegs.regs.rsp;
    target_ctx->rip = machRegs.regs.rip;
    target_ctx->eflags = machRegs.regs.eflags;
    return;
}

void get_target()
{
    printf ("ei_shar_args at: %p \n", ei_shar_args);
    
    ei_shar_args = (struct shar_arg*)(0x7f9000907000 + uk_offset);
    /* copy TSS_STRUCT from Guest VM. Let T_PF use its orginal stack */
    memcpy((void*)ana_t_tss, (void*)(ei_shar_args->tss_base), 0x68);
    execState->m_emeta->t_pf_stack = *((unsigned long*)(ana_t_tss+0x4));//#PF uses original stack as in the guest VM
    *((unsigned long*)(ana_t_tss+0x4 + 0x8*10)) = t_int3_stack;//setup t_int3_stack in t_tss structure, ist[7]
    unsigned long t_rsp0 = *((unsigned long*)(ana_t_tss+0x4));
    unsigned long t_rsp1 = *((unsigned long*)(ana_t_tss+0xc));
    printf ("t_rsp0 stack: %lx. \n", t_rsp0);
    printf ("t_rsp1 stack: %lx. \n", t_rsp1);
    ei_shar_args->flag = 1;
    
    do {
        asm volatile("mfence; \n\t");
    } while (ei_shar_args->flag != 2);
    printf ("onsite receive request. \n");  

    printf ("ei_shar_args->rip: %lx, rsp: %lx. \n", ei_shar_args->rip, ei_shar_args->rsp);
    ei_shar_args->rip += 3;

    printf ("ei_shar_args at: %p \n", ei_shar_args);
    
    printf ("ei_shar_args->gs_base: %lx \n", ei_shar_args->gs_base);
    printf ("ei_shar_args->msr_kernel_gs_base: %lx \n", ei_shar_args->msr_kernel_gs_base);
    
    unsigned long* tt = (unsigned long*)(ei_shar_args->rip);
    printf ("target rip: %p, target code: %lx. \n", tt, *tt);
    tt = (unsigned long*)(ei_shar_args->g_syscall_entry);
    printf ("syscall entry at: %p, code: %lx. \n", tt, *tt);

    /* To syn TSC_OFFSET through hyp */
    asm volatile ("movq $0x378, %rax; \n\t"
            "vmcall; \n\t");
    return;
}

void dump_regs()
{
    printf ("rax: %lx\n", machRegs.regs.rax);
    printf ("rbx: %lx ", machRegs.regs.rbx);
    printf ("rcx: %lx ", machRegs.regs.rcx);
    printf ("rdx: %lx ", machRegs.regs.rdx);
    printf ("rdi: %lx ", machRegs.regs.rdi);
    printf ("rsi: %lx ", machRegs.regs.rsi);
    printf ("r8: %lx ", machRegs.regs.r8);
    printf ("r9: %lx ", machRegs.regs.r9);
    printf ("r10: %lx \n", machRegs.regs.r10);
    printf ("rip: %lx \n", machRegs.regs.rip);
    printf ("rsp: %lx \n", machRegs.regs.rsp);
    return;
}

void to_native(void)
{
    /* update board_ctx based on target vcpu context */
    board_ctx->rip = ei_shar_args->rip;
    board_ctx->rax = ei_shar_args->rax;
    board_ctx->rcx = ei_shar_args->rcx;
    // t_fsbase = ei_shar_args->fs_base;
    int index = 0xc0000102;
    wrmsr(index, ei_shar_args->msr_kernel_gs_base);
    write_fs(ei_shar_args->fs_base);
    write_gs(ei_shar_args->gs_base);
    restore_user_privilege (); //original statement

    /* transfer to trampoline */
    asm volatile (
            // /* prepare stack for iret */
            "movq %0, %%rbx; \n\t"
            "movq %1, %%rax; \n\t"//f_trampoline
            "movq 0x50(%%rbx), %%rcx; \n\t"//eflags
            "pushq %%rcx; \n\t"
            "popfq; \n\t"

            /* load all registers */
            "movq 0x8(%%rbx), %%rdi; \n\t"
            "movq 0x10(%%rbx), %%rsi; \n\t"
            "movq 0x18(%%rbx), %%rdx; \n\t"
            "movq 0x28(%%rbx), %%r8; \n\t"
            "movq 0x30(%%rbx), %%r9; \n\t"
            "movq 0x38(%%rbx), %%r11; \n\t"
            "movq 0x40(%%rbx), %%r10; \n\t"
            "movq 0x70(%%rbx), %%rbp; \n\t"
            "movq 0x78(%%rbx), %%r12; \n\t"
            "movq 0x80(%%rbx), %%r13; \n\t"
            "movq 0x88(%%rbx), %%r14; \n\t"
            "movq 0x90(%%rbx), %%r15; \n\t"
            "movq 0x60(%%rbx), %%rsp; \n\t"
            "movq 0x68(%%rbx), %%rbx; \n\t"
            "jmpq *%%rax; \n\t"

            ::"m"(ei_shar_args),"m"(entry_gate):"%rcx","%rax", "%rdx", "%rbx", "%rdi", "%rsi");
    
    asm volatile ("movq $0xffff, %rax; \n\t"
            "vmcall; \n\t");

}

static unsigned long rdfsbase(void)
{
    volatile unsigned long fsbase = 0;

    // read fs register.
    asm volatile("rdfsbase %0" : "=r" (fsbase) :: "memory");

    return fsbase;
}

void ana_kmod(){

    machRegs.regs.r9 = ei_shar_args->r9;
    machRegs.regs.r10 = ei_shar_args->r10; 
    machRegs.regs.r11 = ei_shar_args->r11;
    machRegs.regs.r12 = ei_shar_args->r12;
    machRegs.regs.r13 = ei_shar_args->r13;
    machRegs.regs.r14 = ei_shar_args->r14;
    machRegs.regs.r15 = ei_shar_args->r15;
    machRegs.regs.rax = ei_shar_args->rax;
    machRegs.regs.rbx = ei_shar_args->rbx;
    machRegs.regs.rcx = ei_shar_args->rcx;
    machRegs.regs.rdx = ei_shar_args->rdx;
    machRegs.regs.rsi = ei_shar_args->rsi;
    machRegs.regs.rdi = ei_shar_args->rdi;
    machRegs.regs.rbp = ei_shar_args->rbp;
    machRegs.regs.rsp = ei_shar_args->rsp;
    machRegs.regs.rip = ei_shar_args->rip;
    machRegs.regs.eflags = ei_shar_args->eflags;
    //assert(ei_shar_args->msr_kernel_gs_base != 0);
    //assert(ei_shar_args->fs_base != 0);
    machRegs.fs_base = ei_shar_args->fs_base;
    //machRegs.gs_base = ei_shar_args->msr_kernel_gs_base; //commenting this 
    machRegs.gs_base = ei_shar_args->gs_base; //adding this in the place of the above
    int index = 0xc0000102;
    wrmsr(index, ei_shar_args->msr_kernel_gs_base);
    write_gs(ei_shar_args->gs_base);

    execState->SynRegsFromNative(&machRegs);
    execState->processAt(ei_shar_args->rip);

    return;
}

int main(int argc, char** argv) {

    printf("target exported \n");
    unsigned long adds, adde;
    adds = 0x0;
    adde = 0xfffffffffffff000;
    execState = new ExecState(adds, adde);
    init_global_var();
    dump_regs();
    get_target();

#ifdef _ANA_KMOD
    ana_kmod();
    return 0;
#endif

    execState->InitRediPagePool();
    execState->processAt(ei_shar_args->rip); //the analyzer will find the scall handler address and place the in3 and return back

    to_native();
    
    printf ("after to_native, %d, =========\n", __LINE__);
    init_t_ctx(); 
    dump_regs(); 
    execState->SynRegsFromNative(&machRegs);
    execState->processAt(machRegs.regs.rip);

    return 0;
}
