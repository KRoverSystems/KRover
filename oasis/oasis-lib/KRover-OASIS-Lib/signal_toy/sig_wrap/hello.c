#include<stdio.h>
#include<signal.h>
#include<unistd.h>

/* stack layout  * interruted instruction */
                /* handler_address */
void func(void)
{
    return;
}
void sig_handler (int num, unsigned long addr);
void sig_handler (int num, unsigned long addr)
{
    unsigned long sig_hand;
    int signo;
    int i;
    addr += 0x78;
    // printf ("num: %d, addr: %lx\n", num, addr);
    for (i = 0; i < num; i ++)
    {
        addr += 0x8;
        sig_hand = *((unsigned long*) addr);
        addr += 0x8;
        signo = *((unsigned long*) addr);
        asm volatile ("movq %0, %%rdi; \n\t"
                "movq %1, %%rbx; \n\t"
                "callq *%%rbx; \n\t"
                ::"m"(signo), "m"(sig_hand):"%rbx", "rdi");
    }
    return;
}

void stub (void);
asm (" .text");
asm (" .type    stub, @function");
asm ("stub: \n");
asm ("pushq %rbx \n");
asm ("movq 0x8(%rsp), %rbx \n");
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %rdi \n");
asm ("pushq %rcx \n");
asm ("pushq %r11 \n");
asm ("pushq %rax \n");
asm ("pushq %rbp \n");
asm ("pushq %r15 \n");
asm ("pushq %r14 \n");
asm ("pushq %r13 \n");
asm ("pushq %r12 \n");
asm ("movq %rbx, %rdi \n");
asm ("movq %rsp, %rsi \n");

asm ("movq $0x300, %rax \n");
asm ("vmcall \n");
// asm ("movq %0, %%rax \n");
asm ("lea -0x7c(%rip), %rax \n");
asm ("callq *%rax \n");
// asm ("callq sig_handler \n");
asm ("popq %r12 \n");
asm ("popq %r13 \n");
asm ("popq %r14 \n");
asm ("popq %r15 \n");
asm ("popq %rbp \n");
asm ("popq %rax \n");
asm ("popq %r11 \n");
asm ("popq %rcx \n");
asm ("popq %rdi \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rbx \n");
asm ("add $0x18, %rsp \n");
asm ("retq \n");

// void stub (void)
// {
//     asm (// "vmcall; \n\t"
//             "pushq %%rbx; \n\t"
//             "movq 0x8(%%rsp), %%rbx; \n\t"
//             // "movq 0x10(%rsp), %rcx; \n\t"
//             // "movq %rax, %r11; \n\t"
//             "pushq %%rsi; \n\t"
//             "pushq %%rdx; \n\t"
//             "pushq %%r10; \n\t"
//             "pushq %%r8; \n\t"
//             "pushq %%r9; \n\t"
//             "pushq %%rdi; \n\t"
//             "pushq %%rcx; \n\t"
//             "pushq %%r11; \n\t"
//             "pushq %%rax; \n\t"
//             "pushq %%rbp; \n\t"
//             "pushq %%r15; \n\t"
//             "pushq %%r14; \n\t"
//             "pushq %%r13; \n\t"
//             "pushq %%r12; \n\t"
//             // "movq $0x300, %rax; \n\t"
//             // "vmcall; \n\t"
//             // "callq *%rbx; \n\t"//call signal handler
//             "movq %%rbx, %%rdi; \n\t"
//             "movq %%rsp, %%rsi; \n\t"
//             "movq %0, %%rax; \n\t"
//             "callq *%%rax; \n\t"
//             // "callq sig_handler; \n\t"//call signal handler
//             "popq %%r12; \n\t"
//             "popq %%r13; \n\t"
//             "popq %%r14; \n\t"
//             "popq %%r15; \n\t"
//             "popq %%rbp; \n\t"
//             "popq %%rax; \n\t"
//             "popq %%r11; \n\t"
//             "popq %%rcx; \n\t"
//             "popq %%rdi; \n\t"
//             "popq %%r9; \n\t"
//             "popq %%r8; \n\t"
//             "popq %%r10; \n\t"
//             "popq %%rdx; \n\t"
//             "popq %%rsi; \n\t"
//             "popq %%rbx; \n\t"
//             // "movq $0x300, %rax; \n\t"
//             // "vmcall; \n\t"
//             "add $0x18, %%rsp; \n\t"
//             "retq; \n\t"//return to interrupted instruction
//             ::"m"(sig_handler):);
//     return;
// }

