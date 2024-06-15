// #define offset 0xffff6a8000000000
#define ana_low 0xfffffe8000000000
#define ana_high 0xfffffeffffffffff
#define pf_stack 0xfffffef020905008
// #define find_n_entry (*find_n_entry_ptr) 
// void (*find_n_entry_ptr)(void) = 0xffffffffff;
// static __attribute__ ((noinline)) unsigned long long rdtsc(void)
// {
//     unsigned long long x;
//     asm volatile (".byte 0x0f, 0x31" : "=A"(x));
//     return x;
// }

void stub (void)
{
    asm volatile ( // "vmcall; \n\t"
        "pushq %rax; \n\t"
        "movq %cr2, %rax; \n\t"
        "pushq %rax; \n\t"//saved err_addr into stack
        "pushq %rdx; \n\t"
        "movq $0xfffffe7fffffffff, %rdx; \n\t"//ana_low
        "cmp %rdx, %rax; \n\t"
        "jbe 1f; \n\t"
        "movq $0xfffffeffffffffff, %rdx; \n\t"//ana_high
        "cmp %rdx, %rax; \n\t"
        "ja 1f; \n\t"
        "movq $0xffff9876, %rax; \n\t"
        "vmcall; \n\t"
        "1: \n\t"
        // for debugging
        "movq $0xffff9876, %rax; \n\t"
        "vmcall; \n\t"
        // "pushq $0x2b; \n\t"
        "movq 0x40(%rsp), %rdx; \n\t"
        "pushq %rdx; \n\t"
        "movq $0xfffffef07ffffc48, %rdx; \n\t"//rsp
        "pushq %rdx; \n\t"
        "pushf; \n\t"
        // "pushq $0x33; \n\t"
        "movq 0x40(%rsp), %rdx; \n\t"
        "pushq %rdx; \n\t"
        "movq $0xfffffef020905008, %rdx; \n\t"
        "movq (%rdx), %rdx; \n\t"//find_n_exit_pf
        // "movq $0x123456789, %rax; \n\t"
        // "vmcall; \n\t"
        "pushq %rdx; \n\t"
        "iretq; \n\t"
        // "callq *%rdx; \n\t"
        );
}
            // "pushq %rsi; \n\t"
            // "pushq %rdx; \n\t"
            // "pushq %r10; \n\t"
            // "pushq %r8; \n\t"
            // "pushq %r9; \n\t"
            // "pushq %rax; \n\t"
            // "pushq %rcx; \n\t"
            // "pushq %r11; \n\t"
            // "pushq %rbx; \n\t"
            // "pushq %rbp; \n\t"
            // "pushq %r15; \n\t"
            // "pushq %r14; \n\t"
            // "pushq %r13; \n\t"
            // "pushq %r12; \n\t"
            // "pushq %rax; \n\t"//push 7th arg on stack
            // "movq %r10, %rcx; \n\t"//prepare the 4th arg in register
            // "lea -0x23f(%rip), %r15; \n\t"
            // "callq *%r15; \n\t"
            // // "vmcall; \n\t"
            // "movq -0x18(%rsp), %rdi; \n\t"
            // "movq -0x20(%rsp), %rsi; \n\t"
            // "movq -0x28(%rsp), %rdx; \n\t"
            // "movq -0x30(%rsp), %rcx; \n\t"
            // "movq -0x38(%rsp), %r8; \n\t"
            // "movq -0x40(%rsp), %r9; \n\t"
            // "movq %rcx, %r10; \n\t"
            // "add $0x8, %rsp; \n\t"
            // "popq %r12; \n\t"
            // "popq %r13; \n\t"
            // "popq %r14; \n\t"
            // "popq %r15; \n\t"
            // "popq %rbp; \n\t"
            // "popq %rbx; \n\t"
            // "popq %r11; \n\t"
            // "popq %rcx; \n\t"
            // "popq %rax; \n\t"
            // "vmcall; \n\t"
            // "popq %r9; \n\t"
            // "popq %r8; \n\t"
            // "popq %r10; \n\t"
            // "popq %rdx; \n\t"
            // "popq %rsi; \n\t"
            // "popq %rdi; \n\t"
            // "jmpq *%rcx; \n\t"
