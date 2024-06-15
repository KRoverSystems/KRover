//This page is mapped at 0x7f900090b000
//0x7f9000905fe8: target rip
//0x7f9000905fe0: rax 
//0x7f9000905fd8: rcx
//0x7f9000905fd0: 
//0x7f9000905fc8: addr of normal malloc/free ret handler
//0x7f9000905fc0: addr of syscall_handler
//0x7f9000905fb8: addr of pf_handler
//0x7f9000905fb0: addr of entry_gate

// this page is NX in a-EPT, but X in t-EPT
void syscall_exit (void);
asm (" .text");
asm (" .type    syscall_exit, @function");
asm ("syscall_exit: \n");
// asm ("movq %rcx, -0x5d68(%rip) \n");
// asm ("movq %rax, -0x5d69(%rip) \n");
// asm ("movq %rsp, -0x5d6a(%rip) \n");
asm ("movq %rcx, -0x5290(%rip) \n");
asm ("movq %rax, -0x528f(%rip) \n");
asm ("leaq -0xaf10(%rip), %rax \n");
asm ("jmpq *%rax \n");
// // asm ("vmcall \n");
// // asm ("movq %rsp, -0x5296(%rip) \n");
// asm ("movq $0x0, %rax \n");
// asm ("movq $0x9, %rcx \n");
// asm ("vmfunc \n");
// // asm ("movq -0x52c7(%rip), %rax \n");
// // asm ("vmcall \n");
// // asm ("jmpq *0x5d2b(%rip) \n");//jump to syscall_store_context
// asm ("jmpq *-0x52c6(%rip) \n");//jump to syscall_store_context
// asm ("vmcall \n");

