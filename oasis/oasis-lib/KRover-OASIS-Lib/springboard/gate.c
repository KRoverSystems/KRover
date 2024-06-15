//This page is mapped at 0x7f9000900000
//0x7f9000905fe8: target rip
//0x7f9000905fe0: rax 
//0x7f9000905fd8: rcx
//0x7f9000905fd0: 
//0x7f9000905fc8: addr of normal malloc/free ret handler
//0x7f9000905fc0: addr of syscall_handler
//0x7f9000905fb8: addr of pf_handler
//0x7f9000905fb0: addr of entry_gate
//the addr of entry_gate and ret_exit_gate are hardcoded in nme.c
//the addr of pf_exit and syscall_exit are hardcoded in imee.c

void entry_gate (void);
asm (" .text");
asm (" .type    entry_gate, @function");
asm ("entry_gate: \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x0, %rcx \n");
asm ("vmfunc \n");
// asm ("movq $0x7ffff7aa44f0, %rax \n");
// asm ("movq (%rax), %rax \n");
// asm ("vmcall \n");
asm ("movq 0x5d5f(%rip), %rcx \n");
asm ("movq 0x5d60(%rip), %rax \n");
// asm ("vmcall \n");
// asm ("syscall \n");
asm ("jmpq *0x5d62(%rip) \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

/* TODO: pass ana_stack & ana_handler into here */
void ret_exit_gate (void);
asm (" .text");
asm (" .type    ret_exit_gate, @function");
asm ("ret_exit_gate: \n");
asm ("movq %rcx, 0x5d3f(%rip) \n");
asm ("movq %rax, 0x5d40(%rip) \n");//since rsp stores rax
// asm ("movq %rsp, 0x5d3f(%rip) \n");
// asm ("vmcall \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x9, %rcx \n");
asm ("vmfunc \n");
// asm ("vmcall \n");
asm ("jmpq *0x5d11(%rip) \n");//jump to malloc/free ret handler
// asm ("vmcall \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

void pf_exit (void);
asm (" .text");
asm (" .type    pf_exit, @function");
asm ("pf_exit: \n");
asm ("movq %rcx, 0x5d0b(%rip) \n");
asm ("movq %rax, 0x5d0c(%rip) \n");//since rsp stores rax
// asm ("movq %rsp, 0x5d3f(%rip) \n");
// asm ("vmcall \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x9, %rcx \n");
asm ("vmfunc \n");
asm ("movq 0x0(%rsp), %rax \n");
asm ("movq 0x8(%rsp), %rbx \n");
asm ("movq 0x20(%rsp), %rcx \n");
asm ("vmcall \n");
asm ("jmpq *0x5ccd(%rip) \n");//jump to malloc/free ret handler
// asm ("movq (%rsp), %rdi \n");
// asm ("movq 0x8(%rsp), %rsi \n");
// asm ("movq 0x10(%rsp), %rdx \n");
// asm ("movq 0x20(%rsp), %rcx \n");
// asm ("movq %cr2, %rbx \n");
// asm ("vmcall \n");
// asm ("movq $0x0, %rax \n");
// asm ("movq $0x9, %rcx \n");
// asm ("movq %rax, %rcx \n");
// asm ("vmfunc \n");
// // asm ("mov 0x5cc2(%rip), %rdx \n");
// // asm ("vmcall \n");
// asm ("jmpq *0x5c2c(%rip) \n");//jump to int3_store_context1
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
// asm ("nop \n");
asm ("nop \n");

void sysret_exit_gate (void);
asm (" .text");
asm (" .type    sysret_exit_gate, @function");
asm ("sysret_exit_gate: \n");
asm ("movq %rcx, 0x5cd4(%rip) \n");
asm ("movq %rax, 0x5cd5(%rip) \n");
// asm ("movq %rsp, 0x5cc3(%rip) \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x9, %rcx \n");
asm ("vmfunc \n");
asm ("jmpq *0x5cae(%rip) \n");//jump to int3_store_context1
// asm ("vmcall \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

void int3_exit_gate (void);
asm (" .text");
asm (" .type    int3_exit_gate, @function");
asm ("int3_exit_gate: \n");
asm ("movq %rcx, 0x5c9f(%rip) \n");
asm ("movq %rax, 0x5ca0(%rip) \n");//since rsp stores rax
// asm ("movq %rsp, 0x5d3f(%rip) \n");
// asm ("vmcall \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x9, %rcx \n");
asm ("vmfunc \n");
// asm ("vmcall \n");
asm ("jmpq *0x5c51(%rip) \n");//jump to malloc/free ret handler
// asm ("vmcall \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

void syscall_exit_gate (void);
asm (" .text");
asm (" .type    syscall_exit_gate, @function");
asm ("syscall_exit_gate: \n");
// asm ("movq %rcx, 0x5cd4(%rip) \n");
// asm ("movq %rax, 0x5cd5(%rip) \n");
// // asm ("movq %rsp, 0x5cc3(%rip) \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x9, %rcx \n");
asm ("vmfunc \n");
asm ("jmpq *0x5c43(%rip) \n");//jump to int3_store_context1
// asm ("vmcall \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

void ve_exit_gate (void);
asm (" .text");
asm (" .type    ve_exit_gate, @function");
asm ("ve_exit_gate: \n");
asm ("movq %rcx, 0x5c44(%rip) \n");
asm ("movq %rax, 0x5c45(%rip) \n");//since rsp stores rax
// asm ("movq %rsp, 0x5d3f(%rip) \n");
// asm ("vmcall \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x9, %rcx \n");
asm ("vmfunc \n");
// asm ("vmcall \n");
asm ("jmpq *0x5bee(%rip) \n");//jump to malloc/free ret handler
// asm ("vmcall \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

void db_exit_gate (void);
asm (" .text");
asm (" .type    db_exit_gate, @function");
asm ("db_exit_gate: \n");
asm ("movq %rcx, 0x5c0f(%rip) \n");
asm ("movq %rax, 0x5c10(%rip) \n");//since rsp stores rax
// asm ("movq %rsp, 0x5d3f(%rip) \n");
// asm ("vmcall \n");
asm ("movq $0x0, %rax \n");
asm ("movq $0x9, %rcx \n");
asm ("vmfunc \n");
// asm ("vmcall \n");
asm ("jmpq *0x5bb1(%rip) \n");//jump to malloc/free ret handler
// asm ("vmcall \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
