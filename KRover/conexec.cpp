#include <linux/types.h>
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>
#include <iostream>
#include "conexec.h"
#include "VMState.h"
#include "interface.h"
#include "symexec.h"
#include "thinctrl.h"
#include "EFlagsManager.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

extern "C" void InsnExecNonRIP (struct pt_regs* regs);
void InsnExecNonRIP (struct pt_regs* regs);
asm (" .text");
asm (" .type    InsnExecNonRIP, @function");
asm (" .align 4096");
asm ("InsnExecNonRIP: \n");
/* save Ana context on stack */
asm ("pushq %rax \n"); 
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rdi \n");//0x58
asm ("pushq %rsi \n");//0x50
asm ("pushq %rbp \n");//0x48
asm ("pushq %r8 \n");//0x40
asm ("pushq %r9 \n");//0x38
asm ("pushq %r10 \n");//0x30
asm ("pushq %r11 \n");//0x28
asm ("pushq %r12 \n");//0x20
asm ("pushq %r13 \n");//0x18
asm ("pushq %r14 \n");//0x10
asm ("pushq %r15 \n");//0x8
asm ("pushf \n");//0x0
asm ("movq %rsp, 0xcf(%rip) \n");//Save A-rsp
/* load target context */
asm ("movq (%rdi), %r15 \n");//addr of pt_regs 
asm ("movq 0x8(%rdi), %r14 \n");
asm ("movq 0x10(%rdi), %r13 \n");
asm ("movq 0x18(%rdi), %r12 \n");
asm ("movq 0x20(%rdi), %rbp \n");
asm ("movq 0x28(%rdi), %rbx \n");
asm ("movq 0x30(%rdi), %r11 \n");
asm ("movq 0x38(%rdi), %r10 \n");
asm ("movq 0x40(%rdi), %r9 \n");
asm ("movq 0x48(%rdi), %r8 \n");
asm ("movq 0x50(%rdi), %rax \n");
asm ("movq 0x58(%rdi), %rcx \n");
asm ("movq 0x60(%rdi), %rdx \n");
asm ("movq 0x68(%rdi), %rsi \n");
asm ("push 0x90(%rdi) \n");
asm ("popf \n");
asm ("movq 0x98(%rdi), %rsp \n");
asm ("movq 0x70(%rdi), %rdi \n");
/* 15-byte nop for T instruction */
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

/* save T context */
asm ("xchg 0x70(%rip), %rsp \n");//Load A-rsp
asm ("push %rdi \n");
asm ("movq 0x60(%rsp), %rdi \n");//addr of pt_regs 
asm ("movq %r15, (%rdi) \n");
asm ("movq %r14, 0x8(%rdi) \n");
asm ("movq %r13, 0x10(%rdi) \n");
asm ("movq %r12, 0x18(%rdi) \n");
asm ("movq %rbp, 0x20(%rdi) \n");
asm ("movq %rbx, 0x28(%rdi) \n");
asm ("movq %r11, 0x30(%rdi) \n");
asm ("movq %r10, 0x38(%rdi) \n");
asm ("movq %r9 , 0x40(%rdi) \n");
asm ("movq %r8 , 0x48(%rdi) \n");
asm ("movq %rax, 0x50(%rdi) \n");
asm ("movq %rcx, 0x58(%rdi) \n");
asm ("movq %rdx, 0x60(%rdi) \n");
asm ("movq %rsi, 0x68(%rdi) \n");
asm ("pop %rsi \n");
asm ("movq %rsi, 0x70(%rdi) \n");//save T-rdi
asm ("pushf \n");
asm ("pop 0x90(%rdi) \n");
asm ("movq 0x20(%rip), %rsi \n");//saved T-rsp
asm ("movq %rsi, 0x98(%rdi) \n");
/* Restore Ana context */
asm ("popf \n");
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
asm ("popq %rax \n");
asm ("retq \n");
asm ("nop \n");//saved Ana-RSP/T-RSP 8-byte 
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

extern "C" unsigned char RIP_R14_R15_START, RIP_R14_R15_END;
//assume RIP Relative instruction only read rip, do not write rip
//so, load r15 with rip; after execution, no need to update r15 and rip
extern "C" void InsnExecRIP (struct pt_regs* regs);
void InsnExecRIP (struct pt_regs* regs);
asm (" .text");
asm (" .type    InsnExecRIP, @function");
asm ("InsnExecRIP: \n");
/* save Ana context on stack */
asm ("pushq %rax \n"); 
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rdi \n");//0x58
asm ("pushq %rsi \n");//0x50
asm ("pushq %rbp \n");//0x48
asm ("pushq %r8 \n");//0x40
asm ("pushq %r9 \n");//0x38
asm ("pushq %r10 \n");//0x30
asm ("pushq %r11 \n");//0x28
asm ("pushq %r12 \n");//0x20
asm ("pushq %r13 \n");//0x18
asm ("pushq %r14 \n");//0x10
asm ("pushq %r15 \n");//0x8
asm ("pushf \n");//0x0
asm ("movq %rsp, 0xd0(%rip) \n");//Save A-rsp

asm ("RIP_R14_R15_START :\n") ;
asm (".global RIP_R14_R15_START") ;

/* load target context */
asm ("movq 0x80(%rdi), %r15 \n");//rdi stores addr of pt_regs, load r15 with rip 
asm ("movq 0x8(%rdi), %r14 \n");

asm ("RIP_R14_R15_END :\n") ;
asm (".global RIP_R14_R15_END") ;

asm ("movq 0x10(%rdi), %r13 \n");
asm ("movq 0x18(%rdi), %r12 \n");
asm ("movq 0x20(%rdi), %rbp \n");
asm ("movq 0x28(%rdi), %rbx \n");
asm ("movq 0x30(%rdi), %r11 \n");
asm ("movq 0x38(%rdi), %r10 \n");
asm ("movq 0x40(%rdi), %r9 \n");
asm ("movq 0x48(%rdi), %r8 \n");
asm ("movq 0x50(%rdi), %rax \n");
asm ("movq 0x58(%rdi), %rcx \n");
asm ("movq 0x60(%rdi), %rdx \n");
asm ("movq 0x68(%rdi), %rsi \n");
asm ("push 0x90(%rdi) \n");
asm ("popf \n");
asm ("movq 0x98(%rdi), %rsp \n");
asm ("movq 0x70(%rdi), %rdi \n");
/* 15-byte nop for T instruction */
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
/* save T context */
asm ("xchg %rsp, 0x6d(%rip) \n");//restore A-rsp, save T-rsp
asm ("push %rdi \n");
asm ("movq 0x60(%rsp), %rdi \n");//addr of pt_regs 
// asm ("movq %r15, (%rdi) \n");//no need to update r15
asm ("movq %r14, 0x8(%rdi) \n");
asm ("movq %r13, 0x10(%rdi) \n");
asm ("movq %r12, 0x18(%rdi) \n");
asm ("movq %rbp, 0x20(%rdi) \n");
asm ("movq %rbx, 0x28(%rdi) \n");
asm ("movq %r11, 0x30(%rdi) \n");
asm ("movq %r10, 0x38(%rdi) \n");
asm ("movq %r9 , 0x40(%rdi) \n");
asm ("movq %r8 , 0x48(%rdi) \n");
asm ("movq %rax, 0x50(%rdi) \n");
asm ("movq %rcx, 0x58(%rdi) \n");
asm ("movq %rdx, 0x60(%rdi) \n");
asm ("movq %rsi, 0x68(%rdi) \n");
asm ("pop %rsi \n");
asm ("movq %rsi, 0x70(%rdi) \n");//save T-rdi
asm ("pushf \n");
asm ("pop 0x90(%rdi) \n");
asm ("movq 0x20(%rip), %rsi \n");//saved T-rsp
asm ("movq %rsi, 0x98(%rdi) \n");
/* Restore Ana context */
asm ("popf \n");
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
asm ("popq %rax \n");
asm ("retq \n");
asm ("nop \n");//saved Ana-RSP/T-RSP 8-byte 
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

//r15 will be reload with a IMM before the rewritten rip rel insn
extern "C" void BlockExecRIP (struct pt_regs* regs);
void BlockExecRIP (struct pt_regs* regs);
asm (" .text");
asm (" .type    BlockExecRIP, @function");
asm ("BlockExecRIP: \n");
/* save Ana context on stack */
asm ("pushq %rax \n"); 
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rdi \n");//0x58
asm ("pushq %rsi \n");//0x50
asm ("pushq %rbp \n");//0x48
asm ("pushq %r8 \n");//0x40
asm ("pushq %r9 \n");//0x38
asm ("pushq %r10 \n");//0x30
asm ("pushq %r11 \n");//0x28
asm ("pushq %r12 \n");//0x20
asm ("pushq %r13 \n");//0x18
asm ("pushq %r14 \n");//0x10
asm ("pushq %r15 \n");//0x8
asm ("pushf \n");//0x0
asm ("movq %rsp, 0xdc(%rip) \n");//Save A-rsp into saved_rsp 
/* load target context */
/* r15 will be reload with a IMM in T_page */
asm ("movq 0x8(%rdi), %r14 \n"); //rdi stores addr of pt_regs
asm ("movq 0x10(%rdi), %r13 \n");
asm ("movq 0x18(%rdi), %r12 \n");
asm ("movq 0x20(%rdi), %rbp \n");
asm ("movq 0x28(%rdi), %rbx \n");
asm ("movq 0x30(%rdi), %r11 \n");
asm ("movq 0x38(%rdi), %r10 \n");
asm ("movq 0x40(%rdi), %r9 \n");
asm ("movq 0x48(%rdi), %r8 \n");
asm ("movq 0x50(%rdi), %rax \n");
asm ("movq 0x58(%rdi), %rcx \n");
asm ("movq 0x60(%rdi), %rdx \n");
asm ("movq 0x68(%rdi), %rsi \n");
asm ("push 0x90(%rdi) \n");
asm ("popf \n");
asm ("movq 0x98(%rdi), %rsp \n");
asm ("movq 0x70(%rdi), %rdi \n");
/* jmp to T_page. 8-nop to store the addr of T_page */
asm ("jmpq *0x88(%rip) \n");//Jump_to_T_Addr
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
/* callback to check if mem involves symbol */
asm ("Call_Back: \n");//actually, it is a jmp insn on T page, so we need to save T rip by ourself
asm ("movq %r15, 0x89(%rip) \n");//Saved_T_RIP
/* BlkExec_RET: save T context except r15 */
asm ("End_T: \n");
asm ("xchg %rsp, 0x7a(%rip) \n");//restore A-rsp, save T-rsp
asm ("push %rdi \n");
asm ("movq 0x60(%rsp), %rdi \n");//addr of pt_regs 
asm ("movq %r14, 0x8(%rdi) \n");
asm ("movq %r13, 0x10(%rdi) \n");
asm ("movq %r12, 0x18(%rdi) \n");
asm ("movq %rbp, 0x20(%rdi) \n");
asm ("movq %rbx, 0x28(%rdi) \n");
asm ("movq %r11, 0x30(%rdi) \n");
asm ("movq %r10, 0x38(%rdi) \n");
asm ("movq %r9 , 0x40(%rdi) \n");
asm ("movq %r8 , 0x48(%rdi) \n");
asm ("movq %rax, 0x50(%rdi) \n");
asm ("movq %rcx, 0x58(%rdi) \n");
asm ("movq %rdx, 0x60(%rdi) \n");
asm ("movq %rsi, 0x68(%rdi) \n");
asm ("pop %rsi \n");
asm ("movq %rsi, 0x70(%rdi) \n");//save T-rdi into pt_regs
asm ("pushf \n");
asm ("pop 0x90(%rdi) \n");
asm ("movq 0x2d(%rip), %rsi \n");//Saved_RSP
asm ("movq %rsi, 0x98(%rdi) \n");//save T-rsp into pt_regs 
/* Restore Ana context */
asm ("popf \n");
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
asm ("popq %rax \n");
asm ("retq \n");
asm ("  .align 32 \n");
asm ("Jmp_to_T_Addr: \n");// return value indicates how many bytes are copied

asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("Saved_RSP: \n");
asm ("nop \n");//saved Ana-RSP/T-RSP 8-byte 
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("Saved_T_RIP: \n");
asm ("nop \n");//save next T rip before calling callback 
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

void print_byte_code (char* addr, int size) {
    int i ;
    unsigned char * a = (unsigned char*)addr ;
    printf ("<<<<< %d byte code: ", size) ;
    for (i=0; i<size; i++) {
        printf("0x%x, ", a[i]) ;
    }
    printf ("\n") ;
}

bool ConExecutor::ClearTinsn(void* T_addr, int size)
{
    memcpy(T_addr, (void*)&NopBytes[0], size);
    return true;
}

void ConExecutor::write_fs2 (unsigned long base)
{
    asm volatile ("movq %0, %%rax; \n\t"
            "wrfsbase %%rax; \n\t"
            ::"m"(base):"%rax");
    return;
}

unsigned long ConExecutor::read_fs2 (void)
{
    unsigned long base;
    asm volatile (
            "rdfsbase %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            ::"m"(base):"%rax");
    return base;
}

uint ConExecutor::preCIE(Instruction* in)
{
    uint cie_mode = 2; //just CIE, no rewriting of ins

    Expression::Ptr thePC(new RegisterAST(MachRegister::getPC(Arch_x86_64)));
    Expression::Ptr theR15(new RegisterAST(MachRegister(x86_64::r15)));

    if(in->isRead(thePC))
    {
        if (in->isRead(theR15) || in->isWritten(theR15))
            cie_mode = 0; //can not CIE
        else
            cie_mode = 1; //can CIE by replacing RIP with R15
    }

    return cie_mode;
}

void ConExecutor::ModifyR15ToR14(unsigned char* newInst, unsigned char* oldInst, int size) {

	int i = 0;
    bool REX_R = false ;
	memcpy(newInst, oldInst, size) ;

/*	prefix : 
		 0xf0, 									lock
		 0xf2, 0xf3, 							rep/rep
		 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65		Segment
		 0x66									Operand-size override
		 0x67									Address-size override prefix
		 0x4X									REX
*/		 
    // skip the prefix if any;
	while(newInst[i] == 0xf0 ||
		  newInst[i] == 0xf2 || newInst[i] == 0xf3 ||
		  newInst[i] == 0x2e || newInst[i] == 0x36 || newInst[i] == 0x3e || newInst[i] == 0x26 || newInst[i] == 0x64 || newInst[i] == 0x65 ||
		  newInst[i] == 0x66 ||
		  newInst[i] == 0x67 
		  ) i++ ;

    // skip the REX if any;
	if ((newInst[i] & 0x40) == 0x40) {
        REX_R = ((newInst[i]&0x4) == 0x4);
        i++ ;
    } 
	assert (REX_R) ;
    // first byte of opcode:
	if (newInst[i] == 0x0f) {	// not 1 byte opcode
		i++ ;
        // second byte of opcode
		if (newInst[i] == 0x38 || newInst[i] == 0x3a) // not 2 bytes opcode
			i++ ;
	}
	// now i is last byte(3rd) of op code, skip it.
	i ++ ;
    
    // ModR/M byte, REX.R (bit 2) combined with ModR/M.rrr (bit3,4,5) is the register number;
    // here REX.R = 1, and ModR/M=0x3d , rrr=111;
#ifndef _PROD_PERF
    std::cout << "R15/RIP related: " ;
    int j ;
    for(j=0; j< size; j++)
        std::cout << std::hex << (unsigned int)newInst[j] << " ";
    std::cout << std::endl ;
#endif
	assert((newInst[i]&0x38) == 0x38) ; // REX.R=1 rrr=111 0x3d(bit 3,4,5) means %r15
	newInst[i] &= ~8 ;			        // REX.R=1 rrr=110 0x35(bit 3,4,5) means %r14

#ifndef _PROD_PERF
    std::cout << "modified: " ;
    for(j=0; j< size; j++)
        std::cout << std::hex << (unsigned int)newInst[j] << " ";

    std::cout << std::endl ;
#endif

	return ;
}

bool ConExecutor::checkIfMemUseWriteReg(Instruction* in, std::set<int> writeRegIDs)
{
    std::vector<Operand> oprands;
    in->getOperands(oprands);
    for (auto O : oprands) {

#ifdef _DEBUG_OUTPUT            
        std::cout << O.format(Arch_x86_64, 0) << std::endl;
#endif

        if (O.readsMemory())
        { 
            std::vector<Expression::Ptr> memrd;
            auto V = O.getValue();
            V->getChildren(memrd);
            assert(memrd.size() == 1);  // memory dereference: [xxx] -> xxx
            
#ifdef _DEBUG_OUTPUT            
            std::cout << "++++++++++++memrd size " << memrd.size() << std::endl;
#endif
            auto it = *memrd.begin();
            std::vector<Expression::Ptr> exps;
            it->getChildren(exps);
            for (auto E : exps)
            {
                RegisterAST* reg_ptr = dynamic_cast<RegisterAST*>(E.get());
                if (reg_ptr != nullptr)
                {
                    if (writeRegIDs.find(reg_ptr->getID()) != writeRegIDs.end())
                    {
                        return true;
                    }
                }
            }
        }
        if (O.writesMemory()) 
        {
            std::vector<Expression::Ptr> memwr;
            auto V = O.getValue();
            V->getChildren(memwr);
            assert(memwr.size() == 1);  // memory dereference: [xxx] -> xxx
            
#ifdef _DEBUG_OUTPUT            
            std::cout << "+++++++++++memwr size " << memwr.size() << std::endl;
#endif
            auto it = *memwr.begin();
            std::vector<Expression::Ptr> exps;
            it->getChildren(exps);

            for (auto E : exps)
            {
                RegisterAST* reg_ptr = dynamic_cast<RegisterAST*>(E.get());
                if (reg_ptr != nullptr)
                {
                    if (writeRegIDs.find(reg_ptr->getID()) != writeRegIDs.end())
                    {
                        return true;
                    }
                }
            }

        }
    }
    return false;
}

bool ConExecutor::checkIfImplicitMemUseWriteReg(Instruction* in, std::set<int> writeRegIDs)
{
    std::set<Expression::Ptr> memrd = in->getOperation().getImplicitMemReads();
    if(memrd.size() != 0)
    {
        for (auto it : memrd)
        {
            std::vector<Expression::Ptr> exps;
            it->getChildren(exps);

            for (auto E : exps)
            {
                RegisterAST* reg_ptr = dynamic_cast<RegisterAST*>(E.get());
                if (reg_ptr != nullptr)
                {
                    if (writeRegIDs.find(reg_ptr->getID()) != writeRegIDs.end())
                    {
                        return true;
                    }
                }
            }
        }
    }
    
    std::set<Expression::Ptr> memwr = in->getOperation().getImplicitMemWrites();
    if (memwr.size() != 0)
    {
        for (auto it : memwr)
        {
            std::vector<Expression::Ptr> exps;
            it->getChildren(exps);

            for (auto E : exps)
            {
                RegisterAST* reg_ptr = dynamic_cast<RegisterAST*>(E.get());
                if (reg_ptr != nullptr)
                {
                    if (writeRegIDs.find(reg_ptr->getID()) != writeRegIDs.end())
                    {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool ConExecutor::InsertInsnUpdateR15(void* nt_t_page, ulong newR15)
{
    char Insn[10];
    Insn[0] = 0x49;
    Insn[1] = 0xbf;
    int i = 0;
    for (i = 2; i < 10; i ++)
    {
        Insn[i] = ((unsigned char)(newR15>>((i-2)*8))) & 0xff;
    }
    memcpy(nt_t_page, Insn, 10);
    return true;
}

ConExecutor::ConExecutor() 
{
    /* Make the page where three asm function located writable */
    int ret;
    void* execPage = (void*)(((unsigned long)InsnExecNonRIP) & ~0xFFF);
    ret = mprotect(execPage, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    
    /* Init a RIP-relative Jmp Insn which is the last Insn of Block T-Insn Executor */
    auto init = std::initializer_list<unsigned char>({0xff, 0x25, 0x00, 0x00, 0x00, 0x00});
    std::copy(init.begin(), init.end(), Jmp_RIP_Insn);
    T_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    if (T_page == MAP_FAILED)
    {
        printf ("Init T_page failed: %lx. \n", (unsigned long)T_page);
        assert(0);
    }

    init = std::initializer_list<unsigned char>({0x4c, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00});
    std::copy(init.begin(), init.end(), Lea_RIP_Insn);
}

bool ConExecutor::checkInst (void *T_insn, Instruction *instr) {
   Instruction inst;
 
   InstructionDecoder decoder ((const unsigned char*)T_insn,
           InstructionDecoder::maxInstructionLength,
           Architecture::Arch_x86_64) ;
 
   inst = decoder.decode((const unsigned char*)T_insn) ;
  
   char r15_ins_string[64] ;
   char rip_ins_string[64] ;
   int i = 0 ;
   strcpy(r15_ins_string, inst.format().c_str()) ;
   strcpy(rip_ins_string, instr->format().c_str()) ;
 
   while ((r15_ins_string[i] == rip_ins_string[i]) ||
          (r15_ins_string[i] == '1' && rip_ins_string[i] == 'i') ||
          (r15_ins_string[i] == '5' && rip_ins_string[i] == 'p')
          ) {
       if (r15_ins_string[i] == 0 && rip_ins_string[i] == 0)
           return true ;
       i ++ ;
   }
   std::cout << "r15 instruction: \n"<< inst.format() << std::endl ;
 
   return false ;
}

#define MAX_INSTRUCTION_LEN 12
int ConExecutor::RewRIPInsn (unsigned char *dest, unsigned char *src, int size, bool bUseR14) {

    unsigned char rip_code[MAX_INSTRUCTION_LEN] ;
    int i = 0 ;
    int REX_Byte = -1 ;
    bool REX_R = false, REX_B = false, REX_X = false ;
    unsigned char mod_REG_RM ;
    bool pre_fix_done = false ;

    memset (rip_code, 0, sizeof(rip_code)) ;
    memcpy (rip_code, src, size) ;

    /*	prefix : 
		 0xf0, 									lock
		 0xf2, 0xf3, 							rep/rep
		 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65		Segment
		 0x66									Operand-size override
		 0x67									Address-size override prefix
		 0x4X									REX
    */	
    // skip the prefix if any;
    while (!pre_fix_done) {
        switch (rip_code[i]) {
            case 0xf0 :                     // lock
                dest[i] = rip_code[i] ;
                i ++ ;
                continue ;

            case 0xf2 :                     // repnz
            case 0xf3 :                     // repz
                dest[i] = rip_code[i] ;
                i ++ ;
                continue ;
            
            case 0x2e :
            case 0x36 :
            case 0x3e :
            case 0x26 :
            case 0x64 :
            case 0x65 :                     // segment
                dest[i] = rip_code[i] ;
                i ++ ;
                continue ;
            
            case 0x66 :                     // operand-size override.
                dest[i] = rip_code[i] ;
                i ++ ;
                continue ;

            case 0x67 :                     // Address-size override prefix
                dest[i] = rip_code[i] ;
                i ++ ;
                continue ;
            
            default :
                // REX, if there is a REX, it must be the last prefix, next byte is opcode;
                if ((rip_code[i] & 0xf0) == 0x40) {
                    REX_Byte = i ;
                    REX_R = ((rip_code[i]&0x4) == 0x4) ;
                    REX_B = ((rip_code[i]&0x1) == 0x1) ;
                    REX_X = ((rip_code[i]&0x2) == 0x2) ;
                    i ++ ;
                }
                pre_fix_done = true ;
                break ;
        } ;
    };
    
    if (REX_Byte != -1) {
        
        dest[REX_Byte] = rip_code[REX_Byte] | 1 ;       // combined with mod_REG_RM.rm build reg No. r15.
        REX_Byte = 0 ;
    } else {

        dest[i] = 0x41 ;
        REX_Byte = 1 ;
    }

    // first byte of opcode:
	if (rip_code[i] == 0x0f) {	// not 1 byte opcode
        dest[i+REX_Byte] = rip_code[i] ;
		i ++ ;
        // second byte of opcode
		if (rip_code[i] == 0x38 || rip_code[i] == 0x3a) { // not 2 bytes opcode
            dest[i+REX_Byte] = rip_code[i] ;
			i ++ ;
        }
	}
	// now i is the prime op code byte.
    dest[i+REX_Byte] = rip_code[i] ;
	i ++ ;
    // modR/MReg
    mod_REG_RM = rip_code[i] ;    
    unsigned char mod = (mod_REG_RM & 0xc0) >> 6 ;
    unsigned char rm  = (mod_REG_RM & 0x7) ;
    unsigned char reg = (mod_REG_RM & 0x38) >> 3 ;
    // rm should be 0b101, which is for rip.
    if (rm != 0x5 || mod != 0) {
        return 0 ;
    }

    mod = 0x2 ;
    if (bUseR14)
        rm = 0x6 ;
    else
        rm = 0x7 ;

    mod_REG_RM = (mod << 6)  | (reg<<3) | rm ;

    dest[i+REX_Byte] = mod_REG_RM ;
    i ++ ;

    for(;i<size; i++)
        dest[i+REX_Byte] = rip_code[i] ;

    return size + REX_Byte;
}
static    char r1x_str[256] ;
static    char rip_str[256] ;
bool ConExecutor::checkInst (unsigned char *r1xcode, unsigned char *ripcode, bool bUseR14) {

    return true ;
    Instruction instr1x, instrip;

    InstructionDecoder decoder ((const unsigned char*)r1xcode, 
            InstructionDecoder::maxInstructionLength, 
            Architecture::Arch_x86_64) ;

    instr1x = decoder.decode((const unsigned char*)r1xcode) ;
    instrip = decoder.decode((const unsigned char*)ripcode) ;

    strcpy (r1x_str, instr1x.format().c_str()) ;
    strcpy (rip_str, instrip.format().c_str()) ;
    char* rip = rip_str, *r1x = r1x_str;
    char *s1=r1x, *s2 = rip ;

    char c = bUseR14 ? '4' : '5' ;
    while (1) {

        if (*r1x==0 && *rip==0) return true ; ;
        
        if (*r1x == *rip) {
            r1x ++ ;
            rip ++ ;
            continue ;
        }

        if (*r1x == '1' && *(r1x+1) == c && *rip == 'i' && *(rip+1) == 'p') {
            r1x += 2 ;
            rip += 2 ;
            continue ;
        }

        break ;
    }
    print_byte_code((char*)r1xcode, 12) ;
    print_byte_code((char*)ripcode, 12) ;
    std::cout << instr1x.format() << std::endl ;
    std::cout << instrip.format() << std::endl ;
    assert (0) ;
    return false ;
}

bool ConExecutor::InsnDispatch(Instruction* instr, struct pt_regs* regs, uint mode)
{
    int InsnSize = instr->size();
    ulong crtAddr = regs->rip - InsnSize; 
    switch (mode) {
        case  2:    //rip is not used, no instruction rewriting is required
        {
            void* T_insn = (void*)((char*)InsnExecNonRIP + 0x68);
            memcpy(T_insn, (void*)crtAddr, InsnSize);
            InsnExecNonRIP(regs);
            ClearTinsn(T_insn, InsnSize);
            break ;
        }
        case 1:
        case 0:
        {
            // mode 1 means r15 not in use
            // mode 3 means r15 is in use, we should use r14
            void* T_insn_no_r15 = (void*)((char*)InsnExecRIP + 0x6c);
            bool bUser14 = (mode==0);
            int ret = RewRIPInsn((unsigned char*)T_insn_no_r15, (unsigned char*)instr->ptr(), instr->size(), bUser14) ;
            assert(ret) ;
#ifndef _PROD_PERF
            checkInst((unsigned char*)T_insn_no_r15, (unsigned char*)instr->ptr(), bUser14) ;
#endif
            AddjustR14R15 (bUser14);
            InsnExecRIP(regs);
            ClearTinsn(T_insn_no_r15, 12);
            break ;
        }
        default :
            assert (0) ;
    }

    return 0;
}

extern "C" void R14_Substitute(void);
void R14_Substitute(void);
asm (" .text");
asm (" .type    R14_Substitute, @function");
asm ("R14_Substitute: \n");
/* load target context */
asm ("movq 0x80(%rdi), %r14 \n");//rdi stores addr of pt_regs, load r15 with rip 
asm ("movq 0x0(%rdi), %r15 \n");
asm ("nop \n");//save next T rip before calling callback 
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

extern "C" void R15_Substitute(void);
void R15_Substitute(void);
asm (" .text");
asm (" .type    R15_Substitute, @function");
asm ("R15_Substitute: \n");
/* load target context */
asm ("movq 0x80(%rdi), %r15 \n");//rdi stores addr of pt_regs, load r15 with rip 
asm ("movq 0x8(%rdi), %r14 \n");
asm ("nop \n");//save next T rip before calling callback 
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");
asm ("nop \n");

void ConExecutor::AddjustR14R15 (bool bUseR14) {
    unsigned char *dest = (unsigned char*)&RIP_R14_R15_START ;
    unsigned char *dest_end = (unsigned char*)&RIP_R14_R15_END ;
    unsigned char *src = bUseR14 ? (unsigned char*)(void*)R14_Substitute : (unsigned char*)(void*)R15_Substitute  ;

    while (dest < dest_end) {
        *dest++ = *src++ ;
    }

    dest_end += 0x5e;

    if(bUseR14){
        dest_end[2] = 0x3f;
        dest_end[3] = 0x90;
    }
    else{
        dest_end[2] = 0x77;
        dest_end[3] = 0x08;
    }
}
