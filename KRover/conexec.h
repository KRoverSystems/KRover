#ifndef _CON_EXEC_H__
#define _CON_EXEC_H__

#include <linux/types.h>
#include <iostream>
#include <vector>
#include <asm/ptrace.h>
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "thinctrl.h"
#include "centralhub.h"
#include "defines.h"

struct OprndInfo;
class SymInfoDB;
class VMState;

namespace Dyninst::InstructionAPI {
class Instruction;
class Expression;
}

class ConExecutor {

   private:
    void* T_page;   //The page for ana to execute T_Insn 
    char Jmp_RIP_Insn[6];
    char Lea_RIP_Insn[7];
    bool firstRipRelDone = false;
    bool isPrevR14Relative = false;
    unsigned char NopBytes[15] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

    bool if_condition_fail (entryID opera_id, struct pt_regs* regs);
    bool bind_value_for_exp(Instruction* instr, Expression::Ptr target, struct pt_regs* regs);
    bool emul_cf_inst(Instruction* instr, InsnCategory Cate, struct pt_regs* regs);
    int RewRIPInsn(void* T_insn, void* orig_insn_addr, Instruction* instr);
    bool ClearTinsn(void* T_addr, int size);
    bool InsertInsnUpdateR15(void* nt_t_page, ulong newR15);
    bool checkIfMemUseWriteReg(Instruction* in, std::set<int> writeRegIDs);
    bool checkIfImplicitMemUseWriteReg(Instruction* in, std::set<int> writeRegIDs);
    void ModifyR15ToR14(unsigned char* newInst, unsigned char* oldInst, int size) ;

   public:

    CThinCtrl* m_ThinCtrl;
    ConExecutor(); 
    ~ConExecutor(){}; 
    
    uint preCIE(Instruction* in);
    bool InsnDispatch(Instruction* instr, struct pt_regs* regs, uint mode);
    bool BlockDispatch(Address S_Addr, struct pt_regs* regs);
    unsigned long read_fs2 (void);
    void write_fs2 (unsigned long base);
    bool checkInst (void *T_insn, Instruction *instr) ;
    int RewRIPInsn (unsigned char *dest, unsigned char *src, int size, bool bUseR14);
    bool checkInst (unsigned char *r1xcode, unsigned char *ripcode, bool bUseR14);
    void AddjustR14R15 (bool bUseR14);
};

#endif  // !_CON_EXEC_H__
