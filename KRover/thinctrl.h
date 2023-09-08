#ifndef _THINCTRL_H__
#define _THINCTRL_H__

#include <iostream>
#include <vector>
#include "VMState.h"
#include "CodeSource.h"
#include "InstructionDecoder.h"
#include "defines.h"

class VMState;
class CAnalyze;
class SymExecutor;
class ConExecutor;

using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

static __attribute__ ((noinline)) unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long) lo | ((unsigned long long) hi << 32));
}

class opData {

    public :
        Operand *O;
        bool rdmem; //O->readsMemory
        bool wrmem; //O->writesMemory
        bool hasregs; 
        std::set<RegisterAST::Ptr> readRegs;  //read reg list
        std::set<RegisterAST::Ptr> writeRegs; //write reg list
        std::set<uint> readRegIds;  //IDs of read regs
        std::set<uint> writeRegIds; //IDs of write regs

};

class wrapInstruction {

    public:
        Instruction * in;
        std::vector<Operand> ioperands;
        std::vector<opData*> opdata_ptrs;
        ulong igs_base;

        //for cie
        uint cie_mode = 2; //whether a given instruction can be CIE and in which way?
        bool isRepIns = false; //rep prefix
        entryID bInsID;
        uint xoredOperand[2] = {0, 0};  // {reg_idx, reg_sz}
        InsnCategory cate;

    wrapInstruction(Instruction* I){
        in = I;
        in->getOperands(ioperands);
        uint regIDs[2] = {0x0, 0x0};
        uint regSz = 0;
        int op_count = 0;
        for (auto O : ioperands)
        {
            uint rid;
            opData* OD = new opData;
            OD->O = &O;
            OD->rdmem = O.readsMemory();
            OD->wrmem = O.writesMemory();
            O.getReadSet(OD->readRegs); //get read registers
            for (auto R : OD->readRegs){
                rid = R->getID();
                OD->readRegIds.insert(rid); //record reg_id for each reg
            }
            O.getWriteSet(OD->writeRegs); //get write registers
            for (auto R : OD->writeRegs){
                rid = R->getID();
                OD->writeRegIds.insert(rid); //record reg-id for each reg
            }
            if((OD->writeRegs.size() + OD->readRegs.size()) >= 0) //record if operand has read or write regs
                OD->hasregs = true;
            else
                OD->hasregs = false;

            opdata_ptrs.push_back(OD);
            bInsID = in->getOperation().getID();
            if(bInsID == e_xor){ //handling the case of XORing same register eg: xor %eax %eax,    xor %rax %rax  etc...
                auto V = OD->O->getValue();
                std::vector<Expression::Ptr> exps;
                V->getChildren(exps);
                if(exps.size() == 0 && OD->hasregs){ //if the operand is in the form of just a single register such as %eax, not immediate or an expression like 0x10(%eax) etc
                    if(OD->readRegs.size() == 1){ 
                        for (auto R : OD->readRegs){      //get the reg idx of the signle register operand
                            regIDs[op_count] = R->getID(); //destination operand is both read and write, source operan is read, so both operands will come here
                            if(regSz == 0)
                                regSz = R->size();
                        }
                    }
                }
                op_count++;
            }
        }
        if(regIDs[0] != 0x0 && regIDs[1] != 0x0 && (regIDs[0] == regIDs[1])){
            xoredOperand[0] = regIDs[0]; //set register idx
            xoredOperand[1] = regSz;     //set reg size
        }
    }
};

class MyCodeRegion : public CodeRegion {
    private:
        std::map<Address, Address> knowData;
    public:
        MyCodeRegion (Address add1, Address add2);
        ~MyCodeRegion();

        /* InstructionSource implementation */
        bool isValidAddress(const Address) const;
        void* getPtrToInstruction(const Address) const;
        void* getPtrToData(const Address) const;
        unsigned int getAddressWidth() const;
        bool isCode(const Address) const;
        bool isData(const Address) const;
        bool isReadOnly(const Address) const;

        Address offset() const;
        Address length() const;
        Architecture getArch() const;

        /** interval **/
        Address low() const { return offset(); }
        Address high() const { return offset() + length(); }
};

/* MyCodeSource */
class PARSER_EXPORT MyCodeSource: public CodeSource {
    private:
        // void init_regions(Address add1, Address add2);
        void init_regions(Address adds, Address adde);
        void init_hints();

        mutable CodeRegion* _lookup_cache;
    public:
        // MyCodeSource(Address add1, Address add2);
        MyCodeSource(Address adds, Address adde);
        ~MyCodeSource();
        
        /* InstructionSource implementation */
        bool isValidAddress(const Address) const;
        void* getPtrToInstruction(const Address) const;
        void* getPtrToData(const Address) const;
        unsigned int getAddressWidth() const;
        bool isCode(const Address) const;
        bool isData(const Address) const;
        bool isReadOnly(const Address) const;

        Address offset() const;
        Address length() const;
        Architecture getArch() const;

        void MyaddRegion (CodeRegion *cr)
        {
            addRegion(cr);
            return;
        }

    private:
        CodeRegion* lookup_region(const Address addr) const;
};

class CThinCtrl {
    public:
    MyCodeSource* m_sts;
    CodeObject* m_co;
    CodeRegion* m_cr;
    std::shared_ptr<CAnalyze> m_Analyze;
    InstructionDecoder* decoder;
    std::map<uint, wrapInstruction*> m_InsnCache;
    VMState *m_VM;
    SYCPUState *m_CPU;    
    std::shared_ptr<SymExecutor> m_SymExecutor;
    std::shared_ptr<ConExecutor> m_ConExecutor;
    std::shared_ptr<EFlagsManager> m_EFlagsMgr;

    bool bPath_explore ;

#ifdef _PreDisassemble
    ulong m_endRIP;
    std::map<uint64_t, ulong> m_NextIP;
    bool ReadNextIPFromFile();
    bool PreParseOperand(Instruction* in);
#endif

    public:
    CThinCtrl(VMState* VM, ulong adds, ulong adde);
    ~CThinCtrl();

    void setAna(std::shared_ptr<CAnalyze> analyze) {m_Analyze = analyze;};
    bool processFunction(ulong addr);
    bool ExecOneInsn(ulong addr){printf("FIX\n"); return false;};
    bool hasSymOperand(wrapInstruction* win);
    ulong isUseGS(Instruction* in);
    bool analyzeExecution(pt_regs *m_regs, unsigned long term_rsp);
    std::shared_ptr<SymExecutor> shareSymExecutor(){return m_SymExecutor;}    
    std::shared_ptr<ConExecutor> shareConExecutor(){return m_ConExecutor;}    
    std::shared_ptr<EFlagsManager> shareEflagsMgr(){return m_EFlagsMgr;} 

   private:
    bool setReadRegs(DAPIInstr *I);
    bool setReadRegs(DAPIInstrPtr &I);
    bool parseOperands(InstrInfo *info);
    bool maySymbolicRegister(uint ID);
    bool maySymbolicMemoryCell(ulong memory_addr, int width);

    bool _mayOperandUseSymbol_XX(OprndInfoPtr &oi);
    bool _mayOperandUseSymbol_RX(DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool _mayOperandUseSymbol_XW(DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool _mayOperandUseSymbol_RW(DAPIInstrPtr &I, OprndInfoPtr &oi);

    bool chkCondFail (entryID opera_id, struct pt_regs* regs);
    bool dependFlagCon(Instruction* insn, bool &bChoice);
    bool dispatchRet(Instruction* in, struct pt_regs* m_regs);
    bool dispatchCall(Instruction* in, struct pt_regs* m_regs);
    bool dispatchBranch(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count);
    bool updateJCCDecision(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count);
    bool bindRegValForMemOpd(DIAPIOperandPtr op);
    ulong getSegRegVal(Instruction* in);
    bool calculateBinaryFunction (Dyninst::InstructionAPI::BinaryFunction* bf, KVExprPtr &exprPtr) ;
    bool OpdhasSymReg(opData* OD);
    bool OpdhasSymMemCell(opData* OD, Operand* O, ulong gs_base);
    bool OpdhasSymMemCellRep(opData* OD, Operand* O, ulong gs_base);
    void dumpMregs(pt_regs *m_regs);
    bool dispatchCIE(Instruction* in, struct pt_regs* m_regs, uint mode);
    bool dispatchSIE(Instruction *in);
    bool stageForCIESIE(wrapInstruction *win, struct pt_regs *m_regs, bool do_cie);
    bool execErrorHandle(int err);
    bool evalSinglePathTermination(struct pt_regs * m_regs, InsnCategory cate);
    bool evalPathSearchtermination();
    void getMemoryAccesses(Instruction *in);
    bool checkImplicitMemAccess(Instruction *I);
    bool getBranchAddress(Instruction* in, uint64_t &trueBranch, uint64_t &falseBranch) ;
    void startPathExplore (void) ;
};

#endif  // !_THINCTRL_H__
