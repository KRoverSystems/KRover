#include <iostream>
#include <fstream>
#include "thinctrl.h"
#include "Analyze.h"
#include <linux/types.h>
#include <signal.h>
#include <ucontext.h>
#include "CPUState.h"
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "Visitor.h"
#include "Operation_impl.h"
#include "conexec.h"
#include "defines.h"
#include "interface.h"
#include "symexec.h"
#include "EFlagsManager.h"
#include "Expr.h"
#include "HistoryTree.h"
#include "Analyze.h"

extern HistoryManager *g_hm  ;
bool dumpreg = false ;

static struct hm_time {
    unsigned long start ;
    unsigned long start1 ;
    unsigned long end ;
    unsigned long instno ;
} hmt[40] ;
static int hmtround = 0 ; 

using namespace std;

struct ExecData *execData; /*shares execution configs and runtime data bwn the analyzer*/
struct ExecProfile *execProfile;
bool endCurrentPath = false;

unsigned long z3_api_calls = 0;
unsigned long z3_api_clk_cycls[100];
unsigned long tr_0 = 0;
unsigned long tr = 0;
unsigned long tm_0 = 0;
unsigned long tmm = 0;
unsigned long ti_0 = 0;
unsigned long ti = 0;
unsigned long st1_0 = 0;
unsigned long st1 = 0;
unsigned long st2_0 = 0;
unsigned long st2 = 0;
unsigned long st3_0 = 0;
unsigned long st3 = 0;

#ifndef SETUID
#define START_COUNT 0 //138

#define END_COUNT   0  //190
#else
#define START_COUNT 100000 // for test, we will not start path exploring any more.

#define END_COUNT 101500
#endif

uint64_t insn_count = 0;
uint64_t symExe_count = 0;
uint64_t symFlag_count = 0;
uint64_t nop_count = 0;
uint64_t cie_count = 0;
uint64_t sie_count = 0;
uint64_t ret_count = 0;
uint64_t call_count = 0;
uint64_t branch_count = 0;
uint64_t thin_ctrl_invokation_count = 0;


#ifndef _PROD_PERF
    unsigned long kmalloc_f_adr = 0xffffffff8130eab0;
    unsigned long memcpy_in_addr = 0xffffffff81ceda26;
    unsigned long kfree_function_address = 0xffffffff81a4c970;
    unsigned long ins_after_kmaloc_return;
    bool kmalloc_entered;
    bool kmalloc_returned;
    unsigned long memcpy_len;
    unsigned long memcpy_destination;
    unsigned long caller_adr_aft_ret;
    unsigned long kmalloc_buf_address;
    bool cie_operands_pased = false;
    bool parsing_operands_for_mem_adr = false;  //this is used to skip memory access inside parseoperands() when cie operand parsing as requested by ana
    
    bool is_indirect_call = false;
    int call_ins_count = 0;
    unsigned long call_ret_adr_list[256];
    unsigned long bb_count = 0;
#endif

/********************************* MyCodeRegion  *******************************/
MyCodeRegion::MyCodeRegion(Address add1, Address add2)
{
    knowData[add1] = add2;//only one pair in this CodeRegion map
}

MyCodeRegion::~MyCodeRegion()
{

}

bool MyCodeRegion::isValidAddress(const Address addr) const
{
    // return true;
    return contains(addr);
}

void* MyCodeRegion::getPtrToInstruction(const Address addr) const
{
    if (isValidAddress(addr))
    {
        return (void*)addr;
    }
    return NULL;
}

void* MyCodeRegion::getPtrToData(const Address addr) const
{
    if (isValidAddress(addr))
    {
        return (void*)addr;
    }
    return NULL;
}

unsigned int MyCodeRegion::getAddressWidth() const
{
    return 0x10;
}

bool MyCodeRegion::isCode(const Address addr) const
{
    return true;
}

bool MyCodeRegion::isData(const Address addr) const
{
    return false;
}

bool MyCodeRegion::isReadOnly(const Address addr) const
{
    return true;
}

Address MyCodeRegion::offset() const
{
    return knowData.begin()->first;
}

Address MyCodeRegion::length() const
{
    return knowData.begin()->second - knowData.begin()->first ;
}

Architecture MyCodeRegion::getArch() const
{
    Architecture arch = Arch_x86_64;
    return arch;//TODO: 
}

/****************************** MyCodeSource **************************/
void MyCodeSource::init_regions(Address adds, Address adde)
{
    MyCodeRegion *cr;

    cr = new MyCodeRegion(adds, adde);
    MyaddRegion(cr);
}


void MyCodeSource::init_hints()//intialize the std::vector<Hint> _hints;
{
    return;
}

MyCodeSource::~MyCodeSource()
{

}

MyCodeSource::MyCodeSource(Address adds, Address adde)
{
    init_regions(adds, adde);
    init_hints();
}

inline CodeRegion* MyCodeSource::lookup_region(const Address addr) const
{
    CodeRegion *ret = NULL;
    if (_lookup_cache && _lookup_cache->contains(addr))
        ret = _lookup_cache;
    else {
        set<CodeRegion *> stab;
        int rcnt = findRegions(addr, stab);

        assert(rcnt <=1 || regionsOverlap());

        if (rcnt) {
            ret = *stab.begin();
            _lookup_cache = ret;
        }
    }
    return ret;
}

bool MyCodeSource::isValidAddress(const Address addr) const
{
    CodeRegion *cr = lookup_region(addr);
    if (cr)
    {
        return cr->isValidAddress(addr);
    }
    else
    {
        return false;
    }
}

void* MyCodeSource::getPtrToInstruction(const Address addr) const
{
    return (void*)addr;
}

void* MyCodeSource::getPtrToData(const Address addr) const
{
    return NULL;
}

unsigned int MyCodeSource::getAddressWidth() const
{
    return 0x10;
}

bool MyCodeSource::isCode(const Address addr) const
{
    return true;
}

bool MyCodeSource::isData(const Address addr) const
{
    return false;
}

bool MyCodeSource::isReadOnly(const Address addr) const
{
    return true;
}

Address MyCodeSource::offset() const
{
    return _regions[0]->offset();
}

Address MyCodeSource::length() const
{
    return _regions[0]->length();
}

Architecture MyCodeSource::getArch() const
{
    Architecture arch = Arch_x86_64;
    return arch;//TODO: 
}

unsigned long long tt0, tt1, tt;
unsigned long long ttt0, ttt1, ttt;


class PrintVisitor : public Visitor {
    public:
        PrintVisitor() {};
        ~PrintVisitor() {};
        virtual void visit(BinaryFunction* b) {
            std::cout << "\tVisiting binary function " << b->format(defaultStyle) << std::endl;
        }
        virtual void visit(Immediate* i) {
            std::cout << "\tVisiting imm " << i->format(Arch_x86_64, defaultStyle) << std::endl;
        }
        virtual void visit(RegisterAST* r) {
            std::cout << "\tVisiting regsiter " << r->getID().name() << std::endl;
            auto A = r->eval();
            assert(A.defined);
            std::cout << "reg bind value " << A.convert<ulong>() << std::endl;
        }
        virtual void visit(Dereference* d) {
            std::cout << "\tVisiting deference " << std::endl;
        }
};


/* Expr visitor */
class ExprEvalVisitor : public Visitor {
    private: 
        VMState* state;
    public:
        ExprEvalVisitor(VMState* VM) : state(VM) {};
        ExprEvalVisitor() : state(NULL) {};
        ~ExprEvalVisitor() {};
        virtual void visit(BinaryFunction* b) {};
        virtual void visit(Immediate* i) {};
        bool symreg = false;
        virtual void visit(RegisterAST* r) {
            uint indx = r->getID();
            uint size = r->size();
            RegValue RV = {indx, size};
            bool res = state->readRegister(RV);
            assert(res);

            if (RV.bsym) {
                symreg = true;
                cout << r->format() << " is sym!!!" << "\n";
                RV.expr->print() ;
                std::cout << std::endl;
            } else { 
                switch (size) {
                    case 8:
                    {   
                        r->setValue(Result(s64, RV.i64));
                    }
                        break;
                    case 4:
                        r->setValue(Result(s32, RV.i32));
                        break;
                    case 2:
                        r->setValue(Result(s16, RV.i16));
                        break;
                    case 1:
                        r->setValue(Result(s8, RV.i8));
                        break;
                    default:
                        FIX_ME();
                        break;
                }
            }
        }
        virtual void visit(Dereference* d) {};
};

CThinCtrl::CThinCtrl(VMState* VM, ulong adds, ulong adde) {
    m_VM = VM;
    m_sts = new MyCodeSource(adds, adde);
    m_co = new CodeObject(m_sts);
    m_cr = *(m_sts->regions().begin());
    decoder = new InstructionDecoder((unsigned char *)m_sts->getPtrToInstruction(m_cr->low()), InstructionDecoder::maxInstructionLength, m_sts->getArch());
    
    m_SymExecutor.reset(new SymExecutor());
    m_ConExecutor.reset(new ConExecutor());
    m_ConExecutor.get()->m_ThinCtrl = this;
    m_EFlagsMgr = m_VM->m_EFlagsMgr;
    bPath_explore = false ;
}

CThinCtrl::~CThinCtrl() {}

bool CThinCtrl::dependFlagCon(Instruction* insn, bool &bChoice) {
    
    if(m_EFlagsMgr->isConditionalExecuteInstr(insn->getOperation().getID()))
    {
        return m_EFlagsMgr->DependencyFlagConcreted(insn->getOperation().getID(), bChoice) ;
    }
    else
    {
        return true ;
    }
}

bool CThinCtrl::chkCondFail (entryID opera_id, struct pt_regs* regs)
{
    bool ret;
    unsigned long eflags;
    eflags = regs->eflags;
    bool cf, pf, zf, sf, of;
    cf = eflags & 0x1;
    pf = (eflags >> 2) & 0x1;
    zf = (eflags >> 6) & 0x1;
    sf = (eflags >> 7) & 0x1;
    of = (eflags >> 11) & 0x1;

    ret = false;
   
    /* the index operation is in dyninst/common/h/entryIDs.h */
    switch (opera_id)
    {
        case e_jnbe:
        // if (cf && zf)
            if (cf || zf)
                ret = true;
                break;
        case e_jb: 
            if (!cf)
                ret = true;
                break;
        case e_jnb: 
            if (cf)
                ret = true;
                break;
        case e_jnb_jae_j: 
            if (cf)
                ret = true;
                break;
        case e_jb_jnaej_j:
            if (!cf)
                ret = true;
                break;
        case e_jbe:
            if ((!cf) && (!zf))
                ret = true;
                break;
        case e_jz:
            if (!zf)
                ret = true;
                break;
        case e_jnz:
            if (zf)
                ret = true;
                break;

        case e_jnp:
            if (pf)
                ret = true;
                break;
        case e_jp: 
            if (!pf)
                ret = true;
                break;
        case e_jcxz_jec:
            int ecx;
            ecx = (int) (regs->rcx & 0xffffffff);
            if (ecx)
                ret = true;
                break;
    /* singed conditional jumps */
        case e_jnle:
        // if (zf && (sf ^ of))
            if (zf || (sf ^ of))
                ret = true;
                break;
        case e_jnl:
            if ((sf ^ of))
                ret = true;
                break;
        case e_jl:
            if (!(sf ^ of))
                ret = true;
                break;
        case e_jle:
        // if (!((sf ^ of) && zf))
            if (!((sf ^ of) || zf))
                ret = true;
                break;
        case e_jno:
            if (of)
                ret = true;
                break;
        case e_jns:
            if (sf)
                ret = true;
                break;
        case e_jo:
            if (!of)
                ret = true;
                break;
        case e_js: 
            if (!sf)
                ret = true;
                break;
        default :
            assert(0);
    }

    return ret;
}

// False indicates a symbolic Register in involved in mem addressing
bool CThinCtrl::bindRegValForMemOpd(DIAPIOperandPtr op)
{
    std::set<RegisterAST::Ptr> regsRead;
    op->getReadSet(regsRead);
    
    for (auto reg : regsRead)
    {
        uint indx = reg->getID();
        uint size = reg->size();
        std:: cout << "reg format: " << reg->format() << ". reg idx: " << indx << ". size: " << size << std::endl;
        RegValue V = {indx, size};
        bool res = m_VM->readRegister(V);
        assert(res);
        std::cout << V.i64 << std::endl;

        if (V.bsym) {
            // Do nothing
            cout << reg->format() << "\n";
            return false;
        } else {
            switch (size) {
                case 8:
                    reg->setValue(Result(s64, V.i64));
                    break;
                case 4:
                    reg->setValue(Result(s64, V.i32));
                    break;
                case 2:
                    reg->setValue(Result(s64, V.i16));
                    break;
                case 1:
                    reg->setValue(Result(s64, V.i8));
                    break;
                default:
                    FIX_ME();
                    break;
            }
        }
    }
    return true;
}

bool CThinCtrl::checkImplicitMemAccess(Instruction *I)
{
    ExprEvalVisitor visitor;
    visitor = ExprEvalVisitor(m_VM);

    std::set<Expression::Ptr> memrd = I->getOperation().getImplicitMemReads();
    if(memrd.size() != 0)
    {
        for (auto it : memrd)
        {
            it->apply(&visitor);
            auto rdaddr = it->eval();
            assert(rdaddr.defined);
#ifdef _DEBUG_OUTPUT
            std::cout << "$$$$$$$$$$$$check implicit read for insn " << I->format() << " at addr " << std::hex << rdaddr.convert<ulong>() << std::endl;
#endif
            
            if (m_VM->isSYMemoryCell(rdaddr.convert<ulong>(), (ulong)it->size()))
                return true;
        }
    }
    
    std::set<Expression::Ptr> memwr = I->getOperation().getImplicitMemWrites();
    if (memwr.size() != 0)
    {
        for (auto it : memwr)
        {
            it->apply(&visitor);
            auto wraddr = it->eval();
            assert(wraddr.defined);

#ifdef _DEBUG_OUTPUT
            std::cout << "@@@@@@@@@@222check implicit write for insn " << I->format() << " at addr " << std::hex << wraddr.convert<ulong>() << std::endl;
#endif

            if (m_VM->isSYMemoryCell(wraddr.convert<ulong>(), (ulong)it->size()))
                return true;
        
            if(I->getOperation().getID() == e_push) {
                
                struct pt_regs* m_regs2 = m_VM->getPTRegs();
                if ((wraddr.convert<ulong>()) != (m_regs2->rsp - 8)) {

                    std::vector<Expression::Ptr> children;
                    it->getChildren(children);

                    for (auto c : children)
                    {
                        RegisterAST* R = dynamic_cast<RegisterAST*>(c.get());
                        Immediate* IMM = dynamic_cast<Immediate*>(c.get());

                        if(R != nullptr)
                        {
                            
                            RegValue RV{(uint)R->getID(), (uint)R->size()};
                            bool res = m_VM->readRegister(RV);
                            assert(res);
                            assert(!RV.bsym);
                        }
                        else if(IMM != nullptr)
                        {
                            Result imm = IMM->eval();
                            assert(imm.defined);
                            long cval = imm.convert<long>();
                        }
                        else
                        {
                            assert(0);
                        }
                    }
                }
            }
        
        }
        struct pt_regs* m_regs2 = m_VM->getPTRegs();
        if(I->getOperation().getID() == e_push)
        {
            if (m_VM->isSYMemoryCell(m_regs2->rsp - 8, 8)) {
                return true;
            }
        }
    }
    return false;
}

bool CThinCtrl::dispatchRet(Instruction* in, struct pt_regs* m_regs)
{
    int idx = x86_64::rsp;
    assert(!m_VM->isSYReg(idx));
    
    Address stack_ptr = m_regs->rsp;
    Address tempTarget;

    MemValue MV{stack_ptr, 0x8};
    bool res = m_VM->readMemory(MV);
    assert(res);
    if(MV.bsym){
        std::cout << "return address is symbolic, sym addr detected" << std::endl;
        MV.expr->print();
        std::cout << std::endl;
#ifdef _SYM_ADDR
        std::cout << "Sym addr concretization enabled, handling symbolic address" << std::endl;
        //get the concrete address
        tempTarget = m_EFlagsMgr->ConcretizeExpression(MV.expr);
        std::cout << "concretized val : " << std::hex << tempTarget << std::endl;
#else
        assert(0);
#endif
    }
    else{
        tempTarget = *((unsigned long*) stack_ptr);
    }

    m_regs->rip = tempTarget;
    m_regs->rsp += 0x8;
    
    return true;
}

extern void check_all_gprs() ;
bool CThinCtrl::dispatchCall(Instruction* in, struct pt_regs* m_regs)
{

    is_indirect_call = false;
    std::vector<Operand> oprands;
    in->getOperands(oprands);
    assert(oprands.size() == 1);//no need to assert?
    auto O = *oprands.begin();
    OprndInfoPtr oi(new OprndInfo(O));

    //check if oi points to O
    if (!O.readsMemory())
    {
        Expression::Ptr target = oi->PO->getValue();
        RegisterAST* rast = new RegisterAST(MachRegister::getPC(Arch_x86_64));
        target->bind(rast, Result(s64, m_regs->rip));
        Result res = target->eval();
        Address tempTarget;
        if (res.defined) //direct call
        {
            tempTarget = res.convert<Address>();
            tempTarget -= in->size();//for direct transfer, dyninst implicitly adds insn->size() when getting oprand
            m_regs->rsp -= 0x8;
            *((unsigned long*) (m_regs->rsp)) = m_regs->rip;//push ret addr
            m_regs->rip = tempTarget;
        }
        else //indirect call through register 
        {
            std::set<RegisterAST::Ptr> regsRead;
            oi->PO->getReadSet(regsRead);
            assert(regsRead.size() == 1);
            auto R = *regsRead.begin();
            oi->reg_index = R->getID();

            RegValue RV{oi->reg_index, (uint)R->size()};
            bool ret = m_VM->readRegister(RV);
            assert(ret);
            if(RV.bsym){
                printf("Indirect call through a symbolic register detected\nExpression: ");
                RV.expr->print();
                printf("\n");
            }
            assert(!RV.bsym);
                
            tempTarget = RV.i64;
            m_regs->rsp -= 0x8;
            *((unsigned long*) (m_regs->rsp)) = m_regs->rip;
            m_regs->rip = tempTarget;
            is_indirect_call = true;
        }
    }
    else
    {
        bool noSymReg = bindRegValForMemOpd(oi->PO);
        assert(noSymReg);
        Expression::Ptr target = oi->PO->getValue();
        std::vector<Expression::Ptr> exps;
        target->getChildren(exps);
        // memory dereference: [xxx] -> xxx
        assert(exps.size() == 1);

        // Get and eval the address
        auto A = *exps.begin();
        auto RS = A->eval();
        assert(RS.defined);
        oi->mem_conaddr = RS.convert<ulong>();
        
        MemValue MV{oi->mem_conaddr, 8};//in x64, a mem access addr must be 8-byte
        bool ret = m_VM->readMemory(MV);
        assert(ret);
        assert(!MV.bsym);
            
        m_regs->rsp -= 0x8;
        *((unsigned long*) (m_regs->rsp)) = m_regs->rip;
        m_regs->rip = MV.i64;
    }
    return true;
}

bool CThinCtrl::updateJCCDecision(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count)
{
    bool bExecute = false;
    entryID temp_operation_id = in->getOperation().getID();
    
    if (!dependFlagCon(in, bExecute))
    {

        if (bPath_explore) //in path exploration
        {
            uint64_t trueB, falseB, BtoTake ;
            getBranchAddress(in, trueB, falseB) ;  //get the 2 possible path addresses
            BtoTake = m_EFlagsMgr->EvalCondition(in->getOperation().getID(), (uint64_t)crtAddr, trueB, falseB) ;
            if(BtoTake == trueB) {
                bExecute = true ; 
            } else if (BtoTake == falseB) {
                bExecute = false ;
            } else {
                // end execute ;
                // set rsp to max, to ensure it is greater than term_rsp.
                m_regs->rsp = -1 ;  //to stop the execution of this path, impossible path
            }
            m_EFlagsMgr->ConcreteFlag(in->getOperation().getID(), bExecute) ;
            std::cout << "Sym branch in path explore: bExecute: " << bExecute << std::endl; 
            return bExecute; 
        }

        /* Evaluate bExecute based on concrete value of symbols */
        bExecute = m_EFlagsMgr->EvalCondition(in->getOperation().getID());       
        std::cout << "Sym branch: bExecute: " << bExecute << std::endl; 
        
        //!-n concretize eflags based on the decision we took
        m_EFlagsMgr->ConcreteFlag(in->getOperation().getID(), bExecute) ;
    }
    else
    {
        bExecute = !chkCondFail(temp_operation_id, m_regs);
    }
    return bExecute;           
}

bool CThinCtrl::dispatchBranch(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count)
{
    std::vector<Operand> oprands;
    in->getOperands(oprands);
    assert(oprands.size() == 1);
    auto O = *oprands.begin();
    OprndInfoPtr oi(new OprndInfo(O));
    if (!O.readsMemory())
    {
        Expression::Ptr target = oi->PO->getValue();
        RegisterAST* rast = new RegisterAST(MachRegister::getPC(Arch_x86_64));
        target->bind(rast, Result(s64, m_regs->rip));
        Result res = target->eval();
        Address tempTarget;
        if (res.defined) //direct jmp
        {
            tempTarget = res.convert<Address>();
            tempTarget -= in->size();//for direct transfer, dyninst implicitly adds insn->size() when getting oprand
            if (in->allowsFallThrough())
            {
                bool bExecute = updateJCCDecision(in, m_regs, crtAddr, cc_insn_count);
                //if not execute, change tempTarget to next instruction
                if (!bExecute)
                {
                    tempTarget = m_regs->rip;
                }
            }
            m_regs->rip = tempTarget;
        }
        else //indirect jmp through register 
        {
            std::set<RegisterAST::Ptr> regsRead;
            oi->PO->getReadSet(regsRead);
            assert(regsRead.size() == 1);
            auto R = *regsRead.begin();
            oi->reg_index = R->getID();

            RegValue RV{oi->reg_index, (uint)R->size()};
            bool ret = m_VM->readRegister(RV);
            assert(ret);
            assert(!RV.bsym);
                
            tempTarget = RV.i64;
            if (in->allowsFallThrough())
            {
                bool bExecute = updateJCCDecision(in, m_regs, crtAddr, cc_insn_count);
                //if not execute, change tempTarget to next instruction
                if (!bExecute)
                {
                    tempTarget = m_regs->rip;
                }
            }
            m_regs->rip = tempTarget;
        }
    }
    else
    {
        bool noSymReg = bindRegValForMemOpd(oi->PO);
        assert(noSymReg);
        Expression::Ptr target = oi->PO->getValue();
        
        std::vector<Expression::Ptr> exps;
        target->getChildren(exps);
        // memory dereference: [xxx] -> xxx
        assert(exps.size() == 1);

        // Get and eval the address
        auto A = *exps.begin();
        auto RS = A->eval();
        assert(RS.defined);
        oi->mem_conaddr = RS.convert<ulong>();
#ifdef _DEBUG_OUTTPUT
        std::cout << "fetch jmp dest from addr " << oi->mem_conaddr << std::endl;
#endif
        MemValue MV{oi->mem_conaddr, 8};//in x64, a mem access addr must be 8-byte
        bool ret = m_VM->readMemory(MV);
        assert(ret);
        assert(MV.bsym);
            
        Address tempTarget = MV.i64;
        if (in->allowsFallThrough())
        {
            bool bExecute = updateJCCDecision(in, m_regs, crtAddr, cc_insn_count);
            //if not execute, change tempTarget to next instruction
            if (!bExecute)
            {
                tempTarget = m_regs->rip;
            }

        }
        m_regs->rip = tempTarget;
    }
    return true;
}

bool CThinCtrl::OpdhasSymReg(opData* OD)
{
    // check if a read reg is symbol 
    for (auto rid : OD->readRegIds)
    {
        if (m_VM->isSYReg(rid))
        {
            //printf ("read reg %lx is sym. \n", R->getID());
            return true;
        }
    }

    // if no, further check if a write reg is symbol 
    for (auto rid : OD->writeRegIds)
    {
        if (m_VM->isSYReg(rid))
        {
            //printf ("write reg %lx is sym. \n", R->getID());
            return true;
        }
    }
    return false; 
}

bool CThinCtrl::OpdhasSymMemCellRep(opData* OD, Operand* OP, ulong gs_base)
{
    ulong mem_addr;

    //for REP prefix  
    //we do this check in processFunction(), hence commenting
    
    RegValue r_rcx {(uint)x86_64::rcx, 8} ;
    m_VM->readRegister (r_rcx) ;
    unsigned long loop_cnt = r_rcx.u64 ;
    if(r_rcx.bsym) {
        // do something but assert;
        assert(0);
    }
    
    /* check if any read mem is symbol */
    ExprEvalVisitor visitor;
    visitor = ExprEvalVisitor(m_VM);

    if (OD->rdmem)
    {   
        std::set<Expression::Ptr> memrd;
        OP->addEffectiveReadAddresses(memrd);
        assert(memrd.size() == 1);
        auto it = *memrd.begin();
            
        it->apply(&visitor);
        auto rdaddr = it->eval();

        if(visitor.symreg){
            printf("cpu clock : %llu \n", rdtsc());
            assert(0);
        }
        assert(rdaddr.defined); //sometime this does not assert even if the operand is symbolic, open issue to investigate 

        if (gs_base == 0)
            mem_addr = rdaddr.convert<ulong>();
        else
            mem_addr = rdaddr.convert<ulong>() + gs_base;
#ifdef _DEBUG_OUTPUT    
        std::cout << "it format " << it->format() << std::endl;
        std::cout << "read addr: " << hex << mem_addr << std::endl;
#endif
        // for REP prefix  
        while (loop_cnt != 0) {
        // for REP prefix  
            if (m_VM->isSYMemoryCell(mem_addr, (ulong)OP->getValue()->size()))
            {
#ifdef _SYM_DEBUG_OUTPUT
            std::cout << "read symbolic memory. it format " << it->format() << std::endl;
            std::cout << "read addr: " << hex << mem_addr << std::endl;
#endif
                return true;
            }
        //for REP prefix  
            mem_addr += (ulong)OP->getValue()->size() ;
            loop_cnt -- ;
        }
        //for REP prefix  
    }

    /* if no, further check if a write mem is symbol */
    if (OD->wrmem)
    {
        std::set<Expression::Ptr> memwr;
        OP->addEffectiveWriteAddresses(memwr);
        assert(memwr.size() == 1);
        auto it = *memwr.begin();
            
        it->apply(&visitor);
        auto wraddr = it->eval();

#ifdef _SYM_BUF_LOCATION_TEST
        if(!wraddr.defined && visitor.symreg){ //the write memory address(stored in the register) is symbolic
            std::cout << "SYM_BUF_LOCATION, expect to be sent to CIE as the buffer is allocated in memory...\n";
        }
        else //if the register storing the write mem address is not symbolic, follow the original behavior 
            assert(wraddr.defined);
#else
        if(!wraddr.defined){
            printf("cpu clock : %llu \n", rdtsc());
        }
        assert(wraddr.defined);
#endif

        if (gs_base == 0)
            mem_addr = wraddr.convert<ulong>();
        else
            mem_addr = wraddr.convert<ulong>() + gs_base;

        //for REP prefix  
        while (loop_cnt != 0) {
        //for REP prefix  
            if (m_VM->isSYMemoryCell(mem_addr, (ulong)OP->getValue()->size()))
            {
                return true;
            }
            mem_addr += (ulong)OP->getValue()->size();
            loop_cnt -- ;
        }
        //for REP prefix  
    }   
    return false;
}

bool CThinCtrl::OpdhasSymMemCell(opData* OD, Operand* OP, ulong gs_base)
{
    ulong mem_addr;

    /* check if any read mem is symbol */
    ExprEvalVisitor visitor;
    visitor = ExprEvalVisitor(m_VM);
  
    if (OD->rdmem)
    {   
        std::set<Expression::Ptr> memrd;
        OP->addEffectiveReadAddresses(memrd);
        assert(memrd.size() == 1);
        auto it = *memrd.begin();
            
        it->apply(&visitor);
        auto rdaddr = it->eval();

        if(visitor.symreg){
#ifdef _SYM_ADDR
            return true;
#endif
            printf("cpu clock : %llu \n", rdtsc());
            printf("mem read with a symbolic address detected");
            assert(0);
        }
        assert(rdaddr.defined); //sometime this does not assert even if the operand is symbolic, open issue to investigate 

        if (gs_base == 0)
            mem_addr = rdaddr.convert<ulong>();
        else
            mem_addr = rdaddr.convert<ulong>() + gs_base;

#ifdef _DEBUG_OUTPUT    
        std::cout << "it format " << it->format() << std::endl;
        std::cout << "read addr: " << hex << mem_addr << std::endl;
#endif

        if (m_VM->isSYMemoryCell(mem_addr, OP->getValue()->size()))
        {
#ifdef _SYM_DEBUG_OUTPUT
            std::cout << "read symbolic memory. it format " << it->format() << std::endl;
            std::cout << "read addr: " << hex << mem_addr << std::endl;
#endif

            return true;
        }
    }

    /* if no, further check if a write mem is symbol */
    if (OD->wrmem)
    {
        std::set<Expression::Ptr> memwr;
        OP->addEffectiveWriteAddresses(memwr);
        assert(memwr.size() == 1);
        auto it = *memwr.begin();
            
        it->apply(&visitor);
        auto wraddr = it->eval();

        if(visitor.symreg){
#ifdef _SYM_ADDR
            return true;
#endif
            printf("cpu clock : %llu \n", rdtsc());
            printf("mem read with a symbolic address detected");
            assert(0);
        }

#ifdef _SYM_BUF_LOCATION_TEST
        if(!wraddr.defined && visitor.symreg){ //the write memory address(stored in the register) is symbolic
            std::cout << "SYM_BUF_LOCATION, expect to be sent to CIE as the buffer is allocated in memory...\n";
        }
        else //if the register storing the write mem address is not symbolic, follow the original behavior 
            assert(wraddr.defined);
#else
        if(!wraddr.defined){
            printf("cpu clock : %llu \n", rdtsc());
        }
        assert(wraddr.defined);
#endif

        if (gs_base == 0)
            mem_addr = wraddr.convert<ulong>();
        else
            mem_addr = wraddr.convert<ulong>() + gs_base;

#ifdef _DEBUG_OUTPUT
        std::cout << "it format " << it->format() << std::endl;
        std::cout << "write addr: " << hex << mem_addr << std::endl;
#endif
        if (m_VM->isSYMemoryCell(mem_addr, OP->getValue()->size()))
        {
#ifdef _SYM_DEBUG_OUTPUT
            std::cout << "write symbolic memory. it format " << it->format() << std::endl;
            std::cout << "write addr: " << hex << mem_addr << std::endl;
#endif      
            return true;
        }
    }   
    return false;
}

ulong CThinCtrl::isUseGS(Instruction* in)
{
    /* check if Insn uses gs as base in mem access, if yes, get gsbase first */
    std::set<RegisterAST::Ptr> regrd = in->getOperation().implicitReads();
    if (regrd.size() != 0)
    {
        for (auto it : regrd)
        {
            if (it->getID() == x86_64::gs)
            {
                RegValue RV{(uint)it->getID(), 8};
                bool ret = m_VM->readRegister(RV);
                assert(ret);
                return RV.u64;
            }
        }
    }
    return 0;
}

//for %ds %es
ulong CThinCtrl::getSegRegVal(Instruction* in)
{
    int r_id;
    /* check if Insn uses gs as base in mem access, if yes, get gsbase first */
    std::set<RegisterAST::Ptr> regrd = in->getOperation().implicitReads();
    if (regrd.size() != 0)
    {
        for (auto it : regrd)
        {
            r_id = it->getID();
            if (r_id == x86_64::gs || r_id == x86_64::ds || r_id == x86_64::es)
            {
                RegValue RV{(uint)it->getID(), 8};
                bool ret = m_VM->readRegister(RV);
                assert(ret);
                return RV.u64;
            }
        }
    }
    return 0;
}

bool CThinCtrl::hasSymOperand(wrapInstruction* win)
{
    Instruction* in = win->in;
    std::vector<Operand> oprands = win->ioperands;
    std::vector<opData*> od_ptrs = win->opdata_ptrs;
    int i = 0;
#ifndef _PROD_PERF
    st1_0 = rdtsc();
#endif
#ifndef _PROD_PERF
    st1 += (rdtsc() - st1_0);
#endif
    bool ret = false;
    int tmp_idx = 0;
    for (auto O : oprands) {
#ifndef _PROD_PERF
        st2_0 = rdtsc();
#endif

        bool rm = od_ptrs[i]->rdmem;
        bool wm = od_ptrs[i]->wrmem;  
#ifndef _PROD_PERF
        st2 += (rdtsc() - st2_0);
#endif
        if(!rm && !wm)
        {
#ifndef _PROD_PERF
            tr_0 = rdtsc();
#endif
           
            ret = OpdhasSymReg(od_ptrs[i]);
#ifndef _PROD_PERF
            tr += (rdtsc() - tr_0);
#endif
            if (ret){
                std::cout << "sym reg ...\n";
                return true; 
            }
        }
        else
        {
#ifndef _PROD_PERF
            st3_0 = rdtsc();
#endif
            
            ulong gs_base = win->igs_base;
#ifndef _PROD_PERF
            st3 += (rdtsc() - st3_0);
            tm_0 = rdtsc(); 
#endif
            
            if(win->isRepIns)
            {
                ret = OpdhasSymMemCellRep(od_ptrs[i], &O, gs_base);
            }
            else
            {
                ret = OpdhasSymMemCell(od_ptrs[i], &O, gs_base);
            }

#ifndef _PROD_PERF
            tmm += (rdtsc() - tm_0);
#endif
            if (ret){
                std::cout << "sym mem ...\n";
                return true; 
            }
        }
        i++;
    }
#ifndef _PROD_PERF
    ti_0 = rdtsc();
#endif
    ret = checkImplicitMemAccess(in);
    if(ret)
        std::cout << "sym implicit mem " << std::endl;
#ifndef _PROD_PERF
    ti += (rdtsc() - ti_0);
#endif
    
    return ret;  
}

#ifdef _PreDisassemble
bool CThinCtrl::PreParseOperand(Instruction* in)
{
    std::vector<Operand> oprands;
    in->getOperands(oprands);
    bool ret = false;
    for (auto OP : oprands) {
        if (!OP.readsMemory() && !OP.writesMemory())
        {
            /* get read regs */
            std::set<RegisterAST::Ptr> readRegs;
            OP.getReadSet(readRegs);

            /* get write regs */
            std::set<RegisterAST::Ptr> writeRegs;
            OP.getWriteSet(writeRegs);
        }
        else
        {
            /* get addr expr for memory read */
            if (OP.readsMemory())
            {
                std::set<Expression::Ptr> memrd;
                OP.addEffectiveReadAddresses(memrd);
                assert(memrd.size() == 1);
            }

            /* get addr expr for memory write */
            if (OP.writesMemory())
            {
                std::set<Expression::Ptr> memwr;
                OP.addEffectiveWriteAddresses(memwr);
                assert(memwr.size() == 1);
            }             
        }
    }
    /* get addr expr for implicit mem read */
    std::set<Expression::Ptr> memrd = in->getOperation().getImplicitMemReads();
   
    /* get addr expr for implicit mem write */
    std::set<Expression::Ptr> memwr = in->getOperation().getImplicitMemWrites();
    
    return true;
}

bool CThinCtrl::ReadNextIPFromFile()
{
    ifstream theFile;
    string fname = "/home/neo/smu/KRover/KRover/stc-files/nextIPofTransInsn.txt";
    string line;
    ulong endRIP;
    ulong crtRIP, nextRIP;
    uint64_t key;
    uint64_t counter = 0;
    ulong val;
    theFile.open(fname);
    if (!theFile) {
        std::cout << "error open next RIP file " << std::endl;
        return false;
    }
    std::getline(theFile, line);
    sscanf(line.c_str(), "%lx", &endRIP);
    m_endRIP = endRIP;
#ifdef DEBUG_LOG
    std::cout << "end rip " << m_endRIP << std::endl;
#endif
    //ulong r = 0;
    while (std::getline(theFile, line)) {
        counter ++;
        sscanf(line.c_str(), "%lx, %lx.", &crtRIP, &nextRIP);
        key = crtRIP & 0xFFFFFFFF;
        key = key | (counter << 48);
        val = nextRIP & 0xFFFFFFFFFFFFFFFF;
        m_NextIP[key] = val;
    }
#ifdef DEBUG_LOG
    std::cout << "next RIP map created " << std::endl;
#endif
    theFile.close();
    return true;
}
#endif

extern void print_pf_fixed() ;
bool bEndCurrentRun = false ;
bool CThinCtrl::processFunction(unsigned long addr) {
    

    Instruction I;
    Instruction* in;
    wrapInstruction* win;
    struct pt_regs* m_regs = m_VM->getPTRegs();
    Address crtAddr;

#ifndef _PROD_PERF
    std::cout << "######### at start of processFuncyion, rip " << std::hex << m_regs->rip << std::endl;
#endif

    execData = m_Analyze->execData; /*shares execution configs and runtime data bwn the analyzer*/
    execProfile = m_Analyze->execProfile;
    bool terminateNow = false;

    //To the the termination condition: rsp is higher or equal to init rsp
    ulong term_rsp = m_regs->rsp;

    //To find the decision for symbolic conditional instruction
    long long unsigned int cc_insn_count = 0;
    bool bExecute = false;

    //for perf
    unsigned long long ts, t0, t1, t;
    ts = t0 = t1 = t = 0;
    unsigned long dis_as0, pre_dis_as0;
    unsigned long dis_as1, pre_dis_as1; 
    unsigned long dis_as, pre_dis_as;
    dis_as0 = dis_as1 = dis_as = 0;
    pre_dis_as0 = pre_dis_as1 = pre_dis_as = 0;
    unsigned long call_t0, call_t1, call_t;
    call_t0 = call_t1 = call_t = 0;
    unsigned long branch_t0, branch_t1, branch_t;
    branch_t0 = branch_t1 = branch_t = 0;
    unsigned long nop_t0, nop_t1, nop_t;
    nop_t0 = nop_t1 = nop_t = 0;
    unsigned long cie_t0, cie_t1, cie_t;
    cie_t0 = cie_t1 = cie_t = 0;
    unsigned long sie_t0, sie_t1, sie_t;
    sie_t0 = sie_t1 = sie_t = 0;
    unsigned long ret_t0, ret_t;
    ret_t0 = ret_t = 0;

    unsigned long trans_rip;
    bool is_prev_ctrl_trans = false;
    unsigned long shouldsym_t0, shouldsym_t;
    shouldsym_t0 = shouldsym_t = 0;

    uint64_t prev_insn_count;
    uint64_t insn_count_t = 0;
    uint64_t ins_cache_hit_count = 0;
    ulong tipc_data_start = addr;
    bool return_to_native = false;

    int uni_insn = 0;
    tt = tt0 = tt1 = 0;
    ttt = ttt0 = ttt1 = 0;


ts = rdtsc();
thin_ctrl_invokation_count++;
#ifdef _PreDisassemble

if(thin_ctrl_invokation_count == 1){
    #ifdef DEBUG_LOG       
        printf("\nin pre-disassemble stage..................\n");
    #endif
        //printf("\nin pre-disassemble stage..................\n");
        //pre_dis_as0 = rdtsc();

        /* pre disassembling and parsing Operand */
        if (ReadNextIPFromFile() == false)
            return false;
        pre_dis_as0 = rdtsc();

        //printf("1\n");
        crtAddr = m_regs->rip;
        int count = 0;
        int new_ins_count = 0;
        uint64_t cf_counter = 0;
        while (true) {
            //printf("\n ################### round : %d   crtAdr : %lx ", count+1, crtAddr);
            int idx = crtAddr & 0xFFFFFFF;
            if (m_InsnCache[idx] == nullptr)
            {
                //printf("new decode \n");
                I = decoder->decode((unsigned char *)m_cr->getPtrToInstruction(crtAddr));
                in = new Instruction(I);

                win = new wrapInstruction(in);
                win->cie_mode = m_ConExecutor->preCIE(in);
                win->igs_base = isUseGS(in);
                
                //REP prefix
                win->isRepIns = !(in->getOperation().getPrefixID() == prefix_none);
                m_InsnCache[idx] = win;

                new_ins_count++;
            }
            else
            {        
                win = m_InsnCache[idx];
                in = win->in;
            }

            if (crtAddr == m_endRIP)
            {
                break;
            }
            
            count ++;

            InsnCategory cate = in->getCategory();
            uint64_t key;
            if (cate == c_ReturnInsn || cate == c_CallInsn || cate == c_BranchInsn)
            {
                cf_counter ++;
                key = crtAddr & 0xFFFFFFFF;
                key = key | (cf_counter << 48);
                crtAddr = m_NextIP[key];
            }
            else
            {
                crtAddr += in->size();
            }
        }
        pre_dis_as1 = rdtsc();
}
#endif

    //To process insn one by one
    t0 = rdtsc();
    while (true) {

        if(execProfile->executionMode == EXEC_MD_SINGLE_PATH_SEDED && endCurrentPath){
            std::cout << "Current path has been flagged for termnation, ending now ..." << std::endl;
        }
        endCurrentPath = false; /*reset to false as a new round is being started*/

        if (execProfile->executionMode == EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT && execData->insn_count == execProfile->startIncCount) {
            printf("\nstarting a new path\n");
            startPathExplore();
        }
        crtAddr = m_regs->rip;

#ifdef _DEBUG_LOG_L0       
        printf("\n-------------------instruction %lu adr : %lx\n", execData->insn_count, crtAddr);
#endif
        /* get the Insn from the InsnCache or decoding on the site */
#ifndef _PROD_PERF
        dis_as0 = rdtsc();
#endif
        int idx = crtAddr & 0xFFFFFFF; 

        //temporiliy disable checking against cache by commenting this if block
        if (m_InsnCache[idx] != nullptr)
        {
            win = m_InsnCache[idx];
            in = win->in;
#ifndef _PROD_PERF
            ins_cache_hit_count++;
#endif
        }
        else
        {
            uni_insn ++;
            I = decoder->decode((unsigned char *)m_cr->getPtrToInstruction(crtAddr));
            in = new Instruction(I);
            win = new wrapInstruction(in);
            win->cie_mode = m_ConExecutor->preCIE(in);
            win->igs_base = isUseGS(in);
            win->cate = in->getCategory();
            win->isRepIns = !(in->getOperation().getPrefixID() == prefix_none);
            m_InsnCache[idx] = win;
        }
#ifndef _PROD_PERF
        dis_as1 = rdtsc();
        dis_as += (dis_as1-dis_as0);  
#endif

#ifdef _DEBUG_LOG_L0
        std::cout << "idx :" << std::hex << idx << " ,in :" << in->format() << std::endl;
#endif

#if CFG_ANA_ON_END_OF_INS_DECODE == 1
        m_Analyze->analyztsHub(ON_END_OF_INS_DECODE);
#endif

#if 0   //to generate nextPofTransInsn.txt
        InsnCategory cate_t = in->getCategory();
        if(is_prev_ctrl_trans)
        {
            std::cout << hex << trans_rip << ", " << crtAddr << ".\n";
            is_prev_ctrl_trans = false;
        }
        if (cate_t == c_ReturnInsn || cate_t == c_CallInsn || cate_t == c_BranchInsn)
        {
            trans_rip = crtAddr;
            is_prev_ctrl_trans = true;
            //std::cout << "trans ins "<< pi << std::endl;
            //pi++;
        }
#endif

        execData->insn_count++;
        execData->win = win;
        std::cout << "insn_count: " << std::dec <<  execData->insn_count << std::endl;
        //dumpMregs(m_regs);

        if (in->getOperation().getID() == e_ud2) { //detect invalid/errorneous kernel paths and terminate(eg:something like kernel assert(), panic)
            #ifdef _DEBUG_LOG_L0
            std::cout << "UD2 instruction detected" << std::endl;
            #endif
            execErrorHandle(ERR_UD2_INS_DETECTED);
            continue ;
        }

        if (in->getOperation().getID() == e_nop)
        {
#ifndef _PROD_PERF
            nop_t0 = rdtsc();
#endif
            m_regs->rip += in->size();
#ifndef _PROD_PERF
            nop_t1 = rdtsc();
            nop_t += (nop_t1 - nop_t0);
            nop_count++;
#endif

#if CFG_ANA_ON_END_OF_INS_EXEC == 1
        if(m_Analyze->analyztsHub(ON_END_OF_INS_EXEC) == -1){
            std::cout << "Ending SE, returning to Analyzer ..." << std::endl;
            break;
        }
#endif
            continue;
        }

        InsnCategory cate = in->getCategory();
        m_regs->rip += in->size();

        //chk REP prefix
        if(win->isRepIns) {
            RegValue v_RCX = {(uint)x86_64::rcx, 8} ;
            m_VM->readRegister(v_RCX) ;

            if (v_RCX.bsym) {
                #ifdef _DEBUG_LOG_L0
                std::cout << "REP instruction with symbolic rcx detected" << std::endl;
                #endif
                execErrorHandle(ERR_REP_INS_WITH_SYM_RCX); /*this functions sets endCurrentPath flag*/
                if(endCurrentPath){
                    continue;
                }
                /*else,
                this means the analyzer has instructed to continue execution,
                ana has handled the symbolic value by concretizing
                */

            }
        }

        switch (cate) {
            case c_ReturnInsn: 
                {   
#ifndef _PROD_PERF
                    ret_t0 = rdtsc();
#endif
                    //dyninst does not differentiate rep with repz
                    //but we only found repz ret instructions in kernel
                    if(in->getOperation().getPrefixID() == prefix_rep) 
                    {
                        FLAG_STAT zf_bit;
                        m_VM->getFlagBit(x86_64::zf, zf_bit);
                        //only execute if zf=0, else skip
                        if(zf_bit == FLAG_CLEAR)
                        {
#ifndef _PROD_PERF                        
                            std::cout << "zf != 0, skipping the repz ret instruction\n";
#endif
                            break;
                        }
                        if(zf_bit == FLAG_UNCERTAIN)
                        {
#ifndef _PROD_PERF                        
                            std::cout << "zf is undefined...\n";
#endif
                            assert(0);
                        }
                    }

                    dispatchRet(in, m_regs);
#ifndef _PROD_PERF
                    ret_t += (rdtsc() - ret_t0);
                    ret_count++;
#endif
                    break;
                }
            case c_CallInsn:
                {
                    caller_adr_aft_ret = m_regs->rip; //the function call returns here
#ifndef _PROD_PERF
                    call_count++;
                    call_t0 = rdtsc();
#endif
                    dispatchCall(in, m_regs);
#ifndef _PROD_PERF
                    call_t1 = rdtsc();
                    call_t += (call_t1 - call_t0);
#endif
                    break;

                }
            case c_BranchInsn:
                {
#ifndef _PROD_PERF
                    branch_count++;
                    branch_t0 = rdtsc();
#endif
                    dispatchBranch(in, m_regs, crtAddr, cc_insn_count);
#ifndef _PROD_PERF
                    branch_t1 = rdtsc();
                    branch_t += (branch_t1 - branch_t0);
#endif
                    break;
                }
            default:
                {
                    if (!dependFlagCon(in, bExecute)) //instructions involving dependant flag eg : cmov, sbb, adc
                    {                                  
#ifndef _PROD_PERF
                        symFlag_count ++;
#endif
                        /* Evaluate bExecute based on concrete value of symbols */
#ifndef _PROD_PERF
                        tt0 = rdtsc();
#endif
                        bExecute = m_EFlagsMgr->EvalCondition(in->getOperation().getID());
#ifndef _PROD_PERF
                        tt1 = rdtsc();
                        tt += (tt1-tt0);
                        z3_api_clk_cycls[z3_api_calls] = tt1 - tt0;
                        z3_api_calls++;
#endif
#ifdef _DEBUG_OUTPUT
                        std::cout << "bExecute: " << bExecute << std::endl; 
#endif
                        //concretize the flags based on the decision taken i.e. 'bExecute'
                        //this concretization should take place before 'sbb' is dispatched for SIE
                        m_EFlagsMgr->ConcreteFlag(in->getOperation().getID(), bExecute) ;
                        
                        //not all instructions involving a dependent flag are similar to cmov
                        //eg: sbb ; the instruction uses CF during its operation
                        entryID c_ins = in->getOperation().getID();
                        if(c_ins == e_sbb || c_ins == e_adc)  
                        {
#ifndef _PROD_PERF
                            shouldsym_t0 = rdtsc();
#endif
                            bool shouldSymExe = false;    
                            shouldSymExe = hasSymOperand(win);
#ifndef _PROD_PERF
                            shouldsym_t += (rdtsc() - shouldsym_t0);
#endif
                            if (shouldSymExe)
                            {
                                stageForCIESIE(win, m_regs, false); //SIE
                            }
                            else
                            {
#ifndef _PROD_PERF
                                cie_count++; 
                                cie_t0 = rdtsc();     
#endif                  
                                stageForCIESIE(win, m_regs, true);                                
                                if (m_EFlagsMgr->isFlagChangingInstr(in->getOperation().getID()))
                                {
                                    m_VM->clearAllSymFlag();
                                }
#ifndef _PROD_PERF
                                cie_t1 = rdtsc();
                                cie_t += (cie_t1 - cie_t0);
#endif
                            }
                            break;
                        }

                        if (bExecute == false){
#ifndef _PROD_PERF
                            symExe_count ++;
                            //sym flg conditionally executed ins, cond is false, skipping & counting under symExe_count
#endif                            
                            continue;
                        }
                        else
                        {
                            //To symexecutor due to depend on sym flag
                            stageForCIESIE(win, m_regs, false);
                        }
                    }
                    else
                    {
#ifndef _PROD_PERF
                        shouldsym_t0 = rdtsc();
#endif
                        bool shouldSymExe = false;    
                        shouldSymExe = hasSymOperand(win);
                        if(shouldSymExe && (win->bInsID == e_xor) && (win->xoredOperand[0] > 0)){
                            //if ins is xor and XORs the same reg
                                uint reg_indx = win->xoredOperand[0] ;
                                int rsize = win->xoredOperand[1];
                                RegValue rv ;
                                if(win->xoredOperand[1] == 4){                      //if register is size 4
                                    rv.indx = win->xoredOperand[0] & (0xFFFFF0FF);  //now we update the corresponding 8 byte reg
                                    rv.size = 0x8;
                                }
                                else{
                                    rv.indx = win->xoredOperand[0];                 //no change to other rg sizes
                                    rv.size = win->xoredOperand[1];
                                }
                                bool res = m_VM->readRegister(rv);
                                assert(res);

                                rv.bsym = false ;                                   //now mark the register as nonsym
                                if (win->xoredOperand[1] == 4)  {                   //if reg size is 4, set the correspnding 8 byte reg val to 0
                                    rv.u64 = 0 ;
                                }
                                m_VM->writeRegister (rv) ;                          //write to reg
                                //next we dispatch to CIE to set the flags automatically
    #ifndef _PROD_PERF
                                //SYM flag removed, dispatch for CIE
                                cie_count++; 
                                cie_t0 = rdtsc();     
    #endif                  
                                stageForCIESIE(win, m_regs, true);
                                //clear sym flags as well
                                if (m_EFlagsMgr->isFlagChangingInstr(e_xor))
                                {
                                    m_VM->clearAllSymFlag();
                                }
    #ifndef _PROD_PERF
                                cie_t1 = rdtsc();
                                cie_t += (cie_t1 - cie_t0);
    #endif                            
                                
                            
    #ifndef _PROD_PERF
                            shouldsym_t += (rdtsc() - shouldsym_t0);
    #endif
                        }
                        else if (shouldSymExe)
                        {
                            stageForCIESIE(win, m_regs, false);
                        } else {
                            /* Instruction CIE */  
#ifndef _PROD_PERF
                            cie_count++; 
                            cie_t0 = rdtsc();     
#endif                  
                            stageForCIESIE(win, m_regs, true);

                            if (m_EFlagsMgr->isFlagChangingInstr(in->getOperation().getID()))
                            {
                                m_VM->clearAllSymFlag();
                            }
#ifndef _PROD_PERF
                            cie_t1 = rdtsc();
                            cie_t += (cie_t1 - cie_t0);
#endif
                        }
                    }
                    break;
                }
        } /*end of switch*/
 
#if CFG_ANA_ON_END_OF_BB_EXEC == 1
        if (cate == c_ReturnInsn || cate == c_CallInsn || cate == c_BranchInsn)
        {
            if(m_Analyze->analyztsHub(ON_AFT_BB_END_EXEC) == -1){
#ifdef _DEBUG_LOG_L0
                std::cout << "Ending execution ..." << std::endl;
#endif
                break;
            }
        }
#endif

#if CFG_ANA_ON_END_OF_INS_EXEC == 1
        if(m_Analyze->analyztsHub(ON_END_OF_INS_EXEC) == -1){
#ifdef _DEBUG_LOG_L0
                std::cout << "Ending execution ..." << std::endl;
#endif
            break;
        }
#endif
       if(execProfile->executionMode == EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT){
            endCurrentPath = false;
            if(execData->insn_count >= execProfile->terminate_ins_count){
                endCurrentPath = true;
#ifdef _DEBUG_LOG_L0
                std::cout << "Current path to be ended ..." << std::endl;
#endif
                g_hm->endCurrrentExecution(m_EFlagsMgr->getConstraint()) ;
                execData->insn_count = execProfile->startIncCount ;
            }
       }
       else if(execProfile->executionMode == EXEC_MD_SINGLE_PATH_SEDED){
            
            if(execProfile->terminationMode != END_AT_ANA_REQUEST){
                if(evalSinglePathTermination(m_regs, cate)){
        #ifdef _DEBUG_LOG_L0
                    std::cout << "Ending execution ..." << std::endl;
        #endif
                    return true;
                }
            }
       }

    }
    return true;
}

bool CThinCtrl::evalSinglePathTermination(struct pt_regs * m_regs, InsnCategory cate){
    bool terminateNow = false;

    switch(execProfile->terminationMode){
        case END_AT_FUN_RET:
        {
            if(m_regs->rsp > execData->start_rsp && cate == c_ReturnInsn){
#if CFG_ANA_ON_TERMINATION_COND == 1
                m_Analyze->analyztsHub(ON_TERM_COND_FUN_RET);
#endif
                terminateNow = true;
#ifdef _DEBUG_LOG_L0
                std::cout << "End condition, ON_TERM_COND_FUN_RET met" << std::endl;
#endif
            }
        }   break;
        case END_AT_GIVEN_RIP:
        {
            if(m_regs->rip == execProfile->terminate_rip){
#if CFG_ANA_ON_TERMINATION_COND == 1
                m_Analyze->analyztsHub(ON_TERM_COND_GIVEN_RIP);
#endif
                terminateNow = true;
#ifdef _DEBUG_LOG_L0
                std::cout << "End condition, END_AT_GIVEN_RIP met" << std::endl;
#endif
            }
        }   break;
        case END_AT_GIVEN_INS_COUNT:
        {
            if(execData->insn_count == execProfile->terminate_ins_count){
#if CFG_ANA_ON_TERMINATION_COND == 1
                m_Analyze->analyztsHub(ON_TERM_COND_INS_COUNT);
#endif
                terminateNow = true;   
#ifdef _DEBUG_LOG_L0
                std::cout << "End condition, END_AT_GIVEN_INS_COUNT met" << std::endl;       
#endif                             
            }
        }   break;
        default:
            break;
    }
    return terminateNow;
}

bool CThinCtrl::stageForCIESIE(wrapInstruction *win, pt_regs *m_regs, bool do_cie){

#ifdef _PARSE_CIE_SIE_OPERANDS
    int action = NO_NEW_ACTION;

    getMemoryAccesses(win->in);
#if CFG_ANA_ON_BFR_CIE_OR_SIE == 1
    action = m_Analyze->analyztsHub(ON_BFR_CIE_OR_SIE);
    std::cout << "Analyzer requested: " << action << std::endl;
#endif

    //set is_cie as per analyzer
    if(action == DO_CIE)
        do_cie = true;
    else if(action == DO_SIE)
        do_cie = false;
#endif

    if(do_cie){
        dispatchCIE(win->in, m_regs, win->cie_mode);
    }
    else{
        dispatchSIE(win->in);
    }

    return true;
}




bool CThinCtrl::dispatchCIE(Instruction *in, struct pt_regs* m_regs, uint mode){
#ifdef _DEBUG_LOG_L0
    std::cout << "dispatching for CIE" << std::endl;
#endif
    m_ConExecutor->InsnDispatch(in, m_regs, mode);
}

bool CThinCtrl::dispatchSIE(Instruction *in){
#ifdef _DEBUG_LOG_L0
        std::cout << "dispatching for SIE" << std::endl ;
#endif
    InstrInfo *ioi = new InstrInfo(new Instruction (*in));
    entryID i_id =  in->getOperation().getID();

    symExe_count ++;
    if(i_id != e_mov && i_id != e_pop && i_id != e_push){
        parseOperands(ioi);
    }

    InstrInfoPtr ptr(ioi);
    m_SymExecutor->pushInstr(ptr);

    if (false == m_SymExecutor->run(m_VM)) {              
        execErrorHandle(ERR_SYM_EXE_FAILED_FOR_CUR_INS);
        return false;
    }
    return true;
}

void CThinCtrl::getMemoryAccesses(Instruction *in){

    InstrInfo *ioi2 = new InstrInfo(new Instruction (*in));
    parsing_operands_for_mem_adr = true; //this is to indicate that the parsing is just to obtain the memory address
    parseOperands(ioi2);

    entryID i_id =  in->getOperation().getID();
    if(i_id == e_push){
        pt_regs *m_regs = m_VM->getPTRegs();
        execData->opDetails[1].opmemac.memrdwr = true;
        execData->opDetails[1].opmemac.rdmem = false;
        execData->opDetails[1].opmemac.memAddress = m_regs->rsp - 0x8;
        execData->opDetails[1].opmemac.wrmem = true;
        std::cout << "op mem_conaddr: " << std::hex << execData->opDetails[1].opmemac.memAddress << std::endl;
    }
    else if(i_id == e_pop){
        pt_regs *m_regs = m_VM->getPTRegs();
        execData->opDetails[1].opmemac.memrdwr = true;
        execData->opDetails[1].opmemac.rdmem = true;
        execData->opDetails[1].opmemac.memAddress = m_regs->rsp + 0x8;
        execData->opDetails[1].opmemac.wrmem = false;
        std::cout << "op mem_conaddr: " << std::hex << execData->opDetails[1].opmemac.memAddress << std::endl;
    }
    parsing_operands_for_mem_adr = false;

}

bool CThinCtrl::execErrorHandle(int ex_err){
#ifdef _DEBUG_LOG_L0
                std::cout << "at ThinCtrl execErrorHandle" << std::endl;
#endif
        endCurrentPath = false;

    switch(ex_err){
        case ERR_UD2_INS_DETECTED:
        case ERR_SYM_EXE_FAILED_FOR_CUR_INS:
        {
            endCurrentPath = true;
        }   break;
        case ERR_REP_INS_WITH_SYM_RCX:
        {
            endCurrentPath = true;
            if(CFG_ANA_ON_RECOVERABLE_ERR == 1){
                if(m_Analyze->analyztsHub(ON_AFT_BB_END_EXEC) != -1)
                    endCurrentPath = false;
            } 
        }
        default:
        {
            std::cout << "Unhandled err code ..." << std::endl;
        }   break;
    }

    if(endCurrentPath){
#ifdef _DEBUG_LOG_L0
        std::cout << "Current path to be ended ..." << std::endl;
#endif
        if(execProfile->executionMode != EXEC_MD_SINGLE_PATH_SEDED){
            g_hm->endCurrrentExecution(m_EFlagsMgr->getConstraint()) ;
            execData->insn_count = execProfile->startIncCount ;
        }
    }
    return true;
}



#if 1   //analyzer-exp-detection
bool CThinCtrl::analyzeExecution(pt_regs *m_regs, unsigned long term_rsp){
        
        unsigned long concrete_reg_val;

        if (bEndCurrentRun ) {
            g_hm->endCurrrentExecution(m_EFlagsMgr->getConstraint()) ;
            insn_count = execProfile->startIncCount ;
            hmtround++;
            bEndCurrentRun = false ;
            
            return true;
        }
        if (insn_count >= END_COUNT) {    
            printf ("%s:\t %d, instruction count 30.\n", __FILE__, __LINE__) ;

            g_hm->endCurrrentExecution(m_EFlagsMgr->getConstraint()) ;
            
            insn_count = execProfile->startIncCount ;
            
            hmtround++;
            return true;
        }

        return true;
}
#endif

void CThinCtrl::dumpMregs(pt_regs *m_regs){
    printf ("rax: %lx\n", m_regs->rax);
    printf ("rbx: %lx ", m_regs->rbx);
    printf ("rcx: %lx ", m_regs->rcx);
    printf ("rdx: %lx ", m_regs->rdx);
    printf ("rdi: %lx ", m_regs->rdi);
    printf ("rsi: %lx ", m_regs->rsi);
    printf ("r8: %lx ", m_regs->r8);
    printf ("r9: %lx ", m_regs->r9);
    printf ("r10: %lx \n", m_regs->r10);
    printf ("r11: %lx \n", m_regs->r11);
    printf ("r12: %lx \n", m_regs->r12);
    printf ("r13: %lx \n", m_regs->r13);
    printf ("r14: %lx \n", m_regs->r14);
    printf ("r15: %lx \n", m_regs->r15);
    printf ("rip: %lx \n", m_regs->rip);
    printf ("rsp: %lx \n", m_regs->rsp);
    printf ("rbp: %lx \n", m_regs->rbp);
}

bool CThinCtrl::parseOperands(InstrInfo *info) {
    DAPIInstrPtr &I = info->PI;
    std::vector<OprndInfoPtr> &vecOI = info->vecOI;

    // Set the value of referred regsiters before parsing
    setReadRegs(I);

    bool bUS = false;  // Operands refer to symbolic variable?
    std::vector<Operand> oprands;

#ifdef _PARSE_CIE_SIE_OPERANDS
    int opcount = 0;
    // clear/init-to-0 the operands' mem access information
    memset((void*)(&execData->opDetails[0]) , 0x0, sizeof(struct OpDetails) );
    memset((void*)(&execData->opDetails[1]) , 0x0, sizeof(struct OpDetails) );
#endif

    I->getOperands(oprands);
    for (auto O : oprands) {
        OprndInfoPtr oi(new OprndInfo(O));
        oi->size = O.getValue()->size();  // Set the operand size ASAP;
        oi->symb = false;                 // Set to false by default;

        bool res = false;  // Operands refer to symbolic variable?
        bool bRead = false ;
        bool bWrite = false ;
        bRead = O.readsMemory () ;
        bWrite = O.writesMemory () ;
        if (!bRead && !bWrite) {
            if(!parsing_operands_for_mem_adr)
                res = _mayOperandUseSymbol_XX(oi);
        } else if (bRead && !bWrite) {
            res = _mayOperandUseSymbol_RX(I, oi);
        } else if (!bRead && bWrite) {
            res = _mayOperandUseSymbol_XW(I, oi);
        } else if (bRead && bWrite) {
            res = _mayOperandUseSymbol_RW(I, oi);
        }
        bUS |= res;
        vecOI.push_back(oi);

#ifdef _PARSE_CIE_SIE_OPERANDS
        if(opcount > 2) //we expect only two operands, if encountered more than 2, add support
            assert(0);
        if (!bRead && !bWrite) {
            execData->opDetails[opcount].opmemac.memrdwr = false;
            execData->opDetails[opcount].opmemac.rdmem = false;
            execData->opDetails[opcount].opmemac.wrmem = false;
        } else if (bRead && !bWrite) {
            execData->opDetails[opcount].opmemac.memrdwr = true;
            execData->opDetails[opcount].opmemac.rdmem = true;
            execData->opDetails[opcount].opmemac.memAddress = oi->mem_conaddr;
            execData->opDetails[opcount].opmemac.wrmem = false; 
            execData->opDetails[opcount].opmemac.size = oi->size;
            std::cout << "op mem_conaddr: " << std::hex << oi->mem_conaddr << std::endl;
        } else if (!bRead && bWrite) {
            execData->opDetails[opcount].opmemac.memrdwr = true;
            execData->opDetails[opcount].opmemac.rdmem = false;
            execData->opDetails[opcount].opmemac.memAddress = oi->mem_conaddr;
            execData->opDetails[opcount].opmemac.wrmem = true;
            execData->opDetails[opcount].opmemac.size = oi->size;
            std::cout << "op mem_conaddr: " << std::hex << oi->mem_conaddr << std::endl;
        } else if (bRead && bWrite) {
            execData->opDetails[opcount].opmemac.memrdwr = true;
            execData->opDetails[opcount].opmemac.rdmem = true;
            execData->opDetails[opcount].opmemac.memAddress = oi->mem_conaddr;
            execData->opDetails[opcount].opmemac.wrmem = true;
            execData->opDetails[opcount].opmemac.size = oi->size;
            std::cout << "op mem_conaddr: " << std::hex << oi->mem_conaddr << std::endl;
        }
        opcount++;
#endif
    }
    return bUS;
}

bool CThinCtrl::setReadRegs(DAPIInstr *I) {
    std::set<RegisterAST::Ptr> readRegs;
    I->getReadSet(readRegs);
            
    for (auto P : readRegs) {
        uint indx = P->getID();
        uint size = P->size();
        
        // filter out the read to flag BIT reg
        if((indx&(x86_64::BIT| x86_64::FLAG | Arch_x86_64)) == (x86_64::BIT| x86_64::FLAG | Arch_x86_64))
            continue;
       
        RegValue V = {indx, size};
        bool res = m_VM->readRegister(V);
        assert(res);
        
        if (V.bsym) {
            // Do nothing
        } else {
            switch (size) {
                case 8:
                    P->setValue(Result(s64, V.i64));
                    break;
                case 4:
                    P->setValue(Result(s32, V.i32));
                    break;
                case 2:
                    P->setValue(Result(s16, V.i16));
                    break;
                case 1:
                    P->setValue(Result(s8, V.i8));
                    break;
                default:
                    FIX_ME();
                    break;
            }
        }
    }
}

bool CThinCtrl::setReadRegs(DAPIInstrPtr &I) {
    return setReadRegs(I.get());
}

bool CThinCtrl::calculateBinaryFunction (BinaryFunction* bf, KVExprPtr &exprPtr) {

    bool res = false;
    std::vector<Expression::Ptr> exps;
    bf->getChildren(exps);
    std::vector<KVExprPtr> KVE;
    for (auto E : exps) {
        // we already assert exps.size() == 2.
        RegisterAST* R = dynamic_cast<RegisterAST*>(E.get());
        Immediate* IMM = dynamic_cast<Immediate*>(E.get());
        BinaryFunction* binF = dynamic_cast<BinaryFunction*>(E.get());
        if (R != nullptr) {

            RegValue RV{(uint)R->getID(), (uint)R->size()};
            res = m_VM->readRegister(RV);
            assert(res);
            if (RV.bsym){
                RV.expr->setExprSize((uint)R->size());
                KVE.push_back(RV.expr);
            }
            else {
                KVExprPtr expr ;
                expr.reset ((new ConstExpr(RV.u64, (uint)R->size(), 0))) ;
                KVE.push_back (expr) ;
            }

        } else if (IMM != nullptr) {

            Result imm = IMM->eval();
            assert(imm.defined);
            long cval = imm.convert<long>();
            KVExprPtr eptr;
            eptr.reset(new ConstExpr(cval, IMM->size(), 0));
            KVE.push_back(eptr);

        } else if (binF != nullptr) {
            KVExprPtr eptr;
            calculateBinaryFunction(binF, eptr) ;
            KVE.push_back(eptr);
        } else {
            std::cout << "Unsupported pointer, add your support!" << std::endl ;
            assert (0) ;
        }
    }
    if(bf->isAdd() || bf->isMultiply()) {
        //make sure the size of the two expressions added are of the same
        int exp_sz0 = KVE[0]->getExprSize();
        int exp_sz1 = KVE[1]->getExprSize();
        int mx_sz = exp_sz0;
        if((KVE[0]->getKind() == EXPR::Expr::Const) && (exp_sz0 < exp_sz1))
        {
            mx_sz = exp_sz1;
            KVE[0]->setExprSize(exp_sz1);
        }
        else if((KVE[1]->getKind() == EXPR::Expr::Const) && (exp_sz1 < exp_sz0))
        {
            mx_sz = exp_sz0;
            KVE[1]->setExprSize(exp_sz0);
        }

        if(bf->isAdd())
            exprPtr.reset(new AddExpr(KVE[0], KVE[1], mx_sz, 0)) ;
        if(bf->isMultiply())
            exprPtr.reset(new MulExpr(KVE[0], KVE[1], mx_sz, 0)) ;
    }
    else {
        std::cout << "Unsupported pointer, add your support!" << std::endl ;
    }
    return true ;
}

// Case 1: no memory access
// eg1: mov $0x0,0xfffffff4(%rbp) -> $0x0
// eg2: mov 0xffffffe8(%rbp),%rax -> %rax
// eg3: mov %rax,0xfffffff8(%rbp) -> %rax
// eg4: jmp 0xb(%rip) -> 0xb(%rip)
bool CThinCtrl::_mayOperandUseSymbol_XX(OprndInfoPtr &oi) {
    //std::cout << "_mayOperandUseSymbol_XX\n";
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_RD;

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            // Read immediate operand:
            //std::cout << "Read immediate\n";
            // eg1: mov $0x0,0xfffffff4(%rbp) -> $0x0
            oi->opty = OPTY_IMM;
            auto RS = O->getValue()->eval();
            assert(RS.defined);
            oi->imm_value = RS.convert<ulong>();
            return true;
        } else {
            // Read a register operand or RIP-relative instruction:
            // eg3: mov %rax,0xfffffff8(%rbp) -> %rax
            // eg4: jmp 0xb(%rip) -> 0xb(%rip)
            // cout << O->format(Arch_x86_64) << endl;
            oi->opty = OPTY_REG;
           
            bool symReg = false;
            for (auto R : rdwrRegs)
            {
                RegValue RV{(uint)R->getID(), (uint)R->size()};
                res = m_VM->readRegister(RV);
                assert(res);
                if (RV.bsym)
                {
                    symReg = true;
                    break;
                }
            }

            if(symReg == false)
            {
                oi->reg_index = (*rdwrRegs.begin())->getID();//symexecutor needs rsp index when handling push & pop instrution
                
                oi->opty = OPTY_REGCON;
                auto RS = O->getValue()->eval();//The operand uses singel/multiple Concrete registers and/or Imm, evalute directly.
                assert(RS.defined);
                oi->reg_conval = RS.convert<ulong>();
            }
            else
            {
                oi->opty = OPTY_REGSYM;//it may be a single symbolic reg, or a combination
                oi->symb = true;
                auto V = O->getValue();
                std::vector<Expression::Ptr> exps;
                V->getChildren(exps);

                // reg/imm expr has no child expr
                if (exps.size() == 0) {
                    auto R = *rdwrRegs.begin();//The Operand is a symbolic register
                    oi->reg_index = R->getID();

                    RegValue RV{oi->reg_index, (uint)R->size()};
                    res = m_VM->readRegister(RV);
                    assert(res);
                    oi->reg_symval = RV.expr;
                } else {
                    BinaryFunction* bf = dynamic_cast<BinaryFunction*>(V.get());
                    assert(bf != nullptr) ;
                    assert(exps.size() == 2) ;
                    KVExprPtr exprPTR ;
                    calculateBinaryFunction (bf, exprPTR) ;
                    oi->reg_symval = exprPTR ;
                }
            }
            return true;
        }
    } else if (O->isWritten()) {
        //std::cout << "O->iswritten() yes\n";
        // Write into a register oprand:
        // eg2: mov 0xffffffe8(%rbp),%rax -> %rax
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_WR;

        // Should be a register operand
        O->getWriteSet(rdwrRegs);
        assert(rdwrRegs.size() == 1);
        auto R = *rdwrRegs.begin();
        oi->reg_index = R->getID();
        oi->symb = m_VM->isSYReg(oi->reg_index);
        if (oi->symb)
            oi->opty = OPTY_REGSYM;
        else
            oi->opty = OPTY_REGCON;
        return true;
    } else {
        ERRR_ME("Unexpected operand");
        exit(EXIT_FAILURE);
        return false;
    }
}

// For a memory read/write operand, it may involve multiple registers. 
// All involved registers are read regsiters except those push/pop or mov to
// regs? 
// Case 2: Read memory, and only do reading
// eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
bool CThinCtrl::_mayOperandUseSymbol_RX(DAPIInstrPtr& I, OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        // Read a memory cell:
        // eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_RD;
        oi->opty = OPTY_MEMCELL;
        
        /* For a mem access insn, if it uses gs, mem access Operand should add gs base */
        //for %ds %es
        ulong seg_base = getSegRegVal(I.get());

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {  // Direct memory access or through gs             
            std::vector<Expression::Ptr> exps;
            auto V = O->getValue();
            V->getChildren(exps);
            assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

            // Get and eval the address
            auto A = *exps.begin();
            auto RS = A->eval();
            assert(RS.defined);
            oi->mem_conaddr = RS.convert<ulong>() + seg_base;  

#ifdef _PARSE_CIE_SIE_OPERANDS
            //the target of _PARSE_CIE_SIE_OPERANDS is to obtain the memory address,
            //no need to perform the actual memory read
            //std::cout << "passed mem_conaddr: " << std::hex << oi->mem_conaddr << std::endl;
            if(parsing_operands_for_mem_adr)
                return true; 
#endif          

            MemValue MV{oi->mem_conaddr, oi->size};
            res = m_VM->readMemory(MV);
            assert(res);
            if (MV.bsym) {
                oi->opty = OPTY_MEMCELLSYM;
                oi->symb = true;
                oi->mem_symval = MV.expr;
            } else {
                oi->opty = OPTY_MEMCELLCON;
                oi->mem_conval = MV.i64;
            }
        } else {
            //std::cout <<"Access with one or more registers\n";
            // Access with one or more registers
            // eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
            bool bSymbolic;
            bool hasSymReg = false;

            for (auto R : rdwrRegs)
                hasSymReg |= maySymbolicRegister(R.get()->getID());

            if (hasSymReg) {
#ifdef _SYM_ADDR
                std::cout << "Sym addr concretization enabled, handling symbolic address" << std::endl;
                oi->opty = OPTY_REGSYM;//it may be a single symbolic reg, or a combination, we dont change this even if we derive the concrete address for memread
                oi->symb = true; // ??
                auto V = O->getValue();
                std::vector<Expression::Ptr> exps;
                V->getChildren(exps);
                uint64_t concrete_reg_val;
                KVExprPtr exprPTR(nullptr) ;

                if (exps.size() == 1) {
                    auto A = *exps.begin();
                    BinaryFunction* bf = dynamic_cast<BinaryFunction*>(A.get());
                    RegisterAST* R = dynamic_cast<RegisterAST*>(A.get());
                    Immediate* IMM = dynamic_cast<Immediate*>(A.get());
                    if(bf != nullptr){
                        calculateBinaryFunction (bf, exprPTR) ;
                        std::cout << "expression: ";
                        exprPTR->print();
                        std::cout << std::endl;
                    }
                    else if(R != nullptr){
                        RegValue RV{(uint)R->getID(), (uint)R->size()};
                        res = m_VM->readRegister(RV);
                        assert(res);
                        if(RV.bsym)
                        {
                            std::cout << "symbol: ";
                            RV.expr->print();
                            std::cout << std::endl;
                            exprPTR = RV.expr;
                        }
                        else
                        { 
                            assert(0);
                        }
                    } 
                    else if(R != nullptr){
                        std::cout << "IMM not null\n"; //can not be as the operand is symbolic
                        assert(0);
                    }

                    //get the concrete address for mem read
                    concrete_reg_val = m_EFlagsMgr->ConcretizeExpression(exprPTR);
                    std::cout << "concretized val : " << std::hex << concrete_reg_val << std::endl;
                    oi->mem_conaddr = (unsigned long)concrete_reg_val;        

                    //read memory
                    MemValue MV{oi->mem_conaddr, oi->size};
                    MV.isSymList = false;
                    res = m_VM->readMemory(MV);
                    assert(res);
                    if (MV.bsym) {
                        std::cout << "sym-mem\n";
                        oi->opty = OPTY_MEMCELLSYM;
                        oi->symb = true;
                        oi->mem_symval = MV.expr;
                        oi->mem_symval->print();
                        std::cout << std::endl;
                    } else {
                        std::cout << "not sym-mem\n";
                        oi->opty = OPTY_MEMCELLCON;
                        oi->symb = false; //because the content at this address is not symbolic ?
                        oi->mem_conval = MV.i64;
                    }
                    return true;
                }
                assert(false);
             
#endif
                std::cout << "sym mem addr detected ...\n enable _SYM_ADDR it you want to concretize\n";
                assert(0);
            }
            else {
                std::vector<Expression::Ptr> exps;
                auto V = O->getValue();
                V->getChildren(exps);
                // memory dereference: [xxx] -> xxx
                assert(exps.size() == 1);

                // Get and eval the address
                auto A = *exps.begin();
                auto RS = A->eval();
                assert(RS.defined);
                //for %ds %es
                if (seg_base == 0)
                    oi->mem_conaddr = RS.convert<ulong>();
                else
                    oi->mem_conaddr = RS.convert<ulong>() + seg_base;
#ifdef _PARSE_CIE_SIE_OPERANDS
                //the target of _PARSE_CIE_SIE_OPERANDS is to obtain the memory address,
                //no need to perform the actual memory read
                //std::cout << "passed mem_conaddr: " << std::hex << oi->mem_conaddr << std::endl;
                if(parsing_operands_for_mem_adr)
                    return true; 
#endif          
                MemValue MV{oi->mem_conaddr, oi->size};
                res = m_VM->readMemory(MV);
                assert(res);
                if (MV.bsym) {
                    oi->opty = OPTY_MEMCELLSYM;
                    oi->symb = true;
                    oi->mem_symval = MV.expr;
                } else {
                    oi->opty = OPTY_MEMCELLCON;
                    oi->mem_conval = MV.i64;
                }
                return true;
            }
        }
    } else if (O->isWritten()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        assert(0);
        oi->rdwr = OPAC_WR;
        O->getWriteSet(rdwrRegs);
        // Should be a register operand
        assert(rdwrRegs.size() == 1);
        auto R = *rdwrRegs.begin();
        oi->reg_index = R.get()->getID();
        cout << "246: Write: " << O->getValue()->format() << "\n";
        return false;
    } else {
        cerr << "249: Unexpected operand" << O->getValue()->format() << "\n";
        return false;
    }
}

// Case 3: Write memory, and only do writing
// eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
bool CThinCtrl::_mayOperandUseSymbol_XW(DAPIInstrPtr& I, OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        assert(0);
    } else if (O->isWritten()) {
        // eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_WR;       // Write into a memory cell
        oi->opty = OPTY_MEMCELL;  // may be refined later
        
        /* For a mem access insn, if it uses gs, mem access Operand should add gs base */
        ulong gs_base = isUseGS(I.get()); 

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            assert(0);
        } else {
            // Access memory with one or more registers
            // eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
            bool hasSymReg = false;
            for (auto R : rdwrRegs)
                hasSymReg |= maySymbolicRegister(R->getID());

            if (hasSymReg) {

#ifdef _SYM_ADDR
                std::cout << "Sym addr concretization enabled, handling symbolic address" << std::endl;
                oi->opty = OPTY_REGSYM;//it may be a single symbolic reg, or a combination, we dont change this even if we derive the concrete address for memread
                oi->symb = true; // ??
                auto V = O->getValue();
                std::vector<Expression::Ptr> exps;
                V->getChildren(exps);
                uint64_t concrete_reg_val;
                KVExprPtr exprPTR(nullptr) ;

                if (exps.size() == 1) {
                    auto A = *exps.begin();
                    BinaryFunction* bf = dynamic_cast<BinaryFunction*>(A.get());
                    RegisterAST* R = dynamic_cast<RegisterAST*>(A.get());
                    Immediate* IMM = dynamic_cast<Immediate*>(A.get());
                    if(bf != nullptr){
                        calculateBinaryFunction (bf, exprPTR) ;
                        std::cout << "expression: ";
                        exprPTR->print();
                        std::cout << std::endl;
                    }
                    else if(R != nullptr){
                        RegValue RV{(uint)R->getID(), (uint)R->size()};
                        res = m_VM->readRegister(RV);
                        assert(res);
                        if(RV.bsym)
                        {
                            std::cout << "symbol: ";
                            RV.expr->print();
                            std::cout << std::endl;
                            exprPTR = RV.expr;
                        }
                        else
                        { 
                            assert(0);
                        }
                    } 
                    else if(R != nullptr){
                        std::cout << "IMM not null\n"; //can not be as the operand is symbolic
                        assert(0);
                    }

                    //get the concrete address for mem read
                    concrete_reg_val = m_EFlagsMgr->ConcretizeExpression(exprPTR);
                    std::cout << "concretized val : " << std::hex << concrete_reg_val << std::endl;
                    oi->mem_conaddr = (unsigned long)concrete_reg_val;        

                    //read memory
                    MemValue MV{oi->mem_conaddr, oi->size};
                    MV.isSymList = false;
                    res = m_VM->readMemory(MV);
                    assert(res);
                    if (MV.bsym) {
                        std::cout << "sym-mem\n";
                        oi->opty = OPTY_MEMCELLSYM;
                        oi->symb = true;
                        oi->mem_symval = MV.expr;
                        oi->mem_symval->print();
                        std::cout << std::endl;
                    } else {
                        std::cout << "not sym-mem\n";
                        oi->opty = OPTY_MEMCELLCON;
                        oi->symb = false; //because the content at this address is not symbolic ?
                        oi->mem_conval = MV.i64;
                    }
                    return true;
                }
                assert(false);
             
#endif
                std::cout << "sym mem addr detected ...\n enable _SYM_ADDR it you want to concretize\n";
                assert(0);
                // Operand has at lease one symbolic register;
                oi->symb = true;
                return false;
            } else {
                // Memory access without symbolic register               
                std::vector<Expression::Ptr> exps;
                auto V = O->getValue();
                V->getChildren(exps);
                assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

                // Get and eval the address
                auto A = *exps.begin();
                auto RS = A->eval();
                assert(RS.defined);
                if (gs_base == 0)
                    oi->mem_conaddr = RS.convert<ulong>();
                else
                    oi->mem_conaddr = RS.convert<ulong>() + gs_base;
                
#ifdef _PARSE_CIE_SIE_OPERANDS
                //the target of _PARSE_CIE_SIE_OPERANDS is to obtain the memory address,
                //once addr is obtined return
                //std::cout << "passed mem_conaddr: " << std::hex << oi->mem_conaddr << std::endl;
                if(parsing_operands_for_mem_adr)
                    return true; 
#endif          
                oi->symb = true;
                return true;
            }
        }
    } else {
        assert(0);
        cerr << "345: Unexpected operand" << O->getValue()->format() << "\n";
        return false;
    }
}

// Case 4: Reading & writing apply on the same memory cell
// eg1. add $0x8,0xfffffff8(%rbp) -> 0xfffffff8(%rbp)
bool CThinCtrl::_mayOperandUseSymbol_RW(DAPIInstrPtr& I, OprndInfoPtr &oi) {
// bool CThinCtrl::_mayOperandUseSymbol_RW(OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;

    oi->rdwr = OPAC_RDWR;
    oi->opty = OPTY_MEMCELL;
        
    /* For a mem access insn, if it uses gs, mem access Operand should add gs base */
    ulong gs_base = isUseGS(I.get()); 

    std::set<RegisterAST::Ptr> rdwrRegs;
    O->getReadSet(rdwrRegs);
    if (rdwrRegs.size() == 0) {
        assert(0);
    } else {
        // Access memory with one or more registers:
        // eg1.add $0x8, 0xfffffff8(%rbp)->0xfffffff8(%rbp)
        bool hasSymReg = false;
        for (auto R : rdwrRegs)
            hasSymReg |= maySymbolicRegister(R->getID());

        if (hasSymReg) {
            FIX_ME();
            assert(0);
        } else {
            // Memory access without symbolic register
            std::vector<Expression::Ptr> exps;
            auto V = O->getValue();
            V->getChildren(exps);
            assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

            // Get and eval the address
            auto A = *exps.begin();
            auto RS = A->eval();
            assert(RS.defined);

            if (gs_base == 0)
                oi->mem_conaddr = RS.convert<ulong>();
            else
                oi->mem_conaddr = RS.convert<ulong>() + gs_base;
            
#ifdef _PARSE_CIE_SIE_OPERANDS
            //the target of _PARSE_CIE_SIE_OPERANDS is to obtain the memory address,
            //no need to perform the actual memory read, hence return
            //std::cout << "passed mem_conaddr: " << std::hex << oi->mem_conaddr << std::endl;
            if(parsing_operands_for_mem_adr)
                return true; 
#endif          
            MemValue MV{oi->mem_conaddr, oi->size};
            res = m_VM->readMemory(MV);
            assert(res);
            if (MV.bsym) {
                oi->opty = OPTY_MEMCELLSYM;
                oi->symb = true;
                oi->mem_symval = MV.expr;
            } else {
                oi->opty = OPTY_MEMCELLCON;
                oi->mem_conval = MV.i64;
            }
            return true;
        }
    }

    return false;
}

bool CThinCtrl::maySymbolicRegister(uint ID) {
    return m_VM->isSYReg(ID);
}

bool CThinCtrl::maySymbolicMemoryCell(ulong memory_addr, int width) {
    return m_VM->isSYMemoryCell(memory_addr, width);
}

bool CThinCtrl::getBranchAddress(Instruction* in, uint64_t &trueBranch, uint64_t &falseBranch)
{
    std::vector<Operand> oprands;
    in->getOperands(oprands);
    assert(oprands.size() == 1);
    auto O = *oprands.begin();
    OprndInfoPtr oi(new OprndInfo(O));
    struct pt_regs* m_regs = m_VM->getPTRegs() ;
    if (!O.readsMemory())
    {
        Expression::Ptr target = oi->PO->getValue();
        RegisterAST* rast = new RegisterAST(MachRegister::getPC(Arch_x86_64));
        target->bind(rast, Result(s64, m_regs->rip));
        Result res = target->eval();
        Address tempTarget;
        if (res.defined) //direct jmp
        {
            tempTarget = res.convert<Address>();
            trueBranch = tempTarget - in->size();
            falseBranch = m_regs->rip ;
        }
        else //indirect jmp through register 
        {
            std::set<RegisterAST::Ptr> regsRead;
            oi->PO->getReadSet(regsRead);
            assert(regsRead.size() == 1);
            auto R = *regsRead.begin();
            oi->reg_index = R->getID();

            RegValue RV{oi->reg_index, (uint)R->size()};
            bool ret = m_VM->readRegister(RV);
            assert(ret);
            assert(!RV.bsym);
                
            tempTarget = RV.i64;
            
            trueBranch = tempTarget ;
            falseBranch = m_regs->rip  + in->size() ;
        }
    }
    else
    {
        Expression::Ptr target = oi->PO->getValue();
        std::vector<Expression::Ptr> exps;
        target->getChildren(exps);
        // memory dereference: [xxx] -> xxx
        assert(exps.size() == 1);

        // Get and eval the address
        auto A = *exps.begin();
        auto RS = A->eval();
        assert(RS.defined);
        oi->mem_conaddr = RS.convert<ulong>();
#ifdef _DEBUG_OUTTPUT
        std::cout << "fetch jmp dest from addr " << oi->mem_conaddr << std::endl;
#endif
        MemValue MV{oi->mem_conaddr, 8};//in x64, a mem access addr must be 8-byte
        bool ret = m_VM->readMemory(MV);
        assert(ret);
        assert(MV.bsym);
            
        Address tempTarget = MV.i64;

        trueBranch = tempTarget ;
        falseBranch = m_regs->rip  + in->size() ;
    }
    return true;
}


static struct MacReg tmpMRegs ;

void PrintConstraint (std::set<KVExprPtr> *c) {
    for(auto it : *c) {
        it->print() ;
        std::cout << "\n" ;
    }
    std::cout << "\n" ;
}

void CThinCtrl::startPathExplore() {
    
    extern void init_pgTable() ;  //set all pages to read only except?
    extern void restore_pages() ; //restore 
    hmt[hmtround].start = hmt[hmtround].start = rdtsc();

    if (bPath_explore == false) {
        bPath_explore = true ;
    
        m_VM->ReadCPUState(m_VM, &tmpMRegs) ;
        m_EFlagsMgr->backup() ;
        PrintConstraint(&m_EFlagsMgr->m_Constraint_back) ;
        m_VM->backup() ;
        init_pgTable () ;
    } else {
        m_VM->SetCPUState(m_VM, &tmpMRegs) ;
        m_VM->restore() ;
        m_EFlagsMgr->restore() ;
        restore_pages () ;
    }

    hmt[hmtround].start1 = rdtsc();
    hmt[hmtround].instno = 0 ;

}

void printHMTime () {
    int i = 0 ;
    std::cout << std::dec ;
    std::cout << std::endl << "time :" << std::endl ;

    printf ("%15ld, \t\t%15ld, \t\t%15ld, \t\t%15ld, \t\t%15ld\n", hmt[i].end, hmt[i].start, hmt[i].start1, hmt[i].end - hmt[i].start, hmt[i].instno) ;
    for (i=1; i <= hmtround; i++) {
        printf ("%15ld, \t\t%15ld, \t\t%15ld, \t\t%15ld, \t\t%15ld, \t\t%15ld\n", 
            hmt[i].end, hmt[i].start, hmt[i].start1, hmt[i].end - hmt[i].start, hmt[i].start1 - hmt[i-1].end, hmt[i].instno) ;
    }
    std::cout << std::hex ;
}