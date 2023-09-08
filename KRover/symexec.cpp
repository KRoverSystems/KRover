#include "symexec.h"
#include <linux/types.h>
#include <signal.h>
#include <ucontext.h>
#include <iostream>
#include "BinaryFunction.h"
#include "CodeObject.h"
#include "Expr.h"
#include "InstructionDecoder.h"
#include "VMState.h"
#include "interface.h"
#include "thinctrl.h"
#include "SymList.h"
#include "EFlagsManager.h"

#define signext_to_long(sz1, v) ((((v) & (1<<((sz1*8)-1))) == 0) ? (v) : ((long)(-1)) & ~((1UL << (sz1*8)) - 1) | (v))
using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

using namespace EXPR;

bool SymExecutor::pushInstr(InstrInfoPtr &I) {
    m_IOIs.push_back(I);
    return true;
}

bool SymExecutor::run(VMState *vm) {
    bool ret = false;
    _run_prologue();


    for (auto IOI : m_IOIs) {
        auto &I = IOI->PI;
        auto &vecOI = IOI->vecOI;
        m_RIPUpdated = false;

        entryID id = I->getOperation().getID() ;

        switch (id) {
            case e_mov:
            case e_movbe:
            case e_movsl:
            case e_movabs:
            case e_movapd:
            case e_movaps:
            case e_movd:
            case e_movddup:
            case e_movdq2q:
            case e_movdqa:
            case e_movdqu:
            case e_movhpd:
            case e_movhps:
            case e_movhps_movlhps:
            case e_movlpd:
            case e_movlps:
            case e_movlps_movhlps:
            case e_movmskpd:
            case e_movmskps:
            case e_movntdq:
            case e_movntdqa:  // SSE 4.1
            case e_movnti:
            case e_movntpd:
            case e_movntps:
            case e_movntq:
            case e_movntsd:
            case e_movntss:
            case e_movq:
            case e_movq2dq:
            case e_movsd_sse:
            case e_movshdup:
            case e_movsldup:
            case e_movss:
            case e_movupd:
            case e_movups: {
                ret = process_mov(vm, IOI);
            } break;

            case e_movsx:
            case e_movslq:
            case e_movsxd: {
                ret = process_movsx(vm, IOI);
            } break;

            case e_movzx:{
                ret = process_movzx(vm, IOI);
            } break;

            
            case e_cbw:
            case e_cwde:
            case e_cwtl: {
                ret = process_cbw(vm, IOI);
            } break;

            case e_cdq:
            case e_cwd: {
                ret = process_cdq(vm, IOI);
                break ;
            }

            case e_addpd:
            case e_addps:
            case e_addsd:
            case e_addss:
            case e_addsubpd:
            case e_addsubps: {
                assert(0);
            } break ;

            case e_add: {
                ret = process_add(vm, IOI);
            } break;
            
            case e_subpd:
            case e_subps:
            case e_subsd:
            case e_subss:            {
                // Process substraction
                assert(0);
            } break;

            case e_sub: {
                // Process substraction
                ret = process_sub(vm, IOI);
                break;
            } 
            
            case e_idiv: {
                ret = process_idiv(vm, IOI) ;
                break ;
            }
            
            case e_mul:
            case e_imul:  {
                ret = process_mul(vm, IOI) ;
                break ;
            }

            case e_mulpd:
            case e_mulps:
            case e_mulsd:
            case e_mulss: {
                assert(0);
            } break;
            case e_div: {
                ret = process_div(vm, IOI) ;
            } break;

            case e_divpd:
            case e_divps:
            case e_divsd:
            case e_divss: {
                assert(0);
            } break;

            case e_and: {
                ret = process_and(vm, IOI) ;
                break ;
            }
            case e_andnpd:
            case e_andnps:
            case e_andpd:
            case e_andps: {
                //  Process logical and
                assert(0);
            } break;
            case e_or: {
                ret = process_or(vm, IOI);
                break; 
            }
            case e_orpd:
            case e_orps: {
                assert(0);
            } break;
            case e_not: {
                ret = process_not(vm, IOI);
                break; 
            } break;
            case e_neg: {
                ret = process_neg(vm, IOI);
                break ;
            }
            case e_test: {
                ret = process_test(vm, IOI);
            } break;

            case e_cmovbe:
            case e_cmove:
            case e_cmovnae:
            case e_cmovnb:  // or cmovae 
            case e_cmovnbe:
            case e_cmovne:
            case e_cmovng:  // or cmovle
            case e_cmovnge:
            case e_cmovnl:  // or cmovge
            case e_cmovno:
            case e_cmovns:
            case e_cmovo:
            case e_cmovpe:
            case e_cmovpo:
            case e_cmovs: {
                ret = process_cmovxx(vm, IOI) ;
                break ;
            }
            case e_ja:
	        case e_jb:
	        case e_jbe:
	        case e_je:
	        case e_jge:
	        case e_jl:
	        case e_jle:
	        case e_jmp:
	        case e_jmpq:
	        case e_jne:
            case e_jz:
            case e_jnz:
	        case e_jns:
	        case e_js: {
                ret = process_jcc(vm, IOI) ;
                break ;
            }
            case e_setb:
            case e_setbe:
            case e_setl:
            case e_setle:
            case e_setnb:
            case e_setnbe:
            case e_setnl:
            case e_setnle:
            case e_setno:
            case e_setnp:
            case e_setns:
            case e_setnz:
            case e_seto:
            case e_setp:
            case e_sets:
            case e_setz: {
                ret = process_set(vm, IOI) ;
                break;
            }
            case e_cmp: 
            case e_cmpw: {
                ret = process_cmp(vm, IOI) ;
                break ;
            }
            case e_xor :{
                ret = process_xor(vm, IOI) ;
                break ;
            }
            case e_shl_sal: {
                ret = process_shl_sal (vm, IOI) ;
                break ;
            }
            case e_shr: {
                ret = process_shr (vm, IOI) ;
                break ;
            }
            case e_shrd:{
                ret = process_shrd (vm, IOI) ;
                break ;
            }
            case e_sar:{
                ret = process_sar (vm, IOI) ;
                break ;
            }
            case e_xchg: {
                ret = process_xchg (vm, IOI) ;
                break ;
            }

            case e_pop:{
                ret = process_pop (vm, IOI) ;
                break ;
            }

            case e_push:{
                ret = process_push (vm, IOI) ;
                break ;
            }

            case e_lea:
                ret = process_lea (vm, IOI) ;
                break ;

            case e_rdtsc: {
                // read real time clock ...
                break ;
            }
            case e_sbb: {
                ret = process_sbb (vm, IOI);
                break;
            }

            case e_sidt: {
                ret = process_sidt (vm, IOI);
                break;
            }

            case e_dec: {
                ret = process_dec (vm, IOI);
                break;
            }

            case e_xadd: {
                ret = process_xadd (vm, IOI);
                break;
            }
            case e_bswap: {
                ret = process_bswap(vm, IOI);
            } break;

            case e_leave: {
                ret = process_leave(vm, IOI);
            } break;

            case e_bsr: {
                ret = process_bsr(vm, IOI);
                break ;
            }

            case e_bt: {
                ret = process_bt(vm, IOI);
                break ;
            }
            case e_rcl:
            case e_rcr:
            case e_rol:
            case e_rolb:
            case e_ror: {
                ret = process_rotate(vm, IOI);
                break ;
            }
            case e_stos:
            case e_stosb:
            case e_stosd:
            case e_stosw: {
                ret = process_stos(vm, IOI) ;
                break ;
            }

            case e_movsb:
            case e_movsw:
            case e_movsd: {
                ret = process_movs(vm, IOI) ;
                break ;
            }

            default: {
                cout << "!!!!!!!!!!Unhandled SIE: instruction: " << I->format() << "!!!!!!!\n";
                ret = false ;

            } break;
        }

    } 
    _run_postlogue();
    return ret;
}

bool SymExecutor::_run_prologue(void) {}

bool SymExecutor::_run_postlogue(void) {
    m_IOIs.clear();
    return true;
}

bool SymExecutor::process_sidt(VMState *vm, InstrInfoPtr &infoptr) {
    
    unsigned char ret[10];
    unsigned long ra = (unsigned long)&ret[0];
    asm volatile("sidt %0; \n\t"
                ::"m"(ra):);
    std::cout << "at process_sidt : sidt val " << *((unsigned short*)(&ret[0])) << " // " << *((unsigned long*)(&ret[2])) << std::endl;

    return false;
}

bool SymExecutor::process_lea(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    KVExprPtr e;
    bool res;
    long val;

    if (oidst->size == 4)  {
        if ((oidst->opty & OPTY_REG) == OPTY_REG) {
            
            // we need to clear the 3rd byte, according to dyn_reg.h::435
            uint reg_indx = oidst->reg_index ;
            reg_indx &= (0xFFFFF0FF) ;
            RegValue rv ;
            rv.size = 8 ;
            rv.indx = reg_indx ;
            rv.bsym = false ;
            rv.u64 = 0 ;
            vm->writeRegister (rv) ;
        }
    }

    if(oisrc->symb) {
        KVExprPtr e1(nullptr);
        // Do reading
        res = oisrc->getSymValue(e1);
        assert(res);

        // Do writting
        e1->print();
        std::cout << std::endl;
        if(oidst->size < e1->getExprSize())
        {   
            e.reset(new ExtractExpr(e1, 0, oidst->size)); //, oidst->size, 0));
            res = oidst->setSymValue(vm, e);
            assert(res); 
            return true;
        }

        res = oidst->setSymValue(vm, e1);
        assert(res);
    } 
    else {
        assert(oidst->symb) ;
        // Do reading
        res = oisrc->getConValue(val);
        assert(res);
        // Do writting
        res = oidst->setConValue(vm, val);
        assert(res);
    }

    return true ;
}

bool SymExecutor::process_jcc(VMState *vm, InstrInfoPtr &infoptr) {
    return true ;
}

bool SymExecutor::process_bsr(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    KVExprPtr e, er;
    bool res ;
    
    res = oisrc->getSymValue(e);
    assert(res);

    er.reset(new BsrExpr(e, oidst->size, 0)) ;
    
    res = oidst->setSymValue(vm, er) ;
    assert (res) ;

    return true ;
}

bool SymExecutor::process_stos (VMState *vm, InstrInfoPtr &infoptr) {

    Instruction *in = new Instruction(*infoptr->PI);
    InstrInfo *ioi = new InstrInfo(in);
    
    parseOperands(vm, ioi, true);

    auto &vecOI = ioi->vecOI;

    OprndInfoPtr &oisrc = vecOI[1];

    bool res ;

    RegValue rv_rdi, rv_rcx ;
    rv_rdi.indx = x86_64::rdi ;
    rv_rdi.size = 8 ;
    vm->readRegister(rv_rdi) ;
    assert (!rv_rdi.bsym) ;
    uint64_t addr = rv_rdi.u64 ;

    rv_rcx.indx = x86_64::rcx ;
    rv_rcx.size = 8 ;
    vm->readRegister(rv_rcx) ;
    assert (!rv_rcx.bsym) ;

    uint64_t loopcnt = 1 ;

    if (in->getOperation().getPrefixID() != prefix_none)
        loopcnt = rv_rcx.u64 ;
    
    SymCellPtr cellList ;
    long v ;
    MemValue mv ;

    mv.size = oisrc->size ;
    if (oisrc->symb) {
        res = oisrc->getSymValue(cellList, v) ;
        assert(res) ;
        mv.bsym = mv.isSymList = true ;
        mv.symcellPtr = cellList ;
        mv.i64 = v ;

    } else {
        res = oisrc->getConValue(v) ;
        assert (res) ;
        mv.bsym = mv.isSymList = false ;
        mv.i64 = v ;
    }

    for (uint64_t i = 0; i < loopcnt; i++) {
        
        mv.addr = addr ;

        vm->writeMemory(mv) ;
        
        addr += oisrc->size ;
    }
    
    rv_rdi.u64 = addr ;
    vm->writeRegister(rv_rdi) ;

    if (in->getOperation().getPrefixID() != prefix_none) {
        rv_rcx.u64 = 0 ;
        vm->writeRegister(rv_rcx) ;
    }
    //delete in; delete ioi;
    return true ;
}

bool SymExecutor::process_movs (VMState *vm, InstrInfoPtr &infoptr) {

    Instruction *in = new Instruction(*infoptr->PI);
    InstrInfo *ioi = new InstrInfo(in);
    
    parseOperands(vm, ioi, true);
    auto &vecOI = ioi->vecOI;
    OprndInfoPtr &oidest = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    bool res ;

    RegValue rv_rdi, rv_rcx, rv_rsi ;

    rv_rsi.indx = x86_64::rsi ;
    rv_rsi.size = 8 ;
    vm->readRegister(rv_rsi) ;
    assert (!rv_rsi.bsym) ;
    uint64_t s_addr = rv_rsi.u64 ;

    rv_rdi.indx = x86_64::rdi ;
    rv_rdi.size = 8 ;
    vm->readRegister(rv_rdi) ;
    assert (!rv_rdi.bsym) ;
    uint64_t d_addr = rv_rdi.u64 ;

    rv_rcx.indx = x86_64::rcx ;
    rv_rcx.size = 8 ;
    vm->readRegister(rv_rcx) ;
    assert (!rv_rcx.bsym) ;

    uint64_t loopcnt = 1 ;

    if (in->getOperation().getPrefixID() != prefix_none)
        loopcnt = rv_rcx.u64 ;
    
    SymCellPtr cellList ;
    long v ;

    for (uint64_t i = 0; i < loopcnt; i++) {
        MemValue mv ;
        mv.size = oisrc->size ;
        mv.addr = s_addr ;
        mv.isSymList = true;
        vm->readMemory(mv) ;

        mv.addr = d_addr ;
        vm->writeMemory(mv) ;
        
        s_addr += oisrc->size ;
        d_addr += oidest->size ;
    }
    
    rv_rdi.u64 = d_addr ;
    vm->writeRegister(rv_rdi) ;

    rv_rsi.u64 = s_addr ;
    vm->writeRegister(rv_rsi) ;

    if (in->getOperation().getPrefixID() != prefix_none) {
        rv_rcx.u64 = 0 ;
        vm->writeRegister(rv_rcx) ;
    }
    //delete in; delete ioi;
    return true ;
}

bool SymExecutor::process_rotate(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    KVExprPtr e1, e2, er;
    long v1, v2 ;
    bool res ;
    
    assert(oisrc->symb || oidst->symb) ;
    
    if(oisrc->symb) {
        res = oisrc->getSymValue(e1) ;
        assert(res);
    } else {
         res = oisrc->getConValue(v1) ;
         e1.reset(new ConstExpr(v1, oisrc->size, 0)) ;
    }

    if(oidst->symb) {
        res = oidst->getSymValue(e2) ;
        assert(res);
    } else {
        res = oidst->getConValue(v2) ;
        assert(res);
        e2.reset(new ConstExpr(v2, oidst->size, 0)) ;
    }

    er.reset(new RotateExpr(e1, e2, oidst->size, 0)) ;
    
    return true ;
}
bool SymExecutor::process_bt(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    KVExprPtr e1, e2, er;
    long v1, v2 ;
    bool res ;
    
    assert(oisrc->symb || oidst->symb) ;
    
    if(oisrc->symb) {
        res = oisrc->getSymValue(e1) ;
        assert(res);
    } else {
         res = oisrc->getConValue(v1) ;
         e1.reset(new ConstExpr(v1, oisrc->size, 0)) ;
    }

    if(oidst->symb) {
        res = oidst->getSymValue(e2) ;
        assert(res);
    } else {
        res = oidst->getConValue(v2) ;
        assert(res);
        e2.reset(new ConstExpr(v2, oidst->size, 0)) ;
    }

    er.reset(new BtExpr(e1, e2, oidst->size, 0)) ;
    
    vm->SaveFlagChangingInstructionExpr(e_bt, er) ;
    return true ;
}

bool SymExecutor::process_jmp(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc = vecOI[0];
    bool res;
    long val;

    // Do reading
    assert(!oisrc->symb);
    res = oisrc->getConValue(val);
    assert(res);

    RegValue V{(uint)x86_64::rip, 8, false, val};
    vm->writeRegister(V);
    m_RIPUpdated = true;
    return true;
}

bool SymExecutor::process_leave(VMState *vm, InstrInfoPtr &infoptr) {
    // leaveq =
    // mov %rbp, %rsp
    // +
    // pop %rbp
    bool res = false ;

    // fisrt mov
    RegValue rv_rbp{(uint)x86_64::rbp, 8, false, false};
    RegValue rv_rsp{(uint)x86_64::rsp, 8, false, false};

    // read %rbp
    res = vm->readRegister(rv_rbp);
    assert (res) ;
    // can %rsp is a symbol? I think, it should not.
    assert (!rv_rbp.bsym) ;

    std::cout << "v_rbp.bsym " << rv_rbp.bsym << std::endl;
    std::cout << "v_rsp.bsym " << rv_rsp.bsym << std::endl;

    // copy rbp to rsp
    rv_rsp.bsym = rv_rbp.bsym ;
    rv_rsp.expr = rv_rbp.expr ;
    rv_rsp.isSymList = rv_rbp.isSymList ;
    rv_rsp.size = rv_rbp.size ;
    rv_rsp.symcellPtr = rv_rbp.symcellPtr ;
    rv_rsp.u64 = rv_rbp.u64 ;
    
    // write to %rsp,
    // maybe we don't need to write to %rsp at this moment, 
    // any way, after pop, we will write again.
    res = vm->writeRegister(rv_rsp) ;
    assert (res) ;

    // then pop
    MemValue MV ;
    MV.addr = rv_rsp.u64 ;
    MV.size = 8 ;
    MV.isSymList = true;
    res = vm->readMemory(MV) ;
    assert(res) ;

    if(MV.symcellPtr==NULL)
        std::cout << "old rbp points to non sym mem" << std::endl;
    printCellList(MV.symcellPtr);

    rv_rbp.bsym = MV.bsym ;
    rv_rbp.expr = MV.expr ;
    rv_rbp.isSymList = MV.isSymList ;
    rv_rbp.size = MV.size ;
    rv_rbp.symcellPtr = MV.symcellPtr ;
    rv_rbp.u64 = MV.u64 ;

    res = vm->writeRegister(rv_rbp) ;

    assert(res) ;
    
    rv_rsp.u64 += 8 ;
    res = vm->writeRegister(rv_rsp);
    assert(res) ;

    return true ;
}

// REP prefix
//
// all the rep prefix instructions are like:
//   rep movs[blq] %ds:(%rsi), %es:(%rdi) 
//
bool SymExecutor::process_mov_rep(VMState *vm, InstrInfoPtr &infoptr) {
    Instruction *in = new Instruction(*infoptr->PI);
    InstrInfo *ioi = new InstrInfo(in);
    
    parseOperands(vm, ioi, true);

    auto &vecOI = ioi->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];

    int op_size = oidst->size ;

    RegValue r_rcx {(uint)x86_64::rcx, 8} ,
             r_ds  {(uint)x86_64::ds,  8} ,
             r_es  {(uint)x86_64::es,  8} ,
             r_rsi {(uint)x86_64::rsi, 8} ,
             r_rdi {(uint)x86_64::rdi, 8} ;

    vm->readRegister (r_rcx) ;
    vm->readRegister (r_ds) ;
    vm->readRegister (r_es) ;
    vm->readRegister (r_rsi) ;
    vm->readRegister (r_rdi) ;
    // should check all above registers are not symbol ??

    unsigned long loop_cnt = r_rcx.u64 ;
    unsigned long rd_addr = r_rsi.u64, wr_addr = r_rdi.u64 ;

    while (loop_cnt!=0) {
        // copy source to dest;
        MemValue mv ;
        mv.addr = rd_addr;
        mv.size = op_size ;
        mv.isSymList = true ;

        vm->readMemory (mv) ;
        
        mv.addr = wr_addr ;
        vm->writeMemory (mv) ;

        // update loop counter, address;
        loop_cnt -- ;
        rd_addr += op_size ;
        wr_addr += op_size ;
    }

    // update rcx;
    r_rcx.u64 = loop_cnt ;
    vm->writeRegister (r_rcx) ;
    return true ;

}

bool SymExecutor::process_mov(VMState *vm, InstrInfoPtr &infoptr) {
    // Process move instruction
    Instruction *in = new Instruction(*infoptr->PI);
    InstrInfo *ioi = new InstrInfo(in);

    //REP prefix
    if (in->getOperation().getPrefixID() != prefix_none) {
        return process_mov_rep(vm, infoptr) ;
    }

    parseOperands(vm, ioi, true);

    auto &vecOI = ioi->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    SymCellPtr cellList;
    bool res;
    long val;

    bool dest_is_sym = oidst->symb ;

    if (oidst->size == 4)  {
        if ((oidst->opty & OPTY_REG) == OPTY_REG) {
            // we need to clear the 3rd byte, according to dyn_reg.h::435
            uint reg_indx = oidst->reg_index ;
            reg_indx &= (0xFFFFF0FF) ;
            RegValue rv ;
            rv.size = 8 ;
            rv.indx = reg_indx ;
            rv.bsym = false ;
            rv.u64 = 0 ;
            vm->writeRegister (rv) ;
        }
    }

    if(oisrc->symb) {
        // Do reading
        res = oisrc->getSymValue (cellList, val) ;
        assert(res);
#ifdef _DEBUG_OUTPUT
        printCellList (cellList) ;
#endif
        printCellList (cellList) ;
        // Do writting
        res = oidst->setSymValue(vm, cellList, val);
        if (!res) {
            printf ("%s:\t %d, return false.\n", __FILE__, __LINE__) ;
            return res ;
        }
        assert(res);
    } else {
#ifndef _SYM_ADDR
        //comenting this to avoid asertion 
        assert(dest_is_sym) ;
#endif
        // Do reading
        res = oisrc->getConValue(val);
        assert(res);
        // Do writting
        res = oidst->setConValue(vm, val);
        assert(res);
    }

    return true;
}

bool SymExecutor::process_add(VMState *vm, InstrInfoPtr &infoptr) {
    // Process addition
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    bool res;

    KVExprPtr oe ;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);

        res = oisrc2->getSymValue(e2);
        assert(res);
        
        // Generate new expression
        oe.reset(new AddExpr(e1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);

        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);

        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        oe.reset(new AddExpr(e1, c2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);

        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));
        oe.reset(new AddExpr(c1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }

    vm->SaveFlagChangingInstructionExpr(e_add, oe) ;
    return true ;
}

bool SymExecutor::process_xadd(VMState *vm, InstrInfoPtr &infoptr) {
    // operation
    // SUM := SRC + DEST;
    // SRC := DEST;
    // DEST := SUM;

    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    OprndInfoPtr &oisrc = oisrc2;
    bool res;

    KVExprPtr oe ;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1); //dst
        assert(res);
        res = oisrc2->getSymValue(e2); //src
        assert(res);

        // Generate new expression for SUM
        oe.reset(new AddExpr(e1, e2));

        //SRC=DEST
        res = oisrc->setSymValue(vm,e1);
        assert(res);
        //DEST=SUM
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1); //dst
        assert(res);

        long v2;
        res = oisrc2->getConValue(v2); //src
        assert(res);
        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        oe.reset(new AddExpr(e1, c2));

        //SRC=DEST
        res = oisrc->setSymValue(vm,e1);
        assert(res);
        //DEST=SUM
        res = oidst->setSymValue(vm, oe);
        assert(res);
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2); //src
        assert(res);

        long v1;
        res = oisrc1->getConValue(v1); //dst
        assert(res);

        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));
        oe.reset(new AddExpr(c1, e2));

        //SRC=DEST
        res = oisrc->setConValue(vm, v1);
        assert(res);
        //DEST=SUM
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }
    vm->SaveFlagChangingInstructionExpr(e_add, oe) ;
    return true ;
}

bool SymExecutor::process_test(VMState *vm, InstrInfoPtr &infoptr) {
    
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    bool res;

    KVExprPtr oe = NULL ;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getSymValue(e2);
        assert(res);

        // Generate new expression
        oe.reset(new AndExpr(e1, e2));

    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);

        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);

        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        oe.reset(new AndExpr(e1, c2));
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);

        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));
        oe.reset(new AndExpr(c1, e2));
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }
    vm->SaveFlagChangingInstructionExpr(e_test, oe) ;
    return true;   
}

bool SymExecutor::process_cmovxx(VMState *vm, InstrInfoPtr &infoptr) {
    // Process conditional move instruction
    bool domov = true ;

    auto &I = infoptr->PI;

    if (domov){
        auto &vecOI = infoptr->vecOI;
        OprndInfoPtr &oidst = vecOI[0];
        OprndInfoPtr &oisrc = vecOI[1];
        KVExprPtr e;
        bool res;
        long val;

        if(oisrc->symb) {
            // Do reading
            res = oisrc->getSymValue(e);
            assert(res);
            // Do writting
            res = oidst->setSymValue(vm, e);
            assert(res);
        } else {
            // Do reading
            res = oisrc->getConValue(val);
            assert(res);
            // Do writting
            res = oidst->setConValue(vm, val);
            assert(res);
        }
    }

    return true;
}

bool SymExecutor::process_jxx(VMState *vm, InstrInfoPtr &infoptr) {

    std::cout << "jump instructions: JMP/Jcc" << "\n" ;
    assert(0) ;
    return true;
}

bool SymExecutor::process_cmp(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL;
    bool res;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getSymValue(e2);
        assert(res);

        e1->print();
        std::cout << std::endl;
        e2->print();
        std::cout << std::endl;

        // Generate new expression
        oe.reset(new SubExpr(e1, e2));

    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);

        std::cout << std::endl;

        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);

        v2 = signext_to_long(oisrc2->size, v2) ;
        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0)); 

        oe.reset(new SubExpr(e1, c2));
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);
        e2->print();
        std::cout << std::endl;

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);
        ExprPtr c1(new ConstExpr(v1,oisrc2->size, 0));
        oe.reset(new SubExpr(c1, e2));
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }
    res = vm->SaveFlagChangingInstructionExpr(e_cmp, oe) ;
    assert (res) ;
    return true;   
}

bool SymExecutor::process_dec(VMState *vm, InstrInfoPtr &infoptr) {
    // Process dec
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL;
    bool res;

    if (oisrc1->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);

        long v2 = 1;
        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        oe.reset(new SubExpr(e1, c2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    }
    else {
        ERRR_ME("operand is not symbolic, why sent here ?");
        assert(0);
    }

    res = vm->SaveFlagChangingInstructionExpr(e_dec, oe) ;
    assert (res) ;
    return true ;
}

bool SymExecutor::process_bswap(VMState *vm, InstrInfoPtr &infoptr) {
    // Process bswap
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL;
    bool res;

    std::vector<int> sizes ;
    std::vector<int> offsets ;
    std::vector<ExprPtr> exprs ;

    if (oisrc1->symb) {
        KVExprPtr ee(nullptr);
        KVExprPtr e1(nullptr),e2(nullptr),e3(nullptr),e4(nullptr) ;
        KVExprPtr e5(nullptr),e6(nullptr),e7(nullptr),e8(nullptr) ;
        res = oisrc1->getSymValue(ee);
        assert(res);

        switch (oisrc1->size) {
            case 4: {
                    e1.reset(new ExtractExpr(ee, 0, 1, 1, 0));
                    e2.reset(new ExtractExpr(ee, 1, 2, 1, 0));
                    e3.reset(new ExtractExpr(ee, 2, 3, 1, 0));
                    e4.reset(new ExtractExpr(ee, 3, 4, 1, 0));
                    exprs.push_back(e4);
                    exprs.push_back(e3);
                    exprs.push_back(e2);
                    exprs.push_back(e1);
                    offsets.push_back(0);
                    offsets.push_back(1);
                    offsets.push_back(2);
                    offsets.push_back(3);
                    sizes.push_back(1);
                    sizes.push_back(1);
                    sizes.push_back(1);
                    sizes.push_back(1);

                    oe.reset(new CombineMultiExpr(exprs, offsets, sizes, 4, 0));
            } break;
            case 8: {
                    e1.reset(new ExtractExpr(ee, 0, 1, 1, 0));
                    e2.reset(new ExtractExpr(ee, 1, 2, 1, 0));
                    e3.reset(new ExtractExpr(ee, 2, 3, 1, 0));
                    e4.reset(new ExtractExpr(ee, 3, 4, 1, 0));
                    
                    e5.reset(new ExtractExpr(ee, 4, 5, 1, 0));
                    e6.reset(new ExtractExpr(ee, 5, 6, 1, 0));
                    e7.reset(new ExtractExpr(ee, 6, 7, 1, 0));
                    e8.reset(new ExtractExpr(ee, 7, 8, 1, 0));
                    
                    exprs.push_back(e8);
                    exprs.push_back(e7);
                    exprs.push_back(e6);
                    exprs.push_back(e5);

                    exprs.push_back(e4);
                    exprs.push_back(e3);
                    exprs.push_back(e2);
                    exprs.push_back(e1);
                    
                    offsets.push_back(0);
                    offsets.push_back(1);
                    offsets.push_back(2);
                    offsets.push_back(3);
                    
                    offsets.push_back(4);
                    offsets.push_back(5);
                    offsets.push_back(6);
                    offsets.push_back(7);
                    
                    sizes.push_back(1);
                    sizes.push_back(1);
                    sizes.push_back(1);
                    sizes.push_back(1);

                    sizes.push_back(1);
                    sizes.push_back(1);
                    sizes.push_back(1);
                    sizes.push_back(1);
            } break;
            default: {
                std::cout << "unsupported operand size for bswap" << std::endl;
                assert(0);
            } break;
        }
    }
    else {
        std::cout << "if not a symbol, why send here ?" << std::endl;
        assert(0);
    }
    return true ;
}

bool SymExecutor::process_sub(VMState *vm, InstrInfoPtr &infoptr) {
    // Process sub
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL;
    bool res;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getSymValue(e2);
        assert(res);

        // Generate new expression
        oe.reset(new SubExpr(e1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);

        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);

        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        oe.reset(new SubExpr(e1, c2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);

        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));
        oe.reset(new SubExpr(c1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }
    res = vm->SaveFlagChangingInstructionExpr(e_sub, oe) ;
    assert (res) ;
    return true ;

}

bool SymExecutor::process_sbb(VMState *vm, InstrInfoPtr &infoptr) {
    //std::cout <<"at process_sbb\n";

    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0]; //dest
    OprndInfoPtr &oisrc2 = vecOI[1]; //src
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL;
    bool res;

    FLAG_STAT cf_bit;
    vm->getFlagBit(x86_64::cf, cf_bit);

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr), e0(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);

        //add CF to dest first
        if(cf_bit){
            res = oisrc1->getSymValue(e0);
            assert(res);
            ExprPtr cf(new ConstExpr(1, oisrc1->size, 0));
            e1.reset(new AddExpr(e0, cf, oisrc1->size, 0));
        }
        else
        {
            res = oisrc1->getSymValue(e1);
            assert(res);
        }

        // Generate new expression
        oe.reset(new SubExpr(e1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr), e0(nullptr);

        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);
        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));

        //add CF to dest first
        if(cf_bit){
            res = oisrc1->getSymValue(e0);
            assert(res);
            ExprPtr cf(new ConstExpr(1, oisrc1->size, 0));
            e1.reset(new AddExpr(e0, cf, oisrc1->size, 0));
        }
        else
        {
            res = oisrc1->getSymValue(e1);
            assert(res);
        }

        oe.reset(new SubExpr(e1, c2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);
        if(cf_bit)
            v1 += 1;
        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));

        oe.reset(new SubExpr(c1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } 
    else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }
    res = vm->SaveFlagChangingInstructionExpr(e_sbb, oe) ;
    assert (res) ;
    return true ;
}

bool SymExecutor::process_and(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL ;
    bool res;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getSymValue(e2);
        assert(res);

        // Generate new expression
        oe.reset(new AndExpr(e1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        
        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);

        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        
        oe.reset(new AndExpr(e1, c2));

        res = oidst->setSymValue(vm, oe);
        assert(res);
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);

        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));

        oe.reset(new AndExpr(c1, e2));
        
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }
    res = vm->SaveFlagChangingInstructionExpr(e_and, oe) ;
    assert (res) ;

    return true;   
}
bool SymExecutor::process_or(VMState *vm, InstrInfoPtr &infoptr) {
    
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL ;
    bool res;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getSymValue(e2);
        assert(res);

        // Generate new expression
        oe.reset(new OrExpr(e1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);

        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);

        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        oe.reset(new OrExpr(e1, c2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);

        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));
        oe.reset(new OrExpr(c1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }

    res = vm->SaveFlagChangingInstructionExpr(e_or, oe) ;
    assert (res) ;
    return true;   
}

bool SymExecutor::process_xor(VMState *vm, InstrInfoPtr &infoptr) {
    
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL ;
    bool res;
    
//handling the case of writig to a size 4 register and the need to clear the uper 4 bytes of the corresponding 8 byte reg
    if (oidst->size == 4)  {
        if ((oidst->opty & OPTY_REG) == OPTY_REG) {
            // we need to clear the 3rd byte, according to dyn_reg.h::435
            uint reg_indx = oidst->reg_index ;
            reg_indx &= (0xFFFFF0FF) ;
            RegValue rv ;
            rv.size = 8 ;
            rv.indx = reg_indx ;
            rv.bsym = false ;
            rv.u64 = 0 ;
            vm->writeRegister (rv) ;
        }
    }

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getSymValue(e2);
        assert(res);
        e1->print();
        std::cout << std::endl;
        e2->print();
        std::cout << std::endl;

        // Generate new expression
        oe.reset(new XorExpr(e1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        e1->print();
        std::cout << std::endl;

        long v2;
        res = oisrc2->getConValue(v2);
        assert(res);

        ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
        oe.reset(new XorExpr(e1, c2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    }

    else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        res = oisrc2->getSymValue(e2);
        assert(res);
        e2->print();
        std::cout << std::endl;

        long v1;
        res = oisrc1->getConValue(v1);
        assert(res);

        ExprPtr c1(new ConstExpr(v1, oisrc2->size, 0));
        oe.reset(new XorExpr(c1, e2));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }

    res = vm->SaveFlagChangingInstructionExpr(e_xor, oe) ;
    assert (res) ;

    return true;   
}

bool SymExecutor::process_shl_sal(VMState *vm, InstrInfoPtr &infoptr) {
    
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    bool res;

    if ((!oisrc1->symb) || (oisrc2->symb)) {
        printf ("%s:\t %d, return false.\n", __FILE__, __LINE__) ;
        return false ;
    }
    

    assert (oisrc1->symb) ;
    assert (!oisrc2->symb) ;

    KVExprPtr e1(nullptr);
    res = oisrc1->getSymValue(e1);
    assert(res);

    long v2;
    res = oisrc2->getConValue(v2);
    assert(res);

    ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
    KVExprPtr oe(new Shl_SalExpr(e1, c2));
    res = oidst->setSymValue(vm, oe);

    assert(res);
    
    res = vm->SaveFlagChangingInstructionExpr(e_shl_sal, oe) ;
    assert (res) ;
    return true;   
}

bool SymExecutor::process_shr(VMState *vm, InstrInfoPtr &infoptr) {
    
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    bool res;

    assert (oisrc1->symb) ;
    assert (!oisrc2->symb) ;

    KVExprPtr e1(nullptr);
    res = oisrc1->getSymValue(e1);
    assert(res);

    long v2;

    res = oisrc2->getConValue(v2);
    assert(res);
    ExprPtr c2(new ConstExpr(v2, oisrc1->size, 0));
    KVExprPtr oe(new ShrExpr(e1, c2));
    res = oidst->setSymValue(vm, oe);
    assert(res);

    res = vm->SaveFlagChangingInstructionExpr(e_shr, oe) ;
    assert (res) ;

    return true;   
}

bool SymExecutor::process_sar(VMState *vm, InstrInfoPtr &infoptr) {
    
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    OprndInfoPtr &oidst = oisrc1;
    bool res;

    assert (oisrc1->symb) ;
    assert (!oisrc2->symb) ;

    KVExprPtr e1(nullptr);
    res = oisrc1->getSymValue(e1);
    assert(res);

    long v2;
    res = oisrc1->getConValue(v2);
    assert(res);
    ExprPtr c2(new ConstExpr(v2, oisrc2->size, 0));
    KVExprPtr oe(new SarExpr(e1, c2));
    res = oidst->setSymValue(vm, oe);
    assert(res);

    res = vm->SaveFlagChangingInstructionExpr(e_sar, oe) ;
    assert (res) ;
    return true;   
}

bool SymExecutor::process_div(VMState *vm, InstrInfoPtr &infoptr) {
    // Process addition
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &o_d = vecOI[0]; 
    OprndInfoPtr &o_a = vecOI[1];
    OprndInfoPtr &o_Divisor = vecOI[2];
    bool res;
    KVExprPtr e(nullptr);
    KVExprPtr e_a(nullptr), e_d(nullptr), e_Dividend(nullptr), e_Divisor(nullptr);
    KVExprPtr e_quotient(nullptr), e_remainder(nullptr);
    long v_a, v_d, v_Dividend, v_Divisor ;

    if (o_d->symb || o_a->symb) {
        if(o_d->symb) {
            res = o_d->getSymValue(e_d) ;
            assert (res) ;
        }
        else {
            res = o_d->getConValue(v_d) ;
            assert (res) ;
            e_d.reset(new ConstExpr(v_d, o_d->size, 0)) ;
        }
         if(o_a->symb) {
            res = o_a->getSymValue(e_a) ;
            assert (res) ;
         }
        else {
            res = o_a->getConValue(v_a) ;
            assert (res) ;
            e_a.reset(new ConstExpr(v_a, o_a->size, 0)) ;
        }
    } else {
        // dx:ax both not symbol, we may need a 128bits int.
        res = o_d->getConValue(v_d) ;
        assert (res) ;
        e_d.reset(new ConstExpr(v_d, o_d->size, 0)) ;
        
        res = o_a->getConValue(v_a) ;
        assert (res) ;
        e_a.reset(new ConstExpr(v_a, o_a->size, 0)) ;
    }

    e_Dividend.reset(new CombineExpr(e_d, e_a, o_d->size, o_a->size, o_d->size + o_a->size, 0)) ;

    if (o_Divisor->symb) {
        res = o_Divisor->getSymValue(e_Divisor) ;
        e_Divisor.reset(new ZeroExtExpr(e_Divisor, o_d->size + o_a->size, 0)); //without just force setting the size using setExprSize(), lets zero extend as it makes sense for unsigned divisor
        assert (res) ;
    } else {
        res = o_Divisor->getConValue(v_Divisor) ;
        assert (res) ;
        e_Divisor.reset(new ConstExpr(v_Divisor, o_d->size + o_a->size, 0)) ; //size of the divident is 2*divisor, hnce using the dividend size here instead of the divisor's
    }

    KVExprPtr e_Quotient(new DivExpr(e_Dividend, e_Divisor, o_d->size + o_a->size, 0));  //using the actual size of e_Dividend at this point of time
    KVExprPtr e_Remainder(new RemExpr(e_Dividend, e_Divisor, o_d->size + o_a->size, 0));  //using the actual size of e_Dividend at this point of time

    e_quotient.reset(new ExtractExpr(e_Quotient, 0, o_a->size, o_a->size, 0)) ;   //bringing down the expression size to match that of the register length storing the quotient
    e_remainder.reset(new ExtractExpr(e_Remainder, 0, o_d->size, o_d->size, 0)) ; //bringing down the expression size to match that of the register length storing the remainder

    res = o_a->setSymValue(vm, e_quotient) ;
    assert (res) ;
    res = o_d->setSymValue(vm, e_remainder) ;
    assert (res) ;
    //no flag update as the effect of this ins on flags is undefined as per intel manual
    return true ;
}

bool SymExecutor::process_idiv(VMState *vm, InstrInfoPtr &infoptr) {
    // Process addition
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &o_d = vecOI[0]; 
    OprndInfoPtr &o_a = vecOI[1];
    OprndInfoPtr &o_Divisor = vecOI[2];
    bool res;
    KVExprPtr e(nullptr);
    KVExprPtr e_a(nullptr), e_d(nullptr), e_Dividend(nullptr), e_Divisor(nullptr);
    long v_a, v_d, v_Dividend, v_Divisor ;

    if (o_d->symb || o_a->symb) {
        if(o_d->symb) {
            res = o_d->getSymValue(e_d) ;
            assert (res) ;
        }
        else {
            res = o_d->getConValue(v_d) ;
            assert (res) ;
            e_d.reset(new ConstExpr(v_d, o_d->size, 0)) ;
        }
         if(o_a->symb) {
            res = o_a->getSymValue(e_a) ;
            assert (res) ;
         }
        else {
            res = o_a->getConValue(v_a) ;
            assert (res) ;
            e_a.reset(new ConstExpr(v_a, o_a->size, 0)) ;
        }
    } else {
        // dx:ax both not symbol, we may need a 128bits int.
        res = o_d->getConValue(v_d) ;
        assert (res) ;
        e_d.reset(new ConstExpr(v_d, o_d->size, 0)) ;
        
        res = o_a->getConValue(v_a) ;
        assert (res) ;
        e_a.reset(new ConstExpr(v_a, o_a->size, 0)) ;
    }

    e_Dividend.reset(new CombineExpr(e_d, e_a, o_d->size, o_a->size, o_d->size + o_a->size, 0)) ;

    if (o_Divisor->symb) {
        res = o_Divisor->getSymValue(e_Divisor) ;
        assert (res) ;
        e_Divisor.reset(new SignExtExpr(e_Divisor, o_d->size + o_a->size, 0)); //without just force setting the size using setExprSize(), lets zero extend as it makes sense for unsigned divisor
    } else {
        res = o_Divisor->getConValue(v_Divisor) ;
        assert (res) ;
        e_Divisor.reset(new ConstExpr(v_Divisor, o_Divisor->size, 0)) ;
    }

    KVExprPtr e_Quotient(new iDivExpr(e_Dividend, e_Divisor, o_d->size + o_a->size, 0));  //using the actual size of e_Dividend at this point of time
    KVExprPtr e_Remainder(new iRemExpr(e_Dividend, e_Divisor, o_d->size + o_a->size, 0));  //using the actual size of e_Dividend at this point of time
    KVExprPtr e_quotient(nullptr), e_remainder(nullptr);
    e_quotient.reset(new ExtractExpr(e_Quotient, 0, o_a->size, o_a->size, 0)) ;   //bringing down the expression size to match that of the register length storing the quotient
    e_remainder.reset(new ExtractExpr(e_Remainder, 0, o_d->size, o_d->size, 0)) ; //bringing down the expression size to match that of the register length storing the remainder

    res = o_a->setSymValue(vm, e_quotient) ;
    assert (res) ;
    res = o_d->setSymValue(vm, e_remainder) ;
    assert (res) ;
    //no flag update as the effect of this ins on flags is undefined as per intel manual
    return true ;
}
__uint128_t SignedTOUnsigned (long v, int size) {
    switch (size) {
        case 1:
            return (__uint128_t)(uint8_t)(v) ;
        case 2:
            return (__uint128_t)(uint16_t)(v) ;
        case 4:
            return (__uint128_t)(uint32_t)(v) ;
        case 8:
            return (__uint128_t)(uint64_t)(v) ;
        default :
            assert (0) ;
    }
}
bool SymExecutor::process_mul(VMState *vm, InstrInfoPtr &infoptr) {
    // Process addition
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &o_d = vecOI[0];        // dx
    OprndInfoPtr &o_a = vecOI[1];        // ax
    OprndInfoPtr &o_m = vecOI[2];        // oper
    KVExprPtr e_d, e_a, e_m ;
    long v_d, v_a, v_m ;
    bool res;
    __uint128_t v_r=0, u_a, u_m ;

    if(o_a->symb) {
        o_a->getSymValue(e_a) ;
        assert (res) ;
    }
    else {
        res = o_a->getConValue(v_a) ;
        assert (res) ;
        e_a.reset(new ConstExpr(v_a, o_a->size, 0)) ;
    }
    if(o_m->symb) {
        res = o_m->getSymValue(e_m) ;
        assert (res) ;
    }
    else {
        o_m->getConValue(v_m) ;
        assert (res) ;
        e_m.reset(new ConstExpr(v_m, o_m->size, 0)) ;
    }

    if(!o_a->symb && !o_m->symb) {
        auto &I = infoptr->PI;    
        entryID id = I->getOperation().getID() ;
        
        if (id == e_mul) {
            u_a = SignedTOUnsigned (v_a, o_a->size) ;
            u_m = SignedTOUnsigned (v_m, o_m->size) ;
            v_r = u_a * u_m ;
        } else {
            v_r = v_a * v_m ;
        }
        uint64_t vrl = (uint64_t)(v_r & ((((__uint128_t)1)<<o_a->size*8)-1)) ;
        uint64_t vrh = (uint64_t)((v_r>>(o_d->size*8)) & ((((__uint128_t)1)<<o_d->size*8)-1)) ;
        res = o_a->setConValue(vm, vrl) ;
        assert (res) ;
        res = o_d->setConValue(vm, vrh) ;
        assert (res) ;

        return true ;
    }

    KVExprPtr e_r(new MulExpr(e_a, e_m, o_m->size, 0)) ;
    e_a.reset(new ExtractExpr(e_r, 0, o_a->size, o_a->size, 0)) ;
    e_d.reset(new ExtractExpr(e_r, o_a->size, o_a->size*2, o_a->size, 0)) ;
    
    res = o_a->setSymValue(vm, e_a) ;
    assert (res) ;
    res = o_d->setSymValue(vm, e_d) ;
    assert (res) ;

    return true ;
}

bool SymExecutor::process_not(VMState *vm, InstrInfoPtr &infoptr) {
    // Process addition
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oidst = oisrc1;
    KVExprPtr oe = NULL ;
    bool res;

    if (oisrc1->symb) {
        KVExprPtr e1(nullptr) ;
        res = oisrc1->getSymValue(e1);
        assert(res);
        // Generate new expression
        oe.reset(new NotExpr(e1));
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }

    return true ;
}

bool SymExecutor::process_neg(VMState *vm, InstrInfoPtr &infoptr) {
    // Process addition
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oidst = oisrc1;
    bool res;

    assert (oisrc1->symb) ;

    KVExprPtr e1(nullptr) ;
    res = oisrc1->getSymValue(e1);
    assert(res);
    // Generate new expression
    KVExprPtr oe(new NegExpr(e1));
    res = oidst->setSymValue(vm, oe);
    assert (res) ;

    res = vm->SaveFlagChangingInstructionExpr(e_neg, oe) ;
    
    assert(res);
    return true ;
}

bool SymExecutor::process_pop(VMState *vm, InstrInfoPtr &infoptr) {
    Instruction *in = new Instruction(*infoptr->PI);
    InstrInfo *ioi = new InstrInfo(in);

    parseOperands(vm, ioi, true);

    auto &vecOI = ioi->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];   // rsp
    bool res;
    RegValue V ;
     
    assert(!oisrc2->symb) ;

    V.indx = oisrc2->reg_index;
    V.size = oisrc2->size ;
    V.isSymList = false ;

    res = vm->readRegister(V);
    assert (res) ;
    assert (V.size==8) ;

    MemValue MV;
    MV.addr = V.u64 ;
    MV.size = oisrc1->size ;
    MV.isSymList = true;
    res = vm->readMemory(MV) ;
    assert(res) ;

    if(MV.bsym) {
        res = oisrc1->setSymValue(vm, MV.symcellPtr, MV.i64) ;
    }
    else {
        res = oisrc1->setConValue(vm, MV.u64) ;
#ifdef _DEBUG_OUTPUT
        std::cout << std::hex << "0x" << MV.u64 << std::endl ;
#endif
    }

    assert(res) ;
    
    V.u64 += V.size ;
    res = vm->writeRegister(V);
    assert(res) ;

    return true;
}

bool SymExecutor::process_push(VMState *vm, InstrInfoPtr &infoptr) {
    Instruction *in = new Instruction(*infoptr->PI);
    InstrInfo *ioi = new InstrInfo(in);

    parseOperands(vm, ioi, true);

    auto &vecOI = ioi->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];    // rsp 
    bool res;
    RegValue V ;
     
    assert(!oisrc2->symb) ;

    V.indx = oisrc2->reg_index;
    V.size = oisrc2->size ;
    V.isSymList = false ;

    res = vm->readRegister(V);
    assert(res) ;

    assert (V.size==8) ;
    V.u64 -= V.size ;
    res = vm->writeRegister(V);
    assert(res) ;

    MemValue MV;
    MV.addr = V.u64 ;
    MV.size = oisrc1->size ;
    MV.isSymList = false ;

    SymCellPtr cellList ;
    long v ;
    if(oisrc1->symb) {
        res = oisrc1->getSymValue(cellList, v);
        assert(res) ;

        MV.bsym = true ;
        MV.symcellPtr = cellList ;
        MV.isSymList = true ;
        MV.i64 = (uint64_t) v ;
    } else {
        long v ;
        res = oisrc1->getConValue(v);
        assert(res) ;
        MV.bsym = false ;
        MV.i64 = v ;
        MV.isSymList = false ;
    }

    res = vm->writeMemory(MV) ;
    assert(res) ;

    return true;
}


bool SymExecutor::process_xchg(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc1 = vecOI[0];
    OprndInfoPtr &oisrc2 = vecOI[1];
    bool res;

    if (oisrc1->symb && oisrc2->symb) {
        KVExprPtr e1(nullptr), e2(nullptr);
        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getSymValue(e2);
        assert(res);

        res = oisrc1->setSymValue(vm, e2);
        assert(res);
        res = oisrc2->setSymValue(vm, e1);
        assert(res);

    } else if (oisrc1->symb && !oisrc2->symb) {
        KVExprPtr e1(nullptr);
        long v2;

        res = oisrc1->getSymValue(e1);
        assert(res);
        res = oisrc2->getConValue(v2);
        assert(res);

        res = oisrc1->setConValue(vm, v2);
        assert(res);
        res = oisrc2->setSymValue(vm, e1);
        assert(res);

    } else if (!oisrc1->symb && oisrc2->symb) {
        KVExprPtr e2(nullptr);
        long v1;
 
        res = oisrc2->getSymValue(e2);
        assert(res);
        res = oisrc1->getConValue(v1);
        assert(res);
 
        res = oisrc1->setSymValue(vm, e2);
        assert(res);
        res = oisrc2->setConValue(vm, v1);
        assert(res);
    } else {
        ERRR_ME("Unexpected operands");
        assert(0);
    }
    return true;
}

bool SymExecutor::process_movsx(VMState *vm, InstrInfoPtr &infoptr) {
    // Process move instruction
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    bool res;

//We need to handle  mov %r11d, %r10d case here ????????????????????????????????????

    if(oisrc->symb) {
        KVExprPtr e;
        // Do reading
        res = oisrc->getSymValue(e);
        assert(res);

        KVExprPtr oe(new SignExtExpr(e, oidst->size, 0));

        // Do writting
        res = oidst->setSymValue(vm, oe);
        assert(res);
    } else {
        long val;
        assert  (oidst->symb) ;
        // Do reading
        res = oisrc->getConValue(val);
        assert(res);

        // Do writting
        res = oidst->setConValue(vm, val);
        assert(res);
    }

    return true;
}

bool SymExecutor::process_movzx(VMState *vm, InstrInfoPtr &infoptr) {
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    OprndInfoPtr &oisrc = vecOI[1];
    bool res;

    //mov %r11d, %r10d; 
    bool dest_is_sym = oidst->symb ;

    if (oidst->size == 4)  {
        if ((oidst->opty & OPTY_REG) == OPTY_REG) {
            // we need to clear the 3rd byte, according to dyn_reg.h::435
            uint reg_indx = oidst->reg_index ;
            reg_indx &= (0xFFFFF0FF) ;
            RegValue rv ;
            rv.size = 8 ;
            rv.indx = reg_indx ;
            rv.bsym = false ;
            rv.u64 = 0 ;
            vm->writeRegister (rv) ;
        }
    }

    if(oisrc->symb) {
        KVExprPtr e(nullptr);
        // Do reading
        res = oisrc->getSymValue(e);
        assert(res);

        KVExprPtr oe(new ZeroExtExpr(e, oidst->size, 0));

        // Do writting
        res = oidst->setSymValue(vm, oe);
        assert(res);
        
    } else {
        long val;

#ifndef _SYM_ADDR
        assert  (dest_is_sym) ;
#endif
        // Do reading
        res = oisrc->getConValue(val);
        assert(res);
        //std::cout << "con val : " << val << std::endl;
        // Do writting
        res = oidst->setConValue(vm, val);
        assert(res);
    }

    return true;
}

bool SymExecutor::process_cbw(VMState *vm, InstrInfoPtr &infoptr) {
    // eax sign extend to rax like
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oisrc = vecOI[0];
    KVExprPtr e, oe ;
    RegValue rv, rvdest ;
    bool res ;    

    assert (oisrc->symb) ;
    res = oisrc->getSymValue(e) ;
    assert (res) ;
    rv.isSymList = false ;
    
    switch (oisrc->size) {
        case 2:
            rv.indx = x86_64::al ;
            rv.size = 1 ;
            break ;
        case 4:
            rv.indx = x86_64::ax ;
            rv.size = 2 ;
            break ;
        case 8:
            rv.indx = x86_64::eax ;
            rv.size = 4 ;
            break ;
        default :
        // ?
            assert (0) ;
    }
    res = vm->readRegister(rv) ;
    assert (res) ;

    if(rv.bsym)
    {
        oe.reset(new SignExtExpr(e, oisrc->size, 0)) ;
        res = oisrc->setSymValue(vm, oe) ;
        assert (res) ;
    }
    else
    {         
        rvdest.bsym = false ;
        rvdest.isSymList = false;
        rvdest.size = oisrc->size;

        switch (oisrc->size) {
        case 2:
            rvdest.indx = x86_64::ax ;
            rvdest.i16 = (rv.i8 & 0x80) ? (0xff00 | rv.i8) : rv.i8;
            break ;
        case 4:
            rvdest.indx = x86_64::eax ;
            rvdest.i32 = (rv.i16 & 0x8000) ? (0xffff0000 | rv.i16) : rv.i16;
            break ;
        case 8:
            rvdest.indx = x86_64::rax ;
            rvdest.i64 = (rv.i32 & 0x80000000) ? (0xffffffff00000000 | rv.i32) : rv.i32;
            break ;
        default :
            assert (0) ;
        }
        res = vm->writeRegister(rvdest);
        assert(res);
    }

    return true;
}

bool SymExecutor::process_cdq(VMState *vm, InstrInfoPtr &infoptr) {
    // eax sign extend to edx::eax like
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &o_d = vecOI[0];       // dx
    OprndInfoPtr &o_a = vecOI[1];       // ax
    KVExprPtr e_a, e_r, e_d;
    RegValue rv_d ;
    long v_a;
    bool res;

    if (o_a->symb) {
        res = o_a->getSymValue (e_a) ;
        assert (res) ;
        e_r.reset (new SignExtExpr(e_a, o_a->size*2, 0)) ;
        e_d.reset (new ExtractExpr(e_r, o_a->size, o_a->size*2, o_d->size, 0)) ;

        res = o_d->setSymValue(vm, e_d) ;
        assert (res) ;
        return true ;
    } else {
        res = o_a->getConValue (v_a) ;
        assert (res) ;
        if (v_a>=0) 
            v_a = 0 ;
        else
            v_a = -1 ;
        res = o_d->setConValue(vm, v_a) ;
        assert (res) ;
        return true ;
    }
    return true;
}
bool SymExecutor::process_set(VMState *vm, InstrInfoPtr &infoptr) {
    
    auto &vecOI = infoptr->vecOI;
    OprndInfoPtr &oidst = vecOI[0];
    long v = 1 ;
    bool res ;

    res = oidst->setConValue(vm, v) ;
    assert (res) ;
    
    return true ;
}

bool SymExecutor::process_shrd(VMState *vm, InstrInfoPtr &infoptr) {
    assert (0) ;
    return true ;
}

bool SymExecutor::Print_Inst(VMState *vm, InstrInfoPtr &infoptr, const char* cstr) {
    auto &vecOI = infoptr->vecOI ;
    int i = 0;
    DAPIInstrPtr &I = infoptr->PI;    

    std::cout << cstr << I->format() << std::endl ;
#if 0
    for(i=0; i<vecOI.size(); i++) {
        OprndInfoPtr &o=vecOI[i] ;
        KVExprPtr e ;
        long v ;
        if(o->symb) {
            o->getSymValue (e) ;
            e->print() ;
            std::cout << "," ;
        } else {
            if((o->rdwr & OPAC_RD) != 0){
                o->getConValue(v) ;
                std::cout << std::hex << v << ", " ;
            } else {
                std::cout << "----, " ;
            }
        }
    }
#endif
    std::cout << endl ;
    return true ;   
}

ulong SymExecutor::isUseGS(VMState* vm, DAPIInstrPtr& I)
{
    /* check if Insn uses gs as base in mem access, if yes, get gsbase first */
    std::set<RegisterAST::Ptr> regrd = I.get()->getOperation().implicitReads();
    if (regrd.size() != 0)
    {
        for (auto it : regrd)
        {
            if (it->getID() == x86_64::gs)
            {
                RegValue RV{(uint)it->getID(), 8};
                bool ret = vm->readRegister(RV);
                assert(ret);
                return RV.u64;
            }
        }
    }
    return 0;
}

bool SymExecutor::calculateBinaryFunction (BinaryFunction* bf, KVExprPtr &exprPtr, VMState* vm) {

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
            res = vm->readRegister(RV);
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
            calculateBinaryFunction(binF, eptr, vm) ;
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

bool SymExecutor::_parseOperand_XX(VMState *vm, DAPIInstrPtr& I, OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_RD;

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            // Read immediate operand:
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
            assert(rdwrRegs.size() == 1);
            auto R = *rdwrRegs.begin();
            oi->reg_index = R->getID();

            RegValue RV{oi->reg_index, (uint)R->size()};
            RV.isSymList = true;
            res = vm->readRegister(RV);
            assert(res);
            if (RV.bsym) {
                oi->opty = OPTY_REGSYM;
                oi->symb = true;
                oi->isSymList = true;
                auto V = O->getValue();
                std::vector<Expression::Ptr> exps;
                V->getChildren(exps);
                if (exps.size() > 1) {
                    FIX_ME();  // Add up child expresses
                } else {
                    oi->conVal = RV.i64;//is it okay if this read is eax, ax, etc?
                    oi->symList = RV.symcellPtr;
                    oi->isSymList = true ;
                }
            } else {
                oi->opty = OPTY_REGCON;
                auto RS = O->getValue()->eval();
                assert(RS.defined);
                oi->reg_conval = RS.convert<ulong>();
            }
            return true;
        }
    } else if (O->isWritten()) {
        // Write into a register oprand:
        // eg2: mov 0xffffffe8(%rbp),%rax -> %rax
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_WR;

        // Should be a register operand
        O->getWriteSet(rdwrRegs);
        oi->opty = OPTY_REG;
        assert(rdwrRegs.size() == 1);
        auto R = *rdwrRegs.begin();
        oi->reg_index = R->getID();
        oi->symb = vm->isSYReg(oi->reg_index);
        return true;
    } else {
        ERRR_ME("Unexpected operand");
        exit(EXIT_FAILURE);
        return false;
    }
}

bool SymExecutor::_parseOperand_RX(VMState *vm, DAPIInstrPtr& I, OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        // Read a memory cell:
        // eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_RD;
        oi->opty = OPTY_MEMCELL;

        /* For a mem access insn, if it uses gs, mem access Operand should add gs base */
        // ulong gs_base = isUseGS(I.get()); 
        ulong gs_base = isUseGS(vm, I); 
        
        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {  // Direct memory access
            assert(gs_base != 0);
                    
            std::vector<Expression::Ptr> exps;
            auto V = O->getValue();
            V->getChildren(exps);
            assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

            // Get and eval the address
            auto A = *exps.begin();
            auto RS = A->eval();
            assert(RS.defined);
            oi->mem_conaddr = RS.convert<ulong>() + gs_base;
                
            MemValue MV{oi->mem_conaddr, oi->size};
            MV.isSymList = true;
            res = vm->readMemory(MV);
            assert(res);
            if (MV.bsym) {
                oi->opty = OPTY_MEMCELLSYM;
                oi->symb = true;
                oi->conVal = MV.i64;//is it okay if this read is eax, ax, etc?
                oi->symList = MV.symcellPtr;
                oi->isSymList = true ;
            } else {
                oi->opty = OPTY_MEMCELLCON;
                oi->mem_conval = MV.i64;
            }
        } else {
            // Access with one or more registers
            // eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
            bool bSymbolic;
            bool hasSymReg = false;
            for (auto R : rdwrRegs){
                hasSymReg |= maySymbolicRegister(vm, R.get()->getID());

            }

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
                        calculateBinaryFunction (bf, exprPTR, vm) ;
                        std::cout << "expression: ";
                        exprPTR->print();
                        std::cout << std::endl;
                    }
                    else if(R != nullptr){
                        RegValue RV{(uint)R->getID(), (uint)R->size()};
                        res = vm->readRegister(RV);
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
                    concrete_reg_val = vm->m_EFlagsMgr->ConcretizeExpression(exprPTR);
                    std::cout << "Concretized val : " << std::hex << concrete_reg_val << std::endl;
                    oi->mem_conaddr = (unsigned long)concrete_reg_val;        

                    //read memory
                    MemValue MV{oi->mem_conaddr, oi->size};
                    MV.isSymList = true;
                    res = vm->readMemory(MV);
                    assert(res);
                    if (MV.bsym) {
                        std::cout << "sym-mem\n";
                        oi->opty = OPTY_MEMCELLSYM;
                        oi->symb = true;
                        oi->conVal = MV.i64;
                        oi->symList = MV.symcellPtr;
                        oi->isSymList = true ;
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
                std::cout << "sym mem addr \n Consider enabling _SYM_ADDR to concretize\n";
                assert(0);
            }
            else {
                // Memory access without symbolic register
                std::vector<Expression::Ptr> exps;
                auto V = O->getValue();
                V->getChildren(exps);
                // memory dereference: [xxx] -> xxx
                assert(exps.size() == 1);

                // Get and eval the address
                auto A = *exps.begin();
                auto RS = A->eval();
                assert(RS.defined);
#ifdef _DEBUG_OUTPUT                
                std::cout << "read addr " << std::hex << RS.convert<ulong>() << std::endl;
#endif

                if (gs_base == 0)
                    oi->mem_conaddr = RS.convert<ulong>();
                else
                    oi->mem_conaddr = RS.convert<ulong>() + gs_base;

#ifdef _DEBUG_OUTPUT                
                std::cout << "read addr " << std::hex << oi->mem_conaddr << std::endl;
#endif
                MemValue MV{oi->mem_conaddr, oi->size};
                MV.isSymList = true;
                res = vm->readMemory(MV);
                assert(res);
                if (MV.bsym) {
                    oi->opty = OPTY_MEMCELLSYM;
                    oi->symb = true;
                    oi->conVal = MV.i64;//is it okay if this read is eax, ax, etc?
                    oi->symList = MV.symcellPtr;
                    oi->isSymList = true ;

                } else {
                    oi->opty = OPTY_MEMCELLCON;
                    oi->mem_conval = MV.i64;
                }
                return true;
            }
        }
    } 
    else if (O->isWritten()) {
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

bool SymExecutor::_parseOperand_XW(VMState *vm, DAPIInstrPtr& I, OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        assert(0);
        // Accessing an immeidate value, or reading a register
        oi->rdwr = OPAC_RD;
        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            oi->opty = OPTY_IMM;
            auto RS = O->getValue()->eval();
            oi->imm_value = RS.convert<ulong>();
            return false;
        } else {
            bool bSymbolic;
            // A register operand
            assert(rdwrRegs.size() == 1);
            auto R = *rdwrRegs.begin();
            oi->reg_index = R.get()->getID();
            oi->symb = bSymbolic = maySymbolicRegister(vm, oi->reg_index);

            if (bSymbolic) {
                oi->symb = true;
                oi->reg_symval = NULL;
                cout << "282: Read: " << O->getValue()->format() << "@SYReg"
                     << "\n";
                return true;
            } else {
                cout << "285: Read: " << O->getValue()->format() << "@NMreg"
                     << "\n";
                return false;
            }
        }
    } else if (O->isWritten()) {
        // eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_WR;       // Write into a memory cell
        oi->opty = OPTY_MEMCELL;  // may be refined later

        /* For a mem access insn, if it uses gs, mem access Operand should add gs base */
        ulong gs_base = isUseGS(vm, I); 
        
        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            assert(0);
            // Direct memory access
            std::vector<Expression::Ptr> exps;
            auto V = O->getValue();
            V->getChildren(exps);
            assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

            // Get and eval the address
            auto A = *exps.begin();
            auto RS = A->eval();
            assert(RS.defined);
            oi->symb = false;
            return false;
        } else {
            // Access memory with one or more registers
            // eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
            bool hasSymReg = false;
            for (auto R : rdwrRegs)
                hasSymReg |= maySymbolicRegister(vm, R->getID());

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
                        calculateBinaryFunction (bf, exprPTR, vm) ;
                        std::cout << "expression: ";
                        exprPTR->print();
                        std::cout << std::endl;
                    }
                    else if(R != nullptr){
                        RegValue RV{(uint)R->getID(), (uint)R->size()};
                        res = vm->readRegister(RV);
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
                    concrete_reg_val = vm->m_EFlagsMgr->ConcretizeExpression(exprPTR);
                    std::cout << "Concretized val : " << std::hex << concrete_reg_val << std::endl;
                    oi->mem_conaddr = (unsigned long)concrete_reg_val;        

                    //read memory
                    MemValue MV{oi->mem_conaddr, oi->size};
                    MV.isSymList = true;
                    res = vm->readMemory(MV);
                    assert(res);
                    if (MV.bsym) {
                        std::cout << "sym-mem\n";
                        oi->opty = OPTY_MEMCELLSYM;
                        oi->symb = true;
                        oi->conVal = MV.i64;
                        oi->symList = MV.symcellPtr;
                        oi->isSymList = true ;
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
                std::cout << "sym mem addr detected \n Consider enabling _SYM_ADDR to concretize\n";
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
                oi->symb = true;
                return true;
            }
        }
    } else {
        assert(0);
    }
}

bool SymExecutor::_parseOperand_RW(VMState *vm, DAPIInstrPtr& I, OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;

    oi->rdwr = OPAC_RDWR;
    oi->opty = OPTY_MEMCELL;

    /* For a mem access insn, if it uses gs, mem access Operand should add gs
     * base */
    ulong gs_base = isUseGS(vm, I); 
    
    std::set<RegisterAST::Ptr> rdwrRegs;
    O->getReadSet(rdwrRegs);
    if (rdwrRegs.size() == 0) {
        assert(0);
    } else {
        // Access memory with one or more registers:
        // eg1.add $0x8, 0xfffffff8(%rbp)->0xfffffff8(%rbp)
        bool hasSymReg = false;
        for (auto R : rdwrRegs)
            hasSymReg |= maySymbolicRegister(vm, R->getID());

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

            MemValue MV{oi->mem_conaddr, oi->size};
            MV.isSymList = true;
            res = vm->readMemory(MV);
            assert(res);
            if (MV.bsym) {
                oi->opty = OPTY_MEMCELLSYM;
                oi->symb = true;
                oi->conVal = MV.i64;//is it okay if this read is eax, ax, etc?
                oi->symList = MV.symcellPtr;
                oi->isSymList = true ;
            } else {
                oi->opty = OPTY_MEMCELLCON;
                oi->mem_conval = MV.i64;
            }
            return true;
        }
    }

    return false;
}

bool SymExecutor::parseOperands(VMState *vm, InstrInfo *info, bool isSymList) {
    DAPIInstrPtr &I = info->PI;
    std::vector<OprndInfoPtr> &vecOI = info->vecOI;

    // Set the value of referred regsiters before parsing
    setReadRegs(vm, I);

    bool bUS = false;  // Operands refer to symbolic variable?
    std::vector<Operand> oprands;
    I->getOperands(oprands);
    for (auto O : oprands) {
        OprndInfoPtr oi(new OprndInfo(O));
        oi->size = O.getValue()->size();  // Set the operand size ASAP;
        oi->symb = false;                 // Set to false by default;
        bool res = false;
        if (!O.readsMemory() && !O.writesMemory())
        {
            res = _parseOperand_XX(vm, I, oi);
        } else if (O.readsMemory() && !O.writesMemory()) {
            res = _parseOperand_RX(vm, I, oi);
        } else if (!O.readsMemory() && O.writesMemory()) {
            res = _parseOperand_XW(vm, I, oi);
        } else if (O.readsMemory() && O.writesMemory()) {
            res = _parseOperand_RW(vm, I, oi);
        }

        bUS |= res;
        vecOI.push_back(oi);
    }
    // end for
    return bUS;
}


bool SymExecutor::maySymbolicRegister(VMState *vm, uint ID) {
    return vm->isSYReg(ID);
} ;

bool SymExecutor::setReadRegs(VMState *vm, DAPIInstr *I) {
    std::set<RegisterAST::Ptr> readRegs;
    I->getReadSet(readRegs);

    for (auto P : readRegs) {
        uint indx = P->getID();
        uint size = P->size();

        if ((indx & x86::FLAG) == x86::FLAG)
            continue ;

        RegValue V = {indx, size};
        V.isSymList = false;
        bool res = vm->readRegister(V);
        assert(res);
        
        if (V.bsym) {
            // Do nothing
#ifdef _DEBUG_OUTPUT
            cout << "123: " << P->format() << "\n";
#endif
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

bool SymExecutor::setReadRegs(VMState *vm, DAPIInstrPtr &I) {
    return setReadRegs(vm, I.get());
}

void printCellList (SymCellPtr cellList) {
    int i = 0 ;
    std::cout << std::endl;
    while(cellList!=NULL) {
        std::cout<<cellList->addr<<"@"<<cellList->size<<"," ;
        if(cellList->exprPtr)
            cellList->exprPtr->print();
        std::cout << "; " ;
        cellList = cellList->next ;
        if(i++>20) {
            std::cout << ">20!!!" ;
            return ;
        }
    }
    std::cout << std::endl;
}
