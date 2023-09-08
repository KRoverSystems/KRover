#include "CPUState.h"
#include <assert.h>
#include <signal.h>
#include <ucontext.h>
#include <functional>
#include <map>
#include <string>
#include <vector>
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "dyn_regs.h"
#include "Expr.h"
#include "CPUState.h"
#include "SymList.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;
using namespace EXPR;

enum PTREGS_ENCODING {
    R15_PTRIDX = 0,
    R14_PTRIDX = 1,
    R13_PTRIDX = 2,
    R12_PTRIDX = 3,
    RBP_PTRIDX = 4,
    RBX_PTRIDX = 5,
    R11_PTRIDX = 6,
    R10_PTRIDX = 7,
    R9_PTRIDX = 8,
    R8_PTRIDX = 9,
    RAX_PTRIDX = 10,
    RCX_PTRIDX = 11,
    RDX_PTRIDX = 12,
    RSI_PTRIDX = 13,
    RDI_PTRIDX = 14,
    ORAX_PTRIDX = 15,
    RIP_PTRIDX = 16,
    CS_PTRIDX = 17,
    EFL_PTRIDX = 18,
    RSP_PTRIDX = 19,
    SS_PTRIDX = 20,
    FS_PTRIDX = 21,
    GS_PTRIDX = 22,
    //for %ds %es
    DS_PTRIDX = 23,
    ES_PTRIDX = 24,
};

std::map<uint, std::string> SYCPUState::PTRegsEncoding = {
    {R15_PTRIDX, "x86_64::r15"},
    {R14_PTRIDX, "x86_64::r14"},
    {R13_PTRIDX, "x86_64::r13"},
    {R12_PTRIDX, "x86_64::r12"},
    {RBP_PTRIDX, "x86_64::rbp"},
    {RBX_PTRIDX, "x86_64::rbx"},
    {R11_PTRIDX, "x86_64::r11"},
    {R10_PTRIDX, "x86_64::r10"},
    {R9_PTRIDX, "x86_64::r9"},
    {R8_PTRIDX, "x86_64::r8"},
    {RAX_PTRIDX, "x86_64::rax"},
    {RCX_PTRIDX, "x86_64::rcx"},
    {RDX_PTRIDX, "x86_64::rdx"},
    {RSI_PTRIDX, "x86_64::rsi"},
    {RDI_PTRIDX, "x86_64::rdi"},
    {ORAX_PTRIDX, "x86_64::orig_rax"},
    {RIP_PTRIDX, "x86_64::rip"},
    {CS_PTRIDX, "x86_64::cs"},
    {EFL_PTRIDX, "x86_64::flags"},
    {RSP_PTRIDX, "x86_64::rsp"},
    {SS_PTRIDX, "x86_64::ss"},
    {FS_PTRIDX, "x86_64::fs"},
    {GS_PTRIDX, "x86_64::gs"},
    //for %ds %es
    {DS_PTRIDX, "x86_64::ds"},
    {ES_PTRIDX, "x86_64::es"},
};

std::map<uint, DyinstEC> SYCPUState::DyinstEncoding = {
    // 64 bits
    {x86_64::r8, {R8_PTRIDX, 8}},
    {x86_64::r9, {R9_PTRIDX, 8}},
    {x86_64::r10, {R10_PTRIDX, 8}},
    {x86_64::r11, {R11_PTRIDX, 8}},
    {x86_64::r12, {R12_PTRIDX, 8}},
    {x86_64::r13, {R13_PTRIDX, 8}},
    {x86_64::r14, {R14_PTRIDX, 8}},
    {x86_64::r15, {R15_PTRIDX, 8}},
    {x86_64::rax, {RAX_PTRIDX, 8}},
    {x86_64::rbx, {RBX_PTRIDX, 8}},
    {x86_64::rcx, {RCX_PTRIDX, 8}},
    {x86_64::rdx, {RDX_PTRIDX, 8}},
    {x86_64::rsi, {RSI_PTRIDX, 8}},
    {x86_64::rdi, {RDI_PTRIDX, 8}},
    {x86_64::rbp, {RBP_PTRIDX, 8}},
    {x86_64::rsp, {RSP_PTRIDX, 8}},
    {x86_64::rip, {RIP_PTRIDX, 8}},
    {x86_64::flags, {EFL_PTRIDX, 8}},
    {x86_64::fs, {FS_PTRIDX, 8}},
    {x86_64::gs, {GS_PTRIDX, 8}},
    //for %ds %es
    {x86_64::ds, {DS_PTRIDX, 8}},
    {x86_64::es, {ES_PTRIDX, 8}},
    // 32 bits
    {x86_64::r8d, {R8_PTRIDX, 4}},
    {x86_64::r9d, {R9_PTRIDX, 4}},
    {x86_64::r10d, {R10_PTRIDX, 4}},
    {x86_64::r11d, {R11_PTRIDX, 4}},
    {x86_64::r12d, {R12_PTRIDX, 4}},
    {x86_64::r13d, {R13_PTRIDX, 4}},
    {x86_64::r14d, {R14_PTRIDX, 4}},
    {x86_64::r15d, {R15_PTRIDX, 4}},
    {x86_64::eax, {RAX_PTRIDX, 4}},
    {x86_64::ebx, {RBX_PTRIDX, 4}},
    {x86_64::ecx, {RCX_PTRIDX, 4}},
    {x86_64::edx, {RDX_PTRIDX, 4}},
    {x86_64::esi, {RSI_PTRIDX, 4}},
    {x86_64::edi, {RDI_PTRIDX, 4}},
    {x86_64::ebp, {RBP_PTRIDX, 4}},
    {x86_64::esp, {RSP_PTRIDX, 4}},
    // 16 bits
    {x86_64::r8w, {R8_PTRIDX, 2}},
    {x86_64::r9w, {R9_PTRIDX, 2}},
    {x86_64::r10w, {R10_PTRIDX, 2}},
    {x86_64::r11w, {R11_PTRIDX, 2}},
    {x86_64::r12w, {R12_PTRIDX, 2}},
    {x86_64::r13w, {R13_PTRIDX, 2}},
    {x86_64::r14w, {R14_PTRIDX, 2}},
    {x86_64::r15w, {R15_PTRIDX, 2}},
    {x86_64::ax, {RAX_PTRIDX, 2}},
    {x86_64::bx, {RBX_PTRIDX, 2}},
    {x86_64::cx, {RCX_PTRIDX, 2}},
    {x86_64::dx, {RDX_PTRIDX, 2}},
    {x86_64::si, {RSI_PTRIDX, 2}},
    {x86_64::di, {RDI_PTRIDX, 2}},
    {x86_64::bp, {RBP_PTRIDX, 2}},
    {x86_64::sp, {RSP_PTRIDX, 2}},
    // 8 bits
    {x86_64::r8b, {R8_PTRIDX, 1}},
    {x86_64::r9b, {R9_PTRIDX, 1}},
    {x86_64::r10b, {R10_PTRIDX, 1}},
    {x86_64::r11b, {R11_PTRIDX, 1}},
    {x86_64::r12b, {R12_PTRIDX, 1}},
    {x86_64::r13b, {R13_PTRIDX, 1}},
    {x86_64::r14b, {R14_PTRIDX, 1}},
    {x86_64::r15b, {R15_PTRIDX, 1}},
    {x86_64::al, {RAX_PTRIDX, 1}},
    {x86_64::bl, {RBX_PTRIDX, 1}},
    {x86_64::cl, {RCX_PTRIDX, 1}},
    {x86_64::dl, {RDX_PTRIDX, 1}},

    {x86_64::ah, {RAX_PTRIDX, 1}},
    {x86_64::bh, {RBX_PTRIDX, 1}},
    {x86_64::ch, {RCX_PTRIDX, 1}},
    {x86_64::dh, {RDX_PTRIDX, 1}},
   
    {x86_64::sil, {RSI_PTRIDX, 1}},
    {x86_64::dil, {RDI_PTRIDX, 1}},
    {x86_64::bpl, {RBP_PTRIDX, 1}},
    {x86_64::spl, {RSP_PTRIDX, 1}},
    // flags
    // {"x86_64::cf", x86_64::cf,1}},
    // {"x86_64::pf", x86_64::pf,1}},
    // {"x86_64::af", x86_64::af,1}},
    // {"x86_64::zf", x86_64::zf,1}},
    // {"x86_64::sf", x86_64::sf,1}},
    // {"x86_64::tf", x86_64::tf,1}},
    // {"x86_64::df", x86_64::df,1}},
    // {"x86_64::of", x86_64::of,1}},
    // {"x86_64::rf", x86_64::rf,1}},
    {x86_64::cf, {PTREGS_REG_TOTAL + 1, 1}},
    {x86_64::pf, {PTREGS_REG_TOTAL + 2, 1}},
    {x86_64::af, {PTREGS_REG_TOTAL + 3, 1}},
    {x86_64::zf, {PTREGS_REG_TOTAL + 4, 1}},
    {x86_64::sf, {PTREGS_REG_TOTAL + 5, 1}},
    {x86_64::tf, {PTREGS_REG_TOTAL + 6, 1}},
    {x86_64::df, {PTREGS_REG_TOTAL + 7, 1}},
    {x86_64::of, {PTREGS_REG_TOTAL + 8, 1}},
    {x86_64::rf, {PTREGS_REG_TOTAL + 9, 1}},
};

static uint64_t reg_mask_bits[] = { 0xff, 
                           0x1,
                           0x2,
                           0x3,
                           0xF,
                           0xC0,
                           0xF0
                        } ;

/******************************************** Read & write registers *****************************/
bool SYCPUState::setConcreteCPUState(struct MacReg *regs) {
    memcpy(&m_PTRegs, regs, sizeof(m_PTRegs));
    return true;
}

bool SYCPUState::readConcreteCPUState(struct MacReg *regs) {
    memcpy(regs, &m_PTRegs, sizeof(m_PTRegs));
    return true;
}

bool SYCPUState::clearAllSymFlag() {
    std::set<int> flags = {x86_64::cf, x86_64::pf, x86_64::af, x86_64::zf, x86_64::sf, x86_64::tf, x86_64::df, x86_64::of, x86_64::rf};
    int flag_index;
    int flag_count = 0;
    int iteration = 0;

    if(!flag_list.set){
        for (auto flag : flags)
        {
            flag_index = flag;
            auto it = m_Regs.find(flag_index);
            assert(it != m_Regs.end());
            MachineReg *R = (it->second).get();
            R->bsym_flag = false;
            flag_list.regs[flag_count] = (ulong)R;
            flag_count++;
        }
        flag_list.set = true;
        flag_list.set_count = flag_count;
    }
    else
    {
        while(iteration < flag_list.set_count)
        {
            MachineReg *R = (MachineReg *)(flag_list.regs[iteration]);
            R->bsym_flag = false;
            iteration++;
        }
    }

    return true;
}

struct pt_regs* SYCPUState::getPTRegs(void) {
    return ((struct pt_regs*)(&m_PTRegs));
}

ulong SYCPUState::readConReg(uint reg_idx)
{
    auto it = m_Regs.find(reg_idx);
    assert(it != m_Regs.end());

    auto R = it->second;
    MachineReg *mr = R.get();
    return *(mr->pu64);
}

bool SYCPUState::writeConReg(uint reg_idx, ulong val)
{
    auto it = m_Regs.find(reg_idx);
    assert(it != m_Regs.end());

    auto R = it->second;
    MachineReg *mr = R.get();
    std::cout << mr->size << std::endl;

    switch (mr->size)
    {
        case 8:
            *(mr->pu64) = val;
            break;
        case 4:
            *(mr->pu32) = (uint32_t)val;
            break;
        case 2:
            *(mr->pu16) = (uint16_t)val;
            break;
        case 1:
            *(mr->pu8) = (uint8_t)val;
            break;
        default:
            assert(0);
            break;
    }
    return true;
}

int SYCPUState::regIdxToSize(uint reg_index) {
    int val = 0x00000f00 & reg_index;
    switch (val){
    case 0x0:       //0x00000000; //64 bits 
        return 8;
    case 0xf00:     //0x00000F00; //32 bit
        return 4;
    case 0x300:     //0x00000300; //16 bit
        return 3;
    case 0x200:     //0x00000200;  //8-bit, second byte 
    case 0x100:     //0x00000100;  //8-bit, first byte 
        return 1;
    default:
        return 0;
    }
}

SYCPUState::MachineReg* SYCPUState::idxToReg(uint reg_index) {

    auto it = m_Regs.find(reg_index);

    if(it == m_Regs.end())
        std::cout << "reg_idx:" << reg_index << std::endl;
    assert(it != m_Regs.end());

    auto R = it->second;

    MachineReg *mr = R.get() ;

    return mr ;
}

int SYCPUState::RegToSubIndex (MachineReg *R) {
    int subIdx = -1 ;
    if ((R->indx & 0xf00) == x86_64::D_REG)
        subIdx = REG_D ;
    else 
        subIdx = (R->indx&0xf00) >> 8;

    assert (subIdx < 7) ;
    return subIdx ;
}

bool SYCPUState::isSYReg(uint reg_index) {

    MachineReg *mr = idxToReg(reg_index) ;

    int subRegIndex = RegToSubIndex(mr) ;

    bool bsym = (*mr->pSymBitmap) & reg_mask_bits[subRegIndex] ;

    return (bsym);
}

bool SYCPUState::isSYReg(MachineReg *R, int subRegIndex) {

    bool bsym = (*R->pSymBitmap) & reg_mask_bits[subRegIndex] ;

    return (bsym);
}

bool SYCPUState::setSYReg(MachineReg *R) {
    
    int subRegIndex = RegToSubIndex(R) ;
    *(R->pSymBitmap) |= reg_mask_bits[subRegIndex] ;

    return true ;

}
bool SYCPUState::clrSYReg(MachineReg *R) {

    int subRegIndex = RegToSubIndex(R) ;
    *(R->pSymBitmap) &= ~(reg_mask_bits[subRegIndex]) ;

    return true ;
}

bool SYCPUState::readRegister(RegValue &V) {
    MachineReg *R = idxToReg(V.indx) ;
    bool ret ;
    assert(R->indx == V.indx);
    assert(R->size == V.size);
    
    int subRegIndex = RegToSubIndex(R) ;
    bool bSym = isSYReg((R), subRegIndex) ;

    V.bsym = bSym ;
    if (!bSym) {
        V.isSymList = false ;
        return readConcreteValue(R, V) ;
    }

    SymCellPtr symList, tmp ;
    u_int64_t addr ;
    int size, i=0, symsize = 0 ;
    KVExprPtr e ;

    regIdxToAddrSize(subRegIndex, addr, size) ;
    readConcreteValue(R, V) ;

    if (V.isSymList) {
         R->pSymList->GetCellList(symList, addr, size) ;
         V.symcellPtr = symList ;
        return true ;
    } else {
         R->pSymList->GetExpr(addr, size, V.i64, V.expr) ;
    }
    
    return true ;
}

bool SYCPUState::regIdxToAddrSize(int idx, uint64_t &addr, int &size) {
    switch (idx) {
        case REG_FULL:
            addr = 0 ;
            size = 8 ;
            break ;
        
        case REG_D:
            addr = 0 ;
            size = 4 ;
            break ;            
        
        case REG_W:
            addr = 0 ;
            size = 2 ;
            break ;

        case REG_L:
            addr = 0 ;
            size = 1 ;
            break ;

        case REG_H:
            addr = 1 ;
            size = 1 ;
            break ;
        
        default :
            assert(0);
    }
    return true ;
}

bool SYCPUState::writeRegister(RegValue &V) {
    bool ret ;
    MachineReg *R = idxToReg(V.indx) ;
    assert(R->indx == V.indx);
    assert(R->size == V.size);
    
    int subRegIndex = RegToSubIndex(R) ;
    bool bSym = V.bsym ;
    u_int64_t addr ;
    int size ;
    regIdxToAddrSize(subRegIndex, addr, size) ;

    if (!bSym) {
        clrSYReg(R) ;
        ret = R->pSymList->Remove(addr, size) ;
        assert (ret);
        return writeConcreteValue(R, V) ;
    }
    writeConcreteValue(R, V) ;
    if (V.isSymList) {
        SymCellPtr tmp, scPtr = V.symcellPtr ;
        uint64_t start = scPtr->addr; ;
        if(start>=8) {
            for (tmp=scPtr; tmp!=NULL; tmp=tmp->next) {
                tmp->addr = tmp->addr - start ;
            }
        }
        uint64_t tmpbitmap = 0 ;
        for (tmp=scPtr; tmp!=NULL; tmp=tmp->next) {
            uint64_t offset = tmp->addr ;
            int i ;
            for(i=tmp->addr; i<tmp->addr+tmp->size; i++){
                tmpbitmap |= (1<<i) ;
            }
        }
        clrSYReg(R) ;
        *R->pSymBitmap |= tmpbitmap ;
        ret = R->pSymList->Merge(V.symcellPtr, addr, addr+size) ;
    } else {
        setSYReg(R) ;
        SymCellPtr SymList (new SymCell(addr, size, V.expr)) ;
        return R->pSymList->Merge(SymList, addr, addr+size) ;
    }

    return true ;
}

bool SYCPUState::writeConcreteValue(MachineReg *R, RegValue &V) {
    switch (R->size) {
        case 1: {
            if((R->indx&0xf00) == (x86_64::L_REG)) {
                *R->pi8 = V.i8;
            }
            else {
                // ah register;
                int16_t tmp = V.i8 << 8;
                *R->pi16 = (*R->pi16&0xff) | (tmp&0xff00) ;
            }
        } break;
        case 2: {
            *R->pi16 = V.i16;
        } break;
        case 4: {
            *R->pi32 = V.i32;
        } break;
        case 8: {
            *R->pi64 = V.i64;
        } break;
        default: {
            FIX_ME();
            return false;
        } break;
    }
    return true;
}

bool SYCPUState::readConcreteValue(MachineReg *R, RegValue &V) {
    switch (R->size) {
        case 1: {
            if((R->indx&0xf00) == (x86_64::L_REG)) {
                // al register ;
                V.i8 = *(R->pi8) ;
            } else {
                // ah register;
                int16_t tmp = *(R->pi16);
                V.i8 = (int8_t)(tmp>>8) ;
            }
        } break;
        case 2: {
            V.i16 = *(R->pi16);
        } break;
        case 4: {
            V.i32 = *(R->pi32);
        } break;
        case 8: {
            V.i64 = *(R->pi64);
        } break;
        default: {
            FIX_ME();
            return false;
        } break;
    }
    return true;
}


bool SYCPUState::getFlagBit(uint flag_index, FSInstrPtr &ptr) {
    auto it = m_Regs.find(flag_index);
    assert(it != m_Regs.end());
    MachineReg *R = (it->second).get();
    ptr = R->fsinstr;
    return true;
}

bool SYCPUState::setFlagBit(uint flag_index, FSInstrPtr &ptr) {
    auto it = m_Regs.find(flag_index);
    assert(it != m_Regs.end());
    MachineReg *R = (it->second).get();
    R->fsinstr = ptr;
    return true;
}


bool SYCPUState::getFlagBit(uint flag_index, FLAG_STAT &flag) {
    auto it = m_Regs.find(flag_index);
    assert(it != m_Regs.end());
    MachineReg *R = (it->second).get();

    assert ((flag_index & (x86_64::BIT|x86_64::FLAG|Arch_x86_64)) == (x86_64::BIT|x86_64::FLAG|Arch_x86_64)) ;
    flag_index &= 0xff ; 

    if (!R->bsym_flag)  {
        if(m_PTRegs.regs.eflags & (1<<flag_index))
            flag = FLAG_SET ;
        else
            flag = FLAG_CLEAR ;
    }
    else
        flag = FLAG_UNCERTAIN ;
    
    return true;
}

bool SYCPUState::setFlagBit(uint flag_index, FLAG_STAT &flag) {
    auto it = m_Regs.find(flag_index);
    assert(it != m_Regs.end());
    MachineReg *R = (it->second).get();
   
    assert ((flag_index & (x86_64::BIT|x86_64::FLAG|Arch_x86_64)) == (x86_64::BIT|x86_64::FLAG|Arch_x86_64)) ;
    flag_index &= 0xff ;

    if (flag == FLAG_UNCERTAIN) {
        R->bsym_flag = true ;
    } else {
        if(flag==FLAG_SET)
            m_PTRegs.regs.eflags |= 1<<flag_index ;
        else if (flag==FLAG_CLEAR)
            m_PTRegs.regs.eflags &= ~(1<<flag_index) ;
    }
    
    return true;
}

bool SYCPUState::FlagBitDefinited(uint flag_index) {
    auto it = m_Regs.find(flag_index);
    assert(it != m_Regs.end());
    MachineReg *R = (it->second).get();
    if(R->bsym_flag) 
            return false ;
    else 
        return true ;
}
bool SYCPUState::hasSymReg(void) {
    for (auto iter = m_Regs.begin(); iter != m_Regs.end(); iter++) {
        if (*iter->second.get()->pSymBitmap) {
            std::cout << "hasSymReg: " << iter->second.get()->idpt << " " << iter->second.get()->indx 
                << " " << *iter->second.get()->pSymBitmap << std::endl ;
            return true ;
        }
    }
    return false ;
}


void SYCPUState::backup () {
    memcpy (m_ArrRegs_back, m_ArrRegs, sizeof(m_ArrRegs)) ;
    memcpy (&m_PTRegs_back, &m_PTRegs, sizeof(m_PTRegs_back)) ;
    memcpy (m_symBitmap_back, m_symBitmap, sizeof(m_symBitmap_back)) ;

    for (int i = 0; i< DYINST_REG_TOTAL; i++) {
        m_symList[i].backup() ;
    }

    for(auto it: m_Regs) {
        it.second->backup () ;
    }
}

void SYCPUState::restore () {
    memcpy (m_ArrRegs, m_ArrRegs_back, sizeof(m_ArrRegs)) ;
    memcpy (&m_PTRegs, &m_PTRegs_back, sizeof(m_PTRegs_back)) ;
    memcpy (m_symBitmap, m_symBitmap_back, sizeof(m_symBitmap_back)) ;

    for (int i = 0; i< DYINST_REG_TOTAL; i++) {
        m_symList[i].restore() ;
    }
    for(auto it: m_Regs) {
        it.second->restore () ;
    }
}

std::string SYCPUState::regIdxToName(uint regidx){

    string name;
    DyinstEC dynenc;

    dynenc = DyinstEncoding[regidx];
    name = PTRegsEncoding[dynenc.offt];

    return name;
}