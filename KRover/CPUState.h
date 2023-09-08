
#ifndef __CPU_STATE_H__
#define __CPU_STATE_H__

#include <asm/ptrace.h>
#include <linux/types.h>
#include <signal.h>
#include <ucontext.h>
#include <map>
#include "oprand.h"
#include "defines.h"
#include "SymList.h"

#define FLAG_REG_CT 12

struct pt_regs;

struct DyinstEC {
    uint32_t offt, size;
};

struct MacReg {
    struct pt_regs regs;
    ulong fs_base;
    ulong gs_base;
    //for %ds %es
    ulong ds_base;
    ulong es_base;
};

struct FlagRegMgt {
    bool set;
    ulong set_count;
    ulong regs[FLAG_REG_CT];
};

// Manage CPU registers
#define PTREGS_REG_TOTAL 23  //~PTRegsEncoding.size()
#define DYINST_REG_TOTAL 32  //~DyinstEncoding.size()

class SYCPUState {
    /*
    x86_64::FULL    0
    x86_64::L_REG   1    first  8bits
    x86_64::H_REG   2    second 8bits
    x86_64::W_REG   3    first  16bits
    x86_64::D_REG   f    first  32bits
    */
    #define REG_32H    6
    #define REG_16H    5
    #define REG_D       4
    #define REG_W       3
    #define REG_H       2
    #define REG_L       1
    #define REG_FULL    0

   private:
    static std::map<uint, std::string> PTRegsEncoding;
    static std::map<uint, DyinstEC> DyinstEncoding;
    union {
        ulong m_ArrRegs[DYINST_REG_TOTAL];
        MacReg m_PTRegs;
    };

    union {
        ulong m_ArrRegs_back[DYINST_REG_TOTAL];
        MacReg m_PTRegs_back;
    };
    
    uint64_t m_symBitmap[DYINST_REG_TOTAL] ;
    uint64_t m_symBitmap_back[DYINST_REG_TOTAL] ;
    Symbol_List_Map m_symList[DYINST_REG_TOTAL] ;

    struct MachineReg {
        uint indx;  // Register index
        uint size;  // number of bytes
        uint idpt;
        bool bsym_flag;  // is a symbolic value?
        uint64_t *pSymBitmap;
        Symbol_List_Map *pSymList ;
        bool bsym_flag_back;
        union {
            int64_t *pi64;
            int32_t *pi32;
            int16_t *pi16;
            int8_t *pi8;
            uint64_t *pu64;
            uint32_t *pu32;
            uint16_t *pu16;
            uint8_t *pu8;
        };
        union {
            KVExprPtr symval;    // symbolic expression
            FSInstrPtr fsinstr;  // used for lazily calculate CPU bit falgs.
        };
        KVExprPtr symval_back ;
        void backup () {
            bsym_flag_back = bsym_flag ;
            if(bsym_flag) {

                symval_back = symval ;
            }
        }

        void restore () {
            bsym_flag = bsym_flag_back ;
            if(bsym_flag_back) {

                symval = symval_back ;
            }
        }
        
        MachineReg() : bsym_flag(false), symval(nullptr) {}
        ~MachineReg() {}
    };
    typedef std::shared_ptr<MachineReg> MachineRegPtr;
    // All used registers
    std::map<uint, MachineRegPtr> m_Regs;
    struct FlagRegMgt flag_list;

    public:
    SYCPUState(void) : m_Regs(), m_symList(), flag_list() {
        MachineReg *R;
        for (auto E : DyinstEncoding) {
            uint iddy = E.first;
            uint idpt = E.second.offt;
            uint size = E.second.size;
            R = new MachineReg();
            R->indx = iddy;
            R->size = size;
            R->idpt = idpt ;
            R->pu64 = &m_ArrRegs[idpt];
            R->pSymBitmap = &m_symBitmap[idpt];
            m_symBitmap[idpt] = 0 ;
            R->pSymList = &m_symList[idpt] ;
            m_Regs[iddy].reset(R);
        };

        flag_list.set = false;
    }

    ~SYCPUState(void) {
        m_Regs.clear();
    }

    // update state with concrete values, always invoke before symbolic execution
    bool setConcreteCPUState(struct MacReg *regs);
    bool readConcreteCPUState(struct MacReg *regs);
    bool clearAllSymFlag(void);

    struct pt_regs* getPTRegs(void);
    ulong readConReg(uint idx);
    bool writeConReg(uint idx, ulong val);
    bool isSYReg(uint reg_index);
    bool isSYReg(MachineReg *R, int subRegIndex) ;
    bool setSYReg(MachineReg *R) ;
    bool clrSYReg(MachineReg *R) ;

    SYCPUState::MachineReg* idxToReg(uint reg_index) ;
    int RegToSubIndex (MachineReg *R) ;
    bool regIdxToAddrSize(int idx, uint64_t &addr, int &size) ;
    int regIdxToSize(uint reg_index);
    std::string regIdxToName(uint regidx);

    bool writeRegister(RegValue &v);
    bool readRegister(RegValue &v);

    bool getFlagBit(uint flag_index, FSInstrPtr &ptr);
    bool setFlagBit(uint flag_index, FSInstrPtr &ptr);
    
    bool getFlagBit(uint flag_index, FLAG_STAT &flag);
    bool setFlagBit(uint flag_index, FLAG_STAT &flag);
    
    bool FlagBitDefinited(uint flag_index) ;
    bool hasSymReg(void) ;
    void list_mregs (void) ;
    void backup ();
    void restore () ;

   private:

    bool writeConcreteValue(MachineReg *R, RegValue &V);
    bool readConcreteValue(MachineReg *R, RegValue &V);

};

#endif  // !__CPU_STATE_H__
