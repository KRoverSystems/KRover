#ifndef OPRAND_H
#define OPRAND_H
#include <memory>
#include <vector>

#include "defines.h"

class VMState;
/* -------------------------------------- */
namespace Dyninst {
    namespace InstructionAPI {
        class Expression;
        class RegisterAST;
        class Operand;
        class Instruction;
    }  // namespace InstructionAPI
}  // namespace Dyninst

namespace EXPR {
class Expr;
}

typedef Dyninst::InstructionAPI::Instruction DAPIInstr;
typedef std::shared_ptr<Dyninst::InstructionAPI::Instruction> DAPIInstrPtr;
typedef Dyninst::InstructionAPI::Operand DIAPIOperand;
typedef std::shared_ptr<Dyninst::InstructionAPI::Operand> DIAPIOperandPtr;
typedef Dyninst::InstructionAPI::RegisterAST DIAPIRegisterAST;
typedef std::shared_ptr<Dyninst::InstructionAPI::RegisterAST> DIAPIRegisterASTPtr;

typedef EXPR::Expr KVExpr;
typedef std::shared_ptr<KVExpr> KVExprPtr;

enum OperandType {
    OPTY_UNK = 0,
    OPTY_IMM = 0x01,
    OPTY_REG = 0x08,         // A register operand, can be any of the following 2;
    OPTY_REGCON = 0x0A,      // The register stores a concrete value;
    OPTY_REGSYM = 0x0C,      // The register stores a symbolic value;
    OPTY_MEMCELL = 0x80,     // A memory operand, can be any of following 3;
    OPTY_MEMCELLCON = 0xC0,  // The memory cell stores a concrete value;
    OPTY_MEMADDRSYM = 0x90,  // The memory address is a symbolic value;
    OPTY_MEMCELLSYM = 0xB0,  // The memory cell stores a symbolic value;
};

enum OperandAccs {
    OPAC_UNK = 0,   // 00b
    OPAC_RD = 1,    // 01b
    OPAC_WR = 2,    // 10b
    OPAC_RDWR = 3,  // 11b
};

struct OprndInfo {
    DIAPIOperandPtr PO;
    OperandType opty;//check the operand type first, if it is a memory cell, record its memory access type.
    OperandAccs rdwr;
    uint size;
    bool symb;
    // The operand container: can be an immediate, a regsiter or a memory
    // address
    union {
        ulong imm_value;
        uint reg_index;
        ulong mem_conaddr;     // A concrete address
        KVExprPtr mem_symaddr;  // A symbolic expression
    };
    // The operand value: can be the value in register or in memory cell 
    union {
        long reg_conval;  // A concrete value
        long mem_conval;
        KVExprPtr reg_symval;  // A symbolic value
        KVExprPtr mem_symval;
    };

    bool isSymList;
    long conVal;
    SymCellPtr symList;

    OprndInfo(DIAPIOperand &O);
    ~OprndInfo() {}

    bool getConValue(long &out);
    bool setConValue(VMState *vm, long in);
    bool getSymValue(KVExprPtr &out);
    bool getSymValue(SymCellPtr &out, long &v);
    bool setSymValue(VMState *vm, KVExprPtr &in);
    bool setSymValue(VMState *vm, SymCellPtr &in, long &v) ;
};
typedef std::shared_ptr<OprndInfo> OprndInfoPtr;

struct InstrInfo {
    DAPIInstrPtr PI;
    std::vector<OprndInfoPtr> vecOI;
    bool hasSymbOprand;
    InstrInfo(DAPIInstr *I);  // reuse the passing copy
    ~InstrInfo() { vecOI.clear(); }
};
typedef std::shared_ptr<InstrInfo> InstrInfoPtr;

enum FLAG_STAT
{
    FLAG_CLEAR      = false ,
    FLAG_SET        = true ,
    Schrodingers_cat  = -1
}; 
#define FLAG_UNCERTAIN Schrodingers_cat

// Base class for layzily calculating CPU bit flags;
// Every instruction that modifies flags should inherit from this class;
class FlagSettingInstr {
   protected:
    InstrInfoPtr m_IOI;

    FLAG_STAT sf, zf, of, cf, pf, af ;
    FLAG_STAT flags_set ; 

   public:
    FlagSettingInstr(InstrInfoPtr &info) : m_IOI(info) {sf=zf=of=cf=pf=af=FLAG_UNCERTAIN;}
    ~FlagSettingInstr() {}
    
    virtual FLAG_STAT calc_sflag(void) {
        return sf;
    };
    virtual FLAG_STAT calc_zflag(void) {
        return zf;
    };

    virtual FLAG_STAT calc_oflag(void) {
        return of;
    };

    virtual FLAG_STAT calc_cflag(void) {
        return cf;
    };

    virtual FLAG_STAT calc_pflag(void) {
        return pf;
    };

    virtual FLAG_STAT calc_aflag(void) {
        return af;
    };
    
    
    virtual FLAG_STAT set_sflag(FLAG_STAT flag) {
        return sf=flag;
    };
    virtual FLAG_STAT set_zflag(FLAG_STAT flag) {
        return zf=flag;
    };
    virtual FLAG_STAT set_oflag(FLAG_STAT flag) {
        return of=flag;
    };

    virtual FLAG_STAT set_cflag(FLAG_STAT flag) {
        return cf=flag;
    };

    virtual FLAG_STAT set_pflag(FLAG_STAT flag) {
        return pf=flag;
    };

    virtual FLAG_STAT set_aflag(FLAG_STAT flag) {
        return af=flag;
    };
    bool GetConVals(int &sz1, long &conval1, int &sz2, long &conval2);        
};

typedef std::shared_ptr<FlagSettingInstr> FSInstrPtr;

ulong HashTogether(ulong addr, ulong size);
ulong ExprHash(ulong addr, ulong size) ;
ulong CellHash(ulong addr, ulong size) ;
/* -------------------------------------- */
#endif //OPRAND_H
