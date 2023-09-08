#include "VMState.h"

/* ------------------------------- */
OprndInfo::OprndInfo(DIAPIOperand &O) : PO(new DIAPIOperand(O)), mem_symval(nullptr) {
    opty = OPTY_UNK;
    rdwr = OPAC_UNK;
    symb = false;
}

InstrInfo::InstrInfo(DAPIInstr *I) : PI(I), vecOI() {
    hasSymbOprand = false;
}

bool OprndInfo::getConValue(long &out) {
    if (symb || (rdwr & OPAC_RD) == 0) {
        ERRR_ME("expect reading on a concrete value");
        exit(EXIT_FAILURE);
    }
    bool res = true;
    switch (opty) {
        case OPTY_IMM: {
            out = imm_value;
        } break;
        case OPTY_REGCON: {
            out = reg_conval;
        } break;
        case OPTY_MEMCELLCON: {
            out = mem_conval;
        } break;
        default: {
            res = false;
            FIX_ME();
            exit(EXIT_FAILURE);  // "Unexpected operand type"
        } break;
    }
    return res;
}

bool OprndInfo::setConValue(VMState *vm, long in) {
    // Do writting
    bool res = false;
    switch (opty) {
        case OPTY_REG:
        case OPTY_REGCON:
        case OPTY_REGSYM: {
            RegValue V{reg_index, size, false, false, in};
            res = vm->writeRegister(V);
            assert(res);
        } break;
        case OPTY_MEMCELL:
        case OPTY_MEMCELLCON: {
            MemValue V{mem_conaddr, size, false, false, in};
            res = vm->writeMemory(V);
            assert(res);
        } break;
        default: {
            ERRR_ME("unexpected operand");
            exit(EXIT_FAILURE);
        } break;
    }
    return res;
}

bool OprndInfo::getSymValue(KVExprPtr &out) {
    bool res = false;
    switch (opty) {
        case OPTY_REGSYM: {
            res = true;
            out = reg_symval;
        } break;
        case OPTY_MEMCELLSYM: {
            res = true;
            out = mem_symval;
        } break;
        default: {
            FIX_ME();
            exit(EXIT_FAILURE);  // "Unexpected operand type"
        } break;
    }
    return res;
}

bool OprndInfo::getSymValue(SymCellPtr &out, long &v) {
    
    assert(isSymList) ;
    out = symList ;
    v = conVal ;
    return true ;
}
bool OprndInfo::setSymValue(VMState *vm, SymCellPtr &in, long &v) {
    bool res = false;
    switch (opty) {
        case OPTY_REG:
        case OPTY_REGCON:
        case OPTY_REGSYM: {
            // Write to register
            RegValue V = {reg_index, size, true, true, v, NULL, in};
            res = vm->writeRegister(V);
        } break;
        case OPTY_MEMCELL:
        case OPTY_MEMCELLCON:
        case OPTY_MEMCELLSYM: {
            // write to memory cell
            MemValue V = {mem_conaddr, size, true, true, v, NULL, in};
            res = vm->writeMemory(V);
        } break;
        default: {
            FIX_ME();
            exit(EXIT_FAILURE);  // "Unexpected operand type"
        } break;
    }
    return res;
}

bool OprndInfo::setSymValue(VMState *vm, KVExprPtr &in) {
    bool res = false;
    switch (opty) {
        case OPTY_REG:
        case OPTY_REGCON:
        case OPTY_REGSYM: {
            // Write to register
            RegValue V = {reg_index, size, true, false, 0, in, NULL};
            res = vm->writeRegister(V);
        } break;
        case OPTY_MEMCELL:
        case OPTY_MEMCELLCON:
        case OPTY_MEMCELLSYM: {
            // write to memory cell
            MemValue V = {mem_conaddr, size, true, false, 0, in, NULL};
            res = vm->writeMemory(V);
        } break;
        default: {
            FIX_ME();
            exit(EXIT_FAILURE);  // "Unexpected operand type"
        } break;
    }
    return res;
}

ulong HashTogether(ulong addr, ulong size) {
    return (addr << 3 + size);
}

ulong CellHash(ulong addr, ulong size) {
    return (addr&(~0xfUL));
}
ulong ExprHash(ulong addr, ulong size) {
    return ((addr&0xf)<<4) | (size-1) ;
}
/* ------------------------------- */

