#include "MemState.h"

#include <signal.h>
#include <ucontext.h>

#include <functional>
#include <string>

#include "CPUState.h"
#include "CodeObject.h"
#include "Expression.h"
#include "InstructionDecoder.h"

#include "Expr.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;
using namespace EXPR;

/*********************************************** SYMem bitmaps ***********************************/
// head-cave (l): symbol (m) : tail-cave (r)
SYMemChunk *SYMemBitmap::markSYMemBitmap(ulong addr, ulong size) {
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    ulong hcave_sz = addr - aligned_addr;  // hcave means head-cave
    ulong align_sz = hcave_sz + size;
    SYMemChunk *m, *r;

    if (align_sz > SYMEM_BLOCK_SIZE) {  // split memory into 32-byte chuncks
        ulong sz = SYMEM_BLOCK_SIZE - hcave_sz;
        m = _maskSYMemBitmap(aligned_addr, hcave_sz, sz);
        r = markSYMemBitmap(aligned_addr + SYMEM_BLOCK_SIZE, size - sz);
        m->r = r;
        r->l = m;
    } else {
        ulong sz = size ; //SYMEM_BLOCK_SIZE - hcave_sz;
        m = _maskSYMemBitmap(aligned_addr, hcave_sz, sz);
    }
    return m;
}

SYMemChunk *SYMemBitmap::_maskSYMemBitmap(ulong aligned_addr, ulong hcave_sz, ulong symbol_size) {
    SYMemChunkPtr blk;
    auto it = m_SYMemBitmap.find(aligned_addr);
    if (it == m_SYMemBitmap.end()) {
        blk.reset(new SYMemChunk());
        m_SYMemBitmap[aligned_addr] = blk;
    } else {
        blk = it->second;
    }
    SYMemChunk *c = blk.get();

    SYMEM_CHUNK_TY allones = -1U;
    SYMEM_CHUNK_TY m1 = allones << hcave_sz;
    SYMEM_CHUNK_TY m2 = allones >> (SYMEM_BLOCK_SIZE - hcave_sz - symbol_size);
    SYMEM_CHUNK_TY mm = m1 & m2;

    c->bitmap |= mm;
    return c;
}

void SYMemBitmap::unmarkSYMemBitmap(ulong addr, ulong size) {
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    ulong hcave_sz = addr - aligned_addr;
    ulong align_sz = hcave_sz + size;

    if (align_sz > SYMEM_BLOCK_SIZE) {
        ulong sz = SYMEM_BLOCK_SIZE - hcave_sz;
        _unmaskSYMemBitmap(aligned_addr, hcave_sz, sz);
        unmarkSYMemBitmap(aligned_addr + SYMEM_BLOCK_SIZE, size - sz);
    } else {
        ulong sz = size ; // SYMEM_BLOCK_SIZE - hcave_sz;
        _unmaskSYMemBitmap(aligned_addr, hcave_sz, sz);
    }
}

void SYMemBitmap::_unmaskSYMemBitmap(ulong aligned_addr, ulong cave_sz, ulong symbol_size) {
    auto it = m_SYMemBitmap.find(aligned_addr);
    if (it == m_SYMemBitmap.end())
        return;

    SYMemChunkPtr blk = it->second;
    SYMEM_CHUNK_TY allones = -1U;
    SYMEM_CHUNK_TY m1 = allones << cave_sz;
    SYMEM_CHUNK_TY m2 = allones >> (SYMEM_BLOCK_SIZE - cave_sz - symbol_size);
    SYMEM_CHUNK_TY mm = ~(m1 & m2);

    blk->bitmap &= mm;
    if (blk->bitmap == 0) {
        m_SYMemBitmap.erase(it);  // no long needs
    }
}

// Return true if any byte is symbolic
bool SYMemBitmap::testSYMemBitmap(ulong addr, ulong size) {
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    ulong hcave_sz = addr - aligned_addr;
    ulong align_sz = hcave_sz + size;

    if (align_sz > SYMEM_BLOCK_SIZE) {  // split chunck
        ulong sz = SYMEM_BLOCK_SIZE - hcave_sz;
        bool res1 = _testSYMemBitmap(aligned_addr, hcave_sz, sz);
        bool res2 = testSYMemBitmap(aligned_addr + SYMEM_BLOCK_SIZE, size - sz);
        return res1 | res2;
    } else {
        ulong sz = size ; // SYMEM_BLOCK_SIZE - hcave_sz;
        return _testSYMemBitmap(aligned_addr, hcave_sz, sz);
    }
}

bool SYMemBitmap::_testSYMemBitmap(ulong aligned_addr, ulong cave_sz, ulong symbol_size) {
    auto it = m_SYMemBitmap.find(aligned_addr);
    if (it == m_SYMemBitmap.end())
        return false;

    SYMemChunkPtr blk = it->second;
    SYMEM_CHUNK_TY allones = -1U;
    SYMEM_CHUNK_TY m1 = allones << cave_sz;
    SYMEM_CHUNK_TY m2 = allones >> (SYMEM_BLOCK_SIZE - cave_sz - symbol_size);
    SYMEM_CHUNK_TY mm = m1 & m2;

    return ((blk->bitmap & mm) != 0);
}

SYMemChunk *SYMemBitmap::findSYMemChunk(ulong addr) {
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    auto it = m_SYMemBitmap.find(aligned_addr);
    if (it == m_SYMemBitmap.end())
        return NULL;
    else
        return (it->second).get();
}


bool SYMemState::isSYMemoryCell(ulong addr, ulong size) {
    return m_Bitmap.testSYMemBitmap(addr, size);
}

bool SYMemState::writeMemoryCell(MemValue &v) {
    // unmarshling
    ulong addr = v.addr;
    ulong size = v.size;
    if (v.bsym) {
        writeConcreteValue(addr, size, v.i64) ;
        if(v.isSymList) {
            return writeSymbolicValue(addr, size, v.symcellPtr);
        } else {
            return writeSymbolicValue(addr, size, v.expr);
        }
    } else {
        m_Bitmap.unmarkSYMemBitmap(addr, size) ;
        m_AllSymbolList.Remove(addr, size) ;
        return writeConcreteValue(addr, size, v.i64);
    }
}

bool SYMemState::readMemoryCell(MemValue &v) {
    // marshling
    ulong addr = v.addr;
    ulong size = v.size;
    v.bsym = m_Bitmap.testSYMemBitmap(addr, size);

    if (v.bsym) {
        readConcreteValue(addr, size, v.i64) ;
        if(v.isSymList) {
            return readSymbolicValue(addr, size, v.symcellPtr);
        } else {
            return readSymbolicValue(addr, size, v.expr);
        }
    } else {
        v.isSymList = false ;
        return readConcreteValue(addr, size, v.i64);
    }
}

bool SYMemState::writeSymbolicValue(ulong addr, ulong size, SymCellPtr &SymList) {
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    ulong hcave_sz = addr - aligned_addr;
    if (hcave_sz + size > SYMEM_BLOCK_SIZE) {
        FIX_ME();  // We cannot set cross-chunk symbolic value;
    }

    m_Bitmap.unmarkSYMemBitmap(addr, size) ;
    
    SymCellPtr tmp ;
    for (tmp=SymList; tmp!=NULL; tmp=tmp->next) {
        // set address.
        tmp->addr = tmp->addr + addr ;
        // for each symcell in list, mask the symbol bit.
        m_Bitmap.markSYMemBitmap(tmp->addr, tmp->size);
    }

    return m_AllSymbolList.Merge(SymList, addr, addr+size) ;
}

bool SYMemState::writeSymbolicValue(ulong addr, ulong size, KVExprPtr &e) {
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    ulong hcave_sz = addr - aligned_addr;
    if (hcave_sz + size > SYMEM_BLOCK_SIZE) {
        FIX_ME();  // We cannot set cross-chunk symbolic value;
    }
    m_Bitmap.markSYMemBitmap(addr, size);

    SymCellPtr SymList (new SymCell(addr, size, e)) ;
    
    return m_AllSymbolList.Merge(SymList, addr, addr+size) ;
}

bool SYMemState::readSymbolicValue(ulong addr, ulong size, SymCellPtr &SymList) {
     // Complicate cases: need to split or merge?
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    ulong hcave_sz = addr - aligned_addr;
    if (hcave_sz + size > SYMEM_BLOCK_SIZE) {
        FIX_ME();  // Doesn't support cross-chunk memory read
    }

    SYMemChunk *c = m_Bitmap.findSYMemChunk(aligned_addr);
    assert(c != NULL);

    SYMEM_CHUNK_TY allones = -1U;
    SYMEM_CHUNK_TY m1 = allones << hcave_sz;
    SYMEM_CHUNK_TY m2 = allones >> (SYMEM_BLOCK_SIZE - size - hcave_sz);
    SYMEM_CHUNK_TY mm = m1 & m2;

    return m_AllSymbolList.GetCellList(SymList, addr, size) ;
}

bool SYMemState::readSymbolicValue(ulong addr, ulong size, KVExprPtr &e) {
     // Complicate cases: need to split or merge?
    ulong aligned_addr = addr & SYMEM_BLOCK_MASK;
    ulong hcave_sz = addr - aligned_addr;
    if (hcave_sz + size > SYMEM_BLOCK_SIZE) {
        FIX_ME();  // Doesn't support cross-chunk memory read
    }

    SYMemChunk *c = m_Bitmap.findSYMemChunk(aligned_addr);
    assert(c != NULL);

    SYMEM_CHUNK_TY allones = -1U;
    SYMEM_CHUNK_TY m1 = allones << hcave_sz;
    SYMEM_CHUNK_TY m2 = allones >> (SYMEM_BLOCK_SIZE - size - hcave_sz);
    SYMEM_CHUNK_TY mm = m1 & m2;

    // read symbol list from m_AllSymbolList
    SymCellPtr symList, tmp ;
    int i = 0, symsize = 0 ;
    long v ;
    readConcreteValue (addr, size, v) ;
    m_AllSymbolList.GetExpr (addr, size, (uint64_t)v, e) ;
    
    return true ;
}

/****************************************** Read & write concrete value **************************/
bool SYMemState::writeConcreteValue(ulong address, ulong size, long v) {

    switch (size) {
        case 1: {
            char *addr = (char *)address;
            *addr = (char)v;
        } break;
        case 2: {
            short *addr = (short *)address;
            *addr = (short)v;
        } break;
        case 4: {
            int *addr = (int *)address;
            *addr = (int)v;
        } break;
        case 8: {
            long *addr = (long *)address;
            *addr = (long)v;
        } break;
        default: {
            cerr << "Unexpected length"
                 << "\n";
            return false;
        } break;
    }
    return true;
}

bool SYMemState::readConcreteValue(ulong address, ulong size, long &v) {
    switch (size) {
        case 1: {
            char *addr = (char *)address;
            v = (ulong)(*addr);
        } break;
        case 2: {
            short *addr = (short *)address;
            v = (ulong)(*addr);
        } break;
        case 4: {
            int *addr = (int *)address;
            v = (ulong)(*addr);
        } break;
        case 8: {
            long *addr = (long *)address;
            v = (ulong)(*addr);
        } break;
        default: {
            cerr << "Unexpected length"
                 << "\n";
            return false;
        } break;
    }
    return true;
}

void SYMemState::backup () {
    m_Bitmap.backup() ;
    m_AllSymbolList.backup() ;
}

void SYMemState::restore () {
    m_Bitmap.restore() ;
    m_AllSymbolList.restore() ;
}