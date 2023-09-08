#ifndef _SYMINFO_DB_H__
#define _SYMINFO_DB_H__

#include <linux/types.h>
#include <map>
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "defines.h"
#include "SymList.h"

// Matinain a bitmap for the whole memory. For less memory footprint,
// the whole memory is split into N-byte chuncks, and set bitmap on these chunks.
typedef uint32_t SYMEM_CHUNK_TY;
#define SYMEM_BLOCK_SIZE 32UL
#define SYMEM_BLOCK_MASK (~(SYMEM_BLOCK_SIZE - 1))

struct SYMemChunk {
    SYMEM_CHUNK_TY bitmap;   // 32 bits
    SYMEM_CHUNK_TY objmask;  // 32 bits
    SYMemChunk *l, *r;       // left and right exactly adjacent chunks;

    SYMemChunk(void) {
        bitmap = 0;
        objmask = 0;
        l = r = NULL;
    }
    
    SYMemChunk(SYMemChunk *c) {
        bitmap = c->bitmap;
        objmask = c->objmask;
        l = c->l;
        r = c->r;
    }
    ~SYMemChunk() {
        if (l)
            l->r = NULL;
        if (r)
            r->l = NULL;
    }
};
typedef std::shared_ptr<SYMemChunk> SYMemChunkPtr;

class SYMemBitmap {
   private:
    // Check if the given address contains a symboilc value;
    std::map<ulong, SYMemChunkPtr> m_SYMemBitmap;
    std::map<ulong, SYMemChunkPtr> m_SYMemBitmap_backup;

   public:
    SYMemBitmap() : m_SYMemBitmap() {}
    ~SYMemBitmap() { m_SYMemBitmap.clear(); }

    // Interfaces for querying if a memory cell is symbolic
    SYMemChunk *markSYMemBitmap(ulong addr, ulong size);
    void unmarkSYMemBitmap(ulong addr, ulong size);
    bool testSYMemBitmap(ulong addr, ulong size);

    // Return a pointer to the chunk if exist;
    SYMemChunk *findSYMemChunk(ulong addr);
    void backup () {
        SYMemChunkPtr scPtr ;
        m_SYMemBitmap_backup.clear() ;
        for(auto it: m_SYMemBitmap) {
            scPtr.reset(new SYMemChunk(it.second.get())) ;
            m_SYMemBitmap_backup[it.first] = scPtr ;
        }
        return ;
    }
    void restore () {
        SYMemChunkPtr scPtr ;
        m_SYMemBitmap.clear() ;
        for(auto it: m_SYMemBitmap_backup) {
            scPtr.reset(new SYMemChunk(it.second.get())) ;
            m_SYMemBitmap[it.first] = scPtr ;
        }
        return ;
    }

    std::map<ulong, SYMemChunkPtr> *getSysMemMap () {
        return &m_SYMemBitmap ;
    }

   private:
    SYMemChunk *_maskSYMemBitmap(ulong aligned_addr, ulong cave_size, ulong symbol_size);
    void _unmaskSYMemBitmap(ulong aligned_addr, ulong cave_size, ulong symbol_size);
    bool _testSYMemBitmap(ulong aligned_addr, ulong cave_size, ulong symbol_size);
};

// A layer of synthetic memory built on top of physical memory
class SYMemState {
    /**
 * @brief Symbolic object information database. This system is modeled as following:
 * Level-1 is a symbolic object tracking system. It splits the whole memory into 32-byte chunks
 * and use a bitmap to track the state of each chunk.
 * Level-2, for each chunck, store the symbolic objects.
 */

   private:
    // Bitmap for the whole memory
    SYMemBitmap m_Bitmap;

    Symbol_List_Map m_AllSymbolList ;

   public:
    SYMemState(void) : m_Bitmap(), m_AllSymbolList() {}
    ~SYMemState(void) { }

    bool isSYMemoryCell(ulong addr, ulong size);
    bool writeMemoryCell(MemValue &v);
    bool readMemoryCell(MemValue &v);
    bool readConcreteValue(ulong addr, ulong size, long &v);

    void backup () ;
    void restore () ;

   private:
    bool writeSymbolicValue(ulong addr, ulong size, KVExprPtr &e);
    bool writeSymbolicValue(ulong addr, ulong size, SymCellPtr &SymList) ;
    bool readSymbolicValue(ulong addr, ulong size, KVExprPtr &e);
    bool readSymbolicValue(ulong addr, ulong size, SymCellPtr &SymList) ;
    bool writeConcreteValue(ulong addr, ulong size, long v);
};

#endif  // _SYMINFO_DB_H__
