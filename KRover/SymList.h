#ifndef __SYMLIST_H__
#define __SYMLIST_H__

#include "defines.h"

struct SymCell {
    SymCellPtr next, prev;
    int64_t addr ;
    int size ;
    KVExprPtr exprPtr ;
    SymCell () {
        addr = 0;
        size = 0 ;
        exprPtr = NULL ;
        next = prev = NULL ;
    } ;
    SymCell (int64_t o, int s, KVExprPtr ptr) {
        addr = o;
        size = s ;
        exprPtr = ptr ;
        next = prev = NULL ;
    } ;
    SymCell (SymCellPtr c) {
        next = prev = NULL ;
        addr = c->addr ;
        size = c->size ;
        exprPtr = c->exprPtr ;
    }
 
    bool operator < (SymCell c1) {
        return (addr < c1.addr) ;
    } ;
    bool operator > (SymCell c1) {
        return (addr > c1.addr) ;
    } ;
    bool operator <= (SymCell c1) {
        return (addr <= c1.addr) ;
    } ;
    bool operator >= (SymCell c1) {
        return (addr >= c1.addr) ;
    } ;
    bool operator == (SymCell c1) {
        return (addr == c1.addr) ;
    } ;
} ;

typedef std::map<int64_t, SymCellPtr> SymCellMap ;

class Symbol_List_Map {
        SymCellPtr m_sl ;
        SymCellMap m_sm ;
        SymCellPtr m_listheader, m_listtail ;

        SymCellMap m_sm_back ;
        SymCellPtr m_listheader_back, m_listtail_back ;

        bool GetAffectedCells (SymCellPtr &insertAfter, SymCellPtr &insertBefore, 
                    int64_t header_start, int64_t tail_end) ;
        
        bool SplitCell3 (SymCellPtr &insertAfter, SymCellPtr &insertBefore, 
                    int64_t header_start, int64_t tail_end, bool read=false) ;
        
        bool SeplitCell_Head (SymCellPtr &insertAfter, int64_t header_start, bool read=false) ;
        
        bool SeplitCell_Tail (SymCellPtr &insertBefore, int64_t tail_end, bool read=false) ;
        bool Split_Head_Tail (SymCellPtr &insertAfter, SymCellPtr &insertBefore,
                int64_t header_start, int64_t tail_end, bool read=false) ;

        bool Remove (SymCellPtr &insertAfter, SymCellPtr &insertBefore) ;

        bool CreateSymbolList (SymCellPtr &out, SymCellPtr &After, SymCellPtr &Before, 
                    int64_t s, int64_t e) ;

        public:
            Symbol_List_Map () ;
            ~Symbol_List_Map () ;

            bool Merge (SymCellPtr src_list, uint64_t s, uint64_t e) ;
            bool Remove (uint64_t addr, int size) ;
            bool GetCellList (SymCellPtr &cellList, int64_t addr, int size) ;
            bool GetExpr (int64_t addr, int size, int64_t concreteV, KVExprPtr &e) ;


            void backup () ;
            void restore () ;


} ;
extern void printCellList (SymCellPtr cellList) ;
#endif //__SYMLIST_H__