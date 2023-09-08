#include <assert.h>
#include <signal.h>
#include <ucontext.h>
#include <functional>
#include <map>
#include <string>
#include <vector>
#include <string.h>
#include <list>
#include <memory>
#include "SymList.h"
#include "Expr.h"

using namespace EXPR;

#define ADDR_TO_KEY(addr) ((addr)&0x7FFFFFFFFFFFFFFL)

Symbol_List_Map::Symbol_List_Map ():m_listheader(), m_listtail() {

    m_listheader.reset(new SymCell((int64_t) (0xF000000000000000), 0, NULL)) ;
    m_listtail.reset(new SymCell(0x7FFFFFFFFFFFFFFLL, 0, NULL)) ;
    
    m_listheader->next = m_listtail ;
    m_listtail->prev = m_listheader ;
    
    m_sl = m_listheader ;
    
    m_sm[-1] = m_listheader ;
    m_sm[ADDR_TO_KEY(m_listtail->addr)] = m_listtail ;
}

Symbol_List_Map::~Symbol_List_Map () {
    m_sm.clear () ;
}

bool Symbol_List_Map::GetAffectedCells (SymCellPtr &insertAfter, SymCellPtr &insertBefore, 
                    int64_t header_start, int64_t tail_end) {
    bool insertAfterFound = false ,insertBeforeFound = false ;
    insertAfter = m_listheader ;
    auto it = m_sm.find(ADDR_TO_KEY(header_start)) ;
    
    if (it != m_sm.end()) {
        // can find in hash table, dont need to iterate 
        insertAfter = it->second ;
        insertAfter = insertAfter->prev ;
        insertAfterFound = true ;
    }
    insertBefore = insertAfter ;

    do {
        if(!insertAfterFound)
        {
            if (insertAfter->addr < header_start && 
                header_start <= insertAfter->next->addr) {
                
                insertAfterFound = true ;
            } else {
                insertAfter = insertAfter->next ;
            }
        }
        if (!insertBeforeFound) {
            if (insertBefore->addr+insertBefore->size <= tail_end && 
                tail_end < insertBefore->next->addr + insertBefore->next->size) {

                insertBefore = insertBefore->next ;
                insertBeforeFound = true ;
            } else {
                insertBefore = insertBefore->next ;
            }
        }
    } while(!insertAfterFound || !insertBeforeFound) ;

    return true ;
}

bool Symbol_List_Map::SplitCell3 (SymCellPtr &insertAfter, SymCellPtr &insertBefore, 
                   int64_t header_start, int64_t tail_end, bool read) {
    // insertBefore is same as insertAfter 
    int64_t p1_a, p1_s, p3_a, p3_s, p2_a, p2_s ;

    p1_a = insertAfter->addr ;
    p1_s = header_start-insertAfter->addr ;

    p3_a = tail_end ;
    p3_s = insertAfter->addr+insertAfter->size - tail_end ;

    p2_a = p1_a + p1_s ;
    p2_s = p3_a - p2_a ;

    KVExprPtr e1(new ExtractExpr(insertAfter->exprPtr, 0, p1_s)) ;
    KVExprPtr e3(new ExtractExpr(insertAfter->exprPtr, (p3_a-p1_a), (p3_a-p1_a) + p3_s)) ;
    KVExprPtr e2(new ExtractExpr(insertAfter->exprPtr, (p2_a-p1_a), (p2_a-p1_a) + p2_s)) ;
    SymCellPtr p3(new SymCell(p3_a, p3_s, e3)) ;
    SymCellPtr p2(new SymCell(p2_a, p2_s, e2)) ;

    insertAfter->size = p1_s ;
    insertAfter->exprPtr = e1 ;

    p2->prev=insertAfter ;
    p2->next=p3;

    if(insertAfter->next != NULL) {
        insertAfter->next->prev = p3 ;
    }

    p3->next = insertAfter->next ;
    p3->prev = p2 ;

    insertAfter->next = p2 ;
    
    if (!read) {
        m_sm[ADDR_TO_KEY(p3->addr)] = p3 ;
        m_sm[ADDR_TO_KEY(p2->addr)] = p2 ;
        m_sm[ADDR_TO_KEY(insertAfter->addr)] = insertAfter ;
    }
    
    insertBefore = p3 ;
}

bool Symbol_List_Map::SeplitCell_Head(SymCellPtr &insertAfter, int64_t header_start, bool read) {

    int64_t p1_a = insertAfter->addr, p2_a = header_start ;
    int p1_s = header_start-insertAfter->addr, p2_s = insertAfter->addr+insertAfter->size - header_start ;

    KVExprPtr e1(new ExtractExpr(insertAfter->exprPtr, 0, p1_s)) ;
    KVExprPtr e2(new ExtractExpr(insertAfter->exprPtr, (p2_a-p1_a), (p2_a-p1_a) + p2_s)) ;
    
    SymCellPtr p2(new SymCell(p2_a, p2_s, e2)) ;
    
    insertAfter->size = p1_s ;
    insertAfter->exprPtr = e1 ;

    p2->next = insertAfter->next ;
    if(insertAfter->next != NULL) {
        insertAfter->next->prev = p2 ;
    }

    p2->prev = insertAfter ;
    insertAfter->next = p2 ;
    
    if (!read) {
        m_sm[ADDR_TO_KEY(p2->addr)] = p2 ;
        m_sm[ADDR_TO_KEY(insertAfter->addr)] = insertAfter ;
    }
}

bool Symbol_List_Map::SeplitCell_Tail(SymCellPtr &insertBefore, int64_t tail_end, bool read){
    int64_t p2_a = tail_end, p1_a = insertBefore->addr;
    int p2_s = insertBefore->addr+insertBefore->size - tail_end, p1_s = tail_end-insertBefore->addr;

    KVExprPtr e2(new ExtractExpr(insertBefore->exprPtr, (tail_end-insertBefore->addr), (tail_end-insertBefore->addr) + p2_s)) ;
    KVExprPtr e1(new ExtractExpr(insertBefore->exprPtr, 0, p1_s)) ;
    
    SymCellPtr p1(new SymCell(p1_a, p1_s, e1)) ;

    insertBefore->addr = p2_a ;
    insertBefore->size = p2_s ;
    insertBefore->exprPtr = e2 ;
    
    if(insertBefore->prev != NULL) {
        insertBefore->prev->next = p1 ;
    }
    
    p1->next = insertBefore ;
    p1->prev = insertBefore->prev ;
    insertBefore->prev = p1 ;

    if (!read) {
        m_sm[ADDR_TO_KEY(insertBefore->addr)] = insertBefore ;
        m_sm[ADDR_TO_KEY(p1->addr)] = p1 ;
    }
    return true ;
}

bool Symbol_List_Map::Split_Head_Tail(SymCellPtr &insertAfter, SymCellPtr &insertBefore,
        int64_t header_start, int64_t tail_end, bool read) {

    if(insertAfter == insertBefore) {
        if(insertAfter->addr+insertAfter->size >= tail_end) {
            SplitCell3 (insertAfter, insertBefore, header_start, tail_end, read) ;
        }
    } else {
        if(insertAfter->addr+insertAfter->size > header_start) {
            SeplitCell_Head(insertAfter, header_start, read) ;
        }
        if (insertBefore->addr < tail_end) {
            SeplitCell_Tail(insertBefore, tail_end, read) ;
        }
    }
    return true ;
}

bool Symbol_List_Map::Merge(SymCellPtr src_list, uint64_t s, uint64_t e) {
    int64_t header_start, header_end, tail_start, tail_end ;
    SymCellPtr h, t, tmp;
    SymCellPtr insertAfter, insertBefore ;

    t = h = src_list;
    while (t->next!=NULL)
        t = t->next;
    
    header_start = h->addr ;
    header_end = h->addr + h->size ;

    tail_start = t->addr ;
    tail_end = t->addr + t->size ;

    if (s<header_start) header_start = s ;
    if (e>tail_end) tail_end = e ;

    GetAffectedCells (insertAfter, insertBefore, header_start, tail_end) ;
    Split_Head_Tail (insertAfter, insertBefore, header_start, tail_end) ;
    Remove (insertAfter, insertBefore) ;

    insertAfter->next = h ;
    h->prev = insertAfter ;

    insertBefore->prev = t ;
    t->next = insertBefore ;

    do {
        m_sm[ADDR_TO_KEY(h->addr)] = h ;
        if (h == t) break ;
        h = h->next ;
    } while (1);

    return true ;
} 
bool Symbol_List_Map::Remove (SymCellPtr &insertAfter, SymCellPtr &insertBefore) {
    SymCellPtr tmp ;
    for(tmp = insertAfter->next; tmp!=insertBefore; tmp = tmp->next) {
        m_sm.erase(ADDR_TO_KEY(tmp->addr)) ;
    }
    insertAfter->next = insertBefore ;
    insertBefore->prev = insertAfter ;
}

bool Symbol_List_Map::Remove (uint64_t addr, int size) {
    
    SymCellPtr insertAfter, insertBefore ;
    
    GetAffectedCells (insertAfter, insertBefore, addr, addr+size) ;
    Split_Head_Tail (insertAfter, insertBefore, addr, addr+size) ;
    Remove (insertAfter, insertBefore) ;
    return true ;
}

bool Symbol_List_Map::CreateSymbolList (SymCellPtr &out, SymCellPtr &after, SymCellPtr &before, 
                    int64_t s, int64_t e) {
    SymCellPtr it, tmp = NULL, newCell = NULL ;
    out = NULL ;
    for(it = before; it != after; it = it->prev) {
        tmp = newCell ;

        newCell.reset(new SymCell(it)) ;
        newCell->next = tmp ;
        if (tmp != NULL)
            tmp->prev = newCell ;
    }
    tmp = newCell ;
    newCell.reset(new SymCell(it)) ;
    newCell->next = tmp ;
    if (tmp != NULL)
        tmp->prev = newCell ;

    after = newCell ;
    for(before=after; before->next!=NULL; before=before->next) ;
}

void printCellList (SymCellPtr cellList) ;
bool Symbol_List_Map::GetCellList(SymCellPtr &cellList, int64_t addr, int size) {
    SymCellPtr after, before, tmp ;
    
    GetAffectedCells (after, before, addr, addr+size) ;
    CreateSymbolList (cellList, after, before, addr, addr+size) ;

    Split_Head_Tail(after, before, addr, addr+size, true) ;

    before->prev->next = NULL ;

    cellList=after->next ;

    after->next->prev = NULL ;

    for(tmp=cellList; tmp!=NULL; tmp=tmp->next) {
        tmp->addr = tmp->addr - addr ;
    }
    
    return true ;
}

bool Symbol_List_Map::GetExpr (int64_t addr, int size, int64_t concreteV, KVExprPtr &e) {
    SymCellPtr cellList, tmp = NULL;
    int i = 0 ;
    int next_addr = 0 ;
    
    GetCellList(cellList, addr, size) ;
    // combine cell list to expr ;
    std::vector<int> sizes ;
    std::vector<int> offsets ;
    std::vector<ExprPtr> exprs ;

    for (tmp=cellList; tmp!=NULL; tmp=tmp->next) {
        
        while (next_addr < tmp->addr) {
            uint8_t* c_val = (uint8_t*)&concreteV ;

            KVExprPtr c_expr (new ConstExpr(c_val[next_addr], 1, 0)) ;

            sizes.push_back (1) ;
            offsets.push_back (next_addr) ;
            exprs.push_back (c_expr) ;
            i++ ;

            next_addr++ ;
        }
        
        sizes.push_back (tmp->size) ;
        offsets.push_back (tmp->addr) ;
        exprs.push_back (tmp->exprPtr) ;
        i++ ;

        next_addr = tmp->addr + tmp->size ;
    }
    while (next_addr < size) {
        uint8_t* c_val = (uint8_t*)&concreteV ;

        KVExprPtr c_expr (new ConstExpr(c_val[next_addr], 1, 0)) ;

        sizes.push_back (1) ;
        offsets.push_back (next_addr) ;
        exprs.push_back (c_expr) ;
        i++ ;

        next_addr++ ;
    }
    if (i>1) {
        e.reset(new CombineMultiExpr(exprs, offsets, sizes, size, 0)) ;
    } else {
        e = cellList->exprPtr ;
    }
}

void Symbol_List_Map::backup () {
   
    SymCellPtr tmp, bak, scp;
   
    m_listheader_back.reset(new SymCell(m_listheader)) ;
    m_listtail_back.reset(new SymCell(m_listtail)) ;
    
    // empty list with header / tail.
    m_listheader_back->next = m_listtail_back ;
    m_listtail_back->prev = m_listheader_back ;
    
    bak = m_listheader_back ;
    tmp = m_listheader->next ;

    scp = m_listheader_back ;
    
    m_sm_back.clear() ;
    
    m_sm_back[-1] = m_listheader_back ;
    
    while (tmp != m_listtail) {
        
        scp.reset(new SymCell(tmp)) ;
        
        scp->prev = bak ;
        scp->next = m_listtail_back ;
        
        m_listtail_back->prev = scp ;

        bak->next = scp ;

        tmp = tmp->next ;
        bak = bak->next ;

        m_sm_back[ADDR_TO_KEY(scp->addr)] = scp ;
    }
    m_sm_back[ADDR_TO_KEY(m_listtail_back->addr)] = m_listtail_back ;
}

void Symbol_List_Map::restore () {
    SymCellPtr tmp, bak, scp;
   
    m_listheader.reset(new SymCell(m_listheader_back)) ;
    m_listtail.reset(new SymCell(m_listtail_back)) ;

    m_listheader->next = m_listtail ;
    m_listtail->prev = m_listheader ;
    
    bak = m_listheader ;
    tmp = m_listheader_back->next ;

    scp = m_listheader ;

    m_sm.clear() ;
    
    m_sm[-1] = m_listheader ;

    while (tmp != m_listtail_back) {

        scp.reset(new SymCell(tmp)) ;
        
        scp->prev = bak ;
        scp->next = m_listtail ;

        m_listtail->prev = scp ;
        
        bak->next = scp ;

        tmp = tmp->next ;
        bak = bak->next ;

        m_sm[ADDR_TO_KEY(scp->addr)] = scp ;
    }

    m_sm[ADDR_TO_KEY(m_listtail->addr)] = m_listtail ;
}