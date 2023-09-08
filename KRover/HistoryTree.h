#ifndef HISTOTREE_H
#define HISTOTREE_H

#include <memory>
#include <stack>
#include <set>
#include "Expr.h"

extern uint64_t NodeHash (uint64_t s, uint64_t count) ;
class HistoryNode ;

typedef std::shared_ptr<HistoryNode> HistoryNodePtr;
typedef std::vector<unsigned long long> RunPath ;
typedef std::shared_ptr<RunPath> RunPathPtr ;
typedef std::vector<RunPath> RunPathAll ;



class HistoryNode {

    uint64_t s_addr ;
    uint64_t e_addr ;
    uint64_t count ;
    uint64_t s_hash, e_hash ;
    bool bReachable ;
    bool bDone ;

    HistoryNodePtr left, right ;

    public :
        HistoryNode (uint64_t s, uint64_t e,  uint64_t c, bool b) ;
        HistoryNode (HistoryNode& node) ;

        HistoryNode (HistoryNode* node) ;
        HistoryNode (HistoryNodePtr node) ;

        ~HistoryNode () {} ;


        HistoryNodePtr getLeft() {return left;} ;
        HistoryNodePtr getRight() {return right;} ;

        void setLeft(HistoryNodePtr l) {left=l;} ;
        void setRight(HistoryNodePtr r) {right=r;} ;

        uint64_t getSHashValue(void) {return s_hash;} ;
        uint64_t getEHashValue(void) {return e_hash;} ;

        uint64_t getStartAddr(void) {return s_addr;} ;
        uint64_t getEndAddr(void) {return e_addr;} ;
        
        bool getReachable(void) {return bReachable;} ;
        bool isDone(void) ;
        void doneIt(void) {bDone=true;return;}
} ;

class HistoryManager {
    
    HistoryNodePtr header ;
    HistoryNodePtr fakeend ;
    HistoryNodePtr m_current ;

    uint64_t start, end ;

    std::map<uint64_t, HistoryNodePtr> s_allNode ;
    std::map<uint64_t, HistoryNodePtr> e_allNode ;
    std::stack<HistoryNodePtr> runstack ;
    
    RunPath runpath ;
    RunPathAll all_runpaths ;

    std::vector<std::set<KVExprPtr>> all_constraint;

    public :
        HistoryManager (uint64_t s, uint64_t e) {

            start = s, end = e ;
            s_allNode.clear() ;
            e_allNode.clear() ;
            header.reset(new HistoryNode(-1, -1, -1, false)) ;
            fakeend.reset(new HistoryNode(-1, -1, -1, false)) ;
            
            fakeend->doneIt() ;

            m_current = header ;
            runpath.clear() ;
        } ;
        ~HistoryManager () {} ;

        bool LoadNodeFromCFG(uint64_t base) ;

        uint64_t getExecAddress (uint64_t address, uint64_t branch1, uint64_t branch2) ;

        bool findInRunpath(uint64_t addr) ;
        bool endCurrrentExecution(std::set<KVExprPtr> c) ;
        bool print(void) ;
        bool printCurrentRunpath(RunPath* rp) ;

} ;

#endif // HISTOTREE_H