#include "HistoryTree.h"
#include <iostream>
#include <fstream>
using namespace std;

uint64_t NodeHash (uint64_t s, uint64_t count) {
    uint64_t hash = s ;
    return hash;
}

HistoryNode::HistoryNode (uint64_t s, uint64_t e,  uint64_t c, bool b) {

    s_addr = s ;
    e_addr = e ;
    count = c ;
    bReachable = b ;
    s_hash = NodeHash(s, c) ;
    e_hash = NodeHash(e, c) ;
    left=right=NULL ;
    bDone = false ;
}

HistoryNode::HistoryNode (HistoryNodePtr node) {
    s_addr = node->s_addr ;
    e_addr = node->e_addr ;
    count = node->count ;
    bReachable = node->bReachable ;
    s_hash = node->getSHashValue() ;
    e_hash = node->getEHashValue() ;
    left=right=NULL ;
    bDone = false ;
}

bool HistoryNode::isDone() {
    return bDone ;
}

//not used
bool HistoryManager::LoadNodeFromCFG(uint64_t base) {
    // load all node from cfg file 
    // the format is : ?
    // start_address end_address reachable.
    
    return true ;

    string fname = "path/input.txt" ;
    string line ;

    ifstream theFile;

    long long unsigned int s, e ;
    int iReachable ;
    bool bReachable ;
    HistoryNodePtr node ;
    
    if (!s_allNode.empty()) 
        return true ;

    theFile.open (fname);
    
    if(!theFile) {
        std::cout << "error open file!" << std::endl ;
        return false ;
    }
    
    while (std::getline(theFile, line)) {
        sscanf(line.c_str(), "%llx %llx %d", &s, &e, &iReachable) ;
        bReachable = (iReachable!=0) ;
        node.reset(new HistoryNode(s|base, e|base, 0, bReachable)) ;
        s_allNode[node->getSHashValue()] = node ;
        e_allNode[node->getEHashValue()] = node ;
    }
    theFile.close() ;
    
    return true ;
}
//
// address is the address of current branch instruction;
// branch1 is the first choice of next instruction address;
// branch2 is the second choice of next instruction address;
//
// will return a address branch1 or branch2 if possible, or:
// return 1: left is reachable, but it is already expored (loop)
// return 0: right is reachable, but it is already expored (loop)
// return -1: current is done, or both left/right are unreachable.

uint64_t HistoryManager::getExecAddress (uint64_t address, uint64_t branch1, uint64_t branch2) {
    
    uint64_t hash ;
    HistoryNodePtr /*cur=NULL,*/ left=NULL, right=NULL;
    
    hash = NodeHash (address, 0) ;

    if(runstack.empty()) {
        m_current = header ;
        runstack.push(m_current) ;
    }
    runpath.push_back(address) ;
    left = m_current->getLeft() ;
    right = m_current->getRight() ;
    
    if(!left) {
        left = fakeend ;
        HistoryNodePtr nodePtr ;
        hash = NodeHash(branch1, 0) ;
        auto it = s_allNode.find(hash) ;
        if (it==s_allNode.end()) {
            nodePtr.reset(new HistoryNode(branch1, 0, 0, true)) ;
            s_allNode[hash] = nodePtr ;
        } else {
            nodePtr = it->second ;
        }
        
        left.reset(new HistoryNode(nodePtr)) ;
        m_current->setLeft(left) ;
        m_current = left ;
        if(findInRunpath(branch1)) {
            runpath.push_back(branch1) ;
            runpath.push_back(0) ;
            return 1 ;  //we meet a loop, discuss ??
        }
    }
    
    if (!left->getReachable()) {
        left->doneIt() ;
    }

    if(left->getReachable() && !left->isDone()) {
        assert(branch1 == left->getStartAddr()) ;
        m_current = left ;

        runstack.push(m_current) ;
        runpath.push_back(branch1) ;
        return branch1 ;
    }
    

    if(!right) {
        right = fakeend ;
        HistoryNodePtr nodePtr ;
        hash = NodeHash(branch2, 0) ;
        
        auto it = s_allNode.find(hash) ;
        if (it==s_allNode.end()) {
            nodePtr.reset(new HistoryNode(branch2, 0, 0, true)) ;
            s_allNode[hash] = nodePtr ;
        } else {
            nodePtr = it->second ;
        }

        
        right.reset(new HistoryNode(nodePtr)) ;
        m_current->setRight(right) ;
        m_current = right ;
        if(findInRunpath(branch2)) {
            runpath.push_back(branch2) ;
            runpath.push_back(0) ;
            return 0 ;
        }
        
    }
    
    if (!right->getReachable()) {
        right->doneIt() ;
    }

    if(right->getReachable() && !right->isDone()) {
        assert(branch2 == right->getStartAddr()) ;
        m_current = right ;

        runstack.push(m_current) ;
        runpath.push_back(branch2) ;
        return branch2 ;
    }

    runpath.push_back(0) ;
    return -1 ;
}

bool HistoryManager::findInRunpath(uint64_t addr) {
    for (uint64_t n: runpath) {
        if (n==addr)
            return true ;
    }
    return false ;
}
extern void print_pf_fixed() ;
bool HistoryManager::endCurrrentExecution(std::set<KVExprPtr> c) {

    HistoryNodePtr nodePtr, left, right ;
    m_current->doneIt() ;

    while (!runstack.empty()) {

        nodePtr = runstack.top() ;
        
        if(nodePtr->isDone()) 
        {
            runstack.pop() ;
            continue ;
        }
        
        left = nodePtr->getLeft () ;
        right = nodePtr->getRight () ;

        if ((left && left->isDone()) && 
            (right && right->isDone())) {
                nodePtr->doneIt() ;
            } else {
                break ;
            }
    }

    all_runpaths.push_back(runpath) ;
    all_constraint.push_back(c) ;
    print_pf_fixed () ;

    runpath.clear() ;

    if(!runstack.empty()) {
        m_current = header ;
    }
    else {
        printf ("empty run stack!!!!!!\n") ;
        print () ;
        {
            extern void printHMTime () ;
            printHMTime () ;
        }
        assert (0) ;  //assert after all paths are explored, improve later
    }

    return true ;
}

bool HistoryManager::printCurrentRunpath(RunPath *rp) {
    static int counter = 1; 
    printf ("Current runpath: %d\n", counter) ;
    counter ++ ;
    for(unsigned long long n: *rp) {
        std::cout << std::hex << "0x" << n << ", ";
    }
    std::cout << std::endl ;
}

bool HistoryManager::print(void) {
    std::cout << std::endl << "++++++++++++++++ THE END ++++++++++++++++" << std::endl ;
    
    std::cout << std::endl << all_runpaths.size() << std::endl ;
    
    auto it_c=all_constraint.begin() ; 
    
    for(auto it_path=all_runpaths.begin() ; 
        (it_c != all_constraint.end()) && (it_path != all_runpaths.end()); 
        it_path++, it_c++) {
        for(unsigned long long n: *it_path) {
            std::cout << std::hex << "0x" << n << ", ";
        }
        std::cout << std::endl ;
        
        for(auto itit : *it_c) {
            itit->print() ;
            std::cout << "\n" ;
        }
        std::cout << std::endl;
    }
}
