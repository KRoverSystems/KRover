#include "Analyze.h"
#include <asm/ptrace.h>
#include "VMState.h"
#include "HistoryTree.h"
#include "thinctrl.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

struct MacReg*  m_regs;
int             dispatch_count = 0;
int             ana_round = 0;
int             ana_memblk_no = 0;
unsigned long   printk_address = 0x0;
unsigned long   kill_handler_address = 0x0;
bool            kill_started = false;
unsigned long   rootkit_kmod_object_address;
unsigned long   rootkit_core_layout_base;
unsigned long   rootkit_core_layout_end;
unsigned long   dynamic_symbol_count = 0x0;
string          rootkit_name = "umbra";
string          sym_base = "dynamic_symbol_";
anaMemBlk       anaMemBlk_pool[64];
std::map<unsigned long, anaMemBlk*> ana_memblk_map;
static struct MacReg targ_tmpMRegs ;
extern HistoryManager *g_hm ;

CAnalyze::CAnalyze(VMState *VM, EveMeta* meta) {
    m_VM = VM;
    execData = new ExecData;
    execData->insn_count = 0; 
    execProfile = new ExecProfile;
    execProfile->executionMode = 0; /*DEFAULT, single pat hseeded*/
    execProfile->terminationMode = 0; /*DEFAULT, terminate at stack balance, function return*/
}

CAnalyze::~CAnalyze() {
}

void CAnalyze::setExecProfile(){
        execProfile->executionMode = EXEC_MD_SINGLE_PATH_SEDED;
        execProfile->terminationMode = END_AT_ANA_REQUEST;
        execData->start_rsp = m_regs->regs.rsp; 
}

int CAnalyze::chkAndDeclareSymbols(unsigned long mem_adr, int mem_size){ //return values: NO_NEW_ACTION, DO_CIE, DO_SIE, END_EXECUTION
    int ret = NO_NEW_ACTION;
    MemValue MV{mem_adr, (unsigned long)mem_size}; //read memory and then check if already symbolic
    bool res = m_VM->readMemory(MV);
    assert(res);
    if (MV.bsym) {
        std::cout << "memory is already symbolic" << std::endl;
    }
    else{
        uint64_t seed;
        if(mem_size == 0x8){
            seed= MV.i64;
        }
        else if(mem_size == 0x4)
            seed = MV.i32;
        else
            assert(0);
        dynamic_symbol_count++;
        string symbol_name = sym_base + to_string(dynamic_symbol_count);
        std::cout << "dynamic declaration of symbol: " << symbol_name << std::endl;
        m_VM->createSYMemObject(mem_adr, mem_size, 1, 1, seed, symbol_name.c_str()); //symbolize
        ana_memblk_map[mem_adr]->is_dyn_sym = true; //record symbol details in map
        ana_memblk_map[mem_adr]->sym_size = mem_size;
        ana_memblk_map[mem_adr]->sym_name = symbol_name;
        ret = DO_SIE;
    }
    return ret;
}

void CAnalyze::setupRootkitAnalysis(){
    bool ret = m_AnaCtrl->setupKernSymMap();
    if(!ret)
        assert(0);
    printk_address = m_AnaCtrl->kernel_symbol_lookup("printk");
    kill_handler_address = m_AnaCtrl->kernel_symbol_lookup("__x64_sys_kill");
    rootkit_kmod_object_address = m_AnaCtrl->kernel_module_object_lookup(rootkit_name);
    if(!printk_address || !kill_handler_address || !rootkit_kmod_object_address)
        assert(0);
    rootkit_core_layout_base = (unsigned long)((struct module*)rootkit_kmod_object_address)->core_layout.base; //introspect to get rootkit base adr
    rootkit_core_layout_end  = rootkit_core_layout_base + (unsigned long)((struct module*)rootkit_kmod_object_address)->core_layout.size; //introspect to get sz
    if(!rootkit_core_layout_end || !rootkit_core_layout_base)
        assert(0);
}

bool CAnalyze::isAdrWithinModue(unsigned long ip){
    return (ip >= rootkit_core_layout_base && ip < rootkit_core_layout_end); /*this follows the logic of kernel's "within_module" function*/
}

int CAnalyze::checkOperandsMemAccess(int operand_nu, unsigned long adr){
    if(isAdrWithinModue(adr)){ //in-module memory access"
        std::set<uint> r_readRegIds =  execData->win->opdata_ptrs[operand_nu]->readRegIds;
        if(!r_readRegIds.empty()){
            if(execData->opDetails[operand_nu].opmemac.rdmem){
                if(r_readRegIds.find(x86_64::rip) != r_readRegIds.end())
                    return 1; //rootkit global data read
            }
        }
    }
    else{
        std::set<uint> r_readRegIds =  execData->win->opdata_ptrs[operand_nu]->readRegIds;
        if(execData->opDetails[operand_nu].opmemac.rdmem){
            if(execData->win->igs_base) //check if the global memory access is using GS base -> accessing thread local storge
                return 3; //kernel global mem access trough GS : TLS access
            else if(!m_AnaCtrl->reverse_kernel_symbol_lookup(execData->opDetails[operand_nu].opmemac.memAddress).empty()) //check if the address is resolvable through kernel symbols, i.e. a non-TLS(shared across entire kernel) data access
                return 4; //kernel global SYMbol, kernel non-TLS global data access
        }
    }
    return 0;
}

int CAnalyze::onBeforeCIESIE(){ //analyzes instructions before thery are dispatched for CIE or SIE
    int ret = NO_NEW_ACTION;
    if(ana_round != 1){
        return ret;
    }
    if(execData->opDetails[0].opmemac.memrdwr || execData->opDetails[1].opmemac.memrdwr){
        unsigned long adr;
        InsnCategory cate = execData->win->in->getCategory();
        int result = 0;
        if (cate != c_ReturnInsn && cate != c_CallInsn && cate != c_BranchInsn){
            if(execData->opDetails[0].opmemac.rdmem){
                adr = execData->opDetails[0].opmemac.memAddress;
                result = checkOperandsMemAccess(0, adr);
                if(result > 0){
                    if(ana_memblk_map.find(adr) == ana_memblk_map.end()){  //if adr is in rootkit TLS or kernel global add to map
                        anaMemBlk_pool[ana_memblk_no].is_read = true;
                        ana_memblk_map[adr] = &anaMemBlk_pool[ana_memblk_no];
                        ana_memblk_no++;
                    }              
                    return chkAndDeclareSymbols(adr, execData->opDetails[0].opmemac.size);
                }
            }
            if(execData->opDetails[1].opmemac.rdmem){
                adr = execData->opDetails[1].opmemac.memAddress;
                result = checkOperandsMemAccess(1, adr);
                if(result > 0){
                    if(ana_memblk_map.find(adr) == ana_memblk_map.end()){  //if adr is in rootkit TLS or kernel global add to map
                        anaMemBlk_pool[ana_memblk_no].is_read = true;
                        ana_memblk_map[adr] = &anaMemBlk_pool[ana_memblk_no];
                        ana_memblk_no++;
                    }
                    return chkAndDeclareSymbols(adr, execData->opDetails[1].opmemac.size);
                }
            }
            if(execData->opDetails[0].opmemac.wrmem){
                adr = execData->opDetails[0].opmemac.memAddress;
                if(ana_memblk_map.find(adr) != ana_memblk_map.end()){  //record if this is a write to a previously read kernel global or rootkit TLS mem
                    anaMemBlk *mblk = ana_memblk_map[adr];
                    if(mblk->is_read)
                        mblk->is_write = true;
                }
            }
            if(execData->opDetails[1].opmemac.wrmem){
                adr = execData->opDetails[1].opmemac.memAddress;
                if(ana_memblk_map.find(adr) != ana_memblk_map.end()){  //record if this is a wite to a previously read kernel global or rootkit TLS mem
                    anaMemBlk *mblk = ana_memblk_map[adr];
                    if(mblk->is_read)
                        mblk->is_write = true;
                }
            }
        }
    }
    return ret;
}

int CAnalyze::onEndOfInsDecode(){ //analyzes right after instruction decode
    extern void init_pgTable() ;  //set all pages to read only except?
    extern void restore_pages() ; //restore 
    if(execData->insn_count == 0){
        ana_round++;
        if(ana_round == 1){ 
            unsigned long current_rdi = m_regs->regs.rdi; 
            unsigned long signal_adr = (unsigned long)(&((pt_regs*)current_rdi)->rsi); //obtain kernel address holding signal number
            unsigned long signal     = ((pt_regs*)current_rdi)->rsi; //obtain the signal number to be used as the seed
            m_VM->createSYMemObject(signal_adr, 8, 1, 1, signal, "sig_rsi"); //symbolizing kill scall arg 2
            //first run is a seeded run, but we intend to restore the starting state for path search later, backup state
            m_VM->ReadCPUState(m_VM, &targ_tmpMRegs) ;
            a_EFlagsMgr->backup();
            m_VM->backup() ;
            init_pgTable () ; //setup targ mem pages as read only
        }
        else
            std::cout << "//Parth search : start PATH: " << std::dec << ana_round - 1  << "-----------------------------------------------------------------------" << std::endl;
    }
    return 0;
}

int CAnalyze::onEndOfInsExec(){ //analysis at the end of each instruction
    extern void init_pgTable() ;  //set all pages to read only except pgtable pages?
    extern void restore_pages() ; //restore 
    if(m_regs->regs.rsp > execData->start_rsp){// && execData->win->cate == c_ReturnInsn){
        std::cout << "\nat end cur exec ..." << std::endl;
        if(ana_round == 1){
            std::cout << "rootkit TLS or kernel global addresses subjected to read then write" << std::endl;
            for(auto it = ana_memblk_map.begin(); it != ana_memblk_map.end(); it++){
                if(it->second->is_read && it->second->is_write){
                    std::cout << "adr:0x" << std::hex << it->first << ":" << it->second->sym_name<< std::endl;
                }
            }
            std::cout << "dynamic symbolizations of rootkit TLS or kernel global mem" << std::endl;
            for(auto it = ana_memblk_map.begin(); it != ana_memblk_map.end(); it++){
                std::cout << "adr:0x" << std::hex << it->first << " sym: " << it->second->sym_name << std::endl;
            }
            std::cout << "npath_const_begin_kr" << std::endl;
            std::cout << "Path constriints: " << std::endl;
            a_EFlagsMgr->PrintConstraint();
            std::cout << "npath_const_end_kr" << std::endl;
            m_AnaCtrl->chkSymsInCOnstraints();     //find dynamic memory symbols ended in path constraints
            std::cout << "Ending seeded SE round, instruction count: " << std::dec << execData->insn_count << std::endl;
            m_Thin->bPath_explore = true;         //to enable history tree
        }
        else{ //ana_round > 1
            std::cout << "checking if the newly symbolized memory has been updated in current path" << std::endl;
            for(auto it = ana_memblk_map.begin(); it != ana_memblk_map.end(); it++){
                if(it->second->symbol_for_path_exp){
                    unsigned long adr = it->first;
                    uint size = it->second->sym_size;
                    std::cout << it->second->sym_name << " size:" << std::dec << size << std::endl;
                    MemValue MV{adr, size}; 
                    bool ret = m_VM->readMemory(MV);
                    assert(ret);
                    if(MV.bsym){
                        std::cout << "symbolic" << std::endl;
                        MV.expr->print();
                        std::cout << std::endl;
                    }
                    else{
                        if(size == 0x8)
                            std::cout << "non-symbolic : " << std::dec << MV.i64 << std::endl;
                        if(size == 0x4)
                            std::cout << "non-symbolic : " << std::dec << MV.i32 << std::endl;
                    }
                }
            }
            std::cout << "//Parth search : end PATH: " << std::dec << ana_round - 1  << "-----------------------------------------------------------------------" << std::endl;
            g_hm->endCurrrentExecution(a_EFlagsMgr->getConstraint()); //end the current path exploration round
        }
        execData->insn_count = 0;   //Since the state has been restored to the original starting point[i.e. state bfr very first ins is execed], update the count as well
        m_VM->SetCPUState(m_VM, &targ_tmpMRegs) ;   //restore the kernel state and updated mem pages
        m_VM->restore() ;
        a_EFlagsMgr->restore();
        restore_pages () ;
        for(auto it = ana_memblk_map.begin(); it != ana_memblk_map.end(); it++){  //define new memory symbols for path exploration
            if(it->second->symbol_for_path_exp){
                std::cout << "defining symbolic memory for path search.." << std::endl;
                unsigned long mem_adr = it->first;
                unsigned long mem_size = it->second->sym_size;
                m_VM->createSYMemObject(mem_adr, mem_size, 1, 1, 0, it->second->sym_name.c_str()); 
            }
        }
        return 1;
    }
    if(m_regs->regs.rip == printk_address){
        unsigned long printk_return_address = *((unsigned long*) (m_regs->regs.rsp));
        m_regs->regs.rip = printk_return_address;
        m_regs->regs.rsp += 0x8;
    }
    return 1;
}

int CAnalyze::analyztsHub(int anaPoint) { //analysis of KRover's SE by analyzer goes through this hub
    std::cout << "at analyztsHub" << std::endl;
    switch(anaPoint){
        case ON_END_OF_INS_EXEC:
        {
            return CAnalyze::onEndOfInsExec();
        }   break;
        case ON_BFR_CIE_OR_SIE:
        {
            return CAnalyze::onBeforeCIESIE();
        }   break;
        case ON_END_OF_INS_DECODE:
        {
            return CAnalyze::onEndOfInsDecode();
        }   break;
        default:
            break;
    }
    return 0;
}

bool CAnalyze::beginAnalysis(ulong addr) { //Analysis start
    m_regs = (struct MacReg*)m_VM->getPTRegs();
    unsigned long scall;
    unsigned long tmp;
    std::cout << "at beginAnalysis\n " << std::endl;
    if(dispatch_count == 0){
        setupRootkitAnalysis();
        m_AnaCtrl->InstallINT3Probe(kill_handler_address); //install an int3 probe
        dispatch_count++;
        return true; //dispatch for native execution
    }
    m_AnaCtrl->removeLastInt3(); //remove the int3 probe
    if(dispatch_count == 1){
        m_regs->regs.rip = m_regs->regs.rip - 5;
        setExecProfile();
    }
    dispatch_count++;
    m_Thin->processFunction(addr); //start symbolic analysis
    return true;
}











