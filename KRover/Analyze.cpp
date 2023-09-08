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
std::map<unsigned long, anaMemBlk*> ana_memblk_map;

int             dispatch_count = 0;
unsigned long   scall_handler_address = 0x0;

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

void CAnalyze::setupScallAnalysis(){

    bool ret = m_AnaCtrl->setupKernSymMap();
    if(!ret)
        assert(0);
    scall_handler_address = m_AnaCtrl->kernel_symbol_lookup("__x64_sys_getpriority");
    if(!scall_handler_address)
        assert(0);
}


int CAnalyze::onEndOfInsExec(){ //analysis at the end of each instruction

    if(m_regs->regs.rsp > execData->start_rsp){
        std::cout << "\nEnd of SE ..." << std::endl;
        std::cout << "path constraints : " << std::endl;
        a_EFlagsMgr->PrintConstraint();
        return -1;
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
        setupScallAnalysis();
        m_AnaCtrl->InstallINT3Probe(scall_handler_address); //install an int3 probe at sclla handler start
        dispatch_count++;
        return true; //dispatch for native execution
    }
    m_AnaCtrl->removeLastInt3(); //remove the int3 probe
    if(dispatch_count == 1){
        m_regs->regs.rip = m_regs->regs.rip - 5;
        setExecProfile();
        tmp = m_regs->regs.rdi; //base address of pt_regs object passed to syscall handler
        scall = *((unsigned long*)(tmp+0x8*15)); //16th element in pt_regs is syscall no
        std::cout << "syscall idx : " << std::dec << scall << std::endl;
        m_AnaCtrl->defineSymbolsForScalls(scall, tmp);
    }
    dispatch_count++;
    m_Thin->processFunction(addr); //start symbolic analysis

    return true;
}











