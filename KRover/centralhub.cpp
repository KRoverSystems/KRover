
#include "centralhub.h"

#include <asm/ptrace.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <map>
#include <vector>
#include "centralhub.h"
#include "VMState.h"
#include "defines.h"
#include "Analyze.h"
#include "AnaCtrl.h"
#include "thinctrl.h"

using namespace std;

/****************************** ExecState **************************/
ExecState::ExecState(ulong adds, ulong adde)
{
    m_VM.reset(new VMState());
    m_emeta.reset(new EveMeta);
    // exit(0);
    // // return;
    auto F = new CAnalyze(m_VM.get(), m_emeta.get()); 
    auto T = new CThinCtrl(m_VM.get(), adds, adde);
    auto G = new CAnaCtrl(m_VM.get(), m_emeta.get());

    F->m_Thin = T;
    m_Analyze.reset(F);
    m_ThinCtrl.reset(T);
    m_AnaCtrl.reset(G);

    m_ThinCtrl->setAna(m_Analyze) ;
    m_Analyze->setAnaCtrl(m_AnaCtrl);

    std::shared_ptr<SymExecutor> symexecutor = m_ThinCtrl->shareSymExecutor();
    std::shared_ptr<ConExecutor> conexecutor = m_ThinCtrl->shareConExecutor();
    std::shared_ptr<EFlagsManager> eflagsmgr = m_ThinCtrl->shareEflagsMgr();

    if(symexecutor != nullptr && conexecutor != nullptr && eflagsmgr != nullptr){
        m_Analyze->setSymExecutor(symexecutor);
        m_Analyze->setConExecutor(conexecutor);
        m_Analyze->setEflagsMgr(eflagsmgr);
    }
    else
        assert(0);
}

ExecState::~ExecState() {}

bool ExecState::declareSymbolicObject(ulong addr, ulong size, bool isSigned, bool hasSeed, long conVal, const char *name) {
    return m_VM->createSYMemObject(addr, size, isSigned, hasSeed, conVal, name);
}

bool ExecState::declareSymbolicRegister(uint index, uint size, bool isSigned, bool hasSeed, long conVal, const char *name) {
    return m_VM->createSYRegObject(index, size, isSigned, hasSeed, conVal, name);
}

bool ExecState::SynRegsFromNative(struct MacReg* regs)
{
    VMState::SetCPUState(m_VM.get(), regs);
    return true;
}

bool ExecState::SynRegsToNative(struct MacReg* regs)
{
    VMState::ReadCPUState(m_VM.get(), regs);
    return true;
}

bool ExecState::processAt(ulong addr) {
#ifndef _PROD_PERF
    printf("at processAt\n");
#endif

    return m_Analyze->beginAnalysis(addr);
}

bool ExecState::InstallINT3Probe(ulong addr) {
    return m_AnaCtrl->InstallINT3Probe(addr);
}

void ExecState::InitRediPagePool() {
    return m_AnaCtrl->InitRediPagePool();
}

void ExecState::DBHandler() {
    return m_AnaCtrl->DBHandler();
}

// Module initialization and finalization
__attribute__((constructor)) void module_init(void) {
    // cout << __PRETTY_FUNCTION__ << "\n";
}

__attribute__((destructor)) void module_fini(void) {
    // cout << __PRETTY_FUNCTION__ << "\n";
}
