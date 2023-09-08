#ifndef _CENTRAL_HUB_H__
#define _CENTRAL_HUB_H__

#include <memory>
#include <vector>           

class VMState;
class CAnalyze;
class CAnaCtrl;
class CThinCtrl;
class SymExecutor;
class CFuzzCtrl;
class CDtFlwTrc;

struct pt_regs;

typedef struct EventMeta {
    unsigned long t_pf_stack;
    unsigned long t_int3_stack;
    unsigned long t_ve_stack;
    unsigned long t_db_stack;
    unsigned long* virt_exce_area;
} EveMeta;

class ExecState {
    std::shared_ptr<VMState> m_VM;
    std::shared_ptr<CThinCtrl> m_ThinCtrl;
   
    public:
    std::shared_ptr<CAnalyze> m_Analyze;
    std::shared_ptr<CAnaCtrl> m_AnaCtrl;
    std::shared_ptr<CFuzzCtrl> m_FuzzCtrl;
    std::shared_ptr<CDtFlwTrc> m_DtFlwTrc;
    std::shared_ptr<EveMeta> m_emeta;
    
    ExecState(ulong adds, ulong adde);
    ~ExecState();

    bool declareSymbolicObject(ulong addr, ulong size, bool isSigned, bool hasSeed, long conVal, const char *name);
    bool declareSymbolicRegister(uint index, uint size, bool isSigned, bool hasSeed, long conVal, const char *name); 

    bool runAnalystMode();
    bool runMalwareAnalystMode();
    bool SynRegsFromNative(struct MacReg* regs);
    bool SynRegsToNative(struct MacReg* regs);
    bool processAt(ulong addr);
    bool InstallINT3Probe(ulong addr);
    void InitRediPagePool();
    void DBHandler();
    bool defineSymbolsForScalls(unsigned long scall_idx, unsigned long pt_regs_base_adr);
};

#endif  // !_CENTRAL_HUB_H__
