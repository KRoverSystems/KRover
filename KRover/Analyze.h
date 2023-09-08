#ifndef _ANALYZE_H__
#define _ANALYZE_H__

#include <linux/types.h>
#include <iostream>
#include <map>
#include "centralhub.h"
#include "defines.h"
#include "AnaCtrl.h"
#include "thinctrl.h"
#include "EFlagsManager.h"

class VMState;
class CThinCtrl;
class SymExecutor;
class ConExecutor;
class EFlagsManager;

/*to share data between KRover and user analyzer*/
struct ExecProfile {
    /*Execution modes
    0 : DEFAULT MODE, Single pat hseeded mode, EXEC_MD_SINGLE_PATH_SEDED                  
    1 : Path search start at a given ins count, EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT
    2 :  Path search start at a given rip, EXEC_MD_START_PATH_SEARCH_AT_RIP        
    */
    int executionMode;
    unsigned long startIncCount;
    unsigned long startRip;

    /*Termination modes
    0 : DEFAULT MODE, terminate at stack balance, function return
    1 : terminate at specific RIP
    2 : terminate at specific ins count
    3 : terminate at ana request
    */
    int terminationMode;
    /*for termination mode 1*/
    unsigned long terminate_rip;
    /*for termination mode 2*/
    unsigned long terminate_ins_count;
};

struct ExecData {
    wrapInstruction *win;
    struct OpDetails opDetails[2];
    unsigned long buf[512];
    unsigned long insn_count;
    unsigned long start_rsp;

};

class CAnalyze {
    
    VMState *m_VM;
    POOL* m_page_pool;

    bool defineSymbolsForScalls(unsigned long scall_idx, unsigned long tmp/*pt_regs_base_adr*/);

   public:
    EveMeta* m_emeta;
    CThinCtrl *m_Thin;
    std::shared_ptr<CAnaCtrl> m_AnaCtrl;
    std::shared_ptr<SymExecutor> a_SymExecutor;
    std::shared_ptr<ConExecutor> a_ConExecutor;
    std::shared_ptr<EFlagsManager> a_EFlagsMgr;
    std::shared_ptr<CFuzzCtrl> a_FuzzCtrl;
    std::shared_ptr<CDtFlwTrc> a_DtFlwTrc;


    struct ExecData *execData;
    struct ExecProfile *execProfile;
    int test;

    // CFattCtrl(ExecCtrl *EC, VMState *VM);
    CAnalyze(VMState *VM, EveMeta* meta);
    ~CAnalyze();

    bool beginAnalysis(ulong addr);
    int analyztsHub(int anaPoint);
    int onEndOfInsExec();
    int onEndOfBbExec();
    int onBeforeCIESIE();
    int onEndOfInsDecode();

    void setExecProfile();
    bool beginFuzz();
    void setExecProfileFuzzSE();
    void setupTipcAnalysis();
    void setupScallAnalysis();
    void setupRootkitAnalysis();
    void findRootkitAddressRanges();
    bool isAdrWithinModue(unsigned long adr);
    int  checkOperandsMemAccess(int operand_number, unsigned long adr);
    int  chkAndDeclareSymbols(unsigned long address, int mem_size);
    char* getConstAsStr();

    void initDtFlwTrc();
    int endInsExec2();
    int endInsExec3();
    int bfrInsExec2();
    int setupReversibleRun();
    int findUsableMemSyms();

    bool shouldNativeExec(unsigned long addr);
    void setAnaCtrl(std::shared_ptr<CAnaCtrl> anactrl) {m_AnaCtrl = anactrl;};
    void setSymExecutor(std::shared_ptr<SymExecutor> symexecutor) {a_SymExecutor = symexecutor;}
    void setConExecutor(std::shared_ptr<ConExecutor> conexecutor) {a_ConExecutor = conexecutor;}
    void setEflagsMgr(std::shared_ptr<EFlagsManager> eflagsmgr) {a_EFlagsMgr = eflagsmgr;}
    void setFuzzCtrl(std::shared_ptr<CFuzzCtrl> fuzzctrl) {a_FuzzCtrl = fuzzctrl;}
    void setDtFlwTrc(std::shared_ptr<CDtFlwTrc> dtflwtrc) {a_DtFlwTrc = dtflwtrc;}

   private:



};


//for malwre analysis
using namespace std;
struct ana_mem_block{
    bool    is_read;
    bool    is_write;
    uint    sym_size;
    bool    is_dyn_sym;
    string  sym_name;
    bool    symbol_for_path_exp;
};
typedef struct ana_mem_block anaMemBlk;

/*kernel struct defs, simplified*/
#define DSIZE 0x180
struct module_layout {  //size 0x50
	/* The actual code + data. */
	void *base;
	/* Total size. */
	unsigned int size;
	/* The size of the executable code.  */
	unsigned int text_size;
	/* Size of RO section of the module (text+rodata) */
	unsigned int ro_size;
	/* Size of RO after init section */
	unsigned int ro_after_init_size;
    char misc[0x38];
};

struct module {

    char data[DSIZE];

    /* Core layout: rbtree is accessed frequently, so keep together. */
	struct module_layout core_layout; 
	struct module_layout init_layout;

};

#endif  // _ANALYZE_H__
