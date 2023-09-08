#ifndef _SYM_EFLAGSMANAGER_H__
#define _SYM_EFLAGSMANAGER_H__

#include "VMState.h"
#include "Z3Handler.h"

class VMState;

using namespace z3;
using namespace EXPR;
using namespace Z3HANDLER;


#define FLAG_CHANGING_ATTR 0x1
#define FLAG_SETING_ATTR 0x2
#define CONDITIONAL_EXEC_ATTR 0x4

class EFlagsManager {
    VMState *m_VM ;
    

    KVExprPtr m_LastExpr ;          // last Expr Created by flag changing/setting instruction.
    FSInstrPtr m_LastInstr;         // last flag changing/setting instruction.
    
    KVExprPtr m_LastExpr_back ;
    
    std::map<ulong, bool> branchDecision;

    std::shared_ptr<Z3Handler> m_Z3Handler;
    
    protected:
        bool DoCreateConstraint(int exprID, bool bChoice ) ;
    
    public:
        std::set<KVExprPtr> m_Constraint;
        std::set<KVExprPtr> m_Constraint_back;
        EFlagsManager(VMState *vm) ;
        ~EFlagsManager () {} ;

        FLAG_STAT GetFlag(int flag) {return FLAG_UNCERTAIN ;} ;


        bool isFlagSettingInstr(entryID id) ;
        bool isFlagChangingInstr(entryID id) ;

        bool isConditionalExecuteInstr(entryID id) ;
        void InitInstructionAttr(void) ;

        bool DependencyFlagConcreted(entryID instrID, bool &bChoice) ;
        bool CreateConstraint(entryID instrID, bool bChoice) ;

        bool ConcreteFlag (entryID instrID, bool bChoice) ;

        bool SaveFlagChangingInstruction (FSInstrPtr &ptr) ;
        bool SaveFlagChangingInstructionExpr (entryID instrID, KVExprPtr exprPtr) ;

        bool findDecision(ulong addr, long long unsigned int counter);
        bool findDecision(ulong addr);

        KVExprPtr DoGetCondition(int exprID);
        KVExprPtr GetCondition(entryID instrID); 
        
        bool EvalCondition(entryID insnID);
        bool ReadAddrBoolMapFromFile () ;
        bool PrintConstraint(void) ;
        bool SolveConstraints();
        uint64_t ConcretizeExpression(KVExprPtr exprPtr);
        uint64_t EvalCondition(entryID insnID, uint64_t addr, uint64_t b1, uint64_t b2) ;

        void backup () {
            
            m_LastExpr_back = m_LastExpr ;
            m_Constraint_back = m_Constraint ;
        };
        void restore () {

            m_LastExpr = m_LastExpr_back ;
            m_Constraint =m_Constraint_back ;
        };
        std::set<KVExprPtr> getConstraint() {return m_Constraint;} ;
};

#endif
