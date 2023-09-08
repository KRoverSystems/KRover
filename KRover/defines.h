#ifndef _DEFINE_S_H__
#define _DEFINE_S_H__

/*debug log level
0 : basic logs: instruction number, instruction, if dispatched to CIE/SIE,
1 : To Do
2 : To Do
*/
#define LOG_LEVEL 0

/*When does the the analyzer inspects the target executon
0 : not inspected
1 : inspected */
#define CFG_ANA_ON_END_OF_INS_EXEC 1
#define CFG_ANA_ON_BFR_CIE_OR_SIE 0
#define CFG_ANA_ON_END_OF_BB_EXEC 0
#define CFG_ANA_ON_END_OF_INS_DECODE 0
#define CFG_ANA_ON_END_CALL_INS 0
#define CFG_ANA_ON_END_RET_INS 0
#define CFG_ANA_ON_START_SYM_BRANCH 0
#define CFG_ANA_ON_END_SYM_BRANCH 0
#define CFG_ANA_ON_BFR_SIE 0
#define CFG_ANA_ON_BFE_CIE 0
#define CFG_ANA_ON_AFT_SIE 0
#define CFG_ANA_ON_AFT_CIE 0
#define CFG_ANA_ON_TERMINATION_COND 1

#define CFG_ANA_ON_RECOVERABLE_ERR 1

#include <linux/types.h>
#include <list>
namespace EXPR
{
    class Expr;
}

typedef EXPR::Expr KVExpr;
typedef std::shared_ptr<KVExpr> KVExprPtr;

struct SymCell;
typedef std::shared_ptr<SymCell> SymCellPtr;

struct RegValue
{
    uint indx; // Register index
    uint size; // number of bytes
    bool bsym; // is a symbolic value?
    bool isSymList;
    union
    {
        int64_t i64;
        int32_t i32;
        int16_t i16;
        int8_t i8;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;
    };
    KVExprPtr expr;
    SymCellPtr symcellPtr;
};

struct MemValue
{
    ulong addr; // Memory address
    ulong size; // size in bytes
    bool bsym;  // is a symbolic value?
    bool isSymList;
    union
    {
        int64_t i64;
        int32_t i32;
        int16_t i16;
        int8_t i8;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;
    };
    KVExprPtr expr;
    SymCellPtr symcellPtr;
};

struct OpMemAc
{
    unsigned long memAddress;
    bool memrdwr;
    bool rdmem;
    bool wrmem;
    int size;
};

struct OpDetails
{
    struct OpMemAc opmemac;
};

#if LOG_LEVEL == 0
#define _DEBUG_LOG_L0
#elif LOG_LEVEL == 1
#define _DEBUG_LOG_L0
#define _DEBUG_LOG_L1
#endif

#if 0
    #ifndef _ANA_KMOD
        #define _ANA_KMOD
    #endif
#endif

#if 0
    #ifndef _PreDisassemble
        #define _PreDisassemble
    #endif
#endif

#if 0
    #ifndef __MALWARE_ANALYSIS
        #define __MALWARE_ANALYSIS
    #endif
#endif

#if 0
    #ifndef _PARSE_CIE_SIE_OPERANDS
        #define _PARSE_CIE_SIE_OPERANDS
    #endif
#endif

#if 0
    #ifndef _FAT_CONTROLLED
        #define _FAT_CONTROLLED
    #endif
#endif

#if 1
    #ifndef _SYM_ADDR
        #define _SYM_ADDR
    #endif
#endif

#define ON_END_OF_INS_EXEC 0
#define ON_END_OF_INS_DECODE 1
#define ON_END_CALL_INS 2
#define ON_END_RET_INS 3
#define ON_START_SYM_BRANCH 4
#define ON_END_SYM_BRANCH 5
#define ON_BFR_SIE 6
#define ON_BFE_CIE 7
#define ON_AFT_SIE 8
#define ON_AFT_CIE 9
#define ON_BFR_BB_START_EXEC 10
#define ON_AFT_BB_END_EXEC 11
#define ON_BFR_CIE_OR_SIE 12

//actions instructed by analyzer
#define NO_NEW_ACTION 1
#define DO_CIE 2
#define DO_SIE 3
#define END_EXECUTION -1

#define ON_TERM_COND_FUN_RET 40
#define ON_TERM_COND_INS_COUNT 41
#define ON_TERM_COND_GIVEN_RIP 42

#define END_AT_FUN_RET 0
#define END_AT_GIVEN_RIP 1
#define END_AT_GIVEN_INS_COUNT 2
#define END_AT_ANA_REQUEST 3

#define EXEC_MD_SINGLE_PATH_SEDED 0
#define EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT 1
#define EXEC_MD_START_PATH_SEARCH_AT_RIP 2

#define FIX_ME() printf("Fix-me: %s:%d %s\n", __FILE__, __LINE__, __FUNCTION__)
#define LOCOUT1(O) std::cout << __FILE__ << ":" << dec << __LINE__ << " => " << O << std::endl
#define LOCOUT2(O1, O2) std::cout << __FILE__ << ":" << dec << __LINE__ << " => " << O1 << O2 << std::endl
#define DBG(fmt, ...)                                  \
    do                                                 \
    {                                                  \
        printf("%s(): " fmt, __func__, ##__VA_ARGS__); \
    } while (0)
#define LOG(O1) std::cout << O1 << std::endl
#define ERRR_ME(O) printf("Err-me: %s:%d %s => %s\n", __FILE__, __LINE__, __FUNCTION__, O)

#define ERR_UD2_INS_DETECTED -1
#define ERR_REP_INS_WITH_SYM_RCX -2
#define ERR_SYM_EXE_FAILED_FOR_CUR_INS -3

#endif // _DEFINE_S_H__
