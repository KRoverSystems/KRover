#ifndef _ANA_CTRL_H
#define _ANA_CTRL_H

#include <linux/types.h>

#include <iostream>
#include <map>
#include <sstream>
#include <fstream>


#include "centralhub.h"

/* meta and func for kernel func addr + call inst database */
struct call_insn {
    unsigned long addr;
    unsigned long dest;
    char orig_bytes[5];
    int len;
};

struct CallInAllFuncs{
    unsigned long func_addr;
    struct call_insn* call_insts;
    int num_call;
};

// struct func_call_inst func_call[44020];
struct hook_info {
    unsigned long addr;
    unsigned long dest;
    char orig_bytes[1];//backup only one byte
    int len;//record the len of cur call inst, used when calculate ret addr
};

/* SE analyser's own page pool to hold T's code */
typedef struct pool
{
    void* init;
    void* next;
    void* end;
} POOL;

struct redir_page_info {
    unsigned long orig_t_page_addr;
    unsigned long new_ana_page_addr;
    unsigned long offset;
};

/* If we need more int3 probe or redirect page, adjust here */
#define MAX_INT3 30
#define MAX_Redir_Code_Page 8



class CAnaCtrl {
    
    VMState *m_VM;
    POOL* m_page_pool;
    int crt_max_redir_idx;//the current max number of redirected pages
    int crt_redir_idx; //indicate the idx of the current in use redirected page
    struct redir_page_info redir_code_pages[MAX_Redir_Code_Page];
    struct CallInAllFuncs* m_func_call;
    char per_hook[0x1];
    struct hook_info* probe_orig_inst;
    int crt_int3_idx;
    unsigned long last_redirected_probe_adr;
    bool kernel_symbols_map_filled = false;
   
   public:
    EveMeta* m_emeta;
    CThinCtrl *m_Thin;
    std::shared_ptr<CAnalyze> m_Analyze;
    std::map<std::string, unsigned long> kernel_symbols;
    std::map<unsigned long, std::string> reverse_kernel_symbols;
    std::map<std::string, unsigned long> kernel_module_object_symbols;

    CAnaCtrl(VMState *VM, EveMeta* meta);
    ~CAnaCtrl();

    bool processFunc(ulong addr);
    void INT3Handler(void);
    void VEHandler(void);
    void DBHandler(void);
    bool InstallINT3Probe (ulong addr);
    void InitRediPagePool(void);
    bool shouldNativeExec(unsigned long addr);
    void removeLastInt3();
    bool setupKernSymMap();
    unsigned long kernel_symbol_lookup(std::string fname);
    unsigned long kernel_module_object_lookup(std::string modname);
    std::string reverse_kernel_symbol_lookup(unsigned long address);
    bool chkSymsInCOnstraints();
    bool defineSymbolsForScalls(unsigned long, unsigned long);

   private:
    void PoolInit (size_t size);
    void PoolDestroy (POOL *p);
    size_t PoolCheckAvail (POOL* p);
    void* PoolAlloc (POOL* p, size_t size);
    int FindFuncCallInfo(unsigned long addr);
    void InstallPerInt3 (unsigned long addr, int len, unsigned long dest);
    void InstallInt3ForFunc (unsigned long func_addr);
    int find_probe_idx(unsigned long rip);
    void update_crt_redir_idx (unsigned long tempAddr);
    void RedirCodePageHyperCall (void* ker_addr);
    unsigned long emulCall(struct pt_regs* regs);
    void clear_dr(int idx);
    bool CheckFuncSym(unsigned long);
    bool mustyesUseSymbol(ulong BB_addr); 
    bool mustnotUseSymbol(ulong BB_addr);  
    bool mayUseSymbol(ulong BB_addr);    
};

#define SCALL_SETPRIORITY       141
#define SCALL_GETPRIORITY       140
#define SCALL_GETPID            039
#define SCALL_LSEEK             8
#define SCALL_SOCKET            41
#define SCALL_BIND              49
#define SCALL_PIPE              22
#define SCALL_ACCESS            21
#define SCALL_SYSFS             139
#define SCALL_UMASK             95    
#define SCALL_DUP               32
#define SCALL_DUP2              33
#define SCALL_ALARM             37
#define SCALL_SCH_GET_PRIO_MAX  146
#define SCALL_SCH_GET_PRIO_MIN  147
#define SCALL_LINK              86    
#define SCALL_GETCWD            79    
#define SCALL_LINK              86  
#define SCALL_MLOCK             149   
#define SCALL_MUNLOCK           150
#define SCALL_FCNTL             72   
#define SCALL_WRITE             001
#define SCALL_TRUNCATE          76
#define SCALL_CHDIR             80    
#define SCALL_RENAME            82    
#define SCALL_MKDIR             83    
#define SCALL_RMDIR             84    
#define SCALL_CREAT             85 
#define SCALL_GETRLIMIT         97    
#define SCALL_SETRLIMIT         160 
#define SCALL_UNLINK            87
#define SCALL_SYMLINK           88
#define SCALL_CHMOD             90
#define SCALL_PERSONALITY       135
#define SCALL_SWAPON            87
#define SCALL_MMAP              9
#define SCALL_READ              0
#define SCALL_MPROTECT          10
#define SCALL_MSYNC             26
#define SCALL_MINCORE           27
#define SCALL_GETITIMER         36
#define SCALL_SETITIMER         38
#define SCALL_FLOCK             73
#define SCALL_GETRUSAGE         98
#define SCALL_GETRUSAGE         98
#define SCALL_SETPGID           109
#define SCALL_SETREUID          113
#define SCALL_SETREGID          114
#define SCALL_CAPGET            125
#define SCALL_SETUID            105
#define SCALL_SETGID            106
#define SCALL_GETGROUPS         115
#define SCALL_SETGROUPS         116
#define SCALL_SETRESUID         117
#define SCALL_SETRESGID         119
#define SCALL_SETFSUID          122
#define SCALL_SETFSGID          123
#define SCALL_GETSID            124
#define SCALL_SCHED_GETPARAM    143
#define SCALL_SCHED_SETPARAM    142
#define SCALL_OPEN              2
#define SCALL_IOPL              172
#define SCALL_IOPERM            173
#define SCALL_UTIME             132
#define SCALL_SCHED_GETSCHDLR   145
#define SCALL_MLOCKALL          151
#define SCALL_PRCTL             157
#define SCALL_ARCH_PRCTL        158
#define SCALL_ACCT              163
#define SCALL_SCHED_SETSCHDLR   144
#define SCALL_SCHED_GETAFFINITY 204
#define SCALL_SCHED_SETAFFINITY 203
#define SCALL_SCHED_RR_GT_INTVL 148
#define SCALL_UNSHARE           272
#define SCALL_STATX             332
#define SCALL_TEE               276
#define SCALL_SET_ROBUST_LIST   273
#define SCALL_GET_ROBUST_LIST   274
#define SCALL_MLOCK2            325
#define SCALL_MPROTECT          10
#define SCALL_USERFAULTFD       323
#define SCALL_KCMP              312
#define SCALL_PIPE2             293
#define SCALL_DUP3              292
#define SCALL_CLOSE             3
#define SCALL_BRK               12
#define SCALL_SHMGET            29
#define SCALL_EXIT              60
#define SCALL_SHMAT             30 
#define SCALL_PRLIMIT64         302              
#define SCALL_UTIMES            235              
#define SCALL_PKEY_ALLOC        330  
#define SCALL_GETPGID           121              
#define SCALL_EPOLL_CREATE      213              
#define SCALL_EPOLL_CREATE1     291     
#define SCALL_EVENTFD2          290          
#define SCALL_EVENTFD           284
#define SCALL_INOTIFY_INIT1     294 
#define SCALL_FANOTIFY_INIT     300  

#endif
