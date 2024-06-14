#ifndef IMEE
#define IMEE
#include <linux/list.h>
/* Jiaqi */
// #include <linux/kvm_types.h>
/* /Jiaqi */
#define DBG(fmt, ...) \
    do {printk ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)

/*
#define DBG(fmt, ...) 
*/
// #define DBG(fmt, ...) 

#define ERR(fmt, ...) \
    do {printk ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)

// struct arg_blk
// {
//     unsigned long vcpu_fd;
//     unsigned long syscall_flag;
//     unsigned long rip;
//     unsigned long rsp;
//     unsigned long rax;
//     unsigned long rdi;
//     unsigned long rsi;
//     unsigned long rdx;
//     unsigned long r10;
//     unsigned long r8;
//     unsigned long r9;
//     unsigned long r11;
//     unsigned long rcx;
//     unsigned long ret_rax;
//     unsigned long sstub_entry;
//     unsigned long hard_cr3;
// };
// /* Jiaqi */
// // extern struct arg_blk* imee_arg;
// extern struct arg_blk imee_arg;

struct arg_blk
{
    int instrum_flag;
    int pl_switch;
    unsigned long exit_gate_addr;
    unsigned long syscall_gate_addr;
    unsigned long syscall_gate_pa;
    unsigned long t_idt_va;
    unsigned long t_gdt_va;
    unsigned long t_tss_va;//2 tss pages
    unsigned long t_idt_pa;
    unsigned long t_gdt_pa;
    unsigned long t_tss_pa;
    unsigned long t_tss1_pa;
    unsigned long t_tss2_pa;
    unsigned long stack_addr;//0x2c0 from tss + int 3 stack + data
    unsigned long root_pt_addr;
    unsigned long shar_va;
    unsigned long shar_pa;
    unsigned long ana_t_tss_va;
    unsigned long ana_t_tss_pa;
    unsigned long ana_t_gdt_va;
    unsigned long ana_t_gdt_pa;
    unsigned long ana_t_idt_va;
    unsigned long ana_t_idt_pa;
    unsigned long ana_pf_c_page;
    unsigned long ana_pf_stack;
    // unsigned long virt_exec_area;
    // unsigned long virt_exec_phys_addr;
    unsigned long vcpu_fd;
    unsigned long syscall_flag;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rax;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
// QHQHQHQHQHQHQ add    
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long rbx;
    unsigned long rbp;
    unsigned long rss;
    unsigned long rflags;
    unsigned long rfs;
    unsigned long rgs;
    unsigned long rcs;
    unsigned long xcr0;
    pid_t pid;
// QHQHQHQHQHQHQ ----------------------------    
    unsigned long rcx;
    unsigned long ret_rax;
    unsigned long sstub_entry;
    unsigned long hard_cr3;
};
/* Jiaqi */
// extern struct arg_blk* imee_arg;
extern struct arg_blk imee_arg;

//used to pass target thread's register context between hyp and analyzer. 
struct shar_arg
{
    volatile unsigned long flag;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long rcx;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
    unsigned long r10;
    unsigned long rax;
    unsigned long eflags;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rbx;
    unsigned long rbp;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    // unsigned long long xmm0;
    // unsigned long long xmm1;
    // unsigned long long xmm2;
    // unsigned long long xmm3;
    // unsigned long long xmm4;
    // unsigned long long xmm5;
    // unsigned long long xmm6;
    // unsigned long long xmm7;
    unsigned long fs_base;
    unsigned long gs_base;
    unsigned long msr_kernel_gs_base;
    unsigned long gdt;
    unsigned long idt;
    unsigned long tss_base;
    unsigned long tss_pg_off;
    unsigned long g_syscall_entry;
    unsigned long pf_entry;
    unsigned long int3_entry;
    unsigned long cr0;
    unsigned long cr2;
    unsigned long cr3;
    unsigned long cr4;
    unsigned long efer;
    unsigned long apic_base_addr;
    unsigned long apic_access_addr;
    unsigned long io_bitmap_a_addr;
    unsigned long io_bitmap_b_addr;
    unsigned long msr_bitmap_addr;
    unsigned long tsc_offset;
    unsigned long exit_reason;
    unsigned long exit_qualification;
    unsigned long inst_len;
    unsigned long event_flag;
    unsigned long entry_intr_info;
    unsigned long user_flag;
    volatile unsigned long guest_timeout_flag;
    volatile unsigned long exit_wrong_flag;
    volatile unsigned long cross_page_flag;
    //pp-s
    unsigned long idtr_base;
    unsigned long idtr_limit_u16;
    //pp-e
};
// extern struct shar_arg* ei_shar_arg;
extern struct shar_arg* guest_vcpu_paste;

extern unsigned long host_syscall_entry;
extern unsigned long host_pf_entry;
extern unsigned long guest_syscall_entry;
extern unsigned long onsite_syscall_entry;
extern int vmc_idx;
extern int onsite_ready;

/* The following structures are maintained to make the EPT redirection on target
 * pages more efficient */
// #define max_int3_pool 8
#define max_int3_pool 40
#define max_pf_pool 400
// #define redirected_low_va 0xfffffefff7e3e000
// #define redirected_high_va 0xfffffefff7fcd000
struct gva_hpa_pair {
    unsigned long a_gva;
    unsigned long hpa;
    unsigned long t_gva;
    unsigned long t_gpa;
    unsigned long a_epte;
    unsigned long t_epte;
    unsigned long *spt;
    // int int3_flg;
};
extern struct gva_hpa_pair gva_hpa_pool[max_pf_pool];
extern struct gva_hpa_pair int3_gva_hpa_pool[max_int3_pool];
extern int crt_pfpool_idx;
extern int int3_pool_idx;
extern int pf_cache_flag;
// extern int crt_search_idx;
// extern int pre_search_idx;
/* / */

/* To record #VE intercepted pages */
#define max_ve_pages 8
struct ve_page { 
    unsigned long gva;
    unsigned long* spt;
    unsigned long orig_epte;
    unsigned long new_epte;
};
extern struct ve_page ve_intcp_pages[max_ve_pages];
extern int crt_ve_pool_idx;
/* / */
struct sig_record{
    void* sig_handler;
    // int index;
    // int flag;
};
// struct sig_record sig_array[64];
// EXPORT_SYMBOL_GPL (sig_array);
extern struct sig_record sig_array[64];

struct gpa_hpa {
    unsigned long gpa;
    unsigned long hpa;
};

struct pt_mapping
{
    int lv;  // the level which the entry exits
    ulong e; // the paging structure entry
};

typedef struct introspection_context
{
    struct kvm* kvm;
    struct kvm_vcpu* target_vcpu;
    struct task_struct* task;
    ulong visited;

    ulong eptp;
    struct list_head pt_page; // pt pages of EPT
    struct list_head pd_page; // pd may contain large(2MB) entries 
    struct list_head non_leaf_page; // pdpt & pml4 pages of EPT

    ulong s_eptp;
    struct list_head s_pt_page;
    struct list_head s_pd_page;
    struct list_head s_non_leaf_page;
    // u64 cr3;//onsite cr3
    u64 t_cr3;
    u64 o_cr3;

    struct list_head node; // linked to global list

} intro_ctx_t;


extern intro_ctx_t* current_target;

extern volatile struct kvm_vcpu* imee_vcpu;
extern volatile int imee_pid;
extern spinlock_t sync_lock;
extern volatile unsigned long last_cr3;
extern volatile unsigned long last_rip, last_rsp;
extern volatile unsigned long onsite_cr3;

extern struct kvm_sregs imee_sregs;

volatile extern int exit_flg;
volatile extern unsigned long switched_cr3;


int remap_gpa (intro_ctx_t* ctx, ulong gpa);

void copy_leaf_ept (intro_ctx_t* ctx, struct kvm_arch* arch);
intro_ctx_t* kvm_to_ctx (struct kvm* target);
void switch_intro_ctx (intro_ctx_t* next, struct kvm_vcpu* vcpu);
u64 make_imee_ept (intro_ctx_t* ctx);
int start_guest_intercept (struct kvm_vcpu *vcpu);
int vcpu_entry(void);
int vcpu_reentry(void);
int adjust_dota_context (struct kvm_vcpu *vcpu);
struct kvm_vcpu* pick_cpu (struct kvm* target_kvm);

int adjust_ept_entry (intro_ctx_t* ctx, unsigned long gpa, unsigned long new_pa, int permission);
u64 get_epte_onsite (intro_ctx_t* ctx, u64 gpa);

extern struct desc_ptr imee_idt, imee_gdt;
extern struct kvm_segment imee_tr;
extern ulong code_entry;
extern int trial_run;

extern intro_ctx_t* cur_ctx;

int kvm_imee_stop (struct kvm_vcpu* vcpu);
int kvm_imee_get_guest_context (struct kvm_vcpu *vcpu, void* argp);
// long kvm_imee_get_guest_context (struct kvm_vcpu *vcpu);

extern unsigned long UK_OFFSET;

// QHQ change
#if 0
/* Followings are addresses to host OS */
// #define user_start 0x7ff000000000UL
// #define user_end 0x7ffff8000000UL
#define user_start 0x7f8000000000UL
#define user_end 0x7fffffffffffUL
// the address of onsite wrapper
// #define onsite_wrapper_addr 0x7ff020300000UL
#define onsite_wrapper_addr 0x7f9000300000UL
// the address of dummy_sighandler
// #define dummy_handler_addr 0x7ff020600000UL
#define dummy_handler_addr 0x7f9000600000UL
// the address of sigflag in dummy_sighandler
// #define user_sigflag_addr 0x7ff020804000UL
#define user_sigflag_addr 0x7f9000804000UL

// #define sstub_addr 0x7ff020900000UL
/* to install descriptor tables and debug handler */ 
// #define debug_handler_addr 0x7ff020900000UL
#define gate_addr 0x7f9000900000UL
#define gate_data_num 0xa000 //first part: 1 IDT page + 1 GDT page + 2 TSS page + 1 writable data page; second part: 1 page for root PT + 1 page for shar_mem; third part: three VA pages for the analyzer to access the tss_struct, GDT, and IDT in the s_ept.// The second and third part are not mapped in t-EPT
#define syscall_page_addr 0x7f900090b000UL
#define virt_exce_va 0x7f900090c000UL
// #define kn_shar_addr 0x7f900090c000UL

/* analyser's own #VE and #PF share the same code page and stack(IST[7]) */
#define onsite_pf_addr 0x7f900090d000UL//its data page locates at +0x1000
/* / */
#else
// ==============>
/* Followings are addresses to host OS */
// #define user_start 0x7ff000000000UL
// #define user_end 0x7ffff8000000UL
#define USER_IDX (254UL)
#define ONSITE_WRAPPER_OFFSET (0x1000300000UL)
#define DUMMY_HANDLER_OFFSET (0x1000600000UL)
#define USER_SIGFLAG_OFFSET (0x1000804000UL)
#define GATE_OFFSET (0x1000900000UL)
#define SYSCALL_PAGE_OFFSET (0x100090b000UL)
#define VIRT_EXCE_VA_OFFSET (0x100090c000UL)
#define ONSITE_PF_OFFSET (0x100090d000UL)


// #define user_start 0x7f0000000000UL
#define user_start ((USER_IDX) * (512UL) * (1024UL) * (1024UL) * (1024UL))
// #define user_end 0x7f7fffffffffUL
#define user_end ((USER_IDX+1) * (512UL) * (1024UL) * (1024UL) * (1024UL) - 1UL)

// the address of onsite wrapper
// #define onsite_wrapper_addr 0x7f1000300000UL
#define onsite_wrapper_addr (user_start + ONSITE_WRAPPER_OFFSET)

// the address of dummy_sighuser_start + 
#define dummy_handler_addr (user_start + DUMMY_HANDLER_OFFSET)

// the address of sigflag in dummy_sighandler
//#define user_sigflag_addr 0x7f1000804000UL
#define user_sigflag_addr (user_start + USER_SIGFLAG_OFFSET)


// #define sstub_addr 0x7ff020900000UL
/* to install descriptor tables and debug handler */ 
// #define gate_addr 0x7f1000900000UL
#define gate_addr (user_start + GATE_OFFSET)
#define gate_data_num 0xa000 //first part: 1 IDT page + 1 GDT page + 2 TSS page + 1 writable data page; second part: 1 page for root PT + 1 page for shar_mem; third part: three VA pages for the analyzer to access the tss_struct, GDT, and IDT in the s_ept.// The second and third part are not mapped in t-EPT
//#define syscall_page_addr 0x7f100090b000UL
#define syscall_page_addr (user_start + SYSCALL_PAGE_OFFSET)
//#define virt_exce_va 0x7f100090c000UL
#define virt_exce_va (user_start + VIRT_EXCE_VA_OFFSET)
// #define kn_shar_addr 0x7f900090c000UL

/* analyser's own #VE and #PF share the same code page and stack(IST[7]) */
// #define onsite_pf_addr 0x7f100090d000UL//its data page locates at +0x1000
#define onsite_pf_addr (user_start + ONSITE_PF_OFFSET)

//pp-s
//#define KROVER_OASIS_LIB_PATH "/home/beverly/KRover/oasis-lib/KRover-OASIS-Lib/"
#define KROVER_OASIS_LIB_PATH "/home/neo/smu/oasis/oasis-lib/KRover-OASIS-Lib/"
//pp-e
#define SIG_WRAP_PATH KROVER_OASIS_LIB_PATH "signal_toy/sig_wrap/sig_wrap.so"

#define SIG_HANDLE_PATH (KROVER_OASIS_LIB_PATH "signal_toy/dummy_handler/hello")
#define PF_STUB_PATH (KROVER_OASIS_LIB_PATH "pf_stub/pf.so")
#define DEBUG_HANDLER_GATE_PATH (KROVER_OASIS_LIB_PATH "springboard/gate.so")
#define DEBUG_HANDLER_DATA_PATH (KROVER_OASIS_LIB_PATH "springboard/data_page")
#define DEBUG_HANDLER_SYSCALL_GATE_PATH (KROVER_OASIS_LIB_PATH "springboard/syscall_gate.so")

//QHQQHQHQ change
//#define non_fix_mmap_start 0x7fa000000000UL
//#define non_fix_mmap_end 0x7fa0f0000000UL
// to ======================>
#define non_fix_mmap_offset (0x2000000000UL)
#define non_fix_mmap_size (0xf0000000UL)
#define non_fix_mmap_start (user_start+non_fix_mmap_offset)
#define non_fix_mmap_end (non_fix_mmap_start+non_fix_mmap_size)
//QHQHQHQ-----------------

/* / */
#endif
#endif
