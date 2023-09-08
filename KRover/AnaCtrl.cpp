#include "Analyze.h"
#include "AnaCtrl.h"

#include <asm/ptrace.h>
#include <linux/types.h>
#include <signal.h>
#include <ucontext.h>

#include <iostream>

#include "BPatch.h"
#include "BPatch_basicBlock.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "VMState.h"
#include "defines.h"
#include "interface.h"
#include "thinctrl.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;    


void CAnaCtrl::InitRediPagePool()
{
    //should be after get_target()
    ///* initialize redirect_page_pool */
    m_page_pool = (POOL*) new (POOL);
    PoolInit (0x1000*MAX_Redir_Code_Page);
    return;
}

CAnaCtrl::CAnaCtrl(VMState *VM, EveMeta* meta) {
    m_VM = VM;
    m_emeta = meta;
    void* temp;
    temp = &redir_code_pages[0];
    memset(temp, 0x0, sizeof(redir_code_pages));
    
    crt_redir_idx = crt_max_redir_idx = 0;
    
    /* Int3 probe related */
    per_hook[0] = 0xcc;
    crt_int3_idx = 0;
    probe_orig_inst = (struct hook_info*)malloc(MAX_INT3*sizeof(struct hook_info));

    m_func_call = (struct CallInAllFuncs*)malloc(sizeof(struct CallInAllFuncs)*44020);
}

CAnaCtrl::~CAnaCtrl() {
    // free resources
    /*TODO: complete the objects free */
    PoolDestroy(m_page_pool);
}

int CAnaCtrl::FindFuncCallInfo(unsigned long addr)
{
    int low = 0; 
    int high = 44019;
    while (low <= high) {
        int mid = (low + high)/2;
        int midVal = m_func_call[mid].func_addr;
        if (midVal < addr)
            low = mid + 1;
        else if (midVal > addr)
            high = mid - 1;
        else
            return mid;
    }
    return -1;
}

void CAnaCtrl::PoolInit (size_t size)
{
    void* temp = valloc(size);
    memset (temp, 0x0, size);
    
    m_page_pool->init = (void*)((unsigned long)temp + 0x1000);//The first page will not encounter #PF, so, start from the second page
    m_page_pool->next = (void*)((unsigned long)temp + 0x1000);
    m_page_pool->end = (void*)((unsigned long)temp + size);
    
    printf ("redirected page start from :%p. ends : %p. \n", temp, m_page_pool->end);
    return;
}

void CAnaCtrl::PoolDestroy (POOL *p)
{
    free(p);
}

size_t CAnaCtrl::PoolCheckAvail (POOL* p)
{
    return (unsigned long)p->end - (unsigned long)p->next;
}

void* CAnaCtrl::PoolAlloc (POOL* p, size_t size)
{
    if (PoolCheckAvail(p) < size)
    {
        return NULL;
    }
    void* mem = (void*) p->next;
    p->next = (void*)((unsigned long)p->next + size);
    return mem;
}

void CAnaCtrl::RedirCodePageHyperCall (void* ker_addr)
{    
    if (crt_max_redir_idx == MAX_Redir_Code_Page)
    {
        printf ("new_pages used up. \n");
        asm volatile ("movq $0x999999, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }

    void* new_va = PoolAlloc (m_page_pool, 0x1000);
#ifndef _PROD_PERF
    printf ("new_va: %lx. ker_addr: %lx. \n", (unsigned long)new_va, (unsigned long)ker_addr);
#endif
    memcpy (new_va, ker_addr, 0x1000);
#ifndef _PROD_PERF
    printf ("about to issue hyper call to redirect page: %lx .\n", (unsigned long)ker_addr);
#endif

    /* issue a hypercall to request ept redirection for new page */
    asm volatile ("movq $0xabcd, %%rbx; \n\t"
            "movq %0, %%rax; \n\t"
            "movq %1, %%rcx; \n\t"
            "lea 0x2(%%rip), %%rdx; \n\t"
            "jmpq *%%rax; \n\t"
            ::"m"(ker_addr), "m"(new_va):"%rax","%rbx","%rcx");

    redir_code_pages[crt_max_redir_idx].orig_t_page_addr = (unsigned long) ker_addr;
    redir_code_pages[crt_max_redir_idx].new_ana_page_addr = (unsigned long) new_va;
    redir_code_pages[crt_max_redir_idx].offset = ((unsigned long)ker_addr) - ((unsigned long)new_va);
    
    /* update the crt_redir_idx */
    crt_redir_idx = crt_max_redir_idx;
    crt_max_redir_idx ++;
    
    return;
}

void CAnaCtrl::update_crt_redir_idx (unsigned long tempAddr)
{
    int i;
    for (i = 0; i < crt_max_redir_idx; i ++)
    {
        if (tempAddr == redir_code_pages[i].orig_t_page_addr)
        {
            crt_redir_idx = i;
#ifndef _PROD_PERF
            printf ("update crt_idx as: %d. tempAddr: %lx. \n", crt_redir_idx, tempAddr);
#endif
            break ;
        }
    }
#ifndef _PROD_PERF
    printf ("update crt_idx as: %d. i: %d, crt_max_redir_idx: %d, tempAddr: %lx. \n", crt_redir_idx, i, crt_max_redir_idx, tempAddr);
#endif
    if (i == crt_max_redir_idx)
    {
        RedirCodePageHyperCall((void*) tempAddr);
    }
    return;
}

void CAnaCtrl::InstallPerInt3 (unsigned long addr, int len, unsigned long dest)
{
    probe_orig_inst[crt_int3_idx].addr = addr;
    probe_orig_inst[crt_int3_idx].dest = dest;
    probe_orig_inst[crt_int3_idx].len = len;
    memcpy (&probe_orig_inst[crt_int3_idx].orig_bytes, (void*)addr, 0x1);
    

    //record the last address of int3 where the int3 has been installed
    //this is to be used when we remove the int3 after a function has been natively executed
    last_redirected_probe_adr = (unsigned long)(addr-redir_code_pages[crt_redir_idx].offset);
    memcpy ((void*)(addr-redir_code_pages[crt_redir_idx].offset), per_hook, 0x1);//install the new hook
    crt_int3_idx ++;
    if (crt_int3_idx >= MAX_INT3)
    {
        printf ("int3 array used up, int3_array_idx: %d. \n", crt_int3_idx);
        asm volatile ("movq $0x999999, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }
    return; 
}

void CAnaCtrl::removeLastInt3()
{
    memcpy ((void*)(last_redirected_probe_adr), &probe_orig_inst[crt_int3_idx-1].orig_bytes, 0x1);
#ifndef _PROD_PERF
    std::cout << "last int3 probe has been removed" << std::endl;
#endif
}

void CAnaCtrl::InstallInt3ForFunc (unsigned long func_addr)
{
    printf ("install probe for func : %lx. \n", func_addr);
    int func_idx = FindFuncCallInfo(func_addr); 
    /* no call inst in func */
    if (func_idx == -1)
    {
        printf ("no call inst in func \n");
    }
    else
    {
        int total = m_func_call[func_idx].num_call;
        struct call_insn* ptr = m_func_call[func_idx].call_insts; 
        int i;
        unsigned long addr_l, addr_h;
        int len;
        unsigned long dest;
        addr_l = ptr[0].addr;
        len = ptr[0].len;
        dest = ptr[0].dest;
        
        update_crt_redir_idx(addr_l & ~0xfff);
        InstallPerInt3(addr_l, len, dest);
        printf ("install probe at: %lx. \n", addr_l);
        
        for (i = 1; i < total; i ++)
        {
            addr_h = ptr[i].addr;
            len = ptr[i].len;
            dest = ptr[i].dest;
            if ((addr_h & ~0xfff) != redir_code_pages[crt_redir_idx].orig_t_page_addr)
            {
                update_crt_redir_idx(addr_h & ~0xfff);
            }
            InstallPerInt3(addr_h, len, dest);
            printf ("...install probe at: %lx. \n", addr_h);
        }
    }
    return;
}

bool CAnaCtrl::InstallINT3Probe (ulong addr)
{
    unsigned long addr_l = addr;
    int len = 5;
    unsigned long dest = 0xffffffff810b6080;
#ifndef _PROD_PERF
    printf ("before before install probe at: %lx. \n", addr_l);
#endif
    update_crt_redir_idx(addr_l & ~0xfff);
#ifndef _PROD_PERF
    printf ("before install probe at: %lx. \n", addr_l);
#endif
    InstallPerInt3(addr_l, len, dest);
#ifndef _PROD_PERF
    printf ("install probe at: %lx. \n", addr_l);
#endif
    return true;
}

int CAnaCtrl::find_probe_idx(unsigned long rip)
{
    int i; 
    for (i = 0; i < crt_int3_idx; i ++)
    {
       if(probe_orig_inst[i].addr == rip)
       {
           if(probe_orig_inst[i].dest)
           {
               return i; //probe_orig_inst[i].dest;
           }
           else//needs a disassembler to find the dest 
           {
                printf ("need a disassembler to parse the dest. \n");
                asm volatile ("movq $0xfff, %%rax; \n\t"
                        "vmcall; \n\t"
                        :::"%rax");
           }
       }
    }
    if (i == crt_int3_idx)
    {
        printf ("addr not found in installed probe. \n");
        asm volatile ("movq $0xfff, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }
}

/* return the addr of call destination */
unsigned long CAnaCtrl::emulCall (struct pt_regs* regs)
{
    // unsigned long* int3_stack_ptr = (unsigned long*)(t_int3_stack - 0x28);
    unsigned long* int3_stack_ptr = (unsigned long*)(m_emeta->t_int3_stack - 0x28);
    unsigned long saved_rip, saved_rsp, saved_rflags;
    int probe_idx;
    unsigned long ret_addr, call_dest;
    unsigned long* t_stack_ptr;
    saved_rip = int3_stack_ptr[0];
    saved_rip -= 1;// for int3, saved rip is the rip next to int3
    saved_rflags = int3_stack_ptr[2];
    saved_rsp = int3_stack_ptr[3];
    printf ("saved rip: %lx. rsp: %lx, rflags: %lx. \n", saved_rip, saved_rsp, saved_rflags);
    
    probe_idx = find_probe_idx(saved_rip);
    call_dest = probe_orig_inst[probe_idx].dest;//resolve the call destination based on the saved rip in int3 stack.
   
    ret_addr = saved_rip + probe_orig_inst[probe_idx].len;  
    t_stack_ptr = (unsigned long*)saved_rsp;
    t_stack_ptr --;
    *t_stack_ptr = ret_addr;

    regs->rsp = (unsigned long)t_stack_ptr;
    regs->eflags = saved_rflags;
    
    regs->rip = call_dest;
    printf ("after adjustment... target_rsp: %lx, target_rflags: %lx. rdi: %lx. \n", regs->rsp, regs->eflags, regs->rdi);

    return call_dest;
}

// Here determines whether to invoke ThinCtrl or resume Native
void CAnaCtrl::INT3Handler(void)
{
    struct pt_regs* m_regs = m_VM->getPTRegs();
    unsigned long call_dest = emulCall(m_regs);
    
    InstallInt3ForFunc(call_dest);
    printf ("int3 invoked. \n");
    return;
}

// To complete
void CAnaCtrl::VEHandler(void)
{
    unsigned long* virt_exec_area;
    unsigned long exit_qual = m_emeta->virt_exce_area[1];
    if ((exit_qual & 0x4UL) != 0)
    {
        printf ("unexpected EPT violation . \n");
        asm volatile("movq $0x99999, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }
    else
    {
        unsigned long va = m_emeta->virt_exce_area[2];
        unsigned long* ve_stack_ptr = (unsigned long*)(m_emeta->t_ve_stack - 0x28);
        unsigned long saved_rip, saved_rsp, saved_rflags;
        saved_rip = ve_stack_ptr[0];
        saved_rflags = ve_stack_ptr[2];
        saved_rsp = ve_stack_ptr[3];
        printf ("saved rip: %lx. rsp: %lx, rflags: %lx. \n", saved_rip, saved_rsp, saved_rflags);
        bool ret = m_VM->isSYMemoryCell(va, 8);
        m_emeta->virt_exce_area[0] = 0x0UL;
        if (ret == 0)//execute one Instruction then resume native
        {
            m_Thin->ExecOneInsn(saved_rip);
        }
        else
        {
            printf ("invoke symExecutor. \n");
            asm volatile ("mov $0x99999999, %rax; \n\t"
                    "vmcall; \n\t");
        }
    }
    return;
}

/* no need to clear dr0-dr3, disable through dr7 */
void CAnaCtrl::clear_dr(int idx)
{
    unsigned long dr7;
    switch (idx)
    {
        case 0:
            dr7 = 0xfff0fffc;
            break;
        case 1:
            dr7 = 0xff0ffff3;
            break;
        case 2: 
            dr7 = 0xf0ffffcf;
            break;
        case 3: 
            dr7 = 0x0fffff3f;
            break;
        default: 
            asm volatile ("mov $0xabcdabcd, %rax; \n\t"
                    "vmcall; \n\t");
            break;
    }

    asm volatile (
            "mov %0, %%rbx; \n\t"
            "mov %%DR7, %%rax; \n\t"
            "and %%rbx, %%rax; \n\t"
            "mov %%rax, %%DR7; \n\t"
            ::"m"(dr7):"%rax","%rbx");
           
    return;
}

// To complete
void CAnaCtrl::DBHandler(void)
{
    clear_dr(0);
    printf ("in DB handler. \n");
    asm volatile ("mov $0x99999999, %rax; \n\t"
            "vmcall; \n\t");
    return;
}


// To complete
bool CAnaCtrl::CheckFuncSym(unsigned long addr)
{
    return true;
}

bool CAnaCtrl::setupKernSymMap(){
    ifstream kfile;
	string fline;
	unsigned long count;
    unsigned long ct;
	int i;
	stringstream stream;
	string fname;
	string tmp;
	unsigned long faddress;
    string mod_name;
    string kmod_data_nm = "__this_module";
    
	kfile.open("/home/neo/smu/KRover/KRover/stc-files/kern_syms.txt");
    	if(!kfile.is_open()){
#ifdef _DEBUG_LOG_L0
        std::cout << "file, kern_syms.txt open failed" << std::endl;
#endif
        return false;
   	}
 	
	count = 0;	
    ct = 0;
	while(getline(kfile, fline)){        	
		stringstream stream(fline);
        
		i = 0;
		while(stream >> tmp){
			if(i == 0){
				faddress = strtoul(tmp.c_str(), nullptr, 16);
			}
			if(i == 2)
				fname = tmp;
			if(i == 3){                                
                if(fname.compare(kmod_data_nm) == 0){
                    mod_name = tmp.substr(1, tmp.length() - 2);
                    kernel_module_object_symbols[mod_name] = faddress;
                    ct++;
                }                             
				break;
            }
			i++;
		}
		kernel_symbols[fname] = faddress;
        reverse_kernel_symbols[faddress] = fname;
		count++;
   	}
#ifdef _DEBUG_LOG_L0
    std::cout << "kernel symbol map is created, " << count << " entries" << std::endl;
    std::cout << "kernel module object symbol map is created, " << ct << " entries" << std::endl;
#endif
	kfile.close();
    if(count > 0){
        kernel_symbols_map_filled = true;
        return true;
    }
    else
        return false;
}

unsigned long CAnaCtrl::kernel_symbol_lookup(std::string fname){
    
    if(kernel_symbols_map_filled){
        return kernel_symbols[fname];
    }
    else
        {
#ifdef _DEBUG_LOG_L0
            std::cout << "kernel symbol map is not created" << std::endl;
#endif
            assert(0);
        }
}

unsigned long CAnaCtrl::kernel_module_object_lookup(std::string mod_name){

    if(kernel_module_object_symbols.empty()){
#ifdef _DEBUG_LOG_L0
        std::cout << "kernel module struct symbol map is not created" << std::endl;
#endif
        assert(0);
    }
    else{
        return kernel_module_object_symbols[mod_name];
    }
}

std::string CAnaCtrl::reverse_kernel_symbol_lookup(unsigned long address){
    if(kernel_symbols_map_filled){
        return reverse_kernel_symbols[address];
    }
    else
        {
#ifdef _DEBUG_LOG_L0
            std::cout << "reverse kernel symbol map is not created" << std::endl;
#endif
            assert(0);
        }
}

#ifdef __MALWARE_ANALYSIS
bool CAnaCtrl::chkSymsInCOnstraints(){
    bool ret = false;
    extern std::map<unsigned long, anaMemBlk*> ana_memblk_map;
    fstream esfile;
	string pcbegin = "npath_const_begin_kr";
	string pcend = "npath_const_end_kr";
    string fline;
	bool cbegin = false;
    std::map<string, unsigned long> dsyms_map;
    int dsym_names_count = 0;
    for(auto it = ana_memblk_map.begin(); it != ana_memblk_map.end(); it++){
        if(it->second->is_read){// && it->second->is_write){
            dsyms_map[it->second->sym_name] = it->first;
            dsym_names_count++;
        }
    }

    std::cout << "checking for dynamic symbols existing in path constraints..." << std::endl;
	esfile.open("log", ios::in);
	if (!esfile) {
		cout << "File not opened";
	}
	else {
		char ch;
		while(getline(esfile, fline)){
			if(cbegin){
                int i = 0;
                for(auto it = dsyms_map.begin(); it != dsyms_map.end(); it++){
                    	if(fline.find(it->first) != std::string::npos){
                            std::cout << "dynamic symbol: " << it->first << ":" << it->second << " exists" << std::endl;
                            ana_memblk_map[it->second]->symbol_for_path_exp = true;
                        }
                }

			}
			if(fline.compare(pcbegin) == 0){
				cbegin = true;
			}
			if(fline.compare(pcend) == 0){
				cbegin = false;
			}	
		}
	}
	esfile.close();

    return ret;
}
#endif

bool CAnaCtrl::defineSymbolsForScalls(unsigned long scall_idx, unsigned long tmp/*pt_regs_base_adr*/)
{
    /*
    struct pt_regs {
	r15; r14; r13; r12; bp;	
    bx;	 r11; r10; r9;	r8;	
    ax;	 cx;  dx;  si;  di; 
    orig_ax;  ip;  cs;  flags; sp; ss; }
    */
   bool ret = true;
    
    switch (scall_idx)
    {
        case SCALL_GETPRIORITY:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "who_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 1, "which_rdi"); //symbol
        }   break;
        case SCALL_SETPRIORITY:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60;  //adr of rdx
            //printf ("nice value: %lu. \n", *((unsigned long*)tmp));
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 19, "prio_rdx");
            tmp += 0x8;  //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "who_rsi"); 
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "which_rdi");    
        }   break;
        case SCALL_LSEEK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60;  //adr of rdx
            //printf ("nice value: %d. \n", *((unsigned long*)tmp));
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1, "whence_rdx");
            tmp += 0x8;  //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x5, "offset_rsi"); 
            tmp += 0x8;  //adr of rdi
            //std::cout << "fd : " << *((unsigned long*)tmp) << std::endl;
            //m_VM->createSYMemObject(tmp, 8, 1, 0x0, "fd_rdi");    
        }   break;
        case SCALL_SOCKET:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60;  //adr of rdx
            //printf ("nice value: %d. \n", *((unsigned long*)tmp));
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 17, "protocol_rdx");
            tmp += 0x8;  //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 2, "type_rsi"); 
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 2, "domain_rdi");    
        }   break;
        case SCALL_PIPE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70;  //adr of rdi
            
            //symbolizing buffer
            //unsigned long val = *(unsigned long*)tmp;
            //m_VM->createSYMemObject(tmp, 8, 0, 1, val, "bufadr_rdi"); //working symbol

            //symbolizing the buffer content
            unsigned long fd0_adr = *(unsigned long*)tmp;
            unsigned long fd1_adr = fd0_adr + 4;
            //printf("tmp : %lx fd2 %d, fd2 %d\n", *(unsigned long*)tmp, *(int *)fd0_adr, *(int *)fd1_adr);
            m_VM->createSYMemObject( fd0_adr, 4, 1, 1, 0x2, "fd1");
            m_VM->createSYMemObject( fd1_adr, 4, 1, 1, 0x1, "fd2");
        }   break;
        case SCALL_ACCESS:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 4, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 1, "filename_rdi");
        }   break;
        case SCALL_SYSFS:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 4, 1, 1, 3, "option_rdi");
        }   break;
        case SCALL_UMASK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0770, "mask_rdi");
        }   break;
        case SCALL_DUP:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 4, 1, 1, 1, "fd_rdi");
        }   break;
        case SCALL_DUP2:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            //printf(" new %lu, old %lu\n", *((unsigned long*)(tmp+0x68)), *((unsigned long*)(tmp+0x68+0x8)) );
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0xffffffff, "newfd_rsi"); //##symbol
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 4, 1, 1, 2, "oldfd_rdi");
        }   break;
        case SCALL_ALARM:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 4, 1, 1, 100, "seconds_rdi");
        }   break;
        case SCALL_SCH_GET_PRIO_MAX:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 4, 1, 1, 1, "policy_rdi"); //policy = SCHED_FIFO 1
        }   break;
        case SCALL_SCH_GET_PRIO_MIN:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 4, 1, 1, 1, "policy_rdi"); //policy = SCHED_FIFO 1
        }   break;
        case SCALL_GETCWD:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 4, "len_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x7fffffffdf80, "buf_rdi");
        }   break;
        case SCALL_LINK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            m_VM->createSYMemObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            //m_VM->createSYMemObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            //m_VM->createSYMemObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //m_VM->createSYMemObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;
        case SCALL_MLOCK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1024, "len_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 1, "adr_rdi");
        }   break;
        case SCALL_MUNLOCK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1024, "len_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 1, "adr_rdi");
        }   break;
        case SCALL_FCNTL:
        {   
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "cmd_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 4, 1, 1, 1, "fd_rdi");
        }   break;
        case SCALL_WRITE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60;  //adr of rdx
            //printf ("nice value: %d. \n", *((unsigned long*)tmp));
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 2, "count_rdx");
            tmp += 0x8;  //adr of rsi
            //printf("adr %lx buf content %c%c ", adr, *(char *)adr, *((char *)(adr+1)));
            
            //##symbolize buf arg which is an address
            //m_VM->createSYMemObject(tmp, 8, 1,1,  0x7fffffffdfb0, "buf_rsi"); 
            
            //##symbolize buf content chars
            unsigned long adr = *((unsigned long *)tmp);
            //printf("adr : %lx adr[0]:%x  adr[1]:%x\n", adr, *(uint8_t*)adr, *((uint8_t*)(adr+1)));
            m_VM->createSYMemObject(adr, 1, 1,1, 0x61, "buf[0]_rsi"); 
            m_VM->createSYMemObject(adr + 1, 1, 1,1, 0x62, "buf[1]_rsi"); 
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 4, "fd_rdi");    
        }   break;
        case SCALL_TRUNCATE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x5, "len_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 1, "filenm_rdi");
        }   break;
        case SCALL_MKDIR:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 777, "mode_rsi");
        }   break;
        case SCALL_RMDIR:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long directory_name_adr = *(unsigned long*)tmp;
            printf("dir nm :%c%c%c\n", *(char*)directory_name_adr, *(char*)(directory_name_adr+1), *(char*)(directory_name_adr+2) );
            m_VM->createSYMemObject(directory_name_adr    , 1, 0, 1, 0x61, "dirname_rdi_1"); //d
            m_VM->createSYMemObject(directory_name_adr + 1, 1, 0, 1, 0x61, "dirname_rdi_2"); //i
            m_VM->createSYMemObject(directory_name_adr + 2, 1, 0, 1, 0x61, "dirname_rdi_3"); //r
            //m_VM->createSYMemObject(directory_name_adr + 2, 1, 0, 1, 0x00, "dirname_rdi_4"); //\0
        }   break;
        case SCALL_GETRLIMIT:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "adr_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "resource_rdi"); //seed val 7 : RLIMIT_NOFILE
        }   break;
        case SCALL_SETRLIMIT:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            unsigned long bRlim = *(unsigned long*)tmp;  //bRlim has the address of rlimit struct
            m_VM->createSYMemObject(bRlim+0x8, 8, 1, 1, 0x0, "rlim_lim_max_rsi");  //symbolize the 2nd object of rlimit obj
            
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x7, "resource_rdi"); //seed val 7 : RLIMIT_NOFILE
        }   break;
        case SCALL_UNLINK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            //printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            m_VM->createSYMemObject(old_filename_adr    , 4, 0, 1, 0x6f6c6400, "fname_rdi"); //o
            //m_VM->createSYMemObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            //m_VM->createSYMemObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            //m_VM->createSYMemObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
        }   break;
        case SCALL_SYMLINK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            m_VM->createSYMemObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            m_VM->createSYMemObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            m_VM->createSYMemObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //m_VM->createSYMemObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;
        case SCALL_CHMOD:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 777, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            //printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            //m_VM->createSYMemObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            //m_VM->createSYMemObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            //m_VM->createSYMemObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //m_VM->createSYMemObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;
        case SCALL_PERSONALITY:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0x0, "persona_rdi");
        }   break;
        case SCALL_MMAP:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            //---sym %r10
            //tmp += 0x38;
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1, "flags_r10");

            //---sym %r9
            //tmp += 0x40;
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "offset_r9");

            //---sym %r8
            //tmp += 0x48;
            //m_VM->createSYMemObject(tmp, 8, 1, 1, -1, "fd_r8"); //symbol

            //---sym %rdx
            //tmp += 0x60; //adr of rdx
            //m_VM->createSYMemObject(tmp, 8, 0, 1, 0x3, "prot_rdx");

            //---sym %rsi
            //tmp+= 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 0, 1, 1024, "len_rsi");

            //---sym %rdi
            tmp+= 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0x0, "adr_rdi");

        }   break;
        case SCALL_READ:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; //adr of rdx
            //m_VM->createSYMemObject(tmp, 8, 0, 1, 0x2, "count_rdx"); 
            tmp += 8;
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0x7fffffffdfc0, "bufadr_rsi"); 
            tmp += 8;
            //m_VM->createSYMemObject(tmp, 8, 0, 1, 3, "fd_rdi"); 
        }   break;
        case SCALL_MSYNC:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; //adr of rdx
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0x1, "flags_rdx"); 
        }   break;
        
        case SCALL_MINCORE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0, "len_rsi"); 
        }   break;
        
        case SCALL_GETITIMER:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0, "which_rdi"); //ITIMER_REAL 0
        }   break;
        case SCALL_SETITIMER:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0, "which_rdi"); //ITIMER_REAL 0
        }   break;
        case SCALL_FLOCK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 0, 1, 1, "operation_rdi"); 
        }   break;
        case SCALL_GETRUSAGE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0, "who_rdi"); 
        }   break;
        case SCALL_SETPGID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 0, "pgid_rsi"); 
        }   break;
        case SCALL_SETREUID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, -1, "euid_rsi"); 
        }   break;
        case SCALL_SETREGID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, -1, "egid_rsi"); 
        }   break;
        case SCALL_CAPGET:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            ulong adr = *((ulong*)tmp);
            //printf("adr : %lx\n", adr);
            m_VM->createSYMemObject(adr, 4, 0, 1, 0x20080522, "version"); //first element of  the struct pointed to by the %rdi
            //m_VM->createSYMemObject(adr + 4, 4, 0, 1, 0x0, "pid"); //second element of  the struct pointed to by the %rdi
        }   break;
        case SCALL_SETUID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 2000, "uid_rdi"); 
        }   break;
        case SCALL_SETGID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 2000, "gid_rdi");
        }   break;
        case SCALL_GETGROUPS:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 0, 1, 32, "size_rdi");
        }   break;
        case SCALL_SETGROUPS:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 0, 1, 32, "size_rdi");
        }   break;
        case SCALL_SETRESUID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, -1, "euid_rsi"); 
        }   break;
        case SCALL_SETRESGID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, -1, "euid_rsi"); 
        }   break;
        case SCALL_SETFSUID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; 
            m_VM->createSYMemObject(tmp, 8, 1, 1, 2000, "fsuid_rdi"); 
        }   break;
        case SCALL_SETFSGID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; 
            m_VM->createSYMemObject(tmp, 8, 1, 1, 2000, "fsgid_rdi"); 
        }   break;
        case SCALL_GETSID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_SCHED_GETPARAM:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_SCHED_SETPARAM:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_OPEN:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; 
            m_VM->createSYMemObject(tmp, 8, 1, 1, 777, "mode_rdx");
            tmp += 0x8;
            //m_VM->createSYMemObject(tmp, 8, 0, 1, (0 ), "flags_rsi"); //O_RDONLY 0   O_CREAT 64
            tmp += 0x8;
            //unsigned long old_filename_adr = *(unsigned long*)tmp;
            //printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            //m_VM->createSYMemObject(old_filename_adr + 6, 1, 0, 1, 0x68, "fname_rdi_6"); //7th character in file name "/proc/kallsyms", i.e. 'k'
        }   break;
        case SCALL_IOPL:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1, "pid_rdi"); 
        }   break;
        case SCALL_IOPERM:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60;  //adr of rdx
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "turn_on_rdx");
            tmp += 0x8;  //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 32, "num_rsi"); 
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x378 "from_rdi");    
        }   break;
        case SCALL_UTIME:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "times_rsi"); 
        }   break;
        case SCALL_UTIMES:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "times_rsi"); 
        }   break;
        case SCALL_SCHED_GETSCHDLR:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "pid_rdi"); 
        }   break;
        case SCALL_MLOCKALL:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 1, "flags_rdi"); 
        }   break;
        case SCALL_PRCTL:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 15, "arg1_rdi"); 
        }   break;
        case SCALL_ARCH_PRCTL:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1004, "code_rdi"); 
        }   break;
        case SCALL_ACCT:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "code_rdi"); 
        }   break;
        case SCALL_SCHED_SETSCHDLR:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x3, "policy_rsi");
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); //symbol
        }   break;
        case SCALL_SCHED_GETAFFINITY:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 32, "size_rsi");
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); //symbol
        }   break;
        case SCALL_SCHED_SETAFFINITY:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 64, "size_rsi"); //symbol
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_SCHED_RR_GT_INTVL:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 64, "size_rsi"); 
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); //symbol
        }   break;
        case SCALL_UNSHARE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, (0x00000200 | 0x00000400), "flags_rdi"); 
        }   break;
        case SCALL_STATX:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            //------------------------
            //tmp += 0x70; //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0xffffff9c, "dirfd_rdi"); //seed = -100
            //------------------------
            tmp += 0x60; //adr of rdx
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "flags_rdx"); 

            //------------------------
            //tmp += 0x38; //adr of r10
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x00000200U, "mask_r10"); 
            //m_VM->createSYMemObject(tmp, 8, 1, 1, (0x00000001U | 0x00000002U), "mask_r10"); 
        }   break;
        case SCALL_TEE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x38; //adr of r10
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x04, "flags_r10"); 
        }   break;
        case SCALL_SET_ROBUST_LIST:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 24, "len_rsi"); //symbol 
        }   break;
        case SCALL_GET_ROBUST_LIST:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_MLOCK2:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; //adr of rdx
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x01, "flags_rdx"); //##symbol
            tmp+= 0x8;
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1024, "len_rsi");
        }   break;
        case SCALL_MPROTECT:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; //adr of rdx
            //m_VM->createSYMemObject(tmp, 8, 1, 1, (ulong)0x1, "prot_rdx");
            tmp += 0x8;  //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 4096, "len_rsi"); 
            tmp += 0x8;  //adr of rdi
            unsigned long val = *(unsigned long*)tmp;
            m_VM->createSYMemObject(tmp, 8, 1, 1, val, "addr_rdi");    //0x7ffff7ff4000
        }   break;
        case SCALL_USERFAULTFD:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 524288, "flags_rdi"); 
        }   break;
        case SCALL_KCMP:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; //adr of rdx
            m_VM->createSYMemObject(tmp, 8, 1, 1, 2, "type_rdx"); 
        }   break;
        case SCALL_PIPE2:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68; //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 2048, "flags_rsi"); //symbol 
            tmp += 0x8;  //adr of rdi

            //symbolize buffer address
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x7fffffffdfe0, "bufadr_rdi"); 

            //symbolize the buffer content
            //unsigned long fd0_adr = *(unsigned long*)tmp;
            //unsigned long fd1_adr = fd0_adr + 4;
            //printf("tmp : %lx fd2 %d, fd2 %d\n", *(unsigned long*)tmp, *(int *)fd0_adr, *(int *)fd1_adr);
            //m_VM->createSYMemObject( fd0_adr, 4, 1, 1, 0x2, "fd1");
            //m_VM->createSYMemObject( fd1_adr, 4, 1, 1, 0x1, "fd2");
        }   break;
        case SCALL_DUP3:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; //adr of rdx
            m_VM->createSYMemObject(tmp, 8, 1, 1, 524288, "flags_rdx"); 
        }   break;
        case SCALL_CLOSE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 4, "fd_rdi"); 
        }   break;
        case SCALL_BRK:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "adr_rdi"); 
        }   break;
        case SCALL_SHMGET:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60;  //adr of rdx            
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x200, "flag_rdx");    
            tmp += 0x8;  //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "size_rsi"); 
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "key_rdi");

        }   break;
        case SCALL_EXIT:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x70; //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "err_rdi"); 
        }   break;
        case SCALL_SHMAT:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60;  //adr of rdx
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "shmid_rdx");
            tmp += 0x8;  //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "shmadr_rsi"); 
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1000, "flag_rdi");    
        }   break;
        case SCALL_PRLIMIT64:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x60; //adr of rdx
            unsigned long bRlim = *(unsigned long*)tmp;  //bRlim has the address of rlimit struct
            m_VM->createSYMemObject(bRlim+0x8, 8, 1, 1, 0x0, "new_rlim_lim_max_rdx");  //symbolize the 2nd object of rlimit obj
            
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x7, "resource_rdi"); //seed val 7 : RLIMIT_NOFILE
        }   break;
        case SCALL_PKEY_ALLOC:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif   
            tmp += 0x68;  //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0, "access_rights_rsi"); 
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "flags_rdi");

        }   break;
        case SCALL_GETPGID:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif    
            tmp += 0x70;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "pid_rdi");

        }   break;
        case SCALL_EPOLL_CREATE:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif    
            tmp += 0x70;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0x1, "size_rdi");

        }   break;     
        case SCALL_EPOLL_CREATE1:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif    
            tmp += 0x70;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 524288, "flags_rdi");

        }   break;
        case SCALL_EVENTFD2:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif
            tmp += 0x68;  //adr of rsi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 524288, "flags_rsi");    
            tmp += 0x8;  //adr of rdi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0X0, "initval_rdi");

        }   break;  
        case SCALL_EVENTFD:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif   
            tmp += 0x70;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0X0, "initval_rdi");

        }   break; 
        case SCALL_INOTIFY_INIT1:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif   
            tmp += 0x70;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0X0, "flags_rdi");
            
        }   break;    
        case SCALL_FANOTIFY_INIT:
        {
#ifndef _PROD_PERF 
            printf("case:%d\n", (int)scall_idx);
#endif   
            tmp += 0x68;  //adr of rsi
            //m_VM->createSYMemObject(tmp, 8, 1, 1, 0x0, "event_f_flags_rsi");    
            tmp += 0x8;  //adr of rdi
            m_VM->createSYMemObject(tmp, 8, 1, 1, 0X0, "flags_rdi");
            
        }   break;             
        default:
        {
            ret = false;
        }   break;
    }

    return ret;
}
