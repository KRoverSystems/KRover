#include <iostream>
#include <fstream>
#include <linux/types.h>
#include <ucontext.h>
#include <set>
#include <cassert> 
#include <string.h>

std::set<unsigned long> allEntriesAddr ;
std::set<unsigned long> allVAAddress ;
std::set<unsigned long> ptEntriesAddr_4K ;
std::set<unsigned long> ptEntriesAddr_2M ;
std::set<unsigned long> ptEntriesAddr_1G ;
std::set<unsigned long>  pageTableAddr ;

// I don't know how to calculate,
// hard code, this is for 16GB Physical RAM 0x0000 0003 FFFF F000
// for 4GB, should be 0x0000 0000 FFFF F000
#define PHYS_MASK (0x00000007FFFFF000UL)
#define PS_BIT (0x80)
#define IS_PAGE(x) ((x)&0x80)
#define IS_VAILD(x) (((x)&0x1)==0x1)

static unsigned long read_cr3(void) ;
static unsigned long Traverse(unsigned long cr3, unsigned long linear_addr) ;


#ifndef phys_to_virt
#define page_offset_base (0xffff888000000000UL)
#define phys_to_virt(x) ((unsigned long*)(((unsigned long) (x)) + page_offset_base))
#define printk printf
#define KERN_INFO
#else
extern unsigned long page_offset_base ;
#endif


static unsigned long read_cr3(void) {
    unsigned long cr3 = 0, cr4 = 0 ;
    asm volatile (  "mov %%cr3, %%rax; \n\t"
                    "mov %%rax, %0; \n\t"
                    "mov %%cr4, %%rax; \n\t"
                    "mov %%rax, %1; \n\t"
                    :"=m"(cr3), "=m"(cr4)::"%rax");

    return cr3;
}
static void addVA (unsigned long VA) {
    allVAAddress.insert(VA) ;
}
static void Traverse_PT (unsigned long VA_Start, unsigned long pdE) {
    int index = 0x0 ;
    unsigned long *pt = phys_to_virt(pdE&PHYS_MASK) ;
    unsigned long ptE ;
    unsigned long VA ;

    pageTableAddr.insert((unsigned long)pt) ;

    for(index =0 ; index < 0x200; index ++) {
        
        VA = VA_Start | ((unsigned long)index) << 12 ;
        ptE = pt[index] ;
        if (IS_VAILD(ptE)) {
            allEntriesAddr.insert((unsigned long)&pt[index]) ;
            addVA(VA) ;
        } 
    }
}

static void Traverse_PD (unsigned long VA_Start, unsigned long pdptE) {
    int index = 0x0 ;
    unsigned long *pd = phys_to_virt(pdptE&PHYS_MASK) ;
    unsigned long pdE ;
    unsigned long VA ;

    pageTableAddr.insert((unsigned long)pd) ;

    for(index =0 ; index < 0x200; index ++) {
        
        VA = VA_Start | ((unsigned long)index) << 21 ;
        pdE = pd[index] ;
        if (IS_VAILD(pdE)) {
            if(!IS_PAGE(pdE)) {
                Traverse_PT(VA, pdE) ;

            }
            else {
                allEntriesAddr.insert((unsigned long)&pd[index]) ;
                addVA(VA) ;
            }
        } 
    }
}

static void Traverse_PDPT (unsigned long VA_Start, unsigned long pml4E) {

    int index = 0x0 ;
    unsigned long *pdpt = phys_to_virt(pml4E&PHYS_MASK) ;
    unsigned long pdptE ;
    unsigned long VA ;

    pageTableAddr.insert((unsigned long)pdpt) ;

    for(index =0 ; index < 0x200; index ++) {

        VA = VA_Start | ((unsigned long)index) << 30 ;
        pdptE = pdpt[index] ;
        if (IS_VAILD(pdptE)) {
            if(!IS_PAGE(pdptE)) {
                Traverse_PD(VA, pdptE) ;

            } else {
                allEntriesAddr.insert((unsigned long)&pdpt[index]) ;
                addVA(VA) ;
            }
        }
    }
}


static void Traverse_PML4 (unsigned long cr3) {

    int index = 0x100 ;
    unsigned long *pml4 = phys_to_virt(cr3&PHYS_MASK) ;
    unsigned long pml4E ;
    unsigned long VA ;

    pageTableAddr.insert((unsigned long)pml4) ;
    
    for(; index<0x200; index++) {

        if (index == 0x1fe) continue ;

        VA = (0xFFFF000000000000UL) | (((unsigned long)index)<<39);
        pml4E = pml4[index] ;
        
        if(IS_VAILD(pml4E)) {
            
            Traverse_PDPT (VA, pml4E) ;
        }
    }

}


static void Traverse (unsigned long cr3) {

    Traverse_PML4(cr3) ;
}



static unsigned long Translate(unsigned long cr3, unsigned long linear_addr, unsigned long *pagesize, unsigned long *EntryAddress)
{
    unsigned long *pml4, pml4E ;
    unsigned long *pdpt, pdptE ;
    unsigned long *pd,   pdE ;
    unsigned long *pt,   ptE ;

    int index ;

    unsigned long phys_addr = 0 ;

    // pml4, pml4 entry
    pml4 = phys_to_virt(cr3&PHYS_MASK);

    index = (linear_addr >> 39) & 0x1ff ;  // entry index in pml4 ;
    pml4E = pml4[index] ;                  // physical address of pdpt come from pml4E
    if (IS_PAGE(pml4E)) {
        return 0 ;
    }

    // pdpt, pdpt entry 
    pdpt = phys_to_virt(pml4E & PHYS_MASK) ;
    index = (linear_addr >> 30) & 0x1ff ;
    pdptE = pdpt[index] ;                   // physical address of pd come from pdptE

    if(IS_PAGE(pdptE)) {
        phys_addr = (pdE & (0x0000000FC0000000UL)) | (0x3fffffff & linear_addr) ;
        *pagesize = 1024*1024*1024UL ;
        *EntryAddress = (unsigned long)&pdpt[index] ;

        return phys_addr ;
    }

    // pd, pd entry
    index = (linear_addr >> 21) & 0x1ff ;
    pd = phys_to_virt(pdptE & PHYS_MASK);
    pdE = pd[index] ;                       // physical address of pt come from pdE    

    if(IS_PAGE(pdE)) {
        // PS = 1, this is 2MB page.
        phys_addr = (pdE & (0x0000000FFFE00000UL)) | (0x1fffff & linear_addr) ;
        *pagesize = 1024*1024*2UL ;
        *EntryAddress = (unsigned long)&pd[index] ;

    } else {
        index = (linear_addr >> 12) & 0x1ff ;
        pt = phys_to_virt(pdE & PHYS_MASK) ;
        ptE = pt[index] ;                   // final physical address come from ptE

        phys_addr = (ptE & PHYS_MASK) | (linear_addr & 0xfff);
        *pagesize = 1024*4UL ;
        *EntryAddress = (unsigned long)&pt[index] ;
    }
    return phys_addr ;
}

static __attribute_noinline__ void invalidateTLBEntry(unsigned long VA) {

    asm volatile (
        "invlpg (%rdi); \n\t"
        );
}

static void AllPTPages(unsigned long cr3) {
    int i ;
    unsigned long ptPagePA ;
    unsigned long pagesize ;
    unsigned long EntryAddress ;

    printk (KERN_INFO "all pages use %lu entries.\n", allEntriesAddr.size()) ;
    printk (KERN_INFO "page table using: %lu\n", pageTableAddr.size()) ;
    
    for (auto it = pageTableAddr.begin() ; it != pageTableAddr.end(); it++) {
        ptPagePA = Translate(cr3, *it, &pagesize, &EntryAddress) ;

        if (pagesize==1024*1024*2UL) {
            ptEntriesAddr_2M.insert (EntryAddress) ;
            printk  ("2M %016lx\n", *it) ;

        } else if (pagesize==1024*4UL) {
            ptEntriesAddr_4K.insert (EntryAddress) ;

        } else if (pagesize==1024*1024*1024UL) {
            ptEntriesAddr_1G.insert (EntryAddress) ;
            printk  ("1G %016lx\n", *it) ;
        } else {
            // printk ("") ;
        }
    }

    printk ("\n\n4K entries %lu :\n", ptEntriesAddr_4K.size()) ;
    //for (auto it : ptEntriesAddr_4K) {
    //    printk ("\t0x%016lx\n", it) ;
    //}

    printk ("\n\n2M entries %lu :\n", ptEntriesAddr_2M.size()) ;
    //for (auto it : ptEntriesAddr_2M) {
    //    printk ("\t0x%016lx\n", it) ;
    //}

    printk ("\n\n1G entries %lu :\n", ptEntriesAddr_1G.size()) ;
    //for (auto it : ptEntriesAddr_1G) {
    //    printk ("\t0x%016lx\n", it) ;
    //}
    
    int modify_count = 0 ;
    for(auto it : allEntriesAddr) {

        auto found_1g = ptEntriesAddr_1G.find(it) ;
        if(found_1g != ptEntriesAddr_1G.end())
            continue ;

        auto found_2M = ptEntriesAddr_2M.find(it) ;
        if(found_2M != ptEntriesAddr_2M.end())
            continue ;
        
        auto found_4K = ptEntriesAddr_4K.find(it) ;
        if(found_4K != ptEntriesAddr_4K.end())
            continue ;

        // entry is not a page table used entry ;
        unsigned long *entryVA = (unsigned long*)it;
        *entryVA = (*entryVA) & (0xFFFFFFFFFFFFFFFDUL) ; // read only;
        modify_count ++ ;

    }

    // this will invalidate TLB by just write cr3.
    // maybe some limitation, now we have a CR4.PGE = 0 and CR4.PCIDE=0, 
    // CR3.G (global page.) for different entries, some time it is '1', some time '0' 
    // this bit should be ignored.

    // intel manual says, 
    // "If CR4.PCIDE = 0, the instruction invalidates all TLB entries associated with PCID 000H except those for
    // global pages. It also invalidates all entries in all paging-structure caches associated with PCID 000H" 
    // but I don't quite understand, if PCIDE is 0, what is the PCID=000H.
    // so I keep the above invlpg for backup.
    asm ("mfence \n\t") ;
    asm volatile (
        "movq %0, %%rax; \n\t"
        "movq %%rax, %%cr3; \n\t"
        ::"m"(cr3):"%rax");
    asm ("mfence \n\t") ;
    
}
typedef struct _BackupPages {
    unsigned long VA ;
    unsigned long entry ;
    unsigned long pgPtr ;
    unsigned long size ;
} BackupPages ;
BackupPages bkPG[40] ;



#define NUM_MAX_4K_PAGE (200)
#define NUM_MAX_2M_PAGE (10)
static void *pagePool4K ;
static void *pagePool2M ;

static int pf_fixed_4k = 0 ;
static int pf_fixed_2m = 0 ;
static int pf_fixed = 0 ;


void init_pgTable (void) {    

    unsigned long cr3 = read_cr3 () ;
    pf_fixed_4k = pf_fixed_2m = pf_fixed = 0 ;

    pagePool4K = malloc (4096*(NUM_MAX_4K_PAGE)+1) ;
    pagePool2M = malloc (2*1024*1024*(NUM_MAX_2M_PAGE+1)) ;
    
    printf ("allocate @ 0x%lx, 0x%lx\n", (unsigned long)pagePool4K, (unsigned long) pagePool2M) ;
    // touch each to avoid alloc on write.
    for (int i=0; i<NUM_MAX_4K_PAGE; i++) {
        unsigned char *ptr ;
        ptr = (unsigned char*)pagePool4K + (1024*4*i) ;
        ptr[0] = 0x55 ;
        ptr[1] = 0xaa ;
    }

    for (int i=0; i<NUM_MAX_2M_PAGE; i++) {
        unsigned char *ptr ;
        ptr = (unsigned char*)pagePool2M + (1024*1024*2*i) ;
        
        for (int j=0; j<512; j++) {
            ptr[0] = 0x55 ;
            ptr[1] = 0xaa ;

            ptr += 4*1024 ;
        }
    }

    assert (pagePool2M && pagePool4K) ;


    Traverse(cr3) ;
    AllPTPages(cr3) ;

}
void print_pf_fixed() {

    printf ("pf_fixed: %d, 4K: %d, 2M: %d\n", pf_fixed, pf_fixed_4k, pf_fixed_2m) ;
}

//give write access to the page
bool AllowPGWrite (unsigned long VA) {
    unsigned long cr3 = read_cr3 () ;
    unsigned long pgSize, entry ;
    unsigned long *entryVA ;
    
    Translate (cr3, VA, &pgSize, &entry) ;

    entryVA = (unsigned long*)entry ;
    *entryVA = (*entryVA) | 2 ;

    asm ("mfence \n\t") ;
    invalidateTLBEntry (VA) ;
    asm ("mfence \n\t") ;

    bkPG[pf_fixed].entry = (unsigned long)entryVA ;

    if (pgSize == 1024*4UL) {

        if(pf_fixed_4k >= NUM_MAX_4K_PAGE) {
            print_pf_fixed () ;
            assert (0) ;
        }

        bkPG[pf_fixed].size = 1024*4UL ;
        bkPG[pf_fixed].VA = VA & (~(0xfffUL)) ;
        bkPG[pf_fixed].pgPtr = ((unsigned long)pagePool4K + ((unsigned long)pf_fixed_4k*1024*4UL  + 0xfff))  & (~(0xfffUL));
        
        pf_fixed_4k ++ ;
    }
    
    if (pgSize == 1024*1024*2UL) {

        if (pf_fixed_2m >= NUM_MAX_2M_PAGE){
            print_pf_fixed () ;
            assert (0) ;
        }

        bkPG[pf_fixed].size = 1024*1024*2UL ;
        bkPG[pf_fixed].VA = VA  & (~(0x1fffffUL));
        bkPG[pf_fixed].pgPtr = ((unsigned long)pagePool2M + ((unsigned long)pf_fixed_2m*1024*1024*2UL + 0x1fffff))  & (~(0x1fffffUL));
        
        pf_fixed_2m ++ ;
    }

    if (pgSize == 1024*1024*1024UL) {
        printf( "1G page size not handled, die now !");
        assert(0);
    }

    printf ("copy 0x%lx, 0x%lx, %d\n", bkPG[pf_fixed].pgPtr, bkPG[pf_fixed].VA, (int)bkPG[pf_fixed].size) ;
    memcpy((void*)bkPG[pf_fixed].pgPtr, (void*)bkPG[pf_fixed].VA, bkPG[pf_fixed].size) ;

    pf_fixed ++ ;
    return true ;
}


void restore_pages() {
    int i ;
    unsigned long *entryVA ;

    for(i=0; i<pf_fixed; i++) {
        memcpy( (void*)bkPG[i].VA, (void*)bkPG[i].pgPtr, bkPG[i].size) ;
        entryVA = (unsigned long*)bkPG[i].entry;
        *entryVA = (*entryVA) & (~2UL) ;

        asm ("mfence \n\t") ;
        invalidateTLBEntry (bkPG[i].VA) ;
        asm ("mfence \n\t") ;
    }
    pf_fixed_4k = pf_fixed_2m = pf_fixed = 0 ;
}

void check_all_gprs() {
    unsigned long rax, rbx, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15, rbp, rsi, rdi;
    
    asm volatile (
            "movq %%rax, %0; \n\t"
            "movq %%rbx, %1; \n\t"
            "movq %%rcx, %2; \n\t"
            "movq %%rdx, %3; \n\t"
            "movq %%r8, %4; \n\t"
            "movq %%r9, %5; \n\t"
            "movq %%r10, %6; \n\t"
            "movq %%r11, %7; \n\t"
            "movq %%r12, %8; \n\t"
            "movq %%r13, %9; \n\t"
            "movq %%r14, %10; \n\t"
            "movq %%r15, %11; \n\t"
            "movq %%rbp, %12; \n\t"
            "movq %%rsi, %13; \n\t"
            "movq %%rdi, %14; \n\t"
            ::"m"(rax), "m"(rbx), "m"(rcx), "m"(rdx), "m"(r8), "m"(r9), "m"(r10), "m"(r11), "m"(r12), "m"(r13), "m"(r14), "m"(r15), 
            "m"(rbp), "m"(rsi), "m"(rdi):"%rax", "%rbx", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%rbp", "%rsi", "%rdi");

            printf ("check gprs: %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx\n", 
            rax, rbx, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15, rbp, rsi, rdi) ;

}