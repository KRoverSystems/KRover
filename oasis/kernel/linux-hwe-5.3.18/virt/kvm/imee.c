#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>

#include <asm/desc.h>
#include <asm/apic.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include "imee.h"
#include "../../arch/x86/kvm/vmx/vmx.h"

LIST_HEAD(introspection_contexts);

intro_ctx_t *current_target;
EXPORT_SYMBOL_GPL(current_target);

volatile int t_exit_flg;
EXPORT_SYMBOL_GPL(t_exit_flg);

volatile int imee_pid;
EXPORT_SYMBOL_GPL(imee_pid);
volatile struct kvm_vcpu *imee_vcpu;
EXPORT_SYMBOL_GPL(imee_vcpu);

spinlock_t sync_lock;
EXPORT_SYMBOL_GPL(sync_lock);

volatile unsigned long last_cr3;
EXPORT_SYMBOL_GPL(last_cr3);
unsigned long ana_h_cr3;
EXPORT_SYMBOL_GPL(ana_h_cr3);

volatile unsigned long last_rip;
EXPORT_SYMBOL_GPL(last_rip);
volatile unsigned long last_rsp;
EXPORT_SYMBOL_GPL(last_rsp);

struct desc_ptr imee_idt, imee_gdt;
EXPORT_SYMBOL_GPL(imee_idt);
EXPORT_SYMBOL_GPL(imee_gdt);

struct kvm_sregs imee_sregs;
EXPORT_SYMBOL_GPL(imee_sregs);

struct kvm_segment imee_tr;
EXPORT_SYMBOL_GPL(imee_tr);

// #define NBASE 4
#define NBASE 40
void *p_bases[NBASE];
void *p_base;
int p_base_idx;
int p_idx;
#define PAGE_ORDER 10

struct arg_blk imee_arg;
EXPORT_SYMBOL_GPL(imee_arg);
// struct shar_arg* ei_shar_arg;
// EXPORT_SYMBOL_GPL (ei_shar_arg);
struct shar_arg *guest_vcpu_paste;
EXPORT_SYMBOL_GPL(guest_vcpu_paste);

struct sig_record sig_array[64];
EXPORT_SYMBOL_GPL(sig_array);

struct gva_hpa_pair gva_hpa_pool[max_pf_pool];
EXPORT_SYMBOL_GPL(gva_hpa_pool);
struct gva_hpa_pair int3_gva_hpa_pool[max_int3_pool];
EXPORT_SYMBOL_GPL(int3_gva_hpa_pool);

int crt_pfpool_idx; //the Number of used gva_hpa pairs.
EXPORT_SYMBOL_GPL(crt_pfpool_idx);
int int3_pool_idx;
EXPORT_SYMBOL_GPL(int3_pool_idx);
int pf_cache_flag;
EXPORT_SYMBOL_GPL(pf_cache_flag);
// int crt_search_idx;//It is likely an index of
// EXPORT_SYMBOL_GPL(crt_search_idx);
// int pre_search_idx;//add this to handle cross page hook
// EXPORT_SYMBOL_GPL(pre_search_idx);

struct ve_page ve_intcp_pages[max_ve_pages];
EXPORT_SYMBOL_GPL(ve_intcp_pages);
int crt_ve_pool_idx;
EXPORT_SYMBOL_GPL(crt_ve_pool_idx);

unsigned long host_syscall_entry;
EXPORT_SYMBOL_GPL(host_syscall_entry);
unsigned long guest_syscall_entry;
EXPORT_SYMBOL_GPL(guest_syscall_entry);
unsigned long
	onsite_syscall_entry; //ana and target share same syscall MSR in onsite mode
EXPORT_SYMBOL_GPL(onsite_syscall_entry);
unsigned long host_pf_entry;
EXPORT_SYMBOL_GPL(host_pf_entry);

/* inform guest vcpu its time to share vcpu states in ei_shar_arg*/
// int onsite_ready;
// EXPORT_SYMBOL_GPL(onsite_ready);

int kernel_idx; //defined in walk_gpt_new as 468
int user_idx; //defined as 255 currently
unsigned long UK_OFFSET;
EXPORT_SYMBOL_GPL(UK_OFFSET);

unsigned long eptp_list;
void *ana_tss_tmp;

// 64bit
#define HPTE_P_MASK 0x1
#define EPTE_P_MASK 0x7
#define EPTE_L_MASK (0x1 << 7)
#define HPTE_L_MASK (0x1 << 7)
#define HPTE_NX_BIT (0x1 << 63)
#define EPTE_SVE_BIT (0x1UL << 63)
#define NO_CONFLICT_GPA_MASK 0x006000000000UL
#define GPA_MASK 0x7FFFFFF000UL
#define HPAE_MASK 0x7FFFFFF000UL //mask PT entry to become a valid pa
#define EPTE_MASK (0x8000007FFFFFF000UL)
#define NL_EPTE_MASK 0x107UL //RWX for a non-leaf & not large EPTE
#define L_PDE_OFFSET 0x1FF000UL //OFFSET MASK if it is a large PD entry
#define L_PDPTE_OFFSET 0x3FFFF000UL //OFFSET MASK if it is a large PDPT entry
// #define PAGESIZE 0x1000
// #define L_RWX_EPTE 0xF77UL //RWX for a leaf EPTE
// #define PTE_RW_BIT          0x2
// #define PAGE_P_MASK 0x7UL//invalid entry if last 3 bits are all 0
// #define L_PAGE_MASK 0x80UL // check if it is a LARGE entry
// #define HPA_MASK (0xFFFUL | (1UL << 63))
// #define EPT_MASK (0xFFFUL | (1UL << 63))

// void clear_smap_bit (void)
// {
//     unsigned long cr4;
//
//     asm volatile ("movq %%cr4, %0;":"=r"(cr4)::);
//     // printk (KERN_ERR "changing CR4 from %X\n", cr4);
//     cr4 &= ~(1 << 21);
//     // printk (KERN_ERR "to %X, WP_bit cleared.\n", cr4);
//     asm volatile ("movq %0, %%cr4;"::"r"(cr4):);
//     return;
// }
//
// void set_smap_bit (void)
// {
//     unsigned long cr4;
//
//     asm volatile ("movq %%cr4, %0;":"=r"(cr4)::);
//     // printk (KERN_ERR "changing CR4 from %X\n", cr4);
//     cr4 |= (1 << 21);
//     // printk (KERN_ERR "to %X, WP_bit set\n", cr4);
//     asm volatile ("movq %0, %%cr4;"::"r"(cr4):);
//     return;
// }

void imee_write_eoi_64(void)
{
	apic->write(APIC_EOI, 0);

	/* check if the CPU in the vcpu mode and have vmcs loaded */
	struct kvm_vcpu *vcpu = current_target->target_vcpu;
	int cpu = smp_processor_id();
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	if (vmx && vmx->loaded_vmcs && vmx->loaded_vmcs->cpu == cpu) {
		kvm_x86_ops->read_rsp_rip_64((u64 *)&last_rsp,
					     (u64 *)&last_rip);
		kvm_x86_ops->get_sregs(vcpu, &imee_sregs);
		guest_syscall_entry =
			kvm_x86_ops->get_guest_syscall_entry(vcpu);
		last_cr3 = imee_sregs.cr3;
		t_exit_flg++;
		smp_wmb();
	}
	return;
}

asmlinkage void imee_guest_int(void);
asm("  .text");
asm("  .type   imee_guest_int, @function");
asm("imee_guest_int: \n");
asm("cli \n");
asm("pushq %rax \n");
asm("pushq %rbx \n");
asm("pushq %rcx \n");
asm("pushq %rdx \n");
asm("pushq %rsi \n");
asm("pushq %rdi \n");
asm("pushq %rbp \n");
asm("pushq %r8 \n");
asm("pushq %r9 \n");
asm("pushq %r10 \n");
asm("pushq %r11 \n");
asm("pushq %r12 \n");
asm("pushq %r13 \n");
asm("pushq %r14 \n");
asm("pushq %r15 \n");
asm("call imee_write_eoi_64 \n");
asm("popq %r15 \n");
asm("popq %r14 \n");
asm("popq %r13 \n");
asm("popq %r12 \n");
asm("popq %r11 \n");
asm("popq %r10 \n");
asm("popq %r9 \n");
asm("popq %r8 \n");
asm("popq %rbp \n");
asm("popq %rdi \n");
asm("popq %rsi \n");
asm("popq %rdx \n");
asm("popq %rcx \n");
asm("popq %rbx \n");
asm("popq %rax \n");
asm("sti \n");
asm("iretq");

struct kvm_vcpu *pick_cpu(struct kvm *target_kvm)
{
	// TODO: randomly pick a cpu?
	return target_kvm->vcpus[0];
}
EXPORT_SYMBOL_GPL(pick_cpu);

// static pte_t* get_pte (struct task_struct *tsk, unsigned long addr)
// {
//     pgd_t* pgd;
//     pud_t* pud;
//     pmd_t* pmd;
//     pte_t* pte;
//
//     struct mm_struct* mm = tsk->mm;
//
//     pgd = pgd_offset (mm, addr);
//     if (pgd_none (*pgd) || pgd_bad (*pgd)) return 0;
//
//     pud = pud_offset (pgd,addr);
//     if (pud_none (*pud) || pud_bad (*pud)) return 0;
//
//     pmd = pmd_offset (pud, addr);
//     if (pmd_none (*pmd) || pmd_bad (*pmd)) return 0;
//
//     pte = pte_offset_map (pmd, addr);
//     if (pte_none(*pte))
//     {
//         pte_unmap (pte);
//         return 0;
//     }
//
//     return pte;
// }

/* get hpa page address for a gpa (guest VM) */
ulong gpa_to_hpa_guest(struct kvm *target_kvm, gpa_t gpa)
{
	struct kvm_arch *arch = &target_kvm->arch;
	struct kvm_mmu_page *page;
	u64 *p;
	int idx;
	ulong hpa;

	list_for_each_entry (page, &arch->active_mmu_pages, link) {
		//matched epte in a leaf EPT page
		if (page->role.level == 1 &&
		    page->gfn == ((gpa >> 12) & ~0x1FFUL)) {
			p = page->spt;
			idx = (gpa >> 12) & 0x1FFUL;
			hpa = (ulong)(p[idx] & PAGE_MASK);
			DBG("level 1 ept page. hpa: %lX gpa: %lX\n", hpa, gpa);
			return hpa;
		}
	}

	list_for_each_entry (page, &arch->active_mmu_pages, link) {
		//matched with a large entry in a EPT PD page
		if (page->role.level == 2 &&
		    page->gfn == ((gpa >> 12) & ~0x3FFFFUL)) {
			p = page->spt;
			idx = (gpa >> 21) & 0x1FFUL;
			if ((p[idx] & EPTE_L_MASK)) {
				hpa = (ulong)(p[idx] & PAGE_MASK) +
				      (gpa & 0x1FF000);
				DBG("level 2 ept page. hpa: %lX gpa: %lX\n",
				    hpa, gpa);
				return hpa;
			} else {
				DBG("matched PDE entry is not a large entry. gpa: %lx. idx: %d. entry: %lx. \n",
				    gpa, idx, p[idx]);
				return 0;
			}
		}
	}

	return 0;
}

u64 get_epte_onsite(intro_ctx_t *ctx, u64 gpa)
{
	struct kvm_mmu_page *cur;
	int idx;
	gpa_t needle;
	needle = (gpa >> 12);

	//if it is a PTE
	idx = needle & 0x1FFUL;
	list_for_each_entry (cur, &ctx->pt_page, link) {
		if (cur->gfn == (needle & ~0x1FFUL)) {
			DBG("Found epte in leaf ept: %lX\n", cur->spt[idx]);
			return cur->spt[idx];
		}
	}

	//if it is a large PDE
	idx = (needle >> 9) & 0x1FFUL;
	list_for_each_entry (cur, &ctx->pd_page, link) {
		if (cur->gfn == (needle & ~0x3FFFFUL)) {
			if (cur->spt[idx] & EPTE_L_MASK) {
				DBG("Found epte in pd ept: %lX\n",
				    cur->spt[idx]);
				return cur->spt[idx];
			}
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(get_epte_onsite);

struct kvm_mmu_page *alloc_oasis_mmu_page(struct list_head *mmu_page_list,
					  int lv, gfn_t gfn);

static void adjust_imee_vcpu(struct kvm_vcpu *vcpu, ulong rip, ulong data,
			     struct arg_blk *args)
{
	struct msr_data msr_d = { 1, MSR_FS_BASE, args->rfs };
	unsigned long old_xcr0 ;

	vcpu->arch.regs[VCPU_REGS_RIP] = rip;
	__set_bit(VCPU_REGS_RIP,
		  (unsigned long *)&vcpu->arch.regs_dirty); // VCPU_REGS_RIP bit
	vcpu->arch.regs[VCPU_REGS_RSP] = data;

	// QHQHQHQHQ add:
	//vcpu->arch.regs[VCPU_REGS_RSS] = args.rss    ;
	vcpu->arch.regs[VCPU_REGS_RSP] = args->rsp;
	// vcpu->arch.regs[VCPU_REGS_RLAGES] = args->rflags ;
	//vcpu->arch.regs[VCPU_REGS_RCS] = args->rcs    ;
	vcpu->arch.regs[VCPU_REGS_RIP] = args->rip;
	vcpu->arch.regs[VCPU_REGS_RBX] = args->rbx;
	vcpu->arch.regs[VCPU_REGS_RBP] = args->rbp;
	vcpu->arch.regs[VCPU_REGS_R12] = args->r12;
	vcpu->arch.regs[VCPU_REGS_R13] = args->r13;
	vcpu->arch.regs[VCPU_REGS_R14] = args->r14;
	vcpu->arch.regs[VCPU_REGS_R15] = args->r15;
	vcpu->arch.regs[VCPU_REGS_RCX] = args->rcx;
	vcpu->arch.regs[VCPU_REGS_R11] = args->r11;
	vcpu->arch.regs[VCPU_REGS_RAX] = args->rax;
	vcpu->arch.regs[VCPU_REGS_RDI] = args->rdi;
	vcpu->arch.regs[VCPU_REGS_RSI] = args->rsi;
	vcpu->arch.regs[VCPU_REGS_RDX] = args->rdx;
	vcpu->arch.regs[VCPU_REGS_R8] = args->r8;
	vcpu->arch.regs[VCPU_REGS_R9] = args->r9;
	vcpu->arch.regs[VCPU_REGS_R10] = args->r10;

	__set_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RBX, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RBP, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R12, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R13, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R14, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R15, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RCX, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R11, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RAX, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RDI, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RSI, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_RDX, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R8,  (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R9,  (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(VCPU_REGS_R10, (unsigned long *)&vcpu->arch.regs_dirty);

	// kvm_x86_ops->set_rflags(vcpu, args->rflags & 0xffffefff);
	kvm_x86_ops->set_rflags(vcpu, args->rflags);
	kvm_x86_ops->set_msr(vcpu, &msr_d);

	msr_d.index = MSR_GS_BASE ;
	msr_d.data = args->rgs ;
	kvm_x86_ops->set_msr(vcpu, &msr_d);

	old_xcr0 = vcpu->arch.xcr0 ;
	//old_xcr0 |= 6 ;
	//vcpu->arch.xcr0 = args->xcr0 ;
	//kvm_set_xcr(vcpu, 0, args->xcr0) ;

	DBG("adjust_imee_vcpu: rip=0x%lx, rsp=0x%lx, fs=0x%lx, xcr0=0x%lx, old_xcr0=0x%lx \n",
	    args->rip, args->rsp, args->rfs, args->xcr0, old_xcr0);
	// QHQHQHQHQ -------------------------
	return;
}

/* EPT redirection. cannot handle if the gpa responsible by a large EPT entry */
int adjust_ept_entry(intro_ctx_t *ctx, unsigned long gpa, unsigned long new_pa,
		     int permission)
{
	struct kvm_mmu_page *oasis_mmu_page;
	int pml4_idx = (gpa >> 39) & 0x1FF;
	int pdpt_idx = (gpa >> 30) & 0x1FF;
	int pd_idx = (gpa >> 21) & 0x1FF;
	int pt_idx = (gpa >> 12) & 0x1FF;

	unsigned long eptp = ctx->eptp;
	u64 *pml4_ptr = __va(eptp);
	u64 *pdpt_ptr, *pd_ptr, *pt_ptr;
	gfn_t gfn;
	int lv;

	if (!(pml4_ptr[pml4_idx] & EPTE_P_MASK)) {
		lv = 3;
		gfn = gpa >> 12 & ~((1 << (lv * 9)) - 1);
		oasis_mmu_page =
			alloc_oasis_mmu_page(&ctx->non_leaf_page, lv, gfn);
		pdpt_ptr = oasis_mmu_page->spt;
		pml4_ptr[pml4_idx] = (__pa(pdpt_ptr) & HPAE_MASK) | 0x7;
	} else {
		pml4_ptr[pml4_idx] |= 0x7;
		pdpt_ptr = __va(pml4_ptr[pml4_idx] & HPAE_MASK);
		// DBG ("ept pml4 entry: %lx\n", pml4_ptr[pml4_idx]);
	}

	if (!(pdpt_ptr[pdpt_idx] & EPTE_P_MASK)) {
		lv = 2;
		gfn = gpa >> 12 & ~((1 << (lv * 9)) - 1);
		oasis_mmu_page =
			alloc_oasis_mmu_page(&ctx->non_leaf_page, lv, gfn);
		pd_ptr = oasis_mmu_page->spt;
		pdpt_ptr[pdpt_idx] = (__pa(pd_ptr) & HPAE_MASK) | 0x7;
	} else {
		if ((pdpt_ptr[pdpt_idx] & EPTE_L_MASK)) {
			ERR("!!!! large PDPT EPT page detected: %lx. \n",
			    pdpt_ptr[pdpt_idx]);
			return -1;
		}
		pdpt_ptr[pdpt_idx] |= 0x7;
		pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
		// DBG ("pdpt entry: %lx\n", pdpt_ptr[pdpt_idx]);
	}

	if (!(pd_ptr[pd_idx] & EPTE_P_MASK)) {
		lv = 1;
		gfn = gpa >> 12 & ~((1 << (lv * 9)) - 1);
		oasis_mmu_page = alloc_oasis_mmu_page(&ctx->pt_page, lv, gfn);
		pt_ptr = oasis_mmu_page->spt;
		pd_ptr[pd_idx] = (__pa(pt_ptr) & HPAE_MASK) | 0x7;
	} else {
		if ((pd_ptr[pd_idx] & EPTE_L_MASK)) {
			ERR("!!!! large PD EPT page detected: %lx. \n",
			    pd_ptr[pd_idx]);
			return -1;
		}
		pd_ptr[pd_idx] |= 0x7;
		pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
		// DBG ("pd entry: %lx\n", pd_ptr[pd_idx]);
	}
	if ((pt_ptr[pt_idx] & EPTE_P_MASK) &&
	    ((pt_ptr[pt_idx] & HPAE_MASK) != new_pa)) {
		ERR("GPA confliction detected in 1st EPT. gpa: %lx, orig leaf ept entry: %lx, expected new_pa: %lx. \n",
		    gpa, pt_ptr[pt_idx], new_pa);
	}

	permission |= 0xf70;
	// pt_ptr[pt_idx] = (new_pa & HPAE_MASK) | permission;
	// pt_ptr[pt_idx] = (new_pa & EPTE_MASK) | permission;
	pt_ptr[pt_idx] = (new_pa & EPTE_MASK) | EPTE_SVE_BIT | permission;
	// DBG ("updated EPT entry: %lx, for gpa: %lx, new_pa: %lx. \n", pt_ptr[pt_idx], gpa, new_pa);
	return 0;
}
EXPORT_SYMBOL_GPL(adjust_ept_entry);

static int fix_ept_mapping(intro_ctx_t *ctx, unsigned long new_pdpt_gpa)
{
	unsigned long *pml4_ptr, *imee_pdpt_ptr, *imee_pd_ptr, *imee_pt_ptr;
	unsigned long imee_pdpt_hpa, imee_pd_hpa, imee_pt_hpa, imee_page_hpa;
	int i, j, k;
	int ret;

	pml4_ptr = (unsigned long *)current->mm->pgd;
	imee_pdpt_hpa = pml4_ptr[user_idx] & HPAE_MASK;
	imee_pdpt_ptr = __va(imee_pdpt_hpa);
	adjust_ept_entry(ctx, new_pdpt_gpa, imee_pdpt_hpa, 0x7);
	// DBG ("FINISH update for pdpt page, original gpa from target: %lx, new hpa from imee: %lx\n", gpa, imee_pdpt_hpa);

	for (i = 0; i < 512; i++) {
		if (imee_pdpt_ptr[i] & HPTE_P_MASK) {
			if ((imee_pdpt_ptr[i] & HPTE_L_MASK)) {
				ERR("PDPT entry for 1GB page in host PT: %lx .\n",
				    imee_pdpt_ptr[i]);
			}

			imee_pd_hpa = imee_pdpt_ptr[i] & HPAE_MASK;
			DBG("i: %d, imee_pd_hpa: %lx\n", i, imee_pdpt_ptr[i]);
			adjust_ept_entry(ctx, imee_pd_hpa, imee_pd_hpa,
					 0x7); // what if confliction
			imee_pd_ptr = __va(imee_pd_hpa);
			for (j = 0; j < 512; j++) {
				if (imee_pd_ptr[j] & HPTE_P_MASK) {
					if ((imee_pdpt_ptr[i] & HPTE_L_MASK)) {
						printk(KERN_ERR
						       "PD entry for 2MB page in host PT: %lx .\n",
						       imee_pd_ptr[j]);
					}

					imee_pt_hpa =
						imee_pd_ptr[j] & HPAE_MASK;
					DBG("j: %d, imee_pt_hpa: %lx\n", j,
					    imee_pd_ptr[j]);
					adjust_ept_entry(ctx, imee_pt_hpa,
							 imee_pt_hpa, 0x7);
					imee_pt_ptr = __va(imee_pt_hpa);
					for (k = 0; k < 512; k++) {
						if (imee_pt_ptr[k] &
						    HPTE_P_MASK) {
							imee_page_hpa =
								imee_pt_ptr[k] &
								HPAE_MASK;
							// DBG ("k: %d, imee_page_hpa: %lx\n", k, imee_pt_ptr[k]);
							ret = adjust_ept_entry(
								ctx,
								imee_page_hpa,
								imee_page_hpa,
								0x7);

							// /* deal with gpa confliction */
							// while (ret == -1)
							// {
							//     // unsigned long re_va = __get_free_page(GFP_USER);
							//     void* re_va = get_ept_page();
							//     unsigned long re_pa = virt_to_phys(re_va);
							//     unsigned long attr_bits = imee_pt_ptr[k] & 0x8000000000000fffUL;
							//     // DBG ("reget a page due to gpa confliction, new gpa: %lx. \n", re_pa);
							//     imee_pt_ptr[k] = (re_pa & HPAE_MASK) | attr_bits;
							//     imee_page_hpa = imee_pt_ptr[k];
							//     DBG ("reget a page due to gpa confliction, new gpa: %lx. entry: %lx. \n", re_pa, imee_page_hpa);
							//     // ret = adjust_ept_entry (ctx, imee_page_hpa, eptptr, imee_page_hpa, 1);
							//     ret = adjust_ept_entry (ctx, imee_page_hpa, eptptr, imee_page_hpa, 0);
							// }
							/* / */
						}
					}
				}
			}
		}
	}
	DBG("FINISH EPT UPDATE===============\n");
	return 0;
}

/* This function does not take care of large page, so be careful */
unsigned long trans_hva_to_hpa(unsigned long hva)
{
	unsigned long *pml4_ptr;
	unsigned long *pdpt_ptr;
	unsigned long *pd_ptr;
	unsigned long *pt_ptr;

	int pml4_idx;
	int pdpt_idx;
	int pd_idx;
	int pt_idx;

	unsigned long pa;

	pml4_idx = (hva >> 39) & 0x1FF;
	pdpt_idx = (hva >> 30) & 0x1FF;
	pd_idx = (hva >> 21) & 0x1FF;
	pt_idx = (hva >> 12) & 0x1FF;

	pml4_ptr = (unsigned long *)current->mm->pgd;

	// DBG ("this is to get pa of shared memory page. \n");

	if (pml4_ptr[pml4_idx] == 0) {
		printk("pml4 entry is invalid \n");
		return 0;
	} else {
		pdpt_ptr = __va(pml4_ptr[pml4_idx] & HPAE_MASK);
		if (pdpt_ptr[pdpt_idx] == 0) {
			printk("pdpt entry is invalid \n");
			return 0;
		} else {
			pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
			if (pd_ptr[pd_idx] == 0) {
				printk("pd entry is invalid \n");
				return 0;
			} else {
				pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
				if (pt_ptr[pt_idx] == 0) {
					printk("pt entry is invalid \n");
					return 0;
				} else {
					pa = pt_ptr[pt_idx] & HPAE_MASK;
					return pa;
				}
			}
		}
	}
}

/* This function does not take care of large page, so be careful */
unsigned long *get_hpte_from_hva(unsigned long hva)
{
	unsigned long *pml4_ptr;
	unsigned long *pdpt_ptr;
	unsigned long *pd_ptr;
	// unsigned long* pt_ptr;

	int pml4_idx;
	int pdpt_idx;
	int pd_idx;
	// int pt_idx;

	unsigned long pa;

	pml4_idx = (hva >> 39) & 0x1FF;
	pdpt_idx = (hva >> 30) & 0x1FF;
	pd_idx = (hva >> 21) & 0x1FF;
	// pt_idx = (hva >> 12) & 0x1FF;

	pml4_ptr = (unsigned long *)current->mm->pgd;

	// DBG ("this is to get pa of shared memory page. \n");

	if (pml4_ptr[pml4_idx] == 0) {
		printk("pml4 entry is invalid \n");
		return 0;
	} else {
		pdpt_ptr = __va(pml4_ptr[pml4_idx] & HPAE_MASK);
		if (pdpt_ptr[pdpt_idx] == 0) {
			printk("pdpt entry is invalid \n");
			return 0;
		} else {
			pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
			if (pd_ptr[pd_idx] == 0) {
				printk("pd entry is invalid \n");
				return 0;
			} else {
				return __va(pd_ptr[pd_idx] & HPAE_MASK);
				// pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
				// if (pt_ptr[pt_idx] == 0)
				// {
				//     printk ("pt entry is invalid \n");
				//     return 0;
				// }
				// else
				// {
				//     pa = pt_ptr[pt_idx] & HPAE_MASK;
				//     return pa;
				// }
			}
		}
	}
}
static int walk_gpt_new(intro_ctx_t *ctx, struct kvm_vcpu *vcpu,
			struct arg_blk *args)
{
	struct kvm *target_kvm;
	unsigned long t_root_hpa;
	unsigned long new_root_hpa;
	unsigned long pfn;
	struct page *pg;
	unsigned long *pp; //pp points to the original guest root PT
	unsigned long new_pdpt_gpa;
	unsigned long *sec_pml4;
	int ret;
	int pcount;

	unsigned long dota_esp;
	unsigned long dota_eip;

	//pp-s
	int present_idx = -1;
	//pp-e

	/* setup UK_OFFSET */
	// kernel_idx = 509;
	// kernel_idx = 255;

	//	QHQQHQHQ change
	// kernel_idx = 254;
	// user_idx = 255;
	// ==================>
	kernel_idx = user_idx = USER_IDX;
	//	QHQQHQHQ change ---------------------

	if (kernel_idx <= 255) {
		UK_OFFSET = ((unsigned long)(kernel_idx - user_idx)) *
			    (((unsigned long)1) << 39);
	} else {
		UK_OFFSET = ((unsigned long)(kernel_idx - user_idx)) *
				    (((unsigned long)1) << 39) +
			    0xffff000000000000;
	}
	DBG("kernel_idx, : %d, user_idx: %d, UK_OFFSET: %lx\n", kernel_idx,
	    user_idx, UK_OFFSET);

	/* get target pml4 page */
	target_kvm = ctx->kvm;
	t_root_hpa = gpa_to_hpa_guest(target_kvm, last_cr3);
	if (t_root_hpa == 0) {
		ERR("cannot get host physical address of guest pml4 table. \n");
		return -1;
	}
	pfn = t_root_hpa >> 12;
	pg = pfn_to_page(pfn);
	pp = (unsigned long *)kmap_atomic(pg);

	// /* 0xffffff0000000000-0xffffff7fffffffff: %esp fixup stacks */
	/* onsite pml4 page is allocated as a user page in ld.so, it is duplicated
     * from target pml4 page except its 509th entry(expect it is not occupied) */
	sec_pml4 = (void *)imee_arg.root_pt_addr;
	memcpy((void *)sec_pml4, (void *)pp, 0x1000);
	new_root_hpa = trans_hva_to_hpa(sec_pml4);
	DBG("onsite root PT page va: %p. pa: %lx. \n", sec_pml4, new_root_hpa);
	
	//pp-s

	/* commenting the following block of code to remove the hard coding of index 510
	if (new_root_hpa == 0 || (pp[510] & HPTE_P_MASK) == 0) {
		ERR("get pa: %lx of onsite new pml4 failed or target pml4 page is not valid, its 510th entry: %lx. \n",
		    new_root_hpa, pp[510]);
		kunmap_atomic(pp);
		return -1;
	}*/

	//debug only--------
	pcount = 511;
	while(pcount >= 0){
		if((pp[pcount] & HPTE_P_MASK) == 1){
			DBG("PP DBG target pml4 idx %d, entry is present\n", pcount);
		}
		pcount--;
	}
	//------------------

	pcount = 511;
	while(pcount >= 0){
		if((pp[pcount] & HPTE_P_MASK) == 1){
			DBG("PP DBG target pml4 idx %d, entry is present\n", pcount);
			present_idx = pcount;
			break;
		}
		pcount--;
	}
	if (new_root_hpa == 0 || present_idx == -1) {
		ERR("get pa: %lx of onsite new pml4 failed or target pml4 page is not valid \n",
		    new_root_hpa);
		kunmap_atomic(pp);
		return -1;
	}
	//pp-e

	adjust_ept_entry(ctx, ctx->o_cr3, new_root_hpa, 0x7);

	//pp-s
	/* remove the hardcoding of index 510
	sec_pml4[kernel_idx] =
		pp[510] | NO_CONFLICT_GPA_MASK |
		0x7; //generate non-conflit GPA for onsite PDPT page
	*/
	//generate non-conflit GPA for onsite PDPT page
	sec_pml4[kernel_idx] = pp[present_idx] | NO_CONFLICT_GPA_MASK | 0x7; 
	//pp-e

	new_pdpt_gpa = sec_pml4[kernel_idx];
	/* Fuse ana PDPT, PD, PT, and pages into onsite */
	ret = fix_ept_mapping(ctx, new_pdpt_gpa);
	kunmap_atomic(pp);

	dota_eip = args->rip + UK_OFFSET;
	dota_esp = args->rsp + UK_OFFSET;
	adjust_imee_vcpu(vcpu, dota_eip, dota_esp, args);
	DBG("dota_eip: %lx, dota_esp: %lx\n", dota_eip, dota_esp);
	// QHQQHQQHQ
	// {
	// 	int i = 0;
	// 	unsigned long *p = sec_pml4 ;
	// 	for(i=0; i<(0x1000/(sizeof(unsigned long))); i++) {
	// 		DBG ("%d\t\t: 0x%px\n", i, (void*)p[i]) ;
	// 		if (i==kernel_idx || i==user_idx) {
	// 			continue;
	// 		} else {
	// 			p[i] = 0 ;
	// 		}
	// 	}
	// 	return -5;
	// }
	// QHQQHQQHQ----------
	return ret;
}

static void *do_alloc_ept_frames(void *base)
{
	base = (void *)__get_free_pages(GFP_KERNEL, PAGE_ORDER);
	return base;
}

void init_ept_frames(void)
{
	if (!p_base) {
		p_idx = 0;
		p_base_idx = 0;
		p_base = do_alloc_ept_frames(p_bases[p_base_idx]);
	}
}
EXPORT_SYMBOL_GPL(init_ept_frames);

static void release_ept_frames(void)
{
	int i = 0;
	for (; i <= p_base_idx; i++) {
		DBG("release %d th EPT frames. \n", i);
		free_pages((ulong)p_bases[i], PAGE_ORDER);
		p_bases[i] = 0;
	}

	p_base_idx = 0;
	p_base = 0;
	p_idx = 0;
}

static ulong *get_ept_page(void)
{
	if (p_base) {
		p_idx++;
		if (p_idx < (1 << PAGE_ORDER)) {
			int i;
			ulong *p =
				(ulong *)(((ulong)p_base) + p_idx * PAGE_SIZE);
			for (i = 0; i < PAGE_SIZE / sizeof(ulong); i++) {
				p[i] = 0;
			}
			return p;
		} else {
			p_base_idx++;
			if (p_base_idx < NBASE) {
				p_base = do_alloc_ept_frames(
					p_bases[p_base_idx]);
				p_idx = 0;
				return (ulong *)p_base;
			} else {
				printk(KERN_ERR
				       "EPT frames have been used up, p_base_idx: %d p_idx: %d\n",
				       p_base_idx, p_idx);
				return 0;
			}
		}
	} else {
		printk(KERN_ERR "EPT frames have not been allocated.");
		return 0;
	}
}

struct kvm_mmu_page *alloc_oasis_mmu_page(struct list_head *mmu_page_list,
					  int lv, gfn_t gfn)
{
	struct kvm_mmu_page *oasis_mmu_page;
	void *page;
	page = get_ept_page();
	memset(page, 0x0, 0x1000);

	oasis_mmu_page = kmalloc(sizeof(struct kvm_mmu_page), GFP_KERNEL);
	oasis_mmu_page->spt = page;
	oasis_mmu_page->role.level = lv;
	oasis_mmu_page->gfn = gfn;

	INIT_LIST_HEAD(&oasis_mmu_page->link);
	list_add(&oasis_mmu_page->link, mmu_page_list);
	return oasis_mmu_page;
}

u64 make_imee_ept(intro_ctx_t *ctx)
{
	struct kvm_mmu_page *root_page;
	struct kvm_mmu_page *oasis_mmu_page;
	struct kvm_mmu_page *cur;
	int pml4_idx, pdpt_idx, pd_idx;
	u64 *pml4, *pdpt, *pd;
	gfn_t gfn;
	int lv;

	lv = 4;
	gfn = 0;
	root_page = alloc_oasis_mmu_page(&ctx->non_leaf_page, lv, gfn);
	pml4 = root_page->spt;

	// complete upper layer EPT entries for large PDE entries
	list_for_each_entry (cur, &ctx->pd_page, link) {
		pml4_idx = ((cur->gfn) >> 27) & 0x1FF;
		pdpt_idx = ((cur->gfn) >> 18) & 0x1FF;

		if (pml4[pml4_idx] == 0) {
			lv = 3;
			gfn = cur->gfn & ~((1 << (lv * 9)) - 1);
			oasis_mmu_page = alloc_oasis_mmu_page(
				&ctx->non_leaf_page, lv, gfn);
			pdpt = oasis_mmu_page->spt;
			pml4[pml4_idx] = __pa(pdpt) | NL_EPTE_MASK;
		} else {
			pdpt = __va(pml4[pml4_idx] & PAGE_MASK);
		}

		if (pdpt[pdpt_idx] == 0) {
			pdpt[pdpt_idx] = __pa(cur->spt) | NL_EPTE_MASK;
		} else {
			printk("PDPT entry is wrongly occupied. pdpt entry: %lx, pd page gfn: %lx. \n",
			       pdpt[pdpt_idx], cur->gfn);
		}
	}

	// complete upper layer EPT entries for all PTE entries
	list_for_each_entry (cur, &ctx->pt_page, link) {
		pml4_idx = ((cur->gfn) >> 27) & 0x1FF;
		pdpt_idx = ((cur->gfn) >> 18) & 0x1FF;
		pd_idx = ((cur->gfn) >> 9) & 0x1FF;

		if (pml4[pml4_idx] == 0) {
			lv = 3;
			gfn = cur->gfn & ~((1 << (lv * 9)) - 1);
			oasis_mmu_page = alloc_oasis_mmu_page(
				&ctx->non_leaf_page, lv, gfn);
			pdpt = oasis_mmu_page->spt;
			pml4[pml4_idx] = __pa(pdpt) | NL_EPTE_MASK;
		} else {
			pdpt = __va(pml4[pml4_idx] & PAGE_MASK);
		}

		if (pdpt[pdpt_idx] == 0) {
			lv = 2;
			gfn = cur->gfn & ~((1 << (lv * 9)) - 1);
			oasis_mmu_page =
				alloc_oasis_mmu_page(&ctx->pd_page, lv, gfn);
			pd = oasis_mmu_page->spt;
			pdpt[pdpt_idx] = __pa(pd) | NL_EPTE_MASK;
		} else {
			pd = __va(pdpt[pdpt_idx] & PAGE_MASK);
		}

		if (pd[pd_idx] == 0) {
			pd[pd_idx] = __pa(cur->spt) | NL_EPTE_MASK;
		} else {
			printk("pd entry is occupied. pd entry: %lx, pt page gfn: %lx.",
			       pd[pd_idx], cur->gfn);
		}
	}

	// list_for_each_entry (cur, non_leaf_page, link)
	// {
	//     DBG ("new non-leaf page at: %px\n", cur->spt);
	// }

	return (u64)__pa(pml4);
}
EXPORT_SYMBOL_GPL(make_imee_ept);

static void cr0_wp_off(void)
{
	u64 cr0;
	asm("movq %%cr0, %0;" : "=r"(cr0)::);
	// printk ("%llX\n", cr0);
	cr0 &= ~0x10000;
	// printk ("%llX\n", cr0);
	asm("movq %0, %%cr0;" ::"r"(cr0) :);
}

static void cr0_wp_on(void)
{
	u64 cr0;
	asm("movq %%cr0, %0;" : "=r"(cr0)::);
	// printk ("%llX\n", cr0);
	cr0 |= 0x10000;
	// printk ("%llX\n", cr0);
	asm("movq %0, %%cr0;" ::"r"(cr0) :);
}

static void install_int_handlers(void)
{
	unsigned char idtr[10];
	u64 *idt;
	gate_desc s;

	asm("sidt %0" : "=m"(idtr)::);

	idt = (u64 *)(*(u64 *)(idtr + 2));
	DBG("idt: %px\n", idt);

	cr0_wp_off();

	pack_gate(&s, GATE_INTERRUPT, (unsigned long)imee_guest_int, 0, 0,
		  __KERNEL_CS);

	idt[0x56 * 2] = *((u64 *)(&s));
	idt[0x56 * 2 + 1] = 0x00000000FFFFFFFFULL;

	cr0_wp_on();
	return;
}

static void remove_int_handlers(void)
{
	unsigned char idtr[10];
	u64 *idt;
	gate_desc s;
	asm("sidt %0" : "=m"(idtr)::);
	idt = (u64 *)(*(u64 *)(idtr + 2));
	// DBG ("idt: %p\n", idt);
	cr0_wp_off();
	idt[0x56 * 2] = 0x0;
	idt[0x56 * 2 + 1] = 0x0;
	cr0_wp_on();
	DBG("remove int handlers done\n");
}

int get_next_ctx(intro_ctx_t **next)
{
	intro_ctx_t *cur = 0;

	list_for_each_entry (cur, &introspection_contexts, node) {
		if (cur->visited == 0) {
			cur->visited++;
			*next = cur;

			current_target = cur;

			DBG("picked VM: target_vm_pid: %d process: %s\n",
			    cur->task->pid, cur->task->comm);

			return 0;
		}
	}

	return -1;
}
EXPORT_SYMBOL_GPL(get_next_ctx);

void copy_leaf_ept(intro_ctx_t *ctx, struct kvm_arch *arch)
{
	struct kvm_mmu_page *t_page;
	struct kvm_mmu_page *oasis_mmu_page;
	u64 *pt_ptr, *pd_ptr;
	gfn_t gfn;
	int lv;
	int i;
	list_for_each_entry (t_page, &arch->active_mmu_pages, link) {
		if (t_page->role.level == 1) {
			if (t_page->role.cr0_wp == 0) {
				printk("///////////////////////target leaf ept page with cr0_wp as 0. \n");
			}
			// DBG ("t_leaf page. gfn: %LX. \n", t_page->gfn);
			lv = 1;
			gfn = t_page->gfn;
			oasis_mmu_page =
				alloc_oasis_mmu_page(&ctx->pt_page, lv, gfn);
			pt_ptr = oasis_mmu_page->spt;
			for (i = 0; i < 512; i++) {
				if (t_page->spt[i] & EPTE_P_MASK) {
					// pt_ptr[i] = (t_page->spt[i] | 0x3) & ~0x4;//copy over and RW & NX
					pt_ptr[i] =
						(t_page->spt[i] | EPTE_SVE_BIT |
						 0x3) &
						~0x4; //copy over and RW & NX
					// DBG ("\t i:%d -> %lX; onsite -> %lX. \n", i, t_page->spt[i], pt_ptr[i]);
				}
			}
		}
		/* copy large PDE entries if any */
		// else if (t_page->role.level == 2)
		else if (t_page->role.level == 2 && t_page->role.cr0_wp == 1)
		// else if (t_page->role.level == 2)
		{
			DBG("t PD page. gfn: %lx. cr0_wp: %x. \n", t_page->gfn,
			    t_page->role.cr0_wp);
			for (i = 0; i < 512; i++) {
				if ((t_page->spt[i] & EPTE_P_MASK) &&
				    (t_page->spt[i] & EPTE_L_MASK)) {
					break;
				}
			}
			if (i != 512) {
				lv = 2;
				gfn = t_page->gfn;
				oasis_mmu_page = alloc_oasis_mmu_page(
					&ctx->pd_page, lv, gfn);
				pd_ptr = oasis_mmu_page->spt;
				for (i = 0; i < 512; i++) {
					// if (t_page->spt[i] & EPTE_P_MASK)
					//     DBG ("\t i:%d -> %lX\n", i, t_page->spt[i]);
					if (t_page->spt[i] & EPTE_L_MASK) {
						pd_ptr[i] =
							(t_page->spt[i] | 0x3) &
							~0x4; // RW & NX
						// DBG ("\t i:%d -> %lX\n", i, t_page->spt[i]);
					}
				}
			}
		}
		/* report large PDPT entry if any*/
		// else if (t_page->role.level == 3)
		else if (t_page->role.level == 3 && t_page->role.cr0_wp == 1) {
			DBG("t PDPT page. gfn: %lx. \n", t_page->gfn);
			for (i = 0; i < 512; i++) {
				// if (t_page->spt[i])
				//     DBG ("\t i:%d -> %lX\n", i, t_page->spt[i]);
				if (t_page->spt[i] & EPTE_L_MASK)
					printk(KERN_ERR
					       "PDPTE 1GB page in target EPT: %lx\n",
					       t_page->spt[i]);
			}
		}
	}
	return;
}
EXPORT_SYMBOL_GPL(copy_leaf_ept);

int adjust_ept_entry_s(intro_ctx_t *ctx, unsigned long gpa, ulong eptp,
		       unsigned long new_pa)
{
	struct kvm_mmu_page *oasis_mmu_page;
	u64 *pml4_ptr, *pdpt_ptr, *pd_ptr, *pt_ptr;
	int pml4_idx, pdpt_idx, pd_idx, pt_idx;
	gfn_t gfn;
	int lv;

	pml4_ptr = __va(eptp);
	pml4_idx = (gpa >> 39) & 0x1FF;
	pdpt_idx = (gpa >> 30) & 0x1FF;
	pd_idx = (gpa >> 21) & 0x1FF;
	pt_idx = (gpa >> 12) & 0x1FF;

	if (gpa == ctx->o_cr3) {
		printk("gpa conflict with onsite cr3!!!!!!!!!!!!\n");
	}

	if (pml4_ptr[pml4_idx] == 0) {
		// DBG ("pml4 PTE is not mapped.\n");
		lv = 3;
		gfn = gpa >> 12 & ~((1 << (lv * 9)) - 1);
		oasis_mmu_page =
			alloc_oasis_mmu_page(&ctx->s_non_leaf_page, lv, gfn);
		pdpt_ptr = oasis_mmu_page->spt;
		pml4_ptr[pml4_idx] = (__pa(pdpt_ptr) & HPAE_MASK) | 0x7;
	} else {
		pdpt_ptr = __va(pml4_ptr[pml4_idx] & HPAE_MASK);
		pml4_ptr[pml4_idx] |= 0x7;
		// DBG ("pdpt page pointer: %p\n", pdpt_ptr);
		// DBG ("pdpt entry: %lx\n", pdpt_ptr[pdpt_idx]);
	}

	if (pdpt_ptr[pdpt_idx] == 0) {
		lv = 2;
		gfn = gpa >> 12 & ~((1 << (lv * 9)) - 1);
		oasis_mmu_page =
			alloc_oasis_mmu_page(&ctx->s_non_leaf_page, lv, gfn);
		pd_ptr = oasis_mmu_page->spt;
		pdpt_ptr[pdpt_idx] = (__pa(pd_ptr) & HPAE_MASK) | 0x7;

	} else {
		pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
		if (pdpt_ptr[pdpt_idx] & 0x80) {
			printk("large page in pdpt. \n");
		}
		// DBG ("pd page pointer: %p\n", pd_ptr);
		// DBG ("pd entry: %lx\n", pd_ptr[pd_idx]);
		pdpt_ptr[pdpt_idx] |= 0x7;
	}

	if (pd_ptr[pd_idx] == 0) {
		// DBG ("pd entry is not mapped.\n");
		lv = 1;
		gfn = gpa >> 12 & ~((1 << (lv * 9)) - 1);
		oasis_mmu_page = alloc_oasis_mmu_page(&ctx->s_pt_page, lv, gfn);
		pt_ptr = oasis_mmu_page->spt;
		pd_ptr[pd_idx] = (__pa(pt_ptr) & HPAE_MASK) | 0x7;
	} else {
		pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
		if (pd_ptr[pd_idx] & 0x80) {
			printk("large page in pd. \n");
		}
		pd_ptr[pd_idx] |= 0x7;
		// DBG ("pt entry: %lx\n", pt_ptr[pt_idx]);
	}
	if (pt_ptr[pt_idx] != 0) {
		printk("in second EPT, pt entry is filled >>>>>>>>>>>>>>, gpa:%lx. pt_ptr[pt_idx]: 0x%lx, new_pa: 0x%lx\n",
		       gpa, (unsigned long)pt_ptr[pt_idx], new_pa);
	}

	pt_ptr[pt_idx] = (new_pa & HPAE_MASK) | 0xf77;
	DBG("in adjust_s_ept, updated EPT entry: %lx, for gpa: %lx\n",
	    pt_ptr[pt_idx], gpa);
	return 0;
}
EXPORT_SYMBOL_GPL(adjust_ept_entry_s);

static int fix_ept_mapping_s(intro_ctx_t *ctx)
{
	unsigned long eptp;

	unsigned long *lib_pml4_ptr, *lib_pdpt_ptr, *lib_pd_ptr, *lib_pt_ptr;
	unsigned long lib_pdpt_hpa, lib_pd_hpa, lib_pt_hpa;
	unsigned long pml4e, pdpte, pde, code_pte, data_pte, sys_code_pte,
		idt_pte, gdt_pte, tss_pte, tss1_pte;
	int pdpt_idx, pd_idx, pt_idx_code, pt_idx_data, pt_idx_sys_code;
	int pt_idx_idt, pt_idx_gdt, pt_idx_tss, pt_idx_tss1;

	unsigned long *sec_pml4;
	void *new_pdpt, *new_pd, *new_pt;

	unsigned long *tmp_pp;
	unsigned long new_gpa;

	unsigned long root_pt_pa;

	eptp = current_target->s_eptp;
	DBG("second ept pointer in fix_ept_mapping_s: %lx\n", eptp);
	pdpt_idx = (imee_arg.exit_gate_addr >> 30) & 0x1FF;
	pd_idx = (imee_arg.exit_gate_addr >> 21) & 0x1FF;
	pt_idx_code = (imee_arg.exit_gate_addr >> 12) & 0x1FF;
	pt_idx_idt = (imee_arg.t_idt_va >> 12) & 0x1FF;
	pt_idx_gdt = (imee_arg.t_gdt_va >> 12) & 0x1FF;
	pt_idx_tss = (imee_arg.t_tss_va >> 12) & 0x1FF;
	pt_idx_tss1 = ((imee_arg.t_tss_va + 0x1000) >> 12) & 0x1FF;
	pt_idx_data = (imee_arg.stack_addr >> 12) & 0x1FF;
	pt_idx_sys_code = (imee_arg.syscall_gate_addr >> 12) & 0x1FF;

	sec_pml4 = (unsigned long *)imee_arg.root_pt_addr;
	root_pt_pa = trans_hva_to_hpa((unsigned long)sec_pml4);
	pml4e = sec_pml4[kernel_idx];

	/* get the pa of lib's code and data page, the new gpa of pdpt, pd, pt can
     * be arbitrary one, |0xc00000000 is enough */
	lib_pml4_ptr = (unsigned long *)current->mm->pgd;
	lib_pdpt_hpa = lib_pml4_ptr[user_idx] & HPAE_MASK;
	lib_pdpt_ptr = __va(lib_pdpt_hpa);
	pdpte = lib_pdpt_ptr[pdpt_idx];
	if ((!(pdpte & _PAGE_PRESENT)) || (pdpte & _PAGE_PSE)) {
		printk("pdpt entry not present or large: %lx. \n", pdpte);
		return -1;
	}

	lib_pd_hpa = pdpte & HPAE_MASK;
	lib_pd_ptr = __va(lib_pd_hpa);
	pde = lib_pd_ptr[pd_idx];
	if ((!(pde & _PAGE_PRESENT)) || (pde & _PAGE_PSE)) {
		printk("pd entry not present or large: %lx. \n", pde);
		return -1;
	}

	lib_pt_hpa = pde & HPAE_MASK;
	lib_pt_ptr = __va(lib_pt_hpa);
	code_pte = lib_pt_ptr[pt_idx_code];
	idt_pte = lib_pt_ptr[pt_idx_idt];
	gdt_pte = lib_pt_ptr[pt_idx_gdt];
	tss_pte = lib_pt_ptr[pt_idx_tss];
	tss1_pte = lib_pt_ptr[pt_idx_tss1];
	data_pte = lib_pt_ptr[pt_idx_data];
	sys_code_pte = lib_pt_ptr[pt_idx_sys_code];
	DBG("tss_pte: %lx, tss1_pte: %lx, tss2_pte: %lx. \n", tss_pte, tss1_pte,
	    data_pte);

	if ((!(code_pte & _PAGE_PRESENT)) || (!(data_pte & _PAGE_PRESENT))) {
		printk("pte not present, code_pte: %lx, data_pte: %lx, sys_code_pte: %lx. \n",
		       code_pte, data_pte, sys_code_pte);
		return -1;
	}

	adjust_ept_entry_s(
		ctx, ctx->o_cr3, eptp,
		root_pt_pa); // the two EPTs share the same guest PML4, the pml4 entry is already adjusted in the setup stage of first EPT
	new_gpa = pml4e;
	new_pdpt = get_ept_page();
	adjust_ept_entry_s(ctx, new_gpa, eptp, __pa(new_pdpt));
	DBG("FINISH update for pdpt page, new created gpa: %lx, new hpa: %lx\n",
	    new_gpa, __pa(new_pdpt));

	/* modify the pdpt entry on which points to a new onsite pd page */
	tmp_pp = (unsigned long *)new_pdpt;
	new_gpa = pdpte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pdpt_idx] = new_gpa;
	new_pd = (void *)get_ept_page();
	adjust_ept_entry_s(ctx, new_gpa, eptp, __pa(new_pd));
	DBG("FINISH update for pd page, new created gpa: %lx, new hpa: %lx\n",
	    new_gpa, __pa(new_pd));

	/* modify the pd entry on which points to a new onsite pt page */
	tmp_pp = (unsigned long *)new_pd;
	new_gpa = pde | NO_CONFLICT_GPA_MASK;
	tmp_pp[pd_idx] = new_gpa;
	new_pt = get_ept_page();
	adjust_ept_entry_s(ctx, new_gpa, eptp, __pa(new_pt));
	DBG("FINISH update for pt page, new created gpa: %lx, new hpa: %lx\n",
	    new_gpa, __pa(new_pt));

	/* modify the two PT entries on which point to the lib's code and data page */
	tmp_pp = (unsigned long *)new_pt;
	new_gpa = code_pte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pt_idx_code] = new_gpa;
	adjust_ept_entry_s(ctx, new_gpa, eptp, code_pte);
	DBG("FINISH update for code pt entry, new created gpa: %lx, original gpa: %lx\n",
	    new_gpa, code_pte);
	new_gpa = data_pte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pt_idx_data] = new_gpa;
	adjust_ept_entry_s(ctx, new_gpa, eptp, data_pte);
	DBG("FINISH update for data pt entry, new created gpa: %lx, original gpa: %lx\n",
	    new_gpa, data_pte);
	new_gpa = sys_code_pte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pt_idx_sys_code] = new_gpa;
	adjust_ept_entry_s(ctx, new_gpa, eptp, sys_code_pte);
	DBG("FINISH update for syscall gate pt entry, new created gpa: %lx, original gpa: %lx\n",
	    new_gpa, sys_code_pte);

	new_gpa = idt_pte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pt_idx_idt] = new_gpa;
	adjust_ept_entry_s(ctx, new_gpa, eptp, idt_pte);
	DBG("FINISH update for idt pt entry, new created gpa: %lx, original gpa: %lx\n",
	    new_gpa, idt_pte);
	new_gpa = gdt_pte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pt_idx_gdt] = new_gpa;
	adjust_ept_entry_s(ctx, new_gpa, eptp, gdt_pte);
	DBG("FINISH update for gdt pt entry, new created gpa: %lx, original gpa: %lx\n",
	    new_gpa, gdt_pte);
	new_gpa = tss_pte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pt_idx_tss] = new_gpa;
	adjust_ept_entry_s(ctx, new_gpa, eptp, tss_pte);
	DBG("FINISH update for tss pt entry, new created gpa: %lx, original gpa: %lx\n",
	    new_gpa, tss_pte);
	new_gpa = tss1_pte | NO_CONFLICT_GPA_MASK;
	tmp_pp[pt_idx_tss1] = new_gpa;
	adjust_ept_entry_s(ctx, new_gpa, eptp, tss1_pte);
	DBG("FINISH update for tss1 pt entry, new created gpa: %lx, original gpa: %lx\n",
	    new_gpa, tss1_pte);
	return 0;
}

void copy_s_leaf_ept(intro_ctx_t *ctx, struct kvm_arch *arch)
{
	struct kvm_mmu_page *t_page;
	struct kvm_mmu_page *oasis_mmu_page;
	u64 *pt_ptr, *pd_ptr;
	gfn_t gfn;
	int lv;
	int i;

	list_for_each_entry (t_page, &arch->active_mmu_pages, link) {
		/* copy PT entries */
		if (t_page->role.level == 1) {
			if (t_page->role.cr0_wp == 0) {
				printk("///////////////////target leaf ept page with cr0_wp as 0. \n");
			}

			lv = 1;
			gfn = t_page->gfn;
			oasis_mmu_page =
				alloc_oasis_mmu_page(&ctx->s_pt_page, lv, gfn);

			/* TODO, fix onsite's active_mmu_pages? */
			hlist_add_head(
				&oasis_mmu_page->hash_link,
				&imee_vcpu->kvm->arch.mmu_page_hash[(
					oasis_mmu_page->gfn &
					((1 << KVM_MMU_HASH_SHIFT) - 1))]);

			pt_ptr = oasis_mmu_page->spt;
			for (i = 0; i < 512; i++) {
				if (t_page->spt[i] & EPTE_P_MASK)
					pt_ptr[i] = t_page->spt[i] |
						    0x2; //force to be W
			}
		}
		/* copy large PDE entries if any */
		// else if (t_page->role.level == 2)
		else if (t_page->role.level == 2 && t_page->role.cr0_wp == 1) {
			for (i = 0; i < 512; i++) {
				if (t_page->spt[i] & EPTE_L_MASK) {
					// DBG ("PDE 2MB page in target EPT. t_page at %px, gfn: %lx. \n", t_page, t_page->gfn);
					break;
				}
			}
			if (i != 512) {
				lv = 2;
				gfn = t_page->gfn;
				oasis_mmu_page = alloc_oasis_mmu_page(
					&ctx->s_pd_page, lv, gfn);

				pd_ptr = oasis_mmu_page->spt;
				for (i = 0; i < 512; i++) {
					if (t_page->spt[i] & EPTE_L_MASK) {
						pd_ptr[i] = t_page->spt[i] |
							    0x2; //force to be W
						// printk ("gfn: %lx, large PDE entry: %lx, i: %d. \n", page->gfn, page->spt[i], i);
					}
				}
			}
		}
		/* report large PDPT entry if any */
		// else if (t_page->role.level == 3)
		else if (t_page->role.level == 3 && t_page->role.cr0_wp == 1) {
			for (i = 0; i < 512; i++) {
				if (t_page->spt[i] & EPTE_L_MASK)
					printk(KERN_ERR
					       "PDPTE 1GB page in target EPT: %lx\n",
					       t_page->spt[i]);
			}
		}
	}
}
// EXPORT_SYMBOL_GPL(copy_s_leaf_ept);

u64 make_imee_s_ept(intro_ctx_t *ctx)
{
	struct kvm_mmu_page *root_page;
	struct kvm_mmu_page *oasis_mmu_page;
	struct kvm_mmu_page *cur;

	int pml4_idx, pdpt_idx, pd_idx;
	u64 *pml4, *pdpt, *pd;
	gfn_t gfn;
	int lv;

	lv = 4;
	gfn = 0;
	root_page = alloc_oasis_mmu_page(&ctx->s_non_leaf_page, lv, gfn);

	pml4 = root_page->spt;
	// complete upper layer EPTs for large PDE entries
	list_for_each_entry (cur, &ctx->s_pd_page, link) {
		pml4_idx = ((cur->gfn) >> 27) & 0x1FF;
		pdpt_idx = ((cur->gfn) >> 18) & 0x1FF;

		if (pml4[pml4_idx] == 0) {
			lv = 3;
			gfn = cur->gfn & ~((1 << (lv * 9)) - 1);
			oasis_mmu_page = alloc_oasis_mmu_page(
				&ctx->s_non_leaf_page, lv, gfn);
			pdpt = oasis_mmu_page->spt;
			pml4[pml4_idx] = __pa(pdpt) | NL_EPTE_MASK;
		} else {
			pdpt = __va(pml4[pml4_idx] & PAGE_MASK);
		}

		if (pdpt[pdpt_idx] == 0) {
			pdpt[pdpt_idx] = __pa(cur->spt) | NL_EPTE_MASK;
		} else {
			printk("s PDPT entry is wrongly occupied. pdpt entry: %lx, pd page gfn: %lx \n",
			       pdpt[pdpt_idx], cur->gfn);
		}
	}

	// complete upper layer EPTs for all PT entries
	list_for_each_entry (cur, &ctx->s_pt_page, link) {
		pml4_idx = ((cur->gfn) >> 27) & 0x1FF;
		pdpt_idx = ((cur->gfn) >> 18) & 0x1FF;
		pd_idx = ((cur->gfn) >> 9) & 0x1FF;

		if (pml4[pml4_idx] == 0) {
			lv = 3;
			gfn = cur->gfn & ~((1 << (lv * 9)) - 1);
			oasis_mmu_page = alloc_oasis_mmu_page(
				&ctx->s_non_leaf_page, lv, gfn);
			pdpt = oasis_mmu_page->spt;
			pml4[pml4_idx] = __pa(pdpt) | NL_EPTE_MASK;
		} else {
			pdpt = __va(pml4[pml4_idx] & PAGE_MASK);
		}

		if (pdpt[pdpt_idx] == 0) {
			lv = 2;
			gfn = cur->gfn & ~((1 << (lv * 9)) - 1);
			oasis_mmu_page =
				alloc_oasis_mmu_page(&ctx->s_pd_page, 2, gfn);
			pd = oasis_mmu_page->spt;
			pdpt[pdpt_idx] = __pa(pd) | NL_EPTE_MASK;
		} else {
			pd = __va(pdpt[pdpt_idx] & PAGE_MASK);
		}

		if (pd[pd_idx] == 0) {
			pd[pd_idx] = __pa(cur->spt) | NL_EPTE_MASK;
		} else {
			printk("ERROR s pd entry is occupied. pd entry: %lx, pt page gfn: %lx.",
			       pd[pd_idx], cur->gfn);
		}
	}

	return (u64)__pa(pml4);
}

intro_ctx_t *kvm_to_ctx(struct kvm *target)
{
	intro_ctx_t *cur;
	list_for_each_entry (cur, &introspection_contexts, node) {
		if (cur->kvm == target)
			return cur;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(kvm_to_ctx);

static void create_introspection_context(struct kvm *target)
{
	intro_ctx_t *ctx;
	struct kvm_arch *arch;

	/* return if this VM is myself */
	if (target->mm->owner == current) {
		return;
	}

	if (kvm_to_ctx(target)) {
		// already created
		return;
	}

	ctx = (intro_ctx_t *)kmalloc(sizeof(intro_ctx_t), GFP_KERNEL);
	ctx->task = target->mm->owner;
	DBG("pid: %d, process: %s, cpu: %d\n", ctx->task->pid, ctx->task->comm,
	    task_cpu(ctx->task));
	ctx->visited = 0;

	list_add(&ctx->node, &introspection_contexts);
	INIT_LIST_HEAD(&ctx->pt_page);
	INIT_LIST_HEAD(&ctx->pd_page);
	INIT_LIST_HEAD(&ctx->non_leaf_page);

	ctx->kvm = target;
	ctx->target_vcpu = pick_cpu((struct kvm *)target);

	/* copy leaf EPTs */
	spin_lock(&ctx->target_vcpu->kvm->mmu_lock);
	arch = (struct kvm_arch *)&target->arch;
	copy_leaf_ept(ctx, arch);
	ctx->eptp = make_imee_ept(ctx);
	DBG("oasis first eptp: %lx. \n", ctx->eptp);

	if (imee_arg.instrum_flag == 1) {
		int i;
		INIT_LIST_HEAD(&ctx->s_pt_page);
		INIT_LIST_HEAD(&ctx->s_pd_page);
		INIT_LIST_HEAD(&ctx->s_non_leaf_page);
		/* init hlist head for mmu_page_hash */
		for (i = 0; i < (1 << KVM_MMU_HASH_SHIFT); i++) {
			INIT_HLIST_HEAD(&imee_vcpu->kvm->arch.mmu_page_hash[i]);
			// DBG ("hlist head: %p. \n", &imee_vcpu->kvm->arch.mmu_page_hash[i]);
		}
		copy_s_leaf_ept(ctx, arch);
		ctx->s_eptp = make_imee_s_ept(ctx);
		DBG("second eptp: %px. \n", ctx->s_eptp);
	}
	spin_unlock(&ctx->target_vcpu->kvm->mmu_lock);
	return;
}

static void free_ept(struct list_head *oasis_mmu_page)
{
	struct kvm_mmu_page *cur, *n;
	list_for_each_entry_safe (cur, n, oasis_mmu_page, link) {
		// int i;
		// DBG ("releasing oasis mmu lv: %d, gfn: %lX  \n", cur->role.level, cur->gfn);
		// if (cur->role.level != 1)
		// {
		//     for (i = 0; i < 512; i++)
		//     {
		//         u64* p = cur->spt;
		//         if (p[i])
		//             DBG ("\t i:%d -> %lX\n", i, p[i]);
		//     }
		// }
		list_del(&cur->link);
		kfree(cur);
	}
	return;
}

static void free_contexts(void)
{
	intro_ctx_t *cur, *bck;
	struct list_head *oasis_mmu_page;
	list_for_each_entry_safe (cur, bck, &introspection_contexts, node) {
		oasis_mmu_page = &cur->pt_page;
		DBG("release ctx->pt_page. \n");
		if (oasis_mmu_page)
			free_ept(oasis_mmu_page);
		oasis_mmu_page = &cur->pd_page;
		DBG("release ctx->pd_page. \n");
		if (oasis_mmu_page)
			free_ept(oasis_mmu_page);
		oasis_mmu_page = &cur->non_leaf_page;
		DBG("release ctx->non leaf_page. \n");
		if (oasis_mmu_page)
			free_ept(oasis_mmu_page);
		oasis_mmu_page = &cur->s_pt_page;
		DBG("release ctx->s_pt_page. \n");
		if (oasis_mmu_page)
			free_ept(oasis_mmu_page);
		oasis_mmu_page = &cur->s_pd_page;
		DBG("release ctx->s_pd_page. \n");
		if (oasis_mmu_page)
			free_ept(oasis_mmu_page);
		oasis_mmu_page = &cur->s_non_leaf_page;
		DBG("release ctx->s_non_leaf_page. \n");
		if (oasis_mmu_page)
			free_ept(oasis_mmu_page);

		list_del(&cur->node);
		kfree(cur);
	}
}

int init_imee_vcpu(intro_ctx_t *next, struct kvm_vcpu *vcpu)
{
	/* setup VMCS control fileds */
	u32 vm_entry_control;
	u32 vm_exit_control;
	DBG("init_imee_vcpu\n");
	// vm_entry_control = kvm_x86_ops->read_vm_entry_controls();
	// DBG ("Read vm entry controls: %lx\n", vm_entry_control);
	vm_entry_control = 0xd3ff;
	kvm_x86_ops->write_vm_entry_controls(vm_entry_control);
	// vm_entry_control = kvm_x86_ops->read_vm_entry_controls();
	vm_exit_control = kvm_x86_ops->read_vm_exit_controls();
	// DBG ("Read vm exit control: %lx\n", vm_exit_control);
	vm_exit_control |= (u32)(0x100000);
	kvm_x86_ops->write_vm_exit_controls(vm_exit_control);
	// vm_exit_control = kvm_x86_ops->read_vm_exit_controls();
	DBG("onsite vm entry controls: %lx, vm exit controls: %lx. \n",
	    vm_entry_control, vm_exit_control);

	kvm_x86_ops->set_segment(vcpu, &imee_sregs.cs, VCPU_SREG_CS);
	kvm_x86_ops->set_segment(vcpu, &imee_sregs.ds, VCPU_SREG_DS);
	kvm_x86_ops->set_segment(vcpu, &imee_sregs.ss, VCPU_SREG_SS);
	kvm_x86_ops->set_segment(vcpu, &imee_sregs.fs, VCPU_SREG_FS);
	kvm_x86_ops->set_segment(vcpu, &imee_sregs.gs, VCPU_SREG_GS);
	kvm_x86_ops->set_segment(vcpu, &imee_sregs.ldt, VCPU_SREG_LDTR);

	kvm_x86_ops->set_rflags(vcpu, 0x2);

	/* CR0, CR4, CR3, EFER */
	kvm_x86_ops->set_cr0(vcpu,
			     (imee_sregs.cr0 | 0x2) &
				     ~(0x4 | 0x8)); // set MP, clear TS and EM
// QHQHQHQHQH 
// change from:
#if 0					 
	kvm_x86_ops->set_cr4(
		vcpu,
		(imee_sregs.cr4 | 0xa0 | 0x600 | 0x10000) &
			~(0x360000)); // set PAE, PGE bit, and OSFXSR, OSXMMEXCPT bits for SSE, and FSGSBASE; clear SMAP, SMEP, OSXSAVE, PCIDE
#else
// to:
	kvm_x86_ops->set_cr4(
		vcpu,
		(imee_sregs.cr4 | 0xa0 | 0x600 | 0x10000 | 1<<18) &
			~(0x320000)); // set PAE, PGE bit, and OSFXSR, OSXMMEXCPT bits for SSE, and FSGSBASE; clear SMAP, SMEP, OSXSAVE, PCIDE

#endif 
// QHQHQHQHQH ------------------------			
	imee_sregs.cr3 = next->o_cr3;
	vcpu->arch.cr3 = next->o_cr3;
	kvm_x86_ops->write_cr3_64(
		imee_sregs.cr3); //set_cr3 provided by kvm would overwrite eptp
	kvm_x86_ops->set_efer(vcpu, 0xd01); //set NXE, LMA, LME, SCE bit

	/* IDTR, GDTR, TR */
	imee_idt.size = imee_sregs.idt.limit;
	imee_idt.address = imee_sregs.idt.base;
	imee_gdt.size =
		0x1000; //in IA-32e mode, a segment descriptor table can contain up to 8192 8-byte desciptors.
	imee_gdt.address = imee_sregs.gdt.base;
	memcpy((void *)(&imee_tr), (void *)(&imee_sregs.tr),
	       sizeof(struct kvm_segment));
	kvm_x86_ops->set_segment(vcpu, &imee_tr, VCPU_SREG_TR);
	kvm_x86_ops->set_idt(vcpu, &imee_idt);
	kvm_x86_ops->set_gdt(vcpu, &imee_gdt);
	DBG("IMEE_IDT.base: %lx, imee_idt.size: %x\n", imee_idt.address,
	    imee_idt.size);
	DBG("IMEE_GDT.base: %lx, imee_gdt.size: %x\n", imee_gdt.address,
	    imee_gdt.size);
	DBG("IMEE_tr.base: %lx, imee_tr.size: %x\n", imee_tr.base,
	    imee_tr.limit);

	return 0;
}

void reset_general_regs(struct kvm_vcpu *vcpu)
{
	vcpu->arch.regs[VCPU_REGS_RAX] = 0;
	vcpu->arch.regs[VCPU_REGS_RBX] = 0;
	vcpu->arch.regs[VCPU_REGS_RCX] = 0;
	vcpu->arch.regs[VCPU_REGS_RDX] = 0;
	vcpu->arch.regs[VCPU_REGS_RSP] = 0;
	vcpu->arch.regs[VCPU_REGS_RBP] = 0;
	vcpu->arch.regs[VCPU_REGS_RSI] = 0;
	vcpu->arch.regs[VCPU_REGS_RDI] = 0;
	vcpu->arch.regs[VCPU_REGS_R8] = 0;
	vcpu->arch.regs[VCPU_REGS_R9] = 0;
	vcpu->arch.regs[VCPU_REGS_R10] = 0;
	vcpu->arch.regs[VCPU_REGS_R11] = 0;
	vcpu->arch.regs[VCPU_REGS_R12] = 0;
	vcpu->arch.regs[VCPU_REGS_R13] = 0;
	vcpu->arch.regs[VCPU_REGS_R14] = 0;
	vcpu->arch.regs[VCPU_REGS_R15] = 0;

	vcpu->arch.regs_dirty = 0xFFFFFFFFU;
	vcpu->arch.regs_avail = 0xFFFFFFFFU;
}

void switch_intro_ctx(intro_ctx_t *next, struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu->root_hpa = next->eptp;
	kvm_x86_ops->write_eptp(vcpu);
	DBG("setup root_hpa. \n");
}
EXPORT_SYMBOL_GPL(switch_intro_ctx);

int kvm_imee_get_guest_context(struct kvm_vcpu *vcpu, void *argp)
{
	struct kvm *cur;
	DBG("================start==================\n");
	imee_vcpu = vcpu;
	t_exit_flg = 0;

	install_int_handlers();

	/* allocate page frames for EPT from the kernel */
	init_ept_frames();
	if (!p_base)
		return -1;

	copy_from_user(&imee_arg, argp, sizeof(struct arg_blk));

	/* init contexts */
	spin_lock(&(kvm_lock.wait_lock));
	list_for_each_entry (cur, &vm_list, vm_list) {
		create_introspection_context(cur);
	}
	spin_unlock(&(kvm_lock.wait_lock));

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_imee_get_guest_context);

/* given a gva, return its gpa page addr */
ulong get_gpa_from_gva_guest(struct kvm *target_kvm, unsigned long gva,
			     unsigned long g_cr3)
{
	int idx[4] = { (gva >> 39) & 0x1FF, (gva >> 30) & 0x1FF,
		       (gva >> 21) & 0x1FF, (gva >> 12) & 0x1FF };
	int lv;
	int page_level = 4;
	ulong gpte, next;
	ulong hpa = 0;
	gpte = g_cr3;

	// from guest PML4 page(lv=0) to PT page(lv=3)
	for (lv = 0; lv < page_level; lv++) {
		next = gpte & GPA_MASK;
		hpa = gpa_to_hpa_guest(target_kvm, next);
		if (hpa == 0)
			break;
		else {
			ulong pfn;
			struct page *pg;
			unsigned long *pp;
			pfn = hpa >> 12;
			pg = pfn_to_page(pfn);
			pp = (unsigned long *)kmap_atomic(pg);
			gpte = pp[idx[lv]];
			kunmap_atomic(pp);
			printk("lv: %d, gpte: %lx. \n", lv, gpte);

			if (!gpte || !(gpte & HPTE_P_MASK))
				break;

			else if (lv == (page_level - 1)) {
				return gpte & GPA_MASK;
			}

			else if (gpte & HPTE_L_MASK) // this is a huge page
			{
				if (lv == 2)
					return (gpte & GPA_MASK) +
					       (gva & L_PDE_OFFSET);
				else if (lv == 1)
					return (gpte & GPA_MASK) +
					       (gva & L_PDPTE_OFFSET);
				else
					return 0;
			}
		}
	}
	return 0;
}

ulong get_hpa_from_gva_guest(struct kvm *target_kvm, unsigned long gva,
			     unsigned long g_cr3)
{
	ulong hpa, gpa;
	gpa = get_gpa_from_gva_guest(target_kvm, gva, g_cr3);
	if (gpa == 0) {
		printk("get gpa for gva: %lx failed. \n", gva);
		return 0;
	}
	hpa = gpa_to_hpa_guest(target_kvm, gpa);
	// DBG ("hpa: %lx. gpa: %lx, gva: %lx. \n", hpa, gpa, gva);
	return hpa;
}
EXPORT_SYMBOL_GPL(get_hpa_from_gva_guest);

/* enfoece write protection for gpa on s-EPT */
int prot_root_PT(unsigned long gpa, int permission)
{
	// unsigned long root_pt_hpa;
	// target_proc = ctx->task;
	// target_kvm = ctx->kvm;
	// orig_root_hpa = get_ptr_guest_page_64 (target_kvm, last_cr3);
	int pml4_idx, pdpt_idx, pd_idx, pt_idx;
	unsigned long *pml4_ptr, *pdpt_ptr, *pd_ptr, *pt_ptr;
	unsigned long eptp = current_target->s_eptp;
	// unsigned long gpa = last_cr3;
	pml4_idx = (gpa >> 39) & 0x1ff;
	pdpt_idx = (gpa >> 30) & 0x1ff;
	pd_idx = (gpa >> 21) & 0x1ff;
	pt_idx = (gpa >> 12) & 0x1ff;
	pml4_ptr = __va(eptp & HPAE_MASK);
	if (pml4_ptr[pml4_idx] == 0) {
		printk("PML4 ENTRY IS EMPTY.\n");
		return 0;
	} else {
		// printk ("pml4 entry: %lx. \n", pml4_ptr[pml4_idx]);
		pdpt_ptr = __va(pml4_ptr[pml4_idx] & HPAE_MASK);
	}

	if (pdpt_ptr[pdpt_idx] == 0) {
		printk("Pdpt ENTRY IS EMPTY.\n");
		return 0;
	} else {
		// printk ("pdpt entry: %lx. \n", pdpt_ptr[pdpt_idx]);
		pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
	}

	if (pd_ptr[pd_idx] == 0) {
		printk("pd ENTRY IS EMPTY.\n");
		return 0;
	} else {
		// printk ("pd entry: %lx. \n", pd_ptr[pd_idx]);
		pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
	}

	if (pt_ptr[pt_idx] == 0) {
		printk("pt ENTRY IS EMPTY.\n");
		return 0;
	} else {
		DBG("last cr3 pt entry: %lx.  for gpa: %lx. \n", pt_ptr[pt_idx],
		    gpa);
		if (permission == 0x1) {
			pt_ptr[pt_idx] &= ~0x2;
			DBG("after write protection for last cr3, pt entry: %lx. \n",
			    pt_ptr[pt_idx]);
		} else if (permission == 0x3) {
			pt_ptr[pt_idx] |= 0x2;
			DBG("give RW permission for last cr3, pt entry: %lx. \n",
			    pt_ptr[pt_idx]);
		} else {
			printk("error permission request for guest root PT:%d. \n",
			       permission);
		}
		return 1;
	}
}
EXPORT_SYMBOL_GPL(prot_root_PT);

int sec_ept(struct kvm_vcpu *vcpu)
{
	int ret;

	ret = fix_ept_mapping_s(current_target);
	/* TODO, set write protection for last_cr3 page */
	// if (prot_root_PT(last_cr3, 0x1) == 0)
	// {
	//     printk ("when enforce write protect on last cr3, entry not found. \n");
	//     return -5;
	// }

	if (ret == 0) {
		eptp_list = get_ept_page();
		// DBG ("eptp_list: 0x%lx\n", eptp_list);
		// DBG ("pa of ept_list: 0x%lx\n", (unsigned long) virt_to_phys((void*)eptp_list));
		kvm_x86_ops->write_vmfunc_control();
		kvm_x86_ops->write_eptp_list(vcpu, eptp_list);

		/* alloc page for virt_exce_area, init mapping at va 0x7f900090c000 to
         * allow analyser to access */
		unsigned long VE_PAGE = get_ept_page();
		unsigned long VE_PHYS = virt_to_phys((void *)VE_PAGE);
		kvm_x86_ops->write_virt_exec_phys_addr(VE_PHYS);
		// unsigned long ana_va = 0x7f900090c000;
		int pt_idx = (virt_exce_va >> 12) & 0x1FF;
		unsigned long *hpt_ptr = get_hpte_from_hva(virt_exce_va);
		if (hpt_ptr[pt_idx] == 0) {
			unsigned long pte = VE_PHYS | 0xf73UL;
			DBG("update pt entry for virt_exec_va page as: %lx. \n",
			    pte);
			hpt_ptr[pt_idx] = pte;
			adjust_ept_entry(current_target, pte, pte, 0x3);
			// return 0;
		} else {
			printk("pt entry for ana_va is occupied %lx. \n",
			       hpt_ptr[pt_idx]);
			// pa = pt_ptr[pt_idx] & HPAE_MASK;
			// return pa;
			return -5;
		}

		// printk ("virt exec area: %lx, phys_addr: %lx. \n", imee_arg.virt_exec_area, imee_arg.virt_exec_phys_addr);
		// kvm_x86_ops->write_virt_exec_phys_addr(imee_arg.virt_exec_phys_addr);
		// *((unsigned long*)VE_PAGE) = 0xffffffffffffffff;
		// kvm_x86_ops->write_secondary_exec_control(0x2000);
		// kvm_x86_ops->write_secondary_exec_control(0x2008);
		// kvm_x86_ops->write_secondary_exec_control(0x12008);
//pp-s
		//checking for advanced VM-exit information for EPT violations
		//this is in IA32_VMX_EPT_VPID_CAP MSR (index 0x48c) bit 22
		unsigned long msr;
		rdmsrl(0x48c, msr);
		if(msr && 0x00400000)
			printk("advanced VM-exit information for EPT violations : ENABLED\n");
		else
			printk("advanced VM-exit information for EPT violations : Not_ENABLED\n");
//pp-e

		kvm_x86_ops->write_secondary_exec_control(0x52008);
		kvm_x86_ops->write_primary_exec_control(0xfff7fffff); //TODO
	}
	return ret;
}

static void ana_idt_init(void)
{
	unsigned char gdtr[10];
	void *host_gdt;
	void *new_page;
	gate_desc s;
	ulong ana_pf_entry, ana_ve_entry, ana_syscall_entry;
	ulong g_tss_page_off;
	tss_desc tss;
	struct shar_arg *ei_shar_arg = (struct shar_arg *)imee_arg.shar_va;
	// ei_shar_arg = (struct shar_arg*) imee_arg.shar_va;

	// ana_pf_entry = 0x2c2;
	ana_pf_entry = 0x261;
	ana_ve_entry = 0x2de;
	ana_syscall_entry = 0x261;
	onsite_syscall_entry =
		ana_syscall_entry + imee_arg.syscall_gate_addr + UK_OFFSET;
	adjust_ept_entry(
		current_target, imee_arg.syscall_gate_pa,
		imee_arg.syscall_gate_pa,
		0x3); //set ana syscall page as NX in a-EPT, so EPT violation to intercept ana syscall
	// adjust_ept_entry (current_target, imee_arg.syscall_gate_pa, (imee_arg.syscall_gate_pa | EPTE_SVE_BIT), 0x3);//set ana syscall page as NX in a-EPT, so EPT violation to intercept ana syscall
	printk("syscall gate page pa: %px. \n", imee_arg.syscall_gate_addr);
	// DBG ("FINISH update for syscall gate page, original gpa from target: %lx, new hpa from imee: %lx\n", gpa, imee_pdpt_hpa);

	/* save VA of guest VM's syscall entry, IDT, GDT, TSS tables */
	ei_shar_arg->g_syscall_entry = guest_syscall_entry;
	ei_shar_arg->idt = imee_idt.address;
	ei_shar_arg->tss_base = imee_tr.base;
	ei_shar_arg->tss_pg_off = imee_tr.base & 0xfffUL;
	g_tss_page_off = ei_shar_arg->tss_pg_off;
	ei_shar_arg->gdt = imee_gdt.address;

	/* update guest fs/gs base, kernel_gs_base */
	if (guest_vcpu_paste != 0) {
		ei_shar_arg->fs_base = guest_vcpu_paste->fs_base;
		ei_shar_arg->gs_base = guest_vcpu_paste->gs_base;
		ei_shar_arg->msr_kernel_gs_base =
			guest_vcpu_paste->msr_kernel_gs_base;
		ei_shar_arg->tss_base = guest_vcpu_paste->tss_base;
		DBG("guest fs base: %lx, gs base: %lx, kernel_gs_base: %lx. tss_base: %lx. \n",
		    ei_shar_arg->fs_base, ei_shar_arg->gs_base,
		    ei_shar_arg->msr_kernel_gs_base, ei_shar_arg->tss_base);
	}
	/* / */

	/* a-EPT & t-EPT IDT, GDT, TSS va, but they are physically mapped into
     * different pages. GPAs are also different(check in t_idt_init) */
	imee_idt.address = imee_arg.t_idt_va + UK_OFFSET;
	imee_tr.base = imee_arg.t_tss_va + UK_OFFSET + ei_shar_arg->tss_pg_off;
	imee_gdt.address = imee_arg.t_gdt_va + UK_OFFSET;
	imee_gdt.size = 8191 * 8; //enlarge the size of GDT to be the maximum

	/* tune a-EPT for IDT */
	new_page = get_ept_page();
	memset(new_page, 0x0, 0x1000);
	pack_gate(&s, GATE_INTERRUPT,
		  ana_pf_entry + imee_arg.ana_pf_c_page + UK_OFFSET, 0, 7,
		  __KERNEL_CS);
	memcpy(new_page + 0x2 * 8 * 0xe, &s, 0x10); //analyzer's #PF hanlder
	pack_gate(&s, GATE_INTERRUPT,
		  ana_ve_entry + imee_arg.ana_pf_c_page + UK_OFFSET, 0, 7,
		  __KERNEL_CS);
	memcpy(new_page + 0x2 * 8 * 0x14, &s, 0x10); //analyzer's #VE hanlder
	adjust_ept_entry(current_target, imee_arg.t_idt_pa,
			 virt_to_phys(new_page), 0x7);

	/* tune a-EPT for TSS. 3 TSS pages may not physcially continuous */
	// new_page = (void*) __get_free_pages(GFP_USER| __GFP_ZERO, 1);
	new_page = get_ept_page(); //1st TSS page
	memset(new_page, 0xff, 0x1000);
	adjust_ept_entry(current_target, imee_arg.t_tss_pa,
			 virt_to_phys(new_page), 0x7);
	new_page += g_tss_page_off;
	new_page += offsetof(struct x86_hw_tss, ist[6]);
	*((unsigned long *)new_page) =
		imee_arg.ana_pf_stack + 0x1000 +
		UK_OFFSET; //setup ana's #PF stack in IST[7]
	new_page = get_ept_page(); //2nd TSS page
	memset(new_page, 0xff, 0x1000);
	adjust_ept_entry(current_target, imee_arg.t_tss1_pa,
			 virt_to_phys(new_page), 0x7);
	DBG("new_page: %p, content: %lx. \n", new_page,
	    *((unsigned long *)new_page));

	/* tune a-EPT for GDT */
	asm("sgdt %0" : "=m"(gdtr)::);
	host_gdt = (void *)(*(unsigned long *)(gdtr + 2));
	new_page = get_ept_page();
	memcpy(new_page, host_gdt,
	       0x1000); //setup onsite analyzer GDT based on host GDT
	set_tssldt_descriptor(&tss, imee_tr.base, DESC_TSS, 0x22c0);
	memcpy((void *)(new_page + GDT_ENTRY_TSS * 0x8), &tss,
	       0x10); //setup tr entry in GDT
	adjust_ept_entry(current_target, imee_arg.t_gdt_pa,
			 virt_to_phys(new_page), 0x7);

	return;
}

/* here setup IDT, GDT, TSS content and their mappings in t-ept. For TSS, here
 * only setup its io-bitmap, later analyzer in onsite helps to setup its ISTs. */
static int t_idt_init(void)
{
	struct page *pg;
	void *pp;
	ulong pfn;
	ulong hpa;
	gate_desc s;
	tss_desc tss;
	ulong guest_idt, guest_gdt;
	ulong t_pf_entry = 0x2c6; //to trap target's #PF
	ulong t_int3_exit = 0x332; //to trap target's int3
	ulong t_ve_exit = 0x38d; //to trap target's #VE
	ulong t_db_exit = 0x3c2; //to trap target's #DB
	struct shar_arg *ei_shar_arg = (struct shar_arg *)imee_arg.shar_va;
	// ei_shar_arg = (struct shar_arg*) imee_arg.shar_va;

	/* IDT */
	guest_idt = ei_shar_arg->idt;
	hpa = get_hpa_from_gva_guest(current_target->kvm, guest_idt, last_cr3);
	if (hpa == 0) {
		printk("get gpa and hpa of idt table fail. \n");
		return -5;
	}
	pfn = hpa >> 12;
	pg = pfn_to_page(pfn);
	pp = kmap_atomic(pg);
	memcpy((void *)imee_arg.t_idt_va, pp,
	       0x1000); //set up t-IDT based on IDT in guest VM T
	pack_gate(&s, GATE_INTERRUPT,
		  t_pf_entry + imee_arg.exit_gate_addr + UK_OFFSET, 3, 0,
		  __KERNEL_CS);
	memcpy((void *)(imee_arg.t_idt_va + 0x2 * 8 * 0xe), &s,
	       0x10); //set up #PF entry in t-IDT
	DBG("new #PF t-IDT entry: %lx. \n",
	    *((unsigned long *)(imee_arg.t_idt_va + 0x2 * 8 * 0xe)));

	pack_gate(&s, GATE_INTERRUPT,
		  t_int3_exit + imee_arg.exit_gate_addr + UK_OFFSET, 3, 7,
		  __KERNEL_CS);
	memcpy((void *)(imee_arg.t_idt_va + 0x2 * 8 * 0x3), &s,
	       0x10); //set up int3 entry in t-IDT
	DBG("new int3 t-IDT entry: %lx. \n",
	    *((unsigned long *)(imee_arg.t_idt_va + 0x2 * 8 * 0x3)));

	pack_gate(&s, GATE_INTERRUPT,
		  t_ve_exit + imee_arg.exit_gate_addr + UK_OFFSET, 3, 7,
		  __KERNEL_CS);
	memcpy((void *)(imee_arg.t_idt_va + 0x2 * 8 * 20), &s,
	       0x10); //set up #VE entry in t-IDT
	DBG("new VE t-IDT entry: %lx. \n",
	    *((unsigned long *)(imee_arg.t_idt_va + 0x2 * 8 * 20)));

	pack_gate(&s, GATE_INTERRUPT,
		  t_db_exit + imee_arg.exit_gate_addr + UK_OFFSET, 3, 7,
		  __KERNEL_CS);
	memcpy((void *)(imee_arg.t_idt_va + 0x2 * 8 * 1), &s,
	       0x10); //set up #DB entry in t-IDT
	DBG("new VE t-IDT entry: %lx. \n",
	    *((unsigned long *)(imee_arg.t_idt_va + 0x2 * 8 * 1)));

	adjust_ept_entry(current_target, imee_arg.ana_t_idt_pa,
			 imee_arg.t_idt_pa,
			 0x3); // allow ana to RW target's IDT on a-EPT

	/* TSS */
	memset((void *)(imee_arg.t_tss_va), 0xff,
	       0x3000); //init io-bitmap, leave tss_struct to ana to setup in onsite mode;
	adjust_ept_entry(current_target, imee_arg.ana_t_tss_pa,
			 imee_arg.t_tss_pa,
			 0x3); //allow ana to RW target's TSS_struct on a-EPT

	/* GDT */
	guest_gdt = ei_shar_arg->gdt;
	hpa = get_hpa_from_gva_guest(current_target->kvm, guest_gdt, last_cr3);
	if (hpa == 0) {
		printk("get gpa and hpa of idt table fail. \n");
		return -5;
	}
	pfn = hpa >> 12;
	pg = pfn_to_page(pfn);
	pp = kmap_atomic(pg);
	memcpy((void *)imee_arg.t_gdt_va, pp,
	       0x1000); //set up t-GDT based on GDT in guest VM
	set_tssldt_descriptor(&tss, imee_tr.base, DESC_TSS, 0x22c0);
	memcpy((void *)(imee_arg.t_gdt_va + GDT_ENTRY_TSS * 0x8), &tss,
	       0x10); //TSS entry
	adjust_ept_entry(current_target, imee_arg.ana_t_gdt_pa,
			 imee_arg.t_gdt_pa,
			 0x3); //allow ana to RW target's GDT on a-EPT
	kunmap(pp);
	DBG("t tables setup completes. \n");
	return 0;
}

int start_guest_intercept(struct kvm_vcpu *vcpu)
{
	int ret;
	int cpu;
	int t_count = 0;
	intro_ctx_t *next = 0;
	ret = -1;
	imee_pid = current->pid;

	printk("last_cr3: %lx, guest_syscall_entry: %lx. \n", last_cr3,
	       guest_syscall_entry);

	if (imee_vcpu != vcpu) {
		DBG("this is not imee_vcpu\n");
		goto out;
	}

	if (get_next_ctx(&next) == -1) {
		DBG("get VM fail. \n");
		goto out;
	}

	switch_intro_ctx(next, vcpu);
	reset_general_regs(vcpu);
	t_exit_flg = 1;
	smp_mb();

	/* sending IPI to get target vcpu context, e.g, last_cr3 */
	// last_cr3 = 0;
	// cpu = next->target_vcpu->cpu;
	// DBG ("Firing IPI to cpu: %d\n", cpu);
	// apic->send_IPI_mask (cpumask_of (cpu), 0x56);
	//
	// while (READ_ONCE(t_exit_flg) == 1)
	// {
	//     t_count ++;
	//     if (t_count > 10000000)
	//     {
	//         ERR ("Waited for too long for exit_flg, last_cr3: %lX\n", last_cr3);
	//         return -1;
	//     }
	// }
	/* / */

	if (imee_arg.hard_cr3 != 0) {
		last_cr3 =
			imee_arg.hard_cr3; // use hardcoded cr3 instead of intercepted cr3
	}
	next->t_cr3 = last_cr3;
	next->o_cr3 = last_cr3 | NO_CONFLICT_GPA_MASK;
	;
	DBG("intercept guest CR3 done! last_cr3: %lx, addr of last_cr3: %px. onsite_cr3: %lx, current cpu: %d\n",
	    last_cr3, &last_cr3, next->o_cr3, smp_processor_id());
	// DBG("last_rsp: %lx, last_rip: %lx\n", last_rsp, last_rip);

	host_syscall_entry = kallsyms_lookup_name("entry_SYSCALL_64");
	host_pf_entry = kallsyms_lookup_name("page_fault");
	if ((host_syscall_entry == 0) || (host_pf_entry == 0) ||
	    (guest_syscall_entry == 0)) {
		DBG("host/guest symbol initialization failed. host_pf_entry: %lx. host_syscall_entry: %lx. guest_syscall_entry: %lx. \n",
		    host_pf_entry, host_syscall_entry, guest_syscall_entry);
		return -1;
	}
	// DBG ("host_pf_entry: %lx. host_syscall_entry: %lx. guest_syscall_entry: %lx. \n", host_pf_entry, host_syscall_entry, guest_syscall_entry);

	if (last_cr3 == 0) {
		DBG("last_cr3: %lx. \n", last_cr3);
		return -1;
	}

	init_imee_vcpu(next, vcpu);
	ret = walk_gpt_new(next, vcpu, &imee_arg);
	ana_idt_init();

	if (ret == 0) {
		if (imee_arg.instrum_flag == 1) {
			ret = t_idt_init();
			if (ret < 0) {
				printk("setup desc tables fail.\n");
				return ret;
			}

			/* setup eptp_list page and ept_switching in vmfunc */
			ret = sec_ept(vcpu);
			if (ret < 0) {
				printk("sec_ept fail.\n");
				return ret;
			}
		}

		kvm_x86_ops->set_segment(vcpu, &imee_tr, VCPU_SREG_TR);
		kvm_x86_ops->set_idt(vcpu, &imee_idt);
		kvm_x86_ops->set_gdt(vcpu, &imee_gdt);
		DBG("IMEE_IDT.base: %lx, imee_idt.size: 0x%x\n",
		    imee_idt.address, imee_idt.size);
		DBG("IMEE_GDT.base: %lx, imee_gdt.size: 0x%x\n",
		    imee_gdt.address, imee_gdt.size);
		DBG("IMEE_tr.base: %lx, imee_tr.size: 0x%x\n",
		    (unsigned long)imee_tr.base, imee_tr.limit);
		imee_arg.syscall_flag = 1;
	}

out:
	return ret;
}
EXPORT_SYMBOL_GPL(start_guest_intercept);

int adjust_dota_context(struct kvm_vcpu *vcpu)
{
	unsigned long ret_rax;
	unsigned long rip;
	unsigned long rflags;
	// copy_from_user (&imee_arg, argp, sizeof (struct arg_blk));
	ret_rax = imee_arg.ret_rax;
	rip = imee_arg.rcx;
	rflags = imee_arg.r11;
	rflags &= 0xffffefff;
	/* now return to syscall stub to recover 6 arguments */
	vcpu->arch.regs[VCPU_REGS_RIP] = rip;
	__set_bit(VCPU_REGS_RIP,
		  (unsigned long *)&vcpu->arch.regs_dirty); // VCPU_REGS_RIP bit
	vcpu->arch.regs[VCPU_REGS_RAX] = ret_rax;
	kvm_x86_ops->set_rflags(vcpu, rflags);
	/* set fs for dota mode */
	if (imee_arg.rax == 0x9e) {
		if (imee_arg.ret_rax == 0) {
			struct kvm_sregs *imee_sregs =
				kmalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
			DBG("set fs as : %lx\n", imee_arg.rsi);
			imee_sregs->fs.selector = 0x0;
			imee_sregs->fs.base = imee_arg.rsi + UK_OFFSET;
			imee_sregs->fs.limit = 0xFFFFF;
			imee_sregs->fs.type = 0x3;
			imee_sregs->fs.s = 1;
			imee_sregs->fs.dpl = 0;
			imee_sregs->fs.present = 1;
			imee_sregs->fs.avl = 0;
			imee_sregs->fs.l = 0;
			imee_sregs->fs.db = 1;
			imee_sregs->fs.g = 1;
			kvm_x86_ops->set_segment(vcpu, &imee_sregs->fs,
						 VCPU_SREG_FS);
			kfree(imee_sregs);
		} else {
			printk(KERN_ERR, "set fs failed\n");
		}
	}
	return 0;
}

int vcpu_entry(void)
{
	int r;
	struct files_struct *files = current->files;
	struct file *filp;
	struct kvm_vcpu *vcpu;
	rcu_read_lock();
	filp = fcheck_files(files, imee_arg.vcpu_fd);
	rcu_read_unlock();
	if (filp) {
		vcpu = filp->private_data;
		if (vcpu) {
			local_irq_enable();
			// vcpu_load (vcpu);
			r = start_guest_intercept(vcpu);

			printk("before kvm_arch_vcpu_ioctl_run rsp=0x%lx, rip=0x%lx, rdx=0x%lx, rax=0x%lx, r=%d \n",
			       vcpu->arch.regs[VCPU_REGS_RSP],
			       vcpu->arch.regs[VCPU_REGS_RIP],
			       vcpu->arch.regs[VCPU_REGS_RDX],
			       vcpu->arch.regs[VCPU_REGS_RAX], r

			);
			asm volatile("movq %%cr3, %%rax; \n\t"
				     "movq %%rax, %0; \n\t"
				     : "=m"(ana_h_cr3)::"%rax");
			kvm_x86_ops->write_host_cr3(
				ana_h_cr3); //overwrite host cr3 in vmcs
			if (r >= 0) {
				// QHQHQHQHQHQ add:
				//extern void dump_vmcs(void) ;
				//dump_vmcs() ;
				printk("before kvm_arch_vcpu_ioctl_run rsp=0x%lx, rip=0x%lx, rdx=0x%lx, rax=0x%lx \n",
				       vcpu->arch.regs[VCPU_REGS_RSP],
				       vcpu->arch.regs[VCPU_REGS_RIP],
				       vcpu->arch.regs[VCPU_REGS_RDX],
				       vcpu->arch.regs[VCPU_REGS_RAX]

				);
				// QHQHQHQHQHQ---------------------
				r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
			}
			// vcpu_put (vcpu);
			return r;
		} else {
			ERR("transfer file to vcpu failed\n");
		}
	} else {
		ERR("fget vcpu file failed\n");
	}
	return r;
}
EXPORT_SYMBOL_GPL(vcpu_entry);

int vcpu_reentry(void)
{
	int r;
	struct files_struct *files = current->real_parent->files;
	struct file *filp;
	struct kvm_vcpu *vcpu;
	rcu_read_lock();
	filp = fcheck_files(files, imee_arg.vcpu_fd);
	rcu_read_unlock();
	if (filp) {
		vcpu = filp->private_data;
		if (vcpu) {
			// vcpu_load (vcpu);
			r = adjust_dota_context(vcpu);
			if (r >= 0) {
				// printk ("enter dota mode again\n");
				r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
			}
			// vcpu_put (vcpu);
			return r;
		} else {
			ERR("transfer vcpu failed\n");
		}
	} else {
		ERR("fget failed\n");
	}
	return r;
}
EXPORT_SYMBOL_GPL(vcpu_reentry);

int kvm_imee_stop(struct kvm_vcpu *vcpu)
{
	current_target = 0;

	DBG("releasing OASIS. cpuid:%d\n", smp_processor_id());

	free_contexts();

	release_ept_frames();

	WRITE_ONCE(t_exit_flg, 0);

	remove_int_handlers();
	if (guest_vcpu_paste) {
		kfree(guest_vcpu_paste);
		guest_vcpu_paste = 0;
	}

	imee_pid = 0;
	imee_vcpu = 0;
	pf_cache_flag = 0;
	crt_pfpool_idx = 0;
	int3_pool_idx = 0;
	smp_mb();

	vcpu->arch.mmu->root_hpa = INVALID_PAGE;
	last_cr3 = 0;
	ana_h_cr3 = 0;

	printk("=================end===================\n");
	return 0;
}