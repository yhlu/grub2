/*
 * yhlu 2015-02-12
 *   adapt from linux kernel arch/x86/mm/init_64.c
 */
struct x86_mapping_info {
	void *(*alloc_pgt_page)(void *); /* allocate buf for page table */
	void *context;
	grub_uint64_t pmd_flag;          /* page flag for PMD entry */
};


#define __va(x)	((void *)((grub_uint32_t)(x)))
#define __pa(x) ((grub_uint64_t)(grub_uint32_t)(x))

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1ULL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define PGDIR_SHIFT     39
#define PTRS_PER_PGD    512
#define PGDIR_SIZE      (1ULL << PGDIR_SHIFT)
#define PGDIR_MASK      (~(PGDIR_SIZE - 1))

#define PUD_SHIFT       30
#define PTRS_PER_PUD    512
#define PUD_SIZE        (1ULL << PUD_SHIFT)
#define PUD_MASK        (~(PUD_SIZE - 1))

#define PMD_SHIFT       21
#define PTRS_PER_PMD    512
#define PMD_SIZE        (1ULL << PMD_SHIFT)
#define PMD_MASK        (~(PMD_SIZE - 1))

#define _PAGE_BIT_PRESENT       0       /* is present */
#define _PAGE_BIT_RW            1       /* writeable */
#define _PAGE_BIT_ACCESSED      5       /* was accessed (raised by CPU) */
#define _PAGE_BIT_DIRTY         6       /* was written to (raised by CPU) */
#define _PAGE_BIT_PSE           7       /* 4 MB (or 2MB) page */
#define _PAGE_BIT_GLOBAL        8       /* Global TLB entry PPro+ */
#define _PAGE_BIT_PROTNONE      _PAGE_BIT_GLOBAL
#define _PAGE_PRESENT   (1ULL << _PAGE_BIT_PRESENT)
#define _PAGE_RW        (1ULL << _PAGE_BIT_RW)
#define _PAGE_ACCESSED  (1ULL << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY     (1ULL << _PAGE_BIT_DIRTY)
#define _PAGE_PSE       (1ULL << _PAGE_BIT_PSE)
#define _PAGE_GLOBAL    (1ULL << _PAGE_BIT_GLOBAL)
#define _PAGE_PROTNONE  (1ULL << _PAGE_BIT_PROTNONE)

#define _KERNPG_TABLE   (_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED |    \
                         _PAGE_DIRTY)
#define __PAGE_KERNEL_EXEC                                              \
        (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_GLOBAL)
#define __PAGE_KERNEL_LARGE_EXEC        (__PAGE_KERNEL_EXEC | _PAGE_PSE)

#define __PHYSICAL_MASK_SHIFT   46
#define __PHYSICAL_MASK         ((grub_uint64_t)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))

/* Cast PAGE_MASK to a signed type so that it is sign-extended if
   virtual addresses are 32-bits but physical addresses are larger
   (ie, 32-bit PAE). */
#define PHYSICAL_PAGE_MASK      (((grub_int64_t)PAGE_MASK) & __PHYSICAL_MASK)

typedef grub_uint64_t   pteval_t;
typedef grub_uint64_t   pmdval_t;
typedef grub_uint64_t   pudval_t;
typedef grub_uint64_t   pgdval_t;

/* PTE_PFN_MASK extracts the PFN from a (pte|pmd|pud|pgd)val_t */
#define PTE_PFN_MASK            ((pteval_t)PHYSICAL_PAGE_MASK)

/* PTE_FLAGS_MASK extracts the flags from a (pte|pmd|pud|pgd)val_t */
#define PTE_FLAGS_MASK          (~PTE_PFN_MASK)

typedef struct { pteval_t pte; } pte_t;

typedef struct { pmdval_t pmd; } pmd_t;

static inline pmd_t native_make_pmd(pmdval_t val)
{
        return (pmd_t) { val };
}

static inline pmdval_t native_pmd_val(pmd_t pmd)
{
        return pmd.pmd;
}

static inline pmdval_t pmd_flags(pmd_t pmd)
{
        return native_pmd_val(pmd) & PTE_FLAGS_MASK;
}

static inline int pmd_present(pmd_t pmd)
{
        /*
         * Checking for _PAGE_PSE is needed too because
         * split_huge_page will temporarily clear the present bit (but
         * the _PAGE_PSE flag will remain set at all times while the
         * _PAGE_PRESENT bit is clear).
         */
        return pmd_flags(pmd) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_PSE);
}

static inline grub_uint32_t pmd_index(grub_uint64_t address)
{
        return (grub_uint32_t)((address >> PMD_SHIFT) & (PTRS_PER_PMD - 1));
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
        *pmdp = pmd;
}
#define set_pmd(pmdp, pmd)              native_set_pmd(pmdp, pmd)

#define __pmd(x)        native_make_pmd(x)

static void
ident_pmd_init(grub_uint64_t pmd_flag, pmd_t *pmd_page,
			  grub_uint64_t addr, grub_uint64_t end)
{
	addr &= PMD_MASK;
	for (; addr < end; addr += PMD_SIZE) {
		pmd_t *pmd = pmd_page + pmd_index(addr);

		if (!pmd_present(*pmd))
			set_pmd(pmd, __pmd(addr | pmd_flag));
	}
}

typedef struct { pudval_t pud; } pud_t;

static inline pud_t native_make_pud(pmdval_t val)
{
        return (pud_t) { val };
}

static inline pudval_t native_pud_val(pud_t pud)
{
        return pud.pud;
}

static inline grub_uint32_t pud_index(grub_uint64_t address)
{
        return (grub_uint32_t)((address >> PUD_SHIFT) & (PTRS_PER_PUD - 1));
}

static inline pudval_t pud_flags(pud_t pud)
{
        return native_pud_val(pud) & PTE_FLAGS_MASK;
}

static inline int pud_present(pud_t pud)
{
        return pud_flags(pud) & _PAGE_PRESENT;
}

#define pud_val(x)      native_pud_val(x)

static inline grub_uint32_t pud_page_vaddr(pud_t pud)
{
        return (grub_uint32_t)__va((grub_uint64_t)pud_val(pud) & PTE_PFN_MASK);
}

/* Find an entry in the second-level page table.. */
static inline pmd_t *pmd_offset(pud_t *pud, grub_uint64_t address)
{
        return (pmd_t *)pud_page_vaddr(*pud) + pmd_index(address);
}

static inline void native_set_pud(pud_t *pudp, pud_t pud)
{
        *pudp = pud;
}
# define set_pud(pudp, pud)             native_set_pud(pudp, pud)
#define __pud(x)        native_make_pud(x)

static int
ident_pud_init(struct x86_mapping_info *info, pud_t *pud_page,
			  grub_uint64_t addr, grub_uint64_t end)
{
	grub_uint64_t next;

	for (; addr < end; addr = next) {
		pud_t *pud = pud_page + pud_index(addr);
		pmd_t *pmd;

		next = (addr & PUD_MASK) + PUD_SIZE;
		if (next > end)
			next = end;

		if (pud_present(*pud)) {
			pmd = pmd_offset(pud, 0);
			ident_pmd_init(info->pmd_flag, pmd, addr, next);
			continue;
		}
		pmd = (pmd_t *)info->alloc_pgt_page(info->context);
		if (!pmd)
			return -1;
		ident_pmd_init(info->pmd_flag, pmd, addr, next);
		set_pud(pud, __pud(__pa(pmd) | _KERNPG_TABLE));
	}

	return 0;
}

typedef struct { pgdval_t pgd; } pgd_t;

static inline pgd_t native_make_pgd(pgdval_t val)
{
        return (pgd_t) { val };
}

static inline pgdval_t native_pgd_val(pgd_t pgd)
{
        return pgd.pgd;
}

#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

static inline pgdval_t pgd_flags(pgd_t pgd)
{
        return native_pgd_val(pgd) & PTE_FLAGS_MASK;
}

static inline int pgd_present(pgd_t pgd)
{
        return pgd_flags(pgd) & _PAGE_PRESENT;
}

#define pgd_val(x)      native_pgd_val(x)
static inline grub_uint32_t pgd_page_vaddr(pgd_t pgd)
{
        return (grub_uint32_t)__va((grub_uint64_t)pgd_val(pgd) & PTE_PFN_MASK);
}

static inline pud_t *pud_offset(pgd_t *pgd, grub_uint64_t address)
{
        return (pud_t *)pgd_page_vaddr(*pgd) + pud_index(address);
}

static inline void native_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
        *pgdp = pgd;
}

#define set_pgd(pgdp, pgd)              native_set_pgd(pgdp, pgd)
#define __pgd(x)        native_make_pgd(x)

static int
ident_mapping_init(struct x86_mapping_info *info, pgd_t *pgd_page,
			      grub_uint64_t addr, grub_uint64_t end)
{
	grub_uint64_t next;
	int result;

	for (; addr < end; addr = next) {
		pgd_t *pgd = pgd_page + pgd_index(addr);
		pud_t *pud;

		next = (addr & PGDIR_MASK) + PGDIR_SIZE;
		if (next > end)
			next = end;

		if (pgd_present(*pgd)) {
			pud = pud_offset(pgd, 0);
			result = ident_pud_init(info, pud, addr, next);
			if (result)
				return result;
			continue;
		}

		pud = (pud_t *)info->alloc_pgt_page(info->context);
		if (!pud)
			return -1;
		result = ident_pud_init(info, pud, addr, next);
		if (result)
			return result;
		set_pgd(pgd, __pgd(__pa(pud) | _KERNPG_TABLE));
	}

	return 0;
}

struct alloc_pgt_data {
	grub_uint8_t *pgt_buf;
	grub_uint32_t pgt_buf_size;
	grub_uint32_t pgt_buf_offset;
};

static void *alloc_pgt_page(void *context)
{
	struct alloc_pgt_data *d = (struct alloc_pgt_data *)context;
	grub_uint8_t *p = (grub_uint8_t *)d->pgt_buf;

	if (d->pgt_buf_offset >= d->pgt_buf_size){
		grub_error(1, "out of pgt_buf\n");
		return NULL;
	}

	p += d->pgt_buf_offset;
	d->pgt_buf_offset += 4096;
	memset(p, 0, 4096);

        return p;
}

#define PGT_BUF_SIZE (4096*12)
static grub_uint8_t pgt_buf[PGT_BUF_SIZE] __attribute__ ((aligned(4096)));
static struct alloc_pgt_data data = {
	.pgt_buf = (grub_uint8_t *) pgt_buf,
	.pgt_buf_size = sizeof (pgt_buf),
	.pgt_buf_offset = 0,
};
static struct x86_mapping_info mapping_info = {
	.alloc_pgt_page = alloc_pgt_page,
	.context = &data,
	.pmd_flag = __PAGE_KERNEL_LARGE_EXEC,
};
static pgd_t *level4p;

static void
fill_linux64_pagetable (grub_uint64_t start, grub_uint64_t size)
{
	grub_uint64_t end = start + size;

	if (!level4p) {
		level4p = alloc_pgt_page(&data);

		/* first 4G */
		ident_mapping_init(&mapping_info, level4p, 0, 1ULL<<32);
	}

	/* align boundry to 2M */
	start = (start >> 21) << 21;
	end = ((end + (1<<21) - 1) >> 21) << 21;
	if (start >= (1ULL<<32))
		ident_mapping_init(&mapping_info, level4p, start, end);
}
