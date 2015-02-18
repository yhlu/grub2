/*
 * yhlu 2015-02-12
 *   adapted from linuxbios: src/cpu/x86/pae/pgtbl.c
 *   change from 1:1 to 63:1
 */
static void paging_off(void)
{
        __asm__ __volatile__ (
                /* Disable paging */
                "movl   %%cr0, %%eax\n\t"
                "andl   $0x7FFFFFFF, %%eax\n\t"
                "movl   %%eax, %%cr0\n\t"
                /* Disable pae */
                "movl   %%cr4, %%eax\n\t"
                "andl   $0xFFFFFFDF, %%eax\n\t"
                "movl   %%eax, %%cr4\n\t"
                :
                :
                : "eax"
                );
}

static void paging_on(void *pdp)
{
        __asm__ __volatile__(
                /* Load the page table address */
                "movl   %0, %%cr3\n\t"
                /* Enable pae */
                "movl   %%cr4, %%eax\n\t"
                "orl    $0x00000020, %%eax\n\t"
                "movl   %%eax, %%cr4\n\t"
                /* Enable paging */
                "movl   %%cr0, %%eax\n\t"
                "orl    $0x80000000, %%eax\n\t"
                "movl   %%eax, %%cr0\n\t"
                :
                : "r" (pdp)
                : "eax"
                );
}

/* windows size: 64M */
static void * map_2M_page(unsigned long page)
{
        struct pde {
                grub_uint32_t addr_lo;
                grub_uint32_t addr_hi;
        } __attribute__ ((packed));
        struct pg_table {
                struct pde pd[2048];
                struct pde pdp[512];
        } __attribute__ ((packed));

        static struct pg_table pgtbl __attribute__ ((aligned(4096)));
        static unsigned long mapped_window;

        unsigned long window;
        void *result;
        int i;

        window = page >> 5;
        if (window != mapped_window) {
                paging_off();
                if (window > 63) {
                        struct pde *pd, *pdp;
                        /* Point the page directory pointers at the page directories */
                        memset(&pgtbl.pdp, 0, sizeof(pgtbl.pdp));
                        pd = pgtbl.pd;
                        pdp = pgtbl.pdp;
                        pdp[0].addr_lo = ((grub_uint32_t)&pd[512*0])|1;
                        pdp[1].addr_lo = ((grub_uint32_t)&pd[512*1])|1;
                        pdp[2].addr_lo = ((grub_uint32_t)&pd[512*2])|1;
                        pdp[3].addr_lo = ((grub_uint32_t)&pd[512*3])|1;
                        /* The first part 63/64 the page table is identity mapped */
                        for(i = 0; i < (1024 + 512 + 256 + 128 + 64 + 32); i++) {
                                pd[i].addr_lo = ((i & 0x7ff) << 21)| 0xE3;
                                pd[i].addr_hi = (i >> 11);
                        }
                        /* The second part 1/64 of the page table holds the mapped page */
                        for(i = (1024 + 512 + 256 + 128 + 64 + 32); i < 2048; i++) {
                                pd[i].addr_lo = ((window & 63) << 26) | ((i & 0x1f) << 21) | 0xE3;
                                pd[i].addr_hi = (window >> 6);
                        }
                        paging_on(pdp);
                }
                mapped_window = window;
        }
        if (window < 64) {
                result = (void *)(page << 21);
        } else {
                result = (void *)(0xfc000000 | ((page & 0x1f) << 21));
        }
        return result;
}

