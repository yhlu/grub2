/*
 * yhlu 2015-02-12
 *   search directly from memory map
 *   grub_alloc_search () is adapted from efi_alloc_high() of linux kernel
 */

struct grub_alloc_search_ctx {
  grub_uint64_t start;
  grub_uint64_t min_addr;
  grub_uint64_t max_addr;
  grub_uint64_t size;
  grub_size_t align_shift;
  grub_memory_type_t type;
};

static int
grub_alloc_search (grub_uint64_t addr, grub_uint64_t size,
                           grub_memory_type_t type, void *data)
{
  struct grub_alloc_search_ctx *ctx = data;
  grub_uint64_t start, end;

  if (ctx->type != type)
	return 0;

  end = addr + size;

  if (end > ctx->max_addr)
	end = ctx->max_addr;

  if ((addr + ctx->size) > end)
	return 0;

   /* round_down */
   start = ((end - ctx->size) >> ctx->align_shift) << ctx->align_shift;
   if (start < addr)
     return 0;

  if (start > ctx->start && start >= ctx->min_addr)
	ctx->start = start;

  return 0;
}

static grub_uint64_t
grub_alloc_high(grub_uint64_t min_addr, grub_uint64_t max_addr,
                grub_uint64_t size, grub_size_t align_shift)
{
   struct grub_alloc_search_ctx ctx = {
     .start = 0,
     .min_addr = min_addr,
     .max_addr = max_addr,
     .size = size,
     .align_shift = align_shift,
     .type = GRUB_MEMORY_AVAILABLE,
   };

  if (min_addr >= max_addr)
    return 0;

  if (grub_mmap_iterate (grub_alloc_search, &ctx))
    return 0;

  return ctx.start;
}
