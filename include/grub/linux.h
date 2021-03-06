#include <grub/file.h>

struct grub_linux_initrd_component;

struct grub_linux_initrd_context
{
  int nfiles;
  struct grub_linux_initrd_component *components;
  grub_off_t size;
};

grub_err_t
grub_initrd_init (int argc, char *argv[],
		  struct grub_linux_initrd_context *ctx);

grub_off_t
grub_get_initrd_size (struct grub_linux_initrd_context *ctx);

void
grub_initrd_close (struct grub_linux_initrd_context *initrd_ctx);

grub_err_t
grub_initrd_load (struct grub_linux_initrd_context *initrd_ctx,
		  char *argv[], void *target);

grub_err_t
grub_initrd_load_copy (struct grub_linux_initrd_context *initrd_ctx,
                  char *argv[], grub_uint64_t target, void * (*map_func)(unsigned long), void *buf);

