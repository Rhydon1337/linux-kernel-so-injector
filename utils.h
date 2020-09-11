#include <linux/kernel.h>

void* find_libc_address(pid_t pid);

void* find_free_space_for_shellcode(pid_t pid);