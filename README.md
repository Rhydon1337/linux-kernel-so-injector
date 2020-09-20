# kernel-injector
## TL;DR
Linux kernel mode to user mode so injection

Tested on linux kernel version: 4.19.91. Current version depends on libc but its easy to change it.

Inject shared library to target process from kernel

## How it works?
The injection process is divided into several stages:

1. Send SIGSTOP to target process
2. Find free space for our shellcode (any R^X pages) using /proc/pid/maps
3. Find libc address using /proc/pid/maps
4. Parse libc elf at runtime to find __libc_dlopen_mode
5. Write to target process memory the so file path
6. Build our shellcode (get_shellcode function) with the correct address of:

    * So file path
    * Previous rip register address (in order to reconsturct the running of the process after loading the so from our shellcode)
    * __libc_dlopen_mode address (using this function in libc we will load our so)
7. Write the shellcode to target process memory
8. Send SIGCONT to target process

The whole process described above is happing at the kernel module.
The only things that the kernel module needs are: target pid, so file path.

## Limitaions
* Currently there is no support for processes which blocked by syscalls (e.g, waitpid).
* Currently implemented only for x86_64.