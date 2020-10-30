# linux-kernel-so-injector
## TL;DR
Linux kernel mode to user mode so injection

Tested on linux kernel version: 4.19.91. Current version depends on libc, but it's easy to change it.

Inject shared library to target process from the kernel

## How it works
The injection process is divided into several stages:

1. Send SIGSTOP to target process
2. Find free space for our shellcode (any R^X pages) using /proc/PID/maps
3. Find libc address using /proc/PID/maps
4. Parse libc elf at runtime to find __libc_dlopen_mode
5. Get the target process rip register 
6. Build our shellcode (get_shellcode function) with the correct address of:
    * So file path
    * Previous rip register address (in order to reconsturct the running of the process after loading the so from our shellcode)
    * __libc_dlopen_mode address (using this function in libc, we will load our so)
7. Write to target process memory the so file path
8. Write the shellcode to target process memory
9. Set target process rip register to the shellcode address
10. Send SIGCONT to target process

The whole process described above happens at the kernel module.
The only things that the kernel module needs are: target pid, so file path.

## Limitations
* Currently there is no support for processes which blocked by syscalls (e.g, waitpid).
* Currently implemented only for x86_64.
* This code isn't robust or fully tested. Therefore, you should expect bugs to occur under certain conditions when process getting non-stop signals or other edge cases.
* The shellcode and so path won't cleaned because I didn't have enough time to implement it from different kernel thread, but there is a commit which all the cleanup code available. However, the kernel thread isn't and without the creation of new kernel thread it will stick the injection.
* The reconstruction isn't fully (r15 isn't restored).

All of the limitations which mentioned above except for the first one (more research is needed for supporting blocking syscalls) could be solved.
