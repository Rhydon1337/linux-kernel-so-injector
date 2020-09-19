#include "so_injector.h"

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <uapi/asm-generic/mman-common.h>
#include <linux/sched/task_stack.h>
#include <uapi/asm/ptrace.h>

#include "consts.h"
#include "utils.h"
#include "elf.h"
#include "so_shellcode_loader.h"

#define KERNEL_PRIV 1

int inject_so_ioctl_parser(unsigned long arg, SoInjectionParameters* parameters) {
    unsigned long status;
    void* so_path;
    status = copy_from_user((void*)parameters, (void*)arg, sizeof(SoInjectionParameters));
    so_path = parameters->so_path;
    parameters->so_path = kmalloc(parameters->so_path_size, GFP_KERNEL);
    status = copy_from_user(parameters->so_path, so_path, parameters->so_path_size);
    if (SUCCESS != status) {
        return -EFAULT;
    }
    return SUCCESS;
}


int inject_so(SoInjectionParameters* parameters) {
    int status;
    struct task_struct* target_task;
    struct pid* pid_struct;
    void* free_addr;
    void* libc_address;
    void* symbol_address;

    printk(KERN_INFO "Start injecting the so to pid %d\n", parameters->pid);
    
    // find the target process
    pid_struct = find_get_pid(parameters->pid);
    target_task = pid_task(pid_struct, PIDTYPE_PID);
    if (NULL == target_task) {
        return INVALID_PID;
    }
    
    // stop the target process
    status = send_sig(SIGSTOP, target_task, KERNEL_PRIV);
    if (0 > status) {
        printk(KERN_INFO "Unable to stop the process, pid %d\n", parameters->pid);
        return SIGSTOP_FAILED;
    }
    printk(KERN_INFO "The process stopped successfully, pid %d\n", parameters->pid);

    // find free space for writing the so name
    free_addr = find_executable_space(parameters->pid);
    if (NULL == free_addr) {
        printk(KERN_INFO "Unable to find free space in the process, pid %d\n", parameters->pid);
        goto release_process;
    }
    printk(KERN_INFO "The free address is: %lx\n", (unsigned long)free_addr);

    // find libc for the injection
    libc_address = find_lib_address(parameters->pid, "libc-");
    if (NULL == libc_address) {
        printk(KERN_INFO "Unable to find any libc in the process, pid %d\n", parameters->pid);
        goto release_process;
    }
    printk(KERN_INFO "The address of the found lib is: %lx\n", (unsigned long)libc_address);

    // find __libc_dlopen_mode for loading the injected so
    symbol_address = get_symbol_address(target_task, libc_address, "__libc_dlopen_mode");
    printk(KERN_INFO "The address of the symbol is: %lx\n", (unsigned long)symbol_address);

    

release_process:
    send_sig(SIGCONT, target_task, KERNEL_PRIV);
    return status;
}