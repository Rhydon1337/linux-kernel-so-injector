#include "ioctl.h"

#include <linux/slab.h>
#include <linux/uaccess.h>

#include "consts.h"

int inject_shellcode_ioctl_parser(unsigned long arg, ShellcodeInjectionParameters* parameters) {
    unsigned long status;
    void* shellcode_usermode_address;
    __get_user(parameters->pid, (int *)arg);
    __get_user(shellcode_usermode_address, (void **)(arg + sizeof(int)));
    __get_user(parameters->shellcode_size, (unsigned int *) (arg + sizeof(int) + sizeof(void*)));
    parameters->shellcode = kmalloc(parameters->shellcode_size, GFP_KERNEL);
    status = copy_from_user(parameters->shellcode, shellcode_usermode_address, parameters->shellcode_size);
    if (SUCCESS != status) {
        return -EFAULT;
    }
    return SUCCESS;
}

int inject_shellcode(ShellcodeInjectionParameters* parameters) {
    printk(KERN_INFO "Start injecting the shellcode to pid %d\n", parameters->pid);
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
        return status;
    }
    kfree(parameters.shellcode);
    return SUCCESS;
}