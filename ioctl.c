#include "ioctl.h"

#include <linux/slab.h>
#include <linux/uaccess.h>

#include "consts.h"

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