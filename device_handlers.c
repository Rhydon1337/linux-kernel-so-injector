#include "device_handlers.h"

#include <linux/module.h>
#include <asm/uaccess.h>

#include "ioctl.h"

int device_open(struct inode *inode, struct file *file) {
    return SUCCESS;
}

int device_close(struct inode *inode, struct file *file) {
    return SUCCESS;
}

long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    long status = SUCCESS;
    switch (cmd)
    {
    case IOCTL_INJECT_SHELLCODE:
        ShellcodeInjectionParameters shellcode_parameter;
        __get_user(shellcode_parameter.pid, (int*)arg);
        status = inject_shellcode_ioctl_handler(shellcode_parameter.pid, );
        break;
    
    default:
        status = SUCCESS;
        break;
    }
    return INVALID_PARAMETER;
}
