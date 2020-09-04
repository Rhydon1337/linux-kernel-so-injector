#include "ioctl.h"

#include <linux/slab.h>

#include "consts.h"
#include "shellcode_injector.h"

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