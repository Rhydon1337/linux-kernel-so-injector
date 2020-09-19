#include "ioctl.h"

#include <linux/slab.h>

#include "consts.h"
#include "so_injector.h"

int inject_so_ioctl_handler(unsigned long arg) {
    int status;
    SoInjectionParameters parameters;
    status = inject_so_ioctl_parser(arg, &parameters);
    if (SUCCESS != status) {
        return status;
    }
    status = inject_so(&parameters);
    if (SUCCESS != status) {
        kfree(parameters.so_path);
        return status;
    }
    kfree(parameters.so_path);
    return SUCCESS;
}