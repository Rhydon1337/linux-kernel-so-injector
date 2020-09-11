#include "file.h"

struct file *file_open(const char *path, int flags, int rights) {
    struct file *filp = NULL;
    int err = 0;

    filp = filp_open(path, flags, rights);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file) {
    filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) {
    int ret;
    ret = kernel_read(file, data, size, &offset);
    return ret;
}   

int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) {
    int ret;
    ret = kernel_write(file, data, size, &offset);
    return ret;
}

int file_sync(struct file *file) {
    vfs_fsync(file, 0);
    return 0;
}