#pragma once
#include <linux/ioctl.h>
#include <linux/fs.h>

int device_open(struct inode *inode, struct file *file);

int device_close(struct inode *inode, struct file *file);

long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
