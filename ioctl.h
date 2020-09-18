#pragma once

#define IOCTL_INJECT_SHARED_OBJECT 1337

int inject_so_ioctl_handler(unsigned long arg);