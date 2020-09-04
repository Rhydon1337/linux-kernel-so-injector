#pragma once

#define IOCTL_INJECT_SHELLCODE 1337

int inject_shellcode_ioctl_handler(unsigned long arg);