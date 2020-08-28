#pragma once

typedef struct {
    int pid;
    void* shellcode;
    unsigned int shellcode_size;
} ShellcodeInjectionParameters;

#define IOCTL_INJECT_SHELLCODE _IOR(1337, 1, char*)

int inject_shellcode_ioctl_parser(unsigned long arg, ShellcodeInjectionParameters* parameters);

int inject_shellcode_ioctl_handler(unsigned long arg);

int inject_shellcode(ShellcodeInjectionParameters* parameters);