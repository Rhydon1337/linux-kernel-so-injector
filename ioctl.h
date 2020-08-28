#pragma once

typedef struct {
    int pid;
    void* shellcode;
    unsigned int shellcode_size;
} ShellcodeInjectionParameters;

#define IOCTL_INJECT_SHELLCODE _IOR(1337, 1, char*)

ShellcodeInjectionParameters inject_shellcode_ioctl_parser();

int inject_shellcode_ioctl_handler(char* message);

int inject_shellcode(int pid, void* shellcode, unsigned int len);