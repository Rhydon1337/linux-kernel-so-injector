#pragma once
#include <linux/sched.h>

typedef struct {
    int pid;
    void* shellcode;
    unsigned int shellcode_size;
} ShellcodeInjectionParameters;

int inject_shellcode_ioctl_parser(unsigned long arg, ShellcodeInjectionParameters* parameters);

int inject_shellcode(ShellcodeInjectionParameters* parameters);

int write_process_memory_page(struct task_struct* task, void* user_address, void* kernel_address, int len);

int write_process_memory(struct task_struct* task, void* user_address, void* kernel_address, int len);
