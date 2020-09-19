#pragma once
#include <linux/sched.h>

typedef struct {
    int pid;
    char* so_path;
    size_t so_path_size;
} SoInjectionParameters;

int inject_so_ioctl_parser(unsigned long arg, SoInjectionParameters* parameters);

int inject_so(SoInjectionParameters* parameters);

int write_process_memory_page(struct task_struct* task, void* user_address, void* kernel_address, int len);

int write_process_memory(struct task_struct* task, void* user_address, void* kernel_address, int len);
