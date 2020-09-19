#pragma once

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <uapi/asm/ptrace.h>
void* find_lib_address(pid_t pid, char* library);

void* find_executable_space(pid_t pid);

ssize_t mem_read(struct task_struct* task, char *buf, size_t count, unsigned long pos);

ssize_t mem_write(struct task_struct* task, char *buf, size_t count, unsigned long pos);

void* get_shellcode(size_t* shellcode_size, struct pt_regs* registers, unsigned long so_library_name, unsigned long load_so_function);