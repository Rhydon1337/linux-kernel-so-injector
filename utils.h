#pragma once

#include <linux/kernel.h>
#include <linux/sched.h>

void* find_lib_address(pid_t pid, char* library);

void* find_executable_space(pid_t pid);

ssize_t mem_read(struct task_struct* task, char *buf, size_t count, unsigned long long pos);

ssize_t mem_write(struct task_struct* task, char *buf, size_t count, unsigned long long pos);
