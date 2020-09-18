#pragma once

#include <linux/sched.h>
#include <linux/elf.h>

void* get_symbol_address(struct task_struct* task, void* module_base_address, const char* symbol_name);