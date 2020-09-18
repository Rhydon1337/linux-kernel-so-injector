#include <linux/kernel.h>

void* find_lib_address(pid_t pid, char* library);

void* find_executable_space(pid_t pid);

