#include "utils.h"

#include "file.h"

void* find_libc_address(pid_t pid) {
    struct file* fp;
	char filename[30];
	char line[850];
	unsigned long addr;
    int offset = 0;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = file_open(filename, O_RDONLY, 0);
	if(NULL == fp) {
		return NULL;
    }
	while(file_read(fp, offset, line, 850) != 0)
	{
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if(strstr(line, "libc-") != NULL)
		{
			break;
		}
	}
	file_close(fp);
	return (void*)addr;
}


void* find_free_space_for_shellcode(pid_t pid)
{
	struct file* fp;
	char filename[30];
	char line[850];
	unsigned long addr;
	char str[20];
	char perms[5];
    int offset = 0;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = file_open(filename, O_RDONLY, 0);
	if(NULL == fp) {
		return NULL;
    }
	while(file_read(fp, offset, line, 850) != 0)
	{
		sscanf(line, "%lx-%*x %s %*s %s %*d", &addr, perms, str);

		if(strstr(perms, "x") != NULL)
		{
			break;
		}
        offset += 850;
	}
	file_close(fp);
	return (void*)addr;
}