#include "ioctl.h"

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <uapi/asm-generic/mman-common.h>
#include <asm/highmem.h>

#include "consts.h"

#define KERNEL_PRIV 1

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

int write_process_memory_till_page(struct task_struct* task, void* user_address, void* kernel_address, int len) {
    void* kaddr;
	struct page* page;
	struct vm_area_struct* vma;
	int ret;
	ret = get_user_pages_remote(task, task->mm, (unsigned long)user_address, 1, FOLL_WRITE, &page, &vma, NULL);
	if (0 >= ret) {
		return GET_USER_PAGE_REMOTE_FAILED;
	}
	kaddr = kmap(page);
    
    memcpy(kaddr, kernel_address, len);

    kunmap(page);
	set_page_dirty_lock(page);
	put_page(page);
	return SUCCESS;
}

int inject_shellcode(ShellcodeInjectionParameters* parameters) {
    int status;
    struct task_struct* target_task;
    struct task_struct* prev_task;
    struct pid* pid_struct;
    void* target_allocated_memory_address;
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
    
    prev_task = get_current();

    // vm_mmap use current task and we doesnt want to allocate the memory at the sender task
    // we want to allocate the memory at the target therfore we have to change the current task
    current_task = target_task;
    
    // allocate memory for the shellcode in the target process
    target_allocated_memory_address = (void*)vm_mmap(NULL, parameters->shellcode_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);


    return SUCCESS;
}

int inject_shellcode_ioctl_handler(unsigned long arg) {
    int status;
    ShellcodeInjectionParameters parameters;
    status = inject_shellcode_ioctl_parser(arg, &parameters);
    if (SUCCESS != status) {
        return status;
    }
    status = inject_shellcode(&parameters);
    if (SUCCESS != status) {
        kfree(parameters.shellcode);
        return status;
    }
    kfree(parameters.shellcode);
    return SUCCESS;
}