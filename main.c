#include <linux/module.h>
#include <linux/kernel.h>   
#include <linux/fs.h>
 
#include "device_handlers.h"
#include "consts.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rhydon");
 
struct file_operations fops = {
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_close,
};

static int driver_init(void)
{		
	int ret_val;
	printk(KERN_ALERT "hello...\n");
	ret_val = register_chrdev(MAYJOR_NUMBER, DEVICE_NAME, &fops);
	if (ret_val < 0) {
    	printk (KERN_ERR "Sorry, registering the character device failed with %d\n", ret_val);
		return ret_val;
	}
	return SUCCESS;
}
 
static void driver_exit(void)
{
	printk(KERN_INFO "bye ...\n");
	unregister_chrdev(MAYJOR_NUMBER, DEVICE_NAME);
}

module_init(driver_init);
module_exit(driver_exit);
