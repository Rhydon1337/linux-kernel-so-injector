#include <linux/module.h>
#include <linux/kernel.h>   
#include <linux/fs.h>
 
#include "device_handlers.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rhydon");
 
struct file_operations fops = {
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_close,
};

static int driver_init(void)
{	
	
	printk(KERN_ALERT "hello...\n");
	return 0;
}
 
static void driver_exit(void)
{
	printk(KERN_WARNING "bye ...\n");
}

module_init(driver_init);
module_exit(driver_exit);
