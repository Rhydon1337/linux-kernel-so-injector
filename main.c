#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rhydon");
 
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
