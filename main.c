#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/device.h>
#include <linux/cdev.h> 

#include "device_handlers.h"
#include "consts.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rhydon");
 
struct file_operations fops = {
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_close,
};

dev_t g_first_device;
struct cdev g_cdev;
struct class* g_cl;     

static int driver_initialization(void)
{
    int ret_val;
    printk(KERN_INFO "hello...\n");
    ret_val = register_chrdev(MAYJOR_NUMBER, DEVICE_NAME, &fops);
    if (ret_val < 0) {
        printk (KERN_ERR "Sorry, registering the character device failed with %d\n", ret_val);
        return ret_val;
    }
    ret_val = alloc_chrdev_region( &g_first_device, 0, 1, DEVICE_NAME);
    if( 0 > ret_val)
    {
        printk( KERN_ALERT "Device Registration failed\n" );
        return -1;
    }
    if ( (g_cl = class_create( THIS_MODULE, "chardev" ) ) == NULL )
    {
        printk( KERN_ALERT "Class creation failed\n" );
        unregister_chrdev_region( g_first_device, 1 );
        return -1;
    }
 
    if( device_create(g_cl, NULL, g_first_device, NULL, DEVICE_NAME) == NULL )
    {
        printk( KERN_ALERT "Device creation failed\n" );
        class_destroy(g_cl);
        unregister_chrdev_region(g_first_device, 1 );
        return -1;
    }
 
    cdev_init(&g_cdev, &fops);
 
    if(cdev_add( &g_cdev, g_first_device, 1 ) == -1)
    {
        printk( KERN_ALERT "Device addition failed\n" );
        device_destroy(g_cl, g_first_device);
        class_destroy(g_cl);
        unregister_chrdev_region(g_first_device, 1);
        return -1;
    }
	return SUCCESS;
}
 
static void driver_exit(void)
{
    cdev_del(&g_cdev);
    device_destroy(g_cl, g_first_device);
    class_destroy(g_cl);
    unregister_chrdev_region(g_first_device, 1);
    printk(KERN_ALERT "Device unregistered\n");
}

module_init(driver_initialization);
module_exit(driver_exit);
