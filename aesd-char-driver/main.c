/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

#include "aesd-circular-buffer.h"

MODULE_AUTHOR("Vrushabh"); /** COMPLETED: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static int aesd_init_module(void);
static void aesd_cleanup_module(void);

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * COMPLETED: handle open
     */
    filp->private_data = &aesd_device;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * COMPLETED: handle release
     */

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);
    /**
     * COMPLETED: handle read
     */

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_pos = 0;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    // Find  buffer entry and position in entry corresponding to f_pos
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_pos);
    if (!entry)
    {
        // if no suitable pos exists simpy return 0
        mutex_unlock(&dev->lock);
        return retval;
    }

    // read only up to the end of entry
    if (count > entry->size - entry_pos)
    {
        count = entry->size - entry_pos;
    }

    if (copy_to_user(buf, entry->buffptr + entry_pos, count))
    {
        retval = -EFAULT;
        mutex_unlock(&dev->lock);
        return retval;
    }
    *f_pos += count;
    retval = count;

    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);
    /**
     * COMPLETED: handle write
     */

    struct aesd_dev *dev = filp->private_data;
    const char *replaced_entry = NULL;

    if (!buf || count == 0)
        return -EINVAL;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    size_t prev_size = dev->working_entry.size;

    // Allocate or grow working buffer
    char *new_ptr = krealloc(dev->working_entry.buffptr,
                             dev->working_entry.size + count, GFP_KERNEL);
    if (!new_ptr)
    {
        retval = -ENOMEM;
        mutex_unlock(&dev->lock);
        return retval;
    }

    dev->working_entry.buffptr = new_ptr;

    if (copy_from_user(dev->working_entry.buffptr + prev_size, buf, count))
    {
        retval = -EFAULT;
        mutex_unlock(&dev->lock);
        return retval;
    }

    dev->working_entry.size += count;
    retval = count;

    // Check if this write contains a newline (end of command)
    if (memchr(dev->working_entry.buffptr + prev_size, '\n', count))
    {
        replaced_entry = aesd_circular_buffer_add_entry(&dev->buffer, &dev->working_entry);

        if (replaced_entry)
            kfree(replaced_entry);

        // Reset working entry for next command
        dev->working_entry.buffptr = NULL;
        dev->working_entry.size = 0;
    }

    mutex_unlock(&dev->lock);
    return retval;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    printk(KERN_WARNING "got inside the init");
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
                                 "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * COMPLETED: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.buffer);
    mutex_init(&aesd_device.lock);

    printk(KERN_WARNING "done initialization of aesd specific");

    result = aesd_setup_cdev(&aesd_device);

    printk(KERN_WARNING "Step 2");

    if (result)
    {
        printk(KERN_WARNING "un register");
        unregister_chrdev_region(dev, 1);
    }
    printk(KERN_WARNING "returning");
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    // 1. Free all buffer entries
    uint8_t index;
    struct aesd_buffer_entry *entry;

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index)
    {
        if (entry->buffptr != NULL)
            kfree(entry->buffptr);
    }

    // 2. Delete the cdev
    cdev_del(&aesd_device.cdev);

    // 3. Destroy mutex
    mutex_destroy(&aesd_device.lock);

    // 4. Unregister device numbers
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
