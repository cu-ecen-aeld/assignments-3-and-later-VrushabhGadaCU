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
#include "aesd_ioctl.h"

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

/**
 * @brief llseek implementation for AESD character device
 *
 * This function handles seeking within the AESD device file. It computes the total size
 * of all entries currently stored in the circular buffer and then uses `fixed_size_llseek`
 * to update the file position based on the given offset and whence.
 */
loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    size_t total_size = 0;
    size_t i;
    loff_t retval;

    // Acquire the device mutex to ensure thread-safe access
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    // Calculate total size of valid data in the circular buffer
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &dev->buffer, i)
    {
        total_size += entry->size;
    }

    // Use kernel helper to perform seek within valid data range
    retval = fixed_size_llseek(filp, off, whence, total_size);

    // Release the mutex before returning
    mutex_unlock(&dev->lock);
    return retval;
}

/**
 * @brief Adjust file offset based on write command and offset within that command
 *
 * This function is called by the AESDCHAR_IOCSEEKTO ioctl command.
 * It computes the absolute file offset corresponding to the given write command
 * index (`write_cmd`) and the byte offset within that command (`write_cmd_offset`).
 */
static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    // Validate command index
    if (write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        return -EINVAL;

    struct aesd_dev *dev = filp->private_data;
    uint8_t index;
    struct aesd_buffer_entry *entry;
    int retval = 0;
    unsigned int start_offset = 0;

    // Lock device for safe access to circular buffer
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    // Start from the oldest valid entry in the circular buffer
    index = dev->buffer.out_offs;


    // Traverse buffer entries until reaching the target command
    for (unsigned int i = 0; i <= write_cmd; i++)
    {
        entry = &dev->buffer.entry[index];

        if (i == write_cmd)
        {
            // Validate offset within target entry
            if (write_cmd_offset >= entry->size)
            {
                retval = -EINVAL;
                mutex_unlock(&dev->lock);
                return retval;
            }
            // Compute absolute byte position within device data
            start_offset += write_cmd_offset;
            break;
        }
        else
        {
            // Accumulate sizes of prior entries
            start_offset += entry->size;
        }

        // Move to next circular buffer entry
        index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    // Update file position to computed offset
    filp->f_pos = start_offset;

    // Unlock before returning
    mutex_unlock(&dev->lock);
    return retval;
}

/**
 * @brief IOCTL handler for AESD character device
 *
 * Supports the AESDCHAR_IOCSEEKTO command to reposition the file offset
 * based on a specific write command and offset provided by the user.
 */
long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int retval = 0;

    // Validate magic number and command number
    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
        return -ENOTTY;

    switch (cmd)
    {
    case AESDCHAR_IOCSEEKTO:
    {
        struct aesd_seekto seekto;

        // Copy parameters from user space
        if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
            retval = EFAULT;
        else
            // Adjust file offset based on provided seek parameters
            retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
        break;
    }

    default:
        // Invalid or unsupported command
        return -ENOTTY;
    }

    return retval;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
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
