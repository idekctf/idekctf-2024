#include "../linux/kernel/module/internal.h"
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");

static DEFINE_MUTEX(load_lock);
static int loaded = 0;
int (*load_module)(struct load_info *info, const char __user *uargs,
		       int flags) = (typeof(load_module))(long)&vfree - 0x11c090;

static long load_ioctl(struct file *file, unsigned int len,
                       unsigned long arg) {
    struct {
        uint8_t *module;
        char *uargs;
    } args;
    struct load_info info = {};
    long ret = -1;

    mutex_lock(&load_lock);
    if (loaded == 0) {
        loaded = 1;
    } else {
        goto done;
    }

    if (len > 345) {
        goto done;
    }

    if (0 != copy_from_user(&args, (void *)arg, sizeof(args))) {
        goto done;
    }

    info.len = len;
    info.hdr = kmalloc(info.len, GFP_KERNEL | __GFP_NOWARN);
    if (!info.hdr) {
        goto done;
    }

    if (0 != copy_from_user(info.hdr, (void *)args.module, info.len)) {
        goto release_hdr;
    }

    ret = load_module(&info, args.uargs, 0);

    goto done;

release_hdr:
    kfree(info.hdr);
done:
    mutex_unlock(&load_lock);
    return ret;
}

static struct file_operations load_fops = {
    .unlocked_ioctl = load_ioctl,
};

static struct miscdevice load_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "load",
    .fops = &load_fops,
};

static int __init load_init(void) {
    if (misc_register(&load_device) < 0) {
        printk(KERN_ALERT "[-] failed to initialize device\n");
        return -1;
    }
    return 0;
}

static void __exit load_exit(void) {}

module_init(load_init);
module_exit(load_exit);
