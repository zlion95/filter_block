#include <linux/init.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/genhd.h>

/*
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
*/

#define DRIVER_NAME "block test driver"
#define DEVICE_NAME "bt_dev"
#define DEVICE_MINOR 0

//#define BLOCK_TEST_MAJOR 16
#define SECTOR_BITS 9
#define DEV_SIZE    (512UL<< 20) 


struct block_test_dev {
    struct block_device *bdev;
    struct request_queue *queue;
    struct gendisk *disk;
    sector_t size;
};

//static DEFINE_SPINLOCK(block_test_lock);
static struct gendisk *block_test_gendisk = NULL;
static int block_test_major = 0;
static struct block_test_dev *bt_dev = NULL;
static struct request_queue *block_test_queue = NULL;

static int do_block_test_request(struct request_queue *q, struct bio *bio)
{
    struct block_test_dev *dev = (struct block_test_dev *)q->queuedata;
    printk("device [%s] recevied [%s] io request, access on dev sector[%llu], length is [%u] sectors.\n",
            dev->disk->disk_name,
            bio_data_dir(bio) == READ ? "read" : "write",
            (unsigned long long)bio->bi_sector,
            bio_sectors(bio));
    bio_endio(bio, 0);
    return 0;
}

static int block_test_open(struct block_device *bdev, fmode_t mode) {
    printk("device is open by: block_test\n");
    return 0;
}

static int block_test_release(struct gendisk *disk, fmode_t mode) {
    printk("device is close by: block_test\n");
    return 0;
}

static struct block_device_operations block_dev_fops = {
    .owner        = THIS_MODULE,
    .open         = block_test_open,
    .release      = block_test_release,
};

static int __init block_test_init(void)
{
    int ret;
	ret = -EBUSY;

    /*
#ifdef BLOCK_TEST_MAJOR
	if (register_blkdev(BLOCK_TEST_MAJOR, "block_test"))
		goto out1;
    block_test_major = BLOCK_TEST_MAJOR;
#else
*/
    block_test_major = register_blkdev(block_test_major, "block_test");
    if (block_test_major < 0) {
        printk(KERN_CRIT "bldev register fail!\n");
        goto out1;
    }
    /*
#endif
*/

	ret = -ENOMEM;
    block_test_gendisk = alloc_disk(1);
    if (!block_test_gendisk) {
        printk(KERN_CRIT "alloc disk fail!\n");
        goto out2;
    }
    bt_dev = kmalloc(sizeof (struct block_test_dev), GFP_KERNEL);
    bt_dev->disk = block_test_gendisk;

    block_test_queue = blk_alloc_queue(GFP_KERNEL);
	if (!block_test_queue) {
        printk(KERN_CRIT "alloc queue fail!\n");
		goto out_queue;
    }
    blk_queue_make_request(block_test_queue, do_block_test_request);

    bt_dev->queue = block_test_queue;
    bt_dev->queue->queuedata = bt_dev;

    bt_dev->size = DEV_SIZE;
    strncpy(bt_dev->disk->disk_name, DEVICE_NAME, 32);
    bt_dev->disk->major = block_test_major;
    bt_dev->disk->first_minor = DEVICE_MINOR;
    bt_dev->disk->fops = &block_dev_fops;
    bt_dev->disk->queue = bt_dev->queue;
    set_capacity(bt_dev->disk, (bt_dev->size >> SECTOR_BITS));

    add_disk(bt_dev->disk);
    return 0;

out_queue:
    put_disk(block_test_gendisk);
out2:
    unregister_blkdev(block_test_major, "block_test");
out1:
    return ret;

}


static void __exit block_test_exit(void)
{
    /*
    if (bt_dev)
    {
        invalidate_bdev(bt_dev, 1);
        blkdev_put(bt_dev);
    }
    */

    blk_cleanup_queue(bt_dev->queue);
    del_gendisk(bt_dev->disk);
    put_disk(bt_dev->disk);
    unregister_blkdev(block_test_major, "block_test");
}


module_init(block_test_init);
module_exit(block_test_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Zhishi Zeng");
