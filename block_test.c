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
#define DEV_SIZE    (1UL<< 30) 
#define DEV_NAME_LEN 32

#define ACTUAL_DEVICE_NAME "/dev/sdb"


struct block_test_dev {
    struct request_queue *queue;
    struct gendisk *disk;
    sector_t size;

    //describ the lower device
    struct block_device *bdev;
    char bdev_name[DEV_NAME_LEN];
};

//use to save old context for original bio
struct bio_context {
    void *bi_private;
    void *bi_end_io;
};

//static DEFINE_SPINLOCK(block_test_lock);
static struct gendisk *block_test_gendisk = NULL;
static int block_test_major = 0;
static struct block_test_dev *bt_dev = NULL;
static struct request_queue *block_test_queue = NULL;


static int block_test_callback(struct bio *bio, int err)
{
    struct bio_context *bio_ctx = bio->bi_private;

    bio->bi_private = bio_ctx->bi_private;
    bio->bi_end_io = bio_ctx->bi_end_io;
    kfree(bio_ctx);
    printk("return [%s] io request, end on sector %llu!\n",
            bio_data_dir(bio) == READ ? "read" : "write",
            (unsigned long long)bio->bi_sector);

    if (bio->bi_end_io)
        bio->bi_end_io(bio, err);

    return 0;
}

static int do_block_test_request(struct request_queue *q, struct bio *bio)
{
    struct bio_context *bio_ctx;
    struct block_test_dev *dev = (struct block_test_dev *)q->queuedata;
    printk("device [%s] recevied [%s] io request, access on dev sector[%llu], length is [%u] sectors.\n",
            dev->disk->disk_name,
            bio_data_dir(bio) == READ ? "read" : "write",
            (unsigned long long)bio->bi_sector,
            bio_sectors(bio));
    bio_ctx = kmalloc(sizeof (struct bio_context), GFP_KERNEL);
    if (!bio_ctx) {
        printk("Alloc memory for bio_context failed!\n");
        bio_endio(bio, -ENOMEM);
        return 0;
    }
    memset(bio_ctx, 0, sizeof(struct bio_context));
    
    bio_ctx->bi_private = bio->bi_private;
    bio_ctx->bi_end_io = bio->bi_end_io;
    bio->bi_private = bio_ctx;
    bio->bi_end_io = block_test_callback;

    bio->bi_bdev = dev->bdev;
    submit_bio(bio_rw(bio), bio);
    //bio_endio(bio, 0);
    return 0;
}

static int block_test_open(struct block_device *bdev, fmode_t mode)
{
    printk("device is open by: block_test\n");
    return 0;
}

static int block_test_release(struct gendisk *disk, fmode_t mode)
{
    printk("device is close by: block_test\n");
    return 0;
}

static struct block_device_operations block_dev_fops = {
    .owner        = THIS_MODULE,
    .open         = block_test_open,
    .release      = block_test_release,
};


static void block_test_dev_init(struct block_test_dev *btdev)
{
    bt_dev = kmalloc(sizeof (struct block_test_dev), GFP_KERNEL);
    strncpy(bt_dev->bdev_name, ACTUAL_DEVICE_NAME, DEV_NAME_LEN);
}

static int __init block_test_init(void)
{
    int ret;
	ret = -EBUSY;

#ifdef BLOCK_TEST_MAJOR
	if (register_blkdev(BLOCK_TEST_MAJOR, "block_test"))
		goto out1;
    block_test_major = BLOCK_TEST_MAJOR;
#else
    block_test_major = register_blkdev(block_test_major, "block_test");
    if (block_test_major < 0) {
        printk(KERN_CRIT "bldev register fail!\n");
        goto out1;
    }
#endif

	ret = -ENOMEM;
    block_test_gendisk = alloc_disk(1);
    if (!block_test_gendisk) {
        printk(KERN_CRIT "alloc disk fail!\n");
        goto out2;
    }
    block_test_dev_init(bt_dev);
    bt_dev->disk = block_test_gendisk;

    block_test_queue = blk_alloc_queue(GFP_KERNEL);
	if (!block_test_queue) {
        printk(KERN_CRIT "alloc queue fail!\n");
		goto out_queue;
    }
    blk_queue_make_request(block_test_queue, do_block_test_request);

    bt_dev->queue = block_test_queue;
    bt_dev->queue->queuedata = bt_dev;

    strncpy(bt_dev->disk->disk_name, DEVICE_NAME, DEV_NAME_LEN);
    bt_dev->disk->major = block_test_major;
    bt_dev->disk->first_minor = DEVICE_MINOR;
    bt_dev->disk->fops = &block_dev_fops;

    bt_dev->bdev = open_bdev_exclusive(bt_dev->bdev_name, FMODE_WRITE | FMODE_READ, bt_dev->bdev);
    if (IS_ERR(bt_dev->bdev)) {
        printk(KERN_CRIT "Opend device [%s] lower dev [%s] failed!\n", bt_dev->disk->disk_name, bt_dev->bdev_name);
        goto out_open_dev;
    }

    bt_dev->size = get_capacity(bt_dev->bdev->bd_disk) << SECTOR_BITS;
    set_capacity(bt_dev->disk, (bt_dev->size >> SECTOR_BITS));

    bt_dev->disk->queue = bt_dev->queue;

    add_disk(bt_dev->disk);
    return 0;

out_open_dev:
    close_bdev_exclusive(bt_dev->bdev, FMODE_WRITE | FMODE_READ);
    blk_cleanup_queue(bt_dev->queue);
    del_gendisk(block_test_gendisk);
out_queue:
    put_disk(block_test_gendisk);
out2:
    unregister_blkdev(block_test_major, "block_test");
out1:
    return ret;

}


static void __exit block_test_exit(void)
{
    close_bdev_exclusive(bt_dev->bdev, FMODE_WRITE | FMODE_READ);
    blk_cleanup_queue(bt_dev->queue);
    del_gendisk(bt_dev->disk);
    put_disk(bt_dev->disk);
    kfree(bt_dev);
    unregister_blkdev(block_test_major, "block_test");
}


module_init(block_test_init);
module_exit(block_test_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Zhishi Zeng");
