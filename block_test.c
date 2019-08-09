#include "block_test.h"

#define LOG_MSG(level, msg)     \
    log_msg(level, __FILE__, __FUNCTION__, __LINE__, msg)


static DEFINE_SPINLOCK(block_test_lock);
static struct task_struct *log_thread = NULL;

static int block_test_major = 0;
static struct block_test_dev *bt_dev = NULL;
static struct timex  txc;
static struct rtc_time tm;
static char msg_to_print[MESSAGE_SIZE];
static struct list_head log_head;

/* 
 * Output one log_info line.
 * */
static void output_log_info(struct log_info_t *log_info, struct file *fp)
{
    unsigned int len = MESSAGE_SIZE;
    int ret;

    memset(msg_to_print, 0, sizeof(msg_to_print));
    sprintf(msg_to_print, "%s level:[%d] ## %s:%s:%u,\tMsg: %s", 
            log_info->utc_time, log_info->level,
            log_info->filename, log_info->func_name,
            log_info->line_num, log_info->message);
    len = strlen(msg_to_print);

    ret = vfs_write(fp, msg_to_print, len, &fp->f_pos);
    if (ret < 0)
        printk(KERN_WARNING "block_test: write log line failed!");
}

/* 
 * Get present UTC time.
 * */
static void get_utc_time(char *utc_time)
{
    do_gettimeofday(&(txc.time));
    txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;
    rtc_time_to_tm(txc.time.tv_sec, &tm);
    sprintf(utc_time, "%04d-%02d-%02d %02d:%02d:%02d",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int log_msg(int level, const char *file, const char *func, 
                int line, const char *message)
{
    struct log_info_t *log_info;
    int ret;

    ret = -ENOMEM;
    log_info = kmalloc(sizeof(struct log_info_t), GFP_ATOMIC);
    if (!log_info)
        return ret;
    memset(log_info, 0, sizeof(struct log_info_t));
    strncpy(log_info->filename, file, SOURCE_NAME_SIZE);
    strncpy(log_info->func_name, func, FUNC_NAME_SIZE);
    strncpy(log_info->message, message, MESSAGE_SIZE);
    get_utc_time(log_info->utc_time);
    log_info->line_num = line;
    log_info->level = level;

    spin_lock(&block_test_lock);
    list_add_tail(&log_info->entry, &log_head);
    spin_unlock(&block_test_lock);

    return 0;
}

/* 
 * Thread to ragularly output batch of log_line.
 * */
static int batch_log_thread(void *data)
{
    struct list_head *head = (struct list_head *)data, temp_head;
    struct log_info_t *log_info, *nlog_info;

    struct file *fp = NULL;
    mm_segment_t old_fs;

    if (fp == NULL)
        fp = filp_open(LOG_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(fp))
        LOG_MSG(0, "error occured while opening file %s, use printk instead\n");

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    INIT_LIST_HEAD(&temp_head);
    while (!kthread_should_stop()) {
        if (!list_empty(head)) {
            spin_lock(&block_test_lock);
            list_splice_init(head, &temp_head);
            spin_unlock(&block_test_lock);
            list_for_each_entry_safe(log_info, nlog_info, &temp_head, entry) {
                list_del(&(log_info->entry));
                output_log_info(log_info, fp);
                kfree(log_info);
            }
        }
        cond_resched();
    }

    if (!list_empty(head)) {
        list_for_each_entry_safe(log_info, nlog_info, head, entry) {
            list_del(&(log_info->entry));
            output_log_info(log_info, fp);
            kfree(log_info);
        }
    }

    set_fs(old_fs);
    if (fp != NULL)
        filp_close(fp, NULL);

    return 0;
}


static void block_test_callback(struct bio *bio, int err)
{
    struct bio_context *bio_ctx = bio->bi_private;

    bio->bi_private = bio_ctx->bi_private;
    bio->bi_end_io = bio_ctx->bi_end_io;

    if (bio->bi_end_io)
        bio->bi_end_io(bio, err);
    kfree(bio_ctx);
}

/* 
 * Check bio from upper device and send to lower device.
 * */
static int block_test_bio_req(struct bio *bio, struct block_test_dev *dev)
{
    
    struct bio_context *bio_ctx;
    char msg[MESSAGE_SIZE];
    int ret = 0;

    bio_ctx = kmalloc(sizeof(struct bio_context), GFP_KERNEL);
    if (!bio_ctx) {
        LOG_MSG(0, "Alloc memory for bio_context failed!\n");
        ret = -ENOMEM;
        goto err1;
    }
    memset(bio_ctx, 0, sizeof(struct bio_context));

    bio_ctx->bi_private = bio->bi_private;
    bio_ctx->bi_end_io = bio->bi_end_io;
    bio->bi_private = bio_ctx;
    bio->bi_end_io = block_test_callback;

    bio->bi_bdev = dev->bdev;


    if (bio_data_dir(bio) == WRITE) {
        sprintf(msg, "device [%s] recevied [%s] io request, access on dev "
                    "%u segs %u sectors from %llu\n",
                dev->disk->disk_name,
                bio_data_dir(bio) == READ ? "read" : "write",
                bio_segments(bio), 
                bio_sectors(bio), 
                (unsigned long long)bio->bi_sector);
        LOG_MSG(0, msg);
    }

    submit_bio(bio_rw(bio), bio);
    goto out;

err1:
    bio_endio(bio, ret);
out:
    return 0;
}

static int block_test_make_request(struct request_queue *q, struct bio *bio)
{
    struct block_test_dev *dev = (struct block_test_dev *)q->queuedata;
    return block_test_bio_req(bio, dev);
}

static int block_test_open(struct block_device *bdev, fmode_t mode)
{
    LOG_MSG(0, "device is opened\n");
    return 0;
}

static int block_test_release(struct gendisk *disk, fmode_t mode)
{
    LOG_MSG(0, "block_test: device is closed\n");
    return 0;
}

static struct block_device_operations block_dev_fops = {
    .owner        = THIS_MODULE,
    .open         = block_test_open,
    .release      = block_test_release,
};


static int block_test_dev_init(struct block_test_dev *btdev, int which,
                               char *actual_device_name, int device_name_len)
{
    int ret = -ENOMEM;

    btdev->disk = alloc_disk(DRIVER_MINORS);
    if (!btdev->disk) {
        printk(KERN_CRIT "alloc gendisk fail\n");
        goto out;
    }

    strncpy(btdev->bdev_name, actual_device_name, device_name_len);
    sprintf(btdev->disk->disk_name, "%s%d", DEVICE_NAME, which);

//    btdev->queue = blk_init_queue(block_test_request, &block_test_lock);
    btdev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!btdev->queue) {
        printk(KERN_CRIT "alloc queue fail!\n");
		goto out_free_disk;
    }
    blk_queue_make_request(btdev->queue, block_test_make_request);
    btdev->queue->queuedata = btdev;

    btdev->disk->major = block_test_major;
    btdev->disk->first_minor = which * DRIVER_MINORS;
    btdev->disk->fops = &block_dev_fops;
    btdev->disk->private_data = btdev;

    btdev->bdev = open_bdev_exclusive(btdev->bdev_name,
                                    FMODE_WRITE | FMODE_READ, btdev->bdev);
    if (IS_ERR(btdev->bdev)) {
        printk(KERN_WARNING "Opend device [%s] lower dev [%s] failed!\n", 
                btdev->disk->disk_name, btdev->bdev_name);
        ret = PTR_ERR(btdev->bdev);
        goto out_queue;
    }

    btdev->size = get_capacity(btdev->bdev->bd_disk) << SECTOR_BITS;
    set_capacity(btdev->disk, (btdev->size >> SECTOR_BITS));

    btdev->disk->queue = btdev->queue;

    add_disk(btdev->disk);
    return 0;

out_queue:
    close_bdev_exclusive(btdev->bdev, FMODE_WRITE | FMODE_READ);
    blk_cleanup_queue(btdev->queue);
    del_gendisk(btdev->disk);
out_free_disk:
    put_disk(btdev->disk);
out:
    return ret;
}

static int __init block_test_init(void)
{
    int ret;
	ret = -EBUSY;

#ifdef BLOCK_TEST_MAJOR
    block_test_major = BLOCK_TEST_MAJOR;
#endif
    block_test_major = register_blkdev(block_test_major, "block_test");
    if (block_test_major <= 0) {
        printk(KERN_CRIT "block_test: bldev register fail!\n");
        goto out1;
    }

    bt_dev = kmalloc(sizeof (struct block_test_dev), GFP_KERNEL);
    if (!bt_dev) {
        printk(KERN_CRIT "alloc block_test_dev memory fail\n");
        ret = -ENOMEM;
        goto out2;
    }
    memset(bt_dev, 0, sizeof(struct block_test_dev));

    INIT_LIST_HEAD(&log_head);
    log_thread = kthread_run(batch_log_thread, &log_head, "block_test_batch_log");
    if (IS_ERR(log_thread)) {
        ret = PTR_ERR(log_thread);
        goto out_thread;
    }

    ret = block_test_dev_init(bt_dev, 0, ACTUAL_DEVICE_NAME1, DEV_NAME_LEN);
    if (ret != 0)
        goto out_thread;

    return 0;

out_thread:
    kfree(bt_dev);
out2:
    unregister_blkdev(block_test_major, "block_test");
out1:
    return ret;
}


static void __exit block_test_exit(void)
{

    if (bt_dev->bdev)
        close_bdev_exclusive(bt_dev->bdev, FMODE_WRITE | FMODE_READ);
    blk_cleanup_queue(bt_dev->queue);

    del_gendisk(bt_dev->disk);
    put_disk(bt_dev->disk);

    kfree(bt_dev);
    unregister_blkdev(block_test_major, "block_test");

    kthread_stop(log_thread);
}


module_init(block_test_init);
module_exit(block_test_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Zhishi Zeng");
