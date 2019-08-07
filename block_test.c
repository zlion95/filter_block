#include "block_test.h"
#include <linux/syscalls.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define LOG_TO_FILE 1

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
 * Output one log_info line and free its space.
 * */

#ifdef LOG_TO_FILE
static void free_log_line(struct log_info_t *log_info, struct file *fp, loff_t *pos)
{
    unsigned int len = MESSAGE_SIZE;
    struct iovec iov = { .iov_base = (void *)msg_to_print, .iov_len = len };
    struct kiocb kiocb;

    memset(msg_to_print, 0, sizeof(msg_to_print));
    sprintf(msg_to_print, "%s level:[%d] ## %s:%s:%u,\tMsg: %s", 
            log_info->utc_time, log_info->level,
            log_info->filename, log_info->func_name,
            log_info->line_num, log_info->message);

    len = strlen(msg_to_print);
    iov.iov_len = len;
    init_sync_kiocb(&kiocb, fp);
    kiocb.ki_pos = *pos;
    kiocb.ki_left = len;

    if (fp == NULL || IS_ERR(fp)) {
        printk(msg_to_print);
    } else {
//        fp->f_op->write(fp, msg_to_print, len, &fp->f_pos);
        fp->f_op->aio_write(&kiocb, &iov, 1, kiocb.ki_pos);
    }

    kfree(log_info);
}
#else
static void free_log_line(struct log_info_t *log_info)
{
    sprintf(msg_to_print, "%s level:[%d] ## %s:%s:%u,\tMsg: %s", 
            log_info->utc_time, log_info->level,
            log_info->filename, log_info->func_name,
            log_info->line_num, log_info->message);
    printk(msg_to_print);
    kfree(log_info);
}
#endif

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
    struct list_head *head = (struct list_head *)data;
    struct log_info_t *log_info;
    struct list_head *lpos;
    loff_t pos;

#ifdef LOG_TO_FILE
    struct file *fp = NULL;
    mm_segment_t old_fs;

    if (fp == NULL)
        fp = filp_open(LOG_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(fp))
        LOG_MSG(0, "error occured while opening file %s, use printk instead\n");

    old_fs = get_fs();
    set_fs(KERNEL_DS);
#endif

    while (!kthread_should_stop()) {
        spin_lock(&block_test_lock);
        if (list_empty(head)) {
            spin_unlock(&block_test_lock);
            schedule_timeout(HZ * 100);
            continue;
        }
        lpos = head->next;
        log_info = list_entry(lpos, struct log_info_t, entry);
        list_del(lpos);
        spin_unlock(&block_test_lock);

        free_log_line(log_info, fp, &pos);
    }

    if (!list_empty(head)) {
        list_for_each(lpos, head) {
            log_info = list_entry(lpos, struct log_info_t, entry);
            list_del(lpos);
            free_log_line(log_info, fp, &pos);
        }
    }

#ifdef LOG_TO_FILE
    set_fs(old_fs);

    if (fp != NULL)
        filp_close(fp, NULL);
#endif

    return 0;
}


static void block_test_callback(struct bio *bio, int err)
{
    struct bio_context *bio_ctx = bio->bi_private;
    char msg[MESSAGE_SIZE];

    bio->bi_private = bio_ctx->bi_private;
    bio->bi_end_io = bio_ctx->bi_end_io;
    kfree(bio_ctx);

    sprintf(msg, "return [%s] io request, end on sector %llu!\n",
            bio_data_dir(bio) == READ ? "read" : "write",
            (unsigned long long)bio->bi_sector);
    LOG_MSG(0, msg);
    //kfree(bio_ctx->bvec_sizes);

    if (bio->bi_end_io)
        bio->bi_end_io(bio, err);
}

static int bio_data_record(struct bio *bio, struct block_test_dev *dev, 
        struct bio_context *bio_ctx)
{
    char msg[MESSAGE_SIZE];
    //int i;
    //struct bio_vec *bvec;

    bio_ctx->bi_sector = bio->bi_sector;
    bio_ctx->bi_size = bio->bi_size;
    bio_ctx->bvec_count = bio->bi_vcnt;


    sprintf(msg, "block_test_dev: [WRITE] bio info bi_sector=%llu, \
bi_size=%u, bvec_count=%u\n",
            (unsigned long long)bio->bi_sector, bio->bi_size,
            bio->bi_vcnt);
    LOG_MSG(0, msg);


    /* 
    bio_ctx->bvec_sizes = kmalloc(sizeof(int) * bio_ctx->bvec_count, GFP_KERNEL);
    if (!bio_ctx->bvec_sizes)
        return -ENOMEM;
    memset(bio_ctx->bvec_sizes, 0, sizeof(int) * bio_ctx->bvec_count);

    bio_for_each_segment(bvec, bio, i) {
        bio_ctx->bvec_sizes[i - bio->bi_idx] = bvec->bv_len;
    }
     * */

    return 0;
}

/* 
 * Check bio from upper device and send to lower device.
 * */
static int block_test_bio_req(struct bio *bio, struct block_test_dev *dev,
                            struct device_io_context *io_context)
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

    sprintf(msg, "device [%s] recevied [%s] io request, access on dev \
%u segs %u sectors from %llu\n",
            dev->disk->disk_name,
            bio_data_dir(bio) == READ ? "read" : "write",
            bio_segments(bio), 
            bio_sectors(bio), 
            (unsigned long long)bio->bi_sector);
    LOG_MSG(0, msg);

    if (bio_data_dir(bio) == WRITE) {
        //ret = bio_data_record(bio, dev, bio_ctx);
        //if (ret != 0)
        //    goto err2;
        io_context->total_write_bi_count += 1;
        io_context->total_write_bi_size += bio->bi_size;
    }
    
    bio_ctx->bi_private = bio->bi_private;
    bio_ctx->bi_end_io = bio->bi_end_io;
    bio->bi_private = bio_ctx;
    bio->bi_end_io = block_test_callback;

    bio->bi_bdev = dev->bdev;
    submit_bio(bio_rw(bio), bio);
    goto out;

err2:
    LOG_MSG(0, "RecorD bio content fail.\n");
    kfree(bio_ctx);
err1:
    bio_endio(bio, ret);
out:
    return 0;
}

static int block_test_make_request(struct request_queue *q, struct bio *bio)
{
    struct block_test_dev *dev = (struct block_test_dev *)q->queuedata;
    struct device_io_context *io_context = dev->private_data;

    return block_test_bio_req(bio, dev, io_context);
}

static int block_test_open(struct block_device *bdev, fmode_t mode)
{
    struct block_test_dev *dev = bdev->bd_disk->private_data;
    struct device_io_context *io_context;

    io_context = kmalloc(sizeof (struct device_io_context), GFP_KERNEL);
    if (!io_context) {
        LOG_MSG(0, "Alloc memory for io_context failed!\n");
        return -ENOMEM;
    }
    io_context->total_write_bi_count = 0;
    io_context->total_write_bi_size = 0;
    dev->private_data = io_context;

    LOG_MSG(0, "device is opened\n");
    return 0;
}

static int block_test_release(struct gendisk *disk, fmode_t mode)
{
    struct block_test_dev *dev = disk->private_data;
    struct device_io_context *io_context = dev->private_data;
    char msg[MESSAGE_SIZE];
    sprintf(msg, "all_write_bi_count=%d, all_write_bi_size=%llu\n",
            io_context->total_write_bi_count, io_context->total_write_bi_size);
    LOG_MSG(0, msg);
    kfree(io_context);
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

#ifdef USE_BDEV_EXCL
    btdev->bdev = open_bdev_exclusive(btdev->bdev_name,
                                    FMODE_WRITE | FMODE_READ, btdev->bdev);
    if (IS_ERR(btdev->bdev)) {
        printk(KERN_WARNING "Opend device [%s] lower dev [%s] failed!\n", 
                btdev->disk->disk_name, btdev->bdev_name);
        ret = PTR_ERR(btdev->bdev);
        goto out_queue;
    }
#else
    btdev->file = filp_open(btdev->bdev_name, O_RDWR, 0);
    if (IS_ERR(btdev->file)) {
        printk("block_test: open pdev file failed.\n");
        ret = -EBUSY;
        goto out_queue;
    }
    btdev->bdev = btdev->file->f_path.dentry->d_inode->i_bdev;
#endif

    btdev->size = get_capacity(btdev->bdev->bd_disk) << SECTOR_BITS;
    set_capacity(btdev->disk, (btdev->size >> SECTOR_BITS));

    btdev->disk->queue = btdev->queue;

    add_disk(btdev->disk);
    return 0;

out_queue:
#ifdef USE_BDEV_EXCL
    close_bdev_exclusive(btdev->bdev, FMODE_WRITE | FMODE_READ);
#else
    if (btdev->file) {
        filp_close(btdev->file, NULL);
        btdev->file = NULL;
    }
#endif
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

#ifdef USE_BDEV_EXCL
    if (bt_dev->bdev)
        close_bdev_exclusive(bt_dev->bdev, FMODE_WRITE | FMODE_READ);
#else
    if (bt_dev->file) {
        filp_close(bt_dev->file, NULL);
        bt_dev->file = NULL;
        bt_dev->bdev = NULL;
    }
#endif
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
