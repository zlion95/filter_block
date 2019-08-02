#include <linux/init.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>

/*
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
*/

#define DRIVER_NAME "block test driver"
#define DRIVER_MINORS 1
#define DEVICE_NAME "bt_dev"

#define ACTUAL_DEVICE_NAME1 "/dev/sdb"
#define DEVICE_MINOR 1

#define SECTOR_BITS 9
#define DEV_SIZE    (1UL<< 30) 
#define DEV_NAME_LEN 32

#define LOG_SCHEDULE_TIME HZ/10
#define LOG_BATCH_SIZE 10
#define SOURCE_NAME_SIZE 100
#define FUNC_NAME_SIZE 32
#define MESSAGE_SIZE 300
#define UTC_TIME_LEN 16

#define USE_BDEV_EXCL 1

/*
 *  Driver description to represent block_test device.
 */
struct block_test_dev {
    struct request_queue *queue;
    struct gendisk *disk;
    sector_t size;                      // Device size in sectors
    void *record_buffer;                // Bio record buffer

    struct file *file;
    //describ the lower device
    struct block_device *bdev;
    char bdev_name[DEV_NAME_LEN];
};

/* 
 * bio_context is used to save old context from upper device
 * */
struct bio_context {
    void *bi_private;
    void *bi_end_io;
    struct block_device *bdev;
};

/*
 * Information for logging data.
 */
struct log_info_t {
    char utc_time[UTC_TIME_LEN];
    char filename[SOURCE_NAME_SIZE];
    char func_name[FUNC_NAME_SIZE];
    char message[MESSAGE_SIZE];
    int level;
    int line_num;
};

/* 
 * Container of one log_info and point to next line.
 * */
struct log_line_t {
    struct log_info_t *log_info;
    struct log_line_t *next;
};

/* 
 * A queue uses to store and transfer log_info to printer thread.
 * */
struct log_queue {
    struct log_line_t *head;
    struct log_line_t *tail;
    int size;
};

//static DEFINE_SPINLOCK(block_test_lock);
static struct task_struct *log_thread = NULL;
static struct log_queue *log_q = NULL;

static int block_test_major = 0;
static struct block_test_dev *bt_dev = NULL;
static struct timex  txc;
static struct rtc_time tm;

/* 
 * Output one log_info line and free its space.
 * */
static void free_log_line(struct log_line_t *log_line) {
    struct log_info_t *log_info;
    log_info = log_line->log_info;
    printk("%s level:[%d] ## file:%s,\tfunction:%s,\tline:%d,\tMsg: %s\n", 
        log_info->utc_time, log_info->level,
        log_info->filename, log_info->func_name,
        log_info->line_num, log_info->message);
    kfree(log_info);
    kfree(log_line);
}

/* 
 * Thread to ragularly output batch of log_line.
 * */
static int batch_log_thread(void *data)
{
    struct log_queue *thread_log_queue = (struct log_queue *)data;
    struct log_line_t *log_line;
    int i;

    printk("block_test_thread: Enter thread, data=%d\n", data==NULL ? 0 : 1);
    while (!kthread_should_stop()) {
        if (thread_log_queue->size > LOG_BATCH_SIZE) {
            for (i = 0; i < LOG_BATCH_SIZE; ++i) {
                log_line = thread_log_queue->head;
                thread_log_queue->head = thread_log_queue->head->next;
                free_log_line(log_line);
                thread_log_queue->size--;
            }
        } 
        schedule_timeout(HZ / 100);
    }

    printk("block_test_thread: Clean thread, queue_size=%d\n", thread_log_queue->size);
    for (; thread_log_queue->size != 0; thread_log_queue->size--) {
        log_line = thread_log_queue->head;
        thread_log_queue->head = thread_log_queue->head->next;
        free_log_line(log_line);
    }
    printk("block_test_thread: Exit thread, queue_size=%d\n", thread_log_queue->size);
    return 0;
}

/* 
 * Get present UTC time.
 * */
static void get_utc_time(char *utc_time) {
    do_gettimeofday(&(txc.time));
    txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;
    rtc_time_to_tm(txc.time.tv_sec, &tm);
    sprintf(utc_time, "%04d-%02d-%02d %02d:%02d:%02d",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int log_msg(int level, const char *file, const char *func, 
                int line, char *message)
{
    struct log_info_t *log_info;
    struct log_line_t *log_line;
    int ret;

    ret = -ENOMEM;
    log_info = kmalloc(sizeof(struct log_info_t), GFP_KERNEL);
    if (!log_info)
        return ret;
    memset(log_info, 0, sizeof(struct log_info_t));
    strncpy(log_info->filename, file, SOURCE_NAME_SIZE);
    strncpy(log_info->func_name, func, FUNC_NAME_SIZE);
    strncpy(log_info->message, message, MESSAGE_SIZE);
    get_utc_time(log_info->utc_time);
    log_info->line_num = line;
    log_info->level = level;

    log_line = kmalloc(sizeof(struct log_line_t), GFP_KERNEL);
    if (!log_line)
        goto line_err;
    log_line->log_info = log_info;
    log_line->next = NULL;
    
    if (log_q->size) {
        log_q->tail->next = log_line;
        log_q->tail = log_q->tail->next;
    } else {
        log_q->head = log_line;
        log_q->tail = log_line;
    }
    log_q->size++;

    return 0;

line_err:
    kfree(log_info);
    return ret;
}

static void block_test_callback(struct bio *bio, int err)
{
    struct bio_context *bio_ctx = bio->bi_private;
    char msg[MESSAGE_SIZE];

    bio->bi_private = bio_ctx->bi_private;
    bio->bi_end_io = bio_ctx->bi_end_io;
//    bio->bi_bdev = bio_ctx->bdev;
    sprintf(msg, "return [%s] io request, end on sector %llu!\n",
            bio_data_dir(bio) == READ ? "read" : "write",
            (unsigned long long)bio->bi_sector);
    log_msg(0, __FILE__, __FUNCTION__, __LINE__, msg);

    kfree(bio_ctx);

    if (bio->bi_end_io)
        bio->bi_end_io(bio, err);
}

static int bio_data_record(struct bio *bio, struct block_test_dev *dev) {
    int i;
    struct bio_vec *bvec;

    void *mem_buffer;
    void *vdisk_buffer = dev->record_buffer + (bio->bi_sector << SECTOR_BITS);

    printk(KERN_NOTICE "bio bi_sector=%llu, bi_size=%u, dev->size=%llu\n",
            (unsigned long long)bio->bi_sector, bio->bi_size, (unsigned long long)dev->size);
    if ((bio->bi_sector << SECTOR_BITS) + bio->bi_size > dev->size)
        return -EIO; 

    bio_for_each_segment(bvec, bio, i) {
        mem_buffer = kmap(bvec->bv_page) + bvec->bv_offset;

        switch (bio_data_dir(bio)) {
            case WRITE:
                memcpy(vdisk_buffer, mem_buffer, bvec->bv_len);
                break;
        }
        printk(KERN_NOTICE "copy bio Beyond-end write %d\n", i);
        kunmap(bvec->bv_page);
        vdisk_buffer += bvec->bv_len;
    }
    return 0;
}

/* 
 * Check bio from upper device and send to lower device.
 * */
static int do_block_test_request(struct request_queue *q, struct bio *bio)
{
    struct bio_context *bio_ctx;
    struct block_test_dev *dev = (struct block_test_dev *)q->queuedata;
    char msg[MESSAGE_SIZE];
    int ret;

    sprintf(msg, "device [%s] recevied [%s] io request, access on dev \
sector[%llu], length is [%u] sectors.\n",
            dev->disk->disk_name,
            bio_data_dir(bio) == READ ? "read" : "write",
            (unsigned long long)bio->bi_sector,
            bio_sectors(bio));
    log_msg(0, __FILE__, __FUNCTION__, __LINE__, msg);
    
    //TODO: Here I need to add some function to filter bio content and then send to lower block.
    ret = bio_data_record(bio, dev);
    if (ret != 0)
        goto out1;

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

    //bio_ctx->bdev = bio->bi_bdev;
    bio->bi_bdev = dev->bdev;
    submit_bio(bio_rw(bio), bio);
    //bio_endio(bio, 0);
    return 0;

out1:
    printk("Record bio content fail.\n");
    bio_endio(bio, ret);
    return 0;
}

static int block_test_open(struct block_device *bdev, fmode_t mode)
{
    printk("block_test: device is opened\n");
    return 0;
}

static int block_test_release(struct gendisk *disk, fmode_t mode)
{
    struct block_test_dev *dev = disk->private_data;
    printk("block_test dump writed data: %s\n", (char *)dev->record_buffer);
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

    btdev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!btdev->queue) {
        printk(KERN_CRIT "alloc queue fail!\n");
		goto out_free_disk;
    }
    blk_queue_make_request(btdev->queue, do_block_test_request);
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

//    btdev->size = get_capacity(btdev->bdev->bd_disk) << SECTOR_BITS;

    // Add virtual memory to record some bio data.
    btdev->size = 200 << SECTOR_BITS;
    set_capacity(btdev->disk, (btdev->size >> SECTOR_BITS));
    btdev->record_buffer = vmalloc(btdev->size);
    if (!btdev->record_buffer) { 
        printk (KERN_NOTICE "vmalloc failure.\n");
        goto out_queue;
    }

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

    ret = block_test_dev_init(bt_dev, 0, ACTUAL_DEVICE_NAME1, DEV_NAME_LEN);
    if (ret != 0)
        goto out2;

    log_q = kmalloc(sizeof (struct log_queue), GFP_KERNEL);
    if (!log_q) {
        printk(KERN_CRIT "kmalloc for log_queue failed!\n");
        goto out2;
    }
    log_q->size = 0;
    log_thread = kthread_run(batch_log_thread, log_q, "block_test_batch_log");
    if (IS_ERR(log_thread)) {
        ret = PTR_ERR(log_thread);
        goto out_thread;
    }

    return 0;

out_thread:
    kfree(log_q);
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
    kfree(log_q);
}


module_init(block_test_init);
module_exit(block_test_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Zhishi Zeng");
