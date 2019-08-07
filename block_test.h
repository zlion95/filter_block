#ifndef __BLOCK_TEST_H_
#define __BLOCK_TEST_H_

#include <linux/init.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>

/*
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
*/
#define USE_BDEV_EXCL 1

#define DRIVER_NAME "block test driver"
#define DRIVER_MINORS 16
#define DEVICE_NAME "bt_dev"

#define ACTUAL_DEVICE_NAME1 "/dev/sdb"
#define DEVICE_MINOR 1

#define SECTOR_BITS 9
#define DEV_SIZE    (1UL<< 30) 
#define DEV_NAME_LEN 32

#define SOURCE_NAME_SIZE 100
#define FUNC_NAME_SIZE 32
#define UTC_TIME_LEN 16
#define MESSAGE_SIZE 300
#define MAX_SLEEP_TIMES 5
#define LOG_SCHEDULE_TIME HZ/10
#define LOG_BATCH_SIZE 10
#define LOG_FILE "/var/log/block_test.log"
#define MAX_LOG_SIZE 128 << 10 << 10

/*
 *  Driver description to represent block_test device.
 */
struct block_test_dev {
    struct request_queue *queue;
    struct gendisk *disk;
    sector_t size;                      // Device size in sectors
//    void *record_buffer;                // Bio record buffer

    struct file *file;
    //describ the lower device
    struct block_device *bdev;
    char bdev_name[DEV_NAME_LEN];
    void *private_data;
};

/* 
 * bio_context is used to save old context from upper device, 
 * and do some statistic for write process.
 * */
struct bio_context {
    void *bi_private;
    void *bi_end_io;
    unsigned int *bvec_sizes;
    sector_t bi_sector;
    unsigned int bi_size;
    unsigned int bvec_count;

    //struct device_io_context *io_context;
};

struct device_io_context {
    unsigned long long total_write_bi_size;
    int total_write_bi_count;
};

/*
 * Information for logging data.
 */
struct log_info_t {
    char filename[SOURCE_NAME_SIZE];
    char func_name[FUNC_NAME_SIZE];
    char message[MESSAGE_SIZE];
    char utc_time[UTC_TIME_LEN];
    int level;
    int line_num;
    struct list_head entry;
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


#endif //__BLOCK_TEST_H_
