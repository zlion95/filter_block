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
#include <linux/syscalls.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

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
    sector_t size;                          // Device size in sectors

    struct file *file;
    struct block_device *bdev;              //describ the lower device
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


#endif //__BLOCK_TEST_H_
