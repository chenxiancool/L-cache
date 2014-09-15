#ifndef _L_CACHE
#define _L_CACHE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/device-mapper.h>
#include <linux/dm-kcopyd.h>
#include <linux/dm-io.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#include "blk_hash.h"
#include "job.h"
#include "sys.h"

struct cache_stats {
	unsigned long reads;
	unsigned long writes;
	unsigned long aht_hits;
	unsigned long aht_miss;
	unsigned long sht_hits;
	unsigned long sht_miss;
	unsigned long replace;
	unsigned long writeback;

	unsigned long cache_size;	// cache size in sector 
	unsigned long blk_size;	// a cache block size in sector
	unsigned long blk_bits;
	unsigned long blk_mask;
};

struct cache_ctx_ctrl {
	struct dm_dev *src_dev;	// source device
	struct dm_dev *cache_dev;	// cache device

	struct dm_kcopyd_client *copier;	// when write-back
	struct dm_io_client *io_client;
	struct cache_job_ctrl *job_ctrl;

	struct block_info *blks;
	struct hash_bucket addr_bkt;
	struct hash_bucket sign_bkt;

        struct crypto_hash *tfm;

        struct kmem_cache *blk_ref_cachep;
        struct kmem_cache *sign_elem_cachep;
        struct kmem_cache *blk_job_cachep;

	struct cache_stats stats;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	#define _GET_BI_SECTOR(bio) (bio->bi_iter.bi_sector)
	#define _GET_BI_SIZE(bio) (bio->bi_iter.bi_size)
	#define _GET_BI_IDX(bio) (bio->bi_iter.bi_idx)
#else
	#define _GET_BI_SECTOR(bio) (bio->bi_sector)
	#define _GET_BI_SIZE(bio) (bio->bi_size)
	#define _GET_BI_IDX(bio) (bio->bi_idx)
#endif	

extern struct cache_ctx_ctrl *ctx_ctrl;


#endif
