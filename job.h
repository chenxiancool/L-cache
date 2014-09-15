#ifndef _L_CACHE_JOB
#define _L_CACHE_JOB

#include <linux/blkdev.h>
#include <linux/types.h>
#include <linux/dm-kcopyd.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/mempool.h>

#include "cache.h"

#define _MIN_EXTRA_PAGES 1024
#define _MIN_JOBS 1024

#define _JOB_RW_UD 0x00000000
#define _JOB_READ 0x10000000
#define _JOB_WRITE 0x20000000

#define _MD5_LEN 16


struct extra_bvec {
	struct bio_vec *bvec;	// extra segment vectors
	struct page_list *pages;	// extra pages
	unsigned int nr_pages;	// num of extra pages
	unsigned int nr_ext_head;
        unsigned int b_head;
	unsigned int nr_ext_central;
        unsigned int b_central;
	unsigned int nr_ext_tail;
        unsigned int b_tail;
};

struct each_job {
	struct list_head list;	// in jobs list (job_head)
	struct cache_ctx_ctrl *ctx_ctrl;	// cache controller
	struct block_ref *blk_ref;	// relate block_ref
        struct bucket_elem *aht_bkt_elem;
        struct sign_hash_elem *sign_elem;       // relate sign_hash_elem
        struct bucket_elem *sht_bkt_elem;

	struct bio *org_bio;	// origin bio
	struct dm_io_region source;
	struct dm_io_region cacher;
	unsigned int rw;	// read or write
	struct extra_bvec ext_bvec;	// if origin bio isn't aligned with 
					// blk_size then ext_bvec may be used
	unsigned char tmp_sign[_MD5_LEN];
};

struct cache_job_type {
	struct list_head job_head;	// see each_job
	spinlock_t lock;	// lock the job_head list
	unsigned int nr;	// elems num of the job_head list
	void *private;	// may have some eatra info
};

struct extra_pages {
	spinlock_t lock;
	struct page_list *pages;	// extra pages hold by job controller
	unsigned int nr_pages;	// total num
	unsigned int nr_frees;	// free num
};

struct cache_job_ctrl {
	wait_queue_head_t destroyd;	// wait all io complete

	struct workqueue_struct *cache_wq;
	struct work_struct cache_work;

	struct kmem_cache *job_cache;
	mempool_t *job_pool;

	struct cache_job_type complete_jobs;
	struct cache_job_type pages_jobs;
	struct cache_job_type io_jobs;
	atomic_t nr_jobs;	// total num of above jobs

	struct extra_pages ext_pages;
};

typedef int (*job_work)(struct each_job *job);

extern struct cache_job_ctrl *init_job_ctrl(struct dm_target *ti);

extern void cache_put_pages(struct extra_pages *ext, struct page_list *head);

extern int cache_get_pages(struct extra_pages *ext, unsigned int nr, 
                struct page_list **pl);

extern struct each_job *new_job(struct cache_ctx_ctrl *ctx, struct bio *bio, 
		struct bucket_elem *aht_elem, struct block_ref *blk_ref,
                struct bucket_elem *sht_elem, struct sign_hash_elem *sign_elem);

extern struct cache_job_ctrl *init_job_ctrl(struct dm_target *ti);

extern void io_callback(unsigned long err, void *ctx);

extern int dm_io_async_bvec(unsigned int nr_regions, struct dm_io_region *where, 
                int rw, struct bio_vec *bvec, io_notify_fn fn, void* ctx);

extern void free_job_ctrl(struct cache_job_ctrl *job);

extern void queue_job(struct each_job *job, struct cache_job_ctrl *job_ctrl);

extern void process_jobs(struct cache_job_type *type, job_work cb_fn);

extern void do_work(struct work_struct *work);

extern int make_signature(struct each_job *job);

#endif
