#include "job.h"
#include "blk_hash.h"

LIST_HEAD(block_lru_head);
spinlock_t block_lru_lock;

void init_each_block(struct block_info *blk)
{
	spin_lock_init(&blk->blk_lock);
	blk->state = _BLK_FREE;
	blk->sign_elem = NULL;
	INIT_LIST_HEAD(&blk->refs);
	blk->refs_nr = 0;
        blk->dirty_nr = 0;
	INIT_LIST_HEAD(&blk->lru);
	bio_list_init(&blk->r_bios);
	bio_list_init(&blk->w_bios);
	blk->private = NULL;
        memset(blk->signature, 0, _MD5_LEN);
}

static void init_block_ref(struct block_ref *ref)
{
        INIT_LIST_HEAD(&ref->ref_list);
        INIT_LIST_HEAD(&ref->hash_list);
        ref->src_sector = -1;
        ref->blk = NULL;
        ref->state = _REF_RESERVE;
}

struct block_ref *new_block_ref(struct kmem_cache *ref_cachep)
{
        struct block_ref *ref;
        ref = kmem_cache_alloc(ref_cachep, GFP_ATOMIC);
        if (!ref) {
                return NULL;
        }
        init_block_ref(ref);
        return ref;
}

/*
* move @entry to the behind of @new_prev
*/
void move_to(struct list_head *entry, struct list_head *new_prev)
{
        list_del(entry);
        list_add(entry, new_prev);
}

/*
* if call write_to_cache directly , it must make sure there hasn't dirty refrences
* in this block's refs list;
*
* if call write_to_cache as the callback fun by write_back_refrences , then the 
* caller(such as write_back_refrences) should write back all dirty refrences.
*
* NOTE ! we must destroy the block_ref obj in this function , because we write new
* data to this block .
*/
void write_to_cache(int read_err, unsigned long write_err, void *context)
{
        struct blk_and_job *p= (struct blk_and_job*)context;
        struct cache_ctx_ctrl *ctrl = p->job->ctx_ctrl;
        struct each_job *job = p->job;
        struct bucket_elem *bkt_elem = job->aht_bkt_elem;
        struct block_info *blk = p->blk;
        struct list_head *pos;
        struct list_head *oth;
        struct block_ref *tmp;

        BUG_ON(!bkt_elem);
        list_for_each_safe(pos, oth, &blk->refs) {
                tmp = (struct block_ref *)container_of(pos,
                                struct block_ref, ref_list);
                // specially when bio is write
                if (tmp == job->blk_ref)
                        continue;

                if (tmp->state == _REF_DIRTY) {
                        --blk->dirty_nr;
                        tmp->state = _REF_CLEAN;        // this isn't necessary
                        ++ctrl->stats.writeback;
                }
                // we will drop this block_ref obj
                --blk->refs_nr;
                spin_lock(&bkt_elem->lock);
                list_del(&tmp->hash_list);
                spin_unlock(&bkt_elem->lock);
                list_del(&tmp->ref_list);
                kmem_cache_free(ctrl->blk_ref_cachep, tmp);
        }

        BUG_ON(blk->dirty_nr != 0);
        blk->state = _BLK_FREE;

        job->cacher.bdev = ctrl->cache_dev->bdev;
        job->cacher.sector = blk->blk_no << ctrl->stats.blk_bits;
        job->cacher.count = ctrl->stats.blk_size;

        blk->state = _BLK_WRITE;
        if (!job->ext_bvec.nr_pages) {
                dm_io_async_bvec(1, &job->cacher, WRITE, job->org_bio->bi_io_vec
                                + _GET_BI_IDX(job->org_bio), io_callback, p);
        } else {
                dm_io_async_bvec(1, &job->cacher, WRITE, job->ext_bvec.bvec,
                                io_callback, p);
        }
}

int write_back_refrences(struct block_info *blk, struct dm_io_region *src, 
                struct dm_io_region *dest, struct each_job *job, dm_kcopyd_notify_fn cb)
{
        struct blk_and_job *p;

        p = kmem_cache_alloc(job->ctx_ctrl->blk_job_cachep, GFP_KERNEL);
        if (!p) {
                vfree(blk->private);
                spin_unlock(&blk->blk_lock);
                return -1;
        }
        p->blk = blk;
        p->job = job;
        blk->state = _BLK_WRITEBACK;
        dm_kcopyd_copy(job->ctx_ctrl->copier, src, blk->dirty_nr, dest,
                        0, cb, (void *)p);
        return 1;
}

/*
* choose a new cache block when blk is NULL
*/
int choose_cacheblock(struct each_job *job, struct block_info *blk,
                struct block_info **req_blk)
{
        struct list_head *pos;
        struct block_info *last;
        struct block_ref *tmp;
        struct dm_io_region *dest;

        if (!blk) {
                spin_lock(&block_lru_lock);
                BUG_ON(list_empty(&block_lru_head));
                last = (struct block_info *)list_last_entry(&block_lru_head,
                                struct block_info, lru);
                move_to(&last->lru, &block_lru_head);
                spin_unlock(&block_lru_lock);
                spin_lock(&last->blk_lock);
        } else {
                last = blk;
        }
        ++job->ctx_ctrl->stats.replace;
        if (!last->dirty_nr) {  // no dirty refrences
                *req_blk = last;
                return 0;       // everything is ok, caller will go on handle this job
        }
        dest = vmalloc(last->dirty_nr * sizeof(struct dm_io_region)); 
        if (!dest) {
                *req_blk = NULL;
                spin_unlock(&last->blk_lock);
                return -1;      // error , the caller will push the job to complete
        }
        last->private = dest;
        list_for_each(pos, &last->refs) {
                tmp = (struct block_ref *)container_of(pos,
                                struct block_ref, ref_list);
                // specially when bio is write
                if (tmp == job->blk_ref)
                        continue;

                if (tmp->state == _REF_DIRTY) {
                        dest->bdev = job->ctx_ctrl->src_dev->bdev;
                        dest->sector = tmp->src_sector;
                        dest->count = job->ctx_ctrl->stats.blk_size;
                        ++dest;
                }
        }
        job->source.bdev = job->ctx_ctrl->cache_dev->bdev;
        job->source.sector = last->blk_no << job->ctx_ctrl->stats.blk_bits;
        job->source.count = job->ctx_ctrl->stats.blk_size;
        *req_blk = last;
        // if return 1, the caller don't care this job any more, and the job
        // will deliver to the write_to_cache.
        return write_back_refrences(last, &job->source, last->private,
                        job, write_to_cache); 
}

/*
* init all cache blocks
* reutrn NULL if failed
* @nr : how many blocks
*/
struct block_info *init_block_info(sector_t nr)
{
	struct block_info *blks;
	sector_t index;

	blks = (struct block_info *)vmalloc(nr * sizeof(struct block_info));
	if (!blks) {
		goto bad1;
	}
        spin_lock_init(&block_lru_lock);
	for(index = 0; index < nr; ++index) {
		blks[index].blk_no = index;
		init_each_block(&blks[index]);
                list_add_tail(&blks[index].lru, &block_lru_head);
	}

	return blks;
bad1:
	return NULL;
}

void free_block_info(struct block_info *blks)
{
	vfree(blks);
}
