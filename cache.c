#ifndef __KERNEL__
	#define __KERNEL__
#endif
#ifndef MODULE
	#define MODULE
#endif
#include "cache.h"

DECLARE_DM_KCOPYD_THROTTLE_WITH_MODULE_PARM(cache_copy_throttle,
	"A percentage of time allocated for copying to and/or from cache");

struct cache_ctx_ctrl *ctx_ctrl;

static void l_cache_status(struct dm_target *ti, status_type_t type,
		unsigned status_flags, char *result, unsigned maxlen)
{
}

/*
* argv[0] path to source device
* argv[1] path to cache device
*  <optional>
* argv[2] cache size in sectors
* argv[3] cache persistence (default no)
* argv[4] cache block size (default 8 sectors)
*/
static int l_cache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	sector_t cache_size = ~0;
	unsigned int persistence = 0;
	sector_t block_size = 8;
	int err = -EINVAL;

	if (argc < 2) {
		printk("L-CACHE : too less params!");
		goto out;
	}

	ctx_ctrl = kmalloc(sizeof(struct cache_ctx_ctrl), GFP_KERNEL);
	if(!ctx_ctrl) {
		ti->error = "L-CACHE : allocate ctx_ctrl failed!";
		err = -ENOMEM;
		goto out;
	}

	// source device
	err = dm_get_device(ti, argv[0],
		dm_table_get_mode(ti->table), &ctx_ctrl->src_dev);
	if (err) {
		ti->error = "L-CACHE : source device lookup failed!";
		goto bad1;
	}

	// cache device
	err = dm_get_device(ti, argv[1],
		dm_table_get_mode(ti->table), &ctx_ctrl->cache_dev);
	if (err) {
		ti->error = "L-CACHE : cache device lookup failed!";
		goto bad2;
	}

	if (argc >= 3) {
		if (sscanf(argv[2], "%llu", &cache_size) != 1) {
			ti->error = "L-CACHE : invalid cache size!";
			err = -EINVAL;
			goto bad3;
		}
	}
	cache_size = ctx_ctrl->cache_dev->bdev->bd_part->nr_sects > cache_size ?
		cache_size : ctx_ctrl->cache_dev->bdev->bd_part->nr_sects;

	if (argc >= 4) {
		if (sscanf(argv[3], "%u", &persistence) != 1) {
			ti->error = "L-CACHE : invalid persistence!";
			err = -EINVAL;
			goto bad3;
		}
	}

	if (argc >= 5) {
		if (sscanf(argv[4], "%u", &block_size) != 1) {
			ti->error = "L-CACHE : invaild block size!";
			err = -EINVAL;
			goto bad3;
		}
	}

	ctx_ctrl->copier = dm_kcopyd_client_create(&dm_kcopyd_throttle);
	if (!ctx_ctrl->copier) {
		ti->error = "L-CACHE : init kcopyd client failed!";
		err = -EINVAL;
		goto bad3;
	}

	ctx_ctrl->io_client = dm_io_client_create();
	if (IS_ERR(ctx_ctrl->io_client)) {
		ti->error = "L-CACHE : create io client failed!";
		err = PTR_ERR(ctx_ctrl->io_client);
		goto bad4;
	}

	// jobs
	ctx_ctrl->job_ctrl = init_job_ctrl(ti);
	if (!ctx_ctrl->job_ctrl) {
		ti->error = "L-CACHE : init_job_ctrl() failed!";
		goto bad5;
	}

	// block infos
	ctx_ctrl->blks = init_block_info(cache_size / block_size);
	if (!ctx_ctrl->blks) {
		ti->error = "L-CACHE : init_block_info() failed!";
		goto bad6;
	}

	// hash
	if (init_hash_bucket(&ctx_ctrl->addr_bkt, _ADDR_HASH_SIZE, 
		sample_addr_hash)) {
		goto bad7;
	}

	if (init_hash_bucket(&ctx_ctrl->sign_bkt, _SIGN_HASH_SIZE,
		sample_sign_hash)) {
		goto bad8;
	}

        // crypto 
        ctx_ctrl->tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
        if (IS_ERR(ctx_ctrl->tfm)) {
                printk("L-CACHE : crypto_alloc_hash() failed");
                goto bad9;
        }

        // blk_ref cache
        ctx_ctrl->blk_ref_cachep = kmem_cache_create("aht_elem_cache",
                        sizeof(struct block_ref), __alignof__(struct block_ref),
                        0, NULL);
        if (!ctx_ctrl->blk_ref_cachep) {
                goto bad10;
        }

        // sign_elem cache
        ctx_ctrl->sign_elem_cachep = kmem_cache_create("sht_elem_cache",
                        sizeof(struct sign_hash_elem), __alignof__(struct sign_hash_elem),
                        0, NULL);
        if (!ctx_ctrl->sign_elem_cachep) {
                goto bad11;
        }

        // blk_and_job cache
        ctx_ctrl->blk_job_cachep = kmem_cache_create("blk_job_cache",
                        sizeof(struct blk_and_job), __alignof__(struct blk_and_job),
                        0, NULL);
        if (!ctx_ctrl->blk_job_cachep) {
                goto bad12;
        }

	// stats init
	ctx_ctrl->stats.reads = 0;
	ctx_ctrl->stats.writes = 0;
	ctx_ctrl->stats.aht_hits = 0;
	ctx_ctrl->stats.aht_miss = 0;
	ctx_ctrl->stats.sht_hits = 0;
	ctx_ctrl->stats.sht_miss = 0;
	ctx_ctrl->stats.replace = 0;
	ctx_ctrl->stats.writeback = 0;
	ctx_ctrl->stats.cache_size = cache_size;
	ctx_ctrl->stats.blk_size = block_size;
	ctx_ctrl->stats.blk_bits = ffs(block_size) - 1;
	ctx_ctrl->stats.blk_mask = block_size - 1; 

	if (dm_set_target_max_io_len(ti, block_size)) {
		goto bad13;
	}
	ti->private = ctx_ctrl;
	printk("L-CACHE : l_cache_ctr() ok!");
        printk("\tL-CACHE info\t\nsource device : %s\ncacher device : %s\n"
                        "cache size : %u\nblock size: %u\nblock bits : %u\n"
                        "block mask : %x", argv[0], argv[1],
                        ctx_ctrl->stats.cache_size, ctx_ctrl->stats.blk_size,
                        ctx_ctrl->stats.blk_bits, ctx_ctrl->stats.blk_mask);

	return 0;
bad13:
        kmem_cache_destroy(ctx_ctrl->blk_job_cachep);
bad12:
        kmem_cache_destroy(ctx_ctrl->sign_elem_cachep);
bad11:
        kmem_cache_destroy(ctx_ctrl->blk_ref_cachep);
bad10:
        crypto_free_hash(ctx_ctrl->tfm);
bad9:
	free_hash_bucket(&ctx_ctrl->sign_bkt);
bad8:
	free_hash_bucket(&ctx_ctrl->addr_bkt);
bad7:
	free_block_info(ctx_ctrl->blks);
bad6:
	free_job_ctrl(ctx_ctrl->job_ctrl);
bad5:
	dm_io_client_destroy(ctx_ctrl->io_client);
bad4:
	dm_kcopyd_client_destroy(ctx_ctrl->copier);
bad3:
	dm_put_device(ti, ctx_ctrl->cache_dev);
bad2:
	dm_put_device(ti, ctx_ctrl->src_dev);
bad1:
	kfree(ctx_ctrl);
out:
	return err;
} 

static void l_cache_dtr(struct dm_target *ti)
{
	struct cache_ctx_ctrl *ctx = ti->private;
	if (ctx) {
                kmem_cache_destroy(ctx_ctrl->blk_job_cachep);
                kmem_cache_destroy(ctx_ctrl->sign_elem_cachep);
                kmem_cache_destroy(ctx_ctrl->blk_ref_cachep);
                crypto_free_hash(ctx_ctrl->tfm);
		free_hash_bucket(&ctx->sign_bkt);
		free_hash_bucket(&ctx->addr_bkt);
		free_block_info(ctx->blks);
		free_job_ctrl(ctx->job_ctrl);
		dm_io_client_destroy(ctx->io_client);
		dm_kcopyd_client_destroy(ctx->copier);
		dm_put_device(ti, ctx->cache_dev);
		dm_put_device(ti, ctx->src_dev);
		kfree(ctx);
	}
	printk("L-CACHE : l_cache_dtr() ok!");
}

static int aht_hit_read(struct cache_ctx_ctrl *ctx, struct bio *bio,
		struct bucket_elem *elem, struct block_ref *ref)
{
        sector_t bi_secotr;
        sector_t offset;
        int res;

        BUG_ON(!ref);
        BUG_ON(!ref->blk);
        bi_secotr = _GET_BI_SECTOR(bio);
        offset = bi_secotr & ctx->stats.blk_mask;

        spin_lock(&ref->blk->blk_lock);
        if (ref->blk->state != _BLK_FREE) {
                spin_unlock(&ref->blk->blk_lock);
                res = DM_MAPIO_REQUEUE;
                goto out;
        }
        spin_unlock(&ref->blk->blk_lock);
        bio->bi_bdev = ctx->cache_dev->bdev;
        _GET_BI_SECTOR(bio) = (ref->blk->blk_no << ctx->stats.blk_bits) + offset;
        spin_lock(&block_lru_lock);
        move_to(&ref->blk->lru, &block_lru_head);
        spin_unlock(&block_lru_lock);
        res = DM_MAPIO_REMAPPED;

out:
	return res;
}

static int aht_miss_read(struct cache_ctx_ctrl *ctx, struct bio *bio,
		struct bucket_elem *elem)
{
        struct each_job *job;
        BUG_ON(!elem);
        job = new_job(ctx, bio, elem, NULL, NULL, NULL);
        job->rw = _JOB_READ;
        queue_job(job, ctx->job_ctrl);
	return DM_MAPIO_SUBMITTED;
}

static int aht_hit_write(struct cache_ctx_ctrl *ctx, struct bio *bio,
		struct bucket_elem *elem, struct block_ref *ref)
{
        int res;
        struct each_job *job = NULL;
        unsigned char sign[_MD5_LEN]; 

        BUG_ON(!ref);
        BUG_ON(!ref->blk);
        spin_lock(&ref->blk->blk_lock);
        if (ref->blk->state != _BLK_FREE) {
                spin_unlock(&ref->blk->blk_lock);
                res = DM_MAPIO_REQUEUE;
                goto out1;
        }
        ref->blk->state = _BLK_WRITE;
        spin_lock(&block_lru_lock);
        move_to(&ref->blk->lru, &block_lru_head);
        spin_unlock(&block_lru_lock);
        job = new_job(ctx, bio, elem, ref, NULL, NULL);
        if (!job->ext_bvec.nr_pages) {
                if (make_signature_normal(ctx, bio, sign)) {
                        printk("L-CACHE : aht_hit_write make_signature_normal failed!");
                        ref->blk->state = _BLK_FREE;
                        spin_unlock(&ref->blk->blk_lock);
                        res = DM_MAPIO_REQUEUE;
                        goto out1;
                }
                if (!memcmp(sign, ref->blk->signature, _MD5_LEN)) {     // matched
                        spin_unlock(&ref->blk->blk_lock);
                        job->rw = _JOB_RW_UD;   // the job will push into complete_jobs
                        res = DM_MAPIO_SUBMITTED;
                        goto out2;
                } else {
                        res = do_new_write(job, sign);
                        if (-1 == res) {
                                spin_unlock(&ref->blk->blk_lock);
                                job->rw = _JOB_RW_UD;
                                res = DM_MAPIO_SUBMITTED;
                                goto out2;
                        } else if (1 == res) {
                                res = DM_MAPIO_REQUEUE; 
                                goto out1;
                        } else {        // res == 0
                                res = DM_MAPIO_SUBMITTED; 
                                goto out2;
                        }
                }
        } else {
                job->ext_bvec.nr_ext_central = dm_div_up(job->ext_bvec.b_central,
                                PAGE_SIZE);
                job->ext_bvec.nr_pages += job->ext_bvec.nr_ext_central;
                job->rw = _JOB_READ;
                res = DM_MAPIO_SUBMITTED;
                goto out2;
        }

out2:
        queue_job(job, ctx->job_ctrl);
        return res;
out1:
        if (!job)
                mempool_free(job, ctx->job_ctrl->job_pool);
	return res;
}

static int aht_miss_write(struct cache_ctx_ctrl *ctx, struct bio *bio,
		struct bucket_elem *elem)
{
	return 0;
}

static int l_cache_map(struct dm_target *ti, struct bio *bio)
{
	struct cache_ctx_ctrl *ctx = (struct cache_ctx_ctrl *)ti->private;
	sector_t bi_sector = _GET_BI_SECTOR(bio);
	sector_t offset = bi_sector & ctx->stats.blk_mask;
	sector_t start = bi_sector - offset;
	struct block_ref *aht_hit;
	struct bucket_elem *elem;
        int res;

	elem = find_aht(&ctx->addr_bkt, start, &aht_hit);
	if (!elem) {
		printk("L-CACHE : find_aht() something wrong!");
		res = DM_MAPIO_SUBMITTED;	// ingore this bio
                goto out;
	}

	if (bio_data_dir(bio) == READ) {
		++ctx->stats.reads;
		if (!aht_hit) {	// AHT MISS
			++ctx->stats.aht_miss;
                        res = aht_miss_read(ctx, bio, elem);
                        goto out;
		} else {	// AHT HIT
			++ctx->stats.aht_hits;
                        //return aht_hit_read(ctx, bio, elem, aht_hit);
                        res = aht_hit_read(ctx, bio, elem, aht_hit);
                        goto out;
		}
	} else {
		++ctx->stats.writes;
		if (!aht_hit) {	// AHT MISS
			++ctx->stats.aht_miss;
		} else {	// AHT HIT
			++ctx->stats.aht_hits;
                        res = aht_hit_write(ctx, bio, elem, aht_hit);
                        goto out;
		}
	}

        //////////////////////////////////////////////// will delete when complete this project
        bio->bi_bdev = ctx->src_dev->bdev;
        return DM_MAPIO_REMAPPED; /////////////
        ////////////////////////////////////////////////
out:
        return res;
}

static struct target_type l_cache_target = {
	.name = "cache",
	.version = {0, 0, 1},
	.module = THIS_MODULE,
	.ctr = l_cache_ctr,
	.dtr = l_cache_dtr,
	.map = l_cache_map,
	.status = l_cache_status,
};

int __init l_cache_init(void)
{
	int err;

	err = dm_register_target(&l_cache_target);
	if (err < 0) {
		printk("L-CACHE : register target failed!\n");
		goto out;
	}

	err = sys_stats_init();
	if (err) {
		printk("L-CACHE : sys_stats_init failed!\n");
		dm_unregister_target(&l_cache_target);
		goto out;
	}

	printk("L-CACHE : install module!\n");
out:
	return err;
}

static void __exit l_cache_exit(void)
{
	dm_unregister_target(&l_cache_target);
	sys_stats_del();
	printk("L-CACHE : remove module!\n");
}

module_init(l_cache_init);
module_exit(l_cache_exit);

MODULE_DESCRIPTION("L-Cache");
MODULE_AUTHOR("Long");
MODULE_LICENSE("GPL");
