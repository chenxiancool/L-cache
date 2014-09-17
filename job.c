#include "job.h"

static struct page_list *alloc_pagelist(void)
{
	struct page_list *pl = NULL;
	
	pl = kmalloc(sizeof(struct page_list), GFP_KERNEL);
	if (!pl) {
		goto bad1;
	}

	pl->page = alloc_page(GFP_KERNEL);
	if (!pl->page) {
		goto bad2;
	}

	return pl;
bad2:
	kfree(pl);	
bad1:
	return NULL;
}

static void free_pagelist(struct page_list *pl)
{
	if (pl) {
		__free_page(pl->page);
		kfree(pl);
	}
}

static void free_pagelists(struct page_list *head)
{
	struct page_list *next;
	while (head) {
		next = head->next;
		free_pagelist(head);
		head = next;
	}
}

void cache_put_pages(struct extra_pages *ext, struct page_list *head)
{
	struct page_list *next;

	spin_lock(&ext->lock);
	while (head) {
		next = head->next;
		head->next = ext->pages;
		ext->pages = head;
		++ext->nr_frees;
		head = next;
	}
	spin_unlock(&ext->lock);
}

int cache_get_pages(struct extra_pages *ext, unsigned int nr, 
                struct page_list **pl)
{
        int res = -1;
        struct page_list *tmp;
        spin_lock(&ext->lock);
        if (nr && nr <= ext->nr_frees) {
                ext->nr_frees -= nr;
                tmp = ext->pages;
                *pl = ext->pages;
                while (--nr) {
                        tmp = tmp->next;
                }
                ext->pages = tmp->next;
                tmp->next = NULL;
                res = 0;
        }
        spin_unlock(&ext->lock);
        return res;
}

static unsigned int alloc_extra_pages(struct extra_pages *ext, unsigned int nr)
{
	unsigned int index;
	struct page_list *head = NULL;
	struct page_list *next;

	for (index = 0; index < nr; ++index) {
		next = alloc_pagelist();
		if (!next) {
			if (head) {
				free_pagelists(head);
				return 1;
			}
		}
		next->next = head;
		head = next;
	}
	cache_put_pages(ext,head);
	ext->nr_pages += nr;

	return 0;
}

static void count_extra_pages(struct cache_ctx_ctrl *ctx, struct bio *bio, 
		struct each_job *job)
{
	sector_t bi_sector = _GET_BI_SECTOR(bio);
	sector_t offset = bi_sector & ctx->stats.blk_mask;
	sector_t start = bi_sector - offset;
	sector_t rest;
	unsigned int tail, head;

	head = to_bytes(offset);
	rest = (ctx->src_dev->bdev->bd_inode->i_size >> SECTOR_SHIFT) - start;
	if (rest < ctx->stats.blk_size) {
		tail = to_bytes(rest) - _GET_BI_SIZE(bio) - head;
		job->source.count = rest;
		job->cacher.count = rest;
	} else {
		tail = to_bytes(ctx->stats.blk_size) - _GET_BI_SIZE(bio) - head;
	}

	if (!head && !tail) {
		job->ext_bvec.nr_pages = 0;
		return;
	}
	if (head) {
		job->ext_bvec.nr_ext_head = dm_div_up(head, PAGE_SIZE);
                job->ext_bvec.b_head = head;
	}
	if (tail) {
		job->ext_bvec.nr_ext_tail = dm_div_up(tail, PAGE_SIZE);
                job->ext_bvec.b_tail = tail;
	}
        job->ext_bvec.b_central = _GET_BI_SIZE(bio);
	job->ext_bvec.nr_pages = job->ext_bvec.nr_ext_head + job->ext_bvec.nr_ext_tail;
} 

struct each_job *new_job(struct cache_ctx_ctrl *ctx, struct bio *bio, 
		struct bucket_elem *aht_elem, struct block_ref *blk_ref,
                struct bucket_elem *sht_elem, struct sign_hash_elem *sign_elem)
{
	struct each_job *job;
	sector_t bi_sector = _GET_BI_SECTOR(bio);
	sector_t offset = bi_sector & ctx->stats.blk_mask;
	sector_t start = bi_sector - offset;

	job = mempool_alloc(ctx->job_ctrl->job_pool, GFP_NOIO);
	BUG_ON(!job);
	INIT_LIST_HEAD(&job->list);
	job->org_bio = bio;
	job->source.bdev = ctx->src_dev->bdev;
	job->source.sector = start;
	job->source.count = ctx->stats.blk_size;
	job->cacher.bdev = ctx->cache_dev->bdev;
        if (blk_ref)
	        job->cacher.sector = blk_ref->blk->blk_no;
        else
                job->cacher.sector = -1;
	job->cacher.count = ctx->stats.blk_size;
        job->ctx_ctrl = ctx;
	job->blk_ref = blk_ref;
        job->aht_bkt_elem = aht_elem;
	job->sign_elem = sign_elem;
        job->sht_bkt_elem = sht_elem;
	job->rw = _JOB_RW_UD;
	job->ext_bvec.bvec = NULL;
	job->ext_bvec.pages = NULL;
	job->ext_bvec.nr_pages = 0;
	job->ext_bvec.nr_ext_head = 0;
        job->ext_bvec.b_head = 0;
	job->ext_bvec.nr_ext_central = 0;
        job->ext_bvec.b_central = 0;
	job->ext_bvec.nr_ext_tail = 0;
        job->ext_bvec.b_tail = 0;
	count_extra_pages(ctx, bio, job);
	memset(job->tmp_sign,0,_MD5_LEN);

	return job;
}

static void push_job(struct each_job *job, struct cache_job_type *type)
{
        spin_lock(&type->lock);
        list_add_tail(&job->list, &type->job_head);
        ++type->nr;
        spin_unlock(&type->lock);
}

static struct each_job *pop_job(struct cache_job_type *type)
{
        struct each_job *job = NULL;
        spin_lock(&type->lock);
        if (type->nr) {        // or can use !list_empty
               job = container_of(type->job_head.next, struct each_job, list);
               list_del(&job->list);
               --type->nr;
        }
        spin_unlock(&type->lock);
        return job;
}

static inline void wake_jobs(struct cache_job_ctrl *job_ctrl)
{
        queue_work(job_ctrl->cache_wq, &job_ctrl->cache_work);
}

void queue_job(struct each_job *job, struct cache_job_ctrl *job_ctrl)
{
        atomic_inc(&job_ctrl->nr_jobs);
        if (job->ext_bvec.nr_pages) {
                push_job(job, &job_ctrl->pages_jobs);
        } else {
                push_job(job, &job_ctrl->io_jobs);
        }
        wake_jobs(job_ctrl);
}

static int pages_work(struct each_job *job)
{
        int res;

        res = cache_get_pages(&job->ctx_ctrl->job_ctrl->ext_pages, 
                        job->ext_bvec.nr_pages, &job->ext_bvec.pages);
        if (res == -1) {
                return 1; // push this job
        } else {        // res == 0
                push_job(job, &job->ctx_ctrl->job_ctrl->io_jobs);
                return 0;
        }
}

static void insert_into_aht(struct bucket_elem *bkt_elem, struct block_ref *ref)
{
        spin_lock(&bkt_elem->lock);
        list_add_tail(&ref->hash_list, &bkt_elem->hash_elems);
        ++bkt_elem->nr;
        spin_unlock(&bkt_elem->lock);
}

static void insert_into_refs(struct block_info *blk, struct block_ref *ref)
{
        /*
        * the caller must make sure blk->blk_lock is locked!!!
        */
        //spin_lock(&blk->blk_lock);
        list_add_tail(&ref->ref_list, &blk->refs);
        ++blk->refs_nr;
        //spin_unlock(&blk->blk_lock);
}

static int insert_aht_and_refs(struct each_job *job)
{
        struct block_ref *new_ref;
        new_ref = new_block_ref(job->ctx_ctrl->blk_ref_cachep);
        if (!new_ref) {
                printk("L-CACHE : new_block_ref() failed!");
                return 1;
        }
        new_ref->src_sector = job->source.sector;
        new_ref->state = _REF_RESERVE;      // be clean until io complete
        new_ref->blk = job->sign_elem->blk;
        insert_into_aht(job->aht_bkt_elem, new_ref);
        insert_into_refs(new_ref->blk, new_ref);
        job->blk_ref = new_ref;
        return 0;
}

static int insert_sht(struct each_job *job, struct block_info *blk)
{
        struct sign_hash_elem *sign_hash;
        sign_hash = new_sign_hash_elem(job->ctx_ctrl->sign_elem_cachep);
        if (!sign_hash) {
                printk("L-CACHE : new_sign_hash_elem failed!");
                return 1;
        }
        sign_hash->blk = blk; 
        spin_lock(&job->sht_bkt_elem->lock);
        list_add_tail(&sign_hash->list, &job->sht_bkt_elem->hash_elems);
        job->sign_elem = sign_hash;
        ++job->sht_bkt_elem->nr;
        spin_unlock(&job->sht_bkt_elem->lock);
        return 0;
}

void io_callback(unsigned long err, void *ctx)
{
        struct blk_and_job *p = (struct blk_and_job *)ctx;
        struct each_job *job = p->job;
        struct block_info *blk = p->blk;
        struct bio *org_bio = job->org_bio;

        if (org_bio->bi_rw == READ) {
                if (job->rw == _JOB_READ) {
                        job->rw = _JOB_SIGN;
                        goto go_sign;
                } else if (job->rw == _JOB_SIGN) {
                        printk("L-CACHE : _JOB_SIGN must be error!");
                        goto complete;
                } else if (job->rw == _JOB_WRITE) {
                        BUG_ON(job->sign_elem); // if not NULL, must be error
                        BUG_ON(!job->sht_bkt_elem);
                        memcpy(blk->signature, job->tmp_sign, _MD5_LEN);
                        insert_sht(job, blk);
                        insert_aht_and_refs(job);
                        blk->state = _BLK_FREE;
                        if (blk->private) {
                                vfree(blk->private);
                                blk->private = NULL;
                        }
                        spin_unlock(&blk->blk_lock);
                        goto complete;
                } else {        // error
                        printk("L-CACHE : io_callback() error!");
                        goto complete;
                }
        } else {        // bio WRITE
                
        }
go_sign:
        kmem_cache_free(job->ctx_ctrl->blk_job_cachep, p);
        push_job(job, &job->ctx_ctrl->job_ctrl->signature_jobs);
        wake_jobs(job->ctx_ctrl->job_ctrl);
        return;
go_io:
        kmem_cache_free(job->ctx_ctrl->blk_job_cachep, p);
        push_job(job, &job->ctx_ctrl->job_ctrl->io_jobs);
        wake_jobs(job->ctx_ctrl->job_ctrl);
        return;
complete:
        kmem_cache_free(job->ctx_ctrl->blk_job_cachep, p);
        push_job(job, &job->ctx_ctrl->job_ctrl->complete_jobs);     // ingore this job
        wake_jobs(job->ctx_ctrl->job_ctrl);
        return;
}

int dm_io_async_bvec(unsigned int nr_regions, struct dm_io_region *where, 
                int rw, struct bio_vec *bvec, io_notify_fn fn, void* ctx)
{
        struct blk_and_job *p = (struct blk_and_job *)ctx;
        struct each_job *job = p->job;
        struct cache_ctx_ctrl *ctrl = job->ctx_ctrl;
        struct dm_io_request iorq;

        iorq.bi_rw = (rw | (1 << REQ_SYNC));
        iorq.mem.type = DM_IO_BVEC;
        iorq.mem.ptr.bvec = bvec;
        iorq.notify.fn = fn;
        iorq.notify.context = ctx;
        iorq.client = ctrl->io_client;

        return dm_io(&iorq, nr_regions, where, NULL);
}

static int make_new_bvec(struct each_job *job)
{
        struct bio *org_bio = job->org_bio;
        unsigned int nr_vecs;
        unsigned int index, tmp;
        struct bio_vec *bvec;
        struct page_list *pl;
        unsigned int head = job->ext_bvec.b_head;
        unsigned int remaining = job->ext_bvec.b_central;
        unsigned int tail = job->ext_bvec.b_tail;

        nr_vecs = org_bio->bi_vcnt - _GET_BI_IDX(org_bio) + job->ext_bvec.nr_pages;
        bvec = kmalloc(nr_vecs * sizeof(struct bio_vec), GFP_NOIO);
        if (!bvec) {
                printk("L-CACHE : kmalloc() bio_vec failed!");
                return 1;        // the job will push back
        }
        /* now we will build new bio_vec*/
        pl = job->ext_bvec.pages;
        index = 0;
        while (head) {  // the head part
                bvec[index].bv_page = pl->page;
                head -= bvec[index].bv_len;
                pl = pl->next;
                ++index;
        }

        tmp = _GET_BI_IDX(org_bio);
        while (remaining) {     // the central part
                bvec[index] = org_bio->bi_io_vec[tmp];
                remaining -= bvec[index].bv_len;
                ++index;
                ++tmp;
        }

        while (tail) {  // the tail part
                bvec[index].bv_len = min(tail, (unsigned int )PAGE_SIZE);
                bvec[index].bv_offset = 0;
                bvec[index].bv_page = pl->page;
                tail -= bvec[index].bv_len;
                pl = pl->next;
                ++index;
        }

        job->ext_bvec.bvec = bvec;

        return 0;
}

int make_signature(struct each_job *job)
{
        struct scatterlist sg;
        struct hash_desc desc;
        struct cache_ctx_ctrl *ctx = job->ctx_ctrl;
        struct bio *org_bio = job->org_bio;
        struct bio_vec *bv;
        int i;
        unsigned char *p;
        unsigned char *buff;
        unsigned int index;
        unsigned int nr_vecs;

        // if use vmalloc it will be error, because make_signature may in the
        // interrupt context
        buff = (unsigned char *)kmalloc(ctx->stats.blk_size * to_bytes(SECTOR_SHIFT),
                                GFP_ATOMIC);
        if (!buff) {
                return 1;       // error
        }

        index = 0;
        if (!job->ext_bvec.nr_pages) {
                bio_for_each_segment(bv, job->org_bio, i) {
                        p = (unsigned char *)kmap(bv->bv_page);
                        memcpy(buff+index, p+bv->bv_offset, bv->bv_len);
                        index += bv->bv_len;
                        kunmap(bv->bv_page);
                }
        } else {
                nr_vecs = org_bio->bi_vcnt - _GET_BI_IDX(org_bio)
                        + job->ext_bvec.nr_pages;
                for(i = 0; i < nr_vecs; ++i) {
                        bv = &job->ext_bvec.bvec[i];
                        p = (unsigned char *)kmap(bv->bv_page);
                        memcpy(buff+index, p+bv->bv_offset, bv->bv_len);
                        index += bv->bv_len;
                        kunmap(bv->bv_page);
                }
        }

        /* for debug message*/
        printk("L-CACHE : make_signature index=%u", index);

        desc.tfm = ctx->tfm;
        desc.flags = 0;
        memset(job->tmp_sign, 0, _MD5_LEN);
        sg_init_one(&sg, buff, index);
        crypto_hash_init(&desc);
        crypto_hash_update(&desc, &sg, index);
        crypto_hash_final(&desc, job->tmp_sign);
        kfree(buff);

        return 0;
}

static int io_fetch(struct each_job *job)
{
        int res;
        struct bio *org_bio = job->org_bio;
        struct blk_and_job *p;

        p = kmem_cache_alloc(job->ctx_ctrl->blk_job_cachep, GFP_KERNEL);
        if (!p) {
                return -1;
        }
        if (job->org_bio->bi_rw == READ) {
                p->blk = NULL;
                p->job = job;
                if (!job->ext_bvec.nr_pages) {  // needn't extra pages
                        res = dm_io_async_bvec(1, &job->source, READ,
                                        org_bio->bi_io_vec + _GET_BI_IDX(org_bio),
                                        io_callback, (void *)p);
                        return res;
                } else {
                        if (make_new_bvec(job)) {
                                return 1;       // the job will push back  
                        }
                        res = dm_io_async_bvec(1, &job->source, READ,
                                        job->ext_bvec.bvec, io_callback,
                                        (void *)p);
                        return res;
                }
        } else {        // bio WRITE

        }
}

static int io_store(struct each_job *job)
{
        int res;
        struct block_info *req_blk;
        struct blk_and_job *p;

        p = kmem_cache_alloc(job->ctx_ctrl->blk_job_cachep, GFP_KERNEL);
        if (!p) {
                printk("L-cACHE : blk_job_cachep failed!");
                spin_unlock(&req_blk->blk_lock);
                res = -1;
                goto out;
        }

        if (job->org_bio->bi_rw == WRITE) {
        
        } else {
                res = choose_cacheblock(job, &req_blk);
                if (0 == res) {
                        p->blk = req_blk;
                        p->job = job;
                        write_to_cache(0,0,p);
                } else if (1 == res) {
                        // while choose_cacheblock return 1 means we needn't care
                        // this job any more, it delivered to other function, but
                        // this also means the job works well, so io_store should
                        // reutrn 0
                        res = 0;
                } else {        // -1 == res, something error
                        // nothing to do, the caller will return -1 to process_jobs,
                        // and process_jobs will push this job to the complete_jobs
                        res = -1;
                }
        }

out:
        return res;
}

static int io_work(struct each_job *job)
{
        int res;

        if (job->rw == _JOB_READ) {
                res = io_fetch(job);
        } else if (job->rw == _JOB_WRITE) {
                res = io_store(job);
        } else {        // something error
                printk("L-CACHE : io_work cann't handle this job(type:%u)",job->rw);
                res = -1;
        }

        return res;
}

static int signature_work(struct each_job *job)
{
        struct bucket_elem *elem;
        struct sign_hash_elem *sign_elem;

        BUG_ON(job->rw != _JOB_SIGN);
        if (make_signature(job)) {
                printk("L-CACHE : make_signature() failed!");
                goto complete;
        }
        elem = find_sht(&job->ctx_ctrl->sign_bkt,
                        job->tmp_sign, &sign_elem);
        if (!elem) {
                printk("L-CACHE : find_sht() something wrong!");
                goto complete;
        }
        job->sign_elem = sign_elem;
        job->sht_bkt_elem = elem;
        if (!sign_elem) {       // SHT MISS
                ++job->ctx_ctrl->stats.sht_miss;
                job->rw = _JOB_WRITE;
                goto go_io;
        } else {        // SHT HIT
                ++job->ctx_ctrl->stats.sht_hits;
                insert_aht_and_refs(job);
                goto complete;
        }

go_io:
        push_job(job, &job->ctx_ctrl->job_ctrl->io_jobs);
        wake_jobs(job->ctx_ctrl->job_ctrl);
        return 0;
complete:
        push_job(job, &job->ctx_ctrl->job_ctrl->complete_jobs);     // ingore this job
        wake_jobs(job->ctx_ctrl->job_ctrl);
        return 0;
}

static int complete_work(struct each_job *job)
{
        struct bio *bio = job->org_bio;

        bio_endio(bio, 0);

        if (job->ext_bvec.nr_pages) {
                kfree(job->ext_bvec.bvec);
                cache_put_pages(&job->ctx_ctrl->job_ctrl->ext_pages,
                                job->ext_bvec.pages);
        }

        mempool_free(job, job->ctx_ctrl->job_ctrl->job_pool);

        return 0;
}

void process_jobs(struct cache_job_type *type, job_work fn)
{
        struct each_job* job;
        int res;

        while ((job = pop_job(type))) {
                res = fn(job);
                if (res < 0) {
                        printk("L-CACHE : process_jobs failed!");
                        push_job(job, &ctx_ctrl->job_ctrl->complete_jobs);
                } else if (res > 0) {   // cann't service at the moment
                        push_job(job, type);
                } else {        // service well!
                }
        }
}

static void process_all(void)
{
        struct cache_ctx_ctrl *ctx = ctx_ctrl;  // hey, ctx_ctrl is a global param
        process_jobs(&ctx->job_ctrl->signature_jobs, signature_work);
        process_jobs(&ctx->job_ctrl->complete_jobs, complete_work);
        process_jobs(&ctx->job_ctrl->pages_jobs, pages_work);
        process_jobs(&ctx->job_ctrl->io_jobs, io_work);
}

void do_work(struct work_struct *work)
{
        process_all();
}

static void init_job_type(struct cache_job_type *type)
{
	INIT_LIST_HEAD(&type->job_head);
	spin_lock_init(&type->lock);
	type->nr = 0;
	type->private = NULL;
}

/*
* init jobs
* 
* return the pointer to a cache_job_ctrl obj if success, however return NULL
* if something failed  
*/

struct cache_job_ctrl *init_job_ctrl(struct dm_target *ti)
{
	struct cache_job_ctrl *job;

	job = kmalloc(sizeof(struct cache_job_ctrl), GFP_KERNEL);
	if (!job) {
		ti->error = "L-CACHE : kmalloc() cache_job_ctrl failed!";
		goto bad1;
	}

	init_waitqueue_head(&job->destroyd);

	job->cache_wq = create_singlethread_workqueue("cache_wq");
	if (!job->cache_wq) {
		ti->error = "L-CACHE : create workqueue failed!";
		goto bad2;
	}
	INIT_WORK(&job->cache_work, do_work);

	job->job_cache = kmem_cache_create("job-cache", 
					sizeof(struct each_job),
					__alignof__(struct each_job),
					0,NULL);
	if (!job->job_cache) {
		ti->error = "L-CACHE : kmem_cache_create() job_cache failed!";
		goto bad3;
	}

	job->job_pool = mempool_create(_MIN_JOBS, mempool_alloc_slab,
			mempool_free_slab, job->job_cache);
	if(!job->job_pool) {
		goto bad4;
	}

	spin_lock_init(&job->ext_pages.lock);
	job->ext_pages.pages = NULL;
	job->ext_pages.nr_pages = 0;
	job->ext_pages.nr_frees = 0;
	if (alloc_extra_pages(&job->ext_pages, _MIN_EXTRA_PAGES)) {
		ti->error = "L-CACHE : alloc_extra_pages() failed!";
		goto bad5;
	}

	init_job_type(&job->signature_jobs);
	init_job_type(&job->complete_jobs);
	init_job_type(&job->pages_jobs);
	init_job_type(&job->io_jobs);
	atomic_set(&job->nr_jobs, 0);

	return job;
bad5:
	mempool_destroy(job->job_pool);
bad4:
	kmem_cache_destroy(job->job_cache);
bad3:
	destroy_workqueue(job->cache_wq);
bad2:
	kfree(job);
bad1:
	return NULL;
}

void free_job_ctrl(struct cache_job_ctrl *job)
{
	free_pagelists(job->ext_pages.pages);
	mempool_destroy(job->job_pool);
	kmem_cache_destroy(job->job_cache);
	destroy_workqueue(job->cache_wq);
	kfree(job);
}
