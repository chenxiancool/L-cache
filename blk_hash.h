#ifndef _L_CACHE_BLOCK
#define _L_CACHE_BLOCK

#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/dm-kcopyd.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/version.h>

#define _BLK_FREE 1
#define _BLK_READ 2
#define _BLK_WRITE 4
#define _BLK_WRITEBACK 8

#define _ADDR_HASH_SIZE 100
#define _SIGN_HASH_SIZE 256
#define _ADDR_HASH_MOD _ADDR_HASH_SIZE
#define _SIGN_HASH_MOD _SIGN_HASH_SIZE

#define _REF_CLEAN 1
#define _REF_DIRTY 2
#define _REF_RESERVE 4

#define _MD5_LEN 16

extern struct list_head block_lru_head;
extern spinlock_t block_lru_lock;

struct block_info {
	sector_t blk_no;	// corresponding sector of cache device
        spinlock_t blk_lock;
	unsigned int state;	// SSD_READ/SSD_WRITE/SSD_FREE

	unsigned char signature[_MD5_LEN];	// signature of this block's content
	struct sign_hash_elem *sign_elem;	// corresponding sign_hash_elem

	struct list_head refs;	// a block_ref list
	unsigned int refs_nr;	// elem num of the refs list
        unsigned int dirty_nr;  // dirty elem num of the refs list;

	struct list_head lru;	// in lru list

	struct bio_list r_bios;
	struct bio_list w_bios;

        void *private;  // other
};

typedef unsigned long (*hash_fun)(void *data);

struct bucket_elem {
	spinlock_t lock;
	struct list_head hash_elems;	// a list of elements
	unsigned int nr;	// num of elements
};

struct hash_bucket {
	unsigned int size;	// num of bucket_elem
	hash_fun hash_fn;	// hash function
	struct bucket_elem *bkt_arr;	// bucket_elem array
};

struct sign_hash_elem {
	struct block_info *blk;
	struct list_head list;	// in bucket_elem's hash_elems list 
};

struct block_ref {
	struct list_head ref_list;	// in block_info's refs list
	struct list_head hash_list;	// in address-hash-table
	sector_t src_sector;	// corresponding sector of source device
	struct block_info *blk;	// corresponding block_info obj
	unsigned int state;	// dirty / clear ...
};

struct blk_and_job {
        struct each_job *job;
        struct block_info *blk;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
        #define list_last_entry(ptr, type, member) \
                list_entry((ptr)->prev, type, member)
#endif

extern struct block_info *init_block_info(sector_t nr);

extern void free_block_info(struct block_info *blks);

extern unsigned long sample_addr_hash(void *data);

extern unsigned long sample_sign_hash(void *data);

extern struct bucket_elem *find_bucket_elem(struct hash_bucket *bkt, void *data);

extern struct bucket_elem *find_aht(struct hash_bucket *bkt, sector_t sect, 
			struct block_ref **ref);

extern struct bucket_elem *find_sht(struct hash_bucket *bkt, unsigned char *data, 
			struct sign_hash_elem **sign_elem);

extern struct block_ref *new_block_ref(struct kmem_cache *ref_cachep);

extern struct sign_hash_elem *new_sign_hash_elem(struct kmem_cache *sign_cahcep);

extern void move_to(struct list_head *entry, struct list_head *new_prev);

extern void write_to_cache(int read_err, unsigned long write_err, void *context);

extern int choose_cacheblock(struct each_job *job, struct block_info **req_blk);

extern unsigned int init_hash_bucket(struct hash_bucket *bkt, 
		unsigned int size, hash_fun fn);

extern void free_hash_bucket(struct hash_bucket *bkt);

#endif
