#include "blk_hash.h"

unsigned long sample_addr_hash(void *data)
{
	unsigned long no = *(unsigned long *)data;
	return no % _ADDR_HASH_MOD;
}

unsigned long sample_sign_hash(void *data)
{
        unsigned char *sign = (unsigned char *)data;
        unsigned long val = sign[7];
        return val % _SIGN_HASH_MOD;
}

/*
* find_bucket_elem
* return NULL if failed
*/
struct bucket_elem *find_bucket_elem(struct hash_bucket *bkt, void *data)
{
	unsigned long index;

	if (!bkt || !bkt->bkt_arr || !bkt->hash_fn) {
		goto bad;
	}
	index = bkt->hash_fn(data);
	if (index >= bkt->size) {
		goto bad;
	}

	return bkt->bkt_arr+index;
bad:
	return NULL;
}

/*
* find address_hash_atble
* return the pointer to the corresponding bucket_elem obj
* @ref : if HIT hold the pointer to the matched block_ref
*/
struct bucket_elem *find_aht(struct hash_bucket *bkt, sector_t sect, 
			struct block_ref **ref)
{
	struct bucket_elem *elem;
	struct list_head *pos;
	struct block_ref *tmp;

	elem = find_bucket_elem(bkt, &sect);
	if (!elem) {
		goto out;
	}
	*ref = NULL;	// if this is NULL, means AHT MISS
	spin_lock(&elem->lock);
	list_for_each(pos, &elem->hash_elems) {
		tmp = container_of(pos, struct block_ref, hash_list);
		if (!tmp) {
			continue;
		}
		if (tmp->src_sector == sect) { // AHT HIT
			*ref = tmp;
			break;
		}
	}
	spin_unlock(&elem->lock);

out:
	return elem;
}

/*
* find signature_hash_atble
* return the pointer to the corresponding bucket_elem obj
* @sign_elem : if HIT hold the pointer to the matched sign_hash_elem
*/
struct bucket_elem *find_sht(struct hash_bucket *bkt, unsigned char *data, 
			struct sign_hash_elem **sign_elem)
{
	struct bucket_elem *elem;
	struct list_head *pos;
	struct sign_hash_elem *tmp;

	elem = find_bucket_elem(bkt, data);
	if (!elem) {
		goto out;
	}
	*sign_elem = NULL;	// if this is NULL, means SHT MISS
	spin_lock(&elem->lock);
	list_for_each(pos, &elem->hash_elems) {
		tmp = container_of(pos, struct sign_hash_elem, list);
		if (!tmp) {
			continue;
		}
                BUG_ON(!tmp->blk);
		if (!memcmp(data, tmp->blk->signature, _MD5_LEN)) { // SHT HIT
			*sign_elem = tmp;
			break;
		}
	}
	spin_unlock(&elem->lock);

out:
	return elem;
}

struct sign_hash_elem *new_sign_hash_elem(struct kmem_cache *sign_cahcep)
{
        struct sign_hash_elem *elem;
        elem = kmem_cache_alloc(sign_cahcep, GFP_ATOMIC);
        if (!elem) {
                return NULL;
        }
        elem->blk = NULL;
        INIT_LIST_HEAD(&elem->list);
        return elem;
}

/*
* init hash bucket
* return 0 if success
*/
unsigned int init_hash_bucket(struct hash_bucket *bkt, 
		unsigned int size, hash_fun fn)
{
	unsigned int index;

	bkt->size = size;
	bkt->hash_fn = fn;
	bkt->bkt_arr = (struct bucket_elem *)vmalloc(size * sizeof(struct bucket_elem));
	if (!bkt->bkt_arr) {
		goto bad1;
	}
	for(index=0; index < size; ++index) {
		spin_lock_init(&(bkt->bkt_arr[index].lock));
		INIT_LIST_HEAD(&(bkt->bkt_arr[index].hash_elems));
		bkt->bkt_arr[index].nr = 0;
	}

	return 0;
bad1:
	return 1;
}

void free_hash_bucket(struct hash_bucket *bkt)
{
	if (bkt) {
		vfree(bkt->bkt_arr);
	}
}
