#include <linux/kobject.h>
#include <linux/sysfs.h>
#include "sys.h"

#define L_CACHE_ATTR_RO(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)


#define L_CACHE_ATTR_FUN(_name, value) \
	static ssize_t _name##_show(struct kobject *kobj, \
			struct kobj_attribute *attr, char *buf) \
	{ \
		if (!ctx_ctrl) { \
			return 0; \
		} \
		return sprintf(buf, "%lu\n", ctx_ctrl->stats.value); \
	}

// reads
L_CACHE_ATTR_FUN(reads, reads)
L_CACHE_ATTR_RO(reads);

// writes 
L_CACHE_ATTR_FUN(writes, writes)
L_CACHE_ATTR_RO(writes);

// aht_hits 
L_CACHE_ATTR_FUN(aht_hits, aht_hits)
L_CACHE_ATTR_RO(aht_hits);

// aht_miss 
L_CACHE_ATTR_FUN(aht_miss, aht_miss)
L_CACHE_ATTR_RO(aht_miss);

// sht_hits 
L_CACHE_ATTR_FUN(sht_hits, sht_hits)
L_CACHE_ATTR_RO(sht_hits);

// sht_miss 
L_CACHE_ATTR_FUN(sht_miss, sht_miss)
L_CACHE_ATTR_RO(sht_miss);

// replace 
L_CACHE_ATTR_FUN(replace, replace)
L_CACHE_ATTR_RO(replace);

// writeback 
L_CACHE_ATTR_FUN(writeback, writeback)
L_CACHE_ATTR_RO(writeback);

// cache_size 
L_CACHE_ATTR_FUN(cache_size, cache_size)
L_CACHE_ATTR_RO(cache_size);

// blk_size 
L_CACHE_ATTR_FUN(blk_size, blk_size)
L_CACHE_ATTR_RO(blk_size);

// blk_bits
L_CACHE_ATTR_FUN(blk_bits, blk_bits)
L_CACHE_ATTR_RO(blk_bits);

// blk_mask
L_CACHE_ATTR_FUN(blk_mask, blk_mask)
L_CACHE_ATTR_RO(blk_mask);

static char stats_name[][16] = {
        "reads", "writes", "aht_hits", "aht_miss",
        "sht_hits", "sht_miss", "replace", "writeback",
        "cache_size", "blk_size", "blk_bits", "blk_mask"
};

// all attributes
static ssize_t all_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	ssize_t res = 0;
	unsigned long *elem;
	unsigned int index = 0;
	if (!ctx_ctrl) {
		return 0;
	}
	elem = &(ctx_ctrl->stats.reads);
	do {
		res += sprintf(buf+res, "%s : %lu\n", stats_name[index], *elem);
		++elem;
		++index;
	} while (index < (sizeof(struct cache_stats)/sizeof(unsigned long)));
	return res;
}
L_CACHE_ATTR_RO(all);

static struct attribute *cache_attrs[] = {
	&reads_attr.attr,
	&writes_attr.attr,
	&aht_hits_attr.attr,
	&aht_miss_attr.attr,
	&sht_hits_attr.attr,
	&sht_miss_attr.attr,
	&replace_attr.attr,
	&writeback_attr.attr,
	&cache_size_attr.attr,
	&blk_size_attr.attr,
	&blk_bits_attr.attr,
	&blk_mask_attr.attr,
	&all_attr.attr,
	NULL,
};

static struct attribute_group cache_attr_group = {
	.attrs = cache_attrs,
	.name = "stats",
};

struct kobject *l_cache_kobj;

int sys_stats_init(void)
{
	int err;

	l_cache_kobj = kobject_create_and_add("l_cache", kernel_kobj);
	if (!l_cache_kobj) {
		printk("L-CACHE : l_cache_kobj create failed!\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(l_cache_kobj, &cache_attr_group);
	if(err) {
		printk("L-CACHE : cache_attr_group create failed!\n");
		return err;
	}
	
	return 0;
}

void sys_stats_del(void)
{
	sysfs_remove_group(l_cache_kobj, &cache_attr_group);
	kobject_put(l_cache_kobj);
}
