/* Common object cache definitions
 *
 * Copyright (C) 2015 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _OBJCACHE_H
#define _OBJCACHE_H

#include <linux/rculist.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/seq_file.h>

struct seq_file;

struct obj_node {
	union {
		struct rcu_head		rcu;
		struct list_head	gc_link;
	};
	struct hlist_node	link;
	struct hlist_node	link_2;
	unsigned long		full_hash_key;
	time64_t		put_timestamp;
	atomic_t		usage;
};

struct objcache {
	/* Parameters that must be set before initialisation */
	const char		*name;
	void (*prepare_for_gc)(struct obj_node *);
	void (*gc_rcu)(struct rcu_head *);

	unsigned long (*hash_key)(const void *);
	int (*cmp_key)(const struct obj_node *, const void *);
	struct hlist_head	*hash_table;
	unsigned		gc_delay;
	u16			nr_buckets;

	/* Secondary hash parameters if we want one - also must be set before
	 * initialisation.  Note that the secondary hash doesn't store its full
	 * hash key in the obj_node struct.
	 */
	u16			nr_buckets_2;
	struct hlist_head	*hash_table_2;
	unsigned long (*hash_key_2)(const void *);
	int (*cmp_key_2)(const struct obj_node *, const void *);

	/* If the cache should be visible through /proc, the following
	 * should be implemented.
	 */
	int (*seq_show)(struct seq_file *, void *);

	/* Internal data */
	spinlock_t		lock;
	atomic_t		count;
	u8			shift;
	u8			shift_2;
	bool			gc_needed;
	bool			gc_clear_all;
	struct work_struct	gc_work;
	struct timer_list	gc_timer;
	time64_t		gc_next_run;
	unsigned		gc_bucket;
	unsigned		gc_last_bucket;
	struct seq_operations	seq_ops;
};

static inline bool objcache_get_maybe(struct obj_node *obj)
{
	return atomic_inc_not_zero(&obj->usage);
}

static inline void objcache_get(struct obj_node *obj)
{
	atomic_inc(&obj->usage);
}

extern void objcache_init(struct objcache *);
extern struct obj_node *objcache_try_add(struct objcache *, struct obj_node *, const void *);
extern struct obj_node *objcache_lookup_rcu(struct objcache *, const void *);
extern bool objcache_add_2(struct objcache *, struct obj_node *, const void *, bool);
extern void objcache_del_2(struct objcache *, struct obj_node *);
extern struct obj_node *objcache_lookup_rcu_2(struct objcache *, const void *);
extern void objcache_put(struct objcache *, struct obj_node *);
extern void objcache_obj_rcu_done(struct objcache *);
extern void objcache_clear(struct objcache *);

extern const struct file_operations objcache_seq_fops;

#endif /* _OBJCACHE_H */
