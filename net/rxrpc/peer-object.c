/* RxRPC remote transport endpoint management
 *
 * Copyright (C) 2007, 2015 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include <net/ip.h>
#include <net/route.h>
#include "ar-internal.h"

static int rxrpc_peer_seq_show(struct seq_file *, void *);
static unsigned long rxrpc_peer_hash_key(const void *);
static int rxrpc_peer_cmp_key(const struct obj_node *, const void *);
static void rxrpc_peer_gc_rcu(struct rcu_head *);

static struct hlist_head rxrpc_peer_cache_hash[256];

struct objcache rxrpc_peer_cache = {
	.name		= "peers",
	.seq_show	= rxrpc_peer_seq_show,
	.gc_rcu		= rxrpc_peer_gc_rcu,
	.hash_key	= rxrpc_peer_hash_key,
	.cmp_key	= rxrpc_peer_cmp_key,
	.hash_table	= rxrpc_peer_cache_hash,
	.gc_delay	= 2,
	.nr_buckets	= ARRAY_SIZE(rxrpc_peer_cache_hash),
};

/*
 * Destroy a peer after the RCU grace period expires.
 */
static void rxrpc_peer_gc_rcu(struct rcu_head *rcu)
{
	struct rxrpc_peer *peer = container_of(rcu, struct rxrpc_peer, obj.rcu);

	_enter("%d", peer->debug_id);

	_net("DESTROY PEER %d", peer->debug_id);

	ASSERT(list_empty(&peer->error_targets));

	kfree(peer);

	objcache_obj_rcu_done(&rxrpc_peer_cache);
}

/*
 * Hash a peer key.
 */
static unsigned long rxrpc_peer_hash_key(const void *_srx)
{
	const struct sockaddr_rxrpc *srx = _srx;
	const u16 *p;
	unsigned int i, size;
	unsigned long hash_key;

	_enter("");

	hash_key = srx->transport_type;
	hash_key += srx->transport_len;
	hash_key += srx->transport.family;

	switch (srx->transport.family) {
	case AF_INET:
		hash_key += (u16 __force)srx->transport.sin.sin_port;
		size = sizeof(srx->transport.sin.sin_addr);
		p = (u16 *)&srx->transport.sin.sin_addr;
		break;
	}

	/* Step through the peer address in 16-bit portions for speed */
	for (i = 0; i < size; i += sizeof(*p), p++)
		hash_key += *p;

	_leave(" 0x%lx", hash_key);
	return hash_key;
}

/*
 * Compare a peer to a key.  Return -ve, 0 or +ve to indicate less than, same
 * or greater than.
 */
static int rxrpc_peer_cmp_key(const struct obj_node *obj, const void *_srx)
{
	const struct rxrpc_peer *peer =
		container_of(obj, struct rxrpc_peer, obj);
	const struct sockaddr_rxrpc *srx = _srx;
	int diff;

	diff = ((peer->srx.transport_type - srx->transport_type) ?:
		(peer->srx.transport_len - srx->transport_len) ?:
		(peer->srx.transport.family - srx->transport.family));
	if (diff != 0)
		return diff;

	switch (srx->transport.family) {
	case AF_INET:
		return ((u16 __force)peer->srx.transport.sin.sin_port -
			(u16 __force)srx->transport.sin.sin_port) ?:
			memcmp(&peer->srx.transport.sin.sin_addr,
			       &srx->transport.sin.sin_addr,
			       sizeof(struct in_addr));
	default:
		BUG();
	}
}

/*
 * Look up a remote transport endpoint for the specified address using RCU.
 */
struct rxrpc_peer *rxrpc_lookup_peer_rcu(const struct sockaddr_rxrpc *srx)
{
	struct rxrpc_peer *peer;
	struct obj_node *obj;

	obj = objcache_lookup_rcu(&rxrpc_peer_cache, srx);
	if (!obj)
		return NULL;

	peer = container_of(obj, struct rxrpc_peer, obj);
	switch (srx->transport.family) {
	case AF_INET:
		_net("PEER %d {%d,%u,%pI4+%hu}",
		     peer->debug_id,
		     peer->srx.transport_type,
		     peer->srx.transport.family,
		     &peer->srx.transport.sin.sin_addr,
		     ntohs(peer->srx.transport.sin.sin_port));
		break;
	}

	_leave(" = %p {u=%d}", peer, atomic_read(&peer->obj.usage));
	return peer;
}

/*
 * assess the MTU size for the network interface through which this peer is
 * reached
 */
static void rxrpc_assess_MTU_size(struct rxrpc_peer *peer)
{
	struct rtable *rt;
	struct flowi4 fl4;

	peer->if_mtu = 1500;

	rt = ip_route_output_ports(&init_net, &fl4, NULL,
				   peer->srx.transport.sin.sin_addr.s_addr, 0,
				   htons(7000), htons(7001),
				   IPPROTO_UDP, 0, 0);
	if (IS_ERR(rt)) {
		_leave(" [route err %ld]", PTR_ERR(rt));
		return;
	}

	peer->if_mtu = dst_mtu(&rt->dst);
	dst_release(&rt->dst);

	_leave(" [if_mtu %u]", peer->if_mtu);
}

/*
 * allocate a new peer
 */
static struct rxrpc_peer *rxrpc_alloc_peer(struct sockaddr_rxrpc *srx,
					   gfp_t gfp)
{
	struct rxrpc_peer *peer;

	_enter("");

	peer = kzalloc(sizeof(struct rxrpc_peer), gfp);
	if (peer) {
		INIT_LIST_HEAD(&peer->error_targets);
		spin_lock_init(&peer->lock);
		peer->debug_id = atomic_inc_return(&rxrpc_debug_id);
		memcpy(&peer->srx, srx, sizeof(*srx));

		rxrpc_assess_MTU_size(peer);
		peer->mtu = peer->if_mtu;

		if (srx->transport.family == AF_INET) {
			peer->hdrsize = sizeof(struct iphdr);
			switch (srx->transport_type) {
			case SOCK_DGRAM:
				peer->hdrsize += sizeof(struct udphdr);
				break;
			default:
				BUG();
				break;
			}
		} else {
			BUG();
		}

		peer->hdrsize += sizeof(struct rxrpc_wire_header);
		peer->maxdata = peer->mtu - peer->hdrsize;
	}

	_leave(" = %p", peer);
	return peer;
}

/*
 * obtain a remote transport endpoint for the specified address
 */
struct rxrpc_peer *rxrpc_lookup_peer(struct sockaddr_rxrpc *srx, gfp_t gfp)
{
	struct rxrpc_peer *peer, *candidate;
	struct obj_node *obj;
	int usage;

	_enter("{%d,%d,%pI4+%hu}",
	       srx->transport_type,
	       srx->transport_len,
	       &srx->transport.sin.sin_addr,
	       ntohs(srx->transport.sin.sin_port));

	/* search the peer list first */
	rcu_read_lock();
	peer = rxrpc_lookup_peer_rcu(srx);
	if (peer && !rxrpc_get_peer_maybe(peer))
		peer = NULL;
	rcu_read_unlock();

	if (!peer) {
		/* The peer is not yet present in cache - create a candidate
		 * for a new record and then redo the search.
		 */
		candidate = rxrpc_alloc_peer(srx, gfp);
		if (!candidate) {
			_leave(" = NULL [nomem]");
			return NULL;
		}

		obj = objcache_try_add(&rxrpc_peer_cache, &candidate->obj,
				       &candidate->srx);
		peer = container_of(obj, struct rxrpc_peer, obj);

		if (peer != candidate)
			kfree(candidate);
	}

	_net("PEER %d {%d,%pI4+%hu}",
	     peer->debug_id,
	     peer->srx.transport_type,
	     &peer->srx.transport.sin.sin_addr,
	     ntohs(peer->srx.transport.sin.sin_port));

	_leave(" = %p {u=%d}", peer, usage);
	return peer;
}

/*
 * Display a remote endpoint in /proc/net/rxrpc_peers.
 */
static int rxrpc_peer_seq_show(struct seq_file *seq, void *v)
{
	struct rxrpc_peer *peer;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "Use SvID Proto MTU   RTT   RPort Remote\n");
		return 0;
	}

	peer = hlist_entry(v, struct rxrpc_peer, obj.link);

	switch (peer->srx.transport.family) {
	case AF_INET:
		seq_printf(seq,
			   "%3d %4x UDP   %5u %5lu %5hu %pI4\n",
			   atomic_read(&peer->obj.usage),
			   peer->srx.srx_service,
			   peer->mtu,
			   peer->rtt,
			   ntohs(peer->srx.transport.sin.sin_port),
			   &peer->srx.transport.sin.sin_addr);
		break;
	}

	return 0;
}
