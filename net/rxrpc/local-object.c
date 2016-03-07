/* Local endpoint object management
 *
 * Copyright (C) 2015 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include "ar-internal.h"

static void rxrpc_local_prepare_for_gc(struct obj_node *);
static void rxrpc_local_gc_rcu(struct rcu_head *);
static unsigned long rxrpc_local_hash_key(const void *);
static int rxrpc_local_cmp_key(const struct obj_node *, const void *);

static DEFINE_MUTEX(rxrpc_local_mutex);
static struct hlist_head rxrpc_local_cache_hash[16];

struct objcache rxrpc_local_cache = {
	.name		= "locals",
	.prepare_for_gc	= rxrpc_local_prepare_for_gc,
	.gc_rcu		= rxrpc_local_gc_rcu,
	.hash_key	= rxrpc_local_hash_key,
	.cmp_key	= rxrpc_local_cmp_key,
	.hash_table	= rxrpc_local_cache_hash,
	.gc_delay	= 2,
	.nr_buckets	= ARRAY_SIZE(rxrpc_local_cache_hash),
};

/*
 * Hash a local key.
 */
static unsigned long rxrpc_local_hash_key(const void *_srx)
{
	const struct sockaddr_rxrpc *srx = _srx;
	const u16 *p;
	unsigned int i, size;
	unsigned long hash_key;

	_enter("%u", srx->transport.family);

	hash_key = srx->transport_type;
	hash_key += srx->transport_len;
	hash_key += srx->transport.family;

	switch (srx->transport.family) {
	case AF_INET:
		hash_key += (u16 __force)srx->transport.sin.sin_port;
		size = sizeof(srx->transport.sin.sin_addr);
		p = (u16 *)&srx->transport.sin.sin_addr;
		break;
	default:
		BUG();
	}

	/* Step through the local address in 16-bit portions for speed */
	for (i = 0; i < size; i += sizeof(*p), p++)
		hash_key += *p;

	_leave(" = 0x%lx", hash_key);
	return hash_key;
}

/*
 * Compare a local to a key.  Return -ve, 0 or +ve to indicate less than, same
 * or greater than.
 */
static int rxrpc_local_cmp_key(const struct obj_node *obj, const void *_srx)
{
	const struct rxrpc_local *local =
		container_of(obj, struct rxrpc_local, obj);
	const struct sockaddr_rxrpc *srx = _srx;
	int diff;

	diff = ((local->srx.transport_type - srx->transport_type) ?:
		(local->srx.transport_len - srx->transport_len) ?:
		(local->srx.transport.family - srx->transport.family));
	if (diff != 0)
		return diff;

	switch (srx->transport.family) {
	case AF_INET:
		/* If the choice of UDP port is left up to the transport, then
		 * the endpoint record doesn't match.
		 */
		return ((u16 __force)local->srx.transport.sin.sin_port -
			(u16 __force)srx->transport.sin.sin_port) ?:
			memcmp(&local->srx.transport.sin.sin_addr,
			       &srx->transport.sin.sin_addr,
			       sizeof(struct in_addr));
	default:
		BUG();
	}
}

/*
 * Allocate a new local endpoint.  This is service ID independent but rather
 * defines a specific transport endpoint.
 */
static struct rxrpc_local *rxrpc_alloc_local(struct sockaddr_rxrpc *srx)
{
	struct rxrpc_local *local;

	local = kzalloc(sizeof(struct rxrpc_local), GFP_KERNEL);
	if (local) {
		INIT_WORK(&local->acceptor, &rxrpc_accept_incoming_calls);
		INIT_WORK(&local->rejecter, &rxrpc_reject_packets);
		INIT_WORK(&local->processor, &rxrpc_process_local_events);
		INIT_LIST_HEAD(&local->services);
		init_rwsem(&local->defrag_sem);
		skb_queue_head_init(&local->accept_queue);
		skb_queue_head_init(&local->reject_queue);
		skb_queue_head_init(&local->event_queue);
		mutex_init(&local->conn_lock);
		spin_lock_init(&local->lock);
		rwlock_init(&local->services_lock);
		local->debug_id = atomic_inc_return(&rxrpc_debug_id);
		memcpy(&local->srx, srx, sizeof(*srx));
		local->srx.srx_service = 0;
	}

	_leave(" = %p", local);
	return local;
}

/*
 * create the local socket
 * - must be called with rxrpc_local_mutex locked
 */
static int rxrpc_open_socket(struct rxrpc_local *local)
{
	struct sock *sock;
	int ret, opt;

	_enter("%p{%d}", local, local->srx.transport_type);

	/* create a socket to represent the local endpoint */
	ret = sock_create_kern(&init_net, PF_INET, local->srx.transport_type,
			       IPPROTO_UDP, &local->socket);
	if (ret < 0) {
		_leave(" = %d [socket]", ret);
		return ret;
	}

	/* if a local address was supplied then bind it */
	if (local->srx.transport_len > sizeof(sa_family_t)) {
		_debug("bind");
		ret = kernel_bind(local->socket,
				  (struct sockaddr *)&local->srx.transport,
				  local->srx.transport_len);
		if (ret < 0) {
			_debug("bind failed %d", ret);
			goto error;
		}
	}

	/* we want to receive ICMP errors */
	opt = 1;
	ret = kernel_setsockopt(local->socket, SOL_IP, IP_RECVERR,
				(char *) &opt, sizeof(opt));
	if (ret < 0) {
		_debug("setsockopt failed");
		goto error;
	}

	/* we want to set the don't fragment bit */
	opt = IP_PMTUDISC_DO;
	ret = kernel_setsockopt(local->socket, SOL_IP, IP_MTU_DISCOVER,
				(char *) &opt, sizeof(opt));
	if (ret < 0) {
		_debug("setsockopt failed");
		goto error;
	}

	/* set the socket up */
	sock = local->socket->sk;
	sock->sk_user_data	= local;
	sock->sk_data_ready	= rxrpc_data_ready;
	sock->sk_error_report	= rxrpc_UDP_error_report;
	_leave(" = 0");
	return 0;

error:
	kernel_sock_shutdown(local->socket, SHUT_RDWR);
	local->socket->sk->sk_user_data = NULL;
	sock_release(local->socket);
	local->socket = NULL;

	_leave(" = %d", ret);
	return ret;
}

/*
 * Look up or create a new local endpoint using the specified address.
 */
struct rxrpc_local *rxrpc_lookup_local(struct sockaddr_rxrpc *srx)
{
	struct rxrpc_local *local;
	struct obj_node *obj;
	const char *new;
	int ret;

	if (srx->transport.family == AF_INET) {
		_enter("{%d,%u,%pI4+%hu}",
		       srx->transport_type,
		       srx->transport.family,
		       &srx->transport.sin.sin_addr,
		       ntohs(srx->transport.sin.sin_port));
	} else {
		_enter("{%d,%u}",
		       srx->transport_type,
		       srx->transport.family);
		return ERR_PTR(-EAFNOSUPPORT);
	}

	mutex_lock(&rxrpc_local_mutex);

	obj = objcache_lookup_rcu(&rxrpc_local_cache, srx);
	if (obj && objcache_get_maybe(obj)) {
		local = container_of(obj, struct rxrpc_local, obj);
		new = "old";
	} else {
		local = rxrpc_alloc_local(srx);
		if (!local)
			goto nomem;

		ret = rxrpc_open_socket(local);
		if (ret < 0)
			goto sock_error;

		obj = objcache_try_add(&rxrpc_local_cache, &local->obj,
				       &local->srx);
		BUG_ON(obj != &local->obj);
		new = "new";
	}

	mutex_unlock(&rxrpc_local_mutex);

	_net("LOCAL %s %d {%d,%u,%pI4+%hu}",
	     new,
	     local->debug_id,
	     local->srx.transport_type,
	     local->srx.transport.family,
	     &local->srx.transport.sin.sin_addr,
	     ntohs(local->srx.transport.sin.sin_port));

	_leave(" = %p [new]", local);
	return local;

nomem:
	ret = -ENOMEM;
sock_error:
	mutex_unlock(&rxrpc_local_mutex);
	kfree(local);
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*
 * Prepare to garbage collect local endpoints.  Closing the socket cannot be
 * done from an RCU callback context because it might sleep.
 */
static void rxrpc_local_prepare_for_gc(struct obj_node *obj)
{
	struct rxrpc_local *local = container_of(obj, struct rxrpc_local, obj);
	struct socket *socket = local->socket;

	if (socket) {
		local->socket = NULL;
		kernel_sock_shutdown(socket, SHUT_RDWR);
		socket->sk->sk_user_data = NULL;
		sock_release(socket);
	}
}

/*
 * Destroy a local endpoint after the RCU grace period expires.
 */
static void rxrpc_local_gc_rcu(struct rcu_head *rcu)
{
	struct rxrpc_local *local = container_of(rcu, struct rxrpc_local, obj.rcu);

	_enter("%p", local);

	ASSERT(list_empty(&local->services));
	ASSERT(!work_pending(&local->acceptor));
	ASSERT(!work_pending(&local->rejecter));
	ASSERT(!work_pending(&local->processor));

	/* finish cleaning up the local descriptor */
	rxrpc_purge_queue(&local->accept_queue);
	rxrpc_purge_queue(&local->reject_queue);
	rxrpc_purge_queue(&local->event_queue);

	_net("DESTROY LOCAL %d", local->debug_id);
	kfree(local);

	objcache_obj_rcu_done(&rxrpc_local_cache);
	_leave("");
}
