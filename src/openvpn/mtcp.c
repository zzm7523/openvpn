/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if P2MP_SERVER

#include "gremlin.h"
#include "socket.h"
#include "packet_buffer.h"
#include "socket-inline.h"
#include "crypto.h"
#include "thread.h"
#include "multi_crypto.h"
#include "multi.h"
#include "tun-inline.h"
#include "forward-inline.h"

#include "memdbg.h"

/* TCP States */
#define TA_UNDEF                 0
#define TA_SOCKET_READ           1
#define TA_SOCKET_WRITE          2
#define TA_TUN_READ              3
#define TA_TUN_WRITE             4
#define TA_INITIAL               5
#define TA_TIMEOUT               6

/* Special tags passed to event.[ch] functions */
#define MTCP_SOCKET      ((void*)1)
#define MTCP_TUN         ((void*)2)
#define MTCP_SIG         ((void*)3) /* Only on Windows */
#ifdef ENABLE_MANAGEMENT
# define MTCP_MANAGEMENT ((void*)4)
#endif

#define MTCP_N           ((void*)16) /* upper bound on MTCP_x */

static const char *
pract (int action)
{
	switch (action)
	{
	case TA_UNDEF:
		return "TA_UNDEF";
	case TA_SOCKET_READ:
		return "TA_SOCKET_READ";
	case TA_SOCKET_WRITE:
		return "TA_SOCKET_WRITE";
	case TA_TUN_READ:
		return "TA_TUN_READ";
	case TA_TUN_WRITE:
		return "TA_TUN_WRITE";
	case TA_INITIAL:
		return "TA_INITIAL";
	case TA_TIMEOUT:
		return "TA_TIMEOUT";
	default:
		return "?";
	}
}

static struct multi_instance *
multi_create_instance_tcp (struct multi_context *m)
{
	struct gc_arena gc = gc_new ();
	struct multi_instance *mi = NULL;
	struct hash *hash = m->hash;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	mi = multi_create_instance (m, NULL);
	if (mi)
	{
		struct hash_element *he;
		const uint32_t hv = hash_value (hash, &mi->real);
		struct hash_bucket *bucket = hash_bucket (hash, hv);

		he = hash_lookup_fast (hash, bucket, &mi->real, hv);

		if (he)
		{
			struct multi_instance *oldmi = (struct multi_instance *) he->value;
			msg (D_MULTI_LOW, "MULTI TCP: new incoming client address matches existing client address -- new client takes precedence");
			oldmi->did_real_hash = false;
			multi_close_instance (m, oldmi, false);
			he->key = &mi->real;
			he->value = mi;
		}
		else
			hash_add_fast (hash, bucket, &mi->real, hv, mi);

		mi->did_real_hash = true;
	}

#ifdef ENABLE_DEBUG
	if (mi)
		dmsg (D_MULTI_DEBUG, "MULTI TCP: instance added: %s", mroute_addr_print (&mi->real, &gc));
	else
		dmsg (D_MULTI_DEBUG, "MULTI TCP: new client instance failed");
#endif

	gc_free (&gc);
	return mi;
}

bool
multi_tcp_instance_specific_init (struct multi_context *m, struct multi_instance *mi)
{
	ASSERT (mi->context.c2.link_socket && mi->context.c2.link_socket->info.lsa);
	ASSERT (mi->context.c2.link_socket->mode == LS_MODE_TCP_ACCEPT_FROM);
	ASSERT (mi->context.c2.link_socket->info.lsa->actual.dest.addr.sa.sa_family == AF_INET
		|| mi->context.c2.link_socket->info.lsa->actual.dest.addr.sa.sa_family == AF_INET6
		);

	if (!mroute_extract_openvpn_sockaddr (&mi->real, &mi->context.c2.link_socket->info.lsa->actual.dest, true))
	{
		msg (D_MULTI_ERRORS, "MULTI TCP: TCP client address is undefined");
		return false;
	}
	return true;
}

void
multi_tcp_instance_specific_free (struct multi_instance *mi)
{
}

struct multi_tcp *
multi_tcp_init (int maxevents, int *maxclients)
{
	struct multi_tcp *mtcp;
	const int extra_events = BASE_N_EVENTS;

	ASSERT (maxevents >= 1);
	ASSERT (maxclients);

	ALLOC_OBJ_CLEAR (mtcp, struct multi_tcp);
	mtcp->maxevents = maxevents + extra_events;
	mtcp->es = event_set_init (&mtcp->maxevents, 0);
	wait_signal (mtcp->es, MTCP_SIG);
	ALLOC_ARRAY (mtcp->esr, struct event_set_return, mtcp->maxevents);
	*maxclients = max_int (min_int (mtcp->maxevents - extra_events, *maxclients), 1);

	msg (D_MULTI_LOW, "MULTI: TCP INIT maxclients=%d maxevents=%d", *maxclients, mtcp->maxevents);

	return mtcp;
}

void
multi_tcp_delete_event (struct multi_tcp *mtcp, event_t event)
{
	if (mtcp && mtcp->es)
		event_del (mtcp->es, event);
}

void
multi_tcp_free (struct multi_tcp *mtcp)
{
	if (mtcp)
	{
		event_free (mtcp->es);
		if (mtcp->esr)
			free (mtcp->esr);
		free (mtcp);
	}
}

void
multi_tcp_dereference_instance (struct multi_tcp *mtcp, struct multi_instance *mi)
{
	struct link_socket *ls = mi->context.c2.link_socket;

	if (ls && mi->socket_set_called)
		event_del (mtcp->es, socket_event_handle (ls));
	mtcp->n_esr = 0;
}

static inline void
multi_tcp_set_global_rw_flags (struct multi_context *m, struct multi_instance *mi)
{
	if (mi)
	{
		/* 不管有没有link读缓存, 总是监听链路读 (必要时新建临时缓存) */
		unsigned int rwflags = EVENT_READ;

		if (LINK_OUT (&mi->context))
			rwflags |= EVENT_WRITE;
		mi->socket_set_called = true;
		socket_set (mi->context.c2.link_socket, m->mtcp->es, rwflags, mi, &mi->tcp_rwflags);
	}
}

static inline int
multi_tcp_wait (struct multi_context *m, struct multi_tcp *mtcp)
{
	struct context *c = &m->top;
	int status = 0;
	bool wakeup = false;

	socket_set_listen_persistent (c->c2.link_socket, mtcp->es, MTCP_SOCKET);

	/* 不管有没有link读缓存, 总是监听链路读 (必要时新建临时缓存) */
	prepare_process_link_any_incoming (c); /* from link */

	/* 更新链路监听事件集 */
	if (m->to_link_pendings->size != 0)
	{
		struct multi_instance *mi;

		MUTEX_LOCK (&m->to_link_pendings_mutex, MAIN_THREAD_INDEX, S_TO_LINK_PENDINGS);
		while ((mi = multi_instance_list_pop_front (m->to_link_pendings)))
		{
			if (!IS_SIG (&mi->context) && !mi->halt)
				multi_tcp_set_global_rw_flags (m, mi);
		}
		MUTEX_UNLOCK (&m->to_link_pendings_mutex, MAIN_THREAD_INDEX, S_TO_LINK_PENDINGS);
	}

#ifndef ENABLE_TUN_THREAD
	/* 更新TUN设备监听事件集 */
	{
		unsigned int rwflags = 0;

		if (prepare_process_tun_any_incoming (c)) /* from tun */
			rwflags |= EVENT_READ;
		if (m->to_tun_pendings->size != 0)
			rwflags |= EVENT_WRITE;

		tun_set (c->c1.tuntap, mtcp->es, rwflags, MTCP_TUN, &mtcp->tun_rwflags);
	}
#endif

#ifdef ENABLE_MANAGEMENT
	if (management)
		management_socket_set (management, mtcp->es, MTCP_MANAGEMENT, &mtcp->management_persist_flags);
#endif

	status = event_wait (mtcp->es, &c->c2.timeval, mtcp->esr, mtcp->maxevents, &wakeup);
	update_time (MAIN_THREAD_INDEX);
	mtcp->n_esr = status > 0 ? status : 0;
	return status;
}

static inline int
do_process_link_server_tcp_read (struct multi_context *m, struct multi_instance *mi, unsigned int mpp_flags)
{
	struct multi_instance_list *work_pendings = g_link_transfer_context->work_pendings;
	struct packet_buffer_list *read_work_bufs = g_link_transfer_context->read_work_bufs;
	struct packet_buffer *buf = NULL;
	unsigned int flags = 0;
	int counter = 0, status = 0;

	ASSERT (mi && mi->context.c2.link_socket);

	do {
		if ((buf = get_link_read_packet_buffer (&mi->context, true)))
		{
			if ((status = read_incoming_link (&mi->context, buf, flags)) <= 0)	/* 线路繁忙或异常, 没有读到包 */
			{
				packet_buffer_list_push_back (read_work_bufs, buf);
				break;
			}
			else
			{				
				++counter;
#ifdef TARGET_LINUX
				flags |= OVERLAPPED_READ_EMPTY_RETURN;
#endif
				if (!multi_process_incoming_link (m, mi, mpp_flags, buf))
					packet_buffer_list_push_back (read_work_bufs, buf);
			}
		}
		else
			ASSERT (0);	/* TCP要求一次性读完缓存的数据包 */

	} while (buf && status > 0 && !IS_SIG (&mi->context) && !stream_buf_read_setup (mi->context.c2.link_socket));

	ASSERT (status <= 0 || IS_SIG (&mi->context) || !mi->context.c2.link_socket->stream_buf.residual_fully_formed);

	if (work_pendings->size > 0)
		multi_post_process_link_incoming (m, counter, mpp_flags);

	return counter;	/* 返回总共读取的数据包数 */
}

static inline int
do_process_link_server_tcp_write (struct multi_context *m, struct multi_instance *mi, unsigned int mpp_flags)
{
	int counter = multi_process_outgoing_link (m, mi, mpp_flags);
	multi_process_post (m, mi, mpp_flags);
	return counter;
}

static inline void
multi_tcp_action (struct multi_context *m, struct multi_instance *mi, int action)
{
	const unsigned int mpp_flags = MPP_PRE_SELECT;

	dmsg (D_MULTI_DEBUG, "MULTI TCP: multi_tcp_action a=%s", pract (action));

	/* Dispatch the action */

	if (action == TA_SOCKET_READ)
		do_process_link_server_tcp_read (m, mi, mpp_flags);
	else if (action == TA_SOCKET_WRITE)
		do_process_link_server_tcp_write (m, mi, mpp_flags);
#ifndef ENABLE_TUN_THREAD
	else if (action == TA_TUN_READ)
		do_process_tun_server_read (m);
	else if (action == TA_TUN_WRITE)
		do_process_tun_server_write (m, mpp_flags);
#endif
	else if (action == TA_TIMEOUT)
		multi_process_timeout (m, mpp_flags);

	if (mi)
	{
		if (IS_SIG (&mi->context))
			multi_close_instance_on_signal (m, mi);
		else
			/* 更新链路监听事件集, 监听读时发布socket_recv_queue(...)调用 */
			multi_tcp_set_global_rw_flags (m, mi);
	}
}

static void
multi_tcp_process_io (struct multi_context *m)
{
	struct multi_tcp *mtcp = m->mtcp;
	struct multi_instance *mi = NULL;
	struct event_set_return *esr = NULL;
	int i;

	for (i = 0; i < mtcp->n_esr; ++i)
	{
		/* incoming data for instance? */
		esr = &mtcp->esr[i];
		if (esr->arg >= MTCP_N)
		{
			if ((mi = (struct multi_instance *) esr->arg))
			{
				if (esr->rwflags & EVENT_WRITE)
					multi_tcp_action (m, mi, TA_SOCKET_WRITE);
				if (esr->rwflags & EVENT_READ)
					multi_tcp_action (m, mi, TA_SOCKET_READ);
			}
		}
		else
		{
			/* new incoming TCP client attempting to connect? */
			if (esr->arg == MTCP_SOCKET)
			{
				ASSERT (m->top.c2.link_socket);
				socket_reset_listen_persistent (m->top.c2.link_socket);
				if ((mi = multi_create_instance_tcp (m)))
					multi_tcp_action (m, mi, TA_INITIAL);
			}
			/* signal received? */
			else if (esr->arg == MTCP_SIG)
			{
				get_signal (&m->top.sig->signal_received);
			}
#ifndef ENABLE_TUN_THREAD
			/* incoming data on TUN? */
			else if (esr->arg == MTCP_TUN)
			{
				if (esr->rwflags & EVENT_WRITE)
					multi_tcp_action (m, NULL, TA_TUN_WRITE);
				else if (esr->rwflags & EVENT_READ)
					multi_tcp_action (m, NULL, TA_TUN_READ);
			}
#endif
#ifdef ENABLE_MANAGEMENT
			else if (esr->arg == MTCP_MANAGEMENT)
			{
				ASSERT (management);
				management_io (management);
			}
#endif
		}

		if (IS_SIG (&m->top))
			break;
	}

	mtcp->n_esr = 0;
}

/* Top level event loop for multi-threaded operation. TCP mode. */
void
tunnel_server_tcp (struct context *top)
{
	struct multi_context m;
	int status;

	CLEAR (m);
	global_multi_context = &m;
	top->mode = CM_TOP;
	context_clear_2 (top);

	/* initialize top-tunnel instance */
	init_instance_handle_signals (top, top->es, CC_HARD_USR1_TO_HUP);
	if (IS_SIG (top))
		return;

	/* initialize global multi_context object */
	multi_init (&m, top, true);

	/* initialize our cloned top object */
	multi_top_init (&m, top, false);

	/* initialize management interface */
	init_management_callback_multi (&m);

	/* 初始化全局包处理缓存, 必须在初始化init_instance_handle_signals(...) 函数调用后 */
	global_variable_init (&m, top);

	/* finished with initialization */
	initialization_sequence_completed (top, ISC_SERVER); /* --mode server --proto tcp-server */

	/* per-packet event loop */
	while (true)
	{
		perf_push (PERF_EVENT_LOOP);

		/* wait on tun/socket list */
		multi_get_timeout (&m, &m.top.c2.timeval);
		status = multi_tcp_wait (&m, m.mtcp);
		MULTI_CHECK_SIG (&m);

		/* check on status of coarse timers */
		multi_process_per_second_timers (&m);

		/* timeout? */
		if (status > 0)
		{
			/* process the I/O which triggered select */
			multi_tcp_process_io (&m);
			MULTI_CHECK_SIG (&m);
		}
		else if (status == 0)
			multi_tcp_action (&m, NULL, TA_TIMEOUT);

		perf_pop ();
	}

#ifdef ENABLE_TUN_THREAD
	/* 停止TUN设备读写线程, 必须在multi_uninit(...)之前 */
	tun_thread_stop (g_tun_transfer_context);
#endif

	/* 停止工作线程组, 必须在close_instance(...)之前 */
	worker_threads_stop ();

	/* shut down management interface */
	uninit_management_callback_multi (&m);

	/* save ifconfig-pool */
	multi_ifconfig_pool_persist (&m, true);

	/* tear down tunnel instance (unless --persist-tun) */
	multi_uninit (&m);
	multi_top_free (&m);
	close_instance (top);

	/* 释放全局包处理缓存, 必须在close_instance(...)函数调用后 */
	global_variable_free ();

	global_multi_context = NULL;
}

#endif
