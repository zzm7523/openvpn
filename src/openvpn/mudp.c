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

/*
 * Get a client instance based on real address.  If
 * the instance doesn't exist, create it while
 * maintaining real address hash table atomicity.
 */

struct multi_instance *
multi_get_create_instance_udp (struct multi_context *m, struct packet_buffer *buf)
{
	struct gc_arena gc = gc_new ();
	struct mroute_addr real;
	struct multi_instance *mi = NULL;
	struct hash *hash = m->hash;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	if (mroute_extract_openvpn_sockaddr (&real, &buf->from.dest, true))
	{
		struct hash_element *he = NULL;
		uint32_t hv = hash_value (hash, &real);
		struct hash_bucket *bucket = hash_bucket (hash, hv);

		he = hash_lookup_fast (hash, bucket, &real, hv);

		if (he)
		{
			mi = (struct multi_instance *) he->value;
		}
		else
		{
			if (!m->top.c2.tls_auth_standalone
					|| tls_pre_decrypt_lite (m->top.c2.tls_auth_standalone, &buf->from, &buf->buf))
			{
				if (frequency_limit_event_allowed (m->new_connection_limiter))
				{
					mi = multi_create_instance (m, &real);
					if (mi)
					{
						hash_add_fast (hash, bucket, &mi->real, hv, mi);
						mi->did_real_hash = true;
					}
				}
				else
				{
					msg (D_MULTI_ERRORS,
						"MULTI: Connection from %s would exceed new connection frequency limit as controlled by --connect-freq",
						mroute_addr_print (&real, &gc));
				}
			}
		}

#ifdef ENABLE_DEBUG
		if (check_debug_level (D_MULTI_DEBUG))
		{
			const char *status;

			if (he && mi)
				status = "[succeeded]";
			else if (!he && mi)
				status = "[created]";
			else
				status = "[failed]";
			dmsg (D_MULTI_DEBUG, "GET INST BY REAL: %s %s", mroute_addr_print (&real, &gc), status);
		}
#endif
	}

	gc_free (&gc);
	return mi;
}

static inline int
do_process_link_server_udp_write (struct multi_context *m, unsigned int mpp_flags)
{
	int total_counter = 0, counter = 0;
	struct multi_instance *mi = NULL;

	do {
		MUTEX_LOCK (&m->to_link_pendings_mutex, MAIN_THREAD_INDEX, S_TO_LINK_PENDINGS);
		do {
			mi = multi_instance_list_pop_front (m->to_link_pendings);
		} while (mi && !mi->halt && !LINK_OUT (&mi->context));

		// 或许不能一次写完, 重新放入m->to_link_pendings 
		if (mi && !mi->halt)
			multi_instance_list_push_back (m->to_link_pendings, mi);
		MUTEX_UNLOCK (&m->to_link_pendings_mutex, MAIN_THREAD_INDEX, S_TO_LINK_PENDINGS);

		if (mi && !mi->halt)
		{		
			counter = multi_process_outgoing_link (m, mi, mpp_flags);
			total_counter += counter;
			multi_process_post (m, mi, mpp_flags);
		}
#ifdef TARGET_LINUX
		else if (proto_is_udp (m->top.c2.link_socket->info.proto))
		{
			if (m->top.options.sockflags & SF_USE_SENDMMSG)
				/* 刷新链路缓存的数据 */
				do_link_force_flush (&m->top);
		}
#endif

	} while (mi && counter > 0 && total_counter < MAX_LINK_BATCH_WRITE);
	
	return total_counter;	/* 返回总共写出的数据包数 */
}

static inline int
do_process_link_server_udp_read (struct multi_context *m, unsigned int mpp_flags)
{
	struct multi_instance_list *work_pendings = g_link_transfer_context->work_pendings;
	struct packet_buffer_list *read_work_bufs = g_link_transfer_context->read_work_bufs;
	struct packet_buffer *buf = NULL;
	unsigned int flags = 0;
	int counter = 0, status = 0;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	do {
		if ((buf = get_link_read_packet_buffer (&m->top, false)))
		{
			if ((status = read_incoming_link (&m->top, buf, flags)) <= 0) /* 线路繁忙或异常, 没有读到包 */
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
				if (!multi_process_incoming_link (m, NULL, mpp_flags, buf))
				{
					packet_buffer_list_push_back (read_work_bufs, buf);
					break;
				}
			}
		}

	} while (buf && status > 0 && counter < MAX_LINK_BATCH_READ && m->top.c2.link_socket && !IS_SIG (&m->top)); 

	if (work_pendings->size > 0)
		multi_post_process_link_incoming (m, counter, mpp_flags);
	
	return counter;	/* 返回总共读取的数据包数 */
}

/* Process an I/O event. */
static void
multi_process_io_udp (struct multi_context *m)
{
	const unsigned int mpp_flags = (MPP_PRE_SELECT|MPP_CLOSE_ON_SIGNAL);
	struct timeval *local_now = now_tv (MAIN_THREAD_INDEX);
	const unsigned int status0 = m->top.c2.event_set_status;
	unsigned int status1 = SOCKET_WRITE|SOCKET_READ|TUN_WRITE|TUN_READ;
	int io_loop = 0;

#ifdef MULTI_DEBUG_EVENT_LOOP
	char buf[16];
	buf[0] = 0;
	if (status0 & SOCKET_READ)
		strcat (buf, "SR/");
	else if (status0 & SOCKET_WRITE)
		strcat (buf, "SW/");
	else if (status0 & TUN_READ)
		strcat (buf, "TR/");
	else if (status0 & TUN_WRITE)
		strcat (buf, "TW/");
	printf ("IO %s\n", buf);
#endif

#ifdef ENABLE_MANAGEMENT
	if (status0 & (MANAGEMENT_READ|MANAGEMENT_WRITE))
	{
		ASSERT (management);
		management_io (management);
	}
#endif

	do {
		/* Incoming data on UDP port */
		if ((status0 & SOCKET_READ) && (status1 & SOCKET_READ))
		{
			if (do_process_link_server_udp_read (m, mpp_flags) <= 0)
				status1 &= ~SOCKET_READ;
		}

#ifndef ENABLE_TUN_THREAD
		/* Incoming data on TUN device */
		if ((status0 & TUN_READ) && (status1 & TUN_READ))
		{
			if (do_process_tun_server_read (m) <= 0)
				status1 &= ~TUN_READ;
		}
#endif

		/* UDP port ready to accept write */
		if ((status0 & SOCKET_WRITE) && (status1 & SOCKET_WRITE))
		{
			if (do_process_link_server_udp_write (m, mpp_flags) <= 0)
				status1 &= ~SOCKET_WRITE;
		}

#ifndef ENABLE_TUN_THREAD
		/* TUN device ready to accept write */
		if ((status0 & TUN_WRITE) && (status1 & TUN_WRITE))
		{
			if (do_process_tun_server_write (m, 0) <= 0)
				status1 &= ~TUN_WRITE;
		}
#endif

		if (status1 & SOCKET_READ)
		{
			if (prepare_process_link_any_incoming (&m->top) == 0)
				status1 &= ~SOCKET_READ;
		}

		if (status1 & SOCKET_WRITE)
		{
			if (prepare_process_link_server_outgoing (m) == 0)
				status1 &= ~SOCKET_WRITE;
		}

#ifndef ENABLE_TUN_THREAD
		if (status1 & TUN_READ)
		{
			if (prepare_process_tun_any_incoming (&m->top) == 0)
				status1 &= ~TUN_READ;
		}

		if (status1 & TUN_WRITE)
		{
			if (prepare_process_tun_server_outgoing (m) == 0)
				status1 &= ~TUN_WRITE;
		}
#endif

	} while (status1 != 0 && ++io_loop < MAX_PROCESS_IO_LOOP);
}

/*
 * Return the io_wait() flags appropriate for a point-to-multipoint tunnel.
 */
static inline unsigned int
p2mp_iow_flags (struct multi_context *m)
{
	unsigned int flags = IOW_WAIT_SIGNAL;

	if (prepare_process_link_any_incoming (&m->top) != 0)
		flags |= IOW_READ_LINK;

	if (prepare_process_link_server_outgoing (m) != 0)
		flags |= IOW_TO_LINK;

#ifndef ENABLE_TUN_THREAD
	if (prepare_process_tun_any_incoming (&m->top) != 0)
		flags |= IOW_READ_TUN;

	if (prepare_process_tun_server_outgoing (m) != 0)
		flags |= IOW_TO_TUN;
#endif

	return flags;
}

/**************************************************************************/
/**
 * Main event loop for OpenVPN in UDP server mode.
 * @ingroup eventloop
 *
 * This function implements OpenVPN's main event loop for UDP server mode.
 * @param top - Top-level context structure.
 */
void tunnel_server_udp (struct context *top)
{
	struct multi_context m;
#ifdef PERF_STATS_CHECK
	time_t last_print_perf_status = now_sec (MAIN_THREAD_INDEX);
#endif

	CLEAR (m);
	global_multi_context = &m;

	top->mode = CM_TOP;
	context_clear_2 (top);

	/* initialize top-tunnel instance */
	init_instance_handle_signals (top, top->es, CC_HARD_USR1_TO_HUP);
	if (IS_SIG (top))
		return;

	/* initialize global multi_context object */
	multi_init (&m, top, false);

	/* initialize our cloned top object */
	multi_top_init (&m, top, false);

	/* initialize management interface */
	init_management_callback_multi (&m);

	/* 初始化全局包处理缓存, 必须在初始化init_instance_handle_signals(...) 函数调用后 */
	global_variable_init (&m, top);

	/* finished with initialization */
	initialization_sequence_completed (top, ISC_SERVER); /* --mode server --proto udp */

	/* per-packet event loop */
	while (true)
	{
		perf_push (PERF_EVENT_LOOP);

		/* set up and do the io_wait() */
		multi_get_timeout (&m, &m.top.c2.timeval);
		io_wait (&m.top, p2mp_iow_flags (&m));
		MULTI_CHECK_SIG (&m);

		/* check on status of coarse timers */
		multi_process_per_second_timers (&m);

		/* timeout? */
		if (m.top.c2.event_set_status == ES_TIMEOUT)
		{
			multi_process_timeout (&m, MPP_PRE_SELECT|MPP_CLOSE_ON_SIGNAL);
		}
		else
		{
			/* process I/O */
			multi_process_io_udp (&m);
			MULTI_CHECK_SIG (&m);
		}

		perf_pop ();

#ifdef PERF_STATS_CHECK
		if (now_sec (MAIN_THREAD_INDEX) > last_print_perf_status + 300 + MAIN_THREAD_INDEX)
		{
			print_perf_status (top, MAIN_THREAD_INDEX);
			last_print_perf_status = now_sec (MAIN_THREAD_INDEX);
		}
#endif
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
