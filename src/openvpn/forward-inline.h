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

#ifndef FORWARD_INLINE_H
#define FORWARD_INLINE_H

/*
 * Inline functions
 */

/*
 * Does TLS session need service?
 */
static inline void
check_tls (struct context *c)
{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
	void check_tls_dowork (struct context *c);
	if (c->c2.tls_multi)
		check_tls_dowork (c);
#endif
}

/*
 * TLS errors are fatal in TCP mode. Also check for --tls-exit trigger.
 */
static inline void
check_tls_errors (struct context *c)
{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
	bool link_socket_connection_oriented (const struct link_socket *sock);
	void check_tls_errors_co (struct context *c);
	void check_tls_errors_nco (struct context *c);

	if (c->c2.tls_multi && c->c2.tls_exit_signal)
	{
		if (link_socket_connection_oriented (c->c2.link_socket))
		{
			if (c->c2.tls_multi->n_soft_errors)
				check_tls_errors_co (c);
		}
		else
		{
			if (c->c2.tls_multi->n_hard_errors)
				check_tls_errors_nco (c);
		}
	}
#endif
}

/*
 * Check for possible incoming configuration messages on the control channel.
 */
static inline void
check_incoming_control_channel (struct context *c)
{
#if P2MP
	void check_incoming_control_channel_dowork (struct context *c);
	if (tls_test_payload_len (c->c2.tls_multi) > 0)
		check_incoming_control_channel_dowork (c);
#endif
}

/*
 * Options like --up-delay need to be triggered by this function which
 * checks for connection establishment.
 */
static inline void
check_connection_established (struct context *c)
{
	void check_connection_established_dowork (struct context *c);

	if (event_timeout_defined (&c->c2.wait_for_connect))
		check_connection_established_dowork (c);
}

/*
 * Should we add routes?
 */
static inline void
check_add_routes (struct context *c)
{
	void check_add_routes_dowork (struct context *c);

	if (event_timeout_trigger (&c->c2.route_wakeup, &c->c2.timeval, ETT_DEFAULT))
		check_add_routes_dowork (c);
}

/*
 * Should we exit due to inactivity timeout?
 */
static inline void
check_inactivity_timeout (struct context *c)
{
	void check_inactivity_timeout_dowork (struct context *c);

	if (c->options.inactivity_timeout)
	{
		bool reset = false;

		MUTEX_LOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);
		if (c->c2.inactivity_bytes >= (counter_type) c->options.inactivity_minimum_bytes)
		{
			c->c2.inactivity_bytes = 0;
			reset = true;
		}
		MUTEX_UNLOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);

		update_time (MAIN_THREAD_INDEX);
		if (reset)
			event_timeout_reset (&c->c2.inactivity_interval, now_sec (MAIN_THREAD_INDEX));

		if (event_timeout_trigger (&c->c2.inactivity_interval, &c->c2.timeval, ETT_DEFAULT))
			check_inactivity_timeout_dowork (c);
	}
}

#if P2MP

static inline void
check_server_poll_timeout (struct context *c)
{
	void check_server_poll_timeout_dowork (struct context *c);

	if (c->options.server_poll_timeout
		&& event_timeout_trigger (&c->c2.server_poll_interval, &c->c2.timeval, ETT_DEFAULT))
		check_server_poll_timeout_dowork (c);
}

/*
 * Scheduled exit?
 */
static inline void
check_scheduled_exit (struct context *c)
{
	void check_scheduled_exit_dowork (struct context *c);

	if (event_timeout_defined (&c->c2.scheduled_exit))
	{
		if (event_timeout_trigger (&c->c2.scheduled_exit, &c->c2.timeval, ETT_DEFAULT))
			check_scheduled_exit_dowork (c);
	}
}

#endif

/*
 * Should we write timer-triggered status file.
 */
static inline void
check_status_file (struct context *c)
{
	void check_status_file_dowork (struct context *c);

	if (c->c1.status_output)
	{
		if (status_trigger_tv (c->c1.status_output, &c->c2.timeval))
			check_status_file_dowork (c);
	}
}

#if P2MP

/*
 * see if we should send a push_request in response to --pull
 */
static inline void
check_push_request (struct context *c)
{
	void check_push_request_dowork (struct context *c);

	if (event_timeout_trigger (&c->c2.push_request_interval, &c->c2.timeval, ETT_DEFAULT))
		check_push_request_dowork (c);
}

#endif

#ifdef ENABLE_CRYPTO
/*
 * Should we persist our anti-replay packet ID state to disk?
 */
static inline void
check_packet_id_persist_flush (struct context *c)
{
	if (packet_id_persist_enabled (&c->c1.pid_persist)
		&& event_timeout_trigger (&c->c2.packet_id_persist_interval, &c->c2.timeval, ETT_DEFAULT))
	{
		RWLOCK_WRLOCK (&c->share_lock, MAIN_THREAD_INDEX, S_SHARE_LOCK);	/* 阻止其它线程访问context */
		packet_id_persist_save (&c->c1.pid_persist);
		RWLOCK_UNLOCK (&c->share_lock, MAIN_THREAD_INDEX, S_SHARE_LOCK);	/* 允许其它线程访问context */
	}
}
#endif

/*
 * Set our wakeup to 0 seconds, so we will be rescheduled immediately.
 */
static inline void
context_immediate_reschedule (struct context *c)
{
	c->c2.timeval.tv_sec = 0;    /* ZERO-TIMEOUT */
	c->c2.timeval.tv_usec = 0;
}

static inline void
context_reschedule_sec (struct context *c, int sec)
{
	if (sec < 0)
		sec = 0;
	if (sec < c->c2.timeval.tv_sec)
	{
		c->c2.timeval.tv_sec = sec;
		c->c2.timeval.tv_usec = 0;
	}
}

static inline void
register_activity (struct context *c, const int size, const int thread_idx)
{
#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx && thread_idx < WORKER_THREAD_INDEX_BASE);
#endif

	if (c->options.inactivity_timeout)
	{
		if (thread_idx == MAIN_THREAD_INDEX)
			c->c2.inactivity_bytes += size;
		else if (thread_idx == TUN_THREAD_INDEX)
			c->c2.tun_io_stats.inactivity_bytes += size;
		else
			ASSERT (0);
	}
}

static inline int
prepare_process_link_p2p_outgoing (struct context *c)
{
	/* c->c2.buffers->link_write_bufs 总是有序 */
	if (c->c2.buffers->link_write_bufs->size == 0 && c->c2.buffers->to_link_bufs->size != 0)
	{
		MUTEX_LOCK (&c->c2.buffers->to_link_bufs_mutex, MAIN_THREAD_INDEX, S_TO_LINK_BUFS);

		/* TCP启用重放保护时, 链路输出必须按packet_id_net排序 */
		packet_buffer_list_attach_back (c->c2.buffers->link_write_bufs, c->c2.buffers->to_link_bufs);
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->link_write_bufs, now_tv (MAIN_THREAD_INDEX),
			PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
			PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		/*
		 * Set our "official" outgoing address, since if buf.len is non-zero, we know the packet authenticated.  
		 * In TLS mode we do nothing because TLS mode takes care of source address authentication.
		 *
		 * Also, update the persisted version of our packet-id.
		 */
		if (!TLS_MODE (c) && addr_defined (&c->c2.from.dest))
		{
			struct packet_buffer *buf = packet_buffer_list_peek_front (c->c2.buffers->link_write_bufs);
			link_socket_set_outgoing_addr (&buf->buf, get_link_socket_info (c), &c->c2.from, NULL, c->c2.es);
		}

		MUTEX_UNLOCK (&c->c2.buffers->to_link_bufs_mutex, MAIN_THREAD_INDEX, S_TO_LINK_BUFS);
	}

	return c->c2.to_link.len || c->c2.buffers->link_write_bufs->size
#ifdef TARGET_LINUX
		|| c->c2.link_socket->writes.size - c->c2.link_socket->writes.offset
#endif
		;
}

static inline void
post_process_link_any_outgoing (struct context *c, struct packet_buffer_list *link_work_bufs
#ifdef ENABLE_FRAGMENT
		, struct packet_buffer_list *frag_work_bufs
#endif
		)
{
	packet_buffer_list_shrink (link_work_bufs);	/* 释放临时缓存 */

	if (link_work_bufs->size > 0)
	{
		if (link_work_bufs->flags & HAVE_MULTI_TYPE_FLAG)
		{
			packet_buffer_list_scatter (link_work_bufs, g_link_transfer_context->link_reclaim_bufs,
				g_link_transfer_context->tun_reclaim_bufs
#ifdef ENABLE_FRAGMENT
				, g_link_transfer_context->frag_reclaim_bufs
#else
				, NULL
#endif
			);
		}
		else
		{
			packet_buffer_list_attach_back (g_link_transfer_context->tun_reclaim_bufs, link_work_bufs);
		}

		if (g_link_transfer_context->link_reclaim_bufs->size > RECLAIM_THRESHOLD)
		{
#ifdef ENABLE_TUN_THREAD
			MUTEX_LOCK (g_link_free_bufs_mutex, MAIN_THREAD_INDEX, S_LINK_FREE_BUFS);
			packet_buffer_list_attach_back (g_link_free_bufs, g_link_transfer_context->link_reclaim_bufs);
			MUTEX_UNLOCK (g_link_free_bufs_mutex, MAIN_THREAD_INDEX, S_LINK_FREE_BUFS);
#else
			packet_buffer_list_attach_back (g_link_free_bufs, g_link_transfer_context->link_reclaim_bufs);
#endif
		}

		if (g_link_transfer_context->tun_reclaim_bufs->size > RECLAIM_THRESHOLD)
		{
#ifdef ENABLE_TUN_THREAD
			bool wakeup;
			MUTEX_LOCK (g_tun_free_bufs_mutex, MAIN_THREAD_INDEX, S_TUN_FREE_BUFS);
			wakeup = g_tun_free_bufs->size == 0;
			packet_buffer_list_attach_back (g_tun_free_bufs, g_link_transfer_context->tun_reclaim_bufs);
			MUTEX_UNLOCK (g_tun_free_bufs_mutex, MAIN_THREAD_INDEX, S_TUN_FREE_BUFS);

			if (wakeup)
				/* 唤醒TUN设备读写线程, g_tun_free_bufs对象有空间，可进行tun读取 */
				event_wakeup (c->c2.tun_event_set);
#else
			packet_buffer_list_attach_back (g_tun_free_bufs, g_link_transfer_context->tun_reclaim_bufs);
#endif
		}
	}

#ifdef ENABLE_FRAGMENT
	packet_buffer_list_shrink (frag_work_bufs);	/* 释放临时缓存 */

	if (frag_work_bufs->size > 0)
	{
		packet_buffer_list_attach_back (g_link_transfer_context->frag_reclaim_bufs, frag_work_bufs);

		if (g_link_transfer_context->frag_reclaim_bufs->size > RECLAIM_THRESHOLD)
		{
			MUTEX_LOCK (g_frag_free_bufs_mutex, MAIN_THREAD_INDEX, S_FRAG_FREE_BUFS);
			packet_buffer_list_attach_back (g_frag_free_bufs, g_link_transfer_context->frag_reclaim_bufs);
			MUTEX_UNLOCK (g_frag_free_bufs_mutex, MAIN_THREAD_INDEX, S_FRAG_FREE_BUFS);
		}
	}
#endif
}

static inline void
post_process_link_p2p_incoming (struct context *c, struct timeval *now_tv)
{
	if (c->c2.buffers->link_read_bufs->size > 0)
	{
		int size;
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->link_read_bufs, now_tv,
			PACKET_BUFFER_ORDER_BY_SEQ,
			PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif
		
		MUTEX_LOCK (&c->c2.buffers->read_link_bufs_mutex, MAIN_THREAD_INDEX, S_READ_LINK_BUFS);

		packet_buffer_list_attach_back (c->c2.buffers->read_link_bufs, c->c2.buffers->link_read_bufs);
		size = c->c2.buffers->read_link_bufs->size;
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->read_link_bufs, now_tv,
			PACKET_BUFFER_ORDER_BY_SEQ,
			PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_UNLOCK (&c->c2.buffers->read_link_bufs_mutex, MAIN_THREAD_INDEX, S_READ_LINK_BUFS);

		wakeup_worker_threads (MAIN_THREAD_INDEX, size);
	}
}

#ifdef TARGET_LINUX
static inline int do_link_force_flush (struct context *c)
{
	const unsigned int flags = OVERLAPPED_FORCE_FLUSH|OVERLAPPED_PACKET_INVALID;
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* 只有主线程能访问c->c2.link_flush变量 */
#endif

	ASSERT (proto_is_udp (c->c2.link_socket->info.proto));

	if (!c->c2.link_flush)
	{
		c->c2.link_flush = packet_buffer_new (g_tun_free_bufs->capacity, g_tun_free_bufs->type);
		c->c2.link_flush_owned = true;	
	}

	ASSERT (buf_init (&c->c2.link_flush->buf, FRAME_HEADROOM (&c->c2.frame)));
	c->c2.link_flush->buf.len = 19;	/* 任意19字节数据 */

	return link_socket_write (c->c2.link_socket, &c->c2.link_flush->buf, NULL, flags);
}
#endif

static inline int 
do_process_link_write (struct context *c, struct packet_buffer_list *work_bufs, struct packet_buffer_list *link_work_bufs
#ifdef ENABLE_FRAGMENT
		, struct packet_buffer_list *frag_work_bufs
#endif
		)
{
	struct packet_buffer *buf = packet_buffer_list_peek_front (work_bufs);
	unsigned int flags = 0;
	int counter = 0, status = 1;
	struct timeval *local_now = now_tv (MAIN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

#ifdef ENABLE_FRAGMENT
	ASSERT (link_work_bufs->size == 0 && frag_work_bufs->size == 0);
#else
	ASSERT (link_work_bufs->size == 0);
#endif

	/* Get the address we will be sending the packet to. */
	if (buf && !(buf->flags & PACKET_BUFFER_TLS_PACKET_FLAG))
		link_socket_get_outgoing_addr (&buf->buf, get_link_socket_info (c), &c->c2.to_link_addr);

#ifdef PACKET_BUFFER_LIST_CHECK
	/* TCP启用重放保护时, 链路输出必须按packet_id_net排序 */
	packet_buffer_list_check (work_bufs, local_now, PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
		PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

	do {
		if ((buf = packet_buffer_list_pop_front (work_bufs)))
		{
			if (buf->buf.len > 0)
			{
#ifdef TARGET_LINUX
				if (work_bufs->size == 0 && proto_is_udp (c->c2.link_socket->info.proto))
					/* 最后一个包, 刷新缓存 */
					flags |= OVERLAPPED_FORCE_FLUSH;
#endif
				status = process_outgoing_link_data (c, buf, flags);
				if (status == 0)
				{
					if (buf->buf.len > 0)
					{
						/* 线路繁忙, 包没有放入写缓存(UDP), 包没有写出(TCP) */
						packet_buffer_list_push_front (work_bufs, buf);
						buf = NULL;
					}
				}
				else if (status > 0)
				{
					if (proto_is_tcp (c->c2.link_socket->info.proto) && buf->buf.len > 0)
					{
						/* 线路繁忙, 包部分写出(TCP) */
						packet_buffer_list_push_front (work_bufs, buf);
						buf = NULL;
					}
#ifdef PERF_STATS_CHECK
					packet_buffer_stat_ttl (buf, MAIN_THREAD_INDEX, local_now, __LINE__, __FILE__);
#endif
					++counter;
				}
			}

			if (buf)
			{
#ifdef PERF_STATS_CHECK
				packet_buffer_clear_track (buf);
#endif
#ifdef ENABLE_FRAGMENT
				if (buf->type == PACKET_BUFFER_FOR_FRAG)
					packet_buffer_list_push_back (frag_work_bufs, buf);
				else
#endif
				{
					if (buf->type != PACKET_BUFFER_FOR_TUN)
						link_work_bufs->flags |= HAVE_MULTI_TYPE_FLAG;
					packet_buffer_list_push_back (link_work_bufs, buf);
				}
			}
		}

		/* status < 0 发生错误, status == 0 缓存不足 */
	} while (buf && status > 0 && c->c2.link_socket && counter < MAX_LINK_BATCH_WRITE);

#ifdef TARGET_LINUX
	if (proto_is_udp (c->c2.link_socket->info.proto))
	{
		if ((c->options.sockflags & SF_USE_SENDMMSG) && !(flags & OVERLAPPED_FORCE_FLUSH))
			do_link_force_flush (c);	// 刷出缓存
	}
#endif

	return counter;
}

static inline int 
do_process_link_p2p_write (struct context *c)
{
	struct packet_buffer_list *write_work_bufs = g_link_transfer_context->write_work_bufs;
#ifdef ENABLE_FRAGMENT
	struct packet_buffer_list *frag_work_bufs = g_link_transfer_context->frag_work_bufs;
#endif
	int counter = 0;

	process_outgoing_link_tls (c);	/* 处理TLS控制包*/

	counter = do_process_link_write (c, c->c2.buffers->link_write_bufs, write_work_bufs
#ifdef ENABLE_FRAGMENT
		, frag_work_bufs
#endif
		);

	if (write_work_bufs->size > 0
#ifdef ENABLE_FRAGMENT
			|| frag_work_bufs->size > 0
#endif
			)
	{
		post_process_link_any_outgoing (c, write_work_bufs
#ifdef ENABLE_FRAGMENT
			, frag_work_bufs
#endif
			);
		write_work_bufs->flags &= ~HAVE_MULTI_TYPE_FLAG;
	}

	return counter;	/* 返回写出的数据包数 */
}

static inline int 
do_process_link_p2p_read (struct context *c)
{
	struct packet_buffer_list *read_work_bufs = g_link_transfer_context->read_work_bufs;
	struct packet_buffer *buf = NULL;
	const bool connection_oriented = link_socket_connection_oriented (c->c2.link_socket);
	int counter = 0, status = 0;
	unsigned int flags = 0;
	struct timeval *local_now = now_tv (MAIN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	ASSERT (c->c2.buffers->link_read_bufs->size == 0);

	do {
		if ((buf = get_link_read_packet_buffer (c, connection_oriented)))
		{
			if ((status = read_incoming_link (c, buf, flags)) <= 0) /* 线路繁忙或异常, 没有读到包 */
			{
				packet_buffer_list_push_back (read_work_bufs, buf);
				break;
			}
			else
			{
				++counter;
#ifdef TARGET_LINUX
				if (proto_is_udp (c->c2.link_socket->info.proto))
					flags |= OVERLAPPED_READ_EMPTY_RETURN;
#endif
				process_incoming_link (c, buf);
				if (buf->buf.len <= 0) /* 控制包或错误 */
					packet_buffer_list_push_back (read_work_bufs, buf);
				else
				{
					set_read_link_data_seq (c, buf, local_now);
					packet_buffer_list_push_back (c->c2.buffers->link_read_bufs, buf);
				}
			}
		}

		if (connection_oriented)
		{	
			if (stream_buf_read_setup (c->c2.link_socket))	/* TCP要求一次性读完缓存的数据包 */
				break;
		}
		else
		{
			if (counter >= MAX_LINK_BATCH_READ)	/* UDP限制一次性读取的数据包数 */
				break;
		}

	} while (buf && status > 0 && c->c2.link_socket && !IS_SIG (c));

	if (c->c2.buffers->link_read_bufs->size > 0)
		post_process_link_p2p_incoming (c, local_now);

	return counter;	/* 返回读取的数据包数 */
}

/* Return the io_wait() flags appropriate for a point-to-point tunnel. */
static inline unsigned int
p2p_iow_flags (struct context *c)
{
	int prepare_process_tun_any_incoming (struct context *c);
	int prepare_process_tun_p2p_outgoing (struct context *c);

	unsigned int flags = (IOW_SHAPER|IOW_CHECK_RESIDUAL|IOW_FRAG|IOW_WAIT_SIGNAL);

	if (prepare_process_link_any_incoming (c)) /* from link */
		flags |= IOW_READ_LINK;

	if (prepare_process_link_p2p_outgoing (c))
		flags |= IOW_TO_LINK;

#ifndef ENABLE_TUN_THREAD
	if (prepare_process_tun_any_incoming (c)) /* from tun */
		flags |= IOW_READ_TUN;

	if (prepare_process_tun_p2p_outgoing (c))
		flags |= IOW_TO_TUN;
#endif

	return flags;
}

/*
 * This is the core I/O wait function, used for all I/O waits except for TCP in server mode.
 */
static inline void
io_wait (struct context *c, const unsigned int flags)
{
	void io_wait_dowork (struct context *c, const unsigned int flags);

	/* slow path */
	io_wait_dowork (c, flags);
}

#endif /* EVENT_INLINE_H */
