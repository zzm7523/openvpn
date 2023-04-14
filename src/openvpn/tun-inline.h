#ifndef __TUN_INLINE_H__
#define __TUN_INLINE_H__

static inline int prepare_process_tun_any_incoming (struct context *c)
{
	struct packet_buffer_list *read_work_bufs = g_tun_transfer_context->read_work_bufs;

	if (read_work_bufs->size < MAX_TUN_BATCH_READ)
	{
#ifdef ENABLE_TUN_THREAD
		MUTEX_LOCK (g_tun_free_bufs_mutex, TUN_THREAD_INDEX, S_TUN_FREE_BUFS);
		/* 访问g_tun_free_bufs对象必须持有g_tun_free_bufs_mutex锁 */
		packet_buffer_list_attach_back (read_work_bufs, g_tun_free_bufs);
		MUTEX_UNLOCK (g_tun_free_bufs_mutex, TUN_THREAD_INDEX, S_TUN_FREE_BUFS);
#else
		packet_buffer_list_attach_back (read_work_bufs, g_tun_free_bufs);
#endif
	}

	return read_work_bufs->size;
}

static inline int
prepare_process_tun_p2p_outgoing (struct context *c)
{
	/* c->c2.buffers->tun_write_bufs总是有序 */
	if (c->c2.buffers->tun_write_bufs->size == 0 && c->c2.buffers->to_tun_bufs->size != 0)
	{
		struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
		ASSERT (is_tun_thread ());
#endif

		MUTEX_LOCK (&c->c2.buffers->to_tun_bufs_mutex, TUN_THREAD_INDEX, S_TO_TUN_BUFS);

		packet_buffer_list_attach_back (c->c2.buffers->tun_write_bufs, c->c2.buffers->to_tun_bufs);
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->tun_write_bufs, local_now,
			PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_UNLOCK (&c->c2.buffers->to_tun_bufs_mutex, TUN_THREAD_INDEX, S_TO_TUN_BUFS);

		if (c->c2.buffers->tun_write_bufs->size > 0)
		{
			if (c->options.replay)
			{
				/* 包重放检查, 如果是重放通过设置包长等于0，释放包 */
				check_replays (c, c->c2.buffers->tun_write_bufs);
			}

			if (!TLS_MODE (c))
			{
				struct packet_buffer *buf;

				/* buf->buf.len == 0 时, 也要处理 */
				buf = packet_buffer_list_peek_front (c->c2.buffers->tun_write_bufs);
				if (!addr_defined (&c->c2.last_from.dest) || !addr_match (&c->c2.last_from.dest, &buf->from.dest))
				{
#ifdef ENABLE_TUN_THREAD
					MUTEX_LOCK (&c->c2.buffers->to_link_bufs_mutex, TUN_THREAD_INDEX, S_TO_LINK_BUFS);
#endif
					c->c2.last_from = buf->from;
					c->c2.from = buf->from;
#ifdef ENABLE_TUN_THREAD
					MUTEX_UNLOCK (&c->c2.buffers->to_link_bufs_mutex, TUN_THREAD_INDEX, S_TO_LINK_BUFS);
#endif
				}
			}
		}
	}

	return c->c2.buffers->tun_write_bufs->size;
}

static inline struct packet_buffer*
get_tun_read_packet_buffer (struct context *c, bool alloc)
{
	struct packet_buffer_list *read_work_bufs = g_tun_transfer_context->read_work_bufs;
	struct packet_buffer *buf = NULL;

#ifdef _DEBUG
	if (rand () % 100 == 0)	/* 测试动态分配packet_buffer */
		buf = packet_buffer_new (read_work_bufs->capacity, read_work_bufs->type);
#endif

	if (!buf)
	{
		if (read_work_bufs->size == 0)
			prepare_process_tun_any_incoming (c);

		buf = packet_buffer_list_pop_front (read_work_bufs);
		if (buf)
			packet_buffer_clear (buf);
		else if (alloc)
			buf = packet_buffer_new (read_work_bufs->capacity, read_work_bufs->type);
	}

	return buf;
}

static inline void
post_process_tun_p2p_incoming (struct context *c, struct timeval *now_tv)
{
	if (c->c2.buffers->tun_read_bufs->size > 0)
	{
		int size;
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->tun_read_bufs, now_tv, PACKET_BUFFER_ORDER_BY_SEQ,
			PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_FRAG_LAST_FLAG|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_mutex, TUN_THREAD_INDEX, S_READ_TUN_BUFS);
		packet_buffer_list_attach_back (c->c2.buffers->read_tun_bufs, c->c2.buffers->tun_read_bufs);
		size = c->c2.buffers->read_tun_bufs->size;
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->read_tun_bufs, now_tv,
			PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_IS_ORDER, __LINE__, __FILE__);
#endif
		MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_mutex, TUN_THREAD_INDEX, S_READ_TUN_BUFS);

		wakeup_worker_threads (TUN_THREAD_INDEX, size);
	}
}

static inline void
post_process_tun_any_outgoing (struct context *c, struct packet_buffer_list *tun_work_bufs)
{
	packet_buffer_list_shrink (tun_work_bufs);	/* 释放临时缓存 */

	if (tun_work_bufs->size > 0)
	{
		if (tun_work_bufs->flags & HAVE_MULTI_TYPE_FLAG)
		{
			packet_buffer_list_scatter (tun_work_bufs, g_tun_transfer_context->link_reclaim_bufs,
				g_tun_transfer_context->tun_reclaim_bufs
#ifdef ENABLE_FRAGMENT
				, g_tun_transfer_context->frag_reclaim_bufs
#else
				, NULL
#endif
			);
		}
		else
		{
			packet_buffer_list_attach_back (g_tun_transfer_context->link_reclaim_bufs, tun_work_bufs);
		}

		if (g_tun_transfer_context->tun_reclaim_bufs->size > RECLAIM_THRESHOLD)
		{
#ifdef ENABLE_TUN_THREAD
			MUTEX_LOCK (g_tun_free_bufs_mutex, TUN_THREAD_INDEX, S_TUN_FREE_BUFS);
			packet_buffer_list_attach_back (g_tun_free_bufs, g_tun_transfer_context->tun_reclaim_bufs);
			MUTEX_UNLOCK (g_tun_free_bufs_mutex, TUN_THREAD_INDEX, S_TUN_FREE_BUFS);
#else
			packet_buffer_list_attach_back (g_tun_free_bufs, g_tun_transfer_context->tun_reclaim_bufs);
#endif
		}

		if (g_tun_transfer_context->link_reclaim_bufs->size > RECLAIM_THRESHOLD)
		{
#ifdef ENABLE_TUN_THREAD
			bool wakeup;
			MUTEX_LOCK (g_link_free_bufs_mutex, TUN_THREAD_INDEX, S_LINK_FREE_BUFS);
			wakeup = g_link_free_bufs->size == 0;
			packet_buffer_list_attach_back (g_link_free_bufs, g_tun_transfer_context->link_reclaim_bufs);
			MUTEX_UNLOCK (g_link_free_bufs_mutex, TUN_THREAD_INDEX, S_LINK_FREE_BUFS);

			if (wakeup)
				/* 唤醒主线程, g_link_free_bufs对象有空间，可进行link读取 */
				event_wakeup (c->c2.event_set);
#else
			packet_buffer_list_attach_back (g_link_free_bufs, g_tun_transfer_context->link_reclaim_bufs);
#endif
		}
	}
}

static inline int 
do_process_tun_write (struct context *c, struct packet_buffer_list *work_bufs, struct packet_buffer_list *free_bufs)
{
	static time_t last_ping_rec_interval_reset = 0;	/* 记录上一次的调用时间, 减少锁定频率 */
	struct packet_buffer *buf = NULL;
	int counter = 0, status = 1;
	struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_tun_thread ());
#endif

#ifdef PACKET_BUFFER_LIST_CHECK
	packet_buffer_list_check (work_bufs, local_now,
		PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

	do {
		if ((buf = packet_buffer_list_pop_front (work_bufs)))
		{
			if (buf->buf.len > 0)
			{
				if ((status = process_outgoing_tun (c, local_now, buf)) <= 0)
				{
					if (buf->buf.len > 0) /* 线路繁忙, 包没有放入写缓存 */
					{
						packet_buffer_list_push_front (work_bufs, buf);
						buf = NULL;
						break;
					}
				}
				else
				{
#ifdef PERF_STATS_CHECK
					packet_buffer_stat_ttl (buf, TUN_THREAD_INDEX, local_now, __LINE__, __FILE__);
#endif
					++counter;
				}

				/* reset packet received timer */
				if (c->options.ping_rec_timeout && local_now->tv_sec > last_ping_rec_interval_reset)
				{
					last_ping_rec_interval_reset = local_now->tv_sec;
					ping_rec_interval_reset (c, TUN_THREAD_INDEX, local_now->tv_sec);
				}
			}

			if (buf)
			{
				/* 发送成功, 或包异常; 更新当前写出的包序号 */
				ASSERT (buf->flags & PACKET_BUFFER_FRAG_LAST_FLAG);
#ifdef PERF_STATS_CHECK
				packet_buffer_clear_track (buf);
#endif
				if (buf->type != PACKET_BUFFER_FOR_LINK)
					free_bufs->flags |= HAVE_MULTI_TYPE_FLAG;
				packet_buffer_list_push_back (free_bufs, buf);
			}
		}

	} while (buf && status > 0 && c->c1.tuntap && counter < MAX_TUN_BATCH_WRITE);

	return counter;
}

static inline int 
do_process_tun_p2p_write (struct context *c)
{
	struct packet_buffer_list *write_work_bufs = g_tun_transfer_context->write_work_bufs;
	int counter = 0;

	counter = do_process_tun_write (c, c->c2.buffers->tun_write_bufs, write_work_bufs);
	if (write_work_bufs->size > 0)
	{
		post_process_tun_any_outgoing (c, write_work_bufs);
		write_work_bufs->flags &= ~HAVE_MULTI_TYPE_FLAG;
	}

	return counter;	/* 返回写出的数据包数 */
}

static inline int 
do_process_tun_p2p_read (struct context *c)
{
	struct packet_buffer_list *read_work_bufs = g_tun_transfer_context->read_work_bufs;
	struct packet_buffer *buf;
	int counter = 0, status = 0;
	struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_tun_thread ());
#endif

	ASSERT (c->c2.buffers->tun_read_bufs->size == 0);

	do {		
		if ((buf = get_tun_read_packet_buffer (c, false)))
		{
			if ((status = read_incoming_tun (c, buf)) <= 0) /* 线路繁忙或异常, 没有读到包 */
			{
				packet_buffer_list_push_back (read_work_bufs, buf);
				break;
			}
			else
			{
				++counter;
				process_incoming_tun (c, local_now, buf);
				if (buf->buf.len <= 0)
					packet_buffer_list_push_back (read_work_bufs, buf);
				else
				{
					set_read_tun_data_seq (c, buf, local_now); /* 隧道数据包分配包序号 */
					packet_buffer_list_push_back (c->c2.buffers->tun_read_bufs, buf);

#ifdef PACKET_BUFFER_RANDOM_DROP
					if (buf->seq_no % 100 == 1)
					{
						/* 随机丢包, 模拟load_crypto_options(...)失败 */
						packet_buffer_drop (buf, PACKET_DROP_CORRUPT_GREMLIN);
					}
#endif
				}
			}
		}

	} while (buf && status > 0 && c->c1.tuntap && counter < MAX_TUN_BATCH_READ && !IS_SIG (c));

	if (c->c2.buffers->tun_read_bufs->size > 0)
		post_process_tun_p2p_incoming (c, local_now);

	return counter;	/* 返回读取的数据包数 */
}

#endif
