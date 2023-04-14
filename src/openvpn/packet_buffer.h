#ifndef __PACKET_BUFFER_H__
#define __PACKET_BUFFER_H__

#include "buffer.h"
#include "packet_id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PACKET_BUFFER_LIST	0x0004FFFFu  /* 必须大于 2 * MAX_MAX_PACKET_BUFFER	65536 */

#ifdef PACKET_TTL_CHECK
#ifndef PERF_STATS_CHECK
#define PERF_STATS_CHECK
#endif
#endif

/* 包最大存活期(微秒), 诊断用, 最大2147483648微秒 */
#ifdef PERF_STATS_CHECK
#define MAX_PACKET_TTL	5000000  /* 5秒 */
#else
#define MAX_PACKET_TTL	2147483648
#endif

/* 定义包缓存的用途 */
#define PACKET_BUFFER_FOR_LINK      (1<<0)
#define PACKET_BUFFER_FOR_TUN       (1<<1)
#define PACKET_BUFFER_FOR_FRAG      (1<<2)
#define PACKET_BUFFER_FOR_ALL       (PACKET_BUFFER_FOR_LINK|PACKET_BUFFER_FOR_TUN|PACKET_BUFFER_FOR_FRAG)

/* 定义包链表排序域 */
#define PACKET_BUFFER_ORDER_BY_SEQ  (1<<0)
#define PACKET_BUFFER_ORDER_BY_PIN  (1<<1)

/* 定义检查标记 */
#define PACKET_BUFFER_IS_ORDER      (1<<0)
#define PACKET_BUFFER_IS_LINEAR     (1<<1)
#define PACKET_BUFFER_NOT_EMPTY     (1<<2)
#define PACKET_BUFFER_NOT_MIX_SEQ   (1<<3)
#define PACKET_BUFFER_HAVE_SEQ      (1<<4)
#define PACKET_BUFFER_KEY_ID_EQUAL  (1<<5)
#define PACKET_BUFFER_NOT_EXPIRE    (1<<6)

/* 定义包处理标记 */
#define PACKET_BUFFER_TLS_PACKET_FLAG      (1<<10)  /* 是否TLS协议数据包 */
#define PACKET_BUFFER_PING_FLAG            (1<<11)  /* 是否PING包 */
#define PACKET_BUFFER_OCC_FLAG             (1<<12)  /* 是否OCC包 */
#define PACKET_BUFFER_BCAST_FLAG           (1<<13)  /* 是否处理过广播和客户到客户路由 */
#define PACKET_BUFFER_TCP_PREPEND_FLAG     (1<<14)  /* 是否添加TCP包长域 */
#define PACKET_BUFFER_HAVE_PIN_FLAG        (1<<15)  /* 是否有PIN */
#define PACKET_BUFFER_REPLAY_CHE_FLAG      (1<<16)  /* 是否重放检查过 */
#define PACKET_BUFFER_COMPRESS_CHK_FLAG    (1<<17)  /* 是否压缩处理过 */
#define PACKET_BUFFER_FRAG_CHK_FLAG        (1<<18)  /* 是否分片处理过 */
#define PACKET_BUFFER_FRAG_LAST_FLAG       (1<<19)  /* 是否最后一个包分片 */
#define PACKET_BUFFER_MASQUERADE_FLAG      (1<<20)  /* 是否伪装处理过 */

struct link_socket_actual;
struct packet_buffer_list;

#ifdef PERF_STATS_CHECK
#define MAX_TRACE_DEEP  64
struct process_track
{
	const char *filename;
	int line;
	uint32_t extra;
	struct timeval timestamp;
};
#endif

struct packet_buffer
{
	struct buffer buf;  /* 放最前面, 方便调试时检查内容 */
	struct link_socket_actual from;

	int64_t seq_no;     /* 接收、发送序号 */
	int64_t local_pin;  /* 本地PIN, 排序用 */
	struct packet_id_net pin;
	int64_t local_key_id;
	int key_id;
	int frag_id;
#ifdef PERF_STATS_CHECK
	const char *filename;
	int line;
	uint32_t extra;
	struct timeval ttl;  /* 包生存期, 诊断用 */
	int n_deep;
	struct process_track tracks[MAX_TRACE_DEEP];
#endif

	bool managed;    /* 分配器管理的 */
	uint32_t type;   /* 缓冲区用途 */
	uint32_t flags;  /* 处理指示 */

	/* 可以这样做, 因为每个packet_buffer实例只能放置在一个packet_buffer_list对象中, 且不能重复 */
	struct packet_buffer *prev;
	struct packet_buffer *next;
};

#define HAVE_MULTI_TYPE_FLAG (1<<0)  /* 包含多种用途的包缓存 */

#define ALLOW_LINK_THREAD    (1<<3)  /* 允许主线程访问对象 */
#define ALLOW_TUN_THREAD     (1<<4)  /* 允许TUN线程访问对象 */
#define ALLOW_WORKER_THREAD  (1<<5)  /* 允许工作线程访问对象 */
#define ALLOW_ANY_THREAD	(ALLOW_LINK_THREAD|ALLOW_TUN_THREAD|ALLOW_WORKER_THREAD)

struct packet_buffer_list
{
	volatile int size;  /* 当前条目数 */
	int capacity;       /* buffer容量 */
	uint32_t type;      /* 缓冲区列表用途 */
	uint32_t flags;     /* 处理指示, 诊断用 */

	struct packet_buffer *head;
	struct packet_buffer *tail;

	/* Windows下free(...)性能有问题, 采用列表内管理packet_buffer对象 */
	int allocator_size;
	struct packet_buffer *allocator;
};

static inline struct packet_buffer*
packet_buffer_new_gc (int capacity, int type, struct gc_arena *gc)
{
	struct packet_buffer *ret;

	ASSERT (capacity > 0 && capacity <= BUF_SIZE_MAX);
	ASSERT (type & PACKET_BUFFER_FOR_LINK || type & PACKET_BUFFER_FOR_TUN || type & PACKET_BUFFER_FOR_FRAG);

	ALLOC_OBJ_CLEAR_GC (ret, struct packet_buffer, gc);
	ret->type = type;
	ret->managed = false;
	ret->buf = alloc_buf_gc (capacity, gc);
	ret->seq_no = -1;
	ret->local_pin = -1;
	ret->local_key_id = -1;
	ret->key_id = -1;
	ret->frag_id = -1;
	ret->flags = 0;
#ifdef PERF_STATS_CHECK
	CLEAR (ret->ttl);
	ret->extra = 0;
#endif

	return ret;
}

static inline struct packet_buffer*
packet_buffer_new (int capacity, int type)
{
	struct packet_buffer *ret;

	ASSERT (capacity > 0 && capacity <= BUF_SIZE_MAX);
	ASSERT (type & PACKET_BUFFER_FOR_LINK || type & PACKET_BUFFER_FOR_TUN || type & PACKET_BUFFER_FOR_FRAG);

	ALLOC_OBJ_CLEAR (ret, struct packet_buffer);
	ret->type = type;
	ret->managed = false;
	ret->buf = alloc_buf (capacity);
	ret->seq_no = -1;
	ret->local_pin = -1;
	ret->local_key_id = -1;
	ret->key_id = -1;
	ret->frag_id = -1;
	ret->flags = 0;
#ifdef PERF_STATS_CHECK
	CLEAR (ret->ttl);
	ret->extra = 0;
#endif

	return ret;
}

static inline void 
packet_buffer_free (struct packet_buffer *buf)
{
	if (buf)
	{
		free_buf (&buf->buf);
		if (!buf->managed)
			free (buf);
	}
}

#ifdef PERF_STATS_CHECK
static inline void
packet_buffer_clear_track (struct packet_buffer *buf)
{
	buf->filename = NULL;
	buf->line = 0;
	buf->extra = 0;
	CLEAR (buf->ttl);
	buf->n_deep = 0;
	CLEAR (buf->tracks);
}
#endif

static inline void 
packet_buffer_clear (struct packet_buffer *buf)
{
	if (buf)
	{
		buf->seq_no = -1;
		buf->local_pin = -1;
		buf->local_key_id = -1;
		buf->key_id = -1;
		buf->frag_id = -1;
		buf->flags = 0;
#ifdef PERF_STATS_CHECK
		packet_buffer_clear_track (buf);
#endif
		buf->buf.len = 0;
		buf->buf.offset = 0;
		buf->buf.tracking = 0;

#ifdef PACKET_BUFFER_LIST_CHECK
		/* 不需要清理 CLEAR (buf->pin); */
		CLEAR (buf->pin);
		/* 不需要清理 CLEAR (buf->from); */
		CLEAR (buf->from);
#endif
		/* 不需要清理 buf_clear (&buf->buf); */
		/* 其它域, 不能清理, 必须保留 */
	}
}

static inline void 
packet_buffer_drop (struct packet_buffer *buf, const uint32_t tracking)
{
	if (buf)
	{
		buf->buf.len = 0;	/* 丢弃包 */
		buf_set_tracking (&buf->buf, tracking);
	}
}

static inline void
packet_buffer_copy (struct packet_buffer *dst, struct packet_buffer *src)
{
	ASSERT (dst->buf.capacity == src->buf.capacity);

	dst->buf.offset = src->buf.offset;
	dst->buf.len = src->buf.len;
	memcpy (BPTR (&dst->buf), BPTR (&src->buf), BLEN (&src->buf));

#ifdef PERF_STATS_CHECK
	dst->filename = src->filename;
	dst->line = src->line;
	dst->extra = src->extra;
	dst->ttl = src->ttl;
	dst->n_deep = src->n_deep;
	memcpy (dst->tracks, src->tracks, sizeof (src->tracks));
#endif
	dst->from = src->from;

	/* 不能复制type域 */
	/* 其它域, 不需要复制或不能复制 */
}

#ifdef PERF_STATS_CHECK
static inline void
packet_buffer_trace (struct packet_buffer *buf, struct timeval *now_tv, int line, const char *filename)
{
	if (buf->n_deep < MAX_TRACE_DEEP)
	{
		struct process_track *track = &buf->tracks[buf->n_deep];
		if (buf->n_deep + 1 < MAX_TRACE_DEEP)
			++buf->n_deep;
		track->timestamp = *now_tv;
		track->line = line;
		track->filename = filename;
	}
	else
		ASSERT (0);
}

static inline void
packet_buffer_list_trace (struct packet_buffer_list *ol, struct timeval *now_tv, int line, const char *filename)
{
	struct packet_buffer *buf = ol->head;
	while (buf)
	{
		packet_buffer_trace (buf, now_tv, line, filename);
		buf = buf->next;
	}
}

static inline void
packet_buffer_mark_ttl (struct packet_buffer *buf, struct timeval *now_tv)
{
	if (!now_tv || now_tv->tv_sec <= 0)
	{
		buf->ttl.tv_sec = 0;
		buf->ttl.tv_usec = 0;
	}
	else
	{
		buf->ttl.tv_sec  = MAX_PACKET_TTL / 1000000;
		buf->ttl.tv_usec = MAX_PACKET_TTL % 1000000;
		tv_add (&buf->ttl, now_tv);
	}
}

static inline bool 
packet_buffer_check_ttl (struct packet_buffer *buf, struct timeval *now_tv, int line, const char *filename)
{
	packet_buffer_trace (buf, now_tv, line, filename);
	return buf->buf.len <= 0 || buf->ttl.tv_sec <= 0 || tv_gt (&buf->ttl, now_tv);
}

static inline void 
packet_buffer_dump_track (struct packet_buffer *buf, struct gc_arena *gc)
{
	int i;
	struct buffer out = alloc_buf_gc (8096, gc);

	for (i = buf->n_deep - 1; i >= 0; i--)
		buf_printf (&out, "file=%s, line=%d, extra=%d, timestamp=%s\n", buf->tracks[i].filename, buf->tracks[i].line,
			buf->tracks[i].extra, tv_string (&buf->tracks[i].timestamp, gc));
	fprintf (stdout, "%s\n", BSTR (&out));
}
#endif

void
packet_buffer_dump (struct packet_buffer *buf, bool full, const char *prefix, struct gc_arena *gc);

struct packet_buffer_list*
packet_buffer_list_new (int capacity, int size, int type, unsigned int flags);

void
packet_buffer_list_free (struct packet_buffer_list *ol);

struct packet_buffer_list*
packet_buffer_list_init (struct packet_buffer_list *ol, int capacity, int size, int type, unsigned int flags);

void
packet_buffer_list_destroy (struct packet_buffer_list *ol);

#ifdef PACKET_BUFFER_LIST_CHECK
void
packet_buffer_list_check (struct packet_buffer_list *ol, struct timeval *now_tv, unsigned int of, int check,
		int line, const char *filename);
#endif

static inline struct packet_buffer* 
packet_buffer_list_push_front (struct packet_buffer_list *ol, struct packet_buffer *buf)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && ol->type & buf->type && buf->buf.capacity == ol->capacity);
#endif

	buf->prev = buf->next = NULL;
	++ol->size;

	if (ol->head)
	{
		buf->next = ol->head;
		ol->head->prev = buf;
		ol->head = buf;
	}
	else
		ol->head = ol->tail = buf;

	return buf;
}

static inline struct packet_buffer* 
packet_buffer_list_push_back (struct packet_buffer_list *ol, struct packet_buffer *buf)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && ol->type & buf->type && buf->buf.capacity == ol->capacity);
#endif

	buf->prev = buf->next = NULL;
	++ol->size;

	if (ol->tail)
	{
		ol->tail->next = buf;
		buf->prev = ol->tail;
		ol->tail = buf;
	}
	else
		ol->head = ol->tail = buf;

	return buf;
}

static inline struct packet_buffer* 
packet_buffer_list_peek_front (struct packet_buffer_list *ol)
{
	return ol ? ol->head : NULL;
}

static inline struct packet_buffer* 
packet_buffer_list_peek_back (struct packet_buffer_list *ol)
{
	return ol ? ol->tail : NULL;
}

static inline struct packet_buffer*
packet_buffer_list_pop_front (struct packet_buffer_list *ol)
{
	struct packet_buffer *buf = NULL;

	if (ol)
	{
		buf = ol->head;
		if (buf)
		{
			--ol->size;
			ol->head = buf->next;

			if (ol->head)
				ol->head->prev = NULL;
			else
				ol->head = ol->tail = NULL;

			buf->prev = buf->next = NULL;
		}
	}

	return buf;
}

static inline void
packet_buffer_list_attach_front (struct packet_buffer_list *ol, struct packet_buffer_list *xl)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && xl && ol->type & xl->type && ol->capacity == xl->capacity);
#endif

	if (xl->size > 0)
	{
		if (!ol->head)
		{
			ol->head = xl->head;
			ol->tail = xl->tail;
		}
		else
		{
			xl->tail->next = ol->head;
			ol->head->prev = xl->tail;
			ol->head = xl->head;
		}

		ol->size += xl->size;
		xl->size = 0;
		xl->head = xl->tail = NULL;
	}
}

static inline void 
packet_buffer_list_attach_back (struct packet_buffer_list *ol, struct packet_buffer_list *xl)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && xl && ol->type & xl->type && ol->capacity == xl->capacity);
#endif

	if (xl->size > 0)
	{
		if (!ol->tail)
		{
			ol->head = xl->head;
			ol->tail = xl->tail;
		}
		else
		{
			ol->tail->next = xl->head;
			xl->head->prev = ol->tail;
			ol->tail = xl->tail;
		}

		ol->size += xl->size;
		xl->size = 0;
		xl->head = xl->tail = NULL;
	}
}

void
packet_buffer_list_attach_by_seq_no (struct packet_buffer_list *ol, struct packet_buffer_list *xl);

void
packet_buffer_list_attach_by_local_pin (struct packet_buffer_list *ol, struct packet_buffer_list *xl);

static inline int
packet_buffer_list_split_front (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int optimal_size)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && xl && ol->type & xl->type && optimal_size > 0 && ol->capacity == xl->capacity);
#endif

	if (ol->size > 0 && xl->size < optimal_size)
	{
		struct packet_buffer *e = ol->head, *p = NULL;

		while (ol->size > 0 && xl->size < optimal_size)
		{
			--ol->size;
			++xl->size;

			p = e;
			e = e->next;
		}

		if (p)
		{
			p->next = NULL;
			if (xl->head)
			{
				xl->tail->next = ol->head;
				ol->head->prev = xl->tail;
				xl->tail = p;
			}
			else
			{
				xl->head = ol->head;
				xl->tail = p;
			}

			if (e)
			{
				e->prev = NULL;
				ol->head = e;
			}
			else
				ol->head = ol->tail = NULL;
		}
	}

	return xl->size;
}

static inline void
packet_buffer_list_shrink (struct packet_buffer_list *ol)
{
	if (ol)
	{
		struct packet_buffer *d = NULL, *e = ol->head;

		while (e)
		{
			if (e->managed)
				e = e->next;
			else
			{
				if (e->prev)
					e->prev->next = e->next;
				if (e->next)
					e->next->prev = e->prev;

				if (ol->head == e)
					ol->head = e->next;
				if (ol->tail == e)
				{
					ol->tail = e->prev;
					if (ol->tail)
						ol->tail->next = NULL;
				}

				d = e;
				e = e->next;
				--ol->size;
				packet_buffer_free (d);
			}
		}
	}
}

static inline void
packet_buffer_list_scatter (struct packet_buffer_list *work_bufs, struct packet_buffer_list *link_bufs,
	struct packet_buffer_list *tun_bufs, struct packet_buffer_list *frag_bufs)
{
	struct packet_buffer *buf;

	ASSERT (work_bufs && link_bufs && tun_bufs);

	do {
		if ((buf = packet_buffer_list_pop_front (work_bufs)))
		{
			if (buf->type & PACKET_BUFFER_FOR_LINK)
				packet_buffer_list_push_back (link_bufs, buf);
			else if (buf->type & PACKET_BUFFER_FOR_TUN)
				packet_buffer_list_push_back (tun_bufs, buf);
			else if (buf->type & PACKET_BUFFER_FOR_FRAG)
			{
				ASSERT (frag_bufs);
				packet_buffer_list_push_back (frag_bufs, buf);
			}
			else
				ASSERT (0);
		}
	} while (buf);
}

/* 分离出要加解密的数据包, 用key_id指定的密钥加解密 */
int
packet_buffer_list_detach_front (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int key_id,
		int optimal_size);

/* 分离出已加解密的连续数据包, next_seq_no指定了起始序号 */
int
packet_buffer_list_detach_by_seq_no (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int64_t next_seq_no);

/* 分离出已加解密的连续数据包, local_pin指定了起始本地PIN */
int
packet_buffer_list_detach_by_local_pin (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int64_t local_pin);

#ifdef __cplusplus
}
#endif

#endif
