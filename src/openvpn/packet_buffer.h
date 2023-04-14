#ifndef __PACKET_BUFFER_H__
#define __PACKET_BUFFER_H__

#include "buffer.h"
#include "packet_id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PACKET_BUFFER_LIST	0x0004FFFFu  /* ������� 2 * MAX_MAX_PACKET_BUFFER	65536 */

#ifdef PACKET_TTL_CHECK
#ifndef PERF_STATS_CHECK
#define PERF_STATS_CHECK
#endif
#endif

/* ���������(΢��), �����, ���2147483648΢�� */
#ifdef PERF_STATS_CHECK
#define MAX_PACKET_TTL	5000000  /* 5�� */
#else
#define MAX_PACKET_TTL	2147483648
#endif

/* ������������; */
#define PACKET_BUFFER_FOR_LINK      (1<<0)
#define PACKET_BUFFER_FOR_TUN       (1<<1)
#define PACKET_BUFFER_FOR_FRAG      (1<<2)
#define PACKET_BUFFER_FOR_ALL       (PACKET_BUFFER_FOR_LINK|PACKET_BUFFER_FOR_TUN|PACKET_BUFFER_FOR_FRAG)

/* ��������������� */
#define PACKET_BUFFER_ORDER_BY_SEQ  (1<<0)
#define PACKET_BUFFER_ORDER_BY_PIN  (1<<1)

/* �������� */
#define PACKET_BUFFER_IS_ORDER      (1<<0)
#define PACKET_BUFFER_IS_LINEAR     (1<<1)
#define PACKET_BUFFER_NOT_EMPTY     (1<<2)
#define PACKET_BUFFER_NOT_MIX_SEQ   (1<<3)
#define PACKET_BUFFER_HAVE_SEQ      (1<<4)
#define PACKET_BUFFER_KEY_ID_EQUAL  (1<<5)
#define PACKET_BUFFER_NOT_EXPIRE    (1<<6)

/* ����������� */
#define PACKET_BUFFER_TLS_PACKET_FLAG      (1<<10)  /* �Ƿ�TLSЭ�����ݰ� */
#define PACKET_BUFFER_PING_FLAG            (1<<11)  /* �Ƿ�PING�� */
#define PACKET_BUFFER_OCC_FLAG             (1<<12)  /* �Ƿ�OCC�� */
#define PACKET_BUFFER_BCAST_FLAG           (1<<13)  /* �Ƿ�����㲥�Ϳͻ����ͻ�·�� */
#define PACKET_BUFFER_TCP_PREPEND_FLAG     (1<<14)  /* �Ƿ����TCP������ */
#define PACKET_BUFFER_HAVE_PIN_FLAG        (1<<15)  /* �Ƿ���PIN */
#define PACKET_BUFFER_REPLAY_CHE_FLAG      (1<<16)  /* �Ƿ��طż��� */
#define PACKET_BUFFER_COMPRESS_CHK_FLAG    (1<<17)  /* �Ƿ�ѹ������� */
#define PACKET_BUFFER_FRAG_CHK_FLAG        (1<<18)  /* �Ƿ��Ƭ����� */
#define PACKET_BUFFER_FRAG_LAST_FLAG       (1<<19)  /* �Ƿ����һ������Ƭ */
#define PACKET_BUFFER_MASQUERADE_FLAG      (1<<20)  /* �Ƿ�αװ����� */

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
	struct buffer buf;  /* ����ǰ��, �������ʱ������� */
	struct link_socket_actual from;

	int64_t seq_no;     /* ���ա�������� */
	int64_t local_pin;  /* ����PIN, ������ */
	struct packet_id_net pin;
	int64_t local_key_id;
	int key_id;
	int frag_id;
#ifdef PERF_STATS_CHECK
	const char *filename;
	int line;
	uint32_t extra;
	struct timeval ttl;  /* ��������, ����� */
	int n_deep;
	struct process_track tracks[MAX_TRACE_DEEP];
#endif

	bool managed;    /* ����������� */
	uint32_t type;   /* ��������; */
	uint32_t flags;  /* ����ָʾ */

	/* ����������, ��Ϊÿ��packet_bufferʵ��ֻ�ܷ�����һ��packet_buffer_list������, �Ҳ����ظ� */
	struct packet_buffer *prev;
	struct packet_buffer *next;
};

#define HAVE_MULTI_TYPE_FLAG (1<<0)  /* ����������;�İ����� */

#define ALLOW_LINK_THREAD    (1<<3)  /* �������̷߳��ʶ��� */
#define ALLOW_TUN_THREAD     (1<<4)  /* ����TUN�̷߳��ʶ��� */
#define ALLOW_WORKER_THREAD  (1<<5)  /* �������̷߳��ʶ��� */
#define ALLOW_ANY_THREAD	(ALLOW_LINK_THREAD|ALLOW_TUN_THREAD|ALLOW_WORKER_THREAD)

struct packet_buffer_list
{
	volatile int size;  /* ��ǰ��Ŀ�� */
	int capacity;       /* buffer���� */
	uint32_t type;      /* �������б���; */
	uint32_t flags;     /* ����ָʾ, ����� */

	struct packet_buffer *head;
	struct packet_buffer *tail;

	/* Windows��free(...)����������, �����б��ڹ���packet_buffer���� */
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
		/* ����Ҫ���� CLEAR (buf->pin); */
		CLEAR (buf->pin);
		/* ����Ҫ���� CLEAR (buf->from); */
		CLEAR (buf->from);
#endif
		/* ����Ҫ���� buf_clear (&buf->buf); */
		/* ������, ��������, ���뱣�� */
	}
}

static inline void 
packet_buffer_drop (struct packet_buffer *buf, const uint32_t tracking)
{
	if (buf)
	{
		buf->buf.len = 0;	/* ������ */
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

	/* ���ܸ���type�� */
	/* ������, ����Ҫ���ƻ��ܸ��� */
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

/* �����Ҫ�ӽ��ܵ����ݰ�, ��key_idָ������Կ�ӽ��� */
int
packet_buffer_list_detach_front (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int key_id,
		int optimal_size);

/* ������Ѽӽ��ܵ��������ݰ�, next_seq_noָ������ʼ��� */
int
packet_buffer_list_detach_by_seq_no (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int64_t next_seq_no);

/* ������Ѽӽ��ܵ��������ݰ�, local_pinָ������ʼ����PIN */
int
packet_buffer_list_detach_by_local_pin (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int64_t local_pin);

#ifdef __cplusplus
}
#endif

#endif
