#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "error.h"
#include "otime.h"
#include "socket.h"
#include "packet_buffer.h"
#include "thread.h"

#include "memdbg.h"

void
packet_buffer_dump (struct packet_buffer *buf, bool full, const char *prefix, struct gc_arena *gc)
{
	if (buf)
	{
		struct buffer out = alloc_buf_gc (1024 + 2 * (full ? buf->buf.len : 0), gc);
		if (prefix)
		{
			buf_printf (&out, "%s, ", prefix);
		}
		buf_printf (&out,
			"seq_no=%"PRIu64", local_pin=%"PRIu64", pin=%u, %u, local_key_id=%"PRIu64", key_id=%d, frag_id=%d, flags=%u, type=%d\n",
			buf->seq_no, buf->local_pin, buf->pin.id, (unsigned int) buf->pin.time, buf->local_key_id, buf->key_id, buf->frag_id,
			buf->flags, buf->type);
#ifdef PERF_STATS_CHECK
		buf_printf (&out, ", extra=%u, ttl=%d", buf->extra, buf->ttl);
#endif
		fprintf (stdout, "%s, buf->buf.len=%d, buf->buf.tracking=%u\n", BSTR (&out), buf->buf.len, buf->buf.tracking);
		if (full)
		{
			fprintf (stdout, "%s\n", print_link_socket_actual (&buf->from, gc));
			fprintf (stdout, "%s\n", format_hex (BPTR (&buf->buf), BLEN (&buf->buf), 80, gc));		
		}
	}
}

struct packet_buffer_list*
packet_buffer_list_new (int capacity, int size, int type, unsigned int flags)
{
	struct packet_buffer_list *ret;

	ASSERT (capacity > 0 && capacity <= BUF_SIZE_MAX && size >= 0 && size <= MAX_PACKET_BUFFER_LIST);
	ASSERT (type & PACKET_BUFFER_FOR_LINK || type & PACKET_BUFFER_FOR_TUN || type & PACKET_BUFFER_FOR_FRAG);

	ALLOC_OBJ_CLEAR (ret, struct packet_buffer_list);

	return packet_buffer_list_init (ret, capacity, size, type, flags);
}

void
packet_buffer_list_free (struct packet_buffer_list *ol)
{
	if (ol)
	{
		packet_buffer_list_destroy (ol);
		free (ol);
	}
}

struct packet_buffer_list*
packet_buffer_list_init (struct packet_buffer_list *ol, int capacity, int size, int type, unsigned int flags)
{
	ASSERT (ol && capacity > 0 && capacity <= BUF_SIZE_MAX && size >= 0 && size <= MAX_PACKET_BUFFER_LIST);
	ASSERT (type & PACKET_BUFFER_FOR_LINK || type & PACKET_BUFFER_FOR_TUN || type & PACKET_BUFFER_FOR_FRAG);

	CLEAR (*ol);
	ol->capacity = capacity;
	ol->type = type;
	ol->flags = flags;

	if (size > 0)
	{
		struct packet_buffer *buf;
		int i;

		/* Windows下free(...)性能有问题, 采用列表内管理packet_buffer对象 */
		ALLOC_ARRAY_CLEAR (ol->allocator, struct packet_buffer, size);
		ol->allocator_size = size;

		for (i = 0;  i < size; ++i)
		{
			buf = ol->allocator + i;
			buf->managed = true;
			buf->type = type;
			buf->buf = alloc_buf (capacity);
			buf->local_pin = -1;
			buf->local_key_id = -1;
			buf->key_id = -1;
			buf->frag_id = -1;

			packet_buffer_list_push_back (ol, buf);
		}
	}

	return ol;
}

void
packet_buffer_list_destroy (struct packet_buffer_list *ol)
{
	if (ol)
	{
		struct packet_buffer *e;
		
		ASSERT (ol->size == ol->allocator_size);

		e = ol->head;
		while (e)
		{
			ASSERT (e->managed);

			free_buf (&e->buf);	/* 释放 buffer */
			e = e->next;
			--ol->size;
		}		

		ASSERT (ol->size == 0);

		if (ol->allocator)
			free (ol->allocator);
		ol->allocator = NULL;
		ol->allocator_size = ol->size = 0;
	}
}

#ifdef PACKET_BUFFER_LIST_CHECK
void 
packet_buffer_list_check (struct packet_buffer_list *ol, struct timeval *now_tv, unsigned int of, int check,
		int line, const char *filename)
{
	int i = 0;
	struct packet_buffer *s = NULL, *x = NULL, *e = NULL;
	bool hav_eq_seq_no = false, hav_gt_seq_no = false;

	ASSERT (ol);

	if ((ol->head && ol->head->prev) || (ol->tail && ol->tail->next))
		ASSERT (0);
	if ((ol->head && !ol->tail) || (!ol->head && ol->tail))
		ASSERT (0);
	if (ol->tail && ol->tail != ol->head && !ol->tail->prev)
		ASSERT (0);
	if (ol->size < 0 || ol->size > MAX_PACKET_BUFFER_LIST)
		ASSERT (0);

	e = ol->head;
	while (e)
	{
#ifdef PERF_STATS_CHECK
		packet_buffer_trace (e, now_tv, line, filename);
#endif

		ASSERT (e->type & ol->type && e->buf.data != NULL);
		if (check & PACKET_BUFFER_KEY_ID_EQUAL) /* 检查key_id是否相等 */
		{
			ASSERT (s == NULL || e->key_id == s->key_id);
			ASSERT (x == NULL || e->key_id == x->key_id);
		}

		if (check & PACKET_BUFFER_NOT_EMPTY) /* 检查数据包内容是否为空 */
			ASSERT (e->buf.len > 0);

		if (check & PACKET_BUFFER_HAVE_SEQ)	/* SEQ_NO是否有效 */
			ASSERT (e->seq_no >= 0);

#ifdef PACKET_TTL_CHECK
		if (check & PACKET_BUFFER_NOT_EXPIRE) /* 检查TTL是否到期 */
			ASSERT (e->buf.len <= 0 || e->ttl.tv_sec <= 0 || tv_gt (&e->ttl, now_tv));
#endif

		if (check & PACKET_BUFFER_IS_ORDER)	/* 检查数据包序号是否有序 */
		{
			if (of & PACKET_BUFFER_ORDER_BY_SEQ)
				ASSERT (s == NULL || e->seq_no == 0 || e->seq_no > s->seq_no ||
					(e->seq_no == s->seq_no && e->frag_id > s->frag_id));
			if (of & PACKET_BUFFER_ORDER_BY_PIN)
			{
				ASSERT (x == NULL || e->local_pin < 0 || e->local_pin > x->local_pin);
				ASSERT (x == NULL || e->local_pin < 0 || e->buf.len <= 0 ||
					(e->pin.id <= 0 && x->pin.id <= 0 /* 未启用抗重放保护 */) ||
					(e->pin.id > x->pin.id || e->pin.time > x->pin.time /* 启用抗重放保护 */));
			}
		}

		if (check & PACKET_BUFFER_IS_LINEAR) /* 检查数据包序号是否线性 */
		{
			if (of & PACKET_BUFFER_ORDER_BY_SEQ)
				ASSERT (s == NULL || e->seq_no == 0 || e->seq_no == s->seq_no + 1 ||
					(e->seq_no == s->seq_no && e->frag_id > s->frag_id));
			if (of & PACKET_BUFFER_ORDER_BY_PIN)
			{
				ASSERT (x == NULL || e->local_pin < 0 || e->local_pin == x->local_pin + 1);
				ASSERT (x == NULL || e->local_pin < 0 || e->buf.len <= 0 || x->buf.len <= 0 ||
					(e->pin.id <= 0 && x->pin.id <= 0 /* 未启用抗重放保护 */) ||
					(e->pin.id == x->pin.id + 1 || (e->pin.time > x->pin.time && e->pin.id == 1) /* 启用抗重放保护 */));
			}
		}

		if (e->seq_no == 0)
			hav_eq_seq_no = true;
		else if (e->seq_no > 0)
			hav_gt_seq_no = true;

		if (e->seq_no > 0)
			s = e;
		if (e->local_pin > 0)
			x = e;

		++i;
		e = e->next;
	}

	if (of & PACKET_BUFFER_NOT_MIX_SEQ)	/* 检查是否混合seq_no == 0和seq_no > 0的包 */
		ASSERT (!(hav_eq_seq_no && hav_gt_seq_no));

	ASSERT (i == ol->size);	/* 检测链表是否有效 */
}
#endif

void
packet_buffer_list_attach_by_seq_no (struct packet_buffer_list *ol, struct packet_buffer_list *xl)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && xl && ol->type & xl->type && ol->capacity == xl->capacity);
#endif

	if (xl->size > 0)
	{
		if (ol->head)
		{
			struct packet_buffer *insert = ol->head, *seq_no_left = xl->head;

			/* SEQ_NO有序, 通过SEQ_NO定位插入点 */
			while (seq_no_left && seq_no_left->seq_no == 0)
				seq_no_left = seq_no_left->next;

			if (seq_no_left)
			{				
				do {
					if (insert->seq_no <= 0 || insert->seq_no < seq_no_left->seq_no ||
						(insert->seq_no == seq_no_left->seq_no && insert->frag_id < seq_no_left->frag_id))
					{
						insert = insert->next;
					}
					else
						break;
				} while (insert);
			}

			if (insert) /* 插入insert前面 */
			{
				if (insert->prev)
				{
					insert->prev->next = xl->head;
					xl->head->prev = insert->prev;
				}
				else
					ol->head = xl->head;
				insert->prev = xl->tail;
				xl->tail->next = insert;
			}
			else /* 插入ol->tail后面 */
			{
				ol->tail->next = xl->head;
				xl->head->prev = ol->tail;
				ol->tail = xl->tail;
			}
		}
		else
		{
			ol->head = xl->head;
			ol->tail = xl->tail;
		}

		ol->size += xl->size;
		xl->size = 0;
		xl->head = xl->tail = NULL;
	}
}

void
packet_buffer_list_attach_by_local_pin (struct packet_buffer_list *ol, struct packet_buffer_list *xl)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && xl && ol->type & xl->type && ol->capacity == xl->capacity);
#endif

	if (xl->size > 0)
	{
		if (ol->head)
		{
			struct packet_buffer *insert = ol->head, *pin_left = xl->head;

			/* PIN有序, 通过PIN定位插入点 */
			do {
#ifdef PACKET_BUFFER_LIST_CHECK
				ASSERT (insert->local_pin > 0 && pin_left->local_pin > 0);
#endif
				if (insert->local_pin < pin_left->local_pin)
					insert = insert->next;
				else
					break;
			} while (insert);

			if (insert) /* 插入insert前面 */
			{
				if (insert->prev)
				{
					insert->prev->next = xl->head;
					xl->head->prev = insert->prev;
				}
				else
					ol->head = xl->head;
				insert->prev = xl->tail;
				xl->tail->next = insert;
			}
			else /* 插入ol->tail后面 */
			{
				ol->tail->next = xl->head;
				xl->head->prev = ol->tail;
				ol->tail = xl->tail;
			}
		}
		else
		{
			ol->head = xl->head;
			ol->tail = xl->tail;
		}

		ol->size += xl->size;
		xl->size = 0;
		xl->head = xl->tail = NULL;
	}
}

/* xl中, 不允许seq_no == 0包和seq_no > 0的包混杂在一起, 必须包括包的所有分片 */
int
packet_buffer_list_detach_front (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int key_id, int optimal_size)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && xl && ol->type & xl->type && optimal_size > 0 && ol->capacity == xl->capacity);
#endif

	if (ol->size > 0 && xl->size < optimal_size)
	{
		struct packet_buffer *e = ol->head, *p = NULL;

		while (e && ((e->key_id < 0 && key_id < 0) || e->key_id == key_id) && 
			(!p || p->seq_no == e->seq_no || p->seq_no + 1 == e->seq_no))
		{
			--ol->size;
			++xl->size;

			p = e;
			e = e->next;

			/* xl中, 不允许seq_no == 0包和seq_no > 0的包混杂在一起, 必须包括包的所有分片 */
			if (p->flags & PACKET_BUFFER_FRAG_CHK_FLAG)
			{
				if ((p->flags & PACKET_BUFFER_FRAG_LAST_FLAG) && (p->seq_no == 0 || xl->size >= optimal_size))
					break;
			}
			else
			{
				if (p->seq_no == 0 || xl->size >= optimal_size)
					break;
			}
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

#ifdef PACKET_BUFFER_LIST_CHECK
		ASSERT (xl->size > 0 && xl->tail->flags & PACKET_BUFFER_FRAG_LAST_FLAG);
#endif
	}

	return xl->size;
}

/* xl中, 允许seq_no == 0包和seq_no > 0的包混杂在一起 */
int
packet_buffer_list_detach_by_seq_no (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int64_t next_seq_no)
{
#ifdef PACKET_BUFFER_LIST_CHECK
	ASSERT (ol && xl && ol->type & xl->type && ol->capacity == xl->capacity);
#endif

	if (ol->size > 0 && (ol->head->seq_no == 0 || ol->head->seq_no == next_seq_no))
	{
		struct packet_buffer *e = ol->head, *p = NULL;

		while (e && (e->seq_no == 0 || e->seq_no == next_seq_no))
		{
			if (e->seq_no > 0 && e->flags & PACKET_BUFFER_FRAG_LAST_FLAG)
				++next_seq_no;

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

int
packet_buffer_list_detach_by_local_pin (struct packet_buffer_list *ol, struct packet_buffer_list *xl, int64_t local_pin)
{
	if (ol->size > 0 && ol->head->local_pin == local_pin)
	{
		struct packet_buffer *p = NULL, *e = ol->head;

		do {
			--ol->size;
			++xl->size;
			p = e;
			e = e->next;

		} while (e && e->local_pin == ++local_pin);
		
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
