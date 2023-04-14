/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifdef ENABLE_FRAGMENT

#include "misc.h"
#include "options.h"
#include "openvpn.h"
#include "integer.h"
#include "fragment.h"
#include "thread.h"

#include "memdbg.h"

#define FRAG_ERR(s) { errmsg = s; goto error; }

static void
fragment_list_buf_init (struct fragment_list *list, const struct frame *frame)
{
	int i;
	for (i = 0; i < N_FRAG_BUF; ++i)
		list->fragments[i].buf = alloc_buf (BUF_SIZE (frame));
}

static void
fragment_list_buf_free (struct fragment_list *list)
{
	int i;
	for (i = 0; i < N_FRAG_BUF; ++i)
		free_buf (&list->fragments[i].buf);
}

static void
fragment_ttl_reap (struct fragment_master *f, time_t now_sec)
{
	int i;
	struct fragment *frag;
	for (i = 0; i < N_FRAG_BUF; ++i)
	{
		frag = &f->incoming.fragments[i];
		if (frag->defined && frag->timestamp + FRAG_TTL_SEC <= now_sec)
		{
			msg (D_FRAG_ERRORS, "FRAG TTL expired i=%d", i);
			frag->defined = false;
		}
	}
}

/*
 * Given a sequence ID number, get a fragment buffer. Use a sliding window, similar to packet_id code.
 */
static struct fragment *
fragment_list_get_buf (struct fragment_list *list, int seq_id)
{
	int diff;
	if (abs (diff = modulo_subtract (seq_id, list->seq_id, N_SEQ_ID)) >= N_FRAG_BUF)
	{
		int i;
		for (i = 0; i < N_FRAG_BUF; ++i)
			list->fragments[i].defined = false;
		list->index = 0;
		list->seq_id = seq_id;
		diff = 0;
	}
	while (diff > 0)
	{
		list->fragments[list->index = modulo_add (list->index, 1, N_FRAG_BUF)].defined = false;
		list->seq_id = modulo_add (list->seq_id, 1, N_SEQ_ID);
		--diff;
	}
	return &list->fragments[modulo_add (list->index, diff, N_FRAG_BUF)];
}

struct fragment_master *
fragment_init (struct frame *frame)
{
	struct fragment_master *ret;
	time_t local_now = now_sec (MAIN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	/* code that initializes other parts of fragment_master assume an initial CLEAR */
	ALLOC_OBJ_CLEAR (ret, struct fragment_master);

	/* add in the size of our contribution to the expanded frame size */
	frame_add_to_extra_frame (frame, sizeof (fragment_header_type));

	/*
	 * Outgoing sequence ID is randomized to reduce
	 * the probability of sequence number collisions
	 * when openvpn sessions are restarted.  This is
	 * not done out of any need for security, as all
	 * fragmentation control information resides
	 * inside of the encrypted/authenticated envelope.
	 */
	ret->outgoing_seq_id = (int) get_random () & (N_SEQ_ID - 1);

	event_timeout_init (&ret->wakeup, FRAG_WAKEUP_INTERVAL, local_now);

	return ret;
}

void
fragment_free (struct fragment_master *f)
{
	fragment_list_buf_free (&f->incoming);
	free_buf (&f->outgoing);
	free (f);
}

void
fragment_frame_init (struct fragment_master *f, const struct frame *frame)
{
	fragment_list_buf_init (&f->incoming, frame);
	f->outgoing = alloc_buf (BUF_SIZE (frame));
}

static inline void
do_fragment_incoming (struct context *c, struct fragment_master *f, fragment_header_type flags, int frag_type,
		struct packet_buffer *buf, const struct frame *frame, time_t now_sec)
{
	const char *errmsg = NULL;
	const int seq_id = ((flags >> FRAG_SEQ_ID_SHIFT) & FRAG_SEQ_ID_MASK);
	const int n = ((flags >> FRAG_ID_SHIFT) & FRAG_ID_MASK);
	const int size = ((frag_type == FRAG_YES_LAST)
		? (int) (((flags >> FRAG_SIZE_SHIFT) & FRAG_SIZE_MASK) << FRAG_SIZE_ROUND_SHIFT) : buf->buf.len);

	/* get the appropriate fragment buffer based on received seq_id */
	struct fragment *frag = NULL;

	/*
	 * Scanning incoming packet reassembly buffers for packets which have not yet been reassembled 
	 * completely but are already older than their time-to-live.
	 */
	if (f->wakeup.defined)
	{
		if (now_sec > f->wakeup.last + f->wakeup.n)
		{
			fragment_ttl_reap (f, now_sec);
			f->wakeup.last = now_sec;
		}
	}

	frag = fragment_list_get_buf (&f->incoming, seq_id);

	dmsg (D_FRAG_DEBUG, "FRAG_IN len=%d type=%d seq_id=%d frag_id=%d size=%d flags="
		fragment_header_format, buf->buf.len, frag_type, seq_id, n, size, flags);

	/* make sure that size is an even multiple of 1<<FRAG_SIZE_ROUND_SHIFT */
	if (size & FRAG_SIZE_ROUND_MASK)
		FRAG_ERR ("bad fragment size");

	/* is this the first fragment for our sequence number? */
	if (!frag->defined || (frag->defined && frag->max_frag_size != size))
	{
		frag->defined = true;
		frag->max_frag_size = size;
		frag->map = 0;
		ASSERT (buf_init (&frag->buf, FRAME_HEADROOM_ADJ (frame, FRAME_HEADROOM_MARKER_FRAGMENT)));
	}

	/* copy the data to fragment buffer */
	if (!buf_copy_range (&frag->buf, n * size, &buf->buf, 0, buf->buf.len))
		FRAG_ERR ("fragment buffer overflow");

	/* set elements in bit array to reflect which fragments have been received */
		frag->map |= (((frag_type == FRAG_YES_LAST) ? FRAG_MAP_MASK : 1) << n);

	/* update timestamp on partially built datagram */
	frag->timestamp = now_sec;

	/* received full datagram? */
	if ((frag->map & FRAG_MAP_MASK) == FRAG_MAP_MASK)
	{
		frag->defined = false;
		buf_assign (&buf->buf, &frag->buf);
		buf->flags |= PACKET_BUFFER_FRAG_LAST_FLAG;
	}
	else
	{
		buf->buf.len = 0;
	}

	return;

error:
	if (errmsg)
		msg (D_FRAG_ERRORS, "FRAG_IN error flags=" fragment_header_format ": %s", flags, errmsg);
	packet_buffer_drop (buf, PACKET_DROP_FRAGMENT_ERROR);
	buf->flags |= PACKET_BUFFER_FRAG_LAST_FLAG;
	return;
}

/*
 * Accept an incoming datagram (which may be a fragment) from remote.
 * If the datagram is whole (i.e not a fragment), pass through.
 * If the datagram is a fragment, join with other fragments received so far.
 * If a fragment fully completes the datagram, return the datagram.
 */
void
fragment_incoming (struct context *c, struct fragment_master *f, struct packet_buffer *buf,
		const struct frame *frame, time_t now_sec)
{
	const char *errmsg = NULL;
	int frag_type = 0;
	fragment_header_type flags = 0;

	if (buf->buf.len > 0)
	{
		/* get flags from packet head */
		if (!buf_read (&buf->buf, &flags, sizeof (flags)))
			FRAG_ERR ("flags not found in packet");
		flags = ntoh_fragment_header_type (flags);

		/* get fragment type from flags */
		frag_type = ((flags >> FRAG_TYPE_SHIFT) & FRAG_TYPE_MASK);

#if 0
		/* If you want to extract FRAG_EXTRA_MASK/FRAG_EXTRA_SHIFT bits, do it here. */
		if (frag_type == FRAG_WHOLE || frag_type == FRAG_YES_NOTLAST)
		{
		}
#endif

		/* handle the fragment type */
		if (frag_type == FRAG_WHOLE)
		{
			dmsg (D_FRAG_DEBUG, "FRAG_IN buf->len=%d type=FRAG_WHOLE flags="
				fragment_header_format, buf->buf.len, flags);

			if (flags & (FRAG_SEQ_ID_MASK | FRAG_ID_MASK))
				FRAG_ERR ("spurrious FRAG_WHOLE flags");
		}
		else if (frag_type == FRAG_YES_NOTLAST || frag_type == FRAG_YES_LAST)
		{
			do_fragment_incoming (c, f, flags, frag_type, buf, frame, now_sec);
		}
		else if (frag_type == FRAG_TEST)
		{
			FRAG_ERR ("FRAG_TEST not implemented");
		}
		else
		{
			FRAG_ERR ("unknown fragment type");
		}
	}

	return;

error:
	if (errmsg)
		msg (D_FRAG_ERRORS, "FRAG_IN error flags=" fragment_header_format ": %s", flags, errmsg);
	packet_buffer_drop (buf, PACKET_DROP_FRAGMENT_ERROR);
	buf->flags |= PACKET_BUFFER_FRAG_LAST_FLAG;
	return;
}

/*
 * Without changing the number of fragments, return a possibly smaller max fragment size
 * that will allow for the last fragment to be of similar size as previous fragments.
 */
static inline int
optimal_fragment_size (int len, int max_frag_size)
{
	const int mfs_aligned = (max_frag_size & ~FRAG_SIZE_ROUND_MASK);
	const int div = len / mfs_aligned;
	const int mod = len % mfs_aligned;

	if (div > 0 && mod > 0 && mod < mfs_aligned * 3 / 4)
		return min_int (mfs_aligned, (max_frag_size - ((max_frag_size - mod) / (div + 1))
			+ FRAG_SIZE_ROUND_MASK) & ~FRAG_SIZE_ROUND_MASK);
	else
		return mfs_aligned;
}

#define MIN_PREPARE_CHUNK_SIZE	64

static inline int
prepare_fragment_packet_buffer (struct context *c, int thread_idx, struct packet_buffer_list *ol, int min_size)
{
	if (ol->size < min_size)
	{
		const int optimal_size = max_int (c->options.packet_queue_len / c->options.worker_thread,
			MIN_PREPARE_CHUNK_SIZE);
		struct packet_buffer *buf;

#ifdef _DEBUG
		if (rand () % 100 == 0)	/* 测试动态分配packet_buffer */
		{		
			buf = packet_buffer_new (g_frag_free_bufs->capacity, g_frag_free_bufs->type);
			packet_buffer_list_push_back (ol, buf);
		}
#endif

		MUTEX_LOCK (g_frag_free_bufs_mutex, thread_idx, S_FRAG_FREE_BUFS);
		packet_buffer_list_split_front (g_frag_free_bufs, ol, optimal_size);
		MUTEX_UNLOCK (g_frag_free_bufs_mutex, thread_idx, S_FRAG_FREE_BUFS);

		while (ol->size < min_size)
		{
			buf = packet_buffer_new (g_frag_free_bufs->capacity, g_frag_free_bufs->type);
			packet_buffer_list_push_back (ol, buf);
		}
	}

	return ol->size;
}

/* process an outgoing datagram, possibly breaking it up into fragments */
void
fragment_outgoing (struct context *c, int thread_idx, struct fragment_master *f, struct packet_buffer *buf,
		const struct frame* frame, struct packet_buffer_list *frag_work_bufs, struct packet_buffer_list *work_bufs)
{
	int outgoing_frag_size = 0;
	const char *errmsg = NULL;

	ASSERT (buf->flags & PACKET_BUFFER_FRAG_CHK_FLAG || buf->flags & PACKET_BUFFER_FRAG_LAST_FLAG);

	if (buf->buf.len == 0 || (buf->flags & PACKET_BUFFER_FRAG_CHK_FLAG))
	{
		buf->flags |= PACKET_BUFFER_FRAG_CHK_FLAG;
		packet_buffer_list_push_back (work_bufs, buf);
	}
	else
	{
		buf->flags |= PACKET_BUFFER_FRAG_CHK_FLAG;
		if (buf->buf.len > PAYLOAD_SIZE_DYNAMIC (&c->c2.frame_fragment)) /* should we fragment? */
		{
			struct packet_buffer *frag_buf = buf;
			int i = 0, len = 0, key_id = buf->key_id;
			unsigned int flags = buf->flags, tracking = buf->buf.tracking;
			int64_t seq_no = buf->seq_no;
			struct link_socket_actual from = buf->from;
#ifdef PERF_STATS_CHECK
			struct timeval x, ttl = buf->ttl;
			unsigned int extra = buf->extra;

			x.tv_sec = MAX_PACKET_TTL / 1000000;
			x.tv_usec = MAX_PACKET_TTL % 1000000;
#endif

			/* Send the datagram as a series of 2 or more fragments. */
			outgoing_frag_size = optimal_fragment_size (buf->buf.len, PAYLOAD_SIZE_DYNAMIC (frame));
			if (buf->buf.len > outgoing_frag_size * MAX_FRAGS)
				FRAG_ERR ("too many fragments would be required to send datagram");

			/* 计算需要的额外分片缓存数目 */
			len = buf->buf.len - outgoing_frag_size;
			while (len > 0)
			{
				++i;
				len -= outgoing_frag_size;
			}

			/* 获取需要的额外的分片缓存 */
			prepare_fragment_packet_buffer (c, thread_idx, frag_work_bufs, i);

			/* Send the datagram as a series of 2 or more fragments. */
			f->outgoing_frag_size = outgoing_frag_size;

			/* The outgoing buffer should be empty so we can put new data in it */
			if (c->c2.fragment->outgoing.len)
				msg (D_FRAG_ERRORS, "FRAG: outgoing buffer is not empty, len=[%d,%d]",
					buf->buf.len, c->c2.fragment->outgoing.len);

			ASSERT (buf_init (&f->outgoing, FRAME_HEADROOM (frame)));
			ASSERT (buf_copy (&f->outgoing, &buf->buf));

			f->outgoing_seq_id = modulo_add (f->outgoing_seq_id, 1, N_SEQ_ID);
			f->outgoing_frag_id = 0;
			buf->buf.len = 0;

			do {
				packet_buffer_clear (frag_buf);
#ifdef PERF_STATS_CHECK
				frag_buf->ttl = ttl;
				if (frag_buf->ttl.tv_sec > 0)
					tv_add (&frag_buf->ttl, &x);	/* 增加分片TTL */
				frag_buf->extra = extra;
#endif
				frag_buf->flags = flags;
				frag_buf->seq_no = seq_no;
				frag_buf->key_id = key_id;
				frag_buf->from = from;

				ASSERT (fragment_ready_to_send (c->c2.fragment, frag_buf, &c->c2.frame_fragment));
				frag_buf->buf.tracking = tracking;
				packet_buffer_list_push_back (work_bufs, frag_buf);
				if (fragment_outgoing_defined (f))
					frag_buf = packet_buffer_list_pop_front (frag_work_bufs);
			} while (fragment_outgoing_defined (f));

			ASSERT (!fragment_outgoing_defined (f) && work_bufs->tail->flags & PACKET_BUFFER_FRAG_LAST_FLAG);
		}
		else
		{
			/* Send the datagram whole. */
			fragment_prepend_flags (&buf->buf, FRAG_WHOLE, 0, 0, 0);
			ASSERT (buf->flags & PACKET_BUFFER_FRAG_LAST_FLAG);
			packet_buffer_list_push_back (work_bufs, buf);
		}
	}

	return;

error:
	if (errmsg)
		msg (D_FRAG_ERRORS, "FRAG_OUT error, len=%d frag_size=%d MAX_FRAGS=%d: %s",
			buf->buf.len, outgoing_frag_size, MAX_FRAGS, errmsg);
	buf->flags |= PACKET_BUFFER_FRAG_CHK_FLAG;
	packet_buffer_drop (buf, PACKET_DROP_FRAGMENT_ERROR);
	ASSERT (buf->flags & PACKET_BUFFER_FRAG_LAST_FLAG);
	packet_buffer_list_push_back (work_bufs, buf);
	return;
}

/* return true (and set buf) if we have an outgoing fragment which is ready to send */
bool
fragment_ready_to_send (struct fragment_master *f, struct packet_buffer *buf, const struct frame* frame)
{
	if (fragment_outgoing_defined (f))
	{
		/* get fragment size, and determine if it is the last fragment */
		int size = f->outgoing_frag_size;
		bool last = false;
		if (f->outgoing.len <= size)
		{
			size = f->outgoing.len;
			last = true;
		}

		/* initialize return buffer */
		ASSERT (buf_init (&buf->buf, FRAME_HEADROOM (frame)));
		ASSERT (buf_copy_n (&buf->buf, &f->outgoing, size));

		buf->frag_id = f->outgoing_frag_id;
		if (last)
			buf->flags |= PACKET_BUFFER_FRAG_LAST_FLAG;
		else
			buf->flags &= ~PACKET_BUFFER_FRAG_LAST_FLAG;

		/* fragment flags differ based on whether or not we are sending the last fragment */
		fragment_prepend_flags (&buf->buf,
			last ? FRAG_YES_LAST : FRAG_YES_NOTLAST,
			f->outgoing_seq_id,
			f->outgoing_frag_id++,
			f->outgoing_frag_size);

		ASSERT (!last || !f->outgoing.len); /* outgoing buffer length should be zero after last fragment sent */

		return true;
	}
	else
		return false;
}

#else
static void dummy (void) {}
#endif
