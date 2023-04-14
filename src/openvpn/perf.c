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

#include "error.h"
#include "otime.h"
#include "socket.h"
#include "openvpn.h"
#include "thread.h"
#include "perf.h"

#include "memdbg.h"

#ifdef ENABLE_PERFORMANCE_METRICS

static const char *metric_names[] = {
	"PERF_BIO_READ_PLAINTEXT",
	"PERF_BIO_WRITE_PLAINTEXT",
	"PERF_BIO_READ_CIPHERTEXT",
	"PERF_BIO_WRITE_CIPHERTEXT",
	"PERF_TLS_MULTI_PROCESS",
	"PERF_IO_WAIT",
	"PERF_EVENT_LOOP",
	"PERF_MULTI_CREATE_INSTANCE",
	"PERF_MULTI_CLOSE_INSTANCE",
	"PERF_MULTI_SHOW_STATS",
	"PERF_MULTI_BCAST",
	"PERF_MULTI_MCAST",
	"PERF_SCRIPT",
	"PERF_READ_IN_LINK",
	"PERF_PROC_IN_LINK",
	"PERF_READ_IN_TUN",
	"PERF_PROC_IN_TUN",
	"PERF_PROC_OUT_LINK",
	"PERF_PROC_OUT_TUN",
	"PERF_PROC_OUT_TUN_MTCP"
};

struct perf
{
# define PS_INITIAL            0
# define PS_METER_RUNNING      1
# define PS_METER_INTERRUPTED  2
	int state;

	struct timeval start;
	double sofar;
	double sum;
	double max;
	double count;
};

struct perf_set
{
	int stack_len;
	int stack[STACK_N];
	struct perf perf[PERF_N];
};

static struct perf_set perf_set[MAX_THREAD_INDEX] = {0};

static void perf_print_state (int lev, int thread_idx);

static inline int
get_stack_index (int sdelta, int thread_idx)
{
	const int sindex = perf_set[thread_idx].stack_len + sdelta;
	if (sindex >= 0 && sindex < STACK_N)
		return sindex;
	else
		return -1;
}

static int
get_perf_index (int sdelta, int thread_idx)
{
	const int sindex = get_stack_index (sdelta, thread_idx);
	if (sindex >= 0)
	{
		const int pindex = perf_set[thread_idx].stack[sindex];
		if (pindex >= 0 && pindex < PERF_N)
			return pindex;
		else
			return -1;
	}
	else
		return -1;
}

static struct perf *
get_perf (int sdelta, int thread_idx)
{
	const int pindex = get_perf_index (sdelta, thread_idx);
	if (pindex >= 0)
		return &perf_set[thread_idx].perf[pindex];
	else
		return NULL;
}

static void
push_perf_index (int pindex, int thread_idx)
{
	const int sindex = get_stack_index (0, thread_idx);
	const int newlen = get_stack_index (1, thread_idx);
	if (sindex >= 0 && newlen >= 0 && pindex >= 0 && pindex < PERF_N)
	{
		int i;
		for (i = 0; i < sindex; ++i)
		{
			if (perf_set[thread_idx].stack[i] == pindex)
			{
				perf_print_state (M_INFO, thread_idx);
				msg (M_FATAL, "PERF: push_perf_index %s failed", metric_names [pindex]);
				break;
			}
		}
		perf_set[thread_idx].stack[sindex] = pindex;
		perf_set[thread_idx].stack_len = newlen;
	}
	else
		msg (M_FATAL, "PERF: push_perf_index: stack push error"); 
}

static void
pop_perf_index (int thread_idx)
{
	const int newlen = get_stack_index (-1, thread_idx);
	if (newlen >= 0)
	{
		perf_set[thread_idx].stack_len = newlen;
	}
	else
		msg (M_FATAL, "PERF: pop_perf_index: stack pop error"); 
}

static void
state_must_be (const struct perf *p, const int wanted)
{
	if (p->state != wanted)
		msg (M_FATAL, "PERF: bad state actual=%d wanted=%d", p->state, wanted);
}

static void
update_sofar (struct perf *p)
{
	struct timeval current;
	ASSERT (!gettimeofday (&current, NULL));
	p->sofar += (double) tv_subtract (&current, &p->start, 600) / 1000000.0;
	tv_clear (&p->start);
}

static void
perf_start (struct perf *p)
{
	state_must_be (p, PS_INITIAL);
	ASSERT (!gettimeofday (&p->start, NULL));
	p->sofar = 0.0;
	p->state = PS_METER_RUNNING;
}

static void
perf_stop (struct perf *p)
{
	state_must_be (p, PS_METER_RUNNING);
	update_sofar (p);
	p->sum += p->sofar;
	if (p->sofar > p->max)
		p->max = p->sofar;
	p->count += 1.0;
	p->sofar = 0.0;
	p->state = PS_INITIAL;
}

static void
perf_interrupt (struct perf *p)
{
	state_must_be (p, PS_METER_RUNNING);
	update_sofar (p);
	p->state = PS_METER_INTERRUPTED;
}

static void
perf_resume (struct perf *p)
{
	state_must_be (p, PS_METER_INTERRUPTED);
	ASSERT (!gettimeofday (&p->start, NULL));
	p->state = PS_METER_RUNNING;
}

void
perf_push (int type)
{
	struct perf *prev;
	struct perf *cur;
	int thread_idx;
	
	ASSERT (SIZE (metric_names) == PERF_N);
	thread_idx = get_thread_index (pthread_self ());
	push_perf_index (type, thread_idx);

	prev = get_perf (-2, thread_idx);
	cur = get_perf (-1, thread_idx);

	ASSERT (cur);

	if (prev)
		perf_interrupt (prev);
	perf_start (cur);
}

void
perf_pop (void)
{
	int thread_idx;
	struct perf *prev, *cur;

	thread_idx = get_thread_index (pthread_self ());

	prev = get_perf (-2, thread_idx);
	cur = get_perf (-1, thread_idx);

	ASSERT (cur);
	perf_stop (cur);

	if (prev)
		perf_resume (prev);

	pop_perf_index (thread_idx);
}

void
perf_output_results (void)
{
	int i, thread_idx;

	thread_idx = get_thread_index (pthread_self ());
	msg (M_INFO, "LATENCY PROFILE (mean and max are in milliseconds)");
	for (i = 0; i < PERF_N; ++i)
	{
		struct perf *p = &perf_set[thread_idx].perf[i];
		if (p->count > 0.0)
		{
			const double mean = p->sum / p->count;
			msg (M_INFO, "%s n=%.0f mean=%.3f max=%.3f", metric_names[i], p->count, mean*1000.0, p->max*1000.0);
		}
	}
}

static void
perf_print_state (int lev, int thread_idx)
{
	struct gc_arena gc = gc_new ();
	int i;
	msg (lev, "PERF STATE");
	msg (lev, "Stack:");
	for (i = 0; i < perf_set[thread_idx].stack_len; ++i)
	{
		const int j = perf_set[thread_idx].stack[i];
		const struct perf *p = &perf_set[thread_idx].perf[j];
		msg (lev, "[%d] %s state=%d start=%s sofar=%f sum=%f max=%f count=%f",
			i,
			metric_names[j],
			p->state,
			tv_string (&p->start, &gc),
			p->sofar,
			p->sum,
			p->max,
			p->count);
	}
	gc_free (&gc);
}
#endif

#ifdef PERF_STATS_CHECK

static inline const char* 
lock_2_ascii (int c)
{
	switch (c)
	{
	case S_LINK_FREE_BUFS:
		return "LINK_FREE_BUFS";
	case S_TUN_FREE_BUFS :
		return "TUN_FREE_BUFS";
	case S_FRAG_FREE_BUFS:
		return "FRAG_FREE_BUFS";
	case S_TO_LINK_BUFS:
		return "TO_LINK_BUFS";
	case S_TO_TUN_BUFS:
		return "TO_TUN_BUFS";
	case S_READ_LINK_BUFS:
		return "READ_LINK_BUFS";
	case S_READ_TUN_BUFS:
		return "READ_TUN_BUFS";
	case S_READ_TUN_BUFS_PIN:
		return "READ_TUN_BUFS_PIN";
	case S_READ_TUN_BUFS_ENC:
		return "READ_TUN_BUFS_ENC";
	case S_READ_LINK_PENDINGS:
		return "READ_LINK_PENDINGS";
	case S_READ_TUN_PENDINGS:
		return "READ_TUN_PENDINGS";
	case S_TO_TUN_PENDINGS:
		return "TO_TUN_PENDINGS";
	case S_TO_LINK_PENDINGS:
		return "TO_LINK_PENDINGS";
	case S_VHASH:
		return "VHASH";
	case S_ITER:
		return "ITER";
	case S_FRAGMENT_OUT:
		return "FRAGMENT_OUT";
	case S_FRAGMENT_IN:
		return "FRAGMENT_IN";
	case S_SHARE_LOCK:
		return "SHARE_LOCK";
	case S_WORKER_THREAD:
		return "WORKER_THREAD";
	case S_ENCRYPT_DEVICE:
		return "ENCRYPT_DEVICE";
	case S_PF:
		return "PF";
	case S_REF_COUNT:
		return "REFCOUNT";
	case S_COARSE:
		return "COARSE";
	default:
		return "UNKNOWN";
	}
}

void
print_perf_status (const struct context *c, int thread_idx)
{
	struct gc_arena gc = gc_new ();
	struct buffer buf = alloc_buf_gc (ERR_BUF_SIZE, &gc);
	int i;
	struct lock_stats *lock_stat;

	buf_printf (&buf, "total=%lld, long_delay=%lld, short_delay=%lld, tiny_delay=%lld, max_delay=%d",
		g_packet_stats[thread_idx].total_counter,
		g_packet_stats[thread_idx].long_delay,
		g_packet_stats[thread_idx].short_delay,
		g_packet_stats[thread_idx].tiny_delay,
		g_packet_stats[thread_idx].max_delay);

	if (thread_idx == MAIN_THREAD_INDEX)
	{
#ifdef ENABLE_TUN_THREAD
		msg (M_INFO, "LINK ttl statistics %s", BSTR (&buf));
#else
		msg (M_INFO, "LINK/TUN TTL statistics %s", BSTR (&buf));
#endif
#ifdef TARGET_LINUX
		buf_reset_len (&buf);
		for (i = 0; i < MAX_OVERLAPPED_SIZE; ++i)
		{
			if (c->c2.link_socket->reads.stats[i] > 0)
				buf_printf (&buf, ", %d=%d", i, c->c2.link_socket->reads.stats[i]);
		}
		msg (M_INFO, "LINK recvmmsg statistics %s", BSTR (&buf));

		buf_reset_len (&buf);
		for (i = 0; i < MAX_OVERLAPPED_SIZE; ++i)
		{
			if (c->c2.link_socket->writes.stats[i] > 0)
				buf_printf (&buf, ", %d=%d", i, c->c2.link_socket->writes.stats[i]);
		}
		msg (M_INFO, "LINK sendmmsg statistics %s", BSTR (&buf));
#endif
	}
#ifdef ENABLE_TUN_THREAD
	else if (thread_idx == TUN_THREAD_INDEX)
	{
		msg (M_INFO, "TUN ttl statistics %s", BSTR (&buf));
	}
#endif

	buf_reset_len (&buf);
	for (i = 0; i < S_LOCK_CATEGORY_N; ++i)
	{
		lock_stat = &g_lock_stats[thread_idx][i];
		buf_printf (&buf, "\n%s, acquire_total=%lld, wait_total=%lld, total_wait_time=%lld, max_wait_time=%d, max_lock_time=%d",
			lock_2_ascii (i),
			lock_stat->acquire_total,
			lock_stat->wait_total,
			lock_stat->total_wait_time,
			lock_stat->max_wait_time,
			lock_stat->max_lock_time);
	}
	msg (M_INFO, "LOCK statistics thread_idx=%d%s", thread_idx, BSTR (&buf));

	gc_free (&gc);
}

#endif

