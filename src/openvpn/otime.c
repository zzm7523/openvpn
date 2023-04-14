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

#include "otime.h"
#include "memdbg.h"

struct time_adj global_time_adjs[MAX_THREAD_INDEX] = {0};

#if TIME_BACKTRACK_PROTECTION

/*
 * Try to filter out time instability caused by the system
 * clock backtracking or jumping forward.
 */

void
update_now (const time_t system_time, int thread_idx)
{
	const int forward_threshold = 86400; /* threshold at which to dampen forward jumps */
	const int backward_trigger  = 10;    /* backward jump must be >= this many seconds before we adjust */
	struct time_adj *time_adj = &global_time_adjs[thread_idx];
	time_t real_time = system_time + time_adj->now_adj;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx && (sizeof (global_time_adjs[0]) & (CACHE_LINE_SIZE - 1)) == 0);
#endif

	if (real_time > time_adj->now_tv.tv_sec)
	{
		const time_t overshoot = real_time - time_adj->now_tv.tv_sec - 1;

		if (overshoot > forward_threshold && time_adj->now_adj >= overshoot)
		{
			time_adj->now_adj -= overshoot;
			real_time -= overshoot;
		}

		time_adj->now_tv.tv_sec = real_time;
	}
	else if (real_time < time_adj->now_tv.tv_sec - backward_trigger)
		time_adj->now_adj += (time_adj->now_tv.tv_sec - real_time);
}

void
update_now_usec (struct timeval *tv, int thread_idx)
{
	struct time_adj *time_adj = &global_time_adjs[thread_idx];
	const time_t last = time_adj->now_tv.tv_sec;

	update_now (tv->tv_sec, thread_idx);
	if (time_adj->now_tv.tv_sec > last || (time_adj->now_tv.tv_sec == last && tv->tv_usec > time_adj->now_tv.tv_usec))
	{
		time_adj->now_tv.tv_usec = tv->tv_usec;
	}
}

#endif /* TIME_BACKTRACK_PROTECTION */

/* 
 * Return a numerical string describing a struct timeval.
 */
const char *
tv_string (const struct timeval *tv, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (64, gc);
	buf_printf (&out, "[%d/%d]", (int) tv->tv_sec, (int) tv->tv_usec);
	return BSTR (&out);
}

/* 
 * Return an ascii string describing an absolute date/time in a struct timeval.
 */
const char *
tv_string_abs (const struct timeval *tv, struct gc_arena *gc)
{
	return time_string ((time_t) tv->tv_sec, (int) tv->tv_usec, true, gc);
}

/* format a time_t as ascii, or use current time if 0 */

const char *
time_string (time_t t, int usec, bool show_usec, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (64, gc);
	struct timeval tv;

	if (t)
	{
		tv.tv_sec = t;
		tv.tv_usec = usec;
	}
	else
	{
		gettimeofday (&tv, NULL);
	}

	t = tv.tv_sec;
	buf_printf (&out, "%s", ctime (&t));
	buf_rmtail (&out, '\n');

	if (show_usec && tv.tv_usec)
		buf_printf (&out, " us=%d", (int) tv.tv_usec);

	return BSTR (&out);
}

/*
 * Limit the frequency of an event stream.
 *
 * Used to control maximum rate of new incoming connections.
 */

struct frequency_limit *
frequency_limit_init (int max, int per)
{
	struct frequency_limit *f;

	ASSERT (max >= 0 && per >= 0);

	ALLOC_OBJ (f, struct frequency_limit);
	f->max = max;
	f->per = per;
	f->n = 0;
	f->reset = 0;
	return f;
}

void
frequency_limit_free (struct frequency_limit *f)
{
	free (f);
}

bool
frequency_limit_event_allowed (struct frequency_limit *f)
{
	if (f->per)
	{
		bool ret;
		if (now_sec (MAIN_THREAD_INDEX) >= f->reset + f->per)
		{
			f->reset = now_sec (MAIN_THREAD_INDEX);
			f->n = 0;
		}
		ret = (++f->n <= f->max);
		return ret;
	}
	else
		return true;
}

#ifdef TIME_TEST
void
time_test (void)
{
	struct timeval tv;
	time_t t;
	int i;
	for (i = 0; i < 10000; ++i)
	{
		t = time (NULL);
		gettimeofday (&tv, NULL);
#if 1
		msg (M_INFO, "t=%u s=%u us=%u",
			(unsigned int) t, (unsigned int) tv.tv_sec, (unsigned int) tv.tv_usec);
#endif
	}
}
#endif
