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

#include "buffer.h"
#include "error.h"
#include "win32.h"
#include "init.h"
#include "status.h"
#include "sig.h"
#include "occ.h"
#include "socket.h"
#include "manage.h"
#include "openvpn.h"
#include "thread.h"

#include "memdbg.h"

/* Handle signals */

struct signal_info siginfo_static; /* GLOBAL */

struct signame
{
	int value;
	const char *upper;
	const char *lower;
};

static const struct signame signames[] = {
	{ SIGINT,  "SIGINT",  "sigint"},
	{ SIGTERM, "SIGTERM", "sigterm" },
	{ SIGHUP,  "SIGHUP",  "sighup" },
	{ SIGUSR1, "SIGUSR1", "sigusr1" },
	{ SIGUSR2, "SIGUSR2", "sigusr2" }
};

int
parse_signal (const char *signame)
{
	int i;
	for (i = 0; i < (int) SIZE (signames); ++i)
	{
		if (!strcmp (signame, signames[i].upper))
			return signames[i].value;
	}
	return -1;
}

const char *
signal_name (const int sig, const bool upper)
{
	int i;
	for (i = 0; i < (int) SIZE (signames); ++i)
	{
		if (sig == signames[i].value)
			return upper ? signames[i].upper : signames[i].lower;
	}
	return "UNKNOWN";
}

const char *
signal_description (const int signum, const char *sigtext)
{
	if (sigtext)
		return sigtext;
	else
		return signal_name (signum, false);
}

void
throw_signal (const int signum)
{
	siginfo_static.signal_received = signum;
	siginfo_static.hard = true;
}

void
throw_signal_soft (const int signum, const char *signal_text)
{
	siginfo_static.signal_received = signum;
	siginfo_static.hard = false;
	siginfo_static.signal_text = signal_text;
}

static void
signal_reset (struct signal_info *si)
{
	if (si)
	{
		si->signal_received = 0;
		si->signal_text = NULL;
		si->hard = false;
	}
}

void
print_signal (const struct signal_info *si, const char *title, int msglevel)
{
	if (si)
	{
		const char *hs = (si->hard ? "hard" : "soft");
		const char *type = (const char *) (si->signal_text ? si->signal_text : "");
		const char *t = (title ? title : "process");

		switch (si->signal_received)
		{
		case SIGINT:
		case SIGTERM:
			msg (msglevel, "%s[%s,%s] received, %s exiting",
				signal_name (si->signal_received, true), hs, type, t);
			break;
		case SIGHUP:
		case SIGUSR1:
			msg (msglevel, "%s[%s,%s] received, %s restarting",
				signal_name (si->signal_received, true), hs, type, t);
			break;
		default:
			msg (msglevel, "Unknown signal %d [%s,%s] received by %s", si->signal_received, hs, type, t);
			break;
		}
	}
	else
		msg (msglevel, "Unknown signal received");
}

/*
 * Call management interface with restart info
 */
void
signal_restart_status (const struct signal_info *si)
{
#ifdef ENABLE_MANAGEMENT
	if (management)
	{
		int state = -1;
		switch (si->signal_received)
		{
		case SIGINT:
		case SIGTERM:
			state = OPENVPN_STATE_EXITING;
			break;
		case SIGHUP:
		case SIGUSR1:
			state = OPENVPN_STATE_RECONNECTING;
			break;
		}

		if (state >= 0)
		{
			management_set_state (management, state,
				si->signal_text ? (const char*) si->signal_text : signal_name (si->signal_received, true),
				(in_addr_t)0,
				(in_addr_t)0);
		}
	}
#endif
}

#ifdef HAVE_SIGNAL_H

/* normal signal handler, when we are in event loop */
static void
signal_handler (const int signum)
{
	throw_signal (signum);
	signal (signum, signal_handler);
}

#endif

/* set handlers for unix signals */

#ifdef HAVE_SIGNAL_H
#define SM_UNDEF     0
#define SM_PRE_INIT  1
#define SM_POST_INIT 2
static int signal_mode; /* GLOBAL */
#endif

void
pre_init_signal_catch (void)
{
#ifndef WIN32
#ifdef HAVE_SIGNAL_H
	signal_mode = SM_PRE_INIT;
	signal (SIGINT, signal_handler);
	signal (SIGTERM, signal_handler);
	signal (SIGHUP, SIG_IGN);
	signal (SIGUSR1, SIG_IGN);
	signal (SIGUSR2, SIG_IGN);
	signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGNAL_H */
#endif /* WIN32 */
}

void
post_init_signal_catch (void)
{
#ifndef WIN32
#ifdef HAVE_SIGNAL_H
	signal_mode = SM_POST_INIT;
	signal (SIGINT, signal_handler);
	signal (SIGTERM, signal_handler);
	signal (SIGHUP, signal_handler);
	signal (SIGUSR1, signal_handler);
	signal (SIGUSR2, signal_handler);
	signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGNAL_H */
#endif
}

/* called after daemonization to retain signal settings */
void
restore_signal_state (void)
{
#ifdef HAVE_SIGNAL_H
	if (signal_mode == SM_PRE_INIT)
		pre_init_signal_catch ();
	else if (signal_mode == SM_POST_INIT)
		post_init_signal_catch ();
#endif
}

/*
 * Print statistics.
 *
 * Triggered by SIGUSR2 or F2 on Windows.
 */
void
print_status (const struct context *c, struct status_output *so)
{
	struct gc_arena gc = gc_new ();
	int ret = 0;
	struct timeval tv = {0, 0};
	counter_type link_read_bytes_auth = 0L;
	counter_type tun_read_bytes = 0L;
	counter_type tun_write_bytes = 0L;
	counter_type pre_decompress = 0L;
	counter_type post_decompress = 0L;
	counter_type pre_compress = 0L;
	counter_type post_compress = 0L;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
	ASSERT (c->options.mode == MODE_POINT_TO_POINT);
#endif

	gettimeofday (&tv, NULL);

	link_read_auth_get_stats (c, &link_read_bytes_auth);
	tun_io_get_stats (c, &tun_read_bytes, &tun_write_bytes, NULL);

	status_reset (so);

	status_printf (so, "OpenVPN STATISTICS");
	status_printf (so, "Updated,%u,%s", (unsigned int) tv.tv_sec, time_string (tv.tv_sec, tv.tv_usec, false, &gc));
	status_printf (so, "TUN/TAP read bytes," counter_format, tun_read_bytes);
	status_printf (so, "TUN/TAP write bytes," counter_format, tun_write_bytes);
	status_printf (so, "TCP/UDP read bytes," counter_format, c->c2.link_read_bytes);
	status_printf (so, "TCP/UDP write bytes," counter_format, c->c2.link_write_bytes);
	status_printf (so, "Auth read bytes," counter_format, link_read_bytes_auth);

#ifdef ENABLE_LZO
	if (c->options.lzo & LZO_SELECTED)
	{
		lzo_get_stats (MAIN_THREAD_INDEX, &pre_decompress, &post_decompress, &pre_compress, &post_compress);
		status_printf (so, "pre-compress bytes," counter_format, pre_compress);
		status_printf (so, "post-compress bytes," counter_format, post_compress);
		status_printf (so, "pre-decompress bytes," counter_format, pre_decompress);
		status_printf (so, "post-decompress bytes," counter_format, post_decompress);
	}
#endif

#ifdef PACKET_TRUNCATION_CHECK
	status_printf (so, "TUN read truncations," counter_format, c->c2.n_trunc_tun_read);
	status_printf (so, "TUN write truncations," counter_format, c->c2.n_trunc_tun_write);
	status_printf (so, "Pre-encrypt truncations," counter_format, c->c2.n_trunc_pre_encrypt);
	status_printf (so, "Post-decrypt truncations," counter_format, c->c2.n_trunc_post_decrypt);
#endif

#ifdef WIN32
	if (tuntap_defined (c->c1.tuntap))
		status_printf (so, "TAP-WIN32 driver status,\"%s\"", tap_win_getinfo (c->c1.tuntap, &gc));
#endif

	status_printf (so, "END");
	status_flush (so);

	gc_free (&gc);
}

#ifdef ENABLE_OCC
/*
 * Handle the triggering and time-wait of explicit exit notification.
 */

static void
process_explicit_exit_notification_init (struct context *c)
{
	msg (M_INFO, "SIGTERM received, sending exit notification to peer");
	event_timeout_init (&c->c2.explicit_exit_notification_interval, 1, 0);
	reset_coarse_timers (c);
	signal_reset (c->sig);
	halt_non_edge_triggered_signals ();
	c->c2.explicit_exit_notification_time_wait = now_sec (MAIN_THREAD_INDEX);
}

void
process_explicit_exit_notification_timer_wakeup (struct context *c)
{
	if (event_timeout_trigger (&c->c2.explicit_exit_notification_interval, &c->c2.timeval, ETT_DEFAULT))
	{
		ASSERT (c->c2.explicit_exit_notification_time_wait && c->options.ce.explicit_exit_notification);

		if (now_sec (MAIN_THREAD_INDEX) >= c->c2.explicit_exit_notification_time_wait + c->options.ce.explicit_exit_notification)
		{
			event_timeout_clear (&c->c2.explicit_exit_notification_interval);
			c->sig->signal_received = SIGTERM;
			c->sig->signal_text = "exit-with-notification";
		}
		else
		{
			c->c2.occ_op = OCC_EXIT;
		}
	}
}
#endif

/*
 * Process signals
 */

void
remap_signal (struct context *c)
{
	if (c->sig->signal_received == SIGUSR1 && c->options.remap_sigusr1)
		c->sig->signal_received = c->options.remap_sigusr1;
}

static void
process_sigusr2 (const struct context *c)
{
	struct status_output *so = status_open (NULL, 0, M_INFO, NULL, 0);
	print_status (c, so);
	status_close (so);
	signal_reset (c->sig);
}

static bool
process_sigterm (struct context *c)
{
	bool ret = true;
#ifdef ENABLE_OCC
	if (c->options.ce.explicit_exit_notification && !c->c2.explicit_exit_notification_time_wait)
	{
		process_explicit_exit_notification_init (c);
		ret = false;
	}
#endif
	return ret;
}

/**
 * If a restart signal is received during exit-notification, reset the
 * signal and return true. If its a soft restart signal from the event loop
 * which implies the loop cannot continue, remap to SIGTERM to exit promptly.
 */
static bool
ignore_restart_signals (struct context *c)
{
	bool ret = false;
#ifdef ENABLE_OCC
	if ((c->sig->signal_received == SIGUSR1 || c->sig->signal_received == SIGHUP) &&
		event_timeout_defined (&c->c2.explicit_exit_notification_interval) )
	{
		if (c->sig->hard)
		{
			msg (M_INFO, "Ignoring %s received during exit notification",
				signal_name (c->sig->signal_received, true));
			signal_reset (c->sig);
			ret = true;
		}
		else
		{
			msg (M_INFO, "Converting soft %s received during exit notification to SIGTERM",
				signal_name (c->sig->signal_received, true));
			register_signal (c, SIGTERM, "exit-with-notification");
			ret = false;
		}
	}
#endif
	return ret;
}

bool
process_signal (struct context *c)
{
	bool ret = true;
	if (ignore_restart_signals (c))
		ret = false;
	else if (c->sig->signal_received == SIGTERM || c->sig->signal_received == SIGINT)
	{
		ret = process_sigterm (c);
	}
	else if (c->sig->signal_received == SIGUSR2)
	{
		process_sigusr2 (c);
		ret = false;
	}
	return ret;
}

void
register_signal (struct context *c, int sig, const char *text)
{
	if (c->sig->signal_received != SIGTERM)
		c->sig->signal_received = sig;
	c->sig->signal_text = text;
}
