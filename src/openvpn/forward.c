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

#include "gremlin.h"
#include "forward.h"
#include "init.h"
#include "push.h"
#include "mss.h"
#include "event.h"
#include "ps.h"
#include "dhcp.h"
#include "common.h"

#include "thread.h"
#include "multi_crypto.h"
#include "socket-inline.h"
#include "multi.h"
#include "tun-inline.h"
#include "forward-inline.h"
#include "occ-inline.h"
#include "ping-inline.h"
#include "mstats.h"
#include "masquerade.h"

#ifdef WIN32
#include <sys/timeb.h>
#endif

#ifdef ENABLE_GUOMI
#include <openssl/encrypt_device.h>
#endif

#include "memdbg.h"

counter_type link_read_bytes_global = 0L;  /* GLOBAL */
counter_type link_write_bytes_global = 0L; /* GLOBAL */

/* show event wait debugging info */

#ifdef ENABLE_DEBUG

const char *
wait_status_string (struct context *c, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (64, gc);
	buf_printf (&out, "I/O WAIT %s|%s|%s|%s %s",
		tun_stat (c->c1.tuntap, EVENT_READ, gc),
		tun_stat (c->c1.tuntap, EVENT_WRITE, gc),
		socket_stat (c->c2.link_socket, EVENT_READ, gc),
		socket_stat (c->c2.link_socket, EVENT_WRITE, gc),
		tv_string (&c->c2.timeval, gc));
	return BSTR (&out);
}

void
show_wait_status (struct context *c)
{
	struct gc_arena gc = gc_new ();
	dmsg (D_EVENT_WAIT, "%s", wait_status_string (c, &gc));
	gc_free (&gc);
}

#endif

/*
 * In TLS mode, let TLS level respond to any control-channel
 * packets which were received, or prepare any packets for
 * transmission.
 *
 * tmp_int is purely an optimization that allows us to call
 * tls_multi_process less frequently when there's not much
 * traffic on the control-channel.
 *
 */
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
void
check_tls_dowork (struct context *c)
{
	interval_t wakeup = BIG_TIMEOUT;
	int tmp_status;

	if (interval_test (&c->c2.tmp_int))
	{
		/* 阻止其它线程访问context */
		RWLOCK_WRLOCK (&c->share_lock, MAIN_THREAD_INDEX, S_SHARE_LOCK);

		tmp_status = tls_multi_process (c->c2.tls_multi, &c->c2.to_link, &c->c2.to_link_addr,
			get_link_socket_info (c), &wakeup);

		if (tmp_status == TLSMP_ACTIVE)
		{
			update_time (MAIN_THREAD_INDEX);
			interval_action (&c->c2.tmp_int);
		}
		else if (tmp_status == TLSMP_KILL)
		{
			if (c->options.tls_server)
				/* 服务端不能通过信号立即退出, 可能有认证错误需要发送到客户端, 采用调度退出 */
				schedule_exit (c, c->options.scheduled_exit_interval, SIGTERM);
			else
				register_signal (c, SIGTERM, "auth-control-exit");
		}
		
		/* 允许其它线程访问context */
		RWLOCK_UNLOCK (&c->share_lock, MAIN_THREAD_INDEX, S_SHARE_LOCK);

		interval_future_trigger (&c->c2.tmp_int, wakeup);
	}

	interval_schedule_wakeup (&c->c2.tmp_int, &wakeup);

	if (wakeup)
		context_reschedule_sec (c, wakeup);
}
#endif

#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)

void
check_tls_errors_co (struct context *c)
{
	if (c->options.tls_server)
	{
		/* 服务端不能通过信号立即退出, 可能有TLS警告需要发送到客户端, 采用调度退出 */
		if (!event_timeout_defined (&c->c2.scheduled_exit) || c->c2.scheduled_exit_signal == 0)
		{
			msg (D_STREAM_ERRORS, "Fatal TLS error (check_tls_errors_co), restarting");
			c->c2.tls_multi->n_soft_errors = 0;
			schedule_exit (c, c->options.scheduled_exit_interval, c->c2.tls_exit_signal);
		}
	}
	else
	{
		/* 客户端通过信号立即退出, TLS警告不需要发送到服务端 */
		register_signal (c, c->c2.tls_exit_signal, "tls-error"); /* SOFT-SIGUSR1 -- TLS error */
	}
}

void
check_tls_errors_nco (struct context *c)
{
	if (c->options.tls_server)
	{
		/* 服务端不能通过信号立即退出, 可能有TLS警告需要发送到客户端, 改用调度退出 */
		if (!event_timeout_defined (&c->c2.scheduled_exit) || c->c2.scheduled_exit_signal == 0)
		{
			c->c2.tls_multi->n_hard_errors = 0;
			schedule_exit (c, c->options.scheduled_exit_interval, c->c2.tls_exit_signal);
		}
	}
	else
	{
		/* 客户端通过信号立即退出, TLS警告不需要发送到服务端 */
		register_signal (c, c->c2.tls_exit_signal, "tls-error"); /* SOFT-SIGUSR1 -- TLS error */
	}
}

#endif

#if P2MP

/* Handle incoming configuration messages on the control channel. */
void
check_incoming_control_channel_dowork (struct context *c)
{
	const int len = tls_test_payload_len (c->c2.tls_multi);
	if (len)
	{
		struct gc_arena gc = gc_new ();
		struct buffer buf = alloc_buf_gc (len, &gc);

		if (tls_rec_payload (c->c2.tls_multi, &buf))
		{
			/* force null termination of message */
			buf_null_terminate (&buf);

			/* enforce character class restrictions, CC_PRINT改为CC_PRINT | CC_BLANK, 增加\t支持 */
			string_mod (BSTR (&buf), CC_PRINT | CC_BLANK, CC_CRLF, 0);

			if (buf_string_match_head_str (&buf, "AUTH_FAILED"))
				receive_auth_failed (c, &buf);
			else if (buf_string_match_head_str (&buf, "PUSH_"))
				incoming_push_message (c, &buf);
			else if (buf_string_match_head_str (&buf, "RESTART"))
				server_pushed_signal (c, &buf, true, 7);
			else if (buf_string_match_head_str (&buf, "HALT"))
				server_pushed_signal (c, &buf, false, 4);
			else
				msg (D_PUSH_ERRORS, "WARNING: Received unknown control message: %s", BSTR (&buf));
		}
		else
		{
			msg (D_PUSH_ERRORS, "WARNING: Receive control message failed");
		}

		gc_free (&gc);
	}
}

/* Periodically resend PUSH_REQUEST until PUSH message received */
void
check_push_request_dowork (struct context *c)
{
	send_push_request (c);

	/* if no response to first push_request, retry at PUSH_REQUEST_INTERVAL second intervals */
	event_timeout_modify_wakeup (&c->c2.push_request_interval, PUSH_REQUEST_INTERVAL);
}

#endif /* P2MP */

/* Things that need to happen immediately after connection initiation should go here. */
void
check_connection_established_dowork (struct context *c)
{
	if (event_timeout_trigger (&c->c2.wait_for_connect, &c->c2.timeval, ETT_DEFAULT))
	{
		if (CONNECTION_ESTABLISHED (c))
		{
#if P2MP
			/* if --pull was specified, send a push request to server */
			if (c->c2.tls_multi && c->options.pull)
			{
#ifdef ENABLE_MANAGEMENT
				if (management)
					management_set_state (management, OPENVPN_STATE_GET_CONFIG, NULL, 0, 0);
#endif
				/* send push request in 1 sec */
				event_timeout_init (&c->c2.push_request_interval, 1, now_sec (MAIN_THREAD_INDEX));
				reset_coarse_timers (c);
			}
			else
#endif
			{
				do_up (c, false, 0);
			}

			event_timeout_clear (&c->c2.wait_for_connect);
		}
	}
}

/*
 * Send a string to remote over the TLS control channel.
 * Used for push/pull messages, passing username/password, etc.
 */
bool
send_control_channel_string (struct context *c, const char *str, int msglevel)
{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
	if (c->c2.tls_multi) {
		struct gc_arena gc = gc_new ();
		bool stat;

		/* buffered cleartext write onto TLS control channel */
		stat = tls_send_payload (c->c2.tls_multi, (uint8_t*) str, (int) strlen (str) + 1);

		/*
		 * Reschedule tls_multi_process.
		 * NOTE: in multi-client mode, usually the below two statements are
		 * insufficient to reschedule the client instance object unless
		 * multi_schedule_context_wakeup (m, mi) is also called.
		 */
		interval_action (&c->c2.tmp_int);
		context_immediate_reschedule (c); /* ZERO-TIMEOUT */

		msg (msglevel, "SENT CONTROL [%s]: '%s' (status=%d)", tls_common_name (c->c2.tls_multi, false),
			sanitize_control_message (str, &gc), (int) stat);

		gc_free (&gc);
		return stat;
	}
#endif
	return true;
}

/* Add routes. */
static void
check_add_routes_action (struct context *c, const bool errors)
{
	do_route (&c->options, c->c1.route_list, c->c1.route_ipv6_list, c->c1.tuntap, c->plugins, c->c2.es);
	update_time (MAIN_THREAD_INDEX);
	event_timeout_clear (&c->c2.route_wakeup);
	event_timeout_clear (&c->c2.route_wakeup_expire);
	initialization_sequence_completed (c, errors ? ISC_ERRORS : 0); /* client/p2p --route-delay was defined */
}

void
check_add_routes_dowork (struct context *c)
{
	static time_t last_ping_rec_interval_reset = 0;	/* 记录上一次的调用时间, 减少锁定频率 */

	if (test_routes (c->c1.route_list, c->c1.tuntap))
	{
		check_add_routes_action (c, false);
	}
	else if (event_timeout_trigger (&c->c2.route_wakeup_expire, &c->c2.timeval, ETT_DEFAULT))
	{
		check_add_routes_action (c, true);
	}
	else
	{
		msg (D_ROUTE, "Route: Waiting for TUN/TAP interface to come up...");
		if (c->c1.tuntap)
		{
			if (!tun_standby (c->c1.tuntap))
			{
				register_signal (c, SIGHUP, "ip-fail");
				c->persist.restart_sleep_seconds = 10;
#ifdef WIN32
				show_routes (M_INFO|M_NOPREFIX);
				show_adapters (M_INFO|M_NOPREFIX);
#endif
			}
		}

		update_time (MAIN_THREAD_INDEX);
		if (c->c2.route_wakeup.n != 1)
			event_timeout_init (&c->c2.route_wakeup, 1, now_sec (MAIN_THREAD_INDEX));

		/* reset packet received timer */
		if (c->options.ping_rec_timeout && now_sec (MAIN_THREAD_INDEX) > last_ping_rec_interval_reset)
		{
			last_ping_rec_interval_reset = now_sec (MAIN_THREAD_INDEX);
			ping_rec_interval_reset (c, MAIN_THREAD_INDEX, now_sec (MAIN_THREAD_INDEX));
		}
	}
}

/*
 * Should we exit due to inactivity timeout?
 */
void
check_inactivity_timeout_dowork (struct context *c)
{
	msg (M_INFO, "Inactivity timeout (--inactive), exiting");
	register_signal (c, SIGTERM, "inactive");
}

#if P2MP

void
check_server_poll_timeout_dowork (struct context *c)
{
	update_time (MAIN_THREAD_INDEX);
	event_timeout_reset (&c->c2.server_poll_interval, now_sec (MAIN_THREAD_INDEX));
	ASSERT (c->c2.tls_multi);
	if (!tls_initial_packet_received (c->c2.tls_multi))
	{
		msg (M_INFO, "Server poll timeout, restarting");
		register_signal (c, SIGUSR1, "server_poll");
		c->persist.restart_sleep_seconds = -1;
	}
}

/*
 * Schedule a signal n_seconds from now.
 */
void
schedule_exit (struct context *c, const int n_seconds, const int signal)
{
	tls_set_single_session (c->c2.tls_multi);
	update_time (MAIN_THREAD_INDEX);
	reset_coarse_timers (c);
	event_timeout_init (&c->c2.scheduled_exit, n_seconds, now_sec (MAIN_THREAD_INDEX));
	c->c2.scheduled_exit_signal = signal;
	msg (D_SCHED_EXIT, "Delayed exit in %d seconds", n_seconds);
}

/*
 * Scheduled exit?
 */
void
check_scheduled_exit_dowork (struct context *c)
{
	register_signal (c, c->c2.scheduled_exit_signal, "delayed-exit");
}

#endif

/*
 * Should we write timer-triggered status file.
 */
void
check_status_file_dowork (struct context *c)
{
	if (c->c1.status_output)
	{
		print_status (c, c->c1.status_output);
	}
}

#ifdef ENABLE_GUOMI
static inline void
check_encrypt_device (struct context *c)
{
	unsigned long open_flags = 0;
	ENCRYPT_DEVICE_PROVIDER *provider;

	provider = ENCRYPT_DEVICE_PROVIDER_get ();
	if (provider)
	{
		if (event_timeout_trigger (&c->c2.device_check_interval, &c->c2.timeval, ETT_DEFAULT)) 
			ENCRYPT_DEVICE_recover_all (provider, open_flags);
	}
}
#endif

/*
 * Coarse timers work to 1 second resolution.
 */
static void
process_coarse_timers (struct context *c)
{
#ifdef ENABLE_CRYPTO
	/* flush current packet-id to file once per 60 seconds if --replay-persist was specified */
	check_packet_id_persist_flush (c);
#endif

	/* should we update status file? */
	check_status_file (c);

#ifdef ENABLE_GUOMI
	check_encrypt_device (c);
#endif

	/* process connection establishment items */
	check_connection_established (c);

#if P2MP
	/* see if we should send a push_request in response to --pull */
	check_push_request (c);
#endif

#ifdef PLUGIN_PF
	pf_check_reload (c);
#endif

	/* process --route options */
	check_add_routes (c);

	/* possibly exit due to --inactive */
	check_inactivity_timeout (c);
	if (c->sig->signal_received)
		return;

	/* restart if ping not received */
	check_ping_restart (c);
	if (c->sig->signal_received)
		return;

#if P2MP
	check_server_poll_timeout (c);
	if (c->sig->signal_received)
		return;

	check_scheduled_exit (c);
	if (c->sig->signal_received)
		return;
#endif

#ifdef ENABLE_OCC
	/* Should we send an OCC_REQUEST message? */
	check_send_occ_req (c);

	/* Should we send an MTU load test? */
	check_send_occ_load_test (c);

	/* Should we send an OCC_EXIT message to remote? */
	if (c->c2.explicit_exit_notification_time_wait)
		process_explicit_exit_notification_timer_wakeup (c);
#endif

	/* Should we ping the remote? */
	check_ping_send (c);
}

static void
check_coarse_timers_dowork (struct context *c)
{
	const struct timeval save = c->c2.timeval;

	c->c2.timeval.tv_sec = BIG_TIMEOUT;
	c->c2.timeval.tv_usec = 0;
	process_coarse_timers (c);
	c->c2.coarse_timer_wakeup = now_sec (MAIN_THREAD_INDEX) + c->c2.timeval.tv_sec; 

	dmsg (D_INTERVAL, "TIMER: coarse timer wakeup %d seconds", (int) c->c2.timeval.tv_sec);

	/* Is the coarse timeout NOT the earliest one? */
	if (c->c2.timeval.tv_sec > save.tv_sec)
		c->c2.timeval = save;
}

static inline void
check_coarse_timers (struct context *c)
{
	const time_t local_now = now_sec (MAIN_THREAD_INDEX);

	if (local_now >= c->c2.coarse_timer_wakeup)
		check_coarse_timers_dowork (c);
	else
		context_reschedule_sec (c, (int) (c->c2.coarse_timer_wakeup - local_now));
}

static void
check_timeout_random_component_dowork (struct context *c)
{
	const int update_interval = 10; /* seconds */

	c->c2.update_timeout_random_component = now_sec (MAIN_THREAD_INDEX) + update_interval;
	c->c2.timeout_random_component.tv_usec = (time_t) get_random () & 0x0003FFFF;
	c->c2.timeout_random_component.tv_sec = 0;

	dmsg (D_INTERVAL, "RANDOM USEC=%d", (int) c->c2.timeout_random_component.tv_usec);
}

static inline void
check_timeout_random_component (struct context *c)
{
	if (now_sec (MAIN_THREAD_INDEX) >= c->c2.update_timeout_random_component)
		check_timeout_random_component_dowork (c);
	if (c->c2.timeval.tv_sec >= 1)
		tv_add (&c->c2.timeval, &c->c2.timeout_random_component);
}

#ifdef ENABLE_SOCKS

/*
 * Handle addition and removal of the 10-byte Socks5 header in UDP packets.
 */

static inline void
socks_postprocess_incoming_link (struct context *c, struct packet_buffer *buf)
{
	if (c->c2.link_socket->socks_proxy && c->c2.link_socket->info.proto == PROTO_UDPv4)
		socks_process_incoming_udp (&buf->buf, &buf->from);
}

static inline void
socks_preprocess_outgoing_link (struct context *c, struct packet_buffer *buf, struct link_socket_actual **to_addr,
		int *size_delta)
{
	if (c->c2.link_socket->socks_proxy && c->c2.link_socket->info.proto == PROTO_UDPv4)
	{
		*size_delta += socks_process_outgoing_udp (&buf->buf, c->c2.to_link_addr);
		*to_addr = &c->c2.link_socket->socks_relay;
	}
}

/* undo effect of socks_preprocess_outgoing_link */
static inline void
link_socket_write_post_size_adjust (int *size, int size_delta, struct buffer *buf)
{
	if (size_delta > 0 && *size > size_delta)
	{
		*size -= size_delta;
		if (!buf_advance (buf, size_delta))
			*size = 0;
	}
}
#endif

/*
 * Output: c->c2.buf
 */

int
read_incoming_link (struct context *c, struct packet_buffer *buf, unsigned int flags)
{
	/* Set up for recvfrom call to read datagram sent to our TCP/UDP port. */
	int status;

	/* ASSERT (!buf->buf.len); */

	perf_push (PERF_READ_IN_LINK);

	ASSERT (buf_init (&buf->buf, FRAME_HEADROOM_ADJ (&c->c2.frame, FRAME_HEADROOM_MARKER_READ_LINK)));

	status = link_socket_read (c->c2.link_socket, &buf->buf, &buf->from, flags);

	if (socket_connection_reset (c->c2.link_socket, status))
	{
#if PORT_SHARE
		if (port_share && socket_foreign_protocol_detected (c->c2.link_socket))
		{
			const struct buffer *fbuf = socket_foreign_protocol_head (c->c2.link_socket);
			const int sd = socket_foreign_protocol_sd (c->c2.link_socket);

			port_share_redirect (port_share, fbuf, sd);
			register_signal (c, SIGTERM, "port-share-redirect");
#ifdef _DEBUG
			msg (M_INFO, "port-share-redirect, context ...");
#endif
		}
		else
#endif
		{
			/* received a disconnect from a connection-oriented protocol */
			if (c->options.inetd)
			{
				register_signal (c, SIGTERM, "connection-reset-inetd");
				msg (D_STREAM_ERRORS, "Connection reset, inetd/xinetd exit [%d]", status);
			}
			else
			{
#ifdef ENABLE_OCC
				if (event_timeout_defined (&c->c2.explicit_exit_notification_interval))
				{
					msg (D_STREAM_ERRORS, "Connection reset during exit notification period, ignoring [%d]", status);
					openvpn_sleep (1);
				}
				else
#endif
				{
					register_signal (c, SIGUSR1, "connection-reset"); /* SOFT-SIGUSR1 -- TCP connection reset */
					msg (D_STREAM_ERRORS, "Connection reset, restarting [%d]", status);
				}
			}
		}
		perf_pop ();
		return -1;
	}

	/* check recvfrom status */
	check_status (status, "read", c->c2.link_socket, NULL);

#ifdef ENABLE_SOCKS
	/* Remove socks header if applicable */
	socks_postprocess_incoming_link (c, buf);
#endif

#ifdef ENABLE_MASQUERADE
	if (BLEN (&buf->buf) > 0)
	{
		/* 读取后, 需解除内容伪装 */
		if (unmasquerade_link_buffer (&buf->buf, c->c1.masq_options) < 0)
			msg (D_LINK_ERRORS, "remove the masquerade error, packet size %d", BLEN (&buf->buf));
	}
#endif

	perf_pop ();
	return status;
}

/*
 * Input:  c->c2.buf
 * Output: c->c2.to_tun
 */

void
process_incoming_link (struct context *c, struct packet_buffer *buf)
{
	static time_t last_ping_rec_interval_reset = 0;	/* 记录上一次的调用时间, 减少锁定频率 */
	struct gc_arena gc = gc_new ();
	struct link_socket_info *lsi = get_link_socket_info (c);

	perf_push (PERF_PROC_IN_LINK);

	if (buf->buf.len > 0)
	{
		/* link_read_bytes_global, c->c2.link_read_bytes 只有主线程访问 */
		c->c2.link_read_bytes += buf->buf.len;
		link_read_bytes_global += buf->buf.len;

#ifdef ENABLE_MEMSTATS
		if (mmap_stats)
			mmap_stats->link_read_bytes = link_read_bytes_global;
#endif
		c->c2.original_recv_size = buf->buf.len;

#ifdef ENABLE_MANAGEMENT
		if (management)
		{
			management_bytes_in (management, buf->buf.len);
#ifdef MANAGEMENT_DEF_AUTH
			management_bytes_server (management, (counter_type *) &c->c2.link_read_bytes,
				(counter_type *) &c->c2.link_write_bytes, &c->c2.mda_context);
#endif
		}
#endif
	}
	else
		c->c2.original_recv_size = 0;

#ifdef ENABLE_DEBUG
	/* take action to corrupt packet if we are in gremlin test mode */
	if (c->options.gremlin)
	{
		if (!ask_gremlin (c->options.gremlin))
			packet_buffer_drop (buf, PACKET_DROP_CORRUPT_GREMLIN);
		corrupt_gremlin (&buf->buf, c->options.gremlin);
	}
#endif

	/* log incoming packet */
#ifdef LOG_RW
	if (c->c2.log_rw && buf->buf.len > 0)
		fprintf (stderr, "R");
#endif
	msg (D_LINK_RW, "%s READ [%d] from %s: %s", proto2ascii (lsi->proto, true), BLEN (&buf->buf),
		print_link_socket_actual (&buf->from, &gc), PROTO_DUMP (&buf->buf, &gc));

	/*
	 * Good, non-zero length packet received. Commence multi-stage processing of packet,
	 * such as authenticate, decrypt, decompress.
	 * If any stage fails, it sets buf.len to 0 or -1,
	 * telling downstream stages to ignore the packet.
	 */
	if (buf->buf.len > 0)
	{
		if (!link_socket_verify_incoming_addr (&buf->buf, lsi, &buf->from))
			link_socket_bad_incoming_addr (&buf->buf, lsi, &buf->from);

#ifdef ENABLE_CRYPTO
#ifdef ENABLE_SSL
		if (c->c2.tls_multi)
		{
			/*
			 * If tls_pre_decrypt returns true, it means the incoming packet was
			 * a good TLS control channel packet.  If so, TLS code will deal
			 * with the packet and set buf.len to 0 so downstream stages ignore it.
			 *
			 * If the packet is a data channel packet, tls_pre_decrypt will load
			 * crypto_options with the correct encryption key and return false.
			 */
			if (tls_pre_decrypt (c, buf))
			{
				buf->flags |= PACKET_BUFFER_TLS_PACKET_FLAG;
				interval_action (&c->c2.tmp_int);

				update_time (MAIN_THREAD_INDEX);
				/* reset packet received timer if TLS packet */
				if (c->options.ping_rec_timeout && now_sec (MAIN_THREAD_INDEX) > last_ping_rec_interval_reset)
				{
					last_ping_rec_interval_reset = now_sec (MAIN_THREAD_INDEX);
					ping_rec_interval_reset (c, MAIN_THREAD_INDEX, now_sec (MAIN_THREAD_INDEX));
				}
			}
		}
#if P2MP_SERVER
		/* Drop non-TLS packet if client-connect script/plugin has not yet succeeded. */
		if (c->c2.context_auth != CAS_SUCCEEDED)
			packet_buffer_drop (buf, PACKET_DROP_SCRIPT_NOT_SUCCEEDED);
#endif
#endif /* ENABLE_SSL */
#endif /* ENABLE_CRYPTO */

		/* 包可能已篡改, 工作线程解密时才能识别; 不能在这里重置c->c2.ping_rec_interval对象 */

		if (buf->buf.len > 0)
			c->c2.max_recv_size_local = max_int (c->c2.original_recv_size, c->c2.max_recv_size_local);

		/* 其它代码移到工作线程 */
	}

	perf_pop ();
	gc_free (&gc);
}

/*
 * Output: c->c2.buf
 */

int
read_incoming_tun (struct context *c, struct packet_buffer *buf)
{
	/* Setup for read() call on TUN/TAP device. */
	/*ASSERT (!c->c2.to_link.len);*/

	perf_push (PERF_READ_IN_TUN);

	if (!c->c1.tuntap)
		return -1;

#ifdef TUN_PASS_BUFFER
	buf->buf.len = read_tun_buffered (c->c1.tuntap, &buf->buf, MAX_RW_SIZE_TUN (&c->c2.frame));
#else
	ASSERT (buf_init (&buf->buf, FRAME_HEADROOM (&c->c2.frame)));
	ASSERT (buf_safe (&buf->buf, MAX_RW_SIZE_TUN (&c->c2.frame)));
	buf->buf.len = read_tun (c->c1.tuntap, BPTR (&buf->buf), MAX_RW_SIZE_TUN (&c->c2.frame));
#endif

#ifdef PACKET_TRUNCATION_CHECK
	ipv4_packet_size_verify (BPTR (&buf->buf), BLEN (&buf->buf), TUNNEL_TYPE (c->c1.tuntap),
		"READ_TUN", &c->c2.n_trunc_tun_read);
#endif

	/* Was TUN/TAP interface stopped? */
	if (tuntap_stop (buf->buf.len))
	{
		register_signal (c, SIGTERM, "tun-stop");
		msg (M_INFO, "TUN/TAP interface has been stopped, exiting");
		perf_pop ();
		return -1;		  
	}

	/* Was TUN/TAP I/O operation aborted? */
	if (tuntap_abort (buf->buf.len))
	{
		register_signal (c, SIGHUP, "tun-abort");
		c->persist.restart_sleep_seconds = 10;
		msg (M_INFO, "TUN/TAP I/O operation aborted, restarting");
		perf_pop ();
		return -1;
	}

	/* Check the status return from read() */
	check_status (buf->buf.len, "read from TUN/TAP", NULL, c->c1.tuntap);

	perf_pop ();
	return buf->buf.len;
}

/**
 * Drops UDP packets which OS decided to route via tun.
 *
 * On Windows and OS X when netwotk adapter is disabled or
 * disconnected, platform starts to use tun as external interface.
 * When packet is sent to tun, it comes to openvpn, encapsulated
 * and sent to routing table, which sends it again to tun.
 */
static void
drop_if_recursive_routing (struct context *c, struct packet_buffer *buf)
{
	bool drop = false;
	struct openvpn_sockaddr tun_sa;
	int proto_ver, ip_hdr_offset = 0;

	if (c->c2.to_link_addr == NULL) /* no remote addr known */
		return;

	tun_sa = c->c2.to_link_addr->dest;

	proto_ver = get_tun_ip_ver (TUNNEL_TYPE (c->c1.tuntap), &buf->buf, &ip_hdr_offset);

	if (proto_ver == 4)
	{
		const struct openvpn_iphdr *pip;

		/* make sure we got whole IP header */
		if (BLEN (&buf->buf) < ((int) sizeof (struct openvpn_iphdr) + ip_hdr_offset))
			return;

		/* skip ipv4 packets for ipv6 tun */
		if (tun_sa.addr.sa.sa_family != AF_INET)
			return;

		pip = (struct openvpn_iphdr *) (BPTR (&buf->buf) + ip_hdr_offset);

		/* drop packets with same dest addr as gateway */
		if (tun_sa.addr.in4.sin_addr.s_addr == pip->daddr)
			drop = true;
	}
	else if (proto_ver == 6)
	{
		const struct openvpn_ipv6hdr *pip6;

		/* make sure we got whole IPv6 header */
		if (BLEN (&buf->buf) < ((int) sizeof (struct openvpn_ipv6hdr) + ip_hdr_offset))
			return;

		/* skip ipv6 packets for ipv4 tun */
		if (tun_sa.addr.sa.sa_family != AF_INET6)
			return;

		/* drop packets with same dest addr as gateway */
		pip6 = (struct openvpn_ipv6hdr *) (BPTR (&buf->buf) + ip_hdr_offset);
		if (IN6_ARE_ADDR_EQUAL (&tun_sa.addr.in6.sin6_addr, &pip6->daddr))
			drop = true;
	}

	if (drop)
	{
		struct gc_arena gc = gc_new ();

		buf->buf.len = 0;
		msg (D_LOW, "Recursive routing detected, drop tun packet to %s",
			print_link_socket_actual (c->c2.to_link_addr, &gc));
		gc_free (&gc);
	}
}

/*
 * Input:  c->c2.buf
 * Output: c->c2.to_link
 */

void
process_incoming_tun (struct context *c, struct timeval *now_tv, struct packet_buffer *buf)
{
	struct gc_arena gc = gc_new ();

	perf_push (PERF_PROC_IN_TUN);

	if (buf->buf.len > 0)
	{
		c->c2.tun_read_bytes += buf->buf.len;
		tun_io_sync_stats (c, TUN_THREAD_INDEX, now_tv->tv_sec);
	}

#ifdef LOG_RW
	if (c->c2.log_rw && buf->buf.len > 0)
		fprintf (stderr, "r");
#endif

	/* Show packet content */
	dmsg (D_TUN_RW, "TUN READ [%d]", BLEN (&buf->buf));

	if (buf->buf.len > 0)
	{
		if ((c->options.mode == MODE_POINT_TO_POINT) && (!c->options.allow_recursive_routing))
			drop_if_recursive_routing (c, buf);

		/* The --passtos and --mssfix options require us to examine the IP header (IPv4 or IPv6). */
		process_ip_header (c, PIPV4_PASSTOS|PIP_MSSFIX|PIPV4_CLIENT_NAT, &buf->buf);

#ifdef PACKET_TRUNCATION_CHECK
		/* if (c->c2.buf.len > 1) --c->c2.buf.len; */
		ipv4_packet_size_verify (BPTR (&buf->buf), BLEN (&buf->buf), TUNNEL_TYPE (c->c1.tuntap),
			"PRE_ENCRYPT", &c->c2.n_trunc_pre_encrypt);
#endif

#if P2MP_SERVER
		if (c->c2.context_auth != CAS_SUCCEEDED)
			packet_buffer_drop (buf, PACKET_DROP_SCRIPT_NOT_SUCCEEDED);
#endif

		/* 加密移到工作线程处理 */
	}

	perf_pop ();
	gc_free (&gc);
}

void
process_ip_header (struct context *c, unsigned int flags, struct buffer *buf)
{
	if (!c->options.ce.mssfix)
		flags &= ~PIP_MSSFIX;
#if PASSTOS_CAPABILITY
	if (!c->options.passtos)
		flags &= ~PIPV4_PASSTOS;
#endif
	if (!c->options.route_gateway_via_dhcp)
		flags &= ~PIPV4_EXTRACT_DHCP_ROUTER;

	if (buf->len > 0)
	{
		/* The --passtos and --mssfix options require us to examine the IPv4 header. */
#if PASSTOS_CAPABILITY
		if (flags & (PIPV4_PASSTOS|PIP_MSSFIX))
#else
		if (flags & PIP_MSSFIX)
#endif
		{
			struct buffer ipbuf = *buf;
			if (is_ipv4 (TUNNEL_TYPE (c->c1.tuntap), &ipbuf))
			{
#if PASSTOS_CAPABILITY
				/* extract TOS from IP header */
				if (flags & PIPV4_PASSTOS)
					link_socket_extract_tos (c->c2.link_socket, &ipbuf);
#endif

				/* possibly alter the TCP MSS */
				if (flags & PIP_MSSFIX)
					mss_fixup_ipv4 (&ipbuf, MTU_TO_MSS (TUN_MTU_SIZE_DYNAMIC (&c->c2.frame)));

#ifdef ENABLE_CLIENT_NAT
				/* possibly do NAT on packet */
				if ((flags & PIPV4_CLIENT_NAT) && c->options.client_nat)
				{
					const int direction = (flags & PIPV4_OUTGOING) ? CN_INCOMING : CN_OUTGOING;
					client_nat_transform (c->options.client_nat, &ipbuf, direction);
				}
#endif
				/* possibly extract a DHCP router message */
				if (flags & PIPV4_EXTRACT_DHCP_ROUTER)
				{
					const in_addr_t dhcp_router = dhcp_extract_router_msg (&ipbuf);
					if (dhcp_router)
						route_list_add_vpn_gateway (c->c1.route_list, c->c2.es, dhcp_router);
				}
			}
			else if (is_ipv6 (TUNNEL_TYPE (c->c1.tuntap), &ipbuf))
			{
				/* possibly alter the TCP MSS */
				if (flags & PIP_MSSFIX)
					mss_fixup_ipv6 (&ipbuf, MTU_TO_MSS (TUN_MTU_SIZE_DYNAMIC (&c->c2.frame)));
			}
		}
	}
}

void
process_outgoing_link_tls (struct context *c)
{
	if (c->c2.to_link.len > 0 && c->c2.to_link.len <= EXPANDED_SIZE (&c->c2.frame))
	{
		struct packet_buffer *buf = NULL, *head = NULL;

#ifdef THREAD_ACCESS_CHECK
		ASSERT (is_main_thread ());	/* 只有主线程能访问c->c2.buffers->link_write_bufs变量 */
#endif

		buf = get_link_read_packet_buffer (c, true);
		buf_assign (&buf->buf, &c->c2.to_link);
		/* tls、ping、occ、bcast, unicast包的seq_no统一设置为0 */
		buf->seq_no = 0;
		buf->flags |= (PACKET_BUFFER_TLS_PACKET_FLAG | PACKET_BUFFER_FRAG_LAST_FLAG);

		/* 不能放在link_write_bufs列表头部, 因为link_write_bufs头部数据包可能没有完整写出 */
		head = packet_buffer_list_pop_front (c->c2.buffers->link_write_bufs);
		packet_buffer_list_push_front (c->c2.buffers->link_write_bufs, buf);
		if (head)
			packet_buffer_list_push_front (c->c2.buffers->link_write_bufs, head);
	}

	buf_reset (&c->c2.to_link);
}

int
process_outgoing_link_data (struct context *c, struct packet_buffer *buf, unsigned int flags)
{
	struct gc_arena gc = gc_new ();
	int size = 0, orig_size = buf->buf.len;

	perf_push (PERF_PROC_OUT_LINK);

	/* Setup for call to send/sendto which will send packet to remote over the TCP/UDP port. */
	if (!link_socket_actual_defined (c->c2.to_link_addr))
		packet_buffer_drop (buf, PACKET_DROP_SOCKET_NOT_DEFINED);

	if (buf->buf.len > 0 && buf->buf.len <= EXPANDED_SIZE (&c->c2.frame))
	{
#ifdef ENABLE_DEBUG
		/* In gremlin-test mode, we may choose to drop this packet */
		if (!c->options.gremlin || ask_gremlin (c->options.gremlin))
#endif
		{
			/* Let the traffic shaper know how many bytes we wrote. */
#ifdef ENABLE_FEATURE_SHAPER
			if (c->options.shaper)
				shaper_wrote_bytes (&c->c2.shaper, BLEN (&buf->buf) + datagram_overhead (c->options.ce.proto));
#endif
			/* Let the pinger know that we sent a packet. */
			if (c->options.ping_send_timeout)
			{
				update_time (MAIN_THREAD_INDEX);
				event_timeout_reset (&c->c2.ping_send_interval, now_sec (MAIN_THREAD_INDEX));
			}

#if PASSTOS_CAPABILITY
			/* Set TOS */
			link_socket_set_tos (c->c2.link_socket);
#endif

			/* Log packet send */
#ifdef LOG_RW
			if (c->c2.log_rw)
				fprintf (stderr, "W");
#endif
			msg (D_LINK_RW, "%s WRITE [%d] to %s: %s", proto2ascii (c->c2.link_socket->info.proto, true),
				BLEN (&buf->buf), print_link_socket_actual (c->c2.to_link_addr, &gc),
				PROTO_DUMP (&buf->buf, &gc));

#ifdef ENABLE_MASQUERADE
			if (!(buf->flags & PACKET_BUFFER_MASQUERADE_FLAG))
			{
				/* 写出前, 需先做内容伪装 */
				buf->flags |= PACKET_BUFFER_MASQUERADE_FLAG;
				if (masquerade_link_buffer (&buf->buf, c->c1.masq_options) < 0)
					msg (D_LINK_ERRORS, "masquerade error, packet size %d", BLEN (&buf->buf));
			}
#endif

			/* Packet send complexified by possible Socks5 usage */
			{
#ifdef ENABLE_SOCKS
				/* If Socks5 over UDP, prepend header */
				int size_delta = 0;
				socks_preprocess_outgoing_link (c, buf, &c->c2.to_link_addr, &size_delta);
#endif
				if (proto_is_tcp (c->c2.link_socket->info.proto) && !(buf->flags & PACKET_BUFFER_TCP_PREPEND_FLAG))
				{
					packet_size_type len = BLEN (&buf->buf);
					dmsg (D_STREAM_DEBUG, "STREAM: WRITE %d offset=%d", (int) len, buf->buf.offset);
					ASSERT (len > 0 && len <= c->c2.link_socket->stream_buf.maxlen);
					len = htonps (len);
					ASSERT (buf_write_prepend (&buf->buf, &len, sizeof (len)));
					buf->flags |= PACKET_BUFFER_TCP_PREPEND_FLAG;
					orig_size = buf->buf.len;
				}

				/* Send packet */
				size = link_socket_write (c->c2.link_socket, &buf->buf, c->c2.to_link_addr, flags);
				/* TCP 可能一次调用不能写出完整数据包, 调整偏移和大小 */
				if (size > 0)
					buf_advance (&buf->buf, size);

#ifdef ENABLE_SOCKS
				/* Undo effect of prepend */
				link_socket_write_post_size_adjust (&size, size_delta, &buf->buf);
#endif
			}

			if (size > 0
#ifdef TARGET_LINUX 
				&& !(flags & OVERLAPPED_PACKET_INVALID)
#endif
				)
			{
				c->c2.max_send_size_local = max_int (orig_size, c->c2.max_send_size_local);
				c->c2.link_write_bytes += size;
				link_write_bytes_global += size;
#ifdef ENABLE_MEMSTATS
				if (mmap_stats)
					mmap_stats->link_write_bytes = link_write_bytes_global;
#endif
#ifdef ENABLE_MANAGEMENT
				if (management)
				{
					management_bytes_out (management, size);
#ifdef MANAGEMENT_DEF_AUTH
					management_bytes_server (management, (counter_type *) &c->c2.link_read_bytes,
						(counter_type *) &c->c2.link_write_bytes, &c->c2.mda_context);
#endif
				}
#endif
			}
		}

		/* Check return status */
		if (size < 0)
		{
#ifdef WIN32
			packet_buffer_drop (buf, PACKET_DROP_WRITE_ERROR);
#else
			const int my_errno = openvpn_errno ();
			if (my_errno == EAGAIN || my_errno == EWOULDBLOCK)
				;	/* 发送缓冲不足, 稍后重发包 */
			else
				/* 链路发包错误, 例如: Message too long (code=90); 丢弃包 */
				packet_buffer_drop (buf, PACKET_DROP_WRITE_ERROR);
#endif
		}
		
		check_status (size, "write", c->c2.link_socket, NULL);

		if (size > 0)
		{
			/* Did we write a different size packet than we intended? */
			if (size != orig_size && proto_is_udp (c->c2.link_socket->info.proto))
				msg (D_LINK_ERRORS, "TCP/UDP packet was truncated/expanded on write to %s (tried=%d,actual=%d)",
					print_link_socket_actual (c->c2.to_link_addr, &gc), orig_size, size);

			/* if not a ping/control message, indicate activity regarding --inactive parameter */
			register_activity (c, size, MAIN_THREAD_INDEX);
		}
	}
	else
	{
		if (buf->buf.len > 0)
			msg (D_LINK_ERRORS, "TCP/UDP packet too large on write to %s (tried=%d,max=%d)",
				print_link_socket_actual (c->c2.to_link_addr, &gc), buf->buf.len, EXPANDED_SIZE (&c->c2.frame));

		packet_buffer_drop (buf, PACKET_DROP_WRITE_ERROR);
		size = -1;
	}

	perf_pop ();
	gc_free (&gc);

	return size;
}

/*
 * Input: c->c2.to_tun
 */

int
process_outgoing_tun (struct context *c, struct timeval *now_tv, struct packet_buffer *buf)
{
	int size;
	struct gc_arena gc = gc_new ();

	/* Set up for write() call to TUN/TAP device. */
	if (!c->c1.tuntap || buf->buf.len <= 0)
		return -1;

	perf_push (PERF_PROC_OUT_TUN);

	/* The --mssfix option requires us to examine the IP header (IPv4 or IPv6). */
	process_ip_header (c, PIP_MSSFIX|PIPV4_EXTRACT_DHCP_ROUTER|PIPV4_CLIENT_NAT|PIPV4_OUTGOING, &buf->buf);

	if (buf->buf.len > 0 && buf->buf.len <= MAX_RW_SIZE_TUN (&c->c2.frame))
	{
		/* Write to TUN/TAP device. */

#ifdef LOG_RW
		if (c->c2.log_rw)
			fprintf (stderr, "w");
#endif
		dmsg (D_TUN_RW, "TUN WRITE [%d]", BLEN (&buf->buf));

#ifdef PACKET_TRUNCATION_CHECK
		ipv4_packet_size_verify (BPTR (&buf->buf), BLEN (&buf->buf), TUNNEL_TYPE (c->c1.tuntap),
			"WRITE_TUN", &c->c2.n_trunc_tun_write);
#endif

#ifdef TUN_PASS_BUFFER
		size = write_tun_buffered (c->c1.tuntap, &buf->buf);
#else
		size = write_tun (c->c1.tuntap, BPTR (&buf->buf), BLEN (&buf->buf));
#endif

		if (size > 0)
		{
			c->c2.tun_write_bytes += size;
			tun_io_sync_stats (c, TUN_THREAD_INDEX, now_tv->tv_sec);
		}

		/* Check return status */
		if (size < 0)
		{
#ifdef WIN32
			packet_buffer_drop (buf, PACKET_DROP_WRITE_ERROR);
#else
			const int my_errno = openvpn_errno ();
			if (my_errno == EAGAIN || my_errno == EWOULDBLOCK)
				;	/* TUN设备写缓冲不足, 稍后重写 */
			else
				/* TUN设备写失败, 丢弃包 */
				packet_buffer_drop (buf, PACKET_DROP_WRITE_ERROR);
#endif
		}

		check_status (size, "write to TUN/TAP", NULL, c->c1.tuntap);

		/* check written packet size */
		if (size > 0)
		{
			/* Did we write a different size packet than we intended? */
			if (size != BLEN (&buf->buf))
				msg (D_LINK_ERRORS,
					"TUN/TAP packet was destructively fragmented on write to %s (tried=%d,actual=%d)",
					c->c1.tuntap->actual_name, BLEN (&buf->buf), size);

			/* indicate activity regarding --inactive parameter */
			register_activity (c, size, TUN_THREAD_INDEX);
		}
	}
	else
	{
		/* This should never happen, probably indicates some kind of MTU mismatch. */
		if (buf->buf.len > MAX_RW_SIZE_TUN (&c->c2.frame))
			msg (D_LINK_ERRORS, "tun packet too large on write (tried=%d,max=%d) %s",
				buf->buf.len, MAX_RW_SIZE_TUN (&c->c2.frame),
				format_hex (BPTR (&buf->buf), BLEN (&buf->buf), BLEN (&buf->buf), &gc));

		packet_buffer_drop (buf, PACKET_DROP_WRITE_ERROR);
		size = -1;
	}

	perf_pop ();
	gc_free (&gc);

	return size;
}

void
pre_select (struct context *c)
{
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* TLS协议必须在主线程处理 */
#endif

	/* make sure current time (now) is updated on function entry */

	/*
	 * Start with an effectively infinite timeout, then let it reduce to a timeout
	 * that reflects the component which needs the earliest service.
	 */
	c->c2.timeval.tv_sec = BIG_TIMEOUT;
	c->c2.timeval.tv_usec = 0;

#if defined(WIN32)
	if (check_debug_level (D_TAP_WIN_DEBUG))
	{
		c->c2.timeval.tv_sec = 1;
		if (tuntap_defined (c->c1.tuntap))
			tun_show_debug (c->c1.tuntap);
	}
#endif

	/* check coarse timers? */
	check_coarse_timers (c);
	if (c->sig->signal_received)
		return;

	/* Does TLS need service? */
	check_tls (c);

	/* In certain cases, TLS errors will require a restart */
	check_tls_errors (c);
	if (c->sig->signal_received)
		return;

	/* check for incoming configuration info on the control channel */
	check_incoming_control_channel (c);
	if (c->sig->signal_received)
		return;

#ifdef ENABLE_OCC
	/* Should we send an OCC message? */
	check_send_occ_msg (c);
#endif

	/* Update random component of timeout */
	check_timeout_random_component (c);
}

/*
 * Wait for I/O events.  Used for both TCP & UDP sockets in point-to-point mode and
 * for UDP sockets inpoint-to-multipoint mode.
 */

void
io_wait_dowork (struct context *c, const unsigned int flags)
{
	unsigned int socket = 0;
#ifndef ENABLE_TUN_THREAD
	unsigned int tuntap = 0;
#endif
	bool wakeup = false;
	struct event_set_return esr[4];

	/* These shifts all depend on EVENT_READ and EVENT_WRITE */
	static int socket_shift = 0;     /* depends on SOCKET_READ and SOCKET_WRITE */
#ifndef ENABLE_TUN_THREAD
	static int tun_shift = 2;        /* depends on TUN_READ and TUN_WRITE */
#endif
	static int err_shift = 4;        /* depends on ES_ERROR */
#ifdef ENABLE_MANAGEMENT
	static int management_shift = 6; /* depends on MANAGEMENT_READ and MANAGEMENT_WRITE */
#endif

	c->c2.event_set_status = 0;

	/* Decide what kind of events we want to wait for. */
	event_reset (c->c2.event_set);

	/*
	 * If outgoing data (for TCP/UDP port) pending, wait for ready-to-send
	 * status from TCP/UDP port. Otherwise, wait for incoming data on TUN/TAP device.
	 */
	if (flags & IOW_TO_LINK)
	{
		if (flags & IOW_SHAPER)
		{
			/*
			 * If sending this packet would put us over our traffic shaping quota, don't send
			 * -- instead compute the delay we must wait until it will be OK to send the packet.
			 */
#ifdef ENABLE_FEATURE_SHAPER
			int delay = 0;

			/* set traffic shaping delay in microseconds */
			if (c->options.shaper)
				delay = max_int (delay, shaper_delay (&c->c2.shaper));

			if (delay < 1000)
				socket |= EVENT_WRITE;
			else
				shaper_soonest_event (&c->c2.timeval, delay);
#else /* ENABLE_FEATURE_SHAPER */
			socket |= EVENT_WRITE;
#endif /* ENABLE_FEATURE_SHAPER */
		}
		else
		{
			socket |= EVENT_WRITE;
#ifdef TARGET_LINUX
			/* 写缓存还有空间 */
			if (c->c2.link_socket->writes.size < MAX_OVERLAPPED_SIZE)
				c->c2.event_set_status |= SOCKET_WRITE;
#endif
		}
	}

	if (flags & IOW_READ_LINK)
	{
		socket |= EVENT_READ;
#ifdef TARGET_LINUX
		/* 读取缓存还有数据 */
		if (c->c2.link_socket->reads.offset < c->c2.link_socket->reads.size)
			c->c2.event_set_status |= SOCKET_READ;
#endif
	}

#ifndef ENABLE_TUN_THREAD
	if (flags & IOW_READ_TUN)
		tuntap |= EVENT_READ;

	/*
	 * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status from device.
	 * Otherwise, wait for incoming data on TCP/UDP port.
	 */
	if (flags & IOW_TO_TUN)
		tuntap |= EVENT_WRITE;
#endif

	if (c->c2.event_set_status)
	{
		update_time (MAIN_THREAD_INDEX);
		return;
	}

	/* On win32 we use the keyboard or an event object as a source of asynchronous signals. */
	if (flags & IOW_WAIT_SIGNAL)
		wait_signal (c->c2.event_set, (void*) &err_shift);

	/* Configure event wait based on socket, tuntap flags. */
	socket_set (c->c2.link_socket, c->c2.event_set, socket, (void*) &socket_shift, NULL);

#ifndef ENABLE_TUN_THREAD
	tun_set (c->c1.tuntap, c->c2.event_set, tuntap, (void*) &tun_shift, NULL);
#endif

#ifdef ENABLE_MANAGEMENT
	if (management)
		management_socket_set (management, c->c2.event_set, (void*) &management_shift, NULL);
#endif

	/*
	 * Possible scenarios:
	 *  (1) tcp/udp port has data available to read
	 *  (2) tcp/udp port is ready to accept more data to write
	 *  (3) tun dev has data available to read
	 *  (4) tun dev is ready to accept more data to write
	 *  (5) we received a signal (handler sets signal_received)
	 *  (6) timeout (tv) expired
	 */
	if (c->sig->signal_received)
	{
		c->c2.event_set_status = ES_ERROR;
	}
	else
	{
		if (!(flags & IOW_CHECK_RESIDUAL) || !socket_read_residual (c->c2.link_socket))
		{
			int status;

#ifdef ENABLE_DEBUG
			if (check_debug_level (D_EVENT_WAIT))
				show_wait_status (c);
#endif

			/* Wait for something to happen. */
			status = event_wait (c->c2.event_set, &c->c2.timeval, esr, SIZE (esr), &wakeup);
			check_status (status, "event_wait", NULL, NULL);

			if (status > 0)
			{
				int i;

				for (i = 0; i < status; ++i)
				{
					const struct event_set_return *e = &esr[i];

					if (e->arg)
						c->c2.event_set_status |= ((e->rwflags & 3) << *((int*) e->arg));
				}
			}
			else if (status == 0)
			{
				c->c2.event_set_status =  wakeup ? ES_WAKEUP : ES_TIMEOUT;
			}
		}
		else
		{
			c->c2.event_set_status = SOCKET_READ;
		}
	}

	update_time (MAIN_THREAD_INDEX);

	/* set signal_received if a signal was received */
	if (c->c2.event_set_status & ES_ERROR)
		get_signal (&c->sig->signal_received);

	dmsg (D_EVENT_WAIT, "I/O WAIT status=0x%04x", c->c2.event_set_status);
}

void
process_io (struct context *c)
{
	const unsigned int status0 = c->c2.event_set_status;
	unsigned int status1 = SOCKET_WRITE|SOCKET_READ|TUN_WRITE|TUN_READ;
	int io_loop = 0;

#ifdef ENABLE_MANAGEMENT
	if (status0 & (MANAGEMENT_READ|MANAGEMENT_WRITE))
	{		
		ASSERT (management);
		management_io (management);
	}
#endif

	do {
		/* Incoming data on TCP/UDP port */
		if ((status0 & SOCKET_READ) && (status1 & SOCKET_READ))
		{
			if (do_process_link_p2p_read (c) <= 0)
				status1 &= ~SOCKET_READ;
		}

#ifndef ENABLE_TUN_THREAD
		/* Incoming data on TUN device */
		if ((status0 & TUN_READ) && (status1 & TUN_READ))
		{
			if (do_process_tun_p2p_read (c) <= 0)
				status1 &= ~TUN_READ;
		}
#endif

		/* TCP/UDP port ready to accept write */
		if ((status0 & SOCKET_WRITE) && (status1 & SOCKET_WRITE))
		{
			if (do_process_link_p2p_write (c) <= 0)
				status1 &= ~SOCKET_WRITE;
		}

#ifndef ENABLE_TUN_THREAD
		/* TUN device ready to accept write */
		if ((status0 & TUN_WRITE) && (status1 & TUN_WRITE))
		{
			if (do_process_tun_p2p_write (c) <= 0)
				status1 &= ~TUN_WRITE;
		}
#endif

		if (status1 & SOCKET_READ)
		{
			if (prepare_process_link_any_incoming (c) == 0)
				status1 &= ~SOCKET_READ;
		}

		if (status1 & SOCKET_WRITE)
		{
			if (prepare_process_link_p2p_outgoing (c) == 0)
				status1 &= ~SOCKET_WRITE;
		}

#ifndef ENABLE_TUN_THREAD
		if (status1 & TUN_READ)
		{
			if (prepare_process_tun_any_incoming (c) == 0)
				status1 &= ~TUN_READ;
		}

		if (status1 & TUN_WRITE)
		{
			if (prepare_process_tun_p2p_outgoing (c) == 0)
				status1 &= ~TUN_WRITE;
		}
#endif

	} while (c->options.shaper <= 0 && status1 != 0 && ++io_loop < MAX_PROCESS_IO_LOOP);
}
