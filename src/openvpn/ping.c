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

#include "forward.h"
#include "socket.h"
#include "socket-inline.h"
#include "ping.h"
#include "openvpn.h"
#include "thread.h"
#include "ping-inline.h"
#include "multi_crypto.h"

#include "memdbg.h"

/*
 * This random string identifies an OpenVPN ping packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 *
 * PING_STRING_SIZE must be sizeof (ping_string)
 */
const uint8_t ping_string[] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

/*
 * Should we exit or restart due to ping (or other authenticated packet)
 * not received in n seconds?
 */
void
check_ping_restart_dowork (struct context *c)
{
	struct gc_arena gc = gc_new ();
	switch (c->options.ping_rec_timeout_action)
	{
	case PING_EXIT:
		msg (M_INFO, "%sInactivity timeout (--ping-exit), exiting", format_common_name (c, &gc));
		c->sig->signal_received = SIGTERM;
		c->sig->signal_text = "ping-exit";
		break;
	case PING_RESTART:
		msg (M_INFO, "%sInactivity timeout (--ping-restart), restarting", format_common_name (c, &gc));
		c->sig->signal_received = SIGUSR1; /* SOFT-SIGUSR1 -- Ping Restart */
		c->sig->signal_text = "ping-restart";
		break;
	default:
		ASSERT (0);
	}

	gc_free (&gc);
}

/*
 * Should we ping the remote?
 */
void
check_ping_send_dowork (struct context *c)
{
	struct packet_buffer *buf;

	buf = get_link_read_packet_buffer (c, true);
	ASSERT (buf_init (&buf->buf, FRAME_HEADROOM (&c->c2.frame)));
	ASSERT (buf_safe (&buf->buf, MAX_RW_SIZE_TUN (&c->c2.frame)));
	ASSERT (buf_write (&buf->buf, ping_string, sizeof (ping_string)));

	/* tls、ping、occ、bcast, unicast包的seq_no统一设置为0 */
	buf->seq_no = 0;

#ifdef PERF_STATS_CHECK
	buf->extra = 5;
	packet_buffer_mark_ttl (buf, now_tv (MAIN_THREAD_INDEX));
#endif
	buf->flags |= (PACKET_BUFFER_PING_FLAG | PACKET_BUFFER_FRAG_LAST_FLAG);

	/* PING包放入tup接收队列 */
	MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_mutex, MAIN_THREAD_INDEX, S_READ_TUN_BUFS);
	packet_buffer_list_push_front (c->c2.buffers->read_tun_bufs, buf);
	MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_mutex, MAIN_THREAD_INDEX, S_READ_TUN_BUFS);

	c->c2.did_tun_pending0 = true;

	if (c->options.mode == MODE_POINT_TO_POINT)
	{
		wakeup_worker_threads (MAIN_THREAD_INDEX, c->c2.buffers->read_tun_bufs->size);
	}

	dmsg (D_PING, "SENT PING");
} 
