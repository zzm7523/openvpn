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

#ifdef ENABLE_OCC

#include "gremlin.h"
#include "occ.h"

#include "socket.h"
#include "socket-inline.h"
#include "openvpn.h"
#include "thread.h"
#include "forward-inline.h"
#include "occ-inline.h"
#include "multi_crypto.h"

#include "memdbg.h"

/*
 * This random string identifies an OpenVPN
 * Configuration Control packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 *
 * The OCC protocol is as follows:
 *
 * occ_magic -- (16 octets)
 *
 * type [OCC_REQUEST | OCC_REPLY] (1 octet)
 * null terminated options string if OCC_REPLY (variable)
 *
 * When encryption is used, the OCC packet
 * is encapsulated within the encrypted
 * envelope.
 *
 * OCC_STRING_SIZE must be set to sizeof (occ_magic)
 */

const uint8_t occ_magic[] = {
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c
};

static const struct mtu_load_test mtu_load_test_sequence[] = {
	{OCC_MTU_LOAD_REQUEST, -1000},
	{OCC_MTU_LOAD, -1000},
	{OCC_MTU_LOAD_REQUEST, -1000},
	{OCC_MTU_LOAD, -1000},
	{OCC_MTU_LOAD_REQUEST, -1000},
	{OCC_MTU_LOAD, -1000},

	{OCC_MTU_LOAD_REQUEST, -750},
	{OCC_MTU_LOAD, -750},
	{OCC_MTU_LOAD_REQUEST, -750},
	{OCC_MTU_LOAD, -750},
	{OCC_MTU_LOAD_REQUEST, -750},
	{OCC_MTU_LOAD, -750},

	{OCC_MTU_LOAD_REQUEST, -500},
	{OCC_MTU_LOAD, -500},
	{OCC_MTU_LOAD_REQUEST, -500},
	{OCC_MTU_LOAD, -500},
	{OCC_MTU_LOAD_REQUEST, -500},
	{OCC_MTU_LOAD, -500},

	{OCC_MTU_LOAD_REQUEST, -400},
	{OCC_MTU_LOAD, -400},
	{OCC_MTU_LOAD_REQUEST, -400},
	{OCC_MTU_LOAD, -400},
	{OCC_MTU_LOAD_REQUEST, -400},
	{OCC_MTU_LOAD, -400},

	{OCC_MTU_LOAD_REQUEST, -300},
	{OCC_MTU_LOAD, -300},
	{OCC_MTU_LOAD_REQUEST, -300},
	{OCC_MTU_LOAD, -300},
	{OCC_MTU_LOAD_REQUEST, -300},
	{OCC_MTU_LOAD, -300},

	{OCC_MTU_LOAD_REQUEST, -200},
	{OCC_MTU_LOAD, -200},
	{OCC_MTU_LOAD_REQUEST, -200},
	{OCC_MTU_LOAD, -200},
	{OCC_MTU_LOAD_REQUEST, -200},
	{OCC_MTU_LOAD, -200},

	{OCC_MTU_LOAD_REQUEST, -150},
	{OCC_MTU_LOAD, -150},
	{OCC_MTU_LOAD_REQUEST, -150},
	{OCC_MTU_LOAD, -150},
	{OCC_MTU_LOAD_REQUEST, -150},
	{OCC_MTU_LOAD, -150},

	{OCC_MTU_LOAD_REQUEST, -100},
	{OCC_MTU_LOAD, -100},
	{OCC_MTU_LOAD_REQUEST, -100},
	{OCC_MTU_LOAD, -100},
	{OCC_MTU_LOAD_REQUEST, -100},
	{OCC_MTU_LOAD, -100},

	{OCC_MTU_LOAD_REQUEST, -50},
	{OCC_MTU_LOAD, -50},
	{OCC_MTU_LOAD_REQUEST, -50},
	{OCC_MTU_LOAD, -50},
	{OCC_MTU_LOAD_REQUEST, -50},
	{OCC_MTU_LOAD, -50},

	{OCC_MTU_LOAD_REQUEST, 0},
	{OCC_MTU_LOAD, 0},
	{OCC_MTU_LOAD_REQUEST, 0},
	{OCC_MTU_LOAD, 0},
	{OCC_MTU_LOAD_REQUEST, 0},
	{OCC_MTU_LOAD, 0},

	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},
	{OCC_MTU_REQUEST, 0},

	{-1, 0}
};

void
check_send_occ_req_dowork (struct context *c)
{
	if (++c->c2.occ_n_tries >= OCC_N_TRIES)
	{
		if (c->options.ce.remote)
		{
			counter_type link_read_bytes_auth = 0L;

			link_read_auth_get_stats (c, &link_read_bytes_auth);

			/* No OCC_REPLY from peer after repeated attempts. Give up.*/
			msg (D_SHOW_OCC,
				"NOTE: failed to obtain options consistency info from peer -- "
				"this could occur if the remote peer is running a version of "
				PACKAGE_NAME
				" before 1.5-beta8 or if there is a network connectivity problem, and will not necessarily prevent "
				PACKAGE_NAME
				" from running (" counter_format " bytes received from peer, " counter_format
				" bytes authenticated data channel traffic) -- you can disable the options consistency "
				"check with --disable-occ.",
				c->c2.link_read_bytes,
				link_read_bytes_auth);
		}

		event_timeout_clear (&c->c2.occ_interval);
	}
	else
	{
		c->c2.occ_op = OCC_REQUEST;

		/* If we don't hear back from peer, send another OCC_REQUEST in OCC_INTERVAL_SECONDS. */
		update_time (MAIN_THREAD_INDEX);
		event_timeout_reset (&c->c2.occ_interval, now_sec (MAIN_THREAD_INDEX));
	}
}

void
check_send_occ_load_test_dowork (struct context *c)
{
	if (CONNECTION_ESTABLISHED (c))
	{
		const struct mtu_load_test *entry;

		if (!c->c2.occ_mtu_load_n_tries)
			msg (M_INFO, "NOTE: Beginning empirical MTU test -- results should be available in 3 to 4 minutes.");

		entry = &mtu_load_test_sequence[c->c2.occ_mtu_load_n_tries++];
		if (entry->op >= 0)
		{
			c->c2.occ_op = entry->op;
			c->c2.occ_mtu_load_size = EXPANDED_SIZE (&c->c2.frame) + entry->delta;
		}
		else
		{
			msg (M_INFO,
				"NOTE: failed to empirically measure MTU (requires " PACKAGE_NAME " 1.5 or higher at other end of connection).");
			event_timeout_clear (&c->c2.occ_mtu_load_test_interval);
			c->c2.occ_mtu_load_n_tries = 0;
		}
	}
}

void
check_send_occ_msg_dowork (struct context *c)
{
	struct packet_buffer *buf;
	bool doit = false;

	buf = get_link_read_packet_buffer (c, true);
	ASSERT (buf_init (&buf->buf, FRAME_HEADROOM (&c->c2.frame)));
	ASSERT (buf_safe (&buf->buf, MAX_RW_SIZE_TUN (&c->c2.frame)));
	ASSERT (buf_write (&buf->buf, occ_magic, OCC_STRING_SIZE));

	/* tls、ping、occ、bcast, unicast包的seq_no统一设置为0 */
	buf->seq_no = 0;

#ifdef PERF_STATS_CHECK
	buf->extra = 4;
	packet_buffer_mark_ttl (buf, now_tv (MAIN_THREAD_INDEX));
#endif
	buf->flags |= (PACKET_BUFFER_OCC_FLAG | PACKET_BUFFER_FRAG_LAST_FLAG);

	switch (c->c2.occ_op)
	{
	case OCC_REQUEST:
		if (!buf_write_u8 (&buf->buf, OCC_REQUEST))
			break;
		dmsg (D_PACKET_CONTENT, "SENT OCC_REQUEST");
		doit = true;
		break;

	case OCC_REPLY:
		if (c->c2.options_string_local)
		{
			if (!buf_write_u8 (&buf->buf, OCC_REPLY))
				break;
			if (!buf_write (&buf->buf, c->c2.options_string_local, (int) strlen (c->c2.options_string_local) + 1))
				break;
			dmsg (D_PACKET_CONTENT, "SENT OCC_REPLY");
			doit = true;
		}
		break;

	case OCC_MTU_REQUEST:
		if (!buf_write_u8 (&buf->buf, OCC_MTU_REQUEST))
			break;
		dmsg (D_PACKET_CONTENT, "SENT OCC_MTU_REQUEST");
		doit = true;
		break;

	case OCC_MTU_REPLY:
		if (!buf_write_u8 (&buf->buf, OCC_MTU_REPLY))
			break;
		if (!buf_write_u16 (&buf->buf, c->c2.max_recv_size_local))
			break;
		if (!buf_write_u16 (&buf->buf, c->c2.max_send_size_local))
			break;
		dmsg (D_PACKET_CONTENT, "SENT OCC_MTU_REPLY");
		doit = true;
		break;

	case OCC_MTU_LOAD_REQUEST:
		if (!buf_write_u8 (&buf->buf, OCC_MTU_LOAD_REQUEST))
			break;
		if (!buf_write_u16 (&buf->buf, c->c2.occ_mtu_load_size))
			break;
		dmsg (D_PACKET_CONTENT, "SENT OCC_MTU_LOAD_REQUEST");
		doit = true;
		break;

	case OCC_MTU_LOAD:
		{
			int need_to_add;
			if (!buf_write_u8 (&buf->buf, OCC_MTU_LOAD))
				break;
			need_to_add = min_int (c->c2.occ_mtu_load_size, EXPANDED_SIZE (&c->c2.frame))
				- OCC_STRING_SIZE
				- sizeof (uint8_t)
				- EXTRA_FRAME (&c->c2.frame);

			while (need_to_add > 0)
			{
				/* Fill the load test packet with pseudo-random bytes. */
				if (!buf_write_u8 (&buf->buf, get_random () & 0xFF))
					break;
				--need_to_add;
			}
			dmsg (D_PACKET_CONTENT, "SENT OCC_MTU_LOAD min_int(%d-%d-%d-%d,%d) size=%d",
				c->c2.occ_mtu_load_size,
				OCC_STRING_SIZE,
				(int) sizeof (uint8_t),
				EXTRA_FRAME (&c->c2.frame),
				MAX_RW_SIZE_TUN (&c->c2.frame),
				BLEN (&buf->buf));
			doit = true;
		}
		break;

	case OCC_EXIT:
		if (!buf_write_u8 (&buf->buf, OCC_EXIT))
			break;
		dmsg (D_PACKET_CONTENT, "SENT OCC_EXIT");
		doit = true;
		break;
	}

	if (doit)
	{
		ASSERT (buf->buf.len > 0);

		/* OCC包放入tup接收队列 */
		MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_mutex, MAIN_THREAD_INDEX, S_READ_TUN_BUFS);
		packet_buffer_list_push_back (c->c2.buffers->read_tun_bufs, buf);
		MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_mutex, MAIN_THREAD_INDEX, S_READ_TUN_BUFS);

		c->c2.did_tun_pending0 = true;

		if (c->options.mode == MODE_POINT_TO_POINT)
		{
			wakeup_worker_threads (MAIN_THREAD_INDEX, c->c2.buffers->read_tun_bufs->size);
		}
	}
	else
	{
		packet_buffer_free (buf);
	}

	c->c2.occ_op = -1;
}

void
process_received_occ_msg (struct context *c, struct buffer *buf)
{
	ASSERT (buf_advance (buf, OCC_STRING_SIZE));

	switch (buf_read_u8 (buf))
	{
	case OCC_REQUEST:
		dmsg (D_PACKET_CONTENT, "RECEIVED OCC_REQUEST");
		c->c2.occ_op = OCC_REPLY;
		break;

	case OCC_MTU_REQUEST:
		dmsg (D_PACKET_CONTENT, "RECEIVED OCC_MTU_REQUEST");
		c->c2.occ_op = OCC_MTU_REPLY;
		break;

	case OCC_MTU_LOAD_REQUEST:
		dmsg (D_PACKET_CONTENT, "RECEIVED OCC_MTU_LOAD_REQUEST");
		c->c2.occ_mtu_load_size = buf_read_u16 (buf);
		if (c->c2.occ_mtu_load_size >= 0)
			c->c2.occ_op = OCC_MTU_LOAD;
		break;

	case OCC_REPLY:
		dmsg (D_PACKET_CONTENT, "RECEIVED OCC_REPLY");
		if (c->options.occ && !TLS_MODE (c) && c->c2.options_string_remote)
		{
			if (!options_cmp_equal_safe ((char *) BPTR (buf), c->c2.options_string_remote, buf->len))
			{
				options_warning_safe ((char *) BPTR (buf), c->c2.options_string_remote, buf->len);
			}
		}
		event_timeout_clear (&c->c2.occ_interval);
		break;

	case OCC_MTU_REPLY:
		dmsg (D_PACKET_CONTENT, "RECEIVED OCC_MTU_REPLY");
		c->c2.max_recv_size_remote = buf_read_u16 (buf);
		c->c2.max_send_size_remote = buf_read_u16 (buf);
		if (c->options.mtu_test && c->c2.max_recv_size_remote > 0 && c->c2.max_send_size_remote > 0)
		{
			msg (M_INFO, "NOTE: Empirical MTU test completed [Tried,Actual] local->remote=[%d,%d] remote->local=[%d,%d]",
				c->c2.max_send_size_local,
				c->c2.max_recv_size_remote,
				c->c2.max_send_size_remote,
				c->c2.max_recv_size_local);
			if (c->options.ce.fragment <= 0
				&& (proto_is_dgram (c->options.ce.proto))
				&& c->c2.max_send_size_local > TUN_MTU_MIN
				&& (c->c2.max_recv_size_remote < c->c2.max_send_size_local
				|| c->c2.max_recv_size_local < c->c2.max_send_size_remote))
			{
				msg (M_INFO, "NOTE: This connection is unable to accommodate a UDP packet size of %d. Consider using --fragment or --mssfix options as a workaround.",
					c->c2.max_send_size_local);
			}
		}
		event_timeout_clear (&c->c2.occ_mtu_load_test_interval);
		break;

	case OCC_EXIT:
		dmsg (D_PACKET_CONTENT, "RECEIVED OCC_EXIT");
		c->sig->signal_received = SIGTERM;
		c->sig->signal_text = "remote-exit";
		break;
	}

	buf->len = 0;	/* don't pass packet on */
	buf_set_tracking (buf, PACKET_DROP_OCC_PACKET);
}

#else
static void dummy (void) {}
#endif
