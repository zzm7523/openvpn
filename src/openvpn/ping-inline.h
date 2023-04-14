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

#ifndef PING_INLINE_H
#define PING_INLINE_H

/*
 * Should we exit or restart due to ping (or other authenticated packet) not received in n seconds?
 */
static inline void
check_ping_restart (struct context *c)
{
	/* SSL连接建立成功后启用PING RESTART检查, SSL连接建立成功前由hello_window和handshake_windows参数控制 */
	void check_ping_restart_dowork (struct context *c);
	static time_t last_check_ping_restart = 0;	/* 记录上一次的调用时间, 减少锁定频率 */
	bool restart;

	if (!c->options.ping_rec_timeout || now_sec (MAIN_THREAD_INDEX) < last_check_ping_restart + 1)
		return;

	last_check_ping_restart = now_sec (MAIN_THREAD_INDEX);

	MUTEX_LOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);
	restart = event_timeout_trigger (&c->c2.ping_rec_interval, &c->c2.timeval, (!c->options.ping_timer_remote
		|| link_socket_actual_defined (&c->c1.link_socket_addr.actual)) ? ETT_DEFAULT : 15);
	MUTEX_UNLOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);

	if (restart)
	{
		struct tls_multi *multi = c->c2.tls_multi;
		if (multi)
		{
			int i;
			for (i = 0; i < (int) SIZE (multi->key_scan); ++i)
			{
				if ((*multi->key_scan[i])->state > S_START)
				{
					check_ping_restart_dowork (c);
					break;
				}
			}
		}
		else
		{
			check_ping_restart_dowork (c);	/* 采用共享密钥时 */
		}
	}
}

/*
 * Should we ping the remote?
 */
static inline void
check_ping_send (struct context *c)
{
	void check_ping_send_dowork (struct context *c);

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	if (c->options.ping_send_timeout && event_timeout_trigger (&c->c2.ping_send_interval,
		&c->c2.timeval, !TO_LINK_DEF (c) ? ETT_DEFAULT : 1))
	{
		check_ping_send_dowork (c);
	}
}

#endif
