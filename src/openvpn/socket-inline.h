#ifndef __SOCKET_INLINE_H__
#define __SOCKET_INLINE_H__

#ifdef __cplusplus
extern "C" {
#endif

static inline int
datagram_overhead (int proto)
{
	ASSERT (proto >= 0 && proto < PROTO_N);
	return proto_overhead[proto];
}

/* Misc inline functions */

static inline bool
legal_ipv4_port (int port)
{
	return port > 0 && port < 65536;
}

static inline bool
link_socket_proto_connection_oriented (int proto)
{
	return !proto_is_dgram (proto);
}

static inline bool
link_socket_connection_oriented (const struct link_socket *sock)
{
	if (sock)
		return link_socket_proto_connection_oriented (sock->info.proto);
	else
		return false;
}

static inline bool
addr_defined (const struct openvpn_sockaddr *addr)
{
	if (!addr)
	{
		return 0;
	}
	else
	{
		switch (addr->addr.sa.sa_family)
		{
		case AF_INET: 
			return addr->addr.in4.sin_addr.s_addr != 0;
		case AF_INET6: 
			return !IN6_IS_ADDR_UNSPECIFIED (&addr->addr.in6.sin6_addr);
		default: 
			return 0;
		}
	}
}

static inline bool
addr_local (const struct sockaddr *addr)
{
	if (!addr)
		return false;

	switch (addr->sa_family)
	{
	case AF_INET:
		return ((const struct sockaddr_in *) addr)->sin_addr.s_addr == htonl (INADDR_LOOPBACK);

	case AF_INET6:
		return IN6_IS_ADDR_LOOPBACK (&((const struct sockaddr_in6 *) addr)->sin6_addr);

	default:
		return false;
	}
}

static inline bool
addr_defined_ipi (const struct link_socket_actual *lsa)
{
#if ENABLE_IP_PKTINFO
	if (!lsa)
		return 0;

	switch (lsa->dest.addr.sa.sa_family)
	{
#ifdef HAVE_IN_PKTINFO
	case AF_INET: return lsa->pi.in4.ipi_spec_dst.s_addr != 0;
#elif defined(IP_RECVDSTADDR)
	case AF_INET: return lsa->pi.in4.s_addr != 0;
#endif
	case AF_INET6: return !IN6_IS_ADDR_UNSPECIFIED (&lsa->pi.in6.ipi6_addr);
	default: return 0;
	}
#else
	ASSERT (0);
#endif
	return false;
}

static inline bool
link_socket_actual_defined (const struct link_socket_actual *act)
{
	return act && addr_defined (&act->dest);
}

static inline bool
addr_match (const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2)
{
	switch (a1->addr.sa.sa_family)
	{
	case AF_INET:
		return a1->addr.in4.sin_addr.s_addr == a2->addr.in4.sin_addr.s_addr;
	case AF_INET6:
		return IN6_ARE_ADDR_EQUAL(&a1->addr.in6.sin6_addr, &a2->addr.in6.sin6_addr);
	}
	ASSERT (0);
	return false;
}

static inline in_addr_t
addr_host (const struct openvpn_sockaddr *addr)
{
	/* 
	* "public" addr returned is checked against ifconfig for possible clash:
	*  non sense for now given that we do ifconfig only IPv4
	*/
	if (addr->addr.sa.sa_family != AF_INET)
		return 0;
	return ntohl (addr->addr.in4.sin_addr.s_addr);
}

static inline bool
addr_port_match (const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2)
{
	switch (a1->addr.sa.sa_family)
	{
	case AF_INET:
		return a1->addr.in4.sin_addr.s_addr == a2->addr.in4.sin_addr.s_addr
			&& a1->addr.in4.sin_port == a2->addr.in4.sin_port;
	case AF_INET6:
		return IN6_ARE_ADDR_EQUAL (&a1->addr.in6.sin6_addr, &a2->addr.in6.sin6_addr) 
			&& a1->addr.in6.sin6_port == a2->addr.in6.sin6_port;
	}
	ASSERT (0);
	return false;
}

static inline bool
addr_match_proto (const struct openvpn_sockaddr *a1, const struct openvpn_sockaddr *a2, const int proto)
{
	return link_socket_proto_connection_oriented (proto) ? addr_match (a1, a2) : addr_port_match (a1, a2);
}

static inline void
addr_zero_host (struct openvpn_sockaddr *addr)
{
	switch (addr->addr.sa.sa_family)
	{
	case AF_INET:
		addr->addr.in4.sin_addr.s_addr = 0;
		break;
	case AF_INET6: 
		memset (&addr->addr.in6.sin6_addr, 0, sizeof (struct in6_addr));
		break;
	}
}

static inline void
addr_copy_sa (struct openvpn_sockaddr *dst, const struct openvpn_sockaddr *src)
{
	dst->addr = src->addr;
}

static inline void
addr_copy_host (struct openvpn_sockaddr *dst, const struct openvpn_sockaddr *src)
{
	switch (src->addr.sa.sa_family)
	{
	case AF_INET:
		dst->addr.in4.sin_addr.s_addr = src->addr.in4.sin_addr.s_addr;
		break;
	case AF_INET6: 
		dst->addr.in6.sin6_addr = src->addr.in6.sin6_addr;
		break;
	}
}

static inline bool
addr_inet4or6 (struct sockaddr *addr)
{
	return addr->sa_family == AF_INET || addr->sa_family == AF_INET6;
}

static inline int
af_addr_size (unsigned short af)
{
	switch (af) 
	{
	case AF_INET: 
		return sizeof (struct sockaddr_in);
	case AF_INET6: 
		return sizeof (struct sockaddr_in6);
	default: 
#if 0
		/* could be called from socket_do_accept() with empty addr */
		msg (M_ERR, "Bad address family: %d\n", af);
		ASSERT (0);
#endif
		return 0;
	}
}

static inline bool
link_socket_actual_match (const struct link_socket_actual *a1, const struct link_socket_actual *a2)
{
	return addr_port_match (&a1->dest, &a2->dest);
}

#if PORT_SHARE

static inline bool
socket_foreign_protocol_detected (const struct link_socket *sock)
{
	return link_socket_connection_oriented (sock)
		&& sock->stream_buf.port_share_state == PS_FOREIGN;
}

static inline const struct buffer *
socket_foreign_protocol_head (const struct link_socket *sock)
{
	return &sock->stream_buf.buf;
}

static inline int
socket_foreign_protocol_sd (const struct link_socket *sock)
{
	return sock->sd;
}

#endif

static inline bool
socket_connection_reset (const struct link_socket *sock, int status)
{
	if (link_socket_connection_oriented (sock))
	{
		if (sock->stream_reset || sock->stream_buf.error)
			return true;
		else if (status < 0)
		{
			const int err = openvpn_errno ();
#ifdef WIN32
			return err == WSAECONNRESET || err == WSAECONNABORTED;
#else
			return err == ECONNRESET;
#endif
		}
	}
	return false;
}

static inline bool
link_socket_verify_incoming_addr (struct buffer *buf, const struct link_socket_info *info,
		const struct link_socket_actual *from_addr)
{
	if (buf->len > 0)
	{
		switch (from_addr->dest.addr.sa.sa_family)
		{
		case AF_INET6:
		case AF_INET:
			if (!link_socket_actual_defined (from_addr))
				return false;
			if (info->remote_float || !addr_defined (&info->lsa->remote))
				return true;
			if (addr_match_proto (&from_addr->dest, &info->lsa->remote, info->proto))
				return true;
		}
	}
	return false;
}

static inline void
link_socket_get_outgoing_addr (struct buffer *buf, const struct link_socket_info *info,
		struct link_socket_actual **act)
{
	if (buf->len > 0)
	{
		struct link_socket_addr *lsa = info->lsa;
		if (link_socket_actual_defined (&lsa->actual))
			*act = &lsa->actual;
		else
		{
			link_socket_bad_outgoing_addr ();
			buf->len = 0;
			buf_set_tracking (buf, PACKET_DROP_SOCKET_NOT_DEFINED);
			*act = NULL;
		}
	}
}

static inline void
link_socket_set_outgoing_addr (const struct buffer *buf, struct link_socket_info *info,
		const struct link_socket_actual *act, const char *common_name, struct env_set *es)
{
	if (!buf || buf->len > 0)
	{
		struct link_socket_addr *lsa = info->lsa;
		if (/* new or changed address? */
			(!info->connection_established
				|| !addr_match_proto (&act->dest, &lsa->actual.dest, info->proto))
			/* address undef or address == remote or --float */
			&& (info->remote_float || !addr_defined (&lsa->remote)
				|| addr_match_proto (&act->dest, &lsa->remote, info->proto))
				)
		{
			link_socket_connection_initiated (buf, info, act, common_name, es);
		}
	}
}

static inline bool
stream_buf_read_setup (struct link_socket* sock)
{
	bool stream_buf_read_setup_dowork (struct link_socket* sock);

	if (link_socket_connection_oriented (sock))
		return stream_buf_read_setup_dowork (sock);
	else
		return true;
}

#ifdef WIN32

static inline int
link_socket_read_udp_win32 (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *from,
		unsigned int flags)
{
	int status = 0;

	if (overlapped_io_active (&sock->reads))
	{
		status = socket_finalize (sock->sd, &sock->reads, buf, from);
	}
	else
	{
		socket_recv_queue (sock, 0, buf, from);
	}

	if (status < 0)
	{
		return status;
	}
	else
	{
		return sock->reads.iostate == IOSTATE_QUEUED ? 0 : BLEN (buf);
	}
}

#endif

/* read a TCP or UDP packet from link */
static inline int
link_socket_read (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *from,
		unsigned int flags)
{
	if (proto_is_udp (sock->info.proto)) /* unified UDPv4 and UDPv6 */
	{
		int res;

#ifdef WIN32
		res = link_socket_read_udp_win32 (sock, buf, from, flags);
#else
		res = link_socket_read_udp_posix (sock, buf, from, flags);
#endif
		return res;
	}
	else if (proto_is_tcp (sock->info.proto)) /* unified TCPv4 and TCPv6 */
	{
		/* from address was returned by accept */
		addr_copy_sa (&from->dest, &sock->info.lsa->actual.dest);
		return link_socket_read_tcp (sock, buf, flags);
	}
	else
	{
		ASSERT (0);
		return -1; /* NOTREACHED */
	}
}

#ifdef WIN32

static inline int
link_socket_write_win32 (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to,
		unsigned int flags)
{
	int status = 0, err = 0;

	if (overlapped_io_active (&sock->writes))
	{
		status = socket_finalize (sock->sd, &sock->writes, NULL, NULL);
		if (sock->writes.iostate == IOSTATE_QUEUED) /* 包还不能放入发送缓存 */
			return 0;
		else
		{
			ASSERT (sock->writes.iostate == IOSTATE_INITIAL);

			if (status < 0)
				err = WSAGetLastError ();

			socket_send_queue (sock, buf, to);
			if (status < 0)
			{
				WSASetLastError (err);
				return status;
			}
			else
				return BLEN (buf);
		}
	}
	else
	{
		socket_send_queue (sock, buf, to);
		return BLEN (buf);
	}
}

#else

static inline int
link_socket_write_udp_posix (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to, unsigned int flags)
{
	int link_socket_write_udp_posix_sendmsg (struct link_socket *sock, struct buffer *buf,
		struct link_socket_actual *to, unsigned int flags);

#if defined(TARGET_LINUX) || defined(TARGET_ANDROID)
	int link_socket_write_udp_posix_sendmmsg (struct link_socket *sock, struct buffer *buf,
		struct link_socket_actual *to, unsigned int flags);

	if (sock->sockflags & SF_USE_SENDMMSG)
		return link_socket_write_udp_posix_sendmmsg (sock, buf, to, flags);
	else
#endif
	{
#if ENABLE_IP_PKTINFO
		if ((sock->sockflags & SF_USE_IP_PKTINFO) && addr_defined_ipi (to))
			return link_socket_write_udp_posix_sendmsg (sock, buf, to, flags);
		else
#endif
			return sendto (sock->sd, BPTR (buf), BLEN (buf), 0, (struct sockaddr *) &to->dest.addr.sa,
					(socklen_t) af_addr_size (to->dest.addr.sa.sa_family));
	}
}

static inline int
link_socket_write_tcp_posix (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to,
		unsigned int flags)
{
	return send (sock->sd, BPTR (buf), BLEN (buf), MSG_NOSIGNAL);
}

#endif

static inline int
link_socket_write_udp (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to,
		unsigned int flags)
{
#ifdef WIN32
	return link_socket_write_win32 (sock, buf, to, flags);
#else
	return link_socket_write_udp_posix (sock, buf, to, flags);
#endif
}

/* write a TCP or UDP packet to link */
static inline int
link_socket_write (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to,
		unsigned int flags)
{
	if (proto_is_udp (sock->info.proto)) /* unified UDPv4 and UDPv6 */
	{
		return link_socket_write_udp (sock, buf, to, flags);
	}
	else if (proto_is_tcp (sock->info.proto)) /* unified TCPv4 and TCPv6 */
	{
		return link_socket_write_tcp (sock, buf, to, flags);
	}
	else
	{
		ASSERT (0);
		return -1; /* NOTREACHED */
	}
}

#if PASSTOS_CAPABILITY

/* Extract TOS bits.  Assumes that ipbuf is a valid IPv4 packet. */
static inline void
link_socket_extract_tos (struct link_socket *ls, const struct buffer *ipbuf)
{
	if (ls && ipbuf)
	{
		struct openvpn_iphdr *iph = (struct openvpn_iphdr *) BPTR (ipbuf);
		ls->ptos = iph->tos;
		ls->ptos_defined = true;
	}
}

/* Set socket properties to reflect TOS bits which were extracted from tunnel packet. */
static inline void
link_socket_set_tos (struct link_socket *ls)
{
	if (ls && ls->ptos_defined)
		setsockopt (ls->sd, IPPROTO_IP, IP_TOS, (const char*) &ls->ptos, sizeof (ls->ptos));
}

#endif

/* Socket I/O wait functions */
static inline bool
socket_read_residual (const struct link_socket *s)
{
	return s && s->stream_buf.residual_fully_formed;
}

static inline event_t
socket_event_handle (const struct link_socket *s)
{
#ifdef WIN32
	return &s->rw_handle;
#else
	return s->sd;
#endif
}

static inline void
socket_set_listen_persistent (struct link_socket *s, struct event_set *es, void *arg)
{
	if (s && !s->listen_persistent_queued)
	{
		event_ctl (es, socket_listen_event_handle (s), EVENT_READ, arg);
		s->listen_persistent_queued = true;
	}
}

static inline void
socket_reset_listen_persistent (struct link_socket *s)
{
#ifdef WIN32
	reset_net_event_win32 (&s->listen_handle, s->sd);
#endif
}

#ifdef __cplusplus
}
#endif

#endif
