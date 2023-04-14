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

#ifndef SOCKET_H
#define SOCKET_H

#include "buffer.h"
#include "common.h"
#include "error.h"
#include "proto.h"
#include "mtu.h"
#include "win32.h"
#include "event.h"
#include "proxy.h"
#include "socks.h"
#include "misc.h"
#include "pthread.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 定义数据包丢弃原因, 用于调试跟踪 */
#define PACKET_DROP_SOCKET_NOT_DEFINED     (1<<0)
#define PACKET_DROP_TUNTAP_NOT_DEFINED     (1<<1)
#define PACKET_DROP_CRYPTO_OPTION_ERROR    (1<<2)
#define PACKET_DROP_SCRIPT_NOT_SUCCEEDED   (1<<3)
#define PACKET_DROP_WRITE_ERROR            (1<<4)
#define PACKET_DROP_FRAGMENT_ERROR         (1<<5)
#define PACKET_DROP_LZO_ERROR              (1<<6)
#define PACKET_DROP_MROUTE_EXTRACT_FAIL    (1<<7)
#define PACKET_DROP_BAD_PACKET_ID          (1<<8)
#define PACKET_DROP_OCC_PACKET             (1<<9)
#define PACKET_DROP_PING_PACKET            (1<<10)
#define PACKET_DROP_CORRUPT_GREMLIN        (1<<11)
#define PACKET_DROP_BY_PACKET_FILTER       (1<<12)
#define PACKET_DROP_BAD_SOURCE_ADDRESS     (1<<13)
#define PACKET_DROP_HMAC_AUTH_FAILED       (1<<14)
#define PACKET_DROP_CRYPT_FAILED           (1<<15)
#define PACKET_DROP_SOCKS_ERROR            (1<<16)
#define PACKET_DROP_CAS_NOT_SUCCEEDED      (1<<17)
#define PACKET_DROP_ID_ROLL_OVER           (1<<18)

/*
 * OpenVPN's default port number as assigned by IANA.
 */
#define OPENVPN_PORT 1194

/*
 * Number of seconds that "resolv-retry infinite"
 * represents.
 */
#define RESOLV_RETRY_INFINITE 1000000000

/* 
 * packet_size_type is used to communicate packet size over
 * the wire when stream oriented protocols are being used
 */

typedef uint16_t packet_size_type;

/* convert a packet_size_type from host to network order */
#define htonps(x) htons(x)

/* convert a packet_size_type from network to host order */
#define ntohps(x) ntohs(x)

/* OpenVPN sockaddr struct */
struct openvpn_sockaddr
{
	/*int dummy;*/ /* add offset to force a bug if sa not explicitly dereferenced */
	union
	{
		struct sockaddr sa;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} addr;
};

/* actual address of remote, based on source address of received packets */
struct link_socket_actual
{
	/*int dummy;*/ /* add offset to force a bug if dest not explicitly dereferenced */
	struct openvpn_sockaddr dest;
#if ENABLE_IP_PKTINFO
	union
	{
#ifdef HAVE_IN_PKTINFO
		struct in_pktinfo in4;
#elif defined(IP_RECVDSTADDR)
		struct in_addr in4;
#endif
		struct in6_pktinfo in6;
	} pi;
#endif
};

/* IP addresses which are persistant across SIGUSR1s */
struct link_socket_addr
{
	struct openvpn_sockaddr local;
	struct openvpn_sockaddr remote;   /* initial remote */
	struct link_socket_actual actual; /* reply to this address */
};

struct link_socket_info
{
	struct link_socket_addr *lsa;
	bool connection_established;
	const char *ipchange_command;
	const struct plugin_list *plugins;
	bool remote_float;  
	int proto;                    /* Protocol (PROTO_x defined below) */
	int mtu_changed;              /* Set to true when mtu value is changed */
};

/*
 * Used to extract packets encapsulated in streams into a buffer,
 * in this case IP packets embedded in a TCP stream.
 */
struct stream_buf
{
	struct buffer buf_init;
	struct buffer residual;
	int maxlen;
	bool residual_fully_formed;

	struct buffer buf;
	struct buffer next;
	int len;     /* -1 if not yet known */

	bool error;  /* if true, fatal TCP error has occurred,
				 requiring that connection be restarted */
#if PORT_SHARE
# define PS_DISABLED 0
# define PS_ENABLED  1
# define PS_FOREIGN  2
	int port_share_state;
#endif
};

/*
 * Used to set socket buffer sizes
 */
struct socket_buffer_size
{
	int rcvbuf;
	int sndbuf;
};

#if defined(TARGET_LINUX) || defined(TARGET_ANDROID)
#define PKTINFO_BUF_SIZE       64
#define MAX_OVERLAPPED_SIZE    64
#define DEF_OVERLAPPED_WRITE   4    /* 必须足够小(需要及时写出) */

#define OVERLAPPED_READ_EMPTY_RETURN  (1<<0)	/* 如果缓存为空, 立即返回 */
#define OVERLAPPED_FORCE_FLUSH        (1<<1)	/* 立即写出链路缓存 */
#define OVERLAPPED_PACKET_INVALID     (1<<2)	/* 包内容无效，仅用来刷新链路缓存 */

struct overlapped
{
	struct link_socket_actual addr;
	int addrlen;
	struct buffer buf;
};

struct overlapped_io
{
	int offset;
	int size;

	uint64_t stats[MAX_OVERLAPPED_SIZE];

	struct iovec iov[MAX_OVERLAPPED_SIZE];
	struct mmsghdr mesg[MAX_OVERLAPPED_SIZE];
	uint8_t pktinfo_buf[MAX_OVERLAPPED_SIZE][PKTINFO_BUF_SIZE];

	struct overlapped items[MAX_OVERLAPPED_SIZE];
};
#endif

/*
 * This is the main socket structure used by OpenVPN.  The SOCKET_
 * defines try to abstract away our implementation differences between
 * using sockets on Posix vs. Win32.
 */
struct link_socket
{
	struct link_socket_info info;

	socket_descriptor_t sd;

#ifdef ENABLE_SOCKS
	socket_descriptor_t ctrl_sd;  /* only used for UDP over Socks */
#endif

#ifdef WIN32
	struct overlapped_io reads;
	struct overlapped_io writes;
	struct rw_handle rw_handle;
	struct rw_handle listen_handle; /* For listening on TCP socket in server mode */
#else
	struct overlapped_io reads;
	struct overlapped_io writes;
#endif

	/* used for printing status info only */
	unsigned int rwflags_debug;

	/* used for long-term queueing of pre-accepted socket listen */
	bool listen_persistent_queued;

	/* Does config file contain any <connection> ... </connection> blocks? */
	bool connection_profiles_defined;

	const char *remote_host;
	int remote_port;
	const char *local_host;
	int local_port;
	bool bind_local;

# define INETD_NONE   0
# define INETD_WAIT   1
# define INETD_NOWAIT 2
	int inetd;

# define LS_MODE_DEFAULT           0
# define LS_MODE_TCP_LISTEN        1
# define LS_MODE_TCP_ACCEPT_FROM   2
	int mode;

	int resolve_retry_seconds;
	int connect_retry_seconds;
	int connect_timeout;
	int connect_retry_max;
	int mtu_discover_type;

	struct socket_buffer_size socket_buffer_sizes;

	int mtu;                      /* OS discovered MTU, or 0 if unknown */

	bool did_resolve_remote;

# define SF_USE_IP_PKTINFO    (1<<0)
# define SF_TCP_NODELAY       (1<<1)
# define SF_PORT_SHARE        (1<<2)
# define SF_HOST_RANDOMIZE    (1<<3)
# define SF_GETADDRINFO_DGRAM (1<<4)
# define SF_USE_SENDMMSG      (1<<5)
# define SF_USE_RECVMMSG      (1<<6)
	unsigned int sockflags;

	/* for stream sockets */
	struct stream_buf stream_buf;
	struct buffer stream_buf_data;
	bool stream_reset;

#ifdef ENABLE_MASQUERADE
	/* 链路伪装选项 */
	struct masquerade_options *masq_options;
#endif

#ifdef ENABLE_HTTP_PROXY
	/* HTTP proxy */
	struct http_proxy_info *http_proxy;
#endif

#ifdef ENABLE_SOCKS
	/* Socks proxy */
	struct socks_proxy_info *socks_proxy;
	struct link_socket_actual socks_relay; /* Socks UDP relay address */
#endif

#if defined(ENABLE_HTTP_PROXY) || defined(ENABLE_SOCKS)
	/* The OpenVPN server we will use the proxy to connect to */
	const char *proxy_dest_host;
	int proxy_dest_port;
#endif

#if PASSTOS_CAPABILITY
	/* used to get/set TOS. */
#if defined(TARGET_LINUX)
	uint8_t ptos;
#else /* all the BSDs, Solaris, MacOS use plain "int" -> see "man ip" there */
	int  ptos;
#endif
	bool ptos_defined;
#endif

#ifdef ENABLE_DEBUG
	int gremlin; /* --gremlin bits */
#endif
};

/* Some Posix/Win32 differences. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef WIN32

#define openvpn_close_socket(s) closesocket(s)

int socket_recv_queue (struct link_socket *sock, int maxsize, struct buffer *buf, struct link_socket_actual *from);

int socket_send_queue (struct link_socket *sock, struct buffer *buf, const struct link_socket_actual *to);

int socket_finalize (SOCKET s, struct overlapped_io *io, struct buffer *buf, struct link_socket_actual *from);

#else

#define openvpn_close_socket(s) close(s)

#endif

struct link_socket *link_socket_new (void);

void socket_bind (socket_descriptor_t sd, struct openvpn_sockaddr *local, const char *prefix);

int openvpn_connect (socket_descriptor_t sd, struct openvpn_sockaddr *remote, int connect_timeout,
		volatile int *signal_received);

/* Initialize link_socket object. */
void
link_socket_init_phase1 (struct link_socket *sock,
		const bool connection_profiles_defined,
		const char *local_host,
		int local_port,
		const char *remote_host,
		int remote_port,
		int proto,
		int mode,
		const struct link_socket *accept_from,
#ifdef ENABLE_MASQUERADE
		struct masquerade_options *masq_options,
#endif
#ifdef ENABLE_HTTP_PROXY
		struct http_proxy_info *http_proxy,
#endif
#ifdef ENABLE_SOCKS
		struct socks_proxy_info *socks_proxy,
#endif
#ifdef ENABLE_DEBUG
		int gremlin,
#endif
		bool bind_local,
		bool remote_float,
		int inetd,
		struct link_socket_addr *lsa,
		const char *ipchange_command,
		const struct plugin_list *plugins,
		int resolve_retry_seconds,
		int connect_retry_seconds,
		int connect_timeout,
		int connect_retry_max,
		int mtu_discover_type,
		int rcvbuf,
		int sndbuf,
		int mark,
		unsigned int sockflags);

void link_socket_init_phase2 (struct link_socket *sock, const struct frame *frame,
		volatile int *signal_received);

void socket_adjust_frame_parameters (struct frame *frame, int proto);

void frame_adjust_path_mtu (struct frame *frame, int pmtu, int proto);

void link_socket_close (struct link_socket *sock);

void sd_close (socket_descriptor_t *sd);

#define PS_SHOW_PORT_IF_DEFINED (1<<0)
#define PS_SHOW_PORT            (1<<1)
#define PS_SHOW_PKTINFO         (1<<2)
#define PS_DONT_SHOW_ADDR       (1<<3)

const char *print_sockaddr_ex (const struct openvpn_sockaddr *addr, const char *separator,
		const unsigned int flags, struct gc_arena *gc);


const char *print_sockaddr (const struct openvpn_sockaddr *addr, struct gc_arena *gc);

const char *print_link_socket_actual_ex (const struct link_socket_actual *act,
		const char *separator, const unsigned int flags, struct gc_arena *gc);

const char *print_link_socket_actual (const struct link_socket_actual *act, struct gc_arena *gc);


#define IA_EMPTY_IF_UNDEF (1<<0)
#define IA_NET_ORDER      (1<<1)
const char *print_in_addr_t (in_addr_t addr, unsigned int flags, struct gc_arena *gc);
const char *print_in6_addr  (struct in6_addr addr6, unsigned int flags, struct gc_arena *gc);
struct in6_addr add_in6_addr (struct in6_addr base, uint32_t add);

#define SA_IP_PORT        (1<<0)
#define SA_SET_IF_NONZERO (1<<1)
void setenv_sockaddr (struct env_set *es, const char *name_prefix, const struct openvpn_sockaddr *addr,
		const unsigned int flags);

void setenv_in_addr_t (struct env_set *es, const char *name_prefix, in_addr_t addr,
		const unsigned int flags);

void setenv_in6_addr (struct env_set *es, const char *name_prefix, const struct in6_addr *addr,
		const unsigned int flags);

void setenv_link_socket_actual (struct env_set *es, const char *name_prefix,
		const struct link_socket_actual *act, const unsigned int flags);

void bad_address_length (int actual, int expected);

/*
 * IPV4_INVALID_ADDR: returned by link_socket_current_remote()
 * to ease redirect-gateway logic for ipv4 tunnels on ipv6 endpoints
 */
#define IPV4_INVALID_ADDR 0xffffffff
in_addr_t link_socket_current_remote (const struct link_socket_info *info);

void link_socket_connection_initiated (const struct buffer *buf, struct link_socket_info *info,
		const struct link_socket_actual *addr, const char *common_name, struct env_set *es);

void link_socket_bad_incoming_addr (struct buffer *buf, const struct link_socket_info *info,
		const struct link_socket_actual *from_addr);

void link_socket_bad_outgoing_addr (void);

void setenv_trusted (struct env_set *es, const struct link_socket_info *info);

bool link_socket_update_flags (struct link_socket *ls, unsigned int sockflags);
void link_socket_update_buffer_sizes (struct link_socket *ls, int rcvbuf, int sndbuf);

/* Low-level functions */

/* return values of openvpn_inet_aton */
#define OIA_HOSTNAME   0
#define OIA_IP         1
#define OIA_ERROR     -1
int openvpn_inet_aton (const char *dotted_quad, struct in_addr *addr);

int addr_guess_family (int proto, const char *name);

/* integrity validation on pulled options */
bool ip_addr_dotted_quad_safe (const char *dotted_quad);
bool ip_or_dns_addr_safe (const char *addr, const bool allow_fqdn);
bool mac_addr_safe (const char *mac_addr);
bool ipv6_addr_safe (const char *ipv6_text_addr);

socket_descriptor_t create_socket_tcp (int af);

socket_descriptor_t socket_do_accept (socket_descriptor_t sd, struct link_socket_actual *act,
		const bool nowait);
/* proto related */
bool proto_is_net (int proto);
bool proto_is_dgram (int proto);
bool proto_is_udp (int proto);
bool proto_is_tcp (int proto);


#if UNIX_SOCK_SUPPORT

socket_descriptor_t create_socket_unix (void);

void socket_bind_unix (socket_descriptor_t sd, struct sockaddr_un *local, const char *prefix);

socket_descriptor_t socket_accept_unix (socket_descriptor_t sd, struct sockaddr_un *remote);

int socket_connect_unix (socket_descriptor_t sd, struct sockaddr_un *remote);

void sockaddr_unix_init (struct sockaddr_un *local, const char *path);

const char *sockaddr_unix_name (const struct sockaddr_un *local, const char *null);

void socket_delete_unix (const struct sockaddr_un *local);

bool unix_socket_get_peer_uid_gid (const socket_descriptor_t sd, int *uid, int *gid);

#endif

/* DNS resolution */
#define GETADDR_RESOLVE               (1<<0)
#define GETADDR_FATAL                 (1<<1)
#define GETADDR_HOST_ORDER            (1<<2)
#define GETADDR_MENTION_RESOLVE_RETRY (1<<3)
#define GETADDR_FATAL_ON_SIGNAL       (1<<4)
#define GETADDR_WARN_ON_SIGNAL        (1<<5)
#define GETADDR_MSG_VIRT_OUT          (1<<6)
#define GETADDR_TRY_ONCE              (1<<7)
#define GETADDR_UPDATE_MANAGEMENT_STATE (1<<8)
#define GETADDR_RANDOMIZE             (1<<9)

in_addr_t getaddr (unsigned int flags, const char *hostname, int resolve_retry_seconds,
		bool *succeeded, volatile int *signal_received);

int openvpn_getaddrinfo (unsigned int flags, const char *hostname, int resolve_retry_seconds,
		volatile int *signal_received, int ai_family, struct addrinfo **res);

/* Transport protocol naming and other details. */

/* Use enum's instead of #define to allow for easier optional proto support */
enum proto_num
{
	PROTO_NONE,  /* catch for uninitialized */
	PROTO_UDPv4,
	PROTO_TCPv4_SERVER,
	PROTO_TCPv4_CLIENT,
	PROTO_TCPv4,
	PROTO_UDPv6,
	PROTO_TCPv6_SERVER,
	PROTO_TCPv6_CLIENT,
	PROTO_TCPv6,
	PROTO_N
};

int ascii2proto (const char *proto_name);
const char *proto2ascii (int proto, bool display_form);
const char *proto2ascii_all (struct gc_arena *gc);
int proto_remote (int proto, bool remote);
const char *addr_family_name (int af);

/* Overhead added to packets by various protocols. */
#define IPv4_UDP_HEADER_SIZE              28
#define IPv4_TCP_HEADER_SIZE              40
#define IPv6_UDP_HEADER_SIZE              48
#define IPv6_TCP_HEADER_SIZE              60

extern const int proto_overhead[];

/*
 * Stream buffer handling -- stream_buf is a helper class to assist in the packetization
 * of stream transport protocols such as TCP.
 */

void stream_buf_init (struct stream_buf *sb, struct buffer *buf, const unsigned int sockflags,
		const int proto);

void stream_buf_close (struct stream_buf* sb);
bool stream_buf_added (struct stream_buf *sb, int length_added
#ifdef ENABLE_MASQUERADE
			, struct masquerade_options *opt
#endif
	);

/* Socket Read Routines */
int link_socket_read_tcp (struct link_socket *sock, struct buffer *buf, unsigned int flags);

#ifndef WIN32

int link_socket_read_udp_posix (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *from,
		unsigned int flags);

#endif

/* Socket Write routines */
int link_socket_write_tcp (struct link_socket *sock, struct buffer *buf, struct link_socket_actual *to,
		unsigned int flags);

event_t socket_listen_event_handle (struct link_socket *s);

unsigned int
socket_set (struct link_socket *s, struct event_set *es, unsigned int rwflags, void *arg,
		unsigned int *persistent);

const char *socket_stat (const struct link_socket *s, unsigned int rwflags, struct gc_arena *gc);

#ifdef __cplusplus
}
#endif

#endif /* SOCKET_H */
