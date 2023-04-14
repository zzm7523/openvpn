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

#ifndef OPENVPN_H
#define OPENVPN_H

#include "buffer.h"
#include "options.h"
#include "socket.h"
#include "crypto.h"
#include "ssl.h"
#include "packet_id.h"
#include "lzo.h"
#include "tun.h"
#include "interval.h"
#include "status.h"
#include "fragment.h"
#include "shaper.h"
#include "route.h"
#include "proxy.h"
#include "socks.h"
#include "sig.h"
#include "misc.h"
#include "pool.h"
#include "plugin.h"
#include "manage.h"
#include "pf.h"
#include "packet_buffer.h"
#include "thread.h"

#ifdef WIN32
#include <sys/timeb.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Our global key schedules, packaged thusly to facilitate --persist-key. */
struct key_schedule
{
#ifdef ENABLE_CRYPTO
	/* which cipher, HMAC digest, and key sizes are we using? */
	struct key_type key_type;

	/* pre-shared static key, read from a file */
	int n_static_key;
	struct key_ctx_bi *static_key;

#ifdef ENABLE_SSL
	/* our global SSL context */
	struct tls_root_ctx ssl_ctx;

	/* optional authentication HMAC key for TLS control channel */
	struct key_ctx_bi tls_auth_key;

#endif				/* ENABLE_SSL */
#else				/* ENABLE_CRYPTO */
	int dummy;
#endif				/* ENABLE_CRYPTO */
};

/* struct packet_id_persist should be empty if we are not building with crypto. */
#ifndef PACKET_ID_H
struct packet_id_persist
{
	int dummy;
};

static inline void
packet_id_persist_init (struct packet_id_persist *p)
{
}
#endif

/* Packet processing buffers. */
struct context_buffers
{
	/* TUN设备最后读进包序号 */
	int64_t read_tun_data_seq;
	/* 链路最后读进包序号 */
	int64_t read_link_data_seq;

#ifdef ENABLE_FRAGMENT
	/* 链路等待分片包序号, 访问必须持有read_tun_bufs_pin_mutex锁 */
	int64_t frag_data_seq;
#endif

	/* 当前写(加密) local_key_id, 访问必须持有read_tun_bufs_mutex锁 */
	int64_t write_local_key_id;

	/* 当前写(加密) local_pin, 未启用分片, 需持有read_tun_bufs_mutex; 启用分片, 需持有read_tun_bufs_pin_mutex */
	int64_t write_local_pin;

	/* LINK写工作缓存列表(准备好的), 只有主线程访问, 不需要锁定 */
	struct packet_buffer_list *link_write_bufs;
	/* TUN写工作缓存列表(准备好的), 只有TUN读写线程访问, 不需要锁定 */
	struct packet_buffer_list *tun_write_bufs;

	/* LINK读工作缓存列表, 只有主线程访问, 不需要锁定 */
	struct packet_buffer_list *link_read_bufs;
	/* TUN读工作缓存列表, 只有TUN读写线程访问, 不需要锁定 */
	struct packet_buffer_list *tun_read_bufs;

	/* 从链路读取的包缓存 */
	pthread_mutex_t read_link_bufs_mutex;
	struct packet_buffer_list *read_link_bufs;

	/* 从TUN设备读取的包缓存 */
	pthread_mutex_t read_tun_bufs_mutex;
	struct packet_buffer_list *read_tun_bufs;

#ifdef ENABLE_FRAGMENT
	pthread_mutex_t read_tun_bufs_pin_mutex;
	struct packet_buffer_list *read_tun_bufs_pin;
	pthread_mutex_t read_tun_bufs_enc_mutex;
	struct packet_buffer_list *read_tun_bufs_enc;
#endif

	/* 写往链路的包缓存 */
	pthread_mutex_t to_link_bufs_mutex;
	struct packet_buffer_list *to_link_bufs;     /* 准备好的 */
	int64_t to_link_bufs_last_local_pin;
	struct packet_buffer_list *to_link_bufs_rdy; /* 未准备好的 */

	/* 写往TUN设备的包缓存 */
	pthread_mutex_t to_tun_bufs_mutex;
	struct packet_buffer_list *to_tun_bufs;     /* 准备好的 */
	int64_t to_tun_bufs_last_seq;
	struct packet_buffer_list *to_tun_bufs_rdy; /* 未准备好的 */
};

/* always-persistent context variables */
struct context_persist
{
	int restart_sleep_seconds;
};


/**************************************************************************/
/**
 * Level 0 %context containing information related to the OpenVPN process.
 *
 * Level 0 state is initialized once at program startup, and then remains
 * throughout the lifetime of the OpenVPN process.  This structure
 * contains information related to the process's PID, user, group, and privileges.
 */
struct context_0
{
	/* workspace for --user/--group */
	bool uid_gid_specified;
	/* helper which tells us whether we should keep trying to drop privileges */
	bool uid_gid_chroot_set;
	struct platform_state_user platform_state_user;
	struct platform_state_group platform_state_group;
};


/**
 * Level 1 %context containing state that persists across \c SIGUSR1
 * restarts.
 *
 * Level 1 state is reset on \c SIGHUP restarts.  This structure is
 * initialized for every iteration of the \c main() function's outer \c
 * SIGHUP loop, but persists over iteration of that function's inner \c
 * SIGUSR1 loop.
 */
struct context_1
{
	struct link_socket_addr link_socket_addr;
	/**< Local and remote addresses on the external network. */

	/* tunnel session keys */
	struct key_schedule ks;

	/* persist crypto sequence number to/from file */
	struct packet_id_persist pid_persist;

	struct tuntap *tuntap;        /**< Tun/tap virtual network interface. */
	bool tuntap_owned;            /**< Whether the tun/tap interface should
								  *   be cleaned up when this %context is
								  *   cleaned up. */

	struct route_list *route_list;
	/**< List of routing information. See the --route command line option. */

	/* list of --route-ipv6 directives */
	struct route_ipv6_list *route_ipv6_list;

	/* --status file */
	struct status_output *status_output;
	bool status_output_owned;

#ifdef ENABLE_MASQUERADE
	/* 链路伪装选项 */
	struct masquerade_options *masq_options;
	bool masq_options_owned;
#endif

#ifdef ENABLE_HTTP_PROXY
	/* HTTP proxy object */
	struct http_proxy_info *http_proxy;
	bool http_proxy_owned;
#endif

#ifdef ENABLE_SOCKS
	/* SOCKS proxy object */
	struct socks_proxy_info *socks_proxy;
	bool socks_proxy_owned;
#endif

#if P2MP

#if P2MP_SERVER
	/* persist --ifconfig-pool db to file */
	struct ifconfig_pool_persist *ifconfig_pool_persist;
	bool ifconfig_pool_persist_owned;
#endif

	/* if client mode, hash of option strings we pulled from server */
	struct md5_digest pulled_options_digest_save;
	/**< Hash of option strings received from the remote OpenVPN server. Only used in client-mode. */

	struct user_pass *auth_user_pass;
	/**< Username and password for authentication. */
#endif
};

struct tun_io_stats
{
	time_t last_sync_time;
	counter_type write_bytes;
	counter_type read_bytes;
	counter_type inactivity_bytes;
	char padding[CACHE_LINE_SIZE - sizeof (time_t) - 3 * sizeof (counter_type)];
};

struct link_read_auth_stats
{
	time_t last_sync_time;
	counter_type read_bytes_auth;
	char padding[CACHE_LINE_SIZE - sizeof (time_t) - sizeof (counter_type)];
};

/**
 * Level 2 %context containing state that is reset on both \c SIGHUP and
 * \c SIGUSR1 restarts.
 *
 * This structure is initialized at the top of the \c
 * tunnel_point_to_point(), \c tunnel_server_udp_single_threaded(), and \c
 * tunnel_server_tcp() functions.  In other words, it is reset for every
 * iteration of the \c main() function's inner \c SIGUSR1 loop.
 */
struct context_2
{
	struct gc_arena gc;           /**< Garbage collection arena for
								  *   allocations done in the level 2 scope
								  *   of this context_2 structure. */

	/* our global wait events */
	struct event_set *event_set;
	int event_set_max;
	bool event_set_owned;
	unsigned int event_set_status;

#ifdef ENABLE_TUN_THREAD
	struct event_set *tun_event_set;
	int tun_event_set_max;
	bool tun_event_set_owned;
	unsigned int tun_event_set_status;
#endif

	/* event flags returned by io_wait */
#define SOCKET_READ       (1<<0)
#define SOCKET_WRITE      (1<<1)
#define TUN_READ          (1<<2)
#define TUN_WRITE         (1<<3)
#define ES_ERROR          (1<<4)
#define ES_TIMEOUT        (1<<5)
#ifdef ENABLE_MANAGEMENT
#define MANAGEMENT_READ   (1<<6)
#define MANAGEMENT_WRITE  (1<<7)
# endif
#define ES_WAKEUP         (1<<8)

	struct link_socket *link_socket;	 /* socket used for TCP/UDP connection to remote */
	bool link_socket_owned;

	struct packet_buffer *link_flush;	/* 特殊包, 用来刷新链路写缓存 */
	bool link_flush_owned;

	struct link_socket_info *link_socket_info;
	const struct link_socket *accept_from; /* possibly do accept() on a parent link_socket */

	struct link_socket_actual *to_link_addr;	/* IP address of remote */
	struct link_socket_actual from;				/* address of incoming datagram */
	struct link_socket_actual last_from;		/* 只有TUN线程访问 */

	/* MTU frame parameters */
	struct frame frame;

#ifdef ENABLE_FRAGMENT
	/* Object to handle advanced MTU negotiation and datagram fragmentation */
	pthread_mutex_t fragment_in_mutex;
	pthread_mutex_t fragment_out_mutex;
	struct fragment_master *fragment;
	struct frame frame_fragment;
	struct frame frame_fragment_omit;
#endif

#ifdef ENABLE_FEATURE_SHAPER
	/* Traffic shaper object. */
	struct shaper shaper;
#endif

	/* Statistics */
	counter_type tun_write_bytes;
	counter_type tun_read_bytes;
	struct tun_io_stats tun_io_stats;

	counter_type link_write_bytes;
	counter_type link_read_bytes;

	counter_type link_read_bytes_auth;
	/* link_read_auth_stats数组, 每个线程一个link_read_auth_stats对象 */
	struct link_read_auth_stats link_read_auth_stats[MAX_THREAD_INDEX];

#ifdef PACKET_TRUNCATION_CHECK
	counter_type n_trunc_tun_read;
	counter_type n_trunc_tun_write;
	counter_type n_trunc_pre_encrypt;
	counter_type n_trunc_post_decrypt;
#endif

	struct event_timeout bytecount_update_interval;
#ifdef ENABLE_GUOMI
	struct event_timeout device_check_interval;
#endif

	/* Timer objects for ping and inactivity timeout features. */
	struct event_timeout wait_for_connect;
	struct event_timeout ping_send_interval;
	struct event_timeout ping_rec_interval;

	/* --inactive */
	struct event_timeout inactivity_interval;
	counter_type inactivity_bytes;

#ifdef ENABLE_OCC
	/* the option strings must match across peers */
	char *options_string_local;
	char *options_string_remote;

	int occ_op;			/* INIT to -1 */
	int occ_n_tries;
	struct event_timeout occ_interval;
#endif

	/* Keep track of maximum packet size received so far (of authenticated packets). */
	int original_recv_size;		/* temporary */
	int max_recv_size_local;	/* max packet size received */
	int max_recv_size_remote;	/* max packet size received by remote */
	int max_send_size_local;	/* max packet size sent */
	int max_send_size_remote;	/* max packet size sent by remote */

#ifdef ENABLE_OCC
	/* remote wants us to send back a load test packet of this size */
	int occ_mtu_load_size;

	struct event_timeout occ_mtu_load_test_interval;
	int occ_mtu_load_n_tries;
#endif

#ifdef ENABLE_CRYPTO

	/* TLS-mode crypto objects. */
#ifdef ENABLE_SSL

	struct tls_multi *tls_multi;  /**< TLS state structure for this VPN tunnel. */

	struct tls_auth_standalone *tls_auth_standalone;
	/**< TLS state structure required for the
	*   initial authentication of a client's
	*   connection attempt.  This structure
	*   is used by the \c
	*   tls_pre_decrypt_lite() function when
	*   it performs the HMAC firewall check
	*   on the first connection packet
	*   received from a new client.  See the
	*   \c --tls-auth commandline option. */

	/* used to optimize calls to tls_multi_process */
	struct interval tmp_int;

	/* throw this signal on TLS errors */
	int tls_exit_signal;

#endif /* ENABLE_SSL */

	struct crypto_options crypto_options;
	/**< Security parameters and crypto state
	*   used by the \link data_crypto Data
	*   Channel Crypto module\endlink to
	*   process data channel packet. */

	/* used to keep track of data channel packet sequence numbers */
	struct packet_id packet_id;
	struct event_timeout packet_id_persist_interval;

#endif /* ENABLE_CRYPTO */

	/* Buffers used for packet processing. */
	struct context_buffers *buffers;
	bool buffers_owned; /* if true, we should free all buffers on close */

	/* 不实际分配缓存, 指向tls协议数据 */
	struct buffer to_link;

	/* IPv4 TUN device? */
	bool ipv4_tun;

	/* should we print R|W|r|w to console on packet transfers? */
	bool log_rw;

	/* route stuff */
	struct event_timeout route_wakeup;
	struct event_timeout route_wakeup_expire;

	/* did we open tun/tap dev during this cycle? */
	bool did_open_tun;

	/* 主线程生成了PING或OCC包, 需要发送(放入multi_context的read_tun_pendings队列) */
	bool did_tun_pending0;

	/* TUN线程生成广播或客户到客户路由, 需要发送(放入multi_context的read_tun_pendings队列) */
	bool did_tun_pending1;

	/* Event loop info */

	/* how long to wait on link/tun read before we will need to be serviced */
	struct timeval timeval;

	/* next wakeup for processing coarse timers (>1 sec resolution) */
	time_t coarse_timer_wakeup;

	/* maintain a random delta to add to timeouts to avoid contexts waking up simultaneously */
	time_t update_timeout_random_component;
	struct timeval timeout_random_component;

	/* indicates that the do_up_delay function has run */
	bool do_up_ran;

#ifdef ENABLE_OCC
	/* indicates that we have received a SIGTERM when options->explicit_exit_notification is enabled,
	but we have not exited yet */
	time_t explicit_exit_notification_time_wait;
	struct event_timeout explicit_exit_notification_interval;
#endif

	/* environmental variables to pass to scripts */
	struct env_set *es;
	bool es_owned;

#if P2MP

#if P2MP_SERVER
	/* --ifconfig endpoints to be pushed to client */
	bool push_reply_deferred;
	bool push_ifconfig_defined;
	time_t sent_push_reply_expiry;
	in_addr_t push_ifconfig_local;
	in_addr_t push_ifconfig_remote_netmask;
#ifdef ENABLE_CLIENT_NAT
	in_addr_t push_ifconfig_local_alias;
#endif

	bool push_ifconfig_ipv6_defined;
	struct in6_addr push_ifconfig_ipv6_local;
	int push_ifconfig_ipv6_netbits;
	struct in6_addr push_ifconfig_ipv6_remote;

	/* client authentication state, CAS_SUCCEEDED must be 0 */
# define CAS_SUCCEEDED 0
# define CAS_PENDING   1
# define CAS_FAILED    2
# define CAS_PARTIAL   3 /* at least one client-connect script/plugin
	succeeded while a later one in the chain failed */
	volatile int context_auth;
#endif

	struct event_timeout push_request_interval;
	int n_sent_push_requests;
	bool did_pre_pull_restore;

	/* hash of pulled options, so we can compare when options change */
	bool pulled_options_md_init_done;
	md_ctx_t *pulled_options_ctx;
	struct md5_digest pulled_options_digest;

	struct event_timeout server_poll_interval;

	struct event_timeout scheduled_exit;
	int scheduled_exit_signal;
#endif

	/* packet filter */
#ifdef ENABLE_PF
	struct pf_context pf;
#endif

#ifdef MANAGEMENT_DEF_AUTH
	struct man_def_auth_context mda_context;
#endif
};

/**
 * Contains all state information for one tunnel.
 *
 * This structure represents one VPN tunnel.  It is used to store state
 * information related to a VPN tunnel, but also includes process-wide
 * data, such as configuration options.
 *
 * The @ref tunnel_state "Structure of VPN tunnel state storage" related
 * page describes how this structure is used in client-mode and
 * server-mode.
 */
struct context
{
	struct options options;		/**< Options loaded from command line or configuration file. */

	bool first_time;	/**< True on the first iteration of OpenVPN's main loop. */

	pthread_rwlock_t share_lock;	/* 共享锁 */

	/* context modes */
# define CM_P2P            0 /* standalone point-to-point session or client */
# define CM_TOP            1 /* top level of a multi-client or point-to-multipoint server */
# define CM_TOP_CLONE      2 /* clone of a CM_TOP context for one thread */
# define CM_CHILD_UDP      3 /* child context of a CM_TOP or CM_THREAD */
# define CM_CHILD_TCP      4 /* child context of a CM_TOP or CM_THREAD */
	int mode;                     /**< Role of this context within the
								  *   OpenVPN process.  Valid values are \c
								  *   CM_P2P, \c CM_TOP, \c CM_TOP_CLONE,
								  *   \c CM_CHILD_UDP, and \c CM_CHILD_TCP. */

	struct gc_arena gc;           /**< Garbage collection arena for
								  *   allocations done in the scope of this
								  *   context structure. */

	struct env_set *es;           /**< Set of environment variables. */

	struct signal_info *sig;      /**< Internal error signaling object. */

	struct plugin_list *plugins;  /**< List of plug-ins. */
	bool plugins_owned;           /**< Whether the plug-ins should be
								  *   cleaned up when this %context is
								  *   cleaned up. */

	bool did_we_daemonize;        /**< Whether demonization has already
								  *   taken place. */

	struct context_persist persist;
	/**< Persistent %context. */
	struct context_0 *c0;         /**< Level 0 %context. */
	struct context_1 c1;          /**< Level 1 %context. */
	struct context_2 c2;          /**< Level 2 %context. */
};

#ifdef WIN32
__CACHE_LINE_ALIGNED__
#endif
struct transfer_context
{
	volatile bool terminate;  /* 线程是否需要终止 */

	struct multi_context *m;  /* SERVER 全局上下文 */
	struct context *c;        /* P2P 全局上下文 */

	struct crypto_options crypto_opt;
	unsigned int rand;

	int thread_idx;       /* 0为主线程, 1为TUN设备读写线程 */
	pthread_t thread_id;  /* 线程ID*/

	struct multi_instance_list *work_pendings;

	struct packet_buffer_list *read_work_bufs;
	struct packet_buffer_list *write_work_bufs;
#ifdef ENABLE_FRAGMENT
	struct packet_buffer_list *frag_work_bufs;
#endif

	struct packet_buffer_list *link_reclaim_bufs;
	struct packet_buffer_list *tun_reclaim_bufs;
#ifdef ENABLE_FRAGMENT
	struct packet_buffer_list *frag_reclaim_bufs;
#endif
}
#ifndef WIN32
__CACHE_LINE_ALIGNED__
#endif
;

extern struct transfer_context *g_link_transfer_context;
extern struct transfer_context *g_tun_transfer_context;

extern pthread_t global_main_id;
extern struct multi_context *global_multi_context;	/* GLOBAL */
extern struct context *global_context;	/* GLOBAL */
extern struct argv *global_exec_argv;	/* GLOBAL */

void 
transfer_context_init (struct transfer_context *tc, struct multi_context *m, struct context *c);
void 
transfer_context_free (struct transfer_context *tc);

static inline void
ping_rec_interval_reset (struct context *c, int thread_idx, time_t now_sec)
{
	MUTEX_LOCK (&g_coarse_mutex, thread_idx, S_COARSE);
	// !!线程本地now_sec有差异, event_timeout_reset必须用实时时间
	event_timeout_reset (&c->c2.ping_rec_interval, openvpn_time (NULL, thread_idx));
	MUTEX_UNLOCK (&g_coarse_mutex, thread_idx, S_COARSE);
}

static inline void
link_read_auth_sync_stats (struct context *c, int thread_idx, time_t now_sec)
{
	if (c && now_sec > c->c2.link_read_auth_stats[thread_idx].last_sync_time)
	{
		MUTEX_LOCK (&g_coarse_mutex, thread_idx, S_COARSE);
		c->c2.link_read_bytes_auth += c->c2.link_read_auth_stats[thread_idx].read_bytes_auth;
		MUTEX_UNLOCK (&g_coarse_mutex, thread_idx, S_COARSE);

		c->c2.link_read_auth_stats[thread_idx].last_sync_time = now_sec;
		c->c2.link_read_auth_stats[thread_idx].read_bytes_auth = 0L;
	}
}

static inline void
link_read_auth_get_stats (const struct context *c, counter_type *read_bytes_auth)
{
	if (c && read_bytes_auth)
	{
		MUTEX_LOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);
		*read_bytes_auth = c->c2.link_read_bytes_auth;
		MUTEX_UNLOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);
	}
}

static inline void
tun_io_sync_stats (struct context *c, int thread_idx, time_t now_sec)
{
	if (c && now_sec > c->c2.tun_io_stats.last_sync_time)
	{
		MUTEX_LOCK (&g_coarse_mutex, thread_idx, S_COARSE);
		c->c2.tun_write_bytes += c->c2.tun_io_stats.write_bytes;
		c->c2.tun_read_bytes += c->c2.tun_io_stats.read_bytes;
		c->c2.inactivity_bytes += c->c2.tun_io_stats.inactivity_bytes;
		MUTEX_UNLOCK (&g_coarse_mutex, thread_idx, S_COARSE);

		c->c2.tun_io_stats.last_sync_time = now_sec;
		c->c2.tun_io_stats.write_bytes = 0L;
		c->c2.tun_io_stats.read_bytes = 0L;
		c->c2.tun_io_stats.inactivity_bytes = 0L;
	}
}

static inline void
tun_io_get_stats (const struct context *c, counter_type *read_bytes, counter_type *write_bytes, counter_type *inactivity_bytes)
{
	if (c && (read_bytes || write_bytes || inactivity_bytes))
	{
		MUTEX_LOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);
		if (read_bytes)
			*read_bytes = c->c2.tun_write_bytes;
		if (write_bytes)
			*write_bytes = c->c2.tun_read_bytes;
		if (inactivity_bytes)
			*inactivity_bytes = c->c2.inactivity_bytes;
		MUTEX_UNLOCK (&g_coarse_mutex, MAIN_THREAD_INDEX, S_COARSE);
	}
}

/* 设置包接收序号, 只有主线程访问, 不需要锁定 */
static inline void 
set_read_link_data_seq (struct context *c, struct packet_buffer *buf, struct timeval *now_tv)
{
#ifdef PERF_STATS_CHECK
	ASSERT (is_main_thread ());
	ASSERT (buf->ttl.tv_sec <= 0 && buf->seq_no <= 0 && buf->buf.len > 0);

	if (get_thread_id (WORKER_THREAD_INDEX_BASE))	/* 工作线程启动后才能分配TTL */
	{
		buf->extra = 0;
		packet_buffer_mark_ttl (buf, now_tv);
	}
#endif

	buf->flags |= PACKET_BUFFER_FRAG_LAST_FLAG;
	buf->seq_no = ++c->c2.buffers->read_link_data_seq;
}

/* 设置包接收序号, 只有TUN线程访问, 不需要锁定(tls、ping、occ、bcast, unicast包的seq_no统一设置为0) */
static inline void 
set_read_tun_data_seq (struct context *c, struct packet_buffer *buf, struct timeval *now_tv)
{
#ifdef PERF_STATS_CHECK
	ASSERT (is_tun_thread ());
	ASSERT (buf->ttl.tv_sec <= 0 && buf->seq_no <= 0 && buf->buf.len > 0);

	if (get_thread_id (WORKER_THREAD_INDEX_BASE))	/* 工作线程启动后才能分配TTL */
	{
		buf->extra = 0;
		packet_buffer_mark_ttl (buf, now_tv);
	}
#endif

	buf->flags |= PACKET_BUFFER_FRAG_LAST_FLAG;
	buf->seq_no = ++c->c2.buffers->read_tun_data_seq;
}

static inline struct link_socket_info *
get_link_socket_info (struct context *c)
{
	if (c->c2.link_socket_info)
		return c->c2.link_socket_info;
	else
		return &c->c2.link_socket->info;
}

static inline int 
prepare_process_link_any_incoming (struct context *c)
{
	struct packet_buffer_list *read_work_bufs = g_link_transfer_context->read_work_bufs;

	if (read_work_bufs->size < MAX_LINK_BATCH_READ)
	{
#ifdef ENABLE_TUN_THREAD
		/* g_link_free_bufs对象访问必须持有g_link_free_bufs_mutex锁 */
		MUTEX_LOCK (g_link_free_bufs_mutex, MAIN_THREAD_INDEX, S_LINK_FREE_BUFS);
		packet_buffer_list_attach_back (read_work_bufs, g_link_free_bufs);
		MUTEX_UNLOCK (g_link_free_bufs_mutex, MAIN_THREAD_INDEX, S_LINK_FREE_BUFS);
#else
		packet_buffer_list_attach_back (read_work_bufs, g_link_free_bufs);
#endif
	}
	return read_work_bufs->size;
}

static inline struct packet_buffer*
get_link_read_packet_buffer (struct context *c, bool alloc)
{
	struct packet_buffer_list *read_work_bufs = g_link_transfer_context->read_work_bufs;
	struct packet_buffer *buf = NULL;

#ifdef _DEBUG
	if (rand () % 100 == 0)	/* 测试动态分配packet_buffer */
		buf = packet_buffer_new (read_work_bufs->capacity, read_work_bufs->type);
#endif

	if (!buf)
	{
		if (read_work_bufs->size == 0)
			prepare_process_link_any_incoming (c);

		buf = packet_buffer_list_pop_front (read_work_bufs);
		if (buf)
			packet_buffer_clear (buf);
		else if (alloc)	/* TCP时需要创建临时packet_buffer对象 */
			buf = packet_buffer_new (read_work_bufs->capacity, read_work_bufs->type);
	}

	return buf;
}

#define CONNECTION_ESTABLISHED(c) (get_link_socket_info(c)->connection_established)

/*
 * Check for a signal when inside an event loop
 */
#define EVENT_LOOP_CHECK_SIGNAL(c, func, arg)   \
	if (IS_SIG (c))                           \
	{                                       \
		const int brk = func (arg);           \
		perf_pop ();                          \
		if (brk)                              \
			break;                              \
		else                                  \
			continue;                           \
	}

/*
 * Macros for referencing objects which may not have been compiled in.
 */

#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
#define TLS_MODE(c) ((c)->c2.tls_multi != NULL)
#define PROTO_DUMP_FLAGS (check_debug_level (D_LINK_RW_VERBOSE) ? (PD_SHOW_DATA|PD_VERBOSE) : 0)
#define PROTO_DUMP(buf, gc) protocol_dump ((buf), \
	PROTO_DUMP_FLAGS | \
	(c->c2.tls_multi ? PD_TLS : 0) | \
	(c->options.tls_auth_file ? c->c1.ks.key_type.hmac_length : 0), gc)
#else
#define TLS_MODE(c) (false)
#define PROTO_DUMP(buf, gc) format_hex (BPTR (buf), BLEN (buf), 80, gc)
#endif

#ifdef ENABLE_CRYPTO
#define MD5SUM(buf, len, gc) md5sum ((buf), (len), 0, (gc))
#else
#define MD5SUM(buf, len, gc) "[unavailable]"
#endif

#ifdef ENABLE_CRYPTO
#define CIPHER_ENABLED(c) (c->c1.ks.key_type.cipher != NULL)
#else
#define CIPHER_ENABLED(c) (false)
#endif

#ifdef __cplusplus
}
#endif

#endif
