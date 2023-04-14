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

/**
 * @file Header file for server-mode related structures and functions.
 */

#ifndef MULTI_H
#define MULTI_H

#if P2MP_SERVER

#include "init.h"
#include "socket.h"
#include "forward.h"
#include "tun-inline.h"
#include "forward-inline.h"
#include "mroute.h"
#include "list.h"
#include "schedule.h"
#include "pool.h"
#include "mudp.h"
#include "mtcp.h"
#include "perf.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Server-mode state structure for one single VPN tunnel.
 *
 * This structure is used by OpenVPN processes running in server-mode to store state
 * information related to one single VPN tunnel.
 *
 * The @ref tunnel_state "Structure of VPN tunnel state storage" related page describes
 * the role the structure plays when OpenVPN is running in server-mode.
 */
struct multi_instance
{
	struct schedule_entry se;	/* this must be the first element of the structure */
	struct gc_arena gc;
	bool defined;
	int refcount;
	int route_count;	/* number of routes (including cached routes) owned by this instance */
	time_t create_time;	/**< Time at which a VPN tunnel instance was created.
						 * This parameter is set by the \c multi_create_instance()
						 * function. */
	volatile bool halt;
	time_t halt_time;			/* halt时间, 延时关闭使用 */
	struct timeval wakeup;		/* absolute time */
	struct mroute_addr real;	/**< External network address of the remote peer. */
	ifconfig_pool_handle vaddr_handle;
	const char *msg_prefix;

	unsigned int tcp_rwflags;	/* queued outgoing data in Server/TCP mode */
	struct mbuf_set *tcp_link_out_deferred;
	bool socket_set_called;

	in_addr_t reporting_addr;       /* IP address shown in status listing */

	bool did_open_context;
	bool did_real_hash;
	bool did_iter;
#ifdef MANAGEMENT_DEF_AUTH
	bool did_cid_hash;
	struct buffer_list *cc_config;
#endif
	bool connection_established_flag;
	bool did_iroutes;
	volatile int n_clients_delta;	/* added to multi_context.n_clients when instance is closed */

	struct context context;			/* The context structure storing state for this VPN tunnel. */
};

struct multi_instance_entry
{
	struct multi_instance *mi;
	struct multi_instance_entry *next;
};

struct multi_instance_list
{
	volatile int size;
	unsigned int flags;  /* 处理指示, 诊断用 */

	struct multi_instance_entry *head;
	struct multi_instance_entry *tail;
	struct multi_instance_entry *free;
};

/* 延迟释放实例, DELAY_FREE_TIME > WORKER_THREAD_WAIT_TIMEOUT * 2 */
#define DELAY_FREE_TIME  10

/*
 * Walk (don't run) through the routing table, deleting old entries, and possibly
 * multi_instance structs as well which have been marked for deletion.
 */
struct multi_reap
{
	int bucket_base;
	int buckets_per_pass;
	time_t last_call;
};

/**
 * Main OpenVPN server state structure.
 *
 * This structure is used by OpenVPN processes running in server-mode to store all the
 * VPN tunnel and process-wide state.
 *
 * The @ref tunnel_state "Structure of VPN tunnel state storage" related page describes
 * the role the structure plays when OpenVPN is running in server-mode.
 */
struct multi_context
{
	/* VPN tunnel instances indexed by real address of the remote peer. 只有主线程访问, 不需要锁定 */
	struct hash *hash;
	/* VPN tunnel instances indexed by virtual address of remote hosts. 主线程、TUN线程都会访问, 需要锁定 */
	struct hash *vhash;
#ifdef ENABLE_TUN_THREAD
	pthread_mutex_t vhash_mutex;
#endif
	/* VPN tunnel instances indexed by real address of the remote peer. 主线程、TUN线程都会访问, 需要锁定 */
	struct hash *iter;
#ifdef ENABLE_TUN_THREAD
	pthread_mutex_t iter_mutex;
#endif

	struct schedule *schedule;
	struct multi_tcp *mtcp;       /* State specific to OpenVPN using TCP as external transport. */
	struct ifconfig_pool *ifconfig_pool;
	struct frequency_limit *new_connection_limiter;
	struct mroute_helper *route_helper;
	struct multi_reap *reaper;
	struct mroute_addr local;
	bool enable_c2c;
	int max_clients;
	int tcp_queue_limit;
	int status_file_version;
	volatile int n_clients; /* current number of authenticated clients */

#ifdef MANAGEMENT_DEF_AUTH
	struct hash *cid_hash;	/* 只有主线程访问, 不需要锁定 */
	unsigned long cid_counter;
#endif

	pthread_mutex_t read_tun_pendings_mutex;
	struct multi_instance_list *read_tun_pendings;

	pthread_mutex_t read_link_pendings_mutex;
	struct multi_instance_list *read_link_pendings;

	pthread_mutex_t to_tun_pendings_mutex;
	struct multi_instance_list *to_tun_pendings;

	pthread_mutex_t to_link_pendings_mutex;
	struct multi_instance_list *to_link_pendings;

	struct multi_instance_list *free_pendings;		/* 只有主线程访问, 不需要锁定 */

	struct multi_instance *earliest_wakeup;
	struct context_buffers *context_buffers;
	time_t per_second_trigger;

	struct context top;           /* < Storage structure for process-wide configuration. */
	struct event_timeout stale_routes_check_et;	/* Timer object for stale route check */
};

/* Host route */
struct multi_route
{
	struct mroute_addr addr;
	struct multi_instance *instance;

# define MULTI_ROUTE_CACHE   (1<<0)
# define MULTI_ROUTE_AGEABLE (1<<1)
	unsigned int flags;

	unsigned int cache_generation;
	time_t last_reference;
};

struct multi_instance_list* multi_instance_list_new (unsigned int flags);
void multi_instance_list_free (struct multi_instance_list *ml);

static inline void 
multi_instance_list_push_back (struct multi_instance_list *ml, struct multi_instance *mi)
{
	if (ml && mi)
	{
		struct multi_instance_entry *me;

		if (!ml->tail || (ml->head->mi != mi && ml->tail->mi != mi))
		{
			if (ml->free)
			{
				me = ml->free;
				ml->free = me->next;
				CLEAR (*me);
			}
			else
				ALLOC_OBJ_CLEAR (me, struct multi_instance_entry);

			++ml->size;
			me->mi = mi;
			if (ml->tail)
			{
				ml->tail->next = me;
				ml->tail = me;
			}
			else
				ml->head = ml->tail = me;
		}
	}
}

static inline struct multi_instance* 
multi_instance_list_pop_front (struct multi_instance_list *ml)
{
	struct multi_instance *mi = NULL;

	if (ml)
	{
		struct multi_instance_entry *me;

		me = ml->head;
		if (me)
		{
			mi = me->mi;
			--ml->size;

			ml->head = me->next;
			if (!ml->head)
				ml->head = ml->tail = NULL;

			CLEAR (*me);
			me->next = ml->free;
			ml->free = me;
		}
	}

	return mi;
}

static inline void
multi_instance_list_attach_back (struct multi_instance_list *ml, struct multi_instance_list *xl)
{
	if (ml && xl)
	{
		struct multi_instance *mi;

		while (xl->size > 0)
		{
			mi = multi_instance_list_pop_front (xl);
			if (mi)
				multi_instance_list_push_back (ml, mi);
		}
	}
}

static inline bool 
multi_instance_list_contain (struct multi_instance_list *ml, struct multi_instance *mi)
{
	if (ml && mi)
	{
		struct multi_instance_entry *me = ml->head;

		while (me)
		{
			if (me->mi == mi)
				return true;
			else
				me = me->next;
		}		

		ASSERT (!ml->tail || !ml->tail->next);
	}

	return false;
}

static inline void
multi_instance_list_remove (struct multi_instance_list *ml, struct multi_instance *mi)
{
	if (ml && mi)
	{
		struct multi_instance_entry *e = ml->head, *d = NULL, *p = NULL;

		while (e)
		{
			if (e->mi == mi)
			{
				if (p)
					p->next = e->next;
				if (e == ml->head)
					ml->head = e->next;
				if (e == ml->tail)
				{
					ml->tail = p;
					if (ml->tail)
						ml->tail->next = NULL;
				}

				--ml->size;
				d = e;
				e = e->next;

				CLEAR (*d);
				d->next = ml->free;
				ml->free = d;
			}
			else
			{
				p = e;
				e = e->next;
			}
		}		

		ASSERT (!ml->tail || !ml->tail->next);
	}
}

#define ISC_ERRORS (1<<0)
#define ISC_SERVER (1<<1)

void initialization_sequence_completed (struct context *c, const unsigned int flags);

/**************************************************************************/
/**
 * Main event loop for OpenVPN in server mode.
 * @ingroup eventloop
 *
 * This function calls the appropriate main event loop function depending
 * on the transport protocol used:
 *  - \c tunnel_server_udp()
 *  - \c tunnel_server_tcp()
 *
 * @param top          - Top-level context structure.
 */
void tunnel_server (struct context *top);


const char *multi_instance_string (const struct multi_instance *mi, bool null, struct gc_arena *gc);

/*
 * Called by mtcp.c, mudp.c, or other (to be written) protocol drivers
 */

void multi_init (struct multi_context *m, struct context *t, bool tcp_mode);
void multi_uninit (struct multi_context *m);

void multi_top_init (struct multi_context *m, const struct context *top, const bool alloc_buffers);
void multi_top_free (struct multi_context *m);

struct multi_instance *multi_create_instance (struct multi_context *m, const struct mroute_addr *real);
void multi_close_instance (struct multi_context *m, struct multi_instance *mi, bool shutdown);

bool multi_process_timeout (struct multi_context *m, const unsigned int mpp_flags);

#define MPP_PRE_SELECT					(1<<0)
#define MPP_CLOSE_ON_SIGNAL				(1<<1)

/**************************************************************************/
/**
 * Perform postprocessing of a VPN tunnel instance.
 *
 * After some VPN tunnel activity has taken place, the VPN tunnel's state
 * may need updating and some follow-up action may be required.  This
 * function controls the necessary postprocessing.  It is called by many
 * other functions that handle VPN tunnel related activity, such as \c
 * multi_process_incoming_link(), \c multi_process_outgoing_link(), \c
 * multi_process_incoming_tun(), \c multi_process_outgoing_tun(), and \c
 * multi_process_timeout(), among others.
 *
 * @param m            - The single \c multi_context structure.
 * @param mi           - The \c multi_instance of the VPN tunnel to be
 *                       postprocessed.
 * @param flags        - Fast I/O optimization flags.
 *
 * @return
 *  - True, if the VPN tunnel instance \a mi was not closed due to a
 *    signal during processing.
 *  - False, if the VPN tunnel instance \a mi was closed.
 */
bool multi_process_post (struct multi_context *m, struct multi_instance *mi, const unsigned int flags);


/**************************************************************************/
/**
 * Demultiplex and process a packet received over the external network
 * interface.
 * @ingroup external_multiplexer
 *
 * This function determines which VPN tunnel instance the incoming packet
 * is associated with, and then calls \c process_incoming_link() to handle
 * it.  Afterwards, if the packet is destined for a broadcast/multicast
 * address or a remote host reachable through a different VPN tunnel, this
 * function takes care of sending it they are.
 *
 * @note This function is only used by OpenVPN processes which are running
 *     in server mode, and can therefore sustain multiple active VPN
 *     tunnels.
 *
 * @param m            - The single \c multi_context structure.
 * @param instance     - The VPN tunnel state structure associated with
 *                       the incoming packet, if known, as is the case
 *                       when using TCP transport. Otherwise NULL, as is
 *                       the case when using UDP transport.
 * @param mpp_flags    - Fast I/O optimization flags.
 */
bool
multi_process_incoming_link (struct multi_context *m, struct multi_instance *instance, const unsigned int mpp_flags,
		struct packet_buffer *buf);

void
multi_process_incoming_link_post (struct multi_context *m, struct multi_instance *instance, struct packet_buffer *buf);

/**
 * Determine the destination VPN tunnel of a packet received over the
 * virtual tun/tap network interface and then process it accordingly.
 * @ingroup internal_multiplexer
 *
 * This function determines which VPN tunnel instance the packet is
 * destined for, and then calls \c process_outgoing_tun() to handle it.
 *
 * @note This function is only used by OpenVPN processes which are running
 *     in server mode, and can therefore sustain multiple active VPN
 *     tunnels.
 *
 * @param m            - The single \c multi_context structure.
 * @param mpp_flags    - Fast I/O optimization flags.
 */
bool multi_process_incoming_tun (struct multi_context *m, struct timeval *now_tv, const unsigned int mpp_flags,
		struct packet_buffer *buf);

void multi_print_status (struct multi_context *m, struct status_output *so, const int version);

void multi_ifconfig_pool_persist (struct multi_context *m, bool force);

bool multi_process_signal (struct multi_context *m);

void multi_close_instance_on_signal (struct multi_context *m, struct multi_instance *mi);

void init_management_callback_multi (struct multi_context *m);
void uninit_management_callback_multi (struct multi_context *m);

static inline void
route_quota_inc (struct multi_instance *mi, int thread_idx)
{
	MUTEX_LOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
	++mi->route_count;
	MUTEX_UNLOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
}

static inline void
route_quota_dec (struct multi_instance *mi, int thread_idx)
{
	MUTEX_LOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
	--mi->route_count;
	MUTEX_UNLOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
}

/* can we add a new route? */
static inline bool
route_quota_test (const struct multi_context *m, const struct multi_instance *mi, int thread_idx)
{
	/* Per-client route quota management */
	void route_quota_exceeded (const struct multi_context *m, const struct multi_instance *mi);
	int refcount;

	MUTEX_LOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
	refcount = mi->route_count;
	MUTEX_UNLOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);

	if (refcount >= mi->context.options.max_routes_per_client)
	{
		route_quota_exceeded (m, mi);
		return false;
	}
	else
		return true;
}

/*
 * Set a msg() function prefix with our current client instance ID.
 */

static inline void
set_prefix (struct multi_instance *mi, int thread_idx)
{
#ifdef MULTI_DEBUG_EVENT_LOOP
	if (mi->msg_prefix)
		printf ("[%s]\n", mi->msg_prefix);
#endif
	msg_set_prefix (mi->msg_prefix, thread_idx);
}

static inline void
clear_prefix (struct multi_instance *mi, int thread_idx)
{
#ifdef MULTI_DEBUG_EVENT_LOOP
	printf ("[NULL]\n");
#endif
	msg_set_prefix (NULL, thread_idx);
}

static void
generate_prefix (struct multi_instance *mi, int thread_idx)
{
	mi->msg_prefix = multi_instance_string (mi, true, &mi->gc);
	set_prefix (mi, thread_idx);
}

static void
ungenerate_prefix (struct multi_instance *mi, int thread_idx)
{
	mi->msg_prefix = NULL;
	set_prefix (mi, thread_idx);
}

/*
 * Instance reference counting
 */

static inline int
multi_instance_get_refcount (struct multi_instance *mi, int thread_idx)
{
	int refcount;

	MUTEX_LOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
	refcount = mi->refcount;
	MUTEX_UNLOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);

	return refcount;
}

static inline void
multi_instance_inc_refcount (struct multi_instance *mi, int thread_idx)
{
	MUTEX_LOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
	++mi->refcount;
	MUTEX_UNLOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
}

static inline void
multi_instance_dec_refcount (struct multi_instance *mi, int thread_idx)
{
	int refcount;

	MUTEX_LOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);
	refcount = --mi->refcount;
	MUTEX_UNLOCK (&g_refcount_mutex, thread_idx, S_REF_COUNT);

	if (refcount == 0)
	{
		time_t local_now = now_sec (thread_idx);

		ASSERT (mi->halt && mi->halt_time != 0 && (local_now - mi->halt_time) > DELAY_FREE_TIME);

		if (mi->did_open_context)
			close_context (&mi->context, SIGTERM, CC_GC_FREE);

		multi_tcp_instance_specific_free (mi);
		ungenerate_prefix (mi, thread_idx);

		gc_free (&mi->gc);
		free (mi);
	}
}

static inline void
multi_route_del (struct multi_route *route, int thread_idx)
{
	struct multi_instance *mi = route->instance;

	route_quota_dec (mi, thread_idx);
	multi_instance_dec_refcount (mi, thread_idx);

	free (route);
}

static inline bool
multi_route_defined (const struct multi_context *m, time_t now_sec, const struct multi_route *r)
{
	if (r->instance->halt)
		return false;
	else if ((r->flags & MULTI_ROUTE_CACHE) && r->cache_generation != m->route_helper->cache_generation)
		return false;
	else if ((r->flags & MULTI_ROUTE_AGEABLE) && r->last_reference + m->route_helper->ageable_ttl_secs < now_sec)
		return false;
	else
		return true;
}

/*
 * Instance Reaper
 *
 * Reaper constants.  The reaper is the process where the virtual address
 * and virtual route hash table is scanned for dead entries which are
 * then removed.  The hash table could potentially be quite large, so we
 * don't want to reap in a single pass.
 */

#define REAP_MAX_WAKEUP   10  /* Do reap pass at least once per n seconds */
#define REAP_DIVISOR     256  /* How many passes to cover whole hash table */
#define REAP_MIN          16  /* Minimum number of buckets per pass */
#define REAP_MAX        1024  /* Maximum number of buckets per pass */

/*
 * Mark a cached host route for deletion after this
 * many seconds without any references.
 */
#define MULTI_CACHE_ROUTE_TTL 60

static inline void
multi_reap_process (struct multi_context *m)
{
	if (m->reaper->last_call != now_sec (MAIN_THREAD_INDEX))
	{
		void multi_reap_process_dowork (struct multi_context *m);
		multi_reap_process_dowork (m);
	}
}

static inline void
multi_process_per_second_timers (struct multi_context *m)
{
	if (m->per_second_trigger != now_sec (MAIN_THREAD_INDEX))
	{
		void multi_process_per_second_timers_dowork (struct multi_context *m);
		multi_process_per_second_timers_dowork (m);
		m->per_second_trigger = now_sec (MAIN_THREAD_INDEX);
	}
}

/*
 * Compute earliest timeout expiry from the set of
 * all instances.  Output:
 *
 * m->earliest_wakeup : instance needing the earliest service.
 * dest               : earliest timeout as a delta in relation
 *                      to current time.
 */
static inline void
multi_get_timeout (struct multi_context *m, struct timeval *dest)
{
	struct timeval tv, current;

	CLEAR (tv);
	m->earliest_wakeup = (struct multi_instance *) schedule_get_earliest_wakeup (m->schedule, &tv);
	if (m->earliest_wakeup)
	{
		ASSERT (!openvpn_gettimeofday (&current, NULL, MAIN_THREAD_INDEX));
		tv_delta (dest, &current, &tv);
		if (dest->tv_sec >= REAP_MAX_WAKEUP)
		{
			m->earliest_wakeup = NULL;
			dest->tv_sec = REAP_MAX_WAKEUP;
			dest->tv_usec = 0;
		}
	}
	else
	{
		dest->tv_sec = REAP_MAX_WAKEUP;
		dest->tv_usec = 0;
	}
}

/* Check for signals. */
#define MULTI_CHECK_SIG(m) EVENT_LOOP_CHECK_SIGNAL (&(m)->top, multi_process_signal, (m))

static inline int
prepare_process_link_server_outgoing (struct multi_context *m)
{
	return m->to_link_pendings->size
#ifdef TARGET_LINUX
		|| m->top.c2.link_socket->writes.size - m->top.c2.link_socket->writes.offset
#endif
		;
}

static inline int
prepare_process_tun_server_outgoing (struct multi_context *m)
{
	return m->to_tun_pendings->size;
}

static inline void
multi_post_process_link_incoming (struct multi_context *m, const int counter, unsigned int mpp_flags)
{
	struct multi_instance_list *work_pendings = g_link_transfer_context->work_pendings;
	struct timeval *local_now = now_tv (MAIN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	if (work_pendings->size > 0)
	{
		struct multi_instance_entry *me = work_pendings->head;
		struct multi_instance *mi = NULL;
		int size = 0;

		while (me)
		{
			mi = me->mi;
			me = me->next;

			/* postprocess and set wakeup */
			multi_process_post (m, mi, mpp_flags);

			if (mi->context.c2.buffers->link_read_bufs->size > 0)
			{
				MUTEX_LOCK (&mi->context.c2.buffers->read_link_bufs_mutex, MAIN_THREAD_INDEX, S_READ_LINK_BUFS);
#ifdef PACKET_BUFFER_LIST_CHECK
				packet_buffer_list_check (mi->context.c2.buffers->link_read_bufs, local_now, PACKET_BUFFER_ORDER_BY_SEQ,
					PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
				packet_buffer_list_check (mi->context.c2.buffers->read_link_bufs, local_now, PACKET_BUFFER_ORDER_BY_SEQ,
					PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif
				packet_buffer_list_attach_back (
					mi->context.c2.buffers->read_link_bufs, mi->context.c2.buffers->link_read_bufs);
				size += mi->context.c2.buffers->read_link_bufs->size;
				MUTEX_UNLOCK (&mi->context.c2.buffers->read_link_bufs_mutex, MAIN_THREAD_INDEX, S_READ_LINK_BUFS);
			}
		}

		MUTEX_LOCK (&m->read_link_pendings_mutex, MAIN_THREAD_INDEX, S_READ_LINK_PENDINGS);
		multi_instance_list_attach_back (m->read_link_pendings, work_pendings);
		MUTEX_UNLOCK (&m->read_link_pendings_mutex, MAIN_THREAD_INDEX, S_READ_LINK_PENDINGS);

		wakeup_worker_threads (MAIN_THREAD_INDEX, max_int (size, counter));
	}
}

/* Send a packet to TCP/UDP socket. */
static inline int
multi_process_outgoing_link (struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
	struct packet_buffer_list *write_work_bufs = g_link_transfer_context->write_work_bufs;
#ifdef ENABLE_FRAGMENT
	struct packet_buffer_list *frag_work_bufs = g_link_transfer_context->frag_work_bufs;
#endif
	struct context *c = &mi->context;
	int counter = 0;
	struct timeval *local_now = now_tv (MAIN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());
#endif

	set_prefix (mi, MAIN_THREAD_INDEX);

	process_outgoing_link_tls (c);	/* 处理TLS控制包*/

	if (c->c2.buffers->link_write_bufs->size == 0 && c->c2.buffers->to_link_bufs->size != 0)
	{
		MUTEX_LOCK (&c->c2.buffers->to_link_bufs_mutex, MAIN_THREAD_INDEX, S_TO_LINK_BUFS);

		/* TCP启用重放保护时, 链路输出必须按packet_id_net排序 */
		packet_buffer_list_attach_back (c->c2.buffers->link_write_bufs, c->c2.buffers->to_link_bufs);
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->link_write_bufs, local_now,
			PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
			PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_UNLOCK (&c->c2.buffers->to_link_bufs_mutex, MAIN_THREAD_INDEX, S_TO_LINK_BUFS);
	}

	if (c->c2.buffers->link_write_bufs->size > 0
#ifdef TARGET_LINUX
		|| c->c2.link_socket->writes.size > c->c2.link_socket->writes.offset
#endif
		)
	{
		counter = do_process_link_write (c, c->c2.buffers->link_write_bufs, write_work_bufs
#ifdef ENABLE_FRAGMENT
			, frag_work_bufs
#endif		
			);

		if (write_work_bufs->size > 0
#ifdef ENABLE_FRAGMENT
				|| frag_work_bufs->size > 0
#endif
				)
			post_process_link_any_outgoing (&mi->context, write_work_bufs
#ifdef ENABLE_FRAGMENT
				, frag_work_bufs
#endif
				);
		write_work_bufs->flags &= ~HAVE_MULTI_TYPE_FLAG;
	}

	clear_prefix (mi, MAIN_THREAD_INDEX);

	return counter;	/* 返回写出的数据包数 */
}

static inline void
multi_post_process_tun_incoming (struct multi_context *m, const int counter)
{
	struct multi_instance_list *work_pendings = g_tun_transfer_context->work_pendings;
	struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_tun_thread ());
#endif

	if (work_pendings->size > 0)
	{
		struct multi_instance_entry *me = work_pendings->head;
		struct multi_instance *mi = NULL;
		int size = 0;

		while (me)
		{
			mi = me->mi;
			me = me->next;

			if (mi->context.c2.buffers->tun_read_bufs->size > 0)
			{
				MUTEX_LOCK (&mi->context.c2.buffers->read_tun_bufs_mutex, TUN_THREAD_INDEX, S_READ_TUN_BUFS);
#ifdef PACKET_BUFFER_LIST_CHECK
				packet_buffer_list_check (mi->context.c2.buffers->tun_read_bufs, local_now, PACKET_BUFFER_ORDER_BY_SEQ,
					PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
				packet_buffer_list_check (mi->context.c2.buffers->read_tun_bufs, local_now, PACKET_BUFFER_ORDER_BY_SEQ,
					PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif
				packet_buffer_list_attach_back (
					mi->context.c2.buffers->read_tun_bufs, mi->context.c2.buffers->tun_read_bufs);
				size += mi->context.c2.buffers->read_tun_bufs->size;
				MUTEX_UNLOCK (&mi->context.c2.buffers->read_tun_bufs_mutex, TUN_THREAD_INDEX, S_READ_TUN_BUFS);
			}
		}

		MUTEX_LOCK (&m->read_tun_pendings_mutex, TUN_THREAD_INDEX, S_READ_TUN_PENDINGS);
		multi_instance_list_attach_back (m->read_tun_pendings, work_pendings);
		MUTEX_UNLOCK (&m->read_tun_pendings_mutex, TUN_THREAD_INDEX, S_READ_TUN_PENDINGS);

		wakeup_worker_threads (TUN_THREAD_INDEX, max_int (size, counter));
	}
}

/**
 * Send a packet over the virtual tun/tap network interface to its locally
 * reachable destination.
 * @ingroup internal_multiplexer
 *
 * This function calls \c process_outgoing_tun() to perform the actual
 * sending of the packet.  Afterwards, it calls \c multi_process_post() to
 * perform server-mode postprocessing.
 *
 * @param m            - The single \c multi_context structure.
 * @param mpp_flags    - Fast I/O optimization flags.
 *
 * @return
 *  - True, if the \c multi_instance associated with the packet sent was
 *    not closed due to a signal during processing.
 *  - Falls, if the \c multi_instance was closed.
 */
static inline int
multi_process_outgoing_tun (struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
	struct context *c = &mi->context;
	int counter = 0;
	struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_tun_thread ());
#endif

	set_prefix (mi, TUN_THREAD_INDEX);

	if (c->c2.buffers->tun_write_bufs->size == 0 && c->c2.buffers->to_tun_bufs->size != 0)
	{
		MUTEX_LOCK (&c->c2.buffers->to_tun_bufs_mutex, TUN_THREAD_INDEX, S_TO_TUN_BUFS);

		packet_buffer_list_attach_back (c->c2.buffers->tun_write_bufs, c->c2.buffers->to_tun_bufs);

#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->tun_write_bufs, local_now,
			PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_UNLOCK (&c->c2.buffers->to_tun_bufs_mutex, TUN_THREAD_INDEX, S_TO_TUN_BUFS);

		if (c->c2.buffers->tun_write_bufs->size > 0)
		{
			struct packet_buffer *buf;

			if (c->options.replay)
			{
				/* 包重放检查, 如果是重放通过设置包长等于0，释放包 */
				check_replays (c, c->c2.buffers->tun_write_bufs);
			}

			/* 广播和客户到客户路由处理 */
			buf = c->c2.buffers->tun_write_bufs->head;
			while (buf)
			{
				if (buf->buf.len > 0 && !(buf->flags & PACKET_BUFFER_BCAST_FLAG))
				{
					buf->flags |= PACKET_BUFFER_BCAST_FLAG;
					multi_process_incoming_link_post (m, mi, buf);
				}
				buf = buf->next;
			}

			/* 广播和客户到客户路由需要发送 */
			if (m->top.c2.did_tun_pending1)
			{
				m->top.c2.did_tun_pending1 = false;
				counter = MIN_WORK_CHUNK_SIZE;	/* 设置counter小于等于MIN_WORK_CHUNK_SIZE */
				multi_post_process_tun_incoming (m, counter);
			}
		}
	}

	if (c->c2.buffers->tun_write_bufs->size > 0)
	{
		struct packet_buffer_list *write_work_bufs = g_tun_transfer_context->write_work_bufs;

		counter = do_process_tun_write (c, c->c2.buffers->tun_write_bufs, write_work_bufs);
		if (write_work_bufs->size > 0)
		{
			post_process_tun_any_outgoing (c, write_work_bufs);
			write_work_bufs->flags &= ~HAVE_MULTI_TYPE_FLAG;
		}
	}

	clear_prefix (mi, TUN_THREAD_INDEX);
	return counter;
}
static inline int 
do_process_tun_server_write (struct multi_context *m, unsigned int mpp_flags)
{
	int total_counter = 0, counter = 0;
	struct multi_instance *mi = NULL;
	struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_tun_thread ());
#endif

#if defined(ENABLE_PF) && defined(ENABLE_TUN_THREAD)
	MUTEX_LOCK (&g_pf_mutex, TUN_THREAD_INDEX, S_PF);	/* 阻止主线程重新加载规则 */
#endif

	do {
		MUTEX_LOCK (&m->to_tun_pendings_mutex, TUN_THREAD_INDEX, S_TO_TUN_PENDINGS);
		do {
			mi = multi_instance_list_pop_front (m->to_tun_pendings);
		} while (mi && !mi->halt && !TUN_OUT (&mi->context));

		// 或许不能一次写完, 重新放入m->to_tun_pendings
		if (mi && !mi->halt)
			multi_instance_list_push_back (m->to_tun_pendings, mi);
		MUTEX_UNLOCK (&m->to_tun_pendings_mutex, TUN_THREAD_INDEX, S_TO_TUN_PENDINGS);

		if (mi && !mi->halt)
		{
			counter = multi_process_outgoing_tun (m, mi, mpp_flags);
			total_counter += counter;
		}

	} while (mi && counter > 0 && total_counter < MAX_TUN_BATCH_WRITE);

#if defined(ENABLE_PF) && defined(ENABLE_TUN_THREAD)
	MUTEX_UNLOCK (&g_pf_mutex, TUN_THREAD_INDEX, S_PF);
#endif

	return total_counter;	/* 返回总共写出的数据包数 */
}

static inline int 
do_process_tun_server_read (struct multi_context *m)
{
	struct multi_instance_list *work_pendings = g_tun_transfer_context->work_pendings;
	struct packet_buffer_list *read_work_bufs = g_tun_transfer_context->read_work_bufs;
	struct packet_buffer *buf;
	const unsigned int mpp_flags = 0;
	int counter = 0, status = 0;
	struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_tun_thread ());
#endif

#if defined(ENABLE_PF) && defined(ENABLE_TUN_THREAD)
	MUTEX_LOCK (&g_pf_mutex, TUN_THREAD_INDEX, S_PF);	/* 阻止主线程重新加载规则 */
#endif

	do {
		if ((buf = get_tun_read_packet_buffer (&m->top, false)))
		{
			if ((status = read_incoming_tun (&m->top, buf)) <= 0) /* 线路繁忙或异常, 没有读到包 */
			{
				packet_buffer_list_push_back (read_work_bufs, buf);
				break;
			}
			else 
			{
				++counter;
				if (!multi_process_incoming_tun (m, local_now, mpp_flags, buf))
					packet_buffer_list_push_back (read_work_bufs, buf);
			}
		}

	} while (buf && status > 0 && m->top.c1.tuntap && counter < MAX_TUN_BATCH_READ && !IS_SIG (&m->top));

	if (work_pendings->size > 0)
		multi_post_process_tun_incoming (m, counter);

#if defined(ENABLE_PF) && defined(ENABLE_TUN_THREAD)
	MUTEX_UNLOCK (&g_pf_mutex, TUN_THREAD_INDEX, S_PF);
#endif

	return counter;	/* 返回总共读取的数据包数 */
}

#ifdef __cplusplus
}
#endif

#endif /* P2MP_SERVER */

#endif /* MULTI_H */
