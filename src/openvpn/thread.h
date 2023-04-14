#ifndef __THREAD_H__
#define __THREAD_H__

#include "basic.h"
#include "common.h"
#include "buffer.h"
#include "packet_buffer.h"

#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

struct transfer_context;
struct multi_context;
struct context;

#ifdef PERF_STATS_CHECK

#define S_LINK_FREE_BUFS     0
#define S_TUN_FREE_BUFS      1
#define S_FRAG_FREE_BUFS     2

#define S_TO_LINK_BUFS       3
#define S_TO_TUN_BUFS        4

#define S_READ_LINK_BUFS     5
#define S_READ_TUN_BUFS      6
#define S_READ_TUN_BUFS_PIN  7
#define S_READ_TUN_BUFS_ENC  8

#define S_READ_TUN_PENDINGS  9
#define S_READ_LINK_PENDINGS 10
#define S_TO_TUN_PENDINGS    11
#define S_TO_LINK_PENDINGS   12

#define S_VHASH              13
#define S_ITER               14

#define S_FRAGMENT_OUT       15
#define S_FRAGMENT_IN        16

#define S_SHARE_LOCK         17

#define S_WORKER_THREAD      18
#define S_ENCRYPT_DEVICE     19
#define S_PF                 20
#define S_REF_COUNT          21
#define S_COARSE             22

#define S_LOCK_CATEGORY_N    23

struct packet_stats
{
	int64_t total_counter;   /* д��������*/
	int64_t tiny_delay;      /* д��ʱtiny */	
	int64_t short_delay;     /* д��ʱshort */
	int64_t long_delay;      /* д��ʱlong */
	int max_delay;           /* д��ʱ�ֵ */
	char padding[CACHE_LINE_SIZE - 4 * sizeof (int64_t) - sizeof (int)];
};

#define S_MAX_MUTEX_NEST    3
#define MAX_TIME_CONSUMING  10000000  /* 10 �� */

#ifdef WIN32
__CACHE_LINE_ALIGNED__
#endif
struct lock_trace
{
	void *stack[S_MAX_MUTEX_NEST + S_MAX_MUTEX_NEST];
	int total;
	int mutex;
	int rwlock;
}
#ifndef WIN32
__CACHE_LINE_ALIGNED__
#endif
;

#ifdef WIN32
__CACHE_LINE_ALIGNED__
#endif
struct lock_stats
{
	int64_t acquire_total;    /* ��ȡ���Ĵ��� */
	int64_t wait_total;       /* �Ⱥ����Ĵ��� */
	int64_t total_wait_time;  /* ��ȡ���Ⱥ��ʱ������(΢��) */

	int max_wait_time;  /* ��ȡ���ķѵ����ʱ��(΢��) */
	int max_lock_time;  /* �������ʱ��, ΢�� */

	int thread_index;   /* �����߳����� */
	int64_t lock_entry_time;  /* ������ʼʱ��(΢��) */
}
#ifndef WIN32
__CACHE_LINE_ALIGNED__
#endif
;

extern struct packet_stats g_packet_stats[MAX_THREAD_INDEX];
extern struct lock_trace g_lock_trace[MAX_THREAD_INDEX];
extern struct lock_stats g_lock_stats[MAX_THREAD_INDEX][S_LOCK_CATEGORY_N];

static inline void
packet_buffer_stat_ttl (struct packet_buffer *buf, int thread_idx, struct timeval *now_tv, int line, const char *filename)
{
	packet_buffer_trace (buf, now_tv, line, filename);

	if (buf->ttl.tv_sec > 0)
	{
		struct timeval x, r;
		int time_consuming;

		x.tv_sec = MAX_PACKET_TTL / 1000000;
		x.tv_usec = MAX_PACKET_TTL % 1000000;
		tv_delta (&r, &x, &buf->ttl);

		time_consuming = tv_subtract (now_tv, &r, MAX_PACKET_TTL / 1000000);

		++g_packet_stats[thread_idx].total_counter;
		if (time_consuming > g_packet_stats[thread_idx].max_delay)
			g_packet_stats[thread_idx].max_delay = time_consuming;

		if (time_consuming < 10000)
			++g_packet_stats[thread_idx].tiny_delay;
		else if (time_consuming < 100000)
			++g_packet_stats[thread_idx].short_delay;
		else
			++g_packet_stats[thread_idx].long_delay;
	}
}

static inline 
int64_t get_cpu_time (void)
{
#ifdef WIN32
	FILETIME create_time, exit_time, kernel_time, user_time = {0, 0};
	GetThreadTimes (GetCurrentThread (), &create_time, &exit_time, &kernel_time, &user_time);
	return (((int64_t) user_time.dwHighDateTime << 32) | (int64_t) user_time.dwLowDateTime) / 10;
#else
	struct timespec tp = {0};
	clock_gettime (CLOCK_THREAD_CPUTIME_ID, &tp);
	return tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
#endif
}

static inline void
MUTEX_LOCK (pthread_mutex_t *m, int t, int c)
{
	struct lock_stats *s = &g_lock_stats[t][c];
	int time_consuming, x;
	int64_t t0, t1;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == t);
#endif

	t0 = get_cpu_time ();
	x = pthread_mutex_lock (m);
	t1 = get_cpu_time ();

	ASSERT (x == 0 && c >= 0 && c < S_LOCK_CATEGORY_N);

	++s->acquire_total;
	time_consuming = (int) (t1 - t0);
	if (time_consuming > 10 && time_consuming < MAX_TIME_CONSUMING)
	{
		++s->wait_total;
		s->total_wait_time += time_consuming;
		if (s->max_wait_time < time_consuming)
			s->max_wait_time = time_consuming;
	}

	s->thread_index = THREAD_SELF_INDEX ();
	s->lock_entry_time = t1;
	g_lock_trace[t].stack[g_lock_trace[t].total] = m;
	++g_lock_trace[t].total;
	ASSERT (++g_lock_trace[t].mutex <= S_MAX_MUTEX_NEST);	/* MUTEX_LOCK Ƕ�ײ�����S_MAX_MUTEX_NEST�� */
}

static inline void
MUTEX_UNLOCK (pthread_mutex_t *m, int t, int c)
{
	struct lock_stats *s = &g_lock_stats[t][c];
	int time_consuming, x;

	/* MUTEX_LOCK Ƕ�ײ�����S_MAX_MUTEX_NEST�� */
	--g_lock_trace[t].total;
	g_lock_trace[t].stack[g_lock_trace[t].total] = NULL;
	ASSERT (g_lock_trace[t].mutex <= S_MAX_MUTEX_NEST);
	ASSERT (--g_lock_trace[t].mutex >= 0);

	ASSERT (s->thread_index == -1 || s->thread_index == THREAD_SELF_INDEX ());
	s->thread_index = -1;

	time_consuming = (int) (get_cpu_time () - s->lock_entry_time);
	if (time_consuming > 10 && time_consuming < MAX_TIME_CONSUMING)
	{
		if (s->max_lock_time < time_consuming)
			s->max_lock_time = time_consuming;
	}

	x = pthread_mutex_unlock (m);
	ASSERT (x == 0);
}

/* ������, ��ȡ��������ʧ��, Ҫ������(EAGAIN) */
static inline int
RWLOCK_RDLOCK (pthread_rwlock_t *share_lock, int t, int c)
{
	struct lock_stats *s = &g_lock_stats[t][c];
	int time_consuming, x;
	int64_t t0, t1;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == t);
#endif

	t0 = get_cpu_time ();
	x = pthread_rwlock_rdlock (share_lock);
	t1 = get_cpu_time ();

	ASSERT ((x == 0 || x == EAGAIN) && c >= 0 && c < S_LOCK_CATEGORY_N);

	++s->acquire_total;	
	time_consuming = (int) (t1 - t0);
	if (time_consuming > 10 && time_consuming < MAX_TIME_CONSUMING)
	{
		++s->wait_total;
		s->total_wait_time += time_consuming;
		if (s->max_wait_time < time_consuming)
			s->max_wait_time = time_consuming;
	}

	/* RWLOCK_RDLOCK, RWLOCK_WRLOCK ��֧��Ƕ�� */
	g_lock_trace[t].stack[g_lock_trace[t].total] = share_lock;
	++g_lock_trace[t].total;
	ASSERT (++g_lock_trace[t].rwlock == 1);
	s->lock_entry_time = t1;
	s->thread_index = THREAD_SELF_INDEX ();

	return x;	/* ����pthread_rwlock_rdlock��������ֵ */
}

static inline void
RWLOCK_WRLOCK (pthread_rwlock_t *share_lock, int t, int c)
{
	struct lock_stats *s = &g_lock_stats[t][c];
	int time_consuming;
	int64_t t0, t1;
	
#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == t);
#endif

	t0 = get_cpu_time ();
	ASSERT (pthread_rwlock_wrlock (share_lock) == 0);
	t1 = get_cpu_time ();

	ASSERT (c >= 0 && c < S_LOCK_CATEGORY_N);

	++s->acquire_total;
	time_consuming = (int) (t1 - t0);
	if (time_consuming > 10 && time_consuming < MAX_TIME_CONSUMING)
	{
		++s->wait_total;
		s->total_wait_time += time_consuming;
		if (s->max_wait_time < time_consuming)
			s->max_wait_time = time_consuming;
	}

	/* RWLOCK_RDLOCK, RWLOCK_WRLOCK ��֧��Ƕ�� */
	g_lock_trace[t].stack[g_lock_trace[t].total] = share_lock;
	++g_lock_trace[t].total;
	ASSERT (++g_lock_trace[t].rwlock == 1);
	s->lock_entry_time = t1;
	s->thread_index = THREAD_SELF_INDEX ();
}

static inline void
RWLOCK_UNLOCK (pthread_rwlock_t *share_lock, int t, int c)
{
	struct lock_stats *s = &g_lock_stats[t][c];
	int time_consuming, x;

	/* RWLOCK_RDLOCK, RWLOCK_WRLOCK ��֧��Ƕ�� */
	--g_lock_trace[t].total;
	g_lock_trace[t].stack[g_lock_trace[t].total] = NULL;
	ASSERT (--g_lock_trace[t].rwlock == 0);

	ASSERT (s->thread_index == -1 || s->thread_index == THREAD_SELF_INDEX ());
	s->thread_index = -1;

	time_consuming = (int) (get_cpu_time () - s->lock_entry_time);
	if (time_consuming > 10 && time_consuming < MAX_TIME_CONSUMING)
	{
		if (s->max_lock_time < time_consuming)
			s->max_lock_time = time_consuming;
	}

	x = pthread_rwlock_unlock (share_lock);
	ASSERT (x == 0);
}

static inline bool
HOLD_LOCK (int thread_idx, void *lock)
{
	int i;
	for (i = 0; i < g_lock_trace[thread_idx].total; ++i)
	{
		if (g_lock_trace[thread_idx].stack[i] == lock)
			return true;
	}
	return false;
}
#else

#define MUTEX_LOCK(m, t, c)   pthread_mutex_lock (m)
#define MUTEX_UNLOCK(m, t, c) pthread_mutex_unlock (m)

#define RWLOCK_RDLOCK(sk, t, c) pthread_rwlock_rdlock (sk)
#define RWLOCK_WRLOCK(sk, t, c) pthread_rwlock_wrlock (sk)
#define RWLOCK_UNLOCK(sk, t, c) pthread_rwlock_unlock (sk)

#endif

/* ȫ��link���ɻ����б��� */
extern pthread_mutex_t *g_link_free_bufs_mutex;
/* ȫ��link���ɻ����б�, ������Ҫ����g_link_free_bufs_mutex */
extern struct packet_buffer_list *g_link_free_bufs;

/* ȫ��tun���ɻ����б��� */
extern pthread_mutex_t *g_tun_free_bufs_mutex;
/* ȫ��tun���ɻ����б�, ������Ҫ����g_tun_free_bufs_mutex */
extern struct packet_buffer_list *g_tun_free_bufs;

#ifdef ENABLE_FRAGMENT
/* ȫ�ַ�Ƭ���ɻ����б��� */
extern pthread_mutex_t *g_frag_free_bufs_mutex;
/* ȫ��tun��Ƭ���ɻ����б�, ������Ҫ����g_frag_free_bufs_mutex */
extern struct packet_buffer_list *g_frag_free_bufs;
#endif

#if defined(ENABLE_PF) && defined(ENABLE_TUN_THREAD)
/* link�̺߳�tun�߳�pfͬ���� */
extern pthread_mutex_t g_pf_mutex;
#endif

#ifdef ENABLE_GUOMI
/* ���������豸 */
extern pthread_mutex_t g_encrypt_device_mutex;
extern pthread_cond_t g_encrypt_device_cond;
#endif

/* ����env_set���� */
extern pthread_mutex_t g_env_mutex;
/* ��������Ƶ�����ʵĶ��� */
extern pthread_mutex_t g_coarse_mutex;
/* �����������ü��� */
extern pthread_mutex_t g_refcount_mutex;

/* ���ڹ����̺߳������̵߳�ͬ��, �źŷ�������; ����Ҫ����g_xxx_thread_mutex�� */
#define NONE_COND_SIGNAL		0
#define UNICAST_COND_SIGNAL		1
#define BROADCAST_COND_SIGNAL	2

/* �����߳�����, ȱʡһ���� */
extern int g_thread_group_size;
/* �����̺߳������̵߳�ͬ���� */
extern pthread_mutex_t *g_thread_mutexs;
/* �����̺߳������̵߳�ͬ���¼�*/
extern pthread_cond_t *g_thread_conds;

struct thread_group_status
{
	int cond_signal_type;
	char padding[CACHE_LINE_SIZE - sizeof (int)];
};
extern struct thread_group_status g_thread_group_status[MAX_THREAD_GROUP];

struct CRYPTO_dynlock_value
{
	pthread_mutex_t mutex;
};

int openssl_static_lock_steup (void);

int openssl_static_lock_cleanup (void);

struct CRYPTO_dynlock_value* openssl_dynlock_create (const char *file, int line);

void openssl_dynlock_locking (int mode, struct CRYPTO_dynlock_value *dynlock, const char *file, int line);

void openssl_dynlock_destroy (struct CRYPTO_dynlock_value *dynlock, const char *file, int line);

void global_variable_init (struct multi_context *m, struct context *c);

void global_variable_free (void);

void wakeup_worker_threads (const int wakener_thread_idx, const int counter);

void worker_threads_start (struct multi_context *m, struct context *c);

void worker_threads_stop (void);

#define ENABLE_THREAD_NAME
#ifdef ENABLE_THREAD_NAME
/*
 * ��Linux��ͨ����������鿴�߳���
 * cat /proc/<pid>/task/<tid>/comm
 */
void set_thread_name (const char *thread_name);
#endif

#ifdef TARGET_LINUX
void set_thread_cpu (pthread_t t_id, int cpu);
#endif

#ifdef ENABLE_TUN_THREAD
void tun_thread_start (struct transfer_context *tc);
void tun_thread_stop (struct transfer_context *tc);
#endif

#ifdef __cplusplus
}
#endif

#endif

