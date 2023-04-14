#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef WIN32
#include <sys/timeb.h>
#else
#include <sys/prctl.h>
#endif

#include <openssl/err.h>

#include "ssl_common.h"
#include "packet_buffer.h"
#include "socket-inline.h"
#include "thread.h"
#include "lzo.h"
#include "multi_crypto.h"
#include "multi.h"
#include "event.h"
#include "fragment.h"
#include "tun-inline.h"
#include "forward-inline.h"

#include "memdbg.h"

#ifdef PERF_STATS_CHECK
struct packet_stats g_packet_stats[MAX_THREAD_INDEX] = {0};
struct lock_trace g_lock_trace[MAX_THREAD_INDEX] = {0};
struct lock_stats g_lock_stats[MAX_THREAD_INDEX][S_LOCK_CATEGORY_N] = {0};
#endif

/* 全局link自由缓存列表锁 */
pthread_mutex_t *g_link_free_bufs_mutex = NULL;
/* 全局link自由缓存列表, 访问需要锁定g_link_free_bufs_mutex */
struct packet_buffer_list *g_link_free_bufs = NULL;

/* 全局tun自由缓存列表锁 */
pthread_mutex_t *g_tun_free_bufs_mutex = NULL;
/* 全局tun自由缓存列表, 访问需要锁定g_tun_free_bufs_mutex */
struct packet_buffer_list *g_tun_free_bufs = NULL;

#ifdef ENABLE_FRAGMENT
/* 全局分片自由缓存列表锁 */
pthread_mutex_t *g_frag_free_bufs_mutex = NULL;
/* 全局tun分片自由缓存列表, 访问需要锁定g_frag_free_bufs_mutex */
struct packet_buffer_list *g_frag_free_bufs = NULL;
#endif

#if defined(ENABLE_PF) && defined(ENABLE_TUN_THREAD)
/* link线程和tun线程pf同步锁 */
pthread_mutex_t g_pf_mutex;
#endif

/* 保护env_set对象 */
pthread_mutex_t g_env_mutex;
/* 保护不会频繁访问的对象 */
pthread_mutex_t g_coarse_mutex;
/* 保护对象引用计数 */
pthread_mutex_t g_refcount_mutex;

/* 工作线程组数, 缺省一个组 */
int g_thread_group_size = 1;
/* 工作线程和传输线程的同步锁 */
pthread_mutex_t *g_thread_mutexs = NULL;
/* 工作线程和传输线程的同步事件*/
pthread_cond_t *g_thread_conds = NULL;

struct thread_group_status g_thread_group_status[MAX_THREAD_GROUP] = {0};

#ifdef ENABLE_GUOMI
/* 保护加密设备 */
pthread_mutex_t g_encrypt_device_mutex;
pthread_cond_t g_encrypt_device_cond;
#endif

#ifdef WIN32
__CACHE_LINE_ALIGNED__
#endif
struct worker_workspace
{
	struct crypto_options crypto_opt;

#ifdef ENABLE_LZO
	struct lzo_compress_workspace compwork;
	struct buffer compress_buf;
	struct buffer decompress_buf;
#endif

	struct packet_buffer *work_buf;     /* 工作缓存 */

	struct packet_buffer_list *work_bufs0;  /* 工作缓存列表 */
	struct packet_buffer_list *work_bufs1;  /* 工作缓存列表 */
	struct packet_buffer_list *work_bufs2;  /* 工作缓存列表 */

#ifdef ENABLE_FRAGMENT
	struct packet_buffer_list *frag_work_bufs;  /* 分片缓存列表 */
#endif
}
#ifndef WIN32
__CACHE_LINE_ALIGNED__
#endif
;

/* 工作线程运行时信息 */
#ifdef WIN32
__CACHE_LINE_ALIGNED__
#endif
struct worker_context
{
	volatile bool terminate;  /* 线程是否需要终止 */

	pthread_t thread_id;      /* 线程ID*/

	int group_idx;   /* 工作线程组索引 */
	int thread_idx;  /* 工作线程索引, 0为主线程, 1为TUN设备读写线程 */

	struct multi_context *m;  /* SERVER 全局上下文 */
	struct context *c;        /* P2P 全局上下文 */

	struct worker_workspace *workspace;
}
#ifndef WIN32
__CACHE_LINE_ALIGNED__
#endif
;

static struct worker_context *static_worker_contexts = NULL;
static int static_n_worker_context = 0;

/* OPENSSL静态锁 */
static pthread_mutex_t *static_openssl_mutexs = NULL;

static void* do_process (void *arg);

static void do_point_to_point (struct worker_context *wc);

static void do_server (struct worker_context *wc);

static bool 
do_process_incoming_link (struct context *c, int thread_idx, struct crypto_options *opt,
	struct packet_buffer *work,
	struct packet_buffer *buf
#ifdef ENABLE_LZO
	, struct lzo_compress_workspace *comp_work, struct buffer *decompress_buf
#endif
);

static void
do_process_incoming_tun (struct context *c, int thread_idx, struct crypto_options *opt,
	struct packet_buffer *work, struct packet_buffer *buf);

static void openssl_static_lock_locking (int mode, int n, const char * file, int line)
{
	pthread_mutex_t *mutex = &(static_openssl_mutexs[n]);
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock (mutex);
	else
		pthread_mutex_unlock (mutex);
}

static void openssl_threadid_func (CRYPTO_THREADID *id)
{
#ifdef WIN32
	CRYPTO_THREADID_set_numeric (id, GetCurrentThreadId ());
#else
	CRYPTO_THREADID_set_numeric (id, pthread_self ());
#endif
}

int openssl_static_lock_steup (void)
{
	if (!static_openssl_mutexs)
	{
		int i;
		static_openssl_mutexs = (pthread_mutex_t *) malloc (CRYPTO_num_locks () * sizeof (pthread_mutex_t));
		for (i = 0; i < CRYPTO_num_locks (); ++i)
			ASSERT (pthread_mutex_init (&(static_openssl_mutexs[i]), NULL) == 0);

		CRYPTO_THREADID_set_callback (openssl_threadid_func);
		CRYPTO_set_locking_callback (openssl_static_lock_locking);
	}
	return 1;
}

int openssl_static_lock_cleanup (void)
{
	if (static_openssl_mutexs)
	{
		int i;	
		CRYPTO_THREADID_set_callback (NULL);
		CRYPTO_set_locking_callback (NULL);
		
		for (i = 0; i < CRYPTO_num_locks (); ++i)
			ASSERT (pthread_mutex_destroy (&(static_openssl_mutexs[i])) == 0);
		free (static_openssl_mutexs);
		static_openssl_mutexs = NULL;
	}
	return 1;
}

struct CRYPTO_dynlock_value *openssl_dynlock_create (const char *file, int line)
{
	struct CRYPTO_dynlock_value *dynlock = (struct CRYPTO_dynlock_value *) malloc (sizeof (struct CRYPTO_dynlock_value));
	ASSERT (pthread_mutex_init (&(dynlock->mutex), NULL) == 0);
	return dynlock;
}

void openssl_dynlock_locking (int mode, struct CRYPTO_dynlock_value *dynlock, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock (&(dynlock->mutex));
	else
		pthread_mutex_unlock (&(dynlock->mutex));
}

void openssl_dynlock_destroy (struct CRYPTO_dynlock_value *dynlock, const char *file, int line)
{
	ASSERT (pthread_mutex_destroy (&(dynlock->mutex)) == 0);
}

bool is_main_thread (void)
{
	return pthread_equal (pthread_self (), global_main_id);
}

bool is_tun_thread (void)
{
#ifdef ENABLE_TUN_THREAD
	return pthread_equal (pthread_self (), g_tun_transfer_context->thread_id);
#else
	return pthread_equal (pthread_self (), global_main_id);
#endif
}

bool is_worker_thread (void)
{
	return !is_main_thread () && !is_tun_thread ();
}

pthread_t* get_thread_id (int thread_idx)
{
	if (thread_idx == MAIN_THREAD_INDEX)
//		return &g_link_transfer_context->thread_id;
		return &global_main_id;
#ifdef ENABLE_TUN_THREAD
	else if (thread_idx == TUN_THREAD_INDEX)
		return &g_tun_transfer_context->thread_id;
#endif
	else
	{
		int i;
		for (i = 0; i < static_n_worker_context; ++i)
		{
			if (thread_idx == static_worker_contexts[i].thread_idx)
				return &static_worker_contexts[i].thread_id;
		}
	}
	return NULL;
}

int get_thread_index (pthread_t tid)
{
	if (pthread_equal (tid, global_main_id))
		return MAIN_THREAD_INDEX;
#ifdef ENABLE_TUN_THREAD
	else if (pthread_equal (tid, g_tun_transfer_context->thread_id))
		return TUN_THREAD_INDEX;
#endif
	else
	{
		int i;
		for (i = 0; i < static_n_worker_context; ++i)
		{
			if (pthread_equal (tid, static_worker_contexts[i].thread_id))
				return static_worker_contexts[i].thread_idx;
		}
	}
	return -1;
}

void
wakeup_worker_threads (const int wakener_thread_idx, const int counter)
{
	bool broadcast = counter > MIN_WORK_CHUNK_SIZE ? true : false;
	int thread_group_idx;

	if (wakener_thread_idx == MAIN_THREAD_INDEX)
		thread_group_idx = g_link_transfer_context->rand++ % g_thread_group_size;
	else if (wakener_thread_idx == TUN_THREAD_INDEX)
		thread_group_idx = g_tun_transfer_context->rand++ % g_thread_group_size;
	else
		ASSERT (0);

	MUTEX_LOCK (&g_thread_mutexs[thread_group_idx], wakener_thread_idx, S_WORKER_THREAD);

	/* 处于未发送信号状态时, 发送信号 */
	if (g_thread_group_status[thread_group_idx].cond_signal_type == NONE_COND_SIGNAL)
	{
		if (broadcast)
		{
			g_thread_group_status[thread_group_idx].cond_signal_type = BROADCAST_COND_SIGNAL;
			ASSERT (pthread_cond_broadcast (&g_thread_conds[thread_group_idx]) == 0);
		}
		else
		{
			g_thread_group_status[thread_group_idx].cond_signal_type = UNICAST_COND_SIGNAL;
			ASSERT (pthread_cond_signal (&g_thread_conds[thread_group_idx]) == 0);
		}
	}

	MUTEX_UNLOCK (&g_thread_mutexs[thread_group_idx], wakener_thread_idx, S_WORKER_THREAD);
}

static void 
worker_context_init (struct worker_context *wc, int group_idx, struct multi_context *m, struct context *c)
{
	struct options *options = &c->options;
	struct frame *frame = &c->c2.frame;

	wc->terminate = true;
	wc->group_idx = group_idx;
	wc->thread_idx = -1;

	ASSERT (c);
	wc->m = m;
	wc->c = c;

	ALLOC_OBJ_CLEAR (wc->workspace, struct worker_workspace);
#ifdef ENABLE_LZO
	lzo_compress_init (&wc->workspace->compwork, options->lzo);
	wc->workspace->compress_buf = alloc_buf (512 + BUF_SIZE (frame));
	wc->workspace->decompress_buf = alloc_buf (512 + BUF_SIZE (frame));
#endif

	wc->workspace->work_buf = packet_buffer_new (BUF_SIZE (frame) /* 必须为BUF_SIZE (frame)*/, PACKET_BUFFER_FOR_ALL);

	wc->workspace->work_bufs0 = packet_buffer_list_new (BUF_SIZE (frame), 0, PACKET_BUFFER_FOR_ALL, ALLOW_WORKER_THREAD);
	wc->workspace->work_bufs1 = packet_buffer_list_new (BUF_SIZE (frame), 0, PACKET_BUFFER_FOR_ALL, ALLOW_WORKER_THREAD);
	wc->workspace->work_bufs2 = packet_buffer_list_new (BUF_SIZE (frame), 0, PACKET_BUFFER_FOR_ALL, ALLOW_WORKER_THREAD);
#ifdef ENABLE_FRAGMENT
	wc->workspace->frag_work_bufs = packet_buffer_list_new (BUF_SIZE (frame), 0, PACKET_BUFFER_FOR_FRAG, ALLOW_WORKER_THREAD);
#endif
}

static void worker_context_free (struct worker_context *wc)
{
	ASSERT (wc->workspace->work_bufs0->size == 0 && wc->workspace->work_bufs1->size == 0
		&& wc->workspace->work_bufs2->size == 0);

	wc->terminate = true;
	wc->thread_idx = -1;

#ifdef ENABLE_LZO
	free_buf (&wc->workspace->compress_buf);
	free_buf (&wc->workspace->decompress_buf);
	lzo_compress_uninit (&wc->workspace->compwork);
#endif

	packet_buffer_free (wc->workspace->work_buf);

	packet_buffer_list_free (wc->workspace->work_bufs0);
	packet_buffer_list_free (wc->workspace->work_bufs1);
	packet_buffer_list_free (wc->workspace->work_bufs2);

#ifdef ENABLE_FRAGMENT
	packet_buffer_list_shrink (wc->workspace->frag_work_bufs);
	MUTEX_LOCK (g_frag_free_bufs_mutex, MAIN_THREAD_INDEX, S_FRAG_FREE_BUFS);
	packet_buffer_list_attach_back (g_frag_free_bufs, wc->workspace->frag_work_bufs);
	MUTEX_UNLOCK (g_frag_free_bufs_mutex, MAIN_THREAD_INDEX, S_FRAG_FREE_BUFS);
	packet_buffer_list_free (wc->workspace->frag_work_bufs);
#endif

	free (wc->workspace);
}

void global_variable_init (struct multi_context *m, struct context *c)
{
	int i, capacity, packet_queue_len;

	ASSERT (c);
	capacity = BUF_SIZE (&c->c2.frame);
	packet_queue_len = c->options.packet_queue_len;
#ifdef THREAD_ACCESS_CHECK
	ASSERT ((sizeof (struct transfer_context) & (CACHE_LINE_SIZE - 1)) == 0);
#endif
	ALLOC_OBJ_CLEAR (g_link_transfer_context, struct transfer_context);
	transfer_context_init (g_link_transfer_context, m, c);
	g_link_transfer_context->terminate = false;
	g_link_transfer_context->thread_id = pthread_self ();
	g_link_transfer_context->thread_idx = MAIN_THREAD_INDEX;

	ALLOC_OBJ_CLEAR (g_tun_transfer_context, struct transfer_context);
	transfer_context_init (g_tun_transfer_context, m, c);
#ifndef ENABLE_TUN_THREAD
	g_tun_transfer_context->terminate = false;
	g_tun_transfer_context->thread_id = pthread_self ();
	g_tun_transfer_context->thread_idx = MAIN_THREAD_INDEX;
#endif

	g_thread_group_size = max_int (1, min_int (MAX_THREAD_GROUP, c->options.worker_thread / 2));

	g_thread_mutexs = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t) * g_thread_group_size);
	g_thread_conds = (pthread_cond_t *) malloc (sizeof (pthread_cond_t) * g_thread_group_size);
	for (i = 0; i < g_thread_group_size; ++i)
	{
		ASSERT (pthread_mutex_init (&g_thread_mutexs[i], NULL) == 0);
		ASSERT (pthread_cond_init (&g_thread_conds[i], NULL) == 0);
	}

#ifdef THREAD_ACCESS_CHECK
	ASSERT ((sizeof (struct worker_context) & (CACHE_LINE_SIZE - 1)) == 0);
#endif
	static_n_worker_context = c->options.worker_thread;
	ALLOC_ARRAY_CLEAR (static_worker_contexts, struct worker_context, static_n_worker_context);
	for (i = 0; i < static_n_worker_context; ++i)
		worker_context_init (&static_worker_contexts[i], i % g_thread_group_size, m, c);

	msg (M_INFO, "init packet buffer queue length = %d", packet_queue_len);

#ifdef ENABLE_TUN_THREAD
	g_link_free_bufs_mutex = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
	ASSERT (pthread_mutex_init (g_link_free_bufs_mutex, NULL) == 0);
	g_tun_free_bufs_mutex = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
	ASSERT (pthread_mutex_init (g_tun_free_bufs_mutex, NULL) == 0);
#endif

	g_link_free_bufs = packet_buffer_list_new (
		capacity, packet_queue_len, PACKET_BUFFER_FOR_LINK, ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);
	g_tun_free_bufs = packet_buffer_list_new (
		capacity, packet_queue_len, PACKET_BUFFER_FOR_TUN, ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);

#ifdef ENABLE_FRAGMENT
	g_frag_free_bufs_mutex = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
	ASSERT (pthread_mutex_init (g_frag_free_bufs_mutex, NULL) == 0);
	g_frag_free_bufs = packet_buffer_list_new (capacity, packet_queue_len, PACKET_BUFFER_FOR_FRAG, ALLOW_ANY_THREAD);
#endif
}

void global_variable_free (void)
{
	int i;

	for (i = 0; i < static_n_worker_context; ++i)
		worker_context_free (&static_worker_contexts[i]);
	free (static_worker_contexts);
	static_worker_contexts = NULL;
	static_n_worker_context = 0;

	transfer_context_free (g_tun_transfer_context);
	g_tun_transfer_context = NULL;
	transfer_context_free (g_link_transfer_context);
	g_link_transfer_context = NULL;

	for (i = 0; i < g_thread_group_size; ++i)
	{
		ASSERT (pthread_mutex_destroy (&g_thread_mutexs[i]) == 0);
		ASSERT (pthread_cond_destroy (&g_thread_conds[i]) == 0);
	}
	free (g_thread_mutexs);
	g_thread_mutexs = NULL;
	free (g_thread_conds);
	g_thread_conds = NULL;

	msg (M_INFO, "destory global packet buffers");

	packet_buffer_list_shrink (g_link_free_bufs);
	packet_buffer_list_free (g_link_free_bufs);
	g_link_free_bufs = NULL;
	packet_buffer_list_shrink (g_tun_free_bufs);
	packet_buffer_list_free (g_tun_free_bufs);
	g_tun_free_bufs = NULL;

#ifdef ENABLE_TUN_THREAD
	ASSERT (pthread_mutex_destroy (g_link_free_bufs_mutex) == 0);
	free (g_link_free_bufs_mutex);
	g_link_free_bufs_mutex = NULL;
	ASSERT (pthread_mutex_destroy (g_tun_free_bufs_mutex) == 0);
	free (g_tun_free_bufs_mutex);
	g_tun_free_bufs_mutex = NULL;
#endif

#ifdef ENABLE_FRAGMENT
	packet_buffer_list_shrink (g_frag_free_bufs);
	packet_buffer_list_free (g_frag_free_bufs);
	g_frag_free_bufs = NULL;
	ASSERT (pthread_mutex_destroy (g_frag_free_bufs_mutex) == 0);
	free (g_frag_free_bufs_mutex);
	g_frag_free_bufs_mutex = NULL;
#endif
}

void worker_threads_start (struct multi_context *m, struct context *c)
{
	int i;
	pthread_attr_t attr;

	ASSERT (c);
	msg (M_INFO, "start worker thread number = %d", static_n_worker_context);

	/* 锁定,要求主线程先运行 */
	for (i = 0; i < g_thread_group_size; ++i)
		MUTEX_LOCK (&g_thread_mutexs[i], MAIN_THREAD_INDEX, S_WORKER_THREAD);

	pthread_attr_init (&attr);
	pthread_attr_setscope (&attr, PTHREAD_SCOPE_SYSTEM);	/* 绑定线程 */

	for (i = 0; i < static_n_worker_context; ++i)	/* 创建工作线程 */
	{
		/* 0为主线程, 1为TUN设备读写线程 */
		if (static_worker_contexts[i].terminate)
		{
			static_worker_contexts[i].terminate = false;
			static_worker_contexts[i].thread_idx = WORKER_THREAD_INDEX_BASE + i;

			ASSERT (pthread_create (&static_worker_contexts[i].thread_id, &attr, do_process,
				&static_worker_contexts[i]) == 0);
		}
	}

	pthread_attr_destroy (&attr);

	/* 通知工作线程开始运行 */
	for (i = 0; i < g_thread_group_size; ++i)
	{
		g_thread_group_status[i].cond_signal_type = BROADCAST_COND_SIGNAL;
		ASSERT (pthread_cond_broadcast (&g_thread_conds[i]) == 0);
		MUTEX_UNLOCK (&g_thread_mutexs[i], MAIN_THREAD_INDEX, S_WORKER_THREAD);
	}
}

void worker_threads_stop (void)
{
	int i = 0;
	void *status = NULL;

	msg (M_INFO, "stop worker thread");

	for (i = 0; i < static_n_worker_context; ++i)
		static_worker_contexts[i].terminate = true;

	/* 通知工作线程终止 */
	for (i = 0; i < g_thread_group_size; ++i)
	{
		MUTEX_LOCK (&g_thread_mutexs[i], MAIN_THREAD_INDEX, S_WORKER_THREAD);
		g_thread_group_status[i].cond_signal_type = BROADCAST_COND_SIGNAL;
		ASSERT (pthread_cond_broadcast (&g_thread_conds[i]) == 0);
		MUTEX_UNLOCK (&g_thread_mutexs[i], MAIN_THREAD_INDEX, S_WORKER_THREAD);
	}

	/* 等候工作线程终止 */
	for (i = 0; i < static_n_worker_context; ++i)
	{
		if (static_worker_contexts[i].thread_idx != -1)
		{
			ASSERT (pthread_join (static_worker_contexts[i].thread_id, &status) == 0);
			static_worker_contexts[i].thread_idx = -1;
		}
	}
}

#ifdef ENABLE_THREAD_NAME
#ifdef WIN32
/*
 * The information on how to set the thread name comes from
 * a MSDN article: http://msdn2.microsoft.com/en-us/library/xcb2z8hs.aspx
 */
const DWORD kVCThreadNameException = 0x406D1388;

typedef struct tagTHREADNAME_INFO
{
	DWORD dwType;		// Must be 0x1000.
	LPCSTR szName;		// Pointer to name (in user addr space).
	DWORD dwThreadID;	// Thread ID (-1=caller thread).
	DWORD dwFlags;		// Reserved for future use, must be zero.
} THREADNAME_INFO;

void set_thread_name (const char *thread_name)
{
	/* 只在调试的时候生效 */
	if (!IsDebuggerPresent ())
		return;
	else
	{
		THREADNAME_INFO info = { 0x0 };

		info.dwType = 0x1000;
		info.szName = thread_name;
		info.dwThreadID = GetCurrentThreadId ();
		info.dwFlags = 0;

		__try
		{
			RaiseException (kVCThreadNameException, 0, sizeof (info) / sizeof (DWORD), (DWORD_PTR*) (&info));
		}
		__except (EXCEPTION_CONTINUE_EXECUTION)
		{
		}
	}
}
#else
void set_thread_name (const char *thread_name)
{
	prctl (PR_SET_NAME, thread_name);
}
#endif
#endif

#ifdef TARGET_LINUX
void set_thread_cpu (pthread_t t_id, int cpu)
{
	cpu_set_t mask;

	CPU_ZERO (&mask);
	CPU_SET (cpu, &mask);

	if (pthread_setaffinity_np (t_id, sizeof (mask), &mask) == 0)
		msg (M_INFO, "set thread affinity success, pthread_id=%lu, cpu=%d", t_id, cpu);
	else
		msg (M_WARN, "set thread affinity fail, pthread_id=%lu, cpu=%d", t_id, cpu);
}
#endif

#ifdef PERF_STATS_CHECK
#define NOW_UPDATE_FREQUENCY        1
#else
#define NOW_UPDATE_FREQUENCY        8
#endif

static inline int get_timeout_abstime (struct timespec *abstime, int timeout, int thread_idx)
{
	struct timeval timeout_tv = { 0x0 }, local_now = { 0x0 };

	gettimeofday (&local_now, NULL);  /* 必须采用系统时间 */

	timeout_tv.tv_sec = timeout;
	timeout_tv.tv_usec = thread_idx * 100000;  /* 线程超时值不一样, 减少竞争 */
	tv_add (&local_now, &timeout_tv);

	abstime->tv_sec = local_now.tv_sec;
	abstime->tv_nsec = local_now.tv_usec * 1000;
	return 1;
}

void* do_process (void *arg)
{
	struct worker_context *wc = (struct worker_context *) arg;
	struct context *c = wc->c;
	struct timespec abstime;
#ifdef PERF_STATS_CHECK
	time_t last_print_perf_status;
#endif
#ifdef ENABLE_THREAD_NAME
	char thread_name[32];
#endif
	pthread_mutex_t *p_thread_mutex = &g_thread_mutexs[wc->group_idx];
	pthread_cond_t *p_thread_cond = &g_thread_conds[wc->group_idx];
	int *p_cond_signal_type = &g_thread_group_status[wc->group_idx].cond_signal_type;

#ifdef ENABLE_THREAD_NAME
	sprintf (thread_name, PACKAGE "/wk:%d", wc->thread_idx - WORKER_THREAD_INDEX_BASE);
	set_thread_name (thread_name);
#endif

#ifdef TARGET_LINUX
	if (c->options.bind_cpu)
	{
#ifdef ENABLE_TUN_THREAD
		set_thread_cpu (pthread_self (), wc->thread_idx - WORKER_THREAD_INDEX_BASE + 2);
#else
		set_thread_cpu (pthread_self (), wc->thread_idx - WORKER_THREAD_INDEX_BASE + 1);
#endif
	}
#endif

	update_time (wc->thread_idx);
#ifdef PERF_STATS_CHECK
	last_print_perf_status = now_sec (wc->thread_idx);
#endif

	do
	{
		MUTEX_LOCK (p_thread_mutex, wc->thread_idx, S_WORKER_THREAD);	/* 锁定,要求主线程先运行 */
		if (*p_cond_signal_type == NONE_COND_SIGNAL)	/* 处于未发送信号状态时, 超时等候 */
		{
			get_timeout_abstime (&abstime, WORKER_THREAD_WAIT_TIMEOUT, wc->thread_idx);
			pthread_cond_timedwait (p_thread_cond, p_thread_mutex, &abstime);
		}
		*p_cond_signal_type = NONE_COND_SIGNAL;	/* 置未发送信号状态 */
		MUTEX_UNLOCK (p_thread_mutex, wc->thread_idx, S_WORKER_THREAD);

		/* 隧道数据包加解密处理 */
		if (c->options.mode == MODE_POINT_TO_POINT)
			do_point_to_point (wc);
		else if (c->options.mode == MODE_SERVER)
			do_server (wc);
		else
			ASSERT (0);

#ifdef PERF_STATS_CHECK
		if (now_sec (wc->thread_idx) > last_print_perf_status + 300 + wc->thread_idx)
		{
			print_perf_status (c, wc->thread_idx);
			last_print_perf_status = now_sec (wc->thread_idx);
		}
#endif
	} while (!wc->terminate);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ERR_remove_thread_state (NULL);
#endif

	return arg;
}

#ifdef ENABLE_LZO
static void do_compress (struct context *c, int thread_idx, struct packet_buffer_list *work_bufs0,
	struct lzo_compress_workspace *comp_work, struct buffer *compress_buf)
{
	struct packet_buffer *buf = work_bufs0->head;

	while (buf)
	{
		/* Compress the packet. */
		lzo_compress (&buf->buf, *compress_buf, comp_work, thread_idx, now_sec (thread_idx), &c->c2.frame);
		buf = buf->next;
	}
}
#endif

static void do_alloc_packet_id_0 (struct context *c, int thread_idx, struct crypto_options *opt, 
	struct packet_buffer_list *work_bufs0)
{
	struct packet_buffer *buf = NULL;
	bool success = false;
	struct packet_id *packet_id = NULL;
	bool long_form = false;
	struct timeval *local_now = now_tv (thread_idx);

#ifdef PERF_STATS_CHECK
	ASSERT (work_bufs0->size != 0);
	ASSERT (HOLD_LOCK (thread_idx, &c->c2.buffers->read_tun_bufs_mutex));
#endif

	buf = packet_buffer_list_peek_front (work_bufs0);
	ASSERT (buf->key_id < 0);

	/* 加载加密选项 */
	success = load_crypto_options (c, thread_idx, opt, DO_ENCRYPT, buf);
	if (success)
	{
		packet_id = opt->packet_id;
		long_form = BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM);
	}
	else
		msg (D_TLS_KEYSELECT, "load crypto options(ENCRYPT) fail!");

	buf = work_bufs0->head;
	while (buf)
	{
		/* 未启用分片, 需要锁定read_tun_bufs_mutex; 启用分片, 需要锁定read_tun_bufs_pin_mutex */
		buf->local_pin = ++c->c2.buffers->write_local_pin;

		if (success)
		{
			buf->local_key_id = opt->local_key_id;
			buf->key_id = opt->key_id;

			/* TCP启用重放保护时, 链路输出必须按packet_id_net排序, 分配了PIN的包不能丢弃 */
			/* 空包不要分配PIN */
			if (packet_id && buf->buf.len > 0 && !(buf->flags & PACKET_BUFFER_HAVE_PIN_FLAG))
			{
				if (!packet_id_alloc_outgoing (&packet_id->send, &buf->pin, long_form, local_now->tv_sec))
				{
					packet_buffer_drop (buf, PACKET_DROP_ID_ROLL_OVER);
					msg (D_CRYPT_ERRORS, "ENCRYPT ERROR: packet ID roll over");
				}
				buf->flags |= PACKET_BUFFER_HAVE_PIN_FLAG;
			}
		}
		else
		{
			packet_buffer_drop (buf, PACKET_DROP_CRYPTO_OPTION_ERROR);
			/* 丢弃的包不能直接返回g_tun_free_bufs, 因为SEQ_NO需要同步 */
		}

		buf = buf->next;
	}

#ifdef PACKET_BUFFER_LIST_CHECK
	/* TCP启用重放保护时, 链路输出必须按packet_id_net排序 */
	packet_buffer_list_check (work_bufs0, local_now, PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
		PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif
}

#ifdef ENABLE_FRAGMENT
static void do_fragment (struct context *c, int thread_idx, struct packet_buffer_list *work_bufs0,
	struct packet_buffer_list *work_bufs1, struct packet_buffer_list *frag_work_bufs)
{
	struct packet_buffer *buf = NULL;

	/* 多个工作线程会改变fragment, 需要锁定 */
	MUTEX_LOCK (&c->c2.fragment_out_mutex, thread_idx, S_FRAGMENT_OUT);

	do
	{
		buf = packet_buffer_list_pop_front (work_bufs0);
		if (buf)
			fragment_outgoing (c, thread_idx, c->c2.fragment, buf, &c->c2.frame_fragment, frag_work_bufs, work_bufs1);
	} while (buf);

	MUTEX_UNLOCK (&c->c2.fragment_out_mutex, thread_idx, S_FRAGMENT_OUT);
}

static void do_alloc_packet_id_1 (struct context *c, int thread_idx, struct crypto_options *opt, 
	struct packet_buffer_list *work_bufs1)
{
	struct packet_buffer *buf = NULL;
	bool success = false;
	struct packet_id *packet_id = NULL;
	bool long_form = false;
	struct timeval *local_now = now_tv (thread_idx);

#ifdef PERF_STATS_CHECK
	ASSERT (c->c2.buffers->read_tun_bufs_pin->size != 0);
	ASSERT (HOLD_LOCK (thread_idx, &c->c2.buffers->read_tun_bufs_pin_mutex));
#endif

	buf = packet_buffer_list_peek_front (c->c2.buffers->read_tun_bufs_pin);
	ASSERT (buf->key_id < 0);

	/* 加载加密选项 */
	success = load_crypto_options (c, thread_idx, opt, DO_ENCRYPT, buf);
	if (success)
	{
		packet_id = opt->packet_id;
		long_form = BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM);
	}
	else
		msg (D_TLS_KEYSELECT, "load crypto options(ENCRYPT) fail!");

	do
	{
		buf = packet_buffer_list_pop_front (c->c2.buffers->read_tun_bufs_pin);

		if (buf->seq_no <= 1 || buf->seq_no == c->c2.buffers->frag_data_seq)
		{	
			/* 未启用分片, 需要锁定read_tun_bufs_mutex; 启用分片, 需要锁定read_tun_bufs_pin_mutex */
			buf->local_pin = ++c->c2.buffers->write_local_pin;

			if (success)
			{
				buf->local_key_id = opt->local_key_id;
				buf->key_id = opt->key_id;

				/* TCP启用重放保护时, 链路输出必须按packet_id_net排序, 分配了pin的包不能丢弃 */
				/* 空包不要分配PIN */
				if (packet_id && buf->buf.len > 0 && !(buf->flags & PACKET_BUFFER_HAVE_PIN_FLAG))
				{
					if (!packet_id_alloc_outgoing (&packet_id->send, &buf->pin, long_form, local_now->tv_sec))
					{
						packet_buffer_drop (buf, PACKET_DROP_ID_ROLL_OVER);
						msg (D_CRYPT_ERRORS, "ENCRYPT ERROR: packet ID roll over");
					}
					buf->flags |= PACKET_BUFFER_HAVE_PIN_FLAG;
				}
			}
			else
			{
				packet_buffer_drop (buf, PACKET_DROP_CRYPTO_OPTION_ERROR);
				/* 丢弃的包不能直接返回g_tun_free_bufs, 因为SEQ_NO需要同步 */
			}

			/* 更新下一个需要设置PIN的包序号 */
			if (buf->seq_no > 0 && (buf->flags & PACKET_BUFFER_FRAG_LAST_FLAG))
				c->c2.buffers->frag_data_seq = buf->seq_no + 1;

			packet_buffer_list_push_back (work_bufs1, buf);
		}
		else
		{
			packet_buffer_list_push_front (c->c2.buffers->read_tun_bufs_pin, buf);
			break;
		}

	} while (c->c2.buffers->read_tun_bufs_pin->size > 0);

#ifdef PACKET_BUFFER_LIST_CHECK
	/* TCP启用重放保护时, 链路输出必须按packet_id_net排序 */
	packet_buffer_list_check (work_bufs1, local_now, PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
		PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif
}

static int prepare_do_encrypt_1 (struct context *c, int thread_idx, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs1)
{
	struct packet_buffer *buf = NULL;
	int len = 0, key_id = -1;

#ifdef PERF_STATS_CHECK
	ASSERT (c->c2.buffers->read_tun_bufs_enc->size != 0);
	ASSERT (HOLD_LOCK (thread_idx, &c->c2.buffers->read_tun_bufs_enc_mutex));
#endif

	buf = packet_buffer_list_peek_front (c->c2.buffers->read_tun_bufs_enc);
	/* 采用共享密钥时opt->key_id == -1, buf->key_id == -1 */

	if ((opt->key_id < 0 || opt->key_id != buf->key_id) &&
		!load_crypto_options (c, thread_idx, opt, DO_ENCRYPT, buf))
	{
		msg (D_TLS_KEYSELECT, "load crypto options(ENCRYPT) fail!");
		key_id = buf->key_id;

		do {
			/* 已经分配了local_pin, local_key_id */
			packet_buffer_drop (buf, PACKET_DROP_CRYPTO_OPTION_ERROR);
			++len;
			/* 丢弃的包不能直接返回g_tun_free_bufs, 因为SEQ_NO需要同步 */	
			buf = buf->next;
		} while (buf && buf->key_id == key_id);
	}
	else
	{
		len = min_int (max_int (c->c2.buffers->read_tun_bufs_enc->size / c->options.worker_thread,
			MIN_WORK_CHUNK_SIZE), MAX_WORK_CHUNK_SIZE);
	}

	packet_buffer_list_detach_front (c->c2.buffers->read_tun_bufs_enc, work_bufs1, buf->key_id, len);

#ifdef PACKET_BUFFER_LIST_CHECK
	packet_buffer_list_check (work_bufs1, now_tv (thread_idx), PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
		PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_FRAG_LAST_FLAG|PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

	return len;
}
#endif

static int
prepare_do_encrypt_0 (struct context *c, int thread_idx, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs0, struct packet_buffer_list *work_bufs1
#ifdef ENABLE_LZO
	, struct lzo_compress_workspace *comp_work, struct buffer *compress_buf
#endif
#ifdef ENABLE_FRAGMENT
	, struct packet_buffer_list *frag_work_bufs
#endif
	)
{
	struct packet_buffer *buf = NULL;
	int len = 0;
	struct timeval *local_now = now_tv (thread_idx);

#ifdef ENABLE_FRAGMENT
	if (c->c2.fragment)
	{
		MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_enc_mutex, thread_idx, S_READ_TUN_BUFS_ENC);
		if (c->c2.buffers->read_tun_bufs_enc->size != 0)
		{
#ifdef PERF_STATS_CHECK
			packet_buffer_list_trace (c->c2.buffers->read_tun_bufs_enc, local_now, __LINE__, __FILE__);
#endif
			len = prepare_do_encrypt_1 (c, thread_idx, opt, work_bufs1);
		}
		MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_enc_mutex, thread_idx, S_READ_TUN_BUFS_ENC);

		if (len != 0)
			return len;  /* 不需要更多处理, 直接返回 */
	}
#endif

#if P2MP_SERVER
	/* Drop non-TLS outgoing packet if client-connect script/plugin has not yet succeeded. */
	if (c->c2.context_auth != CAS_SUCCEEDED)
	{
		MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_mutex, thread_idx, S_READ_TUN_BUFS);
		packet_buffer_list_attach_back (work_bufs1, c->c2.buffers->read_tun_bufs);
		MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_mutex, thread_idx, S_READ_TUN_BUFS);

		buf = work_bufs1->head;
		while (buf)
		{
			packet_buffer_drop (buf, PACKET_DROP_CAS_NOT_SUCCEEDED);
			/* 丢弃的包不能直接返回g_tun_free_bufs, 因为SEQ_NO需要同步 */
			buf = buf->next;
		}
		return work_bufs1->size;  /* 不需要更多处理, 直接返回 */
	}
#endif

	MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_mutex, thread_idx, S_READ_TUN_BUFS);

#ifdef PACKET_BUFFER_LIST_CHECK
	packet_buffer_list_check (c->c2.buffers->read_tun_bufs, local_now, PACKET_BUFFER_ORDER_BY_SEQ,
		PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_FRAG_LAST_FLAG|PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

	if (c->c2.buffers->read_tun_bufs->size != 0)
	{
		len = min_int (max_int (c->c2.buffers->read_tun_bufs->size / c->options.worker_thread,
			MIN_WORK_CHUNK_SIZE), MAX_WORK_CHUNK_SIZE);

		packet_buffer_list_detach_front (c->c2.buffers->read_tun_bufs, work_bufs0, -1, len);
		ASSERT (work_bufs0->size != 0);

#ifdef ENABLE_FRAGMENT
		if (!c->c2.fragment)	/* 未启用分片, 立即分配PIN */
#endif
			do_alloc_packet_id_0 (c, thread_idx, opt, work_bufs0);
	}

	MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_mutex, thread_idx, S_READ_TUN_BUFS);

	if (work_bufs0->size != 0)
	{
#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (work_bufs0, local_now, PACKET_BUFFER_ORDER_BY_SEQ,
			PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_FRAG_LAST_FLAG|PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

#ifdef ENABLE_LZO
		if (c->options.lzo & LZO_SELECTED)
			do_compress (c, thread_idx, work_bufs0, comp_work, compress_buf);
#endif

#ifdef ENABLE_FRAGMENT
		if (c->c2.fragment)
			do_fragment (c, thread_idx, work_bufs0, work_bufs1, frag_work_bufs);
		else
#endif
			packet_buffer_list_attach_back (work_bufs1, work_bufs0);
	}

#ifdef ENABLE_FRAGMENT
	if (c->c2.fragment)
	{
		MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_pin_mutex, thread_idx, S_READ_TUN_BUFS_PIN);

		if (work_bufs1->size != 0)
		{
			packet_buffer_list_attach_by_seq_no (c->c2.buffers->read_tun_bufs_pin, work_bufs1);
#ifdef PACKET_BUFFER_LIST_CHECK
			packet_buffer_list_check (c->c2.buffers->read_tun_bufs_pin, local_now, PACKET_BUFFER_ORDER_BY_SEQ,
				PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_FRAG_LAST_FLAG|PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif
		}

		if (c->c2.buffers->read_tun_bufs_pin->size != 0)
			do_alloc_packet_id_1 (c, thread_idx, opt, work_bufs1);

		MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_pin_mutex, thread_idx, S_READ_TUN_BUFS_PIN);

		MUTEX_LOCK (&c->c2.buffers->read_tun_bufs_enc_mutex, thread_idx, S_READ_TUN_BUFS_ENC);

		if (work_bufs1->size != 0)
		{
#ifdef PACKET_BUFFER_LIST_CHECK
			packet_buffer_list_check (c->c2.buffers->read_tun_bufs_enc, local_now,
				PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
				PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif
			packet_buffer_list_attach_by_local_pin (c->c2.buffers->read_tun_bufs_enc, work_bufs1);
		}

		if (c->c2.buffers->read_tun_bufs_enc->size != 0)
			len = prepare_do_encrypt_1 (c, thread_idx, opt, work_bufs1);

		MUTEX_UNLOCK (&c->c2.buffers->read_tun_bufs_enc_mutex, thread_idx, S_READ_TUN_BUFS_ENC);
	}
#endif

	return work_bufs1->size;
}

static int
prepare_do_decrypt (struct context *c, int thread_idx, struct crypto_options *opt, struct packet_buffer_list *work_bufs)
{
	struct packet_buffer *buf = NULL;

	MUTEX_LOCK (&c->c2.buffers->read_link_bufs_mutex, thread_idx, S_READ_LINK_BUFS);

#ifdef PACKET_BUFFER_LIST_CHECK
	packet_buffer_list_check (c->c2.buffers->read_link_bufs, now_tv (thread_idx), PACKET_BUFFER_ORDER_BY_SEQ,
		PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_FRAG_LAST_FLAG|PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

	if (c->c2.buffers->read_link_bufs->size != 0)
	{
		int len = min_int (max_int (c->c2.buffers->read_link_bufs->size / c->options.worker_thread,
			MIN_WORK_CHUNK_SIZE), MAX_WORK_CHUNK_SIZE);

		buf = packet_buffer_list_peek_front (c->c2.buffers->read_link_bufs);
		/* 采用共享密钥时opt->key_id == -1, buf->key_id == -1 */
		ASSERT (buf->buf.len > 0 /*&& buf->key_id >= 0*/);

		packet_buffer_list_detach_front (c->c2.buffers->read_link_bufs, work_bufs, buf->key_id, len);
	}

	MUTEX_UNLOCK (&c->c2.buffers->read_link_bufs_mutex, thread_idx, S_READ_LINK_BUFS);

	if (buf && work_bufs->size != 0)
	{
		/* 加载加密选项 */
		bool success = load_crypto_options (c, thread_idx, opt, DO_DECRYPT, buf);	
		if (!success)
			msg (D_TLS_KEYSELECT, "load crypto options(DECRYPT) fail!");

		buf = work_bufs->head;
		while (buf)
		{
			if (success)
			{				
				ASSERT (buf->key_id == opt->key_id);
				buf->local_key_id = opt->local_key_id;	/* 关联包到tls_session */
			}
			else
			{
				packet_buffer_drop (buf, PACKET_DROP_CRYPTO_OPTION_ERROR);
				/* 丢弃的包不能直接返回g_link_free_bufs, 因为SEQ_NO需要同步 */
			}

			buf = buf->next;
		}
	}

#ifdef PACKET_BUFFER_LIST_CHECK
	packet_buffer_list_check (work_bufs, now_tv (thread_idx), PACKET_BUFFER_ORDER_BY_SEQ,
		PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_FRAG_LAST_FLAG|PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

	return work_bufs->size;
}

static inline int
prepare_do_p2p (struct context *c, int thread_idx, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs0, struct packet_buffer_list *work_bufs1
#ifdef ENABLE_LZO
	, struct lzo_compress_workspace *comp_work, struct buffer *compress_buf
#endif
#ifdef ENABLE_FRAGMENT
	, struct packet_buffer_list *frag_work_bufs
#endif
	)
{
	int doit = DO_NONE;

	if (ANY_IN (c))
	{
		if ((thread_idx % 2) == 0) /* 减少锁冲突 */
		{
			if (TUN_IN (c) && prepare_do_encrypt_0 (c, thread_idx, opt, work_bufs0, work_bufs1
#ifdef ENABLE_LZO
				, comp_work, compress_buf
#endif
#ifdef ENABLE_FRAGMENT
				,frag_work_bufs
#endif
				))
				doit = DO_ENCRYPT;
			else if (LINK_IN (c) && prepare_do_decrypt (c, thread_idx, opt, work_bufs1))
				doit = DO_DECRYPT;
		}
		else
		{
			if (LINK_IN (c) && prepare_do_decrypt (c, thread_idx, opt, work_bufs1))
				doit = DO_DECRYPT;
			else if (TUN_IN (c) && prepare_do_encrypt_0 (c, thread_idx, opt, work_bufs0, work_bufs1
#ifdef ENABLE_LZO
				, comp_work, compress_buf
#endif
#ifdef ENABLE_FRAGMENT
				,frag_work_bufs
#endif
				))
				doit = DO_ENCRYPT;
		}
	}

	return doit; /* 数据需要加密或解密 */
}

static inline void
post_do_encrypt_p2p (struct context *c, int thread_idx, struct crypto_options *opt, struct packet_buffer_list *work_bufs)
{
	if (work_bufs && work_bufs->size != 0)
	{
		struct packet_buffer *buf = NULL;
		bool wakeup = false;

#ifdef PACKET_BUFFER_LIST_CHECK
		/* TCP启用重放保护时, 链路输出必须按packet_id_net排序 */
		packet_buffer_list_check (work_bufs, now_tv (thread_idx), PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
			PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		buf = packet_buffer_list_peek_front (work_bufs);

		MUTEX_LOCK (&c->c2.buffers->to_link_bufs_mutex, thread_idx, S_TO_LINK_BUFS);

		/* 判断数据包是否有序, 是否能立刻写出 */
		if (buf->local_pin <= 1 || buf->local_pin == c->c2.buffers->to_link_bufs_last_local_pin + 1)
		{
			wakeup = true;	/* 能立即写出, 唤醒主线程监听链路写 */
			packet_buffer_list_attach_back (c->c2.buffers->to_link_bufs, work_bufs);
			if (buf->local_pin == c->c2.buffers->to_link_bufs_last_local_pin + 1)
			{
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_link_bufs);
				c->c2.buffers->to_link_bufs_last_local_pin = buf->local_pin;
			}
		}
		else
		{
			packet_buffer_list_attach_by_local_pin (c->c2.buffers->to_link_bufs_rdy, work_bufs);
		}

		if (c->c2.buffers->to_link_bufs_rdy->size != 0)
		{
			buf = packet_buffer_list_peek_front (c->c2.buffers->to_link_bufs_rdy);

			/* 判断数据包是否有序, 是否能立刻写出 */
			if (buf->local_pin == c->c2.buffers->to_link_bufs_last_local_pin + 1)
			{
				wakeup = true;	/* 能立即写出, 唤醒主线程监听链路写 */
				packet_buffer_list_detach_by_local_pin (c->c2.buffers->to_link_bufs_rdy, c->c2.buffers->to_link_bufs,
					buf->local_pin);
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_link_bufs);
				c->c2.buffers->to_link_bufs_last_local_pin = buf->local_pin;
			}
		}

#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->to_link_bufs, now_tv (thread_idx),
			PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		packet_buffer_list_check (c->c2.buffers->to_link_bufs_rdy, now_tv (thread_idx),
			PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_UNLOCK (&c->c2.buffers->to_link_bufs_mutex, thread_idx, S_TO_LINK_BUFS);

		if (wakeup)
			event_wakeup (c->c2.event_set); /* 唤醒主线程监听链路写 */
	}
}

static inline void
post_do_decrypt_p2p (struct context *c, int thread_idx, struct crypto_options *opt, struct packet_buffer_list *work_bufs)
{
	if (work_bufs->size != 0)
	{
		struct packet_buffer *buf = NULL;
		bool wakeup = false;

#ifdef PACKET_BUFFER_LIST_CHECK
		{
			unsigned int of = PACKET_BUFFER_ORDER_BY_SEQ;
			if (proto_is_tcp (c->c2.link_socket->info.proto))
				of |= PACKET_BUFFER_ORDER_BY_PIN;
			/* 只能用PACKET_BUFFER_IS_ORDER; 有些包需要额外处理(例如:PING, OCC), 造成work_bufs内包序号、PIN不连续 */
			packet_buffer_list_check (work_bufs, now_tv (thread_idx), of, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		}
#endif		

		buf = packet_buffer_list_peek_front (work_bufs);

		MUTEX_LOCK (&c->c2.buffers->to_tun_bufs_mutex, thread_idx, S_TO_TUN_BUFS);

		/* 判断数据包是否有序, 是否能立刻写出 */
		if (buf->seq_no <= 1 || buf->seq_no == c->c2.buffers->to_tun_bufs_last_seq + 1)
		{
			wakeup = true;	/* 能立即写出, 唤醒TUN设备读写线程监听TUN设备写 */
			packet_buffer_list_attach_back (c->c2.buffers->to_tun_bufs, work_bufs);
			if (buf->seq_no == c->c2.buffers->to_tun_bufs_last_seq + 1)
			{
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_tun_bufs);
				c->c2.buffers->to_tun_bufs_last_seq = buf->seq_no;
			}
		}
		else
		{
			packet_buffer_list_attach_by_seq_no (c->c2.buffers->to_tun_bufs_rdy, work_bufs);
		}

		if (c->c2.buffers->to_tun_bufs_rdy->size != 0)
		{
			buf = packet_buffer_list_peek_front (c->c2.buffers->to_tun_bufs_rdy);

			/* 判断数据包是否有序, 是否能立刻写出 */
			if (buf->seq_no == c->c2.buffers->to_tun_bufs_last_seq + 1)
			{
				wakeup = true;	/* 能立即写出, 唤醒TUN设备读写线程监听TUN设备写 */
				packet_buffer_list_detach_by_seq_no (c->c2.buffers->to_tun_bufs_rdy, c->c2.buffers->to_tun_bufs,
					buf->seq_no);
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_tun_bufs);
				c->c2.buffers->to_tun_bufs_last_seq = buf->seq_no;
			}
		}

#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->to_tun_bufs, now_tv (thread_idx),
			PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		packet_buffer_list_check (c->c2.buffers->to_tun_bufs_rdy, now_tv (thread_idx),
			PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif		

		MUTEX_UNLOCK (&c->c2.buffers->to_tun_bufs_mutex, thread_idx, S_TO_TUN_BUFS);

		if (wakeup)
		{
#ifndef ENABLE_TUN_THREAD
			event_wakeup (c->c2.event_set); /* 唤醒TUN设备读写线程监听TUN设备写 */
#else
			event_wakeup (c->c2.tun_event_set); /* 唤醒TUN设备读写线程监听TUN设备写 */
#endif
		}
	}
}

static void
do_more_process_incoming_link_p2p (struct context *c, int thread_idx, struct packet_buffer_list *work_bufs0,
	struct packet_buffer_list *work_bufs1)
{
	if (work_bufs0->size != 0)	/* 有数据需要写锁定c->share_lock对象才能处理 */
	{
		struct packet_buffer_list zl;
		struct packet_buffer *buf;

		packet_buffer_list_init (&zl, work_bufs0->capacity, 0, work_bufs0->type, ALLOW_WORKER_THREAD);

		RWLOCK_WRLOCK (&c->share_lock, thread_idx, S_SHARE_LOCK);

		buf = work_bufs0->head;
		while (buf)
		{
#ifdef ENABLE_OCC
			/* Did we just receive an OCC packet? */
			if (buf->flags & PACKET_BUFFER_OCC_FLAG)
				process_received_occ_msg (c, &buf->buf);
#endif

			buf = buf->next;
		}

		RWLOCK_UNLOCK (&c->share_lock, thread_idx, S_SHARE_LOCK);

		while (work_bufs0->size > 0)
		{
			buf = packet_buffer_list_pop_front (work_bufs0);
			if (buf)
			{
				packet_buffer_list_push_back (&zl, buf);
				packet_buffer_list_attach_by_seq_no (work_bufs1, &zl);
			}
		}
		
#ifdef PACKET_BUFFER_LIST_CHECK
		{
			unsigned int of = PACKET_BUFFER_ORDER_BY_SEQ;
			if (proto_is_tcp (c->c2.link_socket->info.proto))
				of |= PACKET_BUFFER_ORDER_BY_PIN;
			packet_buffer_list_check (work_bufs1, now_tv (thread_idx), of, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		}
#endif

		packet_buffer_list_destroy (&zl);

		/* 简化代码(不影响性能), 不判断数据是否有序; 立即唤醒TUN设备线程, 由它进行判断 */

		/* 唤醒TUN设备读写线程监听TUN设备写 */
#ifndef ENABLE_TUN_THREAD
		event_wakeup (c->c2.event_set); /* 数据有序, 唤醒主线程 */
#else
		event_wakeup (c->c2.tun_event_set); /* 数据有序, 唤醒TUN设备读写线程 */
#endif
	}
}

void do_point_to_point (struct worker_context *wc)
{
	struct packet_buffer_list *work_bufs0 = wc->workspace->work_bufs0;
	struct packet_buffer_list *work_bufs1 = wc->workspace->work_bufs1;
	struct packet_buffer_list *work_bufs2 = wc->workspace->work_bufs2;

	struct packet_buffer *buf = NULL;
	struct packet_buffer *work_buf = wc->workspace->work_buf;

	struct context *c = wc->c;

	const int thread_idx = wc->thread_idx;
	int doit = DO_NONE, loop = 0;

	struct crypto_options *opt = &wc->workspace->crypto_opt;

#ifdef ENABLE_LZO
	struct lzo_compress_workspace *comp_work = &wc->workspace->compwork;
	struct buffer *compress_buf = &wc->workspace->compress_buf;
	struct buffer *decompress_buf = &wc->workspace->decompress_buf;
#endif

#ifdef ENABLE_FRAGMENT
	struct packet_buffer_list *frag_work_bufs = wc->workspace->frag_work_bufs;
#endif

	ASSERT (NOW_UPDATE_FREQUENCY * MAX_WORK_CHUNK_SIZE < 1024);	/* now_tv更新间隔必须小于1秒 */

#ifdef ENABLE_LZO
	if (c->options.lzo & LZO_SELECTED)
		lzo_modify_flags (comp_work, c->options.lzo);
#endif

	/* 点对点只有一个活动上下文 */
	do {
		ASSERT (work_bufs0->size == 0 && work_bufs1->size == 0 && work_bufs2->size == 0);

		/* 更新当前时间, 只需秒精度(第一次循环必须更新) */
		if ((loop++ % NOW_UPDATE_FREQUENCY) == 0)
			update_time (thread_idx);

		/* 准备要处理的数据, 放入work_bufs_1, 确定要加密还是解密*/
		doit = prepare_do_p2p (c, thread_idx, opt, work_bufs0, work_bufs1
#ifdef ENABLE_LZO
			, comp_work, compress_buf
#endif
#ifdef ENABLE_FRAGMENT
			,frag_work_bufs
#endif
			);
		ASSERT (work_bufs0->size == 0);

		if (doit == DO_ENCRYPT)
		{
			do {
				if ((buf = packet_buffer_list_pop_front (work_bufs1)))
				{
					if (buf->buf.len > 0)
						do_process_incoming_tun (c, thread_idx, opt, work_buf, buf);
					packet_buffer_list_push_back (work_bufs2, buf);
				}
			} while (buf);

			post_do_encrypt_p2p (c, thread_idx, opt, work_bufs2);
		}
		else if (doit == DO_DECRYPT)
		{		
			do {
				if ((buf = packet_buffer_list_pop_front (work_bufs1)))
				{
					if (buf->buf.len > 0)
					{
						if (do_process_incoming_link (c, thread_idx, opt, work_buf, buf
#ifdef ENABLE_LZO
							, comp_work, decompress_buf
#endif
							))
							/* 有数据需要写锁定share_lock对象才能处理 */
							packet_buffer_list_push_back (work_bufs0, buf);
						else
							packet_buffer_list_push_back (work_bufs2, buf);
					}
					else
						packet_buffer_list_push_back (work_bufs2, buf);
				}
			} while (buf);

			if (work_bufs0->size != 0)
				do_more_process_incoming_link_p2p (c, thread_idx, work_bufs0, work_bufs2);
			post_do_decrypt_p2p (c, thread_idx, opt, work_bufs2);
		}

		/* read_link_bufs->size == 0 && read_tun_bufs->size == 0 && read_tun_bufs_enc->size == 0 才退出 */
	} while (doit == DO_ENCRYPT || doit == DO_DECRYPT);

	ASSERT (work_bufs0->size == 0 && work_bufs1->size == 0 && work_bufs2->size == 0);
}

static inline int
prepare_tun_do_server (struct multi_context *m, struct multi_instance **mi, int thread_idx, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs0, struct packet_buffer_list *work_bufs1
#ifdef ENABLE_LZO
	, struct lzo_compress_workspace *comp_work, struct buffer *compress_buf
#endif
#ifdef ENABLE_FRAGMENT
	, struct packet_buffer_list *frag_work_bufs
#endif		
	)
{
	int doit = DO_NONE;

	if (m->read_tun_pendings->size != 0)
	{
		MUTEX_LOCK (&m->read_tun_pendings_mutex, thread_idx, S_READ_TUN_PENDINGS);

		do {
			*mi = multi_instance_list_pop_front (m->read_tun_pendings);
		} while ((*mi) && !TUN_IN (&(*mi)->context));

		// 可能需要更多线程来处理, 重新放入m->read_tun_pendings
		if (*mi)
			multi_instance_list_push_back (m->read_tun_pendings, *mi);

		MUTEX_UNLOCK (&m->read_tun_pendings_mutex, thread_idx, S_READ_TUN_PENDINGS);
	}

	if (*mi)
	{
		set_prefix (*mi, thread_idx);

#ifdef ENABLE_LZO
		if ((*mi)->context.options.lzo & LZO_SELECTED)
			lzo_modify_flags (comp_work, (*mi)->context.options.lzo);
#endif

		if (prepare_do_encrypt_0 (&(*mi)->context, thread_idx, opt, work_bufs0, work_bufs1
#ifdef ENABLE_LZO
			, comp_work, compress_buf
#endif
#ifdef ENABLE_FRAGMENT
			,frag_work_bufs
#endif						
			))
			doit = DO_ENCRYPT;
	}

	return doit;
}

static inline int
prepare_link_do_server (struct multi_context *m, struct multi_instance **mi, int thread_idx, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs1
#ifdef ENABLE_LZO
	, struct lzo_compress_workspace *comp_work, struct buffer *decompress_buf
#endif
)
{
	int doit = DO_NONE;

	if (m->read_link_pendings->size != 0)
	{
		MUTEX_LOCK (&m->read_link_pendings_mutex, thread_idx, S_READ_LINK_PENDINGS);

		do {
			*mi = multi_instance_list_pop_front (m->read_link_pendings);
		} while ((*mi) && !LINK_IN (&(*mi)->context));

		// 可能需要更多线程来处理, 重新放入m->read_tun_pendings
		if (*mi)
			multi_instance_list_push_back (m->read_link_pendings, *mi);

		MUTEX_UNLOCK (&m->read_link_pendings_mutex, thread_idx, S_READ_LINK_PENDINGS);
	}

	if (*mi)
	{
		set_prefix (*mi, thread_idx);

#ifdef ENABLE_LZO
		if ((*mi)->context.options.lzo & LZO_SELECTED)
			lzo_modify_flags (comp_work, (*mi)->context.options.lzo);
#endif

		if (prepare_do_decrypt (&(*mi)->context, thread_idx, opt, work_bufs1))
			doit = DO_DECRYPT;
	}

	return doit;
}

static inline int
prepare_do_server (struct multi_context *m, struct multi_instance **mi, int thread_idx, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs0, struct packet_buffer_list *work_bufs1
#ifdef ENABLE_LZO
	, struct lzo_compress_workspace *comp_work, struct buffer *compress_buf, struct buffer *decompress_buf
#endif
#ifdef ENABLE_FRAGMENT
	, struct packet_buffer_list *frag_work_bufs
#endif			
	)
{
	int doit = DO_NONE;

	if ((thread_idx % 2) == 0)	/* 减少锁冲突 */
	{
		doit = prepare_tun_do_server (m, mi, thread_idx, opt, work_bufs0, work_bufs1
#ifdef ENABLE_LZO
			, comp_work, compress_buf
#endif
#ifdef ENABLE_FRAGMENT
			, frag_work_bufs
#endif		
			);
		if (doit == DO_NONE)
			doit = prepare_link_do_server (m, mi, thread_idx, opt, work_bufs1
#ifdef ENABLE_LZO
				, comp_work, decompress_buf
#endif
				);
	}
	else
	{
		doit = prepare_link_do_server (m, mi, thread_idx, opt, work_bufs1
#ifdef ENABLE_LZO
			, comp_work, decompress_buf
#endif
			);
		if (doit == DO_NONE)
			doit = prepare_tun_do_server (m, mi, thread_idx, opt, work_bufs0, work_bufs1
#ifdef ENABLE_LZO
				, comp_work, compress_buf
#endif
#ifdef ENABLE_FRAGMENT
				, frag_work_bufs
#endif		
				);
	}

	return doit; /* 数据需要加密或解密 */
}

static inline void
post_do_encrypt_server (struct multi_context *m, int thread_idx, struct multi_instance *mi, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs)
{
	if (work_bufs && work_bufs->size != 0)
	{
		struct context *c = &mi->context;
		struct packet_buffer *buf = NULL;
		bool wakeup = false;
#ifdef PACKET_BUFFER_LIST_CHECK
		struct timeval *local_now = now_tv (thread_idx);
#endif

#ifdef PACKET_BUFFER_LIST_CHECK
		/* TCP启用重放保护时, 链路输出必须按packet_id_net排序 */
		packet_buffer_list_check (work_bufs, local_now, PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN,
			PACKET_BUFFER_HAVE_SEQ|PACKET_BUFFER_IS_LINEAR|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		buf = packet_buffer_list_peek_front (work_bufs);

		MUTEX_LOCK (&c->c2.buffers->to_link_bufs_mutex, thread_idx, S_TO_LINK_BUFS);

		/* 判断数据包是否有序, 是否能立刻写出 */
		if (buf->local_pin <= 1 || buf->local_pin == c->c2.buffers->to_link_bufs_last_local_pin + 1)
		{
			wakeup = true;	/* 能立即写出, 唤醒主线程监听链路写 */
			packet_buffer_list_attach_back (c->c2.buffers->to_link_bufs, work_bufs);
			if (buf->local_pin == c->c2.buffers->to_link_bufs_last_local_pin + 1)
			{
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_link_bufs);
				c->c2.buffers->to_link_bufs_last_local_pin = buf->local_pin;
			}
		}
		else
		{
			packet_buffer_list_attach_by_local_pin (c->c2.buffers->to_link_bufs_rdy, work_bufs);
		}

		if (c->c2.buffers->to_link_bufs_rdy->size != 0)
		{
			buf = packet_buffer_list_peek_front (c->c2.buffers->to_link_bufs_rdy);

			/* 判断数据包是否有序, 是否能立刻写出 */
			if (buf->local_pin == c->c2.buffers->to_link_bufs_last_local_pin + 1)
			{
				wakeup = true;	/* 能立即写出, 唤醒主线程监听链路写 */
				packet_buffer_list_detach_by_local_pin (c->c2.buffers->to_link_bufs_rdy, c->c2.buffers->to_link_bufs,
					buf->local_pin);
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_link_bufs);
				c->c2.buffers->to_link_bufs_last_local_pin = buf->local_pin;
			}
		}

#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->to_link_bufs, local_now,
			PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		packet_buffer_list_check (c->c2.buffers->to_link_bufs_rdy, local_now,
			PACKET_BUFFER_ORDER_BY_SEQ|PACKET_BUFFER_ORDER_BY_PIN, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_UNLOCK (&c->c2.buffers->to_link_bufs_mutex, thread_idx, S_TO_LINK_BUFS);

		if (wakeup)
		{
			MUTEX_LOCK (&m->to_link_pendings_mutex, thread_idx, S_TO_LINK_PENDINGS);
			multi_instance_list_push_back (m->to_link_pendings, mi);
			MUTEX_UNLOCK (&m->to_link_pendings_mutex, thread_idx, S_TO_LINK_PENDINGS);

			event_wakeup (c->c2.event_set); /* 唤醒主线程监听链路写 */
		}
	}
}

static inline void
post_do_decrypt_server (struct multi_context *m, int thread_idx, struct multi_instance *mi, struct crypto_options *opt,
	struct packet_buffer_list *work_bufs)
{
	if (work_bufs->size != 0)
	{
		struct context *c = &mi->context;
		struct packet_buffer *buf = NULL;
		bool wakeup = false;
#ifdef PACKET_BUFFER_LIST_CHECK
		struct timeval *local_now = now_tv (thread_idx);
#endif

#ifdef PACKET_BUFFER_LIST_CHECK
		{
			unsigned int of = PACKET_BUFFER_ORDER_BY_SEQ;
			if (proto_is_tcp (c->c2.link_socket->info.proto))
				of |= PACKET_BUFFER_ORDER_BY_PIN;
			/* 只能用PACKET_BUFFER_IS_ORDER; 有些包需要额外处理(例如:PING, OCC), 造成work_bufs内包序号、PIN不连续 */
			packet_buffer_list_check (work_bufs, local_now, of, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		}
#endif

		buf = packet_buffer_list_peek_front (work_bufs);

		MUTEX_LOCK (&c->c2.buffers->to_tun_bufs_mutex, thread_idx, S_TO_TUN_BUFS);

		/* 判断数据包是否有序, 是否能立刻写出 */
		if (buf->seq_no <= 1 || buf->seq_no == c->c2.buffers->to_tun_bufs_last_seq + 1)
		{
			wakeup = true;	/* 能立即写出, 唤醒TUN设备读写线程监听TUN设备写 */
			packet_buffer_list_attach_back (c->c2.buffers->to_tun_bufs, work_bufs);
			if (buf->seq_no == c->c2.buffers->to_tun_bufs_last_seq + 1)
			{
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_tun_bufs);
				c->c2.buffers->to_tun_bufs_last_seq = buf->seq_no;
			}
		}
		else
		{
			packet_buffer_list_attach_by_seq_no (c->c2.buffers->to_tun_bufs_rdy, work_bufs);
		}

		if (c->c2.buffers->to_tun_bufs_rdy->size != 0)
		{
			buf = packet_buffer_list_peek_front (c->c2.buffers->to_tun_bufs_rdy);

			/* 判断数据包是否有序, 是否能立刻写出 */
			if (buf->seq_no == c->c2.buffers->to_tun_bufs_last_seq + 1)
			{
				wakeup = true;	/* 能立即写出, 唤醒TUN设备读写线程监听TUN设备写 */
				packet_buffer_list_detach_by_seq_no (c->c2.buffers->to_tun_bufs_rdy, c->c2.buffers->to_tun_bufs,
					buf->seq_no);
				buf = packet_buffer_list_peek_back (c->c2.buffers->to_tun_bufs);
				c->c2.buffers->to_tun_bufs_last_seq = buf->seq_no;
			}
		}

#ifdef PACKET_BUFFER_LIST_CHECK
		packet_buffer_list_check (c->c2.buffers->to_tun_bufs, local_now,
			PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		packet_buffer_list_check (c->c2.buffers->to_tun_bufs_rdy, local_now,
			PACKET_BUFFER_ORDER_BY_SEQ, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
#endif

		MUTEX_UNLOCK (&c->c2.buffers->to_tun_bufs_mutex, thread_idx, S_TO_TUN_BUFS);

		if (wakeup)
		{
			MUTEX_LOCK (&m->to_tun_pendings_mutex, thread_idx, S_TO_TUN_PENDINGS);
			multi_instance_list_push_back (m->to_tun_pendings, mi);
			MUTEX_UNLOCK (&m->to_tun_pendings_mutex, thread_idx, S_TO_TUN_PENDINGS);

#ifndef ENABLE_TUN_THREAD
			event_wakeup (c->c2.event_set); /* 唤醒TUN设备读写线程监听TUN设备写 */
#else
			event_wakeup (c->c2.tun_event_set); /* 唤醒TUN设备读写线程监听TUN设备写 */
#endif
		}
	}
}

static void
do_more_process_incoming_link_server (struct multi_context *m, int thread_idx, struct multi_instance *mi,
	struct packet_buffer_list *work_bufs0, struct packet_buffer_list *work_bufs1)
{
	if (work_bufs0->size != 0)	/* 有数据需要写锁定c->share_lock对象才能处理 */
	{
		struct context *c = &mi->context;
		struct packet_buffer_list zl;
		struct packet_buffer *buf;

		packet_buffer_list_init (&zl, work_bufs0->capacity, 0, work_bufs0->type, ALLOW_WORKER_THREAD);

		RWLOCK_WRLOCK (&c->share_lock, thread_idx, S_SHARE_LOCK);

		buf = work_bufs0->head;
		while (buf)
		{
#ifdef ENABLE_OCC
			/* Did we just receive an OCC packet? */
			if (buf->flags & PACKET_BUFFER_OCC_FLAG)
				process_received_occ_msg (c, &buf->buf);
#endif
			buf = buf->next;
		}

		RWLOCK_UNLOCK (&c->share_lock, thread_idx, S_SHARE_LOCK);

		while (work_bufs0->size > 0)
		{
			buf = packet_buffer_list_pop_front (work_bufs0);
			if (buf)
			{
				packet_buffer_list_push_back (&zl, buf);
				packet_buffer_list_attach_by_seq_no (work_bufs1, &zl);
			}
		}
		
#ifdef PACKET_BUFFER_LIST_CHECK
		{
			unsigned int of = PACKET_BUFFER_ORDER_BY_SEQ;

			if (proto_is_tcp (c->c2.link_socket->info.proto))
				of |= PACKET_BUFFER_ORDER_BY_PIN;
			packet_buffer_list_check (work_bufs1, now_tv (thread_idx), of, PACKET_BUFFER_IS_ORDER|PACKET_BUFFER_NOT_EXPIRE, __LINE__, __FILE__);
		}
#endif

		packet_buffer_list_destroy (&zl);

		/* 简化代码(不影响性能), 不判断数据是否有序; 立即唤醒TUN设备线程, 由它进行判断 */

		/* 唤醒TUN设备读写线程监听TUN设备写 */
		MUTEX_LOCK (&m->to_tun_pendings_mutex, thread_idx, S_TO_TUN_PENDINGS);
		multi_instance_list_push_back (m->to_tun_pendings, mi);
		MUTEX_UNLOCK (&m->to_tun_pendings_mutex, thread_idx, S_TO_TUN_PENDINGS);

#ifndef ENABLE_TUN_THREAD
		event_wakeup (c->c2.event_set); /* 数据有序, 唤醒主线程 */
#else
		event_wakeup (c->c2.tun_event_set); /* 数据有序, 唤醒TUN设备读写线程 */
#endif
	}
}

void do_server (struct worker_context *wc)
{
	struct packet_buffer_list *work_bufs0 = wc->workspace->work_bufs0;
	struct packet_buffer_list *work_bufs1 = wc->workspace->work_bufs1;
	struct packet_buffer_list *work_bufs2 = wc->workspace->work_bufs2;

	struct packet_buffer *buf = NULL;
	struct packet_buffer *work_buf = wc->workspace->work_buf;

	struct multi_context *m = wc->m;
	struct multi_instance *mi = NULL;

	const int thread_idx = wc->thread_idx;
	int doit = DO_NONE, loop = 0;

	struct crypto_options *opt = &wc->workspace->crypto_opt;

#ifdef ENABLE_LZO
	struct lzo_compress_workspace *comp_work = &wc->workspace->compwork;
	struct buffer *compress_buf = &wc->workspace->compress_buf;
	struct buffer *decompress_buf = &wc->workspace->decompress_buf;
#endif

#ifdef ENABLE_FRAGMENT
	struct packet_buffer_list *frag_work_bufs = wc->workspace->frag_work_bufs;
#endif

	ASSERT (NOW_UPDATE_FREQUENCY * MAX_WORK_CHUNK_SIZE < 1024);	/* now_tv更新间隔必须小于1秒 */

	do {
		ASSERT (work_bufs0->size == 0 && work_bufs1->size == 0 && work_bufs2->size == 0);

		/* 更新当前时间, 只需秒精度(第一次循环必须更新) */
		if ((loop++ % NOW_UPDATE_FREQUENCY) == 0)
			update_time (thread_idx);

		mi = NULL;

		/* 准备要处理的数据, 放入work_bufs_1, 确定要加密还是解密*/
		doit = prepare_do_server (m, &mi, thread_idx, opt, work_bufs0, work_bufs1
#ifdef ENABLE_LZO
			, comp_work, compress_buf, decompress_buf
#endif
#ifdef ENABLE_FRAGMENT
			,frag_work_bufs
#endif			
			);
		ASSERT (work_bufs0->size == 0);

		if (doit == DO_ENCRYPT)
		{
			do {
				if ((buf = packet_buffer_list_pop_front (work_bufs1)))
				{
					if (buf->buf.len > 0)
						do_process_incoming_tun (&mi->context, thread_idx, opt, work_buf, buf);
					packet_buffer_list_push_back (work_bufs2, buf);
				}
			} while (buf);

			post_do_encrypt_server (m, thread_idx, mi, opt, work_bufs2);
		}
		else if (doit == DO_DECRYPT)
		{
			do {
				if ((buf = packet_buffer_list_pop_front (work_bufs1)))
				{
					if (buf->buf.len > 0)
					{
						if (do_process_incoming_link (&mi->context, thread_idx, opt, work_buf, buf
#ifdef ENABLE_LZO
							, comp_work, decompress_buf
#endif
							))
							/* 有数据需要写锁定share_lock对象才能处理 */
							packet_buffer_list_push_back (work_bufs0, buf);
						else
							packet_buffer_list_push_back (work_bufs2, buf);
					}
					else
						packet_buffer_list_push_back (work_bufs2, buf);
				}
			} while (buf);

			if (work_bufs0->size != 0)
				do_more_process_incoming_link_server (m, thread_idx, mi, work_bufs0, work_bufs2);
			post_do_decrypt_server (m, thread_idx, mi, opt, work_bufs2);
		}

		clear_prefix (mi, thread_idx);

		/* read_link_pendings->size == 0 && read_tun_pendings->size == 0 才退出 */
	} while (mi /*&& (doit == DO_ENCRYPT || doit == DO_DECRYPT)*/);

	ASSERT (work_bufs0->size == 0 && work_bufs1->size == 0 && work_bufs2->size == 0);
}

bool 
do_process_incoming_link (struct context *c, int thread_idx, struct crypto_options *opt,
	struct packet_buffer *work, struct packet_buffer *buf
#ifdef ENABLE_LZO
	, struct lzo_compress_workspace *comp_work, struct buffer *decompress_buf
#endif
)
{
	bool status = false, more = false;

#ifdef PACKET_TTL_CHECK
	ASSERT (packet_buffer_check_ttl (buf, now_tv (thread_idx), __LINE__, __FILE__));
#endif

	if (opt->ks_stats)
	{
		++opt->ks_stats->n_packets;
		if (buf->buf.len > 0)
			opt->ks_stats->n_bytes += buf->buf.len;
	}

	if (verify_hmac (thread_idx, opt, &buf->buf))
		status = openvpn_decrypt (thread_idx, opt, &c->c2.frame, buf, work);

	if (status)
	{
#ifdef ENABLE_FRAGMENT
		if (c->c2.fragment)
		{
			/* 多个工作线程会改变fragment, 需要锁定 */
			MUTEX_LOCK (&c->c2.fragment_in_mutex, thread_idx, S_FRAGMENT_IN);
			fragment_incoming (c, c->c2.fragment, buf, &c->c2.frame_fragment, now_sec (thread_idx));
			MUTEX_UNLOCK (&c->c2.fragment_in_mutex, thread_idx, S_FRAGMENT_IN);
		}
#endif

#ifdef ENABLE_LZO
		/* decompress the incoming packet */
		if (c->options.lzo & LZO_SELECTED)
			lzo_decompress (&buf->buf, *decompress_buf, comp_work, thread_idx, now_sec (thread_idx), &c->c2.frame);
#endif

		if (buf->buf.len > 0)
		{
			c->c2.link_read_auth_stats[thread_idx].read_bytes_auth += buf->buf.len;
			link_read_auth_sync_stats (c, thread_idx, now_sec (thread_idx));
		}

		/* Did we just receive an openvpn ping packet? */
		if (is_ping_msg (&buf->buf))
		{
			dmsg (D_PING, "RECEIVED PING PACKET");
			packet_buffer_drop (buf, PACKET_DROP_PING_PACKET);
			update_time (thread_idx);
			/* reset packet received timer */
			ping_rec_interval_reset (c, thread_idx, now_sec (thread_idx));
		}

#ifdef ENABLE_OCC
		/* Did we just receive an OCC packet? */
		if (is_occ_msg (&buf->buf))
		{
			buf->flags |= PACKET_BUFFER_OCC_FLAG;
			more = true;
		}
#endif

		/* to_tun defined + unopened tuntap can cause deadlock */
		if (!tuntap_defined (c->c1.tuntap))
			packet_buffer_drop (buf, PACKET_DROP_TUNTAP_NOT_DEFINED);
	}
	else
	{
		if (link_socket_connection_oriented (c->c2.link_socket))
		{
			/* decryption errors are fatal in TCP mode */
			register_signal (c, SIGUSR1, "decryption-error"); /* SOFT-SIGUSR1 -- decryption error in TCP mode */
			msg (D_STREAM_ERRORS, "Fatal decryption error (process_incoming_link), restarting");
		}
	}

	return more;
}

void 
do_process_incoming_tun (struct context *c, int thread_idx, struct crypto_options *opt, struct packet_buffer *work,
	struct packet_buffer *buf)
{
#ifdef PACKET_TTL_CHECK
	ASSERT (packet_buffer_check_ttl (buf, now_tv (thread_idx), __LINE__, __FILE__));
#endif

#ifdef ENABLE_CRYPTO
	if (openvpn_encrypt (thread_idx, opt, &c->c2.frame, buf, work))
		generate_hmac (thread_idx, opt, &buf->buf);
#endif

	if (opt->ks_stats)
	{
		++opt->ks_stats->n_packets;
		if (buf->buf.len > 0)
			opt->ks_stats->n_bytes += buf->buf.len;
	}

#ifdef ENABLE_CRYPTO
#ifdef ENABLE_SSL
	/*
	 * In TLS mode, prepend the appropriate one-byte opcode to the packet which identifies it as a data channel
	 * packet and gives the low-permutation version of the key-id to the recipient so it knows which decrypt key to use.
	 */
	if (c->c2.tls_multi && buf->buf.len > 0)
	{
		ASSERT (buf->key_id == opt->key_id);
		if (!c->c2.tls_multi->opt.server && c->c2.tls_multi->use_peer_id)
		{
			uint32_t peer;
			peer = htonl (((P_DATA_V2 << P_OPCODE_SHIFT) | opt->key_id) << 24 | (c->c2.tls_multi->peer_id & 0xFFFFFF));
			ASSERT (buf_write_prepend (&buf->buf, &peer, 4));
		}
		else
		{
			uint8_t *op;
			ASSERT (op = buf_prepend (&buf->buf, 1));
			*op = (P_DATA_V1 << P_OPCODE_SHIFT) | opt->key_id;
		}
	}
#endif
#endif
}
