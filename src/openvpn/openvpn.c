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

#ifndef WIN32
#include <sys/resource.h>
#endif

#include "openvpn.h"
#include "gremlin.h"
#include "init.h"
#include "thread.h"
#include "socket.h"
#include "socket-inline.h"
#include "multi_crypto.h"
#include "multi.h"
#include "win32.h"

#include "memdbg.h"

#define P2P_CHECK_SIG() EVENT_LOOP_CHECK_SIGNAL (c, process_signal_p2p, c);

struct transfer_context *g_link_transfer_context = NULL;	/* GLOBAL */
struct transfer_context *g_tun_transfer_context  = NULL;	/* GLOBAL */

pthread_t global_main_id;
struct multi_context *global_multi_context = NULL;	/* GLOBAL */
struct context *global_context = NULL;	/* GLOBAL */
struct argv *global_exec_argv = NULL;	/* GLOBAL */

void
transfer_context_init (struct transfer_context *tc, struct multi_context *m, struct context *c)
{
	int capacity = BUF_SIZE (&c->c2.frame);

	tc->terminate = true;
	tc->thread_idx = -1;
	tc->rand = rand ();

	tc->m = m;
	tc->c = c;
	if (m)
		tc->work_pendings = multi_instance_list_new (ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);

	tc->read_work_bufs = packet_buffer_list_new (capacity, 0, PACKET_BUFFER_FOR_ALL,
		ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);
	tc->write_work_bufs = packet_buffer_list_new (capacity, 0, PACKET_BUFFER_FOR_ALL,
		ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);

	tc->link_reclaim_bufs = packet_buffer_list_new (capacity, 0, PACKET_BUFFER_FOR_LINK,
		ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);
	tc->tun_reclaim_bufs = packet_buffer_list_new (capacity, 0, PACKET_BUFFER_FOR_TUN,
		ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);

#ifdef ENABLE_FRAGMENT
	tc->frag_work_bufs = packet_buffer_list_new (capacity, 0, PACKET_BUFFER_FOR_ALL,
		ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);
	tc->frag_reclaim_bufs = packet_buffer_list_new (capacity, 0, PACKET_BUFFER_FOR_FRAG,
		ALLOW_LINK_THREAD|ALLOW_TUN_THREAD);
#endif
}

void transfer_context_free (struct transfer_context *tc)
{
	int thread_idx = get_thread_index (pthread_self ());

	ASSERT (tc);

	if (tc->read_work_bufs->size > 0)
		packet_buffer_list_scatter (tc->read_work_bufs, tc->link_reclaim_bufs, tc->tun_reclaim_bufs
#ifdef ENABLE_FRAGMENT			
			, tc->frag_reclaim_bufs
#else
			, NULL
#endif	
		);
	packet_buffer_list_free (tc->read_work_bufs);
	tc->read_work_bufs = NULL;

	if (tc->write_work_bufs->size > 0)
		packet_buffer_list_scatter (tc->write_work_bufs, tc->link_reclaim_bufs, tc->tun_reclaim_bufs
#ifdef ENABLE_FRAGMENT			
			, tc->frag_reclaim_bufs
#else
			, NULL
#endif
		);
	packet_buffer_list_free (tc->write_work_bufs);
	tc->write_work_bufs = NULL;
	
#ifdef ENABLE_FRAGMENT
	if (tc->frag_work_bufs->size > 0)
		packet_buffer_list_attach_back (tc->frag_reclaim_bufs, tc->frag_work_bufs);
	packet_buffer_list_free (tc->frag_work_bufs);
	tc->frag_work_bufs = NULL;
#endif

	if (tc->link_reclaim_bufs->size > 0)
	{
#ifdef ENABLE_TUN_THREAD
		MUTEX_LOCK (g_link_free_bufs_mutex, thread_idx, S_LINK_FREE_BUFS);
		packet_buffer_list_attach_back (g_link_free_bufs, tc->link_reclaim_bufs);
		MUTEX_UNLOCK (g_link_free_bufs_mutex, thread_idx, S_LINK_FREE_BUFS);
#else
		packet_buffer_list_attach_back (g_link_free_bufs, tc->link_reclaim_bufs);
#endif
	}
	packet_buffer_list_free (tc->link_reclaim_bufs);
	tc->link_reclaim_bufs = NULL;

	if (tc->tun_reclaim_bufs->size > 0)
	{
#ifdef ENABLE_TUN_THREAD
		MUTEX_LOCK (g_tun_free_bufs_mutex, thread_idx, S_TUN_FREE_BUFS);
		packet_buffer_list_attach_back (g_tun_free_bufs, tc->tun_reclaim_bufs);
		MUTEX_UNLOCK (g_tun_free_bufs_mutex, thread_idx, S_TUN_FREE_BUFS);
#else
		packet_buffer_list_attach_back (g_tun_free_bufs, tc->tun_reclaim_bufs);
#endif
	}
	packet_buffer_list_free (tc->tun_reclaim_bufs);
	tc->tun_reclaim_bufs = NULL;

#ifdef ENABLE_FRAGMENT
	if (tc->frag_reclaim_bufs->size > 0)
	{
		MUTEX_LOCK (g_frag_free_bufs_mutex, thread_idx, S_FRAG_FREE_BUFS);
		packet_buffer_list_attach_back (g_frag_free_bufs, tc->frag_reclaim_bufs);
		MUTEX_UNLOCK (g_frag_free_bufs_mutex, thread_idx, S_FRAG_FREE_BUFS);
	}
	packet_buffer_list_free (tc->frag_reclaim_bufs);
	tc->frag_reclaim_bufs = NULL;
#endif

	if (tc->work_pendings)
	{
		multi_instance_list_free (tc->work_pendings);
		tc->work_pendings = NULL;
	}
}

static bool
process_signal_p2p (struct context *c)
{
	remap_signal (c);
	return process_signal (c);
}

/**************************************************************************/
/**
 * Main event loop for OpenVPN in client mode, where only one VPN tunnel is active.
 * @ingroup eventloop
 *
 * @param c - The context structure of the single active VPN tunnel.
 */
static void
tunnel_point_to_point (struct context *c)
{
#ifdef PERF_STATS_CHECK
	time_t last_print_perf_status = now_sec (MAIN_THREAD_INDEX);
#endif

	context_clear_2 (c);

	/* set point-to-point mode */
	c->mode = CM_P2P;

	/* initialize tunnel instance */
	init_instance_handle_signals (c, c->es, CC_HARD_USR1_TO_HUP);
	if (IS_SIG (c))
		return;

	/* 初始化全局包处理缓存, 必须在初始化init_instance_handle_signals(...) 函数调用后 */
	global_variable_init (NULL, c);

	/* 使用共享密钥时, 需立即启动TUN设备线程和工作线程 */
	if (!c->options.tls_client && !c->options.tls_server)
	{
#ifdef ENABLE_TUN_THREAD
		tun_thread_start (g_tun_transfer_context);
#endif

		worker_threads_start (NULL, c);
	}

	/* main event loop */
	while (true)
	{
		perf_push (PERF_EVENT_LOOP);

		/* process timers, TLS, etc. */
		pre_select (c);
		P2P_CHECK_SIG ();

		/* set up and do the I/O wait */
		io_wait (c, p2p_iow_flags (c));
		P2P_CHECK_SIG ();

		/* timeout? */
		if (c->c2.event_set_status == ES_TIMEOUT)
		{
			perf_pop ();
			continue;
		}

		/* process the I/O which triggered select */
		process_io (c);

		P2P_CHECK_SIG ();

		perf_pop ();

#ifdef PERF_STATS_CHECK
		if (now_sec (MAIN_THREAD_INDEX) > last_print_perf_status + 300 + MAIN_THREAD_INDEX)
		{
			print_perf_status (c, MAIN_THREAD_INDEX);
			last_print_perf_status = now_sec (MAIN_THREAD_INDEX);
		}
#endif
	}

	uninit_management_callback ();

#ifdef ENABLE_TUN_THREAD
	/* 停止TUN设备读写线程 */
	tun_thread_stop (g_tun_transfer_context);
#endif

	/* 停止工作线程组, 必须在close_instance(...)之前 */
	worker_threads_stop ();

	/* tear down tunnel instance (unless --persist-tun) */
	close_instance (c);

	/* 释放全局包处理缓存, 必须在close_instance(...)函数调用后 */
	global_variable_free ();
}

/**************************************************************************/
/**
 * OpenVPN's main init-run-cleanup loop.
 * @ingroup eventloop
 *
 * This function contains the two outer OpenVPN loops.  Its structure is as follows:
 *  - Once-per-process initialization.
 *  - Outer loop, run at startup and then once per \c SIGHUP:
 *    - Level 1 initialization
 *    - Inner loop, run at startup and then once per \c SIGUSR1:
 *      - Call event loop function depending on client or server mode:
 *        - \c tunnel_point_to_point()
 *        - \c tunnel_server()
 *    - Level 1 cleanup
 *  - Once-per-process cleanup.
 *
 * @param argc - Commandline argument count.
 * @param argv - Commandline argument values.
 */
static
int
openvpn_main (int argc, char *argv[])
{
	struct argv arg;
	struct context c;

	global_main_id = pthread_self ();
	gc_mutex_init ();
	argv_init_ex (&arg, argc, argv);
	global_context = &c;
	global_exec_argv = &arg;

#if PEDANTIC
	fprintf (stderr, "Sorry, I was built with --enable-pedantic and I am incapable of doing any real work!\n");
	return 1;
#endif

#ifdef WIN32
	SetConsoleOutputCP (CP_UTF8);
#endif

	CLEAR (c);

	/* signify first time for components which can only be initialized once per program instantiation. */
	c.first_time = true;

	/* initialize program-wide statics */
	if (init_static ())
	{
		/* This loop is initially executed on startup and then once per SIGHUP. */
		do
		{
			/* enter pre-initialization mode with regard to signal handling */
			pre_init_signal_catch ();

			/* zero context struct but leave first_time member alone */
			context_clear_all_except_first_time (&c);

			/* static signal info object */
			CLEAR (siginfo_static);
			c.sig = &siginfo_static;

			/* initialize garbage collector scoped to context object */
			gc_init (&c.gc, true);

			/* initialize environmental variable store */
			c.es = env_set_create (&c.gc);
#ifdef WIN32
			set_win_sys_path_via_env (c.es);
#endif

#ifdef ENABLE_MANAGEMENT
			/* initialize management subsystem */
			init_management (&c);
#endif

			/* initialize options to default state */
			init_options (&c.options, true);

			/* parse command line options, and read configuration file */
			parse_argv (&c.options, argc, argv, M_USAGE, OPT_P_DEFAULT, NULL, c.es);

#ifdef ENABLE_PLUGIN
			/* plugins may contribute options configuration */
			init_verb_mute (&c, IVM_LEVEL_1);
			init_plugins (&c);
			open_plugins (&c, true, OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE);
#endif

			/* init verbosity and mute levels */
			init_verb_mute (&c, IVM_LEVEL_1);

			/* set dev options */
			init_options_dev (&c.options);

			/* openssl print info? */
			if (print_openssl_info (&c.options))
				break;

#ifdef ENABLE_GUOMI
			/* 测试加密设备是否正常? */
			if (c.options.test_device)
			{
				do_test_encrypt_device (&c);
				break;
			}
#endif

#ifdef ENABLE_GUOMI
			/* 初始化加密设备 */
			init_encrypt_devices (&c);
#endif

			/* --genkey mode? */
			if (c.options.genkey)
			{
				do_genkey (&c.options);
				break;
			}

			/* tun/tap persist command? */
			if (do_persist_tuntap (&c.options))
				break;

			/* sanity check on options */
			options_postprocess (&c.options);

			/* print version number */
			msg (M_INFO, "%s", title_string);
#ifdef WIN32
			show_windows_version (M_INFO);
#endif
			show_library_versions (M_INFO);

			/* show all option settings */
			show_settings (&c.options);

			/* misc stuff */
			pre_setup (&c.options);

			/* test crypto? */
			if (do_test_crypto (&c.options))
				break;
			
			/* Query private key passwords before becoming a daemon if we don't use the	
			 * management interface to get them. */
#ifdef ENABLE_MANAGEMENT
			if (!(c.options.management_flags & MF_QUERY_PASSWORDS))
#endif
			{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
				if (c.options.key_pass_file)
					pem_password_setup (c.options.key_pass_file);
#endif
			}

			/* become a daemon if --daemon */
			if (c.first_time)
			{
				c.did_we_daemonize = possibly_become_daemon (&c.options);
				write_pid (c.options.writepid);
			}

#ifdef ENABLE_MANAGEMENT
			/* open management subsystem */
			if (!open_management (&c))
				break;

			/* query for private key passwords through management interface, if needed */
			if (c.options.management_flags & MF_QUERY_PASSWORDS)
			{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)
				if (c.options.key_pass_file)
					pem_password_setup (c.options.key_pass_file);
#endif
			}
#endif

			/* set certain options as environmental variables */
			setenv_settings (c.es, &c.options);

			/* finish context init */
			context_init_1 (&c);

#ifdef TARGET_LINUX
			if (c.options.bind_cpu)
				set_thread_cpu (pthread_self (), 1);
#endif

			do
			{
				c.options.integration_completed = false;

				/* run tunnel depending on mode */
				switch (c.options.mode)
				{
				case MODE_POINT_TO_POINT:
					tunnel_point_to_point (&c);
					break;
#if P2MP_SERVER
				case MODE_SERVER:
					tunnel_server (&c);
					break;
#endif
				default:
					ASSERT (0);
				}

				/* indicates first iteration -- has program-wide scope */
				c.first_time = false;

				/* any signals received? */
				if (IS_SIG (&c))
					print_signal (c.sig, NULL, M_INFO);

				/* pass restart status to management subsystem */
				signal_restart_status (c.sig);
			}
			while (c.sig->signal_received == SIGUSR1);

#ifdef ENABLE_GUOMI
			/* 释放加密设备 */
			uninit_encrypt_devices ();
#endif

			uninit_options (&c.options);

			env_set_destroy (c.es);

			gc_reset (&c.gc);
		}
		while (c.sig->signal_received == SIGHUP);
	}

	context_gc_free (&c);

#ifdef ENABLE_MANAGEMENT
	/* close management interface */
	close_management ();
#endif

	argv_reset (&arg);

	/* uninitialize program-wide statics */
	uninit_static ();

	openvpn_exit (exit_status);	/* exit point */
	
	gc_mutex_destory ();

	return 0;				/* NOTREACHED */
}

#ifdef WIN32
int
wmain (int argc, wchar_t *wargv[])
{
	char **argv;
	int i, ret;

#ifdef ENABLE_MINI_DUMP
	char dumpFileName[256];
	sprintf (dumpFileName, "%s_%u.dmp", PACKAGE_NAME, GetCurrentProcessId ());
	enableMiniDump (dumpFileName);
#endif

	if ((argv = (char **) calloc (argc + 2, sizeof (char*))) == NULL)
		return 1;

	for (i = 0; i < argc; i++)
	{
		int n = WideCharToMultiByte (CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
		argv[i] = (char*) malloc (n);
		WideCharToMultiByte (CP_UTF8, 0, wargv[i], -1, argv[i], n, NULL, NULL);
	}

	ret = openvpn_main (argc, argv);

	for (i = 0; i < argc; i++)
	{
		free (argv[i]);
	}
	free (argv);

	return ret;
}
#else
int
main (int argc, char *argv[])
{
#ifdef ENABLE_MINI_DUMP
	struct rlimit coredump;

	memset (&coredump, 0x0, sizeof (struct rlimit));
	coredump.rlim_cur = RLIM_INFINITY;
	coredump.rlim_max = RLIM_INFINITY;

	if (setrlimit (RLIMIT_CORE, &coredump))
		msg (M_INFO, "openvpn setrlimit fail!\n");
#endif

	return openvpn_main (argc, argv);
}
#endif
