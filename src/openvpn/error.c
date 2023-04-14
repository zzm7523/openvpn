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

#include "gremlin.h"
#include "error.h"
#include "buffer.h"
#include "misc.h"
#include "win32.h"
#include "socket.h"
#include "packet_buffer.h"
#include "socket-inline.h"
#include "tun.h"
#include "otime.h"
#include "perf.h"
#include "status.h"
#include "integer.h"
#include "ps.h"
#include "mstats.h"
#include "thread.h"
#include "multi_crypto.h"
#include "multi.h"

#include "memdbg.h"

#if SYSLOG_CAPABILITY
#ifndef LOG_OPENVPN
#define LOG_OPENVPN LOG_DAEMON
#endif
#endif

/* Globals */
unsigned int x_debug_level; /* GLOBAL */

/* Mute state */
static int mute_cutoff;     /* GLOBAL */
static int mute_count;      /* GLOBAL */
static int mute_category;   /* GLOBAL */

/*
 * Output mode priorities are as follows:
 *
 *  (1) --log-x overrides everything
 *  (2) syslog is used if --daemon or --inetd is defined and not --log-x
 *  (3) if OPENVPN_DEBUG_COMMAND_LINE is defined, output
 *      to constant logfile name.
 *  (4) Output to stdout.
 */

/* If true, indicates that stdin/stdout/stderr have been redirected due to --log */
static bool std_redir;      /* GLOBAL */

/* Should messages be written to the syslog? */
static bool use_syslog;     /* GLOBAL */

/* Should timestamps be included on messages to stdout/stderr? */
static bool suppress_timestamps; /* GLOBAL */

/* Should stdout/stderr be be parsable and always be prefixed with time and message flags */
static bool machine_readable_output;   /* GLOBAL */

/* The program name passed to syslog */
#if SYSLOG_CAPABILITY
static char *pgmname_syslog;  /* GLOBAL */
#endif

/* If non-null, messages should be written here (used for debugging only) */
static FILE *msgfp;         /* GLOBAL */

/* If true, we forked from main OpenVPN process */
static bool forked;         /* GLOBAL */

/* openvpn_exit() �ݹ���� */
static bool exit_recur;     /* GLOBAL */

/* our default output targets */
static FILE *default_out;   /* GLOBAL */
static FILE *default_err;   /* GLOBAL */

static pthread_mutex_t *static_msg_mutex = NULL;	/* ��Ϣ�� */
struct msg_prefix global_msg_prefixs[MAX_THREAD_INDEX] = {0};

void
init_msg_mutex (void)
{
	pthread_mutexattr_t mutexattr;

	/* ������������Ϊ�ɵݹ�, ��Ϣ���ܵݹ���� */
	pthread_mutexattr_init (&mutexattr);	
	ASSERT (pthread_mutexattr_settype (&mutexattr, PTHREAD_MUTEX_RECURSIVE_NP) == 0);

	static_msg_mutex = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
	ASSERT (pthread_mutex_init (static_msg_mutex, &mutexattr) == 0);    
}

void
uninit_msg_mutex (void)
{
	if (static_msg_mutex)
	{
		ASSERT (pthread_mutex_destroy (static_msg_mutex) == 0);
		static_msg_mutex = NULL;
	}
}

void
msg_forked (void)
{
	forked = true;
}

bool
set_debug_level (const int level, const unsigned int flags)
{
	const int ceiling = 15;

	if (level >= 0 && level <= ceiling)
	{
		x_debug_level = level;
		return true;
	}
	else if (flags & SDL_CONSTRAIN)
	{
		x_debug_level = constrain_int (level, 0, ceiling);
		return true;
	}
	return false;
}

int
get_debug_level (void)
{
	return x_debug_level;
}

bool
set_mute_cutoff (const int cutoff)
{
	if (cutoff >= 0)
	{
		mute_cutoff = cutoff;
		return true;
	}
	else
		return false;
}

int
get_mute_cutoff (void)
{
	return mute_cutoff;
}

void
set_suppress_timestamps (bool suppressed)
{
	suppress_timestamps = suppressed;
}

void
set_machine_readable_output (bool parsable)
{
	machine_readable_output = parsable;
}

void
error_reset (void)
{
	use_syslog = std_redir = false;
	suppress_timestamps = false;
	machine_readable_output = false;
	x_debug_level = 1;
	mute_cutoff = 0;
	mute_count = 0;
	mute_category = 0;
	forked = false;
	exit_recur = false;
	default_out = OPENVPN_MSG_FP;
	default_err = OPENVPN_MSG_FP;

#ifdef OPENVPN_DEBUG_COMMAND_LINE
	msgfp = fopen (OPENVPN_DEBUG_FILE, "w");
	if (!msgfp)
		openvpn_exit (OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
#else
	msgfp = NULL;
#endif
}

void
errors_to_stderr (void)
{
	default_err = OPENVPN_ERROR_FP;  
}

/*
 * Return a file to print messages to before syslog is opened.
 */
FILE *
msg_fp (const unsigned int flags)
{
	FILE *fp = msgfp;
	if (!fp)
		fp = (flags & (M_FATAL|M_USAGE_SMALL)) ? default_err : default_out;
	if (!fp)
		openvpn_exit (OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
	return fp;
}

#define SWAP { tmp = m1; m1 = m2; m2 = tmp; }

int x_msg_line_num; /* GLOBAL */

void x_msg (const unsigned int flags, const char *format, ...)
{
	va_list arglist;
	va_start (arglist, format);
	x_msg_va (flags, format, arglist);
	va_end (arglist);
}

void x_msg_va (const unsigned int flags, const char *format, va_list arglist)
{
	struct gc_arena gc = gc_new ();
#if SYSLOG_CAPABILITY
	int level;
#endif
	char *m1;
	char *m2;
	char *tmp;
	int e;
	const char *prefix;
	const char *prefix_sep;

	void usage_small (void);

#ifndef HAVE_VARARG_MACROS
	/* the macro has checked this otherwise */
	if (!msg_test (flags))
		return;
#endif

	e = openvpn_errno ();

	/* Apply muting filter. */
#ifndef HAVE_VARARG_MACROS
	/* the macro has checked this otherwise */
	if (!dont_mute (flags))
		return;
#endif

	m1 = (char *) gc_malloc (ERR_BUF_SIZE, false, &gc);
	m2 = (char *) gc_malloc (ERR_BUF_SIZE, false, &gc);

	vsnprintf (m1, ERR_BUF_SIZE, format, arglist);
	m1[ERR_BUF_SIZE - 1] = 0; /* windows vsnprintf needs this */

	if ((flags & M_ERRNO) && e)
	{
		openvpn_snprintf (m2, ERR_BUF_SIZE, "%s: %s (errno=%d)", m1, strerror_ts (e, &gc), e);
		SWAP;
	}

	if (flags & M_OPTERR)
	{
		openvpn_snprintf (m2, ERR_BUF_SIZE, "Options error: %s", m1);
		SWAP;
	}

#if SYSLOG_CAPABILITY
	if (flags & (M_FATAL|M_NONFATAL|M_USAGE_SMALL))
		level = LOG_ERR;
	else if (flags & M_WARN)
		level = LOG_WARNING;
	else
		level = LOG_NOTICE;
#endif

	/* set up client prefix */
	if (flags & M_NOIPREFIX)
		prefix = NULL;
	else
		prefix = msg_get_prefix ();
	prefix_sep = " ";
	if (!prefix)
		prefix_sep = prefix = "";

	/* virtual output capability used to copy output to management subsystem */
	if (!forked)
	{
		if (is_main_thread ())
		{
			const struct virtual_output *vo = msg_get_virtual_output ();
			if (vo)
			{
				openvpn_snprintf (m2, ERR_BUF_SIZE, "%s%s%s", prefix, prefix_sep, m1);
				virtual_output_print (vo, flags, m2);
			}
		}
	}

	if (!(flags & M_MSG_VIRT_OUT))
	{
		if (use_syslog && !std_redir && !forked)
		{
#if SYSLOG_CAPABILITY
			syslog (level, "%s%s%s", prefix, prefix_sep, m1);
#endif
		}
		else
		{
			const bool show_usec = check_debug_level (DEBUG_LEVEL_USEC_TIME);
			FILE *fp = msg_fp (flags);

			/* ����������������ļ�������Ҫͬ��, ������MUTEX_LOCK��, ʧ��ʱ�ݹ� */
			if (static_msg_mutex)
				ASSERT_FATAL (pthread_mutex_lock (static_msg_mutex) == 0);

			if (machine_readable_output)
			{
				struct timeval tv;
				gettimeofday (&tv, NULL);

				fprintf (fp, "%" PRIi64 ".%06ld %x %s%s%s%s", (int64_t) tv.tv_sec, (long) tv.tv_usec,
					flags, prefix, prefix_sep, m1, "\n");
			}
			else if ((flags & M_NOPREFIX) || suppress_timestamps)
			{
				fprintf (fp, "%s%s%s%s", prefix, prefix_sep, m1, (flags&M_NOLF) ? "" : "\n");
			}
			else
			{
				fprintf (fp, "%s %s%s%s%s", time_string (0, 0, show_usec, &gc), prefix, prefix_sep,
					m1, (flags&M_NOLF) ? "" : "\n");
			}

			fflush (fp);
			++x_msg_line_num;

			if (static_msg_mutex)
				ASSERT_FATAL (pthread_mutex_unlock (static_msg_mutex) == 0);
		}
	}

	if (flags & M_FATAL)
	{
		msg (M_INFO, "Exiting due to fatal error");

		// unix likeϵͳ��, ����core�ļ�; win32ϵͳ��, ����mini dump�ļ�
#if defined(_DEBUG) && !defined(WIN32)
		crash ();
#endif

		if (!global_context || !global_context->sig || is_main_thread ())
		{
			// ���߳���������openvpn_exit ()�˳�
			openvpn_exit (OPENVPN_EXIT_STATUS_ERROR);
		}
		else
		{
			// �����߳������ź�, ͨ���ź������̵߳���openvpn_exit ()�˳�
			global_context->sig->signal_received = SIGTERM;
			exit_status = OPENVPN_EXIT_STATUS_ERROR;
		}
	}

	if (flags & M_USAGE_SMALL)
		usage_small ();

	gc_free (&gc);
}

/*
 * Apply muting filter.
 */
bool
dont_mute (unsigned int flags)
{
	bool ret = true;
	if (mute_cutoff > 0 && !(flags & M_NOMUTE))
	{
		const int mute_level = DECODE_MUTE_LEVEL (flags);
		if (mute_level > 0 && mute_level == mute_category)
		{
			if (mute_count == mute_cutoff)
				msg (M_INFO | M_NOMUTE, "NOTE: --mute triggered...");
			if (++mute_count > mute_cutoff)
				ret = false;
		}
		else
		{
			const int suppressed = mute_count - mute_cutoff;
			if (suppressed > 0)
				msg (M_INFO | M_NOMUTE, "%d variation(s) on previous %d message(s) suppressed by --mute",
					suppressed,  mute_cutoff);
			mute_count = 1;
			mute_category = mute_level;
		}
	}
	return ret;
}

void
assert_failed (const char *filename, int line, const char *condition)
{
	if (condition)
		msg (M_FATAL, "Assertion failed at %s:%d (%s)", filename, line, condition);
	else
		msg (M_FATAL, "Assertion failed at %s:%d", filename, line);
	_exit (1);
}

/*
 * Fail memory allocation.  Don't use msg() because it tries
 * to allocate memory as part of its operation.
 */
void
out_of_memory (void)
{
	if (static_msg_mutex)
		ASSERT_FATAL (pthread_mutex_lock (static_msg_mutex) == 0);
	fprintf (stderr, PACKAGE_NAME ": Out of Memory\n");
	if (static_msg_mutex)
		ASSERT_FATAL (pthread_mutex_unlock (static_msg_mutex) == 0);
	exit (1);
}

void
open_syslog (const char *pgmname, bool stdio_to_null)
{
#if SYSLOG_CAPABILITY
	if (!msgfp && !std_redir)
	{
		if (!use_syslog)
		{
			pgmname_syslog = string_alloc (pgmname ? pgmname : PACKAGE, NULL);
			openlog (pgmname_syslog, LOG_PID, LOG_OPENVPN);
			use_syslog = true;

			/* Better idea: somehow pipe stdout/stderr output to msg() */
			if (stdio_to_null)
				set_std_files_to_null (false);
		}
	}
#else
	msg (M_WARN, "Warning on use of --daemon/--inetd: this operating system lacks daemon logging features,"
		" therefore when I become a daemon, I won't be able to log status or error messages");
#endif
}

void
close_syslog (void)
{
#if SYSLOG_CAPABILITY
	if (use_syslog)
	{
		closelog ();
		use_syslog = false;
		if (pgmname_syslog)
		{
			free (pgmname_syslog);
			pgmname_syslog = NULL;
		}
	}
#endif
}

#ifdef WIN32

static HANDLE orig_stderr;

HANDLE
get_orig_stderr (void)
{
	if (orig_stderr)
		return orig_stderr;
	else
		return GetStdHandle (STD_ERROR_HANDLE);
}

#endif

void
redirect_stdout_stderr (const char *file, bool append)
{
#if defined(WIN32)
	if (!std_redir)
	{
		struct gc_arena gc = gc_new ();
		HANDLE log_handle;
		int log_fd;

		SECURITY_ATTRIBUTES saAttr; 
		saAttr.nLength = sizeof (SECURITY_ATTRIBUTES); 
		saAttr.bInheritHandle = TRUE; 
		saAttr.lpSecurityDescriptor = NULL; 

		log_handle = CreateFileW (wide_string (file, &gc),
			GENERIC_WRITE,
			FILE_SHARE_READ,
			&saAttr,
			append ? OPEN_ALWAYS : CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		gc_free (&gc);

		if (log_handle == INVALID_HANDLE_VALUE)
		{
			msg (M_WARN|M_ERRNO, "Warning: cannot open --log file: %s", file);
			return;
		}

		/* append to logfile? */
		if (append)
		{
			if (SetFilePointer (log_handle, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
				msg (M_ERR, "Error: cannot seek to end of --log file: %s", file);
		}

		/* save original stderr for password prompts */
		orig_stderr = GetStdHandle (STD_ERROR_HANDLE);

#if 0 /* seems not be necessary with stdout/stderr redirection below */
		/* set up for redirection */
		if (!SetStdHandle (STD_OUTPUT_HANDLE, log_handle) || !SetStdHandle (STD_ERROR_HANDLE, log_handle))
			msg (M_ERR, "Error: cannot redirect stdout/stderr to --log file: %s", file);
#endif

		/* direct stdout/stderr to point to log_handle */
		log_fd = _open_osfhandle ((intptr_t) log_handle, _O_TEXT);
		if (log_fd == -1)
			msg (M_ERR, "Error: --log redirect failed due to _open_osfhandle failure");

		/* open log_handle as FILE stream */
		ASSERT (msgfp == NULL);
		msgfp = _fdopen (log_fd, "wt");
		if (msgfp == NULL)
			msg (M_ERR, "Error: --log redirect failed due to _fdopen");

		/* redirect C-library stdout/stderr to log file */
		if (_dup2 (log_fd, 1) == -1 || _dup2 (log_fd, 2) == -1)
			msg (M_WARN, "Error: --log redirect of stdout/stderr failed");

		std_redir = true;
	}
#elif defined(HAVE_DUP2)
	if (!std_redir)
	{
		int out = open (file, O_CREAT | O_WRONLY | (append ? O_APPEND : O_TRUNC), S_IRUSR | S_IWUSR);

		if (out < 0)
		{
			msg (M_WARN|M_ERRNO, "Warning: Error redirecting stdout/stderr to --log file: %s", file);
			return;
		}

		if (dup2 (out, 1) == -1)
			msg (M_ERR, "--log file redirection error on stdout");
		if (dup2 (out, 2) == -1)
			msg (M_ERR, "--log file redirection error on stderr");

		if (out > 2)
			close (out);

		std_redir = true;
	}

#else
	msg (M_WARN, "WARNING: The --log option is not supported on this OS because it lacks the dup2 function");
#endif
}

/*
 * Functions used to check return status of I/O operations.
 */

unsigned int x_cs_info_level;    /* GLOBAL */
unsigned int x_cs_verbose_level; /* GLOBAL */
unsigned int x_cs_err_delay_ms;  /* GLOBAL */

int exit_status = OPENVPN_EXIT_STATUS_GOOD;	/* GLOBAL */

void
reset_check_status (void)
{
	x_cs_info_level = 0;
	x_cs_verbose_level = 0;
}

void
set_check_status (unsigned int info_level, unsigned int verbose_level)
{
	x_cs_info_level = info_level;
	x_cs_verbose_level = verbose_level;
}

/*
 * Called after most socket or tun/tap operations, via the inline
 * function check_status ().
 *
 * Decide if we should print an error message, and see if we can
 * extract any useful info from the error, such as a Path MTU hint
 * from the OS.
 */
void
x_check_status (int status, const char *description, struct link_socket *sock, struct tuntap *tt)
{
	const int my_errno = openvpn_errno ();
	const char *extended_msg = NULL;

	msg (x_cs_verbose_level, "%s %s returned %d", sock ? proto2ascii (sock->info.proto, true) : "",
		description, status);

	if (status < 0)
	{
		struct gc_arena gc = gc_new ();
#if EXTENDED_SOCKET_ERROR_CAPABILITY
		/* get extended socket error message and possible PMTU hint from OS */
		if (sock)
		{
			int mtu;
			extended_msg = format_extended_socket_error (sock->sd, &mtu, &gc);
			if (mtu > 0 && sock->mtu != mtu)
			{
				sock->mtu = mtu;
				sock->info.mtu_changed = true;
			}
		}
#elif defined(WIN32)
		/* get possible driver error from TAP-Windows driver */
		extended_msg = tap_win_getinfo (tt, &gc);
#endif
		if (!ignore_sys_error (my_errno))
		{
			if (extended_msg)
				msg (x_cs_info_level, "%s %s [%s]: %s (code=%d)", description, sock ? proto2ascii (sock->info.proto, true) : "",
					extended_msg, strerror_ts (my_errno, &gc), my_errno);
			else
				msg (x_cs_info_level, "%s %s: %s (code=%d)", description, sock ? proto2ascii (sock->info.proto, true) : "",
					strerror_ts (my_errno, &gc), my_errno);

			if (x_cs_err_delay_ms)
				platform_sleep_milliseconds (x_cs_err_delay_ms);
		}
		gc_free (&gc);
	}
}

/* Allow MSG to be redirected through a virtual_output object */

const struct virtual_output *x_msg_virtual_output; /* GLOBAL */

/*
 * Exiting.
 */
void
openvpn_exit (const int status)
{
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* ֻ�����߳��ܵ��� openvpn_exit () */
#endif

	if (!forked && !exit_recur)
	{
		void tun_abort (void);
#ifdef ENABLE_PLUGIN
		void plugin_abort (void);
#endif

		/* ?? openvpn_exit(...) ����ݹ� ?? */
		exit_recur = true;

		tun_abort ();

#ifdef WIN32
		uninit_win32 ();
#endif

		close_syslog ();

#ifdef ENABLE_PLUGIN
		plugin_abort ();
#endif

#if PORT_SHARE
		if (port_share)
			port_share_abort (port_share);
#endif

#ifdef ENABLE_MEMSTATS
		mstats_close ();
#endif

#ifdef ENABLE_GUOMI
		/* �ͷż����豸 */
		uninit_encrypt_devices ();
#endif

#ifdef ABORT_ON_ERROR
		if (status == OPENVPN_EXIT_STATUS_ERROR)
			abort ();
#endif

		if (status == OPENVPN_EXIT_STATUS_GOOD)
			perf_output_results ();

		exit_recur = false;
	}

	exit (status);
}

/*
 * Translate msg flags into a string
 */
const char *
msg_flags_string (const unsigned int flags, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (16, gc);
	if (flags == M_INFO)
		buf_printf (&out, "I");
	if (flags & M_FATAL)
		buf_printf (&out, "F");
	if (flags & M_NONFATAL)
		buf_printf (&out, "N");
	if (flags & M_WARN)
		buf_printf (&out, "W");
	if (flags & M_DEBUG)
		buf_printf (&out, "D");
	return BSTR (&out);
}

#ifdef ENABLE_DEBUG
void
crash (void)
{
	char *null = NULL;
	*null = 0;
}
#endif

#ifdef WIN32

const char *
strerror_win32 (DWORD errnum, struct gc_arena *gc)
{
	/*
	 * This code can be omitted, though often the Windows WSA error messages are less informative than
	 * the Posix equivalents.
	 */
#if 1
	switch (errnum)
	{
	/* When the TAP-Windows driver returns STATUS_UNSUCCESSFUL, this code gets returned to user space. */
	case ERROR_GEN_FAILURE:
		return "General failure (ERROR_GEN_FAILURE)";
	case ERROR_IO_PENDING:
		return "I/O Operation in progress (ERROR_IO_PENDING)";
	case WSA_IO_INCOMPLETE:
		return "I/O Operation in progress (WSA_IO_INCOMPLETE)";
	case WSAEINTR:
		return "Interrupted system call (WSAEINTR)";
	case WSAEBADF:
		return "Bad file number (WSAEBADF)";
	case WSAEACCES:
		return "Permission denied (WSAEACCES)";
	case WSAEFAULT:
		return "Bad address (WSAEFAULT)";
	case WSAEINVAL:
		return "Invalid argument (WSAEINVAL)";
	case WSAEMFILE:
		return "Too many open files (WSAEMFILE)";
	case WSAEWOULDBLOCK:
		return "Operation would block (WSAEWOULDBLOCK)";
	case WSAEINPROGRESS:
		return "Operation now in progress (WSAEINPROGRESS)";
	case WSAEALREADY:
		return "Operation already in progress (WSAEALREADY)";
	case WSAEDESTADDRREQ:
		return "Destination address required (WSAEDESTADDRREQ)";
	case WSAEMSGSIZE:
		return "Message too long (WSAEMSGSIZE)";
	case WSAEPROTOTYPE:
		return "Protocol wrong type for socket (WSAEPROTOTYPE)";
	case WSAENOPROTOOPT:
		return "Bad protocol option (WSAENOPROTOOPT)";
	case WSAEPROTONOSUPPORT:
		return "Protocol not supported (WSAEPROTONOSUPPORT)";
	case WSAESOCKTNOSUPPORT:
		return "Socket type not supported (WSAESOCKTNOSUPPORT)";
	case WSAEOPNOTSUPP:
		return "Operation not supported on socket (WSAEOPNOTSUPP)";
	case WSAEPFNOSUPPORT:
		return "Protocol family not supported (WSAEPFNOSUPPORT)";
	case WSAEAFNOSUPPORT:
		return "Address family not supported by protocol family (WSAEAFNOSUPPORT)";
	case WSAEADDRINUSE:
		return "Address already in use (WSAEADDRINUSE)";
	case WSAENETDOWN:
		return "Network is down (WSAENETDOWN)";
	case WSAENETUNREACH:
		return "Network is unreachable (WSAENETUNREACH)";
	case WSAENETRESET:
		return "Net dropped connection or reset (WSAENETRESET)";
	case WSAECONNABORTED:
		return "Software caused connection abort (WSAECONNABORTED)";
	case WSAECONNRESET:
		return "Connection reset by peer (WSAECONNRESET)";
	case WSAENOBUFS:
		return "No buffer space available (WSAENOBUFS)";
	case WSAEISCONN:
		return "Socket is already connected (WSAEISCONN)";
	case WSAENOTCONN:
		return "Socket is not connected (WSAENOTCONN)";
	case WSAETIMEDOUT:
		return "Connection timed out (WSAETIMEDOUT)";
	case WSAECONNREFUSED:
		return "Connection refused (WSAECONNREFUSED)";
	case WSAELOOP:
		return "Too many levels of symbolic links (WSAELOOP)";
	case WSAENAMETOOLONG:
		return "File name too long (WSAENAMETOOLONG)";
	case WSAEHOSTDOWN:
		return "Host is down (WSAEHOSTDOWN)";
	case WSAEHOSTUNREACH:
		return "No Route to Host (WSAEHOSTUNREACH)";
	case WSAENOTEMPTY:
		return "Directory not empty (WSAENOTEMPTY)";
	case WSAEPROCLIM:
		return "Too many processes (WSAEPROCLIM)";
	case WSAEUSERS:
		return "Too many users (WSAEUSERS)";
	case WSAEDQUOT:
		return "Disc Quota Exceeded (WSAEDQUOT)";
	case WSAESTALE:
		return "Stale NFS file handle (WSAESTALE)";
	case WSASYSNOTREADY:
		return "Network SubSystem is unavailable (WSASYSNOTREADY)";
	case WSAVERNOTSUPPORTED:
		return "WINSOCK DLL Version out of range (WSAVERNOTSUPPORTED)";
	case WSANOTINITIALISED:
		return "Successful WSASTARTUP not yet performed (WSANOTINITIALISED)";
	case WSAEREMOTE:
		return "Too many levels of remote in path (WSAEREMOTE)";
	case WSAHOST_NOT_FOUND:
		return "Host not found (WSAHOST_NOT_FOUND)";
	default:
		break;
	}
#endif

	/* format a windows error message */
	{
		LPVOID lpMsgBuf = NULL;
		char *rv = NULL;
		struct buffer out = alloc_buf_gc (1024, gc);

		FormatMessageW (
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errnum, 
			MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US),
			(LPWSTR) &lpMsgBuf, 0, NULL);
		if (lpMsgBuf)
		{
			int n = WideCharToMultiByte (CP_UTF8, 0, (LPCWSTR) lpMsgBuf, -1, NULL, 0, NULL, NULL);
			rv = (char*) malloc (n);
			WideCharToMultiByte (CP_UTF8, 0, (LPCWSTR) lpMsgBuf, -1, rv, n, NULL, NULL);

			LocalFree (lpMsgBuf);

			/* trim to the left */
			if (rv)
			{
				unsigned char *p;
				for (p = (unsigned char *) rv + strlen (rv) - 1; p >= (unsigned char *) rv; p--)
				{
					if (isspace (*p))
						*p = '\0';
					else
						break;
				}
				buf_printf (&out, "%s", rv);
				free (rv);
			}
		}
		else
			buf_printf (&out, "[Unknown Win32 Error]");

		return BSTR (&out);
	}
}

#endif
