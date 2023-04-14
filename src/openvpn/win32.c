/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/*
 * Win32-specific OpenVPN code, targetted at the mingw
 * development environment.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef WIN32

#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "sig.h"
#include "win32.h"
#include "misc.h"

#include "memdbg.h"

#include "win32_wfp.h"

#include <DbgHelp.h>  

#ifdef HAVE_VERSIONHELPERS_H
#include <versionhelpers.h>
#else
#include "compat-versionhelpers.h"
#endif

/* WFP function pointers. Initialized in win_wfp_init_funcs() */
func_ConvertInterfaceIndexToLuid ConvertInterfaceIndexToLuid_ = NULL;
func_FwpmEngineOpen0 FwpmEngineOpen0 = NULL;
func_FwpmEngineClose0 FwpmEngineClose0 = NULL;
func_FwpmFilterAdd0 FwpmFilterAdd0 = NULL;
func_FwpmSubLayerAdd0 FwpmSubLayerAdd0 = NULL;
func_FwpmSubLayerDeleteByKey0 FwpmSubLayerDeleteByKey0 = NULL;
func_FwpmFreeMemory0 FwpmFreeMemory0 = NULL;
func_FwpmGetAppIdFromFileName0 FwpmGetAppIdFromFileName0 = NULL;
func_FwpmSubLayerGetByKey0 FwpmSubLayerGetByKey0 = NULL;

/*
 * WFP firewall name.
 */
static WCHAR *FIREWALL_NAME = L"OpenVPN"; /* GLOBAL */

/*
 * WFP handle and GUID.
 */
static HANDLE m_hEngineHandle = NULL; /* GLOBAL */

/*
 * Windows internal socket API state (opaque).
 */
static struct WSAData wsa_state; /* GLOBAL */

/*
 * Should we call win32_pause() on program exit?
 */
static bool pause_exit_enabled = false; /* GLOBAL */

/*
 * win32_signal is used to get input from the keyboard
 * if we are running in a console, or get input from an
 * event object if we are running as a service.
 */

struct win32_signal win32_signal; /* GLOBAL */

/*
 * Save our old window title so we can restore
 * it on exit.
 */
struct window_title window_title; /* GLOBAL*/

/*
 * Special global semaphore used to protect network
 * shell commands from simultaneous instantiation.
 */

struct semaphore netcmd_semaphore; /* GLOBAL */

/*
 * Windows system pathname such as c:\windows
 */
static char *win_sys_path = NULL; /* GLOBAL */

void
init_win32 (void)
{
	if (WSAStartup (0x0101, &wsa_state))
	{
		msg (M_ERR, "WSAStartup failed");
	}

	window_title_clear (&window_title);
	win32_signal_clear (&win32_signal);
}

void
uninit_win32 (void)
{
	netcmd_semaphore_close ();
	if (pause_exit_enabled)
	{
		if (win32_signal.mode == WSO_MODE_UNDEF)
		{
			struct win32_signal w;
			win32_signal_open (&w, WSO_FORCE_CONSOLE, NULL, false);
			win32_pause (&w);
			win32_signal_close (&w);
		}
		else
			win32_pause (&win32_signal);
	}
	window_title_restore (&window_title);
	win32_signal_close (&win32_signal);
	WSACleanup ();
	free (win_sys_path);
}

void
set_pause_exit_win32 (void)
{
	pause_exit_enabled = true;
}

bool
init_security_attributes_allow_all (struct security_attributes *obj)
{
	CLEAR (*obj);

	obj->sa.nLength = sizeof (SECURITY_ATTRIBUTES);
	obj->sa.lpSecurityDescriptor = &obj->sd;
	obj->sa.bInheritHandle = FALSE;
	if (!InitializeSecurityDescriptor (&obj->sd, SECURITY_DESCRIPTOR_REVISION))
		return false;
	if (!SetSecurityDescriptorDacl (&obj->sd, TRUE, NULL, FALSE))
		return false;
	return true;
}

void
overlapped_io_init (struct overlapped_io *o, const struct frame *frame, BOOL event_state,
		bool tuntap_buffer) /* if true: tuntap buffer, if false: socket buffer */
{
	CLEAR (*o);
	/* manual reset event, initially set according to event_state */
	o->overlapped.hEvent = CreateEvent (NULL, TRUE, event_state, NULL);
	if (o->overlapped.hEvent == NULL)
		msg (M_ERR, "Error: overlapped_io_init: CreateEvent failed");

	/* allocate buffer for overlapped I/O */
	alloc_buf_sock_tun (&o->buf_init, frame, tuntap_buffer, 0);
}

void
overlapped_io_close (struct overlapped_io *o)
{
	if (o->overlapped.hEvent)
	{
		if (!CloseHandle (o->overlapped.hEvent))
			msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on overlapped I/O event object");
	}
	free_buf (&o->buf_init);
}

char *
overlapped_io_state_ascii (const struct overlapped_io *o)
{
	switch (o->iostate)
	{
	case IOSTATE_INITIAL:
		return "0";
	case IOSTATE_QUEUED:
		return "Q";
	case IOSTATE_IMMEDIATE_RETURN:
		return "1";
	}
	return "?";
}

/*
 * Event-based notification of network events
 */

void
init_net_event_win32 (struct rw_handle *event, long network_events, socket_descriptor_t sd, unsigned int flags)
{
	/* manual reset events, initially set to unsignaled */

	/* initialize write event */
	if (!(flags & NE32_PERSIST_EVENT) || !event->write)
	{
		if (flags & NE32_WRITE_EVENT)
		{
			event->write = CreateEvent (NULL, TRUE, FALSE, NULL);
			if (event->write == NULL)
				msg (M_ERR, "Error: init_net_event_win32: CreateEvent (write) failed");
		}
		else
			event->write = NULL;
	}

	/* initialize read event */
	if (!(flags & NE32_PERSIST_EVENT) || !event->read)
	{
		event->read = CreateEvent (NULL, TRUE, FALSE, NULL);
		if (event->read == NULL)
			msg (M_ERR, "Error: init_net_event_win32: CreateEvent (read) failed");
	}

	/* setup network events to change read event state */
	if (WSAEventSelect (sd, event->read, network_events) != 0)
		msg (M_FATAL | M_ERRNO, "Error: init_net_event_win32: WSAEventSelect call failed");
}

long
reset_net_event_win32 (struct rw_handle *event, socket_descriptor_t sd)
{
	WSANETWORKEVENTS wne;  
	if (WSAEnumNetworkEvents (sd, event->read, &wne) != 0)
	{
		msg (M_FATAL | M_ERRNO, "Error: reset_net_event_win32: WSAEnumNetworkEvents call failed");
		return 0; /* NOTREACHED */
	}
	else
		return wne.lNetworkEvents;
}

void
close_net_event_win32 (struct rw_handle *event, socket_descriptor_t sd, unsigned int flags)
{
	if (event->read)
	{
		if (socket_defined (sd))
		{
			if (WSAEventSelect (sd, event->read, 0) != 0)
				msg (M_WARN | M_ERRNO, "Warning: close_net_event_win32: WSAEventSelect call failed");
		}
		if (!ResetEvent (event->read))
			msg (M_WARN | M_ERRNO, "Warning: ResetEvent (read) failed in close_net_event_win32");
		if (!(flags & NE32_PERSIST_EVENT))
		{
			if (!CloseHandle (event->read))
				msg (M_WARN | M_ERRNO, "Warning: CloseHandle (read) failed in close_net_event_win32");
			event->read = NULL;
		}
	}

	if (event->write)
	{
		if (!ResetEvent (event->write))
			msg (M_WARN | M_ERRNO, "Warning: ResetEvent (write) failed in close_net_event_win32");
		if (!(flags & NE32_PERSIST_EVENT))
		{
			if (!CloseHandle (event->write))
				msg (M_WARN | M_ERRNO, "Warning: CloseHandle (write) failed in close_net_event_win32");
			event->write = NULL;
		}
	}
}

/*
 * struct net_event_win32
 */

void
net_event_win32_init (struct net_event_win32 *ne)
{
	CLEAR (*ne);
	ne->sd = SOCKET_UNDEFINED;
}

void
net_event_win32_start (struct net_event_win32 *ne, long network_events, socket_descriptor_t sd)
{
	ASSERT (!socket_defined (ne->sd));
	ne->sd = sd;
	ne->event_mask = 0;
	init_net_event_win32 (&ne->handle, network_events, sd, NE32_PERSIST_EVENT|NE32_WRITE_EVENT);
}

void
net_event_win32_reset_write (struct net_event_win32 *ne)
{
	BOOL status;
	if (ne->event_mask & FD_WRITE)
		status = SetEvent (ne->handle.write);
	else
		status = ResetEvent (ne->handle.write);
	if (!status)
		msg (M_WARN | M_ERRNO, "Warning: SetEvent/ResetEvent failed in net_event_win32_reset_write");
}

void
net_event_win32_reset (struct net_event_win32 *ne)
{
	ne->event_mask |= reset_net_event_win32 (&ne->handle, ne->sd);
}

void
net_event_win32_stop (struct net_event_win32 *ne)
{
	if (net_event_win32_defined (ne))
		close_net_event_win32 (&ne->handle, ne->sd, NE32_PERSIST_EVENT);
	ne->sd = SOCKET_UNDEFINED;
	ne->event_mask = 0;
}

void
net_event_win32_close (struct net_event_win32 *ne)
{
	if (net_event_win32_defined (ne))
		close_net_event_win32 (&ne->handle, ne->sd, 0);
	net_event_win32_init (ne);
}

/*
 * Simulate *nix signals on Windows.
 *
 * Two modes:
 * (1) Console mode -- map keyboard function keys to signals
 * (2) Service mode -- map Windows event object to SIGTERM
 */

static void
win_trigger_event(struct win32_signal *ws)
{
	if (ws->mode == WSO_MODE_SERVICE && HANDLE_DEFINED (ws->in.read))
		SetEvent (ws->in.read);
	else /* generate a key-press event */
	{
		DWORD tmp;
		INPUT_RECORD ir;
		HANDLE stdin_handle = GetStdHandle (STD_INPUT_HANDLE);

		CLEAR (ir);
		ir.EventType = KEY_EVENT;
		ir.Event.KeyEvent.bKeyDown = true;
		if (!stdin_handle || !WriteConsoleInput (stdin_handle, &ir, 1, &tmp))
			msg (M_WARN|M_ERRNO, "WARN: win_trigger_event: WriteConsoleInput");
	}
}

/*
 * Callback to handle console ctrl events
 */
static bool WINAPI
win_ctrl_handler (DWORD signum)
{
	msg (D_LOW, "win_ctrl_handler: signal received (code=%lu)", (unsigned long) signum);

	if (siginfo_static.signal_received == SIGTERM)
		return true;

	switch (signum)
	{
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		throw_signal (SIGTERM);
		/* trigget the win32_signal to interrupt the event loop */
		win_trigger_event (&win32_signal);
		return true;
		break;
	default:
		msg (D_LOW, "win_ctrl_handler: signal (code=%lu) not handled", (unsigned long) signum);
		break;
	}

	/* pass all other signals to the next handler */
	return false;
}

void
win32_signal_clear (struct win32_signal *ws)
{
	CLEAR (*ws);
}

void
win32_signal_open (struct win32_signal *ws, int force, const char *exit_event_name, bool exit_event_initial_state)
{
	CLEAR (*ws);

	ws->mode = WSO_MODE_UNDEF;
	ws->in.read = INVALID_HANDLE_VALUE;
	ws->in.write = INVALID_HANDLE_VALUE;
	ws->console_mode_save = 0;
	ws->console_mode_save_defined = false;

	if (force == WSO_NOFORCE || force == WSO_FORCE_CONSOLE)
	{
		/*
		* Try to open console.
		*/
		ws->in.read = GetStdHandle (STD_INPUT_HANDLE);
		if (ws->in.read != INVALID_HANDLE_VALUE)
		{
			if (GetConsoleMode (ws->in.read, &ws->console_mode_save))
			{
				/* running on a console */
				const DWORD new_console_mode = ws->console_mode_save
					& ~(ENABLE_WINDOW_INPUT
					| ENABLE_PROCESSED_INPUT
					| ENABLE_LINE_INPUT
					| ENABLE_ECHO_INPUT 
					| ENABLE_MOUSE_INPUT);

				if (new_console_mode != ws->console_mode_save)
				{
					if (!SetConsoleMode (ws->in.read, new_console_mode))
						msg (M_ERR, "Error: win32_signal_open: SetConsoleMode failed");
					ws->console_mode_save_defined = true;
				}
				ws->mode = WSO_MODE_CONSOLE;
			}
			else
				ws->in.read = INVALID_HANDLE_VALUE; /* probably running as a service */
		}
	}

	/*
	* If console open failed, assume we are running
	* as a service.
	*/
	if ((force == WSO_NOFORCE || force == WSO_FORCE_SERVICE) && !HANDLE_DEFINED (ws->in.read) && exit_event_name)
	{
		struct security_attributes sa;

		if (!init_security_attributes_allow_all (&sa))
			msg (M_ERR, "Error: win32_signal_open: init SA failed");

		ws->in.read = CreateEventA (&sa.sa,
			TRUE,
			exit_event_initial_state ? TRUE : FALSE,
			exit_event_name);
		if (ws->in.read == NULL)
		{
			msg (M_WARN|M_ERRNO, "NOTE: CreateEvent '%s' failed", exit_event_name);
		}
		else
		{
			if (WaitForSingleObject (ws->in.read, 0) != WAIT_TIMEOUT)
				msg (M_FATAL, "ERROR: Exit Event ('%s') is signaled", exit_event_name);
			else
				ws->mode = WSO_MODE_SERVICE;
		}
	}

	/* set the ctrl handler in both console and service modes */
	if (!SetConsoleCtrlHandler ((PHANDLER_ROUTINE) win_ctrl_handler, true))
		msg (M_WARN|M_ERRNO, "WARN: SetConsoleCtrlHandler failed");
}

static bool
keyboard_input_available (struct win32_signal *ws)
{
	ASSERT (ws->mode == WSO_MODE_CONSOLE);
	if (HANDLE_DEFINED (ws->in.read))
	{
		DWORD n;
		if (GetNumberOfConsoleInputEvents (ws->in.read, &n))
			return n > 0;
	}
	return false;
}

static unsigned int
keyboard_ir_to_key (INPUT_RECORD *ir)
{
	if (ir->Event.KeyEvent.uChar.AsciiChar == 0)
		return ir->Event.KeyEvent.wVirtualScanCode;

	if ((ir->Event.KeyEvent.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))
			&& (ir->Event.KeyEvent.wVirtualKeyCode != 18))
		return ir->Event.KeyEvent.wVirtualScanCode * 256;

	return ir->Event.KeyEvent.uChar.AsciiChar;
}

static unsigned int
win32_keyboard_get (struct win32_signal *ws)
{
	ASSERT (ws->mode == WSO_MODE_CONSOLE);
	if (HANDLE_DEFINED (ws->in.read))
	{
		INPUT_RECORD ir;
		do {
			DWORD n;
			if (!keyboard_input_available (ws))
				return 0;
			if (!ReadConsoleInput (ws->in.read, &ir, 1, &n))
				return 0;
		} while (ir.EventType != KEY_EVENT || ir.Event.KeyEvent.bKeyDown != TRUE);

		return keyboard_ir_to_key (&ir);
	}
	else
		return 0;
}

void
win32_signal_close (struct win32_signal *ws)
{
	if (ws->mode == WSO_MODE_SERVICE && HANDLE_DEFINED (ws->in.read))
		CloseHandle (ws->in.read);
	if (ws->console_mode_save_defined)
	{
		if (!SetConsoleMode (ws->in.read, ws->console_mode_save))
			msg (M_ERR, "Error: win32_signal_close: SetConsoleMode failed");
	}
	CLEAR (*ws);
}

/*
 * Return true if interrupt occurs in service mode.
 */
bool
win32_service_interrupt (struct win32_signal *ws)
{
	if (ws->mode == WSO_MODE_SERVICE)
	{
		if (HANDLE_DEFINED (ws->in.read) && WaitForSingleObject (ws->in.read, 0) == WAIT_OBJECT_0)
			return true;
	}
	return false;
}

int
win32_signal_get (struct win32_signal *ws)
{
	int ret = 0;

	if (siginfo_static.signal_received)
	{
		ret = siginfo_static.signal_received;
	}
	else
	{
		if (ws->mode == WSO_MODE_SERVICE)
		{
			if (win32_service_interrupt (ws))
				ret = SIGTERM;
		}
		else if (ws->mode == WSO_MODE_CONSOLE)
		{
			switch (win32_keyboard_get (ws))
			{
			case 0x3B: /* F1 -> USR1 */
				ret = SIGUSR1;
				break;
			case 0x3C: /* F2 -> USR2 */
				ret = SIGUSR2;
				break;
			case 0x3D: /* F3 -> HUP */
				ret = SIGHUP;
				break;
			case 0x3E: /* F4 -> TERM */
				ret = SIGTERM;
				break;
			case 0x03: /* CTRL-C -> TERM */
				ret = SIGTERM;
				break;
			}
		}
		if (ret)
		{
			siginfo_static.signal_received = ret;
			siginfo_static.hard = true;
		}
	}
	return ret;
}

void
win32_pause (struct win32_signal *ws)
{
	if (ws->mode == WSO_MODE_CONSOLE && HANDLE_DEFINED (ws->in.read))
	{
		int status;
		msg (M_INFO|M_NOPREFIX, "Press any key to continue...");
		do {
			status = WaitForSingleObject (ws->in.read, INFINITE);
		} while (!win32_keyboard_get (ws));
	}
}

/* window functions */

void
window_title_clear (struct window_title *wt)
{
	CLEAR (*wt);
}

void
window_title_save (struct window_title *wt)
{
	if (!wt->saved)
	{
		if (!GetConsoleTitleA (wt->old_window_title, sizeof (wt->old_window_title)))
		{
			wt->old_window_title[0] = 0;
			wt->saved = false;
		}
		else
			wt->saved = true;
	}
}

void
window_title_restore (const struct window_title *wt)
{
	if (wt->saved)
		SetConsoleTitleA (wt->old_window_title);
}

void
window_title_generate (const char *title)
{
	struct gc_arena gc = gc_new ();
	struct buffer out = alloc_buf_gc (256, &gc);
	if (!title)
		title = "";
	buf_printf (&out, "[%s] " PACKAGE_NAME " " PACKAGE_VERSION " F4:EXIT F1:USR1 F2:USR2 F3:HUP", title);
	SetConsoleTitleA (BSTR (&out));
	gc_free (&gc);
}

/* semaphore functions */

void
semaphore_clear (struct semaphore *s)
{
	CLEAR (*s);
}

void
semaphore_open (struct semaphore *s, const char *name)
{
	struct security_attributes sa;

	s->locked = false;
	s->name = name;
	s->hand = NULL;

	if (init_security_attributes_allow_all (&sa))
		s->hand = CreateSemaphoreA (&sa.sa, 1, 1, name);

	if (s->hand == NULL)
		msg (M_WARN|M_ERRNO, "WARNING: Cannot create Win32 semaphore '%s'", name);
	else
		dmsg (D_SEMAPHORE, "Created Win32 semaphore '%s'", s->name);
}

bool
semaphore_lock (struct semaphore *s, int timeout_milliseconds)
{
	bool ret = true;

	if (s->hand)
	{
		DWORD status;
		ASSERT (!s->locked);

		dmsg (D_SEMAPHORE_LOW, "Attempting to lock Win32 semaphore '%s' prior to net shell command (timeout = %d sec)",
			s->name, timeout_milliseconds / 1000);
		status = WaitForSingleObject (s->hand, timeout_milliseconds);
		if (status == WAIT_FAILED)
			msg (M_ERR, "Wait failed on Win32 semaphore '%s'", s->name);
		ret = (status == WAIT_TIMEOUT) ? false : true;
		if (ret)
		{
			dmsg (D_SEMAPHORE, "Locked Win32 semaphore '%s'", s->name);
			s->locked = true;
		}
		else
		{
			dmsg (D_SEMAPHORE, "Wait on Win32 semaphore '%s' timed out after %d milliseconds",
				s->name, timeout_milliseconds);
		}
	}
	return ret;
}

void
semaphore_release (struct semaphore *s)
{
	if (s->hand)
	{
		ASSERT (s->locked);
		dmsg (D_SEMAPHORE, "Releasing Win32 semaphore '%s'", s->name);
		if (!ReleaseSemaphore (s->hand, 1, NULL))
			msg (M_WARN | M_ERRNO, "ReleaseSemaphore failed on Win32 semaphore '%s'", s->name);
		s->locked = false;
	}
}

void
semaphore_close (struct semaphore *s)
{
	if (s->hand)
	{
		if (s->locked)
			semaphore_release (s);
		dmsg (D_SEMAPHORE, "Closing Win32 semaphore '%s'", s->name);
		CloseHandle (s->hand);
		s->hand = NULL;
	}
}

/*
 * Special global semaphore used to protect network
 * shell commands from simultaneous instantiation.
 */

void
netcmd_semaphore_init (void)
{
	semaphore_open (&netcmd_semaphore, PACKAGE "_netcmd");
}

void
netcmd_semaphore_close (void)
{
	semaphore_close (&netcmd_semaphore);
}

void
netcmd_semaphore_lock (void)
{
	const int timeout_seconds = 600;

	if (!netcmd_semaphore.hand)
		netcmd_semaphore_init ();

	if (!semaphore_lock (&netcmd_semaphore, timeout_seconds * 1000))
		msg (M_FATAL, "Cannot lock net command semaphore"); 
}

void
netcmd_semaphore_release (void)
{
	semaphore_release (&netcmd_semaphore);
	/* netcmd_semaphore has max count of 1 - safe to close after release */
	semaphore_close (&netcmd_semaphore);
}

/*
 * Return true if filename is safe to be used on Windows,
 * by avoiding the following reserved names:
 *
 * CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
 * LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9, and CLOCK$
 *
 * See: http://msdn.microsoft.com/en-us/library/aa365247.aspx
 *  and http://msdn.microsoft.com/en-us/library/86k9f82k(VS.80).aspx
 */

static bool
cmp_prefix (const char *str, const bool n, const char *pre)
{
	size_t i = 0;

	if (!str)
		return false;

	while (true)
	{
		const int c1 = pre[i];
		int c2 = str[i];
		++i;
		if (c1 == '\0')
		{
			if (n)
			{
				if (isdigit (c2))
					c2 = str[i];
				else
					return false;
			}
			return c2 == '\0' || c2 == '.';
		}
		else if (c2 == '\0')
			return false;
		if (c1 != tolower (c2))
			return false;
	}
}

bool
win_safe_filename (const char *fn)
{
	if (cmp_prefix (fn, false, "con"))
		return false;
	if (cmp_prefix (fn, false, "prn"))
		return false;
	if (cmp_prefix (fn, false, "aux"))
		return false;
	if (cmp_prefix (fn, false, "nul"))
		return false;
	if (cmp_prefix (fn, true, "com"))
		return false;
	if (cmp_prefix (fn, true, "lpt"))
		return false;
	if (cmp_prefix (fn, false, "clock$"))
		return false;
	return true;
}

/*
 * Service functions for openvpn_execve
 */

static char *
env_block (const struct env_set *es)
{
	char force_path[256];
	char *sysroot = get_win_sys_path ();

	if (!openvpn_snprintf (force_path, sizeof (force_path), "PATH=%s\\System32;%s;%s\\System32\\Wbem",
			sysroot, sysroot, sysroot))
    msg (M_WARN, "env_block: default path truncated to %s", force_path);

	if (es)
	{
		struct env_item *e;
		char *ret;
		char *p;
		size_t nchars = 1;
		bool path_seen = false;

		for (e = es->list; e != NULL; e = e->next)
			nchars += strlen (e->string) + 1;

		nchars += strlen (force_path) + 1;

		ret = (char *) malloc (nchars);
		check_malloc_return (ret);

		p = ret;
		for (e = es->list; e != NULL; e = e->next)
		{
			if (env_allowed (e->string))
			{
				strcpy (p, e->string);
				p += strlen (e->string) + 1;
			}
			if (strncmp (e->string, "PATH=", 5) == 0)
				path_seen = true;
		}

		/* make sure PATH is set */
		if (!path_seen)
		{
			msg (M_INFO, "env_block: add %s", force_path);
			strcpy (p, force_path);
			p += strlen (force_path) + 1;
		}

		*p = '\0';
		return ret;
	}
	else
		return NULL;
}

static WCHAR *
wide_cmd_line (const struct argv *a, struct gc_arena *gc)
{
	size_t nchars = 1;
	size_t maxlen = 0;
	size_t i;
	struct buffer buf;
	char *work = NULL;

	if (!a)
		return NULL;

	for (i = 0; i < a->arg_c; ++i)
	{
		const char *arg = a->arg_v[i];
		const size_t len = strlen (arg);

		nchars += len + 3;
		if (len > maxlen)
			maxlen = len;
	}

	work = (char*) gc_malloc (maxlen + 1, false, gc);
	check_malloc_return (work);
	buf = alloc_buf_gc (nchars, gc);

	for (i = 0; i < a->arg_c; ++i)
	{
		const char *arg = a->arg_v[i];
		if (a->norm)
		{
			if (i)
				buf_printf (&buf, " ");
			buf_printf (&buf, "%s", arg);
		}
		else
		{
			strcpy (work, arg);
			string_mod (work, CC_PRINT, CC_DOUBLE_QUOTE|CC_CRLF, '_');
			if (i)
				buf_printf (&buf, " ");
			if (string_class (work, CC_ANY, CC_SPACE))
				buf_printf (&buf, "%s", work);
			else
				buf_printf (&buf, "\"%s\"", work);
		}
	}

	return wide_string (BSTR (&buf), gc);
}

/*
 * Attempt to simulate fork/execve on Windows
 */
int
openvpn_execve (const struct argv *a, const struct env_set *es, const unsigned int flags, struct buffer *out)
{
#define PIPE_SIZE	(4096 + 24)
	static bool exec_warn = false;
	int ret = -1;

	if (a && a->arg_v[0])
	{
		if (openvpn_execve_allowed (flags))
		{
			struct gc_arena gc = gc_new ();
			HANDLE child_out_rd = INVALID_HANDLE_VALUE;
			HANDLE child_out_wr = INVALID_HANDLE_VALUE;
			HANDLE child_out_err = INVALID_HANDLE_VALUE;
			SECURITY_ATTRIBUTES sa_attr;
			STARTUPINFOW start_info;
			PROCESS_INFORMATION proc_info;
			/* this allows console programs to run, and is ignored otherwise */
			DWORD proc_flags = CREATE_NO_WINDOW;
			char *env = env_block (es);
			WCHAR *cl = wide_cmd_line (a, &gc);
			WCHAR *cmd = wide_string (a->arg_v[0], &gc);

			CLEAR (sa_attr);
			CLEAR (start_info);
			CLEAR (proc_info);

			/* fill in STARTUPINFO struct */
			GetStartupInfoW (&start_info);
			start_info.cb = sizeof (start_info);
			start_info.dwFlags = STARTF_USESHOWWINDOW;
			start_info.wShowWindow = SW_HIDE;

			if (out)
			{
				start_info.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;

				sa_attr.nLength = sizeof (SECURITY_ATTRIBUTES);
				sa_attr.bInheritHandle = TRUE;
				sa_attr.lpSecurityDescriptor = NULL;

				if (!CreatePipe (&child_out_rd, &child_out_wr, &sa_attr, PIPE_SIZE))
				{
					msg (M_WARN|M_ERRNO, "openvpn_execve: CreatePipe failed");
					goto error;
				}

				if (!SetHandleInformation (child_out_rd, HANDLE_FLAG_INHERIT, 0))
				{
					msg (M_WARN|M_ERRNO, "openvpn_execve: SetHandleInformation failed");
					goto error;
				}

				if (!DuplicateHandle (GetCurrentProcess (), child_out_wr, GetCurrentProcess (), &child_out_err, 0,
					TRUE, DUPLICATE_SAME_ACCESS))
				{
					msg (M_WARN|M_ERRNO, "openvpn_execve: DuplicateHandle failed");
					goto error;				
				}

				start_info.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
				start_info.hStdError = child_out_err;
				start_info.hStdOutput = child_out_wr;
			}

			if (CreateProcessW (cmd, cl, NULL, NULL, out ? TRUE : FALSE, proc_flags, env, NULL, &start_info, &proc_info))
			{
				char rd_buf[1024];
				DWORD rd_len = 0, exit_status = 0;

				if (child_out_wr != INVALID_HANDLE_VALUE)
				{
					CloseHandle (child_out_wr);	/* 必须先关闭 */
					child_out_wr = INVALID_HANDLE_VALUE;
				}
				if (child_out_rd != INVALID_HANDLE_VALUE)
				{
					for (;;)
					{
						if (!ReadFile (child_out_rd, rd_buf, sizeof (rd_buf), &rd_len, NULL) || rd_len == 0)
							break;
						buf_write (out, rd_buf, rd_len);
					}
					buf_null_terminate (out);
					CloseHandle (child_out_rd);
					child_out_rd = INVALID_HANDLE_VALUE;
				}

				CloseHandle (proc_info.hThread);
				WaitForSingleObject (proc_info.hProcess, INFINITE);
				if (GetExitCodeProcess (proc_info.hProcess, &exit_status))
					ret = (int) exit_status;
				else
					msg (M_WARN|M_ERRNO, "openvpn_execve: GetExitCodeProcess %S failed", cmd);
				CloseHandle (proc_info.hProcess);
			}
			else
				msg (M_WARN|M_ERRNO, "openvpn_execve: CreateProcess %S failed", cmd);

error:
			if (child_out_wr != INVALID_HANDLE_VALUE)
				CloseHandle (child_out_wr);
			if (child_out_err != INVALID_HANDLE_VALUE)
				CloseHandle (child_out_err);					
			if (child_out_rd != INVALID_HANDLE_VALUE)
				CloseHandle (child_out_rd);			
			free (env);
			gc_free (&gc);
		}
		else if (!exec_warn && (script_security < SSEC_SCRIPTS))
		{
			msg (M_WARN, SCRIPT_SECURITY_WARNING);
			exec_warn = true;
		}
	}
	else
	{
		msg (M_WARN, "openvpn_execve: called with empty argv");
	}

	return ret;
}

WCHAR *
wide_string (const char *utf8_str, struct gc_arena *gc)
{
	int n = MultiByteToWideChar (CP_UTF8, 0, utf8_str, -1, NULL, 0);
	WCHAR *ucs16_str = (WCHAR *) gc_malloc (n * sizeof (WCHAR), false, gc);
	MultiByteToWideChar (CP_UTF8, 0, utf8_str, -1, ucs16_str, n);
	return ucs16_str;
}

char *
local_string (const char *utf8_str, struct gc_arena *gc)
{
	WCHAR *ucs16_str = NULL;
	char *local_str = NULL;
	int n = 0;
	
	n = MultiByteToWideChar (CP_UTF8, 0, utf8_str, -1, NULL, 0);
	ucs16_str = (WCHAR *) gc_malloc (n * sizeof (WCHAR), false, gc);
	MultiByteToWideChar (CP_UTF8, 0, utf8_str, -1, ucs16_str, n);

	n = WideCharToMultiByte (CP_ACP, 0, ucs16_str, -1, NULL, 0, NULL, NULL);
	local_str = (char*) gc_malloc (n + 10, false, gc);
	ZeroMemory(local_str, n + 10);
	WideCharToMultiByte (CP_ACP, 0, ucs16_str, -1, local_str, n, NULL, NULL);
	return local_str;
}

char *
utf8_string (const char *local_str, struct gc_arena *gc)
{
	WCHAR *ucs16_str = NULL;
	char *utf8_str = NULL;
	int n = 0;
	
	n = MultiByteToWideChar (CP_ACP, 0, local_str, -1, NULL, 0);
	ucs16_str = (WCHAR *) gc_malloc (n * sizeof (WCHAR), false, gc);
	MultiByteToWideChar (CP_ACP, 0, local_str, -1, ucs16_str, n);

	n = WideCharToMultiByte (CP_UTF8, 0, ucs16_str, -1, NULL, 0, NULL, NULL);
	utf8_str = (char*) gc_malloc (n + 10, false, gc);
	ZeroMemory(utf8_str, n + 10);
	WideCharToMultiByte (CP_UTF8, 0, ucs16_str, -1, utf8_str, n, NULL, NULL);
	return utf8_str;
}

/*
 * call ourself in another process
 */
void
fork_to_self (const char *cmdline)
{
	STARTUPINFOA start_info;
	PROCESS_INFORMATION proc_info;
	char self_exe[1024];
	char *cl = string_alloc (cmdline, NULL);
	DWORD status;

	CLEAR (start_info);
	CLEAR (proc_info);
	CLEAR (self_exe);

	status = GetModuleFileNameA (NULL, self_exe, sizeof (self_exe));
	if (status == 0 || status == sizeof (self_exe))
	{
		msg (M_WARN|M_ERRNO, "fork_to_self: CreateProcess failed: cannot get module name via GetModuleFileName");
		goto done;
	}

	/* fill in STARTUPINFO struct */
	GetStartupInfoA (&start_info);
	start_info.cb = sizeof (start_info);
	start_info.dwFlags = STARTF_USESHOWWINDOW;
	start_info.wShowWindow = SW_HIDE;

	if (CreateProcessA (self_exe, cl, NULL, NULL, FALSE, 0, NULL, NULL, &start_info, &proc_info))
	{
		CloseHandle (proc_info.hThread);
		CloseHandle (proc_info.hProcess);
	}
	else
	{
		msg (M_WARN|M_ERRNO, "fork_to_self: CreateProcess failed: %s", cmdline);
	}

done:
	free (cl);
}

bool start_win32_service (const char *srv_name)
{
	struct gc_arena gc = gc_new ();
	bool ret = false;

	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;

	/* Open a handle to the SC Manager database. */
	schSCManager = OpenSCManagerA (NULL, NULL, SC_MANAGER_ALL_ACCESS); 
	if (NULL == schSCManager)
	{
		msg (M_WARN|M_ERRNO, "OpenSCManager failed - %s", strerror_win32 (GetLastError (), &gc));
		goto finish;
	}

	schService = OpenServiceA (schSCManager, srv_name, SERVICE_ALL_ACCESS); 
	if (NULL == schService)
	{
		msg (M_WARN|M_ERRNO, "OpenService failed - %s", strerror_win32 (GetLastError (), &gc));
		goto finish;
	}

	if (StartService (schService, 0, NULL)) 
	{
		msg (M_INFO, "Service %s started", srv_name);
		ret = true;
	}
	else
	{
		DWORD error = GetLastError ();
		if (error == ERROR_SERVICE_ALREADY_RUNNING)
			msg (M_INFO, "StartService failed - %s", "service already running");
		else
			msg (M_WARN|M_ERRNO, "StartService failed - %s", strerror_win32 (error, &gc));
	}

finish:
	if (schService)
		CloseServiceHandle (schService);
	if (schSCManager)
		CloseServiceHandle (schSCManager);
	gc_free (&gc);
	return ret;
}

bool stop_win32_service (const char *srv_name)
{
	struct gc_arena gc = gc_new ();
	bool ret = false;

	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;
	SERVICE_STATUS status;

	/* Open a handle to the SC Manager database. */
	schSCManager = OpenSCManagerA (NULL, NULL, SC_MANAGER_ALL_ACCESS); 
	if (NULL == schSCManager)
	{
		msg (M_WARN|M_ERRNO, "OpenSCManager failed - %s", strerror_win32 (GetLastError (), &gc));
		goto finish;
	}

	schService = OpenServiceA (schSCManager, srv_name, SERVICE_STOP|SERVICE_QUERY_STATUS); 
	if (NULL == schService)
	{
		msg (M_WARN|M_ERRNO, "OpenService failed - %s", strerror_win32 (GetLastError (), &gc));
		goto finish;
	}

	if (ControlService (schService, SERVICE_CONTROL_STOP, &status))
	{
		int i = 0;

		if (status.dwCurrentState != SERVICE_STOP_PENDING && status.dwCurrentState != SERVICE_STOPPED)
			msg (M_WARN, "ControlService SERVICE_CONTROL_STOP return status %d", status.dwCurrentState);

		while (status.dwCurrentState == SERVICE_STOP_PENDING && i++ < 600)
		{
			millisleep (200);
			if (!QueryServiceStatus (schService, &status))
				break;
		}

		ret = status.dwCurrentState == SERVICE_STOPPED;
		if (ret)
			msg (M_INFO, "Service %s stopped", srv_name);
		else
			msg (M_INFO, "Service %s stop failed - status %d ", srv_name, status.dwCurrentState);
	}
	else
	{
		msg (M_WARN|M_ERRNO, "ControlService failed - %s", strerror_win32 (GetLastError (), &gc));
    }

finish:
	if (schService)
		CloseServiceHandle (schService);
	if (schSCManager)
		CloseServiceHandle (schSCManager);
	gc_free (&gc);
	return ret;
}

char *
get_win_sys_path (void)
{
	ASSERT (win_sys_path);
	return win_sys_path;
}

void
set_win_sys_path (const char *newpath, struct env_set *es)
{
	free (win_sys_path);
	win_sys_path = string_alloc (newpath, NULL);
	setenv_str (es, SYS_PATH_ENV_VAR_NAME, win_sys_path); /* route.exe needs this */
}

void
set_win_sys_path_via_env (struct env_set *es)
{
	char buf[256];
	DWORD status = GetEnvironmentVariableA (SYS_PATH_ENV_VAR_NAME, buf, sizeof (buf));
	if (!status)
		msg (M_ERR, "Cannot find environmental variable %s", SYS_PATH_ENV_VAR_NAME);
	if (status > sizeof (buf) - 1)
		msg (M_FATAL, "String overflow attempting to read environmental variable %s", SYS_PATH_ENV_VAR_NAME);
	set_win_sys_path (buf, es);
}

const char *
win_get_tempdir (void)
{
	static char tmpdir[MAX_PATH];
	WCHAR wtmpdir[MAX_PATH];

	if (!GetTempPathW (_countof(wtmpdir), wtmpdir))
	{
		/* Warn if we can't find a valid temporary directory, which should be unlikely. */
		msg (M_WARN, "Could not find a suitable temporary directory. (GetTempPath() failed).  Consider using --tmp-dir");
		return NULL;
	}

	if (WideCharToMultiByte (CP_UTF8, 0, wtmpdir, -1, NULL, 0, NULL, NULL) > sizeof (tmpdir))
	{
		msg (M_WARN, "Could not get temporary directory. Path is too long. Consider using --tmp-dir");
		return NULL;
	}

	WideCharToMultiByte (CP_UTF8, 0, wtmpdir, -1, tmpdir, sizeof (tmpdir), NULL, NULL);
	return tmpdir;
}

static inline HMODULE
loadSystemDll (const char *pszName)
{
	char   szPath[MAX_PATH];
	UINT   cchPath = GetSystemDirectoryA (szPath, sizeof (szPath));
	size_t cbName  = strlen (pszName) + 1;

	if (cchPath + 1 + cbName > sizeof (szPath))
		return NULL;
	szPath[cchPath] = '\\';
	memcpy (&szPath[cchPath + 1], pszName, cbName);

	return LoadLibraryA (szPath);
}

static inline BOOL
IsDataSectionNeeded (const WCHAR *pModuleName)
{  
	if (pModuleName == 0)
	{  
		return FALSE;
	}
	else
	{
		WCHAR szFileName[_MAX_FNAME] = L"";
		_wsplitpath (pModuleName, NULL, NULL, szFileName, NULL);

		if (wcsicmp (szFileName, L"ntdll") == 0)
			return TRUE;  

		return FALSE;  
	}
}

static inline BOOL CALLBACK
MiniDumpCallback (PVOID pParam, const PMINIDUMP_CALLBACK_INPUT pInput, PMINIDUMP_CALLBACK_OUTPUT pOutput)  
{  
	if (pInput == 0 || pOutput == 0)
		return FALSE;

	switch (pInput->CallbackType)
	{
	case ModuleCallback:
		if (pOutput->ModuleWriteFlags & ModuleWriteDataSeg)
		{
			if (!IsDataSectionNeeded (pInput->Module.FullPath))
				pOutput->ModuleWriteFlags &= (~ModuleWriteDataSeg);
		}
	case IncludeModuleCallback:
	case IncludeThreadCallback:
	case ThreadCallback:
	case ThreadExCallback:
		return TRUE;
	default:
		;
	}

	return FALSE;
}

static inline void
CreateMiniDump (PEXCEPTION_POINTERS pep, const char *strFileName)
{  
	typedef BOOL  (WINAPI* lpMiniDumpWriteDump) (
		__in          HANDLE hProcess,
		__in          DWORD ProcessId,
		__in          HANDLE hFile,
		__in          MINIDUMP_TYPE DumpType,
		__in          PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
		__in          PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		__in          PMINIDUMP_CALLBACK_INFORMATION CallbackParam
	);

	lpMiniDumpWriteDump MiniDumpWriteDump;
	HINSTANCE hDbgHelp;
	HANDLE hFile;

	hDbgHelp = loadSystemDll ("dbghelp.dll");
	if (hDbgHelp == NULL)
		return;

    MiniDumpWriteDump = (lpMiniDumpWriteDump) GetProcAddress (hDbgHelp, "MiniDumpWriteDump");
	if (MiniDumpWriteDump == NULL)
		return;

	hFile = CreateFileA (strFileName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
	{
		MINIDUMP_EXCEPTION_INFORMATION mdei;
		MINIDUMP_CALLBACK_INFORMATION mci;

		mdei.ThreadId           = GetCurrentThreadId ();
		mdei.ExceptionPointers  = pep;
		mdei.ClientPointers     = FALSE;

		mci.CallbackRoutine     = (MINIDUMP_CALLBACK_ROUTINE) MiniDumpCallback;
		mci.CallbackParam       = 0;

		MiniDumpWriteDump (GetCurrentProcess (), GetCurrentProcessId (), hFile, MiniDumpNormal,
				(pep != 0) ? &mdei : 0, NULL, &mci);

		CloseHandle (hFile);
	}
}

static char *globalDumpFileName = NULL;

static LONG __stdcall
MyUnhandledExceptionFilter (PEXCEPTION_POINTERS pExceptionInfo)
{
	if (globalDumpFileName && strlen (globalDumpFileName) > 0)
		CreateMiniDump (pExceptionInfo, globalDumpFileName);

	return EXCEPTION_EXECUTE_HANDLER;
}

void
enableMiniDump (const char *dumpFileName)
{
	if (dumpFileName && strlen (dumpFileName) > 0)
	{
		globalDumpFileName = (char *) malloc (strlen (dumpFileName) + 1); // dumpFileName;
		strcpy (globalDumpFileName, dumpFileName);
	}

	// 注册异常处理函数
	SetUnhandledExceptionFilter (MyUnhandledExceptionFilter);
}

bool
win_wfp_init_funcs (void)
{
	/* Initialize all WFP-related function pointers */
	HMODULE iphlpapiHandle;
	HMODULE fwpuclntHandle;

	iphlpapiHandle = LoadLibraryA ("iphlpapi.dll");
	if (iphlpapiHandle == NULL)
	{
		msg (M_NONFATAL, "Can't load iphlpapi.dll");
		return false;
	}

	fwpuclntHandle = LoadLibraryA ("fwpuclnt.dll");
	if (fwpuclntHandle == NULL)
	{
		msg (M_NONFATAL, "Can't load fwpuclnt.dll");
		return false;
	}

	ConvertInterfaceIndexToLuid_ = (func_ConvertInterfaceIndexToLuid) GetProcAddress (iphlpapiHandle, "ConvertInterfaceIndexToLuid");
	FwpmFilterAdd0 = (func_FwpmFilterAdd0) GetProcAddress (fwpuclntHandle, "FwpmFilterAdd0");
	FwpmEngineOpen0 = (func_FwpmEngineOpen0) GetProcAddress (fwpuclntHandle, "FwpmEngineOpen0");
	FwpmEngineClose0 = (func_FwpmEngineClose0) GetProcAddress (fwpuclntHandle, "FwpmEngineClose0");
	FwpmSubLayerAdd0 = (func_FwpmSubLayerAdd0) GetProcAddress (fwpuclntHandle, "FwpmSubLayerAdd0");
	FwpmSubLayerDeleteByKey0 = (func_FwpmSubLayerDeleteByKey0) GetProcAddress (fwpuclntHandle, "FwpmSubLayerDeleteByKey0");
	FwpmFreeMemory0 = (func_FwpmFreeMemory0) GetProcAddress (fwpuclntHandle, "FwpmFreeMemory0");
	FwpmGetAppIdFromFileName0 = (func_FwpmGetAppIdFromFileName0) GetProcAddress (fwpuclntHandle, "FwpmGetAppIdFromFileName0");
	FwpmSubLayerGetByKey0 = (func_FwpmSubLayerGetByKey0) GetProcAddress (fwpuclntHandle, "FwpmSubLayerGetByKey0");

	if (!ConvertInterfaceIndexToLuid_ ||
		!FwpmFilterAdd0 ||
		!FwpmEngineOpen0 ||
		!FwpmEngineClose0 ||
		!FwpmSubLayerAdd0 ||
		!FwpmSubLayerDeleteByKey0 ||
		!FwpmFreeMemory0 ||
		!FwpmSubLayerGetByKey0 ||
		!FwpmGetAppIdFromFileName0)
	{
		msg (M_NONFATAL, "Can't get address for all WFP-related procedures.");
		return false;
	}

	return true;
}

/* UUID of WFP sublayer used by all instances of openvpn
2f660d7e-6a37-11e6-a181-001e8c6e04a2 */
DEFINE_GUID (
	OPENVPN_BLOCK_OUTSIDE_DNS_SUBLAYER,
	0x2f660d7e,
	0x6a37,
	0x11e6,
	0xa1, 0x81, 0x00, 0x1e, 0x8c, 0x6e, 0x04, 0xa2
);

/*
* Add a persistent sublayer with specified uuid
*/
static DWORD
add_sublayer (GUID uuid)
{
	FWPM_SESSION0 session;
	HANDLE engine = NULL;
	DWORD err = 0;
	FWPM_SUBLAYER0 sublayer;

	CLEAR (session);
	CLEAR (sublayer);

	err = FwpmEngineOpen0 (NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (err != ERROR_SUCCESS)
		goto out;

	sublayer.subLayerKey = uuid;
	sublayer.displayData.name = FIREWALL_NAME;
	sublayer.displayData.description = FIREWALL_NAME;
	sublayer.flags = 0;
	sublayer.weight = 0x100;

	/* Add sublayer to the session */
	err = FwpmSubLayerAdd0 (engine, &sublayer, NULL);

out:
	if (engine)
		FwpmEngineClose0 (engine);
	return err;
}

bool
win_wfp_add_filter (HANDLE engineHandle, const FWPM_FILTER0 *filter, PSECURITY_DESCRIPTOR sd, UINT64 *id)
{
	if (FwpmFilterAdd0 (engineHandle, filter, sd, id) != ERROR_SUCCESS)
	{
		msg (M_NONFATAL, "Can't add WFP filter");
		return false;
	}
	return true;
}

bool
win_wfp_block_dns (const NET_IFINDEX index)
{
	FWPM_SESSION0 session = { 0x0 };
	FWPM_SUBLAYER0 *sublayer_ptr = NULL;
	NET_LUID tapluid;
	UINT64 filterid;
	WCHAR openvpnpath[MAX_PATH];
	FWP_BYTE_BLOB *openvpnblob = NULL;
	FWPM_FILTER0 Filter = { 0x0 };
	FWPM_FILTER_CONDITION0 Condition[2] = { 0x0 };
	DWORD status;

	/* Add temporary filters which don't survive reboots or crashes. */
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	dmsg (D_LOW, "Opening WFP engine");

	if (FwpmEngineOpen0 (NULL, RPC_C_AUTHN_WINNT, NULL, &session, &m_hEngineHandle) != ERROR_SUCCESS)
	{
		msg (M_NONFATAL, "Can't open WFP engine");
		return false;
	}

	/* Check sublayer exists and add one if it does not. */
	if (FwpmSubLayerGetByKey0 (m_hEngineHandle, &OPENVPN_BLOCK_OUTSIDE_DNS_SUBLAYER, &sublayer_ptr) == ERROR_SUCCESS)
	{
		msg (D_LOW, "Retrieved existing sublayer");
		FwpmFreeMemory0 ((void **) &sublayer_ptr);
	}
	else
	{
		/* Add a new sublayer -- as another process may add it in the meantime,
		 do not treat "already exists" as an error */
		status = add_sublayer (OPENVPN_BLOCK_OUTSIDE_DNS_SUBLAYER);

		if (status == FWP_E_ALREADY_EXISTS || status == ERROR_SUCCESS)
			msg (D_LOW, "Added a persistent sublayer with pre-defined UUID");
		else
		{
			msg (M_NONFATAL, "Failed to add persistent sublayer (status = %lu)", status);
			goto err;
		}
	}

	dmsg (M_INFO, "Blocking DNS using WFP");
	if (ConvertInterfaceIndexToLuid (index, &tapluid) != NO_ERROR)
	{
		msg (M_NONFATAL, "Can't convert interface index to LUID");
		goto err;
	}
	dmsg (D_LOW, "Tap Luid: %I64d", tapluid.Value);

	/* Get OpenVPN path. */
	status = GetModuleFileNameW (NULL, openvpnpath, _countof (openvpnpath));
	if (status == 0 || status == _countof (openvpnpath))
	{
		msg (M_WARN|M_ERRNO, "block_dns: failed to get executable path");
		goto err;
	}

	if (FwpmGetAppIdFromFileName0 (openvpnpath, &openvpnblob) != ERROR_SUCCESS)
		goto err;

	/* Prepare filter. */
	Filter.subLayerKey = OPENVPN_BLOCK_OUTSIDE_DNS_SUBLAYER;
	Filter.displayData.name = FIREWALL_NAME;
	Filter.weight.type = FWP_UINT8;
	Filter.weight.uint8 = 0xF;
	Filter.filterCondition = Condition;
	Filter.numFilterConditions = 2;

	/* First filter. Permit IPv4 DNS queries from OpenVPN itself. */
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	Filter.action.type = FWP_ACTION_PERMIT;

	Condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	Condition[0].matchType = FWP_MATCH_EQUAL;
	Condition[0].conditionValue.type = FWP_UINT16;
	Condition[0].conditionValue.uint16 = 53;

	Condition[1].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	Condition[1].matchType = FWP_MATCH_EQUAL;
	Condition[1].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	Condition[1].conditionValue.byteBlob = openvpnblob;

	/* Add filter condition to our interface. */
	if (!win_wfp_add_filter (m_hEngineHandle, &Filter, NULL, &filterid))
		goto err;
	dmsg (D_LOW, "Filter (Permit OpenVPN IPv4 DNS) added with ID=%I64d", filterid);

	/* Second filter. Permit IPv6 DNS queries from OpenVPN itself. */
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

	/* Add filter condition to our interface. */
	if (!win_wfp_add_filter (m_hEngineHandle, &Filter, NULL, &filterid))
		goto err;
	dmsg (D_LOW, "Filter (Permit OpenVPN IPv6 DNS) added with ID=%I64d", filterid);

	/* Third filter. Block all IPv4 DNS queries. */
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	Filter.action.type = FWP_ACTION_BLOCK;
	Filter.weight.type = FWP_EMPTY;
	Filter.numFilterConditions = 1;

	if (!win_wfp_add_filter (m_hEngineHandle, &Filter, NULL, &filterid))
		goto err;
	dmsg (D_LOW, "Filter (Block IPv4 DNS) added with ID=%I64d", filterid);

	/* Forth filter. Block all IPv6 DNS queries. */
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

	if (!win_wfp_add_filter (m_hEngineHandle, &Filter, NULL, &filterid))
		goto err;
	dmsg (D_LOW, "Filter (Block IPv6 DNS) added with ID=%I64d", filterid);

	/* Fifth filter. Permit IPv4 DNS queries from TAP.
	 * Use a non-zero weight so that the permit filters get higher priority
	 * over the block filter added with automatic weighting */

	Filter.weight.type = FWP_UINT8;
	Filter.weight.uint8 = 0xE;
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	Filter.action.type = FWP_ACTION_PERMIT;
	Filter.numFilterConditions = 2;

	Condition[1].fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
	Condition[1].matchType = FWP_MATCH_EQUAL;
	Condition[1].conditionValue.type = FWP_UINT64;
	Condition[1].conditionValue.uint64 = &tapluid.Value;

	/* Add filter condition to our interface. */
	if (!win_wfp_add_filter (m_hEngineHandle, &Filter, NULL, &filterid))
		goto err;
	dmsg (D_LOW, "Filter (Permit IPv4 DNS queries from TAP) added with ID=%I64d", filterid);

	/* Sixth filter. Permit IPv6 DNS queries from TAP.
	* Use same weight as IPv4 filter */
	Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

	/* Add filter condition to our interface. */
	if (!win_wfp_add_filter (m_hEngineHandle, &Filter, NULL, &filterid))
		goto err;
	dmsg (D_LOW, "Filter (Permit IPv6 DNS queries from TAP) added with ID=%I64d", filterid);

	FwpmFreeMemory0 ((void **) &openvpnblob);
	return true;

err:
	if (openvpnblob)
		FwpmFreeMemory0 ((void **) &openvpnblob);
	if (m_hEngineHandle)
	{
		FwpmEngineClose0 (m_hEngineHandle);
		m_hEngineHandle = NULL;
	}

	return false;
}

bool
win_wfp_uninit (void)
{
	dmsg (D_LOW, "Uninitializing WFP");
	if (m_hEngineHandle)
	{
		FwpmEngineClose0 (m_hEngineHandle);
		m_hEngineHandle = NULL;
	}
	return true;
}

int
win32_version_info (void)
{
	if (!IsWindowsXPOrGreater ())
		msg (M_FATAL, "Error: Windows version must be XP or greater.");

	if (!IsWindowsVistaOrGreater ())
		return WIN_XP;

	if (!IsWindows7OrGreater ())
		return WIN_VISTA;

	if (!IsWindows8OrGreater ())
		return WIN_7;

	if (!IsWindows8Point1OrGreater())
		return WIN_8;

	if (!IsWindows1OrGreater ())
		return WIN_8_1;
	else
		return WIN_10;
}

bool
win32_is_64bit (void)
{
#if defined(_WIN64)
	return true;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
	// 32-bit programs run on both 32-bit and 64-bit Windows
	BOOL f64 = FALSE;
	return IsWow64Process (GetCurrentProcess (), &f64) && f64;
#else
	return false; // Win64 does not support Win16
#endif
}

const char *
win32_version_string (struct gc_arena *gc, bool add_name)
{
	struct buffer out = alloc_buf_gc (256, gc);
	int version = win32_version_info ();

	switch (version)
	{
	case WIN_XP:
		buf_printf (&out, "5.1%s", add_name ? " (Windows XP)" : "");
		break;
	case WIN_VISTA:
		buf_printf (&out, "6.0%s", add_name ? " (Windows Vista)" : "");
		break;
	case WIN_7:
		buf_printf (&out, "6.1%s", add_name ? " (Windows 7)" : "");
		break;
	case WIN_8:
		buf_printf (&out, "6.2%s", add_name ? " (Windows 8 or greater)" : "");
		break;
	case WIN_8_1:
		buf_printf (&out, "6.3%s", add_name ? " (Windows 8.1 or greater)" : "");
		break;
	case WIN_10:
		buf_printf (&out, "10.0%s", add_name ? " (Windows 10 or greater)" : "");
		break;
	default:
		msg (M_NONFATAL, "Unknown Windows version: %d", version);
		buf_printf (&out, "0.0%s", add_name ? " (unknown)" : "");
		break;
	}

    buf_printf (&out, win32_is_64bit () ? " 64bit" : " 32bit");

	return BSTR (&out);
}

#endif
