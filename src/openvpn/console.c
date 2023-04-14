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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "console.h"
#include "error.h"
#include "buffer.h"
#include "misc.h"
#include "openvpn.h"

#include "memdbg.h"

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef WIN32

#include "win32.h"

/* 定义特殊字符串, 代表用户放弃输入 */
#define USER_CANCEL_INPUT	"-------USER-CANCEL-INPUT-------"

/*
 * Get input from console.
 *
 * Return false on input error, or if service exit event is signaled.
 */

static bool
get_console_input_win32 (const char *prompt, const bool echo, char *input, const int capacity)
{
	HANDLE in = INVALID_HANDLE_VALUE;
	HANDLE err = INVALID_HANDLE_VALUE;
	DWORD len = 0;

	ASSERT (prompt && input && capacity > 0);

	input[0] = '\0';

	in = GetStdHandle (STD_INPUT_HANDLE);
	err = get_orig_stderr ();

	if (in != INVALID_HANDLE_VALUE && err != INVALID_HANDLE_VALUE
			&& !win32_service_interrupt (&win32_signal)
			&& WriteFile (err, prompt, (DWORD) strlen (prompt), &len, NULL))
	{
		bool is_console = (GetFileType (in) == FILE_TYPE_CHAR);
		DWORD flags_save = 0;
		WCHAR *winput;
		int status = 0;

		if (is_console)
		{
			if (GetConsoleMode (in, &flags_save))
			{
				DWORD flags = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
				if (echo)
					flags |= ENABLE_ECHO_INPUT;
				SetConsoleMode (in, flags);
			}
			else
				is_console = 0;
		}

		if (is_console)
		{
			winput = (WCHAR *) malloc (capacity * sizeof (WCHAR));
			if (winput == NULL)
				return false;

			status = ReadConsoleW (in, winput, capacity, &len, NULL);
#ifdef _DEBUG
			if (!status)
				fprintf (stdout, "ReadConsoleW (...) error, error_no=%d\n", GetLastError ());
#endif
			WideCharToMultiByte (CP_UTF8, 0, winput, len, input, capacity, NULL, NULL);
			free (winput);
		}
		else
		{
			status = ReadFile (in, input, capacity, &len, NULL);
#ifdef _DEBUG
			if (!status)
				fprintf (stdout, "ReadFile (...) error, error_no=%d\n", GetLastError ());
#endif
		}

		string_null_terminate (input, (int) len, capacity);
		chomp (input);

		if (!echo)
			WriteFile (err, "\r\n", 2, &len, NULL);
		if (is_console)
			SetConsoleMode (in, flags_save);
		if (status && !win32_service_interrupt (&win32_signal) && strcmp (input, USER_CANCEL_INPUT) != 0)
			return true;
	}

	return false;
}

#endif

static FILE*
open_tty (const bool write)
{
	FILE *ret;
	ret = fopen ("/dev/tty", write ? "w" : "r");
	if (!ret)
		ret = write ? stderr : stdin;
	return ret;
}

static void
close_tty (FILE *fp)
{
	if (fp != stderr && fp != stdin)
		fclose (fp);
}

#if !defined(WIN32) /*&& !defined(HAVE_GETPASS)*/

#include <termios.h>

#define MAX_STRING_LEN 512

static char*
get_password (const char *prompt)
{
	struct termios attr;
	static char password[MAX_STRING_LEN];
	int n = 0;

	fputs (prompt, stderr);
	fflush (stderr);

	if (tcgetattr (STDIN_FILENO, &attr) != 0)
		return NULL;
	attr.c_lflag &= ~(ECHO);

	if (tcsetattr (STDIN_FILENO, TCSAFLUSH, &attr) != 0)
		return NULL;
	while ((password[n] = getchar ()) != '\n')
	{
		if (n < sizeof (password) - 1 && password[n] >= ' ' && password[n] <= '~')
		{
			n++;
		}
		else
		{
			fprintf (stderr,"\n");
			fputs (prompt, stderr);
			fflush (stderr);
			n = 0;
		}
	}

	password[n] = '\0';
	printf ("\n");
	if (n > (MAX_STRING_LEN - 1))
	{
		password[MAX_STRING_LEN - 1] = '\0';
	}

	attr.c_lflag |= ECHO;
	tcsetattr (STDIN_FILENO, TCSANOW, &attr);
	return (char*) &password;
}

#endif

#ifdef ENABLE_SYSTEMD

/* is systemd running */

static bool
check_systemd_running (void)
{
	struct stat c;

	/* We simply test whether the systemd cgroup hierarchy is mounted,
	 * as well as the systemd-ask-password executable being available
	 */

	return (sd_booted() > 0) && (stat (SYSTEMD_ASK_PASSWORD_PATH, &c) == 0);
}

static bool
get_console_input_systemd (const char *prompt, const bool echo, char *input, const int capacity)
{
	int std_out;
	bool ret = false;
	struct argv argv;

	argv_init (&argv);
	argv_printf (&argv, SYSTEMD_ASK_PASSWORD_PATH);
	argv_printf_cat (&argv, "%s", prompt);

	if ((std_out = openvpn_popen (&argv, NULL)) < 0)
	{
		return false;
	}

	memset (input, 0, capacity);
	if (read (std_out, input, capacity - 1) > 0)
	{
		chomp (input);
		ret = true;
	}
	close (std_out);

	argv_reset (&argv);

	return ret;
}

#endif

/* Get input from console */
bool
get_console_input (const char *prompt, const bool echo, char *input, const int capacity)
{
	bool ret = false;
	ASSERT (prompt);
	ASSERT (input);
	ASSERT (capacity > 0);
	input[0] = '\0';

#if defined(WIN32)
	return get_console_input_win32 (prompt, echo, input, capacity);
#else
#ifdef ENABLE_SYSTEMD
	if (check_systemd_running ())
		return get_console_input_systemd (prompt, echo, input, capacity);
#endif

	if (global_context->options.integration)
	{
		fprintf (stderr, "%s", prompt);
		fflush (stderr);

		if (fgets (input, capacity, stdin) != NULL)
		{
			chomp (input);
			ret = true;
		}
	}
	else
	{
		/* did we --daemon'ize before asking for passwords?
		 * (in which case neither stdin or stderr are connected to a tty and /dev/tty can not be open()ed anymore)
		 */
		if (!isatty (0) && !isatty (2))
		{
			int fd = open ("/dev/tty", O_RDWR);
			if (fd < 0)
			{
				msg (M_FATAL,
					"neither stdin nor stderr are a tty device and you have neither a controlling tty nor systemd - can't ask for '%s'.  If you used --daemon, you need to use --askpass to make passphrase-protected keys work, and you can not use --auth-nocache.", prompt);
			}
			close (fd);
		}


		if (echo)
		{
			FILE *fp = open_tty (true);
			fprintf (fp, "%s", prompt);
			fflush (fp);
			close_tty (fp);

			fp = open_tty (false);
			if (fgets (input, capacity, fp) != NULL)
			{
				chomp (input);
				ret = true;
			}
			close_tty (fp);
		}
		else
		{
			char *gp = get_password (prompt);
			if (gp)
			{
				strncpynt (input, gp, capacity);
				memset (gp, 0, strlen (gp));
				ret = true;
			}
		}
	}

	return ret;	
#endif
}
