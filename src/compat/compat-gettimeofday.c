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

#ifndef HAVE_GETTIMEOFDAY

#include "compat.h"

#ifdef WIN32

#include <windows.h>
#include <time.h>

/* Offset between 1/1/1601 and 1/1/1970 in 100 nanosec units */
#define _W32_FT_OFFSET (116444736000000000ULL)

int
gettimeofday (struct timeval *tp, void *tz)
{
	union
	{
		unsigned long long ns100; /*time since 1 Jan 1601 in 100ns units */
		FILETIME ft;
	} _now;

	if (tp)
	{
		GetSystemTimeAsFileTime (&_now.ft);
		tp->tv_usec = (long) ((_now.ns100 / 10ULL) % 1000000ULL);
		tp->tv_sec  = (long) ((_now.ns100 - _W32_FT_OFFSET) / 10000000ULL);
	}

	/* Always return 0 as per Open Group Base Specifications Issue 6. Do not set errno on error.  */
	return 0;
}

#else

#ifdef HAVE_TIME_H
#include <time.h>
#endif

int
gettimeofday (struct timeval *tv, void *tz)
{
	struct timeb tb;
	ftime (&tb);

	tv->tv_sec = tb.time;
	tv->tv_usec = tb.millitm * 1000;
	return 0;
}

#endif /* WIN32 */

#endif /* HAVE_GETTIMEOFDAY */
