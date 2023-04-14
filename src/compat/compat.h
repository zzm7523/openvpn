/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2011 - David Sommerseth <davids@redhat.com>
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

#ifndef COMPAT_H
#define COMPAT_H

/* 重新定义NTDDI_VERSION到NTDDI_WINXP */
//#undef NTDDI_VERSION
//#define NTDDI_VERSION NTDDI_WINXP
//#undef _WIN32_WINNT
//#define _WIN32_WINNT _WIN32_WINNT_WINXP

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_DIRNAME
char * dirname (char *str);
#endif /* HAVE_DIRNAME */

#ifndef HAVE_BASENAME
char * basename (char *str);
#endif /* HAVE_BASENAME */

#ifndef HAVE_GETTIMEOFDAY
int gettimeofday (struct timeval *tv, void *tz);
#endif

#ifndef HAVE_DAEMON
int daemon (int nochdir, int noclose);
#endif

/* XP 没有inet_ntop函数 */
#ifdef WIN32
#if _WIN32_WINNT <= _WIN32_WINNT_WINXP 
#undef HAVE_INET_NTOP
#endif
#endif
#ifndef HAVE_INET_NTOP
const char * inet_ntop (int af, const void *src, char *dst, socklen_t size);
#endif

/* XP 没有inet_pton函数 */
#ifdef WIN32
#if _WIN32_WINNT <= _WIN32_WINNT_WINXP 
#undef HAVE_INET_PTON
#endif
#endif
#ifndef HAVE_INET_PTON
int inet_pton (int af, const char *src, void *dst);
#endif

#ifdef __cplusplus
}
#endif

#endif /* COMPAT_H */
