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

/*
 * The interval_ routines are designed to optimize the calling of a routine
 * (normally tls_multi_process()) which can be called less frequently
 * between triggers.
 */

#ifndef PERF_H
#define PERF_H

#include "basic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ENABLE_PERFORMANCE_METRICS

/*
 * Metrics
 */
#define PERF_BIO_READ_PLAINTEXT     0
#define PERF_BIO_WRITE_PLAINTEXT    1
#define PERF_BIO_READ_CIPHERTEXT    2
#define PERF_BIO_WRITE_CIPHERTEXT   3
#define PERF_TLS_MULTI_PROCESS      4
#define PERF_IO_WAIT                5
#define PERF_EVENT_LOOP             6
#define PERF_MULTI_CREATE_INSTANCE  7
#define PERF_MULTI_CLOSE_INSTANCE   8
#define PERF_MULTI_SHOW_STATS       9
#define PERF_MULTI_BCAST            10
#define PERF_MULTI_MCAST            11
#define PERF_SCRIPT                 12
#define PERF_READ_IN_LINK           13
#define PERF_PROC_IN_LINK           14
#define PERF_READ_IN_TUN            15
#define PERF_PROC_IN_TUN            16
#define PERF_PROC_OUT_LINK          17
#define PERF_PROC_OUT_TUN           18
#define PERF_PROC_OUT_TUN_MTCP      19
#define PERF_N                      20

#ifdef ENABLE_PERFORMANCE_METRICS

struct context;

/*
 * Stack size
 */
#define STACK_N               64

void perf_push (int type);
void perf_pop (void);
void perf_output_results (void);

#else

static inline void perf_push (int type) {}
static inline void perf_pop (void) {}
static inline void perf_output_results (void) {}

#endif

#ifdef PERF_STATS_CHECK
void print_perf_status (const struct context *c, int thread_idx);
#endif

#ifdef __cplusplus
}
#endif

#endif
