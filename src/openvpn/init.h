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

#ifndef INIT_H
#define INIT_H

#include "openvpn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Baseline maximum number of events to wait for. */
#define BASE_N_EVENTS (4 + 1)

void context_clear (struct context *c);
void context_clear_1 (struct context *c);
void context_clear_2 (struct context *c);
void context_init_1 (struct context *c);
void context_clear_all_except_first_time (struct context *c);

bool init_static (void);

void uninit_static (void);

#define IVM_LEVEL_1 (1<<0) 
#define IVM_LEVEL_2 (1<<1)

void init_verb_mute (struct context *c, unsigned int flags);

void init_options_dev (struct options *options);

bool print_openssl_info (const struct options *options);

bool do_genkey (const struct options *options);

bool do_persist_tuntap (const struct options *options);

bool possibly_become_daemon (const struct options *options);

void pre_setup (const struct options *options);

void init_instance_handle_signals (struct context *c, const struct env_set *env, const unsigned int flags);

void init_instance (struct context *c, const struct env_set *env, const unsigned int flags);

/* Query for private key and auth-user-pass username/passwords. */
void init_query_passwords (const struct context *c);

void do_route (const struct options *options, struct route_list *route_list,
		struct route_ipv6_list *route_ipv6_list, const struct tuntap *tt,
		const struct plugin_list *plugins, struct env_set *es);

void do_compute_occ_strings (struct context *c);

void close_instance (struct context *c);

bool do_test_crypto (const struct options *o);

void context_gc_free (struct context *c);

void do_up (struct context *c, bool pulled_options, unsigned int option_types_found);

unsigned int pull_permission_mask (const struct context *c);

void do_uid_gid_chroot (struct context *c, bool no_delay);

const char *format_common_name (struct context *c, struct gc_arena *gc);

void reset_coarse_timers (struct context *c);

void do_deferred_options (struct context *c, const unsigned int found);

void inherit_context_child (struct context *dest, const struct context *src);

void inherit_context_top (struct context *dest, const struct context *src);

#define CC_GC_FREE          (1<<0)
#define CC_USR1_TO_HUP      (1<<1)
#define CC_HARD_USR1_TO_HUP (1<<2)
#define CC_NO_CLOSE         (1<<3)

void close_context (struct context *c, int sig, unsigned int flags);

struct context_buffers *init_context_buffers (struct context *c);

void free_context_buffers (struct context_buffers *cb);

#ifdef ENABLE_MANAGEMENT

void init_management (struct context *c);
bool open_management (struct context *c);
void close_management (void);

void management_show_net_callback (void *arg, const int msglevel);

#endif

void init_management_callback_p2p (struct context *c);
void uninit_management_callback (void);

#ifdef ENABLE_PLUGIN
void init_plugins (struct context *c);
void open_plugins (struct context *c, const bool import_options, int init_point);
#endif

#ifdef ENABLE_GUOMI
void do_test_encrypt_device (struct context *c);
bool init_encrypt_devices (struct context *c);
void uninit_encrypt_devices (void);
#endif

#ifdef __cplusplus
}
#endif

#endif
