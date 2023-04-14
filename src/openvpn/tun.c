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
 * Support routines for configuring and accessing TUN/TAP
 * virtual network adapters.
 *
 * This file is based on the TUN/TAP driver interface routines
 * from VTun by Maxim Krasnyansky <max_mk@yahoo.com>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "gremlin.h"
#include "fdmisc.h"
#include "common.h"
#include "misc.h"
#include "manage.h"
#include "route.h"
#include "win32.h"

#include "socket.h"
#include "packet_buffer.h"
#include "socket-inline.h"
#include "thread.h"
#include "multi_crypto.h"
#include "multi.h"
#include "tun.h"
#include "tun-inline.h"

#ifdef WIN32
#include <sys/timeb.h>

#ifdef HAVE_VERSIONHELPERS_H
#include <versionhelpers.h>
#else
#include "compat-versionhelpers.h"
#endif
#endif

#include <openssl/err.h>

#include "memdbg.h"

#ifdef WIN32

/* #define SIMULATE_DHCP_FAILED */       /* simulate bad DHCP negotiation */

#define NI_TEST_FIRST  (1<<0)
#define NI_IP_NETMASK  (1<<1)
#define NI_OPTIONS     (1<<2)

static void netsh_ifconfig (const struct tuntap_options *to, const char *flex_name, const in_addr_t ip,
		const in_addr_t netmask, const unsigned int flags);
static void netsh_command (const struct argv *a, int n, int msglevel);

static const char *netsh_get_id (const char *dev_node, struct gc_arena *gc);

static void init_ip_addr_string2 (IP_ADDR_STRING *dest, const IP_ADDR_STRING *src1, const IP_ADDR_STRING *src2);


/*
* Given an adapter index, return true if the adapter is DHCP disabled.
*/

#define DHCP_STATUS_UNDEF     0
#define DHCP_STATUS_ENABLED   1
#define DHCP_STATUS_DISABLED  2

static int
dhcp_status (DWORD index)
{
	struct gc_arena gc = gc_new ();
	int ret = DHCP_STATUS_UNDEF;

	if (index != TUN_ADAPTER_INDEX_INVALID)
	{
		const IP_ADAPTER_INFO *ai = get_adapter_info (index, &gc);
		if (ai)
		{
			if (ai->DhcpEnabled)
				ret = DHCP_STATUS_ENABLED;
			else
				ret = DHCP_STATUS_DISABLED;
		}
	}

	gc_free (&gc);
	return ret;
}

#endif

static void clear_tuntap (struct tuntap *tuntap);

bool
is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
	ASSERT (match_type);
	if (!dev)
		return false;
	if (dev_type)
		return !strcmp (dev_type, match_type);
	else
		return !strncmp (dev, match_type, strlen (match_type));
}

int
dev_type_enum (const char *dev, const char *dev_type)
{
	if (is_dev_type (dev, dev_type, "tun"))
		return DEV_TYPE_TUN;
	else if (is_dev_type (dev, dev_type, "tap"))
		return DEV_TYPE_TAP;
	else if (is_dev_type (dev, dev_type, "null"))
		return DEV_TYPE_NULL;
	else
		return DEV_TYPE_UNDEF;
}

const char *
dev_type_string (const char *dev, const char *dev_type)
{
	switch (dev_type_enum (dev, dev_type))
	{
	case DEV_TYPE_TUN:
		return "tun";
	case DEV_TYPE_TAP:
		return "tap";
	case DEV_TYPE_NULL:
		return "null";
	default:
		return "[unknown-dev-type]";
	}
}

/*
 * Try to predict the actual TUN/TAP device instance name, before the device is actually opened.
 */
const char *
guess_tuntap_dev (const char *dev, const char *dev_type,
		const char *dev_node, struct gc_arena *gc)
{
#ifdef WIN32
	const int dt = dev_type_enum (dev, dev_type);
	if (dt == DEV_TYPE_TUN || dt == DEV_TYPE_TAP)
	{
		return netsh_get_id (dev_node, gc);
	}
#endif

	/* default case */
	return dev;
}


/* --ifconfig-nowarn disables some options sanity checking */
static const char ifconfig_warn_how_to_silence[] = "(silence this warning with --ifconfig-nowarn)";

/*
 * If !tun, make sure ifconfig_remote_netmask looks like a netmask.
 *
 * If tun, make sure ifconfig_remote_netmask looks like an IPv4 address.
 */
static void
ifconfig_sanity_check (bool tun, in_addr_t addr, int topology)
{
	struct gc_arena gc = gc_new ();
	const bool looks_like_netmask = ((addr & 0xFF000000) == 0xFF000000);
	if (tun)
	{
		if (looks_like_netmask && (topology == TOP_NET30 || topology == TOP_P2P))
			msg (M_WARN,
				"WARNING: Since you are using --dev tun with a point-to-point topology, the second argument to --ifconfig must be an IP address.  You are using something (%s) that looks more like a netmask. %s",
				print_in_addr_t (addr, 0, &gc),
				ifconfig_warn_how_to_silence);
	}
	else /* tap */
	{
		if (!looks_like_netmask)
			msg (M_WARN,
				"WARNING: Since you are using --dev tap, the second argument to --ifconfig must be a netmask, for example something like 255.255.255.0. %s",
				ifconfig_warn_how_to_silence);
	}
	gc_free (&gc);
}

/*
 * For TAP-style devices, generate a broadcast address.
 */
static in_addr_t
generate_ifconfig_broadcast_addr (in_addr_t local, in_addr_t netmask)
{
	return local | ~netmask;
}

/*
 * Check that --local and --remote addresses do not clash with ifconfig addresses or subnet.
 */
static void
check_addr_clash (const char *name, int type, in_addr_t __public, in_addr_t local, in_addr_t remote_netmask)
{
	struct gc_arena gc = gc_new ();

#if 0
	msg (M_INFO, "CHECK_ADDR_CLASH type=%d public=%s local=%s, remote_netmask=%s",
		type,
		print_in_addr_t (public, 0, &gc),
		print_in_addr_t (local, 0, &gc),
		print_in_addr_t (remote_netmask, 0, &gc));
#endif

	if (__public)
	{
		if (type == DEV_TYPE_TUN)
		{
			const in_addr_t test_netmask = 0xFFFFFF00;
			const in_addr_t public_net = __public & test_netmask;
			const in_addr_t local_net = local & test_netmask;
			const in_addr_t remote_net = remote_netmask & test_netmask;

			if (__public == local || __public == remote_netmask)
				msg (M_WARN,
					"WARNING: --%s address [%s] conflicts with --ifconfig address pair [%s, %s]. %s",
					name,
					print_in_addr_t (__public, 0, &gc),
					print_in_addr_t (local, 0, &gc),
					print_in_addr_t (remote_netmask, 0, &gc),
					ifconfig_warn_how_to_silence);

			if (public_net == local_net || public_net == remote_net)
				msg (M_WARN,
					"WARNING: potential conflict between --%s address [%s] and --ifconfig address pair [%s, %s] -- this is a warning only that is triggered when local/remote addresses exist within the same /24 subnet as --ifconfig endpoints. %s",
					name,
					print_in_addr_t (__public, 0, &gc),
					print_in_addr_t (local, 0, &gc),
					print_in_addr_t (remote_netmask, 0, &gc),
					ifconfig_warn_how_to_silence);
		}
		else if (type == DEV_TYPE_TAP)
		{
			const in_addr_t public_network = __public & remote_netmask;
			const in_addr_t virtual_network = local & remote_netmask;

			if (public_network == virtual_network)
				msg (M_WARN,
					"WARNING: --%s address [%s] conflicts with --ifconfig subnet [%s, %s] -- local and remote addresses cannot be inside of the --ifconfig subnet. %s",
					name,
					print_in_addr_t (__public, 0, &gc),
					print_in_addr_t (local, 0, &gc),
					print_in_addr_t (remote_netmask, 0, &gc),
					ifconfig_warn_how_to_silence);
		}
	}
	gc_free (&gc);
}

/*
 * Issue a warning if ip/netmask (on the virtual IP network) conflicts with
 * the settings on the local LAN.  This is designed to flag issues where
 * (for example) the OpenVPN server LAN is running on 192.168.1.x, but then
 * an OpenVPN client tries to connect from a public location that is also running
 * off of a router set to 192.168.1.x.
 */
void
check_subnet_conflict (const in_addr_t ip, const in_addr_t netmask, const char *prefix)
{
#if 0 /* too many false positives */
	struct gc_arena gc = gc_new ();
	in_addr_t lan_gw = 0;
	in_addr_t lan_netmask = 0;

	if (get_default_gateway (&lan_gw, &lan_netmask) && lan_netmask)
	{
		const in_addr_t lan_network = lan_gw & lan_netmask; 
		const in_addr_t network = ip & netmask;

		/* do the two subnets defined by network/netmask and lan_network/lan_netmask intersect? */
		if ((network & lan_netmask) == lan_network || (lan_network & netmask) == network)
		{
			msg (M_WARN, "WARNING: potential %s subnet conflict between local LAN [%s/%s] and remote VPN [%s/%s]",
				prefix,
				print_in_addr_t (lan_network, 0, &gc),
				print_in_addr_t (lan_netmask, 0, &gc),
				print_in_addr_t (network, 0, &gc),
				print_in_addr_t (netmask, 0, &gc));
		}
	}
	gc_free (&gc);
#endif
}

void
warn_on_use_of_common_subnets (void)
{
	struct gc_arena gc = gc_new ();
	struct route_gateway_info rgi;
	const int needed = (RGI_ADDR_DEFINED|RGI_NETMASK_DEFINED);

	get_default_gateway (&rgi);
	if ((rgi.flags & needed) == needed)
	{
		const in_addr_t lan_network = rgi.gateway.addr & rgi.gateway.netmask;
		if (lan_network == 0xC0A80000 || lan_network == 0xC0A80100)
			msg (M_WARN, "NOTE: your local LAN uses the extremely common subnet address 192.168.0.x or 192.168.1.x.  Be aware that this might create routing conflicts if you connect to the VPN server from public locations such as internet cafes that use the same subnet.");
	}
	gc_free (&gc);
}

/*
 * Return a string to be used for options compatibility check between peers.
 */
const char *
ifconfig_options_string (const struct tuntap* tt, bool remote, bool disable, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (256, gc);
	if (tt->did_ifconfig_setup && !disable)
	{
		if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
		{
			buf_printf (&out, "%s %s",
				print_in_addr_t (tt->local & tt->remote_netmask, 0, gc),
				print_in_addr_t (tt->remote_netmask, 0, gc));
		}
		else if (tt->type == DEV_TYPE_TUN)
		{
			const char *l, *r;
			if (remote)
			{
				r = print_in_addr_t (tt->local, 0, gc);
				l = print_in_addr_t (tt->remote_netmask, 0, gc);
			}
			else
			{
				l = print_in_addr_t (tt->local, 0, gc);
				r = print_in_addr_t (tt->remote_netmask, 0, gc);
			}
			buf_printf (&out, "%s %s", r, l);
		}
		else
			buf_printf (&out, "[undef]");
	}
	return BSTR (&out);
}

/*
 * Return a status string describing wait state.
 */
const char *
tun_stat (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (64, gc);
	if (tt)
	{
		if (rwflags & EVENT_READ)
		{
			buf_printf (&out, "T%s", (tt->rwflags_debug & EVENT_READ) ? "R" : "r");
#ifdef WIN32
			buf_printf (&out, "%s", overlapped_io_state_ascii (&tt->reads));
#endif
		}
		if (rwflags & EVENT_WRITE)
		{
			buf_printf (&out, "T%s", (tt->rwflags_debug & EVENT_WRITE) ? "W" : "w");
#ifdef WIN32
			buf_printf (&out, "%s", overlapped_io_state_ascii (&tt->writes));
#endif
		}
	}
	else
	{
		buf_printf (&out, "T?");
	}
	return BSTR (&out);
}

/*
 * Return true for point-to-point topology, false for subnet topology
 */
bool
is_tun_p2p (const struct tuntap *tt)
{
	bool tun = false;

	if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
		tun = false;
	else if (tt->type == DEV_TYPE_TUN)
		tun = true;
	else
		msg (M_FATAL, "Error: problem with tun vs. tap setting"); /* JYFIXME -- needs to be caught earlier, in init_tun? */

	return tun;
}

/*
 * Set the ifconfig_* environment variables, both for IPv4 and IPv6
 */
void
do_ifconfig_setenv (const struct tuntap *tt, struct env_set *es)
{
	struct gc_arena gc = gc_new ();
	const char *ifconfig_local = print_in_addr_t (tt->local, 0, &gc);
	const char *ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, 0, &gc);

	/* Set environmental variables with ifconfig parameters. */
	if (tt->did_ifconfig_setup)
	{
		bool tun = is_tun_p2p (tt);

		setenv_str (es, "ifconfig_local", ifconfig_local);
		if (tun)
		{
			setenv_str (es, "ifconfig_remote", ifconfig_remote_netmask);
		}
		else
		{
			const char *ifconfig_broadcast = print_in_addr_t (tt->broadcast, 0, &gc);
			setenv_str (es, "ifconfig_netmask", ifconfig_remote_netmask);
			setenv_str (es, "ifconfig_broadcast", ifconfig_broadcast);
		}
	}

	if (tt->did_ifconfig_ipv6_setup)
	{
		const char *ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);
		const char *ifconfig_ipv6_remote = print_in6_addr (tt->remote_ipv6, 0, &gc);

		setenv_str (es, "ifconfig_ipv6_local", ifconfig_ipv6_local);
		setenv_int (es, "ifconfig_ipv6_netbits", tt->netbits_ipv6);
		setenv_str (es, "ifconfig_ipv6_remote", ifconfig_ipv6_remote);
	}

	gc_free (&gc);
}

/*
 * Init tun/tap object.
 *
 * Set up tuntap structure for ifconfig, but don't execute yet.
 */
struct tuntap*	init_tun (const char *dev,       /* --dev option */
		const char *dev_type,  /* --dev-type option */
		int topology,          /* one of the TOP_x values */
		const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
		const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
		const char *ifconfig_ipv6_local_parm,     /* --ifconfig parm 1 IPv6 */
		int         ifconfig_ipv6_netbits_parm,
		const char *ifconfig_ipv6_remote_parm,    /* --ifconfig parm 2 IPv6 */
		in_addr_t local_public,
		in_addr_t remote_public,
		const bool strict_warn,
		struct env_set *es)
{
	struct gc_arena gc = gc_new ();
	struct tuntap *tt;

	ALLOC_OBJ (tt, struct tuntap);
	clear_tuntap (tt);

	tt->type = dev_type_enum (dev, dev_type);
	tt->topology = topology;

	if (ifconfig_local_parm && ifconfig_remote_netmask_parm)
	{
		/* We only handle TUN/TAP devices here, not --dev null devices. */
		bool tun = is_tun_p2p (tt);

		/* Convert arguments to binary IPv4 addresses. */
		tt->local = getaddr (
			GETADDR_RESOLVE
			| GETADDR_HOST_ORDER
			| GETADDR_FATAL_ON_SIGNAL
			| GETADDR_FATAL,
			ifconfig_local_parm,
			0,
			NULL,
			NULL);

		tt->remote_netmask = getaddr (
			(tun ? GETADDR_RESOLVE : 0)
			| GETADDR_HOST_ORDER
			| GETADDR_FATAL_ON_SIGNAL
			| GETADDR_FATAL,
			ifconfig_remote_netmask_parm,
			0,
			NULL,
			NULL);

		/* Look for common errors in --ifconfig parms */
		if (strict_warn)
		{
			ifconfig_sanity_check (tt->type == DEV_TYPE_TUN, tt->remote_netmask, tt->topology);

			/*
			 * If local_public or remote_public addresses are defined,
			 * make sure they do not clash with our virtual subnet.
			 */
			check_addr_clash ("local",
				tt->type,
				local_public,
				tt->local,
				tt->remote_netmask);

			check_addr_clash ("remote",
				tt->type,
				remote_public,
				tt->local,
				tt->remote_netmask);

			if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
				check_subnet_conflict (tt->local, tt->remote_netmask, "TUN/TAP adapter");
			else if (tt->type == DEV_TYPE_TUN)
				check_subnet_conflict (tt->local, IPV4_NETMASK_HOST, "TUN/TAP adapter");
		}

		/* If TAP-style interface, generate broadcast address. */
		if (!tun)
		{
			tt->broadcast = generate_ifconfig_broadcast_addr (tt->local, tt->remote_netmask);
		}


		tt->did_ifconfig_setup = true;
	}

	if (ifconfig_ipv6_local_parm && ifconfig_ipv6_remote_parm)
	{
		/* Convert arguments to binary IPv6 addresses. */
		if (inet_pton (AF_INET6, ifconfig_ipv6_local_parm, &tt->local_ipv6) != 1 ||
			inet_pton (AF_INET6, ifconfig_ipv6_remote_parm, &tt->remote_ipv6) != 1) 
		{
			msg (M_FATAL, "init_tun: problem converting IPv6 ifconfig addresses %s and %s to binary",
				ifconfig_ipv6_local_parm, ifconfig_ipv6_remote_parm);
		}
		tt->netbits_ipv6 = ifconfig_ipv6_netbits_parm;

		tt->did_ifconfig_ipv6_setup = true;
	}

	/* Set environmental variables with ifconfig parameters. */
	if (es)
		do_ifconfig_setenv (tt, es);

	gc_free (&gc);
	return tt;
}

/*
 * Platform specific tun initializations
 */
void
init_tun_post (struct tuntap *tt, const struct frame *frame, const struct tuntap_options *options)
{
	tt->options = *options;
#ifdef WIN32
	overlapped_io_init (&tt->reads, frame, FALSE, true);
	overlapped_io_init (&tt->writes, frame, TRUE, true);
	tt->rw_handle.read = tt->reads.overlapped.hEvent;
	tt->rw_handle.write = tt->writes.overlapped.hEvent;
	tt->adapter_index = TUN_ADAPTER_INDEX_INVALID;
#endif
}

#if defined(WIN32) || defined(TARGET_DARWIN)

/* some of the platforms will auto-add a "network route" pointing
 * to the interface on "ifconfig tunX 2001:db8::1/64", others need
 * an extra call to "route add..."
 * -> helper function to simplify code below
 */
void add_route_connected_v6_net (struct tuntap *tt, const struct env_set *es)
{
	struct route_ipv6 r6;

	r6.defined = true;
	r6.network = tt->local_ipv6;
	r6.netbits = tt->netbits_ipv6;
	r6.gateway = tt->local_ipv6;
	r6.metric  = 0;			/* connected route */
	r6.metric_defined = true;
	add_route_ipv6 (&r6, tt, 0, es);
}

void delete_route_connected_v6_net (struct tuntap *tt, const struct env_set *es)
{
	struct route_ipv6 r6;

	r6.defined = true;
	r6.network = tt->local_ipv6;
	r6.netbits = tt->netbits_ipv6;
	r6.gateway = tt->local_ipv6;
	r6.metric  = 0;			/* connected route */
	r6.metric_defined = true;
	delete_route_ipv6 (&r6, tt, 0, es);
}
#endif

#if defined(TARGET_DRAGONFLY)
/* we can't use true subnet mode on tun on all platforms, as that
 * conflicts with IPv6 (wants to use ND then, which we don't do),
 * but the OSes want "a remote address that is different from ours"
 * - so we construct one, normally the first in the subnet, but if
 * this is the same as ours, use the second one.
 * The actual address does not matter at all, as the tun interface
 * is still point to point and no layer 2 resolution is done...
 */

const char *
create_arbitrary_remote (struct tuntap *tt, struct gc_arena *gc)
{
	in_addr_t remote;

	remote = (tt->local & tt->remote_netmask) + 1;

	if (remote == tt->local)
		remote++;

	return print_in_addr_t (remote, 0, &gc);
}
#endif

/* execute the ifconfig command through the shell */
void
do_ifconfig (struct tuntap *tt, const char *actual,	/* actual device name */
		int tun_mtu, const struct env_set *es)
{
	struct gc_arena gc = gc_new ();

	if (tt->did_ifconfig_setup)
	{
		bool tun = false;
		const char *ifconfig_local = NULL;
		const char *ifconfig_remote_netmask = NULL;
		const char *ifconfig_broadcast = NULL;
		const char *ifconfig_ipv6_local = NULL;
		const char *ifconfig_ipv6_remote = NULL;
		bool do_ipv6 = false;
		struct argv argv;

		argv_init (&argv);

		msg (M_INFO, "do_ifconfig, tt->ipv6=%d, tt->did_ifconfig_ipv6_setup=%d",
			tt->ipv6, tt->did_ifconfig_ipv6_setup);

		/* We only handle TUN/TAP devices here, not --dev null devices. */
		tun = is_tun_p2p (tt);

		/* Set ifconfig parameters */
		ifconfig_local = print_in_addr_t (tt->local, 0, &gc);
		ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, 0, &gc);

		if (tt->ipv6 && tt->did_ifconfig_ipv6_setup)
		{
			ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);
			ifconfig_ipv6_remote = print_in6_addr (tt->remote_ipv6, 0, &gc);
			do_ipv6 = true;
		}

		/* If TAP-style device, generate broadcast address. */
		if (!tun)
			ifconfig_broadcast = print_in_addr_t (tt->broadcast, 0, &gc);

#ifdef ENABLE_MANAGEMENT
		if (management)
		{
			management_set_state (management, OPENVPN_STATE_ASSIGN_IP, NULL, tt->local, 0);
		}
#endif

#if defined(TARGET_LINUX)
#ifdef ENABLE_IPROUTE
		/* Set the MTU for the device */
		argv_printf (&argv, "%s link set dev %s up mtu %d",
			iproute_path,
			actual,
			tun_mtu);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "Linux ip link set failed");

		if (tun)
		{
			/* Set the address for the device */
			argv_printf (&argv, "%s addr add dev %s local %s peer %s",
				iproute_path,
				actual,
				ifconfig_local,
				ifconfig_remote_netmask);
			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, es, S_FATAL, "Linux ip addr add failed");
		}
		else
		{
			argv_printf (&argv, "%s addr add dev %s %s/%d broadcast %s",
				iproute_path,
				actual,
				ifconfig_local,
				count_netmask_bits (ifconfig_remote_netmask),
				ifconfig_broadcast);
			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, es, S_FATAL, "Linux ip addr add failed");
		}
		if (do_ipv6)
		{
			argv_printf (&argv, "%s -6 addr add %s/%d dev %s",
				iproute_path,
				ifconfig_ipv6_local,
				tt->netbits_ipv6,
				actual);
			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, es, S_FATAL, "Linux ip -6 addr add failed");
		}
		tt->did_ifconfig = true;
#else
		if (tun)
			argv_printf (&argv, "%s %s %s pointopoint %s mtu %d",
				IFCONFIG_PATH,
				actual,
				ifconfig_local,
				ifconfig_remote_netmask,
				tun_mtu);
		else
			argv_printf (&argv, "%s %s %s netmask %s mtu %d broadcast %s",
				IFCONFIG_PATH,
				actual,
				ifconfig_local,
				ifconfig_remote_netmask,
				tun_mtu,
				ifconfig_broadcast);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "Linux ifconfig failed");
		if (do_ipv6)
		{
			argv_printf (&argv, "%s %s add %s/%d",
				IFCONFIG_PATH,
				actual,
				ifconfig_ipv6_local,
				tt->netbits_ipv6);
			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, es, S_FATAL, "Linux ifconfig inet6 failed");
		}
		tt->did_ifconfig = true;

#endif /*ENABLE_IPROUTE*/

#elif defined(TARGET_ANDROID)
		if (do_ipv6)
		{
		    char out6[128];
			openvpn_snprintf(out6, sizeof(out6), "%s/%d", ifconfig_ipv6_local, tt->netbits_ipv6);
			management_android_control (management, "IFCONFIG6", out6);
		}

		{
		    char out[128];
			char *top;

			switch (tt->topology)
			{
			case TOP_NET30:
				top = "net30";
				break;
			case TOP_P2P:
				top = "p2p";
				break;
			case TOP_SUBNET:
				top = "subnet";
				break;
			default:
				top = "undef";
			}

			openvpn_snprintf (out, sizeof (out), "%s %s %d %s", ifconfig_local, ifconfig_remote_netmask, tun_mtu, top);
			management_android_control (management, "IFCONFIG", out);
		}

#elif defined (WIN32)
		{
			/* Make sure that both ifconfig addresses are part of the same .252 subnet. */
			if (tun)
			{
				verify_255_255_255_252 (tt->local, tt->remote_netmask);
				tt->adapter_netmask = ~3;
			}
			else
			{
				tt->adapter_netmask = tt->remote_netmask;
			}

			switch (tt->options.ip_win32_type)
			{
			case IPW32_SET_MANUAL:
				msg (M_INFO, "******** NOTE:  Please manually set the IP/netmask of '%s' to %s/%s (if it is not already set)",
					actual,
					ifconfig_local,
					print_in_addr_t (tt->adapter_netmask, 0, &gc));
				break;
			case IPW32_SET_NETSH:
				if (!strcmp (actual, "NULL"))
					msg (M_FATAL, "Error: When using --ip-win32 netsh, if you have more than one TAP-Windows adapter, you must also specify --dev-node");

				if (dhcp_status (tt->adapter_index) != DHCP_STATUS_DISABLED)
					tt->enable_dhcp = true;	/* 关闭tun设备时, 重新启用dhcp */

				netsh_ifconfig (&tt->options,
					actual,
					tt->local,
					tt->adapter_netmask,
					NI_IP_NETMASK|NI_OPTIONS);
				break;
			}
			tt->did_ifconfig = true;
		}

		/* IPv6 always uses "netsh" interface */
		if (do_ipv6)
		{
			char *saved_actual;
			char iface[64];
			DWORD index;

			if (!strcmp (actual, "NULL"))
				msg (M_FATAL, "Error: When using --tun-ipv6, if you have more than one TAP-Windows adapter, you must also specify --dev-node");

			index = get_adapter_index_flexible (actual);
			openvpn_snprintf (iface, sizeof (iface), "interface=%lu", index);

			/* example: netsh interface ipv6 set address interface=42 2001:608:8003::d store=active */
			argv_printf (&argv, "%s%sc interface ipv6 set address %s %s store=active",
				get_win_sys_path (),
				NETSH_PATH_SUFFIX,
				win32_version_info () == WIN_XP ? actual : iface,
				ifconfig_ipv6_local);
			netsh_command (&argv, 4, M_FATAL);

			/* explicit route needed */
			/* on windows, OpenVPN does ifconfig first, open_tun later, so
			 * tt->actual_name might not yet be initialized, but routing code
			 * needs to know interface name - point to "actual", restore later
			 */
			saved_actual = tt->actual_name;
			tt->actual_name = (char *) actual;
			/* we use adapter_index in add_route_ipv6 */
			tt->adapter_index = index;
			add_route_connected_v6_net (tt, es);
			tt->actual_name = saved_actual;
		}

#else
		msg (M_FATAL, "Sorry, but I don't know how to do 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
#endif
		argv_reset (&argv);
	}

	gc_free (&gc);
}

static void
clear_tuntap (struct tuntap *tuntap)
{
	CLEAR (*tuntap);
#ifdef WIN32
	tuntap->hand = NULL;
#else
	tuntap->fd = -1;
#endif
	tuntap->ipv6 = false;
}

static void
open_null (struct tuntap *tt)
{
	tt->actual_name = string_alloc ("null", NULL);
}

#ifndef WIN32
static void
open_tun_generic (const char *dev, const char *dev_type, const char *dev_node,
		bool ipv6_explicitly_supported, bool dynamic, struct tuntap *tt)
{
	char tunname[256];
	char dynamic_name[256];
	bool dynamic_opened = false;


	if (tt->ipv6 && !ipv6_explicitly_supported)
		msg (M_WARN, "NOTE: explicit support for IPv6 tun devices is not provided for this OS");

	if (tt->type == DEV_TYPE_NULL)
	{
		open_null (tt);
	}
	else
	{
		/* --dev-node specified, so open an explicit device node */
		if (dev_node)
		{
			openvpn_snprintf (tunname, sizeof (tunname), "%s", dev_node);
		}
		else
		{
			/*
			 * dynamic open is indicated by --dev specified without
			 * explicit unit number.  Try opening /dev/[dev]n
			 * where n = [0, 255].
			 */
#ifdef TARGET_NETBSD
			/* on NetBSD, tap (but not tun) devices are opened by
			 * opening /dev/tap and then querying the system about the
			 * actual device name (tap0, tap1, ...) assigned
			 */
			if (dynamic && strcmp (dev, "tap") == 0)
			{
				struct ifreq ifr;
				if ((tt->fd = open ("/dev/tap", O_RDWR)) < 0)
				{
					msg (M_FATAL, "Cannot allocate NetBSD TAP dev dynamically");
				}
				if (ioctl (tt->fd, TAPGIFNAME, (void*) &ifr) < 0)
				{
					msg (M_FATAL, "Cannot query NetBSD TAP device name");
				}
				CLEAR (dynamic_name);
				strncpy (dynamic_name, ifr.ifr_name, sizeof (dynamic_name) -1);
				dynamic_opened = true;
				openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dynamic_name);
			}
			else
#endif

				if (dynamic && !has_digit ((unsigned char *)dev))
				{
					int i;
					for (i = 0; i < 256; ++i)
					{
						openvpn_snprintf (tunname, sizeof (tunname),
							"/dev/%s%d", dev, i);
						openvpn_snprintf (dynamic_name, sizeof (dynamic_name),
							"%s%d", dev, i);
						if ((tt->fd = open (tunname, O_RDWR)) > 0)
						{
							dynamic_opened = true;
							break;
						}
						msg (D_READ_WRITE | M_ERRNO, "Tried opening %s (failed)", tunname);
					}
					if (!dynamic_opened)
						msg (M_FATAL, "Cannot allocate TUN/TAP dev dynamically");
				}
				/* explicit unit number specified */
				else
				{
					openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dev);
				}
		}

		if (!dynamic_opened)
		{
			/* has named device existed before? if so, don't destroy at end */
			if (if_nametoindex (dev) > 0)
			{
				msg (M_INFO, "TUN/TAP device %s exists previously, keep at program end", dev);
				tt->persistent_if = true;
			}

			if ((tt->fd = open (tunname, O_RDWR)) < 0)
				msg (M_ERR, "Cannot open TUN/TAP dev %s", tunname);
		}

		set_nonblock (tt->fd);
		set_cloexec (tt->fd); /* don't pass fd to scripts */
		msg (M_INFO, "TUN/TAP device %s opened", tunname);

		/* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
		tt->actual_name = string_alloc (dynamic_opened ? dynamic_name : dev, NULL);
	}
}

static void
close_tun_generic (struct tuntap *tt)
{
	if (tt->fd >= 0)
		close (tt->fd);
	if (tt->actual_name)
		free (tt->actual_name);
	clear_tuntap (tt);
}

#endif

#if defined (TARGET_ANDROID)
void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
#define ANDROID_TUNNAME "vpnservice-tun"
	struct user_pass up;
	struct gc_arena gc = gc_new ();
	bool opentun;
	int android_method;
	int i, oldtunfd = tt->fd;

	for (i = 0; i < tt->options.dns_len; i++)
	{
		management_android_control (management, "DNSSERVER",
			print_in_addr_t (tt->options.dns[i], 0, &gc));
	}

	if (tt->options.domain)
	{
		management_android_control (management, "DNSDOMAIN", tt->options.domain);
	}

	android_method = managment_android_persisttun_action (management);

	/* Android 4.4 workaround */
	if (oldtunfd >= 0 && android_method == ANDROID_OPEN_AFTER_CLOSE)
	{
		close (oldtunfd);
		openvpn_sleep (2);
	}

	if (oldtunfd >= 0  && android_method == ANDROID_KEEP_OLD_TUN)
	{
		/* keep the old fd */
		opentun = true;
	}
	else
	{
		opentun = management_android_control (management, "OPENTUN", dev);
		/* Pick up the fd from management interface after calling the OPENTUN command */
		tt->fd = management->connection.lastfdreceived;
		management->connection.lastfdreceived = -1;
	}

	if (oldtunfd>=0 && android_method == ANDROID_OPEN_BEFORE_CLOSE)
	{
		close (oldtunfd);
	}

	/* Set the actual name to a dummy name */
	tt->actual_name = string_alloc (ANDROID_TUNNAME, NULL);

	if ((tt->fd < 0) || !opentun)
	{
		msg (M_ERR, "ERROR: Cannot open TUN");
	}

	gc_free (&gc);
}

void
close_tun (struct tuntap *tt)
{
	if (tt)
	{
		close_tun_generic (tt);
		free (tt);
	}
}

int
write_tun (struct tuntap *tt, uint8_t *buf, int len)
{
	return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap *tt, uint8_t *buf, int len)
{
	return read (tt->fd, buf, len);
}

#elif defined(TARGET_LINUX)

#ifdef HAVE_LINUX_IF_TUN_H	/* New driver support */

#ifndef HAVE_LINUX_SOCKIOS_H
#error header file linux/sockios.h required
#endif

#if !PEDANTIC

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	struct ifreq ifr;

	/* We handle --dev null specially, we do not open /dev/null for this. */
	if (tt->type == DEV_TYPE_NULL)
	{
		open_null (tt);
	}
	else
	{
		/* Process --dev-node */
		const char *node = dev_node;
		if (!node)
			node = "/dev/net/tun";

		/* Open the interface */
		if ((tt->fd = open (node, O_RDWR)) < 0)
		{
			msg (M_ERR, "ERROR: Cannot open TUN/TAP dev %s", node);
		}

		/* Process --tun-ipv6 */
		CLEAR (ifr);
		if (!tt->ipv6)
			ifr.ifr_flags = IFF_NO_PI;

#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
		ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

		/* Figure out if tun or tap device */
		if (tt->type == DEV_TYPE_TUN)
		{
			ifr.ifr_flags |= IFF_TUN;
		}
		else if (tt->type == DEV_TYPE_TAP)
		{
			ifr.ifr_flags |= IFF_TAP;
		}
		else
		{
			msg (M_FATAL, "I don't recognize device %s as a tun or tap device", dev);
		}

		/* Set an explicit name, if --dev is not tun or tap */
		if (strcmp (dev, "tun") && strcmp (dev, "tap"))
			strncpynt (ifr.ifr_name, dev, IFNAMSIZ);

		/* Use special ioctl that configures tun/tap device with the parms we set in ifr */
		if (ioctl (tt->fd, TUNSETIFF, (void *) &ifr) < 0)
		{
			msg (M_ERR, "ERROR: Cannot ioctl TUNSETIFF %s", dev);
		}

		msg (M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);

		/* Try making the TX send queue bigger */
#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
		if (tt->options.txqueuelen)
		{
			struct ifreq netifr;
			int ctl_fd;

			if ((ctl_fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0)
			{
				CLEAR (netifr);
				strncpynt (netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
				netifr.ifr_qlen = tt->options.txqueuelen;
				if (ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0)
					msg (D_OSBUF, "TUN/TAP TX queue length set to %d", tt->options.txqueuelen);
				else
					msg (M_WARN | M_ERRNO, "Note: Cannot set tx queue length on %s", ifr.ifr_name);
				close (ctl_fd);
			}
			else
			{
				msg (M_WARN | M_ERRNO, "Note: Cannot open control socket on %s", ifr.ifr_name);
			}
		}
#endif

		set_nonblock (tt->fd);
		set_cloexec (tt->fd);
		tt->actual_name = string_alloc (ifr.ifr_name, NULL);
	}
	return;
}

#else

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	ASSERT (0);
}

#endif

#else

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	open_tun_generic (dev, dev_type, dev_node, false, true, tt);
}

#endif /* HAVE_LINUX_IF_TUN_H */

#ifdef ENABLE_FEATURE_TUN_PERSIST

/*
 * This can be removed in future
 * when all systems will use newer
 * linux-headers
 */
#ifndef TUNSETOWNER
#define TUNSETOWNER	_IOW('T', 204, int)
#endif
#ifndef TUNSETGROUP
#define TUNSETGROUP	_IOW('T', 206, int)
#endif

void
tuncfg (const char *dev, const char *dev_type, const char *dev_node, int persist_mode, const char *username,
		const char *groupname, const struct tuntap_options *options)
{
	struct tuntap *tt;

	ALLOC_OBJ (tt, struct tuntap);
	clear_tuntap (tt);
	tt->type = dev_type_enum (dev, dev_type);
	tt->options = *options;
	open_tun (dev, dev_type, dev_node, tt);

	if (ioctl (tt->fd, TUNSETPERSIST, persist_mode) < 0)
		msg (M_ERR, "Cannot ioctl TUNSETPERSIST(%d) %s", persist_mode, dev);

	if (username != NULL)
	{
		struct platform_state_user platform_state_user;

		if (!platform_user_get (username, &platform_state_user))
			msg (M_ERR, "Cannot get user entry for %s", username);
		else
			if (ioctl (tt->fd, TUNSETOWNER, platform_state_user.pw->pw_uid) < 0)
				msg (M_ERR, "Cannot ioctl TUNSETOWNER(%s) %s", username, dev);
	}
	if (groupname != NULL)
	{
		struct platform_state_group platform_state_group;

		if (!platform_group_get (groupname, &platform_state_group))
			msg (M_ERR, "Cannot get group entry for %s", groupname);
		else
			if (ioctl (tt->fd, TUNSETGROUP, platform_state_group.gr->gr_gid) < 0)
				msg (M_ERR, "Cannot ioctl TUNSETOWNER(%s) %s", groupname, dev);
	}
	close_tun (tt);
	msg (M_INFO, "Persist state set to: %s", (persist_mode ? "ON" : "OFF"));
}

#endif /* ENABLE_FEATURE_TUN_PERSIST */

void
close_tun (struct tuntap *tt)
{
	if (tt)
	{
		if (tt->type != DEV_TYPE_NULL && tt->did_ifconfig)
		{
			struct argv argv;
			struct gc_arena gc = gc_new ();
			argv_init (&argv);

#ifdef ENABLE_IPROUTE
			if (is_tun_p2p (tt))
			{
				argv_printf (&argv, "%s addr del dev %s local %s peer %s",
					iproute_path,
					tt->actual_name,
					print_in_addr_t (tt->local, 0, &gc),
					print_in_addr_t (tt->remote_netmask, 0, &gc));
			}
			else
			{
				argv_printf (&argv, "%s addr del dev %s %s/%d",
					iproute_path,
					tt->actual_name,
					print_in_addr_t (tt->local, 0, &gc),
					count_netmask_bits (print_in_addr_t (tt->remote_netmask, 0, &gc)));
			}
#else
			argv_printf (&argv, "%s %s 0.0.0.0", IFCONFIG_PATH, tt->actual_name);
#endif

			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, NULL, 0, "Linux ip addr del failed");

			if (tt->ipv6 && tt->did_ifconfig_ipv6_setup)
			{
				const char * ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);

#ifdef ENABLE_IPROUTE
				argv_printf (&argv, "%s -6 addr del %s/%d dev %s",
					iproute_path,
					ifconfig_ipv6_local,
					tt->netbits_ipv6,
					tt->actual_name);
				argv_msg (M_INFO, &argv);
				openvpn_execve_check (&argv, NULL, 0, "Linux ip -6 addr del failed");
#else
				argv_printf (&argv, "%s %s del %s/%d",
					IFCONFIG_PATH,
					tt->actual_name,
					ifconfig_ipv6_local,
					tt->netbits_ipv6);
				argv_msg (M_INFO, &argv);
				openvpn_execve_check (&argv, NULL, 0, "Linux ifconfig inet6 del failed");
#endif
			}

			argv_reset (&argv);
			gc_free (&gc);
		}
		close_tun_generic (tt);
		free (tt);
	}
}

int
write_tun (struct tuntap *tt, uint8_t *buf, int len)
{
	if (tt->ipv6)
	{
		struct tun_pi pi;
		struct iphdr *iph;
		struct iovec vect[2];
		int ret;

		iph = (struct iphdr *) buf;

		pi.flags = 0;

		if (iph->version == 6)
			pi.proto = htons (OPENVPN_ETH_P_IPV6);
		else
			pi.proto = htons (OPENVPN_ETH_P_IPV4);

		vect[0].iov_len = sizeof (pi);
		vect[0].iov_base = &pi;
		vect[1].iov_len = len;
		vect[1].iov_base = buf;

		ret = writev (tt->fd, vect, 2);
		return (ret - sizeof (pi));
	}
	else
		return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap *tt, uint8_t *buf, int len)
{
	if (tt->ipv6)
	{
		struct iovec vect[2];
		struct tun_pi pi;
		int ret;

		vect[0].iov_len = sizeof (pi);
		vect[0].iov_base = &pi;
		vect[1].iov_len = len;
		vect[1].iov_base = buf;

		ret = readv (tt->fd, vect, 2);
		return (ret - sizeof (pi));
	}
	else
		return read (tt->fd, buf, len);
}

#elif defined(WIN32)

int
tun_read_queue (struct tuntap *tt, int maxsize, struct buffer *buf)
{
	if (tt->reads.iostate == IOSTATE_INITIAL)
	{
		DWORD len;
		BOOL status;
		int err;

		/* reset buf to its initial state */
		tt->reads.buf = tt->reads.buf_init;

		len = maxsize ? maxsize : BLEN (&tt->reads.buf);
		ASSERT (len <= (DWORD) BLEN (&tt->reads.buf));

		/* the overlapped read will signal this event on I/O completion */
		ASSERT (ResetEvent (tt->reads.overlapped.hEvent));

		status = ReadFile (
			tt->hand,
			BPTR (&tt->reads.buf),
			len,
			&tt->reads.size,
			&tt->reads.overlapped
			);

		if (status) /* operation completed immediately? */
		{
			/* since we got an immediate return, we must signal the event object ourselves */
			ASSERT (SetEvent (tt->reads.overlapped.hEvent));

			if (buf)
			{
				buf_assign (buf, &tt->reads.buf);
				buf->len = tt->reads.size;
				tt->reads.iostate = IOSTATE_INITIAL;
			}
			else
			{
				tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
			}

			tt->reads.status = 0;

			dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read immediate return [%d,%d]",
				(int) len,
				(int) tt->reads.size);	       
		}
		else
		{
			err = GetLastError (); 
			if (err == ERROR_IO_PENDING) /* operation queued? */
			{
				tt->reads.iostate = IOSTATE_QUEUED;
				tt->reads.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read queued [%d]", (int) len);
			}
			else /* error occurred */
			{
				struct gc_arena gc = gc_new ();
				ASSERT (SetEvent (tt->reads.overlapped.hEvent));
				tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
				tt->reads.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read error [%d] : %s",
					(int) len,
					strerror_win32 (status, &gc));
				gc_free (&gc);
			}
		}
	}

	return tt->reads.iostate;
}

int
tun_write_queue (struct tuntap *tt, struct buffer *buf)
{
	if (tt->writes.iostate == IOSTATE_INITIAL)
	{
		BOOL status;
		int err;

		/* make a private copy of buf */
		tt->writes.buf = tt->writes.buf_init;
		tt->writes.buf.len = 0;
		ASSERT (buf_copy (&tt->writes.buf, buf));

		/* the overlapped write will signal this event on I/O completion */
		ASSERT (ResetEvent (tt->writes.overlapped.hEvent));

		status = WriteFile (
			tt->hand,
			BPTR (&tt->writes.buf),
			BLEN (&tt->writes.buf),
			&tt->writes.size,
			&tt->writes.overlapped
			);

		if (status) /* operation completed immediately? */
		{
			tt->writes.iostate = IOSTATE_INITIAL;

			/* since we got an immediate return, we must signal the event object ourselves */
			ASSERT (SetEvent (tt->writes.overlapped.hEvent));

			tt->writes.status = 0;

			dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write immediate return [%d,%d]",
				BLEN (&tt->writes.buf),
				(int) tt->writes.size);	       
		}
		else
		{
			err = GetLastError (); 
			if (err == ERROR_IO_PENDING) /* operation queued? */
			{
				tt->writes.iostate = IOSTATE_QUEUED;
				tt->writes.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write queued [%d]", BLEN (&tt->writes.buf));
			}
			else /* error occurred */
			{
				struct gc_arena gc = gc_new ();
				ASSERT (SetEvent (tt->writes.overlapped.hEvent));
				tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
				tt->writes.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write error [%d] : %s",
					BLEN (&tt->writes.buf),
					strerror_win32 (err, &gc));
				buf->len = 0; /* drop packet */
				buf_set_tracking (buf, PACKET_DROP_WRITE_ERROR);
				gc_free (&gc);
			}
		}
	}

	return tt->writes.iostate;
}

int
tun_finalize (HANDLE h, struct overlapped_io *io, struct buffer *buf)
{
	int ret = -1;
	BOOL status;

	switch (io->iostate)
	{
	case IOSTATE_QUEUED:
		status = GetOverlappedResult (
			h,
			&io->overlapped,
			&io->size,
			FALSE);
		if (status)
		{
			/* successful return for a queued operation */
			if (buf)
				buf_assign (buf, &io->buf);
			ret = io->size;
			io->iostate = IOSTATE_INITIAL;
			ASSERT (ResetEvent (io->overlapped.hEvent));
			dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion success [%d]", ret);
		}
		else
		{
			if (GetLastError () == ERROR_IO_INCOMPLETE)
			{
				ret = 0;
				io->iostate = IOSTATE_QUEUED;
			}
			else
			{
				/* error during a queued operation */
				ret = -1;
				/* if no error (i.e. just not finished yet), then DON'T execute this code */
				io->iostate = IOSTATE_INITIAL;
				ASSERT (ResetEvent (io->overlapped.hEvent));
				msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion error");
			}
		}
		break;

	case IOSTATE_IMMEDIATE_RETURN:
		io->iostate = IOSTATE_INITIAL;
		ASSERT (ResetEvent (io->overlapped.hEvent));
		if (io->status)
		{
			/* error return for a non-queued operation */
			SetLastError (io->status);
			ret = -1;
			msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion non-queued error");
		}
		else
		{
			/* successful return for a non-queued operation */
			if (buf)
				buf_assign (buf, &io->buf);
			ret = io->size;
			dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion non-queued success [%d]", ret);
		}
		break;

	case IOSTATE_INITIAL: /* were we called without proper queueing? */
		SetLastError (ERROR_INVALID_FUNCTION);
		ret = -1;
		dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion BAD STATE");
		break;

	default:
		ASSERT (0);
	}

	if (buf)
		buf->len = ret;
	return ret;
}

const struct tap_reg *
get_tap_reg (struct gc_arena *gc)
{
	HKEY adapter_key;
	LONG status;
	DWORD len;
	struct tap_reg *first = NULL;
	struct tap_reg *last = NULL;
	int i = 0;

	status = RegOpenKeyExA (
		HKEY_LOCAL_MACHINE,
		ADAPTER_KEY,
		0,
		KEY_READ,
		&adapter_key);

	if (status != ERROR_SUCCESS)
		msg (M_FATAL, "Error opening registry key: %s", ADAPTER_KEY);

	while (true)
	{
		char enum_name[256];
		char unit_string[256];
		HKEY unit_key;
		char component_id_string[] = "ComponentId";
		char component_id[256];
		char net_cfg_instance_id_string[] = "NetCfgInstanceId";
		char net_cfg_instance_id[256];
		DWORD data_type;

		len = sizeof (enum_name);
		status = RegEnumKeyExA (
			adapter_key,
			i,
			enum_name,
			&len,
			NULL,
			NULL,
			NULL,
			NULL);
		if (status == ERROR_NO_MORE_ITEMS)
			break;
		else if (status != ERROR_SUCCESS)
			msg (M_FATAL, "Error enumerating registry subkeys of key: %s", ADAPTER_KEY);

		openvpn_snprintf (unit_string, sizeof (unit_string), "%s\\%s", ADAPTER_KEY, enum_name);

		status = RegOpenKeyExA (
			HKEY_LOCAL_MACHINE,
			unit_string,
			0,
			KEY_READ,
			&unit_key);

		if (status != ERROR_SUCCESS)
			dmsg (D_REGISTRY, "Error opening registry key: %s", unit_string);
		else
		{
			len = sizeof (component_id);
			status = RegQueryValueExA (
				unit_key,
				component_id_string,
				NULL,
				&data_type,
				(LPBYTE) component_id,
				&len);

			if (status != ERROR_SUCCESS || data_type != REG_SZ)
				dmsg (D_REGISTRY, "Error opening registry key: %s\\%s",
					unit_string, component_id_string);
			else
			{	      
				len = sizeof (net_cfg_instance_id);
				status = RegQueryValueExA (
					unit_key,
					net_cfg_instance_id_string,
					NULL,
					&data_type,
					(LPBYTE) net_cfg_instance_id,
					&len);

				if (status == ERROR_SUCCESS && data_type == REG_SZ)
				{
					if (!strcmp (component_id, TAP_WIN_COMPONENT_ID))
					{
						struct tap_reg *reg;
						ALLOC_OBJ_CLEAR_GC (reg, struct tap_reg, gc);
						reg->guid = string_alloc (net_cfg_instance_id, gc);

						/* link into return list */
						if (!first)
							first = reg;
						if (last)
							last->next = reg;
						last = reg;
					}
				}
			}
			RegCloseKey (unit_key);
		}
		++i;
	}

	RegCloseKey (adapter_key);
	return first;
}

const struct panel_reg *
get_panel_reg (struct gc_arena *gc)
{
	LONG status;
	HKEY network_connections_key;
	DWORD len;
	struct panel_reg *first = NULL;
	struct panel_reg *last = NULL;
	int i = 0;

	status = RegOpenKeyExA (
		HKEY_LOCAL_MACHINE,
		NETWORK_CONNECTIONS_KEY,
		0,
		KEY_READ,
		&network_connections_key);

	if (status != ERROR_SUCCESS)
		msg (M_FATAL, "Error opening registry key: %s", NETWORK_CONNECTIONS_KEY);

	while (true)
	{
		char enum_name[256];
		char connection_string[256];
		HKEY connection_key;
		WCHAR name_data[256];
		DWORD name_type;
		const WCHAR name_string[] = L"Name";

		len = sizeof (enum_name);
		status = RegEnumKeyExA (
			network_connections_key,
			i,
			enum_name,
			&len,
			NULL,
			NULL,
			NULL,
			NULL);
		if (status == ERROR_NO_MORE_ITEMS)
			break;
		else if (status != ERROR_SUCCESS)
			msg (M_FATAL, "Error enumerating registry subkeys of key: %s", NETWORK_CONNECTIONS_KEY);

		openvpn_snprintf (connection_string, sizeof (connection_string),
			"%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, enum_name);

		status = RegOpenKeyExA (
			HKEY_LOCAL_MACHINE,
			connection_string,
			0,
			KEY_READ,
			&connection_key);

		if (status != ERROR_SUCCESS)
			dmsg (D_REGISTRY, "Error opening registry key: %s", connection_string);
		else
		{
			len = sizeof (name_data);
			status = RegQueryValueExW (
				connection_key,
				name_string,
				NULL,
				&name_type,
				(LPBYTE) name_data,
				&len);

			if (status != ERROR_SUCCESS || name_type != REG_SZ)
				dmsg (D_REGISTRY, "Error opening registry key: %s\\%s\\%s", NETWORK_CONNECTIONS_KEY, connection_string, name_string);
			else
			{
				int n;
				LPSTR name;
				struct panel_reg *reg;

				ALLOC_OBJ_CLEAR_GC (reg, struct panel_reg, gc);
				n = WideCharToMultiByte (CP_UTF8, 0, name_data, -1, NULL, 0, NULL, NULL);
				name = (LPSTR) gc_malloc (n, false, gc);
				WideCharToMultiByte (CP_UTF8, 0, name_data, -1, name, n, NULL, NULL);
				reg->name = name;
				reg->guid = string_alloc (enum_name, gc);

				/* link into return list */
				if (!first)
					first = reg;
				if (last)
					last->next = reg;
				last = reg;
			}
			RegCloseKey (connection_key);
		}
		++i;
	}

	RegCloseKey (network_connections_key);

	return first;
}

/*
 * Check that two addresses are part of the same 255.255.255.252 subnet.
 */
void
verify_255_255_255_252 (in_addr_t local, in_addr_t remote)
{
	struct gc_arena gc = gc_new ();
	const unsigned int mask = 3;
	const char *err = NULL;

	if (local == remote)
	{
		err = "must be different";
		goto error;
	}
	if ((local & (~mask)) != (remote & (~mask)))
	{
		err = "must exist within the same 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
		goto error;
	}
	if ((local & mask) == 0
		|| (local & mask) == 3
		|| (remote & mask) == 0
		|| (remote & mask) == 3)
	{
		err = "cannot use the first or last address within a given 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
		goto error;
	}

	gc_free (&gc);
	return;

error:
	msg (M_FATAL, "There is a problem in your selection of --ifconfig endpoints [local=%s, remote=%s].  The local and remote VPN endpoints %s.  Try '" PACKAGE " --show-valid-subnets' option for more info.",
		print_in_addr_t (local, 0, &gc),
		print_in_addr_t (remote, 0, &gc),
		err);
	gc_free (&gc);
}

void show_valid_win32_tun_subnets (void)
{
	int i;
	int col = 0;

	printf ("On Windows, point-to-point IP support (i.e. --dev tun)\n");
	printf ("is emulated by the TAP-Windows driver.  The major limitation\n");
	printf ("imposed by this approach is that the --ifconfig local and\n");
	printf ("remote endpoints must be part of the same 255.255.255.252\n");
	printf ("subnet.  The following list shows examples of endpoint\n");
	printf ("pairs which satisfy this requirement.  Only the final\n");
	printf ("component of the IP address pairs is at issue.\n\n");
	printf ("As an example, the following option would be correct:\n");
	printf ("    --ifconfig 10.7.0.5 10.7.0.6 (on host A)\n");
	printf ("    --ifconfig 10.7.0.6 10.7.0.5 (on host B)\n");
	printf ("because [5,6] is part of the below list.\n\n");

	for (i = 0; i < 256; i += 4)
	{
		printf ("[%3d,%3d] ", i + 1, i + 2);
		if (++col > 4)
		{
			col = 0;
			printf ("\n");
		}
	}
	if (col)
		printf ("\n");
}

void
show_tap_win_adapters (int msglev, int warnlev)
{
	struct gc_arena gc = gc_new ();

	bool warn_panel_null = false;
	bool warn_panel_dup = false;
	bool warn_tap_dup = false;

	int links;

	const struct tap_reg *tr;
	const struct tap_reg *tr1;
	const struct panel_reg *pr;

	const struct tap_reg *tap_reg = get_tap_reg (&gc);
	const struct panel_reg *panel_reg = get_panel_reg (&gc);

	msg (msglev, "Available TAP-WIN32 adapters [name, GUID]:");

	/* loop through each TAP-Windows adapter registry entry */
	for (tr = tap_reg; tr != NULL; tr = tr->next)
	{
		links = 0;

		/* loop through each network connections entry in the control panel */
		for (pr = panel_reg; pr != NULL; pr = pr->next)
		{
			if (!strcmp (tr->guid, pr->guid))
			{
				msg (msglev, "'%s' %s", pr->name, tr->guid);
				++links;
			}
		}

		if (links > 1)
		{
			warn_panel_dup = true;
		}
		else if (links == 0)
		{
			/* a TAP adapter exists without a link from the network connections control panel */
			warn_panel_null = true;
			msg (msglev, "[NULL] %s", tr->guid);
		}
	}

	/* check for TAP-Windows adapter duplicated GUIDs */
	for (tr = tap_reg; tr != NULL; tr = tr->next)
	{
		for (tr1 = tap_reg; tr1 != NULL; tr1 = tr1->next)
		{
			if (tr != tr1 && !strcmp (tr->guid, tr1->guid))
				warn_tap_dup = true;
		}
	}

	/* warn on registry inconsistencies */
	if (warn_tap_dup)
		msg (warnlev, "WARNING: Some TAP-Windows adapters have duplicate GUIDs");

	if (warn_panel_dup)
		msg (warnlev, "WARNING: Some TAP-Windows adapters have duplicate links from the Network Connections control panel");

	if (warn_panel_null)
		msg (warnlev, "WARNING: Some TAP-Windows adapters have no link from the Network Connections control panel");

	gc_free (&gc);
}

/*
 * Confirm that GUID is a TAP-Windows adapter.
 */
static bool
is_tap_win (const char *guid, const struct tap_reg *tap_reg)
{
	const struct tap_reg *tr;

	for (tr = tap_reg; tr != NULL; tr = tr->next)
	{
		if (guid && !strcmp (tr->guid, guid))
			return true;
	}

	return false;
}

static const char *
guid_to_name (const char *guid, const struct panel_reg *panel_reg)
{
	const struct panel_reg *pr;

	for (pr = panel_reg; pr != NULL; pr = pr->next)
	{
		if (guid && !strcmp (pr->guid, guid))
			return pr->name;
	}

	return NULL;
}

static const char *
name_to_guid (const char *name, const struct tap_reg *tap_reg, const struct panel_reg *panel_reg)
{
	const struct panel_reg *pr;

	for (pr = panel_reg; pr != NULL; pr = pr->next)
	{
		if (name && !strcmp (pr->name, name) && is_tap_win (pr->guid, tap_reg))
			return pr->guid;
	}

	return NULL;
}

static void
at_least_one_tap_win (const struct tap_reg *tap_reg)
{
	if (!tap_reg)
		msg (M_FATAL, "There are no TAP-Windows adapters on this system.  You should be able to create a TAP-Windows adapter by going to Start -> All Programs -> TAP-Windows -> Utilities -> Add a new TAP-Windows virtual ethernet adapter.");
}

/*
 * Get an adapter GUID and optional actual_name from the 
 * registry for the TAP device # = device_number.
 */
static const char *
get_unspecified_device_guid (const int device_number, char *actual_name, int actual_name_size,
		const struct tap_reg *tap_reg_src, const struct panel_reg *panel_reg_src,
		struct gc_arena *gc)
{
	const struct tap_reg *tap_reg = tap_reg_src;
	struct buffer ret = clear_buf ();
	struct buffer actual = clear_buf ();
	int i;

	ASSERT (device_number >= 0);

	/* Make sure we have at least one TAP adapter */
	if (!tap_reg)
		return NULL;

	/* The actual_name output buffer may be NULL */
	if (actual_name)
	{
		ASSERT (actual_name_size > 0);
		buf_set_write (&actual, (uint8_t *) actual_name, actual_name_size);
	}

	/* Move on to specified device number */
	for (i = 0; i < device_number; i++)
	{
		tap_reg = tap_reg->next;
		if (!tap_reg)
			return NULL;
	}

	/* Save Network Panel name (if exists) in actual_name */
	if (actual_name)
	{
		const char *act = guid_to_name (tap_reg->guid, panel_reg_src);
		if (act)
			buf_printf (&actual, "%s", act);
		else
			buf_printf (&actual, "%s", tap_reg->guid);
	}

	/* Save GUID for return value */
	ret = alloc_buf_gc (256, gc);
	buf_printf (&ret, "%s", tap_reg->guid);
	return BSTR (&ret);
}

/*
 * Lookup a --dev-node adapter name in the registry
 * returning the GUID and optional actual_name.
 */
static const char *
get_device_guid (const char *name, char *actual_name, int actual_name_size,
		const struct tap_reg *tap_reg, const struct panel_reg *panel_reg,
		struct gc_arena *gc)
{
	struct buffer ret = alloc_buf_gc (256, gc);
	struct buffer actual = clear_buf ();

	/* Make sure we have at least one TAP adapter */
	if (!tap_reg)
		return NULL;

	/* The actual_name output buffer may be NULL */
	if (actual_name)
	{
		ASSERT (actual_name_size > 0);
		buf_set_write (&actual, (uint8_t *) actual_name, actual_name_size);
	}

	/* Check if GUID was explicitly specified as --dev-node parameter */
	if (is_tap_win (name, tap_reg))
	{
		const char *act = guid_to_name (name, panel_reg);
		buf_printf (&ret, "%s", name);
		if (act)
			buf_printf (&actual, "%s", act);
		else
			buf_printf (&actual, "%s", name);
		return BSTR (&ret);
	}

	/* Lookup TAP adapter in network connections list */
	{
		const char *guid = name_to_guid (name, tap_reg, panel_reg);
		if (guid)
		{
			buf_printf (&actual, "%s", name);
			buf_printf (&ret, "%s", guid);
			return BSTR (&ret);
		}
	}

	return NULL;
}

/*
 * Get adapter info list
 */
const IP_ADAPTER_INFO *
get_adapter_info_list (struct gc_arena *gc)
{
	ULONG size = 0;
	IP_ADAPTER_INFO *pi = NULL;
	DWORD status;

	if ((status = GetAdaptersInfo (NULL, &size)) != ERROR_BUFFER_OVERFLOW)
	{
		msg (M_INFO, "GetAdaptersInfo #1 failed (status=%u) : %s",
			(unsigned int) status,
			strerror_win32 (status, gc));
	}
	else
	{
		pi = (PIP_ADAPTER_INFO) gc_malloc (size, false, gc);
		if ((status = GetAdaptersInfo (pi, &size)) == NO_ERROR)
			return pi;
		else
		{
			msg (M_INFO, "GetAdaptersInfo #2 failed (status=%u) : %s",
				(unsigned int) status,
				strerror_win32 (status, gc));
		}
	}
	return pi;
}

const IP_PER_ADAPTER_INFO *
get_per_adapter_info (const DWORD index, struct gc_arena *gc)
{
	ULONG size = 0;
	IP_PER_ADAPTER_INFO *pi = NULL;
	DWORD status;

	if (index != TUN_ADAPTER_INDEX_INVALID)
	{
		if ((status = GetPerAdapterInfo (index, NULL, &size)) != ERROR_BUFFER_OVERFLOW)
		{
			msg (M_INFO, "GetPerAdapterInfo #1 failed (status=%u) : %s",
				(unsigned int) status,
				strerror_win32 (status, gc));
		}
		else
		{
			pi = (PIP_PER_ADAPTER_INFO) gc_malloc (size, false, gc);
			if ((status = GetPerAdapterInfo ((ULONG)index, pi, &size)) == ERROR_SUCCESS)
				return pi;
			else
			{
				msg (M_INFO, "GetPerAdapterInfo #2 failed (status=%u) : %s",
					(unsigned int) status,
					strerror_win32 (status, gc));
			}
		}
	}
	return pi;
}

static const IP_INTERFACE_INFO *
get_interface_info_list (struct gc_arena *gc)
{
	ULONG size = 0;
	IP_INTERFACE_INFO *ii = NULL;
	DWORD status;

	if ((status = GetInterfaceInfo (NULL, &size)) != ERROR_INSUFFICIENT_BUFFER)
	{
		msg (M_INFO, "GetInterfaceInfo #1 failed (status=%u) : %s",
			(unsigned int) status,
			strerror_win32 (status, gc));
	}
	else
	{
		ii = (PIP_INTERFACE_INFO) gc_malloc (size, false, gc);
		if ((status = GetInterfaceInfo (ii, &size)) == NO_ERROR)
			return ii;
		else
		{
			msg (M_INFO, "GetInterfaceInfo #2 failed (status=%u) : %s",
				(unsigned int) status,
				strerror_win32 (status, gc));
		}
	}
	return ii;
}

static const IP_ADAPTER_INDEX_MAP *
get_interface_info (DWORD index, struct gc_arena *gc)
{
	const IP_INTERFACE_INFO *list = get_interface_info_list (gc);
	if (list)
	{
		int i;
		for (i = 0; i < list->NumAdapters; ++i)
		{
			const IP_ADAPTER_INDEX_MAP *inter = &list->Adapter[i];
			if (index == inter->Index)
				return inter;
		}
	}
	return NULL;
}

/*
 * Given an adapter index, return a pointer to the
 * IP_ADAPTER_INFO structure for that adapter.
 */

const IP_ADAPTER_INFO *
get_adapter (const IP_ADAPTER_INFO *ai, DWORD index)
{
	if (ai && index != TUN_ADAPTER_INDEX_INVALID)
	{
		const IP_ADAPTER_INFO *a;

		/* find index in the linked list */
		for (a = ai; a != NULL; a = a->Next)
		{
			if (a->Index == index)
				return a;
		}
	}
	return NULL;
}

const IP_ADAPTER_INFO *
get_adapter_info (DWORD index, struct gc_arena *gc)
{
	return get_adapter (get_adapter_info_list (gc), index);
}

static int
get_adapter_n_ip_netmask (const IP_ADAPTER_INFO *ai)
{
	if (ai)
	{
		int n = 0;
		const IP_ADDR_STRING *ip = &ai->IpAddressList;

		while (ip)
		{
			++n;
			ip = ip->Next;
		}
		return n;
	}
	else
		return 0;
}

static bool
get_adapter_ip_netmask (const IP_ADAPTER_INFO *ai, const int n, in_addr_t *ip, in_addr_t *netmask)
{
	bool ret = false;
	*ip = 0;
	*netmask = 0;

	if (ai)
	{
		const IP_ADDR_STRING *iplist = &ai->IpAddressList;
		int i = 0;

		while (iplist)
		{
			if (i == n)
				break;
			++i;
			iplist = iplist->Next;
		}

		if (iplist)
		{
			const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
			const char *ip_str = iplist->IpAddress.String;
			const char *netmask_str = iplist->IpMask.String;
			bool succeed1 = false;
			bool succeed2 = false;

			if (ip_str && netmask_str && strlen (ip_str) && strlen (netmask_str))
			{
				*ip = getaddr (getaddr_flags, ip_str, 0, &succeed1, NULL);
				*netmask = getaddr (getaddr_flags, netmask_str, 0, &succeed2, NULL);
				ret = (succeed1 == true && succeed2 == true);
			}
		}
	}

	return ret;
}

static bool
test_adapter_ip_netmask (const IP_ADAPTER_INFO *ai, const in_addr_t ip, const in_addr_t netmask)
{
	if (ai)
	{
		in_addr_t ip_adapter = 0;
		in_addr_t netmask_adapter = 0;
		const bool status = get_adapter_ip_netmask (ai, 0, &ip_adapter, &netmask_adapter);
		return (status && ip_adapter == ip && netmask_adapter == netmask);
	}
	else
		return false;
}

const IP_ADAPTER_INFO *
get_tun_adapter (const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
	if (list && tt)
		return get_adapter (list, tt->adapter_index);
	else
		return NULL;
}

bool
is_adapter_up (const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
	int i;
	bool ret = false;

	const IP_ADAPTER_INFO *ai = get_tun_adapter (tt, list);

	if (ai)
	{
		const int n = get_adapter_n_ip_netmask (ai);

		/* loop once for every IP/netmask assigned to adapter */
		for (i = 0; i < n; ++i)
		{
			in_addr_t ip, netmask;
			if (get_adapter_ip_netmask (ai, i, &ip, &netmask))
			{
				if (tt->local && tt->adapter_netmask)
				{
					/* wait for our --ifconfig parms to match the actual adapter parms */
					if (tt->local == ip && tt->adapter_netmask == netmask)
						ret = true;
				}
				else
				{
					/* --ifconfig was not defined, maybe using a real DHCP server */
					if (ip && netmask)
						ret = true;
				}
			}
		}
	}
	else
		ret = true; /* this can occur when TAP adapter is bridged */

	return ret;
}

bool
is_ip_in_adapter_subnet (const IP_ADAPTER_INFO *ai, const in_addr_t ip, in_addr_t *highest_netmask)
{
	bool ret = false;

	if (highest_netmask)
		*highest_netmask = 0;

	if (ai)
	{
		int i;
		const int n = get_adapter_n_ip_netmask (ai);

		for (i = 0; i < n; ++i)
		{
			in_addr_t adapter_ip, adapter_netmask;
			if (get_adapter_ip_netmask (ai, i, &adapter_ip, &adapter_netmask))
			{
				if (adapter_ip && adapter_netmask && (ip & adapter_netmask) == (adapter_ip & adapter_netmask))
				{
					if (highest_netmask && adapter_netmask > *highest_netmask)
						*highest_netmask = adapter_netmask;
					ret = true;
				}
			}
		}
	}

	return ret;
}

DWORD
adapter_index_of_ip (const IP_ADAPTER_INFO *list, const in_addr_t ip, int *count, in_addr_t *netmask)
{
	struct gc_arena gc = gc_new ();
	DWORD ret = TUN_ADAPTER_INDEX_INVALID;
	in_addr_t highest_netmask = 0;
	bool first = true;

	if (count)
		*count = 0;

	while (list)
	{
		in_addr_t hn;

		if (is_ip_in_adapter_subnet (list, ip, &hn))
		{
			if (first || hn > highest_netmask)
			{
				highest_netmask = hn;
				if (count)
					*count = 1;
				ret = list->Index;
				first = false;
			}
			else if (hn == highest_netmask)
			{
				if (count)
					++*count;
			}
		}
		list = list->Next;
	}

	dmsg (D_ROUTE_DEBUG, "DEBUG: IP Locate: ip=%s nm=%s index=%d count=%d",
		print_in_addr_t (ip, 0, &gc),
		print_in_addr_t (highest_netmask, 0, &gc),
		(int) ret,
		count ? *count : -1);

	if (ret == TUN_ADAPTER_INDEX_INVALID && count)
		*count = 0;

	if (netmask)
		*netmask = highest_netmask;

	gc_free (&gc);
	return ret;
}

/*
 * Delete all temporary address/netmask pairs which were added
 * to adapter (given by index) by previous calls to AddIPAddress.
 */
static void
delete_temp_addresses (DWORD index)
{
	struct gc_arena gc = gc_new ();
	const IP_ADAPTER_INFO *a = get_adapter_info (index, &gc);

	if (a)
	{
		const IP_ADDR_STRING *ip = &a->IpAddressList;
		while (ip)
		{
			DWORD status;
			const DWORD context = ip->Context;

			if ((status = DeleteIPAddress ((ULONG) context)) == NO_ERROR)
			{
				msg (M_INFO, "Successfully deleted previously set dynamic IP/netmask: %s/%s",
					ip->IpAddress.String,
					ip->IpMask.String);
			}
			else
			{
				const char *empty = "0.0.0.0";
				if (strcmp (ip->IpAddress.String, empty) || strcmp (ip->IpMask.String, empty))
					msg (M_INFO, "NOTE: could not delete previously set dynamic IP/netmask: %s/%s (status=%u)",
						ip->IpAddress.String,
						ip->IpMask.String,
						(unsigned int) status);
			}
			ip = ip->Next;
		}
	}

	gc_free (&gc);
}

/*
 * Get interface index for use with IP Helper API functions.
 */
static DWORD
get_adapter_index_method_1 (const char *guid)
{
	DWORD index = TUN_ADAPTER_INDEX_INVALID;
	ULONG aindex = 0L;
	wchar_t wbuf[256];

	_snwprintf (wbuf, SIZE (wbuf), L"\\DEVICE\\TCPIP_%S", guid);
	wbuf[SIZE (wbuf) - 1] = 0;
	if (GetAdapterIndex (wbuf, &aindex) != NO_ERROR)
		index = TUN_ADAPTER_INDEX_INVALID;
	else
		index = (DWORD) aindex;

	return index;
}

static DWORD
get_adapter_index_method_2 (const char *guid)
{
	struct gc_arena gc = gc_new ();
	DWORD index = TUN_ADAPTER_INDEX_INVALID;
	const IP_ADAPTER_INFO *list = get_adapter_info_list (&gc);

	while (list)
	{
		if (!strcmp (guid, list->AdapterName))
		{
			index = list->Index;
			break;
		}
		list = list->Next;
	}

	gc_free (&gc);
	return index;
}

static DWORD
get_adapter_index (const char *guid)
{
	DWORD index = get_adapter_index_method_1 (guid);
	if (index == TUN_ADAPTER_INDEX_INVALID)
		index = get_adapter_index_method_2 (guid);
	if (index == TUN_ADAPTER_INDEX_INVALID)
		msg (M_INFO, "NOTE: could not get adapter index for %s", guid);
	return index;
}

DWORD
get_adapter_index_flexible (const char *name) /* actual name or GUID */
{
	struct gc_arena gc = gc_new ();
	DWORD index = get_adapter_index_method_1 (name);
	if (index == TUN_ADAPTER_INDEX_INVALID)
		index = get_adapter_index_method_2 (name);
	if (index == TUN_ADAPTER_INDEX_INVALID)
	{
		const struct tap_reg *tap_reg = get_tap_reg (&gc);
		const struct panel_reg *panel_reg = get_panel_reg (&gc);
		const char *guid = name_to_guid (name, tap_reg, panel_reg);
		index = get_adapter_index_method_1 (guid);
		if (index == TUN_ADAPTER_INDEX_INVALID)
			index = get_adapter_index_method_2 (guid);
	}
	if (index == TUN_ADAPTER_INDEX_INVALID)
		msg (M_INFO, "NOTE: could not get adapter index for name/GUID '%s'", name);
	gc_free (&gc);
	return index;
}

/*
 * Return a string representing a PIP_ADDR_STRING
 */
static const char *
format_ip_addr_string (const IP_ADDR_STRING *ip, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (256, gc);
	while (ip)
	{
		buf_printf (&out, "%s", ip->IpAddress.String);
		if (strlen (ip->IpMask.String))
		{
			buf_printf (&out, "/");
			buf_printf (&out, "%s", ip->IpMask.String);
		}
		buf_printf (&out, " ");
		ip = ip->Next;
	}
	return BSTR (&out);
}

/*
 * Show info for a single adapter
 */
static void
show_adapter (int msglev, const IP_ADAPTER_INFO *a, struct gc_arena *gc)
{
	msg (msglev, "%s", a->Description);
	msg (msglev, "  Index = %d", (int)a->Index);
	msg (msglev, "  GUID = %s", a->AdapterName);
	msg (msglev, "  IP = %s", format_ip_addr_string (&a->IpAddressList, gc));
	msg (msglev, "  MAC = %s", format_hex_ex (a->Address, a->AddressLength, 0, 1, ":", gc));
	msg (msglev, "  GATEWAY = %s", format_ip_addr_string (&a->GatewayList, gc));
	if (a->DhcpEnabled)
	{
		msg (msglev, "  DHCP SERV = %s", format_ip_addr_string (&a->DhcpServer, gc));
		msg (msglev, "  DHCP LEASE OBTAINED = %s", time_string (a->LeaseObtained, 0, false, gc));
		msg (msglev, "  DHCP LEASE EXPIRES  = %s", time_string (a->LeaseExpires, 0, false, gc));
	}
	if (a->HaveWins)
	{
		msg (msglev, "  PRI WINS = %s", format_ip_addr_string (&a->PrimaryWinsServer, gc));
		msg (msglev, "  SEC WINS = %s", format_ip_addr_string (&a->SecondaryWinsServer, gc));
	}

	{
		const IP_PER_ADAPTER_INFO *pai = get_per_adapter_info (a->Index, gc);
		if (pai)
		{
			msg (msglev, "  DNS SERV = %s", format_ip_addr_string (&pai->DnsServerList, gc));
		}
	}
}

/*
 * Show current adapter list
 */
void
show_adapters (int msglev)
{
	struct gc_arena gc = gc_new ();
	const IP_ADAPTER_INFO *ai = get_adapter_info_list (&gc);

	msg (msglev, "SYSTEM ADAPTER LIST");
	if (ai)
	{
		const IP_ADAPTER_INFO *a;

		/* find index in the linked list */
		for (a = ai; a != NULL; a = a->Next)
		{
			show_adapter (msglev, a, &gc);
		}
	}
	gc_free (&gc);
}

/*
 * Set a particular TAP-Windows adapter (or all of them if
 * adapter_name == NULL) to allow it to be opened from
 * a non-admin account.  This setting will only persist
 * for the lifetime of the device object.
 */

static void
tap_allow_nonadmin_access_handle (const char *device_path, HANDLE hand)
{
	struct security_attributes sa;
	BOOL status;

	if (!init_security_attributes_allow_all (&sa))
		msg (M_ERR, "Error: init SA failed");

	status = SetKernelObjectSecurity (hand, DACL_SECURITY_INFORMATION, &sa.sd);
	if (!status)
	{
		msg (M_ERRNO, "Error: SetKernelObjectSecurity failed on %s", device_path);
	}
	else
	{
		msg (M_INFO|M_NOPREFIX, "TAP-Windows device: %s [Non-admin access allowed]", device_path);
	}
}

void
tap_allow_nonadmin_access (const char *dev_node)
{
	struct gc_arena gc = gc_new ();
	const struct tap_reg *tap_reg = get_tap_reg (&gc);
	const struct panel_reg *panel_reg = get_panel_reg (&gc);
	const char *device_guid = NULL;
	HANDLE hand;
	char actual_buffer[256];
	char device_path[256];

	at_least_one_tap_win (tap_reg);

	if (dev_node)
	{
		/* Get the device GUID for the device specified with --dev-node. */
		device_guid = get_device_guid (dev_node, actual_buffer, sizeof (actual_buffer), tap_reg, panel_reg, &gc);

		if (!device_guid)
			msg (M_FATAL, "TAP-Windows adapter '%s' not found", dev_node);

		/* Open Windows TAP-Windows adapter */
		openvpn_snprintf (device_path, sizeof (device_path), "%s%s%s",
			USERMODEDEVICEDIR,
			device_guid,
			TAP_WIN_SUFFIX);

		hand = CreateFileA (
			device_path,
			MAXIMUM_ALLOWED,
			0, /* was: FILE_SHARE_READ */
			0,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			0
			);

		if (hand == INVALID_HANDLE_VALUE)
			msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);

		tap_allow_nonadmin_access_handle (device_path, hand);
		CloseHandle (hand);
	}
	else 
	{
		int device_number = 0;

		/* Try opening all TAP devices */
		while (true)
		{
			device_guid = get_unspecified_device_guid (device_number, 
				actual_buffer, 
				sizeof (actual_buffer),
				tap_reg,
				panel_reg,
				&gc);

			if (!device_guid)
				break;

			/* Open Windows TAP-Windows adapter */
			openvpn_snprintf (device_path, sizeof (device_path), "%s%s%s",
				USERMODEDEVICEDIR,
				device_guid,
				TAP_WIN_SUFFIX);

			hand = CreateFileA (
				device_path,
				MAXIMUM_ALLOWED,
				0, /* was: FILE_SHARE_READ */
				0,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
				0
				);

			if (hand == INVALID_HANDLE_VALUE)
				msg (M_WARN, "CreateFile failed on TAP device: %s", device_path);
			else
			{
				tap_allow_nonadmin_access_handle (device_path, hand);
				CloseHandle (hand);
			}

			device_number++;
		}
	}
	gc_free (&gc);
}

/*
 * DHCP release/renewal
 */
bool
dhcp_release_by_adapter_index (const DWORD adapter_index)
{
	struct gc_arena gc = gc_new ();
	bool ret = false;
	const IP_ADAPTER_INDEX_MAP *inter = get_interface_info (adapter_index, &gc);

	if (inter)
	{
		DWORD status = IpReleaseAddress ((IP_ADAPTER_INDEX_MAP *)inter);
		if (status == NO_ERROR)
		{
			msg (D_TUNTAP_INFO, "TAP: DHCP address released");
			ret = true;
		}
		else
			msg (M_WARN, "NOTE: Release of DHCP-assigned IP address lease on TAP-Windows adapter failed: %s (code=%u)",
				strerror_win32 (status, &gc), (unsigned int) status);
	}

	gc_free (&gc);
	return ret;
}

static bool
dhcp_release (const struct tuntap *tt)
{
	if (tt && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->adapter_index != TUN_ADAPTER_INDEX_INVALID)
		return dhcp_release_by_adapter_index (tt->adapter_index);
	else
		return false;
}

bool
dhcp_renew_by_adapter_index (const DWORD adapter_index)
{
	struct gc_arena gc = gc_new ();
	bool ret = false;
	const IP_ADAPTER_INDEX_MAP *inter = get_interface_info (adapter_index, &gc);

	if (inter)
	{
		DWORD status = IpRenewAddress ((IP_ADAPTER_INDEX_MAP *)inter);
		if (status == NO_ERROR)
		{
			msg (D_TUNTAP_INFO, "TAP: DHCP address renewal succeeded");
			ret = true;
		}
		else
			msg (M_WARN, "WARNING: Failed to renew DHCP IP address lease on TAP-Windows adapter: %s (code=%u)",
				strerror_win32 (status, &gc), (unsigned int) status);
	}
	gc_free (&gc);
	return ret;
}

static bool
dhcp_renew (const struct tuntap *tt)
{
	if (tt && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->adapter_index != TUN_ADAPTER_INDEX_INVALID)
		return dhcp_renew_by_adapter_index (tt->adapter_index);
	else
		return false;
}

/*
 * netsh functions
 */

static void
netsh_command (const struct argv *a, int n, int msglevel)
{
	int i;
	bool status;

	for (i = 0; i < n; ++i)
	{
		openvpn_sleep (1);
		netcmd_semaphore_lock ();
		argv_msg_prefix (M_INFO, a, "NETSH");
		status = openvpn_execve_check (a, NULL, 0, "ERROR: netsh command failed");
		netcmd_semaphore_release ();
		if (status)
			return;
		openvpn_sleep (4);
	}

	msg (msglevel, "NETSH: command failed");
}

void
ipconfig_register_dns (const struct env_set *es)
{
	struct argv argv;
	bool status;
	const char err[] = "ERROR: Windows ipconfig command failed";

	msg (D_TUNTAP_INFO, "Start net commands...");
	netcmd_semaphore_lock ();

	argv_init (&argv);

	/**
	 * OpenVPN no longer restarts the `dnscache` service, this had unwanted side effects,
	 * and seems to be no longer necessary with currently supported Windows versions.
	 */

	argv_printf (&argv, "%s%sc /flushdns", get_win_sys_path (), WIN_IPCONFIG_PATH_SUFFIX);
	argv_msg (D_TUNTAP_INFO, &argv);
	status = openvpn_execve_check (&argv, es, 0, err);
	argv_reset (&argv);

	argv_printf (&argv, "%s%sc /registerdns", get_win_sys_path (), WIN_IPCONFIG_PATH_SUFFIX);
	argv_msg (D_TUNTAP_INFO, &argv);
	status = openvpn_execve_check (&argv, es, 0, err);
	argv_reset (&argv);

	netcmd_semaphore_release ();
	msg (D_TUNTAP_INFO, "End net commands...");
}

void
ip_addr_string_to_array (in_addr_t *dest, int *dest_len, const IP_ADDR_STRING *src)
{
	int i = 0;

	while (src)
	{
		const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
		const char *ip_str = src->IpAddress.String;
		in_addr_t ip = 0;
		bool succeed = false;

		if (i >= *dest_len)
			break;
		if (!ip_str || !strlen (ip_str))
			break;

		ip = getaddr (getaddr_flags, ip_str, 0, &succeed, NULL);
		if (!succeed)
			break;
		dest[i++] = ip;

		src = src->Next;
	}
	*dest_len = i;

#if 0
	{
		struct gc_arena gc = gc_new ();

		msg (M_INFO, "ip_addr_string_to_array [%d]", *dest_len);
		for (i = 0; i < *dest_len; ++i)
		{
			msg (M_INFO, "%s", print_in_addr_t (dest[i], 0, &gc));
		}
		gc_free (&gc);
	}
#endif
}

static bool
ip_addr_one_to_one (const in_addr_t *a1, const int a1len, const IP_ADDR_STRING *ias)
{
	in_addr_t a2[8];
	int a2len = SIZE (a2);
	int i;

	ip_addr_string_to_array (a2, &a2len, ias);
	/*msg (M_INFO, "a1len=%d a2len=%d", a1len, a2len);*/
	if (a1len != a2len)
		return false;

	for (i = 0; i < a1len; ++i)
	{
		if (a1[i] != a2[i])
			return false;
	}

	return true;
}

static bool
ip_addr_member_of (const in_addr_t addr, const IP_ADDR_STRING *ias)
{
	in_addr_t aa[8];
	int len = SIZE (aa);
	int i;

	ip_addr_string_to_array (aa, &len, ias);
	for (i = 0; i < len; ++i)
	{
		if (addr == aa[i])
			return true;
	}
	return false;
}

static void
netsh_ifconfig_options (const char *type, const in_addr_t *addr_list, const int addr_len,
		const IP_ADDR_STRING *current, const char *flex_name, const bool test_first)
{
	struct gc_arena gc = gc_new ();
	struct argv argv = argv_new ();
	bool delete_first = false;
	char iface[64];
	DWORD index;

	index = get_adapter_index_flexible (flex_name);
	openvpn_snprintf (iface, sizeof (iface), "name=%lu", index);

	/* first check if we should delete existing DNS/WINS settings from TAP interface */
	if (test_first)
	{
		if (!ip_addr_one_to_one (addr_list, addr_len, current))
			delete_first = true;
	}
	else
		delete_first = true;

	/* delete existing DNS/WINS settings from TAP interface */
	if (delete_first)
	{
		argv_printf (&argv, "%s%sc interface ip delete %s %s all",
			get_win_sys_path (),
			NETSH_PATH_SUFFIX,
			type,
			win32_version_info () == WIN_XP ? flex_name : iface);
		netsh_command (&argv, 2, M_FATAL);
	}

	/* add new DNS/WINS settings to TAP interface */
	{
		int count = 0, i;

		for (i = 0; i < addr_len; ++i)
		{
			if (delete_first || !test_first || !ip_addr_member_of (addr_list[i], current))
			{
				const char *fmt = count ? "%s%sc interface ip add %s %s %s"
					: "%s%sc interface ip set %s %s static %s";

				argv_printf (&argv, fmt,
					get_win_sys_path (),
					NETSH_PATH_SUFFIX,
					type,
					win32_version_info () == WIN_XP ? flex_name : iface,
					print_in_addr_t (addr_list[i], 0, &gc));
				netsh_command (&argv, 2, M_FATAL);

				++count;
			}
			else
			{
				msg (M_INFO, "NETSH: \"%s\" %s %s [already set]",
					flex_name,
					type,
					print_in_addr_t (addr_list[i], 0, &gc));
			}
		}
	}

	argv_reset (&argv);
	gc_free (&gc);
}

static void
init_ip_addr_string2 (IP_ADDR_STRING *dest, const IP_ADDR_STRING *src1, const IP_ADDR_STRING *src2)
{
	CLEAR (dest[0]);
	CLEAR (dest[1]);
	if (src1)
	{
		dest[0] = *src1;
		dest[0].Next = NULL;
	}
	if (src2)
	{
		dest[1] = *src2;
		dest[0].Next = &dest[1];
		dest[1].Next = NULL;
	}
}

static void
netsh_ifconfig (const struct tuntap_options *to, const char *flex_name, const in_addr_t ip,
		const in_addr_t netmask, const unsigned int flags)
{
	struct gc_arena gc = gc_new ();
	struct argv argv = argv_new ();
	const IP_ADAPTER_INFO *ai = NULL;
	const IP_PER_ADAPTER_INFO *pai = NULL;
	const IP_ADAPTER_INFO *list = get_adapter_info_list (&gc);
	const DWORD index = get_adapter_index_flexible (flex_name);

	if (flags & NI_TEST_FIRST)
	{
		ai = get_adapter (list, index);
		pai = get_per_adapter_info (index, &gc);
	}

	if (flags & NI_IP_NETMASK)
	{
		if (test_adapter_ip_netmask (ai, ip, netmask))
		{
			msg (M_INFO, "NETSH: \"%s\" %s/%s [already set]",
				flex_name,
				print_in_addr_t (ip, 0, &gc),
				print_in_addr_t (netmask, 0, &gc));
		}
		else
		{
			char iface[64];

			openvpn_snprintf (iface, sizeof (iface), "name=%lu", index);

			/* example: netsh interface ip set address name=42 static 10.3.0.1 255.255.255.0 */
			argv_printf (&argv, "%s%sc interface ip set address %s static %s %s",
				get_win_sys_path (),
				NETSH_PATH_SUFFIX,
				win32_version_info () == WIN_XP ? flex_name : iface,
				print_in_addr_t (ip, 0, &gc),
				print_in_addr_t (netmask, 0, &gc));

			netsh_command (&argv, 4, M_FATAL);
		}
	}

	/* set WINS/DNS options */
	if (flags & NI_OPTIONS)
	{
		IP_ADDR_STRING wins[2];

		CLEAR (wins[0]);
		CLEAR (wins[1]);

		netsh_ifconfig_options ("dns",
			to->dns,
			to->dns_len,
			pai ? &pai->DnsServerList : NULL,
			flex_name,
			BOOL_CAST (flags & NI_TEST_FIRST));
		if (ai && ai->HaveWins)
			init_ip_addr_string2 (wins, &ai->PrimaryWinsServer, &ai->SecondaryWinsServer);

		netsh_ifconfig_options ("wins",
			to->wins,
			to->wins_len,
			ai ? wins : NULL,
			flex_name,
			BOOL_CAST (flags & NI_TEST_FIRST));
	}

	argv_reset (&argv);
	gc_free (&gc);
}

static void
netsh_enable_dhcp (const struct tuntap_options *to, const char *actual_name, DWORD adapter_index)
{
	struct argv argv;
	char iface[64];

	argv_init (&argv);
	openvpn_snprintf (iface, sizeof (iface), "name=%lu", adapter_index);

	/* example: netsh interface ip set address name=42 dhcp */
	argv_printf (&argv, "%s%sc interface ip set address %s dhcp",
		get_win_sys_path (),
		NETSH_PATH_SUFFIX,
		win32_version_info () == WIN_XP ? actual_name : iface);

	netsh_command (&argv, 4, M_FATAL);

	argv_reset(&argv);

	/* example: netsh interface ip set dns name=42 dhcp */
	argv_printf(&argv, "%s%sc interface ip set dns %s dhcp",
		get_win_sys_path(),
		NETSH_PATH_SUFFIX,
		win32_version_info() == WIN_XP ? actual_name : iface);

	netsh_command(&argv, 4, M_FATAL);

	argv_reset (&argv);
}

/*
 * Return a TAP name for netsh commands.
 */
static const char *
netsh_get_id (const char *dev_node, struct gc_arena *gc)
{
	const struct tap_reg *tap_reg = get_tap_reg (gc);
	const struct panel_reg *panel_reg = get_panel_reg (gc);
	struct buffer actual = alloc_buf_gc (256, gc);
	const char *guid;

	at_least_one_tap_win (tap_reg);

	if (dev_node)
	{
		guid = get_device_guid (dev_node, BSTR (&actual), BCAP (&actual), tap_reg, panel_reg, gc);
	}
	else
	{
		guid = get_unspecified_device_guid (0, BSTR (&actual), BCAP (&actual), tap_reg, panel_reg, gc);

		/* 存在多个TAP设备时, 使用第一个空闲的TAP设备 */
//		if (get_unspecified_device_guid (1, NULL, 0, tap_reg, panel_reg, gc)) /* ambiguous if more than one TAP-Windows adapter */
//			guid = NULL;
	}

	if (!guid)
		return "NULL";         /* not found */
	else if (strcmp (BSTR (&actual), "NULL"))
		return BSTR (&actual); /* control panel name */
	else
		return guid;           /* no control panel name, return GUID instead */
}

/*
 * Called iteratively on TAP-Windows wait-for-initialization polling loop
 */
void
tun_standby_init (struct tuntap *tt)
{
	tt->standby_iter = 0;
}

bool
tun_standby (struct tuntap *tt)
{
	bool ret = true;

	++tt->standby_iter;
	if (tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
	{
		if (tt->standby_iter == IPW32_SET_ADAPTIVE_TRY_NETSH)
		{
			if (dhcp_status (tt->adapter_index) != DHCP_STATUS_DISABLED)
				tt->enable_dhcp = true;	/* 关闭tun设备时, 重新启用dhcp */
			msg (M_INFO, "NOTE: now trying netsh (this may take some time)");
			netsh_ifconfig (&tt->options, tt->actual_name, tt->local, tt->adapter_netmask,
				NI_TEST_FIRST|NI_IP_NETMASK|NI_OPTIONS);
		}
		else if (tt->standby_iter >= IPW32_SET_ADAPTIVE_TRY_NETSH * 2)
		{
			ret = false;
		}
	}

	return ret;
}

/*
 * Convert DHCP options from the command line / config file into a raw DHCP-format options string.
 */

static void
write_dhcp_u8 (struct buffer *buf, const int type, const int data, bool *error)
{
	if (!buf_safe (buf, 3))
	{
		*error = true;
		msg (M_WARN, "write_dhcp_u8: buffer overflow building DHCP options");
		return;
	}
	buf_write_u8 (buf, type);
	buf_write_u8 (buf, 1);
	buf_write_u8 (buf, data);
}

static void
write_dhcp_u32_array (struct buffer *buf, const int type, const uint32_t *data, const unsigned int len, bool *error)
{
	if (len > 0)
	{
		int i;
		const int size = len * sizeof (uint32_t);

		if (!buf_safe (buf, 2 + size))
		{
			*error = true;
			msg (M_WARN, "write_dhcp_u32_array: buffer overflow building DHCP options");
			return;
		}
		if (size < 1 || size > 255)
		{
			*error = true;
			msg (M_WARN, "write_dhcp_u32_array: size (%d) must be > 0 and <= 255", size);
			return;
		}
		buf_write_u8 (buf, type);
		buf_write_u8 (buf, size);
		for (i = 0; i < (int) len; ++i)
			buf_write_u32 (buf, data[i]);
	}
}

static void
write_dhcp_str (struct buffer *buf, const int type, const char *str, bool *error)
{
	const size_t len = strlen (str);
	if (!buf_safe (buf, 2 + (int) len))
	{
		*error = true;
		msg (M_WARN, "write_dhcp_str: buffer overflow building DHCP options");
		return;
	}
	if (len < 1 || len > 255)
	{
		*error = true;
		msg (M_WARN, "write_dhcp_str: string '%s' must be > 0 bytes and <= 255 bytes", str);
		return;
	}
	buf_write_u8 (buf, type);
	buf_write_u8 (buf, (int) len);
	buf_write (buf, str, (int) len);
}

static bool
build_dhcp_options_string (struct buffer *buf, const struct tuntap_options *o)
{
	bool error = false;
	if (o->domain)
		write_dhcp_str (buf, 15, o->domain, &error);

	if (o->netbios_scope)
		write_dhcp_str (buf, 47, o->netbios_scope, &error);

	if (o->netbios_node_type)
		write_dhcp_u8 (buf, 46, o->netbios_node_type, &error);

	write_dhcp_u32_array (buf, 6, (uint32_t *) o->dns, o->dns_len, &error);
	write_dhcp_u32_array (buf, 44, (uint32_t *) o->wins, o->wins_len, &error);
	write_dhcp_u32_array (buf, 42, (uint32_t *) o->ntp, o->ntp_len, &error);
	write_dhcp_u32_array (buf, 45, (uint32_t *) o->nbdd, o->nbdd_len, &error);

	/* the MS DHCP server option 'Disable Netbios-over-TCP/IP is implemented as vendor option 001,
	value 002. A value of 001 means 'leave NBT alone' which is the default */
	if (o->disable_nbt)
	{
		if (!buf_safe (buf, 8))
		{
			msg (M_WARN, "build_dhcp_options_string: buffer overflow building DHCP options");
			return false;
		}
		buf_write_u8 (buf,  43);
		buf_write_u8 (buf,  6);  /* total length field */
		buf_write_u8 (buf,  0x001);
		buf_write_u8 (buf,  4);  /* length of the vendor specified field */
		buf_write_u32 (buf, 0x002);
	}
	return !error;
}

static void
fork_dhcp_action (struct tuntap *tt)
{
	if (tt->options.dhcp_pre_release || tt->options.dhcp_renew)
	{
		struct gc_arena gc = gc_new ();
		struct buffer cmd = alloc_buf_gc (256, &gc);
		const int verb = 3;
		const int pre_sleep = 1;

		buf_printf (&cmd, "openvpn --verb %d --tap-sleep %d", verb, pre_sleep);
		if (tt->options.dhcp_pre_release)
			buf_printf (&cmd, " --dhcp-pre-release");
		if (tt->options.dhcp_renew)
			buf_printf (&cmd, " --dhcp-renew");
		buf_printf (&cmd, " --dhcp-internal %u", (unsigned int) tt->adapter_index);

		fork_to_self (BSTR (&cmd));
		gc_free (&gc);
	}
}

void
fork_register_dns_action (struct tuntap *tt)
{
	if (tt && tt->options.register_dns)
	{
		struct gc_arena gc = gc_new ();
		struct buffer cmd = alloc_buf_gc (256, &gc);
		const int verb = 3;

		buf_printf (&cmd, "openvpn --verb %d --register-dns --rdns-internal", verb);
		fork_to_self (BSTR (&cmd));
		gc_free (&gc);
	}
}

static uint32_t
dhcp_masq_addr (const in_addr_t local, const in_addr_t netmask, const int offset)
{
	struct gc_arena gc = gc_new ();
	in_addr_t dsa; /* DHCP server addr */

	if (offset < 0)
		dsa = (local | (~netmask)) + offset;
	else
		dsa = (local & netmask) + offset;

	if (dsa == local)
		msg (M_FATAL, "ERROR: There is a clash between the --ifconfig local address and the internal DHCP server address -- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the --ifconfig subnet for the internal DHCP server",
			print_in_addr_t (dsa, 0, &gc));

	if ((local & netmask) != (dsa & netmask))
		msg (M_FATAL, "ERROR: --ip-win32 dynamic [offset] : offset is outside of --ifconfig subnet");

	gc_free (&gc);
	return htonl (dsa);
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	struct gc_arena gc = gc_new ();
	char device_path[256];
	const char *device_guid = NULL;
	DWORD len;
	bool dhcp_masq = false;
	bool dhcp_masq_post = false;

	/*netcmd_semaphore_lock ();*/

	msg (M_INFO, "open_tun, tt->ipv6=%d", tt->ipv6);

	if (tt->type == DEV_TYPE_NULL)
	{
		open_null (tt);
		gc_free (&gc);
		return;
	}
	else if (tt->type == DEV_TYPE_TAP || tt->type == DEV_TYPE_TUN)
	{
		;
	}
	else
	{
		msg (M_FATAL|M_NOPREFIX, "Unknown virtual device type: '%s'", dev);
	}

	/* Lookup the device name in the registry, using the --dev-node high level name. */
	{
		const struct tap_reg *tap_reg = get_tap_reg (&gc);
		const struct panel_reg *panel_reg = get_panel_reg (&gc);
		char actual_buffer[256];

		at_least_one_tap_win (tap_reg);

		if (dev_node)
		{
			/* Get the device GUID for the device specified with --dev-node. */
			device_guid = get_device_guid (dev_node, actual_buffer, sizeof (actual_buffer), tap_reg, panel_reg, &gc);

			if (!device_guid)
				msg (M_FATAL, "TAP-Windows adapter '%s' not found", dev_node);

			/* Open Windows TAP-Windows adapter */
			openvpn_snprintf (device_path, sizeof (device_path), "%s%s%s", USERMODEDEVICEDIR,
				device_guid, TAP_WIN_SUFFIX);

			tt->hand = CreateFileA (
				device_path,
				GENERIC_READ | GENERIC_WRITE,
				0, /* was: FILE_SHARE_READ */
				0,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
				0
				);

			if (tt->hand == INVALID_HANDLE_VALUE)
				msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);
		}
		else 
		{
			int device_number = 0;

			/* Try opening all TAP devices until we find one available */
			while (true)
			{
				device_guid = get_unspecified_device_guid (device_number, actual_buffer, 
					sizeof (actual_buffer), tap_reg, panel_reg, &gc);

				if (!device_guid)
				{
					msg (M_FATAL, "All TAP-Windows adapters on this system are currently in use.");
					break;
				}

				/* Open Windows TAP-Windows adapter */
				openvpn_snprintf (device_path, sizeof (device_path), "%s%s%s", USERMODEDEVICEDIR,
					device_guid, TAP_WIN_SUFFIX);

				tt->hand = CreateFileA (
					device_path,
					GENERIC_READ | GENERIC_WRITE,
					0, /* was: FILE_SHARE_READ */
					0,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
					0
					);

				if (tt->hand == INVALID_HANDLE_VALUE)
					msg (D_TUNTAP_INFO, "CreateFile failed on TAP device: %s", device_path);
				else
					break;

				device_number++;
			}
		}

		/* translate high-level device name into a device instance GUID using the registry */
		tt->actual_name = string_alloc (actual_buffer, NULL);
	}

	tt->adapter_index = get_adapter_index (device_guid);
	msg (M_INFO, "TAP-WIN32 device [%u] [%s] opened: %s", (unsigned int) tt->adapter_index, tt->actual_name, device_path);

	/* get driver version info */
	if (tt->hand)
	{
		ULONG info[3];
		CLEAR (info);
		if (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_VERSION, &info, sizeof (info),
				&info, sizeof (info), &len, NULL))
		{
			msg (D_TUNTAP_INFO, "TAP-Windows Driver Version %d.%d %s", (int) info[0], (int) info[1],
				(info[2] ? "(DEBUG)" : ""));
		}
		if (!(info[0] == TAP_WIN_MIN_MAJOR && info[1] >= TAP_WIN_MIN_MINOR))
		{
			msg (M_FATAL, "ERROR:  This version of " PACKAGE_NAME " requires a TAP-Windows driver that is at least version %d.%d -- If you recently upgraded your " PACKAGE_NAME " distribution, a reboot is probably required at this point to get Windows to see the new driver.",
				TAP_WIN_MIN_MAJOR,
				TAP_WIN_MIN_MINOR);
		}
		/* usage of numeric constants is ugly, but this is really tied to *this* version of the driver */
		if (tt->ipv6 && tt->type == DEV_TYPE_TUN && info[0] == 9 && info[1] < 8)
		{
			msg (M_INFO, "WARNING:  Tap-Win32 driver version %d.%d does not support IPv6 in TUN mode.  IPv6 will be disabled.  Upgrade to Tap-Win32 9.8 (2.2-beta3 release or later) or use TAP mode to get IPv6", (int) info[0], (int) info[1]);
			tt->ipv6 = false;
		}

		/* tap driver 9.8 (2.2.0 and 2.2.1 release) is buggy */
		if (tt->type == DEV_TYPE_TUN && info[0] == 9 && info[1] == 8)
		{
			msg (M_FATAL, "ERROR:  Tap-Win32 driver version %d.%d is buggy regarding small IPv4 packets in TUN mode.  Upgrade to Tap-Win32 9.9 (2.2.2 release or later) or use TAP mode", (int) info[0], (int) info[1]);
		}
	}

	/* get driver MTU */
	{
		ULONG mtu = 0L;
		if (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_MTU, &mtu, sizeof (mtu), &mtu, sizeof (mtu), &len, NULL))
		{
			tt->post_open_mtu = (int) mtu;
			msg (D_MTU_INFO, "TAP-Windows MTU=%d", (int) mtu);
		}
	}

	/*
	 * Preliminaries for setting TAP-Windows adapter TCP/IP
	 * properties via --ip-win32 dynamic or --ip-win32 adaptive.
	 */
	if (tt->did_ifconfig_setup)
	{
		if (tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ)
		{
			/* If adapter is set to non-DHCP, set to DHCP mode. */
			if (dhcp_status (tt->adapter_index) == DHCP_STATUS_DISABLED)
			{
				netsh_enable_dhcp (&tt->options, tt->actual_name, tt->adapter_index);
			}
			dhcp_masq = true;
			dhcp_masq_post = true;
		}
		else if (tt->options.ip_win32_type == IPW32_SET_ADAPTIVE)
		{
			/* If adapter is set to non-DHCP, use netsh right away. */
			if (dhcp_status (tt->adapter_index) != DHCP_STATUS_ENABLED)
			{
				netsh_ifconfig (&tt->options, tt->actual_name, tt->local, tt->adapter_netmask,
					NI_TEST_FIRST|NI_IP_NETMASK|NI_OPTIONS);
			}
			else
			{
				dhcp_masq = true;
			}
		}
	}

	/* set point-to-point mode if TUN device */
	if (tt->type == DEV_TYPE_TUN)
	{
		if (!tt->did_ifconfig_setup)
		{
			msg (M_FATAL, "ERROR: --dev tun also requires --ifconfig");
		}

		if (tt->topology == TOP_SUBNET)
		{
			in_addr_t ep[3];
			BOOL status;

			ep[0] = htonl (tt->local);
			ep[1] = htonl (tt->local & tt->remote_netmask);
			ep[2] = htonl (tt->remote_netmask);

			status = DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_TUN, ep, sizeof (ep),
				ep, sizeof (ep), &len, NULL);

			msg (status ? M_INFO : M_FATAL, "Set TAP-Windows TUN subnet mode network/local/netmask = %s/%s/%s [%s]",
				print_in_addr_t (ep[1], IA_NET_ORDER, &gc),
				print_in_addr_t (ep[0], IA_NET_ORDER, &gc),
				print_in_addr_t (ep[2], IA_NET_ORDER, &gc),
				status ? "SUCCEEDED" : "FAILED");
		}
		else
		{
			in_addr_t ep[2];
			ep[0] = htonl (tt->local);
			ep[1] = htonl (tt->remote_netmask);

			if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT, ep, sizeof (ep),
					ep, sizeof (ep), &len, NULL))
				msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set Point-to-Point mode, which is required for --dev tun");
		}
	}

	/* should we tell the TAP-Windows driver to masquerade as a DHCP server as a means of setting the adapter address? */
	if (dhcp_masq)
	{
		uint32_t ep[4];

		/* We will answer DHCP requests with a reply to set IP/subnet to these values */
		ep[0] = htonl (tt->local);
		ep[1] = htonl (tt->adapter_netmask);

		/* At what IP address should the DHCP server masquerade at? */
		if (tt->type == DEV_TYPE_TUN)
		{
			if (tt->topology == TOP_SUBNET)
			{
				if (tt->options.dhcp_masq_custom_offset)
					ep[2] = dhcp_masq_addr (tt->local, tt->remote_netmask, tt->options.dhcp_masq_offset);
				else
					ep[2] = dhcp_masq_addr (tt->local, tt->remote_netmask, -1);
			}
			else
				ep[2] = htonl (tt->remote_netmask);
		}
		else
		{
			ASSERT (tt->type == DEV_TYPE_TAP);
			ep[2] = dhcp_masq_addr (tt->local, tt->adapter_netmask, tt->options.dhcp_masq_custom_offset ? tt->options.dhcp_masq_offset : 0);
		}

		/* lease time in seconds */
		ep[3] = (uint32_t) tt->options.dhcp_lease_time;

		ASSERT (ep[3] > 0);

#ifndef SIMULATE_DHCP_FAILED /* this code is disabled to simulate bad DHCP negotiation */
		if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, ep, sizeof (ep),
				ep, sizeof (ep), &len, NULL))
			msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set TAP_WIN_IOCTL_CONFIG_DHCP_MASQ mode");

		msg (M_INFO, "Notified TAP-Windows driver to set a DHCP IP/netmask of %s/%s on interface %s [DHCP-serv: %s, lease-time: %d]",
			print_in_addr_t (tt->local, 0, &gc),
			print_in_addr_t (tt->adapter_netmask, 0, &gc),
			device_guid,
			print_in_addr_t (ep[2], IA_NET_ORDER, &gc),
			ep[3]
		);

		/* user-supplied DHCP options capability */
		if (tt->options.dhcp_options)
		{
			struct buffer buf = alloc_buf (256);
			if (build_dhcp_options_string (&buf, &tt->options))
			{
				msg (D_DHCP_OPT, "DHCP option string: %s", format_hex (BPTR (&buf), BLEN (&buf), 0, &gc));
				if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT, BPTR (&buf), BLEN (&buf),
						BPTR (&buf), BLEN (&buf), &len, NULL))
					msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT DeviceIoControl call");
			}
			else
				msg (M_WARN, "DHCP option string not set due to error");
			free_buf (&buf);
		}
#endif
	}

	/* set driver media status to 'connected' */
	{
		ULONG status = TRUE;
		if (!DeviceIoControl (tt->hand, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &status, sizeof (status),
				&status, sizeof (status), &len, NULL))
			msg (M_WARN, "WARNING: The TAP-Windows driver rejected a TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.");
	}

	/* possible wait for adapter to come up */
	{
		int s = tt->options.tap_sleep;
		if (s > 0)
		{
			msg (M_INFO, "Sleeping for %d seconds...", s);
			openvpn_sleep (s);
		}
	}

	/* possibly use IP Helper API to set IP address on adapter */
	{
		const DWORD index = tt->adapter_index;

		/* flush arp cache */
		if (index != TUN_ADAPTER_INDEX_INVALID)
		{
			DWORD status;

			if ((status = FlushIpNetTable (index)) == NO_ERROR)
				msg (M_INFO, "Successful ARP Flush on interface [%u] %s", (unsigned int) index, device_guid);
			else
				msg (D_TUNTAP_INFO, "NOTE: FlushIpNetTable failed on interface [%u] %s (status=%u) : %s",
					(unsigned int) index, device_guid, (unsigned int) status, strerror_win32 (status, &gc));
		}

		/*
		 * If the TAP-Windows driver is masquerading as a DHCP server
		 * make sure the TCP/IP properties for the adapter are set correctly.
		 */
		if (dhcp_masq_post)
		{
			/* check dhcp enable status */
			if (dhcp_status (index) == DHCP_STATUS_DISABLED)
				msg (M_WARN, "WARNING: You have selected '--ip-win32 dynamic', which will not work unless the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");

			/* force an explicit DHCP lease renewal on TAP adapter? */
			if (tt->options.dhcp_pre_release)
				dhcp_release (tt);
			if (tt->options.dhcp_renew)
				dhcp_renew (tt);
		}
		else
			fork_dhcp_action (tt);

		if (tt->did_ifconfig_setup && tt->options.ip_win32_type == IPW32_SET_IPAPI)
		{
			DWORD status;
			const char *error_suffix = "I am having trouble using the Windows 'IP helper API' to automatically set the IP address -- consider using other --ip-win32 methods (not 'ipapi')";

			/* couldn't get adapter index */
			if (index == TUN_ADAPTER_INDEX_INVALID)
			{
				msg (M_FATAL, "ERROR: unable to get adapter index for interface %s -- %s", device_guid, error_suffix);
			}

			/* check dhcp enable status */
			if (dhcp_status (index) == DHCP_STATUS_DISABLED)
				msg (M_WARN, "NOTE: You have selected (explicitly or by default) '--ip-win32 ipapi', which has a better chance of working correctly if the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");

			/* delete previously added IP addresses which were not correctly deleted */
			delete_temp_addresses (index);

			/* add a new IP address */
			if ((status = AddIPAddress (htonl (tt->local), htonl (tt->adapter_netmask),
					index, &tt->ipapi_context, &tt->ipapi_instance)) == NO_ERROR)
				msg (M_INFO, "Succeeded in adding a temporary IP/netmask of %s/%s to interface %s using the Win32 IP Helper API",
					print_in_addr_t (tt->local, 0, &gc),
					print_in_addr_t (tt->adapter_netmask, 0, &gc),
					device_guid);
			else
			{
				msg (M_FATAL, "ERROR: AddIPAddress %s/%s failed on interface %s, index=%d, status=%u (windows error: '%s') -- %s",
					print_in_addr_t (tt->local, 0, &gc),
					print_in_addr_t (tt->adapter_netmask, 0, &gc),
					device_guid,
					(int) index,
					(unsigned int) status,
					strerror_win32 (status, &gc),
					error_suffix);
			}
			tt->ipapi_context_defined = true;
		}
	}

	/*netcmd_semaphore_release ();*/

	gc_free (&gc);
}

const char *
tap_win_getinfo (const struct tuntap *tt, struct gc_arena *gc)
{
	if (tt && tt->hand != NULL)
	{
		struct buffer out = alloc_buf_gc (256, gc);
		DWORD len;
		if (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_INFO,
			BSTR (&out), BCAP (&out),
			BSTR (&out), BCAP (&out),
			&len, NULL))
		{
			return BSTR (&out);
		}
	}
	return NULL;
}

void
tun_show_debug (struct tuntap *tt)
{
	if (tt && tt->hand != NULL)
	{
		struct buffer out = alloc_buf (1024);
		DWORD len;
		while (DeviceIoControl (tt->hand, TAP_WIN_IOCTL_GET_LOG_LINE,
			BSTR (&out), BCAP (&out),
			BSTR (&out), BCAP (&out),
			&len, NULL))
		{
			msg (D_TAP_WIN_DEBUG, "TAP-Windows: %s", BSTR (&out));
		}
		free_buf (&out);
	}
}

void
close_tun (struct tuntap *tt)
{
	struct gc_arena gc = gc_new ();

	if (tt)
	{
		if (tt->ipv6 && tt->did_ifconfig_ipv6_setup && tt->actual_name)
		{
			const char *ifconfig_ipv6_local;
			struct argv argv;
			char iface[64];
			DWORD index;

			argv_init (&argv);
			index = get_adapter_index_flexible (tt->actual_name);
			openvpn_snprintf (iface, sizeof (iface), "interface=%lu", index);

			/* remove route pointing to interface */
			delete_route_connected_v6_net (tt, NULL);

			/* "store=active" is needed in Windows 8(.1) to delete the
			 * address we added (pointed out by Cedric Tabary).
			 */

			/* netsh interface ipv6 delete address \"%s\" %s */
			ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0,  &gc);
			argv_printf (&argv, "%s%sc interface ipv6 delete address %s %s store=active",
				get_win_sys_path (),
				NETSH_PATH_SUFFIX,
				win32_version_info () == WIN_XP ? tt->actual_name : iface,
				ifconfig_ipv6_local);

			netsh_command (&argv, 1, M_WARN);
			argv_reset (&argv);
		}
#if 1
		if (tt->ipapi_context_defined)
		{
			DWORD status;
			if ((status = DeleteIPAddress (tt->ipapi_context)) != NO_ERROR)
			{
				msg (M_WARN, "Warning: DeleteIPAddress[%u] failed on TAP-Windows adapter, status=%u : %s",
					(unsigned int) tt->ipapi_context,
					(unsigned int) status,
					strerror_win32 (status, &gc));
			}
		}
#endif

		if (tt->options.dhcp_release)
			dhcp_release (tt);

		if (tt->enable_dhcp)
		{
			/* If adapter is set to non-DHCP, set to DHCP mode. */
			if (dhcp_status (tt->adapter_index) == DHCP_STATUS_DISABLED)
			{
				msg (M_INFO, "TAP-Windows Adapter is set to non-DHCP, set to DHCP mode.");
				netsh_enable_dhcp (&tt->options, tt->actual_name, tt->adapter_index);
			}
		}

		if (tt->hand != NULL)
		{
			dmsg (D_WIN32_IO_LOW, "Attempting CancelIO on TAP-Windows adapter");
			if (!CancelIo (tt->hand))
				msg (M_WARN | M_ERRNO, "Warning: CancelIO failed on TAP-Windows adapter");
		}

		dmsg (D_WIN32_IO_LOW, "Attempting close of overlapped read event on TAP-Windows adapter");
		overlapped_io_close (&tt->reads);

		dmsg (D_WIN32_IO_LOW, "Attempting close of overlapped write event on TAP-Windows adapter");
		overlapped_io_close (&tt->writes);

		if (tt->hand != NULL)
		{
			dmsg (D_WIN32_IO_LOW, "Attempting CloseHandle on TAP-Windows adapter");
			if (!CloseHandle (tt->hand))
				msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on TAP-Windows adapter");
		}

		if (tt->actual_name)
			free (tt->actual_name);

		clear_tuntap (tt);
		free (tt);
	}

	gc_free (&gc);
}

/*
 * Convert --ip-win32 constants between index and ascii form.
 */

struct ipset_names
{
	const char *short_form;
};

/* Indexed by IPW32_SET_x */
static const struct ipset_names ipset_names[] = {
	{"manual"},
	{"netsh"},
	{"ipapi"},
	{"dynamic"},
	{"adaptive"}
};

int
ascii2ipset (const char* name)
{
	int i;
	ASSERT (IPW32_SET_N == SIZE (ipset_names));
	for (i = 0; i < IPW32_SET_N; ++i)
		if (!strcmp (name, ipset_names[i].short_form))
			return i;
	return -1;
}

const char *
ipset2ascii (int index)
{
	ASSERT (IPW32_SET_N == SIZE (ipset_names));
	if (index < 0 || index >= IPW32_SET_N)
		return "[unknown --ip-win32 type]";
	else
		return ipset_names[index].short_form;
}

const char *
ipset2ascii_all (struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (256, gc);
	int i;

	ASSERT (IPW32_SET_N == SIZE (ipset_names));
	for (i = 0; i < IPW32_SET_N; ++i)
	{
		if (i)
			buf_printf (&out, " ");
		buf_printf (&out, "[%s]", ipset2ascii (i));
	}
	return BSTR (&out);
}

#else /* generic */

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	open_tun_generic (dev, dev_type, dev_node, false, true, tt);
}

void
close_tun (struct tuntap* tt)
{
	if (tt)
	{
		close_tun_generic (tt);
		free (tt);
	}
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
	return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
	return read (tt->fd, buf, len);
}

#endif

#ifdef ENABLE_TUN_THREAD

void* do_tun_process (void *arg);

void tun_thread_start (struct transfer_context *tc)
{
	pthread_attr_t attr;

	pthread_attr_init (&attr);
	pthread_attr_setscope (&attr, PTHREAD_SCOPE_SYSTEM);	/* 绑定线程 */

	tc->terminate = false;
	tc->thread_idx = TUN_THREAD_INDEX;

	ASSERT (pthread_create (&tc->thread_id, NULL, do_tun_process, tc) == 0);

	pthread_attr_destroy (&attr);
}

void tun_thread_stop (struct transfer_context *tc)
{
	if (tc->thread_idx == 1 && !tc->terminate)
	{
		void *status = NULL;

		msg (M_INFO, "stop tun thread");

		/* 通知TUN设备读写线程终止 */
		tc->terminate = true;
		tc->thread_idx = -1;

		/* 唤醒TUN设备读写线程 */
		if (tc->m)
			event_wakeup (tc->m->top.c2.tun_event_set);
		else
			event_wakeup (tc->c->c2.tun_event_set);

		/* 等候TUN设备读写线程终止 */
		ASSERT (pthread_join (tc->thread_id, &status) == 0);
	}
}

/* Return the io_wait() flags appropriate for a point-to-point tunnel. */
static inline unsigned int
tun_p2p_iow_flags (struct context *c)
{
	unsigned int flags = 0;

	if (prepare_process_tun_any_incoming (c))
		flags |= IOW_READ_TUN;

	if (prepare_process_tun_p2p_outgoing (c))
		flags |= IOW_TO_TUN;

	return flags;
}

/* Return the io_wait() flags appropriate for a point-to-multipoint tunnel. */
static inline unsigned int
tun_p2mp_iow_flags (struct multi_context *m)
{
	unsigned int flags = 0;

	if (prepare_process_tun_any_incoming (&m->top))
		flags |= IOW_READ_TUN;

	if (prepare_process_tun_server_outgoing (m))
		flags |= IOW_TO_TUN;

	return flags;
}

void
tun_io_wait (struct context *c, const unsigned int flags)
{
	unsigned int tuntap = 0;
	int status, i;
	bool wakeup = false;
	struct timeval timeout = {1, 0};
	struct event_set_return esr[2];

	/* These shifts all depend on EVENT_READ and EVENT_WRITE */
	static int tun_shift = 2;        /* depends on TUN_READ and TUN_WRITE */
	static int err_shift = 4;        /* depends on ES_ERROR */

	c->c2.tun_event_set_status = 0;

	/* Decide what kind of events we want to wait for. */
	event_reset (c->c2.tun_event_set);

	/*
	 * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status
	 * from device.  Otherwise, wait for incoming data on TCP/UDP port.
	 */
	if (flags & IOW_TO_TUN)
		tuntap |= EVENT_WRITE;

	if (flags & IOW_READ_TUN)
		tuntap |= EVENT_READ;

	/* Configure event wait based on socket, tuntap flags. */
	tun_set (c->c1.tuntap, c->c2.tun_event_set, tuntap, (void*) &tun_shift, NULL);

	/*
	 * Possible scenarios:
	 *  (1) tun dev has data available to read
	 *  (2) tun dev is ready to accept more data to write
	 *  (3) timeout (tv) expired
	 */

	/* Wait for something to happen. */
	status = event_wait (c->c2.tun_event_set, &timeout, esr, SIZE (esr), &wakeup);
	check_status (status, "event_wait", NULL, NULL);

	if (status > 0)
	{
		for (i = 0; i < status; ++i)
		{
			const struct event_set_return *e = &esr[i];

			if (e->arg)
				c->c2.tun_event_set_status |= ((e->rwflags & 3) << *((int*) e->arg));
		}
	}
	else if (status == 0)
	{
		c->c2.tun_event_set_status = wakeup ? ES_WAKEUP : ES_TIMEOUT;
	}

	update_time (TUN_THREAD_INDEX);

	dmsg (D_EVENT_WAIT, "I/O WAIT status=0x%04x", c->c2.tun_event_set_status);
}

static inline void 
do_process_tun_p2p (struct context *c)
{
	const unsigned int status0 = c->c2.tun_event_set_status;
	unsigned int status1 = TUN_WRITE|TUN_READ;
	int io_loop = 0;

	do {
		/* Incoming data on TUN device */
		if ((status0 & TUN_READ) && (status1 & TUN_READ))
		{
			if (do_process_tun_p2p_read (c) <= 0)
				status1 &= ~TUN_READ;
		}

		/* TUN device ready to accept write */
		if ((status0 & TUN_WRITE) && (status1 & TUN_WRITE))
		{
			if (do_process_tun_p2p_write (c) <= 0)
				status1 &= ~TUN_WRITE;
		}

		if (status1 & TUN_READ)
		{
			if (prepare_process_tun_any_incoming (c) == 0)
				status1 &= ~TUN_READ;
		}

		if (status1 & TUN_WRITE)
		{
			if (prepare_process_tun_p2p_outgoing (c) == 0)
				status1 &= ~TUN_WRITE;
		}

	} while (c->options.shaper <= 0 && status1 != 0 && ++io_loop < MAX_PROCESS_IO_LOOP);
}

static inline void 
do_process_tun_server (struct multi_context *m)
{
	const unsigned int status0 = m->top.c2.tun_event_set_status;
	unsigned int status1 = TUN_WRITE|TUN_READ;
	int io_loop = 0;

	do {
		/* Incoming data on TUN device */
		if ((status0 & TUN_READ) && (status1 & TUN_READ))
		{
			if (do_process_tun_server_read (m) <= 0)
				status1 &= ~TUN_READ;
		}

		/* TUN device ready to accept write */
		if ((status0 & TUN_WRITE) && (status1 & TUN_WRITE))
		{
			if (do_process_tun_server_write (m, 0) <= 0)
				status1 &= ~TUN_WRITE;
		}

		if (status1 & TUN_READ)
		{
			if (prepare_process_tun_any_incoming (&m->top) == 0)
				status1 &= ~TUN_READ;
		}

		if (status1 & TUN_WRITE)
		{
			if (prepare_process_tun_server_outgoing (m) == 0)
				status1 &= ~TUN_WRITE;
		}

	} while (status1 != 0 && ++io_loop < MAX_PROCESS_IO_LOOP);
}

void* 
do_tun_process (void *arg)
{
	struct transfer_context *tc = (struct transfer_context *) arg;
#ifdef PERF_STATS_CHECK
	time_t last_print_perf_status;
#endif

#ifdef ENABLE_THREAD_NAME
	set_thread_name (PACKAGE "/tun");
#endif

#ifdef TARGET_LINUX
	if (tc->c->options.bind_cpu)
		set_thread_cpu (pthread_self (), 2);
#endif

	update_time (TUN_THREAD_INDEX);
#ifdef PERF_STATS_CHECK
	last_print_perf_status = now_sec (TUN_THREAD_INDEX);
#endif

	while (!tc->terminate)
	{
		switch (tc->c->options.mode)
		{
		case MODE_POINT_TO_POINT:
			tun_io_wait (tc->c, tun_p2p_iow_flags (tc->c));
			do_process_tun_p2p (tc->c);
			break;
#if P2MP_SERVER
		case MODE_SERVER:
			tun_io_wait (&tc->m->top, tun_p2mp_iow_flags (tc->m));
			do_process_tun_server (tc->m);
			break;
#endif
		default:
			ASSERT (0);
		}

#ifdef PERF_STATS_CHECK
		if (now_sec (TUN_THREAD_INDEX) > last_print_perf_status + 300 + TUN_THREAD_INDEX)
		{
			print_perf_status (tc->c, TUN_THREAD_INDEX);
			last_print_perf_status = now_sec (TUN_THREAD_INDEX);
		}
#endif
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ERR_remove_thread_state (NULL);
#endif

	return tc;
}

#endif
