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

#ifndef FDMISC_H
#define FDMISC_H

#include "basic.h"
#include "error.h"
#include "syshead.h"

#ifdef __cplusplus
extern "C" {
#endif

bool set_nonblock_action (socket_descriptor_t fd);
bool set_cloexec_action (socket_descriptor_t fd);

void set_nonblock (socket_descriptor_t fd);
void set_cloexec (socket_descriptor_t fd);

static inline void openvpn_fd_set (socket_descriptor_t fd, fd_set *setp)
{
#ifndef WIN32 /* The Windows FD_SET() implementation does not overflow */
	ASSERT (fd >= 0 && fd < FD_SETSIZE);
#endif
	FD_SET (fd, setp);
}

#undef FD_SET /* prevent direct use of FD_SET() */

#ifdef __cplusplus
}
#endif

#endif
