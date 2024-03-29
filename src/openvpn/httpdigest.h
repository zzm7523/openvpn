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

#ifndef HTTPDIGEST_H
#define HTTPDIGEST_H

#if PROXY_DIGEST_AUTH

#ifdef __cplusplus
extern "C" {
#endif

#define HASHLEN 16
typedef unsigned char HASH[HASHLEN];
#define HASHHEXLEN 32
typedef unsigned char HASHHEX[HASHHEXLEN+1];
#undef IN
#undef OUT
#define IN const
#define OUT

/* calculate H(A1) as per HTTP Digest spec */
void DigestCalcHA1 (
	IN char *pszAlg,
	IN char *pszUserName,
	IN char *pszRealm,
	IN char *pszPassword,
	IN char *pszNonce,
	IN char *pszCNonce,
	OUT HASHHEX SessionKey
);

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse (
	IN HASHHEX HA1,           /* H(A1) */
	IN char *pszNonce,       /* nonce from server */
	IN char *pszNonceCount,  /* 8 hex digits */
	IN char *pszCNonce,      /* client nonce */
	IN char *pszQop,         /* qop-value: "", "auth", "auth-int" */
	IN char *pszMethod,      /* method from the request */
	IN char *pszDigestUri,   /* requested URL */
	IN HASHHEX HEntity,       /* H(entity body) if qop="auth-int" */
	OUT HASHHEX Response      /* request-digest or response-digest */
);

#ifdef __cplusplus
}
#endif

#endif

#endif
