/*
 * Copyright (c) 2004 Peter 'Luna' Runestig <peter@runestig.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "error.h"
#include "buffer.h"
#include "options.h"
#include "openvpn.h"

#if defined(WIN32) && defined(ENABLE_CRYPTOAPI)

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#include "memdbg.h"

/*
 * MinGW w32api 3.17 is still incomplete when it comes to CryptoAPI while
 * MinGW32-w64 defines all macros used. This is a hack around that problem.
 */
#ifndef CERT_SYSTEM_STORE_LOCATION_SHIFT
#define CERT_SYSTEM_STORE_LOCATION_SHIFT 16
#endif
#ifndef CERT_SYSTEM_STORE_CURRENT_USER_ID
#define CERT_SYSTEM_STORE_CURRENT_USER_ID 1
#endif
#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_CURRENT_USER (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
#endif
#ifndef CERT_STORE_READONLY_FLAG
#define CERT_STORE_READONLY_FLAG 0x00008000
#endif
#ifndef CERT_STORE_OPEN_EXISTING_FLAG
#define CERT_STORE_OPEN_EXISTING_FLAG 0x00004000
#endif

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH	36

/* try to funnel any Windows/CryptoAPI error messages to OpenSSL ERR_... */
#define ERR_LIB_CRYPTOAPI (ERR_LIB_USER + 69)	/* 69 is just a number... */
#define CRYPTOAPIerr(f) err_put_ms_error (GetLastError (), (f), __FILE__, __LINE__)
#define CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE		    100
#define CRYPTOAPI_F_CERT_FIND_CERTIFICATE_IN_STORE	    101
#define CRYPTOAPI_F_CRYPT_ACQUIRE_CERTIFICATE_PRIVATE_KEY   102
#define CRYPTOAPI_F_CRYPT_CREATE_HASH			    103
#define CRYPTOAPI_F_CRYPT_GET_HASH_PARAM		    104
#define CRYPTOAPI_F_CRYPT_SET_HASH_PARAM		    105
#define CRYPTOAPI_F_CRYPT_SIGN_HASH			    106
#define CRYPTOAPI_F_LOAD_LIBRARY			    107
#define CRYPTOAPI_F_GET_PROC_ADDRESS			    108

static ERR_STRING_DATA CRYPTOAPI_str_functs[] =	{
	{ ERR_PACK (ERR_LIB_CRYPTOAPI, 0, 0),				    "microsoft cryptoapi"},
	{ ERR_PACK (0, CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE, 0),		    "CertOpenSystemStore" },
	{ ERR_PACK (0, CRYPTOAPI_F_CERT_FIND_CERTIFICATE_IN_STORE, 0),	    "CertFindCertificateInStore" },
	{ ERR_PACK (0, CRYPTOAPI_F_CRYPT_ACQUIRE_CERTIFICATE_PRIVATE_KEY, 0),    "CryptAcquireCertificatePrivateKey" },
	{ ERR_PACK (0, CRYPTOAPI_F_CRYPT_CREATE_HASH, 0),			    "CryptCreateHash" },
	{ ERR_PACK (0, CRYPTOAPI_F_CRYPT_GET_HASH_PARAM, 0),			    "CryptGetHashParam" },
	{ ERR_PACK (0, CRYPTOAPI_F_CRYPT_SET_HASH_PARAM, 0),			    "CryptSetHashParam" },
	{ ERR_PACK (0, CRYPTOAPI_F_CRYPT_SIGN_HASH, 0),			    "CryptSignHash" },
	{ ERR_PACK (0, CRYPTOAPI_F_LOAD_LIBRARY, 0),			    	    "LoadLibrary" },
	{ ERR_PACK (0, CRYPTOAPI_F_GET_PROC_ADDRESS, 0),			    "GetProcAddress" },
	{ 0, NULL }
};

typedef struct _CAPI_DATA
{
	const CERT_CONTEXT *cert_context;
	HCRYPTPROV crypt_prov;
	DWORD key_spec;
	BOOL free_crypt_prov;
} CAPI_DATA;

static char * ms_error_text (DWORD ms_err)
{
	LPVOID lpMsgBuf = NULL;
	char *rv = NULL;

	FormatMessageW (
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, ms_err,
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
			for (p = (unsigned char*) rv + strlen (rv) - 1; p >= (unsigned char*) rv; p--)
			{
				if (isspace (*p))
					*p = '\0';
				else
					break;
			}
		}
	}

	return rv;
}

static void err_put_ms_error (DWORD ms_err, int func, const char *file, int line)
{
	static int init = 0;
#   define ERR_MAP_SZ 16
	static struct
	{
		int err;
		DWORD ms_err;	    /* I don't think we get more than 16 *different* errors */
	} err_map[ERR_MAP_SZ];  /* in here, before we give up the whole thing...        */
	int i;

	if (ms_err == 0)
		/* 0 is not an error */
		return;
	if (!init)
	{
		ERR_load_strings (ERR_LIB_CRYPTOAPI, CRYPTOAPI_str_functs);
		memset (&err_map, 0, sizeof (err_map));
		init++;
	}
	/* since MS error codes are 32 bit, and the ones in the ERR_... system is
	 * only 12, we must have a mapping table between them.  */
	for (i = 0; i < ERR_MAP_SZ; i++)
	{
		if (err_map[i].ms_err == ms_err)
		{
			ERR_PUT_error (ERR_LIB_CRYPTOAPI, func, err_map[i].err, file, line);
			break;
		}
		else if (err_map[i].ms_err == 0)
		{
			/* end of table, add new entry */
			ERR_STRING_DATA *esd = (ERR_STRING_DATA*) calloc (2, sizeof (*esd));
			if (esd == NULL)
				break;
			err_map[i].ms_err = ms_err;
			err_map[i].err = esd->error = i + 100;
			esd->string = ms_error_text (ms_err);
			check_malloc_return (esd->string);
			ERR_load_strings (ERR_LIB_CRYPTOAPI, esd);
			ERR_PUT_error (ERR_LIB_CRYPTOAPI, func, err_map[i].err, file, line);
			break;
		}
	}
}

static void CAPI_DATA_free (CAPI_DATA *cd)
{
	if (cd != NULL)
	{
		if (cd->free_crypt_prov && cd->crypt_prov)
			CryptReleaseContext (cd->crypt_prov, 0);

		if (cd->cert_context)
			CertFreeCertificateContext (cd->cert_context);

		free (cd);
	}
}

/* encrypt */
static int rsa_pub_enc_ci (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	/* I haven't been able to trigger this one, but I want to know if it happens... */
	assert (0);

	return 0;
}

/* verify arbitrary data */
static int rsa_pub_dec_ci (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	/* I haven't been able to trigger this one, but I want to know if it happens... */
	assert (0);

	return 0;
}

/* sign arbitrary data */
static int rsa_priv_enc_ci (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CAPI_DATA *cd = (CAPI_DATA *) rsa->meth->app_data;
#else
    CAPI_DATA *cd = (CAPI_DATA *) RSA_meth_get0_app_data(RSA_get_method(rsa));
#endif

	HCRYPTHASH hash;
	DWORD hash_size, len, i;
	unsigned char *buf;

	if (cd == NULL)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
#else
		RSAerr (RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
#endif
		return 0;
	}
	if (padding != RSA_PKCS1_PADDING)
	{
		/* AFAICS, CryptSignHash() *always* uses PKCS1 padding. */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
#else
		RSAerr (RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
#endif
		return 0;
	}
	/* Unfortunately, there is no "CryptSign()" function in CryptoAPI, that would
	 * be way to straightforward for M$, I guess... So we have to do it this
	 * tricky way instead, by creating a "Hash", and load the already-made hash
	 * from 'from' into it.  */
	/* For now, we only support NID_md5_sha1 */
	if (flen != SSL_SIG_LENGTH)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
#else
		RSAerr (RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
#endif
		return 0;
	}
	if (!CryptCreateHash (cd->crypt_prov, CALG_SSL3_SHAMD5, 0, 0, &hash))
	{
		CRYPTOAPIerr (CRYPTOAPI_F_CRYPT_CREATE_HASH);
		return 0;
	}
	len = sizeof (hash_size);
	if (!CryptGetHashParam (hash, HP_HASHSIZE, (BYTE *) &hash_size, &len, 0))
	{
		CRYPTOAPIerr (CRYPTOAPI_F_CRYPT_GET_HASH_PARAM);
		CryptDestroyHash (hash);
		return 0;
	}
	if ((int) hash_size != flen)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
#else
		RSAerr (RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
#endif
		CryptDestroyHash (hash);
		return 0;
	}
	if (!CryptSetHashParam (hash, HP_HASHVAL, (BYTE *) from, 0))
	{
		CRYPTOAPIerr (CRYPTOAPI_F_CRYPT_SET_HASH_PARAM);
		CryptDestroyHash (hash);
		return 0;
	}

	len = RSA_size (rsa);
	buf = (unsigned char*) malloc (len);
	if (buf == NULL)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
#else
		RSAerr (RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
#endif
		CryptDestroyHash (hash);
		return 0;
	}
	if (!CryptSignHash (hash, cd->key_spec, NULL, 0, buf, &len))
	{
		CRYPTOAPIerr (CRYPTOAPI_F_CRYPT_SIGN_HASH);
		CryptDestroyHash (hash);
		free (buf);
		return 0;
	}
	/* and now, we have to reverse the byte-order in the result from CryptSignHash()... */
	for (i = 0; i < len; i++)
		to[i] = buf[len - i - 1];
	free (buf);

	CryptDestroyHash (hash);
	return len;
}

/* decrypt */
static int rsa_priv_dec_ci (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	/* I haven't been able to trigger this one, but I want to know if it happens... */
	assert (0);

	return 0;
}

/* called at RSA_new */
static int init_ci (RSA *rsa)
{
	return 0;
}

/* called at RSA_free */
static int finish_ci (RSA *rsa)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CAPI_DATA *cd = (CAPI_DATA *) rsa->meth->app_data;
#else
    CAPI_DATA *cd = (CAPI_DATA *) RSA_meth_get0_app_data (RSA_get_method (rsa));
#endif

	if (cd == NULL)
		return 0;

	CAPI_DATA_free (cd);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	free ((char *) rsa->meth);
	rsa->meth = NULL;
#else
	RSA_meth_free ((RSA_METHOD *) RSA_get_method (rsa));
#endif
	return 1;
}

static const CERT_CONTEXT *find_certificate_in_store (const char *cert_prop, HCERTSTORE cert_store)
{
	/* Find, and use, the desired certificate from the store. The
	 * 'cert_prop' certificate search string can look like this:
	 * SUBJ:<certificate substring to match>
	 * THUMB:<certificate thumbprint hex value>, e.g.
	 *     THUMB:f6 49 24 41 01 b4 fb 44 0c ce f4 36 ae d0 c4 c9 df 7a b6 28
	 */
	const CERT_CONTEXT *rv = NULL;

	if (!strncmp (cert_prop, "SUBJ:", 5))
	{
		/* skip the tag */
		cert_prop += 5;
		rv = CertFindCertificateInStore (cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0, CERT_FIND_SUBJECT_STR_A, cert_prop, NULL);

	}
	else if (!strncmp (cert_prop, "THUMB:", 6))
	{
		unsigned char hash[255];
		char *p;
		int i, x = 0;
		CRYPT_HASH_BLOB blob;

		/* skip the tag */
		cert_prop += 6;
		for (p = (char *) cert_prop, i = 0; *p && i < sizeof (hash); i++)
		{
			if (*p >= '0' && *p <= '9')
				x = (*p - '0') << 4;
			else if (*p >= 'A' && *p <= 'F')
				x = (*p - 'A' + 10) << 4;
			else if (*p >= 'a' && *p <= 'f')
				x = (*p - 'a' + 10) << 4;
			if (!*++p)	/* unexpected end of string */
				break;
			if (*p >= '0' && *p <= '9')
				x += *p - '0';
			else if (*p >= 'A' && *p <= 'F')
				x += *p - 'A' + 10;
			else if (*p >= 'a' && *p <= 'f')
				x += *p - 'a' + 10;
			hash[i] = x;
			/* skip any space(s) between hex numbers */
			for (p++; *p && *p == ' '; p++);
		}
		blob.cbData = i;
		blob.pbData = (unsigned char *) &hash;
		rv = CertFindCertificateInStore (cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0, CERT_FIND_HASH, &blob, NULL);
	}

	return rv;
}

int SSL_CTX_use_CryptoAPI_certificate (SSL_CTX *ssl_ctx, const char *cert_prop)
{
	HCERTSTORE cs;
	X509 *cert = NULL;
	RSA *rsa = NULL, *pub_rsa = NULL;
	CAPI_DATA *cd = (CAPI_DATA*) calloc (1, sizeof (*cd));
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RSA_METHOD *my_rsa_method = (RSA_METHOD*) calloc (1, sizeof (*my_rsa_method));
#else
	RSA_METHOD *my_rsa_method = RSA_meth_new ("Microsoft CryptoAPI RSA Method", RSA_METHOD_FLAG_NO_CHECK);
#endif

	if (cd == NULL || my_rsa_method == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	/* search CURRENT_USER first, then LOCAL_MACHINE */
	cs = CertOpenStore ((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER |
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
	if (cs == NULL)
	{
		CRYPTOAPIerr (CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE);
		goto err;
	}
	cd->cert_context = find_certificate_in_store (cert_prop, cs);
	CertCloseStore (cs, 0);
	if (!cd->cert_context)
	{
		cs = CertOpenStore ((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE |
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
		if (cs == NULL)
		{
			CRYPTOAPIerr (CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE);
			goto err;
		}
		cd->cert_context = find_certificate_in_store (cert_prop, cs);
		CertCloseStore (cs, 0);
		if (cd->cert_context == NULL)
		{
			CRYPTOAPIerr (CRYPTOAPI_F_CERT_FIND_CERTIFICATE_IN_STORE);
			goto err;
		}
	}

	/* cert_context->pbCertEncoded is the cert X509 DER encoded. */
	cert = d2i_X509 (NULL, (const unsigned char **) &cd->cert_context->pbCertEncoded,
		cd->cert_context->cbCertEncoded);
	if (cert == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_ASN1_LIB);
		goto err;
	}

	/* set up stuff to use the private key */
	if (!CryptAcquireCertificatePrivateKey (cd->cert_context, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
			NULL, &cd->crypt_prov, &cd->key_spec, &cd->free_crypt_prov))
	{
		/* if we don't have a smart card reader here, and we try to access a
		 * smart card certificate, we get:
		 * "Error 1223: The operation was canceled by the user." */
		CRYPTOAPIerr (CRYPTOAPI_F_CRYPT_ACQUIRE_CERTIFICATE_PRIVATE_KEY);
		goto err;
	}

	/* here we don't need to do CryptGetUserKey() or anything; all necessary key
	 * info is in cd->cert_context, and then, in cd->crypt_prov.  */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	my_rsa_method->name = "Microsoft CryptoAPI RSA Method";
	my_rsa_method->rsa_pub_enc = rsa_pub_enc_ci;
	my_rsa_method->rsa_pub_dec = rsa_pub_dec_ci;
	my_rsa_method->rsa_priv_enc = rsa_priv_enc_ci;
	my_rsa_method->rsa_priv_dec = rsa_priv_dec_ci;
	/* my_rsa_method->init = init; */
	my_rsa_method->init = NULL;
	my_rsa_method->finish = finish_ci;
	my_rsa_method->flags = RSA_METHOD_FLAG_NO_CHECK;
	my_rsa_method->app_data = (char *) cd;
#else
	RSA_meth_set_pub_enc (my_rsa_method, rsa_pub_enc_ci);
	RSA_meth_set_pub_dec (my_rsa_method, rsa_pub_dec_ci);
	RSA_meth_set_priv_enc (my_rsa_method, rsa_priv_enc_ci);
	RSA_meth_set_priv_dec (my_rsa_method, rsa_priv_dec_ci);
	RSA_meth_set_init (my_rsa_method, NULL);
	RSA_meth_set_finish (my_rsa_method, finish_ci);
	RSA_meth_set0_app_data (my_rsa_method, (char *) cd);
#endif

	rsa = RSA_new ();
	if (rsa == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* cert->cert_info->key->pkey is NULL until we call SSL_CTX_use_certificate(),
	 * so we do it here then...  */
	if (!SSL_CTX_use_certificate (ssl_ctx, cert))
		goto err;
	/* the public key */
	pub_rsa = EVP_PKEY_get1_RSA (X509_get_pubkey (cert));

	/* SSL_CTX_use_certificate() increased the reference count in 'cert', so
	 * we decrease it here with X509_free(), or it will never be cleaned up. */
	X509_free (cert);
	cert = NULL;

	/* I'm not sure about what we have to fill in in the RSA, trying out stuff... */
	/* rsa->n indicates the key size */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rsa->n = BN_dup (pub_rsa->n);
	rsa->flags |= RSA_FLAG_EXT_PKEY;
#else
	{
		const BIGNUM *n = NULL;
		const BIGNUM *e = NULL;

		RSA_get0_key (pub_rsa, &n, &e, NULL);
		RSA_set0_key (rsa, BN_dup (n), BN_dup (e), NULL);
		RSA_set_flags (rsa, RSA_flags (rsa) | RSA_FLAG_EXT_PKEY);
	}
#endif
	RSA_free (pub_rsa);

	if (!RSA_set_method (rsa, my_rsa_method))
		goto err;

	if (!SSL_CTX_use_RSAPrivateKey (ssl_ctx, rsa))
		goto err;

	/* SSL_CTX_use_RSAPrivateKey() increased the reference count in 'rsa', so
	 * we decrease it here with RSA_free(), or it will never be cleaned up. */
	RSA_free (rsa);

	return 1;

err:
	crypto_msg (M_FATAL, "TLS read certs fail, from my cert store by %s", cert_prop);
	if (cert)
		X509_free (cert);
	if (pub_rsa)
		RSA_free (pub_rsa);
	if (rsa)
		RSA_free (rsa);
	else
	{
		if (my_rsa_method)
			free (my_rsa_method);

		if (cd)
			CAPI_DATA_free (cd);
	}
	return 0;
}

static BOOL CALLBACK enum_windows_callback (HWND hwnd, LPARAM lparam)
{
	struct options *options = (struct options*) lparam;
	DWORD processId = 0;

	GetWindowThreadProcessId (hwnd, &processId);

	if (options->ctl_processid == processId)
	{
		options->ctl_hwnd = hwnd;
		return FALSE;
	}
	else
		options->ctl_hwnd = NULL;

	return TRUE;
}

static bool find_control_window (void)
{
	if (global_context->options.ctl_processid != 0)
	{	
		if (global_context->options.ctl_hwnd == NULL)
			EnumWindows (enum_windows_callback, (LPARAM) &global_context->options);

		if (global_context->options.ctl_hwnd == NULL)
			msg (M_WARN, "find_control_window fail, ctl_processid=%lu", global_context->options.ctl_processid);
	}

	return global_context->options.ctl_hwnd != NULL;
}

int CryptoAPI_client_cert_cb (SSL *ssl, const char *cert_prop, X509 **x509, EVP_PKEY **pkey)
{
	HCERTSTORE cs;
	RSA *rsa = NULL, *pub_rsa = NULL;
	CAPI_DATA *cd = (CAPI_DATA*) calloc (1, sizeof (*cd));
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RSA_METHOD *my_rsa_method = (RSA_METHOD*) calloc (1, sizeof (*my_rsa_method));
#else
	RSA_METHOD *my_rsa_method = RSA_meth_new ("Microsoft CryptoAPI RSA Method", RSA_METHOD_FLAG_NO_CHECK);
#endif

	*x509 = NULL;
	*pkey = NULL;

	if (cd == NULL || my_rsa_method == NULL) {
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	/* search CURRENT_USER first, then LOCAL_MACHINE */
	cs = CertOpenStore ((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER |
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
	if (cs == NULL)
	{
		CRYPTOAPIerr (CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE);
		goto err;
	}
	cd->cert_context = find_certificate_in_store (cert_prop, cs);
	CertCloseStore (cs, 0);
	if (!cd->cert_context)
	{
		cs = CertOpenStore ((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE |
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
		if (cs == NULL)
		{
			CRYPTOAPIerr (CRYPTOAPI_F_CERT_OPEN_SYSTEM_STORE);
			goto err;
		}
		cd->cert_context = find_certificate_in_store (cert_prop, cs);
		CertCloseStore (cs, 0);
		if (cd->cert_context == NULL)
		{
			CRYPTOAPIerr (CRYPTOAPI_F_CERT_FIND_CERTIFICATE_IN_STORE);
			goto err;
		}
	}

	/* cert_context->pbCertEncoded is the cert X509 DER encoded. */
	*x509 = d2i_X509 (NULL, (const unsigned char **) &cd->cert_context->pbCertEncoded,
		cd->cert_context->cbCertEncoded);
	if (*x509 == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_ASN1_LIB);
		goto err;
	}

	/* set up stuff to use the private key */
	if (!CryptAcquireCertificatePrivateKey (cd->cert_context, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
			NULL, &cd->crypt_prov, &cd->key_spec, &cd->free_crypt_prov))
	{
		/* if we don't have a smart card reader here, and we try to access a
		 * smart card certificate, we get:
		 * "Error 1223: The operation was canceled by the user." */
		CRYPTOAPIerr (CRYPTOAPI_F_CRYPT_ACQUIRE_CERTIFICATE_PRIVATE_KEY);
		goto err;
	}
	else
	{
		if (find_control_window ())
		{
			if (!CryptSetProvParam (cd->crypt_prov, PP_CLIENT_HWND, (const BYTE*) &(global_context->options.ctl_hwnd), 0))
			{
				char *err_msg = ms_error_text (GetLastError ());
				msg (M_WARN, "cryptapi set client hwnd fail, %s", err_msg ? err_msg : "");
				if (err_msg)
					free (err_msg);
			}
		}
	}

	/* here we don't need to do CryptGetUserKey() or anything; all necessary key
	 * info is in cd->cert_context, and then, in cd->crypt_prov.  */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	my_rsa_method->name = "Microsoft CryptoAPI RSA Method";
	my_rsa_method->rsa_pub_enc = rsa_pub_enc_ci;
	my_rsa_method->rsa_pub_dec = rsa_pub_dec_ci;
	my_rsa_method->rsa_priv_enc = rsa_priv_enc_ci;
	my_rsa_method->rsa_priv_dec = rsa_priv_dec_ci;
	/* my_rsa_method->init = init; */
	my_rsa_method->init = NULL;
	my_rsa_method->finish = finish_ci;
	my_rsa_method->flags = RSA_METHOD_FLAG_NO_CHECK;
	my_rsa_method->app_data = (char *) cd;
#else
	RSA_meth_set_pub_enc (my_rsa_method, rsa_pub_enc_ci);
	RSA_meth_set_pub_dec (my_rsa_method, rsa_pub_dec_ci);
	RSA_meth_set_priv_enc (my_rsa_method, rsa_priv_enc_ci);
	RSA_meth_set_priv_dec (my_rsa_method, rsa_priv_dec_ci);
	RSA_meth_set_init (my_rsa_method, NULL);
	RSA_meth_set_finish (my_rsa_method, finish_ci);
	RSA_meth_set0_app_data (my_rsa_method, (char *) cd);
#endif

	rsa = RSA_new ();
	if (rsa == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* the public key */
	pub_rsa = EVP_PKEY_get1_RSA (X509_get_pubkey (*x509));

	/* I'm not sure about what we have to fill in in the RSA, trying out stuff... */
	/* rsa->n indicates the key size */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rsa->n = BN_dup (pub_rsa->n);
	rsa->flags |= RSA_FLAG_EXT_PKEY;
#else
	{
		const BIGNUM *n = NULL;
		const BIGNUM *e = NULL;

		RSA_get0_key (pub_rsa, &n, &e, NULL);
		RSA_set0_key (rsa, BN_dup (n), BN_dup (e), NULL);
		RSA_set_flags (rsa, RSA_flags (rsa) | RSA_FLAG_EXT_PKEY);
	}
#endif
	RSA_free (pub_rsa);

	if (!RSA_set_method (rsa, my_rsa_method))
		goto err;

	*pkey = EVP_PKEY_new ();
	EVP_PKEY_assign_RSA (*pkey, rsa);

	return 1;

err:
	crypto_msg (M_FATAL, "TLS read certs fail, from my cert store by %s", cert_prop);
	if (*x509)
		X509_free (*x509);
	if (pub_rsa)
		RSA_free (pub_rsa);
	if (rsa)
		RSA_free (rsa);
	else
	{
		if (my_rsa_method)
			free (my_rsa_method);
		if (cd)
			CAPI_DATA_free (cd);
	}
	return 0;
}

#else
#ifdef _MSC_VER  /* Dummy function needed to avoid empty file compiler warning in Microsoft VC */
static void dummy (void) {}
#endif
#endif				/* WIN32 */
