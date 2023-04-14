/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010 Fox Crypto B.V. <openvpn@fox-it.com>
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

/**
 * @file Control Channel OpenSSL Backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_OPENSSL)

#include "errlevel.h"
#include "buffer.h"
#include "misc.h"
#include "manage.h"
#include "ssl_backend.h"
#include "ssl_common.h"
#include "base64.h"

#ifdef ENABLE_CRYPTOAPI
#include "cryptoapi.h"
#endif
#ifdef ENABLE_GUOMI
#include "gmed_api.h"
#endif
#include "console.h"

#include "ssl_verify_openssl.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>

#include "memdbg.h"

/* Allocate space in SSL objects in which to store a struct tls_session pointer back to parent. */

int global_SSL_tls_session_index = -1; /* GLOBAL */
int global_SSL_key_state_index   = -1; /* GLOBAL */
int global_RSA_tls_session_index = -1; /* GLOBAL */
int global_RSA_key_state_index   = -1; /* GLOBAL */

/* encrypt */
static int
rsa_pub_enc (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	ASSERT (0);
	return -1;
}

/* verify arbitrary data */
static int
rsa_pub_dec (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	ASSERT (0);
	return -1;
}

/* decrypt */
static int
rsa_priv_dec (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	ASSERT (0);
	return -1;
}

/* called at RSA_free */
static int
rsa_finish (RSA *rsa)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	free ((void*) rsa->meth);
	rsa->meth = NULL;
#else
	const RSA_METHOD *meth = RSA_get_method (rsa);
    RSA_meth_free ((RSA_METHOD *) meth);
#endif
	return 1;
}

/* sign arbitrary data */
static int
rsa_priv_enc (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	/* optional app data in rsa->meth->app_data; */
	struct tls_session *session = NULL;
	struct key_state *state = NULL;
	char *in_b64 = NULL;
	char *out_b64 = NULL;
	int ret = -1, len = 0;

	if (padding != RSA_PKCS1_PADDING)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
#else
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
#endif
		goto done;
	}

	/* convert 'from' to base64 */
	if (openvpn_base64_encode (from, flen, &in_b64) <= 0)
		goto done;

	/* call MI for signature */
	if (management)
		out_b64 = management_query_pk_sig (management, in_b64);
	else
	{
		struct gc_arena gc = gc_new ();
		struct buffer pk_sign_prompt = alloc_buf_gc (256, &gc);

		out_b64 = (char *) malloc (8192);

		buf_printf (&pk_sign_prompt, "Enter PK sign: %s", in_b64);

		if (!get_console_input (BSTR (&pk_sign_prompt), false, out_b64, 8192))
			msg (M_FATAL, "ERROR: could not read PK sign from stdin");

		gc_free (&gc);
	}

	if (!out_b64)
		goto done;

	/* decode base64 signature to binary */
	len = RSA_size (rsa);
	ret = openvpn_base64_decode (out_b64, to, len);

	/* verify length */
	if (ret != len)
		ret = -1;

done:
	session = (struct tls_session *) RSA_get_ex_data (rsa, global_RSA_tls_session_index);
	state = (struct key_state *) RSA_get_ex_data (rsa, global_RSA_key_state_index);
	if (session && state)
	{
		time_t new_must_negotiate;
		/* 私钥已校验, 调整state->must_negotiate参数值 */
		update_time (MAIN_THREAD_INDEX);
		new_must_negotiate = now_sec (MAIN_THREAD_INDEX) + max_int (10, session->opt->hello_window);
		if (state->must_negotiate > new_must_negotiate)
		{
			state->saved_must_negotiate = state->must_negotiate;
			state->must_negotiate = new_must_negotiate;
			msg (M_INFO, "adjusting tls handshake window from %d to %d", session->opt->handshake_window,
				max_int (10, session->opt->hello_window));
		}
	}
	if (in_b64)
		free (in_b64);
	if (out_b64)
		free (out_b64);
	return ret;
}

static ECDSA_SIG* 
sm2_sign_ex (const unsigned char *dgst, int dlen, const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)
{
	/* optional app data in rsa->meth->app_data; */
	char *in_b64  = NULL;
	char *out_b64 = NULL;
	int len;
	unsigned char *to = NULL;
	unsigned char *pp = NULL;
	ECDSA_SIG *sig = NULL;

	/* convert 'from' to base64 */
	if (openvpn_base64_encode (dgst, dlen, &in_b64) <= 0)
		goto done;

	/* call MI for signature */
	if (management)
		out_b64 = management_query_pk_sig (management, in_b64);
	else
	{
		struct gc_arena gc = gc_new ();
		struct buffer pk_sign_prompt = alloc_buf_gc (256, &gc);

		out_b64 = (char*) malloc (8192);
		memset(out_b64, 0x0, 8192);

		buf_printf (&pk_sign_prompt, "Enter PK sign: %s", in_b64);

		if (!get_console_input (BSTR (&pk_sign_prompt), false, out_b64, 8192))
			msg (M_FATAL, "ERROR: could not read PK sign from stdin");

		gc_free (&gc);
	}

	if (!out_b64)
		goto done;

	/* decode base64 signature to binary */
	to = pp = (unsigned char*) malloc (8192);
	memset (to, 0x0, 8192);

	if ((len = openvpn_base64_decode (out_b64, pp, -1)) > 0)
		sig = d2i_ECDSA_SIG (NULL, (const unsigned char **) &pp, (long) len);

done:
	if (in_b64)
		free (in_b64);
	if (out_b64)
		free (out_b64);
	if (to)
		free (to);
	return sig;
}

void
tls_init_lib (void)
{
#ifdef ENABLE_GUOMI	
	ERR_load_crypto_strings ();
#endif
	OpenSSL_add_all_algorithms ();
#ifdef ENABLE_GUOMI	
	ECDSA_set_default_method(ECDSA_sm2());
#endif
	SSL_library_init ();
#ifndef ENABLE_SMALL
	SSL_load_error_strings ();
#endif

	global_SSL_tls_session_index = SSL_get_ex_new_index (0, "struct tls_session *", NULL, NULL, NULL);
	ASSERT (global_SSL_tls_session_index >= 0);

	global_SSL_key_state_index = SSL_get_ex_new_index (0, "struct key_state *", NULL, NULL, NULL);
	ASSERT (global_SSL_key_state_index >= 0);

	global_RSA_tls_session_index = RSA_get_ex_new_index (0, "struct tls_session *", NULL, NULL, NULL);
	ASSERT (global_RSA_tls_session_index >= 0);

	global_RSA_key_state_index = RSA_get_ex_new_index (0, "struct key_state *", NULL, NULL, NULL);
	ASSERT (global_RSA_key_state_index >= 0);
}

void
tls_free_lib (void)
{
	OBJ_cleanup ();
	EVP_cleanup ();
	CRYPTO_cleanup_all_ex_data ();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ERR_remove_thread_state (NULL);
#endif
#ifndef ENABLE_SMALL
	ERR_free_strings ();
#endif
}

void
tls_clear_error (void)
{
	ERR_clear_error ();
}

/* OpenSSL callback to get a temporary RSA key, mostly used for export ciphers. */
static RSA*
tmp_rsa_cb (SSL *s, int is_export, int keylength)
{
	static RSA *rsa_tmp = NULL;
	if (rsa_tmp == NULL)
	{
		BIGNUM *bn = BN_new ();
		rsa_tmp = RSA_new ();

		msg (D_HANDSHAKE, "Generating temp (%d bit) RSA key", keylength);

		if (!bn || !BN_set_word (bn, RSA_F4) || !RSA_generate_key_ex (rsa_tmp, keylength, bn, NULL))
			crypto_msg (M_FATAL, "Failed to generate temp RSA key");

		if (bn)
			BN_free (bn);
	}
	return (rsa_tmp);
}

static EC_KEY*
tmp_ecdh_cb (SSL *ssl, int is_export, int keylength)
{
	static EC_KEY *ecdh = NULL;
	if (ecdh == NULL)
	{
		ecdh = EC_KEY_new ();
		if (ecdh)
		{
#ifdef ENABLE_GUOMI
			if ((ssl->version >> 8) == GMTLS1_VERSION_MAJOR)
				EC_KEY_set_group (ecdh, EC_GROUP_new_by_curve_name (NID_sm2));
			else
#endif
				EC_KEY_set_group (ecdh, EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1));
		}
		if (ecdh == NULL || !EC_KEY_generate_key (ecdh))
			crypto_msg (M_FATAL, "Failed to generate temp EC key");
	}
	return ecdh;
}

static int 
PKCS12_client_cert_cb (SSL *ssl, const char *sign_pkcs12_file, X509 **x509_sign, EVP_PKEY **pkey_sign
#ifdef ENABLE_GUOMI
		, const char *encrypt_pkcs12_file, X509 **x509_encrypt, EVP_PKEY **pkey_encrypt
#endif
		)
{
	void ssl_purge_auth (const bool auth_user_pass_only);
	struct gc_arena gc = gc_new ();
	FILE *fp = NULL;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12 = NULL;
	int verify_ok, input_count = 0;
	char password[256];

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* 只有主线程能调用 openvpn_exit () */
#endif

	*x509_sign = NULL;
	*pkey_sign = NULL;
#ifdef ENABLE_GUOMI
	*x509_encrypt = NULL;
	*pkey_encrypt = NULL;
#endif

	/* Load the sign PKCS #12 file */
	if (!(fp = platform_fopen (sign_pkcs12_file, "rb")))
		crypto_msg (M_FATAL, "Error opening file %s", sign_pkcs12_file);
	p12 = d2i_PKCS12_fp (fp, NULL);
	fclose (fp);
	if (!p12)
		crypto_msg (M_FATAL, "Error reading sign PKCS#12 file %s", sign_pkcs12_file);

	/* Parse the sign PKCS #12 file */
	verify_ok = PKCS12_parse (p12, "", pkey_sign, x509_sign, &ca);
	if (!verify_ok)
	{
		do
		{
			pem_password_callback (password, sizeof (password) - 1, 0, NULL);
			ca = NULL;
			if (!(verify_ok = PKCS12_parse (p12, password, pkey_sign, x509_sign, &ca)))
			{
				msg (M_WARN, "ERROR: Private Key Password verify fail");
				ssl_purge_auth (false);	// 通知客户端重新输入私钥保护密码
			}
		} while (!verify_ok && ++input_count < MAX_PRI_KEY_PASS_INPUT_COUNT);		
	}

	PKCS12_free (p12);

	if (!verify_ok)	// 致命错误, 直接退出openvpn进程
		msg (M_FATAL, "FATAL: could not open sign Private Key fail");

#ifdef ENABLE_GUOMI
	/* 加密证书没有单独指定或不存在时, 使用签名证书 */
	if (encrypt_pkcs12_file)
	{
		if (!(fp = platform_fopen (encrypt_pkcs12_file, "rb")))
			crypto_msg (M_FATAL, "Error opening file %s", encrypt_pkcs12_file);

		p12 = d2i_PKCS12_fp (fp, NULL);
		fclose (fp);
		if (!p12)
			crypto_msg (M_FATAL, "Error reading encrypt PKCS#12 file %s", encrypt_pkcs12_file);

		/* Parse the sign PKCS #12 file, 签名pkcs12和加密pkcs12文件的保护密码必须相同 */
		ca = NULL;
		verify_ok = PKCS12_parse (p12, password, pkey_encrypt, x509_encrypt, &ca);
		PKCS12_free (p12);

		if (!verify_ok)	// 致命错误, 直接退出openvpn进程
			msg (M_FATAL, "FATAL: could not open encrypt Private Key fail");
	}
	else
	{
		*x509_encrypt = X509_dup (*x509_sign);
		*pkey_encrypt = evp_pkey_dup (*pkey_sign);
	}
#endif

	if (!verify_ok)
		ssl_purge_auth (false);

	gc_free (&gc);
	return verify_ok;
}

static RSA_METHOD * rsa_meth_new ()
{
	RSA_METHOD *rsa_meth;

	/* allocate custom RSA method object */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ALLOC_OBJ_CLEAR (rsa_meth, RSA_METHOD);
	rsa_meth->name = "OpenVPN external private key RSA Method";
	rsa_meth->rsa_pub_enc = rsa_pub_enc;
	rsa_meth->rsa_pub_dec = rsa_pub_dec;
	rsa_meth->rsa_priv_enc = rsa_priv_enc;
	rsa_meth->rsa_priv_dec = rsa_priv_dec;
	rsa_meth->init = NULL;
	rsa_meth->finish = rsa_finish;
	rsa_meth->flags = RSA_METHOD_FLAG_NO_CHECK;
	rsa_meth->app_data = NULL;
#else
	rsa_meth = RSA_meth_new ("OpenVPN external private key RSA Method", RSA_METHOD_FLAG_NO_CHECK);
	check_malloc_return (rsa_meth);
	RSA_meth_set_pub_enc (rsa_meth, rsa_pub_enc);
	RSA_meth_set_pub_dec (rsa_meth, rsa_pub_dec);
	RSA_meth_set_priv_enc (rsa_meth, rsa_priv_enc);
	RSA_meth_set_priv_dec (rsa_meth, rsa_priv_dec);
	RSA_meth_set_init (rsa_meth, NULL);
	RSA_meth_set_finish (rsa_meth, rsa_finish);
	RSA_meth_set0_app_data (rsa_meth, NULL);
#endif

	return rsa_meth;
}

static int
External_CryptoAPI_client_cert_cb (SSL *ssl, char *base64_data, X509 **x509, EVP_PKEY **pkey
#ifdef ENABLE_GUOMI
		, X509 **x509_encrypt, EVP_PKEY **pkey_encrypt
#endif
)
{
	struct tls_session *session = NULL;
	struct key_state *state = NULL;
	EC_KEY *ec = NULL;
	RSA *rsa = NULL;
	RSA *pub_rsa = NULL;
	EVP_PKEY *pub_pkey = NULL;

	ASSERT (NULL != ssl && NULL != base64_data);

	*x509 = NULL;
	*pkey = NULL;
#ifdef ENABLE_GUOMI
	if (x509_encrypt)
		*x509_encrypt = NULL;
	if (pkey_encrypt)
		*pkey_encrypt = NULL;
#endif

	if (strlen (base64_data) > 0)
	{
		void *buf = malloc (strlen (base64_data) + 1);
		int buf_len = openvpn_base64_decode (base64_data, buf, -1);
		
		if (buf_len > 0)
		{
			BIO *bio = BIO_new_mem_buf (buf, buf_len);
			if (bio)
			{
				*x509 = d2i_X509_bio (bio, NULL);
				BIO_free (bio);
				ERR_clear_error ();
			}
		}
	}

	if (!(*x509))
	{
		crypto_msg (M_FATAL, "parse x509 certificate fail, %s", (base64_data && strlen (base64_data) > 0) ? base64_data : "NULL");
		goto err;
	}

	/* get the public key */
	pub_pkey = X509_get_pubkey (*x509);
	if (pub_pkey == NULL)
		goto err;
#ifdef ENABLE_GUOMI
	if (x509_encrypt)
		*x509_encrypt = X509_dup (*x509);
#endif

	if (EVP_PKEY_type (EVP_PKEY_id (pub_pkey)) == EVP_PKEY_EC)
	{
#ifdef ENABLE_GUOMI
		ec = EC_KEY_new_by_curve_name (NID_sm2);
		ECDSA_set_method (ec, ECDSA_sm2_ex (sm2_sign_ex));
#else
		ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
#endif
		*pkey = EVP_PKEY_new ();
		EVP_PKEY_assign_EC_KEY (*pkey, ec);

#ifdef ENABLE_GUOMI
		if (pkey_encrypt)
		{
			ec = EC_KEY_new_by_curve_name (NID_sm2);
			ECDSA_set_method (ec, ECDSA_sm2_ex (sm2_sign_ex));
			*pkey_encrypt = EVP_PKEY_new ();
			EVP_PKEY_assign_EC_KEY (*pkey_encrypt, ec);
		}
#endif
	}
	else
	{
		/* allocate RSA object */
		rsa = RSA_new ();
		if (rsa == NULL)
		{
			SSLerr (SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
			goto err;
		}

		pub_rsa = EVP_PKEY_get1_RSA (pub_pkey);
		if (pub_rsa == NULL)
			goto err;
		else
		{
			/* initialize RSA object */
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
		}

		if (!RSA_set_method (rsa, rsa_meth_new ()))
			goto err;

		session = (struct tls_session *) SSL_get_ex_data (ssl, global_SSL_tls_session_index);
		state = (struct key_state *) SSL_get_ex_data (ssl, global_SSL_key_state_index);
		if (session && state)
		{
			RSA_set_ex_data (rsa, global_RSA_tls_session_index, session);
			RSA_set_ex_data (rsa, global_RSA_key_state_index, state);
		}

		*pkey = EVP_PKEY_new ();
		EVP_PKEY_assign_RSA (*pkey, rsa);

#ifdef ENABLE_GUOMI
		if (pkey_encrypt)
		{
			/* allocate RSA object */
			rsa = RSA_new ();
			if (rsa == NULL)
			{
				SSLerr (SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
				goto err;
			}

			/* initialize RSA object */
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
			if (!RSA_set_method (rsa, rsa_meth_new ()))
				goto err;

			if (session && state)
			{
				RSA_set_ex_data (rsa, global_RSA_tls_session_index, session);
				RSA_set_ex_data (rsa, global_RSA_key_state_index, state);
			}

			*pkey_encrypt = EVP_PKEY_new ();
			EVP_PKEY_assign_RSA (*pkey_encrypt, rsa);
		}
#endif
	}
	
	EVP_PKEY_free (pub_pkey);

	return 1;

err:
	if (*x509)
		X509_free (*x509);
	*x509 = NULL;
#ifdef ENABLE_GUOMI
	if (x509_encrypt)
	{
		if (*x509_encrypt)
			X509_free (*x509_encrypt);
		*x509_encrypt = NULL;
	}
#endif

	if (rsa)
		RSA_free (rsa);
	if (ec)
		EC_KEY_free (ec);
	if (pub_pkey)
		EVP_PKEY_free (pub_pkey);
	crypto_msg (M_FATAL, "Cannot enable SSL external private key capability");
	return 0;
}

static const char* 
ca_dn_sk_to_descn (STACK_OF(X509_NAME) *ca_dn_sk)
{
#define MAX_CA_DN_SK_DESCN_LEN	8192

	char buf[MAX_CA_DN_SK_DESCN_LEN];
	X509_NAME *xn;

	struct buffer out = alloc_buf (MAX_CA_DN_SK_DESCN_LEN);
	int i = 0, j = sk_X509_NAME_num (ca_dn_sk);

	buf_printf (&out, "-----BEGIN CA DN-----\n");

	for (i = 0; i < j; ++i)
	{
		xn = sk_X509_NAME_value (ca_dn_sk, i);
		/*
		 * 转化成字符串来比较是可行的, 因为
		 * 1. X509_NAME_oneline修改导致不兼容的可能性很小
		 * 2. openvpn.exe, vpnclient.exe, vpnservice.exe总是链接到同一个openssl库
		 */
		X509_NAME_oneline (xn, buf, sizeof (buf));
		buf_printf (&out, "%s\n", buf);
	}

	buf_printf (&out, "-----END CA DN-----\n");

	return BSTR (&out);
}

#define MAX_CLIENT_CERT_SELECT_PROMPT_LEN	(8192 + 1024)
#define MAX_CERT_IDENTIFY_LEN	8192

static char global_cert_identify[MAX_CERT_IDENTIFY_LEN] = { 0 };

static int 
tls_client_cert_cb_ext (SSL *ssl, X509 **x509_sign, EVP_PKEY **pkey_sign, X509 **x509_encrypt, EVP_PKEY **pkey_encrypt)
{
	int ret = 0;
	struct gc_arena gc = gc_new ();
	struct tls_session *session = NULL;
	struct key_state *state = NULL;

	session = (struct tls_session *) SSL_get_ex_data (ssl, global_SSL_tls_session_index);
	state = (struct key_state *) SSL_get_ex_data (ssl, global_SSL_key_state_index);

	if (0 == strlen (global_cert_identify))
	{
		struct buffer cert_prompt = alloc_buf_gc (MAX_CLIENT_CERT_SELECT_PROMPT_LEN, &gc);
		STACK_OF(X509_NAME) *ca_names = SSL_get_client_CA_list (ssl);
		const char *ca_dn_descn = ca_dn_sk_to_descn (ca_names); 

		buf_printf (&cert_prompt, "Enter Client certificate:%s\n%s", SSL_get_version (ssl), ca_dn_descn);
		buf_write (&cert_prompt, "\n", 1);	// 空行CA DN列表已完全输出
		buf_null_terminate (&cert_prompt);

		if (!get_console_input (BSTR (&cert_prompt), true, global_cert_identify, MAX_CERT_IDENTIFY_LEN))
			msg (M_FATAL, "ERROR: could not read Client certificate from stdin");
	}

	rm_trailing_chars (global_cert_identify, "\r\n\t ");

#ifdef ENABLE_CRYPTOAPI
	if (0 == strncmp (global_cert_identify, "cryptoapicert", strlen ("cryptoapicert")))
	{
		const char *thumb = global_cert_identify + strlen ("cryptoapicert");
		thumb = skip_leading_whitespace (thumb);

		ret = CryptoAPI_client_cert_cb (ssl, thumb, x509_sign, pkey_sign);
	}
	else
#endif
#ifdef ENABLE_GUOMI
		if (0 == strncmp (global_cert_identify, "gmedapicert", strlen ("gmedapicert")))
		{
			int init_encrypt_devices (struct context *c);
			extern struct context *global_context;

			const char *thumb = global_cert_identify + strlen ("gmedapicert");
			thumb = skip_leading_whitespace (thumb);

			/* 客户端, 读取证书前, 尝试初始化加密设备 */
			init_encrypt_devices (global_context);
			ret = GmedCertAPI_client_cert_cb (ssl, thumb, x509_sign, pkey_sign, x509_encrypt, pkey_encrypt);
			if (session && state)
			{
				time_t new_must_negotiate;
				/* 私钥已校验, 调整state->must_negotiate参数值 */
				update_time (MAIN_THREAD_INDEX);
				new_must_negotiate = now_sec (MAIN_THREAD_INDEX) + max_int (10, session->opt->hello_window);
				if (state->must_negotiate > new_must_negotiate)
				{
					state->saved_must_negotiate = state->must_negotiate;
					state->must_negotiate = new_must_negotiate;
					msg (M_INFO, "adjusting tls handshake window from %d to %d", session->opt->handshake_window,
						max_int (10, session->opt->hello_window));
				}
			}
		}
		else
#endif
/*
#ifdef ENABLE_PKCS11
			if (0 == strncmp (global_cert_identify, "pkcs11-id", strlen ("pkcs11-id")))
			{
				const char *pkcs11_id = global_cert_identify + strlen ("pkcs11-id");
				pkcs11_id = skip_leading_whitespace (pkcs11_id);
				// TODO implement pkcs11-id callback support
			}
			else
#endif
*/
				if (0 == strncmp (global_cert_identify, "pkcs12", strlen ("pkcs12")))
				{
					const char *sign_pkcs12_file = NULL;
#ifdef ENABLE_GUOMI
					const char *encrypt_pkcs12_file = NULL;
#endif
					char *params[5];

					CLEAR (params);
					parse_line (global_cert_identify, params, sizeof (params), __FILE__, __LINE__, M_FATAL, &gc);
					ASSERT (streq ("pkcs12", params[0]));
					sign_pkcs12_file = params[1];
#ifdef ENABLE_GUOMI
					encrypt_pkcs12_file = params[2];
#endif

					ret = PKCS12_client_cert_cb (ssl, sign_pkcs12_file, x509_sign, pkey_sign
#ifdef ENABLE_GUOMI
							, encrypt_pkcs12_file, x509_encrypt, pkey_encrypt
#endif
							);
					if (session && state)
					{
						time_t new_must_negotiate;
						/* 私钥已校验, 调整state->must_negotiate参数值 */
						update_time (MAIN_THREAD_INDEX);
						new_must_negotiate = now_sec (MAIN_THREAD_INDEX) + max_int (10, session->opt->hello_window);
						if (state->must_negotiate > new_must_negotiate)
						{
							state->saved_must_negotiate = state->must_negotiate;
							state->must_negotiate = new_must_negotiate;
							msg (M_INFO, "adjusting tls handshake window from %d to %d", session->opt->handshake_window,
								max_int (10, session->opt->hello_window));
						}
					}
				}
				else
					if (strlen (global_cert_identify) > 0)	// BASE64编码的证书
					{
						ret = External_CryptoAPI_client_cert_cb (ssl, global_cert_identify, x509_sign, pkey_sign
#ifdef ENABLE_GUOMI
								, x509_encrypt, pkey_encrypt
#endif
							);
					}
					else
					{	
						msg (M_WARN, "read invalid data from stdin");	// 空白行无效输入
					}

	if (!ret)
		memset (global_cert_identify, 0x0, MAX_CERT_IDENTIFY_LEN);

	gc_free (&gc);
	return ret;
}

static int 
tls_client_cert_cb (SSL *ssl, X509 **x509_sign, EVP_PKEY **pkey_sign)
{
	int ret = 0;
	X509 *x509_encrypt = NULL;
	EVP_PKEY *pkey_encrypt = NULL;

	ret = tls_client_cert_cb_ext (ssl, x509_sign, pkey_sign, &x509_encrypt, &pkey_encrypt);
	if (x509_encrypt)
		X509_free (x509_encrypt);
	if (pkey_encrypt)
		EVP_PKEY_free (pkey_encrypt);
	return ret;
}

void
tls_ctx_server_new (struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	ASSERT (NULL != ctx);

#ifdef ENABLE_GUOMI
	ctx->ctx = SSL_CTX_new (GMTLSv1_TLSv1_server_method ());
#else
	ctx->ctx = SSL_CTX_new (SSLv23_server_method ());
#endif

	if (ctx->ctx == NULL)
		crypto_msg (M_FATAL, "SSL_CTX_new tls_ctx_server_new");

	/*
	 * 上海CA签发的证书, 可能带有OpenSSL不支持的标记为关键的扩展
	 * X509v3 Authority Key Identifier: critical
	 * 看一下v3_purp.c文件中的x509_supported_extension(X509_EXTENSION *ex)函数
	 */
	{
		X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
		unsigned long flags = X509_V_FLAG_IGNORE_CRITICAL;

		X509_VERIFY_PARAM_set_flags(param, flags);
		SSL_CTX_set1_param(ctx->ctx, param);
		X509_VERIFY_PARAM_free(param);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_CTX_set_tmp_rsa_callback (ctx->ctx, tmp_rsa_cb);
	SSL_CTX_set_tmp_ecdh_callback (ctx->ctx, tmp_ecdh_cb);
#endif
}

void
tls_ctx_client_new (struct tls_root_ctx *ctx, unsigned int ssl_flags)
{
	ASSERT (NULL != ctx);

#ifdef ENABLE_GUOMI
	ctx->ctx = SSL_CTX_new (GMTLSv1_TLSv1_client_method ());
#else
	ctx->ctx = SSL_CTX_new (SSLv23_client_method ());
#endif

	if (ctx->ctx == NULL)
		crypto_msg (M_FATAL, "SSL_CTX_new tls_ctx_client_new");

	// TLS协议设置客户证书回调
	SSL_CTX_set_client_cert_cb (ctx->ctx, tls_client_cert_cb);

#ifdef ENABLE_GUOMI
	// GM TLS协议设置客户证书回调
	SSL_CTX_set_client_cert_cb_ext (ctx->ctx, tls_client_cert_cb_ext);
#endif
}

void
tls_ctx_free (struct tls_root_ctx *ctx)
{
	ASSERT (NULL != ctx);
	if (NULL != ctx->ctx)
		SSL_CTX_free (ctx->ctx);
	ctx->ctx = NULL;
}

bool tls_ctx_initialised (struct tls_root_ctx *ctx)
{
	ASSERT (NULL != ctx);
	return NULL != ctx->ctx;
}

#define MAX_TLS_VERSION_ARRAY_LEN	8
#define MAX_TLS_VERSION_LEN			64

bool
tls_version_check (const char *tls_version)
{
	struct gc_arena gc = gc_new ();
	char **version_array = string_array_alloc (MAX_TLS_VERSION_ARRAY_LEN, MAX_TLS_VERSION_LEN, &gc);
	int i, array_len = MAX_TLS_VERSION_ARRAY_LEN;
	bool legal = true;

	ASSERT (NULL != tls_version);

	array_len = string_to_array (tls_version, ':', version_array, array_len, MAX_TLS_VERSION_LEN);
	for (i = 0; i < array_len; ++i)
	{
		if (strcasecmp ("SSLv3", version_array[i]) && strcasecmp ("TLSv1", version_array[i])
			&& strcasecmp ("TLSv1.1", version_array[i]) && strcasecmp ("TLSv1.2", version_array[i])
			&& strcasecmp ("TLSv1.3", version_array[i])
#ifdef ENABLE_GUOMI
			&& strcasecmp ("GMTLSv1", version_array[i]) && strcasecmp ("GMTLSv1.1", version_array[i])
#endif
			)
		{
			legal = false;
			msg (M_WARN, "unknown tls version %s", version_array[i]);
		}
	}

	gc_free (&gc);
	return legal;
}

static unsigned long
tls_version_mask (const char *tls_version)
{
#ifdef ENABLE_GUOMI
	unsigned long mask = SSL_OP_NO_GMTLSv1_1|SSL_OP_NO_GMTLSv1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1|
		SSL_OP_NO_SSLv3|SSL_OP_NO_SSLv2;
#else
#ifdef SSL_OP_NO_TLSv1_3
	unsigned long mask = SSL_OP_NO_TLSv1_3|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1|SSL_OP_NO_SSLv3|SSL_OP_NO_SSLv2;
#else
	unsigned long mask = SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1|SSL_OP_NO_SSLv3|SSL_OP_NO_SSLv2;
#endif
#endif

	struct gc_arena gc = gc_new ();
	char **version_array = string_array_alloc (MAX_TLS_VERSION_ARRAY_LEN, MAX_TLS_VERSION_LEN, &gc);
	int i, array_len = MAX_TLS_VERSION_ARRAY_LEN;

	ASSERT (NULL != tls_version);

	array_len = string_to_array (tls_version, ':', version_array, array_len, MAX_TLS_VERSION_LEN);
	for (i = 0; i < array_len; ++i)
	{
		if (strcasecmp ("SSLv3", version_array[i]) == 0)
			mask &= ~SSL_OP_NO_SSLv3;
		else if (strcasecmp ("TLSv1", version_array[i]) == 0)
			mask &= ~SSL_OP_NO_TLSv1;
		else if (strcasecmp ("TLSv1.1", version_array[i]) == 0)
			mask &= ~SSL_OP_NO_TLSv1_1;
		else if (strcasecmp ("TLSv1.2", version_array[i]) == 0)
			mask &= ~SSL_OP_NO_TLSv1_2;
#ifdef SSL_OP_NO_TLSv1_3
		else if (strcasecmp ("TLSv1.3", version_array[i]) == 0)
			mask &= ~SSL_OP_NO_TLSv1_3;
#endif
#ifdef ENABLE_GUOMI
		else if (strcasecmp ("GMTLSv1", version_array[i]) == 0)
			mask &= ~SSL_OP_NO_GMTLSv1;
		else if (strcasecmp ("GMTLSv1.1", version_array[i]) == 0)
			mask &= ~SSL_OP_NO_GMTLSv1_1;
#endif			
		else
		{
			msg (M_FATAL, "unknown tls version %s", version_array[i]);
			break;
		}
	}

	gc_free (&gc);
	return mask;
}

/*
 * Print debugging information on SSL/TLS session negotiation.
 */

#ifndef INFO_CALLBACK_SSL_CONST
#define INFO_CALLBACK_SSL_CONST const
#endif

static void
info_callback (INFO_CALLBACK_SSL_CONST SSL * s, int where, int ret)
{
	if (where & SSL_CB_LOOP)
		dmsg (D_HANDSHAKE_VERBOSE, "SSL state (%s): %s", where & SSL_ST_CONNECT ? "connect" :
			where & SSL_ST_ACCEPT ? "accept" : "undefined", SSL_state_string_long (s));
	else if (where & SSL_CB_ALERT)
		dmsg (D_HANDSHAKE_VERBOSE, "SSL alert (%s): %s: %s", where & SSL_CB_READ ? "read" : "write",
			SSL_alert_type_string_long (ret), SSL_alert_desc_string_long (ret));
}

void
tls_ctx_set_options (struct tls_root_ctx *ctx, unsigned int ssl_flags, const char *tls_version)
{
	ASSERT (NULL != ctx && NULL != tls_version);

	/* process SSL options including minimum TLS version we will accept from peer */
	{
		unsigned long sslopt = SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET | tls_version_mask (tls_version);
		// 要求客户端优先
/*
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
		sslopt |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
*/
		sslopt &= ~SSL_OP_CIPHER_SERVER_PREFERENCE;
#ifdef SSL_OP_NO_COMPRESSION
		/* Disable compression - flag not available in OpenSSL 0.9.8 */
		sslopt |= SSL_OP_NO_COMPRESSION;
#endif
		SSL_CTX_set_options (ctx->ctx, sslopt);
	}

	SSL_CTX_set_session_cache_mode (ctx->ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_default_passwd_cb (ctx->ctx, pem_password_callback);

	/* Require peer certificate verification */
#if P2MP_SERVER
	if (ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
	{
		msg (M_WARN, "WARNING: POTENTIALLY DANGEROUS OPTION "
			"--client-cert-not-required may accept clients which do not present a certificate");
	}
	else
#endif
		SSL_CTX_set_verify (ctx->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

	SSL_CTX_set_info_callback (ctx->ctx, info_callback);
}

static bool
is_tls_cipher_rule_str (const char *cipher, size_t cipher_len)
{
	ASSERT (NULL != cipher && 0 != cipher_len);

	return cipher[0] == '-' || cipher[0] == '+' || cipher[0] == '!' || cipher[0] == '@';
}

void
tls_ctx_restrict_ciphers (struct tls_root_ctx *ctx, const char *ciphers)
{
	size_t begin_of_cipher, end_of_cipher;
	const char *current_cipher;
	size_t current_cipher_len;

	const tls_cipher_name_pair *cipher_pair;
	char openssl_ciphers[4096];
	size_t openssl_ciphers_len = 0;

	if (ciphers == NULL)
	{
		/* 兼容GMTLS, ciphers == NULL时, 不使用缺省值 */
//		/* Use sane default TLS cipher list */
//		if (!SSL_CTX_set_cipher_list (ctx->ctx,
//				/* Use openssl's default list as a basis */
//				"DEFAULT"
//				/* Disable export ciphers and openssl's 'low' and 'medium' ciphers */
//				":!EXP:!LOW:!MEDIUM"
//				/* Disable unsupported TLS modes */
//				":!PSK:!SRP:!kRSA"))
//			crypto_msg (M_FATAL, "Failed to set default TLS cipher list.");
		return;
	}

	openssl_ciphers[0] = '\0';

	ASSERT (NULL != ctx);

	/* Translate IANA cipher suite names to OpenSSL names */
	begin_of_cipher = end_of_cipher = 0;
	for (; begin_of_cipher < strlen (ciphers); begin_of_cipher = end_of_cipher)
	{
		end_of_cipher += strcspn (&ciphers[begin_of_cipher], ":");
		cipher_pair = tls_get_cipher_name_pair (&ciphers[begin_of_cipher], end_of_cipher - begin_of_cipher);

		if (NULL == cipher_pair)
		{
			/* No translation found, use original */
			current_cipher = &ciphers[begin_of_cipher];
			current_cipher_len = end_of_cipher - begin_of_cipher;
			
			/* Ignore rule_str */
			if (current_cipher_len == 0 || !is_tls_cipher_rule_str (current_cipher, current_cipher_len))
			{
				/* Issue warning on missing translation %.*s format specifier expects length of type int,
				 * so guarantee that length is small enough and cast to int.
				 */
				msg (M_WARN, "No valid translation found for TLS cipher '%.*s'",
					(int) MIN (current_cipher_len, 256), current_cipher);
			}
		}
		else
		{
			/* Use OpenSSL name */
			current_cipher = cipher_pair->openssl_name;
			current_cipher_len = strlen (current_cipher);

			if (end_of_cipher - begin_of_cipher == current_cipher_len &&
				0 != memcmp (&ciphers[begin_of_cipher], cipher_pair->iana_name, end_of_cipher - begin_of_cipher))
			{
				// Non-IANA name used, show warning
				msg (M_WARN, "Deprecated TLS cipher name '%s', please use IANA name '%s'",
					cipher_pair->openssl_name, cipher_pair->iana_name);
			}
		}

		/* Make sure new cipher name fits in cipher string */
		if ((SIZE_MAX - openssl_ciphers_len) < current_cipher_len ||
			((sizeof (openssl_ciphers) - 1) < openssl_ciphers_len + current_cipher_len))
		{
			msg (M_FATAL, "Failed to set restricted TLS cipher list, too long (>%d).",
				(int) sizeof (openssl_ciphers) - 1);
			break;
		}

		/* Concatenate cipher name to OpenSSL cipher string */
		memcpy (&openssl_ciphers[openssl_ciphers_len], current_cipher, current_cipher_len);
		openssl_ciphers_len += current_cipher_len;
		openssl_ciphers[openssl_ciphers_len] = ':';
		openssl_ciphers_len++;
		end_of_cipher++;
	}

	if (openssl_ciphers_len > 0)
		openssl_ciphers[openssl_ciphers_len - 1] = '\0';

	/* Set OpenSSL cipher list */
	if (!SSL_CTX_set_cipher_list (ctx->ctx, openssl_ciphers))
		crypto_msg (M_FATAL, "Failed to set restricted TLS cipher list: %s", openssl_ciphers);
}

void
tls_ctx_check_cert_time (const struct tls_root_ctx *ctx)
{
	int ret;
	SSL *ssl = NULL;
	const X509 *cert = NULL;

	ASSERT (ctx);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(LIBRESSL_VERSION_NUMBER)
	/* OpenSSL 1.0.2 and up */
	cert = SSL_CTX_get0_certificate (ctx->ctx);
#else
	/* OpenSSL 1.0.1 and earlier need an SSL object to get at the certificate */
	ssl = SSL_new (ctx->ctx);
	cert = SSL_get_certificate (ssl);
#endif

	if (cert == NULL)
	{
		goto cleanup; /* Nothing to check if there is no certificate */
	}

	ret = X509_cmp_time (X509_get_notBefore (cert), NULL);
	if (ret == 0)
	{
		msg (D_TLS_DEBUG_MED, "Failed to read certificate notBefore field.");
	}
	if (ret > 0)
	{
		msg (M_WARN, "WARNING: Your certificate is not yet valid!");
	}

	ret = X509_cmp_time (X509_get_notAfter (cert), NULL);
	if (ret == 0)
	{
		msg (D_TLS_DEBUG_MED, "Failed to read certificate notAfter field.");
	}
	if (ret < 0)
	{
		msg (M_WARN, "WARNING: Your certificate has expired!");
	}

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
	SSL_free (ssl);
#endif
	return;
}

void
tls_ctx_load_dh_params (struct tls_root_ctx *ctx, const char *dh_file, const char *dh_file_inline)
{
	DH *dh;
	BIO *bio;

	ASSERT (NULL != ctx);

	if (!strcmp (dh_file, INLINE_FILE_TAG) && dh_file_inline)
	{
		if (!(bio = BIO_new_mem_buf ((char *) dh_file_inline, -1)))
			crypto_msg (M_FATAL, "Cannot open memory BIO for inline DH parameters");
	}
	else
	{
		/* Get Diffie Hellman Parameters */
		if (!(bio = BIO_new_file (dh_file, "r")))
			crypto_msg (M_FATAL, "Cannot open %s for DH parameters", dh_file);
	}

	dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
	BIO_free (bio);

	if (!dh)
		crypto_msg (M_FATAL, "Cannot load DH parameters from %s", dh_file);
	if (!SSL_CTX_set_tmp_dh (ctx->ctx, dh))
		crypto_msg (M_FATAL, "SSL_CTX_set_tmp_dh");

	msg (D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with %d bit key", 8 * DH_size (dh));

	DH_free (dh);
}

int
tls_ctx_load_pkcs12 (struct tls_root_ctx *ctx, const char *pkcs12_file, const char *pkcs12_file_inline, bool load_ca_file)
{
	void ssl_purge_auth (const bool auth_user_pass_only);
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12;
	int i, verify_ok, input_count = 0;
	char password[256];

	ASSERT (NULL != ctx);

	if (!strcmp (pkcs12_file, INLINE_FILE_TAG) && pkcs12_file_inline)
	{
		BIO *b64 = BIO_new (BIO_f_base64 ());
		BIO *bio = BIO_new_mem_buf ((void *) pkcs12_file_inline, (int) strlen (pkcs12_file_inline));
		ASSERT (b64 && bio);
		BIO_push (b64, bio);
		p12 = d2i_PKCS12_bio (b64, NULL);
		if (!p12)
			crypto_msg (M_FATAL, "Error reading inline PKCS#12 file");
		BIO_free (b64);
		BIO_free (bio);
	}
	else
	{
		/* Load the PKCS #12 file */
		if (!(fp = platform_fopen (pkcs12_file, "rb")))
			crypto_msg (M_FATAL, "Error opening file %s", pkcs12_file);
		p12 = d2i_PKCS12_fp (fp, NULL);
		fclose (fp);
		if (!p12)
			crypto_msg (M_FATAL, "Error reading PKCS#12 file %s", pkcs12_file);
	}

	/* Parse the PKCS #12 file */
	verify_ok = PKCS12_parse (p12, "", &pkey, &cert, &ca);
	if (!verify_ok)
	{
		do
		{
			pem_password_callback (password, sizeof (password) - 1, 0, NULL);
			/* Reparse the PKCS #12 file with password */
			ca = NULL;
			if (!(verify_ok = PKCS12_parse (p12, password, &pkey, &cert, &ca)))
			{
#ifdef ENABLE_MANAGEMENT
				if (management && (ERR_GET_REASON (ERR_peek_error ()) == PKCS12_R_MAC_VERIFY_FAILURE))
					management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
				ssl_purge_auth (false);	// 通知客户端重新输入私钥保护密码
			}
		} while (!verify_ok && ++input_count < MAX_PRI_KEY_PASS_INPUT_COUNT);
	}
	PKCS12_free (p12);

	if (verify_ok)
	{
#ifdef ENABLE_GUOMI
		GM_X509_set_usage (cert, GM_X509_USAGE_SIGN);
		if (EVP_PKEY_type (pkey->type) == EVP_PKEY_EC)
		{
			EC_KEY *eckey = EVP_PKEY_get1_EC_KEY (pkey);
			if (eckey)
			{
				GM_EC_KEY_set_usage (eckey, GM_KEY_USAGE_SIGN);
				EC_KEY_free (eckey);
			}
		}
		else if (EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA || EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA2)
		{
			RSA *rsakey = EVP_PKEY_get1_RSA (pkey);
			if (rsakey)
			{
				GM_RSA_set_usage (rsakey, GM_KEY_USAGE_SIGN);
				RSA_free (rsakey);
			}
		}
#endif

		/* Load Certificate */
		if (!SSL_CTX_use_certificate (ctx->ctx, cert))
			crypto_msg (M_FATAL, "Cannot use certificate");

		/* Load Private Key */
		if (!SSL_CTX_use_PrivateKey (ctx->ctx, pkey))
			crypto_msg (M_FATAL, "Cannot use private key");
		warn_if_group_others_accessible (pkcs12_file);

		/* Check Private Key */
		if (!SSL_CTX_check_private_key (ctx->ctx))
			crypto_msg (M_FATAL, "Private key does not match the certificate");

		/* Set Certificate Verification chain */
		if (load_ca_file)
		{
			/* Add CAs from PKCS12 to the cert store and mark them as trusted. 
			 * They're also used to fill in the chain of intermediate certs as necessary.
			 */
			if (ca && sk_X509_num (ca))
			{
				X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx->ctx);
				for (i = 0; i < sk_X509_num (ca); i++)
				{
					if (!X509_STORE_add_cert (cert_store, sk_X509_value (ca, i)))
					{
						crypto_msg (M_FATAL, "Cannot add certificate to certificate chain (X509_STORE_add_cert)");
						break;
					}
					if (!SSL_CTX_add_client_CA (ctx->ctx, sk_X509_value (ca, i)))
					{
						crypto_msg (M_FATAL, "Cannot add certificate to client CA list (SSL_CTX_add_client_CA)");
						break;
					}
				}
			}
		}
		else
		{
			/* If trusted CA certs were loaded from a PEM file, and we ignore the
			 * ones in PKCS12, do load PKCS12-provided certs to the client extra
			 * certs chain just in case they include intermediate CAs needed to
			 * prove my identity to the other end. This does not make them trusted.
			 */
			if (ca && sk_X509_num (ca))
			{
				X509 *dup;
				for (i = 0; i < sk_X509_num (ca); i++)
				{
					/* SSL_CTX_add_extra_chain_cert(...) 不会增加cert引用计数 */
					dup = X509_dup (sk_X509_value (ca, i));
					if (!dup || !SSL_CTX_add_extra_chain_cert (ctx->ctx, dup))
					{
						crypto_msg (M_FATAL, "Cannot add extra certificate to chain (SSL_CTX_add_extra_chain_cert)");
						break;
					}
				}
			}
		}
	}

	if (cert)
		X509_free (cert);
	if (pkey)
		EVP_PKEY_free (pkey);
	if (ca)
		sk_X509_pop_free (ca, X509_free);

	return verify_ok;
}

#ifdef ENABLE_CRYPTOAPI
void
tls_ctx_load_cryptoapi (struct tls_root_ctx *ctx, const char *cryptoapi_cert)
{
	ASSERT (NULL != ctx);

	/* Load Certificate and Private Key */
	if (!SSL_CTX_use_CryptoAPI_certificate (ctx->ctx, cryptoapi_cert))
	{
		crypto_msg (M_FATAL, "Cannot load certificate \"%s\" from Microsoft Certificate Store", cryptoapi_cert);
	}
}
#endif /* WIN32 */

#ifdef ENABLE_GUOMI
void
tls_ctx_load_gmedapi (struct tls_root_ctx *ctx, const char *gmedapi_cert)
{
	ASSERT (NULL != ctx);

	/* Load Certificate and Private Key */
	if (!SSL_CTX_use_GmedCertAPI_certificate (ctx->ctx, gmedapi_cert))
	{
		crypto_msg (M_FATAL, "Cannot load certificate \"%s\" from GUOMI encrypt device", gmedapi_cert);
	}
}
#endif

static void
tls_ctx_add_extra_certs (struct tls_root_ctx *ctx, BIO *bio)
{
	X509 *cert;
	for (;;)
	{
		cert = NULL;
		if (!PEM_read_bio_X509 (bio, &cert, 0, NULL)) /* takes ownership of cert */
			break;
		if (!cert)
		{
			crypto_msg (M_FATAL, "Error reading extra certificate");
			break;
		}
		/* SSL_CTX_add_extra_chain_cert(...) 不会增加cert引用计数 */
		if (SSL_CTX_add_extra_chain_cert (ctx->ctx, cert) != 1)
		{
			crypto_msg (M_FATAL, "Error adding extra certificate");
			break;
		}
	}
}

/* Like tls_ctx_load_cert, but returns a copy of the certificate in **X509 */
static void
tls_ctx_load_cert_file_and_copy (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_file_inline, X509 **x509)
{
	BIO *in = NULL;
	X509 *x = NULL;
	int ret = 0;
	bool inline_file = false;

	ASSERT (NULL != ctx);
	if (NULL != x509)
		ASSERT (NULL == *x509);

	inline_file = (strcmp (cert_file, INLINE_FILE_TAG) == 0);

	if (inline_file && cert_file_inline)
		in = BIO_new_mem_buf ((char *) cert_file_inline, -1);
	else
		in = BIO_new_file (cert_file, "r");

	if (in == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
		goto end;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	x = PEM_read_bio_X509 (in, NULL, ctx->ctx->default_passwd_callback, ctx->ctx->default_passwd_callback_userdata);
#else
	x = PEM_read_bio_X509 (in, NULL, SSL_CTX_get_default_passwd_cb (ctx->ctx),
			SSL_CTX_get_default_passwd_cb_userdata (ctx->ctx));
#endif
	if (x == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PEM_LIB);
		goto end;
	}

	ret = SSL_CTX_use_certificate (ctx->ctx, x);
	if (ret)
		tls_ctx_add_extra_certs (ctx, in);

end:
	if (!ret)
	{
		if (inline_file)
			crypto_msg (M_FATAL, "Cannot load inline certificate file");
		else
			crypto_msg (M_FATAL, "Cannot load certificate file %s", cert_file);
	}

	if (in != NULL)
		BIO_free (in);
	if (x509)
		*x509 = x;
	else if (x)
		X509_free (x);
}

void
tls_ctx_load_cert_file (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_file_inline)
{
	X509 *x509 = NULL;
	tls_ctx_load_cert_file_and_copy (ctx, cert_file, cert_file_inline, &x509);
	if (x509)
	{
#ifdef ENABLE_GUOMI
		GM_X509_set_usage (x509, GM_X509_USAGE_SIGN);
#endif
		X509_free (x509);
	}
}

void
tls_ctx_free_cert_file (X509 *x509)
{
	X509_free (x509);
}

int
tls_ctx_load_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file, const char *priv_key_file_inline)
{
	int status = 0;
	SSL_CTX *ssl_ctx = NULL;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = 1;

	ASSERT (NULL != ctx);

	ssl_ctx = ctx->ctx;

	if (!strcmp (priv_key_file, INLINE_FILE_TAG) && priv_key_file_inline)
		in = BIO_new_mem_buf ((char *) priv_key_file_inline, -1);
	else
		in = BIO_new_file (priv_key_file, "r");

	if (!in)
		goto end;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	pkey = PEM_read_bio_PrivateKey (in, NULL, ssl_ctx->default_passwd_callback, ssl_ctx->default_passwd_callback_userdata);
#else
	pkey = PEM_read_bio_PrivateKey (in, NULL, SSL_CTX_get_default_passwd_cb (ctx->ctx),
			SSL_CTX_get_default_passwd_cb_userdata (ctx->ctx));
#endif
	if (!pkey)
		goto end;

#ifdef ENABLE_GUOMI
	if (EVP_PKEY_type (pkey->type) == EVP_PKEY_EC)
	{
		EC_KEY *eckey = EVP_PKEY_get1_EC_KEY (pkey);
		if (eckey)
		{
			GM_EC_KEY_set_usage (eckey, GM_KEY_USAGE_SIGN);
			EC_KEY_free (eckey);
		}
	}
	else if (EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA || EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA2)
	{
		RSA *rsakey = EVP_PKEY_get1_RSA (pkey);
		if (rsakey)
		{
			GM_RSA_set_usage (rsakey, GM_KEY_USAGE_SIGN);
			RSA_free (rsakey);
		}
	}
#endif

	if (!SSL_CTX_use_PrivateKey (ssl_ctx, pkey))
	{
#ifdef ENABLE_MANAGEMENT
		if (management && (ERR_GET_REASON (ERR_peek_error ()) == EVP_R_BAD_DECRYPT))
			management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
		crypto_msg (M_WARN, "Cannot load private key file %s", priv_key_file);
		goto end;
	}
	warn_if_group_others_accessible (priv_key_file);

	/* Check Private Key */
	if (!SSL_CTX_check_private_key (ssl_ctx))
		crypto_msg (M_FATAL, "Private key does not match the certificate");
	ret = 0;

end:
	if (pkey)
		EVP_PKEY_free (pkey);
	if (in)
		BIO_free (in);
	return ret;
}

#ifdef MANAGMENT_EXTERNAL_KEY

int
tls_ctx_use_external_private_key (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_file_inline)
{
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec = NULL;
	RSA *rsa = NULL;
	RSA *pub_rsa;
	X509 *cert = NULL;

	ASSERT (NULL != ctx);

	tls_ctx_load_cert_file_and_copy (ctx, cert_file, cert_file_inline, &cert);

	ASSERT (NULL != cert);

	pkey = X509_get_pubkey (cert);

	if (EVP_PKEY_type (EVP_PKEY_id (pkey)) == EVP_PKEY_EC)
	{
#ifdef ENABLE_GUOMI
		ec = EC_KEY_new_by_curve_name (NID_sm2);
		ECDSA_set_method (ec, ECDSA_sm2_ex (sm2_sign_ex));
#else
		ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
#endif
		EVP_PKEY_free (pkey);
		pkey = EVP_PKEY_new ();
		EVP_PKEY_assign_EC_KEY (pkey, ec);
	}
	else
	{
		/* allocate RSA object */
		rsa = RSA_new ();
		if (rsa == NULL)
		{
			SSLerr (SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
			goto err;
		}
		else
		{
			/* initialize RSA object */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			ASSERT (cert->cert_info->key->pkey); /* NULL before SSL_CTX_use_certificate() is called */
			pub_rsa = cert->cert_info->key->pkey->pkey.rsa;
			rsa->n = BN_dup (pub_rsa->n);
			rsa->flags |= RSA_FLAG_EXT_PKEY;
#else
			{
				const BIGNUM *n = NULL;
				const BIGNUM *e = NULL;

				pub_rsa = EVP_PKEY_get0_RSA (pkey);
				RSA_get0_key (pub_rsa, &n, &e, NULL);
				RSA_set0_key (rsa, BN_dup (n), BN_dup (e), NULL);
				RSA_set_flags (rsa, RSA_flags (rsa) | RSA_FLAG_EXT_PKEY);
			}
#endif

			if (!RSA_set_method (rsa, rsa_meth_new ()))
				goto err;
		}

		EVP_PKEY_free (pkey);
		pkey = EVP_PKEY_new ();
		EVP_PKEY_assign_RSA (pkey, rsa);
	}

	/* bind our custom RSA object to ssl_ctx */
	if (!SSL_CTX_use_PrivateKey (ctx->ctx, pkey))
		goto err;

	X509_free (cert);
	EVP_PKEY_free (pkey); /* this will down ref pkey and rsa */

	return 1;

err:
	if (cert)
		X509_free (cert);
	if (pkey)
		EVP_PKEY_free (pkey);
	crypto_msg (M_FATAL, "Cannot enable SSL external private key capability");
	return 0;
}

#endif

static int
sk_x509_name_cmp (const X509_NAME * const *a, const X509_NAME * const *b)
{
	return X509_NAME_cmp (*a, *b);
}

void
tls_ctx_load_ca (struct tls_root_ctx *ctx, const char *ca_file, const char *ca_file_inline,  const char *ca_path, bool tls_server)
{
	STACK_OF(X509_INFO) *info_stack = NULL;
	STACK_OF(X509_NAME) *cert_names = NULL;
	X509_LOOKUP *lookup = NULL;
	X509_STORE *store = NULL;
	X509_NAME *xn = NULL;
	BIO *in = NULL;
	int i, crl_num = 0, added = 0, prev = 0;

	ASSERT (NULL != ctx);

	store = SSL_CTX_get_cert_store (ctx->ctx);
	if (!store)
		crypto_msg (M_FATAL, "Cannot get certificate store (SSL_CTX_get_cert_store)");

	/* Try to add certificates and CRLs from ca_file */
	if (ca_file)
	{
		if (!strcmp (ca_file, INLINE_FILE_TAG) && ca_file_inline)
			in = BIO_new_mem_buf ((char *) ca_file_inline, -1);
		else
			in = BIO_new_file (ca_file, "r");

		if (in)
			info_stack = PEM_X509_INFO_read_bio (in, NULL, NULL, NULL);

		if (info_stack)
		{
			for (i = 0; i < sk_X509_INFO_num (info_stack); i++)
			{
				X509_INFO *info = sk_X509_INFO_value (info_stack, i);
				if (info->crl)
				{
					++crl_num;
					X509_STORE_add_crl (store, info->crl);
				}

				if (tls_server && !info->x509)
				{
					crypto_msg (M_FATAL, "X509 name was missing in TLS mode");
					break;
				}

				if (info->x509)
				{
					X509_STORE_add_cert (store, info->x509);
					added++;

					if (!tls_server)
						continue;

					/* Use names of CAs as a client CA list */
					if (cert_names == NULL)
					{
						cert_names = sk_X509_NAME_new (sk_x509_name_cmp);
						if (!cert_names)
							continue;
					}

					xn = X509_get_subject_name (info->x509);
					if (!xn)
						continue;

					/* Don't add duplicate CA names */
					if (sk_X509_NAME_find (cert_names, xn) == -1)
					{
						xn = X509_NAME_dup (xn);
						if (!xn)
							continue;
						sk_X509_NAME_push (cert_names, xn);
					}
				}

				if (tls_server) {
					int cnum = sk_X509_NAME_num (cert_names);
					if (cnum != (prev + 1))
					{
						msg (M_WARN, "Cannot load CA certificate file %s (entry %d did not validate)", np (ca_file), added);
					}
					prev = cnum;
				}

			}
			sk_X509_INFO_pop_free (info_stack, X509_INFO_free);
		}

		if (tls_server)
			SSL_CTX_set_client_CA_list (ctx->ctx, cert_names);

		// 允许CA列表为空
		/*
		if (!added)
			crypto_msg (M_FATAL, "Cannot load CA certificate file %s (no entries were read)", np (ca_file));
		*/

		if (tls_server) {
			int cnum = sk_X509_NAME_num (cert_names);
			if (cnum != added)
				crypto_msg (M_FATAL, "Cannot load CA certificate file %s (only %d of %d entries were valid X509 names)", np (ca_file), cnum, added);
		}

		if (in)
			BIO_free (in);
	}

	/* Set a store for certs (CA & CRL) with a lookup on the "capath" hash directory */
	if (ca_path)
	{
		lookup = X509_STORE_add_lookup (store, X509_LOOKUP_hash_dir ());
		if (lookup && X509_LOOKUP_add_dir (lookup, ca_path, X509_FILETYPE_PEM))
			msg (M_WARN, "WARNING: experimental option --capath %s", ca_path);
		else
			crypto_msg (M_FATAL, "Cannot add lookup at --capath %s", ca_path);
		if (crl_num != 0)
			X509_STORE_set_flags (store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}
}

void
tls_ctx_load_extra_certs (struct tls_root_ctx *ctx, const char *extra_certs_file, const char *extra_certs_file_inline)
{
	BIO *in;
	if (!strcmp (extra_certs_file, INLINE_FILE_TAG) && extra_certs_file_inline)
		in = BIO_new_mem_buf ((char *)extra_certs_file_inline, -1);
	else
		in = BIO_new_file (extra_certs_file, "r");

	if (in == NULL)
		crypto_msg (M_FATAL, "Cannot load extra-certs file: %s", extra_certs_file);
	else
		tls_ctx_add_extra_certs (ctx, in);

	BIO_free (in);
}


#ifdef ENABLE_GUOMI
int
tls_ctx_load_encrypt_pkcs12 (struct tls_root_ctx *ctx, const char *pkcs12_file, const char *pkcs12_file_inline)
{
	void ssl_purge_auth (const bool auth_user_pass_only);
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12;
	int verify_ok, input_count = 0;
	char password[256];

	ASSERT (NULL != ctx);

	if (!strcmp (pkcs12_file, INLINE_FILE_TAG) && pkcs12_file_inline)
	{
		BIO *b64 = BIO_new (BIO_f_base64 ());
		BIO *bio = BIO_new_mem_buf ((void *) pkcs12_file_inline, (int) strlen (pkcs12_file_inline));
		ASSERT (b64 && bio);
		BIO_push (b64, bio);
		p12 = d2i_PKCS12_bio (b64, NULL);
		if (!p12)
			crypto_msg (M_FATAL, "Error reading inline PKCS#12 file");
		BIO_free (b64);
		BIO_free (bio);
	}
	else
	{
		/* Load the PKCS #12 file */
		if (!(fp = platform_fopen (pkcs12_file, "rb")))
			crypto_msg (M_FATAL, "Error opening file %s", pkcs12_file);
		p12 = d2i_PKCS12_fp (fp, NULL);
		fclose (fp);
		if (!p12)
			crypto_msg (M_FATAL, "Error reading PKCS#12 file %s", pkcs12_file);
	}

	/* Parse the PKCS #12 file */
	verify_ok = PKCS12_parse (p12, "", &pkey, &cert, &ca);
	if (!verify_ok)
	{
		do
		{
			pem_password_callback (password, sizeof (password) - 1, 0, NULL);
			/* Reparse the PKCS #12 file with password */
			ca = NULL;
			if (!(verify_ok = PKCS12_parse (p12, password, &pkey, &cert, &ca)))
			{
#ifdef ENABLE_MANAGEMENT
				if (management && (ERR_GET_REASON (ERR_peek_error ()) == PKCS12_R_MAC_VERIFY_FAILURE))
					management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
				ssl_purge_auth (false);	// 通知客户端重新输入私钥保护密码
			}
		} while (!verify_ok && ++input_count < MAX_PRI_KEY_PASS_INPUT_COUNT);
	}
	PKCS12_free (p12);

	if (verify_ok)
	{
		GM_X509_set_usage (cert, GM_X509_USAGE_ENCRYPT);
		if (EVP_PKEY_type (pkey->type) == EVP_PKEY_EC)
		{
			EC_KEY *eckey = EVP_PKEY_get1_EC_KEY (pkey);
			if (eckey)
			{
				GM_EC_KEY_set_usage (eckey, GM_X509_USAGE_ENCRYPT);
				EC_KEY_free (eckey);
			}
		}
		else if (EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA || EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA2)
		{
			RSA *rsakey = EVP_PKEY_get1_RSA (pkey);
			if (rsakey)
			{
				GM_RSA_set_usage (rsakey, GM_X509_USAGE_ENCRYPT);
				RSA_free (rsakey);
			}
		}

		/* Load encrypt Certificate */
		if (!SSL_CTX_use_encrypt_certificate (ctx->ctx, cert))
			crypto_msg (M_FATAL, "Cannot use encrypt certificate");

		/* Load encrypt Private Key */
		if (!SSL_CTX_use_encrypt_PrivateKey (ctx->ctx, pkey))
			crypto_msg (M_FATAL, "Cannot use encrypt private key");
		warn_if_group_others_accessible (pkcs12_file);

		/* Check encrypt Private Key */
		if (!SSL_CTX_check_encrypt_private_key (ctx->ctx))
			crypto_msg (M_FATAL, "Private key does not match the certificate");
	}

	if (cert)
		X509_free (cert);
	if (pkey)
		EVP_PKEY_free (pkey);

	return verify_ok;
}

void
tls_ctx_load_encrypt_cert_file (struct tls_root_ctx *ctx, const char *cert_file, const char *cert_file_inline)
{
	BIO *in = NULL;
	X509 *x = NULL;
	int ret = 0;
	bool inline_file = false;

	ASSERT (NULL != ctx);

	inline_file = (strcmp (cert_file, INLINE_FILE_TAG) == 0);

	if (inline_file && cert_file_inline)
		in = BIO_new_mem_buf ((char *) cert_file_inline, -1);
	else
		in = BIO_new_file (cert_file, "r");

	if (in == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
		goto end;
	}

	x = PEM_read_bio_X509 (in, NULL, ctx->ctx->default_passwd_callback, ctx->ctx->default_passwd_callback_userdata);
	if (x == NULL)
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PEM_LIB);
		goto end;
	}

	GM_X509_set_usage (x, GM_X509_USAGE_ENCRYPT);

	ret = SSL_CTX_use_encrypt_certificate (ctx->ctx, x);

end:
	if (!ret)
	{
		if (inline_file)
			crypto_msg (M_FATAL, "Cannot load inline certificate file");
		else
			crypto_msg (M_FATAL, "Cannot load certificate file %s", cert_file);
	}

	if (in != NULL)
		BIO_free (in);
	if (x)
		X509_free (x);
}

int
tls_ctx_load_encrypt_priv_file (struct tls_root_ctx *ctx, const char *priv_key_file, const char *priv_key_file_inline)
{
	int status = 0;
	SSL_CTX *ssl_ctx = NULL;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = 1;

	ASSERT (NULL != ctx);

	ssl_ctx = ctx->ctx;

	if (!strcmp (priv_key_file, INLINE_FILE_TAG) && priv_key_file_inline)
		in = BIO_new_mem_buf ((char *) priv_key_file_inline, -1);
	else
		in = BIO_new_file (priv_key_file, "r");

	if (!in)
		goto end;

	pkey = PEM_read_bio_PrivateKey (in, NULL, ssl_ctx->default_passwd_callback, ssl_ctx->default_passwd_callback_userdata);
	if (!pkey)
		goto end;

	if (EVP_PKEY_type (pkey->type) == EVP_PKEY_EC)
	{
		EC_KEY *eckey = EVP_PKEY_get1_EC_KEY (pkey);
		if (eckey)
		{
			GM_EC_KEY_set_usage (eckey, GM_KEY_USAGE_ENCRYPT);
			EC_KEY_free (eckey);
		}
	}
	else if (EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA || EVP_PKEY_type (pkey->type) == EVP_PKEY_RSA2)
	{
		RSA *rsakey = EVP_PKEY_get1_RSA (pkey);
		if (rsakey)
		{
			GM_RSA_set_usage (rsakey, GM_KEY_USAGE_ENCRYPT);
			RSA_free (rsakey);
		}
	}

	if (!SSL_CTX_use_encrypt_PrivateKey (ssl_ctx, pkey))
	{
#ifdef ENABLE_MANAGEMENT
		if (management && (ERR_GET_REASON (ERR_peek_error ()) == EVP_R_BAD_DECRYPT))
			management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
		crypto_msg (M_WARN, "Cannot load encrypt private key file %s", priv_key_file);
		goto end;
	}
	warn_if_group_others_accessible (priv_key_file);

	/* Check Private Key */
	if (!SSL_CTX_check_encrypt_private_key (ssl_ctx))
		crypto_msg (M_FATAL, "Private key does not match the certificate");
	ret = 0;

end:
	if (pkey)
		EVP_PKEY_free (pkey);
	if (in)
		BIO_free (in);
	return ret;
}
#endif

/* **************************************
 *
 * Key-state specific functions
 *
 ***************************************/
/*
 *
 * BIO functions
 *
 */

#ifdef BIO_DEBUG

#warning BIO_DEBUG defined

static FILE *biofp;                            /* GLOBAL */
static bool biofp_toggle;                      /* GLOBAL */
static time_t biofp_last_open;                 /* GLOBAL */
static const int biofp_reopen_interval = 600;  /* GLOBAL */

static void
close_biofp (void)
{
	if (biofp)
	{
		ASSERT (!fclose (biofp));
		biofp = NULL;
	}
}

static void
open_biofp (void)
{
	const time_t current = time (NULL);
	const pid_t pid = getpid ();

	if (biofp_last_open + biofp_reopen_interval < current)
		close_biofp ();
	if (!biofp)
	{
		char fn[256];
		openvpn_snprintf (fn, sizeof (fn), "bio/%d-%d.log", pid, biofp_toggle);
		biofp = fopen (fn, "w");
		ASSERT (biofp);
		biofp_last_open = time (NULL);
		biofp_toggle ^= 1;
	}
}

static void
bio_debug_data (const char *mode, BIO *bio, const uint8_t *buf, int len, const char *desc)
{
	struct gc_arena gc = gc_new ();
	if (len > 0)
	{
		open_biofp ();
		fprintf (biofp, "BIO_%s %s time=" time_format " bio=" ptr_format " len=%d data=%s\n",
			mode, desc, time (NULL), (ptr_type) bio, len, format_hex (buf, len, 0, &gc));
		fflush (biofp);
	}
	gc_free (&gc);
}

static void
bio_debug_oc (const char *mode, BIO *bio)
{
	open_biofp ();
	fprintf (biofp, "BIO %s time=" time_format " bio=" ptr_format "\n", mode, time (NULL), (ptr_type) bio);
	fflush (biofp);
}

#endif

/*
 * OpenVPN's interface to SSL/TLS authentication,
 * encryption, and decryption is exclusively through "memory BIOs".
 */
static BIO *
getbio (const BIO_METHOD * type, const char *desc)
{
	BIO *ret = BIO_new ((BIO_METHOD *) type);
	if (!ret)
		crypto_msg (M_FATAL, "Error creating %s BIO", desc);
	return ret;
}

/*
 * Write to an OpenSSL BIO in non-blocking mode.
 */
static int
bio_write (BIO *bio, const uint8_t *data, int size, const char *desc)
{
	int i;
	int ret = 0;
	ASSERT (size >= 0);
	if (size)
	{
		/*
		* Free the L_TLS lock prior to calling BIO routines so that foreground thread can still call
		* tls_pre_decrypt or tls_pre_encrypt, allowing tunnel packet forwarding to continue.
		*/
#ifdef BIO_DEBUG
		bio_debug_data ("write", bio, data, size, desc);
#endif
		i = BIO_write (bio, data, size);

		if (i < 0)
		{
			if (BIO_should_retry (bio))
			{
				;
			}
			else
			{
				crypto_msg (D_TLS_ERRORS, "TLS ERROR: BIO write %s error", desc);
				ret = -1;
				ERR_clear_error ();
			}
		}
		else if (i != size)
		{
			crypto_msg (D_TLS_ERRORS, "TLS ERROR: BIO write %s incomplete %d/%d", desc, i, size);
			ret = -1;
			ERR_clear_error ();
		}
		else
		{			/* successful write */
			dmsg (D_HANDSHAKE_VERBOSE, "BIO write %s %d bytes", desc, i);
			ret = 1;
		}
	}
	return ret;
}

/*
 * Inline functions for reading from and writing to BIOs.
 */

static void
bio_write_post (const int status, struct buffer *buf)
{
	if (status == 1) /* success status return from bio_write? */
	{
		memset (BPTR (buf), 0, BLEN (buf)); /* erase data just written */
		buf->len = 0;
	}
}

/*
 * Read from an OpenSSL BIO in non-blocking mode.
 */
static int
bio_read (BIO *bio, struct buffer *buf, int maxlen, const char *desc)
{
	int i, ret = 0;
	ASSERT (buf->len >= 0);
	if (buf->len)
	{
		;
	}
	else
	{
		int len = buf_forward_capacity (buf);
		if (maxlen < len)
			len = maxlen;

		/* BIO_read brackets most of the serious RSA key negotiation number crunching. */
		i = BIO_read (bio, BPTR (buf), len);

		VALGRIND_MAKE_READABLE ((void *) &i, sizeof (i));

#ifdef BIO_DEBUG
		bio_debug_data ("read", bio, BPTR (buf), i, desc);
#endif
		if (i < 0)
		{
			if (BIO_should_retry (bio))
			{
				;
			}
			else
			{
				crypto_msg (D_TLS_ERRORS, "TLS_ERROR: BIO read %s error", desc);
				buf_reset_len (buf);
				ret = -1;
				ERR_clear_error ();
			}
		}
		else if (!i)
		{
			buf_reset_len (buf);
		}
		else
		{			/* successful read */
			dmsg (D_HANDSHAKE_VERBOSE, "BIO read %s %d bytes", desc, i);
			buf->len = i;
			ret = 1;
			VALGRIND_MAKE_READABLE ((void *) BPTR (buf), BLEN (buf));
		}
	}
	return ret;
}

void
key_state_ssl_init (struct key_state_ssl *ks_ssl, const struct tls_root_ctx *ssl_ctx, bool is_server, struct tls_session *session)
{
	ASSERT (NULL != ssl_ctx);
	ASSERT (ks_ssl);
	CLEAR (*ks_ssl);

	ks_ssl->ssl = SSL_new (ssl_ctx->ctx);
	if (!ks_ssl->ssl)
		crypto_msg (M_FATAL, "SSL_new failed");

	/* put session * in ssl object so we can access it from verify callback */
	SSL_set_ex_data (ks_ssl->ssl, global_SSL_tls_session_index, session);

	ks_ssl->ssl_bio = getbio (BIO_f_ssl (), "ssl_bio");
	ks_ssl->ct_in = getbio (BIO_s_mem (), "ct_in");
	ks_ssl->ct_out = getbio (BIO_s_mem (), "ct_out");

#ifdef BIO_DEBUG
	bio_debug_oc ("open ssl_bio", ks_ssl->ssl_bio);
	bio_debug_oc ("open ct_in", ks_ssl->ct_in);
	bio_debug_oc ("open ct_out", ks_ssl->ct_out);
#endif

	if (is_server)
		SSL_set_accept_state (ks_ssl->ssl);
	else
		SSL_set_connect_state (ks_ssl->ssl);

	SSL_set_bio (ks_ssl->ssl, ks_ssl->ct_in, ks_ssl->ct_out);
	BIO_set_ssl (ks_ssl->ssl_bio, ks_ssl->ssl, BIO_NOCLOSE);
}

void key_state_ssl_free (struct key_state_ssl *ks_ssl)
{
	if (ks_ssl->ssl)
	{
#ifdef BIO_DEBUG
		bio_debug_oc ("close ssl_bio", ks_ssl->ssl_bio);
		bio_debug_oc ("close ct_in", ks_ssl->ct_in);
		bio_debug_oc ("close ct_out", ks_ssl->ct_out);
#endif
		BIO_free_all (ks_ssl->ssl_bio);
		SSL_free (ks_ssl->ssl);
	}
}

int
key_state_write_plaintext (struct key_state_ssl *ks_ssl, struct buffer *buf)
{
	int ret = 0;
	perf_push (PERF_BIO_WRITE_PLAINTEXT);

#ifdef ENABLE_CRYPTO_OPENSSL
	ASSERT (NULL != ks_ssl);

	ret = bio_write (ks_ssl->ssl_bio, BPTR (buf), BLEN (buf), "tls_write_plaintext");
	bio_write_post (ret, buf);
#endif /* ENABLE_CRYPTO_OPENSSL */

	perf_pop ();
	return ret;
}

int
key_state_write_plaintext_const (struct key_state_ssl *ks_ssl, const uint8_t *data, int len)
{
	int ret = 0;
	perf_push (PERF_BIO_WRITE_PLAINTEXT);

	ASSERT (NULL != ks_ssl);

	ret = bio_write (ks_ssl->ssl_bio, data, len, "tls_write_plaintext_const");

	perf_pop ();
	return ret;
}

int
key_state_read_ciphertext (struct key_state_ssl *ks_ssl, struct buffer *buf, int maxlen)
{
	int ret = 0;
	perf_push (PERF_BIO_READ_CIPHERTEXT);

	ASSERT (NULL != ks_ssl);

	ret = bio_read (ks_ssl->ct_out, buf, maxlen, "tls_read_ciphertext");

	perf_pop ();
	return ret;
}

int
key_state_write_ciphertext (struct key_state_ssl *ks_ssl, struct buffer *buf)
{
	int ret = 0;
	perf_push (PERF_BIO_WRITE_CIPHERTEXT);

	ASSERT (NULL != ks_ssl);

	ret = bio_write (ks_ssl->ct_in, BPTR (buf), BLEN (buf), "tls_write_ciphertext");
	bio_write_post (ret, buf);

	perf_pop ();
	return ret;
}

int
key_state_read_plaintext (struct key_state_ssl *ks_ssl, struct buffer *buf, int maxlen)
{
	int ret = 0;
	perf_push (PERF_BIO_READ_PLAINTEXT);

	ASSERT (NULL != ks_ssl);

	ret = bio_read (ks_ssl->ssl_bio, buf, maxlen, "tls_read_plaintext");

	perf_pop ();
	return ret;
}

/* **************************************
 *
 * Information functions
 *
 * Print information for the end user.
 *
 ***************************************/
void print_details (struct key_state_ssl *ks_ssl, const char *prefix)
{
	const SSL_CIPHER *ciph;
	X509 *cert;
	char s1[256];
	char s2[256];

	s1[0] = s2[0] = 0;
	ciph = SSL_get_current_cipher (ks_ssl->ssl);
	openvpn_snprintf (s1, sizeof (s1), "%s %s, cipher %s %s", prefix, SSL_get_version (ks_ssl->ssl),
		SSL_CIPHER_get_version (ciph), SSL_CIPHER_get_name (ciph));

	cert = SSL_get_peer_certificate (ks_ssl->ssl);
	if (cert != NULL)
	{
		EVP_PKEY *pkey = X509_get_pubkey (cert);
		if (pkey != NULL)
		{
			if (EVP_PKEY_id (pkey) == EVP_PKEY_RSA)
			{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
				RSA *rsa = pkey->pkey.rsa;
				int bits = BN_num_bits (pkey->pkey.rsa->n);
#else
				RSA *rsa = EVP_PKEY_get0_RSA (pkey);
				int bits = RSA_bits (rsa);
#endif
				if (rsa != NULL)
					openvpn_snprintf(s2, sizeof (s2), ", %d bit RSA", bits);
			}
			else if (EVP_PKEY_id (pkey) == EVP_PKEY_DSA)
			{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
				DSA *dsa = pkey->pkey.dsa;
				int bits = BN_num_bits (pkey->pkey.dsa->p);
#else
				DSA *dsa = EVP_PKEY_get0_DSA (pkey);
				int bits = DSA_bits (dsa);
#endif
				if (dsa != NULL)
					openvpn_snprintf (s2, sizeof (s2), ", %d bit DSA", bits);
			}
#ifndef OPENSSL_NO_EC
			else if (EVP_PKEY_id (pkey) == EVP_PKEY_EC)
			{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
				EC_KEY *ec = pkey->pkey.ec;
#else
				EC_KEY *ec = EVP_PKEY_get0_EC_KEY (pkey);
#endif
				if (ec != NULL)
				{
					const EC_GROUP *group = EC_KEY_get0_group (ec);
					const char *curve;
					int bits, nid;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
					BN_CTX *bn_ctx = BN_CTX_new ();
					BIGNUM *order = BN_new ();
					EC_GROUP_get_order (group, order, bn_ctx);
					bits = BN_num_bits (order);
					BN_free (order);
					BN_CTX_free (bn_ctx);
#else
					bits = EC_GROUP_order_bits (group);
#endif
					nid = EC_GROUP_get_curve_name (group);
					if (nid == 0 || (curve = OBJ_nid2sn (nid)) == NULL)
						curve = "Error getting curve name";
					openvpn_snprintf (s2, sizeof (s2), ", %d bit EC, curve: %s", bits, curve);
				}
			}
#endif
			EVP_PKEY_free (pkey);
		}

		X509_free (cert);
	}

	/* The SSL API does not allow us to look at temporary RSA/DH keys,
	 * otherwise we should print their lengths too */
	msg (D_HANDSHAKE, "%s%s", s1, s2);
}

void
show_available_tls_ciphers (const char *tls_version, const char *cipher_list)
{
	struct tls_root_ctx tls_ctx;
	SSL *ssl;
	const char *cipher_name;
	const tls_cipher_name_pair *pair;
	int priority = 0;

	CLEAR (tls_ctx);

#ifdef ENABLE_GUOMI
	tls_ctx.ctx = SSL_CTX_new (GMTLSv1_TLSv1_method ());
#else
	tls_ctx.ctx = SSL_CTX_new (SSLv23_method ());
#endif

	if (!tls_ctx.ctx)
		crypto_msg (M_FATAL, "Cannot create SSL_CTX object");

	ssl = SSL_new (tls_ctx.ctx);
	if (!ssl)
		crypto_msg (M_FATAL, "Cannot create SSL object");

	tls_ctx_restrict_ciphers (&tls_ctx, cipher_list);

	printf ("Available TLS Ciphers,\n");
	printf ("listed in order of preference:\n\n");

	while ((cipher_name = SSL_get_cipher_list (ssl, priority++)))
	{
		pair = tls_get_cipher_name_pair (cipher_name, strlen (cipher_name));

		if (NULL == pair)
		{
			/* No translation found, print warning */
			printf ("%s (No IANA name known to " PACKAGE_NAME ", use OpenSSL name.)\n", cipher_name);
		}
		else
			printf ("%s\n", pair->iana_name);
	}
	printf ("\n" SHOW_TLS_CIPHER_LIST_WARNING);

	SSL_free (ssl);
	SSL_CTX_free (tls_ctx.ctx);
}

const char *
get_ssl_library_version (void)
{
    return SSLeay_version (SSLEAY_VERSION);
}

#endif /* defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_OPENSSL) */
