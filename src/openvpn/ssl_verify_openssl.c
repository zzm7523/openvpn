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
 * @file Control Channel Verification Module OpenSSL implementation
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_OPENSSL)

#include "ssl_verify.h"
#include "ssl_verify_backend.h"
#include "ssl_openssl.h"
#include "console.h"
#include "openvpn.h"

#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "memdbg.h"

#define MAX_PEM_X509_CERT_LEN	32768

static void
print_x509_verify_warning (X509 *err_cert, int error, int error_depth)
{
	struct gc_arena gc = gc_new ();
	char read_buf[1024];
	int read_len = 1024;
	BIO *bio_err = BIO_new (BIO_s_mem ());
	struct buffer buf = alloc_buf_gc (8192, &gc);
	char *subject = x509_get_subject (err_cert, &gc);

	BIO_printf (bio_err, "VERIFY ERROR: depth=%d, error=%s", error_depth,
		X509_verify_cert_error_string (error));

	switch (error)
	{
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			BIO_printf (bio_err,", notBefore=");
			ASN1_TIME_print (bio_err, X509_get_notBefore (err_cert));
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			BIO_printf (bio_err, ", notAfter=");
			ASN1_TIME_print (bio_err, X509_get_notAfter (err_cert));
			break;
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			BIO_printf (bio_err, ", X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN");
			break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			BIO_printf (bio_err, ", X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT");
			break;
	}

	while ((read_len = BIO_read (bio_err, read_buf, sizeof (read_buf))) > 0)
		buf_write (&buf, read_buf, read_len);
	buf_null_terminate (&buf);

	msg (M_WARN, "%s, %s", BSTR (&buf), subject);

	BIO_free (bio_err);
	gc_free (&gc);
}

static int 
tls_server_cert_trust_confirm (X509_STORE_CTX *ctx)
{
	struct gc_arena gc = gc_new ();
	BIO *bio = NULL;
	X509 *cert = NULL;
	X509_STORE *cert_store = NULL;
	STACK_OF(X509) *chain = NULL;
	int ret = 0, i = 0, read_len = 0;
	char read_buf[1024], trust_confirm[128];
	struct buffer trust_confirm_prompt = alloc_buf_gc (MAX_PEM_X509_CERT_LEN + 128, &gc);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	cert_store = ctx->ctx;
	chain = ctx->chain;
#else
	cert_store = X509_STORE_CTX_get0_store (ctx);
	chain = X509_STORE_CTX_get0_chain (ctx);
#endif
	if (cert_store == NULL || chain == NULL)
		goto cleanup;

	ASSERT (sk_X509_num (chain) > 0);

	buf_printf (&trust_confirm_prompt, "Trust server certificate[trust|reject]:\n");

	for (i = 0; i < sk_X509_num (chain); ++i)
	{
		bio = BIO_new (BIO_s_mem ());
		if (!bio)
			goto cleanup;

		cert = sk_X509_value (chain, i);
		if (!PEM_write_bio_X509 (bio, cert))
			goto cleanup;

		memset (read_buf, 0x0, sizeof (read_buf));
		while ((read_len = BIO_read (bio, read_buf, sizeof (read_buf))) > 0)
			buf_write (&trust_confirm_prompt, read_buf, read_len);

		BIO_free (bio);
	}

	buf_write (&trust_confirm_prompt, "\n", 1);	// 空行表示证书链已完全输出
	buf_null_terminate (&trust_confirm_prompt);

	memset (trust_confirm, 0x0, sizeof (trust_confirm));
	if (!get_console_input (BSTR (&trust_confirm_prompt), true, trust_confirm, sizeof (trust_confirm)))
		msg (M_FATAL, "ERROR: could not read Server certificate trust from stdin");

	if (0 == strncmp (trust_confirm, "trust", strlen ("trust")))
	{
		for (i = 1; i < sk_X509_num (chain); ++i)
		{
			cert = sk_X509_value (chain, i);	// 在内存中保存信任证书链
			if (cert)
				X509_STORE_add_cert (cert_store, X509_dup (cert));
		}
		ret = 1;
	}

cleanup:
	gc_free (&gc);
	return ret;
}

int
verify_callback (int preverify_ok, X509_STORE_CTX *ctx)
{
	int ret = 0, error, error_depth;
	X509 *current_cert;
	struct tls_session *session;
	SSL *ssl;
	struct gc_arena gc = gc_new ();

	current_cert = X509_STORE_CTX_get_current_cert (ctx);
	error = X509_STORE_CTX_get_error (ctx);
	error_depth = X509_STORE_CTX_get_error_depth (ctx);

	/* get the tls_session pointer */
	ssl = (SSL*) X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx ());
	ASSERT (ssl);
	session = (struct tls_session *) SSL_get_ex_data (ssl, global_SSL_tls_session_index);
	ASSERT (session);

	cert_hash_remember (session, error_depth, x509_get_sha1_hash (current_cert, &gc));

	if (!preverify_ok && global_context && global_context->options.tls_client && global_context->options.integration && 
		(error == X509_V_ERR_CERT_NOT_YET_VALID || error == X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD /* 证书还未生效 */
		|| error == X509_V_ERR_CERT_HAS_EXPIRED || error == X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD  /* 证书已过期   */
		|| error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN	/* 可以建立证书链，但自签名证书不在信任列表 */
		|| error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT	/* 需要验证的第一个证书就是自签名证书，但不在信任列表 */
		))
	{
		print_x509_verify_warning (current_cert, error, error_depth);
		preverify_ok = tls_server_cert_trust_confirm (ctx);
	}

	/* did peer present cert which was signed by our root cert? */
	if (!preverify_ok)
	{
		/* get the X509 name */
		char *subject = x509_get_subject (current_cert, &gc);

		if (subject)
		{
			/* Remote site specified a certificate, but it's not correct */
			msg (D_TLS_ERRORS, "VERIFY ERROR: depth=%d, error=%s: %s", error_depth,
				X509_verify_cert_error_string (error), subject);
		}

		ERR_clear_error ();

		session->verified = false;

		goto cleanup;
	}

	if (SUCCESS != verify_cert (session, current_cert, error_depth, ctx))
		goto cleanup;

	ret = 1;

cleanup:
	gc_free (&gc);
	return ret;
}

#ifdef ENABLE_X509ALTUSERNAME
bool
x509_username_field_ext_supported (const char *fieldname)
{
	int nid = OBJ_txt2nid (fieldname);
	return nid == NID_subject_alt_name || nid == NID_issuer_alt_name;
}

static bool
extract_x509_extension (X509 *cert, char *fieldname, char *out, int size)
{
	bool retval = false;
	char *buf = 0;
	int nid = 0;
	GENERAL_NAMES *extensions = NULL;

	if (!x509_username_field_ext_supported (fieldname))
	{
		msg (D_TLS_ERRORS, "ERROR: --x509-alt-username field 'ext:%s' not supported",
			fieldname);
		return false;
	}

	nid = OBJ_txt2nid (fieldname);
	extensions = (GENERAL_NAMES *) X509_get_ext_d2i (cert, nid, NULL, NULL);
	if (extensions)
	{
		int numalts, i;
		/* get amount of alternatives,
		 * RFC2459 claims there MUST be at least one, but we don't depend on it...
		 */

		numalts = sk_GENERAL_NAME_num (extensions);

		/* loop through all alternatives */
		for (i = 0; i < numalts; i++)
		{
			/* get a handle to alternative name number i */
			const GENERAL_NAME *name = sk_GENERAL_NAME_value (extensions, i);

			switch (name->type)
			{
			case GEN_EMAIL:
				if (ASN1_STRING_to_UTF8 ((unsigned char **) &buf, name->d.ia5) < 0)
				{
					continue;
				}
				if (strlen (buf) != name->d.ia5->length)
				{
					msg (D_TLS_ERRORS, "ASN1 ERROR: string contained terminating zero");
					OPENSSL_free (buf);
				}
				else
				{
					strncpynt (out, buf, size);
					OPENSSL_free (buf);
					retval = true;
				}
				break;

			default:
				msg (D_TLS_ERRORS, "ASN1 ERROR: can not handle field type %d", name->type);
				break;
			}
		}
		GENERAL_NAMES_free (extensions);
	}

	return retval;
}
#endif /* ENABLE_X509ALTUSERNAME */

/*
 * Extract a field from an X509 subject name.
 *
 * Example:
 *
 * /C=US/ST=CO/L=Denver/O=ORG/CN=First-CN/CN=Test-CA/Email=jim@yonan.net
 *
 * The common name is 'Test-CA'
 *
 * Return true on success, false on error (insufficient buffer size in 'out'
 * to contain result is grounds for error).
 */
static result_t
extract_x509_field_ssl (X509_NAME *x509, const char *field_name, char *out, int size)
{
	int lastpos = -1;
	int tmp = -1;
	X509_NAME_ENTRY *x509ne = 0;
	ASN1_STRING *asn1 = 0;
	unsigned char *buf = (unsigned char *) 1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
	int nid = OBJ_txt2nid ((char *) field_name);

	ASSERT (size > 0);
	*out = '\0';
	do {
		lastpos = tmp;
		tmp = X509_NAME_get_index_by_NID (x509, nid, lastpos);
	} while (tmp > -1);

	/* Nothing found */
	if (lastpos == -1)
		return FAILURE;

	x509ne = X509_NAME_get_entry (x509, lastpos);
	if (!x509ne)
		return FAILURE;

	asn1 = X509_NAME_ENTRY_get_data (x509ne);
	if (!asn1)
		return FAILURE;
	if (ASN1_STRING_to_UTF8 (&buf, asn1) < 0)
		return FAILURE;

	strncpynt (out, (char *)buf, size);

	{
		const result_t ret = (strlen ((char *) buf) < (size_t) size) ? SUCCESS: FAILURE;
		OPENSSL_free (buf);
		return ret;
	}
}

result_t
backend_x509_get_username (char *common_name, int cn_len, char *x509_username_field, X509 *peer_cert)
{
#ifdef ENABLE_X509ALTUSERNAME
	if (strncmp ("ext:", x509_username_field, 4) == 0)
	{
		if (!extract_x509_extension (peer_cert, x509_username_field + 4, common_name, cn_len))
			return FAILURE;
	}
	else
#endif
		if (FAILURE == extract_x509_field_ssl (X509_get_subject_name (peer_cert),
				x509_username_field, common_name, cn_len))
			return FAILURE;

	return SUCCESS;
}

char *
backend_x509_get_serial (openvpn_x509_cert_t *cert, struct gc_arena *gc)
{
	ASN1_INTEGER *asn1_i;
	BIGNUM *bignum;
	char *openssl_serial, *serial;

	asn1_i = X509_get_serialNumber (cert);
	bignum = ASN1_INTEGER_to_BN (asn1_i, NULL);
	openssl_serial = BN_bn2dec (bignum);

	serial = string_alloc (openssl_serial, gc);

	BN_free (bignum);
	OPENSSL_free (openssl_serial);

	return serial;
}

char *
backend_x509_get_serial_hex (openvpn_x509_cert_t *cert, struct gc_arena *gc)
{
	const ASN1_INTEGER *asn1_i = X509_get_serialNumber (cert);
	return format_hex_ex (asn1_i->data, asn1_i->length, 0, 1, ":", gc);
}

unsigned char *
x509_get_sha1_hash (X509 *cert, struct gc_arena *gc)
{
	unsigned char *hash = (unsigned char*) gc_malloc (SHA_DIGEST_LENGTH, false, gc);
	const EVP_MD *sha1 = EVP_sha1 ();
	X509_digest(cert, sha1, hash, NULL);
	return hash;
}

char *
x509_get_subject (X509 *cert, struct gc_arena *gc)
{
	BIO *subject_bio = NULL;
	BUF_MEM *subject_mem;
	char *subject = NULL;
	size_t maxlen = 0;

	/*
	 * Generate the subject string in OpenSSL proprietary format,
	 * when in --compat-names mode
	 */
	if (compat_flag (COMPAT_FLAG_QUERY | COMPAT_NAMES))
	{
		subject = (char*) gc_malloc (256, false, gc);
		X509_NAME_oneline (X509_get_subject_name (cert), subject, 256);
		subject[255] = '\0';
		return subject;
	}

	subject_bio = BIO_new (BIO_s_mem ());
	if (subject_bio == NULL)
		goto err;

	X509_NAME_print_ex (subject_bio, X509_get_subject_name (cert), 0,
		XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN |
		ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL);

	if (BIO_eof (subject_bio))
		goto err;

	BIO_get_mem_ptr (subject_bio, &subject_mem);

	maxlen = subject_mem->length;
	subject = (char*) gc_malloc (maxlen + 1, false, gc);

	memcpy (subject, subject_mem->data, maxlen);
	subject[maxlen] = '\0';

err:
	if (subject_bio)
		BIO_free (subject_bio);
	return subject;
}


#ifdef ENABLE_X509_TRACK

void
x509_track_add (const struct x509_track **ll_head, const char *name, int msglevel, struct gc_arena *gc)
{
	struct x509_track *xt;
	ALLOC_OBJ_CLEAR_GC (xt, struct x509_track, gc);
	if (*name == '+')
	{
		xt->flags |= XT_FULL_CHAIN;
		++name;
	}
	xt->name = name;
	xt->nid = OBJ_txt2nid (name);
	if (xt->nid != NID_undef)
	{
		xt->next = *ll_head;
		*ll_head = xt;
	}
	else
		msg (msglevel, "x509_track: no such attribute '%s'", name);
}

/* worker method for setenv_x509_track */
static void
do_setenv_x509 (struct env_set *es, const char *name, char *value, int depth)
{
	char *name_expand;
	size_t name_expand_size;

	string_mod (value, CC_ANY, CC_CRLF, '?');
	msg (D_X509_ATTR, "X509 ATTRIBUTE name='%s' value='%s' depth=%d", name, value, depth);
	name_expand_size = 64 + strlen (name);
	name_expand = (char *) malloc (name_expand_size);
	check_malloc_return (name_expand);
	openvpn_snprintf (name_expand, name_expand_size, "X509_%d_%s", depth, name);
	setenv_str (es, name_expand, value);
	free (name_expand);
}

void
x509_setenv_track (const struct x509_track *xt, struct env_set *es, const int depth, X509 *x509)
{
	X509_NAME *x509_name = X509_get_subject_name (x509);
	const char nullc = '\0';
	int i;

	while (xt)
	{
		if (depth == 0 || (xt->flags & XT_FULL_CHAIN))
		{
			i = X509_NAME_get_index_by_NID (x509_name, xt->nid, -1);
			if (i >= 0)
			{
				X509_NAME_ENTRY *ent = X509_NAME_get_entry (x509_name, i);
				if (ent)
				{
					ASN1_STRING *val = X509_NAME_ENTRY_get_data (ent);
					unsigned char *buf;
					buf = (unsigned char *) 1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
					if (ASN1_STRING_to_UTF8 (&buf, val) >= 0)
					{
						do_setenv_x509 (es, xt->name, (char *) buf, depth);
						OPENSSL_free (buf);
					}
				}
			}
			else
			{
				i = X509_get_ext_by_NID (x509, xt->nid, -1);
				if (i >= 0)
				{
					X509_EXTENSION *ext = X509_get_ext (x509, i);
					if (ext)
					{
						BIO *bio = BIO_new (BIO_s_mem ());
						if (bio)
						{
							if (X509V3_EXT_print (bio, ext, 0, 0))
							{
								if (BIO_write (bio, &nullc, 1) == 1)
								{
									char *str;
									BIO_get_mem_data (bio, &str);
									do_setenv_x509 (es, xt->name, str, depth);
								}
							}
							BIO_free (bio);
						}
					}
				}
			}
		}
		xt = xt->next;
	}
}
#endif

/*
 * Save X509 fields to environment, using the naming convention:
 *
 *  X509_{cert_depth}_{name}={value}
 */
void
x509_setenv (struct env_set *es, int cert_depth, openvpn_x509_cert_t *peer_cert)
{
	int i, n, fn_nid;
	ASN1_OBJECT *fn;
	ASN1_STRING *val;
	X509_NAME_ENTRY *ent;
	const char *objbuf;
	unsigned char *buf;
	char *name_expand;
	size_t name_expand_size;
	X509_NAME *x509 = X509_get_subject_name (peer_cert);

	n = X509_NAME_entry_count (x509);
	for (i = 0; i < n; ++i)
	{
		ent = X509_NAME_get_entry (x509, i);
		if (!ent)
			continue;
		fn = X509_NAME_ENTRY_get_object (ent);
		if (!fn)
			continue;
		val = X509_NAME_ENTRY_get_data (ent);
		if (!val)
			continue;
		fn_nid = OBJ_obj2nid (fn);
		if (fn_nid == NID_undef)
			continue;
		objbuf = OBJ_nid2sn (fn_nid);
		if (!objbuf)
			continue;
		buf = (unsigned char *) 1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
		if (ASN1_STRING_to_UTF8 (&buf, val) < 0)
			continue;
		name_expand_size = 64 + strlen (objbuf);
		name_expand = (char *) malloc (name_expand_size);
		check_malloc_return (name_expand);
		openvpn_snprintf (name_expand, name_expand_size, "X509_%d_%s", cert_depth, objbuf);
		string_mod (name_expand, CC_PRINT, CC_CRLF, '_');
		string_mod ((char*) buf, CC_PRINT, CC_CRLF, '_');
		setenv_str (es, name_expand, (char*) buf);
		free (name_expand);
		OPENSSL_free (buf);
	}
}

result_t
x509_verify_ns_cert_type (openvpn_x509_cert_t *peer_cert, const int usage)
{
	if (usage == NS_CERT_CHECK_NONE)
	{
		return SUCCESS;
	}
	else if (usage == NS_CERT_CHECK_CLIENT)
	{
		/*
		 * Unfortunately, X509_check_purpose() does some weird thing that
		 * prevent it to take a const argument
		 */
		result_t result = X509_check_purpose (peer_cert, X509_PURPOSE_SSL_CLIENT, 0) ? SUCCESS : FAILURE;

		/*
		 * old versions of OpenSSL allow us to make the less strict check we used to
		 * do. If this less strict check pass, warn user that this might not be the
		 * case when its distribution will update to OpenSSL 1.1
		 */
		if (result == FAILURE)
		{
			ASN1_BIT_STRING *ns;
			ns = (ASN1_BIT_STRING *) X509_get_ext_d2i (peer_cert, NID_netscape_cert_type, NULL, NULL);
			result = (ns && ns->length > 0 && (ns->data[0] & NS_SSL_CLIENT)) ? SUCCESS : FAILURE;
			if (result == SUCCESS)
			{
				msg (M_WARN, "X509: Certificate is a client certificate yet it's purpose "
					"cannot be verified (check may fail in the future)");
			}
			ASN1_BIT_STRING_free (ns);
		}
		return result;
	}
	else if (usage == NS_CERT_CHECK_SERVER)
	{
		/*
		 * Unfortunately, X509_check_purpose() does some weird thing that
		 * prevent it to take a const argument
		 */
		result_t result = X509_check_purpose (peer_cert, X509_PURPOSE_SSL_SERVER, 0) ? SUCCESS : FAILURE;

		/*
		 * old versions of OpenSSL allow us to make the less strict check we used to
		 * do. If this less strict check pass, warn user that this might not be the
		 * case when its distribution will update to OpenSSL 1.1
		 */
		if (result == FAILURE)
		{
			ASN1_BIT_STRING *ns;
			ns = (ASN1_BIT_STRING *) X509_get_ext_d2i (peer_cert, NID_netscape_cert_type, NULL, NULL);
			result = (ns && ns->length > 0 && (ns->data[0] & NS_SSL_SERVER)) ? SUCCESS : FAILURE;
			if (result == SUCCESS)
			{
				msg (M_WARN, "X509: Certificate is a server certificate yet it's purpose "
					"cannot be verified (check may fail in the future)");
			}
			ASN1_BIT_STRING_free (ns);
		}
		return result;
	}
	else
	{
		return FAILURE;
	}
}

result_t
x509_verify_cert_ku (X509 *x509, const unsigned * const expected_ku, int expected_len)
{
	ASN1_BIT_STRING *ku = NULL;
	result_t fFound = FAILURE;

	if ((ku = (ASN1_BIT_STRING *) X509_get_ext_d2i (x509, NID_key_usage, NULL, NULL)) == NULL)
	{
		msg (D_HANDSHAKE, "Certificate does not have key usage extension");
	}
	else
	{
		unsigned nku = 0;
		int i;

		for (i = 0; i < 8; i++)
		{
			if (ASN1_BIT_STRING_get_bit (ku, i))
				nku |= 1 << (7 - i);
		}

		/* Fixup if no LSB bits */
		if ((nku & 0xff) == 0)
		{
			nku >>= 8;
		}

		msg (D_HANDSHAKE, "Validating certificate key usage");
		for (i = 0; fFound != SUCCESS && i < expected_len; i++)
		{
			if (expected_ku[i] != 0)
			{
				msg (D_HANDSHAKE, "++ Certificate has key usage  %04x, expects %04x", nku, expected_ku[i]);

				if (nku == expected_ku[i])
					fFound = SUCCESS;
			}
		}
	}

	if (ku != NULL)
		ASN1_BIT_STRING_free (ku);

	return fFound;
}

result_t
x509_verify_cert_eku (X509 *x509, const char * const expected_oid)
{
	EXTENDED_KEY_USAGE *eku = NULL;
	result_t fFound = FAILURE;

	if ((eku = (EXTENDED_KEY_USAGE *) X509_get_ext_d2i (x509, NID_ext_key_usage, NULL, NULL)) == NULL)
	{
		msg (D_HANDSHAKE, "Certificate does not have extended key usage extension");
	}
	else
	{
		int i;

		msg (D_HANDSHAKE, "Validating certificate extended key usage");
		for (i = 0; SUCCESS != fFound && i < sk_ASN1_OBJECT_num (eku); i++)
		{
			ASN1_OBJECT *oid = sk_ASN1_OBJECT_value (eku, i);
			char szOid[1024];

			if (SUCCESS != fFound && OBJ_obj2txt (szOid, sizeof (szOid), oid, 0) != -1)
			{
				msg (D_HANDSHAKE, "++ Certificate has EKU (str) %s, expects %s",
					szOid, expected_oid);
				if (!strcmp (expected_oid, szOid))
					fFound = SUCCESS;
			}
			if (SUCCESS != fFound && OBJ_obj2txt (szOid, sizeof (szOid), oid, 1) != -1)
			{
				msg (D_HANDSHAKE, "++ Certificate has EKU (oid) %s, expects %s",
					szOid, expected_oid);
				if (!strcmp (expected_oid, szOid))
					fFound = SUCCESS;
			}
		}
	}

	if (eku != NULL)
		sk_ASN1_OBJECT_pop_free (eku, ASN1_OBJECT_free);

	return fFound;
}

result_t
x509_write_pem (FILE *peercert_file, X509 *peercert)
{
	if (PEM_write_X509 (peercert_file, peercert) < 0)
	{
		msg (M_ERR, "Failed to write peer certificate in PEM format");
		return FAILURE;
	}
	return SUCCESS;
}

/*
 * check peer cert against CRL
 */
result_t
x509_verify_crl (const char *crl_file, X509 *peer_cert, const char *subject)
{
	X509_CRL *crl = NULL;
	X509_REVOKED *revoked;
	const ASN1_INTEGER *serialNumber;
	BIO *in = NULL;
	int n, i;
	result_t retval = FAILURE;
	struct gc_arena gc = gc_new ();
	char *serial;

	in = BIO_new_file (crl_file, "r");

	if (in == NULL)
	{
		msg (M_WARN, "CRL: cannot read: %s", crl_file);
		goto end;
	}
	crl = PEM_read_bio_X509_CRL (in, NULL, NULL, NULL);
	if (crl == NULL)
	{
		msg (M_WARN, "CRL: cannot read CRL from file %s", crl_file);
		goto end;
	}

	if (X509_NAME_cmp (X509_CRL_get_issuer (crl), X509_get_issuer_name (peer_cert)) != 0)
	{
		msg (M_WARN, "CRL: CRL %s is from a different issuer than the issuer of certificate %s", crl_file, subject);
		retval = SUCCESS;
		goto end;
	}

	n = sk_X509_REVOKED_num (X509_CRL_get_REVOKED (crl));
	for (i = 0; i < n; i++)
	{
		revoked = (X509_REVOKED *) sk_X509_REVOKED_value (X509_CRL_get_REVOKED (crl), i);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		serialNumber = revoked->serialNumber;
#else
		serialNumber = X509_REVOKED_get0_serialNumber (revoked);
#endif
		if (ASN1_INTEGER_cmp (serialNumber, X509_get_serialNumber (peer_cert)) == 0)
		{
			serial = backend_x509_get_serial_hex (peer_cert, &gc);
			msg (D_HANDSHAKE, "CRL CHECK FAILED: %s (serial %s) is REVOKED", subject, (serial ? serial : "NOT AVAILABLE"));
			goto end;
		}
	}

	retval = SUCCESS;
	msg (D_HANDSHAKE, "CRL CHECK OK: %s", subject);

end:
	gc_free (&gc);
	BIO_free (in);
	if (crl)
		X509_CRL_free (crl);

	return retval;
}

#endif /* defined(ENABLE_SSL) && defined(ENABLE_CRYPTO_OPENSSL) */
