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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_CRYPTO

#include "error.h"
#include "misc.h"
#include "crypto.h"
#include "socket.h"
#include "multi_crypto.h"
#include "options.h"

#include "memdbg.h"

#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
int is_supported_keysize (const EVP_CIPHER *cipher, int keysize)
{
	int ret = 0;
	ASSERT (keysize >= 0 && keysize <= MAX_CIPHER_KEY_LENGTH);

	if (cipher && keysize > 0)
	{
		EVP_CIPHER_CTX *ctx;

		ctx = EVP_CIPHER_CTX_new ();
		if (EVP_CipherInit (ctx, cipher, NULL, NULL, 0) && EVP_CIPHER_CTX_set_key_length (ctx, keysize))
			ret = 1;
		EVP_CIPHER_CTX_free (ctx);
	}

	return ret;
}
#endif

void check_cipher_array (const char *cipher_name[], int array_len, int keysize, bool use_iv, bool server)
{
#define EVP_CIPH_INVALID_MODE	-1

	ASSERT (keysize >= 0 && keysize <= MAX_CIPHER_KEY_LENGTH);

	if (cipher_name && array_len > 0)
	{
		struct gc_arena gc = gc_new ();
		struct buffer out = alloc_buf_gc (MAX_ALGO_STR_LEN * 2, &gc);
		int i, mode = EVP_CIPH_INVALID_MODE, min_block_iv_size = 0xFFFF, max_block_iv_size = 0x0;
		bool mode_equal = true;
		const EVP_CIPHER *cipher;

		for (i = 0; i < array_len; ++i)
		{
			cipher = EVP_get_cipherbyname (cipher_name[i]);
			if (cipher)
			{
				buf_printf (&out, ", %s block length = %d bit, iv length = %d bit", cipher_name[i],
					EVP_CIPHER_block_size (cipher) * 8, EVP_CIPHER_iv_length (cipher) * 8);
				
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
				if (keysize > 0)
				{
					if (!is_supported_keysize (cipher, keysize))
						crypto_msg (M_FATAL, "cipher algorithm %s don't support key length %d bit",
							cipher_name[i], keysize * 8);
				}
#endif
				if (use_iv)
				{
					min_block_iv_size = min_int (min_block_iv_size,
						EVP_CIPHER_block_size (cipher) + EVP_CIPHER_iv_length (cipher));
					max_block_iv_size = max_int (max_block_iv_size,
						EVP_CIPHER_block_size (cipher) + EVP_CIPHER_iv_length (cipher));
				}
				else
				{
					min_block_iv_size = min_int (min_block_iv_size, EVP_CIPHER_block_size (cipher));
					max_block_iv_size = max_int (max_block_iv_size, EVP_CIPHER_block_size (cipher));
				}

				if (mode_equal)
				{
					if (mode == EVP_CIPH_INVALID_MODE)
						mode = EVP_CIPHER_mode (cipher);
					else
					{
						if (mode != EVP_CIPHER_mode (cipher))
							mode_equal = false;
					}
				}
			}
			else
			{
				crypto_msg (M_FATAL, "cipher algorithm '%s' not found", cipher_name[i]);
				break;
			}
		}

		if (server)
		{
			if (!mode_equal)
				crypto_msg (M_FATAL, "cipher array mode don't equal%s", BSTR (&out));

			if (min_block_iv_size != max_block_iv_size)
				crypto_msg (M_FATAL, "cipher array block iv length don't equal%s", BSTR (&out));
		}

		gc_free (&gc);
	}
}

void check_auth_array (const char *auth_name[], int array_len, bool server)
{
	if (auth_name && array_len > 0)
	{
		struct gc_arena gc = gc_new ();
		struct buffer out = alloc_buf_gc (MAX_ALGO_STR_LEN * 2, &gc);
		int i, min_md_size = 0xFFFF, max_md_size = 0x0;
		const EVP_MD *md;

		for (i = 0; i < array_len; ++i)
		{
			md = EVP_get_digestbyname (auth_name[i]);
			if (md)
			{
				buf_printf (&out, ", %s digest length = %d bit", auth_name[i], EVP_MD_size (md) * 8);
				min_md_size = min_int (min_md_size, EVP_MD_size (md));
				max_md_size = max_int (max_md_size, EVP_MD_size (md));
			}
			else
			{
				crypto_msg (M_FATAL, "Message hash algorithm '%s' not found", auth_name[i]);
				break;
			}
		}

		if (server && min_md_size != max_md_size)
			crypto_msg (M_FATAL, "auth array digest length don't equal%s", BSTR (&out));

		gc_free (&gc);
	}
}

int get_option_str (const char *option_string, const char delim, const char *name, char *value, int value_len)
{
	const char *start, *end;
	int ret = 0;

	if (option_string && name && value && value_len > 0)
	{
		if ((start = strstr (option_string, name)))
		{
			start = skip_leading_whitespace (start + strlen (name));
			end = strchr (start, delim);
			if (end)
			{
				if (end - start < value_len)
				{
					strncpy (value, start, end - start);
					*(value + (end - start)) = 0x0;
					ret = 1;
				}
			}
			else
			{
				if ((int) strlen (start) < value_len)
				{
					strcpy (value, start);
					*(value + strlen (start)) = 0x0;
					ret = 1;
				}
			}
		}
	}

	return ret;
}

int get_option_i (const char *option_string, const char delim, const char *name, int *value)
{
	char x[32] = {0};
	int ret = 0;

	if ((ret = get_option_str (option_string, delim, name, x, sizeof (x))))
		*value = atoi (x);
	return ret;
}

const char*
select_ciphername (const char *clientname[], int c_len, const int c_keysize, const char *servername[],
		int s_len, const int s_keysize)
{
	ASSERT (c_keysize >= 0 && c_keysize <= MAX_CIPHER_KEY_LENGTH && s_keysize >= 0 &&
		s_keysize <= MAX_CIPHER_KEY_LENGTH);

	if (clientname && servername)
	{
		const cipher_kt_t *cipher;
		int i, j;

		for (i = 0; i < c_len; ++i)
		{
			for (j = 0; j < s_len; ++j)
			{
				if (strcmp (clientname[i], servername[j]) == 0)
				{
					if ((cipher = cipher_kt_get (clientname[i])))
					{
						int x_c_keysize = c_keysize;
						int x_s_keysize = s_keysize;

						if (x_c_keysize == 0)
							x_c_keysize = cipher_kt_key_size (cipher);
						if (x_s_keysize == 0)
							x_s_keysize = cipher_kt_key_size (cipher);
						if (x_c_keysize == x_s_keysize
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
								&& is_supported_keysize (cipher, x_c_keysize)
#endif
							)
							return clientname[i];
					}
				}
			}
		}
	}

	return NULL;
}

const char*
select_authname (const char *clientname[], int c_len, const char *servername[], int s_len)
{
	if (clientname && servername)
	{
		int i, j;

		for (i = 0; i < c_len; ++i)
		{
			for (j = 0; j < s_len; ++j)
			{
				if (strcmp (clientname[i], servername[j]) == 0)
					return clientname[i];
			}
		}
	}
	
	return NULL;
}

const char*
select_block_iv_longest_ciphername (const char *ciphername[], int len, bool use_iv)
{
	int i = 0, longest_block_iv_size = 0, curr_block_iv_size = 0;
	const EVP_CIPHER *cipher = NULL;
	const char *selected_ciphername = NULL;

	for (i = 0; i < len; ++i)
	{
		cipher = EVP_get_cipherbyname (ciphername[i]);
		if (cipher)
		{
			curr_block_iv_size = EVP_CIPHER_block_size (cipher);
			if (use_iv)
				curr_block_iv_size += EVP_CIPHER_iv_length (cipher);
			if (longest_block_iv_size < curr_block_iv_size)
			{
				selected_ciphername = ciphername[i];
				longest_block_iv_size = curr_block_iv_size;
			}
		}
		else
		{
			crypto_msg (M_FATAL, "Cipher algorithm '%s' not found", ciphername[i]);
			break;
		}
	}

	return selected_ciphername;
}

const char*
select_md_longest_authname (const char *authname[], int len)
{
	const char *selected_authname = NULL;
	int i = 0, md_size = 0;
	const EVP_MD *md = NULL;

	for (i = 0; i < len; ++i)
	{
		md = EVP_get_digestbyname (authname[i]);
		if (md)
		{
			if (md_size < EVP_MD_size (md))
			{
				selected_authname = authname[i];
				md_size = EVP_MD_size (md);
			}
		}
		else
		{
			crypto_msg (M_FATAL, "Message hash algorithm '%s' not found", authname[i]);
			break;
		}
	}

	return selected_authname;
}

/*
 * Encryption and Compression Routines.
 *
 * On entry, buf contains the input data and length.
 * On exit, it should be set to the output data and length.
 *
 * If buf->len is <= 0 we should return
 * If buf->len is set to 0 on exit it tells the caller to ignore the packet.
 *
 * work is a workspace buffer we are given of size BUF_SIZE.
 * work may be used to return output data, or the input buffer
 * may be modified and returned as output.  If output data is
 * returned in work, the data should start after FRAME_HEADROOM bytes
 * of padding to leave room for downstream routines to prepend.
 *
 * Up to a total of FRAME_HEADROOM bytes may be prepended to the input buf
 * by all routines (encryption, decryption, compression, and decompression).
 *
 * Note that the buf_prepend return will assert if we try to
 * make a header bigger than FRAME_HEADROOM.  This should not
 * happen unless the frame parameters are wrong.
 */

/*
 * How many bytes will we add to frame buffer for a given set of crypto options?
 */
void
crypto_adjust_frame_parameters (struct frame *frame, const struct key_type *kt, bool cipher_defined,
		bool use_iv, bool packet_id, bool packet_id_long_form)
{
	int crypto_overhead = 0;

	if (packet_id)
		crypto_overhead += packet_id_size (packet_id_long_form);

	if (cipher_defined)
    {
		if (use_iv)
			crypto_overhead += cipher_kt_iv_size (kt->cipher);

		/* extra block required by cipher_ctx_update() */
		crypto_overhead += cipher_kt_block_size (kt->cipher);
	}

	crypto_overhead += kt->hmac_length;

	frame_add_to_extra_frame (frame, crypto_overhead);

#ifdef __GNUC__
	msg (D_MTU_DEBUG, "%s: Adjusting frame parameters for crypto by %u bytes", __func__, crypto_overhead);
#else
	msg (D_MTU_DEBUG, "%s: Adjusting frame parameters for crypto by %u bytes", __FUNCTION__, crypto_overhead);
#endif
}

/*
 * Build a struct key_type.
 */
void
init_key_type (struct key_type *kt, const char *ciphername, bool ciphername_defined, const char *authname,
		bool authname_defined, int keysize, bool cfb_ofb_ctr_allowed, bool warn)
{
	CLEAR (*kt);

	if (ciphername && ciphername_defined)
	{
		kt->cipher = cipher_kt_get (translate_cipher_name_from_openvpn (ciphername));
		kt->cipher_length = cipher_kt_key_size (kt->cipher);
		if (keysize > 0 && keysize <= MAX_CIPHER_KEY_LENGTH)
			kt->cipher_length = keysize;

		/* check legal cipher mode */
		{
			if (!(cipher_kt_mode_cbc (kt->cipher)
#ifdef ENABLE_OFB_CFB_CTR_MODE
				|| (cfb_ofb_ctr_allowed && cipher_kt_mode_ofb_cfb_ctr (kt->cipher))
#endif
				))
				msg (M_FATAL, "Cipher '%s' mode not supported", ciphername);
		}
	}
	else
	{
		if (warn)
			msg (M_WARN, "******* WARNING *******: '--cipher none' was specified. This means "
				"NO encryption will be performed and tunnelled data WILL be transmitted "
				"in clear text over the network! PLEASE DO RECONSIDER THIS SETTING!");
	}

	if (authname && authname_defined)
	{
		kt->digest = md_kt_get (authname);
		kt->hmac_length = md_kt_size (kt->digest);
	}
	else
	{
		if (warn)
			msg (M_WARN, "******* WARNING *******: '--auth none' was specified. This means "
				"no authentication will be performed on received packets, meaning you CANNOT "
				"trust that the data received by the remote side have NOT been manipulated. "
				"PLEASE DO RECONSIDER THIS SETTING!");
	}
}

/* given a key and key_type, build a key_ctx */
void
init_key_ctx (struct key_ctx *ctx, struct key *key, const struct key_type *kt, int enc, const char *prefix)
{
	struct gc_arena gc = gc_new ();
	CLEAR (*ctx);

	if (kt->cipher && kt->cipher_length > 0)
	{
		ctx->cipher = cipher_ctx_new ();
		cipher_ctx_init (ctx->cipher, key->cipher, kt->cipher_length, kt->cipher, enc);

		if (prefix)
		{
			msg (D_HANDSHAKE, "%s: Cipher '%s' initialized with %d bit key",
				prefix,
				cipher_kt_name (kt->cipher),
				kt->cipher_length * 8);
			dmsg (D_SHOW_KEYS, "%s: CIPHER KEY: %s", prefix,
				format_hex (key->cipher, kt->cipher_length, 0, &gc));
			dmsg (D_CRYPTO_DEBUG, "%s: CIPHER block_size=%d iv_size=%d",
				prefix,
				cipher_kt_block_size (kt->cipher),
				cipher_kt_iv_size (kt->cipher));
			if (cipher_kt_block_size (kt->cipher) < 128 / 8)
			{
				msg (M_WARN, "WARNING: INSECURE cipher with block size less than 128"
					" bit (%d bit).  This allows attacks like SWEET32.  Mitigate by "
					"using a --cipher with a larger block size (e.g. AES-256-CBC).",
					cipher_kt_block_size (kt->cipher) * 8);
			}
		}
	}

	if (kt->digest && kt->hmac_length > 0)
	{
		ctx->hmac = hmac_ctx_new ();
		hmac_ctx_init (ctx->hmac, key->hmac, kt->hmac_length, kt->digest);

		if (prefix)
		{
			msg (D_HANDSHAKE, "%s: Using %d bit message hash '%s' for HMAC authentication",
				prefix, md_kt_size (kt->digest) * 8, md_kt_name (kt->digest));
			dmsg (D_SHOW_KEYS, "%s: HMAC KEY: %s",
				prefix, format_hex (key->hmac, kt->hmac_length, 0, &gc));
			dmsg (D_CRYPTO_DEBUG, "%s: HMAC size=%d block_size=%d",
				prefix,
				md_kt_size (kt->digest),
				hmac_ctx_size (ctx->hmac));
		}
	}

	gc_free (&gc);
}

void
free_key_ctx (struct key_ctx *ctx)
{
	if (ctx->cipher)
	{
		cipher_ctx_cleanup (ctx->cipher);
		free (ctx->cipher);
		ctx->cipher = NULL;
	}
	if (ctx->hmac)
	{
		hmac_ctx_cleanup (ctx->hmac);
		free (ctx->hmac);
		ctx->hmac = NULL;
	}
}

void
free_key_ctx_bi (struct key_ctx_bi *ctx)
{
	free_key_ctx (&ctx->encrypt);
	free_key_ctx (&ctx->decrypt);
}


static bool
key_is_zero (struct key *key, const struct key_type *kt)
{
	int i;
	for (i = 0; i < kt->cipher_length; ++i)
	{
		if (key->cipher[i])
			return false;
	}
	msg (D_CRYPT_ERRORS, "CRYPTO INFO: WARNING: zero key detected");
	return true;
}

/*
 * Make sure that cipher key is a valid key for current key_type.
 */
bool
check_key (struct key *key, const struct key_type *kt)
{
	if (kt->cipher)
	{
		/* Check for zero key */
		if (key_is_zero (key, kt))
			return false;

		/* Check for weak or semi-weak DES keys. */
		{
			const int ndc = key_des_num_cblocks (kt->cipher);
			if (ndc)
				return key_des_check (key->cipher, kt->cipher_length, ndc);
			else
				return true;
		}
	}
	return true;
}

/*
 * Make safe mutations to key to ensure it is valid,
 * such as ensuring correct parity on DES keys.
 *
 * This routine cannot guarantee it will generate a good
 * key.  You must always call check_key after this routine
 * to make sure.
 */ 
void
fixup_key (struct key *key, const struct key_type *kt)
{
	struct gc_arena gc = gc_new ();
	if (kt->cipher)
	{
#ifdef ENABLE_DEBUG
		const struct key orig = *key;
#endif
		const int ndc = key_des_num_cblocks (kt->cipher);

		if (ndc)
			key_des_fixup (key->cipher, kt->cipher_length, ndc);

#ifdef ENABLE_DEBUG
		if (check_debug_level (D_CRYPTO_DEBUG))
		{
			if (memcmp (orig.cipher, key->cipher, kt->cipher_length))
				dmsg (D_CRYPTO_DEBUG, "CRYPTO INFO: fixup_key: before=%s after=%s",
					format_hex (orig.cipher, kt->cipher_length, 0, &gc),
					format_hex (key->cipher, kt->cipher_length, 0, &gc));
		}
#endif
	}
	gc_free (&gc);
}

void
check_replay_iv_consistency (const struct key_type *kt, bool packet_id, bool use_iv)
{
	ASSERT (kt);

	if (cipher_kt_mode_ofb_cfb_ctr (kt->cipher) && !(packet_id && use_iv))
		msg (M_FATAL, "--no-replay or --no-iv cannot be used with a CFB or OFB or CTR mode cipher");
}

/*
 * Generate a random key.  If key_type is provided, make sure generated key is valid for key_type.
 */
void
generate_key_random (struct key *key, const struct key_type *kt)
{
	int cipher_len = MAX_CIPHER_KEY_LENGTH;
	int hmac_len = MAX_HMAC_KEY_LENGTH;
	struct gc_arena gc = gc_new ();

	do {
		CLEAR (*key);
		if (kt)
		{
			if (kt->cipher && kt->cipher_length > 0 && kt->cipher_length <= cipher_len)
				cipher_len = kt->cipher_length;

			if (kt->digest && kt->hmac_length > 0 && kt->hmac_length <= hmac_len)
				hmac_len = kt->hmac_length;
		}
		if (!rand_bytes (key->cipher, cipher_len) || !rand_bytes (key->hmac, hmac_len))
			msg (M_FATAL, "ERROR: Random number generator cannot obtain entropy for key generation");

		dmsg (D_SHOW_KEY_SOURCE, "Cipher source entropy: %s", format_hex (key->cipher, cipher_len, 0, &gc));
		dmsg (D_SHOW_KEY_SOURCE, "HMAC source entropy: %s", format_hex (key->hmac, hmac_len, 0, &gc));

		if (kt)
			fixup_key (key, kt);
	} while (kt && !check_key (key, kt));

	gc_free (&gc);
}

/*
 * Print key material
 */
void
key2_print (const struct key2 *k, const struct key_type *kt, const char* prefix0, const char *prefix1)
{
	struct gc_arena gc = gc_new ();
	ASSERT (k->n == 2);
	dmsg (D_SHOW_KEY_SOURCE, "%s (cipher): %s",
		prefix0,
		format_hex (k->keys[0].cipher, kt->cipher_length, 0, &gc));
	dmsg (D_SHOW_KEY_SOURCE, "%s (hmac): %s",
		prefix0,
		format_hex (k->keys[0].hmac, kt->hmac_length, 0, &gc));
	dmsg (D_SHOW_KEY_SOURCE, "%s (cipher): %s",
		prefix1,
		format_hex (k->keys[1].cipher, kt->cipher_length, 0, &gc));
	dmsg (D_SHOW_KEY_SOURCE, "%s (hmac): %s",
		prefix1,
		format_hex (k->keys[1].hmac, kt->hmac_length, 0, &gc));
	gc_free (&gc);
}

void
test_crypto (struct crypto_options *opt, struct frame *frame)
{
	int i, j;
	struct gc_arena gc = gc_new ();
	struct buffer src = alloc_buf_gc (TUN_MTU_SIZE (frame), &gc);
	struct buffer work = alloc_buf_gc (BUF_SIZE (frame), &gc);
	struct packet_buffer buf;
	struct packet_buffer *workspace;

	ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));
	packet_buffer_clear (&buf);

	msg (M_INFO, "Entering " PACKAGE_NAME " crypto self-test mode.");
	for (i = 1; i <= TUN_MTU_SIZE (frame); ++i)
	{
		update_time (MAIN_THREAD_INDEX);

		msg (M_INFO, "TESTING ENCRYPT/DECRYPT of packet length=%d", i);

		/* Load src with random data. */
		ASSERT (buf_init (&src, 0) && i <= src.capacity);
		src.len = i;
		ASSERT (rand_bytes (BPTR (&src), BLEN (&src)));

		/* copy source to input buf */
		buf.buf = work;
		buf.key_id = opt->key_id;
		memcpy (buf_write_alloc (&buf.buf, BLEN (&src)), BPTR (&src), BLEN (&src));

		/* 必须动态分配, 因为openvpn_encrypt, openvpn_decrypt交换了buf和workspace的数据指针 */
		workspace = packet_buffer_new_gc (BUF_SIZE (frame), PACKET_BUFFER_FOR_ALL, &gc);

		/* encrypt */
		openvpn_encrypt (MAIN_THREAD_INDEX, opt, frame, &buf, workspace);
		generate_hmac (MAIN_THREAD_INDEX, opt, &buf.buf);

		/* decrypt */
		verify_hmac (MAIN_THREAD_INDEX, opt, &buf.buf);
		openvpn_decrypt (MAIN_THREAD_INDEX, opt, frame, &buf, workspace);

		/* compare */
		if (buf.buf.len != src.len)
		{
			msg (M_FATAL, "SELF TEST FAILED, src.len=%d buf.len=%d", src.len, buf.buf.len);
			goto exit;
		}
		for (j = 0; j < i; ++j)
		{
			const uint8_t in = *(BPTR (&src) + j), out = *(BPTR (&buf.buf) + j);
			if (in != out)
			{
				msg (M_FATAL, "SELF TEST FAILED, pos=%d in=%d out=%d", j, in, out);
				goto exit;
			}
		}
	}
	msg (M_INFO, PACKAGE_NAME " crypto self-test mode SUCCEEDED.");

exit:
	gc_free (&gc);
}

#ifdef ENABLE_SSL

void
get_tls_handshake_key (const struct key_type *key_type, struct key_ctx_bi *ctx, const char *passphrase_file,
		const int key_direction, const unsigned int flags)
{
	if (passphrase_file && key_type->hmac_length)
	{
		struct key2 key2;
		struct key_type kt = *key_type;
		struct key_direction_state kds;

		/* for control channel we are only authenticating, not encrypting */
		kt.cipher_length = 0;
		kt.cipher = NULL;

		if (flags & GHK_INLINE)
		{
			/* key was specified inline, key text is in passphrase_file */
			read_key_file (&key2, passphrase_file, RKF_INLINE|RKF_MUST_SUCCEED);

			/* succeeded? */
			if (key2.n == 2)
				msg (M_INFO, "Control Channel Authentication: tls-auth using INLINE static key file");
			else
				msg (M_FATAL, "INLINE tls-auth file lacks the requisite 2 keys");
		}
		else
		{
			/* first try to parse as an OpenVPN static key file */
			read_key_file (&key2, passphrase_file, 0);

			/* succeeded? */
			if (key2.n == 2)
			{
				msg (M_INFO, "Control Channel Authentication: using '%s' as a " PACKAGE_NAME " static key file",
					passphrase_file);
			}
			else
			{
				int hash_size;

				CLEAR (key2);

				/* failed, now try to get hash from a freeform file */
				hash_size = read_passphrase_hash (passphrase_file, kt.digest, key2.keys[0].hmac, MAX_HMAC_KEY_LENGTH);
				ASSERT (hash_size == kt.hmac_length);

				/* suceeded */
				key2.n = 1;

				msg (M_INFO, "Control Channel Authentication: using '%s' as a free-form passphrase file",
					passphrase_file);
			}
		}

		/* handle key direction */
		key_direction_state_init (&kds, key_direction);
		must_have_n_keys (passphrase_file, "tls-auth", &key2, kds.need_keys);

		/* initialize hmac key in both directions */
		init_key_ctx (&ctx->encrypt, &key2.keys[kds.out_key], &kt, OPENVPN_OP_ENCRYPT,
			"Outgoing Control Channel Authentication");
		init_key_ctx (&ctx->decrypt, &key2.keys[kds.in_key], &kt, OPENVPN_OP_DECRYPT,
			"Incoming Control Channel Authentication");

		secure_memzero (&key2, sizeof (key2));
	}
	else
	{
		CLEAR (*ctx);
	}
}
#endif

/* header and footer for static key file */
static const char static_key_head[] = "-----BEGIN OpenVPN Static key V1-----";
static const char static_key_foot[] = "-----END OpenVPN Static key V1-----";

static const char printable_char_fmt[] =
	"Non-Hex character ('%c') found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

static const char unprintable_char_fmt[] =
	"Non-Hex, unprintable character (0x%02x) found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

/* read key from file */

void
read_key_file (struct key2 *key2, const char *file, const unsigned int flags)
{
	struct gc_arena gc = gc_new ();
	struct buffer in;
	int fd, size;
	uint8_t hex_byte[3] = {0, 0, 0};
	const char *error_filename = file;

	/* parse info */
	const unsigned char *cp;
	int hb_index = 0;
	int line_num = 1;
	int line_index = 0;
	int match = 0;

	/* output */
	uint8_t* out = (uint8_t*) &key2->keys;
	const int keylen = sizeof (key2->keys);
	int count = 0;

	/* parse states */
# define PARSE_INITIAL        0
# define PARSE_HEAD           1
# define PARSE_DATA           2
# define PARSE_DATA_COMPLETE  3
# define PARSE_FOOT           4
# define PARSE_FINISHED       5
	int state = PARSE_INITIAL;

	/* constants */
	const size_t hlen = strlen (static_key_head);
	const size_t flen = strlen (static_key_foot);
	const int onekeylen = sizeof (key2->keys[0]);

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* 只有主线程能调用 openvpn_exit () */
#endif

	CLEAR (*key2);

	/*
	 * Key can be provided as a filename in 'file' or if RKF_INLINE
	 * is set, the actual key data itself in ascii form.
	 */
	if (flags & RKF_INLINE) /* 'file' is a string containing ascii representation of key */
	{
		size = (int) strlen (file) + 1;
		buf_set_read (&in, (const uint8_t *) file, size);
		error_filename = INLINE_FILE_TAG;
	}
	else /* 'file' is a filename which refers to a file containing the ascii key */
	{
		in = alloc_buf_gc (2048, &gc);
		fd = platform_open (file, O_RDONLY, 0);
		if (fd == -1)
			msg (M_ERR, "Cannot open key file '%s'", file);
		size = read (fd, in.data, in.capacity);
		if (size < 0)
			msg (M_FATAL, "Read error on key file ('%s')", file);
		if (size == in.capacity)
			msg (M_FATAL, "Key file ('%s') can be a maximum of %d bytes", file, (int) in.capacity);
		close (fd);
	}

	cp = (unsigned char *) in.data;
	while (size > 0)
	{
		const unsigned char c = *cp;

#if 0
		msg (M_INFO, "char='%c'[%d] s=%d ln=%d li=%d m=%d c=%d",
			c, (int) c, state, line_num, line_index, match, count);
#endif

		if (c == '\n')
		{
			line_index = match = 0;
			++line_num;	      
		}
		else
		{
			/* first char of new line */
			if (!line_index)
			{
				/* first char of line after header line? */
				if (state == PARSE_HEAD)
					state = PARSE_DATA;

				/* first char of footer */
				if ((state == PARSE_DATA || state == PARSE_DATA_COMPLETE) && c == '-')
					state = PARSE_FOOT;
			}

			/* compare read chars with header line */
			if (state == PARSE_INITIAL)
			{
				if (line_index < (int) hlen && c == static_key_head[line_index])
				{
					if (++match == hlen)
						state = PARSE_HEAD;
				}
			}

			/* compare read chars with footer line */
			if (state == PARSE_FOOT)
			{
				if (line_index < (int) flen && c == static_key_foot[line_index])
				{
					if (++match == flen)
						state = PARSE_FINISHED;
				}
			}

			/* reading key */
			if (state == PARSE_DATA)
			{
				if (isxdigit (c))
				{
					ASSERT (hb_index >= 0 && hb_index < 2);
					hex_byte[hb_index++] = c;
					if (hb_index == 2)
					{
						unsigned int u;
						ASSERT (sscanf ((const char *) hex_byte, "%x", &u) == 1);
						*out++ = u;
						hb_index = 0;
						if (++count == keylen)
							state = PARSE_DATA_COMPLETE;
					}
				}
				else if (isspace (c))
					;
				else
				{
					msg (M_FATAL, (isprint (c) ? printable_char_fmt : unprintable_char_fmt),
						c, line_num, error_filename, count, onekeylen, keylen);
					break;
				}
			}
			++line_index;
		}
		++cp;
		--size;
	}

	/*
	 * Normally we will read either 1 or 2 keys from file.
	 */
	key2->n = count / onekeylen;

	ASSERT (key2->n >= 0 && key2->n <= (int) SIZE (key2->keys));

	if (flags & RKF_MUST_SUCCEED)
	{
		if (!key2->n)
			msg (M_FATAL, "Insufficient key material or header text not found in file '%s' (%d/%d/%d bytes found/min/max)",
				error_filename, count, onekeylen, keylen);

		if (state != PARSE_FINISHED)
			msg (M_FATAL, "Footer text not found in file '%s' (%d/%d/%d bytes found/min/max)",
				error_filename, count, onekeylen, keylen);
	}

	/* zero file read buffer if not an inline file */
	if (!(flags & RKF_INLINE))
		buf_clear (&in);

	if (key2->n)
		warn_if_group_others_accessible (error_filename);

#if 0
	/* DEBUGGING */
	{
		int i;
		printf ("KEY READ, n=%d\n", key2->n);
		for (i = 0; i < (int) SIZE (key2->keys); ++i)
		{
			/* format key as ascii */
			const char *fmt =
				format_hex_ex ((const uint8_t*) &key2->keys[i], sizeof (key2->keys[i]), 0, 16, "\n", &gc);
			printf ("[%d]\n%s\n\n", i, fmt);
		}
	}
#endif

	/* pop our garbage collection level */
	gc_free (&gc);
}

int
read_passphrase_hash (const char *passphrase_file, const md_kt_t *digest, uint8_t *output, int len)
{
	md_ctx_t *md;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* 只有主线程能调用 openvpn_exit () */
#endif
	ASSERT (len >= md_kt_size (digest));
	memset (output, 0, len);

	md = md_ctx_new ();
	md_ctx_init (md, digest);

	/* read passphrase file */
	{
		const int min_passphrase_size = 8;
		uint8_t buf[64];
		int total_size = 0;
		int fd = platform_open (passphrase_file, O_RDONLY, 0);

		if (fd == -1)
			msg (M_ERR, "Cannot open passphrase file: '%s'", passphrase_file);

		for (;;)
		{
			int size = read (fd, buf, sizeof (buf));
			if (size == 0)
				break;
			if (size == -1)
			{
				msg (M_ERR, "Read error on passphrase file: '%s'", passphrase_file);
				break;
			}
			md_ctx_update (md, buf, size);
			total_size += size;
		}
		close (fd);

		warn_if_group_others_accessible (passphrase_file);

		if (total_size < min_passphrase_size)
			msg (M_FATAL, "Passphrase file '%s' is too small (must have at least %d characters)",
				passphrase_file, min_passphrase_size);
	}

	md_ctx_final (md, output);
	md_ctx_cleanup (md);
	md_ctx_free (md);

	return md_kt_size (digest);
}

/*
 * Write key to file, return number of random bits written.
 */
int
write_key_file (const int nkeys, const char *filename)
{
	struct gc_arena gc = gc_new ();
	int fd, i;
	int nbits = 0;

	/* must be large enough to hold full key file */
	struct buffer out = alloc_buf_gc (2048, &gc);
	struct buffer nbits_head_text = alloc_buf_gc (128, &gc);

	/* how to format the ascii file representation of key */
	const int bytes_per_line = 16;

	/* open key file */
	fd = platform_open (filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

	if (fd == -1)
		msg (M_ERR, "Cannot open shared secret file '%s' for write", filename);

	buf_printf (&out, "%s\n", static_key_head);

	for (i = 0; i < nkeys; ++i)
	{
		struct key key;
		char* fmt;

		/* generate random bits */
		generate_key_random (&key, NULL);

		/* format key as ascii */
		fmt = format_hex_ex ((const uint8_t*) &key,
			sizeof (key),
			0,
			bytes_per_line,
			"\n",
			&gc);

		/* increment random bits counter */
		nbits += sizeof (key) * 8;

		/* write to holding buffer */
		buf_printf (&out, "%s\n", fmt);

		/* zero memory which held key component (will be freed by GC) */
		secure_memzero (fmt, strlen (fmt));
		secure_memzero (&key, sizeof (key));
	}

	buf_printf (&out, "%s\n", static_key_foot);

	/* write number of bits */
	buf_printf (&nbits_head_text, "#\n# %d bit OpenVPN static key\n#\n", nbits);
	buf_write_string_file (&nbits_head_text, filename, fd);

	/* write key file, now formatted in out, to file */
	buf_write_string_file (&out, filename, fd);

	if (close (fd))
		msg (M_ERR, "Close error on shared secret file %s", filename);

	/* zero memory which held file content (memory will be freed by GC) */
	buf_clear (&out);

	/* pop our garbage collection level */
	gc_free (&gc);

	return nbits;
}

void
must_have_n_keys (const char *filename, const char *option, const struct key2 *key2, int n)
{
	if (key2->n < n)
	{
#ifdef ENABLE_SMALL
		msg (M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d]", filename, option, key2->n, n);
#else
		msg (M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d] -- try generating a new key file with '" PACKAGE " --genkey --secret [file]', or use the existing key file in bidirectional mode by specifying --%s without a key direction parameter", filename, option, key2->n, n, option);
#endif
	}
}

int
ascii2keydirection (int msglevel, bool warning, const char *str)
{
	if (!str)
		return KEY_DIRECTION_BIDIRECTIONAL;
	else if (!strcmp (str, "0"))
		return KEY_DIRECTION_NORMAL;
	else if (!strcmp (str, "1"))
		return KEY_DIRECTION_INVERSE;
	else
	{
		if (warning)
			msg (msglevel, "Unknown key direction '%s' -- must be '0' or '1'", str);
		return -1;
	}
	return KEY_DIRECTION_BIDIRECTIONAL; /* NOTREACHED */
}

const char *
keydirection2ascii (int kd, bool remote)
{
	if (kd == KEY_DIRECTION_BIDIRECTIONAL)
		return NULL;
	else if (kd == KEY_DIRECTION_NORMAL)
		return remote ? "1" : "0";
	else if (kd == KEY_DIRECTION_INVERSE)
		return remote ? "0" : "1";
	else
	{
		ASSERT (0);
	}
	return NULL; /* NOTREACHED */
}

void
key_direction_state_init (struct key_direction_state *kds, int key_direction)
{
	CLEAR (*kds);
	switch (key_direction)
	{
	case KEY_DIRECTION_NORMAL:
		kds->out_key = 0;
		kds->in_key = 1;
		kds->need_keys = 2;
		break;
	case KEY_DIRECTION_INVERSE:
		kds->out_key = 1;
		kds->in_key = 0;
		kds->need_keys = 2;
		break;
	case KEY_DIRECTION_BIDIRECTIONAL:
		kds->out_key = 0;
		kds->in_key = 0;
		kds->need_keys = 1;
		break;
	default:
		ASSERT (0);
	}
}

void
verify_fix_key2 (struct key2 *key2, const struct key_type *kt, const char *shared_secret_file)
{
	int i;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* 只有主线程能调用 openvpn_exit () */
#endif

	for (i = 0; i < key2->n; ++i)
	{
		/* Fix parity for DES keys and make sure not a weak key */
		fixup_key (&key2->keys[i], kt);

		/* This should be a very improbable failure */
		if (!check_key (&key2->keys[i], kt))
		{
			msg (M_FATAL, "Key #%d in '%s' is bad.  Try making a new key with --genkey.",
				i + 1, shared_secret_file);
			break;
		}
	}
}

/* given a key and key_type, write key to buffer */
bool
write_key (const struct key *key, const struct key_type *kt, struct buffer *buf)
{
	ASSERT (kt->cipher_length <= MAX_CIPHER_KEY_LENGTH && kt->hmac_length <= MAX_HMAC_KEY_LENGTH);

	if (!buf_write (buf, &kt->cipher_length, 1))
		return false;
	if (!buf_write (buf, &kt->hmac_length, 1))
		return false;
	if (!buf_write (buf, key->cipher, kt->cipher_length))
		return false;
	if (!buf_write (buf, key->hmac, kt->hmac_length))
		return false;

	return true;
}

/*
 * Given a key_type and buffer, read key from buffer.
 * Return: 1 on success
 *        -1 read failure
 *         0 on key length mismatch 
 */
int
read_key (struct key *key, const struct key_type *kt, struct buffer *buf)
{
	uint8_t cipher_length;
	uint8_t hmac_length;

	CLEAR (*key);
	if (!buf_read (buf, &cipher_length, 1))
		goto read_err;
	if (!buf_read (buf, &hmac_length, 1))
		goto read_err;

	if (cipher_length != kt->cipher_length || hmac_length != kt->hmac_length)
		goto key_len_err;

	if (!buf_read (buf, key->cipher, cipher_length))
		goto read_err;
	if (!buf_read (buf, key->hmac, hmac_length))
		goto read_err;

	return 1;

read_err:
	msg (D_TLS_ERRORS, "TLS Error: error reading key from remote");
	return -1;

key_len_err:
	msg (D_TLS_ERRORS, "TLS Error: key length mismatch, local cipher/hmac %d/%d, remote cipher/hmac %d/%d",
		kt->cipher_length, kt->hmac_length, cipher_length, hmac_length);
	return 0;
}

/*
 * Random number functions, used in cases where we want
 * reasonably strong cryptographic random number generation
 * without depleting our entropy pool.  Used for random
 * IV values and a number of other miscellaneous tasks.
 */
struct prng_nonce
{
	int nonce_secret_len;
	int processed;
	const md_kt_t *nonce_md;
	uint8_t *nonce_data;
	char padding[CACHE_LINE_SIZE - 2 * sizeof (int) - sizeof (md_kt_t *) - sizeof (uint8_t *)];
};

static struct prng_nonce static_prng_nonces[MAX_THREAD_INDEX] = {0};

/* Reset the nonce value, also done periodically to refresh entropy */
static void
prng_reset_nonce (int thread_idx)
{
	struct prng_nonce *prng_nonce = &static_prng_nonces[thread_idx];

	const int size = md_kt_size (prng_nonce->nonce_md) + prng_nonce->nonce_secret_len;

#if 1 /* Must be 1 for real usage */
	if (!rand_bytes (prng_nonce->nonce_data, size))
		msg (M_FATAL, "ERROR: Random number generator cannot obtain entropy for PRNG");
#else
	/* Only for testing -- will cause a predictable PRNG sequence */
	{
		int i;
		for (i = 0; i < size; ++i)
			prng_nonce->nonce_data[i] = (uint8_t) i;
	}
#endif
}

void
prng_init (const char *md_name, const int nonce_secret_len_parm)
{
	int nonce_data_len, i;
	struct prng_nonce *prng_nonce;
#ifdef THREAD_ACCESS_CHECK
	ASSERT ((sizeof (struct prng_nonce) & (CACHE_LINE_SIZE - 1)) == 0);
#endif

	prng_uninit ();

	for (i = 0; i < MAX_THREAD_INDEX; ++i)
	{
		prng_nonce = &static_prng_nonces[i];

		prng_nonce->nonce_md = md_name ? md_kt_get (md_name) : NULL;
		if (prng_nonce->nonce_md)
		{
			ASSERT (nonce_secret_len_parm >= NONCE_SECRET_LEN_MIN && nonce_secret_len_parm <= NONCE_SECRET_LEN_MAX);
			prng_nonce->nonce_secret_len = nonce_secret_len_parm;

			nonce_data_len = md_kt_size (prng_nonce->nonce_md) + prng_nonce->nonce_secret_len;
			dmsg (D_CRYPTO_DEBUG, "PRNG init md=%s size=%d", md_kt_name (prng_nonce->nonce_md), nonce_data_len);				
			prng_nonce->nonce_data = (uint8_t*) malloc (nonce_data_len);
			check_malloc_return (prng_nonce->nonce_data);
			prng_reset_nonce (i);
		}
	}
}

void
prng_uninit (void)
{
	int i;
	struct prng_nonce *prng_nonce;

	for (i = 0; i < MAX_THREAD_INDEX; ++i)
	{
		prng_nonce = &static_prng_nonces[i];
		if (prng_nonce)
		{
			if (prng_nonce->nonce_data)
				free (prng_nonce->nonce_data);
			prng_nonce->nonce_data = NULL;
			prng_nonce->processed = 0;
			prng_nonce->nonce_md = NULL;
			prng_nonce->nonce_secret_len = 0;
		}
	}
}

void
prng_bytes (uint8_t *output, int len, int thread_idx)
{
	struct prng_nonce *prng_nonce = &static_prng_nonces[thread_idx];
#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx);
#endif

	if (prng_nonce->nonce_md)
	{
		const int md_size = md_kt_size (prng_nonce->nonce_md);
		const int nonce_data_len = md_size + prng_nonce->nonce_secret_len;

		while (len > 0)
		{
			const int blen = min_int (len, md_size);

			md_full (prng_nonce->nonce_md, prng_nonce->nonce_data, nonce_data_len, prng_nonce->nonce_data);
			memcpy (output, prng_nonce->nonce_data, blen);
			output += blen;
			len -= blen;

			/* Ensure that random data is reset regularly */
			prng_nonce->processed += blen;
			if (prng_nonce->processed > PRNG_NONCE_RESET_BYTES)
			{
				prng_reset_nonce (thread_idx);
				prng_nonce->processed = 0;
			}
		}
	}
	else
		ASSERT (rand_bytes (output, len));
}

/* an analogue to the random() function, but use prng_bytes */
long int
get_random (void)
{
	long int l = 0L;

	prng_bytes ((unsigned char *) &l, sizeof (l), THREAD_SELF_INDEX ());
	if (l < 0)
		l = -l;

	return l;
}

#ifndef ENABLE_SSL

void
init_ssl_lib (void)
{
	crypto_init_lib ();
}

void
free_ssl_lib (void)
{
	crypto_uninit_lib ();
	prng_uninit ();
}

#endif /* ENABLE_SSL */

/*
 * md5 functions
 */

const char *
md5sum (uint8_t *buf, int len, int n_print_chars, struct gc_arena *gc)
{
	uint8_t digest[MD5_DIGEST_LENGTH];
	const md_kt_t *md5_kt = md_kt_get ("MD5");

	md_full (md5_kt, buf, len, digest);

	return format_hex (digest, MD5_DIGEST_LENGTH, n_print_chars, gc);
}

void
md5_digest_clear (struct md5_digest *digest)
{
	CLEAR (*digest);
}

bool
md5_digest_defined (const struct md5_digest *digest)
{
	int i;
	for (i = 0; i < MD5_DIGEST_LENGTH; ++i)
		if (digest->digest[i])
			return true;
	return false;
}

bool
md5_digest_equal (const struct md5_digest *d1, const struct md5_digest *d2)
{
	return memcmp (d1->digest, d2->digest, MD5_DIGEST_LENGTH) == 0;
}

#endif /* ENABLE_CRYPTO */
