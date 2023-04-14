#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "socket.h"
#include "packet_buffer.h"
#include "socket-inline.h"
#include "openvpn.h"
#include "thread.h"
#include "multi_crypto.h"

#include "memdbg.h"

static const char error_prefix[] = "Authenticate/Decrypt packet error";

static inline void
key_state_sync_stats (struct key_state *ks, int thread_idx)
{
	time_t local_now = now_sec (thread_idx);

	if (ks && local_now > ks->ks_stats[thread_idx].last_sync_time)
	{
		MUTEX_LOCK (&g_coarse_mutex, thread_idx, S_COARSE);
		ks->n_bytes += ks->ks_stats[thread_idx].n_bytes;
		ks->n_packets += ks->ks_stats[thread_idx].n_packets;
		MUTEX_UNLOCK (&g_coarse_mutex, thread_idx, S_COARSE);

		ks->ks_stats[thread_idx].last_sync_time = local_now;
		ks->ks_stats[thread_idx].n_bytes = 0L;
		ks->ks_stats[thread_idx].n_packets = 0L;
	}
}

void
key_state_get_stats (const struct key_state *ks, int thread_idx, counter_type *n_bytes, counter_type *n_packets)
{
	if (ks && (n_bytes || n_packets))
	{
		MUTEX_LOCK (&g_coarse_mutex, thread_idx, S_COARSE);
		if (n_bytes)
			*n_bytes = ks->n_bytes;
		if (n_packets)
			*n_packets = ks->n_packets;
		MUTEX_UNLOCK (&g_coarse_mutex, thread_idx, S_COARSE);
	}
}

bool
load_crypto_options (struct context *c, int thread_idx, struct crypto_options *opt, int doit, struct packet_buffer *buf)
{
	struct gc_arena gc = gc_new ();
	struct tls_multi *multi = c->c2.tls_multi;
	bool ret = false;
	time_t local_now = now_sec (thread_idx);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx);
#endif

	CLEAR (*opt);
	opt->local_key_id = -1;
	opt->key_id = -1;
	opt->flags = c->c2.crypto_options.flags;

	RWLOCK_RDLOCK (&c->share_lock, thread_idx, S_SHARE_LOCK); /* 阻止主线程对context修改 */

	if (multi)
	{
		struct key_state *ks_select = NULL, *ks = NULL;
		int i = 0;

		if (doit == DO_ENCRYPT)
		{
			for (i = 0; i < KEY_SCAN_SIZE; ++i)
			{
				ks = *multi->key_scan[i];
				if (ks->state >= S_ACTIVE && ks->authenticated
#ifdef ENABLE_DEF_AUTH
					&& !ks->auth_deferred
#endif
					)
				{
					if (!ks_select)
						ks_select = ks;
					if (buf && buf->key_id == ks->key_id)
					{
						ks_select = ks;
						break;
					}
					else if (local_now >= ks->auth_deferred_expire && ks->local_key_id >= c->c2.buffers->write_local_key_id)
					{
						ks_select = ks;
						break;
					}
				}
			}

			if (ks_select)
			{
				opt->key_ctx_bi = &ks_select->key[thread_idx];
				opt->local_key_id = ks_select->local_key_id;
				opt->key_id = ks_select->key_id;
				opt->packet_id = multi->opt.replay ? &ks_select->packet_id : NULL;
				opt->flags &= multi->opt.crypto_flags_and;
				opt->flags |= multi->opt.crypto_flags_or;
				opt->ks_stats = &ks_select->ks_stats[thread_idx];
				key_state_sync_stats (ks_select, thread_idx);
				ret = true;
				if (!buf || buf->key_id < 0)
				{
					/* 未启用分片, 需要锁定read_tun_bufs_mutex; 启用分片, 需要锁定read_tun_bufs_pin_mutex */
					if (ks_select->local_key_id > c->c2.buffers->write_local_key_id)
						c->c2.buffers->write_local_key_id = ks_select->local_key_id;
				}
				dmsg (D_TLS_KEYSELECT, "TLS: tls_pre_encrypt: key_id=%d", ks_select->key_id);
			}
			else
				dmsg (D_TLS_KEYSELECT, "TLS Warning: no data channel send key available: %s", print_key_id (multi, &gc));
		}
		else if (doit == DO_DECRYPT)
		{
			for (i = 0; i < KEY_SCAN_SIZE; ++i)
			{
				/*
				 * This is the basic test of TLS state compatibility between a local OpenVPN 
				 * instance and its remote peer.
				 *
				 * If the test fails, it tells us that we are getting a packet from a source
				 * which claims reference to a prior negotiated TLS session, but the local
				 * OpenVPN instance has no memory of such a negotiation.
				 *
				 * It almost always occurs on UDP sessions when the passive side of the
				 * connection is restarted without the active side restarting as well (the 
				 * passive side is the server which only listens for the connections, the 
				 * active side is the client which initiates connections).
				 */
				ks = *multi->key_scan[i];
				if (DECRYPT_KEY_ENABLED (multi, ks) && ks->authenticated
					&& buf->key_id == ks->key_id && (buf->local_key_id < 0 || buf->local_key_id == ks->local_key_id)
#ifdef ENABLE_DEF_AUTH
					&& !ks->auth_deferred
#endif
					&& link_socket_actual_match (&buf->from, &ks->remote_addr))
				{
					/* return appropriate data channel decrypt key in opt */
					opt->key_ctx_bi = &ks->key[thread_idx];
					opt->local_key_id = ks->local_key_id;
					opt->key_id = ks->key_id;
					opt->packet_id = multi->opt.replay ? &ks->packet_id : NULL;
					opt->flags &= multi->opt.crypto_flags_and;
					opt->flags |= multi->opt.crypto_flags_or;
					opt->ks_stats = &ks->ks_stats[thread_idx];
					key_state_sync_stats (ks, thread_idx);
					ret = true;
					dmsg (D_TLS_KEYSELECT, "TLS: tls_pre_decrypt, key_id=%d, IP=%s", buf->key_id,
						print_link_socket_actual (&buf->from, &gc));
				}
#if 0 /* keys out of sync? */
				else
				{
					dmsg (D_TLS_ERRORS, "TLS_PRE_DECRYPT: [%d] dken=%d rkid=%d lkid=%d auth=%d def=%d match=%d",
						i,
						DECRYPT_KEY_ENABLED (multi, ks),
						key_id,
						ks->key_id,
						ks->authenticated,
#ifdef ENABLE_DEF_AUTH
						ks->auth_deferred,
#else
						-1,
#endif
						link_socket_actual_match (&buf->from, &ks->remote_addr));
				}
#endif
			}

			if (!ret)
				msg (D_TLS_ERRORS, "TLS Error: local/remote TLS keys are out of sync: %s [%d]",
					print_link_socket_actual (&buf->from, &gc), buf->key_id);
		}
	}
	else
	{
		if (c->c1.ks.static_key)
			opt->key_ctx_bi = &c->c1.ks.static_key[thread_idx];	/* 共享密钥时 */
		opt->local_key_id = -1;
		opt->key_id = -1;
		opt->packet_id = c->c2.crypto_options.packet_id;
		opt->pid_persist = c->c2.crypto_options.pid_persist;
		opt->flags = c->c2.crypto_options.flags;
		ret = true;
	}

	RWLOCK_UNLOCK (&c->share_lock, thread_idx, S_SHARE_LOCK); /* 允许主线程对context修改 */

	if (!ret)
	{
		if (buf)
			packet_buffer_drop (buf, PACKET_DROP_CRYPTO_OPTION_ERROR);
		tls_clear_error ();
	}
	gc_free (&gc);
	return ret;
}

void
check_replays (struct context *c, struct packet_buffer_list *ol)
{
	struct gc_arena gc = gc_new ();
	struct crypto_options *opt = &g_tun_transfer_context->crypto_opt;
	bool success = false;
	struct packet_buffer *prev_load = NULL, *next = NULL;
	struct timeval *local_now = now_tv (TUN_THREAD_INDEX);
#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_tun_thread ());
#endif

	next = ol->head;
	while (next)
	{
		/* 0 长包也要检查, 因为TCP要求pin连续且不中断 */
		if (!prev_load || next->local_key_id != prev_load->local_key_id)
		{
			success = load_crypto_options (c, TUN_THREAD_INDEX, opt, DO_DECRYPT, next);
			prev_load = next;
		}

		if (!success)
		{
			msg (M_WARN, "load crypto options(DECRYPT, CHECK REPLAY) fail!");
			packet_buffer_drop (next, PACKET_DROP_CRYPTO_OPTION_ERROR);
		}
		else if (next->flags & PACKET_BUFFER_HAVE_PIN_FLAG && !(next->flags & PACKET_BUFFER_REPLAY_CHE_FLAG))
		{
			next->flags |= PACKET_BUFFER_REPLAY_CHE_FLAG; /* 标记已做了重放检查 */
			packet_id_reap_test (&opt->packet_id->rec, local_now->tv_sec);
			if (packet_id_test (&opt->packet_id->rec, local_now->tv_usec, &next->pin))
			{
				packet_id_add (&opt->packet_id->rec, local_now->tv_sec, &next->pin);
				if (opt->pid_persist && (opt->flags & CO_PACKET_ID_LONG_FORM))
					packet_id_persist_save_obj (opt->pid_persist, opt->packet_id);
			}
			else
			{
				if (!(opt->flags & CO_MUTE_REPLAY_WARNINGS))
					msg (D_REPLAY_ERRORS, "%s: bad packet ID (may be a replay): %s -- see the man page entry for --no-replay"
						" and --replay-window for more info or silence this warning with --mute-replay-warnings",
						error_prefix, packet_id_net_print (&next->pin, true, &gc));
				packet_buffer_drop (next, PACKET_DROP_BAD_PACKET_ID);
			}
		}

		next = next->next;
	}

	gc_free (&gc);
}

/**
 * As memcmp(), but constant-time.
 * Returns 0 when data is equal, non-zero otherwise.
 */
static inline int
memcmp_constant_time (const void *a, const void *b, size_t size)
{
	const uint8_t *a1 = (const uint8_t*) a;
	const uint8_t *b1 = (const uint8_t*) b;
	int ret = 0;
	size_t i;

	for (i = 0; i < size; ++i)
	{
		ret |= *a1++ ^ *b1++;
	}

	return ret;
}

bool verify_hmac (int thread_idx, struct crypto_options *opt, struct buffer *buf)
{
#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx);
#endif

	if (buf->len > 0 && opt->key_ctx_bi)
	{
		struct key_ctx *ctx = &opt->key_ctx_bi->decrypt;

		/* Verify the HMAC */
		if (ctx->hmac)
		{
			int hmac_len;
			uint8_t local_hmac[MAX_HMAC_KEY_LENGTH]; /* HMAC of ciphertext computed locally */

			hmac_ctx_reset (ctx->hmac);

			/* Assume the length of the input HMAC */
			hmac_len = hmac_ctx_size (ctx->hmac);

			/* Authentication fails if insufficient data in packet for HMAC */
			if (buf->len < hmac_len)
				CRYPT_ERROR ("missing authentication info");

			hmac_ctx_update (ctx->hmac, BPTR (buf) + hmac_len, BLEN (buf) - hmac_len);
			hmac_ctx_final (ctx->hmac, local_hmac);

			/* Compare locally computed HMAC with packet HMAC */
			if (memcmp_constant_time (local_hmac, BPTR (buf), hmac_len))
				CRYPT_ERROR ("packet HMAC authentication failed");

			ASSERT (buf_advance (buf, hmac_len));
		}
	}

	return true;

error_exit:
	crypto_clear_error ();
	buf->len = 0;	/* 丢弃包 */
	buf_set_tracking (buf, PACKET_DROP_HMAC_AUTH_FAILED);
	return false;
}

bool generate_hmac (int thread_idx, struct crypto_options *opt, struct buffer *buf)
{
#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx);
#endif

	if (buf->len > 0 && opt->key_ctx_bi)
	{
		struct key_ctx *ctx = &opt->key_ctx_bi->encrypt;

		/* HMAC the ciphertext (or plaintext if !cipher) */
		if (ctx->hmac)
		{
			uint8_t *output = NULL;
			hmac_ctx_reset (ctx->hmac);
			hmac_ctx_update (ctx->hmac, BPTR (buf), BLEN (buf));
			output = buf_prepend (buf, hmac_ctx_size (ctx->hmac));
			ASSERT (output);
			hmac_ctx_final (ctx->hmac, output);
		}
	}

	return true;
}

static inline bool
multi_add_pkcs5_padding (struct packet_buffer *buf, const int block_size)
{
	int i;
	int n = block_size - buf_len (&buf->buf) % block_size;
	uint8_t *u = buf_bend (&buf->buf);

	if (u && n > 0)
	{
		for (i = 0; i < n; ++i)
		{
			*u = n;
			++u;
		}
		buf->buf.len += n;
	}

	return true;
}

static inline bool
multi_remove_pkcs5_padding (struct packet_buffer *buf, const int block_size)
{
	uint8_t *u = buf_blast (&buf->buf);

	if (u)
	{
		int n = *u;

		if (n <= block_size)
		{
			buf->buf.len -= n;
			return true;
		}
	}

	return false;
}

bool 
openvpn_encrypt (int thread_idx, struct crypto_options *opt, struct frame *frame, struct packet_buffer *buf,
	struct packet_buffer *work)
{
	struct gc_arena gc = gc_new ();

#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx);
#endif

	if (buf->buf.len > 0 && opt->key_ctx_bi)
	{
		struct key_ctx *ctx = &opt->key_ctx_bi->encrypt;

		ASSERT (buf->key_id == opt->key_id || (buf->key_id < 0 && opt->key_id < 0));

		/* Do Encrypt from buf -> work */
		if (ctx->cipher)
		{
			const int block_size = cipher_ctx_block_size (ctx->cipher);
			uint8_t iv_buf[OPENVPN_MAX_IV_LENGTH];
			const int iv_size = cipher_ctx_iv_length (ctx->cipher);
			const unsigned int mode = cipher_ctx_mode (ctx->cipher);
			int outlen;

			// 无效pkcs5填充
			EVP_CIPHER_CTX_set_padding (ctx->cipher, 0);

			if (mode == OPENVPN_MODE_CBC)
			{
				/* generate pseudo-random IV */
				if (opt->flags & CO_USE_IV)
					prng_bytes (iv_buf, iv_size, thread_idx);
				else
					CLEAR (iv_buf);

				/* Put packet ID in plaintext buffer or IV, depending on cipher mode */
				if (opt->packet_id)
					ASSERT (packet_id_write (&buf->pin, &buf->buf, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM), true));

				// PKCS5填充
				multi_add_pkcs5_padding (buf, block_size);
			}
			else if (mode == OPENVPN_MODE_CFB || mode == OPENVPN_MODE_OFB || mode == OPENVPN_MODE_CTR)
			{
				struct buffer b;

				ASSERT (opt->flags & CO_USE_IV);    /* IV and packet-ID required */
				ASSERT (opt->packet_id); /* for this mode. */

				buf_set_write (&b, iv_buf, iv_size);
				ASSERT (packet_id_write (&buf->pin, &b, true, false));

				// 流模式不需要填充
			}
			else /* We only support CBC, CFB, or OFB modes right now */
			{
				ASSERT (0);
			}

			/* initialize work buffer with FRAME_HEADROOM bytes of prepend capacity */
			ASSERT (buf_init (&work->buf, FRAME_HEADROOM (frame)));

			/* set the IV pseudo-randomly */
			if (opt->flags & CO_USE_IV)
				dmsg (D_PACKET_CONTENT, "ENCRYPT IV: %s", format_hex (iv_buf, iv_size, 0, &gc));

			dmsg (D_PACKET_CONTENT, "ENCRYPT FROM: %s",
				format_hex (BPTR (&buf->buf), BLEN (&buf->buf), 80, &gc));

			/* cipher_ctx was already initialized with key & keylen */
			ASSERT (cipher_ctx_reset (ctx->cipher, iv_buf));

			/* Buffer overflow check */
			if (!buf_safe (&work->buf, buf->buf.len + cipher_ctx_block_size (ctx->cipher)))
			{
				msg (D_CRYPT_ERRORS, "ENCRYPT: buffer size error, bc=%d bo=%d bl=%d wc=%d wo=%d wl=%d cbs=%d",
					buf->buf.capacity,
					buf->buf.offset,
					buf->buf.len,
					work->buf.capacity,
					work->buf.offset,
					work->buf.len,
					cipher_ctx_block_size (ctx->cipher));
				goto err;
			}

			/* Encrypt packet ID, payload */
			ASSERT (cipher_ctx_update (ctx->cipher, BPTR (&work->buf), &outlen, BPTR (&buf->buf), BLEN (&buf->buf)));
			work->buf.len += outlen;

			/* Flush the encryption buffer */
			ASSERT (cipher_ctx_final (ctx->cipher, BPTR (&work->buf) + outlen, &outlen));
			work->buf.len += outlen;

			/* prepend the IV to the ciphertext */
			if (opt->flags & CO_USE_IV)
			{
				uint8_t *output = buf_prepend (&work->buf, iv_size);
				ASSERT (output);
				memcpy (output, iv_buf, iv_size);
			}

			dmsg (D_PACKET_CONTENT, "ENCRYPT TO: %s", format_hex (BPTR (&work->buf), BLEN (&work->buf), 80, &gc));

			{
				uint8_t *data = buf->buf.data;
				buf->buf = work->buf;
				work->buf.data = data;
			}
		}
		else				/* No Encryption */
		{
			if (opt->packet_id)
			{
				ASSERT (packet_id_write (&buf->pin, &buf->buf, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM), true));
			}
		}
	}

	gc_free (&gc);
	return true;

err:
	crypto_clear_error ();
	packet_buffer_drop (buf, PACKET_DROP_CRYPT_FAILED);
	gc_free (&gc);
	return false;
}

bool
openvpn_decrypt (int thread_idx, struct crypto_options *opt, struct frame *frame, struct packet_buffer *buf,
	struct packet_buffer *work)
{
	struct gc_arena gc = gc_new ();

#ifdef THREAD_ACCESS_CHECK
	ASSERT (THREAD_SELF_INDEX () == thread_idx);
#endif

	if (buf->buf.len > 0 && opt->key_ctx_bi) 
	{
		struct key_ctx *ctx = &opt->key_ctx_bi->decrypt;

		ASSERT (buf->key_id == opt->key_id || (buf->key_id < 0 && opt->key_id < 0));

		if (ctx->cipher) 
		{
			const unsigned int mode = cipher_ctx_mode (ctx->cipher);
			const int iv_size = cipher_ctx_iv_length (ctx->cipher);
			uint8_t iv_buf[OPENVPN_MAX_IV_LENGTH];
			int outlen;

			/* 有效PKCS5填充 */
			EVP_CIPHER_CTX_set_padding (ctx->cipher, 1);

			/* initialize work buffer with FRAME_HEADROOM bytes of prepend capacity */
			ASSERT (buf_init (&work->buf, FRAME_HEADROOM_ADJ (frame, FRAME_HEADROOM_MARKER_DECRYPT)));

			/* use IV if user requested it */
			if (opt->flags & CO_USE_IV) 
			{
				if (buf->buf.len < iv_size)
					CRYPT_ERROR ("missing IV info");
				memcpy (iv_buf, BPTR (&buf->buf), iv_size);
				ASSERT (buf_advance (&buf->buf, iv_size));
			}
			else
				CLEAR (iv_buf);

			/* show the IV's initial state */
			if (opt->flags & CO_USE_IV)
				dmsg (D_PACKET_CONTENT, "DECRYPT IV: %s", format_hex (iv_buf, iv_size, 0, &gc));

			if (buf->buf.len < 1)
				CRYPT_ERROR ("missing payload");
			/* ctx->cipher was already initialized with key & keylen */
			if (!cipher_ctx_reset (ctx->cipher, iv_buf))
				CRYPT_ERROR ("cipher init failed");

			/* Buffer overflow check (should never happen) */
			if (!buf_safe (&work->buf, buf->buf.len + cipher_ctx_block_size (ctx->cipher)))
				CRYPT_ERROR ("potential buffer overflow");

			if (!cipher_ctx_update (ctx->cipher, BPTR (&work->buf), &outlen, BPTR (&buf->buf), BLEN (&buf->buf)))
				CRYPT_ERROR ("cipher update failed");
			work->buf.len += outlen;

			/* Flush the decryption buffer */
			if (!cipher_ctx_final (ctx->cipher, BPTR (&work->buf) + outlen, &outlen))
				CRYPT_ERROR ("cipher final failed");
			work->buf.len += outlen;

			dmsg (D_PACKET_CONTENT, "DECRYPT TO: %s", format_hex (BPTR (&work->buf), BLEN (&work->buf), 80, &gc));

			{
				uint8_t *data = buf->buf.data;
				buf->buf = work->buf;
				work->buf.data = data;
			}

			/* Get packet ID from plaintext buffer or IV, depending on cipher mode */
			if (mode == OPENVPN_MODE_CBC)
			{
				if (opt->packet_id)
				{
					if (!packet_id_read (&buf->pin, &buf->buf, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM)))
						CRYPT_ERROR ("error reading CBC packet-id");
					buf->flags |= PACKET_BUFFER_HAVE_PIN_FLAG;
				}
			}
			else if (mode == OPENVPN_MODE_CFB || mode == OPENVPN_MODE_OFB || mode == OPENVPN_MODE_CTR)
			{
				struct buffer b;

				ASSERT (opt->flags & CO_USE_IV);    /* IV and packet-ID required */
				ASSERT (opt->packet_id); /*  for this mode. */

				buf_set_read (&b, iv_buf, iv_size);
				if (!packet_id_read (&buf->pin, &b, true))
					CRYPT_ERROR ("error reading CFB/OFB/CTR packet-id");
				buf->flags |= PACKET_BUFFER_HAVE_PIN_FLAG;
			}
			else /* We only support CBC, CFB, or OFB modes right now */
			{
				ASSERT (0);
			}
		}
		else
		{
			if (opt->packet_id)
			{
				if (!packet_id_read (&buf->pin, &buf->buf, BOOL_CAST (opt->flags & CO_PACKET_ID_LONG_FORM)))
					CRYPT_ERROR ("error reading packet-id");
				if (!BOOL_CAST (opt->flags & CO_IGNORE_PACKET_ID))
					buf->flags |= PACKET_BUFFER_HAVE_PIN_FLAG;
			}
		}
	
#ifdef _DEBUG
		/* This should never happen, probably indicates some kind of MTU mismatch. */
		if (buf->buf.len > MAX_RW_SIZE_TUN (frame))
			msg (D_LINK_ERRORS, "tun packet too large on write (tried=%d,max=%d) %s", buf->buf.len,
				MAX_RW_SIZE_TUN (frame), format_hex (BPTR (&buf->buf), BLEN (&buf->buf), BLEN (&buf->buf), &gc));
#endif
	}

	gc_free (&gc);
	return true;

error_exit:
	crypto_clear_error ();
	packet_buffer_drop (buf, PACKET_DROP_CRYPT_FAILED);
	gc_free (&gc);
	return false;
}
