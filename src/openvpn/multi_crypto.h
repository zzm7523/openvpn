#ifndef __MULTI_CRYPTO_H__
#define __MULTI_CRYPTO_H__

#include "crypto.h"
#include "ssl_common.h"
#include "mtu.h"
#include "packet_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DO_NONE     0
#define DO_DECRYPT  1
#define DO_ENCRYPT  2

void
key_state_get_stats (const struct key_state *ks, int thread_idx, counter_type *n_bytes, counter_type *n_packets);

bool
load_crypto_options (struct context *c, int thread_idx, struct crypto_options *opt, int doit,
	struct packet_buffer *buf);

void
check_replays (struct context *c, struct packet_buffer_list *ol);

bool
verify_hmac (int thread_idx, struct crypto_options *opt, struct buffer *buf);

bool
generate_hmac (int thread_idx, struct crypto_options *opt, struct buffer *buf);

bool
openvpn_encrypt (int thread_idx, struct crypto_options *opt, struct frame *frame, struct packet_buffer *buf,
	struct packet_buffer *work);

bool
openvpn_decrypt (int thread_idx, struct crypto_options *opt, struct frame *frame, struct packet_buffer *buf,
	struct packet_buffer *work);

#ifdef __cplusplus
}
#endif

#endif
