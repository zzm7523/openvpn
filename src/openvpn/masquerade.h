#ifndef __MASQUERADE_H__
#define __MASQUERADE_H__

#ifdef ENABLE_MASQUERADE

#include "buffer.h"
#include "mtu.h"
#include "crypto.h"
#include "crypto_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

enum masquerade_proto_num
{
	MASQUERADE_PROTO_NONE,
	MASQUERADE_PROTO_XORSTREAM,
	MASQUERADE_PROTO_N
};

struct masquerade_options
{
	int masq_proto;		/* 链路伪装协议 */
	int op_code;		/* packet opcode */
	struct buffer work_buf;
	md_ctx_t *md_ctx;	/* 采用SHA1算法 */
	unsigned char md_salt[SHA_DIGEST_LENGTH];
};

extern const uint8_t masquerade_string[];

int ascii_2_masquerade_proto (const char *proto_name);

const char* masquerade_proto_2_ascii (int proto);

const char* masquerade_proto_2_ascii_all (struct gc_arena *gc);

void masquerade_adjust_frame_parameters (struct frame *frame, int masq_proto);

int masquerade_link_buffer (struct buffer *buf, struct masquerade_options *opt);

bool pre_unmasquerade_link_buffer (const struct buffer *buf, int offset, struct masquerade_options *opt);

int unmasquerade_link_buffer (struct buffer *buf, struct masquerade_options *opt);

#ifdef __cplusplus
}
#endif

#endif

#endif
