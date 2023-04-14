#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_MASQUERADE

#include "error.h"
#include "ssl.h"
#include "masquerade.h"

#include "memdbg.h"

#define MASQUERADE_RANDOM_LENGTH	4

const uint8_t masquerade_string[] = {
	0x6d, 0x5d, 0x45, 0xb0, 0x8b, 0xc4, 0xd9, 0xbd, 0x44, 0x4c, 0xc2, 0xb0, 0x7d, 0x29, 0x93, 0xea
};

struct masquerade_proto_names
{
	unsigned short proto_num;
	const char *proto_name;
	int extra_link;	/* 伪装链路开销 */
};

static const struct masquerade_proto_names masquerade_proto_names[MASQUERADE_PROTO_N] = {
	{MASQUERADE_PROTO_NONE, "none", 0},
	{MASQUERADE_PROTO_XORSTREAM, "xorstream", 0}
};

int
ascii_2_masquerade_proto (const char *proto_name)
{
	int i;

	ASSERT (MASQUERADE_PROTO_N == SIZE (masquerade_proto_names));

	for (i = 0; i < MASQUERADE_PROTO_N; ++i)
	{
		if (!strcmp (proto_name, masquerade_proto_names[i].proto_name))
			return masquerade_proto_names[i].proto_num;
	}

	return -1;
}

const char* 
masquerade_proto_2_ascii (int proto)
{
	int i;

	ASSERT (MASQUERADE_PROTO_N == SIZE (masquerade_proto_names));

	for (i = 0; i < MASQUERADE_PROTO_N; ++i)
	{
		if (proto == masquerade_proto_names[i].proto_num)
			return masquerade_proto_names[i].proto_name;
	}

	return "[unknown masquerade protocol]";
}

const char*
masquerade_proto_2_ascii_all (struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (512, gc);
	int i;

	ASSERT (MASQUERADE_PROTO_N == SIZE (masquerade_proto_names));

	for (i = 0; i < MASQUERADE_PROTO_N; ++i)
	{
		if (i)
			buf_printf (&out, " ");
		buf_printf (&out, "[%s]", masquerade_proto_names[i].proto_name);
	}

	return BSTR (&out);
}

static inline void
xorstream_generate_expansion (int xor_len, unsigned char *random, int random_len, struct masquerade_options *opt)
{
	unsigned char md[SHA_DIGEST_LENGTH];

	while (BLEN (&opt->work_buf) < xor_len)
	{
		md_ctx_init (opt->md_ctx, EVP_sha1 ());

		if (BLEN (&opt->work_buf) > 0)
		{
			md_ctx_update (opt->md_ctx, BPTR (&opt->work_buf), BLEN (&opt->work_buf));
		}
		else
		{
			md_ctx_update (opt->md_ctx, opt->md_salt, SHA_DIGEST_LENGTH);
			md_ctx_update (opt->md_ctx, random, random_len);
			md_ctx_update (opt->md_ctx, masquerade_string, sizeof (masquerade_string));
		}

		md_ctx_final (opt->md_ctx, md);

		buf_write (&opt->work_buf, md, SHA_DIGEST_LENGTH);
	}
}

static inline int 
xorstream_masquerade_link_buffer (struct buffer *buf, struct masquerade_options *opt)
{
	uint8_t *b, *x;
	uint8_t *random;
	int i, op;

	ASSERT (BLEN (buf) > MASQUERADE_RANDOM_LENGTH + MASQUERADE_RANDOM_LENGTH);

	/* 重置工作区 */
	buf_reset_len (&opt->work_buf);

	/* 判断包类型 */
	x = BPTR (buf);
	op = *x >> P_OPCODE_SHIFT;

	/* 混淆op_code, 兼容port_share, 要求特殊处理 */
	b = BPTR (buf);
	*b = *b ^ masquerade_string[2] ^ opt->md_salt[0];
	b++;

	/* 定位伪随机数 */
	random = BPTR (buf) + BLEN (buf) - MASQUERADE_RANDOM_LENGTH;

	if (op == P_DATA_V1 || op == P_DATA_V2)
	{
		int hdr = min_int (BLEN (buf) - MASQUERADE_RANDOM_LENGTH, SHA_DIGEST_LENGTH);

		/* 数据层包, 混淆协议头 */
		xorstream_generate_expansion (hdr - 1, random, MASQUERADE_RANDOM_LENGTH, opt);

		for (i = 1, b, x = BPTR (&opt->work_buf); i < hdr; i++, b++, x++)
		{
			*b ^= *x;
		}
	}
	else
	{
		/* 控制层包, 混淆全部内容 */
		xorstream_generate_expansion (BLEN (buf) - MASQUERADE_RANDOM_LENGTH - 1, random, MASQUERADE_RANDOM_LENGTH, opt);

		for (i = 1, b, x = BPTR (&opt->work_buf); i < BLEN (buf) - MASQUERADE_RANDOM_LENGTH; i++, b++, x++)
		{
			*b ^= *x;
		}
	}

	return BLEN (buf);
}

static inline bool 
xorstream_pre_unmasquerade_link_buffer (const struct buffer *buf, int offset, struct masquerade_options *opt)
{
	if (BLEN (buf) >= offset)
	{
		uint8_t *b;

		/* 解除op_code混淆, 兼容port_share, 要求特殊处理 */
		b = BPTR (buf) + offset;	
		opt->op_code = (*b ^ masquerade_string[2] ^ opt->md_salt[0]) & (0xFF << P_OPCODE_SHIFT);

		return true;
	}
	else
	{
		return false;
	}
}

static inline int 
xorstream_unmasquerade_link_buffer (struct buffer *buf, struct masquerade_options *opt)
{
	uint8_t *b, *x;
	uint8_t *random;
	int i, op;
	
	ASSERT (BLEN (buf) > MASQUERADE_RANDOM_LENGTH + MASQUERADE_RANDOM_LENGTH);

	/* 重置工作区 */
	buf_reset_len (&opt->work_buf);

	/* 解除op_code混淆, 兼容port_share, 要求特殊处理 */
	b = BPTR (buf);
	*b = *b ^ masquerade_string[2] ^ opt->md_salt[0];
	b++;

	/* 判断包类型 */
	x = BPTR (buf);
	op = *x >> P_OPCODE_SHIFT;

	random = BPTR (buf) + BLEN (buf) - MASQUERADE_RANDOM_LENGTH;

	if (op == P_DATA_V1 || op == P_DATA_V2)
	{
		int hdr = min_int (BLEN (buf) - MASQUERADE_RANDOM_LENGTH, SHA_DIGEST_LENGTH);

		/* 数据层包, 解除头部混淆 */
		xorstream_generate_expansion (hdr - 1, random, MASQUERADE_RANDOM_LENGTH, opt);

		for (i = 1, b, x = BPTR (&opt->work_buf); i < hdr; i++, b++, x++)
		{
			*b ^= *x;
		}
	}
	else
	{
		/* 控制层包, 解除全部内容混淆 */
		xorstream_generate_expansion (BLEN (buf) - MASQUERADE_RANDOM_LENGTH - 1, random, MASQUERADE_RANDOM_LENGTH, opt);

		for (i = 1, b, x = BPTR (&opt->work_buf); i < BLEN (buf) - MASQUERADE_RANDOM_LENGTH; i++, b++, x++)
		{
			*b ^= *x;
		}
	}

	return BLEN (buf);
}

void
masquerade_adjust_frame_parameters (struct frame *frame, int masq_proto)
{
	if (masq_proto >= 0 && masq_proto < MASQUERADE_PROTO_N)
		frame_add_to_extra_link (frame, masquerade_proto_names[masq_proto].extra_link);
	else
		msg (M_FATAL, "unknown masquerade protoco %d", masq_proto);
}

int
masquerade_link_buffer (struct buffer *buf, struct masquerade_options *opt)
{
	if (opt)
	{
		if (opt->masq_proto == MASQUERADE_PROTO_XORSTREAM)
			return xorstream_masquerade_link_buffer (buf, opt);
		else
			msg (M_FATAL, "unknown masquerade protoco %d", opt->masq_proto);
	}
	else
	{
		return BLEN (buf);
	}
}

bool
pre_unmasquerade_link_buffer (const struct buffer *buf, int offset, struct masquerade_options *opt)
{
	if (opt)
	{
		if (opt->masq_proto == MASQUERADE_PROTO_XORSTREAM)
			return xorstream_pre_unmasquerade_link_buffer (buf, offset, opt);
		else
			msg (M_FATAL, "unknown masquerade protoco %d", opt->masq_proto);
	}
	else
	{
		ASSERT (BLEN (buf) >= offset);
		opt->op_code = *(BPTR (buf) + offset);
		return true;
	}
}

int
unmasquerade_link_buffer (struct buffer *buf, struct masquerade_options *opt)
{
	if (opt)
	{
		if (opt->masq_proto == MASQUERADE_PROTO_XORSTREAM)
			return xorstream_unmasquerade_link_buffer (buf, opt);
		else
			msg (M_FATAL, "unknown masquerade protoco %d", opt->masq_proto);
	}
	else
	{
		return BLEN (buf);
	}
}

#endif
