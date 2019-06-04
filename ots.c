#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>

#include "ots.h"

#define ATTESTATION_TAG_SIZE 8
#define STR_DETAIL(x) #x
#define STR(x) STR_DETAIL(x)
typedef unsigned char u8;

#define SUPPORTED_VERSION 0x1

// 160-bit hash
#define MIN_FILE_DIGEST_LENGTH 20

// 256-bit hash
#define MAX_FILE_DIGEST_LENGTH 32

// maximum size of attestation payload
#define MAX_PAYLOAD_SIZE 8192
#define MAX_RESULT_LENGTH 4096
#define MAX_TMPBUF_SIZE MAX_PAYLOAD_SIZE

#define memeq(d, d2, len) (memcmp(d, d2, len) == 0)

#define attestation_eq(a1, a2) memeq(a1, a2, ATTESTATION_TAG_SIZE)

#define peek_cursor(len) (cursor->p + (len) > cursor->end)

#define check_cursor(len)				\
	do {						\
	if (peek_cursor(len)) {	   \
		ots_errmsg = (char*)__PRETTY_FUNCTION__;	\
		cursor->state = OTS_ERR_OVERFLOW;		\
		return 0;					\
	}						\
	} while(0)


struct cursor {
	u8 *p;
	u8 *end;
	enum ots_parse_state state;
};

// ots
const u8 succinct_proof_magic[] = { 0x6f, 0x74, 0x73 };

static const u8 proof_magic[] = {
	0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
	0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
	0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94
};

static const u8 pending_attestation[ATTESTATION_TAG_SIZE] = {
	0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e
};

static const u8 bitcoin_block_header_attestation[ATTESTATION_TAG_SIZE] = {
	0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01
};

static const u8 litecoin_block_header_attestation[ATTESTATION_TAG_SIZE] = {
	0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45
};


char *ots_errmsg = "no additional information";

static void init_cursor(struct cursor *cursor) {
	cursor->state = OTS_PARSE_PARTIAL;
	cursor->p = NULL;
	cursor->end = NULL;
};

static int consume_bytes(struct cursor *cursor, const u8 *bytes,
			 unsigned int bytes_len) {
	// this should only trigger if we've missed a check_cursor up above
	// this doesn't provide useful error messages if we hit it here.
	check_cursor(bytes_len);

	if (bytes == NULL || memcmp(cursor->p, bytes, bytes_len) == 0)
		cursor->p += bytes_len;
	else
		return 0;

	return 1;
}


static int consume_matching_byte(struct cursor *cursor, const u8 byte) {
	u8 bytes[] = { byte };
	return consume_bytes(cursor, bytes, sizeof(bytes));
}

static int consume_byte(struct cursor *cursor, u8 *byte) {
	if (!consume_bytes(cursor, NULL, 1))
		return 0;
	if (byte)
		*byte = *(cursor->p - 1);
	return 1;
}

// NOTE: this is technically a varuint
static int consume_version(struct cursor *cursor, u8 *ver) {
	int ok;
	check_cursor(1);
	*ver = *cursor->p;
	ok = consume_matching_byte(cursor, SUPPORTED_VERSION);
	if (!ok) {
		cursor->state = OTS_ERR_UNSUPPORTED_VERSION;
		return 0;
	}
	return ok;
}

static int parse_op_class(u8 type, enum op_class *class)
{
	switch ((enum binary_op)type) {
	case OP_APPEND:
	case OP_PREPEND:
		*class = OP_CLS_BINARY;
		return 1;
	}

	switch ((enum unary_op)type) {
	case OP_HEXLIFY:
	case OP_REVERSE:
		*class = OP_CLS_UNARY;
		return 1;
	}

	switch ((enum crypto_op)type) {
	case OP_KECCAK256:
	case OP_SHA1:
	case OP_SHA256:
	case OP_RIPEMD160:
		*class = OP_CLS_CRYPTO;
		return 1;
	}

	return 0;
}

static int parse_crypto_op_payload(struct cursor *cursor, struct op *op)
{
	u8 *digest;
	int digest_len;

	op->class = OP_CLS_CRYPTO;
	digest = cursor->p;

#define consume_hash(typ)					\
	digest_len = sizeof(op->crypto.data.typ);		 \
	if (!consume_bytes(cursor, NULL, digest_len)) return 0;	\
	memcpy(op->crypto.data.typ, digest, digest_len); \
	return 1

	switch (op->crypto.op) {
	case OP_SHA1:      consume_hash(sha1);
	case OP_SHA256:    consume_hash(sha256);
	case OP_KECCAK256: consume_hash(keccak256);
	case OP_RIPEMD160: consume_hash(ripemd160);
	}

#undef consume_hash

	// backtrack on failure
	(cursor->p)--;

	return 0;
}

static int parse_crypto_op(struct cursor *cursor, struct op *op)
{
	u8 tag;

	if (!consume_byte(cursor, &tag))
		return 0;

	if (!parse_op_class(tag, &op->class)) {
		ots_errmsg = "could not parse op class";
		cursor->state = OTS_ERR_CORRUPT;
		return 0;
	}

	if (op->class != OP_CLS_CRYPTO) {
		ots_errmsg = "tried to parse crypto op, but is not crypto op class";
		cursor->state = OTS_ERR_CORRUPT;
		return 0;
	}

	op->crypto.op = tag;

	return parse_crypto_op_payload(cursor, op);
}

static int consume_varint(struct cursor *cursor, int max_len,
			  int *res) {
	int shift = 0;
	*res = 0;
	u8 byte;

	while (1) {
		if (!consume_byte(cursor, &byte))
			return 0;

		*res |= (byte & 127) << shift;

		if (*res > max_len) {
			ots_errmsg = "varint larger than max_len";
			return 0;
		}

		if (!(byte & 128))
			break;

		shift += 7;
	}

	return 1;
}


static int consume_varbytes(struct cursor *cursor, int max_len,
				int min_len, int *len, u8 **data) {
	if (!consume_varint(cursor, max_len, len)) {
		cursor->state = OTS_ERR_CORRUPT;
		return 0;
	}

	if (*len > max_len) {
		ots_errmsg = "consume_varbytes: payload too large";
		cursor->state = OTS_ERR_CORRUPT;
		return 0;
	}

	if (*len < min_len) {
		cursor->state = OTS_ERR_CORRUPT;
		ots_errmsg = "consume_varbytes: payload too small";
		return 0;
	}

	*data = cursor->p;
	return consume_bytes(cursor, NULL, *len);
}

static int parse_binary_op_payload(struct cursor *cursor, struct op *op) {
	static const unsigned int min_len = 1;
	op->class = OP_CLS_BINARY;

	return consume_varbytes(cursor, MAX_RESULT_LENGTH, min_len,
				&op->binary.data_len,
				&op->binary.data);
}

static int consume_op(struct cursor *cursor, u8 tag, struct op *op) {
	if (!parse_op_class(tag, &op->class)) {
		ots_errmsg = "could not parse OP class";
		cursor->state = OTS_ERR_CORRUPT;
		return 0;
	}

	switch (op->class) {
	case OP_CLS_CRYPTO:
		op->crypto.op = tag;
		op->crypto.data.sha1[0] = 0;
		return 1;
	/* return parse_crypto_op_payload(cursor, op); */
	case OP_CLS_BINARY:
		op->binary.op = tag;
		return parse_binary_op_payload(cursor, op);
	case OP_CLS_UNARY:
		op->unary_op = tag;
		return 1;
	}

	assert(!"unhandled op->class");
	return 0;
}

static enum attestation_type parse_attestation_type(u8 *data) {
	if (attestation_eq(data, bitcoin_block_header_attestation))
		return ATTESTATION_BITCOIN_BLOCK_HEADER;
	else if (attestation_eq(data, pending_attestation))
		return ATTESTATION_PENDING;
	else if (attestation_eq(data, litecoin_block_header_attestation))
		return ATTESTATION_LITECOIN_BLOCK_HEADER;

	return ATTESTATION_UNKNOWN;
}

static int consume_attestation(struct cursor *cursor,
				   struct attestation *attestation) {
	u8 *tag = cursor->p;
	if (!consume_bytes(cursor, NULL, ATTESTATION_TAG_SIZE))
		return 0;

	attestation->type = parse_attestation_type(tag);

	int len;
	consume_varint(cursor, MAX_PAYLOAD_SIZE, &len);

	switch (attestation->type) {
	case ATTESTATION_PENDING:
		if (!consume_varbytes(cursor, MAX_PAYLOAD_SIZE-1, 1,
					&attestation->payload.data_len,
					&attestation->payload.data))
			return 0;
		break;
	case ATTESTATION_UNKNOWN:
		attestation->payload.data = cursor->p;
		attestation->payload.data_len = len;
		consume_bytes(cursor, NULL, len);
	break;
	case ATTESTATION_LITECOIN_BLOCK_HEADER:
	case ATTESTATION_BITCOIN_BLOCK_HEADER:
		if (!consume_varint(cursor, INT_MAX, &attestation->height))
			return 0;
		break;
	}

	return 1;
}


static int consume_timestamp(struct cursor *cursor, struct token *token,
				 ots_token_cb *cb);

static int consume_tag_or_attestation(struct cursor *cursor, u8 tag,
					  struct token *token, ots_token_cb *cb) {
	if (tag == 0x00) {
		if (!consume_attestation(cursor, &token->data.attestation))
			return 0;

		token->type = TOK_ATTESTATION;
		(*cb)(token);
	}
	else {
		if (!consume_op(cursor, tag, &token->data.op))
			return 0;
		token->type = TOK_OP;
		(*cb)(token);
		if (!consume_timestamp(cursor, token, cb))
			return 0;
	}
	return 1;
}

#define consume_tag(tag) \
	if (!consume_byte(cursor, &tag)) return 0

static int consume_timestamp(struct cursor *cursor, struct token *token,
			     ots_token_cb *cb)
{
	u8 tag;

	token->type = TOK_TIMESTAMP;
	(*cb)(token);

	consume_tag(tag);

	while (tag == 0xff) {
		consume_tag(tag);

		if (!consume_tag_or_attestation(cursor, tag, token, cb))
			return 0;

		consume_tag(tag);
	}

	if (!consume_tag_or_attestation(cursor, tag, token, cb)) {
		ots_errmsg = "failed to consume final timestamp tag or attestation";
		return 0;
	}


	return 1;
}

#undef consume_tag

static int consume_magic(struct cursor *cursor) {
	check_cursor(sizeof(proof_magic));
	return consume_bytes(cursor, proof_magic, sizeof(proof_magic));
}

static int consume_header(struct cursor *cursor, ots_token_cb *cb) {
	struct token tok;
	int ok = 0;
	u8 version;

	ok = consume_magic(cursor);
	if (!ok) return ok;

	ok = consume_version(cursor, &version);
	if (!ok) return ok;

	tok.type = TOK_VERSION;
	tok.data.version = version;
	(*cb)(&tok);

	return 1;
}

static int consume_crypto_op(struct cursor *cursor, struct token *token) {
	if (!parse_crypto_op(cursor, &token->data.op)) {
		cursor->state = OTS_ERR_CORRUPT;
		ots_errmsg = "expected file hash";
		return 0;
	}

	token->type = TOK_OP;

	return 1;
}

enum ots_parse_state parse_ots_proof(u8 *buf, int len, ots_token_cb *cb) {
	struct token token;
	struct cursor cursor_data;
	struct cursor *cursor = &cursor_data;
	init_cursor(cursor);

	cursor->p	= buf;
	cursor->end = buf + len;

	if (!consume_header(cursor, cb))
	return cursor->state;

	token.type = TOK_FILEHASH;
	(*cb)(&token);

	if (!consume_crypto_op(cursor, &token))
	return cursor->state;

	(*cb)(&token);

	if (!consume_timestamp(cursor, &token, cb))
	return cursor->state;

	cursor->state = OTS_PARSE_OK;
	return cursor->state;
}


const char *describe_parse_state(enum ots_parse_state state) {
	switch (state) {
	case OTS_PARSE_OK: return "success";
	case OTS_PARSE_PARTIAL: return "incomplete";
	case OTS_ERR_OVERFLOW: return "overflow";
	case OTS_ERR_CORRUPT: return "corrupt";
	case OTS_ERR_UNSUPPORTED_VERSION: return "unsupported version";
	}

	assert(!"unhandled parse_state");

	return "unknown";
}
