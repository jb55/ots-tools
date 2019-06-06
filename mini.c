
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

#include "ots.h"
#include "mini.h"
#include "decoder.h"
#include "util.h"
#include "varint.h"

#define SUPPORTED_VERSION 0x1

static void fail(int err, const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(err);
}

const u8 ots_mini_magic[] = { 0x6f, 0x74, 0x73 };

// These have a pretty basic encoding
static u8 ots_mini_encode_op(const struct op *op)
{
	switch (op->class) {
	case OP_CLS_CRYPTO:
		switch (op->crypto.op) {
		case OP_SHA1:      return MINI_OP_SHA1;
		case OP_RIPEMD160: return MINI_OP_RIPEMD160;
		case OP_KECCAK256: return MINI_OP_KECCAK256;
		case OP_SHA256:    return MINI_OP_SHA256;
		}
		break;
	case OP_CLS_BINARY:
		switch (op->binary.op) {
		case OP_APPEND:  return MINI_OP_APPEND;
		case OP_PREPEND: return MINI_OP_PREPEND;
		}

		break;
	case OP_CLS_UNARY:
		switch (op->unary_op) {
		case OP_HEXLIFY: return MINI_OP_HEXLIFY;
		case OP_REVERSE: return MINI_OP_REVERSE;
		}
		break;
	}

	return 0;
}

static u8 ots_mini_encode_attestation_tag(const struct attestation *a)
{
	switch (a->type) {
	case ATTESTATION_BITCOIN_BLOCK_HEADER:  return MINI_ATT_BTC;
	case ATTESTATION_LITECOIN_BLOCK_HEADER: return MINI_ATT_LTC;
	case ATTESTATION_PENDING:               return MINI_ATT_PEND;
	case ATTESTATION_UNKNOWN:               return MINI_ATT_UNK;
	}

	return MINI_ATT_UNK;
}

static inline bool encode_overflows(struct encoder *encoder, int len)
{
	return encoder->cursor + len >= encoder->buf + encoder->buflen;
}

static void writebuf(struct encoder *encoder, const unsigned char *data, int len)
{
	if (encode_overflows(encoder, len))
		fail(4, "buffer overrun");
	memcpy(encoder->cursor, data, len);
	encoder->cursor += len;
}

static void writebuf_varint(struct encoder *encoder, uint64_t n)
{
	int len = varint_length(n);
	if (encode_overflows(encoder, len))
		fail(4, "buffer overrun");
	varint_write(encoder->cursor, n);
	encoder->cursor += len;
}

static int ots_mini_write_tag(struct encoder *e, u8 tag)
{
	if (e->has_ts) {
		tag |= 0x80;
	}

	writebuf(e, &tag, 1);
	e->has_ts = false;

	return 1;
}

// find the smallest attestation
void ots_mini_find(struct token *token)
{
	enum attestation_type typ;
	struct token_search *search =
		(struct token_search*)token->user_data;

	if (search->done)
		return;

	switch (token->type) {
	case TOK_ATTESTATION:
		typ = token->data.attestation.type;

		if (search->upgraded && typ != ATTESTATION_PENDING) {
			// finish right away if we're looking for
			// an upgraded proof
			// TODO: find smallest of multiple upgraded proofs?
			// the only way this could happen is if we're
			// committing to multiple blockchains

			search->att_token_start_candidate =
				search->att_token_start;
			search->done = true;
			return;
		}

		search->att_payload_size +=
			token->data.attestation.data_len;

		// we found a smaller attestation
		if (search->att_candidate_payload_size == 0 ||
		    search->att_payload_size <
		    search->att_candidate_payload_size)
		{
			debug("using payload %d, prev candidate %d\n",
			      search->att_payload_size,
			      search->att_candidate_payload_size);

			search->att_candidate_payload_size =
				search->att_payload_size;

			search->att_token_start_candidate =
				search->att_token_start;
		}

		search->att_token_start =
			search->tokindex+1;

		search->att_payload_size = 0;
		break;

	case TOK_OP:
		// very start of the file
		if (token->data.op.class == OP_CLS_CRYPTO &&
		    token->data.op.crypto.datalen != 0)
		{
			search->att_token_start = search->tokindex+1;
			search->att_payload_size = 0;
		}
		else if (token->data.op.class == OP_CLS_BINARY)
		{
			search->att_payload_size +=
				token->data.op.binary.data_len;
		}
		break;

	default:
		break;

	}

	// ops are 1 byte, but TS's are discounted due to our encoding
	if (token->type != TOK_TIMESTAMP)
		search->att_payload_size++;

	search->tokindex++;
}

static int consume_mini_magic(struct cursor *cursor) {
	return consume_bytes(cursor, ots_mini_magic, sizeof(ots_mini_magic));
}


static int consume_mini_version(struct cursor *cursor, u8 *ver,
				bool *has_filehash) {
	int ok;
	check_cursor(1);
	*ver = *cursor->p;
	*has_filehash = !(*ver & 0x80);
	*ver = *ver & ~0x80;

	ok = consume_matching_byte(cursor, SUPPORTED_VERSION);
	if (!ok) {
		cursor->state = DECODER_ERR_UNSUPPORTED_VERSION;
		return 0;
	}
	return ok;
}


static int consume_mini_header(struct cursor *cursor,
			       mini_ots_token_cb *cb, void *user_data,
			       bool *has_filehash)
{
	struct mini_token tok = { .user_data = user_data };
	int ok = 0;
	u8 version;

	ok = consume_mini_magic(cursor);
	if (!ok) return ok;

	ok = consume_mini_version(cursor, &version, has_filehash);
	if (!ok) return ok;

	tok.type = TOK_VERSION;
	tok.data.version = version;
	(*cb)(&tok);

	return 1;
}

static int parse_mini_op_class(u8 type, enum op_class *class)
{
	switch ((enum mini_binary_op)type) {
	case MINI_OP_APPEND:
	case MINI_OP_PREPEND:
		*class = OP_CLS_BINARY;
		return 1;
	}

	switch ((enum mini_unary_op)type) {
	case MINI_OP_HEXLIFY:
	case MINI_OP_REVERSE:
		*class = OP_CLS_UNARY;
		return 1;
	}

	switch ((enum mini_crypto_op)type) {
	case MINI_OP_KECCAK256:
	case MINI_OP_SHA1:
	case MINI_OP_SHA256:
	case MINI_OP_RIPEMD160:
		*class = OP_CLS_CRYPTO;
		return 1;
	}

	return 0;
}


static int parse_mini_crypto_op_payload(struct cursor *cursor,
					struct mini_op *op)
{
	u8 *digest;
	int digest_len;

	op->class = OP_CLS_CRYPTO;
	digest = cursor->p;

#define consume_hash(typ)					\
	digest_len = sizeof(op->crypto.cryptodata.typ);		\
	if (!consume_bytes(cursor, NULL, digest_len)) return 0;	\
	memcpy(op->crypto.cryptodata.typ, digest, digest_len);	\
	op->crypto.datalen = digest_len;			\
	return 1

	switch (op->crypto.op) {
	case MINI_OP_SHA1:      consume_hash(sha1);
	case MINI_OP_SHA256:    consume_hash(sha256);
	case MINI_OP_KECCAK256: consume_hash(keccak256);
	case MINI_OP_RIPEMD160: consume_hash(ripemd160);
	}

#undef consume_hash

	// backtrack on failure
	(cursor->p)--;

	return 0;
}



static int parse_mini_crypto_op(struct cursor *cursor,
				struct mini_op *op)
{
	u8 tag;

	if (!consume_byte(cursor, &tag))
		return 0;

	if (!parse_mini_op_class(tag, &op->class)) {
		decoder_errmsg = "could not parse op class";
		cursor->state = DECODER_ERR_CORRUPT;
		return 0;
	}

	if (op->class != OP_CLS_CRYPTO) {
		decoder_errmsg = "tried to parse crypto op, but is not crypto op class";
		cursor->state = DECODER_ERR_CORRUPT;
		return 0;
	}

	op->crypto.op = tag;

	return parse_mini_crypto_op_payload(cursor, op);
}

static int consume_mini_crypto_op(struct cursor *cursor,
				  struct mini_token *token)
{
	if (!parse_mini_crypto_op(cursor, &token->data.op)) {
		cursor->state = DECODER_ERR_CORRUPT;
		decoder_errmsg = "expected file hash";
		return 0;
	}

	token->type = TOK_OP;

	return 1;
}

static enum mini_attestation parse_mini_attestation_type(u8 *data) {
	if (attestation_eq(data, bitcoin_block_header_attestation))
		return MINI_ATT_BTC;
	else if (attestation_eq(data, pending_attestation))
		return MINI_ATT_PEND;
	else if (attestation_eq(data, litecoin_block_header_attestation))
		return MINI_ATT_LTC;

	return MINI_ATT_UNK;
}


static int consume_mini_attestation(struct cursor *cursor,
				    struct attestation *attestation)
{
	u8 *tag = cursor->p;
	if (!consume_bytes(cursor, NULL, ATTESTATION_TAG_SIZE))
		return 0;

	attestation->type = parse_mini_attestation_type(tag);

	int len;
	consume_varint(cursor, MAX_PAYLOAD_SIZE, &len);
	attestation->data_len = len;

	switch (attestation->type) {
	case ATTESTATION_PENDING:
		if (!consume_varbytes(cursor, MAX_PAYLOAD_SIZE-1, 1,
				      &attestation->data_len,
				      &attestation->data))
			return 0;
		break;
	case ATTESTATION_UNKNOWN:
		attestation->data = cursor->p;
		consume_bytes(cursor, NULL, len);
		break;
	case ATTESTATION_LITECOIN_BLOCK_HEADER:
	case ATTESTATION_BITCOIN_BLOCK_HEADER:
		if (!consume_varint(cursor, INT_MAX,
				    &attestation->height))
			return 0;
		attestation->data = (unsigned char*)&attestation->height;
		break;
	}

	return 1;
}


static int consume_mini_tag(struct cursor *cursor, u8 *tag,
			    bool *has_timestamp)
{
	if (!consume_byte(cursor, tag))
		return 0;

	*has_timestamp = *tag & 0x80;
	*tag = *tag & ~0x80;

	return 1;
}


static int parse_mini_binary_op_payload(struct cursor *cursor,
					struct mini_op *op)
{
	static const unsigned int min_len = 1;
	op->class = OP_CLS_BINARY;

	return consume_varbytes(cursor, MAX_RESULT_LENGTH, min_len,
				&op->binary.data_len,
				&op->binary.bindata);
}


static int consume_mini_op(struct cursor *cursor, u8 tag,
			   struct mini_op *op)
{
	if (!parse_mini_op_class(tag, &op->class)) {
		decoder_errmsg = "could not parse OP class";
		cursor->state = DECODER_ERR_CORRUPT;
		return 0;
	}

	switch (op->class) {
	case OP_CLS_CRYPTO:
		op->crypto.op = tag;
		op->crypto.datalen = 0;
		return 1;
		/* return parse_crypto_op_payload(cursor, op); */
	case OP_CLS_BINARY:
		op->binary.op = tag;
		return parse_mini_binary_op_payload(cursor, op);
	case OP_CLS_UNARY:
		op->unary_op = tag;
		return 1;
	}

	assert(!"unhandled op->class");
	return 0;
}


static int consume_mini_timestamp(struct cursor *cursor,
				  struct mini_token *token,
				  mini_ots_token_cb *cb);

static int consume_mini_tag_or_attestation(struct cursor *cursor,
					   u8 tag, struct mini_token *token,
					   mini_ots_token_cb *cb)
{
	if (tag == 0x00) {
		if (!consume_mini_attestation(cursor, &token->data.attestation))
			return 0;

		token->type = TOK_ATTESTATION;
		(*cb)(token);
	}
	else {
		if (!consume_mini_op(cursor, tag, &token->data.op))
			return 0;
		token->type = TOK_OP;
		(*cb)(token);
		if (!consume_mini_timestamp(cursor, token, cb))
			return 0;
	}
	return 1;
}

static int consume_mini_timestamp(struct cursor *cursor,
				  struct mini_token *token,
				  mini_ots_token_cb *cb)
{
	u8 tag;
	bool has_timestamp;

	token->type = TOK_TIMESTAMP;
	(*cb)(token);

	consume_mini_tag(cursor, &tag, &has_timestamp);

	while (tag == 0xff) {
		consume_mini_tag(cursor, &tag, &has_timestamp);

		if (!consume_mini_tag_or_attestation(cursor, tag, token, cb))
			return 0;

		consume_mini_tag(cursor, &tag, &has_timestamp);
	}

	if (!consume_mini_tag_or_attestation(cursor, tag, token, cb)) {
		decoder_errmsg = "failed to consume final timestamp tag or attestation";
		return 0;
	}


	return 1;
}




enum decoder_state parse_ots_mini(u8 *buf, int len,
				  mini_ots_token_cb *cb,
				  void *user_data)
{
	struct mini_token token = { .user_data = user_data };
	struct cursor cursor_data;
	struct cursor *cursor = &cursor_data;
	bool has_filehash = false;
	init_cursor(cursor);

	cursor->p   = buf;
	cursor->end = buf + len;

	if (!consume_mini_header(cursor, cb, user_data, &has_filehash))
		return cursor->state;

	if (has_filehash) {
		token.type = TOK_FILEHASH;
		(*cb)(&token);

		if (!consume_mini_crypto_op(cursor, &token))
			return cursor->state;
	}


	(*cb)(&token);

	if (!consume_mini_timestamp(cursor, &token, cb))
		return cursor->state;

	cursor->state = DECODER_PARSE_OK;
	return cursor->state;
}


void ots_mini_encode(struct token *token)
{
	struct encoder *e = (struct encoder*)token->user_data;
	int *tokindex = &e->attest_loc->tokindex;
	int data_len;

	u8 tag, ver;
	struct op *op;

	if (e->attest_loc->done)
		return;

	// >1 because we always need version and first crypto op
	// otherwise skip until we hit the first non-remote attestation

	// 3 = VERSION, FILEHASH, FIRST CRYPTO OP
	// TODO: this is a bit brittle if the format ever changes
	// TODO: we could leave off file_hash for really small timestamps?

	int skip = e->strip_filehash? 2 : 3;

	if (*tokindex >= skip && *tokindex < e->attest_loc->att_token_start_candidate) {
		(*tokindex)++;
		return;
	}

	switch (token->type) {
	case TOK_VERSION:
		ver = token->data.version;
		if (e->strip_filehash)
			ver |= 0x80;
		writebuf(e, ots_mini_magic, sizeof(ots_mini_magic));
		writebuf(e, &ver, 1);
		break;
	case TOK_TIMESTAMP:
		e->has_ts = true;
		break;
	case TOK_OP:
		op = &token->data.op;
		tag = ots_mini_encode_op(op);
		ots_mini_write_tag(e, tag);
		switch (op->class) {
		case OP_CLS_BINARY:
			writebuf(e, op->binary.bindata, op->binary.data_len);
			break;
		case OP_CLS_CRYPTO:
			if (op->crypto.datalen != 0) {
				debug("writing file hash\n");
				writebuf(e, op->crypto.cryptodata.sha1,
					 op->crypto.datalen);
			}
			break;
		case OP_CLS_UNARY:
			break;
		}
		break;
	case TOK_ATTESTATION:
		tag = ots_mini_encode_attestation_tag(&token->data.attestation);
		ots_mini_write_tag(e, tag);

		data_len = token->data.attestation.data_len;

		debug("attestation data_len: %d\n", data_len);
		writebuf_varint(e, data_len);

		writebuf(e, token->data.attestation.data, data_len);

		e->attest_loc->done = true;
		break;
	case TOK_FILEHASH:
		break;

	}

	(*tokindex)++;
}
