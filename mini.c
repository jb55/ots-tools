
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <assert.h>

#include "ots.h"
#include "ots_internal.h"
#include "mini.h"
#include "decoder.h"
#include "encoder.h"
#include "util.h"
#include "varint.h"

#define SUPPORTED_VERSION 0x1

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

static int ots_mini_write_tag(struct mini_encoder *e, u8 tag)
{
	if (e->has_ts) {
		tag |= 0x80;
	}

	writebuf(e->encoder, &tag, 1);
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
	case TOK_TIMESTAMP:
		if (!search->first_ts)
			break;

		debug("first ts\n");
		search->first_ts = false;
		search->end_header_index = search->tokindex;
		search->att_token_start = search->tokindex;
		search->att_payload_size = 0;

		break;

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
		if (token->data.op.class == OP_CLS_BINARY)
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
				bool *has_filehash)
{
	check_cursor(1);
	*ver = *(cursor->p)++;
	*has_filehash = !(*ver & 0x80);
	*ver = *ver & ~0x80;

	if (*ver != SUPPORTED_VERSION) {
		cursor->state = DECODER_ERR_UNSUPPORTED_VERSION;
		return 0;
	}

	return 1;
}


static int consume_mini_header(struct cursor *cursor,
			       ots_token_cb *cb, void *user_data,
			       bool *has_filehash)
{
	struct token tok = { .user_data = user_data };
	int ok = 0;
	u8 version;

	ok = consume_mini_magic(cursor);
	if (!ok) return ok;

	ok = consume_mini_version(cursor, &version, has_filehash);
	if (!ok) return ok;

	tok.type = TOK_VERSION;
	tok.data.version.number = version;
	tok.data.version.has_filehash = *has_filehash;
	(*cb)(&tok);

	return 1;
}

static u8 convert_mini_tag(u8 type)
{
	// clear ts bit just incase
	type &= ~0x80;

	switch ((enum mini_tag)type) {
	case MINI_OP_APPEND:    return OP_APPEND;
	case MINI_OP_PREPEND:   return OP_PREPEND;
	case MINI_OP_HEXLIFY:   return OP_HEXLIFY;
	case MINI_OP_REVERSE:   return OP_REVERSE;
	case MINI_OP_KECCAK256: return OP_KECCAK256;
	case MINI_OP_RIPEMD160: return OP_RIPEMD160;
	case MINI_OP_SHA1:      return OP_SHA1;
	case MINI_OP_SHA256:    return OP_SHA256;
	case MINI_ATT_BTC:      return ATTESTATION_BITCOIN_BLOCK_HEADER;
	case MINI_ATT_LTC:      return ATTESTATION_LITECOIN_BLOCK_HEADER;
	case MINI_ATT_PEND:     return ATTESTATION_PENDING;
	case MINI_ATT_UNK:      return ATTESTATION_UNKNOWN;
	}

	debug("op_tag %x\n", type);
	assert(!"convert_mini_op: unrecognized op tag");
}

static int parse_mini_crypto_op(struct cursor *cursor, struct op *op)
{
	u8 tag;

	if (!consume_byte(cursor, &tag))
		return 0;

	tag = convert_mini_tag(tag);
	return parse_crypto_op_body(cursor, tag, op);
}


static int consume_mini_crypto_op(struct cursor *cursor, struct token *token)
{

	if (!parse_mini_crypto_op(cursor, &token->data.op)) {
		cursor->state = DECODER_ERR_CORRUPT;
		decoder_errmsg = "expected file hash";
		return 0;
	}

	token->type = TOK_OP;

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

static bool is_op(enum mini_tag tag)
{
	switch (tag) {
	case MINI_OP_APPEND:
	case MINI_OP_PREPEND:
	case MINI_OP_HEXLIFY:
	case MINI_OP_REVERSE:
	case MINI_OP_KECCAK256:
	case MINI_OP_RIPEMD160:
	case MINI_OP_SHA1:
	case MINI_OP_SHA256:
		return true;
	case MINI_ATT_BTC:
	case MINI_ATT_LTC:
	case MINI_ATT_PEND:
	case MINI_ATT_UNK:
		return false;
	}

	return false;
}

/* static bool is_attestation(enum mini_tag tag) */
/* { */
/* 	switch (tag) { */
/* 	case MINI_OP_APPEND: */
/* 	case MINI_OP_PREPEND: */
/* 	case MINI_OP_HEXLIFY: */
/* 	case MINI_OP_REVERSE: */
/* 	case MINI_OP_KECCAK256: */
/* 	case MINI_OP_RIPEMD160: */
/* 	case MINI_OP_SHA1: */
/* 	case MINI_OP_SHA256: */
/* 		return false; */
/* 	case MINI_ATT_BTC: */
/* 	case MINI_ATT_LTC: */
/* 	case MINI_ATT_PEND: */
/* 	case MINI_ATT_UNK: */
/* 		return true; */
/* 	} */

/* 	return false; */
/* } */

static int consume_mini_timestamp(struct cursor *cursor,
				  struct token *token,
				  ots_token_cb *cb)
{
	u8 tag;
	u8 ots_tag;
	bool has_timestamp = false;

	while (!cursor_eof(cursor)) {
		consume_mini_tag(cursor, &tag, &has_timestamp);
		ots_tag = convert_mini_tag(tag);
		
		if (has_timestamp) {
			token->type = TOK_TIMESTAMP;
			(*cb)(token);
		}

		if (is_op(tag))  {
			consume_op(cursor, ots_tag, &token->data.op);
			token->type = TOK_OP;
			(*cb)(token);

		}
		else {
			consume_attestation_body(cursor, &token->data.attestation,
						 ots_tag);
			token->type = TOK_ATTESTATION;
			(*cb)(token);
		}
	}

	return 1;
}




enum decoder_state parse_ots_mini(const u8 *buf, int len,
				  ots_token_cb *cb,
				  void *user_data)
{
	struct token token = { .user_data = user_data };
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

		(*cb)(&token);
	}

	if (!consume_mini_timestamp(cursor, &token, cb))
		return cursor->state;

	cursor->state = DECODER_PARSE_OK;
	return cursor->state;
}


void ots_mini_encode_fn(struct token *token)
{
	struct mini_encoder *e = (struct mini_encoder*)token->user_data;
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

	int skip = e->attest_loc->end_header_index;

	if (*tokindex > skip && *tokindex < e->attest_loc->att_token_start_candidate) {
		(*tokindex)++;
		return;
	}

	switch (token->type) {
	case TOK_VERSION:
		ver = token->data.version.number;
		if (e->strip_filehash)
			ver |= 0x80;
		writebuf(e->encoder, ots_mini_magic, sizeof(ots_mini_magic));
		writebuf(e->encoder, &ver, 1);
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
			writebuf_varint(e->encoder, op->binary.data_len);
			writebuf(e->encoder, op->binary.bindata, op->binary.data_len);
			break;
		case OP_CLS_CRYPTO:
			if (op->crypto.datalen != 0) {
				debug("writing file hash\n");
				writebuf(e->encoder, op->crypto.cryptodata.sha1,
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

		data_len = token->data.attestation.raw_data_len;

		writebuf_varint(e->encoder, data_len);
		writebuf(e->encoder, token->data.attestation.raw_data, data_len);

		e->attest_loc->done = true;
		break;
	case TOK_FILEHASH:
		break;

	}

	(*tokindex)++;
}


enum mini_res encode_ots_mini(struct mini_options *opts, const u8 *proof,
			      int prooflen, u8 *buf, int bufsize, int *outlen)
{
	enum decoder_state res;

	struct token_search search = {
		.done = false,
		.first_ts = true,
		.att_token_start = -1,
		.att_candidate_payload_size = 0,
		.att_payload_size = 0,
		.upgraded = opts? opts->upgraded : false,
		.tokindex = 0,
	};

	struct encoder encoder = {
		.buf = buf,
		.buflen = bufsize,
		.cursor = buf,
	};

	struct mini_encoder mencoder = {
		.encoder = &encoder,
		.attest_loc = &search,
		.strip_filehash = opts? opts->strip_filehash : true,
		.has_ts = false,
	};

	res = parse_ots_proof(proof, prooflen, ots_mini_find, &search);
	search.first_ts = true;

	if (res != DECODER_PARSE_OK)
		return MINI_ERR_OTS_PARSE_FAILED;

	search.done = search.done || search.att_token_start_candidate != 0;

	if (!search.done) {
		if (search.upgraded)
			return MINI_ERR_UPGRADED_NOT_FOUND;
		else
			return MINI_ERR_PENDING_NOT_FOUND;
	}

	search.tokindex = 0;
	search.done = false;

	res = parse_ots_proof(proof, prooflen, ots_mini_encode_fn, &mencoder);
	if (res != DECODER_PARSE_OK)
		return MINI_ERR_OTS_PARSE_FAILED;

	*outlen = encoder.cursor - buf;

	return MINI_OK;
}
