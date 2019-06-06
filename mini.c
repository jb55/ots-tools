
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "ots.h"
#include "mini.h"
#include "util.h"
#include "varint.h"

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
