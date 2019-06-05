
#include <stdio.h>
#include <stdbool.h>

#include "ots.h"
#include "util.h"

enum minitypes {
	MINI_FILEHASH = 0x00
};

enum minitags {
	MINI_OP_SHA1      = 0x01,
	MINI_OP_RIPEMD160 = 0x02,
	MINI_OP_SHA256    = 0x03,
	MINI_OP_KECCAK256 = 0x04,

	MINI_OP_APPEND    = 0x0A,
	MINI_OP_PREPEND   = 0x0B,

	MINI_OP_REVERSE   = 0x10,
	MINI_OP_HEXLIFY   = 0x11,

	MINI_ATT_PEND = 0x1A,
	MINI_ATT_UNK  = 0x1B,
	MINI_ATT_BTC  = 0x1C,
	MINI_ATT_LTC  = 0x1D,

};

static FILE *encode_fd;
static const u8 succinct_proof_magic[] = { 0x6f, 0x74 };

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

static void ots_mini_write_tag(u8 tag, bool *has_ts)
{
	if (*has_ts)
		tag |= 0x80;
	fwrite(&tag, 1, 1, encode_fd);
	*has_ts = false;
}

static void ots_mini_encode(struct token *token)
{
	u8 tag;
	static bool has_ts = false;

	switch (token->type) {
	case TOK_VERSION:
		fwrite(succinct_proof_magic, sizeof(succinct_proof_magic), 1, encode_fd);
		break;
	case TOK_TIMESTAMP:
		has_ts = true;
		break;
	case TOK_OP:
		tag = ots_mini_encode_op(&token->data.op);
		ots_mini_write_tag(tag, &has_ts);
		break;
	case TOK_ATTESTATION:
		tag = ots_mini_encode_attestation_tag(&token->data.attestation);
		ots_mini_write_tag(tag, &has_ts);
		break;
	case TOK_FILEHASH:
		break;
	}

}

/* static void ots_mini_decode(u8 *data, int data_len) */
/* { */
/* } */


int main(int argc, char *argv[])
{

	size_t len = 0;
	enum ots_parse_state res;

	if (argc != 2)
		return 1;

	u8 *proof = file_contents(argv[1], &len);
	encode_fd = stdout;
	res = parse_ots_proof(proof, len, ots_mini_encode);

	if (res != OTS_PARSE_OK) {
		printf("error: %s, %s\n", describe_parse_state(res), ots_errmsg);
		return 1;
	}

	free(proof);

	return 0;
}
