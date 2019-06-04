
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "ots.h"
#include "util.h"

static FILE *encode_fd;
#define UNUSED __attribute__((__unused__))

#define MAX_PAYLOAD_SIZE 8192
#define MAX_RESULT_LENGTH 4096
#define MAX_TMPBUF_SIZE MAX_PAYLOAD_SIZE

static char tmpbuf[MAX_TMPBUF_SIZE];
typedef unsigned char u8;

static inline u8 hexdigit( char hex ) {
	return (hex <= '9') ? hex - '0' : toupper(hex) - 'A' + 10 ;
}

static char hexchar(unsigned int val)
{
	if (val < 10)
		return '0' + val;
	if (val < 16)
		return 'a' + val - 10;
	assert(!"hexchar invalid val");
}

static int hex_encode(u8 *buf, size_t bufsize, char *dest, size_t dest_size) {
	size_t i;

	if (dest_size < bufsize * 2 + 1)
		return 0;

	for (i = 0; i < bufsize; i++) {
		unsigned int c = buf[i];
		*(dest++) = hexchar(c >> 4);
		*(dest++) = hexchar(c & 0xF);
	}
	*dest = '\0';

	return 1;
}


static int encode_crypto_digest(enum crypto_op op, union crypto_data crypto,
								char *buf, size_t bufsize) {
#define encode_digest(typ)										\
	hex_encode(crypto.typ, sizeof(crypto.typ), buf, bufsize);	\
	return 1

	switch (op) {
	case OP_SHA1:	   encode_digest(sha1);
	case OP_SHA256:	   encode_digest(sha256);
	case OP_RIPEMD160: encode_digest(ripemd160);
	case OP_KECCAK256: encode_digest(keccak256);
	}

#undef encode_digest

	return 0;
}


static const char *crypto_op_str(enum crypto_op op) {
	switch (op) {
	case OP_SHA1: return "sha1";
	case OP_SHA256: return "sha256";
	case OP_KECCAK256: return "keccak256";
	case OP_RIPEMD160: return "ripemd160";
	}

	assert(!"unhandled crypto_op_str");
	return NULL;
}

static const char *binary_op_str(enum binary_op op) {
	switch (op) {
	case OP_APPEND: return "append";
	case OP_PREPEND: return "prepend";
	}

	assert(!"unhandled binary_op_str");
	return NULL;
}

static const char *unary_op_str(enum unary_op op) {
	switch (op) {
	case OP_HEXLIFY: return "hexlify";
	case OP_REVERSE: return "reverse";
	}

	assert(!"unhandled unary_op_str");
	return NULL;
}


static const char *op_tag_str(enum op_class cls, struct op *op) {
	switch (cls) {
	case OP_CLS_CRYPTO: return crypto_op_str(op->crypto.op);
	case OP_CLS_BINARY: return binary_op_str(op->binary.op);
	case OP_CLS_UNARY:	return unary_op_str(op->unary_op);
	}

	assert(!"unhandled op_class in op_tag_str");
	return NULL;
}


static char *attestation_type_name(enum attestation_type type) {
	switch (type) {
	case ATTESTATION_BITCOIN_BLOCK_HEADER:
		return "bitcoin";
	case ATTESTATION_LITECOIN_BLOCK_HEADER:
		return "litecoin";
	case ATTESTATION_PENDING:
		return "pending";
	case ATTESTATION_UNKNOWN:
		return "unknown";
	}

	assert(!"attestation type not handled");
	return "impossible";
}

static void proof_encode(struct token *token) {
	switch (token->type) {
	case TOK_VERSION:
		fwrite(succinct_proof_magic, sizeof(succinct_proof_magic), 1, encode_fd);
		break;
	case TOK_TIMESTAMP:
		fwrite("\x0", 1, 1, encode_fd);
		break;
	case TOK_OP:
		break;
	case TOK_ATTESTATION:
		break;
	case TOK_FILEHASH:
		break;
	}

}

static void print_op(struct op *op) {
	printf("%s", op_tag_str(op->class, op));

	switch (op->class) {
	case OP_CLS_CRYPTO:
		if (op->crypto.data.sha1[0] != 0) {
			encode_crypto_digest(op->crypto.op, op->crypto.data, tmpbuf, sizeof(tmpbuf));
			printf(" %s", tmpbuf);
		}
		break;
	case OP_CLS_BINARY:
		hex_encode(op->binary.data, op->binary.data_len, tmpbuf, sizeof(tmpbuf));
		printf(" %s", tmpbuf);
		break;
	case OP_CLS_UNARY:
		break;
	}
}


void print_attestation(struct attestation *attestation) {
	const char *name = attestation_type_name(attestation->type);
	printf("%s", name);
	switch (attestation->type) {
	case ATTESTATION_PENDING:
		printf(" %.*s\n", attestation->payload.data_len,
			   attestation->payload.data);
		break;
	case ATTESTATION_LITECOIN_BLOCK_HEADER:
	case ATTESTATION_BITCOIN_BLOCK_HEADER:
		printf(" height %d\n", attestation->height);
		break;
	case ATTESTATION_UNKNOWN:
		hex_encode(attestation->payload.data, attestation->payload.data_len,
				   tmpbuf, MAX_TMPBUF_SIZE);
		printf("unknown %s\n", tmpbuf);
	}
}

static void print_token(struct token *token) {
	switch (token->type) {
	case TOK_VERSION:
		printf("version %hhu", token->data.version);
		printf("\n");
		break;
	case TOK_OP:
		print_op(&token->data.op);
		printf("\n");
		break;
	case TOK_FILEHASH:
		printf("file_hash ");
		break;
	case TOK_ATTESTATION:
		printf("attestation ");
		print_attestation(&token->data.attestation);
		printf("\n");
		break;
	case TOK_TIMESTAMP:
		printf("  ");
		break;
	}

}

static void proof_cb(struct token *token) {
	print_token(token);
}



int main(int argc UNUSED, char *argv[])
{
	size_t len = 0;
	enum ots_parse_state res;

	(void)proof_cb;
	(void)proof_encode;
	u8 *proof = file_contents(argv[1], &len);
	encode_fd = stdout;
	res = parse_ots_proof(proof, len, proof_cb);

	if (res != OTS_PARSE_OK) {
		printf("error: %s, %s\n", describe_parse_state(res), ots_errmsg);
		return 1;
	}

	free(proof);

	return 0;
}
