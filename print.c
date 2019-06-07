
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "ots.h"
#include "util.h"

#define MAX_PAYLOAD_SIZE 8192
#define MAX_RESULT_LENGTH 4096
#define MAX_TMPBUF_SIZE MAX_PAYLOAD_SIZE

static char tmpbuf[MAX_TMPBUF_SIZE];

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

static int hex_encode(const u8 *buf, size_t bufsize, char *dest, size_t dest_size) {
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

	debug("%x\n", op);
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

static void print_op(struct op *op, FILE *fd) {
	fprintf(fd, "%s", op_tag_str(op->class, op));

	switch (op->class) {
	case OP_CLS_CRYPTO:
		if (op->crypto.datalen != 0) {
			encode_crypto_digest(op->crypto.op,
					     op->crypto.cryptodata,
					     tmpbuf, sizeof(tmpbuf));
			fprintf(fd, " %s", tmpbuf);
		}
		break;
	case OP_CLS_BINARY:
		hex_encode(op->binary.bindata, op->binary.data_len, tmpbuf, sizeof(tmpbuf));
		fprintf(fd, " %s", tmpbuf);
		break;
	case OP_CLS_UNARY:
		break;
	}
}


static void print_attestation(struct attestation *attestation, FILE *fd) {
	const char *name = attestation_type_name(attestation->type);
	fprintf(fd, "%s", name);
	switch (attestation->type) {
	case ATTESTATION_PENDING:
		fprintf(fd, " %.*s\n", attestation->data_len,
			   attestation->data);
		break;
	case ATTESTATION_LITECOIN_BLOCK_HEADER:
	case ATTESTATION_BITCOIN_BLOCK_HEADER:
		fprintf(fd, " height %d\n", attestation->height);
		break;
	case ATTESTATION_UNKNOWN:
		hex_encode(attestation->data, attestation->data_len,
				   tmpbuf, MAX_TMPBUF_SIZE);
		fprintf(fd, "unknown %s\n", tmpbuf);
	}
}

static void print_indents(int indent, FILE *fd) {
	for (int i = 0; i < indent; i++)
		fprintf(fd, "|    ");
}

void print_token(struct token *token, FILE *fd) {
	static int indent = 0;
	static bool at_fork = false;

	if (!at_fork) {
		print_indents(indent, fd);
	}
	else
		at_fork = false;

	switch (token->type) {
	case TOK_VERSION:
		fprintf(fd, "version %hhu", token->data.version.number);
		if (!token->data.version.has_filehash)
			fprintf(fd, " (without filehash)");
		fprintf(fd, "\n");
		break;
	case TOK_OP:
		print_op(&token->data.op, fd);
		fprintf(fd, "\n");
		break;
	case TOK_FILEHASH:
		fprintf(fd, "file_hash ");
		break;
	case TOK_ATTESTATION:
		indent--;
		fprintf(fd, "attestation ");
		print_attestation(&token->data.attestation, fd);
		break;
	case TOK_TIMESTAMP:
		fprintf(fd, "|\n");
		print_indents(indent, fd);
		indent++;
		fprintf(fd, "\\--> ");
		/* print_indents(indent, fd); */
		at_fork = true;
		break;
	}

}
