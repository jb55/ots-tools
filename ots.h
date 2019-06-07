
#ifndef OTS_H
#define OTS_H

#include <string.h>
#include "decoder.h"

#define ATTESTATION_TAG_SIZE 8
#define MAX_RESULT_LENGTH 4096
#define MAX_PAYLOAD_SIZE 8192

#define memeq(d, d2, len) (memcmp(d, d2, len) == 0)
#define attestation_eq(a1, a2) memeq(a1, a2, ATTESTATION_TAG_SIZE)

enum attestation_type {
	ATTESTATION_PENDING,
	ATTESTATION_BITCOIN_BLOCK_HEADER,
	ATTESTATION_LITECOIN_BLOCK_HEADER,
	ATTESTATION_UNKNOWN,
};

enum op_class {
	OP_CLS_CRYPTO,
	OP_CLS_BINARY,
	OP_CLS_UNARY,
};

enum crypto_op {
	OP_SHA1      = 0x02,
	OP_RIPEMD160 = 0x03,
	OP_SHA256    = 0x08,
	OP_KECCAK256 = 0x67,
};

enum binary_op {
	OP_APPEND  = 0xF0,
	OP_PREPEND = 0xF1
};

enum unary_op {
	OP_REVERSE = 0xF2,
	OP_HEXLIFY = 0xF3
};

enum token_type {
	TOK_VERSION,
	TOK_FILEHASH,
	TOK_OP,
	TOK_TIMESTAMP,
	TOK_ATTESTATION,
};

union crypto_data {
	unsigned char sha256[32];
	unsigned char ripemd160[20];
	unsigned char sha1[20];
	unsigned char keccak256[32];
};

struct crypto {
	int datalen;
	enum crypto_op op;
	union crypto_data cryptodata;
};

struct op {
	enum op_class class;
	union {
		struct crypto crypto;
		struct {
			enum binary_op op;
			unsigned char *bindata;
			int data_len;
		} binary;
		enum unary_op unary_op;
	};
};

struct attestation {
	enum attestation_type type;
	const unsigned char *data;
	const u8 *raw_data;
	int raw_data_len;
	int height;
	int data_len;
};

struct version {
	unsigned char number;
	bool has_filehash;
};

struct token {
	void *user_data;
	enum token_type type;
	union {
		struct version version;
		struct op op;
		struct attestation attestation;
	} data;
};


extern const u8 ots_proof_magic[31];
extern const u8 pending_attestation[ATTESTATION_TAG_SIZE];
extern const u8 bitcoin_block_header_attestation[ATTESTATION_TAG_SIZE];
extern const u8 litecoin_block_header_attestation[ATTESTATION_TAG_SIZE];



typedef void (ots_token_cb)(struct token *tok);

const char *describe_parse_state(enum decoder_state state);

enum decoder_state parse_ots_proof(const unsigned char *buf, int len,
				   ots_token_cb *cb, void *user_data);

extern char *ots_errmsg;

#endif /* OTS_H */
