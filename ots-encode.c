
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>

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

static char tmpbuf[MAX_TMPBUF_SIZE];

#define memeq(d, d2, len) (memcmp(d, d2, len) == 0)

#define attestation_eq(a1, a2) memeq(a1, a2, ATTESTATION_TAG_SIZE)

#define peek_cursor(len) (cursor->p + (len) > cursor->end)

#define check_cursor(len)                           \
    do {                                            \
        if (peek_cursor(len)) {    \
            errmsg = "in " STR(__func__);    \
            cursor->state = ERR_OVERFLOW;           \
            return 0;                               \
        }                                           \
    } while(0)

enum parse_state {
    PARSE_OK,
    PARSE_PARTIAL,
    ERR_OVERFLOW,
    ERR_CORRUPT,
    ERR_UNSUPPORTED_VERSION,
};

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
    u8 sha256[32];
    u8 ripemd160[20];
    u8 sha1[20];
    u8 keccak256[32];
};

struct op {
    enum op_class class;
    union {
        struct {
            enum crypto_op op;
            union crypto_data data;
        } crypto;
        struct {
            enum binary_op op;
            u8 *data;
            int data_len;
        } binary;
        enum unary_op unary_op;
    };
};

struct attestation {
    enum attestation_type type;
    union {
        struct {
            u8 *data;
            int data_len;
        } payload;
        int height;
    };
};

struct token {
    enum token_type type;
    union {
        u8 version;
        struct op op;
        struct attestation attestation;
    } data;
};

typedef void (ots_token_cb)(struct token *tok);

struct cursor {
    u8 *p;
    u8 *end;
    enum parse_state state;
};

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


static char *errmsg = "no additional information";

static void init_cursor(struct cursor *cursor) {
    cursor->state = PARSE_PARTIAL;
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
        cursor->state = ERR_UNSUPPORTED_VERSION;
        return 0;
    }
    return ok;
}

static int parse_op_class(u8 type, enum op_class *class) {
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

static int parse_crypto_op_payload(struct cursor *cursor, struct op *op) {
    u8 *digest;
    int digest_len;

    op->class = OP_CLS_CRYPTO;
    digest = cursor->p;

#define consume_hash(typ)                                       \
    digest_len = sizeof(op->crypto.data.typ);        \
    if (!consume_bytes(cursor, NULL, digest_len)) return 0;     \
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

static int parse_crypto_op(struct cursor *cursor, struct op *op) {
    u8 tag;

    if (!consume_byte(cursor, &tag)) return 0;
    if (!parse_op_class(tag, &op->class)) {
        errmsg = "could not parse op class";
        cursor->state = ERR_CORRUPT;
        return 0;
    }

    if (op->class != OP_CLS_CRYPTO) {
        errmsg = "tried to parse crypto op, but is not crypto op class";
        cursor->state = ERR_CORRUPT;
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
            errmsg = "varint larger than max_len";
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
        cursor->state = ERR_CORRUPT;
        return 0;
    }

    if (*len > max_len) {
        errmsg = "consume_varbytes: payload too large";
        cursor->state = ERR_CORRUPT;
        return 0;
    }

    if (*len < min_len) {
        cursor->state = ERR_CORRUPT;
        errmsg = "consume_varbytes: payload too small";
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
        errmsg = "could not parse OP class";
        cursor->state = ERR_CORRUPT;
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
                             ots_token_cb *cb) {
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

    if (!consume_tag_or_attestation(cursor, tag, token, cb))
        return 0;


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

static int consume_crypto_op(struct cursor *cursor, struct token *token,
                             ots_token_cb *cb) {
    if (!parse_crypto_op(cursor, &token->data.op)) {
        cursor->state = ERR_CORRUPT;
        errmsg = "expected file hash";
        return 0;
    }

    token->type = TOK_OP;

    return 1;
}

static enum parse_state parse_ots_proof(u8 *buf, int len, ots_token_cb *cb) {
    struct token token;
    struct cursor cursor_data;
    struct cursor *cursor = &cursor_data;
    init_cursor(cursor);

    cursor->p   = buf;
    cursor->end = buf + len;

    if (!consume_header(cursor, cb))
        return cursor->state;

    token.type = TOK_FILEHASH;
    (*cb)(&token);

    if (!consume_crypto_op(cursor, &token, cb))
        return cursor->state;

    (*cb)(&token);

    if (!consume_timestamp(cursor, &token, cb))
        return cursor->state;

    cursor->state = PARSE_OK;
    return cursor->state;
}


static u8 *file_contents(const char *filename, size_t *length) {
    FILE *f = fopen(filename, "rb");
    u8 *buffer;

    if (!f) {
        fprintf(stderr, "Unable to open %s for reading\n", filename);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *length = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    buffer = malloc(*length+1);
    *length = fread(buffer, 1, *length, f);
    fclose(f);

    return buffer;
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
    case OP_CLS_UNARY:  return unary_op_str(op->unary_op);
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
    #define encode_digest(typ) \
        hex_encode(crypto.typ, sizeof(crypto.typ), buf, bufsize); \
        return 1

    switch (op) {
    case OP_SHA1:      encode_digest(sha1);
    case OP_SHA256:    encode_digest(sha256);
    case OP_RIPEMD160: encode_digest(ripemd160);
    case OP_KECCAK256: encode_digest(keccak256);
    }

    #undef encode_digest

    return 0;
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

static void print_attestation(struct attestation *attestation) {
    const char *name = attestation_type_name(attestation->type);
    printf("%s", name);
    switch (attestation->type) {
    case ATTESTATION_PENDING:
        printf(" %.*s\n", attestation->payload.data_len,
               attestation->payload.data);
        break;
    case ATTESTATION_LITECOIN_BLOCK_HEADER:
    case ATTESTATION_BITCOIN_BLOCK_HEADER:
        printf(" %d\n", attestation->height);
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

static const char *describe_parse_state(enum parse_state state) {
    switch (state) {
    case PARSE_OK: return "success";
    case PARSE_PARTIAL: return "incomplete";
    case ERR_OVERFLOW: return "overflow";
    case ERR_CORRUPT: return "corrupt";
    case ERR_UNSUPPORTED_VERSION: return "unsupported version";
    }

    assert(!"unhandled parse_state");

    return "unknown";
}

static int is_parse_error(enum parse_state state) {
    return state != PARSE_OK;
}

int main(int argc, char *argv[])
{
    size_t len = 0;
    enum parse_state res;

    u8 *proof = file_contents(argv[1], &len);
    res = parse_ots_proof(proof, len, proof_cb);

    if (is_parse_error(res)) {
        printf("error: %s, %s\n", describe_parse_state(res), errmsg);
        return 1;
    }

    return 0;
}
