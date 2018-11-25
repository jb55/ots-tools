
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define STR_DETAIL(x) #x
#define STR(x) STR_DETAIL(x)
typedef unsigned char u8;

#define SUPPORTED_VERSION 0x1

// 160-bit hash
#define MIN_FILE_DIGEST_LENGTH 20 

// 256-bit hash
#define MAX_FILE_DIGEST_LENGTH 32 

#define peek_cursor(len) (cursor->p + (len) > cursor->end)

#define consume_tag(tag)                        \
    do {                                        \
        if (!consume_byte(cursor)) return 0;    \
        tag = *(cursor->p - 1);                 \
    }                                           \
    while (0)

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

enum op_class {
    OP_CLS_CRYPTO
};

enum crypto_op {
    OP_SHA1      = 0x02,
    OP_RIPEMD160 = 0x03,
    OP_SHA256    = 0x08,
    OP_KECCAK256 = 0x67,
};

enum ots_token_tag {
    TOK_VERSION,
    TOK_FILEHASH,
    TOK_OP,
};

union crypto_data {
    u8 sha256[32];
    u8 ripemd160[20];
    u8 sha1[20];
    u8 keccak256[32];
};

union ots_token_data {
    u8 version;
    union crypto_data crypto;
};

union op {
    enum crypto_op crypto;
};

struct ots_token {
    enum ots_token_tag tag;
    enum op_class class;
    union op op;
    union ots_token_data data;
};

typedef void (ots_token_cb)(struct ots_token *tok);

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

static char *errmsg = "no additional information";

static void init_cursor(struct cursor *cursor) {
    cursor->state = PARSE_PARTIAL;
    cursor->p = NULL;
    cursor->end = NULL;
};

static int consume_bytes(struct cursor *cursor, const u8 *bytes, int bytes_len) {
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

static int consume_byte(struct cursor *cursor) {
    return consume_bytes(cursor, NULL, 1);
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

static int consume_tag_or_attestation(struct cursor *cursor, u8 tag,
                                      struct ots_token *token) {
}

static int consume_timestamp(struct cursor *cursor, struct ots_token *token) {
    u8 tag;
    consume_tag(tag);

    while (tag == 0xff) {
        consume_tag(tag);
        consume_tag_or_attestation(cursor, tag, token);
        consume_tag(tag);
    }

    consume_tag_or_attestation(cursor, tag, token);
}

static int parse_crypto_op(struct cursor *cursor, struct ots_token *token) {
    u8 *digest;
    int digest_len;

    if (!consume_byte(cursor)) return 0;
    enum crypto_op op = (enum crypto_op)(*(cursor->p - 1));

    token->op.crypto = op;
    token->tag = TOK_OP;
    token->class = OP_CLS_CRYPTO;
    digest = cursor->p;

    #define consume_hash(typ) \
        digest_len = sizeof(token->data.crypto.typ); \
        if (!consume_bytes(cursor, NULL, digest_len)) return 0; \
        memcpy(token->data.crypto.typ, digest, digest_len); \
        return 1

    switch (op) {
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

/* static int consume_op(struct cursor *cursor, struct ots_token *token) { */
/*     return 0; */
/* } */

static int consume_magic(struct cursor *cursor) {
    check_cursor(sizeof(proof_magic));
    return consume_bytes(cursor, proof_magic, sizeof(proof_magic));
}

static int consume_header(struct cursor *cursor, ots_token_cb *cb) {
    struct ots_token tok;
    int ok = 0;
    u8 version;

    ok = consume_magic(cursor);
    if (!ok) return ok;

    ok = consume_version(cursor, &version);
    if (!ok) return ok;

    tok.tag = TOK_VERSION;
    tok.data.version = version;
    (*cb)(&tok);

    return 1;
}

static int consume_crypto_op(struct cursor *cursor, struct ots_token *token,
                             ots_token_cb *cb) {
    if (!parse_crypto_op(cursor, token)) {
        cursor->state = ERR_CORRUPT;
        errmsg = "expected file hash";
        return 0;
    }

    return 1;
}

static enum parse_state parse_ots_proof(u8 *buf, int len, ots_token_cb *cb) {
    struct ots_token token;
    struct cursor cursor_data;
    struct cursor *cursor = &cursor_data;
    init_cursor(cursor);

    cursor->p   = buf;
    cursor->end = buf + len;

    if (!consume_header(cursor, cb))
        return cursor->state; 

    token.tag = TOK_FILEHASH;
    (*cb)(&token);

    if (!consume_crypto_op(cursor, &token, cb))
        return cursor->state;

    (*cb)(&token);

    /* cursor->state = PARSE_OK; */
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
    return "unknown";
}

static void print_op_tag(enum op_class cls, union op op) {
    switch (cls) {
    case OP_CLS_CRYPTO:
        printf("%s", crypto_op_str(op.crypto));
    }
}

static void print_tag(struct ots_token *token) {
    switch (token->tag) {
    case TOK_VERSION:
        printf("version");
        return;
    case TOK_FILEHASH:
        printf("file_hash");
        return;
    case TOK_OP:
        print_op_tag(token->class, token->op);
        return;
    }

    printf("unknown");
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

static void print_op(struct ots_token *token) {
    static char buf[256];

    switch (token->class) {
    case OP_CLS_CRYPTO:
        encode_crypto_digest(token->op.crypto, token->data.crypto,
                             buf, sizeof(buf));
        printf("%s", buf);
        break;
    }
}

static void print_token(struct ots_token *token) {
    print_tag(token);
    printf(" ");

    switch (token->tag) {
    case TOK_VERSION:
        printf("%hhu", token->data.version);
        printf("\n");
        break;
    case TOK_OP:
        print_op(token);
        printf("\n");
        break;
    case TOK_FILEHASH:
        break;
    }

}

static void proof_cb(struct ots_token *token) {
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

    if (is_parse_error(res))
        printf("error: ");
    printf("%s, %s\n", describe_parse_state(res), errmsg);

    return 0;
}
