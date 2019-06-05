
#ifndef OTS_H
#define OTS_H

enum ots_parse_state {
    OTS_PARSE_OK,
    OTS_PARSE_PARTIAL,
    OTS_ERR_OVERFLOW,
    OTS_ERR_CORRUPT,
    OTS_ERR_UNSUPPORTED_VERSION,
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
    unsigned char sha256[32];
    unsigned char ripemd160[20];
    unsigned char sha1[20];
    unsigned char keccak256[32];
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
            unsigned char *data;
            int data_len;
        } binary;
        enum unary_op unary_op;
    };
};

struct attestation {
    enum attestation_type type;
    union {
        struct {
            unsigned char *data;
            int data_len;
        } payload;
        int height;
    };
};

struct token {
    enum token_type type;
    union {
        unsigned char version;
        struct op op;
        struct attestation attestation;
    } data;
};

typedef void (ots_token_cb)(struct token *tok);

const char *describe_parse_state(enum ots_parse_state state);
enum ots_parse_state parse_ots_proof(unsigned char *buf, int len, ots_token_cb *cb);
extern char *ots_errmsg;

#endif /* OTS_H */
