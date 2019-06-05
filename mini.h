
#ifndef OTS_MINI_H
#define OTS_MINI_H

#include <stdbool.h>

enum minitag {
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

struct token_search {
	bool done;
	bool upgraded;
	int tokindex;
	int att_token_start;
};

struct encoder {
	struct token_search *attest_loc;
	bool has_ts;
	unsigned char *buf;
	int buflen;
	unsigned char *cursor;
};

void ots_mini_find(struct token *token);
void ots_mini_encode(struct token *token);
extern const unsigned char ots_mini_magic[3];

#endif /* OTS_MINI_H */
