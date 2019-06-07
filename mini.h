
#ifndef OTS_MINI_H
#define OTS_MINI_H

#include <stdbool.h>
#include "ots.h"

enum mini_res {
	MINI_OK,
	MINI_ERR_UPGRADED_NOT_FOUND,
	MINI_ERR_PENDING_NOT_FOUND,
	MINI_ERR_OTS_PARSE_FAILED,
};

enum mini_tag {
	MINI_OP_SHA1      = 0x01,
	MINI_OP_RIPEMD160 = 0x02,
	MINI_OP_SHA256    = 0x03,
	MINI_OP_KECCAK256 = 0x04,
	MINI_OP_APPEND    = 0x0A,
	MINI_OP_PREPEND   = 0x0B,
	MINI_OP_REVERSE   = 0x10,
	MINI_OP_HEXLIFY   = 0x11,
	MINI_ATT_PEND     = 0x1A,
	MINI_ATT_UNK      = 0x1B,
	MINI_ATT_BTC      = 0x1C,
	MINI_ATT_LTC      = 0x1D,
};


struct token_search {
	bool done;
	bool upgraded;
	int tokindex;
	int att_token_start_candidate;
	int att_candidate_payload_size;
	int att_payload_size;
	int att_token_start;
};

struct mini_encoder {
	struct encoder *encoder;
	struct token_search *attest_loc;
	bool strip_filehash;
	bool has_ts;
};

struct mini_options {
	bool upgraded;
	bool strip_filehash;
};

enum decoder_state parse_ots_mini(const u8 *buf, int len, ots_token_cb *cb,
				  void *user_data);

enum mini_res encode_ots_mini(struct mini_options *opts, const u8 *proof,
			      int prooflen, u8 *buf, int bufsize, int *outlen);

extern const unsigned char ots_mini_magic[3];

#endif /* OTS_MINI_H */
