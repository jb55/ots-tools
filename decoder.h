
#ifndef OTS_ENCODER_H
#define OTS_ENCODER_H

#include "short_types.h"
#include <stdbool.h>


enum decoder_state {
	DECODER_PARSE_OK,
	DECODER_PARSE_PARTIAL,
	DECODER_ERR_OVERFLOW,
	DECODER_ERR_CORRUPT,
	DECODER_ERR_UNSUPPORTED_VERSION,
};

struct cursor {
	const u8 *p;
	const u8 *end;
	int state;
};

extern char *decoder_errmsg;

bool cursor_eof(struct cursor *cursor);
void init_cursor(struct cursor *cursor);
int consume_bytes(struct cursor *cursor, const u8 *bytes, u32 bytes_len);
int consume_matching_byte(struct cursor *cursor, const u8 byte);
int consume_byte(struct cursor *cursor, u8 *byte);
int consume_varint(struct cursor *cursor, int max_len, int *res);
int consume_varbytes(struct cursor *cursor, int max_len, int min_len,
		     int *len, u8 **data);

#define peek_cursor(len) (cursor->p + (len) > cursor->end)

#define check_cursor(len)						\
	do {								\
		if (peek_cursor(len)) {					\
			decoder_errmsg = (char*)__PRETTY_FUNCTION__;	\
			cursor->state = DECODER_ERR_OVERFLOW;		\
			return 0;					\
		}							\
	} while(0)


#endif /* OTS_ENCODER_H */ 
