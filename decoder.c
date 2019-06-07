
#include "decoder.h"
#include "short_types.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

char *decoder_errmsg = "no additional information";

void init_cursor(struct cursor *cursor) {
	cursor->state = DECODER_PARSE_PARTIAL;
	cursor->p = NULL;
	cursor->end = NULL;
};


bool cursor_eof(struct cursor *cursor)
{
	return cursor->p >= cursor->end;
}


int consume_bytes(struct cursor *cursor, const u8 *bytes,
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


int consume_matching_byte(struct cursor *cursor, const u8 byte) {
	u8 bytes[] = { byte };
	return consume_bytes(cursor, bytes, sizeof(bytes));
}

int consume_byte(struct cursor *cursor, u8 *byte) {
	if (!consume_bytes(cursor, NULL, 1))
		return 0;
	if (byte)
		*byte = *(cursor->p - 1);
	return 1;
}

const char *describe_parse_state(enum decoder_state state) {
	switch (state) {
	case DECODER_PARSE_OK: return "success";
	case DECODER_PARSE_PARTIAL: return "incomplete";
	case DECODER_ERR_OVERFLOW: return "overflow";
	case DECODER_ERR_CORRUPT: return "corrupt";
	case DECODER_ERR_UNSUPPORTED_VERSION: return "unsupported version";
	}

	assert(!"unhandled parse_state");

	return "unknown";
}

int consume_varint(struct cursor *cursor, int max_len, int *res)
{
	int shift = 0;
	*res = 0;
	u8 byte;

	while (1) {
		if (!consume_byte(cursor, &byte))
			return 0;

		*res |= (byte & 127) << shift;

		if (*res > max_len) {
			decoder_errmsg = "varint larger than max_len";
			return 0;
		}

		if (!(byte & 128))
			break;

		shift += 7;
	}

	return 1;
}


int consume_varbytes(struct cursor *cursor, int max_len,
		     int min_len, int *len, u8 **data)
{
	if (!consume_varint(cursor, max_len, len)) {
		cursor->state = DECODER_ERR_CORRUPT;
		return 0;
	}

	if (*len > max_len) {
		decoder_errmsg = "consume_varbytes: payload too large";
		cursor->state = DECODER_ERR_CORRUPT;
		return 0;
	}

	if (*len < min_len) {
		cursor->state = DECODER_ERR_CORRUPT;
		decoder_errmsg = "consume_varbytes: payload too small";
		return 0;
	}

	*data = (u8*)cursor->p;
	return consume_bytes(cursor, NULL, *len);
}
