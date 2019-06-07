
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "encoder.h"
#include "util.h"
#include "varint.h"

static inline bool encode_overflows(struct encoder *encoder, int len)
{
	return encoder->cursor + len >= encoder->buf + encoder->buflen;
}


void writebuf(struct encoder *encoder, const unsigned char *data, int len)
{
	if (encode_overflows(encoder, len))
		fail(4, "buffer overrun");
	memcpy(encoder->cursor, data, len);
	encoder->cursor += len;
}

void writebuf_varint(struct encoder *encoder, uint64_t n)
{
	int len = varint_length(n);
	if (encode_overflows(encoder, len))
		fail(4, "buffer overrun");
	varint_write(encoder->cursor, n);
	encoder->cursor += len;
}
