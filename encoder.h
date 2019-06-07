
#ifndef OTS_ENCODER_H
#define OTS_ENCODER_H

#include <inttypes.h>

struct encoder {
	unsigned char *buf;
	int buflen;
	unsigned char *cursor;
};

void writebuf(struct encoder *encoder, const unsigned char *data, int len);
void writebuf_varint(struct encoder *encoder, uint64_t n);

#endif /* OTS_ENCODER_H */
