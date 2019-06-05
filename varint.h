
#ifndef OTS_VARINT_H
#define OTS_VARINT_H

#include <inttypes.h>

uint64_t varint_read(unsigned char *data, int *ok);
unsigned int varint_length(uint64_t data);
void varint_write(unsigned char *dest, uint64_t size);
unsigned int varint_peek_length(unsigned char chsize);

#endif /* PSBT_VARINT_H */
