

#define _DEFAULT_SOURCE

#include <limits.h>
#include <endian.h>
#include <string.h>

#include "varint.h"

static const unsigned int MAX_SERIALIZE_SIZE = 0x02000000;

unsigned int varint_peek_length(unsigned char chsize) {
	if (chsize < 253)
		return sizeof(unsigned char);
	else if (chsize == 253)
		return sizeof(unsigned char) + sizeof(unsigned short);
	else if (chsize == 254)
		return sizeof(unsigned char) + sizeof(unsigned int);
	else
		return sizeof(unsigned char) + sizeof(uint64_t);
}

unsigned int varint_length(uint64_t data) {
	if (data < 253)
		return sizeof(unsigned char);
	else if (data <= USHRT_MAX)
		return sizeof(unsigned char) + sizeof(unsigned short);
	else if (data <= UINT_MAX)
		return sizeof(unsigned char) + sizeof(unsigned int);
	else
		return sizeof(unsigned char) + sizeof(uint64_t);
}

inline static void serialize_u8(unsigned char *dest, unsigned char data) {
	*dest = data;
}

inline static void serialize_u16(unsigned char *dest, unsigned short data) {
	data = htole16(data);
	memcpy(dest, &data, sizeof(data));
}

inline static void serialize_u32(unsigned char *dest, unsigned int data) {
	data = htole32(data);
	memcpy(dest, &data, sizeof(data));
}

inline static void serialize_u64(unsigned char *dest, uint64_t data) {
	data = htole64(data);
	memcpy(dest, &data, sizeof(data));
}

inline static unsigned char deserialize_u8(unsigned char *src) {
	return *src;
}

inline static unsigned short deserialize_u16(unsigned char *src) {
	unsigned short data;
	memcpy(&data, src, sizeof(data));
	return le16toh(data);
}

inline static unsigned int deserialize_u32(unsigned char *src) {
	unsigned int data;
	memcpy(&data, src, sizeof(data));
	return le32toh(data);
}

inline static uint64_t deserialize_u64(unsigned char *src) {
	uint64_t data;
	memcpy(&data, src, sizeof(data));
	return le64toh(data);
}

void varint_write(unsigned char *dest, uint64_t size)
{
	if (size < 253) {
		serialize_u8(dest, size);
	}
	else if (size <= USHRT_MAX) {
		serialize_u8(dest, 253);
		serialize_u16(dest, size);
	}
	else if (size <= UINT_MAX) {
		serialize_u8(dest, 254);
		serialize_u32(dest, size);
	}
	else {
		serialize_u8(dest, 255);
		serialize_u64(dest, size);
	}
}



#define READERR(msg) \
	{*ok = 0; return -1;}

uint64_t varint_read(unsigned char *data, int *ok) {
	unsigned char *p = data;
	unsigned char chsize = deserialize_u8(p++);
	uint64_t ret_size = 0;

	if (chsize < 253) {
		ret_size = chsize;
	}

	else if (chsize == 253) {
		ret_size = deserialize_u16(p);
		if (ret_size < 253)
			READERR("non-canonical varint_read()");

	}
	else if (chsize == 254) {
		ret_size = deserialize_u32(p);

		if (ret_size < 0x10000u)
			READERR("non-canonical varint_read()");
	}
	else {
		ret_size = deserialize_u64(p);
		if (ret_size < 0x100000000ULL)
			READERR("non-canonical varint_read()");
	}

	if (ret_size > (uint64_t)MAX_SERIALIZE_SIZE)
		READERR("non-canonical varint_read()");

	return ret_size;
}
