
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int read_fd(FILE *fd, unsigned char *buf, size_t buflen, size_t *written)
{
	unsigned char *p = buf;
	int len = 0;
	*written = 0;

	do {
		len = fread(p, 1, 4096, fd);
		*written += len;
		p += len;
		if (p > buf + buflen)
			return 0;
	} while (len == 4096);

	return 1;
}


int read_file_or_stdin(const char *filename, unsigned char *buf, size_t buflen,
		       size_t *written)
{
	FILE *file = NULL;
	if (filename != NULL) {
		file = fopen(filename, "rb");
		int ok = read_fd(file, buf, buflen, written);
		fclose(file);
		return ok;
	}
	else {
		return read_fd(stdin, buf, buflen, written);
	}
}

void fail(int err, const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(err);
}

static bool char_to_hex(unsigned char *val, char c)
{
	if (c >= '0' && c <= '9') {
		*val = c - '0';
		return true;
	}
 	if (c >= 'a' && c <= 'f') {
		*val = c - 'a' + 10;
		return true;
	}
 	if (c >= 'A' && c <= 'F') {
		*val = c - 'A' + 10;
		return true;
	}
	return false;
}

bool hex_decode(const char *str, size_t slen, void *buf, size_t bufsize)
{
	unsigned char v1, v2;
	unsigned char *p = buf;

	while (slen > 1) {
		if (!char_to_hex(&v1, str[0]) || !char_to_hex(&v2, str[1]))
			return false;
		if (!bufsize)
			return false;
		*(p++) = (v1 << 4) | v2;
		str += 2;
		slen -= 2;
		bufsize--;
	}
	return slen == 0 && bufsize == 0;
}
