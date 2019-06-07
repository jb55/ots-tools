
#ifndef OTS_UTIL_H
#define OTS_UTIL_H

#include <stdio.h>

#ifdef DEBUG
	#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
	#define debug(...)
#endif


typedef unsigned char u8;

void fail(int err, const char *msg);
int read_fd(FILE *fd, unsigned char *buf, size_t buflen, size_t *written);
int read_file_or_stdin(const char *filename, unsigned char *buf, size_t buflen,
		       size_t *written);

bool hex_decode(const char *str, size_t slen, void *buf, size_t bufsize);

#endif /* OTS_UTIL_H */
