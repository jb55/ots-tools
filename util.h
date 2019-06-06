
#ifndef OTS_UTIL_H
#define OTS_UTIL_H

#include <stdlib.h>

#ifdef DEBUG
	#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
	#define debug(...)
#endif


typedef unsigned char u8;

unsigned char *file_contents(const char *filename, size_t *length);


#endif /* OTS_UTIL_H */
