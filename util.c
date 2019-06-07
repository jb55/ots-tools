
#include <stdio.h>
#include <stdlib.h>

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
