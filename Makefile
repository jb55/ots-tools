
CFLAGS=-std=c99 -O -Wall -Werror

ots-encode: ots-encode.c Makefile
	$(CC) $(CFLAGS) $< -o $@
