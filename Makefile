
CFLAGS=-std=c99 -ggdb -O -Wall -Werror

ots-encode: ots-encode.c Makefile
	$(CC) $(CFLAGS) $< -o $@
