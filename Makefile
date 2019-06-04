
CFLAGS=-std=c99 -ggdb -O -Wall -Wextra -Werror

OBJS=ots.o

ots-encode: ots-encode.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@
