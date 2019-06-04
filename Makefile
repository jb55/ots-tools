
CFLAGS=-std=c99 -ggdb -O -Wall -Wextra -Werror

OBJS=ots.o

otsprint: otsprint.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

otsmini: otsmini.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@
