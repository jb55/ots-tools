
CFLAGS=-std=c99 -ggdb -O -Wall -Wextra -Werror

OBJS=ots.o
OBJS+=util.o

all: otsprint otsmini

otsprint: otsprint.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

otsmini: otsmini.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

TAGS: fake
	etags -o - *.c > $@

.PHONY: fake
