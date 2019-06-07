
CFLAGS=-std=c99 -ggdb -O -Wall -Wextra -Werror

OBJS=ots.o
OBJS+=util.o
OBJS+=varint.o
OBJS+=mini.o
OBJS+=base58.o
OBJS+=compiler.o
OBJS+=decoder.o

all: otsprint otsmini

otsprint: otsprint.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

otsmini: otsmini.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

run-tests: test.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

check: run-tests fake
	./run-tests

clean: fake
	rm -f $(OBJS) otsprint otsmini

TAGS: fake
	etags -o - *.c > $@

.PHONY: fake
