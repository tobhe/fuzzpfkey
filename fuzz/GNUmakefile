CFLAGS=		-D_DEFAULT_SOURCE -D_GNU_SOURCE \
		-Wall

.PHONY: all clean install
all:	fuzzpfkey

fuzzpfkey: fuzzpfkey.c siphash.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

clean:
	rm -f fuzzpfkey fuzzpfkey.o out
