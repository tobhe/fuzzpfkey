all:	fuzzpfkey

fuzzpfkey:	fuzzpfkey.c siphash.c
	$(CC) -I../../include $^ -o fuzzpfkey

clean:
	rm -f fuzzpfkey
