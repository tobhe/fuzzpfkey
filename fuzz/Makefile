CC=	afl-cc
PROG=	fuzzpfkey

SRCS+=	fuzzpfkey.c siphash.c

CFLAGS += -Wall -Wshadow -Wpointer-arith -Wcast-qual
ASMFLAGS += -mmark-bti-property

.include <bsd.prog.mk>
