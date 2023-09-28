/*
 * Copyright (c) 2023 Tobias Heider <me@tobhe.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <net/pfkeyv2.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <sys/kcov.h>
#include <sys/mman.h>

#include "siphash.h"

#define PFATAL(x...)                                                           \
	do {                                                                   \
		fprintf(stderr, "[-] SYSTEM ERROR : " x);                      \
		fprintf(stderr, "\n\tLocation : %s(), %s:%u\n", __FUNCTION__,  \
			__FILE__, __LINE__);                                   \
		perror("      OS message ");                                   \
		fprintf(stderr, "\n");                                         \
		exit(EXIT_FAILURE);                                            \
	} while (0)

struct kcov {
	int fd;
	unsigned long  size;
	unsigned long *cover;
};

struct kcov *kcov_new(void)
{
	struct kcov *k;
	int fd;
	unsigned long  size = 1024;
	unsigned long *cover;

	fd = open("/dev/kcov", O_RDWR);
	if (fd == -1)
		PFATAL("open(/dev/kcov)");

	if (ioctl(fd, KIOSETBUFSIZE, &size) == -1)
		PFATAL("ioctl(KIOSETBUFSIZE)");

	/* Mmap buffer shared between kernel- and user-space. */
	cover = mmap(NULL, size * sizeof(unsigned long),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (cover == MAP_FAILED) {
		PFATAL("mmap");
	}

	k = calloc(1, sizeof(struct kcov));
	k->fd = fd;
	k->cover = cover;
	k->size = size;
	return k;
}

void kcov_enable(struct kcov *kcov)
{
	/* reset counter */
	__atomic_store_n(&kcov->cover[0], 0, __ATOMIC_RELAXED);
	int mode = KCOV_MODE_TRACE_PC;

	if (ioctl(kcov->fd, KIOENABLE, &mode) != 0)
		PFATAL("ioctl(KIOENABLE)");

	/* Reset coverage. */
	__atomic_store_n(&kcov->cover[0], 0, __ATOMIC_RELAXED);
	__sync_synchronize();
}

int kcov_disable(struct kcov *kcov)
{
	/* Stop counter */
	__sync_synchronize();

	int kcov_len = __atomic_load_n(&kcov->cover[0], __ATOMIC_RELAXED);

	/* Stop actual couting. */
	if (ioctl(kcov->fd, KIODISABLE) != 0)
		PFATAL("ioctl(KCOV_DISABLE)");

	return kcov_len;
}

void kcov_free(struct kcov *kcov)
{
	close(kcov->fd);
	kcov->fd = -1;
	munmap(kcov->cover, kcov->size * sizeof(unsigned long));
	kcov->cover = MAP_FAILED;
}

unsigned long *kcov_cover(struct kcov *kcov) { return kcov->cover; }

void
print_hex(char *buf, size_t len)
{
        unsigned int     i;

        for (i = 0; i < len; i++) {
                if (i && (i % 4) == 0) {
                        if ((i % 32) == 0)
                                printf("\n");
                        else
                                printf(" ");
                }
                printf("%02x", buf[i]);
        }
        printf("\n");
}

int
main(int argc, char **argv)
{
	struct kcov	*k;
	unsigned long	*kbuf;
	uint8_t		*afl_shared = NULL;
	const char	*afl_shm_id_str;
	uint64_t	 previous;
	int		 sock;
	char		 inbuf[512*1024] = {0} ;
	size_t		 inlen, slen;
	int i;

	k = kcov_new();
	if (k == NULL)
		err(1, "kcov_new");

	kbuf = kcov_cover(k);

	afl_shm_id_str = getenv("__AFL_SHM_ID");
	if (afl_shm_idr_str != NULL) {
		int afl_shm_id = atoi(afl_shm_id_str);
		afl_shared = shmat(afl_shm_id, NULL, 0);
	}

	/* get input */
	inlen = read(0, inbuf, sizeof(inbuf));
	if (inlen <= 16)
		err(1, "read");

	/* OpenBSD expects a valid PID */
	uint32_t pid = getpid();
	memcpy(inbuf + 12, &pid, sizeof(pid));
	}

	kcov_enable(k);

	sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (sock == -1)
		err(1, "sock");

	printf("inbuf: ");
	print_hex(inbuf, inlen);
	slen = send(sock, inbuf, inlen, 0);
	if (slen == -1)
		printf("send()");

	int kcov_len = kcov_disable(k);

	/* write output */
	previous = 0;
	if (afl_shared != NULL) {
		for (i = 0; i < kcov_len; i++) {
			uint64_t current = kbuf[i + 1];
			uint64_t hash = hsiphash_static(&current,
							sizeof(unsigned long));
			uint64_t mixed = (hash & 0xffff) ^ previous;
			previous = (hash & 0xffff) >> 1;

			uint8_t *s = &afl_shared[mixed];
			int r = __builtin_add_overflow(*s, 1, s);
			if (r) {
				*s = 128;
			}
		}
	}

	kcov_free(k);

	return (0);
}
