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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#ifdef __OpenBSD__
#include <net/pfkeyv2.h>
#include <sys/kcov.h>
#endif /* OpenBSD */

#ifdef __linux__
#include <linux/pfkeyv2.h>
#include <linux/kcov.h>
#endif /* linux */

#include "siphash.h"

struct kcov {
	int		 fd;
	unsigned long	 size;
	unsigned long	*cover;
};

struct kcov *
kcov_new(void)
{
	struct kcov *k;
	int fd;
	const unsigned long  size = 1024;
	unsigned long *cover;

#if defined(__OpenBSD__)
	fd = open("/dev/kcov", O_RDWR);
	if (fd == -1)
		err(1, "open(/dev/kcov)");
	if (ioctl(fd, KIOSETBUFSIZE, &size) == -1)
		err(1, "ioctl(KIOSETBUFSIZE)");
#elif defined(__linux__)
	fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd == -1)
		err(1, "open(/sys/kernel/debug/kcov)");
	if (ioctl(fd, KCOV_INIT_TRACE, size))
		err(1, "ioctl(KOV_INIT_TRACE)");
#endif

	/* Mmap buffer shared between kernel- and user-space. */
	cover = mmap(NULL, size * sizeof(unsigned long),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (cover == MAP_FAILED) {
		err(1, "mmap");
	}

	k = calloc(1, sizeof(struct kcov));
	k->fd = fd;
	k->cover = cover;
	k->size = size;
	return k;
}

void
kcov_enable(struct kcov *kcov)
{
	/* reset counter */
	__atomic_store_n(&kcov->cover[0], 0, __ATOMIC_RELAXED);

#if defined(__OpenBSD__)
	int mode = KCOV_MODE_TRACE_PC;
	if (ioctl(kcov->fd, KIOENABLE, &mode) != 0)
		err(1, "ioctl(KIOENABLE)");
#elif defined(__linux__)
	if (ioctl(kcov->fd, KCOV_ENABLE, KCOV_TRACE_PC) != 0)
		err(1, "ioctl(KCOV_ENABLE)");
#endif
}

int kcov_disable(struct kcov *kcov)
{
	int kcov_len = __atomic_load_n(&kcov->cover[0], __ATOMIC_RELAXED);

	/* Stop actual couting. */
#if defined(__OpenBSD__)
	if (ioctl(kcov->fd, KIODISABLE) != 0)
		err(1, "ioctl(KIODISABLE)");
#elif defined(__linux__)
	if (ioctl(kcov->fd, KCOV_DISABLE, 0) != 0)
		err(1, "ioctl(KCOV_DISABLE)");
#endif

	return kcov_len;
}

void kcov_free(struct kcov *kcov)
{
	close(kcov->fd);
	kcov->fd = -1;
	munmap(kcov->cover, kcov->size * sizeof(unsigned long));
	kcov->cover = MAP_FAILED;
}

unsigned long *kcov_cover(struct kcov *kcov)
{
	return kcov->cover;
}

void
print_hex(uint8_t *buf, size_t len)
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
	int		 sock, kcov_len;
	uint8_t		 inbuf[512*1024] = {0} ;
	size_t		 inlen, slen;
	const char	*path = NULL;
	int		 i, fd;

	if (argc == 2)
		path = argv[1];

	k = kcov_new();
	if (k == NULL)
		errx(1, "kcov_new");

	kbuf = kcov_cover(k);

	afl_shm_id_str = getenv("__AFL_SHM_ID");
	if (afl_shm_id_str != NULL) {
		int afl_shm_id = atoi(afl_shm_id_str);
		afl_shared = shmat(afl_shm_id, NULL, 0);
	}
	printf("afl_shared: %p\n", afl_shared);

	kcov_enable(k);

	sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (sock == -1) {
		err(1, "sock: ");
		goto done;
	}

	if (path != NULL) {
		fd = open(argv[1], O_RDONLY);
		if (fd == -1)
			err(1, "open()");
	} else {
		fd = 0;
	}

	/* get input */
	inlen = read(fd, inbuf, sizeof(inbuf));

	/* OpenBSD expects a valid PID */
	struct sadb_msg *msg = (struct sadb_msg *)inbuf;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_pid = getpid();
	printf("pid = %x\n", msg->sadb_msg_pid);
	msg->sadb_msg_len = inlen / 8;

	printf("sending: len=%zu: ", inlen);
	print_hex(inbuf, inlen);
	slen = write(sock, inbuf, inlen);
	if (slen == -1) {
		err(1, "write():");
		goto done;
	}

	inlen = read(fd, inbuf, sizeof(inbuf));
	if (inlen == -1) {
		err(1, "read(): ");
		goto done;
	}
	printf("recv: len=%zu: ", inlen);
	print_hex(inbuf, inlen);
 done:

	kcov_len = kcov_disable(k);

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
