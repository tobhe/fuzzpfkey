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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>
#include <net/pfkeyv2.h>

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
	int		 fd;
	int		 sock;
	char		 inbuf[512*1024] = {0} ;
	size_t		 inlen, slen;
	uint32_t	 pid;

	if (argc != 2)
		errx(1, "argc != 2");

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		err(1, "open()");

	sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (sock == -1)
		err(1, "sock");

	/* get input */
	inlen = read(fd, inbuf, sizeof(inbuf));
	print_hex(inbuf, inlen);

 	pid = getpid();
	memcpy(inbuf + 12, &pid, sizeof(pid));

	slen = send(sock, inbuf, inlen, 0);
	if (slen == -1)
		errx(1, "send()\n");

	return (0);
}
