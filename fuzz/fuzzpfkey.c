/*
   Copyright 2023 Tobias Heider <tobhe@openbsd.org>
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0
*/

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>

#ifdef __OpenBSD__
#include <net/pfkeyv2.h>
#include <sys/kcov.h>
#endif /* OpenBSD */

#ifdef __linux__
#include <linux/pfkeyv2.h>
#include <linux/kcov.h>
#endif /* linux */

#include "siphash.h"

/* AFL config*/
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1U << MAP_SIZE_POW2)

#define FORKSRV_FD 198

#define SHM_ENV_VAR "__AFL_SHM_ID"

#define FS_OPT_ERROR 0xf800008f
#define FS_OPT_GET_ERROR(x) ((x & 0x00ffff00) >> 8)
#define FS_OPT_SET_ERROR(x) ((x & 0x0000ffff) << 8)
#define FS_ERROR_MAP_SIZE 1
#define FS_ERROR_SHMAT 8

#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_MAX_MAPSIZE ((0x00fffffeU >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) \
  (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))

uint8_t *__afl_area_ptr;

__thread uint32_t __afl_map_size = MAP_SIZE;

struct kcov {
	int		 k_fd;
	unsigned long	 k_size;
	unsigned long	*k_cover;
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
	k->k_fd = fd;
	k->k_cover = cover;
	k->k_size = size;
	return k;
}

void
kcov_enable(struct kcov *kcov)
{
	/* reset counter */
	__atomic_store_n(&kcov->k_cover[0], 0, __ATOMIC_RELAXED);

#if defined(__OpenBSD__)
	int mode = KCOV_MODE_TRACE_PC;
	if (ioctl(kcov->k_fd, KIOENABLE, &mode) != 0)
		err(1, "ioctl(KIOENABLE)");
#elif defined(__linux__)
	if (ioctl(kcov->k_fd, KCOV_ENABLE, KCOV_TRACE_PC) != 0)
		err(1, "ioctl(KCOV_ENABLE)");
#endif
}

int kcov_disable(struct kcov *kcov)
{
	int kcov_len = __atomic_load_n(&kcov->k_cover[0], __ATOMIC_RELAXED);

	/* Stop actual couting. */
#if defined(__OpenBSD__)
	if (ioctl(kcov->k_fd, KIODISABLE) != 0)
		err(1, "ioctl(KIODISABLE)");
#elif defined(__linux__)
	if (ioctl(kcov->k_fd, KCOV_DISABLE, 0) != 0)
		err(1, "ioctl(KCOV_DISABLE)");
#endif

	return kcov_len;
}

void kcov_free(struct kcov *kcov)
{
	close(kcov->k_fd);
	kcov->k_fd = -1;
	munmap(kcov->k_cover, kcov->k_size * sizeof(unsigned long));
	kcov->k_cover = MAP_FAILED;
}

unsigned long *kcov_cover(struct kcov *kcov)
{
	return kcov->k_cover;
}


/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {

  uint32_t status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;

}

/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  /* NOTE TODO BUG FIXME: if you want to supply a variable sized map then
     uncomment the following: */

  /*
  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

    uint32_t val = atoi(ptr);
    if (val > 0) __afl_map_size = val;

  }

  */

  if (__afl_map_size > MAP_SIZE) {

    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {

      fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {

        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);

      }

    } else {

      fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);

    }

  }

  if (id_str) {

#ifdef USEMMAP
    const char    *shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);

    }

    __afl_area_ptr = shm_base;
#else
    uint32_t shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, 0, 0);

#endif

    if (__afl_area_ptr == (void *)-1) {

      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);

    }

    /* Write something into the bitmap so that the parent doesn't give up */

    __afl_area_ptr[0] = 1;

  }

}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  uint8_t  tmp[4] = {0, 0, 0, 0};
  uint32_t status = 0;

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);

  /* Phone home and tell the parent that we're OK. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

}

static uint32_t __afl_next_testcase(uint8_t *buf, uint32_t max_len) {

  int32_t status, res = 0xffffff;

  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &status, 4) != 4) return 0;

  /* we have a testcase - read it */
  status = read(0, buf, max_len);

  /* report that we are starting the target */
  if (write(FORKSRV_FD + 1, &res, 4) != 4) return 0;

  return status;

}

static void __afl_end_testcase(void) {
  int status = 0xffffff;
  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);
}

/* you just need to modify the while() loop in this main() */

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
main(int argc, char *argv[])
{
	struct kcov	*k;
	unsigned long	*kbuf;
	uint8_t  buf[1024];
	int len;
	uint64_t	 previous = 0;
	int sock, kcov_len;
	size_t slen;
	int i;

	__afl_map_size = MAP_SIZE;

	__afl_map_shm();
	__afl_start_forkserver();

	k = kcov_new();
	if (k == NULL) {
		errx(1, "kcov_new");
		exit(1);
	}

	sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (sock == -1) {
		err(1, "sock: ");
		exit(1);
	}

	kbuf = kcov_cover(k);

	while ((len = __afl_next_testcase(buf, sizeof(buf))) > 0) {
		if (len >= sizeof(struct sadb_msg)) {
			kcov_enable(k);

			struct sadb_msg *msg = (struct sadb_msg *)buf;
			msg->sadb_msg_version = PF_KEY_V2;
			msg->sadb_msg_pid = getpid();
			msg->sadb_msg_len = len / 8;

#ifdef DEBUG
			printf("sending: len=%d: ", len);
			print_hex(buf, len);
#endif
			write(sock, buf, len);

			kcov_len = kcov_disable(k);

			for (i = 0; i < kcov_len; i++) {
				uint64_t current = kbuf[i + 1];
				uint32_t hash = hsiphash_static(&current, sizeof(unsigned long));
				uint64_t mixed = (hash & 0xffff) ^ previous;
				previous = (hash & 0xffff) >> 1;

				uint8_t *s = &__afl_area_ptr[mixed];
				int r = __builtin_add_overflow(*s, 1, s);
				if (r) {
					*s = 128;
				}
			}
		}
 skip:
		__afl_end_testcase();
	}
	close(sock);
	return 0;
}
