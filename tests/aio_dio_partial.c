// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * An O_DIRECT write that fails part way, after some of its bios were
 * submitted, must not leave the old contents of the clusters it did not
 * reach readable.  The write source is MAPPED bytes of 0x5a followed by an
 * unmapped page, so iomap submits bios for the mapped part and then fails
 * with EFAULT.  The file has its clusters reserved with FALLOC_FL_KEEP_SIZE
 * on a volume that held 0xee, so a cluster the write did not reach still
 * holds 0xee.  ntfs moves the data and initialized sizes to the end of the
 * write before the I/O and takes them back when the write fails, but an
 * asynchronous write returns -EIOCBQUEUED while its bios are in flight and
 * then completes with the error, so the rollback does not run.
 *
 * Usage: aio_dio_partial FILE MAPPED LENGTH aio|sync|nowait
 * Writes LENGTH bytes at offset 0 with io_submit() (aio) or pwritev()
 * (sync), then reads the whole file back with O_DIRECT and prints the
 * write's result, the file size and how many bytes read back as 0xee.
 * Exit status 0 when no 0xee byte is readable, 1 when some are, 2 on a
 * setup error.  nowait writes the MAPPED bytes alone with pwritev2() and
 * RWF_NOWAIT into a file of size 0: such a write moves the initialized
 * size and has to wait for its I/O, so it must fail with EAGAIN and leave
 * the size alone (exit status 1 otherwise), as on ext4.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static void die(const char *what)
{
	perror(what);
	exit(2);
}

int main(int argc, char **argv)
{
	long pg = sysconf(_SC_PAGESIZE);
	size_t mapped, len, i, old = 0;
	unsigned char *src, *rd;
	struct stat st;
	long long res;
	int fd;

	if (argc != 5)
		return 2;
	mapped = strtoull(argv[2], NULL, 0);
	len = strtoull(argv[3], NULL, 0);
	if (mapped % pg || len <= mapped || len % pg)
		return 2;
	fd = open(argv[1], O_RDWR | O_DIRECT);
	if (fd < 0)
		die("open");
	/* MAPPED bytes of data, then nothing mapped up to LENGTH */
	src = mmap(NULL, len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src == MAP_FAILED)
		die("mmap");
	memset(src, 0x5a, mapped);
	if (munmap(src + mapped, len - mapped))
		die("munmap");

	if (!strcmp(argv[4], "aio")) {
		aio_context_t ctx = 0;
		struct iocb cb = { 0 }, *cbs[1] = { &cb };
		struct io_event ev;

		if (syscall(SYS_io_setup, 1, &ctx))
			die("io_setup");
		cb.aio_fildes = fd;
		cb.aio_lio_opcode = IOCB_CMD_PWRITE;
		cb.aio_buf = (unsigned long)src;
		cb.aio_nbytes = len;
		cb.aio_offset = 0;
		if (syscall(SYS_io_submit, ctx, 1, cbs) != 1)
			die("io_submit");
		if (syscall(SYS_io_getevents, ctx, 1, 1, &ev, NULL) != 1)
			die("io_getevents");
		res = ev.res;
		syscall(SYS_io_destroy, ctx);
	} else if (!strcmp(argv[4], "nowait")) {
		struct iovec iov = { src, mapped };

		res = pwritev2(fd, &iov, 1, 0, RWF_NOWAIT);
		if (res < 0)
			res = -errno;
	} else {
		struct iovec iov = { src, len };

		res = pwritev(fd, &iov, 1, 0);
		if (res < 0)
			res = -errno;
	}

	if (fstat(fd, &st))
		die("fstat");
	if (st.st_size) {
		size_t sz = (st.st_size + pg - 1) / pg * pg;

		if (posix_memalign((void **)&rd, pg, sz))
			die("posix_memalign");
		memset(rd, 0, sz);
		if (pread(fd, rd, sz, 0) < st.st_size)
			die("pread");
		for (i = 0; i < (size_t)st.st_size; i++)
			old += rd[i] == 0xee;
	}
	printf("%s write of %zu (%zu mapped): result %lld, size %lld, "
	       "%zu bytes of old data\n", argv[4], len, mapped, res,
	       (long long)st.st_size, old);
	if (!strcmp(argv[4], "nowait") && (res != -EAGAIN || st.st_size))
		return 1;
	return old ? 1 : 0;
}
