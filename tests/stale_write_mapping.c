// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * A buffered write into a hole maps the hole as delalloc in ->iomap_begin()
 * and copies afterwards. Here its copy blocks on a userfaultfd page after
 * the first page, just before it starts on the second one. Meanwhile the
 * test stores a byte through a shared mapping into the block where the
 * write will end, writes the file back with sync_file_range() (which does
 * not wait for the writer's inode lock), so that writeback allocates the
 * clusters, and drops the second page from the page cache. When the copy
 * resumes, the writer's mapping still says delalloc. Unless the file system
 * notices that it is stale, __iomap_write_begin() zeroes the rest of the
 * block instead of reading it back, and the stored byte is lost.
 *
 * Usage: stale_write_mapping FILE OFFSET
 * FILE must be a hole for two pages from OFFSET (page aligned) and extend
 * past them. Exit status 0 when the file reads back right, 1 on lost or
 * wrong data, 2 on a setup error. Needs root (userfaultfd for kernel-mode
 * faults, drop_caches).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define TAIL	100	/* bytes the write puts into the second page */
#define MARK	200	/* offset of the stored byte in the second page */

struct child_args {
	int fd;
	const void *src;
	size_t len;
	off_t pos;
};

/* shares the mm with the parent (CLONE_VM), so the userfaultfd range applies */
static int writer(void *arg)
{
	struct child_args *a = arg;

	return pwrite(a->fd, a->src, a->len, a->pos) != (ssize_t)a->len;
}

static void die(const char *what)
{
	perror(what);
	exit(2);
}

static int resident(int fd, off_t off, long pg)
{
	unsigned char vec = 0;
	void *m = mmap(NULL, pg, PROT_READ, MAP_SHARED, fd, off);

	if (m == MAP_FAILED)
		die("mmap for mincore");
	if (mincore(m, pg, &vec))
		die("mincore");
	munmap(m, pg);
	return vec & 1;
}

/* the two pages from POS: the write's data, then zeroes and the stored byte */
static size_t check(int fd, off_t pos, long pg, const char *when)
{
	unsigned char *d = malloc(2 * pg);
	size_t i, bad = 0;

	if (!d || pread(fd, d, 2 * pg, pos) != 2 * pg)
		die("pread");
	for (i = 0; i < (size_t)(2 * pg); i++) {
		unsigned char exp = i < (size_t)pg + TAIL ? 0x5c :
				    i == (size_t)pg + MARK ? 0x77 : 0;

		if (d[i] != exp && !bad++)
			printf("%s: byte %zu is 0x%02x, expected 0x%02x\n",
			       when, i, d[i], exp);
	}
	if (bad)
		printf("%s: %zu bytes wrong\n", when, bad);
	free(d);
	return bad;
}

int main(int argc, char **argv)
{
	long pg = sysconf(_SC_PAGESIZE);
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg;
	struct uffdio_copy copy;
	struct uffd_msg msg;
	struct pollfd pfd;
	unsigned char *buf, *fill, *file;
	size_t bad;
	off_t pos;
	int fd, uffd, status, dc, tries;
	pid_t pid;

	if (argc != 3)
		return 2;
	pos = atoll(argv[2]);
	fd = open(argv[1], O_RDWR);
	if (fd < 0)
		die("open");

	/* source: one page of data, then a page that faults through userfaultfd */
	buf = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	fill = mmap(NULL, pg, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED || fill == MAP_FAILED)
		die("mmap source");
	memset(buf, 0x5c, pg);
	memset(fill, 0x5c, pg);
	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0)
		die("userfaultfd");
	if (ioctl(uffd, UFFDIO_API, &api))
		die("UFFDIO_API");
	reg.range.start = (unsigned long)(buf + pg);
	reg.range.len = pg;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg))
		die("UFFDIO_REGISTER");

	struct child_args args = { fd, buf, pg + TAIL, pos };
	size_t stack_size = 1 << 20;
	char *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);

	if (stack == MAP_FAILED)
		die("stack");
	pid = clone(writer, stack + stack_size, CLONE_VM | SIGCHLD, &args);
	if (pid < 0)
		die("clone");
	pfd.fd = uffd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 10000) != 1 || read(uffd, &msg, sizeof(msg)) != sizeof(msg))
		die("waiting for the fault");

	/* The writer holds the inode lock and waits before the second page. */
	file = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pos);
	if (file == MAP_FAILED)
		die("mmap file");
	file[pg + MARK] = 0x77;
	if (munmap(file, 2 * pg))
		die("munmap");
	if (sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WAIT_BEFORE |
			    SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER))
		die("sync_file_range");
	for (tries = 0; tries < 10 && resident(fd, pos + pg, pg); tries++) {
		posix_fadvise(fd, pos + pg, pg, POSIX_FADV_DONTNEED);
		usleep(100000);
	}
	if (resident(fd, pos + pg, pg)) {
		fprintf(stderr, "the second page stays in the page cache\n");
		return 2;
	}

	copy.dst = (unsigned long)(buf + pg);
	copy.src = (unsigned long)fill;
	copy.len = pg;
	copy.mode = 0;
	if (ioctl(uffd, UFFDIO_COPY, &copy))
		die("UFFDIO_COPY");
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status)) {
		fprintf(stderr, "the write failed or was short\n");
		return 2;
	}

	bad = check(fd, pos, pg, "page cache");
	if (fsync(fd))
		die("fsync");
	dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (dc < 0 || write(dc, "3\n", 2) != 2)
		die("drop_caches");
	close(dc);
	bad += check(fd, pos, pg, "disk");
	return bad ? 1 : 0;
}
