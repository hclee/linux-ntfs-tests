// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * A buffered write into a hole whose copy from user space stops because the
 * writer gets SIGKILL: the source buffer's second page is registered with
 * userfaultfd, so the copy blocks on it until the parent kills the child.
 * Afterwards the part of the cluster the write did not reach must read as
 * zeroes (not the old contents of the reused clusters), also after fsync
 * and drop_caches.
 *
 * Usage: killed_short_write FILE CLUSTER_SIZE
 * Exit status 0 when the cluster reads back right, 1 on wrong data, 2 on
 * a setup error. Needs root (userfaultfd for kernel-mode faults).
 */
#define _GNU_SOURCE
#include <errno.h>
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

struct child_args {
	int fd;
	const void *src;
	size_t len;
	off_t off;
};

/* shares the mm with the parent (CLONE_VM), so the userfaultfd range applies */
static int writer(void *arg)
{
	struct child_args *a = arg;

	/* the parent kills it during the copy: the result does not matter */
	return pwrite(a->fd, a->src, a->len, a->off) < 0;
}

static void die(const char *what)
{
	perror(what);
	exit(2);
}

int main(int argc, char **argv)
{
	long cs, pg = sysconf(_SC_PAGESIZE);
	size_t size, copy, len;
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg;
	struct uffd_msg msg;
	struct pollfd pfd;
	unsigned char *buf, *data;
	off_t off;
	int fd, uffd, status, bad = 0;
	pid_t pid;
	size_t i;

	if (argc != 3)
		return 2;
	cs = atol(argv[2]);
	size = 32 * cs;
	off = 8 * cs;
	/* the copy stops inside the second cluster of the write */
	copy = cs + cs / 2;
	if (copy < (size_t)pg)
		copy = pg + 512;
	len = 4 * cs > (long)copy + pg ? 4 * cs : copy + pg;

	fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		die("open");
	data = malloc(size);
	memset(data, 0xab, size);
	if (pwrite(fd, data, size, 0) != (ssize_t)size || fsync(fd))
		die("fill");
	/* free the clusters with the old data in them, keep the size */
	if (ftruncate(fd, 0) || ftruncate(fd, size))
		die("truncate");
	if (pwrite(fd, "\1", 1, size - 1) != 1)	/* initialized_size = size */
		die("last byte");

	/* source: COPY bytes, then a page that faults through userfaultfd */
	size_t map = ((copy + pg - 1) / pg + 1) * pg;
	buf = mmap(NULL, map, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		die("mmap");
	unsigned char *src = buf + map - pg - copy;
	memset(src, 0x5c, copy);
	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0)
		die("userfaultfd");
	if (ioctl(uffd, UFFDIO_API, &api))
		die("UFFDIO_API");
	reg.range.start = (unsigned long)(buf + map - pg);
	reg.range.len = pg;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg))
		die("UFFDIO_REGISTER");

	struct child_args args = { fd, src, len, off };
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
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	if (!WIFSIGNALED(status))
		fprintf(stderr, "child was not killed\n");

	if (fsync(fd))
		die("fsync");
	int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (dc < 0 || write(dc, "3\n", 2) != 2)
		die("drop_caches");
	close(dc);
	off_t st = lseek(fd, 0, SEEK_END);
	if (pread(fd, data, size, 0) != (ssize_t)size)
		die("pread");
	/* everything is 0x00 or the written 0x5c, never the old 0xab */
	for (i = 0; i < size; i++) {
		if (data[i] == 0xab) {
			if (!bad)
				printf("old data at %zu (cluster %zu)\n", i, i / cs);
			bad++;
		}
	}
	printf("cluster %ld: file size %lld, %d old bytes\n", cs, (long long)st, bad);
	return bad ? 1 : 0;
}
