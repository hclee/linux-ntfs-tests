// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FILE holds old data (0xab) in allocated clusters past its initialized
 * size, as Windows leaves a file after SetFileValidData() (the guest script
 * sets it up with set_init_size.py). A buffered write at offset 0 raises the
 * initialized size to its end, then its copy from user space blocks on a
 * userfaultfd page. Meanwhile the test maps the file shared and writable,
 * which initializes all of it (mmap does not wait for the writer's inode
 * lock), writes a page through the mapping in the middle of the file, and
 * kills the writer. Its short write must not take the initialized size back
 * below the mapped page or drop the page from the page cache: the page must
 * keep its data and the old data must not show anywhere, also after fsync
 * and drop_caches.
 *
 * Usage: killed_write_mmap FILE CLUSTER_SIZE
 * Exit status 0 when the file reads back right, 1 on lost or old data, 2 on
 * a setup error. Needs root (userfaultfd for kernel-mode faults).
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct child_args {
	int fd;
	const void *src;
	size_t len;
};

/* shares the mm with the parent (CLONE_VM), so the userfaultfd range applies */
static int writer(void *arg)
{
	struct child_args *a = arg;

	/* the parent kills it during the copy: the result does not matter */
	return pwrite(a->fd, a->src, a->len, 0) < 0;
}

static void die(const char *what)
{
	perror(what);
	exit(2);
}

int main(int argc, char **argv)
{
	long cs, pg = sysconf(_SC_PAGESIZE);
	size_t size, len, copy, map, i, lost = 0, old = 0;
	off_t moff;
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg;
	struct uffd_msg msg;
	struct pollfd pfd;
	struct stat st;
	unsigned char *buf, *src, *file, *data;
	int fd, uffd, status;
	pid_t pid;

	if (argc != 3)
		return 2;
	cs = atol(argv[2]);
	fd = open(argv[1], O_RDWR);
	if (fd < 0 || fstat(fd, &st))
		die("open");
	size = st.st_size;
	len = 4 * cs > 65536 ? 4 * cs : 65536;	/* the write: [0, len) */
	copy = len / 4;				/* the copy stops here */
	moff = size / 2;			/* the mapped page, past the write */
	if ((size_t)moff < len + pg)
		die("file too small");

	/* source: COPY bytes, then a page that faults through userfaultfd */
	map = (copy + pg - 1) / pg * pg + pg;
	buf = mmap(NULL, map, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		die("mmap source");
	src = buf + map - pg - copy;
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

	struct child_args args = { fd, src, len };
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
	/*
	 * The writer is stalled after COPY bytes, holding the inode lock.
	 * Mapping the file shared and writable initializes it up to its size
	 * without that lock; then write a page through the mapping.
	 */
	file = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (file == MAP_FAILED)
		die("mmap file");
	memset(file + moff, 0x77, pg);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	if (!WIFSIGNALED(status))
		fprintf(stderr, "child was not killed\n");

	for (i = 0; i < (size_t)pg; i++)
		if (file[moff + i] != 0x77)
			lost++;
	if (lost)
		printf("mapped page lost in the page cache (%zu bytes)\n", lost);
	if (munmap(file, size) || fsync(fd))
		die("fsync");
	int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);

	if (dc < 0 || write(dc, "3\n", 2) != 2)
		die("drop_caches");
	close(dc);
	data = malloc(size);
	if (pread(fd, data, size, 0) != (ssize_t)size)
		die("pread");
	for (i = 0; i < size; i++) {
		if (i >= (size_t)moff && i < (size_t)moff + pg) {
			if (data[i] != 0x77)
				lost++;
		} else if (data[i] == 0xab) {
			if (!old)
				printf("old data at %zu\n", i);
			old++;
		}
	}
	printf("cluster %ld: file size %lld, %zu lost bytes at %lld, %zu old bytes\n",
	       cs, (long long)lseek(fd, 0, SEEK_END), lost, (long long)moff, old);
	return lost || old ? 1 : 0;
}
