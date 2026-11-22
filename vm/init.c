// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Minimal /init for the NTFS kernel-driver test VM.
 *
 * Loads the modules packed into the initramfs, mounts the host's root file
 * system read-only over virtio-9p (tag "root") and the writable work
 * directory over it (tag "work", path given as ntfsvm.work=PATH on the kernel
 * command line), chroots into the host tree and runs
 *   python3 <ntfsvm.script> <work directory>
 * Then it powers the VM off. Build with: gcc -static -O2 -o init init.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *const modules[] = {
	"netfs", "9pnet", "9pnet_virtio", "9p", "loop", "ntfs", "ntfs3", NULL
};

static void insmod(const char *name)
{
	char path[128];
	int fd;

	snprintf(path, sizeof(path), "/m/%s.ko", name);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;		/* built into the kernel */
	if (syscall(SYS_finit_module, fd, "", 0))
		fprintf(stderr, "init: loading %s failed: %m\n", name);
	if (fd >= 0)
		close(fd);
}

static char *cmdline_value(const char *key)
{
	static char buf[4096];
	char *p, *e;
	int fd = open("/proc/cmdline", O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return NULL;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return NULL;
	buf[n] = 0;
	p = strstr(buf, key);
	if (!p)
		return NULL;
	p += strlen(key);
	e = strpbrk(p, " \n");
	if (e)
		*e = 0;
	return strdup(p);
}

int main(void)
{
	char target[4096], *work, *script;
	pid_t pid;
	int status = 1, i;

	mount("proc", "/proc", "proc", 0, NULL);
	mount("sys", "/sys", "sysfs", 0, NULL);
	mount("dev", "/dev", "devtmpfs", 0, NULL);
	for (i = 0; modules[i]; i++)
		insmod(modules[i]);

	work = cmdline_value("ntfsvm.work=");
	script = cmdline_value("ntfsvm.script=");
	if (!work || !script) {
		fprintf(stderr, "init: ntfsvm.work= / ntfsvm.script= missing\n");
		goto out;
	}
	mkdir("/host", 0755);
	if (mount("root", "/host", "9p", MS_RDONLY,
		  "trans=virtio,version=9p2000.L,msize=512000,cache=loose")) {
		perror("init: mount root");
		goto out;
	}
	snprintf(target, sizeof(target), "/host%s", work);
	if (mount("work", target, "9p", 0,
		  "trans=virtio,version=9p2000.L,msize=512000,cache=none")) {
		perror("init: mount work");
		goto out;
	}
	mount("proc", "/host/proc", "proc", 0, NULL);
	mount("sys", "/host/sys", "sysfs", 0, NULL);
	mount("dev", "/host/dev", "devtmpfs", 0, NULL);
	if (chroot("/host") || chdir(work)) {
		perror("init: chroot");
		goto out;
	}
	pid = fork();
	if (!pid) {
		char *argv[] = { "python3", script, work, NULL };
		char *envp[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin",
				 "LC_ALL=C", "PYTHONDONTWRITEBYTECODE=1", NULL };
		char tmp[4200];

		snprintf(tmp, sizeof(tmp), "%s/tmp", work);
		mkdir(tmp, 0700);
		setenv("TMPDIR", tmp, 1);
		envp[2] = "PYTHONDONTWRITEBYTECODE=1";
		execve("/usr/bin/python3", argv, envp);
		perror("init: exec python3");
		_exit(127);
	}
	waitpid(pid, &status, 0);
	fprintf(stderr, "init: probe exited with status %d\n",
		WIFEXITED(status) ? WEXITSTATUS(status) : -1);
out:
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
