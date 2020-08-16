/*	$NetBSD: lchflags.c,v 1.4 2008/04/29 05:46:08 martin Exp $	*/

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Luke Mewburn.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Emulate lchflags(2), checking path with lstat(2) first to ensure that
 * it's not a symlink, and then call chflags(2) */

#include <nbcompat.h>
#include <nbcompat/stat.h>
#include <nbcompat/unistd.h>

/* Linux glibc does not have the cflags(2) system call */
#ifdef __linux__

#include <sys/ioctl.h>
#include <fcntl.h>

#define EXT2_IOC_SETFLAGS               _IOW('f', 2, long)

#ifdef O_LARGEFILE
#define FILE_OPEN_FLAGS (O_RDONLY|O_NONBLOCK|O_LARGEFILE)
#else
#define FILE_OPEN_FLAGS (O_RDONLY|O_NONBLOCK)
#endif

int
lchflags(const char *path, unsigned long flags)
{
	struct stat sb;
	int iflags;
	int esave;
	int fd;
	int r;

	/* Target must be regular file or directory */
	if (lstat(path, &sb) == -1)
		return -1;
	if (!S_ISREG(sb.st_mode) && !S_ISDIR(sb.st_mode))
		goto unsupported;

	/* Apparently ext2/3/4 has its own version of some flags */
#ifdef EXT2_IMMUTABLE_FL
	if (flags & UF_IMMUTABLE)
		flags |= EXT2_IMMUTABLE_FL;
#endif
#ifdef EXT2_APPEND_FL
	if (flags & UF_APPEND)
		flags |= EXT2_APPEND_FL;
#endif
#ifdef EXT2_NODUMP_FL
	if (flags & UF_NODUMP)
		flags |= EXT2_NODUMP_FL;
#endif

	/* Have to set flags using ioctl(2) on Linux */
	if ((fd = open(path, FILE_OPEN_FLAGS)) == -1)
		return -1;
	iflags = (int)flags;
	if ((r = ioctl(fd, EXT2_IOC_SETFLAGS, &iflags)) == -1) {
		esave = errno;
		close(fd);
		errno = esave;
		return r;
	}

	/* Done */
	close(fd);
	return 0;

unsupported:
	/* No can do */
	errno = EOPNOTSUPP;
	return -1;
}

#else	/* !__linux__ */

int
lchflags(const char *path, unsigned long flags)
{
	struct stat psb;

	if (lstat(path, &psb) == -1)
		return -1;
	if (S_ISLNK(psb.st_mode)) {
		return 0;
	}
	return (chflags(path, flags));
}

#endif	 /* !__linux__ */
