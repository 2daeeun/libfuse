/* SPDX-License-Identifier: GPL-2.0 */
#ifndef EXTFUSE_READ_CACHE_FD_H
#define EXTFUSE_READ_CACHE_FD_H

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * Take an attribute snapshot only through the inode-lifetime O_PATH
 * descriptor.  The identity check is a second guard against ever inserting a
 * reused open-file descriptor's attributes into the ExtFUSE nodeid cache.
 * Linux fstat supports O_PATH and observes the pinned object directly, including
 * an O_NOFOLLOW symlink or an unlinked inode, without empty-path handling.
 */
static inline int extfuse_snapshot_pinned_inode(int inode_fd,
						 dev_t expected_dev,
						 ino_t expected_ino,
						 struct stat *snapshot)
{
	if (fstat(inode_fd, snapshot))
		return -1;
	if (snapshot->st_dev != expected_dev ||
	    snapshot->st_ino != expected_ino) {
		errno = ESTALE;
		return -1;
	}
	return 0;
}

#endif /* EXTFUSE_READ_CACHE_FD_H */
