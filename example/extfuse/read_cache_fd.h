/* SPDX-License-Identifier: GPL-2.0 */
#ifndef EXTFUSE_READ_CACHE_FD_H
#define EXTFUSE_READ_CACHE_FD_H

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * Take a post-reply attribute snapshot only through the inode-lifetime O_PATH
 * descriptor.  The identity check is a second guard against ever inserting a
 * reused open-file descriptor's attributes into the ExtFUSE nodeid cache.
 */
static inline int extfuse_snapshot_pinned_inode(int inode_fd,
						 dev_t expected_dev,
						 ino_t expected_ino,
						 struct stat *snapshot)
{
	if (fstatat(inode_fd, "", snapshot,
		    AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
		return -1;
	if (snapshot->st_dev != expected_dev ||
	    snapshot->st_ino != expected_ino) {
		errno = ESTALE;
		return -1;
	}
	return 0;
}

#endif /* EXTFUSE_READ_CACHE_FD_H */
