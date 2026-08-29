/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  The libfuse authors
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt.
 */

#include "fuse_uring_reply.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
	struct fuse_uring_ent_in_out ent_in_out;
	struct fuse_out_header source_out;
	struct fuse_out_header out;
	char first[16];
	char second[32];
	struct iovec iov[] = {
		{ .iov_base = &source_out, .iov_len = sizeof(source_out) },
		{ .iov_base = first, .iov_len = sizeof(first) },
		{ .iov_base = second, .iov_len = sizeof(second) },
	};
	size_t payload_sz;
	int res;

	memset(&out, 0xff, sizeof(out));
	memset(&ent_in_out, 0xff, sizeof(ent_in_out));
	res = fuse_uring_prepare_reply(&out, &ent_in_out, 7, 0, 0, 64);
	assert(res == 0);
	assert(out.len == sizeof(out));
	assert(out.error == 0);
	assert(out.unique == 7);
	assert(ent_in_out.payload_sz == 0);

	res = fuse_uring_prepare_reply(&out, &ent_in_out, 8, 0, 48, 64);
	assert(res == 0);
	assert(out.len == sizeof(out) + 48);
	assert(out.error == 0);
	assert(out.unique == 8);
	assert(ent_in_out.payload_sz == 48);

	res = fuse_uring_prepare_reply(&out, &ent_in_out, 9, -ENOENT, 48, 64);
	assert(res == 0);
	assert(out.len == sizeof(out));
	assert(out.error == -ENOENT);
	assert(out.unique == 9);
	assert(ent_in_out.payload_sz == 0);

	res = fuse_uring_prepare_reply(&out, &ent_in_out, 10, 0, 65, 64);
	assert(res == -E2BIG);
	assert(out.len == sizeof(out));
	assert(out.error == -EINVAL);
	assert(out.unique == 10);
	assert(ent_in_out.payload_sz == 0);

#if SIZE_MAX > UINT32_MAX
	res = fuse_uring_prepare_reply(&out, &ent_in_out, 11, 0,
				       (size_t)UINT32_MAX - sizeof(out) + 1,
				       SIZE_MAX);
	assert(res == -EOVERFLOW);
	assert(out.len == sizeof(out));
	assert(out.error == -EINVAL);
	assert(out.unique == 11);
	assert(ent_in_out.payload_sz == 0);
#endif

	res = fuse_uring_iov_payload_size(iov, 3, 64, &payload_sz);
	assert(res == 0);
	assert(payload_sz == sizeof(first) + sizeof(second));

	iov[2].iov_len = 49;
	res = fuse_uring_iov_payload_size(iov, 3, 64, &payload_sz);
	assert(res == -E2BIG);
	iov[2].iov_len = sizeof(second);

	iov[1].iov_base = NULL;
	res = fuse_uring_iov_payload_size(iov, 3, 64, &payload_sz);
	assert(res == -EINVAL);
	iov[1].iov_base = first;

	iov[0].iov_len--;
	res = fuse_uring_iov_payload_size(iov, 3, 64, &payload_sz);
	assert(res == -EINVAL);

	return 0;
}
