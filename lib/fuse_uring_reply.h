/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  The libfuse authors
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt.
 */

#ifndef LIB_FUSE_URING_REPLY_H_
#define LIB_FUSE_URING_REPLY_H_

#include "fuse_kernel.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

static inline size_t fuse_uring_reply_protocol_max_payload(void)
{
	return UINT32_MAX - sizeof(struct fuse_out_header);
}

static inline int fuse_uring_prepare_reply(
	struct fuse_out_header *out, struct fuse_uring_ent_in_out *ent_in_out,
	uint64_t unique, int error, size_t payload_sz, size_t max_payload_sz)
{
	int validation_error = 0;

	if (error)
		payload_sz = 0;
	else if (payload_sz > max_payload_sz)
		validation_error = -E2BIG;
	else if (payload_sz > fuse_uring_reply_protocol_max_payload())
		validation_error = -EOVERFLOW;

	if (validation_error) {
		error = -EINVAL;
		payload_sz = 0;
	}

	out->len = (uint32_t)(sizeof(*out) + payload_sz);
	out->error = error;
	out->unique = unique;
	ent_in_out->payload_sz = (uint32_t)payload_sz;

	return validation_error;
}

static inline int fuse_uring_iov_payload_size(const struct iovec *iov,
					      int count, size_t max_payload_sz,
					      size_t *payload_sz)
{
	size_t len = 0;
	size_t protocol_max = fuse_uring_reply_protocol_max_payload();

	if (iov == NULL || payload_sz == NULL || count < 1 ||
	    iov[0].iov_base == NULL ||
	    iov[0].iov_len != sizeof(struct fuse_out_header))
		return -EINVAL;

	for (int idx = 1; idx < count; idx++) {
		const struct iovec *cur = &iov[idx];

		if (cur->iov_len && cur->iov_base == NULL)
			return -EINVAL;
		if (len > max_payload_sz || cur->iov_len > max_payload_sz - len)
			return -E2BIG;
		if (len > protocol_max || cur->iov_len > protocol_max - len)
			return -EOVERFLOW;
		len += cur->iov_len;
	}

	*payload_sz = len;
	return 0;
}

#endif /* LIB_FUSE_URING_REPLY_H_ */
