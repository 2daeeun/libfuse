/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef FUSE_ADAPTIVE_PROTOCOL_H
#define FUSE_ADAPTIVE_PROTOCOL_H
#include "fuse_adaptive.h"
#define FUSE_ADAPTIVE_CONTROL_VERSION 1
#define FUSE_ADAPTIVE_REPLY_MAX (1024U * 1024U)
enum fuse_adaptive_control_op {
	FUSE_ADAPTIVE_STATUS = 1,
	FUSE_ADAPTIVE_WORKLOAD,
	FUSE_ADAPTIVE_SET_DEPTH,
	FUSE_ADAPTIVE_CONFIGURE,
	FUSE_ADAPTIVE_GET_CONFIG,
};
struct fuse_adaptive_control_request {
	uint32_t version, operation, depth, reserved;
	struct fuse_workload_settings settings;
};
#endif
