/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef LIB_FUSE_WORKLOAD_H
#define LIB_FUSE_WORKLOAD_H

#include "fuse_adaptive.h"
#include "fuse_kernel.h"

/* Pure detector: its caller serializes updates and handles collection errors. */
struct fuse_workload_detector {
	struct fuse_workload_settings settings;
	uint64_t last_end_ns, last_window, last_generation, candidate_since;
	uint32_t candidate_profile, candidate_workload;
};

void fuse_workload_defaults(struct fuse_workload_settings *settings);
int fuse_workload_validate(const struct fuse_workload_settings *settings);
int fuse_workload_detector_init(struct fuse_workload_detector *detector,
				const struct fuse_workload_settings *settings);
void fuse_workload_detector_reset(struct fuse_workload_detector *detector);
int fuse_workload_detector_update(struct fuse_workload_detector *detector,
				  const struct fuse_workload_snapshot *snapshot,
				  struct fuse_workload_result *result);
const char *fuse_workload_name(unsigned int workload);

#endif
