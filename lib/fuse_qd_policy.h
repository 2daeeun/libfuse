/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef LIB_FUSE_QD_POLICY_H
#define LIB_FUSE_QD_POLICY_H

#include "fuse_workload.h"

struct fuse_workload_detail;

#define FUSE_QD_POLICY_MAX_RULES 128
#define FUSE_QD_POLICY_NAME_SIZE 64

enum fuse_qd_policy_pattern {
	FUSE_QD_RANDOM,
	FUSE_QD_SEQUENTIAL,
	FUSE_QD_ANY,
};

struct fuse_qd_policy_rule {
	char context[FUSE_QD_POLICY_NAME_SIZE], name[FUSE_QD_POLICY_NAME_SIZE];
	uint64_t size;
	uint32_t files, requesters, sequential, read_percent, depth;
	/* Exact rules keep their historical ratio tolerance and endpoint rules. */
	uint64_t size_max;
	uint32_t files_max, requesters_max, read_percent_max, ranged;
};

/* Immutable after load. Mixed ratios use request counts, not bytes; pure
 * read/write rules require exactly 100%. Context names come from the file;
 * Range rules have inclusive bounds and no implicit ratio tolerance.
 * "none" is reserved for disabling the policy. Settings include thresholds.
 */
struct fuse_qd_policy_config {
	struct fuse_workload_settings settings;
	uint32_t ratio_tolerance, nr_rules;
	struct fuse_qd_policy_rule rules[FUSE_QD_POLICY_MAX_RULES];
};

struct fuse_qd_policy_result {
	uint32_t rule_id, target_depth, profile, stable;
	uint32_t read_percent, files, requesters;
	uint64_t stable_ns;
	const char *rule_name;
};

/* Pure policy detector; the caller serializes updates and performs changes. */
struct fuse_qd_policy {
	struct fuse_workload_settings settings;
	const struct fuse_qd_policy_config *config;
	char context[FUSE_QD_POLICY_NAME_SIZE];
	uint64_t last_end_ns, last_window, last_generation, candidate_since;
	uint32_t candidate_rule, candidate_profile;
};

/* Strict text parser; no shell expansion or live reload. Failure leaves an
 * empty table. max_depth returns zero when the named context has no rules.
 */
int fuse_qd_policy_load(const char *path, struct fuse_qd_policy_config *config);
uint32_t fuse_qd_policy_max_depth(const struct fuse_qd_policy_config *config,
				  const char *context);
int fuse_qd_policy_init(struct fuse_qd_policy *policy,
			const struct fuse_qd_policy_config *config,
			const char *context, uint32_t window_ms);
void fuse_qd_policy_reset(struct fuse_qd_policy *policy);
/* NULL detail resets persistence. Malformed snapshots reset and return -EINVAL.
 * No matching rule returns zero with target_depth=0 and rule_id=0.
 */
int fuse_qd_policy_update(struct fuse_qd_policy *policy,
			  const struct fuse_workload_detail *detail,
			  struct fuse_qd_policy_result *result);

#endif
