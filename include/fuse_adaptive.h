/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef FUSE_ADAPTIVE_H
#define FUSE_ADAPTIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fuse_session;

enum fuse_uring_runtime_phase {
	FUSE_URING_RUNTIME_IDLE,
	FUSE_URING_RUNTIME_PREPARING,
	FUSE_URING_RUNTIME_DRAINING,
	FUSE_URING_RUNTIME_RECONFIGURING,
	FUSE_URING_RUNTIME_RECLAIMING,
	FUSE_URING_RUNTIME_COMPLETE,
	FUSE_URING_RUNTIME_FAILED,
};

/* Experimental local API, enabled with -o io_uring_adaptive. */
struct fuse_uring_runtime_queue_status {
	uint32_t qid, current_depth, target_depth, phase;
	int32_t error;
	uint64_t generation, payload_bytes, registered_bytes, reclaim_bytes;
};

struct fuse_uring_runtime_status {
	uint64_t transaction;
	uint32_t max_depth, nr_queues, busy;
	int32_t error;
};

enum fuse_workload_class {
	FUSE_WORKLOAD_RR_1T_1F,
	FUSE_WORKLOAD_RR_NT_1F,
	FUSE_WORKLOAD_RW_1T_1F,
	FUSE_WORKLOAD_RW_NT_1F,
	FUSE_WORKLOAD_SR_1T_1F,
	FUSE_WORKLOAD_SR_NT_NF,
	FUSE_WORKLOAD_SW_1T_1F,
	FUSE_WORKLOAD_SW_NT_NF,
	FUSE_WORKLOAD_UNKNOWN,
	FUSE_WORKLOAD_MIXED,
	FUSE_WORKLOAD_IDLE,
};

struct fuse_workload_settings {
	uint32_t window_ms, stable_ms, min_requests, min_pairs;
	uint32_t dominance_percent, sequential_percent, random_percent,
		reserved;
	uint64_t thresholds[3];
};

enum fuse_workload_observation_flag {
	FUSE_WORKLOAD_FLAG_WORKER = 1U << 0,
	FUSE_WORKLOAD_FLAG_APPEND = 1U << 1,
	FUSE_WORKLOAD_FLAG_PASSTHROUGH = 1U << 2,
	FUSE_WORKLOAD_FLAG_DAX = 1U << 3,
};

struct fuse_workload_result {
	uint64_t timestamp_ns, stable_ns, requests, bytes;
	uint64_t min_size, max_size, generation;
	uint32_t workload, profile, operation, files, requesters, flags;
	uint32_t dominant_percent, sequential_percent, stable,
		policy_configured;
};

/* profile: 0..3, operation: 0=read/1=write; UINT32_MAX when undetermined.
 * files/requesters: 0, 1, or 2 (two or more); not exact cardinalities.
 * min_size/max_size measure requested iter bytes, not completed bytes.
 * stable is legacy detector readiness; policy_configured reports whether an
 * explicit host/case policy was selected. Mixed policy readiness is reported
 * separately by the control socket's policy_stable field.
 */

/** Enqueue a session-wide depth change; negative errno on failure/busy.
 * The returned transaction identifies an asynchronous, per-queue operation.
 * The caller must keep the session alive for the duration of every API call.
 */
int fuse_session_uring_set_depth(struct fuse_session *se, uint32_t depth,
				 uint64_t *transaction);
/** Return queue count, or negative errno; capacity=0 queries count only. */
int fuse_session_uring_get_status(
	struct fuse_session *se, struct fuse_uring_runtime_status *status,
	struct fuse_uring_runtime_queue_status *queues, size_t capacity);
int fuse_session_workload_get(struct fuse_session *se,
			      struct fuse_workload_result *result);
/** Replace detector settings asynchronously and reset persistence immediately.
 * A zero return means accepted; workload_get reports later kernel errors.
 * With a policy file selected, only identical settings are accepted (reset);
 * attempts to override file settings return -EPERM.
 */
int fuse_session_workload_configure(
	struct fuse_session *se, const struct fuse_workload_settings *settings);

#ifdef __cplusplus
}
#endif
#endif
