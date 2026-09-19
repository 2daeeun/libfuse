// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fuse_workload.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

#define NS_PER_MS UINT64_C(1000000)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

void fuse_workload_defaults(struct fuse_workload_settings *settings)
{
	*settings = (struct fuse_workload_settings){
		.window_ms = 1000,
		.stable_ms = 10000,
		.min_requests = 16,
		.min_pairs = 16,
		.dominance_percent = 80,
		.sequential_percent = 80,
		.random_percent = 20,
		.thresholds = { 32768, 131072, 1048576 },
	};
}

int fuse_workload_validate(const struct fuse_workload_settings *settings)
{
	if (!settings || !settings->window_ms || settings->window_ms > INT_MAX ||
	    settings->stable_ms < settings->window_ms ||
	    !settings->min_requests || !settings->min_pairs ||
	    settings->dominance_percent <= 50 ||
	    settings->dominance_percent > 100 ||
	    settings->sequential_percent <= 50 ||
	    settings->sequential_percent > 100 ||
	    settings->random_percent >= 50 || settings->reserved ||
	    !settings->thresholds[0] ||
	    settings->thresholds[0] >= settings->thresholds[1] ||
	    settings->thresholds[1] >= settings->thresholds[2])
		return -EINVAL;
	return 0;
}

void fuse_workload_detector_reset(struct fuse_workload_detector *detector)
{
	detector->last_end_ns = 0;
	detector->last_window = 0;
	detector->last_generation = 0;
	detector->candidate_since = 0;
	detector->candidate_profile = UINT32_MAX;
	detector->candidate_workload = FUSE_WORKLOAD_UNKNOWN;
}

int fuse_workload_detector_init(struct fuse_workload_detector *detector,
				const struct fuse_workload_settings *settings)
{
	if (!detector || fuse_workload_validate(settings))
		return -EINVAL;
	detector->settings = *settings;
	fuse_workload_detector_reset(detector);
	return 0;
}

static unsigned int percent(uint64_t value, uint64_t total)
{
	unsigned int low = 0, high = 100;

	if (!total)
		return 0;
	if (value <= UINT64_MAX / 100)
		return (unsigned int)(value * 100 / total);
	/* Avoid both overflow and a dependency on 128-bit integer support. */
	while (low < high) {
		unsigned int mid = low + (high - low + 1) / 2;
		uint64_t cutoff =
			total / 100 * mid + (total % 100 * mid + 99) / 100;

		if (value >= cutoff)
			low = mid;
		else
			high = mid - 1;
	}
	return low;
}

static bool sum(uint64_t *total, uint64_t value)
{
	if (UINT64_MAX - *total < value)
		return false;
	*total += value;
	return true;
}

static unsigned int classify(bool write, bool sequential, unsigned int files,
			     unsigned int requesters)
{
	if (!sequential && files == 1) {
		if (requesters == 1)
			return write ? FUSE_WORKLOAD_RW_1T_1F :
				       FUSE_WORKLOAD_RR_1T_1F;
		if (requesters == 2)
			return write ? FUSE_WORKLOAD_RW_NT_1F :
				       FUSE_WORKLOAD_RR_NT_1F;
	}
	if (sequential) {
		if (files == 1 && requesters == 1)
			return write ? FUSE_WORKLOAD_SW_1T_1F :
				       FUSE_WORKLOAD_SR_1T_1F;
		if (files == 2 && requesters == 2)
			return write ? FUSE_WORKLOAD_SW_NT_NF :
				       FUSE_WORKLOAD_SR_NT_NF;
	}
	return FUSE_WORKLOAD_UNKNOWN;
}

int fuse_workload_detector_update(struct fuse_workload_detector *detector,
				  const struct fuse_workload_snapshot *snapshot,
				  struct fuse_workload_result *result)
{
	const struct fuse_workload_settings *settings;
	const struct fuse_workload_op_stats *op;
	uint64_t count[2] = { 0, 0 }, window_ns, duration;
	unsigned int rw, bucket, dominant = 0;
	bool sequential;

	if (!detector || !result)
		return -EINVAL;
	*result = (struct fuse_workload_result){
		.workload = FUSE_WORKLOAD_UNKNOWN,
		.profile = UINT32_MAX,
		.operation = UINT32_MAX,
	};
	if (!snapshot) {
		fuse_workload_detector_reset(detector);
		return 0;
	}
	settings = &detector->settings;
	if (snapshot->version != FUSE_WORKLOAD_VERSION ||
	    snapshot->end_ns <= snapshot->start_ns || !snapshot->generation ||
	    !snapshot->window_id)
		goto invalid;
	for (rw = 0; rw < 2; rw++) {
		op = &snapshot->op[rw];
		for (bucket = 0; bucket < 4; bucket++) {
			if (!sum(&count[rw], op->count[bucket]) ||
			    !sum(&result->bytes, op->bytes[bucket]))
				goto invalid;
		}
		if (!sum(&result->requests, count[rw]) ||
		    op->seq_contiguous > op->seq_pairs ||
		    op->seq_pairs > count[rw] || op->files > 2 ||
		    op->requesters > 2 ||
		    (count[rw] &&
		     (!op->min_size || !op->files || !op->requesters ||
		      op->min_size > op->max_size)))
			goto invalid;
	}
	result->timestamp_ns = snapshot->end_ns;
	result->generation = snapshot->generation;
	result->flags = snapshot->flags;
	window_ns = (uint64_t)settings->window_ms * NS_PER_MS;
	duration = snapshot->end_ns - snapshot->start_ns;
	if (snapshot->generation != detector->last_generation ||
	    snapshot->window_id != detector->last_window + 1 ||
	    snapshot->start_ns != detector->last_end_ns)
		fuse_workload_detector_reset(detector);
	detector->last_generation = snapshot->generation;
	detector->last_window = snapshot->window_id;
	detector->last_end_ns = snapshot->end_ns;
	if (duration < window_ns / 2 || duration > window_ns * 2)
		goto unknown;
	if (!result->requests) {
		result->workload = FUSE_WORKLOAD_IDLE;
		goto unknown;
	}
	if (result->requests < settings->min_requests)
		goto unknown;
	rw = count[1] > count[0];
	if (percent(count[rw], result->requests) <
	    settings->dominance_percent) {
		result->workload = FUSE_WORKLOAD_MIXED;
		goto unknown;
	}
	op = &snapshot->op[rw];
	result->operation = rw;
	result->files = op->files;
	result->requesters = op->requesters;
	result->min_size = op->min_size;
	result->max_size = op->max_size;
	for (bucket = 1; bucket < 4; bucket++)
		if (op->count[bucket] > op->count[dominant])
			dominant = bucket;
	result->dominant_percent = percent(op->count[dominant], count[rw]);
	if (result->dominant_percent < settings->dominance_percent) {
		result->workload = FUSE_WORKLOAD_MIXED;
		goto unknown;
	}
	result->profile = dominant;
	/* Native/WBCache dispatch follows the same app-facing iter observation.
	 * Preserve the provenance bit; all other limitations remain fail-closed.
	 */
	if ((snapshot->flags & ~FUSE_WORKLOAD_PASSTHROUGH) ||
	    op->seq_pairs < settings->min_pairs)
		goto unknown;
	result->sequential_percent = percent(op->seq_contiguous, op->seq_pairs);
	sequential = result->sequential_percent >= settings->sequential_percent;
	if (!sequential &&
	    op->seq_contiguous >
		    op->seq_pairs / 100 * settings->random_percent +
			    op->seq_pairs % 100 * settings->random_percent /
				    100)
		goto unknown;
	result->workload = classify(rw, sequential, op->files, op->requesters);
	if (result->workload >= FUSE_WORKLOAD_UNKNOWN)
		goto unknown;
	if (detector->candidate_profile != result->profile ||
	    detector->candidate_workload != result->workload) {
		detector->candidate_profile = result->profile;
		detector->candidate_workload = result->workload;
		detector->candidate_since = snapshot->end_ns;
	}
	result->stable_ns = snapshot->end_ns - detector->candidate_since;
	result->stable = result->stable_ns >=
			 (uint64_t)settings->stable_ms * NS_PER_MS;
	/* Policy is deliberately absent; detection never changes configuration. */
	return 0;
unknown:
	detector->candidate_profile = UINT32_MAX;
	detector->candidate_workload = FUSE_WORKLOAD_UNKNOWN;
	detector->candidate_since = 0;
	return 0;
invalid:
	fuse_workload_detector_reset(detector);
	return -EINVAL;
}

const char *fuse_workload_name(unsigned int workload)
{
	static const char *const names[] = {
		"RR_1T_1F", "RR_NT_1F", "RW_1T_1F", "RW_NT_1F",
		"SR_1T_1F", "SR_NT_NF", "SW_1T_1F", "SW_NT_NF",
		"UNKNOWN",  "MIXED",	"IDLE",
	};

	return workload < ARRAY_SIZE(names) ? names[workload] : "UNKNOWN";
}
