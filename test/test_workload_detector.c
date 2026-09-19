// SPDX-License-Identifier: LGPL-2.1-or-later
/* Pure detector tests: no mount, privileges, kernel changes, or timing sleeps. */
#include "../lib/fuse_workload.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define SECOND UINT64_C(1000000000)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static struct fuse_workload_snapshot sample(unsigned int second, unsigned int rw,
					   unsigned int profile, uint64_t size,
					   unsigned int files,
					   unsigned int requesters,
					   unsigned int contiguous)
{
	struct fuse_workload_snapshot snapshot = {
		.version = FUSE_WORKLOAD_VERSION,
		.generation = 1,
		.window_id = second,
		.start_ns = second * SECOND,
		.end_ns = (second + 1) * SECOND,
	};
	struct fuse_workload_op_stats *op = &snapshot.op[rw];

	op->count[profile] = 100;
	op->bytes[profile] = 100 * size;
	op->min_size = op->max_size = size;
	op->seq_pairs = 99;
	op->seq_contiguous = contiguous;
	op->files = files;
	op->requesters = requesters;
	return snapshot;
}

static void classes_and_sizes(struct fuse_workload_detector *detector)
{
	static const struct {
		unsigned int rw, files, requesters, sequential, expected;
	} cases[] = {
		{ 0, 1, 1, 0, FUSE_WORKLOAD_RR_1T_1F },
		{ 0, 1, 2, 0, FUSE_WORKLOAD_RR_NT_1F },
		{ 1, 1, 1, 0, FUSE_WORKLOAD_RW_1T_1F },
		{ 1, 1, 2, 0, FUSE_WORKLOAD_RW_NT_1F },
		{ 0, 1, 1, 99, FUSE_WORKLOAD_SR_1T_1F },
		{ 0, 2, 2, 98, FUSE_WORKLOAD_SR_NT_NF },
		{ 1, 1, 1, 99, FUSE_WORKLOAD_SW_1T_1F },
		{ 1, 2, 2, 98, FUSE_WORKLOAD_SW_NT_NF },
		{ 0, 2, 1, 99, FUSE_WORKLOAD_UNKNOWN },
		{ 1, 1, 2, 99, FUSE_WORKLOAD_UNKNOWN },
		{ 0, 2, 2, 0, FUSE_WORKLOAD_UNKNOWN },
	};
	static const struct {
		uint64_t size;
		unsigned int profile;
	} sizes[] = {
		{ 4096, 0 },	{ 8192, 0 },   { 16384, 0 },   { 32767, 0 },
		{ 32768, 1 },	{ 65536, 1 },  { 131071, 1 },  { 131072, 2 },
		{ 262144, 2 },	{ 524288, 2 }, { 1048575, 2 }, { 1048576, 3 },
		{ 2097152, 3 },
	};
	struct fuse_workload_snapshot snapshot;
	struct fuse_workload_result result;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		fuse_workload_detector_reset(detector);
		snapshot = sample(1, cases[i].rw, 0, 16384, cases[i].files,
				  cases[i].requesters, cases[i].sequential);
		assert(!fuse_workload_detector_update(detector, &snapshot,
						      &result));
		assert(result.workload == cases[i].expected);
		assert(!result.stable && !result.policy_configured);
	}
	/* The wire profile comes from the kernel; the raw sizes remain arbitrary. */
	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		snapshot =
			sample(1, 1, sizes[i].profile, sizes[i].size, 1, 2, 0);
		assert(!fuse_workload_detector_update(detector, &snapshot,
						      &result));
		assert(result.profile == sizes[i].profile);
		assert(result.min_size == sizes[i].size);
		assert(result.max_size == sizes[i].size);
	}
}

static void persistence(struct fuse_workload_detector *detector)
{
	struct fuse_workload_snapshot snapshot;
	struct fuse_workload_result result;
	unsigned int i;

	fuse_workload_detector_reset(detector);
	for (i = 1; i <= 11; i++) {
		snapshot = sample(i, 1, 0, 16384, 1, 2, 0);
		assert(!fuse_workload_detector_update(detector, &snapshot,
						      &result));
		assert(result.stable_ns == (i - 1) * SECOND);
		assert(result.stable == (i == 11));
	}
	/* Size changes inside one profile retain continuity. */
	snapshot = sample(12, 1, 0, 8192, 1, 2, 0);
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.stable && result.stable_ns == 11 * SECOND);
	/* Size profile changes without application restart reset the timer. */
	snapshot = sample(13, 1, 1, 65536, 1, 2, 0);
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.profile == 1 && !result.stable && !result.stable_ns);
	/* A missing snapshot, reconfiguration, and I/O idle each reset it. */
	snapshot = sample(15, 1, 1, 65536, 1, 2, 0);
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(!result.stable_ns);
	snapshot = sample(16, 1, 1, 65536, 1, 2, 0);
	snapshot.generation = 2;
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(!result.stable_ns);
	snapshot = sample(17, 1, 1, 65536, 1, 2, 0);
	memset(snapshot.op, 0, sizeof(snapshot.op));
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.workload == FUSE_WORKLOAD_IDLE && !result.stable_ns);
	assert(!fuse_workload_detector_update(detector, NULL, &result));
	assert(result.workload == FUSE_WORKLOAD_UNKNOWN);
	snapshot = sample(18, 1, 1, 65536, 1, 2, 0);
	snapshot.end_ns += 3 * SECOND;
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.workload == FUSE_WORKLOAD_UNKNOWN);
}

static void mixed_and_limited(struct fuse_workload_detector *detector)
{
	struct fuse_workload_snapshot snapshot;
	struct fuse_workload_result result;
	unsigned int flag;

	/* Request-count dominance, not byte-weighted mean: 4K wins over 1M. */
	snapshot = sample(1, 1, 0, 4096, 1, 1, 0);
	snapshot.op[1].count[3] = 10;
	snapshot.op[1].bytes[3] = 10 * 1048576;
	snapshot.op[1].max_size = 1048576;
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.profile == 0 && result.dominant_percent == 90);
	assert(result.min_size == 4096 && result.max_size == 1048576);
	snapshot.op[1].count[3] = 100;
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.workload == FUSE_WORKLOAD_MIXED);
	snapshot = sample(1, 1, 0, 4096, 1, 1, 0);
	snapshot.op[0] = snapshot.op[1];
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.workload == FUSE_WORKLOAD_MIXED);
	for (flag = FUSE_WORKLOAD_WORKER; flag <= FUSE_WORKLOAD_DAX;
	     flag <<= 1) {
		if (flag == FUSE_WORKLOAD_PASSTHROUGH)
			continue;
		snapshot = sample(1, 1, 0, 4096, 1, 1, 99);
		snapshot.flags = flag;
		assert(!fuse_workload_detector_update(detector, &snapshot,
						      &result));
		assert(result.workload == FUSE_WORKLOAD_UNKNOWN);
		assert(result.flags == flag);
	}
	snapshot = sample(1, 1, 0, 4096, 1, 1, 20);
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.workload == FUSE_WORKLOAD_UNKNOWN); /* 20/99 > 20%. */
	snapshot.op[1].seq_pairs = 1;
	snapshot.op[1].seq_contiguous = 0;
	assert(!fuse_workload_detector_update(detector, &snapshot, &result));
	assert(result.workload == FUSE_WORKLOAD_UNKNOWN);
}

static void passthrough_classes(struct fuse_workload_detector *detector)
{
	static const unsigned int restricted[] = {
		FUSE_WORKLOAD_WORKER, FUSE_WORKLOAD_APPEND, FUSE_WORKLOAD_DAX,
		1U << 31,
	};
	static const uint64_t sizes[] = { 4096, 32768, 131072, 1048576 };
	unsigned int rw, sequential, multi, profile, second, i;
	struct fuse_workload_snapshot snapshot;
	struct fuse_workload_result result;

	for (rw = 0; rw < 2; rw++)
		for (sequential = 0; sequential < 2; sequential++)
			for (multi = 0; multi < 2; multi++)
				for (profile = 0; profile < 4; profile++) {
					unsigned int expected = sequential ?
						(rw ? FUSE_WORKLOAD_SW_1T_1F :
						      FUSE_WORKLOAD_SR_1T_1F) :
						(rw ? FUSE_WORKLOAD_RW_1T_1F :
						      FUSE_WORKLOAD_RR_1T_1F);

					fuse_workload_detector_reset(detector);
					for (second = 1; second <= 11; second++) {
						snapshot = sample(second, rw, profile,
								  sizes[profile],
								  sequential && multi ? 2 : 1,
								  multi ? 2 : 1,
								  sequential ? 99 : 0);
						snapshot.flags = FUSE_WORKLOAD_PASSTHROUGH;
						assert(!fuse_workload_detector_update(
							detector, &snapshot, &result));
						assert(result.workload == expected + multi);
						assert(result.profile == profile);
						assert(result.flags == FUSE_WORKLOAD_PASSTHROUGH);
						assert(result.stable == (second == 11));
						assert(!result.policy_configured);
					}
				}
	for (i = 0; i < ARRAY_SIZE(restricted); i++) {
		snapshot = sample(12, 1, 3, 1048576, 2, 2, 99);
		snapshot.flags = FUSE_WORKLOAD_PASSTHROUGH | restricted[i];
		assert(!fuse_workload_detector_update(detector, &snapshot, &result));
		assert(result.workload == FUSE_WORKLOAD_UNKNOWN && !result.stable);
		assert(result.flags == snapshot.flags);
		snapshot = sample(13, 1, 3, 1048576, 2, 2, 99);
		snapshot.flags = FUSE_WORKLOAD_PASSTHROUGH;
		assert(!fuse_workload_detector_update(detector, &snapshot, &result));
		assert(!result.stable && !result.stable_ns);
	}
}

static void invalid_input(struct fuse_workload_detector *detector)
{
	struct fuse_workload_snapshot snapshot;
	struct fuse_workload_result result;
	struct fuse_workload_settings settings;

	fuse_workload_defaults(&settings);
	settings.thresholds[1] = settings.thresholds[0];
	assert(fuse_workload_validate(&settings) == -EINVAL);
	fuse_workload_defaults(&settings);
	settings.dominance_percent = 50;
	assert(fuse_workload_validate(&settings) == -EINVAL);
	fuse_workload_defaults(&settings);
	settings.window_ms = UINT32_MAX;
	settings.stable_ms = UINT32_MAX;
	assert(fuse_workload_validate(&settings) == -EINVAL);
	snapshot = sample(1, 1, 0, 4096, 1, 1, 99);
	snapshot.version++;
	assert(fuse_workload_detector_update(detector, &snapshot, &result) ==
	       -EINVAL);
	snapshot.version--;
	snapshot.op[1].seq_contiguous = 100;
	assert(fuse_workload_detector_update(detector, &snapshot, &result) ==
	       -EINVAL);
	snapshot.op[1].seq_contiguous = 0;
	snapshot.op[1].count[1] = UINT64_MAX;
	assert(fuse_workload_detector_update(detector, &snapshot, &result) ==
	       -EINVAL);
}

int main(void)
{
	struct fuse_workload_settings settings;
	struct fuse_workload_detector detector;

	fuse_workload_defaults(&settings);
	assert(!fuse_workload_detector_init(&detector, &settings));
	classes_and_sizes(&detector);
	persistence(&detector);
	mixed_and_limited(&detector);
	passthrough_classes(&detector);
	invalid_input(&detector);
	assert(!strcmp(fuse_workload_name(FUSE_WORKLOAD_RW_NT_1F), "RW_NT_1F"));
	puts("workload detector: PASS");
	return 0;
}
