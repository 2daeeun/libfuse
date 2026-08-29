/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  The libfuse authors
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt.
 */

#include "fuse_uring_affinity.h"

#include <assert.h>
#include <numa.h>
#include <stddef.h>

static void set_mask(struct bitmask *mask, const unsigned int *cpus,
		     size_t count)
{
	numa_bitmask_clearall(mask);
	for (size_t index = 0; index < count; index++)
		numa_bitmask_setbit(mask, cpus[index]);
}

int main(void)
{
	const unsigned int cpu0[] = { 0 };
	const unsigned int cpu2[] = { 2 };
	const unsigned int cpu01[] = { 0, 1 };
	const unsigned int cpu02[] = { 0, 2 };
	const unsigned int cpu0123[] = { 0, 1, 2, 3 };
	struct bitmask *allowed_cpus = numa_bitmask_alloc(8);
	struct bitmask *local_cpus = numa_bitmask_alloc(8);

	assert(allowed_cpus != NULL);
	assert(local_cpus != NULL);
	assert(fuse_uring_affinity_query_failed(-1));
	assert(!fuse_uring_affinity_query_failed(0));
	assert(!fuse_uring_affinity_query_failed(16));

	set_mask(allowed_cpus, cpu0123, 4);
	set_mask(local_cpus, cpu01, 2);
	assert(fuse_uring_select_thread_cpu(0, allowed_cpus, local_cpus) == 1);
	assert(fuse_uring_select_thread_cpu(1, allowed_cpus, local_cpus) == 0);

	set_mask(allowed_cpus, cpu02, 2);
	set_mask(local_cpus, cpu0, 1);
	assert(fuse_uring_select_thread_cpu(0, allowed_cpus, local_cpus) == 2);

	set_mask(allowed_cpus, cpu0, 1);
	assert(fuse_uring_select_thread_cpu(0, allowed_cpus, local_cpus) == 0);

	set_mask(allowed_cpus, cpu2, 1);
	set_mask(local_cpus, cpu2, 1);
	assert(fuse_uring_select_thread_cpu(0, allowed_cpus, local_cpus) == 2);

	numa_bitmask_clearall(allowed_cpus);
	assert(fuse_uring_select_thread_cpu(0, allowed_cpus, local_cpus) == -1);

	set_mask(allowed_cpus, cpu01, 2);
	assert(fuse_uring_select_thread_cpu(0, allowed_cpus, NULL) == 1);

	numa_bitmask_free(local_cpus);
	numa_bitmask_free(allowed_cpus);
	return 0;
}
