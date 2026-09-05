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

static void test_physical_cores(void)
{
	struct bitmask *allowed = numa_bitmask_alloc(128);
	struct bitmask *local = numa_bitmask_alloc(128);
	struct bitmask *targets = numa_bitmask_alloc(128);
	int cores[128];

	assert(allowed && local && targets);
	for (unsigned int count = 32; count <= 128; count *= 2) {
		for (unsigned int layout = 0; layout < 3; layout++) {
			numa_bitmask_clearall(allowed);
			numa_bitmask_clearall(local);
			numa_bitmask_clearall(targets);
			for (unsigned int cpu = 0; cpu < count; cpu++) {
				/* Adjacent SMT, split SMT and hybrid P/E layouts. */
				cores[cpu] = layout == 0 ? (int)(cpu / 2) :
					layout == 1 ? (int)(cpu % (count / 2)) :
					cpu < 12 ? (int)(cpu / 2) : (int)cpu;
				numa_bitmask_setbit(allowed, cpu);
				numa_bitmask_setbit(local, cpu);
			}
			for (unsigned int qid = 0; qid < count; qid++) {
				int cpu = fuse_uring_select_thread_core(
					qid, allowed, local, cores, count);

				assert(cpu >= 0 && (unsigned int)cpu < count);
				assert(cores[cpu] != cores[qid]);
				assert(!numa_bitmask_isbitset(targets, cpu));
				numa_bitmask_setbit(targets, cpu);
			}
		}
	}
	/* Local NUMA subset: retain a bijection within that node. */
	numa_bitmask_clearall(allowed);
	numa_bitmask_clearall(local);
	for (unsigned int cpu = 0; cpu < 8; cpu++) {
		cores[cpu] = (int)(cpu / 2);
		numa_bitmask_setbit(allowed, cpu);
		if (cpu < 4)
			numa_bitmask_setbit(local, cpu);
	}
	assert(fuse_uring_select_thread_core(0, allowed, local, cores, 8) == 2);
	assert(fuse_uring_select_thread_core(1, allowed, local, cores, 8) == 3);
	/* Missing/incomplete topology and SMT-only masks retain the old policy. */
	assert(fuse_uring_select_thread_core(0, allowed, local, NULL, 0) == 1);
	cores[3] = -1;
	assert(fuse_uring_select_thread_core(0, allowed, local, cores, 8) == 1);
	numa_bitmask_clearall(allowed);
	numa_bitmask_setbit(allowed, 0);
	numa_bitmask_setbit(allowed, 1);
	assert(fuse_uring_select_thread_core(0, allowed, local, cores, 8) == 1);
	/* All queue IDs still honor a daemon pinned to CPU 2. */
	numa_bitmask_clearall(allowed);
	numa_bitmask_setbit(allowed, 2);
	for (unsigned int qid = 0; qid < 128; qid++)
		assert(fuse_uring_select_thread_core(
			qid, allowed, local, cores, 8) == 2);
	numa_bitmask_clearall(allowed);
	assert(fuse_uring_select_thread_core(0, allowed, local, cores, 8) == -1);
	numa_bitmask_free(targets);
	numa_bitmask_free(local);
	numa_bitmask_free(allowed);
}

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

	test_physical_cores();

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
