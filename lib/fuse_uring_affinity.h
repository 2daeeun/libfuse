/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2026  The libfuse authors
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt.
 */

#ifndef LIB_FUSE_URING_AFFINITY_H_
#define LIB_FUSE_URING_AFFINITY_H_

#include <limits.h>
#include <numa.h>
#include <stdbool.h>
#include <stdlib.h>

static inline bool fuse_uring_affinity_query_failed(int result)
{
	return result < 0;
}

static inline int
fuse_uring_select_thread_cpu(unsigned int qid,
			     const struct bitmask *allowed_cpus,
			     const struct bitmask *local_cpus)
{
	unsigned int base_cpu;
	unsigned int cpu;
	unsigned int nr_cpus;
	unsigned int offset;

	if (allowed_cpus == NULL || allowed_cpus->size == 0 ||
	    allowed_cpus->size > INT_MAX)
		return -1;

	nr_cpus = (unsigned int)allowed_cpus->size;
	base_cpu = qid % nr_cpus;

	/* Prefer a different allowed CPU on the queue's NUMA node. */
	if (local_cpus != NULL) {
		for (offset = 1; offset < nr_cpus; offset++) {
			cpu = (base_cpu + offset) % nr_cpus;
			if (numa_bitmask_isbitset(allowed_cpus, cpu) &&
			    cpu < local_cpus->size &&
			    numa_bitmask_isbitset(local_cpus, cpu))
				return (int)cpu;
		}
	}

	/* A remote CPU is still preferable to sharing the request CPU. */
	for (offset = 1; offset < nr_cpus; offset++) {
		cpu = (base_cpu + offset) % nr_cpus;
		if (numa_bitmask_isbitset(allowed_cpus, cpu))
			return (int)cpu;
	}

	/* A single-CPU affinity mask has no separate worker CPU. */
	if (numa_bitmask_isbitset(allowed_cpus, base_cpu))
		return (int)base_cpu;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		if (numa_bitmask_isbitset(allowed_cpus, cpu))
			return (int)cpu;
	}

	return -1;
}

/*
 * Use a common rotation of the allowed CPUs on this NUMA node. Merely picking
 * the next non-sibling for each qid can put multiple queues on the same CPU;
 * a valid rotation is a permutation, with no SMT sibling of any request CPU.
 * core_ids contain the first CPU in each sysfs thread_siblings_list, which is
 * unique across packages (unlike core_id). Unknown topology retains the old
 * policy, as do masks that cannot provide a separate physical core.
 */
static inline int
fuse_uring_select_thread_core(unsigned int qid,
			      const struct bitmask *allowed_cpus,
			      const struct bitmask *local_cpus,
			      const int *core_ids, size_t nr_core_ids)
{
	unsigned int *cpus;
	size_t count = 0;
	size_t own_index = 0;
	bool found = false;
	int target = -1;

	if (!core_ids || !allowed_cpus || !allowed_cpus->size ||
	    allowed_cpus->size > INT_MAX)
		goto fallback;
	cpus = calloc(allowed_cpus->size, sizeof(*cpus));
	if (!cpus)
		goto fallback;
	for (unsigned int cpu = 0; cpu < allowed_cpus->size; cpu++) {
		if (!numa_bitmask_isbitset(allowed_cpus, cpu) ||
		    (local_cpus && (cpu >= local_cpus->size ||
				    !numa_bitmask_isbitset(local_cpus, cpu))))
			continue;
		if (cpu >= nr_core_ids || core_ids[cpu] < 0)
			goto out;
		if (cpu == qid) {
			own_index = count;
			found = true;
		}
		cpus[count++] = cpu;
	}
	/* In particular, preserve externally pinned single-worker experiments. */
	if (!found)
		goto out;
	for (size_t stride = 1; stride < count; stride++) {
		bool distinct = true;

		for (size_t index = 0; index < count; index++) {
			if (core_ids[cpus[index]] ==
			    core_ids[cpus[(index + stride) % count]]) {
				distinct = false;
				break;
			}
		}
		if (distinct) {
			target = (int)cpus[(own_index + stride) % count];
			break;
		}
	}
out:
	free(cpus);
	if (target >= 0)
		return target;
fallback:
	return fuse_uring_select_thread_cpu(qid, allowed_cpus, local_cpus);
}

#endif /* LIB_FUSE_URING_AFFINITY_H_ */
