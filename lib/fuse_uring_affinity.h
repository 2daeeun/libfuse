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

#endif /* LIB_FUSE_URING_AFFINITY_H_ */
