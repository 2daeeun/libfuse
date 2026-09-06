/* SPDX-License-Identifier: GPL-2.0 */
#ifndef EXTFUSE_BACKGROUND_LIMITS_H
#define EXTFUSE_BACKGROUND_LIMITS_H

#include <sched.h>

#include <fuse_lowlevel.h>

static inline unsigned int perf_background_allowed_cpus(void)
{
	cpu_set_t mask;
	int count;

	CPU_ZERO(&mask);
	if (sched_getaffinity(0, sizeof(mask), &mask))
		return 1;
	count = CPU_COUNT(&mask);
	return count > 0 ? (unsigned int)count : 1;
}

static inline unsigned int
perf_background_default(unsigned int allowed_cpus)
{
	/* Two requests per CPU, with a 32 MiB ceiling at 128 KiB per request. */
	if (allowed_cpus >= 128)
		return 256;
	if (allowed_cpus <= 6)
		return 12;
	return 2 * allowed_cpus;
}

static inline void
perf_background_apply(struct fuse_conn_info *conn,
		      struct fuse_conn_info_opts *opts,
		      unsigned int allowed_cpus)
{
	/*
	 * The same bound serves daemon and kernel-forwarded I/O.  Apply explicit
	 * mount options last, including max_background=0 (kernel default).
	 * Leave congestion at its incoming value: libfuse derives 75% when zero.
	 */
	conn->max_background = perf_background_default(allowed_cpus);
	fuse_apply_conn_info_opts(opts, conn);
}

#endif /* EXTFUSE_BACKGROUND_LIMITS_H */
