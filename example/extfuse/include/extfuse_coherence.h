/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXTFUSE_COHERENCE_H__
#define __EXTFUSE_COHERENCE_H__

/* Packed per-node state shared by BPF handlers and the userspace cache. */
#define EXTFUSE_NATIVE_STATE_ACTIVE_BITS 16U
#define EXTFUSE_NATIVE_STATE_ACTIVE_MASK \
	((1ULL << EXTFUSE_NATIVE_STATE_ACTIVE_BITS) - 1)
#define EXTFUSE_NATIVE_STATE_SEQUENCE_ONE \
	(1ULL << EXTFUSE_NATIVE_STATE_ACTIVE_BITS)
#define EXTFUSE_NATIVE_STATE_SEQUENCE_MAX \
	((1ULL << (64U - EXTFUSE_NATIVE_STATE_ACTIVE_BITS)) - 1)

/*
 * Request-count policy shared by the daemon and BPF handlers.  These flags
 * deliberately relax metadata freshness only for the paper-like profile;
 * the functional gate leaves the policy map at zero.
 */
#define EXTFUSE_POLICY_RELAX_NATIVE_READ_METADATA (1U << 0)
#define EXTFUSE_POLICY_RELAX_NATIVE_MMAP_METADATA (1U << 1)
#define EXTFUSE_POLICY_ATTR_RELEASE_BARRIER (1U << 2)
#define EXTFUSE_POLICY_KNOWN_MASK \
	(EXTFUSE_POLICY_RELAX_NATIVE_READ_METADATA | \
	 EXTFUSE_POLICY_RELAX_NATIVE_MMAP_METADATA | \
	 EXTFUSE_POLICY_ATTR_RELEASE_BARRIER)

#endif /* __EXTFUSE_COHERENCE_H__ */
