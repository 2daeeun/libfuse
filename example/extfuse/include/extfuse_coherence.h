/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXTFUSE_COHERENCE_H__
#define __EXTFUSE_COHERENCE_H__

#include <linux/types.h>

/* READ changes attrs (atime), not xattrs. Each domain has its own token. */
struct extfuse_io_state {
	__u64 attr_state;
	__u64 xattr_state;
};

/* Packed per-node state shared by BPF handlers and the userspace cache. */
#define EXTFUSE_NATIVE_STATE_ACTIVE_BITS 16U
#define EXTFUSE_NATIVE_STATE_ACTIVE_MASK \
	((1ULL << EXTFUSE_NATIVE_STATE_ACTIVE_BITS) - 1)
#define EXTFUSE_NATIVE_STATE_SEQUENCE_ONE \
	(1ULL << EXTFUSE_NATIVE_STATE_ACTIVE_BITS)
#define EXTFUSE_NATIVE_STATE_SEQUENCE_MAX \
	((1ULL << (64U - EXTFUSE_NATIVE_STATE_ACTIVE_BITS)) - 1)

/*
 * Request-count policy shared by the daemon and BPF handlers.  Paper-like
 * WBCache forwarding uses the ordinary READ/WRITE handlers without the
 * coherence-epochs bit; the strict gate combines both bits and enables the
 * private BEGIN/END protocol. Paper READ also uses the attr-only map guard,
 * without enabling the full kernel epoch protocol.
 */
/* Bit zero is retired: cached atime must not survive an unguarded READ. */
#define EXTFUSE_POLICY_RELAX_NATIVE_MMAP_METADATA (1U << 1)
#define EXTFUSE_POLICY_ATTR_RELEASE_BARRIER (1U << 2)
#define EXTFUSE_POLICY_COHERENCE_EPOCHS (1U << 3)
#define EXTFUSE_POLICY_WBCACHE_PASSTHROUGH (1U << 4)
#define EXTFUSE_POLICY_PAPER_CAPABILITY_ENODATA (1U << 5)
#define EXTFUSE_POLICY_PAPER_WRITE_FAST (1U << 6)
#define EXTFUSE_POLICY_KNOWN_MASK \
	(EXTFUSE_POLICY_RELAX_NATIVE_MMAP_METADATA | \
	 EXTFUSE_POLICY_ATTR_RELEASE_BARRIER | \
	 EXTFUSE_POLICY_COHERENCE_EPOCHS | \
	 EXTFUSE_POLICY_WBCACHE_PASSTHROUGH | \
	 EXTFUSE_POLICY_PAPER_CAPABILITY_ENODATA | \
	 EXTFUSE_POLICY_PAPER_WRITE_FAST)

#endif /* __EXTFUSE_COHERENCE_H__ */
