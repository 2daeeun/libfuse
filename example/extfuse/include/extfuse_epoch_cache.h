/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXTFUSE_EPOCH_CACHE_H__
#define __EXTFUSE_EPOCH_CACHE_H__

#include <linux/fuse.h>
#include <linux/limits.h>
#include <linux/types.h>
#include <linux/xattr.h>

#define EXTFUSE_EPOCH_XATTR_VALUE_MAX 256U
#define EXTFUSE_EPOCH_XATTR_MAX_ENTRIES (1U << 16)

struct extfuse_epoch_entry_key {
	__u64 parent;
	__u32 uid;
	__u32 gid;
	__u32 pid;
	char name[NAME_MAX + 1];
};

struct extfuse_epoch_entry_value {
	__u64 incarnation;
	__u64 namespace_epoch;
	__u64 nlookup;
	struct fuse_entry_out out;
};

/* Driver-owned tokens captured with the exact daemon GETATTR reply. */
struct extfuse_epoch_attr_value {
	__u64 incarnation;
	__u64 attr_epoch;
	struct fuse_attr_out out;
};

/*
 * Xattr permission checks may depend on every request credential exposed in
 * fuse_in_header. Epoch-coherent caching therefore never shares a reply
 * across callers.
 */
struct extfuse_epoch_xattr_key {
	__u64 nodeid;
	__u32 uid;
	__u32 gid;
	__u32 pid;
	char name[XATTR_NAME_MAX + 1];
};

struct extfuse_epoch_xattr_value {
	/* Zero for a value, or positive ENODATA for a cached negative result. */
	__s32 error;
	__u32 size;
	__u32 dependencies;
	__u32 data_valid;
	__u64 incarnation;
	__u64 xattr_epoch;
	__u64 data_epoch;
	__u8 data[EXTFUSE_EPOCH_XATTR_VALUE_MAX];
};

struct extfuse_epoch_mutation_payload {
	struct fuse_mutation_out out;
	struct fuse_mutation_node_out nodes[FUSE_MUTATION_MAX_NODES];
};

union extfuse_epoch_scratch_value {
	struct extfuse_epoch_entry_value entry;
	struct extfuse_epoch_xattr_value xattr;
	struct extfuse_epoch_mutation_payload mutation;
};

union extfuse_epoch_scratch_key {
	struct extfuse_epoch_entry_key entry;
	struct extfuse_epoch_xattr_key xattr;
};

struct extfuse_epoch_scratch {
	union extfuse_epoch_scratch_value value;
	union extfuse_epoch_scratch_key key;
};

#endif /* __EXTFUSE_EPOCH_CACHE_H__ */
