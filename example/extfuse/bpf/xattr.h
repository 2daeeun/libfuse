#ifndef __EBPF_XATTR_H__
#define __EBPF_XATTR_H__

/*
 * Xattr replies are keyed by the FUSE inode and exact label name.  Values
 * larger than this bounded payload are never inserted and stay on the daemon
 * path.
 */
#define EXTFUSE_XATTR_VALUE_MAX 256U

typedef struct xattr_key {
	__u64 nodeid;
	char name[XATTR_NAME_MAX + 1];
} xattr_key_t;

typedef struct xattr_value {
	/* Zero for a value, or the positive ENODATA cache result. */
	__s32 error;
	__u32 size;
	/* Exact native-I/O state observed before the lower xattr snapshot. */
	__u64 native_state;
	/* Exact daemon-mutation state observed before the lower snapshot. */
	__u64 daemon_state;
	__u8 data[EXTFUSE_XATTR_VALUE_MAX];
} xattr_value_t;

#endif /* __EBPF_XATTR_H__ */
