#ifndef __EBPF_ATTR_H__
#define __EBPF_ATTR_H__

#include <linux/fuse.h>

typedef struct lookup_attr_key {
    /* node id */
    __u64 nodeid;
} lookup_attr_key_t;

typedef struct lookup_attr_value {
	__u32 stale;
	/* Exact native-I/O state observed before the lower attr snapshot. */
	__u64 native_state;
	/* Exact daemon-mutation state observed before the lower snapshot. */
	__u64 daemon_state;
	/* node attr */
	struct fuse_attr_out out;
} lookup_attr_val_t;

#endif /* __EBPF_ATTR_H__ */
