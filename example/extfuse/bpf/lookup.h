#ifndef __EBPF_LOOKUP_H__
#define __EBPF_LOOKUP_H__

typedef struct lookup_entry_key {
    /* parent node id */
    __u64 nodeid;
    /* node name */
    char name[NAME_MAX + 1];
} lookup_entry_key_t;

typedef struct lookup_entry_value {
	__u32 stale;
    __u64 nlookup;	/* ref cnt */
    __u64 nodeid;	/* child node id */
    __u64 generation;
    __u64 entry_valid;
    __u32 entry_valid_nsec;
} lookup_entry_val_t;

/* Match the preserved StackFS/ExtFUSE-1.0 metadata-map budget. */
#define EXTFUSE_METADATA_MAX_ENTRIES (2U << 16)

#endif /* __EBPF_LOOKUP_H__ */
