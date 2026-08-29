/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LIBEXTFUSE_H
#define __LIBEXTFUSE_H

#include <errno.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PASSTHRU 1
#define RETURN 0
#define UPCALL (-ENOSYS)

#define MAX_MAPS 32
#define EXTFUSE_HANDLER_SLOTS 128

enum extfuse_data_map {
	EXTFUSE_ENTRY_MAP = 0,
	EXTFUSE_ATTR_MAP,
	EXTFUSE_XATTR_MAP,
	EXTFUSE_DAEMON_IO_MAP,
	EXTFUSE_NATIVE_IO_MAP,
	EXTFUSE_MMAP_MAP,
	EXTFUSE_POLICY_MAP,
	EXTFUSE_V3_ENTRY_MAP,
	EXTFUSE_V3_ATTR_MAP,
	EXTFUSE_V3_XATTR_MAP,
	EXTFUSE_V3_SCRATCH_MAP,
	EXTFUSE_HANDLERS_MAP,
	EXTFUSE_DATA_MAP_COUNT,
};

struct bpf_object;
struct fuse_conn_info;

typedef struct ebpf_context {
	/* Main ExtFUSE program passed in the FUSE_INIT reply. */
	int ctrl_fd;
	/* Named maps in enum extfuse_data_map order. */
	int data_fd[MAX_MAPS];
	/* Owns all program and map file descriptors. */
	struct bpf_object *object;
} ebpf_context_t;

typedef struct ebpf_ctrl_key {
	uint32_t opcode;
} ebpf_ctrl_key_t;

typedef struct ebpf_handler {
	int prog_fd;
} ebpf_handler_t;

/* Load the BPF object. The returned context owns all loaded BPF FDs. */
ebpf_context_t *ebpf_init(const char *filename);
void ebpf_fini(ebpf_context_t *context);

/*
 * Enable ExtFUSE from a libfuse init() callback and put ctrl_fd in the
 * FUSE_INIT response. Keep context alive for at least the mounted session.
 * Returns 0, -EOPNOTSUPP if the kernel did not advertise ExtFUSE, or -EINVAL.
 */
int ebpf_enable_extfuse(ebpf_context_t *context,
			struct fuse_conn_info *conn);

/* Update the handlers prog-array for one FUSE opcode. */
int ebpf_ctrl_update(ebpf_context_t *context,
		     const ebpf_ctrl_key_t *key,
		     const ebpf_handler_t *handler);
int ebpf_ctrl_delete(ebpf_context_t *context,
		     const ebpf_ctrl_key_t *key);

/* Data-map accessors. */
int ebpf_data_next(ebpf_context_t *context, const void *key, void *next,
		   int idx);
int ebpf_data_lookup(ebpf_context_t *context, const void *key, void *value,
		     int idx);
int ebpf_data_update(ebpf_context_t *context, const void *key,
		     const void *value, int idx, int overwrite);
/* Replace an existing element with BPF_EXIST; never create a missing row. */
int ebpf_data_replace(ebpf_context_t *context, const void *key,
		      const void *value, int idx);
int ebpf_data_delete(ebpf_context_t *context, const void *key, int idx);

#ifdef __cplusplus
}
#endif

#endif /* __LIBEXTFUSE_H */
