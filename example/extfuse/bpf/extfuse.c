#include <linux/bpf.h>
#include <linux/xattr.h>
#include <bpf/bpf_helpers.h>

#include <extfuse.h>
#include <extfuse_epoch_cache.h>

#include "lookup.h"
#include "attr.h"
#include "xattr.h"

/********************************************************************
	HELPERS
*********************************************************************/

//#define DEBUGNOW

/* #define HAVE_PASSTHRU */

#ifndef DEBUGNOW
#define PRINTK(fmt, ...)
#else
#define PRINTK(fmt, ...)                                               \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
#endif

#define __EXTFUSE_STRINGIFY_1(value) #value
#define __EXTFUSE_STRINGIFY(value) __EXTFUSE_STRINGIFY_1(value)
#define HANDLER(op, number) \
	SEC("extfuse/" __EXTFUSE_STRINGIFY(number)) int bpf_func_##op

static long (*const bpf_extfuse_read_args)(void *ctx, __u32 type,
					   void *dst, __u32 size) =
	(void *)BPF_FUNC_extfuse_read_args;
static long (*const bpf_extfuse_write_args)(void *ctx, __u32 type,
					    const void *src, __u32 size) =
	(void *)BPF_FUNC_extfuse_write_args;
static long (*const bpf_extfuse_write_args_var)(void *ctx, __u32 type,
						const void *src, __u32 size) =
	(void *)BPF_FUNC_extfuse_write_args_var;

#define memset __builtin_memset

/*
	BPF_MAP_TYPE_PERCPU_HASH: each CPU core gets its own hash-table.
	BPF_MAP_TYPE_LRU_PERCPU_HASH: all cores share one hash-table but have they own LRU structures of the table.
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EXTFUSE_METADATA_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, lookup_entry_key_t);
	__type(value, lookup_entry_val_t);
} entry_map SEC(".maps");

/* order of maps is important */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EXTFUSE_METADATA_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, lookup_attr_key_t);
	__type(value, lookup_attr_val_t);
} attr_map SEC(".maps");

/* Bounded reply cache; eviction is a safe daemon miss. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1U << 16);
	__type(key, xattr_key_t);
	__type(value, xattr_value_t);
} xattr_map SEC(".maps");

/* Userspace daemon mutations use a distinct per-node packed state. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EXTFUSE_METADATA_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, __u64);
} daemon_io_map SEC(".maps");

/* BEGIN/END sequence and active-I/O count, packed into one atomic u64. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EXTFUSE_METADATA_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, __u64);
} native_io_map SEC(".maps");

/* Native mmap page faults may change lower metadata after FUSE RELEASE. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EXTFUSE_METADATA_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, __u32);
} mmap_map SEC(".maps");

/* Index zero contains EXTFUSE_POLICY_* flags selected before FUSE_INIT. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} policy_map SEC(".maps");

/* Epoch-coherent maps use only kernel-owned coherence tokens. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EXTFUSE_METADATA_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct extfuse_epoch_entry_key);
	__type(value, struct extfuse_epoch_entry_value);
} epoch_entry_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EXTFUSE_METADATA_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct extfuse_epoch_attr_value);
} epoch_attr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, EXTFUSE_EPOCH_XATTR_MAX_ENTRIES);
	__type(key, struct extfuse_epoch_xattr_key);
	__type(value, struct extfuse_epoch_xattr_value);
} epoch_xattr_map SEC(".maps");

/* Keep the credential-sized xattr key and bounded reply off one BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct extfuse_epoch_scratch);
} epoch_scratch_map SEC(".maps");

/* BPF_MAP_TYPE_PROG_ARRAY must ALWAYS be the last one */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, FUSE_OPS_COUNT << 1);
	__type(key, __u32);
	__type(value, __u32);
} handlers SEC(".maps");

int SEC("extfuse") fuse_xdp_main_handler(void *ctx)
{
    struct extfuse_req *args = (struct extfuse_req *)ctx;
    int opcode = (int)args->in.h.opcode;

	PRINTK("Opcode %d\n", opcode);

	if (args->coherence.version == EXTFUSE_COHERENCE_VERSION) {
		if (args->coherence.unique != args->in.h.unique ||
		    args->coherence.target_count >
			EXTFUSE_COHERENCE_MAX_TARGETS)
			return args->coherence.phase ==
				EXTFUSE_COHERENCE_PHASE_POST_DAEMON ? RETURN : UPCALL;
		if (args->coherence.phase != EXTFUSE_COHERENCE_PHASE_PRE &&
		    args->coherence.phase !=
			EXTFUSE_COHERENCE_PHASE_POST_DAEMON)
			return UPCALL;

		/* Only audited epoch handlers inspect the shared context. */
		if (opcode != FUSE_LOOKUP && opcode != FUSE_GETATTR &&
		    opcode != FUSE_GETXATTR && opcode != FUSE_READ &&
		    opcode != FUSE_WRITE &&
		    opcode != FUSE_COPY_FILE_RANGE &&
		    opcode != FUSE_COPY_FILE_RANGE_64 &&
		    opcode != EXTFUSE_PASSTHROUGH_READ &&
		    opcode != EXTFUSE_PASSTHROUGH_WRITE &&
		    opcode != EXTFUSE_PASSTHROUGH_MMAP) {
			if (opcode == EXTFUSE_PASSTHROUGH_ATTR_PREPARE ||
			    opcode == EXTFUSE_PASSTHROUGH_ATTR_COMMIT)
				return RETURN;
			return args->coherence.phase ==
				EXTFUSE_COHERENCE_PHASE_POST_DAEMON ? RETURN : UPCALL;
		}
	}

	bpf_tail_call(ctx, &handlers, opcode);
	return UPCALL;
}

struct epoch_target_snapshot {
	__u64 incarnation;
	__u64 attr_epoch;
	__u64 xattr_epoch;
	__u64 data_epoch;
	__u64 namespace_epoch;
};

/*
 * ExtFUSE context fields may be read only through fixed offsets.  In
 * particular, do not return a pointer into coherence.targets: clang turns
 * that into a modified context pointer which the BPF verifier must reject.
 */
#define EPOCH_TARGET_MATCHES(_args, _index, _nodeid, _dependencies) \
	((_index) < (_args)->coherence.target_count && \
	 (_args)->coherence.targets[_index].nodeid == (_nodeid) && \
	 (_args)->coherence.targets[_index].incarnation && \
	 (((_args)->coherence.targets[_index].dependencies & (_dependencies)) == \
	  (_dependencies)) && \
	 !((_args)->coherence.targets[_index].active & (_dependencies)))

#define EPOCH_SNAPSHOT_TARGET(_args, _snapshot, _index) \
	do { \
		(_snapshot)->incarnation = \
			(_args)->coherence.targets[_index].incarnation; \
		(_snapshot)->attr_epoch = \
			(_args)->coherence.targets[_index].attr_epoch; \
		(_snapshot)->xattr_epoch = \
			(_args)->coherence.targets[_index].xattr_epoch; \
		(_snapshot)->data_epoch = \
			(_args)->coherence.targets[_index].data_epoch; \
		(_snapshot)->namespace_epoch = \
			(_args)->coherence.targets[_index].namespace_epoch; \
	} while (0)

static __attribute__((noinline)) int
epoch_read_target_0(struct extfuse_req *args,
		 struct epoch_target_snapshot *snapshot, __u64 nodeid,
		 __u32 dependencies)
{
	if (!EPOCH_TARGET_MATCHES(args, 0, nodeid, dependencies))
		return 0;
	EPOCH_SNAPSHOT_TARGET(args, snapshot, 0);
	return 1;
}

static __attribute__((noinline)) int
epoch_read_target_1(struct extfuse_req *args,
		 struct epoch_target_snapshot *snapshot, __u64 nodeid,
		 __u32 dependencies)
{
	if (!EPOCH_TARGET_MATCHES(args, 1, nodeid, dependencies))
		return 0;
	EPOCH_SNAPSHOT_TARGET(args, snapshot, 1);
	return 1;
}

static __attribute__((noinline)) int
epoch_read_target_2(struct extfuse_req *args,
		 struct epoch_target_snapshot *snapshot, __u64 nodeid,
		 __u32 dependencies)
{
	if (!EPOCH_TARGET_MATCHES(args, 2, nodeid, dependencies))
		return 0;
	EPOCH_SNAPSHOT_TARGET(args, snapshot, 2);
	return 1;
}

static __attribute__((noinline)) int
epoch_read_target_3(struct extfuse_req *args,
		 struct epoch_target_snapshot *snapshot, __u64 nodeid,
		 __u32 dependencies)
{
	if (!EPOCH_TARGET_MATCHES(args, 3, nodeid, dependencies))
		return 0;
	EPOCH_SNAPSHOT_TARGET(args, snapshot, 3);
	return 1;
}

static int epoch_find_target(struct extfuse_req *args, __u64 nodeid,
			  __u32 dependencies, int post_daemon,
			  struct epoch_target_snapshot *snapshot)
{
	if (!nodeid || !dependencies ||
	    args->coherence.version != EXTFUSE_COHERENCE_VERSION ||
	    args->coherence.target_count > EXTFUSE_COHERENCE_MAX_TARGETS ||
	    (args->coherence.request_dependencies & dependencies) !=
		dependencies ||
	    (post_daemon &&
	     (args->coherence.validated_dependencies & dependencies) !=
		dependencies))
		return 0;

	return epoch_read_target_0(args, snapshot, nodeid, dependencies) ||
		epoch_read_target_1(args, snapshot, nodeid, dependencies) ||
		epoch_read_target_2(args, snapshot, nodeid, dependencies) ||
		epoch_read_target_3(args, snapshot, nodeid, dependencies);
}

static int epoch_post_daemon(const struct extfuse_req *args)
{
	return args->coherence.phase ==
		EXTFUSE_COHERENCE_PHASE_POST_DAEMON;
}

static int gen_entry_key(void *ctx, int param, const char *op, lookup_entry_key_t *key)
{
	__s64 ret = bpf_extfuse_read_args(ctx, NODEID, &key->nodeid,
					 sizeof(__u64));
	(void)op;
	if (ret < 0) {
		PRINTK("%s: Failed to read nodeid: %d!\n", op, ret);
		return ret;
	}

	ret = bpf_extfuse_read_args(ctx, param, key->name,
					sizeof(key->name));
	if (ret < 0) {
		PRINTK("%s: Failed to read param %d: %d!\n", op, param, ret);
		return ret;
	}

	return 0;
}

static int gen_attr_key(void *ctx, int param, const char *op, lookup_attr_key_t *key)
{
	__s64 ret = bpf_extfuse_read_args(ctx, NODEID, &key->nodeid,
					 sizeof(__u64));
	(void)param;
	(void)op;
	if (ret < 0) {
		PRINTK("%s: Failed to read nodeid: %d!\n", op, ret);
		return ret;
	}

	return 0;
}

static void create_lookup_entry(struct fuse_entry_out *out,
				lookup_entry_val_t *entry, struct fuse_attr_out *attr)
{
	memset(out, 0, sizeof(*out));
	out->nodeid				= entry->nodeid;
	out->generation			= entry->generation;
	out->entry_valid		= entry->entry_valid;
	out->entry_valid_nsec	= entry->entry_valid_nsec;
	if (attr) {
		out->attr_valid		= attr->attr_valid;
		out->attr_valid_nsec	= attr->attr_valid_nsec;
		out->attr.ino		= attr->attr.ino;
		out->attr.mode		= attr->attr.mode;
		out->attr.nlink		= attr->attr.nlink;
		out->attr.uid		= attr->attr.uid;
		out->attr.gid		= attr->attr.gid;
		out->attr.rdev		= attr->attr.rdev;
		out->attr.size		= attr->attr.size;
		out->attr.blksize	= attr->attr.blksize;
		out->attr.blocks	= attr->attr.blocks;
		out->attr.atime		= attr->attr.atime;
		out->attr.mtime		= attr->attr.mtime;
		out->attr.ctime		= attr->attr.ctime;
		out->attr.atimensec	= attr->attr.atimensec;
		out->attr.mtimensec	= attr->attr.mtimensec;
		out->attr.ctimensec	= attr->attr.ctimensec;
		out->attr.flags		= attr->attr.flags;
	}
}

/*
 * Writable shared native mmap can modify lower metadata after FUSE RELEASE.
 * A separate small-key map keeps that session-lifetime state out of the
 * LOOKUP handler's already tight 512-byte BPF stack budget.
 */
static int has_passthrough_mmap_marker(__u64 nodeid)
{
	return bpf_map_lookup_elem(&mmap_map, &nodeid) != NULL;
}

static int policy_enabled(__u32 flag)
{
	__u32 key = 0;
	__u32 *flags = bpf_map_lookup_elem(&policy_map, &key);

	return flags && (*flags & flag);
}

static int daemon_state_inactive(__u64 nodeid, __u64 *current_state)
{
	__u64 *state = bpf_map_lookup_elem(&daemon_io_map, &nodeid);
	__u64 current = state ? *state : 0;

	if (current & EXTFUSE_NATIVE_STATE_ACTIVE_MASK)
		return 0;
	*current_state = current;
	return 1;
}

static int native_state_inactive(__u64 nodeid, __u64 *current_state)
{
	__u64 *state = bpf_map_lookup_elem(&native_io_map, &nodeid);
	__u64 current = state ? *state : 0;

	if (current & EXTFUSE_NATIVE_STATE_ACTIVE_MASK)
		return 0;
	*current_state = current;
	return 1;
}

static int daemon_cache_token_current(__u64 nodeid, __u64 cached_state)
{
	__u64 current;

	return daemon_state_inactive(nodeid, &current) && current == cached_state;
}

static int native_cache_token_current(__u64 nodeid, __u64 cached_state)
{
	__u64 current;

	return native_state_inactive(nodeid, &current) && current == cached_state;
}

static int cache_tokens_current(__u64 nodeid, __u64 daemon_state,
				__u64 native_state)
{
	return daemon_cache_token_current(nodeid, daemon_state) &&
	       native_cache_token_current(nodeid, native_state);
}

/*
 * A native data write may remove security.capability, but it cannot create a
 * capability xattr which was absent before the write.  The negative result is
 * therefore stable across native-I/O sequence changes.  It is not stable
 * across daemon SETXATTR/REMOVEXATTR, so callers must still validate the exact
 * daemon mutation token.  Keep every positive value and every other xattr on
 * the full two-token path.
 */
static int native_stable_negative_capability(const xattr_key_t *key,
					     const xattr_value_t *value)
{
	return value->error == ENODATA && !value->size &&
	       !__builtin_memcmp(key->name, "security.capability",
				 sizeof("security.capability"));
}

static int epoch_gen_xattr_key(void *ctx, struct extfuse_req *args,
			    struct extfuse_epoch_xattr_key *key)
{
	memset(key, 0, sizeof(*key));
	key->nodeid = args->in.h.nodeid;
	key->uid = args->in.h.uid;
	key->gid = args->in.h.gid;
	key->pid = args->in.h.pid;
	return bpf_extfuse_read_args(ctx, IN_PARAM_1_VALUE, key->name,
				      sizeof(key->name));
}

static int epoch_capability_key(const struct extfuse_epoch_xattr_key *key)
{
	return !__builtin_memcmp(key->name, "security.capability",
				sizeof("security.capability"));
}

static __u32 epoch_xattr_dependencies(
	const struct extfuse_epoch_xattr_key *key,
	const struct extfuse_epoch_xattr_value *value)
{
	if (epoch_capability_key(key) && value->error == ENODATA && !value->size)
		return EXTFUSE_COHERENCE_DOMAIN_XATTR;
	if (!value->error || (value->error == ENODATA && !value->size))
		return EXTFUSE_COHERENCE_DOMAIN_XATTR |
		       EXTFUSE_COHERENCE_DOMAIN_DATA;
	return 0;
}

static int epoch_xattr_tokens_current(
	const struct epoch_target_snapshot *target,
	const struct extfuse_epoch_xattr_value *value, __u32 dependencies)
{
	if (value->incarnation != target->incarnation ||
	    value->xattr_epoch != target->xattr_epoch)
		return 0;
	if ((dependencies & EXTFUSE_COHERENCE_DOMAIN_DATA) &&
	    value->data_epoch != target->data_epoch)
		return 0;
	return 1;
}

static int epoch_lookup(void *ctx, struct extfuse_req *args)
{
	struct extfuse_epoch_entry_key *key;
	struct extfuse_epoch_entry_value *value;
	struct epoch_target_snapshot target;
	struct extfuse_epoch_scratch *scratch;
	__u32 scratch_key = 0;
	int ret;

	scratch = bpf_map_lookup_elem(&epoch_scratch_map, &scratch_key);
	if (!scratch)
		return epoch_post_daemon(args) ? RETURN : UPCALL;
	key = &scratch->key.entry;
	value = &scratch->value.entry;
	memset(key, 0, sizeof(*key));
	memset(value, 0, sizeof(*value));
	key->parent = args->in.h.nodeid;
	key->uid = args->in.h.uid;
	key->gid = args->in.h.gid;
	key->pid = args->in.h.pid;
	ret = bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, key->name,
				     sizeof(key->name));
	if (ret < 0)
		return epoch_post_daemon(args) ? RETURN : UPCALL;
	if (epoch_post_daemon(args) && args->coherence.daemon_error) {
		bpf_map_delete_elem(&epoch_entry_map, key);
		return RETURN;
	}
	if (!epoch_find_target(args, key->parent,
			    EXTFUSE_COHERENCE_DOMAIN_NAMESPACE,
			    epoch_post_daemon(args), &target)) {
		if (epoch_post_daemon(args))
			bpf_map_delete_elem(&epoch_entry_map, key);
		return epoch_post_daemon(args) ? RETURN : UPCALL;
	}

	if (epoch_post_daemon(args)) {
		if (bpf_extfuse_read_args(ctx, OUT_PARAM_0, &value->out,
					   sizeof(value->out)) < 0) {
			bpf_map_delete_elem(&epoch_entry_map, key);
			return RETURN;
		}
		/*
		 * A positive LOOKUP embeds child attributes, but the epoch-coherent PRE
		 * context can validate only the parent namespace token before the
		 * cached child nodeid is known.  Child WRITE/SETATTR can therefore
		 * make a positive row stale without changing the parent token.
		 * Cache only negative entries until the wire context can carry a
		 * separately validated child ATTR dependency.
		 */
		if (value->out.nodeid) {
			bpf_map_delete_elem(&epoch_entry_map, key);
			return RETURN;
		}
		value->incarnation = target.incarnation;
		value->namespace_epoch = target.namespace_epoch;
		value->nlookup = 0;
		if (bpf_map_update_elem(&epoch_entry_map, key, value, BPF_ANY))
			bpf_map_delete_elem(&epoch_entry_map, key);
		return RETURN;
	}

	value = bpf_map_lookup_elem(&epoch_entry_map, key);
	if (!value || value->incarnation != target.incarnation ||
	    value->namespace_epoch != target.namespace_epoch)
		return UPCALL;
	/* Reject and purge positive rows left by an older epoch-coherent object. */
	if (value->out.nodeid) {
		bpf_map_delete_elem(&epoch_entry_map, key);
		return UPCALL;
	}
	ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &value->out,
				     sizeof(value->out));
	if (ret)
		return UPCALL;
	return RETURN;
}

HANDLER(FUSE_LOOKUP, 1)(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;
	int ret = UPCALL;

	if (args->coherence.version == EXTFUSE_COHERENCE_VERSION)
		return epoch_lookup(ctx, args);

#ifdef DEBUGNOW
	__u64 nid = args->in.h.nodeid;
	const char *name = (const char *)args->in.args[0].value;
	const unsigned int len = args->in.args[0].size - 1;

	PRINTK("LOOKUP: parent nodeid: 0x%llx name: %s(%d)\n",
			nid, name, len);
#endif

	lookup_entry_key_t key = {0, {0}};

	memset(key.name, 0, sizeof(key.name));
	ret = gen_entry_key(ctx, IN_PARAM_0_VALUE, "LOOKUP", &key);
	if (ret < 0)
		return UPCALL;

	//PRINTK("key name: %s nodeid: 0x%llx\n", key.name, key.nodeid);

	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale) {
		if (entry && entry->stale)
			PRINTK("LOOKUP: STALE key name: %s nodeid: 0x%llx\n",
				key.name, key.nodeid);
		else
			PRINTK("LOOKUP: No entry for node %s\n", key.name);
		return UPCALL;
	}

	PRINTK("LOOKUP(0x%llx, %s): nlookup %lld\n",
		key.nodeid, key.name, entry->nlookup);

	/* prepare output */
	struct fuse_entry_out out;
	__u64 nodeid = entry->nodeid;


	/* negative entries have no attr */
	if (!nodeid) {
		create_lookup_entry(&out, entry, NULL);
	} else {
		if (has_passthrough_mmap_marker(nodeid))
			return UPCALL;
		lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &nodeid);
		if (!attr || attr->stale) {
			if (attr && attr->stale)
				PRINTK("LOOKUP: STALE attr for node: 0x%llx\n", nodeid);
			else
				PRINTK("LOOKUP: No attr for node 0x%llx\n", nodeid);
			return UPCALL;
		}
		if (!cache_tokens_current(nodeid, attr->daemon_state,
					  attr->native_state))
			return UPCALL;

		PRINTK("LOOKUP nodeid 0x%llx attr ino: 0x%llx\n",
				entry->nodeid, attr->out.attr.ino);

		create_lookup_entry(&out, entry, &attr->out);
	}

	/* populate output */
	ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &out, sizeof(out));
	if (ret) {
		PRINTK("LOOKUP: Failed to write param 0: %d!\n", ret);
		return UPCALL;
	}

	/* atomic incr to avoid data races with user/other cpus */
	__sync_fetch_and_add(&entry->nlookup, 1);
	return RETURN;
}

HANDLER(FUSE_GETATTR, 3)(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;
	lookup_attr_key_t key = {0};
	struct epoch_target_snapshot target;
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "GETATTR", &key);
	if (ret < 0)
		return UPCALL;

	if (args->coherence.version == EXTFUSE_COHERENCE_VERSION) {
		struct extfuse_epoch_attr_value replacement = {};
		struct extfuse_epoch_attr_value *cached;

		if (has_passthrough_mmap_marker(key.nodeid)) {
			if (epoch_post_daemon(args))
				bpf_map_delete_elem(&epoch_attr_map, &key.nodeid);
			return epoch_post_daemon(args) ? RETURN : UPCALL;
		}
		if (epoch_post_daemon(args) && args->coherence.daemon_error) {
			bpf_map_delete_elem(&epoch_attr_map, &key.nodeid);
			return RETURN;
		}
		if (!epoch_find_target(args, key.nodeid,
				    EXTFUSE_COHERENCE_DOMAIN_ATTR,
				    epoch_post_daemon(args), &target)) {
			if (epoch_post_daemon(args))
				bpf_map_delete_elem(&epoch_attr_map, &key.nodeid);
			return epoch_post_daemon(args) ? RETURN : UPCALL;
		}
		if (epoch_post_daemon(args)) {
			replacement.incarnation = target.incarnation;
			replacement.attr_epoch = target.attr_epoch;
			if (bpf_extfuse_read_args(
				    ctx, OUT_PARAM_0, &replacement.out,
				    sizeof(replacement.out)) < 0) {
				bpf_map_delete_elem(&epoch_attr_map, &key.nodeid);
				return RETURN;
			}
			if (bpf_map_update_elem(&epoch_attr_map, &key.nodeid,
						&replacement, BPF_ANY))
				bpf_map_delete_elem(&epoch_attr_map, &key.nodeid);
			return RETURN;
		}

		cached = bpf_map_lookup_elem(&epoch_attr_map, &key.nodeid);
		if (!cached || cached->incarnation != target.incarnation ||
		    cached->attr_epoch != target.attr_epoch)
			return UPCALL;
		ret = bpf_extfuse_write_args(
			ctx, OUT_PARAM_0, &cached->out, sizeof(cached->out));
		return ret ? UPCALL : RETURN;
	}

	if (has_passthrough_mmap_marker(key.nodeid))
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr) {
		PRINTK("GETATTR: No attr for node 0x%llx\n", key.nodeid);
		return UPCALL;
	}

	/*
	 * fuse_getattr_in.dummy is reserved padding, not an attribute mask.
	 * Serving any stale value can therefore expose indefinitely old
	 * metadata. Let userspace refresh the complete cached value.
	 */
	if (attr->stale) {
		PRINTK("GETATTR: STALE attr mask: 0x%x for node: 0x%llx\n",
			attr->stale, key.nodeid);
		return UPCALL;
	}
	if (!cache_tokens_current(key.nodeid, attr->daemon_state,
				  attr->native_state))
		return UPCALL;

	PRINTK("GETATTR(0x%llx): %lld\n", key.nodeid, attr->out.attr.ino);

	/* populate output */
	ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &attr->out, sizeof(attr->out));
	if (ret) {
		PRINTK("GETATTR: Failed to write param 0: %d!\n", ret);
		return UPCALL;
	}

	return RETURN;
}

/*
 * Native passthrough bypasses the ordinary FUSE READ/WRITE request path.
 * Epoch coherence invokes one private policy hook before lower I/O and closes
 * the matching epoch in the kernel. Legacy coherence retains the explicit
 * BEGIN/END map transition implemented below.
 */
static int mark_passthrough_attr_stale(void *ctx, __u32 mask)
{
	lookup_attr_key_t key = {0};
	lookup_attr_val_t *attr;

	if (gen_attr_key(ctx, IN_PARAM_0_VALUE, "PASSTHROUGH", &key) < 0)
		return -EIO;
	attr = bpf_map_lookup_elem(&attr_map, &key);
	if (attr)
		__sync_fetch_and_or(&attr->stale, mask);
	return RETURN;
}

static int transition_native_state(__u64 *state, __u32 phase)
{
	__u64 old_state;
	__u64 new_state;
	__u64 sequence;
	__u64 active;
	int attempt;

#pragma unroll
	for (attempt = 0; attempt < 8; attempt++) {
		old_state = *state;
		sequence = old_state >> EXTFUSE_NATIVE_STATE_ACTIVE_BITS;
		active = old_state & EXTFUSE_NATIVE_STATE_ACTIVE_MASK;
		if (sequence == EXTFUSE_NATIVE_STATE_SEQUENCE_MAX)
			return -EOVERFLOW;
		if (phase == EXTFUSE_PASSTHROUGH_PHASE_BEGIN) {
			if (active == EXTFUSE_NATIVE_STATE_ACTIVE_MASK)
				return -EOVERFLOW;
			active++;
		} else {
			if (!active)
				return -ESTALE;
			active--;
		}
		new_state = ((sequence + 1) <<
			     EXTFUSE_NATIVE_STATE_ACTIVE_BITS) | active;
		if (__sync_val_compare_and_swap(state, old_state, new_state) ==
		    old_state)
			return 0;
	}
	return -EAGAIN;
}

static int update_native_state(void *ctx, __u32 phase)
{
	__u64 nodeid = 0;
	__u64 initial_state;
	__u64 *state;

	if (bpf_extfuse_read_args(ctx, NODEID, &nodeid, sizeof(nodeid)) < 0)
		return -EIO;
	state = bpf_map_lookup_elem(&native_io_map, &nodeid);
	if (!state && phase == EXTFUSE_PASSTHROUGH_PHASE_BEGIN) {
		initial_state = EXTFUSE_NATIVE_STATE_SEQUENCE_ONE | 1;
		if (!bpf_map_update_elem(&native_io_map, &nodeid,
					 &initial_state, BPF_NOEXIST))
			return 0;
		state = bpf_map_lookup_elem(&native_io_map, &nodeid);
	}
	if (!state) {
		/* Poison the key so every cached token misses after an invalid END. */
		initial_state = EXTFUSE_NATIVE_STATE_SEQUENCE_ONE | 1;
		bpf_map_update_elem(&native_io_map, &nodeid, &initial_state,
				    BPF_NOEXIST);
		return -ESTALE;
	}
	return transition_native_state(state, phase);
}

static int invalidate_positive_capability(void *ctx)
{
	xattr_key_t key = {};
	xattr_value_t *value;

	if (bpf_extfuse_read_args(ctx, NODEID, &key.nodeid,
				   sizeof(key.nodeid)) < 0)
		return -EIO;
	__builtin_memcpy(key.name, "security.capability",
			 sizeof("security.capability"));
	value = bpf_map_lookup_elem(&xattr_map, &key);
	if (value && !value->error)
		bpf_map_delete_elem(&xattr_map, &key);
	return RETURN;
}

static int passthrough_notification(void *ctx, __u32 mask, int write,
				    int relax_metadata)
{
	struct extfuse_passthrough_in in = {};
	int ret;

	ret = bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &in, sizeof(in));
	/* AllOpt requires V2; a missing phase must never degrade to legacy I/O. */
	if (ret < 0)
		return -EIO;
	if (in.reserved ||
	    (in.phase != EXTFUSE_PASSTHROUGH_PHASE_BEGIN &&
	     in.phase != EXTFUSE_PASSTHROUGH_PHASE_END))
		return -EINVAL;
	if (relax_metadata)
		return RETURN;

	if (in.phase == EXTFUSE_PASSTHROUGH_PHASE_BEGIN) {
		ret = update_native_state(ctx, in.phase);
		if (ret)
			return ret;
	}
	if (mark_passthrough_attr_stale(ctx, mask))
		return -EIO;
	if (write && invalidate_positive_capability(ctx))
		return -EIO;
	if (in.phase == EXTFUSE_PASSTHROUGH_PHASE_END)
		return update_native_state(ctx, in.phase);
	return RETURN;
}

HANDLER(EXTFUSE_PASSTHROUGH_READ, 65)(void *ctx)
{
	if (policy_enabled(EXTFUSE_POLICY_COHERENCE_EPOCHS)) {
		__u64 nodeid = 0;

		if (policy_enabled(EXTFUSE_POLICY_RELAX_NATIVE_READ_METADATA))
			return RETURN;
		if (bpf_extfuse_read_args(
			    ctx, NODEID, &nodeid, sizeof(nodeid)) < 0)
			return -EIO;
		bpf_map_delete_elem(&epoch_attr_map, &nodeid);
		return RETURN;
	}
	/*
	 * Match the paper-like MDOpt rule: read-side atime changes do not
	 * invalidate metadata-cache entries.  The private notification still
	 * completes locally and remains visible to the request tracer.
	 */
	return passthrough_notification(
		ctx, FATTR_ATIME, 0,
		policy_enabled(EXTFUSE_POLICY_RELAX_NATIVE_READ_METADATA));
}

HANDLER(EXTFUSE_PASSTHROUGH_WRITE, 66)(void *ctx)
{
	if (policy_enabled(EXTFUSE_POLICY_COHERENCE_EPOCHS))
		return RETURN;
	return passthrough_notification(
		ctx, FATTR_ATIME | FATTR_SIZE | FATTR_MTIME | FATTR_CTIME,
		1, 0);
}

HANDLER(EXTFUSE_PASSTHROUGH_MMAP, 67)(void *ctx)
{
	struct extfuse_passthrough_in in = {};
	__u64 nodeid = 0;
	__u32 marker = 1;

	if (bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &in, sizeof(in)) < 0)
		return -EIO;
	if (in.reserved || in.phase != EXTFUSE_PASSTHROUGH_PHASE_BEGIN)
		return -EINVAL;
	/* The gate profile never enables this paper-comparison relaxation. */
	if (!policy_enabled(EXTFUSE_POLICY_COHERENCE_EPOCHS) &&
	    policy_enabled(EXTFUSE_POLICY_RELAX_NATIVE_MMAP_METADATA))
		return RETURN;
	if (bpf_extfuse_read_args(ctx, NODEID, &nodeid, sizeof(nodeid)) < 0)
		return -EIO;
	if (bpf_map_update_elem(&mmap_map, &nodeid, &marker, BPF_ANY))
		return -EIO;
	return RETURN;
}

static int attr_needs_native_refresh(const lookup_attr_val_t *attr,
				     __u64 native_state)
{
	return attr->stale || attr->native_state != native_state;
}

static int attr_needs_refresh(const lookup_attr_val_t *attr, __u64 daemon_state,
			      __u64 native_state)
{
	return attr->daemon_state != daemon_state ||
	       attr_needs_native_refresh(attr, native_state);
}

static int old_daemon_token_refresh_allowed(const lookup_attr_val_t *attr,
					    __u64 daemon_state)
{
	if (attr->daemon_state == daemon_state)
		return 1;
	/*
	 * Only the negotiated release barrier retains an old daemon-token row
	 * as a refresh seed.  A lower stat cannot reconstruct daemon-only
	 * FUSE_ATTR_* flags, so mismatched rows carrying any such flag remain a
	 * conservative upcall.
	 */
	return policy_enabled(EXTFUSE_POLICY_ATTR_RELEASE_BARRIER) &&
	       !attr->out.attr.flags;
}

/*
 * After a native operation END, the next ordinary GETATTR may lazily take a
 * fresh lower inode snapshot.  Hand the kernel exact coherence tokens only
 * when the existing row can safely be refreshed.  A miss is a conservative
 * no-refresh result, not permission to publish an unguarded attribute value.
 */
HANDLER(EXTFUSE_PASSTHROUGH_ATTR_PREPARE,
	EXTFUSE_PASSTHROUGH_ATTR_PREPARE)(void *ctx)
{
	struct extfuse_passthrough_attr_cookie cookie = {};
	lookup_attr_key_t key = {};
	lookup_attr_val_t *attr;

	if (gen_attr_key(ctx, IN_PARAM_0_VALUE, "ATTR_PREPARE", &key) < 0)
		return UPCALL;
	if (has_passthrough_mmap_marker(key.nodeid))
		return UPCALL;
	attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;
	if (!daemon_state_inactive(key.nodeid, &cookie.daemon_state) ||
	    !old_daemon_token_refresh_allowed(attr, cookie.daemon_state))
		return UPCALL;
	if (!native_state_inactive(key.nodeid, &cookie.native_state) ||
	    !attr_needs_refresh(attr, cookie.daemon_state, cookie.native_state))
		return UPCALL;
	if (bpf_extfuse_write_args(ctx, OUT_PARAM_0, &cookie, sizeof(cookie)))
		return UPCALL;
	return RETURN;
}

/*
 * Publish the kernel's full, fresh fuse_attr only if the PREPARE identity is
 * still exact.  Copy the current row so its negotiated TTL is retained, then
 * use BPF_EXIST for one atomic replacement; an erased or racing row is never
 * recreated with stale state.
 */
HANDLER(EXTFUSE_PASSTHROUGH_ATTR_COMMIT,
	EXTFUSE_PASSTHROUGH_ATTR_COMMIT)(void *ctx)
{
	struct extfuse_passthrough_attr_cookie cookie = {};
	struct fuse_attr fresh_attr = {};
	lookup_attr_key_t key = {};
	lookup_attr_val_t replacement;
	lookup_attr_val_t *attr;
	__u64 daemon_state;
	__u64 native_state;
	__u32 daemon_attr_flags;

	if (gen_attr_key(ctx, IN_PARAM_0_VALUE, "ATTR_COMMIT", &key) < 0)
		return UPCALL;
	if (bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &cookie,
				  sizeof(cookie)) < 0 ||
	    bpf_extfuse_read_args(ctx, IN_PARAM_1_VALUE, &fresh_attr,
				  sizeof(fresh_attr)) < 0)
		return UPCALL;
	if (has_passthrough_mmap_marker(key.nodeid))
		return UPCALL;
	attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;
	replacement = *attr;
	daemon_attr_flags = replacement.out.attr.flags;
	if (!daemon_state_inactive(key.nodeid, &daemon_state) ||
	    daemon_state != cookie.daemon_state ||
	    !old_daemon_token_refresh_allowed(&replacement, daemon_state))
		return UPCALL;
	if (!native_state_inactive(key.nodeid, &native_state) ||
	    native_state != cookie.native_state)
		return UPCALL;
	if (has_passthrough_mmap_marker(key.nodeid))
		return UPCALL;
	/* Preserve the legacy fallback unless the release barrier was negotiated. */
	if (!attr_needs_refresh(&replacement, daemon_state, native_state)) {
		if (policy_enabled(EXTFUSE_POLICY_ATTR_RELEASE_BARRIER))
			return RETURN;
		return UPCALL;
	}

	replacement.stale = 0;
	replacement.daemon_state = cookie.daemon_state;
	replacement.native_state = cookie.native_state;
	replacement.out.attr = fresh_attr;
	/* stat cannot reconstruct daemon-only FUSE_ATTR_* protocol flags. */
	replacement.out.attr.flags = daemon_attr_flags;
	/*
	 * A BEGIN or daemon mutation after the final checks advances its state map.
	 * This replacement then carries an old token, so LOOKUP/GETATTR reject it;
	 * BPF_EXIST also prevents a concurrently erased row from being resurrected.
	 */
	if (bpf_map_update_elem(&attr_map, &key, &replacement, BPF_EXIST))
		return UPCALL;
	return RETURN;
}

HANDLER(FUSE_READ, 15)(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;
	lookup_attr_key_t key = {0};
	__u64 nodeid;
	int ret;

	if (args->coherence.version == EXTFUSE_COHERENCE_VERSION) {
		if (epoch_post_daemon(args))
			return RETURN;
		if (!policy_enabled(EXTFUSE_POLICY_WBCACHE_PASSTHROUGH))
			return UPCALL;

		/* The lower read may update atime; never retain an old ATTR row. */
		nodeid = args->in.h.nodeid;
		bpf_map_delete_elem(&epoch_attr_map, &nodeid);
		return PASSTHRU;
	}

	ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "READ", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;

#ifndef HAVE_PASSTHRU
	if (attr->stale & FATTR_ATIME)
			return UPCALL;
#endif

	/* mark as stale to prevent future references to cached attrs */
	__sync_fetch_and_or(&attr->stale, FATTR_ATIME);

	/* delete to prevent future cached attrs */
	//bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("READ: marked stale attr for node 0x%llx\n", key.nodeid);

#ifdef HAVE_PASSTHRU
	return PASSTHRU;
#else
	return UPCALL;
#endif
}

static int epoch_publish_mutation_attrs(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;
	struct extfuse_epoch_scratch *scratch;
	struct extfuse_epoch_mutation_payload *payload;
	__u32 scratch_key = 0;
	__u32 actual;
	__u32 expected;
	int index;

	if (!epoch_post_daemon(args))
		return UPCALL;
	if (args->coherence.daemon_error || args->out.numargs < 2)
		return RETURN;
	actual = args->out.args[1].size;
	if (actual < sizeof(struct fuse_mutation_out) ||
	    actual > sizeof(struct extfuse_epoch_mutation_payload))
		return RETURN;
	scratch = bpf_map_lookup_elem(&epoch_scratch_map, &scratch_key);
	if (!scratch)
		return RETURN;
	payload = &scratch->value.mutation;
	memset(payload, 0, sizeof(*payload));
	if (bpf_extfuse_read_args(ctx, OUT_PARAM_1, payload,
				   sizeof(*payload)) < 0)
		return RETURN;
	if (payload->out.version != FUSE_MUTATION_OUT_VERSION ||
	    !payload->out.count ||
	    payload->out.count > FUSE_MUTATION_MAX_NODES ||
	    payload->out.flags)
		return RETURN;
	expected = sizeof(payload->out) +
		   payload->out.count * sizeof(payload->nodes[0]);
	if (actual != expected)
		return RETURN;

#pragma unroll
	for (index = 0; index < FUSE_MUTATION_MAX_NODES; index++) {
		struct extfuse_epoch_attr_value replacement = {};
		struct epoch_target_snapshot target;
		struct fuse_mutation_node_out *node;
		__u32 xattr_flags = FUSE_MUTATION_NODE_XATTR_UNCHANGED |
			FUSE_MUTATION_NODE_XATTR_CHANGED;
		__u32 known_flags = FUSE_MUTATION_NODE_ATTR_VALID |
			xattr_flags;

		if (index >= payload->out.count)
			continue;
		node = &payload->nodes[index];
		if (node->reserved || (node->flags & ~known_flags) ||
		    (node->flags & xattr_flags) == xattr_flags ||
		    !(node->flags & FUSE_MUTATION_NODE_ATTR_VALID))
			continue;
		if (!epoch_find_target(args, node->nodeid,
				    EXTFUSE_COHERENCE_DOMAIN_ATTR, 1, &target) ||
		    has_passthrough_mmap_marker(node->nodeid)) {
			bpf_map_delete_elem(&epoch_attr_map, &node->nodeid);
			continue;
		}
		replacement.incarnation = target.incarnation;
		replacement.attr_epoch = target.attr_epoch;
		replacement.out = node->attr;
		bpf_map_update_elem(&epoch_attr_map, &node->nodeid,
				    &replacement, BPF_ANY);
	}
	return RETURN;
}

HANDLER(FUSE_WRITE, 16)(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;
	lookup_attr_key_t key = {0};
	__u64 nodeid;

	if (args->coherence.version == EXTFUSE_COHERENCE_VERSION) {
		if (!epoch_post_daemon(args)) {
			if (!policy_enabled(
				    EXTFUSE_POLICY_WBCACHE_PASSTHROUGH))
				return UPCALL;

			/* Size and timestamps must be refreshed after lower writeback. */
			nodeid = args->in.h.nodeid;
			bpf_map_delete_elem(&epoch_attr_map, &nodeid);
			return PASSTHRU;
		}
		return epoch_publish_mutation_attrs(ctx);
	}

	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "WRITE", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;

#ifndef HAVE_PASSTHRU
	if (attr->stale & (FATTR_ATIME | FATTR_SIZE | FATTR_MTIME))
		return UPCALL;
#endif
	/* mark as stale to prevent future references to cached attrs */
	__sync_fetch_and_or(&attr->stale,
			   FATTR_ATIME | FATTR_SIZE | FATTR_MTIME);

	/* delete to prevent future cached attrs */
	//bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("WRITE: marked stale attr for node 0x%llx\n", key.nodeid);

#ifdef HAVE_PASSTHRU
	return PASSTHRU;
#else
	return UPCALL;
#endif
}

HANDLER(FUSE_COPY_FILE_RANGE, 47)(void *ctx)
{
	return epoch_publish_mutation_attrs(ctx);
}

HANDLER(FUSE_COPY_FILE_RANGE_64, 53)(void *ctx)
{
	return epoch_publish_mutation_attrs(ctx);
}

HANDLER(FUSE_SETATTR, 4)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "SETATTR", &key);
	if (ret < 0)
		return UPCALL;

	/* delete to prevent future cached attrs */
	bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("SETATTR: deleted stale attr for node 0x%llx\n", key.nodeid);

	return UPCALL;
}

HANDLER(FUSE_GETXATTR, 22)(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;

	if (args->coherence.version == EXTFUSE_COHERENCE_VERSION) {
		struct extfuse_epoch_xattr_key *key;
		struct extfuse_epoch_xattr_value *value;
		struct epoch_target_snapshot target;
		struct extfuse_epoch_scratch *scratch;
		struct fuse_getxattr_in in = {};
		struct fuse_getxattr_out out = {};
		__u32 dependencies;
		__u32 scratch_key = 0;
		__u32 actual;
		__s64 ret;

		scratch = bpf_map_lookup_elem(&epoch_scratch_map, &scratch_key);
		if (!scratch)
			return epoch_post_daemon(args) ? RETURN : UPCALL;
		key = &scratch->key.xattr;
		if (epoch_gen_xattr_key(ctx, args, key) < 0 ||
		    bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &in,
					   sizeof(in)) < 0)
			return epoch_post_daemon(args) ? RETURN : UPCALL;
		if (has_passthrough_mmap_marker(key->nodeid)) {
			if (epoch_post_daemon(args))
				bpf_map_delete_elem(&epoch_xattr_map, key);
			return epoch_post_daemon(args) ? RETURN : UPCALL;
		}

		if (epoch_post_daemon(args)) {
			/* Errors other than an exact size-query ENODATA are not cached. */
			if (args->coherence.daemon_error) {
				if ((args->coherence.daemon_error != ENODATA &&
				     args->coherence.daemon_error != -ENODATA) ||
				    in.size) {
					bpf_map_delete_elem(&epoch_xattr_map, key);
					return RETURN;
				}
				dependencies = epoch_capability_key(key) ?
					EXTFUSE_COHERENCE_DOMAIN_XATTR :
					EXTFUSE_COHERENCE_DOMAIN_XATTR |
					EXTFUSE_COHERENCE_DOMAIN_DATA;
			} else {
				dependencies = EXTFUSE_COHERENCE_DOMAIN_XATTR |
					       EXTFUSE_COHERENCE_DOMAIN_DATA;
			}

			if (!epoch_find_target(args, key->nodeid, dependencies, 1,
					    &target)) {
				bpf_map_delete_elem(&epoch_xattr_map, key);
				return RETURN;
			}
			value = &scratch->value.xattr;
			memset(value, 0, sizeof(*value));
			value->dependencies = dependencies;
			value->incarnation = target.incarnation;
			value->xattr_epoch = target.xattr_epoch;
			value->data_epoch = target.data_epoch;
			if (args->coherence.daemon_error) {
				value->error = ENODATA;
			} else if (!in.size) {
				if (bpf_extfuse_read_args(ctx, OUT_PARAM_0, &out,
							   sizeof(out)) < 0) {
					bpf_map_delete_elem(&epoch_xattr_map, key);
					return RETURN;
				}
				if (out.size > EXTFUSE_EPOCH_XATTR_VALUE_MAX) {
					bpf_map_delete_elem(&epoch_xattr_map, key);
					return RETURN;
				}
				value->size = out.size;
			} else {
				actual = args->out.args[0].size;
				if (actual > EXTFUSE_EPOCH_XATTR_VALUE_MAX) {
					bpf_map_delete_elem(&epoch_xattr_map, key);
					return RETURN;
				}
				/* POST permits a bounded destination larger than actual. */
				if (bpf_extfuse_read_args(
					    ctx, OUT_PARAM_0, value->data,
					    EXTFUSE_EPOCH_XATTR_VALUE_MAX) < 0) {
					bpf_map_delete_elem(&epoch_xattr_map, key);
					return RETURN;
				}
				value->size = actual;
				value->data_valid = 1;
			}
			if (bpf_map_update_elem(&epoch_xattr_map, key, value, BPF_ANY))
				bpf_map_delete_elem(&epoch_xattr_map, key);
			return RETURN;
		}

		value = bpf_map_lookup_elem(&epoch_xattr_map, key);
		if (!value)
			return UPCALL;
		dependencies = epoch_xattr_dependencies(key, value);
		if (!dependencies || value->dependencies != dependencies ||
		    (value->error == ENODATA && in.size))
			return UPCALL;
		if (!epoch_find_target(args, key->nodeid, dependencies, 0, &target) ||
		    !epoch_xattr_tokens_current(&target, value, dependencies))
			return UPCALL;
		if (value->error == ENODATA)
			return -ENODATA;
		if (value->error || value->size > EXTFUSE_EPOCH_XATTR_VALUE_MAX)
			return UPCALL;
		if (!in.size) {
			out.size = value->size;
			ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &out,
						       sizeof(out));
			return ret ? UPCALL : RETURN;
		}
		if (in.size < value->size)
			return -ERANGE;
		if (!value->data_valid)
			return UPCALL;
		ret = bpf_extfuse_write_args_var(
			ctx, OUT_PARAM_0, value->data, value->size);
		return ret ? UPCALL : RETURN;
	}

	struct fuse_getxattr_in in = {};
	struct fuse_getxattr_out out = {};
	xattr_key_t key = {};
	xattr_value_t *value;
	__s64 ret;

	ret = bpf_extfuse_read_args(ctx, NODEID, &key.nodeid,
				       sizeof(key.nodeid));
	if (ret < 0)
		return UPCALL;
	ret = bpf_extfuse_read_args(ctx, IN_PARAM_1_VALUE, key.name,
					       sizeof(key.name));
	if (ret < 0)
		return UPCALL;
	ret = bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &in, sizeof(in));
	if (ret < 0)
		return UPCALL;

	value = bpf_map_lookup_elem(&xattr_map, &key);
	if (!value)
		return UPCALL;
	if (has_passthrough_mmap_marker(key.nodeid) ||
	    !daemon_cache_token_current(key.nodeid, value->daemon_state))
		return UPCALL;
	if (!native_stable_negative_capability(&key, value) &&
	    !native_cache_token_current(key.nodeid, value->native_state))
		return UPCALL;
	if (value->error == ENODATA) {
		if (!value->size)
			return -ENODATA;
		bpf_map_delete_elem(&xattr_map, &key);
		return UPCALL;
	}
	if (value->error || value->size > EXTFUSE_XATTR_VALUE_MAX) {
		/* Malformed or uncacheable entries must not become fast-path replies. */
		bpf_map_delete_elem(&xattr_map, &key);
		return UPCALL;
	}

	if (!in.size) {
		out.size = value->size;
		ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &out,
					       sizeof(out));
	} else if (in.size < value->size) {
		return -ERANGE;
	} else {
		ret = bpf_extfuse_write_args_var(ctx, OUT_PARAM_0,
						   value->data, value->size);
	}
	return ret ? UPCALL : RETURN;
}

HANDLER(FUSE_FLUSH, 25)(void *ctx)
{
	(void)ctx;
	/* FLUSH may carry delayed write or close errors from userspace. */
	return UPCALL;
}

#ifndef DEBUGNOW
static int remove(void *ctx, int param, const char *op, __u64 parent,
		  lookup_entry_key_t *key)
{
	lookup_entry_val_t *entry;
	__u64 nodeid;

	memset(key->name, 0, sizeof(key->name));
	if (gen_entry_key(ctx, param, op, key))
		return UPCALL;

	if (parent)
		key->nodeid = parent;

	/* lookup entry using its key <parent inode number, name> */
	entry = bpf_map_lookup_elem(&entry_map, key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future cached lookups for this entry */
	__sync_fetch_and_or(&entry->stale, 1);

	PRINTK("%s key name: %s nodeid: 0x%llx", op, key->name, key->nodeid);
	PRINTK("\t nlookup %lld Marked Stale!\n", entry->nlookup);

	/*
	 * If the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because userspace does not track
	 * negative entries and already knows entries with a single reference.
	 */
	nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
}

static int rename_cached_entries(void *ctx, __u64 newdir)
{
	lookup_entry_key_t key = {0, {0}};

	remove(ctx, IN_PARAM_1_VALUE, "RENAME", 0, &key);
	return remove(ctx, IN_PARAM_2_VALUE, "RENAME", newdir, &key);
}
#endif

HANDLER(FUSE_RENAME, 12)(void *ctx)
{
#ifndef DEBUGNOW
	struct fuse_rename_in inarg = {};

	if (bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &inarg,
				   sizeof(inarg)) < 0)
		return UPCALL;
	return rename_cached_entries(ctx, inarg.newdir);
#else
	lookup_entry_key_t key = {0, {0}};

	/* do it for IN_PARAM_1_VALUE */
	memset(key.name, 0, sizeof(key.name));
	if (gen_entry_key(ctx, IN_PARAM_1_VALUE, "RENAME", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_or(&entry->stale, 1);

	PRINTK("RENAME key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	__u64 nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	/* do it for IN_PARAM_2_VALUE */
	memset(key.name, 0, sizeof(key.name));
	if (gen_entry_key(ctx, IN_PARAM_2_VALUE, "RENAME", &key))
		return UPCALL;

	/* lookup by key */
	entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_or(&entry->stale, 1);

	PRINTK("RENAME key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

HANDLER(FUSE_RENAME2, 45)(void *ctx)
{
#ifndef DEBUGNOW
	struct fuse_rename2_in inarg = {};

	if (bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &inarg,
				   sizeof(inarg)) < 0)
		return UPCALL;
	return rename_cached_entries(ctx, inarg.newdir);
#else
	/*
	 * The verbose legacy debug implementation above only models RENAME.
	 * Keep RENAME2 conservative when that diagnostic-only build is used.
	 */
	return UPCALL;
#endif
}

HANDLER(FUSE_RMDIR, 11)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};
	return remove(ctx, IN_PARAM_0_VALUE, "RMDIR", 0, &key);
#else
	lookup_entry_key_t key = {0, {0}};
	memset(key.name, 0, sizeof(key.name));
	if (gen_entry_key(ctx, IN_PARAM_0_VALUE, "RMDIR", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_or(&entry->stale, 1);

	PRINTK("RMDIR key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	__u64 nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

HANDLER(FUSE_UNLINK, 10)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};
	return remove(ctx, IN_PARAM_0_VALUE, "UNLINK", 0, &key);
#else
	lookup_entry_key_t key = {0, {0}};
	memset(key.name, 0, sizeof(key.name));
	if (gen_entry_key(ctx, IN_PARAM_0_VALUE, "UNLINK", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_or(&entry->stale, 1);

	PRINTK("UNLINK key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	__u64 nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

char _license[] SEC("license") = "GPL";
