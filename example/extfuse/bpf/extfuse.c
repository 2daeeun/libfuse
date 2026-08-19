#include <linux/bpf.h>
#include <linux/xattr.h>
#include <bpf/bpf_helpers.h>

#include <extfuse.h>

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

	bpf_tail_call(ctx, &handlers, opcode);
	return UPCALL;
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

HANDLER(FUSE_LOOKUP, 1)(void *ctx)
{
	int ret = UPCALL;

#ifdef DEBUGNOW
	struct extfuse_req *args = (struct extfuse_req *)ctx;
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
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "GETATTR", &key);
	if (ret < 0)
		return UPCALL;
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
 * The kernel invokes these private handlers before and after the lower I/O so
 * a racing daemon refresh cannot overwrite the final stale transition.
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
	if (policy_enabled(EXTFUSE_POLICY_RELAX_NATIVE_MMAP_METADATA))
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
	    attr->daemon_state != cookie.daemon_state)
		return UPCALL;
	if (!native_state_inactive(key.nodeid, &cookie.native_state) ||
	    !attr_needs_native_refresh(attr, cookie.native_state))
		return UPCALL;
	if (bpf_extfuse_write_args(ctx, OUT_PARAM_0, &cookie,
				    sizeof(cookie)))
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
	    replacement.daemon_state != cookie.daemon_state)
		return UPCALL;
	if (!native_state_inactive(key.nodeid, &native_state) ||
	    native_state != cookie.native_state ||
	    !attr_needs_native_refresh(&replacement, cookie.native_state))
		return UPCALL;
	if (has_passthrough_mmap_marker(key.nodeid))
		return UPCALL;

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
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "READ", &key);
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

HANDLER(FUSE_WRITE, 16)(void *ctx)
{
	lookup_attr_key_t key = {0};
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
