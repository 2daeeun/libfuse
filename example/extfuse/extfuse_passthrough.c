/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Benchmark-only ExtFUSE wrapper around libfuse's passthrough_ll example.
 * The passthrough source lives in the ExtFUSE-enabled libfuse checkout; all
 * benchmark-specific policy changes live in this translation unit.
 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 318

#include <fuse_lowlevel.h>
#include <stddef.h>

static struct fuse_session *
perf_intercept_session_new(struct fuse_args *args,
			   const struct fuse_lowlevel_ops *op,
			   size_t op_size, void *userdata);
int upstream_passthrough_main(int argc, char *argv[]);

#undef FUSE_USE_VERSION
#undef fuse_session_new
#define main upstream_passthrough_main
#define fuse_session_new perf_intercept_session_new
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#include <passthrough_ll.c>
#pragma GCC diagnostic pop
#undef fuse_session_new
#undef main

#include <bpf/bpf.h>
#include <ebpf.h>
#include <extfuse_coherence.h>
#include <fuse_i.h>
#include <fuse_kernel.h>
#include <linux/bpf.h>
#include <linux/xattr.h>
#include <ftw.h>
#include <stdatomic.h>
#include <sys/xattr.h>
#include <time.h>

#include "read_cache_fd.h"

void perf_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
void perf_getattr(fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi);
#ifdef HAVE_STATX
void perf_statx(fuse_req_t req, fuse_ino_t ino, int flags, int mask,
		struct fuse_file_info *fi);
#endif
void perf_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
		   size_t size);
void perf_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		 mode_t mode, struct fuse_file_info *fi);
void perf_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void perf_release(fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi);
void perf_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
	       struct fuse_file_info *fi);
void perf_write_buf(fuse_req_t req, fuse_ino_t ino,
		    struct fuse_bufvec *buffer, off_t offset,
		    struct fuse_file_info *fi);
void perf_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		  int valid, struct fuse_file_info *fi);
void perf_unlink(fuse_req_t req, fuse_ino_t parent, const char *name);
void perf_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		 fuse_ino_t newparent, const char *newname,
		 unsigned int flags);
void perf_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode);
void perf_opendir(fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi);
void perf_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
		  struct fuse_file_info *fi);
void perf_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
		      off_t offset, struct fuse_file_info *fi);
void perf_releasedir(fuse_req_t req, fuse_ino_t ino,
		     struct fuse_file_info *fi);

#define ALLOWED_DATA_PREFIX "/home/leedaeeun/Documents/github/fuse_exp/"
#define ALLOWED_BPF_PREFIX "/home/leedaeeun/Documents/github/libfuse/"

enum perf_mode {
	PERF_MODE_OFF,
	PERF_MODE_UPCALL,
	PERF_MODE_HIT,
	PERF_MODE_ALLOPT,
};

enum perf_profile {
	PERF_PROFILE_ZERO_TTL,
	PERF_PROFILE_PAPER_LIKE,
	/*
	 * Cache policy for the functional gate: metadata-only cases avoid
	 * writeback so lower attributes remain directly observable, while AllOpt
	 * enables WBCache forwarding with the strict epoch extensions.
	 */
	PERF_PROFILE_GATE,
};

struct entry_key {
	uint64_t nodeid;
	char name[NAME_MAX + 1];
};

struct entry_value {
	uint32_t stale;
	uint64_t nlookup;
	uint64_t nodeid;
	uint64_t generation;
	uint64_t entry_valid;
	uint32_t entry_valid_nsec;
};

struct attr_key {
	uint64_t nodeid;
};

struct attr_value {
	uint32_t stale;
	uint64_t native_state;
	uint64_t daemon_state;
	struct fuse_attr_out out;
};

struct xattr_key {
	uint64_t nodeid;
	char name[XATTR_NAME_MAX + 1];
};

struct xattr_value {
	int32_t error;
	uint32_t size;
	uint64_t native_state;
	uint64_t daemon_state;
	uint8_t data[256];
};

#define PERF_XATTR_VALUE_MAX ((size_t)sizeof(((struct xattr_value *)0)->data))
#define PERF_XATTR_MAX_ENTRIES (1U << 16)
#define PERF_XATTR_LOCK_BUCKETS 4096U
#define PERF_CAPABILITY_XATTR "security.capability"
#define PERF_ATTR_RELEASE_BARRIER_INIT_FMT "%s=%u %s=%u %s=%u "
#define PERF_COHERENCE_EPOCHS_INIT_FMT \
	"coherence_epochs_capable=%u coherence_epochs_requested=%u "
#define PERF_MUTATION_METADATA_INIT_FMT \
	"mutation_metadata_capable=%u mutation_metadata_requested=%u "
#define PERF_NOTIFY_INVAL_XATTR_INIT_FMT \
	"notify_inval_xattr_capable=%u notify_inval_xattr_requested=%u "
#define PERF_WBCACHE_PASSTHROUGH_INIT_FMT \
	"wbcache_passthrough_capable=%u wbcache_passthrough_requested=%u "
#define PERF_START_MOUNT_FMT \
	"mountpoint=%s debug=%u callback_counting=%u "
#define PERF_START_WBCACHE_FMT \
	"wbcache_passthrough=%u native_passthrough=0 "
#define PERF_INIT_CACHE_FMT \
	"reply_timeout=%.3f cache_mode=%d writeback_requested=%u "
#define PERF_INIT_BACKING_FMT "max_backing_depth=%u single_issuer=%u "
#define PERF_INIT_BUFPOOL_FMT \
	"uring_bufpool_capable=%u uring_bufpool_requested=%u "
#define PERF_INIT_ZERO_COPY_FMT \
	"uring_zero_copy_required=%u prog_fd=%u rc=%d "
#define PERF_INIT_STD_CAPS_FMT "capable_std=0x%08x want_std=0x%08x "
#define PERF_INIT_EXT_CAPS_FMT \
	"capable_ext=0x%016" PRIx64 " want_ext=0x%016" PRIx64 " "
#define PERF_INIT_MAX_WRITE_FMT "max_write=%u\n"
#define PERF_POSIX_ACL_ACCESS_XATTR "system.posix_acl_access"

enum perf_backing_mode {
	PERF_BACKING_DAEMON,
	PERF_BACKING_WBCACHE,
	PERF_BACKING_QUARANTINED,
};

struct perf_backing {
	struct perf_backing *next;
	fuse_ino_t ino;
	int backing_id;
	uint64_t open_count;
	enum perf_backing_mode mode;
	bool registration_may_modify;
};

#define PERF_TOMBSTONE_BUCKETS 16384U
#define PERF_METADATA_MAX_ENTRIES (2U << 16)

struct perf_tombstone {
	struct perf_tombstone *next;
	fuse_ino_t ino;
};

#define PERF_INODE_GENERATION_BUCKETS (1U << 16)
#define PERF_CACHE_MUTATION_MAX_INODES 4U

/*
 * A metadata snapshot only conflicts with mutations of the same FUSE nodeid.
 * Keep these records for the session lifetime: metadata-hit modes deliberately
 * pin passthrough_ll's lo_inode objects until destroy, so their pointer-valued
 * nodeids cannot be recycled while a record is reachable.
 */
struct perf_inode_generation {
	struct perf_inode_generation *next;
	fuse_ino_t ino;
	uint64_t generation;
	uint64_t active;
};

struct perf_cache_mutation {
	fuse_ino_t inodes[PERF_CACHE_MUTATION_MAX_INODES];
	size_t count;
	bool overflow;
	bool armed;
};

struct perf_cache_snapshot {
	uint64_t daemon_state;
	uint64_t native_state;
};

enum perf_cache_attr_outcome {
	PERF_CACHE_ATTR_DISABLED,
	PERF_CACHE_ATTR_PUBLISHED,
	PERF_CACHE_ATTR_UNSTABLE,
	PERF_CACHE_ATTR_SUPPRESSED,
	PERF_CACHE_ATTR_MISSING,
	PERF_CACHE_ATTR_ERROR,
};

_Static_assert(sizeof(struct entry_key) == 264, "entry key ABI");
_Static_assert(sizeof(struct entry_value) == 48, "entry value ABI");
_Static_assert(sizeof(struct attr_key) == 8, "attr key ABI");
_Static_assert(sizeof(struct attr_value) == 128, "attr value ABI");
_Static_assert(offsetof(struct attr_value, native_state) == 8,
	       "attr native-state alignment");
_Static_assert(offsetof(struct attr_value, daemon_state) == 16,
	       "attr daemon-state alignment");
_Static_assert(offsetof(struct attr_value, out) == 24,
	       "attr value alignment");
_Static_assert(sizeof(struct xattr_key) == 264, "xattr key ABI");
_Static_assert(sizeof(struct xattr_value) == 280, "xattr value ABI");

struct perf_counters {
	atomic_uint_fast64_t lookup;
	atomic_uint_fast64_t lookup_positive;
	atomic_uint_fast64_t lookup_enoent;
	atomic_uint_fast64_t lookup_other_errors;
	atomic_uint_fast64_t getattr;
	atomic_uint_fast64_t getxattr;
	atomic_uint_fast64_t create;
	atomic_uint_fast64_t open;
	atomic_uint_fast64_t release;
	atomic_uint_fast64_t read;
	atomic_uint_fast64_t write;
	atomic_uint_fast64_t wbcache_daemon_read_fallbacks;
	atomic_uint_fast64_t wbcache_daemon_write_fallbacks;
	atomic_uint_fast64_t flush;
	atomic_uint_fast64_t setattr;
	atomic_uint_fast64_t mkdir;
	atomic_uint_fast64_t unlink;
	atomic_uint_fast64_t rename;
	atomic_uint_fast64_t opendir;
	atomic_uint_fast64_t readdir;
	atomic_uint_fast64_t releasedir;
	atomic_uint_fast64_t forget;
	atomic_uint_fast64_t forget_multi;
	atomic_uint_fast64_t cache_entry_updates;
	atomic_uint_fast64_t cache_attr_updates;
	atomic_uint_fast64_t cache_xattr_updates;
	atomic_uint_fast64_t cache_update_errors;
	atomic_uint_fast64_t cache_entry_invalidations;
	atomic_uint_fast64_t cache_attr_invalidations;
	atomic_uint_fast64_t cache_xattr_invalidations;
	atomic_uint_fast64_t cache_invalidation_errors;
	atomic_uint_fast64_t cache_bypass_events;
	atomic_uint_fast64_t cache_bypass_errors;
	atomic_uint_fast64_t passthrough_registrations;
	atomic_uint_fast64_t passthrough_reuses;
	atomic_uint_fast64_t passthrough_opens;
	atomic_uint_fast64_t passthrough_fallback_cohorts;
	atomic_uint_fast64_t passthrough_fallback_opens;
	atomic_uint_fast64_t passthrough_closes;
	atomic_uint_fast64_t passthrough_close_errors;
	atomic_uint_fast64_t passthrough_state_errors;
	atomic_uint_fast64_t passthrough_attr_suppressions;
	atomic_uint_fast64_t passthrough_mmap_suppressions;
	atomic_uint_fast64_t passthrough_release_readonly_fast;
	atomic_uint_fast64_t passthrough_release_may_modify;
	atomic_uint_fast64_t passthrough_release_registration_refreshes;
	atomic_uint_fast64_t passthrough_release_attr_snapshots;
	atomic_uint_fast64_t passthrough_release_attr_published;
	atomic_uint_fast64_t passthrough_release_attr_unstable;
	atomic_uint_fast64_t passthrough_release_attr_suppressed;
	atomic_uint_fast64_t passthrough_release_attr_missing;
	atomic_uint_fast64_t passthrough_release_attr_disabled;
	atomic_uint_fast64_t passthrough_release_attr_retired_skips;
	atomic_uint_fast64_t passthrough_release_attr_errors;
	atomic_uint_fast64_t passthrough_tombstones;
	atomic_uint_fast64_t passthrough_tracked_records;
	atomic_uint_fast64_t passthrough_residual_records;
	atomic_uint_fast64_t daemon_io_state_records;
	atomic_uint_fast64_t daemon_io_active_residuals;
	atomic_uint_fast64_t daemon_io_state_audit_errors;
	atomic_uint_fast64_t native_io_state_records;
	atomic_uint_fast64_t native_io_active_residuals;
	atomic_uint_fast64_t native_io_state_audit_errors;
};

struct perf_state {
	enum perf_mode mode;
	enum perf_profile profile;
	const char *mode_name;
	const char *transport;
	bool count_callbacks;
	bool trace_metadata_upcalls;
	ebpf_context_t *bpf;
	struct fuse_conn_info_opts *conn_opts;
	struct fuse_session *session;
	struct fuse_lowlevel_ops operations;
	struct perf_counters counters;
	int init_rc;
	bool capable;
	bool requested;
	bool coherence_epochs_capable;
	bool coherence_epochs_requested;
	bool mutation_metadata_capable;
	bool mutation_metadata_requested;
	bool notify_inval_xattr_capable;
	bool notify_inval_xattr_requested;
	bool single_issuer;
	bool uring_bufpool_capable;
	bool uring_bufpool_requested;
	bool uring_zero_copy_required;
	bool passthrough_capable;
	bool passthrough_requested;
	bool wbcache_passthrough_capable;
	bool wbcache_passthrough_requested;
	bool passthrough_coherence_capable;
	bool passthrough_coherence_requested;
	bool passthrough_coherence_v2_capable;
	bool passthrough_coherence_v2_requested;
	bool passthrough_attr_refresh_capable;
	bool passthrough_attr_refresh_requested;
	bool passthrough_attr_release_barrier_capable;
	bool passthrough_attr_release_barrier_requested;
	bool require_passthrough_coherence;
	uint32_t bpf_policy_flags;
	pthread_rwlock_t namespace_lock;
	pthread_mutex_t backing_mutex;
	pthread_mutex_t xattr_locks[PERF_XATTR_LOCK_BUCKETS];
	size_t xattr_locks_initialized;
	struct perf_backing *backings;
	struct perf_tombstone *tombstones[PERF_TOMBSTONE_BUCKETS];
	struct perf_inode_generation
		*inode_generations[PERF_INODE_GENERATION_BUCKETS];
	bool cache_bypass;
	bool xattr_cache_bypass;
	bool paper_capability_enodata_safe;
	pthread_mutex_t policy_mutex;
};

static struct perf_state perf_state = {
	.namespace_lock = PTHREAD_RWLOCK_INITIALIZER,
	.backing_mutex = PTHREAD_MUTEX_INITIALIZER,
	.policy_mutex = PTHREAD_MUTEX_INITIALIZER,
};

static int capability_scan_error;
static dev_t capability_scan_dev;

static int verify_capability_absent_cb(const char *path,
				       const struct stat *st, int type,
				       struct FTW *ftw)
{
	ssize_t size;

	(void)ftw;
	if (type == FTW_DNR || type == FTW_NS) {
		capability_scan_error = EACCES;
		return 1;
	}
	if (!st || st->st_dev != capability_scan_dev) {
		capability_scan_error = EXDEV;
		return 1;
	}
	errno = 0;
	size = lgetxattr(path, PERF_CAPABILITY_XATTR, NULL, 0);
	if (size >= 0) {
		fprintf(stderr,
			"PAPER_CAPABILITY_POLICY result=reject path=%s reason=present\n",
			path);
		capability_scan_error = EEXIST;
		return 1;
	}
	if (errno != ENODATA && errno != ENOTSUP && errno != EOPNOTSUPP) {
		capability_scan_error = errno ? errno : EIO;
		return 1;
	}
	return 0;
}

static int verify_paper_capability_absent(const char *source)
{
	struct stat source_stat;
	int result;

	if (lstat(source, &source_stat)) {
		fprintf(stderr,
			"PAPER_CAPABILITY_POLICY result=reject source=%s errno=%d error=%s\n",
			source, errno, strerror(errno));
		return -1;
	}
	capability_scan_dev = source_stat.st_dev;
	capability_scan_error = 0;
	result = nftw(source, verify_capability_absent_cb, 32, FTW_PHYS);
	if (result) {
		errno = capability_scan_error ? capability_scan_error : EIO;
		fprintf(stderr,
			"PAPER_CAPABILITY_POLICY result=reject source=%s errno=%d error=%s\n",
			source, errno, strerror(errno));
		return -1;
	}
	perf_state.paper_capability_enodata_safe = true;
	fprintf(stderr,
		"PAPER_CAPABILITY_POLICY result=enabled source=%s lower_tree=verified-absent\n",
		source);
	return 0;
}

#define PERF_METADATA_EVIDENCE_MAX (4U * 1024U * 1024U)

struct perf_metadata_bytes {
	unsigned char *data;
	size_t size;
};

struct perf_metadata_upcall {
	int64_t monotonic_ns;
	struct timespec start;
	uint64_t unique;
	uint32_t opcode;
	uint64_t nodeid;
	intmax_t origin_pid;
	intmax_t origin_tgid;
	intmax_t origin_tid;
	intmax_t uid;
	intmax_t gid;
	int lower_fd;
	uintmax_t lower_dev;
	uintmax_t lower_ino;
	bool lower_stat_available;
	int evidence_errors;
	struct perf_metadata_bytes comm;
	struct perf_metadata_bytes cmdline;
	struct perf_metadata_bytes exe;
	struct perf_metadata_bytes cwd;
	struct perf_metadata_bytes lower_path;
	struct perf_metadata_bytes kernel_stack;
	const char *path_state;
	intmax_t getattr_fi_present;
	intmax_t getattr_fi_flags;
	intmax_t getattr_fh;
	const unsigned char *name;
	size_t name_size;
	intmax_t size;
};

static int64_t perf_timespec_ns(const struct timespec *time)
{
	return (int64_t)time->tv_sec * INT64_C(1000000000) + time->tv_nsec;
}

static void perf_metadata_bytes_reset(struct perf_metadata_bytes *bytes)
{
	free(bytes->data);
	bytes->data = NULL;
	bytes->size = 0;
}

static int perf_metadata_read_fd(int fd, struct perf_metadata_bytes *bytes)
{
	size_t capacity = 4096;
	unsigned char *data;

	data = malloc(capacity + 1);
	if (!data)
		return -1;
	for (;;) {
		ssize_t result;

		if (bytes->size == capacity) {
			unsigned char *resized;
			size_t new_capacity;

			if (capacity == PERF_METADATA_EVIDENCE_MAX) {
				errno = EOVERFLOW;
				goto error;
			}
			new_capacity = capacity * 2;
			if (new_capacity > PERF_METADATA_EVIDENCE_MAX)
				new_capacity = PERF_METADATA_EVIDENCE_MAX;
			resized = realloc(data, new_capacity + 1);
			if (!resized)
				goto error;
			data = resized;
			capacity = new_capacity;
		}
		result = read(fd, data + bytes->size, capacity - bytes->size);
		if (result > 0) {
			bytes->size += (size_t)result;
			continue;
		}
		if (!result)
			break;
		if (errno == EINTR)
			continue;
		goto error;
	}
	data[bytes->size] = '\0';
	bytes->data = data;
	return 0;

error:
	free(data);
	bytes->size = 0;
	return -1;
}

static int perf_metadata_read_file(const char *path,
				   struct perf_metadata_bytes *bytes)
{
	int fd;
	int result;
	int saved_error;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	result = perf_metadata_read_fd(fd, bytes);
	saved_error = errno;
	close(fd);
	errno = saved_error;
	return result;
}

static int perf_metadata_proc_path(char *path, size_t path_size, pid_t pid,
				   const char *leaf)
{
	int result = snprintf(path, path_size, "/proc/%jd/%s", (intmax_t)pid,
			      leaf);

	if (result < 0 || (size_t)result >= path_size) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static int perf_metadata_read_proc(pid_t pid, const char *leaf,
				   struct perf_metadata_bytes *bytes)
{
	char path[64];

	if (perf_metadata_proc_path(path, sizeof(path), pid, leaf))
		return -1;
	return perf_metadata_read_file(path, bytes);
}

static int perf_metadata_readlink(const char *path,
				  struct perf_metadata_bytes *bytes)
{
	size_t capacity = 256;
	unsigned char *data;

	data = malloc(capacity + 1);
	if (!data)
		return -1;
	for (;;) {
		ssize_t result = readlink(path, (char *)data, capacity);

		if (result < 0)
			goto error;
		if ((size_t)result < capacity) {
			bytes->size = (size_t)result;
			data[bytes->size] = '\0';
			bytes->data = data;
			return 0;
		}
		if (capacity == PERF_METADATA_EVIDENCE_MAX) {
			errno = EOVERFLOW;
			goto error;
		}
		capacity *= 2;
		if (capacity > PERF_METADATA_EVIDENCE_MAX)
			capacity = PERF_METADATA_EVIDENCE_MAX;
		{
			unsigned char *resized = realloc(data, capacity + 1);

			if (!resized)
				goto error;
			data = resized;
		}
	}

error:
	free(data);
	bytes->size = 0;
	return -1;
}

static int perf_metadata_read_proc_link(pid_t pid, const char *leaf,
					struct perf_metadata_bytes *bytes)
{
	char path[64];

	if (perf_metadata_proc_path(path, sizeof(path), pid, leaf))
		return -1;
	return perf_metadata_readlink(path, bytes);
}

static int perf_metadata_parse_tgid(const struct perf_metadata_bytes *status,
				    intmax_t *tgid)
{
	const char *cursor = (const char *)status->data;
	const char *end = cursor + status->size;

	while (cursor < end) {
		const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
		char *number_end;
		intmax_t value;

		if (!line_end)
			line_end = end;
		if ((size_t)(line_end - cursor) < 5 ||
		    memcmp(cursor, "Tgid:", 5)) {
			cursor = line_end < end ? line_end + 1 : end;
			continue;
		}
		cursor += 5;
		while (cursor < line_end && (*cursor == ' ' || *cursor == '\t'))
			cursor++;
		errno = 0;
		value = strtoimax(cursor, &number_end, 10);
		if (errno || number_end == cursor || number_end > line_end) {
			errno = EINVAL;
			return -1;
		}
		while (number_end < line_end &&
		       (*number_end == ' ' || *number_end == '\t'))
			number_end++;
		if (number_end != line_end || value <= 0) {
			errno = EINVAL;
			return -1;
		}
		*tgid = value;
		return 0;
	}
	errno = ENODATA;
	return -1;
}

static void perf_metadata_capture_proc(struct perf_metadata_upcall *upcall,
				       pid_t pid)
{
	struct perf_metadata_bytes status = { 0 };

	if (perf_metadata_read_proc(pid, "status", &status) ||
	    perf_metadata_parse_tgid(&status, &upcall->origin_tgid))
		upcall->evidence_errors++;
	perf_metadata_bytes_reset(&status);
	if (perf_metadata_read_proc(pid, "comm", &upcall->comm))
		upcall->evidence_errors++;
	else if (upcall->comm.size &&
		 upcall->comm.data[upcall->comm.size - 1] == '\n')
		upcall->comm.size--;
	if (perf_metadata_read_proc(pid, "cmdline", &upcall->cmdline))
		upcall->evidence_errors++;
	if (perf_metadata_read_proc_link(pid, "exe", &upcall->exe))
		upcall->evidence_errors++;
	if (perf_metadata_read_proc_link(pid, "cwd", &upcall->cwd))
		upcall->evidence_errors++;
	if (perf_metadata_read_proc(pid, "stack", &upcall->kernel_stack))
		upcall->evidence_errors++;
}

static void perf_metadata_capture_path(struct perf_metadata_upcall *upcall)
{
	static const char deleted_suffix[] = " (deleted)";
	char path[64];
	struct stat st;
	int result;

	if (fstat(upcall->lower_fd, &st))
		upcall->evidence_errors++;
	else {
		upcall->lower_dev = (uintmax_t)st.st_dev;
		upcall->lower_ino = (uintmax_t)st.st_ino;
		upcall->lower_stat_available = true;
	}
	result = snprintf(path, sizeof(path), "/proc/self/fd/%d",
			  upcall->lower_fd);
	if (result < 0 || (size_t)result >= sizeof(path) ||
	    perf_metadata_readlink(path, &upcall->lower_path)) {
		upcall->evidence_errors++;
		return;
	}
	upcall->path_state = "live";
	if (upcall->lower_path.size >= sizeof(deleted_suffix) - 1 &&
	    !memcmp(upcall->lower_path.data + upcall->lower_path.size -
			    (sizeof(deleted_suffix) - 1),
		    deleted_suffix, sizeof(deleted_suffix) - 1))
		upcall->path_state = "deleted";
}

static void perf_metadata_upcall_begin(struct perf_metadata_upcall *upcall,
				       fuse_req_t req, fuse_ino_t ino,
				       uint32_t opcode, int lower_fd,
				       const struct fuse_file_info *fi,
				       const char *name, intmax_t size)
{
	const struct fuse_ctx *context;

	memset(upcall, 0, sizeof(*upcall));
	upcall->monotonic_ns = -1;
	upcall->origin_pid = -1;
	upcall->origin_tgid = -1;
	upcall->origin_tid = -1;
	upcall->uid = -1;
	upcall->gid = -1;
	upcall->lower_fd = lower_fd;
	upcall->path_state = "unavailable";
	upcall->getattr_fi_present = -1;
	upcall->getattr_fi_flags = -1;
	upcall->getattr_fh = -1;
	upcall->size = size;
	upcall->opcode = opcode;
	upcall->nodeid = (uint64_t)ino;
	upcall->unique = ((struct fuse_req *)req)->unique;
	if (clock_gettime(CLOCK_MONOTONIC, &upcall->start))
		upcall->evidence_errors++;
	else
		upcall->monotonic_ns = perf_timespec_ns(&upcall->start);
	context = fuse_req_ctx(req);
	if (!context) {
		upcall->evidence_errors++;
	} else {
		upcall->origin_pid = context->pid;
		upcall->origin_tid = context->pid;
		upcall->uid = context->uid;
		upcall->gid = context->gid;
		if (context->pid > 0)
			perf_metadata_capture_proc(upcall, context->pid);
		else
			upcall->evidence_errors += 6;
	}
	perf_metadata_capture_path(upcall);
	if (opcode == FUSE_GETATTR) {
		upcall->getattr_fi_present = fi != NULL;
		if (fi) {
			upcall->getattr_fi_flags = fi->flags;
			upcall->getattr_fh = (intmax_t)fi->fh;
		}
	}
	if (name) {
		upcall->name = (const unsigned char *)name;
		upcall->name_size = strlen(name);
	}
}

static void perf_metadata_emit_hex(const unsigned char *data, size_t size)
{
	static const char digits[] = "0123456789abcdef";
	size_t index;

	for (index = 0; index < size; index++) {
		fputc(digits[data[index] >> 4], stderr);
		fputc(digits[data[index] & 0xf], stderr);
	}
}

static void perf_metadata_upcall_end(struct perf_metadata_upcall *upcall,
				     intmax_t result, int callback_errno)
{
	struct timespec end;
	int64_t duration_ns = -1;
	int saved_error = errno;

	if (clock_gettime(CLOCK_MONOTONIC, &end))
		upcall->evidence_errors++;
	else if (upcall->monotonic_ns >= 0)
		duration_ns = perf_timespec_ns(&end) - upcall->monotonic_ns;

	flockfile(stderr);
	fprintf(stderr,
		"FIG9_METADATA_UPCALL_V1\tmonotonic_ns=%" PRId64
		"\tduration_ns=%" PRId64 "\tunique=%" PRIu64
		"\topcode=%u\tnodeid=%" PRIu64
		"\torigin_pid=%" PRIdMAX "\torigin_tgid=%" PRIdMAX
		"\torigin_tid=%" PRIdMAX "\tuid=%" PRIdMAX
		"\tgid=%" PRIdMAX "\tlower_fd=%d\tlower_dev=",
		upcall->monotonic_ns, duration_ns, upcall->unique,
		upcall->opcode, upcall->nodeid, upcall->origin_pid,
		upcall->origin_tgid, upcall->origin_tid, upcall->uid,
		upcall->gid, upcall->lower_fd);
	if (upcall->lower_stat_available)
		fprintf(stderr, "%" PRIuMAX, upcall->lower_dev);
	else
		fputs("-1", stderr);
	fputs("\tlower_ino=", stderr);
	if (upcall->lower_stat_available)
		fprintf(stderr, "%" PRIuMAX, upcall->lower_ino);
	else
		fputs("-1", stderr);
	fprintf(stderr,
		"\tresult=%" PRIdMAX "\terrno=%d\tevidence_errors=%d\tcomm_hex=",
		result, callback_errno, upcall->evidence_errors);
	perf_metadata_emit_hex(upcall->comm.data, upcall->comm.size);
	fputs("\tcmdline_hex=", stderr);
	perf_metadata_emit_hex(upcall->cmdline.data, upcall->cmdline.size);
	fputs("\texe_hex=", stderr);
	perf_metadata_emit_hex(upcall->exe.data, upcall->exe.size);
	fputs("\tcwd_hex=", stderr);
	perf_metadata_emit_hex(upcall->cwd.data, upcall->cwd.size);
	fputs("\tlower_path_hex=", stderr);
	perf_metadata_emit_hex(upcall->lower_path.data, upcall->lower_path.size);
	fputs("\tkernel_stack_hex=", stderr);
	perf_metadata_emit_hex(upcall->kernel_stack.data,
			       upcall->kernel_stack.size);
	fprintf(stderr,
		"\tpath_state=%s\tgetattr_fi_present=%" PRIdMAX
		"\tgetattr_fi_flags=%" PRIdMAX "\tgetattr_fh=%" PRIdMAX
		"\tname_hex=",
		upcall->path_state, upcall->getattr_fi_present,
		upcall->getattr_fi_flags, upcall->getattr_fh);
	perf_metadata_emit_hex(upcall->name, upcall->name_size);
	fprintf(stderr, "\tsize=%" PRIdMAX "\tmode=%s\ttransport=%s\n",
		upcall->size, perf_state.mode_name, perf_state.transport);
	funlockfile(stderr);

	perf_metadata_bytes_reset(&upcall->comm);
	perf_metadata_bytes_reset(&upcall->cmdline);
	perf_metadata_bytes_reset(&upcall->exe);
	perf_metadata_bytes_reset(&upcall->cwd);
	perf_metadata_bytes_reset(&upcall->lower_path);
	perf_metadata_bytes_reset(&upcall->kernel_stack);
	errno = saved_error;
}

_Static_assert((PERF_XATTR_LOCK_BUCKETS &
		(PERF_XATTR_LOCK_BUCKETS - 1)) == 0,
	       "xattr lock bucket count must be a power of two");
_Static_assert((PERF_INODE_GENERATION_BUCKETS &
		(PERF_INODE_GENERATION_BUCKETS - 1)) == 0,
	       "inode generation bucket count must be a power of two");

static bool metadata_hits_enabled(void)
{
	return perf_state.mode == PERF_MODE_HIT ||
	       perf_state.mode == PERF_MODE_ALLOPT;
}

static bool coherence_epochs_enabled(void)
{
	return perf_state.requested && perf_state.coherence_epochs_requested;
}

static bool mutation_metadata_enabled(void)
{
	return coherence_epochs_enabled() &&
	       perf_state.mutation_metadata_requested;
}

static bool notify_inval_xattr_enabled(void)
{
	return coherence_epochs_enabled() &&
	       perf_state.notify_inval_xattr_requested;
}

static bool wbcache_passthrough_enabled(void)
{
	return perf_state.mode == PERF_MODE_ALLOPT;
}

static bool paper_wbcache_passthrough_enabled(void)
{
	return wbcache_passthrough_enabled() &&
	       perf_state.profile == PERF_PROFILE_PAPER_LIKE;
}

static bool strict_wbcache_coherence_enabled(void)
{
	return wbcache_passthrough_enabled() &&
	       perf_state.profile == PERF_PROFILE_GATE;
}

static const char *coherence_mode_name(void)
{
	if (!perf_state.wbcache_passthrough_requested)
		return "none";
	return coherence_epochs_enabled() ? "strict" : "paper";
}

static bool attr_release_barrier_enabled(void)
{
	return !coherence_epochs_enabled() &&
	       perf_state.passthrough_coherence_v2_requested &&
	       perf_state.passthrough_attr_release_barrier_requested &&
	       (perf_state.bpf_policy_flags &
		EXTFUSE_POLICY_ATTR_RELEASE_BARRIER);
}

static bool file_may_modify(int flags)
{
	/* RELEASE has no dirty bit, so writable/truncating opens are conservative. */
	return (flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC);
}

static uint64_t counter_value(atomic_uint_fast64_t *counter)
{
	return atomic_load_explicit(counter, memory_order_relaxed);
}

static void counter_increment(atomic_uint_fast64_t *counter)
{
	atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
}

static void counter_decrement(atomic_uint_fast64_t *counter)
{
	atomic_fetch_sub_explicit(counter, 1, memory_order_relaxed);
}

static void callback_increment(atomic_uint_fast64_t *counter)
{
	if (perf_state.count_callbacks)
		counter_increment(counter);
}

static struct perf_backing *find_backing_locked(fuse_ino_t ino,
						 struct perf_backing ***link)
{
	struct perf_backing **cursor = &perf_state.backings;

	while (*cursor) {
		if ((*cursor)->ino == ino) {
			if (link)
				*link = cursor;
			return *cursor;
		}
		cursor = &(*cursor)->next;
	}
	if (link)
		*link = cursor;
	return NULL;
}

static size_t tombstone_bucket(fuse_ino_t ino)
{
	uint64_t value = (uint64_t)ino;

	value ^= value >> 33;
	value *= UINT64_C(0xff51afd7ed558ccd);
	value ^= value >> 33;
	return (size_t)value & (PERF_TOMBSTONE_BUCKETS - 1);
}

static size_t xattr_lock_bucket(fuse_ino_t ino)
{
	uint64_t value = (uint64_t)ino;

	value ^= value >> 33;
	value *= UINT64_C(0xff51afd7ed558ccd);
	value ^= value >> 33;
	return (size_t)value & (PERF_XATTR_LOCK_BUCKETS - 1);
}

static pthread_mutex_t *xattr_lock_for_inode(fuse_ino_t ino)
{
	return &perf_state.xattr_locks[xattr_lock_bucket(ino)];
}

static int initialize_xattr_locks(void)
{
	size_t index;

	for (index = 0; index < PERF_XATTR_LOCK_BUCKETS; index++) {
		int error = pthread_mutex_init(&perf_state.xattr_locks[index],
					       NULL);

		if (error) {
			while (index)
				pthread_mutex_destroy(
					&perf_state.xattr_locks[--index]);
			perf_state.xattr_locks_initialized = 0;
			errno = error;
			return -1;
		}
		perf_state.xattr_locks_initialized = index + 1;
	}
	return 0;
}

static void cleanup_xattr_locks(void)
{
	while (perf_state.xattr_locks_initialized)
		pthread_mutex_destroy(
			&perf_state.xattr_locks[
				--perf_state.xattr_locks_initialized]);
}

static bool find_tombstone_locked(fuse_ino_t ino)
{
	struct perf_tombstone *tombstone;

	for (tombstone = perf_state.tombstones[tombstone_bucket(ino)];
	     tombstone; tombstone = tombstone->next) {
		if (tombstone->ino == ino)
			return true;
	}
	return false;
}

/*
 * 새 coherence capability가 없는 구형 커널용 보수적 fallback이다. Native
 * mmap은 FUSE RELEASE 뒤에도 lower metadata를 바꿀 수 있으므로, passthrough로
 * 노출한 inode를 session-lifetime tombstone으로 남긴다. C3/C4 측정은 이
 * fallback을 허용하지 않고 새 capability가 없으면 INIT에서 실패한다.
 */
static void add_tombstone_locked(fuse_ino_t ino,
				 struct perf_tombstone *candidate)
{
	size_t bucket;

	/* Every legacy caller preallocates this before exposing lower I/O. */
	if (!candidate)
		return;
	if (find_tombstone_locked(ino)) {
		free(candidate);
		return;
	}
	bucket = tombstone_bucket(ino);
	candidate->ino = ino;
	candidate->next = perf_state.tombstones[bucket];
	perf_state.tombstones[bucket] = candidate;
	counter_increment(&perf_state.counters.passthrough_tombstones);
}

static int disable_metadata_cache_locked(const char *reason);
static int disable_xattr_cache_locked(const char *reason);

/*
 * The kernel records every native mmap in a dedicated nodeid map.
 * That marker survives RELEASE, so later daemon refreshes cannot accidentally
 * make mmap-mutated attributes BPF-visible.
 */
static bool has_passthrough_mmap_marker_locked(fuse_ino_t ino)
{
	uint64_t key = ino;
	uint32_t value;
	int lookup_error;

	if (!ebpf_data_lookup(perf_state.bpf, &key, &value,
			      EXTFUSE_MMAP_MAP))
		return true;
	lookup_error = errno;
	if (lookup_error == ENOENT)
		return false;

	counter_increment(&perf_state.counters.passthrough_state_errors);
	fprintf(stderr,
		"CACHE_ERROR map=mmap operation=marker-lookup "
		"nodeid=%" PRIu64 " errno=%d error=%s\n",
		(uint64_t)ino, lookup_error, strerror(lookup_error));
	disable_metadata_cache_locked("mmap-marker-lookup");
	disable_xattr_cache_locked("mmap-marker-lookup");
	return true;
}

static double epoch_attr_timeout(fuse_ino_t ino, double timeout)
{
	bool marked;

	pthread_mutex_lock(&perf_state.backing_mutex);
	marked = has_passthrough_mmap_marker_locked(ino);
	pthread_mutex_unlock(&perf_state.backing_mutex);
	if (marked) {
		counter_increment(
			&perf_state.counters.passthrough_mmap_suppressions);
		return 0;
	}
	return timeout;
}

static bool attr_cache_suppressed_locked(fuse_ino_t ino,
					 bool *mmap_suppressed)
{
	struct perf_backing *backing;

	*mmap_suppressed = false;
	/*
	 * Paper WBCache has a finite ordinary READ/WRITE request boundary.  Those
	 * handlers stale any existing row before lower I/O, so the mere presence
	 * of a registered backing file must not suppress otherwise current attrs.
	 * Tombstones below are only for legacy native passthrough, where mmap can
	 * keep modifying the lower inode after RELEASE without a notification.
	 */
	if (paper_wbcache_passthrough_enabled())
		return false;
	backing = find_backing_locked(ino, NULL);
	if (coherence_epochs_enabled() ||
	    perf_state.passthrough_coherence_v2_requested) {
		*mmap_suppressed = has_passthrough_mmap_marker_locked(ino);
		return *mmap_suppressed;
	}

	/*
	 * Compatibility fallback for an older kernel without negotiated native-I/O
	 * notifications. A retained zero-open record means cleanup failed. Keep
	 * suppressing BPF attributes rather than expose stale metadata.
	 */
	return find_tombstone_locked(ino) ||
	       (backing && backing->mode != PERF_BACKING_DAEMON);
}

static size_t inode_generation_bucket(fuse_ino_t ino)
{
	uint64_t value = (uint64_t)ino;

	value ^= value >> 33;
	value *= UINT64_C(0xff51afd7ed558ccd);
	value ^= value >> 33;
	return (size_t)value & (PERF_INODE_GENERATION_BUCKETS - 1);
}

static struct perf_inode_generation *
find_inode_generation_locked(fuse_ino_t ino)
{
	struct perf_inode_generation *state;

	for (state = perf_state.inode_generations[
		     inode_generation_bucket(ino)];
	     state; state = state->next) {
		if (state->ino == ino)
			return state;
	}
	return NULL;
}

static struct perf_inode_generation *
get_inode_generation_locked(fuse_ino_t ino)
{
	struct perf_inode_generation *state;
	size_t bucket;

	state = find_inode_generation_locked(ino);
	if (state)
		return state;
	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;
	bucket = inode_generation_bucket(ino);
	state->ino = ino;
	state->next = perf_state.inode_generations[bucket];
	perf_state.inode_generations[bucket] = state;
	return state;
}

static bool inode_generation_value_locked(
	const struct perf_inode_generation *state, uint64_t *value)
{
	if (!state) {
		*value = 0;
		return true;
	}
	if (state->generation > EXTFUSE_NATIVE_STATE_SEQUENCE_MAX ||
	    state->active > EXTFUSE_NATIVE_STATE_ACTIVE_MASK)
		return false;
	*value = (state->generation << EXTFUSE_NATIVE_STATE_ACTIVE_BITS) |
		 state->active;
	return true;
}

static void disable_all_caches_locked(const char *reason)
{
	disable_metadata_cache_locked(reason);
	disable_xattr_cache_locked(reason);
}

static bool publish_inode_generation_locked(
	fuse_ino_t ino, const struct perf_inode_generation *state,
	const char *reason)
{
	uint64_t key = ino;
	uint64_t value;

	if (!inode_generation_value_locked(state, &value)) {
		errno = EOVERFLOW;
		goto error;
	}
	if (!ebpf_data_update(perf_state.bpf, &key, &value,
			      EXTFUSE_DAEMON_IO_MAP, 1))
		return true;
error:
	counter_increment(&perf_state.counters.cache_update_errors);
	counter_increment(&perf_state.counters.passthrough_state_errors);
	fprintf(stderr,
		"CACHE_ERROR map=daemon_io operation=update nodeid=%" PRIu64
		" reason=%s errno=%d error=%s\n",
		(uint64_t)ino, reason, errno, strerror(errno));
	disable_all_caches_locked(reason);
	return false;
}

static bool native_state_snapshot_locked(fuse_ino_t ino, uint64_t *state,
					 const char *reason)
{
	uint64_t key = ino;
	int lookup_error;

	*state = 0;
	if (!perf_state.passthrough_coherence_v2_requested &&
	    !perf_state.wbcache_passthrough_requested)
		return true;
	if (!ebpf_data_lookup(perf_state.bpf, &key, state,
			      EXTFUSE_NATIVE_IO_MAP))
		return true;
	lookup_error = errno;
	if (lookup_error == ENOENT)
		return true;

	counter_increment(&perf_state.counters.passthrough_state_errors);
	fprintf(stderr,
		"CACHE_ERROR map=native_io operation=lookup nodeid=%" PRIu64
		" errno=%d error=%s\n",
		(uint64_t)ino, lookup_error, strerror(lookup_error));
	disable_metadata_cache_locked(reason);
	disable_xattr_cache_locked(reason);
	return false;
}

static bool cache_snapshot_begin(fuse_ino_t ino,
				 struct perf_cache_snapshot *snapshot)
{
	struct perf_inode_generation *state;
	bool result;

	memset(snapshot, 0, sizeof(*snapshot));
	if (!metadata_hits_enabled())
		return true;
	pthread_mutex_lock(&perf_state.backing_mutex);
	state = find_inode_generation_locked(ino);
	result = inode_generation_value_locked(state, &snapshot->daemon_state);
	if (!result) {
		counter_increment(&perf_state.counters.passthrough_state_errors);
		disable_all_caches_locked("daemon-state-snapshot");
	}
	if (!native_state_snapshot_locked(
		    ino, &snapshot->native_state, "native-state-snapshot"))
		result = false;
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return result;
}

static bool inode_generation_stable_locked(fuse_ino_t ino,
					    uint64_t expected_state)
{
	struct perf_inode_generation *state;
	uint64_t current_state;

	state = find_inode_generation_locked(ino);
	if (!inode_generation_value_locked(state, &current_state))
		return false;
	return current_state == expected_state &&
	       !(current_state & EXTFUSE_NATIVE_STATE_ACTIVE_MASK);
}

static bool cache_snapshot_stable_locked(
	fuse_ino_t ino, const struct perf_cache_snapshot *snapshot)
{
	uint64_t native_state;

	if (!inode_generation_stable_locked(
		    ino, snapshot->daemon_state))
		return false;
	if (!native_state_snapshot_locked(
		    ino, &native_state, "native-state-validation"))
		return false;
	return native_state == snapshot->native_state &&
	       !(native_state & EXTFUSE_NATIVE_STATE_ACTIVE_MASK);
}

static void advance_inode_generation_locked(fuse_ino_t ino,
					     const char *reason)
{
	struct perf_inode_generation *state;

	if (!metadata_hits_enabled() ||
	    (perf_state.cache_bypass && perf_state.xattr_cache_bypass) || !ino)
		return;
	state = get_inode_generation_locked(ino);
	if (!state) {
		counter_increment(&perf_state.counters.passthrough_state_errors);
		disable_all_caches_locked(reason);
		return;
	}
	if (state->generation == EXTFUSE_NATIVE_STATE_SEQUENCE_MAX) {
		counter_increment(&perf_state.counters.passthrough_state_errors);
		disable_all_caches_locked("inode-generation-counter-overflow");
		return;
	}
	state->generation++;
	publish_inode_generation_locked(ino, state, reason);
}

static void cache_mutation_add(struct perf_cache_mutation *mutation,
			       fuse_ino_t ino)
{
	size_t index;

	if (!ino || mutation->overflow)
		return;
	for (index = 0; index < mutation->count; index++) {
		if (mutation->inodes[index] == ino)
			return;
	}
	if (mutation->count == PERF_CACHE_MUTATION_MAX_INODES) {
		mutation->overflow = true;
		return;
	}
	mutation->inodes[mutation->count++] = ino;
}

static bool cache_mutation_begin(struct perf_cache_mutation *mutation)
{
	struct perf_inode_generation *states[PERF_CACHE_MUTATION_MAX_INODES];
	size_t index;

	if (!metadata_hits_enabled() || !mutation->count)
		return true;
	pthread_mutex_lock(&perf_state.backing_mutex);
	if (perf_state.cache_bypass && perf_state.xattr_cache_bypass)
		goto out;
	if (mutation->overflow) {
		counter_increment(&perf_state.counters.passthrough_state_errors);
		disable_all_caches_locked("inode-generation-overflow");
		goto out;
	}
	for (index = 0; index < mutation->count; index++) {
		states[index] = get_inode_generation_locked(
			mutation->inodes[index]);
		if (!states[index]) {
			counter_increment(
				&perf_state.counters.passthrough_state_errors);
			disable_all_caches_locked(
				"inode-generation-allocation");
			goto out;
		}
		if (states[index]->generation ==
				EXTFUSE_NATIVE_STATE_SEQUENCE_MAX ||
		    states[index]->active == EXTFUSE_NATIVE_STATE_ACTIVE_MASK) {
			counter_increment(
				&perf_state.counters.passthrough_state_errors);
			disable_all_caches_locked(
				"inode-generation-counter-overflow");
			goto out;
		}
	}
	for (index = 0; index < mutation->count; index++) {
		states[index]->generation++;
		states[index]->active++;
	}
	mutation->armed = true;
	for (index = 0; index < mutation->count; index++)
		publish_inode_generation_locked(mutation->inodes[index],
						 states[index],
						 "daemon-mutation-begin");
out:
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return counter_value(&perf_state.counters.cache_bypass_errors) == 0;
}

static void cache_mutation_end(struct perf_cache_mutation *mutation)
{
	struct perf_inode_generation *state;
	bool invalid_state = false;
	size_t index;

	if (!mutation->armed)
		return;
	pthread_mutex_lock(&perf_state.backing_mutex);
	for (index = 0; index < mutation->count; index++) {
		state = find_inode_generation_locked(mutation->inodes[index]);
		if (!state || !state->active) {
			invalid_state = true;
			continue;
		}
		if (state->generation == EXTFUSE_NATIVE_STATE_SEQUENCE_MAX)
			invalid_state = true;
		else {
			state->generation++;
			state->active--;
			publish_inode_generation_locked(
				mutation->inodes[index], state,
				"daemon-mutation-end");
			continue;
		}
		state->active--;
	}
	mutation->armed = false;
	if (invalid_state) {
		counter_increment(&perf_state.counters.passthrough_state_errors);
		disable_all_caches_locked("inode-generation-state");
	}
	pthread_mutex_unlock(&perf_state.backing_mutex);
}

static uint64_t timeout_seconds(double timeout)
{
	if (timeout <= 0)
		return 0;
	if (timeout >= (double)UINT64_MAX)
		return UINT64_MAX;
	return (uint64_t)timeout;
}

static uint32_t timeout_nanoseconds(double timeout)
{
	double fraction;

	if (timeout <= 0)
		return 0;
	fraction = timeout - (double)timeout_seconds(timeout);
	if (fraction <= 0)
		return 0;
	if (fraction >= 0.999999999)
		return 999999999;
	return (uint32_t)(fraction * 1000000000.0);
}

static void stat_to_fuse_attr(const struct stat *st, struct fuse_attr *attr)
{
	memset(attr, 0, sizeof(*attr));
	attr->ino = st->st_ino;
	attr->mode = st->st_mode;
	attr->nlink = st->st_nlink;
	attr->uid = st->st_uid;
	attr->gid = st->st_gid;
	attr->rdev = st->st_rdev;
	attr->size = st->st_size;
	attr->blksize = st->st_blksize;
	attr->blocks = st->st_blocks;
	attr->atime = st->st_atim.tv_sec;
	attr->mtime = st->st_mtim.tv_sec;
	attr->ctime = st->st_ctim.tv_sec;
	attr->atimensec = st->st_atim.tv_nsec;
	attr->mtimensec = st->st_mtim.tv_nsec;
	attr->ctimensec = st->st_ctim.tv_nsec;
}

static int disable_metadata_cache_locked(const char *reason)
{
	const uint32_t opcodes[] = {
		FUSE_LOOKUP,
		FUSE_GETATTR,
	};
	size_t index;
	int result = 0;

	if (perf_state.cache_bypass)
		return 0;
	perf_state.cache_bypass = true;
	counter_increment(&perf_state.counters.cache_bypass_events);
	for (index = 0; index < sizeof(opcodes) / sizeof(opcodes[0]); index++) {
		ebpf_ctrl_key_t key = { .opcode = opcodes[index] };

		if (ebpf_ctrl_delete(perf_state.bpf, &key) && errno != ENOENT) {
			counter_increment(&perf_state.counters.cache_bypass_errors);
			fprintf(stderr,
				"CACHE_BYPASS_ERROR opcode=%u reason=%s errno=%d "
				"error=%s\n",
				opcodes[index], reason, errno, strerror(errno));
			result = -1;
		}
	}
	if (result && perf_state.session)
		fuse_session_exit(perf_state.session);
	fprintf(stderr, "CACHE_BYPASS reason=%s result=%s\n", reason,
		result ? "FATAL" : "UPCALL");
	return result;
}

static int disable_xattr_cache_locked(const char *reason)
{
	ebpf_ctrl_key_t key = { .opcode = FUSE_GETXATTR };
	int result = 0;

	if (perf_state.xattr_cache_bypass)
		return 0;
	perf_state.xattr_cache_bypass = true;
	counter_increment(&perf_state.counters.cache_bypass_events);
	if (ebpf_ctrl_delete(perf_state.bpf, &key) && errno != ENOENT) {
		counter_increment(&perf_state.counters.cache_bypass_errors);
		fprintf(stderr,
			"CACHE_BYPASS_ERROR opcode=%u reason=%s errno=%d "
			"error=%s\n",
			FUSE_GETXATTR, reason, errno, strerror(errno));
		result = -1;
	}
	if (result && perf_state.session)
		fuse_session_exit(perf_state.session);
	fprintf(stderr, "CACHE_BYPASS opcode=GETXATTR reason=%s result=%s\n",
		reason, result ? "FATAL" : "UPCALL");
	return result;
}

static int cache_attr_locked(fuse_ino_t nodeid, const struct stat *st,
			     double timeout, uint64_t daemon_state,
			     uint64_t native_state, bool existing_only,
			     bool *missing)
{
	struct attr_key key = { .nodeid = nodeid };
	struct attr_value value = {
		.native_state = native_state,
		.daemon_state = daemon_state,
	};
	int result;

	if (missing)
		*missing = false;
	value.out.attr_valid = timeout_seconds(timeout);
	value.out.attr_valid_nsec = timeout_nanoseconds(timeout);
	stat_to_fuse_attr(st, &value.out.attr);
	if (existing_only)
		result = ebpf_data_replace(perf_state.bpf, &key, &value,
					   EXTFUSE_ATTR_MAP);
	else
		result = ebpf_data_update(perf_state.bpf, &key, &value,
					  EXTFUSE_ATTR_MAP, 1);
	if (result) {
		uint64_t errors;

		if (existing_only && errno == ENOENT) {
			if (missing)
				*missing = true;
			return 0;
		}
		counter_increment(&perf_state.counters.cache_update_errors);
		errors = counter_value(&perf_state.counters.cache_update_errors);
		if (errors <= 8)
			fprintf(stderr,
				"CACHE_ERROR map=attr nodeid=%" PRIu64
				" errno=%d error=%s\n",
					(uint64_t)nodeid, errno, strerror(errno));
		disable_metadata_cache_locked("attr-update");
		return -1;
	}
	counter_increment(&perf_state.counters.cache_attr_updates);
	return 0;
}

static enum perf_cache_attr_outcome
cache_attr(fuse_ino_t nodeid, const struct stat *st, double timeout,
	   const struct perf_cache_snapshot *snapshot, bool existing_only,
	   double *reply_timeout)
{
	bool missing;
	bool suppressed;
	bool mmap_suppressed;
	bool stable;
	enum perf_cache_attr_outcome outcome = PERF_CACHE_ATTR_DISABLED;

	*reply_timeout = timeout;
	if (!metadata_hits_enabled())
		return outcome;
	pthread_mutex_lock(&perf_state.backing_mutex);
	if (perf_state.cache_bypass) {
		*reply_timeout = 0;
		goto out;
	}
	stable = cache_snapshot_stable_locked(nodeid, snapshot);
	suppressed = attr_cache_suppressed_locked(nodeid, &mmap_suppressed);
	/*
	 * generation은 userspace가 관리하는 BPF cache만 보호한다. 관계없는
	 * inode의 mutation은 이 snapshot을 폐기하지 않는다. 정상 FUSE
	 * A snapshot which overlapped a mutation must not be installed in either
	 * the BPF map or the kernel's inode-attribute cache. Stable ordinary replies
	 * keep the configured TTL. Native mmap page faults can mutate lower metadata
	 * after RELEASE, so marked inodes also use zero TTL permanently.
	 */
	if (!stable) {
		*reply_timeout = 0;
		outcome = PERF_CACHE_ATTR_UNSTABLE;
		goto out;
	}
	if (suppressed) {
		if (mmap_suppressed) {
			*reply_timeout = 0;
			counter_increment(
				&perf_state.counters.passthrough_mmap_suppressions);
		} else {
			counter_increment(
				&perf_state.counters.passthrough_attr_suppressions);
		}
		outcome = PERF_CACHE_ATTR_SUPPRESSED;
		goto out;
	}
	if (cache_attr_locked(nodeid, st, timeout, snapshot->daemon_state,
			      snapshot->native_state, existing_only, &missing))
		outcome = PERF_CACHE_ATTR_ERROR;
	else if (missing) {
		*reply_timeout = 0;
		outcome = PERF_CACHE_ATTR_MISSING;
	} else {
		outcome = PERF_CACHE_ATTR_PUBLISHED;
	}
out:
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return outcome;
}

static int cache_entry(fuse_ino_t parent, const char *name,
			       struct fuse_entry_param *entry,
			       const struct perf_cache_snapshot *snapshot)
{
	struct entry_key key = {};
	struct entry_value value = {
		.nlookup = 1,
		.nodeid = entry->ino,
		.generation = entry->generation,
	};
	bool attr_suppressed;
	bool mmap_suppressed;
	bool stable;
	int result = 0;

	if (!metadata_hits_enabled())
		return 0;
	if (strlen(name) >= sizeof(key.name)) {
		errno = ENAMETOOLONG;
		counter_increment(&perf_state.counters.cache_update_errors);
		return -1;
	}
	key.nodeid = parent;
	memcpy(key.name, name, strlen(name) + 1);
	value.entry_valid = timeout_seconds(entry->entry_timeout);
	value.entry_valid_nsec = timeout_nanoseconds(entry->entry_timeout);

	pthread_mutex_lock(&perf_state.backing_mutex);
	if (perf_state.cache_bypass) {
		entry->attr_timeout = 0;
		goto out;
	}
	stable = cache_snapshot_stable_locked(entry->ino, snapshot);
	attr_suppressed = attr_cache_suppressed_locked(entry->ino,
						      &mmap_suppressed);
	if (perf_state.cache_bypass) {
		entry->attr_timeout = 0;
		goto out;
	}
	if (!stable)
		entry->attr_timeout = 0;
	if (attr_suppressed) {
		/*
		 * native mmap page faults can bypass daemon-side invalidation.
		 * 해당 inode의 attr만 BPF cache에서 제외한다. entry는 아래에서
		 * 저장하지만 BPF LOOKUP이 mmap marker를 먼저 확인해 upcall한다.
		 */
		if (mmap_suppressed) {
			entry->attr_timeout = 0;
			counter_increment(
				&perf_state.counters.passthrough_mmap_suppressions);
		} else {
			counter_increment(
				&perf_state.counters.passthrough_attr_suppressions);
		}
	} else if (stable &&
		   cache_attr_locked(entry->ino, &entry->attr,
				     entry->attr_timeout,
				     snapshot->daemon_state,
				     snapshot->native_state, false, NULL)) {
		result = -1;
		goto out;
	}
	/*
	 * namespace lock이 parent/name identity를 보호하므로 positive entry는
	 * 항상 적재한다. 전역 attr mutation과 겹쳤다는 이유로 entry까지 버리면
	 * 병렬 compile에서 원본 Figure 2의 insertion 정책을 잃게 된다.
	 */
	if (ebpf_data_update(perf_state.bpf, &key, &value,
			     EXTFUSE_ENTRY_MAP, 1)) {
		uint64_t errors;

		counter_increment(&perf_state.counters.cache_update_errors);
		errors = counter_value(&perf_state.counters.cache_update_errors);
		if (errors <= 8)
			fprintf(stderr,
				"CACHE_ERROR map=entry parent=%" PRIu64
				" name=%s errno=%d error=%s\n",
					(uint64_t)parent, name, errno, strerror(errno));
		disable_metadata_cache_locked("entry-update");
		result = -1;
		goto out;
	}
	counter_increment(&perf_state.counters.cache_entry_updates);
out:
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return result;
}

/*
 * StackFS returns a one-second negative fuse_entry_param and stores the same
 * parent/name result in its ExtFUSE entry map.  Keep that observable policy in
 * the modern passthrough target as well; namespace mutations already invalidate
 * the affected parent/name key under namespace_lock.
 */
static int cache_negative_entry(fuse_ino_t parent, const char *name,
				 double timeout)
{
	struct entry_key key = {};
	struct entry_value value = {
		.nlookup = 0,
		.nodeid = 0,
		.entry_valid = timeout_seconds(timeout),
		.entry_valid_nsec = timeout_nanoseconds(timeout),
	};
	int result = 0;

	if (!metadata_hits_enabled())
		return 0;
	if (strlen(name) >= sizeof(key.name)) {
		errno = ENAMETOOLONG;
		counter_increment(&perf_state.counters.cache_update_errors);
		return -1;
	}
	key.nodeid = parent;
	memcpy(key.name, name, strlen(name) + 1);

	pthread_mutex_lock(&perf_state.backing_mutex);
	if (perf_state.cache_bypass)
		goto out;
	if (ebpf_data_update(perf_state.bpf, &key, &value,
			     EXTFUSE_ENTRY_MAP, 1)) {
		counter_increment(&perf_state.counters.cache_update_errors);
		fprintf(stderr,
			"CACHE_ERROR map=entry-negative parent=%" PRIu64
			" name=%s errno=%d error=%s\n",
			(uint64_t)parent, name, errno, strerror(errno));
		disable_metadata_cache_locked("negative-entry-update");
		result = -1;
		goto out;
	}
	counter_increment(&perf_state.counters.cache_entry_updates);
out:
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return result;
}

static int fill_xattr_key(struct xattr_key *key, fuse_ino_t nodeid,
			  const char *name)
{
	size_t length = strlen(name);

	if (length >= sizeof(key->name)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memset(key, 0, sizeof(*key));
	key->nodeid = nodeid;
	memcpy(key->name, name, length + 1);
	return 0;
}

/*
 * The caller holds the inode's xattr stripe from the lower-filesystem read
 * through this map update.  Unlike the global metadata epoch, that excludes
 * only mutations which can change this inode's xattrs, so parallel activity
 * on unrelated compile outputs cannot discard a valid snapshot.
 */
static int cache_xattr_reply_serialized(fuse_ino_t nodeid, const char *name,
					const void *data, size_t size,
					int error,
					const struct perf_cache_snapshot *snapshot)
{
	struct xattr_key key;
	struct xattr_value value = {
		.error = error,
		.size = size,
		.native_state = snapshot->native_state,
		.daemon_state = snapshot->daemon_state,
	};
	int result = 0;

	if (!metadata_hits_enabled() || size > PERF_XATTR_VALUE_MAX)
		return 0;
	if ((error != 0 && error != ENODATA) ||
	    (error == ENODATA && (size || data)) || (size && !data))
		return 0;
	if (fill_xattr_key(&key, nodeid, name))
		return 0;
	if (size)
		memcpy(value.data, data, size);

	pthread_mutex_lock(&perf_state.backing_mutex);
	if (perf_state.xattr_cache_bypass)
		goto out;
	if (!cache_snapshot_stable_locked(nodeid, snapshot))
		goto out;
	if (ebpf_data_update(perf_state.bpf, &key, &value,
			     EXTFUSE_XATTR_MAP, 1)) {
		counter_increment(&perf_state.counters.cache_update_errors);
		fprintf(stderr,
			"CACHE_ERROR map=xattr nodeid=%" PRIu64
			" name=%s errno=%d error=%s\n",
			(uint64_t)nodeid, name, errno, strerror(errno));
		disable_xattr_cache_locked("xattr-update");
		result = -1;
		goto out;
	}
	counter_increment(&perf_state.counters.cache_xattr_updates);
out:
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return result;
}

/* The caller holds xattr_lock_for_inode(nodeid). */
static bool negative_capability_cache_current_serialized(fuse_ino_t nodeid,
							 uint64_t *daemon_state)
{
	struct xattr_key key;
	struct xattr_value value;
	bool current = false;

	*daemon_state = 0;
	if (!metadata_hits_enabled() ||
	    fill_xattr_key(&key, nodeid, PERF_CAPABILITY_XATTR))
		return false;

	pthread_mutex_lock(&perf_state.backing_mutex);
	if (perf_state.xattr_cache_bypass ||
	    (wbcache_passthrough_enabled() &&
	     has_passthrough_mmap_marker_locked(nodeid)))
		goto out;
	if (ebpf_data_lookup(perf_state.bpf, &key, &value, EXTFUSE_XATTR_MAP)) {
		if (errno == ENOENT)
			goto out;
		counter_increment(&perf_state.counters.cache_update_errors);
		fprintf(stderr,
			"CACHE_ERROR map=xattr operation=negative-lookup nodeid=%" PRIu64
			" errno=%d error=%s\n",
			(uint64_t)nodeid, errno, strerror(errno));
		disable_xattr_cache_locked("negative-capability-lookup");
		goto out;
	}
	current = value.error == ENODATA && !value.size &&
		  inode_generation_stable_locked(nodeid, value.daemon_state);
	if (current)
		*daemon_state = value.daemon_state;
out:
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return current;
}

/*
 * The caller still holds xattr_lock_for_inode(nodeid) after a successful data
 * write.  A data write can remove security.capability, but cannot create one,
 * so a previously current ENODATA result remains true.  Refresh only that
 * existing row: an eviction or any coherence race must remain a normal miss.
 */
static void
refresh_negative_capability_serialized(fuse_ino_t nodeid,
				       uint64_t previous_daemon_state)
{
	struct perf_inode_generation *state;
	struct xattr_key key;
	struct xattr_value current;
	struct xattr_value replacement = {
		.error = ENODATA,
	};

	if (!metadata_hits_enabled() ||
	    fill_xattr_key(&key, nodeid, PERF_CAPABILITY_XATTR))
		return;

	pthread_mutex_lock(&perf_state.backing_mutex);
	if (perf_state.xattr_cache_bypass ||
	    (wbcache_passthrough_enabled() &&
	     has_passthrough_mmap_marker_locked(nodeid)))
		goto out;
	state = find_inode_generation_locked(nodeid);
	if (!inode_generation_value_locked(state, &replacement.daemon_state)) {
		counter_increment(
			&perf_state.counters.passthrough_state_errors);
		disable_all_caches_locked("negative-capability-state");
		goto out;
	}
	if (replacement.daemon_state & EXTFUSE_NATIVE_STATE_ACTIVE_MASK)
		goto out;
	if (ebpf_data_lookup(perf_state.bpf, &key, &current,
			     EXTFUSE_XATTR_MAP)) {
		if (errno == ENOENT)
			goto out;
		goto error;
	}
	if (current.error != ENODATA || current.size ||
	    current.daemon_state != previous_daemon_state)
		goto out;
	replacement.native_state = current.native_state;
	if (!ebpf_data_replace(perf_state.bpf, &key, &replacement,
			       EXTFUSE_XATTR_MAP)) {
		counter_increment(&perf_state.counters.cache_xattr_updates);
		goto out;
	}
	if (errno == ENOENT)
		goto out;
error:
	counter_increment(&perf_state.counters.cache_update_errors);
	fprintf(stderr,
		"CACHE_ERROR map=xattr operation=negative-refresh nodeid=%" PRIu64
		" errno=%d error=%s\n",
		(uint64_t)nodeid, errno, strerror(errno));
	disable_xattr_cache_locked("negative-capability-refresh");
out:
	pthread_mutex_unlock(&perf_state.backing_mutex);
}

static int invalidate_xattr_locked(fuse_ino_t nodeid, const char *name,
				   bool positive_only)
{
	struct xattr_key key;
	struct xattr_value value;

	if (!metadata_hits_enabled() ||
	    perf_state.xattr_cache_bypass)
		return 0;
	if (fill_xattr_key(&key, nodeid, name))
		return 0;
	if (positive_only) {
		if (ebpf_data_lookup(perf_state.bpf, &key, &value,
				     EXTFUSE_XATTR_MAP)) {
			if (errno == ENOENT)
				return 0;
			goto error;
		}
		if (value.error == ENODATA)
			return 0;
	}
	if (!ebpf_data_delete(perf_state.bpf, &key, EXTFUSE_XATTR_MAP)) {
		counter_increment(&perf_state.counters.cache_xattr_invalidations);
		return 0;
	}
	if (errno == ENOENT)
		return 0;
error:
	counter_increment(&perf_state.counters.cache_invalidation_errors);
	fprintf(stderr,
		"CACHE_INVALIDATION_ERROR map=xattr nodeid=%" PRIu64
		" name=%s errno=%d error=%s\n",
		(uint64_t)nodeid, name, errno, strerror(errno));
	disable_xattr_cache_locked("xattr-delete");
	return -1;
}

static int invalidate_xattr(fuse_ino_t nodeid, const char *name,
			    bool positive_only)
{
	pthread_mutex_t *xattr_lock = xattr_lock_for_inode(nodeid);
	int result;

	pthread_mutex_lock(xattr_lock);
	pthread_mutex_lock(&perf_state.backing_mutex);
	result = invalidate_xattr_locked(nodeid, name, positive_only);
	pthread_mutex_unlock(&perf_state.backing_mutex);
	pthread_mutex_unlock(xattr_lock);
	return result;
}

/* The caller already holds xattr_lock_for_inode(nodeid). */
static int invalidate_xattr_serialized(fuse_ino_t nodeid, const char *name,
				       bool positive_only)
{
	int result;

	pthread_mutex_lock(&perf_state.backing_mutex);
	result = invalidate_xattr_locked(nodeid, name, positive_only);
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return result;
}

static int invalidate_attr_locked(fuse_ino_t nodeid)
{
	struct attr_key key = { .nodeid = nodeid };

	if (!metadata_hits_enabled())
		return 0;
	if (perf_state.cache_bypass && perf_state.xattr_cache_bypass)
		return 0;
	/*
	 * Every deletion advances the exact nodeid generation, including
	 * invalidations discovered indirectly through an entry-map lookup and
	 * failure cleanup outside an explicit mutation guard.  A snapshot which
	 * started before this point can therefore never republish the deleted
	 * value after the map delete completes.
	 */
	advance_inode_generation_locked(nodeid, "attr-invalidation-generation");
	if (perf_state.cache_bypass)
		return 0;
	if (!ebpf_data_delete(perf_state.bpf, &key, EXTFUSE_ATTR_MAP)) {
		counter_increment(
			&perf_state.counters.cache_attr_invalidations);
		return 0;
	}
	if (errno == ENOENT)
		return 0;
	counter_increment(&perf_state.counters.cache_invalidation_errors);
	fprintf(stderr,
		"CACHE_INVALIDATION_ERROR map=attr nodeid=%" PRIu64
		" errno=%d error=%s\n",
		(uint64_t)nodeid, errno, strerror(errno));
	disable_metadata_cache_locked("attr-delete");
	return -1;
}

static int invalidate_attr(fuse_ino_t nodeid)
{
	int result;

	pthread_mutex_lock(&perf_state.backing_mutex);
	result = invalidate_attr_locked(nodeid);
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return result;
}

static int invalidate_entry_locked(fuse_ino_t parent, const char *name)
{
	struct entry_key key = { .nodeid = parent };
	struct entry_value value = {};
	int lookup_error;
	int result = 0;

	if (!metadata_hits_enabled())
		return 0;
	if (perf_state.cache_bypass)
		return 0;
	if (strlen(name) >= sizeof(key.name)) {
		errno = ENAMETOOLONG;
		counter_increment(
			&perf_state.counters.cache_invalidation_errors);
		return -1;
	}
	memcpy(key.name, name, strlen(name) + 1);
	if (invalidate_attr_locked(parent))
		result = -1;
	if (perf_state.cache_bypass)
		return -1;
	if (ebpf_data_lookup(perf_state.bpf, &key, &value,
			     EXTFUSE_ENTRY_MAP)) {
		lookup_error = errno;
		if (lookup_error != ENOENT) {
			counter_increment(
				&perf_state.counters.cache_invalidation_errors);
			fprintf(stderr,
				"CACHE_INVALIDATION_ERROR map=entry_lookup "
				"parent=%" PRIu64 " name=%s errno=%d "
				"error=%s\n",
				(uint64_t)parent, name, lookup_error,
				strerror(lookup_error));
			result = -1;
		}
	} else if (value.nodeid && invalidate_attr_locked(value.nodeid)) {
		result = -1;
	}
	if (perf_state.cache_bypass)
		return -1;
	if (!ebpf_data_delete(perf_state.bpf, &key, EXTFUSE_ENTRY_MAP)) {
		counter_increment(
			&perf_state.counters.cache_entry_invalidations);
	} else if (errno != ENOENT) {
		counter_increment(
			&perf_state.counters.cache_invalidation_errors);
		fprintf(stderr,
			"CACHE_INVALIDATION_ERROR map=entry_delete "
			"parent=%" PRIu64 " name=%s errno=%d error=%s\n",
			(uint64_t)parent, name, errno, strerror(errno));
		result = -1;
	}
	if (result && !perf_state.cache_bypass)
		disable_metadata_cache_locked("entry-invalidation");
	return result;
}

static int invalidate_entry(fuse_ino_t parent, const char *name)
{
	int result;

	pthread_mutex_lock(&perf_state.backing_mutex);
	result = invalidate_entry_locked(parent, name);
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return result;
}

static void apply_wbcache_passthrough_flags(struct fuse_file_info *fi,
					    int backing_id)
{
	fi->backing_id = backing_id;
	/*
	 * Keep the ordinary FUSE page cache.  Only page-backed READ/WRITE
	 * requests selected by the ExtFUSE policy use the registered lower file.
	 */
	fi->extfuse_wbcache_passthrough = 1;
	fi->direct_io = 0;
	fi->parallel_direct_writes = 0;
}

/*
 * AllOpt is an experimental invariant, not a best-effort mount mode.  Finish
 * the callback that discovered the failure so its side effects and reply stay
 * consistent, but request loop shutdown immediately.  The validation harness
 * then rejects the fallback counters instead of measuring daemon I/O as
 * WBCache passthrough.
 */
static void request_allopt_session_exit(void)
{
	if (perf_state.session)
		fuse_session_exit(perf_state.session);
}

/*
 * candidate is preallocated before CREATE can modify the lower filesystem.
 * Legacy native fallback also preallocates tombstone_candidate; paper WBCache
 * passes NULL because its ordinary READ/WRITE hooks provide the finite
 * invalidation boundary.  This function always consumes both objects.
 */
static void attach_wbcache_passthrough(fuse_req_t req, fuse_ino_t ino, int fd,
				       struct fuse_file_info *fi,
				       struct perf_backing *candidate,
				       struct perf_tombstone *tombstone_candidate)
{
	struct perf_backing **link;
	struct perf_backing *backing;
	uint64_t count;
	int backing_id;
	int saved_error;

	fi->backing_id = 0;
	fi->extfuse_wbcache_passthrough = 0;
	pthread_mutex_lock(&perf_state.backing_mutex);
	backing = find_backing_locked(ino, &link);
	if (backing && backing->mode == PERF_BACKING_QUARANTINED &&
	    !backing->open_count) {
		const char *reason = NULL;

		errno = 0;
		if (invalidate_attr_locked(ino)) {
			saved_error = errno ? errno : EIO;
			reason = "quarantine-attr-delete";
			counter_increment(
				&perf_state.counters.passthrough_state_errors);
		} else if (backing->backing_id > 0 &&
			   fuse_passthrough_close(req,
						  backing->backing_id) < 0) {
			saved_error = errno ? errno : EIO;
			reason = "quarantine-backing-close";
			counter_increment(
				&perf_state.counters.passthrough_close_errors);
		}
		if (reason) {
			free(candidate);
			free(tombstone_candidate);
			backing->open_count = 1;
			counter_increment(
				&perf_state.counters
					 .passthrough_fallback_cohorts);
			counter_increment(
				&perf_state.counters.passthrough_fallback_opens);
			count = counter_value(
				&perf_state.counters
					 .passthrough_fallback_cohorts);
			if (count <= 8)
				fprintf(stderr,
					"PASSTHROUGH_FALLBACK nodeid=%" PRIu64
					" reason=%s errno=%d error=%s\n",
					(uint64_t)ino, reason, saved_error,
					strerror(saved_error));
			request_allopt_session_exit();
			pthread_mutex_unlock(&perf_state.backing_mutex);
			return;
		}
		if (backing->backing_id > 0)
			counter_increment(
				&perf_state.counters.passthrough_closes);
		advance_inode_generation_locked(ino,
					 "backing-quarantine-removal");
		*link = backing->next;
		counter_decrement(
			&perf_state.counters.passthrough_tracked_records);
		free(backing);
		backing = NULL;
	}
	if (backing) {
		free(candidate);
		free(tombstone_candidate);
		backing->open_count++;
		if (backing->mode == PERF_BACKING_WBCACHE) {
			counter_increment(&perf_state.counters.passthrough_reuses);
			apply_wbcache_passthrough_flags(fi,
						  backing->backing_id);
			counter_increment(&perf_state.counters.passthrough_opens);
		} else {
			counter_increment(
				&perf_state.counters.passthrough_fallback_opens);
			request_allopt_session_exit();
		}
		pthread_mutex_unlock(&perf_state.backing_mutex);
		return;
	}

	backing = candidate;
	backing->ino = ino;
	backing->open_count = 1;
	backing->mode = PERF_BACKING_DAEMON;
	backing->registration_may_modify = file_may_modify(fi->flags);
	backing->next = *link;
	*link = backing;
	counter_increment(&perf_state.counters.passthrough_tracked_records);

	errno = 0;
	if (!paper_wbcache_passthrough_enabled() &&
	    invalidate_attr_locked(ino)) {
		saved_error = errno ? errno : EIO;
		backing->mode = PERF_BACKING_QUARANTINED;
		free(tombstone_candidate);
		counter_increment(
			&perf_state.counters.passthrough_state_errors);
		counter_increment(
			&perf_state.counters.passthrough_fallback_cohorts);
		counter_increment(
			&perf_state.counters.passthrough_fallback_opens);
		count = counter_value(
			&perf_state.counters.passthrough_fallback_cohorts);
		if (count <= 8)
			fprintf(stderr,
				"PASSTHROUGH_FALLBACK nodeid=%" PRIu64
				" reason=attr-delete errno=%d error=%s\n",
				(uint64_t)ino, saved_error,
				strerror(saved_error));
		request_allopt_session_exit();
		pthread_mutex_unlock(&perf_state.backing_mutex);
		return;
	}

	errno = 0;
	backing_id = fuse_passthrough_open(req, fd);
	saved_error = errno ? errno : EIO;
	if (backing_id > 0) {
		backing->backing_id = backing_id;
		backing->mode = PERF_BACKING_WBCACHE;
		if (paper_wbcache_passthrough_enabled() ||
		    perf_state.passthrough_coherence_v2_requested ||
		    coherence_epochs_enabled())
			free(tombstone_candidate);
		else
			add_tombstone_locked(ino, tombstone_candidate);
		counter_increment(
			&perf_state.counters.passthrough_registrations);
		if (!paper_wbcache_passthrough_enabled())
			advance_inode_generation_locked(ino,
						 "backing-registration");
		apply_wbcache_passthrough_flags(fi, backing_id);
		counter_increment(&perf_state.counters.passthrough_opens);
		count = counter_value(
			&perf_state.counters.passthrough_registrations);
		if (count <= 8)
			fprintf(stderr,
				"PASSTHROUGH_REGISTER nodeid=%" PRIu64
				" backing_id=%d\n",
				(uint64_t)ino, backing_id);
	} else {
		free(tombstone_candidate);
		counter_increment(
			&perf_state.counters.passthrough_fallback_cohorts);
		counter_increment(
			&perf_state.counters.passthrough_fallback_opens);
		count = counter_value(
			&perf_state.counters.passthrough_fallback_cohorts);
		if (count <= 8)
			fprintf(stderr,
				"PASSTHROUGH_FALLBACK nodeid=%" PRIu64
				" reason=backing-open errno=%d error=%s\n",
				(uint64_t)ino, saved_error,
				strerror(saved_error));
		request_allopt_session_exit();
	}
	pthread_mutex_unlock(&perf_state.backing_mutex);
}

static bool classify_wbcache_passthrough_release(fuse_ino_t ino,
						 bool handle_may_modify,
						 bool *may_modify,
						 bool *registration_refresh)
{
	struct perf_backing *backing;
	uint64_t errors;

	*may_modify = handle_may_modify;
	*registration_refresh = false;
	pthread_mutex_lock(&perf_state.backing_mutex);
	backing = find_backing_locked(ino, NULL);
	if (!backing || !backing->open_count) {
		counter_increment(
			&perf_state.counters.passthrough_state_errors);
		errors = counter_value(
			&perf_state.counters.passthrough_state_errors);
		if (errors <= 8)
			fprintf(stderr,
				"PASSTHROUGH_STATE_ERROR operation=%s nodeid=%" PRIu64 "\n",
				"release-plan",
				(uint64_t)ino);
		request_allopt_session_exit();
		pthread_mutex_unlock(&perf_state.backing_mutex);
		return false;
	}

	/*
	 * The kernel-held registered file can outlive its originating handle.
	 * Refresh when that writable registration is finally retired, even if the
	 * userspace handle delivering the last RELEASE was opened read-only.
	 */
	if (backing->open_count == 1 && backing->registration_may_modify) {
		*may_modify = true;
		*registration_refresh = !handle_may_modify;
	}
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return true;
}

static bool release_wbcache_passthrough(fuse_req_t req, fuse_ino_t ino,
					bool advance_generation)
{
	struct perf_backing **link;
	struct perf_backing *backing;
	uint64_t errors;

	pthread_mutex_lock(&perf_state.backing_mutex);
	backing = find_backing_locked(ino, &link);
	if (!backing || !backing->open_count) {
		counter_increment(
			&perf_state.counters.passthrough_state_errors);
		errors = counter_value(
			&perf_state.counters.passthrough_state_errors);
		if (errors <= 8)
			fprintf(stderr,
				"PASSTHROUGH_STATE_ERROR operation=release "
				"nodeid=%" PRIu64 "\n",
				(uint64_t)ino);
		request_allopt_session_exit();
		pthread_mutex_unlock(&perf_state.backing_mutex);
		return false;
	}

	backing->open_count--;
	if (backing->open_count) {
		pthread_mutex_unlock(&perf_state.backing_mutex);
		return true;
	}

	if (backing->mode != PERF_BACKING_DAEMON) {
		/*
		 * Legacy native fallback has no lower-I/O completion notification,
		 * so its final close still invalidates attributes.  Paper WBCache
		 * forwarding performs its cache side effects in the ordinary I/O
		 * handler; the strict gate uses epochs and a final snapshot.
		 */
		if (!paper_wbcache_passthrough_enabled() &&
		    !perf_state.passthrough_coherence_v2_requested &&
		    !coherence_epochs_enabled() &&
		    invalidate_attr_locked(ino)) {
			backing->mode = PERF_BACKING_QUARANTINED;
			counter_increment(
				&perf_state.counters.passthrough_state_errors);
			request_allopt_session_exit();
			pthread_mutex_unlock(&perf_state.backing_mutex);
			return false;
		}
		if (backing->backing_id > 0 &&
		    fuse_passthrough_close(req, backing->backing_id) < 0) {
			backing->mode = PERF_BACKING_QUARANTINED;
			counter_increment(
				&perf_state.counters.passthrough_close_errors);
			request_allopt_session_exit();
			pthread_mutex_unlock(&perf_state.backing_mutex);
			return false;
		}
		if (backing->backing_id > 0)
			counter_increment(
				&perf_state.counters.passthrough_closes);
	}

	/* Clean read-only retirement does not change metadata or its generation. */
	if (advance_generation)
		advance_inode_generation_locked(ino, "backing-release");
	*link = backing->next;
	counter_decrement(
		&perf_state.counters.passthrough_tracked_records);
	free(backing);
	pthread_mutex_unlock(&perf_state.backing_mutex);
	return true;
}

static void cleanup_wbcache_passthrough_state(void)
{
	struct perf_backing *backing;
	struct perf_tombstone *tombstone;
	size_t bucket;
	uint64_t residuals = 0;

	pthread_mutex_lock(&perf_state.backing_mutex);
	while ((backing = perf_state.backings)) {
		perf_state.backings = backing->next;
		residuals++;
		counter_increment(
			&perf_state.counters.passthrough_residual_records);
		counter_decrement(
			&perf_state.counters.passthrough_tracked_records);
		if (residuals <= 8)
			fprintf(stderr,
				"PASSTHROUGH_RESIDUAL nodeid=%" PRIu64
				" backing_id=%d open_count=%" PRIu64
				" mode=%u\n",
				(uint64_t)backing->ino, backing->backing_id,
				backing->open_count,
				(unsigned int)backing->mode);
		free(backing);
	}
	for (bucket = 0; bucket < PERF_TOMBSTONE_BUCKETS; bucket++) {
		while ((tombstone = perf_state.tombstones[bucket])) {
			perf_state.tombstones[bucket] = tombstone->next;
			free(tombstone);
		}
	}
	if (residuals > 8)
		fprintf(stderr,
			"PASSTHROUGH_RESIDUAL suppressed=%" PRIu64 "\n",
			residuals - 8);
	pthread_mutex_unlock(&perf_state.backing_mutex);
}

static void cleanup_inode_generation_state(void)
{
	struct perf_inode_generation *state;
	size_t bucket;

	pthread_mutex_lock(&perf_state.backing_mutex);
	for (bucket = 0; bucket < PERF_INODE_GENERATION_BUCKETS; bucket++) {
		while ((state = perf_state.inode_generations[bucket])) {
			perf_state.inode_generations[bucket] = state->next;
			free(state);
		}
	}
	pthread_mutex_unlock(&perf_state.backing_mutex);
}

static int check_map_layout(int fd, enum bpf_map_type expected_type,
			    uint32_t expected_key, uint32_t expected_value,
			    uint32_t expected_entries, uint32_t expected_flags,
			    const char *name)
{
	struct bpf_map_info info = {};
	uint32_t size = sizeof(info);

	if (bpf_obj_get_info_by_fd(fd, &info, &size))
		return -1;
	if (info.type != expected_type || info.key_size != expected_key ||
	    info.value_size != expected_value ||
	    info.max_entries != expected_entries ||
	    info.map_flags != expected_flags) {
		fprintf(stderr,
			"MAP_ABI_ERROR name=%s type=%u/%u key=%u/%u "
			"value=%u/%u entries=%u/%u flags=0x%x/0x%x\n",
			name, info.type, expected_type, info.key_size,
			expected_key, info.value_size, expected_value,
			info.max_entries, expected_entries, info.map_flags,
			expected_flags);
		errno = EPROTO;
		return -1;
	}
	fprintf(stderr,
		"MAP name=%s id=%u type=%u key=%u value=%u entries=%u "
		"flags=0x%x\n",
		name, info.id, info.type, info.key_size, info.value_size,
		info.max_entries, info.map_flags);
	return 0;
}

static int check_maps(void)
{
	return check_map_layout(
		       perf_state.bpf->data_fd[EXTFUSE_ENTRY_MAP],
		       BPF_MAP_TYPE_HASH, sizeof(struct entry_key),
			       sizeof(struct entry_value), PERF_METADATA_MAX_ENTRIES,
		       BPF_F_NO_PREALLOC, "entry") ||
		       check_map_layout(
			       perf_state.bpf->data_fd[EXTFUSE_ATTR_MAP],
			       BPF_MAP_TYPE_HASH, sizeof(struct attr_key),
			       sizeof(struct attr_value), PERF_METADATA_MAX_ENTRIES,
			       BPF_F_NO_PREALLOC, "attr") ||
		       check_map_layout(
			       perf_state.bpf->data_fd[EXTFUSE_XATTR_MAP],
			       BPF_MAP_TYPE_LRU_HASH, sizeof(struct xattr_key),
			       sizeof(struct xattr_value), PERF_XATTR_MAX_ENTRIES,
			       0, "xattr") ||
		       check_map_layout(
			       perf_state.bpf->data_fd[EXTFUSE_DAEMON_IO_MAP],
			       BPF_MAP_TYPE_HASH, sizeof(uint64_t),
			       sizeof(uint64_t), PERF_METADATA_MAX_ENTRIES,
			       BPF_F_NO_PREALLOC, "daemon_io") ||
		       check_map_layout(
			       perf_state.bpf->data_fd[EXTFUSE_NATIVE_IO_MAP],
			       BPF_MAP_TYPE_HASH, sizeof(uint64_t),
			       sizeof(uint64_t), PERF_METADATA_MAX_ENTRIES,
			       BPF_F_NO_PREALLOC, "native_io") ||
		       check_map_layout(
			       perf_state.bpf->data_fd[EXTFUSE_MMAP_MAP],
			       BPF_MAP_TYPE_HASH, sizeof(uint64_t),
			       sizeof(uint32_t), PERF_METADATA_MAX_ENTRIES,
			       BPF_F_NO_PREALLOC, "mmap") ||
		       check_map_layout(
			       perf_state.bpf->data_fd[EXTFUSE_POLICY_MAP],
			       BPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
			       sizeof(uint32_t), 1, 0, "policy") ||
		       check_map_layout(
		       perf_state.bpf->data_fd[EXTFUSE_HANDLERS_MAP],
		       BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t),
		       sizeof(uint32_t), EXTFUSE_HANDLER_SLOTS, 0,
		       "handlers");
}

static int configure_bpf_policy(void)
{
	uint32_t key = 0;
	uint32_t flags = 0;
	uint32_t observed = 0;

	if (wbcache_passthrough_enabled())
		flags |= EXTFUSE_POLICY_WBCACHE_PASSTHROUGH;
	if (paper_wbcache_passthrough_enabled())
		flags |= EXTFUSE_POLICY_PAPER_READ_ATIME_CACHE;
	if (perf_state.paper_capability_enodata_safe)
		flags |= EXTFUSE_POLICY_PAPER_CAPABILITY_ENODATA;
	if (perf_state.passthrough_attr_release_barrier_requested)
		flags |= EXTFUSE_POLICY_ATTR_RELEASE_BARRIER;
	if (coherence_epochs_enabled())
		flags |= EXTFUSE_POLICY_COHERENCE_EPOCHS;
	if (flags & ~EXTFUSE_POLICY_KNOWN_MASK) {
		errno = EINVAL;
		return -1;
	}
	if (ebpf_data_update(perf_state.bpf, &key, &flags,
			     EXTFUSE_POLICY_MAP, 1)) {
		fprintf(stderr,
			"BPF_POLICY_ERROR flags=0x%08x errno=%d error=%s\n",
			flags, errno, strerror(errno));
		return -1;
	}
	if (ebpf_data_lookup(perf_state.bpf, &key, &observed,
			     EXTFUSE_POLICY_MAP) || observed != flags) {
		if (observed != flags)
			errno = EPROTO;
		fprintf(stderr,
			"BPF_POLICY_ERROR operation=readback expected=0x%08x "
			"observed=0x%08x errno=%d error=%s\n",
			flags, observed, errno, strerror(errno));
		return -1;
	}
	perf_state.bpf_policy_flags = flags;
	fprintf(stderr,
		"BPF_POLICY flags=0x%08x %s=%s %s=%s %s=%s %s=%s %s=%s %s=%s\n",
		flags,
		"paper_read_atime_cache",
		(flags & EXTFUSE_POLICY_PAPER_READ_ATIME_CACHE) ?
			"retained" : "coherent",
		"paper_native_mmap_metadata",
		(flags & EXTFUSE_POLICY_RELAX_NATIVE_MMAP_METADATA) ?
			"relaxed" : "strict",
		"attr_release_barrier",
		(flags & EXTFUSE_POLICY_ATTR_RELEASE_BARRIER) ?
			"enabled" : "disabled",
		"coherence_epochs",
		(flags & EXTFUSE_POLICY_COHERENCE_EPOCHS) ?
			"enabled" : "disabled",
		"wbcache_passthrough",
		(flags & EXTFUSE_POLICY_WBCACHE_PASSTHROUGH) ?
			"enabled" : "disabled",
		"paper_capability_enodata",
		(flags & EXTFUSE_POLICY_PAPER_CAPABILITY_ENODATA) ?
			"enabled" : "disabled");
	return 0;
}

static void revoke_paper_capability_enodata(const char *operation)
{
	uint32_t key = 0;
	uint32_t flags;

	if (!perf_state.bpf ||
	    !perf_state.paper_capability_enodata_safe)
		return;
	pthread_mutex_lock(&perf_state.policy_mutex);
	if (!perf_state.paper_capability_enodata_safe)
		goto out;
	perf_state.paper_capability_enodata_safe = false;
	if (ebpf_data_lookup(perf_state.bpf, &key, &flags,
			     EXTFUSE_POLICY_MAP)) {
		fprintf(stderr,
			"PAPER_CAPABILITY_POLICY result=revoke-error operation=%s errno=%d error=%s\n",
			operation, errno, strerror(errno));
		request_allopt_session_exit();
		goto out;
	}
	flags &= ~EXTFUSE_POLICY_PAPER_CAPABILITY_ENODATA;
	if (ebpf_data_update(perf_state.bpf, &key, &flags,
			     EXTFUSE_POLICY_MAP, 1)) {
		fprintf(stderr,
			"PAPER_CAPABILITY_POLICY result=revoke-error operation=%s errno=%d error=%s\n",
			operation, errno, strerror(errno));
		request_allopt_session_exit();
		goto out;
	}
	perf_state.bpf_policy_flags = flags;
	fprintf(stderr,
		"PAPER_CAPABILITY_POLICY result=revoked operation=%s\n",
		operation);
out:
	pthread_mutex_unlock(&perf_state.policy_mutex);
}

static int force_all_upcalls(void)
{
	const uint32_t opcodes[] = {
		FUSE_LOOKUP,
		FUSE_GETATTR,
		FUSE_SETATTR,
		FUSE_UNLINK,
		FUSE_RMDIR,
		FUSE_RENAME,
		FUSE_RENAME2,
		FUSE_READ,
		FUSE_WRITE,
		FUSE_GETXATTR,
		FUSE_FLUSH,
	};
	size_t i;

	for (i = 0; i < sizeof(opcodes) / sizeof(opcodes[0]); i++) {
		ebpf_ctrl_key_t key = { .opcode = opcodes[i] };

		if (ebpf_ctrl_delete(perf_state.bpf, &key)) {
			fprintf(stderr,
				"HANDLER_DELETE_ERROR opcode=%u errno=%d "
				"error=%s\n",
				opcodes[i], errno, strerror(errno));
			return -1;
		}
	}
	fprintf(stderr, "HANDLERS mode=upcall deleted=%zu\n",
		sizeof(opcodes) / sizeof(opcodes[0]));
	return 0;
}

static int disable_nonmetadata_hits(void)
{
	uint32_t opcodes[] = { FUSE_FLUSH, FUSE_READ };
	bool retain_read_attr =
		perf_state.mode == PERF_MODE_HIT &&
		perf_state.profile == PERF_PROFILE_PAPER_LIKE;
	size_t opcode_count = retain_read_attr ? 2 : 1;
	size_t i;

	for (i = 0; i < opcode_count; i++) {
		ebpf_ctrl_key_t key = { .opcode = opcodes[i] };

		if (ebpf_ctrl_delete(perf_state.bpf, &key)) {
			fprintf(stderr,
				"HANDLER_DELETE_ERROR opcode=%u errno=%d error=%s\n",
				opcodes[i], errno, strerror(errno));
			return -1;
		}
	}
	fprintf(stderr,
		"HANDLERS mode=hit common_fastpath=LOOKUP,GETATTR,GETXATTR "
		"forced_upcall=FLUSH paper_read_attr_policy=%s\n",
		retain_read_attr ? "retain" : "coherent-refresh");
	return 0;
}

static void audit_packed_state_map(int map_index, uint64_t *records,
				   uint64_t *active, uint64_t *errors)
{
	uint64_t current_key;
	uint64_t next_key;
	uint64_t state;
	const void *cursor = NULL;

	*records = 0;
	*active = 0;
	*errors = 0;
	for (;;) {
		if (ebpf_data_next(perf_state.bpf, cursor, &next_key, map_index)) {
			if (errno != ENOENT)
				(*errors)++;
			break;
		}
		current_key = next_key;
		cursor = &current_key;
		if (ebpf_data_lookup(perf_state.bpf, &current_key, &state,
				     map_index)) {
			if (errno != ENOENT)
				(*errors)++;
			continue;
		}
		(*records)++;
		if (!(state >> EXTFUSE_NATIVE_STATE_ACTIVE_BITS))
			(*errors)++;
		if (state & EXTFUSE_NATIVE_STATE_ACTIVE_MASK)
			(*active)++;
	}
}

static void audit_coherence_state(void)
{
	uint64_t daemon_records = 0;
	uint64_t daemon_active = 0;
	uint64_t daemon_errors = 0;
	uint64_t native_records = 0;
	uint64_t native_active = 0;
	uint64_t native_errors = 0;

	if (!metadata_hits_enabled())
		return;
	audit_packed_state_map(EXTFUSE_DAEMON_IO_MAP, &daemon_records,
			       &daemon_active, &daemon_errors);
	if (perf_state.passthrough_coherence_v2_requested ||
	    perf_state.wbcache_passthrough_requested)
		audit_packed_state_map(EXTFUSE_NATIVE_IO_MAP, &native_records,
				       &native_active, &native_errors);
	atomic_store_explicit(&perf_state.counters.daemon_io_state_records,
			      daemon_records, memory_order_relaxed);
	atomic_store_explicit(&perf_state.counters.daemon_io_active_residuals,
			      daemon_active, memory_order_relaxed);
	atomic_store_explicit(&perf_state.counters.daemon_io_state_audit_errors,
			      daemon_errors, memory_order_relaxed);
	atomic_store_explicit(&perf_state.counters.native_io_state_records,
			      native_records, memory_order_relaxed);
	atomic_store_explicit(&perf_state.counters.native_io_active_residuals,
			      native_active, memory_order_relaxed);
	atomic_store_explicit(&perf_state.counters.native_io_state_audit_errors,
			      native_errors, memory_order_relaxed);
	fprintf(stderr,
		"COHERENCE_STATE daemon_records=%" PRIu64
		" daemon_active_residuals=%" PRIu64
		" daemon_audit_errors=%" PRIu64
		" native_records=%" PRIu64
		" native_active_residuals=%" PRIu64
		" native_audit_errors=%" PRIu64 "\n",
		daemon_records, daemon_active, daemon_errors, native_records,
		native_active, native_errors);
}

static void print_counters(const char *phase)
{
	fprintf(stderr,
		"DAEMON_COUNTS phase=%s mode=%s transport=%s "
		"callback_counting=%u "
		"lookup=%" PRIu64
		" lookup_positive=%" PRIu64
		" lookup_enoent=%" PRIu64
		" lookup_other_errors=%" PRIu64
		" getattr=%" PRIu64
		" getxattr=%" PRIu64 " create=%" PRIu64
		" open=%" PRIu64 " release=%" PRIu64
		" read=%" PRIu64 " write=%" PRIu64
		" wbcache_daemon_read_fallbacks=%" PRIu64
		" wbcache_daemon_write_fallbacks=%" PRIu64
		" flush=%" PRIu64 " setattr=%" PRIu64
		" mkdir=%" PRIu64 " unlink=%" PRIu64
		" rename=%" PRIu64 " opendir=%" PRIu64
		" readdir=%" PRIu64 " releasedir=%" PRIu64
		" forget=%" PRIu64 " forget_multi=%" PRIu64
		" cache_entry_updates=%" PRIu64
		" cache_attr_updates=%" PRIu64
		" cache_xattr_updates=%" PRIu64
		" cache_update_errors=%" PRIu64
			" cache_entry_invalidations=%" PRIu64
			" cache_attr_invalidations=%" PRIu64
			" cache_xattr_invalidations=%" PRIu64
			" cache_invalidation_errors=%" PRIu64
			" cache_bypass_events=%" PRIu64
			" cache_bypass_errors=%" PRIu64
			" passthrough_registrations=%" PRIu64
		" passthrough_reuses=%" PRIu64
		" passthrough_opens=%" PRIu64
		" passthrough_fallback_cohorts=%" PRIu64
		" passthrough_fallback_opens=%" PRIu64
		" passthrough_closes=%" PRIu64
		" passthrough_close_errors=%" PRIu64
		" passthrough_state_errors=%" PRIu64
		" passthrough_attr_suppressions=%" PRIu64
		" passthrough_mmap_suppressions=%" PRIu64
		" passthrough_release_readonly_fast=%" PRIu64
		" passthrough_release_may_modify=%" PRIu64
		" passthrough_release_registration_refreshes=%" PRIu64
		" passthrough_release_attr_snapshots=%" PRIu64
		" passthrough_release_attr_published=%" PRIu64
		" passthrough_release_attr_unstable=%" PRIu64
		" passthrough_release_attr_suppressed=%" PRIu64
		" passthrough_release_attr_missing=%" PRIu64
		" passthrough_release_attr_disabled=%" PRIu64
		" passthrough_release_attr_retired_skips=%" PRIu64
		" passthrough_release_attr_errors=%" PRIu64
		" passthrough_tombstones=%" PRIu64
			" passthrough_tracked_records=%" PRIu64
		" passthrough_residual_records=%" PRIu64
		" daemon_io_state_records=%" PRIu64
		" daemon_io_active_residuals=%" PRIu64
		" daemon_io_state_audit_errors=%" PRIu64
		" native_io_state_records=%" PRIu64
		" native_io_active_residuals=%" PRIu64
		" native_io_state_audit_errors=%" PRIu64 "\n",
		phase, perf_state.mode_name, perf_state.transport,
		perf_state.count_callbacks,
		counter_value(&perf_state.counters.lookup),
		counter_value(&perf_state.counters.lookup_positive),
		counter_value(&perf_state.counters.lookup_enoent),
		counter_value(&perf_state.counters.lookup_other_errors),
		counter_value(&perf_state.counters.getattr),
		counter_value(&perf_state.counters.getxattr),
		counter_value(&perf_state.counters.create),
		counter_value(&perf_state.counters.open),
		counter_value(&perf_state.counters.release),
		counter_value(&perf_state.counters.read),
		counter_value(&perf_state.counters.write),
		counter_value(
			&perf_state.counters.wbcache_daemon_read_fallbacks),
		counter_value(
			&perf_state.counters.wbcache_daemon_write_fallbacks),
		counter_value(&perf_state.counters.flush),
		counter_value(&perf_state.counters.setattr),
		counter_value(&perf_state.counters.mkdir),
		counter_value(&perf_state.counters.unlink),
		counter_value(&perf_state.counters.rename),
		counter_value(&perf_state.counters.opendir),
		counter_value(&perf_state.counters.readdir),
		counter_value(&perf_state.counters.releasedir),
		counter_value(&perf_state.counters.forget),
		counter_value(&perf_state.counters.forget_multi),
		counter_value(&perf_state.counters.cache_entry_updates),
		counter_value(&perf_state.counters.cache_attr_updates),
		counter_value(&perf_state.counters.cache_xattr_updates),
		counter_value(&perf_state.counters.cache_update_errors),
		counter_value(
			&perf_state.counters.cache_entry_invalidations),
			counter_value(
				&perf_state.counters.cache_attr_invalidations),
			counter_value(
				&perf_state.counters.cache_xattr_invalidations),
			counter_value(
				&perf_state.counters.cache_invalidation_errors),
			counter_value(&perf_state.counters.cache_bypass_events),
			counter_value(&perf_state.counters.cache_bypass_errors),
			counter_value(
				&perf_state.counters.passthrough_registrations),
		counter_value(&perf_state.counters.passthrough_reuses),
		counter_value(&perf_state.counters.passthrough_opens),
		counter_value(
			&perf_state.counters.passthrough_fallback_cohorts),
		counter_value(
			&perf_state.counters.passthrough_fallback_opens),
		counter_value(&perf_state.counters.passthrough_closes),
		counter_value(
			&perf_state.counters.passthrough_close_errors),
		counter_value(
			&perf_state.counters.passthrough_state_errors),
			counter_value(
				&perf_state.counters.passthrough_attr_suppressions),
		counter_value(
			&perf_state.counters.passthrough_mmap_suppressions),
		counter_value(&perf_state.counters
				      .passthrough_release_readonly_fast),
		counter_value(&perf_state.counters
				      .passthrough_release_may_modify),
		counter_value(&perf_state.counters
				      .passthrough_release_registration_refreshes),
		counter_value(
			&perf_state.counters.passthrough_release_attr_snapshots),
		counter_value(&perf_state.counters
				      .passthrough_release_attr_published),
		counter_value(&perf_state.counters
				      .passthrough_release_attr_unstable),
		counter_value(&perf_state.counters
				      .passthrough_release_attr_suppressed),
		counter_value(&perf_state.counters
				      .passthrough_release_attr_missing),
		counter_value(&perf_state.counters
				      .passthrough_release_attr_disabled),
		counter_value(&perf_state.counters
				      .passthrough_release_attr_retired_skips),
		counter_value(
			&perf_state.counters.passthrough_release_attr_errors),
		counter_value(
			&perf_state.counters.passthrough_tombstones),
			counter_value(
			&perf_state.counters.passthrough_tracked_records),
		counter_value(
			&perf_state.counters.passthrough_residual_records),
		counter_value(&perf_state.counters.daemon_io_state_records),
		counter_value(&perf_state.counters.daemon_io_active_residuals),
		counter_value(&perf_state.counters.daemon_io_state_audit_errors),
		counter_value(&perf_state.counters.native_io_state_records),
		counter_value(&perf_state.counters.native_io_active_residuals),
		counter_value(&perf_state.counters.native_io_state_audit_errors));
	fflush(stderr);
}

static void perf_init(void *userdata, struct fuse_conn_info *conn)
{
	struct lo_data *lo = userdata;
	int extfuse_rc = 0;

	perf_state.init_rc = 0;
	fuse_apply_conn_info_opts(perf_state.conn_opts, conn);
	lo_init(userdata, conn);
	/*
	 * Original StackFS only exposed READDIR, not READDIRPLUS.  Leaving the
	 * modern passthrough_ll callback negotiated would let a directory reply
	 * instantiate child inodes and attrs without passing perf_lookup(), which
	 * also skips the proactive security.capability fill.  Keep every Fig. 9
	 * case on the same paper-compatible directory enumeration contract.
	 */
	fuse_unset_feature_flag(conn, FUSE_CAP_READDIRPLUS_AUTO);
	fuse_unset_feature_flag(conn, FUSE_CAP_READDIRPLUS);
	perf_state.passthrough_capable =
		(conn->capable_ext & FUSE_CAP_PASSTHROUGH) != 0;
	perf_state.passthrough_coherence_capable =
		(conn->capable_ext &
		 FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE) != 0;
	perf_state.passthrough_coherence_v2_capable =
		(conn->capable_ext &
		 FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE_V2) != 0;
	perf_state.passthrough_attr_refresh_capable =
		(conn->capable_ext &
		 FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH) != 0;
	perf_state.passthrough_attr_release_barrier_capable =
		(conn->capable_ext &
		 FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER) != 0;
	perf_state.coherence_epochs_capable =
		(conn->capable_ext & FUSE_CAP_EXTFUSE_COHERENCE_EPOCHS) != 0;
	perf_state.mutation_metadata_capable =
		(conn->capable_ext & FUSE_CAP_MUTATION_METADATA) != 0;
	perf_state.notify_inval_xattr_capable =
		(conn->capable_ext & FUSE_CAP_NOTIFY_INVAL_XATTR) != 0;
	perf_state.wbcache_passthrough_capable =
		(conn->capable_ext &
		 FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH) != 0;
	perf_state.uring_bufpool_capable =
		(conn->capable_ext & FUSE_CAP_IO_URING_BUFPOOL) != 0;
	/*
	 * C2 is MDOpt transported over the standard libfuse io_uring queue.  The
	 * experimental per-request fixed-buffer path remains available as a generic
	 * opt-in API, but it is not part of the paper configuration.
	 */
	perf_state.uring_zero_copy_required = false;
	if (wbcache_passthrough_enabled()) {
		/* C3/C4 retain the upper FUSE cache; native passthrough stays off. */
		lo->writeback = 1;
		if (!fuse_set_feature_flag(conn, FUSE_CAP_WRITEBACK_CACHE)) {
			perf_state.init_rc = -EOPNOTSUPP;
			conn->want_ext |= FUSE_CAP_WRITEBACK_CACHE;
		}
		fuse_unset_feature_flag(conn, FUSE_CAP_PASSTHROUGH);
		conn->max_backing_stack_depth = FUSE_BACKING_STACKED_UNDER;
	}
	if (!strcmp(perf_state.transport, "uring"))
		perf_state.single_issuer = fuse_set_conn_flag(
			conn, FUSE_CONN_FLAG_SINGLE_ISSUER);
	fuse_unset_feature_flag(conn, FUSE_CAP_IO_URING_BUFPOOL);
	perf_state.uring_bufpool_requested = false;
	perf_state.capable =
		(conn->capable_ext & FUSE_CAP_EXTFUSE) != 0;
	if (perf_state.mode != PERF_MODE_OFF) {
		extfuse_rc = ebpf_enable_extfuse(perf_state.bpf, conn);
		perf_state.requested = extfuse_rc == 0;
		if (extfuse_rc) {
			conn->want_ext |= FUSE_CAP_EXTFUSE;
			if (!perf_state.init_rc)
				perf_state.init_rc = extfuse_rc;
		}
	}
	if (perf_state.requested && strict_wbcache_coherence_enabled()) {
		if (perf_state.coherence_epochs_capable)
			perf_state.coherence_epochs_requested =
				fuse_set_feature_flag(
					conn,
					FUSE_CAP_EXTFUSE_COHERENCE_EPOCHS);
		if (!perf_state.coherence_epochs_requested) {
			if (!perf_state.init_rc)
				perf_state.init_rc = -EOPNOTSUPP;
			/* The strict gate must never run without the kernel guard. */
			conn->want_ext |= FUSE_CAP_EXTFUSE_COHERENCE_EPOCHS;
		} else {
			if (perf_state.mutation_metadata_capable)
				perf_state.mutation_metadata_requested =
					fuse_set_feature_flag(
						conn, FUSE_CAP_MUTATION_METADATA);
			if (perf_state.notify_inval_xattr_capable)
				perf_state.notify_inval_xattr_requested =
					fuse_set_feature_flag(
						conn,
						FUSE_CAP_NOTIFY_INVAL_XATTR);
		}
	}
	if (wbcache_passthrough_enabled()) {
		/* Do not mix this cached route with the native passthrough ABI. */
		fuse_unset_feature_flag(conn, FUSE_CAP_PASSTHROUGH);
		fuse_unset_feature_flag(
			conn, FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE);
		fuse_unset_feature_flag(
			conn, FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE_V2);
		fuse_unset_feature_flag(
			conn,
			FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER);
		perf_state.passthrough_requested = false;
		perf_state.passthrough_coherence_requested = false;
		perf_state.passthrough_coherence_v2_requested = false;
		perf_state.passthrough_attr_release_barrier_requested = false;

		if (perf_state.requested &&
		    (conn->want_ext & FUSE_CAP_WRITEBACK_CACHE))
			perf_state.wbcache_passthrough_requested =
				fuse_set_feature_flag(
					conn,
					FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH);
		if (!perf_state.wbcache_passthrough_requested) {
			if (!perf_state.init_rc)
				perf_state.init_rc = -EOPNOTSUPP;
			/* Fail INIT instead of measuring a daemon-I/O fallback. */
			conn->want_ext |=
				FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH;
		}
		if (perf_state.wbcache_passthrough_requested &&
		    perf_state.passthrough_attr_refresh_capable)
			perf_state.passthrough_attr_refresh_requested =
				fuse_set_feature_flag(
					conn,
					FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH);
		if (wbcache_passthrough_enabled() &&
		    !perf_state.passthrough_attr_refresh_requested) {
			if (!perf_state.init_rc)
				perf_state.init_rc = -EOPNOTSUPP;
			/* All WBCache passthrough profiles require lower attr refill. */
			conn->want_ext |=
				FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH;
		}
	}
	if (coherence_epochs_enabled()) {
		/*
		 * WBCache forwarding uses kernel epochs to bracket lower I/O.  Metadata
		 * replies remain in the generation-validated maps used by MDOpt so the
		 * same LOOKUP/GETATTR/GETXATTR rows are reusable across requests.
		 * Attribute refresh is valid for this route, but the RELEASE barrier
		 * remains exclusive to native passthrough coherence V2.
		 */
		fuse_unset_feature_flag(
			conn,
			FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER);
		perf_state.passthrough_attr_release_barrier_requested = false;
	}
	if ((perf_state.wbcache_passthrough_requested ||
	     perf_state.passthrough_attr_release_barrier_requested ||
	     coherence_epochs_enabled()) &&
	    perf_state.requested && configure_bpf_policy()) {
		if (!perf_state.init_rc)
			perf_state.init_rc = -EIO;
		request_allopt_session_exit();
	}
	fprintf(stderr,
		"INIT mode=%s transport=%s coherence_mode=%s capable=%u requested=%u "
		PERF_COHERENCE_EPOCHS_INIT_FMT
		PERF_MUTATION_METADATA_INIT_FMT
		PERF_NOTIFY_INVAL_XATTR_INIT_FMT
		"passthrough_capable=%u passthrough_requested=%u "
		PERF_WBCACHE_PASSTHROUGH_INIT_FMT
		"passthrough_coherence_capable=%u "
		"passthrough_coherence_requested=%u "
		"passthrough_coherence_v2_capable=%u "
		"passthrough_coherence_v2_requested=%u "
		"passthrough_attr_refresh_capable=%u "
		"passthrough_attr_refresh_requested=%u "
		PERF_ATTR_RELEASE_BARRIER_INIT_FMT
		"paper_read_atime_cache=%s "
		"paper_capability_enodata=%s "
		"wbcache_policy_enabled=%u "
		"readdirplus_policy=stackfs-compatible-disabled "
		"readdirplus_requested=%u readdirplus_auto_requested=%u "
		PERF_INIT_CACHE_FMT
		PERF_INIT_BACKING_FMT
		PERF_INIT_BUFPOOL_FMT
		PERF_INIT_ZERO_COPY_FMT
		PERF_INIT_STD_CAPS_FMT
		PERF_INIT_EXT_CAPS_FMT
		PERF_INIT_MAX_WRITE_FMT,
		perf_state.mode_name, perf_state.transport,
		coherence_mode_name(),
		perf_state.capable, perf_state.requested,
		perf_state.coherence_epochs_capable,
		perf_state.coherence_epochs_requested,
		perf_state.mutation_metadata_capable,
		mutation_metadata_enabled(),
		perf_state.notify_inval_xattr_capable,
		notify_inval_xattr_enabled(),
		perf_state.passthrough_capable,
		perf_state.passthrough_requested,
		perf_state.wbcache_passthrough_capable,
		perf_state.wbcache_passthrough_requested,
		perf_state.passthrough_coherence_capable,
		perf_state.passthrough_coherence_requested,
		perf_state.passthrough_coherence_v2_capable,
		perf_state.passthrough_coherence_v2_requested,
		perf_state.passthrough_attr_refresh_capable,
		perf_state.passthrough_attr_refresh_requested,
		"passthrough_attr_release_barrier_capable",
		perf_state.passthrough_attr_release_barrier_capable,
		"passthrough_attr_release_barrier_requested",
		perf_state.passthrough_attr_release_barrier_requested,
		"passthrough_attr_release_barrier_policy",
		attr_release_barrier_enabled(),
		(perf_state.bpf_policy_flags &
		 EXTFUSE_POLICY_PAPER_READ_ATIME_CACHE) ?
			"retained" : "coherent",
		(perf_state.bpf_policy_flags &
		 EXTFUSE_POLICY_PAPER_CAPABILITY_ENODATA) ?
			"enabled" : "disabled",
		(perf_state.bpf_policy_flags &
		 EXTFUSE_POLICY_WBCACHE_PASSTHROUGH) != 0,
		(conn->want_ext & FUSE_CAP_READDIRPLUS) != 0,
		(conn->want_ext & FUSE_CAP_READDIRPLUS_AUTO) != 0,
		lo->timeout, lo->cache,
		(conn->want_ext & FUSE_CAP_WRITEBACK_CACHE) != 0,
		conn->max_backing_stack_depth,
		perf_state.single_issuer,
		perf_state.uring_bufpool_capable,
		perf_state.uring_bufpool_requested,
		perf_state.uring_zero_copy_required,
		conn->extfuse_prog_fd, perf_state.init_rc,
		conn->capable, conn->want, conn->capable_ext,
		conn->want_ext, conn->max_write);
	fflush(stderr);
}

static void perf_destroy(void *userdata)
{
	if (wbcache_passthrough_enabled())
		cleanup_wbcache_passthrough_state();
	audit_coherence_state();
	print_counters("destroy");
	cleanup_inode_generation_state();
	lo_destroy(userdata);
}

static bool snapshot_inode_attr(fuse_req_t req, fuse_ino_t ino,
				struct stat *st,
				struct perf_cache_snapshot *snapshot);
static void prefetch_capability(fuse_req_t req, fuse_ino_t ino);

__attribute__((noinline, used))
void perf_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param entry;
	struct lo_data *lo = lo_data(req);
	struct stat st;
	struct perf_cache_snapshot snapshot;
	bool have_snapshot;
	int error;

	callback_increment(&perf_state.counters.lookup);
	if (!metadata_hits_enabled()) {
		error = lo_do_lookup(req, parent, name, &entry);
	} else {
		/*
		 * lo_do_lookup() protects the inode identity index with lo->mutex.
		 * successful entry가 map에 들어갈 때까지 namespace read-lock을 잡아
		 * mutation의 invalidate -> write -> invalidate 구간과 순서를 보장한다.
		 * attr snapshot만 child generation으로 검증하며, 관계없는
		 * attr mutation 때문에
		 * positive entry 자체를 버리지는 않는다.
		 */
		pthread_rwlock_rdlock(&perf_state.namespace_lock);
		error = lo_do_lookup(req, parent, name, &entry);
	}
	if (error) {
		if (error == ENOENT) {
			struct fuse_entry_param negative = {
				.entry_timeout = lo->timeout,
			};

			callback_increment(&perf_state.counters.lookup_enoent);
			if (metadata_hits_enabled()) {
				cache_negative_entry(parent, name, lo->timeout);
				pthread_rwlock_unlock(&perf_state.namespace_lock);
			}
			fuse_reply_entry(req, &negative);
			return;
		}
		if (metadata_hits_enabled())
			pthread_rwlock_unlock(&perf_state.namespace_lock);
		callback_increment(&perf_state.counters.lookup_other_errors);
		fuse_reply_err(req, error);
		return;
	}
	callback_increment(&perf_state.counters.lookup_positive);
	if (metadata_hits_enabled()) {
		/*
		 * The child nodeid is not known before lo_do_lookup() performs its
		 * fstat. Take a second, generation-bracketed snapshot so a mutation
		 * which overlapped that first fstat cannot be published as current.
		 */
		have_snapshot = snapshot_inode_attr(req, entry.ino, &st, &snapshot);
		if (have_snapshot)
			entry.attr = st;
		/* Publish the xattr before entry_map can expose this nodeid. */
		prefetch_capability(req, entry.ino);
		if (have_snapshot)
			cache_entry(parent, name, &entry, &snapshot);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
	}
	fuse_reply_entry(req, &entry);
}

__attribute__((noinline, used))
void perf_getattr(fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
	struct lo_data *lo;
	struct stat st;
	struct perf_metadata_upcall upcall;
	double reply_timeout;
	struct perf_cache_snapshot snapshot;
	int result;
	int saved_error;
	int fd;

	fd = fi ? (int)fi->fh : lo_fd(req, ino);
	if (perf_state.trace_metadata_upcalls)
		perf_metadata_upcall_begin(&upcall, req, ino, FUSE_GETATTR, fd,
					   fi, NULL, -1);
	callback_increment(&perf_state.counters.getattr);
	if (!metadata_hits_enabled()) {
		lo_getattr(req, ino, fi);
		return;
	}
	lo = lo_data(req);
	cache_snapshot_begin(ino, &snapshot);
	result = fstatat(fd, "", &st, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (result < 0) {
		saved_error = errno;
		if (perf_state.trace_metadata_upcalls)
			perf_metadata_upcall_end(&upcall, result, saved_error);
		fuse_reply_err(req, saved_error);
		return;
	}
	cache_attr(ino, &st, lo->timeout, &snapshot, false,
		   &reply_timeout);
	/* Root and getattr-only inodes also need the paper's proactive xattr fill. */
	prefetch_capability(req, ino);
	if (perf_state.trace_metadata_upcalls)
		perf_metadata_upcall_end(&upcall, result, 0);
	fuse_reply_attr(req, &st, reply_timeout);
}

#ifdef HAVE_STATX
__attribute__((noinline, used))
void perf_statx(fuse_req_t req, fuse_ino_t ino, int flags, int mask,
		struct fuse_file_info *fi)
{
	lo_statx(req, ino, flags, mask, fi);
}
#endif

/* The caller holds xattr_lock_for_inode(ino). */
static void prefetch_xattr_serialized(fuse_req_t req, fuse_ino_t ino,
				      const char *name)
{
	uint8_t value[PERF_XATTR_VALUE_MAX];
	struct perf_cache_snapshot snapshot;
	ssize_t required;
	ssize_t result;
	int saved_error;

	cache_snapshot_begin(ino, &snapshot);
	required = lo_do_getxattr(req, ino, name, NULL, 0);
	if (required < 0) {
		saved_error = errno;
		if (saved_error == ENODATA)
			cache_xattr_reply_serialized(ino, name, NULL, 0,
						       ENODATA, &snapshot);
		else
			invalidate_xattr_serialized(ino, name, false);
		errno = saved_error;
		return;
	}
	if ((size_t)required > sizeof(value)) {
		/* Oversized values are deliberately serviced by the daemon. */
		invalidate_xattr_serialized(ino, name, false);
		return;
	}
	result = lo_do_getxattr(req, ino, name, value, sizeof(value));
	if (result == required)
		cache_xattr_reply_serialized(ino, name, value,
					     (size_t)result, 0, &snapshot);
	else {
		saved_error = result < 0 ? errno : 0;
		/* Never retain a value from a torn size/value observation. */
		invalidate_xattr_serialized(ino, name, false);
		if (result < 0)
			errno = saved_error;
	}
}

static void prefetch_xattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	pthread_mutex_t *xattr_lock = xattr_lock_for_inode(ino);

	pthread_mutex_lock(xattr_lock);
	prefetch_xattr_serialized(req, ino, name);
	pthread_mutex_unlock(xattr_lock);
}

static void prefetch_capability(fuse_req_t req, fuse_ino_t ino)
{
	prefetch_xattr(req, ino, PERF_CAPABILITY_XATTR);
}

__attribute__((noinline, used))
void perf_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			   size_t size)
{
	uint8_t cache_value[PERF_XATTR_VALUE_MAX];
	char *value = NULL;
	struct perf_metadata_upcall upcall;
	pthread_mutex_t *xattr_lock;
	struct perf_cache_snapshot snapshot;
	ssize_t result;
	ssize_t cached_result;
	int saved_error;

	if (perf_state.trace_metadata_upcalls)
		perf_metadata_upcall_begin(&upcall, req, ino, FUSE_GETXATTR,
					   lo_fd(req, ino),
					   NULL, name, (intmax_t)size);
	callback_increment(&perf_state.counters.getxattr);
	if (!metadata_hits_enabled()) {
		lo_getxattr(req, ino, name, size);
		return;
	}
	if (size) {
		value = malloc(size);
		if (!value) {
			if (perf_state.trace_metadata_upcalls)
				perf_metadata_upcall_end(&upcall, -1, ENOMEM);
			fuse_reply_err(req, ENOMEM);
			return;
		}
	}
	xattr_lock = xattr_lock_for_inode(ino);
	pthread_mutex_lock(xattr_lock);
	cache_snapshot_begin(ino, &snapshot);
	if (size) {
		result = lo_do_getxattr(req, ino, name, value, size);
	} else {
		result = lo_do_getxattr(req, ino, name, NULL, 0);
	}
	if (result < 0) {
		saved_error = errno;
		if (saved_error == ENODATA)
			cache_xattr_reply_serialized(ino, name, NULL, 0,
						       ENODATA, &snapshot);
		else
			invalidate_xattr_serialized(ino, name, false);
		pthread_mutex_unlock(xattr_lock);
		free(value);
		if (perf_state.trace_metadata_upcalls)
			perf_metadata_upcall_end(&upcall, result, saved_error);
		fuse_reply_err(req, saved_error);
		return;
	}

	if (size) {
		if ((size_t)result <= PERF_XATTR_VALUE_MAX)
			cache_xattr_reply_serialized(ino, name, value,
						       (size_t)result, 0,
						       &snapshot);
		else
			invalidate_xattr_serialized(ino, name, false);
		pthread_mutex_unlock(xattr_lock);
		if (perf_state.trace_metadata_upcalls)
			perf_metadata_upcall_end(&upcall, result, 0);
		if (result)
			fuse_reply_buf(req, value, (size_t)result);
		else
			fuse_reply_err(req, 0);
		free(value);
		return;
	}

	if ((size_t)result <= sizeof(cache_value)) {
		cached_result = lo_do_getxattr(req, ino, name, cache_value,
					       sizeof(cache_value));
		if (cached_result == result)
			cache_xattr_reply_serialized(ino, name, cache_value,
						       (size_t)cached_result,
						       0, &snapshot);
		else
			invalidate_xattr_serialized(ino, name, false);
	} else {
		invalidate_xattr_serialized(ino, name, false);
	}
	pthread_mutex_unlock(xattr_lock);
	if (perf_state.trace_metadata_upcalls)
		perf_metadata_upcall_end(&upcall, result, 0);
	fuse_reply_xattr(req, (size_t)result);
}

/*
 * Capture attributes through passthrough_ll's session-pinned O_PATH fd. The
 * Exact userspace and native-I/O generations are sampled before fstat so
 * cache_attr() can reject a snapshot that overlapped a mutation of this inode
 * without being disturbed by mutations of unrelated inodes.
 */
static bool snapshot_pinned_inode_attr(
	fuse_ino_t ino, int fd, dev_t dev, ino_t lower_ino, struct stat *st,
	struct perf_cache_snapshot *snapshot)
{
	cache_snapshot_begin(ino, snapshot);
	/* passthrough_ll keeps only a pinned fd for the synthetic root node. */
	if (ino == FUSE_ROOT_ID)
		return !fstatat(fd, "", st,
				AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	return !extfuse_snapshot_pinned_inode(fd, dev, lower_ino, st);
}

static bool snapshot_inode_attr(fuse_req_t req, fuse_ino_t ino,
				struct stat *st,
				struct perf_cache_snapshot *snapshot)
{
	struct lo_data *lo = lo_data(req);
	struct lo_inode *inode = lo_inode(req, ino);
	dev_t dev = 0;
	ino_t lower_ino = 0;
	bool indexed = true;
	int fd;

	/* unlink/rename retirement changes these fields under lo->mutex. */
	pthread_mutex_lock(&lo->mutex);
	fd = inode->fd;
	if (ino != FUSE_ROOT_ID) {
		indexed = inode->indexed;
		dev = inode->dev;
		lower_ino = inode->ino;
	}
	pthread_mutex_unlock(&lo->mutex);
	if (!indexed) {
		errno = ESTALE;
		return false;
	}

	return snapshot_pinned_inode_attr(ino, fd, dev, lower_ino, st, snapshot);
}

static bool inode_identity_retired(fuse_req_t req, fuse_ino_t ino)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	bool retired;

	if (ino == FUSE_ROOT_ID)
		return false;
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	pthread_mutex_lock(&lo->mutex);
	retired = !inode->indexed;
	pthread_mutex_unlock(&lo->mutex);
	return retired;
}

static void cache_pinned_inode_attr(struct lo_data *lo, fuse_ino_t ino,
				    int fd, dev_t dev, ino_t lower_ino)
{
	struct perf_cache_snapshot snapshot;
	struct stat st;
	double reply_timeout;

	if (snapshot_pinned_inode_attr(ino, fd, dev, lower_ino, &st, &snapshot))
		cache_attr(ino, &st, lo->timeout, &snapshot, false,
			   &reply_timeout);
}

static double cache_inode_attr_snapshot(fuse_req_t req, fuse_ino_t ino,
					struct stat *reply_attr)
{
	struct lo_data *lo = lo_data(req);
	struct stat st;
	double reply_timeout = lo->timeout;
	struct perf_cache_snapshot snapshot;

	if (snapshot_inode_attr(req, ino, &st, &snapshot)) {
		cache_attr(ino, &st, lo->timeout, &snapshot, false,
			   &reply_timeout);
		if (reply_attr)
			*reply_attr = st;
	}
	if (coherence_epochs_enabled())
		reply_timeout = epoch_attr_timeout(ino, reply_timeout);
	return reply_timeout;
}

static double cache_inode_attr_before_reply(fuse_req_t req, fuse_ino_t ino,
					     struct stat *reply_attr)
{
	double reply_timeout;

	reply_timeout = cache_inode_attr_snapshot(req, ino, reply_attr);
	prefetch_capability(req, ino);
	return reply_timeout;
}

static int pin_child(int parent_fd, const char *name, struct stat *identity);
static fuse_ino_t find_identity_nodeid_locked(struct lo_data *lo,
					       int victim_fd,
					       const struct stat *identity);

static void perf_tmpfile(fuse_req_t req, fuse_ino_t parent, mode_t mode,
			 struct fuse_file_info *fi)
{
	struct lo_data *lo = lo_data(req);
	struct fuse_entry_param entry;
	struct perf_backing *candidate = NULL;
	struct perf_tombstone *tombstone_candidate = NULL;
	struct perf_cache_mutation mutation = {};
	int fd;
	int error;

	callback_increment(&perf_state.counters.create);
	if (!metadata_hits_enabled()) {
		lo_tmpfile(req, parent, mode, fi);
		return;
	}
	if (wbcache_passthrough_enabled()) {
		candidate = calloc(1, sizeof(*candidate));
		if (!paper_wbcache_passthrough_enabled())
			tombstone_candidate =
				calloc(1, sizeof(*tombstone_candidate));
		if (!candidate ||
		    (!paper_wbcache_passthrough_enabled() &&
		     !tombstone_candidate)) {
			free(candidate);
			free(tombstone_candidate);
			fuse_reply_err(req, ENOMEM);
			return;
		}
	}
	cache_mutation_add(&mutation, parent);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		free(candidate);
		free(tombstone_candidate);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(parent);
	pthread_rwlock_wrlock(&perf_state.namespace_lock);
	fd = openat(lo_fd(req, parent), ".",
		    (fi->flags | O_TMPFILE) & ~O_NOFOLLOW, mode);
	if (fd < 0) {
		int saved_error = errno;

		pthread_rwlock_unlock(&perf_state.namespace_lock);
		invalidate_attr(parent);
		cache_mutation_end(&mutation);
		cache_inode_attr_snapshot(req, parent, NULL);
		free(candidate);
		free(tombstone_candidate);
		fuse_reply_err(req, saved_error);
		return;
	}
	error = fill_entry_param_new_inode(req, parent, fd, &entry);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
	invalidate_attr(parent);
	cache_mutation_end(&mutation);
	cache_inode_attr_snapshot(req, parent, NULL);
	if (error) {
		free(candidate);
		free(tombstone_candidate);
		close(fd);
		fuse_reply_err(req, error);
		return;
	}
	fi->fh = fd;
	if (lo->direct_io || lo->cache == CACHE_NEVER)
		fi->direct_io = 1;
	else if (lo->cache == CACHE_ALWAYS)
		fi->keep_cache = 1;
	fi->parallel_direct_writes = 1;
	if (wbcache_passthrough_enabled())
		attach_wbcache_passthrough(req, entry.ino, fd, fi, candidate,
					   tombstone_candidate);
	entry.attr_timeout = cache_inode_attr_before_reply(
		req, entry.ino, &entry.attr);
	fuse_reply_create(req, &entry, fi);
}

__attribute__((noinline, used))
void perf_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		 mode_t mode, struct fuse_file_info *fi)
{
	struct lo_data *lo;
	struct fuse_entry_param entry;
	struct perf_backing *candidate = NULL;
	struct perf_tombstone *tombstone_candidate = NULL;
	struct perf_cache_mutation mutation = {};
	struct stat st;
	struct stat existing_identity = {};
	struct perf_cache_snapshot snapshot;
	fuse_ino_t existing_ino = 0;
	bool have_snapshot;
	int existing_fd = -1;
	int fd;
	int error;

	callback_increment(&perf_state.counters.create);
	if (!metadata_hits_enabled()) {
		lo_create(req, parent, name, mode, fi);
		return;
	}
	lo = lo_data(req);
	if (wbcache_passthrough_enabled()) {
		candidate = calloc(1, sizeof(*candidate));
		if (!paper_wbcache_passthrough_enabled())
			tombstone_candidate =
				calloc(1, sizeof(*tombstone_candidate));
		if (!candidate ||
		    (!paper_wbcache_passthrough_enabled() &&
		     !tombstone_candidate)) {
			free(candidate);
			free(tombstone_candidate);
			fuse_reply_err(req, ENOMEM);
			return;
		}
	}
	pthread_rwlock_wrlock(&perf_state.namespace_lock);
	existing_fd = pin_child(lo_fd(req, parent), name, &existing_identity);
	if (existing_fd >= 0) {
		pthread_mutex_lock(&lo->mutex);
		existing_ino = find_identity_nodeid_locked(
			lo, existing_fd, &existing_identity);
		pthread_mutex_unlock(&lo->mutex);
	} else if (errno != ENOENT) {
		int saved_error = errno;

		invalidate_entry(parent, name);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		free(candidate);
		free(tombstone_candidate);
		fuse_reply_err(req, saved_error);
		return;
	}
	cache_mutation_add(&mutation, parent);
	cache_mutation_add(&mutation, existing_ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		if (existing_fd >= 0)
			close(existing_fd);
		free(candidate);
		free(tombstone_candidate);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_entry(parent, name);
	fd = openat(lo_fd(req, parent), name,
		    (fi->flags | O_CREAT) & ~O_NOFOLLOW, mode);
	if (fd == -1) {
		int saved_error = errno;

		pthread_rwlock_unlock(&perf_state.namespace_lock);
		if (existing_fd >= 0)
			close(existing_fd);
		invalidate_entry(parent, name);
		cache_mutation_end(&mutation);
		cache_inode_attr_snapshot(req, parent, NULL);
		free(candidate);
		free(tombstone_candidate);
		fuse_reply_err(req, saved_error);
		return;
	}
	fi->fh = fd;
	if (lo->direct_io || lo->cache == CACHE_NEVER)
		fi->direct_io = 1;
	else if (lo->cache == CACHE_ALWAYS)
		fi->keep_cache = 1;
	fi->parallel_direct_writes = 1;

	error = lo_do_lookup(req, parent, name, &entry);
	if (error) {
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		if (existing_fd >= 0)
			close(existing_fd);
		invalidate_entry(parent, name);
		close(fd);
		cache_mutation_end(&mutation);
		cache_inode_attr_snapshot(req, parent, NULL);
		free(candidate);
		free(tombstone_candidate);
		fuse_reply_err(req, error);
		return;
	}
	invalidate_entry(parent, name);
	invalidate_attr(entry.ino);
	invalidate_xattr(entry.ino, PERF_CAPABILITY_XATTR, true);
	if (wbcache_passthrough_enabled())
		attach_wbcache_passthrough(req, entry.ino, fd, fi, candidate,
					   tombstone_candidate);
	cache_mutation_end(&mutation);
	if (existing_fd >= 0)
		close(existing_fd);
	cache_inode_attr_snapshot(req, parent, NULL);
	have_snapshot = snapshot_inode_attr(req, entry.ino, &st, &snapshot);
	if (have_snapshot)
		entry.attr = st;
	prefetch_capability(req, entry.ino);
	if (have_snapshot)
		cache_entry(parent, name, &entry, &snapshot);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
	/* CREATE의 정상 lo->timeout을 보존해 C0와 같은 VFS 캐시를 사용한다. */
	if (coherence_epochs_enabled())
		entry.attr_timeout = epoch_attr_timeout(entry.ino,
						     entry.attr_timeout);
	fuse_reply_create(req, &entry, fi);
}

static void perf_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
			   off_t offset, off_t length,
			   struct fuse_file_info *fi)
{
	struct perf_cache_mutation mutation = {};
	pthread_mutex_t *xattr_lock;
	int error;

	if (!metadata_hits_enabled()) {
		lo_fallocate(req, ino, mode, offset, length, fi);
		return;
	}
	xattr_lock = xattr_lock_for_inode(ino);
	pthread_mutex_lock(xattr_lock);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
	error = -do_fallocate(fi->fh, mode, offset, length);
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
	cache_mutation_end(&mutation);
	pthread_mutex_unlock(xattr_lock);
	fuse_reply_err(req, error);
}

static void perf_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			  const char *value, size_t size, int flags)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct perf_cache_mutation mutation = {};
	char procname[64];
	pthread_mutex_t *xattr_lock;
	int length;
	int result;
	int saved_error;

	if (!strcmp(name, PERF_CAPABILITY_XATTR))
		revoke_paper_capability_enodata("setxattr");
	if (!metadata_hits_enabled()) {
		lo_setxattr(req, ino, name, value, size, flags);
		return;
	}
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	if (!lo->xattr) {
		fuse_reply_err(req, ENOSYS);
		return;
	}
	length = snprintf(procname, sizeof(procname), "/proc/self/fd/%i",
			  inode->fd);
	if (length < 0 || (size_t)length >= sizeof(procname)) {
		fuse_reply_err(req, ENAMETOOLONG);
		return;
	}
	xattr_lock = xattr_lock_for_inode(ino);
	pthread_mutex_lock(xattr_lock);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, name, false);
	result = setxattr(procname, name, value, size, flags);
	saved_error = result == -1 ? errno : 0;
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, name, false);
	cache_mutation_end(&mutation);
	if (!saved_error)
		prefetch_xattr_serialized(req, ino, name);
	pthread_mutex_unlock(xattr_lock);
	fuse_reply_err(req, saved_error);
}

static void perf_removexattr(fuse_req_t req, fuse_ino_t ino,
			     const char *name)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct perf_cache_mutation mutation = {};
	char procname[64];
	pthread_mutex_t *xattr_lock;
	int length;
	int result;
	int saved_error;

	if (!strcmp(name, PERF_CAPABILITY_XATTR))
		revoke_paper_capability_enodata("removexattr");
	if (!metadata_hits_enabled()) {
		lo_removexattr(req, ino, name);
		return;
	}
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	if (!lo->xattr) {
		fuse_reply_err(req, ENOSYS);
		return;
	}
	length = snprintf(procname, sizeof(procname), "/proc/self/fd/%i",
			  inode->fd);
	if (length < 0 || (size_t)length >= sizeof(procname)) {
		fuse_reply_err(req, ENAMETOOLONG);
		return;
	}
	xattr_lock = xattr_lock_for_inode(ino);
	pthread_mutex_lock(xattr_lock);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, name, false);
	result = removexattr(procname, name);
	saved_error = result == -1 ? errno : 0;
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, name, false);
	cache_mutation_end(&mutation);
	if (!saved_error)
		prefetch_xattr_serialized(req, ino, name);
	pthread_mutex_unlock(xattr_lock);
	fuse_reply_err(req, saved_error);
}

#ifdef HAVE_COPY_FILE_RANGE
static void perf_copy_file_range(fuse_req_t req, fuse_ino_t ino_in,
				 off_t offset_in,
				 struct fuse_file_info *fi_in,
				 fuse_ino_t ino_out, off_t offset_out,
				 struct fuse_file_info *fi_out, size_t length,
				 int flags)
{
	struct lo_data *lo;
	struct perf_cache_mutation mutation = {};
	struct perf_cache_snapshot snapshot_in;
	struct perf_cache_snapshot snapshot_out;
	struct fuse_mutation_attr attrs[2];
	struct stat attr_in;
	struct stat attr_out;
	pthread_mutex_t *xattr_lock;
	double attr_timeout;
	size_t attr_count;
	ssize_t result;
	int saved_error;

	if (!metadata_hits_enabled()) {
		lo_copy_file_range(req, ino_in, offset_in, fi_in, ino_out,
				   offset_out, fi_out, length, flags);
		return;
	}
	lo = lo_data(req);
	xattr_lock = xattr_lock_for_inode(ino_out);
	pthread_mutex_lock(xattr_lock);
	cache_mutation_add(&mutation, ino_in);
	cache_mutation_add(&mutation, ino_out);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino_in);
	if (ino_out != ino_in) {
		invalidate_attr(ino_out);
		invalidate_xattr_serialized(ino_out, PERF_CAPABILITY_XATTR,
					    true);
	} else {
		invalidate_xattr_serialized(ino_in, PERF_CAPABILITY_XATTR,
					    true);
	}
	result = copy_file_range(fi_in->fh, &offset_in, fi_out->fh,
				 &offset_out, length, flags);
	saved_error = result < 0 ? errno : 0;
	invalidate_attr(ino_in);
	if (ino_out != ino_in) {
		invalidate_attr(ino_out);
		invalidate_xattr_serialized(ino_out, PERF_CAPABILITY_XATTR,
					    true);
	} else {
		invalidate_xattr_serialized(ino_in, PERF_CAPABILITY_XATTR,
					    true);
	}
	cache_mutation_end(&mutation);
	pthread_mutex_unlock(xattr_lock);
	if (result < 0) {
		fuse_reply_err(req, saved_error);
	} else {
		attr_count = 0;
		if (snapshot_inode_attr(req, ino_in, &attr_in, &snapshot_in)) {
			cache_attr(ino_in, &attr_in, lo->timeout, &snapshot_in,
				   false, &attr_timeout);
			attrs[attr_count++] = (struct fuse_mutation_attr) {
				.ino = ino_in,
				.attr = &attr_in,
				.attr_timeout = epoch_attr_timeout(
					ino_in, attr_timeout),
				.flags = FUSE_MUTATION_NODE_ATTR_VALID,
			};
		}
		if (ino_out != ino_in &&
		    snapshot_inode_attr(req, ino_out, &attr_out, &snapshot_out)) {
			cache_attr(ino_out, &attr_out, lo->timeout, &snapshot_out,
				   false, &attr_timeout);
			attrs[attr_count++] = (struct fuse_mutation_attr) {
				.ino = ino_out,
				.attr = &attr_out,
				.attr_timeout = epoch_attr_timeout(
					ino_out, attr_timeout),
				.flags = FUSE_MUTATION_NODE_ATTR_VALID,
			};
		}
		if (mutation_metadata_enabled() && attr_count)
			fuse_reply_copy_file_range_attrs(
				req, (size_t)result, attrs, attr_count);
		else
			fuse_reply_write(req, (size_t)result);
	}
}
#endif

__attribute__((noinline, used))
void perf_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct perf_backing *candidate = NULL;
	struct perf_tombstone *tombstone_candidate = NULL;
	struct perf_cache_mutation mutation = {};
	pthread_mutex_t *xattr_lock = NULL;
	bool mutating;
	int error;

	callback_increment(&perf_state.counters.open);
	if (!metadata_hits_enabled()) {
		lo_open(req, ino, fi);
		return;
	}

	if (wbcache_passthrough_enabled()) {
		candidate = calloc(1, sizeof(*candidate));
		if (!paper_wbcache_passthrough_enabled())
			tombstone_candidate =
				calloc(1, sizeof(*tombstone_candidate));
		if (!candidate ||
		    (!paper_wbcache_passthrough_enabled() &&
		     !tombstone_candidate)) {
			free(candidate);
			free(tombstone_candidate);
			fuse_reply_err(req, ENOMEM);
			return;
		}
	}

	mutating = fi->flags & O_TRUNC;
	if (mutating) {
		xattr_lock = xattr_lock_for_inode(ino);
		pthread_mutex_lock(xattr_lock);
		cache_mutation_add(&mutation, ino);
		if (!cache_mutation_begin(&mutation)) {
			cache_mutation_end(&mutation);
			pthread_mutex_unlock(xattr_lock);
			free(candidate);
			free(tombstone_candidate);
			fuse_reply_err(req, EIO);
			return;
		}
		invalidate_attr(ino);
		invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR,
					    true);
	}
	error = lo_do_open(req, ino, fi);
	if (error) {
		if (mutating) {
			invalidate_attr(ino);
			invalidate_xattr_serialized(ino,
						    PERF_CAPABILITY_XATTR, true);
			cache_mutation_end(&mutation);
			pthread_mutex_unlock(xattr_lock);
		}
		free(candidate);
		free(tombstone_candidate);
		fuse_reply_err(req, error);
		return;
	}
	if (mutating) {
		invalidate_attr(ino);
		invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR,
					    true);
		cache_mutation_end(&mutation);
		pthread_mutex_unlock(xattr_lock);
	}

	if (wbcache_passthrough_enabled())
		attach_wbcache_passthrough(req, ino, (int)fi->fh, fi, candidate,
					   tombstone_candidate);
	cache_inode_attr_before_reply(req, ino, NULL);
	fuse_reply_open(req, fi);
}

__attribute__((noinline, used))
void perf_release(fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
	struct lo_data *lo;
	struct perf_cache_mutation mutation = {};
	struct stat st;
	double ignored_reply_timeout;
	struct perf_cache_snapshot snapshot;
	enum perf_cache_attr_outcome outcome;
	pthread_mutex_t *xattr_lock;
	uint64_t errors;
	int snapshot_error;
	bool barrier;
	bool handle_may_modify;
	bool may_modify = true;
	bool registration_refresh = false;
	bool retired;
	bool released;

	callback_increment(&perf_state.counters.release);
	if (!wbcache_passthrough_enabled()) {
		lo_release(req, ino, fi);
		return;
	}
	if (paper_wbcache_passthrough_enabled()) {
		/*
		 * Paper AllOpt retires the registered lower file on RELEASE, but
		 * RELEASE itself is not a metadata mutation.  Every actual lower
		 * WRITE already made the attr/xattr rows stale in the ordinary
		 * ExtFUSE WRITE decision, so do not add a close-time fstat, cache
		 * publication, or generation transition to the data path.
		 */
		released = release_wbcache_passthrough(req, ino, false);
		close(fi->fh);
		if (!released) {
			xattr_lock = xattr_lock_for_inode(ino);
			pthread_mutex_lock(xattr_lock);
			invalidate_attr(ino);
			invalidate_xattr_serialized(
				ino, PERF_CAPABILITY_XATTR, false);
			pthread_mutex_unlock(xattr_lock);
		}
		fuse_reply_err(req, 0);
		return;
	}
	xattr_lock = xattr_lock_for_inode(ino);
	pthread_mutex_lock(xattr_lock);
	barrier = attr_release_barrier_enabled();
	handle_may_modify = file_may_modify(fi->flags);
	if (!classify_wbcache_passthrough_release(ino, handle_may_modify,
						  &may_modify,
						  &registration_refresh)) {
		/* Fatal state loss must not leave an exact-token row serviceable. */
		invalidate_attr(ino);
		invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
		close(fi->fh);
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, 0);
		return;
	}
	if (!may_modify) {
		released = release_wbcache_passthrough(req, ino, false);
		close(fi->fh);
		if (released) {
			counter_increment(
				&perf_state.counters
					 .passthrough_release_readonly_fast);
		} else {
			/* A retirement failure must not leave cached metadata usable. */
			invalidate_attr(ino);
			invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR,
						    true);
		}
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, 0);
		return;
	}
	counter_increment(&perf_state.counters.passthrough_release_may_modify);
	if (registration_refresh)
		counter_increment(
			&perf_state.counters
				 .passthrough_release_registration_refreshes);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		if (barrier) {
			invalidate_attr(ino);
			invalidate_xattr_serialized(
				ino, PERF_CAPABILITY_XATTR, true);
		}
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	if (!barrier)
		invalidate_attr(ino);
	invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
	released = release_wbcache_passthrough(req, ino, !barrier);
	close(fi->fh);
	if (!barrier)
		invalidate_attr(ino);
	invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
	cache_mutation_end(&mutation);
	if (released && (perf_state.passthrough_coherence_v2_requested ||
			 perf_state.wbcache_passthrough_requested)) {
		/*
		 * Last-writer close may update IMA/EVM xattrs after the final native
		 * WRITE notification. Keep the daemon token active through backing
		 * deregistration and close, then snapshot through the pinned O_PATH fd.
		 */
		lo = lo_data(req);
		if (snapshot_inode_attr(req, ino, &st, &snapshot)) {
			counter_increment(&perf_state.counters
					 .passthrough_release_attr_snapshots);
			outcome = cache_attr(ino, &st, lo->timeout, &snapshot,
					     barrier, &ignored_reply_timeout);
			switch (outcome) {
			case PERF_CACHE_ATTR_PUBLISHED:
				counter_increment(&perf_state.counters
						 .passthrough_release_attr_published);
				break;
			case PERF_CACHE_ATTR_UNSTABLE:
				counter_increment(&perf_state.counters
						 .passthrough_release_attr_unstable);
				break;
			case PERF_CACHE_ATTR_SUPPRESSED:
				counter_increment(&perf_state.counters
						 .passthrough_release_attr_suppressed);
				break;
			case PERF_CACHE_ATTR_MISSING:
				counter_increment(&perf_state.counters
						 .passthrough_release_attr_missing);
				break;
			case PERF_CACHE_ATTR_DISABLED:
				counter_increment(&perf_state.counters
						 .passthrough_release_attr_disabled);
				break;
			case PERF_CACHE_ATTR_ERROR:
				counter_increment(&perf_state.counters
						 .passthrough_release_attr_errors);
				break;
			}
			prefetch_xattr_serialized(req, ino,
						  PERF_CAPABILITY_XATTR);
		} else {
			snapshot_error = errno;
			retired = snapshot_error == ESTALE &&
				  inode_identity_retired(req, ino);
			if (retired) {
				counter_increment(&perf_state.counters
					.passthrough_release_attr_retired_skips);
				errors = counter_value(&perf_state.counters
					.passthrough_release_attr_retired_skips);
				if (errors <= 8)
					fprintf(stderr,
						"PASSTHROUGH_ATTR_REFRESH_SKIP nodeid=%" PRIu64
						" reason=retired\n",
						(uint64_t)ino);
			} else {
				counter_increment(&perf_state.counters
						 .passthrough_release_attr_errors);
				errors = counter_value(&perf_state.counters
						       .passthrough_release_attr_errors);
				if (errors <= 8)
					fprintf(stderr,
						"PASSTHROUGH_ATTR_REFRESH_ERROR nodeid=%" PRIu64
						" errno=%d error=%s\n",
						(uint64_t)ino, snapshot_error,
						strerror(snapshot_error));
			}
			/*
			 * The barrier leaves a non-retired old-token row in place.  It
			 * cannot be served, but it remains a BPF_EXIST refresh seed.
			 */
			if (!barrier || retired)
				invalidate_attr(ino);
		}
	}
	/*
	 * The kernel disarms the negotiated RELEASE barrier when this reply is
	 * consumed.  Keep it after attr publication (or safe old-token retention)
	 * and all serialized capability-xattr work.
	 */
	pthread_mutex_unlock(xattr_lock);
	fuse_reply_err(req, 0);
}

__attribute__((noinline, used))
void perf_read(fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t offset, struct fuse_file_info *fi)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct perf_cache_mutation mutation = {};
	struct stat st;
	double ignored_reply_timeout;
	struct perf_cache_snapshot snapshot;
	int inode_fd;

	if (perf_state.wbcache_passthrough_requested)
		counter_increment(
			&perf_state.counters.wbcache_daemon_read_fallbacks);
	callback_increment(&perf_state.counters.read);
	if (!metadata_hits_enabled() ||
	    (perf_state.mode == PERF_MODE_HIT &&
	     perf_state.profile == PERF_PROFILE_PAPER_LIKE)) {
		/*
		 * The paper's MDOpt cache does not invalidate attributes for
		 * read-side atime changes.  Preserve that request-count policy only
		 * in the paper-like metadata cases; the gate and AllOpt fallback
		 * paths retain the coherence refresh below.
		 */
		lo_read(req, ino, size, offset, fi);
		return;
	}
	lo = lo_data(req);
	/*
	 * lo_read() completes the FUSE reply before it returns.  The kernel may
	 * then dispatch RELEASE on another worker, close fi->fh, and let an
	 * unrelated open reuse that descriptor while this callback takes its
	 * post-read attribute snapshot.  Caching that unrelated object's mode
	 * under @ino makes the next ExtFUSE GETATTR/LOOKUP fail with EIO and can
	 * mark the kernel inode bad.
	 *
	 * Metadata-hit modes deliberately ignore FORGET and pin lo_inode objects
	 * until destroy, because BPF LOOKUP hits are invisible to passthrough_ll's
	 * userspace refcount.  Use that inode's O_PATH descriptor: unlike fi->fh,
	 * it remains tied to exactly this inode after the READ reply and through
	 * concurrent RELEASE.
	 */
	inode = lo_inode(req, ino);
	inode_fd = inode->fd;
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	lo_read(req, ino, size, offset, fi);
	cache_mutation_end(&mutation);

	/*
	 * lo_read() has already completed the FUSE reply.  Refresh the cached
	 * attributes only when this post-read snapshot remains current; neither
	 * fstat nor map-update failure may replace the completed READ result.
	 */
	cache_snapshot_begin(ino, &snapshot);
	if (!extfuse_snapshot_pinned_inode(inode_fd, inode->dev, inode->ino,
					    &st))
		cache_attr(ino, &st, lo->timeout, &snapshot, false,
			   &ignored_reply_timeout);
}

__attribute__((noinline, used))
void perf_write_buf(fuse_req_t req, fuse_ino_t ino,
		    struct fuse_bufvec *buffer, off_t offset,
		    struct fuse_file_info *fi)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct perf_cache_mutation mutation = {};
	pthread_mutex_t *xattr_lock;
	struct stat st;
	double ignored_reply_timeout;
	struct perf_cache_snapshot snapshot;
	struct fuse_mutation_attr mutation_attr;
	bool carry_negative_capability;
	bool have_attr = false;
	uint64_t negative_capability_daemon_state;
	ssize_t result;
	int inode_fd;

	if (perf_state.wbcache_passthrough_requested)
		counter_increment(
			&perf_state.counters.wbcache_daemon_write_fallbacks);
	callback_increment(&perf_state.counters.write);
	if (!metadata_hits_enabled()) {
		lo_write_buf(req, ino, buffer, offset, fi);
		return;
	}
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	inode_fd = inode->fd;
	xattr_lock = xattr_lock_for_inode(ino);
	pthread_mutex_lock(xattr_lock);
	carry_negative_capability =
		negative_capability_cache_current_serialized(
			ino, &negative_capability_daemon_state);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	if (!carry_negative_capability)
		invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
	result = lo_do_write_buf(req, ino, buffer, offset, fi);
	cache_mutation_end(&mutation);
	if (result >= 0 && carry_negative_capability)
		refresh_negative_capability_serialized(
			ino, negative_capability_daemon_state);
	pthread_mutex_unlock(xattr_lock);

	if (result >= 0) {
		/* Populate the new snapshot before the successful WRITE reply. */
		cache_snapshot_begin(ino, &snapshot);
		if (!extfuse_snapshot_pinned_inode(inode_fd, inode->dev,
						    inode->ino, &st)) {
			cache_attr(ino, &st, lo->timeout, &snapshot, false,
				   &ignored_reply_timeout);
			have_attr = true;
		}
		if (have_attr && mutation_metadata_enabled()) {
			mutation_attr = (struct fuse_mutation_attr) {
				.ino = ino,
				.attr = &st,
				.attr_timeout = epoch_attr_timeout(
					ino, ignored_reply_timeout),
				.flags = FUSE_MUTATION_NODE_ATTR_VALID,
			};
			fuse_reply_write_attr(req, (size_t)result,
					      &mutation_attr);
		} else {
			fuse_reply_write(req, (size_t)result);
		}
	} else {
		fuse_reply_err(req, (int)-result);
	}
}

static void perf_flush(fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi)
{
	callback_increment(&perf_state.counters.flush);
	lo_flush(req, ino, fi);
}

__attribute__((noinline, used))
void perf_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		  int valid, struct fuse_file_info *fi)
{
	struct stat out_attr;
	struct perf_cache_mutation mutation = {};
	pthread_mutex_t *xattr_lock;
	double reply_timeout;
	int error;

	callback_increment(&perf_state.counters.setattr);
	if (!metadata_hits_enabled()) {
		lo_setattr(req, ino, attr, valid, fi);
		return;
	}
	xattr_lock = xattr_lock_for_inode(ino);
	pthread_mutex_lock(xattr_lock);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_mutex_unlock(xattr_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
	if (valid & FUSE_SET_ATTR_MODE)
		invalidate_xattr_serialized(ino, PERF_POSIX_ACL_ACCESS_XATTR,
					    false);
	error = lo_do_setattr(req, ino, attr, valid, fi, &out_attr);
	invalidate_attr(ino);
	invalidate_xattr_serialized(ino, PERF_CAPABILITY_XATTR, true);
	if (valid & FUSE_SET_ATTR_MODE)
		invalidate_xattr_serialized(ino, PERF_POSIX_ACL_ACCESS_XATTR,
					    false);
	cache_mutation_end(&mutation);
	pthread_mutex_unlock(xattr_lock);
	if (error) {
		fuse_reply_err(req, error);
		return;
	}

	reply_timeout = cache_inode_attr_before_reply(req, ino, &out_attr);
	fuse_reply_attr(req, &out_attr, reply_timeout);
}

static int pin_child(int parent_fd, const char *name, struct stat *identity)
{
	int fd;

	fd = openat(parent_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstatat(fd, "", identity, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) {
		int saved_error = errno;

		close(fd);
		errno = saved_error;
		return -1;
	}
	return fd;
}

/* lo->mutex must be held so lo_find() cannot race inode-number retirement. */
static fuse_ino_t find_identity_nodeid_locked(struct lo_data *lo,
					       int victim_fd,
					       const struct stat *identity)
{
	struct lo_inode *inode;

	if (victim_fd < 0)
		return 0;
	inode = lo_find_identity_locked(lo, identity->st_dev, identity->st_ino);
	return inode ? (uintptr_t)inode : 0;
}

/* lo->mutex must be held so lo_find() cannot race inode-number retirement. */
static fuse_ino_t identity_nodeid_locked(struct lo_data *lo, int victim_fd,
					 const struct stat *identity)
{
	struct lo_inode *inode;
	struct stat after;
	bool retire = false;

	if (victim_fd < 0)
		return 0;
	if (!fstatat(victim_fd, "", &after,
		     AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
		retire = after.st_nlink == 0;
	inode = lo_find_identity_locked(lo, identity->st_dev, identity->st_ino);
	if (!inode)
		return 0;
	if (retire) {
		/*
		 * Prevent inode-number reuse while keeping this pointer alive for
		 * outstanding kernel references and any BPF LOOKUP replies.
		 */
		lo_inode_index_remove_locked(lo, inode);
		inode->ino = 0;
		inode->dev = 0;
	}
	return (uintptr_t)inode;
}

__attribute__((noinline, used))
void perf_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct lo_data *lo;
	struct perf_cache_mutation mutation = {};
	struct stat identity = {};
	int parent_fd;
	int result;
	int saved_error;
	int victim_fd;
	fuse_ino_t victim_ino = 0;

	callback_increment(&perf_state.counters.unlink);
	if (!metadata_hits_enabled()) {
		lo_unlink(req, parent, name);
		return;
	}
	lo = lo_data(req);
	parent_fd = lo_fd(req, parent);
	pthread_rwlock_wrlock(&perf_state.namespace_lock);
	victim_fd = pin_child(parent_fd, name, &identity);
	if (victim_fd < 0) {
		saved_error = errno;
		invalidate_entry(parent, name);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, saved_error);
		return;
	}
	pthread_mutex_lock(&lo->mutex);
	victim_ino = find_identity_nodeid_locked(lo, victim_fd, &identity);
	pthread_mutex_unlock(&lo->mutex);
	cache_mutation_add(&mutation, parent);
	cache_mutation_add(&mutation, victim_ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		close(victim_fd);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_entry(parent, name);
	pthread_mutex_lock(&lo->mutex);
	result = unlinkat(parent_fd, name, 0);
	saved_error = result == -1 ? errno : 0;
	if (!result)
		victim_ino = identity_nodeid_locked(lo, victim_fd, &identity);
	pthread_mutex_unlock(&lo->mutex);
	if (victim_ino)
		invalidate_attr(victim_ino);
	invalidate_entry(parent, name);
	cache_mutation_end(&mutation);
	cache_inode_attr_snapshot(req, parent, NULL);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
	if (victim_fd >= 0)
		close(victim_fd);
	fuse_reply_err(req, saved_error);
}

static void perf_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct lo_data *lo;
	struct perf_cache_mutation mutation = {};
	struct stat identity = {};
	int parent_fd;
	int result;
	int saved_error;
	int victim_fd;
	fuse_ino_t victim_ino = 0;

	if (!metadata_hits_enabled()) {
		lo_rmdir(req, parent, name);
		return;
	}
	lo = lo_data(req);
	parent_fd = lo_fd(req, parent);
	pthread_rwlock_wrlock(&perf_state.namespace_lock);
	victim_fd = pin_child(parent_fd, name, &identity);
	if (victim_fd < 0) {
		saved_error = errno;
		invalidate_entry(parent, name);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, saved_error);
		return;
	}
	pthread_mutex_lock(&lo->mutex);
	victim_ino = find_identity_nodeid_locked(lo, victim_fd, &identity);
	pthread_mutex_unlock(&lo->mutex);
	cache_mutation_add(&mutation, parent);
	cache_mutation_add(&mutation, victim_ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		close(victim_fd);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_entry(parent, name);
	pthread_mutex_lock(&lo->mutex);
	result = unlinkat(parent_fd, name, AT_REMOVEDIR);
	saved_error = result == -1 ? errno : 0;
	if (!result)
		victim_ino = identity_nodeid_locked(lo, victim_fd, &identity);
	pthread_mutex_unlock(&lo->mutex);
	if (victim_ino)
		invalidate_attr(victim_ino);
	invalidate_entry(parent, name);
	cache_mutation_end(&mutation);
	cache_inode_attr_snapshot(req, parent, NULL);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
	if (victim_fd >= 0)
		close(victim_fd);
	fuse_reply_err(req, saved_error);
}

__attribute__((noinline, used))
void perf_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		 fuse_ino_t newparent, const char *newname,
		 unsigned int flags)
{
	struct lo_data *lo;
	struct perf_cache_mutation mutation = {};
	struct stat source_identity = {};
	struct stat target_identity = {};
	int parent_fd;
	int target_parent_fd;
	int result;
	int saved_error;
	int source_fd;
	int target_fd;
	fuse_ino_t source_ino = 0;
	fuse_ino_t target_ino = 0;

	callback_increment(&perf_state.counters.rename);
	if (!metadata_hits_enabled()) {
		lo_rename(req, parent, name, newparent, newname, flags);
		return;
	}
	lo = lo_data(req);
	parent_fd = lo_fd(req, parent);
	target_parent_fd = lo_fd(req, newparent);
	if (flags) {
		fuse_reply_err(req, EINVAL);
		return;
	}
	pthread_rwlock_wrlock(&perf_state.namespace_lock);
	source_fd = pin_child(parent_fd, name, &source_identity);
	if (source_fd < 0) {
		saved_error = errno;
		invalidate_entry(parent, name);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, saved_error);
		return;
	}
	target_fd = pin_child(target_parent_fd, newname, &target_identity);
	if (target_fd < 0 && errno != ENOENT) {
		saved_error = errno;
		invalidate_entry(newparent, newname);
		close(source_fd);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, saved_error);
		return;
	}
	pthread_mutex_lock(&lo->mutex);
	source_ino = find_identity_nodeid_locked(lo, source_fd,
						  &source_identity);
	target_ino = find_identity_nodeid_locked(lo, target_fd,
						  &target_identity);
	pthread_mutex_unlock(&lo->mutex);
	cache_mutation_add(&mutation, parent);
	cache_mutation_add(&mutation, newparent);
	cache_mutation_add(&mutation, source_ino);
	cache_mutation_add(&mutation, target_ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		close(source_fd);
		if (target_fd >= 0)
			close(target_fd);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_entry(parent, name);
	invalidate_entry(newparent, newname);
	pthread_mutex_lock(&lo->mutex);
	result = renameat(parent_fd, name, target_parent_fd, newname);
	saved_error = result == -1 ? errno : 0;
	if (!result) {
		source_ino = identity_nodeid_locked(lo, source_fd,
						   &source_identity);
		target_ino = identity_nodeid_locked(lo, target_fd,
						   &target_identity);
	}
	pthread_mutex_unlock(&lo->mutex);
	if (source_ino)
		invalidate_attr(source_ino);
	if (target_ino && target_ino != source_ino)
		invalidate_attr(target_ino);
	invalidate_entry(parent, name);
	invalidate_entry(newparent, newname);
	cache_mutation_end(&mutation);
	cache_inode_attr_snapshot(req, parent, NULL);
	if (newparent != parent)
		cache_inode_attr_snapshot(req, newparent, NULL);
	if (source_ino)
		cache_inode_attr_snapshot(req, source_ino, NULL);
	if (target_ino && target_ino != source_ino)
		cache_inode_attr_snapshot(req, target_ino, NULL);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
	if (source_fd >= 0)
		close(source_fd);
	if (target_fd >= 0)
		close(target_fd);
	fuse_reply_err(req, saved_error);
}

static void perf_mknod_symlink(fuse_req_t req, fuse_ino_t parent,
			       const char *name, mode_t mode, dev_t rdev,
			       const char *link)
{
	struct fuse_entry_param entry;
	struct perf_cache_mutation mutation = {};
	struct stat st;
	struct perf_cache_snapshot snapshot;
	bool have_snapshot = false;
	int saved_error;
	int result;

	if (!metadata_hits_enabled()) {
		lo_mknod_symlink(req, parent, name, mode, rdev, link);
		return;
	}
	cache_mutation_add(&mutation, parent);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_entry(parent, name);
	pthread_rwlock_wrlock(&perf_state.namespace_lock);
	result = mknod_wrapper(lo_fd(req, parent), name, link, mode, rdev);
	saved_error = result == -1 ? errno :
		      lo_do_lookup(req, parent, name, &entry);
	invalidate_entry(parent, name);
	cache_mutation_end(&mutation);
	cache_inode_attr_snapshot(req, parent, NULL);
	if (!saved_error)
		have_snapshot = snapshot_inode_attr(
			req, entry.ino, &st, &snapshot);
	if (have_snapshot)
		entry.attr = st;
	if (!saved_error)
		prefetch_capability(req, entry.ino);
	if (have_snapshot)
		cache_entry(parent, name, &entry, &snapshot);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
	if (saved_error) {
		fuse_reply_err(req, saved_error);
		return;
	}
	/* 생성 응답의 TTL은 libfuse passthrough_ll과 동일하게 유지한다. */
	if (coherence_epochs_enabled())
		entry.attr_timeout = epoch_attr_timeout(entry.ino,
						     entry.attr_timeout);
	fuse_reply_entry(req, &entry);
}

static void perf_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, dev_t rdev)
{
	perf_mknod_symlink(req, parent, name, mode, rdev, NULL);
}

static void perf_symlink(fuse_req_t req, const char *link,
			 fuse_ino_t parent, const char *name)
{
	perf_mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}

__attribute__((noinline, used))
void perf_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode)
{
	callback_increment(&perf_state.counters.mkdir);
	perf_mknod_symlink(req, parent, name, S_IFDIR | mode, 0, NULL);
}

static void perf_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
		      const char *name)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct fuse_entry_param entry;
	struct perf_cache_mutation mutation = {};
	struct stat st;
	char procname[64];
	struct perf_cache_snapshot snapshot;
	bool have_snapshot = false;
	int length;
	int result;
	int saved_error;

	if (!metadata_hits_enabled()) {
		lo_link(req, ino, parent, name);
		return;
	}
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	entry = (struct fuse_entry_param) {
		.attr_timeout = lo->timeout,
		.entry_timeout = lo->timeout,
	};
	length = snprintf(procname, sizeof(procname), "/proc/self/fd/%i",
			  inode->fd);
	if (length < 0 || (size_t)length >= sizeof(procname)) {
		fuse_reply_err(req, ENAMETOOLONG);
		return;
	}
	cache_mutation_add(&mutation, ino);
	cache_mutation_add(&mutation, parent);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	invalidate_entry(parent, name);
	pthread_rwlock_wrlock(&perf_state.namespace_lock);
	result = linkat(AT_FDCWD, procname, lo_fd(req, parent), name,
			AT_SYMLINK_FOLLOW);
	saved_error = result == -1 ? errno : 0;
	if (!saved_error &&
	    fstatat(inode->fd, "", &entry.attr,
		    AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
		saved_error = errno;
	if (!saved_error) {
		pthread_mutex_lock(&lo->mutex);
		inode->refcount++;
		pthread_mutex_unlock(&lo->mutex);
		entry.ino = (uintptr_t)inode;
	}
	invalidate_attr(ino);
	invalidate_entry(parent, name);
	cache_mutation_end(&mutation);
	cache_inode_attr_snapshot(req, parent, NULL);
	if (!saved_error)
		have_snapshot = snapshot_inode_attr(
			req, entry.ino, &st, &snapshot);
	if (have_snapshot)
		entry.attr = st;
	if (!saved_error)
		prefetch_capability(req, entry.ino);
	if (have_snapshot)
		cache_entry(parent, name, &entry, &snapshot);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
	if (saved_error) {
		fuse_reply_err(req, saved_error);
		return;
	}
	/* LINK 응답의 TTL도 baseline passthrough_ll과 동일하게 유지한다. */
	if (coherence_epochs_enabled())
		entry.attr_timeout = epoch_attr_timeout(entry.ino,
						     entry.attr_timeout);
	fuse_reply_entry(req, &entry);
}

static void perf_readlink(fuse_req_t req, fuse_ino_t ino)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct perf_cache_mutation mutation = {};
	dev_t dev;
	ino_t lower_ino;
	int fd;

	if (!metadata_hits_enabled()) {
		lo_readlink(req, ino);
		return;
	}
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	fd = inode->fd;
	dev = inode->dev;
	lower_ino = inode->ino;
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	lo_readlink(req, ino);
	invalidate_attr(ino);
	cache_mutation_end(&mutation);
	cache_pinned_inode_attr(lo, ino, fd, dev, lower_ino);
}

__attribute__((noinline, used))
void perf_opendir(fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
	callback_increment(&perf_state.counters.opendir);
	lo_opendir(req, ino, fi);
}

__attribute__((noinline, used))
void perf_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		  off_t offset, struct fuse_file_info *fi)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct perf_cache_mutation mutation = {};
	dev_t dev;
	ino_t lower_ino;
	int fd;

	callback_increment(&perf_state.counters.readdir);
	if (!metadata_hits_enabled()) {
		lo_readdir(req, ino, size, offset, fi);
		return;
	}
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	fd = inode->fd;
	dev = inode->dev;
	lower_ino = inode->ino;
	pthread_rwlock_rdlock(&perf_state.namespace_lock);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	lo_readdir(req, ino, size, offset, fi);
	invalidate_attr(ino);
	cache_mutation_end(&mutation);
	cache_pinned_inode_attr(lo, ino, fd, dev, lower_ino);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
}

__attribute__((noinline, used))
void perf_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	struct lo_data *lo;
	struct lo_inode *inode;
	struct perf_cache_mutation mutation = {};
	dev_t dev;
	ino_t lower_ino;
	int fd;

	callback_increment(&perf_state.counters.readdir);
	if (!metadata_hits_enabled()) {
		lo_readdirplus(req, ino, size, offset, fi);
		return;
	}
	lo = lo_data(req);
	inode = lo_inode(req, ino);
	fd = inode->fd;
	dev = inode->dev;
	lower_ino = inode->ino;
	pthread_rwlock_rdlock(&perf_state.namespace_lock);
	cache_mutation_add(&mutation, ino);
	if (!cache_mutation_begin(&mutation)) {
		cache_mutation_end(&mutation);
		pthread_rwlock_unlock(&perf_state.namespace_lock);
		fuse_reply_err(req, EIO);
		return;
	}
	invalidate_attr(ino);
	lo_readdirplus(req, ino, size, offset, fi);
	invalidate_attr(ino);
	cache_mutation_end(&mutation);
	cache_pinned_inode_attr(lo, ino, fd, dev, lower_ino);
	pthread_rwlock_unlock(&perf_state.namespace_lock);
}

__attribute__((noinline, used))
void perf_releasedir(fuse_req_t req, fuse_ino_t ino,
		     struct fuse_file_info *fi)
{
	callback_increment(&perf_state.counters.releasedir);
	lo_releasedir(req, ino, fi);
}

static void perf_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	callback_increment(&perf_state.counters.forget);
	if (!metadata_hits_enabled()) {
		lo_forget(req, ino, nlookup);
		return;
	}
	/*
	 * BPF LOOKUP hits increase the kernel's lookup count without running
	 * lo_lookup(). Keep benchmark inode objects pinned until destroy so a
	 * later FORGET cannot over-decrement passthrough_ll's userspace count.
	 */
	fuse_reply_none(req);
}

static void perf_forget_multi(fuse_req_t req, size_t count,
			      struct fuse_forget_data *forgets)
{
	callback_increment(&perf_state.counters.forget_multi);
	if (!metadata_hits_enabled()) {
		lo_forget_multi(req, count, forgets);
		return;
	}
	fuse_reply_none(req);
}

static struct fuse_session *
perf_intercept_session_new(struct fuse_args *args,
			   const struct fuse_lowlevel_ops *operations,
			   size_t operation_size, void *userdata)
{
	struct fuse_session *session;
	size_t copy_size = operation_size;

	perf_state.conn_opts = fuse_parse_conn_info_opts(args);
	if (!perf_state.conn_opts)
		return NULL;
	if (copy_size > sizeof(perf_state.operations))
		copy_size = sizeof(perf_state.operations);
	memset(&perf_state.operations, 0, sizeof(perf_state.operations));
	memcpy(&perf_state.operations, operations, copy_size);
	perf_state.operations.init = perf_init;
	perf_state.operations.destroy = perf_destroy;
	perf_state.operations.lookup = perf_lookup;
	perf_state.operations.getattr = perf_getattr;
#ifdef HAVE_STATX
	perf_state.operations.statx = perf_statx;
#endif
	perf_state.operations.getxattr = perf_getxattr;
	perf_state.operations.create = perf_create;
	perf_state.operations.tmpfile = perf_tmpfile;
	perf_state.operations.open = perf_open;
	perf_state.operations.release = perf_release;
	perf_state.operations.read = perf_read;
	perf_state.operations.write_buf = perf_write_buf;
	perf_state.operations.flush = perf_flush;
	perf_state.operations.setattr = perf_setattr;
	perf_state.operations.fallocate = perf_fallocate;
	perf_state.operations.setxattr = perf_setxattr;
	perf_state.operations.removexattr = perf_removexattr;
#ifdef HAVE_COPY_FILE_RANGE
	perf_state.operations.copy_file_range = perf_copy_file_range;
#endif
	perf_state.operations.mknod = perf_mknod;
	perf_state.operations.mkdir = perf_mkdir;
	perf_state.operations.symlink = perf_symlink;
	perf_state.operations.link = perf_link;
	perf_state.operations.unlink = perf_unlink;
	perf_state.operations.rmdir = perf_rmdir;
	perf_state.operations.rename = perf_rename;
	perf_state.operations.readlink = perf_readlink;
	perf_state.operations.opendir = perf_opendir;
	perf_state.operations.readdir = perf_readdir;
	perf_state.operations.readdirplus = perf_readdirplus;
	perf_state.operations.releasedir = perf_releasedir;
	perf_state.operations.forget = perf_forget;
	perf_state.operations.forget_multi = perf_forget_multi;

	session = fuse_session_new_fn(args, &perf_state.operations,
				      sizeof(perf_state.operations), userdata);
	perf_state.session = session;
	return session;
}

static bool path_has_prefix(const char *path, const char *prefix)
{
	char resolved[PATH_MAX];
	size_t prefix_length = strlen(prefix);

	if (!realpath(path, resolved))
		return false;
	return !strncmp(resolved, prefix, prefix_length);
}

static bool has_allowed_bpf_prefix(const char *path)
{
	return path_has_prefix(path, ALLOWED_BPF_PREFIX);
}

static bool path_is_within_root(const char *path, const char *root)
{
	char resolved_path[PATH_MAX];
	char resolved_root[PATH_MAX];
	size_t root_length;

	if (!realpath(path, resolved_path) || !realpath(root, resolved_root))
		return false;
	root_length = strlen(resolved_root);
	return !strcmp(resolved_path, resolved_root) ||
	       (!strncmp(resolved_path, resolved_root, root_length) &&
		resolved_path[root_length] == '/');
}

static bool has_allowed_data_prefix(const char *path, const char *disk_root)
{
	return path_has_prefix(path, ALLOWED_DATA_PREFIX) ||
	       path_is_within_root(path, disk_root);
}

static int parse_mode(const char *name, enum perf_mode *mode)
{
	if (!strcmp(name, "off"))
		*mode = PERF_MODE_OFF;
	else if (!strcmp(name, "upcall"))
		*mode = PERF_MODE_UPCALL;
	else if (!strcmp(name, "hit"))
		*mode = PERF_MODE_HIT;
	else if (!strcmp(name, "allopt"))
		*mode = PERF_MODE_ALLOPT;
	else
		return -1;
	return 0;
}

static int parse_profile(const char *name, enum perf_profile *profile)
{
	if (!strcmp(name, "zero-ttl"))
		*profile = PERF_PROFILE_ZERO_TTL;
	else if (!strcmp(name, "paper-like"))
		*profile = PERF_PROFILE_PAPER_LIKE;
	else if (!strcmp(name, "gate"))
		*profile = PERF_PROFILE_GATE;
	else
		return -1;
	return 0;
}

static int parse_metadata_upcall_tracing(bool *enabled)
{
	const char *text = getenv("EXTFUSE_TRACE_METADATA_UPCALLS");

	if (!text) {
		*enabled = false;
		return 0;
	}
	if (!strcmp(text, "0")) {
		*enabled = false;
		return 0;
	}
	if (!strcmp(text, "1")) {
		*enabled = true;
		return 0;
	}
	return -1;
}

static int parse_uring_q_depth(unsigned int *q_depth)
{
	const char *text = getenv("EXTFUSE_URING_Q_DEPTH");
	unsigned long value;
	char *end;

	if (!text || !*text) {
		*q_depth = 8;
		return 0;
	}
	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno || *end || value < 1 || value > 4096)
		return -1;
	*q_depth = (unsigned int)value;
	return 0;
}

static void cleanup_bpf(void)
{
	ebpf_fini(perf_state.bpf);
	perf_state.bpf = NULL;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s {off|upcall|hit|allopt} {classic|uring} "
		"{zero-ttl|paper-like|gate} BPF_OBJECT SOURCE MOUNTPOINT "
		"[PASSTHROUGH_LL_OPTION ...]\n",
		program);
}

int main(int argc, char **argv)
{
	char options[PATH_MAX * 2];
	char uring_options[64] = "";
	char **passthrough_argv;
	const char *bpf_object;
	const char *source;
	const char *mountpoint;
	int option_length;
	int rc;
	const char *count_callbacks;
	const char *fuse_debug;
	const char *require_coherence;
	const char *fig9_disk_root;
	int debug_enabled;
	size_t extra_argc;
	size_t passthrough_argc;
	size_t i;
	unsigned int uring_q_depth;

	if (argc < 7 || parse_mode(argv[1], &perf_state.mode) ||
	    (strcmp(argv[2], "classic") && strcmp(argv[2], "uring")) ||
	    parse_profile(argv[3], &perf_state.profile)) {
		usage(argv[0]);
		return 2;
	}
	perf_state.mode_name = argv[1];
	perf_state.transport = argv[2];
	if (parse_metadata_upcall_tracing(
		    &perf_state.trace_metadata_upcalls)) {
		fprintf(stderr,
			"EXTFUSE_TRACE_METADATA_UPCALLS must be 0 or 1\n");
		return 2;
	}
	if (perf_state.trace_metadata_upcalls &&
	    perf_state.mode != PERF_MODE_HIT &&
	    perf_state.mode != PERF_MODE_ALLOPT) {
		fprintf(stderr,
			"EXTFUSE_TRACE_METADATA_UPCALLS requires a metadata-hit mode\n");
		return 2;
	}
	if (parse_uring_q_depth(&uring_q_depth)) {
		fprintf(stderr,
			"EXTFUSE_URING_Q_DEPTH must be an integer in [1,4096]\n");
		return 2;
	}
	if (!strcmp(perf_state.transport, "uring")) {
		option_length = snprintf(
			uring_options, sizeof(uring_options),
			",io_uring,io_uring_q_depth=%u", uring_q_depth);
		if (option_length < 0 ||
		    (size_t)option_length >= sizeof(uring_options))
			return 2;
	}
	count_callbacks = getenv("EXTFUSE_COUNT_CALLBACKS");
	perf_state.count_callbacks =
		!count_callbacks || strcmp(count_callbacks, "0");
	fuse_debug = getenv("EXTFUSE_FUSE_DEBUG");
	debug_enabled = fuse_debug && strcmp(fuse_debug, "0");
	require_coherence = getenv("EXTFUSE_REQUIRE_PASSTHROUGH_COHERENCE");
	if (require_coherence && strcmp(require_coherence, "0") &&
	    strcmp(require_coherence, "1")) {
		fprintf(stderr,
			"EXTFUSE_REQUIRE_PASSTHROUGH_COHERENCE must be 0 or 1\n");
		return 2;
	}
	perf_state.require_passthrough_coherence =
		require_coherence && !strcmp(require_coherence, "1");
	bpf_object = argv[4];
	source = argv[5];
	mountpoint = argv[6];
	fig9_disk_root = getenv("FIG9_DISK_ROOT");

	if (!fig9_disk_root || fig9_disk_root[0] != '/' ||
	    !strcmp(fig9_disk_root, "/")) {
		fprintf(stderr,
			"FIG9_DISK_ROOT must be an absolute path other than /\n");
		return 2;
	}
	if (!has_allowed_data_prefix(source, fig9_disk_root) ||
	    !has_allowed_data_prefix(mountpoint, fig9_disk_root) ||
	    strchr(source, ',') || strchr(mountpoint, ',')) {
		fprintf(stderr,
			"PATH_POLICY_ERROR source=%s mountpoint=%s "
			"package_prefix=%s disk_root=%s\n",
			source, mountpoint, ALLOWED_DATA_PREFIX, fig9_disk_root);
		return 2;
	}
	if (metadata_hits_enabled() &&
	    perf_state.profile == PERF_PROFILE_PAPER_LIKE &&
	    verify_paper_capability_absent(source))
		return 1;
	if (metadata_hits_enabled()) {
		if (initialize_xattr_locks()) {
			fprintf(stderr, "cannot initialize xattr locks: %s\n",
				strerror(errno));
			return 1;
		}
		if (atexit(cleanup_xattr_locks)) {
			cleanup_xattr_locks();
			fprintf(stderr, "cannot register xattr lock cleanup\n");
			return 1;
		}
	}
	if (perf_state.mode != PERF_MODE_OFF) {
		if (!has_allowed_bpf_prefix(bpf_object)) {
			fprintf(stderr, "BPF_PATH_POLICY_ERROR object=%s\n",
				bpf_object);
			return 2;
		}
		perf_state.bpf = ebpf_init(bpf_object);
		if (!perf_state.bpf) {
			fprintf(stderr, "ebpf_init(%s) failed: %s\n",
				bpf_object, strerror(errno));
			return 1;
		}
		atexit(cleanup_bpf);
		if (check_maps())
			return 1;
		if (configure_bpf_policy())
			return 1;
		if (perf_state.mode == PERF_MODE_UPCALL &&
		    force_all_upcalls())
			return 1;
		if (metadata_hits_enabled() &&
		    disable_nonmetadata_hits())
			return 1;
	}

	if (perf_state.profile == PERF_PROFILE_GATE) {
		option_length = snprintf(
			options, sizeof(options),
			"source=%s,cache=auto,timeout=0,xattr,no_writeback,"
			"max_write=131072,splice_read,splice_write,"
			"splice_move,fsname=extfuse-perf-%s-%s%s",
			source, perf_state.mode_name, perf_state.transport,
			uring_options);
	} else if (perf_state.profile == PERF_PROFILE_ZERO_TTL) {
		option_length = snprintf(
			options, sizeof(options),
			"source=%s,cache=never,timeout=0,xattr,"
			"no_writeback,max_write=131072,splice_read,"
			"splice_write,splice_move,fsname=extfuse-perf-%s-%s%s",
			source, perf_state.mode_name, perf_state.transport,
			uring_options);
	} else {
		option_length = snprintf(
			options, sizeof(options),
			"source=%s,cache=auto,timeout=1.0,xattr,allow_other,writeback,"
			"writeback_cache,max_write=131072,splice_read,"
			"splice_write,splice_move,fsname=extfuse-perf-%s-%s%s",
			source, perf_state.mode_name, perf_state.transport,
			uring_options);
	}
	if (option_length < 0 || (size_t)option_length >= sizeof(options)) {
		fprintf(stderr, "mount options are too long\n");
		return 2;
	}

	extra_argc = (size_t)(argc - 7);
	passthrough_argc = 5 + extra_argc;
	passthrough_argv = calloc(passthrough_argc + 1,
				  sizeof(*passthrough_argv));
	if (!passthrough_argv) {
		fprintf(stderr, "cannot allocate passthrough argv\n");
		return 1;
	}
	passthrough_argv[0] = argv[0];
	/* Fig. 9 실행기에서 debug를 요청하면 libfuse의 -d를 사용한다. */
	passthrough_argv[1] = debug_enabled ? (char *)"-d" : (char *)"-f";
	passthrough_argv[2] = (char *)"-o";
	passthrough_argv[3] = options;
	for (i = 0; i < extra_argc; i++)
		passthrough_argv[4 + i] = argv[7 + i];
	passthrough_argv[4 + extra_argc] = (char *)mountpoint;
	passthrough_argv[passthrough_argc] = NULL;

	fprintf(stderr,
		"START mode=%s transport=%s profile=%s source=%s "
		PERF_START_MOUNT_FMT
		PERF_START_WBCACHE_FMT
		"xattr_lock_buckets=%u passthrough_extra_args=%zu "
		"mount_options=%s\n",
		perf_state.mode_name, perf_state.transport, argv[3],
		source, mountpoint, debug_enabled, perf_state.count_callbacks,
		wbcache_passthrough_enabled(), PERF_XATTR_LOCK_BUCKETS,
		extra_argc, options);
	for (i = 0; i < extra_argc; i++)
		fprintf(stderr, "PASSTHROUGH_ARG index=%zu value=%s\n", i,
			argv[7 + i]);
	rc = upstream_passthrough_main((int)passthrough_argc,
				       passthrough_argv);
	free(passthrough_argv);
	print_counters("exit");
	free(perf_state.conn_opts);
	perf_state.conn_opts = NULL;
	return rc;
}
