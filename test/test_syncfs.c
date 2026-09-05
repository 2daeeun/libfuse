#define FUSE_USE_VERSION 318

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <fuse_kernel.h>
#include <fuse_lowlevel.h>

struct test_state {
	uint64_t want;
	uint64_t capable;
	unsigned sync_calls;
	int sync_error;
	struct fuse_out_header out;
	struct fuse_init_out init;
};

static void test_init(void *userdata, struct fuse_conn_info *conn)
{
	struct test_state *state = userdata;

	state->capable = conn->capable_ext;
	conn->want_ext = state->want;
	if (state->want & FUSE_CAP_EXTFUSE)
		conn->extfuse_prog_fd = 123;
	if (state->want & FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH)
		conn->max_backing_stack_depth = FUSE_BACKING_STACKED_UNDER;
}

static void test_syncfs(fuse_req_t req, fuse_ino_t ino)
{
	struct test_state *state = fuse_req_userdata(req);

	assert(ino == FUSE_ROOT_ID);
	state->sync_calls++;
	fuse_reply_err(req, state->sync_error);
}

static ssize_t capture_writev(int fd, struct iovec *iov, int count,
			      void *userdata)
{
	struct test_state *state = userdata;
	ssize_t total = 0;
	int i;

	(void)fd;
	assert(iov[0].iov_len == sizeof(state->out));
	memcpy(&state->out, iov[0].iov_base, sizeof(state->out));
	if (state->out.unique == 1 && state->out.error == 0) {
		assert(count == 2 && iov[1].iov_len == sizeof(state->init));
		memcpy(&state->init, iov[1].iov_base, sizeof(state->init));
	}
	for (i = 0; i < count; i++)
		total += iov[i].iov_len;
	return total;
}

static ssize_t unused_read(int fd, void *buf, size_t size, void *userdata)
{
	(void)fd;
	(void)buf;
	(void)size;
	(void)userdata;
	errno = ENOSYS;
	return -1;
}

static void run_case(uint64_t wire, uint64_t want, unsigned minor,
		     int callback, int old_ops, int expect_error, int sync_error)
{
	struct test_state state = { .want = want, .sync_error = sync_error };
	struct fuse_lowlevel_ops ops = { .init = test_init };
	struct fuse_custom_io io = {
		.writev = capture_writev, .read = unused_read,
	};
	char *argv[] = { (char *)"syncfs-test" };
	struct fuse_args args = FUSE_ARGS_INIT(1, argv);
	struct fuse_session *session;
	struct {
		struct fuse_in_header in;
		struct fuse_init_in init;
	} init = { 0 };
	struct {
		struct fuse_in_header in;
		struct fuse_syncfs_in syncfs;
	} sync = { 0 };
	struct fuse_buf buf;
	uint64_t reply_flags;
	int pipefd[2];

	if (callback)
		ops.syncfs = test_syncfs;
	assert(pipe(pipefd) == 0);
	session = fuse_session_new(&args, &ops,
		old_ops ? offsetof(struct fuse_lowlevel_ops, syncfs) : sizeof(ops),
		&state);
	assert(session);
	assert(fuse_session_custom_io(session, &io, sizeof(io), pipefd[0]) == 0);
	init.in.len = sizeof(init);
	init.in.opcode = FUSE_INIT;
	init.in.unique = 1;
	init.init.major = FUSE_KERNEL_VERSION;
	init.init.minor = minor;
	init.init.flags = FUSE_INIT_EXT | (uint32_t)wire;
	init.init.flags2 = wire >> 32;
	buf = (struct fuse_buf) { .mem = &init, .size = sizeof(init) };
	fuse_session_process_buf(session, &buf);
	assert(state.out.error == (expect_error ? -EPROTO : 0));
	assert(!!(state.capable & FUSE_CAP_SYNCFS_SUPPORT) ==
	       (minor >= 48 && !!(wire & FUSE_SYNCFS_SUPPORT)));
	if (!expect_error) {
		reply_flags = state.init.flags |
			((uint64_t)state.init.flags2 << 32);
		assert(!!(reply_flags & FUSE_SYNCFS_SUPPORT) ==
		       !!(want & FUSE_CAP_SYNCFS_SUPPORT));
		assert(!!(reply_flags & FUSE_EXTFUSE_SYNCFS_PURE) ==
		       !!(want & FUSE_CAP_EXTFUSE_SYNCFS_PURE));
		assert(!!(reply_flags & FUSE_EXTFUSE_PAPER_READ_GUARD) ==
		       !!(want & FUSE_CAP_EXTFUSE_PAPER_READ_GUARD));
		sync.in.len = sizeof(sync);
		sync.in.opcode = FUSE_SYNCFS;
		sync.in.unique = 2;
		sync.in.nodeid = FUSE_ROOT_ID;
		buf = (struct fuse_buf) { .mem = &sync, .size = sizeof(sync) };
		fuse_session_process_buf(session, &buf);
		assert(state.out.unique == 2);
		assert(state.sync_calls == (callback && !old_ops ? 1U : 0U));
		assert(state.out.error ==
		       (callback && !old_ops ? -sync_error : -ENOSYS));
	}
	fuse_session_destroy(session);
	close(pipefd[0]);
	close(pipefd[1]);
	fuse_opt_free_args(&args);
}

int main(void)
{
	const uint64_t pure = FUSE_CAP_SYNCFS_SUPPORT | FUSE_CAP_EXTFUSE |
		FUSE_CAP_EXTFUSE_SYNCFS_PURE;
	const uint64_t pure_wire = FUSE_SYNCFS_SUPPORT | FUSE_FS_EXTFUSE |
		FUSE_EXTFUSE_SYNCFS_PURE;
	const uint64_t guard = FUSE_CAP_EXTFUSE_PAPER_READ_GUARD |
		FUSE_CAP_EXTFUSE | FUSE_CAP_WRITEBACK_CACHE |
		FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH |
		FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH;
	const uint64_t guard_wire = FUSE_EXTFUSE_PAPER_READ_GUARD |
		FUSE_FS_EXTFUSE | FUSE_WRITEBACK_CACHE |
		FUSE_EXTFUSE_WBCACHE_PASSTHROUGH |
		FUSE_EXTFUSE_PASSTHROUGH_ATTR_REFRESH;

	/* Legacy op_size, optional callback, no implicit opt-in, errors preserved. */
	run_case(0, 0, 48, 1, 1, 0, 0);
	run_case(0, 0, 48, 0, 0, 0, 0);
	run_case(FUSE_SYNCFS_SUPPORT, 0, 48, 1, 0, 0, 0);
	run_case(FUSE_SYNCFS_SUPPORT, FUSE_CAP_SYNCFS_SUPPORT, 48, 1, 0, 0, EIO);
	run_case(FUSE_SYNCFS_SUPPORT, FUSE_CAP_SYNCFS_SUPPORT, 48, 1, 0, 0, ENOSYS);
	run_case(FUSE_SYNCFS_SUPPORT, FUSE_CAP_SYNCFS_SUPPORT, 48, 0, 0, 1, 0);
	run_case(FUSE_SYNCFS_SUPPORT, FUSE_CAP_SYNCFS_SUPPORT, 48, 1, 1, 1, 0);
	run_case(FUSE_SYNCFS_SUPPORT, FUSE_CAP_SYNCFS_SUPPORT, 47, 1, 0, 1, 0);
	run_case(0, FUSE_CAP_SYNCFS_SUPPORT, 48, 1, 0, 1, 0);
	run_case(pure_wire, pure, 48, 1, 0, 0, 0);
	run_case(pure_wire, pure & ~FUSE_CAP_EXTFUSE, 48, 1, 0, 1, 0);
	run_case(pure_wire, pure & ~FUSE_CAP_SYNCFS_SUPPORT, 48, 1, 0, 1, 0);
	run_case(guard_wire, guard, 48, 1, 0, 0, 0);
	run_case(guard_wire, guard & ~FUSE_CAP_WRITEBACK_CACHE, 48, 1, 0, 1, 0);
	run_case(guard_wire, guard & ~FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH,
		 48, 1, 0, 1, 0);
	run_case(guard_wire | FUSE_PASSTHROUGH, guard | FUSE_CAP_PASSTHROUGH,
		 48, 1, 0, 1, 0);
	return 0;
}
