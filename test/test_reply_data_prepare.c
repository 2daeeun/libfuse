#define _GNU_SOURCE
#define FUSE_USE_VERSION 318

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <fuse_kernel.h>
#include <fuse_lowlevel.h>

/* Fault injection is confined to this test executable, never the library. */
static int fail_allocation;

int posix_memalign(void **mem, size_t alignment, size_t size)
{
	void *result;

	if (fail_allocation)
		return ENOMEM;
	if (alignment < sizeof(void *) || (alignment & (alignment - 1)))
		return EINVAL;
	if (size > SIZE_MAX - alignment)
		return ENOMEM;
	result = aligned_alloc(alignment,
		(size + alignment - 1) & ~(alignment - 1));
	if (!result)
		return ENOMEM;
	*mem = result;
	return 0;
}

struct test_state {
	struct fuse_buf source;
	enum fuse_buf_copy_flags flags;
	int enabled;
	int old_api;
	int send_failure;
	int calls;
	int sends;
	int api_result;
	int splice_requested;
	int splice_enabled;
	int splice_sends;
	ssize_t prepared;
	struct fuse_out_header reply;
};

static void test_init(void *userdata, struct fuse_conn_info *conn)
{
	struct test_state *state = userdata;

	if (state->splice_requested)
		state->splice_enabled = fuse_set_feature_flag(
			conn, FUSE_CAP_SPLICE_WRITE);
}

static void prepare(void *opaque, ssize_t result)
{
	struct test_state *state = opaque;

	assert(!state->calls && !state->sends);
	state->calls++;
	state->prepared = result;
	/* A metadata callback must not accidentally change transport errno. */
	errno = EBUSY;
}

static ssize_t capture_writev(int fd, struct iovec *iov, int count,
			      void *userdata)
{
	struct test_state *state = userdata;
	ssize_t total = 0;
	int i;

	(void)fd;
	if (state->enabled) {
		assert(state->calls == !state->old_api);
		assert(!state->sends++);
		memcpy(&state->reply, iov[0].iov_base, sizeof(state->reply));
		if (state->send_failure) {
			errno = EIO;
			return -1;
		}
	}
	for (i = 0; i < count; i++)
		total += iov[i].iov_len;
	return total;
}

static ssize_t capture_splice(int fdin, off_t *offin, int fdout,
			      off_t *offout, size_t len, unsigned flags,
			      void *userdata)
{
	struct test_state *state = userdata;
	char scratch[4096];
	size_t remain = len;
	ssize_t got;

	(void)offin;
	(void)fdout;
	(void)offout;
	(void)flags;
	assert(state->enabled && state->calls == !state->old_api);
	assert(!state->sends++);
	state->splice_sends++;
	got = read(fdin, &state->reply, sizeof(state->reply));
	assert(got == sizeof(state->reply));
	remain -= got;
	while (remain) {
		got = read(fdin, scratch, remain < sizeof(scratch) ?
			   remain : sizeof(scratch));
		assert(got > 0);
		remain -= got;
	}
	if (state->send_failure) {
		errno = EIO;
		return -1;
	}
	return len;
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

static void test_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		      off_t off, struct fuse_file_info *fi)
{
	struct test_state *state = fuse_req_userdata(req);
	struct fuse_bufvec vector = FUSE_BUFVEC_INIT(0);

	(void)ino;
	(void)size;
	(void)off;
	(void)fi;
	vector.buf[0] = state->source;
	if (state->old_api)
		state->api_result = fuse_reply_data(req, &vector, state->flags);
	else
		state->api_result = fuse_reply_data_with_prepare(req, &vector,
			state->flags, prepare, state);
}

static void request_read(struct fuse_session *session, struct test_state *state,
			 ssize_t expected, int reply_error)
{
	struct {
		struct fuse_in_header in;
		struct fuse_read_in read;
	} request = { 0 };
	struct fuse_buf buffer = { .mem = &request, .size = sizeof(request) };

	state->enabled = 1;
	state->calls = state->sends = 0;
	request.in.len = sizeof(request);
	request.in.opcode = FUSE_READ;
	request.in.unique = 2;
	request.in.nodeid = FUSE_ROOT_ID;
	request.read.size = state->source.size;
	fuse_session_process_buf(session, &buffer);
	assert(state->calls == !state->old_api);
	assert(state->sends == 1);
	assert(state->old_api || state->prepared == expected);
	assert(state->reply.error == reply_error);
	assert(state->api_result == (state->send_failure ? -EIO : 0));
}

int main(int argc, char **argv)
{
	struct test_state state = { 0 };
	struct fuse_lowlevel_ops ops = { .init = test_init, .read = test_read };
	struct fuse_custom_io io = {
		.writev = capture_writev, .read = unused_read,
		.splice_send = capture_splice,
	};
	char *fuse_argv[] = { (char *)"reply-data-prepare-test" };
	struct fuse_args args = FUSE_ARGS_INIT(1, fuse_argv);
	struct fuse_session *session;
	struct {
		struct fuse_in_header in;
		struct fuse_init_in init;
	} init = { 0 };
	struct fuse_buf buffer = { .mem = &init, .size = sizeof(init) };
	char bytes[16384] = { 0 };
	int channel[2], lower[2];
	int result = 0;
	int splice_before;

	if (argc == 2 && !strcmp(argv[1], "--splice"))
		state.splice_requested = 1;
	else if (argc != 1)
		return 2;

	assert(pipe(channel) == 0);
	session = fuse_session_new(&args, &ops, sizeof(ops), &state);
	assert(session);
	assert(fuse_session_custom_io(session, &io, sizeof(io), channel[0]) == 0);
	init.in.len = sizeof(init);
	init.in.opcode = FUSE_INIT;
	init.in.unique = 1;
	init.init.major = FUSE_KERNEL_VERSION;
	init.init.minor = FUSE_KERNEL_MINOR_VERSION;
	fuse_session_process_buf(session, &buffer);
	if (state.splice_requested && !state.splice_enabled) {
		fprintf(stderr, "SKIP: splice is unavailable in this build\n");
		result = 77;
		goto out;
	}

	state.source = (struct fuse_buf) { .mem = bytes, .size = sizeof(bytes) };
	state.flags = FUSE_BUF_NO_SPLICE;
	request_read(session, &state, sizeof(bytes), 0);
	state.send_failure = 1;
	request_read(session, &state, sizeof(bytes), 0);
	state.send_failure = 0;
	state.flags = 0;
	request_read(session, &state, sizeof(bytes), 0);
	if (state.splice_requested && !state.splice_sends) {
		/* Resource limits can deny pipe growth. Never call copy coverage
		 * a successful splice test; Meson records this variant as skipped.
		 */
		fprintf(stderr, "SKIP: splice pipe capacity is unavailable\n");
		result = 77;
		goto out;
	}
	if (state.splice_requested) {
		splice_before = state.splice_sends;
		state.send_failure = 1;
		request_read(session, &state, sizeof(bytes), 0);
		assert(state.splice_sends == splice_before + 1);
		state.send_failure = 0;
	}
	state.old_api = 1;
	splice_before = state.splice_sends;
	request_read(session, &state, 0, 0);
	assert(state.splice_sends == splice_before + state.splice_requested);
	state.old_api = 0;
	state.flags = state.splice_requested ? 0 : FUSE_BUF_NO_SPLICE;

	/* Short lower read followed by EOF, then zero-byte EOF. */
	assert(pipe(lower) == 0);
	assert(write(lower[1], bytes, 37) == 37);
	close(lower[1]);
	state.source = (struct fuse_buf) { .fd = lower[0], .size = sizeof(bytes),
		.flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_RETRY };
	request_read(session, &state, 37, 0);
	request_read(session, &state, 0, 0);
	close(lower[0]);
	state.source.fd = -1;
	request_read(session, &state, -EBADF, -EBADF);
	state.flags = FUSE_BUF_NO_SPLICE;
	fail_allocation = 1;
	request_read(session, &state, -ENOMEM, -ENOMEM);
	fail_allocation = 0;

	/* Notifications use no per-request callback and retain their old path. */
	state.old_api = 1;
	state.calls = state.sends = 0;
	{
		struct fuse_bufvec notify = FUSE_BUFVEC_INIT(sizeof(bytes));

		notify.buf[0].mem = bytes;
		assert(fuse_lowlevel_notify_store(session, FUSE_ROOT_ID, 0,
			&notify, FUSE_BUF_NO_SPLICE) == 0);
		assert(state.calls == 0 && state.sends == 1);
	}
out:
	fuse_session_destroy(session);
	close(channel[0]);
	close(channel[1]);
	fuse_opt_free_args(&args);
	return result;
}
