#define FUSE_USE_VERSION 318

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <fuse_kernel.h>
#include <fuse_lowlevel.h>

#define TEST_PROG_FD UINT32_C(0x12345678)

_Static_assert(FUSE_CAP_EXTFUSE == (1ULL << 34),
	       "unexpected public ExtFUSE capability bit");
_Static_assert(FUSE_FS_EXTFUSE == (1ULL << 43),
	       "unexpected ExtFUSE wire capability bit");
_Static_assert(FUSE_OVER_IO_URING == (1ULL << 41),
	       "unexpected FUSE-over-io_uring wire capability bit");
_Static_assert(sizeof(struct fuse_conn_info) == 128,
	       "fuse_conn_info ABI size changed");
_Static_assert(offsetof(struct fuse_conn_info, extfuse_prog_fd) == 68,
	       "fuse_conn_info ExtFUSE FD offset changed");
_Static_assert(sizeof(struct fuse_init_out) == 64,
	       "fuse_init_out wire size changed");
_Static_assert(offsetof(struct fuse_init_out, extfuse_prog_fd) == 44,
	       "fuse_init_out ExtFUSE FD offset changed");
_Static_assert(offsetof(struct fuse_init_out, unused) == 48,
	       "fuse_init_out reserved tail offset changed");

enum test_mode {
	MODE_NOT_WANTED,
	MODE_WANTED,
	MODE_FORCE_INVALID_WANT,
};

struct test_state {
	enum test_mode mode;
	bool saw_capability;
	bool saw_uring_capability;
	bool helper_enabled;
	_Alignas(max_align_t)
	unsigned char reply[sizeof(struct fuse_out_header) +
			    sizeof(struct fuse_init_out)];
	size_t reply_len;
};

static void test_init(void *userdata, struct fuse_conn_info *conn)
{
	struct test_state *state = userdata;

	state->saw_capability =
		fuse_get_feature_flag(conn, FUSE_CAP_EXTFUSE);
	state->saw_uring_capability =
		fuse_get_feature_flag(conn, FUSE_CAP_OVER_IO_URING);

	if (state->mode == MODE_WANTED) {
		state->helper_enabled =
			fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE);
		conn->extfuse_prog_fd = TEST_PROG_FD;
	} else if (state->mode == MODE_FORCE_INVALID_WANT) {
		conn->want_ext |= FUSE_CAP_EXTFUSE;
		conn->extfuse_prog_fd = TEST_PROG_FD;
	}
}

static ssize_t capture_writev(int fd, struct iovec *iov, int count,
			      void *userdata)
{
	struct test_state *state = userdata;
	size_t total = 0;
	int i;

	(void)fd;
	for (i = 0; i < count; i++) {
		if (total + iov[i].iov_len > sizeof(state->reply)) {
			errno = EOVERFLOW;
			return -1;
		}
		memcpy(state->reply + total, iov[i].iov_base, iov[i].iov_len);
		total += iov[i].iov_len;
	}
	state->reply_len = total;
	return (ssize_t)total;
}

static ssize_t unused_read(int fd, void *buf, size_t buf_len, void *userdata)
{
	(void)fd;
	(void)buf;
	(void)buf_len;
	(void)userdata;
	errno = ENOSYS;
	return -1;
}

static int run_case(bool advertise, bool advertise_uring, enum test_mode mode,
		    bool expect_error, const char *name)
{
	struct {
		struct fuse_in_header header;
		struct fuse_init_in init;
	} request;
	struct fuse_lowlevel_ops ops = {
		.init = test_init,
	};
	struct fuse_custom_io io = {
		.writev = capture_writev,
		.read = unused_read,
	};
	char *argv[] = { (char *)"extfuse-init-test" };
	struct fuse_args args = FUSE_ARGS_INIT(1, argv);
	struct fuse_buf request_buf;
	struct fuse_session *session;
	struct test_state state = {
		.mode = mode,
	};
	const struct fuse_out_header *reply_header;
	const struct fuse_init_out *reply_init;
	uint64_t reply_flags;
	int pipefd[2] = { -1, -1 };
	int rc = 1;

	if (pipe(pipefd) != 0) {
		perror("pipe");
		goto out_args;
	}

	session = fuse_session_new(&args, &ops, sizeof(ops), &state);
	if (session == NULL) {
		fprintf(stderr, "%s: fuse_session_new failed\n", name);
		goto out_pipe;
	}
	if (fuse_session_custom_io(session, &io, sizeof(io), pipefd[0]) != 0) {
		fprintf(stderr, "%s: fuse_session_custom_io failed\n", name);
		goto out_session;
	}

	memset(&request, 0, sizeof(request));
	request.header.len = sizeof(request);
	request.header.opcode = FUSE_INIT;
	request.header.unique = 1;
	request.init.major = FUSE_KERNEL_VERSION;
	request.init.minor = FUSE_KERNEL_MINOR_VERSION;
	request.init.flags = FUSE_INIT_EXT;
	if (advertise)
		request.init.flags2 |= (uint32_t)(FUSE_FS_EXTFUSE >> 32);
	if (advertise_uring)
		request.init.flags2 |= (uint32_t)(FUSE_OVER_IO_URING >> 32);

	request_buf = (struct fuse_buf) {
		.size = sizeof(request),
		.mem = &request,
	};
	fuse_session_process_buf(session, &request_buf);

	if (state.reply_len < sizeof(*reply_header)) {
		fprintf(stderr, "%s: missing INIT reply\n", name);
		goto out_session;
	}
	reply_header = (const struct fuse_out_header *)state.reply;
	if (reply_header->unique != request.header.unique) {
		fprintf(stderr, "%s: wrong reply unique\n", name);
		goto out_session;
	}

	if (expect_error) {
		if (reply_header->error != -EPROTO) {
			fprintf(stderr, "%s: expected EPROTO, got %d\n",
				name, reply_header->error);
			goto out_session;
		}
		if (state.saw_capability) {
			fprintf(stderr, "%s: absent capability reported present\n",
				name);
			goto out_session;
		}
		rc = 0;
		goto out_session;
	}

	if (reply_header->error != 0 ||
	    state.reply_len != sizeof(*reply_header) + sizeof(*reply_init)) {
		fprintf(stderr, "%s: malformed successful INIT reply\n", name);
		goto out_session;
	}
	reply_init = (const struct fuse_init_out *)(state.reply +
						    sizeof(*reply_header));
	reply_flags = reply_init->flags;
	if (reply_flags & FUSE_INIT_EXT)
		reply_flags |= (uint64_t)reply_init->flags2 << 32;

	if (state.saw_capability != advertise) {
		fprintf(stderr, "%s: capable_ext mapping mismatch\n", name);
		goto out_session;
	}
	if (state.saw_uring_capability != advertise_uring) {
		fprintf(stderr, "%s: io_uring capable_ext mapping mismatch\n",
			name);
		goto out_session;
	}
	if (reply_flags & FUSE_OVER_IO_URING) {
		fprintf(stderr, "%s: io_uring enabled without mount option\n",
			name);
		goto out_session;
	}
	if (mode == MODE_WANTED && advertise) {
		if (!state.helper_enabled ||
		    !(reply_flags & FUSE_FS_EXTFUSE) ||
		    reply_init->extfuse_prog_fd != TEST_PROG_FD) {
			fprintf(stderr, "%s: ExtFUSE opt-in was not serialized\n",
				name);
			goto out_session;
		}
	} else if ((reply_flags & FUSE_FS_EXTFUSE) ||
		   reply_init->extfuse_prog_fd != 0) {
		fprintf(stderr, "%s: ExtFUSE was enabled without opt-in\n", name);
		goto out_session;
	}

	rc = 0;

out_session:
	fuse_session_destroy(session);
out_pipe:
	close(pipefd[0]);
	close(pipefd[1]);
out_args:
	fuse_opt_free_args(&args);
	if (rc == 0)
		printf("PASS %s\n", name);
	return rc;
}

int main(void)
{
	int failed = 0;

	failed |= run_case(false, false, MODE_NOT_WANTED, false,
			   "not-advertised-not-wanted");
	failed |= run_case(true, false, MODE_NOT_WANTED, false,
			   "advertised-not-wanted");
	failed |= run_case(true, false, MODE_WANTED, false,
			   "advertised-wanted");
	failed |= run_case(true, true, MODE_WANTED, false,
			   "extfuse-and-io-uring-advertised-classic");
	failed |= run_case(false, false, MODE_FORCE_INVALID_WANT, true,
			   "not-advertised-forced-want");

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
