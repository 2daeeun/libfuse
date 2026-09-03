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
_Static_assert(FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE == (1ULL << 35),
	       "unexpected passthrough-coherence capability bit");
_Static_assert(FUSE_EXTFUSE_PASSTHROUGH_COHERENCE == (1ULL << 44),
	       "unexpected passthrough-coherence wire bit");
_Static_assert(FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE_V2 == (1ULL << 36),
	       "unexpected passthrough-coherence-v2 capability bit");
_Static_assert(FUSE_EXTFUSE_PASSTHROUGH_COHERENCE_V2 == (1ULL << 45),
	       "unexpected passthrough-coherence-v2 wire bit");
_Static_assert(FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH == (1ULL << 37),
	       "unexpected passthrough-attr-refresh capability bit");
_Static_assert(FUSE_EXTFUSE_PASSTHROUGH_ATTR_REFRESH == (1ULL << 46),
	       "unexpected passthrough-attr-refresh wire bit");
_Static_assert(FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER ==
		       (1ULL << 38),
	       "unexpected passthrough-attr-release-barrier capability bit");
_Static_assert(FUSE_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER == (1ULL << 47),
	       "unexpected passthrough-attr-release-barrier wire bit");
_Static_assert(FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH == (1ULL << 42),
	       "unexpected writeback-cache passthrough capability bit");
_Static_assert(FUSE_EXTFUSE_WBCACHE_PASSTHROUGH == (1ULL << 51),
	       "unexpected writeback-cache passthrough wire bit");
_Static_assert(FOPEN_EXTFUSE_WBCACHE_PASSTHROUGH == (1U << 8),
	       "unexpected writeback-cache passthrough open bit");
_Static_assert(FUSE_OVER_IO_URING == (1ULL << 41),
	       "unexpected FUSE-over-io_uring wire capability bit");
_Static_assert(FUSE_CAP_IO_URING_BUFPOOL == (1ULL << 43),
	       "unexpected io-uring buffer-pool capability bit");
_Static_assert(FUSE_HAS_IO_URING_BUFPOOL == (1ULL << 52),
	       "unexpected io-uring buffer-pool wire bit");
_Static_assert(FOPEN_IO_URING_ZERO_COPY == (1U << 9),
	       "unexpected io-uring zero-copy open bit");
_Static_assert(FUSE_IO_URING_CMD_ADD_QUEUE == 3,
	       "unexpected io-uring add-queue command");
_Static_assert(FUSE_IO_URING_CMD_ADD_BUFPOOL == 4,
	       "unexpected io-uring add-buffer-pool command");
_Static_assert(FUSE_URING_ENT_ZERO_COPY == (1U << 0),
	       "unexpected io-uring zero-copy entry bit");
_Static_assert(FUSE_URING_ZERO_COPY == (1U << 0),
	       "unexpected io-uring zero-copy queue bit");
_Static_assert(sizeof(struct fuse_uring_ent_in_out) == 32,
	       "unexpected io-uring entry metadata size");
_Static_assert(sizeof(struct fuse_uring_cmd_req) == 40,
	       "unexpected io-uring command size");
_Static_assert(sizeof(struct fuse_file_info) == 64,
	       "fuse_file_info ABI size changed");
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
	MODE_WANTED_COHERENCE,
	MODE_WANTED_COHERENCE_V2,
	MODE_WANTED_ATTR_REFRESH,
	MODE_WANTED_ATTR_RELEASE_BARRIER,
	MODE_WANTED_WBCACHE_PASSTHROUGH,
	MODE_WANTED_WBCACHE_ATTR_REFRESH,
	MODE_WANTED_WBCACHE_ATTR_RELEASE_BARRIER,
	MODE_FORCE_INVALID_WANT,
	MODE_FORCE_ATTR_REFRESH_WANT,
	MODE_FORCE_ATTR_RELEASE_BARRIER_WANT,
};

struct test_state {
	enum test_mode mode;
	bool saw_capability;
	bool saw_uring_capability;
	bool saw_coherence_capability;
	bool saw_coherence_v2_capability;
	bool saw_attr_refresh_capability;
	bool saw_attr_release_barrier_capability;
	bool helper_enabled;
	bool passthrough_helper_enabled;
	bool coherence_helper_enabled;
	bool coherence_v2_helper_enabled;
	bool attr_refresh_helper_enabled;
	bool attr_release_barrier_helper_enabled;
	bool wbcache_helper_enabled;
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
	state->saw_coherence_capability = fuse_get_feature_flag(
		conn, FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE);
	state->saw_coherence_v2_capability = fuse_get_feature_flag(
		conn, FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE_V2);
	state->saw_attr_refresh_capability = fuse_get_feature_flag(
		conn, FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH);
	state->saw_attr_release_barrier_capability = fuse_get_feature_flag(
		conn, FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER);

	if (state->mode == MODE_WANTED_WBCACHE_PASSTHROUGH) {
		state->helper_enabled =
			fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE);
		fuse_set_feature_flag(conn, FUSE_CAP_WRITEBACK_CACHE);
		state->wbcache_helper_enabled = fuse_set_feature_flag(
			conn, FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH);
		conn->max_backing_stack_depth = FUSE_BACKING_STACKED_UNDER;
		conn->extfuse_prog_fd = TEST_PROG_FD;
	} else if (state->mode == MODE_WANTED_WBCACHE_ATTR_REFRESH ||
	    state->mode == MODE_WANTED_WBCACHE_ATTR_RELEASE_BARRIER) {
		state->helper_enabled =
			fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE);
		fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE_COHERENCE_EPOCHS);
		fuse_set_feature_flag(conn, FUSE_CAP_WRITEBACK_CACHE);
		fuse_set_feature_flag(conn,
				      FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH);
		state->attr_refresh_helper_enabled = fuse_set_feature_flag(
			conn, FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH);
		if (state->mode == MODE_WANTED_WBCACHE_ATTR_RELEASE_BARRIER)
			state->attr_release_barrier_helper_enabled = fuse_set_feature_flag(
				conn,
				FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER);
		conn->extfuse_prog_fd = TEST_PROG_FD;
	} else if (state->mode == MODE_WANTED ||
	    state->mode == MODE_WANTED_COHERENCE ||
	    state->mode == MODE_WANTED_COHERENCE_V2 ||
	    state->mode == MODE_WANTED_ATTR_REFRESH ||
	    state->mode == MODE_WANTED_ATTR_RELEASE_BARRIER) {
		state->helper_enabled =
			fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE);
		if (state->mode == MODE_WANTED_COHERENCE ||
		    state->mode == MODE_WANTED_COHERENCE_V2 ||
		    state->mode == MODE_WANTED_ATTR_REFRESH ||
		    state->mode == MODE_WANTED_ATTR_RELEASE_BARRIER) {
			state->passthrough_helper_enabled = fuse_set_feature_flag(
				conn, FUSE_CAP_PASSTHROUGH);
			state->coherence_helper_enabled = fuse_set_feature_flag(
				conn,
				FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE);
		}
		if (state->mode == MODE_WANTED_COHERENCE_V2 ||
		    state->mode == MODE_WANTED_ATTR_REFRESH ||
		    state->mode == MODE_WANTED_ATTR_RELEASE_BARRIER)
			state->coherence_v2_helper_enabled = fuse_set_feature_flag(
				conn,
				FUSE_CAP_EXTFUSE_PASSTHROUGH_COHERENCE_V2);
		if (state->mode == MODE_WANTED_ATTR_REFRESH ||
		    state->mode == MODE_WANTED_ATTR_RELEASE_BARRIER)
			state->attr_refresh_helper_enabled = fuse_set_feature_flag(
				conn,
				FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH);
		if (state->mode == MODE_WANTED_ATTR_RELEASE_BARRIER)
			state->attr_release_barrier_helper_enabled =
				fuse_set_feature_flag(
					conn,
					FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER);
		conn->extfuse_prog_fd = TEST_PROG_FD;
	} else if (state->mode == MODE_FORCE_INVALID_WANT) {
		conn->want_ext |= FUSE_CAP_EXTFUSE;
		conn->extfuse_prog_fd = TEST_PROG_FD;
	} else if (state->mode == MODE_FORCE_ATTR_REFRESH_WANT) {
		conn->want_ext |= FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_REFRESH;
	} else if (state->mode == MODE_FORCE_ATTR_RELEASE_BARRIER_WANT) {
		conn->want_ext |=
			FUSE_CAP_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER;
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

static int run_case_flags(bool advertise, bool advertise_uring,
			  bool advertise_coherence, bool advertise_coherence_v2,
			  bool advertise_attr_refresh,
			  bool advertise_attr_release_barrier,
			  uint64_t additional_flags, enum test_mode mode,
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
	const uint64_t wbcache_attr_flags =
		FUSE_FS_EXTFUSE | FUSE_EXTFUSE_COHERENCE_EPOCHS |
		FUSE_WRITEBACK_CACHE | FUSE_EXTFUSE_WBCACHE_PASSTHROUGH |
		FUSE_EXTFUSE_PASSTHROUGH_ATTR_REFRESH;
	const uint64_t native_attr_flags =
		FUSE_PASSTHROUGH | FUSE_EXTFUSE_PASSTHROUGH_COHERENCE |
		FUSE_EXTFUSE_PASSTHROUGH_COHERENCE_V2 |
		FUSE_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER;
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
	request.init.flags = FUSE_INIT_EXT | (uint32_t)additional_flags;
	request.init.flags2 = (uint32_t)(additional_flags >> 32);
	if (advertise)
		request.init.flags2 |= (uint32_t)(FUSE_FS_EXTFUSE >> 32);
	if (advertise_uring)
		request.init.flags2 |= (uint32_t)(FUSE_OVER_IO_URING >> 32);
	if (advertise_coherence)
		request.init.flags2 |= (uint32_t)(
			(FUSE_PASSTHROUGH |
			 FUSE_EXTFUSE_PASSTHROUGH_COHERENCE) >> 32);
	if (advertise_coherence_v2)
		request.init.flags2 |= (uint32_t)
			(FUSE_EXTFUSE_PASSTHROUGH_COHERENCE_V2 >> 32);
	if (advertise_attr_refresh)
		request.init.flags2 |=
			(uint32_t)(FUSE_EXTFUSE_PASSTHROUGH_ATTR_REFRESH >> 32);
	if (advertise_attr_release_barrier)
		request.init.flags2 |= (uint32_t)(
			FUSE_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER >> 32);

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
		if (state.saw_capability != advertise ||
		    state.saw_uring_capability != advertise_uring ||
		    state.saw_coherence_capability != advertise_coherence ||
		    state.saw_coherence_v2_capability !=
			    advertise_coherence_v2 ||
		    state.saw_attr_refresh_capability !=
			    advertise_attr_refresh ||
		    state.saw_attr_release_barrier_capability !=
			    advertise_attr_release_barrier) {
			fprintf(stderr, "%s: error-path capability mapping mismatch\n",
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
	if (state.saw_coherence_capability != advertise_coherence) {
		fprintf(stderr, "%s: coherence capable_ext mapping mismatch\n",
			name);
		goto out_session;
	}
	if (state.saw_coherence_v2_capability != advertise_coherence_v2) {
		fprintf(stderr,
			"%s: coherence-v2 capable_ext mapping mismatch\n", name);
		goto out_session;
	}
	if (state.saw_attr_refresh_capability != advertise_attr_refresh) {
		fprintf(stderr,
			"%s: attr-refresh capable_ext mapping mismatch\n",
			name);
		goto out_session;
	}
	if (state.saw_attr_release_barrier_capability !=
	    advertise_attr_release_barrier) {
		fprintf(stderr,
			"%s: attr-release-barrier capable_ext mapping mismatch\n",
			name);
		goto out_session;
	}
	if (reply_flags & FUSE_OVER_IO_URING) {
		fprintf(stderr, "%s: io_uring enabled without mount option\n",
			name);
		goto out_session;
	}
	if ((mode == MODE_WANTED || mode == MODE_WANTED_COHERENCE ||
	     mode == MODE_WANTED_COHERENCE_V2 ||
	     mode == MODE_WANTED_ATTR_REFRESH ||
	     mode == MODE_WANTED_ATTR_RELEASE_BARRIER ||
	     mode == MODE_WANTED_WBCACHE_PASSTHROUGH ||
	     mode == MODE_WANTED_WBCACHE_ATTR_REFRESH) &&
	    advertise) {
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
	if ((mode == MODE_WANTED_COHERENCE ||
	     mode == MODE_WANTED_COHERENCE_V2 ||
	     mode == MODE_WANTED_ATTR_REFRESH ||
	     mode == MODE_WANTED_ATTR_RELEASE_BARRIER) &&
	    advertise_coherence) {
		if (!state.passthrough_helper_enabled ||
		    !state.coherence_helper_enabled ||
		    !(reply_flags & FUSE_PASSTHROUGH) ||
		    !(reply_flags & FUSE_EXTFUSE_PASSTHROUGH_COHERENCE)) {
			fprintf(stderr,
				"%s: coherence opt-in was not serialized\n", name);
			goto out_session;
		}
	} else if (reply_flags & FUSE_EXTFUSE_PASSTHROUGH_COHERENCE) {
		fprintf(stderr, "%s: coherence was enabled without opt-in\n", name);
		goto out_session;
	}
	if ((mode == MODE_WANTED_COHERENCE_V2 ||
	     mode == MODE_WANTED_ATTR_REFRESH ||
	     mode == MODE_WANTED_ATTR_RELEASE_BARRIER) &&
	    advertise_coherence_v2) {
		if (!state.coherence_v2_helper_enabled ||
		    !(reply_flags & FUSE_EXTFUSE_PASSTHROUGH_COHERENCE_V2)) {
			fprintf(stderr,
				"%s: coherence-v2 opt-in was not serialized\n",
				name);
			goto out_session;
		}
	} else if (reply_flags & FUSE_EXTFUSE_PASSTHROUGH_COHERENCE_V2) {
		fprintf(stderr,
			"%s: coherence-v2 was enabled without opt-in\n", name);
		goto out_session;
	}
	if ((mode == MODE_WANTED_ATTR_REFRESH ||
	     mode == MODE_WANTED_ATTR_RELEASE_BARRIER ||
	     mode == MODE_WANTED_WBCACHE_ATTR_REFRESH) &&
	    advertise_attr_refresh) {
		if (!state.attr_refresh_helper_enabled ||
		    !(reply_flags & FUSE_EXTFUSE_PASSTHROUGH_ATTR_REFRESH)) {
			fprintf(stderr,
				"%s: attr-refresh opt-in was not serialized\n",
				name);
			goto out_session;
		}
	} else if (reply_flags & FUSE_EXTFUSE_PASSTHROUGH_ATTR_REFRESH) {
		fprintf(stderr, "%s: attr refresh was enabled without opt-in\n",
			name);
		goto out_session;
	}
	if (mode == MODE_WANTED_ATTR_RELEASE_BARRIER &&
	    advertise_attr_release_barrier) {
		if (!state.attr_release_barrier_helper_enabled ||
		    !(reply_flags &
		      FUSE_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER)) {
			fprintf(stderr,
				"%s: attr release barrier opt-in was not serialized\n",
				name);
			goto out_session;
		}
	} else if (reply_flags &
		   FUSE_EXTFUSE_PASSTHROUGH_ATTR_RELEASE_BARRIER) {
		fprintf(stderr,
			"%s: attr release barrier was enabled without opt-in\n",
			name);
		goto out_session;
	}
	if (mode == MODE_WANTED_WBCACHE_ATTR_REFRESH &&
	    ((reply_flags & wbcache_attr_flags) != wbcache_attr_flags ||
	     (reply_flags & native_attr_flags))) {
		fprintf(stderr,
			"%s: WBCache attr-refresh opt-in was not serialized\n",
			name);
		goto out_session;
	}
	if (mode == MODE_WANTED_WBCACHE_PASSTHROUGH &&
	    (!state.wbcache_helper_enabled ||
	     !(reply_flags & FUSE_WRITEBACK_CACHE) ||
	     !(reply_flags & FUSE_EXTFUSE_WBCACHE_PASSTHROUGH) ||
	     (reply_flags & (FUSE_EXTFUSE_COHERENCE_EPOCHS |
			    FUSE_MUTATION_METADATA |
			    FUSE_HAS_NOTIFY_INVAL_XATTR |
			    FUSE_EXTFUSE_PASSTHROUGH_ATTR_REFRESH |
			    FUSE_PASSTHROUGH)) ||
	     reply_init->max_stack_depth != 1)) {
		fprintf(stderr,
			"paper WBCache passthrough opt-in was not serialized\n");
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

static int run_case(bool advertise, bool advertise_uring,
		    bool advertise_coherence, bool advertise_coherence_v2,
		    bool advertise_attr_refresh,
		    bool advertise_attr_release_barrier, enum test_mode mode,
		    bool expect_error, const char *name)
{
	return run_case_flags(advertise, advertise_uring, advertise_coherence,
			      advertise_coherence_v2, advertise_attr_refresh,
			      advertise_attr_release_barrier, 0, mode,
			      expect_error, name);
}

int main(void)
{
	const uint64_t wbcache_attr_refresh_prerequisite_flags =
		FUSE_EXTFUSE_COHERENCE_EPOCHS | FUSE_WRITEBACK_CACHE |
		FUSE_EXTFUSE_WBCACHE_PASSTHROUGH;
	int failed = 0;

	failed |= run_case(false, false, false, false, false, false, MODE_NOT_WANTED,
			   false, "not-advertised-not-wanted");
	failed |= run_case(true, false, false, false, false, false, MODE_NOT_WANTED,
			   false, "advertised-not-wanted");
	failed |= run_case(true, false, false, false, false, false, MODE_WANTED, false,
			   "advertised-wanted");
	failed |= run_case(true, true, false, false, false, false, MODE_WANTED, false,
			   "extfuse-and-io-uring-advertised-classic");
	failed |= run_case(true, false, true, false, false, false,
			   MODE_WANTED_COHERENCE, false,
			   "extfuse-coherence-advertised-wanted");
	failed |= run_case(true, false, true, true, false, false,
			   MODE_WANTED_COHERENCE_V2, false,
			   "extfuse-coherence-v2-advertised-wanted");
	failed |= run_case(true, false, false, true, false, false,
			   MODE_WANTED_COHERENCE_V2, true,
			   "extfuse-coherence-v2-without-base-rejected");
	failed |= run_case(true, false, true, true, true, false, MODE_NOT_WANTED,
			   false, "extfuse-attr-refresh-advertised-not-wanted");
	failed |= run_case(true, false, true, true, true, false,
			   MODE_WANTED_ATTR_REFRESH, false,
			   "extfuse-attr-refresh-advertised-wanted");
	failed |= run_case(true, false, true, false, true, false,
			   MODE_WANTED_ATTR_REFRESH, true,
			   "extfuse-attr-refresh-without-v2-rejected");
	failed |= run_case(
		false, false, false, false, true, false, MODE_WANTED_ATTR_REFRESH,
		true, "extfuse-attr-refresh-without-prerequisites-rejected");
	failed |= run_case(true, false, true, true, false, false,
			   MODE_FORCE_ATTR_REFRESH_WANT, true,
			   "extfuse-attr-refresh-unadvertised-forced-want");
	failed |= run_case_flags(
		true, false, false, false, false, false,
		FUSE_WRITEBACK_CACHE | FUSE_EXTFUSE_WBCACHE_PASSTHROUGH,
		MODE_WANTED_WBCACHE_PASSTHROUGH, false,
		"extfuse-paper-wbcache-passthrough-advertised-wanted");
	failed |= run_case_flags(
		true, false, false, false, true, false,
		wbcache_attr_refresh_prerequisite_flags,
		MODE_WANTED_WBCACHE_ATTR_REFRESH, false,
		"extfuse-wbcache-attr-refresh-advertised-wanted");
	failed |= run_case_flags(
		true, false, false, false, true, false,
		wbcache_attr_refresh_prerequisite_flags & ~FUSE_WRITEBACK_CACHE,
		MODE_WANTED_WBCACHE_ATTR_REFRESH, true,
		"extfuse-wbcache-attr-refresh-without-writeback-rejected");
	failed |= run_case_flags(true, false, false, false, true, true,
				 wbcache_attr_refresh_prerequisite_flags,
				 MODE_WANTED_WBCACHE_ATTR_RELEASE_BARRIER, true,
				 "extfuse-wbcache-release-barrier-rejected");
	failed |= run_case(true, false, true, true, true, true,
			   MODE_NOT_WANTED, false,
			   "extfuse-attr-release-barrier-advertised-not-wanted");
	failed |= run_case(true, false, true, true, true, true,
			   MODE_WANTED_ATTR_RELEASE_BARRIER, false,
			   "extfuse-attr-release-barrier-advertised-wanted");
	failed |= run_case(true, false, true, true, false, true,
			   MODE_WANTED_ATTR_RELEASE_BARRIER, true,
			   "extfuse-attr-release-barrier-without-refresh-rejected");
	failed |= run_case(false, false, false, false, false, true,
			   MODE_WANTED_ATTR_RELEASE_BARRIER, true,
			   "extfuse-attr-release-barrier-without-prerequisites-rejected");
	failed |= run_case(true, false, true, true, true, false,
			   MODE_FORCE_ATTR_RELEASE_BARRIER_WANT, true,
			   "extfuse-attr-release-barrier-unadvertised-forced-want");
	failed |= run_case(false, false, false, false, false, false,
			   MODE_FORCE_INVALID_WANT, true,
			   "not-advertised-forced-want");

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
