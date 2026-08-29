#define FUSE_USE_VERSION 318

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <fuse_kernel.h>
#include <fuse_lowlevel.h>

#define TEST_NODEID UINT64_C(42)
#define TEST_COPY_NODEID UINT64_C(84)
#define TEST_PROG_FD UINT32_C(0x12345678)

_Static_assert(FUSE_KERNEL_MINOR_VERSION == 46, "unexpected protocol minor");
_Static_assert(FUSE_EXTFUSE_COHERENCE_V3 == (1ULL << 48),
	       "unexpected V3 wire bit");
_Static_assert(FUSE_MUTATION_METADATA == (1ULL << 49),
	       "unexpected mutation-metadata wire bit");
_Static_assert(FUSE_HAS_NOTIFY_INVAL_XATTR == (1ULL << 50),
	       "unexpected xattr-notify wire bit");
_Static_assert(FUSE_CAP_EXTFUSE_COHERENCE_V3 == (1ULL << 39),
	       "unexpected V3 capability bit");
_Static_assert(FUSE_CAP_MUTATION_METADATA == (1ULL << 40),
	       "unexpected mutation-metadata capability bit");
_Static_assert(FUSE_CAP_NOTIFY_INVAL_XATTR == (1ULL << 41),
	       "unexpected xattr-notify capability bit");
_Static_assert(sizeof(struct fuse_mutation_out) == 8,
	       "unexpected mutation header size");
_Static_assert(sizeof(struct fuse_mutation_node_out) == 120,
	       "unexpected mutation node size");
_Static_assert(sizeof(struct fuse_notify_inval_xattr_out) == 16,
	       "unexpected xattr notification size");

enum reply_mode {
	REPLY_WRITE_VALID,
	REPLY_WRITE_INVALID_FLAGS,
	REPLY_WRITE_INVALID_ATTR,
	REPLY_COPY_VALID,
};

enum negotiation_mode {
	NEGOTIATE_NONE,
	NEGOTIATE_CORE_ONLY,
	NEGOTIATE_ALL,
	NEGOTIATE_INVALID_MUTATION,
};

struct test_state {
	enum negotiation_mode negotiation;
	enum reply_mode reply_mode;
	unsigned char reply[2048];
	size_t reply_len;
	unsigned int writes;
};

static struct stat test_stat(uint64_t ino, off_t size)
{
	struct stat attr = {
		.st_ino = ino,
		.st_mode = S_IFREG | 0644,
		.st_nlink = 1,
		.st_size = size,
		.st_blksize = 4096,
		.st_blocks = 8,
	};

	return attr;
}

static void test_init(void *userdata, struct fuse_conn_info *conn)
{
	struct test_state *state = userdata;

	if (state->negotiation == NEGOTIATE_NONE)
		return;
	if (state->negotiation == NEGOTIATE_INVALID_MUTATION) {
		fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE);
		fuse_set_feature_flag(conn, FUSE_CAP_MUTATION_METADATA);
		conn->extfuse_prog_fd = TEST_PROG_FD;
		return;
	}
	if (!fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE) ||
	    !fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE_COHERENCE_V3)) {
		fprintf(stderr, "failed to opt in to advertised V3 capabilities\n");
		return;
	}
	if (state->negotiation == NEGOTIATE_ALL &&
	    (!fuse_set_feature_flag(conn, FUSE_CAP_MUTATION_METADATA) ||
	     !fuse_set_feature_flag(conn, FUSE_CAP_NOTIFY_INVAL_XATTR))) {
		fprintf(stderr, "failed to opt in to advertised V3 extensions\n");
		return;
	}
	conn->extfuse_prog_fd = TEST_PROG_FD;
}

static void test_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
		       size_t size, off_t off, struct fuse_file_info *fi)
{
	struct test_state *state = fuse_req_userdata(req);
	struct stat attr = test_stat(ino, (off_t)size);
	struct fuse_mutation_attr mutation = {
		.ino = ino,
		.attr = &attr,
		.attr_timeout = 1.25,
		.flags = FUSE_MUTATION_NODE_ATTR_VALID |
			 FUSE_MUTATION_NODE_XATTR_UNCHANGED,
	};

	(void)buf;
	(void)off;
	(void)fi;
	if (state->reply_mode == REPLY_WRITE_INVALID_FLAGS)
		mutation.flags |= FUSE_MUTATION_NODE_XATTR_CHANGED;
	else if (state->reply_mode == REPLY_WRITE_INVALID_ATTR)
		mutation.attr = NULL;
	fuse_reply_write_attr(req, size, &mutation);
}

static void test_copy_file_range(fuse_req_t req, fuse_ino_t ino_in,
				 off_t off_in, struct fuse_file_info *fi_in,
				 fuse_ino_t ino_out, off_t off_out,
				 struct fuse_file_info *fi_out, size_t len,
				 int flags)
{
	struct stat attr_in = test_stat(ino_in, 4096);
	struct stat attr_out = test_stat(ino_out, 8192);
	struct fuse_mutation_attr attrs[2] = {
		{
			.ino = ino_in,
			.attr = &attr_in,
			.attr_timeout = 1.0,
			.flags = FUSE_MUTATION_NODE_ATTR_VALID |
				 FUSE_MUTATION_NODE_XATTR_UNCHANGED,
		},
		{
			.ino = ino_out,
			.attr = &attr_out,
			.attr_timeout = 1.0,
			.flags = FUSE_MUTATION_NODE_ATTR_VALID |
				 FUSE_MUTATION_NODE_XATTR_CHANGED,
		},
	};

	(void)off_in;
	(void)fi_in;
	(void)off_out;
	(void)fi_out;
	(void)flags;
	fuse_reply_copy_file_range_attrs(req, len, attrs, 2);
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
	state->writes++;
	return (ssize_t)total;
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

static void reset_capture(struct test_state *state)
{
	memset(state->reply, 0, sizeof(state->reply));
	state->reply_len = 0;
}

static void send_init(struct fuse_session *session,
		      enum negotiation_mode negotiation)
{
	struct {
		struct fuse_in_header header;
		struct fuse_init_in init;
	} request = { 0 };
	struct fuse_buf buf;
	uint64_t flags = FUSE_FS_EXTFUSE;

	if (negotiation == NEGOTIATE_INVALID_MUTATION)
		flags |= FUSE_MUTATION_METADATA;
	else if (negotiation != NEGOTIATE_NONE)
		flags |= FUSE_EXTFUSE_COHERENCE_V3;
	if (negotiation == NEGOTIATE_ALL)
		flags |= FUSE_MUTATION_METADATA | FUSE_HAS_NOTIFY_INVAL_XATTR;
	request.header.len = sizeof(request);
	request.header.opcode = FUSE_INIT;
	request.header.unique = 1;
	request.init.major = FUSE_KERNEL_VERSION;
	request.init.minor = FUSE_KERNEL_MINOR_VERSION;
	request.init.flags = FUSE_INIT_EXT;
	request.init.flags2 = (uint32_t)(flags >> 32);
	buf = (struct fuse_buf) {
		.size = sizeof(request),
		.mem = &request,
	};
	fuse_session_process_buf(session, &buf);
}

static void send_write(struct fuse_session *session, uint64_t unique)
{
	struct {
		struct fuse_in_header header;
		struct fuse_write_in write;
		char data[4];
	} request = { 0 };
	struct fuse_buf buf;

	request.header.len = sizeof(request);
	request.header.opcode = FUSE_WRITE;
	request.header.unique = unique;
	request.header.nodeid = TEST_NODEID;
	request.write.size = sizeof(request.data);
	memcpy(request.data, "data", sizeof(request.data));
	buf = (struct fuse_buf) {
		.size = sizeof(request),
		.mem = &request,
	};
	fuse_session_process_buf(session, &buf);
}

static void send_copy(struct fuse_session *session, uint64_t unique)
{
	struct {
		struct fuse_in_header header;
		struct fuse_copy_file_range_in copy;
	} request = { 0 };
	struct fuse_buf buf;

	request.header.len = sizeof(request);
	request.header.opcode = FUSE_COPY_FILE_RANGE_64;
	request.header.unique = unique;
	request.header.nodeid = TEST_NODEID;
	request.copy.nodeid_out = TEST_COPY_NODEID;
	request.copy.len = 32;
	buf = (struct fuse_buf) {
		.size = sizeof(request),
		.mem = &request,
	};
	fuse_session_process_buf(session, &buf);
}

static int check_init_reply(const struct test_state *state,
			    enum negotiation_mode negotiation)
{
	const struct fuse_out_header *header =
		(const struct fuse_out_header *)state->reply;
	const struct fuse_init_out *init =
		(const struct fuse_init_out *)(header + 1);
	uint64_t flags;
	uint64_t expected_v3_flags = 0;
	uint64_t all_v3_flags = FUSE_EXTFUSE_COHERENCE_V3 |
		FUSE_MUTATION_METADATA | FUSE_HAS_NOTIFY_INVAL_XATTR;

	if (negotiation == NEGOTIATE_INVALID_MUTATION) {
		if (state->reply_len != sizeof(*header) ||
		    header->error != -EPROTO) {
			fprintf(stderr, "invalid V3 dependency did not fail INIT\n");
			return 1;
		}
		return 0;
	}
	if (state->reply_len != sizeof(*header) + sizeof(*init) ||
	    header->error) {
		fprintf(stderr, "malformed INIT reply\n");
		return 1;
	}
	flags = init->flags;
	if (flags & FUSE_INIT_EXT)
		flags |= (uint64_t)init->flags2 << 32;
	if (negotiation != NEGOTIATE_NONE) {
		expected_v3_flags = FUSE_EXTFUSE_COHERENCE_V3;
		if (negotiation == NEGOTIATE_ALL)
			expected_v3_flags = all_v3_flags;
		if ((flags & all_v3_flags) != expected_v3_flags ||
		    !(flags & FUSE_FS_EXTFUSE) ||
		    init->extfuse_prog_fd != TEST_PROG_FD) {
			fprintf(stderr, "V3 INIT opt-in was not serialized\n");
			return 1;
		}
	} else if (flags & all_v3_flags) {
		fprintf(stderr, "V3 INIT bits enabled without opt-in\n");
		return 1;
	}
	return 0;
}

static int check_legacy_write(const struct test_state *state, const char *name)
{
	const struct fuse_out_header *header =
		(const struct fuse_out_header *)state->reply;
	const struct fuse_write_out *write =
		(const struct fuse_write_out *)(header + 1);
	size_t expected = sizeof(*header) + sizeof(*write);

	if (state->reply_len != expected || header->error || write->size != 4) {
		fprintf(stderr, "%s: malformed legacy WRITE reply\n", name);
		return 1;
	}
	return 0;
}

static int check_write_trailer(const struct test_state *state)
{
	const struct fuse_out_header *header =
		(const struct fuse_out_header *)state->reply;
	const struct fuse_write_out *write =
		(const struct fuse_write_out *)(header + 1);
	const struct fuse_mutation_out *mutation =
		(const struct fuse_mutation_out *)(write + 1);
	const struct fuse_mutation_node_out *node =
		(const struct fuse_mutation_node_out *)(mutation + 1);
	size_t expected = sizeof(*header) + sizeof(*write) + sizeof(*mutation) +
			  sizeof(*node);

	if (state->reply_len != expected || header->error || write->size != 4 ||
	    mutation->version != FUSE_MUTATION_OUT_VERSION ||
	    mutation->count != 1 || mutation->flags ||
	    node->nodeid != TEST_NODEID || node->reserved ||
	    node->flags != (FUSE_MUTATION_NODE_ATTR_VALID |
			    FUSE_MUTATION_NODE_XATTR_UNCHANGED) ||
	    node->attr.attr.size != 4) {
		fprintf(stderr, "malformed negotiated WRITE trailer\n");
		return 1;
	}
	return 0;
}

static int check_copy_trailer(const struct test_state *state)
{
	const struct fuse_out_header *header =
		(const struct fuse_out_header *)state->reply;
	const struct fuse_copy_file_range_out *copy =
		(const struct fuse_copy_file_range_out *)(header + 1);
	const struct fuse_mutation_out *mutation =
		(const struct fuse_mutation_out *)(copy + 1);
	const struct fuse_mutation_node_out *nodes =
		(const struct fuse_mutation_node_out *)(mutation + 1);
	size_t expected = sizeof(*header) + sizeof(*copy) + sizeof(*mutation) +
			  2 * sizeof(*nodes);

	if (state->reply_len != expected || header->error ||
	    copy->bytes_copied != 32 || mutation->count != 2 ||
	    nodes[0].nodeid != TEST_NODEID ||
	    nodes[1].nodeid != TEST_COPY_NODEID ||
	    !(nodes[1].flags & FUSE_MUTATION_NODE_XATTR_CHANGED)) {
		fprintf(stderr, "malformed negotiated COPY trailer\n");
		return 1;
	}
	return 0;
}

static int check_notify(const struct test_state *state)
{
	const struct fuse_out_header *header =
		(const struct fuse_out_header *)state->reply;
	const struct fuse_notify_inval_xattr_out *notify =
		(const struct fuse_notify_inval_xattr_out *)(header + 1);
	size_t expected = sizeof(*header) + sizeof(*notify);

	if (state->reply_len != expected || header->unique ||
	    header->error != FUSE_NOTIFY_INVAL_XATTR ||
	    notify->ino != TEST_NODEID || notify->flags || notify->padding) {
		fprintf(stderr, "malformed xattr invalidation notification\n");
		return 1;
	}
	return 0;
}

static int run_session(enum negotiation_mode negotiation)
{
	struct fuse_lowlevel_ops ops = {
		.init = test_init,
		.write = test_write,
		.copy_file_range = test_copy_file_range,
	};
	struct fuse_custom_io io = {
		.writev = capture_writev,
		.read = unused_read,
	};
	char argv0[] = "extfuse-v3-test";
	char *argv = argv0;
	struct fuse_args args = FUSE_ARGS_INIT(1, &argv);
	struct test_state state = {
		.negotiation = negotiation,
	};
	struct fuse_session *session = NULL;
	int pipefd[2] = { -1, -1 };
	int failed = 1;

	if (pipe(pipefd)) {
		perror("pipe");
		goto out_args;
	}
	session = fuse_session_new(&args, &ops, sizeof(ops), &state);
	if (!session || fuse_session_custom_io(session, &io, sizeof(io),
					       pipefd[0])) {
		fprintf(stderr, "failed to create custom-I/O session\n");
		goto out_session;
	}
	send_init(session, negotiation);
	if (check_init_reply(&state, negotiation))
		goto out_session;
	if (negotiation == NEGOTIATE_INVALID_MUTATION) {
		failed = 0;
		goto out_session;
	}
	reset_capture(&state);

	state.reply_mode = REPLY_WRITE_VALID;
	send_write(session, 2);
	if (negotiation == NEGOTIATE_ALL ?
		check_write_trailer(&state) :
		check_legacy_write(&state, "unnegotiated-mutation"))
		goto out_session;

	if (negotiation != NEGOTIATE_ALL) {
		if (negotiation == NEGOTIATE_CORE_ONLY &&
		    fuse_lowlevel_notify_inval_xattr(session, TEST_NODEID) !=
			    -ENOSYS) {
			fprintf(stderr, "core-only V3 unexpectedly enabled xattr notify\n");
			goto out_session;
		}
		failed = 0;
		goto out_session;
	}

	reset_capture(&state);
	state.reply_mode = REPLY_WRITE_INVALID_FLAGS;
	send_write(session, 3);
	if (check_legacy_write(&state, "invalid-flags"))
		goto out_session;

	reset_capture(&state);
	state.reply_mode = REPLY_WRITE_INVALID_ATTR;
	send_write(session, 4);
	if (check_legacy_write(&state, "invalid-attr"))
		goto out_session;

	reset_capture(&state);
	state.reply_mode = REPLY_COPY_VALID;
	send_copy(session, 5);
	if (check_copy_trailer(&state))
		goto out_session;

	reset_capture(&state);
	if (fuse_lowlevel_notify_inval_xattr(session, TEST_NODEID) ||
	    check_notify(&state))
		goto out_session;

	failed = 0;

out_session:
	if (session)
		fuse_session_destroy(session);
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
out_args:
	fuse_opt_free_args(&args);
	return failed;
}

int main(void)
{
	int failed = 0;

	failed |= run_session(NEGOTIATE_NONE);
	failed |= run_session(NEGOTIATE_CORE_ONLY);
	failed |= run_session(NEGOTIATE_ALL);
	failed |= run_session(NEGOTIATE_INVALID_MUTATION);
	if (!failed)
		puts("PASS ExtFUSE coherence V3 replies and notification");
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
