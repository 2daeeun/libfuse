#define FUSE_USE_VERSION 318

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <fuse_kernel.h>
#include <fuse_lowlevel.h>

static ssize_t discard_writev(int fd, struct iovec *iov, int count,
			      void *userdata)
{
	ssize_t total = 0;
	int index;

	(void)fd;
	(void)userdata;
	for (index = 0; index < count; index++)
		total += (ssize_t)iov[index].iov_len;
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

static void test_getattr(fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi)
{
	(void)ino;
	(void)fi;
	fuse_reply_err(req, ENOENT);
}

static int process_init(struct fuse_session *session)
{
	struct {
		struct fuse_in_header header;
		struct fuse_init_in init;
	} request = { 0 };
	struct fuse_buf buffer;

	request.header.len = sizeof(request);
	request.header.opcode = FUSE_INIT;
	request.header.unique = 1;
	request.init.major = FUSE_KERNEL_VERSION;
	request.init.minor = FUSE_KERNEL_MINOR_VERSION;
	buffer = (struct fuse_buf) {
		.size = sizeof(request),
		.mem = &request,
	};
	fuse_session_process_buf(session, &buffer);
	return 0;
}

static void process_getattr(struct fuse_session *session)
{
	struct {
		struct fuse_in_header header;
		struct fuse_getattr_in getattr;
	} request = { 0 };
	struct fuse_buf buffer;

	request.header.len = sizeof(request);
	request.header.opcode = FUSE_GETATTR;
	request.header.unique = 2;
	request.header.nodeid = FUSE_ROOT_ID;
	buffer = (struct fuse_buf) {
		.size = sizeof(request),
		.mem = &request,
	};
	fuse_session_process_buf(session, &buffer);
}

int main(void)
{
	struct fuse_lowlevel_ops ops = {
		.getattr = test_getattr,
	};
	struct fuse_custom_io io = {
		.writev = discard_writev,
		.read = unused_read,
	};
	char *argv[] = { (char *)"native-request-counter-test" };
	struct fuse_args args = FUSE_ARGS_INIT(1, argv);
	struct fuse_session *session = NULL;
	uint64_t value;
	int pipefd[2] = { -1, -1 };
	int result = 1;

	if (pipe(pipefd) || !(session = fuse_session_new(
			&args, &ops, sizeof(ops), NULL)) ||
	    fuse_session_custom_io(session, &io, sizeof(io), pipefd[0]) ||
	    process_init(session))
		goto out;

	if (fuse_session_native_request_counter_start(session) ||
	    fuse_session_native_request_counter_start(session) != -EBUSY ||
	    fuse_session_native_request_counter_read(
		    session, FUSE_GETATTR, &value) != -EBUSY)
		goto out;
	process_getattr(session);
	if (fuse_session_native_request_counter_stop(session) ||
	    fuse_session_native_request_counter_read(
		    session, FUSE_GETATTR, &value) ||
	    value != 1)
		goto out;
	if (fuse_session_native_request_counter_read(
		    session, FUSE_INIT, &value) || value != 0 ||
	    fuse_session_native_request_counter_read(session, 64, &value) !=
		    -EINVAL ||
	    fuse_session_native_request_counter_stop(session) != -EINVAL)
		goto out;

	if (fuse_session_native_request_counter_start(session) ||
	    fuse_session_native_request_counter_stop(session) ||
	    fuse_session_native_request_counter_read(
		    session, FUSE_GETATTR, &value) ||
	    value != 0)
		goto out;

	result = 0;
	puts("NATIVE_REQUEST_COUNTER_TEST result=PASS");
out:
	if (session)
		fuse_session_destroy(session);
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	fuse_opt_free_args(&args);
	return result;
}
