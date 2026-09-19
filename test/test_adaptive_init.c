/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define FUSE_USE_VERSION 318
#include "fuse_adaptive.h"
#include "fuse_kernel.h"
#include "fuse_lowlevel.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

_Static_assert(sizeof(struct fuse_uring_runtime_cmd) == 80, "SQE128 command");
_Static_assert(sizeof(struct fuse_uring_cmd_req) == 40, "legacy command ABI");
_Static_assert(sizeof(struct fuse_init_out) == 64, "INIT ABI");
_Static_assert(sizeof(struct fuse_workload_snapshot) == 248, "snapshot ABI");
_Static_assert(FUSE_WORKLOAD_FLAG_WORKER == FUSE_WORKLOAD_WORKER,
	       "worker flag ABI");
_Static_assert(FUSE_WORKLOAD_FLAG_APPEND == FUSE_WORKLOAD_APPEND,
	       "append flag ABI");
_Static_assert(FUSE_WORKLOAD_FLAG_PASSTHROUGH == FUSE_WORKLOAD_PASSTHROUGH,
	       "passthrough flag ABI");
_Static_assert(FUSE_WORKLOAD_FLAG_DAX == FUSE_WORKLOAD_DAX, "DAX flag ABI");

struct init_reply {
	struct fuse_out_header header;
	struct fuse_init_out out;
};

static unsigned int startup_logs;
static char startup_log[256];

static void capture_log(enum fuse_log_level level, const char *fmt, va_list ap)
{
	char text[512];

	vsnprintf(text, sizeof(text), fmt, ap);
	if (strncmp(text, "FUSE_ADAPTIVE ", 14))
		return;
	assert(level == FUSE_LOG_INFO);
	assert(strlen(text) < sizeof(startup_log));
	memcpy(startup_log, text, strlen(text) + 1);
	startup_logs++;
}

static struct fuse_session *session(const char *options, void *userdata)
{
	char *argv[3];
	struct fuse_args args = FUSE_ARGS_INIT(3, argv);
	struct fuse_lowlevel_ops ops = { 0 };
	struct fuse_session *se;

	argv[0] = (char *)"adaptive-test";
	argv[1] = (char *)"-o";
	argv[2] = (char *)options;
	se = fuse_session_new(&args, &ops, sizeof(ops), userdata);
	fuse_opt_free_args(&args);
	return se;
}

static ssize_t capture(int fd, struct iovec *iov, int count, void *userdata)
{
	struct init_reply *reply = userdata;
	size_t size = 0;
	(void)fd;
	assert(count > 0 && iov[0].iov_len == sizeof(reply->header));
	memcpy(&reply->header, iov[0].iov_base, sizeof(reply->header));
	if (count > 1) {
		assert(iov[1].iov_len <= sizeof(reply->out));
		memcpy(&reply->out, iov[1].iov_base, iov[1].iov_len);
	}
	for (int i = 0; i < count; i++)
		size += iov[i].iov_len;
	return size;
}

static ssize_t unused_read(int fd, void *buf, size_t size, void *userdata)
{
	(void)fd;
	(void)buf;
	(void)size;
	(void)userdata;
	return -ENOSYS;
}

static void init_session(const char *options, uint64_t caps, bool adaptive)
{
	struct init_reply reply = { 0 };
	struct fuse_session *se = session(options, &reply);
	struct fuse_custom_io io = { .writev = capture, .read = unused_read };
	struct {
		struct fuse_in_header h;
		struct fuse_init_in in;
	} request = {
		.h = { .len = sizeof(request),
		       .opcode = FUSE_INIT,
		       .unique = 7 },
		.in = { .major = FUSE_KERNEL_VERSION,
			.minor = FUSE_KERNEL_MINOR_VERSION,
			.flags = FUSE_INIT_EXT | (uint32_t)caps,
			.flags2 = caps >> 32 },
	};
	struct fuse_buf buf = { .size = sizeof(request), .mem = &request };
	int fd = open("/dev/null", O_RDWR | O_CLOEXEC);

	assert(se && fd >= 0);
	assert(!fuse_session_custom_io(se, &io, sizeof(io), fd));
	startup_logs = 0;
	fuse_session_process_buf(se, &buf);
	assert(reply.header.unique == 7);
	if (adaptive) {
		assert(reply.header.error == -EOPNOTSUPP);
		assert(fuse_session_exited(se));
		assert(startup_logs == 0);
	} else {
		uint64_t flags = reply.out.flags |
			((uint64_t)reply.out.flags2 << 32);

		assert(!reply.header.error && !fuse_session_exited(se));
		assert(!(flags & (FUSE_HAS_IO_URING_RUNTIME |
				  FUSE_HAS_WORKLOAD_MONITOR)));
		assert(startup_logs == 1);
		assert(!strcmp(
			"FUSE_ADAPTIVE mode=off runtime_qd=0 workload_monitor=0 initial_depth=8 max_depth=8 policy=POLICY_NOT_CONFIGURED\n",
			startup_log));
	}
	fuse_session_destroy(se);
}

static void disabled_apis(const char *options)
{
	struct fuse_uring_runtime_status status;
	struct fuse_workload_result workload;
	uint64_t transaction;
	struct fuse_session *se = session(options, NULL);

	assert(se);
	assert(fuse_session_uring_set_depth(se, 2, &transaction) ==
	       -EOPNOTSUPP);
	assert(fuse_session_uring_get_status(se, &status, NULL, 0) ==
	       -EOPNOTSUPP);
	assert(fuse_session_workload_get(se, &workload) == -EOPNOTSUPP);
	fuse_session_destroy(se);
}

int main(void)
{
	static const char * const enabled[] = {
		"io_uring,io_uring_adaptive",
		"io_uring,io_uring_adaptive=on",
		"io_uring,io_uring_adaptive=off,io_uring_adaptive=on",
	};
	static const char * const disabled[] = {
		"io_uring_q_depth=8",
		"io_uring,io_uring_adaptive=off,io_uring_q_depth=8",
		"io_uring,io_uring_adaptive,io_uring_adaptive=off,io_uring_q_depth=8",
	};
	uint64_t caps[] = {
		0, FUSE_OVER_IO_URING,
		FUSE_OVER_IO_URING | FUSE_HAS_IO_URING_RUNTIME,
		FUSE_OVER_IO_URING | FUSE_HAS_WORKLOAD_MONITOR,
	};

	fuse_set_log_func(capture_log);
	for (size_t i = 0; i < sizeof(disabled) / sizeof(*disabled); i++) {
		disabled_apis(disabled[i]);
		/* No ring creation: INIT deliberately omits FUSE_OVER_IO_URING. */
		init_session(disabled[i], FUSE_HAS_IO_URING_RUNTIME |
			     FUSE_HAS_WORKLOAD_MONITOR, false);
	}
	assert(!session("io_uring_adaptive", NULL));
	assert(!session("io_uring_adaptive=on", NULL));
	assert(!session("io_uring,io_uring_adaptive=invalid", NULL));
	assert(!session("io_uring,io_uring_adaptive=", NULL));
	assert(!session("io_uring,io_uring_adaptive=1", NULL));
	assert(!session("io_uring,io_uring_adaptive=OFF", NULL));
	assert(!session("io_uring_control=/tmp/unused-adaptive-test", NULL));
	assert(!session("io_uring,io_uring_adaptive=off,io_uring_control=/tmp/unused-adaptive-test",
			NULL));
	assert(!session("io_uring,io_uring_adaptive,io_uring_q_depth=0", NULL));
	assert(!session("io_uring,io_uring_adaptive,io_uring_q_depth_max=1",
			NULL));
	assert(!session("io_uring,io_uring_adaptive,io_uring_drain_timeout_ms=0",
			NULL));
	for (size_t i = 0; i < sizeof(enabled) / sizeof(*enabled); i++)
		for (size_t j = 0; j < sizeof(caps) / sizeof(*caps); j++)
			init_session(enabled[i], caps[j], true);
	fuse_set_log_func(NULL);
	puts("PASS adaptive ON/OFF options, INIT, startup log and disabled APIs");
	return 0;
}
