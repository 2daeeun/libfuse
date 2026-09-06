/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 318

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <fuse_kernel.h>
#include <fuse_lowlevel.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static unsigned int affinity_count;
static int affinity_error;

static int test_sched_getaffinity(pid_t pid, size_t size, cpu_set_t *mask)
{
	unsigned int i;

	assert(pid == 0 && size == sizeof(*mask));
	if (affinity_error) {
		errno = affinity_error;
		return -1;
	}
	CPU_ZERO(mask);
	for (i = 0; i < affinity_count; i++)
		CPU_SET(i, mask);
	return 0;
}

/* Replace only the OS query; exercise the production policy and options. */
#define sched_getaffinity test_sched_getaffinity
#include "../example/extfuse/background_limits.h"
#undef sched_getaffinity

struct test_state {
	struct fuse_conn_info_opts *opts;
	unsigned int allowed_cpus;
	unsigned int max_requested;
	unsigned int congestion_requested;
	uint64_t want;
	struct fuse_out_header out;
	struct fuse_init_out init;
};

static void test_init(void *userdata, struct fuse_conn_info *conn)
{
	struct test_state *state = userdata;

	perf_background_apply(conn, state->opts, state->allowed_cpus);
	state->max_requested = conn->max_background;
	state->congestion_requested = conn->congestion_threshold;
	conn->want_ext = state->want;
	if (state->want & FUSE_CAP_EXTFUSE)
		conn->extfuse_prog_fd = 123;
	if (state->want & FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH)
		conn->max_backing_stack_depth = FUSE_BACKING_STACKED_UNDER;
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
	if (!state->out.error) {
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

static void run_case(unsigned int cpus, const char *options, uint64_t want,
		     unsigned int max_requested, unsigned int congestion_requested,
		     unsigned int max_wire, unsigned int congestion_wire)
{
	struct test_state state = { .allowed_cpus = cpus, .want = want };
	struct fuse_lowlevel_ops ops = { .init = test_init };
	struct fuse_custom_io io = {
		.writev = capture_writev, .read = unused_read,
	};
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_session *session;
	struct {
		struct fuse_in_header in;
		struct fuse_init_in init;
	} init = { 0 };
	struct fuse_buf buf;
	const uint64_t wire = FUSE_FS_EXTFUSE | FUSE_WRITEBACK_CACHE |
		FUSE_EXTFUSE_WBCACHE_PASSTHROUGH;
	int pipefd[2];

	assert(fuse_opt_add_arg(&args, "extfuse-background-limits-test") == 0);
	if (options) {
		assert(fuse_opt_add_arg(&args, "-o") == 0);
		assert(fuse_opt_add_arg(&args, options) == 0);
	}
	state.opts = fuse_parse_conn_info_opts(&args);
	assert(state.opts);
	assert(pipe(pipefd) == 0);
	session = fuse_session_new(&args, &ops, sizeof(ops), &state);
	assert(session);
	assert(fuse_session_custom_io(session, &io, sizeof(io), pipefd[0]) == 0);
	init.in.len = sizeof(init);
	init.in.opcode = FUSE_INIT;
	init.in.unique = 1;
	init.init.major = FUSE_KERNEL_VERSION;
	init.init.minor = FUSE_KERNEL_MINOR_VERSION;
	init.init.flags = FUSE_INIT_EXT | (uint32_t)wire;
	init.init.flags2 = wire >> 32;
	buf = (struct fuse_buf) { .mem = &init, .size = sizeof(init) };
	fuse_session_process_buf(session, &buf);
	assert(state.out.unique == 1 && state.out.error == 0);
	assert(state.max_requested == max_requested);
	assert(state.congestion_requested == congestion_requested);
	assert(state.init.max_background == max_wire);
	assert(state.init.congestion_threshold == congestion_wire);
	fuse_session_destroy(session);
	close(pipefd[0]);
	close(pipefd[1]);
	free(state.opts);
	fuse_opt_free_args(&args);
}

int main(void)
{
	const uint64_t modes[] = {
		0, FUSE_CAP_EXTFUSE,
		FUSE_CAP_EXTFUSE | FUSE_CAP_WRITEBACK_CACHE |
			FUSE_CAP_EXTFUSE_WBCACHE_PASSTHROUGH,
	};
	size_t i;

	affinity_count = 32;
	assert(perf_background_allowed_cpus() == 32);
	affinity_error = EINVAL;
	assert(perf_background_allowed_cpus() == 1);
	affinity_error = 0;
	affinity_count = 0;
	assert(perf_background_allowed_cpus() == 1);
	assert(perf_background_default(0) == 12);
	assert(perf_background_default(1) == 12);
	assert(perf_background_default(6) == 12);
	assert(perf_background_default(7) == 14);
	assert(perf_background_default(128) == 256);
	assert(perf_background_default(UINT_MAX) == 256);

	/* Identical defaults and override semantics for off, MDOpt and WBCache. */
	for (i = 0; i < ARRAY_SIZE(modes); i++) {
		run_case(1, NULL, modes[i], 12, 0, 12, 9);
		run_case(16, NULL, modes[i], 32, 0, 32, 24);
		run_case(32, NULL, modes[i], 64, 0, 64, 48);
		run_case(256, NULL, modes[i], 256, 0, 256, 192);
		run_case(32, "max_background=4", modes[i], 4, 0, 4, 3);
		run_case(32, "max_background=0", modes[i], 0, 0, 0, 0);
		run_case(32, "max_background=64,congestion_threshold=40",
			 modes[i], 64, 40, 64, 40);
		run_case(32, "max_background=4,congestion_threshold=40",
			 modes[i], 4, 40, 4, 4);
		run_case(32, "max_background=4,congestion_threshold=0",
			 modes[i], 4, 0, 4, 3);
		run_case(32, "max_background=70000", modes[i],
			 70000, 0, 65535, 49151);
		run_case(32, "max_background=4,max_background=20",
			 modes[i], 20, 0, 20, 15);
	}
	puts("EXTFUSE_BACKGROUND_LIMITS result=PASS wire_cases=33 affinity_cases=3");
	return 0;
}
