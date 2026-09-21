// SPDX-License-Identifier: LGPL-2.1-or-later
/* Production monitor/control socket with synthetic kernel telemetry and QD
 * backend. No FUSE mount, io_uring creation, or kernel modification is needed.
 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 317
#include <assert.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sys/ioctl.h>

static int mock_ioctl(int fd, unsigned long request, ...);
#define ioctl mock_ioctl
#include "../lib/fuse_adaptive.c"
#undef ioctl

static atomic_uint startup_logs;
static atomic_uint policy_startup_logs;

void fuse_log(enum fuse_log_level level, const char *fmt, ...)
{
	char text[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);
	assert(level == FUSE_LOG_INFO);
	if (!strncmp(text, "FUSE_QD_POLICY ", 15))
		return;
	if (strstr(text, "policy=thinkpad-c6")) {
		assert(!strcmp(
			"FUSE_ADAPTIVE mode=on runtime_qd=1 workload_monitor=1 initial_depth=32 max_depth=64 policy=thinkpad-c6\n",
			text));
		atomic_fetch_add(&policy_startup_logs, 1);
		return;
	}
	assert(!strcmp(
		"FUSE_ADAPTIVE mode=on runtime_qd=1 workload_monitor=1 initial_depth=2 max_depth=64 policy=POLICY_NOT_CONFIGURED\n",
		text));
	atomic_fetch_add(&startup_logs, 1);
}

static struct {
	pthread_mutex_t lock;
	unsigned int config_calls, snapshot_calls, detail_calls, config_eagain;
	int snapshot_errno, config_errno, status_error, status_errno;
	uint64_t generation, window, end_ns, thresholds[3];
	uint64_t transaction;
	unsigned int requests, depth, target;
	bool busy, detail_mode;
} backend = { .lock = PTHREAD_MUTEX_INITIALIZER, .depth = 2, .target = 2 };

static int mock_ioctl(int fd, unsigned long request, ...)
{
	void *arg;
	va_list ap;
	int error = 0;

	assert(fd == 57);
	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	pthread_mutex_lock(&backend.lock);
	if (request == FUSE_DEV_IOC_MONITOR_CONFIG) {
		struct fuse_workload_config *config = arg;

		assert(config->version == FUSE_WORKLOAD_VERSION);
		assert(config->flags == (FUSE_WORKLOAD_ENABLE |
			(backend.detail_mode ? FUSE_WORKLOAD_DETAIL : 0)));
		backend.config_calls++;
		if (backend.config_eagain) {
			backend.config_eagain--;
			error = EAGAIN;
		} else if (backend.config_errno) {
			error = backend.config_errno;
		} else {
			memcpy(backend.thresholds, config->thresholds,
			       sizeof(backend.thresholds));
			backend.generation++;
			backend.window = 0;
			backend.end_ns = UINT64_C(1000000000);
		}
	} else {
		struct fuse_workload_snapshot *snapshot = arg;
		struct fuse_workload_op_stats *op;
		unsigned int bucket = 0;

		assert(request == (backend.detail_mode ?
			FUSE_DEV_IOC_MONITOR_DETAIL : FUSE_DEV_IOC_MONITOR_SNAPSHOT));
		backend.snapshot_calls++;
		if (backend.detail_mode)
			backend.detail_calls++;
		error = backend.snapshot_errno;
		if (!error) {
			*snapshot = (struct fuse_workload_snapshot) {
				.version = FUSE_WORKLOAD_VERSION,
				.generation = backend.generation,
				.window_id = ++backend.window,
				.start_ns = backend.end_ns,
				.end_ns = backend.end_ns + UINT64_C(10000000),
			};
			backend.end_ns = snapshot->end_ns;
			if (backend.detail_mode) {
				struct fuse_workload_detail *detail = arg;

				/* One sequential stream alternates 1 MiB reads and
				 * writes: union topology is 1T/1F, legacy is MIXED.
				 */
				detail->files = detail->requesters = 1;
				detail->seq_pairs = detail->seq_contiguous = 31;
				for (unsigned int rw = 0; rw < 2; rw++) {
					op = &snapshot->op[rw];
					op->count[3] = 16;
					op->bytes[3] = 16 * UINT64_C(1048576);
					op->min_size = op->max_size = 1048576;
					/* Per-operation offsets skip the other op. */
					op->seq_pairs = 15;
					op->files = op->requesters = 1;
				}
			} else {
				while (bucket < 3 &&
				       backend.thresholds[bucket] <= 16384)
					bucket++;
				op = &snapshot->op[1];
				op->count[bucket] = 16;
				op->bytes[bucket] = 16 * 16384;
				op->min_size = op->max_size = 16384;
				op->seq_pairs = 16;
				op->files = 1;
				op->requesters = 2;
			}
		}
	}
	pthread_mutex_unlock(&backend.lock);
	if (error) {
		errno = error;
		return -1;
	}
	return 0;
}

int fuse_uring_request_qd(struct fuse_session *se, uint32_t depth,
			  uint64_t *transaction)
{
	int rc = 0;

	assert(se->uring.runtime_qd);
	pthread_mutex_lock(&backend.lock);
	if (!depth || depth > 64)
		rc = -EINVAL;
	else if (backend.busy)
		rc = -EBUSY;
	else {
		backend.requests++;
		backend.busy = true;
		backend.target = depth;
		*transaction = ++backend.transaction;
	}
	pthread_mutex_unlock(&backend.lock);
	return rc;
}

int fuse_uring_runtime_status(struct fuse_session *se,
	struct fuse_uring_runtime_status *status,
	struct fuse_uring_runtime_queue_status *queues, size_t capacity)
{
	assert(se->uring.runtime_qd);
	if (capacity && capacity < 2)
		return -ENOSPC;
	pthread_mutex_lock(&backend.lock);
	if (backend.status_errno) {
		int rc = -backend.status_errno;

		pthread_mutex_unlock(&backend.lock);
		return rc;
	}
	*status = (struct fuse_uring_runtime_status) {
		.transaction = backend.transaction, .max_depth = 64,
		.nr_queues = 2, .busy = backend.busy, .error = backend.status_error,
	};
	if (capacity) {
		for (unsigned int i = 0; i < 2; i++)
			queues[i] = (struct fuse_uring_runtime_queue_status) {
				.qid = i, .current_depth = backend.depth,
				.target_depth = backend.target,
				.phase = backend.busy ? FUSE_URING_RUNTIME_DRAINING :
					FUSE_URING_RUNTIME_COMPLETE,
				.generation = 1,
				.payload_bytes = (uint64_t)backend.depth * 131072,
			};
	}
	pthread_mutex_unlock(&backend.lock);
	return 2;
}

static void init_session(struct fuse_session *se, char *path)
{
	memset(se, 0, sizeof(*se));
	se->fd = 57;
	se->uring.runtime_qd = true;
	se->uring.q_depth = 2;
	se->uring.max_depth = 64;
	se->uring.control_path = path;
	assert(pthread_mutex_init(&se->uring.runtime_lock, NULL) == 0);
}

static int connect_control(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	assert(fd >= 0);
	assert(strlen(path) < sizeof(addr.sun_path));
	memcpy(addr.sun_path, path, strlen(path) + 1);
	assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	return fd;
}

static void exchange(const char *path, const void *request, size_t size,
		     char reply[4096])
{
	int fd = connect_control(path);
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	ssize_t len;

	assert(send(fd, request, size, MSG_NOSIGNAL) == (ssize_t)size);
	assert(poll(&pfd, 1, 2000) == 1);
	len = recv(fd, reply, 4095, 0);
	assert(len > 0);
	reply[len] = 0;
	close(fd);
}

static void has_error(const char *reply, int error)
{
	char text[64];

	snprintf(text, sizeof(text), "\"error\":%d", error);
	assert(strstr(reply, text));
}

static struct fuse_workload_result wait_result(struct fuse_session *se,
					       int error, bool stable,
					       unsigned int profile)
{
	uint64_t deadline = adaptive_now() + UINT64_C(2000000000);
	struct fuse_workload_result result;

	while (adaptive_now() < deadline) {
		int rc = fuse_session_workload_get(se, &result);

		if (rc == error && result.stable == stable &&
		    (error || result.profile == profile))
			return result;
		usleep(1000);
	}
	fprintf(stderr, "monitor result timeout: error=%d stable=%u profile=%u\n",
		error, stable, profile);
	abort();
}

static void test_disabled_and_failed_start(void)
{
	struct fuse_session se;
	unsigned int config_calls;

	init_session(&se, NULL);
	se.uring.runtime_qd = false;
	pthread_mutex_lock(&backend.lock);
	config_calls = backend.config_calls;
	pthread_mutex_unlock(&backend.lock);
	assert(fuse_adaptive_start(&se) == 0);
	assert(!se.uring.adaptive);
	pthread_mutex_lock(&backend.lock);
	assert(backend.config_calls == config_calls);
	backend.config_errno = ENOMEM;
	pthread_mutex_unlock(&backend.lock);
	fuse_adaptive_stop(&se);
	pthread_mutex_destroy(&se.uring.runtime_lock);

	init_session(&se, NULL);
	assert(fuse_adaptive_start(&se) == 0);
	(void)wait_result(&se, -ENOMEM, false, 0);
	assert(atomic_load(&startup_logs) == 0);
	fuse_adaptive_stop(&se);
	pthread_mutex_destroy(&se.uring.runtime_lock);
	pthread_mutex_lock(&backend.lock);
	backend.config_errno = 0;
	pthread_mutex_unlock(&backend.lock);
}

/* Inspect publication without socket traffic that could wake poll itself. */
static void wait_settings(struct fuse_session *se, uint32_t window_ms)
{
	uint64_t deadline = adaptive_now() + UINT64_C(2000000000);

	while (adaptive_now() < deadline) {
		struct fuse_adaptive *a;
		bool applied;

		pthread_mutex_lock(&se->uring.runtime_lock);
		a = se->uring.adaptive;
		assert(a);
		pthread_mutex_lock(&a->lock);
		applied = a->configured && !a->dirty && !a->error &&
			a->detector.settings.window_ms == window_ms;
		pthread_mutex_unlock(&a->lock);
		pthread_mutex_unlock(&se->uring.runtime_lock);
		if (applied)
			return;
		usleep(1000);
	}
	fprintf(stderr, "configuration publication timeout: window_ms=%u\n",
		window_ms);
	abort();
}

static void test_config_failure(struct fuse_session *se, const char *path,
			       struct fuse_adaptive_control_request *req)
{
	struct fuse_workload_result result;
	unsigned int snapshots;
	uint64_t until;
	char reply[4096];

	/* The kernel must retain the previous buckets when CONFIG fails. */
	pthread_mutex_lock(&backend.lock);
	backend.config_errno = ENOMEM;
	assert(backend.thresholds[0] == 8192);
	pthread_mutex_unlock(&backend.lock);
	req->settings.thresholds[0] = 32768;
	assert(fuse_session_workload_configure(se, &req->settings) == 0);
	result = wait_result(se, -ENOMEM, false, 0);
	assert(result.workload == FUSE_WORKLOAD_UNKNOWN);
	pthread_mutex_lock(&backend.lock);
	snapshots = backend.snapshot_calls;
	assert(backend.thresholds[0] == 8192);
	pthread_mutex_unlock(&backend.lock);

	/* Exercise multiple collector deadlines, with a live socket each time. */
	until = adaptive_now() + (uint64_t)req->settings.window_ms * 5000000;
	req->operation = FUSE_ADAPTIVE_GET_CONFIG;
	do {
		exchange(path, req, sizeof(*req), reply);
		has_error(reply, -ENOMEM);
		assert(strstr(reply, "\"pending\":false"));
		assert(fuse_session_workload_get(se, &result) == -ENOMEM);
		assert(result.workload == FUSE_WORKLOAD_UNKNOWN && !result.stable);
		pthread_mutex_lock(&backend.lock);
		assert(backend.snapshot_calls == snapshots);
		pthread_mutex_unlock(&backend.lock);
	} while (adaptive_now() < until);

	pthread_mutex_lock(&backend.lock);
	backend.config_errno = 0;
	pthread_mutex_unlock(&backend.lock);
	assert(fuse_session_workload_configure(se, &req->settings) == 0);
	wait_settings(se, req->settings.window_ms);
	result = wait_result(se, 0, true, 0);
	assert(result.workload == FUSE_WORKLOAD_RW_NT_1F);
	pthread_mutex_lock(&backend.lock);
	assert(backend.snapshot_calls > snapshots);
	assert(backend.thresholds[0] == 32768);
	pthread_mutex_unlock(&backend.lock);
}

static void test_protocol_and_monitor(char *path)
{
	struct fuse_adaptive_control_request req = {
		.version = FUSE_ADAPTIVE_CONTROL_VERSION,
		.operation = FUSE_ADAPTIVE_CONFIGURE,
	};
	struct fuse_workload_result result;
	struct fuse_session se;
	struct stat st;
	uint64_t generation;
	char reply[4096];
	int idle;

	init_session(&se, path);
	pthread_mutex_lock(&backend.lock);
	backend.config_eagain = 2;
	pthread_mutex_unlock(&backend.lock);
	assert(fuse_adaptive_start(&se) == 0);
	assert(lstat(path, &st) == 0 && S_ISSOCK(st.st_mode));
	assert((st.st_mode & 0777) == 0600);
	fuse_workload_defaults(&req.settings);
	req.settings.window_ms = 10;
	req.settings.stable_ms = 30;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, 0);
	assert(strstr(reply, "\"pending\":true"));
	result = wait_result(&se, 0, true, 0);
	assert(result.workload == FUSE_WORKLOAD_RW_NT_1F);
	assert(result.min_size == 16384 && result.max_size == 16384);
	assert(!result.policy_configured);
	generation = result.generation;
	pthread_mutex_lock(&backend.lock);
	assert(backend.config_calls >= 3);
	assert(backend.snapshot_calls >= 4);
	assert(backend.requests == 0);
	pthread_mutex_unlock(&backend.lock);
	assert(atomic_load(&startup_logs) == 1);

	req.operation = FUSE_ADAPTIVE_WORKLOAD;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, 0);
	assert(strstr(reply, "\"source\":\"fuse_iter_requested\""));
	assert(strstr(reply, "POLICY_NOT_CONFIGURED"));
	assert(strstr(reply, "RW_NT_1F"));
	req.operation = FUSE_ADAPTIVE_GET_CONFIG;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, 0);
	assert(strstr(reply, "\"window_ms\":10"));
	assert(strstr(reply, "\"stable_ms\":30"));
	assert(strstr(reply, "\"pending\":false"));
	req.operation = FUSE_ADAPTIVE_STATUS;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, 0);
	assert(strstr(reply, "\"max_depth\":64"));
	assert(strstr(reply, "\"qid\":1"));
	req.operation = FUSE_ADAPTIVE_SET_DEPTH;
	req.depth = 8;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, 0);
	assert(strstr(reply, "\"transaction\":1"));
	req.depth = 16;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, -EBUSY);
	req.depth = 0;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, -EINVAL);

	req.operation = FUSE_ADAPTIVE_STATUS;
	req.version++;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, -EINVAL);
	req.version--;
	req.reserved = 1;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, -EINVAL);
	req.reserved = 0;
	exchange(path, &req, sizeof(req) - 1, reply);
	has_error(reply, -EINVAL);
	req.operation = UINT32_MAX;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, -EINVAL);

	/* Failed snapshots immediately invalidate the previous stable state. */
	pthread_mutex_lock(&backend.lock);
	backend.snapshot_errno = EIO;
	pthread_mutex_unlock(&backend.lock);
	result = wait_result(&se, -EIO, false, 0);
	assert(result.workload == FUSE_WORKLOAD_UNKNOWN);
	pthread_mutex_lock(&backend.lock);
	backend.snapshot_errno = EAGAIN;
	pthread_mutex_unlock(&backend.lock);
	(void)wait_result(&se, -EAGAIN, false, 0);
	pthread_mutex_lock(&backend.lock);
	backend.snapshot_errno = 0;
	pthread_mutex_unlock(&backend.lock);
	(void)wait_result(&se, 0, true, 0);

	/* Reconfiguration resets stable results even while INIT is not ready. */
	pthread_mutex_lock(&backend.lock);
	backend.config_eagain = 1000;
	pthread_mutex_unlock(&backend.lock);
	req.settings.thresholds[0] = 8192;
	assert(fuse_session_workload_configure(&se, &req.settings) == 0);
	(void)fuse_session_workload_get(&se, &result);
	assert(!result.stable && result.workload == FUSE_WORKLOAD_UNKNOWN);
	req.operation = FUSE_ADAPTIVE_STATUS;
	exchange(path, &req, sizeof(req), reply); /* Wake the sleeping monitor. */
	(void)wait_result(&se, -EAGAIN, false, 0);
	req.operation = FUSE_ADAPTIVE_GET_CONFIG;
	exchange(path, &req, sizeof(req), reply);
	has_error(reply, -EAGAIN);
	assert(strstr(reply, "\"pending\":true"));
	assert(strstr(reply, "8192"));
	pthread_mutex_lock(&backend.lock);
	backend.config_eagain = 0;
	pthread_mutex_unlock(&backend.lock);
	result = wait_result(&se, 0, true, 1);
	assert(result.generation > generation);
	pthread_mutex_lock(&backend.lock);
	assert(backend.requests == 1); /* No automatic QD policy. */
	pthread_mutex_unlock(&backend.lock);

	/* Public configuration must wake a monitor sleeping for a long window. */
	req.settings.window_ms = 30000;
	req.settings.stable_ms = 30000;
	assert(fuse_session_workload_configure(&se, &req.settings) == 0);
	wait_settings(&se, 30000);
	req.settings.window_ms = 10;
	req.settings.stable_ms = 30;
	assert(fuse_session_workload_configure(&se, &req.settings) == 0);
	wait_settings(&se, 10);
	(void)wait_result(&se, 0, true, 1);
	test_config_failure(&se, path, &req);

	/* A client which sends nothing must not prevent bounded shutdown. */
	idle = connect_control(path);
	generation = adaptive_now();
	fuse_adaptive_stop(&se);
	assert(adaptive_now() - generation < UINT64_C(2000000000));
	/* Successful and failed CONFIG retries do not repeat startup evidence. */
	assert(atomic_load(&startup_logs) == 1);
	close(idle);
	assert(lstat(path, &st) == -1 && errno == ENOENT);
	assert(fuse_session_workload_get(&se, &result) == -EOPNOTSUPP);
	fuse_adaptive_stop(&se);
	pthread_mutex_destroy(&se.uring.runtime_lock);
}

static void test_path_ownership(char *path)
{
	struct fuse_session se;
	struct stat before, after;
	char moved[256];
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	assert(fd >= 0);
	assert(write(fd, "keep", 4) == 4);
	assert(fstat(fd, &before) == 0);
	close(fd);
	init_session(&se, path);
	assert(fuse_adaptive_start(&se) == -EADDRINUSE);
	assert(lstat(path, &after) == 0 && after.st_ino == before.st_ino);
	assert(after.st_size == 4);
	fuse_adaptive_stop(&se);
	assert(unlink(path) == 0);
	pthread_mutex_destroy(&se.uring.runtime_lock);

	init_session(&se, path);
	assert(fuse_adaptive_start(&se) == 0);
	snprintf(moved, sizeof(moved), "%s.old", path);
	assert(rename(path, moved) == 0);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	assert(fd >= 0);
	assert(fstat(fd, &before) == 0);
	close(fd);
	fuse_adaptive_stop(&se);
	assert(lstat(path, &after) == 0 && after.st_ino == before.st_ino);
	assert(S_ISREG(after.st_mode));
	assert(unlink(path) == 0);
	assert(unlink(moved) == 0);
	pthread_mutex_destroy(&se.uring.runtime_lock);
}

/* Exercise automatic submission through the production controller and QD API
 * backend, using synthetic monotonic observation windows instead of sleeping.
 */
static void test_policy_controller(const char *policy_file)
{
	struct fuse_session se;
	struct fuse_adaptive a = { 0 };
	struct fuse_workload_detail detail = { 0 };
	struct fuse_workload_snapshot *s = &detail.snapshot;
	struct fuse_qd_policy_config *config = calloc(1, sizeof(*config));
	unsigned int baseline;

	assert(config && !fuse_qd_policy_load(policy_file, config));
	init_session(&se, NULL);
	se.uring.policy_name = (char *)"dell-c2";
	se.uring.policy_config = config;
	se.uring.adaptive = &a;
	a.se = &se;
	a.settings = config->settings;
	a.configured = true;
	assert(!pthread_mutex_init(&a.lock, NULL));
	adaptive_reset_policy(&a);
	backend.busy = false;
	backend.status_error = 0;
	backend.depth = backend.target = 2;
	baseline = backend.requests;
	s->version = FUSE_WORKLOAD_VERSION;
	s->generation = 1;
	detail.files = detail.requesters = 32;
	detail.seq_pairs = detail.seq_contiguous = 68;
	for (unsigned int phase = 0; phase < 2; phase++) {
		struct fuse_workload_op_stats *op;

		memset(s->op, 0, sizeof(s->op));
		op = &s->op[phase ? 0 : 1];
		op->count[2] = 100;
		op->bytes[2] = 100 * UINT64_C(131072);
		op->min_size = op->max_size = 131072;
		op->seq_pairs = op->seq_contiguous = 68;
		op->files = op->requesters = 2;
		for (unsigned int i = 0; i <= 10; i++) {
			s->window_id++;
			s->start_ns = s->end_ns;
			s->end_ns += UINT64_C(1000000000);
			assert(!fuse_qd_policy_update(&a.policy, &detail,
						      &a.policy_result));
			if (i == 10) {
				assert(a.policy_result.stable);
				backend.status_errno = ENOTSUP;
				adaptive_apply_policy(&a); /* Pool creation pending. */
				assert(!a.policy_error);
				backend.status_errno = EAGAIN;
				adaptive_apply_policy(&a); /* Queue readiness pending. */
				assert(!a.policy_error);
				assert(backend.requests == baseline + phase);
				backend.status_errno = 0;
				a.dirty = true;
				adaptive_apply_policy(&a);
				assert(backend.requests == baseline + phase);
				a.dirty = false;
			}
			adaptive_apply_policy(&a);
			assert(backend.requests == baseline + phase + (i == 10));
		}
		assert(backend.target == (phase ? 2 : 32));
		adaptive_apply_policy(&a); /* Busy: do not enqueue again. */
		assert(backend.requests == baseline + phase + 1);
		backend.busy = false;
		if (!phase) {
			backend.depth = backend.target;
			adaptive_apply_policy(&a); /* All queues already match. */
			assert(backend.requests == baseline + 1);
		}
	}
	backend.status_error = -ENOMEM;
	adaptive_apply_policy(&a);
	assert(a.policy_error == -ENOMEM);
	adaptive_apply_policy(&a);
	assert(backend.requests == baseline + 2); /* No failing retry loop. */
	adaptive_reset_policy(&a);
	assert(!a.policy_result.stable && !a.policy_error);
	adaptive_apply_policy(&a);
	assert(backend.requests == baseline + 2);
	se.uring.adaptive = NULL;
	a.policy_result.stable = 1;
	adaptive_apply_policy(&a); /* Concurrent detach/stop wins. */
	assert(backend.requests == baseline + 2);
	pthread_mutex_destroy(&a.lock);
	pthread_mutex_destroy(&se.uring.runtime_lock);
	free(config);
}

/* Run the production collector thread, policy matcher, controller and socket
 * together. Only telemetry and QD execution are mocked; no mount is created.
 */
static void test_policy_monitor(char *path, const char *policy_file)
{
	struct fuse_adaptive_control_request req = {
		.version = FUSE_ADAPTIVE_CONTROL_VERSION,
		.operation = FUSE_ADAPTIVE_WORKLOAD,
	};
	struct fuse_qd_policy_config *config = calloc(1, sizeof(*config));
	struct fuse_workload_result result;
	struct fuse_session se;
	unsigned int baseline, completed_snapshots;
	uint64_t deadline;
	char reply[4096];
	bool stable = false, sampled = false;

	assert(config && !fuse_qd_policy_load(policy_file, config));
	/* Shorten only this in-memory fixture; retain the file's mixed rule. */
	config->settings.window_ms = 10;
	config->settings.stable_ms = 30;
	init_session(&se, path);
	se.uring.q_depth = 32;
	se.uring.policy_name = (char *)"thinkpad-c6";
	se.uring.policy_config = config;
	pthread_mutex_lock(&backend.lock);
	backend.busy = false;
	backend.status_error = 0;
	backend.depth = backend.target = 32;
	backend.detail_mode = true;
	baseline = backend.requests;
	pthread_mutex_unlock(&backend.lock);
	assert(!fuse_adaptive_start(&se));
	/* The policy file owns settings; APIs may reset but cannot override them. */
	req.settings = config->settings;
	req.settings.window_ms++;
	assert(fuse_session_workload_configure(&se, &req.settings) == -EPERM);
	assert(!fuse_session_workload_configure(&se, &config->settings));
	deadline = adaptive_now() + UINT64_C(2000000000);
	while (adaptive_now() < deadline) {
		exchange(path, &req, sizeof(req), reply);
		has_error(reply, 0);
		if (strstr(reply, "\"policy_stable\":1")) {
			stable = true;
			break;
		}
		usleep(1000);
	}
	assert(stable);
	assert(strstr(reply, "\"policy\":\"thinkpad-c6\""));
	assert(strstr(reply, "\"policy_rule\":\"seqrw50-1m-1t-1f\""));
	assert(strstr(reply, "\"policy_target_depth\":2"));
	assert(strstr(reply, "\"policy_error\":0"));
	assert(strstr(reply, "\"workload\":\"MIXED\""));
	assert(strstr(reply, "\"stable\":0"));
	assert(!fuse_session_workload_get(&se, &result));
	assert(result.workload == FUSE_WORKLOAD_MIXED && !result.stable);
	assert(result.policy_configured);
	assert(atomic_load(&policy_startup_logs) == 1);
	pthread_mutex_lock(&backend.lock);
	assert(backend.detail_calls >= 4);
	assert(backend.requests == baseline + 1);
	assert(backend.busy && backend.target == 2);
	backend.depth = backend.target;
	backend.busy = false;
	completed_snapshots = backend.detail_calls;
	pthread_mutex_unlock(&backend.lock);
	deadline = adaptive_now() + UINT64_C(2000000000);
	while (adaptive_now() < deadline) {
		pthread_mutex_lock(&backend.lock);
		sampled = backend.detail_calls > completed_snapshots;
		assert(backend.requests == baseline + 1);
		pthread_mutex_unlock(&backend.lock);
		if (sampled)
			break;
		usleep(1000);
	}
	assert(sampled);
	fuse_adaptive_stop(&se);
	pthread_mutex_lock(&backend.lock);
	assert(backend.requests == baseline + 1);
	backend.detail_mode = false;
	pthread_mutex_unlock(&backend.lock);
	pthread_mutex_destroy(&se.uring.runtime_lock);
	free(config);
}

int main(int argc, char **argv)
{
	char directory[] = "/tmp/fuse-adaptive-control.XXXXXX";
	char path[128];

	assert(mkdtemp(directory));
	snprintf(path, sizeof(path), "%s/control.sock", directory);
	test_disabled_and_failed_start();
	test_protocol_and_monitor(path);
	test_path_ownership(path);
	assert(argc == 2);
	test_policy_controller(argv[1]);
	test_policy_monitor(path, argv[1]);
	assert(rmdir(directory) == 0);
	puts("adaptive monitor and control socket: PASS (mock kernel/QD backend)");
	return 0;
}
