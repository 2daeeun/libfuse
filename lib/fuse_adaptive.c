/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "fuse_i.h"
#include "fuse_adaptive_i.h"
#include "fuse_adaptive_protocol.h"
#include "fuse_uring_i.h"
#include "fuse_workload.h"
#include "fuse_qd_policy.h"

#include <errno.h>
#ifdef __linux__
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

struct fuse_adaptive {
	struct fuse_session *se;
	pthread_t thread;
	pthread_mutex_t lock;
	int stopfd, configfd, socketfd, error;
	bool dirty, configured;
	dev_t socket_dev;
	ino_t socket_ino;
	struct fuse_workload_settings settings;
	struct fuse_workload_detector detector;
	struct fuse_workload_result result;
	struct fuse_qd_policy policy;
	struct fuse_qd_policy_result policy_result;
	uint64_t policy_candidate, policy_transaction;
	int policy_error;
};

static const char *adaptive_policy_name(struct fuse_adaptive *a)
{
	return a->se->uring.policy_name ?
		a->se->uring.policy_name : "POLICY_NOT_CONFIGURED";
}

static void adaptive_reset_policy(struct fuse_adaptive *a)
{
	memset(&a->policy_result, 0, sizeof(a->policy_result));
	a->policy_candidate = a->policy_transaction = 0;
	a->policy_error = 0;
	if (a->se->uring.policy_config)
		fuse_qd_policy_init(&a->policy, a->se->uring.policy_config,
				    a->se->uring.policy_name, a->settings.window_ms);
}

/* Existing lock order is runtime_lock -> monitor lock -> QD backend lock.
 * Do not call the public wrapper with the monitor lock held. The generation
 * and dirty checks below serialize application with detector reconfiguration.
 */
static void adaptive_apply_policy(struct fuse_adaptive *a)
{
#ifdef HAVE_URING
	static const char applied_log[] =
		"FUSE_QD_POLICY profile=%s rule=%s target_depth=%u transaction=%" PRIu64 "\n";
	struct fuse_session *se = a->se;
	struct fuse_uring_runtime_status status = { 0 };
	struct fuse_uring_runtime_queue_status *queues = NULL;
	uint64_t transaction = 0;
	uint32_t target = 0;
	const char *rule = NULL;
	bool equal = true;
	int count, rc;

	pthread_mutex_lock(&se->uring.runtime_lock);
	if (se->uring.adaptive != a)
		goto unlock_runtime;
	pthread_mutex_lock(&a->lock);
	if (a->policy_candidate != a->policy.candidate_since) {
		a->policy_candidate = a->policy.candidate_since;
		a->policy_error = 0;
		a->policy_transaction = 0;
	}
	if (!se->uring.policy_config || !a->configured || a->dirty || a->error ||
	    !a->policy_result.stable || a->policy_error)
		goto unlock;
	target = a->policy_result.target_depth;
	count = fuse_uring_runtime_status(se, &status, NULL, 0);
	/* ENOTSUP also means that the runtime pool has not been created yet. */
	if (count == -EAGAIN || count == -ENOTSUP || status.busy)
		goto unlock;
	if (count <= 0) {
		a->policy_error = count ? count : -EIO;
		goto unlock;
	}
	if (a->policy_transaction && status.transaction == a->policy_transaction &&
	    status.error) {
		a->policy_error = status.error;
		goto unlock;
	}
	queues = calloc((size_t)count, sizeof(*queues));
	if (!queues) {
		a->policy_error = -ENOMEM;
		goto unlock;
	}
	rc = fuse_uring_runtime_status(se, &status, queues, (size_t)count);
	if (rc == -EAGAIN || rc == -ENOTSUP)
		goto unlock;
	if (rc < 0) {
		a->policy_error = rc;
		goto unlock;
	}
	if (status.busy)
		goto unlock;
	for (int i = 0; i < rc; i++)
		if (queues[i].current_depth != target || queues[i].error ||
		    queues[i].reclaim_bytes)
			equal = false;
	if (equal)
		goto unlock;
	rc = fuse_uring_request_qd(se, target, &transaction);
	if (!rc) {
		a->policy_transaction = transaction;
		rule = a->policy_result.rule_name;
	} else if (rc != -EBUSY && rc != -EAGAIN) {
		a->policy_error = rc;
	}
unlock:
	free(queues);
	pthread_mutex_unlock(&a->lock);
unlock_runtime:
	pthread_mutex_unlock(&se->uring.runtime_lock);
	if (rule)
		fuse_log(FUSE_LOG_INFO, applied_log,
			 adaptive_policy_name(a), rule, target, transaction);
#else
	(void)a;
#endif
}

static uint64_t adaptive_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int fuse_session_uring_set_depth(struct fuse_session *se, uint32_t depth,
				 uint64_t *transaction)
{
	int rc;

	if (!se || !transaction)
		return -EINVAL;
	pthread_mutex_lock(&se->uring.runtime_lock);
#ifdef HAVE_URING
	rc = se->uring.runtime_qd ?
		     fuse_uring_request_qd(se, depth, transaction) :
		     -EOPNOTSUPP;
#else
	(void)depth;
	rc = -EOPNOTSUPP;
#endif
	pthread_mutex_unlock(&se->uring.runtime_lock);
	return rc;
}

int fuse_session_uring_get_status(
	struct fuse_session *se, struct fuse_uring_runtime_status *status,
	struct fuse_uring_runtime_queue_status *queues, size_t capacity)
{
	int rc;

	if (!se || !status || (capacity && !queues))
		return -EINVAL;
	pthread_mutex_lock(&se->uring.runtime_lock);
#ifdef HAVE_URING
	rc = se->uring.runtime_qd ?
		     fuse_uring_runtime_status(se, status, queues, capacity) :
		     -EOPNOTSUPP;
#else
	rc = -EOPNOTSUPP;
#endif
	pthread_mutex_unlock(&se->uring.runtime_lock);
	return rc;
}

int fuse_session_workload_get(struct fuse_session *se,
			      struct fuse_workload_result *result)
{
	struct fuse_adaptive *a;
	int rc = -EOPNOTSUPP;

	if (!se || !result)
		return -EINVAL;
	pthread_mutex_lock(&se->uring.runtime_lock);
	a = se->uring.adaptive;
	if (a) {
		pthread_mutex_lock(&a->lock);
		*result = a->result;
		rc = a->error;
		pthread_mutex_unlock(&a->lock);
	}
	pthread_mutex_unlock(&se->uring.runtime_lock);
	return rc;
}

int fuse_session_workload_configure(
	struct fuse_session *se, const struct fuse_workload_settings *settings)
{
	struct fuse_adaptive *a;
	int rc;

	if (!se || !settings)
		return -EINVAL;
	rc = fuse_workload_validate(settings);
	if (rc)
		return rc;
	pthread_mutex_lock(&se->uring.runtime_lock);
	a = se->uring.adaptive;
	if (!a) {
		rc = -EOPNOTSUPP;
	} else if (se->uring.policy_config &&
		   memcmp(settings, &se->uring.policy_config->settings,
			  sizeof(*settings))) {
		/* File-selected settings can only be reset, not overridden. */
		rc = -EPERM;
	} else {
		uint64_t one = 1;

		pthread_mutex_lock(&a->lock);
		a->settings = *settings;
		a->dirty = true;
		a->configured = false;
		/* No old stable result may survive a configuration change. */
		memset(&a->result, 0, sizeof(a->result));
		a->result.workload = FUSE_WORKLOAD_UNKNOWN;
		a->result.profile = UINT32_MAX;
		a->result.operation = UINT32_MAX;
		adaptive_reset_policy(a);
		pthread_mutex_unlock(&a->lock);
		(void)write(a->configfd, &one, sizeof(one));
	}
	pthread_mutex_unlock(&se->uring.runtime_lock);
	return rc;
}

static void write_workload(FILE *out, struct fuse_adaptive *a)
{
	static const char *const names[] = {
		"RR_1T_1F", "RR_NT_1F", "RW_1T_1F", "RW_NT_1F",
		"SR_1T_1F", "SR_NT_NF", "SW_1T_1F", "SW_NT_NF",
		"UNKNOWN",  "MIXED",	"IDLE",
	};
	struct fuse_workload_result r;
	struct fuse_qd_policy_result p;
	uint64_t transaction;
	int rc, policy_error;

	pthread_mutex_lock(&a->lock);
	r = a->result;
	p = a->policy_result;
	rc = a->error;
	policy_error = a->policy_error;
	transaction = a->policy_transaction;
	pthread_mutex_unlock(&a->lock);

	if (rc) {
		fprintf(out, "{\"error\":%d}\n", rc);
		return;
	}
	fputs("{\"error\":0,\"source\":\"fuse_iter_requested\",", out);
	fprintf(out,
		"\"policy\":\"%s\",\"workload\":\"%s\",",
		adaptive_policy_name(a),
		r.workload <= FUSE_WORKLOAD_IDLE ? names[r.workload] :
						   "UNKNOWN");
	fprintf(out,
		"\"profile\":%u,\"min_size\":%" PRIu64 ",\"max_size\":%" PRIu64,
		r.profile, r.min_size, r.max_size);
	fprintf(out, ",\"requests\":%" PRIu64 ",\"bytes\":%" PRIu64, r.requests,
		r.bytes);
	fprintf(out, ",\"files_saturated\":%u,\"requesters_saturated\":%u,",
		r.files, r.requesters);
	fprintf(out, "\"flags\":%u,\"stable_ns\":%" PRIu64 ",\"stable\":%u,",
		r.flags, r.stable_ns, r.stable);
	fprintf(out,
		"\"operation\":%u,\"dominant_percent\":%u,\"sequential_percent\":%u,",
		r.operation, r.dominant_percent, r.sequential_percent);
	fprintf(out, "\"timestamp_ns\":%" PRIu64 ",", r.timestamp_ns);
	fprintf(out, "\"policy_rule\":\"%s\",\"policy_target_depth\":%u,",
		p.rule_name ? p.rule_name : "NONE", p.target_depth);
	fprintf(out, "\"policy_stable_ns\":%" PRIu64 ",\"policy_stable\":%u,",
		p.stable_ns, p.stable);
	fprintf(out, "\"policy_files\":%u,\"policy_requesters\":%u,\"policy_read_percent\":%u,",
		p.files, p.requesters, p.read_percent);
	fprintf(out, "\"policy_error\":%d,\"policy_transaction\":%" PRIu64 ",",
		policy_error, transaction);
	fprintf(out, "\"generation\":%" PRIu64 "}\n", r.generation);
}

static void write_status(FILE *out, struct fuse_session *se)
{
	struct fuse_uring_runtime_status s = { 0 };
	struct fuse_uring_runtime_queue_status *q;
	int count = fuse_session_uring_get_status(se, &s, NULL, 0);
	int rc;

	if (count < 0) {
		fprintf(out, "{\"error\":%d}\n", count);
		return;
	}
	q = calloc(count ? (size_t)count : 1, sizeof(*q));
	if (!q) {
		fprintf(out, "{\"error\":%d}\n", -ENOMEM);
		return;
	}
	rc = fuse_session_uring_get_status(se, &s, q, count);
	if (rc < 0) {
		fprintf(out, "{\"error\":%d}\n", rc);
		free(q);
		return;
	}
	fprintf(out,
		"{\"error\":%d,\"pid\":%ld,\"transaction\":%" PRIu64
		",\"busy\":%u,\"max_depth\":%u,\"queues\":[",
		s.error, (long)getpid(), s.transaction, s.busy, s.max_depth);
	for (int i = 0; i < rc; i++) {
		fprintf(out, "%s{\"qid\":%u,\"current_depth\":%u,",
			i ? "," : "", q[i].qid, q[i].current_depth);
		fprintf(out, "\"target_depth\":%u,\"phase\":%u,\"error\":%d,",
			q[i].target_depth, q[i].phase, q[i].error);
		fprintf(out,
			"\"generation\":%" PRIu64 ",\"payload_bytes\":%" PRIu64
			",\"registered_bytes\":%" PRIu64
			",\"reclaim_bytes\":%" PRIu64 "}",
			q[i].generation, q[i].payload_bytes,
			q[i].registered_bytes, q[i].reclaim_bytes);
	}
	fputs("]}\n", out);
	free(q);
}

static void serve_client(struct fuse_adaptive *a)
{
	struct fuse_adaptive_control_request req;
	struct ucred cred;
	socklen_t credlen = sizeof(cred);
	char *reply = NULL;
	size_t replylen = 0;
	uint64_t transaction = 0;
	int fd, rc;
	ssize_t len;
	FILE *out;
	struct pollfd pfd;

	fd = accept4(a->socketfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0)
		return;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) ||
	    (cred.uid != geteuid() && cred.uid != 0))
		goto done;
	pfd = (struct pollfd){ .fd = fd, .events = POLLIN };
	if (poll(&pfd, 1, 50) <= 0)
		goto done;
	len = recv(fd, &req, sizeof(req), MSG_TRUNC);
	out = open_memstream(&reply, &replylen);
	if (!out)
		goto done;
	if (len != sizeof(req) ||
	    req.version != FUSE_ADAPTIVE_CONTROL_VERSION || req.reserved) {
		fprintf(out, "{\"error\":%d}\n", -EINVAL);
	} else {
		switch (req.operation) {
		case FUSE_ADAPTIVE_STATUS:
			write_status(out, a->se);
			break;
		case FUSE_ADAPTIVE_WORKLOAD:
			write_workload(out, a);
			break;
		case FUSE_ADAPTIVE_SET_DEPTH:
			rc = fuse_session_uring_set_depth(a->se, req.depth,
							  &transaction);
			fprintf(out,
				"{\"error\":%d,\"transaction\":%" PRIu64 "}\n",
				rc, transaction);
			break;
		case FUSE_ADAPTIVE_CONFIGURE:
			rc = fuse_session_workload_configure(a->se,
							     &req.settings);
			fprintf(out, "{\"error\":%d,\"pending\":%s}\n", rc,
				rc ? "false" : "true");
			break;
		case FUSE_ADAPTIVE_GET_CONFIG: {
			struct fuse_workload_settings s;
			bool pending;

			pthread_mutex_lock(&a->lock);
			s = a->settings;
			pending = a->dirty;
			rc = a->error;
			pthread_mutex_unlock(&a->lock);
			fprintf(out,
				"{\"error\":%d,\"pending\":%s,\"window_ms\":%u,",
				rc, pending ? "true" : "false", s.window_ms);
			fprintf(out,
				"\"stable_ms\":%u,\"min_requests\":%u,\"min_pairs\":%u,",
				s.stable_ms, s.min_requests, s.min_pairs);
			fprintf(out,
				"\"dominance_percent\":%u,\"sequential_percent\":%u,",
				s.dominance_percent, s.sequential_percent);
			fprintf(out,
				"\"random_percent\":%u,\"thresholds\":[%" PRIu64
				",%" PRIu64 ",%" PRIu64 "]}\n",
				s.random_percent, s.thresholds[0],
				s.thresholds[1], s.thresholds[2]);
			break;
		}
		default:
			fprintf(out, "{\"error\":%d}\n", -EINVAL);
		}
	}
	fclose(out);
	if (replylen <= FUSE_ADAPTIVE_REPLY_MAX)
		(void)send(fd, reply, replylen, MSG_NOSIGNAL);
	free(reply);
done:
	close(fd);
}

static void *adaptive_monitor(void *opaque)
{
	struct fuse_adaptive *a = opaque;
	struct pollfd fds[3] = {
		{ .fd = a->stopfd, .events = POLLIN },
		{ .fd = a->socketfd, .events = POLLIN },
		{ .fd = a->configfd, .events = POLLIN },
	};
	uint64_t next = adaptive_now();
	bool announced = false;
	int rc;

	for (;;) {
		uint64_t now = adaptive_now();
		uint64_t wait_ms =
			now >= next ? 0 : (next - now + 999999) / 1000000;
		int timeout = wait_ms > INT_MAX ? INT_MAX : (int)wait_ms;
		bool announce = false;
		bool observed = false;

		rc = poll(fds, 3, timeout);
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc < 0 || fds[0].revents)
			break;
		if (fds[2].revents & POLLIN) {
			uint64_t value;
			(void)read(a->configfd, &value, sizeof(value));
		}
		if (fds[1].revents & POLLIN)
			serve_client(a);
		pthread_mutex_lock(&a->lock);
		if (a->dirty) {
			struct fuse_workload_config config = {
				.version = FUSE_WORKLOAD_VERSION,
				.flags = FUSE_WORKLOAD_ENABLE,
			};
			if (a->se->uring.policy_config)
				config.flags |= FUSE_WORKLOAD_DETAIL;
			memcpy(config.thresholds, a->settings.thresholds,
			       sizeof(config.thresholds));
			a->error = ioctl(a->se->fd, FUSE_DEV_IOC_MONITOR_CONFIG,
					 &config) < 0 ?
					   -errno :
					   0;
			a->configured = !a->error;
			if (a->configured && !announced) {
				announce = true;
				announced = true;
			}
			fuse_workload_detector_init(&a->detector, &a->settings);
			adaptive_reset_policy(a);
			/* INIT publication may lag the reply that started this thread. */
			a->dirty = a->error == -EAGAIN;
			next = adaptive_now() +
			       (a->dirty ? 10000000ULL :
					   (uint64_t)a->settings.window_ms *
						   1000000);
		}
		now = adaptive_now();
		if (!a->dirty && now >= next) {
			struct fuse_workload_detail detail = {
				.snapshot.version = FUSE_WORKLOAD_VERSION
			};

			/* Failed CONFIG must not classify an older kernel bucket table. */
			if (!a->configured) {
				next = now + (uint64_t)a->settings.window_ms *
						     1000000;
				pthread_mutex_unlock(&a->lock);
				continue;
			}
			rc = ioctl(a->se->fd, a->se->uring.policy_config ?
				   FUSE_DEV_IOC_MONITOR_DETAIL : FUSE_DEV_IOC_MONITOR_SNAPSHOT,
				   &detail);
			a->error = rc < 0 ? -errno : 0;
			rc = fuse_workload_detector_update(
				&a->detector, rc < 0 ? NULL : &detail.snapshot,
				&a->result);
			if (!a->error)
				a->error = rc;
			if (a->se->uring.policy_config) {
				rc = fuse_qd_policy_update(&a->policy,
					a->error ? NULL : &detail, &a->policy_result);
				if (!a->error)
					a->error = rc;
			}
			a->result.policy_configured = !!a->se->uring.policy_config;
			observed = true;
			next = now + (uint64_t)a->settings.window_ms * 1000000;
		}
		pthread_mutex_unlock(&a->lock);
		if (announce)
			fuse_log(FUSE_LOG_INFO,
				 "FUSE_ADAPTIVE mode=on runtime_qd=1 workload_monitor=1 initial_depth=%u max_depth=%u policy=%s\n",
				 a->se->uring.q_depth, a->se->uring.max_depth,
				 adaptive_policy_name(a));
		if (observed && a->se->uring.policy_config)
			adaptive_apply_policy(a);
	}
	return NULL;
}

static void remove_owned_socket(struct fuse_adaptive *a)
{
	struct stat st;
	const char *path = a->se->uring.control_path;

	if (path && a->socket_ino && !lstat(path, &st) &&
	    st.st_dev == a->socket_dev && st.st_ino == a->socket_ino &&
	    S_ISSOCK(st.st_mode))
		(void)unlink(path);
}

int fuse_adaptive_start(struct fuse_session *se)
{
	struct fuse_adaptive *a;
	const char *path = se->uring.control_path;
	int rc = 0;

	if (!se->uring.runtime_qd)
		return 0;
	a = calloc(1, sizeof(*a));
	if (!a)
		return -ENOMEM;
	a->se = se;
	a->socketfd = -1;
	a->configfd = -1;
	a->stopfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (a->stopfd < 0) {
		rc = -errno;
		free(a);
		return rc;
	}
	pthread_mutex_init(&a->lock, NULL);
	a->configfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (a->configfd < 0) {
		rc = -errno;
		goto fail;
	}
	fuse_workload_defaults(&a->settings);
	if (se->uring.policy_config)
		a->settings = se->uring.policy_config->settings;
	fuse_workload_detector_init(&a->detector, &a->settings);
	adaptive_reset_policy(a);
	a->result.workload = FUSE_WORKLOAD_UNKNOWN;
	a->result.profile = UINT32_MAX;
	a->result.operation = UINT32_MAX;
	a->dirty = true;
	if (path) {
		struct sockaddr_un addr = { .sun_family = AF_UNIX };
		struct stat st;

		if (!*path || strlen(path) >= sizeof(addr.sun_path)) {
			rc = -ENAMETOOLONG;
			goto fail;
		}
		memcpy(addr.sun_path, path, strlen(path) + 1);
		a->socketfd = socket(
			AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
			0);
		if (a->socketfd < 0 ||
		    bind(a->socketfd, (struct sockaddr *)&addr, sizeof(addr))) {
			rc = -errno;
			goto fail;
		}
		if (lstat(path, &st)) {
			rc = -errno;
			goto fail;
		}
		a->socket_dev = st.st_dev;
		a->socket_ino = st.st_ino;
		if (fchmodat(AT_FDCWD, path, 0600, AT_SYMLINK_NOFOLLOW) ||
		    listen(a->socketfd, 8)) {
			rc = -errno;
			goto fail;
		}
	}
	pthread_mutex_lock(&se->uring.runtime_lock);
	if (se->uring.adaptive) {
		pthread_mutex_unlock(&se->uring.runtime_lock);
		rc = -EBUSY;
		goto fail;
	}
	se->uring.adaptive = a;
	rc = pthread_create(&a->thread, NULL, adaptive_monitor, a);
	if (rc)
		se->uring.adaptive = NULL;
	pthread_mutex_unlock(&se->uring.runtime_lock);
	if (!rc)
		return 0;
	rc = -rc;
fail:
	remove_owned_socket(a);
	if (a->socketfd >= 0)
		close(a->socketfd);
	close(a->stopfd);
	if (a->configfd >= 0)
		close(a->configfd);
	pthread_mutex_destroy(&a->lock);
	free(a);
	return rc;
}

void fuse_adaptive_stop(struct fuse_session *se)
{
	struct fuse_adaptive *a;
	uint64_t one = 1;

	pthread_mutex_lock(&se->uring.runtime_lock);
	a = se->uring.adaptive;
	se->uring.adaptive = NULL;
	pthread_mutex_unlock(&se->uring.runtime_lock);
	if (!a)
		return;
	(void)write(a->stopfd, &one, sizeof(one));
	pthread_join(a->thread, NULL);
	remove_owned_socket(a);
	if (a->socketfd >= 0)
		close(a->socketfd);
	close(a->stopfd);
	close(a->configfd);
	pthread_mutex_destroy(&a->lock);
	free(a);
}
#else
int fuse_adaptive_start(struct fuse_session *se)
{
	(void)se;
	return 0;
}

void fuse_adaptive_stop(struct fuse_session *se)
{
	(void)se;
}

int fuse_session_uring_set_depth(struct fuse_session *se, uint32_t depth,
				 uint64_t *transaction)
{
	(void)se;
	(void)depth;
	(void)transaction;
	return -EOPNOTSUPP;
}

int fuse_session_uring_get_status(
	struct fuse_session *se, struct fuse_uring_runtime_status *status,
	struct fuse_uring_runtime_queue_status *queues, size_t capacity)
{
	(void)se;
	(void)status;
	(void)queues;
	(void)capacity;
	return -EOPNOTSUPP;
}

int fuse_session_workload_get(struct fuse_session *se,
			      struct fuse_workload_result *result)
{
	(void)se;
	(void)result;
	return -EOPNOTSUPP;
}

int fuse_session_workload_configure(
	struct fuse_session *se, const struct fuse_workload_settings *settings)
{
	(void)se;
	(void)settings;
	return -EOPNOTSUPP;
}
#endif
