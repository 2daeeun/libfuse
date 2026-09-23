/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025  Bernd Schubert <bschubert@ddn.com>
 *
 * Implementation of (most of) FUSE-over-io-uring.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file LGPL2.txt
 */

#define _GNU_SOURCE

#include "fuse_i.h"
#include "fuse_adaptive_i.h"
#include "fuse_kernel.h"
#include "fuse_uring_affinity.h"
#include "fuse_uring_i.h"
#include "fuse_uring_reply.h"

#include <stdlib.h>
#include <liburing.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <numa.h>
#include <pthread.h>
#include <stdio.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <time.h>

/* Size of command data area in SQE when IORING_SETUP_SQE128 is used */
#define FUSE_URING_MAX_SQE128_CMD_DATA 80

enum fuse_uring_cqe_kind {
	FUSE_URING_CQE_COMMAND = 0,
	FUSE_URING_CQE_FIXED_IO,
};

struct fuse_ring_ent {
	struct fuse_ring_queue *ring_queue; /* back pointer */
	struct fuse_req req;

	struct fuse_uring_req_header *req_header;
	void *op_payload;
	size_t req_payload_sz;

	/* commit id of a fuse request */
	uint64_t req_commit_id;

	enum fuse_uring_cmd last_cmd;
	enum fuse_uring_cqe_kind cqe_kind;
	fuse_uring_fixed_io_callback_t fixed_io_callback;
	void *fixed_io_userdata;
	bool fixed_io_pending;
	bool fixed_io_write;
	bool fixed_io_completed;
	unsigned int fixed_buf_index;
	bool retired;
	bool submitted;
	int rearm_error;

	/* header and payload */
	struct iovec iov[2];
};

struct fuse_ring_queue {
	/* back pointer */
	struct fuse_ring_pool *ring_pool;
	int qid;
	int numa_node;
	pthread_t tid;
	int eventfd;
	int control_eventfd;
	size_t req_header_sz;
	struct io_uring ring;

	pthread_mutex_t ring_lock;

	/* batched inline replies across cqe handling; flushed by the loop */
	_Atomic bool cqe_processing;

	/* Slot zero owns this queue's shared command payload pool. */
	void *payload_pool;
	size_t payload_pool_sz;
	bool sparse_buffers_registered;
	unsigned int payload_slot;
	/* Addresses are CQE tokens; never interpreted as entry pointers. */
	char payload_tags[2];
	bool payload_released[2];
	struct fuse_ring_ent control_ent;
	struct fuse_uring_runtime_state query_result;
	bool control_pending;
	/* OFF-only startup/shutdown inventory; never sampled on the I/O path. */
	bool allocation_started;
	bool rearming;
	int control_result;
	unsigned int current_depth;
	uint64_t generation;
	void *prepared_pool;
	size_t prepared_pool_sz;
	void **prepared_payloads;
	struct fuse_uring_runtime_queue_status runtime_status;
	bool write_in_task;
	uint64_t fixed_read_submitted;
	uint64_t fixed_read_completed;
	uint64_t fixed_read_errors;
	uint64_t fixed_read_bytes;
	uint64_t fixed_write_submitted;
	uint64_t fixed_write_completed;
	uint64_t fixed_write_errors;
	uint64_t fixed_write_bytes;
	uint64_t copied_fallbacks;
	uint64_t copied_read_fallbacks;
	uint64_t copied_write_fallbacks;

	/* size depends on queue depth */
	struct fuse_ring_ent ent[];
};

/**
 * Main fuse_ring structure, holds all fuse-ring data
 */
struct fuse_ring_pool {
	struct fuse_session *se;

	/* mirror of se->conn.io_uring_single_issuer, fixed at ring creation */
	bool single_issuer;
	bool zero_copy;
	bool write_in_task;

	/* number of queues */
	size_t nr_queues;

	/* Optional, immutable physical-core identities sampled before workers. */
	int *cpu_core_ids;

	/* number of per queue entries */
	size_t queue_depth;
	size_t initial_depth;
	bool runtime_qd;
	unsigned int drain_timeout_ms;
	pthread_mutex_t control_lock;
	uint64_t transaction;
	unsigned int target_depth;
	unsigned int control_qid;
	bool control_busy;
	int control_error;

	/* max payload size for fuse requests*/
	size_t max_req_payload_sz;

	/* size of a single queue */
	size_t queue_mem_size;

	unsigned int started_threads;
	unsigned int failed_threads;
	atomic_uint ready_queues;

	/* Avoid sending queue entries before FUSE_INIT reply*/
	sem_t init_sem;

	pthread_cond_t thread_start_cond;
	pthread_mutex_t thread_start_mutex;

	/* pointer to the first queue */
	struct fuse_ring_queue *queues;
};

static size_t
fuse_ring_queue_size(const size_t q_depth)
{
	const size_t req_size = sizeof(struct fuse_ring_ent) * q_depth;

	return sizeof(struct fuse_ring_queue) + req_size;
}

static struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_ring_pool *fuse_ring, int qid)
{
	void *ptr =
		((char *)fuse_ring->queues) + (qid * fuse_ring->queue_mem_size);

	return ptr;
}

/**
 * return a pointer to the 80B area
 */
static void *fuse_uring_get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (void *)&sqe->cmd[0];
}

static void fuse_uring_sqe_set_req_data(struct fuse_uring_cmd_req *req,
					const unsigned int qid,
					const uint64_t commit_id)
{
	memset(req, 0, sizeof(*req));
	req->qid = qid;
	req->commit_id = commit_id;
}

static void
fuse_uring_sqe_prepare(struct io_uring_sqe *sqe, struct fuse_ring_ent *req,
		       __u32 cmd_op)
{
	/* These fields should be written once, never change */
	sqe->opcode = IORING_OP_URING_CMD;

	/*
	 * IOSQE_FIXED_FILE: fd is the index to the fd *array*
	 * given to io_uring_register_files()
	 */
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->fd = 0;

	sqe->rw_flags = 0;
	sqe->ioprio = 0;
	sqe->off = 0;

	io_uring_sqe_set_data(sqe, req);
	if (req)
		req->cqe_kind = FUSE_URING_CQE_COMMAND;

	sqe->cmd_op = cmd_op;
	sqe->__pad1 = 0;
}

#ifdef HAVE_URING_ZERO_COPY
static void fuse_uring_use_payload_pool(struct io_uring_sqe *sqe,
				       struct fuse_ring_queue *queue)
{
	sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
	sqe->buf_index = queue->payload_slot;
}
#endif

/* Keep the real preparation/COMMIT boundaries available to opt-in uprobes. */
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9
#define FUSE_URING_PROBE __attribute__((noipa, used))
#else
#define FUSE_URING_PROBE __attribute__((noinline, used))
#endif

static int fuse_uring_check_queue_owner(struct fuse_ring_queue *queue)
{
	if (!queue->ring_pool->single_issuer ||
	    pthread_equal(pthread_self(), queue->tid))
		return 0;

	queue->ring_pool->se->error = -EINVAL;
	fuse_log(FUSE_LOG_ERR,
		 "qid=%d single-issuer reply came from a different thread\n",
		 queue->qid);
	return -EINVAL;
}

FUSE_URING_PROBE
int fuse_uring_commit_sqe(struct fuse_ring_pool *ring_pool,
				 struct fuse_ring_queue *queue,
				 struct fuse_ring_ent *ring_ent)
{
	const bool locked = !ring_pool->single_issuer;
	struct fuse_session *se = ring_pool->se;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	struct io_uring_sqe *sqe;
	int res = 0;

	/* The public single-issuer contract excludes deferred foreign replies. */
	if (fuse_uring_check_queue_owner(queue))
		return -EINVAL;

	/*
	 * Multi-issuer: serialise every submission-side SQ access under
	 * ring_lock. Single-issuer: only the uring thread submits, so skip the
	 * lock and batch inline replies (cqe_processing), flushed by the next
	 * submit_and_wait().
	 */
	if (locked)
		pthread_mutex_lock(&queue->ring_lock);

	sqe = io_uring_get_sqe(&queue->ring);

	if (sqe == NULL) {
		/* This is an impossible condition, unless there is a bug.
		 * The kernel sent back an SQEs, which is assigned to a request.
		 * There is no way to get out of SQEs, as the number of
		 * SQEs matches the number tof requests.
		 */

		if (locked)
			pthread_mutex_unlock(&queue->ring_lock);
		se->error = -EIO;
		fuse_log(FUSE_LOG_ERR, "Failed to get a ring SQEs\n");

		return -EIO;
	}

	ring_ent->last_cmd = FUSE_IO_URING_CMD_COMMIT_AND_FETCH;
	fuse_uring_sqe_prepare(sqe, ring_ent, ring_ent->last_cmd);
	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe), queue->qid,
				    ring_ent->req_commit_id);
	if (ring_pool->runtime_qd)
		((struct fuse_uring_cmd_req *)fuse_uring_get_sqe_cmd(sqe))->flags =
			queue->generation;
#ifdef HAVE_URING_ZERO_COPY
	if (ring_pool->zero_copy)
		fuse_uring_use_payload_pool(sqe, queue);
#endif

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "    unique: %" PRIu64 ", result=%d\n",
			 out->unique, ent_in_out->payload_sz);
	}

	if (!atomic_load_explicit(&queue->cqe_processing, memory_order_relaxed))
		res = io_uring_submit(&queue->ring);

	if (locked)
		pthread_mutex_unlock(&queue->ring_lock);
	if (res < 0) {
		se->error = res;
		fuse_session_exit(se);
		return res;
	}

	return 0;
}

int fuse_req_get_payload(fuse_req_t req, char **payload, size_t *payload_sz,
			 void **mr)
{
	struct fuse_ring_ent *ring_ent;

	/* Not possible without io-uring interface */
	if (!req->flags.is_uring)
		return -EINVAL;
	if (req->flags.is_uring_zero_copy)
		return -ENODATA;

	ring_ent = container_of(req, struct fuse_ring_ent, req);

	*payload = ring_ent->op_payload;
	*payload_sz = ring_ent->req_payload_sz;

	/*
	 * For now unused, but will be used later when the application can
	 * allocate the buffers itself and register them for rdma.
	 */
	if (mr)
		*mr = NULL;

	return 0;
}

int fuse_uring_submit_fixed_io(fuse_req_t req, int fd, off_t offset,
			       size_t size, bool write_to_fd,
			       fuse_uring_fixed_io_callback_t callback,
			       void *userdata)
{
#ifdef HAVE_URING_ZERO_COPY
	struct fuse_ring_ent *ent;
	struct fuse_ring_queue *queue;
	struct fuse_ring_pool *pool;
	struct fuse_uring_req_header *rrh;
	struct fuse_in_header *in;
	uint32_t request_size;
	struct io_uring_sqe *sqe;

	if (!req || !callback || fd < 0 || offset < 0 || size > UINT_MAX)
		return -EINVAL;
	if (!req->flags.is_uring || !req->flags.is_uring_zero_copy)
		return -EINVAL;

	ent = container_of(req, struct fuse_ring_ent, req);
	queue = ent->ring_queue;
	pool = queue->ring_pool;
	rrh = ent->req_header;
	in = (struct fuse_in_header *)&rrh->in_out;
	if ((write_to_fd && in->opcode != FUSE_WRITE) ||
	    (!write_to_fd && in->opcode != FUSE_READ))
		return -EINVAL;
	request_size = write_to_fd ?
		((struct fuse_write_in *)&rrh->op_in)->size :
		((struct fuse_read_in *)&rrh->op_in)->size;
	if (!pool->zero_copy || !pool->single_issuer ||
	    !ent->fixed_buf_index ||
	    ent->fixed_buf_index > pool->queue_depth ||
	    size > request_size || ent->fixed_io_pending ||
	    !pthread_equal(pthread_self(), queue->tid) ||
	    !atomic_load_explicit(&queue->cqe_processing,
				  memory_order_relaxed))
		return -EINVAL;

	sqe = io_uring_get_sqe(&queue->ring);
	if (!sqe)
		return -EAGAIN;
	if (write_to_fd)
		io_uring_prep_write_fixed(sqe, fd, NULL, (unsigned int)size,
					  offset, ent->fixed_buf_index);
	else
		io_uring_prep_read_fixed(sqe, fd, NULL, (unsigned int)size,
					 offset, ent->fixed_buf_index);
	io_uring_sqe_set_data(sqe, ent);
	ent->cqe_kind = FUSE_URING_CQE_FIXED_IO;
	ent->fixed_io_callback = callback;
	ent->fixed_io_userdata = userdata;
	ent->fixed_io_pending = true;
	ent->fixed_io_write = write_to_fd;
	ent->fixed_io_completed = false;

	if (write_to_fd)
		queue->fixed_write_submitted++;
	else
		queue->fixed_read_submitted++;

	/* The queue loop flushes this SQE before it waits again. */
	return 0;
#else
	(void)req;
	(void)fd;
	(void)offset;
	(void)size;
	(void)write_to_fd;
	(void)callback;
	(void)userdata;
	return -ENOTSUP;
#endif
}

int fuse_reply_uring_zero_copy(fuse_req_t req, size_t count)
{
#ifdef HAVE_URING_ZERO_COPY
	struct fuse_ring_ent *ent;
	struct fuse_ring_queue *queue;
	struct fuse_ring_pool *pool;
	struct fuse_uring_req_header *rrh;
	struct fuse_out_header *out;
	struct fuse_uring_ent_in_out *ent_in_out;
	struct fuse_in_header *in;
	struct fuse_read_in *read_in;
	int validation_error;
	int res;

	if (!req || !req->flags.is_uring || !req->flags.is_uring_zero_copy)
		return -EINVAL;
	ent = container_of(req, struct fuse_ring_ent, req);
	if (ent->fixed_io_pending)
		return -EBUSY;
	queue = ent->ring_queue;
	pool = queue->ring_pool;
	rrh = ent->req_header;
	out = (struct fuse_out_header *)&rrh->in_out;
	ent_in_out = &rrh->ring_ent_in_out;
	in = (struct fuse_in_header *)&rrh->in_out;
	read_in = (struct fuse_read_in *)&rrh->op_in;
	if (in->opcode != FUSE_READ || !ent->fixed_io_completed ||
	    ent->fixed_io_write || count > read_in->size)
		return -EINVAL;
	ent->fixed_io_completed = false;

	validation_error = fuse_uring_prepare_reply(
		out, ent_in_out, req->unique, 0, count,
		pool->max_req_payload_sz);
	if (validation_error)
		fuse_log(FUSE_LOG_ERR,
			 "invalid zero-copy io_uring reply size %zu: %s\n",
			 count, strerror(-validation_error));

	res = fuse_uring_commit_sqe(pool, queue, ent);
	fuse_free_req(req);
	if (res)
		return res;
	return validation_error;
#else
	(void)req;
	(void)count;
	return -ENOTSUP;
#endif
}

int send_reply_uring(fuse_req_t req, int error, const void *arg, size_t argsize)
{
	int validation_error;
	int res;
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	size_t max_payload_sz = ring_pool->max_req_payload_sz;

	if (!error && argsize && arg == NULL) {
		fuse_log(FUSE_LOG_ERR, "non-empty io_uring reply has no payload");
		error = -EINVAL;
		argsize = 0;
	}

	validation_error = fuse_uring_prepare_reply(
		out, ent_in_out, req->unique, error, argsize, max_payload_sz);
	if (validation_error) {
		fuse_log(FUSE_LOG_ERR,
			 "io_uring reply payload %zu exceeds limit %zu: %s",
			 argsize, max_payload_sz, strerror(-validation_error));
	} else if (!out->error && ent_in_out->payload_sz) {
		if (arg != ring_ent->op_payload)
			memcpy(ring_ent->op_payload, arg,
			       ent_in_out->payload_sz);
	}

	res = fuse_uring_commit_sqe(ring_pool, queue, ring_ent);

	fuse_free_req(req);

	return res;
}

int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags)
{
	return fuse_reply_data_uring_with_prepare(req, bufv, flags, NULL, NULL);
}

FUSE_URING_PROBE
int fuse_reply_data_uring_with_prepare(fuse_req_t req, struct fuse_bufvec *bufv,
				      enum fuse_buf_copy_flags flags,
				      fuse_reply_data_prepare_t prepare,
				      void *opaque)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	size_t max_payload_sz = ring_ent->req_payload_sz;
	struct fuse_bufvec dest_vec = FUSE_BUFVEC_INIT(max_payload_sz);
	int res;

	dest_vec.buf[0].mem = ring_ent->op_payload;
	dest_vec.buf[0].size = max_payload_sz;

	res = fuse_buf_copy(&dest_vec, bufv, flags);

	if (fuse_uring_prepare_reply(out, ent_in_out, req->unique,
				     res < 0 ? res : 0,
				     res > 0 ? (size_t)res : 0,
				     max_payload_sz)) {
		res = out->error;
		fuse_log(FUSE_LOG_ERR,
			 "copied io_uring reply exceeds buffer size %zu",
			 max_payload_sz);
	}

	if (prepare) {
		int saved_errno = errno;

		prepare(opaque, res);
		errno = saved_errno;
	}

	res = fuse_uring_commit_sqe(ring_pool, queue, ring_ent);

	fuse_free_req(req);

	return res;
}

/**
 * Copy the iov into the ring buffer and submit and commit/fetch sqe
 */
int fuse_send_msg_uring(fuse_req_t req, struct iovec *iov, int count)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	const struct fuse_out_header *source_out;
	size_t max_buf = ring_pool->max_req_payload_sz;
	size_t len = 0;
	int error;
	int res;

	res = fuse_uring_iov_payload_size(iov, count, max_buf, &len);
	if (res) {
		fuse_log(FUSE_LOG_ERR, "invalid io_uring reply iovec: %s",
			 strerror(-res));
		error = -EINVAL;
		len = 0;
		goto prepare;
	}

	source_out = iov[0].iov_base;
	error = source_out->error;
	if (source_out->unique != req->unique ||
	    source_out->len != sizeof(*source_out) + len) {
		fuse_log(FUSE_LOG_ERR,
			 "invalid io_uring reply header for unique %" PRIu64,
			 req->unique);
		error = -EINVAL;
		len = 0;
	}

prepare:
	res = fuse_uring_prepare_reply(out, ent_in_out, req->unique, error,
				       len, max_buf);
	if (res) {
		fuse_log(FUSE_LOG_ERR, "invalid io_uring reply payload: %s",
			 strerror(-res));
		len = 0;
	}

	if (!out->error) {
		len = 0;
		for (int idx = 1; idx < count; idx++) {
			const struct iovec *cur = &iov[idx];

			memcpy(ring_ent->op_payload + len, cur->iov_base,
			       cur->iov_len);
			len += cur->iov_len;
		}
	}

	return fuse_uring_commit_sqe(ring_pool, queue, ring_ent);
}

static int fuse_queue_setup_io_uring(struct io_uring *ring, size_t qid,
				     size_t depth, int fd, int evfd,
				     bool single_issuer, bool runtime_qd)
{
	int rc;
	struct io_uring_params params = {0};
	int files[2] = { fd, evfd };

	depth += runtime_qd ? 4 : 1; /* stop/control polls and control command */

	params.flags = IORING_SETUP_SQE128;

	/* Replies are batched and flushed in one io_uring_enter; don't let a
	 * single failing commit SQE stall submission of the rest of the batch.
	 */
	params.flags |= IORING_SETUP_SUBMIT_ALL;

	/* Avoid cq overflow */
	params.flags |= IORING_SETUP_CQSIZE;
	params.cq_entries = depth * 2;

	/*
	 * This queue's creator also receives and replies to every request.
	 * Its existing submit_and_wait() loop runs completion task-work; no
	 * off-thread submitter or additional wait is needed. Multi-issuer queues
	 * retain immediate task-work and their locked foreign-reply submissions.
	 */
	if (single_issuer)
		params.flags |= IORING_SETUP_SINGLE_ISSUER |
				IORING_SETUP_DEFER_TASKRUN;

	rc = io_uring_queue_init_params(depth, ring, &params);
	if (rc != 0) {
		fuse_log(FUSE_LOG_ERR, "Failed to setup qid %zu: %d (%s)\n",
			 qid, rc, strerror(-rc));
		return rc;
	}

	rc = io_uring_register_files(ring, files, 1);
	if (rc != 0) {
		fuse_log(FUSE_LOG_ERR,
			 "Failed to register files for ring idx %zu: %s",
			 qid, strerror(-rc));
		return rc;
	}

	if (single_issuer) {
		/*
		 * Only fuse_uring_thread() issues io_uring_enter() on this
		 * ring, so the registered ring-fd index is valid. Non-fatal -
		 * older kernels just keep using the normal ring fd.
		 */
		rc = io_uring_register_ring_fd(ring);
		if (rc < 0)
			fuse_log(FUSE_LOG_DEBUG,
				 "qid=%zu register_ring_fd failed: %s\n",
				 qid, strerror(-rc));
	}

	fuse_log(FUSE_LOG_INFO,
		 "FUSE_URING_TASKRUN qid=%zu setup_flags=0x%08x single_issuer=%u defer_taskrun=%u\n",
		 qid, params.flags,
		 !!(params.flags & IORING_SETUP_SINGLE_ISSUER),
		 !!(params.flags & IORING_SETUP_DEFER_TASKRUN));
	return 0;
}

struct fuse_uring_allocation {
	uint64_t entries;
	uint64_t payload_bytes;
	uint64_t registered_bytes;
	uint64_t header_bytes;
	bool valid;
};

static bool fuse_uring_allocation_add(uint64_t *total, size_t length)
{
	if (length > UINT64_MAX - *total)
		return false;
	*total += length;
	return true;
}

/* Only call in the owner before readiness publication, or after owner join.
 * Count owned allocation lengths, not QD-derived capacity or resident pages.
 * In zero-copy mode ent->op_payload is a mutable, non-owning pool slice.
 */
static struct fuse_uring_allocation
fuse_uring_allocation_inventory(const struct fuse_ring_queue *queue)
{
	const struct fuse_ring_pool *pool = queue->ring_pool;
	struct fuse_uring_allocation out = { .valid = true };

	if (pool->runtime_qd || !queue->allocation_started ||
	    queue->current_depth != pool->queue_depth ||
	    !pool->queue_depth || !queue->req_header_sz)
		out.valid = false;
	if (pool->zero_copy) {
		if (!queue->payload_pool || !queue->payload_pool_sz ||
		    !queue->sparse_buffers_registered)
			out.valid = false;
		if (queue->payload_pool)
			out.payload_bytes = queue->payload_pool_sz;
		out.registered_bytes = queue->runtime_status.registered_bytes;
		if (out.registered_bytes != out.payload_bytes)
			out.valid = false;
	}
	for (size_t idx = 0; idx < pool->queue_depth; idx++) {
		const struct fuse_ring_ent *ent = &queue->ent[idx];

		if (ent->req_header) {
			out.entries++;
			if (!fuse_uring_allocation_add(&out.header_bytes,
						queue->req_header_sz))
				out.valid = false;
		}
		if (!pool->zero_copy) {
			if (!ent->op_payload || !ent->req_payload_sz)
				out.valid = false;
			if (ent->op_payload &&
			    !fuse_uring_allocation_add(&out.payload_bytes,
						ent->req_payload_sz))
				out.valid = false;
		}
	}
	if (out.entries != pool->queue_depth || !out.payload_bytes)
		out.valid = false;
	return out;
}

static void fuse_uring_log_allocation(struct fuse_ring_queue *queue,
				      const char *stage)
{
	struct fuse_uring_allocation value;

	if (queue->ring_pool->runtime_qd)
		return;
	value = fuse_uring_allocation_inventory(queue);
	fuse_log(FUSE_LOG_INFO,
		 "FUSE_URING_ALLOCATION version=1 stage=%s qid=%d depth=%u entries=%" PRIu64
		 " payload_bytes=%" PRIu64
		 " registered_bytes=%" PRIu64 " header_bytes=%" PRIu64
		 " sq_entries=%u cq_entries=%u registration=%s valid=%u\n",
		 stage, queue->qid, queue->current_depth, value.entries,
		 value.payload_bytes, value.registered_bytes, value.header_bytes,
		 queue->ring.sq.ring_entries, queue->ring.cq.ring_entries,
		 queue->allocation_started ? "submitted" : "not-submitted",
		 value.valid);
}

static void fuse_session_destruct_uring(struct fuse_ring_pool *fuse_ring)
{
	uint64_t read_submitted = 0;
	uint64_t read_completed = 0;
	uint64_t read_errors = 0;
	uint64_t read_bytes = 0;
	uint64_t write_submitted = 0;
	uint64_t write_completed = 0;
	uint64_t write_errors = 0;
	uint64_t write_bytes = 0;
	uint64_t copied_fallbacks = 0;
	uint64_t copied_read_fallbacks = 0;
	uint64_t copied_write_fallbacks = 0;

	/* Runtime owners must finish leaving their CQ pump without cancellation
	 * while holding a mutex or awaiting a resource release notification.
	 */
	if (fuse_ring->runtime_qd && fuse_ring->se)
		atomic_store_explicit(&fuse_ring->se->mt_exited, true,
				      memory_order_relaxed);

	for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		if (queue->tid != 0) {
			uint64_t value = 1ULL;
			int rc;

			rc = write(queue->eventfd, &value, sizeof(value));
			if (rc != sizeof(value))
				fprintf(stderr,
					"Wrote to eventfd=%d err=%s: rc=%d\n",
					queue->eventfd, strerror(errno), rc);
			if (fuse_ring->runtime_qd)
				sem_post(&fuse_ring->init_sem);
			else
				pthread_cancel(queue->tid);
			pthread_join(queue->tid, NULL);
			queue->tid = 0;
		}

		fuse_uring_log_allocation(queue, "end");

		if (queue->eventfd >= 0) {
			close(queue->eventfd);
			queue->eventfd = -1;
		}
		if (queue->control_eventfd >= 0)
			close(queue->control_eventfd);

		if (queue->ring.ring_fd != -1)
			io_uring_queue_exit(&queue->ring);

		for (size_t idx = 0; idx < fuse_ring->queue_depth; idx++) {
			struct fuse_ring_ent *ent = &queue->ent[idx];

			if (!fuse_ring->zero_copy && ent->op_payload)
				numa_free(ent->op_payload, ent->req_payload_sz);
			if (ent->req_header) {
				numa_free(ent->req_header, queue->req_header_sz);
				pthread_mutex_destroy(&ent->req.lock);
			}
		}
		if (queue->payload_pool)
			numa_free(queue->payload_pool, queue->payload_pool_sz);
		if (queue->prepared_pool)
			numa_free(queue->prepared_pool, queue->prepared_pool_sz);
		if (queue->prepared_payloads) {
			for (size_t i = 0; i < fuse_ring->queue_depth; i++)
				if (queue->prepared_payloads[i])
					numa_free(queue->prepared_payloads[i],
						  fuse_ring->max_req_payload_sz);
			free(queue->prepared_payloads);
		}
		read_submitted += queue->fixed_read_submitted;
		read_completed += queue->fixed_read_completed;
		read_errors += queue->fixed_read_errors;
		read_bytes += queue->fixed_read_bytes;
		write_submitted += queue->fixed_write_submitted;
		write_completed += queue->fixed_write_completed;
		write_errors += queue->fixed_write_errors;
		write_bytes += queue->fixed_write_bytes;
		copied_fallbacks += queue->copied_fallbacks;
		copied_read_fallbacks += queue->copied_read_fallbacks;
		copied_write_fallbacks += queue->copied_write_fallbacks;

		/* Reuse existing counters after join: no per-request tracing cost. */
		if (queue->fixed_read_submitted || queue->fixed_write_submitted)
			fuse_log(FUSE_LOG_INFO,
				 "FUSE_URING_QUEUE_STATS qid=%zu"
				 " read_submitted=%" PRIu64
				 " read_completed=%" PRIu64
				 " read_errors=%" PRIu64 " read_bytes=%" PRIu64
				 " write_submitted=%" PRIu64
				 " write_completed=%" PRIu64
				 " write_errors=%" PRIu64 " write_bytes=%" PRIu64
				 " copied_read_fallbacks=%" PRIu64
				 " copied_write_fallbacks=%" PRIu64 "\n",
				 qid, queue->fixed_read_submitted,
				 queue->fixed_read_completed, queue->fixed_read_errors,
				 queue->fixed_read_bytes, queue->fixed_write_submitted,
				 queue->fixed_write_completed, queue->fixed_write_errors,
				 queue->fixed_write_bytes, queue->copied_read_fallbacks,
				 queue->copied_write_fallbacks);

		pthread_mutex_destroy(&queue->ring_lock);
	}

	fuse_log(FUSE_LOG_INFO,
		 "FUSE_URING_ZERO_COPY_STATS active=%u read_submitted=%" PRIu64
		 " read_completed=%" PRIu64
		 " read_errors=%" PRIu64 " read_bytes=%" PRIu64
		 " write_submitted=%" PRIu64 " write_completed=%" PRIu64
		 " write_errors=%" PRIu64 " write_bytes=%" PRIu64
		 " copied_fallbacks=%" PRIu64
		 " copied_read_fallbacks=%" PRIu64
		 " copied_write_fallbacks=%" PRIu64 "\n",
		 fuse_ring->zero_copy &&
		 atomic_load_explicit(&fuse_ring->ready_queues,
					 memory_order_relaxed) == fuse_ring->nr_queues,
		 read_submitted, read_completed, read_errors, read_bytes,
		 write_submitted, write_completed, write_errors, write_bytes,
		 copied_fallbacks, copied_read_fallbacks,
		 copied_write_fallbacks);

	free(fuse_ring->cpu_core_ids);
	free(fuse_ring->queues);
	pthread_cond_destroy(&fuse_ring->thread_start_cond);
	pthread_mutex_destroy(&fuse_ring->thread_start_mutex);
	pthread_mutex_destroy(&fuse_ring->control_lock);
	sem_destroy(&fuse_ring->init_sem);
	free(fuse_ring);
}

#ifdef HAVE_URING_ZERO_COPY
static int fuse_uring_submit_control(struct fuse_ring_queue *queue,
				     enum fuse_uring_cmd command)
{
	struct fuse_ring_ent control_ent = { 0 };
	struct fuse_uring_cmd_req *cmd;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int res;

	sqe = io_uring_get_sqe(&queue->ring);
	if (!sqe)
		return -EIO;
	fuse_uring_sqe_prepare(sqe, &control_ent, command);
	cmd = fuse_uring_get_sqe_cmd(sqe);
	fuse_uring_sqe_set_req_data(cmd, queue->qid, 0);

	switch (command) {
	case FUSE_IO_URING_CMD_ADD_QUEUE:
		cmd->flags = FUSE_URING_ZERO_COPY;
		if (queue->write_in_task)
			cmd->flags |= FUSE_URING_WRITE_IN_TASK;
		break;
	case FUSE_IO_URING_CMD_ADD_BUFPOOL:
		cmd->bufpool.uaddr = (uintptr_t)queue->payload_pool;
		cmd->bufpool.len = (uint32_t)queue->payload_pool_sz;
		fuse_uring_use_payload_pool(sqe, queue);
		break;
	default:
		return -EINVAL;
	}

	res = io_uring_submit_and_wait(&queue->ring, 1);
	if (res < 0)
		return res;
	if (!res)
		return -EIO;
	res = io_uring_wait_cqe(&queue->ring, &cqe);
	if (res < 0)
		return res;
	if (io_uring_cqe_get_data(cqe) != &control_ent || cqe->res > 0)
		res = -EPROTO;
	else
		res = cqe->res;
	io_uring_cqe_seen(&queue->ring, cqe);
	return res;
}

static int fuse_uring_setup_zero_copy_queue(struct fuse_ring_queue *queue)
{
	int res;

	if (!queue->sparse_buffers_registered || !queue->payload_pool ||
	    !queue->payload_pool_sz)
		return -EINVAL;
	queue->write_in_task = queue->ring_pool->write_in_task;
	res = fuse_uring_submit_control(queue, FUSE_IO_URING_CMD_ADD_QUEUE);
	if (queue->write_in_task && (res == -EINVAL || res == -EOPNOTSUPP)) {
		/* Older paired kernels reject the new flag before creating a queue. */
		queue->write_in_task = false;
		res = fuse_uring_submit_control(queue, FUSE_IO_URING_CMD_ADD_QUEUE);
	}
	if (res) {
		fuse_log(FUSE_LOG_ERR,
			 "qid=%d FUSE_IO_URING_CMD_ADD_QUEUE failed: %s\n",
			 queue->qid, strerror(-res));
		return res;
	}
	fuse_log(FUSE_LOG_INFO,
		 "FUSE_URING_WRITE_IN_TASK qid=%d requested=%u negotiated=%u\n",
		 queue->qid, queue->ring_pool->write_in_task, queue->write_in_task);
	res = fuse_uring_submit_control(queue, FUSE_IO_URING_CMD_ADD_BUFPOOL);
	if (res) {
		fuse_log(FUSE_LOG_ERR,
			 "qid=%d FUSE_IO_URING_CMD_ADD_BUFPOOL failed: %s\n",
			 queue->qid, strerror(-res));
		return res;
	}
	return 0;
}
#endif

static int fuse_uring_register_ent(struct fuse_ring_queue *queue,
				   struct fuse_ring_ent *ent)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		/*
		 * All SQEs are idle here - no good reason this
		 * could fail
		 */
		fuse_log(FUSE_LOG_ERR, "Failed to get all ring SQEs");
		return -EIO;
	}

	ent->last_cmd = FUSE_IO_URING_CMD_REGISTER;
	fuse_uring_sqe_prepare(sqe, ent, ent->last_cmd);

	/* only needed for fetch */
	ent->iov[0].iov_base = ent->req_header;
	ent->iov[0].iov_len = queue->req_header_sz;

	if (queue->ring_pool->zero_copy) {
		ent->iov[1].iov_base = NULL;
		ent->iov[1].iov_len = 0;
	} else {
		ent->iov[1].iov_base = ent->op_payload;
		ent->iov[1].iov_len = ent->req_payload_sz;
	}

	sqe->addr = (uint64_t)(ent->iov);
	sqe->len = 2;

	/* this is a fetch, kernel does not read commit id */
	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe), queue->qid, 0);
#ifdef HAVE_URING_ZERO_COPY
	if (queue->ring_pool->zero_copy) {
		struct fuse_uring_cmd_req *cmd = fuse_uring_get_sqe_cmd(sqe);

		cmd->ent_zero_copy_buf_index = ent->fixed_buf_index;
		fuse_uring_use_payload_pool(sqe, queue);
	}
#endif

	return 0;

}

static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *queue);
static int fuse_uring_runtime_service(struct fuse_ring_queue *queue);

static uint64_t fuse_uring_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Runtime commands never borrow a stack pointer as CQE user_data. */
/* Keep SQE128's extension out of the compiler's 64-byte SQE size inference. */
static __attribute__((noinline)) void
fuse_uring_runtime_prepare(struct io_uring_sqe *sqe,
				       struct fuse_ring_queue *queue,
				       struct fuse_ring_ent *ent,
				       unsigned int opcode,
				       const struct fuse_uring_runtime_cmd *cmd)
{
	/* liburing's public SQE type describes only the first 64 bytes. */
	struct sqe128_storage {
		struct io_uring_sqe sqe;
		unsigned char extension[64];
	};
	struct sqe128_storage *storage = (void *)sqe;

	fuse_uring_sqe_prepare(sqe, ent, opcode);
	memcpy((char *)storage + offsetof(struct io_uring_sqe, cmd),
	       cmd, sizeof(*cmd));
#ifdef HAVE_URING_ZERO_COPY
	if (opcode == FUSE_IO_URING_CMD_RECONFIG && queue->ring_pool->zero_copy)
		fuse_uring_use_payload_pool(sqe, queue);
#else
	(void)queue;
#endif
}

static struct fuse_uring_runtime_cmd
fuse_uring_runtime_command(struct fuse_ring_queue *queue)
{
	struct fuse_uring_runtime_cmd cmd = {
		.version = FUSE_URING_RUNTIME_VERSION,
		.qid = queue->qid,
		.generation = queue->generation,
	};

	return cmd;
}

/* Submit under the same lock used by copied-mode foreign repliers. */
static int fuse_uring_runtime_flush(struct fuse_ring_queue *queue)
{
	int err;

	pthread_mutex_lock(&queue->ring_lock);
	err = io_uring_submit(&queue->ring);
	pthread_mutex_unlock(&queue->ring_lock);
	return err < 0 ? err : 0;
}

static int fuse_uring_runtime_pump(struct fuse_ring_queue *queue)
{
	struct __kernel_timespec timeout = { .tv_nsec = 10000000 };
	struct io_uring_cqe *cqe;
	int err;

	if (atomic_load_explicit(&queue->ring_pool->se->mt_exited,
				 memory_order_relaxed))
		return -ENOTCONN;
	err = fuse_uring_runtime_flush(queue);
	if (err)
		return err;
	err = io_uring_wait_cqe_timeout(&queue->ring, &cqe, &timeout);
	if (err == -ETIME || err == -EINTR)
		return 0;
	if (err)
		return err;
	atomic_store_explicit(&queue->cqe_processing, true, memory_order_relaxed);
	err = fuse_uring_queue_handle_cqes(queue);
	atomic_store_explicit(&queue->cqe_processing, false, memory_order_relaxed);
	return err;
}

static int fuse_uring_runtime_control(struct fuse_ring_queue *queue,
				      unsigned int opcode,
				      struct fuse_uring_runtime_cmd *cmd)
{
	struct io_uring_sqe *sqe;
	int err;

	/* Only the owner enters this function, and only one control is issued. */
	if (queue->control_pending)
		return -EBUSY;
	pthread_mutex_lock(&queue->ring_lock);
	sqe = io_uring_get_sqe(&queue->ring);
	if (!sqe) {
		pthread_mutex_unlock(&queue->ring_lock);
		return -EAGAIN;
	}
	queue->control_pending = true;
	fuse_uring_runtime_prepare(sqe, queue, &queue->control_ent, opcode, cmd);
	pthread_mutex_unlock(&queue->ring_lock);
	while (queue->control_pending) {
		err = fuse_uring_runtime_pump(queue);
		if (err)
			return err;
	}
	return queue->control_result;
}

static int fuse_uring_runtime_query(struct fuse_ring_queue *queue,
				    struct fuse_uring_runtime_state *state)
{
	struct fuse_uring_runtime_cmd cmd = fuse_uring_runtime_command(queue);
	int err;

	memset(&queue->query_result, 0, sizeof(queue->query_result));
	cmd.result_addr = (uintptr_t)&queue->query_result;
	err = fuse_uring_runtime_control(queue, FUSE_IO_URING_CMD_QUERY, &cmd);
	if (!err)
		*state = queue->query_result;
	return err;
}

static int fuse_uring_runtime_rearm(struct fuse_ring_queue *queue,
				    unsigned int depth)
{
	struct fuse_ring_pool *pool = queue->ring_pool;
	int err = 0;

	queue->rearming = true;
	pthread_mutex_lock(&queue->ring_lock);
	for (unsigned int i = 0; i < depth; i++) {
		struct fuse_ring_ent *ent = &queue->ent[i];
		struct fuse_uring_runtime_cmd cmd = fuse_uring_runtime_command(queue);
		struct io_uring_sqe *sqe;

		if (ent->submitted && !ent->retired)
			continue;
		sqe = io_uring_get_sqe(&queue->ring);
		if (!sqe) {
			err = -EAGAIN;
			break;
		}
		cmd.entry_id = i;
		cmd.header_addr = (uintptr_t)ent->req_header;
		if (!pool->zero_copy) {
			cmd.payload_addr = (uintptr_t)ent->op_payload;
			cmd.len = ent->req_payload_sz;
		}
		ent->last_cmd = FUSE_IO_URING_CMD_REARM;
		ent->rearm_error = 0;
		ent->retired = false;
		ent->submitted = true;
		fuse_uring_runtime_prepare(sqe, queue, ent, ent->last_cmd, &cmd);
#ifdef HAVE_URING_ZERO_COPY
		if (pool->zero_copy)
			fuse_uring_use_payload_pool(sqe, queue);
#endif
	}
	pthread_mutex_unlock(&queue->ring_lock);
	return err;
}

static int fuse_uring_runtime_configuration(struct fuse_ring_queue *queue,
					    unsigned int depth, bool init)
{
	struct fuse_ring_pool *pool = queue->ring_pool;
	struct fuse_uring_runtime_cmd cmd = fuse_uring_runtime_command(queue);

	cmd.flags = init ? FUSE_URING_RUNTIME_INIT : 0;
	cmd.depth = depth;
	cmd.max_depth = pool->queue_depth;
	if (pool->zero_copy) {
		cmd.flags |= FUSE_URING_RUNTIME_ZERO_COPY;
		if (pool->write_in_task)
			cmd.flags |= FUSE_URING_RUNTIME_WRITE_IN_TASK;
		cmd.addr = (uintptr_t)queue->payload_pool;
		cmd.len = queue->payload_pool_sz;
		cmd.pool_index = queue->payload_slot;
	}
	return fuse_uring_runtime_control(queue, FUSE_IO_URING_CMD_RECONFIG, &cmd);
}

static int fuse_uring_runtime_resume(struct fuse_ring_queue *queue)
{
	struct fuse_uring_runtime_cmd cmd = fuse_uring_runtime_command(queue);

	/* QUERY has observed accepted rearm commands before request admission. */
	queue->rearming = false;
	return fuse_uring_runtime_control(queue, FUSE_IO_URING_CMD_RESUME, &cmd);
}

static int fuse_uring_runtime_start_queue(struct fuse_ring_queue *queue)
{
	struct fuse_uring_runtime_state state;
	int err;

	err = fuse_uring_runtime_configuration(queue, queue->current_depth, true);
	if (err)
		return err;
	err = fuse_uring_runtime_rearm(queue, queue->current_depth);
	if (err)
		return err;
	err = fuse_uring_runtime_query(queue, &state);
	if (err)
		return err;
	if (state.active != queue->current_depth)
		return -EIO;
	return fuse_uring_runtime_resume(queue);
}

static int fuse_uring_poll_control(struct fuse_ring_queue *queue)
{
	struct io_uring_sqe *sqe;

	pthread_mutex_lock(&queue->ring_lock);
	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe) {
		io_uring_prep_poll_add(sqe, queue->control_eventfd, POLLIN);
		io_uring_sqe_set_data(sqe,
				     (void *)(uintptr_t)queue->control_eventfd);
	}
	pthread_mutex_unlock(&queue->ring_lock);
	return sqe ? 0 : -EAGAIN;
}

static void fuse_uring_runtime_phase(struct fuse_ring_queue *queue,
				     unsigned int phase)
{
	pthread_mutex_lock(&queue->ring_pool->control_lock);
	queue->runtime_status.phase = phase;
	pthread_mutex_unlock(&queue->ring_pool->control_lock);
}

static bool fuse_uring_runtime_drained(struct fuse_ring_queue *queue)
{
	for (size_t i = 0; i < queue->ring_pool->queue_depth; i++) {
		struct fuse_ring_ent *ent = &queue->ent[i];

		if ((ent->submitted && !ent->retired) || ent->fixed_io_pending ||
		    atomic_load_explicit(&ent->req.ref_cnt, memory_order_acquire) != 1)
			return false;
	}
	return true;
}

static int fuse_uring_runtime_drain(struct fuse_ring_queue *queue)
{
	uint64_t deadline = fuse_uring_now_ms() + queue->ring_pool->drain_timeout_ms;
	int err;

	while (!fuse_uring_runtime_drained(queue)) {
		if (fuse_uring_now_ms() >= deadline)
			return -ETIMEDOUT;
		err = fuse_uring_runtime_pump(queue);
		if (err)
			return err;
	}
	return 0;
}

static int fuse_uring_runtime_pause(struct fuse_ring_queue *queue)
{
	struct fuse_uring_runtime_cmd cmd = fuse_uring_runtime_command(queue);

	return fuse_uring_runtime_control(queue, FUSE_IO_URING_CMD_PAUSE, &cmd);
}

/* Resume old configuration even if a slow request prevented full quiescence. */
static int fuse_uring_runtime_restore(struct fuse_ring_queue *queue,
				      unsigned int depth)
{
	uint64_t deadline = fuse_uring_now_ms() + queue->ring_pool->drain_timeout_ms;
	struct fuse_uring_runtime_state state;
	int err;

	for (;;) {
		err = fuse_uring_runtime_rearm(queue, depth);
		if (err)
			return err;
		err = fuse_uring_runtime_query(queue, &state);
		if (err)
			return err;
		for (size_t i = 0; i < depth; i++)
			if (queue->ent[i].rearm_error)
				return queue->ent[i].rearm_error;
		if (state.active == depth) {
			err = fuse_uring_runtime_resume(queue);
			if (!err)
				return 0;
			/* A concurrently completed COMMIT may have retired an entry. */
			if (err != -EBUSY && err != -EAGAIN)
				return err;
		}
		if (fuse_uring_now_ms() >= deadline)
			return -ETIMEDOUT;
		err = fuse_uring_runtime_pump(queue);
		if (err)
			return err;
	}
}

static unsigned int fuse_uring_alternate_slot(struct fuse_ring_queue *queue)
{
	return queue->payload_slot ? 0 : queue->ring_pool->queue_depth + 1;
}

static int fuse_uring_runtime_prepare_payload(struct fuse_ring_queue *queue,
					      unsigned int depth)
{
	struct fuse_ring_pool *pool = queue->ring_pool;

	if (pool->zero_copy) {
#ifdef HAVE_URING_ZERO_COPY
		unsigned int slot = fuse_uring_alternate_slot(queue);
		unsigned int token = slot ? 1 : 0;
		struct iovec iov;
		__u64 tag = (uintptr_t)&queue->payload_tags[token];
		int err;

		queue->prepared_pool_sz = depth * pool->max_req_payload_sz;
		queue->prepared_pool = numa_alloc_local(queue->prepared_pool_sz);
		if (!queue->prepared_pool) {
			queue->prepared_pool_sz = 0;
			return -ENOMEM;
		}
		iov.iov_base = queue->prepared_pool;
		iov.iov_len = queue->prepared_pool_sz;
		queue->payload_released[token] = false;
		err = io_uring_register_buffers_update_tag(&queue->ring, slot,
							 &iov, &tag, 1);
		if (err != 1) {
			numa_free(queue->prepared_pool, queue->prepared_pool_sz);
			queue->prepared_pool = NULL;
			queue->prepared_pool_sz = 0;
			return err < 0 ? err : -EIO;
		}
#else
		return -ENOTSUP;
#endif
	} else {
		for (unsigned int i = queue->current_depth; i < depth; i++) {
			queue->prepared_payloads[i] = numa_alloc_local(pool->max_req_payload_sz);
			if (!queue->prepared_payloads[i])
				return -ENOMEM;
		}
	}
	return 0;
}

static void fuse_uring_runtime_swap_pool(struct fuse_ring_queue *queue)
{
	void *old = queue->payload_pool;
	size_t old_sz = queue->payload_pool_sz;

	queue->payload_pool = queue->prepared_pool;
	queue->payload_pool_sz = queue->prepared_pool_sz;
	queue->prepared_pool = old;
	queue->prepared_pool_sz = old_sz;
	queue->payload_slot = fuse_uring_alternate_slot(queue);
}

static int fuse_uring_runtime_free_prepared(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *pool = queue->ring_pool;

	if (queue->prepared_pool) {
#ifdef HAVE_URING_ZERO_COPY
		unsigned int slot = fuse_uring_alternate_slot(queue);
		unsigned int token = slot ? 1 : 0;
		struct iovec empty = { 0 };
		__u64 tag = 0;
		int err;

		err = io_uring_register_buffers_update_tag(&queue->ring, slot,
							 &empty, &tag, 1);
		if (err != 1)
			return err < 0 ? err : -EIO;
		/* The tag, not registration's return, proves the old pin is gone. */
		while (!queue->payload_released[token]) {
			err = fuse_uring_runtime_pump(queue);
			if (err)
				return err;
		}
		numa_free(queue->prepared_pool, queue->prepared_pool_sz);
		queue->prepared_pool = NULL;
		queue->prepared_pool_sz = 0;
#else
		return -ENOTSUP;
#endif
	}
	for (size_t i = 0; i < pool->queue_depth; i++) {
		if (queue->prepared_payloads[i]) {
			numa_free(queue->prepared_payloads[i], pool->max_req_payload_sz);
			queue->prepared_payloads[i] = NULL;
		}
	}
	return 0;
}

static void fuse_uring_runtime_publish_memory(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *pool = queue->ring_pool;
	uint64_t reclaim = queue->prepared_pool_sz;

	if (!pool->zero_copy)
		for (size_t i = 0; i < pool->queue_depth; i++)
			if (queue->prepared_payloads[i])
				reclaim += pool->max_req_payload_sz;
	pthread_mutex_lock(&pool->control_lock);
	queue->runtime_status.current_depth = queue->current_depth;
	queue->runtime_status.generation = queue->generation;
	queue->runtime_status.payload_bytes = queue->current_depth * pool->max_req_payload_sz;
	queue->runtime_status.registered_bytes = pool->zero_copy ?
		queue->payload_pool_sz + queue->prepared_pool_sz : 0;
	queue->runtime_status.reclaim_bytes = reclaim;
	pthread_mutex_unlock(&pool->control_lock);
}

/* Returns a recoverable transaction error; fatal is set only if recovery fails. */
static int fuse_uring_runtime_change(struct fuse_ring_queue *queue,
				     unsigned int depth, bool *fatal)
{
	struct fuse_ring_pool *pool = queue->ring_pool;
	struct fuse_uring_runtime_state state;
	unsigned int old_depth = queue->current_depth;
	uint64_t old_generation = queue->generation;
	bool switched = false;
	bool configured = false;
	int err, restore_err;

	if (old_depth == depth)
		return 0;
	fuse_uring_runtime_phase(queue, FUSE_URING_RUNTIME_PREPARING);
	err = fuse_uring_runtime_prepare_payload(queue, depth);
	fuse_uring_runtime_publish_memory(queue);
	if (err)
		goto free_prepared;
	fuse_uring_runtime_phase(queue, FUSE_URING_RUNTIME_DRAINING);
	err = fuse_uring_runtime_pause(queue);
	if (err)
		goto free_prepared;
	err = fuse_uring_runtime_drain(queue);
	if (err)
		goto restore;
	err = fuse_uring_runtime_query(queue, &state);
	if (err || state.state != FUSE_URING_STATE_QUIESCED || state.active) {
		if (!err)
			err = -EBUSY;
		goto restore;
	}
	fuse_uring_runtime_phase(queue, FUSE_URING_RUNTIME_RECONFIGURING);
	if (pool->zero_copy)
		fuse_uring_runtime_swap_pool(queue);
	else
		for (unsigned int i = old_depth; i < depth; i++) {
			queue->ent[i].op_payload = queue->prepared_payloads[i];
			queue->prepared_payloads[i] = NULL;
		}
	switched = true;
	queue->generation++;
	err = fuse_uring_runtime_configuration(queue, depth, false);
	if (err)
		goto restore;
	configured = true;
	err = fuse_uring_runtime_restore(queue, depth);
	if (err)
		goto restore;
	queue->current_depth = depth;
	if (!pool->zero_copy)
		for (unsigned int i = depth; i < old_depth; i++) {
			queue->prepared_payloads[i] = queue->ent[i].op_payload;
			queue->ent[i].op_payload = NULL;
		}
	fuse_uring_runtime_phase(queue, FUSE_URING_RUNTIME_RECLAIMING);
	fuse_uring_runtime_publish_memory(queue);
	err = fuse_uring_runtime_free_prepared(queue);
	if (err)
		*fatal = true;
	fuse_uring_runtime_publish_memory(queue);
	return err;

restore:
	if (queue->control_pending) {
		*fatal = true;
		return err;
	}
	if (configured) {
		/* Retire the unsuccessful new generation before reverting it. */
		restore_err = fuse_uring_runtime_pause(queue);
		if (!restore_err)
			restore_err = fuse_uring_runtime_drain(queue);
		if (restore_err) {
			*fatal = true;
			return restore_err;
		}
	}
	if (switched) {
		if (pool->zero_copy)
			fuse_uring_runtime_swap_pool(queue);
		else
			for (unsigned int i = old_depth; i < depth; i++) {
				queue->prepared_payloads[i] = queue->ent[i].op_payload;
				queue->ent[i].op_payload = NULL;
			}
		queue->generation = configured ? queue->generation + 1 : old_generation;
		if (configured) {
			restore_err = fuse_uring_runtime_configuration(queue, old_depth, false);
			if (restore_err) {
				*fatal = true;
				return restore_err;
			}
		}
	}
	restore_err = fuse_uring_runtime_restore(queue, old_depth);
	if (restore_err) {
		*fatal = true;
		return restore_err;
	}
free_prepared:
	if (queue->control_pending) {
		*fatal = true;
		return err;
	}
	restore_err = fuse_uring_runtime_free_prepared(queue);
	if (restore_err) {
		*fatal = true;
		return restore_err;
	}
	fuse_uring_runtime_publish_memory(queue);
	return err;
}

static int fuse_uring_runtime_service(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *pool = queue->ring_pool;
	struct fuse_ring_queue *next = NULL;
	unsigned int depth;
	bool fatal = false;
	int err;

	pthread_mutex_lock(&pool->control_lock);
	if (!pool->control_busy || pool->control_qid != (unsigned int)queue->qid) {
		pthread_mutex_unlock(&pool->control_lock);
		return 0;
	}
	depth = pool->target_depth;
	pthread_mutex_unlock(&pool->control_lock);
	err = fuse_uring_runtime_change(queue, depth, &fatal);
	pthread_mutex_lock(&pool->control_lock);
	queue->runtime_status.error = err;
	queue->runtime_status.phase = err ? FUSE_URING_RUNTIME_FAILED :
		FUSE_URING_RUNTIME_COMPLETE;
	if (err || ++pool->control_qid == pool->nr_queues) {
		pool->control_error = err;
		pool->control_busy = false;
	} else {
		next = fuse_uring_get_queue(pool, pool->control_qid);
	}
	pthread_mutex_unlock(&pool->control_lock);
	if (next) {
		uint64_t value = 1;

		if (write(next->control_eventfd, &value, sizeof(value)) < 0 &&
		    errno != EAGAIN)
			return -errno;
	}
	return fatal ? err : 0;
}

int fuse_uring_request_qd(struct fuse_session *se, uint32_t depth,
			  uint64_t *transaction)
{
	struct fuse_ring_pool *pool = se->uring.pool;
	struct fuse_ring_queue *first;
	uint64_t value = 1;
	int err = 0;

	if (!pool || !pool->runtime_qd)
		return -ENOTSUP;
	if (!transaction || !depth || depth > pool->queue_depth)
		return -EINVAL;
	if (atomic_load_explicit(&pool->ready_queues, memory_order_acquire) !=
	    pool->nr_queues)
		return -EAGAIN;
	if (atomic_load_explicit(&se->mt_exited, memory_order_relaxed))
		return -ENOTCONN;
	pthread_mutex_lock(&pool->control_lock);
	if (pool->control_busy) {
		err = -EBUSY;
		goto out;
	}
	pool->control_busy = true;
	pool->control_error = 0;
	pool->control_qid = 0;
	pool->target_depth = depth;
	*transaction = ++pool->transaction;
	for (size_t i = 0; i < pool->nr_queues; i++) {
		struct fuse_ring_queue *q = fuse_uring_get_queue(pool, i);

		q->runtime_status.target_depth = depth;
		q->runtime_status.error = 0;
		q->runtime_status.phase = FUSE_URING_RUNTIME_IDLE;
	}
	first = fuse_uring_get_queue(pool, 0);
	if (write(first->control_eventfd, &value, sizeof(value)) < 0 && errno != EAGAIN) {
		err = -errno;
		pool->control_busy = false;
		pool->control_error = err;
	}
out:
	pthread_mutex_unlock(&pool->control_lock);
	return err;
}

int fuse_uring_runtime_status(struct fuse_session *se,
			      struct fuse_uring_runtime_status *status,
			      struct fuse_uring_runtime_queue_status *queues,
			      size_t capacity)
{
	struct fuse_ring_pool *pool = se->uring.pool;

	if (!pool || !pool->runtime_qd)
		return -ENOTSUP;
	if (!status || (capacity && !queues))
		return -EINVAL;
	if (atomic_load_explicit(&pool->ready_queues, memory_order_acquire) !=
	    pool->nr_queues)
		return -EAGAIN;
	if (capacity && capacity < pool->nr_queues)
		return -ENOSPC;
	pthread_mutex_lock(&pool->control_lock);
	*status = (struct fuse_uring_runtime_status) {
		.transaction = pool->transaction,
		.max_depth = pool->queue_depth,
		.nr_queues = pool->nr_queues,
		.busy = pool->control_busy,
		.error = pool->control_error,
	};
	if (capacity)
		for (size_t i = 0; i < pool->nr_queues; i++)
			queues[i] = fuse_uring_get_queue(pool, i)->runtime_status;
	pthread_mutex_unlock(&pool->control_lock);
	return pool->nr_queues;
}

static int fuse_uring_register_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	unsigned int sq_ready;
	struct io_uring_sqe *sqe;
	int res;

	if (ring_pool->runtime_qd) {
		res = fuse_uring_runtime_start_queue(queue);
		if (res)
			return res;
		goto polls;
	}
	for (size_t idx = 0; idx < ring_pool->queue_depth; idx++) {
		struct fuse_ring_ent *ent = &queue->ent[idx];

		res = fuse_uring_register_ent(queue, ent);
		if (res != 0)
			return res;
	}

	sq_ready = io_uring_sq_ready(&queue->ring);
	if (sq_ready != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR,
			 "SQE ready mismatch, expected %zu got %u\n",
			 ring_pool->queue_depth, sq_ready);
		return -EINVAL;
	}

polls:
	/* Poll SQE for the eventfd to wake up on teardown */
	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to get eventfd SQE");
		return -EIO;
	}

	io_uring_prep_poll_add(sqe, queue->eventfd, POLLIN);
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)queue->eventfd);
	if (ring_pool->runtime_qd)
		return fuse_uring_poll_control(queue);

	/* Only preparation until here, no submission yet */

	return 0;
}

static int fuse_uring_submit_registered_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *pool = queue->ring_pool;
	size_t expected = pool->runtime_qd ? io_uring_sq_ready(&queue->ring) :
		pool->queue_depth + 1;
	size_t submitted = 0;
	unsigned int ready;

	while (submitted < expected) {
		int res = io_uring_submit(&queue->ring);

		if (res < 0)
			return res;
		if (res == 0)
			return -EIO;
		submitted += (size_t)res;
	}
	if (submitted != expected)
		return -EIO;

	if (!pool->runtime_qd) {
		queue->allocation_started = true;
		fuse_uring_log_allocation(queue, "start");
	}
	ready = atomic_fetch_add_explicit(&pool->ready_queues, 1,
					 memory_order_acq_rel) + 1;
	if (ready == pool->nr_queues) {
		if (pool->zero_copy) {
			fuse_log(FUSE_LOG_INFO,
				 "FUSE_URING_ZERO_COPY active=1 queues=%zu queue_depth=%zu max_queue_depth=%zu fixed_buf_slot=0 request_slots=%zu register_entries=%zu\n",
				 pool->nr_queues, pool->initial_depth, pool->queue_depth,
				 pool->nr_queues * pool->queue_depth,
				 pool->nr_queues * pool->initial_depth);
		} else {
			fuse_log(FUSE_LOG_INFO,
				 "FUSE_URING_ZERO_COPY active=0 reason=not-requested queues=%zu queue_depth=%zu max_queue_depth=%zu\n",
				 pool->nr_queues, pool->initial_depth, pool->queue_depth);
		}
	}
	return 0;
}

static int *fuse_uring_read_cpu_core_ids(size_t nr_cpus)
{
	int *core_ids = calloc(nr_cpus, sizeof(*core_ids));

	if (!core_ids)
		return NULL;
	for (size_t cpu = 0; cpu < nr_cpus; cpu++) {
		char path[128];
		unsigned int first_sibling;
		FILE *file;

		core_ids[cpu] = -1;
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%zu/topology/thread_siblings_list",
			 cpu);
		file = fopen(path, "re");
		if (!file)
			continue;
		if (fscanf(file, "%u", &first_sibling) == 1 &&
		    first_sibling <= INT_MAX)
			core_ids[cpu] = (int)first_sibling;
		fclose(file);
	}
	return core_ids;
}

static struct fuse_ring_pool *fuse_create_ring(struct fuse_session *se)
{
	struct fuse_ring_pool *fuse_ring = NULL;
	const char *write_in_task = getenv("FUSE_URING_WRITE_IN_TASK");
	const size_t nr_queues = get_nprocs_conf();
	size_t payload_sz = se->bufsize - FUSE_BUFFER_HEADER_SIZE;
	size_t queue_sz;

	if (write_in_task && strcmp(write_in_task, "0") &&
	    strcmp(write_in_task, "1")) {
		fuse_log(FUSE_LOG_ERR, "FUSE_URING_WRITE_IN_TASK must be 0 or 1\n");
		return NULL;
	}
	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "starting io-uring q-depth=%d\n",
			 se->uring.q_depth);

	fuse_ring = calloc(1, sizeof(*fuse_ring));
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}
	pthread_mutex_init(&fuse_ring->control_lock, NULL);
	pthread_cond_init(&fuse_ring->thread_start_cond, NULL);
	pthread_mutex_init(&fuse_ring->thread_start_mutex, NULL);
	sem_init(&fuse_ring->init_sem, 0, 0);

	queue_sz = fuse_ring_queue_size(se->uring.runtime_qd ?
		se->uring.max_depth : se->uring.q_depth);
	fuse_ring->queues = calloc(1, queue_sz * nr_queues);
	if (fuse_ring->queues == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the queues failed\n");
		goto err;
	}

	fuse_ring->se = se;
	fuse_ring->nr_queues = nr_queues;
	fuse_ring->cpu_core_ids = fuse_uring_read_cpu_core_ids(nr_queues);
	fuse_ring->runtime_qd = se->uring.runtime_qd;
	fuse_ring->queue_depth = se->uring.runtime_qd ?
		se->uring.max_depth : se->uring.q_depth;
	fuse_ring->initial_depth = se->uring.q_depth;
	fuse_ring->drain_timeout_ms = se->uring.drain_timeout_ms;
	fuse_ring->max_req_payload_sz = payload_sz;
	fuse_ring->queue_mem_size = queue_sz;
	fuse_ring->single_issuer = se->conn.io_uring_single_issuer;
	fuse_ring->zero_copy =
		(se->conn.want_ext & FUSE_CAP_IO_URING_BUFPOOL) != 0;
	fuse_ring->write_in_task = fuse_ring->zero_copy && fuse_ring->single_issuer &&
		(!write_in_task || !strcmp(write_in_task, "1"));

	/*
	 * very basic queue initialization, that cannot fail and will
	 * allow easy cleanup if something (like mmap) fails in the middle
	 * below
	 */
	for (size_t qid = 0; qid < nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		queue->ring.ring_fd = -1;
		queue->numa_node = numa_node_of_cpu(qid);
		queue->qid = qid;
		queue->ring_pool = fuse_ring;
		queue->eventfd = -1;
		queue->control_eventfd = -1;
		queue->current_depth = se->uring.q_depth;
		queue->generation = 1;
		queue->runtime_status.qid = qid;
		queue->runtime_status.current_depth = se->uring.q_depth;
		queue->runtime_status.target_depth = se->uring.q_depth;
		queue->runtime_status.generation = 1;
		queue->runtime_status.payload_bytes = se->uring.q_depth * payload_sz;
		pthread_mutex_init(&queue->ring_lock, NULL);
	}

	return fuse_ring;

err:
	if (fuse_ring)
		fuse_session_destruct_uring(fuse_ring);

	return NULL;
}

static void fuse_uring_resubmit(struct fuse_ring_queue *queue,
				struct fuse_ring_ent *ent)
{
	const bool locked = !queue->ring_pool->single_issuer;
	struct io_uring_sqe *sqe;
	int res = 0;

	if (fuse_uring_check_queue_owner(queue))
		return;

	if (locked)
		pthread_mutex_lock(&queue->ring_lock);

	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		/* This is an impossible condition, unless there is a bug.
		 * The kernel sent back an SQEs, which is assigned to a request.
		 * There is no way to get out of SQEs, as the number of
		 * SQEs matches the number tof requests.
		 */

		if (locked)
			pthread_mutex_unlock(&queue->ring_lock);
		queue->ring_pool->se->error = -EIO;
		fuse_log(FUSE_LOG_ERR, "Failed to get a ring SQEs\n");

		return;
	}

	fuse_uring_sqe_prepare(sqe, ent, ent->last_cmd);

	switch (ent->last_cmd) {
	case FUSE_IO_URING_CMD_REGISTER:
		sqe->addr = (uint64_t)(ent->iov);
		sqe->len = 2;
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, 0);
#ifdef HAVE_URING_ZERO_COPY
		if (queue->ring_pool->zero_copy) {
			struct fuse_uring_cmd_req *cmd =
				fuse_uring_get_sqe_cmd(sqe);

			cmd->ent_zero_copy_buf_index = ent->fixed_buf_index;
			fuse_uring_use_payload_pool(sqe, queue);
		}
#endif
		break;
	case FUSE_IO_URING_CMD_COMMIT_AND_FETCH:
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, ent->req_commit_id);
		if (queue->ring_pool->runtime_qd)
			((struct fuse_uring_cmd_req *)fuse_uring_get_sqe_cmd(sqe))->flags =
				queue->generation;
#ifdef HAVE_URING_ZERO_COPY
		if (queue->ring_pool->zero_copy)
			fuse_uring_use_payload_pool(sqe, queue);
#endif
		break;
	default:
		fuse_log(FUSE_LOG_ERR, "Unknown command type: %d\n",
			 ent->last_cmd);
		queue->ring_pool->se->error = -EINVAL;
		break;
	}

	if (!atomic_load_explicit(&queue->cqe_processing, memory_order_relaxed))
		res = io_uring_submit(&queue->ring);
	if (locked)
		pthread_mutex_unlock(&queue->ring_lock);
	if (res < 0) {
		queue->ring_pool->se->error = res;
		fuse_session_exit(queue->ring_pool->se);
	}
}

static int fuse_uring_handle_cqe(struct fuse_ring_queue *queue,
				 struct io_uring_cqe *cqe)
{
	struct fuse_ring_ent *ent = io_uring_cqe_get_data(cqe);
	struct fuse_uring_ent_in_out *ent_in_out;
	struct fuse_ring_pool *fuse_ring = queue->ring_pool;
	struct fuse_req *req;
	struct fuse_uring_req_header *rrh;
	struct fuse_in_header *in;
	bool zero_copy;

	if (!ent) {
		fuse_log(FUSE_LOG_ERR,
			 "cqe=%p io_uring_cqe_get_data returned NULL\n", cqe);
		return -EIO;
	}

	req = &ent->req;
	rrh = ent->req_header;
	in = (struct fuse_in_header *)&rrh->in_out;
	ent_in_out = &rrh->ring_ent_in_out;

	ent->req_commit_id = ent_in_out->commit_id;
	if (unlikely(ent->req_commit_id == 0)) {
		/*
		 * If this happens kernel will not find the response - it will
		 * be stuck forever - better to abort immediately.
		 */
		fuse_log(FUSE_LOG_ERR, "Received invalid commit_id=0\n");
		abort();
	}
	if (ent_in_out->payload_sz > fuse_ring->max_req_payload_sz ||
	    ent_in_out->reserved ||
	    (ent_in_out->flags & ~FUSE_URING_ENT_ZERO_COPY)) {
		fuse_log(FUSE_LOG_ERR,
			 "qid=%d invalid io_uring request metadata flags=%" PRIu64
			 " payload=%u offset=%u reserved=%" PRIu64 "\n",
			 queue->qid, ent_in_out->flags, ent_in_out->payload_sz,
			 ent_in_out->offset, ent_in_out->reserved);
		return -EPROTO;
	}

	zero_copy = (ent_in_out->flags & FUSE_URING_ENT_ZERO_COPY) != 0;
	if (fuse_ring->zero_copy) {
		if (ent_in_out->offset > queue->payload_pool_sz ||
		    fuse_ring->max_req_payload_sz >
			    queue->payload_pool_sz - ent_in_out->offset ||
		    (zero_copy && in->opcode != FUSE_READ &&
		     in->opcode != FUSE_WRITE)) {
			fuse_log(FUSE_LOG_ERR,
				 "qid=%d invalid zero-copy request opcode=%u flags=%" PRIu64
				 " offset=%u\n",
				 queue->qid, in->opcode, ent_in_out->flags,
				 ent_in_out->offset);
			return -EPROTO;
		}
		ent->op_payload = (char *)queue->payload_pool +
				  ent_in_out->offset;
	} else if (zero_copy || ent_in_out->offset) {
		fuse_log(FUSE_LOG_ERR,
			 "qid=%d received buffer-pool metadata without a pool\n",
			 queue->qid);
		return -EPROTO;
	}

	memset(&req->flags, 0, sizeof(req->flags));
	memset(&req->u, 0, sizeof(req->u));
	req->flags.is_uring = 1;
	req->flags.is_uring_zero_copy = zero_copy;
	ent->fixed_io_completed = false;
	if (fuse_ring->zero_copy && !zero_copy &&
	    (in->opcode == FUSE_READ || in->opcode == FUSE_WRITE)) {
		queue->copied_fallbacks++;
		if (in->opcode == FUSE_READ)
			queue->copied_read_fallbacks++;
		else
			queue->copied_write_fallbacks++;
	}
	req->ref_cnt++;
	req->ch = NULL; /* not needed for uring */
	req->interrupted = 0;
	list_init_req(req);

	fuse_session_process_uring_cqe(fuse_ring->se, req, in, &rrh->op_in,
				       ent->op_payload, ent_in_out->payload_sz);
	return 0;
}

static int fuse_uring_handle_fixed_io_cqe(struct fuse_ring_queue *queue,
					   struct fuse_ring_ent *ent,
					   int result)
{
	fuse_uring_fixed_io_callback_t callback = ent->fixed_io_callback;
	void *userdata = ent->fixed_io_userdata;
	bool write_to_fd = ent->fixed_io_write;

	if (!ent->fixed_io_pending || !callback) {
		fuse_log(FUSE_LOG_ERR,
			 "qid=%d unexpected fixed-I/O completion\n", queue->qid);
		return -EIO;
	}
	ent->fixed_io_pending = false;
	ent->fixed_io_callback = NULL;
	ent->fixed_io_userdata = NULL;
	ent->cqe_kind = FUSE_URING_CQE_COMMAND;
	ent->fixed_io_completed = true;

	if (write_to_fd) {
		if (result < 0)
			queue->fixed_write_errors++;
		else {
			queue->fixed_write_completed++;
			queue->fixed_write_bytes += (uint64_t)result;
		}
	} else {
		if (result < 0)
			queue->fixed_read_errors++;
		else {
			queue->fixed_read_completed++;
			queue->fixed_read_bytes += (uint64_t)result;
		}
	}

	callback(&ent->req, result, userdata);
	return 0;
}

static bool fuse_uring_cqe_is_fixed_io(struct fuse_ring_queue *queue,
				      struct io_uring_cqe *cqe)
{
	struct fuse_ring_ent *ent = io_uring_cqe_get_data(cqe);

	if ((uintptr_t)ent == (unsigned int)queue->eventfd)
		return false;
	if (queue->ring_pool->runtime_qd &&
	    ((uintptr_t)ent == (unsigned int)queue->control_eventfd ||
	     ent == &queue->control_ent ||
	     (void *)ent == &queue->payload_tags[0] ||
	     (void *)ent == &queue->payload_tags[1]))
		return false;
	return ent && ent->cqe_kind == FUSE_URING_CQE_FIXED_IO;
}

static int fuse_uring_dispatch_cqe(struct fuse_ring_queue *queue,
				  struct io_uring_cqe *cqe, bool fixed_io,
				  bool *stop)
{
	struct fuse_session *se = queue->ring_pool->se;
	struct fuse_ring_ent *ent = io_uring_cqe_get_data(cqe);
	int err = cqe->res;

	if ((uintptr_t)ent == (unsigned int)queue->eventfd) {
		if (err > 0) {
			*stop = true;
			return -ENOTCONN;
		}
		return err < 0 && err != -ECANCELED ? err : 0;
	}
	if (queue->ring_pool->runtime_qd) {
		if ((uintptr_t)ent == (unsigned int)queue->control_eventfd) {
			uint64_t value;

			if (err < 0)
				return err == -ECANCELED ? 0 : err;
			if (read(queue->control_eventfd, &value, sizeof(value)) < 0 &&
			    errno != EAGAIN)
				return -errno;
			return fuse_uring_poll_control(queue);
		}
		if (ent == &queue->control_ent) {
			queue->control_result = err;
			queue->control_pending = false;
			return 0;
		}
		for (unsigned int i = 0; i < 2; i++) {
			if ((void *)ent == &queue->payload_tags[i]) {
				if (err)
					return -EIO;
				queue->payload_released[i] = true;
				return 0;
			}
		}
		if (!fixed_io && err == FUSE_URING_CQE_RETIRED) {
			ent->retired = true;
			return 0;
		}
		if (!fixed_io && err < 0 &&
		    ent->last_cmd == FUSE_IO_URING_CMD_REARM) {
			if (!queue->rearming) {
				if (err == -ENOTCONN)
					return 0;
				se->error = err;
				return err;
			}
			ent->retired = true;
			ent->rearm_error = err;
			return 0;
		}
	}
	if (fixed_io)
		return fuse_uring_handle_fixed_io_cqe(queue, ent, err);
	if (unlikely(err != 0)) {
		switch (err) {
		case -EAGAIN:
			fallthrough;
		case -EINTR:
			fuse_uring_resubmit(queue, ent);
			return 0;
		default:
			break;
		}
		/* -ENOTCONN is ok on umount */
		if (err != -ENOTCONN) {
			se->error = err;
			return err;
		}
		return 0;
	}
	return fuse_uring_handle_cqe(queue, cqe);
}

#define FUSE_URING_CQE_BATCH_MAX 32

static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *queue)
{
	struct {
		struct io_uring_cqe *cqe;
		bool fixed_io;
	} ready[FUSE_URING_CQE_BATCH_MAX];
	size_t num_completed = 0;
	struct io_uring_cqe *cqe;
	unsigned int head;
	bool stop = false;
	int ret = 0;

	if (!queue->ring_pool->zero_copy) {
		/* Preserve the original order for copied/multi-issuer transport. */
		io_uring_for_each_cqe(&queue->ring, head, cqe) {
			int err = fuse_uring_dispatch_cqe(
				queue, cqe, fuse_uring_cqe_is_fixed_io(queue, cqe),
				&stop);

			if (stop)
				return err;
			num_completed++;
			if (err && !ret)
				ret = err;
		}
		goto advance;
	}

	/*
	 * A completed lower WRITE can still own a daemon mutation until its
	 * callback runs. Finish already-ready fixed I/O before admitting new
	 * request callbacks, so GETATTR need not observe that obsolete ACTIVE
	 * state. Snapshot kinds too: a completion callback changes its entry
	 * back to COMMAND and may enqueue the next COMMIT_AND_FETCH.
	 * CQ storage stays owned until both passes finish; arrivals during the
	 * callbacks belong to the next batch. No wait or allocation is added.
	 */
	io_uring_for_each_cqe(&queue->ring, head, cqe) {
		ready[num_completed].cqe = cqe;
		ready[num_completed].fixed_io = fuse_uring_cqe_is_fixed_io(queue, cqe);
		if (++num_completed == FUSE_URING_CQE_BATCH_MAX)
			break;
	}
	for (unsigned int pass = 0; pass < 2; pass++) {
		for (size_t index = 0; index < num_completed; index++) {
			int err;

			if (ready[index].fixed_io != (pass == 0))
				continue;
			err = fuse_uring_dispatch_cqe(
				queue, ready[index].cqe, ready[index].fixed_io, &stop);
			if (stop)
				return err;
			if (err && !ret)
				ret = err;
		}
	}
advance:
	if (num_completed)
		io_uring_cq_advance(&queue->ring, num_completed);
	return ret;
}

/*
 * The kernel selects a synchronous request queue from task_cpu(current).
 * Binding that queue's userspace thread to the same CPU makes the request
 * issuer and handler time-share one CPU. Background requests may be balanced
 * independently. Keep each queue on the same NUMA node when possible, but use
 * a different physical core allowed by the daemon's affinity mask. Logical
 * CPU qid+1 can be qid's SMT sibling, so CPU-number rotation alone is not enough.
 */
static void fuse_uring_set_thread_cpu(struct fuse_ring_queue *queue)
{
	struct bitmask *allowed_cpus;
	struct bitmask *local_cpus;
	int target_cpu;
	int rc;

	allowed_cpus = numa_allocate_cpumask();
	local_cpus = numa_allocate_cpumask();
	if (allowed_cpus == NULL || local_cpus == NULL) {
		fuse_log(FUSE_LOG_ERR,
			 "Failed to allocate affinity masks for qid=%d\n",
			 queue->qid);
		goto out;
	}

	rc = numa_sched_getaffinity(0, allowed_cpus);
	if (fuse_uring_affinity_query_failed(rc)) {
		fuse_log(FUSE_LOG_ERR,
			 "Failed to read affinity for qid=%d: %s\n", queue->qid,
			 strerror(errno));
		goto out;
	}

	numa_bitmask_clearall(local_cpus);
	if (queue->numa_node >= 0 &&
	    numa_node_to_cpus(queue->numa_node, local_cpus) != 0)
		numa_bitmask_clearall(local_cpus);

	target_cpu = fuse_uring_select_thread_core(
		queue->qid, allowed_cpus, local_cpus,
		queue->ring_pool->cpu_core_ids, queue->ring_pool->nr_queues);
	if (target_cpu < 0) {
		fuse_log(FUSE_LOG_ERR, "No allowed CPU for qid=%d\n",
			 queue->qid);
		goto out;
	}

	numa_bitmask_clearall(local_cpus);
	numa_bitmask_setbit(local_cpus, target_cpu);
	rc = numa_sched_setaffinity(0, local_cpus);
	if (rc != 0) {
		fuse_log(FUSE_LOG_ERR, "Failed to bind qid=%d to CPU=%d: %s\n",
			 queue->qid, target_cpu, strerror(errno));
		goto out;
	}

	fuse_log(FUSE_LOG_DEBUG, "Bound qid=%d ring thread to CPU=%d\n",
		 queue->qid, target_cpu);

out:
	if (local_cpus != NULL)
		numa_free_cpumask(local_cpus);
	if (allowed_cpus != NULL)
		numa_free_cpumask(allowed_cpus);
}

/*
 * @return negative error code or io-uring file descriptor
 */
static int fuse_uring_init_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring = queue->ring_pool;
	struct fuse_session *se = ring->se;
	int res;
	size_t page_sz = sysconf(_SC_PAGESIZE);

	queue->eventfd = eventfd(0, EFD_CLOEXEC);
	if (queue->eventfd < 0) {
		res = -errno;
		fuse_log(FUSE_LOG_ERR,
			 "Failed to create eventfd for qid %d: %s\n",
			 queue->qid, strerror(errno));
		return res;
	}
	if (ring->runtime_qd) {
		queue->control_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (queue->control_eventfd < 0)
			return -errno;
		queue->prepared_payloads = calloc(ring->queue_depth, sizeof(void *));
		if (!queue->prepared_payloads)
			return -ENOMEM;
	}

	res = fuse_queue_setup_io_uring(&queue->ring, queue->qid,
					ring->queue_depth, se->fd,
					queue->eventfd, ring->single_issuer,
					ring->runtime_qd);
	if (res != 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d io_uring init failed\n",
			 queue->qid);
		return res;
	}

	queue->req_header_sz = ROUND_UP(sizeof(struct fuse_uring_req_header),
				       page_sz);
	if (ring->zero_copy) {
#ifdef HAVE_URING_ZERO_COPY
		struct iovec payload_iov;
		__u64 payload_tag = ring->runtime_qd ?
			(uintptr_t)&queue->payload_tags[0] : 0;

		if (ring->queue_depth > UINT_MAX - 1 ||
		    ring->max_req_payload_sz >
			    UINT32_MAX / ring->queue_depth)
			return -EOVERFLOW;
		queue->payload_pool_sz = ring->initial_depth *
					 ring->max_req_payload_sz;
		queue->payload_pool = numa_alloc_local(queue->payload_pool_sz);
		if (!queue->payload_pool)
			return -ENOMEM;

		res = io_uring_register_buffers_sparse(
			&queue->ring, (unsigned int)ring->queue_depth +
			(ring->runtime_qd ? 2 : 1));
		if (res)
			return res;
		queue->sparse_buffers_registered = true;
		payload_iov.iov_base = queue->payload_pool;
		payload_iov.iov_len = queue->payload_pool_sz;
		res = io_uring_register_buffers_update_tag(
			&queue->ring, 0, &payload_iov, &payload_tag, 1);
		if (res != 1)
			return res < 0 ? res : -EIO;
		queue->runtime_status.registered_bytes = queue->payload_pool_sz;
#else
		return -ENOTSUP;
#endif
	}

	for (size_t idx = 0; idx < ring->queue_depth; idx++) {
		struct fuse_ring_ent *ring_ent = &queue->ent[idx];
		struct fuse_req *req = &ring_ent->req;

		ring_ent->ring_queue = queue;

		/*
		 * Also allocate the header to have it page aligned, which
		 * is a requirement for page pinning
		 */
		ring_ent->req_header =
			numa_alloc_local(queue->req_header_sz);
		if (!ring_ent->req_header)
			return -ENOMEM;
		pthread_mutex_init(&req->lock, NULL);
		ring_ent->req_payload_sz = ring->max_req_payload_sz;
		ring_ent->fixed_buf_index = (unsigned int)idx + 1;

		if (ring->zero_copy) {
			ring_ent->op_payload = idx < ring->initial_depth ?
				(char *)queue->payload_pool +
				idx * ring_ent->req_payload_sz : NULL;
		} else if (idx < ring->initial_depth) {
			ring_ent->op_payload =
				numa_alloc_local(ring_ent->req_payload_sz);
			if (!ring_ent->op_payload)
				return -ENOMEM;
		}

		req->se = se;
		req->flags.is_uring = 1;
		req->ref_cnt = 1; /* extra ref to avoid destruction */
		list_init_req(req);
	}

	return queue->ring.ring_fd;
}

static void *fuse_uring_thread(void *arg)
{
	struct fuse_ring_queue *queue = arg;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	const bool single_issuer = ring_pool->single_issuer;
	int err;
	char thread_name[16] = { 0 };

	snprintf(thread_name, 16, "fuse-ring-%d", queue->qid);
	thread_name[15] = '\0';
	fuse_set_thread_name(thread_name);

	fuse_uring_set_thread_cpu(queue);

	err = fuse_uring_init_queue(queue);
	pthread_mutex_lock(&ring_pool->thread_start_mutex);
	if (err < 0)
		ring_pool->failed_threads++;
	ring_pool->started_threads++;
	pthread_cond_broadcast(&ring_pool->thread_start_cond);
	pthread_mutex_unlock(&ring_pool->thread_start_mutex);

	if (err < 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d queue setup failed\n",
			 queue->qid);
		goto err_non_fatal;
	}

	sem_wait(&ring_pool->init_sem);
	if (atomic_load_explicit(&se->mt_exited, memory_order_relaxed))
		return NULL;

	if (ring_pool->zero_copy && !ring_pool->runtime_qd) {
#ifdef HAVE_URING_ZERO_COPY
		err = fuse_uring_setup_zero_copy_queue(queue);
#else
		err = -ENOTSUP;
#endif
		if (err)
			goto err;
	}
	err = fuse_uring_register_queue(queue);
	if (err)
		goto err;
	err = fuse_uring_submit_registered_queue(queue);
	if (err)
		goto err;

	/* Not using fuse_session_exited(se), as that cannot be inlined */
	while (!atomic_load_explicit(&se->mt_exited, memory_order_relaxed)) {
		/*
		 * Single-issuer: one combined submit_and_wait() flushes the
		 * previous iteration's batched replies and waits. Multi-issuer:
		 * split it - wait only here (no ring_lock) so off-thread
		 * repliers keep submitting; the batched inline replies are
		 * flushed below. The returned cqe is ignored; handle_cqes()
		 * re-scans and advances the CQ.
		 */
		if (single_issuer) {
			err = io_uring_submit_and_wait(&queue->ring, 1);
			if (err < 0)
				goto err;
		} else {
			struct io_uring_cqe *cqe;

			err = io_uring_wait_cqe(&queue->ring, &cqe);
			if (err < 0)
				goto err;
		}

		/*
		 * Batch inline replies (commit_sqe()/resubmit()) across cqe
		 * handling. Lock-free: the flag only gates who submits, while
		 * the SQ stays serialised by ring_lock, so a reply that batched
		 * here is always flushed by the submit below before the next
		 * wait - it is never stranded.
		 */
		atomic_store_explicit(&queue->cqe_processing, true,
				      memory_order_relaxed);

		err = fuse_uring_queue_handle_cqes(queue);
		if (err < 0)
			goto err;

		atomic_store_explicit(&queue->cqe_processing, false,
				      memory_order_relaxed);
		if (ring_pool->runtime_qd) {
			err = fuse_uring_runtime_service(queue);
			if (err < 0)
				goto err;
		}

		/*
		 * Multi-issuer does not use io_uring_submit_and_wait(),
		 * but io_uring_wait_cqe() and locked io_uring_submit().
		 */
		if (!single_issuer) {
			pthread_mutex_lock(&queue->ring_lock);
			err = io_uring_submit(&queue->ring);
			pthread_mutex_unlock(&queue->ring_lock);
			if (err < 0)
				goto err;
		}
	}

	return NULL;

err:
	/* A normal unmount must not replace success or an earlier error. */
	if (err < 0 && err != -ENOTCONN)
		se->error = err;
	fuse_session_exit(se);
err_non_fatal:
	return NULL;
}

static int fuse_uring_start_ring_threads(struct fuse_ring_pool *ring)
{
	int rc = 0;

	for (size_t qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		rc = pthread_create(&queue->tid, NULL, fuse_uring_thread, queue);
		if (rc != 0)
			break;
	}

	return rc;
}

static int fuse_uring_sanity_check(struct fuse_session *se)
{
	if (se->uring.q_depth == 0) {
		fuse_log(FUSE_LOG_ERR, "io-uring queue depth must be > 0\n");
		return -EINVAL;
	}
	if (se->uring.runtime_qd &&
	    (!se->uring.max_depth || se->uring.q_depth > se->uring.max_depth ||
	     se->uring.max_depth >= UINT16_MAX || !se->uring.drain_timeout_ms))
		return -EINVAL;
	if (se->uring.runtime_qd &&
	    !(se->conn.want_ext & FUSE_CAP_IO_URING_RUNTIME))
		return -ENOTSUP;
	if ((se->conn.want_ext & FUSE_CAP_IO_URING_BUFPOOL) &&
	    !se->conn.io_uring_single_issuer) {
		fuse_log(FUSE_LOG_ERR,
			 "io-uring zero-copy requires single-issuer queues\n");
		return -EINVAL;
	}
	if ((se->conn.want_ext & FUSE_CAP_IO_URING_BUFPOOL) &&
	    se->uring.q_depth > UINT16_MAX) {
		fuse_log(FUSE_LOG_ERR,
			 "io-uring zero-copy queue depth exceeds the 16-bit buffer index\n");
		return -EOVERFLOW;
	}
#ifndef HAVE_URING_ZERO_COPY
	if (se->conn.want_ext & FUSE_CAP_IO_URING_BUFPOOL)
		return -ENOTSUP;
#endif

	_Static_assert(sizeof(struct fuse_uring_cmd_req) <=
		       FUSE_URING_MAX_SQE128_CMD_DATA,
		       "SQE128_CMD_DATA has 80B cmd data");
	_Static_assert(sizeof(struct fuse_uring_runtime_cmd) == 80,
		       "Runtime command must occupy exactly the SQE128 command area");

	return 0;
}

int fuse_uring_start(struct fuse_session *se)
{
	int err = 0;
	struct fuse_ring_pool *fuse_ring;

	err = fuse_uring_sanity_check(se);
	if (err)
		return err;

	fuse_ring = fuse_create_ring(se);
	if (fuse_ring == NULL) {
		err = -EADDRNOTAVAIL;
		goto err;
	}

	pthread_mutex_lock(&se->uring.runtime_lock);
	se->uring.pool = fuse_ring;
	pthread_mutex_unlock(&se->uring.runtime_lock);
	err = fuse_uring_start_ring_threads(fuse_ring);
	if (err)
		goto err;

	/*
	 * Wait for all threads to start or to fail
	 */
	pthread_mutex_lock(&fuse_ring->thread_start_mutex);
	while (fuse_ring->started_threads < fuse_ring->nr_queues)
		pthread_cond_wait(&fuse_ring->thread_start_cond,
				  &fuse_ring->thread_start_mutex);

	if (fuse_ring->failed_threads != 0)
		err = -EADDRNOTAVAIL;
	pthread_mutex_unlock(&fuse_ring->thread_start_mutex);

err:
	if (err) {
		/* Note all threads need to have been started */
		pthread_mutex_lock(&se->uring.runtime_lock);
		se->uring.pool = NULL;
		pthread_mutex_unlock(&se->uring.runtime_lock);
		if (fuse_ring)
			fuse_session_destruct_uring(fuse_ring);
	}
	return err;
}

int fuse_uring_stop(struct fuse_session *se)
{
	struct fuse_ring_pool *ring;

	fuse_adaptive_stop(se);
	pthread_mutex_lock(&se->uring.runtime_lock);
	ring = se->uring.pool;
	se->uring.pool = NULL;
	pthread_mutex_unlock(&se->uring.runtime_lock);

	if (ring)
		fuse_session_destruct_uring(ring);

	return 0;
}

void fuse_uring_wake_ring_threads(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	/* Wake up the threads to let them send SQEs */
	for (size_t qid = 0; qid < ring->nr_queues; qid++)
		sem_post(&ring->init_sem);
}
