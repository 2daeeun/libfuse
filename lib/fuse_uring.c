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
	size_t req_header_sz;
	struct io_uring ring;

	pthread_mutex_t ring_lock;

	/* batched inline replies across cqe handling; flushed by the loop */
	_Atomic bool cqe_processing;

	/* Slot zero owns this queue's shared command payload pool. */
	void *payload_pool;
	size_t payload_pool_sz;
	bool sparse_buffers_registered;
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

	/* number of queues */
	size_t nr_queues;

	/* number of per queue entries */
	size_t queue_depth;

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
static void fuse_uring_use_payload_pool(struct io_uring_sqe *sqe)
{
	sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
	sqe->buf_index = 0;
}
#endif

static int fuse_uring_commit_sqe(struct fuse_ring_pool *ring_pool,
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
#ifdef HAVE_URING_ZERO_COPY
	if (ring_pool->zero_copy)
		fuse_uring_use_payload_pool(sqe);
#endif

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "    unique: %" PRIu64 ", result=%d\n",
			 out->unique, ent_in_out->payload_sz);
	}

	if (!atomic_load_explicit(&queue->cqe_processing, memory_order_relaxed))
		io_uring_submit(&queue->ring);

	if (locked)
		pthread_mutex_unlock(&queue->ring_lock);

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
				     max_payload_sz))
		fuse_log(FUSE_LOG_ERR,
			 "copied io_uring reply exceeds buffer size %zu",
			 max_payload_sz);

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
				     bool single_issuer)
{
	int rc;
	struct io_uring_params params = {0};
	int files[2] = { fd, evfd };

	depth += 1; /* for the eventfd poll SQE */

	params.flags = IORING_SETUP_SQE128;

	/* Replies are batched and flushed in one io_uring_enter; don't let a
	 * single failing commit SQE stall submission of the rest of the batch.
	 */
	params.flags |= IORING_SETUP_SUBMIT_ALL;

	/* Avoid cq overflow */
	params.flags |= IORING_SETUP_CQSIZE;
	params.cq_entries = depth * 2;

	/* These flags should help to increase performance, but actually
	 * make it a bit slower - reason should get investigated.
	 */
	if (0) {
		/* Has the main slow down effect */
		params.flags |= IORING_SETUP_SINGLE_ISSUER;

		// params.flags |= IORING_SETUP_DEFER_TASKRUN;
		params.flags |= IORING_SETUP_TASKRUN_FLAG;

		/* Second main effect to make it slower */
		params.flags |= IORING_SETUP_COOP_TASKRUN;
	}

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

	return 0;
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
			pthread_cancel(queue->tid);
			pthread_join(queue->tid, NULL);
			queue->tid = 0;
		}

		if (queue->eventfd >= 0) {
			close(queue->eventfd);
			queue->eventfd = -1;
		}

		if (queue->ring.ring_fd != -1)
			io_uring_queue_exit(&queue->ring);

		for (size_t idx = 0; idx < fuse_ring->queue_depth; idx++) {
			struct fuse_ring_ent *ent = &queue->ent[idx];

			if (!fuse_ring->zero_copy)
				numa_free(ent->op_payload, ent->req_payload_sz);
			numa_free(ent->req_header, queue->req_header_sz);
		}
		if (queue->payload_pool)
			numa_free(queue->payload_pool, queue->payload_pool_sz);
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

	free(fuse_ring->queues);
	pthread_cond_destroy(&fuse_ring->thread_start_cond);
	pthread_mutex_destroy(&fuse_ring->thread_start_mutex);
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
		break;
	case FUSE_IO_URING_CMD_ADD_BUFPOOL:
		cmd->bufpool.uaddr = (uintptr_t)queue->payload_pool;
		cmd->bufpool.len = (uint32_t)queue->payload_pool_sz;
		fuse_uring_use_payload_pool(sqe);
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
	res = fuse_uring_submit_control(queue, FUSE_IO_URING_CMD_ADD_QUEUE);
	if (res) {
		fuse_log(FUSE_LOG_ERR,
			 "qid=%d FUSE_IO_URING_CMD_ADD_QUEUE failed: %s\n",
			 queue->qid, strerror(-res));
		return res;
	}
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
		fuse_uring_use_payload_pool(sqe);
	}
#endif

	return 0;

}

static int fuse_uring_register_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	unsigned int sq_ready;
	struct io_uring_sqe *sqe;
	int res;

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

	/* Poll SQE for the eventfd to wake up on teardown */
	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to get eventfd SQE");
		return -EIO;
	}

	io_uring_prep_poll_add(sqe, queue->eventfd, POLLIN);
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)queue->eventfd);

	/* Only preparation until here, no submission yet */

	return 0;
}

static int fuse_uring_submit_registered_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *pool = queue->ring_pool;
	size_t expected = pool->queue_depth + 1;
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

	ready = atomic_fetch_add_explicit(&pool->ready_queues, 1,
					 memory_order_acq_rel) + 1;
	if (ready == pool->nr_queues) {
		if (pool->zero_copy) {
			fuse_log(FUSE_LOG_INFO,
				 "FUSE_URING_ZERO_COPY active=1 queues=%zu queue_depth=%zu fixed_buf_slot=0 request_slots=%zu register_entries=%zu\n",
				 pool->nr_queues, pool->queue_depth,
				 pool->nr_queues * pool->queue_depth,
				 pool->nr_queues * pool->queue_depth);
		} else {
			fuse_log(FUSE_LOG_INFO,
				 "FUSE_URING_ZERO_COPY active=0 reason=not-requested queues=%zu queue_depth=%zu\n",
				 pool->nr_queues, pool->queue_depth);
		}
	}
	return 0;
}

static struct fuse_ring_pool *fuse_create_ring(struct fuse_session *se)
{
	struct fuse_ring_pool *fuse_ring = NULL;
	const size_t nr_queues = get_nprocs_conf();
	size_t payload_sz = se->bufsize - FUSE_BUFFER_HEADER_SIZE;
	size_t queue_sz;

	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "starting io-uring q-depth=%d\n",
			 se->uring.q_depth);

	fuse_ring = calloc(1, sizeof(*fuse_ring));
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}

	queue_sz = fuse_ring_queue_size(se->uring.q_depth);
	fuse_ring->queues = calloc(1, queue_sz * nr_queues);
	if (fuse_ring->queues == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the queues failed\n");
		goto err;
	}

	fuse_ring->se = se;
	fuse_ring->nr_queues = nr_queues;
	fuse_ring->queue_depth = se->uring.q_depth;
	fuse_ring->max_req_payload_sz = payload_sz;
	fuse_ring->queue_mem_size = queue_sz;
	fuse_ring->single_issuer = se->conn.io_uring_single_issuer;
	fuse_ring->zero_copy =
		(se->conn.want_ext & FUSE_CAP_IO_URING_BUFPOOL) != 0;

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
		pthread_mutex_init(&queue->ring_lock, NULL);
	}

	pthread_cond_init(&fuse_ring->thread_start_cond, NULL);
	pthread_mutex_init(&fuse_ring->thread_start_mutex, NULL);
	sem_init(&fuse_ring->init_sem, 0, 0);

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
			fuse_uring_use_payload_pool(sqe);
		}
#endif
		break;
	case FUSE_IO_URING_CMD_COMMIT_AND_FETCH:
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, ent->req_commit_id);
#ifdef HAVE_URING_ZERO_COPY
		if (queue->ring_pool->zero_copy)
			fuse_uring_use_payload_pool(sqe);
#endif
		break;
	default:
		fuse_log(FUSE_LOG_ERR, "Unknown command type: %d\n",
			 ent->last_cmd);
		queue->ring_pool->se->error = -EINVAL;
		break;
	}

	if (!atomic_load_explicit(&queue->cqe_processing, memory_order_relaxed))
		io_uring_submit(&queue->ring);
	if (locked)
		pthread_mutex_unlock(&queue->ring_lock);
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

static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	size_t num_completed = 0;
	struct io_uring_cqe *cqe;
	unsigned int head;
	struct fuse_ring_ent *ent;
	int ret = 0;

	io_uring_for_each_cqe(&queue->ring, head, cqe) {
		int err = 0;
		void *cqe_data = io_uring_cqe_get_data(cqe);

		num_completed++;

		err = cqe->res;
		if ((uintptr_t)cqe_data == (unsigned int)queue->eventfd) {
			if (err > 0)
				return -ENOTCONN;
			if (err < 0 && err != -ECANCELED)
				ret = err;
			continue;
		}

		ent = cqe_data;
		if (ent && ent->cqe_kind == FUSE_URING_CQE_FIXED_IO) {
			err = fuse_uring_handle_fixed_io_cqe(queue, ent, err);
			if (err && !ret)
				ret = err;
			continue;
		}
		if (unlikely(err != 0)) {
			switch (err) {
			case -EAGAIN:
				fallthrough;
			case -EINTR:
				ent = cqe_data;
				fuse_uring_resubmit(queue, ent);
				continue;
			default:
				break;
			}

			/* -ENOTCONN is ok on umount  */
			if (err != -ENOTCONN) {
				se->error = cqe->res;

				/* return first error */
				if (ret == 0)
					ret = err;
			}

		} else {
			err = fuse_uring_handle_cqe(queue, cqe);
			if (err && !ret)
				ret = err;
		}
	}

	if (num_completed)
		io_uring_cq_advance(&queue->ring, num_completed);

	return ret;
}

/*
 * The kernel selects a synchronous request queue from task_cpu(current).
 * Binding that queue's userspace thread to the same CPU makes the request
 * issuer and handler time-share one CPU. Background requests may be balanced
 * independently. Keep each queue on the same NUMA node when possible, but use
 * a different CPU allowed by the daemon's affinity mask.
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

	target_cpu = fuse_uring_select_thread_cpu(queue->qid, allowed_cpus,
						  local_cpus);
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

	res = fuse_queue_setup_io_uring(&queue->ring, queue->qid,
					ring->queue_depth, se->fd,
					queue->eventfd, ring->single_issuer);
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
		__u64 payload_tag = 0;

		if (ring->queue_depth > UINT_MAX - 1 ||
		    ring->max_req_payload_sz >
			    UINT32_MAX / ring->queue_depth)
			return -EOVERFLOW;
		queue->payload_pool_sz = ring->queue_depth *
					 ring->max_req_payload_sz;
		queue->payload_pool = numa_alloc_local(queue->payload_pool_sz);
		if (!queue->payload_pool)
			return -ENOMEM;

		res = io_uring_register_buffers_sparse(
			&queue->ring, (unsigned int)ring->queue_depth + 1);
		if (res)
			return res;
		queue->sparse_buffers_registered = true;
		payload_iov.iov_base = queue->payload_pool;
		payload_iov.iov_len = queue->payload_pool_sz;
		res = io_uring_register_buffers_update_tag(
			&queue->ring, 0, &payload_iov, &payload_tag, 1);
		if (res != 1)
			return res < 0 ? res : -EIO;
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
		ring_ent->req_payload_sz = ring->max_req_payload_sz;
		ring_ent->fixed_buf_index = (unsigned int)idx + 1;

		if (ring->zero_copy) {
			ring_ent->op_payload =
				(char *)queue->payload_pool +
				idx * ring_ent->req_payload_sz;
		} else {
			ring_ent->op_payload =
				numa_alloc_local(ring_ent->req_payload_sz);
			if (!ring_ent->op_payload)
				return -ENOMEM;
		}

		req->se = se;
		pthread_mutex_init(&req->lock, NULL);
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

	if (ring_pool->zero_copy) {
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

	se->uring.pool = fuse_ring;
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
		if (fuse_ring)
			fuse_session_destruct_uring(fuse_ring);
		se->uring.pool = NULL;
	}
	return err;
}

int fuse_uring_stop(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	if (ring == NULL)
		return 0;

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
