/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Exercise the production owner-thread transaction and CQ dispatcher using a
 * deterministic, in-memory SQ/CQ. This does not require io_uring or a mount;
 * it tests userspace ordering and failure recovery, not kernel execution.
 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 317
#include <assert.h>
#include <liburing.h>
#include <numa.h>
#include <stdlib.h>
#include <time.h>

static int mock_submit(struct io_uring *ring);
static int mock_wait(struct io_uring *ring, struct io_uring_cqe **cqe,
		     struct __kernel_timespec *timeout);
static void *mock_alloc(size_t size);
static void mock_free(void *ptr, size_t size);
static int mock_clock(clockid_t id, struct timespec *ts);
static int mock_update(struct io_uring *ring, unsigned int off,
		       const struct iovec *iov, const __u64 *tags, unsigned int nr);

#define io_uring_submit mock_submit
#define io_uring_wait_cqe_timeout mock_wait
#define io_uring_register_buffers_update_tag mock_update
#define numa_alloc_local mock_alloc
#define numa_free mock_free
#define clock_gettime mock_clock
#include "../lib/fuse_uring.c"
#undef io_uring_submit
#undef io_uring_wait_cqe_timeout
#undef io_uring_register_buffers_update_tag
#undef numa_alloc_local
#undef numa_free
#undef clock_gettime

#define MAX_TEST_DEPTH 64
#define TEST_RING_DEPTH 256
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
static struct {
	struct fuse_ring_pool pool;
	struct fuse_session se;
	struct fuse_ring_queue *queue;
	unsigned int sq_head, sq_tail, cq_head, cq_tail, flags;
	struct io_uring_sqe sqes[2 * TEST_RING_DEPTH];
	struct io_uring_cqe cqes[TEST_RING_DEPTH];
	struct fuse_ring_ent *armed[MAX_TEST_DEPTH];
	unsigned int depth, state;
	uint64_t generation, ticks;
	bool hold_entry, fail_reconfig, fail_rearm, fail_register;
	int fail_alloc;
	size_t allocated, registrations;
	uint64_t tags[MAX_TEST_DEPTH + 2];
	size_t registered[MAX_TEST_DEPTH + 2];
	void *registered_ptr[MAX_TEST_DEPTH + 2];
	void *delayed_ptr;
	uint64_t delayed_tag;
	unsigned int delayed_waits;
} fake;

/* Private libfuse helpers reached by the dispatcher are never data-test paths. */
void list_init_req(struct fuse_req *req)
{
	req->next = req;
	req->prev = req;
}

void fuse_free_req(struct fuse_req *req)
{
	req->ref_cnt--;
}

void fuse_session_process_uring_cqe(struct fuse_session *se,
	struct fuse_req *req, struct fuse_in_header *in, void *header,
	void *payload, size_t len)
{
	(void)se; (void)req; (void)in; (void)header; (void)payload; (void)len;
	assert(!"unexpected data request in control protocol test");
}

static void completion(struct io_uring *ring, void *token, int result)
{
	struct io_uring_cqe *cqe;

	assert(fake.cq_tail - fake.cq_head < TEST_RING_DEPTH);
	cqe = &ring->cq.cqes[fake.cq_tail++ & (TEST_RING_DEPTH - 1)];
	memset(cqe, 0, sizeof(*cqe));
	cqe->user_data = (uintptr_t)token;
	cqe->res = result;
}

static unsigned int active_count(void)
{
	unsigned int count = 0;

	for (unsigned int i = 0; i < MAX_TEST_DEPTH; i++)
		count += fake.armed[i] != NULL;
	return count;
}

static int mock_submit(struct io_uring *ring)
{
	unsigned int count = 0;

	while (ring->sq.sqe_head != ring->sq.sqe_tail) {
		struct io_uring_sqe *sqe = &ring->sq.sqes[
			(ring->sq.sqe_head++ & (TEST_RING_DEPTH - 1)) * 2];
		struct fuse_uring_runtime_cmd *cmd = (void *)sqe->cmd;
		void *token = (void *)(uintptr_t)sqe->user_data;
		int result = 0;

		count++;
		if (sqe->opcode == IORING_OP_POLL_ADD)
			continue;
		assert(sqe->opcode == IORING_OP_URING_CMD);
		assert(cmd->version == FUSE_URING_RUNTIME_VERSION);
		switch (sqe->cmd_op) {
		case FUSE_IO_URING_CMD_PAUSE:
			assert(cmd->generation == fake.generation);
			fake.state = FUSE_URING_STATE_QUIESCING;
			for (unsigned int i = 0; i < MAX_TEST_DEPTH; i++) {
				if (fake.armed[i] && !(fake.hold_entry && i == 0)) {
					completion(ring, fake.armed[i], FUSE_URING_CQE_RETIRED);
					fake.armed[i] = NULL;
				}
			}
			break;
		case FUSE_IO_URING_CMD_QUERY: {
			struct fuse_uring_runtime_state *out = (void *)(uintptr_t)cmd->result_addr;

			if (!active_count() && fake.state == FUSE_URING_STATE_QUIESCING)
				fake.state = FUSE_URING_STATE_QUIESCED;
			out->state = fake.state;
			out->active = active_count();
			out->depth = fake.depth;
			out->generation = fake.generation;
			break;
		}
		case FUSE_IO_URING_CMD_RECONFIG:
			assert(!active_count());
			if (fake.fail_reconfig && !(cmd->flags & FUSE_URING_RUNTIME_INIT)) {
				fake.fail_reconfig = false;
				result = -ENOMEM;
				break;
			}
			if (cmd->flags & FUSE_URING_RUNTIME_ZERO_COPY) {
				assert(sqe->uring_cmd_flags & IORING_URING_CMD_FIXED);
				assert(sqe->buf_index == cmd->pool_index);
				assert(fake.registered[cmd->pool_index] == cmd->len);
			}
			fake.depth = cmd->depth;
			fake.generation = cmd->generation;
			fake.state = FUSE_URING_STATE_QUIESCED;
			break;
		case FUSE_IO_URING_CMD_REARM:
			assert(cmd->generation == fake.generation);
			assert(cmd->entry_id < fake.depth);
			assert(!fake.armed[cmd->entry_id]);
			if (fake.fail_rearm && cmd->generation > 1) {
				fake.fail_rearm = false;
				result = -ENOMEM;
				break;
			}
			fake.armed[cmd->entry_id] = token;
			continue;
		case FUSE_IO_URING_CMD_RESUME:
			assert(cmd->generation == fake.generation);
			assert(active_count() == fake.depth);
			fake.state = FUSE_URING_STATE_RUNNING;
			break;
		default:
			assert(!"unexpected command");
		}
		completion(ring, token, result);
	}
	fake.sq_head = ring->sq.sqe_head;
	fake.sq_tail = ring->sq.sqe_tail;
	return count;
}

static int mock_wait(struct io_uring *ring, struct io_uring_cqe **cqe,
		     struct __kernel_timespec *timeout)
{
	(void)timeout;
	fake.ticks += 10;
	if (fake.delayed_tag && !--fake.delayed_waits) {
		completion(ring, (void *)(uintptr_t)fake.delayed_tag, 0);
		fake.delayed_tag = 0;
		fake.delayed_ptr = NULL;
	}
	if (fake.cq_head == fake.cq_tail)
		return -ETIME;
	*cqe = &ring->cq.cqes[fake.cq_head & (TEST_RING_DEPTH - 1)];
	return 0;
}

static void *mock_alloc(size_t size)
{
	void *ptr;

	if (fake.fail_alloc > 0 && !--fake.fail_alloc)
		return NULL;
	ptr = calloc(1, size);
	assert(ptr);
	fake.allocated += size;
	return ptr;
}

static void mock_free(void *ptr, size_t size)
{
	assert(ptr && fake.allocated >= size);
	assert(ptr != fake.delayed_ptr); /* A successful update is not release. */
	fake.allocated -= size;
	free(ptr);
}

static int mock_clock(clockid_t id, struct timespec *ts)
{
	(void)id;
	ts->tv_sec = fake.ticks / 1000;
	ts->tv_nsec = (fake.ticks % 1000) * 1000000;
	return 0;
}

static int mock_update(struct io_uring *ring, unsigned int off,
		       const struct iovec *iov, const __u64 *tags, unsigned int nr)
{
	(void)ring;
	assert(nr == 1 && off < MAX_TEST_DEPTH + 2);
	if (fake.fail_register && iov->iov_len) {
		fake.fail_register = false;
		return -ENOMEM;
	}
	if (fake.tags[off]) {
		assert(!fake.delayed_tag);
		fake.delayed_ptr = fake.registered_ptr[off];
		fake.delayed_tag = fake.tags[off];
		fake.delayed_waits = 2;
	}
	fake.registrations -= fake.registered[off];
	fake.registered[off] = iov->iov_len;
	fake.registered_ptr[off] = iov->iov_base;
	fake.registrations += iov->iov_len;
	fake.tags[off] = *tags;
	return 1;
}

static void setup(bool zero_copy)
{
	struct fuse_ring_pool *pool = &fake.pool;
	struct fuse_ring_queue *q;

	memset(&fake, 0, sizeof(fake));
	q = calloc(2, fuse_ring_queue_size(MAX_TEST_DEPTH));
	assert(q);
	fake.queue = q;
	pool->se = &fake.se;
	pool->runtime_qd = true;
	pool->zero_copy = zero_copy;
	pool->single_issuer = zero_copy;
	pool->queue_depth = MAX_TEST_DEPTH;
	pool->initial_depth = 2;
	pool->nr_queues = 1;
	pool->max_req_payload_sz = 4096;
	pool->drain_timeout_ms = 50;
	pool->queues = q;
	pool->queue_mem_size = fuse_ring_queue_size(MAX_TEST_DEPTH);
	pthread_mutex_init(&pool->control_lock, NULL);
	fake.se.uring.pool = pool;
	q->ring_pool = pool;
	q->current_depth = 2;
	q->generation = 1;
	q->eventfd = -1;
	q->control_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	assert(q->control_eventfd >= 0);
	pthread_mutex_init(&q->ring_lock, NULL);
	q->prepared_payloads = calloc(MAX_TEST_DEPTH, sizeof(void *));
	q->ring.flags = IORING_SETUP_SQE128;
	q->ring.sq.khead = &fake.sq_head;
	q->ring.sq.ktail = &fake.sq_tail;
	q->ring.sq.kflags = &fake.flags;
	q->ring.sq.ring_entries = TEST_RING_DEPTH;
	q->ring.sq.ring_mask = TEST_RING_DEPTH - 1;
	q->ring.sq.sqes = fake.sqes;
	q->ring.cq.khead = &fake.cq_head;
	q->ring.cq.ktail = &fake.cq_tail;
	q->ring.cq.ring_mask = TEST_RING_DEPTH - 1;
	q->ring.cq.ring_entries = TEST_RING_DEPTH;
	q->ring.cq.cqes = fake.cqes;
	if (zero_copy) {
		struct iovec iov;
		__u64 tag = (uintptr_t)&q->payload_tags[0];

		q->payload_pool_sz = 2 * 4096;
		q->payload_pool = mock_alloc(q->payload_pool_sz);
		iov.iov_base = q->payload_pool;
		iov.iov_len = q->payload_pool_sz;
		assert(mock_update(&q->ring, 0, &iov, &tag, 1) == 1);
	}
	for (unsigned int i = 0; i < MAX_TEST_DEPTH; i++) {
		struct fuse_ring_ent *ent = &q->ent[i];

		ent->ring_queue = q;
		ent->req_header = calloc(1, sizeof(*ent->req_header));
		ent->req_payload_sz = 4096;
		ent->req.ref_cnt = 1;
		if (!zero_copy && i < 2)
			ent->op_payload = mock_alloc(4096);
	}
	assert(fuse_uring_runtime_start_queue(q) == 0);
	assert(fake.state == FUSE_URING_STATE_RUNNING);
	assert(active_count() == 2);
	assert(fake.allocated == 2 * 4096);
	atomic_store(&pool->ready_queues, 1);
}

static void teardown(void)
{
	struct fuse_ring_queue *q = fake.queue;

	if (fake.pool.zero_copy)
		mock_free(q->payload_pool, q->payload_pool_sz);
	for (unsigned int i = 0; i < MAX_TEST_DEPTH; i++) {
		if (!fake.pool.zero_copy && q->ent[i].op_payload)
			mock_free(q->ent[i].op_payload, 4096);
		free(q->ent[i].req_header);
	}
	assert(!q->prepared_pool && !fake.allocated);
	free(q->prepared_payloads);
	close(q->control_eventfd);
	pthread_mutex_destroy(&q->ring_lock);
	pthread_mutex_destroy(&fake.pool.control_lock);
	free(q);
}

static void test_transitions(bool zero_copy)
{
	unsigned int depths[] = { 8, 16, 32, 64, 2, 2, 64, 2 };
	struct fuse_uring_runtime_queue_status queue_status;
	struct fuse_uring_runtime_status status;
	uint64_t tx;

	setup(zero_copy);
	assert(fuse_uring_request_qd(&fake.se, 0, &tx) == -EINVAL);
	assert(fuse_uring_request_qd(&fake.se, 65, &tx) == -EINVAL);
	for (size_t i = 0; i < ARRAY_SIZE(depths); i++) {
		assert(fuse_uring_request_qd(&fake.se, depths[i], &tx) == 0);
		assert(tx == i + 1);
		assert(fuse_uring_request_qd(&fake.se, 2, &tx) == -EBUSY);
		assert(fuse_uring_runtime_service(fake.queue) == 0);
		assert(fuse_uring_runtime_status(&fake.se, &status, &queue_status, 1) == 1);
		assert(!status.busy && !status.error);
		assert(queue_status.current_depth == depths[i]);
		assert(queue_status.phase == FUSE_URING_RUNTIME_COMPLETE);
		assert(!queue_status.reclaim_bytes);
		assert(fake.allocated == depths[i] * 4096);
		assert(fake.state == FUSE_URING_STATE_RUNNING);
		if (zero_copy)
			assert(fake.registrations == fake.allocated);
	}
	teardown();
}

static void test_failure(bool zero_copy, unsigned int which)
{
	bool fatal = false;
	int expected = -ENOMEM;

	setup(zero_copy);
	switch (which) {
	case 0:
		fake.fail_alloc = 1;
		break;
	case 1:
		fake.fail_reconfig = true;
		break;
	case 2:
		fake.fail_rearm = true;
		break;
	case 3:
		fake.hold_entry = true;
		expected = -ETIMEDOUT;
		break;
	case 4:
		fake.fail_register = true;
		break;
	default:
		assert(false);
	}
	assert(fuse_uring_runtime_change(fake.queue, 8, &fatal) == expected);
	assert(!fatal);
	assert(fake.queue->current_depth == 2);
	assert(active_count() == 2);
	assert(fake.state == FUSE_URING_STATE_RUNNING);
	assert(fake.allocated == 2 * 4096);
	assert(!fake.queue->runtime_status.reclaim_bytes);
	assert(fake.queue->runtime_status.payload_bytes == 2 * 4096);
	if (zero_copy)
		assert(fake.registrations == fake.allocated &&
		       fake.queue->runtime_status.registered_bytes == fake.allocated);
	teardown();
}

static void test_partial_session(void)
{
	struct fuse_uring_runtime_queue_status queues[2];
	struct fuse_uring_runtime_status status;
	struct fuse_ring_queue *second;
	uint64_t tx;

	setup(false);
	second = fuse_uring_get_queue(&fake.pool, 1);
	second->qid = 1;
	second->ring_pool = &fake.pool;
	second->current_depth = 2;
	second->generation = 1;
	second->runtime_status.current_depth = 2;
	second->control_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	assert(second->control_eventfd >= 0);
	second->prepared_payloads = calloc(MAX_TEST_DEPTH, sizeof(void *));
	for (unsigned int i = 0; i < 2; i++)
		second->ent[i].op_payload = mock_alloc(4096);
	fake.pool.nr_queues = 2;
	atomic_store(&fake.pool.ready_queues, 2);
	assert(fuse_uring_request_qd(&fake.se, 8, &tx) == 0);
	assert(fuse_uring_runtime_service(fake.queue) == 0);
	assert(fuse_uring_runtime_status(&fake.se, &status, queues, 2) == 2);
	assert(status.busy && queues[0].current_depth == 8);
	assert(queues[1].current_depth == 2);
	/* The second queue fails before PAUSE; the first remains usable at 8. */
	fake.fail_alloc = 1;
	assert(fuse_uring_runtime_service(second) == 0);
	assert(fuse_uring_runtime_status(&fake.se, &status, queues, 2) == 2);
	assert(!status.busy && status.error == -ENOMEM);
	assert(queues[0].current_depth == 8 && !queues[0].error);
	assert(queues[1].current_depth == 2 && queues[1].error == -ENOMEM);
	assert(queues[1].phase == FUSE_URING_RUNTIME_FAILED);
	for (unsigned int i = 0; i < 2; i++)
		mock_free(second->ent[i].op_payload, 4096);
	free(second->prepared_payloads);
	close(second->control_eventfd);
	teardown();
}

int main(void)
{
	test_transitions(false);
	test_partial_session();
	for (unsigned int i = 0; i < 4; i++)
		test_failure(false, i);
#ifdef HAVE_URING_ZERO_COPY
	test_transitions(true);
	for (unsigned int i = 0; i < 5; i++)
		test_failure(true, i);
#endif
	puts("runtime QD transitions, allocation/register/rearm failures, timeout rollback: PASS");
	return 0;
}
