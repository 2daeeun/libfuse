#!/usr/bin/env python3
"""Compile real ring setup/submission code against bounded syscall fixtures.

This neither creates an io_uring instance nor mounts FUSE. It tests accepted
setup flags, owner enforcement, and the production queue loop's flush points.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("FUSE_URING_TASKRUN_SOURCE", ROOT / "lib/fuse_uring.c"))


def balanced(source, start):
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if not depth:
                return source[start:end + 1]
    raise AssertionError("unterminated production region")


def function(source, name):
    match = re.search(r"^(?:static )?(?:int|void) " + name + r"\(", source, re.M)
    if match is None:
        raise AssertionError(f"missing production function {name}")
    return balanced(source, match.start())


HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <liburing.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "fuse_kernel.h"

#define FUSE_LOG_ERR 1
#define FUSE_LOG_DEBUG 2
#define FUSE_LOG_INFO 3
struct fuse_session { bool debug; int error; _Atomic int mt_exited; };
struct fuse_ring_pool { bool single_issuer, zero_copy; struct fuse_session *se; };
struct fuse_ring_queue {
    struct fuse_ring_pool *ring_pool;
    int qid;
    pthread_t tid;
    pthread_mutex_t ring_lock;
    _Atomic bool cqe_processing;
    struct io_uring ring;
};
struct fuse_ring_ent {
    struct fuse_uring_req_header *req_header;
    uint64_t req_commit_id;
    unsigned int last_cmd;
    struct iovec iov[2];
};
static struct fuse_session session;
static struct fuse_ring_pool pool = {.se = &session};
static struct fuse_ring_queue queue = {.ring_pool = &pool, .qid = 4,
                                      .ring_lock = PTHREAD_MUTEX_INITIALIZER};
static struct fuse_uring_req_header header;
static struct fuse_ring_ent entry = {.req_header = &header, .req_commit_id = 19};
static struct io_uring_sqe sqe;
static struct fuse_uring_cmd_req command;
static struct io_uring_cqe cqe;
static int init_error, files_error, ring_fd_error, no_sqe, submit_error;
static int setups, files_registered, rings_registered, flags_seen;
static int sqes, pending, submits, combined_waits, plain_waits, handled, locks;
static bool locked;
static char log_line[256];

static void fuse_log(int level, const char *fmt, ...)
{
    va_list args; (void)level; va_start(args, fmt);
    vsnprintf(log_line, sizeof(log_line), fmt, args); va_end(args);
}
static int mock_setup(unsigned int depth, struct io_uring *ring, struct io_uring_params *params)
{
    assert(ring == &queue.ring && depth == 9);
    assert(params->cq_entries == 18);
    setups++; flags_seen = params->flags; return init_error;
}
static int mock_files(struct io_uring *ring, const int *fds, unsigned int count)
{ assert(ring == &queue.ring && count == 1 && fds[0] == 17); files_registered++; return files_error; }
static int mock_ring_fd(struct io_uring *ring)
{ assert(ring == &queue.ring); rings_registered++; return ring_fd_error; }
static struct io_uring_sqe *mock_sqe(struct io_uring *ring)
{
    assert(ring == &queue.ring);
    if (pool.single_issuer) assert(pthread_equal(pthread_self(), queue.tid));
    else assert(locked);
    sqes++;
    if (no_sqe) return NULL;
    pending++; return &sqe;
}
static int mock_submit(struct io_uring *ring)
{
    assert(ring == &queue.ring);
    if (pool.single_issuer) assert(pthread_equal(pthread_self(), queue.tid));
    else assert(locked);
    submits++; pending = 0; return submit_error ? submit_error : 1;
}
static int mock_submit_wait(struct io_uring *ring, unsigned int count)
{
    assert(ring == &queue.ring && count == 1 && pool.single_issuer);
    assert(pthread_equal(pthread_self(), queue.tid) && !locked);
    combined_waits++; pending = 0; return submit_error ? submit_error : 1;
}
static int mock_wait(struct io_uring *ring, struct io_uring_cqe **out)
{
    assert(ring == &queue.ring && !pool.single_issuer && !locked);
    plain_waits++; *out = &cqe; return 0;
}
static int mock_lock(pthread_mutex_t *mutex)
{ assert(mutex == &queue.ring_lock && !locked); locked = true; locks++; return 0; }
static int mock_unlock(pthread_mutex_t *mutex)
{ assert(mutex == &queue.ring_lock && locked); locked = false; return 0; }
static void fuse_uring_sqe_prepare(struct io_uring_sqe *out, struct fuse_ring_ent *ent, unsigned int op)
{ assert(out == &sqe && ent == &entry); (void)op; }
static struct fuse_uring_cmd_req *fuse_uring_get_sqe_cmd(struct io_uring_sqe *out)
{ assert(out == &sqe); return &command; }
static void fuse_uring_sqe_set_req_data(struct fuse_uring_cmd_req *cmd, unsigned int qid, uint64_t id)
{ assert(cmd == &command && qid == 4 && (id == 19 || id == 0)); }
static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *q);

#define io_uring_queue_init_params mock_setup
#define io_uring_register_files mock_files
#define io_uring_register_ring_fd mock_ring_fd
#define io_uring_get_sqe mock_sqe
#define io_uring_submit mock_submit
#define io_uring_submit_and_wait mock_submit_wait
#define io_uring_wait_cqe mock_wait
#define pthread_mutex_lock mock_lock
#define pthread_mutex_unlock mock_unlock

@PRODUCTION@

static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *q)
{
    assert(q == &queue && atomic_load(&queue.cqe_processing)); handled++;
    if (handled == 1) assert(!fuse_uring_commit_sqe(&pool, q, &entry));
    if (!pool.single_issuer || handled == 2) atomic_store(&session.mt_exited, 1);
    return 0;
}
static int run_queue_loop(void)
{
    struct fuse_ring_queue *queue = &::QUEUE_PLACEHOLDER::;
    struct fuse_session *se = &session;
    const bool single_issuer = pool.single_issuer;
    int err;
    @LOOP@
    return 0;
err:
    return err;
}
static int foreign_result;
static void *foreign_reply(void *unused)
{ (void)unused; foreign_result = fuse_uring_commit_sqe(&pool, &queue, &entry); return NULL; }

int main(int argc, char **argv)
{
    int result;
    const unsigned int common = IORING_SETUP_SQE128 | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE;
    assert(argc == 2);
    pool.single_issuer = strstr(argv[1], "multi") == NULL;
    queue.tid = pthread_self();
    if (strstr(argv[1], "setup")) {
        if (strstr(argv[1], "unsupported")) init_error = -EINVAL;
        if (strstr(argv[1], "files-error")) files_error = -EBADF;
        if (strstr(argv[1], "ring-fd-fallback")) ring_fd_error = -EINVAL;
        result = fuse_queue_setup_io_uring(&queue.ring, 4, 8, 17, 18, pool.single_issuer);
        assert(setups == 1);
        assert((unsigned int)flags_seen == (common | (pool.single_issuer ?
               IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN : 0)));
        assert(result == (init_error ? init_error : files_error));
        assert(files_registered == !init_error);
        assert(rings_registered == (!init_error && !files_error && pool.single_issuer));
        assert((strstr(log_line, "FUSE_URING_TASKRUN") != NULL) == !result);
        if (!result) assert(strstr(log_line, pool.single_issuer ? "defer_taskrun=1" : "defer_taskrun=0"));
    } else if (strstr(argv[1], "loop")) {
        if (strstr(argv[1], "error")) submit_error = -EIO;
        result = run_queue_loop();
        assert(result == submit_error);
        assert(!pending && !locked && !atomic_load(&queue.cqe_processing));
        if (submit_error) assert(!handled && combined_waits == 1);
        else if (pool.single_issuer) assert(combined_waits == 2 && !plain_waits && !submits && !locks);
        else assert(plain_waits == 1 && !combined_waits && submits == 1 && locks == 2);
    } else if (strstr(argv[1], "foreign")) {
        pthread_t thread;
        assert(!pthread_create(&thread, NULL, foreign_reply, NULL));
        assert(!pthread_join(thread, NULL));
        if (pool.single_issuer) assert(foreign_result == -EINVAL && !sqes && !submits && !locks);
        else assert(!foreign_result && sqes == 1 && submits == 1 && locks == 1);
    } else {
        bool retry = strstr(argv[1], "retry") != NULL;
        atomic_store(&queue.cqe_processing, strstr(argv[1], "batch") != NULL);
        no_sqe = strstr(argv[1], "full") != NULL;
        if (retry) {
            entry.last_cmd = FUSE_IO_URING_CMD_REGISTER;
            fuse_uring_resubmit(&queue, &entry);
            result = session.error;
        } else result = fuse_uring_commit_sqe(&pool, &queue, &entry);
        assert(result == (no_sqe ? -EIO : 0));
        assert(!locked && sqes == 1 && locks == !pool.single_issuer);
        assert(submits == (!no_sqe && !atomic_load(&queue.cqe_processing)));
    }
    puts("PASS"); return 0;
}
"""


class UringTaskrunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text()
        names = ("fuse_uring_check_queue_owner", "fuse_uring_commit_sqe",
                 "fuse_queue_setup_io_uring", "fuse_uring_resubmit")
        production = "\n".join(function(source, name) for name in names)
        loop = balanced(source, source.index("while (!atomic_load_explicit(&se->mt_exited"))
        cls.directory = tempfile.TemporaryDirectory(prefix="fuse-uring-taskrun-")
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        path = root / "taskrun.c"
        # Rename fixture globals before inserting unmodified production code.
        harness = re.sub(r"\bqueue\b", "fixture_queue", HARNESS)
        harness = harness.replace("struct fuse_ring_queue *fixture_queue = &::QUEUE_PLACEHOLDER::;",
                                  "struct fuse_ring_queue *queue = &fixture_queue;")
        path.write_text(harness.replace("@PRODUCTION@", production).replace("@LOOP@", loop))
        cls.binary = root / "taskrun"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-O2",
                        "-Wall", "-Wextra", "-Werror", "-pthread", "-I", str(ROOT / "include"),
                        str(path), "-o", str(cls.binary)], check=True, timeout=20)

    def run_cases(self, *cases):
        for case in cases:
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary), case], capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(), "PASS")

    def test_accepted_setup_flags_and_unchanged_multi_issuer(self):
        self.run_cases("setup-single", "setup-multi", "setup-ring-fd-fallback")

    def test_setup_failure_never_claims_active_or_retries_other_flags(self):
        self.run_cases("setup-unsupported", "setup-files-error")

    def test_foreign_reply_contract_and_multi_issuer_submission(self):
        self.run_cases("foreign-single", "foreign-multi")

    def test_owner_commit_batching_and_full_queue_failure(self):
        self.run_cases("commit", "commit-batch", "commit-full", "commit-multi", "commit-multi-batch")

    def test_retry_uses_same_owner_and_existing_flush_policy(self):
        self.run_cases("retry", "retry-batch", "retry-full", "retry-multi")

    def test_production_loop_flushes_before_wait_without_an_added_wait(self):
        self.run_cases("loop", "loop-multi", "loop-error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
