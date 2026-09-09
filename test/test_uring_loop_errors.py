#!/usr/bin/env python3
"""Inject errors into the complete production ring-thread function, without I/O."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SOURCE = Path(os.environ.get("FUSE_URING_LOOP_SOURCE",
                            Path(__file__).resolve().parents[1] / "lib/fuse_uring.c"))


def thread_function(source):
    start = source.index("static void *fuse_uring_thread(void *arg)")
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if not depth:
            return source[start:end + 1]
    raise AssertionError("unterminated fuse_uring_thread")


HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define HAVE_URING_ZERO_COPY 1
#define FUSE_LOG_ERR 1
struct io_uring { int unused; };
struct io_uring_cqe { int unused; };
struct fuse_session { _Atomic int mt_exited; int error; };
struct fuse_ring_pool {
 struct fuse_session *se;
 bool single_issuer, zero_copy;
 pthread_mutex_t thread_start_mutex;
 pthread_cond_t thread_start_cond;
 sem_t init_sem;
 unsigned failed_threads, started_threads;
};
struct fuse_ring_queue {
 struct fuse_ring_pool *ring_pool;
 int qid;
 struct io_uring ring;
 pthread_mutex_t ring_lock;
 atomic_bool cqe_processing;
};
static struct fuse_session session;
static struct fuse_ring_pool pool = {
 .se = &session, .single_issuer = true,
 .thread_start_mutex = PTHREAD_MUTEX_INITIALIZER,
 .thread_start_cond = PTHREAD_COND_INITIALIZER,
};
static struct fuse_ring_queue queue = {
 .ring_pool = &pool, .qid = 4, .ring_lock = PTHREAD_MUTEX_INITIALIZER,
};
static int init_error, setup_error, register_error, registered_submit_error;
static int wait_error, submit_error, dispatch_error;
static unsigned exits, combined_waits, plain_waits, submits, dispatches;
static bool cancel_at_wait;
static void fuse_set_thread_name(const char *name) { assert(!strcmp(name, "fuse-ring-4")); }
static void fuse_uring_set_thread_cpu(struct fuse_ring_queue *q) { assert(q == &queue); }
static int fuse_uring_init_queue(struct fuse_ring_queue *q) { assert(q == &queue); return init_error; }
static int fuse_uring_setup_zero_copy_queue(struct fuse_ring_queue *q)
{ assert(q == &queue && pool.zero_copy); return setup_error; }
static int fuse_uring_register_queue(struct fuse_ring_queue *q)
{ assert(q == &queue); return register_error; }
static int fuse_uring_submit_registered_queue(struct fuse_ring_queue *q)
{ assert(q == &queue); return registered_submit_error; }
static void fuse_log(int level, const char *format, ...)
{ assert(level == FUSE_LOG_ERR && format); }
static void cancellation_point(void)
{
 if (cancel_at_wait) { assert(!pthread_cancel(pthread_self())); pthread_testcancel(); }
}
static int io_uring_submit_and_wait(struct io_uring *ring, unsigned count)
{
 assert(ring == &queue.ring && pool.single_issuer && count == 1);
 combined_waits++; cancellation_point(); return wait_error;
}
static int io_uring_wait_cqe(struct io_uring *ring, struct io_uring_cqe **cqe)
{
 assert(ring == &queue.ring && !pool.single_issuer); *cqe = NULL;
 plain_waits++; cancellation_point(); return wait_error;
}
static int io_uring_submit(struct io_uring *ring)
{ assert(ring == &queue.ring && !pool.single_issuer); submits++; return submit_error; }
static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *q)
{
 assert(q == &queue && atomic_load(&queue.cqe_processing)); dispatches++;
 if (!dispatch_error) atomic_store(&session.mt_exited, 1);
 return dispatch_error;
}
static void fuse_session_exit(struct fuse_session *se)
{ assert(se == &session); exits++; atomic_store(&se->mt_exited, 1); }
@PRODUCTION@
int main(int argc, char **argv)
{
 const char *name; int expected = 0;
 assert(argc == 2); name = argv[1]; assert(!sem_init(&pool.init_sem, 0, 1));
 pool.single_issuer = strstr(name, "multi") == NULL;
 if (!strcmp(name, "single-wait-error") || !strcmp(name, "multi-wait-error"))
  expected = wait_error = -EIO;
 if (!strcmp(name, "single-wait-interrupted")) expected = wait_error = -EINTR;
 if (!strcmp(name, "multi-submit-error")) expected = submit_error = -ENOSPC;
 if (!strcmp(name, "dispatch-protocol-error")) expected = dispatch_error = -EPROTO;
 if (!strcmp(name, "registration-error")) expected = register_error = -EINVAL;
 if (!strcmp(name, "registered-submit-error")) expected = registered_submit_error = -EIO;
 if (!strcmp(name, "zero-copy-setup-error")) {
  pool.zero_copy = true; expected = setup_error = -EOPNOTSUPP;
 }
 if (!strcmp(name, "unmount-wait")) wait_error = -ENOTCONN;
 if (!strcmp(name, "unmount-dispatch") || !strcmp(name, "unmount-preserve-error"))
  dispatch_error = -ENOTCONN;
 if (!strcmp(name, "unmount-preserve-error")) expected = session.error = -EIO;
 if (!strcmp(name, "setup-fallback")) init_error = -ENOSYS;
 if (!strcmp(name, "already-stopped")) atomic_store(&session.mt_exited, 1);
 if (!strcmp(name, "cancel-single") || !strcmp(name, "cancel-multi")) {
  pthread_t thread; void *result; cancel_at_wait = true;
  assert(!pthread_create(&thread, NULL, fuse_uring_thread, &queue));
  assert(!pthread_join(thread, &result) && result == PTHREAD_CANCELED);
  assert(!exits && !session.error && !dispatches);
 } else {
  assert(fuse_uring_thread(&queue) == NULL);
  assert(session.error == expected);
  if (init_error) assert(!exits && pool.failed_threads == 1 && !session.mt_exited);
  else if (wait_error || submit_error || dispatch_error || setup_error ||
           register_error || registered_submit_error) assert(exits == 1 && session.mt_exited);
  else assert(!exits && session.mt_exited);
 }
 assert(pool.started_threads == 1);
 if (wait_error || init_error || setup_error || register_error || registered_submit_error)
  assert(!dispatches);
 if (submit_error) assert(dispatches == 1 && submits == 1);
 if (!strcmp(name, "single-success")) assert(combined_waits == 1 && !plain_waits && dispatches == 1);
 if (!strcmp(name, "multi-success")) assert(plain_waits == 1 && submits == 1 && dispatches == 1);
 if (!strcmp(name, "already-stopped")) assert(!combined_waits && !plain_waits && !dispatches);
 /* Error exit must occur after releasing the multi-issuer submit mutex. */
 assert(!pthread_mutex_trylock(&queue.ring_lock)); pthread_mutex_unlock(&queue.ring_lock);
 assert(!pthread_mutex_trylock(&pool.thread_start_mutex)); pthread_mutex_unlock(&pool.thread_start_mutex);
 sem_destroy(&pool.init_sem);
 printf("PASS case=%s error=%d exits=%u dispatches=%u\n", name, session.error, exits, dispatches);
 return 0;
}
"""


class UringLoopErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="fuse-uring-loop-errors-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        source = directory / "loop.c"
        source.write_text(HARNESS.replace("@PRODUCTION@", thread_function(SOURCE.read_text())))
        cls.binary = directory / "loop"
        result = subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=c11",
                                 "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                                 str(source), "-o", str(cls.binary)],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise AssertionError(result.stderr)

    def case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_negative_loop_errors_reach_session_error(self):
        for name in ("single-wait-error", "multi-wait-error", "single-wait-interrupted",
                     "multi-submit-error", "dispatch-protocol-error"):
            with self.subTest(name=name):
                self.case(name)

    def test_post_initialization_failures_reach_session_error(self):
        for name in ("registration-error", "registered-submit-error", "zero-copy-setup-error"):
            with self.subTest(name=name):
                self.case(name)

    def test_normal_unmount_preserves_success_or_existing_error(self):
        for name in ("unmount-wait", "unmount-dispatch", "unmount-preserve-error"):
            with self.subTest(name=name):
                self.case(name)

    def test_success_stop_and_initial_setup_fallback_remain_unchanged(self):
        for name in ("single-success", "multi-success", "already-stopped", "setup-fallback"):
            with self.subTest(name=name):
                self.case(name)

    def test_cancellation_does_not_become_a_session_error(self):
        self.case("cancel-single")
        self.case("cancel-multi")


if __name__ == "__main__":
    unittest.main(verbosity=2)
