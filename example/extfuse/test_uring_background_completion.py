#!/usr/bin/env python3
"""Exercise the production FUSE ring completion without building Linux."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


LINUX = Path(os.environ.get("EXTFUSE_KERNEL_SOURCE",
                           Path(__file__).resolve().parents[3] / "linux"))

HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

enum { FR_BACKGROUND, FR_SENT };
struct list_head { unsigned int count; };
struct lock { pthread_mutex_t mutex; bool queue; };
struct fuse_conn {
 struct lock bg_lock;
 struct list_head bg_queue;
 unsigned int active_background, num_background, max_background;
};
struct fuse_ring { struct fuse_conn *fc; };
struct fuse_req {
 struct list_head list;
 unsigned long flags;
 struct { struct { int error; } h; } out;
};
struct fuse_ring_queue {
 struct fuse_ring *ring;
 struct lock lock;
 unsigned int active_background, pending;
};
struct fuse_ring_ent {
 struct fuse_ring_queue *queue;
 struct fuse_req *fuse_req;
 void *cmd;
};
static struct fuse_conn fc;
static struct fuse_ring ring;
static struct fuse_ring_queue queue;
static struct fuse_req req;
static struct fuse_ring_ent ent;
static _Thread_local bool queue_held, bg_held, enqueuer;
static unsigned int completion_bg_locks, global_flushes, legacy_started;
static unsigned int unregister_calls, completions;
static bool inject_enqueue;
static pthread_barrier_t enqueue_start, enqueue_done;

static void barrier_wait(pthread_barrier_t *barrier) {
 int ret = pthread_barrier_wait(barrier);
 assert(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void spin_lock(struct lock *lock) {
 assert(!pthread_mutex_lock(&lock->mutex));
 if (lock->queue) { assert(!queue_held && !bg_held); queue_held = true; }
 else { assert(!bg_held); bg_held = true;
        if (!enqueuer) completion_bg_locks++; }
}
static void spin_unlock(struct lock *lock) {
 if (lock->queue) { assert(queue_held && !bg_held); queue_held = false; }
 else { assert(bg_held); bg_held = false; }
 assert(!pthread_mutex_unlock(&lock->mutex));
 if (lock->queue && inject_enqueue) {
  inject_enqueue = false;
  barrier_wait(&enqueue_start);
  barrier_wait(&enqueue_done);
 }
}
static void lockdep_assert_not_held(struct lock *lock) {
 assert(!(lock->queue ? queue_held : bg_held));
}
static bool list_empty(struct list_head *head) { return !head->count; }
static void list_del_init(struct list_head *head) { head->count = 0; }
static bool test_bit(unsigned int bit, unsigned long *flags) {
 return (*flags & (1UL << bit)) != 0;
}
static void clear_bit(unsigned int bit, unsigned long *flags) {
 *flags &= ~(1UL << bit);
}
static void fuse_request_bg_finish(struct fuse_conn *conn,
                                   struct fuse_req *request) {
 assert(queue_held && bg_held && conn == &fc && request == &req);
 assert(conn->active_background && conn->num_background);
 clear_bit(FR_BACKGROUND, &request->flags);
 conn->active_background--; conn->num_background--;
}
static void fuse_uring_flush_bg(struct fuse_ring_queue *q) {
 assert(queue_held && bg_held && q == &queue);
 while (q->pending && (fc.active_background < fc.max_background ||
                      !q->active_background)) {
  q->pending--; q->active_background++; fc.active_background++;
 }
}
static void fuse_flush_bg_queue(struct fuse_conn *conn) {
 assert(bg_held && !queue_held && conn == &fc);
 global_flushes++;
 while (conn->bg_queue.count &&
        conn->active_background < conn->max_background) {
  conn->bg_queue.count--; conn->active_background++; legacy_started++;
 }
}
static void zero_copy_unregister(void *cmd, struct fuse_ring_ent *entry,
                                 unsigned int issue_flags) {
 assert(cmd == &fc && entry == &ent && issue_flags == 73);
 assert(!queue_held && !bg_held && !entry->fuse_req);
 unregister_calls++;
}
static void fuse_request_end(struct fuse_req *request) {
 assert(request == &req && !queue_held && !bg_held);
 assert(!request->list.count && !test_bit(FR_SENT, &request->flags));
 assert(unregister_calls == completions + 1); completions++;
}

/* PRODUCTION_COMPLETION */

static void *enqueue_legacy(void *unused) {
 (void)unused; enqueuer = true; barrier_wait(&enqueue_start);
 /* Same enqueue/flush ordering as fuse_request_queue_background(). */
 spin_lock(&fc.bg_lock);
 fc.num_background++; fc.bg_queue.count++;
 fuse_flush_bg_queue(&fc);
 spin_unlock(&fc.bg_lock);
 barrier_wait(&enqueue_done); return NULL;
}
static void reset(bool background) {
 assert(!pthread_mutex_init(&fc.bg_lock.mutex, NULL));
 assert(!pthread_mutex_init(&queue.lock.mutex, NULL));
 queue.lock.queue = true; ring.fc = &fc; queue.ring = &ring;
 fc.max_background = 2;
 fc.active_background = fc.num_background = background ? 1 : 0;
 queue.active_background = background ? 1 : 0;
 req.flags = (1UL << FR_SENT) | (background ? 1UL << FR_BACKGROUND : 0);
 req.list.count = 1;
 ent = (struct fuse_ring_ent){.queue = &queue, .fuse_req = &req, .cmd = &fc};
}
static void finish(int error) {
 fuse_uring_req_end(&ent, &req, error, 73);
 assert(req.out.h.error == error);
 assert(!test_bit(FR_BACKGROUND, &req.flags));
}
int main(int argc, char **argv) {
 assert(argc == 2); const char *name = argv[1];
 bool foreground = !strcmp(name, "foreground");
 reset(!foreground);
 if (!strcmp(name, "legacy-pending")) {
  fc.bg_queue.count = 1; fc.num_background++; finish(0);
  assert(completion_bg_locks == 2 && legacy_started == 1);
 } else if (!strcmp(name, "per-queue-pending")) {
  queue.pending = 1; fc.num_background++; finish(0);
  assert(queue.pending == 0 && queue.active_background == 1);
  assert(fc.active_background == 1 && completion_bg_locks == 1);
 } else if (!strcmp(name, "mixed-pending")) {
  queue.pending = 1; fc.bg_queue.count = 1; fc.num_background += 2;
  finish(0);
  assert(queue.pending == 0 && legacy_started == 1);
  assert(fc.active_background == 2 && completion_bg_locks == 2);
 } else if (!strcmp(name, "enqueue-after-empty-snapshot")) {
  pthread_t thread;
  assert(!pthread_barrier_init(&enqueue_start, NULL, 2));
  assert(!pthread_barrier_init(&enqueue_done, NULL, 2));
  inject_enqueue = true;
  assert(!pthread_create(&thread, NULL, enqueue_legacy, NULL));
  finish(0); assert(!pthread_join(thread, NULL));
  assert(completion_bg_locks == 1 && legacy_started == 1);
  assert(global_flushes == 1 && fc.bg_queue.count == 0);
  assert(!pthread_barrier_destroy(&enqueue_start));
  assert(!pthread_barrier_destroy(&enqueue_done));
 } else {
  finish(!strcmp(name, "completion-error") ? -EIO : 0);
  assert(completion_bg_locks == (foreground ? 0U : 1U));
  assert(global_flushes == 0 && fc.active_background == 0);
 }
 assert(unregister_calls == 1 && completions == 1);
 assert(!pthread_mutex_destroy(&queue.lock.mutex));
 assert(!pthread_mutex_destroy(&fc.bg_lock.mutex));
 return 0;
}
'''


def production_completion():
    source = (LINUX / "fs/fuse/dev_uring.c").read_text()
    start = source.index("static void fuse_uring_req_end(")
    end = source.index("\n/* Abort all list queued request", start)
    return source[start:end]


class UringBackgroundCompletionTest(unittest.TestCase):
    def test_background_progress_and_locking(self):
        scenarios = ("empty-background", "foreground", "completion-error",
                     "legacy-pending", "per-queue-pending", "mixed-pending",
                     "enqueue-after-empty-snapshot")
        with tempfile.TemporaryDirectory(prefix="extfuse-bg-completion-") as tmp:
            source = Path(tmp) / "completion.c"
            binary = Path(tmp) / "completion"
            source.write_text(HARNESS.replace("/* PRODUCTION_COMPLETION */",
                                             production_completion()))
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O2",
                            "-Wall", "-Wextra", "-Werror", "-pthread",
                            "-fsanitize=undefined", str(source), "-o", str(binary)],
                           check=True, capture_output=True, text=True)
            for scenario in scenarios:
                with self.subTest(scenario=scenario):
                    subprocess.run([str(binary), scenario], check=True,
                                   capture_output=True, text=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
