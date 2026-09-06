#!/usr/bin/env python3
"""Execute actual CQ dispatch and fixed-completion code without an io_uring instance."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("FUSE_URING_CQ_SOURCE", ROOT / "lib/fuse_uring.c"))
HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define FUSE_LOG_ERR 1
#define FUSE_URING_CQE_BATCH_MAX 32
#define unlikely(x) (x)
#define fallthrough __attribute__((fallthrough))
struct io_uring { int unused; };
struct io_uring_cqe { uint64_t user_data; int res; };
struct fuse_req { int id; };
typedef struct fuse_req *fuse_req_t;
typedef void (*fuse_uring_fixed_io_callback_t)(fuse_req_t, ssize_t, void *);
enum { FUSE_URING_CQE_COMMAND, FUSE_URING_CQE_FIXED_IO };
struct fuse_session { int error; };
struct fuse_ring_pool { struct fuse_session *se; bool zero_copy; };
struct fuse_ring_ent {
 struct fuse_req req;
 fuse_uring_fixed_io_callback_t fixed_io_callback;
 void *fixed_io_userdata;
 bool fixed_io_write, fixed_io_pending, fixed_io_completed;
 int cqe_kind;
};
struct fuse_ring_queue {
 struct fuse_ring_pool *ring_pool; struct io_uring ring; int eventfd, qid;
 uint64_t fixed_write_errors, fixed_write_completed, fixed_write_bytes;
 uint64_t fixed_read_errors, fixed_read_completed, fixed_read_bytes;
};
static struct fuse_session session;
static struct fuse_ring_pool pool = {.se = &session, .zero_copy = true};
static struct fuse_ring_queue queue = {.ring_pool = &pool, .eventfd = 99};
static struct fuse_ring_ent entries[64];
static struct io_uring_cqe completions[64];
static unsigned int cq_head, cq_tail, advances, handled, fixed, retried;
static unsigned int active, metadata_active, log_errors;
static bool append_completion;
static char events[128];
static unsigned int event_index;
static void event(char value) { assert(event_index + 1 < sizeof(events)); events[event_index++] = value; }
static void *io_uring_cqe_get_data(struct io_uring_cqe *cqe) { return (void *)(uintptr_t)cqe->user_data; }
#define io_uring_for_each_cqe(ring, head, cqe) \
 for ((head) = cq_head; (head) < cq_tail && (((cqe) = &completions[head]), 1); (head)++)
static void io_uring_cq_advance(struct io_uring *ring, unsigned int count)
{ assert(ring == &queue.ring && count && cq_head + count <= cq_tail); cq_head += count; advances++; }
static void fuse_log(int level, const char *format, ...)
{ (void)format; assert(level == FUSE_LOG_ERR); log_errors++; }
static void add_command(unsigned int index, int result)
{
 assert(index < 64); entries[index].req.id = index;
 entries[index].cqe_kind = FUSE_URING_CQE_COMMAND;
 completions[index].user_data = (uintptr_t)&entries[index]; completions[index].res = result;
 if (cq_tail <= index) cq_tail = index + 1;
}
static void fixed_callback(fuse_req_t req, ssize_t result, void *userdata)
{
 struct fuse_ring_ent *ent = userdata;
 assert(req == &ent->req && !ent->fixed_io_pending && ent->fixed_io_completed);
 assert(ent->cqe_kind == FUSE_URING_CQE_COMMAND && active && !advances);
 assert(result == 4096 || result == -EIO || result == -EAGAIN);
 active--; fixed++; event('F');
 if (append_completion) { append_completion = false; add_command(cq_tail, 0); }
}
static void add_fixed(unsigned int index, int result)
{
 add_command(index, result); active++;
 entries[index].cqe_kind = FUSE_URING_CQE_FIXED_IO;
 entries[index].fixed_io_pending = true; entries[index].fixed_io_write = true;
 entries[index].fixed_io_callback = fixed_callback; entries[index].fixed_io_userdata = &entries[index];
}
static int fuse_uring_handle_cqe(struct fuse_ring_queue *q, struct io_uring_cqe *cqe)
{
 struct fuse_ring_ent *ent = io_uring_cqe_get_data(cqe);
 assert(q == &queue && ent && !ent->fixed_io_completed);
 handled++; metadata_active += active != 0; event('G'); return 0;
}
static void fuse_uring_resubmit(struct fuse_ring_queue *q, struct fuse_ring_ent *ent)
{ assert(q == &queue && ent && !ent->fixed_io_pending); retried++; event('R'); }
@PRODUCTION@
int main(int argc, char **argv)
{
 int result; const char *name;
 assert(argc == 2); name = argv[1];
 if (!strcmp(name, "empty")) {
  assert(!fuse_uring_queue_handle_cqes(&queue) && !advances && !handled && !fixed);
  puts("PASS"); return 0;
 }
 if (!strcmp(name, "bound")) {
  for (unsigned int i = 0; i < 37; i++) add_command(i, 0);
  add_fixed(33, 4096);
  assert(!fuse_uring_queue_handle_cqes(&queue));
  assert(cq_head == 32 && handled == 32 && metadata_active == 32 && !fixed);
  advances = 0;
  assert(!fuse_uring_queue_handle_cqes(&queue));
  assert(cq_head == 37 && handled == 36 && metadata_active == 32 && fixed == 1 && !active);
  puts("PASS"); return 0;
 }
 add_command(0, 0); add_fixed(1, 4096);
 if (!strcmp(name, "copied")) pool.zero_copy = false;
 if (!strcmp(name, "new-arrival")) append_completion = true;
 if (!strcmp(name, "io-error")) completions[1].res = -EIO;
 if (!strcmp(name, "fixed-eagain")) completions[1].res = -EAGAIN;
 if (!strcmp(name, "retry")) { completions[0].res = -EAGAIN; add_command(2, -EINTR); }
 if (!strcmp(name, "command-error")) { completions[0].res = -ENOSPC; add_command(2, 0); }
 if (!strcmp(name, "unmount-command")) completions[0].res = -ENOTCONN;
 if (!strcmp(name, "bad-fixed")) entries[1].fixed_io_pending = false;
 if (!strcmp(name, "event-stop") || !strcmp(name, "event-cancel") || !strcmp(name, "event-error")) {
  completions[0].user_data = queue.eventfd;
  completions[0].res = !strcmp(name, "event-stop") ? 1 :
                      !strcmp(name, "event-cancel") ? -ECANCELED : -EBADF;
 }
 result = fuse_uring_queue_handle_cqes(&queue);
 if (!strcmp(name, "copied")) {
  assert(!result && !strcmp(events, "GF") && metadata_active == 1 && cq_head == 2);
 } else if (!strcmp(name, "new-arrival")) {
  assert(!result && !strcmp(events, "FG") && cq_head == 2 && cq_tail == 3 && !metadata_active);
  assert(!fuse_uring_queue_handle_cqes(&queue));
  assert(!strcmp(events, "FGG") && cq_head == 3 && fixed == 1 && handled == 2);
 } else if (!strcmp(name, "retry")) {
  assert(!result && !strcmp(events, "FRR") && retried == 2 && !handled && cq_head == 3);
 } else if (!strcmp(name, "command-error")) {
  assert(result == -ENOSPC && session.error == -ENOSPC && !strcmp(events, "FG") && cq_head == 3);
 } else if (!strcmp(name, "unmount-command")) {
  assert(!result && !session.error && !strcmp(events, "F") && cq_head == 2);
 } else if (!strcmp(name, "bad-fixed")) {
  assert(result == -EIO && log_errors == 1 && !fixed && handled == 1 && cq_head == 2);
 } else if (!strcmp(name, "event-stop")) {
  assert(result == -ENOTCONN && !advances && !handled && fixed == 1 && !active);
 } else if (!strcmp(name, "event-cancel")) {
  assert(!result && !handled && fixed == 1 && cq_head == 2);
 } else if (!strcmp(name, "event-error")) {
  assert(result == -EBADF && !handled && fixed == 1 && cq_head == 2);
 } else {
  assert(!result && !strcmp(events, "FG") && !metadata_active && !active && cq_head == 2);
  assert(fixed == 1 && handled == 1 && !retried);
 }
 if (!strcmp(name, "io-error") || !strcmp(name, "fixed-eagain"))
  assert(queue.fixed_write_errors == 1 && !queue.fixed_write_completed);
 else if (strcmp(name, "bad-fixed"))
  assert(queue.fixed_write_completed == 1 && queue.fixed_write_bytes == 4096);
 puts("PASS"); return 0;
}
"""


def function(source, name):
    match = re.search(r"^static (?:int|bool) " + name + r"\(", source, re.M)
    if match is None:
        return ""
    opening = source.index("{", match.start())
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():end + 1]
    raise AssertionError("unterminated production function")


class UringCompletionPriorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text()
        names = ("fuse_uring_handle_fixed_io_cqe", "fuse_uring_cqe_is_fixed_io",
                 "fuse_uring_dispatch_cqe", "fuse_uring_queue_handle_cqes")
        production = "\n".join(function(source, name) for name in names)
        cls.temporary = tempfile.TemporaryDirectory(prefix="fuse-uring-cq-")
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        path = root / "completion.c"
        path.write_text(HARNESS.replace("@PRODUCTION@", production))
        cls.binary = root / "completion"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-O2",
                        "-Wall", "-Wextra", "-Werror", "-include", "sys/types.h",
                        str(path), "-o", str(cls.binary)], check=True, timeout=20)

    def cases(self, *names):
        for name in names:
            with self.subTest(name=name):
                result = subprocess.run([str(self.binary), name], capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "PASS")

    def test_ready_lower_completion_ends_mutation_before_getattr(self):
        self.cases("priority")

    def test_copied_transport_retains_original_fifo_order(self):
        self.cases("copied")

    def test_snapshot_kind_and_new_arrival_do_not_double_dispatch(self):
        self.cases("new-arrival", "bound", "empty")

    def test_lower_error_cqes_remain_completions_not_retries(self):
        self.cases("io-error", "fixed-eagain", "bad-fixed")

    def test_command_retry_errors_and_disconnect_keep_existing_rules(self):
        self.cases("retry", "command-error", "unmount-command")

    def test_eventfd_stop_cancel_error(self):
        self.cases("event-stop", "event-cancel", "event-error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
