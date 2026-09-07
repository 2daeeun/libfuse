#!/usr/bin/env python3
"""Exercise the paired kernel's buffered WRITE submission/completion bodies.

Run explicitly when C compilation is authorized. This fixture substitutes VFS,
iterator, locking, and asynchronous completion boundaries; it does not build a
kernel, mount a filesystem, or establish real concurrency/performance behavior.
Calling harness_source() only extracts C source and never invokes a compiler.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


KERNEL = Path(os.environ.get(
    "EXTFUSE_KERNEL_SOURCE", Path(__file__).resolve().parents[3] / "linux"))


def function(source, name):
    match = re.search(r"^(?:static )?[^;{}\n]*\b" + name +
                      r"\([^;{}]*\)\s*\{", source, re.M)
    if match is None:
        raise AssertionError(f"missing function {name}")
    opening = source.index("{", match.start())
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if not depth:
            return source[match.start():end + 1]
    raise AssertionError(f"unterminated function {name}")


HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
typedef int64_t loff_t;
typedef uint32_t u32;
#define likely(value) (value)
#define unlikely(value) (value)
#define IORING_OP_WRITE_FIXED 1
#define IO_URING_F_INLINE (1U << 0)
#define IO_URING_F_NONBLOCK (1U << 1)
#define IO_URING_F_COMPLETE_DEFER (1U << 2)
#define IO_URING_F_UNLOCKED (1U << 3)
#define IO_URING_F_IOWQ (1U << 4)
#define IORING_SETUP_SINGLE_ISSUER (1U << 0)
#define IORING_SETUP_DEFER_TASKRUN (1U << 1)
#define IORING_SETUP_SQPOLL (1U << 2)
#define IORING_SETUP_IOPOLL (1U << 3)
#define REQ_F_BUF_NODE (1U << 0)
#define REQ_F_ISREG (1U << 1)
#define REQ_F_FORCE_ASYNC (1U << 2)
#define REQ_F_NOWAIT (1U << 3)
#define REQ_F_LINK (1U << 4)
#define REQ_F_HARDLINK (1U << 5)
#define REQ_F_HAS_METADATA (1U << 6)
#define REQ_F_IMPORT_BUFFER (1U << 7)
#define REQ_F_CUR_POS (1U << 8)
#define REQ_F_REISSUE (1U << 9)
#define REQ_F_BL_NO_RECYCLE (1U << 10)
#define IOCB_DIRECT (1U << 0)
#define IOCB_NOWAIT (1U << 1)
#define IOCB_HIPRI (1U << 2)
#define IOCB_WRITE (1U << 3)
#define FOP_BUFFER_WASYNC (1U << 0)
#define O_NONBLOCK (1U << 0)
#define FMODE_WRITE 1
#define WRITE 1
#define ITER_SOURCE 1
#define EPOLLOUT 1
#define IOU_COMPLETE 100
#define IOU_ISSUE_SKIP_COMPLETE 101
#define EIOCBQUEUED 529
#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516
#define S_ISBLK(mode) ((mode) == 2)
struct file;
struct kiocb { struct file *ki_filp; loff_t ki_pos; unsigned ki_flags; };
struct iov_iter { size_t count; };
struct iov_iter_state { size_t count; };
struct io_async_rw {
 struct iov_iter iter; struct iov_iter_state iter_state; size_t bytes_done;
};
struct file_operations {
 unsigned fop_flags;
 ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
 bool write;
};
struct inode { unsigned i_mode; };
struct file {
 unsigned f_flags; struct file_operations *f_op; loff_t f_pos;
 struct inode inode;
};
struct io_mapped_ubuf { bool is_kbuf, write_in_task; };
struct io_rsrc_node { struct io_mapped_ubuf *buf; };
struct io_ring_ctx { unsigned flags; void *submitter_task; bool uring_lock; };
struct io_rw { struct kiocb kiocb; };
struct io_kiocb {
 struct io_ring_ctx *ctx; struct file *file; struct io_rsrc_node *buf_node;
 struct io_async_rw *async_data; unsigned flags, opcode; bool failed;
 struct { int res; unsigned flags; } cqe; struct io_rw rw;
};
struct io_br_sel { void *buf_list; };
#define io_kiocb_to_cmd(req, type) (&(req)->rw)
#define file_inode(file) (&(file)->inode)
static int owner;
static void *current = &owner;
static struct io_kiocb *active;
static bool expect_drop = true, worker, nowait_supported = true, start_ok = true;
static int import_result, init_result, verify_result;
static ssize_t lower_result = 4096, callback_result;
static unsigned unlocks, locks, verifies, starts, writes, ends, notifications;
static unsigned cleans, result_sets, callbacks, traces, short_traces, saved;
static unsigned restored, meta_restored, outstanding_writes;

/* VFS may sleep here. Completion/request-cache operations require reentry. */
static void assert_lower_lock(void)
{ assert(active->ctx->uring_lock == !(expect_drop || worker)); }
static void assert_completion_lock(void)
{ assert(active->ctx->uring_lock == !worker); }
static void mutex_unlock(bool *lock)
{ assert(*lock); *lock = false; unlocks++; }
static void mutex_lock(bool *lock)
{ assert(!*lock); *lock = true; locks++; }
static size_t iov_iter_count(struct iov_iter *iter) { return iter->count; }
static void iov_iter_save_state(struct iov_iter *iter, struct iov_iter_state *state)
{ assert_completion_lock(); state->count = iter->count; saved++; }
static void iov_iter_restore(struct iov_iter *iter, struct iov_iter_state *state)
{ assert_completion_lock(); iter->count = state->count; restored++; }
static void io_meta_restore(struct io_async_rw *io, struct kiocb *kiocb)
{ (void)io; (void)kiocb; assert_completion_lock(); meta_restored++; }
static int io_rw_import_reg_vec(struct io_kiocb *req, struct io_async_rw *io,
                               int direction, unsigned flags)
{ (void)req; (void)io; (void)flags; assert(direction == ITER_SOURCE);
  assert_completion_lock(); return import_result; }
static int io_rw_init_file(struct io_kiocb *req, int mode, int direction)
{ assert(req == active && mode == FMODE_WRITE && direction == WRITE);
  assert_completion_lock(); return init_result; }
static bool io_file_supports_nowait(struct io_kiocb *req, int events)
{ assert(req == active && events == EPOLLOUT); return nowait_supported; }
static loff_t *io_kiocb_update_pos(struct io_kiocb *req)
{ assert_lower_lock(); return &req->rw.kiocb.ki_pos; }
static int rw_verify_area(int direction, struct file *file, loff_t *pos, size_t count)
{ assert_lower_lock(); assert(direction == WRITE && file == active->file);
  assert(pos == &active->rw.kiocb.ki_pos && count == active->async_data->iter.count);
  verifies++; return verify_result; }
static bool io_kiocb_start_write(struct io_kiocb *req, struct kiocb *kiocb)
{ assert_lower_lock(); assert(req == active && kiocb == &req->rw.kiocb);
  starts++; if (start_ok) outstanding_writes++; return start_ok; }
static ssize_t lower_write(struct kiocb *kiocb, struct iov_iter *iter)
{ assert_lower_lock(); assert(kiocb == &active->rw.kiocb && outstanding_writes == 1);
  if (expect_drop) assert(!(kiocb->ki_flags & IOCB_NOWAIT));
  writes++;
  if (lower_result >= 0) {
   assert((size_t)lower_result <= iter->count);
   iter->count -= lower_result; kiocb->ki_pos += lower_result;
  }
  return lower_result; }
static ssize_t loop_rw_iter(int direction, struct io_rw *rw, struct iov_iter *iter)
{ assert(direction == WRITE); return lower_write(&rw->kiocb, iter); }
static void trace_io_uring_write_in_task(struct io_kiocb *req, long result)
{ assert_completion_lock(); assert(req == active && result == lower_result); traces++; }
static void trace_io_uring_short_write(struct io_ring_ctx *ctx, loff_t pos,
                                      int wanted, long result)
{ assert_completion_lock(); assert(ctx == active->ctx && pos >= 0);
  assert(result >= 0 && result < wanted); short_traces++; }
static void kiocb_end_write(struct kiocb *kiocb)
{ assert_completion_lock(); assert(kiocb == &active->rw.kiocb && outstanding_writes == 1);
  outstanding_writes--; ends++; }
static void fsnotify_modify(struct file *file)
{ assert_completion_lock(); assert(file == active->file && !outstanding_writes);
  notifications++; }
static void fsnotify_access(struct file *file)
{ (void)file; assert(!"WRITE must use modification notification"); }
static bool req_has_async_data(struct io_kiocb *req) { return req->async_data != NULL; }
static bool io_rw_should_reissue(struct io_kiocb *req)
{ (void)req; assert_completion_lock(); return false; }
static void req_set_fail(struct io_kiocb *req) { req->failed = true; }
static unsigned io_put_kbuf(struct io_kiocb *req, long result, void *list)
{ (void)req; (void)result; (void)list; assert(!"fixed WRITE has no selected buffer"); return 0; }
static void io_req_set_res(struct io_kiocb *req, unsigned result, unsigned flags)
{ assert_completion_lock(); assert(!outstanding_writes);
  req->cqe.res = result; req->cqe.flags = flags; result_sets++; }
static void io_req_rw_cleanup(struct io_kiocb *req, unsigned flags)
{ (void)flags; assert_completion_lock(); assert(req == active && result_sets == 1); cleans++; }
/* Model the enqueue boundary, not later task-work or the filesystem callback. */
static void io_complete_rw(struct kiocb *kiocb, long result)
{ assert_completion_lock(); assert(kiocb == &active->rw.kiocb);
  callbacks++; callback_result = result; }
static void io_complete_rw_iopoll(struct kiocb *kiocb, long result)
{ (void)kiocb; (void)result; assert(!"opted-in WRITE excludes IOPOLL"); }

@END_WRITE@
@IO_END@
@COMMON@
@FIXUP@
@RW_DONE@
@KIOCB_DONE@
@NEED_COMPLETE@
@ELIGIBLE@
@WRITE@

static bool refuse(const char *name, struct io_kiocb *req, unsigned *flags)
{
 if (!strcmp(name, "unmarked")) req->buf_node->buf->write_in_task = false;
 else if (!strcmp(name, "user-buffer")) req->buf_node->buf->is_kbuf = false;
 else if (!strcmp(name, "no-node")) { req->flags &= ~REQ_F_BUF_NODE; req->buf_node = NULL; }
 else if (!strcmp(name, "read")) req->opcode = 2;
 else if (!strcmp(name, "wrong-owner")) req->ctx->submitter_task = NULL;
 else if (!strcmp(name, "missing-single")) req->ctx->flags &= ~IORING_SETUP_SINGLE_ISSUER;
 else if (!strcmp(name, "missing-defer")) req->ctx->flags &= ~IORING_SETUP_DEFER_TASKRUN;
 else if (!strcmp(name, "sqpoll")) req->ctx->flags |= IORING_SETUP_SQPOLL;
 else if (!strcmp(name, "iopoll")) req->ctx->flags |= IORING_SETUP_IOPOLL;
 else if (!strcmp(name, "explicit-async")) req->flags |= REQ_F_FORCE_ASYNC;
 else if (!strcmp(name, "explicit-nowait")) req->flags |= REQ_F_NOWAIT;
 else if (!strcmp(name, "link")) req->flags |= REQ_F_LINK;
 else if (!strcmp(name, "hardlink")) req->flags |= REQ_F_HARDLINK;
 else if (!strcmp(name, "metadata")) req->flags |= REQ_F_HAS_METADATA;
 else if (!strcmp(name, "direct")) req->rw.kiocb.ki_flags |= IOCB_DIRECT;
 else if (!strcmp(name, "kiocb-nowait")) req->rw.kiocb.ki_flags |= IOCB_NOWAIT;
 else if (!strcmp(name, "hipri")) req->rw.kiocb.ki_flags |= IOCB_HIPRI;
 else if (!strcmp(name, "nonblocking-file")) req->file->f_flags |= O_NONBLOCK;
 else if (!strcmp(name, "native-async")) req->file->f_op->fop_flags |= FOP_BUFFER_WASYNC;
 else if (!strcmp(name, "no-iter")) req->file->f_op->write_iter = NULL;
 else if (!strcmp(name, "negative-offset")) req->rw.kiocb.ki_pos = -1;
 else if (!strcmp(name, "not-regular")) req->flags &= ~REQ_F_ISREG;
 else if (!strcmp(name, "not-inline")) *flags &= ~IO_URING_F_INLINE;
 else if (!strcmp(name, "not-nonblock")) *flags &= ~IO_URING_F_NONBLOCK;
 else if (!strcmp(name, "not-deferred")) *flags &= ~IO_URING_F_COMPLETE_DEFER;
 else if (!strcmp(name, "unlocked")) *flags |= IO_URING_F_UNLOCKED;
 else if (!strcmp(name, "worker")) *flags |= IO_URING_F_IOWQ;
 else return false;
 return true;
}

int main(int argc, char **argv)
{
 assert(argc == 2); const char *name = argv[1];
 struct io_ring_ctx ctx = {
  .flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
  .submitter_task = current, .uring_lock = true,
 };
 struct file_operations ops = { .write_iter = lower_write };
 struct file file = { .f_op = &ops, .inode.i_mode = 1 };
 struct io_mapped_ubuf buffer = { .is_kbuf = true, .write_in_task = true };
 struct io_rsrc_node node = { .buf = &buffer };
 struct io_async_rw io = { .iter.count = 4096, .iter_state.count = 4096 };
 struct io_kiocb req = {
  .ctx = &ctx, .file = &file, .buf_node = &node, .async_data = &io,
  .flags = REQ_F_BUF_NODE | REQ_F_ISREG, .opcode = IORING_OP_WRITE_FIXED,
  .rw.kiocb.ki_filp = &file,
 };
 unsigned flags = IO_URING_F_INLINE | IO_URING_F_NONBLOCK | IO_URING_F_COMPLETE_DEFER;
 active = &req;
 if (!strncmp(name, "refuse-", 7)) {
  assert(refuse(name + 7, &req, &flags));
  assert(!io_write_should_run_in_task(&req, flags));
  return 0;
 }
 assert(io_write_should_run_in_task(&req, flags));
 if (!strcmp(name, "legacy-ext4")) { buffer.write_in_task = false; expect_drop = false; }
 else if (!strcmp(name, "verify-error")) verify_result = -EACCES;
 else if (!strcmp(name, "freeze-retry")) start_ok = false;
 else if (!strcmp(name, "init-error")) init_result = -EBADF;
 else if (!strcmp(name, "import-error")) { req.flags |= REQ_F_IMPORT_BUFFER; import_result = -EFAULT; }
 else if (!strcmp(name, "short") || !strcmp(name, "short-then-error")) lower_result = 2048;
 else if (!strcmp(name, "zero")) lower_result = 0;
 else if (!strcmp(name, "error")) lower_result = -EIO;
 else if (!strcmp(name, "lower-retry")) lower_result = -EAGAIN;
 else if (!strcmp(name, "unsupported")) lower_result = -EOPNOTSUPP;
 else if (!strcmp(name, "restart")) lower_result = -ERESTARTSYS;
 else if (!strcmp(name, "queued")) lower_result = -EIOCBQUEUED;
 else if (!strcmp(name, "current-position")) req.flags |= REQ_F_CUR_POS;
 else assert(!strcmp(name, "full"));
 int ret = io_write(&req, flags);
 assert(ctx.uring_lock);
 if (init_result || import_result) {
  assert(ret == (import_result ? import_result : init_result));
  assert(!unlocks && !locks && !verifies && !starts && !writes);
 } else if (!expect_drop) {
  assert(ret == -EAGAIN && !unlocks && !locks && !verifies && !starts && !writes);
  assert(restored == 1 && meta_restored == 1 && io.iter.count == 4096);
 } else {
  assert(unlocks == 1 && locks == 1 && verifies == 1);
  if (verify_result || !start_ok) {
   assert(ret == (verify_result ? verify_result : -EAGAIN));
   assert(starts == (unsigned)!verify_result && !writes && !traces);
  } else {
   assert(starts == 1 && writes == 1 && traces == 1);
   if (lower_result == 4096) {
    assert(ret == IOU_COMPLETE && req.cqe.res == 4096 && !req.cqe.flags && !req.failed);
    assert(ends == 1 && notifications == 1 && cleans == 1 && result_sets == 1);
    assert(!callbacks && !outstanding_writes && !io.iter.count);
    assert(file.f_pos == ((req.flags & REQ_F_CUR_POS) ? 4096 : 0));
    return 0;
   }
   if (lower_result >= 0) {
    assert(ret == -EAGAIN && io.bytes_done == (size_t)lower_result);
    assert(saved == 1 && short_traces == 1 && ends == 1 && !outstanding_writes);
    assert(io.iter.count == 4096 - io.bytes_done && io.iter_state.count == io.iter.count);
    assert(!notifications && !cleans && !result_sets && !callbacks && !restored);
    if (!strcmp(name, "zero")) return 0;
    /* Re-enter as the existing worker retry would, preserving the iterator. */
    worker = true; expect_drop = false; ctx.uring_lock = false;
    lower_result = !strcmp(name, "short-then-error") ? -EIO : 2048;
    ret = io_write(&req, IO_URING_F_UNLOCKED | IO_URING_F_IOWQ);
    assert(!ctx.uring_lock && unlocks == 1 && locks == 1 && traces == 1);
    assert(verifies == 2 && starts == 2 && writes == 2);
    if (lower_result < 0) {
     assert(ret == IOU_ISSUE_SKIP_COMPLETE && callbacks == 1 && callback_result == -EIO);
     assert(io_fixup_rw_res(&req, callback_result) == 2048);
     assert(outstanding_writes == 1 && ends == 1 && !notifications && !cleans && !result_sets);
    } else {
     assert(ret == IOU_COMPLETE && req.cqe.res == 4096 && !io.iter.count && !req.failed);
     assert(ends == 2 && notifications == 1 && cleans == 1 && result_sets == 1);
     assert(!outstanding_writes && !callbacks);
    }
    return 0;
   }
   assert(ret == IOU_ISSUE_SKIP_COMPLETE && outstanding_writes == 1 && !ends);
   assert(callbacks == (unsigned)(lower_result != -EIOCBQUEUED));
   if (callbacks)
    assert(callback_result == (lower_result == -ERESTARTSYS ? -EINTR : lower_result));
   assert(!notifications && !cleans && !result_sets);
   return 0;
  }
 }
 assert(!outstanding_writes && !ends && !notifications && !cleans && !result_sets && !callbacks);
 return 0;
}
"""


def harness_source():
    source = (KERNEL / "io_uring/rw.c").read_text()
    code = HARNESS
    for tag, name in (
            ("END_WRITE", "io_req_end_write"),
            ("IO_END", "io_req_io_end"),
            ("COMMON", "__io_complete_rw_common"),
            ("FIXUP", "io_fixup_rw_res"),
            ("RW_DONE", "io_rw_done"),
            ("KIOCB_DONE", "kiocb_done"),
            ("NEED_COMPLETE", "need_complete_io"),
            ("ELIGIBLE", "io_write_should_run_in_task"),
            ("WRITE", "io_write")):
        code = code.replace(f"@{tag}@", function(source, name))
    return code


class WriteInTaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (KERNEL / "io_uring/rw.c").exists():
            if "EXTFUSE_KERNEL_SOURCE" in os.environ:
                raise AssertionError("EXTFUSE_KERNEL_SOURCE must name the paired Linux tree")
            raise unittest.SkipTest("EXTFUSE_KERNEL_SOURCE must name the paired Linux tree")
        code = harness_source()
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-write-in-task-")
        cls.addClassCleanup(cls.directory.cleanup)
        path = Path(cls.directory.name)
        (path / "check.c").write_text(code)
        cls.binary = path / "check"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=c11",
                        "-Wall", "-Wextra", "-Werror", str(path / "check.c"),
                        "-o", str(cls.binary)], check=True, timeout=20)

    def test_full_write_relocks_before_inline_completion_and_notifications(self):
        self.check("full")
        self.check("current-position")

    def test_unmarked_buffer_keeps_existing_buffered_write_punt(self):
        self.check("legacy-ext4")

    def test_early_failures_balance_lock_and_never_report_success(self):
        for name in ("verify-error", "freeze-retry", "init-error", "import-error"):
            with self.subTest(name=name):
                self.check(name)

    def test_partial_write_retains_progress_for_worker_retry(self):
        for name in ("short", "short-then-error", "zero"):
            with self.subTest(name=name):
                self.check(name)

    def test_error_restart_and_queued_results_keep_original_completion_path(self):
        for name in ("error", "lower-retry", "unsupported", "restart", "queued"):
            with self.subTest(name=name):
                self.check(name)

    def test_other_requests_keep_their_execution_policy(self):
        for name in (
                "unmarked", "user-buffer", "no-node", "read", "wrong-owner",
                "missing-single", "missing-defer", "sqpoll", "iopoll",
                "explicit-async", "explicit-nowait", "link", "hardlink",
                "metadata", "direct", "kiocb-nowait", "hipri", "nonblocking-file",
                "native-async", "no-iter", "negative-offset", "not-regular",
                "not-inline", "not-nonblock", "not-deferred", "unlocked", "worker"):
            with self.subTest(name=name):
                self.check(f"refuse-{name}")

    def check(self, name):
        subprocess.run([str(self.binary), name], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
