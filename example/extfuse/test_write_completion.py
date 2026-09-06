#!/usr/bin/env python3
"""Compile actual WRITE completion and END helpers without mounting."""

from pathlib import Path
import shlex
import os
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).parent / "extfuse_passthrough.c").read_text()
HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef uint64_t fuse_ino_t;
typedef void *fuse_req_t;
#define EXTFUSE_NATIVE_STATE_ACTIVE_MASK 255
#define EXTFUSE_NATIVE_STATE_SEQUENCE_MAX 4095
#define PERF_CAPABILITY_XATTR "security.capability"
struct perf_cache_mutation { bool armed, attr_only, xattr_quiescent; size_t count; fuse_ino_t inodes[2]; };
struct perf_cache_snapshot { uint64_t daemon_state, native_state; bool xattr; };
struct perf_cache_lockset { int unused; };
struct perf_inode_generation { uint64_t generation, active, xattr_generation, xattr_active; };
struct lo_data { double timeout; };
struct lo_inode { int fd; dev_t dev; ino_t ino; };
struct fuse_file_info { uint64_t fh; };
struct fuse_bufvec { size_t size; };
typedef int pthread_mutex_t;
enum perf_cache_attr_outcome { PERF_CACHE_ATTR_DISABLED, PERF_CACHE_ATTR_PUBLISHED,
 PERF_CACHE_ATTR_UNSTABLE, PERF_CACHE_ATTR_SUPPRESSED, PERF_CACHE_ATTR_MISSING,
 PERF_CACHE_ATTR_ERROR };
static struct { bool cache_bypass, xattr_cache_bypass; void *session;
 struct { int passthrough_state_errors; } counters; } perf_state;
static struct perf_inode_generation state;
static struct lo_data lower = { 1.0 };
static struct lo_inode inode = { 77, 3, 19 };
static pthread_mutex_t xlock;
static int locked, lock_calls, snapshots, publications, replies, freed, exits, refills;
static int capture_error, native_error, native_active, publish_race, stat_error;
static int publish_error, submit_error, reply_error, begin_error, revoke, xlocked;
static ssize_t returned_size;
static int returned_error;
static void (*pending)(fuse_req_t, ssize_t, void *);
static void *pending_context;

static void cache_mutation_lock(struct perf_cache_mutation *m, struct perf_cache_lockset *l)
{ (void)m; (void)l; assert(!locked); locked = 1; lock_calls++; }
static void cache_mutation_unlock(struct perf_cache_lockset *l) { (void)l; assert(locked); locked = 0; }
static struct perf_inode_generation *find_inode_generation_locked(fuse_ino_t ino)
{ assert(locked && ino == 17); return &state; }
static void publish_inode_generation_locked(fuse_ino_t ino, struct perf_inode_generation *s, const char *why)
{ (void)why; assert(locked && ino == 17 && s == &state); }
static void counter_increment(int *value) { (*value)++; }
static void disable_all_caches_locked(const char *why)
{ (void)why; assert(locked); perf_state.cache_bypass = perf_state.xattr_cache_bypass = true; }
static bool inode_generation_value_locked(struct perf_inode_generation *s, uint64_t *value, bool xattr)
{ assert(locked && !xattr); *value = s->generation * 256 + s->active; return !capture_error; }
static bool native_state_snapshot_locked(fuse_ino_t ino, uint64_t *value, const char *why, bool xattr)
{ (void)why; assert(locked && ino == 17 && !xattr); *value = native_active; return !native_error; }
@END@

static bool cache_snapshot_begin(fuse_ino_t ino, struct perf_cache_snapshot *snapshot)
{ (void)ino; (void)snapshot; assert(!"redundant snapshot lock"); return false; }
static int extfuse_snapshot_pinned_inode(int fd, dev_t dev, ino_t ino, struct stat *st)
{ (void)st; assert(!locked && !xlocked && fd == 77 && dev == 3 && ino == 19); snapshots++;
  if (publish_race) state.generation++; return stat_error ? -EIO : 0; }
static enum perf_cache_attr_outcome cache_attr(fuse_ino_t ino, struct stat *st, double timeout,
 const struct perf_cache_snapshot *snapshot, bool existing, double *reply_timeout)
{ (void)st; assert(!locked && !xlocked && ino == 17 && timeout == 1.0 && !existing);
  *reply_timeout = timeout; publications++;
  if (snapshot->daemon_state != state.generation * 256 + state.active) return PERF_CACHE_ATTR_UNSTABLE;
  return publish_error ? PERF_CACHE_ATTR_ERROR : PERF_CACHE_ATTR_PUBLISHED; }
static pthread_mutex_t *xattr_lock_for_inode(fuse_ino_t ino) { assert(ino == 17); return &xlock; }
static void pthread_mutex_lock(pthread_mutex_t *lock) { assert(lock == &xlock && !locked && !xlocked); xlocked = 1; }
static void pthread_mutex_unlock(pthread_mutex_t *lock) { assert(lock == &xlock && xlocked); xlocked = 0; }
static void invalidate_xattr_serialized(fuse_ino_t ino, const char *name, bool all)
{ (void)name; assert(xlocked && ino == 17 && all && !snapshots && !replies); }
static void prefetch_xattr_serialized(fuse_req_t req, fuse_ino_t ino, const char *name)
{ (void)req; (void)name; assert(xlocked && ino == 17 && !snapshots && !replies); refills++; }
static bool paper_capability_is_safe(void) { return !revoke; }
static bool paper_write_fast_active(void) { return true; }
static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino) { (void)req; assert(ino == 17); return &inode; }
static struct lo_data *lo_data(fuse_req_t req) { (void)req; return &lower; }
static size_t fuse_buf_size(struct fuse_bufvec *buf) { return buf->size; }
static bool fuse_req_is_uring_zero_copy(fuse_req_t req) { return req != NULL; }
static void cache_mutation_add(struct perf_cache_mutation *m, fuse_ino_t ino) { m->count = 1; m->inodes[0] = ino; }
static bool cache_mutation_begin(struct perf_cache_mutation *m)
{ if (begin_error) return false; m->armed = true; state.generation++; state.active++;
  state.xattr_generation++; state.xattr_active++; return true; }
static int fuse_uring_submit_fixed_io(fuse_req_t req, int fd, off_t offset, size_t size, bool write,
 void (*callback)(fuse_req_t, ssize_t, void *), void *context)
{ (void)req; assert(fd == 88 && offset == 4096 && size == 8192 && write && state.active && !locked);
  if (submit_error) return -EAGAIN; pending = callback; pending_context = context; return 0; }
static int fuse_reply_err(fuse_req_t req, int error)
{ (void)req; assert(!locked && !xlocked && !replies); replies++; returned_error = error; return reply_error; }
static int fuse_reply_write(fuse_req_t req, size_t size)
{ (void)req; assert(!locked && !xlocked && !replies); replies++; returned_size = size; return reply_error; }
static void fuse_session_exit(void *session) { assert(session == &perf_state); exits++; }
static void test_free(void *ptr) { assert(ptr); freed++; free(ptr); }
#define free test_free
@WRITE@

int main(int argc, char **argv)
{
 struct fuse_file_info fi = { 88 }; struct fuse_bufvec buf = { 8192 };
 ssize_t result = 8192; const char *which;
 assert(argc == 2); which = argv[1]; perf_state.session = &perf_state;
 if (!strncmp(which, "read-", 5)) {
  struct perf_cache_mutation mutation = { .armed = true, .attr_only = true,
    .count = 1, .inodes = { 17 } };
  struct perf_cache_snapshot snapshot;
  state.generation = state.active = 1;
  native_active = !strcmp(which, "read-native-active");
  capture_error = !strcmp(which, "read-capture-error");
  bool ready = cache_mutation_end_with_snapshot(&mutation, &snapshot);
  assert(ready == (!native_active && !capture_error));
  assert(!state.active && !mutation.armed && lock_calls == 1 && !locked);
  printf("%d 0 0 0 0 0\n", ready);
  return 0;
 }
 if (!strcmp(which, "capture-error")) capture_error = 1;
 else if (!strcmp(which, "native-error")) native_error = 1;
 else if (!strcmp(which, "native-active")) native_active = 1;
 else if (!strcmp(which, "publish-race")) publish_race = 1;
 else if (!strcmp(which, "stat-error")) stat_error = 1;
 else if (!strcmp(which, "publish-error")) publish_error = 1;
 else if (!strcmp(which, "submit-error")) submit_error = 1;
 else if (!strcmp(which, "submit-capture-error")) submit_error = capture_error = 1;
 else if (!strcmp(which, "reply-error")) reply_error = -EPIPE;
 else if (!strcmp(which, "begin-error")) begin_error = 1;
 else if (!strcmp(which, "revoke")) revoke = 1;
 else if (!strcmp(which, "overlap")) { state.active = state.xattr_active = 1; }
 else if (!strcmp(which, "io-error")) result = -EIO;
 else if (!strcmp(which, "short")) result = 4096;
 else if (!strcmp(which, "oversize")) result = 8193;
 perf_write_uring_zero_copy(&fi, 17, &buf, 4096, &fi);
 if (pending) { assert(!freed && !replies); pending(&fi, result, pending_context); }
 assert(!locked && !xlocked && replies == 1 && freed == 1);
 assert(lock_calls == (begin_error ? 0 : 1));
 if (!strcmp(which, "overlap")) assert(state.active == 1 && !snapshots && !publications);
 else assert(!state.active);
 if (native_active || capture_error || native_error) assert(!snapshots && !publications);
 if (revoke) assert(refills == 1 && snapshots == 1);
 printf("%d %d %d %d %zd %d\n", snapshots, publications, refills, exits, returned_size, returned_error);
 return 0;
}
"""


class WriteCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        end = SOURCE.split("static bool cache_mutation_end_capture(", 1)[1]
        end = "static bool cache_mutation_end_capture(" + end.split("static uint64_t timeout_seconds", 1)[0]
        write = SOURCE.split("struct perf_uring_write_context {", 1)[1]
        write = "struct perf_uring_write_context {" + write.split("struct perf_read_context {", 1)[0]
        source = root / "completion.c"
        source.write_text(HARNESS.replace("@END@", end).replace("@WRITE@", write))
        cls.binary = root / "completion"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-O2",
                        "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                        "-Wno-misleading-indentation", str(source), "-o", str(cls.binary)], check=True)

    def case(self, name):
        result = subprocess.run([self.binary, name], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [int(value) for value in result.stdout.split()], result.stderr

    def test_success_overlap_revocation_and_superseded_token(self):
        for name in ("success", "overlap", "revoke", "publish-race", "native-active"):
            with self.subTest(name=name):
                values, errors = self.case(name)
                self.assertEqual(values[3], 0, errors)
                self.assertEqual(values[4:], [8192, 0])

    def test_read_wrapper_retains_inactive_valid_snapshot_requirement(self):
        for name in ("read-success", "read-native-active", "read-capture-error"):
            with self.subTest(name=name):
                self.case(name)

    def test_failed_capture_keeps_quiescent_publication_error(self):
        for name in ("capture-error", "native-error", "stat-error", "publish-error"):
            with self.subTest(name=name):
                values, errors = self.case(name)
                self.assertEqual(values[3], 1)
                self.assertIn("operation=write-attr-publication", errors)
                self.assertEqual(values[4:], [8192, 0])

    def test_submission_failure_reuses_end_snapshot_and_unwinds(self):
        for name in ("submit-error", "submit-capture-error", "begin-error"):
            with self.subTest(name=name):
                values, errors = self.case(name)
                self.assertGreater(values[3], 0)
                self.assertGreater(values[5], 0)
                if name == "submit-capture-error":
                    self.assertIn("operation=write-submit-attr-publication", errors)

    def test_error_short_oversize_and_reply_failure_still_reply_once(self):
        for name in ("io-error", "short", "oversize", "reply-error"):
            with self.subTest(name=name):
                values, errors = self.case(name)
                self.assertGreater(values[3], 0, errors)


if __name__ == "__main__":
    unittest.main()
