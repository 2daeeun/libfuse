#!/usr/bin/env python3
"""Run the actual classic WRITE callback against bounded lower/reply fixtures."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get("EXTFUSE_SYNC_WRITE_SOURCE", ROOT / "extfuse_passthrough.c"))
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
typedef int pthread_mutex_t;
#define EXTFUSE_NATIVE_STATE_ACTIVE_MASK 255
#define PERF_CAPABILITY_XATTR "security.capability"
#define FUSE_MUTATION_NODE_ATTR_VALID 1
struct lo_data { double timeout; };
struct lo_inode { int fd; dev_t dev; ino_t ino; };
struct perf_cache_mutation { bool armed, xattr_quiescent; };
struct perf_cache_snapshot { uint64_t daemon_state, native_state; };
struct fuse_mutation_attr { fuse_ino_t ino; struct stat *attr; double attr_timeout; int flags; };
struct fuse_file_info { int writepage; };
struct fuse_bufvec { size_t size; };
enum perf_cache_attr_outcome { PERF_CACHE_ATTR_DISABLED, PERF_CACHE_ATTR_PUBLISHED,
 PERF_CACHE_ATTR_UNSTABLE, PERF_CACHE_ATTR_SUPPRESSED, PERF_CACHE_ATTR_MISSING, PERF_CACHE_ATTR_ERROR };
static struct { bool wbcache_passthrough_requested, paper_write_fast; void *session;
 struct { int wbcache_daemon_write_fallbacks, write; } counters; } perf_state;
static struct lo_data lower = {1.0};
static struct lo_inode inode = {77, 3, 19};
static pthread_mutex_t xlock;
static bool fast = true, overlap, revoke, stat_error, metadata, active, locked;
static int replies, exits, reply_error, returned_error, attr_replies, lower_calls;
static size_t returned_size;
static ssize_t lower_result = 8192;
static char events[64];
static size_t event_index;
static void event(char ch) { assert(event_index + 1 < sizeof(events)); events[event_index++] = ch; }
static void counter_increment(int *counter) { (*counter)++; }
static void callback_increment(int *counter) { (*counter)++; }
static bool c2_fixed_write_enabled(void) { return false; }
static bool metadata_hits_enabled(void) { return true; }
static bool paper_write_fast_active(void) { return fast; }
static bool paper_capability_is_safe(void) { return !revoke; }
static bool mutation_metadata_enabled(void) { return metadata; }
static struct lo_data *lo_data(fuse_req_t req) { (void)req; return &lower; }
static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino) { (void)req; assert(ino == 17); return &inode; }
static pthread_mutex_t *xattr_lock_for_inode(fuse_ino_t ino) { assert(ino == 17); return &xlock; }
static void pthread_mutex_lock(pthread_mutex_t *lock) { assert(lock == &xlock && !locked); locked = true; }
static void pthread_mutex_unlock(pthread_mutex_t *lock) { assert(lock == &xlock && locked); locked = false; }
static bool negative_capability_cache_current_serialized(fuse_ino_t ino, uint64_t *state)
{ assert(ino == 17 && locked); *state = 0; return false; }
static void invalidate_attr(fuse_ino_t ino) { assert(ino == 17); }
static void invalidate_xattr_serialized(fuse_ino_t ino, const char *name, bool all)
{ (void)name; assert(ino == 17 && all && locked); }
static void refresh_negative_capability_serialized(fuse_ino_t ino, uint64_t state)
{ (void)ino; (void)state; assert(!"unexpected negative-row carry"); }
static void refill_capability_after_write(fuse_req_t req, fuse_ino_t ino)
{ (void)req; assert(ino == 17 && !active && !replies); event('C'); }
static void cache_mutation_add(struct perf_cache_mutation *mutation, fuse_ino_t ino)
{ (void)mutation; assert(ino == 17); }
static bool cache_mutation_begin(struct perf_cache_mutation *mutation)
{ assert(!active); mutation->armed = active = true; event('B'); return true; }
static bool cache_mutation_end(struct perf_cache_mutation *mutation)
{ assert(active && mutation->armed); active = mutation->armed = false;
 mutation->xattr_quiescent = !overlap; event('E'); return !overlap; }
static __attribute__((unused)) size_t fuse_buf_size(struct fuse_bufvec *buf) { return buf->size; }
static ssize_t lo_do_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *buf,
 off_t off, struct fuse_file_info *fi)
{ (void)req; (void)fi; assert(ino == 17 && off == 4096 && buf->size == 8192 && active);
 lower_calls++; event('W'); buf->size = 0; return lower_result; }
static void lo_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *buf,
 off_t off, struct fuse_file_info *fi)
{ (void)req; (void)ino; (void)buf; (void)off; (void)fi; assert(!"unexpected nonmetadata path"); }
static void perf_write_uring_zero_copy(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *buf,
 off_t off, struct fuse_file_info *fi)
{ (void)req; (void)ino; (void)buf; (void)off; (void)fi; assert(!"unexpected fixed path"); }
static bool cache_snapshot_begin(fuse_ino_t ino, struct perf_cache_snapshot *snapshot)
{ assert(ino == 17 && !active); memset(snapshot, 0, sizeof(*snapshot)); return true; }
static int extfuse_snapshot_pinned_inode(int fd, dev_t dev, ino_t ino, struct stat *st)
{ (void)st; assert(fd == 77 && dev == 3 && ino == 19 && !active && !locked && !replies);
 event('S'); return stat_error ? -EIO : 0; }
static enum perf_cache_attr_outcome cache_attr(fuse_ino_t ino, struct stat *st,
 double timeout, const struct perf_cache_snapshot *snapshot, bool existing, double *reply_timeout)
{ (void)st; (void)snapshot; assert(ino == 17 && timeout == 1.0 && !existing && !active && !replies);
 *reply_timeout = timeout; event('P'); return PERF_CACHE_ATTR_PUBLISHED; }
static double epoch_attr_timeout(fuse_ino_t ino, double timeout) { assert(ino == 17); return timeout; }
static int fuse_reply_err(fuse_req_t req, int error)
{ (void)req; assert(!active && !locked && !replies); replies++; returned_error = error; event('R'); return reply_error; }
static int fuse_reply_write(fuse_req_t req, size_t size)
{ (void)req; assert(!active && !locked && !replies); replies++; returned_size = size; event('R'); return reply_error; }
static int fuse_reply_write_attr(fuse_req_t req, size_t size, const struct fuse_mutation_attr *attr)
{ assert(attr->ino == 17 && attr->attr_timeout == 1.0); attr_replies++; return fuse_reply_write(req, size); }
static void fuse_session_exit(void *session) { assert(session == &perf_state); exits++; event('X'); }
@CONTRACT@
@CALLBACK@
int main(int argc, char **argv)
{
 struct fuse_file_info fi = {.writepage = 1}; struct fuse_bufvec buf = {.size = 8192};
 assert(argc == 2); perf_state.session = &perf_state; perf_state.paper_write_fast = true;
 if (strstr(argv[1], "ordinary")) fi.writepage = 0;
 if (strstr(argv[1], "legacy")) fast = false;
 if (strstr(argv[1], "short")) lower_result = 4096;
 if (strstr(argv[1], "zero")) lower_result = 0;
 if (strstr(argv[1], "oversize")) lower_result = 8193;
 if (strstr(argv[1], "io-error")) lower_result = -ENOSPC;
 stat_error = strstr(argv[1], "stat-error") != NULL;
 overlap = strstr(argv[1], "overlap") != NULL;
 revoke = strstr(argv[1], "revoke") != NULL;
 metadata = strstr(argv[1], "metadata") != NULL;
 if (strstr(argv[1], "reply-error")) reply_error = -EPIPE;
 perf_write_buf(&fi, 17, &buf, 4096, &fi);
 assert(lower_calls == 1 && replies == 1 && !active && !locked);
 printf("%s %d %zu %d %d\n", events, returned_error, returned_size, exits, attr_replies);
 return 0;
}
"""


def extract(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


class SyncWriteCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text()
        contract = extract(source, "static void perf_write_contract_failed(",
                           "static void refill_capability_after_write(")
        callback = extract(source, "__attribute__((noinline, used))\nvoid perf_write_buf(",
                           "static void perf_flush(")
        cls.temporary = tempfile.TemporaryDirectory(prefix="extfuse-sync-write-")
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        path = root / "completion.c"
        path.write_text(HARNESS.replace("@CONTRACT@", contract).replace("@CALLBACK@", callback))
        cls.binary = root / "completion"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-O2",
                        "-Wall", "-Wextra", "-Werror", str(path), "-o", str(cls.binary)],
                       check=True, timeout=20)

    def case(self, name, expected, marker=None):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), expected)
        if marker:
            self.assertIn("operation=" + marker, result.stderr)
        else:
            self.assertEqual(result.stderr, "")

    def test_full_write_preserves_reply_and_metadata(self):
        self.case("full", "BWESPR 0 8192 0 0")
        self.case("metadata-full", "BWESPR 0 8192 0 1")
        self.case("overlap-full", "BWER 0 8192 0 0")

    def test_writeback_short_zero_oversize_reject_after_publication(self):
        for name in ("short", "zero", "oversize", "metadata-short"):
            with self.subTest(name=name):
                self.case(name, "BWESPRX 5 0 1 0",
                          "write-oversize" if name == "oversize" else "write-short")

    def test_short_overlap_and_revocation_complete_coherence_before_error(self):
        self.case("overlap-short", "BWERX 5 0 1 0", "write-short")
        self.case("revoke-short", "BWECSPRX 5 0 1 0", "write-short")

    def test_non_writeback_short_and_zero_keep_existing_semantics(self):
        self.case("ordinary-short", "BWESPR 0 4096 0 0")
        self.case("ordinary-zero", "BWESPR 0 0 0 0")
        self.case("legacy-short", "BWESPR 0 4096 0 0")

    def test_lower_errors_and_existing_publication_reply_errors(self):
        self.case("io-error", "BWERX 28 0 1 0", "write-io")
        self.case("ordinary-io-error", "BWER 28 0 0 0")
        self.case("stat-error", "BWESRX 0 8192 1 0", "write-attr-publication")
        self.case("reply-error", "BWESPRX 0 8192 1 0", "write-reply")

    def test_writepage_is_decoded_from_wire_cache_flag(self):
        lowlevel = (ROOT.parents[1] / "lib/fuse_lowlevel.c").read_text()
        self.assertGreaterEqual(len(re.findall(
            r"fi\.writepage\s*=\s*\(?arg->write_flags & FUSE_WRITE_CACHE", lowlevel)), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
