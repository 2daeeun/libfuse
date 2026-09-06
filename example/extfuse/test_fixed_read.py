#!/usr/bin/env python3
"""Exercise the production fixed-READ ownership path without a mount or BPF load."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get("EXTFUSE_FIXED_READ_SOURCE", ROOT / "extfuse_passthrough.c"))
HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef uint64_t fuse_ino_t;
struct request { bool fixed; };
typedef struct request *fuse_req_t;
struct lo_data { double timeout; };
struct lo_inode { int fd; dev_t dev; ino_t ino; };
struct perf_cache_mutation { bool attr_only, active, armed; size_t count; uint64_t read_generation; };
struct perf_inode_generation { _Atomic uint64_t read_cohort_refs; };
struct perf_cache_snapshot { int token; };
struct fuse_file_info {
    int flags;
    uint64_t fh;
    unsigned int io_uring_zero_copy, io_uring_zero_copy_write;
};
#define PERF_MODE_HIT 1
static struct {
    int mode;
    bool passthrough_coherence_v2_requested, wbcache_passthrough_requested;
    bool fixed_read, c2_fixed_write, uring_bufpool_requested, single_issuer;
    void *session;
} perf_state;
static struct lo_data lower_data = { .timeout = 1.0 };
static struct lo_inode lower_inode = { .fd = 77, .dev = 3, .ino = 19 };
static int allocation_failure, begin_failure, submit_result, snapshot_unstable;
static int snapshot_failure, cache_failure, reply_failure;
static unsigned int allocated, freed, active, ended, submissions, replies, exits;
static int reply_error;
static size_t reply_size;
static char events[64];
static size_t event_count;
static void (*pending_callback)(fuse_req_t, ssize_t, void *);
static void *pending_context;

static void event(char value)
{
    assert(event_count + 1 < sizeof(events));
    events[event_count++] = value;
}

static void *test_calloc(size_t n, size_t size)
{
    if (allocation_failure)
        return NULL;
    allocated++;
    return calloc(n, size);
}

static void test_free(void *value)
{
    assert(value);
    freed++;
    event('F');
    free(value);
}

static struct lo_data *lo_data(fuse_req_t req) { (void)req; return &lower_data; }
static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino)
{
    (void)req;
    assert(ino == 17);
    return &lower_inode;
}
static bool fuse_req_is_uring_zero_copy(fuse_req_t req) { return req->fixed; }
static void cache_mutation_add(struct perf_cache_mutation *mutation, fuse_ino_t ino)
{
    assert(mutation->attr_only && ino == 17);
    event('A');
}
static bool cache_mutation_begin(struct perf_cache_mutation *mutation)
{
    event('B');
    mutation->active = true;
    active++;
    return !begin_failure;
}
/* Cohort synchronization is exercised by test_read_cohort.py's actual code. */
static bool cache_read_begin(struct perf_cache_mutation *mutation,
                              struct perf_inode_generation **cohort)
{
    *cohort = NULL;
    return cache_mutation_begin(mutation);
}
static bool cache_read_cohort_last(struct perf_cache_mutation *mutation,
                                   struct perf_inode_generation *cohort)
{
    (void)mutation;
    (void)cohort;
    assert(!"unexpected cohort in the transport-ownership fixture");
    return false;
}
static bool cache_mutation_end(struct perf_cache_mutation *mutation)
{
    assert(mutation->active && active == 1);
    mutation->active = false;
    active--;
    ended++;
    event('E');
    return true;
}
static bool cache_mutation_end_with_snapshot(struct perf_cache_mutation *mutation,
                                             struct perf_cache_snapshot *snapshot)
{
    cache_mutation_end(mutation);
    snapshot->token = 42;
    return !snapshot_unstable;
}
static int extfuse_snapshot_pinned_inode(int fd, dev_t dev, ino_t ino, struct stat *st)
{
    (void)st;
    assert(fd == 77 && dev == 3 && ino == 19 && !active);
    event('S');
    return snapshot_failure ? -EIO : 0;
}
static int cache_attr(fuse_ino_t ino, struct stat *st, double timeout,
                      struct perf_cache_snapshot *snapshot, bool existing,
                      double *reply_timeout)
{
    (void)st;
    assert(ino == 17 && timeout == 1.0 && snapshot->token == 42 && !existing);
    *reply_timeout = timeout;
    event('P');
    errno = EBUSY;
    return cache_failure ? -EIO : 0;
}
static int fuse_reply_err(fuse_req_t req, int error)
{
    (void)req;
    assert(!active && !replies);
    replies++;
    reply_error = error;
    event('R');
    return reply_failure;
}
static int fuse_reply_uring_zero_copy(fuse_req_t req, size_t size)
{
    assert(req->fixed && !active && !replies && size <= 8192);
    replies++;
    reply_size = size;
    event('R');
    return reply_failure;
}
static int fuse_uring_submit_fixed_io(fuse_req_t req, int fd, off_t offset,
                                      size_t size, bool write,
                                      void (*callback)(fuse_req_t, ssize_t, void *),
                                      void *userdata)
{
    assert(req->fixed && fd == 88 && offset == 4096 && size == 8192 && !write);
    assert(active == 1 && callback && userdata);
    submissions++;
    event('Q');
    if (!submit_result) {
        pending_callback = callback;
        pending_context = userdata;
    }
    return submit_result;
}
static void fuse_session_exit(void *session)
{
    assert(session == &perf_state);
    exits++;
}

#define calloc test_calloc
#define free test_free
@OPEN_HELPERS@
@READ_HELPERS@

int main(int argc, char **argv)
{
    struct request request = { .fixed = true };
    struct fuse_file_info fi = { .flags = O_RDONLY, .fh = 88 };
    ssize_t completed = 8192;

    assert(argc == 2 || argc == 7);
    perf_state.session = &perf_state;
    if (!strcmp(argv[1], "open")) {
        assert(argc == 7);
        perf_state.fixed_read = atoi(argv[2]);
        perf_state.c2_fixed_write = atoi(argv[3]);
        perf_state.uring_bufpool_requested = atoi(argv[4]);
        perf_state.single_issuer = atoi(argv[5]);
        fi.flags = atoi(argv[6]);
        enable_uring_fixed_io_for_open(&fi);
        printf("%u %u\n", fi.io_uring_zero_copy, fi.io_uring_zero_copy_write);
        return 0;
    }
    if (!strcmp(argv[1], "short")) completed = 2048;
    else if (!strcmp(argv[1], "eof")) completed = 0;
    else if (!strcmp(argv[1], "io-error")) completed = -EIO;
    else if (!strcmp(argv[1], "oversize")) completed = 8193;
    else if (!strcmp(argv[1], "submit-error")) submit_result = -EAGAIN;
    else if (!strcmp(argv[1], "begin-error")) begin_failure = 1;
    else if (!strcmp(argv[1], "alloc-error")) allocation_failure = 1;
    else if (!strcmp(argv[1], "copied-request")) request.fixed = false;
    else if (!strcmp(argv[1], "unstable")) snapshot_unstable = 1;
    else if (!strcmp(argv[1], "snapshot-error")) snapshot_failure = 1;
    else if (!strcmp(argv[1], "cache-error")) cache_failure = 1;
    else if (!strcmp(argv[1], "reply-error")) reply_failure = -EPIPE;
    errno = ERANGE;
    perf_read_fixed(&request, 17, 8192, 4096, &fi);
    if (pending_callback) {
        /* The submission frame has returned; context must still be owned. */
        assert(allocated == 1 && !freed && active == 1 && !replies);
        pending_callback(&request, completed, pending_context);
        assert(errno == ERANGE);
    }
    assert(!active && allocated == freed && replies == 1);
    printf("%s %u %u %u %d %zu %u\n", events, ended, submissions,
           freed, reply_error, reply_size, exits);
    return 0;
}
"""


class FixedReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("static bool c2_fixed_write_enabled(")
        end = source.index("static bool paper_capability_is_safe(", start)
        helpers = source[start:end]
        start = source.index("struct perf_read_context {")
        end = source.index("__attribute__((noinline, used))\nvoid perf_read(", start)
        read_helpers = source[start:end]
        prefetch_start = read_helpers.index("static bool cache_read_end_prefetched(")
        prefetch_end = read_helpers.index("static void perf_read_prepare(", prefetch_start)
        # The actual publication helper is covered by test_read_cohort.py.
        # This fixture retains the transport callback and original fallback.
        read_helpers = (read_helpers[:prefetch_start] +
                        "static bool cache_read_end_prefetched(struct perf_read_context *context, "
                        "const struct stat *st) { (void)context; (void)st; return false; }\n" +
                        read_helpers[prefetch_end:])
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-fixed-read-")
        cls.addClassCleanup(cls.directory.cleanup)
        path = Path(cls.directory.name)
        harness = path / "read.c"
        harness.write_text(HARNESS.replace("@OPEN_HELPERS@", helpers).replace(
            "@READ_HELPERS@", read_helpers))
        cls.binary = path / "read"
        subprocess.run([
            *shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-O2",
            "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(cls.binary),
        ], check=True)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, check=True)
        return result.stdout.strip(), result.stderr

    def test_success_short_and_eof_publish_before_reply(self):
        for name, count in (("success", 8192), ("short", 2048), ("eof", 0)):
            with self.subTest(name=name):
                self.assertEqual(self.run_case(name),
                                 (f"ABQESPRF 1 1 1 0 {count} 0", ""))

    def test_io_error_closes_mutation_before_error_reply(self):
        self.assertEqual(self.run_case("io-error"), ("ABQESPRF 1 1 1 5 0 0", ""))

    def test_submit_error_releases_heap_and_mutation(self):
        self.assertEqual(self.run_case("submit-error"), ("ABQESPRF 1 1 1 11 0 0", ""))

    def test_begin_error_unwinds_without_submitting(self):
        self.assertEqual(self.run_case("begin-error"), ("ABEFR 1 0 1 5 0 0", ""))

    def test_allocation_failure_owns_no_mutation(self):
        self.assertEqual(self.run_case("alloc-error"), ("R 0 0 0 12 0 0", ""))

    def test_oversize_reply_fails_closed(self):
        output, error = self.run_case("oversize")
        self.assertEqual(output, "ABQESPRF 1 1 1 5 0 1")
        self.assertIn("operation=read-oversize", error)

    def test_copied_request_cannot_satisfy_fixed_contract(self):
        output, error = self.run_case("copied-request")
        self.assertEqual(output, "R 0 0 0 95 0 1")
        self.assertIn("operation=read-request", error)

    def test_metadata_snapshot_failure_preserves_payload(self):
        for name, events in (("unstable", "ABQERF"),
                             ("snapshot-error", "ABQESRF"),
                             ("cache-error", "ABQESPRF")):
            with self.subTest(name=name):
                self.assertEqual(self.run_case(name),
                                 (f"{events} 1 1 1 0 8192 0", ""))

    def test_reply_failure_frees_context_and_stops_session(self):
        output, error = self.run_case("reply-error")
        self.assertEqual(output, "ABQESPRF 1 1 1 0 8192 1")
        self.assertIn("operation=read-reply", error)

    def test_open_flags_keep_read_only_and_write_modes_separate(self):
        for read in (0, 1):
            for write in (0, 1):
                for pool in (0, 1):
                    for issuer in (0, 1):
                        for mode in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
                            with self.subTest(read=read, write=write, pool=pool,
                                              issuer=issuer, mode=mode):
                                output = subprocess.check_output([
                                    str(self.binary), "open", str(read), str(write),
                                    str(pool), str(issuer), str(mode),
                                ], text=True)
                                generic = int(bool(read and pool and issuer and mode == os.O_RDONLY))
                                write_only = int(bool(write and pool and not generic))
                                self.assertEqual(output.strip(), f"{generic} {write_only}")


if __name__ == "__main__":
    unittest.main()
