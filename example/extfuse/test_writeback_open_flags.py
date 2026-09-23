#!/usr/bin/env python3
"""Exercise production OPEN/CREATE/TMPFILE callbacks on real lower files.

Only FUSE replies and metadata-cache plumbing are mocked. The extracted
callbacks, lower open calls, and read/write syscalls run unchanged, without a
mount. This covers writeback reads on a write-only application handle and the
offset semantics of lower writes when the application requested O_APPEND.
"""

from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LOWER_SOURCE = (ROOT / "example/passthrough_ll.c").read_text()
PERF_SOURCE = (ROOT / "example/extfuse/extfuse_passthrough.c").read_text()


def function(source, name, optional=False):
    match = re.search(r"^(?:static )?(?:int|void) " + name + r"\([^;]*?\)\s*\{",
                      source, re.M)
    if match is None:
        if optional:
            return ""
        raise AssertionError(f"production callback missing: {name}")
    opening = source.index("{", match.start())
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef void *fuse_req_t;
typedef uint64_t fuse_ino_t;
enum { CACHE_AUTO, CACHE_NEVER, CACHE_ALWAYS, FUSE_LOG_DEBUG };
#define PERF_CAPABILITY_XATTR "security.capability"
struct fuse_file_info {
        int flags;
        uint64_t fh;
        unsigned int direct_io, keep_cache, parallel_direct_writes;
};
struct fuse_entry_param {
        fuse_ino_t ino;
        struct stat attr;
        double attr_timeout;
};
struct lo_data { bool writeback, direct_io; int cache; pthread_mutex_t mutex; };
struct perf_backing { int unused; };
struct perf_tombstone { int unused; };
struct perf_cache_mutation { int unused; };
struct perf_cache_snapshot { int unused; };
static struct lo_data lower = { .mutex = PTHREAD_MUTEX_INITIALIZER };
static struct {
        pthread_rwlock_t namespace_lock;
        struct { unsigned int create; } counters;
} perf_state = { .namespace_lock = PTHREAD_RWLOCK_INITIALIZER };
static int parent_fd, inode_fd, replies, reply_error;
static bool metadata_enabled = true;

static struct lo_data *lo_data(fuse_req_t req)
{ (void)req; return &lower; }
static int lo_fd(fuse_req_t req, fuse_ino_t ino)
{ (void)req; return ino == 1 ? parent_fd : inode_fd; }
static bool lo_debug(fuse_req_t req) { (void)req; return false; }
static void fuse_log(int level, const char *fmt, ...)
{ (void)level; (void)fmt; }
static int fuse_reply_err(fuse_req_t req, int error)
{ (void)req; replies++; reply_error = error; return 0; }
static int fuse_reply_create(fuse_req_t req, struct fuse_entry_param *entry,
                             struct fuse_file_info *fi)
{ (void)req; assert(entry->ino == 2 && fi->fh != UINT64_MAX); replies++; return 0; }
static int fill_entry_param_new_inode(fuse_req_t req, fuse_ino_t parent,
                                      int fd, struct fuse_entry_param *entry)
{ (void)req; assert(parent == 1 && fcntl(fd, F_GETFL) >= 0); entry->ino = 2; return 0; }
static int lo_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name,
                        struct fuse_entry_param *entry)
{ (void)req; assert(parent == 1); entry->ino = 2;
  return fstatat(parent_fd, name, &entry->attr, 0) ? errno : 0; }
static void callback_increment(unsigned int *count) { (*count)++; }
static bool metadata_hits_enabled(void) { return metadata_enabled; }
static bool allopt_enabled(void) { return false; }
static bool paper_wbcache_passthrough_enabled(void) { return false; }
static bool coherence_epochs_enabled(void) { return false; }
static void cache_mutation_add(struct perf_cache_mutation *mutation, fuse_ino_t ino)
{ (void)mutation; (void)ino; }
static bool cache_mutation_begin(struct perf_cache_mutation *mutation)
{ (void)mutation; return true; }
static void cache_mutation_end(struct perf_cache_mutation *mutation) { (void)mutation; }
static void invalidate_attr(fuse_ino_t ino) { (void)ino; }
static void invalidate_entry(fuse_ino_t ino, const char *name)
{ (void)ino; (void)name; }
static void invalidate_xattr(fuse_ino_t ino, const char *name, bool all)
{ (void)ino; (void)name; (void)all; }
static double cache_inode_attr_snapshot(fuse_req_t req, fuse_ino_t ino, struct stat *st)
{ (void)req; (void)ino; (void)st; return 1.0; }
static double cache_inode_attr_before_reply(fuse_req_t req, fuse_ino_t ino, struct stat *st)
{ (void)req; (void)ino; (void)st; return 1.0; }
static void enable_uring_fixed_io_for_open(struct fuse_file_info *fi) { (void)fi; }
static void attach_backing(fuse_req_t req, fuse_ino_t ino, int fd,
                           struct fuse_file_info *fi, struct perf_backing *candidate,
                           struct perf_tombstone *tombstone)
{ (void)req; (void)ino; (void)fd; (void)fi; (void)candidate; (void)tombstone;
  assert(!"AllOpt is outside this lower-open test"); }
static int pin_child(int fd, const char *name, struct stat *identity)
{ (void)fd; (void)name; (void)identity; errno = ENOENT; return -1; }
static fuse_ino_t find_identity_nodeid_locked(struct lo_data *lo, int fd,
                                               const struct stat *identity)
{ (void)lo; (void)fd; (void)identity; return 0; }
static bool snapshot_inode_attr(fuse_req_t req, fuse_ino_t ino, struct stat *st,
                                struct perf_cache_snapshot *snapshot)
{ (void)req; (void)ino; (void)st; (void)snapshot; return false; }
static void prefetch_capability(fuse_req_t req, fuse_ino_t ino) { (void)req; (void)ino; }
static void cache_entry(fuse_ino_t parent, const char *name,
                        struct fuse_entry_param *entry,
                        struct perf_cache_snapshot *snapshot)
{ (void)parent; (void)name; (void)entry; (void)snapshot; }
static double epoch_attr_timeout(fuse_ino_t ino, double timeout)
{ (void)ino; return timeout; }

@CALLBACKS@

int main(int argc, char **argv)
{
        struct fuse_file_info fi = { .fh = UINT64_MAX };
        struct stat st;
        char actual[8] = {0}, read_path[64];
        int access, actual_flags, fd, reader, original_flags, expected_access;
        bool append, tmpfile, opening, writeback;

        assert(argc == 7);
        assert(chdir(argv[6]) == 0);
        writeback = atoi(argv[2]);
        access = atoi(argv[3]);
        append = atoi(argv[4]);
        metadata_enabled = atoi(argv[5]);
        lower.writeback = writeback;
        parent_fd = open(".", O_RDONLY | O_DIRECTORY);
        assert(parent_fd >= 0);
        tmpfile = strstr(argv[1], "tmpfile") != NULL;
        opening = !strcmp(argv[1], "lo_do_open");
        original_flags = access | O_CLOEXEC | O_NOFOLLOW;
        if (append)
                original_flags |= O_APPEND;
        if (opening) {
                fd = open("file", O_CREAT | O_EXCL | O_RDWR, 0600);
                assert(fd >= 0 && close(fd) == 0);
                inode_fd = open("file", O_PATH);
                assert(inode_fd >= 0);
        } else if (tmpfile) {
                original_flags |= O_TMPFILE;
        } else {
                original_flags |= O_CREAT | O_EXCL;
        }
        fi.flags = original_flags;
        if (!strcmp(argv[1], "lo_create"))
                lo_create(NULL, 1, "file", 0600, &fi);
        else if (!strcmp(argv[1], "lo_tmpfile"))
                lo_tmpfile(NULL, 1, 0600, &fi);
        else if (!strcmp(argv[1], "perf_create"))
                perf_create(NULL, 1, "file", 0600, &fi);
        else if (!strcmp(argv[1], "perf_tmpfile"))
                perf_tmpfile(NULL, 1, 0600, &fi);
        else {
                assert(opening);
                reply_error = lo_do_open(NULL, 2, &fi);
        }
        if (tmpfile && (reply_error == EOPNOTSUPP || reply_error == ENOSYS))
                return 77;
        assert(reply_error == 0 && replies == !opening);
        fd = (int)fi.fh;
        assert(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
        actual_flags = fcntl(fd, F_GETFL);
        assert(actual_flags >= 0);
        expected_access = writeback && access == O_WRONLY ? O_RDWR : access;
        assert((actual_flags & O_ACCMODE) == expected_access);
        assert(!!(actual_flags & O_APPEND) == (append && !writeback));
        assert((fi.flags & O_ACCMODE) == expected_access);
        assert(!!(fi.flags & O_APPEND) == (append && !writeback));
        assert((fi.flags & ~(O_ACCMODE | O_APPEND)) ==
               (original_flags & ~(O_ACCMODE | O_APPEND)));
        if (access == O_RDONLY) {
                errno = 0;
                assert(pwrite(fd, "abcd", 4, 0) == -1 && errno == EBADF);
                assert(pread(fd, actual, 4, 0) == 0);
        } else {
                assert(pwrite(fd, "abcd", 4, 0) == 4);
                assert(fsync(fd) == 0);
                /* A writeback partial-page write must be able to read first. */
                errno = 0;
                if (expected_access == O_RDWR)
                        assert(pread(fd, actual, 4, 0) == 4 && !memcmp(actual, "abcd", 4));
                else
                        assert(pread(fd, actual, 4, 0) == -1 && errno == EBADF);
                /* The kernel supplies the offset; lower O_APPEND would ignore it. */
                assert(pwrite(fd, "Z", 1, 0) == 1);
                assert(fstat(fd, &st) == 0);
                assert(st.st_size == (append && !writeback ? 5 : 4));
                snprintf(read_path, sizeof(read_path), "/proc/self/fd/%d", fd);
                reader = open(read_path, O_RDONLY);
                assert(reader >= 0);
                assert(pread(reader, actual, sizeof(actual), 0) == st.st_size);
                assert(!memcmp(actual, append && !writeback ? "abcdZ" : "Zbcd", st.st_size));
                assert(close(reader) == 0);
        }
        assert(close(fd) == 0 && close(parent_fd) == 0);
        if (opening)
                assert(close(inode_fd) == 0);
        return 0;
}
'''


class WritebackOpenFlagsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-open-flags-")
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        source = directory / "callbacks.c"
        callbacks = [function(LOWER_SOURCE, "lo_update_open_flags", optional=True)]
        callbacks += [function(LOWER_SOURCE, name) for name in
                      ("lo_tmpfile", "lo_create", "lo_do_open")]
        callbacks += [function(PERF_SOURCE, name) for name in
                      ("perf_tmpfile", "perf_create")]
        source.write_text(HARNESS.replace("@CALLBACKS@", "\n".join(callbacks)))
        cls.binary = directory / "callbacks"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                       ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
                        str(source), "-o", str(cls.binary)], check=True)

    def run_callback(self, name):
        for writeback in (False, True):
            for access in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
                if "tmpfile" in name and access == os.O_RDONLY:
                    continue  # Linux O_TMPFILE requires a writable access mode.
                for append in (False, True):
                    for metadata in ((False, True) if name.startswith("perf_") else (True,)):
                        with self.subTest(callback=name, writeback=writeback,
                                          access=access, append=append, metadata=metadata):
                            with tempfile.TemporaryDirectory(prefix="extfuse-open-case-") as directory:
                                result = subprocess.run(
                                    [str(self.binary), name, str(int(writeback)), str(access),
                                     str(int(append)), str(int(metadata)), directory],
                                    capture_output=True, text=True, timeout=10)
                                if result.returncode == 77:
                                    self.skipTest("temporary filesystem lacks O_TMPFILE")
                                self.assertEqual(result.returncode, 0, result.stderr)

    def test_lo_create(self):
        self.run_callback("lo_create")

    def test_lo_tmpfile(self):
        self.run_callback("lo_tmpfile")

    def test_lo_do_open(self):
        self.run_callback("lo_do_open")

    def test_perf_create(self):
        self.run_callback("perf_create")

    def test_perf_tmpfile(self):
        self.run_callback("perf_tmpfile")


if __name__ == "__main__":
    unittest.main()
