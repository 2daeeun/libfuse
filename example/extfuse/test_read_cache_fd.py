#!/usr/bin/env python3
"""Exercise production pinned-inode snapshots on ordinary Linux O_PATH fds."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SOURCE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned int snapshot_calls;
static int snapshot_fstat(int fd, struct stat *st)
{
        snapshot_calls++;
        return fstat(fd, st);
}

#define fstat snapshot_fstat
#include "read_cache_fd.h"
#undef fstat

int main(int argc, char **argv)
{
        struct stat expected, actual, replacement;
        int fd, other;

        assert(argc == 3);
        assert(chdir(argv[2]) == 0);
        other = open("file", O_CREAT | O_EXCL | O_RDWR, 0600);
        assert(other >= 0);
        assert(write(other, "payload", 7) == 7);
        assert(close(other) == 0);
        assert(symlink("file", "link") == 0);
        fd = open(!strcmp(argv[1], "symlink") ? "link" : "file",
                  O_PATH | O_NOFOLLOW);
        assert(fd >= 0);
        /* Compare the old API's pinned-object identity, including symlinks. */
        assert(fstatat(fd, "", &expected, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) == 0);
        if (!strcmp(argv[1], "symlink"))
                assert(S_ISLNK(expected.st_mode));
        else
                assert(S_ISREG(expected.st_mode));

        if (!strcmp(argv[1], "unlinked")) {
                assert(unlink("file") == 0);
                other = open("file", O_CREAT | O_EXCL | O_RDWR, 0600);
                assert(other >= 0);
                assert(write(other, "replacement", 11) == 11);
                assert(close(other) == 0);
                assert(stat("file", &replacement) == 0);
                assert(replacement.st_ino != expected.st_ino);
        } else if (!strcmp(argv[1], "reused")) {
                other = open("replacement", O_CREAT | O_EXCL | O_RDWR, 0600);
                assert(other >= 0 && other != fd);
                assert(dup2(other, fd) == fd);
                assert(close(other) == 0);
                errno = 0;
                assert(extfuse_snapshot_pinned_inode(fd, expected.st_dev,
                                                    expected.st_ino, &actual) == -1);
                assert(errno == ESTALE);
                goto done;
        } else if (!strcmp(argv[1], "wrong-device")) {
                errno = 0;
                assert(extfuse_snapshot_pinned_inode(fd, expected.st_dev + 1,
                                                    expected.st_ino, &actual) == -1);
                assert(errno == ESTALE);
                goto done;
        } else if (!strcmp(argv[1], "closed")) {
                assert(close(fd) == 0);
                errno = 0;
                assert(extfuse_snapshot_pinned_inode(fd, expected.st_dev,
                                                    expected.st_ino, &actual) == -1);
                assert(errno == EBADF);
                fd = -1;
                goto done;
        }
        assert(extfuse_snapshot_pinned_inode(fd, expected.st_dev,
                                            expected.st_ino, &actual) == 0);
        assert(actual.st_dev == expected.st_dev);
        assert(actual.st_ino == expected.st_ino);
        assert(actual.st_mode == expected.st_mode);
        assert(actual.st_size == expected.st_size);
        if (!strcmp(argv[1], "unlinked"))
                assert(actual.st_nlink == 0);
done:
        assert(snapshot_calls == 1);
        if (fd >= 0)
                assert(close(fd) == 0);
        return 0;
}
'''


class PinnedInodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("C compiler unavailable")
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-pinned-stat-")
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        source = root / "snapshot.c"
        source.write_text(SOURCE)
        cls.binary = root / "snapshot"
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(ROOT), str(source), "-o", str(cls.binary)], check=True)

    def run_case(self, name):
        with tempfile.TemporaryDirectory(prefix="extfuse-pinned-case-") as directory:
            subprocess.run([str(self.binary), name, directory], check=True, timeout=10)

    def test_regular_opath(self):
        self.run_case("regular")

    def test_symlink_opath_is_not_followed(self):
        self.run_case("symlink")

    def test_unlinked_inode_is_not_replaced_by_new_path(self):
        self.run_case("unlinked")

    def test_reused_descriptor_rejects_wrong_inode(self):
        self.run_case("reused")

    def test_wrong_device_is_rejected(self):
        self.run_case("wrong-device")

    def test_closed_descriptor_preserves_errno(self):
        self.run_case("closed")


if __name__ == "__main__":
    unittest.main()
