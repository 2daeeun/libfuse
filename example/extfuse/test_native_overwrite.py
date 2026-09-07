#!/usr/bin/env python3
"""Exercise the production backing-file lock routing without building Linux."""
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
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define FMODE_BACKING 1
#define FMODE_CAN_ODIRECT 2
#define IOCB_DIRECT 1
#define IOCB_APPEND 2
#define IOCB_NOWAIT 4
#define IOCB_ATOMIC 8
#define WARN_ON_ONCE(x) (x)
#define EXPORT_SYMBOL_GPL(x)
#define pr_debug(...) ((void)0)
typedef uint64_t u64;
struct inode { loff_t size; mode_t i_mode; pthread_rwlock_t sem; };
struct file { struct inode *inode; int f_mode, f_flags; void *private_data; };
struct iov_iter { size_t count; };
struct kiocb { struct file *ki_filp; loff_t ki_pos; int ki_flags; bool sync; };
struct backing_file_ctx {
 const void *cred;
 int (*begin_io)(struct kiocb *, bool);
 int (*end_io)(struct kiocb *, ssize_t, bool);
 void (*accessed)(struct file *);
 void (*end_write)(struct kiocb *, ssize_t);
};
struct fuse_file { struct file *backing; const void *cred; };
static struct inode upper_inode;
static struct file upper, lower;
static struct fuse_file ff;
static int security_result, remove_error, begin_error, lower_error;
static bool shrink_on_lock, parallel_lower, hold_lower, short_write;
static atomic_int read_locks, write_locks, checks, removals, begins, ends;
static atomic_int lower_calls, attr_calls, entered, release_lower;
static atomic_int active_lower, max_lower;
static pthread_barrier_t lower_barrier;
static _Thread_local int shared, exclusive, credentials;

static struct inode *file_inode(struct file *f) { return f->inode; }
static struct file *file_dentry(struct file *f) { return f; }
static void *file_mnt_idmap(struct file *f) { (void)f; return NULL; }
static loff_t i_size_read(struct inode *i) { return i->size; }
static size_t iov_iter_count(struct iov_iter *i) { return i->count; }
static bool is_sync_kiocb(struct kiocb *i) { return i->sync; }
static void inode_lock_shared(struct inode *i) {
 assert(!shared && !exclusive);
 assert(!pthread_rwlock_rdlock(&i->sem));
 shared = 1; atomic_fetch_add(&read_locks, 1);
 if (shrink_on_lock) { i->size = 1; shrink_on_lock = false; }
}
static void inode_unlock_shared(struct inode *i) {
 assert(shared && !exclusive); shared = 0;
 assert(!pthread_rwlock_unlock(&i->sem));
}
static void inode_lock(struct inode *i) {
 assert(!shared && !exclusive);
 assert(!pthread_rwlock_wrlock(&i->sem));
 exclusive = 1; atomic_fetch_add(&write_locks, 1);
}
static void inode_unlock(struct inode *i) {
 assert(exclusive && !shared); exclusive = 0;
 assert(!pthread_rwlock_unlock(&i->sem));
}
static int dentry_needs_remove_privs(void *idmap, struct file *f) {
 (void)idmap; assert(f == &upper); assert(shared && !exclusive);
 assert(!credentials); atomic_fetch_add(&checks, 1);
 return security_result;
}
static int file_remove_privs(struct file *f) {
 assert(f == &upper && exclusive && !shared && !credentials);
 atomic_fetch_add(&removals, 1); return remove_error;
}
static int fuse_passthrough_begin_io(struct kiocb *iocb, bool write) {
 assert(iocb->ki_filp == &upper && write && !credentials);
 assert(shared || exclusive); atomic_fetch_add(&begins, 1);
 return begin_error;
}
static int fuse_passthrough_end_io(struct kiocb *iocb, ssize_t ret, bool write) {
 assert(iocb->ki_filp == &upper && write && credentials);
 assert(shared || exclusive); atomic_fetch_add(&ends, 1); return ret < 0 ? ret : 0;
}
static void fuse_passthrough_end_write(struct kiocb *iocb, ssize_t ret) {
 (void)ret; assert(iocb->ki_filp == &upper && credentials);
 assert(shared || exclusive); atomic_fetch_add(&attr_calls, 1);
}
static struct file *fuse_file_passthrough(struct fuse_file *f) { return f->backing; }
static int backing_file_begin_io(struct backing_file_ctx *c, struct kiocb *i, bool w) {
 return c->begin_io(i, w);
}
struct cred_scope { bool active; };
static struct cred_scope enter_creds(const void *c) {
 assert(c == &ff && !credentials); credentials = 1;
 return (struct cred_scope){true};
}
static void leave_creds(struct cred_scope *s) {
 (void)s; assert(credentials); credentials = 0;
}
#define scoped_with_creds(c) \
 for (struct cred_scope scope __attribute__((cleanup(leave_creds))) = enter_creds(c); \
      ; )
static int do_backing_file_write_iter(struct file *f, struct iov_iter *iter,
 struct kiocb *iocb, int flags, struct backing_file_ctx *ctx) {
 (void)flags; assert(f == &lower && credentials && (shared || exclusive));
 atomic_fetch_add(&lower_calls, 1);
 int active = atomic_fetch_add(&active_lower, 1) + 1;
 int maximum = atomic_load(&max_lower);
 while (active > maximum && !atomic_compare_exchange_weak(&max_lower, &maximum, active)) {}
 if (parallel_lower) pthread_barrier_wait(&lower_barrier);
 if (hold_lower) {
  atomic_store(&entered, 1);
  while (!atomic_load(&release_lower)) sched_yield();
 }
 ssize_t ret = lower_error ? lower_error : (ssize_t)iter->count;
 if (short_write) ret /= 2;
 if (ret > 0) iocb->ki_pos += ret;
 ctx->end_write(iocb, ret); ctx->end_io(iocb, ret, true);
 atomic_fetch_sub(&active_lower, 1);
 return ret;
}
/* PRODUCTION_BACKING */
/* PRODUCTION_FUSE */

static struct kiocb iocb = { .sync = true };
static struct iov_iter iter = { .count = 4096 };
static void reset(void) {
 upper_inode.size = 8192; upper_inode.i_mode = S_IFREG | 0600;
 assert(!pthread_rwlock_init(&upper_inode.sem, NULL));
 upper = (struct file){.inode = &upper_inode, .private_data = &ff};
 lower = (struct file){.f_mode = FMODE_BACKING | FMODE_CAN_ODIRECT};
 ff = (struct fuse_file){.backing = &lower, .cred = &ff};
 iocb = (struct kiocb){.sync = true, .ki_filp = &upper};
}
static void clean(void) {
 assert(!shared && !exclusive && !credentials);
 assert(!pthread_rwlock_trywrlock(&upper_inode.sem));
 assert(!pthread_rwlock_unlock(&upper_inode.sem));
 assert(!pthread_rwlock_destroy(&upper_inode.sem));
}
static void *writer(void *unused) {
 (void)unused;
 struct kiocb local = iocb;
 assert(fuse_passthrough_write_iter(&local, &iter) == 4096);
 assert(!shared && !exclusive && !credentials);
 return NULL;
}
int main(int argc, char **argv) {
 assert(argc == 2); const char *name = argv[1]; reset();
 bool fallback = false; ssize_t expected = 4096;
 if (!strcmp(name, "parallel")) {
  pthread_t threads[2]; parallel_lower = true;
  assert(!pthread_barrier_init(&lower_barrier, NULL, 2));
  for (int i = 0; i < 2; i++) assert(!pthread_create(&threads[i], NULL, writer, NULL));
  for (int i = 0; i < 2; i++) assert(!pthread_join(threads[i], NULL));
  assert(atomic_load(&max_lower) == 2 && atomic_load(&write_locks) == 0);
  assert(atomic_load(&begins) == 2 && atomic_load(&ends) == 2 && atomic_load(&attr_calls) == 2);
  assert(!pthread_barrier_destroy(&lower_barrier)); clean(); return 0;
 }
 if (!strcmp(name, "truncate-excluded")) {
  pthread_t thread; hold_lower = true;
  assert(!pthread_create(&thread, NULL, writer, NULL));
  while (!atomic_load(&entered)) sched_yield();
  assert(pthread_rwlock_trywrlock(&upper_inode.sem) == EBUSY);
  atomic_store(&release_lower, 1);
  assert(!pthread_join(thread, NULL));
  assert(atomic_load(&ends) == 1 && atomic_load(&attr_calls) == 1);
  clean(); return 0;
 }
 if (!strcmp(name, "extending")) { iocb.ki_pos = 8192; fallback = true; }
 if (!strcmp(name, "overflow")) { upper_inode.size = LLONG_MAX; iocb.ki_pos = LLONG_MAX - 1; fallback = true; lower_error = -EFBIG; expected = -EFBIG; }
 if (!strcmp(name, "negative")) { iocb.ki_pos = -1; fallback = true; lower_error = -EINVAL; expected = -EINVAL; }
 if (!strcmp(name, "append")) { iocb.ki_flags = IOCB_APPEND; fallback = true; }
 if (!strcmp(name, "file-append")) { upper.f_flags = O_APPEND; fallback = true; }
 if (!strcmp(name, "direct")) { iocb.ki_flags = IOCB_DIRECT; fallback = true; }
 if (!strcmp(name, "nowait")) { iocb.ki_flags = IOCB_NOWAIT; fallback = true; }
 if (!strcmp(name, "atomic")) { iocb.ki_flags = IOCB_ATOMIC; fallback = true; }
 if (!strcmp(name, "async")) { iocb.sync = false; fallback = true; }
 if (!strcmp(name, "nonregular")) { upper_inode.i_mode = S_IFDIR | 0700; fallback = true; }
 if (!strcmp(name, "shrink")) { shrink_on_lock = true; fallback = true; }
 if (!strcmp(name, "killpriv")) { security_result = 1; fallback = true; }
 if (!strcmp(name, "killpriv-error")) { security_result = 1; remove_error = -EPERM; fallback = true; expected = -EPERM; }
 if (!strcmp(name, "security-error")) { security_result = -EACCES; expected = -EACCES; }
 if (!strcmp(name, "begin-error")) { begin_error = -EIO; expected = -EIO; }
 if (!strcmp(name, "lower-error")) { lower_error = -ENOSPC; expected = -ENOSPC; }
 if (!strcmp(name, "short")) { short_write = true; expected = 2048; }
 if (!strcmp(name, "empty")) { iter.count = 0; expected = 0; }
 if (!strcmp(name, "bad-backing")) { lower.f_mode = 0; expected = -EIO; }
 ssize_t ret = fuse_passthrough_write_iter(&iocb, &iter);
 assert(ret == expected);
 assert(atomic_load(&write_locks) == (int)fallback);
 assert(atomic_load(&removals) == (int)fallback);
 bool no_io = security_result < 0 || remove_error || !iter.count || !lower.f_mode;
 assert(atomic_load(&begins) == !no_io);
 assert(atomic_load(&lower_calls) == (!no_io && !begin_error));
 assert(atomic_load(&ends) == atomic_load(&lower_calls));
 assert(atomic_load(&attr_calls) == atomic_load(&lower_calls));
 clean(); return 0;
}
'''


def function(source, name):
    start = source.index("ssize_t " + name + "(")
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


class NativeOverwriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="extfuse-native-overwrite-")
        backing = (LINUX / "fs/backing-file.c").read_text()
        start = backing.index("static ssize_t backing_file_write_iter_prepared(")
        end = backing.index("ssize_t backing_file_splice_read(", start)
        fuse = (LINUX / "fs/fuse/passthrough.c").read_text()
        text = HARNESS.replace("/* PRODUCTION_BACKING */", backing[start:end])
        text = text.replace("/* PRODUCTION_FUSE */", function(fuse, "fuse_passthrough_write_iter"))
        source = Path(cls.tmp.name) / "native_overwrite.c"
        source.write_text(text)
        cls.binary = Path(cls.tmp.name) / "native_overwrite"
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-Wall",
                        "-Wextra", "-Werror", "-fsanitize=undefined", "-pthread",
                        str(source), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cases(self, *cases):
        for case in cases:
            with self.subTest(case=case):
                subprocess.run([str(self.binary), case], check=True, timeout=5)

    def test_overwrites_overlap_with_individual_callbacks(self):
        self.run_cases("normal", "parallel")

    def test_upper_truncate_excluded_until_completion(self):
        self.run_cases("truncate-excluded", "shrink")

    def test_ineligible_io_keeps_exclusive_path(self):
        self.run_cases("extending", "overflow", "negative", "append", "file-append",
                       "direct", "nowait", "atomic", "async", "nonregular")

    def test_privileges_rechecked_before_exclusive_io(self):
        self.run_cases("killpriv", "killpriv-error", "security-error")

    def test_errors_and_short_completions_remain_exact(self):
        self.run_cases("begin-error", "lower-error", "short", "empty", "bad-backing")


if __name__ == "__main__":
    unittest.main()
