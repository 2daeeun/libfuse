#!/usr/bin/env python3
"""Execute native mmap policy and backing lifetime code without building Linux."""
import os
from pathlib import Path
import shlex
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
LINUX = Path(os.environ.get("EXTFUSE_KERNEL_SOURCE", ROOT.parents[2] / "linux"))


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/extfuse_types.h>
#include "extfuse_coherence.h"
#include "attr.h"

#define RETURN 0
#define UPCALL (-ENOSYS)
#define HANDLER(op, number) int bpf_func_##op
#define PRINTK(...)
#define NODEID 0
#define IN_PARAM_0_VALUE 1
#define OUT_PARAM_0 0
#define BPF_NOEXIST 1
#define EXTFUSE_PASSTHROUGH_READ 65
#define EXTFUSE_PASSTHROUGH_MMAP 67
#define EXPORT_SYMBOL_GPL(x)
#define WARN_ON_ONCE(x) (x)
#define FMODE_BACKING 1
#define FMODE_NOACCOUNT 2
#define U32_MAX UINT32_MAX
#define pr_debug(...)
static int mmap_map, native_io_map, attr_map, daemon_io_map;
static bool present, native_present, map_error, stale_error, fail_cas;
static __u32 marker;
static struct extfuse_io_state native_state, daemon_state;
static lookup_attr_val_t attr;
struct request { __u64 nodeid; struct extfuse_passthrough_in in; };

static int bpf_extfuse_read_args(void *ctx, int field, void *out, size_t size) {
 struct request *r = ctx;
 if (field == NODEID) { assert(size == sizeof(r->nodeid)); memcpy(out, &r->nodeid, size); }
 else { assert(size == sizeof(r->in)); memcpy(out, &r->in, size); }
 return 0;
}
static int bpf_extfuse_write_args(void *ctx, int field, const void *in, size_t size) {
 (void)ctx; (void)field; (void)in; (void)size; return 0;
}
static bool count_request(__u32 opcode, __u32 phase, int ret) {
 return /* COUNT_CONDITION */;
}
static int gen_attr_key(void *ctx, int field, const char *name, lookup_attr_key_t *key) {
 (void)field; (void)name; key->nodeid = ((struct request *)ctx)->nodeid;
 return stale_error ? -EIO : 0;
}
static void *bpf_map_lookup_elem(void *map, const void *key) {
 (void)key;
 if (map == &mmap_map) return present ? &marker : NULL;
 if (map == &native_io_map) return native_present ? &native_state : NULL;
 if (map == &daemon_io_map) return &daemon_state;
 assert(map == &attr_map); return &attr;
}
static int bpf_map_update_elem(void *map, const void *key, const void *value, int flags) {
 (void)key; assert(flags == BPF_NOEXIST);
 if (map_error) return -ENOMEM;
 if (map == &mmap_map) {
  if (present) return -EEXIST;
  marker = *(const __u32 *)value; present = true;
 } else {
  assert(map == &native_io_map);
  if (native_present) return -EEXIST;
  native_state = *(const struct extfuse_io_state *)value; native_present = true;
 }
 return 0;
}
static int policy_enabled(__u32 bit) { (void)bit; return 0; }
/* Inject CAS starvation without modifying the production retry/poison logic. */
static __u32 test_cas(__u32 *p, __u32 old, __u32 next) {
 return fail_cas ? old + 1 : __sync_val_compare_and_swap(p, old, next);
}
#define __sync_val_compare_and_swap test_cas
/* BPF_CODE */
#undef __sync_val_compare_and_swap

static int notify(__u32 opcode, __u32 phase, __u32 count) {
 struct request r = {.nodeid = 1, .in = {.phase = phase, .mmap_count = count}};
 if (opcode == EXTFUSE_PASSTHROUGH_MMAP) return bpf_func_EXTFUSE_PASSTHROUGH_MMAP(&r);
 assert(opcode == EXTFUSE_PASSTHROUGH_READ);
 return passthrough_notification(&r, FATTR_ATIME, 0);
}
static int getattr_result(void) {
 struct request r = {.nodeid = 1}; return bpf_func_FUSE_GETATTR(&r);
}
static void refresh(void) {
 assert(!has_passthrough_mmap_marker(1));
 attr.stale = 0; attr.native_state = native_state.attr_state;
 attr.daemon_state = daemon_state.attr_state;
}

typedef uint64_t u64;
typedef struct { int64_t value; } atomic64_t;
static int64_t atomic64_read(atomic64_t *v) { return v->value; }
static void atomic64_inc(atomic64_t *v) { v->value++; }
static void atomic64_dec(atomic64_t *v) { v->value--; }
struct fuse_conn { int unused; };
struct inode { struct fuse_conn conn; };
struct dentry { struct inode *inode; };
struct path { struct dentry *dentry; };
struct file { int f_mode, refs; void *private_data, *f_cred; };
struct backing_file {
 struct file file;
 void (*release)(struct file *, void *);
 void *release_data;
 struct path user_path;
};
#define backing_file(f) ((struct backing_file *)(f))
static const struct path *backing_file_user_path(struct file *f) {
 return &backing_file(f)->user_path;
}
struct fuse_passthrough_mmap { atomic64_t mappings; };
struct fuse_file {
 struct file *passthrough; void *cred;
 struct fuse_passthrough_mmap *passthrough_mmap;
};
struct vm_area_struct { struct file *vm_file; unsigned long vm_start, vm_end; };
struct backing_file_ctx { void *cred; void (*accessed)(struct file *); };
struct fuse_backing { int unused; };
static struct inode upper_inode;
static struct dentry upper_dentry = {&upper_inode};
static bool lower_closed, upper_path_live = true;
static int release_events, retired_count, lower_mmap_calls, mmap_error;
static bool replace_file;
static struct file redirected;
static int nr_files, filp_cachep, bfilp_cachep;
static struct inode *d_inode(struct dentry *d) { assert(upper_path_live); return d->inode; }
static struct fuse_conn *get_fuse_conn(struct inode *i) { return &i->conn; }
static void fuse_invalidate_attr(struct inode *i) { (void)i; }
static struct inode *file_inode(struct file *f) { (void)f; return &upper_inode; }
static void kfree(void *p) { free(p); }
static int extfuse_passthrough_mmap_end(struct fuse_conn *fc, struct inode *inode, __u32 count) {
 (void)fc; (void)inode; assert(lower_closed && upper_path_live);
 release_events++; retired_count += count;
 return notify(EXTFUSE_PASSTHROUGH_MMAP, EXTFUSE_PASSTHROUGH_PHASE_END, count);
}
static void security_file_free(struct file *f) { (void)f; assert(lower_closed); }
static void percpu_counter_dec(int *p) { (void)p; }
static void put_cred(void *p) { (void)p; }
static void path_put(const struct path *p) { (void)p; upper_path_live = false; }
static void kmem_cache_free(int cache, void *p) { (void)cache; (void)p; }
#define likely(x) (x)
#define unlikely(x) (x)
/* LIFETIME_CODE */
static void fput(struct file *f) {
 assert(f->refs > 0);
 if (!--f->refs) {
  lower_closed = true; file_free(f); lower_closed = false;
 }
}
static struct file *fuse_file_passthrough(struct fuse_file *ff) { return ff->passthrough; }
static int fuse_passthrough_extfuse_notify(struct file *f, __u32 op, __u32 phase) {
 (void)f; return notify(op, phase, 0);
}
static void fuse_file_accessed(struct file *f) { (void)f; }
static bool can_mmap_file(struct file *f) { (void)f; return true; }
static void vma_set_file(struct vm_area_struct *vma, struct file *f) {
 f->refs++; vma->vm_file = f;
}
#define scoped_with_creds(c) for (int once = ((void)(c), 1); once; once = 0)
static int vfs_mmap(struct file *file, struct vm_area_struct *vma) {
 lower_mmap_calls++;
 if (replace_file) { fput(file); vma->vm_file = &redirected; }
 return mmap_error;
}
/* MMAP_CODE */
static void prepare(struct backing_file *bf, struct fuse_file *ff, struct file *upper, bool negotiated) {
 memset(bf, 0, sizeof(*bf)); memset(ff, 0, sizeof(*ff));
 bf->file.f_mode = FMODE_BACKING | FMODE_NOACCOUNT; bf->file.refs = 1;
 bf->user_path.dentry = &upper_dentry;
 ff->passthrough = &bf->file; upper->private_data = ff;
 if (negotiated) {
  ff->passthrough_mmap = calloc(1, sizeof(*ff->passthrough_mmap));
  backing_file_set_release(&bf->file, fuse_passthrough_backing_release, ff->passthrough_mmap);
 }
 upper_path_live = true;
}
int main(int argc, char **argv) {
 assert(argc == 2); const char *name = argv[1];
 if (!strcmp(name, "trace-count")) {
  for (int error = 0; error > -2; error--) {
   assert(count_request(EXTFUSE_PASSTHROUGH_MMAP, EXTFUSE_PASSTHROUGH_PHASE_BEGIN, error));
   assert(!count_request(EXTFUSE_PASSTHROUGH_MMAP, EXTFUSE_PASSTHROUGH_PHASE_END, error));
   assert(count_request(EXTFUSE_PASSTHROUGH_READ, EXTFUSE_PASSTHROUGH_PHASE_BEGIN, error) == !!error);
   assert(count_request(EXTFUSE_PASSTHROUGH_READ, EXTFUSE_PASSTHROUGH_PHASE_END, error));
  }
  return 0;
 }
 struct backing_file bf, other;
 struct fuse_file ff, other_ff;
 struct file upper = {}, other_upper = {};
 struct vm_area_struct vma = {.vm_file = &upper}, second = {.vm_file = &upper};
 bool legacy = !strcmp(name, "legacy");
 prepare(&bf, &ff, &upper, !legacy);
 if (!strcmp(name, "begin-error")) map_error = true;
 if (!strcmp(name, "mmap-error")) mmap_error = -ENOMEM;
 if (!strcmp(name, "replaced-file")) replace_file = true;
 int ret = fuse_passthrough_mmap(&upper, &vma);
 if (map_error) {
  assert(ret < 0 && !lower_mmap_calls && !ff.passthrough_mmap->mappings.value);
  map_error = false; fuse_passthrough_release(&ff, NULL); assert(!release_events); return 0;
 }
 assert(ret == mmap_error && marker == 1 && getattr_result() == UPCALL);
 if (replace_file) {
  assert(!ff.passthrough_mmap->mappings.value);
  fuse_passthrough_release(&ff, NULL);
  assert(!release_events && marker == 1 && getattr_result() == UPCALL);
  return 0;
 }
 if (!strcmp(name, "multiple")) {
  assert(!fuse_passthrough_mmap(&upper, &second)); assert(marker == 2);
 } else if (!strcmp(name, "two-files")) {
  prepare(&other, &other_ff, &other_upper, true);
  second.vm_file = &other_upper;
  assert(!fuse_passthrough_mmap(&other_upper, &second)); assert(marker == 2);
 } else if (!strcmp(name, "fork")) {
  second = vma; bf.file.refs++;
 } else if (!strcmp(name, "cached-shared")) {
  assert(!notify(EXTFUSE_PASSTHROUGH_MMAP, EXTFUSE_PASSTHROUGH_PHASE_BEGIN, 0));
 } else if (!strcmp(name, "underflow")) {
  assert(transition_mmap_count(&marker, marker + 1, 0) < 0);
 } else if (!strcmp(name, "overflow")) {
  marker = 0x7fffffffU; assert(transition_mmap_count(&marker, 1, 1) < 0);
 } else if (!strcmp(name, "cas-starvation")) {
  fail_cas = true; assert(transition_mmap_count(&marker, 1, 1) < 0); fail_cas = false;
 } else if (!strcmp(name, "stale-error")) {
  stale_error = true;
 }
 fuse_passthrough_release(&ff, NULL);
 assert(!release_events && getattr_result() == UPCALL);
 if (!strcmp(name, "fork") || !strcmp(name, "multiple")) {
  fput(second.vm_file); assert(!release_events);
 }
 fput(vma.vm_file);
 if (!strcmp(name, "two-files")) {
  assert(marker == 1 && getattr_result() == UPCALL);
  upper_path_live = true;
  fuse_passthrough_release(&other_ff, NULL);
  assert(marker == 1); fput(second.vm_file);
 }
 bool guarded = legacy || !strcmp(name, "cached-shared") ||
  !strcmp(name, "underflow") || !strcmp(name, "overflow") ||
  !strcmp(name, "cas-starvation") || !strcmp(name, "stale-error");
 assert(!!marker == guarded);
 assert(getattr_result() == UPCALL); /* The old snapshot never becomes valid. */
 if (!guarded) {
  assert(release_events == (!strcmp(name, "two-files") ? 2 : 1));
  assert(retired_count == ((!strcmp(name, "multiple") || !strcmp(name, "two-files")) ? 2 : 1));
  assert(!(native_state.attr_state & EXTFUSE_NATIVE_STATE_ACTIVE_MASK));
  refresh(); assert(!getattr_result());
 }
 return 0;
}
'''


class NativeMmapLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="extfuse-mmap-lifetime-")
        bpf = (ROOT / "bpf/extfuse.c").read_text()
        names = ["static int has_passthrough_mmap_marker(",
                 "static int daemon_domain_inactive(", "static int native_domain_inactive(",
                 "static int daemon_cache_token_current(", "static int native_cache_token_current(",
                 "static int cache_tokens_current(", "static int mark_passthrough_attr_stale(",
                 "static int transition_native_state(", "static int update_native_state(",
                 "static int passthrough_notification(", "static int transition_mmap_count(",
                 "HANDLER(EXTFUSE_PASSTHROUGH_MMAP, 67)", "HANDLER(FUSE_GETATTR, 3)"]
        source = HARNESS.replace("/* BPF_CODE */", "\n".join(function(bpf, n) for n in names))
        kernel = (LINUX / "fs/fuse/extfuse.c").read_text()
        condition = re.search(r"if \((opcode == EXTFUSE_PASSTHROUGH_MMAP \?.*?)\) \{",
                              kernel, re.S).group(1)
        source = source.replace("/* COUNT_CONDITION */", "(" + condition + ")")
        table = (LINUX / "fs/file_table.c").read_text()
        fuse = (LINUX / "fs/fuse/passthrough.c").read_text()
        backing = (LINUX / "fs/backing-file.c").read_text()
        lifetime = function(table, "void backing_file_set_release(")
        lifetime += function(fuse, "static void fuse_passthrough_backing_release(")
        lifetime += function(table, "static inline void file_free(")
        source = source.replace("/* LIFETIME_CODE */", lifetime)
        mmap = function(backing, "int backing_file_mmap(")
        mmap += function(fuse, "ssize_t fuse_passthrough_mmap(")
        mmap += function(fuse, "void fuse_passthrough_release(")
        source = source.replace("/* MMAP_CODE */", mmap)
        path = Path(cls.tmp.name) / "mmap.c"
        path.write_text(source)
        cls.binary = path.with_suffix("")
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
            "-fsanitize=undefined", "-D__EXPORTED_HEADERS__", "-I" + str(ROOT / "include"),
            "-I" + str(ROOT / "bpf"),
            "-I" + str(LINUX / "include/uapi"), str(path), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_mapping_outlives_close_and_fork(self):
        for name in ("single", "multiple", "two-files", "fork", "mmap-error"):
            with self.subTest(name=name):
                subprocess.run([str(self.binary), name], check=True, timeout=10)

    def test_fail_closed_and_legacy(self):
        for name in ("legacy", "cached-shared", "replaced-file", "begin-error", "stale-error",
                     "underflow", "overflow", "cas-starvation"):
            with self.subTest(name=name):
                subprocess.run([str(self.binary), name], check=True, timeout=10)

    def test_retirement_does_not_count_another_mmap(self):
        subprocess.run([str(self.binary), "trace-count"], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
