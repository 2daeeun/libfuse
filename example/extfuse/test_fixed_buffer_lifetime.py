#!/usr/bin/env python3
"""Compile the paired kernel's fixed-bvec ownership helpers in a fixture.

No mount or kernel artifact is built. Run explicitly when C compilation is
allowed; source inspection alone does not execute these lifetime checks.
EXTFUSE_KERNEL_SOURCE selects the paired Linux source tree.
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
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
#define IO_BUF_DEST 1
#define IO_BUF_SOURCE 2
#define IO_BUF_WRITE_IN_TASK 4
#define IO_IMU_DEST 1
#define IO_IMU_SOURCE 2
#define IORING_RSRC_BUFFER 1
#define PAGE_SHIFT 12
#define MAX_RW_COUNT 0x7ffff000U
#define BUILD_BUG_ON(value) _Static_assert(!(value), #value)
#define unlikely(value) (value)
#define array_index_nospec(index, count) (index)
#define array_size(count, size) ((size_t)(count) * (size))
#define check_add_overflow(a, b, result) __builtin_add_overflow(a, b, result)
struct folio { unsigned refs; size_t size; };
struct bio_vec { struct folio *bv_page; unsigned bv_len, bv_offset; };
struct io_mapped_ubuf {
 unsigned ubuf, len, nr_bvecs, acct_pages, folio_shift, refs;
 void (*release)(void *); void *priv; bool is_kbuf, write_in_task; u8 dir;
 struct bio_vec bvec[];
};
struct io_rsrc_node { struct io_mapped_ubuf *buf; };
struct io_rsrc_data { unsigned nr; struct io_rsrc_node *nodes[2]; };
struct io_ring_ctx { struct io_rsrc_data buf_table; void *user, *mm_account; int node_cache; };
struct io_uring_cmd { struct io_ring_ctx *ctx; };
#define cmd_to_io_kiocb(cmd) (cmd)
static bool locked, fail_node, fail_imu;
static unsigned gets, puts, imu_frees, node_frees, custom_releases;
static struct folio *page_folio(struct folio *page) { return page; }
static size_t folio_size(struct folio *folio) { return folio->size; }
static void folio_get(struct folio *folio) { assert(folio->refs); folio->refs++; gets++; }
static void folio_put(struct folio *folio) { assert(folio->refs); folio->refs--; puts++; }
static void refcount_set(unsigned *refs, unsigned value) { *refs = value; }
static unsigned refcount_read(unsigned *refs) { return *refs; }
static bool refcount_dec_and_test(unsigned *refs) { assert(*refs); return !--*refs; }
static void io_ring_submit_lock(struct io_ring_ctx *ctx, unsigned flags)
{ (void)ctx; (void)flags; assert(!locked); locked = true; }
static void io_ring_submit_unlock(struct io_ring_ctx *ctx, unsigned flags)
{ (void)ctx; (void)flags; assert(locked); locked = false; }
static struct io_rsrc_node *io_rsrc_node_alloc(struct io_ring_ctx *ctx, int type)
{ (void)ctx; assert(locked && type == IORING_RSRC_BUFFER);
  return fail_node ? NULL : calloc(1, sizeof(struct io_rsrc_node)); }
static struct io_mapped_ubuf *io_alloc_imu(struct io_ring_ctx *ctx, unsigned count)
{ (void)ctx; assert(locked); return fail_imu ? NULL :
  malloc(sizeof(struct io_mapped_ubuf) + count * sizeof(struct bio_vec)); }
static void io_cache_free(void *cache, void *node)
{ (void)cache; assert(locked); node_frees++; free(node); }
static void io_free_imu(struct io_ring_ctx *ctx, struct io_mapped_ubuf *imu)
{ (void)ctx; imu_frees++; free(imu); }
static void io_unaccount_mem(void *user, void *mm, unsigned pages)
{ (void)user; (void)mm; (void)pages; assert(!"kernel folios are not user pins"); }
@RELEASE@
@UNMAP@
/* Node-reference handling is unchanged. Exercise its final buffer release. */
static void io_put_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node)
{ io_buffer_unmap(ctx, node->buf); node_frees++; free(node); }
@REGISTER@
@UNREGISTER@
@FUSE_SETUP_FIXTURE@
static void custom_release(void *priv)
{ assert(priv == &custom_releases); custom_releases++; }
int main(int argc, char **argv)
{
 assert(argc == 2); const char *name = argv[1];
 if (!strncmp(name, "setup-", 6)) return check_fuse_setup(name + 6);
 struct io_ring_ctx ctx = { .buf_table.nr = 1 };
 struct io_uring_cmd cmd = { .ctx = &ctx };
 struct folio first = {1, 16384}, second = {1, 4096};
 struct bio_vec bvs[] = {{&first, 4096, 0}, {&first, 4096, 4096}, {&second, 1024, 0}};
 unsigned count = 3, index = 0;
 u8 dir = IO_BUF_SOURCE;
 bool custom = !strcmp(name, "custom-release");
 void (*release)(void *) = custom ? custom_release : NULL;
 void *priv = custom ? &custom_releases : NULL;
 if (!strcmp(name, "node-failure")) fail_node = true;
 if (!strcmp(name, "imu-failure")) fail_imu = true;
 if (!strcmp(name, "bad-tail")) bvs[2].bv_len = 4097;
 if (!strcmp(name, "bad-offset")) bvs[2].bv_offset = 4096;
 if (!strcmp(name, "no-page")) bvs[2].bv_page = NULL;
 if (!strcmp(name, "empty")) count = 0;
 if (!strcmp(name, "bad-index")) index = 1;
 if (!strcmp(name, "bad-direction")) dir = 0;
 if (!strcmp(name, "task-write")) dir |= IO_BUF_WRITE_IN_TASK;
 if (!strcmp(name, "task-read")) dir = IO_BUF_DEST | IO_BUF_WRITE_IN_TASK;
 if (!strcmp(name, "task-both")) dir |= IO_BUF_DEST | IO_BUF_WRITE_IN_TASK;
 if (!strcmp(name, "task-without-direction")) dir = IO_BUF_WRITE_IN_TASK;
 if (!strcmp(name, "bad-owner")) priv = &custom_releases;
 if (!strcmp(name, "overflow")) {
  first.size = UINT_MAX; bvs[0].bv_len = MAX_RW_COUNT; bvs[1].bv_len = 4096;
 }
 int ret = io_buffer_register_bvec_array(&cmd, bvs, count, release, priv, dir, index, 0);
 if (ret) {
  assert(!gets && !puts && !custom_releases && !ctx.buf_table.nodes[0] && !locked);
  assert(first.refs == 1 && second.refs == 1);
  assert(ret == ((fail_node || fail_imu) ? -ENOMEM :
                 !strcmp(name, "overflow") ? -EOVERFLOW : -EINVAL));
  assert(node_frees == (unsigned)fail_imu); return 0;
 }
 struct io_mapped_ubuf *imu = ctx.buf_table.nodes[0]->buf;
 assert(imu->nr_bvecs == 3 && imu->len == 9216 && !imu->acct_pages && imu->is_kbuf);
 assert(imu->dir == IO_BUF_SOURCE);
 assert(imu->write_in_task == !strcmp(name, "task-write"));
 assert(io_buffer_register_bvec_array(&cmd, bvs, count, NULL, NULL, dir, index, 0) == -EBUSY);
 /* A stack/scratch descriptor array may disappear immediately after return. */
 memset(bvs, 0, sizeof(bvs));
 assert(imu->bvec[0].bv_page == &first && imu->bvec[2].bv_len == 1024);
 assert(gets == (custom ? 0U : 3U));
 if (custom) {
  assert(!io_buffer_unregister_bvec(&cmd, 0, 0));
  assert(custom_releases == 1 && !puts && first.refs == 1 && second.refs == 1);
 } else {
  assert(first.refs == 3 && second.refs == 2);
  /* Independent retained buffer users can outlive the sparse slot. */
  imu->refs += 2;
  assert(!io_buffer_unregister_bvec(&cmd, 0, 0));
  assert(!ctx.buf_table.nodes[0] && !puts && !imu_frees);
  folio_put(&first); folio_put(&second);  /* Drop the request's original refs. */
  io_buffer_unmap(&ctx, imu); assert(puts == 2 && !imu_frees);
  io_buffer_unmap(&ctx, imu);
  assert(!first.refs && !second.refs && puts == 5);
 }
 assert(imu_frees == 1 && node_frees == 1 && !locked);
 assert(io_buffer_unregister_bvec(&cmd, 0, 0) == -EINVAL);
 return 0;
}
"""


FUSE_SETUP_FIXTURE = r"""
#define FUSE_READ 15
#define FUSE_WRITE 16
#define FUSE_WRITE_CACHE 1
#define FUSE_URING_INLINE_BVECS @INLINE_BVECS@
#define GFP_KERNEL_ACCOUNT 0
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define typeof __typeof__
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define min_t(type, first, second) ((type)(first) < (type)(second) ? (type)(first) : (type)(second))
struct fuse_arg { size_t size; const void *value; };
struct fuse_args {
 unsigned opcode, in_numargs, out_numargs; bool out_argvar;
 struct fuse_arg in_args[2], out_args[1];
};
struct fuse_folio_desc { unsigned offset, length; };
struct fuse_args_pages {
 struct fuse_args args; struct folio **folios;
 struct fuse_folio_desc *descs; unsigned num_folios;
};
struct fuse_req { struct fuse_args *args; };
struct fuse_write_in { unsigned write_flags; };
struct fuse_conn { unsigned max_pages; };
struct fuse_ring { struct fuse_conn *fc; unsigned max_payload_sz; };
struct fuse_ring_queue { struct fuse_ring *ring; bool write_in_task; };
struct fuse_ring_ent {
 struct fuse_ring_queue *queue; struct io_uring_cmd *cmd;
 unsigned zero_copy_index; bool zero_copied;
};
static unsigned scratch_allocs, scratch_frees;
static bool fail_scratch;
static void *kvmalloc_array(size_t count, size_t size, unsigned flags)
{ (void)flags; scratch_allocs++; return fail_scratch ? NULL : malloc(count * size); }
static void kvfree(void *memory) { assert(memory); scratch_frees++; free(memory); }
static void bvec_set_folio(struct bio_vec *bv, struct folio *folio,
                          unsigned length, unsigned offset)
{ *bv = (struct bio_vec) {folio, length, offset}; }
@SETUP@
static int check_fuse_setup(const char *name)
{
 unsigned count = (unsigned)strtoul(name, NULL, 10);
 bool write = strstr(name, "write") != NULL;
 bool cropped = strstr(name, "cropped") != NULL;
 bool bad_tail = strstr(name, "bad-tail") != NULL;
 struct folio folios[33], *pages[33];
 struct fuse_folio_desc descs[33];
 assert(count >= 31 && count <= ARRAY_SIZE(folios));
 for (unsigned i = 0; i < count; i++) {
  folios[i] = (struct folio) {1, 4096}; pages[i] = &folios[i];
  descs[i] = (struct fuse_folio_desc) {0, 4096};
 }
 unsigned bytes = count * 4096 - (cropped ? 3072 : 0);
 struct fuse_write_in in = {.write_flags = FUSE_WRITE_CACHE};
 struct fuse_args_pages ap = {
  .args = {.opcode = write ? FUSE_WRITE : FUSE_READ,
           .in_numargs = write ? 2 : 1, .out_numargs = 1, .out_argvar = !write,
           .in_args = {{sizeof(in), &in}, {bytes, NULL}}, .out_args = {{bytes, NULL}}},
  .folios = pages, .descs = descs, .num_folios = count,
 };
 struct fuse_req req = {.args = &ap.args};
 struct io_ring_ctx ctx = {.buf_table.nr = 2};
 struct io_uring_cmd cmd = {.ctx = &ctx};
 struct fuse_conn fc = {.max_pages = 33};
 struct fuse_ring ring = {.fc = &fc, .max_payload_sz = 33 * 4096};
 struct fuse_ring_queue queue = {.ring = &ring, .write_in_task = true};
 struct fuse_ring_ent ent = {.queue = &queue, .cmd = &cmd, .zero_copy_index = 1};
 fail_scratch = strstr(name, "allocation-failure") != NULL;
 fail_imu = strstr(name, "registration-failure") != NULL;
 if (bad_tail) descs[count - 1].length = 4097;
 int ret = fuse_uring_set_up_zero_copy(&ent, &req, 0);
 assert(!locked && scratch_allocs == (unsigned)(count > 32));
 assert(scratch_frees == (unsigned)(count > 32 && !fail_scratch));
 if (bad_tail || fail_scratch || fail_imu) {
  assert(ret == (bad_tail ? -EINVAL : -ENOMEM));
  assert(!ent.zero_copied && !ctx.buf_table.nodes[1] && !gets && !puts);
  for (unsigned i = 0; i < count; i++) assert(folios[i].refs == 1);
  return 0;
 }
 assert(!ret && ent.zero_copied && gets == count);
 struct io_mapped_ubuf *imu = ctx.buf_table.nodes[1]->buf;
 assert(imu->nr_bvecs == count && imu->len == bytes);
 assert(imu->dir == (write ? IO_BUF_SOURCE : IO_BUF_DEST));
 assert(imu->write_in_task == write);
 assert(imu->bvec[count - 1].bv_len == (cropped ? 1024U : 4096U));
 imu->refs++; /* An independent buffer user survives sparse-slot removal. */
 assert(!io_buffer_unregister_bvec(&cmd, 1, 0) && !puts && !imu_frees);
 for (unsigned i = 0; i < count; i++) folio_put(&folios[i]);
 io_buffer_unmap(&ctx, imu);
 for (unsigned i = 0; i < count; i++) assert(!folios[i].refs);
 assert(puts == 2 * count && imu_frees == 1 && node_frees == 1);
 return 0;
}
"""


def harness_source():
    source = (KERNEL / "io_uring/rsrc.c").read_text()
    fuse_source = (KERNEL / "fs/fuse/dev_uring.c").read_text()
    inline_bvecs = re.search(r"^#define FUSE_URING_INLINE_BVECS (\d+)$",
                             fuse_source, re.M).group(1)
    setup = FUSE_SETUP_FIXTURE.replace("@INLINE_BVECS@", inline_bvecs).replace(
        "@SETUP@", function(fuse_source, "fuse_uring_set_up_zero_copy"))
    code = HARNESS.replace("@FUSE_SETUP_FIXTURE@", setup)
    for tag, name in (
            ("RELEASE", "io_release_bvec_folios"),
            ("UNMAP", "io_buffer_unmap"),
            ("REGISTER", "io_buffer_register_bvec_array"),
            ("UNREGISTER", "io_buffer_unregister_bvec")):
        code = code.replace(f"@{tag}@", function(source, name))
    return code


class FixedBufferLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (KERNEL / "io_uring/rsrc.c").exists():
            raise unittest.SkipTest("EXTFUSE_KERNEL_SOURCE must name the paired Linux tree")
        code = harness_source()
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-bvec-lifetime-")
        cls.addClassCleanup(cls.directory.cleanup)
        path = Path(cls.directory.name)
        (path / "check.c").write_text(code)
        cls.binary = path / "check"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=c11",
                        "-Wall", "-Wextra", "-Werror", str(path / "check.c"),
                        "-o", str(cls.binary)], check=True, timeout=20)

    def test_final_user_owns_folios_after_scratch_and_slot_are_gone(self):
        self.check("retained-users")
        self.check("task-write")

    def test_existing_custom_release_keeps_caller_ownership(self):
        self.check("custom-release")

    def test_validation_and_allocation_failures_take_no_references(self):
        for name in ("node-failure", "imu-failure", "bad-tail", "bad-offset",
                     "no-page", "empty", "bad-index", "bad-direction", "bad-owner", "overflow",
                     "task-read", "task-both", "task-without-direction"):
            with self.subTest(name=name):
                self.check(name)

    def test_read_and_write_scratch_boundary_retains_last_user_ownership(self):
        for count in (31, 32, 33):
            for direction in ("read", "write"):
                for tail in ("full", "cropped"):
                    with self.subTest(count=count, direction=direction, tail=tail):
                        self.check(f"setup-{count}-{direction}-{tail}")

    def test_scratch_and_registration_errors_release_only_owned_resources(self):
        for name in ("32-read-bad-tail", "33-read-bad-tail",
                     "33-write-allocation-failure", "32-read-registration-failure",
                     "33-write-registration-failure"):
            with self.subTest(name=name):
                self.check("setup-" + name)

    def check(self, name):
        subprocess.run([str(self.binary), name], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
