#!/usr/bin/env python3
"""Exercise kernel ring input serialization without mounting or building Linux.

The production registration and serialization functions run against controlled
copy/registration boundaries. Optionally set EXTFUSE_KERNEL_BASELINE_SOURCE to
an older dev_uring.c file to compare every successful wire result directly.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


LINUX = Path(os.environ.get("EXTFUSE_KERNEL_SOURCE",
                           Path(__file__).resolve().parents[3] / "linux"))


def function(source, name):
    match = re.search(r"^static [^;{}\n]*\b" + name +
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


HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
#define FUSE_READ 15
#define FUSE_WRITE 16
#define FUSE_WRITE_CACHE 1
#define FUSE_URING_ENT_ZERO_COPY 1
#define FUSE_URING_HEADER_OP 1
#define FUSE_URING_HEADER_RING_ENT 2
#define FUSE_URING_INLINE_BVECS @INLINE_BVECS@
#define IO_BUF_DEST 1
#define IO_BUF_SOURCE 2
#define IO_BUF_WRITE_IN_TASK 4
#define ITER_DEST 1
#define GFP_KERNEL_ACCOUNT 0
#define MAX_RW_COUNT 0x7ffff000U
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define check_add_overflow(a, b, out) __builtin_add_overflow(a, b, out)
#define container_of(p, t, member) ((t *)((char *)(p) - offsetof(t, member)))
#define pr_info_ratelimited(...) ((void)0)
struct folio { size_t size; };
struct bio_vec { struct folio *folio; unsigned length, offset; };
struct fuse_in_arg { unsigned size; const void *value; };
struct fuse_arg { unsigned size; void *value; };
struct fuse_args {
 unsigned opcode, in_numargs, out_numargs;
 bool zero_copy, in_pages, out_pages, out_argvar;
 struct fuse_in_arg in_args[4];
 struct fuse_arg out_args[2];
};
struct fuse_folio_desc { unsigned offset, length; };
struct fuse_args_pages {
 struct fuse_args args; struct folio **folios;
 struct fuse_folio_desc *descs; unsigned num_folios;
};
struct fuse_req { struct fuse_args *args; struct { struct { uint64_t unique; } h; } in; };
struct fuse_write_in { unsigned write_flags; };
struct fuse_conn { unsigned max_pages; };
struct fuse_ring { struct fuse_conn *fc; unsigned max_payload_sz; };
struct fuse_bufpool { uintptr_t base_uaddr; };
struct fuse_ring_queue {
 struct fuse_ring *ring; struct fuse_bufpool *bufpool;
 bool zero_copy, write_in_task;
};
struct fuse_ring_ent {
 struct fuse_ring_queue *queue; void *cmd;
 unsigned zero_copy_index; bool zero_copied;
 struct { void *iov_base; size_t iov_len; } payload;
};
struct fuse_uring_ent_in_out { uint64_t flags, commit_id, payload_sz, offset; };
struct iov_iter { unsigned unused; };
struct fuse_copy_state { bool skip_folio_copy; struct { unsigned copied_sz; } ring; };
static unsigned copies, imports, finishes, registrations, registered_bytes;
static unsigned header_fail, import_fail, copy_fail, register_fail;
static unsigned op_size;
static unsigned char op_bytes[64];
static struct fuse_uring_ent_in_out wire;
static bool scratch_fail;
static size_t folio_size(struct folio *folio) { return folio->size; }
static void *kvmalloc_array(size_t count, size_t size, unsigned flags)
{ (void)flags; return scratch_fail ? NULL : malloc(count * size); }
static void kvfree(void *value) { free(value); }
static void bvec_set_folio(struct bio_vec *bv, struct folio *folio,
                          unsigned length, unsigned offset)
{ *bv = (struct bio_vec){folio, length, offset}; }
static int io_buffer_register_bvec_array(void *cmd, const struct bio_vec *bvs,
 unsigned count, void (*release)(void *), void *priv, u8 dir,
 unsigned index, unsigned issue_flags)
{
 (void)cmd; (void)issue_flags; assert(index == 1 && !release && !priv);
 assert(dir & (IO_BUF_DEST | IO_BUF_SOURCE)); registrations++;
 if (register_fail) return -(int)register_fail;
 for (unsigned i = 0; i < count; i++) registered_bytes += bvs[i].length;
 return 0;
}
static int copy_header_to_ring(struct fuse_ring_ent *ent, unsigned type,
                               const void *header, size_t size)
{
 (void)ent;
 if (header_fail == type) return -EFAULT;
 if (type == FUSE_URING_HEADER_OP) {
  assert(size <= sizeof(op_bytes)); op_size = size; memcpy(op_bytes, header, size);
 } else {
  assert(type == FUSE_URING_HEADER_RING_ENT && size == sizeof(wire));
  memcpy(&wire, header, size);
 }
 return 0;
}
static bool bufpool_enabled(struct fuse_ring_queue *queue) { return !!queue->bufpool; }
static int setup_fuse_copy_state(struct fuse_copy_state *cs, struct fuse_req *req,
 struct fuse_ring_ent *ent, int dir, struct iov_iter *iter, unsigned issue_flags)
{
 (void)req; (void)iter; (void)issue_flags; assert(dir == ITER_DEST); imports++;
 if (import_fail) return -(int)import_fail;
 memset(cs, 0, sizeof(*cs)); cs->skip_folio_copy = ent->zero_copied; return 0;
}
/* Observe generic copying at its boundary; page-layout validation is production. */
static int fuse_copy_args(struct fuse_copy_state *cs, unsigned count, unsigned pages,
                          struct fuse_arg *args, int zeroing)
{
 assert(!zeroing); copies++;
 if (copy_fail) return -(int)copy_fail;
 for (unsigned i = 0; i < count; i++)
  if (!(cs->skip_folio_copy && pages && i + 1 == count))
   cs->ring.copied_sz += args[i].size;
 return 0;
}
static void fuse_copy_finish(struct fuse_copy_state *cs) { (void)cs; finishes++; }
@CAN_ZERO@
@SETUP_ZERO@
@SERIALIZE@
int main(int argc, char **argv)
{
 assert(argc == 2); const char *name = argv[1];
 bool fixed = !strncmp(name, "fixed-", 6);
 bool read = strstr(name, "read") != NULL;
 struct folio folios[33], *pages[33];
 struct fuse_folio_desc descs[33];
 unsigned count = strstr(name, "large") ? 33 : 2;
 unsigned bytes = count * 4096 - (strstr(name, "cropped") ? 3072 : 0);
 for (unsigned i = 0; i < ARRAY_SIZE(folios); i++) {
  folios[i].size = 4096; pages[i] = &folios[i];
  descs[i] = (struct fuse_folio_desc){0, 4096};
 }
 struct fuse_write_in in = {.write_flags = FUSE_WRITE_CACHE};
 struct fuse_args_pages ap = {
  .args = {.opcode = read ? FUSE_READ : FUSE_WRITE,
           .zero_copy = fixed, .in_pages = !read, .out_pages = read,
           .in_numargs = read ? 1 : 2, .out_numargs = 1, .out_argvar = read,
           .in_args = {{sizeof(in), &in}, {bytes, NULL}},
           .out_args = {{read ? bytes : 8, NULL}}},
  .folios = pages, .descs = descs, .num_folios = count,
 };
 struct fuse_req req = {.args = &ap.args, .in.h.unique = 0x12345678};
 struct fuse_conn fc = {.max_pages = 33};
 struct fuse_ring ring = {.fc = &fc, .max_payload_sz = 33 * 4096};
 struct fuse_bufpool pool = {.base_uaddr = 0x1000};
 struct fuse_ring_queue queue = {.ring = &ring, .bufpool = &pool,
                                 .zero_copy = fixed, .write_in_task = true};
 struct fuse_ring_ent ent = {.queue = &queue, .zero_copy_index = 1,
                             .payload = {(void *)0x2000, 33 * 4096}};
 int expected = 0;
 bool generic = !fixed && !read;
 if (!strcmp(name, "header-only")) {
  ap.args.opcode = 3; ap.args.in_pages = false; ap.args.in_numargs = 1; generic = false;
 }
 if (!strcmp(name, "empty-input")) {
  ap.args.opcode = 3; ap.args.in_pages = false; ap.args.in_numargs = 0; generic = false;
 }
 if (strstr(name, "no-pool")) { queue.bufpool = NULL; ent.payload.iov_base = NULL; }
 if (strstr(name, "copied-fallback")) { queue.zero_copy = false; generic = true; }
 if (strstr(name, "extra-argument")) {
  ap.args.in_numargs = 3; ap.args.in_args[2].size = bytes;
  ap.args.in_args[1] = (struct fuse_in_arg){3, "abc"};
  if (fixed) expected = -EINVAL;
 }
 if (strstr(name, "bad-page")) { descs[count - 1].length = 4097; expected = -EINVAL; }
 if (strstr(name, "short-pages")) { ap.args.in_args[1].size += 1; expected = -EINVAL; }
 if (strstr(name, "empty-pages")) { ap.num_folios = 0; expected = -EINVAL; }
 if (strstr(name, "empty-payload")) { ap.args.in_args[1].size = 0; expected = -EINVAL; }
 if (strstr(name, "bad-out-args")) { ap.args.out_numargs = 0; expected = -EINVAL; }
 if (strstr(name, "register-failure")) { register_fail = ENOMEM; expected = -ENOMEM; }
 if (strstr(name, "scratch-failure")) { scratch_fail = true; expected = -ENOMEM; }
 if (strstr(name, "op-failure")) { header_fail = FUSE_URING_HEADER_OP; expected = -EFAULT; }
 if (strstr(name, "ring-failure")) { header_fail = FUSE_URING_HEADER_RING_ENT; expected = -EFAULT; }
 if (strstr(name, "import-failure")) { import_fail = EFAULT; expected = -EFAULT; }
 if (strstr(name, "copy-failure")) { copy_fail = EIO; expected = -EIO; }
 int ret = fuse_uring_args_to_ring(&req, &ent, 0);
 assert(ret == expected);
 if (expected) {
  assert(!wire.commit_id);
  if (expected == -EINVAL || register_fail || scratch_fail)
   assert(!ent.zero_copied && !imports && !copies && !op_size);
  if (copy_fail) assert(copies == 1 && finishes == 1);
  if (import_fail) assert(imports == 1 && !copies && !finishes);
  printf("error=%d registered=%u zero=%u\n",
         ret, registered_bytes, ent.zero_copied);
  return 0;
 }
 bool zc = fixed && queue.zero_copy;
 assert(wire.commit_id == req.in.h.unique && wire.flags == (unsigned)zc);
 assert(wire.payload_sz == (read || !ap.args.in_pages ? 0 : bytes +
                            (ap.args.in_numargs > 2 ? 3 : 0)));
 assert(wire.offset == (queue.bufpool && ent.payload.iov_base ? 4096 : 0));
 assert(op_size == (ap.args.in_numargs ? sizeof(in) : 0));
 if (op_size) assert(!memcmp(op_bytes, &in, sizeof(in)));
 assert(registrations == (unsigned)zc && registered_bytes == (zc ? bytes : 0));
 if (!getenv("EXTFUSE_PAYLOAD_BASELINE")) {
  assert(imports == (unsigned)generic && copies == (unsigned)generic);
  assert(finishes == (unsigned)generic);
 }
 printf("wire=%llu,%llu,%llu,%llu op=%u,%u registration=%u,%u\n",
        (unsigned long long)wire.flags, (unsigned long long)wire.commit_id,
        (unsigned long long)wire.payload_sz, (unsigned long long)wire.offset,
        op_size, op_bytes[0], registrations, registered_bytes);
 return 0;
}
'''


def harness(source):
    code = HARNESS.replace("@INLINE_BVECS@", re.search(
        r"^#define FUSE_URING_INLINE_BVECS (\d+)$", source, re.M).group(1))
    for tag, name in (("CAN_ZERO", "can_zero_copy_req"),
                      ("SETUP_ZERO", "fuse_uring_set_up_zero_copy"),
                      ("SERIALIZE", "fuse_uring_args_to_ring")):
        code = code.replace(f"@{tag}@", function(source, name))
    return code


class UringFixedRequestPayloadTests(unittest.TestCase):
    def test_production_serialization_and_error_paths(self):
        scenarios = (
            "fixed-write", "fixed-write-cropped", "fixed-write-large",
            "fixed-write-large-cropped", "fixed-read", "fixed-read-no-pool",
            "copied-write", "copied-read", "copied-extra-argument",
            "fixed-copied-fallback", "header-only", "empty-input",
            "fixed-write-extra-argument", "fixed-write-bad-page",
            "fixed-write-short-pages", "fixed-write-empty-pages",
            "fixed-write-empty-payload", "fixed-read-bad-out-args",
            "fixed-write-register-failure", "fixed-write-large-scratch-failure",
            "fixed-write-op-failure", "fixed-write-ring-failure",
            "copied-write-import-failure", "copied-write-copy-failure",
        )
        sources = [("current", (LINUX / "fs/fuse/dev_uring.c").read_text())]
        baseline = os.environ.get("EXTFUSE_KERNEL_BASELINE_SOURCE")
        if baseline:
            sources.append(("baseline", Path(baseline).read_text()))
        results = {}
        with tempfile.TemporaryDirectory(prefix="extfuse-fixed-payload-") as work:
            for label, source in sources:
                path = Path(work) / f"{label}.c"
                path.write_text(harness(source))
                binary = path.with_suffix("")
                subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
                    "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)],
                    check=True, timeout=20)
                env = os.environ.copy()
                env.pop("EXTFUSE_PAYLOAD_BASELINE", None)
                if label == "baseline":
                    env["EXTFUSE_PAYLOAD_BASELINE"] = "1"
                for scenario in scenarios:
                    with self.subTest(source=label, scenario=scenario):
                        result = subprocess.run([str(binary), scenario], env=env,
                                                capture_output=True, text=True,
                                                timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        if label == "current":
                            results[scenario] = result.stdout
                        else:
                            self.assertEqual(result.stdout, results[scenario])


if __name__ == "__main__":
    unittest.main()
