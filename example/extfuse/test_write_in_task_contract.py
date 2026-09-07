#!/usr/bin/env python3
"""Source-derived predicate and ordering checks; no C build or kernel execution."""

import itertools
import os
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
KERNEL = Path(os.environ.get("EXTFUSE_KERNEL_SOURCE", ROOT.parent / "linux"))
RW = (KERNEL / "io_uring/rw.c").read_text()
RSRC = (KERNEL / "io_uring/rsrc.c").read_text()
FUSE = (KERNEL / "fs/fuse/dev_uring.c").read_text()
LIB = (ROOT / "lib/fuse_uring.c").read_text()


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


def expression(source):
    # The production predicate contains only comparisons, bit masks and
    # short-circuit Boolean operators. This does not interpret C statements.
    source = re.sub(r"\b\w+(?:->\w+|\.\w+)+",
                    lambda m: re.sub(r"->|\.", "_", m.group()), source)
    source = source.replace("&&", " and ").replace("||", " or ")
    return " ".join(re.sub(r"!(?!=)", " not ", source).split())


PREDICATE = function(RW, "io_write_should_run_in_task")
REJECT = re.search(r"if \((.*?)\)\s*return false;", PREDICATE, re.S).group(1)
ACCEPT = re.search(r"return false;.*?return (.*?);", PREDICATE, re.S).group(1)
SYMBOLS = dict((name, 1 << i) for i, name in enumerate(sorted(set(re.findall(
    r"\b(?:IO_URING_F_|IORING_SETUP_|IORING_OP_|REQ_F_|IOCB_|O_|FOP_)[A-Z_]+",
    PREDICATE)))))


def state():
    values = dict(SYMBOLS)
    for name in ("required", "ring_flags"):
        value = re.search(r"unsigned int " + name + r" = (.*?);", PREDICATE, re.S).group(1)
        values[name] = eval(expression(value), {"__builtins__": {}}, values)
    values.update(
        req_opcode=values["IORING_OP_WRITE_FIXED"],
        req_flags=values["REQ_F_BUF_NODE"] | values["REQ_F_ISREG"],
        req_buf_node_buf_is_kbuf=True, req_buf_node_buf_write_in_task=True,
        issue_flags=values["required"], ctx_flags=values["ring_flags"],
        current=1, ctx_submitter_task=1, rw_kiocb_ki_pos=0,
        rw_kiocb_ki_flags=0, req_file_f_flags=0,
        req_file_f_op_write_iter=True, req_file_f_op_fop_flags=0)
    return values


def permitted(values):
    rejected = eval(expression(REJECT), {"__builtins__": {}}, values)
    return not rejected and bool(eval(expression(ACCEPT), {"__builtins__": {}}, values))


class WriteInTaskContractTests(unittest.TestCase):
    def test_predicate_flags_have_shared_header_declarations(self):
        # The model's symbolic values must not hide a file-local C macro.
        paths = ("include/linux/io_uring_types.h", "include/uapi/linux/io_uring.h",
                 "include/linux/fs.h", "include/uapi/asm-generic/fcntl.h")
        headers = "\n".join((KERNEL / path).read_text() for path in paths)
        for name in SYMBOLS:
            with self.subTest(name=name):
                self.assertRegex(headers, r"(?m)^\s*(?:#define\s+" + name +
                                 r"\b|" + name + r"\s*(?:=|,))")

    def test_production_predicate_accepts_only_the_opted_in_owner(self):
        values = state()
        self.assertTrue(permitted(values))
        for field, value in (
                ("req_opcode", 0), ("req_buf_node_buf_is_kbuf", False),
                ("req_buf_node_buf_write_in_task", False),
                ("current", 2), ("rw_kiocb_ki_pos", -1),
                ("req_file_f_op_write_iter", False)):
            with self.subTest(field=field):
                self.assertFalse(permitted(dict(values, **{field: value})))
        for bit in ("REQ_F_BUF_NODE", "REQ_F_ISREG"):
            self.assertFalse(permitted(dict(values, req_flags=values["req_flags"] & ~values[bit])))

    def test_explicit_async_nowait_direct_links_and_async_files_keep_their_path(self):
        values = state()
        groups = {
            "req_flags": ("REQ_F_FORCE_ASYNC", "REQ_F_NOWAIT", "REQ_F_LINK",
                          "REQ_F_HARDLINK", "REQ_F_HAS_METADATA"),
            "rw_kiocb_ki_flags": ("IOCB_DIRECT", "IOCB_NOWAIT", "IOCB_HIPRI"),
            "req_file_f_flags": ("O_NONBLOCK",),
            "req_file_f_op_fop_flags": ("FOP_BUFFER_WASYNC",),
        }
        for field, bits in groups.items():
            for bit in bits:
                with self.subTest(bit=bit):
                    self.assertFalse(permitted(dict(values, **{field: values[field] | values[bit]})))

    def test_ring_and_issue_masks_are_exhaustive(self):
        values = state()
        bits = ("IORING_SETUP_SINGLE_ISSUER", "IORING_SETUP_DEFER_TASKRUN",
                "IORING_SETUP_SQPOLL", "IORING_SETUP_IOPOLL",
                "IO_URING_F_INLINE", "IO_URING_F_NONBLOCK", "IO_URING_F_COMPLETE_DEFER",
                "IO_URING_F_UNLOCKED", "IO_URING_F_IOWQ")
        for selected in itertools.product((False, True), repeat=len(bits)):
            candidate = dict(values, ctx_flags=0, issue_flags=0)
            for name, enabled in zip(bits, selected):
                if enabled:
                    field = "ctx_flags" if name.startswith("IORING_SETUP") else "issue_flags"
                    candidate[field] |= values[name]
            expected = selected == (True, True, False, False, True, True, True, False, False)
            self.assertEqual(permitted(candidate), expected, selected)

    def test_blocking_region_owns_no_ring_mutex_and_relocks_on_early_error(self):
        write = function(RW, "io_write")
        unlocked, rest = write.split("mutex_unlock(&req->ctx->uring_lock);", 1)[1].split(
            "mutex_lock(&req->ctx->uring_lock);", 1)
        self.assertNotRegex(unlocked, r"\breturn\b")
        self.assertIn("rw_verify_area(WRITE", unlocked)
        self.assertIn("io_kiocb_start_write(req, kiocb)", unlocked)
        self.assertIn("req->file->f_op->write_iter(kiocb, &io->iter)", unlocked)
        self.assertEqual(unlocked.count("goto out_relock;"), 2)
        self.assertLess(rest.index("trace_io_uring_write_in_task("), rest.index("kiocb_done("))
        self.assertRegex(write, r"out_relock:\s*if \(write_in_task\)\s*"
                         r"mutex_lock\(&req->ctx->uring_lock\);\s*return ret;")
        register = (KERNEL / "io_uring/register.c").read_text()
        self.assertIn("ctx->submitter_task && ctx->submitter_task != current", register)
        self.assertIn("current != ctx->submitter_task", PREDICATE)

    def test_short_write_and_completion_ownership_are_preserved(self):
        write = function(RW, "io_write")
        for text in ("io->bytes_done += ret2;", "iov_iter_save_state(&io->iter, &io->iter_state);",
                     "io_req_end_write(req);", "return kiocb_done(req, ret2, NULL, issue_flags);"):
            self.assertIn(text, write)
        done = function(RW, "kiocb_done")
        self.assertIn("io_req_rw_cleanup(req, issue_flags);", done)
        self.assertIn("return IOU_COMPLETE;", done)
        self.assertIn("io_rw_done(req, ret);", done)
        queue = (KERNEL / "io_uring/io_uring.c").read_text()
        self.assertRegex(queue, r"if \(issue_flags & IO_URING_F_COMPLETE_DEFER\)\s*"
                         r"io_req_complete_defer\(req\);")

    def test_opt_in_is_limited_to_writeback_source_buffers(self):
        setup = function(FUSE, "fuse_uring_set_up_zero_copy")
        self.assertIn("in->write_flags & FUSE_WRITE_CACHE", setup)
        self.assertIn("req->args->in_args[0].size >= sizeof(*in)", setup)
        self.assertEqual(setup.count("IO_BUF_WRITE_IN_TASK"), 1)
        self.assertIn("imu->write_in_task = false;", RSRC)
        self.assertEqual(RSRC.count("imu->write_in_task = false;"), 2)
        self.assertIn("imu->dir = dir & (IO_BUF_DEST | IO_BUF_SOURCE);", RSRC)

    def test_negotiation_falls_back_only_before_any_lower_write(self):
        setup = function(LIB, "fuse_uring_setup_zero_copy_queue")
        self.assertIn("res == -EINVAL || res == -EOPNOTSUPP", setup)
        self.assertEqual(setup.count("FUSE_IO_URING_CMD_ADD_QUEUE)"), 2)
        self.assertNotIn("fuse_uring_submit_fixed_io", setup)
        self.assertLess(setup.index("queue->write_in_task = false;"),
                        setup.index("FUSE_IO_URING_CMD_ADD_BUFPOOL"))
        self.assertIn("requested=%u negotiated=%u", setup)
        add = function(FUSE, "fuse_uring_add_queue")
        self.assertLess(add.index("flags & ~FUSE_URING_ADD_QUEUE_FLAGS"),
                        add.index("fuse_uring_create(fc)"))
        self.assertIn("(flags & FUSE_URING_WRITE_IN_TASK) && !zero_copy", add)

    def test_wire_header_and_flag_layout_match(self):
        kernel = (KERNEL / "include/uapi/linux/fuse.h").read_bytes()
        self.assertEqual(kernel, (ROOT / "include/fuse_kernel.h").read_bytes())
        self.assertIn(b"#define FUSE_URING_WRITE_IN_TASK\t\t(1 << 1)", kernel)


if __name__ == "__main__":
    unittest.main(verbosity=2)
