#!/usr/bin/env python3
"""Check the kernel small-map update path without loading BPF or building Linux."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


LINUX = Path(os.environ.get("EXTFUSE_KERNEL_SOURCE",
                           Path(__file__).resolve().parents[3] / "linux"))


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if not depth:
            return source[start:end + 1]
    raise AssertionError("unterminated function: " + signature)


HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct { void *ptr; bool is_kernel; } bpfptr_t;
struct file { int unused; };
struct bpf_map {
    unsigned map_type, key_size, value_size;
    void *record;
    bool offloaded;
};
union bpf_attr {
    struct { unsigned map_fd; u64 key, value, flags; };
};
#define noinline __attribute__((noinline))
#define __aligned(n) __attribute__((aligned(n)))
#define ALIGN(x, n) (((x) + (n) - 1) & ~((__typeof__(x))(n) - 1))
#define ERR_PTR(err) ((void *)(intptr_t)(err))
#define PTR_ERR(ptr) ((int)(intptr_t)(ptr))
#define IS_ERR(ptr) ((uintptr_t)(ptr) >= (uintptr_t)-4095)
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_LRU_HASH 9
#define FMODE_CAN_WRITE 2
#define CHECK_ATTR(cmd) invalid_attr
#define CLASS(type, name) int name __attribute__((cleanup(put_fd))) = get_fd

static struct file map_file;
static struct bpf_map map = { .map_type = BPF_MAP_TYPE_HASH,
                             .key_size = 8, .value_size = 120 };
static union bpf_attr attr;
static unsigned char input_key[2048], input_value[2048], published[2048];
static bool invalid_attr, writable = true, kernel_pointer, bad_fd;
static unsigned open_fds, fd_gets, fd_puts, active, increments, decrements;
static unsigned allocations, frees, copies, updates, waits;
static unsigned fail_allocation, fail_copy;
static int flags_error, update_error;

static int get_fd(unsigned fd)
{ assert(fd == 17); fd_gets++; open_fds++; return (int)fd; }
static void put_fd(int *fd)
{ assert(*fd == 17 && open_fds == 1); open_fds--; fd_puts++; }
static struct file *fd_file(int fd)
{ assert(fd == 17 && open_fds == 1); return &map_file; }
static struct bpf_map *__bpf_map_get(int fd)
{ assert(fd == 17); return bad_fd ? ERR_PTR(-EBADF) : &map; }
static bpfptr_t make_bpfptr(u64 ptr, bool is_kernel)
{ return (bpfptr_t) { .ptr = (void *)(uintptr_t)ptr, .is_kernel = is_kernel }; }
static void bpf_map_write_active_inc(struct bpf_map *m)
{ assert(m == &map && !active); active++; increments++; }
static void bpf_map_write_active_dec(struct bpf_map *m)
{ assert(m == &map && active == 1); active--; decrements++; }
static unsigned map_get_sys_perms(struct bpf_map *m, int fd)
{ assert(m == &map && fd == 17 && active == 1); return writable ? FMODE_CAN_WRITE : 0; }
static int bpf_map_check_op_flags(struct bpf_map *m, u64 flags, u64 mask)
{ assert(m == &map && flags == attr.flags && mask == ~(u64)0); return flags_error; }
static bool bpf_map_is_offloaded(struct bpf_map *m)
{ assert(m == &map); return m->offloaded; }
static unsigned bpf_map_value_size(struct bpf_map *m)
{ return m->value_size * (m->map_type == BPF_MAP_TYPE_PERCPU_HASH ? 4 : 1); }
static int copy_from_bpfptr(void *dst, bpfptr_t src, unsigned size)
{
    assert(active == 1 && src.is_kernel == kernel_pointer);
    copies++;
    if (copies == fail_copy || (!src.ptr && size)) return 1;
    assert(size <= sizeof(input_value));
    if (size) memcpy(dst, src.ptr, size);
    return 0;
}
static void kvfree(void *ptr)
{ if (ptr) { assert(!IS_ERR(ptr)); frees++; free(ptr); } }
static void *kvmemdup_bpfptr(bpfptr_t src, unsigned size)
{
    void *ptr;
    allocations++;
    if (allocations == fail_allocation || size > sizeof(input_value))
        return ERR_PTR(-ENOMEM);
    ptr = malloc(size ? size : 1);
    assert(ptr);
    if (copy_from_bpfptr(ptr, src, size)) { kvfree(ptr); return ERR_PTR(-EFAULT); }
    return ptr;
}
static void *___bpf_copy_key(bpfptr_t key, unsigned size)
{
    if (size) return kvmemdup_bpfptr(key, size);
    return key.ptr ? ERR_PTR(-EINVAL) : NULL;
}
static int bpf_map_update_value(struct bpf_map *m, struct file *file,
                                void *key, void *value, u64 flags)
{
    unsigned size = bpf_map_value_size(m);
    assert(m == &map && file == &map_file && open_fds == 1 && active == 1);
    assert(flags == attr.flags && size <= sizeof(published));
    assert((uintptr_t)value % 8 == 0);
    if (map.key_size) assert(!memcmp(key, input_key, map.key_size));
    assert(!memcmp(value, input_value, size));
    updates++;
    if (!update_error) memcpy(published, value, size);
    return update_error;
}
static void maybe_wait_bpf_programs(struct bpf_map *m)
{ assert(m == &map && active == 1 && updates == 1); waits++; }

@PRODUCTION@

int main(int argc, char **argv)
{
    const char *name;
    bool fallback = false;
    int expected = 0;
    unsigned expected_updates = 1;
    assert(argc == 2); name = argv[1];
    for (size_t i = 0; i < sizeof(input_key); i++) {
        input_key[i] = (unsigned char)(i * 31 + 7);
        input_value[i] = (unsigned char)(i * 13 + 19);
    }
    if (!strcmp(name, "kernel-pointers")) kernel_pointer = true;
    if (!strcmp(name, "aligned-boundary")) map.value_size = 248;
    if (!strcmp(name, "unaligned-boundary")) { map.key_size = 1; map.value_size = 248; }
    if (!strcmp(name, "oversize")) { map.key_size = 1; map.value_size = 249; fallback = true; }
    if (!strcmp(name, "percpu")) { map.map_type = BPF_MAP_TYPE_PERCPU_HASH; fallback = true; }
    if (!strcmp(name, "lru")) { map.map_type = BPF_MAP_TYPE_LRU_HASH; fallback = true; }
    if (!strcmp(name, "offloaded")) { map.offloaded = true; fallback = true; }
    if (!strcmp(name, "btf-record")) { map.record = &map; fallback = true; }
    if (!strcmp(name, "empty-key")) { map.key_size = 0; fallback = true; }
    if (!strcmp(name, "empty-value")) { map.value_size = 0; fallback = true; }
    if (!strcmp(name, "huge-key")) {
        map.key_size = UINT32_MAX; fallback = true;
        expected = -ENOMEM; expected_updates = 0;
    }
    if (!strcmp(name, "invalid-attr")) {
        invalid_attr = true; expected = -EINVAL; expected_updates = 0;
    }
    if (!strcmp(name, "bad-fd")) { bad_fd = true; expected = -EBADF; expected_updates = 0; }
    if (!strcmp(name, "read-only")) { writable = false; expected = -EPERM; expected_updates = 0; }
    if (!strcmp(name, "bad-flags")) {
        expected = flags_error = -EINVAL; expected_updates = 0;
    }
    if (!strcmp(name, "bad-key") || !strcmp(name, "bad-value")) {
        fail_copy = !strcmp(name, "bad-key") ? 1 : 2;
        expected = -EFAULT; expected_updates = 0;
    }
    if (!strcmp(name, "fallback-key-oom") || !strcmp(name, "fallback-value-oom")) {
        map.record = &map; fallback = true;
        fail_allocation = !strcmp(name, "fallback-key-oom") ? 1 : 2;
        expected = -ENOMEM; expected_updates = 0;
    }
    if (!strcmp(name, "existing-key")) expected = update_error = -EEXIST;
    if (!strcmp(name, "missing-key")) expected = update_error = -ENOENT;
    if (!strcmp(name, "map-error")) expected = update_error = -EIO;
    attr = (union bpf_attr) { .map_fd = 17,
        .key = map.key_size ? (uintptr_t)input_key : 0,
        .value = (uintptr_t)input_value,
        .flags = !strcmp(name, "existing-key") ? 1 : 2 };
    assert(map_update_elem(&attr, make_bpfptr(0, kernel_pointer)) == expected);
    assert(!active && increments == decrements && !open_fds && fd_gets == fd_puts);
    assert(updates == expected_updates && waits == (expected == 0));
    if (invalid_attr || bad_fd || !writable || flags_error) {
        assert(!copies && !updates && !allocations);
        assert(increments == (!invalid_attr && !bad_fd));
    } else if (fallback) {
        assert(allocations > 0);
        assert(frees == allocations - (expected == -ENOMEM));
    } else {
        assert(!allocations && !frees && copies == (fail_copy ? fail_copy : 2));
    }
    if (!expected) assert(!memcmp(published, input_value, bpf_map_value_size(&map)));
    printf("PASS case=%s allocations=%u updates=%u error=%d\n",
           name, allocations, updates, expected);
    return 0;
}
"""


class SmallMapUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (LINUX / "kernel/bpf/syscall.c").read_text()
        limit = re.search(r"^#define BPF_MAP_UPDATE_STACK_SIZE \d+$", source, re.M)
        if not limit:
            raise AssertionError("missing small-map stack limit")
        production = "\n".join([
            limit.group(0),
            function(source, "static noinline int map_update_elem_small("),
            function(source, "static int map_update_elem(union bpf_attr *attr,"),
        ])
        cls.temporary = tempfile.TemporaryDirectory(prefix="extfuse-small-map-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        harness = directory / "map_update.c"
        harness.write_text(HARNESS.replace("@PRODUCTION@", production))
        cls.binary = directory / "map_update"
        command = [*shlex.split(os.environ.get("CC", "cc")), "-std=gnu11", "-O2",
                   "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)

    def cases(self, *names):
        for name in names:
            with self.subTest(case=name):
                result = subprocess.run([str(self.binary), name], capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_small_user_and_kernel_updates_need_no_temporary_allocation(self):
        self.cases("small", "kernel-pointers", "aligned-boundary", "unaligned-boundary")

    def test_ineligible_maps_keep_the_original_value_size_and_allocation_path(self):
        self.cases("oversize", "huge-key", "percpu", "lru", "offloaded", "btf-record",
                   "empty-key", "empty-value")

    def test_common_validation_precedes_access_to_input_buffers(self):
        self.cases("invalid-attr", "bad-fd", "read-only", "bad-flags")

    def test_copy_and_map_errors_do_not_publish_or_leak_write_access(self):
        self.cases("bad-key", "bad-value", "existing-key", "missing-key", "map-error")

    def test_fallback_allocation_errors_release_the_copied_key(self):
        self.cases("fallback-key-oom", "fallback-value-oom")


if __name__ == "__main__":
    unittest.main(verbosity=2)
