#!/usr/bin/env python3
"""Compile and exercise the production stale-mark helper without loading BPF."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SOURCE = Path(os.environ.get(
    "EXTFUSE_STALE_MARK_SOURCE",
    Path(__file__).resolve().parent / "bpf" / "extfuse.c",
))

HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint32_t __u32;
typedef struct { uint64_t nodeid; } lookup_attr_key_t;
/* Atomic reads make the userspace concurrency test well-defined in C. */
typedef struct { _Atomic __u32 stale; } lookup_attr_val_t;
static lookup_attr_val_t row;
static _Atomic unsigned int updates;
static __u32 concurrent_bits;
static int attr_map, key_error, missing;
#define IN_PARAM_0_VALUE 0
#define RETURN 0

static int gen_attr_key(void *ctx, int param, const char *op,
                        lookup_attr_key_t *key)
{
    (void)ctx;
    (void)param;
    (void)op;
    key->nodeid = 17;
    return key_error ? -EIO : 0;
}

static lookup_attr_val_t *bpf_map_lookup_elem(int *map,
                                             lookup_attr_key_t *key)
{
    assert(map == &attr_map && key->nodeid == 17);
    return missing ? NULL : &row;
}

static __u32 counted_or(_Atomic __u32 *value, __u32 mask)
{
    /* Inject another writer after the helper's read, before its atomic OR. */
    if (concurrent_bits)
        atomic_fetch_or(value, concurrent_bits);
    atomic_fetch_add(&updates, 1);
    return atomic_fetch_or(value, mask);
}
#define __sync_fetch_and_or(value, mask) counted_or((value), (mask))

@PRODUCTION_HELPER@

static void *mark_worker(void *arg)
{
    __u32 mask = 1U << (uintptr_t)arg;

    for (unsigned int i = 0; i < 1000; i++)
        assert(mark_passthrough_attr_stale(NULL, mask) == RETURN);
    return NULL;
}

int main(int argc, char **argv)
{
    int result;

    assert(argc == 7);
    atomic_init(&row.stale, strtoul(argv[1], NULL, 0));
    __u32 mask = strtoul(argv[2], NULL, 0);
    concurrent_bits = strtoul(argv[3], NULL, 0);
    key_error = atoi(argv[4]);
    missing = atoi(argv[5]);
    if (atoi(argv[6])) {
        pthread_t workers[32];

        for (uintptr_t i = 0; i < 32; i++)
            assert(!pthread_create(&workers[i], NULL, mark_worker, (void *)i));
        for (unsigned int i = 0; i < 32; i++)
            assert(!pthread_join(workers[i], NULL));
        result = RETURN;
    } else {
        result = mark_passthrough_attr_stale(NULL, mask);
    }
    printf("%d %u %u\n", result, atomic_load(&row.stale),
           atomic_load(&updates));
    return 0;
}
"""


class StaleMarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("static int mark_passthrough_attr_stale(")
        end = source.index("\nstatic int transition_native_state(", start)
        helper = source[start:end]
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-stale-")
        cls.addClassCleanup(cls.directory.cleanup)
        path = Path(cls.directory.name)
        harness = path / "stale.c"
        harness.write_text(HARNESS.replace("@PRODUCTION_HELPER@", helper))
        cls.binary = path / "stale"
        subprocess.run([
            *shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-O2",
            "-Wall", "-Wextra", "-Werror", "-pthread", str(harness),
            "-o", str(cls.binary),
        ], check=True)

    def run_helper(self, initial, mask, concurrent=0, key_error=0,
                   missing=0, threaded=0):
        output = subprocess.check_output([
            str(self.binary), str(initial), str(mask), str(concurrent),
            str(key_error), str(missing), str(threaded),
        ], text=True)
        return tuple(map(int, output.split()))

    def test_already_marked_row_avoids_atomic_write(self):
        self.assertEqual(self.run_helper(0x0f, 0x07), (0, 0x0f, 0))

    def test_unmarked_row_sets_every_requested_bit(self):
        self.assertEqual(self.run_helper(0, 0x07), (0, 0x07, 1))

    def test_partial_mask_preserves_unrelated_bits(self):
        self.assertEqual(self.run_helper(0x81, 0x07), (0, 0x87, 1))

    def test_concurrent_bit_add_is_not_lost(self):
        self.assertEqual(self.run_helper(0x01, 0x07, concurrent=0x80),
                         (0, 0x87, 1))

    def test_zero_mask_avoids_atomic_write(self):
        self.assertEqual(self.run_helper(0x80, 0), (0, 0x80, 0))

    def test_missing_attr_keeps_forwarding_eligible(self):
        self.assertEqual(self.run_helper(0x80, 0x07, missing=1),
                         (0, 0x80, 0))

    def test_invalid_key_still_fails(self):
        self.assertEqual(self.run_helper(0x80, 0x07, key_error=1),
                         (-5, 0x80, 0))

    def test_parallel_writers_preserve_all_bits(self):
        self.assertEqual(self.run_helper(0, 0, threaded=1),
                         (0, 0xffffffff, 32))


if __name__ == "__main__":
    unittest.main()
