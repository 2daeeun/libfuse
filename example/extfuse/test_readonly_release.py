#!/usr/bin/env python3
"""Check when native read-only close may request a guarded attribute snapshot."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "extfuse_coherence.h"
typedef uint64_t fuse_ino_t;
typedef int pthread_mutex_t;
struct attr_key { fuse_ino_t nodeid; };
struct attr_value { uint64_t native_state; unsigned stale; };
#define EXTFUSE_ATTR_MAP 1
static struct { bool passthrough_coherence_v2_requested, cache_bypass;
 pthread_mutex_t backing_mutex; void *bpf; } perf_state = {true, false, 0, NULL};
static bool locked, suppressed, state_error, disabled;
static int lookup_error, lookups;
static uint64_t native;
static struct attr_value row;
static void pthread_mutex_lock(pthread_mutex_t *m) { (void)m; assert(!locked); locked = true; }
static void pthread_mutex_unlock(pthread_mutex_t *m) { (void)m; assert(locked); locked = false; }
static bool attr_cache_suppressed_locked(fuse_ino_t ino, bool *mmap) {
 assert(ino == 1 && locked); *mmap = suppressed; return suppressed;
}
static bool native_state_snapshot_locked(fuse_ino_t ino, uint64_t *state,
 const char *reason, bool xattr) {
 (void)reason; assert(ino == 1 && locked && !xattr); *state = native;
 return !state_error;
}
static int ebpf_data_lookup(void *bpf, struct attr_key *key, struct attr_value *value, int map) {
 (void)bpf; assert(locked && key->nodeid == 1 && map == EXTFUSE_ATTR_MAP);
 lookups++; *value = row; errno = lookup_error; return lookup_error ? -1 : 0;
}
static void disable_metadata_cache_locked(const char *reason) {
 (void)reason; assert(locked); disabled = true;
}
/* PRODUCTION */
int main(int argc, char **argv) {
 assert(argc == 2); const char *name = argv[1]; bool expected = false;
 if (!strcmp(name, "stale-atime")) { row.stale = 1; expected = true; }
 if (!strcmp(name, "read-completed")) { native = 2 * EXTFUSE_NATIVE_STATE_SEQUENCE_ONE; expected = true; }
 if (!strcmp(name, "missing-seed")) { lookup_error = ENOENT; expected = true; }
 if (!strcmp(name, "active-read")) native = EXTFUSE_NATIVE_STATE_SEQUENCE_ONE | 1;
 if (!strcmp(name, "mmap")) { suppressed = true; row.stale = 1; }
 if (!strcmp(name, "state-error")) state_error = true;
 if (!strcmp(name, "lookup-error")) lookup_error = EIO;
 if (!strcmp(name, "bypass")) perf_state.cache_bypass = true;
 if (!strcmp(name, "legacy")) perf_state.passthrough_coherence_v2_requested = false;
 assert(native_readonly_attr_needs_refresh(1) == expected);
 assert(!locked && disabled == (lookup_error == EIO));
 if (suppressed || state_error || perf_state.cache_bypass ||
     !perf_state.passthrough_coherence_v2_requested ||
     (native & EXTFUSE_NATIVE_STATE_ACTIVE_MASK)) assert(!lookups);
 return 0;
}
'''


class ReadonlyReleaseTests(unittest.TestCase):
    def test_native_close_refreshes_only_idle_stale_or_missing_attributes(self):
        source = (ROOT / "extfuse_passthrough.c").read_text()
        start = source.index("static bool native_readonly_attr_needs_refresh(")
        end = source.index("__attribute__((noinline, used))", start)
        with tempfile.TemporaryDirectory(prefix="extfuse-readonly-release-") as tmp:
            cfile = Path(tmp) / "release.c"
            cfile.write_text(HARNESS.replace("/* PRODUCTION */", source[start:end]))
            binary = cfile.with_suffix("")
            subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
                "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                "-I" + str(ROOT / "include"), str(cfile), "-o", str(binary)], check=True)
            for name in ("current", "stale-atime", "read-completed", "missing-seed",
                         "active-read", "mmap", "state-error", "lookup-error", "bypass", "legacy"):
                with self.subTest(name=name):
                    subprocess.run([str(binary), name], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
