#!/usr/bin/env python3
"""Exercise production BPF WRITE/GETXATTR coherence with unprivileged maps."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
WBCACHE = 1 << 4
PROOF = 1 << 5
WRITE_FAST = 1 << 6
EPOCHS = 1 << 3
WRITE_STALE = (1 << 3) | (1 << 4) | (1 << 5) | (1 << 10)

HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <linux/limits.h>
#include <linux/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "extfuse_coherence.h"
#include "attr.h"
#include "xattr.h"

#define RETURN 0
#define UPCALL (-ENOSYS)
#define PASSTHRU 1
#define NODEID 0
#define IN_PARAM_0_VALUE 1
#define IN_PARAM_1_VALUE 2
#define OUT_PARAM_0 0
#define EXTFUSE_COHERENCE_VERSION 1
#define PRINTK(...)
#define HANDLER(op, number) int bpf_func_##op
struct extfuse_req { struct { __u32 version, target_count; } coherence; };
static int policy_map, attr_map, xattr_map, daemon_io_map, native_io_map, mmap_map;
static __u32 flags;
static lookup_attr_val_t attr;
static xattr_value_t capability;
static struct extfuse_io_state daemon_state, native_state;
static const char *xattr_name = "security.capability";
static struct fuse_getxattr_in incoming = {.size = 4};
static int marked;
static int missing_policy, missing_attr, missing_capability, key_error, delete_error;
static int revoke_at_attr;
static unsigned int policy_lookups, attr_lookups, xattr_lookups, deletes;
static void revoke_paper_capability_policy(void);

static long bpf_extfuse_read_args(void *ctx, __u32 type, void *dst, __u32 size)
{
    (void)ctx;
    if (key_error)
        return -EIO;
    if (type == NODEID) {
        assert(size == sizeof(__u64)); *(__u64 *)dst = 17;
    } else if (type == IN_PARAM_1_VALUE) {
        memset(dst, 0, size); assert(strlen(xattr_name) < size);
        memcpy(dst, xattr_name, strlen(xattr_name));
    } else {
        assert(type == IN_PARAM_0_VALUE && size == sizeof(incoming));
        memcpy(dst, &incoming, size);
    }
    return 0;
}

static long bpf_extfuse_write_args(void *ctx, __u32 type, const void *src, __u32 size)
{
    (void)ctx; assert(type == OUT_PARAM_0 && size == sizeof(struct fuse_getxattr_out));
    assert(((const struct fuse_getxattr_out *)src)->size == capability.size);
    return 0;
}
static long bpf_extfuse_write_args_var(void *ctx, __u32 type, const void *src, __u32 size)
{
    (void)ctx; assert(type == OUT_PARAM_0 && size == capability.size);
    assert(!size || !memcmp(src, capability.data, size)); return 0;
}

static void *bpf_map_lookup_elem(int *map, const void *key)
{
    if (map == &policy_map) {
        assert(*(__u32 *)key == 0);
        policy_lookups++;
        return missing_policy ? NULL : &flags;
    }
    if (map == &attr_map) {
        assert(((lookup_attr_key_t *)key)->nodeid == 17);
        attr_lookups++;
        if (revoke_at_attr) {
            /* SETXATTR revokes proof before publishing a new positive row. */
            revoke_paper_capability_policy();
            capability.error = 0;
            missing_capability = 0;
        }
        return missing_attr ? NULL : &attr;
    }
    if (map == &daemon_io_map || map == &native_io_map || map == &mmap_map) {
        assert(*(__u64 *)key == 17);
        if (map == &mmap_map) return marked ? &marked : NULL;
        return map == &daemon_io_map ? &daemon_state : &native_state;
    }
    assert(map == &xattr_map);
    assert(((xattr_key_t *)key)->nodeid == 17);
    assert(!strcmp(((xattr_key_t *)key)->name, xattr_name));
    xattr_lookups++;
    return missing_capability ? NULL : &capability;
}

static int bpf_map_delete_elem(int *map, const void *key)
{
    assert(map == &xattr_map && ((xattr_key_t *)key)->nodeid == 17);
    deletes++;
    if (delete_error)
        return -delete_error;
    missing_capability = 1;
    return 0;
}

@PRODUCTION@

int main(int argc, char **argv)
{
    struct extfuse_req request = {0};
    int result;

    assert(argc == 13);
    flags = strtoul(argv[2], NULL, 0);
    request.coherence.version = atoi(argv[3]);
    request.coherence.target_count = atoi(argv[4]);
    missing_policy = atoi(argv[5]);
    missing_attr = atoi(argv[6]);
    missing_capability = atoi(argv[7]);
    capability.error = atoi(argv[8]);
    capability.size = capability.error ? 0 : 4;
    delete_error = atoi(argv[9]);
    key_error = atoi(argv[10]);
    revoke_at_attr = atoi(argv[12]);
    if (atoi(argv[11]))
        revoke_paper_capability_policy();
    if (!strncmp(argv[1], "get", 3)) {
        if (strstr(argv[1], "user")) xattr_name = "user.fixture";
        if (strstr(argv[1], "daemon-active")) daemon_state.xattr_state = 1;
        if (strstr(argv[1], "daemon-token")) daemon_state.xattr_state = 65536;
        if (strstr(argv[1], "native-active")) native_state.xattr_state = 1;
        if (strstr(argv[1], "native-token")) native_state.xattr_state = 65536;
        if (strstr(argv[1], "marked")) marked = 1;
        if (strstr(argv[1], "size")) incoming.size = 0;
        if (strstr(argv[1], "small")) incoming.size = 2;
        if (strstr(argv[1], "empty")) capability.size = 0;
        if (strstr(argv[1], "malformed-negative")) capability.size = 1;
        result = bpf_func_FUSE_GETXATTR(&request);
    } else {
        result = !strcmp(argv[1], "read") ? bpf_func_FUSE_READ(&request) :
                                           bpf_func_FUSE_WRITE(&request);
        if (strstr(argv[1], "positive")) {
            assert(result == PASSTHRU);
            /* Model SETXATTR publication followed by lower killpriv after
             * the prehook. The BPF cache row still contains the old value. */
            revoke_paper_capability_policy();
            daemon_state.xattr_state += EXTFUSE_NATIVE_STATE_SEQUENCE_ONE;
            capability.daemon_state = daemon_state.xattr_state;
            capability.error = 0; capability.size = 4; missing_capability = 0;
            result = bpf_func_FUSE_GETXATTR(&request);
        }
    }
    printf("%d %u %u %u %u %u %u\n", result, attr.stale, policy_lookups,
           attr_lookups, xattr_lookups, deletes, flags);
    return 0;
}
"""


class WBCacheCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "bpf/extfuse.c").read_text()
        regions = (
            ("static int gen_attr_key(", "static void create_lookup_entry("),
            ("static int has_passthrough_mmap_marker(", "static int capability_name("),
            ("static void revoke_paper_capability_policy(", "static int daemon_domain_inactive("),
            ("static int daemon_domain_inactive(", "static int daemon_state_inactive("),
            ("static int daemon_cache_token_current(", "static int cache_tokens_current("),
            ("static int native_stable_negative_capability(", "HANDLER(FUSE_LOOKUP, 1)"),
            ("static int mark_passthrough_attr_stale(", "static int transition_native_state("),
            ("static int invalidate_positive_capability(", "static int passthrough_notification("),
            ("HANDLER(FUSE_READ, 15)", "HANDLER(FUSE_SETATTR, 4)"),
            ("HANDLER(FUSE_GETXATTR, 22)", "HANDLER(FUSE_SETXATTR, 21)"),
        )
        production = "\n".join(source[source.index(start):source.index(end, source.index(start))]
                               for start, end in regions)
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-wbcache-capability-")
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        path = root / "handlers.c"
        path.write_text(HARNESS.replace("@PRODUCTION@", production))
        cls.binary = root / "handlers"
        subprocess.run([
            *shlex.split(os.environ.get("CC", "cc")), "-std=c11", "-O2",
            "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "include"),
            "-I", str(ROOT / "bpf"), str(path), "-o", str(cls.binary),
        ], check=True, timeout=20)

    def run_handler(self, flags=WBCACHE, version=1, targets=0, missing_policy=0,
                    missing_attr=0, missing_capability=0, cap_error=0,
                    delete_error=0, key_error=0, revoke=0, operation="write",
                    revoke_at_attr=0):
        result = subprocess.run([
            str(self.binary), operation, *map(str, (flags, version, targets,
            missing_policy, missing_attr, missing_capability, cap_error,
            delete_error, key_error, revoke, revoke_at_attr)),
        ], check=True, capture_output=True, text=True, timeout=5)
        return tuple(map(int, result.stdout.split()))

    def test_paper_write_skips_capability_lookup_independently_of_absence_proof(self):
        for flags in (WBCACHE, WBCACHE | PROOF, WBCACHE | WRITE_FAST):
            for error, missing in ((0, 0), (61, 0), (0, 1)):
                with self.subTest(flags=flags, error=error, missing=missing):
                    row = self.run_handler(flags=flags, cap_error=error,
                                           missing_capability=missing)
                    self.assertEqual(row[:6], (1, WRITE_STALE, 1, 1, 0, 0))
        self.assertEqual(self.run_handler(missing_attr=1)[:6], (1, 0, 1, 1, 0, 0))

    def test_strict_positive_negative_and_absent_capability_paths(self):
        for error, missing, deletions in ((0, 0, 1), (61, 0, 0), (0, 1, 0)):
            with self.subTest(error=error, missing=missing):
                row = self.run_handler(flags=WBCACHE | EPOCHS, cap_error=error,
                                       missing_capability=missing)
                self.assertEqual(row[:6], (1, WRITE_STALE, 1, 1, 1, deletions))

    def test_revocation_and_post_hook_publication_cannot_resurrect_positive_hit(self):
        for revoke, middle in ((0, 0), (1, 0), (0, 1)):
            with self.subTest(revoke_before=revoke, revoke_during=middle):
                row = self.run_handler(flags=WBCACHE | PROOF, cap_error=61,
                                       revoke=revoke, revoke_at_attr=middle,
                                       operation="late-positive")
                self.assertEqual(row[0], -38)
                self.assertEqual(row[1], WRITE_STALE)
                self.assertEqual(row[4:7], (1, 0, WBCACHE))

    def test_missing_policy_and_invalidation_failures_keep_fallbacks(self):
        row = self.run_handler(flags=WBCACHE | PROOF, missing_policy=1)
        self.assertEqual(row[:6], (-38, WRITE_STALE & ~(1 << 10), 2, 1, 1, 1))
        row = self.run_handler(flags=WBCACHE | EPOCHS, delete_error=5)
        self.assertEqual(row[:6], (-38, WRITE_STALE, 1, 1, 1, 1))
        row = self.run_handler(flags=WBCACHE | EPOCHS, delete_error=2)
        self.assertEqual(row[0], 1)  # Concurrent deletion's ENOENT is harmless.
        for flags in (WBCACHE, WBCACHE | PROOF):
            row = self.run_handler(flags=flags, key_error=1)
            self.assertEqual(row[:6], (-38, 0, 1, 0, 0, 0))

    def test_strict_and_legacy_write_branches_keep_their_original_work(self):
        for flags in (WBCACHE, WBCACHE | PROOF):
            self.assertEqual(self.run_handler(flags=flags, targets=1)[:6],
                             (1, 0, 1, 0, 0, 0))
        for flags, lookups in ((PROOF, 1), (PROOF | WRITE_FAST, 0)):
            row = self.run_handler(flags=flags, version=0)
            self.assertEqual(row[:6], (-38, WRITE_STALE & ~(1 << 10), 1, 1, lookups, lookups))

    def test_read_invalidation_is_independent_of_capability_proof(self):
        for flags in (WBCACHE, WBCACHE | PROOF):
            self.assertEqual(self.run_handler(flags=flags, operation="read")[:6],
                             (1, 1 << 4, 1, 1, 0, 0))
            self.assertEqual(self.run_handler(flags=flags, targets=1, operation="read")[:6],
                             (1, 0, 1, 0, 0, 0))
            self.assertEqual(self.run_handler(flags=flags, version=0, operation="read")[:6],
                             (-38, 1 << 4, 0, 1, 0, 0))

    def test_positive_capability_always_uses_daemon_only_in_paper_mode(self):
        for operation in ("getcap", "getcap-size", "getcap-empty", "getcap-small"):
            with self.subTest(operation=operation):
                self.assertEqual(self.run_handler(operation=operation)[0], -38)
                for flags in (0, WBCACHE | EPOCHS):
                    expected = -34 if operation.endswith("small") else 0
                    self.assertEqual(self.run_handler(flags=flags, operation=operation)[0], expected)
        self.assertEqual(self.run_handler(operation="getcap", cap_error=5)[0], -38)
        for flags in (0, WBCACHE, WBCACHE | EPOCHS):
            self.assertEqual(self.run_handler(flags=flags, operation="getuser")[0], 0)
            self.assertEqual(self.run_handler(flags=flags, operation="getuser-small")[0], -34)

    def test_negative_capability_preserves_proof_and_exact_daemon_token_checks(self):
        proof = self.run_handler(flags=WBCACHE | PROOF, cap_error=61, operation="getcap")
        self.assertEqual(proof[0], -61)
        self.assertEqual(proof[4], 0)
        for operation in ("getcap", "getcap-native-active", "getcap-native-token"):
            self.assertEqual(self.run_handler(cap_error=61, operation=operation)[0], -61)
        for operation in ("getcap-daemon-active", "getcap-daemon-token", "getcap-marked",
                          "getcap-malformed-negative"):
            self.assertEqual(self.run_handler(cap_error=61, operation=operation)[0], -38)
        for operation in ("getuser-native-active", "getuser-native-token",
                          "getuser-daemon-active", "getuser-daemon-token"):
            self.assertEqual(self.run_handler(cap_error=61, operation=operation)[0], -38)


if __name__ == "__main__":
    unittest.main(verbosity=2)
