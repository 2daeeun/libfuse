#!/usr/bin/env python3
"""Source/model checks only: no BPF load, build, mount, or lower I/O."""

import ctypes
import itertools
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent
DAEMON = (ROOT / "extfuse_passthrough.c").read_text()
BPF = (ROOT / "bpf/extfuse.c").read_text()
HEADER = (ROOT / "include/extfuse_coherence.h").read_text()
ACTIVE_BITS = int(re.search(
    r"#define EXTFUSE_NATIVE_STATE_ACTIVE_BITS (\d+)U", HEADER
).group(1))
ONE = 1 << ACTIVE_BITS
ACTIVE_MASK = ONE - 1


def structure(source, name):
    return re.search(r"struct " + name + r" \{(.*?)\n\};", source, re.S).group(1)


def domain_transition(state, begin, write=False):
    """Model the two independently packed domains, not kernel execution."""
    delta = ONE + 1 if begin else ONE - 1
    return (state[0] + delta, state[1] + delta if write else state[1])


def current(state, token, domain):
    return not (state[domain] & ACTIVE_MASK) and state[domain] == token


def publish_equivalent(published, state):
    return all(old == new or (old & ACTIVE_MASK and new & ACTIVE_MASK)
               for old, new in zip(published, state))


def cache_bucket(ino):
    value = ino ^ (ino >> 33)
    value = (value * 0xff51afd7ed558ccd) & ((1 << 64) - 1)
    value ^= value >> 33
    return value & (4096 - 1)


class CacheContractTests(unittest.TestCase):
    def test_map_and_cached_xattr_layout(self):
        class IoState(ctypes.Structure):
            _fields_ = [("attr_state", ctypes.c_uint64),
                        ("xattr_state", ctypes.c_uint64)]

        class XattrValue(ctypes.Structure):
            _fields_ = [("error", ctypes.c_int32), ("size", ctypes.c_uint32),
                        ("native_state", ctypes.c_uint64),
                        ("daemon_state", ctypes.c_uint64),
                        ("data", ctypes.c_uint8 * 256)]

        self.assertEqual(structure(HEADER, "extfuse_io_state").split(),
                         ["__u64", "attr_state;", "__u64", "xattr_state;"])
        self.assertEqual(structure(DAEMON, "xattr_value").split(), [
            "int32_t", "error;", "uint32_t", "size;", "uint64_t",
            "native_state;", "uint64_t", "daemon_state;", "uint8_t",
            "data[256];",
        ])
        self.assertEqual(ctypes.sizeof(IoState), 16)
        self.assertEqual(ctypes.sizeof(XattrValue), 280)
        self.assertEqual(XattrValue.native_state.offset, 8)
        self.assertEqual(XattrValue.daemon_state.offset, 16)
        self.assertEqual(BPF.count("__type(value, struct extfuse_io_state);"), 2)
        self.assertIn('sizeof(struct attr_value) == 128', DAEMON)
        self.assertIn('sizeof(struct xattr_value) == 280', DAEMON)

    def test_read_does_not_invalidate_xattr(self):
        for workers in (1, 32, 64, 128):
            state = (0, 0)
            for _ in range(workers):
                state = domain_transition(state, True)
                self.assertFalse(current(state, 0, 0))
                self.assertTrue(current(state, 0, 1))
            for _ in range(workers):
                state = domain_transition(state, False)
                self.assertTrue(current(state, 0, 1))
            self.assertEqual(state, (2 * workers * ONE, 0))
            self.assertFalse(current(state, 0, 0))
            self.assertTrue(current(state, state[0], 0))

    def test_read_write_interleavings(self):
        # All valid orders for one READ and one WRITE BEGIN/END pair.
        for order in itertools.permutations(("rb", "re", "wb", "we")):
            if order.index("rb") > order.index("re"):
                continue
            if order.index("wb") > order.index("we"):
                continue
            state = (0, 0)
            for operation in order:
                state = domain_transition(
                    state, operation[1] == "b", operation[0] == "w"
                )
                self.assertFalse(current(state, 0, 0))
                if operation == "wb":
                    self.assertFalse(current(state, state[1], 1))
            self.assertEqual(state, (4 * ONE, 2 * ONE))
            self.assertFalse(current(state, 0, 1))
            self.assertTrue(current(state, state[1], 1))

    def test_source_selects_matching_domains(self):
        for token in (
            "delta = EXTFUSE_NATIVE_STATE_SEQUENCE_ONE + 1;",
            "delta = EXTFUSE_NATIVE_STATE_SEQUENCE_ONE - 1;",
            "transition_native_state(&state->attr_state, phase)",
            "if (!ret && write)",
            "transition_native_state(&state->xattr_state, phase)",
            "daemon_cache_token_current(key.nodeid, value->daemon_state, 1)",
            "native_cache_token_current(key.nodeid, value->native_state, 1)",
            "return passthrough_notification(ctx, FATTR_ATIME, 0);",
        ):
            self.assertIn(token, BPF)
        self.assertIn("cache_snapshot_begin_domain(ino, &snapshot, true)", DAEMON)
        self.assertIn("snapshot->xattr", DAEMON)
        self.assertNotIn("PAPER_READ_ATIME_CACHE", DAEMON + BPF)

    def test_write_xattr_refill_does_not_wait_for_read(self):
        state = domain_transition((0, 0), True)  # READ still in progress.
        state = domain_transition(state, True, True)
        state = domain_transition(state, False, True)  # WRITE completed.
        self.assertFalse(current(state, state[0], 0))
        self.assertTrue(current(state, state[1], 1))
        self.assertEqual(DAEMON.count(
            "if (context->mutation.xattr_quiescent &&"
        ), 2)
        self.assertIn("result >= 0 && mutation.xattr_quiescent &&", DAEMON)
        self.assertIn("mutation->xattr_quiescent = xattr_quiescent && "
                      "!invalid_state &&", DAEMON)

    def test_read_publication_before_reply(self):
        read = DAEMON.split("void perf_read(fuse_req_t req", 2)[2]
        read = read.split("void perf_write_buf(", 1)[0]
        self.assertIn(".mutation.attr_only = true", read)
        self.assertNotIn("invalidate_attr(", read)
        self.assertIn("context.inode = lo_inode(req, ino);", read)
        self.assertIn("FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK", read)
        self.assertIn("buf.buf[0].fd = fi->fh;", read)
        self.assertIn("buf.buf[0].pos = offset;", read)
        self.assertRegex(read, r"fuse_reply_data_with_prepare\(.*?"
                         r"FUSE_BUF_SPLICE_MOVE,\s*perf_read_prepare, &context\);"
                         r"\s*\}")
        prepare = DAEMON.split("static void perf_read_prepare(", 1)[1]
        prepare = prepare.split("__attribute__((noinline, used))", 1)[0]
        self.assertIn("cache_mutation_end_with_snapshot(&context->mutation, &snapshot)",
                      prepare)
        self.assertNotIn("cache_snapshot_begin(", prepare)
        self.assertLess(prepare.index("cache_mutation_end_with_snapshot("),
                        prepare.index("extfuse_snapshot_pinned_inode("))
        self.assertLess(prepare.index("extfuse_snapshot_pinned_inode("),
                        prepare.index("cache_attr("))
        self.assertNotIn("fuse_reply_", prepare)
        self.assertIn("errno = saved_errno;", prepare)

    def test_read_snapshot_reuses_end_lock_and_revalidates(self):
        end = DAEMON.split("static bool cache_mutation_end_with_snapshot(", 1)[1]
        end = end.split("static bool cache_mutation_end(", 1)[0]
        self.assertEqual(end.count("cache_mutation_lock(mutation, &locks)"), 1)
        self.assertEqual(end.count("cache_mutation_unlock(&locks)"), 1)
        self.assertNotIn("backing_mutex", end)
        self.assertIn("snapshot && quiescent && !invalid_state", end)
        self.assertIn("!mutation->attr_only || mutation->count != 1", end)
        self.assertIn("EXTFUSE_NATIVE_STATE_ACTIVE_MASK", end)
        self.assertNotIn("extfuse_snapshot_pinned_inode(", end)
        self.assertIn("cache_mutation_end_with_snapshot(mutation, NULL)", DAEMON)
        # A reader or writer which starts during the unlocked lower snapshot
        # must still invalidate the captured identity before cache publication.
        for workers in (1, 32, 64, 128):
            state = (0, 0)
            for _ in range(workers):
                state = domain_transition(state, True)
            for _ in range(workers):
                state = domain_transition(state, False)
            token = state[0]
            self.assertTrue(current(state, token, 0))
            for write in (False, True):
                raced = domain_transition(state, True, write)
                self.assertFalse(current(raced, token, 0))
                raced = domain_transition(raced, False, write)
                self.assertFalse(current(raced, token, 0))
        self.assertIn("stable = cache_snapshot_stable_locked(nodeid, snapshot)",
                      DAEMON)

    def test_active_cohort_publication_preserves_bpf_decisions(self):
        # Exhaust all valid interleavings of two readers and two writers.
        # The optimized map need not report the exact active count, but must
        # make the same cache-hit decision for EVERY previously seen token.
        checked = 0
        for order in itertools.permutations(range(8)):
            if any(order.index(i) > order.index(i + 1)
                   for i in range(0, 8, 2)):
                continue
            state = published = (0, 0)
            seen = [{0}, {0}]
            for event in order:
                state = domain_transition(state, event % 2 == 0, event >= 4)
                if not publish_equivalent(published, state):
                    published = state
                for domain in (0, 1):
                    seen[domain].update((state[domain], published[domain]))
                    for token in seen[domain]:
                        self.assertEqual(current(state, token, domain),
                                         current(published, token, domain))
            self.assertEqual(published, state)
            checked += 1
        self.assertEqual(checked, 2520)

    def test_overlapping_io_only_coalesces_active_states(self):
        for workers in (1, 32, 64, 128):
            for write in (False, True):
                state = published = (0, 0)
                updates = 0
                for begin in (True, False):
                    for _ in range(workers):
                        state = domain_transition(state, begin, write)
                        if not publish_equivalent(published, state):
                            published = state
                            updates += 1
                self.assertEqual(updates, 2)
                self.assertEqual(published, state)
                self.assertEqual(state[0], workers * 2 * ONE)
        # An invalidation while inactive cannot be hidden as a cohort update.
        self.assertFalse(publish_equivalent((2 * ONE, 0), (3 * ONE, ONE)))

    def test_publication_requires_a_successful_first_map_update(self):
        publish = DAEMON.split("static bool publish_inode_generation_locked(", 1)[1]
        publish = publish.split("static bool native_state_snapshot_locked(", 1)[0]
        self.assertIn("perf_state.mode == PERF_MODE_HIT && state->published_valid", publish)
        self.assertIn("daemon_domain_equivalent(state->published.attr_state, attr_state)", publish)
        self.assertIn("daemon_domain_equivalent(state->published.xattr_state, xattr_state)", publish)
        self.assertRegex(publish, r"if \(!ebpf_data_update\([^;]+\) \{\s*"
                         r"state->published = value;\s*"
                         r"state->published_valid = true;\s*return true;")
        self.assertIn('disable_all_caches_locked(reason);', publish)
        # Missing/active maps still fail closed in the unchanged BPF handlers.
        self.assertIn("if (current & EXTFUSE_NATIVE_STATE_ACTIVE_MASK)", BPF)
        self.assertNotRegex(BPF, r"bpf_map_(?:update|delete)_elem\(&daemon_io_map")

    def test_inode_lock_order_and_hash_collisions(self):
        for workers in (1, 32, 64, 128):
            buckets = [cache_bucket(0x100000 + i * 128) for i in range(workers)]
            self.assertEqual(len(set(buckets)), workers)
        # Model insertion sort/dedup used by cache_mutation_lock, including
        # opposite rename directions, the same inode and stripe collisions.
        for inputs in itertools.product((0, 1, 7, 4095), repeat=4):
            buckets = []
            for bucket in inputs:
                pos = 0
                while pos < len(buckets) and buckets[pos] < bucket:
                    pos += 1
                if pos < len(buckets) and buckets[pos] == bucket:
                    continue
                buckets.insert(pos, bucket)
            self.assertEqual(buckets, sorted(set(inputs)))
        lock = DAEMON.split("static void cache_mutation_lock(", 1)[1]
        lock = lock.split("static void cache_mutation_unlock(", 1)[0]
        self.assertIn("locks->buckets[pos] < bucket", lock)
        self.assertIn("locks->buckets[pos] == bucket", lock)
        self.assertIn("perf_state.mode != PERF_MODE_HIT", lock)
        self.assertIn("pthread_mutex_lock(&perf_state.backing_mutex)", lock)
        self.assertIn("generation hash chains must belong to exactly one cache lock", DAEMON)
        self.assertIn("bucket & (PERF_CACHE_LOCK_BUCKETS - 1)", DAEMON)

    def test_cold_and_hot_operations_use_the_same_inode_lock(self):
        for name, next_name, argument in (
            ("cache_snapshot_begin_domain", "cache_snapshot_begin", "ino"),
            ("cache_attr", "cache_entry", "nodeid"),
            ("cache_xattr_reply_serialized", "negative_capability_cache_current_serialized", "nodeid"),
            ("negative_capability_cache_current_serialized", "refresh_negative_capability_serialized", "nodeid"),
            ("refresh_negative_capability_serialized", "invalidate_xattr_locked", "nodeid"),
        ):
            section = DAEMON.split(name + "(", 1)[1].split(next_name + "(", 1)[0]
            self.assertIn(f"cache_lock_for_inode({argument})", section, name)
            self.assertIn("pthread_mutex_lock(lock)", section, name)
            self.assertIn("pthread_mutex_unlock(lock)", section, name)
        for name, next_name in (("cache_entry", "cache_negative_entry"),
                                ("invalidate_attr_locked", "invalidate_attr")):
            section = DAEMON.split(name + "(", 1)[1].split(next_name + "(", 1)[0]
            self.assertIn("cache_lock_for_inode(", section, name)
            self.assertIn("lock != &perf_state.backing_mutex", section, name)
            self.assertIn("pthread_mutex_lock(lock)", section, name)
            self.assertIn("pthread_mutex_unlock(lock)", section, name)

    def test_cross_inode_failures_are_serialized_and_fail_closed(self):
        self.assertIn("atomic_bool cache_bypass;", DAEMON)
        self.assertIn("atomic_bool xattr_cache_bypass;", DAEMON)
        for name, flag in (("disable_metadata_cache_locked", "cache_bypass"),
                           ("disable_xattr_cache_locked", "xattr_cache_bypass")):
            # Skip the forward declaration.
            section = DAEMON.split(f"static int {name}(const char *reason)\n{{", 1)[1]
            section = section.split("\n}\n", 1)[0]
            self.assertIn("pthread_mutex_lock(&perf_state.cache_disable_mutex)", section)
            self.assertIn("pthread_mutex_unlock(&perf_state.cache_disable_mutex)", section)
            self.assertLess(section.index("ebpf_ctrl_delete("),
                            section.index(f"perf_state.{flag} = true;"))
            self.assertIn("cache_bypass_errors", section)
            self.assertIn("fuse_session_exit(perf_state.session)", section)

    def test_partial_commit_cannot_replace_writeback_fields(self):
        partial = BPF.split("if (mask) {", 1)[1].split("} else {", 1)[0]
        self.assertIn("replacement.stale != FATTR_ATIME", partial)
        self.assertIn("replacement.daemon_state != cookie.daemon_state", partial)
        self.assertIn("replacement.out.attr.atime = fresh_attr.atime;", partial)
        self.assertNotIn("replacement.out.attr =", partial)
        self.assertNotIn("replacement.out.attr.size", partial)
        self.assertNotIn("replacement.out.attr.mtime", partial)


class UringAffinityModelTests(unittest.TestCase):
    """Topology/source checks; the C test still requires a separate build."""

    @staticmethod
    def select(qid, allowed, local, cores):
        cpus = sorted(set(allowed) & set(local))
        if (qid not in cpus or any(cpu not in cores or cores[cpu] < 0
                                   for cpu in cpus)):
            return None  # The C helper invokes its unchanged legacy policy.
        for stride in range(1, len(cpus)):
            if all(cores[cpu] != cores[cpus[(i + stride) % len(cpus)]]
                   for i, cpu in enumerate(cpus)):
                return cpus[(cpus.index(qid) + stride) % len(cpus)]
        return None

    def test_distinct_core_bijection_across_topologies(self):
        for count in (4, 20, 32, 64, 128):
            for layout in ("adjacent-smt", "split-smt", "hybrid", "no-smt"):
                cores = {cpu: (cpu // 2 if layout == "adjacent-smt" else
                               cpu % (count // 2) if layout == "split-smt" else
                               cpu // 2 if layout == "hybrid" and cpu < 12 else
                               cpu) for cpu in range(count)}
                targets = [self.select(cpu, range(count), range(count), cores)
                           for cpu in range(count)]
                self.assertEqual(set(targets), set(range(count)))
                for cpu, target in enumerate(targets):
                    self.assertNotEqual(cores[cpu], cores[target])

    def test_numa_sparse_masks_and_legacy_cases(self):
        cores = {0: 0, 1: 0, 4: 4, 5: 4, 8: 8, 9: 8}
        allowed = set(cores)
        local = {0, 1, 4, 5}
        self.assertEqual([self.select(qid, allowed, local, cores)
                          for qid in sorted(local)], [4, 5, 0, 1])
        for qid in range(128):
            self.assertIsNone(self.select(qid, {2}, {2}, {2: 2}))
        self.assertIsNone(self.select(0, {0, 1}, {0, 1}, cores))
        self.assertIsNone(self.select(0, allowed, local, {}))
        self.assertIsNone(self.select(0, set(), local, cores))
        self.assertIsNone(self.select(0, allowed, local, {**cores, 4: -1}))

    def test_affinity_source_uses_topology_without_changing_io_policy(self):
        libroot = ROOT.parents[1]
        affinity = (libroot / "lib/fuse_uring_affinity.h").read_text()
        uring = (libroot / "lib/fuse_uring.c").read_text()
        ctest = (libroot / "test/test_uring_affinity.c").read_text()
        self.assertIn("fuse_uring_select_thread_core(", uring)
        self.assertIn("/topology/thread_siblings_list", uring)
        self.assertIn("free(fuse_ring->cpu_core_ids)", uring)
        self.assertIn("core_ids[cpus[(index + stride) % count]]", affinity)
        self.assertIn("target = (int)cpus[(own_index + stride) % count]", affinity)
        self.assertIn("return fuse_uring_select_thread_cpu(qid, allowed_cpus, local_cpus)", affinity)
        self.assertIn("if (!found)", affinity)
        self.assertIn("cores[cpu] != cores[qid]", ctest)
        self.assertIn("!numa_bitmask_isbitset(targets, cpu)", ctest)
        self.assertIn("qid < 128", ctest)


if __name__ == "__main__":
    unittest.main()
