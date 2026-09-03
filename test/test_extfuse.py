#!/usr/bin/env python3

import subprocess
from os.path import join as pjoin
from pathlib import Path

from util import basename


def test_extfuse_init():
    subprocess.check_call([pjoin(basename, 'test', 'test_extfuse_init')])


def _source_region(path, start, end):
    source = path.read_text(encoding='utf-8')
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_extfuse_paper_c2_write_contract():
    """Paper C2 uses the ordinary WRITE hook, not daemon generations."""
    root = Path(__file__).resolve().parents[1]
    daemon = root / 'example' / 'extfuse' / 'extfuse_passthrough.c'
    bpf = root / 'example' / 'extfuse' / 'bpf' / 'extfuse.c'

    completion = _source_region(
        daemon, 'static void perf_uring_write_complete',
        'static void perf_read_uring_zero_copy')
    submission = _source_region(
        daemon, 'static void perf_write_uring_zero_copy',
        '__attribute__((noinline, used))\nvoid perf_read')
    write_hook = _source_region(
        bpf, 'HANDLER(FUSE_WRITE, 16)', 'HANDLER(FUSE_SETATTR, 4)')

    for region in (completion, submission):
        assert 'cache_mutation_begin' not in region
        assert 'cache_mutation_end' not in region
        assert 'backing_mutex' not in region
        assert 'xattr_lock' not in region
    assert '(void)userdata;' in completion
    assert 'perf_uring_write_complete' in submission
    assert 'NULL' in submission

    # One call covers paper AllOpt; the later call covers legacy C1/C2 even
    # when no attr row exists. The helper preserves a negative ENODATA row.
    assert write_hook.count('invalidate_positive_capability(ctx)') == 2
    legacy_invalidation = write_hook.rfind(
        'invalidate_positive_capability(ctx)')
    attr_lookup = write_hook.index(
        'bpf_map_lookup_elem(&attr_map, &key)', legacy_invalidation)
    assert legacy_invalidation < attr_lookup
