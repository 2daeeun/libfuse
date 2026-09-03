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
    """Paper C2 uses standard io_uring transport and the C1 data callbacks."""
    root = Path(__file__).resolve().parents[1]
    daemon = root / 'example' / 'extfuse' / 'extfuse_passthrough.c'
    bpf = root / 'example' / 'extfuse' / 'bpf' / 'extfuse.c'

    daemon_source = daemon.read_text(encoding='utf-8')
    read_callback = _source_region(
        daemon, '__attribute__((noinline, used))\nvoid perf_read(fuse_req_t req',
        '__attribute__((noinline, used))\nvoid perf_write_buf')
    write_callback = _source_region(
        daemon, '__attribute__((noinline, used))\nvoid perf_write_buf(fuse_req_t req',
        'static void perf_flush')
    write_hook = _source_region(
        bpf, 'HANDLER(FUSE_WRITE, 16)', 'HANDLER(FUSE_SETATTR, 4)')

    assert 'perf_read_uring_zero_copy' not in daemon_source
    assert 'perf_write_uring_zero_copy' not in daemon_source
    assert 'fuse_uring_submit_fixed_io' not in daemon_source
    assert 'perf_state.uring_zero_copy_required = false;' in daemon_source
    assert 'lo_read(req, ino, size, offset, fi);' in read_callback
    assert 'lo_do_write_buf(req, ino, buffer, offset, fi);' in write_callback
    assert 'cache_attr(ino, &st, lo->timeout' in write_callback

    # One call covers paper AllOpt; the later call covers legacy C1/C2 even
    # when no attr row exists. The helper preserves a negative ENODATA row.
    assert write_hook.count('invalidate_positive_capability(ctx)') == 2
    legacy_invalidation = write_hook.rfind(
        'invalidate_positive_capability(ctx)')
    attr_lookup = write_hook.index(
        'bpf_map_lookup_elem(&attr_map, &key)', legacy_invalidation)
    assert legacy_invalidation < attr_lookup
