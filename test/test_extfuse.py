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
    """The optional C2 path fixes WRITE only and preserves cache ordering."""
    root = Path(__file__).resolve().parents[1]
    daemon = root / 'example' / 'extfuse' / 'extfuse_passthrough.c'
    bpf = root / 'example' / 'extfuse' / 'bpf' / 'extfuse.c'
    lowlevel = root / 'lib' / 'fuse_lowlevel.c'
    uring = root / 'lib' / 'fuse_uring.c'

    daemon_source = daemon.read_text(encoding='utf-8')
    uring_source = uring.read_text(encoding='utf-8')
    completion = _source_region(
        daemon, 'static void perf_uring_write_complete',
        'static void perf_write_uring_zero_copy')
    submission = _source_region(
        daemon, 'static void perf_write_uring_zero_copy',
        '__attribute__((noinline, used))\nvoid perf_read')
    write_callback = _source_region(
        daemon, '__attribute__((noinline, used))\nvoid perf_write_buf(fuse_req_t req',
        'static void perf_flush')
    write_hook = _source_region(
        bpf, 'HANDLER(FUSE_WRITE, 16)', 'HANDLER(FUSE_SETATTR, 4)')
    fill_open = _source_region(
        lowlevel, 'static void fill_open', 'int fuse_reply_entry')
    verification = _source_region(
        daemon, 'static int verify_paper_capability_absent',
        '#define PERF_METADATA_EVIDENCE_MAX')
    policy_publish = _source_region(
        daemon, 'static int configure_bpf_policy',
        'static void revoke_paper_capability_enodata')
    policy_revoke = _source_region(
        daemon, 'static void revoke_paper_capability_enodata',
        'static int force_all_upcalls')

    assert 'perf_read_uring_zero_copy' not in daemon_source
    assert 'fi->io_uring_zero_copy_write = 1;' in daemon_source
    assert 'fi->io_uring_zero_copy = 1;' not in daemon_source
    assert 'FOPEN_IO_URING_ZERO_COPY_WRITE' in fill_open
    assert 'fuse_uring_submit_fixed_io' in submission
    assert 'lo_do_write_buf' not in submission
    assert 'pthread_mutex_lock' not in submission
    assert 'context->capability_fast = paper_write_fast_active();' in submission
    assert 'cache_mutation_begin' in submission
    assert submission.index('cache_mutation_begin') < submission.index(
        'fuse_uring_submit_fixed_io')
    assert completion.index('cache_mutation_end') < completion.index(
        'publish_pinned_write_attr')
    assert completion.index('publish_pinned_write_attr') < completion.index(
        'fuse_reply_write')
    assert 'attr_outcome != PERF_CACHE_ATTR_UNSTABLE' in completion
    assert 'attr_outcome != PERF_CACHE_ATTR_UNSTABLE' in submission
    assert 'lo_do_write_buf(req, ino, buffer, offset, fi);' in write_callback
    assert 'attr_outcome = cache_attr(' in write_callback
    assert 'attr_outcome == PERF_CACHE_ATTR_PUBLISHED' in write_callback
    assert 'if (!capability_fast) {' in write_callback
    conditional_invalidation = write_callback.index('invalidate_attr(ino);')
    fast_branch = write_callback.index('if (!capability_fast) {')
    lower_write = write_callback.index(
        'lo_do_write_buf(req, ino, buffer, offset, fi);')
    assert fast_branch < conditional_invalidation < lower_write
    assert 'publish_attr = !capability_fast || quiescent;' in write_callback
    assert 'have_attr = !capability_fast ||' in write_callback
    assert 'attr_outcome == PERF_CACHE_ATTR_PUBLISHED;' in write_callback
    sync_reply = write_callback.index(
        'reply_result = fuse_reply_write(req, (size_t)result);')
    sync_attr_failure = write_callback.index(
        '"sync", "write-attr-publication", EIO')
    assert sync_reply < sync_attr_failure
    assert 'attr_outcome != PERF_CACHE_ATTR_UNSTABLE' in write_callback

    # Keep the legacy aggregate while exposing directional fallbacks.  WRITE
    # must be zero for the fixed-WRITE qualification; copied READs remain
    # expected because C2 deliberately leaves the READ transport unchanged.
    assert 'queue->copied_fallbacks++;' in uring_source
    assert 'queue->copied_read_fallbacks++;' in uring_source
    assert 'queue->copied_write_fallbacks++;' in uring_source
    assert 'copied_read_fallbacks=%' in uring_source
    assert 'copied_write_fallbacks=%' in uring_source
    assert 'EXTFUSE_C2_FIXED_WRITE' in daemon_source
    assert 'EXTFUSE_READ_UPCALL_ONLY' in daemon_source
    assert 'EXTFUSE_PAPER_WRITE_FAST' in daemon_source
    assert 'EXTFUSE_WBCACHE_WRITE_STREAM' in daemon_source
    assert 'prefetch_capability(req, ino);' in daemon_source
    assert 'perf_state.read_handler_removed = remove_read_handler;' in (
        daemon_source)
    assert ('perf_state.read_upcall_only && perf_state.requested &&\n'
            '\t    perf_state.read_handler_removed') in daemon_source

    # The startup scan proves absence but does not publish fast-path safety.
    # Publication follows a successful policy-map update/readback; revocation
    # exposes the userspace slow path before clearing the BPF bits.
    assert 'paper_capability_verified_absent = true;' in verification
    assert 'paper_capability_enodata_safe' not in verification
    assert policy_publish.index('ebpf_data_update') < policy_publish.index(
        '&perf_state.paper_capability_enodata_safe')
    assert policy_revoke.index(
        '&perf_state.paper_capability_enodata_safe') < policy_revoke.index(
        'flags &= ~')

    for name in (
            'EXTFUSE_READ_UPCALL_ONLY',
            'EXTFUSE_PAPER_WRITE_FAST',
            'EXTFUSE_C2_FIXED_WRITE',
            'EXTFUSE_WBCACHE_WRITE_STREAM'):
        assert f'parse_boolean_environment("{name}"' in daemon_source
        assert f'{name}=%u' in daemon_source
    assert ('!perf_state.paper_write_fast' in daemon_source and
            'EXTFUSE_C2_FIXED_WRITE requires hit mode' in daemon_source)
    for key in (
            'read_upcall_only_requested',
            'paper_write_fast_enabled',
            'uring_fixed_write_required',
            'wbcache_write_stream_requested'):
        assert daemon_source.count(f'{key}=%u') == 1

    # Paper C1/C2 skip the positive capability lookup only under the explicit
    # policy bit. C3/C4 retain their existing WBCache invalidation contract.
    assert write_hook.count('invalidate_positive_capability(ctx)') == 2
    legacy_invalidation = write_hook.rfind(
        'invalidate_positive_capability(ctx)')
    fast_policy = write_hook.rfind(
        'policy_enabled(EXTFUSE_POLICY_PAPER_WRITE_FAST)',
        0, legacy_invalidation)
    attr_lookup = write_hook.index(
        'bpf_map_lookup_elem(&attr_map, &key)', legacy_invalidation)
    assert fast_policy < legacy_invalidation < attr_lookup
