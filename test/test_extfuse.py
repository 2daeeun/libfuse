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
    assert 'perf_state.read_handler_removed = false;' in daemon_source
    assert 'perf_state.read_upcall_only_requested = false;' in daemon_source
    assert 'EXTFUSE_READ_UPCALL_ONLY=1 is retired' in daemon_source

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


def test_reply_data_prepare_source_contract():
    """Static branch coverage; complements, but does not replace, C tests."""
    root = Path(__file__).resolve().parents[1]
    lowlevel = root / 'lib' / 'fuse_lowlevel.c'
    uring = root / 'lib' / 'fuse_uring.c'
    source = lowlevel.read_text(encoding='utf-8')
    once = _source_region(lowlevel, 'static void fuse_data_prepare_once',
                          'static int fuse_send_data_iov_fallback')
    fallback = _source_region(lowlevel, 'static int fuse_send_data_iov_fallback',
                              'struct fuse_ll_pipe {')
    splice = _source_region(lowlevel, 'static int fuse_send_data_iov(',
                            '\n#else\nstatic int fuse_send_data_iov(')
    reply = _source_region(lowlevel, 'int fuse_reply_data_with_prepare(',
                           'int fuse_reply_statfs(')
    uring_reply = _source_region(uring,
                                 'int fuse_reply_data_uring_with_prepare(',
                                 'int fuse_send_msg_uring(')

    # Nulling the callback before invocation makes every outer error path safe
    # after a transport failure. Allocation and read failures reach this guard.
    assert once.index('prepare->callback = NULL') < once.index('callback(')
    assert 'errno = saved_errno;' in once
    assert fallback.count('fuse_data_prepare_once(prepare, len);') == 2
    assert fallback.count('fuse_send_msg(') == 2
    assert 'if (res != 0)\n\t\treturn res;' in fallback
    assert 'return -res;' in fallback
    assert reply.index('fuse_send_data_iov(') < reply.index(
        'fuse_data_prepare_once(&prepare, res > 0 ? -res : res);')
    assert reply.index('fuse_data_prepare_once(&prepare,') < reply.index(
        'fuse_free_req(req);')
    assert reply.index('fuse_data_prepare_once(&prepare,') < reply.index(
        'fuse_reply_err(req, res)')

    # Splice pipe allocation can fall back, and vmsplice/header/read-back
    # errors clear the pipe. No callback is consumed on a retry branch.
    assert 'if (llp == NULL)\n\t\tgoto fallback;' in splice
    assert 'res = ENOMEM;\n\t\t\t\tgoto clear_pipe;' in splice
    assert 'clear_pipe:\n\tfuse_ll_clear_pipe(se);\n\treturn res;' in splice
    short = splice[splice.index('if (res != 0 && res < len)'):]
    assert short.index('res = fuse_buf_copy(&mem_buf, buf, 0);') < short.index(
        'fuse_data_prepare_once(prepare, len);')
    assert short.index('read_back(llp->pipe[0], mbuf, now_len)') < short.index(
        'fuse_data_prepare_once(prepare, len);')
    assert short.index('fuse_data_prepare_once(prepare, len);') < short.index(
        'fuse_send_msg(')
    # EOF or a failure after a positive partial copy retains the existing
    # partial-reply rule; its count is finalized before the splice boundary.
    assert 'res = now_len;' in short
    final = short[short.index('len = res;'):]
    assert final.index('fuse_data_prepare_once(prepare, len);') < final.index(
        'se->io->splice_send(')
    assert final.index('fuse_data_prepare_once(prepare, len);') < final.index(
        'res = splice(')

    # io_uring copy and validation finish before callback, which precedes the
    # actual common COMMIT boundary; error/zero-byte copies also reach it.
    assert uring_reply.index('fuse_buf_copy(') < uring_reply.index(
        'fuse_uring_prepare_reply(') < uring_reply.index('prepare(opaque, res)')
    assert uring_reply.index('res = out->error;') < uring_reply.index(
        'prepare(opaque, res)')
    assert uring_reply.index('prepare(opaque, res)') < uring_reply.index(
        'fuse_uring_commit_sqe(') < uring_reply.index('fuse_free_req(req)')
    assert 'fuse_reply_data_with_prepare(req, bufv, flags, NULL, NULL)' in source
    assert 'fuse_send_data_iov(se, NULL, iov, 2, bufv, flags, req, NULL)' in source


def test_syncfs_source_contract():
    root = Path(__file__).resolve().parents[1]
    source = (root / 'lib' / 'fuse_lowlevel.c').read_text(encoding='utf-8')
    assert '[FUSE_SYNCFS]\t   = { do_syncfs,' in source
    assert '[FUSE_SYNCFS]\t\t= { _do_syncfs,' in source
    handler = source[source.index('static void _do_syncfs('):
                     source.index('static bool want_flags_valid(')]
    assert 'req->se->op.syncfs(req, nodeid)' in handler
    assert 'fuse_reply_err(req, ENOSYS)' in handler
    assert 'fuse_reply_err(req, 0)' not in handler
    assert 'FUSE_CAP_SYNCFS_SUPPORT) && !se->op.syncfs' in source


def test_reply_data_prepare_splice_coverage_contract():
    root = Path(__file__).resolve().parents[1]
    source = (root / 'test/test_reply_data_prepare.c').read_text()
    meson = (root / 'test/meson.build').read_text()
    assert '.init = test_init' in source
    assert 'conn, FUSE_CAP_SPLICE_WRITE' in source
    assert 'state->splice_sends++;' in source
    assert 'state.splice_sends == splice_before + 1' in source
    assert 'state.splice_requested && !state.splice_sends' in source
    assert 'result = 77;' in source
    assert "args: ['--splice']" in meson
