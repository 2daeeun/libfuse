# Experimental runtime FUSE io_uring QD control

This is a local Linux/libfuse protocol extension. Both patched trees are
required. It is disabled by default. It does not change writeback caching,
`max_write`, `max_pages`, or the number of queues. QD means the number of FUSE
entries **per queue**, including metadata requests, not application iodepth.

The workload detector is separate from the QD actuator. Automatic decisions
require an explicit policy file and profile (see below). Without them,
workload output remains `POLICY_NOT_CONFIGURED` and only manual requests change
QD. Manual requests do not wait for detector persistence.

## Enable and operate

Build libfuse with `-Denable-io-uring=true`. Run a filesystem that uses this
library with these additional libfuse options, once the matching kernel has
been installed/booted and FUSE io_uring is enabled:

```text
-o io_uring,io_uring_adaptive=on,io_uring_q_depth=8,io_uring_q_depth_max=64
-o io_uring_drain_timeout_ms=5000,io_uring_control=/private/path/control.sock
```

The explicit switch accepts `on` and `off`; the existing bare
`io_uring_adaptive` option is an alias for `io_uring_adaptive=on`. Omitting the
switch means OFF. If repeated, the last switch takes effect. Invalid values
are rejected. For ordinary io_uring at fixed QD, use:

```text
-o io_uring,io_uring_adaptive=off,io_uring_q_depth=8
```

OFF does not negotiate the runtime/monitor capabilities, start the adaptive
monitor thread, create a control socket, or reserve adaptive maximum-depth
queue resources. The `io_uring_control` option is invalid with OFF; ON requires
`io_uring`. This switch is selected when starting the mount. Changing it
requires a new daemon/mount; the control CLI does not toggle it in place.
ON alone supplies no automatic QD policy; a policy file/profile enables it.

One INFO startup record reports the effective adaptive mode. OFF is logged
after INIT; ON is logged only after the first successful kernel monitor
configuration, including after any INIT readiness retries:

```text
FUSE_ADAPTIVE mode=off runtime_qd=0 workload_monitor=0 initial_depth=8 max_depth=8 policy=POLICY_NOT_CONFIGURED
FUSE_ADAPTIVE mode=on runtime_qd=1 workload_monitor=1 initial_depth=8 max_depth=64 policy=POLICY_NOT_CONFIGURED
```

Later monitor configuration changes do not repeat this startup record. ON
evidence does not imply that a QD transaction completed: check the control
socket status and all queues separately. OFF evidence describes the adaptive
switch; ordinary io_uring activation must still be checked independently.

Use an existing private directory owned by the daemon user. The daemon binds
an owner-only UNIX seqpacket socket; an existing pathname is an error, and is
never removed on startup. Cleanup only removes the socket inode created by
this session. Peer credentials must match the daemon's effective UID, or root.
The CLI and daemon must use this same local protocol version. The socket
option is optional when the public C API is used instead.

```sh
fuse-uring-ctl --socket /private/path/control.sock status
fuse-uring-ctl --socket /private/path/control.sock workload
fuse-uring-ctl --socket /private/path/control.sock get-config
fuse-uring-ctl --socket /private/path/control.sock set-qd 2
fuse-uring-ctl --socket /private/path/control.sock --json status
fuse-uring-ctl --socket /private/path/control.sock set-qd 64
```

`set-qd` returns an asynchronous transaction number. Poll `status` until
`busy=0`, then inspect the session error and **every queue**, including
`current_depth`, `target_depth`, `phase`, `error` and `reclaim_bytes`. Queues
change sequentially: failure can leave earlier queues at the new depth and
later queues unchanged. This is not a session-wide atomic commit. A later
request can converge the queues again. Another request while busy returns
`-EBUSY`; startup readiness returns `-EAGAIN`. Supported depths are positive
integers up to the configured maximum, including 2, 8, 16, 32 and 64.

Phases: 0 IDLE, 1 PREPARING, 2 DRAINING, 3 RECONFIGURING, 4 RECLAIMING,
5 COMPLETE, 6 FAILED. Exit status 0 from `set-qd` means accepted, not completed.
The CLI exits nonzero for daemon errors. `--json` produces compact JSON.

`include/fuse_adaptive.h` exposes `fuse_session_uring_set_depth()`,
`fuse_session_uring_get_status()`, `fuse_session_workload_get()` and
`fuse_session_workload_configure()`. Keep the session alive during API calls.
The getter returns the queue count (or a negative errno); capacity zero queries
the required count. Threshold configuration is asynchronous; `get-config`
reports requested settings, pending state, and the last monitor error.

## File-based automatic policy

Edit `config/qd-policy.conf` to change workload conditions, target QD and
observation settings. No C code or rebuild is needed for policy edits. The
daemon reads the file once at session creation; edit it before starting the
next mount. Live reload is not implemented. To enable the supplied ThinkPad C2
rules, add:

```text
-o io_uring,io_uring_adaptive=on,io_uring_q_depth=2,io_uring_q_depth_max=512
-o io_uring_policy=thinkpad-c2,io_uring_policy_file=/absolute/path/libfuse/config/qd-policy.conf
```

Other supplied profiles are `dell-c2`, `dell-c6` and `thinkpad-c6`. Select the
profile that matches the machine and filesystem configuration being tested;
the daemon does not infer these from hostnames. Profiles are arbitrary safe
identifiers, so additional profiles require only file edits. The sample file
contains exactly the seven requested experimental rules. Their measured gains
are motivation for testing, not guaranteed performance of this implementation.
The selected profile's largest target must fit `io_uring_q_depth_max`; otherwise
session creation fails. Missing/malformed files, unknown profiles and ambiguous
rules also fail before mounting. Omitting both policy options retains manual
QD control. `io_uring_policy=none` without a file disables automatic selection.

Each rule has the following whitespace-separated fields (sizes are bytes):

```text
rule PROFILE RULE_NAME REQUESTERS FILES SIZE seq|rand READ_PERCENT TARGET_QD
```

The file also owns `window_ms`, `stable_ms`, minimum request/pair counts,
dominance and sequential/random thresholds, and mixed-read ratio tolerance.
`thresholds 32768 131072 1048576` sets the three ascending size-profile
boundaries in bytes. `none` is reserved for disabling automatic selection.
While a file policy is selected, the `configure` API/CLI accepts only identical
detector settings to reset persistence; overrides return `-EPERM`. Thus other
controllers cannot silently replace the file's observation settings.
`stable_ms 10000` is the supplied ten-second requirement. Pure read/write
rules require exactly 100/0 percent read requests. Mixed ratios use request
counts with the supplied tolerance of five percentage points. Size conditions
are exact observed iter sizes: every observed request in the window must have
that size. Arbitrary positive sizes can be specified; the four legacy size
profiles do not constrain rule sizes. Unmatched, idle, insufficient or uncertain
windows reset policy persistence and leave QD unchanged.

The policy observes app-facing FUSE iter attempts as described below. With a
policy selected, the new detail snapshot counts distinct inode incarnations
and requester identities across both read and write operations, exactly up to
32 and saturating at 33. Thus a rule requiring 32 does not accept 31 or 33+.
Requester counts are observed active identities, not a guarantee about the
application's configured thread count. Mixed sequential rules use combined
read/write offset adjacency per inode. Append, async-worker, DAX, passthrough
and incomplete observation windows do not match these rules. This policy is
intended for the supplied C2/C6 data paths.

A matching rule and size profile must persist across consecutive valid
windows for `stable_ms`; the first classified window starts the timer. With
the sample settings, the earliest decision is approximately eleven seconds
after observation starts. Rule/profile changes, gaps and monitor reconfiguration
reset it. The monitor then invokes the existing asynchronous QD engine. Status
must still show successful completion for every queue; the policy does not
make a multi-queue transition atomic. A terminal transition error is exposed
and suppresses automatic retries for the same candidate until it changes or
the detector is reset. A busy engine is retried on a later valid window.
Manual QD changes remain possible; a stable automatic policy can subsequently
request its target again.

`workload` JSON retains the original classifier fields and additionally exposes
`policy`, `policy_rule`, `policy_target_depth`, `policy_stable_ns`,
`policy_stable`, `policy_files`, `policy_requesters`, `policy_read_percent`,
`policy_transaction` and `policy_error`. Mixed policy decisions use
`policy_stable`, independently of the legacy pure-workload `stable` field.
Accepted changes log `FUSE_QD_POLICY` with the profile, rule, target and
transaction number. These records show acceptance, not completed reclamation.

## Actual memory reclamation

SQ/CQ capacity and entry/header metadata are allocated for the maximum depth.
Payload memory is allocated for the current depth. `io_uring_resize_rings()`
is not used: resizing SQ/CQ does not resize FUSE payload buffers.

Copied mode allocates payloads for added entries and unmaps the payloads of
retired entries after draining. In fixed-buffer mode, prepare a new payload
pool in the alternate registered slot, pause admission on this queue, finish
existing replies, switch its generation and pool, rearm, and resume. Remove
the old slot, wait for its **resource-tag CQE**, then unmap the old pool.
Registration update returning success alone is not a reclamation barrier.
Small metadata, header allocations and the sparse registration table remain
at maximum capacity. Application page cache is independent of these buffers.

`payload_bytes` describes active payload allocation, `registered_bytes`
describes allocated payload pools still associated with fixed registration
(zero for copied mode), and `reclaim_bytes` describes prepared/retiring payload
allocation outside the active payload set. These are bookkeeping values,
not measured RSS/PSS, and do not count header memory or zero-copy request folios.
During preparation `reclaim_bytes` includes the replacement pool. During a
fixed-buffer change, old and new pools coexist. Peak memory can therefore grow
even during a requested shrink. Only one queue is transitioned at a time.
Replacement allocation/registration can fail under memory or memlock pressure
even for a shrink, since the old pool must remain usable for rollback.
Fixed-buffer mode retains the existing kernel capability and registration
requirements; this feature does not relax them.

For Q queues and payload slot size B, steady payload allocation is Q * D * B
when all queues have depth D. The copied path can be lazily faulted, so an
allocation reduction need not equal an RSS reduction. Measure daemon
`/proc/<pid>/smaps_rollup` and `/proc/<pid>/status` before and after a completed
transition, using the same PID/workload, and keep allocation estimates separate
from RSS/PSS/VmLck/VmPin and kernel memory evidence. A single aggregate RSS sample does
not prove that all registered page references were released.

## Workload observation and classification

Linux observes `iov_iter_count()` and `ki_pos` at
`fuse_file_read_iter()` / `fuse_file_write_iter()`, before cache aggregation or
FUSE request splitting. This is **FUSE iter requested I/O**, not daemon-visible
`fuse_read_in.size` / `fuse_write_in.size`, successful byte count, or a universal
reconstruction of every application syscall. Cache-hit reads are included.
Failed/retried iter attempts can be included; writev is one aggregate iter.
mmap faults, splice and copy-file-range paths are not comprehensively observed.
Async worker, append, DAX and unknown observation flags prevent a stable supported
class. The passthrough flag is preserved as provenance but does not prevent
classification: native and WBCache dispatch follow the same app-facing iter
observation. This does not change their data paths or prove their runtime QD
transitions have been validated. Native data I/O bypasses daemon request queues;
its application activity need not create FUSE io_uring queue pressure. Workload
observation says nothing about data-path zero-copy success.

Arbitrary nonzero sizes are accepted. Defaults are:

| Actual iter size | Profile index / experimental label |
| --- | --- |
| < 32768 | 0 / 4K |
| 32768 .. 131071 | 1 / 32K |
| 131072 .. 1048575 | 2 / 128K |
| >= 1048576 | 3 / 1024K |

Thus 16 KiB maps to profile 0, and 64 KiB to profile 1. Profiles are range
labels, not measured request sizes. Output includes observed minimum and
maximum sizes; when equal, they give the exact observed size. A mixed window
does not invent an exact modal size. The dominant profile is selected by
request count, not average size or byte count.

The default window is 1000 ms, minimum 16 requests and 16 offset pairs,
dominance 80%, sequential adjacency at least 80%, random adjacency at most
20%, and persistence 10000 ms. File identity is the existing unique inode
incarnation within a connection. Sequential state is per inode and direction;
separate files can interleave. Requester identity is TID plus task start time.
The legacy snapshot's files and requesters saturate at 2 (meaning two or more),
not exact counts; the opt-in policy detail snapshot described above is separate.
This identifies active requesters, not outstanding-request concurrency or a
precise application thread count in every asynchronous I/O model. Concurrent
same-file offset reordering can reduce sequential confidence.

Supported classes are RR_1T_1F, RR_NT_1F, RW_1T_1F, RW_NT_1F, SR_1T_1F,
SR_NT_NF, SW_1T_1F and SW_NT_NF. Unsupported combinations become UNKNOWN;
insufficient dominance becomes MIXED; empty windows become IDLE. Profile and
class form the persistence key. First classification starts the timer, so
the default reaches stable after approximately 11 seconds of observations.
Profile/class change, invalid/missing window, monitor failure or configuration
change resets persistence. Changing raw size within the same profile does not
reset it. `profile` and `operation` are UINT32_MAX when undetermined;
operation 0 is read and 1 is write.

```sh
fuse-uring-ctl --socket /private/path/control.sock configure \
  --window-ms 1000 --stable-ms 10000 \
  --min-requests 16 --min-pairs 16 \
  --dominance-percent 80 --sequential-percent 80 --random-percent 20 \
  --thresholds 32768,131072,1048576
```

`configure` replaces all settings; omitted values use defaults, rather than
patching the current settings. An external policy can consume the result, require
`stable`, look up `(profile, workload)` and submit the target through the public
QD API. No process restart, fio configuration file, or application name is part
of the detector. A continuously running application changing from 4 KiB to
1 MiB resets the profile's persistence timer; QD changes only after a configured
policy submits a target, or the operator submits it manually.

## Protocol and synchronization

INIT negotiates `FUSE_HAS_IO_URING_RUNTIME` and `FUSE_HAS_WORKLOAD_MONITOR`.
An explicitly requested adaptive session fails when the kernel lacks either
capability. Existing 40-byte uring commands and 64-byte INIT reply stay intact.
New 80-byte SQE128 commands implement RECONFIG(INIT), PAUSE, QUERY, RECONFIG,
REARM and RESUME. Runtime COMMIT carries the generation in its flags field.
Kernel entry identity is stable across generations. PAUSE, REARM, RESUME and
runtime COMMIT reject stale generations. RECONFIG(INIT) uses generation 1;
subsequent RECONFIG uses the current generation plus one and requires a drained
queue. QUERY accepts any input generation and reports the actual generation
and queue state under the queue lock, so state discovery does not require a
known generation. No active request is moved.

The policy additionally requests `FUSE_WORKLOAD_DETAIL` and reads
`FUSE_DEV_IOC_MONITOR_DETAIL`. The original snapshot/ioctl layout is unchanged.
Both snapshot ioctls consume the same observation window; do not run an external
collector against the policy's connection. A kernel without the detail
extension cannot supply automatic policy observations, and the monitor exposes
an error instead of falling back to imprecise cardinality.

Kernel queue locks serialize arrival, park/commit and resume; a runtime mutex
serializes controls. Entry references and pending task work survive retirement
until completion/teardown. Userspace ring owners execute changes; the monitor
wakes them using separate eventfds. Session/pool control locks protect APIs and
status. Workload statistics use per-CPU double banks with RCU publication and
a grace period on the collector, plus a per-inode spinlock for sequence state. No global
monitor mutex or grace-period wait is added to the I/O hot path.

Drain timeout restores the previous queue configuration if possible, without
cancelling application I/O. It is **cooperative**: synchronous filesystem
callbacks can block the owner thread beyond the configured timeout. Teardown
also joins these owners cooperatively. Irrecoverable command/rollback/resource
cleanup errors mark the session terminated using `fuse_session_exit()` instead
of freeing possibly referenced memory. The normal multithread loop is woken;
a single/custom loop blocked in a device read may still need its normal
shutdown wake-up, as documented by that API. This is not a forced process kill.
A control timeout or session shutdown is not proof of reclamation.

Changing QD can temporarily increase latency, allocate/pin/unmap memory and
pause dispatch on each queue. Monitor sampling adds accounting and collector
cost. No numerical latency or throughput overhead is asserted without live
measurement. Control/status values and mocked tests do not establish mounted
filesystem correctness, RSS savings or performance.

## Non-mount tests and remaining runtime validation

Meson tests: `adaptive workload detector`, `adaptive QD policy`, `adaptive options and INIT`,
`adaptive control CLI`, `adaptive monitor and control socket`, and
`io_uring runtime QD engine` (the last two with io_uring enabled).
The engine tests use real production transition/CQ code with mocked kernel
submissions, failure injection and delayed resource-release CQEs. The control
test uses a real local socket with mocked ioctls. They do not run the new
kernel protocol on a mounted filesystem.

Before performance claims, boot the matching kernel and validate copied and
fixed-buffer modes separately: continuous reads/writes with checksums, repeated
2/8/16/32/64 changes, idle queues, slow callbacks, simultaneous control calls,
partial failure, daemon exit/unmount, registration failures and KASAN/lockdep.
Keep one application process alive while switching 4 KiB/1 MiB phases, verify
timer resets and file/requester identity, and record status plus RSS/PSS across
completed shrink/grow cycles. Run performance measurements separately from
fault-injection and tracing runs.
