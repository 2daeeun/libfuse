# ExtFUSE passthrough example

This directory contains the modern ExtFUSE passthrough filesystem used by the
semi-manual `fuse_exp/fig9_mo/hand` request-count experiment. It wraps this
checkout's `example/passthrough_ll.c`, loads the ExtFUSE BPF program, and keeps
the daemon, loader, and BPF build artifacts inside the libfuse build tree.

The implementation combines three distinct categories:

- the original ExtFUSE map and handler model;
- compatibility with the paired modern Linux and libfuse branches;
- local C0-C4 experiment, coherence, and request-count extensions.

It is disabled in ordinary libfuse builds. Configure a dedicated build tree:

```bash
meson setup build-hand \
  -Dtests=false -Dexamples=true -Dutils=true -Denable-io-uring=true \
  -Denable-extfuse-example=true \
  -Dextfuse-kernel-source=/home/leedaeeun/Documents/github/linux \
  -Dextfuse-kernel-build=/home/leedaeeun/Documents/github/_kernel_build/build-6.19.14-ExtFUSE-AllOpt
meson compile -C build-hand extfuse-passthrough extfuse-bpf
```

The hand runner consumes only these libfuse-tree artifacts:

- `build-hand/example/extfuse-passthrough`
- `build-hand/example/libextfuse.so`
- `build-hand/example/extfuse.bpf.o`
- `build-hand/lib/libfuse3.so`

No file under `fuse_exp/fig9_mo/runtime/` is a build or runtime input for the
hand runner.

With the paired protocol-7.48 kernel, the `gate` profile negotiates driver-owned
ExtFUSE coherence epochs. Native passthrough and strict WBCache passthrough
bracket lower READ/WRITE with explicit BPF BEGIN/END policy hooks and a matching
driver-owned epoch. Like the
archived ExtFUSE example, LOOKUP rows use the parent/name key, GETATTR rows use
the inode key, and GETXATTR rows use the inode/name key. A positive LOOKUP is
served only while both its entry row and the child's attribute row are current;
namespace mutations delete affected entry rows. Attribute and xattr rows also
carry the daemon/native generation observed with the lower snapshot. Userspace
publishes a race-validated row before its daemon reply, while the matching
POST_DAEMON hook only acknowledges that publication.

This no-op StackFS example deliberately makes those metadata results independent
of the request credential. A filesystem with credential-dependent lookup,
attribute, or xattr policy must validate that policy in its BPF handler, extend
the map key with an adequate credential token, or leave the operation on the
daemon path, as required by the ExtFUSE model. The exact size-query
``security.capability=ENODATA`` result is the sole XATTR-only generation
exception: a lower data write may remove an existing capability but does not
create an absent one. This is a policy contract of this daemon and lower VFS,
not a generic guarantee for arbitrary FUSE write callbacks.

WRITE and COPY_FILE_RANGE return exact lower-inode attribute snapshots in the
optional mutation trailer when that independent capability is available.
Node-wide xattr notification support is negotiated independently as well; both
optional features require the coherence epochs core bit but do not require one
another.

The C3/C4 paper-like data path is distinct from native per-open passthrough.
It keeps the upper FUSE writeback cache and invokes the ExtFUSE READ/WRITE BPF
policy for every page-backed request.  A PASSTHRU decision then uses the
kernel's registered backing file and credential to execute lower VFS I/O;
`FUSE_CAP_PASSTHROUGH` remains disabled for this mode.  Paper-like C3/C4
negotiate WBCache passthrough and writeback cache without coherence epochs,
mutation trailers, xattr notification, or private READ/WRITE hooks.  WRITE
marks an existing attribute row stale and invalidates capability state in the
same ordinary BPF decision; a later real metadata miss is refreshed through
the daemon.  The `gate` profile additionally negotiates coherence epochs and
attribute refresh for strict race validation.  `DAEMON_COUNTS` reports
`wbcache_daemon_read_fallbacks` and `wbcache_daemon_write_fallbacks` even when
ordinary callback counting is disabled, so a performance run can reject any
data request that unexpectedly reached userspace.

Paper-like WBCache RELEASE only retires the registered lower file.  It does not
perform a close-time fstat, attribute publication, or generation transition;
actual WRITE decisions already invalidate affected metadata.  The strict gate
retains the conservative mutation, invalidation, and final lower-inode snapshot
path.

Registering or reusing a paper-like WBCache backing file is likewise not a
metadata mutation: it does not invalidate attributes, advance a generation, or
allocate a session-lifetime passthrough tombstone.  Attribute caching therefore
remains available while the backing is registered.  The ordinary READ/WRITE
hook stales any resident row at the actual lower-I/O boundary, and a later
daemon GETATTR publishes the lazy refresh.  Strict and legacy native modes keep
their existing epoch or tombstone safeguards.

Paper-like C2 keeps logical READ/WRITE callbacks in the daemon and submits the
request pages with io_uring fixed I/O.  The ordinary FUSE_WRITE BPF hook is the
paper-like coherence boundary for both C1 and C2: it marks a resident attribute
row stale and removes only a positive `security.capability` row before the
daemon write, while preserving an exact negative `ENODATA` row.  The fixed-I/O
submission and completion therefore do not take the global generation lock,
publish daemon BEGIN/END states, issue map syscalls, carry callback userdata, or
perform fstat/attribute publication.  This intentionally retains the archived
ExtFUSE request-boundary coherence scope: a concurrent daemon metadata refresh
can race a data write because paper-like mode has no epoch protocol.  The
`gate` profile remains the strict race-validation mode and does not use this C2
zero-copy shortcut.

In the `paper-like` throughput profile C1/C2 do not install the READ cache
handler.  C3/C4 use the ordinary READ handler to mark an existing atime row
stale and return PASSTHRU even when no row exists, matching the archived
ExtFUSE handler without making metadata residency a data-forwarding
prerequisite.  No private BEGIN/END hook is executed.  WRITE applies its stale
metadata side effects in the same way; the `gate` profile instead retains
strict generation and epoch guards.

Xattr payloads through 256 bytes are eligible for coherence epochs caching.
Larger values, malformed state, persistent writable-mmap markers, and token
mismatches always use the daemon path. Native mappings install their marker at
mmap time; ordinary cached shared mappings install it only on the first write
fault, so read-only cached compilation mappings do not suppress GETATTR hits.
A marked inode also receives zero attribute TTL in daemon and mutation-trailer
replies so later page-fault metadata cannot hide behind the upper VFS cache.
Kernels without coherence epochs retain the existing V1/V2 maps and manual
generation protocol.
