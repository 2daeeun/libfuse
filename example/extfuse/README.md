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

With the paired protocol-7.46 kernel, metadata modes negotiate driver-owned
ExtFUSE coherence epochs. Native passthrough invokes one BPF policy hook before
lower READ/WRITE and closes the matching epoch in the driver after I/O; there
is no second BPF completion callback. Negative LOOKUP rows are bound to the
parent incarnation and namespace epoch plus the exact request uid/gid/pid;
positive LOOKUP rows stay on the daemon path because their embedded child
attributes require a separate child ATTR token. GETATTR rows are bound to the
inode incarnation and attribute epoch, and GETXATTR rows to the inode
XATTR/DATA epochs plus the exact request uid/gid/pid. The sole XATTR-only
exception is an exact size-query ``security.capability=ENODATA`` result. That
exception is a policy contract of this passthrough daemon and its lower VFS:
a data write may remove an existing capability but does not create an absent
one. It is not a generic guarantee for arbitrary FUSE write callbacks.
Likewise, this example does not make GETATTR, LOOKUP, or GETXATTR authorization
depend on supplementary groups, process capabilities, or other ``/proc``
state. A daemon that does so must add a matching credential token to its cache
policy or leave those handlers on the daemon path; uid/gid/pid alone is not a
generic process credential fingerprint.
Daemon replies are published only from the race-validated POST_DAEMON phase.
WRITE and COPY_FILE_RANGE return exact lower-inode attribute snapshots in the
optional mutation trailer when that independent capability is available.
Node-wide xattr notification support is negotiated independently as well; both
optional features require the coherence epochs core bit but do not require one
another.

Xattr payloads through 256 bytes are eligible for coherence epochs caching.
Larger values, malformed state, persistent writable-mmap markers, and token
mismatches always use the daemon path. A marked inode also receives zero
attribute TTL in daemon and mutation-trailer replies so later page-fault
metadata cannot hide behind the upper VFS cache. Kernels without coherence
epochs retain the existing V1/V2 maps and manual generation protocol.
