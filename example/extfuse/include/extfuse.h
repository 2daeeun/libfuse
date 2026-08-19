/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXTFUSE_H__
#define __EXTFUSE_H__

#include <linux/errno.h>
#include <linux/extfuse.h>
#include <linux/fuse.h>
#include <linux/limits.h>

#include <extfuse_coherence.h>

#define PASSTHRU 1
#define RETURN 0
#define UPCALL (-ENOSYS)

/* The handlers prog-array retains the original ExtFUSE 128-slot layout. */
#define FUSE_OPS_COUNT 64

/*
 * Private opcodes used only by the v6.19 native-passthrough coherence hook.
 * They never appear on /dev/fuse and deliberately live above the FUSE ABI
 * opcode range used by this experiment.
 */
#define EXTFUSE_PASSTHROUGH_READ 65
#define EXTFUSE_PASSTHROUGH_WRITE 66
#define EXTFUSE_PASSTHROUGH_MMAP 67

#endif /* __EXTFUSE_H__ */
