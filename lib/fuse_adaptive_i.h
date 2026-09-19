/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef FUSE_ADAPTIVE_I_H
#define FUSE_ADAPTIVE_I_H
#include "fuse_adaptive.h"
int fuse_adaptive_start(struct fuse_session *se);
void fuse_adaptive_stop(struct fuse_session *se);
#endif
