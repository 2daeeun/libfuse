#define FUSE_USE_VERSION 30

#include "fuse.h"
#include "fuse_kernel.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	if (sizeof(struct fuse_file_info) != 64) {
		fprintf(stderr, "struct fuse_file_info size mismatch\n");
		exit(1);
	}
	if (sizeof(struct fuse_conn_info) != 128) {
		fprintf(stderr, "struct fuse_conn_info size mismatch\n");
		exit(1);
	}
	if (offsetof(struct fuse_conn_info, extfuse_prog_fd) != 68) {
		fprintf(stderr,
			"struct fuse_conn_info ExtFUSE fd offset mismatch\n");
		exit(1);
	}
	if (sizeof(struct fuse_init_out) != 64) {
		fprintf(stderr, "struct fuse_init_out size mismatch\n");
		exit(1);
	}
	if (offsetof(struct fuse_init_out, extfuse_prog_fd) != 44) {
		fprintf(stderr,
			"struct fuse_init_out ExtFUSE fd offset mismatch\n");
		exit(1);
	}
}
