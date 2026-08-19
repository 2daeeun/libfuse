/* SPDX-License-Identifier: GPL-2.0 */
#define FUSE_USE_VERSION 318

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fuse_lowlevel.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ebpf.h>

/* BPF_PROG_TYPE_EXTFUSE is the type appended by the v6.19.14 kernel port. */
#define EXTFUSE_BPF_PROG_TYPE 33
#define EXTFUSE_MAIN_SECTION "extfuse"
#define EXTFUSE_HANDLER_PREFIX "extfuse/"

#define ERROR(fmt, ...) fprintf(stderr, "libextfuse: " fmt, ##__VA_ARGS__)

static int set_errno_from_libbpf(int err)
{
	int code = err < 0 ? -err : err;

	if (code >= __LIBBPF_ERRNO__START && code < __LIBBPF_ERRNO__END)
		errno = EINVAL;
	else if (code > 0)
		errno = code;
	return err;
}

static const char *libbpf_error_string(int err, char *buffer, size_t size)
{
	if (libbpf_strerror(err, buffer, size) != 0)
		snprintf(buffer, size, "libbpf error %d", err);
	return buffer;
}

static bool is_extfuse_section(const char *section)
{
	return section &&
		(!strcmp(section, EXTFUSE_MAIN_SECTION) ||
		 !strncmp(section, EXTFUSE_HANDLER_PREFIX,
			  strlen(EXTFUSE_HANDLER_PREFIX)));
}

static int parse_handler_opcode(const char *section, uint32_t *opcode)
{
	const char *number;
	char *end;
	unsigned long value;

	if (!section || strncmp(section, EXTFUSE_HANDLER_PREFIX,
				strlen(EXTFUSE_HANDLER_PREFIX)))
		return -EINVAL;

	number = section + strlen(EXTFUSE_HANDLER_PREFIX);
	if (*number == '\0')
		return -EINVAL;

	errno = 0;
	value = strtoul(number, &end, 10);
	if (errno || *end != '\0' || value >= EXTFUSE_HANDLER_SLOTS)
		return -EINVAL;

	*opcode = (uint32_t)value;
	return 0;
}

static int set_program_types(struct bpf_object *object)
{
	struct bpf_program *program;
	char error_buffer[128];
	int main_count = 0;
	int err;

	bpf_object__for_each_program(program, object) {
		const char *section = bpf_program__section_name(program);

		if (!is_extfuse_section(section)) {
			ERROR("unexpected BPF program section '%s'\n",
			      section ? section : "(null)");
			return -EINVAL;
		}
		if (!strcmp(section, EXTFUSE_MAIN_SECTION))
			main_count++;

		err = bpf_program__set_type(program,
				(enum bpf_prog_type)EXTFUSE_BPF_PROG_TYPE);
		if (err) {
			ERROR("cannot set ExtFUSE type on section '%s': %s\n",
			      section, libbpf_error_string(err, error_buffer,
							  sizeof(error_buffer)));
			return err;
		}
	}

	if (main_count != 1) {
		ERROR("expected one '%s' main program, found %d\n",
		      EXTFUSE_MAIN_SECTION, main_count);
		return -EINVAL;
	}
	return 0;
}

static int map_fd_by_name(struct bpf_object *object, const char *name)
{
	struct bpf_map *map = bpf_object__find_map_by_name(object, name);

	if (!map) {
		ERROR("required BPF map '%s' is missing\n", name);
		return -ENOENT;
	}
	return bpf_map__fd(map);
}

static int populate_handlers(struct bpf_object *object, int handlers_fd)
{
	struct bpf_program *program;
	int count = 0;

	bpf_object__for_each_program(program, object) {
		const char *section = bpf_program__section_name(program);
		uint32_t opcode;
		uint32_t program_fd;
		int fd;
		int err;

		if (!strcmp(section, EXTFUSE_MAIN_SECTION))
			continue;
		err = parse_handler_opcode(section, &opcode);
		if (err) {
			ERROR("invalid ExtFUSE handler section '%s'\n", section);
			return err;
		}
		fd = bpf_program__fd(program);
		if (fd < 0)
			return -EINVAL;
		program_fd = (uint32_t)fd;
		if (bpf_map_update_elem(handlers_fd, &opcode, &program_fd,
					BPF_ANY)) {
			err = -errno;
			ERROR("cannot install handler %u from '%s': %s\n",
			      opcode, section, strerror(errno));
			return err;
		}
		count++;
	}

	if (!count) {
		ERROR("BPF object contains no ExtFUSE handlers\n");
		return -EINVAL;
	}
	return 0;
}

ebpf_context_t *ebpf_init(const char *filename)
{
	static const char *const map_names[EXTFUSE_DATA_MAP_COUNT] = {
		[EXTFUSE_ENTRY_MAP] = "entry_map",
		[EXTFUSE_ATTR_MAP] = "attr_map",
		[EXTFUSE_XATTR_MAP] = "xattr_map",
		[EXTFUSE_DAEMON_IO_MAP] = "daemon_io_map",
		[EXTFUSE_NATIVE_IO_MAP] = "native_io_map",
		[EXTFUSE_MMAP_MAP] = "mmap_map",
		[EXTFUSE_POLICY_MAP] = "policy_map",
		[EXTFUSE_HANDLERS_MAP] = "handlers",
	};
	struct bpf_program *main_program;
	struct bpf_object *object = NULL;
	ebpf_context_t *context = NULL;
	char error_buffer[128];
	long open_err;
	int err;
	int i;

	if (!filename) {
		errno = EINVAL;
		return NULL;
	}

	context = calloc(1, sizeof(*context));
	if (!context)
		return NULL;
	context->ctrl_fd = -1;
	for (i = 0; i < MAX_MAPS; i++)
		context->data_fd[i] = -1;

	object = bpf_object__open_file(filename, NULL);
	open_err = libbpf_get_error(object);
	if (open_err) {
		object = NULL;
		set_errno_from_libbpf((int)open_err);
		ERROR("cannot open BPF object '%s': %s\n",
		      filename, libbpf_error_string((int)open_err, error_buffer,
							 sizeof(error_buffer)));
		goto error;
	}

	err = set_program_types(object);
	if (err) {
		set_errno_from_libbpf(err);
		goto error;
	}

	err = bpf_object__load(object);
	if (err) {
		set_errno_from_libbpf(err);
		ERROR("cannot load BPF object '%s': %s\n",
		      filename, libbpf_error_string(err, error_buffer,
						       sizeof(error_buffer)));
		goto error;
	}

	for (i = 0; i < EXTFUSE_DATA_MAP_COUNT; i++) {
		context->data_fd[i] = map_fd_by_name(object, map_names[i]);
		if (context->data_fd[i] < 0) {
			errno = -context->data_fd[i];
			goto error;
		}
	}

	err = populate_handlers(object,
				context->data_fd[EXTFUSE_HANDLERS_MAP]);
	if (err) {
		set_errno_from_libbpf(err);
		goto error;
	}

	main_program = bpf_object__find_program_by_name(
				object, "fuse_xdp_main_handler");
	if (!main_program) {
		errno = ENOENT;
		ERROR("main program 'fuse_xdp_main_handler' is missing\n");
		goto error;
	}
	context->ctrl_fd = bpf_program__fd(main_program);
	if (context->ctrl_fd < 0) {
		errno = EINVAL;
		goto error;
	}
	context->object = object;
	return context;

error:
	bpf_object__close(object);
	free(context);
	return NULL;
}

void ebpf_fini(ebpf_context_t *context)
{
	if (!context)
		return;
	bpf_object__close(context->object);
	free(context);
}

int ebpf_enable_extfuse(ebpf_context_t *context,
			struct fuse_conn_info *conn)
{
	if (!context || !conn || context->ctrl_fd < 0)
		return -EINVAL;
	if (!fuse_set_feature_flag(conn, FUSE_CAP_EXTFUSE))
		return -EOPNOTSUPP;
	conn->extfuse_prog_fd = (uint32_t)context->ctrl_fd;
	return 0;
}

static int handlers_fd(const ebpf_context_t *context)
{
	if (!context || context->data_fd[EXTFUSE_HANDLERS_MAP] < 0) {
		errno = EINVAL;
		return -1;
	}
	return context->data_fd[EXTFUSE_HANDLERS_MAP];
}

static int checked_data_fd(const ebpf_context_t *context, int idx)
{
	if (!context || idx < 0 || idx >= MAX_MAPS ||
	    context->data_fd[idx] < 0) {
		errno = EINVAL;
		return -1;
	}
	return context->data_fd[idx];
}

int ebpf_ctrl_update(ebpf_context_t *context,
		     const ebpf_ctrl_key_t *key,
		     const ebpf_handler_t *handler)
{
	uint32_t opcode;
	uint32_t program_fd;
	int fd = handlers_fd(context);

	if (fd < 0 || !key || !handler || handler->prog_fd < 0 ||
	    key->opcode >= EXTFUSE_HANDLER_SLOTS) {
		errno = EINVAL;
		return -1;
	}
	opcode = key->opcode;
	program_fd = (uint32_t)handler->prog_fd;
	return bpf_map_update_elem(fd, &opcode, &program_fd, BPF_ANY);
}

int ebpf_ctrl_delete(ebpf_context_t *context,
		     const ebpf_ctrl_key_t *key)
{
	uint32_t opcode;
	int fd = handlers_fd(context);

	if (fd < 0 || !key || key->opcode >= EXTFUSE_HANDLER_SLOTS) {
		errno = EINVAL;
		return -1;
	}
	opcode = key->opcode;
	return bpf_map_delete_elem(fd, &opcode);
}

int ebpf_data_next(ebpf_context_t *context, const void *key, void *next,
		   int idx)
{
	int fd = checked_data_fd(context, idx);

	if (fd < 0 || !next) {
		errno = EINVAL;
		return -1;
	}
	return bpf_map_get_next_key(fd, key, next);
}

int ebpf_data_lookup(ebpf_context_t *context, const void *key, void *value,
		     int idx)
{
	int fd = checked_data_fd(context, idx);

	if (fd < 0 || !key || !value) {
		errno = EINVAL;
		return -1;
	}
	return bpf_map_lookup_elem(fd, key, value);
}

int ebpf_data_update(ebpf_context_t *context, const void *key,
		     const void *value, int idx, int overwrite)
{
	uint64_t flags = overwrite ? BPF_ANY : BPF_NOEXIST;
	int fd = checked_data_fd(context, idx);

	if (fd < 0 || !key || !value) {
		errno = EINVAL;
		return -1;
	}
	return bpf_map_update_elem(fd, key, value, flags);
}

int ebpf_data_delete(ebpf_context_t *context, const void *key, int idx)
{
	int fd = checked_data_fd(context, idx);

	if (fd < 0 || !key) {
		errno = EINVAL;
		return -1;
	}
	return bpf_map_delete_elem(fd, key);
}
