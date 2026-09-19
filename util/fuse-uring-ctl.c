/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "../lib/fuse_adaptive_protocol.h"

#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void usage(FILE *out)
{
	fputs("Usage: fuse-uring-ctl --socket PATH [--json] COMMAND\n"
	      "Commands: status | workload | set-qd N | configure | get-config\n"
	      "configure replaces detector settings; omitted values use defaults:\n"
	      "  --window-ms 1000 --stable-ms 10000 --min-requests 16 --min-pairs 16\n"
	      "  --dominance-percent 80 --sequential-percent 80 --random-percent 20\n"
	      "  --thresholds 32768,131072,1048576\n"
	      "set-qd returns an asynchronous transaction; poll status for completion.\n",
	      out);
}

static int number(const char *s, uint32_t *out)
{
	char *end;
	unsigned long long v;

	if (!s || !isdigit((unsigned char)*s))
		return -1;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno || *end || v > UINT32_MAX)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

static int thresholds(const char *s, uint64_t out[3])
{
	for (unsigned int i = 0; i < 3; i++) {
		char *end;
		unsigned long long value;

		if (!isdigit((unsigned char)*s))
			return -1;
		errno = 0;
		value = strtoull(s, &end, 10);
		if (errno || !value || (i && value <= out[i - 1]) ||
		    *end != (i == 2 ? '\0' : ','))
			return -1;
		out[i] = value;
		s = end + (i != 2);
	}
	return 0;
}

static void pretty(const char *text)
{
	bool quoted = false, escape = false;
	unsigned int indent = 0;

	for (const char *p = text; *p; p++) {
		char c = *p;

		if (quoted) {
			putchar(c);
			if (escape)
				escape = false;
			else if (c == '\\')
				escape = true;
			else if (c == '"')
				quoted = false;
			continue;
		}
		if (c == '"') {
			quoted = true;
			putchar(c);
		} else if (c == '{' || c == '[') {
			putchar(c);
			putchar('\n');
			indent++;
			printf("%*s", (int)(indent * 2), "");
		} else if (c == '}' || c == ']') {
			if (indent)
				indent--;
			printf("\n%*s%c", (int)(indent * 2), "", c);
		} else if (c == ',') {
			printf(",\n%*s", (int)(indent * 2), "");
		} else if (c == ':') {
			fputs(": ", stdout);
		} else {
			putchar(c);
		}
	}
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "socket", required_argument, NULL, 's' },
		{ "json", no_argument, NULL, 'j' },
		{ "help", no_argument, NULL, 'h' },
		{ "window-ms", required_argument, NULL, 1000 },
		{ "stable-ms", required_argument, NULL, 1001 },
		{ "min-requests", required_argument, NULL, 1002 },
		{ "min-pairs", required_argument, NULL, 1003 },
		{ "dominance-percent", required_argument, NULL, 1004 },
		{ "sequential-percent", required_argument, NULL, 1005 },
		{ "random-percent", required_argument, NULL, 1006 },
		{ "thresholds", required_argument, NULL, 1007 },
		{ NULL, 0, NULL, 0 },
	};
	struct fuse_adaptive_control_request req = {
		.version = FUSE_ADAPTIVE_CONTROL_VERSION,
		.settings = {
			.window_ms = 1000, .stable_ms = 10000,
			.min_requests = 16, .min_pairs = 16,
			.dominance_percent = 80, .sequential_percent = 80,
			.random_percent = 20,
			.thresholds = { 32768, 131072, 1048576 },
		},
	};
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	const char *path = NULL, *command;
	bool json = false;
	char *reply;
	int opt, fd, error = 0, result = 1;
	ssize_t len;
	struct pollfd pfd;

	while ((opt = getopt_long(argc, argv, "s:jh", options, NULL)) != -1) {
		uint32_t value;

		if (opt == 'h') {
			usage(stdout);
			return 0;
		}
		if (opt >= 1000 && opt <= 1006) {
			if (number(optarg, &value))
				goto invalid;
			switch (opt) {
			case 1000:
				req.settings.window_ms = value;
				break;
			case 1001:
				req.settings.stable_ms = value;
				break;
			case 1002:
				req.settings.min_requests = value;
				break;
			case 1003:
				req.settings.min_pairs = value;
				break;
			case 1004:
				req.settings.dominance_percent = value;
				break;
			case 1005:
				req.settings.sequential_percent = value;
				break;
			case 1006:
				req.settings.random_percent = value;
				break;
			}
		} else if (opt == 1007) {
			if (thresholds(optarg, req.settings.thresholds))
				goto invalid;
		} else if (opt == 's') {
			path = optarg;
		} else if (opt == 'j') {
			json = true;
		} else
			goto invalid;
	}
	if (!path || !*path || strlen(path) >= sizeof(addr.sun_path) ||
	    optind >= argc)
		goto invalid;
	command = argv[optind++];
	if (!strcmp(command, "status"))
		req.operation = FUSE_ADAPTIVE_STATUS;
	else if (!strcmp(command, "workload"))
		req.operation = FUSE_ADAPTIVE_WORKLOAD;
	else if (!strcmp(command, "configure"))
		req.operation = FUSE_ADAPTIVE_CONFIGURE;
	else if (!strcmp(command, "get-config"))
		req.operation = FUSE_ADAPTIVE_GET_CONFIG;
	else if (!strcmp(command, "set-qd")) {
		req.operation = FUSE_ADAPTIVE_SET_DEPTH;
		if (optind >= argc || number(argv[optind++], &req.depth) ||
		    !req.depth)
			goto invalid;
	} else {
		goto invalid;
	}
	if (optind != argc)
		goto invalid;
	memcpy(addr.sun_path, path, strlen(path) + 1);
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    send(fd, &req, sizeof(req), MSG_NOSIGNAL) != sizeof(req)) {
		perror("control connection");
		close(fd);
		return 1;
	}
	reply = malloc(FUSE_ADAPTIVE_REPLY_MAX + 1);
	if (!reply) {
		close(fd);
		return 1;
	}
	pfd = (struct pollfd){ .fd = fd, .events = POLLIN };
	if (poll(&pfd, 1, 5000) <= 0) {
		fputs("control response timed out (accepted operations are not cancelled)\n",
		      stderr);
		goto done;
	}
	len = recv(fd, reply, FUSE_ADAPTIVE_REPLY_MAX, MSG_TRUNC);
	if (len <= 0 || len > FUSE_ADAPTIVE_REPLY_MAX) {
		fputs("invalid or oversized control response\n", stderr);
		goto done;
	}
	reply[len] = '\0';
	if (sscanf(reply, "{\"error\":%d", &error) != 1) {
		fputs("invalid control response\n", stderr);
		goto done;
	}
	if (json)
		fputs(reply, stdout);
	else
		pretty(reply);
	result = error ? 1 : 0;
done:
	free(reply);
	close(fd);
	return result;
invalid:
	usage(stderr);
	return 2;
}
