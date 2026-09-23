// SPDX-License-Identifier: LGPL-2.1-or-later
/* Pure policy tests: no timing sleeps, mounting, or runtime QD changes. */
#define _POSIX_C_SOURCE 200809L
#include "../lib/fuse_qd_policy.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SECOND UINT64_C(1000000000)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static const struct test_rule {
	const char *context;
	unsigned int size, files, requesters, sequential, reads, depth;
} rules[] = {
	{ "dell-c2", 131072, 32, 32, 1, 0, 32 },
	{ "dell-c2", 131072, 32, 32, 1, 100, 2 },
	{ "thinkpad-c2", 4096, 1, 1, 0, 0, 512 },
	{ "thinkpad-c2", 4096, 1, 1, 0, 50, 2 },
	{ "thinkpad-c2", 4096, 32, 32, 0, 25, 512 },
	{ "dell-c6", 1048576, 1, 32, 0, 100, 32 },
	{ "thinkpad-c6", 1048576, 1, 1, 1, 50, 2 },
};

static struct fuse_qd_policy_config config;

static struct fuse_workload_detail sample(unsigned int rule,
					  unsigned int second)
{
	const struct test_rule *r = &rules[rule];
	struct fuse_workload_detail detail = {
		.snapshot = {
			.version = FUSE_WORKLOAD_VERSION,
			.generation = 1,
			.window_id = second,
			.start_ns = second * SECOND,
			.end_ns = (second + 1) * SECOND,
		},
		.files = r->files,
		.requesters = r->requesters,
		.seq_pairs = 999,
		.seq_contiguous = r->sequential ? 999 : 0,
	};
	unsigned int rw, bucket = r->size >= 1048576 ? 3 :
				  r->size >= 131072  ? 2 :
						       r->size >= 32768;

	for (rw = 0; rw < 2; rw++) {
		struct fuse_workload_op_stats *op = &detail.snapshot.op[rw];
		uint64_t count = (rw ? 100 - r->reads : r->reads) * 10;

		if (!count)
			continue;
		op->count[bucket] = count;
		op->bytes[bucket] = count * r->size;
		op->min_size = op->max_size = r->size;
		op->files = r->files > 1 ? 2 : 1;
		op->requesters = r->requesters > 1 ? 2 : 1;
		op->seq_pairs = count - 1;
		op->seq_contiguous = r->sequential ? count - 1 : 0;
	}
	return detail;
}

static void init(struct fuse_qd_policy *policy, unsigned int rule)
{
	assert(!fuse_qd_policy_init(policy, &config, rules[rule].context,
				    1000));
}

static struct fuse_qd_policy_result update(struct fuse_qd_policy *policy,
					   struct fuse_workload_detail *detail)
{
	struct fuse_qd_policy_result result;

	assert(!fuse_qd_policy_update(policy, detail, &result));
	return result;
}

static void all_rules_and_contexts(void)
{
	struct fuse_qd_policy policy;
	struct fuse_qd_policy_result result;
	struct fuse_workload_detail detail;
	static const char *const contexts[] = {
		"none", "dell-c2", "thinkpad-c2", "dell-c6", "thinkpad-c6",
	};
	unsigned int i, second, c;

	assert(fuse_qd_policy_max_depth(&config, "none") == 0);
	assert(fuse_qd_policy_max_depth(&config, "dell-c2") == 32);
	assert(fuse_qd_policy_max_depth(&config, "thinkpad-c2") == 512);
	assert(fuse_qd_policy_max_depth(&config, "dell-c6") == 32);
	assert(fuse_qd_policy_max_depth(&config, "thinkpad-c6") == 2);
	for (i = 0; i < ARRAY_SIZE(rules); i++) {
		init(&policy, i);
		for (second = 1; second <= 11; second++) {
			detail = sample(i, second);
			result = update(&policy, &detail);
			assert(result.rule_id == i + 1);
			assert(result.target_depth == rules[i].depth);
			assert(result.read_percent == rules[i].reads);
			assert(result.files == rules[i].files);
			assert(result.requesters == rules[i].requesters);
			assert(result.stable_ns == (second - 1) * SECOND);
			assert(result.stable == (second == 11));
			assert(strcmp(result.rule_name, "none"));
		}
		for (c = 0; c < ARRAY_SIZE(contexts); c++) {
			if (!strcmp(contexts[c], rules[i].context))
				continue;
			memcpy(policy.context, contexts[c], strlen(contexts[c]) + 1);
			result = update(&policy, &detail);
			assert(!result.rule_id && !result.target_depth &&
			       !result.stable);
		}
	}
}

static void exact_size_and_cardinality(void)
{
	struct fuse_qd_policy policy;
	struct fuse_workload_detail detail;
	struct fuse_qd_policy_result result;
	unsigned int i, rw, bucket, cardinality;

	for (i = 0; i < ARRAY_SIZE(rules); i++) {
		init(&policy, i);
		/* Doubling an observed size must not reuse its benchmark rule,
		 * even when the larger size still belongs to the same bucket.
		 */
		detail = sample(i, 1);
		for (rw = 0; rw < 2; rw++) {
			struct fuse_workload_op_stats *op =
				&detail.snapshot.op[rw];

			op->min_size *= 2;
			op->max_size *= 2;
			for (bucket = 0; bucket < 4; bucket++)
				op->bytes[bucket] *= 2;
		}
		assert(!update(&policy, &detail).rule_id);
		detail = sample(i, 1);
		rw = rules[i].reads ? 0 : 1;
		detail.snapshot.op[rw].max_size++;
		assert(!update(&policy, &detail).rule_id);
		if (rules[i].requesters == 32) {
			for (cardinality = 31; cardinality <= 33;
			     cardinality++) {
				detail = sample(i, 1);
				detail.requesters = cardinality;
				result = update(&policy, &detail);
				assert(!!result.rule_id == (cardinality == 32));
			}
		}
		if (rules[i].files == 32) {
			for (cardinality = 31; cardinality <= 33;
			     cardinality++) {
				detail = sample(i, 1);
				detail.files = cardinality;
				result = update(&policy, &detail);
				assert(!!result.rule_id == (cardinality == 32));
			}
		}
	}
}

static void ratio_and_sequence_bounds(void)
{
	struct fuse_qd_policy policy;
	struct fuse_workload_detail detail;
	unsigned int i, read_count, rw, bucket;

	for (i = 0; i < ARRAY_SIZE(rules); i++) {
		unsigned int lower = rules[i].reads * 10;
		unsigned int upper = lower;

		if (lower && lower != 1000) {
			lower -= config.ratio_tolerance * 10;
			upper += config.ratio_tolerance * 10;
		}
		init(&policy, i);
		for (read_count = lower ? lower - 1 : 0;
		     read_count <= (upper < 1000 ? upper + 1 : 1000);
		     read_count++) {
			detail = sample(i, 1);
			bucket = rules[i].size == 4096	 ? 0 :
				 rules[i].size == 131072 ? 2 :
							   3;
			for (rw = 0; rw < 2; rw++) {
				struct fuse_workload_op_stats *op =
					&detail.snapshot.op[rw];
				uint64_t count = rw ? 1000 - read_count :
						      read_count;

				memset(op, 0, sizeof(*op));
				if (!count)
					continue;
				op->count[bucket] = count;
				op->bytes[bucket] = count * rules[i].size;
				op->min_size = op->max_size = rules[i].size;
				op->files = detail.files > 1 && count > 1 ? 2 :
									    1;
				op->requesters =
					detail.requesters > 1 && count > 1 ? 2 :
									     1;
			}
			assert(!!update(&policy, &detail).rule_id ==
			       (read_count >= lower && read_count <= upper));
		}
		detail = sample(i, 1);
		detail.seq_pairs = 1000;
		detail.seq_contiguous = rules[i].sequential ? 800 : 200;
		assert(update(&policy, &detail).rule_id == i + 1);
		detail.seq_contiguous += rules[i].sequential ? -1 : 1;
		assert(!update(&policy, &detail).rule_id);
		detail.seq_pairs = 1;
		detail.seq_contiguous = 0;
		assert(!update(&policy, &detail).rule_id);
	}
}

static void persistence_and_resets(void)
{
	struct fuse_qd_policy policy;
	struct fuse_workload_detail detail;
	struct fuse_qd_policy_result result;
	unsigned int i, flag;

	init(&policy, 2);
	for (i = 1; i <= 11; i++) {
		detail = sample(2, i);
		assert(update(&policy, &detail).stable == (i == 11));
	}
	detail = sample(2, 13); /* Missing window. */
	assert(!update(&policy, &detail).stable_ns);
	detail = sample(2, 14);
	detail.snapshot.generation++;
	assert(!update(&policy, &detail).stable_ns);
	assert(!update(&policy, NULL).rule_id);
	detail = sample(2, 15);
	assert(!update(&policy, &detail).stable_ns);
	detail = sample(3, 16); /* Different rule with the same profile. */
	result = update(&policy, &detail);
	assert(result.rule_id == 4 && !result.stable_ns);
	detail = sample(3, 17);
	for (i = 0; i < 2; i++) {
		detail.snapshot.op[i].count[1] = detail.snapshot.op[i].count[0];
		detail.snapshot.op[i].bytes[1] = detail.snapshot.op[i].bytes[0];
		detail.snapshot.op[i].count[0] =
			detail.snapshot.op[i].bytes[0] = 0;
	}
	result = update(&policy, &detail);
	assert(result.rule_id == 4 && result.profile == 1 && !result.stable_ns);
	for (flag = 1; flag <= FUSE_WORKLOAD_DAX; flag <<= 1) {
		if (flag == FUSE_WORKLOAD_PASSTHROUGH)
			continue;
		detail = sample(3, 18);
		detail.snapshot.flags = flag;
		assert(!update(&policy, &detail).rule_id);
		detail = sample(3, 19);
		assert(!update(&policy, &detail).stable_ns);
	}
	detail = sample(3, 20);
	memset(detail.snapshot.op, 0, sizeof(detail.snapshot.op));
	detail.files = detail.requesters = 0;
	detail.seq_pairs = detail.seq_contiguous = 0;
	assert(!update(&policy, &detail).rule_id);
	detail = sample(3, 21);
	assert(!update(&policy, &detail).stable_ns);
	detail = sample(3, 22);
	detail.snapshot.end_ns += 3 * SECOND;
	assert(!update(&policy, &detail).rule_id);
	detail = sample(3, 23);
	detail.files = 2; /* Unsupported shape. */
	assert(!update(&policy, &detail).rule_id);
	detail = sample(3, 24);
	assert(!update(&policy, &detail).stable_ns);
	policy.settings.stable_ms = 12000;
	fuse_qd_policy_reset(&policy);
	for (i = 1; i <= 13; i++) {
		detail = sample(3, i);
		assert(update(&policy, &detail).stable == (i == 13));
	}
}

static void invalid_and_overflow(void)
{
	struct fuse_qd_policy policy;
	struct fuse_workload_detail detail;
	struct fuse_qd_policy_result result;
	unsigned int i;

	init(&policy, 2);
	assert(fuse_qd_policy_init(NULL, &config, "dell-c2", 1000) == -EINVAL);
	assert(fuse_qd_policy_init(&policy, &config, "unknown", 1000) ==
	       -EINVAL);
	for (i = 0; i < 11; i++) {
		detail = sample(2, 1);
		switch (i) {
		case 0:
			detail.snapshot.version++;
			break;
		case 1:
			detail.snapshot.generation = 0;
			break;
		case 2:
			detail.snapshot.window_id = 0;
			break;
		case 3:
			detail.snapshot.end_ns = detail.snapshot.start_ns;
			break;
		case 4:
			detail.files = 34;
			break;
		case 5:
			detail.seq_contiguous = detail.seq_pairs + 1;
			break;
		case 6:
			detail.snapshot.op[1].count[1] = UINT64_MAX;
			break;
		case 7:
			detail.snapshot.op[0] = detail.snapshot.op[1];
			detail.snapshot.op[0].bytes[0] = UINT64_MAX;
			break;
		case 8:
			detail.snapshot.op[1].bytes[0]--;
			break;
		case 9:
			detail.snapshot.op[1].requesters = 3;
			break;
		case 10:
			detail.seq_pairs = 1001;
			break;
		}
		assert(fuse_qd_policy_update(&policy, &detail, &result) ==
		       -EINVAL);
		assert(!policy.candidate_rule);
	}
	/* Exercise large-count ratio arithmetic without overflowing byte sums. */
	detail = sample(2, 1);
	detail.snapshot.op[1].min_size = detail.snapshot.op[1].max_size = 1;
	detail.snapshot.op[1].count[0] = UINT64_MAX;
	detail.snapshot.op[1].bytes[0] = UINT64_MAX;
	assert(!update(&policy, &detail).rule_id);
	detail.snapshot.op[0] = detail.snapshot.op[1];
	assert(fuse_qd_policy_update(&policy, &detail, &result) == -EINVAL);
}

static int load_text(const char *text, struct fuse_qd_policy_config *parsed)
{
	char path[] = "/tmp/fuse-qd-policy-XXXXXX";
	int fd = mkstemp(path), ret;
	FILE *file;

	assert(fd >= 0);
	file = fdopen(fd, "w");
	assert(file && fputs(text, file) >= 0);
	assert(!fclose(file));
	ret = fuse_qd_policy_load(path, parsed);
	assert(!unlink(path));
	return ret;
}

static void configuration_files(void)
{
	static const char *const invalid[] = {
		"",
		"unknown 1\nrule p n 1 1 4096 rand 0 2\n",
		"stable_ms 10000\nstable_ms 20000\nrule p n 1 1 4096 rand 0 2\n",
		"stable_ms -1\nrule p n 1 1 4096 rand 0 2\n",
		"window_ms 4294967296\nrule p n 1 1 4096 rand 0 2\n",
		"ratio_tolerance 50\nrule p n 1 1 4096 rand 0 2\n",
		"thresholds 0 8192 16384\nrule p n 1 1 4096 rand 0 2\n",
		"thresholds 8192 8192 16384\nrule p n 1 1 4096 rand 0 2\n",
		"thresholds 16384 8192 32768\nrule p n 1 1 4096 rand 0 2\n",
		"thresholds 4096 8192\nrule p n 1 1 4096 rand 0 2\n",
		"thresholds 4096 8192 16384 32768\nrule p n 1 1 4096 rand 0 2\n",
		"thresholds 1 2 18446744073709551616\nrule p n 1 1 4096 rand 0 2\n",
		"thresholds 1 2 3\nthresholds 4 5 6\nrule p n 1 1 4096 rand 0 2\n",
		"rule none n 1 1 4096 rand 0 2\n",
		"rule p n 33 1 4096 rand 0 2\n",
		"rule p n 1 0 4096 rand 0 2\n",
		"rule p n 1 1 0 rand 0 2\n",
		"rule p n 1 1 18446744073709551616 rand 0 2\n",
		"rule p n 1 1 4096 rand 101 2\n",
		"rule p n 1 1 4096 rand 0 0\n",
		"rule p n 1 1 4096 rand 0 4294967296\n",
		"rule p n 1 1 4096 random 0 2\n",
		"rule p\" n 1 1 4096 rand 0 2\n",
		"rule p n 1 1 4096 rand 0 2 extra\n",
		"rule p n 1 1 4096 rand 0 2\nrule p n 1 1 4096 seq 0 32\n",
		"rule p a 1 1 4096 rand 45 2\nrule p b 1 1 4096 rand 50 32\n",
	};
	struct fuse_qd_policy_config parsed;
	struct fuse_qd_policy policy;
	struct fuse_workload_detail detail;
	struct fuse_qd_policy_result result;
	char long_line[600], many_rules[16384];
	size_t offset = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(invalid); i++) {
		assert(load_text(invalid[i], &parsed) == -EINVAL);
		assert(!parsed.nr_rules);
	}
	memset(long_line, 'a', sizeof(long_line));
	long_line[sizeof(long_line) - 2] = '\n';
	long_line[sizeof(long_line) - 1] = 0;
	assert(load_text(long_line, &parsed) == -EINVAL);
	for (i = 0; i <= FUSE_QD_POLICY_MAX_RULES; i++)
		offset += snprintf(many_rules + offset,
				   sizeof(many_rules) - offset,
				   "rule p%u n 1 1 4096 rand 0 2\n", i);
	assert(load_text(many_rules, &parsed) == -EINVAL);
	assert(fuse_qd_policy_load(NULL, &parsed) == -EINVAL);
	assert(!parsed.nr_rules);
	/* An arbitrary new profile, size, ratio, timer and target work without
	 * adding any conditions or host names to the compiled matcher.
	 */
	assert(!load_text(
		"# New experiment\nwindow_ms 250\nstable_ms 750\n"
		"min_requests 1\nmin_pairs 1\ndominance_percent 90\n"
		"sequential_percent 95\nrandom_percent 5\nratio_tolerance 2\n"
		"thresholds 8192 16384 65536\n"
		"rule new-machine.custom new_rule 1 1 8192 rand 50 16 # comment\n",
		&parsed));
	assert(fuse_qd_policy_max_depth(&parsed, "new-machine.custom") == 16);
	assert(parsed.settings.thresholds[0] == 8192);
	assert(parsed.settings.thresholds[1] == 16384);
	assert(parsed.settings.thresholds[2] == 65536);
	assert(!fuse_qd_policy_init(&policy, &parsed, "new-machine.custom",
				    250));
	for (i = 1; i <= 4; i++) {
		unsigned int rw;

		detail = sample(3, i);
		detail.snapshot.start_ns = i * SECOND / 4;
		detail.snapshot.end_ns = (i + 1) * SECOND / 4;
		for (rw = 0; rw < 2; rw++) {
			struct fuse_workload_op_stats *op =
				&detail.snapshot.op[rw];

			op->min_size *= 2;
			op->max_size *= 2;
			op->count[1] = op->count[0];
			op->bytes[1] = op->bytes[0] * 2;
			op->count[0] = op->bytes[0] = 0;
		}
		result = update(&policy, &detail);
		assert(result.target_depth == 16 && result.stable == (i == 4));
		assert(result.profile == 1);
	}
}

static void passthrough_policy(void)
{
	static const uint32_t invalid_flags[] = {
		FUSE_WORKLOAD_WORKER, FUSE_WORKLOAD_APPEND, FUSE_WORKLOAD_DAX,
		UINT32_C(1) << 31,
	};
	struct fuse_qd_policy_config parsed;
	struct fuse_qd_policy policy;
	struct fuse_workload_detail detail;
	struct fuse_qd_policy_result result;
	unsigned int second, i;

	/* A synthetic native rule, not a renamed historical measured policy. */
	assert(!load_text("rule native-fixture mixed-read 1 1 4096 rand 50 32\n",
			 &parsed));
	assert(!fuse_qd_policy_init(&policy, &parsed, "native-fixture", 1000));
	for (second = 1; second <= 11; second++) {
		detail = sample(3, second);
		detail.snapshot.flags = FUSE_WORKLOAD_PASSTHROUGH;
		result = update(&policy, &detail);
		assert(result.rule_id == 1 && result.target_depth == 32);
		assert(result.stable_ns == (second - 1) * SECOND);
		assert(result.stable == (second == 11));
		assert(detail.snapshot.flags == FUSE_WORKLOAD_PASSTHROUGH);
	}
	for (i = 0; i < ARRAY_SIZE(invalid_flags); i++) {
		detail = sample(3, second++);
		detail.snapshot.flags = FUSE_WORKLOAD_PASSTHROUGH |
			invalid_flags[i];
		result = update(&policy, &detail);
		assert(!result.rule_id && !result.target_depth && !result.stable);
		/* A rejected native window must reset the full persistence timer. */
		for (unsigned int elapsed = 0; elapsed <= 10; elapsed++) {
			detail = sample(3, second++);
			detail.snapshot.flags = FUSE_WORKLOAD_PASSTHROUGH;
			result = update(&policy, &detail);
			assert(result.rule_id == 1 && result.target_depth == 32);
			assert(result.stable_ns == elapsed * SECOND);
			assert(result.stable == (elapsed == 10));
		}
	}
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	assert(!fuse_qd_policy_load(argv[1], &config));
	assert(config.nr_rules == 7);
	all_rules_and_contexts();
	exact_size_and_cardinality();
	ratio_and_sequence_bounds();
	persistence_and_resets();
	invalid_and_overflow();
	configuration_files();
	passthrough_policy();
	puts("QD policy tests passed");
	return 0;
}
