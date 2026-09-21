// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fuse_qd_policy.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NS_PER_MS UINT64_C(1000000)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static bool identifier(const char *name)
{
	static const char allowed[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";

	return *name && strlen(name) < FUSE_QD_POLICY_NAME_SIZE &&
	       strspn(name, allowed) == strlen(name);
}

static bool number(const char *text, uint64_t limit, uint64_t *value)
{
	char *end;

	if (!*text || strspn(text, "0123456789") != strlen(text))
		return false;
	errno = 0;
	*value = strtoull(text, &end, 10);
	return !errno && !*end && *value <= limit;
}

static void ratio_bounds(unsigned int ratio, unsigned int tolerance,
			 unsigned int *low, unsigned int *high)
{
	*low = *high = ratio;
	if (ratio && ratio != 100) {
		*low = ratio > tolerance ? ratio - tolerance : 0;
		*high = ratio + tolerance < 100 ? ratio + tolerance : 100;
	}
}

static bool valid_rules(const struct fuse_qd_policy_config *config)
{
	unsigned int i, j, low, high, other_low, other_high;

	for (i = 0; i < config->nr_rules; i++) {
		const struct fuse_qd_policy_rule *r = &config->rules[i];

		ratio_bounds(r->read_percent, config->ratio_tolerance, &low,
			     &high);
		for (j = 0; j < i; j++) {
			const struct fuse_qd_policy_rule *p = &config->rules[j];

			if (strcmp(r->context, p->context))
				continue;
			if (!strcmp(r->name, p->name))
				return false;
			if (r->size != p->size || r->files != p->files ||
			    r->requesters != p->requesters ||
			    r->sequential != p->sequential)
				continue;
			ratio_bounds(p->read_percent, config->ratio_tolerance,
				     &other_low, &other_high);
			if (low <= other_high && other_low <= high)
				return false;
		}
	}
	return config->nr_rules != 0;
}

static int read_config(FILE *file, struct fuse_qd_policy_config *config)
{
	static const char *const globals[] = {
		"window_ms",	  "stable_ms",	       "min_requests",
		"min_pairs",	  "dominance_percent", "sequential_percent",
		"random_percent", "ratio_tolerance",
	};
	uint32_t *values[] = {
		&config->settings.window_ms,
		&config->settings.stable_ms,
		&config->settings.min_requests,
		&config->settings.min_pairs,
		&config->settings.dominance_percent,
		&config->settings.sequential_percent,
		&config->settings.random_percent,
		&config->ratio_tolerance,
	};
	char line[512], *tokens[10], *cursor, *comment;
	unsigned int seen = 0, count, i;
	uint64_t n[6];

	while (fgets(line, sizeof(line), file)) {
		if (!strchr(line, '\n') && !feof(file))
			return -EINVAL;
		comment = strchr(line, '#');
		if (comment)
			*comment = 0;
		count = 0;
		cursor = line;
		while (*(cursor += strspn(cursor, " \t\r\n"))) {
			if (count == ARRAY_SIZE(tokens))
				return -EINVAL;
			tokens[count++] = cursor;
			cursor += strcspn(cursor, " \t\r\n");
			if (*cursor)
				*cursor++ = 0;
		}
		if (!count)
			continue;
		if (!strcmp(tokens[0], "rule")) {
			struct fuse_qd_policy_rule *r;

			if (count != 9 ||
			    config->nr_rules == FUSE_QD_POLICY_MAX_RULES ||
			    !identifier(tokens[1]) || !identifier(tokens[2]) ||
			    !strcmp(tokens[1], "none") ||
			    !number(tokens[3], 32, &n[0]) || !n[0] ||
			    !number(tokens[4], 32, &n[1]) || !n[1] ||
			    !number(tokens[5], UINT64_MAX, &n[2]) || !n[2] ||
			    (strcmp(tokens[6], "seq") &&
			     strcmp(tokens[6], "rand")) ||
			    !number(tokens[7], 100, &n[3]) ||
			    !number(tokens[8], UINT32_MAX, &n[4]) || !n[4])
				return -EINVAL;
			r = &config->rules[config->nr_rules++];
			memcpy(r->context, tokens[1], strlen(tokens[1]) + 1);
			memcpy(r->name, tokens[2], strlen(tokens[2]) + 1);
			r->requesters = n[0];
			r->files = n[1];
			r->size = n[2];
			r->sequential = !strcmp(tokens[6], "seq");
			r->read_percent = n[3];
			r->depth = n[4];
			continue;
		}
		if (!strcmp(tokens[0], "thresholds")) {
			unsigned int mask = 1U << ARRAY_SIZE(globals);

			if (count != 4 || (seen & mask))
				return -EINVAL;
			for (i = 0; i < 3; i++)
				if (!number(tokens[i + 1], UINT64_MAX,
					    &config->settings.thresholds[i]))
					return -EINVAL;
			seen |= mask;
			continue;
		}
		for (i = 0; i < ARRAY_SIZE(globals); i++)
			if (!strcmp(tokens[0], globals[i]))
				break;
		if (i == ARRAY_SIZE(globals) || count != 2 ||
		    (seen & (1U << i)) || !number(tokens[1], UINT32_MAX, &n[0]))
			return -EINVAL;
		seen |= 1U << i;
		*values[i] = n[0];
	}
	if (ferror(file))
		return -EIO;
	return fuse_workload_validate(&config->settings) ||
			       config->ratio_tolerance > 49 ||
			       !valid_rules(config) ?
		       -EINVAL :
		       0;
}

int fuse_qd_policy_load(const char *path, struct fuse_qd_policy_config *config)
{
	FILE *file;
	int err;

	if (!config)
		return -EINVAL;
	memset(config, 0, sizeof(*config));
	if (!path)
		return -EINVAL;
	file = fopen(path, "r");
	if (!file)
		return -errno;
	fuse_workload_defaults(&config->settings);
	config->ratio_tolerance = 5;
	err = read_config(file, config);
	if (fclose(file) && !err)
		err = -EIO;
	if (err)
		memset(config, 0, sizeof(*config));
	return err;
}

uint32_t fuse_qd_policy_max_depth(const struct fuse_qd_policy_config *config,
				  const char *context)
{
	uint32_t depth = 0;
	unsigned int i;

	if (!config || !context)
		return 0;
	for (i = 0; i < config->nr_rules; i++)
		if (!strcmp(config->rules[i].context, context) &&
		    config->rules[i].depth > depth)
			depth = config->rules[i].depth;
	return depth;
}

void fuse_qd_policy_reset(struct fuse_qd_policy *policy)
{
	policy->last_end_ns = policy->last_window = policy->last_generation = 0;
	policy->candidate_since = 0;
	policy->candidate_rule = 0;
	policy->candidate_profile = UINT32_MAX;
}

int fuse_qd_policy_init(struct fuse_qd_policy *policy,
			const struct fuse_qd_policy_config *config,
			const char *context, uint32_t window_ms)
{
	if (!policy || !config || !context || !identifier(context) ||
	    !fuse_qd_policy_max_depth(config, context))
		return -EINVAL;
	policy->settings = config->settings;
	policy->settings.window_ms = window_ms;
	if (fuse_workload_validate(&policy->settings))
		return -EINVAL;
	policy->config = config;
	memcpy(policy->context, context, strlen(context) + 1);
	fuse_qd_policy_reset(policy);
	return 0;
}

/* Exact ratio bounds without multiplying potentially large counts by 100. */
static uint64_t fraction(uint64_t total, unsigned int percent, bool round_up)
{
	return total / 100 * percent +
	       (total % 100 * percent + (round_up ? 99 : 0)) / 100;
}

static unsigned int percentage(uint64_t value, uint64_t total)
{
	unsigned int low = 0, high = 100;

	while (low < high) {
		unsigned int mid = low + (high - low + 1) / 2;

		if (value >= fraction(total, mid, true))
			low = mid;
		else
			high = mid - 1;
	}
	return low;
}

static bool add(uint64_t *total, uint64_t value)
{
	if (UINT64_MAX - *total < value)
		return false;
	*total += value;
	return true;
}

static bool matches(const struct fuse_qd_policy_rule *rule,
		    const struct fuse_workload_detail *detail,
		    const struct fuse_workload_settings *settings,
		    const uint64_t count[2], uint64_t total,
		    unsigned int tolerance)
{
	unsigned int rw, low, high;

	if (detail->files != rule->files ||
	    detail->requesters != rule->requesters)
		return false;
	for (rw = 0; rw < 2; rw++)
		if (count[rw] &&
		    (detail->snapshot.op[rw].min_size != rule->size ||
		     detail->snapshot.op[rw].max_size != rule->size))
			return false;
	if (!rule->read_percent || rule->read_percent == 100) {
		if (count[rule->read_percent ? 1 : 0])
			return false;
	} else {
		ratio_bounds(rule->read_percent, tolerance, &low, &high);
		if (!count[0] || !count[1] ||
		    count[0] < fraction(total, low, true) ||
		    count[0] > fraction(total, high, false))
			return false;
	}
	return rule->sequential ?
		       detail->seq_contiguous >=
			       fraction(detail->seq_pairs,
					settings->sequential_percent, true) :
		       detail->seq_contiguous <=
			       fraction(detail->seq_pairs,
					settings->random_percent, false);
}

int fuse_qd_policy_update(struct fuse_qd_policy *policy,
			  const struct fuse_workload_detail *detail,
			  struct fuse_qd_policy_result *result)
{
	const struct fuse_workload_snapshot *snapshot;
	const struct fuse_workload_settings *settings;
	uint64_t count[2] = { 0, 0 }, buckets[4] = { 0 }, total = 0, bytes = 0;
	uint64_t window_ns, duration;
	unsigned int rw, bucket, dominant = 0, i;

	if (!policy || !result)
		return -EINVAL;
	*result = (struct fuse_qd_policy_result){
		.profile = UINT32_MAX,
		.rule_name = "none",
	};
	if (!detail) {
		fuse_qd_policy_reset(policy);
		return 0;
	}
	snapshot = &detail->snapshot;
	settings = &policy->settings;
	if (snapshot->version != FUSE_WORKLOAD_VERSION ||
	    !snapshot->generation || !snapshot->window_id ||
	    snapshot->end_ns <= snapshot->start_ns || detail->files > 33 ||
	    detail->requesters > 33 ||
	    detail->seq_contiguous > detail->seq_pairs)
		goto invalid;
	for (rw = 0; rw < 2; rw++) {
		const struct fuse_workload_op_stats *op = &snapshot->op[rw];

		for (bucket = 0; bucket < 4; bucket++) {
			if (!add(&count[rw], op->count[bucket]) ||
			    !add(&buckets[bucket], op->count[bucket]) ||
			    !add(&bytes, op->bytes[bucket]) ||
			    (!op->count[bucket] && op->bytes[bucket]) ||
			    (op->count[bucket] &&
			     (op->bytes[bucket] / op->count[bucket] <
				      op->min_size ||
			      op->bytes[bucket] / op->count[bucket] >
				      op->max_size ||
			      (op->bytes[bucket] / op->count[bucket] ==
				       op->max_size &&
			       op->bytes[bucket] % op->count[bucket]))))
				goto invalid;
		}
		if (!add(&total, count[rw]) ||
		    op->seq_contiguous > op->seq_pairs ||
		    op->seq_pairs > count[rw] || op->files > 2 ||
		    op->requesters > 2 || op->files > count[rw] ||
		    op->requesters > count[rw] || op->files > detail->files ||
		    op->requesters > detail->requesters ||
		    (count[rw] &&
		     (!op->min_size || op->min_size > op->max_size ||
		      !op->files || !op->requesters)) ||
		    (!count[rw] && (op->min_size || op->max_size || op->files ||
				    op->requesters)))
			goto invalid;
	}
	if (detail->seq_pairs > total || detail->files > total ||
	    detail->requesters > total ||
	    (total && (!detail->files || !detail->requesters)))
		goto invalid;
	window_ns = (uint64_t)settings->window_ms * NS_PER_MS;
	duration = snapshot->end_ns - snapshot->start_ns;
	if (snapshot->generation != policy->last_generation ||
	    policy->last_window == UINT64_MAX ||
	    snapshot->window_id != policy->last_window + 1 ||
	    snapshot->start_ns != policy->last_end_ns)
		fuse_qd_policy_reset(policy);
	policy->last_generation = snapshot->generation;
	policy->last_window = snapshot->window_id;
	policy->last_end_ns = snapshot->end_ns;
	result->files = detail->files;
	result->requesters = detail->requesters;
	if (!total || total < settings->min_requests || snapshot->flags ||
	    detail->seq_pairs < settings->min_pairs ||
	    duration < window_ns / 2 || duration > window_ns * 2)
		goto unknown;
	result->read_percent = percentage(count[0], total);
	for (bucket = 1; bucket < 4; bucket++)
		if (buckets[bucket] > buckets[dominant])
			dominant = bucket;
	if (buckets[dominant] <
	    fraction(total, settings->dominance_percent, true))
		goto unknown;
	result->profile = dominant;
	for (i = 0; i < policy->config->nr_rules; i++) {
		const struct fuse_qd_policy_rule *rule =
			&policy->config->rules[i];

		if (strcmp(rule->context, policy->context) ||
		    !matches(rule, detail, settings, count, total,
			     policy->config->ratio_tolerance))
			continue;
		result->rule_id = i + 1;
		result->rule_name = rule->name;
		result->target_depth = rule->depth;
		if (policy->candidate_rule != result->rule_id ||
		    policy->candidate_profile != result->profile) {
			policy->candidate_rule = result->rule_id;
			policy->candidate_profile = result->profile;
			policy->candidate_since = snapshot->end_ns;
		}
		result->stable_ns = snapshot->end_ns - policy->candidate_since;
		result->stable = result->stable_ns >=
				 (uint64_t)settings->stable_ms * NS_PER_MS;
		return 0;
	}
unknown:
	policy->candidate_rule = 0;
	policy->candidate_profile = UINT32_MAX;
	policy->candidate_since = 0;
	return 0;
invalid:
	fuse_qd_policy_reset(policy);
	return -EINVAL;
}
