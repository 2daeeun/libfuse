#!/usr/bin/env python3
"""Run the production READ/WRITE cohort and completion functions with pthreads.

Only BPF-map, pinned-stat and reply boundaries are mocked. No mount or daemon
artifact is built. EXTFUSE_READ_COHORT_SOURCE can select an isolated candidate.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


SOURCE = Path(os.environ.get("EXTFUSE_READ_COHORT_SOURCE",
                            Path(__file__).with_name("extfuse_passthrough.c")))


def extract(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if not depth:
            return source[start:end + 1] + (";" if marker.startswith("struct ") else "")
    raise AssertionError(f"unterminated {marker}")


HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define PERF_MODE_HIT 1
#define PERF_CACHE_MUTATION_MAX_INODES 2
#define PERF_INODE_GENERATION_BUCKETS 2
#define EXTFUSE_NATIVE_STATE_ACTIVE_BITS 8
#define EXTFUSE_NATIVE_STATE_ACTIVE_MASK 255
#define EXTFUSE_NATIVE_STATE_SEQUENCE_MAX (UINT64_MAX >> 8)
#define EXTFUSE_DAEMON_IO_MAP 1
#define EXTFUSE_NATIVE_IO_MAP 2
#define PERF_CAPABILITY_XATTR "security.capability"
#define PERF_IO_COHORT_BUSY UINT64_MAX
#define PERF_IO_COHORT_JOIN_ATTEMPTS 4
typedef uint64_t fuse_ino_t;
struct request { unsigned replies; int error; size_t size; };
typedef struct request *fuse_req_t;
struct fuse_file_info { bool writepage; };
enum perf_cache_attr_outcome { PERF_CACHE_ATTR_DISABLED, PERF_CACHE_ATTR_PUBLISHED,
 PERF_CACHE_ATTR_UNSTABLE, PERF_CACHE_ATTR_SUPPRESSED, PERF_CACHE_ATTR_MISSING,
 PERF_CACHE_ATTR_ERROR };
struct extfuse_io_state { uint64_t attr_state, xattr_state; };
@STRUCTS@
struct perf_cache_lockset { int unused; };
struct lo_data { double timeout; };
struct lo_inode { int fd; dev_t dev; ino_t ino; };
static struct {
 int mode;
 void *session;
 atomic_bool cache_bypass, xattr_cache_bypass;
 bool passthrough_coherence_v2_requested, wbcache_passthrough_requested;
 _Atomic(struct perf_inode_generation *) inode_generations[2];
 struct {
  atomic_uint_fast64_t cache_bypass_errors, passthrough_state_errors;
  atomic_uint_fast64_t daemon_io_state_records, daemon_io_active_residuals;
  atomic_uint_fast64_t daemon_io_state_audit_errors, native_io_state_records;
  atomic_uint_fast64_t native_io_active_residuals, native_io_state_audit_errors;
 } counters;
} perf_state = { .mode = PERF_MODE_HIT };
static pthread_mutex_t stripe = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t xstripe = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool held;
static _Thread_local bool xheld;
static atomic_uint locks, attempts, map_updates, attrs, stats, lower_done;
static atomic_uint refills, exits;
static bool revoke;
static atomic_uint hold_begin, begin_entered, hold_stat, stat_entered;
static atomic_bool allow_begin, allow_stat, fail_map, fatal_map, fail_stat;
static atomic_bool fail_attr;
static bool expect_active_stat;
static atomic_uint_fast64_t map_attr, map_xattr, attr_token, attr_atime;
static struct lo_data lo = { 1.0 };
static struct lo_inode inode = { 77, 3, 19 };
static void test_lock(pthread_mutex_t *lock)
{ if (lock == &xstripe) {
   assert(!held && !xheld); pthread_mutex_lock(lock); xheld = true; return;
  }
  assert(lock == &stripe && !held); atomic_fetch_add(&attempts, 1);
  pthread_mutex_lock(lock); held = true; atomic_fetch_add(&locks, 1); }
static void test_unlock(pthread_mutex_t *lock)
{ if (lock == &xstripe) {
   assert(xheld); xheld = false; pthread_mutex_unlock(lock); return;
  }
  assert(lock == &stripe && held); held = false; pthread_mutex_unlock(lock); }
#define pthread_mutex_lock test_lock
#define pthread_mutex_unlock test_unlock
static pthread_mutex_t *cache_lock_for_inode(fuse_ino_t ino)
{ (void)ino; return &stripe; }
static size_t inode_generation_bucket(fuse_ino_t ino) { return ino % 2; }
static bool metadata_hits_enabled(void) { return true; }
static void counter_increment(atomic_uint_fast64_t *counter)
{ atomic_fetch_add(counter, 1); }
static uint64_t counter_value(atomic_uint_fast64_t *counter)
{ return atomic_load(counter); }
static void disable_all_caches_locked(const char *why)
{ (void)why; assert(held); perf_state.cache_bypass = perf_state.xattr_cache_bypass = true; }
static void cache_mutation_lock(struct perf_cache_mutation *mutation,
                                struct perf_cache_lockset *locks_unused)
{ (void)mutation; (void)locks_unused; pthread_mutex_lock(&stripe); }
static void cache_mutation_unlock(struct perf_cache_lockset *locks_unused)
{ (void)locks_unused; pthread_mutex_unlock(&stripe); }
@LOOKUP@
static bool publish_inode_generation_locked(fuse_ino_t ino,
 struct perf_inode_generation *state, const char *reason)
{
 (void)ino; assert(held);
 if (strstr(reason, "begin") && atomic_exchange(&hold_begin, 0)) {
  atomic_store(&begin_entered, 1);
  while (!atomic_load(&allow_begin)) sched_yield();
 }
 if (atomic_exchange(&fail_map, false)) {
  disable_all_caches_locked("map-failure");
  if (atomic_load(&fatal_map)) counter_increment(&perf_state.counters.cache_bypass_errors);
  return false;
 }
 atomic_store(&map_attr, (state->generation << 8) | state->active);
 atomic_store(&map_xattr, (state->xattr_generation << 8) | state->xattr_active);
 atomic_fetch_add(&map_updates, 1); return true;
}
static bool native_state_snapshot_locked(fuse_ino_t ino, uint64_t *value,
 const char *why, bool xattr)
{ (void)ino; (void)why; (void)xattr; assert(held); *value = 0; return true; }
@MUTATION@
static atomic_uint cas_failures, cas_calls;
static bool compare_join(_Atomic uint64_t *object, uint64_t *expected,
                         uint64_t desired, memory_order success, memory_order failure)
{
 if (*expected && *expected < PERF_IO_COHORT_BUSY - 1) {
  cas_calls++;
  if (cas_failures) {
   cas_failures--;
   /* A peer joins and leaves before our retry; count returns to the same value. */
   atomic_fetch_add(object, 1);
   uint64_t changed = atomic_load(object);
   atomic_fetch_sub(object, 1);
   *expected = changed;
   return false;
  }
 }
 return atomic_compare_exchange_strong_explicit(object, expected, desired,
                                                success, failure);
}
#undef atomic_compare_exchange_strong_explicit
#define atomic_compare_exchange_strong_explicit compare_join
@COHORT@
#undef atomic_compare_exchange_strong_explicit
static int extfuse_snapshot_pinned_inode(int fd, dev_t dev, ino_t ino, struct stat *st)
{
 assert(!held && fd == 77 && dev == 3 && ino == 19);
 if (expect_active_stat) assert(atomic_load(&map_attr) & 255);
 atomic_fetch_add(&stats, 1); st->st_atim.tv_sec = atomic_load(&lower_done);
 if (atomic_exchange(&hold_stat, 0)) {
  atomic_store(&stat_entered, 1);
  while (!atomic_load(&allow_stat)) sched_yield();
 }
 return atomic_load(&fail_stat) ? -EIO : 0;
}
static int cache_attr_locked(fuse_ino_t ino, const struct stat *st, double timeout,
 uint64_t daemon_state, uint64_t native_state, bool existing, bool *missing)
{
 struct perf_inode_generation *state = find_inode_generation_locked(ino);
 uint64_t token;
 assert(held && !existing && !missing && !native_state && timeout == 1.0);
 assert(inode_generation_value_locked(state, &token, false));
 assert(!state->active && token == daemon_state);
 if (atomic_exchange(&fail_attr, false)) {
  disable_all_caches_locked("attr-failure"); return -EIO;
 }
 atomic_fetch_add(&attrs, 1); atomic_store(&attr_token, token);
 atomic_store(&attr_atime, st->st_atim.tv_sec); return 0;
}
static enum perf_cache_attr_outcome cache_attr(fuse_ino_t ino, struct stat *st, double timeout,
 const struct perf_cache_snapshot *snapshot, bool existing, double *reply_timeout)
{
 struct perf_inode_generation *state; uint64_t token;
 enum perf_cache_attr_outcome result = PERF_CACHE_ATTR_UNSTABLE;
 assert(!held && !existing && timeout == 1.0); *reply_timeout = timeout;
 pthread_mutex_lock(&stripe); state = find_inode_generation_locked(ino);
 assert(inode_generation_value_locked(state, &token, false));
 if (!perf_state.cache_bypass && !state->active && token == snapshot->daemon_state) {
  atomic_fetch_add(&attrs, 1); atomic_store(&attr_token, token);
  atomic_store(&attr_atime, st->st_atim.tv_sec);
  result = PERF_CACHE_ATTR_PUBLISHED;
 }
 pthread_mutex_unlock(&stripe); return result;
}
@READ@
static struct lo_data *lo_data(fuse_req_t req) { (void)req; return &lo; }
static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino)
{ (void)req; assert(ino == 17); return &inode; }
static bool paper_write_fast_active(void) { return !revoke; }
static bool paper_capability_is_safe(void) { return !revoke; }
static pthread_mutex_t *xattr_lock_for_inode(fuse_ino_t ino)
{ assert(ino == 17); return &xstripe; }
static void invalidate_xattr_serialized(fuse_ino_t ino, const char *name, bool all)
{ assert(ino == 17 && !strcmp(name, PERF_CAPABILITY_XATTR) && all && xheld); }
static void prefetch_xattr_serialized(fuse_req_t req, fuse_ino_t ino, const char *name)
{ assert(req && !req->replies && ino == 17 && !strcmp(name, PERF_CAPABILITY_XATTR));
  assert(xheld && !(atomic_load(&map_xattr) & 255)); atomic_fetch_add(&refills, 1); }
static int fuse_reply_err(fuse_req_t req, int error)
{ assert(!held && !xheld && !req->replies); req->replies++; req->error = error; return 0; }
static int fuse_reply_write(fuse_req_t req, size_t size)
{ assert(!held && !xheld && !req->replies); req->replies++; req->size = size; return 0; }
static void fuse_session_exit(void *session)
{ assert(session == &perf_state); atomic_fetch_add(&exits, 1); }
@WRITE@
static void audit_packed_state_map(int map, uint64_t *records,
 uint64_t *active, uint64_t *errors)
{ (void)map; *records = 1; *active = !!(atomic_load(&map_attr) & 255); *errors = 0; }
@AUDIT@
static struct perf_read_context *context(void)
{
 struct perf_read_context *c = calloc(1, sizeof(*c)); assert(c);
 c->lo = &lo; c->inode = &inode; c->ino = 17;
 c->mutation = (struct perf_cache_mutation){ .inodes = {17}, .count = 1, .attr_only = true };
 return c;
}
static struct perf_inode_generation *record(void)
{
 struct perf_inode_generation *state;
 pthread_mutex_lock(&stripe); state = get_inode_generation_locked(17);
 pthread_mutex_unlock(&stripe); assert(state); return state;
}
static void begin(struct perf_read_context *c)
{ assert(cache_io_begin(&c->mutation, &c->cohort)); }
static void lower_read(void)
{ assert((atomic_load(&map_attr) & 255) || perf_state.cache_bypass);
  atomic_fetch_add(&lower_done, 1); }
static void finish(struct perf_read_context *c)
{ errno = EINTR; perf_read_prepare(c, 4096); assert(errno == EINTR); free(c); }
static void wait_for(atomic_uint *flag, unsigned value)
{ while (atomic_load(flag) < value) sched_yield(); }
static void clean(struct perf_inode_generation *state)
{
 assert(!state->active && !state->xattr_active);
 assert(!atomic_load(&state->read_cohort_refs) && !state->read_cohort_armed);
 assert(!atomic_load(&state->write_cohort_refs) && !state->write_cohort_armed);
 audit_coherence_state(); assert(!perf_state.counters.daemon_io_active_residuals);
 assert(!perf_state.counters.daemon_io_state_audit_errors);
}
static pthread_barrier_t gate;
struct worker { struct perf_read_context *c; bool admit, rendezvous; };
static void *worker(void *opaque)
{
 struct worker *w = opaque;
 if (w->rendezvous) pthread_barrier_wait(&gate);
 if (w->admit) begin(w->c);
 if (w->rendezvous) pthread_barrier_wait(&gate);
 lower_read(); finish(w->c); return NULL;
}
static void *finish_worker(void *opaque) { finish(opaque); return NULL; }
static void parallel(bool concurrent)
{
 enum { N = 16 }; pthread_t threads[N]; struct worker workers[N];
 struct perf_inode_generation *state = record(); unsigned baseline = atomic_load(&locks);
 struct perf_read_context *first = context(); begin(first);
 for (int i = 0; i < N; i++) {
  workers[i] = (struct worker){ context(), concurrent, concurrent };
  if (!concurrent) { begin(workers[i].c); assert(workers[i].c->cohort == state); }
 }
 if (!concurrent) { lower_read(); finish(first); }
 pthread_barrier_init(&gate, NULL, N);
 for (int i = 0; i < N; i++) assert(!pthread_create(&threads[i], NULL, worker, &workers[i]));
 for (int i = 0; i < N; i++) assert(!pthread_join(threads[i], NULL));
 if (concurrent) { lower_read(); finish(first); }
 pthread_barrier_destroy(&gate); clean(state);
 assert(atomic_load(&attr_atime) == N + 1);
 if (!concurrent) { assert(atomic_load(&locks) - baseline == 2);
  assert(atomic_load(&map_updates) == 2 && atomic_load(&stats) == 1); }
}
struct write_worker {
 struct perf_write_context *context;
 struct request request;
 bool admit, rendezvous;
};
static void write_begin(struct write_worker *w)
{
 struct fuse_file_info fi = { .writepage = true };
 w->context = calloc(1, sizeof(*w->context)); assert(w->context);
 assert(perf_write_begin(&w->request, 17, 4096, &fi, w->context, "cohort-test"));
}
static void lower_write(void)
{
 assert(!held && !xheld);
 assert(((atomic_load(&map_attr) & 255) && (atomic_load(&map_xattr) & 255)) ||
        perf_state.cache_bypass);
 atomic_fetch_add(&lower_done, 1);
}
static void write_finish(struct write_worker *w, ssize_t result)
{
 perf_write_complete(&w->request, result, w->context, "cohort-test");
 assert(w->request.replies == 1); free(w->context); w->context = NULL;
}
static void *write_worker(void *opaque)
{
 struct write_worker *w = opaque;
 if (w->rendezvous) pthread_barrier_wait(&gate);
 if (w->admit) write_begin(w);
 if (w->rendezvous) pthread_barrier_wait(&gate);
 lower_write(); write_finish(w, 4096); return NULL;
}
static void write_case(const char *name)
{
 struct perf_inode_generation *state = record();
 struct write_worker a = {0}, b = {0};
 unsigned baseline = atomic_load(&locks);
 perf_state.session = &perf_state;
 if (!strcmp(name, "write-busy-begin")) {
  pthread_t ta, tb; a.admit = b.admit = true;
  unsigned before = atomic_load(&attempts); atomic_store(&hold_begin, 1);
  assert(!pthread_create(&ta, NULL, write_worker, &a)); wait_for(&begin_entered, 1);
  assert(!pthread_create(&tb, NULL, write_worker, &b)); wait_for(&attempts, before + 2);
  assert(!atomic_load(&lower_done)); atomic_store(&allow_begin, true);
  pthread_join(ta, NULL); pthread_join(tb, NULL); clean(state); return;
 }
 if (!strcmp(name, "write-fatal-first")) {
  struct perf_write_context c; struct request req = {0};
  struct fuse_file_info fi = { .writepage = true };
  atomic_store(&fail_map, true); atomic_store(&fatal_map, true);
  assert(!perf_write_begin(&req, 17, 4096, &fi, &c, "cohort-test"));
  assert(req.replies == 1 && req.error == EIO && !atomic_load(&lower_done));
  clean(state); return;
 }
 write_begin(&a);
 if (!strcmp(name, "write-shared-lifetime") || !strcmp(name, "write-concurrent")) {
  enum { N = 16 }; pthread_t threads[N]; struct write_worker workers[N] = {0};
  bool concurrent = !strcmp(name, "write-concurrent");
  for (int i = 0; i < N; i++) {
   workers[i].admit = workers[i].rendezvous = concurrent;
   if (!concurrent) { write_begin(&workers[i]); assert(workers[i].context->cohort == state); }
  }
  if (!concurrent) { lower_write(); write_finish(&a, 4096); }
  pthread_barrier_init(&gate, NULL, N);
  for (int i = 0; i < N; i++) assert(!pthread_create(&threads[i], NULL, write_worker, &workers[i]));
  for (int i = 0; i < N; i++) {
   assert(!pthread_join(threads[i], NULL));
   assert(workers[i].request.size == 4096 && !workers[i].request.error);
  }
  if (concurrent) { lower_write(); write_finish(&a, 4096); }
  pthread_barrier_destroy(&gate); clean(state);
  assert(a.request.size == 4096 && !a.request.error && atomic_load(&attr_atime) == N + 1);
  if (!concurrent) {
   assert(atomic_load(&locks) - baseline == 3 && atomic_load(&map_updates) == 2);
   assert(atomic_load(&stats) == 1 && state->generation == 2 && state->xattr_generation == 2);
  }
  return;
 }
 if (!strcmp(name, "write-busy-end")) {
  pthread_t thread; atomic_store(&hold_stat, 1);
  assert(!pthread_create(&thread, NULL, write_worker, &a)); wait_for(&stat_entered, 1);
  write_begin(&b); assert(!b.context->cohort && b.context->mutation.armed);
  lower_write(); write_finish(&b, 4096);
  atomic_store(&allow_stat, true); pthread_join(thread, NULL); clean(state);
  assert(atomic_load(&attrs) == 1 && atomic_load(&attr_atime) == 2);
  assert(!atomic_load(&exits)); return;
 }
 if (!strcmp(name, "write-end-map-failure")) {
  atomic_store(&fail_map, true); lower_write(); write_finish(&a, 4096);
  assert(perf_state.cache_bypass && !state->active && !state->xattr_active);
  assert(!state->write_cohort_armed && !atomic_load(&state->write_cohort_refs));
  assert(atomic_load(&map_attr) & 255); return;
 }
 write_begin(&b); assert(a.context->cohort == state && b.context->cohort == state);
 if (!strcmp(name, "write-read-overlap")) {
  struct perf_read_context *read = context(); begin(read); revoke = true;
  lower_write(); write_finish(&a, 4096);
  assert(!atomic_load(&refills) && state->active == 2 && state->xattr_active == 1);
  lower_write(); write_finish(&b, 4096);
  assert(atomic_load(&refills) == 1 && state->active == 1 && !state->xattr_active);
  assert(!atomic_load(&attrs)); lower_read(); finish(read); clean(state);
  assert(atomic_load(&attrs) == 1 && state->xattr_generation == 2); return;
 }
 lower_write(); write_finish(&a, !strcmp(name, "write-error-first") ? -EAGAIN : 4096);
 assert(!atomic_load(&stats) && state->active == 1 && state->xattr_active == 1);
 lower_write(); write_finish(&b, !strcmp(name, "write-short-last") ? 4095 : 4096);
 clean(state); assert(atomic_load(&attrs) == 1 && atomic_load(&stats) == 1);
 if (!strcmp(name, "write-error-first")) assert(a.request.error == EAGAIN && b.request.size == 4096);
 if (!strcmp(name, "write-short-last")) assert(!a.request.error && b.request.error == EIO);
 assert(atomic_load(&exits) == 1);
}
int main(int argc, char **argv)
{
 struct perf_inode_generation *state; struct perf_read_context *a, *b;
 assert(argc == 2); const char *name = argv[1];
 if (!strncmp(name, "write-", 6)) { write_case(name); return 0; }
 if (!strcmp(name, "cold-publication")) {
  enum { N = 16 }; pthread_t threads[N]; struct worker workers[N];
  pthread_barrier_init(&gate, NULL, N);
  for (int i = 0; i < N; i++) {
   workers[i] = (struct worker){ context(), true, true };
   assert(!pthread_create(&threads[i], NULL, worker, &workers[i]));
  }
  for (int i = 0; i < N; i++) assert(!pthread_join(threads[i], NULL));
  pthread_barrier_destroy(&gate); state = record(); clean(state);
  assert(!state->next && atomic_load(&attr_atime) == N); return 0;
 }
 if (!strcmp(name, "shared-lifetime") || !strcmp(name, "concurrent")) {
  parallel(!strcmp(name, "concurrent")); return 0;
 }
 state = record(); a = context(); b = context();
 if (!strcmp(name, "busy-begin")) {
  pthread_t ta, tb; struct worker wa = {a, true, false}, wb = {b, true, false};
  unsigned baseline = atomic_load(&attempts); atomic_store(&hold_begin, 1);
  pthread_create(&ta, NULL, worker, &wa); wait_for(&begin_entered, 1);
  pthread_create(&tb, NULL, worker, &wb); wait_for(&attempts, baseline + 2);
  assert(!atomic_load(&lower_done)); atomic_store(&allow_begin, true);
  pthread_join(ta, NULL); pthread_join(tb, NULL); clean(state); return 0;
 }
 if (!strcmp(name, "map-failure") || !strcmp(name, "fatal-first")) {
  atomic_store(&fail_map, true); atomic_store(&fatal_map, !strcmp(name, "fatal-first"));
  bool ok = cache_io_begin(&a->mutation, &a->cohort);
  assert(ok == !atomic_load(&fatal_map)); assert(perf_state.cache_bypass);
  if (ok) { lower_read(); finish(a); } else { cache_mutation_end(&a->mutation); free(a); }
  free(b); clean(state); assert(!atomic_load(&attrs)); return 0;
 }
 if (!strcmp(name, "ordinary-mode")) perf_state.mode = 2;
 unsigned boundary_locks = atomic_load(&locks);
 begin(a);
 if (!strcmp(name, "single-boundary") || !strcmp(name, "end-map-failure") ||
     !strcmp(name, "attr-map-failure")) {
  expect_active_stat = true;
  atomic_store(&fail_map, !strcmp(name, "end-map-failure"));
  atomic_store(&fail_attr, !strcmp(name, "attr-map-failure"));
  lower_read(); finish(a); free(b);
  if (!strcmp(name, "end-map-failure")) {
   assert(perf_state.cache_bypass && !state->active);
   assert(!atomic_load(&state->read_cohort_refs) && !state->read_cohort_armed);
   /* A failed END map update deliberately leaves its old ACTIVE token. */
   assert(atomic_load(&map_attr) & 255);
  } else {
   clean(state);
  }
  assert(atomic_load(&locks) - boundary_locks == 2);
  assert(atomic_load(&stats) == 1);
  assert(atomic_load(&attrs) == !strcmp(name, "single-boundary"));
  return 0;
 }
 if (!strcmp(name, "join-retry") || !strcmp(name, "join-bounded")) {
  unsigned baseline = atomic_load(&locks);
  cas_failures = !strcmp(name, "join-retry") ? 1 : 8;
  cas_calls = 0; begin(b);
  if (!strcmp(name, "join-retry")) {
   assert(b->cohort == state && atomic_load(&locks) == baseline);
   assert(cas_calls == 3); /* injected conflict, refreshed expected, success */
  } else {
   assert(!b->cohort && atomic_load(&locks) == baseline + 1);
   assert(cas_calls == PERF_IO_COHORT_JOIN_ATTEMPTS);
  }
  lower_read(); finish(b); lower_read(); finish(a); clean(state); return 0;
 }
 if (!strcmp(name, "busy-end")) {
  pthread_t thread; lower_read(); atomic_store(&hold_stat, 1);
  pthread_create(&thread, NULL, finish_worker, a); wait_for(&stat_entered, 1);
  begin(b); assert(!b->cohort && b->mutation.armed && !b->mutation.read_generation);
  lower_read(); finish(b);
  atomic_store(&allow_stat, true); pthread_join(thread, NULL); clean(state);
  assert(atomic_load(&stats) == 2 && atomic_load(&attrs) == 1);
  assert(atomic_load(&attr_atime) == 2); return 0;
 }
 if (!strcmp(name, "writer-during-stat")) {
  pthread_t thread;
  struct perf_cache_mutation write = { .inodes = {17}, .count = 1 };
  lower_read(); atomic_store(&hold_stat, 1);
  pthread_create(&thread, NULL, finish_worker, a); wait_for(&stat_entered, 1);
  assert(cache_mutation_begin(&write)); lower_read();
  assert(!cache_mutation_end(&write) && write.xattr_quiescent);
  assert(!atomic_load(&attrs) && (atomic_load(&map_attr) & 255));
  atomic_store(&allow_stat, true); pthread_join(thread, NULL); free(b); clean(state);
  assert(atomic_load(&stats) == 2 && atomic_load(&attrs) == 1);
  assert(atomic_load(&attr_atime) == 2); return 0;
 }
 if (!strcmp(name, "native-fallback") || !strcmp(name, "wbcache-fallback")) {
  perf_state.passthrough_coherence_v2_requested = !strcmp(name, "native-fallback");
  perf_state.wbcache_passthrough_requested = !strcmp(name, "wbcache-fallback");
  lower_read(); finish(a); free(b); clean(state);
  assert(atomic_load(&locks) - boundary_locks == 3);
  assert(atomic_load(&stats) == 1 && atomic_load(&attrs) == 1); return 0;
 }
 if (!strcmp(name, "fatal-admission")) {
  perf_state.counters.cache_bypass_errors = 1;
  assert(!cache_io_begin(&b->mutation, &b->cohort)); assert(!b->cohort);
  cache_mutation_end(&b->mutation); free(b); lower_read(); finish(a); clean(state); return 0;
 }
 if (!strcmp(name, "writer-overlap")) {
  struct perf_cache_mutation write = { .inodes = {17}, .count = 1 };
  begin(b); assert(cache_mutation_begin(&write)); assert(state->active == 2);
  lower_read(); finish(a); assert(!cache_mutation_end(&write));
  assert(write.xattr_quiescent && !state->xattr_active && state->active == 1);
  lower_read(); finish(b); clean(state); assert(state->xattr_generation == 2); return 0;
 }
 if (!strcmp(name, "audit")) {
  audit_coherence_state(); assert(perf_state.counters.daemon_io_state_audit_errors == 1);
  lower_read(); finish(a); free(b); clean(state);
  state->read_cohort_armed = true; audit_coherence_state();
  assert(perf_state.counters.daemon_io_state_audit_errors == 1);
  state->read_cohort_armed = false; clean(state);
  state->write_cohort_armed = true; audit_coherence_state();
  assert(perf_state.counters.daemon_io_state_audit_errors == 1);
  state->write_cohort_armed = false; atomic_store(&state->write_cohort_refs, 1);
  audit_coherence_state(); assert(perf_state.counters.daemon_io_state_audit_errors == 1);
  atomic_store(&state->write_cohort_refs, 0); clean(state); return 0;
 }
 if (!strcmp(name, "stat-error")) atomic_store(&fail_stat, true);
 begin(b); if (perf_state.mode != PERF_MODE_HIT) assert(!a->cohort && !b->cohort);
 lower_read(); finish(a); lower_read(); finish(b); clean(state);
 if (!strcmp(name, "stat-error")) assert(!atomic_load(&attrs));
 return 0;
}
"""


class ReadCohortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text()
        structs = "\n".join(extract(source, f"struct {name} {{") for name in (
            "perf_inode_generation", "perf_cache_mutation", "perf_cache_snapshot"))
        names = {
            "LOOKUP": ("find_inode_generation_locked", "get_inode_generation_locked",
                       "inode_generation_value_locked"),
            "MUTATION": ("cache_mutation_add", "cache_mutation_begin", "cache_mutation_end_capture_locked",
                         "cache_mutation_end_capture",
                         "cache_mutation_end_with_snapshot", "cache_mutation_end"),
            "COHORT": ("cache_io_cohort_refs", "cache_io_begin",
                       "cache_io_cohort_last", "cache_io_cohort_release"),
            "WRITE": ("perf_write_contract_failed", "refill_capability_after_write",
                      "publish_pinned_write_attr", "perf_write_complete", "perf_write_begin"),
            "AUDIT": ("audit_coherence_state",),
        }
        code = HARNESS.replace("@STRUCTS@", structs + "\n" +
                               extract(source, "struct perf_write_context {"))
        for tag, functions in names.items():
            bodies = []
            for name in functions:
                match = re.search(r"^static [^;{}]*\b" + name + r"\([^;{}]*\)\s*\{", source, re.M)
                if match is None:
                    raise AssertionError(f"missing {name}")
                bodies.append(extract(source, match.group()))
            code = code.replace(f"@{tag}@", "\n".join(bodies))
        code = code.replace("@READ@", extract(source, "struct perf_read_context {") +
                            "\n" + extract(source, "static bool cache_read_end_prefetched(") +
                            "\n" + extract(source, "static void perf_read_prepare("))
        cls.directory = tempfile.TemporaryDirectory(prefix="extfuse-read-cohort-")
        cls.addClassCleanup(cls.directory.cleanup)
        path = Path(cls.directory.name)
        (path / "check.c").write_text(code)
        cls.binary = path / "check"
        built = subprocess.run([*shlex.split(os.environ.get("CC", "cc")),
                                "-std=c11", "-O2", "-pthread", "-Wall", "-Wextra", "-Werror",
                                str(path / "check.c"), "-o", str(cls.binary)],
                               capture_output=True, text=True, timeout=20)
        if built.returncode:
            raise AssertionError(built.stderr)

    def check(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_first_context_can_finish_before_parallel_last_member(self):
        self.check("shared-lifetime")

    def test_write_cohort_owns_guard_after_first_context_is_freed(self):
        self.check("write-shared-lifetime")
        self.check("write-concurrent")

    def test_write_boundaries_retain_fallback_and_reject_stale_publication(self):
        self.check("write-busy-begin")
        self.check("write-busy-end")

    def test_write_refills_revoked_xattr_while_read_remains_active(self):
        self.check("write-read-overlap")

    def test_write_failures_preserve_individual_replies_and_release_cohort(self):
        for name in ("write-fatal-first", "write-end-map-failure",
                     "write-error-first", "write-short-last"):
            with self.subTest(name=name):
                self.check(name)

    def test_single_boundary_keeps_active_stat_and_uses_one_completion_lock(self):
        self.check("single-boundary")

    def test_prefetched_publication_failure_keeps_cache_disabled(self):
        for name in ("end-map-failure", "attr-map-failure"):
            with self.subTest(name=name):
                self.check(name)

    def test_active_join_retries_are_bounded_and_avoid_unnecessary_stripe(self):
        for name in ("join-retry", "join-bounded"):
            with self.subTest(name=name):
                self.check(name)

    def test_concurrent_admission_and_completion(self):
        self.check("cold-publication")
        for _ in range(8):
            self.check("concurrent")

    def test_busy_boundaries_keep_ordinary_fallback_and_reject_old_snapshot(self):
        for name in ("busy-begin", "busy-end"):
            with self.subTest(name=name):
                self.check(name)

    def test_writer_xattr_boundary_survives_read_cohort(self):
        self.check("writer-overlap")

    def test_writer_during_prefetched_stat_requires_fresh_post_end_snapshot(self):
        self.check("writer-during-stat")

    def test_native_and_wbcache_modes_keep_original_completion(self):
        for name in ("native-fallback", "wbcache-fallback"):
            with self.subTest(name=name):
                self.check(name)

    def test_map_failure_fatal_admission_and_stat_failure(self):
        for name in ("map-failure", "fatal-first", "fatal-admission", "stat-error"):
            with self.subTest(name=name):
                self.check(name)

    def test_non_hit_mode_and_residual_audit(self):
        for name in ("ordinary-mode", "audit"):
            with self.subTest(name=name):
                self.check(name)


if __name__ == "__main__":
    unittest.main()
