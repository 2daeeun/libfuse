#!/usr/bin/env python3
"""Exercise actual counter functions at controlled pthread interleavings.

Only atomic-load scheduling is intercepted. No FUSE mount or library build is
required. Source/header overrides also allow checking an unmodified baseline.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("EXTFUSE_NATIVE_COUNTER_SOURCE",
                             ROOT / "lib/fuse_lowlevel.c"))
HEADER = Path(os.environ.get("EXTFUSE_NATIVE_COUNTER_HEADER",
                             ROOT / "lib/fuse_i.h"))


HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
@STRUCT@
struct fuse_session { struct fuse_native_request_counter native_request_counter; };
static struct fuse_session se;
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static const atomic_uint_fast64_t *pause_location;
static unsigned pause_nth = 1, matching_loads;
static bool entered, released;
static _Thread_local bool hooked;

static uint_fast64_t raw_load(const atomic_uint_fast64_t *object,
                             memory_order order)
{ return atomic_load_explicit(object, order); }

static uint_fast64_t scheduled_load(const atomic_uint_fast64_t *object,
                                   memory_order order)
{
 uint_fast64_t value = raw_load(object, order);
 if (hooked && object == pause_location) {
  assert(!pthread_mutex_lock(&gate_lock));
  if (++matching_loads == pause_nth) {
   entered = true; assert(!pthread_cond_broadcast(&gate_cond));
   while (!released) assert(!pthread_cond_wait(&gate_cond, &gate_lock));
  }
  assert(!pthread_mutex_unlock(&gate_lock));
 }
 return value;
}
#undef atomic_load_explicit
#define atomic_load_explicit(object, order) scheduled_load((object), (order))
@FUNCTIONS@
@BASELINE_INIT@

enum operation { START, STOP, READ, INCREMENT };
struct call { enum operation op; bool hook; int result; uint64_t value; };
static void *call_control(void *opaque)
{
 struct call *call = opaque;
 hooked = call->hook;
 switch (call->op) {
 case START: call->result = fuse_session_native_request_counter_start(&se); break;
 case STOP: call->result = fuse_session_native_request_counter_stop(&se); break;
 case READ: call->result = fuse_session_native_request_counter_read(&se, 3, &call->value); break;
 case INCREMENT: native_request_counter_increment(&se, 3); call->result = 0; break;
 }
 return NULL;
}
static void hold(pthread_t *thread, struct call *call,
                 const atomic_uint_fast64_t *location)
{
 pause_location = location;
 assert(!pthread_create(thread, NULL, call_control, call));
 assert(!pthread_mutex_lock(&gate_lock));
 while (!entered) assert(!pthread_cond_wait(&gate_cond, &gate_lock));
 assert(!pthread_mutex_unlock(&gate_lock));
}
static void release(pthread_t thread)
{
 assert(!pthread_mutex_lock(&gate_lock));
 released = true; assert(!pthread_cond_broadcast(&gate_cond));
 assert(!pthread_mutex_unlock(&gate_lock));
 assert(!pthread_join(thread, NULL));
}
static void count_pair(void)
{ native_request_counter_increment(&se, 3); native_request_counter_increment(&se, 22); }
static void check_counts(uint64_t getattr, uint64_t getxattr)
{
 uint64_t value = UINT64_MAX;
 assert(!fuse_session_native_request_counter_read(&se, 3, &value));
 assert(value == getattr);
 assert(!fuse_session_native_request_counter_read(&se, 22, &value));
 assert(value == getxattr);
}
static void check_busy(void)
{
 uint64_t value = 77;
 assert(fuse_session_native_request_counter_start(&se) == -EBUSY);
 assert(fuse_session_native_request_counter_stop(&se) == -EBUSY);
 assert(fuse_session_native_request_counter_read(&se, 3, &value) == -EBUSY);
 assert(value == 77);
}
static void *produce(void *unused)
{
 unsigned i;
 (void)unused;
 for (i = 0; i < 10000; i++) count_pair();
 return NULL;
}
int main(int argc, char **argv)
{
 pthread_t thread, stopper, producers[4];
 struct call call = { .hook = true }, stop = { .op = STOP };
 uint64_t value = 77;
 unsigned i;
 int other;
 assert(argc == 2); alarm(8); native_request_counter_init(&se);
 switch (atoi(argv[1])) {
 case 0: /* Sequential/error paths release control and preserve the API. */
  assert(fuse_session_native_request_counter_start(NULL) == -EINVAL);
  assert(fuse_session_native_request_counter_stop(NULL) == -EINVAL);
  assert(fuse_session_native_request_counter_read(NULL, 3, &value) == -EINVAL);
  assert(fuse_session_native_request_counter_read(&se, 64, &value) == -EINVAL);
  assert(fuse_session_native_request_counter_read(&se, 3, NULL) == -EINVAL);
  assert(fuse_session_native_request_counter_stop(&se) == -EINVAL);
  count_pair(); check_counts(0, 0);
  assert(!fuse_session_native_request_counter_start(&se));
  assert(fuse_session_native_request_counter_start(&se) == -EBUSY);
  assert(fuse_session_native_request_counter_read(&se, 3, &value) == -EBUSY);
  assert(value == 77); count_pair(); native_request_counter_increment(&se, 64);
  assert(!fuse_session_native_request_counter_stop(&se)); check_counts(1, 1);
  assert(!fuse_session_native_request_counter_start(&se));
  assert(!fuse_session_native_request_counter_stop(&se)); check_counts(0, 0); break;
 case 1: /* Baseline late losing start erases both counts before its failed CAS. */
  call.op = START; hold(&thread, &call, &se.native_request_counter.epoch);
  other = fuse_session_native_request_counter_start(&se);
  assert(other == 0 || other == -EBUSY);
  if (!other) count_pair();
  release(thread);
  assert((!other && call.result == -EBUSY) || (other == -EBUSY && !call.result));
  if (other) count_pair();
  assert(!fuse_session_native_request_counter_stop(&se)); check_counts(1, 1); break;
 case 2: /* Stop owns control through its completed writer drain. */
  assert(!fuse_session_native_request_counter_start(&se)); count_pair();
  call.op = STOP; hold(&thread, &call, &se.native_request_counter.writers);
  check_busy(); count_pair(); release(thread);
  assert(!call.result); check_counts(1, 1); break;
 case 3: /* A stopped-window read cannot overlap a clear or another controller. */
  assert(!fuse_session_native_request_counter_start(&se)); count_pair();
  assert(!fuse_session_native_request_counter_stop(&se));
  call.op = READ; hold(&thread, &call, &se.native_request_counter.values[3]);
  check_busy(); release(thread); assert(!call.result && call.value == 1);
  check_counts(1, 1); break;
 case 4: /* Start owns control before checking or clearing the stopped bank. */
  call.op = START; hold(&thread, &call, &se.native_request_counter.epoch);
  check_busy(); release(thread); assert(!call.result); count_pair();
  assert(!fuse_session_native_request_counter_stop(&se)); check_counts(1, 1); break;
 case 5: /* Request increments keep running while a control call is held. */
  assert(!fuse_session_native_request_counter_start(&se));
  call.op = READ; hold(&thread, &call, &se.native_request_counter.epoch);
  for (i = 0; i < 4; i++) assert(!pthread_create(&producers[i], NULL, produce, NULL));
  for (i = 0; i < 4; i++) assert(!pthread_join(producers[i], NULL));
  release(thread); assert(call.result == -EBUSY);
  assert(!fuse_session_native_request_counter_stop(&se)); check_counts(40000, 40000); break;
 case 6: /* A late writer from the old epoch must not enter the new window. */
  assert(!fuse_session_native_request_counter_start(&se));
  call.op = INCREMENT; hold(&thread, &call, &se.native_request_counter.epoch);
  assert(!fuse_session_native_request_counter_stop(&se));
  assert(!fuse_session_native_request_counter_start(&se));
  release(thread); native_request_counter_increment(&se, 22);
  assert(!fuse_session_native_request_counter_stop(&se)); check_counts(0, 1); break;
 case 7: /* Stop waits for a counted writer and excludes control while draining. */
  assert(!fuse_session_native_request_counter_start(&se)); pause_nth = 2;
  call.op = INCREMENT; hold(&thread, &call, &se.native_request_counter.epoch);
  assert(!pthread_create(&stopper, NULL, call_control, &stop));
  while (raw_load(&se.native_request_counter.epoch, memory_order_acquire) & 1) sched_yield();
  check_busy(); release(thread); assert(!pthread_join(stopper, NULL));
  assert(!stop.result); check_counts(1, 0); break;
 default: abort();
 }
 puts("NATIVE_COUNTER_RACE_TEST result=PASS"); return 0;
}
"""


class NativeCounterRace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text()
        header = HEADER.read_text()
        struct = re.search(r"struct fuse_native_request_counter \{.*?\n\};",
                           header, re.S).group()
        slots = re.search(r"#define FUSE_NATIVE_REQUEST_COUNTER_SLOTS [^\n]+", header).group()
        start = source.index("static void native_request_counter_")
        finish = source.index("static void convert_stat", start)
        functions = source[start:finish]
        baseline_init = ""
        if "static void native_request_counter_init(" not in functions:
            baseline_init = """
static void native_request_counter_init(struct fuse_session *session)
{
 unsigned i;
 atomic_init(&session->native_request_counter.epoch, 0);
 atomic_init(&session->native_request_counter.writers, 0);
 for (i = 0; i < FUSE_NATIVE_REQUEST_COUNTER_SLOTS; i++)
  atomic_init(&session->native_request_counter.values[i], 0);
}
"""
        cls.directory = tempfile.TemporaryDirectory(prefix="native-counter-race-")
        cls.addClassCleanup(cls.directory.cleanup)
        path = Path(cls.directory.name)
        fixture = path / "test.c"
        fixture.write_text(HARNESS.replace("@STRUCT@", slots + "\n" + struct)
                           .replace("@FUNCTIONS@", functions)
                           .replace("@BASELINE_INIT@", baseline_init))
        cls.binary = path / "test"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
            str(fixture), "-o", str(cls.binary),
        ], check=True, capture_output=True, text=True, timeout=30)

    def test_control_interleavings(self):
        for scenario in range(8):
            with self.subTest(scenario=scenario):
                result = subprocess.run([str(self.binary), str(scenario)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("NATIVE_COUNTER_RACE_TEST result=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
