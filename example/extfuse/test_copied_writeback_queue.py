#!/usr/bin/env python3
"""Exercise kernel writeback placement with copied and fixed request buffers."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


LINUX = Path(os.environ.get("EXTFUSE_KERNEL_SOURCE",
                           Path(__file__).resolve().parents[3] / "linux"))


def selector():
    source = (LINUX / "fs/fuse/dev_uring.c").read_text()
    start = source.index("fuse_uring_lock_writeback_queue(")
    end = source.index("\n}\n", start) + 3
    return "static struct fuse_ring_queue *\n" + source[start:end]


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define FUSE_READ 15
#define FUSE_WRITE 16
#define FUSE_WRITE_CACHE 1
#define READ_ONCE(x) (x)
#define check_add_overflow(a, b, out) __builtin_add_overflow(a, b, out)
typedef uint64_t u64;
typedef struct { bool held, contended; } spinlock_t;
struct list_head { bool empty; };
struct fuse_write_in { u64 offset; unsigned size, write_flags; };
struct fuse_file { bool uring_writeback_seen; u64 uring_writeback_end; };
struct fuse_args {
 struct fuse_file *extfuse_file;
 bool zero_copy, in_pages, out_pages;
 unsigned in_numargs;
 struct { unsigned size; const void *value; } in_args[1];
};
struct fuse_req {
 struct fuse_args *args;
 struct { struct { unsigned opcode; } h; } in;
};
struct fuse_ring_queue {
 spinlock_t lock;
 bool stopped, zero_copy;
 unsigned active_background;
 struct list_head ent_avail_queue, fuse_req_queue, fuse_req_bg_queue;
};
struct fuse_ring {
 unsigned nr_queues, bg_queue_seq;
 struct fuse_ring_queue **queues;
};
static unsigned held;
static void spin_lock(spinlock_t *lock) {
 assert(!held && !lock->held); lock->held = true; held++;
}
static void spin_unlock(spinlock_t *lock) {
 assert(held == 1 && lock->held); lock->held = false; held--;
}
static bool spin_trylock(spinlock_t *lock) {
 assert(!held);
 if (lock->held || lock->contended) return false;
 spin_lock(lock); return true;
}
static bool list_empty(const struct list_head *head) { return head->empty; }
static unsigned atomic_fetch_inc_relaxed(unsigned *p) { return (*p)++; }
/* SELECTOR */
static struct fuse_ring_queue queues[4], *refs[4];
static struct fuse_ring ring;
static struct fuse_file file;
static struct fuse_write_in in;
static struct fuse_args args;
static struct fuse_req req;

static void reset(bool fixed) {
 assert(!held);
 memset(queues, 0, sizeof(queues));
 for (unsigned i = 0; i < 4; i++) {
  queues[i].zero_copy = fixed;
  queues[i].fuse_req_queue.empty = true;
  queues[i].fuse_req_bg_queue.empty = true;
  refs[i] = &queues[i];
 }
 queues[0].active_background = 1;
 ring = (struct fuse_ring){.nr_queues = 4, .queues = refs};
 file = (struct fuse_file){true, 4096};
 in = (struct fuse_write_in){8192, 4096, FUSE_WRITE_CACHE};
 args = (struct fuse_args){.extfuse_file = &file, .zero_copy = fixed,
                          .in_pages = true, .in_numargs = 1};
 args.in_args[0].size = sizeof(in); args.in_args[0].value = &in;
 req = (struct fuse_req){.args = &args, .in.h.opcode = FUSE_WRITE};
}
static unsigned select_queue(void) {
 struct fuse_ring_queue *selected =
  fuse_uring_lock_writeback_queue(&ring, &req, &queues[0]);
 assert(held == 1 && selected->lock.held);
 unsigned index = (unsigned)(selected - queues);
 assert(index < 4);
 spin_unlock(&selected->lock); assert(!held);
 return index;
}
int main(int argc, char **argv) {
 assert(argc == 2);
 switch (atoi(argv[1])) {
 case 0: /* Busy copied writes can use existing idle workers, then saturate. */
  reset(false);
  for (unsigned i = 1; i < 4; i++) {
   in.offset = i * 16384;
   assert(select_queue() == i);
   queues[i].active_background++;
  }
  in.offset = 0; assert(select_queue() == 0);
  reset(false); queues[0].active_background = 0;
  assert(select_queue() == 0); /* An idle home retains locality. */
  queues[0].fuse_req_bg_queue.empty = false; in.offset = 0;
  assert(select_queue() == 1); /* Queued but not yet admitted is busy too. */
  break;
 case 1: /* Copied sequential writes retain their original home placement. */
  reset(false); in.offset = file.uring_writeback_end;
  assert(select_queue() == 0);
  queues[0].ent_avail_queue.empty = true;
  queues[0].fuse_req_bg_queue.empty = false;
  in.offset = file.uring_writeback_end; assert(select_queue() == 0);
  file.uring_writeback_seen = false; in.offset = 987654;
  assert(select_queue() == 0);
  break;
 case 2: /* The fixed path still distributes random and saturated writes. */
  reset(true); assert(select_queue() == 1);
  reset(true); in.offset = file.uring_writeback_end;
  assert(select_queue() == 0);
  queues[0].ent_avail_queue.empty = true;
  in.offset = file.uring_writeback_end; assert(select_queue() == 1);
  reset(true); args.zero_copy = false;
  assert(select_queue() == 0); /* Copied fallback on a fixed queue is unchanged. */
  break;
 case 3: /* Never pass stopped, contended, incompatible or older queued work. */
  for (unsigned mode = 0; mode < 7; mode++) {
   reset(false);
   switch (mode) {
   case 0: queues[1].stopped = true; break;
   case 1: queues[1].zero_copy = true; break;
   case 2: queues[1].lock.contended = true; break;
   case 3: queues[1].ent_avail_queue.empty = true; break;
   case 4: queues[1].fuse_req_queue.empty = false; break;
   case 5: queues[1].fuse_req_bg_queue.empty = false; break;
   case 6: refs[1] = NULL; break;
   }
   assert(select_queue() == 2);
   ring.nr_queues = 2; in.offset = 0; assert(select_queue() == 0);
  }
  reset(false); ring.bg_queue_seq = UINT32_MAX;
  assert(select_queue() == 3);
  reset(false); ring.nr_queues = 1; assert(select_queue() == 0);
  break;
 case 4: /* Metadata, reads, direct writes and malformed requests do not move. */
  for (unsigned mode = 0; mode < 11; mode++) {
   reset(false);
   switch (mode) {
   case 0: req.in.h.opcode = FUSE_READ; break;
   case 1: req.in.h.opcode = 3; break;
   case 2: in.write_flags = 0; break;
   case 3: in.size = 0; break;
   case 4: in.offset = UINT64_MAX - 1; break;
   case 5: args.in_pages = false; break;
   case 6: args.out_pages = true; break;
   case 7: args.extfuse_file = NULL; break;
   case 8: args.in_numargs = 0; break;
   case 9: args.in_args[0].size = 0; break;
   case 10: args.in_args[0].value = NULL; break;
   }
   assert(select_queue() == 0);
   assert(file.uring_writeback_seen && file.uring_writeback_end == 4096);
  }
  reset(false); queues[0].stopped = true;
  assert(select_queue() == 0);
  break;
 default: abort();
 }
 return 0;
}
'''


class CopiedWritebackQueueTests(unittest.TestCase):
    def test_production_selector(self):
        with tempfile.TemporaryDirectory(prefix="extfuse-copied-queue-") as work:
            source = Path(work) / "selector.c"
            binary = Path(work) / "selector"
            source.write_text(HARNESS.replace("/* SELECTOR */", selector()))
            subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
                "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", str(source), "-o", str(binary)],
                check=True, capture_output=True, text=True)
            for scenario in range(5):
                with self.subTest(scenario=scenario):
                    run = subprocess.run([str(binary), str(scenario)],
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
