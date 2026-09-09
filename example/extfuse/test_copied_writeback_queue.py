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


def kernel_function(name, return_type):
    source = (LINUX / "fs/fuse/dev_uring.c").read_text()
    start = source.index(name + "(")
    end = source.index("\n}\n", start) + 3
    return return_type + "\n" + source[start:end]


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FUSE_READ 15
#define FUSE_WRITE 16
#define FUSE_WRITE_CACHE 1
#define READ_ONCE(x) (x)
#define check_add_overflow(a, b, out) __builtin_add_overflow(a, b, out)
typedef uint64_t u64;
typedef struct { bool held, contended; } spinlock_t;
struct list_head {
 bool empty;
 struct list_head *first, *last, *next, *owner;
};
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
 struct fuse_mount *fm;
 struct fuse_ring_queue *ring_queue;
 unsigned long flags;
 struct list_head list;
};
struct fuse_ring_queue {
 struct fuse_ring *ring;
 spinlock_t lock;
 bool stopped, zero_copy, write_in_task;
 unsigned qid;
 unsigned active_background;
 struct list_head ent_avail_queue, fuse_req_queue, fuse_req_bg_queue;
 struct list_head ent_in_userspace, ent_w_req_queue, ent_commit_queue;
 struct list_head ent_released;
};
struct fuse_ring {
 unsigned nr_queues, bg_queue_seq;
 struct fuse_ring_queue **queues;
 struct fuse_conn *fc;
 bool writeback_stream_affinity;
 unsigned writeback_stream_queues;
 unsigned writeback_next_queue[88];
};
struct fuse_conn {
 struct fuse_ring *ring;
 spinlock_t bg_lock;
 unsigned num_background, active_background, max_background;
 bool blocked;
};
struct fuse_mount { struct fuse_conn *fc; };
struct fuse_ring_ent { struct list_head list; };
static unsigned held;
static spinlock_t *background_lock;
static void spin_lock(spinlock_t *lock) {
 assert(!lock->held);
 assert(lock == background_lock ? held == 1 : !held);
 lock->held = true; held++;
}
static void spin_unlock(spinlock_t *lock) {
 assert(lock->held);
 assert(held == (lock == background_lock ? 2u : 1u));
 lock->held = false; held--;
}
static bool spin_trylock(spinlock_t *lock) {
 assert(!held);
 if (lock->held || lock->contended) return false;
 spin_lock(lock); return true;
}
static bool list_empty(const struct list_head *head) { return head->empty; }
static unsigned atomic_fetch_inc_relaxed(unsigned *p) { return (*p)++; }
#define lockdep_assert_held(lock) assert((lock)->held)
#define unlikely(x) (x)
#define FR_URING 1
#define container_of(ptr, type, member) \
 ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#define list_first_entry(head, type, member) \
 container_of((head)->first, type, member)
#define list_first_entry_or_null(head, type, member) \
 ((head)->first ? list_first_entry(head, type, member) : NULL)
static void list_add_tail(struct list_head *node, struct list_head *head) {
 node->next = NULL;
 node->owner = head;
 if (head->last) head->last->next = node;
 else head->first = node;
 head->last = node; head->empty = false;
}
static void list_move_tail(struct list_head *node, struct list_head *head) {
 struct list_head *old = node->owner;
 /* flush_bg() always promotes the oldest background request. */
 assert(old && old->first == node);
 old->first = node->next;
 if (!old->first) { old->last = NULL; old->empty = true; }
 list_add_tail(node, head);
}
static void set_bit(unsigned bit, unsigned long *flags) { *flags |= 1ul << bit; }
#define NUMA_NO_NODE (-1)
struct cpumask { bool cpus[128]; };
static struct cpumask node_masks[2];
static int cpu_nodes[88];
static int cpu_to_node(unsigned cpu) { assert(cpu < 88); return cpu_nodes[cpu]; }
static const struct cpumask *cpumask_of_node(int node) {
 assert(node >= 0 && node < 2); return &node_masks[node];
}
static bool cpumask_test_cpu(unsigned cpu, const struct cpumask *mask) {
 assert(cpu < 128); return mask->cpus[cpu];
}
static unsigned cpumask_next(unsigned cpu, const struct cpumask *mask) {
 for (unsigned i = cpu + 1; i < 128; i++) if (mask->cpus[i]) return i;
 return 128;
}
static unsigned cpumask_first(const struct cpumask *mask) {
 for (unsigned i = 0; i < 128; i++) if (mask->cpus[i]) return i;
 return 128;
}
/* STREAM_TOPOLOGY */
/* SELECTOR */
static struct fuse_ring_queue queues[4], *refs[4];
static struct fuse_ring ring;
static struct fuse_conn connection;
static struct fuse_mount mount;
static struct fuse_file file;
static struct fuse_write_in in;
static struct fuse_args args;
static struct fuse_req req;

static struct fuse_ring_queue *
fuse_uring_background_queue(struct fuse_ring *r, struct fuse_req *request) {
 assert(r == &ring && request->args == &args); return &queues[0];
}
static bool fuse_uring_prep_buffer(struct fuse_ring_ent *ent,
                                 struct fuse_req *request) {
 (void)ent; (void)request; abort();
}
static void fuse_uring_add_req_to_ring_ent(struct fuse_ring_ent *ent,
                                         struct fuse_req *request) {
 (void)ent; (void)request; abort();
}
static void fuse_uring_dispatch_ent(struct fuse_ring_ent *ent) {
 (void)ent; abort();
}
/* FLUSH_BACKGROUND */
/* ENQUEUE */

static void reset(bool fixed) {
 assert(!held);
 memset(queues, 0, sizeof(queues));
 for (unsigned i = 0; i < 4; i++) {
  queues[i].ring = &ring;
  queues[i].qid = i;
  queues[i].zero_copy = fixed;
  queues[i].fuse_req_queue.empty = true;
  queues[i].fuse_req_bg_queue.empty = true;
  queues[i].ent_in_userspace.empty = true;
  queues[i].ent_w_req_queue.empty = true;
  queues[i].ent_commit_queue.empty = true;
  queues[i].ent_released.empty = true;
  refs[i] = &queues[i];
 }
 queues[0].active_background = 1;
 connection = (struct fuse_conn){.ring = &ring};
 mount = (struct fuse_mount){.fc = &connection};
 background_lock = &connection.bg_lock;
 ring = (struct fuse_ring){.nr_queues = 4, .queues = refs, .fc = &connection,
                           .writeback_stream_queues = 1};
 memset(node_masks, 0, sizeof(node_masks));
 memset(cpu_nodes, 0, sizeof(cpu_nodes));
 for (unsigned i = 0; i < 4; i++) node_masks[0].cpus[i] = true;
 fuse_uring_init_stream_queues(&ring);
 file = (struct fuse_file){true, 4096};
 in = (struct fuse_write_in){8192, 4096, FUSE_WRITE_CACHE};
 args = (struct fuse_args){.extfuse_file = &file, .zero_copy = fixed,
                          .in_pages = true, .in_numargs = 1};
 args.in_args[0].size = sizeof(in); args.in_args[0].value = &in;
 req = (struct fuse_req){.args = &args, .in.h.opcode = FUSE_WRITE, .fm = &mount};
}
static unsigned select_from(unsigned home) {
 struct fuse_ring_queue *selected =
  fuse_uring_lock_writeback_queue(&ring, &req, &queues[home]);
 assert(held == 1 && selected->lock.held);
 unsigned index = (unsigned)(selected - queues);
 assert(index < 4);
 spin_unlock(&selected->lock); assert(!held);
 return index;
}
static unsigned select_queue(void) { return select_from(0); }
static void occupy_slots(unsigned index) {
 queues[index].ent_avail_queue.empty = true;
 queues[index].ent_in_userspace.empty = false;
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
  in.offset = 0; assert(select_queue() == 3);
  reset(false); queues[0].active_background = 0;
  assert(select_queue() == 0); /* An idle home retains locality. */
  queues[0].fuse_req_bg_queue.empty = false; in.offset = 0;
  assert(select_queue() == 1); /* Queued but not yet admitted is busy too. */
  break;
 case 1: /* Copied sequential writes retain their original home placement. */
  reset(false); in.offset = file.uring_writeback_end;
  assert(select_queue() == 0);
  occupy_slots(0);
  queues[0].fuse_req_bg_queue.empty = false;
  in.offset = file.uring_writeback_end; assert(select_queue() == 0);
  file.uring_writeback_seen = false; in.offset = 987654;
  assert(select_queue() == 0);
  break;
 case 2: /* The fixed path still distributes random and saturated writes. */
  reset(true); assert(select_queue() == 1);
  reset(true); in.offset = file.uring_writeback_end;
  assert(select_queue() == 0);
  occupy_slots(0);
  in.offset = file.uring_writeback_end; assert(select_queue() == 1);
  reset(true); args.zero_copy = false;
  assert(select_queue() == 0); /* Copied fallback on a fixed queue is unchanged. */
  break;
 case 3: /* Prefer idle workers; only saturation can append behind older work. */
  for (unsigned mode = 0; mode < 7; mode++) {
   reset(false);
   switch (mode) {
   case 0: queues[1].stopped = true; break;
   case 1: queues[1].zero_copy = true; break;
   case 2: queues[1].lock.contended = true; break;
   case 3: occupy_slots(1); break;
   case 4: queues[1].fuse_req_queue.empty = false; break;
   case 5: queues[1].fuse_req_bg_queue.empty = false; break;
   case 6: refs[1] = NULL; break;
   }
   assert(select_queue() == 2);
   ring.nr_queues = 2; in.offset = 0;
   assert(select_queue() == (mode >= 3 && mode <= 5 ? 1u : 0u));
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
 case 5: { /* Actual enqueue appends fairly without passing older requests. */
  struct fuse_req older[4], incoming[24];
  reset(false);
  memset(older, 0, sizeof(older));
  connection.active_background = connection.max_background = 4;
  connection.num_background = 8; /* Four active and four older pending. */
  for (unsigned i = 0; i < 4; i++) {
   queues[i].active_background = 1;
   occupy_slots(i); /* Full registered slots still owned by userspace. */
   list_add_tail(&older[i].list, &queues[i].fuse_req_bg_queue);
  }
  for (unsigned i = 0; i < 24; i++) {
   incoming[i] = req;
   in.offset = (u64)(i + 1) * 16384;
   assert(fuse_uring_queue_bq_req(&incoming[i]));
   assert(!held && incoming[i].ring_queue == &queues[i % 4]);
   assert(incoming[i].flags & (1ul << FR_URING));
  }
  assert(connection.num_background == 32);
  assert(connection.active_background == 4);
  for (unsigned i = 0; i < 4; i++) {
   struct list_head *node = queues[i].fuse_req_bg_queue.first;
   assert(node == &older[i].list); /* Existing oldest request remains first. */
   node = node->next;
   for (unsigned j = i; j < 24; j += 4) {
    assert(node == &incoming[j].list); node = node->next;
   }
   assert(!node && queues[i].fuse_req_bg_queue.last == &incoming[i + 20].list);
   assert(queues[i].active_background == 1);
   assert(list_empty(&queues[i].fuse_req_queue));
  }
  break;
 }
 case 6: /* Saturated fallback still rejects unsafe destinations. */
  for (unsigned mode = 0; mode < 4; mode++) {
   reset(false); ring.bg_queue_seq = 1;
   for (unsigned i = 0; i < 4; i++) {
    queues[i].active_background = 1;
    occupy_slots(i);
    queues[i].fuse_req_bg_queue.empty = false;
   }
   switch (mode) {
   case 0: queues[1].stopped = true; break;
   case 1: queues[1].zero_copy = true; break;
   case 2: queues[1].lock.contended = true; break;
   case 3: refs[1] = NULL; break;
   }
   assert(select_queue() == 2);
  }
  reset(false); ring.bg_queue_seq = 1;
  for (unsigned i = 1; i < 4; i++) queues[i].lock.contended = true;
  assert(select_queue() == 0); /* No safe remote lock: retain home. */
  reset(false); ring.bg_queue_seq = 1;
  for (unsigned i = 1; i < 4; i++) queues[i].stopped = true;
  assert(select_queue() == 0); /* Teardown retains the caller's error path. */
  reset(false); ring.bg_queue_seq = UINT32_MAX;
  for (unsigned i = 0; i < 4; i++) queues[i].active_background = 1;
  assert(select_queue() == 3);
  in.offset = 0; assert(select_queue() == 0); /* Cursor wrap. */
  break;
 case 7: /* Fixed saturation and copied sequential placement are unchanged. */
  for (unsigned fixed = 0; fixed < 2; fixed++) {
   reset(fixed);
   for (unsigned i = 0; i < 4; i++) {
    queues[i].active_background = 1;
    occupy_slots(i);
    queues[i].fuse_req_bg_queue.empty = false;
   }
   for (unsigned i = 0; i < 12; i++) {
    in.offset = fixed ? (u64)i * 16384 : file.uring_writeback_end;
    assert(select_queue() == 0);
   }
  }
  break;
 case 8: /* Pack existing slots, then use every queue's natural capacity. */
  for (unsigned capacity = 1; capacity <= 16; capacity *= 2) {
   reset(true); queues[0].active_background = 0;
   for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
   for (unsigned i = 0; i < 4 * capacity; i++) {
    unsigned expected = i / capacity;
    in.offset = (u64)(i + 1) * 16384;
    assert(select_queue() == expected);
    assert(++queues[expected].active_background <= capacity);
    if (queues[expected].active_background == capacity)
     occupy_slots(expected);
   }
   for (unsigned i = 0; i < 4; i++)
    assert(queues[i].active_background == capacity);
   /* No arbitrary issuer limit: all four queues filled before fallback. */
   in.offset = 0; assert(select_queue() == 0);
  }
  break;
 case 9: /* Overflow packs a busy worker before waking an idle one. */
  for (unsigned mode = 0; mode < 9; mode++) {
   reset(true);
   for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
   occupy_slots(0);
   queues[1].active_background = 3;
   switch (mode) {
   case 0: break;
   case 1: queues[1].stopped = true; break;
   case 2: queues[1].zero_copy = false; break;
   case 3: queues[1].write_in_task = false; break;
   case 4: queues[1].lock.contended = true; break;
   case 5: occupy_slots(1); break;
   case 6: queues[1].fuse_req_queue.empty = false; break;
   case 7: queues[1].fuse_req_bg_queue.empty = false; break;
   case 8: refs[1] = NULL; break;
   }
   assert(select_queue() == (mode == 0 ? 1u : 2u));
  }
  for (unsigned pending = 0; pending < 2; pending++) {
   reset(true);
   for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
   if (pending) queues[0].fuse_req_bg_queue.empty = false;
   else queues[0].fuse_req_queue.empty = false;
   /* An available home slot must not let a new request pass older work. */
   assert(select_queue() == 1);
  }
  break;
 case 10: /* Stable overflow order follows the actual home qid and wraps. */
  for (unsigned cursor = 0; cursor < 8; cursor++) {
   reset(true); ring.bg_queue_seq = cursor;
   for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
   occupy_slots(2);
   assert(select_from(2) == 3);
   queues[3].active_background = 3;
   in.offset = 0; assert(select_from(2) == 3);
   occupy_slots(3);
   in.offset = 32768; assert(select_from(2) == 0);
   occupy_slots(0);
   in.offset = 0; assert(select_from(2) == 1);
  }
  break;
 case 11: /* Packed placement needs both matching fixed mode and opt-in. */
  reset(true); queues[1].write_in_task = true;
  assert(select_queue() == 1); /* Non-WIT home keeps old idle selection. */
  reset(true); queues[0].write_in_task = true; args.zero_copy = false;
  assert(select_queue() == 0); /* A copied fallback cannot enter the policy. */
  reset(false); queues[0].write_in_task = true;
  assert(select_queue() == 1); /* Copied requests still distribute immediately. */
  reset(true);
  for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
  queues[0].stopped = true; assert(select_queue() == 0);
  reset(true);
  for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
  ring.nr_queues = 1; occupy_slots(0);
  assert(select_queue() == 0);
  break;
 case 12: /* Cancelled entries do not make a foreign queue a live worker. */
  for (unsigned live = 0; live < 6; live++) {
   reset(false); ring.bg_queue_seq = 1;
   for (unsigned i = 0; i < 4; i++) {
    queues[i].active_background = 1;
    occupy_slots(i);
   }
   /* Simulate every entry cancelled while stopped is still false. */
   queues[1].ent_in_userspace.empty = true;
   switch (live) {
   case 0: break; /* No entries. */
   case 1: queues[1].ent_avail_queue.empty = false; break;
   case 2: queues[1].ent_in_userspace.empty = false; break;
   case 3: queues[1].ent_w_req_queue.empty = false; break;
   case 4: queues[1].ent_commit_queue.empty = false; break;
   case 5: queues[1].ent_released.empty = false; break;
   }
   assert(select_queue() == (live >= 1 && live <= 4 ? 1u : 2u));
   assert(!queues[1].stopped);
  }
  break;
 case 13: { /* Fixed stream overflow stays behind older work at the same limit. */
  struct fuse_req older, incoming[24];
  struct list_head *node;
  reset(true);
  ring.writeback_stream_affinity = true;
  queues[0].write_in_task = true;
  occupy_slots(0);
  memset(&older, 0, sizeof(older));
  connection.active_background = connection.max_background = 4;
  connection.num_background = 8;
  list_add_tail(&older.list, &queues[0].fuse_req_bg_queue);
  for (unsigned i = 0; i < 24; i++) {
   incoming[i] = req;
   in.offset = (u64)(i + 1) * 16384;
   assert(fuse_uring_queue_bq_req(&incoming[i]));
   assert(!held && incoming[i].ring_queue == &queues[0]);
   assert(incoming[i].flags & (1ul << FR_URING));
  }
  assert(connection.num_background == 32);
  assert(connection.active_background == connection.max_background);
  assert(queues[0].active_background == 1);
  node = queues[0].fuse_req_bg_queue.first;
  assert(node == &older.list);
  node = node->next;
  for (unsigned i = 0; i < 24; i++) {
   assert(node == &incoming[i].list); node = node->next;
  }
  assert(!node && queues[0].fuse_req_bg_queue.last == &incoming[23].list);
  for (unsigned i = 1; i < 4; i++) {
   assert(list_empty(&queues[i].fuse_req_bg_queue));
   assert(!queues[i].active_background);
  }
  /* Teardown still returns failure without adding a new request. */
  queues[0].stopped = true;
  assert(!fuse_uring_queue_bq_req(&req));
  assert(!held && connection.num_background == 32);
  break;
 }
 case 14: /* Opt-in does not serialize copied or asynchronous fixed writes. */
  for (unsigned fixed = 0; fixed < 2; fixed++) {
   reset(fixed); ring.writeback_stream_affinity = true;
   queues[0].write_in_task = false;
   assert(select_queue() == 1);
  }
  break;
 case 15: /* Independent homes retain their own workers even when full. */
  reset(true); ring.writeback_stream_affinity = true;
  for (unsigned i = 0; i < 4; i++) {
   queues[i].write_in_task = true; occupy_slots(i);
  }
  for (unsigned i = 0; i < 24; i++) {
   in.offset = (u64)i * 16384;
   assert(select_from(i % 4) == i % 4);
  }
  break;
 case 16: /* A bounded group uses only its home and eligible neighbours. */
  for (unsigned width = 1; width <= 4; width++) {
   for (unsigned base = 0; base < 4; base++) {
    reset(true); ring.writeback_stream_affinity = true;
    ring.writeback_stream_queues = width;
    for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
    occupy_slots(base);
    for (unsigned i = 1; i < width; i++) {
     assert(select_from(base) == (base + i) % 4);
     occupy_slots((base + i) % 4);
    }
    /* Foreign free slots never expand the configured group. */
    assert(select_from(base) == base);
   }
  }
  break;
 case 17: /* Disabled, copied and non-WIT requests retain the full scan. */
  for (unsigned mode = 0; mode < 3; mode++) {
   reset(mode != 1);
   ring.writeback_stream_affinity = mode != 0;
   ring.writeback_stream_queues = 2;
   for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = mode == 0;
   occupy_slots(0); occupy_slots(1);
   assert(select_queue() == 2);
  }
  break;
 case 18: /* Busy, stopped, mismatched and contended neighbours are skipped. */
  for (unsigned mode = 0; mode < 5; mode++) {
   reset(true); ring.writeback_stream_affinity = true;
   ring.writeback_stream_queues = 2;
   for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
   occupy_slots(0);
   switch (mode) {
   case 0: queues[1].stopped = true; break;
   case 1: queues[1].zero_copy = false; break;
   case 2: queues[1].lock.contended = true; break;
   case 3: queues[1].write_in_task = false; break;
   case 4: queues[1].fuse_req_bg_queue.empty = false; break;
   }
   assert(select_queue() == 0);
  }
  break;
 case 19: /* A numeric node boundary must not spread one fixed stream remotely. */
  reset(true); ring.writeback_stream_affinity = true;
  ring.writeback_stream_queues = 4;
  for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
  cpu_nodes[1] = cpu_nodes[2] = 1;
  node_masks[0].cpus[1] = node_masks[0].cpus[2] = false;
  node_masks[1].cpus[1] = node_masks[1].cpus[2] = true;
  fuse_uring_init_stream_queues(&ring);
  occupy_slots(0); assert(select_queue() == 3);
  occupy_slots(3); assert(select_queue() == 0);
  /* A smaller node never borrows extra workers or visits the same queue twice. */
  assert(ring.writeback_next_queue[3] == 0);
  break;
 case 20: { /* Actual DELL numbering: 41..44 crosses nodes; 41,42,43,66 does not. */
  struct fuse_ring topology = {.nr_queues = 88};
  memset(node_masks, 0, sizeof(node_masks));
  for (unsigned cpu = 0; cpu < 88; cpu++) {
   int node = (cpu < 22 || (cpu >= 44 && cpu < 66)) ? 0 : 1;
   cpu_nodes[cpu] = node; node_masks[node].cpus[cpu] = true;
  }
  fuse_uring_init_stream_queues(&topology);
  assert(topology.writeback_next_queue[41] == 42);
  assert(topology.writeback_next_queue[42] == 43);
  assert(topology.writeback_next_queue[43] == 66);
  assert(topology.writeback_next_queue[87] == 22);
  for (unsigned home = 0; home < 88; home++) {
   unsigned qid = home;
   for (unsigned step = 1; step < 44; step++) {
    qid = topology.writeback_next_queue[qid];
    assert(qid < 88 && qid != home && cpu_nodes[qid] == cpu_nodes[home]);
   }
   assert(topology.writeback_next_queue[qid] == home);
  }
  break;
 }
 case 21: /* Missing, empty or out-of-range topology safely retains the home. */
  for (unsigned mode = 0; mode < 4; mode++) {
   reset(true);
   if (mode == 0) cpu_nodes[0] = NUMA_NO_NODE;
   if (mode == 1) memset(node_masks, 0, sizeof(node_masks));
   if (mode == 2) {
    memset(node_masks, 0, sizeof(node_masks)); node_masks[0].cpus[100] = true;
   }
   if (mode == 3) {
    memset(node_masks, 0, sizeof(node_masks)); node_masks[0].cpus[0] = true;
    node_masks[0].cpus[100] = true;
   }
   fuse_uring_init_stream_queues(&ring);
   assert(ring.writeback_next_queue[0] == 0);
  }
  break;
 case 22: /* Topology selection preserves contention, lifetime and FIFO checks. */
  for (unsigned mode = 0; mode < 5; mode++) {
   reset(true); ring.writeback_stream_affinity = true;
   ring.writeback_stream_queues = 4;
   for (unsigned i = 0; i < 4; i++) queues[i].write_in_task = true;
   cpu_nodes[1] = cpu_nodes[2] = 1;
   node_masks[0].cpus[1] = node_masks[0].cpus[2] = false;
   node_masks[1].cpus[1] = node_masks[1].cpus[2] = true;
   fuse_uring_init_stream_queues(&ring); occupy_slots(0);
   switch (mode) {
   case 0: refs[3] = NULL; break;
   case 1: queues[3].stopped = true; break;
   case 2: queues[3].lock.contended = true; break;
   case 3: queues[3].fuse_req_bg_queue.empty = false; break;
   case 4: queues[3].write_in_task = false; break;
   }
   assert(select_queue() == 0);
  }
  break;
 case 23: /* Copied, asynchronous fixed and disabled policy ignore the table. */
  for (unsigned mode = 0; mode < 3; mode++) {
   reset(mode != 0);
   ring.writeback_stream_affinity = mode != 2;
   ring.writeback_stream_queues = 4;
   for (unsigned i = 0; i < 4; i++) {
    queues[i].write_in_task = mode == 2;
    ring.writeback_next_queue[i] = i;
   }
   occupy_slots(0);
   assert(select_queue() == 1);
  }
  break;
 case 24: { /* Busy fixed workers must share both admitted and waiting work. */
  struct fuse_req incoming[168];
  unsigned queued[4] = {0};
  reset(true);
  ring.writeback_stream_affinity = true;
  ring.writeback_stream_queues = 4;
  connection.active_background = connection.num_background = 32;
  connection.max_background = 176;
  for (unsigned i = 0; i < 4; i++) {
   queues[i].write_in_task = true;
   queues[i].active_background = 8;
   occupy_slots(i);
  }
  for (unsigned i = 0; i < 168; i++) {
   incoming[i] = req;
   in.offset = (u64)(i + 1) * 16384;
   assert(fuse_uring_queue_bq_req(&incoming[i]));
   assert(!held && (incoming[i].flags & (1ul << FR_URING)));
  }
  for (unsigned i = 0; i < 4; i++)
   for (struct list_head *node = queues[i].fuse_req_bg_queue.first;
        node; node = node->next) queued[i]++;
  printf("fixed_group active=%u,%u,%u,%u queued=%u,%u,%u,%u\n",
         queues[0].active_background, queues[1].active_background,
         queues[2].active_background, queues[3].active_background,
         queued[0], queued[1], queued[2], queued[3]);
  fflush(stdout);
  assert(connection.active_background == 176 && connection.blocked);
  assert(connection.num_background == 200);
  for (unsigned i = 0; i < 4; i++) {
   struct list_head *node = queues[i].fuse_req_queue.first;
   assert(queues[i].active_background == 44 && queued[i] == 6);
   for (unsigned j = i; j < 144; j += 4) {
    assert(node == &incoming[j].list);
    assert(incoming[j].ring_queue == &queues[i]);
    node = node->next;
   }
   assert(!node);
   node = queues[i].fuse_req_bg_queue.first;
   for (unsigned j = 144 + i; j < 168; j += 4) {
    assert(node == &incoming[j].list);
    assert(incoming[j].ring_queue == &queues[i]);
    node = node->next;
   }
   assert(!node);
  }
  break;
 }
 case 25: { /* Saturated rotation cannot escape a bounded DELL NUMA group. */
  struct fuse_ring_queue storage[88], *entries[88];
  struct fuse_ring topology = {.nr_queues = 88, .queues = entries,
                               .writeback_stream_affinity = true};
  reset(true);
  memset(storage, 0, sizeof(storage));
  memset(node_masks, 0, sizeof(node_masks));
  for (unsigned cpu = 0; cpu < 88; cpu++) {
   int node = (cpu < 22 || (cpu >= 44 && cpu < 66)) ? 0 : 1;
   cpu_nodes[cpu] = node; node_masks[node].cpus[cpu] = true;
   entries[cpu] = &storage[cpu];
   storage[cpu].qid = cpu;
   storage[cpu].zero_copy = storage[cpu].write_in_task = true;
   storage[cpu].active_background = 8;
   storage[cpu].ent_avail_queue.empty = true;
   storage[cpu].fuse_req_queue.empty = true;
   storage[cpu].fuse_req_bg_queue.empty = true;
  }
  fuse_uring_init_stream_queues(&topology);
  for (unsigned home = 0; home < 88; home++) {
   for (unsigned width = 2; width <= 8; width *= 2) {
    topology.writeback_stream_queues = width;
    topology.bg_queue_seq = UINT32_MAX - 3;
    for (unsigned turn = 0; turn < 32; turn++) {
     unsigned expected = home;
     unsigned cursor = topology.bg_queue_seq;
     struct fuse_ring_queue *selected;
     for (unsigned step = 0; step < cursor % width; step++)
      expected = topology.writeback_next_queue[expected];
     selected = fuse_uring_lock_writeback_queue(&topology, &req, entries[home]);
     assert(held == 1 && selected->lock.held);
     assert(selected == entries[expected]);
     assert(cpu_nodes[selected->qid] == cpu_nodes[home]);
     spin_unlock(&selected->lock);
     assert(!held && topology.bg_queue_seq == cursor + 1);
    }
   }
  }
  break;
 }
 case 26: /* Saturated rotation still requires a live matching worker. */
  for (unsigned mode = 0; mode < 10; mode++) {
   reset(true); ring.writeback_stream_affinity = true;
   ring.writeback_stream_queues = 3; ring.bg_queue_seq = 1;
   for (unsigned i = 0; i < 4; i++) {
    queues[i].write_in_task = true; occupy_slots(i);
    queues[i].fuse_req_bg_queue.empty = false;
   }
   switch (mode) {
   case 0: queues[1].stopped = true; break;
   case 1: queues[1].zero_copy = false; break;
   case 2: queues[1].write_in_task = false; break;
   case 3: queues[1].lock.contended = true; break;
   case 4: refs[1] = NULL; break;
   case 5: queues[1].ent_in_userspace.empty = true; break;
   case 6: queues[1].ent_in_userspace.empty = true;
           queues[1].ent_released.empty = false; break;
   case 7: queues[1].ent_in_userspace.empty = true;
           queues[1].ent_w_req_queue.empty = false; break;
   case 8: queues[1].ent_in_userspace.empty = true;
           queues[1].ent_commit_queue.empty = false; break;
   case 9: queues[1].ent_avail_queue.empty = false; break;
   }
   assert(select_queue() == (mode >= 7 ? 1u : 2u));
  }
  break;
 case 27: /* A short or unknown topology never expands during saturation. */
  reset(true); ring.writeback_stream_affinity = true;
  ring.writeback_stream_queues = 4;
  for (unsigned i = 0; i < 4; i++) {
   queues[i].write_in_task = true; occupy_slots(i);
  }
  cpu_nodes[1] = cpu_nodes[2] = 1;
  node_masks[0].cpus[1] = node_masks[0].cpus[2] = false;
  node_masks[1].cpus[1] = node_masks[1].cpus[2] = true;
  fuse_uring_init_stream_queues(&ring);
  for (unsigned i = 0; i < 32; i++)
   assert(select_queue() == (i % 2 ? 3u : 0u));
  cpu_nodes[0] = NUMA_NO_NODE;
  fuse_uring_init_stream_queues(&ring);
  for (unsigned i = 0; i < 8; i++) assert(select_queue() == 0);
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
            code = HARNESS.replace("/* STREAM_TOPOLOGY */", kernel_function(
                "fuse_uring_init_stream_queues", "static void"))
            code = code.replace("/* SELECTOR */", kernel_function(
                "fuse_uring_lock_writeback_queue", "static struct fuse_ring_queue *"))
            code = code.replace("/* FLUSH_BACKGROUND */", kernel_function(
                "fuse_uring_flush_bg", "static void"))
            code = code.replace("/* ENQUEUE */", kernel_function(
                "fuse_uring_queue_bq_req", "static bool"))
            source.write_text(code)
            compile_run = subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
                "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", str(source), "-o", str(binary)],
                capture_output=True, text=True)
            self.assertEqual(compile_run.returncode, 0, compile_run.stderr)
            for scenario in range(28):
                with self.subTest(scenario=scenario):
                    run = subprocess.run([str(binary), str(scenario)],
                                         capture_output=True, text=True)
                    if scenario == 24:
                        print(run.stdout.strip(), flush=True)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
