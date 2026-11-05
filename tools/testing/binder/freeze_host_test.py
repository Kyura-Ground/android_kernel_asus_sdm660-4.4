#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise actual Binder functions with host stubs; does not build the kernel."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "drivers/android/binder.c").read_text()


def function(name):
    match = re.search(r"static (?:bool|int|void)\s+" + name + r"\([^;]*?\n\{.*?\n}",
                      SOURCE, re.S)
    if not match:
        raise RuntimeError("cannot extract " + name)
    return match.group()


STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define __packed __attribute__((packed))
#include <linux/android/binder.h>
#include <linux/android/binderfs.h>

_Static_assert(sizeof(struct binder_freeze_info) == 12, "freeze ABI");
_Static_assert(sizeof(struct binder_frozen_status_info) == 12, "status ABI");
_Static_assert(sizeof(struct binderfs_device) == 264, "binderfs ABI");
_Static_assert(BINDER_CTL_ADD == 0xc1086201U, "binderfs ioctl ABI");
_Static_assert(BINDER_FREEZE == 0x400c620eU, "freeze ioctl ABI");
_Static_assert(BINDER_GET_FROZEN_INFO == 0xc00c620fU, "status ioctl ABI");
_Static_assert(BR_FROZEN_REPLY == 0x7212, "frozen reply ABI");
_Static_assert(BR_TRANSACTION_PENDING_FROZEN == 0x7214, "pending reply ABI");
_Static_assert(_IOC_NR(BC_REQUEST_FREEZE_NOTIFICATION) == 19, "request ABI");
_Static_assert(_IOC_NR(BC_CLEAR_FREEZE_NOTIFICATION) == 20, "clear ABI");
_Static_assert(_IOC_NR(BC_FREEZE_NOTIFICATION_DONE) == 21, "ack ABI");
#ifdef BINDER_IPC_32BIT
_Static_assert(sizeof(struct binder_frozen_state_info) == 12, "32-bit state");
_Static_assert(BR_FROZEN_BINDER == 0x800c7215U, "32-bit state ioctl");
_Static_assert(BC_REQUEST_FREEZE_NOTIFICATION == 0x40086313U, "32-bit request");
#else
_Static_assert(sizeof(struct binder_frozen_state_info) == 16, "64-bit state");
_Static_assert(BR_FROZEN_BINDER == 0x80107215U, "64-bit state ioctl");
_Static_assert(BC_REQUEST_FREEZE_NOTIFICATION == 0x400c6313U, "64-bit request");
#endif

struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(h) (*(h) = (struct list_head){(h), (h)})
#define list_empty(h) ((h)->next == (h))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
    for (p = container_of((h)->next, __typeof__(*p), m); &p->m != (h); \
         p = container_of(p->m.next, __typeof__(*p), m))
static void list_del(struct list_head *p)
{
    p->prev->next = p->next;
    p->next->prev = p->prev;
    INIT_LIST_HEAD(p);
}
static void list_add_tail(struct list_head *p, struct list_head *h)
{
    assert(list_empty(p));
    p->prev = h->prev; p->next = h;
    h->prev->next = p; h->prev = p;
}
struct rb_node { struct rb_node *next; };
struct rb_root { struct rb_node *first; };
#define rb_first(r) ((r)->first)
#define rb_next(n) ((n)->next)
#define rb_entry container_of
struct binder_work { struct list_head entry; int type; };
enum {
    BINDER_WORK_TRANSACTION_COMPLETE = 2, BINDER_WORK_TRANSACTION_PENDING,
    BINDER_WORK_FROZEN_BINDER = 9, BINDER_WORK_CLEAR_FREEZE_NOTIFICATION
};
struct binder_ref_freeze {
    struct binder_work work;
    binder_uintptr_t cookie;
    bool is_frozen:1, sent:1, resend:1;
};
struct binder_priority { int prio, sched_policy; };
struct binder_proc {
    bool is_frozen, is_dead, sync_recv, async_recv;
    int outstanding_txns, freeze_wait, tmp_ref, pid;
    struct list_head todo, delivered_freeze;
    struct rb_root threads;
};
struct binder_node {
    struct binder_proc *proc;
    int min_priority, sched_policy;
    bool inherit_rt, has_async_transaction;
    struct list_head async_todo;
};
struct binder_thread {
    struct rb_node rb_node;
    bool is_dead;
    int task, pid;
    void *transaction_stack;
    struct list_head todo;
};
struct binder_ref { struct binder_node *node; struct binder_ref_freeze *freeze; };
struct binder_transaction;
struct binder_buffer {
    struct binder_node *target_node;
    struct binder_transaction *transaction;
};
struct binder_transaction {
    struct binder_buffer *buffer;
    struct binder_proc *to_proc;
    unsigned int flags;
    struct binder_work work;
    int lock;
};
static struct binder_ref *test_ref;
static int allocations, fail_alloc, wakes, notices, last_notice;
static int last_queue, lock_depth;
static int copy_fault;
#define __user
#define put_user(v, p) (copy_fault ? 1 : (*(p) = (v), 0))
#define binder_stat_br(...) ((void)0)
#define binder_debug(...) ((void)0)
#define GFP_KERNEL 0
#define BUG_ON(x) assert(!(x))
#define WARN_ON(x) assert(!(x))
#define READ_ONCE(x) (x)
#define binder_user_error(...) ((void)0)
#define binder_stats_created(x) ((void)0)
#define binder_stats_deleted(x) ((void)0)
#define binder_node_lock(x) (++lock_depth)
#define binder_node_unlock(x) (--lock_depth)
#define binder_inner_proc_lock(x) (++lock_depth)
#define binder_inner_proc_unlock(x) (--lock_depth)
#define binder_proc_lock(x) (++lock_depth)
#define binder_proc_unlock(x) (--lock_depth)
#define spin_lock(x) (++lock_depth)
#define spin_unlock(x) (--lock_depth)
#define binder_transaction_priority(task, tx, prio, rt) \
    ((void)(task), (void)(tx), (void)(prio), (void)(rt))
#define binder_wakeup_thread_ilocked(...) (++wakes)
#define binder_wakeup_proc_ilocked(...) (++wakes)
#define wake_up_interruptible_all(...) (++wakes)
#define atomic_inc(x) (++*(x))
#define binder_proc_dec_tmpref(p) (--(p)->tmp_ref)
#define msecs_to_jiffies(x) (x)
#define wait_event_interruptible_timeout(q, condition, timeout) \
    ((condition) ? 1 : 0)
static void *kzalloc(size_t size, int flags)
{
    void *p = fail_alloc ? NULL : calloc(1, size);
    if (p) ++allocations;
    return p;
}
static void kfree(void *p)
{
    if (p) --allocations;
    free(p);
}
static struct binder_ref *binder_get_ref_olocked(struct binder_proc *p,
                                                uint32_t handle, bool strong)
{
    return handle == 42 ? test_ref : NULL;
}
static struct binder_thread *binder_select_thread_ilocked(struct binder_proc *p)
{
    return NULL;
}
static void binder_enqueue_work_ilocked(struct binder_work *w, struct list_head *h)
{
    list_add_tail(&w->entry, h);
    last_queue = 1;
}
static void binder_enqueue_thread_work_ilocked(struct binder_thread *t,
                                              struct binder_work *w)
{
    list_add_tail(&w->entry, &t->todo);
    last_queue = 2;
}
static void binder_dequeue_work_ilocked(struct binder_work *w)
{
    list_del(&w->entry);
}
static void binder_add_freeze_work(struct binder_proc *p, bool frozen)
{
    ++notices;
    last_notice = frozen;
}
'''

TESTS = r'''
static void reset_proc(struct binder_proc *p)
{
    memset(p, 0, sizeof(*p));
    INIT_LIST_HEAD(&p->todo);
    INIT_LIST_HEAD(&p->delivered_freeze);
}
int main(void)
{
    struct binder_proc target, listener;
    struct binder_node node = { .proc = &target };
    struct binder_buffer buffer = { .target_node = &node };
    struct binder_transaction tx = { .buffer = &buffer, .to_proc = &target };
    struct binder_thread thread = {0};
    struct binder_ref ref = { .node = &node };
    struct binder_handle_cookie hc = { .handle = 42, .cookie = 1234 };
    struct binder_freeze_info info = { .enable = 1, .timeout_ms = 1 };
    struct binder_ref_freeze *freeze;
    struct binder_transaction *heap_tx;
    struct binder_work *complete;
    uint32_t returned;

    assert(!strcmp(binder_return_strings[_IOC_NR(BR_FROZEN_BINDER)],
                   "BR_FROZEN_BINDER"));
    assert(!strcmp(binder_command_strings[_IOC_NR(BC_FREEZE_NOTIFICATION_DONE)],
                   "BC_FREEZE_NOTIFICATION_DONE"));
    assert(!strcmp(binder_objstat_strings[BINDER_STAT_FREEZE], "freeze"));
    reset_proc(&target); reset_proc(&listener);
    INIT_LIST_HEAD(&node.async_todo);
    INIT_LIST_HEAD(&thread.todo);
    INIT_LIST_HEAD(&tx.work.entry);
    target.is_frozen = true;
    assert(binder_proc_transaction(&tx, &target, NULL) == BR_FROZEN_REPLY);
    assert(target.sync_recv && !target.outstanding_txns && !wakes);
    target.is_dead = true;
    assert(binder_proc_transaction(&tx, &target, NULL) == BR_DEAD_REPLY);
    target.is_dead = false;
    tx.flags = TF_ONE_WAY;
    assert(binder_proc_transaction(&tx, &target, NULL) ==
           BR_TRANSACTION_PENDING_FROZEN);
    assert(target.async_recv && target.outstanding_txns == 1 && last_queue == 1);
    list_del(&tx.work.entry);
    assert(binder_proc_transaction(&tx, &target, NULL) ==
           BR_TRANSACTION_PENDING_FROZEN);
    assert(!list_empty(&node.async_todo) && target.outstanding_txns == 2);
    list_del(&tx.work.entry);
    target.outstanding_txns = 0;
    node.has_async_transaction = false;
    target.is_frozen = false;
    tx.flags = 0;
    assert(binder_proc_transaction(&tx, &target, &thread) == 0);
    assert(target.outstanding_txns == 1 && last_queue == 2);
    list_del(&tx.work.entry);

    assert(binder_ioctl_freeze(&info, &target) == -EAGAIN);
    assert(!target.is_frozen && !notices);
    target.outstanding_txns = 0;
    thread.transaction_stack = &tx;
    target.threads.first = &thread.rb_node;
    assert(binder_ioctl_freeze(&info, &target) == -EAGAIN);
    assert(!target.is_frozen);
    thread.transaction_stack = NULL;
    assert(binder_ioctl_freeze(&info, &target) >= 0);
    assert(target.is_frozen && notices == 1 && last_notice);
    info.enable = 0;
    assert(binder_ioctl_freeze(&info, &target) == 0);
    assert(!target.is_frozen && !target.sync_recv && !target.async_recv);
    assert(notices == 2 && !last_notice);

    heap_tx = kzalloc(sizeof(*heap_tx), 0);
    heap_tx->to_proc = &target;
    heap_tx->buffer = &buffer;
    buffer.transaction = heap_tx;
    target.is_frozen = true;
    target.outstanding_txns = 1;
    wakes = 0;
    binder_free_transaction(heap_tx);
    assert(!target.outstanding_txns && !target.tmp_ref && wakes == 1);
    assert(!buffer.transaction && !allocations);
    complete = kzalloc(sizeof(*complete), 0);
    complete->type = BINDER_WORK_TRANSACTION_PENDING;
    copy_fault = 1;
    assert(read_complete(&listener, complete, &returned) == -EFAULT);
    assert(!allocations);
    complete = kzalloc(sizeof(*complete), 0);
    complete->type = BINDER_WORK_TRANSACTION_PENDING;
    copy_fault = 0;
    assert(read_complete(&listener, complete, &returned) == 0);
    assert(returned == BR_TRANSACTION_PENDING_FROZEN && !allocations);

    test_ref = &ref;
    fail_alloc = 1;
    assert(binder_request_freeze_notification(&listener, &thread, &hc) == -ENOMEM);
    fail_alloc = 0;
    hc.handle = 999;
    assert(binder_request_freeze_notification(&listener, &thread, &hc) == -EINVAL);
    assert(!allocations);
    hc.handle = 42;
    assert(binder_request_freeze_notification(&listener, &thread, &hc) == 0);
    freeze = ref.freeze;
    assert(freeze->is_frozen && freeze->cookie == hc.cookie && allocations == 1);
    assert(!list_empty(&listener.todo));
    assert(binder_request_freeze_notification(&listener, &thread, &hc) == -EINVAL);
    assert(allocations == 1);
    hc.cookie++;
    assert(binder_clear_freeze_notification(&listener, &thread, &hc) == -EINVAL);
    assert(ref.freeze == freeze);
    hc.cookie--;
    /* A normal ack leaves idle work; clearing must queue it again. */
    list_del(&freeze->work.entry);
    list_add_tail(&freeze->work.entry, &listener.delivered_freeze);
    freeze->sent = true;
    assert(binder_freeze_notification_done(&listener, &thread, hc.cookie) == 0);
    assert(list_empty(&listener.todo) && list_empty(&listener.delivered_freeze));
    assert(!freeze->sent);
    assert(binder_clear_freeze_notification(&listener, &thread, &hc) == 0);
    assert(!ref.freeze && !list_empty(&listener.todo));
    list_del(&freeze->work.entry);
    kfree(freeze);
    /* Clear a notification which has not yet been delivered. */
    target.is_frozen = false;
    assert(binder_request_freeze_notification(&listener, &thread, &hc) == 0);
    freeze = ref.freeze;
    assert(!freeze->is_frozen);
    assert(binder_clear_freeze_notification(&listener, &thread, &hc) == 0);
    assert(freeze->work.type == BINDER_WORK_CLEAR_FREEZE_NOTIFICATION);
    assert(!freeze->resend && !list_empty(&listener.todo));
    list_del(&freeze->work.entry);
    kfree(freeze);
    assert(binder_request_freeze_notification(&listener, &thread, &hc) == 0);
    freeze = ref.freeze;
    /* Model delivery; helper tests cover ack and clear ownership transitions. */
    list_del(&freeze->work.entry);
    list_add_tail(&freeze->work.entry, &listener.delivered_freeze);
    freeze->sent = true;
    assert(binder_clear_freeze_notification(&listener, &thread, &hc) == 0);
    assert(!ref.freeze && freeze->resend);
    assert(freeze->work.type == BINDER_WORK_CLEAR_FREEZE_NOTIFICATION);
    assert(binder_freeze_notification_done(&listener, &thread, hc.cookie) == 0);
    assert(list_empty(&listener.delivered_freeze) && !list_empty(&listener.todo));
    assert(!freeze->sent && !freeze->resend);
    list_del(&freeze->work.entry);
    kfree(freeze);
    assert(binder_freeze_notification_done(&listener, &thread, hc.cookie) == -EINVAL);
    /* A reference to a dead node may still register and clear a watch. */
    node.proc = NULL;
    assert(binder_request_freeze_notification(&listener, &thread, &hc) == 0);
    freeze = ref.freeze;
    assert(list_empty(&freeze->work.entry));
    assert(binder_clear_freeze_notification(&listener, &thread, &hc) == 0);
    assert(!list_empty(&listener.todo));
    list_del(&freeze->work.entry);
    kfree(freeze);
    assert(!allocations && lock_depth == 0);
    puts("PASS: ABI, frozen sync/async, pending replies, drain, notification lifecycle");
    return 0;
}
'''


def program():
    names = ("binder_proc_transaction", "binder_txns_pending_ilocked",
             "binder_ioctl_freeze", "binder_free_transaction",
             "binder_request_freeze_notification",
             "binder_clear_freeze_notification", "binder_freeze_notification_done")
    stats = "typedef int atomic_t;\n"
    for pattern in (r"enum binder_stat_types \{.*?\n};",
                    r"struct binder_stats \{.*?\n};",
                    r"static const char \* const binder_\w+_strings\[\] = \{.*?\n};"):
        matches = re.findall(pattern, SOURCE, re.S)
        if not matches:
            raise RuntimeError("missing statistics declaration: " + pattern)
        stats += "\n".join(matches) + "\n"
    stats += r'''
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
_Static_assert(COUNT(binder_return_strings) == _IOC_NR(BR_CLEAR_FREEZE_NOTIFICATION_DONE) + 1,
               "return statistics bounds");
_Static_assert(COUNT(binder_command_strings) == _IOC_NR(BC_FREEZE_NOTIFICATION_DONE) + 1,
               "command statistics bounds");
_Static_assert(COUNT(binder_objstat_strings) == BINDER_STAT_COUNT,
               "object statistics bounds");
'''
    start = SOURCE.index("\t\tcase BINDER_WORK_TRANSACTION_COMPLETE:",
                         SOURCE.index("static int binder_thread_read"))
    end = SOURCE.index("\t\tcase BINDER_WORK_NODE:", start)
    read_complete = r'''
static int read_complete(struct binder_proc *proc, struct binder_work *w,
                         uint32_t *result)
{
    void *ptr = result;
    uint32_t cmd;
    ++lock_depth;
    switch (w->type) {
''' + SOURCE[start:end] + r'''
    default: abort();
    }
    return 0;
}
'''
    return (STUBS + stats + "\n".join(function(name) for name in names)
            + read_complete + TESTS)


if __name__ == "__main__":
    compiler = shlex.split(os.environ.get("HOSTCC", "cc"))
    with tempfile.TemporaryDirectory(prefix="binder-freeze-host-") as tmp:
        headers = Path(tmp) / "include/linux/android"
        headers.mkdir(parents=True)
        for name in ("binder.h", "binderfs.h"):
            (headers / name).write_text(
                (ROOT / "include/uapi/linux/android" / name).read_text())
        source = Path(tmp) / "test.c"
        source.write_text(program())
        for abi in ([], ["-DBINDER_IPC_32BIT"]):
            binary = Path(tmp) / "test"
            subprocess.run(compiler + ["-std=gnu11", "-Wall", "-Wextra", "-Werror",
                           "-Wno-unused-parameter", "-I", str(Path(tmp) / "include")]
                           + abi + [str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
