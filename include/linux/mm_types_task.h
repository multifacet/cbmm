/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_TASK_H
#define _LINUX_MM_TYPES_TASK_H

/*
 * Here are the definitions of the MM data types that are embedded in 'struct task_struct'.
 *
 * (These are defined separately to decouple sched.h from mm_types.h as much as possible.)
 */

#include <linux/types.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>

#include <asm/page.h>

#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
#include <asm/tlbbatch.h>
#endif

#define USE_SPLIT_PTE_PTLOCKS	(NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS)
#define USE_SPLIT_PMD_PTLOCKS	(USE_SPLIT_PTE_PTLOCKS && \
		IS_ENABLED(CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK))
#define ALLOC_SPLIT_PTLOCKS	(SPINLOCK_SIZE > BITS_PER_LONG/8)

/*
 * The per task VMA cache array:
 */
#define VMACACHE_BITS 2
#define VMACACHE_SIZE (1U << VMACACHE_BITS)
#define VMACACHE_MASK (VMACACHE_SIZE - 1)

struct vmacache {
	u64 seqnum;
	struct vm_area_struct *vmas[VMACACHE_SIZE];
};

/*
 * When updating this, please also update struct resident_page_types[] in
 * kernel/fork.c
 */
enum {
	MM_FILEPAGES,	/* Resident file mapping pages */
	MM_ANONPAGES,	/* Resident anonymous pages */
	MM_SWAPENTS,	/* Anonymous swap entries */
	MM_SHMEMPAGES,	/* Resident shared memory pages */
	NR_MM_COUNTERS
};

#if USE_SPLIT_PTE_PTLOCKS && defined(CONFIG_MMU)
#define SPLIT_RSS_COUNTING
/* per-thread cached information, */
struct task_rss_stat {
	int events;	/* for synchronization threshold */
	int count[NR_MM_COUNTERS];
};
#endif /* USE_SPLIT_PTE_PTLOCKS */

struct mm_rss_stat {
	atomic_long_t count[NR_MM_COUNTERS];
};

struct badger_trap_stats {
	u64 total_dtlb_4kb_store_misses;
	u64 total_dtlb_2mb_store_misses;
	u64 total_dtlb_4kb_load_misses;
	u64 total_dtlb_2mb_load_misses;

	spinlock_t lock;
};

static inline void badger_trap_stats_clear(struct badger_trap_stats *stats)
{
	stats->total_dtlb_4kb_store_misses = 0;
	stats->total_dtlb_2mb_store_misses = 0;
	stats->total_dtlb_4kb_load_misses  = 0;
	stats->total_dtlb_2mb_load_misses  = 0;
}

static inline void badger_trap_stats_init(struct badger_trap_stats *stats)
{
	badger_trap_stats_clear(stats);
	spin_lock_init(&stats->lock);
}

static inline void badger_trap_add_stats(
		struct badger_trap_stats *to,
		const struct badger_trap_stats *from)
{
	//spin_lock(&to->lock);
	to->total_dtlb_4kb_store_misses += from->total_dtlb_4kb_store_misses;
	to->total_dtlb_2mb_store_misses += from->total_dtlb_2mb_store_misses;
	to->total_dtlb_4kb_load_misses += from->total_dtlb_4kb_load_misses;
	to->total_dtlb_2mb_load_misses += from->total_dtlb_2mb_load_misses;
	//spin_unlock(&to->lock); // TODO uncomment
}

struct page_frag {
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	__u32 offset;
	__u32 size;
#else
	__u16 offset;
	__u16 size;
#endif
};

/* Track pages that require TLB flushes */
struct tlbflush_unmap_batch {
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	/*
	 * The arch code makes the following promise: generic code can modify a
	 * PTE, then call arch_tlbbatch_add_mm() (which internally provides all
	 * needed barriers), then call arch_tlbbatch_flush(), and the entries
	 * will be flushed on all CPUs by the time that arch_tlbbatch_flush()
	 * returns.
	 */
	struct arch_tlbflush_unmap_batch arch;

	/* True if a flush is needed. */
	bool flush_required;

	/*
	 * If true then the PTE was dirty when unmapped. The entry must be
	 * flushed before IO is initiated or a stale TLB entry potentially
	 * allows an update without redirtying the page.
	 */
	bool writable;
#endif
};

#endif /* _LINUX_MM_TYPES_TASK_H */
