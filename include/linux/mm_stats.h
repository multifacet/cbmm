#ifndef _MM_STATS_H_
#define _MM_STATS_H_

#include <linux/proc_fs.h>
#include <linux/types.h>

///////////////////////////////////////////////////////////////////////////////
// Histograms.

struct mm_hist;

void mm_stats_init(void);

// Add the measurement `val` to the histogram `hist`.
void mm_stats_hist_measure(struct mm_hist *hist, u64 val);

// Externed stats...
extern struct mm_hist mm_base_page_fault_cycles;
extern struct mm_hist mm_huge_page_fault_cycles;
extern struct mm_hist mm_huge_page_fault_create_new_cycles;
extern struct mm_hist mm_huge_page_fault_clear_cycles;
extern struct mm_hist mm_huge_page_fault_zero_page_cycles;
extern struct mm_hist mm_huge_page_fault_wp_cycles;
extern struct mm_hist mm_huge_page_fault_cow_copy_huge_cycles;
extern struct mm_hist mm_direct_compaction_cycles;
extern struct mm_hist mm_indirect_compaction_cycles;
extern struct mm_hist mm_direct_reclamation_cycles;
extern struct mm_hist mm_huge_page_promotion_scanning_cycles;
extern struct mm_hist mm_huge_page_promotion_work_cycles;
extern struct mm_hist mm_huge_page_promotion_copy_pages_cycles;
extern struct mm_hist mm_process_huge_page_cycles;
extern struct mm_hist mm_process_huge_page_single_page_cycles;

extern struct mm_hist mm_econ_cost;
extern struct mm_hist mm_econ_benefit;

///////////////////////////////////////////////////////////////////////////////
// Page fault tracing.

typedef u64 mm_stats_bitflags_t;

struct mm_stats_pftrace {
	// A bunch of bitflags indicating things that happened during this #PF.
	// See `mm_econ_flags` for more info.
	mm_stats_bitflags_t bitflags;

	// The start and end TSC of the #PF.
	u64 start_tsc;
	u64 end_tsc;

	// Timestamps at which the #PF did the following:
	u64 alloc_start_tsc; // started allocating memory
	u64 alloc_end_tsc;   // finished allocating memory (or OOMed)
	// In normal linux, this will include the time to zero if GFP_ZERO was
	// passed to the allocator. Thus, we have another measurement that
	// includes ONLY THE TIME TO ZERO THE PAGE IN THE ALLOCATOR. This value
	// is only preset if MM_STATS_PF_CLEARED_MEM is set:
	u64 alloc_zeroing_duration;

	u64 prep_start_tsc;  // started preparing the alloced mem
	u64 prep_end_tsc;    // finished ...
};

// A bunch of bit flags that indicate things that could happen during a #PF.
//
// NOTE: Don't forget to update mm_stats_pf_flags_names!
enum mm_stats_pf_flags {
	// Set: a huge page was allocated/promoted/mapped.
	// Clear: a base page was allocated/promoted/mapped.
	MM_STATS_PF_HUGE_PAGE, // 2MB
	MM_STATS_PF_VERY_HUGE_PAGE, // 1GB -- should never happen

	// Set: this fault was a BadgerTrap fault.
	MM_STATS_PF_BADGER_TRAP,

	// Set: this fault was a write-protected page.
	MM_STATS_PF_WP,

	// Set: this fault was a "NUMA hinting fault", possibly with a migration.
	MM_STATS_PF_NUMA,

	// Set: this fault required a swap-in.
	MM_STATS_PF_SWAP,

	// Set: this fault was not anonymous (usually this means it was a
	// file-backed memory region).
	MM_STATS_PF_NOT_ANON,

	// Set: this fault mapped a zero-page.
	MM_STATS_PF_ZERO,

	// Set: attempted and failed to allocate a 2MB page.
	MM_STATS_PF_HUGE_ALLOC_FAILED,

	// Set: a huge page was split.
	MM_STATS_PF_HUGE_SPLIT,

	// Set: an address range was promoted to a huge page (as opposed to
	// freshly created as a huge page).
	MM_STATS_PF_HUGE_PROMOTION,

	// Set: we attempted to do a promotion and failed.
	MM_STATS_PF_HUGE_PROMOTION_FAILED,

	// Set: page contents were copied during promotion.
	MM_STATS_PF_HUGE_COPY,

	// Set: when a page is zeroed/cleared.
	MM_STATS_PF_CLEARED_MEM,

	// Set: the physical memory allocator fell back to the slow path.
	MM_STATS_PF_ALLOC_FALLBACK,

	// Set: the physical memory allocator slowpath executed multiple times.
	MM_STATS_PF_ALLOC_FALLBACK_RETRY,

	// Set: the physical memory allocator slowpath executed page reclamation.
	MM_STATS_PF_ALLOC_FALLBACK_RECLAIM,

	// Set: the physical memory allocator slowpath executed page compaction.
	MM_STATS_PF_ALLOC_FALLBACK_COMPACT,

	// NOTE: must be the last value in the enum... not actually a flag.
	MM_STATS_NUM_FLAGS,
};
static_assert(MM_STATS_NUM_FLAGS <= sizeof(mm_stats_bitflags_t) * 8);

// Names of the above flags for printing as text.
extern char *mm_stats_pf_flags_names[MM_STATS_NUM_FLAGS];

// Hacky mechanism for determining if last allocation has failed.
DECLARE_PER_CPU(bool, pftrace_alloc_fallback);
DECLARE_PER_CPU(bool, pftrace_alloc_fallback_retry);
DECLARE_PER_CPU(bool, pftrace_alloc_fallback_reclaim);
DECLARE_PER_CPU(bool, pftrace_alloc_fallback_compact);
DECLARE_PER_CPU(bool, pftrace_alloc_zeroed_page);
DECLARE_PER_CPU(u64, pftrace_alloc_zeroing_duration);

static inline void mm_stats_set_flag(
		struct mm_stats_pftrace *trace,
		enum mm_stats_pf_flags flag)
{
	trace->bitflags |= 1ull << flag;
}

static inline void mm_stats_clear_flag(
		struct mm_stats_pftrace *trace,
		enum mm_stats_pf_flags flag)
{
	trace->bitflags &= ~(1ull << flag);
}

static inline bool mm_stats_test_flag(
		struct mm_stats_pftrace *trace,
		enum mm_stats_pf_flags flag)
{
	return !!(trace->bitflags & (1ull << flag));
}

static inline void mm_stats_check_alloc_fallback(
		struct mm_stats_pftrace *trace)
{
	if (get_cpu_var(pftrace_alloc_fallback)) {
		mm_stats_set_flag(trace, MM_STATS_PF_ALLOC_FALLBACK);
	}
	if (get_cpu_var(pftrace_alloc_fallback_retry)) {
		mm_stats_set_flag(trace, MM_STATS_PF_ALLOC_FALLBACK_RETRY);
	}
	if (get_cpu_var(pftrace_alloc_fallback_reclaim)) {
		mm_stats_set_flag(trace, MM_STATS_PF_ALLOC_FALLBACK_RECLAIM);
	}
	if (get_cpu_var(pftrace_alloc_fallback_compact)) {
		mm_stats_set_flag(trace, MM_STATS_PF_ALLOC_FALLBACK_COMPACT);
	}
}

static inline void mm_stats_check_alloc_zeroing(
		struct mm_stats_pftrace *trace)
{
	if (get_cpu_var(pftrace_alloc_zeroed_page)) {
		mm_stats_set_flag(trace, MM_STATS_PF_CLEARED_MEM);
		trace->alloc_zeroing_duration =
			get_cpu_var(pftrace_alloc_zeroing_duration);
	}
}

// Initialize the given struct.
void mm_stats_pftrace_init(struct mm_stats_pftrace *trace);

// Registers a complete sample with the sampling system after it is complete
// (i.e. at the end of a page fault). The sampling system may then choose to
// store or drop the sample probablistically.
void mm_stats_pftrace_submit(struct mm_stats_pftrace *trace);

#endif
