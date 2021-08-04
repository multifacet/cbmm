#ifndef _MM_ECON_H_
#define _MM_ECON_H_

#include <linux/fs.h>
#include <linux/types.h>

// Various possible actions, to be used with `struct mm_action`.
#define MM_ACTION_NONE                 0
#define MM_ACTION_PROMOTE_HUGE  (1 <<  0)
#define MM_ACTION_DEMOTE_HUGE   (1 <<  1)
#define MM_ACTION_RUN_DEFRAG    (1 <<  2) // kcompactd
#define MM_ACTION_ALLOC_RECLAIM (1 <<  3)
#define MM_ACTION_EAGER_PAGING  (1 <<  4)
#define MM_ACTION_RUN_PREZEROING (1 <<  5) // asynczero
#define MM_ACTION_RUN_PROMOTION (1 <<  6) // khugepaged

// The length of one Long Time Unit (LTU), the fundamental time accounting unit
// of mm_econ. This value is in milliseconds (1 LTU = MM_ECON_LTU ms).
#define MM_ECON_LTU 10000

extern const struct file_operations proc_mmap_filters_operations;
extern const struct file_operations proc_mem_ranges_operations;

// An action that may be taken by the memory management subsystem.
struct mm_action {
    int action;

    u64 address;

    // Extra parameters of the action.
    union {
        // No extra parameters are needed.
        u64 unused;

        // How large is the huge page we are creating? This is the order (e.g. 2MB would be 9)
        u64 huge_page_order;

        // How many pages are prezeroed?
        u64 prezero_n;
    };
};

enum mm_memory_section {
    SectionCode,
    SectionData,
    SectionHeap,
    SectionMmap,
};

// A typedef for function pointers for tlb miss estimator functions to be used
// in estimating the number of TLB misses caused by the given page.
//
// The return value must be in units of `misses per LTU`.
typedef u64 (*mm_econ_tlb_miss_estimator_fn_t)(const struct mm_action *);

void register_mm_econ_tlb_miss_estimator(mm_econ_tlb_miss_estimator_fn_t f);

// The cost of a particular action relative to the status quo.
struct mm_cost_delta {
    //// Difference in the number of TLB misses.
    //s64 tlb_misses;

    //// Difference in the number of page faults.
    //s64 page_fault_freq;

    //// CPU time spent doing things like coalescing/defraging/zeroing pages.
    //s64 kernel_computation;

    // Total estimated cost in cycles.
    u64 cost;

    // Total estimated benefit in cycles.
    u64 benefit;

    // HACK: extra info about assumptions the estimator made. This isn't
    // fundamentally needed, but it is the fastest way to avoid races between
    // the estimator and the execution of policies.
    int extra;
};

inline bool mm_process_is_using_cbmm(pid_t pid);

bool mm_econ_is_on(void);

bool mm_decide(const struct mm_cost_delta *cost);

void
mm_estimate_changes(const struct mm_action *action, struct mm_cost_delta *cost);

void mm_register_promotion(u64 addr);

void
mm_add_memory_range(pid_t pid, enum mm_memory_section section, u64 mapaddr, u64 section_off,
        u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off);

void mm_copy_profile(pid_t old_pid, pid_t new_pid);
void mm_profile_check_exiting_proc(pid_t pid);

u64 mm_estimated_prezeroed_used(void);

extern int mm_econ_debugging_mode;
#endif
