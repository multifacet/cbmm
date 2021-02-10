#ifndef _MM_ECON_H_
#define _MM_ECON_H_

#include <linux/types.h>

// Various possible actions, to be used with `struct mm_action`.
#define MM_ACTION_NONE                 0
#define MM_ACTION_PROMOTE_HUGE  (1 <<  0)
#define MM_ACTION_DEMOTE_HUGE   (1 <<  1)
#define MM_ACTION_RUN_DEFRAG    (1 <<  2)
#define MM_ACTION_ALLOC_RECLAIM (1 <<  3)

// The length of one Long Time Unit (LTU), the fundamental time accounting unit
// of mm_econ. This value is in milliseconds (1 LTU = MM_ECON_LTU ms).
#define MM_ECON_LTU 10000

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

        // How long the defragmenter runs.
        u64 how_long;
    };
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
};

bool mm_econ_is_on(void);

bool mm_decide(const struct mm_cost_delta *cost);

void
mm_estimate_changes(const struct mm_action *action, struct mm_cost_delta *cost);

void mm_register_promotion(u64 addr);

#endif
