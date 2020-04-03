
#include <linux/printk.h>
#include <linux/mm_econ.h>

// Estimates the change in the given metrics under the given action. Updates
// the given cost struct in place.
//
// Note that this is a pure function! It should not keep state regarding to
// previous queries.
void
mm_estimate_changes(const struct mm_action *action, struct mm_cost_delta *cost)
{
    switch (action->action) {
        case MM_ACTION_NONE:
            cost->kernel_computation = 0;
            cost->page_fault_freq = 0;
            cost->tlb_misses = 0;
            return;

        case MM_ACTION_PROMOTE_HUGE:
            // TODO(markm)
            cost->kernel_computation = 0;
            cost->page_fault_freq = 0;
            cost->tlb_misses = 0;
            return;

        case MM_ACTION_DEMOTE_HUGE:
            // TODO(markm)
            cost->kernel_computation = 0;
            cost->page_fault_freq = 0;
            cost->tlb_misses = 0;
            return;

        case MM_ACTION_RUN_DEFRAG:
            // TODO(markm)
            cost->kernel_computation = 0;
            cost->page_fault_freq = 0;
            cost->tlb_misses = 0;
            return;

        default:
            printk(KERN_WARNING "Unknown mm_action %d\n", action->action);
            return;
    }
}

// Decide whether to take an action with the given cost. Returns true if the
// action associated with `cost` should be TAKEN, and false otherwise.
bool mm_decide(const struct mm_cost_delta *cost)
{
    // TODO(markm): for now default to the normal linux behavior
    return true;
}
