/*
 * Implementation of cost-benefit based memory management.
 */

#include <linux/printk.h>
#include <linux/mm_econ.h>
#include <linux/mm.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/hashtable.h>
#include <linux/mm_stats.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/task.h>

#define HUGE_PAGE_ORDER 9

#define MMAP_FILTER_BUF_SIZE 4096
#define MMAP_FILTER_BUF_DEAD_ZONE 128

///////////////////////////////////////////////////////////////////////////////
// Globals...

// Modes:
// - 0: off (just use default linux behavior)
// - 1: on (cost-benefit estimation)
static int mm_econ_mode = 0;

// The Preloaded Profile, if any.
struct profile_range {
    u64 start;
    u64 end;
    // This should already be in units of misses/huge-page/LTU.
    u64 misses;

    struct rb_node node;
};

// The operator to use when deciding if quantity from an mmap matches
// the filter.
enum mmap_comparator {
    CompEquals,
    CompGreaterThan,
    CompLessThan
};

// The different quantities that can be compared in an mmap
enum mmap_quantity {
    QuantSectionOff,
    QuantAddr,
    QuantLen,
    QuantProt,
    QuantFlags,
    QuantFD,
    QuantOff
};

// A comaprison for filtering an mmap with and how to compare the quantity
struct mmap_comparison {
    struct list_head node;
    enum mmap_quantity quant;
    enum mmap_comparator comp;
    u64 val;
};

// A list of quantities of a mmap to use for deciding if that mmap would
// benefit from being huge.
struct mmap_filter {
    struct list_head node;
    enum mm_memory_section section;
    u64 misses;
    struct list_head comparisons;
};

// A process using mmap filters
struct mmap_filter_proc {
    struct list_head node;
    pid_t pid;
    struct list_head filters;
    struct rb_root ranges_root;
};

// List of processes using mmap filters
static LIST_HEAD(filter_procs);

// The TLB misses estimator, if any.
static mm_econ_tlb_miss_estimator_fn_t tlb_miss_est_fn = NULL;

// Some stats...

// Number of estimates made.
static u64 mm_econ_num_estimates = 0;
// Number of decisions made.
static u64 mm_econ_num_decisions = 0;
// Number of decisions that are "yes".
static u64 mm_econ_num_decisions_yes = 0;
// Number of huge page promotions in #PFs.
static u64 mm_econ_num_hp_promotions = 0;
// Number of times we decided to run async compaction.
static u64 mm_econ_num_async_compaction = 0;
// Number of times we decided to run async prezeroing.
static u64 mm_econ_num_async_prezeroing = 0;

extern inline struct task_struct *extern_get_proc_task(const struct inode *inode);

///////////////////////////////////////////////////////////////////////////////
// Actual implementation
//
// There are two possible estimators:
// 1. kbadgerd (via tlb_miss_est_fn).
// 2. A pre-loaded profile (via preloaded_profile).
//
// In both cases, the required units are misses/huge-page/LTU.

void register_mm_econ_tlb_miss_estimator(
        mm_econ_tlb_miss_estimator_fn_t f)
{
    BUG_ON(!f);
    tlb_miss_est_fn = f;
    pr_warn("mm: registered TLB miss estimator %p\n", f);
}
EXPORT_SYMBOL(register_mm_econ_tlb_miss_estimator);

/*
 * Search the profile for the range containing the given address, and return
 * it. Otherwise, return NULL.
 */
static struct profile_range *
profile_search(struct rb_root *ranges_root, u64 addr)
{
    struct rb_node *node = ranges_root->rb_node;

    while (node) {
        struct profile_range *range =
            container_of(node, struct profile_range, node);

        if (range->start <= addr && addr < range->end)
            return range;

        if (addr < range->start)
            node = node->rb_left;
        else
            node = node->rb_right;
    }

    return NULL;
}

/*
 * Search the tree for the first range that satisfies the condition
 * of "there exists some address x in range s.t. x <comp> addr."
 * This is only used for filter comparisons on the section_off quantity
 */
static struct profile_range *
profile_find_first_range(struct rb_root *ranges_root, u64 addr,
        enum mmap_comparator comp)
{
    struct profile_range *result = NULL;
    struct profile_range *range = NULL;
    struct rb_node *node = ranges_root->rb_node;

    // First find any range that satisfies the condition
    while (node) {
        range = container_of(node, struct profile_range, node);

        if (comp == CompLessThan) {
            if (range->start < addr) {
                result = range;
                break;
            } else {
                node = node->rb_left;
            }
        } else if (comp == CompGreaterThan) {
            if (range->end > addr) {
                result = range;
                break;
            } else {
                node = node->rb_right;
            }
        } else if (comp == CompEquals) {
            if (range->start <= addr && addr < range->end) {
                // Since only ranges do not overlap, we just need
                // to find one range that overlaps with addr
                return range;
            } else if (range->start < addr) {
                node = node->rb_right;
            } else {
                node = node->rb_left;
            }
        } else {
            return NULL;
        }
    }

    if (!node)
        return NULL;

    while (node) {
        range = container_of(node, struct profile_range, node);

        if (comp == CompLessThan) {
            if (range->start >= addr)
                break;

            result = range;
            node = rb_next(node);
        } else if (comp == CompGreaterThan) {
            if (range->end <= addr)
                break;

            result = range;
            node = rb_prev(node);
        }
    }

    return result;
}

static inline bool
ranges_overlap(struct profile_range *r1, struct profile_range *r2)
{
    return (((r1->start <= r2->start && r2->start < r1->end)
        || (r2->start <= r1->start && r1->start < r2->end)));
}

/*
 * Remove all ranges overlapping with the new range
 */
static void remove_overlapping_ranges(struct rb_root *ranges_root,
    struct profile_range *new_range)
{
    struct rb_node *node = ranges_root->rb_node;
    struct rb_node *first_overlapping = NULL;
    struct rb_node *next;
    struct profile_range *cur_range;

    // First, find the earliest range that overlaps with the new range, if there is any
    while (node) {
        cur_range = container_of(node, struct profile_range, node);


        if (ranges_overlap(new_range, cur_range)) {
            first_overlapping = node;
            // We've found one node that overlaps, but keep going to see if we
            // can find an earlier one
            node = node->rb_left;
            continue;
        }

        if (new_range->start < cur_range->start)
            node = node->rb_left;
        else
            node = node->rb_right;
    }

    // If no overlapping range exists, we're done
    if (!first_overlapping)
        return;

    // Now we can delete all of the overlapping ranges
    node = first_overlapping;
    next = rb_next(node);
    cur_range = container_of(node, struct profile_range, node);
    while (ranges_overlap(new_range, cur_range)) {
        rb_erase(node, ranges_root);
        vfree(cur_range);

        if (!next)
            break;

        node = next;
        next = rb_next(node);
        cur_range = container_of(node, struct profile_range, node);
    }
}

/*
 * Insert the given range into the profile.
 * If the new range overlaps with any existing ranges, delete the
 * existing ones as must have been unmapped.
 */
static void
profile_range_insert(struct rb_root *ranges_root, struct profile_range *new_range)
{
    struct rb_node **new = &(ranges_root->rb_node), *parent = NULL;

    remove_overlapping_ranges(ranges_root, new_range);

    while (*new) {
        struct profile_range *this =
            container_of(*new, struct profile_range, node);

        parent = *new;
        if (new_range->start < this->start)
            new = &((*new)->rb_left);
        else if (new_range->start > this->start)
            new = &((*new)->rb_right);
        else
            break;
    }

    rb_link_node(&new_range->node, parent, new);
    rb_insert_color(&new_range->node, ranges_root);
}

/*
 * Move the ranges in one rb_tree to another
 */
static void
profile_move(struct rb_root *src, struct rb_root *dst)
{
    struct profile_range *range;
    struct rb_node *node = src->rb_node;

    while (node) {
        range = container_of(node, struct profile_range, node);

        // Remove the entry from the source
        rb_erase(node, src);

        // Add the entry to the destination
        profile_range_insert(dst, range);

        node = src->rb_node;
    }
}

static void
profile_free_all(struct rb_root *ranges_root)
{
    struct rb_node *node = ranges_root->rb_node;

    while(node) {
        struct profile_range *range =
            container_of(node, struct profile_range, node);

        rb_erase(node, ranges_root);
        node = ranges_root->rb_node;

        vfree(range);
    }
}

static void mmap_filters_free_all(struct mmap_filter_proc *proc)
{
    struct mmap_filter *filter;
    struct mmap_comparison *comparison;
    struct list_head *pos, *n;
    struct list_head *cPos, *cN;

    list_for_each_safe(pos, n, &proc->filters) {
        filter = list_entry(pos, struct mmap_filter, node);

        // Free each comparison in this filter
        list_for_each_safe(cPos, cN, &filter->comparisons) {
            comparison = list_entry(cPos, struct mmap_comparison, node);
            list_del(cPos);
            vfree(comparison);
        }

        list_del(pos);
        vfree(filter);
    }
}

enum free_huge_page_status {
    fhps_none, // no free huge pages
    fhps_free, // huge pages are available
    fhps_zeroed, // huge pages are available and prezeroed!
};

static enum free_huge_page_status
have_free_huge_pages(void)
{
    struct zone *zone;
    struct page *page;
    struct free_area *area;
    struct zoneref *z;
    gfp_t gfp = GFP_TRANSHUGE_LIGHT;
    enum zone_type high_zoneidx = gfp_zone(gfp);
    struct zonelist *zonelist = node_zonelist(numa_node_id(), gfp);
    int order;
    unsigned long flags;
    bool is_free = false, is_zeroed = false;

    for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {
        for (order = HUGE_PAGE_ORDER; order < MAX_ORDER; ++order) {
            area = &(zone->free_area[order]);
            is_free = area->nr_free > 0;

            if (is_free) {
                spin_lock_irqsave(&zone->lock, flags);

                page = list_first_entry_or_null(
                        &area->free_list[MIGRATE_MOVABLE], struct page,
                        lru);
                is_zeroed = page && PageZeroed(page);

                spin_unlock_irqrestore(&zone->lock, flags);

                break;
            }
        }
    }

    return is_zeroed ? fhps_zeroed :
        is_free ? fhps_free :
        fhps_none;
}

static u64
compute_hpage_benefit_from_profile(
        const struct mm_action *action)
{
    u64 ret = 0;
    struct mmap_filter_proc *proc;
    struct profile_range *range = NULL;

    list_for_each_entry(proc, &filter_procs, node) {
        if (proc->pid == current->tgid) {
            range = profile_search(&proc->ranges_root, action->address);
            break;
        }
    }

    if (range) {
        ret = range->misses;

        //pr_warn("mm_econ: estimating page benefit: "
        //        "misses=%llu size=%llu per-page=%llu\n",
        //        range->misses,
        //        (range->end - range->start) >> HPAGE_SHIFT,
        //        ret);
    }

    return ret;
}

static u64
compute_hpage_benefit(const struct mm_action *action)
{
    if (tlb_miss_est_fn)
        return tlb_miss_est_fn(action);
    else
        return compute_hpage_benefit_from_profile(action);
}

// Estimate cost/benefit of a huge page promotion for the current process.
void
mm_estimate_huge_page_promote_cost_benefit(
       const struct mm_action *action, struct mm_cost_delta *cost)
{
    // Estimated cost.
    //
    // For now, we hard-code a bunch of stuff, and we make a lot of
    // assumptions. We can relax these assumptions later if we need to.

    // TODO: Assume allocation is free if we have free huge pages.
    // TODO: Assume we don't care what node it is on...
    // TODO: Maybe account for opportunity cost as rate/ratio?
    const enum free_huge_page_status fhps = have_free_huge_pages();
    const u64 alloc_cost = fhps > fhps_none ? 0 : (1ul << 32);

    // TODO: Assume constant prep costs (zeroing or copying).
    const u64 prep_cost = fhps > fhps_free ? 0 : 100 * 2000; // ~100us

    // Compute total cost.
    cost->cost = alloc_cost + prep_cost;

#define TLB_MISS_COST 50 //cycles

    // Estimate benefit.
    cost->benefit = TLB_MISS_COST * compute_hpage_benefit(action);
}

// Update the given cost/benefit to also account for reclamation of a huge
// page. This assumes that there is already a cost/benefit in `cost`.
void
mm_estimate_huge_page_reclaim_cost(
       const struct mm_action *action, struct mm_cost_delta *cost)
{
    // TODO(markm): for now just assume it is very expensive. We might want to
    // do something more clever later. For example, we can look at the amount
    // of fragmentation or the amount of free memory. If we are heavily
    // fragmented and under memory pressure, then reclaim will be expensive.
    const u64 reclaim_cost = 1000000000; // ~hundreds of ms

    cost->cost += reclaim_cost;
}

// Estimate the cost of running a daemon. In general, this is just the time
// that the daemon runs unless the system is idle -- idle time is considered
// free to consume.
void
mm_estimate_daemon_cost(
       const struct mm_action *action, struct mm_cost_delta *cost)
{
    // FIXME(markm): for now we just use the average system load on all cores
    // because this is easy and cheap. However, we can get something more
    // precise by looking at the number of currently running tasks on only
    // local cores or something like that...
    //
    // nrunning = 0;
    // for_each_cpu_and(cpu, cpumask_of_node(node), cpu_online_mask)
    //   nrunning += cpu_rq(cpu)->nr_running;
    //
    // if (nrunning < ncpus_local)
    //   cost = 0;
    // else
    //   cost = time_to_run;

    const u64 huge_page_zeroing_cost = 100000;

    __kernel_ulong_t loads[3]; /* 1, 5, and 15 minute load averages */
    int ncpus = num_online_cpus();

    get_avenrun(loads, 0, SI_LOAD_SHIFT - FSHIFT);

    // If we have more cpus than load, running a background daemon is free.
    // Otherwise, the cost is however many cycles the daemon runs, as this is
    // time that is taken away from applications.
    if (ncpus > LOAD_INT(loads[0])) {
        cost->cost = 0;
    } else {
        switch (action->action) {
            case MM_ACTION_RUN_PREZEROING:
                cost->cost = huge_page_zeroing_cost * action->prezero_n;
                break;

            case MM_ACTION_RUN_DEFRAG:
            case MM_ACTION_RUN_PROMOTION:
                // TODO(markm): this should be however long the daemon runs
                // for, which means we need to cap the run time. There are also
                // costs for copying pages and scanning.
                //
                // For now, we just make these really expensive.
                cost->cost = 1ul << 32; // >1s
                break;

            default: // Not a daemon...
                BUG();
                return;
        }
    }
}

// Estimate the benefit of prezeroing memory based on the rate of usage of
// zeroed pages so far.
void mm_estimate_async_prezeroing_benefit(
       const struct mm_action *action, struct mm_cost_delta *cost)
{
    // FIXME(markm): we assume that the cost to zero a 2MB region is about 10^6
    // cycles. This is based on previous measurements we've made.
    const u64 zeroing_per_page_cost = 1000000; // cycles

    // The maximum amount of benefit is based on the number of pages we
    // actually zero and actually use. That is, we don't benefit from zeroed
    // pages that are not used, and we do not benefit from unzeroed pages.
    //
    // We will zero no more than `action->prezero_n` pages, and we will use (we
    // estimate) no more than `recent_used` pages, so the benefit is capped at
    // the minimum of these. The `recent_used` is the estimated number of pages
    // used recently.
    const u64 recent_used = mm_estimated_prezeroed_used();

    cost->benefit = min(action->prezero_n, recent_used) * zeroing_per_page_cost;
}

bool mm_econ_is_on(void)
{
    return mm_econ_mode > 0;
}
EXPORT_SYMBOL(mm_econ_is_on);

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
            cost->cost = 0;
            cost->benefit = 0;
            break;

        case MM_ACTION_PROMOTE_HUGE:
            mm_estimate_huge_page_promote_cost_benefit(action, cost);
            break;

        case MM_ACTION_DEMOTE_HUGE:
            // TODO(markm)
            cost->cost = 0;
            cost->benefit = 0;
            break;

        case MM_ACTION_RUN_DEFRAG:
            mm_estimate_daemon_cost(action, cost);
            cost->benefit = 0; // TODO(markm)
            if (cost->cost < cost->benefit)
                mm_econ_num_async_compaction += 1;
            break;

        case MM_ACTION_RUN_PROMOTION:
            mm_estimate_daemon_cost(action, cost);
            // TODO(markm)
            cost->benefit = 0;
            break;

        case MM_ACTION_RUN_PREZEROING:
            mm_estimate_daemon_cost(action, cost);
            mm_estimate_async_prezeroing_benefit(action, cost);
            if (cost->cost < cost->benefit)
                mm_econ_num_async_prezeroing += 1;
            break;

        case MM_ACTION_ALLOC_RECLAIM: // Alloc reclaim for thp allocation.
            // Estimate the cost/benefit of the promotion itself.
            mm_estimate_huge_page_promote_cost_benefit(action, cost);
            // Update the cost if we also need to do reclaim.
            mm_estimate_huge_page_reclaim_cost(action, cost);
            break;

        case MM_ACTION_EAGER_PAGING:
            // TODO(markm)
            cost->cost = 0;
            cost->benefit = 0;
            break;

        default:
            printk(KERN_WARNING "Unknown mm_action %d\n", action->action);
            break;
    }

    // Record some stats for debugging.
    mm_econ_num_estimates += 1;
    mm_stats_hist_measure(&mm_econ_cost, cost->cost);
    mm_stats_hist_measure(&mm_econ_benefit, cost->benefit);
}
EXPORT_SYMBOL(mm_estimate_changes);

// Decide whether to take an action with the given cost. Returns true if the
// action associated with `cost` should be TAKEN, and false otherwise.
bool mm_decide(const struct mm_cost_delta *cost)
{
    bool should_do;
    mm_econ_num_decisions += 1;

    if (mm_econ_mode == 0) {
        return true;
    } else if (mm_econ_mode == 1) {
        should_do = cost->benefit > cost->cost;

        if (should_do)
            mm_econ_num_decisions_yes += 1;

        //pr_warn("mm_econ: cost=%llu benefit=%llu\n", cost->cost, cost->benefit); // TODO remove
        return should_do;
    } else {
        BUG();
        return false;
    }
}
EXPORT_SYMBOL(mm_decide);

// Inform the estimator of the promotion of the given huge page.
void mm_register_promotion(u64 addr)
{
    mm_econ_num_hp_promotions += 1;
}

static bool mm_does_quantity_match(struct mmap_comparison *c, u64 val)
{
    if (c->comp == CompEquals) {
        return val == c->val;
    } else if (c->comp == CompGreaterThan) {
        return val > c->val;
    } else if (c->comp == CompLessThan) {
        return val < c->val;
    } else {
        pr_err("Invalid mmap comparatori\n");
        BUG();
    }

    // Should never reach here
    return false;
}

// Split base_range, which is in subranges, at addr based on comp and add
// the new range(s) to subranges.
static bool mm_split_ranges(struct profile_range *base_range, struct rb_root *subranges,
        u64 addr, enum mmap_comparator comp)
{
    struct profile_range *split_range;

    if (comp == CompGreaterThan) {
        if (base_range->start >= addr) {
            return true;
        }

        split_range = vmalloc(sizeof(struct profile_range));
        if (!split_range)
            return false;

        split_range->misses = 0;
        split_range->start = base_range->start;
        split_range->end = addr;
        base_range->start = addr;

        profile_range_insert(subranges, split_range);
    } else if (comp == CompLessThan) {
        if (base_range->end <= addr) {
            return true;
        }

        split_range = vmalloc(sizeof(struct profile_range));
        if (!split_range)
            return false;

        split_range->misses = 0;
        split_range->start = addr;
        split_range->end = base_range->end;
        base_range->end = addr;

        profile_range_insert(subranges, split_range);
    } else if (comp == CompEquals) {
        // Do we need to split on the left?
        if (base_range->start < addr) {
            split_range = vmalloc(sizeof(struct profile_range));
            if (!split_range)
                return false;

            split_range->misses = 0;
            split_range->start = base_range->start;
            split_range->end = addr;
            base_range->start = addr;

            profile_range_insert(subranges, split_range);
        }
        // Do we need to split on the right?
        if (base_range->end > addr + PAGE_SIZE) {
            split_range = vmalloc(sizeof(struct profile_range));
            if (!split_range)
                return false;

            split_range->misses = 0;
            split_range->start = addr + PAGE_SIZE;
            split_range->end = base_range->end;
            base_range->end = addr + PAGE_SIZE;

            profile_range_insert(subranges, split_range);
        }
    }

    return true;
}

// Search mmap_filters for a filter that matches this new memory map
// and add it to the list of ranges.
// pid: The pid of the process who made this mmap
// section: The memory section the memory range belongs to: code, data, heap, or mmap
// mapaddr: The actual address the new mmap is mapped to
// section_off: The offset of the memory range from the start of the section it belongs to
// addr: The hint from the caller for what address the new mmap should be mapped to
// len: The length of the new mmap
// prot: The protection bits for the mmap
// flags: The flags specified in the mmap call
// fd: Descriptor of the file to map
// off: Offset within the file to start the mapping
// Do we need to lock mmap_filters?
// We might need to lock the profile_ranges rb_tree
void mm_add_memory_range(pid_t pid, enum mm_memory_section section, u64 mapaddr, u64 section_off,
        u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    struct mmap_filter_proc *proc;
    struct mmap_filter *filter;
    struct mmap_comparison *comp;
    struct profile_range *range = NULL;
    struct list_head *filter_head = NULL;
    // Used to keep track of the subranges of the new memory range that are
    // from splitting a range due to a section_off constraint.
    struct rb_root subranges = RB_ROOT;
    struct rb_node *range_node = NULL;
    bool passes_filter;
    u64 val;

    // If this isn't the process we care about, move on
    list_for_each_entry(proc, &filter_procs, node) {
        if (proc->pid == pid) {
            filter_head = &proc->filters;
            break;
        }
    }
    if (!filter_head)
        return;

    // Start with the original range of the new mapping
    range = vmalloc(sizeof(struct profile_range));
    if (!range) {
        pr_warn("mm_add_mmap: no memory for new range");
        return;
    }
    // Align the range bounds to a page
    range->start = mapaddr & PAGE_MASK;
    range->end = (mapaddr + len + PAGE_SIZE - 1) & PAGE_MASK;
    range->misses = 0;
    profile_range_insert(&subranges, range);

    // Check if this mmap matches any of our filters
    list_for_each_entry(filter, filter_head, node) {
        // We need a second rb_tree because we don't want to change the
        // subranges tree unless we are sure a filter matches
        struct rb_root temp_subranges = RB_ROOT;
        // The range in the subranges tree that we are splitting
        struct profile_range *parent_range = NULL;

        passes_filter = section == filter->section;

        list_for_each_entry(comp, &filter->comparisons, node) {
            if (!passes_filter)
                break;

            // Determine the value to use for this comparison
            if (comp->quant == QuantSectionOff) {
                // This type of filter comparison is the most complex because
                // it may cause the region to be split one or more times.
                // This happens when the new region overlaps with multiple filters.
                // To handle this case, while we check if the region matches the
                // filter, we also keep track of how we would need to split the
                // regions using temp_subregions. These subregions then replace
                // the larger region if the filter passes the region.

                enum mmap_comparator comparator;
                u64 section_base;
                u64 search_key;
                // Because ranges can be split, we need to handle this more
                // carefully.

                // Find the range to do the comparison on
                // This step basically involves converting the section offset
                // given in the filter to a virtual address corresponding to
                // that offset. We need to do this because the memory ranges
                // we are operating on are virtual addresses.
                // We need to account for the mmap section growing down
                if (section == SectionMmap) {
                    section_base = mapaddr + section_off;
                    search_key = section_base - comp->val;

                    if (comp->comp == CompGreaterThan)
                        comparator = CompLessThan;
                    else if (comp->comp == CompLessThan)
                        comparator = CompGreaterThan;
                    else
                        comparator = comp->comp;
                } else {
                    section_base = mapaddr - section_off;
                    search_key = section_base + comp->val;
                    comparator = comp->comp;
                }

                if (!parent_range) {
                    // Find the range to potentially split, and add it to
                    // temp_subranges
                    parent_range = profile_find_first_range(&subranges, search_key, comparator);
                    if (!parent_range) {
                        passes_filter = false;
                        break;
                    }

                    // If the found range has already matched with a filter, we
                    // are done
                    if (parent_range->misses != 0) {
                        passes_filter = false;
                        break;
                    }

                    range = vmalloc(sizeof(struct profile_range));
                    if (!range) {
                        pr_warn("mm_add_mmap: no memory for new range");
                        profile_free_all(&subranges);
                        profile_free_all(&temp_subranges);
                        return;
                    }
                    range->start = parent_range->start;
                    range->end = parent_range->end;
                    range->misses = parent_range->misses;

                    profile_range_insert(&temp_subranges, range);
                } else {
                    // Find the range from the temp_subranges
                    range = profile_find_first_range(&temp_subranges, search_key, comparator);
                    if (!range) {
                        passes_filter = false;
                        break;
                    }
                }

                // Assign the misses value.
                range->misses = filter->misses;

                // Split the range if necessary
                if (!mm_split_ranges(range, &temp_subranges, search_key, comparator)) {
                    pr_warn("mm_add_mmap: no memory for new range");
                    profile_free_all(&subranges);
                    profile_free_all(&temp_subranges);
                    return;
                }

                continue;
            }
            else if (comp->quant == QuantAddr)
                val = addr;
            else if (comp->quant == QuantLen)
                val = len;
            else if (comp->quant == QuantProt)
                val = prot;
            else if (comp->quant == QuantFlags)
                val = flags;
            else if (comp->quant == QuantFD)
                val = fd;
            else
                val = off;

            passes_filter = passes_filter && mm_does_quantity_match(comp, val);
        }

        // If we split a range for this filter, remove the old range
        // from the subranges tree, and add the new ones
        if (passes_filter && parent_range) {
            range_node = &parent_range->node;
            rb_erase(range_node, &subranges);
            vfree(parent_range);

            profile_move(&temp_subranges, &subranges);
        }
        // If the entire new range matches this filter, set the misses
        // value for all of the subranges that have not been set yet
        else if(passes_filter) {
            range_node = rb_first(&subranges);

            while (range_node) {
                range = container_of(range_node, struct profile_range, node);

                if (range->misses == 0)
                    range->misses = filter->misses;

                range_node = rb_next(range_node);
            }

            // Because the entire new range matched a filter, we no longer
            // have to check the rest of the filters
            break;
        }
    }

    // Finally, insert all of the new ranges into the proc's tree
    profile_move(&subranges, &proc->ranges_root);

    //printk("Added range %d %llx %llx %lld %llx\n", section, range->start, range->end, range->misses, len);
}

void mm_profile_check_exiting_proc(pid_t pid)
{
    struct mmap_filter_proc *proc;
    list_for_each_entry(proc, &filter_procs, node) {
        if (proc->pid == pid) {
            // If the process exits, we should also clear its profile
            profile_free_all(&proc->ranges_root);
            mmap_filters_free_all(proc);

            // Remove the node from the list
            list_del(&proc->node);
            vfree(proc);
            break;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// sysfs files

static ssize_t enabled_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", mm_econ_mode);
}

static ssize_t enabled_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    int mode;
    int ret;

    ret = kstrtoint(buf, 0, &mode);

    if (ret != 0) {
        mm_econ_mode = 0;
        return ret;
    }
    else if (mode >= 0 && mode <= 1) {
        mm_econ_mode = mode;
        return count;
    }
    else {
        mm_econ_mode = 0;
        return -EINVAL;
    }
}
static struct kobj_attribute enabled_attr =
__ATTR(enabled, 0644, enabled_show, enabled_store);

static ssize_t stats_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf,
            "estimated=%lld\ndecided=%lld\n"
            "yes=%lld\npromoted=%lld\n"
            "compactions=%lld\nprezerotry=%lld\n",
            mm_econ_num_estimates,
            mm_econ_num_decisions,
            mm_econ_num_decisions_yes,
            mm_econ_num_hp_promotions,
            mm_econ_num_async_compaction,
            mm_econ_num_async_prezeroing);
}

static ssize_t stats_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    return -EINVAL;
}
static struct kobj_attribute stats_attr =
__ATTR(stats, 0444, stats_show, stats_store);

static struct attribute *mm_econ_attr[] = {
    &enabled_attr.attr,
    &stats_attr.attr,
    NULL,
};

static const struct attribute_group mm_econ_attr_group = {
    .attrs = mm_econ_attr,
};

///////////////////////////////////////////////////////////////////////////////
// procfs files

static void mm_memory_section_get_str(char *buf, enum mm_memory_section section)
{
    if (section == SectionCode) {
        strcpy(buf, "code");
    } else if (section == SectionData) {
        strcpy(buf, "data");
    } else if (section == SectionHeap) {
        strcpy(buf, "heap");
    } else if (section == SectionMmap) {
        strcpy(buf, "mmap");
    } else {
        printk(KERN_WARNING "Invalid memory section");
        BUG();
    }
}

static char mmap_comparator_get_char(enum mmap_comparator comp)
{
    if (comp == CompEquals) {
        return '=';
    } else if (comp == CompGreaterThan) {
        return '>';
    } else if (comp == CompLessThan) {
        return '<';
    } else {
        printk(KERN_WARNING "Invalid mmap comparator");
        BUG();
    }
}

static void mmap_quantity_get_str(char *buf, enum mmap_quantity quant)
{
    if (quant == QuantSectionOff) {
        strcpy(buf, "section_off");
    } else if (quant == QuantAddr) {
        strcpy(buf, "addr");
    } else if (quant == QuantLen) {
        strcpy(buf, "len");
    } else if (quant == QuantProt) {
        strcpy(buf, "prot");
    } else if (quant == QuantFlags) {
        strcpy(buf, "flags");
    } else if (quant == QuantFD) {
        strcpy(buf, "fd");
    } else if (quant == QuantOff) {
        strcpy(buf, "off");
    } else {
        pr_warn("Invalid mmap quantity");
        BUG();
    }
}

static ssize_t mmap_filters_read(struct file *file,
        char __user *buf, size_t count, loff_t *ppos)
{
    struct task_struct *task = extern_get_proc_task(file_inode(file));
    char *buffer;
    ssize_t len = 0;
    ssize_t ret = 0;
    struct mmap_filter *filter;
    struct mmap_comparison *comparison;
    struct mmap_filter_proc *proc;
    struct list_head *filter_head = NULL;

    if (!task)
        return -ESRCH;

    buffer = vmalloc(sizeof(char) * MMAP_FILTER_BUF_SIZE);
    if (!buffer) {
        put_task_struct(task);
        return -ENOMEM;
    }

    // First, print the CSV Header for easier reading
    len = sprintf(buffer, "SECTION,MISSES,CONSTRAINTS...\n");

    // Find the filters that correspond to this process if there are any
    list_for_each_entry(proc, &filter_procs, node) {
        if (proc->pid == task->tgid) {
            filter_head = &proc->filters;
            break;
        }
    }
    if (!filter_head)
        goto out;

    // Print out all of the filters
    list_for_each_entry(filter, filter_head, node) {
        char section[8];
        char quantity[16];
        u64 misses = filter->misses;
        char comparator;
        u64 val;

        mm_memory_section_get_str(section, filter->section);

        // Make sure we don't overflow the buffer
        if (len > MMAP_FILTER_BUF_SIZE - MMAP_FILTER_BUF_DEAD_ZONE)
            goto out;

        // Print the per filter information
        len += sprintf(&buffer[len], "%s,0x%llx", section, misses);

        list_for_each_entry(comparison, &filter->comparisons, node) {
            mmap_quantity_get_str(quantity, comparison->quant);
            comparator = mmap_comparator_get_char(comparison->comp);
            val = comparison->val;

            // Make sure we don't overflow the buffer
            if (len > MMAP_FILTER_BUF_SIZE - MMAP_FILTER_BUF_DEAD_ZONE)
                goto out;

            // Print the per comparison information
            len += sprintf(&buffer[len], ",%s,%c,0x%llx", quantity,
                comparator, val);
        }

        // Remember to end with a newline
        len += sprintf(&buffer[len], "\n");
    }

out:
    ret = simple_read_from_buffer(buf, count, ppos, buffer, len);

    // Remember to free the buffer
    vfree(buffer);

    put_task_struct(task);

    return ret;
}

static int get_memory_section(char *buf, enum mm_memory_section *section)
{
    int ret = 0;

    if (strcmp(buf, "code") == 0) {
        *section = SectionCode;
    } else if (strcmp(buf, "data") == 0) {
        *section = SectionData;
    } else if (strcmp(buf, "heap") == 0) {
        *section = SectionHeap;
    } else if (strcmp(buf, "mmap") == 0) {
        *section = SectionMmap;
    } else {
        ret = -1;
    }

    return ret;
}

static int get_mmap_quantity(char *buf, enum mmap_quantity *quant)
{
    int ret = 0;

    if (strcmp(buf, "section_off") == 0) {
        *quant = QuantSectionOff;
    } else if (strcmp(buf, "addr") == 0) {
        *quant = QuantAddr;
    } else if (strcmp(buf, "len") == 0) {
        *quant = QuantLen;
    } else if (strcmp(buf, "prot") == 0) {
        *quant = QuantProt;
    } else if (strcmp(buf, "flags") == 0) {
        *quant = QuantFlags;
    } else if (strcmp(buf, "fd") == 0) {
        *quant = QuantFD;
    } else if (strcmp(buf, "off") == 0) {
        *quant = QuantOff;
    } else {
        ret = -1;
    }

    return ret;
}

static int get_mmap_comparator(char *buf, enum mmap_comparator *comp)
{
    int ret = 0;

    if (strcmp(buf, "=") == 0) {
        *comp = CompEquals;
    } else if (strcmp(buf, ">") == 0) {
        *comp = CompGreaterThan;
    } else if (strcmp(buf, "<") == 0) {
        *comp = CompLessThan;
    } else {
        ret = -1;
    }

    return ret;
}

static int mmap_filter_read_comparison(char **tok, struct mmap_comparison *c)
{
    int ret = 0;
    u64 value = 0;
    char *value_buf;

    // Get the quantity
    value_buf = strsep(tok, ",");
    if (!value_buf) {
        return -1;
    }

    ret = get_mmap_quantity(value_buf, &c->quant);
    if (ret != 0) {
        return -1;
    }

    // Get the comparator
    value_buf = strsep(tok, ",");
    if (!value_buf) {
        return -1;
    }

    ret = get_mmap_comparator(value_buf, &c->comp);
    if (ret != 0) {
        return -1;
    }

    // Get the value
    value_buf = strsep(tok, ",");
    if (!value_buf) {
        return -1;
    }

    ret = kstrtoull(value_buf, 0, &value);
    if (ret != 0) {
        return -1;
    }

    c->val = value;

    return 0;
}

static ssize_t mmap_filters_write(struct file *file,
        const char __user *buf, size_t count,
        loff_t *ppos)
{
    struct task_struct *task = NULL;
    char *buf_from_user = NULL;
    char *outerTok = NULL;
    char *tok = NULL;
    struct mmap_filter *filter = NULL;
    struct mmap_comparison *comparison = NULL;
    struct mmap_filter_proc *proc = NULL;
    bool alloc_new_proc = true;
    ssize_t error = 0;
    int ret;
    u64 value;
    char * value_buf;

    // Copy the input from userspace
    buf_from_user = vmalloc(sizeof(char) * (count + 1));
    if (!buf_from_user)
        return -ENOMEM;
    if (copy_from_user(buf_from_user, buf, count)) {
        error = -EFAULT;
        goto err;
    }
    buf_from_user[count] = 0;
    outerTok = buf_from_user;

    task = extern_get_proc_task(file_inode(file));
    if (!task) {
        error = -ESRCH;
        goto err;
    }

    // See if a an entry already exists for this process
    list_for_each_entry(proc, &filter_procs, node) {
        if (proc->pid == task->tgid) {
            alloc_new_proc = false;
            // Free the existing profile
            profile_free_all(&proc->ranges_root);
            mmap_filters_free_all(proc);
            break;
        }
    }

    // Allocate the proc structure if necessary
    if (alloc_new_proc) {
        proc = vmalloc(sizeof(struct mmap_filter_proc));
        if (!proc) {
            error = -ENOMEM;
            goto err;
        }

        // Initialize the new proc
        proc->pid = task->tgid;
        INIT_LIST_HEAD(&proc->filters);
        proc->ranges_root = RB_ROOT;
    }

    // Read in the filters
    tok = strsep(&outerTok, "\n");
    while (outerTok) {
        if (tok[0] == '\0') {
            break;
        }

        filter = vmalloc(sizeof(struct mmap_filter));
        if (!filter) {
            error = -ENOMEM;
            goto err;
        }

        // Get the section of the memory map
        value_buf = strsep(&tok, ",");
        if (!value_buf) {
            error = -EINVAL;
            goto err;
        }
        ret = get_memory_section(value_buf, &filter->section);

        // Get the misses for the filter
        value_buf = strsep(&tok, ",");
        if (!value_buf) {
            error = -EINVAL;
            goto err;
        }

        ret = kstrtoull(value_buf, 0, &value);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        filter->misses = value;

        // Read in the comparisons of the filter
        INIT_LIST_HEAD(&filter->comparisons);
        while (tok) {
            if (tok[0] == '\0')
                break;

            comparison = vmalloc(sizeof(struct mmap_comparison));
            if (!comparison) {
                error = -ENOMEM;
                vfree (comparison);
                goto err;
            }

            ret = mmap_filter_read_comparison(&tok, comparison);
            if (ret != 0) {
                error = -EINVAL;
                vfree (comparison);
                goto err;
            }

            // Add the comparison to the list of comparisons
            list_add_tail(&comparison->node, &filter->comparisons);
        }

        // Add the new filter to the list
        list_add_tail(&filter->node, &proc->filters);

        // Get the next filter
        tok = strsep(&outerTok, "\n");
    }

    // Link the new proc if we need to
    if (alloc_new_proc) {
        list_add_tail(&proc->node, &filter_procs);
    }

    vfree(buf_from_user);
    put_task_struct(task);

    return count;

err:
    if (filter)
        vfree (filter);
    if (proc) {
        mmap_filters_free_all(proc);
        if (alloc_new_proc)
            vfree(proc);
    }
    if (task)
        put_task_struct(task);
    if (buf_from_user)
        vfree(buf_from_user);
    return error;
}

const struct file_operations proc_mmap_filters_operations = {
    .read = mmap_filters_read,
    .write = mmap_filters_write,
    .llseek = default_llseek,
};

static ssize_t print_profile(struct file *file,
        char __user *buf, size_t count, loff_t *ppos)
{
    struct task_struct *task = extern_get_proc_task(file_inode(file));
    char *buffer;
    ssize_t len = 0;
    ssize_t ret = 0;
    struct mmap_filter_proc *proc;
    struct rb_node *node = NULL;

    if (!task)
        return -ESRCH;

    // Find the data for the process this relates to
    list_for_each_entry(proc, &filter_procs, node) {
        if (proc->pid == task->tgid) {
            node = rb_first(&proc->ranges_root);
            break;
        }
    }
    if (!node) {
        put_task_struct(task);
        return 0;
    }

    buffer = vmalloc(sizeof(char) * MMAP_FILTER_BUF_SIZE);
    if (!buffer) {
        put_task_struct(task);
        return -ENOMEM;
    }

    while (node) {
        struct profile_range *range =
            container_of(node, struct profile_range, node);

        // Make sure we don't overflow the buffer
        if (len > MMAP_FILTER_BUF_SIZE - MMAP_FILTER_BUF_DEAD_ZONE)
            goto out;

        len += sprintf(
            &buffer[len],
            "[0x%llx, 0x%llx) (%llu bytes) misses=0x%llx\n",
            range->start,
            range->end,
            range->end - range->start,
            range->misses
        );

        node = rb_next(node);
    }

out:
    ret = simple_read_from_buffer(buf, count, ppos, buffer, len);

    vfree(buffer);

    put_task_struct(task);

    return ret;
}

const struct file_operations proc_mem_ranges_operations = {
    .read = print_profile,
    .llseek = default_llseek,
};
///////////////////////////////////////////////////////////////////////////////
// Init

static int __init mm_econ_init(void)
{
    struct kobject *mm_econ_kobj;
    int err;

    mm_econ_kobj = kobject_create_and_add("mm_econ", mm_kobj);
    if (unlikely(!mm_econ_kobj)) {
        pr_err("failed to create mm_econ kobject\n");
        return -ENOMEM;
    }

    err = sysfs_create_group(mm_econ_kobj, &mm_econ_attr_group);
    if (err) {
        pr_err("failed to register mm_econ group\n");
        kobject_put(mm_econ_kobj);
        return err;
    }

    return 0;
}
subsys_initcall(mm_econ_init);
