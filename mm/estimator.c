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

#define HUGE_PAGE_ORDER 9

///////////////////////////////////////////////////////////////////////////////
// Globals...

// Modes:
// - 0: off (just use default linux behavior)
// - 1: on (cost-benefit estimation)
static int mm_econ_mode = 0;

static int mm_econ_mmap_filters = 0;

// The comm of the process to track
static char process_comm[TASK_COMM_LEN];
// The pid of the process to track. Only used with mmap_filters
static pid_t process_pid = 0;

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
    CompLessThan,
    CompIgnore
};

// A quantity for filtering an mmap with and how to compare the quantity
struct mmap_quantity {
    u64 val;
    enum mmap_comparator comp;
};

// A list of quantities of a mmap to use for deciding if that mmap would
// benefit from being huge.
struct mmap_filter {
    struct list_head node;
    enum mm_memory_section section;
    struct mmap_quantity section_off;
    struct mmap_quantity addr;
    struct mmap_quantity len;
    struct mmap_quantity prot;
    struct mmap_quantity flags;
    struct mmap_quantity fd;
    struct mmap_quantity off;
    u64 misses;
};

// Invariant: none of the ranges overlap!
static struct rb_root preloaded_profile = RB_ROOT;

// List of mmap filters
static LIST_HEAD(mmap_filters);

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
profile_search(u64 addr)
{
    struct rb_node *node = preloaded_profile.rb_node;

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

static inline bool
ranges_overlap(struct profile_range *r1, struct profile_range *r2)
{
    return (((r1->start <= r2->start && r2->start < r1->end)
        || (r2->start <= r1->start && r1->start < r2->end)));
}

/*
 * Remove all ranges overlapping with the new range
 */
static void remove_overlapping_ranges(struct profile_range *new_range)
{
    struct rb_node *node = preloaded_profile.rb_node;
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
        rb_erase(node, &preloaded_profile);
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
profile_range_insert(struct profile_range *new_range)
{
    struct rb_node **new = &(preloaded_profile.rb_node), *parent = NULL;

    remove_overlapping_ranges(new_range);

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
    rb_insert_color(&new_range->node, &preloaded_profile);
}

static void
profile_free_all(void)
{
    struct rb_node *node = preloaded_profile.rb_node;

    while(node) {
        struct profile_range *range =
            container_of(node, struct profile_range, node);

        rb_erase(node, &preloaded_profile);
        node = preloaded_profile.rb_node;

        vfree(range);
    }
}

static void
print_profile(void)
{
    struct rb_node *node = rb_first(&preloaded_profile);

    // We may not be able to write everything to the buffer. So we print
    // everything to printk instead.

    pr_warn("mm_econ: profile...");

    while (node) {
        struct profile_range *range =
            container_of(node, struct profile_range, node);
        pr_warn("mm_econ: [%llu, %llu) (%llu bytes) misses=%llu\n",
                range->start, range->end,
                (range->end - range->start),
                range->misses);

        node = rb_next(node);
    }

    pr_warn("mm_econ: END profile...");
}

static void mmap_filters_free_all(void)
{
    struct mmap_filter *filter;
    struct list_head *pos, *n;

    list_for_each_safe(pos, n, &mmap_filters) {
        filter = list_entry(pos, struct mmap_filter, node);
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
    struct profile_range *range = profile_search(action->address);

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

bool mm_econ_is_on(void)
{
    return mm_econ_mode > 0;
}

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
            // TODO(markm)
            cost->cost = 0;
            cost->benefit = 0;
            break;

        case MM_ACTION_ALLOC_RECLAIM: // Alloc reclaim for thp allocation.
            // Estimate the cost/benefit of the promotion itself.
            mm_estimate_huge_page_promote_cost_benefit(action, cost);
            // Update the cost if we also need to do reclaim.
            mm_estimate_huge_page_reclaim_cost(action, cost);
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

// Decide whether to take an action with the given cost. Returns true if the
// action associated with `cost` should be TAKEN, and false otherwise.
bool mm_decide(const struct mm_cost_delta *cost)
{
    // Only track a new process if we aren't currently tracking one
    if (mm_econ_mmap_filters && process_pid != current->tgid) {
        return false;
    }

    mm_econ_num_decisions += 1;

    if (mm_econ_mode == 0) {
        return true;
    } else if (mm_econ_mode == 1) {
        mm_econ_num_decisions_yes += 1;

        //pr_warn("mm_econ: cost=%llu benefit=%llu\n", cost->cost, cost->benefit); // TODO remove
        return cost->benefit > cost->cost;
    } else {
        BUG();
        return false;
    }
}

// Inform the estimator of the promotion of the given huge page.
void mm_register_promotion(u64 addr)
{
    mm_econ_num_hp_promotions += 1;
}

static bool mm_does_quantity_match(struct mmap_quantity *q, u64 val)
{
    if (q->comp == CompEquals) {
        return val == q->val;
    } else if (q->comp == CompGreaterThan) {
        return val > q->val;
    } else if (q->comp == CompLessThan) {
        return val < q->val;
    } else if (q->comp == CompIgnore) {
        return true;
    } else {
        pr_err("Invalid mmap comparatori\n");
        BUG();
    }

    // Should never reach here
    return false;
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
    struct mmap_filter *filter;
    struct profile_range *range = NULL;
    bool passes_filter;
    // Have misses default to zero if no filters match
    u64 misses = 0;

    if (!mm_econ_mmap_filters)
        return;

    // If this isn't the process we care about, move on
    if (process_pid != pid) {
        return;
    }

    // Check if this mmap matches any of our filters
    list_for_each_entry(filter, &mmap_filters, node) {
        passes_filter = section == filter->section;
        passes_filter = passes_filter && mm_does_quantity_match(&filter->section_off, section_off);
        passes_filter = passes_filter && mm_does_quantity_match(&filter->addr, addr);
        passes_filter = passes_filter && mm_does_quantity_match(&filter->len, len);
        passes_filter = passes_filter && mm_does_quantity_match(&filter->prot, prot);
        passes_filter = passes_filter && mm_does_quantity_match(&filter->flags, flags);
        passes_filter = passes_filter && mm_does_quantity_match(&filter->fd, fd);
        passes_filter = passes_filter && mm_does_quantity_match(&filter->off, off);

        if (passes_filter) {
            misses = filter->misses;
            break;
        }
    }

    // Add the memory range of the mmap to the tree of ranges
    range = vmalloc(sizeof(struct profile_range));
    if (!range) {
        pr_warn("mm_add_mmap: no memory for new range");
        return;
    }
    // Align the range bounds to a page
    range->start = mapaddr & PAGE_MASK;
    range->end = (mapaddr + len + PAGE_SIZE - 1) & PAGE_MASK;
    range->misses = misses;

    profile_range_insert(range);
    //printk("Added range %d %llx %llx %lld %llx\n", section, range->start, range->end, range->misses, len);
}

void mm_profile_register_process(char *comm, pid_t pid)
{
    // Only track a new process if we aren't currently tracking one
    if (process_pid != 0) {
        return;
    }

    // If the comm matches what we're looking for, track this process
    if (strcmp(process_comm, comm) == 0) {
        process_pid = pid;
    }
}

void mm_profile_check_exiting_proc(pid_t pid)
{
    if (process_pid == pid) {
        process_pid = 0;

        // If the process exits, we should also clear its profile
        profile_free_all();
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
            "yes=%lld\npromoted=%lld\n",
            mm_econ_num_estimates,
            mm_econ_num_decisions,
            mm_econ_num_decisions_yes,
            mm_econ_num_hp_promotions);
}

static ssize_t stats_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    return -EINVAL;
}
static struct kobj_attribute stats_attr =
__ATTR(stats, 0444, stats_show, stats_store);

static ssize_t preloaded_profile_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    ssize_t count = sprintf(buf, "\n");
    print_profile();
    return count;
}

/*
 * Removes any existing profile and replaces it with the given one. The
 * expected format for the profile is:
 *      start end misses; start end misses; ...
 *
 * If there is an error, the current profile is still removed, and it is left
 * cleared.
 */
static ssize_t preloaded_profile_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    char *tok = (char *)buf;
    struct profile_range *range = NULL;
    ssize_t error;
    int ret;
    u64 value;
    char *value_buf;

    // First, free the existing profile.
    profile_free_all();
    mmap_filters_free_all();

    // Try to read in all of the ranges
    while (tok) {
        range = vmalloc(sizeof(struct profile_range));
        if (!range) {
            error = -ENOMEM;
            goto err;
        }

        // Get the beginning of the range.
        value_buf = strsep(&tok, " ");
        if (!value_buf) {
            error = -EINVAL;
            goto err;
        }

        ret = kstrtoull(value_buf, 0, &value);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        range->start = value;

        // Get the end of the range.
        value_buf = strsep(&tok, " ");
        if (!value_buf) {
            error = -EINVAL;
            goto err;
        }

        ret = kstrtoull(value_buf, 0, &value);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        range->end = value;

        // Get the TLB miss count.
        value_buf = strsep(&tok, ";");
        if (!value_buf) {
            error = -EINVAL;
            goto err;
        }

        ret = kstrtoull(value_buf, 0, &value);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        range->misses = value;

        profile_range_insert(range);
    }

    pr_warn("mm_econ: profile set.");
    print_profile();

    return count;

err:
    if (range)
        vfree(range);
    profile_free_all();
    return error;
}
static struct kobj_attribute preloaded_profile_attr =
__ATTR(preloaded_profile, 0644, preloaded_profile_show, preloaded_profile_store);

static ssize_t mmap_filters_enabled_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", mm_econ_mmap_filters);
}

static ssize_t mmap_filters_enabled_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    int en;
    int ret;

    ret = kstrtoint(buf, 0, &en);

    if (ret != 0) {
        mm_econ_mmap_filters = 0;
        return ret;
    }
    else if (en >= 0 && en <= 1) {
        mm_econ_mmap_filters = en;
        return count;
    }
    else {
        mm_econ_mmap_filters = 0;
        return -EINVAL;
    }
}
static struct kobj_attribute mmap_filters_enabled_attr =
__ATTR(mmap_filters_enabled, 0644, mmap_filters_enabled_show,
    mmap_filters_enabled_store);

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
    } else if (comp == CompIgnore) {
        return ' ';
    } else {
        printk(KERN_WARNING "Invalid mmap comparator");
        BUG();
    }
}

static ssize_t mmap_filters_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    ssize_t count = 0;
    struct mmap_filter *filter;

    // First, print the CSV Header for easier reading
    count = sprintf(buf, "SECTION,SECTION_OFF_COMP,SECTION_OFF,ADDR_COMP,ADDR,"
                    "LEN_COMP,LEN,PROT_COMP,PROT,FLAGS_COMP,FLAGS,FD_COMP,FD,"
                    "OFF_COMP,OFF,MISSES\n");

    // Print out all of the filters
    list_for_each_entry(filter, &mmap_filters, node) {
        char section[8];
        char comp_section_off = mmap_comparator_get_char(filter->section_off.comp);
        u64 section_off = filter->section_off.val;
        char comp_addr = mmap_comparator_get_char(filter->addr.comp);
        u64 addr = filter->addr.val;
        char comp_len = mmap_comparator_get_char(filter->len.comp);
        u64 len = filter->len.val;
        char comp_prot = mmap_comparator_get_char(filter->prot.comp);
        u64 prot = filter->prot.val;
        char comp_flags = mmap_comparator_get_char(filter->flags.comp);
        u64 flags = filter->flags.val;
        char comp_fd = mmap_comparator_get_char(filter->fd.comp);
        u64 fd = filter->fd.val;
        char comp_off = mmap_comparator_get_char(filter->off.comp);
        u64 off = filter->off.val;
        u64 misses = filter->misses;

        mm_memory_section_get_str(section, filter->section);
    
        // We will keep on adding to the string, so replace the null terminator
        // with a newline
//        buf[count++] = '\n';

        count += sprintf(&buf[count],
                    "%s,%c,0x%llx,%c,0x%llx,%c,0x%llx,%c,0x%llx,%c,0x%llx,"
                    "%c,0x%llx,%c,0x%llx,0x%llx\n",
                    section, comp_section_off, section_off, comp_addr, addr,
                    comp_len, len, comp_prot, prot, comp_flags, flags,
                    comp_fd, fd, comp_off, off, misses);
    }

    return count;
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

static int get_mmap_comparator(char *buf, enum mmap_comparator *comp)
{
    int ret = 0;

    if (strcmp(buf, "=") == 0) {
        *comp = CompEquals;
    } else if (strcmp(buf, ">") == 0) {
        *comp = CompGreaterThan;
    } else if (strcmp(buf, "<") == 0) {
        *comp = CompLessThan;
    } else if (strcmp(buf, " ") == 0 || buf[0] == '\0') {
        // The above condition covers when the ignored option in the CSV
        // is written as ", ," or ",,"
        // If there was nothing before the , that means this quantity
        // should be ignored
        *comp = CompIgnore;
    } else {
        ret = -1;
    }

    return ret;
}

static int mmap_filter_read_quantity(char **tok, struct mmap_quantity *q)
{
    int ret = 0;
    u64 value = 0;
    char *value_buf;

    // Get the comparator
    value_buf = strsep(tok, ",");
    if (!value_buf) {
        return -1;
    }

    ret = get_mmap_comparator(value_buf, &q->comp);
    if (ret != 0) {
        return -1;
    }

    // Get the value
    value_buf = strsep(tok, ",");
    if (!value_buf) {
        return -1;
    }

    ret = kstrtoull(value_buf, 0, &value);
    // We're fine with the value being invalid if it's ignored
    if (ret != 0 && q->comp != CompIgnore) {
        return -1;
    }

    q->val = value;

    return 0;
}

static ssize_t mmap_filters_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    char *tok = (char *)buf;
    struct mmap_filter *filter = NULL;
    ssize_t error = 0;
    int ret;
    u64 value;
    char * value_buf;

    // Free the existing profiles
    profile_free_all();
    mmap_filters_free_all();

    // Read in the filters
    while (tok) {
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

        // Parse the information for the 7 quantities
        ret = mmap_filter_read_quantity(&tok, &filter->section_off);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        ret = mmap_filter_read_quantity(&tok, &filter->addr);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        ret = mmap_filter_read_quantity(&tok, &filter->len);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        ret = mmap_filter_read_quantity(&tok, &filter->prot);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        ret = mmap_filter_read_quantity(&tok, &filter->flags);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        ret = mmap_filter_read_quantity(&tok, &filter->fd);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        ret = mmap_filter_read_quantity(&tok, &filter->off);
        if (ret != 0) {
            error = -EINVAL;
            goto err;
        }

        // Get the misses for the filter
        value_buf = strsep(&tok, "\n");
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

        // Add the new filter to the list
        list_add(&filter->node, &mmap_filters);
    }

    return count;

err:
    if (filter)
        vfree (filter);
    mmap_filters_free_all();
    return error;
}
static struct kobj_attribute mmap_filters_attr =
__ATTR(mmap_filters, 0644, mmap_filters_show, mmap_filters_store);

static ssize_t process_comm_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", process_comm);
}

static ssize_t process_comm_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    strncpy(process_comm, buf, TASK_COMM_LEN);

    if (count < TASK_COMM_LEN) {
        return count;
    } else {
        return TASK_COMM_LEN;
    }
}
static struct kobj_attribute process_comm_attr =
__ATTR(process_comm, 0644, process_comm_show, process_comm_store);

static struct attribute *mm_econ_attr[] = {
    &enabled_attr.attr,
    &preloaded_profile_attr.attr,
    &stats_attr.attr,
    &mmap_filters_enabled_attr.attr,
    &mmap_filters_attr.attr,
    &process_comm_attr.attr,
    NULL,
};

static const struct attribute_group mm_econ_attr_group = {
    .attrs = mm_econ_attr,
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
