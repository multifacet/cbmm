/*
 * Implementation of cost-benefit based memory management.
 */

#include <linux/printk.h>
#include <linux/mm_econ.h>
#include <linux/mm.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/hashtable.h>

#define HUGE_PAGE_ORDER 9

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
    u64 misses;

    struct rb_node node;
};

// Invariant: none of the ranges overlap!
static struct rb_root preloaded_profile = RB_ROOT;

// The TLB misses estimator, if any.
static mm_econ_tlb_miss_estimator_fn_t tlb_miss_est_fn = NULL;

///////////////////////////////////////////////////////////////////////////////
// Actual implementation
//
// There are two possible estimators:
// 1. kbadgerd (via tlb_miss_est_fn).
// 2. A pre-loaded profile (via preloaded_profile).

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

/*
 * Insert the given range into the profile. If the range overlaps with an
 * existing range, this is a no-op.
 */
static void
profile_range_insert(struct profile_range *new_range)
{
    struct rb_node **new = &(preloaded_profile.rb_node), *parent = NULL;

    while (*new) {
        struct profile_range *this =
            container_of(*new, struct profile_range, node);

        /* The ranges should not overlap*/
        if (((new_range->start <= this->start && this->start < new_range->end)
                    || (this->start <= new_range->start && new_range->start < this->end)))
        {
            pr_err("mm_econ: Attempted to insert overlapping profile range!\n");
            pr_err("mm_econ: old range=[%llx, %llx) new_range=[%llx, %llx)",
                    this->start, this->end,
                    new_range->start, new_range->end);
            return;
        }

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

static bool
have_free_huge_pages(void)
{
    struct zone *zone;
    int order;

    for_each_populated_zone(zone) {
	for (order = HUGE_PAGE_ORDER; order < MAX_ORDER; ++order) {
            if (zone->free_area[order].nr_free > 0) {
                return true;
            }
        }
    }

    return false;
}

static u64
compute_hpage_benefit_from_profile(
        const struct mm_action *action)
{
    u64 ret = 0;
    struct profile_range *range = profile_search(action->address);

    // If we found a range, compute the number of misses per page and return.
    if (range) {
        ret = range->misses /
            ((range->end - range->start) >> HPAGE_SHIFT);
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
    const u64 alloc_cost = have_free_huge_pages() ? 0 : (1ul << 32);

    // TODO: Assume constant prep costs (zeroing or copying).
    const u64 prep_cost = 60 * 2000; // ~60us

    // Compute total cost.
    cost->cost = alloc_cost + prep_cost;

    // Estimate benefit.
    cost->benefit = compute_hpage_benefit(action);
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
            return;

        case MM_ACTION_PROMOTE_HUGE:
            mm_estimate_huge_page_promote_cost_benefit(action, cost);
            return;

        case MM_ACTION_DEMOTE_HUGE:
            // TODO(markm)
            cost->cost = 0;
            cost->benefit = 0;
            return;

        case MM_ACTION_RUN_DEFRAG:
            // TODO(markm)
            cost->cost = 0;
            cost->benefit = 0;
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
    if (mm_econ_mode == 0) {
        return true;
    } else if (mm_econ_mode == 1) {
        return cost->benefit > cost->cost;
    } else {
        BUG();
        return false;
    }
}

// Inform the estimator of the promotion of the given huge page.
void mm_register_promotion(u64 addr)
{
    // TODO: not sure if we need this, but the hooks are in place elsewhere...
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

static ssize_t preloaded_profile_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    ssize_t count = sprintf(buf, "\n");
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

    return count;

err:
    if (range)
        vfree(range);
    profile_free_all();
    return error;
}
static struct kobj_attribute preloaded_profile_attr =
__ATTR(preloaded_profile, 0644, preloaded_profile_show, preloaded_profile_store);

static struct attribute *mm_econ_attr[] = {
    &enabled_attr.attr,
    &preloaded_profile_attr.attr,
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
