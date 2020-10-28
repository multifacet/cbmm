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
// sysfs files

// Modes:
// - 0: off (just use default linux behavior)
// - 1: on (cost-benefit estimation)
static int mm_econ_mode = 0;

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

static struct attribute *mm_econ_attr[] = {
    &enabled_attr.attr,
    NULL,
};

static const struct attribute_group mm_econ_attr_group = {
    .attrs = mm_econ_attr,
};

///////////////////////////////////////////////////////////////////////////////
// Actual implementation

struct h_node {
    u64 addr;
    u64 benefit;
    struct hlist_node node;
};

// Create a hash map for the profile.
#define PROFILE_BITS 13
DEFINE_HASHTABLE(mm_econ_profile, PROFILE_BITS);

// We need to know how many bits are masked off the end of the address.
static u64 mm_econ_profile_region_bits = 0;

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
compute_hpage_benefit(const struct mm_action *action)
{
    struct h_node *cur;
    u64 masked_addr = action->address
        & ~GENMASK_ULL(mm_econ_profile_region_bits, 0);

    hash_for_each_possible(mm_econ_profile, cur, node, masked_addr) {
        pr_warn("Found hpage in profile: "
                "address=%llx region=%llx benefit=%lld\n",
                action->address, masked_addr, cur->benefit);
        return cur->benefit;
    }

    return 0;
}

static void
init_hard_wired_profile(void)
{
    mm_econ_profile_region_bits = 0; // TODO
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

    hash_init(mm_econ_profile);
    init_hard_wired_profile();

    return 0;
}
subsys_initcall(mm_econ_init);
