/*
 * Implementation of kbadgerd kthread.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/badger_trap.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sort.h>
#include <linux/rbtree.h>

#define KBADGERD_SLEEP_MS 500
#define KBADGERD_NEW_VMA_CHECK_RATE 4
#define RANGE_SIZE_THRESHOLD HPAGE_PMD_SIZE

// The minimum number of tlb misses for us to consider looking into a range.
// TODO: this probably should be in units of misses per page or something like
// that -- that is, for larger regions, it probably makes sense to require more
// misses. Also, it should depend on the cost of a TLB miss: the cost of the
// TLB misses should exceed the CPU cost of the sampling.
#define RANGE_IRRELEVANCE_THRESHOLD 0

struct kbadgerd_range {
	struct rb_node data_node;
	struct rb_node range_node;

	u64 start;
	u64 end; // exclusive

	// Has the range ever been explored?
	bool explored;

	struct badger_trap_stats stats;
	struct badger_trap_stats totals;
};

/* The internal state of kbadgerd. */
struct kbadgerd_state {
	/* The PID of the process to inspect. */
	volatile pid_t pid;

	/* The interval to sleep (in millisecs). */
	volatile unsigned int sleep_interval;

	/*
	 * Is kbadgerd actively inspecting a process?
	 *
	 * If false and pid != 0, then we need to start inspecting a new process.
	 * If false and pid == 0, there is nothing to do.
	 * If true and pid == 0, a bug has occurred.
	 * If true and pid != 0, we are actively inspecting the process.
	 */
	volatile bool active;
	volatile bool pid_changed;

	/* The process and address space to inspect. */
	struct task_struct *inspected_task;
	struct mm_struct *mm;

	/*
	 * The data and range trees below should never have overlapping ranges,
	 * but old_data may.
	 * The data and range trees should have the same data except for
	 * current_range, which is in range but not data.
	 */
	/* The data collected by inspection. */
	struct rb_root_cached data;

	struct rb_root_cached old_data;

	/* List of the VMA ranges tracked to detect new ranges */
	struct rb_root range;

	/* Current range. */
	struct kbadgerd_range *current_range;

	u64 iteration;
	u64 iteration_time_left;
};
static struct kbadgerd_state state;

/* The task_struct of the kthread. */
static struct task_struct *kbadgerd_task = NULL;

/*
 * Flag that is set to true to halt the kthread. Only used when exiting the
 * module.
 */
static volatile bool kbadgerd_should_stop = false;

/* kbadgerd sysfs. */
static struct kobject *kbadgerd_kobj = NULL;

///////////////////////////////////////////////////////////////////////////////
// Manipulate the range rb-tree.
//
// We actually mostly use it as a heap, sorting the ranges so that the maximum
// range is the one we want to investigate next. We also want to have
// relatively cheap insertion and deletion so we can remove the max,
// investigate it, split it, and then insert the chunks.

static u64 total_misses(const struct badger_trap_stats *stats) {
	return stats->total_dtlb_2mb_load_misses
		+ stats->total_dtlb_2mb_store_misses
		+ stats->total_dtlb_4kb_load_misses
		+ stats->total_dtlb_4kb_store_misses;
}

/* Compares ranges by size/weight, not memory address. */
static int kbadgerd_range_cmp(
		const struct kbadgerd_range *ra,
		const struct kbadgerd_range *rb)
{
	u64 sizea = ra->end - ra->start;
	u64 sizeb = rb->end - rb->start;

	// Prioritize unexplored regions, but if both are unexplored, keep
	// comparing...
	if ((!ra->explored || !rb->explored) && (ra->explored || rb->explored)) {
		if (ra->explored) return 1;
		else return -1;
	}

	// Prioritize regions with more misses, but if both have the same
	// number, keep comparing...
	if (total_misses(&ra->stats) > total_misses(&rb->stats)) {
		return -1;
	} else if (total_misses(&ra->stats) < total_misses(&rb->stats)) {
		return 1;
	}

	// Otherwise, just pick the largest region.
	if (sizea < sizeb)
		return 1;
	else if (sizea > sizeb)
		return -1;
	else
		return 0;
}

// Inserts a new range into the data and range rb trees
// If range_root == NULL, the range is not inserted into the range tree
// If the range overlaps with an existing range, it will not be added to the
// range tree.
static void kbadgerd_range_insert(
		struct rb_root_cached *data_root,
		struct rb_root *range_root,
		struct kbadgerd_range *new_range)
{
	struct rb_node **new = &(data_root->rb_root.rb_node), *parent = NULL;
	bool is_leftmost = true;

	/* Figure out where to put new node in the data rb tree */
	while (*new) {
		struct kbadgerd_range *this =
			container_of(*new, struct kbadgerd_range, data_node);
		int result = kbadgerd_range_cmp(new_range, this);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else {
			// NOTE: since we are sorting by weight, it is possible
			// for two nodes to have the same weight.
			new = &((*new)->rb_right);
			is_leftmost = false;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&new_range->data_node, parent, new);
	rb_insert_color_cached(&new_range->data_node, data_root, is_leftmost);

	/* Figure out where to put the new node in the range rb tree */
	if (!range_root)
		return;

	new = &(range_root->rb_node);
	parent = NULL;
	while (*new) {
		struct kbadgerd_range *this =
			container_of(*new, struct kbadgerd_range, range_node);

		/* The ranges should not overlap*/
		if ((new_range->start <= this->start && this->start < new_range->end)
		    || (this->start <= new_range->start && new_range->start < this->end)) {
		    	BUG();
			return;
		}

		parent = *new;
		if (new_range->start < this->start)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&new_range->range_node, parent, new);
	rb_insert_color(&new_range->range_node, range_root);
}

/* NOTE: max = first, so we can take advantage of rb_root_cached. */
/* Only remove from the data rb tree to avoid accidentally adding the same range twice */
static struct kbadgerd_range *
kbadgerd_range_remove_max(struct rb_root_cached *root)
{
	struct rb_node *max_node = rb_first_cached(root);
	struct kbadgerd_range *max;

	if (!max_node)
		return NULL;

	max = container_of(max_node, struct kbadgerd_range, data_node);
	rb_erase_cached(max_node, root);

	return max;
}

///////////////////////////////////////////////////////////////////////////////
// kbadgerd data collection.

static void set_range_iterations(struct kbadgerd_range *range) {
	u64 range_size_hp = (range->end - range->start) >> HPAGE_SHIFT;
	state.iteration_time_left = range_size_hp > 0 ? range_size_hp : 1;
}

static void start_badger_trap(struct kbadgerd_range *range) {
	BUG_ON(!range);

	set_range_iterations(range);

	// Turn on badger trap for the next range.
	badger_trap_set_stats_loc(state.mm, &range->stats);
	badger_trap_stats_clear(state.mm->bt_stats);
	badger_trap_walk(state.mm, range->start, range->end - 1, true);
}

static void print_data(struct kbadgerd_range *range) {
	pr_warn("kbadgerd: [%llx, %llx) (%lld bytes)", range->start, range->end,
			range->end - range->start);
	if (total_misses(&range->totals)) {
		pr_warn("kbadgerd: \t4KB load misses: %lld", range->totals.total_dtlb_4kb_load_misses);
		pr_warn("kbadgerd: \t4KB store misses: %lld", range->totals.total_dtlb_4kb_store_misses);
		pr_warn("kbadgerd: \t2MB load misses: %lld", range->totals.total_dtlb_2mb_load_misses);
		pr_warn("kbadgerd: \t2MB store misses: %lld\n", range->totals.total_dtlb_2mb_store_misses);
	} else {
		pr_warn("kbadgerd: \tNo misses\n");
	}
}

static void print_all_data(void) {
	struct kbadgerd_range *range;
	// The range tree is used here because it is sorted by the start address
	// This relies on the invariant that the data and range trees have the
	// same ranges
	struct rb_node *node = rb_first(&state.range);

	pr_warn("kbadgerd: Results of inspection for pid=%d\n", state.pid);

	while (node) {
		range = container_of(node, struct kbadgerd_range, range_node);
		print_data(range);

		node = rb_next(node);
	}

	pr_warn("kbadgerd: Discarded ranges for pid=%d\n", state.pid);
	node = rb_first_cached(&state.old_data);

	while (node) {
		range = container_of(node, struct kbadgerd_range, data_node);
		print_data(range);

		node = rb_next(node);
	}

	pr_warn("kbadgerd: END Results of inspection for pid=%d\n", state.pid);
}

static struct kbadgerd_range *
kbadgerd_is_new_range(struct rb_root *root, struct vm_area_struct *vma) {
	struct rb_node *node = root->rb_node;
	struct kbadgerd_range *range;
	struct kbadgerd_range *new_range;
	u64 max_start = vma->vm_start;
	u64 min_end = vma->vm_end;

	while (node) {
		range = container_of(node, struct kbadgerd_range, range_node);

		// If the range is the same or entirely in another range, continue
		if (max_start >= range->start && min_end <= range->end) {
			return NULL;
		}
		// If the start of the range is within an old range and the end is outside
		// of the old range, we may need to create a new range at the end of the old
		// range. This can happen if the VMA grows up from the end
		// If the range keeps growing, there can be multiple ranges between the VMA
		// start and end, so make sure to get the largest one
		if (max_start < range->end && min_end > range->end) {
			if (max_start < range->end) {
				max_start = range->end;
				node = root->rb_node;
				continue;
			}
		}
		// Same as above, but for if the VMA grows down from the start
		if (max_start < range->start && min_end > range->start) {
			if (min_end > range->start) {
				min_end = range->start;
				node = root->rb_node;
				continue;
			}
		}

		// Traverse the tree
		if (vma->vm_start < range->start)
			node = node->rb_left;
		else
			node = node->rb_right;
	}

	new_range =
		(struct kbadgerd_range *)vzalloc(sizeof(struct kbadgerd_range));

	if (!new_range) {
		pr_err("kbadgerd: Unable to alloc new range! Skipping.");
		return NULL;
	}

	badger_trap_stats_init(&new_range->stats);
	badger_trap_stats_init(&new_range->totals);

	new_range->start = max_start;
	new_range->end = min_end;

	return new_range;
}

static void check_for_new_vmas(void) {
	struct vm_area_struct *vma = NULL;
	struct kbadgerd_range *range;

	down_read(&state.mm->mmap_sem);

	for (vma = state.mm->mmap; vma; vma = vma->vm_next) {
		range = kbadgerd_is_new_range(&state.range, vma);

		if (range) {
			kbadgerd_range_insert(&state.data, &state.range, range);
		}
	}

	up_read(&state.mm->mmap_sem);
}

static void start_inspection(void) {
	struct task_struct *target_task;
	struct vm_area_struct *vma = NULL;
	int i;

	pr_warn("kbadgerd: start inspection of pid=%d\n", state.pid);

	BUG_ON(state.pid == 0);

	// Avoid extra printing from badger trap.
	silence();

	// Get the task_struct and mm_struct to be inspected.
	target_task = get_pid_task(find_get_pid(state.pid), PIDTYPE_PID);
	if (!target_task) {
		pr_warn("kbadgerd: no such pid for promotion.\n");
		return;
	}

	state.inspected_task = target_task;

	mmgrab(target_task->mm);
	state.mm = target_task->mm;

	// Collect a list of address ranges. We collect this list rather than
	// an array of vm_area_struct because there can be calls to mmap
	// between iterations of kbadgerd. This would lead to annoyances in
	// managing pointers.
	down_read(&state.mm->mmap_sem);

	state.data = RB_ROOT_CACHED;
	state.old_data = RB_ROOT_CACHED;
	state.range = RB_ROOT;

	state.current_range = NULL;

	for (i = 0, vma = state.mm->mmap; vma; vma = vma->vm_next) {
		struct kbadgerd_range *new_range =
			(struct kbadgerd_range *)vzalloc(sizeof(struct kbadgerd_range));

		if (!new_range) {
			pr_err("kbadgerd: Unable to alloc new range! Skipping.");
			break;
		}

		badger_trap_stats_init(&new_range->stats);
		badger_trap_stats_init(&new_range->totals);

		new_range->start = vma->vm_start;
		new_range->end = vma->vm_end;

		kbadgerd_range_insert(&state.data, &state.range, new_range);

		i += 1;

		pr_warn("kbadgerd: region [%lx, %lx) anon=%d\n",
				vma->vm_start, vma->vm_end,
				vma_is_anonymous(vma));
	}

	up_read(&state.mm->mmap_sem);

	// Start badger trap for the first range...
	state.active = true;
	state.current_range = kbadgerd_range_remove_max(&state.data);
	if (!state.current_range) {
		pr_err("kbadgerd: no range to act on.");
		return;
	}
	start_badger_trap(state.current_range);

	pr_warn("kbadgerd: inited with process %d, %lld iterations\n",
			state.pid, state.iteration_time_left);

	return;
}

static void end_inspection(void) {
	struct kbadgerd_range *range;

	pr_warn("kbadgerd: Ending inspection.\n");

	// Collect final stats...
	if (state.current_range) {
		badger_trap_walk(state.mm,
				state.current_range->start,
				state.current_range->end - 1,
				false);

		badger_trap_add_stats(&state.current_range->totals,
				&state.current_range->stats);

		// Add it back to the tree for simplicity.
		kbadgerd_range_insert(&state.data, NULL, state.current_range);
		state.current_range = NULL;
		badger_trap_set_stats_loc(state.mm, NULL);
	}

	// Print all stats.
	print_all_data();

	// Free the tree.
	while ((range = kbadgerd_range_remove_max(&state.data))) { // NOTE: assignment
		vfree(range);
	}
	while ((range = kbadgerd_range_remove_max(&state.old_data))) { // NOTE: assignment
		vfree(range);
	}

	state.range = RB_ROOT;

	if (state.mm) {
		mmdrop(state.mm);
		state.mm = NULL;
	}

	if (state.inspected_task) {
		put_task_struct(state.inspected_task);
		state.inspected_task = NULL;
	}

	state.active = false;
	state.pid = 0;
}

static void process_and_insert_current_range(void) {
	struct kbadgerd_range *current_range = state.current_range;
	struct kbadgerd_range *new_left_range, *new_right_range;
	u64 midpoint;

	// Mark the current range as explored. This decreases its priority in
	// the next scan should we choose not to split it.
	current_range->explored = true;

	// Remove the range from the range rb tree because it might be split
	rb_erase(&current_range->range_node, &state.range);

	// If the size of the current range is smaller than the threshold, we
	// don't try to break it down further. Just insert it back to the tree.
	if (current_range->end - current_range->start <= RANGE_SIZE_THRESHOLD) {
		kbadgerd_range_insert(&state.data, &state.range, current_range);
		return;
	}

	// If the region took no hits, then don't bother looking at it much more...
	if (total_misses(&current_range->stats) <= RANGE_IRRELEVANCE_THRESHOLD) {
		kbadgerd_range_insert(&state.data, &state.range, current_range);
		return;
	}

	// We want the midpoint to end at a page-aligned boundary.
	midpoint = (current_range->start
		+ (current_range->end - current_range->start) / 2)
		& PAGE_MASK;

	// Range is too small to split further. If RANGE_SIZE_THRESHOLD is
	// large enough, this should never happen.
	if (current_range->start == midpoint || current_range->end == midpoint) {
		kbadgerd_range_insert(&state.data, &state.range, current_range);
		return;
	}

	// Otherwise, we try to split it in half. We give each half the weight
	// of the whole so that we prioritize re-inspection.
	new_left_range =
		(struct kbadgerd_range *)vzalloc(sizeof(struct kbadgerd_range));

	if (!new_left_range) {
		pr_err("kbadgerd: Unable to alloc new range! Reusing old.");
		kbadgerd_range_insert(&state.data, &state.range, current_range);
		return;
	}

	new_right_range =
		(struct kbadgerd_range *)vzalloc(sizeof(struct kbadgerd_range));

	if (!new_right_range) {
		pr_err("kbadgerd: Unable to alloc new range! Reusing old.");
		kbadgerd_range_insert(&state.data, &state.range, current_range);
		vfree(new_left_range);
		return;
	}

	badger_trap_stats_init(&new_left_range->stats);
	badger_trap_stats_init(&new_right_range->stats);
	badger_trap_stats_init(&new_left_range->totals);
	badger_trap_stats_init(&new_right_range->totals);

	// TODO markm: bijan suggested taking stats/2 for each half...

	new_left_range->start = current_range->start;
	new_left_range->end = midpoint;
	new_left_range->stats = current_range->stats;

	new_right_range->start = midpoint;
	new_right_range->end = current_range->end;
	new_right_range->stats = current_range->stats;

	kbadgerd_range_insert(&state.data, &state.range, new_left_range);
	kbadgerd_range_insert(&state.data, &state.range, new_right_range);

	state.current_range = NULL;
	kbadgerd_range_insert(&state.old_data, NULL, current_range);
}

static void continue_inspection(void) {
	struct kbadgerd_range *range;

	if (state.inspected_task->flags & (PF_EXITING | PF_SIGNALED)) {
		pr_warn("kbadgerd: inspected process is exiting. Ending inspection.\n");
		end_inspection();
		return;
	}

	if (state.iteration_time_left == 1 || (state.iteration_time_left % 100 == 0))
		pr_warn("kbadgerd: continuing inspection of pid=%d, %lld iterations left\n",
				state.pid, state.iteration_time_left);

	BUG_ON(state.pid == 0 || !state.active);
	BUG_ON(!state.current_range);

	// If we are not done with the current range, do nothing.
	if (--state.iteration_time_left > 0) return;

	range = state.current_range;

	// Turn off bt for the outgoing range.
	badger_trap_set_stats_loc(state.mm, NULL);
	badger_trap_walk(state.mm, range->start, range->end - 1, false);

	// Accumulate the changes from the last sampling period.
	badger_trap_add_stats(&range->totals, &range->stats);

	// Insert the current range back into the tree.
	process_and_insert_current_range();

	// Move to the next range, if any.
	state.current_range = kbadgerd_range_remove_max(&state.data);
	if (!state.current_range) {
		end_inspection();
		return;
	}

	// TODO markm: want some terminating condition here.

	// Reset the counters and start badger trap.
	start_badger_trap(state.current_range);
}

/* The main loop of kbadgerd. */
static int kbadgerd_do_work(void *data)
{
        u32 i = 0;

	while (!kbadgerd_should_stop) {
		if (state.active && state.pid_changed) {
			pr_warn("kbadgerd: pid changed. Ending inspection.");
			end_inspection();
		}

		if (state.active) {
                        if (i % KBADGERD_NEW_VMA_CHECK_RATE == 0) {
                            check_for_new_vmas();
                        }
			continue_inspection();
		} else if (state.pid != 0) {
			start_inspection();
		}

                i++;
		pr_warn_once("kbadgerd: Interval is %d ms.\n", state.sleep_interval);
		msleep(state.sleep_interval);
	}

	pr_warn("kbadgerd: exiting.\n");

	end_inspection();

	do_exit(0);
	BUG(); // Should never get here.
}

/******************************************************************************/
/* Module init and deinit */

static ssize_t enabled_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "pid=%d\n", state.pid);
}

static ssize_t enabled_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	pid_t pid;
	int ret;

	ret = kstrtoint(buf, 0, &pid);

	if (state.pid != 0) {
		pr_warn("kbadgerd: pid changed while already running.");
		state.pid_changed = true;
	}

	if (sysfs_streq(buf, "off")) {
		return count;
	}

	if (ret != 0) {
		state.pid = 0;
		return ret;
	}
	// Check that this is an existing process.
	else if (find_vpid(pid) != NULL) {
		state.pid = pid;
		return count;
	}
	// Not a valid PID.
	else {
		state.pid = 0;
		return -EINVAL;
	}
}
static struct kobj_attribute enabled_attr =
	__ATTR(enabled, 0644, enabled_show, enabled_store);

static ssize_t sleep_interval_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", state.sleep_interval);
}

static ssize_t sleep_interval_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int interval;
	int ret;

	ret = kstrtouint(buf, 0, &interval);
	if (ret != 0) {
		return ret;
	}
	else if (interval == 0) {
		state.sleep_interval = KBADGERD_SLEEP_MS;
		return count;
	}
	else {
		state.sleep_interval = interval;
		return count;
	}
}
static struct kobj_attribute sleep_interval_attr =
	__ATTR(sleep_interval, 0644, sleep_interval_show,
			sleep_interval_store);

static struct attribute *kbadgerd_attr[] = {
	&enabled_attr.attr,
	&sleep_interval_attr.attr,
	NULL,
};

static const struct attribute_group kbadgerd_attr_group = {
	.attrs = kbadgerd_attr,
};

static int kbadgerd_init_sysfs(struct kobject **kbadgerd_kobj)
{
	int err;

	*kbadgerd_kobj = kobject_create_and_add("kbadgerd", mm_kobj);
	if (unlikely(!*kbadgerd_kobj)) {
		pr_err("failed to create kbadgerd kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(*kbadgerd_kobj, &kbadgerd_attr_group);
	if (err) {
		pr_err("failed to register kbadgerd group\n");
		kobject_put(*kbadgerd_kobj);
		return err;
	}

	return 0;
}

#if IS_MODULE(CONFIG_KBADGERD)
static void kbadgerd_exit_sysfs(struct kobject *kbadgerd_kobj)
{
	sysfs_remove_group(kbadgerd_kobj, &kbadgerd_attr_group);
	kobject_put(kbadgerd_kobj);
}
#endif

static int do_kbadgerd_init(void)
{
	int err;

	BUG_ON(kbadgerd_task);

	pr_warn("kbadgerd: Starting.\n");

	// Init state by clearing it.
	memset(&state, 0, sizeof(state));
	state.sleep_interval = KBADGERD_SLEEP_MS;

	kbadgerd_should_stop = false;
	kbadgerd_task = kthread_run(kbadgerd_do_work, NULL, "kbadgerd");

	if (IS_ERR(kbadgerd_task)) {
		err = PTR_ERR(kbadgerd_task);
		kbadgerd_task = NULL;
		return err;
	}

	err = kbadgerd_init_sysfs(&kbadgerd_kobj);
	if (err)
		return err;

	return 0;
}

#if IS_MODULE(CONFIG_KBADGERD)
static int __init init_kbadgerd(void)
{
	return do_kbadgerd_init();
}
module_init(init_kbadgerd);

static void do_kbadgerd_exit(void)
{
	if (kbadgerd_task) {
		kbadgerd_should_stop = true;
		kthread_stop(kbadgerd_task);
	}

	kbadgerd_exit_sysfs(kbadgerd_kobj);
}

static void __exit exit_kbadgerd(void)
{
	do_kbadgerd_exit();
}
module_exit(exit_kbadgerd);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Mansi <markm@cs.wisc.edu>");
MODULE_DESCRIPTION("BadgerTrap kthread.");
#elif IS_BUILTIN(CONFIG_KBADGERD)
static int __init init_kbadgerd(void)
{
	return do_kbadgerd_init();
}
subsys_initcall(init_kbadgerd);
#endif
