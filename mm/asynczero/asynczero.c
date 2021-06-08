#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/mmzone.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <linux/mm_econ.h>
#include <asm/page_64.h>

#define HUGE_PAGE_ORDER 9

#define list_last_entry_or_null(ptr, type, member) ({ \
	list_empty(ptr) ? NULL : list_last_entry(ptr, type, member) ;\
})

static struct task_struct *asynczero_task = NULL;
static volatile bool asynczero_should_stop = false;

// Only used if mm_econ is off.
int sleep = 1000;
module_param(sleep, int, 0644);

int count = 10;
module_param(count, int, 0644);

// For debugging...
// 0 = mm_econ, 1 = act as if mm_econ is off (even if it is on)
int mode = 0;
module_param(mode, int, 0644);

//int zero_fill_order = MAX_ORDER - 1;
//module_param(zero_fill_order, int, 0644);

u64 pages_zeroed = 0;
module_param(pages_zeroed, ullong, 0444);

static inline bool skip_zone(struct zone *zone)
{
	return false;
}

/*
 * preferrably use the architecture specific extensions to zero-fill a page.
 * use memset as a fallback option.
 */
static inline void zero_fill_page_ntstores(struct page *page)
{
	void *kaddr;
	kaddr = kmap_atomic(page);
	__asm__ (
		"push %%rax;"
		"push %%rcx;"
		"push %%rdi;"
		"movq	%0, %%rdi;"
		"xorq    %%rax, %%rax;"
		"movl    $4096/64, %%ecx;"
		".p2align 4;"
		"1:;"
		"decl    %%ecx;"
		"movnti  %%rax,(%%rdi);"
		"movnti  %%rax,0x8(%%rdi);"
		"movnti  %%rax,0x10(%%rdi);"
		"movnti  %%rax,0x18(%%rdi);"
		"movnti  %%rax,0x20(%%rdi);"
		"movnti  %%rax,0x28(%%rdi);"
		"movnti  %%rax,0x30(%%rdi);"
		"movnti  %%rax,0x38(%%rdi);"
		"leaq    64(%%rdi),%%rdi;"
		"jnz     1b;"
		"nop;"
		"pop %%rdi;"
		"pop %%rcx;"
		"pop %%rax;"
		: /* output */
		: "a" (kaddr)
	);
	kunmap_atomic(kaddr);
	SetPageZeroed(page);
}

/* the core logic to zero-fill a compound page */
static inline void zero_fill_compound_page(struct page *page, int order)
{
	int i;

	if (PageZeroed(page))
		return;

	for (i = 0; i < (1 << order); i++) {
		/* kernel's in-built zeroing function */
		//clear_highpage(page + i);

		/* custom zero-filling logic */
		zero_fill_page_ntstores(page + i);
	}

	pages_zeroed += 1 << order;
}

static int zero_fill_zone_pages(struct zone *zone, int *n)
{
	struct page *page;
	struct free_area *area;
	unsigned long flags;
	int order;
	bool zeroed_something = false;

        for (order = HUGE_PAGE_ORDER; order < MAX_ORDER; ++order) {
		unsigned long retries = 0;
		while (retries < 100) {
			area = &(zone->free_area[order]);

			/* remove one page from freelist with the lock held */
			spin_lock_irqsave(&zone->lock, flags);
			page = list_last_entry_or_null(&area->free_list[MIGRATE_MOVABLE],
					struct page, lru);
			if (!page) {
				spin_unlock_irqrestore(&zone->lock, flags);
				break;
			}
			if (PageZeroed(page)) {
				retries++;
				list_rotate_to_front(&page->lru, &area->free_list[MIGRATE_MOVABLE]);
				spin_unlock_irqrestore(&zone->lock, flags);
				continue;
			}
			list_del(&page->lru);
			area->nr_free--;
			spin_unlock_irqrestore(&zone->lock, flags);

			// zero fill
			zero_fill_compound_page(page, order);
			zeroed_something = true;

			// add back to freelist
			spin_lock_irqsave(&zone->lock, flags);
			list_add(&page->lru, &area->free_list[MIGRATE_MOVABLE]);
			area->nr_free++;
			spin_unlock_irqrestore(&zone->lock, flags);

			// One down... (n-1) to go...
			*n -= 1 << order;
			if (*n <= 0) {
				return 0;
			}
		}
	}

	// If we get here, we completed both loops without zeroing n pages.
	// This could be because the zone doesn't have n pages or because all
	// of the freelists we tried are already zeroed. If they are already
	// zeroed, we want to return a distinct exit code so that we don't
	// waste time continue to zero.
	if (zeroed_something)
		return -1; // ran out of pages to zero
	else
		return -2; // everything was already zeroed
}

static void zero_n_pages(int n)
{
	// STATIC: Keep track of where we left off...
	static struct zone *current_zone = NULL;

	int ret;
	bool all_zeroed = false;

	if (current_zone == NULL)
		current_zone = (first_online_pgdat())->node_zones;

	while (true) {
		// starts from wherever we left off last time...
		while(current_zone) {
			if (!populated_zone(current_zone) || skip_zone(current_zone)) {
				current_zone = next_zone(current_zone);
				continue;
			}

			ret = zero_fill_zone_pages(current_zone, &n);

			switch (ret) {
				case -2:
					all_zeroed = true;
					break;
				case 0:
					all_zeroed = false;
					break;

				case -1:
					break;

				default:
					BUG();
			}

			// If we have zeroed enough, exit for now.
			if (n <= 0) return;

			current_zone = next_zone(current_zone);
		}

		// restart from the beginning next time.
		current_zone = (first_online_pgdat())->node_zones;

		// If this is true it is likely all zones are zeroed (it
		// could be just the last zone, though... best effort).
		if (all_zeroed) return;
	}
}

static int asynczero_do_work(void *data)
{
	while (!asynczero_should_stop) {
		// We just woke up. Check the cost-benefit of doing another iteration.
		struct mm_cost_delta mm_cost_delta;
		struct mm_action mm_action = {
			.action = MM_ACTION_RUN_PREZEROING,
			.prezero_n = count,
		};
		bool should_run;

		if (mm_econ_is_on() && mode == 0) {
			mm_estimate_changes(&mm_action, &mm_cost_delta);
			should_run = mm_decide(&mm_cost_delta);
		} else {
			should_run = true;
		}

		// If worth it, zero some pages.
		if (should_run) zero_n_pages(count);

		// Yield CPU.
		if (mm_econ_is_on() && mode == 0)
			cond_resched();
		else
			msleep(sleep);
	}

	return 0;
}

int init_module(void)
{
	int err;

	asynczero_should_stop = false;
	asynczero_task = kthread_run(asynczero_do_work, NULL, "kasynczerod");

	if (IS_ERR(asynczero_task)) {
		err = PTR_ERR(asynczero_task);
		asynczero_task = NULL;
		return err;
	}

	return 0;
}

void cleanup_module(void)
{
	if (asynczero_task) {
		asynczero_should_stop = true;
		kthread_stop(asynczero_task);
	}

	printk(KERN_INFO"asynczero: exiting\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ashish Panwar");
MODULE_AUTHOR("Mark Mansi");
