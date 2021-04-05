#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/mmzone.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <asm/page_64.h>

#define HUGE_PAGE_ORDER 9

#define list_last_entry_or_null(ptr, type, member) ({ \
	list_empty(ptr) ? NULL : list_last_entry(ptr, type, member) ;\
})

static struct task_struct *asynczero_task[MAX_NUMNODES];
static volatile bool asynczero_should_stop = false;

int sleep = 1000;
module_param(sleep, int, 0644);

int count = 10;
module_param(count, int, 0644);

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

static void zero_fill_zone_pages(struct zone *zone)
{
	struct page *page;
	struct free_area *area;
	unsigned long flags;
	int order;
	u64 old_nzeroed = pages_zeroed;

        for (order = HUGE_PAGE_ORDER; order < MAX_ORDER; ++order) {
		unsigned long retries = 0;
		area = &(zone->free_area[order]);

		while (retries < 100) {
			/* remove one page from freelist with the lock held */
			spin_lock_irqsave(&zone->lock, flags);
			page = list_last_entry_or_null(&area->free_list[MIGRATE_MOVABLE],
					struct page, lru);
			if (!page) {
				spin_unlock_irqrestore(&zone->lock, flags);
				break;;
			}
			if (PageZeroed(page)) {
				retries++;
				list_del(&page->lru);
				list_add(&page->lru, &area->free_list[MIGRATE_MOVABLE]);
				spin_unlock_irqrestore(&zone->lock, flags);
				continue;
			}
			list_del(&page->lru);
			area->nr_free--;
			spin_unlock_irqrestore(&zone->lock, flags);

			// zero fill
			zero_fill_compound_page(page, order);

			// add back to freelist
			spin_lock_irqsave(&zone->lock, flags);
			list_add(&page->lru, &area->free_list[MIGRATE_MOVABLE]);
			area->nr_free++;
			spin_unlock_irqrestore(&zone->lock, flags);

			if (pages_zeroed - old_nzeroed > count) {
				msleep(sleep);
				old_nzeroed = pages_zeroed;
			}
		}
	}
}

static int asynczero_do_work(void *data)
{
	int nid = (int)(long) data;
	struct zone *zone;
	struct zoneref *z;
	struct zonelist *zonelist = node_zonelist(nid, __GFP_THISNODE);
	enum zone_type high_zoneidx = gfp_zone(GFP_ZONEMASK);
	nodemask_t nodemask = nodemask_of_node(nid);

	while (!asynczero_should_stop) {
		for_each_zone_zonelist_nodemask(
				zone, z, zonelist,
				high_zoneidx, &nodemask)
		{
			if (!populated_zone(zone) || skip_zone(zone))
				continue;

			zero_fill_zone_pages(zone);
			msleep(sleep);
		}
	}

	return 0;
}

static int asynczero_start(int nid)
{
	struct task_struct **t = &asynczero_task[nid];

	*t = kthread_run(asynczero_do_work, (void*)(long)nid, "kasynczerod%d", nid);
	if (IS_ERR(*t)) {
		int err = PTR_ERR(*t);
		*t = NULL;
		return err;
	}

	return 0;
}

int init_module(void)
{
	int nid;
	int err;
	int i;

	asynczero_should_stop = false;

	// Zero them out for debugging...
	for (i = 0; i < MAX_NUMNODES; ++i)
		asynczero_task[i] = NULL;

	// Start a kthread for each numa node.
	for_each_node_state(nid, N_MEMORY) {
		err = asynczero_start(nid);
		if (err != 0)
			pr_err("asynczero: unable to start on node %d\n", nid);
	}

	return 0;
}

void cleanup_module(void)
{
	int nid;

	asynczero_should_stop = true;

	for_each_node_state(nid, N_MEMORY)
		if (asynczero_task[nid])
			kthread_stop(asynczero_task[nid]);

	printk(KERN_INFO"asynczero: exiting\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ashish Panwar");
