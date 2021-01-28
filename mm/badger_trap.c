#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/badger_trap.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/pagewalk.h>
#include <linux/sched/mm.h>

char badger_trap_process[CONFIG_NR_CPUS][MAX_NAME_LEN];

static bool silent = false;

void silence(void) {
	silent = true;
}
EXPORT_SYMBOL(silence);

/*
 * This syscall is generic way of setting up badger trap.
 * There are three options to start badger trap.
 * (1) 	option > 0: provide all process names with number of processes.
 * 	This will mark the process names for badger trap to start when any
 * 	process with names specified will start.
 *
 * (2) 	option == 0: starts badger trap for the process calling the syscall itself.
 *  	This requires binary to be updated for the workload to call badger trap. This
 *  	option is useful when you want to skip the warmup phase of the program. You can
 *  	introduce the syscall in the program to invoke badger trap after that phase.
 *
 * (3) 	option < 0: provide all pid with number of processes. This will start badger
 *  	trap for all pids provided immidiately.
 *
 *  Note: 	(1) will allow all the child processes to be marked for badger trap when
 *  		forked from a badger trap process.

 *		(2) and (3) will not mark the already spawned child processes for badger
 *		trap when you mark the parent process for badger trap on the fly. But (2) and (3)
 *		will mark all child spwaned from the parent process adter being marked for badger trap.
 */
SYSCALL_DEFINE3(init_badger_trap,
		const char __user**, process_name_user,
		unsigned long, num_procs, int, option)
{
	unsigned int i;
	char *temp;
	unsigned long ret = 0;
	char **process_name = NULL;
	char proc[MAX_NAME_LEN];
	struct task_struct * tsk;
	unsigned long pid;

	process_name = vmalloc(sizeof(char*) * num_procs);
	if (!process_name) {
		return -ENOMEM;
	}

	ret = copy_from_user(process_name, process_name_user, sizeof(char*) * num_procs);
	if (ret) {
		return ret;
	}

	pr_warn("init_badger_trap %p %lu %d", process_name, num_procs, option);

	if(option > 0)
	{
		for(i = 0; i < CONFIG_NR_CPUS; i++)
		{
			if(i<num_procs) {
				pr_warn("copy from user name=%p", process_name[i]);
				ret = strncpy_from_user(proc, process_name[i], MAX_NAME_LEN);
				pr_warn("copy from user name=%s", proc);
			} else
				temp = strncpy(proc, "", MAX_NAME_LEN);
			temp = strncpy(badger_trap_process[i], proc, MAX_NAME_LEN-1);
		}
	}
	else if(option == 0)
	{
		badger_trap_walk(current->mm, 0, ~0ull, true);
	}
	else if(option < 0)
	{
		for(i = 0; i < CONFIG_NR_CPUS; i++)
		{
			if(i < num_procs)
			{
				ret = kstrtoul(process_name[i], 10, &pid);
				if(ret == 0)
				{
					tsk = find_task_by_vpid(pid);
					badger_trap_walk(tsk->mm, 0, ~0ull, true);
				}
			}
		}
	}

	return 0;
}

/*
 * This function checks whether a process name provided matches from the list
 * of process names stored to be marked for badger trap.
 */
bool is_badger_trap_process(const char* proc_name)
{
	unsigned int i;
	for(i = 0; i < CONFIG_NR_CPUS; i++)
	{
		if(!strncmp(proc_name, badger_trap_process[i], MAX_NAME_LEN)) {
			pr_warn("Badger Trap process (%s).", proc_name);
			return true;
		}
	}
	//pr_info("NOT Badger Trap process (%s).", proc_name);
	return false;
}

/*
 * This function checks whether a process name provided matches from the list
 * of process names stored to be marked for badger trap.
 */
bool is_badger_trap_enabled(const struct mm_struct *mm, u64 address)
{
	if (!mm)
		return false;

	if (!mm->badger_trap_enabled)
		return false;

	if (address < mm->badger_trap_start)
		return false;

	if (mm->badger_trap_end < address)
		return false;

	return true;
}

/*
 * Helper functions to manipulate all the TLB entries for reservation.
 */
inline pte_t pte_mkreserve(pte_t pte)
{
        return pte_set_flags(pte, _PAGE_RESERVED);
}

inline pte_t pte_unreserve(pte_t pte)
{
        return pte_clear_flags(pte, _PAGE_RESERVED);
}

inline int is_pte_reserved(pte_t pte)
{
        if(native_pte_val(pte) & _PAGE_RESERVED)
                return 1;
        else
                return 0;
}

inline pmd_t pmd_mkreserve(pmd_t pmd)
{
        return pmd_set_flags(pmd, _PAGE_RESERVED);
}

inline pmd_t pmd_unreserve(pmd_t pmd)
{
        return pmd_clear_flags(pmd, _PAGE_RESERVED);
}

inline int is_pmd_reserved(pmd_t pmd)
{
        if(native_pmd_val(pmd) & _PAGE_RESERVED)
                return 1;
        else
                return 0;
}

inline pud_t pud_mkreserve(pud_t pud)
{
        return pud_set_flags(pud, _PAGE_RESERVED);
}

inline pud_t pud_unreserve(pud_t pud)
{
        return pud_clear_flags(pud, _PAGE_RESERVED);
}

inline int is_pud_reserved(pud_t pud)
{
        if(native_pud_val(pud) & _PAGE_RESERVED)
                return 1;
        else
                return 0;
}

static int bt_init_pud(pud_t *pud, unsigned long addr,
	 unsigned long next, struct mm_walk *walk)
{
	if (pud_none(*pud) || !pud_present(*pud))
		return 0;

	if (!(pud_flags(*pud) & _PAGE_USER))
		return 0;

	//pr_warn("mm=%p vma=%p addr=%lx pud=%p\n", walk->mm, walk->vma, addr, pud);
	// We can only get huge puds here.
	if (*(bool*)walk->private) {
		*pud = pud_mkreserve(*pud);
	} else {
		*pud = pud_unreserve(*pud);
	}

	return 0;
}

static int bt_init_pmd(pmd_t *pmd, unsigned long addr,
	 unsigned long next, struct mm_walk *walk)
{
	// We get normal as well as huge pmds here.
	if (pmd_none(*pmd) || !pmd_present(*pmd))
		return 0;

	if (!(pmd_flags(*pmd) & _PAGE_USER))
		return 0;

	if (pmd_trans_huge(*pmd)) {
		if (*(bool*)walk->private) {
			//pr_warn("mm=%p vma=%p addr=%lx pmd=%p\n", walk->mm, walk->vma, addr, pmd);
			*pmd = pmd_mkreserve(*pmd);
		} else {
			*pmd = pmd_unreserve(*pmd);
		}
	}

	return 0;
}
static int bt_init_pte(pte_t *pte, unsigned long addr,
	 unsigned long next, struct mm_walk *walk)
{
	if (pte_none(*pte) || !pte_present(*pte))
		return 0;

	if (!(pte_flags(*pte) & _PAGE_USER))
		return 0;

	if (*(bool*)walk->private) {
		//pr_warn("mm=%p vma=%p addr=%lx ptep=%p pte=%lx\n",
		//		walk->mm, walk->vma, addr, pte, pte_val(*pte));
		*pte = pte_mkreserve(*pte);
	} else {
		*pte = pte_unreserve(*pte);
	}

	return 0;
}

static int bt_init_hugetlb_entry(pte_t *ptep, unsigned long hmask,
	     unsigned long addr, unsigned long next,
	     struct mm_walk *walk)
{
	pte_t pte = huge_ptep_get(ptep);

	if (pte_none(pte) || !pte_present(pte))
		return 0;

	if (!(pte_flags(pte) & _PAGE_USER))
		return 0;

	/*
	if (*(bool*)walk->private) {
		*pte = pte_mkreserve(*pte);
	} else {
		*pte = pte_unreserve(*pte);
	}
	*/
	set_huge_pte_at(walk->mm, addr, ptep, pte);

	return 0;
}

static int bt_init_test_walk(unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	//pr_warn("test_walk(addr=%lx, next=%lx, mm=%p, vma=%p is_exec=%d may_exec=%d is_anon=%d\n",
	//		addr, next, walk->mm, walk->vma,
	//		walk->vma && (walk->vma->vm_flags & VM_EXEC),
	//		walk->vma && (walk->vma->vm_flags & VM_MAYEXEC),
	//		walk->vma && vma_is_anonymous(walk->vma));

	// Skip unmapped regions
	if (!walk->vma)
		return 1;

	// Skip executable regions, since we don't handle instruction TLB misses.
	if (walk->vma->vm_flags & VM_EXEC)
		return 1;

	return 0;
}

void badger_trap_set_stats_loc(struct mm_struct *mm, struct badger_trap_stats *stats)
{
	BUG_ON(!mm);
	if (stats)
		mm->bt_stats = stats;
	else
		mm->bt_stats = &mm->bt_stats_inner;
}
EXPORT_SYMBOL(badger_trap_set_stats_loc);

/*
 * This function walks the page tables of the given mm_struct for pages mapped
 * between the given lower and upper addresses (inclusive). Depending on the
 * value of init, we either set or clear the _PAGE_RESERVED bit in all relevant
 * page table entries (init == true => set; init == false => clear).
 *
 * This function takes care of transparent hugepages and hugepages in general.
 *
 * NOTE: The upper and lower boundaries are rounded to the up and down,
 * respectively, to the nearest 2MB boundaries. This makes it easier to deal
 * with huge pages being formed or broken up.
 *
 * NOTE: This function acquires and releases mmap_sem.
 *
 * NOTE: If `init == false`, there MUST have been a prior call with `init ==
 * true` first for the same `mm`. Otherwise, there will be a double free.
 */
void badger_trap_walk(struct mm_struct *mm, u64 lower, u64 upper, bool init)
{
	// markm: see comments in <linux/pagewalk.h>
	const struct mm_walk_ops ops = {
		.pud_entry = bt_init_pud,
		.pmd_entry = bt_init_pmd,
		.pte_entry = bt_init_pte,
		.hugetlb_entry = bt_init_hugetlb_entry,
		.test_walk = bt_init_test_walk,
	};
	int ret;
	u64 upper_rounded;

	BUG_ON(!mm);
	BUG_ON(lower >= upper);

	// Grab when turning on BadgerTrap, and don't release until BadgerTrap
	// is turned off. Under the assumption that there is at least one call
	// with `init == true` for each call with `init == false`, the worse
	// that can happen is a memory leak.
	if (init) {
		mmgrab(mm);
	}

	down_write(&mm->mmap_sem);

	// When initializing, we want to set these first. If deinitializing, we
	// set them after walking.
	if (init) {
		// Round down to hpage boundary.
		mm->badger_trap_start = lower & HPAGE_PMD_MASK;
		// Round up to hpage boundary, but subtract 1 to make it inclusive.
		mm->badger_trap_end = ((upper - 1) & HPAGE_PMD_MASK) + HPAGE_PMD_SIZE - 1;
		mm->badger_trap_enabled = true;
		mm->badger_trap_was_enabled = true;
		badger_trap_stats_clear(mm->bt_stats);
	}

	// Block any other page faults from changing the mappings while we walk.
	//
	// TODO: probably also need to guard migration, thp promotion/demotion,
	// mmap, mprotect, mlock...
	down_write(&mm->badger_trap_page_table_sem);

	pr_warn("BadgerTrap: walk(%llx, %llx) init = %d [%llx, %llx]\n",
			lower, upper, init, mm->badger_trap_start,
			mm->badger_trap_end);

	// upper is inclusive of the end point, whereas walk_page_range expects
	// an exclusive endpoint. But we need to be careful of overflow.
	upper_rounded = upper == ~0ull ?
				upper & (PAGE_SIZE - 1) :
				upper + 1;

	ret = walk_page_range(mm, lower, upper_rounded, &ops, &init);
	if (ret != 0) {
		pr_err("BadgerTrap: walk_page_range returned %d\n", ret);
		BUG();
	}

	up_write(&mm->badger_trap_page_table_sem);

	if (!init) {
		mm->badger_trap_enabled = false;
	}

	up_write(&mm->mmap_sem);

	if (!init) {
		mmdrop(mm);
	}
}
EXPORT_SYMBOL(badger_trap_walk);

void print_badger_trap_stats(const struct mm_struct *mm) {
	//struct vm_area_struct *vma;

	if (silent) return;

	pr_warn("===================================\n");
	pr_warn("BadgerTrap: Statistics for Process %s\n",
			mm->owner ? mm->owner->comm : "<unknown process>");
	pr_warn("BadgerTrap: DTLB load miss for 4KB page detected %llu\n",
			atomic64_read_acquire(&mm->bt_stats->total_dtlb_4kb_load_misses));
	pr_warn("BadgerTrap: DTLB load miss for 2MB page detected %llu\n",
			atomic64_read_acquire(&mm->bt_stats->total_dtlb_2mb_load_misses));
	pr_warn("BadgerTrap: DTLB store miss for 4KB page detected %llu\n",
			atomic64_read_acquire(&mm->bt_stats->total_dtlb_4kb_store_misses));
	pr_warn("BadgerTrap: DTLB store miss for 2MB page detected %llu\n",
			atomic64_read_acquire(&mm->bt_stats->total_dtlb_2mb_store_misses));
	/*
	pr_warn("-----------------------------------\n");
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		pr_warn("BadgerTrap: [%lx, %lx]\n", vma->vm_start, vma->vm_end);
		pr_warn("BadgerTrap: DTLB load miss for 4KB page detected %llu\n",
				vma->bt_stats.total_dtlb_4kb_load_misses);
		pr_warn("BadgerTrap: DTLB load miss for 2MB page detected %llu\n",
				vma->bt_stats.total_dtlb_2mb_load_misses);
		pr_warn("BadgerTrap: DTLB store miss for 4KB page detected %llu\n",
				vma->bt_stats.total_dtlb_4kb_store_misses);
		pr_warn("BadgerTrap: DTLB store miss for 2MB page detected %llu\n",
				vma->bt_stats.total_dtlb_2mb_store_misses);
	}
	*/
	pr_warn("BadgerTrap: END Statistics\n");
	pr_warn("===================================\n");
}
EXPORT_SYMBOL(print_badger_trap_stats);
