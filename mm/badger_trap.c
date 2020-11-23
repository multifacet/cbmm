#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/badger_trap.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/pagewalk.h>

char badger_trap_process[CONFIG_NR_CPUS][MAX_NAME_LEN];

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

	// All other inputs ignored
	if(option == 0)
	{
		current->mm->badger_trap_enabled = true;
		badger_trap_init_all(current->mm);
	}

	if(option < 0)
	{
		for(i = 0; i < CONFIG_NR_CPUS; i++)
		{
			if(i < num_procs)
			{
				ret = kstrtoul(process_name[i], 10, &pid);
				if(ret == 0)
				{
					tsk = find_task_by_vpid(pid);
					tsk->mm->badger_trap_enabled = true;
					badger_trap_init_all(tsk->mm);
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
int is_badger_trap_process(const char* proc_name)
{
	unsigned int i;
	for(i = 0; i < CONFIG_NR_CPUS; i++)
	{
		if(!strncmp(proc_name, badger_trap_process[i], MAX_NAME_LEN)) {
			pr_warn("Badger Trap process (%s).", proc_name);
			return 1;
		}
	}
	pr_warn("NOT Badger Trap process (%s).", proc_name);
	return 0;
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

	// We can only get huge puds here.
	// *pud = pud_mkreserve(*pud);// TODO markm uncomment

	return 0;
}

static int bt_init_pmd(pmd_t *pmd, unsigned long addr,
	 unsigned long next, struct mm_walk *walk)
{
	// We get normal as well as huge pmds here.
	if (pmd_none(*pmd) || !pmd_present(*pmd))
		return 0;

	if (pmd_trans_huge(*pmd))
		*pmd = pmd_mkreserve(*pmd);

	return 0;
}
static int bt_init_pte(pte_t *pte, unsigned long addr,
	 unsigned long next, struct mm_walk *walk)
{
	if (pte_none(*pte) || !pte_present(*pte))
		return 0;

	*pte = pte_mkreserve(*pte);

	return 0;
}

static int bt_init_hugetlb_entry(pte_t *ptep, unsigned long hmask,
	     unsigned long addr, unsigned long next,
	     struct mm_walk *walk)
{
	pte_t pte = huge_ptep_get(ptep);

	if (pte_none(pte) || !pte_present(pte))
		return 0;

	//pte = pte_mkreserve(pte); // TODO markm: uncomment
	set_huge_pte_at(walk->mm, addr, ptep, pte);

	return 0;
}

static int bt_init_test_walk(unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	// Skip unmapped regions
	if (!walk->vma)
		return 1;

	// Skip executable regions, since we don't handle instruction TLB misses.
	if (walk->vma->vm_flags & (VM_EXEC | VM_MAYEXEC))
		return 1;

	// TODO: markm: skipping file-backed memory for now...
	if (!vma_is_anonymous(walk->vma))
		return 1;

	return 0;
}

/*
 * This function walks the page table of the process being marked for badger trap
 * This helps in finding all the PTEs that are to be marked as reserved. This is
 * espicially useful to start badger trap on the fly using (2) and (3). If we do not
 * call this function, when starting badger trap for any process, we may miss some TLB
 * misses from being tracked which may not be desireable.
 *
 * [lower, upper] is the virtual address range for which badger trap is turned on.
 *
 * Note: This function takes care of transparent hugepages and hugepages in general.
 *
 * Note: This function acquires and releases mmap_sem.
 */
void badger_trap_init(struct mm_struct *mm, u64 lower, u64 upper)
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

	down_write(&mm->mmap_sem);

	ret = walk_page_range(mm, lower, upper, &ops, NULL);
	BUG_ON(ret);

	up_write(&mm->mmap_sem);
}

void badger_trap_init_all(struct mm_struct *mm)
{
	badger_trap_init(mm, 0, ~0ull);
}
