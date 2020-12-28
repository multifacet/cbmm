#ifndef _LINUX_BADGER_TRAP_H
#define _LINUX_BADGER_TRAP_H

#include <linux/mm_types.h>

#include <asm/pgtable_types.h>

#define MAX_NAME_LEN	16

extern char badger_trap_process[CONFIG_NR_CPUS][MAX_NAME_LEN];

void silence(void);
bool is_badger_trap_process(const char* proc_name);
bool is_badger_trap_enabled(const struct mm_struct *mm, u64 address);
inline pte_t pte_mkreserve(pte_t pte);
inline pte_t pte_unreserve(pte_t pte);
inline int is_pte_reserved(pte_t pte);
inline pmd_t pmd_mkreserve(pmd_t pmd);
inline pmd_t pmd_unreserve(pmd_t pmd);
inline int is_pmd_reserved(pmd_t pmd);
inline pud_t pud_mkreserve(pud_t pud);
inline pud_t pud_unreserve(pud_t pud);
inline int is_pud_reserved(pud_t pud);
void badger_trap_walk(struct mm_struct *mm, u64 lower, u64 upper, bool init);
void print_badger_trap_stats(const struct mm_struct *mm);

#endif /* _LINUX_BADGER_TRAP_H */
