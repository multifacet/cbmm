/*
 * Stats about the memory management subsystem.
 */

#include <linux/mm_stats.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/cred.h>

#define MM_STATS_INSTR_BUFSIZE 24

struct mm_hist;

static int hist_sprintf(struct file *file, char __user *ubuf,
        size_t count, loff_t *ppos, struct mm_hist *hist);

#define MM_STATS_PROC_CREATE_INT_INNER(type, name, default_val, fmt, extra_code) \
    type name = default_val; \
    static struct proc_dir_entry *name##_ent; \
    \
    static ssize_t name##_read_cb( \
            struct file *file, char __user *ubuf,size_t count, loff_t *ppos) \
    { \
        char buf[MM_STATS_INSTR_BUFSIZE]; \
        int len=0; \
 \
        if(*ppos > 0) \
            return 0; \
 \
        len += sprintf(buf, fmt "\n", name); \
 \
        if(count < len) \
            return 0; \
 \
        if(copy_to_user(ubuf, buf, len)) \
            return -EFAULT; \
 \
        *ppos = len; \
        return len; \
    } \
    \
    static ssize_t name##_write_cb( \
            struct file *file, const char __user *ubuf, size_t len, loff_t *offset) \
    { \
        int num; \
        type val; \
        char input[MM_STATS_INSTR_BUFSIZE]; \
 \
        if(*offset > 0 || len > MM_STATS_INSTR_BUFSIZE) { \
            return -EFAULT; \
        } \
 \
        if(copy_from_user(input, ubuf, len)) { \
            return -EFAULT; \
        } \
 \
        num = sscanf(input, fmt, &val); \
        if(num != 1) { \
            return -EINVAL; \
        } \
 \
        name = val; \
        extra_code \
 \
        printk(KERN_WARNING "mm-econ: %s = " fmt "\n", #name, name); \
 \
        return len; \
    } \
    \
    static struct file_operations name##_ops = \
    { \
        .write = name##_write_cb, \
        .read = name##_read_cb, \
    };

#define MM_STATS_PROC_CREATE_INT(type, name, default_val, fmt) \
    MM_STATS_PROC_CREATE_INT_INNER(type, name, default_val, fmt, { /* nothing */ })

#define MM_STATS_INIT_INT(name) \
    name##_ent = proc_create(#name, 0444, NULL, &name##_ops);

#define MM_STATS_PROC_CREATE_HIST_OUTPUT(name) \
    static struct proc_dir_entry *name##_ent; \
    \
    static ssize_t name##_read_cb( \
            struct file *file, char __user *ubuf,size_t count, loff_t *ppos) \
    { \
        return hist_sprintf(file, ubuf, count, ppos, &name); \
    } \
    \
    static struct file_operations name##_ops = \
    { \
        .read = name##_read_cb, \
    };

#define MM_STATS_INIT_MM_HIST(name) \
    reinit_mm_hist(&name, name##_nbins, name##_min, \
            name##_width, name##_is_exp)

#define MM_STATS_PROC_CREATE_HIST(name) \
    unsigned int name##_nbins; \
    u64 name##_min; \
    u64 name##_width; \
    int name##_is_exp; \
    struct mm_hist name; \
    MM_STATS_PROC_CREATE_INT_INNER(unsigned int, name##_nbins, 20, "%u", \
        { MM_STATS_INIT_MM_HIST(name); }); \
    MM_STATS_PROC_CREATE_INT_INNER(u64, name##_min, 0, "%llu", \
        { MM_STATS_INIT_MM_HIST(name); }); \
    MM_STATS_PROC_CREATE_INT_INNER(u64, name##_width, 1000, "%llu", \
        { MM_STATS_INIT_MM_HIST(name); }); \
    MM_STATS_PROC_CREATE_INT_INNER(int, name##_is_exp, 1, "%d", \
        { MM_STATS_INIT_MM_HIST(name); }); \
    MM_STATS_PROC_CREATE_HIST_OUTPUT(name);

#define MM_STATS_INIT_HIST(name) \
    MM_STATS_INIT_INT(name##_nbins); \
    MM_STATS_INIT_INT(name##_min); \
    MM_STATS_INIT_INT(name##_width); \
    MM_STATS_INIT_INT(name##_is_exp); \
    name##_ent = proc_create(#name, 0444, NULL, &name##_ops); \
    name.bins = NULL; \
    if (MM_STATS_INIT_MM_HIST(name)) { \
        pr_warn("mm-econ: unable to init histogram " #name); \
    }

/*
 * A histogram of u64 values. The minimum and number of bins are adjustable,
 * and there are counters for the number of values that fall outside of the
 * [min, max) range of the histogram. The histogram can also be set to be
 * linear or exponential.
 *
 * If the bins are linear, then bin i contains the frequency of range
 * [min + i*width, min + (i+1)*width).
 *
 * If the bins are exponential, the ith bin contains the frequency of range
 * [min + (2^i)*width, min + (2^(i+1))*width).
 */
struct mm_hist {
    // The number of bins.
    unsigned int n;
    // The smallest value.
    u64 min;
    // The width of a bin.
    u64 width;
    // Are the bin-widths exponentially increasing or linearly increasing?
    bool is_exp;

    // An array of u64 for the data.
    u64 *bins;

    // Frequency of values lower than min or higher than max.
    u64 too_lo_count;
    u64 too_hi_count;
};

static int reinit_mm_hist(struct mm_hist *hist, unsigned int n,
        u64 min, u64 width, bool is_exp) {
    pr_warn("mm-econ: reset mm_hist n=%u min=%llu width=%llu isexp=%d",
            n, min, width, is_exp);

    hist->n = n;
    hist->min = min;
    hist->width = width;
    hist->is_exp = is_exp;
    hist->too_hi_count = 0;
    hist->too_lo_count = 0;

    if (hist->bins) {
        vfree(hist->bins);
    }

    if (hist-> n < 1) {
        pr_warn("mm-econ: adjusting nbins to 1.");
        hist->n = 1;
    }

    hist->bins = (u64 *)vzalloc(n * sizeof(u64));

    if (hist->bins) {
        return 0;
    } else {
        pr_warn("mm-econ: unable to allocate histogram");
        return -ENOMEM;
    }
}

// Returns the bit index of the most-significant bit in val (starting from 0).
static inline int highest_bit(u64 val)
{
    int msb = 0;

    if (val == 0) {
        // There was no set bit. This is an error.
        pr_warn("mm-econ: no MSB, but expected one.");
        return -1;
    }

    if (val & 0xFFFFFFFF00000000) {
        msb += 32;
        val >>= 32;
    }

    if (val & 0xFFFF0000) {
        msb += 16;
        val >>= 16;
    }

    if (val & 0xFF00) {
        msb += 8;
        val >>= 8;
    }

    if (val & 0xF0) {
        msb += 4;
        val >>= 4;
    }

    if (val & 0xC) {
        msb += 2;
        val >>= 2;
    }

    if (val & 0x2) {
        msb += 1;
        val >>= 1;
    }

    return msb;
}

void mm_stats_hist_measure(struct mm_hist *hist, u64 val)
{
    unsigned int bin_idx;

    // Some sanity checking.
    BUG_ON(hist->n == 0);

    if (!hist->bins) {
        pr_warn("mm-econ: no bins allocated.");
        return;
    }

    // Find out if it is too low or too high.
    if (val < hist->min) {
        hist->too_lo_count++;
        return;
    }
    if (hist->is_exp) {
        if (val >= (hist->min + ((1 << (hist->n - 1)) * hist->width))) {
            hist->too_hi_count++;
            return;
        }
    } else {
        if (val >= (hist->min + (hist->n - 1) * hist->width)) {
            hist->too_hi_count++;
            return;
        }
    }

    // If we get here, we know there is a bin for the data. Find out which one.
    if (hist->is_exp) {
        bin_idx = (val - hist->min) / hist->width;
        if (bin_idx > 0) {
            bin_idx = highest_bit(bin_idx) + 1;
        }
    } else {
        bin_idx = (val - hist->min) / hist->width;
    }

    BUG_ON(bin_idx >= hist->n);
    hist->bins[bin_idx]++;
}

/*
 * Reads a histogram and creates the output string to be reported to the user
 */
static int hist_sprintf(struct file *file, char __user *ubuf,
        size_t count, loff_t *ppos, struct mm_hist *hist)
{
        size_t buf_size = min(count, (size_t)((hist->n + 2) * 16 + 1));
        char *buf;
        int len=0;
        int i;

        if(*ppos > 0)
            return 0;

        buf = (char *)vmalloc(buf_size);
        if (!buf) {
            pr_warn("mm-econ: Unable to allocate results string buffer.");
            return -ENOMEM;
        }

        len += sprintf(buf, "%llu %llu ", hist->too_lo_count, hist->too_hi_count);
        for (i = 0; i < hist->n; ++i) {
            len += sprintf(&buf[len], "%llu ", hist->bins[i]);
        }
        buf[len++] = '\0';

        if(count < len) {
            vfree(buf);
            return 0;
        }

        if(copy_to_user(ubuf, buf, len)) {
            vfree(buf);
            return -EFAULT;
        }

        vfree(buf);

        *ppos = len;
        return len;
}

///////////////////////////////////////////////////////////////////////////////
// Implement the pftrace stuff.

// Convert flags to text names for the sake of debugging/printing.
char *mm_stats_pf_flags_names[MM_STATS_NUM_FLAGS] = {
	[MM_STATS_PF_HUGE_PAGE] = "MM_STATS_PF_HUGE_PAGE",
	[MM_STATS_PF_VERY_HUGE_PAGE] = "MM_STATS_PF_VERY_HUGE_PAGE",
	[MM_STATS_PF_BADGER_TRAP] = "MM_STATS_PF_BADGER_TRAP",
        [MM_STATS_PF_WP] = "MM_STATS_PF_WP",
	[MM_STATS_PF_EXEC] = "MM_STATS_PF_EXEC",
	[MM_STATS_PF_NUMA] = "MM_STATS_PF_NUMA",
	[MM_STATS_PF_SWAP] = "MM_STATS_PF_SWAP",
        [MM_STATS_PF_NOT_ANON] = "MM_STATS_PF_NOT_ANON",
	[MM_STATS_PF_NOT_ANON_READ] = "MM_STATS_PF_NOT_ANON_READ",
	[MM_STATS_PF_NOT_ANON_COW] = "MM_STATS_PF_NOT_ANON_COW",
	[MM_STATS_PF_NOT_ANON_SHARED] = "MM_STATS_PF_NOT_ANON_SHARED",
        [MM_STATS_PF_ZERO] = "MM_STATS_PF_ZERO",
	[MM_STATS_PF_HUGE_ALLOC_FAILED] = "MM_STATS_PF_HUGE_ALLOC_FAILED",
        [MM_STATS_PF_HUGE_SPLIT] = "MM_STATS_PF_HUGE_SPLIT",
        [MM_STATS_PF_HUGE_PROMOTION] = "MM_STATS_PF_HUGE_PROMOTION",
	[MM_STATS_PF_HUGE_PROMOTION_FAILED] = "MM_STATS_PF_HUGE_PROMOTION_FAILED",
	[MM_STATS_PF_HUGE_COPY] = "MM_STATS_PF_HUGE_COPY",
	[MM_STATS_PF_CLEARED_MEM] = "MM_STATS_PF_CLEARED_MEM",
	[MM_STATS_PF_ALLOC_FALLBACK] = "MM_STATS_PF_ALLOC_FALLBACK",
        [MM_STATS_PF_ALLOC_PREZEROED] = "MM_STATS_PF_ALLOC_PREZEROED",
        [MM_STATS_PF_ALLOC_NODE_RECLAIM] = "MM_STATS_PF_ALLOC_NODE_RECLAIM",
        [MM_STATS_PF_NEW] = "MM_STATS_PF_NEW",
};

// This is the pftrace file, found at "/pftrace". We also keep track of the
// file offset for writes and the number of writes so far so we can batch
// fsyncing.
#define MM_STATS_PFTRACE_FNAME "/pftrace"
static struct file *pftrace_file = NULL;
static loff_t pftrace_pos = 0;
static long pftrace_nwrites = 0;

// Create /proc/pftrace_enable which enables/disables pftrace.
// 0: off
// !0: on
//
// At the same time, it attempts to open the pftrace file when written to.
static inline int open_pftrace_file(void);
MM_STATS_PROC_CREATE_INT_INNER(int, pftrace_enable, 0, "%d", {
    long err = open_pftrace_file();
    if (err) return err;
})
// Create /proc/pftrace_threshold - the rejection threshold for samples (in cycles).
#define MM_STATS_PFTRACE_DEFAULT_THRESHOLD (100 * 1000)
MM_STATS_PROC_CREATE_INT(u64, pftrace_threshold,
        MM_STATS_PFTRACE_DEFAULT_THRESHOLD, "%llu")
// Keeps count of samples dropped because they occurred in an interrupt context.
MM_STATS_PROC_CREATE_INT(u64, pftrace_discarded_from_interrupt, 0, "%llu")
// Keeps count of samples dropped due to FS errors.
MM_STATS_PROC_CREATE_INT(u64, pftrace_discarded_from_error, 0, "%llu")

// Keep counts of the number of rejected sample for different sets of bitflags.
// This helps us figure out what part of the tail our samples are.
#define REJECTED_HASH_BITS 5
static DEFINE_HASHTABLE(pftrace_rejected_samples, REJECTED_HASH_BITS);

struct rejected_hash_node {
    struct hlist_node node;
    mm_stats_bitflags_t bitflags;
    u64 count;
};

// Output the rejected sample count to a procfs file.
static struct proc_dir_entry *rejected_hash_ent;
static ssize_t rejected_hash_read_cb(
        struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
    ssize_t len = 0;
    int bkt;
    struct rejected_hash_node *node;
    char *buf;

    if(*ppos > 0)
        return 0;

    buf = (char *)vmalloc(count);
    if (!buf) {
        pr_warn("mm_stats: Unable to allocate rejected string buffer.");
        return -ENOMEM;
    }

    hash_for_each(pftrace_rejected_samples, bkt, node, node)
    {
        len += sprintf(&buf[len], "%llx:%llu ",
                node->bitflags, node->count);
    }
    buf[len++] = '\0';

    if(count < len) {
        vfree(buf);
        return 0;
    }

    if(copy_to_user(ubuf, buf, len)) {
        vfree(buf);
        return -EFAULT;
    }

    vfree(buf);

    *ppos = len;
    return len;
}

static struct file_operations rejected_hash_ops =
{
    .read = rejected_hash_read_cb,
};


static inline void rejected_sample(struct mm_stats_pftrace *trace)
{
    struct rejected_hash_node *node = NULL;
    bool found = false;

    // Look for existing entry.
    hash_for_each_possible(pftrace_rejected_samples, node, node, trace->bitflags)
    {
        if (trace->bitflags == node->bitflags) {
            found = true;
            break;
        }
    }

    // If not found, insert.
    if (!found) {
        node = (struct rejected_hash_node *)kmalloc(
                sizeof(struct rejected_hash_node),
                // We pass __GFP_ATOMIC because this may occur in an interrupt
                // context, which doesn't allow sleeping.
                GFP_KERNEL | __GFP_ZERO | __GFP_ATOMIC);
        if (!node) {
            pr_err("mm_stats: unable to alloc rejected_hash_node. skipping.");
            return;
        }

        node->bitflags = trace->bitflags;
        node->count = 0;

        hash_add(pftrace_rejected_samples, &node->node, node->bitflags);
    }

    // Increase the count;
    node->count += 1;
}

static inline int open_pftrace_file(void) {
    struct file *file;
    long err;

    // Don't open multiple times.
    if (likely(pftrace_file != NULL)) return 0;

    // Open the file.
    file = filp_open(MM_STATS_PFTRACE_FNAME,
            O_WRONLY | O_CREAT | O_TRUNC, 0444);
    if (IS_ERR(file)) {
        err = PTR_ERR(file);
        pr_err("mm_stats: Failed to open pftrace file. "
               "errno=%ld current->uid=%u\n",
               err, __kuid_val(current_cred()->uid));
        return err;
    }

    // Successfully opened the file!

    pftrace_file = file;

    pr_warn("mm_stats: Successfully opened %s current->uid=%u\n",
            MM_STATS_PFTRACE_FNAME, __kuid_val(current_cred()->uid));
    return 0;
}

void mm_stats_pftrace_init(struct mm_stats_pftrace *trace)
{
    memset(trace, 0, sizeof(struct mm_stats_pftrace));
}

void mm_stats_pftrace_submit(struct mm_stats_pftrace *trace)
{
    long err;
    ssize_t total_written = 0, written;

    // Check if pftrace is on.
    if (!pftrace_enable) return;

    // Filter out some events.
    // TODO: more complex filter...
    if (trace->end_tsc - trace->start_tsc < pftrace_threshold) {
        rejected_sample(trace);
        return;
    }

    // If we are in an interrupt context, we can't write to a file.
    // TODO: if it turns out to be important we change this to buffer the trace
    //       for latter...
    if (in_interrupt()) {
        pftrace_discarded_from_interrupt += 1;
        return;
    }

    // Make sure the trace file is open.
    err = open_pftrace_file();
    if (err) {
        pr_err_once("mm_stats: pftrace file not open. "
                    "Dropping unrejected samples!");
        pftrace_discarded_from_error += 1;
        return;
    }

    /* for debugging...
    pr_warn("mm_stats: total=%10llu bits=%llx",
            trace->end_tsc - trace->start_tsc,
            trace->bitflags);

    for (i = 0; i < MM_STATS_NUM_FLAGS; ++i) {
        if (mm_stats_test_flag(trace, i)) {
            pr_cont(" %s", mm_stats_pf_flags_names[i]);
        }
    }
    */

    // Write the trace directly to the end of the file.
    while (total_written < sizeof(struct mm_stats_pftrace)) {
        written = kernel_write(pftrace_file, trace,
                sizeof(struct mm_stats_pftrace), &pftrace_pos);
        if (written < 0) {
            pr_err("mm_stats: error writing pftrace: %ld\n", written);
            pftrace_discarded_from_error += 1;
            return;
        }

        total_written += written;
    }

    // Every 1000 writes, flush.
    if (++pftrace_nwrites % 1000 == 0) {
        vfs_fsync(pftrace_file, 0);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Define various stats below.

// Histograms of page fault latency (base page and huge page).
MM_STATS_PROC_CREATE_HIST(mm_base_page_fault_cycles);
MM_STATS_PROC_CREATE_HIST(mm_huge_page_fault_cycles);
// Cycles to allocate a new huge page in the pf handler (pages are never
// promoted in pf handler). This is a subset of the previous histogram. This
// only includes successful operations. Huge zero-page is not included.
MM_STATS_PROC_CREATE_HIST(mm_huge_page_fault_create_new_cycles);
// Time to clear a new huge page. This is a subset of the previous histogram.
MM_STATS_PROC_CREATE_HIST(mm_huge_page_fault_clear_cycles);
// Create a new huge zero page.
MM_STATS_PROC_CREATE_HIST(mm_huge_page_fault_zero_page_cycles);
// Time for a page fault touching a write-protected anon huge page. This
// usually means a COW. There are a few things that can happen here:
// - If nobody else is using the page, we can just make it writable.
// - If there is no backing page, we need to allocate a huge page. Then, we
//   need to clear it.
// - Otherwise, we try to make a private copy of the huge page (COW), which
//   involves copying the entire old huge page.
// - Otherwise, we fall back to splitting the page into base pages.
//
// For now we don't split out all of these possibilities, but it's not hard to
// do so (just a bit of work).
MM_STATS_PROC_CREATE_HIST(mm_huge_page_fault_wp_cycles);
// Time to copy the huge page during a COW clone. This is a subset of the
// previous histogram.
MM_STATS_PROC_CREATE_HIST(mm_huge_page_fault_cow_copy_huge_cycles);

// Histograms of compaction events.
MM_STATS_PROC_CREATE_HIST(mm_direct_compaction_cycles);
MM_STATS_PROC_CREATE_HIST(mm_indirect_compaction_cycles);

// Histograms of reclamation events.
MM_STATS_PROC_CREATE_HIST(mm_direct_reclamation_cycles);

// Histograms of huge page promotion/demotion events.
// Cycles spent by khugepaged to find and promote.
MM_STATS_PROC_CREATE_HIST(mm_huge_page_promotion_scanning_cycles);
// Subset of the above, specifically the work to promote once we have found a
// page. Only includes successful operations.
MM_STATS_PROC_CREATE_HIST(mm_huge_page_promotion_work_cycles);
// Subset of the above, specifically the copying of contents to the new huge
// page. Only includes successful operations.
MM_STATS_PROC_CREATE_HIST(mm_huge_page_promotion_copy_pages_cycles);

// Histograms of process_huge_page, which is used for copying or clearing whole
// huge pages.
MM_STATS_PROC_CREATE_HIST(mm_process_huge_page_cycles);
MM_STATS_PROC_CREATE_HIST(mm_process_huge_page_single_page_cycles);

// Histograms of estimated costs and benefits for mm_econ.
MM_STATS_PROC_CREATE_HIST(mm_econ_cost);
MM_STATS_PROC_CREATE_HIST(mm_econ_benefit);

void mm_stats_init(void)
{
    MM_STATS_INIT_INT(pftrace_enable);
    MM_STATS_INIT_INT(pftrace_threshold);
    MM_STATS_INIT_INT(pftrace_discarded_from_interrupt);
    MM_STATS_INIT_INT(pftrace_discarded_from_error);
    hash_init(pftrace_rejected_samples);
    rejected_hash_ent = proc_create("pftrace_rejected",
            0444, NULL, &rejected_hash_ops);

    MM_STATS_INIT_HIST(mm_base_page_fault_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_fault_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_fault_create_new_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_fault_clear_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_fault_zero_page_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_fault_wp_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_fault_cow_copy_huge_cycles);
    MM_STATS_INIT_HIST(mm_direct_compaction_cycles);
    MM_STATS_INIT_HIST(mm_indirect_compaction_cycles);
    MM_STATS_INIT_HIST(mm_direct_reclamation_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_promotion_scanning_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_promotion_work_cycles);
    MM_STATS_INIT_HIST(mm_huge_page_promotion_copy_pages_cycles);
    MM_STATS_INIT_HIST(mm_process_huge_page_cycles);
    MM_STATS_INIT_HIST(mm_process_huge_page_single_page_cycles);

    MM_STATS_INIT_HIST(mm_econ_cost);
    MM_STATS_INIT_HIST(mm_econ_benefit);
}
