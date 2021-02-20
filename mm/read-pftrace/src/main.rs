//! Reads traces in binary form produced by the pftrace mechanism.

/// ```c
/// typedef u64 mm_stats_bitflags_t;
/// ```
type MMStatsBitflags = u64;

/// ```c
/// struct mm_stats_pftrace {
/// 	// A bunch of bitflags indicating things that happened during this #PF.
/// 	// See `mm_econ_flags` for more info.
/// 	mm_stats_bitflags_t bitflags;
///
/// 	// The start and end TSC of the #PF.
/// 	u64 start_tsc;
/// 	u64 end_tsc;
///
/// 	// Timestamps at which the #PF did the following:
/// 	u64 alloc_start_tsc; // started allocating memory
/// 	u64 alloc_end_tsc;   // finished allocating memory (or OOMed)
///
/// 	u64 prep_start_tsc;  // started preparing the alloced mem
/// 	u64 prep_end_tsc;    // finished ...
/// };
/// ```
#[repr(C)]
struct MMStatsPftrace {
    bitflags: MMStatsBitflags,

    start_tsc: u64,
    end_tsc: u64,

    alloc_start_tsc: u64,
    alloc_end_tsc: u64,

    prep_start_tsc: u64,
    prep_end_tsc: u64,
}

/// A bunch of bit flags that indicate things that could happen during a #PF.
/// ```c
/// enum mm_stats_pf_flags {
/// 	// Set: a huge page was allocated/promoted/mapped.
/// 	// Clear: a base page was allocated/promoted/mapped.
/// 	MM_STATS_PF_HUGE_PAGE, // 2MB
/// 	MM_STATS_PF_VERY_HUGE_PAGE, // 1GB -- should never happen
///
/// 	// Set: this fault was a BadgerTrap fault.
/// 	MM_STATS_PF_BADGER_TRAP,
///
/// 	// Set: this fault was a CoW page.
/// 	MM_STATS_PF_COW,
///
/// 	// Set: this fault was a "NUMA hinting fault", possibly with a migration.
/// 	MM_STATS_PF_NUMA,
///
/// 	// Set: this fault required a swap-in.
/// 	MM_STATS_PF_SWAP,
///
/// 	// Set: this fault was not anonymous (usually this means it was a
/// 	// file-backed memory region).
/// 	MM_STATS_PF_NOT_ANON,
///
/// 	// Set: attempted and failed to allocate a 2MB page.
/// 	MM_STATS_PF_HUGE_ALLOC_FAILED, // TODO(markm): instrument this everywhere
/// 	// TODO(markm): also want to instrument ZERO_PAGE mapping, zeroing out
/// 	// a page, copying a page, promoting vs creating, reclaim/compaction...
///
/// 	// NOTE: must be the last value in the enum... not actually a flag.
/// 	MM_STATS_NUM_FLAGS,
/// };
/// ```
#[repr(u8)]
enum MMStatsPftraceFlags {
    MM_STATS_PF_HUGE_PAGE,
    MM_STATS_PF_VERY_HUGE_PAGE,
    MM_STATS_PF_BADGER_TRAP,
    MM_STATS_PF_COW,
    MM_STATS_PF_NUMA,
    MM_STATS_PF_SWAP,
    MM_STATS_PF_NOT_ANON,
    MM_STATS_PF_ZERO,
    MM_STATS_PF_HUGE_ALLOC_FAILED,
    MM_STATS_PF_HUGE_SPLIT,
    MM_STATS_PF_HUGE_PROMOTION,
    MM_STATS_PF_HUGE_PROMOTION_FAILED,
    MM_STATS_PF_HUGE_COPY,
    MM_STATS_PF_HUGE_ZEROED,

    MM_STATS_NUM_FLAGS,
}

fn main() -> std::io::Result<()> {
    let fname = std::env::args().skip(1).next().expect("Expected file name");
    let buf = std::fs::read(fname)?;
    let buf: &[MMStatsPftrace] = unsafe {
        assert!(buf.len() % std::mem::size_of::<MMStatsPftrace>() == 0);
        let (pre, aligned, post) = buf.as_slice().align_to();
        assert_eq!(pre.len(), 0);
        assert_eq!(post.len(), 0);
        aligned
    };

    do_work(&buf);

    Ok(())
}

fn do_work(buf: &[MMStatsPftrace]) {
    let mut discarded = 0;

    for trace in buf {
        // Sanity checking...
        if trace.end_tsc <= trace.start_tsc {
            discarded += 1;
            continue;
        }

        println!(
            "total={:10} bits={:X}",
            trace.end_tsc - trace.start_tsc,
            trace.bitflags
        );
    }

    println!("------\nTotal: {}\nDiscarded: {}", buf.len(), discarded);
}
