//! Reads traces in binary form produced by the pftrace mechanism.

use std::collections::BTreeMap;

/// ```c
/// typedef u64 mm_stats_bitflags_t;
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
struct MMStatsBitflags(u64);

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

macro_rules! with_stringify {
    (enum $name:ident { $($variant:ident),+ $(,)? }) => {
        #[allow(non_camel_case_types, dead_code)]
        #[repr(u8)]
        #[derive(Debug, Clone, Copy)]
        enum $name { $($variant),+ }

        impl $name {
            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        $name :: $variant => stringify!($variant)
                    ),+
                }
            }
        }
    };
}

// A bunch of bit flags that indicate things that could happen during a #PF.
// ```c
// enum mm_stats_pf_flags {
// 	// Set: a huge page was allocated/promoted/mapped.
// 	// Clear: a base page was allocated/promoted/mapped.
// 	MM_STATS_PF_HUGE_PAGE, // 2MB
// 	MM_STATS_PF_VERY_HUGE_PAGE, // 1GB -- should never happen
//
// 	// Set: this fault was a BadgerTrap fault.
// 	MM_STATS_PF_BADGER_TRAP,
//
// 	// Set: this fault was a CoW page.
// 	MM_STATS_PF_COW,
//
// 	// Set: this fault was a "NUMA hinting fault", possibly with a migration.
// 	MM_STATS_PF_NUMA,
//
// 	// Set: this fault required a swap-in.
// 	MM_STATS_PF_SWAP,
//
// 	// Set: this fault was not anonymous (usually this means it was a
// 	// file-backed memory region).
// 	MM_STATS_PF_NOT_ANON,
//
// 	// Set: attempted and failed to allocate a 2MB page.
// 	MM_STATS_PF_HUGE_ALLOC_FAILED, // TODO(markm): instrument this everywhere
// 	// TODO(markm): also want to instrument ZERO_PAGE mapping, zeroing out
// 	// a page, copying a page, promoting vs creating, reclaim/compaction...
//
// 	// NOTE: must be the last value in the enum... not actually a flag.
// 	MM_STATS_NUM_FLAGS,
// };
// ```
with_stringify! {
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
}

impl MMStatsPftraceFlags {
    pub fn from_u8(n: u8) -> Self {
        if n <= (MMStatsPftraceFlags::MM_STATS_NUM_FLAGS as u8) {
            unsafe { std::mem::transmute(n) }
        } else {
            panic!("Invalid flag: {:X}", n);
        }
    }
}

impl MMStatsBitflags {
    pub fn flags(self) -> Vec<MMStatsPftraceFlags> {
        let mut vec = Vec::new();
        for i in 0..(MMStatsPftraceFlags::MM_STATS_NUM_FLAGS as u8) {
            if self.0 & (1 << i) != 0 {
                vec.push(MMStatsPftraceFlags::from_u8(i));
            }
        }
        vec
    }
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let pftrace_fname = args.next().expect("Expected file name");
    let rejected_fname = args.next().expect("Expected file name");
    let threshold = args
        .next()
        .expect("Expected threshold")
        .parse::<u64>()
        .expect("not an integer");
    let buf = std::fs::read(pftrace_fname)?;
    let buf: &[MMStatsPftrace] = unsafe {
        assert!(buf.len() % std::mem::size_of::<MMStatsPftrace>() == 0);
        let (pre, aligned, post) = buf.as_slice().align_to();
        assert_eq!(pre.len(), 0);
        assert_eq!(post.len(), 0);
        aligned
    };

    let rejected = std::fs::read_to_string(rejected_fname)?
        .trim_end_matches('\u{0}')
        .trim()
        .split(' ')
        .map(|part| {
            let mut iter = part.split(':');
            (iter.next().unwrap(), iter.next().unwrap())
        })
        .map(|(bits, count)| {
            (
                MMStatsBitflags(bits.parse::<u64>().expect("not an integer")),
                count.parse::<u64>().expect("not an integer"),
            )
        })
        .collect::<Vec<_>>();

    do_work(&buf, &rejected, threshold);

    Ok(())
}

fn do_work(buf: &[MMStatsPftrace], rejected: &[(MMStatsBitflags, u64)], threshold: u64) {
    use hdrhistogram::Histogram;

    // We categorize events by their bitflags.
    let mut categorized: BTreeMap<_, Histogram<u64>> = BTreeMap::new();
    for trace in buf {
        categorized
            .entry(trace.bitflags)
            .or_insert(Histogram::new(5).unwrap())
            .record(trace.end_tsc - trace.start_tsc)
            .unwrap();
    }

    // Adjust for the rejected samples.
    for (bitflags, rejected_count) in rejected {
        categorized
            .entry(*bitflags)
            .or_insert(Histogram::new(5).unwrap())
            .record_n(threshold, *rejected_count)
            .unwrap();
    }

    // Print output.
    for (flags, hist) in categorized.iter() {
        println!(
            "{:4X}: {}",
            flags.0,
            flags
                .flags()
                .iter()
                .map(MMStatsPftraceFlags::name)
                .collect::<Vec<_>>()
                .join(" ")
        );

        const QUANTILES: &[f64] = &[0.0, 0.25, 0.5, 0.75, 1.0];

        print!("\t");
        for (p, v) in QUANTILES.iter().map(|p| (*p, hist.value_at_quantile(*p))) {
            print!(" P{:.0}={}", p * 100.0, v);
        }
        println!(" N={}", hist.len());
    }

    println!("------\nTotal: {}", buf.len());

    // Print for plotting...
    for (flags, hist) in categorized.iter() {
        let flags = {
            let flags = flags
                .flags()
                .iter()
                .map(MMStatsPftraceFlags::name)
                .collect::<Vec<_>>()
                .join(",");
            if flags.is_empty() {
                "none".into()
            } else {
                flags
            }
        };
        print!(" {}({})", flags, hist.len());
        for v in (0..=100).map(|p| hist.value_at_quantile((p as f64) / 100.)) {
            print!(" {}", v);
        }
    }

    /*
    for trace in buf {
        println!(
            "total={:10} bits={:4X} {}",
            trace.end_tsc - trace.start_tsc,
            trace.bitflags.0,
            trace
                .bitflags
                .flags()
                .iter()
                .map(MMStatsPftraceFlags::name)
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    */
}
