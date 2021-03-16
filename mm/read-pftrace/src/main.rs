//! Reads traces in binary form produced by the pftrace mechanism.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::arg_enum;

use hdrhistogram::Histogram;

use structopt::StructOpt;

type CategorizedData = BTreeMap<MMStatsBitflags, Histogram<u64>>;

/// Reads pftrace output and dumps useful numbers for plotting.
#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "read-pftrace")]
struct Config {
    /// The pftrace output file.
    pftrace_file: PathBuf,

    /// The file with counts of rejected pftrace samples.
    #[structopt(requires("rejection_threshold"))]
    rejected_file: Option<PathBuf>,

    /// The threshold below which samples are rejected.
    #[structopt(requires("rejected_file"))]
    rejection_threshold: Option<u64>,

    /// Output PDF, rather than CDF.
    #[structopt(long)]
    pdf: bool,

    /// Which data to output.
    #[structopt(
        long,
        possible_values = &DataMode::variants(),
        case_insensitive = true,
        default_value = "duration",
    )]
    data_mode: DataMode,
}

arg_enum! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum DataMode {
        Duration,
        AllocTotal,
        AllocClearing,
        PrepTotal,
    }
}

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
    alloc_zeroing_duration: u64,

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
        MM_STATS_PF_CLEARED_MEM,
        MM_STATS_PF_ALLOC_FALLBACK,

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
    let config = Config::from_args();

    let rejected = config.rejected_file.as_ref().map(|rejected_fname| {
        let rejected = std::fs::read_to_string(rejected_fname)
            .expect("Unable to read rejection file")
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

        (rejected, config.rejection_threshold.unwrap())
    });
    let buf = std::fs::read(&config.pftrace_file)?;
    let buf: &[MMStatsPftrace] = unsafe {
        assert!(buf.len() % std::mem::size_of::<MMStatsPftrace>() == 0);
        let (pre, aligned, post) = buf.as_slice().align_to();
        assert_eq!(pre.len(), 0);
        assert_eq!(post.len(), 0);
        aligned
    };

    if config.pdf {
        generate_pdfs(&config, &buf, rejected.as_ref());
    } else {
        generate_cdfs(&config, &buf, rejected.as_ref());
    }

    Ok(())
}

fn categorize(
    config: &Config,
    buf: &[MMStatsPftrace],
    rejected: Option<&(Vec<(MMStatsBitflags, u64)>, u64)>,
) -> CategorizedData {
    // We categorize events by their bitflags.
    let mut categorized: CategorizedData = BTreeMap::new();
    for trace in buf {
        let data = match config.data_mode {
            DataMode::Duration => trace.end_tsc - trace.start_tsc,
            DataMode::AllocTotal => trace.alloc_end_tsc - trace.alloc_start_tsc,
            DataMode::AllocClearing => trace.alloc_zeroing_duration,
            DataMode::PrepTotal => trace.prep_end_tsc - trace.prep_start_tsc,
        };

        categorized
            .entry(trace.bitflags)
            .or_insert(Histogram::new(5).unwrap())
            .record(data)
            .unwrap();
    }

    // Adjust for the rejected samples.
    if let Some((rejected, threshold)) = rejected {
        for (bitflags, rejected_count) in rejected {
            categorized
                .entry(*bitflags)
                .or_insert(Histogram::new(5).unwrap())
                .record_n(*threshold, *rejected_count)
                .unwrap();
        }
    }

    categorized
}

fn print_quartiles(categorized: &CategorizedData) {
    let mut total = 0;

    let mut keys = categorized.keys().collect::<Vec<_>>();
    keys.sort_by_key(|flags| categorized.get(flags).unwrap().len());
    for flags in keys.iter() {
        let hist = categorized.get(flags).unwrap();
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

        total += hist.len();
    }

    println!("Total: {}", total);
}

fn generate_cdfs(
    config: &Config,
    buf: &[MMStatsPftrace],
    rejected: Option<&(Vec<(MMStatsBitflags, u64)>, u64)>,
) {
    let categorized = categorize(config, buf, rejected);

    // Print output.
    print_quartiles(&categorized);

    // Print for plotting...
    //
    // For the sake of plotting, we sort by the number of events.
    let mut keys = categorized.keys().collect::<Vec<_>>();
    keys.sort_by_key(|flags| categorized.get(flags).unwrap().len());
    for flags in keys.iter() {
        let hist = categorized.get(flags).unwrap();
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

fn generate_pdfs(
    config: &Config,
    buf: &[MMStatsPftrace],
    rejected: Option<&(Vec<(MMStatsBitflags, u64)>, u64)>,
) {
    let categorized = categorize(config, buf, rejected);

    // Print output.
    print_quartiles(&categorized);

    // Print for plotting...
    //
    // For the sake of plotting, we sort by the number of events.
    let minvalue = categorized
        .values()
        .map(|h| h.min())
        .min()
        .expect("No min?");
    let mut keys = categorized.keys().collect::<Vec<_>>();
    keys.sort_by_key(|flags| categorized.get(flags).unwrap().len());
    for flags in keys.iter() {
        let hist = categorized.get(flags).unwrap();
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

        const PDF_STEP_SIZE: u64 = 2;
        let start = if let Some((_, threshold)) = rejected {
            *threshold
        } else {
            minvalue
        };
        let mut min = hist.lowest_equivalent(start);
        for i in 0.. {
            let max = hist.highest_equivalent(min + PDF_STEP_SIZE.pow(i));
            print!(" {}:{}", max, hist.count_between(min, max));

            if max > hist.max() {
                break;
            } else {
                min = max;
            }
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
