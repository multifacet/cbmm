//! Reads traces in binary form produced by the pftrace mechanism.

use std::collections::{BTreeMap, HashSet};
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
    #[structopt(requires("rejection-threshold"))]
    rejected_file: Option<PathBuf>,

    /// The threshold below which samples are rejected.
    #[structopt(requires("rejected-file"))]
    rejection_threshold: Option<u64>,

    /// Output PDF, rather than CDF.
    #[structopt(long)]
    pdf: bool,

    /// Combine all categories in the output, generating the overall distribution of all page
    /// faults, rather than individual categories.
    #[structopt(long)]
    combined: bool,

    /// Output tail latency based on the given maximum number of 9's. That is, given a value of 5,
    /// we output 100 points, with exponentially more density as we go from 0 to 99.999 (i.e., 5
    /// 9's).
    #[structopt(long, conflicts_with("percentile"), conflicts_with("pdf"))]
    tail: Option<usize>,

    /// Report the number of events at each percentile, too.
    #[structopt(long, conflicts_with("percentile"), conflicts_with("pdf"))]
    freq: bool,

    /// Which data to output.
    #[structopt(
        long,
        possible_values = &DataMode::variants(),
        case_insensitive = true,
        default_value = "duration",
    )]
    data_mode: DataMode,

    /// Only output 1 line of data for use with a plotting script.
    #[structopt(long)]
    cli_only: bool,

    /// If passed, creates an "Other" category and collects all bitflags whose frequency is
    /// less than or equal to the given threshold. Otherwise, all categories are listed, even
    /// if they only have one recorded sample. Passing this flag increases the time to process
    /// the trace.
    #[structopt(long, conflicts_with("combined"))]
    other_category: Option<u64>,

    /// Exclude categories containing the given string from the trace before doing any other
    /// processing. Note that for PDFs, this will change the proportion of events.
    #[structopt(long)]
    exclude: Vec<String>,

    /// Instead of printing a distribution, print the given percentile for each of set of bitflags.
    #[structopt(long)]
    percentile: Option<f64>,
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

with_stringify! {
    enum MMStatsPftraceFlags {
        HUGE_PAGE,
        VERY_HUGE_PAGE,
        BADGER_TRAP,
        WP,
        EXEC,
        NUMA,
        SWAP,
        NOT_ANON,
        NOT_ANON_READ,
        NOT_ANON_COW,
        NOT_ANON_SHARED,
        ZERO,
        HUGE_ALLOC_FAILED,
        HUGE_SPLIT,
        HUGE_PROMOTION,
        HUGE_PROMOTION_FAILED,
        HUGE_COPY,
        CLEARED_MEM,
        ALLOC_FALLBACK,
        ALLOC_FALLBACK_RETRY,
        ALLOC_FALLBACK_RECLAIM,
        ALLOC_FALLBACK_COMPACT,
        ALLOC_PREZEROED,
        ALLOC_NODE_RECLAIM,

        OTHER, // A hack -- shouldn't actually be in use...
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

    pub fn from_hex_str(s: &str) -> Result<Self, std::num::ParseIntError> {
        u64::from_str_radix(s, 16).map(|f| Self(f))
    }

    pub fn name(self) -> String {
        let name = self
            .flags()
            .iter()
            .map(MMStatsPftraceFlags::name)
            .collect::<Vec<_>>()
            .join(",");

        if name.is_empty() {
            "none".to_string()
        } else {
            name
        }
    }
}

fn main() -> std::io::Result<()> {
    let config = Config::from_args();

    let excluded_bitmask = compute_excluded_bitmask(&config.exclude);

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
                    MMStatsBitflags::from_hex_str(bits).expect("not an integer"),
                    count.parse::<u64>().expect("not an integer"),
                )
            })
            .filter(|(bits, _)| bits.0 & excluded_bitmask.0 == 0)
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

    if config.percentile.is_some() {
        generate_percentiles(&config, &buf, rejected.as_ref(), excluded_bitmask);
    } else if config.pdf {
        generate_pdfs(&config, &buf, rejected.as_ref(), excluded_bitmask);
    } else {
        generate_cdfs(&config, &buf, rejected.as_ref(), excluded_bitmask);
    }

    Ok(())
}

fn compute_excluded_bitmask(exclude: &[String]) -> MMStatsBitflags {
    let mut x = 0u64;

    for i in 0..(MMStatsPftraceFlags::MM_STATS_NUM_FLAGS as u8) {
        if exclude
            .iter()
            .any(|ex| MMStatsPftraceFlags::from_u8(i).name().contains(ex))
        {
            x |= 1 << i;
        }
    }

    MMStatsBitflags(x)
}

fn categorize(
    config: &Config,
    buf: &[MMStatsPftrace],
    rejected: Option<&(Vec<(MMStatsBitflags, u64)>, u64)>,
    excluded_bitmask: MMStatsBitflags,
) -> CategorizedData {
    // We categorize events by their bitflags.
    let mut categorized: CategorizedData = BTreeMap::new();
    for trace in buf
        .iter()
        .filter(|t| t.bitflags.0 & excluded_bitmask.0 == 0)
    {
        let data = match config.data_mode {
            DataMode::Duration => trace.end_tsc - trace.start_tsc,
            DataMode::AllocTotal => trace.alloc_end_tsc - trace.alloc_start_tsc,
            DataMode::AllocClearing => trace.alloc_zeroing_duration,
            DataMode::PrepTotal => trace.prep_end_tsc - trace.prep_start_tsc,
        };

        let bitflags = if config.combined {
            MMStatsBitflags(0)
        } else {
            trace.bitflags
        };

        categorized
            .entry(bitflags)
            .or_insert(Histogram::new(5).unwrap())
            .record(data)
            .unwrap();
    }

    // Adjust for the rejected samples.
    if let Some((rejected, threshold)) = rejected {
        for (bitflags, rejected_count) in rejected {
            let flags = if config.combined {
                MMStatsBitflags(0)
            } else {
                *bitflags
            };

            categorized
                .entry(flags)
                .or_insert(Histogram::new(5).unwrap())
                .record_n(*threshold, *rejected_count)
                .unwrap();
        }
    }

    // Create "Other" category if needed.
    if let Some(threshold) = config.other_category {
        // Figure out which categories to collect under "Other".
        let cats = categorized
            .iter()
            .filter(|(_, hist)| hist.len() <= threshold)
            .map(|(cat, _)| *cat)
            .collect::<HashSet<_>>();

        // Remove categories.
        for cat in cats.iter() {
            categorized.remove(&cat);
        }

        // Create the new histogram.
        let mut other_hist: Histogram<u64> = Histogram::new(5).unwrap();

        for trace in buf
            .iter()
            .filter(|t| t.bitflags.0 & excluded_bitmask.0 == 0)
            .filter(|trace| cats.contains(&trace.bitflags))
        {
            let data = match config.data_mode {
                DataMode::Duration => trace.end_tsc - trace.start_tsc,
                DataMode::AllocTotal => trace.alloc_end_tsc - trace.alloc_start_tsc,
                DataMode::AllocClearing => trace.alloc_zeroing_duration,
                DataMode::PrepTotal => trace.prep_end_tsc - trace.prep_start_tsc,
            };

            other_hist.record(data).unwrap();
        }

        // Re-adjust
        if let Some((rejected, threshold)) = rejected {
            for (bitflags, rejected_count) in rejected {
                if cats.contains(&bitflags) {
                    other_hist.record_n(*threshold, *rejected_count).unwrap();
                }
            }
        }

        if !other_hist.is_empty() {
            categorized.insert(
                MMStatsBitflags(1u64 << (MMStatsPftraceFlags::OTHER as u64)),
                other_hist,
            );
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
        println!("{:4X}: {}", flags.0, flags.name());

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

fn generate_percentiles(
    config: &Config,
    buf: &[MMStatsPftrace],
    rejected: Option<&(Vec<(MMStatsBitflags, u64)>, u64)>,
    excluded_bitmask: MMStatsBitflags,
) -> () {
    let categorized = categorize(config, buf, rejected, excluded_bitmask);
    let p = config.percentile.unwrap() / 100.0;

    let mut keys = categorized.keys().collect::<Vec<_>>();
    keys.sort_by_key(|flags| categorized.get(flags).unwrap().len());
    for flags in keys.iter() {
        let hist = categorized.get(flags).unwrap();
        print!(
            "{}({}):{} ",
            flags.name(),
            hist.len(),
            hist.value_at_quantile(p)
        );
    }
    println!();
}

/// Generate a list of 100 percentiles to compute. If we are doing a tail latency plot, we want to
/// exponentially be more dense at the tail. Otherwise, we just use uniform density.
fn get_points(config: &Config) -> Box<dyn Iterator<Item = f64>> {
    if let Some(nines) = config.tail {
        let nines = nines as f64;
        // If we are going from 0 to `nines` 9's, then the nth "step" is determined by this
        // function: `p = 100 - 10^(2-n)`. For example:
        //
        //       n     p
        //       0     0
        //       1     90
        //       2     99
        //       3     99.9
        //       4     99.99
        //       5     99.999
        //      ...    ...
        // `nines`     99.9...9  <- `nines` 9's
        //
        // We want to find 100 points in this function, with denser points closer to the tail. To
        // do this, we will first generate 100 linearly spaced points from 0 to `nines`
        // (inclusive). Then, we will map them with the above function.
        Box::new(
            (0..=100)
                .map(|n| n as f64)
                // scale down to `[0, nines]`
                .map(move |n| n * nines / 100.)
                // map into log space
                .map(|n| 100. - 10f64.powf(2. - n))
                // scale down to `[0, 1)` (i.e., not a percent anymore)
                .map(|p| p / 100.),
        )
    } else {
        Box::new((0..=100).map(|p| p as f64).map(|p| p / 100.))
    }
}

fn generate_cdfs(
    config: &Config,
    buf: &[MMStatsPftrace],
    rejected: Option<&(Vec<(MMStatsBitflags, u64)>, u64)>,
    excluded_bitmask: MMStatsBitflags,
) {
    let categorized = categorize(config, buf, rejected, excluded_bitmask);

    // Print output.
    if !config.cli_only {
        print_quartiles(&categorized);
    }

    // Print for plotting...
    //
    // For the sake of plotting, we sort by the number of events.
    let mut keys = categorized.keys().collect::<Vec<_>>();
    keys.sort_by_key(|flags| categorized.get(flags).unwrap().len());
    for flags in keys.iter() {
        let hist = categorized.get(flags).unwrap();
        print!(" {}({})", flags.name(), hist.len());
        for v in get_points(&config).map(|p| hist.value_at_quantile(p)) {
            if config.freq {
                print!(" {},{}", v, hist.count_between(0, v));
            } else {
                print!(" {}", v);
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
                .name()
        );
    }
    */
}

fn generate_pdfs(
    config: &Config,
    buf: &[MMStatsPftrace],
    rejected: Option<&(Vec<(MMStatsBitflags, u64)>, u64)>,
    excluded_bitmask: MMStatsBitflags,
) {
    let categorized = categorize(config, buf, rejected, excluded_bitmask);

    // Print output.
    if !config.cli_only {
        print_quartiles(&categorized);
    }

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
        print!(" {}({})", flags.name(), hist.len());

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
                .name()
        );
    }
    */
}
