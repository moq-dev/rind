//! dudect's leak test: Reparaz, Balasch, and Verbauwhede, "Dude, is my code
//! constant time?" (DATE 2017), following its reference implementation,
//! <https://github.com/oreparaz/dudect/blob/master/src/dudect.h>.
//!
//! An operation is timed on inputs of two classes, in random order, and
//! Welch's t-test compares the two classes' times: once raw, once below each
//! of 100 percentile cutoffs, which drop the long tail that interrupts add,
//! and once on the squared distance from the class mean, which catches a
//! difference in spread rather than in mean.

use std::hint::black_box;
use std::time::Instant;

/// dudect.h's `t_threshold_moderate`: a larger |t| is "probably not constant
/// time".
pub const THRESHOLD: f64 = 10.0;

/// dudect.h's `enough_measurements`: a test with fewer gives no verdict.
const ENOUGH: f64 = 10_000.0;

/// The cropped tests, as in dudect.h.
const CROPS: usize = 100;

/// The fewest timer ticks one measurement may span. An operation shorter than
/// this is repeated, since a coarse counter (24 MHz on Apple's cores) would
/// otherwise round most of its times to the same few ticks.
const MIN_TICKS: u64 = 200;

pub struct Config {
    /// How long each case measures for, once it has [`ENOUGH`] measurements
    /// in every test it reports.
    pub seconds: f64,
}

/// One case's result.
pub struct Report {
    /// Measurements in the raw test.
    pub measurements: usize,
    /// Calls of the operation each measurement times.
    pub reps: u32,
    /// The test with the largest |t|.
    pub test: Test,
    /// Its t statistic: positive when the fixed class is slower.
    pub t: f64,
    /// The difference in mean ticks per call that test saw, fixed minus random.
    pub delta: f64,
}

impl Report {
    pub fn leaks(&self) -> bool {
        self.t.abs() > THRESHOLD
    }
}

#[derive(Clone, Copy)]
pub enum Test {
    Raw,
    /// Only times below the given percentile of the first batch.
    Cropped(f64),
    SecondOrder,
}

impl std::fmt::Display for Test {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => f.write_str("raw"),
            Self::Cropped(p) => write!(f, "below p{:.1}", p * 100.0),
            Self::SecondOrder => f.write_str("second order"),
        }
    }
}

/// The two classes of input: `[fixed, random]`, each a power of two in
/// length. The fixed class holds one secret, as many times as the random
/// class holds secrets.
pub type Classes<T> = [Vec<T>; 2];

/// Builds [`Classes`] of `len` values each.
pub fn classes<T>(
    len: usize,
    mut fixed: impl FnMut() -> T,
    random: impl FnMut() -> T,
) -> Classes<T> {
    assert!(len.is_power_of_two());
    [
        (0..len).map(|_| fixed()).collect(),
        std::iter::repeat_with(random).take(len).collect(),
    ]
}

/// Times `op` on copies of inputs drawn from `classes` at random, until
/// `config`'s budget is spent.
pub fn measure<T: Clone, R>(config: &Config, classes: &Classes<T>, op: impl Fn(&T) -> R) -> Report {
    measure_built(config, classes, T::clone, op)
}

/// Times `op` on what `build` makes from inputs drawn from `classes` at
/// random, until `config`'s budget is spent.
///
/// As in dudect.h, each measurement gets an input of its own: every batch
/// builds its inputs in the random order of their classes, then times them
/// in that order. Reusing a few values per class instead would give each
/// class the costs of its values' addresses, from the cache sets and the
/// store-to-load aliasing they fall in, which never average out.
pub fn measure_built<S, T, R>(
    config: &Config,
    classes: &Classes<S>,
    build: impl Fn(&S) -> T,
    op: impl Fn(&T) -> R,
) -> Report {
    let len = classes[0].len();
    assert!(len.is_power_of_two() && classes[1].len() == len);
    let mask = len - 1;
    let draw = |draws: &mut Vec<u8>, count: usize| -> (Vec<T>, Vec<u8>) {
        draws.resize(count * 4, 0);
        rind::rand::fill(draws).expect("system random source");
        draws
            .as_chunks::<4>()
            .0
            .iter()
            .map(|draw| {
                let draw = u32::from_le_bytes(*draw) as usize;
                let c = draw & 1;
                (build(&classes[c][(draw >> 1) & mask]), c as u8)
            })
            .unzip()
    };
    let mut draws = Vec::new();

    // Warm up, and repeat a call that spans too few ticks.
    let (inputs, _) = draw(&mut draws, 200);
    let mut warm: Vec<u64> = inputs
        .iter()
        .map(|input| time(1, || op(black_box(input))))
        .collect();
    drop(inputs);
    warm.sort_unstable();
    let median = warm[warm.len() / 2].max(1);
    let reps = MIN_TICKS.div_ceil(median).next_power_of_two();

    // About a quarter second of measurements a batch, within 64 MiB of
    // inputs: the first batch sets the crop cutoffs.
    let per_second = ticks_per_second();
    let most = (64 << 20) / size_of::<T>().max(1);
    let batch = ((per_second / 4) / (median * reps)).clamp(1_000, 20_000) as usize;
    let batch = batch.min(most).max(1_000);

    let mut stats: Option<Stats> = None;
    let start = Instant::now();
    loop {
        let (inputs, class) = draw(&mut draws, batch);
        let times: Vec<u64> = inputs
            .iter()
            .map(|input| time(reps, || op(black_box(input))))
            .collect();
        drop(inputs);

        match &mut stats {
            None => stats = Some(Stats::new(&times)),
            Some(stats) => {
                for (&time, &c) in times.iter().zip(&class) {
                    stats.push(time as f64, c as usize);
                }
                let enough = stats.tests.last().unwrap().len() > ENOUGH;
                if enough && start.elapsed().as_secs_f64() >= config.seconds {
                    return stats.report(reps as u32);
                }
            }
        }
    }
}

/// The ticks `reps` calls of `op` take.
#[inline(always)]
fn time<R>(reps: u64, op: impl Fn() -> R) -> u64 {
    let begin = ticks();
    for _ in 0..reps {
        black_box(op());
    }
    ticks().wrapping_sub(begin)
}

/// Reads the CPU's counter after every earlier instruction completes, and
/// before any later one starts.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn ticks() -> u64 {
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    // `_rdtsc` is safe from Rust 1.94 but `unsafe` on the 1.90 MSRV.
    #[allow(unused_unsafe)]
    // SAFETY: every x86_64 CPU has SSE2, so LFENCE, and RDTSC.
    unsafe {
        _mm_lfence();
        let t = _rdtsc();
        _mm_lfence();
        t
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn ticks() -> u64 {
    let t: u64;
    // SAFETY: Linux, macOS, and Windows let user space read the virtual
    // counter.
    unsafe {
        std::arch::asm!(
            "isb",
            "mrs {t}, cntvct_el0",
            "isb",
            t = out(reg) t,
            options(nomem, nostack, preserves_flags),
        );
    }
    t
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("rind-timing reads the x86_64 or aarch64 counter");

/// The counter's rate, measured against the system clock.
pub fn ticks_per_second() -> u64 {
    let start = (Instant::now(), ticks());
    while start.0.elapsed().as_millis() < 100 {}
    let ticks = ticks().wrapping_sub(start.1);
    (ticks as f64 / start.0.elapsed().as_secs_f64()) as u64
}

/// Welch's t-test, updated one value at a time.
#[derive(Clone, Copy, Default)]
struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    fn push(&mut self, x: f64, class: usize) {
        self.n[class] += 1.0;
        let delta = x - self.mean[class];
        self.mean[class] += delta / self.n[class];
        self.m2[class] += delta * (x - self.mean[class]);
    }

    fn len(&self) -> f64 {
        self.n[0] + self.n[1]
    }

    fn t(&self) -> f64 {
        let var = |c: usize| self.m2[c] / (self.n[c] - 1.0) / self.n[c];
        (self.mean[0] - self.mean[1]) / (var(0) + var(1)).sqrt()
    }
}

struct Stats {
    cutoffs: [f64; CROPS],
    /// Raw, then one per cutoff, then second order.
    tests: [Welch; CROPS + 2],
}

impl Stats {
    /// Sets the crop cutoffs from a first batch, as dudect.h does: the
    /// percentiles `1 - 0.5^(10 (i + 1) / 100)`, which crowd towards the top
    /// where the tail starts.
    fn new(first: &[u64]) -> Self {
        let mut sorted = first.to_vec();
        sorted.sort_unstable();
        let cutoffs = std::array::from_fn(|i| {
            let p = percentile(i);
            sorted[(sorted.len() as f64 * p) as usize] as f64
        });
        Self {
            cutoffs,
            tests: [Welch::default(); CROPS + 2],
        }
    }

    fn push(&mut self, x: f64, class: usize) {
        self.tests[0].push(x, class);
        // The cutoffs rise, so `x` falls below every one from this on.
        let from = self.cutoffs.partition_point(|&cutoff| x >= cutoff);
        for test in &mut self.tests[1 + from..=CROPS] {
            test.push(x, class);
        }
        if self.tests[0].n[0] > ENOUGH {
            let centered = x - self.tests[0].mean[class];
            self.tests[CROPS + 1].push(centered * centered, class);
        }
    }

    fn report(&self, reps: u32) -> Report {
        let (i, welch) = self
            .tests
            .iter()
            .enumerate()
            .filter(|(_, w)| w.len() > ENOUGH && !w.t().is_nan())
            .max_by(|a, b| a.1.t().abs().total_cmp(&b.1.t().abs()))
            .expect("the raw test has enough measurements");
        let test = match i {
            0 => Test::Raw,
            i if i <= CROPS => Test::Cropped(percentile(i - 1)),
            _ => Test::SecondOrder,
        };
        let delta = match test {
            Test::SecondOrder => f64::NAN,
            _ => (welch.mean[0] - welch.mean[1]) / f64::from(reps),
        };
        Report {
            measurements: self.tests[0].len() as usize,
            reps,
            test,
            t: welch.t(),
            delta,
        }
    }
}

fn percentile(i: usize) -> f64 {
    1.0 - 0.5f64.powf(10.0 * (i + 1) as f64 / CROPS as f64)
}
