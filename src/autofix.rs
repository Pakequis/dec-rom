//! Auto-Fix search: finds the address-bit and data-bit permutation that turns
//! a scrambled EPROM dump back into genuine Z80 code.
//!
//! The two permutations are found with two different signals, because no
//! single signal sees both:
//!
//! 1. **Address bits, coarse.** For each physical address bit, the mutual
//!    information between `data[x]` and `data[x ^ bit]` is measured. Bytes
//!    one position apart are far more related than bytes 4KB apart, so
//!    sorting the physical bits by that measure gives a first guess of their
//!    logical order with no search at all (`mutual_information_seed`).
//! 2. **Address bits, refined.** Pairs of address bits are swapped while the
//!    swap improves `scoring::compression_score`. Compression does not depend
//!    on the data-bit permutation (which only relabels byte values), so this
//!    step works before the data bits are known.
//! 3. **Data bits.** All 8! = 40,320 data-bit permutations are scored with
//!    `scoring::control_flow_score`, which only a decode with the right byte
//!    values satisfies (`sweep_data_maps`).
//! 4. **Address bits, final.** With the data bits known, address-bit pairs
//!    are swapped again while the swap improves the control-flow score. This
//!    settles the high address bits, which move whole blocks around and are
//!    nearly invisible to compression.
//!
//! Steps 3 and 4 repeat until the address map stops changing. The result is
//! reported with high confidence only if its control-flow score is far above
//! both what random bytes reach and what the second-best data-bit permutation
//! reaches (`is_confident`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rand::{rngs::StdRng, RngExt, SeedableRng};

use crate::detectors::Processor;
use crate::disasm;
use crate::known_patterns;
use crate::reorganizer::{apply_data_lut, build_data_lut, AddrDiff};
use crate::scoring::{compression_score, control_flow_score, control_flow_score_with, ControlFlowScratch};

/// A result needs at least one confirmed call (see
/// `scoring::control_flow_score`) per this many bytes of file to be reported
/// with high confidence. Measured on real 16KB-64KB MSX ROMs, the correct
/// decode has one per 38 to 78 bytes; random bytes of 8KB to 64KB, after the
/// search has done its best to maximize the count, reach at most one per 886
/// bytes. One per 256 bytes sits between the two with a factor of 3 or more
/// on each side.
const CONFIDENT_BYTES_PER_HIT: usize = 256;

/// Absolute floor for the same count, so a small file can't be confirmed by a
/// handful of coincidences: random bytes of 2KB to 4KB reach 5 to 7, which is
/// one per 410 to 585 bytes and too close to the density bar above.
const CONFIDENT_MIN_HITS: u32 = 32;

/// A result's control-flow score must also beat the best score any *other*
/// data-bit permutation reaches under the same address map by this factor.
/// Measured: 1.44 to 2.78 for the correct decode of real ROMs. This is a
/// second, weaker check next to the count thresholds above: it rejects a file
/// on which many data-bit orders score alike, but random bytes can exceed it
/// by chance when the counts are small (up to 1.75 at 4KB, 1.14 at 64KB).
const CONFIDENT_RUNNER_UP_RATIO: f64 = 1.33;

/// How many times data-bit sweep and address-bit refinement may alternate
/// for one starting point before the search settles for what it has.
const MAX_REFINE_ROUNDS: usize = 4;

/// When no starting point produces a confident result, the search restarts
/// from perturbed starting points until the time budget ends or this many
/// restarts in a row fail to improve on the best result so far.
const MAX_STALE_RESTARTS: u32 = 24;

/// How many of the best data-bit permutations are offered as alternatives in
/// a `Confidence::Marginal` result.
const MARGINAL_CANDIDATE_COUNT: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub enum Confidence {
    High,
    Marginal(Vec<Candidate>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub addr_map: Vec<u32>,
    pub data_map: [u32; 8],
    pub processor: Processor,
    pub compression_score: f64,
    pub coverage: f64,
    pub control_flow_hits: u32,
}

pub struct AutoFixResult {
    pub processor: Processor,
    pub addr_map: Vec<u32>,
    pub data_map: [u32; 8],
    pub score: f64,
    pub coverage: f64,
    /// `scoring::control_flow_score` of the winning decode.
    pub control_flow_hits: u32,
    /// Best `scoring::control_flow_score` reached by any other data-bit
    /// permutation under the winning address map.
    pub runner_up_hits: u32,
    pub confidence: Confidence,
    pub elapsed: Duration,
}

/// Runs `f` over `items` on all available cores, preserving order.
fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(items.len().max(1));
    let chunk_size = items.len().div_ceil(threads).max(1);
    let f = &f;
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(f).collect::<Vec<R>>()))
            .collect();
        handles.into_iter().flat_map(|h| h.join().expect("search worker thread panicked")).collect()
    })
}

/// Every permutation of the 8 data bits, in lexicographic order. The order
/// matters: the identity permutation comes first, so wherever the search
/// keeps the first of several equally-scored permutations, "leave the data
/// bits alone" wins the tie.
fn all_data_maps() -> Vec<[u32; 8]> {
    fn extend(current: &mut Vec<u32>, used: &mut [bool; 8], out: &mut Vec<[u32; 8]>) {
        if current.len() == 8 {
            let mut map = [0u32; 8];
            map.copy_from_slice(current);
            out.push(map);
            return;
        }
        for bit in 0..8 {
            if !used[bit] {
                used[bit] = true;
                current.push(bit as u32);
                extend(current, used, out);
                current.pop();
                used[bit] = false;
            }
        }
    }
    let mut out = Vec::with_capacity(40_320);
    extend(&mut Vec::with_capacity(8), &mut [false; 8], &mut out);
    out
}

/// Mutual information, in bits, between each byte whose address has `bit`
/// clear and the byte at the same address with `bit` set.
fn address_bit_mutual_information(data: &[u8], bit: u32) -> f64 {
    let mut joint = vec![0u32; 256 * 256];
    let mut pairs = 0u32;
    for addr in 0..data.len() {
        if (addr >> bit) & 1 == 0 {
            if let Some(&partner) = data.get(addr | (1 << bit)) {
                joint[(data[addr] as usize) << 8 | partner as usize] += 1;
                pairs += 1;
            }
        }
    }
    if pairs == 0 {
        return 0.0;
    }
    let total = pairs as f64;
    let mut first = [0f64; 256];
    let mut second = [0f64; 256];
    for a in 0..256 {
        for b in 0..256 {
            let p = joint[a << 8 | b] as f64 / total;
            first[a] += p;
            second[b] += p;
        }
    }
    let mut information = 0.0;
    for a in 0..256 {
        for b in 0..256 {
            let p = joint[a << 8 | b] as f64 / total;
            if p > 0.0 {
                information += p * (p / (first[a] * second[b])).log2();
            }
        }
    }
    information
}

/// First guess of the address map, with no search: the physical address bit
/// whose two halves are most related byte-for-byte is taken as logical bit 0
/// (adjacent bytes), the next as logical bit 1 (bytes two apart), and so on.
/// Reliable for the low bits, where the relation between nearby bytes is
/// strong; the high bits, where it is weak, are left to the refinement steps.
fn mutual_information_seed(data: &[u8], addr_bits: u32) -> Vec<u32> {
    let bits: Vec<u32> = (0..addr_bits).collect();
    let information = parallel_map(&bits, |&bit| address_bit_mutual_information(data, bit));
    let mut physical_by_information = bits;
    physical_by_information.sort_by(|&a, &b| information[b as usize].total_cmp(&information[a as usize]));
    let mut addr_map = vec![0u32; addr_bits as usize];
    for (logical, &physical) in physical_by_information.iter().enumerate() {
        addr_map[physical as usize] = logical as u32;
    }
    addr_map
}

/// Steepest-ascent search over address-bit pair swaps: every pair is tried,
/// the single best swap is applied if it strictly improves `score`, and this
/// repeats until no swap helps. `score` receives `data` reordered by the
/// candidate address map (data bits untouched). Returns whether `addr_map`
/// changed.
fn climb_address_pairs(data: &[u8], addr_map: &mut [u32], score: impl Fn(&[u8]) -> f64 + Sync) -> bool {
    let n = addr_map.len();
    let pairs: Vec<(usize, usize)> = (0..n).flat_map(|i| (i + 1..n).map(move |j| (i, j))).collect();
    let mut current = score(&AddrDiff::from_full_map(addr_map).apply_full(data));
    let mut changed = false;
    // Each accepted swap strictly improves a score with finitely many values,
    // so this always ends; the cap only bounds the time a long chain of tiny
    // compression gains could take.
    for _ in 0..4 * n {
        let scores = parallel_map(&pairs, |&(i, j)| {
            let mut candidate = addr_map.to_vec();
            candidate.swap(i, j);
            score(&AddrDiff::from_full_map(&candidate).apply_full(data))
        });
        let Some((best_index, &best_score)) =
            scores.iter().enumerate().reduce(|best, cur| if cur.1 > best.1 { cur } else { best })
        else {
            break;
        };
        if best_score <= current {
            break;
        }
        let (i, j) = pairs[best_index];
        addr_map.swap(i, j);
        current = best_score;
        changed = true;
    }
    changed
}

/// Scores every data-bit permutation of `reordered` (a buffer whose address
/// bits are already in candidate order) with `scoring::control_flow_score`.
/// Returns `(score, data_map)` pairs, best first; equal scores keep
/// `all_data_maps`'s order.
fn sweep_data_maps(reordered: &[u8], data_maps: &[[u32; 8]]) -> Vec<(u32, [u32; 8])> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let chunks: Vec<&[[u32; 8]]> = data_maps.chunks(data_maps.len().div_ceil(threads).max(1)).collect();
    let mut ranking: Vec<(u32, [u32; 8])> = parallel_map(&chunks, |chunk| {
        let mut scratch = ControlFlowScratch::default();
        let mut decoded = vec![0u8; reordered.len()];
        chunk
            .iter()
            .map(|data_map| {
                let lut = build_data_lut(data_map);
                for (out, &byte) in decoded.iter_mut().zip(reordered) {
                    *out = lut[byte as usize];
                }
                (control_flow_score_with(&decoded, &mut scratch), *data_map)
            })
            .collect::<Vec<_>>()
    })
    .into_iter()
    .flatten()
    .collect();
    ranking.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    ranking
}

/// One search outcome: an address map and the data-bit permutations ranked
/// under it, best first.
struct Solution {
    addr_map: Vec<u32>,
    ranking: Vec<(u32, [u32; 8])>,
}

impl Solution {
    fn hits(&self) -> u32 {
        self.ranking[0].0
    }

    fn runner_up_hits(&self) -> u32 {
        self.ranking[1].0
    }

    fn data_map(&self) -> [u32; 8] {
        self.ranking[0].1
    }
}

fn is_confident(hits: u32, runner_up_hits: u32, size: usize) -> bool {
    let min_hits = CONFIDENT_MIN_HITS.max((size / CONFIDENT_BYTES_PER_HIT) as u32);
    hits >= min_hits && hits as f64 >= CONFIDENT_RUNNER_UP_RATIO * runner_up_hits as f64
}

/// Steps 3 and 4 of the module-level description, starting from `addr_map`.
fn refine(data: &[u8], mut addr_map: Vec<u32>, data_maps: &[[u32; 8]]) -> Solution {
    for _ in 0..MAX_REFINE_ROUNDS {
        let ranking = sweep_data_maps(&AddrDiff::from_full_map(&addr_map).apply_full(data), data_maps);
        let lut = build_data_lut(&ranking[0].1);
        let changed =
            climb_address_pairs(data, &mut addr_map, |reordered| control_flow_score(&apply_data_lut(reordered, &lut)) as f64);
        if !changed {
            return Solution { addr_map, ranking };
        }
    }
    let ranking = sweep_data_maps(&AddrDiff::from_full_map(&addr_map).apply_full(data), data_maps);
    Solution { addr_map, ranking }
}

/// Steps 2 to 4 of the module-level description, starting from `addr_map`.
fn solve_from(data: &[u8], mut addr_map: Vec<u32>, data_maps: &[[u32; 8]]) -> Solution {
    climb_address_pairs(data, &mut addr_map, compression_score);
    refine(data, addr_map, data_maps)
}

/// Searches for the address-bit and data-bit permutation that decodes `data`
/// into Z80 code (see the module-level description).
///
/// `time_budget` only matters when no confident result is found: the search
/// then keeps restarting from perturbed starting points, drawn from `seed`,
/// until the budget ends. The initial starting points always run to the end,
/// which takes a few seconds at most for a 64KB file.
pub fn find_scrambling(
    data: &[u8],
    addr_bits: u32,
    time_budget: Duration,
    seed: u64,
    progress: impl FnMut(u32, &str),
) -> AutoFixResult {
    find_scrambling_cancellable(data, addr_bits, time_budget, seed, &AtomicBool::new(false), progress)
}

/// Same as `find_scrambling`, but stops early once `cancel` is set and
/// returns the best result found until then. The first starting point is
/// never skipped (there would be nothing to return), and a step in progress
/// finishes before the flag is looked at again.
pub fn find_scrambling_cancellable(
    data: &[u8],
    addr_bits: u32,
    time_budget: Duration,
    seed: u64,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u32, &str),
) -> AutoFixResult {
    debug_assert!(addr_bits >= 2, "find_scrambling requires at least 2 address bits, got {addr_bits}");
    let size = data.len();
    let start = Instant::now();
    let data_maps = all_data_maps();
    let identity_addr: Vec<u32> = (0..addr_bits).collect();

    progress(0, "Estimating the address bit order...");
    let information_seed = mutual_information_seed(data, addr_bits);

    // Starting points, most promising first. The mutual-information seed
    // solves nearly every case on its own. The as-loaded order and the
    // known-pattern library's suggestion cover the files that seed gets
    // wrong (e.g. a dump holding two copies of a smaller ROM, where the top
    // address bit relates the two halves perfectly and is mistaken for bit
    // 0). A known pattern is only a starting point here: it has to win on
    // the same control-flow evidence as any other candidate.
    let mut starting_points = vec![information_seed.clone()];
    if let Some(known) = known_patterns::try_known_patterns(data, addr_bits) {
        starting_points.push(known.addr_map);
    }
    starting_points.push(identity_addr.clone());
    let mut tried: Vec<Vec<u32>> = Vec::new();

    let mut best: Option<Solution> = None;
    let confident = |solution: &Option<Solution>| {
        solution.as_ref().is_some_and(|s| is_confident(s.hits(), s.runner_up_hits(), size))
    };
    for (index, addr_map) in starting_points.iter().enumerate() {
        if confident(&best) || tried.contains(addr_map) || (best.is_some() && cancel.load(Ordering::Relaxed)) {
            continue;
        }
        tried.push(addr_map.clone());
        progress((10 + 20 * index as u32).min(60), "Searching address and data bit order...");
        let solution = solve_from(data, addr_map.clone(), &data_maps);
        if best.as_ref().is_none_or(|b| solution.hits() > b.hits()) {
            best = Some(solution);
        }
    }
    let mut best = best.expect("at least one starting point is always tried");

    let mut rng = StdRng::seed_from_u64(seed);
    let mut stale_restarts = 0;
    let mut longest_restart = Duration::ZERO;
    while !is_confident(best.hits(), best.runner_up_hits(), size)
        && stale_restarts < MAX_STALE_RESTARTS
        && !cancel.load(Ordering::Relaxed)
    {
        // A restart isn't interrupted once it begins, so one is only begun
        // if the slowest restart so far would still fit in the budget.
        let elapsed = start.elapsed();
        if elapsed + longest_restart.mul_f64(1.5) >= time_budget {
            break;
        }
        let pct = 60 + (elapsed.as_secs_f64() / time_budget.as_secs_f64() * 35.0) as u32;
        progress(pct.min(95), "No confident result yet, trying other starting points...");

        let restart_started = Instant::now();
        let mut addr_map = information_seed.clone();
        for _ in 0..rng.random_range(2..=4) {
            let i = rng.random_range(0..addr_bits as usize);
            let j = rng.random_range(0..addr_bits as usize);
            addr_map.swap(i, j);
        }
        let solution = solve_from(data, addr_map, &data_maps);
        longest_restart = longest_restart.max(restart_started.elapsed());
        if solution.hits() > best.hits() {
            best = solution;
            stale_restarts = 0;
        } else {
            stale_restarts += 1;
        }
    }

    // A file that is already correct must come back unchanged. The as-loaded
    // bytes are scored directly and, if nothing found above beats them, the
    // as-loaded address order replaces the result - whatever equally-scored
    // rearrangement the search may have settled on.
    if best.addr_map != identity_addr && control_flow_score(data) >= best.hits() {
        best = refine(data, identity_addr, &data_maps);
    }

    let reordered = AddrDiff::from_full_map(&best.addr_map).apply_full(data);
    let decode = |data_map: &[u32; 8]| apply_data_lut(&reordered, &build_data_lut(data_map));
    let decoded = decode(&best.data_map());
    let score = compression_score(&decoded);
    let coverage = disasm::coverage(Processor::Z80, &decoded);

    let confidence = if is_confident(best.hits(), best.runner_up_hits(), size) {
        Confidence::High
    } else {
        Confidence::Marginal(
            best.ranking
                .iter()
                .take(MARGINAL_CANDIDATE_COUNT)
                .map(|&(hits, data_map)| {
                    let decoded = decode(&data_map);
                    Candidate {
                        addr_map: best.addr_map.clone(),
                        data_map,
                        processor: Processor::Z80,
                        compression_score: compression_score(&decoded),
                        coverage: disasm::coverage(Processor::Z80, &decoded),
                        control_flow_hits: hits,
                    }
                })
                .collect(),
        )
    };

    let elapsed = start.elapsed();
    progress(
        100,
        &format!(
            "Done: {} confirmed calls (next best data bit order: {}) in {:.1}s",
            best.hits(),
            best.runner_up_hits(),
            elapsed.as_secs_f64()
        ),
    );

    AutoFixResult {
        processor: Processor::Z80,
        addr_map: best.addr_map.clone(),
        data_map: best.data_map(),
        score,
        coverage,
        control_flow_hits: best.hits(),
        runner_up_hits: best.runner_up_hits(),
        confidence,
        elapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random generator for the fixtures below.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n
        }

        fn shuffle(&mut self, values: &mut [u32]) {
            for i in (1..values.len()).rev() {
                values.swap(i, self.below(i + 1));
            }
        }
    }

    /// A buffer shaped like a Z80 ROM: routines laid out back to back, each
    /// a sequence of short instruction idioms drawn from a small recurring
    /// set (what makes real code compressible), with calls to other routines
    /// in between, ending in `RET`. Not runnable code, but it has the two
    /// properties the search relies on: nearby bytes are related, and calls
    /// point at routine starts.
    fn synthetic_z80_rom(size: usize, seed: u64) -> Vec<u8> {
        enum Item {
            Idiom(usize),
            Call(usize),
        }
        let mut rng = Lcg(seed);
        // Bytes used inside idioms: none of them is a CALL opcode or one of
        // the terminators `scoring::control_flow_score` looks for.
        const FILLER: [u8; 24] = [
            0x3E, 0x21, 0x11, 0x01, 0x7E, 0x77, 0x23, 0x2B, 0x13, 0x0B, 0xB7, 0xAF, 0xFE, 0xE6, 0xF5, 0xF1, 0xC5, 0xC1,
            0xD5, 0xD1, 0x78, 0x47, 0x4F, 0x79,
        ];
        let idioms: Vec<Vec<u8>> =
            (0..48).map(|_| (0..2 + rng.below(7)).map(|_| FILLER[rng.below(FILLER.len())]).collect()).collect();

        let mut routines: Vec<Vec<Item>> = Vec::new();
        let mut starts: Vec<usize> = Vec::new();
        let mut used = 0usize;
        while used + 80 < size {
            let routine: Vec<Item> = (0..4 + rng.below(12))
                .map(|_| if rng.below(10) < 3 { Item::Call(rng.next() as usize) } else { Item::Idiom(rng.below(idioms.len())) })
                .collect();
            let length: usize =
                routine.iter().map(|item| match item { Item::Idiom(i) => idioms[*i].len(), Item::Call(_) => 3 }).sum::<usize>() + 1;
            starts.push(used);
            used += length;
            routines.push(routine);
        }

        let mut rom = Vec::with_capacity(size);
        for routine in &routines {
            for item in routine {
                match item {
                    Item::Idiom(i) => rom.extend_from_slice(&idioms[*i]),
                    Item::Call(target) => {
                        rom.push(0xCD);
                        rom.extend_from_slice(&(starts[target % starts.len()] as u16).to_le_bytes());
                    }
                }
            }
            rom.push(0xC9);
        }
        rom.resize(size, 0xFF);
        rom
    }

    fn descramble(data: &[u8], result: &AutoFixResult) -> Vec<u8> {
        let reordered = AddrDiff::from_full_map(&result.addr_map).apply_full(data);
        apply_data_lut(&reordered, &build_data_lut(&result.data_map))
    }

    const IDENTITY_DATA_MAP: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    const ROM_SIZE: usize = 8192;
    const ROM_ADDR_BITS: u32 = 13;
    const BUDGET: Duration = Duration::from_secs(30);

    #[test]
    fn all_data_maps_lists_every_permutation_once_starting_with_identity() {
        let maps = all_data_maps();
        assert_eq!(maps.len(), 40_320);
        assert_eq!(maps[0], IDENTITY_DATA_MAP);
        let distinct: std::collections::HashSet<[u32; 8]> = maps.iter().copied().collect();
        assert_eq!(distinct.len(), 40_320);
    }

    #[test]
    fn mutual_information_seed_is_a_permutation() {
        let rom = synthetic_z80_rom(ROM_SIZE, 1);
        let mut seed = mutual_information_seed(&rom, ROM_ADDR_BITS);
        seed.sort_unstable();
        assert_eq!(seed, (0..ROM_ADDR_BITS).collect::<Vec<u32>>());
    }

    #[test]
    fn recovers_a_random_address_and_data_scramble() {
        let correct = synthetic_z80_rom(ROM_SIZE, 2);
        let mut rng = Lcg(99);
        let mut addr_scramble: Vec<u32> = (0..ROM_ADDR_BITS).collect();
        rng.shuffle(&mut addr_scramble);
        let mut data_scramble = IDENTITY_DATA_MAP;
        rng.shuffle(&mut data_scramble);
        let scrambled =
            apply_data_lut(&AddrDiff::from_full_map(&addr_scramble).apply_full(&correct), &build_data_lut(&data_scramble));

        let result = find_scrambling(&scrambled, ROM_ADDR_BITS, BUDGET, 42, |_, _| {});

        assert!(descramble(&scrambled, &result) == correct, "the scramble was not undone exactly");
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn recovers_a_single_data_line_swap() {
        // A data-only scramble leaves compression untouched and still decodes
        // as plausible Z80 instructions, so only the control-flow evidence
        // can tell it from the correct file.
        let correct = synthetic_z80_rom(ROM_SIZE, 3);
        let scrambled = apply_data_lut(&correct, &build_data_lut(&[1, 0, 2, 3, 4, 5, 6, 7]));

        let result = find_scrambling(&scrambled, ROM_ADDR_BITS, BUDGET, 42, |_, _| {});

        assert!(descramble(&scrambled, &result) == correct, "the data line swap was not undone exactly");
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn leaves_an_already_correct_file_unchanged() {
        let correct = synthetic_z80_rom(ROM_SIZE, 4);

        let result = find_scrambling(&correct, ROM_ADDR_BITS, BUDGET, 42, |_, _| {});

        assert_eq!(result.addr_map, (0..ROM_ADDR_BITS).collect::<Vec<u32>>());
        assert_eq!(result.data_map, IDENTITY_DATA_MAP);
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn reports_random_bytes_as_marginal() {
        let mut rng = Lcg(5);
        let noise: Vec<u8> = (0..ROM_SIZE).map(|_| rng.next() as u8).collect();

        // A zero budget skips the restarts, which random bytes would
        // otherwise use up in full without ever becoming confident.
        let result = find_scrambling(&noise, ROM_ADDR_BITS, Duration::ZERO, 42, |_, _| {});

        assert!(matches!(result.confidence, Confidence::Marginal(_)), "random bytes must not be confirmed as Z80 code");
    }

    #[test]
    fn a_cancelled_search_skips_the_restarts_and_still_returns_a_result() {
        let mut rng = Lcg(6);
        let noise: Vec<u8> = (0..ROM_SIZE).map(|_| rng.next() as u8).collect();
        let cancel = AtomicBool::new(true);
        let mut restarted = false;

        // An hour of budget: only the cancel flag can end this quickly.
        let result = find_scrambling_cancellable(&noise, ROM_ADDR_BITS, Duration::from_secs(3600), 42, &cancel, |pct, _| {
            restarted |= (60..100).contains(&pct);
        });

        assert!(!restarted, "a cancelled search must not start any restart");
        assert!(matches!(result.confidence, Confidence::Marginal(_)));
    }

    #[test]
    fn handles_the_smallest_loadable_file() {
        // 4 bytes / 2 address bits is the smallest size `Rom::load` accepts.
        let result = find_scrambling(&[0x00, 0xC9, 0x00, 0xC9], 2, Duration::ZERO, 42, |_, _| {});
        assert!(matches!(result.confidence, Confidence::Marginal(_)));
    }
}
