//! Ascending-support-size address-bit search plus exhaustive data-bit
//! search, bounded by a hard wall-clock time budget.

use std::time::{Duration, Instant};
use itertools::Itertools;
use rand::{rngs::StdRng, RngExt, SeedableRng};

use crate::detectors::Processor;
use crate::disasm;
use crate::known_patterns;
use crate::reorganizer::{AddrDiff, apply_data_lut, build_data_lut};
use crate::scoring::compression_score;

const ANNEAL_INITIAL_TEMPERATURE: f64 = 0.05;
const ANNEAL_COOLING_RATE: f64 = 0.85;
const ANNEAL_MIN_TEMPERATURE: f64 = 0.01;

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
    pub preview: Vec<u8>,
}

pub struct AutoFixResult {
    pub processor: Processor,
    pub addr_map: Vec<u32>,
    pub data_map: [u32; 8],
    pub score: f64,
    pub coverage: f64,
    pub confidence: Confidence,
    pub elapsed: Duration,
    pub max_k_covered: u32,
    pub ascending_k_complete: bool,
}

/// Compression-score improvement (see `scoring::compression_score`) a
/// candidate must show over the as-loaded file for High confidence. This is
/// an uncalibrated starting guess, not a value derived from any deliberate
/// calibration exercise — it has only been confirmed to work for the real
/// scrambled EPROM dumps used to validate this search so far, and may need
/// revisiting if a future fixture's margin doesn't fit it.
const CONFIDENCE_MARGIN: f64 = 0.05;

/// Number of derangements (permutations with no fixed point) of k elements.
fn derangement_count(k: u32) -> u64 {
    if k == 0 {
        return 1;
    }
    if k == 1 {
        return 0;
    }
    let (mut d0, mut d1) = (1u64, 0u64);
    for i in 2..=k {
        let next = (i as u64 - 1) * (d0 + d1);
        d0 = d1;
        d1 = next;
    }
    d1
}

fn num_combinations(n: u32, k: u32) -> u64 {
    if k > n {
        return 0;
    }
    let k = k.min(n - k);
    let mut result: u64 = 1;
    for i in 0..k {
        result = result * (n - i) as u64 / (i + 1) as u64;
    }
    result
}

/// Every address-bit permutation with exactly k positions moved from
/// identity, all others fixed. Lazy end-to-end: combinations stream from
/// `itertools`, and each combination's k! permutations stream one at a time
/// from `.permutations(k)` through a `filter_map` (no intermediate
/// `.collect()`), so the caller's per-item time-budget check genuinely
/// bounds work between checks even when k! is large.
fn derangements_by_support(addr_bits: u32, k: usize) -> impl Iterator<Item = (Vec<u32>, Vec<u32>)> {
    (0..addr_bits).combinations(k).flat_map(move |positions| {
        positions.clone().into_iter().permutations(k).filter_map(move |perm| {
            if positions.iter().zip(perm.iter()).all(|(p, s)| p != s) {
                Some((positions.clone(), perm))
            } else {
                None
            }
        })
    })
}

struct AddrCandidate {
    score: f64,
    addr_map: Vec<u32>,
    data_map: [u32; 8],
}

fn screening_data_patterns() -> [[u32; 8]; 3] {
    [
        [0, 1, 2, 3, 4, 5, 6, 7],
        [7, 6, 5, 4, 3, 2, 1, 0],
        [4, 5, 6, 7, 0, 1, 2, 3],
    ]
}

fn eval_addr_candidate(
    data: &[u8],
    sample_indices: &[usize],
    positions: &[u32],
    sources: &[u32],
    addr_bits: u32,
    screening_luts: &[([u32; 8], [u8; 256])],
) -> AddrCandidate {
    let diff = AddrDiff::new(positions.to_vec(), sources.to_vec());
    let sample_bytes = diff.apply_to_indices(data, sample_indices);

    let mut best_score = f64::MIN;
    let mut best_dp = screening_luts[0].0;
    for (dp, lut) in screening_luts {
        let processed = apply_data_lut(&sample_bytes, lut);
        let score = compression_score(&processed);
        if score > best_score {
            best_score = score;
            best_dp = *dp;
        }
    }

    AddrCandidate {
        score: best_score,
        addr_map: diff.to_full_map(addr_bits),
        data_map: best_dp,
    }
}

fn score_printable_cheap(histogram: &[u32; 256], lut: &[u8; 256]) -> u32 {
    let mut total = 0u32;
    for v in 0..256usize {
        let c = histogram[v];
        if c > 0 && lut[v] >= 32 && lut[v] <= 126 {
            total += c;
        }
    }
    total
}

pub fn find_scrambling(
    data: &[u8],
    addr_bits: u32,
    time_budget: Duration,
    seed: u64,
    mut progress: impl FnMut(u32, &str),
) -> AutoFixResult {
    debug_assert!(addr_bits >= 2, "find_scrambling requires at least 2 address bits, got {addr_bits}");
    let size = data.len();
    let start = Instant::now();

    if let Some(known) = known_patterns::try_known_patterns(data, addr_bits) {
        progress(100, &format!("Matched a known bit-swap pattern (coverage {:.0}%)", known.coverage * 100.0));
        return AutoFixResult {
            processor: known.processor,
            addr_map: known.addr_map,
            data_map: known.data_map,
            score: known.compression_score,
            coverage: known.coverage,
            confidence: Confidence::High,
            elapsed: start.elapsed(),
            max_k_covered: 0,
            ascending_k_complete: true,
        };
    }

    let sample_indices: Vec<usize> = {
        let head_len = size.min(2048);
        let mut idx: Vec<usize> = (0..head_len).collect();
        if size > 2048 {
            let tail_start = size.saturating_sub(2048).max(head_len);
            idx.extend(tail_start..size);
        }
        idx
    };

    let screening_luts: Vec<([u32; 8], [u8; 256])> = screening_data_patterns()
        .into_iter()
        .map(|dp| (dp, build_data_lut(&dp)))
        .collect();

    // The fitness function driving the search (compression_score, below) is
    // processor-agnostic, so no per-processor scorer needs choosing upfront
    // — sidestepping the "guess the processor from still-scrambled bytes"
    // problem entirely rather than working around it. Which processor the
    // final winning candidate matches is still determined once, at the end,
    // from the actual decoded result (see `detect(&recovered)` below).

    progress(0, "Phase 1: ascending-complexity address search...");
    // Phase 3's full-pairs local search converges from a seed in roughly a
    // handful of full-file rescans (cheap: a 32KB file scores in low single
    // digit milliseconds), so restarting it from many distinct seeds is a
    // far more time-efficient way to explore the permutation space than
    // exhaustively enumerating every k-bit-support address derangement,
    // which this phase was previously given half the whole budget for.
    // Leaving phase 1/2 less time and phase 3 more lets many more restarts
    // run, improving the odds that at least one basin reaches the true
    // global optimum instead of settling for whichever one or two seeds
    // phase 1 managed to test before its deadline.
    let phase1_deadline = time_budget.mul_f64(0.12);

    let mut addr_results: Vec<AddrCandidate> = Vec::new();
    let mut candidates_tested: u64 = 0;

    addr_results.push(eval_addr_candidate(data, &sample_indices, &[], &[], addr_bits, &screening_luts));
    candidates_tested += 1;

    let reverse_map: Vec<u32> = (0..addr_bits).rev().collect();
    let reverse_diff = AddrDiff::from_full_map(&reverse_map);
    addr_results.push(eval_addr_candidate(
        data, &sample_indices, &reverse_diff.positions, &reverse_diff.sources, addr_bits, &screening_luts,
    ));
    candidates_tested += 1;

    let mut max_k_covered = 0u32;
    let mut stopped_early = false;

    for k in 2..addr_bits {
        if start.elapsed() > phase1_deadline {
            stopped_early = true;
            break;
        }
        let k_total = num_combinations(addr_bits, k) * derangement_count(k);
        let mut k_count: u64 = 0;
        for (positions, sources) in derangements_by_support(addr_bits, k as usize) {
            if start.elapsed() > phase1_deadline {
                stopped_early = true;
                break;
            }
            addr_results.push(eval_addr_candidate(data, &sample_indices, &positions, &sources, addr_bits, &screening_luts));
            candidates_tested += 1;
            k_count += 1;
            if candidates_tested.is_multiple_of(100) {
                let pct = ((start.elapsed().as_secs_f64() / phase1_deadline.as_secs_f64()) * 50.0).min(49.0) as u32;
                progress(pct, &format!("Phase 1: k={k}, {candidates_tested} candidates tested..."));
            }
        }
        max_k_covered = k;
        if stopped_early || k_count < k_total {
            break;
        }
    }

    // No time check needed here: `addr_results` is already bounded by phase 1's
    // own deadline-checked accumulation loop above, so this sort/dedup is
    // O(bounded-N log N) over an already-capped vector, not a fresh unbounded search.
    addr_results.sort_by(|a, b| b.score.total_cmp(&a.score));
    // Identity and the full bit-reversal are always evaluated above, but
    // only against 3 crude screening data patterns (`screening_data_patterns`)
    // — a coarse enough proxy that either baseline can rank outside the
    // top few thousand candidates on that score alone and never receive
    // phase 2's exhaustive 8!-pattern data-bit search, even when the real
    // wiring turns out to need no address scrambling at all (or a full
    // reversal) plus some data-bit permutation the 3 screening patterns
    // don't happen to approximate well. Since "the address wiring wasn't
    // touched" and "it was fully reversed" are both common real-world
    // cases, both baselines are guaranteed a full data-bit search
    // regardless of where the coarse screening ranked them.
    let mut top_addr_maps: Vec<Vec<u32>> = vec![
        (0..addr_bits).collect(),
        (0..addr_bits).rev().collect(),
    ];
    for cand in &addr_results {
        if !top_addr_maps.contains(&cand.addr_map) {
            top_addr_maps.push(cand.addr_map.clone());
        }
        if top_addr_maps.len() >= 8 {
            break;
        }
    }

    progress(50, "Phase 2: exhaustive data-bit search on top candidates...");
    let phase2_deadline = time_budget.mul_f64(0.22);

    let all_data_patterns: Vec<[u32; 8]> = (0u32..8)
        .permutations(8)
        .map(|p| [p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]])
        .collect();
    let all_data_luts: Vec<([u32; 8], [u8; 256])> = all_data_patterns.iter().map(|dp| (*dp, build_data_lut(dp))).collect();

    // Track a handful of the best (addr_map, data_map) pairs by
    // `score_quick`, not just the single winner: phase 3's hill-climbing can
    // only reach local optima of `score_full` reachable from wherever it
    // starts, and `score_quick` (a small head/tail sample) is only a proxy
    // for the true, whole-file objective. Restarting phase 3 from several
    // distinct quick-scored seeds — instead of committing to just the
    // top one — gives the true answer more than one basin of attraction to
    // be found from.
    const PHASE2_SEED_COUNT: usize = 24;
    let mut phase2_seeds: Vec<(f64, Vec<u32>, [u32; 8])> = Vec::new();
    let mut push_seed = |score: f64, addr_map: &[u32], data_map: [u32; 8]| {
        phase2_seeds.push((score, addr_map.to_vec(), data_map));
        phase2_seeds.sort_by(|a, b| b.0.total_cmp(&a.0));
        phase2_seeds.truncate(PHASE2_SEED_COUNT);
    };
    if let Some(top) = addr_results.first() {
        push_seed(top.score, &top.addr_map, top.data_map);
    }

    'phase2: for addr_map in &top_addr_maps {
        if start.elapsed() > phase2_deadline {
            break;
        }
        let diff = AddrDiff::from_full_map(addr_map);
        let sample_bytes = diff.apply_to_indices(data, &sample_indices);

        let mut histogram = [0u32; 256];
        for &b in &sample_bytes {
            histogram[b as usize] += 1;
        }

        let mut prescreen: Vec<(u32, [u32; 8], [u8; 256])> = all_data_luts
            .iter()
            .map(|(dp, lut)| (score_printable_cheap(&histogram, lut), *dp, *lut))
            .collect();
        prescreen.sort_by_key(|b| std::cmp::Reverse(b.0));

        for (_, dp, lut) in prescreen.iter().take(30) {
            if start.elapsed() > phase2_deadline {
                break 'phase2;
            }
            let processed = apply_data_lut(&sample_bytes, lut);
            let score = compression_score(&processed);
            push_seed(score, addr_map, *dp);
        }
    }

    progress(85, "Phase 3: iterative refinement...");

    // After Phase 3, this function still runs the exhaustive data-map sweep
    // (below, right after `drop(record_candidate)`) and then the
    // disassembly-confirmation ranking tail over whatever candidates the
    // pool ends up holding. Both need their own reserved time slice, carved
    // out of `phase3_deadline` upfront, rather than living on whatever Phase
    // 3 happens to leave over: Phase 3's own loop runs right up to
    // `phase3_deadline`, so "leftover time" can be arbitrarily close to
    // zero.
    //
    // The ranking tail is the one that actually matters for safety: unlike
    // the sweep (which checks elapsed time every permutation and simply
    // stops), the tail below has no deadline check at all — it evaluates
    // every pooled candidate unconditionally. Its per-candidate cost (one
    // `AddrDiff::apply_full`, one `apply_data_lut`, one
    // `disasm::identify_processor` — a full linear decode pass per
    // supported processor — and one `compression_score`, all over the whole
    // file) was measured directly: at 512KB, in a debug (non-release)
    // build — the profile `cargo test` itself runs under, and therefore the
    // one that matters for a hard wall-clock budget — repeated runs of that
    // exact sequence landed 278-389ms per candidate (roughly 530-740ns per
    // byte). 512KB was this project's file-size ceiling when this was
    // measured; `reorganizer::MAX_FILE_SIZE` is now 64KB (Auto-Fix narrowed
    // to Z80 only), so this measurement is a conservative upper bound rather
    // than today's actual worst case. `compression_score` has also since
    // moved off zlib's slowest compression level (see its own doc comment),
    // so real per-candidate cost today is lower than this measurement, not
    // higher — leaving `TAIL_NS_PER_BYTE_PER_CANDIDATE` below (roughly double
    // the slower end of that measured range) with more headroom than it had
    // when calibrated, not less.
    //
    // How many candidates the tail evaluates is bounded by
    // `CANDIDATE_POOL_SIZE` (Phase 3's own pool cap, below) plus
    // `SWEEP_POOL_CAP` (the cap on sweep survivors admitted to that same
    // pool, see the sweep block below) — `MAX_TAIL_CANDIDATES` is exactly
    // that sum, so the reserve scales with the actual worst-case candidate
    // count rather than an arbitrary guess.
    //
    // The reserve is computed from `size` (this call's actual file size),
    // not hardcoded at the 512KB measurement scale: the real per-byte cost
    // is lower for smaller files (cache effects: the 512KB run's per-byte
    // cost was itself several times worse than a 32KB run's, so a rate
    // measured at that scale is already a conservative upper bound for any
    // smaller size, including this project's actual 64KB ceiling), so
    // scaling by `size` keeps small-file, small-budget callers (e.g. this
    // module's own unit tests, at a few hundred bytes) from having almost
    // their entire budget eaten by a reserve sized for a worst case they'll
    // never hit.
    const TAIL_NS_PER_BYTE_PER_CANDIDATE: u64 = 1_500;
    const SWEEP_POOL_CAP: usize = 3;
    const MAX_TAIL_CANDIDATES: u64 = CANDIDATE_POOL_SIZE as u64 + SWEEP_POOL_CAP as u64;
    let tail_reserve = Duration::from_nanos(
        (size as u64)
            .saturating_mul(TAIL_NS_PER_BYTE_PER_CANDIDATE)
            .saturating_mul(MAX_TAIL_CANDIDATES),
    );

    // The sweep's own window: unlike the tail, its loop checks elapsed time
    // every permutation, so this reserve only bounds *opportunity* (how many
    // of the 40,320 data-map permutations it gets to try before giving up),
    // not safety. But it isn't a nicety either: measured directly against a
    // real scrambled EPROM dump, Phase 3's own restarts reliably converge on a
    // compression-best candidate whose data_map is *wrong* (a genuine local
    // optimum that outscores the true decode on compression alone — this is
    // the exact failure mode the sweep exists to catch), and the true
    // decode's data_map was only found by the sweep, at permutation index
    // 722 of the 40,320 — reached after ~2.7s in that same run. Reaching it
    // reliably needs real headroom over that, not just enough for a handful
    // of attempts, so this reserve is a large fraction of the whole budget
    // (up to 15 seconds), not a small fixed bonus — capped at 25% of
    // `time_budget` as well, so a short budget (e.g. this module's own unit
    // tests, seconds rather than the ~60s a real caller gives, where the
    // sweep isn't needed at all since their tiny fixtures fall well under
    // every processor's `disasm::qualifies` byte-count threshold) doesn't
    // have most of its time eaten by a reserve sized for realistic
    // multi-second-to-minute budgets.
    let sweep_reserve = Duration::from_secs(15).min(time_budget.mul_f64(0.25));

    // On top of the sweep and tail reserves above, leave the original small
    // safety margin before the caller's actual deadline: each refinement
    // step below only checks elapsed time between individual candidate
    // evaluations (not whole passes), so without a margin the last one can
    // still push the reported `elapsed` slightly past `time_budget` — which
    // callers may treat as a hard cap.
    let phase3_deadline =
        time_budget.saturating_sub(sweep_reserve + tail_reserve + Duration::from_millis(1500));

    // Full all-pairs transposition neighborhood (not just adjacent swaps):
    // a real scrambling wiring can transpose any two bit positions,
    // including ones that aren't next to each other, and a multi-bit cycle
    // (e.g. bits 10<->11<->14<->13<->12) only decomposes into a chain of
    // *adjacent* transpositions if every intermediate state along that
    // chain also scores as an improvement — which greedy hill-climbing
    // over adjacent pairs alone can't guarantee. Trying every pair directly
    // gives each single-transposition step of the true permutation a
    // chance to be adopted regardless of position, at a cost
    // (addr_bits choose 2, at most 8 choose 2 = 28 for data bits) that's
    // negligible next to the time budget.
    fn greedy_polish(
        data: &[u8],
        addr_bits: u32,
        seed_addr: &[u32],
        seed_data: [u32; 8],
        start: &Instant,
        time_budget: Duration,
    ) -> (Vec<u32>, [u32; 8], f64) {
        let mut current_addr = seed_addr.to_vec();
        let mut current_data = seed_data;
        let mut reordered_full = AddrDiff::from_full_map(&current_addr).apply_full(data);
        let mut current_lut = build_data_lut(&current_data);
        let mut current_score = compression_score(&apply_data_lut(&reordered_full, &current_lut));

        let mut improved = true;
        while improved && start.elapsed() < time_budget {
            improved = false;

            'addr_pairs: for i in 0..addr_bits as usize {
                for j in (i + 1)..addr_bits as usize {
                    if start.elapsed() > time_budget {
                        break 'addr_pairs;
                    }
                    let mut test_addr = current_addr.clone();
                    test_addr.swap(i, j);
                    let reordered = AddrDiff::from_full_map(&test_addr).apply_full(data);
                    let processed = apply_data_lut(&reordered, &current_lut);
                    let score = compression_score(&processed);
                    if score > current_score {
                        current_addr = test_addr;
                        current_score = score;
                        reordered_full = reordered;
                        improved = true;
                    }
                }
            }

            'data_pairs: for i in 0..7usize {
                for j in (i + 1)..8usize {
                    if start.elapsed() > time_budget {
                        break 'data_pairs;
                    }
                    let mut test_data = current_data;
                    test_data.swap(i, j);
                    let lut = build_data_lut(&test_data);
                    let processed = apply_data_lut(&reordered_full, &lut);
                    let score = compression_score(&processed);
                    if score > current_score {
                        current_data = test_data;
                        current_lut = lut;
                        current_score = score;
                        improved = true;
                    }
                }
            }
        }

        (current_addr, current_data, current_score)
    }

    fn random_distinct_pair(rng: &mut StdRng, n: usize) -> (usize, usize) {
        let i = rng.random_range(0..n);
        let mut j = rng.random_range(0..n - 1);
        if j >= i {
            j += 1;
        }
        (i, j)
    }

    fn simulated_anneal(
        data: &[u8],
        addr_bits: u32,
        seed_addr: &[u32],
        seed_data: [u32; 8],
        start: &Instant,
        deadline: Duration,
        rng: &mut StdRng,
    ) -> (Vec<u32>, [u32; 8], f64) {
        let mut current_addr = seed_addr.to_vec();
        let mut current_data = seed_data;
        let mut current_lut = build_data_lut(&current_data);
        let mut reordered_full = AddrDiff::from_full_map(&current_addr).apply_full(data);
        let mut current_score = compression_score(&apply_data_lut(&reordered_full, &current_lut));

        let mut best_addr = current_addr.clone();
        let mut best_data = current_data;
        let mut best_score = current_score;

        let mut temperature = ANNEAL_INITIAL_TEMPERATURE;

        while temperature > ANNEAL_MIN_TEMPERATURE && start.elapsed() < deadline {
            let move_is_addr = rng.random_bool(0.5);
            let (i, j) = if move_is_addr {
                random_distinct_pair(rng, addr_bits as usize)
            } else {
                random_distinct_pair(rng, 8)
            };

            let (candidate_addr, candidate_data, reordered_candidate, lut_candidate) = if move_is_addr {
                let mut test_addr = current_addr.clone();
                test_addr.swap(i, j);
                let reordered = AddrDiff::from_full_map(&test_addr).apply_full(data);
                (test_addr, current_data, reordered, current_lut)
            } else {
                let mut test_data = current_data;
                test_data.swap(i, j);
                let lut = build_data_lut(&test_data);
                (current_addr.clone(), test_data, reordered_full.clone(), lut)
            };

            let processed = apply_data_lut(&reordered_candidate, &lut_candidate);
            let candidate_score = compression_score(&processed);

            let accept = candidate_score > current_score
                || rng.random_bool(((candidate_score - current_score) / temperature).exp().min(1.0));

            if accept {
                current_addr = candidate_addr;
                current_data = candidate_data;
                reordered_full = reordered_candidate;
                current_lut = lut_candidate;
                current_score = candidate_score;
                if current_score > best_score {
                    best_addr = current_addr.clone();
                    best_data = current_data;
                    best_score = current_score;
                }
            }

            temperature *= ANNEAL_COOLING_RATE;
        }

        if start.elapsed() < deadline {
            let (polished_addr, polished_data, polished_score) =
                greedy_polish(data, addr_bits, &best_addr, best_data, start, deadline);
            if polished_score > best_score {
                best_addr = polished_addr;
                best_data = polished_data;
                best_score = polished_score;
            }
        }

        (best_addr, best_data, best_score)
    }

    // Track a pool of the best candidates Phase 3 finds, not just a single
    // winner-by-compression-score: a wrong bit-permutation was found (during
    // an earlier stage of this search's development) to compress strictly
    // better than one real fixture's true decode, so compression alone can
    // rank the wrong candidate first. Keeping a pool lets disassembly
    // confirmation, below, pick the winner from several contenders instead
    // of only ever being able to confirm-or-reject a single one.
    const CANDIDATE_POOL_SIZE: usize = 8;
    let mut top_candidates: Vec<(f64, Vec<u32>, [u32; 8])> = Vec::new();
    let mut record_candidate = |score: f64, addr: &[u32], data_map: [u32; 8]| {
        top_candidates.push((score, addr.to_vec(), data_map));
        top_candidates.sort_by(|a, b| b.0.total_cmp(&a.0));
        top_candidates.truncate(CANDIDATE_POOL_SIZE);
    };

    let mut rng = StdRng::seed_from_u64(seed);
    for (_, seed_addr, seed_data) in &phase2_seeds {
        if start.elapsed() > phase3_deadline {
            break;
        }
        let (addr, data_map, score) =
            simulated_anneal(data, addr_bits, seed_addr, *seed_data, &start, phase3_deadline, &mut rng);
        record_candidate(score, &addr, data_map);
    }
    // Compression score cannot distinguish data-bit permutations that tie at
    // the same local-optimum score under a correct address map — one real
    // fixture's true decode was found to be a genuine local optimum tied
    // with several other, wrong data_maps at the exact same score, and none
    // of Phase 3's finite restarts is guaranteed to land on any one specific
    // tied sibling over the others. The data-map space is small (8! =
    // 40,320) compared to the address-bit space, so it's worth scanning in
    // lexicographic order for the address map the pool's restarts already
    // agree on, scored by disassembly confirmation instead of compression
    // (which can't tell the siblings apart) — but `sweep_deadline` below
    // bounds this to a time-budget-sized prefix of that order, not a
    // guaranteed-complete scan of all 40,320: a fixture whose true data_map
    // sits deep in lexicographic order could still be missed under a tight
    // budget.
    if let Some((_, best_addr, _)) = top_candidates.first().cloned() {
        let diff = AddrDiff::from_full_map(&best_addr);
        let reordered = diff.apply_full(data);
        // Auto-Fix is scoped to Z80 only, so the sweep below always confirms
        // against Z80's decoder directly — no per-candidate processor guess
        // needed. Guessing the processor via `disasm::identify_processor` on
        // the pool's best-so-far candidate is a cross-processor comparison
        // that produces an unreliable ranking and must not be reintroduced.
        let sweep_deadline = phase3_deadline.saturating_add(sweep_reserve);

        // A qualifying sweep result must still reach the final ranking
        // tail below (that's the whole point of the sweep), but nothing
        // upstream bounds how many permutations can qualify. Keep only the
        // `SWEEP_POOL_CAP` best survivors, ranked by `disasm::coverage` —
        // the same disassembly-based signal the final ranking uses —
        // rather than by compression score, for the same reason
        // `top_candidates` above isn't ranked by compression score alone:
        // compression can prefer a wrong permutation over a genuine
        // decode.
        let mut sweep_survivors: Vec<(f64, [u32; 8])> = Vec::new();
        for perm in (0u32..8).permutations(8) {
            if start.elapsed() > sweep_deadline {
                break;
            }
            let mut data_map = [0u32; 8];
            data_map.copy_from_slice(&perm);
            let decoded = apply_data_lut(&reordered, &build_data_lut(&data_map));
            if disasm::qualifies(Processor::Z80, &decoded) {
                let coverage = disasm::coverage(Processor::Z80, &decoded);
                sweep_survivors.push((coverage, data_map));
                sweep_survivors.sort_by(|a, b| b.0.total_cmp(&a.0));
                sweep_survivors.truncate(SWEEP_POOL_CAP);
            }
        }
        for (_, data_map) in sweep_survivors {
            let decoded = apply_data_lut(&reordered, &build_data_lut(&data_map));
            top_candidates.push((compression_score(&decoded), best_addr.clone(), data_map));
        }
    }

    if top_candidates.is_empty() {
        // No restart got to run before the deadline (an extremely small time
        // budget) — fall back to the identity mapping unchanged, the same
        // default this function reported before disassembly-gated selection
        // existed.
        let identity: Vec<u32> = (0..addr_bits).collect();
        top_candidates.push((compression_score(data), identity, [0, 1, 2, 3, 4, 5, 6, 7]));
    }

    // Disassembly coverage is evaluated per pooled candidate, not just the
    // raw compression winner: compression score alone can pick a wrong
    // permutation over the true decode. Ranking the pool by
    // disassembly-confirmed coverage first, compression second, lets
    // disassembly actually overturn a compression-only mistake instead of
    // just labeling it low-confidence.
    struct Evaluated {
        addr: Vec<u32>,
        data_map: [u32; 8],
        compression_score: f64,
        processor: Processor,
        coverage: f64,
        decoded: Vec<u8>,
    }
    let mut ranked: Vec<Evaluated> = top_candidates
        .iter()
        .map(|(score, addr, data_map)| {
            let diff = AddrDiff::from_full_map(addr);
            let reordered = diff.apply_full(data);
            let lut = build_data_lut(data_map);
            let decoded = apply_data_lut(&reordered, &lut);
            // Auto-Fix is scoped to Z80 only - every candidate is confirmed
            // against Z80's decoder specifically, not
            // `disasm::identify_processor`'s cross-processor pick, which
            // produces an unreliable ranking and must not be reintroduced.
            let coverage = disasm::coverage(Processor::Z80, &decoded);
            Evaluated { addr: addr.clone(), data_map: *data_map, compression_score: *score, processor: Processor::Z80, coverage, decoded }
        })
        .collect();
    // Captured here, after decoding and disassembling every pooled
    // candidate, not right after the search loop: that per-candidate work
    // (up to CANDIDATE_POOL_SIZE + SWEEP_POOL_CAP full decodes plus a
    // disassembly pass each) is real time this function spends, and a
    // caller's time-budget assertion should see it.
    let elapsed = start.elapsed();
    // Sort by coverage descending as a heuristic starting order, then pick
    // the first candidate that also passes the absolute `disasm::qualifies`
    // gate for Z80 - not just the raw top-`coverage` entry, since the
    // top-by-coverage candidate can still be too short in absolute bytes.
    // If none of the pool qualifies, fall back to the raw top-`coverage`
    // candidate, reported as `Marginal` rather than silently discarded.
    ranked.sort_by(|a, b| b.coverage.total_cmp(&a.coverage));
    let confirmed_index = ranked.iter().position(|r| disasm::qualifies(r.processor, &r.decoded));
    let winner = &ranked[confirmed_index.unwrap_or(0)];

    let baseline_score = compression_score(data);
    let clear_improvement = winner.compression_score - baseline_score > CONFIDENCE_MARGIN;
    let confirmed = confirmed_index.is_some();

    progress(100, &format!("Done! Best score: {:.3} in {:.1}s", winner.compression_score, elapsed.as_secs_f64()));

    let confidence = if clear_improvement && confirmed {
        Confidence::High
    } else {
        Confidence::Marginal(
            ranked
                .iter()
                .map(|r| Candidate {
                    addr_map: r.addr.clone(),
                    data_map: r.data_map,
                    processor: r.processor,
                    compression_score: r.compression_score,
                    coverage: r.coverage,
                    preview: r.decoded.iter().take(256).copied().collect(),
                })
                .collect(),
        )
    };

    AutoFixResult {
        processor: winner.processor,
        addr_map: winner.addr.clone(),
        data_map: winner.data_map,
        score: winner.compression_score,
        coverage: winner.coverage,
        confidence,
        elapsed,
        max_k_covered,
        ascending_k_complete: !stopped_early,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derangement_count_matches_known_values() {
        assert_eq!(derangement_count(0), 1);
        assert_eq!(derangement_count(1), 0);
        assert_eq!(derangement_count(2), 1);
        assert_eq!(derangement_count(3), 2);
        assert_eq!(derangement_count(4), 9);
        assert_eq!(derangement_count(5), 44);
    }

    #[test]
    fn num_combinations_matches_known_values() {
        assert_eq!(num_combinations(15, 0), 1);
        assert_eq!(num_combinations(15, 1), 15);
        assert_eq!(num_combinations(15, 2), 105);
        assert_eq!(num_combinations(5, 5), 1);
    }

    #[test]
    fn derangements_by_support_k2_enumerates_only_true_derangements() {
        let all: Vec<(Vec<u32>, Vec<u32>)> = derangements_by_support(3, 2).collect();
        assert_eq!(
            all.len(),
            num_combinations(3, 2) as usize * derangement_count(2) as usize
        );
        for (positions, sources) in &all {
            assert_eq!(positions.len(), 2);
            assert_eq!(sources.len(), 2);
            assert_ne!(positions[0], sources[0]);
            assert_ne!(positions[1], sources[1]);
        }
    }

    #[test]
    fn find_scrambling_recovers_a_small_synthetic_address_swap_within_short_budget() {
        let size = 256usize;
        let addr_bits = 8u32;
        let mut correct = vec![0u8; size];
        for addr in 0..size {
            correct[addr] = if addr == 0 { 0xF3 } else { [0x00u8, 0x21, 0xCD, 0xC3][addr % 4] };
        }

        let mut swapped_map: Vec<u32> = (0..addr_bits).collect();
        swapped_map.swap(0, 1);
        let scramble_diff = AddrDiff::from_full_map(&swapped_map);
        let scrambled = scramble_diff.apply_full(&correct);

        let baseline_score = crate::scoring::compression_score(&correct);

        let result = find_scrambling(&scrambled, addr_bits, Duration::from_secs(5), 42, |_, _| {});

        let diff = AddrDiff::from_full_map(&result.addr_map);
        let reordered = diff.apply_full(&scrambled);
        let lut = build_data_lut(&result.data_map);
        let recovered = apply_data_lut(&reordered, &lut);
        let recovered_score = crate::scoring::compression_score(&recovered);

        assert!(
            recovered_score >= baseline_score,
            "auto-fix found a decoding scoring {recovered_score} below the known-correct baseline {baseline_score}"
        );
    }
}
