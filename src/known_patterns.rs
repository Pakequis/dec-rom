//! A small, explicit library of address/data-bit permutations documented as
//! real hardware wiring conventions - generic, composable single-axis
//! conventions (full reversal, nibble swap, adjacent byte/pair swaps, Z80's
//! real-chip-pinout bus reversal — see `crate::pinouts`), cross-produced
//! together in `try_known_patterns`'s Tier 2, plus a growing set of cited
//! real commercial MSX cartridge-converter/copier interfaces (Fort Games,
//! DDX 3.1, TPX102, MegaRAM Disk) in `company_specific_pairs`, tried as
//! atomic (address, data) pairs in Tier 1 (Fort Games, DDX 3.1, TPX102,
//! MegaRAM Disk, ITS Games) - tried as literal candidates before the
//! expensive search, gated by disassembly confirmation (layer 3) since
//! it's cheap for only a handful of candidates.
//!
//! Auto-Fix is scoped to Z80 only: every candidate here is confirmed and
//! ranked against Z80's own decoder specifically, not compared across
//! multiple processors.
//!
//! Anti-cheating constraint: every pattern here is a genuinely general,
//! documented hardware convention — never a permutation invented purely to
//! make one fixture pass. A pattern that happens to exactly match one of
//! this project's sample fixtures is allowed *only* once that fixture's
//! real-world origin is confirmed and cited (e.g. the Fort Games data map
//! below is that company's real commercial EPROM wiring, not an arbitrary
//! permutation chosen to defeat a test) — never added just because it makes
//! a known sample decode correctly.

use crate::detectors::Processor;
use crate::disasm;
use crate::pinouts::pinout_reversal_candidate;
use crate::reorganizer::{apply_data_lut, build_data_lut, AddrDiff};
use crate::scoring::compression_score;

/// A known-pattern candidate that is neither the identity mapping (which
/// proposes no change at all, and is therefore always safe to confirm
/// regardless of what compression or disassembly say about it) nor a real
/// compression improvement over the as-loaded baseline must not be trusted
/// just because it coincidentally clears some processor's `disasm::qualifies`
/// threshold. This mirrors the main search's own compression-improvement
/// bar (see `autofix::CONFIDENCE_MARGIN`) rather than importing it directly
/// — this module doesn't depend on `autofix` and shouldn't start now.
const MIN_CLEAR_IMPROVEMENT: f64 = 0.05;

#[derive(Debug, Clone)]
pub struct KnownPatternResult {
    pub addr_map: Vec<u32>,
    pub data_map: [u32; 8],
    pub processor: Processor,
    pub coverage: f64,
    pub compression_score: f64,
}

fn address_reverse(addr_bits: u32) -> Vec<u32> {
    (0..addr_bits).rev().collect()
}

/// Swaps each contiguous 4-bit group with its mirror-position group, e.g.
/// for 8 bits: `[4,5,6,7,0,1,2,3]`. A trailing partial group (bit count not
/// a multiple of 4) is left in place.
fn address_nibble_swap(addr_bits: u32) -> Vec<u32> {
    let full_nibbles = addr_bits / 4;
    let mut map: Vec<u32> = (0..addr_bits).collect();
    for pair in 0..full_nibbles / 2 {
        let a = pair * 4;
        let b = (full_nibbles - 1 - pair) * 4;
        for k in 0..4 {
            map.swap((a + k) as usize, (b + k) as usize);
        }
    }
    map
}

/// Same idea as `address_nibble_swap`, at 8-bit granularity.
fn address_byte_swap(addr_bits: u32) -> Vec<u32> {
    let full_bytes = addr_bits / 8;
    let mut map: Vec<u32> = (0..addr_bits).collect();
    for pair in 0..full_bytes / 2 {
        let a = pair * 8;
        let b = (full_bytes - 1 - pair) * 8;
        for k in 0..8 {
            map.swap((a + k) as usize, (b + k) as usize);
        }
    }
    map
}

fn candidate_address_maps(addr_bits: u32) -> Vec<Vec<u32>> {
    let mut maps = vec![(0..addr_bits).collect::<Vec<u32>>(), address_reverse(addr_bits)];
    if addr_bits >= 4 {
        maps.push(address_nibble_swap(addr_bits));
    }
    if addr_bits >= 8 {
        maps.push(address_byte_swap(addr_bits));
    }
    // Auto-Fix is scoped to Z80 only - only Z80's own real-chip pinout is a
    // physically meaningful "this EPROM was wired backward next to this
    // CPU" candidate for the systems this tool now targets. The
    // 6502/68000/8086 pinout tables in `crate::pinouts` stay in the
    // codebase (still covered by that module's own unit tests) but are no
    // longer tried here.
    if let Some(map) = pinout_reversal_candidate(Processor::Z80, addr_bits) {
        maps.push(map);
    }
    maps
}

fn candidate_data_maps() -> Vec<[u32; 8]> {
    vec![
        [0, 1, 2, 3, 4, 5, 6, 7], // identity
        [7, 6, 5, 4, 3, 2, 1, 0], // full bit reversal
        [4, 5, 6, 7, 0, 1, 2, 3], // nibble swap
        [1, 0, 3, 2, 5, 4, 7, 6], // adjacent-pair swap (a documented D0<->D1-style PCB wiring mistake)
    ]
}

/// Cited, real commercial (address, data) scramble pairs, tried as *atomic*
/// units — never cross-produced against `candidate_address_maps`/
/// `candidate_data_maps` or against each other. A specific converter's
/// address wiring and data wiring aren't independent hardware facts the way
/// the generic single-axis conventions above are (a full address-bit
/// reversal really is unrelated to any given data-line convention, so
/// cross-producing those is fine) - they're one wiring job, and pairing one
/// company's address map with a *different* company's (or the generic
/// library's) data map isn't a real-world hypothesis worth testing at all.
///
/// This split exists because trying it the naive (cross-product) way was
/// measured to actively pick the *wrong* answer: for real DDX 3.1, TPX102,
/// and MegaRAM Disk EPROM dumps, the genuinely correct (address, data)
/// pair does clear both of `try_known_patterns`'s confirmation bars - but
/// so does that same correct address map paired with an unrelated data map
/// already in `candidate_data_maps` (identity, for the two MSX ROMs; nibble swap, for
/// MegaRAM Disk), and by sheer coincidence of Z80's permissive decoder, the
/// *wrong* pairing scored higher `disasm::coverage` than the genuinely
/// correct one in every case. `compression_score` couldn't break the tie
/// either, for the same documented reason a pure data-bit permutation can't
/// move it much (see `try_known_patterns`'s Bar 2 doc comment) - the correct
/// and incorrect pairings scored within 0.0001 of each other. Verified
/// concretely: the correct MegaRAM Disk pairing decodes to a real FAT-style
/// boot sector (`EB FE 90` jump, `"RAM-DISK"` OEM name); the
/// coverage-preferred wrong pairing decodes to unrecognizable bytes at the
/// same offset. Evaluating cited pairs atomically, ahead of the generic
/// cross-product, means a confirmed real-world pair is never even compared
/// against an accidental combination assembled from unrelated conventions.
fn company_specific_pairs(addr_bits: u32) -> Vec<(Vec<u32>, [u32; 8])> {
    let mut pairs = Vec::new();
    if addr_bits == 16 {
        // Fort Games, the real commercial EPROM wiring used by that
        // company's cartridge converter. The address side is also
        // literally `pinout_reversal_candidate(Z80, 16)` - kept as an
        // explicit pair here anyway rather than relying on that
        // coincidence, so this scheme stays correct even if the
        // pinout-derived candidate ever changes for unrelated reasons.
        if let Some(addr_map) = pinout_reversal_candidate(Processor::Z80, 16) {
            pairs.push((addr_map, [1, 2, 4, 0, 7, 6, 5, 3]));
        }
    }
    if addr_bits == 14 {
        // DDX 3.1's real commercial EPROM wiring. DDX 3.0 shares the same
        // interface family and table, but is not added here separately
        // since no genuinely scrambled DDX 3.0 dump has been verified
        // against it yet - a real DDX 3.0 EPROM dump turned out to already
        // be unscrambled. Verified against a real DDX 3.1 EPROM dump:
        // recovers a genuine MSX ROM header ("AB" signature).
        pairs.push((vec![5, 4, 3, 0, 1, 12, 7, 11, 6, 8, 2, 13, 9, 10], [7, 6, 5, 0, 4, 1, 3, 2]));
        // TPX102's real commercial EPROM wiring, verified against a real
        // TPX102 EPROM dump: also recovers a genuine MSX ROM header.
        pairs.push((vec![5, 3, 1, 12, 7, 11, 13, 4, 6, 8, 2, 0, 9, 10], [6, 7, 5, 0, 4, 1, 3, 2]));
    }
    if addr_bits == 15 {
        // MegaRAM Disk's real commercial EPROM wiring, verified against a
        // real MegaRAM Disk EPROM dump: recovers a genuine FAT-style boot
        // sector (0xEB..0x90 jump, "RAM-DISK" OEM name).
        pairs.push((vec![4, 5, 2, 1, 0, 13, 8, 6, 11, 7, 3, 12, 10, 9, 14], [0, 7, 1, 6, 2, 5, 3, 4]));
        // ITS Games' real commercial EPROM wiring, confirmed to exactly
        // match `autofix::find_scrambling`'s own live, independently-run
        // High-confidence recovery of a real ITS Games EPROM dump - not
        // just trusted on say-so, since an earlier, differently-sourced
        // value for that exact file (a stale hardcoded key with A13/A14
        // swapped) turned out to be wrong, undetected until an independent
        // value became available to cross-check against. Also verified
        // against a second, different ITS Games EPROM dump from the same
        // company: recovers a genuine MSX ROM header ("AB" signature).
        pairs.push((vec![0, 1, 3, 2, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14], [0, 2, 1, 3, 4, 6, 5, 7]));
    }
    pairs
}

/// Checks a single (address map, data map) candidate against the two
/// independent confirmation bars every candidate in this module must clear,
/// regardless of which tier (`company_specific_pairs` or the generic
/// `candidate_address_maps` × `candidate_data_maps` cross-product) proposed
/// it. Returns `None` if either bar fails.
///
/// **Bar 1: `disasm::qualifies`.**
///
/// **Bar 2: identity, or genuine compression improvement over `data` as
/// loaded.** `qualifies` alone isn't enough: on a genuine, already-correct,
/// unscrambled real 68000 dump (from back when this function still
/// considered non-Z80 candidates), a full data-bit reversal
/// coincidentally decoded into a long enough run that Z80's permissive
/// decoder confirmed it — `qualifies` true, despite corrupting 77.6% of the
/// file's bytes. The same mechanism can still happen within Z80-only
/// scope too: a data-bit permutation applied uniformly to every byte is a
/// fixed relabeling of the byte alphabet, so it preserves the
/// byte-frequency histogram and all repeated-substring structure exactly,
/// meaning a general compressor's output size barely changes between the
/// correct file and a wrong permutation of this shape — and Z80's decoder
/// is permissive enough that a wrong permutation can still coincidentally
/// chain a long "valid" run. Requiring either the identity mapping (which
/// proposes no change at all, and needs no compression evidence since
/// there's nothing to improve) or a real, clear compression gain closes
/// this: a non-identity candidate that doesn't actually compress the file
/// better is not trusted just because it coincidentally clears the
/// absolute threshold.
///
/// **Known, accepted trade-off:** requiring compression improvement means a
/// scramble that is *purely* a data-bit permutation (no address-bit
/// component) — which, by the reasoning above, barely changes
/// `compression_score` even for the genuinely correct recovery — can no
/// longer be confirmed by this function, even though earlier versions of
/// this code could. This isn't a silent regression: falling through to the
/// full search (layer 2) is always the safe direction (it either finds the
/// same answer more slowly, or degrades to `Confidence::Marginal`), and the
/// alternative (confirming purely by `qualifies`) is exactly the mechanism
/// that let the 68000 corruption above through undetected. Closing this gap
/// without reopening that one would need a sharper signal than either bar
/// alone provides — not attempted here.
fn evaluate_pair(data: &[u8], addr_bits: u32, addr_map: Vec<u32>, data_map: [u32; 8]) -> Option<KnownPatternResult> {
    let addr_diff = AddrDiff::from_full_map(&addr_map);
    let reordered = addr_diff.apply_full(data);
    let lut = build_data_lut(&data_map);
    let processed = apply_data_lut(&reordered, &lut);

    let identity_addr: Vec<u32> = (0..addr_bits).collect();
    let is_identity = addr_map == identity_addr && data_map == [0, 1, 2, 3, 4, 5, 6, 7];
    let clear_improvement = compression_score(&processed) - compression_score(data) > MIN_CLEAR_IMPROVEMENT;
    if !disasm::qualifies(Processor::Z80, &processed) || !(is_identity || clear_improvement) {
        return None;
    }
    Some(KnownPatternResult {
        coverage: disasm::coverage(Processor::Z80, &processed),
        compression_score: compression_score(&processed),
        addr_map,
        data_map,
        processor: Processor::Z80,
    })
}

/// Tries this module's small explicit library of candidates against `data`
/// in two priority tiers - `company_specific_pairs` first, then the generic
/// `candidate_address_maps` × `candidate_data_maps` cross-product - and
/// returns the highest-`disasm::coverage`-ranked candidate that clears
/// `evaluate_pair`'s two bars within whichever tier produced a hit. `None`
/// means no candidate in either tier clears both bars for `data` — the
/// caller should fall through to the full search (layer 2).
pub fn try_known_patterns(data: &[u8], addr_bits: u32) -> Option<KnownPatternResult> {
    // Tier 1: cited, real-world (address, data) pairs, evaluated as atomic
    // units and given priority over Tier 2 below - see
    // `company_specific_pairs`'s own doc comment for why this priority
    // matters (a real, confirmed pair must never have to out-rank an
    // accidental combination assembled from unrelated generic conventions).
    let mut atomic_hits: Vec<KnownPatternResult> = company_specific_pairs(addr_bits)
        .into_iter()
        .filter_map(|(addr_map, data_map)| evaluate_pair(data, addr_bits, addr_map, data_map))
        .collect();
    if !atomic_hits.is_empty() {
        atomic_hits.sort_by(|a, b| b.coverage.total_cmp(&a.coverage));
        return Some(atomic_hits.remove(0));
    }

    // Tier 2: the generic single-axis conventions, cross-produced. Auto-Fix
    // is scoped to Z80 only: every candidate here is confirmed and ranked
    // against Z80's own decoder specifically, via
    // `disasm::coverage`/`qualifies`, rather than
    // `disasm::identify_processor`'s cross-processor pick. This is what
    // makes plain `coverage`-ratio ranking safe below — its own doc comment
    // already says the ratio is only a fair comparison *within the same
    // processor's decoder*, which is now always true here, so no near-tie
    // tie-break machinery is necessary.
    let mut candidates: Vec<KnownPatternResult> = Vec::new();
    for addr_map in candidate_address_maps(addr_bits) {
        for data_map in candidate_data_maps() {
            if let Some(result) = evaluate_pair(data, addr_bits, addr_map.clone(), data_map) {
                candidates.push(result);
            }
        }
    }
    candidates.sort_by(|a, b| b.coverage.total_cmp(&a.coverage));
    candidates.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reorganizer::{apply_data_lut, build_data_lut, AddrDiff};

    // A short, hand-built repeating-opcode buffer (like the one originally
    // drafted here) is NOT usable for these tests: `disasm::qualifies`'s
    // Z80 threshold (11,000 qualifying bytes) needs a real, sizeable buffer,
    // and the qualifying-run diversity floor requires at least 8 distinct
    // opcodes within one run — a handful of instructions cycling through 3
    // opcodes clears neither bar regardless of buffer size. Use a real,
    // already-correct Z80 EPROM dump instead (the verified-correct decode
    // of a real scrambled fixture, see `tests/msx_flip_bitmath_test.rs` —
    // no ground-truth permutation key needed here, since this file's own
    // byte order already *is* the correct one), large enough (64KB) to
    // clear Z80's threshold comfortably, and genuinely diverse.
    //
    // The dump lives in the local, untracked `samples/` directory; returns
    // `None` (after a notice) when it is absent, so tests that need it skip
    // instead of failing on a clean checkout.
    fn real_z80_code() -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/fort_decodificada.rom");
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("skipping: samples/fort_decodificada.rom not available ({e})");
                None
            }
        }
    }

    /// The mathematical inverse of an `AddrDiff::from_full_map`-style
    /// permutation: if `map[i] = j` (output bit i comes from input bit j),
    /// the inverse satisfies `inverse[j] = i`. Needed to *construct* a
    /// scrambled fixture from known-correct data using a map that isn't
    /// self-inverse — getting this backwards silently applies the map
    /// forwards a second time instead of undoing it.
    fn invert_addr_map(map: &[u32]) -> Vec<u32> {
        let mut inverse = vec![0u32; map.len()];
        for (i, &src) in map.iter().enumerate() {
            inverse[src as usize] = i as u32;
        }
        inverse
    }

    #[test]
    fn recovers_a_full_address_bit_reversal() {
        let Some(correct) = real_z80_code() else { return };
        let addr_bits = (correct.len() as u32).trailing_zeros();
        let reverse_map: Vec<u32> = (0..addr_bits).rev().collect();
        let scramble_diff = AddrDiff::from_full_map(&reverse_map);
        let scrambled = scramble_diff.apply_full(&correct);

        let result = try_known_patterns(&scrambled, addr_bits).expect("a full reversal is in the known-pattern library");

        let diff = AddrDiff::from_full_map(&result.addr_map);
        let reordered = diff.apply_full(&scrambled);
        let lut = build_data_lut(&result.data_map);
        let recovered = apply_data_lut(&reordered, &lut);
        assert_eq!(recovered, correct);
    }

    #[test]
    fn returns_none_for_data_with_no_recognizable_pattern() {
        // A buffer with no code-like structure under any of this module's
        // patterns should not be forced into a low-confidence match. Same
        // size as the real fixture above, so this isn't trivially passing
        // just because the buffer is too small for anything to qualify.
        //
        // Uses a real (fixed-seed, so still deterministic) LCG, not a
        // straight `(i * 167 + 13) % 256` arithmetic ramp: that formula
        // (gcd(167, 256) = 1) is just byte values 0..255 visited in a fixed
        // order, repeating every 256 bytes — far more structured than actual
        // noise, and it was observed, while implementing an earlier version
        // of this test, to coincidentally clear a processor's `qualifies`
        // threshold purely from that repeating structure, not from anything
        // resembling real code. Per this module's own calibration note
        // (`disasm::qualifies`'s doc comment), that's this test's bad luck
        // with one over-structured formula, not a threshold-calibration
        // gap, so the fix is a genuine pseudo-random generator here
        // (matching the one already used in `crate::scoring`'s own noise
        // test) rather than loosening anything in `disasm`.
        let Some(real) = real_z80_code() else { return };
        let addr_bits = (real.len() as u32).trailing_zeros();
        let mut seed: u64 = 424242;
        let noise: Vec<u8> = (0..real.len() as u32)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 56) as u8
            })
            .collect();
        assert!(try_known_patterns(&noise, addr_bits).is_none());
    }

    #[test]
    fn does_not_propose_a_non_improving_change_to_already_correct_code() {
        // Reproduces a real defect found originally against a genuine 68000
        // dump (before Auto-Fix's scope narrowed to Z80 only): a full
        // data-bit reversal of an already-correct file can coincidentally
        // decode into a run long enough for Z80's permissive decoder to
        // confirm — `qualifies` true despite corrupting most of the file's
        // bytes — outranking identity by coverage and getting returned as
        // a false "fix". Kept as a live regression guard using real,
        // already-correct Z80 code since the same mechanism can reproduce
        // within Z80-only scope too, not just cross-processor.
        let Some(correct) = real_z80_code() else { return };
        let addr_bits = (correct.len() as u32).trailing_zeros();

        let result = try_known_patterns(&correct, addr_bits);

        match result {
            None => {} // also acceptable: Layer 1 declining to match at all
            Some(r) => {
                let identity_addr: Vec<u32> = (0..addr_bits).collect();
                assert_eq!(r.addr_map, identity_addr, "a non-identity address map was proposed for already-correct data");
                assert_eq!(r.data_map, [0, 1, 2, 3, 4, 5, 6, 7], "a non-identity data map was proposed for already-correct data");
            }
        }
    }

    #[test]
    fn recovers_a_z80_pinout_derived_bus_reversal() {
        let Some(correct) = real_z80_code() else { return };
        let addr_bits = (correct.len() as u32).trailing_zeros();
        let recovery_map = pinout_reversal_candidate(Processor::Z80, addr_bits)
            .expect("Z80 has 16 address lines, reaching this file's EPROM size");

        let scramble_map = invert_addr_map(&recovery_map);
        let scramble_diff = AddrDiff::from_full_map(&scramble_map);
        let scrambled = scramble_diff.apply_full(&correct);

        let result = try_known_patterns(&scrambled, addr_bits)
            .expect("the Z80 pinout-derived candidate is in the known-pattern library");

        let diff = AddrDiff::from_full_map(&result.addr_map);
        let reordered = diff.apply_full(&scrambled);
        let lut = build_data_lut(&result.data_map);
        let recovered = apply_data_lut(&reordered, &lut);
        assert_eq!(recovered, correct);
    }
}
