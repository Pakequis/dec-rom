//! Real per-processor disassembly: confirms a candidate byte buffer is
//! genuine code (not noise that happens to compress or score well) and
//! identifies which of the 4 supported processors it is.

mod i8086;
mod m68000;
mod mos6502;
mod z80;

use std::collections::HashSet;

use crate::detectors::{Processor, ALL_PROCESSORS};

/// A contiguous run of consecutively-valid decoded instructions only counts
/// as "real code" (rather than a degenerate coincidence) if it clears both
/// this length floor and `MIN_QUALIFYING_RUN_DIVERSITY` below. A run
/// shorter than this, however it decoded, is too small a sample to mean
/// anything — this is what stops an 8-byte buffer from confirming on one
/// lucky decode (see `qualifies`'s doc comment for the measured numbers
/// this was calibrated from, via `examples/scratch_disasm_coverage.rs`).
const MIN_QUALIFYING_RUN_BYTES: usize = 64;

/// Minimum number of distinct first-opcode-byte values a run must contain
/// to count as "real code". A run of one instruction repeated over and
/// over (e.g. all-zero data, which decodes as the same 1-byte opcode for
/// several processors) has diversity 1 no matter how long it runs, and is
/// rejected regardless of `MIN_QUALIFYING_RUN_BYTES` — see `qualifies`'s
/// doc comment for the measured numbers this was calibrated from.
const MIN_QUALIFYING_RUN_DIVERSITY: usize = 8;

/// Absolute qualifying-run byte count `data` must reach under `processor`'s
/// own decoder to be reported as that specific processor by `detect()`,
/// rather than `Unknown`.
///
/// This is per-processor and not one shared number because the four decoders
/// differ by two orders of magnitude in how much of a random byte stream
/// they accept, so the same run length is overwhelming evidence for one and
/// unremarkable for another: the Z80 decoder can only reject an ED-prefixed
/// secondary byte, so random bytes chain thousands of "valid" bytes by
/// chance, while the 68000 decoder rejects nearly every random word and
/// never sustains more than a few dozen. See `qualifies`'s doc comment for
/// each processor's measured noise ceiling and genuine-code floor.
pub fn confirmed_threshold(processor: Processor) -> usize {
    match processor {
        Processor::Z80 => 11_000,
        Processor::M68000 => 128,
        Processor::Mos6502 => 2_000,
        Processor::I8086 => 2_500,
        // `qualifies` returns false for `Unknown` before ever asking for a
        // threshold (there is no decoder to run); an unreachable bar keeps
        // this a total function without inventing a meaningful value.
        Processor::Unknown => usize::MAX,
    }
}

/// One processor's instruction-length decoder: `Some(length)` for a valid
/// instruction starting at `bytes[0]`, `None` for an undefined opcode or a
/// buffer too short to contain it.
type Decoder = fn(&[u8]) -> Option<usize>;

fn decoder_for(processor: Processor) -> Option<Decoder> {
    match processor {
        Processor::Z80 => Some(z80::instruction_length),
        Processor::M68000 => Some(m68000::instruction_length),
        Processor::Mos6502 => Some(mos6502::instruction_length),
        Processor::I8086 => Some(i8086::instruction_length),
        Processor::Unknown => None,
    }
}

/// Walks `data` as a sequential instruction stream from offset 0 using
/// `decode`, the same way a real disassembler recovers from an illegal
/// opcode: the current run breaks and resynchronizes one byte at a time,
/// so an isolated invalid byte ends that run rather than merely being
/// skipped over within it. Returns the byte length and distinct
/// first-opcode-byte count of whichever run is longest among those for
/// which `accept(run_bytes, run_diversity)` returns true, so a run that
/// fails `accept` never counts, even if it happens to be the longest run
/// in the buffer (e.g. an all-zero buffer's one giant same-opcode run,
/// rejected by an `accept` that checks diversity).
///
/// Shared by `longest_qualifying_run_bytes` (`accept` = the two calibrated
/// floors below) and the diagnostic functions at the bottom of this module
/// (`accept` = always true, or the floors again but returning the full
/// stats instead of just the byte count) so the walking logic itself is
/// only written once.
fn longest_run_matching(
    decode: Decoder,
    data: &[u8],
    mut accept: impl FnMut(usize, usize) -> bool,
) -> (usize, usize) {
    let mut best_bytes = 0usize;
    let mut best_diversity = 0usize;
    let mut current_run = 0usize;
    let mut current_run_opcodes: HashSet<u8> = HashSet::new();
    let mut i = 0usize;

    while i < data.len() {
        match decode(&data[i..]) {
            Some(len) if len > 0 => {
                current_run += len;
                current_run_opcodes.insert(data[i]);
                i += len;
            }
            _ => {
                if current_run > best_bytes && accept(current_run, current_run_opcodes.len()) {
                    best_bytes = current_run;
                    best_diversity = current_run_opcodes.len();
                }
                current_run = 0;
                current_run_opcodes.clear();
                i += 1;
            }
        }
    }
    if current_run > best_bytes && accept(current_run, current_run_opcodes.len()) {
        best_bytes = current_run;
        best_diversity = current_run_opcodes.len();
    }
    (best_bytes, best_diversity)
}

fn qualifying_run_accept(run_bytes: usize, run_diversity: usize) -> bool {
    run_bytes >= MIN_QUALIFYING_RUN_BYTES && run_diversity >= MIN_QUALIFYING_RUN_DIVERSITY
}

fn longest_qualifying_run_bytes(decode: Decoder, data: &[u8]) -> usize {
    longest_run_matching(decode, data, qualifying_run_accept).0
}

/// Fraction (0.0..=1.0) of `data` covered by its *longest qualifying run*
/// (see `longest_qualifying_run_bytes`) of consecutively-valid instructions
/// for `processor`.
///
/// This measures the longest qualifying run rather than the total
/// valid-byte count because the total saturates near 1.0 on almost any
/// input, real or noise: both the Z80 and 6502 decoders accept nearly any
/// byte sequence as *some* defined instruction, so an unbroken chain of
/// short 1-byte resyncs can rack up a high total without ever reflecting a
/// real, sustained decode. The longest qualifying run doesn't have that
/// failure mode — noise breaks it constantly, while genuine code decodes
/// in long, opcode-diverse unbroken stretches.
///
/// This ratio is meant for *relative* ranking between same-length
/// candidates (e.g. comparing several candidate decodes of the same source
/// file against each other, where the fraction is scale-safe since all
/// candidates share that file's length). For an absolute
/// confirmation decision (is this actually a specific processor, or
/// Unknown?) across buffers of different sizes, use `qualifies` instead.
pub fn coverage(processor: Processor, data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let Some(decode) = decoder_for(processor) else {
        return 0.0;
    };
    longest_qualifying_run_bytes(decode, data) as f64 / data.len() as f64
}

/// Whether `data` contains a genuine, sufficiently long and opcode-diverse
/// decoded run for `processor` — the confirmation gate `detect()` (in
/// `detectors.rs`) uses to decide between reporting a specific processor
/// and `Unknown`. Unlike `coverage`'s ratio, this compares an **absolute**
/// qualifying-run byte count against `confirmed_threshold(processor)`, so
/// buffers of very different sizes (real fixtures here range 8KB-128KB) are
/// held to the same bar for "this is real code," rather than the same fixed
/// *fraction* of the buffer's own length — which let real code at
/// different sizes clear wildly different absolute bars, and let an 8-byte
/// buffer clear a small fractional bar with one lucky decode.
///
/// Every threshold is read off measurements produced by
/// `examples/scratch_disasm_coverage.rs`
/// (`cargo run --release --example scratch_disasm_coverage -- N`), which
/// reports, per processor, the qualifying-run byte count for the real
/// fixtures (whole file and per window) and for N independent
/// pseudo-random buffers at each of 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 128KB,
/// 256KB and 512KB (512KB was this project's maximum supported file size
/// when this sweep was designed; `reorganizer::MAX_FILE_SIZE` is now 64KB,
/// so the sweep's own top end is a conservative superset of today's actual
/// ceiling rather than an exact match for it — 8086's own count is capped
/// lower at the two largest sizes, since its
/// decoder is the slowest of the four — see `sample_count_for` in that
/// example). Noise runs grow with both buffer size and sample count, so the
/// ceilings below are the worst case seen across all nine sizes at N=1000,
/// not a smaller sample's — a run at N=200 reliably finds slightly lower
/// ceilings (e.g. Z80 5,949 instead of 6,497) simply from having sampled
/// less of the same distribution, not from anything about the code
/// changing. All the numbers below already have `MIN_QUALIFYING_RUN_BYTES`=64
/// and `MIN_QUALIFYING_RUN_DIVERSITY`=8 applied, as `qualifies` does.
///
/// - **Z80, threshold 11,000.** Worst noise run 6,497 (N=1000). Genuine floor
///   20,892 (a real, verified-correct 64KB Z80 EPROM decode); a real 32KB
///   Z80 EPROM correctly decoded reaches 29,069.
/// - **6502, threshold 2,000.** Worst noise run 1,395 (N=1000). Genuine floor
///   3,741 (a real 8KB 6502 dump).
/// - **68000, threshold 128.** Noise never produces a qualifying run at all
///   (worst *unfiltered* run 50 bytes at N=1000, creeping up with size/count
///   but still short of the 64-byte floor). Genuine floor 262
///   (a real 128KB 68000 dump).
/// - **8086, threshold 2,500.** Worst noise run 1,137 (N=1000). No genuine
///   floor — this project has no 8086 fixture.
///
/// Each threshold with a floor to bracket sits at or just under the
/// geometric midpoint of its own noise ceiling and its own lowest genuine
/// floor, so the margin is proportional on both sides rather than tight
/// against one of them (68000's uses 64 — the shortest run that can qualify
/// at all — as its noise-side bound, since noise never reaches even that).
/// 8086's has no genuine floor to bracket, so it is set at ~2.2x its noise
/// ceiling: with nothing to validate the upper side against, wrongly
/// reporting `Unknown` for real 8086 code is the safer of the two errors.
/// All four are unreachable by the degenerate all-zero baseline (0
/// qualifying bytes for every processor, since one repeated opcode has no
/// diversity) and by any buffer smaller than the threshold itself.
///
/// Noise runs keep creeping upward with buffer size, which is exactly why the
/// sweep above already reaches to 512KB — beyond even this project's actual
/// 64KB file-size ceiling (`reorganizer::MAX_FILE_SIZE`) — rather than stopping at the
/// real-fixture range (8KB-128KB): each threshold still sits comfortably
/// above its own worst case measured there, 1.4x (6502) to 2.2x (8086) above,
/// with 68000 never producing a qualifying run at any size tested. No buffer
/// of random bytes has confirmed as any processor at any size or sample count
/// tested up to N=1000.
///
/// **Residual, inherent to the decoders rather than to these numbers:**
/// - Z80 genuine code and Z80 noise overlap below roughly 16KB — 16KB
///   windows of a real, verified-correct Z80 EPROM decode bottom out at
///   3,141 qualifying bytes, *below* the 4,495 random bytes already reach
///   in a buffer half that size — so no threshold can separate them there.
///   11,000 resolves the overlap toward
///   `Unknown`: a genuine Z80 dump much smaller than ~16KB is reported
///   `Unknown` rather than letting noise confirm as Z80.
/// - The 68000 decoder covers a bounded instruction subset, so genuine 68000
///   code only sustains 262 qualifying bytes even across a 128KB fixture,
///   and most single 8KB windows of it produce no qualifying run at all.
///   68000 confirmation therefore rests on a far shorter run than the other
///   processors' — sound against noise (which never qualifies at all) but
///   weak in absolute terms, and the reason a real 68000 dump is still
///   identified as Z80 (12,087 Z80-qualifying bytes, over Z80's
///   threshold) rather than as the 68000 code it is.
/// - 8086's threshold has never been checked against real 8086 code.
pub fn qualifies(processor: Processor, data: &[u8]) -> bool {
    let Some(decode) = decoder_for(processor) else {
        return false;
    };
    longest_qualifying_run_bytes(decode, data) >= confirmed_threshold(processor)
}

/// Diagnostic only, not used by `coverage`/`qualifies`: the plain longest
/// contiguous valid run's raw byte length and its distinct first-opcode-byte
/// count, computed *without* applying `MIN_QUALIFYING_RUN_BYTES`/
/// `MIN_QUALIFYING_RUN_DIVERSITY` — used by
/// `examples/scratch_disasm_coverage.rs` to measure real fixture and noise
/// baselines so those two constants (and each `confirmed_threshold` value)
/// are picked from actual data instead of guessed. Seeing the unfiltered run
/// matters for calibration: when a processor's *qualifying* run is 0 in
/// noise, only the plain run shows how much margin its threshold has.
pub fn longest_run_diagnostics(processor: Processor, data: &[u8]) -> (usize, usize) {
    let Some(decode) = decoder_for(processor) else {
        return (0, 0);
    };
    longest_run_matching(decode, data, |_, _| true)
}

/// Diagnostic only, not used by `coverage`/`qualifies`: same as
/// `longest_qualifying_run_bytes`, but also returns the winning run's
/// distinct-opcode count (not just its byte length) — used by
/// `examples/scratch_disasm_coverage.rs` to show the qualifying run's full
/// stats side by side with the unfiltered ones from `longest_run_diagnostics`.
pub fn qualifying_run_diagnostics(processor: Processor, data: &[u8]) -> (usize, usize) {
    let Some(decode) = decoder_for(processor) else {
        return (0, 0);
    };
    longest_run_matching(decode, data, qualifying_run_accept)
}

/// Whichever processor achieves the highest `coverage` on `data`, and that
/// coverage value. A tie between two processors that both score above 0.0
/// favors whichever comes first in `ALL_PROCESSORS`'s order, since the fold
/// only replaces the incumbent on a strictly greater score. Data on which
/// *every* processor scores 0.0 — degenerate input such as an all-zero
/// buffer, where the one giant repeated-opcode run fails the diversity floor
/// for all four — returns `Processor::Unknown`, the value the fold starts
/// from, rather than an arbitrary first entry.
pub fn identify_processor(data: &[u8]) -> (Processor, f64) {
    ALL_PROCESSORS
        .iter()
        .map(|&p| (p, coverage(p, data)))
        .fold((Processor::Unknown, 0.0), |acc, cur| if cur.1 > acc.1 { cur } else { acc })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_is_zero_for_empty_data() {
        assert_eq!(coverage(Processor::Z80, &[]), 0.0);
    }

    #[test]
    fn coverage_is_zero_for_unknown_processor() {
        assert_eq!(coverage(Processor::Unknown, &[0x00, 0x00]), 0.0);
    }

    #[test]
    fn all_zero_buffer_does_not_confirm_as_any_processor() {
        // A run of one repeated instruction, however long, has no opcode
        // diversity and must not count as a qualifying run — this is the
        // real hazard: a wrong candidate's surviving fill regions must not
        // be able to out-score a correct decode's genuinely varied code.
        let all_zero = vec![0u8; 65536];
        for &p in ALL_PROCESSORS.iter() {
            assert!(
                !qualifies(p, &all_zero),
                "{p:?} must not confirm on degenerate all-zero data"
            );
        }
    }

    #[test]
    fn each_processor_has_its_own_confirmed_threshold_above_its_own_measured_noise_ceiling() {
        // Structural check: the confirmation bar must actually be
        // per-processor, because the four decoders differ enormously in how
        // much of a random byte stream they accept. Z80 rejects only an
        // ED-prefixed secondary byte, so a long chance run is common in
        // noise and its bar has to be high; 68000 and 6502 reject most
        // random bytes, so a much shorter run is already strong evidence.
        // One shared number cannot be right for both ends of that range.
        let z80 = confirmed_threshold(Processor::Z80);
        let m68000 = confirmed_threshold(Processor::M68000);
        let mos6502 = confirmed_threshold(Processor::Mos6502);
        assert_ne!(z80, m68000, "Z80's permissive decoder needs a different bar than M68000's");
        assert!(z80 > m68000, "z80={z80} m68000={m68000}");
        assert!(z80 > mos6502, "z80={z80} mos6502={mos6502}");

        // The worst run each processor's decoder was measured producing on
        // pseudo-random bytes (see `qualifies`'s doc comment for how these
        // were obtained; 68000's is its unfiltered run, since no random buffer
        // ever produced a qualifying 68000 run at all). Re-simulating that
        // here would cost far more than a unit test should, but the invariant
        // it establishes - every threshold sits above its own decoder's
        // measured noise ceiling - is worth pinning: a future edit that
        // lowers one back under its ceiling fails here instead of silently
        // starting to confirm random data.
        for (processor, noise_ceiling) in [
            (Processor::Z80, 6_497usize),
            (Processor::M68000, 50),
            (Processor::Mos6502, 1_395),
            (Processor::I8086, 1_137),
        ] {
            let threshold = confirmed_threshold(processor);
            assert!(
                threshold > noise_ceiling,
                "{processor:?}: threshold {threshold} is not above its measured noise ceiling {noise_ceiling}"
            );
        }
    }

    #[test]
    fn tiny_buffer_with_one_lucky_decode_does_not_confirm() {
        // A short buffer that happens to decode as one or two valid
        // instructions must not clear an absolute-byte confirmation gate —
        // the old fractional gate could be fooled by exactly this.
        let tiny = [0x00u8; 8]; // decodes as some short valid run for at least one processor
        for &p in ALL_PROCESSORS.iter() {
            assert!(!qualifies(p, &tiny), "{p:?} must not confirm on an 8-byte buffer");
        }
    }
}
