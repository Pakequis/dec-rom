//! Fitness signals for the Auto-Fix search (`crate::autofix`).
//!
//! - `compression_score`: candidates that decode to genuine code/data compress
//!   better than incorrect address-bit permutations, since only the correct
//!   address order preserves local byte-level redundancy (repeated sequences,
//!   structured tables). It is blind to the data-bit permutation, which only
//!   relabels byte values.
//! - `control_flow_score`: counts Z80 `CALL` instructions whose target lands
//!   right after an instruction that ends a routine. It depends on the actual
//!   byte values and on where each byte sits, so it sees both the data-bit
//!   and the address-bit permutation.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

/// Higher is better. `0.0` for empty input. A ratio of e.g. `0.6` means the
/// compressed form is 40% of the original size.
///
/// Uses zlib's fastest compression level, not its best: this function is
/// called once per address-pair swap the search tries, on the whole file, so
/// it is on the search's critical path. Only the *relative order* between
/// candidates' scores matters here, never the absolute compressed size
/// (nothing compressed by this function is ever written to disk), and the
/// fastest level preserves that order closely enough for ranking.
pub fn compression_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut encoder = ZlibEncoder::new(Vec::with_capacity(data.len() / 2), Compression::fast());
    encoder.write_all(data).expect("writing to an in-memory Vec cannot fail");
    let compressed = encoder.finish().expect("finishing an in-memory zlib stream cannot fail");
    1.0 - (compressed.len() as f64 / data.len() as f64)
}

/// Reusable buffer for `control_flow_score_with`, so a caller scoring tens of
/// thousands of candidates in a loop doesn't allocate once per candidate.
#[derive(Default)]
pub struct ControlFlowScratch {
    targets: Vec<u16>,
}

/// Load addresses are tried in steps of this many bytes (4KB): Z80 systems
/// map ROMs at page-aligned addresses (an MSX cartridge at 0x4000 or 0x8000,
/// a BIOS at 0x0000), and where a given dump was mapped isn't known upfront.
const LOAD_ADDRESS_STEP: usize = 0x1000;

/// Number of Z80 `CALL` instructions in `data` (unconditional `CD nn nn` and
/// conditional `C4/CC/D4/DC/E4/EC/F4/FC nn nn`) whose 16-bit target falls
/// inside the buffer, right after an instruction that unconditionally leaves
/// a routine: `RET` (`C9`), `JP (HL)` (`E9`), `JP nn` (`C3 nn nn`) or `JR e`
/// (`18 e`). Higher is better.
///
/// Real code calls subroutines, and a subroutine starts where the previous
/// one ended, so in a correct decode a large share of calls satisfy this. A
/// wrong data-bit permutation turns the opcode and operand bytes into other
/// values, and a wrong address-bit permutation moves the routines away from
/// where the operands point, so in both cases the count collapses to what
/// chance produces. Measured on real 16KB-64KB MSX ROMs: 420 to 1,030 for
/// the correct decode, against at most 74 for random bytes of the same sizes
/// even after searching for the permutation that maximizes it.
///
/// Every byte position is treated as a possible `CALL` opcode, without
/// following instruction boundaries: an operand byte that happens to equal a
/// `CALL` opcode adds a spurious candidate, but its target only counts if it
/// also follows a terminator, which chance rarely provides.
///
/// The buffer's load address is unknown, so every multiple of
/// `LOAD_ADDRESS_STEP` that keeps the whole buffer inside the 64KB address
/// space is tried and the best count is returned.
pub fn control_flow_score(data: &[u8]) -> u32 {
    control_flow_score_with(data, &mut ControlFlowScratch::default())
}

/// Same as `control_flow_score`, reusing `scratch` between calls.
pub fn control_flow_score_with(data: &[u8], scratch: &mut ControlFlowScratch) -> u32 {
    let size = data.len();
    let targets = &mut scratch.targets;
    targets.clear();
    for window in data.windows(3) {
        let opcode = window[0];
        if opcode == 0xCD || opcode & 0xC7 == 0xC4 {
            targets.push(u16::from_le_bytes([window[1], window[2]]));
        }
    }

    let mut best = 0u32;
    let mut base = 0usize;
    while base + size <= 0x1_0000 {
        let mut hits = 0u32;
        for &target in targets.iter() {
            let target = target as usize;
            if target > base && target < base + size {
                let offset = target - base;
                let follows_terminator = matches!(data[offset - 1], 0xC9 | 0xE9)
                    || (offset >= 3 && data[offset - 3] == 0xC3)
                    || (offset >= 2 && data[offset - 2] == 0x18);
                if follows_terminator {
                    hits += 1;
                }
            }
        }
        best = best.max(hits);
        base += LOAD_ADDRESS_STEP;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repetitive_data_scores_higher_than_random_noise() {
        let repetitive: Vec<u8> = (0..4096u32).map(|i| (i % 8) as u8).collect();
        // A fixed pseudo-random sequence, not actual randomness (which
        // would make this test flaky) — a simple LCG produces byte-value
        // noise with no repeating structure for a compressor to exploit.
        let mut seed: u64 = 12345;
        let noise: Vec<u8> = (0..4096u32)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 56) as u8
            })
            .collect();

        let repetitive_score = compression_score(&repetitive);
        let noise_score = compression_score(&noise);
        assert!(
            repetitive_score > noise_score,
            "repetitive={repetitive_score} noise={noise_score}"
        );
    }

    #[test]
    fn empty_input_scores_zero() {
        assert_eq!(compression_score(&[]), 0.0);
    }

    #[test]
    fn control_flow_score_counts_calls_into_routine_starts() {
        // 0x0000: CALL 0x0005 ; RET ; (pad) ; 0x0005: RET
        let code = [0xCD, 0x05, 0x00, 0xC9, 0xC9, 0xC9];
        assert_eq!(control_flow_score(&code), 1);
    }

    #[test]
    fn control_flow_score_ignores_calls_into_the_middle_of_nowhere() {
        // CALL 0x0004, but the byte before 0x0004 is a NOP, not a terminator.
        let code = [0xCD, 0x04, 0x00, 0x00, 0x00, 0xC9];
        assert_eq!(control_flow_score(&code), 0);
    }

    #[test]
    fn control_flow_score_tries_page_aligned_load_addresses() {
        // Same routine layout as the first test, assembled to run at 0x4000.
        let code = [0xCD, 0x05, 0x40, 0xC9, 0xC9, 0xC9];
        assert_eq!(control_flow_score(&code), 1);
    }

    #[test]
    fn control_flow_score_handles_buffers_too_short_for_a_call() {
        assert_eq!(control_flow_score(&[]), 0);
        assert_eq!(control_flow_score(&[0xCD, 0x00]), 0);
    }
}
