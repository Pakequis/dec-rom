//! Processor identification: `detect()` reports whether a candidate byte
//! buffer decodes as genuine Z80 code, by delegating to real disassembly
//! coverage (see `crate::disasm`) rather than a weighted scoring heuristic.
//! Auto-Fix is scoped to Z80 only - the `Processor` enum still names all
//! four historically supported CPUs (their decoders and pinout tables are
//! still in the codebase, see `crate::disasm`/`crate::pinouts`), but
//! `detect()` itself only ever confirms Z80.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Processor {
    Z80,
    M68000,
    Mos6502,
    I8086,
    Unknown,
}

/// Every real (non-`Unknown`) processor variant, for callers that need to
/// compare all of them — e.g. detecting the processor from several
/// candidate bit mappings rather than a single guess.
pub const ALL_PROCESSORS: [Processor; 4] =
    [Processor::Z80, Processor::M68000, Processor::Mos6502, Processor::I8086];

impl Processor {
    pub fn label(&self) -> &'static str {
        match self {
            Processor::Z80 => "Z80",
            Processor::M68000 => "68000",
            Processor::Mos6502 => "6502",
            Processor::I8086 => "8086",
            Processor::Unknown => "Unknown",
        }
    }
}

/// Buffer length below which `detect` reports `Unknown` without attempting
/// confirmation at all.
///
/// This is a second floor, independent of the per-processor run-length
/// thresholds in `disasm::confirmed_threshold`: those ask "is this run long
/// enough to be code rather than chance?", which is only a meaningful
/// question when the run stands out against a buffer substantially larger
/// than itself. The lowest per-processor threshold is 128 bytes (68000's,
/// whose decoder rejects nearly all random input), and 128 bytes out of a
/// 200-byte buffer is not a measurement, it is the whole buffer. At 2KB that
/// same bar is under 7% of the buffer, and well clear of the ~34-byte longest
/// valid stretch random bytes manage under that decoder at that size. 2KB is
/// also the smallest EPROM dump size this project realistically sees.
///
/// This only guarantees a buffer at this size is *large enough to measure
/// at all* — it does not mean every processor gets a fair shot at this size.
/// The per-processor thresholds are absolute byte counts, not fractions, so
/// Z80 (threshold 11,000) and 8086 (2,500) can never confirm on a buffer at
/// or near 2KB: a buffer that small cannot contain an 11,000-byte run in the
/// first place. Only 68000 (threshold 128) can meaningfully confirm here;
/// 6502 (2,000) is borderline. Which processors are even reachable at a
/// given buffer size is decided entirely by the thresholds above, not by
/// this constant — a separate, larger limitation documented in `qualifies`'s
/// own doc comment (see its Z80-small-buffer residual note).
const MIN_CONFIRMABLE_LEN: usize = 2048;

pub fn detect(data: &[u8]) -> Processor {
    if data.len() < MIN_CONFIRMABLE_LEN {
        return Processor::Unknown;
    }
    // Confirmation is an absolute-byte gate, not a fraction of data.len() -
    // see `disasm::qualifies`'s doc comment for the measured numbers Z80's
    // threshold was calibrated from (real fixtures span 8KB-128KB, so a
    // fixed fraction of buffer length let the same absolute amount of real
    // code pass or fail depending only on file size, and let a tiny buffer
    // clear a small fractional bar with one lucky decode).
    if crate::disasm::qualifies(Processor::Z80, data) {
        Processor::Z80
    } else {
        Processor::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_unknown_for_short_data() {
        assert_eq!(detect(&[0u8; 4]), Processor::Unknown);
    }

    // A dedicated "short window that still clears the per-processor
    // threshold" regression test (as this module had before Auto-Fix
    // narrowed to Z80 only, using a 6502 fixture) can't be reconstructed
    // for Z80: Z80's own `confirmed_threshold` (11,000 bytes) already
    // exceeds `MIN_CONFIRMABLE_LEN` (2,048 bytes), so no window shorter
    // than `MIN_CONFIRMABLE_LEN` can ever clear Z80's threshold in the
    // first place - the scenario this test class exists to catch is
    // impossible for Z80 by construction, not just untested (see
    // `MIN_CONFIRMABLE_LEN`'s own doc comment, which already noted only
    // 68000/6502 could meaningfully confirm at this size).
}
