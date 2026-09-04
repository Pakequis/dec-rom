//! Real physical package pinouts for the processors and EPROM sizes this
//! project supports, sourced from official manufacturer datasheets. Each
//! table below documents its own source citation.

use crate::detectors::Processor;

pub type PinTable = &'static [(u32, u32)];

/// Zilog Z80 CPU, 40-pin DIP. Source: Zilog *Z80 CPU User Manual*,
/// document UM008011-0816, Figure 3 "Z80 CPU I/O Pin Configuration".
const Z80_PINS: PinTable = &[
    (0, 30), (1, 31), (2, 32), (3, 33), (4, 34), (5, 35), (6, 36), (7, 37),
    (8, 38), (9, 39), (10, 40), (11, 1), (12, 2), (13, 3), (14, 4), (15, 5),
];

/// MOS 6502 / WDC W65C02S, 40-pin DIP (identical pinout across the whole
/// 40-pin-DIP 6502 family). Source: WDC W65C02S datasheet, Figure 3-1
/// "40 Pin PDIP Pinout". Pin 21 (between A11 and A12) is VSS, not an
/// address line.
const MOS6502_PINS: PinTable = &[
    (0, 9), (1, 10), (2, 11), (3, 12), (4, 13), (5, 14), (6, 15), (7, 16),
    (8, 17), (9, 18), (10, 19), (11, 20), (12, 22), (13, 23), (14, 24), (15, 25),
];

/// Motorola MC68000, 64-pin DIP. Source: Motorola "Advance Information —
/// MC68000 16-Bit Microprocessor" (ADI-814-R4), Section 10.1 "Pin
/// Assignments". No A0 pin exists — byte selection within a word uses
/// separate UDS/LDS pins, so the lowest address line is A1. Pin 49
/// (between A20 and A21) is VCC, not an address line.
const M68000_PINS: PinTable = &[
    (1, 29), (2, 30), (3, 31), (4, 32), (5, 33), (6, 34), (7, 35), (8, 36),
    (9, 37), (10, 38), (11, 39), (12, 40), (13, 41), (14, 42), (15, 43),
    (16, 44), (17, 45), (18, 46), (19, 47), (20, 48), (21, 50), (22, 51), (23, 52),
];

/// 2716 (2KB) and 2732 (4KB) EPROMs, 24-pin DIP, pin-compatible: the
/// 2732's extra A11 line only repurposes the 2716's Vpp pin (21), nothing
/// else moves. Source: STMicroelectronics M2716 and M2732A datasheets,
/// "DIP Pin Connections" figures.
const EPROM_2716_PINS: PinTable = &[
    (0, 8), (1, 7), (2, 6), (3, 5), (4, 4), (5, 3), (6, 2), (7, 1), (8, 23), (9, 22), (10, 19),
];
const EPROM_2732_PINS: PinTable = &[
    (0, 8), (1, 7), (2, 6), (3, 5), (4, 4), (5, 3), (6, 2), (7, 1), (8, 23), (9, 22), (10, 19), (11, 21),
];

/// 2764 (8KB) / 27128 (16KB) / 27256 (32KB) / 27512 (64KB) EPROMs, 28-pin
/// DIP, pin-compatible: each larger density only repurposes a previously
/// NC/program/Vpp pin (26→A13, 27→A14, 1→A15), nothing else moves. Source:
/// STMicroelectronics M2764A / M27128A / M27C256B / M27C512 datasheets,
/// "DIP Pin Connections" figures.
const EPROM_2764_PINS: PinTable = &[
    (0, 10), (1, 9), (2, 8), (3, 7), (4, 6), (5, 5), (6, 4), (7, 3), (8, 25), (9, 24), (10, 21), (11, 23), (12, 2),
];
const EPROM_27128_PINS: PinTable = &[
    (0, 10), (1, 9), (2, 8), (3, 7), (4, 6), (5, 5), (6, 4), (7, 3), (8, 25), (9, 24), (10, 21), (11, 23), (12, 2), (13, 26),
];
const EPROM_27256_PINS: PinTable = &[
    (0, 10), (1, 9), (2, 8), (3, 7), (4, 6), (5, 5), (6, 4), (7, 3), (8, 25), (9, 24), (10, 21), (11, 23), (12, 2), (13, 26), (14, 27),
];
const EPROM_27512_PINS: PinTable = &[
    (0, 10), (1, 9), (2, 8), (3, 7), (4, 6), (5, 5), (6, 4), (7, 3), (8, 25), (9, 24), (10, 21), (11, 23), (12, 2), (13, 26), (14, 27), (15, 1),
];

/// 27010 (128KB) EPROM, 32-pin DIP — its own table, *not* a 27512
/// extension: the package grows from 28 to 32 pins with a non-uniform
/// shift (most pins move by +2, Vcc moves by +4). Source: Intel 27C010
/// and STMicroelectronics M27C1001 datasheets, cross-checked between two
/// independent manufacturers.
const EPROM_27010_PINS: PinTable = &[
    (0, 12), (1, 11), (2, 10), (3, 9), (4, 8), (5, 7), (6, 6), (7, 5), (8, 27), (9, 26), (10, 23), (11, 25), (12, 4), (13, 28), (14, 29), (15, 3), (16, 2),
];

pub fn processor_pins(cpu: Processor) -> Option<PinTable> {
    match cpu {
        Processor::Z80 => Some(Z80_PINS),
        Processor::Mos6502 => Some(MOS6502_PINS),
        Processor::M68000 => Some(M68000_PINS),
        Processor::I8086 | Processor::Unknown => None,
    }
}

pub fn eprom_pins(addr_bits: u32) -> Option<PinTable> {
    match addr_bits {
        11 => Some(EPROM_2716_PINS),
        12 => Some(EPROM_2732_PINS),
        13 => Some(EPROM_2764_PINS),
        14 => Some(EPROM_27128_PINS),
        15 => Some(EPROM_27256_PINS),
        16 => Some(EPROM_27512_PINS),
        17 => Some(EPROM_27010_PINS),
        _ => None,
    }
}

/// Derives the "physically reversed bus" candidate for `cpu` wired to an
/// EPROM with `addr_bits` address lines: a connector or trace bundle
/// wired by physical pin position instead of by function — physical rank
/// `r` on the CPU connects to physical rank `addr_bits - 1 - r` on the
/// EPROM (a backward-plugged connector), instead of the correct wiring
/// (each chip's address line connected by function, regardless of
/// physical pin position — a PCB trace can route anywhere).
///
/// Only the CPU's own lowest `addr_bits` address lines are considered:
/// standard memory-map convention routes low-order address lines to
/// memory and high-order ones to chip-select/bank decoding, so a smaller
/// EPROM is never wired to a CPU's *high* address lines. Returns `None` if
/// `cpu`'s address bus doesn't reach `addr_bits` lines at all, or if this
/// project has no cited pinout for one side of the pair.
pub fn pinout_reversal_candidate(cpu: Processor, addr_bits: u32) -> Option<Vec<u32>> {
    let cpu_table = processor_pins(cpu)?;
    let eprom_table = eprom_pins(addr_bits)?;
    if (cpu_table.len() as u32) < addr_bits {
        return None;
    }

    let origin = cpu_table.iter().map(|&(bit, _)| bit).min().unwrap();
    let mut cpu_subset: Vec<(u32, u32)> =
        cpu_table.iter().copied().filter(|&(bit, _)| bit < origin + addr_bits).collect();
    cpu_subset.sort_by_key(|&(_, pin)| pin);

    let mut eprom_subset: Vec<(u32, u32)> = eprom_table.to_vec();
    eprom_subset.sort_by_key(|&(_, pin)| pin);

    let n = addr_bits as usize;
    let mut map = vec![0u32; n];
    for r in 0..n {
        let cpu_bit = cpu_subset[r].0;
        let eprom_bit = eprom_subset[n - 1 - r].0;
        map[eprom_bit as usize] = cpu_bit - origin;
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn z80_has_sixteen_address_lines_with_known_endpoints() {
        let pins = processor_pins(Processor::Z80).expect("Z80 has a cited pinout");
        assert_eq!(pins.len(), 16);
        assert!(pins.contains(&(0, 30)), "A0 should be pin 30");
        assert!(pins.contains(&(15, 5)), "A15 should be pin 5");
    }

    #[test]
    fn mos6502_has_sixteen_address_lines_with_known_endpoints() {
        let pins = processor_pins(Processor::Mos6502).expect("6502 has a cited pinout");
        assert_eq!(pins.len(), 16);
        assert!(pins.contains(&(0, 9)), "A0 should be pin 9");
        assert!(pins.contains(&(15, 25)), "A15 should be pin 25");
    }

    #[test]
    fn m68000_has_no_a0_and_reaches_a23() {
        let pins = processor_pins(Processor::M68000).expect("68000 has a cited pinout");
        assert_eq!(pins.len(), 23, "A1..A23, no A0");
        assert!(!pins.iter().any(|&(bit, _)| bit == 0), "68000 has no A0 pin");
        assert!(pins.contains(&(1, 29)), "A1 should be pin 29");
        assert!(pins.contains(&(23, 52)), "A23 should be pin 52");
    }

    #[test]
    fn i8086_and_unknown_have_no_pinout_table() {
        assert!(processor_pins(Processor::I8086).is_none());
        assert!(processor_pins(Processor::Unknown).is_none());
    }

    #[test]
    fn eprom_pins_covers_every_supported_size() {
        assert_eq!(eprom_pins(11).expect("2716").len(), 11);
        assert_eq!(eprom_pins(12).expect("2732").len(), 12);
        assert_eq!(eprom_pins(13).expect("2764").len(), 13);
        assert_eq!(eprom_pins(14).expect("27128").len(), 14);
        assert_eq!(eprom_pins(15).expect("27256").len(), 15);
        assert_eq!(eprom_pins(16).expect("27512").len(), 16);
        assert_eq!(eprom_pins(17).expect("27010").len(), 17);
        assert!(eprom_pins(10).is_none(), "no cited pinout below the smallest supported EPROM");
    }

    #[test]
    fn eprom_2764_and_27512_endpoints_match_the_datasheets() {
        let e2764 = eprom_pins(13).unwrap();
        assert!(e2764.contains(&(0, 10)), "2764 A0 should be pin 10");
        assert!(e2764.contains(&(12, 2)), "2764 A12 should be pin 2");

        let e27512 = eprom_pins(16).unwrap();
        assert!(e27512.contains(&(0, 10)), "27512 A0 should be pin 10 (28-pin family is pin-compatible)");
        assert!(e27512.contains(&(15, 1)), "27512 A15 should be pin 1");
    }

    #[test]
    fn eprom_27010_is_not_a_27512_extension() {
        let e27010 = eprom_pins(17).unwrap();
        // 27512's A0 is pin 10; the 27010's own datasheet gives A0 = pin 12,
        // a +2 shift, not the same pin number.
        assert!(e27010.contains(&(0, 12)), "27010 A0 should be pin 12, not 27512's pin 10");
        assert!(e27010.contains(&(16, 2)), "27010 A16 should be pin 2");
    }

    fn is_valid_permutation(map: &[u32]) -> bool {
        let mut seen = vec![false; map.len()];
        for &v in map {
            if v as usize >= map.len() || seen[v as usize] {
                return false;
            }
            seen[v as usize] = true;
        }
        true
    }

    #[test]
    fn every_valid_combination_produces_a_permutation() {
        let cpus = [Processor::Z80, Processor::Mos6502, Processor::M68000];
        for &cpu in cpus.iter() {
            for addr_bits in 11..=17u32 {
                if let Some(map) = pinout_reversal_candidate(cpu, addr_bits) {
                    assert_eq!(map.len(), addr_bits as usize, "{cpu:?}/{addr_bits} wrong length");
                    assert!(is_valid_permutation(&map), "{cpu:?}/{addr_bits} not a permutation: {map:?}");
                }
            }
        }
    }

    #[test]
    fn z80_and_6502_cannot_reach_the_27010() {
        assert!(pinout_reversal_candidate(Processor::Z80, 17).is_none());
        assert!(pinout_reversal_candidate(Processor::Mos6502, 17).is_none());
    }

    #[test]
    fn m68000_reaches_every_supported_eprom_size() {
        for addr_bits in 11..=17u32 {
            assert!(
                pinout_reversal_candidate(Processor::M68000, addr_bits).is_some(),
                "68000/{addr_bits} should be reachable (23 usable address lines)"
            );
        }
    }

    #[test]
    fn m68000_27010_candidate_matches_the_independently_hand_derived_value() {
        // Independently hand-derived by working through this function's
        // algorithm on paper against M68000_PINS/EPROM_27010_PINS (sorting
        // both by physical pin, pairing in reverse), without running any
        // code — not a real hardware fixture's key (no physical 68000/27010
        // board exists anywhere in this project), just an arithmetic
        // cross-check independent of this function's own implementation.
        // Exists because the round-trip tests in known_patterns.rs
        // construct their scramble from this function's own output, which
        // can't by itself distinguish a physically-correct derivation from
        // a well-formed-but-wrong one.
        let map = pinout_reversal_candidate(Processor::M68000, 17).expect("68000 reaches 17 bits");
        assert_eq!(map, vec![6, 7, 8, 9, 10, 11, 12, 13, 2, 3, 5, 4, 14, 1, 0, 15, 16]);
    }

    #[test]
    fn i8086_never_produces_a_candidate() {
        for addr_bits in 11..=17u32 {
            assert!(pinout_reversal_candidate(Processor::I8086, addr_bits).is_none());
        }
    }

}
