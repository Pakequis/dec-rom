//! End-to-end Auto-Fix regression test for scrambles that are *not* in the
//! known-pattern library: each real ROM is decoded with its documented
//! scheme, scrambled again with arbitrary address-bit and data-bit
//! permutations, and `find_scrambling` has to undo that exactly, with high
//! confidence. The other end-to-end tests use each fixture's real scramble,
//! which the known-pattern library can suggest; this one exercises the
//! search with no such help.

use std::path::Path;
use std::time::Duration;

use dec_rom::autofix::{find_scrambling, Confidence};
use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};

/// (sample file, address map, data map) that decode each real fixture, as
/// cited in `known_patterns::company_specific_pairs`.
const FIXTURES: [(&str, &[u32], [u32; 8]); 6] = [
    ("bios.bin", &[0, 1, 3, 2, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14], [0, 2, 1, 3, 4, 6, 5, 7]),
    ("rom.bin", &[0, 1, 3, 2, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14], [0, 2, 1, 3, 4, 6, 5, 7]),
    ("msx_flip.bin", &[1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 0, 15, 9, 12, 11, 10], [1, 2, 4, 0, 7, 6, 5, 3]),
    ("ddx31 cks-B181h.rom", &[5, 4, 3, 0, 1, 12, 7, 11, 6, 8, 2, 13, 9, 10], [7, 6, 5, 0, 4, 1, 3, 2]),
    ("TPX102.BIN", &[5, 3, 1, 12, 7, 11, 13, 4, 6, 8, 2, 0, 9, 10], [6, 7, 5, 0, 4, 1, 3, 2]),
    ("MegaRAM Disk 256Kb cks-$6EB1h.ROM", &[4, 5, 2, 1, 0, 13, 8, 6, 11, 7, 3, 12, 10, 9, 14], [0, 7, 1, 6, 2, 5, 3, 4]),
];

fn transform(data: &[u8], addr_map: &[u32], data_map: &[u32; 8]) -> Vec<u8> {
    apply_data_lut(&AddrDiff::from_full_map(addr_map).apply_full(data), &build_data_lut(data_map))
}

/// Deterministic Fisher-Yates shuffle driven by a small xorshift generator,
/// so every run scrambles each fixture the same way.
fn shuffle(values: &mut [u32], state: &mut u64) {
    for i in (1..values.len()).rev() {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        values.swap(i, (*state % (i as u64 + 1)) as usize);
    }
}

#[test]
fn autofix_undoes_arbitrary_scrambles_of_every_real_fixture() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for (name, addr_map, data_map) in FIXTURES {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples").join(name);
        let rom = Rom::load(&path).unwrap_or_else(|e| panic!("samples/{name} must be present and load cleanly: {e}"));
        let correct = transform(&rom.data, addr_map, &data_map);

        for round in 0..3 {
            let mut addr_scramble: Vec<u32> = (0..rom.address_bits).collect();
            shuffle(&mut addr_scramble, &mut state);
            let mut data_scramble = [0u32, 1, 2, 3, 4, 5, 6, 7];
            // The last round scrambles the address bits only.
            if round < 2 {
                shuffle(&mut data_scramble, &mut state);
            }
            let scrambled = transform(&correct, &addr_scramble, &data_scramble);

            let result = find_scrambling(&scrambled, rom.address_bits, Duration::from_secs(60), 42, |_, _| {});

            let recovered = transform(&scrambled, &result.addr_map, &result.data_map);
            assert!(recovered == correct, "{name}, scramble {round}: the decode does not match the correct ROM");
            assert_eq!(result.confidence, Confidence::High, "{name}, scramble {round}");
        }
    }
}
