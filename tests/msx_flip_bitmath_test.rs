//! Bit-math correctness check against a second real-world scrambled dump,
//! independent of the one used elsewhere: an EPROM dump with all 16
//! address bits moved from identity, with a fully known scrambling key and
//! fully known correct decode. This is the only place that key may be
//! referenced outside of tests/msx_flip_autofix_test.rs — never from
//! inside src/.

use std::path::Path;

use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};

#[test]
fn msx_flip_key_decodes_to_fort_decodificada_exactly() {
    let scrambled_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/msx_flip.bin");
    let scrambled = Rom::load(&scrambled_path).expect("samples/msx_flip.bin must be present and load cleanly");

    let expected_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/fort_decodificada.rom");
    let expected = std::fs::read(&expected_path).expect("samples/fort_decodificada.rom must be present");

    // Address map, inverted from the scheme's naive "ROM Ai -> EPROM Aj"
    // reading (map[physical_bit] = logical_bit_source).
    let addr_map: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 0, 15, 9, 12, 11, 10];
    // Data map, used exactly as read from the scheme (map[logical_bit] = physical_bit_source).
    let data_map: [u32; 8] = [1, 2, 4, 0, 7, 6, 5, 3];

    let diff = AddrDiff::from_full_map(&addr_map);
    let reordered = diff.apply_full(&scrambled.data);
    let lut = build_data_lut(&data_map);
    let recovered = apply_data_lut(&reordered, &lut);

    assert_eq!(recovered.len(), expected.len());
    assert_eq!(
        recovered, expected,
        "applying fort.txt's key to msx_flip.bin did not reproduce fort_decodificada.rom byte-for-byte"
    );
}

#[test]
fn pinout_derived_z80_candidate_matches_fort_txt_key() {
    use dec_rom::detectors::Processor;
    use dec_rom::pinouts::pinout_reversal_candidate;

    let derived = pinout_reversal_candidate(Processor::Z80, 16)
        .expect("Z80 has 16 address lines, reaching this file's 16-bit EPROM");
    let expected: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 0, 15, 9, 12, 11, 10];
    assert_eq!(
        derived, expected,
        "pinout_reversal_candidate(Z80, 16) no longer reproduces fort.txt's real key — \
         either the Z80/27512 pinout tables in src/pinouts.rs regressed, or the derivation \
         algorithm changed"
    );
}
