//! Regression tests for the real commercial MSX interface schemes in
//! `known_patterns.rs` (DDX 3.1, TPX102, MegaRAM Disk, ITS Games),
//! confirmed from real scheme-exchange files for each interface. Unlike
//! the fixture used in `tests/msx_flip_bitmath_test.rs`,
//! these fixtures have no separately-shipped "already correct" reference
//! file to compare against byte-for-byte, so each test instead checks two
//! independent signals: `try_known_patterns` picks the exact expected
//! (addr_map, data_map) pair out of the whole library, and the recovered
//! bytes open with a real, recognizable signature (an MSX ROM header's "AB"
//! magic, or a FAT-style boot sector's jump + OEM name) rather than just
//! clearing `disasm::qualifies`'s bar. No ground-truth key is referenced
//! from inside src/ - only the resulting maps, which are already public
//! knowledge once cited in `known_patterns.rs` itself.

use std::path::Path;

use dec_rom::known_patterns::try_known_patterns;
use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};

fn assert_already_correct(path: &str) {
    let rom = Rom::load(Path::new(path)).unwrap_or_else(|e| panic!("{path} must load cleanly: {e}"));
    let identity_addr: Vec<u32> = (0..rom.address_bits).collect();
    let result = try_known_patterns(&rom.data, rom.address_bits)
        .unwrap_or_else(|| panic!("{path} clears disasm::qualifies as-loaded, so Layer 1 must recognize it"));
    assert_eq!(result.addr_map, identity_addr, "{path} was already correct - no address permutation should be proposed");
    assert_eq!(result.data_map, [0, 1, 2, 3, 4, 5, 6, 7], "{path} was already correct - no data permutation should be proposed");
}

fn recover(path: &str) -> (Vec<u32>, [u32; 8], Vec<u8>) {
    let rom = Rom::load(Path::new(path)).unwrap_or_else(|e| panic!("{path} must load cleanly: {e}"));
    let result = try_known_patterns(&rom.data, rom.address_bits)
        .unwrap_or_else(|| panic!("{path} must be recovered by the known-pattern library"));
    let diff = AddrDiff::from_full_map(&result.addr_map);
    let reordered = diff.apply_full(&rom.data);
    let lut = build_data_lut(&result.data_map);
    let recovered = apply_data_lut(&reordered, &lut);
    (result.addr_map, result.data_map, recovered)
}

#[test]
fn recovers_ddx31_as_a_genuine_msx_rom_header() {
    let (addr_map, data_map, recovered) = recover("samples/ddx31 cks-B181h.rom");
    assert_eq!(addr_map, vec![5, 4, 3, 0, 1, 12, 7, 11, 6, 8, 2, 13, 9, 10]);
    assert_eq!(data_map, [7, 6, 5, 0, 4, 1, 3, 2]);
    assert_eq!(&recovered[..2], b"AB", "a real MSX ROM starts with the 'AB' cartridge signature");
}

#[test]
fn recovers_tpx102_as_a_genuine_msx_rom_header() {
    let (addr_map, data_map, recovered) = recover("samples/TPX102.BIN");
    assert_eq!(addr_map, vec![5, 3, 1, 12, 7, 11, 13, 4, 6, 8, 2, 0, 9, 10]);
    assert_eq!(data_map, [6, 7, 5, 0, 4, 1, 3, 2]);
    assert_eq!(&recovered[..2], b"AB", "a real MSX ROM starts with the 'AB' cartridge signature");
}

#[test]
fn recovers_megaram_disk_as_a_genuine_boot_sector() {
    let (addr_map, data_map, recovered) = recover("samples/MegaRAM Disk 256Kb cks-$6EB1h.ROM");
    assert_eq!(addr_map, vec![4, 5, 2, 1, 0, 13, 8, 6, 11, 7, 3, 12, 10, 9, 14]);
    assert_eq!(data_map, [0, 7, 1, 6, 2, 5, 3, 4]);
    assert_eq!(&recovered[..3], &[0xEB, 0xFE, 0x90], "a FAT-style boot sector starts with a short jump + NOP");
    assert_eq!(&recovered[3..11], b"RAM-DISK", "the boot sector's OEM name field must read 'RAM-DISK'");
}

/// These two real DDX 1.2/DDX 3.0 EPROM dumps turned out, on inspection,
/// to already be genuine unscrambled Z80/MSX code as loaded - not
/// scrambled dumps of the DDX 1.2/DDX 3.0 schemes their origin suggests.
/// Both start with the real "AB" MSX ROM
/// signature as-loaded and are full of coherent Portuguese disk-BASIC
/// driver text ("Digital Design Eletronica Ltda", "Disco protegido",
/// "MSXDOS  SYS", ...) - a real product, not corrupted data. These tests
/// guard the other direction from `recovers_*` above: DDX 3.1 and
/// TPX102's atomic pairs in `company_specific_pairs` share these files'
/// own 14-bit address width, so Layer 1's Tier 1 tries them against these
/// files too - both must still lose to identity's own Bar 2 (no genuine
/// compression improvement over already-correct data), not hijack an
/// already-correct file into a false "fix".
#[test]
fn does_not_alter_ddx12_which_is_already_correct() {
    assert_already_correct("samples/DDX12 cks-$650Dh.ROM");
}

#[test]
fn does_not_alter_ddx30_which_is_already_correct() {
    assert_already_correct("samples/DDX30 cks-$1141h.ROM");
}

/// This fixture's own known-correct text fragment (also used by
/// tests/autofix_bios_test.rs, which confirms `autofix::find_scrambling`'s
/// full search reaches the same recovery via a different, slower path).
const BIOS_EXPECTED_TEXT_START: usize = 0x7ed0;
const BIOS_EXPECTED_TEXT: &[u8] = &[
    0x01, 0x09, 0x00, 0x09, 0x22, 0x62, 0xf8, 0xc9, 0x20, 0x49, 0x2e, 0x20, 0x54, 0x2e, 0x20, 0x53,
    0x2e, 0x20, 0x20, 0x00, 0x53, 0x69, 0x73, 0x74, 0x65, 0x6d, 0x61, 0x73, 0x20, 0x4c, 0x74, 0x64,
    0x61, 0x0d, 0x0a, 0x00, 0x00, 0x49, 0x54, 0x53, 0x20, 0x47, 0x61, 0x6d, 0x65, 0x73, 0x20, 0x00,
    0x00, 0x53, 0x74, 0x61, 0x20, 0x52, 0x2e, 0x20, 0x53, 0x61, 0x70, 0x75, 0x63, 0x61, 0x69, 0x20,
    0x4d, 0x47, 0x0d, 0x0a, 0x00, 0x00, 0x20, 0x20, 0x20, 0x46, 0x61, 0x6c, 0x74, 0x61, 0x20, 0x4a,
];

#[test]
fn recovers_bios_bin_via_layer_1_matching_the_known_plaintext() {
    let (addr_map, data_map, recovered) = recover("samples/bios.bin");
    assert_eq!(addr_map, vec![0, 1, 3, 2, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14]);
    assert_eq!(data_map, [0, 2, 1, 3, 4, 6, 5, 7]);
    assert_eq!(&recovered[BIOS_EXPECTED_TEXT_START..BIOS_EXPECTED_TEXT_START + BIOS_EXPECTED_TEXT.len()], BIOS_EXPECTED_TEXT);
}

#[test]
fn recovers_rom_bin_as_a_genuine_msx_rom_header() {
    // Same company (ITS Games), same wiring as the fixture used above,
    // verified independently since it's a different fixture with its own
    // content.
    let (addr_map, data_map, recovered) = recover("samples/rom.bin");
    assert_eq!(addr_map, vec![0, 1, 3, 2, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14]);
    assert_eq!(data_map, [0, 2, 1, 3, 4, 6, 5, 7]);
    assert_eq!(&recovered[..2], b"AB", "a real MSX ROM starts with the 'AB' cartridge signature");
}
