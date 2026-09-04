//! Regression test for processor detection. Auto-Fix is scoped to Z80 only,
//! so `detect()` only ever confirms Z80 or reports `Unknown` — this file
//! checks that real Z80 code is recognized
//! (`detect_identifies_real_bios_decode_as_z80`).
//!
//! `detect()` misidentifying real non-Z80 code as Z80 (because Z80's
//! decoder is far more permissive than the others') and a real 68000 dump
//! being rejected at load time as oversized
//! (`reorganizer::Rom::load` rejects anything over 64KB, Z80's real 16-bit
//! address bus limit — see `MAX_FILE_SIZE`'s doc comment) are both real,
//! previously-hit failure modes, but are no longer covered by dedicated
//! non-Z80 fixtures here; the load-time size rejection itself is still
//! covered without needing a real 68000-sized fixture by
//! `reorganizer::tests::rom_load_rejects_oversized_file`.

use std::path::Path;

use dec_rom::detectors::{detect, Processor};

#[test]
fn detect_identifies_real_bios_decode_as_z80() {
    use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/bios.bin");
    let rom = Rom::load(&path).expect("samples/bios.bin must be present and load cleanly");

    // ITS Games' real scheme, confirmed to exactly match
    // `autofix::find_scrambling`'s own live High-confidence recovery of
    // this fixture. This corrects a stale value that had A13/A14
    // swapped (`..., 12, 14, 13]`) - that swap only relocates two whole 8KB
    // blocks relative to each other, invisible to both this function's own
    // Z80-vs-Unknown check and to a narrow known-plaintext fragment (both
    // high address bits happen to be set throughout that fragment), so the
    // error went undetected until the real scheme gave an independent
    // value to cross-check against.
    let addr_map: Vec<u32> = vec![0, 1, 3, 2, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14];
    let data_map: [u32; 8] = [0, 2, 1, 3, 4, 6, 5, 7];
    let diff = AddrDiff::from_full_map(&addr_map);
    let reordered = diff.apply_full(&rom.data);
    let lut = build_data_lut(&data_map);
    let recovered = apply_data_lut(&reordered, &lut);

    assert_eq!(detect(&recovered), Processor::Z80);
}
