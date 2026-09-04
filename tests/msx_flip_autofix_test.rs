//! End-to-end Auto-Fix regression test against the large-support-size
//! msx_flip fixture: all 16 address bits scrambled, the worst case for
//! ascending-k. Unlike tests/msx_flip_bitmath_test.rs, this calls
//! find_scrambling with no special-casing for this file — same shape as
//! tests/autofix_bios_test.rs. This fixture's ground truth may be
//! referenced from any test file — never from inside src/.

use std::path::Path;
use std::time::Duration;

use dec_rom::autofix::find_scrambling;
use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};

#[test]
fn autofix_recovers_msx_flip_scrambling_within_budget() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/msx_flip.bin");
    let rom = Rom::load(&path).expect("samples/msx_flip.bin must be present and load cleanly");

    let expected_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/fort_decodificada.rom");
    let expected = std::fs::read(&expected_path).expect("samples/fort_decodificada.rom must be present");

    let budget = Duration::from_secs(300);
    let result = find_scrambling(&rom.data, rom.address_bits, budget, 42, |_, _| {});

    assert!(
        result.elapsed <= budget,
        "auto-fix exceeded the time budget: {:?}",
        result.elapsed
    );

    let diff = AddrDiff::from_full_map(&result.addr_map);
    let reordered = diff.apply_full(&rom.data);
    let lut = build_data_lut(&result.data_map);
    let processed = apply_data_lut(&reordered, &lut);

    assert_eq!(
        processed, expected,
        "auto-fix did not recover the exact msx_flip.bin decoding within {budget:?}"
    );
}
