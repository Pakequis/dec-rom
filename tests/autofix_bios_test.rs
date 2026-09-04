//! Regression test for the Auto-Fix engine's Definition of Done: recover a
//! real EPROM dump's real scrambling and match its known-plaintext
//! fragment. This is the only place that ground truth may be referenced —
//! never from inside src/.

use std::path::Path;
use std::time::Duration;

use dec_rom::autofix::find_scrambling;
use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};

const EXPECTED_TEXT_START: usize = 0x7ed0;
const EXPECTED_TEXT: &[u8] = &[
    0x01, 0x09, 0x00, 0x09, 0x22, 0x62, 0xf8, 0xc9, 0x20, 0x49, 0x2e, 0x20, 0x54, 0x2e, 0x20, 0x53,
    0x2e, 0x20, 0x20, 0x00, 0x53, 0x69, 0x73, 0x74, 0x65, 0x6d, 0x61, 0x73, 0x20, 0x4c, 0x74, 0x64,
    0x61, 0x0d, 0x0a, 0x00, 0x00, 0x49, 0x54, 0x53, 0x20, 0x47, 0x61, 0x6d, 0x65, 0x73, 0x20, 0x00,
    0x00, 0x53, 0x74, 0x61, 0x20, 0x52, 0x2e, 0x20, 0x53, 0x61, 0x70, 0x75, 0x63, 0x61, 0x69, 0x20,
    0x4d, 0x47, 0x0d, 0x0a, 0x00, 0x00, 0x20, 0x20, 0x20, 0x46, 0x61, 0x6c, 0x74, 0x61, 0x20, 0x4a,
];

#[test]
fn autofix_recovers_known_bios_scrambling_within_budget() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/bios.bin");
    let rom = Rom::load(&path).expect("samples/bios.bin must be present and load cleanly");

    let budget = Duration::from_secs(60);
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

    let actual = &processed[EXPECTED_TEXT_START..EXPECTED_TEXT_START + EXPECTED_TEXT.len()];
    assert_eq!(
        actual, EXPECTED_TEXT,
        "decoded bytes at 0x{EXPECTED_TEXT_START:04x} did not match the known-correct text"
    );

    assert!(
        matches!(result.confidence, dec_rom::autofix::Confidence::High),
        "expected high confidence recovering samples/bios.bin's known-correct decoding"
    );
}
