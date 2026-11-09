//! Regression tests for find_scrambling's handling of files that don't need
//! fixing: a genuine, unscrambled, real-world Z80 dump should be recognized
//! as already correct (identity mapping, High confidence) rather than
//! spuriously "improved" into a wrong fix; a second, deliberately scrambled
//! case checks the opposite direction — a genuinely wrong file must not be
//! reported as already correct just because it coincidentally looks
//! plausible to Z80's disassembly check. Auto-Fix is scoped to Z80 only -
//! this file used to also check real 6502 and 68000 dumps the same way,
//! back when Auto-Fix considered all four processors; both were removed
//! since Auto-Fix has no reason to (and, for the 68000 dump, can no longer
//! even load a 128KB file at all — see `reorganizer::MAX_FILE_SIZE`).

use std::path::Path;
use std::time::Duration;

use dec_rom::autofix::{find_scrambling, Confidence};
use dec_rom::reorganizer::{apply_data_lut, build_data_lut, AddrDiff, Rom};

fn assert_recognizes_as_already_correct(path_relative: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path_relative);
    let rom = Rom::load(&path).unwrap_or_else(|e| panic!("{path_relative} must load cleanly: {e}"));

    let result = find_scrambling(&rom.data, rom.address_bits, Duration::from_secs(60), 42, |_, _| {});

    let diff = AddrDiff::from_full_map(&result.addr_map);
    let reordered = diff.apply_full(&rom.data);
    let lut = build_data_lut(&result.data_map);
    let decoded = apply_data_lut(&reordered, &lut);

    assert_eq!(
        decoded, rom.data,
        "{path_relative} is already correct but find_scrambling proposed a different decoding"
    );
    assert!(
        matches!(result.confidence, Confidence::High),
        "{path_relative}: expected High confidence recognizing the as-loaded file needs no correction"
    );
}

#[test]
fn recognizes_fort_decodificada_as_already_correct() {
    // This fixture is genuine, already-correct Z80 code (the
    // verified-correct decode of the fixture used in
    // tests/msx_flip_bitmath_test.rs).
    assert_recognizes_as_already_correct("samples/fort_decodificada.rom");
}

#[test]
fn does_not_report_high_confidence_on_a_genuinely_scrambled_file() {
    // A genuinely scrambled file must not be reported as already correct
    // just because its as-loaded bytes still decode as plausible Z80
    // instructions. This fixture is genuine Z80 code (the verified-correct
    // decode of the fixture used in tests/msx_flip_bitmath_test.rs) with a
    // single adjacent data-line swap applied. A data-only scramble leaves
    // the compression score untouched and is not one of the known-pattern
    // library's entries (its adjacent-pair-swap candidate swaps all four
    // pairs at once), so only the control-flow evidence can expose it.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/fort_decodificada.rom");
    let rom = Rom::load(&path).expect("samples/fort_decodificada.rom must be present and load cleanly");

    let data_map: [u32; 8] = [1, 0, 2, 3, 4, 5, 6, 7]; // D0<->D1 swap
    let lut = build_data_lut(&data_map);
    let scrambled = apply_data_lut(&rom.data, &lut);

    let result = find_scrambling(&scrambled, rom.address_bits, Duration::from_secs(60), 42, |_, _| {});

    let diff = AddrDiff::from_full_map(&result.addr_map);
    let reordered = diff.apply_full(&scrambled);
    let lut = build_data_lut(&result.data_map);
    let decoded = apply_data_lut(&reordered, &lut);

    assert!(decoded == rom.data, "the data-line swap was not undone exactly");
    assert!(
        matches!(result.confidence, Confidence::High),
        "expected High confidence undoing a single data-line swap of genuine Z80 code"
    );
}
