//! Address/data bit permutation math and EPROM file I/O for scrambled ROM dumps.

use std::fs;
use std::path::Path;

/// Z80 has a 16-bit address bus (see `crate::pinouts`), so no genuine Z80
/// EPROM dump can exceed 64KB - this project's Auto-Fix is scoped to Z80
/// only, so this is a real physical limit, not an arbitrary cap. Rejecting
/// an oversized file at load time is also what stops a non-Z80 dump from
/// ever reaching disassembly confirmation in the first place - a larger
/// dump from a wider-address-bus processor (e.g. a 128KB 68000 dump) could
/// otherwise coincidentally clear Z80's own confirmation threshold purely
/// by chance, a false positive this size cap rules out structurally
/// instead.
pub const MAX_FILE_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Rom {
    pub data: Vec<u8>,
    pub address_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrDiff {
    pub positions: Vec<u32>,
    pub sources: Vec<u32>,
    mask_clear: usize,
}

/// Extension-based format sniff shared by load and save: `.hex`/`.HEX` means
/// Intel HEX, anything else (`.bin`, `.rom`, no extension, ...) means raw
/// binary.
fn is_hex_path(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("hex"))
}

impl Rom {
    pub fn load(path: &Path) -> Result<Rom, String> {
        let raw = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let is_hex = is_hex_path(path);
        let mut data = if is_hex { parse_intel_hex(&raw, path)? } else { raw };

        // Intel HEX records an exact address range, not necessarily a full
        // EPROM page (e.g. a dump that's genuinely all-0xFF past the last
        // written address is often just not encoded at all) - pad up to the
        // next power-of-two size with 0xFF, the EPROM-erased-state fill,
        // before applying the same size/shape validation below. A `.bin`
        // file is never padded: it's raw bytes, already expected to be an
        // exact power-of-two size, and silently padding one would hide a
        // genuinely malformed file instead of rejecting it.
        if is_hex && !data.is_empty() && !data.len().is_power_of_two() {
            data.resize(data.len().next_power_of_two(), 0xFF);
        }

        if data.len() > MAX_FILE_SIZE {
            return Err(format!(
                "file too large: {} bytes (max {}KB)",
                data.len(),
                MAX_FILE_SIZE / 1024
            ));
        }
        if data.is_empty() || !data.len().is_power_of_two() {
            return Err(format!(
                "file size {} is not a power of two (EPROM dumps must be)",
                data.len()
            ));
        }
        // Auto-Fix's search needs at least 2 address bits to have a source
        // and a target to swap (see `autofix::find_scrambling`'s own
        // `debug_assert!(addr_bits >= 2, ...)`, which release builds don't
        // enforce) - reject anything smaller here instead of letting the
        // search panic on it later.
        if data.len() < 4 {
            return Err(format!(
                "file size {} is too small (min 4 bytes / 2 address bits)",
                data.len()
            ));
        }
        let address_bits = data.len().trailing_zeros();
        Ok(Rom { data, address_bits })
    }

    /// Writes `data` to `path`, as Intel HEX if `path` ends in `.hex`/`.HEX`,
    /// raw binary otherwise - the save-side mirror of `load`'s format sniff.
    pub fn save(path: &Path, data: &[u8]) -> Result<(), String> {
        if is_hex_path(path) {
            Rom::save_hex(path, data)
        } else {
            fs::write(path, data).map_err(|e| format!("failed to write {}: {e}", path.display()))
        }
    }

    /// Exports `data` as Intel HEX: 16-byte data records in ascending
    /// address order, then a single end-of-file record.
    pub fn save_hex(path: &Path, data: &[u8]) -> Result<(), String> {
        if data.len() > u16::MAX as usize + 1 {
            return Err(format!(
                "{} bytes exceeds Intel HEX's 16-bit address range (max {})",
                data.len(),
                u16::MAX as usize + 1
            ));
        }
        let mut out = String::new();
        for chunk_start in (0..data.len()).step_by(16) {
            let chunk = &data[chunk_start..(chunk_start + 16).min(data.len())];
            let mut record = Vec::with_capacity(4 + chunk.len());
            record.push(chunk.len() as u8);
            record.extend_from_slice(&(chunk_start as u16).to_be_bytes());
            record.push(0x00); // data record
            record.extend_from_slice(chunk);
            write_intel_hex_record(&mut out, &record);
        }
        write_intel_hex_record(&mut out, &[0x00, 0x00, 0x00, 0x01]); // EOF record
        fs::write(path, out).map_err(|e| format!("failed to write {}: {e}", path.display()))
    }

    pub fn eprom_type(&self) -> String {
        match self.data.len() {
            2048 => "2716 (2KB)".to_string(),
            4096 => "2732 (4KB)".to_string(),
            8192 => "2764 (8KB)".to_string(),
            16384 => "27128 (16KB)".to_string(),
            32768 => "27256 (32KB)".to_string(),
            65536 => "27512 (64KB)".to_string(),
            n if n < 1024 => format!("{n} bytes"),
            n => format!("{}KB", n / 1024),
        }
    }
}

/// Two's complement of the sum of `bytes` mod 256 - the checksum field of
/// every Intel HEX record ensures the sum of the whole record (including
/// its own checksum byte) is `0` mod 256.
fn intel_hex_checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)).wrapping_neg()
}

/// Appends one Intel HEX record line for `fields` (byte count, address
/// high/low, record type, then any data bytes - everything except the
/// trailing checksum, which this computes) to `out`.
fn write_intel_hex_record(out: &mut String, fields: &[u8]) {
    out.push(':');
    for b in fields {
        out.push_str(&format!("{b:02X}"));
    }
    out.push_str(&format!("{:02X}\n", intel_hex_checksum(fields)));
}

/// One parsed Intel HEX record line, before its meaning (data / EOF /
/// address-extension / ...) is interpreted by `parse_intel_hex`.
struct HexRecord {
    address: u16,
    record_type: u8,
    data: Vec<u8>,
}

/// Parses a single `:LLAAAATT[DD...]CC` line. Validates the checksum and
/// the declared byte count against the line's actual length - a malformed
/// record here is a hard error rather than a silently skipped line: a
/// `.hex` file is exactly the kind of thing a user could have hand-edited
/// or a transfer could have corrupted, and silently dropping bytes from an
/// EPROM dump is worse than refusing to load it.
fn parse_hex_record(line: &str, line_no: usize, path: &Path) -> Result<HexRecord, String> {
    let body = line.strip_prefix(':').ok_or_else(|| {
        format!("{}:{line_no}: Intel HEX record must start with ':'", path.display())
    })?;
    if body.len() < 8 || body.len() % 2 != 0 {
        return Err(format!("{}:{line_no}: malformed Intel HEX record length", path.display()));
    }
    if !body.is_ascii() {
        return Err(format!("{}:{line_no}: non-hex-digit byte in record", path.display()));
    }
    let bytes: Vec<u8> = (0..body.len() / 2)
        .map(|i| u8::from_str_radix(&body[i * 2..i * 2 + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| format!("{}:{line_no}: non-hex-digit byte in record", path.display()))?;

    let byte_count = bytes[0] as usize;
    if bytes.len() != byte_count + 5 {
        return Err(format!(
            "{}:{line_no}: record declares {byte_count} data bytes but line has {} data bytes",
            path.display(),
            bytes.len().saturating_sub(5)
        ));
    }
    let checksum = bytes[bytes.len() - 1];
    if intel_hex_checksum(&bytes[..bytes.len() - 1]) != checksum {
        return Err(format!("{}:{line_no}: checksum mismatch", path.display()));
    }

    Ok(HexRecord {
        address: u16::from_be_bytes([bytes[1], bytes[2]]),
        record_type: bytes[3],
        data: bytes[4..4 + byte_count].to_vec(),
    })
}

/// Parses a whole Intel HEX file's text into the flat byte buffer it
/// encodes, honoring record types `00` (data), `01` (end of file, and
/// nothing after it is read), `02`/`04` (extended segment/linear address,
/// per the Intel HEX spec's own address formulas — `02`'s upper address
/// bits are shifted by 4, `04`'s by 16; the two must not be conflated) and
/// `05` (start linear address, informational only, ignored). Any other
/// record type, or a file with no end-of-file record, is a hard error -
/// see `parse_hex_record`'s doc comment for why silent skipping isn't used
/// here.
fn parse_intel_hex(raw: &[u8], path: &Path) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(raw)
        .map_err(|e| format!("{}: not a valid Intel HEX (ASCII) file: {e}", path.display()))?;

    let mut data: Vec<u8> = Vec::new();
    let mut upper_addr: u32 = 0;
    let mut saw_eof = false;

    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = i + 1;
        let record = parse_hex_record(line, line_no, path)?;
        match record.record_type {
            0x00 => {
                let start = upper_addr as usize + record.address as usize;
                let end = start + record.data.len();
                if end > MAX_FILE_SIZE {
                    return Err(format!(
                        "{}:{line_no}: record address {end:#X} exceeds the {}KB maximum EPROM size",
                        path.display(),
                        MAX_FILE_SIZE / 1024
                    ));
                }
                if data.len() < end {
                    data.resize(end, 0xFF);
                }
                data[start..end].copy_from_slice(&record.data);
            }
            0x01 => {
                saw_eof = true;
                break;
            }
            0x02 => {
                if record.data.len() != 2 {
                    return Err(format!(
                        "{}:{line_no}: extended segment address record must carry 2 data bytes",
                        path.display()
                    ));
                }
                let segment = u16::from_be_bytes([record.data[0], record.data[1]]) as u32;
                upper_addr = segment << 4;
            }
            0x04 => {
                if record.data.len() != 2 {
                    return Err(format!(
                        "{}:{line_no}: extended linear address record must carry 2 data bytes",
                        path.display()
                    ));
                }
                let high = u16::from_be_bytes([record.data[0], record.data[1]]) as u32;
                upper_addr = high << 16;
            }
            0x05 => {} // start linear address - informational, not part of the data image
            other => {
                return Err(format!(
                    "{}:{line_no}: unsupported Intel HEX record type {other:02X}",
                    path.display()
                ));
            }
        }
    }

    if !saw_eof {
        return Err(format!("{}: missing Intel HEX end-of-file record", path.display()));
    }
    Ok(data)
}

impl AddrDiff {
    pub fn new(positions: Vec<u32>, sources: Vec<u32>) -> AddrDiff {
        let mut mask_clear = usize::MAX;
        for &p in &positions {
            mask_clear &= !(1usize << p);
        }
        AddrDiff { positions, sources, mask_clear }
    }

    pub fn identity() -> AddrDiff {
        AddrDiff::new(Vec::new(), Vec::new())
    }

    /// `map[logical_bit] = physical_bit_source`.
    pub fn from_full_map(map: &[u32]) -> AddrDiff {
        let mut positions = Vec::new();
        let mut sources = Vec::new();
        for (i, &src) in map.iter().enumerate() {
            if src != i as u32 {
                positions.push(i as u32);
                sources.push(src);
            }
        }
        AddrDiff::new(positions, sources)
    }

    pub fn to_full_map(&self, addr_bits: u32) -> Vec<u32> {
        let mut map: Vec<u32> = (0..addr_bits).collect();
        for (&pos, &src) in self.positions.iter().zip(&self.sources) {
            map[pos as usize] = src;
        }
        map
    }

    #[inline]
    pub fn remap(&self, addr: usize) -> usize {
        let mut out = addr & self.mask_clear;
        for (&pos, &src) in self.positions.iter().zip(&self.sources) {
            if (addr >> src) & 1 == 1 {
                out |= 1 << pos;
            }
        }
        out
    }

    pub fn apply_to_indices(&self, data: &[u8], indices: &[usize]) -> Vec<u8> {
        indices
            .iter()
            .map(|&addr| {
                let p = self.remap(addr);
                if p < data.len() { data[p] } else { 0 }
            })
            .collect()
    }

    pub fn apply_full(&self, data: &[u8]) -> Vec<u8> {
        (0..data.len())
            .map(|addr| {
                let p = self.remap(addr);
                if p < data.len() { data[p] } else { 0 }
            })
            .collect()
    }
}

pub fn build_data_lut(map: &[u32; 8]) -> [u8; 256] {
    let mut lut = [0u8; 256];
    for val in 0u32..256 {
        let mut result: u8 = 0;
        for (logical, &src) in map.iter().enumerate() {
            if (val >> src) & 1 == 1 {
                result |= 1 << logical;
            }
        }
        lut[val as usize] = result;
    }
    lut
}

pub fn apply_data_lut(data: &[u8], lut: &[u8; 256]) -> Vec<u8> {
    data.iter().map(|&b| lut[b as usize]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_diff_identity_is_noop() {
        let diff = AddrDiff::identity();
        assert_eq!(diff.remap(0b10110), 0b10110);
    }

    #[test]
    fn addr_diff_from_full_map_round_trips() {
        let map = vec![2u32, 1, 0];
        let diff = AddrDiff::from_full_map(&map);
        assert_eq!(diff.to_full_map(3), map);
    }

    #[test]
    fn addr_diff_matches_brute_force_reorder() {
        let map = vec![2u32, 0, 1];
        let diff = AddrDiff::from_full_map(&map);
        for addr in 0u32..8 {
            let mut expected = 0u32;
            for (logical, &src) in map.iter().enumerate() {
                if (addr >> src) & 1 == 1 {
                    expected |= 1 << logical;
                }
            }
            assert_eq!(diff.remap(addr as usize) as u32, expected, "addr={addr}");
        }
    }

    #[test]
    fn data_lut_identity_is_noop() {
        let lut = build_data_lut(&[0, 1, 2, 3, 4, 5, 6, 7]);
        for v in 0..=255u8 {
            assert_eq!(lut[v as usize], v);
        }
    }

    #[test]
    fn data_lut_reverse_matches_bit_reverse() {
        let lut = build_data_lut(&[7, 6, 5, 4, 3, 2, 1, 0]);
        assert_eq!(lut[0b0000_0001], 0b1000_0000);
        assert_eq!(lut[0b1000_0000], 0b0000_0001);
        assert_eq!(lut[0b0000_1111], 0b1111_0000);
    }

    #[test]
    fn rom_load_rejects_oversized_file() {
        let path = std::env::temp_dir().join("dec_rom_test_oversized.bin");
        fs::write(&path, vec![0u8; MAX_FILE_SIZE + 1]).unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("too large"));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rom_load_rejects_non_power_of_two_size() {
        let path = std::env::temp_dir().join("dec_rom_test_odd_size.bin");
        fs::write(&path, vec![0u8; 100]).unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("power of two"));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rom_load_rejects_a_file_too_small_for_auto_fix() {
        let path = std::env::temp_dir().join("dec_rom_test_too_small.bin");
        fs::write(&path, vec![0u8; 2]).unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("too small"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_record_address_past_the_max_file_size() {
        let path = std::env::temp_dir().join("dec_rom_test_hex_oob_address.hex");
        // Extended linear address 0xFFFF0000, then a 1-byte data record at
        // offset 0 - the effective address (~4GB) must be rejected before
        // any allocation is attempted, not just caught by the post-parse
        // size check.
        fs::write(&path, ":02000004FFFFFC\r\n:01000000AA55\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("exceeds the"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_non_ascii_body_without_panicking() {
        let path = std::env::temp_dir().join("dec_rom_test_non_ascii_body.hex");
        // A multi-byte UTF-8 character inside the record body must be
        // rejected cleanly, not panic on a byte-slice landing mid-character.
        fs::write(&path, ":01000000\u{20AC}A55\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("non-hex-digit byte"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rom_load_computes_address_bits_and_eprom_type() {
        let path = std::env::temp_dir().join("dec_rom_test_32k.bin");
        fs::write(&path, vec![0xAAu8; 32768]).unwrap();
        let rom = Rom::load(&path).unwrap();
        assert_eq!(rom.address_bits, 15);
        assert_eq!(rom.eprom_type(), "27256 (32KB)");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn save_writes_exact_bytes() {
        let path = std::env::temp_dir().join("dec_rom_test_save.bin");
        Rom::save(&path, &[1, 2, 3, 4]).unwrap();
        let read_back = fs::read(&path).unwrap();
        assert_eq!(read_back, vec![1, 2, 3, 4]);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn save_hex_and_reload_round_trips() {
        let path = std::env::temp_dir().join("dec_rom_test_roundtrip.hex");
        let original: Vec<u8> = (0..=255u16).cycle().take(4096).map(|v| v as u8).collect();
        Rom::save(&path, &original).unwrap();
        let rom = Rom::load(&path).expect("a file this crate just wrote must load cleanly");
        assert_eq!(rom.data, original);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn save_hex_rejects_data_larger_than_the_16_bit_address_range() {
        let path = std::env::temp_dir().join("dec_rom_test_save_hex_too_big.hex");
        let data = vec![0u8; u16::MAX as usize + 2];
        let err = Rom::save_hex(&path, &data).unwrap_err();
        assert!(err.contains("exceeds Intel HEX's 16-bit address range"), "unexpected error: {err}");
    }

    #[test]
    fn save_reports_an_unwritable_path_clearly() {
        let path = std::env::temp_dir().join("dec_rom_test_does_not_exist_dir").join("out.bin");
        let err = Rom::save(&path, &[1, 2, 3]).unwrap_err();
        assert!(err.contains("failed to write"), "unexpected error: {err}");
    }

    #[test]
    fn intel_hex_shorter_than_a_full_page_is_padded_with_0xff() {
        // A hex file whose highest data record doesn't reach a power-of-two
        // boundary must still load - padded up to the next power of two
        // with 0xFF, the EPROM-erased-state fill.
        let path = std::env::temp_dir().join("dec_rom_test_short.hex");
        // Ten data bytes at address 0, then EOF - 10 is not a power of two.
        fs::write(&path, ":0A0000000102030405060708090ABF\n:00000001FF\n").unwrap();
        let rom = Rom::load(&path).expect("a short-but-valid hex file must still load, padded");
        assert_eq!(rom.data.len(), 16, "10 data bytes must pad up to the next power of two, 16");
        assert_eq!(&rom.data[..10], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A]);
        assert_eq!(&rom.data[10..], &[0xFF; 6]);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_bad_checksum() {
        let path = std::env::temp_dir().join("dec_rom_test_bad_checksum.hex");
        // Same record as the padding test above, checksum corrupted (BF -> C0).
        fs::write(&path, ":0A0000000102030405060708090AC0\n:00000001FF\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("checksum"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_missing_eof_record() {
        let path = std::env::temp_dir().join("dec_rom_test_no_eof.hex");
        fs::write(&path, ":0A0000000102030405060708090ABF\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("end-of-file"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rom_load_reports_a_missing_file_clearly() {
        let path = std::env::temp_dir().join("dec_rom_test_does_not_exist.bin");
        let _ = fs::remove_file(&path); // ensure it really doesn't exist
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("failed to read"), "unexpected error: {err}");
    }

    #[test]
    fn intel_hex_rejects_a_record_missing_the_leading_colon() {
        let path = std::env::temp_dir().join("dec_rom_test_no_colon.hex");
        fs::write(&path, "0A0000000102030405060708090ABF\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("must start with ':'"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_record_with_odd_length() {
        let path = std::env::temp_dir().join("dec_rom_test_odd_len.hex");
        fs::write(&path, ":123456789\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("malformed Intel HEX record length"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_non_hex_digit() {
        let path = std::env::temp_dir().join("dec_rom_test_bad_digit.hex");
        fs::write(&path, ":GG000000\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("non-hex-digit byte"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_declared_byte_count_mismatch() {
        let path = std::env::temp_dir().join("dec_rom_test_byte_count_mismatch.hex");
        // Declares 0x0A (10) data bytes but the line only carries 4.
        fs::write(&path, ":0A0000000102030400\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("declares 10 data bytes but line has 4 data bytes"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_a_non_utf8_file() {
        let path = std::env::temp_dir().join("dec_rom_test_non_utf8.hex");
        fs::write(&path, [0xFFu8, 0xFE, 0x00, 0x01]).unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("not a valid Intel HEX"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_an_extended_segment_address_record_with_wrong_length() {
        let path = std::env::temp_dir().join("dec_rom_test_bad_ext_segment.hex");
        // Type 02 record carrying 1 data byte instead of the required 2.
        fs::write(&path, ":0100000200FD\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("extended segment address record must carry 2 data bytes"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_an_extended_linear_address_record_with_wrong_length() {
        let path = std::env::temp_dir().join("dec_rom_test_bad_ext_linear.hex");
        // Type 04 record carrying 1 data byte instead of the required 2.
        fs::write(&path, ":0100000400FB\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("extended linear address record must carry 2 data bytes"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn intel_hex_rejects_an_unsupported_record_type() {
        let path = std::env::temp_dir().join("dec_rom_test_unsupported_type.hex");
        fs::write(&path, ":00000003FD\r\n:00000001FF\r\n").unwrap();
        let err = Rom::load(&path).unwrap_err();
        assert!(err.contains("unsupported Intel HEX record type"), "unexpected error: {err}");
        fs::remove_file(&path).unwrap();
    }
}
