//! Read/write support for the scramble-scheme `.txt` format used by "A&L
//! Software"'s own ROM/EPROM encoder-decoder application, a standard the
//! MSX ROM-decoding community has used since 2004 to document and exchange
//! address/data bit-wiring schemes for cartridge converters/copiers (the
//! format's own header reads "Codificador/Decodificador de ROM para EPROM"
//! / "(c) 2004 A&L Software" - A&L Software is the name of that PC
//! application, not of any one interface manufacturer). Dec-ROM writes the
//! same format so a scheme it discovers can be shared with, or a scheme
//! discovered by, that existing community tooling - Dec-ROM identifies
//! itself in the header it writes instead of claiming to be that other
//! application (see `write_scheme_txt`).
//!
//! Format, reverse-engineered from several real files in this format
//! (the two-line application-header turned out to be optional on read),
//! encoded in ISO-8859-1/Latin-1 (these files carry accented Portuguese
//! text) with CRLF line endings:
//!
//! ```text
//! Codificador/Decodificador de ROM para EPROM
//! (c) 2004 A&L Software
//!
//! Definição de codificação de ROM para EPROM
//!
//! Comentários: <free text, often the interface/product name>
//! Endereço   : <N> bits
//! Bloco      : <N/8 kB>
//! Ordem      : 0,1,2,3...n
//!
//! Definição das vias de dados
//!
//! ROM    EPROM
//! D0  ->  D6
//! ... (8 rows, D0..D7)
//!
//! Definição das vias de endereço
//!
//! ROM    EPROM
//! A0  ->  A10
//! ... (N rows, A0..A(N-1))
//! ```
//!
//! Both tables read "ROM Xi -> EPROM Xj": the bit the ROM/CPU asserts as
//! logical line `i` physically arrives at the EPROM's (scrambled) line `j`.
//! Confirmed against an independently-verified ground truth (see
//! `tests/msx_flip_bitmath_test.rs`): the data table is
//! used exactly as read (`data_map[i] = j`, `crate::reorganizer::build_data_lut`'s
//! own convention), while the address table needs inverting
//! (`addr_map[j] = i`, `crate::reorganizer::AddrDiff::from_full_map`'s
//! convention) - address lines *select* which physical cell holds a byte
//! rather than directly carrying its bits, so the two tables' physical
//! roles aren't symmetric even though they're written the same way.

/// A parsed or about-to-be-written scheme: an address/data bit-wiring
/// definition read from, or to be written to, the `.txt` format this module
/// implements. `addr_map`/`data_map` are already in this project's own
/// convention (`AddrDiff::from_full_map`/`crate::reorganizer::build_data_lut`),
/// not the txt file's raw "ROM Xi -> EPROM Xj" table order.
#[derive(Debug, Clone, PartialEq)]
pub struct Scheme {
    pub comment: String,
    pub addr_map: Vec<u32>,
    pub data_map: [u32; 8],
}

/// Header Dec-ROM writes in place of the original application's own
/// "Codificador/Decodificador de ROM para EPROM" / "(c) 2004 A&L Software"
/// two-line header - Dec-ROM identifies itself as the tool that produced
/// the file rather than claiming to be that other, still-separately-real
/// application. Parsing tolerates either this, the original two-line
/// header, or no header at all (see this module's own doc comment).
const WRITTEN_HEADER: &str = "DEC-ROM by Pakequis";

/// Generous headroom above any real EPROM socket this project could ever
/// see (Z80 itself maxes out at 16 address lines; the doc comment above
/// notes 15 as a real-world example) - just enough to keep a malformed or
/// hand-edited `.txt`'s declared bit count from turning into a multi-
/// gigabyte allocation in the `vec![0u32; declared_addr_bits as usize]`
/// calls below.
const MAX_SCHEME_ADDR_BITS: u32 = 24;

/// The mathematical inverse of an `AddrDiff::from_full_map`-style
/// permutation: if `map[i] = j`, the inverse satisfies `inverse[j] = i`.
/// Self-paired with `invert_naive_addr_table` below - both directions use
/// the exact same computation, since permutation inversion is its own
/// inverse.
fn invert(map: &[u32]) -> Vec<u32> {
    let mut inverse = vec![0u32; map.len()];
    for (i, &v) in map.iter().enumerate() {
        inverse[v as usize] = i as u32;
    }
    inverse
}

/// Parses one `"X{n}  ->  X{m}"` row (arbitrary internal whitespace),
/// returning `(n, m)`.
fn parse_bit_row(line: &str, prefix: char) -> Option<(u32, u32)> {
    let (lhs, rhs) = line.split_once("->")?;
    let n: u32 = lhs.trim().strip_prefix(prefix)?.parse().ok()?;
    let m: u32 = rhs.trim().strip_prefix(prefix)?.parse().ok()?;
    Some((n, m))
}

/// Parses `bytes` (expected to be ISO-8859-1/Latin-1, per this format's own
/// convention - see this module's doc comment) as a scramble-scheme `.txt`
/// file, adapting its address table to `target_addr_bits` (the actual
/// loaded ROM's address-bit count, from `reorganizer::Rom::address_bits`).
///
/// The txt's own declared address-bit count ("Endereço") can legitimately
/// exceed `target_addr_bits`: several real files in this format describe a
/// full EPROM socket's wiring (e.g. 15 address lines for a 32KB chip) where
/// only a smaller block (e.g. 16KB, 14 bits) is actually used by a given
/// ROM. Dropping those unused high-order lines is only safe when they're
/// genuine fixed points (`Ai -> Ai`) never referenced by a kept row; this
/// function verifies that rather than assuming it, and returns `Err` if the
/// scheme doesn't actually fit `target_addr_bits`.
pub fn parse_scheme_txt(bytes: &[u8], target_addr_bits: u32) -> Result<Scheme, String> {
    let text: String = bytes.iter().map(|&b| b as char).collect();
    let lines: Vec<&str> = text.lines().collect();

    let comment = lines
        .iter()
        .find_map(|l| l.strip_prefix("Comentários:"))
        .map(|s| s.trim().to_string())
        .ok_or("missing 'Comentários:' field")?;

    let declared_addr_bits: u32 = lines
        .iter()
        .find_map(|l| l.strip_prefix("Endereço"))
        .and_then(|rest| rest.split(':').nth(1))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .ok_or("missing or unparseable 'Endereço' field")?;
    if declared_addr_bits > MAX_SCHEME_ADDR_BITS {
        return Err(format!(
            "declared 'Endereço' width {declared_addr_bits} bits is implausibly large (max {MAX_SCHEME_ADDR_BITS})"
        ));
    }

    let data_header =
        lines.iter().position(|l| l.trim() == "Definição das vias de dados").ok_or("missing data-bus section")?;
    let mut data_map = [0u32; 8];
    let mut seen_data = [false; 8];
    let mut data_rows = 0;
    for line in lines[data_header + 1..].iter() {
        match parse_bit_row(line, 'D') {
            Some((i, j)) if (i as usize) < 8 && (j as usize) < 8 => {
                data_map[i as usize] = j;
                seen_data[i as usize] = true;
                data_rows += 1;
            }
            Some((i, j)) => {
                return Err(format!("data row D{i} -> D{j} is out of range (data is always 8 bits)"))
            }
            None if data_rows > 0 => break,
            None => continue,
        }
    }
    if data_rows != 8 || !seen_data.iter().all(|&s| s) {
        return Err("incomplete data-bus table (expected 8 rows, D0..D7)".to_string());
    }

    let addr_header = lines
        .iter()
        .position(|l| l.trim() == "Definição das vias de endereço")
        .ok_or("missing address-bus section")?;
    let mut addr_naive = vec![0u32; declared_addr_bits as usize];
    let mut seen_addr = vec![false; declared_addr_bits as usize];
    let mut addr_rows = 0u32;
    for line in lines[addr_header + 1..].iter() {
        match parse_bit_row(line, 'A') {
            Some((i, j)) if (i as usize) < declared_addr_bits as usize => {
                addr_naive[i as usize] = j;
                seen_addr[i as usize] = true;
                addr_rows += 1;
            }
            Some((i, _)) => return Err(format!("address row A{i} exceeds the declared Endereço bit width")),
            None if addr_rows > 0 => break,
            None => continue,
        }
    }
    if addr_rows != declared_addr_bits || !seen_addr.iter().all(|&s| s) {
        return Err(format!("incomplete address-bus table (expected {declared_addr_bits} rows)"));
    }

    if target_addr_bits > declared_addr_bits {
        return Err(format!(
            "this scheme only covers {declared_addr_bits} address bits, but the loaded ROM needs {target_addr_bits}"
        ));
    }
    for (i, &naive) in addr_naive.iter().enumerate().skip(target_addr_bits as usize) {
        if naive != i as u32 {
            return Err(format!(
                "cannot drop address line A{i}: it maps to A{naive}, not a fixed point, so this scheme doesn't fit a {target_addr_bits}-bit ROM"
            ));
        }
    }
    for (i, &naive) in addr_naive.iter().enumerate().take(target_addr_bits as usize) {
        if naive >= target_addr_bits {
            return Err(format!(
                "address line A{i} maps to A{naive}, a line this {target_addr_bits}-bit ROM doesn't have"
            ));
        }
    }

    let addr_map = invert(&addr_naive[..target_addr_bits as usize]);
    Ok(Scheme { comment, addr_map, data_map })
}

/// Encodes `s` as ISO-8859-1/Latin-1 (every Unicode scalar value from 0x00
/// to 0xFF maps to the identical single byte - the encoding this format's
/// own real-world files use, per this module's doc comment). Errors on any
/// character outside that range rather than silently mangling it.
fn encode_latin1(s: &str) -> Result<Vec<u8>, String> {
    s.chars()
        .map(|c| Some(u32::from(c)).filter(|&cp| cp <= 0xFF).map(|cp| cp as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| format!("'{s}' contains a character outside ISO-8859-1/Latin-1, this format's own encoding"))
}

/// Writes `scheme` in the `.txt` format this module reads (see this
/// module's doc comment), with Dec-ROM's own header (`WRITTEN_HEADER`) in
/// place of the original application's. `comment` becomes the file's
/// "Comentários" field verbatim (any embedded line breaks are collapsed to
/// spaces, since that field is a single line in this format); `addr_map`/
/// `data_map` are in this project's own convention, the same one
/// `parse_scheme_txt` returns.
pub fn write_scheme_txt(comment: &str, addr_map: &[u32], data_map: &[u32; 8]) -> Result<Vec<u8>, String> {
    let addr_bits = addr_map.len() as u32;
    let addr_naive = invert(addr_map);
    let block_kb = (1u64 << addr_bits) / 1024;
    let comment = comment.replace(['\r', '\n'], " ");

    let mut out = String::new();
    out.push_str(WRITTEN_HEADER);
    out.push_str("\r\n\r\n");
    out.push_str("Definição de codificação de ROM para EPROM\r\n\r\n");
    out.push_str(&format!("Comentários: {comment}\r\n"));
    out.push_str(&format!("Endereço   : {addr_bits} bits\r\n"));
    out.push_str(&format!("Bloco      : {block_kb} kB\r\n"));
    out.push_str("Ordem      : 0,1,2,3...n\r\n\r\n");
    out.push_str("Definição das vias de dados\r\n\r\n");
    out.push_str("ROM    EPROM\r\n");
    for (i, &j) in data_map.iter().enumerate() {
        out.push_str(&format!("{:<4}->  D{j}\r\n", format!("D{i}")));
    }
    out.push_str("\r\nDefinição das vias de endereço\r\n\r\n");
    out.push_str("ROM    EPROM\r\n");
    for (i, &j) in addr_naive.iter().enumerate() {
        out.push_str(&format!("{:<4}->  A{j}\r\n", format!("A{i}")));
    }

    encode_latin1(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reorganizer::{apply_data_lut, build_data_lut, AddrDiff};

    /// Loads a fixture from the local, untracked `samples/` directory.
    /// Returns `None` (after a notice) when it is absent, so tests that
    /// need real dumps skip instead of failing on a clean checkout.
    fn load_sample(name: &str) -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("samples").join(name);
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("skipping: samples/{name} not available ({e})");
                None
            }
        }
    }

    #[test]
    fn parses_fort_txt_matching_the_independently_verified_key() {
        // This fixture lacks the two-line application header entirely -
        // this doubles as the "header is optional" check.
        let Some(bytes) = load_sample("fort.txt") else { return };
        let scheme = parse_scheme_txt(&bytes, 16).expect("fort.txt must parse");
        // Ground truth from tests/msx_flip_bitmath_test.rs.
        assert_eq!(scheme.addr_map, vec![1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 0, 15, 9, 12, 11, 10]);
        assert_eq!(scheme.data_map, [1, 2, 4, 0, 7, 6, 5, 3]);
    }

    #[test]
    fn parses_bios_txt_matching_a_live_autofix_recovery() {
        // Ground truth from known_patterns::company_specific_pairs (ITS
        // Games), independently confirmed against
        // `autofix::find_scrambling`'s own live recovery of this fixture.
        let Some(bytes) = load_sample("bios.txt") else { return };
        let scheme = parse_scheme_txt(&bytes, 15).expect("bios.txt must parse");
        assert_eq!(scheme.comment, "ITS Games");
        assert_eq!(scheme.addr_map, vec![0, 1, 3, 2, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14]);
        assert_eq!(scheme.data_map, [0, 2, 1, 3, 4, 6, 5, 7]);
    }

    #[test]
    fn parses_ddx31_txt_matching_known_patterns_rs() {
        let Some(bytes) = load_sample("ddx3.1.txt") else { return };
        let scheme = parse_scheme_txt(&bytes, 14).expect("ddx3.1.txt must parse");
        assert_eq!(scheme.comment, "Interfaces: DDX 3.1");
        // Ground truth from known_patterns::company_specific_pairs.
        assert_eq!(scheme.addr_map, vec![5, 4, 3, 0, 1, 12, 7, 11, 6, 8, 2, 13, 9, 10]);
        assert_eq!(scheme.data_map, [7, 6, 5, 0, 4, 1, 3, 2]);
    }

    #[test]
    fn parses_tpx102_txt_truncating_two_fixed_point_high_bits() {
        // This fixture declares 16 address bits but the real ROM is 14
        // bits (A14->A14 and A15->A15 are fixed points) - this exercises
        // the truncation rule described in `parse_scheme_txt`'s doc comment.
        let Some(bytes) = load_sample("TPX102.txt") else { return };
        let scheme = parse_scheme_txt(&bytes, 14).expect("TPX102.txt must parse and truncate cleanly");
        assert_eq!(scheme.addr_map, vec![5, 3, 1, 12, 7, 11, 13, 4, 6, 8, 2, 0, 9, 10]);
        assert_eq!(scheme.data_map, [6, 7, 5, 0, 4, 1, 3, 2]);
    }

    #[test]
    fn parses_megaramdisk_txt_at_its_native_bit_width() {
        let Some(bytes) = load_sample("megaramdisk.txt") else { return };
        let scheme = parse_scheme_txt(&bytes, 15).expect("megaramdisk.txt must parse");
        assert_eq!(scheme.addr_map, vec![4, 5, 2, 1, 0, 13, 8, 6, 11, 7, 3, 12, 10, 9, 14]);
        assert_eq!(scheme.data_map, [0, 7, 1, 6, 2, 5, 3, 4]);
    }

    #[test]
    fn rejects_a_scheme_that_does_not_fit_a_bigger_rom() {
        let Some(bytes) = load_sample("TPX102.txt") else { return }; // declares 16 bits
        assert!(parse_scheme_txt(&bytes, 17).is_err(), "a scheme can't be extended to more bits than it declares");
    }

    #[test]
    fn write_then_parse_round_trips_the_maps() {
        for (addr_map, data_map) in [
            ((0..16u32).collect::<Vec<u32>>(), [0u32, 1, 2, 3, 4, 5, 6, 7]),
            (vec![1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 0, 15, 9, 12, 11, 10], [1, 2, 4, 0, 7, 6, 5, 3]),
            (vec![5, 4, 3, 0, 1, 12, 7, 11, 6, 8, 2, 13, 9, 10], [7, 6, 5, 0, 4, 1, 3, 2]),
        ] {
            let bytes = write_scheme_txt("round-trip test", &addr_map, &data_map).expect("must encode cleanly");
            let addr_bits = addr_map.len() as u32;
            let scheme = parse_scheme_txt(&bytes, addr_bits).expect("must parse what this module itself wrote");
            assert_eq!(scheme.addr_map, addr_map);
            assert_eq!(scheme.data_map, data_map);
            assert_eq!(scheme.comment, "round-trip test");
        }
    }

    #[test]
    fn written_header_identifies_dec_rom_not_the_original_application() {
        let bytes = write_scheme_txt("x", &[0, 1], &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("DEC-ROM by Pakequis"));
        assert!(!text.contains("A&L Software"), "Dec-ROM must not claim to be the original application");
    }

    #[test]
    fn rejects_a_comment_with_non_latin1_characters() {
        assert!(write_scheme_txt("emoji: 🎮", &[0, 1], &[0, 1, 2, 3, 4, 5, 6, 7]).is_err());
    }

    #[test]
    fn output_is_byte_identical_in_shape_to_a_real_sample_for_a_matching_scheme() {
        // Rewriting DDX 3.1's own scheme should reproduce the same table
        // rows (modulo the header/comment this module intentionally
        // changes - see write_scheme_txt's doc comment - and modulo A14,
        // which the original 15-bit txt describes as a fixed point for the
        // full EPROM socket but this 14-bit ROM-specific scheme correctly
        // omits, per `parse_scheme_txt`'s truncation rule) as the real
        // sample file, confirming the writer's formatting matches the
        // community standard exactly, not just approximately.
        let addr_map = vec![5, 4, 3, 0, 1, 12, 7, 11, 6, 8, 2, 13, 9, 10];
        let data_map = [7, 6, 5, 0, 4, 1, 3, 2];
        let written = write_scheme_txt("Interfaces: DDX 3.1", &addr_map, &data_map).unwrap();
        let written_text: String = written.iter().map(|&b| b as char).collect();

        let Some(original) = load_sample("ddx3.1.txt") else { return };
        let original_text: String = original.iter().map(|&b| b as char).collect();

        for line in original_text.lines() {
            if line.trim() == "A14 ->  A14" {
                continue;
            }
            if line.contains("->") || line.trim() == "ROM    EPROM" || line.starts_with("Comentários") {
                assert!(written_text.contains(line), "written output is missing original line: {line:?}");
            }
        }
    }

    /// Builds a minimal well-formed scheme document from its raw parts, so
    /// each rejection test below can corrupt exactly one part while leaving
    /// the rest valid. `data_rows`/`addr_rows` are `(i, j)` pairs rendered
    /// as `"Xi ->  Xj"` in the file's own "ROM Xi -> EPROM Xj" convention.
    fn doc(comentarios: &str, endereco: &str, data_rows: &str, addr_rows: &str) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("Definição de codificação de ROM para EPROM\r\n\r\n");
        out.push_str(comentarios);
        out.push_str(endereco);
        out.push_str("Bloco      : 1 kB\r\n");
        out.push_str("Ordem      : 0,1,2,3...n\r\n\r\n");
        out.push_str(data_rows);
        out.push_str("\r\n");
        out.push_str(addr_rows);
        encode_latin1(&out).unwrap()
    }

    fn data_section(rows: &[(u32, u32)]) -> String {
        let mut s = String::from("Definição das vias de dados\r\n\r\nROM    EPROM\r\n");
        for &(i, j) in rows {
            s.push_str(&format!("D{i} ->  D{j}\r\n"));
        }
        s
    }

    fn addr_section(rows: &[(u32, u32)]) -> String {
        let mut s = String::from("Definição das vias de endereço\r\n\r\nROM    EPROM\r\n");
        for &(i, j) in rows {
            s.push_str(&format!("A{i} ->  A{j}\r\n"));
        }
        s
    }

    fn identity_pairs(n: u32) -> Vec<(u32, u32)> {
        (0..n).map(|i| (i, i)).collect()
    }

    const VALID_COMENTARIOS: &str = "Comentários: x\r\n";
    const VALID_ENDERECO_4BITS: &str = "Endereço   : 4 bits\r\n";

    #[test]
    fn rejects_a_completely_empty_file() {
        let err = parse_scheme_txt(&[], 4).unwrap_err();
        assert!(err.contains("Comentários"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_random_garbage_bytes() {
        let err = parse_scheme_txt(b"\x00\x01\xffnot a scheme at all\r\n", 4).unwrap_err();
        assert!(err.contains("Comentários"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_a_missing_comentarios_field() {
        let bytes = doc("", VALID_ENDERECO_4BITS, &data_section(&identity_pairs(8)), &addr_section(&identity_pairs(4)));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("Comentários"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_a_missing_endereco_field() {
        let bytes = doc(VALID_COMENTARIOS, "", &data_section(&identity_pairs(8)), &addr_section(&identity_pairs(4)));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("Endereço"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_unparseable_endereco_field() {
        let bytes = doc(
            VALID_COMENTARIOS,
            "Endereço   : abc bits\r\n",
            &data_section(&identity_pairs(8)),
            &addr_section(&identity_pairs(4)),
        );
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("Endereço"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_a_missing_data_bus_section() {
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, "", &addr_section(&identity_pairs(4)));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("data-bus section"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_out_of_range_data_row() {
        let mut rows = identity_pairs(8);
        rows[7] = (9, 7); // D9 doesn't exist - data is always 8 bits (D0..D7)
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&rows), &addr_section(&identity_pairs(4)));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("D9") && err.contains("out of range"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_a_data_row_whose_target_is_out_of_range() {
        let mut rows = identity_pairs(8);
        rows[3] = (3, 999999); // D3 -> D999999 doesn't exist - data is always 8 bits
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&rows), &addr_section(&identity_pairs(4)));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("D999999") && err.contains("out of range"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_implausibly_large_endereco_field_without_allocating() {
        let bytes = doc(
            VALID_COMENTARIOS,
            "Endereço   : 4000000000 bits\r\n",
            &data_section(&identity_pairs(8)),
            &addr_section(&identity_pairs(4)),
        );
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("implausibly large"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_incomplete_data_bus_table() {
        let rows = identity_pairs(5); // needs all 8, D0..D7
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&rows), &addr_section(&identity_pairs(4)));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("incomplete data-bus table"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_a_missing_address_bus_section() {
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&identity_pairs(8)), "");
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("address-bus section"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_out_of_range_address_row() {
        let mut rows = identity_pairs(4);
        rows[3] = (5, 0); // A5 exceeds the declared 4-bit width
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&identity_pairs(8)), &addr_section(&rows));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("A5") && err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_incomplete_address_bus_table() {
        let rows = identity_pairs(2); // Endereço declares 4 bits, needs all 4 rows
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&identity_pairs(8)), &addr_section(&rows));
        let err = parse_scheme_txt(&bytes, 4).unwrap_err();
        assert!(err.contains("incomplete address-bus table"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_dropping_a_non_fixed_point_high_address_line() {
        // Declares 4 bits but the target ROM only needs 2 (A0, A1). A2/A3
        // must be fixed points (Ai -> Ai) to be safely dropped; here A2
        // maps to A3 instead, so truncating to 2 bits would silently lose
        // a real cross-line dependency.
        let rows = vec![(0, 0), (1, 1), (2, 3), (3, 2)];
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&identity_pairs(8)), &addr_section(&rows));
        let err = parse_scheme_txt(&bytes, 2).unwrap_err();
        assert!(err.contains("cannot drop address line A2"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_address_line_that_maps_to_a_line_the_target_rom_lacks() {
        // Declares 4 bits, target ROM is 3 bits (A0..A2). A3 is correctly a
        // fixed point and gets dropped, but A1 maps to A3 - a line the
        // 3-bit ROM doesn't have.
        let rows = vec![(0, 0), (1, 3), (2, 2), (3, 3)];
        let bytes = doc(VALID_COMENTARIOS, VALID_ENDERECO_4BITS, &data_section(&identity_pairs(8)), &addr_section(&rows));
        let err = parse_scheme_txt(&bytes, 3).unwrap_err();
        assert!(err.contains("A1") && err.contains("A3"), "unexpected error: {err}");
    }

    #[test]
    fn descrambling_with_the_parsed_scheme_matches_the_existing_verified_recovery() {
        let Some(rom) = load_sample("MegaRAM Disk 256Kb cks-$6EB1h.ROM") else { return };
        let Some(scheme_bytes) = load_sample("megaramdisk.txt") else { return };
        let scheme = parse_scheme_txt(&scheme_bytes, 15).unwrap();

        let diff = AddrDiff::from_full_map(&scheme.addr_map);
        let reordered = diff.apply_full(&rom);
        let lut = build_data_lut(&scheme.data_map);
        let recovered = apply_data_lut(&reordered, &lut);

        assert_eq!(&recovered[..3], &[0xEB, 0xFE, 0x90]);
        assert_eq!(&recovered[3..11], b"RAM-DISK");
    }
}
