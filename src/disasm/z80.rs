//! Z80 instruction-length/validity decoding, derived from the documented
//! opcode encoding structure (x/y/z bit fields) rather than a full opcode
//! table. Almost every byte sequence is a defined instruction, so this decoder's validity signal is much weaker than for the other three processors (an accepted tradeoff, not a bug).

/// `Some(length_in_bytes)` for a syntactically valid/documented Z80
/// instruction starting at `bytes[0]`, `None` for an undefined opcode
/// (only possible within an ED-prefix secondary byte) or if `bytes` is too
/// short to contain the instruction it starts decoding.
pub(crate) fn instruction_length(bytes: &[u8]) -> Option<usize> {
    let op = *bytes.first()?;
    let len = match op {
        0xCB => 2,
        0xED => return ed_length(bytes),
        0xDD | 0xFD => return prefixed_length(bytes),
        _ => base_length(op),
    };
    Some(len).filter(|&len| bytes.len() >= len)
}

fn base_length(op: u8) -> usize {
    let x = op >> 6;
    let y = (op >> 3) & 0b111;
    let z = op & 0b111;
    match (x, z) {
        (0, 0) => if y <= 1 { 1 } else { 2 },             // NOP/EX AF,AF' / DJNZ,JR,JR cc
        (0, 1) => if y.is_multiple_of(2) { 3 } else { 1 },  // LD rp,nn / ADD HL,rp
        (0, 2) => if y < 4 { 1 } else { 3 },                // LD (BC/DE),A.. / LD (nn),HL/A..
        (0, 3) | (0, 4) | (0, 5) => 1,                      // INC/DEC rp, INC/DEC r
        (0, 6) => 2,                                        // LD r,n
        (0, 7) => 1,                                        // RLCA..CCF
        (1, _) => 1,                                        // LD r,r' / HALT
        (2, _) => 1,                                        // alu[y] r[z]
        (3, 0) => 1,                                        // RET cc
        (3, 1) => 1,                                        // POP rp2 / RET,EXX,JP HL,LD SP,HL
        (3, 2) => 3,                                        // JP cc,nn
        (3, 3) => match y { 0 => 3, 2 | 3 => 2, _ => 1 },   // JP nn / OUT,IN / EX,DI,EI (y=1 is the CB prefix, handled earlier)
        (3, 4) => 3,                                        // CALL cc,nn
        (3, 5) => if y.is_multiple_of(2) { 1 } else { 3 },  // PUSH rp2 / CALL nn (y=1,3,5 are DD/ED/FD, handled earlier)
        (3, 6) => 2,                                        // alu[y] n
        (3, 7) => 1,                                        // RST y*8
        _ => unreachable!("x is a 2-bit field and z is a 3-bit field: every pair is covered above"),
    }
}

fn ed_length(bytes: &[u8]) -> Option<usize> {
    let secondary = *bytes.get(1)?;
    let x = secondary >> 6;
    let len = match x {
        1 => {
            // Every 0x40-0x7F secondary byte is defined; the z=3 (register
            // bit pattern 011) extended-load forms are 4 bytes total, every
            // other one is 2.
            if secondary & 0b111 == 3 { 4 } else { 2 }
        }
        2 => {
            // Only the block-instruction rows are defined within 0x80-0xBF:
            // high nibble 0xA or 0xB (secondary & 0xE0 == 0xA0), and within
            // those rows, only low nibble 0x0-0x3 or 0x8-0xB. 0x80-0x9F share
            // the same low-nibble pattern but are entirely undefined, so the
            // high-nibble check is required, not just the low-nibble one.
            let low = secondary & 0x0F;
            if secondary & 0xE0 == 0xA0 && matches!(low, 0x0..=0x3 | 0x8..=0xB) {
                2
            } else {
                return None;
            }
        }
        _ => return None, // x=0 (0x00-0x3F) and x=3 (0xC0-0xFF) are entirely undefined
    };
    Some(len).filter(|&len| bytes.len() >= len)
}

fn prefixed_length(bytes: &[u8]) -> Option<usize> {
    // A run of leading DD/FD bytes each acts as a 1-byte no-op, overridden
    // by whichever prefix immediately precedes the real opcode. Consumed
    // iteratively here (not by recursing once per byte, which exhausted
    // the stack on a long run of DD/FD bytes and crashed the process) --
    // an ED byte anywhere in the run ends it immediately via `ed_length`,
    // which never itself recurses, so only DD/FD needs bounding here.
    let mut run = 1; // bytes[0] is DD or FD, guaranteed by the caller
    while matches!(bytes.get(run), Some(0xDD) | Some(0xFD)) {
        run += 1;
    }
    let wasted = run - 1; // earlier prefix bytes in the run, each a 1-byte no-op
    let active = &bytes[wasted..]; // starts at the one prefix byte that matters
    let secondary = *active.get(1)?;

    if secondary == 0xCB {
        // DD/FD CB d op: always 4 bytes, every CB secondary byte valid.
        return Some(wasted + 4).filter(|&len| bytes.len() >= len);
    }
    if secondary == 0xED {
        return Some(wasted + 1 + ed_length(&active[1..])?);
    }
    let base_len = base_length(secondary);
    let extra = if references_indirect_hl(secondary) {
        2 // (HL) -> (IX+d)/(IY+d): a displacement byte is inserted, plus the prefix byte itself
    } else {
        1 // just the wasted prefix byte — content unaffected, or a register-direct HL/H/L
          // substitution (e.g. ADD HL,BC -> ADD IX,BC), neither of which needs an extra byte
    };
    Some(wasted + base_len + extra).filter(|&len| bytes.len() >= len)
}

/// True for base opcodes whose addressing genuinely dereferences `(HL)` as
/// memory (which is what inserts a displacement byte under a DD/FD prefix
/// — see `prefixed_length`'s doc comment), as opposed to merely using `HL`
/// as a register-direct operand (e.g. `ADD HL,BC`, `JP (HL)`, `LD SP,HL`),
/// which gets redirected to IX/IY with no length change. `(HL)` is register
/// code 6 in the z or y register field. HALT (opcode 0x76, y=6 AND z=6) is
/// explicitly excluded: it has no addressing mode to redirect at all.
fn references_indirect_hl(op: u8) -> bool {
    let x = op >> 6;
    let y = (op >> 3) & 0b111;
    let z = op & 0b111;
    match x {
        1 => (z == 6 || y == 6) && !(y == 6 && z == 6), // LD r,(HL) / LD (HL),r; HALT excluded
        2 => z == 6,                                     // alu[y] (HL)
        0 => (z == 4 || z == 5 || z == 6) && y == 6,      // INC (HL) / DEC (HL) / LD (HL),n
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_opcodes_have_documented_lengths() {
        assert_eq!(instruction_length(&[0x00]), Some(1)); // NOP
        assert_eq!(instruction_length(&[0xCD, 0, 0]), Some(3)); // CALL nn
        assert_eq!(instruction_length(&[0x21, 0, 0]), Some(3)); // LD HL,nn
        assert_eq!(instruction_length(&[0x76]), Some(1)); // HALT
        assert_eq!(instruction_length(&[0x09]), Some(1)); // ADD HL,BC
        assert_eq!(instruction_length(&[0x41]), Some(1)); // LD B,C (LD r,r')
    }

    #[test]
    fn cb_prefixed_is_always_two_bytes() {
        assert_eq!(instruction_length(&[0xCB, 0x00]), Some(2)); // RLC B
        assert_eq!(instruction_length(&[0xCB, 0xFF]), Some(2)); // SET 7,A
    }

    #[test]
    fn ed_prefixed_defined_and_undefined_ranges() {
        assert_eq!(instruction_length(&[0xED, 0x42]), Some(2)); // SBC HL,BC
        assert_eq!(instruction_length(&[0xED, 0x43, 0, 0]), Some(4)); // LD (nn),BC
        assert_eq!(instruction_length(&[0xED, 0xA0]), Some(2)); // LDI
        assert_eq!(instruction_length(&[0xED, 0x00]), None); // undefined (x=0 range)
        assert_eq!(instruction_length(&[0xED, 0xFF]), None); // undefined (x=3 range)
        assert_eq!(instruction_length(&[0xED, 0x80]), None); // undefined (x=2, not a block op)
    }

    #[test]
    fn dd_prefixed_ix_forms() {
        assert_eq!(instruction_length(&[0xDD, 0x21, 0, 0]), Some(4)); // LD IX,nn
        assert_eq!(instruction_length(&[0xDD, 0xCB, 0x00, 0x46]), Some(4)); // BIT 0,(IX+d)
        assert_eq!(instruction_length(&[0xDD, 0x09]), Some(2)); // ADD IX,BC (register substitution, no displacement)
        assert_eq!(instruction_length(&[0xDD, 0x00]), Some(2)); // NOP with wasted DD prefix
        assert_eq!(instruction_length(&[0xDD, 0x76]), Some(2)); // HALT with wasted DD prefix (not a displacement case)
        assert_eq!(instruction_length(&[0xDD, 0x7E, 0x05]), Some(3)); // LD A,(IX+d) — (HL) source redirected, +1 displacement
        assert_eq!(instruction_length(&[0xDD, 0xDD, 0x21, 0, 0]), Some(5)); // chained prefix: first DD discarded
    }

    #[test]
    fn short_buffers_return_none() {
        assert_eq!(instruction_length(&[]), None);
        assert_eq!(instruction_length(&[0xCD, 0]), None); // CALL nn needs 3 bytes, only 2 given
        assert_eq!(instruction_length(&[0xED]), None); // ED with no secondary byte
    }

    #[test]
    fn a_long_run_of_dd_fd_prefix_bytes_does_not_overflow_the_stack() {
        // Reproduces a real process-abort (SIGABRT, not a catchable panic)
        // found by the final whole-branch review: the original recursive
        // chained-prefix handling recursed once per DD/FD byte with no depth
        // bound. 64KB comfortably exceeds any real fixture's typical prefix
        // run and is well past where the original code aborted in testing.
        let bytes = vec![0xFDu8; 65536];
        // Just needs to return without crashing the test process; the exact
        // value doesn't matter (a run with no terminating opcode after it
        // decodes as one giant no-op chain with nothing left to decode).
        let _ = instruction_length(&bytes);
    }
}
