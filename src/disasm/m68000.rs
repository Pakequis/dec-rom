//! Hand-rolled 68000 instruction-length/validity decoding — no permissively
//! licensed crate exposes exact decode-only length for extension-word cases.
//! Covers a bounded instruction subset; anything else returns `None` (as if illegal).

#[derive(Clone, Copy, PartialEq, Eq)]
enum Size {
    Byte,
    Word,
    Long,
}

fn read_word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]))
}

/// Extra bytes (beyond the base opcode word) an effective-address field
/// contributes: `mode` and `reg` are the standard 3-bit EA sub-fields.
/// `None` for the reserved `mode=111, reg∈{101,110,111}` combinations.
fn ea_extra_bytes(mode: u8, reg: u8, size: Size) -> Option<usize> {
    match mode {
        0b000..=0b100 => Some(0), // Dn, An, (An), (An)+, -(An)
        0b101 | 0b110 => Some(2),                          // (d16,An) / (d8,An,Xn): 1 extension word
        0b111 => match reg {
            0b000 => Some(2),                               // absolute short: 1 word
            0b001 => Some(4),                                // absolute long: 2 words
            0b010 | 0b011 => Some(2),                        // (d16,PC) / (d8,PC,Xn): 1 word
            0b100 => Some(if size == Size::Long { 4 } else { 2 }), // immediate
            _ => None,                                       // 101, 110, 111: reserved
        },
        _ => unreachable!("mode is a 3-bit field"),
    }
}

/// `Some(length_in_bytes)` for a recognized 68000 instruction starting at
/// `bytes[0..2]` (big-endian opcode word), `None` for an illegal opcode, an
/// instruction class this decoder doesn't yet model, or a buffer too short
/// for the instruction it starts decoding.
pub(crate) fn instruction_length(bytes: &[u8]) -> Option<usize> {
    let op = read_word(bytes, 0)?;
    let len = dispatch(op)?;
    Some(len).filter(|&len| bytes.len() >= len)
}

fn dispatch(op: u16) -> Option<usize> {
    let top = (op >> 12) & 0xF;
    match top {
        0xA | 0xF => None, // line-A / line-F: reserved on the base 68000
        0x4 if op == 0x4E71 => Some(2), // NOP
        0x4 if op == 0x4E75 => Some(2), // RTS
        0x4 if op == 0x4E73 => Some(2), // RTE
        0x4 if op == 0x4E77 => Some(2), // RTR
        0x4 if (op & 0xFB80) == 0x4880 => {
            // MOVEM: bit11=1(fixed), bit10=dr (direction: 0=register-to-memory,
            // 1=memory-to-register), bits9-7=001(fixed), bit6=size(0=word,
            // 1=long), bits5-0=EA. Always followed by a
            // mandatory 16-bit register mask.
            //
            // MOVEM has no register-direct addressing mode, so mode=000 (Dn)
            // and mode=001 (An) must be rejected here. Without that, real
            // EXT.W/EXT.L opcodes (0x4880-0x4887 / 0x48C0-0x48C7), which share
            // these same fixed bits with mode=Dn, would be wrongly decoded as
            // 4-byte MOVEM instructions instead of the correct None (this
            // decoder doesn't model EXT specifically).
            let mode = ((op >> 3) & 0b111) as u8;
            let reg = (op & 0b111) as u8;
            if mode == 0b000 || mode == 0b001 {
                return None;
            }
            let size = if (op >> 6) & 1 == 1 { Size::Long } else { Size::Word };
            let ea_extra = ea_extra_bytes(mode, reg, size)?;
            Some(2 + 2 + ea_extra) // opcode word + mask word + EA extension
        }
        0x4 if (op & 0xF1C0) == 0x41C0 => {
            // LEA <ea>,An — bits 11-9 are the destination register (must
            // stay free/variable across A0-A7); only bits 15-12 and 8-6
            // are the fixed part of the opcode, not the whole top 10 bits.
            let mode = ((op >> 3) & 0b111) as u8;
            let reg = (op & 0b111) as u8;
            let ea_extra = ea_extra_bytes(mode, reg, Size::Word)?;
            Some(2 + ea_extra)
        }
        0x4 if (op & 0xFFC0) == 0x4EC0 => {
            // JMP <ea>
            let mode = ((op >> 3) & 0b111) as u8;
            let reg = (op & 0b111) as u8;
            let ea_extra = ea_extra_bytes(mode, reg, Size::Word)?;
            Some(2 + ea_extra)
        }
        0x4 if (op & 0xFFC0) == 0x4E80 => {
            // JSR <ea>
            let mode = ((op >> 3) & 0b111) as u8;
            let reg = (op & 0b111) as u8;
            let ea_extra = ea_extra_bytes(mode, reg, Size::Word)?;
            Some(2 + ea_extra)
        }
        0x5 if (op & 0xF0F8) == 0x50C8 => {
            // DBcc Dn,label — bits 11-8 are the condition code (must stay
            // free/variable across all 16 conditions, including the ones
            // with the top condition bit set, e.g. GE/LT/GT/LE); the fixed
            // part of the opcode is bits 15-12 and bits 7-3 (5 bits: 11001).
            // Opcode word + a mandatory 16-bit displacement.
            Some(4)
        }
        0x6 => {
            // Bcc/BRA/BSR: 8-bit displacement in the low byte; 0x00 means
            // "use the following 16-bit word instead" (word-form branch).
            let disp8 = (op & 0xFF) as u8;
            if disp8 == 0x00 {
                Some(4)
            } else {
                Some(2)
            }
        }
        0x1..=0x3 => {
            // MOVE/MOVEA: top nibble alone selects this class (bits 15-14
            // are always 00 for MOVE by definition of the format — size
            // lives in bits 13-12, which is what makes the top nibble
            // 1/2/3 in the first place — so no extra guard is needed or
            // correct here). Src EA extension words, then dest EA
            // extension words, additive.
            let size = match top {
                0x1 => Size::Byte,
                0x2 => Size::Long,
                0x3 => Size::Word,
                _ => unreachable!(),
            };
            let src_mode = ((op >> 3) & 0b111) as u8;
            let src_reg = (op & 0b111) as u8;
            let dst_reg = ((op >> 9) & 0b111) as u8;
            let dst_mode = ((op >> 6) & 0b111) as u8;
            let src_extra = ea_extra_bytes(src_mode, src_reg, size)?;
            let dst_extra = ea_extra_bytes(dst_mode, dst_reg, size)?;
            Some(2 + src_extra + dst_extra)
        }
        0x7 => {
            // MOVEQ #data,Dn — 8-bit immediate embedded in the opcode word itself.
            if (op & 0x0100) == 0 {
                Some(2)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(words: &[u16]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    #[test]
    fn nop_is_two_bytes() {
        assert_eq!(instruction_length(&bytes(&[0x4E71])), Some(2));
    }

    #[test]
    fn illegal_top_nibbles_return_none() {
        assert_eq!(instruction_length(&bytes(&[0xA000])), None); // line-A
        assert_eq!(instruction_length(&bytes(&[0xFFFF])), None); // line-F
    }

    #[test]
    fn move_word_immediate_to_data_register() {
        // MOVE.W #1,D0 — dest Dn (0 extra words), src immediate word (1 extra word).
        assert_eq!(instruction_length(&bytes(&[0x303C, 0x0001])), Some(4));
    }

    #[test]
    fn move_long_immediate_to_absolute_long() {
        // MOVE.L #$1000,($2000).L — src immediate long (2 extra words), dest
        // absolute long (2 extra words): both operands' extension words are
        // additive, not "one EA block for the whole instruction."
        assert_eq!(instruction_length(&bytes(&[0x23FC, 0x0000, 0x1000, 0x0000, 0x2000])), Some(10));
    }

    #[test]
    fn movem_has_a_mandatory_mask_word() {
        // MOVEM.L D0-D7/A0-A7,-(A7) — predecrement mode needs 0 EA extension
        // words, but the 16-bit register mask is always present regardless.
        assert_eq!(instruction_length(&bytes(&[0x48E7, 0xFFFF])), Some(4));
    }

    #[test]
    fn ext_w_is_not_modeled_as_movem() {
        // EXT.W D0 (0x4880) shares MOVEM's fixed bits with mode=000 (Dn),
        // which is not a valid MOVEM EA (register-direct addressing isn't
        // meaningful for a memory-list-transfer instruction). This decoder
        // doesn't model EXT specifically, so the correct answer is None —
        // not a wrong 4-byte MOVEM length. The buffer carries 2 trailing
        // bytes so a wrongly-computed length of 4 would still fit — the
        // mode-rejection branch, not the buffer-length filter, must be
        // what produces None here.
        assert_eq!(instruction_length(&bytes(&[0x4880, 0xFFFF])), None);
    }

    #[test]
    fn ext_l_is_not_modeled_as_movem() {
        // EXT.L D0 (0x48C0) — same collision as EXT.W above, with size=long.
        assert_eq!(instruction_length(&bytes(&[0x48C0, 0xFFFF])), None);
    }

    #[test]
    fn ext_l_other_register_is_not_modeled_as_movem() {
        // EXT.L D3 (0x48C3) — sweeps the register field to confirm the
        // mode-rejection isn't accidentally keyed off reg==0.
        assert_eq!(instruction_length(&bytes(&[0x48C3, 0xFFFF])), None);
    }

    #[test]
    fn rts_is_two_bytes() {
        assert_eq!(instruction_length(&bytes(&[0x4E75])), Some(2));
    }

    #[test]
    fn short_buffers_return_none() {
        assert_eq!(instruction_length(&[]), None);
        assert_eq!(instruction_length(&[0x30]), None); // half a word
        assert_eq!(instruction_length(&bytes(&[0x303C])), None); // needs an immediate word, none given
    }

    #[test]
    fn lea_into_non_a0_register() {
        // LEA (A0),A1 — destination register field (bits 11-9) must vary
        // across A0-A7; a mask that pins it to one value would wrongly
        // return None for every LEA except into A0.
        assert_eq!(instruction_length(&bytes(&[0x43D0])), Some(2));
    }

    #[test]
    fn dbcc_with_high_condition_code() {
        // DBGE D0,label — condition code GE=0b1100 has its top bit set;
        // a guard that pins that bit to 0 would reject half of all DBcc
        // conditions (including common ones like GE/LT/GT/LE).
        assert_eq!(instruction_length(&bytes(&[0x5CC8, 0x0000])), Some(4));
    }
}
