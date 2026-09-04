//! 6502 instruction-length/validity via the `mos6502` crate's pure
//! `Variant::decode` associated function — no memory bus needed, matching
//! this project's static-validity use case rather than execution.

use mos6502::Variant;
use mos6502::instruction::Nmos6502;

/// `Some(length_in_bytes)` for a documented 6502 instruction starting at
/// `bytes[0]`, `None` for an illegal/undocumented opcode or if `bytes` is
/// too short for the addressing mode it decodes to.
pub(crate) fn instruction_length(bytes: &[u8]) -> Option<usize> {
    let opcode = *bytes.first()?;
    let (_, mode) = Nmos6502::decode(opcode)?;
    let len = 1 + mode.extra_bytes() as usize;
    Some(len).filter(|&len| bytes.len() >= len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_opcodes_have_correct_lengths() {
        assert_eq!(instruction_length(&[0xEA]), Some(1)); // NOP (implied)
        assert_eq!(instruction_length(&[0xA9, 0x00]), Some(2)); // LDA #imm
        assert_eq!(instruction_length(&[0xA5, 0x00]), Some(2)); // LDA zp
        assert_eq!(instruction_length(&[0xAD, 0x00, 0x00]), Some(3)); // LDA abs
        assert_eq!(instruction_length(&[0x4C, 0x00, 0x00]), Some(3)); // JMP abs
        assert_eq!(instruction_length(&[0x60]), Some(1)); // RTS
        assert_eq!(instruction_length(&[0xD0, 0x00]), Some(2)); // BNE rel
    }

    #[test]
    fn illegal_opcodes_return_none() {
        assert_eq!(instruction_length(&[0x9B]), None); // undocumented opcode not in Nmos6502
    }

    #[test]
    fn short_buffers_return_none() {
        assert_eq!(instruction_length(&[]), None);
        assert_eq!(instruction_length(&[0xAD, 0x00]), None); // abs needs 3 bytes, only 2 given
    }
}
