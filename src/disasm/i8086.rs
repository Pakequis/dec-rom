//! 8086 instruction-length/validity via `iced-x86`'s `Decoder` in 16-bit mode.
//! Known limitation: 16-bit mode also accepts genuine 80186+ encodings that
//! don't exist on a real 8086, since `iced-x86` has no per-CPU-generation gate.

use iced_x86::{Decoder, DecoderOptions};

/// `Some(length_in_bytes)` for a valid 16-bit-mode x86 instruction starting
/// at `bytes[0]`, `None` for an invalid encoding or an empty buffer. See
/// this module's doc comment for the 8086-vs-80186+ approximation caveat.
pub(crate) fn instruction_length(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut decoder = Decoder::new(16, bytes, DecoderOptions::NONE);
    let instr = decoder.decode();
    if instr.is_invalid() {
        None
    } else {
        Some(instr.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_opcodes_have_correct_lengths() {
        assert_eq!(instruction_length(&[0x90]), Some(1)); // NOP
        assert_eq!(instruction_length(&[0xB8, 0x00, 0x00]), Some(3)); // MOV AX,imm16
        assert_eq!(instruction_length(&[0xE9, 0x00, 0x00]), Some(3)); // JMP rel16
        assert_eq!(instruction_length(&[0xC3]), Some(1)); // RET
        assert_eq!(instruction_length(&[0xCD, 0x21]), Some(2)); // INT 21h
    }

    #[test]
    fn short_buffers_return_none() {
        assert_eq!(instruction_length(&[]), None);
    }
}
