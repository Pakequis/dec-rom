//! Library crate for Dec-ROM's domain logic: bit-permutation math, processor
//! detection, and the Auto-Fix search engine. The GUI binary and the
//! regression tests both link against this crate.

pub mod reorganizer;
pub mod detectors;
pub mod autofix;
pub mod scoring;

pub mod disasm;
pub mod known_patterns;
pub mod pinouts;
pub mod scheme_txt;
