//! The actor ABI's types: their encodings, byte for byte, and the rules
//! they carry.

mod abi;
mod keys;

/// The bytes a hex string spells.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}
