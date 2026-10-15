//! GP standard-program (SPI) blob emitter.
//!
//! Serializes the standard PVM program format — the blob
//! `vos_pvm::spi::parse_standard_program` consumes. This is the byte-for-byte
//! inverse of that parser and its `deblob_compact` code decoder:
//!
//! ```text
//!   program:  E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s) ‖ o ‖ w ‖ E₄(|c|) ‖ c
//!   c:        E(|j|) ‖ E₁(z_j) ‖ E(|code|) ‖ jump_table ‖ code ‖ packed_bitmask
//! ```
//!
//! where `o` = read-only data, `w` = read-write data, `z` = additional zeroed
//! heap pages, `s` = stack size in bytes, `z_j` = the jump-table entry width
//! in bytes, `Eₙ(·)` is a fixed-width little-endian integer, and `E(·)` is
//! the standard natural encoding. No metadata prefix is emitted or accepted:
//! the result is one canonical bare program blob.
