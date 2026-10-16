//! RISC-V ELF to JAM PVM transpiler.
//!
//! Converts RISC-V rv64em ELF binaries into Gray Paper standard programs
//! (Appendix A).
//!
//! Also provides utilities to hand-assemble PVM programs directly.
//!
//! Two invariants keep translation sound:
//!
//! - **x0 is never a PVM register.** PVM register 0 holds the return
//!   address, so `TranslationContext::require_reg` refuses x0 and every
//!   translation handles an x0 source or destination itself.
//! - **A pass never clears the bitmask of an instruction start.** A PVM
//!   immediate's length follows from the instruction's length, so folding
//!   bytes into the previous instruction changes what it decodes to. A
//!   fusion writes its result where the first instruction of the pair
//!   started, with a full four-byte immediate that trailing continuation
//!   bytes cannot change.

pub mod assembler;
mod derive;
mod linker;
mod peephole;
mod riscv;
mod spi;

use thiserror::Error;

pub use derive::{DeriveError, Derived, INVOCATION_HEAP, MAX_ELF, TRANSPILER_VERSION, derive};
pub use linker::{link_elf_spi, link_elf_spi_with_symbols};
pub use spi::{ServiceMetadata, service_blob};

pub(crate) use peephole::{
    ensure_branch_targets_are_block_starts, peephole_fuse_load_imm_alu,
    peephole_fuse_load_imm_memory,
};

#[derive(Error, Debug)]
pub enum TranspileError {
    #[error("ELF parse error: {0}")]
    ElfParse(String),
    #[error("unsupported RISC-V instruction at offset {offset:#x}: {detail}")]
    UnsupportedInstruction { offset: usize, detail: String },
    #[error("register mapping error: RISC-V register {0} has no PVM equivalent")]
    RegisterMapping(u8),
    #[error("invalid section: {0}")]
    InvalidSection(String),
}

/// A program's functions: each one's first PVM instruction in its code, and
/// its name (demangled), by offset.
pub type Functions = Vec<(u32, String)>;
