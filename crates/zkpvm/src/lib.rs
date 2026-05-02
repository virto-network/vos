//! # zkpvm — zero-knowledge prover and verifier for PVM bytecode
//!
//! A STARK proving system for the **PVM** instruction set used by
//! the Polkadot Virtual Machine and the Kunekt actor runtime.
//! Adapted from the Nexus zkVM (Stwo / Circle-STARK over M31),
//! retargeted at PVM via the `javm` interpreter and ECALL host-call
//! protocol.
//!
//! See the crate-level `README.md` for the full architecture
//! overview and which opcodes are bound today; `STATUS.md` for
//! soundness coverage; `PLAN.md` for the remaining phase plan.
//!
//! ## Quick start
//!
//! ```ignore
//! use javm::{Interpreter, ExitReason};
//! use zkpvm::{prove, verify, SideNote};
//! use zkpvm::core::tracing::TracingPvm;
//!
//! let pvm = Interpreter::new(code, bitmask, args, regs, memory, gas, max_steps);
//! let mut tracing = TracingPvm::new(pvm);
//! assert_eq!(tracing.run(), ExitReason::Trap);
//! let steps = tracing.into_trace();
//!
//! let mut side_note = SideNote::new(steps, code, bitmask);
//! let proof = prove(&mut side_note).expect("proving failed");
//! verify(proof, &side_note).expect("verification failed");
//! ```
//!
//! ## Crate layout
//!
//! - [`chips`] — per-chip AIRs and trace generators.  `chips::cpu`
//!   carries the bulk of the PVM-step constraints; the rest are
//!   auxiliary lookup tables (memory, register-memory, bitwise,
//!   power-of-two, range-256, jump-table, blake2b, program-memory,
//!   program-execution, boundary chips for initial / final state).
//! - [`core`] — PVM step / opcode / tracing types.  Mirrors
//!   `javm`'s semantics so trace fill matches the interpreter
//!   byte-for-byte.
//! - [`framework`] / [`framework_access`] — Stwo integration glue
//!   (component registration, claimed-sum collection, lookup
//!   element propagation).
//! - [`lookups`] — relation definitions for cross-chip lookups
//!   (Range256, BitwiseAnd, MemoryAccess, RegisterMemory,
//!   ProgramMemory, JumpTable, ProgramExecution, Blake2bState,
//!   Blake2bCall).
//! - [`trace`] — column-fill helpers + interaction-trace builder.
//! - [`proof`] — public proof type (serializable).
//! - `prove` / `verify` / `program_id` — top-level prover / verifier
//!   API plus the public program-commitment hash.
//!
//! ## Features
//!
//! - `prover` (default) — trace generation, proof creation, blake3
//!   commitments, rayon parallelism.  Pulls in heavy deps.
//! - `debug-internals` — exposes [`debug_claimed_sums`] for bisecting
//!   prover-side logup imbalances when adding a new constraint.  Off
//!   by default; production callers don't need it.
//! - `--no-default-features` — verifier-only, `no_std` compatible,
//!   minimal dep tree.
//!
//! ## API stability
//!
//! Items at this crate's root (`zkpvm::*`) are the **stable surface**:
//! [`prove`], [`prove_with_config`], [`verify`],
//! [`verify_with_max_log_size`], [`verify_chain`],
//! [`Proof`], [`SegmentState`], [`SideNote`],
//! [`PROOF_FORMAT_VERSION`], [`DEFAULT_MAX_LOG_SIZE`], [`PcsConfig`],
//! [`FriConfig`], [`production_pcs_config`],
//! [`program_commitment_of_proof`], [`program_commitment_hex`],
//! [`ProgramCommitment`].  These are versioned by
//! [`PROOF_FORMAT_VERSION`]: a verifier compiled against version N
//! rejects proofs from any other N.
//!
//! Sub-modules ([`chips`], [`core`], [`framework_access`],
//! [`air_column`], [`trace`], [`proof`]) are **internal — their
//! shapes change without notice**.  They're public only because the
//! companion `zkpvm-verifier` crate links against them and the AIR
//! column derives need crate-root access.  External consumers should
//! not rely on these.

#![cfg_attr(not(feature = "prover"), no_std)]
// In verifier-only builds (--no-default-features), prover-only modules are
// gated out, so many helper fns / structs / consts in always-compiled
// modules become dead from the compiler's perspective.  Silence those
// lints crate-wide when prover is off; on the default build the lints
// remain active and catch genuine dead code.
#![cfg_attr(not(feature = "prover"), allow(dead_code, unused_imports))]

extern crate alloc;

pub mod air_column;
pub mod core;
pub mod trace;
pub mod chips;
mod framework;
mod lookups;
pub mod framework_access;
pub mod proof;

#[cfg(feature = "prover")]
pub mod side_note;

#[cfg(feature = "prover")]
mod prove;
#[cfg(feature = "prover")]
mod verify;
#[cfg(feature = "prover")]
mod program_id;

// Re-export AirColumn + PreprocessedAirColumn at crate root so the derive-
// generated impls (which target `::zkpvm::AirColumn`) resolve correctly.
pub use air_column::{AirColumn, PreprocessedAirColumn};

// Ordering rule: all consumers of a lookup table must be listed BEFORE the table
// chip itself.  Table chips populate their multiplicity column by reading counts
// that consumers accumulate into SideNote during trace generation.
#[cfg(feature = "prover")]
const BASE_COMPONENTS: &[&dyn framework::MachineProverComponent] = &[
    &chips::CpuChip,
    &chips::Blake2bChip, // consumes Bitwise AND lookup
    &chips::MemoryChip,
    &chips::MemoryBoundaryChip,
    &chips::RegisterMemoryChip,
    &chips::RegisterMemoryBoundaryChip,
    &chips::ProgramBoundaryChip,
    &chips::ProgramMemoryChip, // 13a — producer-only until CpuChip consumer in 13b
    &chips::JumpTableChip,     // 13d — producer of jump_table[] lookups
    &chips::RangeMultiplicity256,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
    &chips::PopcountChip, // Phase 33 — per-byte popcount lookup table
    &chips::BitcountChip, // Phase 34 — per-byte (lz, tz) lookup table
    &chips::MulChip,      // Phase 54a — consumer of MultiplicationLookup
    &chips::BitwiseChip,  // Phase 54e — consumer of BitwiseLookup, producer of BitwiseAnd nibble lookups
];

#[cfg(not(feature = "prover"))]
const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[
    &chips::CpuChip,
    &chips::Blake2bChip,
    &chips::MemoryChip,
    &chips::MemoryBoundaryChip,
    &chips::RegisterMemoryChip,
    &chips::RegisterMemoryBoundaryChip,
    &chips::ProgramBoundaryChip,
    &chips::ProgramMemoryChip,
    &chips::JumpTableChip,
    &chips::RangeMultiplicity256,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
    &chips::PopcountChip,
    &chips::BitcountChip,
    &chips::MulChip,
    &chips::BitwiseChip, // Phase 54e — consumer of BitwiseLookup, producer of BitwiseAnd nibble lookups
];

pub use proof::{
    check_pcs_policy, PcsPolicy, Proof, SegmentState, PROOF_FORMAT_VERSION,
    STANDARD_MIN_FRI_LOG_BLOWUP, STANDARD_MIN_FRI_QUERIES, STANDARD_MIN_POW_BITS,
};
#[cfg(feature = "prover")]
pub use prove::{prove, prove_with_config, prove_profiled, prove_profiled_with_config, ProveProfile, production_pcs_config};
#[cfg(feature = "debug-internals")]
pub use prove::debug_claimed_sums;
pub use stwo::core::pcs::PcsConfig;
pub use stwo::core::fri::FriConfig;
#[cfg(feature = "prover")]
pub use verify::{
    verify, verify_chain, verify_with_max_log_size, verify_with_options,
    verify_with_pcs_policy, DEFAULT_MAX_LOG_SIZE,
};
#[cfg(feature = "prover")]
pub use side_note::SideNote;
#[cfg(feature = "prover")]
pub use program_id::{program_commitment_of_proof, program_commitment_hex, ProgramCommitment};
