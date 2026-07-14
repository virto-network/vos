//! # zkpvm — zero-knowledge prover and verifier for PVM bytecode
//!
//! A STARK proving system for the **PVM** instruction set used by
//! the Polkadot Virtual Machine and the Kunekt actor runtime.
//! Adapted from the Nexus zkVM (Stwo / Circle-STARK over M31),
//! retargeted at PVM via the `javm` interpreter and ECALL host-call
//! protocol.
//!
//! See the crate-level `README.md` for the architecture overview,
//! `STATUS.md` for soundness coverage, `SECURITY.md` for the trust
//! boundary, and `docs/plans/mobile-proving.md` for the chain-prove /
//! low-RAM direction.
//!
//! ## Quick start
//!
//! Trace a PVM program, prove its execution, verify the proof:
//!
//! ```ignore
//! use zkpvm::{trace_blob, prove_mobile, verify_with_pcs_policy, PcsPolicy};
//!
//! // `pvm_blob` is a transpiled PVM program; `gas` bounds tracing.
//! let mut sn = trace_blob(&pvm_blob, gas).expect("trace");
//! let proof = prove_mobile(&mut sn).expect("prove");   // MOBILE = low latency
//! verify_with_pcs_policy(proof, &sn, &PcsPolicy::MOBILE).expect("verify");
//! ```
//!
//! A *deployed* verifier sees only the proof + the program commitment
//! (not the trace) and uses the side-note-free `verify_standalone` from
//! the separate `no_std` `zkpvm-verifier` crate. Executions too large
//! for one proof are proved as a chain — see [`verify_chain`], the
//! [`segment`] cut helpers, and the `prover-extension` crate for the
//! streaming / CAS deployment.
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
//! ## API surface
//!
//! The prover-side happy path lives at the crate root:
//!
//! - **Trace** — [`trace_blob`] (whole trace) or [`SideNote::new`]
//!   from a hand-built step trace; [`trace_blob_compact`] /
//!   [`trace_stream`] for the chain / streaming paths.
//! - **Prove** — [`prove`] (STANDARD) or [`prove_mobile`] (low-latency
//!   MOBILE); [`prove_with_config`] for a custom [`PcsConfig`].
//! - **Verify** — [`verify`] / [`verify_with_pcs_policy`] (prover-side,
//!   with the SideNote); [`verify_chain`] for a segment chain. The
//!   side-note-free deployer verifier is `verify_standalone` in the
//!   `zkpvm-verifier` crate.
//! - **Identity** — [`program_commitment_of_proof`] /
//!   [`program_commitment_hex`] extract the program commitment a
//!   verifier pins.
//! - **Large executions** — the [`segment`] cut helpers,
//!   [`canonical_profile_for`], and [`prove_canonical`] produce a
//!   chain of equal-shape segments; the `prover-extension` crate wraps
//!   these with CAS publishing, allowlists, and async jobs.
//!
//! Core types: [`Proof`], [`SegmentState`], [`SideNote`],
//! [`CompactTrace`], [`PcsPolicy`], [`PcsConfig`], [`FriConfig`].
//!
//! Proofs are versioned by [`PROOF_FORMAT_VERSION`]: a verifier
//! compiled against version N rejects proofs from any other N. Items
//! marked `#[doc(hidden)]`, and the sub-modules ([`chips`], [`core`],
//! [`trace`], [`proof`], …), are **internal — their shapes change
//! without notice**; they are public only for the verifier crate, the
//! `prover-extension`, and the AIR-column derives.

#![cfg_attr(not(feature = "prover"), no_std)]
// In verifier-only builds (--no-default-features), prover-only modules are
// gated out, so many helper fns / structs / consts in always-compiled
// modules become dead from the compiler's perspective.  Silence those
// lints crate-wide when prover is off; on the default build the lints
// remain active and catch genuine dead code.
#![cfg_attr(not(feature = "prover"), allow(dead_code, unused_imports))]
// Stylistic lints carried over from the Nexus port — fixing them
// touches a wide swath of generated chip code and would obscure the
// upstream diff. Allowed crate-wide so the workspace's `-D warnings`
// gate doesn't reject the verbatim port. Correctness-relevant lints
// (e.g. `unsound_*`, `correctness::*`) remain active.
#![allow(
    clippy::needless_range_loop,
    clippy::needless_lifetimes,
    clippy::uninlined_format_args,
    clippy::manual_div_ceil,
    clippy::nonminimal_bool,
    clippy::no_effect,
    clippy::manual_range_patterns,
    clippy::derivable_impls,
    clippy::field_reassign_with_default,
    clippy::new_without_default,
    clippy::unnecessary_cast,
    clippy::duplicated_attributes,
    clippy::doc_overindented_list_items,
    clippy::identity_op
)]

extern crate alloc;

pub mod air_column;
pub mod boundary_binding;
pub mod chips;
pub mod core;
mod framework;
pub mod framework_access;
mod lookups;
pub mod proof;
pub mod segment;
pub mod trace;

// Native-recursion Stage-0: the Poseidon2-M31 PCS primitives + the per-build
// PCS selection. Both are `no_std`-clean (verifier path uses them too); their
// prover-only pieces are `#[cfg(feature = "prover")]` within.
pub mod poseidon2;
pub mod recursion_pcs;

// The page-hash spec constants + tag chaining states are needed by the new
// memory-Merkle chips' `add_constraints` (verifier-side, `no_std`); the
// `SideNote` / segment / host-tree-building parts are `#[cfg(prover)]` within.
pub mod page_merkle;

#[cfg(feature = "prover")]
pub mod side_note;

#[cfg(feature = "prover")]
pub mod actor;
#[cfg(feature = "prover")]
mod program_id;
#[cfg(feature = "prover")]
mod prove;
#[cfg(feature = "prover")]
mod verify;

// Re-export AirColumn + PreprocessedAirColumn at crate root so the derive-
// generated impls (which target `::zkpvm::AirColumn`) resolve correctly.
pub use air_column::{AirColumn, PreprocessedAirColumn};

/// Diagnostics: the full BASE_COMPONENTS slice (no activity filter).
/// Returns ALL chips, in declaration order. Test harnesses use this
/// to bisect ConstraintsNotSatisfied failures — force a chip to be
/// active even when its activity flag would normally drop it.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub fn all_components() -> &'static [&'static dyn framework::MachineProverComponent] {
    BASE_COMPONENTS
}

// Ordering rule: all consumers of a lookup table must be listed BEFORE the table
// chip itself.  Table chips populate their multiplicity column by reading counts
// that consumers accumulate into SideNote during trace generation.
//
// Blake2bChip is OPTIONAL.  Skipped when no blake2b ECALL fired in the
// trace.  Saves ~10% prove time and ~57% proof size on workloads that don't
// hash.  Both prover and verifier must agree on inclusion — `active_components`
// is the single source of truth and is deterministic from `SideNote`.
/// Indices into [`BASE_COMPONENTS`] for chips referenced by name in
/// `ChipActivity::is_active`, `Proof::component_mask` bit positions,
/// and other bit-position-sensitive sites (e.g. the boundary-binding
/// check in `boundary_binding`, which the standalone verifier also
/// uses — hence public and feature-ungated).
///
/// Indexed positions are coupled to the declaration order of
/// `BASE_COMPONENTS`. If you reorder the array, update these constants
/// at the same time — the trailing length assertion catches a
/// shortened array but not a within-bounds reorder. The named
/// constants double as documentation for which chip each match arm
/// in `is_active` refers to, so they're kept even for chips that
/// don't currently appear in a match arm.
#[allow(dead_code)]
pub mod chip_idx {
    pub const CPU: usize = 0;
    pub const BLAKE2B: usize = 1;
    pub const BLAKE2B_BOUNDARY: usize = 2;
    pub const MEMORY: usize = 3;
    pub const MEMORY_PAGE: usize = 4;
    pub const MEMORY_MERKLE: usize = 5;
    pub const MEMORY_ROOT_BOUNDARY: usize = 6;
    pub const REGISTER_MEMORY: usize = 7;
    pub const REGISTER_MEMORY_BOUNDARY: usize = 8;
    pub const REGISTER_MEMORY_CLOSING: usize = 9;
    pub const PROGRAM_BOUNDARY: usize = 10;
    pub const PROGRAM_MEMORY: usize = 11;
    pub const JUMP_TABLE: usize = 12;
    pub const RANGE_MULTIPLICITY_256: usize = 13;
    pub const BITWISE_LOOKUP: usize = 14;
    pub const POWER_OF_TWO: usize = 15;
    pub const POPCOUNT: usize = 16;
    pub const BITCOUNT: usize = 17;
    pub const BYTE_TO_BITS: usize = 18;
    pub const MUL: usize = 19;
    pub const BITWISE: usize = 20;
    pub const COMPARE: usize = 21;
    pub const DIVREM: usize = 22;
    pub const RISTRETTO: usize = 23;
    pub const RISTRETTO_ECALL: usize = 24;
    pub const RISTRETTO_COMB_TABLE: usize = 25;
    pub const RISTRETTO_FIXED_BASE_CONSUMER: usize = 26;
    pub const RISTRETTO_COMB_ANCHOR: usize = 27;
    pub const RISTRETTO_COMB_SCALAR_BOUNDARY: usize = 28;
    pub const RISTRETTO_COMB_COMPRESS: usize = 29;
    pub const RISTRETTO_COMB_COMPRESS_OUTPUT: usize = 30;
    /// 2^16-row byte-wide AND table.  Placed last: it is a receiver whose
    /// multiplicity counts are accumulated by the two blake2b chips during
    /// their trace-gen (idx 1/2), so it must be generated after all its
    /// consumers (BASE_COMPONENTS ordering rule).
    pub const BITWISE_AND_BYTE: usize = 31;
    /// Total entries expected in `BASE_COMPONENTS`. Trailing const-time
    /// assertion in `lib.rs` checks this against the actual array length.
    pub const COUNT: usize = BITWISE_AND_BYTE + 1;
}

#[cfg(feature = "prover")]
const BASE_COMPONENTS: &[&dyn framework::MachineProverComponent] = &[
    &chips::CpuChip,
    &chips::Blake2bChip, // OPTIONAL — gated by !side_note.blake2b_calls.is_empty()
    &chips::Blake2bBoundaryChip, // proves the memory-page Merkle blake2b compressions
    &chips::MemoryChip,
    &chips::MemoryPageChip, // per-page boundary writes/reads + leaf hashes
    &chips::MemoryMerkleChip, // Merkle merge rows
    &chips::MemoryRootBoundaryChip, // root sink (bound to public roots)
    &chips::RegisterMemoryChip,
    &chips::RegisterMemoryBoundaryChip,
    &chips::RegisterMemoryClosingChip, // pins proof.final_state.registers
    &chips::ProgramBoundaryChip,
    &chips::ProgramMemoryChip, // producer-only until the CpuChip consumer is added
    &chips::JumpTableChip,     // producer of jump_table[] lookups
    &chips::RangeMultiplicity256,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
    &chips::PopcountChip,           // per-byte popcount lookup table
    &chips::BitcountChip,           // per-byte (lz, tz) lookup table
    &chips::ByteToBitsChip, // per-byte 8-bit decomposition lookup table (dormant until consumers are added)
    &chips::MulChip,        // consumer of MultiplicationLookup
    &chips::BitwiseChip, // consumer of BitwiseLookup, producer of BitwiseAnd nibble lookups
    &chips::CompareChip, // consumer of CompareLookup, producer of Range256 lookups
    &chips::DivRemChip,  // consumer of DivRemLookup
    &chips::RistrettoChip, // OPTIONAL precompile, gated by activity.ristretto
    &chips::RistrettoEcallChip, // OPTIONAL, gated by activity.ristretto_ecall
    &chips::RistrettoCombTableChip, // OPTIONAL, gated by activity.ristretto_comb
    &chips::RistrettoFixedBaseConsumerChip, // OPTIONAL, gated by activity.ristretto_comb
    &chips::RistrettoCombAnchorChip, // column-shrink — OPTIONAL, gated by activity.ristretto_comb
    &chips::RistrettoCombScalarBoundaryChip, // OPTIONAL, gated by activity.ristretto_comb
    &chips::RistrettoCombCompressChip, // OPTIONAL, gated by activity.ristretto_comb
    &chips::RistrettoCombCompressOutputChip, // OPTIONAL, gated by activity.ristretto_comb
    &chips::BitwiseAndByteChip, // byte-wide AND table — consumed by the two blake2b chips
];

#[cfg(feature = "prover")]
const _: () = {
    assert!(
        BASE_COMPONENTS.len() == chip_idx::COUNT,
        "BASE_COMPONENTS length must match chip_idx::COUNT — chip added or removed without \
         updating the constants in chip_idx",
    );
};

#[cfg(not(feature = "prover"))]
const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[
    &chips::CpuChip,
    &chips::Blake2bChip,
    &chips::Blake2bBoundaryChip,
    &chips::MemoryChip,
    &chips::MemoryPageChip,
    &chips::MemoryMerkleChip,
    &chips::MemoryRootBoundaryChip,
    &chips::RegisterMemoryChip,
    &chips::RegisterMemoryBoundaryChip,
    &chips::RegisterMemoryClosingChip, // pins proof.final_state.registers
    &chips::ProgramBoundaryChip,
    &chips::ProgramMemoryChip,
    &chips::JumpTableChip,
    &chips::RangeMultiplicity256,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
    &chips::PopcountChip,
    &chips::BitcountChip,
    &chips::ByteToBitsChip, // per-byte 8-bit decomposition lookup table
    &chips::MulChip,
    &chips::BitwiseChip, // consumer of BitwiseLookup, producer of BitwiseAnd nibble lookups
    &chips::CompareChip, // consumer of CompareLookup, producer of Range256 lookups
    &chips::DivRemChip,  // consumer of DivRemLookup
    &chips::RistrettoChip, // OPTIONAL precompile, mirrored in verifier-only build
    &chips::RistrettoEcallChip, // OPTIONAL, mirrored in verifier-only build
    &chips::RistrettoCombTableChip,
    &chips::RistrettoFixedBaseConsumerChip,
    &chips::RistrettoCombAnchorChip,
    &chips::RistrettoCombScalarBoundaryChip,
    &chips::RistrettoCombCompressChip,
    &chips::RistrettoCombCompressOutputChip,
    &chips::BitwiseAndByteChip,
];

#[cfg(not(feature = "prover"))]
const _: () = {
    assert!(
        BASE_COMPONENTS.len() == chip_idx::COUNT,
        "BASE_COMPONENTS length must match chip_idx::COUNT — chip added or removed without \
         updating the constants in chip_idx",
    );
};

/// Deterministic, side-note-driven filter on `BASE_COMPONENTS`.
/// Returns the components active for THIS trace, in declaration order.
///
/// Both prover and verifier MUST construct the same list.  The predicate
/// reads only `SideNote` fields the verifier also has access to (the
/// public side_note is an input to `verify`).
///
/// Skipping a chip is safe iff all of its lookup producers and consumers
/// have multiplicity 0 across the trace.  For Blake2bChip: no calls in
/// `side_note.blake2b_calls` ⇒ no Blake2b producers/consumers fire on
/// CpuChip or MemoryChip ⇒ all relevant lookup balances stay 0=0.
///
/// Index 1 in `BASE_COMPONENTS` is Blake2bChip — skipping that index is
/// the current implementation.  When more chips become conditional,
/// each gains a corresponding index check.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub fn active_components(
    side_note: &side_note::SideNote,
) -> alloc::vec::Vec<&'static dyn framework::MachineProverComponent> {
    let a = activity_from_steps(side_note);
    BASE_COMPONENTS
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| if a.is_active(i) { Some(c) } else { None })
        .collect()
}

/// Per-chip activity flags inferred from `side_note.steps`
/// alone (no entries-vec dependency), so the predicate can run BEFORE
/// CpuChip's trace_fill populates side_note's per-family entries.
///
/// Each flag: "is there ≥ 1 step with a corresponding opcode in the
/// trace?".  Uses `classify_opcode` for opcode-class detection plus
/// direct `(opcode, imm)` matching for the blake2b ECALL.
#[cfg(feature = "prover")]
fn activity_from_steps(side_note: &side_note::SideNote) -> ChipActivity {
    use crate::chips::cpu::classify::classify_opcode as classify;
    use crate::core::ecall::{
        ECALL_BLAKE2B_COMPRESS, ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT,
        ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, ECALL_SCALAR_MUL_MOD_L,
    };
    use crate::core::opcode::Opcode;
    let mut a = ChipActivity::default();
    for step in &side_note.steps {
        // Blake2b ECALL detection via opcode + imm match (mirrors
        // trace_fill.rs's IsBlakeEcall fill at ~line 1075).
        if matches!(step.opcode, Opcode::Ecalli | Opcode::Ecall)
            && step.imm == ECALL_BLAKE2B_COMPRESS as u64
        {
            a.blake2b = true;
        }
        // Ristretto scalar-mult ECALL gates RistrettoEcallChip. Whether
        // RistrettoChip itself is active depends on the *kind* of the
        // recorded call: Variable scalar mults populate
        // `ristretto_field_rows` and are handled below; FixedBasepoint
        // calls route to the comb-method chips (21..=26) and bypass
        // RistrettoChip. We can't tell the kind from `step.imm` alone,
        // so activate RistrettoChip only via the `ristretto_field_rows`
        // post-ingest check; this avoids activating an empty chip when
        // every scalar mult in the trace was FixedBase.
        if matches!(step.opcode, Opcode::Ecalli | Opcode::Ecall)
            && step.imm == ECALL_RISTRETTO_SCALAR_MULT as u64
        {
            a.ristretto_ecall = true;
        }
        // The point-add and scalar-reduce-wide ECALLs
        // activate the RistrettoEcallChip but not RistrettoChip
        // (those don't fire field-op rows).
        if matches!(step.opcode, Opcode::Ecalli | Opcode::Ecall)
            && (step.imm == ECALL_RISTRETTO_POINT_ADD as u64
                || step.imm == ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE as u64
                || step.imm == ECALL_SCALAR_MUL_MOD_L as u64
                || step.imm == ECALL_SCALAR_ADD_MOD_L as u64)
        {
            a.ristretto_ecall = true;
        }
        let f = classify(step.opcode);
        if f.is_jump_ind || f.is_load_imm_jump_ind {
            a.jump_table = true;
        }
        if f.is_count_set_bits {
            a.popcount = true;
        }
        if f.is_lzb || f.is_tzb {
            a.bitcount = true;
        }
        if f.is_mul
            || f.is_mul_upper_uu
            || f.is_mul_upper_su
            || f.is_mul_upper_ss
            || f.is_rotate_l64
            || f.is_rotate_r64
            || f.is_rotate_l32
            || f.is_rotate_r32
        {
            a.mul = true;
        }
        if f.is_and || f.is_or || f.is_xor || f.is_and_inv || f.is_or_inv || f.is_xnor {
            a.bitwise = true;
        }
        // Compare = SetLt*/Cmov*/Min/Max + branches.
        if f.is_set_lt_u
            || f.is_set_lt_s
            || f.is_cmov_iz
            || f.is_cmov_nz
            || f.is_min_s
            || f.is_min_u
            || f.is_max_s
            || f.is_max_u
            || f.is_branch
        {
            a.compare = true;
        }
        if f.is_div_rem {
            a.divrem = true;
        }
    }
    // Chip-level tests that bypass the ECALL path can pre-populate
    // ristretto_field_rows directly.
    if !side_note.ristretto_field_rows.is_empty() {
        a.ristretto = true;
    }
    // Comb-method consumer + producer chips fire
    // when at least one fixed-basepoint scalar mult call is queued in
    // `ristretto_comb_calls`.  In production this is populated by the
    // ECALL routing; in chip-isolated tests the harness pushes
    // calls directly.
    if !side_note.ristretto_comb_calls.is_empty() {
        a.ristretto_comb = true;
    }
    a
}

#[cfg(feature = "prover")]
#[derive(Default, Clone, Copy)]
struct ChipActivity {
    blake2b: bool,
    jump_table: bool,
    popcount: bool,
    bitcount: bool,
    mul: bool,
    bitwise: bool,
    compare: bool,
    divrem: bool,
    ristretto: bool,
    ristretto_ecall: bool,
    ristretto_comb: bool,
}

#[cfg(feature = "prover")]
impl ChipActivity {
    fn is_active(&self, idx: usize) -> bool {
        // Indices are pinned by `chip_idx` (see lib.rs `mod chip_idx`).
        // Always-active chips fall through to the default arm — only
        // gated chips (= those that depend on side-note evidence to
        // contribute a non-zero claimed_sum) need an explicit arm.
        match idx {
            chip_idx::BLAKE2B => self.blake2b,
            chip_idx::JUMP_TABLE => self.jump_table,
            chip_idx::POPCOUNT => self.popcount,
            chip_idx::BITCOUNT => self.bitcount,
            chip_idx::MUL => self.mul,
            chip_idx::BITWISE => self.bitwise,
            chip_idx::COMPARE => self.compare,
            chip_idx::DIVREM => self.divrem,
            chip_idx::RISTRETTO => self.ristretto,
            chip_idx::RISTRETTO_ECALL => self.ristretto_ecall,
            chip_idx::RISTRETTO_COMB_TABLE
            | chip_idx::RISTRETTO_FIXED_BASE_CONSUMER
            | chip_idx::RISTRETTO_COMB_ANCHOR
            | chip_idx::RISTRETTO_COMB_SCALAR_BOUNDARY
            | chip_idx::RISTRETTO_COMB_COMPRESS
            | chip_idx::RISTRETTO_COMB_COMPRESS_OUTPUT => self.ristretto_comb,
            _ => true,
        }
    }
}

/// Bitmask of active chips (bit i ⇔ BASE_COMPONENTS[i] is
/// included).  Embedded in `Proof::component_mask` so the standalone
/// verifier can reconstruct the active set without a SideNote.
#[cfg(feature = "prover")]
pub(crate) fn active_component_mask(side_note: &side_note::SideNote) -> u32 {
    let a = activity_from_steps(side_note);
    let mut mask = 0u32;
    for i in 0..BASE_COMPONENTS.len() {
        if a.is_active(i) {
            mask |= 1 << i;
        }
    }
    mask
}

/// Verifier-side mirror of `active_components`, returning the
/// same selection upcast to `&dyn MachineComponent`.
#[cfg(feature = "prover")]
pub(crate) fn active_components_verifier(
    side_note: &side_note::SideNote,
) -> alloc::vec::Vec<&'static dyn framework::MachineComponent> {
    let a = activity_from_steps(side_note);
    BASE_COMPONENTS
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| {
            if a.is_active(i) {
                Some(c as &dyn framework::MachineComponent)
            } else {
                None
            }
        })
        .collect()
}

pub use proof::{PROOF_FORMAT_VERSION, PcsPolicy, Proof, SegmentState};
// The per-policy FRI floor constants + the policy checker: used by callers
// that assemble a custom `PcsPolicy`; hidden from the top-level page.
#[doc(hidden)]
pub use proof::{
    MOBILE_MIN_FRI_LOG_BLOWUP, MOBILE_MIN_FRI_QUERIES, MOBILE_MIN_POW_BITS,
    STANDARD_MIN_FRI_LOG_BLOWUP, STANDARD_MIN_FRI_QUERIES, STANDARD_MIN_POW_BITS, check_pcs_policy,
};
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use prove::prove_with_boundary_override;
// ── Prove: the stable surface ────────────────────────────────────────
// Single proof: `prove` / `prove_mobile` / `prove_with_config`.
// Segment chain: `canonical_profile_for` (or `_for_bounds`) derives the
// forcing profile, `prove_canonical` proves each window to one shape.
#[cfg(feature = "prover")]
pub use prove::{
    canonical_profile_for, canonical_profile_for_bounds, prove, prove_canonical, prove_chain,
    prove_mobile, prove_with_config,
};
// Advanced / internal prove surface: the compact-trace floor variant, the
// profiling variants, the thread-pool installer, and the explicit-component
// harness entry.  Public for the prover extension + tests; hidden from docs
// so the top-level page stays the happy path.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use prove::{
    NaturalFloors, ProveProfile, canonical_profile_for_bounds_compact, install_thread_pool,
    natural_log_sizes_for, prepare_side_note_for_verification, production_pcs_config,
    production_pcs_config_mobile, prove_profiled, prove_profiled_with_config,
    prove_with_explicit_components,
};
// ── Trace a PVM blob into a SideNote / CompactTrace ───────────────────
// The ergonomic entry points: `trace_blob` (whole trace, single proof),
// `trace_blob_compact` / `trace_stream` (chain / streaming paths).
#[cfg(feature = "prover")]
pub use actor::{
    interpreter_from_blob, trace_blob, trace_blob_compact, trace_blob_compact_with_patches,
    trace_blob_with_patches, trace_stream, trace_stream_with_patches,
};
#[cfg(feature = "debug-internals")]
pub use prove::{
    debug_assert_constraints_explicit, debug_assert_constraints_streaming, debug_claimed_sums,
    debug_claimed_sums_streaming,
};
#[cfg(feature = "prover")]
pub use side_note::{CompactTrace, SideNote};
pub use stwo::core::fri::FriConfig;
pub use stwo::core::pcs::PcsConfig;
// ── Verify (prover-side, with the SideNote): the stable surface ───────
// The side-note-FREE deployer verifier lives in the `zkpvm-verifier` crate
// (`verify_standalone`) — no_std, no prover deps.
#[cfg(feature = "prover")]
pub use verify::{
    DEFAULT_MAX_LOG_SIZE, verify, verify_chain, verify_with_pcs_policy,
};
// Advanced verify surface (max-log-size / options / explicit components)
// and the OODS reconstruction the recursion path consumes.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use verify::{
    ComponentOodsMask, OodsReconstruction, reconstruct_oods_for_recursion,
    verify_with_explicit_components, verify_with_max_log_size, verify_with_options,
};
#[doc(hidden)]
#[cfg(all(feature = "prover", feature = "poseidon2-channel"))]
pub use verify::{
    DeepBatch, RecursionData, RecursionTranscript, extract_recursion_data,
    record_canonical_transcript,
};

/// Chip-isolated harness surface — re-exports the trait
/// objects callers need to assemble an explicit component slice for
/// `prove_with_explicit_components` / `verify_with_explicit_components`.
/// Intended only for the v2.x chip-rewrite validation harness; production
/// code should use `prove` / `verify`.  Callers build their own
/// `&[&dyn MachineProverComponent]` slice from the chip structs in
/// `crate::chips`.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub mod harness {
    pub use crate::framework::{MachineComponent, MachineProverComponent};
}
#[cfg(feature = "prover")]
pub use program_id::{ProgramCommitment, program_commitment_hex, program_commitment_of_proof};
