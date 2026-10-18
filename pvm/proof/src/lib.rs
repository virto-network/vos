//! # vos-pvm-proof — zero-knowledge prover and verifier for PVM bytecode
//!
//! A STARK proving system for the **PVM** instruction set used by
//! the Polkadot Virtual Machine and the VOS actor runtime.
//! Adapted from the Nexus zkVM (Stwo / Circle-STARK over M31),
//! retargeted at PVM via the `vos_pvm` interpreter and ECALL host-call
//! protocol.
//!
//! See the crate-level `README.md` for the architecture overview,
//! `docs/status.md` for soundness coverage, `SECURITY.md` for the trust
//! boundary, and `docs/plans/roadmap.md` for the chain-prove /
//! low-RAM direction.
//!
//! ## Quick start
//!
//! Trace a standard program's refine run, prove it, verify the proof:
//!
//! ```no_run
//! use vos_pvm_proof::{prove_refine, trace_refine_with_output, verify_refine_bundle_replayed};
//!
//! # fn example(program: &[u8], arguments: &[u8]) {
//! // `gas` bounds the run; the output is read back, up to 32 bytes.
//! let gas = 1_000_000_000;
//! let (trace, _output) = trace_refine_with_output(program, arguments, gas, 32).expect("trace");
//! let bundle = prove_refine(trace).expect("prove");
//! verify_refine_bundle_replayed(&bundle, program, arguments, gas).expect("verify");
//! # }
//! ```
//!
//! A *deployed* verifier sees only the proof + the program commitment
//! (not the trace) and uses the side-note-free `verify_standalone` from
//! the separate `no_std` `vos-pvm-proof-verifier` crate. Executions too large
//! for one proof are proved as a chain — see [`verify_chain`] and the
//! [`segment`] cut helpers.
//!
//! ## Crate layout
//!
//! - [`chips`] — per-chip AIRs and trace generators.  `chips::cpu`
//!   carries the bulk of the PVM-step constraints; the rest are
//!   auxiliary lookup tables (memory, register-memory, bitwise,
//!   power-of-two, range-256, jump-table, blake2b, program-memory,
//!   program-execution, boundary chips for initial / final state).
//! - [`core`] — PVM step / opcode / tracing types.  Mirrors
//!   `vos_pvm`'s semantics so trace fill matches the interpreter
//!   byte-for-byte.
//! - `framework` / [`framework_access`] — Stwo integration glue
//!   (component registration, claimed-sum collection, lookup
//!   element propagation).
//! - `lookups` — relation definitions for cross-chip lookups
//!   (Range256, BitwiseAnd, MemoryAccess, RegisterMemory,
//!   ProgramMemory, JumpTable, ProgramExecution, Blake2bCall,
//!   Blake2bCompression, MerkleNode, …).
//! - [`trace`] — column-fill helpers + interaction-trace builder.
//! - [`proof`] — public proof type (serializable).
//! - `prove` / `verify` / `program_id` — top-level prover / verifier
//!   API plus the public program-commitment hash.
//!
//! ## Features
//!
//! - `prover` (default) — trace generation, proof creation, blake3
//!   commitments, rayon parallelism.  Pulls in heavy deps.
//! - `debug-internals` — exposes `debug_claimed_sums` for bisecting
//!   prover-side logup imbalances when adding a new constraint, and
//!   `prove_chip_isolated_format`, a chip's proof alone for measuring
//!   its leaf.  Off by default; production callers don't need it.
//! - `--no-default-features` — verifier-only, `no_std` compatible,
//!   minimal dep tree.
//!
//! ## API surface
//!
//! The prover-side happy path lives at the crate root:
//!
//! - **Trace** — [`TracingPvm::into_side_note`][into_side_note] (a
//!   run's whole trace) or [`SideNote::new`] from a hand-built step
//!   trace.
//! - **Prove** — [`prove`] (STANDARD) or [`prove_mobile`] (low-latency
//!   MOBILE); [`prove_with_config`] for a custom [`PcsConfig`]; all three
//!   under the legacy format 36. [`prove_format`] proves under any admitted
//!   format of the [`format`](mod@format) registry, at its parameters.
//! - **Verify** — [`verify`] / [`verify_with_pcs_policy`] (prover-side,
//!   with the SideNote); [`verify_chain`] for a segment chain. The
//!   side-note-free deployer verifier is `verify_standalone` in the
//!   `vos-pvm-proof-verifier` crate.
//! - **Identity** — [`program_commitment_of_proof`] /
//!   [`program_commitment_hex`] extract the program commitment a
//!   verifier pins.
//! - **Large executions** — the [`segment`] cut helpers,
//!   [`canonical_profile_for_bounds`], and [`prove_canonical`] produce a
//!   chain of equal-shape segments.
//!
//! Core types: [`Proof`], [`SegmentState`], [`SideNote`], [`PcsPolicy`],
//! [`PcsConfig`], [`FriConfig`].
//!
//! Proofs name their format, an entry of the [`format`](mod@format) registry, which
//! selects their channel, parameters and encodings at run time; a verifier
//! rejects a number the registry does not admit. Items
//! marked `#[doc(hidden)]`, and the sub-modules ([`chips`], [`core`],
//! [`trace`], [`proof`], …), are **internal — their shapes change
//! without notice**; they are public only for the verifier crate, the
//! recursion, and the AIR-column derives.
//!
//! [into_side_note]: crate::core::tracing::TracingPvm::into_side_note

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
pub mod refine;
pub mod refine_codec;
pub mod segment;
pub mod sparse_memory;
pub mod trace;

// The format registry, the PCS stacks it selects at run time, the
// Poseidon2-M31 primitives and the security counts. All are `no_std`-clean
// (the verifier path uses them); their prover-only pieces are
// `#[cfg(feature = "prover")]` within.
pub mod format;
pub mod pcs;
pub mod poseidon2;
pub mod program_id;
pub mod security;
pub mod shape;

// The page-hash spec constants + tag chaining states are needed by the new
// memory-Merkle chips' `add_constraints` (verifier-side, `no_std`); the
// `SideNote` / segment / host-tree-building parts are `#[cfg(prover)]` within.
pub mod page_merkle;

#[cfg(feature = "prover")]
pub mod side_note;

#[cfg(feature = "prover")]
pub mod bench_helpers;
#[cfg(feature = "prover")]
mod commitment;
#[cfg(feature = "prover")]
pub mod kernel;
#[cfg(feature = "prover")]
mod prove;
#[cfg(feature = "prover")]
mod verify;

// Re-export AirColumn + PreprocessedAirColumn at crate root so the derive-
// generated impls (which target `::vos_pvm_proof::AirColumn`) resolve correctly.
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

/// The segment AIR's chips, once: their indices ([`chip_idx`]), their
/// names, the components the prover and the verifier walk
/// (`BASE_COMPONENTS`) and the dispatch from an index to a chip's type
/// (`visit_chip`), all in this order.
macro_rules! chips {
    ($($(#[$doc:meta])* $index:ident = $chip:path,)*) => {
        /// Indices into `BASE_COMPONENTS` for chips referenced by name in
        /// `ChipActivity::is_active`, `Proof::component_mask` bit positions,
        /// and other bit-position-sensitive sites (e.g. the boundary-binding
        /// check in `boundary_binding`, which the standalone verifier also
        /// uses — hence public and feature-ungated).
        pub mod chip_idx {
            chips!(@index 0usize; $($(#[$doc])* $index,)*);

            /// The number of chips.
            pub const COUNT: usize = [$(stringify!($index)),*].len();

            /// Each chip's name, its index's.
            pub const NAMES: [&str; COUNT] = [$(stringify!($index)),*];

            /// Every chip, as a component mask.
            pub const ALL: u32 = ((1u64 << COUNT) - 1) as u32;

            /// The chips a trace may leave out: each is active only when its
            /// opcodes or its precompile occur. A row needing one makes a request
            /// that only the chip answers, its multiplicity a flag the program's
            /// committed code fixes, so a proof without the chip balances only if
            /// no row needs it.
            pub const OPTIONAL: u32 = 1 << BLAKE2B
                | 1 << JUMP_TABLE
                | 1 << WITNESS_INPUT
                | 1 << POPCOUNT
                | 1 << BITCOUNT
                | 1 << MUL
                | 1 << BITWISE
                | 1 << COMPARE
                | 1 << DIVREM;

            /// The chips every proof holds: the CPU, the memory and register
            /// ledgers and their boundaries, the program's memory and boundary, the
            /// page Merkle chips and the fixed tables. A kernel's shape without one
            /// is refused.
            pub const ALWAYS: u32 = ALL & !OPTIONAL;

            /// The canonical forcing set: the chips whose log size the program
            /// commitment depends on and a run's rows vary, padded to a profile's
            /// floors by canonical proving.
            pub const FORCING: u32 = 1 << BLAKE2B | 1 << BLAKE2B_BOUNDARY | 1 << MEMORY_PAGE;
        }

        #[cfg(feature = "prover")]
        const BASE_COMPONENTS: &[&dyn framework::MachineProverComponent] = &[$(&$chip),*];

        #[cfg(not(feature = "prover"))]
        const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[$(&$chip),*];

        /// Calls `visitor` with the chip at `index`.
        ///
        /// # Panics
        /// When `index` is no chip's.
        pub(crate) fn visit_chip<V: ChipVisitor>(index: usize, visitor: V) -> V::Output {
            match index {
                $(chip_idx::$index => visitor.visit(&$chip),)*
                _ => panic!("no chip at index {index}"),
            }
        }
    };
    (@index $n:expr; $(#[$doc:meta])* $index:ident, $($rest:tt)*) => {
        $(#[$doc])*
        pub const $index: usize = $n;
        chips!(@index $n + 1; $($rest)*);
    };
    (@index $n:expr;) => {};
}

/// What [`visit_chip`] does with a chip, generic over its type.
pub(crate) trait ChipVisitor {
    type Output;
    fn visit<C: framework::BuiltInComponent>(self, chip: &C) -> Self::Output;
}

// Ordering rule: all consumers of a lookup table must be listed BEFORE the
// table chip itself. Table chips populate their multiplicity column by
// reading counts that consumers accumulate into SideNote during trace
// generation.
//
// The `chip_idx::OPTIONAL` chips are skipped when no step needs them. Both
// prover and verifier must agree on inclusion — `active_components` is the
// single source of truth and is deterministic from `SideNote`.
chips! {
    CPU = chips::CpuChip,
    /// Optional: the BLAKE2b precompile's calls.
    BLAKE2B = chips::Blake2bChip,
    /// The memory-page Merkle tree's BLAKE2b compressions.
    BLAKE2B_BOUNDARY = chips::Blake2bBoundaryChip,
    MEMORY = chips::MemoryChip,
    /// Per-page boundary writes and reads, and the leaves' hashes.
    MEMORY_PAGE = chips::MemoryPageChip,
    /// The Merkle tree's merge rows.
    MEMORY_MERKLE = chips::MemoryMerkleChip,
    /// The roots, bound to the public ones.
    MEMORY_ROOT_BOUNDARY = chips::MemoryRootBoundaryChip,
    REGISTER_MEMORY = chips::RegisterMemoryChip,
    REGISTER_MEMORY_BOUNDARY = chips::RegisterMemoryBoundaryChip,
    /// Pins the final registers.
    REGISTER_MEMORY_CLOSING = chips::RegisterMemoryClosingChip,
    PROGRAM_BOUNDARY = chips::ProgramBoundaryChip,
    /// The committed program, consumed per step by the CPU.
    PROGRAM_MEMORY = chips::ProgramMemoryChip,
    /// Optional: the jump table, for dynamic jumps.
    JUMP_TABLE = chips::JumpTableChip,
    /// Optional: the witness input's bytes.  Before the range table: its
    /// trace-gen counts the bytes and addresses it range-checks.
    WITNESS_INPUT = chips::WitnessInputChip,
    RANGE_MULTIPLICITY_256 = chips::RangeMultiplicity256,
    BITWISE_LOOKUP = chips::BitwiseLookupChip,
    POWER_OF_TWO = chips::PowerOfTwoChip,
    /// Optional: the per-byte popcount table.
    POPCOUNT = chips::PopcountChip,
    /// Optional: the per-byte (lz, tz) table.
    BITCOUNT = chips::BitcountChip,
    /// The per-byte 8-bit decomposition table.
    BYTE_TO_BITS = chips::ByteToBitsChip,
    /// Optional: MultiplicationLookup's consumer.
    MUL = chips::MulChip,
    /// Optional: BitwiseLookup's consumer, and the BitwiseAnd nibble
    /// lookups' producer.
    BITWISE = chips::BitwiseChip,
    /// Optional: CompareLookup's consumer, and Range256 lookups' producer.
    COMPARE = chips::CompareChip,
    /// Optional: DivRemLookup's consumer.
    DIVREM = chips::DivRemChip,
    /// 2^16-row byte-wide AND table.  Placed last: it is a receiver whose
    /// multiplicity counts are accumulated by the two blake2b chips during
    /// their trace-gen (idx 1/2), so it must be generated after all its
    /// consumers (the ordering rule).
    BITWISE_AND_BYTE = chips::BitwiseAndByteChip,
}

/// Deterministic, side-note-driven filter on `BASE_COMPONENTS`.
/// Returns the components active for THIS trace, in declaration order.
///
/// Both prover and verifier MUST construct the same list.  The predicate
/// reads only `SideNote` fields the verifier also has access to (the
/// public side_note is an input to `verify`).
///
/// Skipping a chip is safe iff all of its lookup producers and consumers
/// have multiplicity 0 across the trace. For Blake2bChip: no calls in
/// `side_note.blake2b_calls` ⇒ no Blake2b producers/consumers fire on
/// CpuChip or MemoryChip ⇒ all relevant lookup balances stay 0=0. Each
/// `chip_idx::OPTIONAL` chip has its arm in `ChipActivity::is_active`.
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
    use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_WITNESS_INPUT};
    let mut a = ChipActivity::default();
    for step in &side_note.steps {
        // A precompile call counts only when served
        // (`PvmStep::served_ecall`).
        let ecall = step.served_ecall();
        if ecall == Some(ECALL_BLAKE2B_COMPRESS as u64) {
            a.blake2b = true;
        }
        // A witness-input call compares its count with its capacity; one
        // that wrote bytes hands them to WitnessInputChip.
        if ecall == Some(u64::from(ECALL_WITNESS_INPUT)) {
            a.compare = true;
        }
        if step.witness.is_some() {
            a.witness_input = true;
        }
        a.opcode(step.opcode);
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
    witness_input: bool,
}

#[cfg(feature = "prover")]
impl ChipActivity {
    /// Mark the chips a step of opcode `op` uses.
    fn opcode(&mut self, op: crate::core::opcode::Opcode) {
        let f = crate::chips::cpu::classify::classify_opcode(op);
        self.jump_table |= f.is_jump_ind || f.is_load_imm_jump_ind;
        self.popcount |= f.is_count_set_bits;
        self.bitcount |= f.is_lzb || f.is_tzb;
        self.mul |= f.is_mul
            || f.is_mul_upper_uu
            || f.is_mul_upper_su
            || f.is_mul_upper_ss
            || f.is_rotate_l64
            || f.is_rotate_r64
            || f.is_rotate_l32
            || f.is_rotate_r32;
        self.bitwise |= f.is_and || f.is_or || f.is_xor || f.is_and_inv || f.is_or_inv || f.is_xnor;
        // Compare = SetLt*/Cmov*/Min/Max + branches.
        self.compare |= f.is_set_lt_u
            || f.is_set_lt_s
            || f.is_cmov_iz
            || f.is_cmov_nz
            || f.is_min_s
            || f.is_min_u
            || f.is_max_s
            || f.is_max_u
            || f.is_branch;
        self.divrem |= f.is_div_rem;
    }

    /// The component mask of the active chips.
    fn mask(&self) -> u32 {
        (0..chip_idx::COUNT)
            .filter(|&index| self.is_active(index))
            .fold(0, |mask, index| mask | 1 << index)
    }

    fn is_active(&self, idx: usize) -> bool {
        // Indices are pinned by `chip_idx` (see lib.rs `mod chip_idx`).
        // Always-active chips fall through to the default arm — only the
        // optional chips (`chip_idx::OPTIONAL`) need an explicit arm.
        match idx {
            chip_idx::BLAKE2B => self.blake2b,
            chip_idx::JUMP_TABLE => self.jump_table,
            chip_idx::WITNESS_INPUT => self.witness_input,
            chip_idx::POPCOUNT => self.popcount,
            chip_idx::BITCOUNT => self.bitcount,
            chip_idx::MUL => self.mul,
            chip_idx::BITWISE => self.bitwise,
            chip_idx::COMPARE => self.compare,
            chip_idx::DIVREM => self.divrem,
            _ => true,
        }
    }
}

/// Bitmask of active chips (bit i ⇔ BASE_COMPONENTS[i] is
/// included).  Embedded in `Proof::component_mask` so the standalone
/// verifier can reconstruct the active set without a SideNote.
/// The chips every proof holds are among them: the least set a segment of
/// the trace proves over.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub fn active_component_mask(side_note: &side_note::SideNote) -> u32 {
    activity_from_steps(side_note).mask()
}

/// The chips a step of opcode `op` activates, the chips every proof holds
/// among them: what a kernel's shape takes from each instruction of its
/// code.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub fn opcode_component_mask(op: core::opcode::Opcode) -> u32 {
    let mut a = ChipActivity::default();
    a.opcode(op);
    a.mask()
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

pub use format::Format;
pub use pcs::{Commitment, StarkProofAny};
pub use proof::{PROOF_FORMAT_VERSION, PcsPolicy, Proof, SegmentState};
pub use refine::{
    MAX_REFINE_CHILD_COMPONENTS, MAX_REFINE_HOST_BOUNDARIES, MAX_REFINE_PROOF_SLICES,
    REFINE_BUNDLE_FORMAT_VERSION, REFINE_CHILD_COMMITMENT_COUNT, RefineBundleVerification,
    RefineHostBoundary, RefineMachineId, RefineProgramId, RefineProofBundle, RefineProofSlice,
    RefineSliceExit, refine_arguments_commitment, refine_bundle_cardinality_is_valid,
    refine_bundle_commitment, refine_bundle_execution_commitment, refine_bundle_terminal_public_io,
    refine_program_id,
};
#[cfg(feature = "prover")]
pub use refine::{
    RefineObservedRun, RefineTraceBundle, RefineTraceError, RefineTraceSlice, prove_refine,
    refine_trace_execution_commitment, trace_refine, trace_refine_observed,
    trace_refine_with_output, verify_refine_bundle_replayed,
};
pub use refine_codec::{
    MAX_REFINE_PROOF_BUNDLE_ALLOCATION_BYTES, MAX_REFINE_PROOF_BUNDLE_WIRE_BYTES,
    REFINE_PROOF_BUNDLE_CODEC_VERSION, RefineProofCodecError, decode_refine_proof_bundle,
    encode_refine_proof_bundle,
};
pub use sparse_memory::{SPARSE_MEMORY_PAGE_SIZE, SparseMemoryImage, SparseMemoryPage};
// The per-policy FRI floor constants + the policy checker: used by callers
// that assemble a custom `PcsPolicy`; hidden from the top-level page.
#[doc(hidden)]
pub use proof::{
    STANDARD_MIN_FRI_LOG_BLOWUP, STANDARD_MIN_FRI_QUERIES, STANDARD_MIN_POW_BITS, check_pcs_policy,
};
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use prove::{prove_pre_config_relabel_for_test, prove_with_boundary_override};
// ── Prove: the stable surface ────────────────────────────────────────
// Single proof: `prove` / `prove_mobile` / `prove_with_config`.
// Segment chain: `canonical_profile_for_bounds` derives the forcing
// profile, `prove_canonical` proves each window to one shape.
#[cfg(feature = "prover")]
pub use prove::{
    KernelSegment, ProvingError, canonical_profile_for_bounds, program_commitment_for_profile,
    program_commitment_for_profile_format, program_commitment_for_shape, prove, prove_canonical,
    prove_canonical_format, prove_chain, prove_format, prove_kernel, prove_mobile, prove_shaped,
    prove_with_config,
};
// Advanced / internal prove surface: the profiling variants, the thread-pool
// installer, and the explicit-component harness entry. Public for tests;
// hidden from docs so the top-level page stays the happy path.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use prove::{
    ProveProfile, install_thread_pool, prepare_side_note_for_verification, production_pcs_config,
    production_pcs_config_mobile, prove_profiled, prove_profiled_with_config,
    prove_with_explicit_components,
};
#[cfg(feature = "debug-internals")]
pub use prove::{
    debug_assert_constraints_explicit, debug_claimed_sums, prove_chip_isolated_format,
};
#[cfg(feature = "prover")]
pub use side_note::SideNote;
pub use stwo::core::fri::FriConfig;
pub use stwo::core::pcs::PcsConfig;
// ── Verify (prover-side, with the SideNote): the stable surface ───────
// The side-note-FREE deployer verifier lives in the `vos-pvm-proof-verifier` crate
// (`verify_standalone`) — no_std, no prover deps.
#[cfg(feature = "prover")]
pub use verify::{DEFAULT_MAX_LOG_SIZE, verify, verify_chain, verify_with_pcs_policy};
// Advanced verify surface (explicit components)
// and the recursion seams the in-AIR verifier is checked against.
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use verify::{
    ComponentOodsMask, OodsReconstruction, RecursionData, RecursionTranscript, SampleLayout,
    extract_recursion_data, reconstruct_oods_for_recursion, record_canonical_transcript,
    replay_stark, sample_layout, sample_layout_of, verify_with_explicit_components,
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

    /// Every chip, in proving order: what a gate checks a forged trace
    /// against when its refusal is a lookup's, not one chip's constraint.
    #[cfg(feature = "debug-internals")]
    pub fn base_components() -> &'static [&'static dyn MachineProverComponent] {
        crate::BASE_COMPONENTS
    }
}
#[cfg(feature = "prover")]
pub use commitment::{ProgramCommitment, program_commitment_hex, program_commitment_of_proof};
