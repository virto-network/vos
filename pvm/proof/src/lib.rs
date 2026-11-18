//! # vos-pvm-proof — zero-knowledge prover and verifier for PVM bytecode
//!
//! A STARK proving system for the **PVM** instruction set used by
//! the Polkadot Virtual Machine and the VOS actor runtime.
//! Adapted from the Nexus zkVM (Stwo / Circle-STARK over M31),
//! retargeted at PVM via the `vos_pvm` interpreter and ECALL host-call
//! protocol.
//!
//! See the crate-level `README.md` for the architecture overview,
//! `docs/status.md` for soundness coverage, and `SECURITY.md` for the
//! trust boundary.
//!
//! ## What it proves
//!
//! A node proves a kernel's run segment by segment over its kernel's shape
//! ([`shape`], [`prove_kernel`], [`prove_shaped`]) under the segment format,
//! 41; `vos-pvm-recair` verifies each segment in a leaf (32), folds the
//! leaves (32) and wraps the root (39), which `vos-pvm-final-verifier`
//! verifies at a venue. A device proves a device kernel's whole run as one
//! masked proof (47) over the device chips ([`device`], [`masked`]), which
//! `vos-pvm-device` proves and a space's ingress verifies. The
//! segment's native verifier, the one a leaf is held to, is
//! `vos-pvm-proof-verifier`'s `verify_standalone`.
//!
//! ```no_run
//! use vos_pvm_proof::{format::SEGMENT, kernel::trace_kernel, prove_kernel};
//! use vos_pvm_proof::shape::KernelShape;
//!
//! # fn example(blob: &[u8], arguments: &[u8], shape: &KernelShape) {
//! // `gas` bounds the run.
//! let trace = trace_kernel(blob, arguments, 1_000_000_000).expect("a halting run");
//! let segments = prove_kernel(&trace.side_note, shape, 0, &SEGMENT).expect("proofs");
//! # }
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
//! - `prove` / `verify` — the top-level prover and verifier; [`program_id`]
//!   — a kernel's program id, its shape and each class's preprocessed root.
//!
//! ## Features
//!
//! - `prover` (default) — trace generation, proof creation, rayon
//!   parallelism.  Pulls in heavy deps.
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
//! - **Trace** — [`kernel::trace_kernel`] (a kernel's run, from the
//!   loader's layout, its steps compact: each window is expanded on its
//!   own), [`TracingPvm::into_run`][into_run] (a run's compact trace),
//!   [`TracingPvm::into_side_note`][into_side_note] (a run's whole trace,
//!   expanded) or [`SideNote::new`] from a hand-built step trace.
//! - **Prove** — [`prove_kernel`] (a kernel's run over its shape, cut into
//!   segments), [`prove_shaped`] (a segment over one class), and
//!   [`program_commitment_for_shape`] (the class's preprocessed root a
//!   kernel's program id pins). [`prove`] / [`prove_format`] prove a segment
//!   over the chips its steps select, the tests' and the gates'.
//! - **Verify** — [`verify`] (prover-side, with the SideNote); the
//!   side-note-free verifier is `verify_standalone` in the
//!   `vos-pvm-proof-verifier` crate.
//!
//! Core types: [`Proof`], [`SegmentState`], [`SideNote`], [`PcsConfig`],
//! [`FriConfig`].
//!
//! Proofs name their format, an entry of the [`format`](mod@format) registry, which
//! selects their channel, parameters and encodings at run time; a verifier
//! rejects a number the registry does not admit. Items
//! marked `#[doc(hidden)]`, and the sub-modules ([`chips`], [`core`],
//! [`trace`], [`proof`], …), are **internal — their shapes change
//! without notice**; they are public only for the verifier crate, the
//! recursion, and the AIR-column derives.
//!
//! [into_run]: crate::core::tracing::TracingPvm::into_run
//! [into_side_note]: crate::core::tracing::TracingPvm::into_side_note

#![cfg_attr(not(feature = "prover"), no_std)]
// In verifier-only builds (--no-default-features), prover-only modules are
// gated out, so many helper fns / structs / consts in always-compiled
// modules become dead from the compiler's perspective.  Silence those
// lints crate-wide when prover is off; on the default build the lints
// remain active and catch genuine dead code.
#![cfg_attr(not(feature = "prover"), allow(dead_code, unused_imports))]
extern crate alloc;

/// The `alloc` items the chips use, in scope with `std` or without.
mod prelude {
    pub(crate) use alloc::{boxed::Box, vec, vec::Vec};
}

pub mod air_column;
pub mod boundary_binding;
pub mod chips;
pub mod core;
pub mod device;
mod framework;
pub mod framework_access;
mod lookups;
pub mod masked;
pub mod memory_layout;
pub mod proof;
pub mod segment;
pub mod sparse_memory;
// The native segment verifier from a proof and its preprocessed root, the
// one copy of its checks (`vos-pvm-proof-verifier`'s `verify_standalone`).
pub mod standalone;
pub mod trace;

// The format registry, the PCS stacks it selects at run time, the
// Poseidon2-M31 primitives and the security counts. All are `no_std`-clean
// (the verifier path uses them); their prover-only pieces are child modules
// behind the `prover` feature.
pub mod constants;
pub mod format;
pub mod pcs;
pub mod poseidon2;
pub mod program_id;
pub mod security;
pub mod shape;

// The page-hash spec constants + tag chaining states are needed by the
// memory-Merkle chips' `add_constraints` (verifier-side, `no_std`); the
// host's tree building is its `host` child, behind the `prover` feature.
pub mod page_merkle;

#[cfg(feature = "prover")]
pub mod side_note;

#[cfg(feature = "prover")]
pub mod kernel;
#[cfg(feature = "prover")]
mod prove;
#[cfg(feature = "prover")]
mod verify;

// Re-export AirColumn + PreprocessedAirColumn at crate root so the derive-
// generated impls (which target `::vos_pvm_proof::AirColumn`) resolve correctly.
pub use air_column::{AirColumn, PreprocessedAirColumn};

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
                | 1 << POSEIDON2
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
        }

        #[cfg(feature = "abi")]
        const _: () = assert!(
            chip_idx::COUNT == vos_abi::records::SEGMENT_CHIPS
                $(&& chip_idx::$index == vos_abi::records::segment_chip::$index)*
        );

        const BASE_COMPONENTS: &[&DynChip] = &[$(&$chip),*];

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

/// A chip as the chip tables hold it: the verifier's trait object, or under
/// `prover` the prover's, which verification upcasts.
#[cfg(feature = "prover")]
pub(crate) type DynChip = dyn framework::MachineProverComponent;
#[cfg(not(feature = "prover"))]
pub(crate) type DynChip = dyn framework::MachineComponent;

/// A chip as Stwo's components the masked set holds: the verifier's
/// `Component`, or under `prover` the prover's, which verification upcasts.
#[cfg(feature = "prover")]
pub(crate) type DynComponent =
    dyn stwo::prover::ComponentProver<stwo::prover::backend::simd::SimdBackend>;
#[cfg(not(feature = "prover"))]
pub(crate) type DynComponent = dyn stwo::core::air::Component;

/// What [`visit_chip`] does with a chip, generic over its type.
pub(crate) trait ChipVisitor {
    type Output;
    fn visit<C>(self, chip: &C) -> Self::Output
    where
        C: framework::BuiltInComponent + Copy + Sync + 'static,
        C::LookupElements: Sync + 'static;
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
    /// Optional: the Poseidon2 call's permutations, one a row.
    /// Before the range table: its trace-gen counts the bytes it
    /// range-checks.
    POSEIDON2 = chips::Poseidon2Chip,
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

/// The device's own chips over the shared chip set's indices
/// (`device::device_chip`), once: the dispatch from an index to a chip's
/// type (`visit_device_chip`) and the component the prover and the
/// verifier walk (`device_component`), the segment AIR's chip at every
/// other index.
macro_rules! device_chips {
    ($($index:ident = $chip:path,)*) => {
        /// Calls `visitor` with the shared chip set's chip at `index` as a
        /// device shape holds it.
        ///
        /// # Panics
        /// When `index` is no chip's.
        pub(crate) fn visit_device_chip<V: ChipVisitor>(index: usize, visitor: V) -> V::Output {
            match index {
                $(device::device_chip::$index => visitor.visit(&$chip),)*
                _ => visit_chip(index, visitor),
            }
        }

        /// The shared chip set's chip at `index` as a device shape holds it.
        pub(crate) fn device_component(index: usize) -> &'static DynChip {
            match index {
                $(device::device_chip::$index => &$chip,)*
                _ => BASE_COMPONENTS[index],
            }
        }
    };
}

device_chips! {
    // The word ledger, in the byte ledger's place.
    MEMORY = chips::WordMemoryChip,
    DEVICE_MEMORY = chips::DeviceWordMemoryChip,
    DATA_TABLE = chips::DataWordTableChip,
    DEVICE_BOUNDARY = chips::DeviceBoundaryChip,
    DEVICE_IO = chips::DeviceIoChip,
}

/// The chips `mask` selects, by index, in chip order: bit i is chip i.
pub(crate) fn chips_of_mask(mask: u32) -> impl Iterator<Item = usize> {
    (0..chip_idx::COUNT).filter(move |chip| mask & 1 << chip != 0)
}

pub use format::Format;
pub use pcs::{Commitment, StarkProofAny};
pub use proof::{Proof, SegmentState};
// The chips a trace activates (`prove/active.rs`).
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use prove::active::{
    active_component_mask, active_components, all_components, opcode_component_mask,
};
#[cfg(feature = "chip-isolated")]
pub use prove::prove_with_boundary_override;
pub use sparse_memory::{SPARSE_MEMORY_PAGE_SIZE, SparseMemoryImage, SparseMemoryPage};
// ── Prove: the stable surface ────────────────────────────────────────
// A kernel's run over its shape: `prove_kernel`, a segment `prove_shaped`,
// its class's preprocessed root `program_commitment_for_shape`. A segment
// over the chips its steps select: `prove` / `prove_format`.
#[cfg(feature = "prover")]
pub use prove::{
    KernelPlan, KernelSegment, MAX_RUN_STEPS, PlannedSegment, SEGMENT_GAS, SegmentError,
    max_segments, plan_kernel, program_commitment_for_shape, prove, prove_format, prove_kernel,
    prove_shaped,
};
// Advanced / internal prove surface: the profiling variants and the
// thread-pool installer. Public for tests; hidden from docs so the
// top-level page stays the happy path.
#[cfg(feature = "chip-isolated")]
pub use prove::prove_with_explicit_components;
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use prove::{
    ProveProfile, install_thread_pool, prepare_side_note_for_verification, prove_profiled,
};
#[cfg(feature = "debug-internals")]
pub use prove::{debug_assert_constraints_explicit, prove_chip_isolated_format};
#[cfg(feature = "prover")]
pub use side_note::SideNote;
pub use stwo::core::fri::FriConfig;
pub use stwo::core::pcs::PcsConfig;
// ── Verify (prover-side, with the SideNote): the stable surface ───────
// The side-note-FREE deployer verifier lives in the `vos-pvm-proof-verifier` crate
// (`verify_standalone`) — no_std, no prover deps.
#[cfg(feature = "prover")]
pub use verify::{DEFAULT_MAX_LOG_SIZE, verify};
// Advanced verify surface (explicit components)
// and the recursion seams the in-AIR verifier is checked against.
#[cfg(feature = "chip-isolated")]
pub use verify::record_canonical_transcript;
#[cfg(feature = "chip-isolated")]
pub use verify::verify_with_explicit_components;
#[doc(hidden)]
#[cfg(feature = "prover")]
pub use verify::{
    OodsReconstruction, RecursionData, RecursionTranscript, SampleLayout, extract_recursion_data,
    reconstruct_oods_for_recursion, replay_stark, sample_layout, sample_layout_of,
};

/// Chip-isolated harness surface — re-exports the trait
/// objects callers need to assemble an explicit component slice for
/// `prove_with_explicit_components` / `verify_with_explicit_components`.
/// Intended only for chip-isolated tests; production code should use
/// `prove` / `verify`.  Callers build their own
/// `&[&dyn MachineProverComponent]` slice from the chip structs in
/// `crate::chips`. A test seam (`chip-isolated`).
#[cfg(any(test, feature = "chip-isolated"))]
pub mod harness {
    pub use crate::framework::{MachineComponent, MachineProverComponent};

    /// Every chip, in proving order: what a gate checks a forged trace
    /// against when its refusal is a lookup's, not one chip's constraint.
    #[cfg(feature = "debug-internals")]
    pub fn base_components() -> &'static [&'static dyn MachineProverComponent] {
        crate::BASE_COMPONENTS
    }
}
