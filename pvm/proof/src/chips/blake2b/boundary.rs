//! Blake2bBoundaryChip — proves blake2b compressions for the in-AIR
//! memory-page Merkle boundary multiproof (§3 of the memory-merkle-binding
//! design), WITHOUT the memory-ledger / CPU-call bindings the main
//! `Blake2bChip` carries.  It reuses the shared compression arithmetic core
//! (`add_compression_core` / `add_compression_interaction_core` / the trace
//! fill / the schedule fill) over its OWN main `BoundaryColumn` — the shared
//! `Column` layout minus the ECALL-binding columns only the main chip
//! constrains, plus `EmitMult` — and:
//!
//! - carries its OWN `PreprocessedColumn` (distinct `preprocessed_prefix`):
//!   stwo dedups preprocessed columns by id while the prover commits each
//!   component's preprocessed trace positionally, so two active components
//!   sharing preprocessed ids would desync — distinct prefixes are required;
//! - carries the **IsReal anchor** the main chip carries too (boolean,
//!   constant within a compression): without it a prover lights up only
//!   the row-95 production and forges `h_out`.  It needs no tail guard: a
//!   trailing partial block has no row 95 and produces nothing;
//! - PRODUCES one `Blake2bCompression` tuple `(h_in, m, t, f, h_out)` per
//!   compression at row 95, which `MemoryPageChip` / `MemoryMerkleChip`
//!   consume.

use crate::prelude::*;
use num_traits::One;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::framework::BuiltInComponent;
use crate::lookups::{
    BitwiseAndByteLookupElements, Blake2bCompressionLookupElements, Range256LookupElements,
};
use crate::trace::eval::TraceEval;

use super::columns::{CompressionColumns, compression_columns};
use super::compression::{ScheduleColumns, add_compression_core, read_schedule};

#[derive(Clone, Copy)]
pub struct Blake2bBoundaryChip;

/// Structurally identical to `blake2b::PreprocessedColumn` but under the
/// distinct `"blake2bnd"` prefix, plus `ContinuityGate`.  `ContinuityGate`
/// is 1 exactly on rows where the IsReal-continuity constraint must hold
/// (interior of a compression, never the row-95 block boundary nor the
/// cyclic last→0 mask wrap).
#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "blake2bnd"]
pub enum PreprocessedColumn {
    #[size = 1]
    IsGIdx0,
    #[size = 1]
    IsGIdx1,
    #[size = 1]
    IsGIdx2,
    #[size = 1]
    IsGIdx3,
    #[size = 1]
    IsGIdx4,
    #[size = 1]
    IsGIdx5,
    #[size = 1]
    IsGIdx6,
    #[size = 1]
    IsGIdx7,
    #[size = 1]
    IsLastOfCompression,
    #[size = 1]
    IsFirstOfCompression,
    #[size = 1]
    IsMxSlot0,
    #[size = 1]
    IsMxSlot1,
    #[size = 1]
    IsMxSlot2,
    #[size = 1]
    IsMxSlot3,
    #[size = 1]
    IsMxSlot4,
    #[size = 1]
    IsMxSlot5,
    #[size = 1]
    IsMxSlot6,
    #[size = 1]
    IsMxSlot7,
    #[size = 1]
    IsMxSlot8,
    #[size = 1]
    IsMxSlot9,
    #[size = 1]
    IsMxSlot10,
    #[size = 1]
    IsMxSlot11,
    #[size = 1]
    IsMxSlot12,
    #[size = 1]
    IsMxSlot13,
    #[size = 1]
    IsMxSlot14,
    #[size = 1]
    IsMxSlot15,
    #[size = 1]
    IsMySlot0,
    #[size = 1]
    IsMySlot1,
    #[size = 1]
    IsMySlot2,
    #[size = 1]
    IsMySlot3,
    #[size = 1]
    IsMySlot4,
    #[size = 1]
    IsMySlot5,
    #[size = 1]
    IsMySlot6,
    #[size = 1]
    IsMySlot7,
    #[size = 1]
    IsMySlot8,
    #[size = 1]
    IsMySlot9,
    #[size = 1]
    IsMySlot10,
    #[size = 1]
    IsMySlot11,
    #[size = 1]
    IsMySlot12,
    #[size = 1]
    IsMySlot13,
    #[size = 1]
    IsMySlot14,
    #[size = 1]
    IsMySlot15,
    /// 1 iff the IsReal-continuity constraint applies from this row to the
    /// next: `r % 96 != 95` (not a compression boundary) AND `r` is not the
    /// last trace row (the cyclic `next` of which wraps to row 0).
    #[size = 1]
    ContinuityGate,
}

impl ScheduleColumns for PreprocessedColumn {
    const IS_FIRST: Self = PreprocessedColumn::IsFirstOfCompression;
    const IS_LAST: Self = PreprocessedColumn::IsLastOfCompression;
    const IS_GIDX: [Self; 8] = [
        PreprocessedColumn::IsGIdx0,
        PreprocessedColumn::IsGIdx1,
        PreprocessedColumn::IsGIdx2,
        PreprocessedColumn::IsGIdx3,
        PreprocessedColumn::IsGIdx4,
        PreprocessedColumn::IsGIdx5,
        PreprocessedColumn::IsGIdx6,
        PreprocessedColumn::IsGIdx7,
    ];
    const IS_MX_SLOT: [Self; 16] = [
        PreprocessedColumn::IsMxSlot0,
        PreprocessedColumn::IsMxSlot1,
        PreprocessedColumn::IsMxSlot2,
        PreprocessedColumn::IsMxSlot3,
        PreprocessedColumn::IsMxSlot4,
        PreprocessedColumn::IsMxSlot5,
        PreprocessedColumn::IsMxSlot6,
        PreprocessedColumn::IsMxSlot7,
        PreprocessedColumn::IsMxSlot8,
        PreprocessedColumn::IsMxSlot9,
        PreprocessedColumn::IsMxSlot10,
        PreprocessedColumn::IsMxSlot11,
        PreprocessedColumn::IsMxSlot12,
        PreprocessedColumn::IsMxSlot13,
        PreprocessedColumn::IsMxSlot14,
        PreprocessedColumn::IsMxSlot15,
    ];
    const IS_MY_SLOT: [Self; 16] = [
        PreprocessedColumn::IsMySlot0,
        PreprocessedColumn::IsMySlot1,
        PreprocessedColumn::IsMySlot2,
        PreprocessedColumn::IsMySlot3,
        PreprocessedColumn::IsMySlot4,
        PreprocessedColumn::IsMySlot5,
        PreprocessedColumn::IsMySlot6,
        PreprocessedColumn::IsMySlot7,
        PreprocessedColumn::IsMySlot8,
        PreprocessedColumn::IsMySlot9,
        PreprocessedColumn::IsMySlot10,
        PreprocessedColumn::IsMySlot11,
        PreprocessedColumn::IsMySlot12,
        PreprocessedColumn::IsMySlot13,
        PreprocessedColumn::IsMySlot14,
        PreprocessedColumn::IsMySlot15,
    ];
}

compression_columns! {
    /// The boundary chip's own main-column set: the compression core's,
    /// without `Column`'s ECALL-binding columns (`HPtr`/`MPtr`/`CallTs` and
    /// the address columns of `address.rs`). Those bind guest-RAM
    /// reads/writes and the CPU ECALL step, meaningless for multiproof
    /// compressions, which hash page images and node pairs that never touch
    /// the memory ledger. `EmitMult`, which `Column` lacks, carries the
    /// row-95 production multiplicity.
    pub enum BoundaryColumn {
        binding {}
        gated {
            #[size = 1]
            EmitMult,
        }
    }
}

impl BuiltInComponent for Blake2bBoundaryChip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = BoundaryColumn;
    type LookupElements = (
        Range256LookupElements,
        BitwiseAndByteLookupElements,
        Blake2bCompressionLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, BoundaryColumn, E>,
        lookup_elements: &(
            Range256LookupElements,
            BitwiseAndByteLookupElements,
            Blake2bCompressionLookupElements,
        ),
    ) {
        let (range256_lookup, bitwise_lookup, compression_lookup) = lookup_elements;

        let is_real = crate::trace::trace_eval!(trace_eval, BoundaryColumn::IsReal);
        let is_real_next = crate::trace::trace_eval_next_row!(trace_eval, BoundaryColumn::IsReal);
        let t_e = crate::trace::trace_eval!(trace_eval, BoundaryColumn::T);
        let continuity_gate =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ContinuityGate);

        // ── IsReal anchor (the §3.1 BREAK fix) ──────────────────
        // Without the dropped CPU-call binding, a prover could light up only
        // the row-95 production (making the V-chain vacuous on rows 0..94 and
        // freeing `h_out`).  Anchor IsReal: (1) boolean, (2) constant within
        // each 96-row compression, so a row-95 production (output_gate =
        // IsReal·IsLast) forces IsReal=1 on the whole compression → the
        // V-chain binds `h_out` to the real compression of (h, m, t, f).
        //
        // These (and T[8..16]=0) are emitted BEFORE the shared core's first
        // `add_to_relation`, so a violation unwinds cleanly in the debug gate
        // harness (the AssertEvaluator's LogupAtRow carries no pending state
        // yet, avoiding the finalize-on-drop double-panic).
        let f1 = E::F::one();
        eval.add_constraint(is_real[0].clone() * (is_real[0].clone() - f1.clone()));
        // ContinuityGate is 0 at the row-95 boundary (so IsReal may change
        // between compressions) and at the last trace row (so the cyclic
        // last→0 wrap doesn't force IsReal[0] == IsReal[last]).
        eval.add_constraint(
            continuity_gate[0].clone() * (is_real_next[0].clone() - is_real[0].clone()),
        );
        // EmitMult may light up only on a real row 95 (the production row);
        // its VALUE there is free — the logup balance alone pins it to the
        // compression's true consumption count.  OutputGateH is itself
        // pinned to IsReal·IsLast by its definition constraint in the
        // shared core.
        let output_gate_h = crate::trace::trace_eval!(trace_eval, BoundaryColumn::OutputGateH);
        let emit_mult = crate::trace::trace_eval!(trace_eval, BoundaryColumn::EmitMult);
        eval.add_constraint((f1.clone() - output_gate_h[0].clone()) * emit_mult[0].clone());
        // T[8..16] = 0 — domain constraint (pins V[13]'s init); retained since
        // the tuple only carries t[0..8].
        for i in 8..16 {
            eval.add_constraint(is_real[0].clone() * t_e[i].clone());
        }

        // Shared compression arithmetic (G-function, V-chain, output
        // derivation, BitwiseAnd / Range256 lookups, the gate-helper
        // definitions).  The schedule selectors come from this chip's own
        // "blake2bnd"-prefixed preprocessed columns.
        let sched = read_schedule(&trace_eval);
        add_compression_core(eval, &trace_eval, &sched, range256_lookup, bitwise_lookup);

        let f_e = crate::trace::trace_eval!(trace_eval, BoundaryColumn::F);
        let output_e = crate::trace::trace_eval!(trace_eval, BoundaryColumn::Output);
        let h_cols: [_; 8] = [
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H0),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H1),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H2),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H3),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H4),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H5),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H6),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::H7),
        ];
        let m_cols: [_; 16] = [
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M0),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M1),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M2),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M3),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M4),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M5),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M6),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M7),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M8),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M9),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M10),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M11),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M12),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M13),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M14),
            crate::trace::trace_eval!(trace_eval, BoundaryColumn::M15),
        ];

        // ── Blake2bCompression producer ─────────────────────────
        // (h_in[64], m[128], t[8], f[1], h_out[64]); +EmitMult at row 95 —
        // each unique compression produced once with its consumption count
        // (the page/merge chips emit −1 per consumption; the
        // RangeMultiplicity256 pattern, producer-side).  The gate pinning
        // EmitMult to real row-95s is emitted with the IsReal anchor above.
        let mut tuple: Vec<E::F> = Vec::with_capacity(265);
        for w in 0..8 {
            for b in 0..8 {
                tuple.push(h_cols[w][b].clone());
            }
        }
        for w in 0..16 {
            for b in 0..8 {
                tuple.push(m_cols[w][b].clone());
            }
        }
        for i in 0..8 {
            tuple.push(t_e[i].clone());
        }
        tuple.push(f_e[0].clone());
        for i in 0..64 {
            tuple.push(output_e[i].clone());
        }
        eval.add_to_relation(RelationEntry::new(
            compression_lookup,
            emit_mult[0].clone().into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
