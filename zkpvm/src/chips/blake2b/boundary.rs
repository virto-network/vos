//! Blake2bBoundaryChip — proves blake2b compressions for the in-AIR
//! memory-page Merkle boundary multiproof (§3 of the memory-merkle-binding
//! design), WITHOUT the memory-ledger / CPU-call bindings the main
//! `Blake2bChip` carries.  It reuses the shared compression arithmetic core
//! (`add_compression_core` / `add_compression_interaction_core` / the trace
//! fill / the schedule fill) over its OWN main `BoundaryColumn` — the shared
//! `Column` layout minus the 1040 ECALL-binding limbs only the main chip
//! constrains — and:
//!
//! - carries its OWN `PreprocessedColumn` (distinct `preprocessed_prefix`):
//!   stwo dedups preprocessed columns by id while the prover commits each
//!   component's preprocessed trace positionally, so two active components
//!   sharing preprocessed ids would desync — distinct prefixes are required;
//! - replaces the dropped CPU-call binding (which is what makes IsReal
//!   honest in the main chip) with its OWN **IsReal anchor**: without it a
//!   prover lights up only the row-95 production and forges `h_out`;
//! - PRODUCES one `Blake2bCompression` tuple `(h_in, m, t, f, h_out)` per
//!   compression at row 95.  `MemoryPageChip` / `MemoryMerkleChip` (step 5)
//!   consume them; until then the chip is validated open-chain.

#[allow(unused_imports)]
use alloc::{vec, vec::Vec};
use num_traits::One;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::m31::BaseField, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::framework::BuiltInComponent;
use crate::lookups::{
    BitwiseAndLookupElements, Blake2bCompressionLookupElements, Range256LookupElements,
};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
#[cfg(feature = "prover")]
use crate::{
    framework::BuiltInProverComponent,
    lookups::{AllLookupElements, LogupTraceBuilder},
    side_note::SideNote,
};

use super::columns::CompressionColumns;
use super::{ScheduleColumns, add_compression_core, read_schedule};
#[cfg(feature = "prover")]
use super::{
    add_compression_interaction_core, build_compression_rows, fill_compression_trace,
    fill_schedule_preprocessed,
};

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

/// The boundary chip's own main-column set: `Column` minus the 1040
/// ECALL-binding limbs (`HPtr`/`MPtr`/`CallTs` and the per-byte
/// `HRdAddr`/`MRdAddr`/`HWrAddr` address columns).  Those bind guest-RAM
/// reads/writes and the CPU ECALL step — meaningless for multiproof
/// compressions, which hash page images and node pairs that never touch
/// the memory ledger.  Variant order, sizes and `mask_next_row` flags
/// mirror `Column`; see `Column`'s doc comments for per-column semantics.
/// `EmitMult` (dead in the main chip) is live here — it carries the row-95
/// production multiplicity.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum BoundaryColumn {
    #[size = 8]
    AIn,
    #[size = 8]
    BIn,
    #[size = 8]
    CIn,
    #[size = 8]
    DIn,
    #[size = 8]
    Mx,
    #[size = 8]
    My,
    #[size = 8]
    A1,
    #[size = 8]
    Carry1,
    #[size = 8]
    And1,
    #[size = 8]
    C1,
    #[size = 8]
    Carry2,
    #[size = 8]
    And2,
    #[size = 8]
    AOut,
    #[size = 8]
    Carry3,
    #[size = 8]
    And3,
    #[size = 8]
    COut,
    #[size = 8]
    Carry4,
    #[size = 8]
    And4,
    #[size = 8]
    BOut,
    #[size = 8]
    Rot63Carry,
    #[size = 8]
    And1AHi,
    #[size = 8]
    And1BHi,
    #[size = 8]
    And1ResHi,
    #[size = 8]
    And2AHi,
    #[size = 8]
    And2BHi,
    #[size = 8]
    And2ResHi,
    #[size = 8]
    And3AHi,
    #[size = 8]
    And3BHi,
    #[size = 8]
    And3ResHi,
    #[size = 8]
    And4AHi,
    #[size = 8]
    And4BHi,
    #[size = 8]
    And4ResHi,
    #[size = 8]
    DOut,
    #[size = 8]
    #[mask_next_row]
    M0,
    #[size = 8]
    #[mask_next_row]
    M1,
    #[size = 8]
    #[mask_next_row]
    M2,
    #[size = 8]
    #[mask_next_row]
    M3,
    #[size = 8]
    #[mask_next_row]
    M4,
    #[size = 8]
    #[mask_next_row]
    M5,
    #[size = 8]
    #[mask_next_row]
    M6,
    #[size = 8]
    #[mask_next_row]
    M7,
    #[size = 8]
    #[mask_next_row]
    M8,
    #[size = 8]
    #[mask_next_row]
    M9,
    #[size = 8]
    #[mask_next_row]
    M10,
    #[size = 8]
    #[mask_next_row]
    M11,
    #[size = 8]
    #[mask_next_row]
    M12,
    #[size = 8]
    #[mask_next_row]
    M13,
    #[size = 8]
    #[mask_next_row]
    M14,
    #[size = 8]
    #[mask_next_row]
    M15,
    #[size = 8]
    #[mask_next_row]
    H0,
    #[size = 8]
    #[mask_next_row]
    H1,
    #[size = 8]
    #[mask_next_row]
    H2,
    #[size = 8]
    #[mask_next_row]
    H3,
    #[size = 8]
    #[mask_next_row]
    H4,
    #[size = 8]
    #[mask_next_row]
    H5,
    #[size = 8]
    #[mask_next_row]
    H6,
    #[size = 8]
    #[mask_next_row]
    H7,
    #[size = 16]
    #[mask_next_row]
    T,
    #[size = 1]
    #[mask_next_row]
    F,
    #[size = 16]
    THi,
    #[size = 8]
    AndTLo,
    #[size = 8]
    AndTHi,
    #[size = 8]
    AndTLoHi,
    #[size = 8]
    AndTHiHi,
    #[size = 8]
    #[mask_next_row]
    V0,
    #[size = 8]
    #[mask_next_row]
    V1,
    #[size = 8]
    #[mask_next_row]
    V2,
    #[size = 8]
    #[mask_next_row]
    V3,
    #[size = 8]
    #[mask_next_row]
    V4,
    #[size = 8]
    #[mask_next_row]
    V5,
    #[size = 8]
    #[mask_next_row]
    V6,
    #[size = 8]
    #[mask_next_row]
    V7,
    #[size = 8]
    #[mask_next_row]
    V8,
    #[size = 8]
    #[mask_next_row]
    V9,
    #[size = 8]
    #[mask_next_row]
    V10,
    #[size = 8]
    #[mask_next_row]
    V11,
    #[size = 8]
    #[mask_next_row]
    V12,
    #[size = 8]
    #[mask_next_row]
    V13,
    #[size = 8]
    #[mask_next_row]
    V14,
    #[size = 8]
    #[mask_next_row]
    V15,
    #[size = 64]
    Output,
    #[size = 64]
    HHi,
    #[size = 128]
    VAfterHi,
    #[size = 64]
    OutAnd1,
    #[size = 64]
    OutAnd1Hi,
    #[size = 64]
    OutXor1Hi,
    #[size = 64]
    OutAnd2,
    #[size = 64]
    OutAnd2Hi,
    #[size = 1]
    #[mask_next_row]
    IsReal,
    #[size = 1]
    GateH,
    #[size = 1]
    InitGateH,
    #[size = 1]
    OutputGateH,
    #[size = 1]
    EmitMult,
    #[size = 8]
    Carry1XcM1,
    #[size = 8]
    Carry1Full,
    #[size = 8]
    Carry3XcM1,
    #[size = 8]
    Carry3Full,
    #[size = 8]
    Carry2XcM1,
    #[size = 8]
    Carry4XcM1,
    #[size = 8]
    Rot63XcM1,
    #[size = 1]
    FBoundH,
    #[size = 8]
    InMatchA,
    #[size = 8]
    InMatchB,
    #[size = 8]
    InMatchC,
    #[size = 8]
    InMatchD,
    #[size = 8]
    MxSlotSum,
    #[size = 8]
    MySlotSum,
    #[size = 8]
    VNextSum0,
    #[size = 8]
    VNextSum1,
    #[size = 8]
    VNextSum2,
    #[size = 8]
    VNextSum3,
    #[size = 8]
    VNextSum4,
    #[size = 8]
    VNextSum5,
    #[size = 8]
    VNextSum6,
    #[size = 8]
    VNextSum7,
    #[size = 8]
    VNextSum8,
    #[size = 8]
    VNextSum9,
    #[size = 8]
    VNextSum10,
    #[size = 8]
    VNextSum11,
    #[size = 8]
    VNextSum12,
    #[size = 8]
    VNextSum13,
    #[size = 8]
    VNextSum14,
    #[size = 8]
    VNextSum15,
}

impl CompressionColumns for BoundaryColumn {
    const IS_REAL: Self = BoundaryColumn::IsReal;
    const GATE_H: Self = BoundaryColumn::GateH;
    const INIT_GATE_H: Self = BoundaryColumn::InitGateH;
    const OUTPUT_GATE_H: Self = BoundaryColumn::OutputGateH;
    const A_IN: Self = BoundaryColumn::AIn;
    const B_IN: Self = BoundaryColumn::BIn;
    const C_IN: Self = BoundaryColumn::CIn;
    const D_IN: Self = BoundaryColumn::DIn;
    const MX: Self = BoundaryColumn::Mx;
    const MY: Self = BoundaryColumn::My;
    const A1: Self = BoundaryColumn::A1;
    const CARRY1: Self = BoundaryColumn::Carry1;
    const AND1: Self = BoundaryColumn::And1;
    const C1: Self = BoundaryColumn::C1;
    const CARRY2: Self = BoundaryColumn::Carry2;
    const AND2: Self = BoundaryColumn::And2;
    const A_OUT: Self = BoundaryColumn::AOut;
    const CARRY3: Self = BoundaryColumn::Carry3;
    const AND3: Self = BoundaryColumn::And3;
    const C_OUT: Self = BoundaryColumn::COut;
    const CARRY4: Self = BoundaryColumn::Carry4;
    const AND4: Self = BoundaryColumn::And4;
    const B_OUT: Self = BoundaryColumn::BOut;
    const ROT63_CARRY: Self = BoundaryColumn::Rot63Carry;
    const AND1_A_HI: Self = BoundaryColumn::And1AHi;
    const AND1_B_HI: Self = BoundaryColumn::And1BHi;
    const AND1_RES_HI: Self = BoundaryColumn::And1ResHi;
    const AND2_A_HI: Self = BoundaryColumn::And2AHi;
    const AND2_B_HI: Self = BoundaryColumn::And2BHi;
    const AND2_RES_HI: Self = BoundaryColumn::And2ResHi;
    const AND3_A_HI: Self = BoundaryColumn::And3AHi;
    const AND3_B_HI: Self = BoundaryColumn::And3BHi;
    const AND3_RES_HI: Self = BoundaryColumn::And3ResHi;
    const AND4_A_HI: Self = BoundaryColumn::And4AHi;
    const AND4_B_HI: Self = BoundaryColumn::And4BHi;
    const AND4_RES_HI: Self = BoundaryColumn::And4ResHi;
    const D_OUT: Self = BoundaryColumn::DOut;
    const T: Self = BoundaryColumn::T;
    const F: Self = BoundaryColumn::F;
    const T_HI: Self = BoundaryColumn::THi;
    const AND_T_LO: Self = BoundaryColumn::AndTLo;
    const AND_T_HI: Self = BoundaryColumn::AndTHi;
    const AND_T_LO_HI: Self = BoundaryColumn::AndTLoHi;
    const AND_T_HI_HI: Self = BoundaryColumn::AndTHiHi;
    const OUTPUT: Self = BoundaryColumn::Output;
    const H_HI: Self = BoundaryColumn::HHi;
    const V_AFTER_HI: Self = BoundaryColumn::VAfterHi;
    const OUT_AND1: Self = BoundaryColumn::OutAnd1;
    const OUT_AND1_HI: Self = BoundaryColumn::OutAnd1Hi;
    const OUT_XOR1_HI: Self = BoundaryColumn::OutXor1Hi;
    const OUT_AND2: Self = BoundaryColumn::OutAnd2;
    const OUT_AND2_HI: Self = BoundaryColumn::OutAnd2Hi;
    const CARRY1_XCM1: Self = BoundaryColumn::Carry1XcM1;
    const CARRY1_FULL: Self = BoundaryColumn::Carry1Full;
    const CARRY3_XCM1: Self = BoundaryColumn::Carry3XcM1;
    const CARRY3_FULL: Self = BoundaryColumn::Carry3Full;
    const CARRY2_XCM1: Self = BoundaryColumn::Carry2XcM1;
    const CARRY4_XCM1: Self = BoundaryColumn::Carry4XcM1;
    const ROT63_XCM1: Self = BoundaryColumn::Rot63XcM1;
    const F_BOUND_H: Self = BoundaryColumn::FBoundH;
    const IN_MATCH_A: Self = BoundaryColumn::InMatchA;
    const IN_MATCH_B: Self = BoundaryColumn::InMatchB;
    const IN_MATCH_C: Self = BoundaryColumn::InMatchC;
    const IN_MATCH_D: Self = BoundaryColumn::InMatchD;
    const MX_SLOT_SUM: Self = BoundaryColumn::MxSlotSum;
    const MY_SLOT_SUM: Self = BoundaryColumn::MySlotSum;
    const M: [Self; 16] = [
        BoundaryColumn::M0,
        BoundaryColumn::M1,
        BoundaryColumn::M2,
        BoundaryColumn::M3,
        BoundaryColumn::M4,
        BoundaryColumn::M5,
        BoundaryColumn::M6,
        BoundaryColumn::M7,
        BoundaryColumn::M8,
        BoundaryColumn::M9,
        BoundaryColumn::M10,
        BoundaryColumn::M11,
        BoundaryColumn::M12,
        BoundaryColumn::M13,
        BoundaryColumn::M14,
        BoundaryColumn::M15,
    ];
    const H: [Self; 8] = [
        BoundaryColumn::H0,
        BoundaryColumn::H1,
        BoundaryColumn::H2,
        BoundaryColumn::H3,
        BoundaryColumn::H4,
        BoundaryColumn::H5,
        BoundaryColumn::H6,
        BoundaryColumn::H7,
    ];
    const V: [Self; 16] = [
        BoundaryColumn::V0,
        BoundaryColumn::V1,
        BoundaryColumn::V2,
        BoundaryColumn::V3,
        BoundaryColumn::V4,
        BoundaryColumn::V5,
        BoundaryColumn::V6,
        BoundaryColumn::V7,
        BoundaryColumn::V8,
        BoundaryColumn::V9,
        BoundaryColumn::V10,
        BoundaryColumn::V11,
        BoundaryColumn::V12,
        BoundaryColumn::V13,
        BoundaryColumn::V14,
        BoundaryColumn::V15,
    ];
    const V_NEXT_SUM: [Self; 16] = [
        BoundaryColumn::VNextSum0,
        BoundaryColumn::VNextSum1,
        BoundaryColumn::VNextSum2,
        BoundaryColumn::VNextSum3,
        BoundaryColumn::VNextSum4,
        BoundaryColumn::VNextSum5,
        BoundaryColumn::VNextSum6,
        BoundaryColumn::VNextSum7,
        BoundaryColumn::VNextSum8,
        BoundaryColumn::VNextSum9,
        BoundaryColumn::VNextSum10,
        BoundaryColumn::VNextSum11,
        BoundaryColumn::VNextSum12,
        BoundaryColumn::VNextSum13,
        BoundaryColumn::VNextSum14,
        BoundaryColumn::VNextSum15,
    ];
}

impl BuiltInComponent for Blake2bBoundaryChip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = BoundaryColumn;
    type LookupElements = (
        Range256LookupElements,
        BitwiseAndLookupElements,
        Blake2bCompressionLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, BoundaryColumn, E>,
        lookup_elements: &(
            Range256LookupElements,
            BitwiseAndLookupElements,
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

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for Blake2bBoundaryChip {
    const IS_PRODUCER: bool = true;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        fill_schedule_preprocessed(&mut trace);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            let gate = (row % 96 != 95) && (row != num_rows - 1);
            trace.fill_columns(row, gate, PreprocessedColumn::ContinuityGate);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        self.generate_main_trace_min(side_note, 0)
    }

    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        if side_note.merkle_blake2b_calls.is_empty() {
            // Canonical-shape: forced present-but-empty (all-padding).
            let log_size = stwo::prover::backend::simd::m31::LOG_N_LANES.max(min_log_size);
            return TraceBuilder::<BoundaryColumn>::new(log_size).finalize_bit_reversed();
        }
        // No memory-op binding: these compressions hash page images / node
        // pairs, not guest RAM — `BoundaryColumn` carries no address/pointer/
        // CallTs columns at all (main-chip-only width).
        let rows = build_compression_rows(&side_note.merkle_blake2b_calls, &[]);
        let num_rows = rows.len();
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_rows).max(min_log_size);
        let mut trace = TraceBuilder::<BoundaryColumn>::new(log_size);
        fill_compression_trace(&mut trace, side_note, &rows);
        // Production multiplicity at each compression's row 95: the unique
        // compression's in-circuit consumption count (a hand-built side note
        // without mults defaults to one consumer per call).
        for k in 0..side_note.merkle_blake2b_calls.len() {
            let mult = side_note.merkle_blake2b_mults.get(k).copied().unwrap_or(1);
            trace.fill_columns(k * 96 + 95, BaseField::from(mult), BoundaryColumn::EmitMult);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let bitwise: &BitwiseAndLookupElements = lookup_elements.as_ref();
        add_compression_interaction_core::<PreprocessedColumn, BoundaryColumn>(
            &mut logup,
            &component_trace,
            range256,
            bitwise,
        );

        // ── Blake2bCompression producer (mirror of add_constraints) ──
        let compression: &Blake2bCompressionLookupElements = lookup_elements.as_ref();
        let emit_mult =
            crate::trace::original_base_column!(component_trace, BoundaryColumn::EmitMult);
        let h_word_cols: [_; 8] = [
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H0),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H1),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H2),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H3),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H4),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H5),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H6),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::H7),
        ];
        let m_word_cols: [_; 16] = [
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M0),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M1),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M2),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M3),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M4),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M5),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M6),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M7),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M8),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M9),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M10),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M11),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M12),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M13),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M14),
            crate::trace::original_base_column!(component_trace, BoundaryColumn::M15),
        ];
        let t_cols = crate::trace::original_base_column!(component_trace, BoundaryColumn::T);
        let f_col = crate::trace::original_base_column!(component_trace, BoundaryColumn::F);
        let output_cols =
            crate::trace::original_base_column!(component_trace, BoundaryColumn::Output);

        logup.add_to_relation_computed(
            compression,
            [emit_mult[0].clone()],
            |[m]| m.into(),
            265,
            move |v| {
                let mut t = Vec::with_capacity(265);
                for w in 0..8 {
                    for b in 0..8 {
                        t.push(h_word_cols[w][b].at(v));
                    }
                }
                for w in 0..16 {
                    for b in 0..8 {
                        t.push(m_word_cols[w][b].at(v));
                    }
                }
                for i in 0..8 {
                    t.push(t_cols[i].at(v));
                }
                t.push(f_col[0].at(v));
                for i in 0..64 {
                    t.push(output_cols[i].at(v));
                }
                t
            },
        );

        logup.finalize()
    }
}
