//! Session 2.1 step 5(b) + column-shrink — RistrettoFixedBaseConsumerChip.
//!
//! Per fixed-basepoint scalar mult call, lays out:
//!   - 4 IsInput coord rows per window (X/Y/Z/T of `T[i][k_i]`).
//!   - 18 FieldOp add rows per window for the point-add formula
//!     `Acc' = Acc + T[i][k_i]` (see `point.rs::point_add_rows_chained`).
//!
//! The previous "lookup-anchor" row that carried (WindowIdx,
//! ScalarWindow, X/Y/Z/T) and emitted the 130-limb
//! `RistrettoCombLookupElements` tuple has been split out into
//! `RistrettoCombAnchorChip` (sibling chip with 64 rows per call).
//! That trims ~137 cells from this chip's per-row width and saves
//! ~1.1 M cells at log_size=13 (8192 rows).
//!
//! Soundness chain:
//!   - `RistrettoCombAnchorChip` emits the 130-limb comb relation
//!     (drained by `RistrettoCombTableChip`) AND emits 128 +1
//!     contributions per anchor row to
//!     `RistrettoCombCoordBoundaryLookupElements` keyed on
//!     `(call_idx, window_idx, coord_kind, byte_idx, value)`.
//!   - This chip's IsInput coord rows (4 per window, with
//!     `IsCoordInput=1`) emit 32 −1 contributions each to the same
//!     coord-boundary relation, with the row's own `out` column
//!     supplying the byte values and per-row witness columns
//!     `(CallIdx, WindowIdx, CoordKind)` keying them.  Balance
//!     forces each IsInput coord row's `out` to equal the matching
//!     coord byte from the anchor chip.
//!   - FieldOp algebra (shared helper) pins each add/sub/mul row's
//!     algebra mod p25519.
//!   - Source-row threading: the 18 add rows for window `i`
//!     reference rows offsets `+0..+3` (this window's IsInput coord
//!     rows) as `q.{x,y,z,t}` source rows, and the previous window's
//!     final 4 add rows (or boundary constants for window 0) as
//!     `p.{x,y,z,t}` source rows.  Chip-local register-file
//!     (`RistrettoCombConsumerRegisterFileLookupElements`) balance
//!     forces each add row's `a`/`b` to equal the named source
//!     row's `out`.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{fields::qm31::SecureField, ColumnVec},
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::chips::ristretto::field_op_constraints;
use crate::{
    framework::BuiltInComponent,
    lookups::{
        RistrettoCombConsumerRegisterFileLookupElements,
        RistrettoCombCoordBoundaryLookupElements,
        RistrettoCombFinalAccLookupElements,
    },
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoFixedBaseConsumerChip;

/// Number of rows per window: 4 IsInput coord rows (X, Y, Z, T) +
/// 18 FieldOp add rows from `point_add_rows_chained`.
pub const ROWS_PER_WINDOW: usize = 4 + 18;
/// Constant boundary input rows at the start of the chip's trace:
/// `[zero, one, ED25519_TWO_D]`.
pub const N_BOUNDARY_INPUTS: usize = 3;

/// Per-row column layout.  Mirrors RistrettoChip's FieldOp witness
/// columns (so the shared `field_op_constraints` helper applies)
/// plus chip-specific source-row + coord-binding metadata.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    // ── FieldOp witness columns (mirror RistrettoChip) ──
    #[size = 32]
    FieldA,
    #[size = 32]
    FieldB,
    #[size = 32]
    FieldOut,
    #[size = 32]
    AddIntermediate,
    #[size = 32]
    AddCarry,
    #[size = 1]
    IsOverflow,
    #[size = 32]
    SubBorrow,
    #[size = 32]
    FinalFormBorrow,
    #[size = 32]
    SubChainBorrow,
    #[size = 32]
    SubChainCarryAip,
    #[size = 64]
    MulProduct,
    #[size = 64]
    MulCarry,
    #[size = 64]
    MulCarryMid,
    #[size = 64]
    MulCarryHi,
    #[size = 32]
    Pass1Lo,
    #[size = 2]
    Pass1Hi,
    #[size = 32]
    Pass1Carry,
    #[size = 32]
    Pass1CarryMid,
    #[size = 32]
    Pass2Lo,
    #[size = 1]
    Pass2CarryOut,
    #[size = 32]
    Pass2Carry,
    #[size = 1]
    Pass2TopBit,
    #[size = 32]
    AfterTopBit,
    #[size = 32]
    AfterTopCarry,
    #[size = 1]
    IsAdd,
    #[size = 1]
    IsSub,
    #[size = 1]
    IsMul,
    #[size = 1]
    IsInput,
    #[size = 1]
    IsOutput,
    #[size = 1]
    IsReal,
    // Phase I-ristretto deg-flatten helpers — defined by FieldOp helper.
    #[size = 1]
    RealAddH,
    #[size = 1]
    RealSubH,
    #[size = 1]
    RealMulH,
    #[size = 1]
    ProducerGateH,
    #[size = 1]
    ConsumerAGateH,
    #[size = 1]
    ConsumerBGateH,
    #[size = 64]
    MulPartialSum,

    // ── Source-row threading for FieldOp consumer A/B ──
    #[size = 1]
    ASourceRowLo,
    #[size = 1]
    ASourceRowHi,
    #[size = 1]
    BSourceRowLo,
    #[size = 1]
    BSourceRowHi,

    // ── Coord-boundary binding metadata ──
    /// `1` iff this row is one of the 4 IsInput coord rows in a
    /// window (offset 0..3 within the window's 22-row chunk).  Gates
    /// the coord-boundary consumer emission.
    #[size = 1]
    IsCoordInput,
    /// Index of the scalar-mult call in `ristretto_comb_calls`.
    /// Set on IsCoordInput rows; zero elsewhere.
    #[size = 1]
    CallIdx,
    /// Window index `i ∈ 0..64`.  Set on IsCoordInput rows.
    #[size = 1]
    WindowIdx,
    /// Coord kind ∈ {0=X, 1=Y, 2=Z, 3=T}.  Set on IsCoordInput rows.
    #[size = 1]
    CoordKind,

    // ── Chip-local register-file producer multiplicity ──
    /// How many downstream FieldOp consumers reference this row's
    /// `out` (counts a/b refs across the trace).  Padding / output
    /// rows have 0.
    #[size = 1]
    ProducerMultiplicity,
    /// `producer_gate_h * producer_multiplicity` deg-flatten helper.
    #[size = 1]
    ProducerEmissionMult,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_fixed_base_consumer"]
pub enum PreprocessedColumn {
    /// Chip-local row index (low byte).
    #[size = 1]
    RowIndexLo,
    /// Chip-local row index (high byte).
    #[size = 1]
    RowIndexHi,
    /// `ByteIdx[k] = k` for k=0..32.
    #[size = 32]
    ByteIdx,
    /// R1e-bis Batch 4b: 1 iff this row is one of the 4 final-Acc
    /// mul rows of window 63 within a real per-call block — i.e.,
    /// the rows producing X3 / Y3 / T3 / Z3 of the running
    /// accumulator at the end of the comb chain.  Per-call block
    /// offsets (0-indexed): 1404 (X3), 1405 (Y3), 1406 (T3),
    /// 1407 (Z3).  Drives 32 producer emissions per row to
    /// `RistrettoCombFinalAccLookupElements`.
    #[size = 1]
    IsFinalAccProducer,
    /// On IsFinalAccProducer rows: the per-call call index
    /// `(row - N_BOUNDARY_INPUTS) / 1408`.  Zero on other rows.
    #[size = 1]
    FinalAccCallIdx,
    /// On IsFinalAccProducer rows: coord_kind ∈ {0=X, 1=Y, 2=Z,
    /// 3=T}.  Mapping mirrors `point_add_rows_chained` emission
    /// order: row offset 1404 → X (0), 1405 → Y (1), 1406 → T (3),
    /// 1407 → Z (2).
    #[size = 1]
    FinalAccCoordKind,
}

/// Per-row witness for the consumer chip.
#[cfg(feature = "prover")]
#[derive(Clone, Copy, Debug)]
struct ConsumerRow {
    field: crate::chips::ristretto::witness::FieldOpRow,
    is_coord_input: u8,
    call_idx: u8,
    window_idx: u8,
    coord_kind: u8,
}

#[cfg(feature = "prover")]
impl Default for ConsumerRow {
    fn default() -> Self {
        Self {
            field: crate::chips::ristretto::witness::FieldOpRow::default(),
            is_coord_input: 0,
            call_idx: 0,
            window_idx: 0,
            coord_kind: 0,
        }
    }
}

/// Build the per-row witness stream from the side_note.
#[cfg(feature = "prover")]
fn build_consumer_rows(side_note: &SideNote) -> Vec<ConsumerRow> {
    use crate::chips::ristretto::comb_table::{
        ed25519_basepoint_extended, CombTable, NUM_WINDOWS,
    };
    use crate::chips::ristretto::point::{
        point_add_rows_chained, point_identity, ExtendedPoint, ExtendedPointSources,
        ED25519_TWO_D,
    };
    use crate::chips::ristretto::witness::fill_input;

    let mut rows: Vec<ConsumerRow> = Vec::new();

    let zero_row_id: u16 = 0;
    let one_row_id: u16 = 1;
    let two_d_row_id: u16 = 2;
    let zero_bytes = [0u8; 32];
    let mut one_bytes = [0u8; 32];
    one_bytes[0] = 1;

    rows.push(boundary_input(fill_input(zero_bytes)));
    rows.push(boundary_input(fill_input(one_bytes)));
    rows.push(boundary_input(fill_input(ED25519_TWO_D)));

    let table = CombTable::from_base(&ed25519_basepoint_extended());

    for (call_idx, call) in side_note.ristretto_comb_calls.iter().enumerate() {
        let mut acc = point_identity();
        let mut acc_sources = ExtendedPointSources {
            x_source: zero_row_id,
            y_source: one_row_id,
            z_source: one_row_id,
            t_source: zero_row_id,
        };

        for w in 0..NUM_WINDOWS {
            let byte = call.scalar[w / 2];
            let nibble_idx = w % 2;
            let k_i = ((byte >> (nibble_idx * 4)) & 0x0F) as usize;
            let entry: ExtendedPoint = table.rows[w][k_i];

            let x_row_id = rows.len() as u16;
            let y_row_id = x_row_id + 1;
            let z_row_id = x_row_id + 2;
            let t_row_id = x_row_id + 3;
            let add_chain_start = x_row_id + 4;

            // 4 IsInput coord rows: X (offset 0), Y, Z, T.
            for (kind, coord_bytes) in [
                (0u8, entry.x),
                (1u8, entry.y),
                (2u8, entry.z),
                (3u8, entry.t),
            ] {
                let mut cr = ConsumerRow::default();
                cr.field = fill_input(coord_bytes);
                cr.is_coord_input = 1;
                cr.call_idx = call_idx as u8;
                cr.window_idx = w as u8;
                cr.coord_kind = kind;
                rows.push(cr);
            }

            // 18 FieldOp add rows for `acc' = acc + entry`.
            let q_sources = ExtendedPointSources {
                x_source: x_row_id,
                y_source: y_row_id,
                z_source: z_row_id,
                t_source: t_row_id,
            };
            let (add_rows, new_acc, new_acc_sources) = point_add_rows_chained(
                &acc,
                &acc_sources,
                &entry,
                &q_sources,
                two_d_row_id,
                add_chain_start,
            );
            for fr in add_rows {
                let mut cr = ConsumerRow::default();
                cr.field = fr;
                rows.push(cr);
            }
            acc = new_acc;
            acc_sources = new_acc_sources;
        }
        let _ = acc;
        let _ = acc_sources;
    }

    finalize_producer_multiplicities(&mut rows);
    rows
}

#[cfg(feature = "prover")]
fn boundary_input(field: crate::chips::ristretto::witness::FieldOpRow) -> ConsumerRow {
    let mut cr = ConsumerRow::default();
    cr.field = field;
    cr
}

/// Walk the row stream and count downstream consumer references onto
/// each producer row's `producer_multiplicity`.
#[cfg(feature = "prover")]
fn finalize_producer_multiplicities(rows: &mut [ConsumerRow]) {
    let n = rows.len();
    for cr in rows.iter_mut() {
        cr.field.producer_multiplicity = 0;
    }
    for i in 0..n {
        let row = rows[i];
        if row.field.is_real == 0 {
            continue;
        }
        // Op + output rows consume `a` from a_source_row.
        if row.field.is_input == 0 {
            let a_src = row.field.a_source_row as usize;
            if a_src < n {
                rows[a_src].field.producer_multiplicity = rows[a_src]
                    .field
                    .producer_multiplicity
                    .checked_add(1)
                    .expect("producer_multiplicity overflowed u16");
            }
        }
        if row.field.is_input == 0 && row.field.is_output == 0 {
            let b_src = row.field.b_source_row as usize;
            if b_src < n {
                rows[b_src].field.producer_multiplicity = rows[b_src]
                    .field
                    .producer_multiplicity
                    .checked_add(1)
                    .expect("producer_multiplicity overflowed u16");
            }
        }
    }
}

#[cfg(feature = "prover")]
fn log_size_for(n_rows: usize) -> u32 {
    if n_rows <= 1 {
        return LOG_N_LANES;
    }
    let n = n_rows as u32;
    let log = 32 - (n - 1).leading_zeros();
    log.max(LOG_N_LANES)
}

impl BuiltInComponent for RistrettoFixedBaseConsumerChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        RistrettoCombCoordBoundaryLookupElements,
        RistrettoCombConsumerRegisterFileLookupElements,
        RistrettoCombFinalAccLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            RistrettoCombCoordBoundaryLookupElements,
            RistrettoCombConsumerRegisterFileLookupElements,
            RistrettoCombFinalAccLookupElements,
        ),
    ) {
        let (coord_lookup, regfile_lookup, final_acc_lookup) = lookup_elements;

        // Column reads.
        let a = crate::trace::trace_eval!(trace_eval, Column::FieldA);
        let b = crate::trace::trace_eval!(trace_eval, Column::FieldB);
        let out = crate::trace::trace_eval!(trace_eval, Column::FieldOut);
        let interm = crate::trace::trace_eval!(trace_eval, Column::AddIntermediate);
        let carry = crate::trace::trace_eval!(trace_eval, Column::AddCarry);
        let borrow = crate::trace::trace_eval!(trace_eval, Column::SubBorrow);
        let ff_brw = crate::trace::trace_eval!(trace_eval, Column::FinalFormBorrow);
        let sub_chain_brw = crate::trace::trace_eval!(trace_eval, Column::SubChainBorrow);
        let sub_chain_aip = crate::trace::trace_eval!(trace_eval, Column::SubChainCarryAip);
        let mul_product = crate::trace::trace_eval!(trace_eval, Column::MulProduct);
        let mul_carry = crate::trace::trace_eval!(trace_eval, Column::MulCarry);
        let mul_carry_mid = crate::trace::trace_eval!(trace_eval, Column::MulCarryMid);
        let mul_carry_hi = crate::trace::trace_eval!(trace_eval, Column::MulCarryHi);
        let pass1_lo = crate::trace::trace_eval!(trace_eval, Column::Pass1Lo);
        let pass1_hi = crate::trace::trace_eval!(trace_eval, Column::Pass1Hi);
        let pass1_carry = crate::trace::trace_eval!(trace_eval, Column::Pass1Carry);
        let pass1_carry_mid = crate::trace::trace_eval!(trace_eval, Column::Pass1CarryMid);
        let pass2_lo = crate::trace::trace_eval!(trace_eval, Column::Pass2Lo);
        let pass2_carry_out = crate::trace::trace_eval!(trace_eval, Column::Pass2CarryOut);
        let pass2_carry = crate::trace::trace_eval!(trace_eval, Column::Pass2Carry);
        let pass2_top_bit = crate::trace::trace_eval!(trace_eval, Column::Pass2TopBit);
        let after_top_bit = crate::trace::trace_eval!(trace_eval, Column::AfterTopBit);
        let after_top_carry = crate::trace::trace_eval!(trace_eval, Column::AfterTopCarry);
        let is_ovf = crate::trace::trace_eval!(trace_eval, Column::IsOverflow);
        let is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
        let is_sub = crate::trace::trace_eval!(trace_eval, Column::IsSub);
        let is_mul = crate::trace::trace_eval!(trace_eval, Column::IsMul);
        let is_input = crate::trace::trace_eval!(trace_eval, Column::IsInput);
        let is_output = crate::trace::trace_eval!(trace_eval, Column::IsOutput);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let real_add_h = crate::trace::trace_eval!(trace_eval, Column::RealAddH);
        let real_sub_h = crate::trace::trace_eval!(trace_eval, Column::RealSubH);
        let real_mul_h = crate::trace::trace_eval!(trace_eval, Column::RealMulH);
        let producer_gate_h = crate::trace::trace_eval!(trace_eval, Column::ProducerGateH);
        let consumer_a_gate_h = crate::trace::trace_eval!(trace_eval, Column::ConsumerAGateH);
        let consumer_b_gate_h = crate::trace::trace_eval!(trace_eval, Column::ConsumerBGateH);
        let mul_partial_sum = crate::trace::trace_eval!(trace_eval, Column::MulPartialSum);

        let a_src_lo = crate::trace::trace_eval!(trace_eval, Column::ASourceRowLo);
        let a_src_hi = crate::trace::trace_eval!(trace_eval, Column::ASourceRowHi);
        let b_src_lo = crate::trace::trace_eval!(trace_eval, Column::BSourceRowLo);
        let b_src_hi = crate::trace::trace_eval!(trace_eval, Column::BSourceRowHi);

        let is_coord_input = crate::trace::trace_eval!(trace_eval, Column::IsCoordInput);
        let call_idx = crate::trace::trace_eval!(trace_eval, Column::CallIdx);
        let window_idx = crate::trace::trace_eval!(trace_eval, Column::WindowIdx);
        let coord_kind = crate::trace::trace_eval!(trace_eval, Column::CoordKind);

        let producer_mult = crate::trace::trace_eval!(trace_eval, Column::ProducerMultiplicity);
        let producer_emission_mult =
            crate::trace::trace_eval!(trace_eval, Column::ProducerEmissionMult);

        let row_idx_lo =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexLo);
        let row_idx_hi =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexHi);
        let byte_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ByteIdx);
        let is_final_acc_producer = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::IsFinalAccProducer
        );
        let final_acc_call_idx = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::FinalAccCallIdx
        );
        let final_acc_coord_kind = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::FinalAccCoordKind
        );

        // Shared FieldOp algebra.
        field_op_constraints::add_field_op_constraints(
            eval,
            &field_op_constraints::FieldOpRefs {
                field_a: &a,
                field_b: &b,
                field_out: &out,
                add_intermediate: &interm,
                add_carry: &carry,
                sub_borrow: &borrow,
                final_form_borrow: &ff_brw,
                sub_chain_borrow: &sub_chain_brw,
                sub_chain_carry_aip: &sub_chain_aip,
                mul_product: &mul_product,
                mul_carry: &mul_carry,
                mul_carry_mid: &mul_carry_mid,
                mul_carry_hi: &mul_carry_hi,
                pass1_lo: &pass1_lo,
                pass1_hi: &pass1_hi,
                pass1_carry: &pass1_carry,
                pass1_carry_mid: &pass1_carry_mid,
                pass2_lo: &pass2_lo,
                pass2_carry_out: &pass2_carry_out,
                pass2_carry: &pass2_carry,
                pass2_top_bit: &pass2_top_bit,
                after_top_bit: &after_top_bit,
                after_top_carry: &after_top_carry,
                is_overflow: &is_ovf,
                is_add: &is_add,
                is_sub: &is_sub,
                is_mul: &is_mul,
                is_input: &is_input,
                is_output: &is_output,
                is_real: &is_real,
                real_add_h: &real_add_h,
                real_sub_h: &real_sub_h,
                real_mul_h: &real_mul_h,
                producer_gate_h: &producer_gate_h,
                consumer_a_gate_h: &consumer_a_gate_h,
                consumer_b_gate_h: &consumer_b_gate_h,
                mul_partial_sum: &mul_partial_sum,
            },
        );

        // ── IsCoordInput flag rules ──
        // Boolean.
        eval.add_constraint(
            is_coord_input[0].clone() * (E::F::from(BaseField::from(1u32)) - is_coord_input[0].clone()),
        );
        // IsCoordInput rows must be IsReal + IsInput.
        eval.add_constraint(
            is_coord_input[0].clone() * (E::F::from(BaseField::from(1u32)) - is_real[0].clone()),
        );
        eval.add_constraint(
            is_coord_input[0].clone() * (E::F::from(BaseField::from(1u32)) - is_input[0].clone()),
        );

        // ProducerEmissionMult deg-flatten helper.
        eval.add_constraint(
            producer_emission_mult[0].clone()
                - producer_gate_h[0].clone() * producer_mult[0].clone(),
        );

        // ── Coord-boundary consumer emissions (gated by IsCoordInput) ──
        // Per IsCoordInput row, 32 −1 contributions, one per byte.
        for k in 0..32 {
            eval.add_to_relation(RelationEntry::new(
                coord_lookup,
                (-is_coord_input[0].clone()).into(),
                &[
                    call_idx[0].clone(),
                    window_idx[0].clone(),
                    coord_kind[0].clone(),
                    byte_idx_pp[k].clone(),
                    out[k].clone(),
                ],
            ));
        }

        // ── Chip-local register-file producer + consumer A/B ──
        for k in 0..32 {
            // Producer.
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                producer_emission_mult[0].clone().into(),
                &[
                    row_idx_lo[0].clone(),
                    row_idx_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    out[k].clone(),
                ],
            ));
            // Consumer A.
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                (-consumer_a_gate_h[0].clone()).into(),
                &[
                    a_src_lo[0].clone(),
                    a_src_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    a[k].clone(),
                ],
            ));
            // Consumer B.
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                (-consumer_b_gate_h[0].clone()).into(),
                &[
                    b_src_lo[0].clone(),
                    b_src_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    b[k].clone(),
                ],
            ));
        }

        // ── Final-Acc cross-chip producer (Batch 4b) ──
        // On each of the 4 final-Acc rows of window 63 in real
        // per-call blocks (gated by IsFinalAccProducer), emit 32
        // producer tuples `(call_idx, coord_kind, byte_idx, out[k])`
        // to the cross-chip relation.  The compress chip's IsInput
        // rows for X/Y/Z/T (offsets +0..+3 of each per-call block
        // in compress's row layout) consume these tuples — binding
        // compress's X/Y/Z/T inputs to the comb chain's
        // window-63 final accumulator coords.
        for k in 0..32 {
            eval.add_to_relation(RelationEntry::new(
                final_acc_lookup,
                is_final_acc_producer[0].clone().into(),
                &[
                    final_acc_call_idx[0].clone(),
                    final_acc_coord_kind[0].clone(),
                    byte_idx_pp[k].clone(),
                    out[k].clone(),
                ],
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoFixedBaseConsumerChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        side_note: &SideNote,
    ) -> FinalizedTrace {
        let log_size = log_size_for(consumer_n_rows(side_note));
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        let real_n_rows = consumer_n_rows(side_note);
        let n_calls = side_note.ristretto_comb_calls.len();
        // Per-window block: 4 IsInput coord rows + 18 add rows = 22.
        // Per-call block: 64 windows × 22 = 1408 rows.
        // Window-63 final-Acc rows are the LAST 4 rows of window 63's
        // 18-row add chain — at offsets 1404, 1405, 1406, 1407 within
        // the per-call block.  Coord kind mapping mirrors
        // `point_add_rows_chained` emission order: X3 (0), Y3 (1),
        // T3 (3), Z3 (2).
        const FINAL_ACC_OFFSETS: [usize; 4] = [1404, 1405, 1406, 1407];
        const FINAL_ACC_COORD_KINDS: [u8; 4] = [0, 1, 3, 2];
        const PER_CALL_ROWS: usize = 64 * ROWS_PER_WINDOW; // 1408
        for row in 0..num_rows {
            let row_lo = (row & 0xff) as u8;
            let row_hi = ((row >> 8) & 0xff) as u8;
            trace.fill_columns(row, row_lo, PreprocessedColumn::RowIndexLo);
            trace.fill_columns(row, row_hi, PreprocessedColumn::RowIndexHi);
            let byte_idx_arr: [u8; 32] = core::array::from_fn(|k| k as u8);
            trace.fill_columns_bytes(row, &byte_idx_arr, PreprocessedColumn::ByteIdx);

            // IsFinalAccProducer + FinalAccCallIdx + FinalAccCoordKind:
            // 1 only on the 4 final-Acc rows of window 63 in real
            // per-call blocks.
            let mut is_final_acc = 0u8;
            let mut call_idx = 0u8;
            let mut coord_kind = 0u8;
            if row >= N_BOUNDARY_INPUTS && row < real_n_rows && n_calls > 0 {
                let within_call_section = row - N_BOUNDARY_INPUTS;
                let c = within_call_section / PER_CALL_ROWS;
                let off = within_call_section % PER_CALL_ROWS;
                if let Some(slot) = FINAL_ACC_OFFSETS.iter().position(|&o| o == off) {
                    is_final_acc = 1;
                    call_idx = c as u8;
                    coord_kind = FINAL_ACC_COORD_KINDS[slot];
                }
            }
            trace.fill_columns(
                row,
                is_final_acc,
                PreprocessedColumn::IsFinalAccProducer,
            );
            trace.fill_columns(row, call_idx, PreprocessedColumn::FinalAccCallIdx);
            trace.fill_columns(
                row,
                coord_kind,
                PreprocessedColumn::FinalAccCoordKind,
            );
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let rows = build_consumer_rows(side_note);
        let log_size = log_size_for(rows.len());
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        for row_i in 0..num_rows {
            let cr = rows.get(row_i).copied().unwrap_or_default();
            fill_consumer_row(&mut trace, row_i, &cr);
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

        let coord: &RistrettoCombCoordBoundaryLookupElements = lookup_elements.as_ref();
        let regfile: &RistrettoCombConsumerRegisterFileLookupElements =
            lookup_elements.as_ref();
        let final_acc: &RistrettoCombFinalAccLookupElements = lookup_elements.as_ref();

        let is_coord_input =
            crate::trace::original_base_column!(component_trace, Column::IsCoordInput);
        let call_idx =
            crate::trace::original_base_column!(component_trace, Column::CallIdx);
        let window_idx =
            crate::trace::original_base_column!(component_trace, Column::WindowIdx);
        let coord_kind =
            crate::trace::original_base_column!(component_trace, Column::CoordKind);

        let is_final_acc_producer_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::IsFinalAccProducer
        );
        let final_acc_call_idx_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::FinalAccCallIdx
        );
        let final_acc_coord_kind_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::FinalAccCoordKind
        );

        let row_idx_lo_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::RowIndexLo
        );
        let row_idx_hi_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::RowIndexHi
        );
        let byte_idx_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::ByteIdx
        );
        let producer_emission_mult = crate::trace::original_base_column!(
            component_trace,
            Column::ProducerEmissionMult
        );
        let consumer_a_gate_h = crate::trace::original_base_column!(
            component_trace,
            Column::ConsumerAGateH
        );
        let consumer_b_gate_h = crate::trace::original_base_column!(
            component_trace,
            Column::ConsumerBGateH
        );
        let a_cols = crate::trace::original_base_column!(component_trace, Column::FieldA);
        let b_cols = crate::trace::original_base_column!(component_trace, Column::FieldB);
        let out_cols = crate::trace::original_base_column!(component_trace, Column::FieldOut);
        let a_src_lo_col =
            crate::trace::original_base_column!(component_trace, Column::ASourceRowLo);
        let a_src_hi_col =
            crate::trace::original_base_column!(component_trace, Column::ASourceRowHi);
        let b_src_lo_col =
            crate::trace::original_base_column!(component_trace, Column::BSourceRowLo);
        let b_src_hi_col =
            crate::trace::original_base_column!(component_trace, Column::BSourceRowHi);

        // Coord-boundary consumer emissions.
        for k in 0..32 {
            logup.add_to_relation_with(
                coord,
                [is_coord_input[0].clone()],
                |[g]| (-g).into(),
                &[
                    call_idx[0].clone(),
                    window_idx[0].clone(),
                    coord_kind[0].clone(),
                    byte_idx_pp[k].clone(),
                    out_cols[k].clone(),
                ],
            );
        }

        // Chip-local register-file emissions.
        for k in 0..32 {
            logup.add_to_relation_with(
                regfile,
                [producer_emission_mult[0].clone()],
                |[m]| m.into(),
                &[
                    row_idx_lo_pp[0].clone(),
                    row_idx_hi_pp[0].clone(),
                    byte_idx_pp[k].clone(),
                    out_cols[k].clone(),
                ],
            );
            logup.add_to_relation_with(
                regfile,
                [consumer_a_gate_h[0].clone()],
                |[g]| (-g).into(),
                &[
                    a_src_lo_col[0].clone(),
                    a_src_hi_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    a_cols[k].clone(),
                ],
            );
            logup.add_to_relation_with(
                regfile,
                [consumer_b_gate_h[0].clone()],
                |[g]| (-g).into(),
                &[
                    b_src_lo_col[0].clone(),
                    b_src_hi_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    b_cols[k].clone(),
                ],
            );
        }

        // ── Final-Acc cross-chip producer emissions ──
        for k in 0..32 {
            logup.add_to_relation_with(
                final_acc,
                [is_final_acc_producer_pp[0].clone()],
                |[g]| g.into(),
                &[
                    final_acc_call_idx_pp[0].clone(),
                    final_acc_coord_kind_pp[0].clone(),
                    byte_idx_pp[k].clone(),
                    out_cols[k].clone(),
                ],
            );
        }

        logup.finalize()
    }
}

#[cfg(feature = "prover")]
fn consumer_n_rows(side_note: &SideNote) -> usize {
    N_BOUNDARY_INPUTS
        + side_note.ristretto_comb_calls.len()
            * crate::chips::ristretto::comb_table::NUM_WINDOWS
            * ROWS_PER_WINDOW
}

#[cfg(feature = "prover")]
fn fill_consumer_row(trace: &mut TraceBuilder<Column>, row_i: usize, cr: &ConsumerRow) {
    use crate::chips::ristretto::witness::FieldOpRow;
    let r: FieldOpRow = cr.field;

    // FieldOp witness columns.
    trace.fill_columns_bytes(row_i, &r.a, Column::FieldA);
    trace.fill_columns_bytes(row_i, &r.b, Column::FieldB);
    trace.fill_columns_bytes(row_i, &r.out, Column::FieldOut);
    trace.fill_columns_bytes(row_i, &r.add_intermediate, Column::AddIntermediate);
    trace.fill_columns_bytes(row_i, &r.add_carry, Column::AddCarry);
    trace.fill_columns_bytes(row_i, &r.sub_borrow, Column::SubBorrow);
    trace.fill_columns_bytes(row_i, &r.final_form_borrow, Column::FinalFormBorrow);
    trace.fill_columns_bytes(row_i, &r.sub_chain_borrow, Column::SubChainBorrow);
    trace.fill_columns_bytes(row_i, &r.sub_chain_carry_aip, Column::SubChainCarryAip);
    trace.fill_columns_bytes(row_i, &r.mul_product, Column::MulProduct);
    trace.fill_columns_bytes(row_i, &r.mul_carry, Column::MulCarry);
    trace.fill_columns_bytes(row_i, &r.mul_carry_mid, Column::MulCarryMid);
    trace.fill_columns_bytes(row_i, &r.mul_carry_hi, Column::MulCarryHi);
    trace.fill_columns_bytes(row_i, &r.pass1_lo, Column::Pass1Lo);
    trace.fill_columns_bytes(row_i, &r.pass1_hi, Column::Pass1Hi);
    trace.fill_columns_bytes(row_i, &r.pass1_carry, Column::Pass1Carry);
    trace.fill_columns_bytes(row_i, &r.pass1_carry_mid, Column::Pass1CarryMid);
    trace.fill_columns_bytes(row_i, &r.pass2_lo, Column::Pass2Lo);
    trace.fill_columns_bytes(row_i, &r.pass2_carry, Column::Pass2Carry);
    trace.fill_columns_bytes(row_i, &r.after_top_bit, Column::AfterTopBit);
    trace.fill_columns_bytes(row_i, &r.after_top_carry, Column::AfterTopCarry);
    trace.fill_columns(row_i, r.is_overflow, Column::IsOverflow);
    trace.fill_columns(row_i, r.pass2_carry_out, Column::Pass2CarryOut);
    trace.fill_columns(row_i, r.pass2_top_bit, Column::Pass2TopBit);
    trace.fill_columns(row_i, r.is_add, Column::IsAdd);
    trace.fill_columns(row_i, r.is_sub, Column::IsSub);
    trace.fill_columns(row_i, r.is_mul, Column::IsMul);
    trace.fill_columns(row_i, r.is_input, Column::IsInput);
    trace.fill_columns(row_i, r.is_output, Column::IsOutput);
    trace.fill_columns(row_i, r.is_real, Column::IsReal);

    // Source-row low/high bytes.
    trace.fill_columns(row_i, (r.a_source_row & 0xff) as u8, Column::ASourceRowLo);
    trace.fill_columns(
        row_i,
        ((r.a_source_row >> 8) & 0xff) as u8,
        Column::ASourceRowHi,
    );
    trace.fill_columns(row_i, (r.b_source_row & 0xff) as u8, Column::BSourceRowLo);
    trace.fill_columns(
        row_i,
        ((r.b_source_row >> 8) & 0xff) as u8,
        Column::BSourceRowHi,
    );

    // Phase I-ristretto deg-flatten helpers.
    let real_b = r.is_real != 0;
    let add_b = r.is_add != 0;
    let sub_b = r.is_sub != 0;
    let mul_b = r.is_mul != 0;
    let inp_b = r.is_input != 0;
    let out_b = r.is_output != 0;
    trace.fill_columns(row_i, real_b && add_b, Column::RealAddH);
    trace.fill_columns(row_i, real_b && sub_b, Column::RealSubH);
    trace.fill_columns(row_i, real_b && mul_b, Column::RealMulH);
    trace.fill_columns(row_i, real_b && !out_b, Column::ProducerGateH);
    trace.fill_columns(row_i, real_b && !inp_b, Column::ConsumerAGateH);
    trace.fill_columns(row_i, real_b && !inp_b && !out_b, Column::ConsumerBGateH);

    // MulPartialSum[k] = Σ a[i]·b[j] for i+j=k.
    let mut psum = [BaseField::from(0u32); 64];
    for k in 0..64usize {
        let mut s: u32 = 0;
        for i in 0..32usize {
            let j = k.wrapping_sub(i);
            if j < 32 {
                s += r.a[i] as u32 * r.b[j] as u32;
            }
        }
        psum[k] = BaseField::from(s);
    }
    trace.fill_columns_base_field(row_i, &psum, Column::MulPartialSum);

    // Coord-boundary metadata.
    trace.fill_columns(row_i, cr.is_coord_input, Column::IsCoordInput);
    trace.fill_columns(row_i, cr.call_idx, Column::CallIdx);
    trace.fill_columns(row_i, cr.window_idx, Column::WindowIdx);
    trace.fill_columns(row_i, cr.coord_kind, Column::CoordKind);

    // Producer multiplicity + emission helper.
    let pm: u32 = r.producer_multiplicity as u32;
    trace.fill_columns(row_i, BaseField::from(pm), Column::ProducerMultiplicity);
    let emission = if real_b && !out_b { pm } else { 0 };
    trace.fill_columns(row_i, BaseField::from(emission), Column::ProducerEmissionMult);
}
