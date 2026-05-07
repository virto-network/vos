//! Session 2.1 step 5(b) — RistrettoFixedBaseConsumerChip with
//! running-sum binding.
//!
//! Per fixed-basepoint scalar mult call, lays out:
//!   - 4 IsInput rows per window (1 lookup-anchor + 3 lookup-coord
//!     rows for X/Y/Z/T of `T[i][k_i]`).
//!   - 18 FieldOp add rows per window for the point-add formula
//!     `Acc' = Acc + T[i][k_i]` (see `point.rs::point_add_rows_chained`).
//!
//! Soundness chain:
//!   - Comb relation (`RistrettoCombLookupElements`): the lookup-anchor
//!     row emits +IsLookupAnchor with the 130-limb tuple `(WindowIdx,
//!     ScalarWindow, X, Y, Z, T)` from its own witness columns.
//!     Balanced against `RistrettoCombTableChip` (-Multiplicity).
//!   - Anchor X-coord binding: per-row constraint
//!     `IsLookupAnchor * (FieldOut - X) = 0` ties the anchor's `out`
//!     to its X column.
//!   - Anchor Y/Z/T-coord binding: chip-local register-file relation
//!     (`RistrettoCombConsumerRegisterFileLookupElements`).  The anchor
//!     row emits 96 *consumer* tuples (32 per coord) keyed on rows
//!     `+1`/`+2`/`+3` (the lookup-coord rows) with byte_idx + Y/Z/T
//!     value.  Those rows emit *producer* tuples for their `out`.
//!     Balance forces `Y == out_at_+1`, `Z == out_at_+2`, `T == out_at_+3`.
//!   - FieldOp algebra (shared helper at `chips::ristretto::field_op_constraints`):
//!     pins each add/sub/mul row's algebra mod p25519.
//!   - Source-row threading: the 18 add rows reference rows `+0`/`+1`/
//!     `+2`/`+3` (this window's lookup rows) as `q.{x,y,z,t}` source
//!     rows, and the previous window's final 4 add rows (or boundary
//!     constants for window 0) as `p.{x,y,z,t}` source rows.  The
//!     chip-local register-file balance forces each add row's `a`/`b`
//!     inputs to equal the `out` column of the named source row.
//!
//! Step 8 (ECALL boundary binding) and Range256 byte-range emissions
//! are deferred to a follow-up — see PERF_ROADMAP.md.

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
use num_traits::One;
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
        RistrettoCombConsumerRegisterFileLookupElements, RistrettoCombLookupElements,
    },
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoFixedBaseConsumerChip;

/// Number of rows per window: 4 IsInput rows (anchor + Y/Z/T coords) +
/// 18 FieldOp add rows from `point_add_rows_chained`.
pub const ROWS_PER_WINDOW: usize = 4 + 18;
/// Constant boundary input rows at the start of the chip's trace:
/// `[zero, one, ED25519_TWO_D]`.
pub const N_BOUNDARY_INPUTS: usize = 3;

/// Per-row column layout.  Mirrors RistrettoChip's FieldOp witness
/// columns (so the shared `field_op_constraints` helper applies) plus
/// chip-specific lookup-anchor / source-row / producer-multiplicity
/// columns.
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

    // ── Lookup-anchor specific witness columns ──
    /// `1` iff this row is the lookup-anchor row of a window (the row
    /// that emits +1 to `RistrettoCombLookupElements`).  Constraint
    /// chain: forces this row's `is_real=1`, `is_input=1`, and ties
    /// `FieldOut` to `X[k]` per byte (so the comb-relation tuple's X
    /// equals the chip's chosen `out`).
    #[size = 1]
    IsLookupAnchor,
    /// Window index `i ∈ 0..64`.  Zero on non-anchor rows.
    #[size = 1]
    WindowIdx,
    /// Scalar window value `k_i ∈ 0..16`.  Zero on non-anchor rows.
    #[size = 1]
    ScalarWindow,
    /// Looked-up `T[i][k_i].x` — 32 LE bytes.  On the anchor row, also
    /// equals `FieldOut` (per the IsLookupAnchor binding constraint).
    #[size = 32]
    X,
    /// Looked-up `T[i][k_i].y` — 32 LE bytes.  Tied to row `+1`'s
    /// `FieldOut` via chip-local register-file balance.
    #[size = 32]
    Y,
    #[size = 32]
    Z,
    #[size = 32]
    T,
    /// Source row IDs for the anchor's Y/Z/T cross-row consumer
    /// emissions.  Set to anchor_row+1/+2/+3 on anchor rows; zero
    /// elsewhere.  Lo/Hi byte split (matches register-file row_id
    /// encoding).
    #[size = 1]
    YSrcRowLo,
    #[size = 1]
    YSrcRowHi,
    #[size = 1]
    ZSrcRowLo,
    #[size = 1]
    ZSrcRowHi,
    #[size = 1]
    TSrcRowLo,
    #[size = 1]
    TSrcRowHi,

    // ── Chip-local register-file producer multiplicity ──
    /// How many downstream FieldOp consumers reference this row's `out`
    /// (or, for lookup-coord rows, also count the anchor's Y/Z/T
    /// consumer).  Drives the producer emission's multiplicity scalar.
    /// Padding / output rows have 0.
    #[size = 1]
    ProducerMultiplicity,
    /// `producer_gate_h * producer_multiplicity` deg-flatten helper.
    /// Used as the producer emission's multiplicity coefficient so the
    /// gated relation entry stays at deg ≤ 2.
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
    /// `ByteIdx[k] = k` for k=0..32.  Used as the `byte_idx` element
    /// of register-file lookup tuples.
    #[size = 32]
    ByteIdx,
}

/// Per-row witness for the consumer chip.  Composes a `FieldOpRow`
/// (FieldOp algebra witness) with chip-specific lookup-anchor /
/// source-row metadata.  Trace fill writes one of these per chip row.
#[cfg(feature = "prover")]
#[derive(Clone, Copy, Debug)]
struct ConsumerRow {
    field: crate::chips::ristretto::witness::FieldOpRow,
    is_lookup_anchor: u8,
    window_idx: u8,
    scalar_window: u8,
    x: [u8; 32],
    y: [u8; 32],
    z: [u8; 32],
    t: [u8; 32],
    y_src_row: u16,
    z_src_row: u16,
    t_src_row: u16,
}

#[cfg(feature = "prover")]
impl Default for ConsumerRow {
    fn default() -> Self {
        Self {
            field: crate::chips::ristretto::witness::FieldOpRow::default(),
            is_lookup_anchor: 0,
            window_idx: 0,
            scalar_window: 0,
            x: [0u8; 32],
            y: [0u8; 32],
            z: [0u8; 32],
            t: [0u8; 32],
            y_src_row: 0,
            z_src_row: 0,
            t_src_row: 0,
        }
    }
}

/// Compute the consumer chip's row stream for the given side_note.
/// Lays out 3 boundary input rows (zero, one, ED25519_TWO_D) followed
/// by per-call `64 × ROWS_PER_WINDOW` rows.  Source-row threading
/// follows `point_add_rows_chained` semantics.
///
/// After laying out all rows, walks the stream to count downstream
/// consumer references and sets `producer_multiplicity` on each
/// producer row accordingly.
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

    // Boundary input rows (constants).
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

    for call in &side_note.ristretto_comb_calls {
        // Acc starts at identity = (0, 1, 1, 0).
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

            let anchor_row_id = rows.len() as u16;
            let y_row_id = anchor_row_id + 1;
            let z_row_id = anchor_row_id + 2;
            let t_row_id = anchor_row_id + 3;
            let add_chain_start = anchor_row_id + 4;

            // Anchor row: IsInput, IsLookupAnchor; out = entry.x.
            let mut anchor = ConsumerRow::default();
            anchor.field = fill_input(entry.x);
            anchor.is_lookup_anchor = 1;
            anchor.window_idx = w as u8;
            anchor.scalar_window = k_i as u8;
            anchor.x = entry.x;
            anchor.y = entry.y;
            anchor.z = entry.z;
            anchor.t = entry.t;
            anchor.y_src_row = y_row_id;
            anchor.z_src_row = z_row_id;
            anchor.t_src_row = t_row_id;
            rows.push(anchor);

            // Y/Z/T lookup-coord rows (plain IsInput).
            rows.push(boundary_input(fill_input(entry.y)));
            rows.push(boundary_input(fill_input(entry.z)));
            rows.push(boundary_input(fill_input(entry.t)));

            // 18 FieldOp add rows for point_add(acc, entry).
            let q_sources = ExtendedPointSources {
                x_source: anchor_row_id,
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
        // `acc` now holds `k · G` in extended Edwards coords; binding
        // it to the ECALL output is step 8 (deferred).
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
/// each producer row's `producer_multiplicity`.  Mirrors
/// `SideNote::finalize_ristretto_multiplicities` plus the
/// lookup-anchor's Y/Z/T cross-row consumer accounting.
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
        // Op rows additionally consume `b`.
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
        // Lookup-anchor rows additionally emit 3 cross-row consumer
        // tuples (one per Y/Z/T coord) referencing rows +1/+2/+3.
        if row.is_lookup_anchor != 0 {
            for src in [row.y_src_row, row.z_src_row, row.t_src_row] {
                let s = src as usize;
                if s < n {
                    rows[s].field.producer_multiplicity = rows[s]
                        .field
                        .producer_multiplicity
                        .checked_add(1)
                        .expect("producer_multiplicity overflowed u16");
                }
            }
        }
    }
}

/// log_size for the chip's trace given the row count.  Pads up to the
/// next power of two with a floor at LOG_N_LANES.
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
        RistrettoCombLookupElements,
        RistrettoCombConsumerRegisterFileLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            RistrettoCombLookupElements,
            RistrettoCombConsumerRegisterFileLookupElements,
        ),
    ) {
        let (comb_lookup, regfile_lookup) = lookup_elements;

        // ── Column reads ──
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

        let is_lookup_anchor = crate::trace::trace_eval!(trace_eval, Column::IsLookupAnchor);
        let window_idx = crate::trace::trace_eval!(trace_eval, Column::WindowIdx);
        let scalar_window = crate::trace::trace_eval!(trace_eval, Column::ScalarWindow);
        let x_col = crate::trace::trace_eval!(trace_eval, Column::X);
        let y_col = crate::trace::trace_eval!(trace_eval, Column::Y);
        let z_col = crate::trace::trace_eval!(trace_eval, Column::Z);
        let t_col = crate::trace::trace_eval!(trace_eval, Column::T);
        let y_src_lo = crate::trace::trace_eval!(trace_eval, Column::YSrcRowLo);
        let y_src_hi = crate::trace::trace_eval!(trace_eval, Column::YSrcRowHi);
        let z_src_lo = crate::trace::trace_eval!(trace_eval, Column::ZSrcRowLo);
        let z_src_hi = crate::trace::trace_eval!(trace_eval, Column::ZSrcRowHi);
        let t_src_lo = crate::trace::trace_eval!(trace_eval, Column::TSrcRowLo);
        let t_src_hi = crate::trace::trace_eval!(trace_eval, Column::TSrcRowHi);

        let producer_mult = crate::trace::trace_eval!(trace_eval, Column::ProducerMultiplicity);
        let producer_emission_mult =
            crate::trace::trace_eval!(trace_eval, Column::ProducerEmissionMult);

        let row_idx_lo =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexLo);
        let row_idx_hi =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexHi);
        let byte_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ByteIdx);

        // ── R1c-3..R1c-5-b: shared FieldOp algebra ──
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

        // ── IsLookupAnchor flag rules ──
        // Boolean.
        eval.add_constraint(
            is_lookup_anchor[0].clone() * (E::F::one() - is_lookup_anchor[0].clone()),
        );
        // Anchor rows must be real-input rows.
        eval.add_constraint(
            is_lookup_anchor[0].clone() * (E::F::one() - is_real[0].clone()),
        );
        eval.add_constraint(
            is_lookup_anchor[0].clone() * (E::F::one() - is_input[0].clone()),
        );
        // Anchor's `out` = X[k] per byte.
        for k in 0..32 {
            eval.add_constraint(
                is_lookup_anchor[0].clone() * (out[k].clone() - x_col[k].clone()),
            );
        }

        // ── Comb relation emission (gated by IsLookupAnchor) ──
        let mut tuple: Vec<E::F> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x_col.iter().cloned());
        tuple.extend(y_col.iter().cloned());
        tuple.extend(z_col.iter().cloned());
        tuple.extend(t_col.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            comb_lookup,
            is_lookup_anchor[0].clone().into(),
            &tuple,
        ));

        // ── ProducerEmissionMult deg-flatten helper ──
        // emission_mult = producer_gate_h * producer_multiplicity (deg 2).
        eval.add_constraint(
            producer_emission_mult[0].clone()
                - producer_gate_h[0].clone() * producer_mult[0].clone(),
        );

        // ── Chip-local register-file producer + consumer A/B ──
        for k in 0..32 {
            // Producer: emission_mult @ (row_id_lo, row_id_hi, byte_idx[k], out[k]).
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
            // Consumer A: -consumer_a_gate_h @ (a_src, byte_idx, a[k]).
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
            // Consumer B: -consumer_b_gate_h @ (b_src, byte_idx, b[k]).
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

        // ── Chip-local register-file: anchor's Y/Z/T cross-row consumers ──
        for k in 0..32 {
            // Y consumer.
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                (-is_lookup_anchor[0].clone()).into(),
                &[
                    y_src_lo[0].clone(),
                    y_src_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    y_col[k].clone(),
                ],
            ));
            // Z consumer.
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                (-is_lookup_anchor[0].clone()).into(),
                &[
                    z_src_lo[0].clone(),
                    z_src_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    z_col[k].clone(),
                ],
            ));
            // T consumer.
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                (-is_lookup_anchor[0].clone()).into(),
                &[
                    t_src_lo[0].clone(),
                    t_src_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    t_col[k].clone(),
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
        for row in 0..num_rows {
            let row_lo = (row & 0xff) as u8;
            let row_hi = ((row >> 8) & 0xff) as u8;
            trace.fill_columns(row, row_lo, PreprocessedColumn::RowIndexLo);
            trace.fill_columns(row, row_hi, PreprocessedColumn::RowIndexHi);
            let byte_idx_arr: [u8; 32] = core::array::from_fn(|k| k as u8);
            trace.fill_columns_bytes(row, &byte_idx_arr, PreprocessedColumn::ByteIdx);
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

        let comb: &RistrettoCombLookupElements = lookup_elements.as_ref();
        let regfile: &RistrettoCombConsumerRegisterFileLookupElements =
            lookup_elements.as_ref();

        // Comb-relation column reads.
        let is_lookup_anchor =
            crate::trace::original_base_column!(component_trace, Column::IsLookupAnchor);
        let window_idx =
            crate::trace::original_base_column!(component_trace, Column::WindowIdx);
        let scalar_window =
            crate::trace::original_base_column!(component_trace, Column::ScalarWindow);
        let x_col = crate::trace::original_base_column!(component_trace, Column::X);
        let y_col = crate::trace::original_base_column!(component_trace, Column::Y);
        let z_col = crate::trace::original_base_column!(component_trace, Column::Z);
        let t_col = crate::trace::original_base_column!(component_trace, Column::T);

        let mut tuple: Vec<_> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x_col.iter().cloned());
        tuple.extend(y_col.iter().cloned());
        tuple.extend(z_col.iter().cloned());
        tuple.extend(t_col.iter().cloned());

        logup.add_to_relation_with(
            comb,
            [is_lookup_anchor[0].clone()],
            |[a]| a.into(),
            &tuple,
        );

        // Chip-local register-file column reads.
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
        let y_src_lo_col =
            crate::trace::original_base_column!(component_trace, Column::YSrcRowLo);
        let y_src_hi_col =
            crate::trace::original_base_column!(component_trace, Column::YSrcRowHi);
        let z_src_lo_col =
            crate::trace::original_base_column!(component_trace, Column::ZSrcRowLo);
        let z_src_hi_col =
            crate::trace::original_base_column!(component_trace, Column::ZSrcRowHi);
        let t_src_lo_col =
            crate::trace::original_base_column!(component_trace, Column::TSrcRowLo);
        let t_src_hi_col =
            crate::trace::original_base_column!(component_trace, Column::TSrcRowHi);

        for k in 0..32 {
            // Producer.
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
            // Consumer A.
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
            // Consumer B.
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

        // Anchor Y/Z/T cross-row consumers.
        for k in 0..32 {
            logup.add_to_relation_with(
                regfile,
                [is_lookup_anchor[0].clone()],
                |[g]| (-g).into(),
                &[
                    y_src_lo_col[0].clone(),
                    y_src_hi_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    y_col[k].clone(),
                ],
            );
            logup.add_to_relation_with(
                regfile,
                [is_lookup_anchor[0].clone()],
                |[g]| (-g).into(),
                &[
                    z_src_lo_col[0].clone(),
                    z_src_hi_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    z_col[k].clone(),
                ],
            );
            logup.add_to_relation_with(
                regfile,
                [is_lookup_anchor[0].clone()],
                |[g]| (-g).into(),
                &[
                    t_src_lo_col[0].clone(),
                    t_src_hi_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    t_col[k].clone(),
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

    // FieldOp witness columns (mirror RistrettoChip's trace fill).
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

    // Phase I-ristretto deg-flatten helpers (mirror RistrettoChip).
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

    // Lookup-anchor specific columns.
    trace.fill_columns(row_i, cr.is_lookup_anchor, Column::IsLookupAnchor);
    trace.fill_columns(row_i, cr.window_idx, Column::WindowIdx);
    trace.fill_columns(row_i, cr.scalar_window, Column::ScalarWindow);
    trace.fill_columns_bytes(row_i, &cr.x, Column::X);
    trace.fill_columns_bytes(row_i, &cr.y, Column::Y);
    trace.fill_columns_bytes(row_i, &cr.z, Column::Z);
    trace.fill_columns_bytes(row_i, &cr.t, Column::T);
    trace.fill_columns(row_i, (cr.y_src_row & 0xff) as u8, Column::YSrcRowLo);
    trace.fill_columns(row_i, ((cr.y_src_row >> 8) & 0xff) as u8, Column::YSrcRowHi);
    trace.fill_columns(row_i, (cr.z_src_row & 0xff) as u8, Column::ZSrcRowLo);
    trace.fill_columns(row_i, ((cr.z_src_row >> 8) & 0xff) as u8, Column::ZSrcRowHi);
    trace.fill_columns(row_i, (cr.t_src_row & 0xff) as u8, Column::TSrcRowLo);
    trace.fill_columns(row_i, ((cr.t_src_row >> 8) & 0xff) as u8, Column::TSrcRowHi);

    // Producer multiplicity + emission helper.
    let pm: u32 = r.producer_multiplicity as u32;
    trace.fill_columns(row_i, BaseField::from(pm), Column::ProducerMultiplicity);
    let emission = if real_b && !out_b { pm } else { 0 };
    trace.fill_columns(row_i, BaseField::from(emission), Column::ProducerEmissionMult);
}
