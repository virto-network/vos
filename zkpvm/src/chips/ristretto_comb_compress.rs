//! Session 2.1 step 8 R1e-bis Batch 2 — RistrettoCombCompressChip.
//!
//! Implements the Ristretto255 compress chain over our `field::Bytes`
//! reference, pinning each step's algebra to the chip's per-row
//! FieldOp constraints.  This batch lays out the **algebra prologue**
//! (rows 1-12 of the design sketch in PERF_ROADMAP.md§"R1e-bis output
//! binding"); the sign checks + conditional rows + memory output
//! producer come in subsequent batches.
//!
//! Per scalar-mult call, the chip emits:
//!   - 5 `IsInput` rows holding `X`, `Y`, `Z`, `T` of the running
//!     extended-Edwards accumulator (the consumer chip's window-63
//!     output) plus the prover's witnessed `inv_sqrt`.
//!   - 12 algebra rows:
//!       row +5: `IsAdd`  — `Z + Y`
//!       row +6: `IsSub`  — `Z - Y`
//!       row +7: `IsMul`  — `u1 = (Z+Y)·(Z-Y)`
//!       row +8: `IsMul`  — `u2 = X·Y`
//!       row +9: `IsMul`  — `u2² = u2·u2`
//!       row+10: `IsMul`  — `tmp = u1·u2²`
//!       row+11: `IsMul`  — `inv_sqrt²`
//!       row+12: `IsMul`  — `inv_sqrt²·tmp` (the unity-check row)
//!       row+13: `IsMul`  — `i1 = inv_sqrt·u1`
//!       row+14: `IsMul`  — `i2 = inv_sqrt·u2`
//!       row+15: `IsMul`  — `i2·T`
//!       row+16: `IsMul`  — `z_inv = i1·(i2·T)`
//!
//! Total: 17 rows per call.  All algebra rows reuse the shared
//! `field_op_constraints` helper for byte-wise mod-p25519 arithmetic.
//!
//! Source-row threading uses a chip-local register-file relation
//! (`RistrettoCombCompressRegFileLookupElements`) — same shape as
//! the consumer chip's, but a distinct relation type so chip-local
//! row IDs don't collide.  Producer per real row: 32 (row_lo, row_hi,
//! byte_idx, out[k]) tuples.  Consumer A/B per algebra row: 32 each
//! for `a` / `b` keyed on the source row's ID.
//!
//! NOT YET IN THIS BATCH:
//!   - The `inv_sqrt²·tmp = 1` unity check on row +12's `out`
//!     (constrains `out[0]=1, out[1..32]=0`).  Lands with the rest of
//!     the integrity checks once row+12 is wired against the rest of
//!     the chain.
//!   - Inter-chip binding: tying X/Y/Z/T to the consumer chip's
//!     window-63 final mul rows via a new boundary relation.  Today
//!     X/Y/Z/T are open IsInput witness — chip-isolated tests rely on
//!     the host-side compress witness to fill them consistently with
//!     the prover-claimed `out_bytes`.
//!   - Sign checks (rows 13, 19, 23) and conditional select/negate
//!     rows (rows 18, 21, 25) — Batch 3.
//!   - Output-byte memory producer + RistrettoEcallChip skip — Batch 4.
//!
//! Validation in this batch: `harness_ristretto_compress_algebra_only`
//! exercises the algebra closure for a synthetic FixedBasepoint call
//! and proves the chip in isolation.  The chip-local register-file
//! relation closes (every consumer balances against the matching
//! producer), so `prove + verify` succeeds against the open chain.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
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
use crate::framework::BuiltInComponent;
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::lookups::{
    ByteToBitsLookupElements, RistrettoCombCompressOutputLookupElements,
    RistrettoCombCompressRegFileLookupElements, RistrettoCombFinalAccLookupElements,
};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoCombCompressChip;

/// Chip-wide boundary input rows at the start of the trace.  Layout:
///   0 — SQRT_M1 (used by iX, iY)
///   1 — INVSQRT_A_MINUS_D (used by enchanted)
///   2 — ZERO (used by conditional-negate IsSub `0 - a` step)
pub const N_BOUNDARY_INPUTS: usize = 3;
const ROW_BD_SQRT_M1: u16 = 0;
const ROW_BD_INVSQRT_AMD: u16 = 1;
const ROW_BD_ZERO: u16 = 2;

/// Number of rows the chip lays down per fixed-basepoint scalar-mult
/// call.  Layout (offsets within the call):
///   0..=3   — IsInput X, Y, Z, T (final Acc)
///       4   — IsInput inv_sqrt witness
///   5..=16  — 12 algebra rows (rows 1-12 of the design sketch)
///  17..=20  — 4 algebra rows (sign-check prep): T·z_inv, iX, iY,
///             enchanted = i1·INVSQRT_A_MINUS_D
///      21   — IsSignWitness for `rotate` (sign of T·z_inv at +17)
///  22..=24  — Conditional select X' = if rotate then iY else X
///  25..=27  — Conditional select Y' = if rotate then iX else Y
///  28..=30  — Conditional select den_inv =
///             if rotate then enchanted else i2
///      31   — IsMul X'·z_inv (sign source for y_negate)
///      32   — IsSignWitness for `y_negate`
///      33   — IsSub neg_y = 0 - Y'
///  34..=36  — Conditional select Y_neg =
///             if y_negate then neg_y else Y'
///      37   — IsSub Z - Y_neg
///      38   — IsMul s = den_inv · (Z - Y_neg)
///      39   — IsSignWitness for `s_neg` (sign of s)
///      40   — IsSub neg_s = 0 - s
///  41..=43  — Conditional select s_can = if s_neg then neg_s else s
pub const ROWS_PER_CALL: usize = 44;

// IsInput / algebra row offsets within a per-call block.
// Some constants are unused in current batches but consumed by later
// ones (the conditional rows in Batch 3d/3e reference rows 17/18/19/20).
#[allow(dead_code)]
const ROW_IN_X: usize = 0;
#[allow(dead_code)]
const ROW_IN_Y: usize = 1;
#[allow(dead_code)]
const ROW_IN_Z: usize = 2;
#[allow(dead_code)]
const ROW_IN_T: usize = 3;
#[allow(dead_code)]
const ROW_IN_INVSQRT: usize = 4;
#[allow(dead_code)]
const ROW_ZPY: usize = 5;
#[allow(dead_code)]
const ROW_ZMY: usize = 6;
#[allow(dead_code)]
const ROW_U1: usize = 7;
#[allow(dead_code)]
const ROW_U2: usize = 8;
#[allow(dead_code)]
const ROW_U2_SQ: usize = 9;
#[allow(dead_code)]
const ROW_TMP: usize = 10;
#[allow(dead_code)]
const ROW_INVSQRT_SQ: usize = 11;
#[allow(dead_code)]
const ROW_UNITY: usize = 12;
#[allow(dead_code)]
const ROW_I1: usize = 13;
#[allow(dead_code)]
const ROW_I2: usize = 14;
#[allow(dead_code)]
const ROW_I2_T: usize = 15;
#[allow(dead_code)]
const ROW_Z_INV: usize = 16;
#[allow(dead_code)]
const ROW_T_Z_INV: usize = 17;
#[allow(dead_code)]
const ROW_IX: usize = 18;
#[allow(dead_code)]
const ROW_IY: usize = 19;
#[allow(dead_code)]
const ROW_ENCHANTED: usize = 20;
const ROW_SIGN_ROTATE: usize = 21;
// Conditional select rows for X' / Y' / den_inv.  Each select uses
// the `out = b + flag · (a - b)` decomposition (3 rows: IsSub diff,
// IsMul scaled, IsAdd out).
#[allow(dead_code)]
const ROW_X_DIFF: usize = 22;
#[allow(dead_code)]
const ROW_X_SCALED: usize = 23;
#[allow(dead_code)]
const ROW_X_POST_ROTATE: usize = 24;
#[allow(dead_code)]
const ROW_Y_DIFF: usize = 25;
#[allow(dead_code)]
const ROW_Y_SCALED: usize = 26;
#[allow(dead_code)]
const ROW_Y_POST_ROTATE: usize = 27;
#[allow(dead_code)]
const ROW_DEN_INV_DIFF: usize = 28;
#[allow(dead_code)]
const ROW_DEN_INV_SCALED: usize = 29;
#[allow(dead_code)]
const ROW_DEN_INV: usize = 30;
#[allow(dead_code)]
const ROW_X_Z_INV: usize = 31;
const ROW_SIGN_Y_NEGATE: usize = 32;
#[allow(dead_code)]
const ROW_NEG_Y: usize = 33;
#[allow(dead_code)]
const ROW_Y_NEG_DIFF: usize = 34;
#[allow(dead_code)]
const ROW_Y_NEG_SCALED: usize = 35;
#[allow(dead_code)]
const ROW_Y_NEG: usize = 36;
#[allow(dead_code)]
const ROW_Z_MINUS_Y_NEG: usize = 37;
#[allow(dead_code)]
const ROW_S: usize = 38;
const ROW_SIGN_S_NEG: usize = 39;
#[allow(dead_code)]
const ROW_NEG_S: usize = 40;
#[allow(dead_code)]
const ROW_S_CAN_DIFF: usize = 41;
#[allow(dead_code)]
const ROW_S_CAN_SCALED: usize = 42;
#[allow(dead_code)]
const ROW_S_CAN: usize = 43;

/// Per-row column layout.  Mirrors `RistrettoFixedBaseConsumerChip`'s
/// FieldOp witness columns + source-row threading metadata.  No
/// boundary-binding metadata yet — that lands with Batch 2's later
/// sub-step (inter-chip binding to consumer chip's final Acc).
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    // ── FieldOp witness columns (mirror RistrettoChip / consumer chip) ──
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

    // ── Chip-local register-file producer multiplicity ──
    /// How many downstream FieldOp consumers reference this row's
    /// `out` (counts `a`/`b` refs across the trace).  Padding /
    /// output rows have 0.
    #[size = 1]
    ProducerMultiplicity,
    /// `producer_gate_h * producer_multiplicity` deg-flatten helper.
    #[size = 1]
    ProducerEmissionMult,

    // ── Sign-check infrastructure (Path γ) ──
    /// 1 iff this row is a sign-witness row (IsInput=1 plus
    /// extra sign-check constraints + emissions).  Boolean.
    /// On IsSignWitness rows, `FieldA` carries the source algebra
    /// row's full 32-byte `out` (so the standard chip-local
    /// register-file ConsumerA emission fires for ALL 32 bytes —
    /// matches the source row's 32-byte producer multiplicity
    /// without needing per-byte-index multiplicity differences).
    /// `FieldA[0]` is the byte whose LSB is sign-witnessed.
    #[size = 1]
    IsSignWitness,
    /// Deg-flatten helper: `consumer_a_gate_h + is_sign_witness`.
    /// Drives the ConsumerA emission's multiplicity so sign-witness
    /// rows (IsInput=1 ⇒ consumer_a_gate_h=0) still consume their
    /// `a` bytes from the source row's producer.
    #[size = 1]
    EffectiveConsumerAGateH,
    /// On IsSignWitness rows: bits 1..7 of `FieldA[0]`.  Bit 0
    /// equals `FieldOut[0]` (the sign witness on this row).
    /// Together with `FieldA[0]` and `FieldOut[0]` they form a
    /// 9-limb `ByteToBitsLookupElements` consumer tuple.
    #[size = 1]
    SignBit1,
    #[size = 1]
    SignBit2,
    #[size = 1]
    SignBit3,
    #[size = 1]
    SignBit4,
    #[size = 1]
    SignBit5,
    #[size = 1]
    SignBit6,
    #[size = 1]
    SignBit7,
    /// 1 iff this is the unity row (+12) of a call whose final
    /// accumulator is the Ristretto identity (0·G).  For the identity
    /// `tmp = u1·u2² = 0`, so no `inv_sqrt` satisfies `inv_sqrt²·tmp = 1`
    /// and the unity check must be skipped (gate `IsUnityCheck −
    /// IsIdentity`).  Bound to `tmp = 0` (the row's `b` operand) so a
    /// non-identity point cannot claim it.  Boolean; 0 on every other
    /// row.
    #[size = 1]
    IsIdentity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_comb_compress"]
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
    /// 1 iff this row is row +12 of a *real* per-call block — i.e.,
    /// `row_idx % ROWS_PER_CALL == ROW_UNITY` AND
    /// `row_idx < n_calls × ROWS_PER_CALL`.  Drives the
    /// `inv_sqrt² · (u1·u2²) = 1` integrity check whose
    /// out-byte equality is `out[0] = 1, out[1..32] = 0`.
    /// Padding rows have IsUnityCheck = 0 so the unity-check
    /// constraints are trivially satisfied there.
    #[size = 1]
    IsUnityCheck,
    /// 1 iff this row is row +43 of a *real* per-call block —
    /// the canonical-s row whose `out` (32 bytes) is the chip's
    /// final compressed Ristretto output.  Drives 32 producer
    /// emissions to `RistrettoCombCompressOutputLookupElements` so
    /// the sibling output chip can consume the bytes for memory
    /// emission.  Padding rows have IsOutputProducer = 0.
    #[size = 1]
    IsOutputProducer,
    /// Per-row call index — for row r in a real per-call block,
    /// `(r - N_BOUNDARY_INPUTS) / ROWS_PER_CALL`.  Boundary input
    /// rows + padding have CallIdx = 0.  Drives the call_idx limb
    /// of the output-binding relation tuple.
    #[size = 1]
    CallIdx,
    /// R1e-bis Batch 4b: 1 iff this row is one of the 4 IsInput
    /// X/Y/Z/T rows at the start of a real per-call block (offsets
    /// +0..+3).  Drives 32 consumer emissions per row to
    /// `RistrettoCombFinalAccLookupElements`, binding the
    /// compress chain's X/Y/Z/T inputs to the consumer chip's
    /// window-63 final-Acc producer.
    #[size = 1]
    IsCoordInputConsumer,
    /// On IsCoordInputConsumer rows: coord_kind ∈ {0=X, 1=Y, 2=Z,
    /// 3=T} matching the per-call offset (+0=X, +1=Y, +2=Z, +3=T).
    #[size = 1]
    CompressCoordKind,
}

#[cfg(feature = "prover")]
#[derive(Clone, Copy, Debug)]
struct CompressRow {
    field: crate::chips::ristretto::witness::FieldOpRow,
    /// 1 iff this row carries the sign-witness extras (Path γ).
    /// On sign-witness rows: `field.a` holds the source row's full
    /// 32-byte `out`; `field.out` is `[sign, 0, ..., 0]`.
    is_sign_witness: u8,
    /// On sign-witness rows: bits 1..7 of `field.a[0]` (bit 0
    /// equals `field.out[0]`).
    sign_bits: [u8; 7],
    /// 1 iff this is the unity row of an identity (0·G) call — drives
    /// `Column::IsIdentity` to skip the unity check (see that column's
    /// doc).  0 on every other row.
    is_identity: u8,
}

#[cfg(feature = "prover")]
impl Default for CompressRow {
    fn default() -> Self {
        Self {
            field: crate::chips::ristretto::witness::FieldOpRow::default(),
            is_sign_witness: 0,
            sign_bits: [0u8; 7],
            is_identity: 0,
        }
    }
}

/// Build the per-row witness stream for the compress chain.  Walks
/// `side_note.ristretto_comb_calls` and for each call:
///   1. Computes the running accumulator `Acc = scalar · G` via the
///      comb-table walk (mirroring the consumer chip's logic).
///   2. Calls `compute_compress_witness(&Acc)` to derive every
///      compress-chain intermediate.
///   3. Lays down the 17 per-call rows, threading source-row IDs
///      through the algebra chain.
#[cfg(feature = "prover")]
fn build_compress_rows(side_note: &SideNote) -> Vec<CompressRow> {
    use crate::chips::ristretto::comb_table::{CombTable, NUM_WINDOWS, ed25519_basepoint_extended};
    use crate::chips::ristretto::compress::{compute_compress_witness, invsqrt_a_minus_d, sqrt_m1};
    use crate::chips::ristretto::point::{ExtendedPoint, point_add_rows, point_identity};
    use crate::chips::ristretto::witness::{fill_add, fill_input, fill_mul, fill_sub};

    let mut rows: Vec<CompressRow> = Vec::new();

    // ── Chip-wide boundary inputs (rows 0..N_BOUNDARY_INPUTS) ──
    // SQRT_M1 and INVSQRT_A_MINUS_D are constants used by every
    // call's iX/iY/enchanted rows.  ZERO drives every conditional
    // negate's IsSub `0 - a` step (Batch 3e).  Push them once at
    // the trace's start; per-call rows reference them by absolute
    // row id.
    rows.push(CompressRow {
        field: fill_input(*sqrt_m1()),
        ..Default::default()
    });
    rows.push(CompressRow {
        field: fill_input(*invsqrt_a_minus_d()),
        ..Default::default()
    });
    rows.push(CompressRow {
        field: fill_input([0u8; 32]),
        ..Default::default()
    });
    debug_assert_eq!(rows.len(), N_BOUNDARY_INPUTS);

    let table = CombTable::from_base(&ed25519_basepoint_extended());

    for call in side_note.ristretto_comb_calls.iter() {
        // Re-derive Acc = scalar · G via the comb-table walk.
        let mut acc = point_identity();
        for w in 0..NUM_WINDOWS {
            let byte = call.scalar[w / 2];
            let nibble_idx = w % 2;
            let k_i = ((byte >> (nibble_idx * 4)) & 0x0F) as usize;
            let entry: ExtendedPoint = table.rows[w][k_i];
            let (_r, new_acc) = point_add_rows(&acc, &entry);
            acc = new_acc;
        }

        let w = compute_compress_witness(&acc);

        // Per-call base row id (in chip-local row numbering).
        let base = rows.len() as u16;
        let r_x = base + ROW_IN_X as u16;
        let r_y = base + ROW_IN_Y as u16;
        let r_z = base + ROW_IN_Z as u16;
        let r_t = base + ROW_IN_T as u16;
        let r_inv = base + ROW_IN_INVSQRT as u16;
        let r_zpy = base + ROW_ZPY as u16;
        let r_zmy = base + ROW_ZMY as u16;
        let r_u1 = base + ROW_U1 as u16;
        let r_u2 = base + ROW_U2 as u16;
        let r_u2sq = base + ROW_U2_SQ as u16;
        let r_tmp = base + ROW_TMP as u16;
        let r_invsq = base + ROW_INVSQRT_SQ as u16;
        let r_i1 = base + ROW_I1 as u16;
        let r_i2 = base + ROW_I2 as u16;
        let r_i2t = base + ROW_I2_T as u16;

        // ── 5 IsInput rows ──
        rows.push(CompressRow {
            field: fill_input(acc.x),
            ..Default::default()
        });
        rows.push(CompressRow {
            field: fill_input(acc.y),
            ..Default::default()
        });
        rows.push(CompressRow {
            field: fill_input(acc.z),
            ..Default::default()
        });
        rows.push(CompressRow {
            field: fill_input(acc.t),
            ..Default::default()
        });
        rows.push(CompressRow {
            field: fill_input(w.inv_sqrt),
            ..Default::default()
        });

        // ── Algebra rows 1-12 ──
        // row +5: Z + Y
        let mut fr = fill_add(acc.z, acc.y);
        fr.a_source_row = r_z;
        fr.b_source_row = r_y;
        debug_assert_eq!(fr.out, w.z_plus_y);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row +6: Z - Y
        let mut fr = fill_sub(acc.z, acc.y);
        fr.a_source_row = r_z;
        fr.b_source_row = r_y;
        debug_assert_eq!(fr.out, w.z_minus_y);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row +7: u1 = (Z+Y)·(Z-Y)
        let mut fr = fill_mul(w.z_plus_y, w.z_minus_y);
        fr.a_source_row = r_zpy;
        fr.b_source_row = r_zmy;
        debug_assert_eq!(fr.out, w.u1);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row +8: u2 = X·Y
        let mut fr = fill_mul(acc.x, acc.y);
        fr.a_source_row = r_x;
        fr.b_source_row = r_y;
        debug_assert_eq!(fr.out, w.u2);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row +9: u2² = u2·u2
        let mut fr = fill_mul(w.u2, w.u2);
        fr.a_source_row = r_u2;
        fr.b_source_row = r_u2;
        debug_assert_eq!(fr.out, w.u2_sq);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+10: tmp = u1·u2²
        let mut fr = fill_mul(w.u1, w.u2_sq);
        fr.a_source_row = r_u1;
        fr.b_source_row = r_u2sq;
        debug_assert_eq!(fr.out, w.u1_u2_sq);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+11: inv_sqrt²
        let mut fr = fill_mul(w.inv_sqrt, w.inv_sqrt);
        fr.a_source_row = r_inv;
        fr.b_source_row = r_inv;
        debug_assert_eq!(fr.out, w.inv_sqrt_sq);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+12: inv_sqrt²·tmp — equals 1 for a non-identity point,
        // 0 for the Ristretto identity (0·G, where tmp = u1·u2² = 0).
        // The unity-check constraint on this row's `out` is gated by
        // `IsUnityCheck − IsIdentity` in `add_constraints`.
        let mut fr = fill_mul(w.inv_sqrt_sq, w.u1_u2_sq);
        fr.a_source_row = r_invsq;
        fr.b_source_row = r_tmp;
        // Honest dichotomy (assertion only): tmp = 0 ⇒ identity ⇒ out = 0;
        // otherwise out = 1.
        let is_identity = w.u1_u2_sq == [0u8; 32];
        if is_identity {
            debug_assert_eq!(
                fr.out, [0u8; 32],
                "identity (0·G) unity row must have inv_sqrt²·tmp = 0"
            );
        } else {
            let one_b = {
                let mut o = [0u8; 32];
                o[0] = 1;
                o
            };
            debug_assert_eq!(fr.out, one_b, "inv_sqrt² · (u1·u2²) must equal 1");
        }
        rows.push(CompressRow {
            field: fr,
            is_identity: is_identity as u8,
            ..Default::default()
        });

        // row+13: i1 = inv_sqrt·u1
        let mut fr = fill_mul(w.inv_sqrt, w.u1);
        fr.a_source_row = r_inv;
        fr.b_source_row = r_u1;
        debug_assert_eq!(fr.out, w.i1);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+14: i2 = inv_sqrt·u2
        let mut fr = fill_mul(w.inv_sqrt, w.u2);
        fr.a_source_row = r_inv;
        fr.b_source_row = r_u2;
        debug_assert_eq!(fr.out, w.i2);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+15: i2·T
        let mut fr = fill_mul(w.i2, acc.t);
        fr.a_source_row = r_i2;
        fr.b_source_row = r_t;
        debug_assert_eq!(fr.out, w.i2_t);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+16: z_inv = i1·(i2·T)
        let mut fr = fill_mul(w.i1, w.i2_t);
        fr.a_source_row = r_i1;
        fr.b_source_row = r_i2t;
        debug_assert_eq!(fr.out, w.z_inv);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_z_inv = base + ROW_Z_INV as u16;

        // row+17: T · z_inv (sign source — its byte 0 LSB feeds the
        // rotate flag witnessed by Batch 3c's first IsSignCheck row).
        let mut fr = fill_mul(acc.t, w.z_inv);
        fr.a_source_row = r_t;
        fr.b_source_row = r_z_inv;
        debug_assert_eq!(fr.out, w.t_z_inv);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+18: iX = X · SQRT_M1
        let mut fr = fill_mul(acc.x, *sqrt_m1());
        fr.a_source_row = r_x;
        fr.b_source_row = ROW_BD_SQRT_M1;
        debug_assert_eq!(fr.out, w.i_x);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+19: iY = Y · SQRT_M1
        let mut fr = fill_mul(acc.y, *sqrt_m1());
        fr.a_source_row = r_y;
        fr.b_source_row = ROW_BD_SQRT_M1;
        debug_assert_eq!(fr.out, w.i_y);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+20: enchanted = i1 · INVSQRT_A_MINUS_D
        let mut fr = fill_mul(w.i1, *invsqrt_a_minus_d());
        fr.a_source_row = r_i1;
        fr.b_source_row = ROW_BD_INVSQRT_AMD;
        debug_assert_eq!(fr.out, w.enchanted_denominator);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // row+21: rotate sign witness — IsInput row carrying
        // `out[0] = T·z_inv.bytes[0] & 1` with `out[1..32] = 0`.
        // FieldA holds the source row's full 32-byte `out` so the
        // standard 32-byte chip-local register-file ConsumerA
        // emission balances against the source row's producer
        // multiplicity at every byte_idx (no per-byte-index
        // multiplicity asymmetry).  ByteToBits binds `FieldOut[0]`
        // to bit 0 of `FieldA[0]`.
        let r_t_z_inv = base + ROW_T_Z_INV as u16;
        let mut sign_witness_bytes = [0u8; 32];
        sign_witness_bytes[0] = w.rotate;
        debug_assert_eq!(w.rotate, w.t_z_inv[0] & 1);
        let mut fr = fill_input(sign_witness_bytes);
        // FieldA = source row's `out` (so the 32-byte ConsumerA
        // emission consumes from the source row's producer).
        fr.a = w.t_z_inv;
        fr.a_source_row = r_t_z_inv;
        let mut sign_bits = [0u8; 7];
        for k in 0..7 {
            sign_bits[k] = (w.t_z_inv[0] >> (k + 1)) & 1;
        }
        rows.push(CompressRow {
            field: fr,
            is_sign_witness: 1,
            sign_bits,
            is_identity: 0,
        });
        let r_sign_rotate = base + ROW_SIGN_ROTATE as u16;
        let r_ix = base + ROW_IX as u16;
        let r_iy = base + ROW_IY as u16;
        let r_enchanted = base + ROW_ENCHANTED as u16;
        let r_i2 = base + ROW_I2 as u16;
        // The rotate flag as a 32-byte field element: byte 0 = rotate,
        // others = 0.  Lives in the sign-witness row's `out`.
        let mut rotate_field = [0u8; 32];
        rotate_field[0] = w.rotate;

        // ── Conditional select X' = if rotate then iY else X ──
        // out = X + rotate · (iY - X)
        // row+22: IsSub diff_x = iY - X
        let mut fr = fill_sub(w.i_y, acc.x);
        fr.a_source_row = r_iy;
        fr.b_source_row = r_x;
        let diff_x = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_x_diff = base + ROW_X_DIFF as u16;
        // row+23: IsMul scaled_x = rotate · diff_x
        let mut fr = fill_mul(rotate_field, diff_x);
        fr.a_source_row = r_sign_rotate;
        fr.b_source_row = r_x_diff;
        let scaled_x = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_x_scaled = base + ROW_X_SCALED as u16;
        // row+24: IsAdd x_post_rotate = X + scaled_x
        let mut fr = fill_add(acc.x, scaled_x);
        fr.a_source_row = r_x;
        fr.b_source_row = r_x_scaled;
        debug_assert_eq!(fr.out, w.x_post_rotate);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // ── Conditional select Y' = if rotate then iX else Y ──
        // row+25: IsSub diff_y = iX - Y
        let mut fr = fill_sub(w.i_x, acc.y);
        fr.a_source_row = r_ix;
        fr.b_source_row = r_y;
        let diff_y = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_y_diff = base + ROW_Y_DIFF as u16;
        // row+26: IsMul scaled_y = rotate · diff_y
        let mut fr = fill_mul(rotate_field, diff_y);
        fr.a_source_row = r_sign_rotate;
        fr.b_source_row = r_y_diff;
        let scaled_y = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_y_scaled = base + ROW_Y_SCALED as u16;
        // row+27: IsAdd y_post_rotate = Y + scaled_y
        let mut fr = fill_add(acc.y, scaled_y);
        fr.a_source_row = r_y;
        fr.b_source_row = r_y_scaled;
        debug_assert_eq!(fr.out, w.y_post_rotate);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });

        // ── Conditional select den_inv = if rotate then enchanted else i2 ──
        // row+28: IsSub diff_d = enchanted - i2
        let mut fr = fill_sub(w.enchanted_denominator, w.i2);
        fr.a_source_row = r_enchanted;
        fr.b_source_row = r_i2;
        let diff_d = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_d_diff = base + ROW_DEN_INV_DIFF as u16;
        // row+29: IsMul scaled_d = rotate · diff_d
        let mut fr = fill_mul(rotate_field, diff_d);
        fr.a_source_row = r_sign_rotate;
        fr.b_source_row = r_d_diff;
        let scaled_d = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_d_scaled = base + ROW_DEN_INV_SCALED as u16;
        // row+30: IsAdd den_inv = i2 + scaled_d
        let mut fr = fill_add(w.i2, scaled_d);
        fr.a_source_row = r_i2;
        fr.b_source_row = r_d_scaled;
        debug_assert_eq!(fr.out, w.den_inv);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_x_post_rotate = base + ROW_X_POST_ROTATE as u16;
        let r_y_post_rotate = base + ROW_Y_POST_ROTATE as u16;
        let r_z_inv = base + ROW_Z_INV as u16;
        let r_den_inv = base + ROW_DEN_INV as u16;

        // ── row+31: X' · z_inv (sign source for y_negate) ──
        let mut fr = fill_mul(w.x_post_rotate, w.z_inv);
        fr.a_source_row = r_x_post_rotate;
        fr.b_source_row = r_z_inv;
        debug_assert_eq!(fr.out, w.x_z_inv);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_x_z_inv = base + ROW_X_Z_INV as u16;

        // ── row+32: y_negate sign witness ──
        let mut sign_witness_bytes = [0u8; 32];
        sign_witness_bytes[0] = w.y_negate_flag;
        let mut fr = fill_input(sign_witness_bytes);
        fr.a = w.x_z_inv;
        fr.a_source_row = r_x_z_inv;
        let mut sign_bits = [0u8; 7];
        for k in 0..7 {
            sign_bits[k] = (w.x_z_inv[0] >> (k + 1)) & 1;
        }
        rows.push(CompressRow {
            field: fr,
            is_sign_witness: 1,
            sign_bits,
            is_identity: 0,
        });
        let r_sign_y_negate = base + ROW_SIGN_Y_NEGATE as u16;

        // ── row+33: neg_y = 0 - Y' ──
        let mut fr = fill_sub([0u8; 32], w.y_post_rotate);
        fr.a_source_row = ROW_BD_ZERO;
        fr.b_source_row = r_y_post_rotate;
        let neg_y = fr.out;
        // Cross-check: neg_y == p - Y' (or 0 if Y' == 0).
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_neg_y = base + ROW_NEG_Y as u16;

        // ── Conditional negate Y_neg = if y_negate then neg_y else Y' ──
        // out = Y' + y_negate · (neg_y - Y')
        // row+34: IsSub diff = neg_y - Y'
        let mut fr = fill_sub(neg_y, w.y_post_rotate);
        fr.a_source_row = r_neg_y;
        fr.b_source_row = r_y_post_rotate;
        let diff_yneg = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_y_neg_diff = base + ROW_Y_NEG_DIFF as u16;
        // row+35: IsMul scaled = y_negate · diff
        let mut y_negate_field = [0u8; 32];
        y_negate_field[0] = w.y_negate_flag;
        let mut fr = fill_mul(y_negate_field, diff_yneg);
        fr.a_source_row = r_sign_y_negate;
        fr.b_source_row = r_y_neg_diff;
        let scaled_yneg = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_y_neg_scaled = base + ROW_Y_NEG_SCALED as u16;
        // row+36: IsAdd Y_neg = Y' + scaled
        let mut fr = fill_add(w.y_post_rotate, scaled_yneg);
        fr.a_source_row = r_y_post_rotate;
        fr.b_source_row = r_y_neg_scaled;
        debug_assert_eq!(fr.out, w.y_neg);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_y_neg = base + ROW_Y_NEG as u16;

        // ── row+37: Z - Y_neg ──
        let mut fr = fill_sub(acc.z, w.y_neg);
        fr.a_source_row = r_z;
        fr.b_source_row = r_y_neg;
        debug_assert_eq!(fr.out, w.z_minus_y_neg);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_z_minus_y_neg = base + ROW_Z_MINUS_Y_NEG as u16;

        // ── row+38: s = den_inv · (Z - Y_neg) ──
        let mut fr = fill_mul(w.den_inv, w.z_minus_y_neg);
        fr.a_source_row = r_den_inv;
        fr.b_source_row = r_z_minus_y_neg;
        debug_assert_eq!(fr.out, w.s);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_s = base + ROW_S as u16;

        // ── row+39: s_neg sign witness ──
        let mut sign_witness_bytes = [0u8; 32];
        sign_witness_bytes[0] = w.s_neg_flag;
        let mut fr = fill_input(sign_witness_bytes);
        fr.a = w.s;
        fr.a_source_row = r_s;
        let mut sign_bits = [0u8; 7];
        for k in 0..7 {
            sign_bits[k] = (w.s[0] >> (k + 1)) & 1;
        }
        rows.push(CompressRow {
            field: fr,
            is_sign_witness: 1,
            sign_bits,
            is_identity: 0,
        });
        let r_sign_s_neg = base + ROW_SIGN_S_NEG as u16;

        // ── row+40: neg_s = 0 - s ──
        let mut fr = fill_sub([0u8; 32], w.s);
        fr.a_source_row = ROW_BD_ZERO;
        fr.b_source_row = r_s;
        let neg_s = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_neg_s = base + ROW_NEG_S as u16;

        // ── Conditional negate s_can = if s_neg then neg_s else s ──
        // row+41: IsSub diff = neg_s - s
        let mut fr = fill_sub(neg_s, w.s);
        fr.a_source_row = r_neg_s;
        fr.b_source_row = r_s;
        let diff_scan = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_s_can_diff = base + ROW_S_CAN_DIFF as u16;
        // row+42: IsMul scaled = s_neg · diff
        let mut s_neg_field = [0u8; 32];
        s_neg_field[0] = w.s_neg_flag;
        let mut fr = fill_mul(s_neg_field, diff_scan);
        fr.a_source_row = r_sign_s_neg;
        fr.b_source_row = r_s_can_diff;
        let scaled_scan = fr.out;
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
        let r_s_can_scaled = base + ROW_S_CAN_SCALED as u16;
        // row+43: IsAdd s_can = s + scaled
        let mut fr = fill_add(w.s, scaled_scan);
        fr.a_source_row = r_s;
        fr.b_source_row = r_s_can_scaled;
        debug_assert_eq!(fr.out, w.s_can);
        rows.push(CompressRow {
            field: fr,
            ..Default::default()
        });
    }

    finalize_producer_multiplicities(&mut rows);
    rows
}

/// Walk the row stream and count downstream consumer references onto
/// each producer row's `producer_multiplicity`.  Mirrors the consumer
/// chip's algorithm — extended to also count sign-witness rows'
/// ConsumerA references (Path γ: sign-witness rows are IsInput=1 but
/// still emit ConsumerA via the chip's extended emission gate
/// `consumer_a_gate_h + is_sign_witness`).
#[cfg(feature = "prover")]
fn finalize_producer_multiplicities(rows: &mut [CompressRow]) {
    let n = rows.len();
    for cr in rows.iter_mut() {
        cr.field.producer_multiplicity = 0;
    }
    for i in 0..n {
        let row = rows[i];
        if row.field.is_real == 0 {
            continue;
        }
        // ConsumerA refs:
        //   - Algebra (IsAdd/IsSub/IsMul) + IsOutput rows (is_input=0).
        //   - Sign-witness rows (is_sign_witness=1).
        let consumes_a = row.field.is_input == 0 || row.is_sign_witness != 0;
        if consumes_a {
            let a_src = row.field.a_source_row as usize;
            if a_src < n {
                rows[a_src].field.producer_multiplicity = rows[a_src]
                    .field
                    .producer_multiplicity
                    .checked_add(1)
                    .expect("producer_multiplicity overflowed u16");
            }
        }
        // ConsumerB refs: only on IsAdd/IsSub/IsMul rows
        // (input/output/sign-witness rows have no `b`).
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

#[cfg(feature = "prover")]
fn compress_n_rows(side_note: &SideNote) -> usize {
    // Always emit the chip-wide boundary input rows, even with zero
    // calls — the FieldOp algebra still pins their final-form < p
    // closure and the chip-local register-file producer side keeps
    // a deterministic shape (consumers from per-call rows
    // 18/19 reference ROW_BD_SQRT_M1, etc.).  log_size_for handles
    // the 0-call case via the LOG_N_LANES floor.
    let n_calls = side_note.ristretto_comb_calls.len();
    if n_calls == 0 {
        return 0;
    }
    N_BOUNDARY_INPUTS + n_calls * ROWS_PER_CALL
}

impl BuiltInComponent for RistrettoCombCompressChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        RistrettoCombCompressRegFileLookupElements,
        ByteToBitsLookupElements,
        RistrettoCombCompressOutputLookupElements,
        RistrettoCombFinalAccLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            RistrettoCombCompressRegFileLookupElements,
            ByteToBitsLookupElements,
            RistrettoCombCompressOutputLookupElements,
            RistrettoCombFinalAccLookupElements,
        ),
    ) {
        let (regfile_lookup, byte_to_bits_lookup, output_lookup, final_acc_lookup) =
            lookup_elements;
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

        let producer_mult = crate::trace::trace_eval!(trace_eval, Column::ProducerMultiplicity);
        let producer_emission_mult =
            crate::trace::trace_eval!(trace_eval, Column::ProducerEmissionMult);

        let is_sign_witness = crate::trace::trace_eval!(trace_eval, Column::IsSignWitness);
        let is_identity = crate::trace::trace_eval!(trace_eval, Column::IsIdentity);
        let effective_consumer_a_gate_h =
            crate::trace::trace_eval!(trace_eval, Column::EffectiveConsumerAGateH);
        let sign_bit1 = crate::trace::trace_eval!(trace_eval, Column::SignBit1);
        let sign_bit2 = crate::trace::trace_eval!(trace_eval, Column::SignBit2);
        let sign_bit3 = crate::trace::trace_eval!(trace_eval, Column::SignBit3);
        let sign_bit4 = crate::trace::trace_eval!(trace_eval, Column::SignBit4);
        let sign_bit5 = crate::trace::trace_eval!(trace_eval, Column::SignBit5);
        let sign_bit6 = crate::trace::trace_eval!(trace_eval, Column::SignBit6);
        let sign_bit7 = crate::trace::trace_eval!(trace_eval, Column::SignBit7);

        let row_idx_lo =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexLo);
        let row_idx_hi =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexHi);
        let byte_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ByteIdx);
        let is_unity_check =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsUnityCheck);
        let is_output_producer = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::IsOutputProducer
        );
        let call_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::CallIdx);
        let is_coord_input_consumer = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::IsCoordInputConsumer
        );
        let compress_coord_kind = crate::trace::preprocessed_trace_eval!(
            trace_eval,
            PreprocessedColumn::CompressCoordKind
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

        // ProducerEmissionMult deg-flatten helper.
        eval.add_constraint(
            producer_emission_mult[0].clone()
                - producer_gate_h[0].clone() * producer_mult[0].clone(),
        );

        // ── Unity check on row +12 (`inv_sqrt² · (u1·u2²) = 1`) ──
        // The compress chain pins `inv_sqrt`'s correctness via this
        // single equality.  IsUnityCheck = 1 selects row +12 of every
        // *real* per-call block (preprocessed; padding rows have 0).
        //
        // The Ristretto identity (0·G — produced by every balanced
        // double-entry layer's zero-sum reveal, `Amount::commit(0, b)`)
        // is the one point where this check cannot hold: its final
        // accumulator is (0:λ:λ:0), so u1 = (Z+Y)(Z−Y) = 0 and u2 =
        // X·Y = 0, hence `tmp = u1·u2² = 0` and there is no inv_sqrt
        // with `inv_sqrt²·tmp = 1`.  `IsIdentity` flags that row so the
        // unity check is skipped there (gate `IsUnityCheck −
        // IsIdentity`).  This is sound: the field-op chain already
        // forces `i1 = inv_sqrt·u1 = 0` and `i2 = inv_sqrt·u2 = 0`
        // (u1=u2=0), so den_inv = 0 ⇒ s = 0 ⇒ output [0;32] (the
        // identity encoding) regardless of the witnessed inv_sqrt.
        //
        // IsIdentity ∈ {0,1}.
        eval.add_constraint(
            is_identity[0].clone() * (E::F::from(BaseField::from(1u32)) - is_identity[0].clone()),
        );
        // IsIdentity may only be set on a unity row (where `b` = tmp).
        eval.add_constraint(
            (E::F::from(BaseField::from(1u32)) - is_unity_check[0].clone())
                * is_identity[0].clone(),
        );
        // Soundness binding: IsIdentity = 1 forces `tmp` (= u1·u2², the
        // unity row's `b` operand) to 0 byte-wise.  Because the field-op
        // chain binds `b` to the actual accumulator's (Z+Y)(Z−Y)·(X·Y)²,
        // a *non*-identity point (tmp ≠ 0) cannot claim IsIdentity, so
        // it cannot skip the unity check and forge a [0;32] output.
        for k in 0..32 {
            eval.add_constraint(is_identity[0].clone() * b[k].clone());
        }
        // Unity check, gated by `(IsUnityCheck − IsIdentity)`: active on
        // every real non-identity unity row, skipped on the identity
        // row (gate 0).  Constraint set: `out[0] = 1, out[1..32] = 0`
        // mod p25519.  Output of an IsMul row is already canonical ∈
        // [0, p) by the FieldOp helper's final-form < p chain, so the
        // bytewise equality with [1, 0, ..., 0] uniquely identifies the
        // field element 1.
        let unity_gate = is_unity_check[0].clone() - is_identity[0].clone();
        eval.add_constraint(
            unity_gate.clone() * (out[0].clone() - E::F::from(BaseField::from(1u32))),
        );
        for k in 1..32 {
            eval.add_constraint(unity_gate.clone() * out[k].clone());
        }

        // ── Sign-witness rows (Path γ) ──
        // IsSignWitness ∈ {0, 1}.
        eval.add_constraint(
            is_sign_witness[0].clone()
                * (E::F::from(BaseField::from(1u32)) - is_sign_witness[0].clone()),
        );
        // Sign-witness rows are also IsInput rows (so the FieldOp
        // partition's `is_real · (is_input - 1) = 0` clause is
        // satisfied without any helper changes).
        eval.add_constraint(
            is_sign_witness[0].clone() * (E::F::from(BaseField::from(1u32)) - is_input[0].clone()),
        );
        // Higher bytes of `out` zero on sign-witness rows.  Together
        // with `out[0] ∈ {0, 1}` (from the ByteToBits consumer), this
        // ensures the row's `out` is a clean boolean field element.
        for k in 1..32 {
            eval.add_constraint(is_sign_witness[0].clone() * out[k].clone());
        }
        // EffectiveConsumerAGateH = consumer_a_gate_h + is_sign_witness.
        // Both addends are boolean and mutually exclusive (sign-witness
        // rows have is_input=1 ⇒ consumer_a_gate_h=0; algebra rows have
        // is_sign_witness=0), so the sum is also boolean.
        eval.add_constraint(
            effective_consumer_a_gate_h[0].clone()
                - consumer_a_gate_h[0].clone()
                - is_sign_witness[0].clone(),
        );

        // ── Chip-local register-file producer + consumer A/B ──
        for k in 0..32 {
            // Producer: emit `producer_emission_mult` × tuple per byte
            // on every IsInput / IsAdd / IsSub / IsMul row.
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
            // Consumer A: emit `-effective_consumer_a_gate_h` per
            // byte.  Fires on IsAdd / IsSub / IsMul rows AND on
            // sign-witness rows (Path γ extension).
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                (-effective_consumer_a_gate_h[0].clone()).into(),
                &[
                    a_src_lo[0].clone(),
                    a_src_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    a[k].clone(),
                ],
            ));
            // Consumer B: emit `-consumer_b_gate_h` per byte on
            // IsAdd / IsSub / IsMul rows.  IsInput / IsOutput rows
            // have no `b` so the gate is 0 there.
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

        // ── Sign-witness emissions (Path γ) ──
        // ByteToBits consumer: `(FieldA[0], FieldOut[0], SignBit1..7)`
        // — multiplicity `+IsSignWitness` matches ByteToBitsChip's
        // `-multiplicity[byte]` producer (ByteToBitsChip writes its
        // multiplicity from `side_note.byte_to_bits_counts[byte]`,
        // which `populate_ristretto_compress_counts` increments per
        // sign-witness row).  Forces `FieldOut[0]` to equal bit 0 of
        // `FieldA[0]` (and binds the higher bits to SignBit1..7,
        // which we don't otherwise use — they stay as zeroed padding
        // cells when IsSignWitness=0).  The
        // 1-byte register-file consumer at byte_idx=0 is no longer
        // needed: FieldA's bytes are already bound to the source
        // row's `out` via the standard 32-byte ConsumerA emission
        // (gated by `effective_consumer_a_gate_h`).
        eval.add_to_relation(RelationEntry::new(
            byte_to_bits_lookup,
            is_sign_witness[0].clone().into(),
            &[
                a[0].clone(),
                out[0].clone(),
                sign_bit1[0].clone(),
                sign_bit2[0].clone(),
                sign_bit3[0].clone(),
                sign_bit4[0].clone(),
                sign_bit5[0].clone(),
                sign_bit6[0].clone(),
                sign_bit7[0].clone(),
            ],
        ));

        // ── Output producer emissions (Batch 4a) ──
        // On row +43 of every real per-call block (gated by
        // IsOutputProducer), emit 32 producer tuples
        // `(call_idx, byte_idx, out[k])` to the new
        // `RistrettoCombCompressOutputLookupElements` relation.
        // The sibling `RistrettoCombCompressOutputChip` consumes
        // these tuples (one per byte) and re-emits the byte values
        // as MemoryAccess producers at `(output_ptr+k, byte, ts,
        // is_write=1)`, binding the actor's PVM-memory output to
        // the canonical s_can computed in-circuit.
        for k in 0..32 {
            eval.add_to_relation(RelationEntry::new(
                output_lookup,
                is_output_producer[0].clone().into(),
                &[
                    call_idx_pp[0].clone(),
                    byte_idx_pp[k].clone(),
                    out[k].clone(),
                ],
            ));
        }

        // ── Final-Acc cross-chip consumer emissions (Batch 4b) ──
        // On the 4 IsInput rows for X/Y/Z/T (offsets +0..+3 of
        // each per-call block, gated by IsCoordInputConsumer), emit
        // 32 consumer tuples `(call_idx, coord_kind, byte_idx,
        // out[k])` to `RistrettoCombFinalAccLookupElements`.
        // Producer side lives in `RistrettoFixedBaseConsumerChip`
        // (Batch 4b) — its window-63 final-Acc rows emit the
        // matching tuples.  Balance forces the compress chain's
        // X/Y/Z/T inputs to equal the comb chain's window-63 final
        // accumulator coords, closing the X/Y/Z/T cross-chip
        // soundness gap.
        for k in 0..32 {
            eval.add_to_relation(RelationEntry::new(
                final_acc_lookup,
                (-is_coord_input_consumer[0].clone()).into(),
                &[
                    call_idx_pp[0].clone(),
                    compress_coord_kind[0].clone(),
                    byte_idx_pp[k].clone(),
                    out[k].clone(),
                ],
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoCombCompressChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let log_size = log_size_for(compress_n_rows(side_note));
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        let real_n_rows = compress_n_rows(side_note);
        for row in 0..num_rows {
            let row_lo = (row & 0xff) as u8;
            let row_hi = ((row >> 8) & 0xff) as u8;
            trace.fill_columns(row, row_lo, PreprocessedColumn::RowIndexLo);
            trace.fill_columns(row, row_hi, PreprocessedColumn::RowIndexHi);
            let byte_idx_arr: [u8; 32] = core::array::from_fn(|k| k as u8);
            trace.fill_columns_bytes(row, &byte_idx_arr, PreprocessedColumn::ByteIdx);
            // Per-call blocks start at offset N_BOUNDARY_INPUTS.  Row
            // is a unity check iff it sits at the unity offset within
            // a real per-call block — guards on (a) being beyond the
            // boundary inputs, (b) within the real-row range, and
            // (c) at the per-call-block-relative ROW_UNITY position.
            let in_call_block = row >= N_BOUNDARY_INPUTS && row < real_n_rows;
            let per_call_offset = if in_call_block {
                Some((row - N_BOUNDARY_INPUTS) % ROWS_PER_CALL)
            } else {
                None
            };
            let is_unity = per_call_offset == Some(ROW_UNITY);
            trace.fill_columns(row, is_unity as u8, PreprocessedColumn::IsUnityCheck);
            let is_output_producer = per_call_offset == Some(ROW_S_CAN);
            trace.fill_columns(
                row,
                is_output_producer as u8,
                PreprocessedColumn::IsOutputProducer,
            );
            let call_idx = if in_call_block {
                ((row - N_BOUNDARY_INPUTS) / ROWS_PER_CALL) as u8
            } else {
                0
            };
            trace.fill_columns(row, call_idx, PreprocessedColumn::CallIdx);
            // IsCoordInputConsumer + CompressCoordKind: 1 on the 4
            // IsInput X/Y/Z/T rows at offsets +0..+3 of real
            // per-call blocks.
            let (is_coord_input_consumer, coord_kind) = match per_call_offset {
                Some(o) if o < 4 => (1u8, o as u8),
                _ => (0u8, 0u8),
            };
            trace.fill_columns(
                row,
                is_coord_input_consumer,
                PreprocessedColumn::IsCoordInputConsumer,
            );
            trace.fill_columns(row, coord_kind, PreprocessedColumn::CompressCoordKind);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let rows = build_compress_rows(side_note);
        let log_size = log_size_for(rows.len());
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        for row_i in 0..num_rows {
            let cr = rows.get(row_i).copied().unwrap_or_default();
            fill_compress_row(&mut trace, row_i, &cr);
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

        let regfile: &RistrettoCombCompressRegFileLookupElements = lookup_elements.as_ref();
        let byte_to_bits: &ByteToBitsLookupElements = lookup_elements.as_ref();
        let output_relation: &RistrettoCombCompressOutputLookupElements = lookup_elements.as_ref();
        let final_acc_relation: &RistrettoCombFinalAccLookupElements = lookup_elements.as_ref();

        let row_idx_lo_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::RowIndexLo
        );
        let is_output_producer_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::IsOutputProducer
        );
        let call_idx_pp_col =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::CallIdx);
        let is_coord_input_consumer_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::IsCoordInputConsumer
        );
        let compress_coord_kind_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::CompressCoordKind
        );
        let row_idx_hi_pp = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::RowIndexHi
        );
        let byte_idx_pp =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::ByteIdx);
        let producer_emission_mult =
            crate::trace::original_base_column!(component_trace, Column::ProducerEmissionMult);
        // ConsumerAGateH is read in `add_constraints` to derive
        // `EffectiveConsumerAGateH = ConsumerAGateH + IsSignWitness`, but the
        // interaction trace below only emits via `EffectiveConsumerAGateH`,
        // not the raw column.
        let consumer_b_gate_h =
            crate::trace::original_base_column!(component_trace, Column::ConsumerBGateH);
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

        let is_sign_witness_col =
            crate::trace::original_base_column!(component_trace, Column::IsSignWitness);
        let effective_consumer_a_gate_h_col =
            crate::trace::original_base_column!(component_trace, Column::EffectiveConsumerAGateH);
        let sign_bit1_col = crate::trace::original_base_column!(component_trace, Column::SignBit1);
        let sign_bit2_col = crate::trace::original_base_column!(component_trace, Column::SignBit2);
        let sign_bit3_col = crate::trace::original_base_column!(component_trace, Column::SignBit3);
        let sign_bit4_col = crate::trace::original_base_column!(component_trace, Column::SignBit4);
        let sign_bit5_col = crate::trace::original_base_column!(component_trace, Column::SignBit5);
        let sign_bit6_col = crate::trace::original_base_column!(component_trace, Column::SignBit6);
        let sign_bit7_col = crate::trace::original_base_column!(component_trace, Column::SignBit7);

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
                [effective_consumer_a_gate_h_col[0].clone()],
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

        // ── Sign-witness emissions ──
        // ByteToBits consumer: `(FieldA[0], FieldOut[0], SignBit1..7)`.
        // Multiplicity +IsSignWitness; the 32-byte ConsumerA above
        // already binds FieldA to the source row's `out`.
        logup.add_to_relation_with(
            byte_to_bits,
            [is_sign_witness_col[0].clone()],
            |[g]| g.into(),
            &[
                a_cols[0].clone(),
                out_cols[0].clone(),
                sign_bit1_col[0].clone(),
                sign_bit2_col[0].clone(),
                sign_bit3_col[0].clone(),
                sign_bit4_col[0].clone(),
                sign_bit5_col[0].clone(),
                sign_bit6_col[0].clone(),
                sign_bit7_col[0].clone(),
            ],
        );

        // ── Output producer emissions ──
        for k in 0..32 {
            logup.add_to_relation_with(
                output_relation,
                [is_output_producer_pp[0].clone()],
                |[g]| g.into(),
                &[
                    call_idx_pp_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    out_cols[k].clone(),
                ],
            );
        }

        // ── Final-Acc cross-chip consumer emissions ──
        for k in 0..32 {
            logup.add_to_relation_with(
                final_acc_relation,
                [is_coord_input_consumer_pp[0].clone()],
                |[g]| (-g).into(),
                &[
                    call_idx_pp_col[0].clone(),
                    compress_coord_kind_pp[0].clone(),
                    byte_idx_pp[k].clone(),
                    out_cols[k].clone(),
                ],
            );
        }

        logup.finalize()
    }
}

#[cfg(feature = "prover")]
fn fill_compress_row(trace: &mut TraceBuilder<Column>, row_i: usize, cr: &CompressRow) {
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

    // Producer multiplicity + emission helper.
    let pm: u32 = r.producer_multiplicity as u32;
    trace.fill_columns(row_i, BaseField::from(pm), Column::ProducerMultiplicity);
    let emission = if real_b && !out_b { pm } else { 0 };
    trace.fill_columns(
        row_i,
        BaseField::from(emission),
        Column::ProducerEmissionMult,
    );

    // Sign-witness columns (Path γ).
    trace.fill_columns(row_i, cr.is_sign_witness, Column::IsSignWitness);
    // EffectiveConsumerAGateH = consumer_a_gate_h + is_sign_witness.
    // consumer_a_gate_h = real · (1 - is_input).
    let consumer_a_gate = (real_b && !inp_b) as u8;
    trace.fill_columns(
        row_i,
        consumer_a_gate + cr.is_sign_witness,
        Column::EffectiveConsumerAGateH,
    );
    trace.fill_columns(row_i, cr.sign_bits[0], Column::SignBit1);
    trace.fill_columns(row_i, cr.sign_bits[1], Column::SignBit2);
    trace.fill_columns(row_i, cr.sign_bits[2], Column::SignBit3);
    trace.fill_columns(row_i, cr.sign_bits[3], Column::SignBit4);
    trace.fill_columns(row_i, cr.sign_bits[4], Column::SignBit5);
    trace.fill_columns(row_i, cr.sign_bits[5], Column::SignBit6);
    trace.fill_columns(row_i, cr.sign_bits[6], Column::SignBit7);
    trace.fill_columns(row_i, cr.is_identity, Column::IsIdentity);
}

/// task #7 soundness: the `IsIdentity` gate must NOT be a free pass.
/// A malicious prover could try to skip the unity check for a
/// *non*-identity point (witnessing `inv_sqrt = 0` to forge a `[0;32]`
/// output) by flipping `IsIdentity = 1`.  The C4 constraint
/// `IsIdentity · b[k] = 0` (b = tmp = u1·u2², bound to the real point
/// by the field-op chain) makes that impossible: for a non-identity
/// point tmp ≠ 0, so `1 · tmp ≠ 0` and the AssertEvaluator rejects.
///
/// This test tampers the honest trace directly (the only way to reach
/// the adversarial column assignment, since honest trace-gen sets
/// `IsIdentity = (tmp == 0)`) and confirms the constraint has teeth.
#[cfg(all(test, feature = "debug-internals"))]
mod identity_gate_soundness {
    use super::{Column, PreprocessedColumn, RistrettoCombCompressChip};
    use crate::air_column::AirColumn;
    use crate::core::tracing::{RistrettoMemOp, ScalarMultKind};
    use crate::framework::{MachineComponent, MachineProverComponent};
    use crate::lookups::AllLookupElements;
    use crate::side_note::{RistrettoCombCall, SideNote};
    use crate::trace::component::ComponentTrace;
    use stwo::core::channel::Blake2sChannel;
    use stwo::core::fields::m31::BaseField;

    /// Single non-identity `scalar·G` comb call routed onto the
    /// compress path (mirrors `harness_ristretto_fixed_base_e2e`).
    fn non_identity_side_note() -> SideNote {
        let scalar_value = curve25519_dalek::scalar::Scalar::from(0x1234_5678u64);
        let scalar = scalar_value.to_bytes();
        let basepoint = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        let out_bytes = (scalar_value * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let mut sn = SideNote::new(Vec::new(), Vec::new(), Vec::new());
        let mut initial_memory = vec![0u8; 256];
        initial_memory[0..32].copy_from_slice(&scalar);
        initial_memory[64..96].copy_from_slice(&basepoint);
        sn.initial_memory = initial_memory;
        sn.ristretto_mem_ops.push(RistrettoMemOp {
            scalar_ptr: 0,
            point_ptr: 64,
            output_ptr: 128,
            ts: 1,
            scalar_bytes: scalar,
            point_bytes: basepoint,
            out_bytes,
            kind: ScalarMultKind::FixedBasepoint,
        });
        sn.ristretto_comb_calls.push(RistrettoCombCall {
            scalar,
            out_bytes,
            output_ptr: 128,
            ts: 1,
        });
        sn.populate_ristretto_comb_counts();
        sn.populate_ristretto_compress_counts();
        sn
    }

    /// Row-by-row `AssertEvaluator` over the compress chip's trace.
    /// Ok(()) if all constraints hold; Err(msg) on the first violation.
    fn assert_compress(trace: &ComponentTrace, side_note: &SideNote) -> Result<(), String> {
        let chip = RistrettoCombCompressChip;
        let mut lookup_elements = AllLookupElements::default();
        let channel = &mut Blake2sChannel::default();
        chip.draw_lookup_elements(&mut lookup_elements, channel);
        let (interaction_trace, claimed_sum) =
            chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
        }))
        .map_err(|p| {
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".into())
        })
    }

    #[test]
    fn is_identity_flag_on_non_identity_point_is_rejected() {
        let mut side_note = non_identity_side_note();
        let chip = RistrettoCombCompressChip;
        let mut trace = chip.generate_component_trace(&mut side_note);

        // Locate the (single) unity row via the preprocessed selector.
        let unity_off = PreprocessedColumn::IsUnityCheck.offset();
        let unity_row = {
            let col = trace.preprocessed_trace[unity_off].as_slice();
            (0..col.len())
                .find(|&r| col[r] == BaseField::from(1u32))
                .expect("a real call must have exactly one unity row")
        };

        let id_off = Column::IsIdentity.offset();
        let b_off = Column::FieldB.offset();

        // Sanity: honest fill leaves IsIdentity = 0 here, and the
        // unity row carries tmp = u1·u2² ≠ 0 (non-identity point).
        assert_eq!(
            trace.original_trace[id_off].as_slice()[unity_row],
            BaseField::from(0u32),
            "honest non-identity unity row must have IsIdentity = 0"
        );
        let tmp_nonzero = (0..32).any(|k| {
            trace.original_trace[b_off + k].as_slice()[unity_row] != BaseField::from(0u32)
        });
        assert!(
            tmp_nonzero,
            "non-identity unity row must carry tmp = u1·u2² ≠ 0 (test setup)"
        );

        // Control: the honest trace satisfies every constraint.
        assert_compress(&trace, &side_note)
            .expect("honest non-identity compress trace must satisfy all constraints");

        // Attack: claim IsIdentity = 1 to skip the unity check.
        trace.original_trace[id_off].as_mut_slice()[unity_row] = BaseField::from(1u32);
        let res = assert_compress(&trace, &side_note);
        assert!(
            res.is_err(),
            "C4 soundness hole: IsIdentity = 1 on a non-identity unity row (tmp ≠ 0) \
             was accepted — a prover could forge a [0;32] output for a real point"
        );
    }
}
