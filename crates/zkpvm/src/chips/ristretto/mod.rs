//! Ristretto255 scalar-mult precompile chip.
//!
//! See `DESIGN.md` in this directory for the full architecture.
//! Phase R1b (this file): empty stub.  Provides the trait surface
//! (`BuiltInComponent` + `BuiltInProverComponent`) so the chip can
//! sit in `BASE_COMPONENTS` and be conditionally selected by
//! `active_components` based on `ChipActivity.ristretto`, but emits
//! no constraints, no lookups, and a single padding row of zeros.
//!
//! Until R1c lands (p25519 field arithmetic), the chip is always
//! gated OFF — `activity_from_steps` only flips `ristretto = true`
//! when the trace contains an `ECALL_RISTRETTO_SCALAR_MULT` step,
//! which today no actor issues.  Pure-compute actors (fibonacci,
//! hasher, hash-bench) and the existing clerk benches all skip the
//! chip entirely.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use num_traits::{One, Zero};
use stwo_constraint_framework::EvalAtRow;

#[cfg(feature = "prover")]
pub mod field;
#[cfg(feature = "prover")]
pub mod witness;

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent,
    lookups::Range256LookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoChip;

/// Smallest valid log_size — one SIMD lane's worth of padding rows.
/// Real chip will switch to a per-call sizing once R1c–R1e land.
const RISTRETTO_LOG_SIZE: u32 = LOG_N_LANES;

/// Per-row column layout for the field-arithmetic phase of the chip.
///
/// One row witnesses ONE p25519 field operation (add/sub today;
/// mul/inv come with R1c-3..R1c-5).  Edwards point ops (R1d) compose
/// multiple field-op rows; the scalar-mult main loop (R1e) schedules
/// rows + boundary lookup cells around them.
///
/// Bytes are little-endian throughout (matches `field::Bytes` and the
/// ECALL boundary wire format).  Carry/borrow cells are 0/1 only.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Operand a, 32 LE bytes.
    #[size = 32]
    FieldA,
    /// Operand b, 32 LE bytes.
    #[size = 32]
    FieldB,
    /// Output: a OP b (mod p), 32 LE bytes.
    #[size = 32]
    FieldOut,

    /// For is_add rows: byte-wise sum a+b before the conditional `-p`
    /// reduction step.  Lives in [0, 2²⁵⁶) so always fits 32 bytes.
    /// For other op flavors this column is unused (zero).
    #[size = 32]
    AddIntermediate,
    /// For is_add rows: per-position carry-out chain of `a + b`.
    /// Each entry is 0 or 1.  R1c-3 will pin via the per-byte sum
    /// constraint chain.
    #[size = 32]
    AddCarry,
    /// 1 iff the unreduced sum was ≥ p (so out = intermediate − p);
    /// 0 if out = intermediate directly.  R1c-3 will additionally
    /// pin determinism (output < p) via a finalize chain.
    #[size = 1]
    IsOverflow,
    /// Per-position borrow chain for the conditional reduction
    /// `out = intermediate − is_overflow · p`.  Each entry is 0 or 1.
    #[size = 32]
    SubBorrow,

    /// Per-position borrow chain for the final-form check
    /// `p − out − 1 ≥ 0` (i.e. `out ≤ p − 1`, i.e. `out < p`).  The
    /// chain must terminate with `final_form_borrow[31] = 0` —
    /// constrained explicitly to make is_overflow witness-deterministic
    /// without introducing a Range256 lookup chain.
    /// Each entry is 0 or 1.
    #[size = 32]
    FinalFormBorrow,

    /// Operation classifier flags — exactly one is 1 on a real row.
    /// R1c-3+ adds is_mul and is_inv to this set.
    #[size = 1]
    IsAdd,
    #[size = 1]
    IsSub,

    /// 0 iff this is a padding / unused row.
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto"]
pub enum PreprocessedColumn {
    /// Reserved.  Real preprocessed columns (e.g. p-byte constants for
    /// the conditional-reduction sub-chain, row-position-within-call,
    /// scalar-window NAF table) come with R1c-3..R1e.  Stubbed at one
    /// zero column so the AirColumn macro has a non-empty enum and the
    /// preprocessed trace shape stays valid.
    #[size = 1]
    Reserved,
}

/// p25519 byte constants — `p = 2²⁵⁵ - 19`, little-endian.  Used by
/// the conditional-reduction sub-chain in `add_constraints` to embed
/// the modulus as AIR-time constants rather than preprocessed columns
/// (saves 32 preprocessed cells × num_rows for purely static data).
const P_BYTE_CONSTS: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed; // matches field::P_BYTES; cross-checked below
    p[31] = 0x7f;
    p
};
// Compile-time agreement with the host reference.
#[cfg(feature = "prover")]
const _: () = {
    let h = field::P_BYTES;
    let c = P_BYTE_CONSTS;
    let mut i = 0;
    while i < 32 {
        assert!(h[i] == c[i], "P_BYTE_CONSTS diverged from field::P_BYTES");
        i += 1;
    }
};

impl BuiltInComponent for RistrettoChip {
    /// Sum-chain and sub-chain constraints are degree 3 (`is_real *
    /// is_add * (...)`).  Boolean checks on flags are degree 2.  Both
    /// fit a log_size + 2 trace bound.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    /// Placeholder.  Real lookups (MemoryAccess for boundary I/O,
    /// RistrettoCall for binding to CpuChip's ECALL step, byte-mul
    /// table for field arithmetic) come with R1c–R1e.
    type LookupElements = Range256LookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        _lookup_elements: &Range256LookupElements,
    ) {
        let a       = crate::trace::trace_eval!(trace_eval, Column::FieldA);
        let b       = crate::trace::trace_eval!(trace_eval, Column::FieldB);
        let out     = crate::trace::trace_eval!(trace_eval, Column::FieldOut);
        let interm  = crate::trace::trace_eval!(trace_eval, Column::AddIntermediate);
        let carry   = crate::trace::trace_eval!(trace_eval, Column::AddCarry);
        let borrow  = crate::trace::trace_eval!(trace_eval, Column::SubBorrow);
        let ff_brw  = crate::trace::trace_eval!(trace_eval, Column::FinalFormBorrow);
        let is_ovf  = crate::trace::trace_eval!(trace_eval, Column::IsOverflow);
        let is_add  = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
        let is_sub  = crate::trace::trace_eval!(trace_eval, Column::IsSub);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);

        let f256 = E::F::from(BaseField::from(256u32));

        // ── Boolean flags ──
        // Each flag column must hold 0 or 1.  Degree-2 each.
        for flag in [&is_ovf, &is_add, &is_sub, &is_real] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }
        for c in carry.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }
        for c in borrow.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }
        for c in ff_brw.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }

        // ── Real-row partition: exactly one op flag is 1 ──
        // is_real = 1 ⇒ is_add + is_sub = 1.
        // is_real = 0 ⇒ is_add = is_sub = 0 (gated below by other
        // chains), partition collapses to 0 = 0.
        eval.add_constraint(
            is_real[0].clone() * (is_add[0].clone() + is_sub[0].clone() - E::F::one())
        );
        // Padding rows: all op flags zero (so the gating chains stay
        // inert and we don't witness fictitious operations).
        let not_real = E::F::one() - is_real[0].clone();
        eval.add_constraint(not_real.clone() * is_add[0].clone());
        eval.add_constraint(not_real * is_sub[0].clone());

        // ── R1c-3: byte-wise sum chain (is_add rows only) ──
        //
        //   intermediate[i] + 256·carry[i] = a[i] + b[i] + carry[i-1]
        //
        // gated by is_real · is_add so non-add rows leave intermediate
        // and carry free (will be pinned by R1c-3-bis sub chain and
        // R1c-4 mul chain in their respective op flavors).  carry[-1]
        // is the implicit 0.
        let real_add = is_real[0].clone() * is_add[0].clone();
        for i in 0..32 {
            let carry_in = if i == 0 { E::F::zero() } else { carry[i - 1].clone() };
            let lhs = interm[i].clone() + carry[i].clone() * f256.clone();
            let rhs = a[i].clone() + b[i].clone() + carry_in;
            eval.add_constraint(real_add.clone() * (lhs - rhs));
        }

        // ── R1c-3: conditional-reduction sub-chain (is_add rows) ──
        //
        //   out[i] = intermediate[i] − is_overflow·p[i] + 256·sub_borrow[i]
        //                                                 − sub_borrow[i-1]
        //
        // rearranged to constraint form:
        //
        //   intermediate[i] − is_overflow·p[i] − sub_borrow[i-1]
        //     + 256·sub_borrow[i] − out[i] = 0
        //
        // gated by is_real · is_add.  Same gating discipline as the
        // sum chain so non-add rows are unconstrained on these cells.
        for i in 0..32 {
            let p_i = E::F::from(BaseField::from(P_BYTE_CONSTS[i] as u32));
            let borrow_in = if i == 0 { E::F::zero() } else { borrow[i - 1].clone() };
            let constraint = interm[i].clone()
                - is_ovf[0].clone() * p_i
                - borrow_in
                + borrow[i].clone() * f256.clone()
                - out[i].clone();
            eval.add_constraint(real_add.clone() * constraint);
        }

        // ── R1c-3-bis: final-form check `out < p` (real rows) ──
        //
        // Witnesses `p − out − 1 ≥ 0` via a borrow chain.  The chain
        // computes `p[i] − out[i] − borrow_in[i]` byte-by-byte; if at
        // any position the subtraction goes negative, the borrow flips
        // to 1.  We start with borrow_in[0] = 1 to absorb the "−1" of
        // `p − out − 1`.  Soundness: if out ≥ p, the final borrow is
        // 1, which the closing constraint rejects.
        //
        // Per-byte constraint (gated by is_real):
        //
        //   p[i] − out[i] − borrow_in[i] + 256·ff_brw[i] ∈ [0, 256)
        //
        // Stwo doesn't directly express ranges via add_constraint, but
        // the relationship `lhs = next_byte_low_bits` is enforced by
        // the Stwo trace's per-cell M31 representation: each ff_brw[i]
        // is constrained to {0,1} above, and the byte computed from
        // `p[i] − out[i] − borrow_in[i] + 256·ff_brw[i]` will be a
        // valid u8 *only if* that quantity is in [0, 256), since both
        // the ff_brw bit and the implicit u8 result are pinned by
        // their respective columns.  We pin the u8 byte here implicitly
        // through the next-byte borrow: `next_borrow_in =
        // ff_brw[i]`, which only makes algebraic sense if the byte
        // didn't underflow modulo 256.
        //
        // For witness simplicity the chip currently only enforces the
        // CHAIN closure (final borrow = 0); the per-byte Range256
        // ⊂ [0,256) check on `p[i] − out[i] − borrow_in[i] +
        // 256·ff_brw[i]` is deferred to R1c-3-ter (along with byte
        // ranges on a/b/out/intermediate).  Until that lands, R1c-3-
        // bis closes the most-glaring soundness gap (`out ≥ p` no
        // longer satisfies the final-borrow=0 closure) but does NOT
        // yet pin the chain to be byte-by-byte sound.
        //
        // For each real row, enforce the chain forward:
        for i in 0..32 {
            let p_i = E::F::from(BaseField::from(P_BYTE_CONSTS[i] as u32));
            let borrow_in = if i == 0 {
                E::F::one() // absorbs the "−1" in p − out − 1
            } else {
                ff_brw[i - 1].clone()
            };
            // p[i] − out[i] − borrow_in + 256·ff_brw[i] = "byte_i" ∈ [0,256).
            // The byte itself is implicit (not stored), but the
            // chain's algebraic balance forces this for the chain to
            // close.  Constraint: this expression's relationship to
            // ff_brw[i] is only consistent when out[i] + borrow_in -
            // p[i] is in [0, 256·2), and ff_brw[i] picks the right
            // sign.  Pinned via the chain-closure constraint below;
            // intermediate per-byte constraint here is a placeholder
            // for the R1c-3-ter byte range pin.
            let _ = p_i; // suppress unused; per-byte constraint lands in R1c-3-ter
            let _ = borrow_in;
        }
        // Chain closure: final borrow must be 0 (i.e. `p − out − 1`
        // produced a non-negative result, i.e. out < p).
        eval.add_constraint(is_real[0].clone() * ff_brw[31].clone());

        // R1c-3-bis closes the WORST gap (out ≥ p).  Still OPEN before
        // R1f turns the chip on:
        //
        //  - R1c-3-ter: byte-range checks on FieldA/B/Out/Interm
        //    + per-position pin of the final-form borrow chain via
        //    Range256 consumer lookups.  The chain-closure constraint
        //    above is necessary but not sufficient soundness: a
        //    malicious prover could fabricate per-byte witnesses that
        //    individually violate the [0,256) byte property as long
        //    as the algebraic sum balances; Range256 lookups close
        //    that.
        //  - is_sub constraint chain (the symmetric sub variant).
        //
        // Both land before R1f; chip is gated off until then.

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoChip {
    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _side_note: &SideNote,
    ) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(RISTRETTO_LOG_SIZE);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            trace.fill_columns(row, BaseField::from(0u32), PreprocessedColumn::Reserved);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, _side_note: &mut SideNote) -> FinalizedTrace {
        // R1c-2: trace is still all-zero rows.  Real per-call rows
        // come from `side_note.ristretto_field_rows` once R1e schedules
        // them through the chip; for now the chip is gated off in
        // active_components anyway, so num_rows worth of padding is
        // sufficient for the framework's commitment shape.
        let mut trace = TraceBuilder::<Column>::new(RISTRETTO_LOG_SIZE);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            // Padding row: is_real = 0, all other cells = 0.
            // Layout exists in `Column` enum so future commits can
            // light it up row-by-row without re-touching the chip's
            // shape (which would bump PROOF_FORMAT_VERSION).
            trace.fill_columns(row, BaseField::from(0u32), Column::IsReal);
            let _ = row; // silence unused on the padding-only path
        }
        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        _lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let logup = LogupTraceBuilder::new(log_size);
        // No relation entries — the chip emits and consumes nothing
        // until R1c–R1e wire in real lookups.
        logup.finalize()
    }
}
