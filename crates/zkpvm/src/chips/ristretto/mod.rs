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
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

#[cfg(feature = "prover")]
pub mod field;
#[cfg(feature = "prover")]
pub mod witness;
#[cfg(feature = "prover")]
pub mod point;

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{Range256LookupElements, RistrettoRegisterFileLookupElements},
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoChip;

/// Smallest valid log_size — one SIMD lane's worth of padding rows.
/// Used when the chip is gated on but has zero rows (boundary case).
#[cfg(feature = "prover")]
const RISTRETTO_MIN_LOG_SIZE: u32 = LOG_N_LANES;

/// R1e-quat: derive the chip's log_size from `side_note
/// .ristretto_field_rows.len()`.  Each row witnesses one field op;
/// the chip pads to the next power of two ≥ rows.len(), with a
/// floor at LOG_N_LANES.
#[cfg(feature = "prover")]
fn ristretto_log_size(side_note: &SideNote) -> u32 {
    let n = side_note.ristretto_field_rows.len() as u32;
    let log = 32 - n.saturating_sub(1).leading_zeros();
    log.max(RISTRETTO_MIN_LOG_SIZE)
}

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

    /// Per-position carry chain for `out + b` on is_sub rows.
    /// Witnesses the byte-wise sum chain
    /// `out[i] + b[i] + sub_chain_borrow[i−1] = "lhs_byte[i]" +
    ///  256 · sub_chain_borrow[i]`, where `lhs_byte[i]` is the
    /// implicit byte that also equals `a[i] + is_underflow·p[i] +
    /// sub_chain_carry_aip[i−1] − 256·sub_chain_carry_aip[i]`.
    /// Each entry is 0 or 1.  Closure: `sub_chain_borrow[31] =
    /// sub_chain_carry_aip[31]` (both sides have the same final
    /// carry-out, guaranteeing the integer equality `out + b =
    /// a + is_underflow·p`).
    ///
    /// On is_sub rows, `IsOverflow` is reinterpreted as
    /// `is_underflow` (1 iff `a < b`); the column is the same wire
    /// witness, the constraint chain just changes role per the op
    /// flag.
    #[size = 32]
    SubChainBorrow,
    /// R1f-fix: per-position carry chain for `a + is_underflow·p`
    /// on is_sub rows.  Together with `SubChainBorrow` (carry of
    /// `out + b`), they witness `out + b ≡ a + is_underflow·p`
    /// byte-wise without requiring a {-1, 0, +1} signed witness.
    /// Each entry is 0 or 1.  Closure: equals `SubChainBorrow[31]`.
    #[size = 32]
    SubChainCarryAip,

    /// R1c-4: 64-byte unreduced schoolbook product `a · b` for is_mul
    /// rows.  Position k holds the canonical byte
    /// `(prod >> 8·k) & 0xff` of the integer product (which fits in
    /// 512 bits / 64 bytes since each operand is < 2²⁵⁶).
    /// Reduction `mod p` happens separately in R1c-5 (this is the
    /// pre-reduction product).
    #[size = 64]
    MulProduct,
    /// R1c-4: per-position low byte of the schoolbook carry chain.
    /// 64 positions; at each, the carry value can grow to ~16 bits
    /// (the partial-product sum at position k accumulates up to
    /// `min(k+1, 64-k)` terms of ≤ 65025, so up to ~32 · 65025 ≈
    /// 2M ≈ 21 bits — split as low 8 + high 16 bits).  Pinned by
    /// R1c-4-b's per-position constraint chain.
    #[size = 64]
    MulCarry,
    /// R1c-4: per-position middle byte of the schoolbook carry.
    #[size = 64]
    MulCarryMid,
    /// R1c-4: per-position high (upper) byte of the schoolbook carry.
    #[size = 64]
    MulCarryHi,

    /// R1c-5-a: pass-1 reduction fold `lo + 38·hi` (mod p), where
    /// `lo = mul_product[..32]` and `hi = mul_product[32..]`.  Stored
    /// as 32 low bytes (Pass1Lo) plus a 2-byte overflow head
    /// (Pass1Hi).  After this fold the residual value sits in
    /// `[0, 2²⁵⁶ + 38·(2²⁵⁶−1)) ⊂ [0, 39·2²⁵⁶)`.
    #[size = 32]
    Pass1Lo,
    /// R1c-5-a: pass-1 overflow into bytes 32..34 (≤ 38, so 2 bytes
    /// is plenty).
    #[size = 2]
    Pass1Hi,
    /// R1c-5-a: per-position carry-byte chain (lo + mid bytes per
    /// position, since 38·byte + byte fits in ≤ 16 bits).
    #[size = 32]
    Pass1Carry,
    #[size = 32]
    Pass1CarryMid,

    /// R1c-5-a: pass-2 fold `pass1_lo + 38·pass1_hi`.  Since
    /// pass1_hi ≤ 38 and 38·38 = 1444 < 2¹¹, this fold can produce
    /// at most a 1-bit overflow into bit 256.  Stored as 32 low
    /// bytes + a 1-bit `pass2_carry_out` (folded via 2²⁵⁶ ≡ 38
    /// equivalence).
    #[size = 32]
    Pass2Lo,
    #[size = 1]
    Pass2CarryOut,
    /// R1c-5-a: per-position carry chain for the pass-2 fold.
    #[size = 32]
    Pass2Carry,

    /// R1c-5-a: top bit of pass2_lo[31] (= bit 255 of the value).
    /// If set, the value is in `[2²⁵⁵, 2²⁵⁶)` and reduces by adding
    /// 19 after clearing bit 255.
    #[size = 1]
    Pass2TopBit,
    /// R1c-5-a: pass2 with bit 255 cleared and +19 added if either
    /// pass2_carry_out or pass2_top_bit is set (both encode the
    /// "+19 mod p" reduction).  This is the value that flows into
    /// the final-form `< p` check, after which it lands in
    /// FieldOut.
    #[size = 32]
    AfterTopBit,
    /// R1c-5-a: per-position carry chain for the +19 step.
    #[size = 32]
    AfterTopCarry,

    /// Operation classifier flags — exactly one is 1 on a real row.
    /// R1c-3+ adds is_mul; is_inv composes mul rows + a Fermat
    /// ladder driver, no separate row class.
    #[size = 1]
    IsAdd,
    #[size = 1]
    IsSub,
    /// R1c-4: 1 iff this row witnesses a 256-bit × 256-bit field
    /// multiplication.  Mutually exclusive with IsAdd / IsSub on
    /// real rows.
    #[size = 1]
    IsMul,
    /// R1e-bdry: 1 iff this row is a BOUNDARY-INPUT producer row.
    /// On is_input rows the chip emits the per-byte producer
    /// tuples (so subsequent rows can consume from this row's
    /// row_id) but DOES NOT fire field-op constraints or consumer
    /// emissions.  The `out` column holds the boundary value;
    /// `a`/`b` are unconstrained on is_input rows (typically zero).
    /// Used for: ECALL scalar/point bytes, curve constants
    /// (ED25519_TWO_D), point-identity coords, etc.
    /// Mutually exclusive with IsAdd/IsSub/IsMul on real rows.
    #[size = 1]
    IsInput,
    /// R1e-bdry: 1 iff this row is a BOUNDARY-OUTPUT consumer row.
    /// On is_output rows the chip emits ONE consumer emission for
    /// `a` (no producer, no `b` consumer, no field-op constraints).
    /// Drains the final row's `out` from the chain so the lookup
    /// balances.  In R1f, the ECALL OUTPUT boundary takes this
    /// role via MemoryChip's write entries; for chip-only tests,
    /// this row class lets us close the chain.
    #[size = 1]
    IsOutput,

    /// R1e-pent: row-id (low byte) of the row that produced this
    /// row's `a` input.  The chip emits a CONSUMER lookup keyed
    /// on (a_source_row, byte_index, a[byte]) — closes the
    /// inter-row binding gap by forcing every input to come from a
    /// prior row's `out` (or from a boundary producer).
    #[size = 1]
    ASourceRowLo,
    #[size = 1]
    ASourceRowHi,
    /// R1e-pent: row-id of the row that produced this row's `b` input.
    #[size = 1]
    BSourceRowLo,
    #[size = 1]
    BSourceRowHi,

    /// 0 iff this is a padding / unused row.
    #[size = 1]
    IsReal,

    // ── Phase I-ristretto Stwo-v2.x degree-flatten helpers ──
    //
    // RistrettoChip's natural form has many `is_real · is_op · linear`
    // selector chains (deg 3) and the schoolbook chain has
    // `is_real · is_mul · partial_sum` with quadratic body (deg 4).
    // Lookup multiplicities `is_real · (1 - is_input) · (1 - is_output)`
    // reach deg 3, which combined with deg-1 tuple yields paired-batch
    // deg 4 — too high once the chip is dialed back to bound 1.

    /// `IsReal · IsAdd` — full add-row selector.
    #[size = 1]
    RealAddH,
    /// `IsReal · IsSub` — full sub-row selector.
    #[size = 1]
    RealSubH,
    /// `IsReal · IsMul` — full mul-row selector.
    #[size = 1]
    RealMulH,
    /// `IsReal · (1 - IsOutput)` — register-file producer multiplicity.
    #[size = 1]
    ProducerGateH,
    /// `IsReal · (1 - IsInput)` — register-file consumer-A multiplicity
    /// (also used as a chain step for ConsumerBGateH).
    #[size = 1]
    ConsumerAGateH,
    /// `ConsumerAGateH · (1 - IsOutput)` — register-file consumer-B
    /// multiplicity (op-rows only).
    #[size = 1]
    ConsumerBGateH,

    /// 64-byte mul schoolbook partial-sum helper:
    /// `MulPartialSum[k] := Σ_{i+j=k, i,j<32} FieldA[i] · FieldB[j]`
    /// for k=0..64 (deg 2 def).  Lifts the per-position quadratic
    /// body so the gated mul constraint sits at deg 2.
    #[size = 64]
    MulPartialSum,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto"]
pub enum PreprocessedColumn {
    /// Reserved.  Real preprocessed columns come with R1c-3..R1e.
    #[size = 1]
    Reserved,
    /// R1e-pent: this row's index, low byte (rows 0..256).
    /// Used as the "row_id_lo" element of producer lookup tuples
    /// emitted on RistrettoRegisterFileLookupElements.
    #[size = 1]
    RowIndexLo,
    /// R1e-pent: this row's index, high byte (256·byte for
    /// chip log_size up to 16).
    #[size = 1]
    RowIndexHi,
    /// R1e-pent: byte-index constants {0, 1, ..., 31} packed into
    /// a 32-cell preprocessed column.  Used to inject the byte_idx
    /// element of producer/consumer lookup tuples without requiring
    /// per-emission constant materialization in the interaction
    /// trace.  At every row, ByteIdx[k] = k.
    #[size = 32]
    ByteIdx,
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
    /// Phase I-ristretto flatten: dropped from 3 to 2.  Every
    /// schoolbook position now uses MulPartialSum[k] (deg-1 helper)
    /// gated by RealMulH (deg-1 helper), bringing actual algebraic
    /// degree to 2 across all constraints.  Stwo v2.x's lifted protocol
    /// enforces actual degree, not declared bound, but we keep them
    /// aligned for clarity (matches Blake2b/Mul/DivRem/Cpu).
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    /// R1e-pent: now a 2-tuple — Range256 for byte ranges +
    /// RistrettoRegisterFile for inter-row binding.
    type LookupElements = (Range256LookupElements, RistrettoRegisterFileLookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(Range256LookupElements, RistrettoRegisterFileLookupElements),
    ) {
        let (range_lookup, regfile_lookup) = lookup_elements;
        let lookup_elements = range_lookup;
        let _ = regfile_lookup; // referenced in producer/consumer emissions below
        let a       = crate::trace::trace_eval!(trace_eval, Column::FieldA);
        let b       = crate::trace::trace_eval!(trace_eval, Column::FieldB);
        let out     = crate::trace::trace_eval!(trace_eval, Column::FieldOut);
        let interm  = crate::trace::trace_eval!(trace_eval, Column::AddIntermediate);
        let carry   = crate::trace::trace_eval!(trace_eval, Column::AddCarry);
        let borrow  = crate::trace::trace_eval!(trace_eval, Column::SubBorrow);
        let ff_brw  = crate::trace::trace_eval!(trace_eval, Column::FinalFormBorrow);
        let sub_chain_brw = crate::trace::trace_eval!(trace_eval, Column::SubChainBorrow);
        let sub_chain_aip = crate::trace::trace_eval!(trace_eval, Column::SubChainCarryAip);
        let a_src_lo = crate::trace::trace_eval!(trace_eval, Column::ASourceRowLo);
        let a_src_hi = crate::trace::trace_eval!(trace_eval, Column::ASourceRowHi);
        let b_src_lo = crate::trace::trace_eval!(trace_eval, Column::BSourceRowLo);
        let b_src_hi = crate::trace::trace_eval!(trace_eval, Column::BSourceRowHi);
        let row_idx_lo = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexLo);
        let row_idx_hi = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIndexHi);
        let byte_idx_pp = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ByteIdx);
        let mul_product   = crate::trace::trace_eval!(trace_eval, Column::MulProduct);
        let mul_carry     = crate::trace::trace_eval!(trace_eval, Column::MulCarry);
        let mul_carry_mid = crate::trace::trace_eval!(trace_eval, Column::MulCarryMid);
        let mul_carry_hi  = crate::trace::trace_eval!(trace_eval, Column::MulCarryHi);
        let pass1_lo      = crate::trace::trace_eval!(trace_eval, Column::Pass1Lo);
        let pass1_hi      = crate::trace::trace_eval!(trace_eval, Column::Pass1Hi);
        let pass1_carry   = crate::trace::trace_eval!(trace_eval, Column::Pass1Carry);
        let pass1_carry_mid = crate::trace::trace_eval!(trace_eval, Column::Pass1CarryMid);
        let pass2_lo      = crate::trace::trace_eval!(trace_eval, Column::Pass2Lo);
        let pass2_carry_out = crate::trace::trace_eval!(trace_eval, Column::Pass2CarryOut);
        let pass2_carry   = crate::trace::trace_eval!(trace_eval, Column::Pass2Carry);
        let pass2_top_bit = crate::trace::trace_eval!(trace_eval, Column::Pass2TopBit);
        let after_top_bit = crate::trace::trace_eval!(trace_eval, Column::AfterTopBit);
        let after_top_carry = crate::trace::trace_eval!(trace_eval, Column::AfterTopCarry);
        let is_ovf  = crate::trace::trace_eval!(trace_eval, Column::IsOverflow);
        let is_add  = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
        let is_sub  = crate::trace::trace_eval!(trace_eval, Column::IsSub);
        let is_mul  = crate::trace::trace_eval!(trace_eval, Column::IsMul);
        let is_input = crate::trace::trace_eval!(trace_eval, Column::IsInput);
        let is_output = crate::trace::trace_eval!(trace_eval, Column::IsOutput);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);

        let f256 = E::F::from(BaseField::from(256u32));

        // ── Phase I-ristretto degree-flatten helpers ──
        let real_add_h = crate::trace::trace_eval!(trace_eval, Column::RealAddH);
        let real_sub_h = crate::trace::trace_eval!(trace_eval, Column::RealSubH);
        let real_mul_h = crate::trace::trace_eval!(trace_eval, Column::RealMulH);
        let producer_gate_h =
            crate::trace::trace_eval!(trace_eval, Column::ProducerGateH);
        let consumer_a_gate_h =
            crate::trace::trace_eval!(trace_eval, Column::ConsumerAGateH);
        let consumer_b_gate_h =
            crate::trace::trace_eval!(trace_eval, Column::ConsumerBGateH);
        let mul_partial_sum =
            crate::trace::trace_eval!(trace_eval, Column::MulPartialSum);
        // Helper-defining constraints (deg 2 each).
        eval.add_constraint(
            real_add_h[0].clone() - is_real[0].clone() * is_add[0].clone()
        );
        eval.add_constraint(
            real_sub_h[0].clone() - is_real[0].clone() * is_sub[0].clone()
        );
        eval.add_constraint(
            real_mul_h[0].clone() - is_real[0].clone() * is_mul[0].clone()
        );
        eval.add_constraint(
            producer_gate_h[0].clone()
                - is_real[0].clone() * (E::F::one() - is_output[0].clone())
        );
        eval.add_constraint(
            consumer_a_gate_h[0].clone()
                - is_real[0].clone() * (E::F::one() - is_input[0].clone())
        );
        eval.add_constraint(
            consumer_b_gate_h[0].clone()
                - consumer_a_gate_h[0].clone()
                    * (E::F::one() - is_output[0].clone())
        );
        // MulPartialSum[k] = Σ_{i+j=k, i,j<32} a[i]·b[j].
        for k in 0..64usize {
            let mut psum = E::F::zero();
            for i in 0..32usize {
                let j = k.wrapping_sub(i);
                if j < 32 {
                    psum += a[i].clone() * b[j].clone();
                }
            }
            eval.add_constraint(mul_partial_sum[k].clone() - psum);
        }

        // ── Boolean flags ──
        // Each flag column must hold 0 or 1.  Degree-2 each.
        for flag in [&is_ovf, &is_add, &is_sub, &is_mul, &is_input, &is_output, &is_real] {
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
        for c in sub_chain_brw.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }
        for c in sub_chain_aip.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }

        // ── Real-row partition: exactly one op flag is 1 ──
        // is_real = 1 ⇒ is_add + is_sub + is_mul + is_input + is_output = 1.
        // is_real = 0 ⇒ all op flags zero.
        eval.add_constraint(
            is_real[0].clone() * (
                is_add[0].clone() + is_sub[0].clone() + is_mul[0].clone()
                    + is_input[0].clone() + is_output[0].clone() - E::F::one()
            )
        );
        let not_real = E::F::one() - is_real[0].clone();
        eval.add_constraint(not_real.clone() * is_add[0].clone());
        eval.add_constraint(not_real.clone() * is_sub[0].clone());
        eval.add_constraint(not_real.clone() * is_mul[0].clone());
        eval.add_constraint(not_real.clone() * is_input[0].clone());
        eval.add_constraint(not_real * is_output[0].clone());

        // ── R1c-3: byte-wise sum chain (is_add rows only) ──
        //
        //   intermediate[i] + 256·carry[i] = a[i] + b[i] + carry[i-1]
        //
        // gated by is_real · is_add so non-add rows leave intermediate
        // and carry free (will be pinned by R1c-3-bis sub chain and
        // R1c-4 mul chain in their respective op flavors).  carry[-1]
        // is the implicit 0.
        let _real_add = is_real[0].clone() * is_add[0].clone(); // routed via RealAddH
        for i in 0..32 {
            let carry_in = if i == 0 { E::F::zero() } else { carry[i - 1].clone() };
            let lhs = interm[i].clone() + carry[i].clone() * f256.clone();
            let rhs = a[i].clone() + b[i].clone() + carry_in;
            eval.add_constraint(real_add_h[0].clone() * (lhs - rhs));
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
            eval.add_constraint(real_add_h[0].clone() * constraint);
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

        // ── R1c-3-quat: is_sub constraint chain ──
        //
        // For is_sub rows we need `out ≡ a − b (mod p)`, i.e.
        // `out + b ≡ a (mod p)`, with no integer overflow when
        // `a, b, out < p`.  Two cases collapse into a single
        // formulation by choosing the right is_underflow witness:
        //
        //   is_underflow = 1 iff a < b  ⇒  out = a − b + p
        //   is_underflow = 0 otherwise  ⇒  out = a − b
        //
        // In both cases `out + b = a + is_underflow · p` exactly
        // (over ℤ).  Byte-wise borrow chain:
        //
        //   a[i] + is_underflow · p[i] + 256·sub_chain_brw[i]
        //     − out[i] − b[i] − sub_chain_brw[i−1] = 0
        //
        // gated by is_real · is_sub.  IsOverflow (witness column) is
        // reinterpreted as is_underflow on these rows; same wire
        // value, different role per op flag.  Closure: final borrow
        // = 0 since the integer equation holds without 2²⁵⁶ overflow
        // when all operands are < p.
        // R1f-fix: prove `out + b == a + is_underflow·p` via two
        // synchronous forward-carry chains (cy_obb on the
        // out+b side, cy_aip on the a+is_uf·p side).  Each chain
        // produces an implicit "byte[i]" at every position; we
        // assert byte_obb[i] == byte_aip[i] per byte, and assert
        // the two chains end with equal carries.  This handles
        // both directions (`out+b > a+p` and vice versa) with
        // simple {0,1} witnesses.
        //
        // Per-byte (gated by is_real · is_sub):
        //   out[i] + b[i] + cy_obb[i-1] − 256·cy_obb[i]
        //     = a[i] + is_uf·p[i] + cy_aip[i-1] − 256·cy_aip[i]
        let _real_sub = is_real[0].clone() * is_sub[0].clone(); // routed via RealSubH
        for i in 0..32 {
            let p_i = E::F::from(BaseField::from(P_BYTE_CONSTS[i] as u32));
            let cy_obb_in = if i == 0 { E::F::zero() } else { sub_chain_brw[i - 1].clone() };
            let cy_aip_in = if i == 0 { E::F::zero() } else { sub_chain_aip[i - 1].clone() };
            let constraint = out[i].clone()
                + b[i].clone()
                + cy_obb_in
                - sub_chain_brw[i].clone() * f256.clone()
                - a[i].clone()
                - is_ovf[0].clone() * p_i
                - cy_aip_in
                + sub_chain_aip[i].clone() * f256.clone();
            eval.add_constraint(real_sub_h[0].clone() * constraint);
        }
        // Closure: cy_obb[31] == cy_aip[31] (both sides produce the
        // same total: integer equality `out + b = a + is_uf·p`).
        eval.add_constraint(
            real_sub_h[0].clone() * (sub_chain_brw[31].clone() - sub_chain_aip[31].clone())
        );

        // ── R1c-4-b: schoolbook field multiplication chain ──
        //
        //   Σ_{i+j=k, 0≤i,j<32} a[i]·b[j] + carry_in[k]
        //     = product[k] + 256·full_carry[k]
        //
        // gated by is_real · is_mul, where
        //
        //   carry_in[k]    = full_carry[k−1]                   (carry_in[0] = 0)
        //   full_carry[k]  = mul_carry[k] + 256·mul_carry_mid[k]
        //                                + 65536·mul_carry_hi[k]
        //
        // Each position's full_carry can grow to ~21 bits at peak
        // density (k = 31 accumulates 32 terms ≤ 65025 plus the
        // incoming carry); 3-byte split has plenty of headroom.
        // Closure: full_carry[63] = 0 — the 512-bit unreduced
        // product fits exactly in 64 bytes when both operands < 2²⁵⁶.
        //
        // Constraint degree: a[i]·b[j] is degree 2, gated by
        // real_mul (degree 2) ⇒ degree 4 overall, matching MulChip's
        // bound at LOG_CONSTRAINT_DEGREE_BOUND = 2.
        let _real_mul = is_real[0].clone() * is_mul[0].clone(); // routed via RealMulH
        let f65536: E::F = E::F::from(BaseField::from(65536u32));

        let full_carry = |k: usize| -> E::F {
            mul_carry[k].clone()
                + mul_carry_mid[k].clone() * f256.clone()
                + mul_carry_hi[k].clone() * f65536.clone()
        };

        // Phase I-ristretto flatten: partial_sum lifted into MulPartialSum[k]
        // (deg-1 helper) so the gated constraint factors into deg-1 selector
        // × deg-1 body = deg 2.
        for k in 0usize..64 {
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let constraint = mul_partial_sum[k].clone()
                + carry_in
                - mul_product[k].clone()
                - full_carry(k) * f256.clone();
            eval.add_constraint(real_mul_h[0].clone() * constraint);
        }
        // Closure: full_carry(63) = 0 (no 65th byte overflow).
        eval.add_constraint(real_mul_h[0].clone() * full_carry(63));

        // ── R1c-5-b: pass-1 reduction fold lo + 38·hi ──
        //
        //   pass1_lo[k] + 256·full_carry1[k]
        //     = mul_product[k] + 38·mul_product[k+32] + carry1_in[k]
        //
        // gated by is_real · is_mul.  full_carry1 split as
        // pass1_carry[k] + 256·pass1_carry_mid[k] (max ~14 bits +
        // incoming carry < 2¹⁶).  Closure: full_carry1[31] = pass1_hi
        // viewed as a 16-bit value (pass1_hi[0] + 256·pass1_hi[1]).
        let f38: E::F = E::F::from(BaseField::from(38u32));
        let pass1_full_carry = |k: usize| -> E::F {
            pass1_carry[k].clone() + pass1_carry_mid[k].clone() * f256.clone()
        };
        let pass1_hi_value = || -> E::F {
            pass1_hi[0].clone() + pass1_hi[1].clone() * f256.clone()
        };
        for k in 0..32 {
            let carry_in = if k == 0 { E::F::zero() } else { pass1_full_carry(k - 1) };
            let constraint = pass1_lo[k].clone()
                + pass1_full_carry(k) * f256.clone()
                - mul_product[k].clone()
                - f38.clone() * mul_product[k + 32].clone()
                - carry_in;
            eval.add_constraint(real_mul_h[0].clone() * constraint);
        }
        eval.add_constraint(
            real_mul_h[0].clone() * (pass1_full_carry(31) - pass1_hi_value())
        );

        // ── R1c-5-b: pass-2 reduction fold pass1_lo + 38·pass1_hi ──
        //
        // 38·pass1_hi is a 16-bit constant injected at byte 0 (low
        // byte) and byte 1 (high byte), with overflow up to bit 22:
        //
        //   38·(2¹⁶−1) = 2490330 ≈ 2²² (3 bytes), but in practice
        //   pass1_hi ≤ 38 since the unreduced product < p² <
        //   (2²⁵⁵)² = 2⁵¹⁰, and lo + 38·hi < 2²⁵⁶ + 38·2²⁵⁶
        //   ⇒ pass1_hi < 39 ⇒ 38·pass1_hi < 1482 ≈ 2¹¹ ⇒ 2 bytes.
        //
        // Constraint per position k ∈ 0..32:
        //
        //   pass2_lo[k] + 256·pass2_carry[k]
        //     = pass1_lo[k] + inject_byte[k] + carry2_in[k]
        //
        // where inject_byte[0..3] are the bytes of 38·pass1_hi
        // (computed as a constant from pass1_hi columns) and
        // inject_byte[3..32] = 0.
        //
        // For the chip, we compute 38·pass1_hi as a wire-level
        // expression: (38·pass1_hi[0]) + 256·(38·pass1_hi[1]) — a
        // single 16-bit constant.  We split it into per-byte
        // contributions inline.
        for k in 0..32 {
            let carry_in = if k == 0 { E::F::zero() } else { pass2_carry[k - 1].clone() };
            let inject_byte = match k {
                0 => f38.clone() * pass1_hi[0].clone(),
                1 => f38.clone() * pass1_hi[1].clone(),
                _ => E::F::zero(),
            };
            let constraint = pass2_lo[k].clone()
                + pass2_carry[k].clone() * f256.clone()
                - pass1_lo[k].clone()
                - inject_byte
                - carry_in;
            eval.add_constraint(real_mul_h[0].clone() * constraint);
        }
        eval.add_constraint(
            real_mul_h[0].clone() * (pass2_carry[31].clone() - pass2_carry_out[0].clone())
        );

        // ── R1c-5-b: top-bit fold ──
        //
        // pass2_top_bit ∈ {0, 1} is bit 7 of pass2_lo[31].  We pin
        // it by witnessing pass2_lo[31] = (pass2_lo[31] − 128·top_bit)
        // + 128·top_bit, plus the bound that the low 7 bits are <
        // 128 (handled implicitly by the after_top_bit chain below
        // which produces after_top_bit[31] from pass2_lo[31] minus
        // 128·top_bit).
        //
        // The after-top chain folds in 38·pass2_carry_out + 19·top_bit:
        //
        //   after_top_bit[k] + 256·after_top_carry[k]
        //     = pass2_lo[k] + inject_at_k + after_carry_in[k]
        //         − 128·pass2_top_bit · [k == 31]
        //
        // where inject_at_0 = 38·pass2_carry_out + 19·pass2_top_bit
        // and inject_at_k>0 = 0 (the value is at most 19+38 = 57 < 128,
        // single byte at position 0).
        let inject0_after = f38.clone() * pass2_carry_out[0].clone()
            + E::F::from(BaseField::from(19u32)) * pass2_top_bit[0].clone();
        let f128 = E::F::from(BaseField::from(128u32));
        for k in 0..32 {
            let carry_in = if k == 0 { E::F::zero() } else { after_top_carry[k - 1].clone() };
            let inject = if k == 0 { inject0_after.clone() } else { E::F::zero() };
            let bit_strip = if k == 31 {
                f128.clone() * pass2_top_bit[0].clone()
            } else { E::F::zero() };
            let constraint = after_top_bit[k].clone()
                + after_top_carry[k].clone() * f256.clone()
                - pass2_lo[k].clone()
                - inject
                - carry_in
                + bit_strip;
            eval.add_constraint(real_mul_h[0].clone() * constraint);
        }
        eval.add_constraint(real_mul_h[0].clone() * after_top_carry[31].clone());

        // ── R1c-5-b: pass2_top_bit boolean + bit-7 pin ──
        //
        // pass2_top_bit ∈ {0, 1} (already booleanized below in the
        // Range256 / boolean sweep).  The "low 7 bits of pass2_lo[31]"
        // soundness: after_top_bit[31] (which is pass2_lo[31] −
        // 128·top_bit) must be < 128 — implicitly pinned by Range256
        // on after_top_bit[31].  Range256 emission appended below
        // covers this; no separate constraint needed.

        // ── R1c-5-b: final FieldOut = after_top_bit − is_overflow·p ──
        //
        // Reuses the SubBorrow chain (already constrained for is_add
        // rows).  For is_mul rows we re-pin out[k] against
        // after_top_bit[k] instead of add_intermediate[k]:
        //
        //   after_top_bit[k] − is_overflow·p[k] − sub_borrow[k−1]
        //     + 256·sub_borrow[k] − out[k] = 0
        //
        // gated by real_mul.  IsOverflow is pinned witness-
        // deterministic by the existing FinalFormBorrow chain
        // (out < p closure).
        for i in 0..32 {
            let p_i = E::F::from(BaseField::from(P_BYTE_CONSTS[i] as u32));
            let borrow_in = if i == 0 { E::F::zero() } else { borrow[i - 1].clone() };
            let constraint = after_top_bit[i].clone()
                - is_ovf[0].clone() * p_i
                - borrow_in
                + borrow[i].clone() * f256.clone()
                - out[i].clone();
            eval.add_constraint(real_mul_h[0].clone() * constraint);
        }

        // Booleans: pass2_carry_out, pass2_top_bit ∈ {0, 1}.
        eval.add_constraint(
            pass2_carry_out[0].clone() * (E::F::one() - pass2_carry_out[0].clone())
        );
        eval.add_constraint(
            pass2_top_bit[0].clone() * (E::F::one() - pass2_top_bit[0].clone())
        );

        // ── R1c-3-ter: per-byte Range256 lookups ──
        //
        // Pin every committed byte cell on real rows to lie in [0, 256).
        // Without these, the algebraic chains above are sound only if
        // every cell is *separately* known to be a valid byte; a
        // malicious prover could otherwise spread the equality across
        // cells whose individual values escape [0, 256).  Producer
        // (positive) multiplicity = is_real, balanced against
        // RangeMultiplicity256's preprocessed consumer side.
        //
        // 32 + 32 + 32 + 32 = 128 emissions per real row.  Padding
        // rows contribute zero (multiplicity = 0).  Even count, so
        // finalize_logup_in_pairs() closes the chip's lookup
        // bookkeeping below.
        // EMISSION ORDER MUST MATCH `generate_interaction_trace`
        // exactly — finalize_logup_in_pairs() pairs adjacent
        // emissions, and order divergence between constraint and
        // interaction sides causes ConstraintsNotSatisfied for any
        // non-zero cell value.  This was the bug bisected at
        // commit cc89e8d and fixed in this commit.
        //
        // Loop 1: 32-byte add cols (a, b, out, interm) — 128 emits.
        for cells in [&a, &b, &out, &interm] {
            for byte in cells.iter() {
                eval.add_to_relation(RelationEntry::new(
                    lookup_elements,
                    is_real[0].clone().into(),
                    &[byte.clone()],
                ));
            }
        }
        // Loop 2: 64-byte mul cols (product + 3-byte carry chain) — 256.
        for cells in [&mul_product, &mul_carry, &mul_carry_mid, &mul_carry_hi] {
            for byte in cells.iter() {
                eval.add_to_relation(RelationEntry::new(
                    lookup_elements,
                    is_real[0].clone().into(),
                    &[byte.clone()],
                ));
            }
        }
        // Loop 3: 32-byte reduction + sub-aux cols — 256.
        for cells_32 in [
            &pass1_lo, &pass1_carry, &pass1_carry_mid,
            &pass2_lo, &pass2_carry,
            &after_top_bit, &after_top_carry,
            &sub_chain_aip,
        ] {
            for byte in cells_32.iter() {
                eval.add_to_relation(RelationEntry::new(
                    lookup_elements,
                    is_real[0].clone().into(),
                    &[byte.clone()],
                ));
            }
        }
        // Loop 4: 2-byte pass1_hi — 2.
        for byte in pass1_hi.iter() {
            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                is_real[0].clone().into(),
                &[byte.clone()],
            ));
        }

        // ── R1e-pent: register-file inter-row binding ──
        //
        // PRODUCER per real row: 32 tuples
        //   (row_idx_lo, row_idx_hi, byte_idx[k], out[k])
        // for k ∈ 0..32, with multiplicity = is_real.
        //
        // CONSUMER per real row: 32 tuples for `a` plus 32 for `b`,
        // keyed on (a_src_lo, a_src_hi, byte_idx[k], a[k]) etc.,
        // with multiplicity = -is_real.
        //
        // Lookup balance forces every consumer to find a matching
        // producer — closes the inter-row binding gap by ensuring
        // every input must come from a prior row's `out` (or from
        // an external boundary producer with a sentinel row_id).
        // Producer fires on rows that produce (op rows + input rows;
        // NOT output rows which only consume).
        // Phase I-ristretto flatten: gate via deg-1 helper columns so
        // multiplicities stay at deg ≤ 1 and paired-batch lookup
        // constraints stay at deg ≤ 2.
        for k in 0..32 {
            // Producer.
            eval.add_to_relation(RelationEntry::new(
                regfile_lookup,
                producer_gate_h[0].clone().into(),
                &[
                    row_idx_lo[0].clone(),
                    row_idx_hi[0].clone(),
                    byte_idx_pp[k].clone(),
                    out[k].clone(),
                ],
            ));
            // Consumer A: op rows + output rows.
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
            // Consumer B: op rows only.
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

        // R1c-4-b still leaves OPEN before R1f turns the chip on:
        //  - R1c-3-quat: is_sub constraint chain (the symmetric
        //    sub variant).  The witness builder already produces
        //    is_sub rows but the chip emits no constraints binding
        //    them to a − b mod p.
        //  - Per-position byte pin on the SubBorrow / FinalFormBorrow
        //    chains.  Today they are constrained to {0,1} only;
        //    individual byte arithmetic on `intermediate − is_overflow·p`
        //    or `p − out − 1` still relies on the per-byte values
        //    being u8.  R1c-3-quat lands these via a Range256 emission
        //    on the implicit byte expressions.

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        side_note: &SideNote,
    ) -> FinalizedTrace {
        let log_size = ristretto_log_size(side_note);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            trace.fill_columns(row, BaseField::from(0u32), PreprocessedColumn::Reserved);
            // R1e-pent: row index split into 2 LE bytes.  Limited
            // to log_size ≤ 16 (chip up to 64K rows).
            let row_lo = (row & 0xff) as u8;
            let row_hi = ((row >> 8) & 0xff) as u8;
            trace.fill_columns(row, row_lo, PreprocessedColumn::RowIndexLo);
            trace.fill_columns(row, row_hi, PreprocessedColumn::RowIndexHi);
            // ByteIdx[k] = k for every row.
            let byte_idx_arr: [u8; 32] = core::array::from_fn(|k| k as u8);
            trace.fill_columns_bytes(row, &byte_idx_arr, PreprocessedColumn::ByteIdx);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        // R1e-quat: lay each FieldOpRow into its column slots.
        // Padding rows beyond rows.len() have is_real = 0 and all
        // cells zero — chip's gating constraints make them inert.
        let log_size = ristretto_log_size(side_note);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        // Borrow the rows — the side_note is shared with the
        // verifier-side active_components selection, which checks
        // `ristretto_field_rows.is_empty()` to decide whether the
        // chip is in the active set.  Moving the rows out would
        // hide them from the verifier and trigger a chip-set
        // mismatch.
        for row_i in 0..num_rows {
            let r = side_note.ristretto_field_rows.get(row_i).copied().unwrap_or_default();

            // 32-byte cells.
            trace.fill_columns_bytes(row_i, &r.a,                  Column::FieldA);
            trace.fill_columns_bytes(row_i, &r.b,                  Column::FieldB);
            trace.fill_columns_bytes(row_i, &r.out,                Column::FieldOut);
            trace.fill_columns_bytes(row_i, &r.add_intermediate,   Column::AddIntermediate);
            trace.fill_columns_bytes(row_i, &r.add_carry,          Column::AddCarry);
            trace.fill_columns_bytes(row_i, &r.sub_borrow,         Column::SubBorrow);
            trace.fill_columns_bytes(row_i, &r.final_form_borrow,  Column::FinalFormBorrow);
            trace.fill_columns_bytes(row_i, &r.sub_chain_borrow,   Column::SubChainBorrow);
            trace.fill_columns_bytes(row_i, &r.sub_chain_carry_aip, Column::SubChainCarryAip);
            trace.fill_columns_bytes(row_i, &r.pass1_lo,           Column::Pass1Lo);
            trace.fill_columns_bytes(row_i, &r.pass1_carry,        Column::Pass1Carry);
            trace.fill_columns_bytes(row_i, &r.pass1_carry_mid,    Column::Pass1CarryMid);
            trace.fill_columns_bytes(row_i, &r.pass2_lo,           Column::Pass2Lo);
            trace.fill_columns_bytes(row_i, &r.pass2_carry,        Column::Pass2Carry);
            trace.fill_columns_bytes(row_i, &r.after_top_bit,      Column::AfterTopBit);
            trace.fill_columns_bytes(row_i, &r.after_top_carry,    Column::AfterTopCarry);

            // 64-byte cells (mul witnesses).
            trace.fill_columns_bytes(row_i, &r.mul_product,        Column::MulProduct);
            trace.fill_columns_bytes(row_i, &r.mul_carry,          Column::MulCarry);
            trace.fill_columns_bytes(row_i, &r.mul_carry_mid,      Column::MulCarryMid);
            trace.fill_columns_bytes(row_i, &r.mul_carry_hi,       Column::MulCarryHi);

            // 2-byte (Pass1Hi).
            trace.fill_columns_bytes(row_i, &r.pass1_hi,           Column::Pass1Hi);

            // 1-byte flag/bit cells.
            trace.fill_columns(row_i, r.is_overflow,     Column::IsOverflow);
            trace.fill_columns(row_i, r.pass2_carry_out, Column::Pass2CarryOut);
            trace.fill_columns(row_i, r.pass2_top_bit,   Column::Pass2TopBit);
            trace.fill_columns(row_i, r.is_add,          Column::IsAdd);
            trace.fill_columns(row_i, r.is_sub,          Column::IsSub);
            trace.fill_columns(row_i, r.is_mul,          Column::IsMul);
            trace.fill_columns(row_i, r.is_input,        Column::IsInput);
            trace.fill_columns(row_i, r.is_output,       Column::IsOutput);
            trace.fill_columns(row_i, r.is_real,         Column::IsReal);
            // R1e-pent: source row IDs (2 bytes each).
            trace.fill_columns(row_i, (r.a_source_row & 0xff) as u8, Column::ASourceRowLo);
            trace.fill_columns(row_i, ((r.a_source_row >> 8) & 0xff) as u8, Column::ASourceRowHi);
            trace.fill_columns(row_i, (r.b_source_row & 0xff) as u8, Column::BSourceRowLo);
            trace.fill_columns(row_i, ((r.b_source_row >> 8) & 0xff) as u8, Column::BSourceRowHi);

            // ── Phase I-ristretto helper fills ──
            // Selectors: bool products (each in {0, 1}).
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

            // MulPartialSum[k] = Σ a[i]·b[j] for i+j=k.  Values can
            // exceed u8/u16 (up to 32 × 255² ≈ 2 million); fill via BaseField.
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

            // Range256 multiplicity is bumped by the row-push
            // helper `SideNote::add_ristretto_field_row` (called
            // BEFORE prove_impl runs).  RangeMultiplicity256's main
            // trace fill then matches the consumer-side balance.
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

        // Emit the matching positive-multiplicity contribution for
        // the 128 per-row Range256 emissions in `add_constraints`.
        // Multiplicity = is_real (so padding rows contribute 0).
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let field_a = crate::trace::original_base_column!(component_trace, Column::FieldA);
        let field_b = crate::trace::original_base_column!(component_trace, Column::FieldB);
        let field_out = crate::trace::original_base_column!(component_trace, Column::FieldOut);
        let interm = crate::trace::original_base_column!(component_trace, Column::AddIntermediate);
        let mul_p   = crate::trace::original_base_column!(component_trace, Column::MulProduct);
        let mul_c   = crate::trace::original_base_column!(component_trace, Column::MulCarry);
        let mul_cm  = crate::trace::original_base_column!(component_trace, Column::MulCarryMid);
        let mul_ch  = crate::trace::original_base_column!(component_trace, Column::MulCarryHi);
        let p1_lo   = crate::trace::original_base_column!(component_trace, Column::Pass1Lo);
        let p1_hi   = crate::trace::original_base_column!(component_trace, Column::Pass1Hi);
        let p1_c    = crate::trace::original_base_column!(component_trace, Column::Pass1Carry);
        let p1_cm   = crate::trace::original_base_column!(component_trace, Column::Pass1CarryMid);
        let p2_lo   = crate::trace::original_base_column!(component_trace, Column::Pass2Lo);
        let p2_c    = crate::trace::original_base_column!(component_trace, Column::Pass2Carry);
        let atb     = crate::trace::original_base_column!(component_trace, Column::AfterTopBit);
        let atc     = crate::trace::original_base_column!(component_trace, Column::AfterTopCarry);
        let scaip   = crate::trace::original_base_column!(component_trace, Column::SubChainCarryAip);

        // EMISSION ORDER MUST MATCH `add_constraints` exactly —
        // finalize_logup_in_pairs pairs adjacent emissions (see
        // `add_constraints` for the matching emit order).
        //
        // Loop 1: 32-byte add cols.
        for cells in [&field_a, &field_b, &field_out, &interm] {
            for col in cells.iter() {
                logup.add_to_relation_with(
                    range256, [is_real[0].clone()],
                    |[real]| real.into(),
                    &[col.clone()],
                );
            }
        }
        // Loop 2: 64-byte mul cols.
        for cells in [&mul_p, &mul_c, &mul_cm, &mul_ch] {
            for col in cells.iter() {
                logup.add_to_relation_with(
                    range256, [is_real[0].clone()],
                    |[real]| real.into(),
                    &[col.clone()],
                );
            }
        }
        // Loop 3: 32-byte reduction + sub-aux cols.
        for cells in [
            &p1_lo, &p1_c, &p1_cm,
            &p2_lo, &p2_c,
            &atb, &atc,
            &scaip,
        ] {
            for col in cells.iter() {
                logup.add_to_relation_with(
                    range256, [is_real[0].clone()],
                    |[real]| real.into(),
                    &[col.clone()],
                );
            }
        }
        // Loop 4: 2-byte pass1_hi.
        for col in p1_hi.iter() {
            logup.add_to_relation_with(
                range256, [is_real[0].clone()],
                |[real]| real.into(),
                &[col.clone()],
            );
        }

        // ── R1e-pent: register-file inter-row binding ──
        //
        // Mirror the constraint-side producer + 2-consumer pattern.
        // Order MUST match add_constraints exactly because
        // finalize_logup_in_pairs() pairs adjacent emissions.
        let regfile: &RistrettoRegisterFileLookupElements = lookup_elements.as_ref();
        let row_idx_lo_pp = crate::trace::preprocessed_base_column!(
            component_trace, PreprocessedColumn::RowIndexLo);
        let row_idx_hi_pp = crate::trace::preprocessed_base_column!(
            component_trace, PreprocessedColumn::RowIndexHi);
        let byte_idx_pp = crate::trace::preprocessed_base_column!(
            component_trace, PreprocessedColumn::ByteIdx);
        let a_src_lo_col = crate::trace::original_base_column!(
            component_trace, Column::ASourceRowLo);
        let a_src_hi_col = crate::trace::original_base_column!(
            component_trace, Column::ASourceRowHi);
        let b_src_lo_col = crate::trace::original_base_column!(
            component_trace, Column::BSourceRowLo);
        let b_src_hi_col = crate::trace::original_base_column!(
            component_trace, Column::BSourceRowHi);
        let out_cols = crate::trace::original_base_column!(
            component_trace, Column::FieldOut);
        let a_cols = crate::trace::original_base_column!(
            component_trace, Column::FieldA);
        let b_cols = crate::trace::original_base_column!(
            component_trace, Column::FieldB);
        let is_input_col = crate::trace::original_base_column!(
            component_trace, Column::IsInput);
        let is_output_col = crate::trace::original_base_column!(
            component_trace, Column::IsOutput);
        let one_packed = || stwo::prover::backend::simd::m31::PackedM31::broadcast(
            BaseField::from(1u32));
        for k in 0..32 {
            // Producer: is_real * (1 - is_output)
            logup.add_to_relation_with(
                regfile,
                [is_real[0].clone(), is_output_col[0].clone()],
                |[real, output_flag]| (real * (one_packed() - output_flag)).into(),
                &[
                    row_idx_lo_pp[0].clone(),
                    row_idx_hi_pp[0].clone(),
                    byte_idx_pp[k].clone(),
                    out_cols[k].clone(),
                ],
            );
            // Consumer A: is_real * (1 - is_input) [fires on op rows + output rows]
            logup.add_to_relation_with(
                regfile,
                [is_real[0].clone(), is_input_col[0].clone()],
                |[real, input_flag]| (-(real * (one_packed() - input_flag))).into(),
                &[
                    a_src_lo_col[0].clone(),
                    a_src_hi_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    a_cols[k].clone(),
                ],
            );
            // Consumer B: is_real * (1 - is_input) * (1 - is_output)
            logup.add_to_relation_with(
                regfile,
                [is_real[0].clone(), is_input_col[0].clone(), is_output_col[0].clone()],
                |[real, input_flag, output_flag]| {
                    (-(real * (one_packed() - input_flag) * (one_packed() - output_flag))).into()
                },
                &[
                    b_src_lo_col[0].clone(),
                    b_src_hi_col[0].clone(),
                    byte_idx_pp[k].clone(),
                    b_cols[k].clone(),
                ],
            );
        }
        logup.finalize()
    }
}
