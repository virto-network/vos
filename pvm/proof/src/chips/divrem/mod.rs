//! `DivRemChip`: per-divrem-row chip.
//!
//! CpuChip emits one DivRemLookup producer per `is_div_rem=1` row;
//! DivRemChip consumes once per real row and proves, over `W = 64` bits
//! (`W = 32` on a 32-bit row, which reads the operands' low words):
//!
//!   1. The schoolbook `q·d + r = b + 2^W·H` as an exact integer identity:
//!      the quotient, remainder, high half `H` (DivCorrHi) and every carry
//!      are Range256-checked bytes, so no equation wraps in M31.
//!   2. `H` pinned by the operation:
//!      - unsigned division and logical right shift (ShloR): `H = 0`;
//!      - signed division (DivS/RemS):
//!        `H ≡ sq·d + sd·q + sr − sb + k (mod 2^W)`, with `k` the overflow
//!        of `MIN / −1`, the one quotient that does not fit;
//!      - arithmetic right shift (SharR, `d = 2^n`):
//!        `H ≡ sq·d − sb (mod 2^W)`, floor division.
//!      With the sign bits pinned on CpuChip, each makes the schoolbook
//!      the signed (or unsigned) identity over the integers.
//!   3. The remainder's bound: `r < d` unsigned, on every row but signed
//!      division (over the low word on a 32-bit row); `|r| < |d|` on
//!      signed division, through two's-complement magnitude chains with
//!      boolean carries over Range256-checked bytes (a 32-bit divisor
//!      sign-extended). CpuChip pins `sign(r) = sign(b)` when `r ≠ 0`.
//!   4. On a 32-bit row, the quotient's and remainder's high words are
//!      their low words' sign extension.
//!
//! Lookup tuple (41 limbs): val_b\[8\] + val_d\[8\] + div_quotient\[8\] +
//! div_remainder\[8\] + sign_bit_b + sign_bit_d + sign_bit_q +
//! sign_bit_r + is_div_rem + div_by_zero + is_32bit + is_div_s +
//! is_shar_r.

use crate::air_column::{AirColumn, PreprocessedAirColumn};

mod constraints;
#[cfg(feature = "prover")]
mod trace;
#[cfg(feature = "prover")]
mod witness;

#[cfg(feature = "prover")]
pub(crate) use witness::entry;
#[cfg(feature = "prover")]
pub use witness::{range_checked_bytes, witness};

pub struct DivRemChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    ValB,
    #[size = 8]
    ValD,
    #[size = 8]
    DivQuotient,
    #[size = 8]
    DivRemainder,
    /// High half `H` of the schoolbook `q·d + r = b + 2^W·H`.
    #[size = 8]
    DivCorrHi,
    /// Per-position low byte of the schoolbook carry (16 positions).
    #[size = 16]
    DivMulCarry,
    /// Per-position high byte; full carry = DivMulCarry + 256·DivMulCarryHi.
    #[size = 16]
    DivMulCarryHi,
    #[size = 1]
    IsDivRem,
    #[size = 1]
    DivByZero,
    #[size = 1]
    Is32Bit,
    /// Signed division or remainder (flowed via the lookup tuple).
    #[size = 1]
    IsDivS,
    /// Arithmetic right shift (flowed via the lookup tuple): floor
    /// division by `d = 2^n`.
    #[size = 1]
    IsSharR,
    /// 1 on the signed division `MIN / −1` alone: the true quotient
    /// `2^(W−1)` does not fit, and the PVM's `MIN` exceeds the schoolbook's
    /// high half by one.
    #[size = 1]
    DivOverflow,
    /// Per-byte `val_d + ~div_remainder` chain witness (`r < d`).
    #[size = 8]
    DivCmpDiff,
    /// Per-byte boolean carry of the chain.
    #[size = 8]
    DivCmpCarry,
    /// Per-byte carry of the signed correction chain, in {0, 1, 2}.
    #[size = 8]
    DivCorrCarry,
    /// 4 sign bits flowed from CpuChip via the lookup tuple.
    #[size = 1]
    SignBitB,
    #[size = 1]
    SignBitD,
    #[size = 1]
    SignBitQ,
    #[size = 1]
    SignBitR,
    /// |val_d| via two's-complement negation gated on sign_bit_d, of the
    /// sign-extended low word on a 32-bit row.
    #[size = 8]
    AbsD,
    #[size = 8]
    AbsDCarry,
    /// |div_remainder| via two's-complement negation gated on sign_bit_r.
    #[size = 8]
    AbsR,
    #[size = 8]
    AbsRCarry,
    /// Per-byte `abs_d + ~abs_r` chain witness.  Top carry forced to 1 on
    /// signed div rows.
    #[size = 8]
    AbsCmpDiff,
    #[size = 8]
    AbsCmpCarry,
    #[size = 1]
    IsPadding,

    // ── Degree-flatten helpers ──
    //
    // Each materialises a multi-flag selector or a quadratic body term so
    // every gated constraint factors into (deg 1 column ref) × (deg 1 body).
    /// `IsDivRem · (1 - DivByZero)` — div is "active" (non-zero divisor).
    #[size = 1]
    DivActiveH,
    /// `(1 - IsPadding) · DivActiveH` — real row + active div.
    #[size = 1]
    NotPaddingDivH,
    /// `NotPaddingDivH · Is64Bit` (Is64Bit = 1 - Is32Bit).
    #[size = 1]
    DivActive64H,
    /// `NotPaddingDivH · Is32Bit`.
    #[size = 1]
    DivActive32H,
    /// `NotPaddingDivH · (1 - IsDivS)` — the unsigned `r < d` chain's gate.
    #[size = 1]
    DivUActiveH,
    /// `DivUActiveH · Is64Bit`, `DivUActiveH · Is32Bit` — where the
    /// `r < d` chain's deciding carry sits (byte 7, byte 3).
    #[size = 1]
    DivU64H,
    #[size = 1]
    DivU32H,
    /// `NotPaddingDivH · IsDivS` — signed division (`|r| < |d|`).
    #[size = 1]
    DivSActiveH,
    /// `NotPaddingDivH · (IsDivS + IsSharR)` — rows whose high half the
    /// signed correction chain pins, and its per-width gates.
    #[size = 1]
    SignChainH,
    #[size = 1]
    SignChain64H,
    #[size = 1]
    SignChain32H,
    /// `NotPaddingDivH · (1 - IsDivS - IsSharR)` — unsigned rows, whose
    /// high half is zero.
    #[size = 1]
    ZeroHighH,
    /// `(1 - IsPadding) · (1 - SignBitD)` and `(1 - IsPadding) · SignBitD`
    /// — split AbsD chain gates by the conditional-negation case.
    #[size = 1]
    RealNotSdH,
    #[size = 1]
    RealSdH,
    /// Same shape on SignBitR for the AbsR chain.
    #[size = 1]
    RealNotSrH,
    #[size = 1]
    RealSrH,
    /// `DivOverflow · Is64Bit`.
    #[size = 1]
    DivOverflow64H,
    /// `SignBitD · IsDivS`: the divisor's sign as signed division reads
    /// it (an arithmetic shift's divisor `2^n` is unsigned).
    #[size = 1]
    SignDDivSH,

    /// 64-bit schoolbook partial-sum helper: `DivPartialSum64[k] :=
    /// Σ_{i+j=k, i,j<8} DivQuotient[i] · ValD[j]` (deg 2 def).  k=0..16.
    #[size = 16]
    DivPartialSum64,
    /// 32-bit schoolbook partial-sum helper, k=0..8 with i,j<4.
    #[size = 8]
    DivPartialSum32,

    /// Signed chain body helpers.
    /// `SignQValDH[i] := SignBitQ · ValD[i]`
    #[size = 8]
    SignQValDH,
    /// `SignDQuotH[i] := SignDDivSH · DivQuotient[i]`
    #[size = 8]
    SignDQuotH,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "divrem"]
pub enum PreprocessedColumn {}
