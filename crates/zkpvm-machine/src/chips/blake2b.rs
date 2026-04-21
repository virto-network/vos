//! Blake2b compression precompile — 96 rows per hash (one per G-function call).
//!
//! G(a, b, c, d, mx, my):
//!   a1 = a + b + mx;  xor1 = d ^ a1;  d1 = xor1 >>> 32  (byte permutation)
//!   c1 = c + d1;      xor2 = b ^ c1;  b1 = xor2 >>> 24  (byte permutation)
//!   a' = a1 + b1 + my; xor3 = d1 ^ a'; d' = xor3 >>> 16  (byte permutation)
//!   c' = c1 + d';     xor4 = b1 ^ c'; b' = xor4 >>> 63  (1-bit carry)
//!
//! Each G-row emits 64 nibble-AND lookups (4 ANDs × 8 bytes × 2 nibbles) to
//! the BitwiseLookupChip, constraining the AND witnesses used in XOR derivations.

use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::{LOG_N_LANES, PackedBaseField}, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use zkpvm_air_column::{AirColumn, PreprocessedAirColumn};
use zkpvm_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, BitwiseAndLookupElements, Blake2bCallLookupElements,
        LogupTraceBuilder, MemoryAccessLookupElements, Range256LookupElements,
    },
    side_note::SideNote,
};

pub struct Blake2bChip;

const IV: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// G-function mixing indices per round: (a, b, c, d) indices into v[16]
const G_INDICES: [[usize; 4]; 8] = [
    [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15], // columns
    [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14],  // diagonals
];

// ── Column layout ────────────────────────────────────────────

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    // Input state (4 × u64 = 32 limbs)
    #[size = 8] AIn,
    #[size = 8] BIn,
    #[size = 8] CIn,
    #[size = 8] DIn,
    // Message words (2 × u64 = 16 limbs)
    #[size = 8] Mx,
    #[size = 8] My,
    // Step 1: a1 = a + b + mx
    #[size = 8] A1,
    #[size = 8] Carry1,
    // Step 2: and1 = d & a1 (witness for XOR: d^a1 = d+a1-2*and1)
    #[size = 8] And1,
    // Step 3: c1 = c + d1 (where d1 = (d^a1) >>> 32 = byte permutation)
    #[size = 8] C1,
    #[size = 8] Carry2,
    // Step 4: and2 = b & c1
    #[size = 8] And2,
    // Step 5: a_out = a1 + b1 + my (where b1 = (b^c1) >>> 24 = byte permutation)
    #[size = 8] AOut,
    #[size = 8] Carry3,
    // Step 6: and3 = d1 & a_out
    #[size = 8] And3,
    // Step 7: c_out = c1 + d_out (where d_out = (d1^a_out) >>> 16 = byte permutation)
    #[size = 8] COut,
    #[size = 8] Carry4,
    // Step 8: and4 = b1 & c_out
    #[size = 8] And4,
    // Step 9: b_out = (b1 ^ c_out) >>> 63 = left rotate by 1
    #[size = 8] BOut,
    #[size = 8] Rot63Carry, // 1-bit carries for rotation
    // ── Nibble witnesses for AND lookups (12 columns × 8 bytes = 96 limbs) ──
    // And1 = DIn & A1
    #[size = 8] And1AHi, // hi nibble of DIn
    #[size = 8] And1BHi, // hi nibble of A1
    #[size = 8] And1ResHi, // hi nibble of And1
    // And2 = BIn & C1
    #[size = 8] And2AHi, // hi nibble of BIn
    #[size = 8] And2BHi, // hi nibble of C1
    #[size = 8] And2ResHi, // hi nibble of And2
    // And3 = D1 & AOut, where D1[k] = DIn[(k+4)%8] + A1[(k+4)%8] - 2·And1[(k+4)%8]
    #[size = 8] And3AHi, // hi nibble of derived D1[k]
    #[size = 8] And3BHi, // hi nibble of AOut
    #[size = 8] And3ResHi, // hi nibble of And3
    // And4 = B1 & COut, where B1[k] = BIn[(k+3)%8] + C1[(k+3)%8] - 2·And2[(k+3)%8]
    #[size = 8] And4AHi, // hi nibble of derived B1[k]
    #[size = 8] And4BHi, // hi nibble of COut
    #[size = 8] And4ResHi, // hi nibble of And4
    // ── Row chaining: full state snapshot + d_out reification ──
    // D_out is not stored in the base trace; derive via XOR identity and
    // reify so the row-chaining constraint can propagate it into V_next.
    #[size = 8] DOut,
    // Message m[0..16] for the current compression. Prover-provided, held
    // constant across all 96 rows of a compression (enforced by inter-row
    // constraint gated on IsLastOfCompression). Mx and My are then selected
    // from these 16 slots via the SIGMA-derived preprocessed selectors.
    #[size = 8] #[mask_next_row] M0,
    #[size = 8] #[mask_next_row] M1,
    #[size = 8] #[mask_next_row] M2,
    #[size = 8] #[mask_next_row] M3,
    #[size = 8] #[mask_next_row] M4,
    #[size = 8] #[mask_next_row] M5,
    #[size = 8] #[mask_next_row] M6,
    #[size = 8] #[mask_next_row] M7,
    #[size = 8] #[mask_next_row] M8,
    #[size = 8] #[mask_next_row] M9,
    #[size = 8] #[mask_next_row] M10,
    #[size = 8] #[mask_next_row] M11,
    #[size = 8] #[mask_next_row] M12,
    #[size = 8] #[mask_next_row] M13,
    #[size = 8] #[mask_next_row] M14,
    #[size = 8] #[mask_next_row] M15,
    // ── Compression-level inputs (h, t, f) ──────────────────────
    // Replicated across all 96 rows of a compression (inter-row equality
    // keeps them constant).  At row 0 of each compression the V witnesses
    // are constrained to the Blake2b initial state derived from these
    // fields and the IV: V[0..8]=H, V[8..12]=IV[0..4], V[12]=IV[4]^T_lo,
    // V[13]=IV[5]^T_hi, V[14]=IV[6] XOR (F ? !0 : 0), V[15]=IV[7].
    #[size = 8] #[mask_next_row] H0,
    #[size = 8] #[mask_next_row] H1,
    #[size = 8] #[mask_next_row] H2,
    #[size = 8] #[mask_next_row] H3,
    #[size = 8] #[mask_next_row] H4,
    #[size = 8] #[mask_next_row] H5,
    #[size = 8] #[mask_next_row] H6,
    #[size = 8] #[mask_next_row] H7,
    /// T as 16 LE bytes (u128 counter).
    #[size = 16] #[mask_next_row] T,
    /// Finalisation flag in {0,1}.
    #[size = 1] #[mask_next_row] F,
    /// Hi nibble of each T byte, for the AND-nibble lookup emitted below.
    #[size = 16] THi,
    /// and_t_lo[i] = IV[4][i] & T[i]; and_t_hi[i] = IV[5][i] & T[8+i].
    /// Together they let initial_v[12]/[13] be expressed via the XOR identity.
    #[size = 8] AndTLo,
    #[size = 8] AndTHi,
    #[size = 8] AndTLoHi,
    #[size = 8] AndTHiHi,
    // Snapshot of v[0..16] at the start of this row's G-call. Each V{k} is the
    // 8 LE bytes of v[k]. Marked mask_next_row so the state-update constraint
    // can reference row N+1's V for row N's inter-row constraint.
    #[size = 8] #[mask_next_row] V0,
    #[size = 8] #[mask_next_row] V1,
    #[size = 8] #[mask_next_row] V2,
    #[size = 8] #[mask_next_row] V3,
    #[size = 8] #[mask_next_row] V4,
    #[size = 8] #[mask_next_row] V5,
    #[size = 8] #[mask_next_row] V6,
    #[size = 8] #[mask_next_row] V7,
    #[size = 8] #[mask_next_row] V8,
    #[size = 8] #[mask_next_row] V9,
    #[size = 8] #[mask_next_row] V10,
    #[size = 8] #[mask_next_row] V11,
    #[size = 8] #[mask_next_row] V12,
    #[size = 8] #[mask_next_row] V13,
    #[size = 8] #[mask_next_row] V14,
    #[size = 8] #[mask_next_row] V15,
    // ── Output derivation at last row of compression ────────────
    // Only constrained at IsLastOfCompression·IsReal rows; zeroes elsewhere.
    // output[i_word][i_byte] = H[i][j] XOR V_after[i][j] XOR V_after[i+8][j].
    // V_after is not a witness — it equals update_expr(k, j) at this row,
    // where IsGIdx_7=1 selects the diagonal G_INDICES[7]=[3,4,9,14].
    /// Claimed output = H ^ V_after[0..8] ^ V_after[8..16].  8 words × 8 bytes.
    #[size = 64] Output,
    /// Hi nibble of H (all 8 words × 8 bytes) for nibble-AND lookups on And1.
    #[size = 64] HHi,
    /// Hi nibble of V_after[k] for k in 0..16, all 8 bytes each.  Validates
    /// the implicit V_after expression as a byte via the AND nibble lookup.
    #[size = 128] VAfterHi,
    /// OutAnd1[i][j] = H[i][j] & V_after[i][j].  8 words × 8 bytes.
    #[size = 64] OutAnd1,
    #[size = 64] OutAnd1Hi,
    /// Hi nibble of OutXor1[i][j] = H[i][j] XOR V_after[i][j].
    #[size = 64] OutXor1Hi,
    /// OutAnd2[i][j] = OutXor1[i][j] & V_after[i+8][j].  8 words × 8 bytes.
    #[size = 64] OutAnd2,
    #[size = 64] OutAnd2Hi,
    // ── Phase 8b: ECALL memory binding ──────────────────────────
    // HPtr / MPtr are the register values φ[10]/φ[11] at the ECALL step,
    // CallTs is its timestamp.  Inter-row equality keeps them constant
    // within a compression so the 256 byte-level memory lookups emitted
    // at IsFirstOfCompression reference well-defined values.
    #[size = 4] #[mask_next_row] HPtr,
    #[size = 4] #[mask_next_row] MPtr,
    #[size = 8] #[mask_next_row] CallTs,
    /// Byte addresses for the 64 h-read lookups: HRdAddr_b*[i] holds byte
    /// `b` of `HPtr + i` for i ∈ 0..64.  4 columns of size 64 each = 256
    /// cells, avoiding the NonZeroU8 size cap (max 255 per variant).
    #[size = 64] HRdAddrB0,
    #[size = 64] HRdAddrB1,
    #[size = 64] HRdAddrB2,
    #[size = 64] HRdAddrB3,
    /// Byte addresses for the 128 m-read lookups.
    #[size = 128] MRdAddrB0,
    #[size = 128] MRdAddrB1,
    #[size = 128] MRdAddrB2,
    #[size = 128] MRdAddrB3,
    /// Byte addresses for the 64 output-write lookups.
    #[size = 64] HWrAddrB0,
    #[size = 64] HWrAddrB1,
    #[size = 64] HWrAddrB2,
    #[size = 64] HWrAddrB3,
    // Row type
    #[size = 1] IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "blake2b"]
pub enum PreprocessedColumn {
    /// Selector: row r has IsGIdx[j] = 1 iff (r % 8) == j.  G_INDICES is
    /// constant per round, so these 8 selectors determine (ai, bi, ci, di)
    /// for every row without needing a round column.
    #[size = 1] IsGIdx0,
    #[size = 1] IsGIdx1,
    #[size = 1] IsGIdx2,
    #[size = 1] IsGIdx3,
    #[size = 1] IsGIdx4,
    #[size = 1] IsGIdx5,
    #[size = 1] IsGIdx6,
    #[size = 1] IsGIdx7,
    /// 1 iff (r % 96) == 95 — last G-call of a compression.  The row-chaining
    /// constraint is gated off at these rows because V_next belongs to the
    /// next (independently-initialised) compression.
    #[size = 1] IsLastOfCompression,
    /// 1 iff (r % 96) == 0 — first G-call of a compression.  Reserved for
    /// the Phase 2 initial-state derivation constraint; currently unused.
    #[size = 1] IsFirstOfCompression,
    /// IsMxSlot[k] = 1 iff SIGMA[round(r)][2·g_idx(r)] == k (ie this row's
    /// Mx comes from message slot k).  round(r) = (r % 96) / 8,
    /// g_idx(r) = r % 8.
    #[size = 1] IsMxSlot0,
    #[size = 1] IsMxSlot1,
    #[size = 1] IsMxSlot2,
    #[size = 1] IsMxSlot3,
    #[size = 1] IsMxSlot4,
    #[size = 1] IsMxSlot5,
    #[size = 1] IsMxSlot6,
    #[size = 1] IsMxSlot7,
    #[size = 1] IsMxSlot8,
    #[size = 1] IsMxSlot9,
    #[size = 1] IsMxSlot10,
    #[size = 1] IsMxSlot11,
    #[size = 1] IsMxSlot12,
    #[size = 1] IsMxSlot13,
    #[size = 1] IsMxSlot14,
    #[size = 1] IsMxSlot15,
    /// IsMySlot[k] = 1 iff SIGMA[round(r)][2·g_idx(r) + 1] == k.
    #[size = 1] IsMySlot0,
    #[size = 1] IsMySlot1,
    #[size = 1] IsMySlot2,
    #[size = 1] IsMySlot3,
    #[size = 1] IsMySlot4,
    #[size = 1] IsMySlot5,
    #[size = 1] IsMySlot6,
    #[size = 1] IsMySlot7,
    #[size = 1] IsMySlot8,
    #[size = 1] IsMySlot9,
    #[size = 1] IsMySlot10,
    #[size = 1] IsMySlot11,
    #[size = 1] IsMySlot12,
    #[size = 1] IsMySlot13,
    #[size = 1] IsMySlot14,
    #[size = 1] IsMySlot15,
}

// ── Software blake2b ─────────────────────────────────────────

pub fn blake2b_compress(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if f { v[14] = !v[14]; }

    for round in 0..12 {
        let s = &SIGMA[round];
        for g_idx in 0..8 {
            let [ai, bi, ci, di] = G_INDICES[g_idx];
            let (mx_idx, my_idx) = if g_idx < 4 {
                (s[2 * g_idx], s[2 * g_idx + 1])
            } else {
                (s[2 * g_idx], s[2 * g_idx + 1])
            };
            g_func(&mut v, ai, bi, ci, di, m[mx_idx], m[my_idx]);
        }
    }

    let mut result = [0u64; 8];
    for i in 0..8 { result[i] = h[i] ^ v[i] ^ v[i + 8]; }
    result
}

fn g_func(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, mx: u64, my: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

// ── Trace generation ─────────────────────────────────────────

/// A single G-function row with all intermediate witness data.
struct GRow {
    a_in: [u8; 8], b_in: [u8; 8], c_in: [u8; 8], d_in: [u8; 8],
    mx: [u8; 8], my: [u8; 8],
    a1: [u8; 8], carry1: [u8; 8],
    and1: [u8; 8], // d & a1
    c1: [u8; 8], carry2: [u8; 8],
    and2: [u8; 8], // b & c1
    a_out: [u8; 8], carry3: [u8; 8],
    and3: [u8; 8], // d1 & a_out
    c_out: [u8; 8], carry4: [u8; 8],
    and4: [u8; 8], // b1 & c_out
    b_out: [u8; 8], rot63_carry: [u8; 8],
    /// d_out = (d1 ^ a_out) rotated right 16.  Materialised so the row-chain
    /// constraint can forward it into V_next[di].
    d_out: [u8; 8],
    // Hi nibbles for AND lookups.  AxHi/BxHi are the hi nibbles of the two AND
    // operands (in the byte ordering used by AndN); ResxHi is the hi nibble of
    // the AND result byte.  For And3/And4 the A-side input is a derived byte
    // (d1/b1), so AxHi is the hi nibble of that derived byte.
    and1_a_hi: [u8; 8], and1_b_hi: [u8; 8], and1_res_hi: [u8; 8],
    and2_a_hi: [u8; 8], and2_b_hi: [u8; 8], and2_res_hi: [u8; 8],
    and3_a_hi: [u8; 8], and3_b_hi: [u8; 8], and3_res_hi: [u8; 8],
    and4_a_hi: [u8; 8], and4_b_hi: [u8; 8], and4_res_hi: [u8; 8],
    /// Snapshot of v[0..16] as LE bytes at the START of this row's G-call.
    v: [[u8; 8]; 16],
    /// Full message m[0..16] (LE bytes) for the compression this row belongs
    /// to.  Replicated per row so the per-row Mx/My = M[sigma_idx] constraint
    /// can be local; inter-row equality keeps M constant inside a compression.
    m: [[u8; 8]; 16],
    /// Compression inputs, replicated across the 96 rows of this compression.
    h: [[u8; 8]; 8],
    t: [u8; 16],
    f: u8,
    t_hi: [u8; 16],
    and_t_lo: [u8; 8],
    and_t_hi: [u8; 8],
    and_t_lo_hi: [u8; 8],
    and_t_hi_hi: [u8; 8],
    // ── Output derivation, only non-zero at the last row of a compression
    output: [u8; 64],
    h_hi: [u8; 64],
    v_after_hi: [u8; 128],
    out_and1: [u8; 64],
    out_and1_hi: [u8; 64],
    out_xor1_hi: [u8; 64],
    out_and2: [u8; 64],
    out_and2_hi: [u8; 64],
    // ── ECALL memory-binding witnesses, constant across the 96 rows of a
    // compression; address columns only referenced at IsFirstOfCompression.
    h_ptr: [u8; 4],
    m_ptr: [u8; 4],
    call_ts: [u8; 8],
    h_rd_addr: [u8; 256],
    m_rd_addr: [u8; 512],
    h_wr_addr: [u8; 256],
}

/// Execute one G-function and capture all intermediate values.  `v_snapshot`
/// is the full v[0..16] state at the start of this G-call (LE bytes); the
/// row-chain constraint requires it in the trace.  `m_full` is the full 16-
/// slot message for the compression this row belongs to.  `call_h`, `call_t`
/// and `call_f` are the compression-level inputs replicated on every row
/// for the initial-state derivation.
fn g_traced(
    v_snapshot: &[u64; 16],
    m_full: &[u64; 16],
    call_h: &[u64; 8],
    call_t: u128,
    call_f: bool,
    a: u64, b: u64, c: u64, d: u64, mx: u64, my: u64,
) -> GRow {
    let a_in = a.to_le_bytes();
    let b_in = b.to_le_bytes();
    let c_in = c.to_le_bytes();
    let d_in = d.to_le_bytes();
    let mx_b = mx.to_le_bytes();
    let my_b = my.to_le_bytes();

    // Step 1: a1 = a + b + mx
    let a1_val = a.wrapping_add(b).wrapping_add(mx);
    let a1 = a1_val.to_le_bytes();
    let carry1 = add_carry_chain(&a_in, &b_in, &mx_b);

    // Step 2: xor1 = d ^ a1, d1 = xor1 >>> 32 (byte swap)
    let xor1_val = d ^ a1_val;
    let and1 = byte_and(&d_in, &a1);
    let d1_val = xor1_val.rotate_right(32);

    // Step 3: c1 = c + d1
    let c1_val = c.wrapping_add(d1_val);
    let c1 = c1_val.to_le_bytes();
    let d1_bytes = d1_val.to_le_bytes();
    let carry2 = add_carry_chain_2(&c_in, &d1_bytes);

    // Step 4: xor2 = b ^ c1, b1 = xor2 >>> 24
    let xor2_val = b ^ c1_val;
    let and2 = byte_and(&b_in, &c1);
    let b1_val = xor2_val.rotate_right(24);

    // Step 5: a_out = a1 + b1 + my
    let a_out_val = a1_val.wrapping_add(b1_val).wrapping_add(my);
    let a_out = a_out_val.to_le_bytes();
    let b1_bytes = b1_val.to_le_bytes();
    let carry3 = add_carry_chain(&a1, &b1_bytes, &my_b);

    // Step 6: xor3 = d1 ^ a_out, d_out = xor3 >>> 16
    let xor3_val = d1_val ^ a_out_val;
    let and3 = byte_and(&d1_bytes, &a_out);
    let d_out_val = xor3_val.rotate_right(16);

    // Step 7: c_out = c1 + d_out
    let c_out_val = c1_val.wrapping_add(d_out_val);
    let c_out = c_out_val.to_le_bytes();
    let d_out_bytes = d_out_val.to_le_bytes();
    let carry4 = add_carry_chain_2(&c1, &d_out_bytes);

    // Step 8: xor4 = b1 ^ c_out, b_out = xor4 >>> 63
    let xor4_val = b1_val ^ c_out_val;
    let and4 = byte_and(&b1_bytes, &c_out);
    let b_out_val = xor4_val.rotate_right(63);
    let b_out = b_out_val.to_le_bytes();
    let rot63_carry = rot63_carries(&xor4_val.to_le_bytes());

    // Hi nibbles for AND lookups.
    let and1_a_hi = hi_nibbles(&d_in);
    let and1_b_hi = hi_nibbles(&a1);
    let and1_res_hi = hi_nibbles(&and1);
    let and2_a_hi = hi_nibbles(&b_in);
    let and2_b_hi = hi_nibbles(&c1);
    let and2_res_hi = hi_nibbles(&and2);
    let and3_a_hi = hi_nibbles(&d1_bytes); // derived: d1 = (d_in ^ a1) >>> 32
    let and3_b_hi = hi_nibbles(&a_out);
    let and3_res_hi = hi_nibbles(&and3);
    let and4_a_hi = hi_nibbles(&b1_bytes); // derived: b1 = (b_in ^ c1) >>> 24
    let and4_b_hi = hi_nibbles(&c_out);
    let and4_res_hi = hi_nibbles(&and4);

    let d_out = d_out_val.to_le_bytes();

    let mut v_bytes = [[0u8; 8]; 16];
    for k in 0..16 { v_bytes[k] = v_snapshot[k].to_le_bytes(); }
    let mut m_bytes = [[0u8; 8]; 16];
    for k in 0..16 { m_bytes[k] = m_full[k].to_le_bytes(); }
    let mut h_bytes = [[0u8; 8]; 8];
    for k in 0..8 { h_bytes[k] = call_h[k].to_le_bytes(); }
    let t_bytes = call_t.to_le_bytes();
    let mut t_hi_bytes = [0u8; 16];
    for i in 0..16 { t_hi_bytes[i] = t_bytes[i] >> 4; }
    let mut and_t_lo = [0u8; 8];
    let mut and_t_hi = [0u8; 8];
    for i in 0..8 {
        and_t_lo[i] = IV[4].to_le_bytes()[i] & t_bytes[i];
        and_t_hi[i] = IV[5].to_le_bytes()[i] & t_bytes[8 + i];
    }
    let mut and_t_lo_hi = [0u8; 8];
    let mut and_t_hi_hi = [0u8; 8];
    for i in 0..8 {
        and_t_lo_hi[i] = and_t_lo[i] >> 4;
        and_t_hi_hi[i] = and_t_hi[i] >> 4;
    }

    GRow {
        a_in, b_in, c_in, d_in, mx: mx_b, my: my_b,
        a1, carry1, and1, c1, carry2, and2,
        a_out, carry3, and3, c_out, carry4, and4,
        b_out, rot63_carry, d_out,
        and1_a_hi, and1_b_hi, and1_res_hi,
        and2_a_hi, and2_b_hi, and2_res_hi,
        and3_a_hi, and3_b_hi, and3_res_hi,
        and4_a_hi, and4_b_hi, and4_res_hi,
        v: v_bytes,
        m: m_bytes,
        h: h_bytes,
        t: t_bytes,
        f: call_f as u8,
        t_hi: t_hi_bytes,
        and_t_lo,
        and_t_hi,
        and_t_lo_hi,
        and_t_hi_hi,
        // Phase 2b witnesses are zero by default; the trace-gen loop fills
        // them on the last row of each compression.
        output: [0u8; 64],
        h_hi: [0u8; 64],
        v_after_hi: [0u8; 128],
        out_and1: [0u8; 64],
        out_and1_hi: [0u8; 64],
        out_xor1_hi: [0u8; 64],
        out_and2: [0u8; 64],
        out_and2_hi: [0u8; 64],
        // Phase 8b ECALL-binding witnesses — filled by the outer loop from
        // the matching blake2b_mem_op (or zero if none).  Address columns
        // are deterministic from HPtr/MPtr plus the byte offset.
        h_ptr: [0u8; 4],
        m_ptr: [0u8; 4],
        call_ts: [0u8; 8],
        h_rd_addr: [0u8; 256],
        m_rd_addr: [0u8; 512],
        h_wr_addr: [0u8; 256],
    }
}

/// Derive v_after[0..16] at the final row of a compression (g_idx=7) from the
/// row's starting V plus the just-updated touched slots.  G_INDICES[7] =
/// [3, 4, 9, 14], so the a/b/c/d outputs land at those positions.
fn row_v_after(r: &GRow) -> [[u8; 8]; 16] {
    let mut v_after = r.v;
    v_after[3] = r.a_out;
    v_after[4] = r.b_out;
    v_after[9] = r.c_out;
    v_after[14] = r.d_out;
    v_after
}

/// Fill the Phase 2b output-derivation witnesses on the last row of a
/// compression.  `v_after` is the v[0..16] state AFTER this row's G-call.
fn fill_output_witnesses(row: &mut GRow, v_after: &[u64; 16]) {
    let mut v_after_bytes = [[0u8; 8]; 16];
    for k in 0..16 { v_after_bytes[k] = v_after[k].to_le_bytes(); }

    for i in 0..8 {
        for j in 0..8 {
            let h_b = row.h[i][j];
            let v1 = v_after_bytes[i][j];
            let v2 = v_after_bytes[i + 8][j];
            let and1 = h_b & v1;
            let xor1 = h_b ^ v1;
            let and2 = xor1 & v2;
            let out = xor1 ^ v2;
            let slot = i * 8 + j;
            row.h_hi[slot] = h_b >> 4;
            row.out_and1[slot] = and1;
            row.out_and1_hi[slot] = and1 >> 4;
            row.out_xor1_hi[slot] = xor1 >> 4;
            row.out_and2[slot] = and2;
            row.out_and2_hi[slot] = and2 >> 4;
            row.output[slot] = out;
        }
    }
    for k in 0..16 {
        for j in 0..8 {
            row.v_after_hi[k * 8 + j] = v_after_bytes[k][j] >> 4;
        }
    }
}

fn hi_nibbles(bytes: &[u8; 8]) -> [u8; 8] {
    let mut r = [0u8; 8];
    for i in 0..8 { r[i] = bytes[i] >> 4; }
    r
}

fn byte_and(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut r = [0u8; 8];
    for i in 0..8 { r[i] = a[i] & b[i]; }
    r
}

/// 3-input addition carry chain: a + b + c mod 2^64
fn add_carry_chain(a: &[u8; 8], b: &[u8; 8], c: &[u8; 8]) -> [u8; 8] {
    let mut carry = [0u8; 8];
    let mut c_val: u16 = 0;
    for i in 0..8 {
        let sum = a[i] as u16 + b[i] as u16 + c[i] as u16 + c_val;
        carry[i] = (sum >> 8) as u8;
        c_val = carry[i] as u16;
    }
    carry
}

/// 2-input addition carry chain: a + b mod 2^64
fn add_carry_chain_2(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let zero = [0u8; 8];
    add_carry_chain(a, b, &zero)
}

/// Carry bits for left-rotate-by-1 (= right-rotate by 63)
fn rot63_carries(input: &[u8; 8]) -> [u8; 8] {
    let mut carry = [0u8; 8];
    for i in 0..8 { carry[i] = input[i] >> 7; }
    carry
}

impl BuiltInComponent for Blake2bChip {
    // Carry bound identity is_real · c · (c-1) · (c-2) is degree 4, so require
    // the same bound that CpuChip uses.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        Range256LookupElements,
        BitwiseAndLookupElements,
        MemoryAccessLookupElements,
        Blake2bCallLookupElements,
    );

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        // Schedule is deterministic per-row: r mod 8 picks g_idx, r mod 96
        // identifies position in a compression.  Every row gets a value
        // (including padding rows past the real compression span) — the
        // IsReal witness gates the state-chain constraint.
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        const GIDX_COLS: [PreprocessedColumn; 8] = [
            PreprocessedColumn::IsGIdx0, PreprocessedColumn::IsGIdx1,
            PreprocessedColumn::IsGIdx2, PreprocessedColumn::IsGIdx3,
            PreprocessedColumn::IsGIdx4, PreprocessedColumn::IsGIdx5,
            PreprocessedColumn::IsGIdx6, PreprocessedColumn::IsGIdx7,
        ];
        const MX_SLOT_COLS: [PreprocessedColumn; 16] = [
            PreprocessedColumn::IsMxSlot0, PreprocessedColumn::IsMxSlot1,
            PreprocessedColumn::IsMxSlot2, PreprocessedColumn::IsMxSlot3,
            PreprocessedColumn::IsMxSlot4, PreprocessedColumn::IsMxSlot5,
            PreprocessedColumn::IsMxSlot6, PreprocessedColumn::IsMxSlot7,
            PreprocessedColumn::IsMxSlot8, PreprocessedColumn::IsMxSlot9,
            PreprocessedColumn::IsMxSlot10, PreprocessedColumn::IsMxSlot11,
            PreprocessedColumn::IsMxSlot12, PreprocessedColumn::IsMxSlot13,
            PreprocessedColumn::IsMxSlot14, PreprocessedColumn::IsMxSlot15,
        ];
        const MY_SLOT_COLS: [PreprocessedColumn; 16] = [
            PreprocessedColumn::IsMySlot0, PreprocessedColumn::IsMySlot1,
            PreprocessedColumn::IsMySlot2, PreprocessedColumn::IsMySlot3,
            PreprocessedColumn::IsMySlot4, PreprocessedColumn::IsMySlot5,
            PreprocessedColumn::IsMySlot6, PreprocessedColumn::IsMySlot7,
            PreprocessedColumn::IsMySlot8, PreprocessedColumn::IsMySlot9,
            PreprocessedColumn::IsMySlot10, PreprocessedColumn::IsMySlot11,
            PreprocessedColumn::IsMySlot12, PreprocessedColumn::IsMySlot13,
            PreprocessedColumn::IsMySlot14, PreprocessedColumn::IsMySlot15,
        ];
        for row in 0..num_rows {
            let g_idx = row % 8;
            trace.fill_columns(row, true, GIDX_COLS[g_idx]);
            let pos_in_compression = row % 96;
            if pos_in_compression == 0 {
                trace.fill_columns(row, true, PreprocessedColumn::IsFirstOfCompression);
            }
            if pos_in_compression == 95 {
                trace.fill_columns(row, true, PreprocessedColumn::IsLastOfCompression);
            }
            // Derive mx_idx / my_idx from SIGMA: round = (r%96)/8, g_idx = r%8.
            let round = pos_in_compression / 8;
            let mx_idx = SIGMA[round][2 * g_idx];
            let my_idx = SIGMA[round][2 * g_idx + 1];
            trace.fill_columns(row, true, MX_SLOT_COLS[mx_idx]);
            trace.fill_columns(row, true, MY_SLOT_COLS[my_idx]);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        if side_note.blake2b_calls.is_empty() {
            let log_size = LOG_N_LANES;
            let trace = TraceBuilder::<Column>::new(log_size);
            return trace.finalize_bit_reversed();
        }

        let mut rows: Vec<GRow> = Vec::new();
        for (call_idx, call) in side_note.blake2b_calls.iter().enumerate() {
            let mut v = [0u64; 16];
            v[..8].copy_from_slice(&call.h);
            v[8..].copy_from_slice(&IV);
            v[12] ^= call.t as u64;
            v[13] ^= (call.t >> 64) as u64;
            if call.f { v[14] = !v[14]; }

            // Phase 8b ECALL-binding data for this compression, if a matching
            // blake2b_mem_op was recorded by the tracer.
            let mem_op = side_note.blake2b_mem_ops.get(call_idx);
            let h_ptr = mem_op.map(|o| o.h_ptr).unwrap_or(0).to_le_bytes();
            let m_ptr = mem_op.map(|o| o.m_ptr).unwrap_or(0).to_le_bytes();
            let call_ts_u = mem_op.map(|o| o.ts).unwrap_or(0);
            let call_ts = call_ts_u.to_le_bytes();
            let h_ptr_u32 = u32::from_le_bytes(h_ptr);
            let m_ptr_u32 = u32::from_le_bytes(m_ptr);
            let mut h_rd_addr = [0u8; 256];
            for i in 0..64 {
                let addr = h_ptr_u32.wrapping_add(i as u32).to_le_bytes();
                h_rd_addr[i * 4..i * 4 + 4].copy_from_slice(&addr);
            }
            let mut m_rd_addr = [0u8; 512];
            for k in 0..128 {
                let addr = m_ptr_u32.wrapping_add(k as u32).to_le_bytes();
                m_rd_addr[k * 4..k * 4 + 4].copy_from_slice(&addr);
            }
            let mut h_wr_addr = [0u8; 256];
            for i in 0..64 {
                let addr = h_ptr_u32.wrapping_add(i as u32).to_le_bytes();
                h_wr_addr[i * 4..i * 4 + 4].copy_from_slice(&addr);
            }

            for round in 0..12 {
                let s = &SIGMA[round];
                for g_idx in 0..8 {
                    let [ai, bi, ci, di] = G_INDICES[g_idx];
                    let mx = call.m[s[2 * g_idx]];
                    let my = call.m[s[2 * g_idx + 1]];

                    let mut row = g_traced(
                        &v, &call.m, &call.h, call.t, call.f,
                        v[ai], v[bi], v[ci], v[di], mx, my,
                    );

                    v[ai] = u64::from_le_bytes(row.a_out);
                    v[bi] = u64::from_le_bytes(row.b_out);
                    v[ci] = u64::from_le_bytes(row.c_out);
                    v[di] = u64::from_le_bytes(row.d_out);

                    // Final G-call of this compression → populate Phase 2b
                    // output witnesses from the just-updated v.
                    if round == 11 && g_idx == 7 {
                        fill_output_witnesses(&mut row, &v);
                    }

                    // Phase 8b ECALL-binding fields, constant across 96 rows.
                    row.h_ptr = h_ptr;
                    row.m_ptr = m_ptr;
                    row.call_ts = call_ts;
                    row.h_rd_addr = h_rd_addr;
                    row.m_rd_addr = m_rd_addr;
                    row.h_wr_addr = h_wr_addr;

                    rows.push(row);
                }
            }
        }

        let num_rows = rows.len();
        let log_size = ((num_rows as f64).log2().ceil() as u32).max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for (row_idx, r) in rows.iter().enumerate() {
            trace.fill_columns_bytes(row_idx, &r.a_in, Column::AIn);
            trace.fill_columns_bytes(row_idx, &r.b_in, Column::BIn);
            trace.fill_columns_bytes(row_idx, &r.c_in, Column::CIn);
            trace.fill_columns_bytes(row_idx, &r.d_in, Column::DIn);
            trace.fill_columns_bytes(row_idx, &r.mx, Column::Mx);
            trace.fill_columns_bytes(row_idx, &r.my, Column::My);
            trace.fill_columns_bytes(row_idx, &r.a1, Column::A1);
            trace.fill_columns_bytes(row_idx, &r.carry1, Column::Carry1);
            trace.fill_columns_bytes(row_idx, &r.and1, Column::And1);
            trace.fill_columns_bytes(row_idx, &r.c1, Column::C1);
            trace.fill_columns_bytes(row_idx, &r.carry2, Column::Carry2);
            trace.fill_columns_bytes(row_idx, &r.and2, Column::And2);
            trace.fill_columns_bytes(row_idx, &r.a_out, Column::AOut);
            trace.fill_columns_bytes(row_idx, &r.carry3, Column::Carry3);
            trace.fill_columns_bytes(row_idx, &r.and3, Column::And3);
            trace.fill_columns_bytes(row_idx, &r.c_out, Column::COut);
            trace.fill_columns_bytes(row_idx, &r.carry4, Column::Carry4);
            trace.fill_columns_bytes(row_idx, &r.and4, Column::And4);
            trace.fill_columns_bytes(row_idx, &r.b_out, Column::BOut);
            trace.fill_columns_bytes(row_idx, &r.rot63_carry, Column::Rot63Carry);
            trace.fill_columns_bytes(row_idx, &r.and1_a_hi, Column::And1AHi);
            trace.fill_columns_bytes(row_idx, &r.and1_b_hi, Column::And1BHi);
            trace.fill_columns_bytes(row_idx, &r.and1_res_hi, Column::And1ResHi);
            trace.fill_columns_bytes(row_idx, &r.and2_a_hi, Column::And2AHi);
            trace.fill_columns_bytes(row_idx, &r.and2_b_hi, Column::And2BHi);
            trace.fill_columns_bytes(row_idx, &r.and2_res_hi, Column::And2ResHi);
            trace.fill_columns_bytes(row_idx, &r.and3_a_hi, Column::And3AHi);
            trace.fill_columns_bytes(row_idx, &r.and3_b_hi, Column::And3BHi);
            trace.fill_columns_bytes(row_idx, &r.and3_res_hi, Column::And3ResHi);
            trace.fill_columns_bytes(row_idx, &r.and4_a_hi, Column::And4AHi);
            trace.fill_columns_bytes(row_idx, &r.and4_b_hi, Column::And4BHi);
            trace.fill_columns_bytes(row_idx, &r.and4_res_hi, Column::And4ResHi);
            trace.fill_columns_bytes(row_idx, &r.d_out, Column::DOut);
            const V_COLS: [Column; 16] = [
                Column::V0, Column::V1, Column::V2, Column::V3,
                Column::V4, Column::V5, Column::V6, Column::V7,
                Column::V8, Column::V9, Column::V10, Column::V11,
                Column::V12, Column::V13, Column::V14, Column::V15,
            ];
            for k in 0..16 {
                trace.fill_columns_bytes(row_idx, &r.v[k], V_COLS[k]);
            }
            const M_COLS: [Column; 16] = [
                Column::M0, Column::M1, Column::M2, Column::M3,
                Column::M4, Column::M5, Column::M6, Column::M7,
                Column::M8, Column::M9, Column::M10, Column::M11,
                Column::M12, Column::M13, Column::M14, Column::M15,
            ];
            for k in 0..16 {
                trace.fill_columns_bytes(row_idx, &r.m[k], M_COLS[k]);
            }
            // Compression-level inputs.
            const H_COLS: [Column; 8] = [
                Column::H0, Column::H1, Column::H2, Column::H3,
                Column::H4, Column::H5, Column::H6, Column::H7,
            ];
            for k in 0..8 {
                trace.fill_columns_bytes(row_idx, &r.h[k], H_COLS[k]);
            }
            trace.fill_columns_bytes(row_idx, &r.t, Column::T);
            trace.fill_columns(row_idx, r.f, Column::F);
            trace.fill_columns_bytes(row_idx, &r.t_hi, Column::THi);
            trace.fill_columns_bytes(row_idx, &r.and_t_lo, Column::AndTLo);
            trace.fill_columns_bytes(row_idx, &r.and_t_hi, Column::AndTHi);
            trace.fill_columns_bytes(row_idx, &r.and_t_lo_hi, Column::AndTLoHi);
            trace.fill_columns_bytes(row_idx, &r.and_t_hi_hi, Column::AndTHiHi);
            // Phase 2b output-derivation witnesses (0 on non-last rows).
            trace.fill_columns_bytes(row_idx, &r.output, Column::Output);
            trace.fill_columns_bytes(row_idx, &r.h_hi, Column::HHi);
            trace.fill_columns_bytes(row_idx, &r.v_after_hi, Column::VAfterHi);
            trace.fill_columns_bytes(row_idx, &r.out_and1, Column::OutAnd1);
            trace.fill_columns_bytes(row_idx, &r.out_and1_hi, Column::OutAnd1Hi);
            trace.fill_columns_bytes(row_idx, &r.out_xor1_hi, Column::OutXor1Hi);
            trace.fill_columns_bytes(row_idx, &r.out_and2, Column::OutAnd2);
            trace.fill_columns_bytes(row_idx, &r.out_and2_hi, Column::OutAnd2Hi);
            // Phase 8b ECALL-binding witnesses.
            trace.fill_columns_bytes(row_idx, &r.h_ptr, Column::HPtr);
            trace.fill_columns_bytes(row_idx, &r.m_ptr, Column::MPtr);
            trace.fill_columns_bytes(row_idx, &r.call_ts, Column::CallTs);
            // Split 4-byte-wide address arrays into per-byte slices.
            {
                let mut b0 = [0u8; 64]; let mut b1 = [0u8; 64];
                let mut b2 = [0u8; 64]; let mut b3 = [0u8; 64];
                for i in 0..64 {
                    b0[i] = r.h_rd_addr[i * 4];
                    b1[i] = r.h_rd_addr[i * 4 + 1];
                    b2[i] = r.h_rd_addr[i * 4 + 2];
                    b3[i] = r.h_rd_addr[i * 4 + 3];
                }
                trace.fill_columns_bytes(row_idx, &b0, Column::HRdAddrB0);
                trace.fill_columns_bytes(row_idx, &b1, Column::HRdAddrB1);
                trace.fill_columns_bytes(row_idx, &b2, Column::HRdAddrB2);
                trace.fill_columns_bytes(row_idx, &b3, Column::HRdAddrB3);
            }
            {
                let mut b0 = [0u8; 128]; let mut b1 = [0u8; 128];
                let mut b2 = [0u8; 128]; let mut b3 = [0u8; 128];
                for k in 0..128 {
                    b0[k] = r.m_rd_addr[k * 4];
                    b1[k] = r.m_rd_addr[k * 4 + 1];
                    b2[k] = r.m_rd_addr[k * 4 + 2];
                    b3[k] = r.m_rd_addr[k * 4 + 3];
                }
                trace.fill_columns_bytes(row_idx, &b0, Column::MRdAddrB0);
                trace.fill_columns_bytes(row_idx, &b1, Column::MRdAddrB1);
                trace.fill_columns_bytes(row_idx, &b2, Column::MRdAddrB2);
                trace.fill_columns_bytes(row_idx, &b3, Column::MRdAddrB3);
            }
            {
                let mut b0 = [0u8; 64]; let mut b1 = [0u8; 64];
                let mut b2 = [0u8; 64]; let mut b3 = [0u8; 64];
                for i in 0..64 {
                    b0[i] = r.h_wr_addr[i * 4];
                    b1[i] = r.h_wr_addr[i * 4 + 1];
                    b2[i] = r.h_wr_addr[i * 4 + 2];
                    b3[i] = r.h_wr_addr[i * 4 + 3];
                }
                trace.fill_columns_bytes(row_idx, &b0, Column::HWrAddrB0);
                trace.fill_columns_bytes(row_idx, &b1, Column::HWrAddrB1);
                trace.fill_columns_bytes(row_idx, &b2, Column::HWrAddrB2);
                trace.fill_columns_bytes(row_idx, &b3, Column::HWrAddrB3);
            }
            trace.fill_columns(row_idx, true, Column::IsReal);

            // Emit per-byte nibble counts.  add_bitwise_and increments both the
            // hi-nibble and lo-nibble (a, b) cell in the 16×16 BitwiseLookup
            // multiplicity table.
            //
            // And3 A-side is d1[k] = (d^a1 rotated right 32) = xor byte at
            // position (k+4)%8.  We reconstruct the true byte value from the
            // trace columns via the XOR identity d_in + a1 - 2·and1 so the
            // multiplicity table stays in sync with the constraint-side
            // derivation.  Same story for And4 A-side (b1).
            for i in 0..8 {
                side_note.add_bitwise_and(r.d_in[i], r.a1[i]);
                side_note.add_bitwise_and(r.b_in[i], r.c1[i]);
                let k3 = (i + 4) % 8;
                let d1_i = r.d_in[k3] ^ r.a1[k3];
                side_note.add_bitwise_and(d1_i, r.a_out[i]);
                let k4 = (i + 3) % 8;
                let b1_i = r.b_in[k4] ^ r.c1[k4];
                side_note.add_bitwise_and(b1_i, r.c_out[i]);
                // Initial-state XOR witnesses: IV[4]/IV[5] are constants, so the
                // nibble multiplicity for their hi/lo nibbles is added here.
                let iv4 = IV[4].to_le_bytes();
                let iv5 = IV[5].to_le_bytes();
                side_note.add_bitwise_and(iv4[i], r.t[i]);
                side_note.add_bitwise_and(iv5[i], r.t[8 + i]);
            }

            // Range-check the inputs/outputs that are not covered by an AND
            // lookup.  D_in/B_in/A1/C1/A_out/C_out/And{1-4} and the derived
            // D1/B1 are all nibble-and-lookup-constrained (hi+lo*16 = byte).
            // The remaining bytes need an explicit Range256 consumer:
            //   A_in, C_in, Mx, My — add-chain operands read by the prover
            //   B_out — rotation output derived from xor4
            for i in 0..8 {
                side_note.add_range256(r.a_in[i]);
                side_note.add_range256(r.c_in[i]);
                side_note.add_range256(r.mx[i]);
                side_note.add_range256(r.my[i]);
                side_note.add_range256(r.b_out[i]);
            }

            // Phase 2b AND counts — only at the last row of each compression.
            // 64 And1 bytes (H & V_after[0..8]) + 64 And2 bytes (Xor1 &
            // V_after[8..16]) = 128 nibble-AND multiplicity increments.
            if row_idx % 96 == 95 {
                let v_after = row_v_after(r);
                for word in 0..8 {
                    for byte in 0..8 {
                        let h_b = r.h[word][byte];
                        let v1 = v_after[word][byte];
                        let v2 = v_after[word + 8][byte];
                        let xor1 = h_b ^ v1;
                        side_note.add_bitwise_and(h_b, v1);
                        side_note.add_bitwise_and(xor1, v2);
                    }
                }
            }
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>, SecureField) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let bitwise: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let is_real = zkpvm_trace::original_base_column!(component_trace, Column::IsReal);
        let a_in = zkpvm_trace::original_base_column!(component_trace, Column::AIn);
        let c_in = zkpvm_trace::original_base_column!(component_trace, Column::CIn);
        let mx = zkpvm_trace::original_base_column!(component_trace, Column::Mx);
        let my = zkpvm_trace::original_base_column!(component_trace, Column::My);
        let b_out = zkpvm_trace::original_base_column!(component_trace, Column::BOut);
        let d_in = zkpvm_trace::original_base_column!(component_trace, Column::DIn);
        let a1 = zkpvm_trace::original_base_column!(component_trace, Column::A1);
        let and1 = zkpvm_trace::original_base_column!(component_trace, Column::And1);
        let b_in = zkpvm_trace::original_base_column!(component_trace, Column::BIn);
        let c1 = zkpvm_trace::original_base_column!(component_trace, Column::C1);
        let and2 = zkpvm_trace::original_base_column!(component_trace, Column::And2);
        let a_out = zkpvm_trace::original_base_column!(component_trace, Column::AOut);
        let and3 = zkpvm_trace::original_base_column!(component_trace, Column::And3);
        let c_out = zkpvm_trace::original_base_column!(component_trace, Column::COut);
        let d_out = zkpvm_trace::original_base_column!(component_trace, Column::DOut);
        let and4 = zkpvm_trace::original_base_column!(component_trace, Column::And4);
        let and1_a_hi = zkpvm_trace::original_base_column!(component_trace, Column::And1AHi);
        let and1_b_hi = zkpvm_trace::original_base_column!(component_trace, Column::And1BHi);
        let and1_res_hi = zkpvm_trace::original_base_column!(component_trace, Column::And1ResHi);
        let and2_a_hi = zkpvm_trace::original_base_column!(component_trace, Column::And2AHi);
        let and2_b_hi = zkpvm_trace::original_base_column!(component_trace, Column::And2BHi);
        let and2_res_hi = zkpvm_trace::original_base_column!(component_trace, Column::And2ResHi);
        let and3_a_hi = zkpvm_trace::original_base_column!(component_trace, Column::And3AHi);
        let and3_b_hi = zkpvm_trace::original_base_column!(component_trace, Column::And3BHi);
        let and3_res_hi = zkpvm_trace::original_base_column!(component_trace, Column::And3ResHi);
        let and4_a_hi = zkpvm_trace::original_base_column!(component_trace, Column::And4AHi);
        let and4_b_hi = zkpvm_trace::original_base_column!(component_trace, Column::And4BHi);
        let and4_res_hi = zkpvm_trace::original_base_column!(component_trace, Column::And4ResHi);

        let sixteen = PackedBaseField::broadcast(BaseField::from(16));
        let two = PackedBaseField::broadcast(BaseField::from(2));

        // For each byte i, emit 8 nibble lookups in order:
        //   And1 hi, And1 lo, And2 hi, And2 lo, And3 hi, And3 lo, And4 hi, And4 lo
        // The constraint-side emission MUST match this order exactly;
        // finalize_logup_in_pairs will pair (hi, lo) per AND.
        for i in 0..8usize {
            // ── And1 = D_in & A1, bytes at position i ──
            logup.add_to_relation_with(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                &[and1_a_hi[i].clone(), and1_b_hi[i].clone(), and1_res_hi[i].clone()],
            );
            let (d_in_i, a1_i, and1_i) = (d_in[i].clone(), a1[i].clone(), and1[i].clone());
            let (and1_a_hi_i, and1_b_hi_i, and1_res_hi_i) =
                (and1_a_hi[i].clone(), and1_b_hi[i].clone(), and1_res_hi[i].clone());
            logup.add_to_relation_computed(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                3,
                move |v| {
                    let a_lo = d_in_i.at(v) - and1_a_hi_i.at(v) * sixteen;
                    let b_lo = a1_i.at(v) - and1_b_hi_i.at(v) * sixteen;
                    let r_lo = and1_i.at(v) - and1_res_hi_i.at(v) * sixteen;
                    vec![a_lo, b_lo, r_lo]
                },
            );

            // ── And2 = B_in & C1, bytes at position i ──
            logup.add_to_relation_with(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                &[and2_a_hi[i].clone(), and2_b_hi[i].clone(), and2_res_hi[i].clone()],
            );
            let (b_in_i, c1_i, and2_i) = (b_in[i].clone(), c1[i].clone(), and2[i].clone());
            let (and2_a_hi_i, and2_b_hi_i, and2_res_hi_i) =
                (and2_a_hi[i].clone(), and2_b_hi[i].clone(), and2_res_hi[i].clone());
            logup.add_to_relation_computed(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                3,
                move |v| {
                    let a_lo = b_in_i.at(v) - and2_a_hi_i.at(v) * sixteen;
                    let b_lo = c1_i.at(v) - and2_b_hi_i.at(v) * sixteen;
                    let r_lo = and2_i.at(v) - and2_res_hi_i.at(v) * sixteen;
                    vec![a_lo, b_lo, r_lo]
                },
            );

            // ── And3 = D1 & A_out, bytes at position i ──
            // D1[i] is derived: D1[i] = D_in[j] + A1[j] - 2·And1[j] where j=(i+4)%8.
            logup.add_to_relation_with(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                &[and3_a_hi[i].clone(), and3_b_hi[i].clone(), and3_res_hi[i].clone()],
            );
            let j3 = (i + 4) % 8;
            let (d_in_j, a1_j, and1_j) = (d_in[j3].clone(), a1[j3].clone(), and1[j3].clone());
            let (a_out_i, and3_i) = (a_out[i].clone(), and3[i].clone());
            let (and3_a_hi_i, and3_b_hi_i, and3_res_hi_i) =
                (and3_a_hi[i].clone(), and3_b_hi[i].clone(), and3_res_hi[i].clone());
            logup.add_to_relation_computed(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                3,
                move |v| {
                    let d1_i = d_in_j.at(v) + a1_j.at(v) - two * and1_j.at(v);
                    let a_lo = d1_i - and3_a_hi_i.at(v) * sixteen;
                    let b_lo = a_out_i.at(v) - and3_b_hi_i.at(v) * sixteen;
                    let r_lo = and3_i.at(v) - and3_res_hi_i.at(v) * sixteen;
                    vec![a_lo, b_lo, r_lo]
                },
            );

            // ── And4 = B1 & C_out, bytes at position i ──
            // B1[i] is derived: B1[i] = B_in[j] + C1[j] - 2·And2[j] where j=(i+3)%8.
            logup.add_to_relation_with(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                &[and4_a_hi[i].clone(), and4_b_hi[i].clone(), and4_res_hi[i].clone()],
            );
            let j4 = (i + 3) % 8;
            let (b_in_j, c1_j, and2_j) = (b_in[j4].clone(), c1[j4].clone(), and2[j4].clone());
            let (c_out_i, and4_i) = (c_out[i].clone(), and4[i].clone());
            let (and4_a_hi_i, and4_b_hi_i, and4_res_hi_i) =
                (and4_a_hi[i].clone(), and4_b_hi[i].clone(), and4_res_hi[i].clone());
            logup.add_to_relation_computed(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                3,
                move |v| {
                    let b1_i = b_in_j.at(v) + c1_j.at(v) - two * and2_j.at(v);
                    let a_lo = b1_i - and4_a_hi_i.at(v) * sixteen;
                    let b_lo = c_out_i.at(v) - and4_b_hi_i.at(v) * sixteen;
                    let r_lo = and4_i.at(v) - and4_res_hi_i.at(v) * sixteen;
                    vec![a_lo, b_lo, r_lo]
                },
            );

            // ── AndTLo = IV[4] & T_lo at byte i ──
            // IV[4] is constant, so a_hi / a_lo are inline.
            let iv4_byte = IV[4].to_le_bytes()[i];
            let iv4_hi = PackedBaseField::broadcast(BaseField::from((iv4_byte >> 4) as u32));
            let iv4_lo = PackedBaseField::broadcast(BaseField::from((iv4_byte & 0x0F) as u32));
            let t_cols = zkpvm_trace::original_base_column!(component_trace, Column::T);
            let t_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::THi);
            let and_t_lo_cols = zkpvm_trace::original_base_column!(component_trace, Column::AndTLo);
            let and_t_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::AndTHi);
            let and_t_lo_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::AndTLoHi);
            let and_t_hi_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::AndTHiHi);
            let iv4_hi_bcast_tuple = iv4_hi;
            logup.add_to_relation_computed(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                3,
                {
                    let t_hi_i = t_hi_cols[i].clone();
                    let and_hi_i = and_t_lo_hi_cols[i].clone();
                    move |v| vec![iv4_hi_bcast_tuple, t_hi_i.at(v), and_hi_i.at(v)]
                },
            );
            {
                let iv4_lo_const = iv4_lo;
                let t_i = t_cols[i].clone();
                let t_hi_i = t_hi_cols[i].clone();
                let and_i = and_t_lo_cols[i].clone();
                let and_hi_i = and_t_lo_hi_cols[i].clone();
                logup.add_to_relation_computed(
                    bitwise,
                    [is_real[0].clone()],
                    |[r]| r.into(),
                    3,
                    move |v| {
                        let b_lo = t_i.at(v) - t_hi_i.at(v) * sixteen;
                        let r_lo = and_i.at(v) - and_hi_i.at(v) * sixteen;
                        vec![iv4_lo_const, b_lo, r_lo]
                    },
                );
            }

            // ── AndTHi = IV[5] & T_hi (bytes 8..16 of T) at byte i ──
            let iv5_byte = IV[5].to_le_bytes()[i];
            let iv5_hi = PackedBaseField::broadcast(BaseField::from((iv5_byte >> 4) as u32));
            let iv5_lo = PackedBaseField::broadcast(BaseField::from((iv5_byte & 0x0F) as u32));
            let iv5_hi_bcast = iv5_hi;
            {
                let t_hi_i = t_hi_cols[8 + i].clone();
                let and_hi_i = and_t_hi_hi_cols[i].clone();
                logup.add_to_relation_computed(
                    bitwise,
                    [is_real[0].clone()],
                    |[r]| r.into(),
                    3,
                    move |v| vec![iv5_hi_bcast, t_hi_i.at(v), and_hi_i.at(v)],
                );
            }
            {
                let iv5_lo_const = iv5_lo;
                let t_i = t_cols[8 + i].clone();
                let t_hi_i = t_hi_cols[8 + i].clone();
                let and_i = and_t_hi_cols[i].clone();
                let and_hi_i = and_t_hi_hi_cols[i].clone();
                logup.add_to_relation_computed(
                    bitwise,
                    [is_real[0].clone()],
                    |[r]| r.into(),
                    3,
                    move |v| {
                        let b_lo = t_i.at(v) - t_hi_i.at(v) * sixteen;
                        let r_lo = and_i.at(v) - and_hi_i.at(v) * sixteen;
                        vec![iv5_lo_const, b_lo, r_lo]
                    },
                );
            }
        }

        // ── Range256 lookups for non-AND-constrained byte columns ──
        // A_in, C_in, Mx, My, B_out.  Issued in a fixed (column, byte) order
        // that the constraint side mirrors.
        for col_cols in [&a_in, &c_in, &mx, &my, &b_out] {
            for i in 0..8 {
                logup.add_to_relation_with(
                    range256,
                    [is_real[0].clone()],
                    |[r]| r.into(),
                    &[col_cols[i].clone()],
                );
            }
        }

        // ── Phase 2b: output-derivation AND-nibble lookups ──────
        // Fire only at IsLastOfCompression · IsReal.  128 AND bytes
        // (And1 and And2 pairs) × 2 nibbles = 256 lookup entries per row
        // (non-last rows have multiplicity 0).
        //
        // Snapshot V[0..16] and H[0..8] columns upfront — we dispatch by
        // numeric index below because the column-fetch macro requires a
        // literal path.
        let is_last_pp = zkpvm_trace::preprocessed_base_column!(
            component_trace, PreprocessedColumn::IsLastOfCompression
        );
        let h_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::HHi);
        let v_after_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::VAfterHi);
        let out_and1_cols = zkpvm_trace::original_base_column!(component_trace, Column::OutAnd1);
        let out_and1_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::OutAnd1Hi);
        let out_xor1_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::OutXor1Hi);
        let out_and2_cols = zkpvm_trace::original_base_column!(component_trace, Column::OutAnd2);
        let out_and2_hi_cols = zkpvm_trace::original_base_column!(component_trace, Column::OutAnd2Hi);
        let h_by_word: [_; 8] = [
            zkpvm_trace::original_base_column!(component_trace, Column::H0),
            zkpvm_trace::original_base_column!(component_trace, Column::H1),
            zkpvm_trace::original_base_column!(component_trace, Column::H2),
            zkpvm_trace::original_base_column!(component_trace, Column::H3),
            zkpvm_trace::original_base_column!(component_trace, Column::H4),
            zkpvm_trace::original_base_column!(component_trace, Column::H5),
            zkpvm_trace::original_base_column!(component_trace, Column::H6),
            zkpvm_trace::original_base_column!(component_trace, Column::H7),
        ];
        let v_by_slot: [_; 16] = [
            zkpvm_trace::original_base_column!(component_trace, Column::V0),
            zkpvm_trace::original_base_column!(component_trace, Column::V1),
            zkpvm_trace::original_base_column!(component_trace, Column::V2),
            zkpvm_trace::original_base_column!(component_trace, Column::V3),
            zkpvm_trace::original_base_column!(component_trace, Column::V4),
            zkpvm_trace::original_base_column!(component_trace, Column::V5),
            zkpvm_trace::original_base_column!(component_trace, Column::V6),
            zkpvm_trace::original_base_column!(component_trace, Column::V7),
            zkpvm_trace::original_base_column!(component_trace, Column::V8),
            zkpvm_trace::original_base_column!(component_trace, Column::V9),
            zkpvm_trace::original_base_column!(component_trace, Column::V10),
            zkpvm_trace::original_base_column!(component_trace, Column::V11),
            zkpvm_trace::original_base_column!(component_trace, Column::V12),
            zkpvm_trace::original_base_column!(component_trace, Column::V13),
            zkpvm_trace::original_base_column!(component_trace, Column::V14),
            zkpvm_trace::original_base_column!(component_trace, Column::V15),
        ];

        // G_INDICES[7] = [3, 4, 9, 14] — at row 95 (g_idx=7, always true at
        // IsLastOfCompression) slot k is touched iff k ∈ {3,4,9,14}:
        //   slot 3 ← a_out;  slot 4 ← b_out;
        //   slot 9 ← c_out;  slot 14 ← d_out;
        //   else slot k keeps V[k].
        // Pick the column for V_after[slot][byte] — element type mirrors
        // whatever `original_base_column!` returns (a FinalizedColumn clone).
        let v_after_byte = |k: usize, byte: usize| match k {
            3 => a_out[byte].clone(),
            4 => b_out[byte].clone(),
            9 => c_out[byte].clone(),
            14 => d_out[byte].clone(),
            _ => v_by_slot[k][byte].clone(),
        };

        for word in 0..8 {
            for byte in 0..8 {
                let slot = word * 8 + byte;
                let v1_src = v_after_byte(word, byte);
                let v2_src = v_after_byte(word + 8, byte);
                let h_b = h_by_word[word][byte].clone();

                // And1 hi
                {
                    let h_hi_s = h_hi_cols[slot].clone();
                    let v_after_hi_s = v_after_hi_cols[word * 8 + byte].clone();
                    let and1_hi_s = out_and1_hi_cols[slot].clone();
                    logup.add_to_relation_computed(
                        bitwise,
                        [is_real[0].clone(), is_last_pp[0].clone()],
                        |[r, l]| (r * l).into(),
                        3,
                        move |v| vec![h_hi_s.at(v), v_after_hi_s.at(v), and1_hi_s.at(v)],
                    );
                }
                // And1 lo
                {
                    let h_b2 = h_b.clone();
                    let h_hi_s = h_hi_cols[slot].clone();
                    let v1_src2 = v1_src.clone();
                    let v_after_hi_s = v_after_hi_cols[word * 8 + byte].clone();
                    let and1_s = out_and1_cols[slot].clone();
                    let and1_hi_s = out_and1_hi_cols[slot].clone();
                    logup.add_to_relation_computed(
                        bitwise,
                        [is_real[0].clone(), is_last_pp[0].clone()],
                        |[r, l]| (r * l).into(),
                        3,
                        move |v| {
                            let a_lo = h_b2.at(v) - h_hi_s.at(v) * sixteen;
                            let b_lo = v1_src2.at(v) - v_after_hi_s.at(v) * sixteen;
                            let r_lo = and1_s.at(v) - and1_hi_s.at(v) * sixteen;
                            vec![a_lo, b_lo, r_lo]
                        },
                    );
                }
                // And2 hi
                {
                    let xor1_hi_s = out_xor1_hi_cols[slot].clone();
                    let v_after_hi_s2 = v_after_hi_cols[(word + 8) * 8 + byte].clone();
                    let and2_hi_s = out_and2_hi_cols[slot].clone();
                    logup.add_to_relation_computed(
                        bitwise,
                        [is_real[0].clone(), is_last_pp[0].clone()],
                        |[r, l]| (r * l).into(),
                        3,
                        move |v| vec![xor1_hi_s.at(v), v_after_hi_s2.at(v), and2_hi_s.at(v)],
                    );
                }
                // And2 lo with xor1_expr = H + v1 - 2·And1
                {
                    let h_b2 = h_b.clone();
                    let v1_src2 = v1_src.clone();
                    let v2_src2 = v2_src.clone();
                    let xor1_hi_s = out_xor1_hi_cols[slot].clone();
                    let v_after_hi_s2 = v_after_hi_cols[(word + 8) * 8 + byte].clone();
                    let and1_s = out_and1_cols[slot].clone();
                    let and2_s = out_and2_cols[slot].clone();
                    let and2_hi_s = out_and2_hi_cols[slot].clone();
                    logup.add_to_relation_computed(
                        bitwise,
                        [is_real[0].clone(), is_last_pp[0].clone()],
                        |[r, l]| (r * l).into(),
                        3,
                        move |v| {
                            let xor1_v = h_b2.at(v) + v1_src2.at(v) - two * and1_s.at(v);
                            let a_lo = xor1_v - xor1_hi_s.at(v) * sixteen;
                            let b_lo = v2_src2.at(v) - v_after_hi_s2.at(v) * sixteen;
                            let r_lo = and2_s.at(v) - and2_hi_s.at(v) * sixteen;
                            vec![a_lo, b_lo, r_lo]
                        },
                    );
                }
            }
        }

        // ── Phase 8b: per-byte memory-access consumer lookups ──
        // Tuple (addr[4], value[1], ts[8], is_write[1]) mirroring the
        // MemoryChip ledger entries for h reads, m reads, output writes.
        // Fire only at IsFirstOfCompression · IsReal (once per compression).
        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let is_first_pp = zkpvm_trace::preprocessed_base_column!(
            component_trace, PreprocessedColumn::IsFirstOfCompression
        );
        let h_rd_addr_b0 = zkpvm_trace::original_base_column!(component_trace, Column::HRdAddrB0);
        let h_rd_addr_b1 = zkpvm_trace::original_base_column!(component_trace, Column::HRdAddrB1);
        let h_rd_addr_b2 = zkpvm_trace::original_base_column!(component_trace, Column::HRdAddrB2);
        let h_rd_addr_b3 = zkpvm_trace::original_base_column!(component_trace, Column::HRdAddrB3);
        let m_rd_addr_b0 = zkpvm_trace::original_base_column!(component_trace, Column::MRdAddrB0);
        let m_rd_addr_b1 = zkpvm_trace::original_base_column!(component_trace, Column::MRdAddrB1);
        let m_rd_addr_b2 = zkpvm_trace::original_base_column!(component_trace, Column::MRdAddrB2);
        let m_rd_addr_b3 = zkpvm_trace::original_base_column!(component_trace, Column::MRdAddrB3);
        let h_wr_addr_b0 = zkpvm_trace::original_base_column!(component_trace, Column::HWrAddrB0);
        let h_wr_addr_b1 = zkpvm_trace::original_base_column!(component_trace, Column::HWrAddrB1);
        let h_wr_addr_b2 = zkpvm_trace::original_base_column!(component_trace, Column::HWrAddrB2);
        let h_wr_addr_b3 = zkpvm_trace::original_base_column!(component_trace, Column::HWrAddrB3);
        let call_ts_cols = zkpvm_trace::original_base_column!(component_trace, Column::CallTs);
        let h_word_cols: [_; 8] = [
            zkpvm_trace::original_base_column!(component_trace, Column::H0),
            zkpvm_trace::original_base_column!(component_trace, Column::H1),
            zkpvm_trace::original_base_column!(component_trace, Column::H2),
            zkpvm_trace::original_base_column!(component_trace, Column::H3),
            zkpvm_trace::original_base_column!(component_trace, Column::H4),
            zkpvm_trace::original_base_column!(component_trace, Column::H5),
            zkpvm_trace::original_base_column!(component_trace, Column::H6),
            zkpvm_trace::original_base_column!(component_trace, Column::H7),
        ];
        let m_word_cols: [_; 16] = [
            zkpvm_trace::original_base_column!(component_trace, Column::M0),
            zkpvm_trace::original_base_column!(component_trace, Column::M1),
            zkpvm_trace::original_base_column!(component_trace, Column::M2),
            zkpvm_trace::original_base_column!(component_trace, Column::M3),
            zkpvm_trace::original_base_column!(component_trace, Column::M4),
            zkpvm_trace::original_base_column!(component_trace, Column::M5),
            zkpvm_trace::original_base_column!(component_trace, Column::M6),
            zkpvm_trace::original_base_column!(component_trace, Column::M7),
            zkpvm_trace::original_base_column!(component_trace, Column::M8),
            zkpvm_trace::original_base_column!(component_trace, Column::M9),
            zkpvm_trace::original_base_column!(component_trace, Column::M10),
            zkpvm_trace::original_base_column!(component_trace, Column::M11),
            zkpvm_trace::original_base_column!(component_trace, Column::M12),
            zkpvm_trace::original_base_column!(component_trace, Column::M13),
            zkpvm_trace::original_base_column!(component_trace, Column::M14),
            zkpvm_trace::original_base_column!(component_trace, Column::M15),
        ];
        let output_cols = zkpvm_trace::original_base_column!(component_trace, Column::Output);

        // 64 h reads: (HRdAddr[i], H[i/8][i%8], CallTs, 0)
        for i in 0..64usize {
            let word = i / 8;
            let byte = i % 8;
            let addr0 = h_rd_addr_b0[i].clone();
            let addr1 = h_rd_addr_b1[i].clone();
            let addr2 = h_rd_addr_b2[i].clone();
            let addr3 = h_rd_addr_b3[i].clone();
            let h_b = h_word_cols[word][byte].clone();
            let ts_c = call_ts_cols.clone();
            let zero_val = PackedBaseField::broadcast(BaseField::from(0u32));
            logup.add_to_relation_computed(
                mem_lookup,
                [is_real[0].clone(), is_first_pp[0].clone()],
                |[r, f]| (r * f).into(),
                14,
                move |v| {
                    let mut t = Vec::with_capacity(14);
                    t.push(addr0.at(v));
                    t.push(addr1.at(v));
                    t.push(addr2.at(v));
                    t.push(addr3.at(v));
                    t.push(h_b.at(v));
                    for ts_col in &ts_c { t.push(ts_col.at(v)); }
                    t.push(zero_val);
                    t
                },
            );
        }
        // 128 m reads
        for k in 0..128usize {
            let word = k / 8;
            let byte = k % 8;
            let addr0 = m_rd_addr_b0[k].clone();
            let addr1 = m_rd_addr_b1[k].clone();
            let addr2 = m_rd_addr_b2[k].clone();
            let addr3 = m_rd_addr_b3[k].clone();
            let m_b = m_word_cols[word][byte].clone();
            let ts_c = call_ts_cols.clone();
            let zero_val = PackedBaseField::broadcast(BaseField::from(0u32));
            logup.add_to_relation_computed(
                mem_lookup,
                [is_real[0].clone(), is_first_pp[0].clone()],
                |[r, f]| (r * f).into(),
                14,
                move |v| {
                    let mut t = Vec::with_capacity(14);
                    t.push(addr0.at(v));
                    t.push(addr1.at(v));
                    t.push(addr2.at(v));
                    t.push(addr3.at(v));
                    t.push(m_b.at(v));
                    for ts_col in &ts_c { t.push(ts_col.at(v)); }
                    t.push(zero_val);
                    t
                },
            );
        }
        // 64 output writes — gated by IsLastOfCompression, since the Output
        // column is only populated on the last row of each compression
        // (Phase 2b witness).  HWrAddr/CallTs are inter-row-constant so they
        // have the correct values on that row too.
        for i in 0..64usize {
            let addr0 = h_wr_addr_b0[i].clone();
            let addr1 = h_wr_addr_b1[i].clone();
            let addr2 = h_wr_addr_b2[i].clone();
            let addr3 = h_wr_addr_b3[i].clone();
            let out_b = output_cols[i].clone();
            let ts_c = call_ts_cols.clone();
            let one_val = PackedBaseField::broadcast(BaseField::from(1u32));
            logup.add_to_relation_computed(
                mem_lookup,
                [is_real[0].clone(), is_last_pp[0].clone()],
                |[r, l]| (r * l).into(),
                14,
                move |v| {
                    let mut t = Vec::with_capacity(14);
                    t.push(addr0.at(v));
                    t.push(addr1.at(v));
                    t.push(addr2.at(v));
                    t.push(addr3.at(v));
                    t.push(out_b.at(v));
                    for ts_col in &ts_c { t.push(ts_col.at(v)); }
                    t.push(one_val);
                    t
                },
            );
        }

        // ── Phase 8c: Blake2b-call consumer linking to CpuChip ECALL step ──
        // Tuple (h_ptr[0..4], m_ptr[0..4], t[0..8], F[1], CallTs[0..8]) = 25 limbs.
        // Fires at IsFirstOfCompression · IsReal (once per compression),
        // with multiplicity -1 so CpuChip's matching producer balances.
        let blake2b_call: &Blake2bCallLookupElements = lookup_elements.as_ref();
        let h_ptr_cols = zkpvm_trace::original_base_column!(component_trace, Column::HPtr);
        let m_ptr_cols = zkpvm_trace::original_base_column!(component_trace, Column::MPtr);
        let t_cols = zkpvm_trace::original_base_column!(component_trace, Column::T);
        let f_col = zkpvm_trace::original_base_column!(component_trace, Column::F);
        logup.add_to_relation_computed(
            blake2b_call,
            [is_real[0].clone(), is_first_pp[0].clone()],
            |[r, f]| (-(r * f)).into(),
            25,
            {
                let h_ptr_c = h_ptr_cols.clone();
                let m_ptr_c = m_ptr_cols.clone();
                let t_c = t_cols.clone();
                let f_c = f_col[0].clone();
                let ts_c = call_ts_cols.clone();
                move |v| {
                    let mut t = Vec::with_capacity(25);
                    for i in 0..4 { t.push(h_ptr_c[i].at(v)); }
                    for i in 0..4 { t.push(m_ptr_c[i].at(v)); }
                    for i in 0..8 { t.push(t_c[i].at(v)); }
                    t.push(f_c.at(v));
                    for i in 0..8 { t.push(ts_c[i].at(v)); }
                    t
                }
            },
        );

        logup.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            Range256LookupElements,
            BitwiseAndLookupElements,
            MemoryAccessLookupElements,
            Blake2bCallLookupElements,
        ),
    ) {
        let (range256_lookup, bitwise_lookup, mem_lookup, blake2b_call_lookup) = lookup_elements;
        let is_real = zkpvm_trace::trace_eval!(trace_eval, Column::IsReal);
        let a_in = zkpvm_trace::trace_eval!(trace_eval, Column::AIn);
        let b_in = zkpvm_trace::trace_eval!(trace_eval, Column::BIn);
        let c_in = zkpvm_trace::trace_eval!(trace_eval, Column::CIn);
        let d_in = zkpvm_trace::trace_eval!(trace_eval, Column::DIn);
        let mx = zkpvm_trace::trace_eval!(trace_eval, Column::Mx);
        let my = zkpvm_trace::trace_eval!(trace_eval, Column::My);
        let a1 = zkpvm_trace::trace_eval!(trace_eval, Column::A1);
        let carry1 = zkpvm_trace::trace_eval!(trace_eval, Column::Carry1);
        let and1 = zkpvm_trace::trace_eval!(trace_eval, Column::And1);
        let c1 = zkpvm_trace::trace_eval!(trace_eval, Column::C1);
        let carry2 = zkpvm_trace::trace_eval!(trace_eval, Column::Carry2);
        let and2 = zkpvm_trace::trace_eval!(trace_eval, Column::And2);
        let a_out = zkpvm_trace::trace_eval!(trace_eval, Column::AOut);
        let carry3 = zkpvm_trace::trace_eval!(trace_eval, Column::Carry3);
        let and3 = zkpvm_trace::trace_eval!(trace_eval, Column::And3);
        let c_out = zkpvm_trace::trace_eval!(trace_eval, Column::COut);
        let carry4 = zkpvm_trace::trace_eval!(trace_eval, Column::Carry4);
        let and4 = zkpvm_trace::trace_eval!(trace_eval, Column::And4);
        let b_out = zkpvm_trace::trace_eval!(trace_eval, Column::BOut);
        let rot63_carry = zkpvm_trace::trace_eval!(trace_eval, Column::Rot63Carry);

        let f256 = E::F::from(BaseField::from(256u32));
        let f2 = E::F::from(BaseField::from(2u32));

        // ── Step 1: a1 = a_in + b_in + mx (3-input addition) ──
        for i in 0..8 {
            let carry_in = if i == 0 { E::F::zero() } else { carry1[i - 1].clone() };
            eval.add_constraint(
                is_real[0].clone() * (
                    a1[i].clone() + carry1[i].clone() * f256.clone()
                    - a_in[i].clone() - b_in[i].clone() - mx[i].clone() - carry_in
                )
            );
        }

        // ── Step 2: xor1 = d ^ a1, d1 = xor1 >>> 32 (byte permutation) ──
        // xor1[i] = d_in[i] + a1[i] - 2*and1[i]
        // d1[i] = xor1[(i+4)%8]

        // ── Step 3: c1 = c_in + d1 ──
        // d1[i] = xor1[(i+4)%8] = d_in[(i+4)%8] + a1[(i+4)%8] - 2*and1[(i+4)%8]
        for i in 0..8 {
            let carry_in = if i == 0 { E::F::zero() } else { carry2[i - 1].clone() };
            let j = (i + 4) % 8; // byte permutation for >>>32
            let d1_i = d_in[j].clone() + a1[j].clone() - f2.clone() * and1[j].clone();
            eval.add_constraint(
                is_real[0].clone() * (
                    c1[i].clone() + carry2[i].clone() * f256.clone()
                    - c_in[i].clone() - d1_i - carry_in
                )
            );
        }

        // ── Step 4: xor2 = b ^ c1, b1 = xor2 >>> 24 ──
        // b1[i] = xor2[(i+3)%8] = b_in[(i+3)%8] + c1[(i+3)%8] - 2*and2[(i+3)%8]

        // ── Step 5: a_out = a1 + b1 + my ──
        for i in 0..8 {
            let carry_in = if i == 0 { E::F::zero() } else { carry3[i - 1].clone() };
            let j = (i + 3) % 8; // byte permutation for >>>24
            let b1_i = b_in[j].clone() + c1[j].clone() - f2.clone() * and2[j].clone();
            eval.add_constraint(
                is_real[0].clone() * (
                    a_out[i].clone() + carry3[i].clone() * f256.clone()
                    - a1[i].clone() - b1_i - my[i].clone() - carry_in
                )
            );
        }

        // ── Step 6: xor3 = d1 ^ a_out, d_out = xor3 >>> 16 ──
        // d1[i] = d_in[(i+4)%8] + a1[(i+4)%8] - 2*and1[(i+4)%8] (from step 2)
        // d_out[i] = xor3[(i+2)%8]

        // ── Step 7: c_out = c1 + d_out ──
        for i in 0..8 {
            let carry_in = if i == 0 { E::F::zero() } else { carry4[i - 1].clone() };
            // d_out[i] = xor3[(i+2)%8] where xor3[k] = d1[k] + a_out[k] - 2*and3[k]
            // d1[k] = d_in[(k+4)%8] + a1[(k+4)%8] - 2*and1[(k+4)%8]
            let k = (i + 2) % 8; // byte perm for >>>16
            let j = (k + 4) % 8; // byte perm for >>>32 (d1)
            let d1_k = d_in[j].clone() + a1[j].clone() - f2.clone() * and1[j].clone();
            let d_out_i = d1_k + a_out[k].clone() - f2.clone() * and3[k].clone();
            eval.add_constraint(
                is_real[0].clone() * (
                    c_out[i].clone() + carry4[i].clone() * f256.clone()
                    - c1[i].clone() - d_out_i - carry_in
                )
            );
        }

        // ── Step 8: xor4 = b1 ^ c_out, b_out = xor4 >>> 63 ──
        // >>>63 = left rotate by 1. At byte level:
        //   b_out[i] = ((xor4[i] << 1) | (xor4[(i+7)%8] >> 7)) & 0xFF
        // = (xor4[i] * 2 + rot63_carry[(i+7)%8]) mod 256
        // where rot63_carry[j] = xor4[j] >> 7 (high bit)
        for i in 0..8 {
            let j = (i + 3) % 8; // b1 byte perm (>>>24)
            let b1_i = b_in[j].clone() + c1[j].clone() - f2.clone() * and2[j].clone();
            let xor4_i = b1_i + c_out[i].clone() - f2.clone() * and4[i].clone();
            let prev_carry = rot63_carry[(i + 7) % 8].clone();
            // b_out[i] + rot63_overflow * 256 = xor4[i] * 2 + prev_carry
            // But rot63_carry[i] = xor4[i] >> 7, so xor4[i] * 2 + prev_carry can be:
            // If xor4[i] < 128: result = xor4[i]*2 + prev_carry, carry_out = 0
            // If xor4[i] >= 128: result = xor4[i]*2 + prev_carry - 256, carry_out = 1
            // Constraint: b_out[i] + rot63_carry[i] * 256 = xor4[i] * 2 + prev_carry
            eval.add_constraint(
                is_real[0].clone() * (
                    b_out[i].clone() + rot63_carry[i].clone() * f256.clone()
                    - f2.clone() * xor4_i - prev_carry
                )
            );
        }

        // ── Nibble AND lookups ───────────────────────────────────
        // Mirror of generate_interaction_trace: for each byte i, emit 8 entries
        // in the exact order (And1 hi, And1 lo, And2 hi, And2 lo, And3 hi, And3
        // lo, And4 hi, And4 lo).  finalize_logup_in_pairs combines (hi, lo) per
        // AND into a single fraction, so ordering MUST match the prover side.
        let f16 = E::F::from(BaseField::from(16u32));
        let and1_a_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And1AHi);
        let and1_b_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And1BHi);
        let and1_res_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And1ResHi);
        let and2_a_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And2AHi);
        let and2_b_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And2BHi);
        let and2_res_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And2ResHi);
        let and3_a_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And3AHi);
        let and3_b_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And3BHi);
        let and3_res_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And3ResHi);
        let and4_a_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And4AHi);
        let and4_b_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And4BHi);
        let and4_res_hi = zkpvm_trace::trace_eval!(trace_eval, Column::And4ResHi);

        for i in 0..8 {
            // And1 hi
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[and1_a_hi[i].clone(), and1_b_hi[i].clone(), and1_res_hi[i].clone()],
            ));
            // And1 lo — (d_in - hi·16, a1 - hi·16, and1 - hi·16)
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[
                    d_in[i].clone() - and1_a_hi[i].clone() * f16.clone(),
                    a1[i].clone() - and1_b_hi[i].clone() * f16.clone(),
                    and1[i].clone() - and1_res_hi[i].clone() * f16.clone(),
                ],
            ));

            // And2 hi
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[and2_a_hi[i].clone(), and2_b_hi[i].clone(), and2_res_hi[i].clone()],
            ));
            // And2 lo — (b_in - hi·16, c1 - hi·16, and2 - hi·16)
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[
                    b_in[i].clone() - and2_a_hi[i].clone() * f16.clone(),
                    c1[i].clone() - and2_b_hi[i].clone() * f16.clone(),
                    and2[i].clone() - and2_res_hi[i].clone() * f16.clone(),
                ],
            ));

            // And3 hi
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[and3_a_hi[i].clone(), and3_b_hi[i].clone(), and3_res_hi[i].clone()],
            ));
            // And3 lo — A-side is derived D1[i] = D_in[j] + A1[j] - 2·And1[j], j=(i+4)%8
            let j3 = (i + 4) % 8;
            let d1_i = d_in[j3].clone() + a1[j3].clone() - f2.clone() * and1[j3].clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[
                    d1_i - and3_a_hi[i].clone() * f16.clone(),
                    a_out[i].clone() - and3_b_hi[i].clone() * f16.clone(),
                    and3[i].clone() - and3_res_hi[i].clone() * f16.clone(),
                ],
            ));

            // And4 hi
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[and4_a_hi[i].clone(), and4_b_hi[i].clone(), and4_res_hi[i].clone()],
            ));
            // And4 lo — A-side is derived B1[i] = B_in[j] + C1[j] - 2·And2[j], j=(i+3)%8
            let j4 = (i + 3) % 8;
            let b1_i = b_in[j4].clone() + c1[j4].clone() - f2.clone() * and2[j4].clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[
                    b1_i - and4_a_hi[i].clone() * f16.clone(),
                    c_out[i].clone() - and4_b_hi[i].clone() * f16.clone(),
                    and4[i].clone() - and4_res_hi[i].clone() * f16.clone(),
                ],
            ));

            // ── AndTLo = IV[4] & T[i] ──
            let t_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::THi);
            let t_e = zkpvm_trace::trace_eval!(trace_eval, Column::T);
            let and_t_lo_e = zkpvm_trace::trace_eval!(trace_eval, Column::AndTLo);
            let and_t_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::AndTHi);
            let and_t_lo_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::AndTLoHi);
            let and_t_hi_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::AndTHiHi);
            let iv4_byte = IV[4].to_le_bytes()[i];
            let iv4_hi_f = E::F::from(BaseField::from((iv4_byte >> 4) as u32));
            let iv4_lo_f = E::F::from(BaseField::from((iv4_byte & 0x0F) as u32));
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[iv4_hi_f.clone(), t_hi_e[i].clone(), and_t_lo_hi_e[i].clone()],
            ));
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[
                    iv4_lo_f.clone(),
                    t_e[i].clone() - t_hi_e[i].clone() * f16.clone(),
                    and_t_lo_e[i].clone() - and_t_lo_hi_e[i].clone() * f16.clone(),
                ],
            ));

            // ── AndTHi = IV[5] & T[8+i] ──
            let iv5_byte = IV[5].to_le_bytes()[i];
            let iv5_hi_f = E::F::from(BaseField::from((iv5_byte >> 4) as u32));
            let iv5_lo_f = E::F::from(BaseField::from((iv5_byte & 0x0F) as u32));
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[iv5_hi_f.clone(), t_hi_e[8 + i].clone(), and_t_hi_hi_e[i].clone()],
            ));
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_real[0].clone().into(),
                &[
                    iv5_lo_f.clone(),
                    t_e[8 + i].clone() - t_hi_e[8 + i].clone() * f16.clone(),
                    and_t_hi_e[i].clone() - and_t_hi_hi_e[i].clone() * f16.clone(),
                ],
            ));
        }

        // ── Range256 for non-AND-covered byte columns ──
        // Must match the prover-side order from generate_interaction_trace.
        let a_in_e = zkpvm_trace::trace_eval!(trace_eval, Column::AIn);
        let c_in_e = zkpvm_trace::trace_eval!(trace_eval, Column::CIn);
        let mx_e = zkpvm_trace::trace_eval!(trace_eval, Column::Mx);
        let my_e = zkpvm_trace::trace_eval!(trace_eval, Column::My);
        let b_out_e = zkpvm_trace::trace_eval!(trace_eval, Column::BOut);
        for col in [&a_in_e, &c_in_e, &mx_e, &my_e, &b_out_e] {
            for i in 0..8 {
                eval.add_to_relation(RelationEntry::new(
                    range256_lookup,
                    is_real[0].clone().into(),
                    &[col[i].clone()],
                ));
            }
        }

        // NOTE: finalize_logup_in_pairs is called at the very end of this
        // method so Phase 2b relation entries are included in the pairing.

        // ── Carry / rot-carry bounds ──
        // 3-input additions (steps 1, 5) produce Carry ∈ {0,1,2}: a+b+c+cin ≤ 767.
        // 2-input additions (steps 3, 7) produce Carry ∈ {0,1}: a+b+cin ≤ 511.
        // Rot63Carry is the top bit of xor4, bounded to {0,1}.
        let f1 = E::F::one();
        for i in 0..8 {
            let c1_v = carry1[i].clone();
            eval.add_constraint(
                is_real[0].clone()
                    * c1_v.clone()
                    * (c1_v.clone() - f1.clone())
                    * (c1_v - f2.clone()),
            );
            let c3_v = carry3[i].clone();
            eval.add_constraint(
                is_real[0].clone()
                    * c3_v.clone()
                    * (c3_v.clone() - f1.clone())
                    * (c3_v - f2.clone()),
            );
            let c2_v = carry2[i].clone();
            eval.add_constraint(is_real[0].clone() * c2_v.clone() * (c2_v - f1.clone()));
            let c4_v = carry4[i].clone();
            eval.add_constraint(is_real[0].clone() * c4_v.clone() * (c4_v - f1.clone()));
            let r_v = rot63_carry[i].clone();
            eval.add_constraint(is_real[0].clone() * r_v.clone() * (r_v - f1.clone()));
        }

        // ── D_out reification ──
        // d_out[i] = xor3[(i+2)%8] where xor3[k] = d1[k] + a_out[k] - 2·and3[k]
        // and d1[k] = d_in[(k+4)%8] + a1[(k+4)%8] - 2·and1[(k+4)%8].
        // Reify so it can flow into V_next[di] via the row-chain update.
        let d_out = zkpvm_trace::trace_eval!(trace_eval, Column::DOut);
        for i in 0..8 {
            let k = (i + 2) % 8;
            let j = (k + 4) % 8;
            let d1_k = d_in[j].clone() + a1[j].clone() - f2.clone() * and1[j].clone();
            let xor3_k = d1_k + a_out[k].clone() - f2.clone() * and3[k].clone();
            eval.add_constraint(is_real[0].clone() * (d_out[i].clone() - xor3_k));
        }

        // ── Row chaining: preprocessed schedule + V-state inputs and update ──
        // IsGIdx[j] (preprocessed) = 1 iff (r % 8) == j.  G_INDICES[j] gives the
        // 4 touched slots (ai,bi,ci,di) for that G-call.  IsLastOfCompression
        // (preprocessed) = 1 iff r is the 95th row of some compression.
        let is_gidx: [_; 8] = [
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx0),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx1),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx2),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx3),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx4),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx5),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx6),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsGIdx7),
        ];
        let is_last = zkpvm_trace::preprocessed_trace_eval!(
            trace_eval, PreprocessedColumn::IsLastOfCompression
        );

        let v_cols: [_; 16] = [
            zkpvm_trace::trace_eval!(trace_eval, Column::V0),
            zkpvm_trace::trace_eval!(trace_eval, Column::V1),
            zkpvm_trace::trace_eval!(trace_eval, Column::V2),
            zkpvm_trace::trace_eval!(trace_eval, Column::V3),
            zkpvm_trace::trace_eval!(trace_eval, Column::V4),
            zkpvm_trace::trace_eval!(trace_eval, Column::V5),
            zkpvm_trace::trace_eval!(trace_eval, Column::V6),
            zkpvm_trace::trace_eval!(trace_eval, Column::V7),
            zkpvm_trace::trace_eval!(trace_eval, Column::V8),
            zkpvm_trace::trace_eval!(trace_eval, Column::V9),
            zkpvm_trace::trace_eval!(trace_eval, Column::V10),
            zkpvm_trace::trace_eval!(trace_eval, Column::V11),
            zkpvm_trace::trace_eval!(trace_eval, Column::V12),
            zkpvm_trace::trace_eval!(trace_eval, Column::V13),
            zkpvm_trace::trace_eval!(trace_eval, Column::V14),
            zkpvm_trace::trace_eval!(trace_eval, Column::V15),
        ];
        let v_cols_next: [_; 16] = [
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V0),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V1),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V2),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V3),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V4),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V5),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V6),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V7),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V8),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V9),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V10),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V11),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V12),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V13),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V14),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::V15),
        ];

        // Input match: a_in[i] = V[G_INDICES[j][0]][i] when IsGIdx[j]=1, etc.
        // Written as a_in[i] = Σ_j IsGIdx[j] · V[G_INDICES[j][0]][i].
        for i in 0..8 {
            let mut exp_a = E::F::zero();
            let mut exp_b = E::F::zero();
            let mut exp_c = E::F::zero();
            let mut exp_d = E::F::zero();
            for (j, &[aj, bj, cj, dj]) in G_INDICES.iter().enumerate() {
                exp_a += is_gidx[j][0].clone() * v_cols[aj][i].clone();
                exp_b += is_gidx[j][0].clone() * v_cols[bj][i].clone();
                exp_c += is_gidx[j][0].clone() * v_cols[cj][i].clone();
                exp_d += is_gidx[j][0].clone() * v_cols[dj][i].clone();
            }
            eval.add_constraint(is_real[0].clone() * (a_in[i].clone() - exp_a));
            eval.add_constraint(is_real[0].clone() * (b_in[i].clone() - exp_b));
            eval.add_constraint(is_real[0].clone() * (c_in[i].clone() - exp_c));
            eval.add_constraint(is_real[0].clone() * (d_in[i].clone() - exp_d));
        }

        // V_next update: for slot k at byte i, V_next[k][i] equals
        //   Σ_j IsGIdx[j] · (a_out/b_out/c_out/d_out if k is touched by G_j,
        //                    else V[k]).
        // Gated by is_real · (1 - is_last_of_compression) so the constraint
        // does not cross a compression boundary or fire on padding.
        let gate = is_real[0].clone() * (f1.clone() - is_last[0].clone());
        for k in 0..16 {
            for i in 0..8 {
                let mut update = E::F::zero();
                for (j, &[aj, bj, cj, dj]) in G_INDICES.iter().enumerate() {
                    let contribution = if k == aj { a_out[i].clone() }
                        else if k == bj { b_out[i].clone() }
                        else if k == cj { c_out[i].clone() }
                        else if k == dj { d_out[i].clone() }
                        else { v_cols[k][i].clone() };
                    update += is_gidx[j][0].clone() * contribution;
                }
                eval.add_constraint(
                    gate.clone() * (v_cols_next[k][i].clone() - update)
                );
            }
        }

        // ── Message authentication ──────────────────────────────
        // M[0..16] witness columns hold the message for this compression.
        // IsMxSlot_k / IsMySlot_k preprocessed selectors encode
        // SIGMA[round][2·g_idx] and SIGMA[round][2·g_idx + 1], so Mx / My
        // become a linear combination of the 16 M slots weighted by the
        // selectors.  Inter-row M_k_next = M_k keeps the message constant
        // across the 96 rows of a single compression.
        let m_cols: [_; 16] = [
            zkpvm_trace::trace_eval!(trace_eval, Column::M0),
            zkpvm_trace::trace_eval!(trace_eval, Column::M1),
            zkpvm_trace::trace_eval!(trace_eval, Column::M2),
            zkpvm_trace::trace_eval!(trace_eval, Column::M3),
            zkpvm_trace::trace_eval!(trace_eval, Column::M4),
            zkpvm_trace::trace_eval!(trace_eval, Column::M5),
            zkpvm_trace::trace_eval!(trace_eval, Column::M6),
            zkpvm_trace::trace_eval!(trace_eval, Column::M7),
            zkpvm_trace::trace_eval!(trace_eval, Column::M8),
            zkpvm_trace::trace_eval!(trace_eval, Column::M9),
            zkpvm_trace::trace_eval!(trace_eval, Column::M10),
            zkpvm_trace::trace_eval!(trace_eval, Column::M11),
            zkpvm_trace::trace_eval!(trace_eval, Column::M12),
            zkpvm_trace::trace_eval!(trace_eval, Column::M13),
            zkpvm_trace::trace_eval!(trace_eval, Column::M14),
            zkpvm_trace::trace_eval!(trace_eval, Column::M15),
        ];
        let m_cols_next: [_; 16] = [
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M0),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M1),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M2),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M3),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M4),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M5),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M6),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M7),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M8),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M9),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M10),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M11),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M12),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M13),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M14),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::M15),
        ];
        let is_mx_slot: [_; 16] = [
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot0),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot1),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot2),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot3),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot4),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot5),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot6),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot7),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot8),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot9),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot10),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot11),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot12),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot13),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot14),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMxSlot15),
        ];
        let is_my_slot: [_; 16] = [
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot0),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot1),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot2),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot3),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot4),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot5),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot6),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot7),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot8),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot9),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot10),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot11),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot12),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot13),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot14),
            zkpvm_trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsMySlot15),
        ];

        // Mx / My selection from M by preprocessed selector.
        let mx = zkpvm_trace::trace_eval!(trace_eval, Column::Mx);
        let my = zkpvm_trace::trace_eval!(trace_eval, Column::My);
        for i in 0..8 {
            let mut exp_mx = E::F::zero();
            let mut exp_my = E::F::zero();
            for k in 0..16 {
                exp_mx += is_mx_slot[k][0].clone() * m_cols[k][i].clone();
                exp_my += is_my_slot[k][0].clone() * m_cols[k][i].clone();
            }
            eval.add_constraint(is_real[0].clone() * (mx[i].clone() - exp_mx));
            eval.add_constraint(is_real[0].clone() * (my[i].clone() - exp_my));
        }

        // Inter-row: M[k] stays constant within a compression.  Gate identical
        // to the V-state update so message slots reset at compression boundary.
        for k in 0..16 {
            for i in 0..8 {
                eval.add_constraint(
                    gate.clone() * (m_cols_next[k][i].clone() - m_cols[k][i].clone())
                );
            }
        }

        // ── Initial state derivation + compression-input consistency ────
        // H, T, F are replicated on every row of a compression (inter-row
        // equality below) so we can anchor the V state at row 0 of a
        // compression to the Blake2b initial state:
        //   V[0..8][i]  = H_k[i]
        //   V[8..12][i] = IV[k-8][i]
        //   V[12][i]    = IV[4][i] XOR T[i]
        //                 = IV[4][i] + T[i] - 2·AndTLo[i]
        //   V[13][i]    = IV[5][i] XOR T[8+i]
        //                 = IV[5][i] + T[8+i] - 2·AndTHi[i]
        //   V[14][i]    = IV[6][i] XOR (F ? 0xFF : 0)
        //                 = IV[6][i] + F·(255 - 2·IV[6][i])
        //   V[15][i]    = IV[7][i]
        let h_cols: [_; 8] = [
            zkpvm_trace::trace_eval!(trace_eval, Column::H0),
            zkpvm_trace::trace_eval!(trace_eval, Column::H1),
            zkpvm_trace::trace_eval!(trace_eval, Column::H2),
            zkpvm_trace::trace_eval!(trace_eval, Column::H3),
            zkpvm_trace::trace_eval!(trace_eval, Column::H4),
            zkpvm_trace::trace_eval!(trace_eval, Column::H5),
            zkpvm_trace::trace_eval!(trace_eval, Column::H6),
            zkpvm_trace::trace_eval!(trace_eval, Column::H7),
        ];
        let t_e = zkpvm_trace::trace_eval!(trace_eval, Column::T);
        let f_e = zkpvm_trace::trace_eval!(trace_eval, Column::F);
        let and_t_lo_e = zkpvm_trace::trace_eval!(trace_eval, Column::AndTLo);
        let and_t_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::AndTHi);
        let is_first = zkpvm_trace::preprocessed_trace_eval!(
            trace_eval, PreprocessedColumn::IsFirstOfCompression
        );

        // F ∈ {0,1}
        eval.add_constraint(
            is_real[0].clone() * f_e[0].clone() * (f_e[0].clone() - f1.clone())
        );

        let init_gate = is_real[0].clone() * is_first[0].clone();
        let f255 = E::F::from(BaseField::from(255u32));
        for i in 0..8 {
            let iv4_i = E::F::from(BaseField::from(IV[4].to_le_bytes()[i] as u32));
            let iv5_i = E::F::from(BaseField::from(IV[5].to_le_bytes()[i] as u32));
            let iv6_i = E::F::from(BaseField::from(IV[6].to_le_bytes()[i] as u32));
            let iv7_i = E::F::from(BaseField::from(IV[7].to_le_bytes()[i] as u32));
            let iv0_i = E::F::from(BaseField::from(IV[0].to_le_bytes()[i] as u32));
            let iv1_i = E::F::from(BaseField::from(IV[1].to_le_bytes()[i] as u32));
            let iv2_i = E::F::from(BaseField::from(IV[2].to_le_bytes()[i] as u32));
            let iv3_i = E::F::from(BaseField::from(IV[3].to_le_bytes()[i] as u32));
            // V[0..8] = H_k
            for k in 0..8 {
                eval.add_constraint(
                    init_gate.clone() * (v_cols[k][i].clone() - h_cols[k][i].clone())
                );
            }
            // V[8..12] = IV[0..4]
            eval.add_constraint(init_gate.clone() * (v_cols[8][i].clone() - iv0_i.clone()));
            eval.add_constraint(init_gate.clone() * (v_cols[9][i].clone() - iv1_i.clone()));
            eval.add_constraint(init_gate.clone() * (v_cols[10][i].clone() - iv2_i.clone()));
            eval.add_constraint(init_gate.clone() * (v_cols[11][i].clone() - iv3_i.clone()));
            // V[12] = IV[4] XOR T[i] via XOR identity using AndTLo.
            let v12_expected = iv4_i.clone() + t_e[i].clone() - f2.clone() * and_t_lo_e[i].clone();
            eval.add_constraint(init_gate.clone() * (v_cols[12][i].clone() - v12_expected));
            // V[13] = IV[5] XOR T[8+i] via XOR identity using AndTHi.
            let v13_expected = iv5_i.clone() + t_e[8 + i].clone() - f2.clone() * and_t_hi_e[i].clone();
            eval.add_constraint(init_gate.clone() * (v_cols[13][i].clone() - v13_expected));
            // V[14] = IV[6] XOR (F·0xFF).
            // = IV[6] + F·0xFF - 2·F·IV[6]  (since F∈{0,1}, F·IV[6] = AND(IV[6], F·0xFF))
            // = IV[6]·(1 - 2F) + 255F
            let v14_expected = iv6_i.clone() + f_e[0].clone() * (f255.clone() - f2.clone() * iv6_i.clone());
            eval.add_constraint(init_gate.clone() * (v_cols[14][i].clone() - v14_expected));
            // V[15] = IV[7]
            eval.add_constraint(init_gate.clone() * (v_cols[15][i].clone() - iv7_i.clone()));
        }

        // ── Inter-row: H, T, F stay constant within a compression ──
        let h_cols_next: [_; 8] = [
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H0),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H1),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H2),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H3),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H4),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H5),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H6),
            zkpvm_trace::trace_eval_next_row!(trace_eval, Column::H7),
        ];
        let t_e_next = zkpvm_trace::trace_eval_next_row!(trace_eval, Column::T);
        let f_e_next = zkpvm_trace::trace_eval_next_row!(trace_eval, Column::F);
        for k in 0..8 {
            for i in 0..8 {
                eval.add_constraint(
                    gate.clone() * (h_cols_next[k][i].clone() - h_cols[k][i].clone())
                );
            }
        }
        for i in 0..16 {
            eval.add_constraint(gate.clone() * (t_e_next[i].clone() - t_e[i].clone()));
        }
        eval.add_constraint(gate.clone() * (f_e_next[0].clone() - f_e[0].clone()));

        // ── Phase 2b: output derivation at row 95 of each compression ──
        // output[i][j] = H[i][j] XOR V_after[i][j] XOR V_after[i+8][j]
        //              = H[i][j] + V_after[i][j] - 2·OutAnd1[i*8+j]
        //                         + V_after[i+8][j] - 2·OutAnd2[i*8+j]
        // V_after[k][j] is an expression: at row 95 IsGIdx_7=1, so
        //   V_after[3] ← a_out, V_after[4] ← b_out,
        //   V_after[9] ← c_out, V_after[14] ← d_out,  else V[k].
        let output_e = zkpvm_trace::trace_eval!(trace_eval, Column::Output);
        let h_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::HHi);
        let v_after_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::VAfterHi);
        let out_and1_e = zkpvm_trace::trace_eval!(trace_eval, Column::OutAnd1);
        let out_and1_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::OutAnd1Hi);
        let out_xor1_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::OutXor1Hi);
        let out_and2_e = zkpvm_trace::trace_eval!(trace_eval, Column::OutAnd2);
        let out_and2_hi_e = zkpvm_trace::trace_eval!(trace_eval, Column::OutAnd2Hi);
        let is_last_e = zkpvm_trace::preprocessed_trace_eval!(
            trace_eval, PreprocessedColumn::IsLastOfCompression
        );
        let output_gate = is_real[0].clone() * is_last_e[0].clone();

        // V_after source picker for the constraint side (mirror of the
        // interaction-trace v_after_byte closure).
        let v_after_e = |k: usize, byte: usize| -> E::F {
            match k {
                3 => a_out[byte].clone(),
                4 => b_out[byte].clone(),
                9 => c_out[byte].clone(),
                14 => d_out[byte].clone(),
                _ => v_cols[k][byte].clone(),
            }
        };

        for word in 0..8 {
            for byte in 0..8 {
                let slot = word * 8 + byte;
                let v1 = v_after_e(word, byte);
                let v2 = v_after_e(word + 8, byte);
                let h_b = h_cols[word][byte].clone();

                // Output derivation (gated at row 95).
                let expected_out = h_b.clone() + v1.clone()
                    - f2.clone() * out_and1_e[slot].clone()
                    + v2.clone()
                    - f2.clone() * out_and2_e[slot].clone();
                eval.add_constraint(
                    output_gate.clone() * (output_e[slot].clone() - expected_out)
                );

                // OutAnd1 hi
                eval.add_to_relation(RelationEntry::new(
                    bitwise_lookup,
                    output_gate.clone().into(),
                    &[
                        h_hi_e[slot].clone(),
                        v_after_hi_e[word * 8 + byte].clone(),
                        out_and1_hi_e[slot].clone(),
                    ],
                ));
                // OutAnd1 lo
                eval.add_to_relation(RelationEntry::new(
                    bitwise_lookup,
                    output_gate.clone().into(),
                    &[
                        h_b.clone() - h_hi_e[slot].clone() * f16.clone(),
                        v1.clone() - v_after_hi_e[word * 8 + byte].clone() * f16.clone(),
                        out_and1_e[slot].clone() - out_and1_hi_e[slot].clone() * f16.clone(),
                    ],
                ));
                // OutAnd2 hi — operands are Xor1 (expression) and V_after[word+8]
                eval.add_to_relation(RelationEntry::new(
                    bitwise_lookup,
                    output_gate.clone().into(),
                    &[
                        out_xor1_hi_e[slot].clone(),
                        v_after_hi_e[(word + 8) * 8 + byte].clone(),
                        out_and2_hi_e[slot].clone(),
                    ],
                ));
                // OutAnd2 lo — xor1_expr = H + v1 - 2·OutAnd1
                let xor1 = h_b.clone() + v1.clone() - f2.clone() * out_and1_e[slot].clone();
                eval.add_to_relation(RelationEntry::new(
                    bitwise_lookup,
                    output_gate.clone().into(),
                    &[
                        xor1 - out_xor1_hi_e[slot].clone() * f16.clone(),
                        v2.clone() - v_after_hi_e[(word + 8) * 8 + byte].clone() * f16.clone(),
                        out_and2_e[slot].clone() - out_and2_hi_e[slot].clone() * f16.clone(),
                    ],
                ));
            }
        }

        // ── Phase 8b: ECALL memory binding ──────────────────────
        // HPtr / MPtr / CallTs are witnessed per row (inter-row equality)
        // and 192 address columns HRdAddr/MRdAddr/HWrAddr decompose
        // HPtr+i / MPtr+k / HPtr+i as u32 LE bytes.
        let h_ptr_e = zkpvm_trace::trace_eval!(trace_eval, Column::HPtr);
        let m_ptr_e = zkpvm_trace::trace_eval!(trace_eval, Column::MPtr);
        let call_ts_e = zkpvm_trace::trace_eval!(trace_eval, Column::CallTs);
        let h_rd_b0 = zkpvm_trace::trace_eval!(trace_eval, Column::HRdAddrB0);
        let h_rd_b1 = zkpvm_trace::trace_eval!(trace_eval, Column::HRdAddrB1);
        let h_rd_b2 = zkpvm_trace::trace_eval!(trace_eval, Column::HRdAddrB2);
        let h_rd_b3 = zkpvm_trace::trace_eval!(trace_eval, Column::HRdAddrB3);
        let m_rd_b0 = zkpvm_trace::trace_eval!(trace_eval, Column::MRdAddrB0);
        let m_rd_b1 = zkpvm_trace::trace_eval!(trace_eval, Column::MRdAddrB1);
        let m_rd_b2 = zkpvm_trace::trace_eval!(trace_eval, Column::MRdAddrB2);
        let m_rd_b3 = zkpvm_trace::trace_eval!(trace_eval, Column::MRdAddrB3);
        let h_wr_b0 = zkpvm_trace::trace_eval!(trace_eval, Column::HWrAddrB0);
        let h_wr_b1 = zkpvm_trace::trace_eval!(trace_eval, Column::HWrAddrB1);
        let h_wr_b2 = zkpvm_trace::trace_eval!(trace_eval, Column::HWrAddrB2);
        let h_wr_b3 = zkpvm_trace::trace_eval!(trace_eval, Column::HWrAddrB3);
        let h_ptr_next = zkpvm_trace::trace_eval_next_row!(trace_eval, Column::HPtr);
        let m_ptr_next = zkpvm_trace::trace_eval_next_row!(trace_eval, Column::MPtr);
        let call_ts_next = zkpvm_trace::trace_eval_next_row!(trace_eval, Column::CallTs);

        // Inter-row equality within a compression.
        for i in 0..4 {
            eval.add_constraint(gate.clone() * (h_ptr_next[i].clone() - h_ptr_e[i].clone()));
            eval.add_constraint(gate.clone() * (m_ptr_next[i].clone() - m_ptr_e[i].clone()));
        }
        for i in 0..8 {
            eval.add_constraint(gate.clone() * (call_ts_next[i].clone() - call_ts_e[i].clone()));
        }

        // Address derivation: HRdAddr[i] = HPtr + i as a u32 combo.
        // Single linear identity per offset, gated by is_real·is_first.
        let init_gate_8b = is_real[0].clone() * is_first[0].clone();
        let b256 = E::F::from(BaseField::from(256u32));
        let b256_2 = b256.clone() * b256.clone();
        let b256_3 = b256_2.clone() * b256.clone();
        let combine4 = |bytes: [E::F; 4]| -> E::F {
            let [b0, b1, b2, b3] = bytes;
            b0 + b1 * b256.clone() + b2 * b256_2.clone() + b3 * b256_3.clone()
        };
        let h_ptr_u32 = combine4([
            h_ptr_e[0].clone(), h_ptr_e[1].clone(),
            h_ptr_e[2].clone(), h_ptr_e[3].clone(),
        ]);
        let m_ptr_u32 = combine4([
            m_ptr_e[0].clone(), m_ptr_e[1].clone(),
            m_ptr_e[2].clone(), m_ptr_e[3].clone(),
        ]);
        for i in 0..64usize {
            let addr_u32 = combine4([
                h_rd_b0[i].clone(), h_rd_b1[i].clone(),
                h_rd_b2[i].clone(), h_rd_b3[i].clone(),
            ]);
            let offset = E::F::from(BaseField::from(i as u32));
            eval.add_constraint(init_gate_8b.clone() * (addr_u32 - h_ptr_u32.clone() - offset));
        }
        for k in 0..128usize {
            let addr_u32 = combine4([
                m_rd_b0[k].clone(), m_rd_b1[k].clone(),
                m_rd_b2[k].clone(), m_rd_b3[k].clone(),
            ]);
            let offset = E::F::from(BaseField::from(k as u32));
            eval.add_constraint(init_gate_8b.clone() * (addr_u32 - m_ptr_u32.clone() - offset));
        }
        for i in 0..64usize {
            let addr_u32 = combine4([
                h_wr_b0[i].clone(), h_wr_b1[i].clone(),
                h_wr_b2[i].clone(), h_wr_b3[i].clone(),
            ]);
            let offset = E::F::from(BaseField::from(i as u32));
            eval.add_constraint(init_gate_8b.clone() * (addr_u32 - h_ptr_u32.clone() - offset));
        }

        // ── 256 memory-access consumer RelationEntry matching the prover side ──
        let f_one = f1.clone();
        let f_zero = E::F::zero();
        let output_words: [_; 8] = [
            output_e[0..8].iter().cloned().collect::<Vec<_>>(),
            output_e[8..16].iter().cloned().collect(),
            output_e[16..24].iter().cloned().collect(),
            output_e[24..32].iter().cloned().collect(),
            output_e[32..40].iter().cloned().collect(),
            output_e[40..48].iter().cloned().collect(),
            output_e[48..56].iter().cloned().collect(),
            output_e[56..64].iter().cloned().collect(),
        ];
        let _ = &output_words; // referenced indirectly below via output_e

        // 64 h reads
        for i in 0..64usize {
            let word = i / 8;
            let byte = i % 8;
            let mut tuple: Vec<E::F> = Vec::with_capacity(14);
            tuple.push(h_rd_b0[i].clone());
            tuple.push(h_rd_b1[i].clone());
            tuple.push(h_rd_b2[i].clone());
            tuple.push(h_rd_b3[i].clone());
            tuple.push(h_cols[word][byte].clone());
            for tb in 0..8 { tuple.push(call_ts_e[tb].clone()); }
            tuple.push(f_zero.clone());
            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                init_gate_8b.clone().into(),
                &tuple,
            ));
        }
        // 128 m reads
        for k in 0..128usize {
            let word = k / 8;
            let byte = k % 8;
            let mut tuple: Vec<E::F> = Vec::with_capacity(14);
            tuple.push(m_rd_b0[k].clone());
            tuple.push(m_rd_b1[k].clone());
            tuple.push(m_rd_b2[k].clone());
            tuple.push(m_rd_b3[k].clone());
            tuple.push(m_cols[word][byte].clone());
            for tb in 0..8 { tuple.push(call_ts_e[tb].clone()); }
            tuple.push(f_zero.clone());
            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                init_gate_8b.clone().into(),
                &tuple,
            ));
        }
        // 64 output writes — gated by is_real · IsLastOfCompression since
        // Output column is only populated at the last row of each
        // compression (Phase 2b witness); HWrAddr/CallTs stay constant.
        let write_gate_8b = is_real[0].clone() * is_last_e[0].clone();
        for i in 0..64usize {
            let mut tuple: Vec<E::F> = Vec::with_capacity(14);
            tuple.push(h_wr_b0[i].clone());
            tuple.push(h_wr_b1[i].clone());
            tuple.push(h_wr_b2[i].clone());
            tuple.push(h_wr_b3[i].clone());
            tuple.push(output_e[i].clone());
            for tb in 0..8 { tuple.push(call_ts_e[tb].clone()); }
            tuple.push(f_one.clone());
            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                write_gate_8b.clone().into(),
                &tuple,
            ));
        }

        // ── Phase 8c: consumer linking to CpuChip ECALL step ──
        // Tuple (h_ptr[0..4], m_ptr[0..4], T[0..8], F, CallTs[0..8]) = 25 limbs.
        // Fires at IsFirstOfCompression · IsReal, mult = -init_gate_8b so
        // CpuChip's producer (+is_blake_ecall) balances.
        let f_col_e = zkpvm_trace::trace_eval!(trace_eval, Column::F);
        {
            let mut tuple: Vec<E::F> = Vec::with_capacity(25);
            for i in 0..4 { tuple.push(h_ptr_e[i].clone()); }
            for i in 0..4 { tuple.push(m_ptr_e[i].clone()); }
            for i in 0..8 { tuple.push(t_e[i].clone()); }
            tuple.push(f_col_e[0].clone());
            for i in 0..8 { tuple.push(call_ts_e[i].clone()); }
            eval.add_to_relation(RelationEntry::new(
                blake2b_call_lookup,
                (-init_gate_8b.clone()).into(),
                &tuple,
            ));
        }

        // T[8..16] = 0 — the ECALL handler only uses the low 8 bytes of t,
        // so the upper half must be zero for the binding to CpuChip Phi12
        // to be unambiguous.  Gated by is_real so padding rows are inert.
        for i in 8..16 {
            eval.add_constraint(is_real[0].clone() * t_e[i].clone());
        }

        eval.finalize_logup_in_pairs();
    }
}

// ── Side note data ───────────────────────────────────────────

/// A single blake2b compression call to be proven.
#[derive(Clone, Debug)]
pub struct Blake2bCall {
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: u128,
    pub f: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_compress() {
        let h = IV;
        let m = [0u64; 16];
        let result = blake2b_compress(&h, &m, 0, true);
        assert_ne!(result, [0u64; 8]);
        let result2 = blake2b_compress(&h, &m, 0, true);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_g_traced_consistency() {
        // Verify g_traced produces the same outputs as g_func
        let mut v1 = [0u64; 16];
        v1[0] = 0x6A09E667F3BCC908;
        v1[4] = 0xBB67AE8584CAA73B;
        v1[8] = 0x3C6EF372FE94F82B;
        v1[12] = 0xA54FF53A5F1D36F1;
        let mx = 0x0123456789ABCDEF;
        let my = 0xFEDCBA9876543210;

        let mut v2 = v1;
        g_func(&mut v2, 0, 4, 8, 12, mx, my);

        let m_full = [0u64; 16];
        let h_full = [0u64; 8];
        let row = g_traced(
            &v1, &m_full, &h_full, 0u128, false,
            v1[0], v1[4], v1[8], v1[12], mx, my,
        );
        assert_eq!(u64::from_le_bytes(row.a_out), v2[0]);
        assert_eq!(u64::from_le_bytes(row.b_out), v2[4]);
        assert_eq!(u64::from_le_bytes(row.c_out), v2[8]);
        assert_eq!(u64::from_le_bytes(row.d_out), v2[12]);
        // State snapshot captured before the G-call should match v1.
        for k in 0..16 {
            assert_eq!(u64::from_le_bytes(row.v[k]), v1[k]);
        }
    }
}
