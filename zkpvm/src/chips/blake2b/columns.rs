//! Blake2b AIR column layouts.
//!
//! `Column` carries the per-row main-trace witness for a single G-function
//! invocation (96 rows per compression), including nibble AND witnesses, the
//! v[0..16] state snapshot, compression-level inputs (h, t, f, m), ECALL
//! memory-binding pointers and per-byte addresses, and the final-row Output
//! witnesses.
//!
//! `PreprocessedColumn` carries the row-index-derived selectors: 8 G-index
//! selectors (one per column/diagonal slot), the first/last-of-compression
//! flags, and the 32 SIGMA-derived message-slot selectors for Mx/My.

use crate::air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    // Input state (4 × u64 = 32 limbs)
    #[size = 8]
    AIn,
    #[size = 8]
    BIn,
    #[size = 8]
    CIn,
    #[size = 8]
    DIn,
    // Message words (2 × u64 = 16 limbs)
    #[size = 8]
    Mx,
    #[size = 8]
    My,
    // Step 1: a1 = a + b + mx
    #[size = 8]
    A1,
    #[size = 8]
    Carry1,
    // Step 2: and1 = d & a1 (witness for XOR: d^a1 = d+a1-2*and1)
    #[size = 8]
    And1,
    // Step 3: c1 = c + d1 (where d1 = (d^a1) >>> 32 = byte permutation)
    #[size = 8]
    C1,
    #[size = 8]
    Carry2,
    // Step 4: and2 = b & c1
    #[size = 8]
    And2,
    // Step 5: a_out = a1 + b1 + my (where b1 = (b^c1) >>> 24 = byte permutation)
    #[size = 8]
    AOut,
    #[size = 8]
    Carry3,
    // Step 6: and3 = d1 & a_out
    #[size = 8]
    And3,
    // Step 7: c_out = c1 + d_out (where d_out = (d1^a_out) >>> 16 = byte permutation)
    #[size = 8]
    COut,
    #[size = 8]
    Carry4,
    // Step 8: and4 = b1 & c_out
    #[size = 8]
    And4,
    // Step 9: b_out = (b1 ^ c_out) >>> 63 = left rotate by 1
    #[size = 8]
    BOut,
    #[size = 8]
    Rot63Carry, // 1-bit carries for rotation
    // The four G-function AND results (And1..And4) are proven by single
    // byte-wide lookups into `BitwiseAndByteChip` (a, b, a&b), so the
    // per-operand hi-nibble witness columns are gone — byte-ness of the
    // operands comes free from table membership.
    // ── Row chaining: full state snapshot + d_out reification ──
    // D_out is not stored in the base trace; derive via XOR identity and
    // reify so the row-chaining constraint can propagate it into V_next.
    #[size = 8]
    DOut,
    // Message m[0..16] for the current compression. Prover-provided, held
    // constant across all 96 rows of a compression (enforced by inter-row
    // constraint gated on IsLastOfCompression). Mx and My are then selected
    // from these 16 slots via the SIGMA-derived preprocessed selectors.
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
    // ── Compression-level inputs (h, t, f) ──────────────────────
    // Replicated across all 96 rows of a compression (inter-row equality
    // keeps them constant).  At row 0 of each compression the V witnesses
    // are constrained to the Blake2b initial state derived from these
    // fields and the IV: V[0..8]=H, V[8..12]=IV[0..4], V[12]=IV[4]^T_lo,
    // V[13]=IV[5]^T_hi, V[14]=IV[6] XOR (F ? !0 : 0), V[15]=IV[7].
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
    /// T as 16 LE bytes (u128 counter).
    #[size = 16]
    #[mask_next_row]
    T,
    /// Finalisation flag in {0,1}.
    #[size = 1]
    #[mask_next_row]
    F,
    /// and_t_lo[i] = IV[4][i] & T[i]; and_t_hi[i] = IV[5][i] & T[8+i].
    /// Together they let initial_v[12]/[13] be expressed via the XOR identity.
    /// Proven by byte-wide AND lookups (a=IV const, b=T byte, a&b=result), so
    /// their hi-nibble witnesses and the T hi-nibble are gone.
    #[size = 8]
    AndTLo,
    #[size = 8]
    AndTHi,
    // Snapshot of v[0..16] at the start of this row's G-call. Each V{k} is the
    // 8 LE bytes of v[k]. Marked mask_next_row so the state-update constraint
    // can reference row N+1's V for row N's inter-row constraint.
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
    // ── Output derivation at last row of compression ────────────
    // Only constrained at IsLastOfCompression·IsReal rows; zeroes elsewhere.
    // output[i_word][i_byte] = H[i][j] XOR V_after[i][j] XOR V_after[i+8][j].
    // V_after is not a witness — it equals update_expr(k, j) at this row,
    // where IsGIdx_7=1 selects the diagonal G_INDICES[7]=[3,4,9,14].
    /// Claimed output = H ^ V_after[0..8] ^ V_after[8..16].  8 words × 8 bytes.
    #[size = 64]
    Output,
    /// OutAnd1[i][j] = H[i][j] & V_after[i][j].  8 words × 8 bytes.  Proven by
    /// a byte-wide AND lookup (H byte, V_after byte, result), so the H /
    /// V_after / result hi-nibble witnesses are gone.
    #[size = 64]
    OutAnd1,
    /// OutAnd2[i][j] = OutXor1[i][j] & V_after[i+8][j].  8 words × 8 bytes.
    /// Byte-wide AND lookup with OutXor1 = H ^ V_after computed inline.
    #[size = 64]
    OutAnd2,
    // ── ECALL memory binding ──────────────────────────
    // HPtr / MPtr are the register values φ[10]/φ[11] at the ECALL step,
    // CallTs is its timestamp.  Inter-row equality keeps them constant
    // within a compression so the 256 byte-level memory lookups emitted
    // at IsFirstOfCompression reference well-defined values.
    #[size = 4]
    #[mask_next_row]
    HPtr,
    #[size = 4]
    #[mask_next_row]
    MPtr,
    #[size = 8]
    #[mask_next_row]
    CallTs,
    /// Byte addresses for the 64 h-read lookups: HRdAddr_b*[i] holds byte
    /// `b` of `HPtr + i` for i ∈ 0..64.  4 columns of size 64 each = 256
    /// cells, avoiding the NonZeroU8 size cap (max 255 per variant).
    #[size = 64]
    HRdAddrB0,
    #[size = 64]
    HRdAddrB1,
    #[size = 64]
    HRdAddrB2,
    #[size = 64]
    HRdAddrB3,
    /// Byte addresses for the 128 m-read lookups.
    #[size = 128]
    MRdAddrB0,
    #[size = 128]
    MRdAddrB1,
    #[size = 128]
    MRdAddrB2,
    #[size = 128]
    MRdAddrB3,
    /// Byte addresses for the 64 output-write lookups.
    #[size = 64]
    HWrAddrB0,
    #[size = 64]
    HWrAddrB1,
    #[size = 64]
    HWrAddrB2,
    #[size = 64]
    HWrAddrB3,
    // Row type.  mask_next_row mirrors `BoundaryColumn::IsReal` (whose
    // IsReal-continuity anchor reads the next row); Blake2bChip leaves the
    // next value unused.
    #[size = 1]
    #[mask_next_row]
    IsReal,
    // Gate helpers — Stwo v2.x lifted-protocol degree flatten.
    // GateH        = IsReal · (1 - IsLastOfCompression)
    // InitGateH    = IsReal · IsFirstOfCompression
    // OutputGateH  = IsReal · IsLastOfCompression
    // Each is the per-row product of `IsReal` (main) and one of the
    // `IsFirstOfCompression`/`IsLastOfCompression` preprocessed columns.
    // Lifting these into helper columns drops the gate's algebraic
    // degree from 2 to 1 in every gated constraint.
    #[size = 1]
    GateH,
    #[size = 1]
    InitGateH,
    #[size = 1]
    OutputGateH,
    // Logup multiplicity of the row-95 compression production.  Live only
    // in `BoundaryColumn::EmitMult` (see boundary.rs for the gating and the
    // RangeMultiplicity256-style value-freedom argument); dead (all-zero)
    // here — Blake2bChip's producer gate stays OutputGateH — and retained
    // solely to keep the main chip's committed layout unchanged.
    #[size = 1]
    EmitMult,
    // Carry-bound helpers — flatten the degree-3 / -4
    // carry-domain constraints to degree 2.
    //
    // For Carry1 / Carry3 (3-input adds, c ∈ {0,1,2}):
    //   `is_real · c · (c-1) · (c-2)` is degree 4.  Two helpers per byte:
    //     Carry1XcM1[i] := Carry1[i] · (Carry1[i] - 1)              (deg 2)
    //     Carry1Full[i] := Carry1XcM1[i] · (Carry1[i] - 2)          (deg 2)
    //     is_real · Carry1Full[i] = 0                                (deg 2)
    //   For valid carries (0/1/2) Carry1Full is always 0; the constraint
    //   forces it.
    //
    // For Carry2 / Carry4 / Rot63Carry (2-input adds, c ∈ {0,1}):
    //   `is_real · c · (c-1)` is degree 3.  One helper per byte:
    //     Carry2XcM1[i] := Carry2[i] · (Carry2[i] - 1)              (deg 2)
    //     is_real · Carry2XcM1[i] = 0                                (deg 2)
    //   For valid carries (0/1) XcM1 is always 0.
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
    // F-bound helper.
    //   FBoundH := F · (F-1)        (deg 2 helper-defining)
    //   is_real · FBoundH = 0        (deg 2; was `is_real · F · (F-1)`,
    //                                 deg 3, before flatten)
    // F ∈ {0,1} so FBoundH is always 0 in valid traces.
    #[size = 1]
    FBoundH,
    // Input-match sum helpers — flatten the 4 input
    // identity constraints (a_in / b_in / c_in / d_in vs the active V slot).
    //
    // Original (deg 3): is_real · (a_in[i] - Σ_j IsGIdx[j] · V[G_INDICES[j][0]][i])
    // Flattened:
    //   InMatchA[i] := Σ_j IsGIdx[j] · V[G_INDICES[j][0]][i]      (deg 2 helper-def)
    //   is_real · (a_in[i] - InMatchA[i]) = 0                      (deg 2 main)
    // Same shape for B / C / D (G_INDICES[j][1..4]).  In valid traces
    // exactly one IsGIdx[j_active] = 1 per row, so InMatchA[i] = a_in[i].
    #[size = 8]
    InMatchA,
    #[size = 8]
    InMatchB,
    #[size = 8]
    InMatchC,
    #[size = 8]
    InMatchD,
    // Mx / My slot-selection helpers — flatten the
    // 2 SIGMA-driven message-byte selectors.
    //
    // Original (deg 3): is_real · (mx[i] - Σ_k IsMxSlot[k] · M[k][i])
    // Flattened:
    //   MxSlotSum[i] := Σ_k IsMxSlot[k] · M[k][i]    (deg 2 helper-def)
    //   is_real · (mx[i] - MxSlotSum[i]) = 0          (deg 2 main)
    // (My uses IsMySlot.)
    #[size = 8]
    MxSlotSum,
    #[size = 8]
    MySlotSum,
    // V_next sum helpers — flatten the 16 V-state
    // update constraints from degree 3 to degree 2.
    //
    // Original (deg 3): GateH · (V_next[k][i] - Σ_j IsGIdx[j] · contribution_j(k, i))
    //   where contribution_j(k, i) ∈ {a_out[i], b_out[i], c_out[i], d_out[i],
    //   V[k][i]} depending on whether k matches G_INDICES[j][0..3] or not.
    // Flattened:
    //   VNextSumK[i] := Σ_j IsGIdx[j] · contribution_j(k, i)        (deg 2 helper-def)
    //   GateH · (V_next[k][i] - VNextSumK[i]) = 0                    (deg 2 main)
    //
    // 16 slots × 8 bytes = 128 helper cells per row.  Witness-fill: at
    // row r with j_active = r % 8, the sum collapses to v_after[k][i]
    // where v_after = r.v with G_INDICES[j_active] slots replaced by
    // r.{a,b,c,d}_out.
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

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "blake2b"]
pub enum PreprocessedColumn {
    /// Selector: row r has IsGIdx[j] = 1 iff (r % 8) == j.  G_INDICES is
    /// constant per round, so these 8 selectors determine (ai, bi, ci, di)
    /// for every row without needing a round column.
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
    /// 1 iff (r % 96) == 95 — last G-call of a compression.  The row-chaining
    /// constraint is gated off at these rows because V_next belongs to the
    /// next (independently-initialised) compression.
    #[size = 1]
    IsLastOfCompression,
    /// 1 iff (r % 96) == 0 — first G-call of a compression.  Reserved for
    /// the initial-state derivation constraint; currently unused.
    #[size = 1]
    IsFirstOfCompression,
    /// IsMxSlot[k] = 1 iff SIGMA[round(r)][2·g_idx(r)] == k (ie this row's
    /// Mx comes from message slot k).  round(r) = (r % 96) / 8,
    /// g_idx(r) = r % 8.
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
    /// IsMySlot[k] = 1 iff SIGMA[round(r)][2·g_idx(r) + 1] == k.
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
}

/// The main-column handles the shared blake2b compression core reads and
/// writes (`add_compression_core`, `add_compression_interaction_core`,
/// `fill_compression_trace`).  `Column` implements it over the full
/// ECALL-binding layout; the boundary chip's `BoundaryColumn` implements it
/// without the 1040 ECALL-binding limbs (`HPtr`/`MPtr`/`CallTs` and the
/// per-byte address columns) that only `Blake2bChip`'s memory-ledger /
/// CPU-call bindings reference.
///
/// Limb counts are fixed by the core's constraint shapes and must match the
/// sizes documented on `Column`'s variants (the `column_eval` /
/// `fill_columns_bytes` size asserts check every access at runtime).  The
/// `M` / `H` / `T` / `F` / `V` / `IS_REAL` handles must be
/// `mask_next_row`-capable: the core reads their next-row values for the
/// inter-row equality and V-chain constraints.
pub(super) trait CompressionColumns: AirColumn {
    const IS_REAL: Self;
    const GATE_H: Self;
    const INIT_GATE_H: Self;
    const OUTPUT_GATE_H: Self;
    const A_IN: Self;
    const B_IN: Self;
    const C_IN: Self;
    const D_IN: Self;
    const MX: Self;
    const MY: Self;
    const A1: Self;
    const CARRY1: Self;
    const AND1: Self;
    const C1: Self;
    const CARRY2: Self;
    const AND2: Self;
    const A_OUT: Self;
    const CARRY3: Self;
    const AND3: Self;
    const C_OUT: Self;
    const CARRY4: Self;
    const AND4: Self;
    const B_OUT: Self;
    const ROT63_CARRY: Self;
    const D_OUT: Self;
    const M: [Self; 16];
    const H: [Self; 8];
    const T: Self;
    const F: Self;
    const AND_T_LO: Self;
    const AND_T_HI: Self;
    const V: [Self; 16];
    const OUTPUT: Self;
    const OUT_AND1: Self;
    const OUT_AND2: Self;
    const CARRY1_XCM1: Self;
    const CARRY1_FULL: Self;
    const CARRY3_XCM1: Self;
    const CARRY3_FULL: Self;
    const CARRY2_XCM1: Self;
    const CARRY4_XCM1: Self;
    const ROT63_XCM1: Self;
    const F_BOUND_H: Self;
    const IN_MATCH_A: Self;
    const IN_MATCH_B: Self;
    const IN_MATCH_C: Self;
    const IN_MATCH_D: Self;
    const MX_SLOT_SUM: Self;
    const MY_SLOT_SUM: Self;
    const V_NEXT_SUM: [Self; 16];
}

impl CompressionColumns for Column {
    const IS_REAL: Self = Column::IsReal;
    const GATE_H: Self = Column::GateH;
    const INIT_GATE_H: Self = Column::InitGateH;
    const OUTPUT_GATE_H: Self = Column::OutputGateH;
    const A_IN: Self = Column::AIn;
    const B_IN: Self = Column::BIn;
    const C_IN: Self = Column::CIn;
    const D_IN: Self = Column::DIn;
    const MX: Self = Column::Mx;
    const MY: Self = Column::My;
    const A1: Self = Column::A1;
    const CARRY1: Self = Column::Carry1;
    const AND1: Self = Column::And1;
    const C1: Self = Column::C1;
    const CARRY2: Self = Column::Carry2;
    const AND2: Self = Column::And2;
    const A_OUT: Self = Column::AOut;
    const CARRY3: Self = Column::Carry3;
    const AND3: Self = Column::And3;
    const C_OUT: Self = Column::COut;
    const CARRY4: Self = Column::Carry4;
    const AND4: Self = Column::And4;
    const B_OUT: Self = Column::BOut;
    const ROT63_CARRY: Self = Column::Rot63Carry;
    const D_OUT: Self = Column::DOut;
    const T: Self = Column::T;
    const F: Self = Column::F;
    const AND_T_LO: Self = Column::AndTLo;
    const AND_T_HI: Self = Column::AndTHi;
    const OUTPUT: Self = Column::Output;
    const OUT_AND1: Self = Column::OutAnd1;
    const OUT_AND2: Self = Column::OutAnd2;
    const CARRY1_XCM1: Self = Column::Carry1XcM1;
    const CARRY1_FULL: Self = Column::Carry1Full;
    const CARRY3_XCM1: Self = Column::Carry3XcM1;
    const CARRY3_FULL: Self = Column::Carry3Full;
    const CARRY2_XCM1: Self = Column::Carry2XcM1;
    const CARRY4_XCM1: Self = Column::Carry4XcM1;
    const ROT63_XCM1: Self = Column::Rot63XcM1;
    const F_BOUND_H: Self = Column::FBoundH;
    const IN_MATCH_A: Self = Column::InMatchA;
    const IN_MATCH_B: Self = Column::InMatchB;
    const IN_MATCH_C: Self = Column::InMatchC;
    const IN_MATCH_D: Self = Column::InMatchD;
    const MX_SLOT_SUM: Self = Column::MxSlotSum;
    const MY_SLOT_SUM: Self = Column::MySlotSum;
    const M: [Self; 16] = [
        Column::M0,
        Column::M1,
        Column::M2,
        Column::M3,
        Column::M4,
        Column::M5,
        Column::M6,
        Column::M7,
        Column::M8,
        Column::M9,
        Column::M10,
        Column::M11,
        Column::M12,
        Column::M13,
        Column::M14,
        Column::M15,
    ];
    const H: [Self; 8] = [
        Column::H0,
        Column::H1,
        Column::H2,
        Column::H3,
        Column::H4,
        Column::H5,
        Column::H6,
        Column::H7,
    ];
    const V: [Self; 16] = [
        Column::V0,
        Column::V1,
        Column::V2,
        Column::V3,
        Column::V4,
        Column::V5,
        Column::V6,
        Column::V7,
        Column::V8,
        Column::V9,
        Column::V10,
        Column::V11,
        Column::V12,
        Column::V13,
        Column::V14,
        Column::V15,
    ];
    const V_NEXT_SUM: [Self; 16] = [
        Column::VNextSum0,
        Column::VNextSum1,
        Column::VNextSum2,
        Column::VNextSum3,
        Column::VNextSum4,
        Column::VNextSum5,
        Column::VNextSum6,
        Column::VNextSum7,
        Column::VNextSum8,
        Column::VNextSum9,
        Column::VNextSum10,
        Column::VNextSum11,
        Column::VNextSum12,
        Column::VNextSum13,
        Column::VNextSum14,
        Column::VNextSum15,
    ];
}
