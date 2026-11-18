//! Blake2b AIR column layouts.
//!
//! `compression_columns!` lays out the compression core's main-trace
//! witness for a single G-function invocation a row (96 rows per
//! compression): the input state and message words, each step's sum,
//! carries and byte-wide AND results (each a lookup into
//! `BitwiseAndByteChip`), the v[0..16] state snapshot, compression-level
//! inputs (h, t, f, m) and the final-row Output witnesses, around a chip's
//! own columns. `Column` is the ECALL chip's: the core's, with the
//! memory-binding pointers, timestamp and address limbs; the boundary
//! chip's `BoundaryColumn` (`boundary.rs`) is the core's, with its
//! production multiplicity in place of those.
//! [`CompressionColumns`] is the handles the shared core reads them by.
//!
//! `PreprocessedColumn` carries the row-index-derived selectors: 8 G-index
//! selectors (one per column/diagonal slot), the first/last-of-compression
//! flags, the 32 SIGMA-derived message-slot selectors for Mx/My, and the
//! IsReal anchor's `ContinuityGate` and `IsTail`.

use crate::air_column::{AirColumn, PreprocessedAirColumn};

/// The compression core's columns in their order, and their
/// [`CompressionColumns`] handles, for a chip whose own columns are
/// `binding`, after the output's, and `gated`, after the gate helpers.
macro_rules! compression_columns {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            binding { $($binding:tt)* }
            gated { $($gated:tt)* }
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Copy, Clone, AirColumn)]
        $vis enum $name {
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
            /// and_t_lo\[i\] = IV\[4\]\[i\] & T\[i\]; and_t_hi\[i\] = IV\[5\]\[i\] & T[8+i].
            /// Together they let initial_v\[12\]/\[13\] be expressed via the XOR identity.
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
            /// OutAnd1\[i\]\[j\] = H\[i\]\[j\] & V_after\[i\]\[j\].  8 words × 8 bytes.  Proven by
            /// a byte-wide AND lookup (H byte, V_after byte, result), so the H /
            /// V_after / result hi-nibble witnesses are gone.
            #[size = 64]
            OutAnd1,
            /// OutAnd2\[i\]\[j\] = OutXor1\[i\]\[j\] & V_after[i+8]\[j\].  8 words × 8 bytes.
            /// Byte-wide AND lookup with OutXor1 = H ^ V_after computed inline.
            #[size = 64]
            OutAnd2,
            $($binding)*
            // Row type: boolean, constant across a compression's 96 rows (the
            // `ContinuityGate` anchor reads the next row) and 0 in the trailing
            // partial block.
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
            $($gated)*
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

        impl CompressionColumns for $name {
            const IS_REAL: Self = Self::IsReal;
            const GATE_H: Self = Self::GateH;
            const INIT_GATE_H: Self = Self::InitGateH;
            const OUTPUT_GATE_H: Self = Self::OutputGateH;
            const A_IN: Self = Self::AIn;
            const B_IN: Self = Self::BIn;
            const C_IN: Self = Self::CIn;
            const D_IN: Self = Self::DIn;
            const MX: Self = Self::Mx;
            const MY: Self = Self::My;
            const A1: Self = Self::A1;
            const CARRY1: Self = Self::Carry1;
            const AND1: Self = Self::And1;
            const C1: Self = Self::C1;
            const CARRY2: Self = Self::Carry2;
            const AND2: Self = Self::And2;
            const A_OUT: Self = Self::AOut;
            const CARRY3: Self = Self::Carry3;
            const AND3: Self = Self::And3;
            const C_OUT: Self = Self::COut;
            const CARRY4: Self = Self::Carry4;
            const AND4: Self = Self::And4;
            const B_OUT: Self = Self::BOut;
            const ROT63_CARRY: Self = Self::Rot63Carry;
            const D_OUT: Self = Self::DOut;
            const T: Self = Self::T;
            const F: Self = Self::F;
            const AND_T_LO: Self = Self::AndTLo;
            const AND_T_HI: Self = Self::AndTHi;
            const OUTPUT: Self = Self::Output;
            const OUT_AND1: Self = Self::OutAnd1;
            const OUT_AND2: Self = Self::OutAnd2;
            const CARRY1_XCM1: Self = Self::Carry1XcM1;
            const CARRY1_FULL: Self = Self::Carry1Full;
            const CARRY3_XCM1: Self = Self::Carry3XcM1;
            const CARRY3_FULL: Self = Self::Carry3Full;
            const CARRY2_XCM1: Self = Self::Carry2XcM1;
            const CARRY4_XCM1: Self = Self::Carry4XcM1;
            const ROT63_XCM1: Self = Self::Rot63XcM1;
            const F_BOUND_H: Self = Self::FBoundH;
            const IN_MATCH_A: Self = Self::InMatchA;
            const IN_MATCH_B: Self = Self::InMatchB;
            const IN_MATCH_C: Self = Self::InMatchC;
            const IN_MATCH_D: Self = Self::InMatchD;
            const MX_SLOT_SUM: Self = Self::MxSlotSum;
            const MY_SLOT_SUM: Self = Self::MySlotSum;
            const M: [Self; 16] = [
                Self::M0,
                Self::M1,
                Self::M2,
                Self::M3,
                Self::M4,
                Self::M5,
                Self::M6,
                Self::M7,
                Self::M8,
                Self::M9,
                Self::M10,
                Self::M11,
                Self::M12,
                Self::M13,
                Self::M14,
                Self::M15,
            ];
            const H: [Self; 8] = [
                Self::H0,
                Self::H1,
                Self::H2,
                Self::H3,
                Self::H4,
                Self::H5,
                Self::H6,
                Self::H7,
            ];
            const V: [Self; 16] = [
                Self::V0,
                Self::V1,
                Self::V2,
                Self::V3,
                Self::V4,
                Self::V5,
                Self::V6,
                Self::V7,
                Self::V8,
                Self::V9,
                Self::V10,
                Self::V11,
                Self::V12,
                Self::V13,
                Self::V14,
                Self::V15,
            ];
            const V_NEXT_SUM: [Self; 16] = [
                Self::VNextSum0,
                Self::VNextSum1,
                Self::VNextSum2,
                Self::VNextSum3,
                Self::VNextSum4,
                Self::VNextSum5,
                Self::VNextSum6,
                Self::VNextSum7,
                Self::VNextSum8,
                Self::VNextSum9,
                Self::VNextSum10,
                Self::VNextSum11,
                Self::VNextSum12,
                Self::VNextSum13,
                Self::VNextSum14,
                Self::VNextSum15,
            ];
        }
    };
}

pub(super) use compression_columns;

compression_columns! {
    pub enum Column {
        binding {
            // ── ECALL memory binding ──────────────────────────
            // HPtr / MPtr are the register values φ[7]/φ[8] at the ECALL step,
            // CallTs is its timestamp.  Inter-row equality keeps them constant
            // within a compression, so the 192 reads emitted on its first row and
            // the 64 writes on its last see the same pointers and timestamp.
            #[size = 4]
            #[mask_next_row]
            HPtr,
            #[size = 4]
            #[mask_next_row]
            MPtr,
            #[size = 8]
            #[mask_next_row]
            CallTs,
            /// `c_i`, the carry out of the low byte of `HPtr + i` for i ∈ 0..64;
            /// limb 0 of that address is `HPtr[0] + i − 256·c_i`, not a column.
            /// See `address.rs`.
            #[size = 64]
            HAddrCarry,
            /// Limbs 1, 2 and 3 of `HPtr + i`: `HPtr`'s own when `c_i = 0`, those of
            /// `HPtrInc` when `c_i = 1`.  The `h` reads use them on the first row,
            /// the digest's writes on the last.
            #[size = 64]
            HAddrB1,
            #[size = 64]
            HAddrB2,
            #[size = 64]
            HAddrB3,
            /// `c_k`, the carry out of the low byte of `MPtr + k` for k ∈ 0..128.
            #[size = 128]
            MAddrCarry,
            /// Limbs 1, 2 and 3 of `MPtr + k`.
            #[size = 128]
            MAddrB1,
            #[size = 128]
            MAddrB2,
            #[size = 128]
            MAddrB3,
            /// Limbs 0..3 of `(HPtr >> 8) + 1`, and the carries out of its limbs 0
            /// and 1 (no carry out of limb 2: a range wrapping 2^32 is unprovable).
            #[size = 3]
            HPtrInc,
            #[size = 2]
            HPtrIncCarry,
            /// Limbs 0..3 of `(MPtr >> 8) + 1`, and its carries.
            #[size = 3]
            MPtrInc,
            #[size = 2]
            MPtrIncCarry,
        }
        gated {}
    }
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
    /// 1 iff (r % 96) == 0 — first G-call of a compression: the initial-state
    /// derivation, the call consumer and the `h`/`m` reads.
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
    /// 1 iff the IsReal-continuity constraint applies from this row to the
    /// next: `r % 96 != 95` (not a compression boundary) and `r` is not the
    /// last trace row (whose next row wraps to row 0).
    #[size = 1]
    ContinuityGate,
    /// 1 on the rows of the trailing partial block, `r ≥ 96·⌊N/96⌋`: a block
    /// with no row 95, which would consume a call and never write, so it
    /// holds no real row.
    #[size = 1]
    IsTail,
}

/// The main-column handles the shared blake2b compression core reads and
/// writes (`add_compression_core`, `add_compression_interaction_core`,
/// `fill_compression_trace`).  `Column` implements it over the full
/// ECALL-binding layout; the boundary chip's `BoundaryColumn` implements it
/// without the ECALL-binding columns (`HPtr`/`MPtr`/`CallTs` and the
/// address columns) that only `Blake2bChip`'s memory-ledger / CPU-call
/// bindings reference.
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
