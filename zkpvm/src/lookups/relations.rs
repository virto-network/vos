use stwo::core::fields::qm31::SecureField;

use crate::core::step::WORD_SIZE;

/// `(z, alpha)` of the three boundary-binding relations, in order
/// `[register_memory, program_execution, merkle_node]`. The native-recursion
/// verifier-AIR binds each relation's challenges to its Fiat-Shamir draw squeeze
/// to recompute the boundary chips' claimed sums in-circuit. The wrapped
/// `LookupElements` field is private to this module, so this accessor lives here.
pub fn boundary_relation_challenges(
    elements: &super::AllLookupElements,
) -> [(SecureField, SecureField); 3] {
    let reg: &RegisterMemoryLookupElements = elements.as_ref();
    let prog: &ProgramExecutionLookupElements = elements.as_ref();
    let merkle: &MerkleNodeLookupElements = elements.as_ref();
    [
        (reg.0.z, reg.0.alpha),
        (prog.0.z, prog.0.alpha),
        (merkle.0.z, merkle.0.alpha),
    ]
}

/// PC is 4 bytes (u32), timestamps are 8 bytes (u64).
const PC_SIZE: usize = 4;
const TS_SIZE: usize = WORD_SIZE; // 8

// (clk, pc)
// clk is 8 bytes, PC is 4 bytes.
const REL_PROG_EXEC_LOOKUP_SIZE: usize = TS_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(ProgramExecutionLookupElements, REL_PROG_EXEC_LOOKUP_SIZE);

// (reg-addr, reg-val, reg-ts, is-write)
// Address is 1 column, value is 8 bytes, timestamp is 8 bytes, is_write is 1.
// is_write binds reads vs writes so a read can't masquerade as a write to skip
// the ledger's read-consistency constraint.
const REL_REG_MEMORY_LOOKUP_SIZE: usize = 1 + WORD_SIZE + TS_SIZE + 1;
stwo_constraint_framework::relation!(RegisterMemoryLookupElements, REL_REG_MEMORY_LOOKUP_SIZE);

// (pc[4], opcode, skip_len, reg_a, reg_b, reg_d, imm[8],
//  flag_bytes[N_FLAG_BYTES], imm_y_canon[4], branch_target_canon[4])
//
// Authenticates instruction-fetch tuples: every CpuChip step emits this
// tuple, and ProgramMemoryChip's preprocessed table holds the canonical
// decoding at every basic-block-starting PC of `code`.  Phase 13a defined
// the chip; 13b wired the (pc, opcode, skip_len, regs, imm) consumer; 13c
// extended the tuple with category/sub-category flags so a prover can't
// clear flags to skip per-op constraints.
//
// Phase 55b: the 48 individual flag columns were packed into 6 bytes
// (`flag_bytes[i] = sum_{j=0..8} 2^j * flag[8*i+j]`) on both sides of
// the lookup.  CpuChip emits 6 byte-to-bits lookups per row to bind
// each individual flag column (or its sum-of-sub-flags expression for
// the 5 folded category slots) back to its packed byte.  The prog_mem
// tuple shrinks from 73 → 31 limbs.
//
// Flag layout per byte (0-indexed within byte; little-endian bits):
//   byte 0: is_add, is_sub, is_mul, is_mul_upper, is_bitwise, is_shift,
//           is_compare, is_move
//   byte 1: is_32bit, is_branch, is_jump, is_div_rem, is_load, is_store,
//           is_exit, is_neg_add
//   byte 2: is_reverse_bytes, is_zero_ext_16, is_sign_ext_8,
//           is_sign_ext_16, is_trap, is_jump_ind, is_load_imm_jump_ind,
//           is_mul_upper_uu
//   byte 3: is_mul_upper_su, is_mul_upper_ss, is_div_s, is_load_i8,
//           is_load_i16, is_load_i32, is_mem_size_1, is_mem_size_2
//   byte 4: is_mem_size_4, is_mem_size_8, is_store_direct, is_load_direct,
//           is_mem_indirect, is_store_imm_any, is_store_imm_direct,
//           is_store_ind
//   byte 5: is_rotate_l64, is_count_set_bits, is_lzb, is_tzb,
//           is_rotate_r64, is_rotate_l32, is_rotate_r32,
//           is_rotate_r_imm_alt
/// Canonical flag count (kept as a public constant so external readers
/// — fuzz harnesses, security docs — can refer to the AIR-side count
/// regardless of the on-tuple packing.  Each FlagByteI on the prog_mem
/// tuple carries 8 of these.
pub const PROG_MEMORY_N_FLAGS: usize = 48;
pub const PROG_MEMORY_N_FLAG_BYTES: usize = PROG_MEMORY_N_FLAGS / 8;
// Tuple shape: pc[4] + opcode + skip_len + reg_a + reg_b + reg_d + imm[8]
//   + 6 packed flag bytes + imm_y_canon[4] + branch_target_canon[4] = 31 limbs.
const REL_PROG_MEMORY_LOOKUP_SIZE: usize =
    PC_SIZE + 1 + 1 + 1 + 1 + 1 + WORD_SIZE + PROG_MEMORY_N_FLAG_BYTES + PC_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(ProgramMemoryLookupElements, REL_PROG_MEMORY_LOOKUP_SIZE);

// Phase 13d: JumpTableChip lookup. Tuple: (addr[4], target[4]) — 8 limbs.
// Pins runtime indirect jump targets: CpuChip emits (val_b+imm, next_pc) per
// JumpInd row; JumpTableChip's preprocessed table holds the canonical
// (addr=2*(idx+1), target=jump_table[idx]) for each entry.
const REL_JUMP_TABLE_LOOKUP_SIZE: usize = PC_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(JumpTableLookupElements, REL_JUMP_TABLE_LOOKUP_SIZE);

// Byte-level: (addr[4], value[1], timestamp[8], is_write[1], is_closing[1]).
// is_closing distinguishes the §2 per-page closing read (emitted only by
// MemoryPageChip) from every other entry (which emit 0), so MemoryChip's
// group-end constraint can require each address group to end on a closing row.
const REL_MEMORY_ACCESS_LOOKUP_SIZE: usize = PC_SIZE + 1 + TS_SIZE + 1 + 1;
stwo_constraint_framework::relation!(MemoryAccessLookupElements, REL_MEMORY_ACCESS_LOOKUP_SIZE);

// (shift_amount[1], power_val[8]) — proves val_d = 2^shift_amount
const REL_POWER_OF_TWO_LOOKUP_SIZE: usize = 1 + WORD_SIZE;
stwo_constraint_framework::relation!(PowerOfTwoLookupElements, REL_POWER_OF_TWO_LOOKUP_SIZE);

// (a, b, a_and_b) — per-byte bitwise AND lookup
const REL_BITWISE_AND_LOOKUP_SIZE: usize = 3;
stwo_constraint_framework::relation!(BitwiseAndLookupElements, REL_BITWISE_AND_LOOKUP_SIZE);

// (byte, popcount) — per-byte popcount lookup (Phase 33)
const REL_POPCOUNT_LOOKUP_SIZE: usize = 2;
stwo_constraint_framework::relation!(PopcountLookupElements, REL_POPCOUNT_LOOKUP_SIZE);

// (byte, lz_byte, tz_byte) — per-byte leading/trailing-zeros lookup (Phase 34)
const REL_BITCOUNT_LOOKUP_SIZE: usize = 3;
stwo_constraint_framework::relation!(BitcountLookupElements, REL_BITCOUNT_LOOKUP_SIZE);

// (cid[4], slot[1], value[8]) — Blake2b state lookup between boundary chip
// and main Blake2b chip for initial-state + final-state authentication.
const REL_BLAKE2B_STATE_LOOKUP_SIZE: usize = 4 + 1 + WORD_SIZE;
stwo_constraint_framework::relation!(Blake2bStateLookupElements, REL_BLAKE2B_STATE_LOOKUP_SIZE);

// Phase 54g/54i/54k — DivRem lookup.  CpuChip emits one producer
// per `is_div_rem` row; DivRemChip consumes once per real (non-
// padding) row.  Tuple binds the per-row inputs to DivRemChip's
// schoolbook + r<d uniqueness + DivS sign-correction chains.
//
// Tuple: (val_b[8], val_d[8], div_quotient[8], div_remainder[8],
//   sign_bit_b, sign_bit_d, sign_bit_q, sign_bit_r,
//   is_div_rem, div_by_zero, is_32bit, is_div_s) — 40 limbs.
//
// Sub-phase tuple-shape log:
// - 54g: 43 limbs (val_b/val_d/q/r/div_corr_hi + 3 flags).
// - 54i: 44 limbs (added is_div_s for the unsigned r<d gate).
// - 54k: 40 limbs (dropped div_corr_hi[8] since DivCorrHi is now
//   DivRemChip-internal — pinned by both schoolbook and sign
//   correction; added SignBitB/D/Q/R so DivRemChip can run the
//   Phase 16/18 sign-correction chains internally).
const REL_DIVREM_LOOKUP_SIZE: usize = WORD_SIZE * 4 + 8;
stwo_constraint_framework::relation!(DivRemLookupElements, REL_DIVREM_LOOKUP_SIZE);

// Phase 54f — Compare lookup.  CpuChip emits one producer per
// `is_compare + is_branch` row; CompareChip consumes once per real
// (non-padding) row.  Tuple binds val_b/val_d/cmp_lt_flag so
// CompareChip's AIR can re-prove the unsigned-LT result over its
// narrower trace via the byte-wise subtraction carry chain.
//
// Tuple: (val_b[8], val_d[8], cmp_lt_flag) — 17 limbs.
const REL_COMPARE_LOOKUP_SIZE: usize = WORD_SIZE * 2 + 1;
stwo_constraint_framework::relation!(CompareLookupElements, REL_COMPARE_LOOKUP_SIZE);

// Phase 54e — Bitwise lookup.  CpuChip emits one producer per
// `is_bitwise` row (sum of 6 sub-flags); BitwiseChip consumes once
// per real (non-padding) row.  Tuple binds val_b/val_d/result + 6
// sub-flags so BitwiseChip's AIR can prove the per-op result-binding
// identities (AND/OR/XOR/AndInv/OrInv/Xnor) over its narrower trace.
//
// Tuple: (val_b[8], val_d[8], result[8], is_and, is_or, is_xor,
//   is_and_inv, is_or_inv, is_xnor) — 30 limbs.
const REL_BITWISE_LOOKUP_SIZE: usize = WORD_SIZE * 3 + 6;
stwo_constraint_framework::relation!(BitwiseLookupElements, REL_BITWISE_LOOKUP_SIZE);

// Phase 54a/b/c/d — Multiplication lookup.  CpuChip emits one producer
// per `is_mul + is_mul_upper_uu + is_mul_upper_su + is_mul_upper_ss`
// row; MulChip consumes once per real (non-padding) row.  Tuple binds
// the per-row mul I/O state so MulChip's AIR proves the schoolbook
// + sign-correction + result-variant dispatch over its narrower trace.
//
// Tuple (Phase 54d): (val_b[8], val_d[8], result[8], sign_bit_b,
//   sign_bit_d, is_rotate_l64, is_rotate_r64, is_rotate_l32,
//   is_rotate_r32, is_mul_lo, is_mul_upper_uu, is_mul_upper_su,
//   is_mul_upper_ss, is_32bit) — 35 limbs.
//
// vs Phase 54c: dropped mul_high[8] + unsigned_product_low[8]
// (MulChip witnesses both internally; result variant binding moved
// to MulChip).  Added 4 rotate flags so MulChip's variant-dispatch
// constraint can fire correctly per row.
const REL_MULTIPLICATION_LOOKUP_SIZE: usize = WORD_SIZE * 3 + 11;
stwo_constraint_framework::relation!(MultiplicationLookupElements, REL_MULTIPLICATION_LOOKUP_SIZE);

// Phase 55a — ByteToBits lookup.  256-row preprocessed table proving
// `(byte, bit0, bit1, bit2, bit3, bit4, bit5, bit6, bit7)` where
// `byte = sum_{i=0..8} 2^i * bit_i`.  Phase 55b uses this table to
// bind CpuChip's individual flag columns to the 6 packed flag bytes
// that flow through the prog_mem tuple.
//
// Tuple: (byte, bit0..bit7) — 9 limbs.
const REL_BYTE_TO_BITS_LOOKUP_SIZE: usize = 1 + 8;
stwo_constraint_framework::relation!(ByteToBitsLookupElements, REL_BYTE_TO_BITS_LOOKUP_SIZE);

// (h_ptr[4], m_ptr[4], t_low[8], f[1], ts[8]) — binds Blake2bChip's HPtr,
// MPtr, T[0..8], F and CallTs to CpuChip's ECALL-step register snapshot +
// timestamp so the precompile can't fabricate the pointer / counter /
// finalise-flag triple.  CpuChip emits 1 producer per blake2b ECALL step,
// Blake2bChip emits 1 consumer per compression.
const REL_BLAKE2B_CALL_LOOKUP_SIZE: usize = 4 + 4 + WORD_SIZE + 1 + TS_SIZE;
stwo_constraint_framework::relation!(Blake2bCallLookupElements, REL_BLAKE2B_CALL_LOOKUP_SIZE);

// (h_in[64], m[128], t[8], f[1], h_out[64]) — one tuple per blake2b
// compression of the in-AIR memory-page Merkle boundary multiproof, bound
// WITHOUT a memory-ledger / CPU-call binding.  Blake2bBoundaryChip PRODUCES
// one per compression at its row-95 output; MemoryPageChip (leaf h-chain)
// and MemoryMerkleChip (node hashes) CONSUME them (step 5).
const REL_BLAKE2B_COMPRESSION_LOOKUP_SIZE: usize = 64 + 128 + 8 + 1 + 64;
stwo_constraint_framework::relation!(
    Blake2bCompressionLookupElements,
    REL_BLAKE2B_COMPRESSION_LOOKUP_SIZE
);

// (level[1], index[1], hash_before[32], hash_after[32]) — one tuple per node
// of the in-AIR memory-page Merkle trie (design §1).  `index` is a SINGLE M31
// limb (2^DEPTH − 1 < p), NOT byte limbs — logup tuples match per-limb and a
// byte-limbed index would break the degree-1 child doubling on merge rows.
// MemoryPageChip PRODUCES one leaf tuple `(DEPTH, page_idx, leaf_before,
// leaf_after)` per listed page; MemoryMerkleChip CONSUMES two children and
// PRODUCES the parent per merge row; MemoryRootBoundaryChip CONSUMES exactly
// one root tuple `(0, 0, initial_root, final_root)`.  Logup balance over this
// relation is what enforces the trie schedule.
const REL_MERKLE_NODE_LOOKUP_SIZE: usize = 1 + 1 + 32 + 32;
stwo_constraint_framework::relation!(MerkleNodeLookupElements, REL_MERKLE_NODE_LOOKUP_SIZE);

// R1e-pent: RistrettoChip register-file lookup.  Each row's `out`
// bytes are PRODUCERS keyed by (row_index, byte_index, byte_value);
// each row's `a` and `b` input bytes are CONSUMERS keyed by
// (a_source_row, byte_index, byte_value) and (b_source_row, ...).
// The lookup polynomial balance forces every consumer to find a
// matching producer — closing the inter-row binding soundness gap.
//
// row_index is split into 2 LE bytes (sufficient for chips up to
// log_size 16 = 65K rows).  byte_index ∈ [0, 32).
//
// Tuple: (row_idx_lo, row_idx_hi, byte_index, byte_value) — 4 limbs.
const REL_RISTRETTO_REGISTER_FILE_LOOKUP_SIZE: usize = 4;
stwo_constraint_framework::relation!(
    RistrettoRegisterFileLookupElements,
    REL_RISTRETTO_REGISTER_FILE_LOOKUP_SIZE
);

// Session 2.1: RistrettoCombTableChip lookup.  Producer: 1024 rows of
// the precomputed comb table for the Ristretto255 / Ed25519 fixed
// basepoint G; each row is `T[i][j] = j · 2^(4·i) · G` keyed by
// `(window_idx, scalar_window)` in extended-Edwards bytes.  Consumer
// (chip-side fixed-base mult path, deferred): 1 emission per scalar
// mult window, binding the chip's running-sum row to the looked-up
// table entry.
//
// Tuple: (window_idx, scalar_window, x[32], y[32], z[32], t[32]) — 130 limbs.
const REL_RISTRETTO_COMB_LOOKUP_SIZE: usize = 1 + 1 + 32 * 4;
stwo_constraint_framework::relation!(RistrettoCombLookupElements, REL_RISTRETTO_COMB_LOOKUP_SIZE);

// Session 2.1 step 8 (partial): scalar nibble binding between
// `RistrettoCombAnchorChip` and a new `RistrettoCombScalarBoundaryChip`.
//
// Tuple: (call_idx, window_idx, k_value).  3 limbs.
//
// Producer: `RistrettoCombAnchorChip` emits +IsReal per row at
// (CallIdx, WindowIdx, ScalarWindow).
// Consumer: `RistrettoCombScalarBoundaryChip` reads the scalar bytes
// from `side_note.ristretto_comb_calls`, decomposes each byte into
// two 4-bit nibbles, and emits −IsReal per row at (call_idx,
// window_idx, expected_nibble).
//
// Balance forces the anchor chip's ScalarWindow per (call, window) to
// equal the expected nibble from the actor's scalar.  Since the
// anchor chip's row stream is a deterministic function of
// `ristretto_comb_calls`, the scalar is consistent end-to-end through
// the comb chip pair.
//
// SOUNDNESS LIMITATION: the boundary chip pulls from `side_note`,
// not directly from PVM memory.  A separate (deferred) refactor is
// needed to bind `side_note.ristretto_comb_calls.scalar` to
// `MemoryAccessLookupElements` — i.e., have the boundary chip emit
// memory producers for the scalar bytes (with `RistrettoEcallChip`
// stopping its scalar-byte producers for FixedBasepoint records to
// avoid double-emission).
const REL_RISTRETTO_COMB_SCALAR_BOUNDARY_SIZE: usize = 3;
stwo_constraint_framework::relation!(
    RistrettoCombScalarBoundaryLookupElements,
    REL_RISTRETTO_COMB_SCALAR_BOUNDARY_SIZE
);

// Session 2.1 column-shrink: anchor-chip↔consumer-chip coord binding.
//
// Tuple: (call_idx, window_idx, coord_kind ∈ {0=X,1=Y,2=Z,3=T},
//         byte_idx, value).  5 limbs.
//
// Producer side (`RistrettoCombAnchorChip`): per anchor row, emits
// 4 × 32 = 128 +1 contributions — one per (coord, byte).
// Consumer side (`RistrettoFixedBaseConsumerChip`): per IsInput
// coord row (4 per window), emits 32 −1 contributions matching the
// row's specific (call, window, coord) at every byte offset.
//
// Forces consumer chip's IsInput coord rows' `out` columns to
// equal the anchor chip's per-coord byte values.  Replaces the
// previous chip-local trick where the consumer chip carried
// X/Y/Z/T columns on a "lookup-anchor" row; splitting the anchor
// metadata into a sibling chip drops ~137 columns from the
// consumer chip's per-row width.
const REL_RISTRETTO_COMB_COORD_BOUNDARY_SIZE: usize = 5;
stwo_constraint_framework::relation!(
    RistrettoCombCoordBoundaryLookupElements,
    REL_RISTRETTO_COMB_COORD_BOUNDARY_SIZE
);

// Session 2.1 step 5(b): chip-local register-file relation for
// RistrettoFixedBaseConsumerChip.  Same shape as RistrettoChip's
// (row_id_lo, row_id_hi, byte_idx, value) but a separate type so the
// two chips' chip-local row numbering doesn't collide.
//
// PRODUCER per real row: 32 tuples (row_id_lo, row_id_hi, byte_idx[k],
// out[k]) — emitted on input + add/sub/mul rows.
// CONSUMER A per real row: 32 tuples for `a` keyed on (a_src_lo,
// a_src_hi, byte_idx[k], a[k]) — emitted on add/sub/mul + output rows.
// CONSUMER B per real row: 32 tuples for `b` — emitted only on
// add/sub/mul rows (input/output rows have no `b`).
//
// Plus the lookup-anchor row's Y/Z/T cross-row binding emits 3 × 32
// = 96 consumer tuples on the anchor row keyed on (y_src/z_src/t_src,
// byte_idx[k], Y[k]/Z[k]/T[k]).  These tie the anchor row's Y/Z/T
// witness columns to rows +1/+2/+3's `out` columns (those rows being
// the Y-, Z-, T-coord IsInput producer rows for the same window).
const REL_RISTRETTO_COMB_CONSUMER_REGFILE_SIZE: usize = 4;
stwo_constraint_framework::relation!(
    RistrettoCombConsumerRegisterFileLookupElements,
    REL_RISTRETTO_COMB_CONSUMER_REGFILE_SIZE
);

// R1e-bis Batch 2: chip-local register-file relation for
// RistrettoCombCompressChip.  Same shape as the consumer chip's
// (row_id_lo, row_id_hi, byte_idx, value) but a distinct type so the
// compress chip's own row numbering doesn't collide with the
// consumer chip's.  Drives source-row threading within the compress
// chain (rows 1-12 of the algebra prologue plus the 4 IsInput rows
// for X/Y/Z/T and the inv_sqrt witness row).
//
// PRODUCER per real row: 32 tuples (row_id_lo, row_id_hi, byte_idx[k],
// out[k]) — emitted on IsInput + IsAdd/IsSub/IsMul rows.
// CONSUMER A per real row: 32 tuples for `a` keyed on
// (a_src_lo, a_src_hi, byte_idx[k], a[k]) — emitted on
// IsAdd/IsSub/IsMul rows.
// CONSUMER B per real row: 32 tuples for `b` — emitted only on
// IsAdd/IsSub/IsMul rows.
const REL_RISTRETTO_COMB_COMPRESS_REGFILE_SIZE: usize = 4;
stwo_constraint_framework::relation!(
    RistrettoCombCompressRegFileLookupElements,
    REL_RISTRETTO_COMB_COMPRESS_REGFILE_SIZE
);

// R1e-bis Batch 4a: cross-chip relation tying compress chain's
// row +43 (s_can canonical compressed bytes) to the output memory
// producer chip.
//
// Tuple: (call_idx, byte_idx, value) — 3 limbs.
//
// PRODUCER (`RistrettoCombCompressChip`): per fixed-base call, the
// row at offset +43 emits 32 tuples (one per byte_idx ∈ 0..32) at
// (call_idx, byte_idx, s_can[byte_idx]) with multiplicity
// `+IsOutputProducer` (preprocessed; 1 on row +43 of real
// per-call blocks, 0 elsewhere).
//
// CONSUMER (`RistrettoCombCompressOutputChip`): per call, 32 rows
// (one per output byte) emit tuples at (call_idx, byte_idx, value)
// with multiplicity `-IsReal`.  Balance forces each row's `value`
// column to equal the compress chain's `s_can[byte_idx]` for that
// call — i.e., binds the output memory producer's byte payload to
// the canonically-compressed Ristretto bytes the compress chain
// derived in-circuit.
const REL_RISTRETTO_COMB_COMPRESS_OUTPUT_SIZE: usize = 3;
stwo_constraint_framework::relation!(
    RistrettoCombCompressOutputLookupElements,
    REL_RISTRETTO_COMB_COMPRESS_OUTPUT_SIZE
);

// R1e-bis Batch 4b: cross-chip relation binding the final-Acc
// X/Y/Z/T from `RistrettoFixedBaseConsumerChip`'s window-63 last
// 4 mul rows to `RistrettoCombCompressChip`'s 4 IsInput rows for
// X/Y/Z/T (offsets +0..+3 within each per-call block).
//
// Tuple: (call_idx, coord_kind, byte_idx, value) — 4 limbs.
// `coord_kind` ∈ {0=X, 1=Y, 2=Z, 3=T}.
//
// PRODUCER (`RistrettoFixedBaseConsumerChip`): per call, the last
// 4 mul rows of window 63's 18-row add chain — at offsets
// `N_BOUNDARY_INPUTS + call_idx × 1408 + 1404..=1407` in the chip's
// row layout — emit 32 producer tuples each (one per byte).
// 4 × 32 = 128 producer tuples per call.  Order within those 4
// rows: X3 (coord_kind=0) at +1404, Y3 (=1) at +1405, T3 (=3)
// at +1406, Z3 (=2) at +1407 — matches the
// `point_add_rows_chained` emission order.
//
// CONSUMER (`RistrettoCombCompressChip`): per call, the 4 IsInput
// rows for X/Y/Z/T (compress-chip offsets +0..+3) emit 32 consumer
// tuples each.  Balance forces the compress chain's IsInput
// `out` columns to equal the consumer chip's window-63 final-Acc
// coords — closing the X/Y/Z/T cross-chip binding gap.
const REL_RISTRETTO_COMB_FINAL_ACC_SIZE: usize = 4;
stwo_constraint_framework::relation!(
    RistrettoCombFinalAccLookupElements,
    REL_RISTRETTO_COMB_FINAL_ACC_SIZE
);

// Phase A prereq 0.2 (ristretto ts-binding): RELATION A — ties every
// ristretto-family ECALL step to the RistrettoEcallChip block that produces
// its memory tuples, so the block's `ts` is the genuine ECALL-step ts.
//
// Tuple: (id[1], ptr0[4], ptr1[4], ptr2[4], ts[8]) — 21 limbs.
//
// `id` ∈ {110,111,112,113,114} disambiguates the call kind (one relation +
// an id limb is sound and simpler than five disjoint relations — a 111-block
// consumer cannot satisfy a 110-step producer).  `ptr0/ptr1/ptr2` are the
// base pointers of the three 32-byte sub-blocks IN TRACE-LAYOUT ORDER
// (ByteIdx 0-31 / 32-63 / 64-95 of the 96-row RistrettoEcallChip block), so
// the chip's per-byte Addr authentication is id-agnostic; CpuChip fills the
// slots per id from the register snapshots φ[7,8,9].  `ts` is the chained
// CpuChip step Timestamp.
//
// PRODUCER (CpuChip, +Is{id}Ecall): one per ristretto ECALL step.
// CONSUMER (RistrettoEcallChip, -InitGate): one per non-empty 96-row block
// (the point reads at ByteIdx 0 are universal across fixed/variable base, so
// every call has a real ByteIdx-0 row).
const REL_RISTRETTO_CALL_LOOKUP_SIZE: usize = 1 + 4 + 4 + 4 + TS_SIZE; // 21
stwo_constraint_framework::relation!(RistrettoCallLookupElements, REL_RISTRETTO_CALL_LOOKUP_SIZE);

// Phase A prereq 0.2: Tier-2 scalar-ptr binding for FIXED-BASE scalar_mult.
// RistrettoEcallChip (which sees `op.kind`) re-emits the already-anchored
// call ts keyed on the authenticated scalar pointer; RistrettoCombScalarBoundaryChip
// consumes it, forcing its 32-row block's `Ts` == the anchored ECALL ts.
//
// Tuple: (scalar_ptr[4], ts[8]) — 12 limbs.  Distinct type from the output
// binding below so the two comb consumers can't collide on a shared key.
//
// PRODUCER (RistrettoEcallChip, +InitGate·IsFixedBase).
// CONSUMER (RistrettoCombScalarBoundaryChip, -1 at the block's first row).
const REL_RISTRETTO_FIXED_SCALAR_TS_SIZE: usize = 4 + TS_SIZE; // 12
stwo_constraint_framework::relation!(
    RistrettoFixedScalarTsLookupElements,
    REL_RISTRETTO_FIXED_SCALAR_TS_SIZE
);

// Phase A prereq 0.2: Tier-2 output-ptr binding for FIXED-BASE scalar_mult.
// Same mechanism as the scalar binding, keyed on the authenticated output
// pointer; RistrettoCombCompressOutputChip consumes it.
//
// Tuple: (output_ptr[4], ts[8]) — 12 limbs.
//
// PRODUCER (RistrettoEcallChip, +InitGate·IsFixedBase).
// CONSUMER (RistrettoCombCompressOutputChip, -1 at the block's first row).
const REL_RISTRETTO_FIXED_OUT_TS_SIZE: usize = 4 + TS_SIZE; // 12
stwo_constraint_framework::relation!(
    RistrettoFixedOutTsLookupElements,
    REL_RISTRETTO_FIXED_OUT_TS_SIZE
);
