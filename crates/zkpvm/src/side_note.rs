use std::collections::HashMap;

use crate::core::step::{PvmStep, NUM_REGS};

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote {
    /// The execution trace steps.
    pub steps: Vec<PvmStep>,
    /// Program bytecode.
    pub code: Vec<u8>,
    /// Bitmask for instruction validation.
    pub bitmask: Vec<u8>,
    /// Range check accumulator: counts of each byte value 0..255.
    pub range256_counts: Vec<u32>,
    /// Bitwise AND lookup counts: (a, b) → multiplicity.
    pub bitwise_and_counts: HashMap<(u8, u8), u32>,
    /// Initial memory state (flat_mem from the PVM interpreter).
    /// The MemoryChip injects synthetic writes at timestamp 0 for addresses
    /// that are read without a prior write.
    pub initial_memory: Vec<u8>,
    /// Number of initial memory entries injected (set by MemoryChip).
    pub num_initial_mem_entries: usize,
    /// Power-of-two lookup counts: shift_amount → multiplicity (set by CpuChip).
    pub power_of_two_counts: Vec<u32>,
    /// Phase 33: popcount lookup counts: byte → multiplicity (set by CpuChip
    /// on CountSetBits32 / CountSetBits64 rows).
    pub popcount_counts: Vec<u32>,
    /// Phase 34: bitcount (lz, tz) lookup counts: byte → multiplicity (set
    /// by CpuChip on LeadingZeroBits / TrailingZeroBits rows).
    pub bitcount_counts: Vec<u32>,
    /// Phase 55a: byte-to-bits decomposition lookup counts (set by
    /// CpuChip's per-row flag-byte decomposition emissions in Phase 55b).
    /// In Phase 55a no consumers emit, so all entries are zero.
    pub byte_to_bits_counts: Vec<u32>,
    /// Blake2b compression calls to prove via the Blake2bChip.
    pub blake2b_calls: Vec<crate::chips::blake2b::Blake2bCall>,
    /// Per-byte memory operations for each blake2b ECALL (reads for h, m;
    /// writes for output).  MemoryChip ingests these into the ledger so the
    /// Blake2bChip memory-consumer lookups balance.
    pub blake2b_mem_ops: Vec<crate::core::tracing::Blake2bMemOp>,
    /// Initial register state at the start of the traced execution.  Seeds
    /// the RegisterMemoryBoundaryChip producers at ts=0 and surfaces in the
    /// public SegmentState boundary.  Default all-zero; callers that care
    /// (ECALL tests, actor entry points with non-zero regs) override via
    /// with_initial_regs or direct assignment.
    pub initial_regs: [u64; NUM_REGS],
    /// Phase 13a: per-PC count of CpuChip steps that fetched the instruction
    /// at that PC.  Populated in Phase 13b once CpuChip emits the
    /// ProgramMemory consumer; in Phase 13a the chip exists with zero
    /// multiplicity everywhere (its claimed_sum is 0).
    pub program_memory_counts: HashMap<u32, u32>,
    /// Phase 13d: program's jump_table — the set of valid dynamic-dispatch
    /// targets used by JumpInd / LoadImmJumpInd.  Empty for programs that
    /// don't use indirect jumps (most negative tests).  JumpTableChip
    /// commits to it via its preprocessed Addr/Target columns; CpuChip's
    /// JumpInd consumer demands `(addr=val_b+imm, target=next_pc)`
    /// against that table, balancing dispatch-by-runtime-index.
    pub jump_table: Vec<u32>,
    /// Phase 13d: per-jump-table-index count of JumpInd dispatches.  Indexed
    /// by `addr/2 - 1` where `addr = (regs[reg_a] + imm) mod 2^32`; entry N
    /// = number of times the program dispatched through `jump_table[N]`.
    /// Set by CpuChip's trace fill from the JumpInd steps; consumed by
    /// JumpTableChip's main-trace fill as Multiplicity.
    pub jump_table_counts: Vec<u32>,
    /// Phase 54a: per-mul-row witness pushed by CpuChip's trace_fill so
    /// MulChip's main trace mirrors CpuChip's val_b/val_d/result/mul_high
    /// exactly.  Must match the column values CpuChip writes — see
    /// chips/mul.rs's collect path.
    pub mul_entries: Vec<MulEntry>,
    /// Phase 54e: per-bitwise-row witness pushed by CpuChip's trace_fill
    /// so BitwiseChip's main trace mirrors CpuChip's val_b/val_d/result
    /// + and_result + nibble decompositions exactly.
    pub bitwise_entries: Vec<BitwiseEntry>,
    /// Phase 54f: per-compare-or-branch-row witness pushed by CpuChip
    /// so CompareChip's AIR can re-prove the unsigned-LT carry chain.
    pub compare_entries: Vec<CompareEntry>,
    /// Phase 54g: per-divrem-row witness for DivRemChip.
    pub divrem_entries: Vec<DivRemEntry>,
    /// R1e-quat: per-row witness for RistrettoChip's field-arithmetic
    /// rows (is_add / is_sub / is_mul rows produced by the host-side
    /// composition in chips::ristretto::{witness, point}).  Populated
    /// either directly (chip-level tests) or by the trace driver
    /// when an ECALL_RISTRETTO_SCALAR_MULT step is captured (R1f).
    /// Empty when the chip is gated off; in that case
    /// `generate_main_trace` emits all-zero padding rows and the
    /// chip's lookup balance stays at 0 = 0.
    #[cfg(feature = "prover")]
    pub ristretto_field_rows: Vec<crate::chips::ristretto::witness::FieldOpRow>,
}

/// Phase 54g/54i/54k — Single divrem-row witness for the DivRemLookup
/// balance.  div_corr_hi / div_corr_carry are DivRemChip-internal
/// (Phase 54k); the 4 sign bits flow from CpuChip via the lookup
/// tuple so DivRemChip can run the Phase 16/18 sign-correction chains.
#[derive(Clone, Debug)]
pub struct DivRemEntry {
    pub val_b: u64,
    pub val_d: u64,
    pub div_quotient: u64,
    pub div_remainder: u64,
    /// Phase 54k: high 8 bytes of the schoolbook output.  Internal to
    /// DivRemChip — pinned by the schoolbook chain on DivU rows and
    /// additionally by the sign-correction chain on DivS rows.
    pub div_corr_hi: [u8; 8],
    /// Phase 54k: per-byte carry of the Phase 16/18 sign-correction
    /// chain.  Internal witness on DivRemChip.
    pub div_corr_carry: [u8; 8],
    pub div_mul_carry: [u8; 16],
    pub div_mul_carry_hi: [u8; 16],
    pub div_by_zero: bool,
    pub is_32bit: bool,
    pub is_div_s: bool,
    /// `val_d - 1 - div_remainder` chain (val_d + ~div_remainder + 1 in
    /// two's complement); fired only on unsigned div rows.  Filled
    /// uniformly so the per-byte Range256 emission balances on every
    /// real DivRemChip row.
    pub div_cmp_diff: [u8; 8],
    pub div_cmp_carry: [u8; 8],
    /// Phase 54k: 4 sign bits flowed from CpuChip.  Bound on CpuChip
    /// via Phase 17/18 nibble lookups; consumed here for the DivS
    /// sign-correction chain.
    pub sign_bit_b: u8,
    pub sign_bit_d: u8,
    pub sign_bit_q: u8,
    pub sign_bit_r: u8,
    /// Phase 54j-redux: |val_d| / |div_remainder| via two's-complement
    /// conditional negation + comparison chain.  All six arrays are
    /// DivRemChip-internal; gated on sign_bit_d/sign_bit_r.
    pub abs_d: [u8; 8],
    pub abs_d_carry: [u8; 8],
    pub abs_r: [u8; 8],
    pub abs_r_carry: [u8; 8],
    pub abs_cmp_diff: [u8; 8],
    pub abs_cmp_carry: [u8; 8],
}

/// Phase 54f — Single compare-or-branch-row witness for the
/// CompareLookup balance.
#[derive(Clone, Debug)]
pub struct CompareEntry {
    pub val_b: u64,
    pub val_d: u64,
    pub cmp_lt_flag: u8,
    /// Per-byte witness for the val_b + ~val_d + 1 chain.
    pub cmp_sub_result: [u8; 8],
    pub cmp_carry: [u8; 8],
}

/// Phase 54e — Single bitwise-row witness for the BitwiseLookup balance.
#[derive(Clone, Debug)]
pub struct BitwiseEntry {
    pub val_b: u64,
    pub val_d: u64,
    pub result: u64,
    pub and_result: [u8; 8],
    pub val_b_hi_nib: [u8; 8],
    pub val_d_hi_nib: [u8; 8],
    pub and_result_hi_nib: [u8; 8],
    pub is_and: bool,
    pub is_or: bool,
    pub is_xor: bool,
    pub is_and_inv: bool,
    pub is_or_inv: bool,
    pub is_xnor: bool,
}

/// Single mul-row witness for the MultiplicationLookup balance.
#[derive(Clone, Debug)]
pub struct MulEntry {
    pub val_b: u64,
    pub val_d: u64,
    pub result: u64,
    pub mul_high: u64,
    /// Phase 54b: schoolbook low/high outputs (separate from `result`,
    /// which differs per variant — see CpuChip's result-binding logic
    /// for non-rotate Mul64 / RotL64 / MulUpper variants).
    pub unsigned_product_low: u64,
    pub unsigned_product_hi: u64,
    /// Phase 54b: per-position carry of the schoolbook chain (16 bytes).
    /// `mul_carry + 256·mul_carry_hi` reconstructs the full ≤16-bit
    /// carry; busiest at position k=3 for 0xFFFF_FFFF² ≈ 0x3FB.
    pub mul_carry: [u8; 16],
    pub mul_carry_hi: [u8; 16],
    /// Phase 54c: Phase 12c sign-correction terms.
    /// `term_a` = sa·val_d for SU/SS, 0 for UU.
    /// `term_b` = sb·val_b for SS, 0 elsewhere.
    pub mul_corr_term_a: [u8; 8],
    pub mul_corr_term_b: [u8; 8],
    /// Per-byte carry chain for `result + term_a + term_b ≡
    /// unsigned_product_hi (mod 2^64)` on is_mul_upper rows.
    pub mul_corr_carry: [u8; 8],
    /// Phase 54c: bit 7 of val_b's MSB (val_b[7] for 64-bit, val_b[3]
    /// for 32-bit).  Used by Phase 12c sign correction.
    pub sign_bit_b: u8,
    pub sign_bit_d: u8,
    /// Phase 54d: rotate-class flags driving result-variant dispatch.
    pub is_rotate_l64: bool,
    pub is_rotate_r64: bool,
    pub is_rotate_l32: bool,
    pub is_rotate_r32: bool,
    pub is_mul_lo: bool,
    pub is_mul_upper_uu: bool,
    pub is_mul_upper_su: bool,
    pub is_mul_upper_ss: bool,
    pub is_32bit: bool,
}

impl SideNote {
    pub fn new(steps: Vec<PvmStep>, code: Vec<u8>, bitmask: Vec<u8>) -> Self {
        Self {
            steps,
            code,
            bitmask,
            range256_counts: vec![0u32; 256],
            bitwise_and_counts: HashMap::new(),
            initial_memory: Vec::new(),
            num_initial_mem_entries: 0,
            power_of_two_counts: vec![0u32; 64],
            popcount_counts: vec![0u32; 256],
            bitcount_counts: vec![0u32; 256],
            byte_to_bits_counts: vec![0u32; 256],
            blake2b_calls: Vec::new(),
            blake2b_mem_ops: Vec::new(),
            initial_regs: [0u64; NUM_REGS],
            program_memory_counts: HashMap::new(),
            jump_table: Vec::new(),
            jump_table_counts: Vec::new(),
            mul_entries: Vec::new(),
            bitwise_entries: Vec::new(),
            compare_entries: Vec::new(),
            divrem_entries: Vec::new(),
            #[cfg(feature = "prover")]
            ristretto_field_rows: Vec::new(),
        }
    }

    /// Builder-style setter: attach a program's jump_table to this side note.
    /// Used by tests and prove paths to seed JumpTableChip's preprocessed
    /// table.  No-op for programs that don't use JumpInd / LoadImmJumpInd
    /// (the chip then has zero-multiplicity rows).
    pub fn with_jump_table(mut self, jump_table: Vec<u32>) -> Self {
        self.jump_table_counts = vec![0u32; jump_table.len()];
        self.jump_table = jump_table;
        self
    }

    pub fn with_memory(mut self, flat_mem: Vec<u8>) -> Self {
        self.initial_memory = flat_mem;
        self
    }

    pub fn with_initial_regs(mut self, regs: [u64; NUM_REGS]) -> Self {
        self.initial_regs = regs;
        self
    }

    pub fn num_steps(&self) -> usize {
        self.steps.len()
    }

    pub fn add_range256(&mut self, value: u8) {
        self.range256_counts[value as usize] += 1;
    }

    /// R1e-quat: push one RistrettoChip field-op row AND increment the
    /// Range256 multiplicity for every committed byte on that row.
    /// Must be used in place of `ristretto_field_rows.push(row)` —
    /// RangeMultiplicity256's trace fill runs at component index 9
    /// while RistrettoChip is at index 19, so RistrettoChip can't
    /// add to the byte counts after its own trace is being built.
    /// Pushing through this helper guarantees Range256's negative-
    /// multiplicity consumer side balances against the chip's
    /// positive emissions.
    #[cfg(feature = "prover")]
    pub fn add_ristretto_field_row(
        &mut self,
        row: crate::chips::ristretto::witness::FieldOpRow,
    ) {
        if row.is_real != 0 {
            for k in 0..32 {
                self.add_range256(row.a[k]);
                self.add_range256(row.b[k]);
                self.add_range256(row.out[k]);
                self.add_range256(row.add_intermediate[k]);
                self.add_range256(row.pass1_lo[k]);
                self.add_range256(row.pass1_carry[k]);
                self.add_range256(row.pass1_carry_mid[k]);
                self.add_range256(row.pass2_lo[k]);
                self.add_range256(row.pass2_carry[k]);
                self.add_range256(row.after_top_bit[k]);
                self.add_range256(row.after_top_carry[k]);
                self.add_range256(row.sub_chain_carry_aip[k]);
            }
            for k in 0..64 {
                self.add_range256(row.mul_product[k]);
                self.add_range256(row.mul_carry[k]);
                self.add_range256(row.mul_carry_mid[k]);
                self.add_range256(row.mul_carry_hi[k]);
            }
            for k in 0..2 {
                self.add_range256(row.pass1_hi[k]);
            }
        }
        self.ristretto_field_rows.push(row);
    }

    pub fn add_bitwise_and(&mut self, a: u8, b: u8) {
        // Split each byte into nibbles for the 16×16 lookup table
        let a_lo = a & 0x0F;
        let a_hi = (a >> 4) & 0x0F;
        let b_lo = b & 0x0F;
        let b_hi = (b >> 4) & 0x0F;
        *self.bitwise_and_counts.entry((a_lo, b_lo)).or_insert(0) += 1;
        *self.bitwise_and_counts.entry((a_hi, b_hi)).or_insert(0) += 1;
    }
}
