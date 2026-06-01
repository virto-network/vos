use std::collections::HashMap;

use crate::core::step::{NUM_REGS, PvmStep};

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
    /// Session 2.1: RistrettoCombTableChip multiplicity counts.
    /// Indexed by `row = window_idx * 16 + scalar_window` (window_idx
    /// ∈ 0..64, scalar_window ∈ 0..16 ⇒ 1024 rows).  Populated by
    /// `populate_ristretto_comb_counts` walking each entry in
    /// `ristretto_comb_calls` and bumping the entry hit by each of
    /// its 64 windows.
    pub ristretto_comb_counts: Vec<u32>,
    /// Session 2.1: per-call records driving the
    /// `RistrettoFixedBaseConsumerChip` trace fill.  One entry per
    /// fixed-basepoint scalar mult.  Empty today (consumer chip is a
    /// chip-isolated POC; production ECALL routing via
    /// `ScalarMultKind::FixedBasepoint` lands in step 8).
    pub ristretto_comb_calls: Vec<RistrettoCombCall>,
    /// Blake2b compression calls to prove via the Blake2bChip.
    pub blake2b_calls: Vec<crate::chips::blake2b::Blake2bCall>,
    /// Per-byte memory operations for each blake2b ECALL (reads for h, m;
    /// writes for output).  MemoryChip ingests these into the ledger so the
    /// Blake2bChip memory-consumer lookups balance.
    pub blake2b_mem_ops: Vec<crate::core::tracing::Blake2bMemOp>,
    /// R1f: Ristretto255 scalar-mult ECALL records (scalar / input
    /// point / output point as 32 LE bytes each).  Populated by the
    /// trace driver after `TracingPvm::run_with_precompiles`; consumed
    /// by `ingest_ristretto_boundary` to emit RistrettoChip boundary
    /// rows.  Empty unless the program issued at least one
    /// ECALL_RISTRETTO_SCALAR_MULT.
    pub ristretto_calls: Vec<crate::core::tracing::RistrettoRecord>,
    /// R1f: per-byte memory operations for each Ristretto ECALL (32
    /// scalar reads + 32 point reads + 32 output writes).  MemoryChip
    /// will eventually ingest these into the ledger so the
    /// RistrettoChip memory-consumer lookups balance — currently
    /// captured but not yet wired into the ledger.
    pub ristretto_mem_ops: Vec<crate::core::tracing::RistrettoMemOp>,
    /// Step 9: Ristretto255 point-add ECALL records.
    pub ristretto_add_calls: Vec<crate::core::tracing::RistrettoPointAddRecord>,
    pub ristretto_add_mem_ops: Vec<crate::core::tracing::RistrettoPointAddMemOp>,
    /// Step 12: scalar_from_bytes_mod_order_wide ECALL records.
    pub scalar_reduce_wide_calls: Vec<crate::core::tracing::ScalarReduceWideRecord>,
    pub scalar_reduce_wide_mem_ops: Vec<crate::core::tracing::ScalarReduceWideMemOp>,
    /// Step 18: scalar mul/add mod ℓ ECALL records.
    pub scalar_binop_calls: Vec<crate::core::tracing::ScalarBinopRecord>,
    pub scalar_binop_mem_ops: Vec<crate::core::tracing::ScalarBinopMemOp>,
    /// Initial register state at the start of the traced execution.  Seeds
    /// the RegisterMemoryBoundaryChip producers at ts=0 and surfaces in the
    /// public SegmentState boundary.  Default all-zero; callers that care
    /// (ECALL tests, actor entry points with non-zero regs) override via
    /// with_initial_regs or direct assignment.
    pub initial_regs: [u64; NUM_REGS],
    /// Final register state at the end of the traced execution.  Seeds
    /// the RegisterMemoryClosingChip producers at `closing_ts =
    /// last_step.timestamp + 1` and surfaces as `proof.final_state.
    /// registers`.  Populated by `prove()` from `last_step.regs_after`
    /// before component trace generation; callers that drive the prover
    /// directly (chip-isolated tests) must set this themselves —
    /// otherwise the closing chip claims all zeros and the
    /// register-memory ledger's read-consistency constraint will
    /// reject any non-zero final value.
    pub final_regs: [u64; NUM_REGS],
    /// Phase Z0: gate for the closing-chip ledger augmentation and the
    /// `final_state.registers` FS-transcript mix.  Set to `true` by the
    /// default `prove()` path because `BASE_COMPONENTS` includes
    /// `RegisterMemoryClosingChip`; left `false` by chip-isolated
    /// harnesses that pass an explicit component slice without the
    /// closing chip — those would otherwise add unbalanced synthetic
    /// closing-read consumers to the register-memory ledger and fail
    /// the "claimed logup sum is not zero" check.  Tests that *do*
    /// include the closing chip in an explicit slice should set this
    /// to `true` themselves.
    pub closing_chip_active: bool,
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

/// Session 2.1: one fixed-base scalar-mult call driving the
/// `RistrettoFixedBaseConsumerChip` + `RistrettoCombCompressChip`
/// + `RistrettoCombCompressOutputChip` trio.
///
/// Step 8 (scalar binding): the `scalar` bytes are pinned to PVM
/// memory by `RistrettoCombScalarBoundaryChip`.
///
/// R1e-bis Batch 4a (output binding): `out_bytes` are produced by
/// `RistrettoCombCompressChip`'s row +43 (canonical s_can) and
/// emitted as memory producers by
/// `RistrettoCombCompressOutputChip`'s 32 rows per call at
/// `(output_ptr + i, byte, ts, is_write=1)`.  `output_ptr` and
/// `ts` come straight from the actor's ECALL-step register
/// snapshot via `ingest_ristretto_boundary`.
#[derive(Clone, Debug)]
pub struct RistrettoCombCall {
    /// 32 LE bytes; the scalar `k` to multiply against the fixed
    /// basepoint G.  Decomposes into 64 4-bit windows that drive the
    /// per-window `RistrettoCombLookupElements` lookups.
    pub scalar: [u8; 32],
    /// 32 LE bytes; the canonical compressed Ristretto encoding of
    /// `k · G`.  Equals `compress(k · G)` per RFC 9496.  Drives the
    /// output chip's memory producer at `(output_ptr+i, byte, ts,
    /// is_write=1)`.
    pub out_bytes: [u8; 32],
    /// `output_ptr` register value at the ECALL step — base of the
    /// 32-byte output buffer in PVM memory.  Drives the output
    /// chip's per-byte memory address.
    pub output_ptr: u32,
    /// ECALL step timestamp.  Same `ts` as the matching
    /// `RistrettoMemOp`; used by the output chip's memory producer.
    pub ts: u64,
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
            ristretto_comb_counts: vec![0u32; 1024],
            ristretto_comb_calls: Vec::new(),
            blake2b_calls: Vec::new(),
            blake2b_mem_ops: Vec::new(),
            ristretto_calls: Vec::new(),
            ristretto_mem_ops: Vec::new(),
            ristretto_add_calls: Vec::new(),
            ristretto_add_mem_ops: Vec::new(),
            scalar_reduce_wide_calls: Vec::new(),
            scalar_reduce_wide_mem_ops: Vec::new(),
            scalar_binop_calls: Vec::new(),
            scalar_binop_mem_ops: Vec::new(),
            initial_regs: [0u64; NUM_REGS],
            final_regs: [0u64; NUM_REGS],
            closing_chip_active: false,
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
    pub fn add_ristretto_field_row(&mut self, row: crate::chips::ristretto::witness::FieldOpRow) {
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

    /// Step 4: walk the chip's row stream and set every producer
    /// row's `producer_multiplicity` to the count of downstream
    /// consumer rows that reference it via `a_source_row` /
    /// `b_source_row`.  Op rows (add/sub/mul) and OUTPUT rows
    /// consume `a`; op rows additionally consume `b`.  Run this AFTER
    /// composing all chip rows and BEFORE prove (the prove path
    /// reads `producer_multiplicity` into a trace column that
    /// scales the register-file lookup emission).
    ///
    /// O(n) over `ristretto_field_rows.len()`.  Idempotent.
    #[cfg(feature = "prover")]
    pub fn finalize_ristretto_multiplicities(&mut self) {
        for r in self.ristretto_field_rows.iter_mut() {
            r.producer_multiplicity = 0;
        }
        let n = self.ristretto_field_rows.len();
        for i in 0..n {
            let row = self.ristretto_field_rows[i];
            if row.is_real == 0 || row.is_input != 0 {
                // INPUT rows have no a/b source — skip consumer accounting
                // for them.  Padding (is_real=0) likewise.
                if row.is_input != 0 { /* still real, but no consumer fields */ }
            }
            if row.is_real == 0 {
                continue;
            }
            // OUTPUT and op rows consume `a`.
            if row.is_input == 0 {
                let a_src = row.a_source_row as usize;
                if a_src < n {
                    let cur = self.ristretto_field_rows[a_src].producer_multiplicity;
                    self.ristretto_field_rows[a_src].producer_multiplicity = cur
                        .checked_add(1)
                        .expect("producer_multiplicity overflowed u16");
                }
            }
            // Op rows additionally consume `b` (NOT input nor output).
            if row.is_input == 0 && row.is_output == 0 {
                let b_src = row.b_source_row as usize;
                if b_src < n {
                    let cur = self.ristretto_field_rows[b_src].producer_multiplicity;
                    self.ristretto_field_rows[b_src].producer_multiplicity = cur
                        .checked_add(1)
                        .expect("producer_multiplicity overflowed u16");
                }
            }
        }
    }

    /// R1f boundary capture: convert each captured Ristretto255 ECALL
    /// record into a balanced 6-row block on the chip:
    ///
    ///   row k+0: INPUT producer  out = scalar bytes
    ///   row k+1: INPUT producer  out = point bytes
    ///   row k+2: INPUT producer  out = output bytes
    ///   row k+3: OUTPUT consumer a = scalar bytes (source = k+0)
    ///   row k+4: OUTPUT consumer a = point bytes  (source = k+1)
    ///   row k+5: OUTPUT consumer a = output bytes (source = k+2)
    ///
    /// The lookup balances by construction: every producer is drained
    /// by exactly one consumer.  The chip activates iff at least one
    /// ECALL was captured.
    ///
    /// Caller MUST populate `ristretto_calls` from
    /// `TracingPvm::ristretto_records()` (and `ristretto_mem_ops` for
    /// the eventual MemoryChip integration) BEFORE invoking this
    /// method, and MUST invoke it before any chip's trace fill so the
    /// Range256 multiplicities accumulate correctly.
    ///
    /// **Step-3 limitation**: this is the BYTE-BOUNDARY closure only.
    /// It does not yet bind the chip output bytes to the actual
    /// scalar-mult result — that work threads through Step 4 (the
    /// scalar-mult chain on extended Edwards coords + curve-equation
    /// witness for compress / decompress).  Until then, the chip
    /// simply attests "these 96 bytes per call were observed" without
    /// constraining their relationship.
    ///
    /// **Canonicality precondition**: each of scalar / point / output
    /// must satisfy `< p` byte-wise (debug_assert in `fill_input`).
    /// Most natural Ristretto encodings sit comfortably under p, but
    /// arbitrary scalars (mod ℓ) can exceed p; a `fill_input_unchecked`
    /// variant for the dedicated boundary path lands together with
    /// Step 4.
    #[cfg(feature = "prover")]
    pub fn ingest_ristretto_boundary(&mut self) {
        use crate::chips::ristretto::witness::{fill_input, fill_output};
        use crate::core::tracing::ScalarMultKind;
        let calls = std::mem::take(&mut self.ristretto_calls);
        // RistrettoCombCall.output_ptr / .ts come from the parallel
        // ristretto_mem_ops record (same per-call order — every
        // RistrettoRecord has exactly one matching RistrettoMemOp,
        // produced together by `TracingPvm::run_with_precompiles`).
        // Collect the (output_ptr, ts) pairs upfront so the mutable
        // borrow of `ristretto_comb_calls` below doesn't conflict
        // with an immutable borrow of `ristretto_mem_ops`.
        let mem_op_data: Vec<(u32, u64)> = self
            .ristretto_mem_ops
            .iter()
            .map(|op| (op.output_ptr, op.ts))
            .collect();
        let mut mem_iter = mem_op_data.iter();
        for rec in &calls {
            // Session 2.1 step 8 (partial): route fixed-basepoint
            // records onto the comb-method path (RistrettoCombTableChip
            // + RistrettoFixedBaseConsumerChip).  Variable-base records
            // continue to use RistrettoChip's double-and-add ladder.
            //
            // **Soundness gap (deferred follow-up)**: this routing does
            // not yet tie the consumer chip's per-window k_i nibbles to
            // the input scalar bytes, nor the chip's final
            // extended-Edwards Acc to the output's compressed Ristretto
            // bytes.  Compress chain implementation (R1e-bis) is the
            // next-larger deliverable; until then a malicious prover
            // could fabricate a fixed-basepoint scalar mult result.
            //
            // We DO bypass RistrettoChip's boundary-row injection for
            // fixed-base records to realize the perf win.  The chip
            // gates off (activity.ristretto stays false if no field
            // rows accumulate) freeing the trace's row budget.
            // Step the mem-op iterator in lockstep with the call
            // iterator so each FixedBasepoint call gets its matching
            // (output_ptr, ts) pair.
            let mem_op = mem_iter.next().copied();
            match rec.kind {
                ScalarMultKind::FixedBasepoint => {
                    let (output_ptr, ts) =
                        mem_op.expect("ristretto_mem_ops length must match ristretto_calls");
                    self.ristretto_comb_calls.push(RistrettoCombCall {
                        scalar: rec.scalar,
                        out_bytes: rec.output,
                        output_ptr,
                        ts,
                    });
                }
                ScalarMultKind::Variable => {
                    let scalar_row = self.ristretto_field_rows.len() as u16;
                    self.add_ristretto_field_row(fill_input(rec.scalar));
                    let point_row = self.ristretto_field_rows.len() as u16;
                    self.add_ristretto_field_row(fill_input(rec.point));
                    let output_row = self.ristretto_field_rows.len() as u16;
                    self.add_ristretto_field_row(fill_input(rec.output));
                    self.add_ristretto_field_row(fill_output(rec.scalar, scalar_row));
                    self.add_ristretto_field_row(fill_output(rec.point, point_row));
                    self.add_ristretto_field_row(fill_output(rec.output, output_row));
                }
            }
        }
        self.populate_ristretto_comb_counts();
        self.populate_ristretto_compress_counts();
        self.ristretto_calls = calls;
    }

    /// Session 2.1: walk every entry in `ristretto_comb_calls` and bump
    /// `ristretto_comb_counts[window_idx * 16 + scalar_window]` for each
    /// of the call's 64 windows.  Idempotent — resets the counts vector
    /// to zero before walking, so multiple calls produce the same final
    /// state.
    ///
    /// Drives the lookup balance between the
    /// `RistrettoFixedBaseConsumerChip` (emits +1 per window) and the
    /// `RistrettoCombTableChip` (emits −multiplicity per row).
    pub fn populate_ristretto_comb_counts(&mut self) {
        for v in self.ristretto_comb_counts.iter_mut() {
            *v = 0;
        }
        for call in &self.ristretto_comb_calls {
            for i in 0..64usize {
                let byte = call.scalar[i / 2];
                let nibble_idx = i % 2;
                let k_i = ((byte >> (nibble_idx * 4)) & 0x0F) as usize;
                let row = i * 16 + k_i;
                self.ristretto_comb_counts[row] += 1;
            }
        }
    }

    /// R1e-bis Batch 3c: walk `ristretto_comb_calls` and bump
    /// `byte_to_bits_counts` for every byte the compress chain
    /// sign-checks.  Each fixed-base scalar mult emits 1 sign check
    /// in Batch 3c (rotate, on `T·z_inv.bytes[0]`) and will grow to
    /// 3 once Batches 3d/3e add the y_negate and s_neg checks.
    ///
    /// Mirrors `populate_ristretto_comb_counts`'s pattern: idempotent
    /// (does NOT zero the counts, since CpuChip's Phase-55b
    /// flag-byte decomposition also writes here — additive
    /// bookkeeping) and called both from chip-isolated tests and
    /// from `ingest_ristretto_boundary` for production traces.
    #[cfg(feature = "prover")]
    pub fn populate_ristretto_compress_counts(&mut self) {
        use crate::chips::ristretto::comb_table::{
            CombTable, NUM_WINDOWS, ed25519_basepoint_extended,
        };
        use crate::chips::ristretto::compress::compute_compress_witness;
        use crate::chips::ristretto::point::{ExtendedPoint, point_add_rows, point_identity};

        let table = CombTable::from_base(&ed25519_basepoint_extended());
        for call in &self.ristretto_comb_calls {
            // Re-derive Acc = scalar · G via the comb-table walk
            // (mirrors `RistrettoCombCompressChip::build_compress_rows`).
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
            // Rotate sign source: byte 0 of T·z_inv.
            self.byte_to_bits_counts[w.t_z_inv[0] as usize] += 1;
            // y_negate sign source: byte 0 of X'·z_inv.
            self.byte_to_bits_counts[w.x_z_inv[0] as usize] += 1;
            // s_neg sign source: byte 0 of s.
            self.byte_to_bits_counts[w.s[0] as usize] += 1;
        }
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
