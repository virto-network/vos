use alloc::sync::Arc;
use std::collections::HashMap;

use crate::core::step::{CompactStep, NUM_REGS, PvmStep, expand_steps};

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote {
    /// The execution trace steps.
    pub steps: Vec<PvmStep>,
    /// Program bytecode.
    pub code: Arc<[u8]>,
    /// Bitmask for instruction validation.
    pub bitmask: Arc<[u8]>,
    /// Range check accumulator: counts of each byte value 0..255.
    pub range256_counts: Vec<u32>,
    /// Bitwise AND nibble lookup counts: (a, b) → multiplicity, for the
    /// 16×16 `BitwiseLookupChip` (CpuChip / ALU BitwiseChip consumers).
    pub bitwise_and_counts: HashMap<(u8, u8), u32>,
    /// Byte-wide bitwise AND lookup counts for the 2^16-row
    /// `BitwiseAndByteChip`, indexed `(a as usize) << 8 | b as usize`.  The two
    /// blake2b chips consume this table (one byte lookup per AND) instead of
    /// two nibble lookups; the byte-ness of `a`/`b` comes free from table
    /// membership.
    pub bitwise_and_byte_counts: Vec<u32>,
    /// Initial memory state (flat_mem from the PVM interpreter).
    /// The MemoryChip injects synthetic writes at timestamp 0 for addresses
    /// that are read without a prior write.
    pub initial_memory: Vec<u8>,
    /// Canonical sorted non-zero pages for a sparse 32-bit memory image.
    /// Mutually exclusive with `initial_memory`; Refine proof tracing uses
    /// this form so the high stack/input pages never imply a dense 4 GiB
    /// allocation.
    pub sparse_initial_memory: Option<crate::SparseMemoryImage>,
    /// Number of initial memory entries injected (set by MemoryChip).
    pub num_initial_mem_entries: usize,
    /// Power-of-two lookup counts: shift_amount → multiplicity (set by CpuChip).
    pub power_of_two_counts: Vec<u32>,
    /// Popcount lookup counts: byte → multiplicity (set by CpuChip
    /// on CountSetBits32 / CountSetBits64 rows).
    pub popcount_counts: Vec<u32>,
    /// Bitcount (lz, tz) lookup counts: byte → multiplicity (set
    /// by CpuChip on LeadingZeroBits / TrailingZeroBits rows).
    pub bitcount_counts: Vec<u32>,
    /// Byte-to-bits decomposition lookup counts, set by CpuChip's
    /// per-row flag-byte decomposition emissions.  When no consumer
    /// emits, all entries are zero.
    pub byte_to_bits_counts: Vec<u32>,
    /// Blake2b compression calls to prove via the Blake2bChip.
    pub blake2b_calls: Vec<crate::chips::blake2b::Blake2bCall>,
    /// Per-byte memory operations for each blake2b ECALL (reads for h, m;
    /// writes for output).  MemoryChip ingests these into the ledger so the
    /// Blake2bChip memory-consumer lookups balance.
    pub blake2b_mem_ops: Vec<crate::core::tracing::Blake2bMemOp>,
    /// Synthetic blake2b compressions for the in-AIR memory-page Merkle
    /// boundary multiproof, proven by `Blake2bBoundaryChip`.  Unlike
    /// `blake2b_calls` these hash page images (leaves) and node pairs, with
    /// no memory-ledger binding.  Built on the prove path from
    /// `page_merkle::boundary_blake2b_calls`, DEDUPLICATED — each unique
    /// compression appears once, with its in-circuit consumption count in
    /// the parallel `merkle_blake2b_mults`.
    pub merkle_blake2b_calls: Vec<crate::chips::blake2b::Blake2bCall>,
    /// Logup multiplicity per entry of `merkle_blake2b_calls` (parallel,
    /// 1:1) — the `EmitMult` value the boundary chip fills at that
    /// compression's row 95.  A missing entry (hand-built side notes)
    /// defaults to 1.
    pub merkle_blake2b_mults: Vec<u32>,
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
    /// Gate for the closing-chip ledger augmentation and the
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
    /// Per-PC count of CpuChip steps that fetched the instruction
    /// at that PC.  Populated once CpuChip emits the ProgramMemory
    /// consumer; until then the chip has zero multiplicity everywhere
    /// (its claimed_sum is 0).
    pub program_memory_counts: HashMap<u32, u32>,
    /// Program's jump_table — the set of valid dynamic-dispatch
    /// targets used by JumpInd / LoadImmJumpInd.  Empty for programs that
    /// don't use indirect jumps (most negative tests).  JumpTableChip
    /// commits to it via its preprocessed Addr/Target columns; CpuChip's
    /// JumpInd consumer demands `(addr=val_b+imm, target=next_pc)`
    /// against that table, balancing dispatch-by-runtime-index.
    pub jump_table: Arc<[u32]>,
    /// Per-jump-table-index count of JumpInd dispatches.  Indexed
    /// by `addr/2 - 1` where `addr = (regs[reg_a] + imm) mod 2^32`; entry N
    /// = number of times the program dispatched through `jump_table[N]`.
    /// Set by CpuChip's trace fill from the JumpInd steps; consumed by
    /// JumpTableChip's main-trace fill as Multiplicity.
    pub jump_table_counts: Vec<u32>,
    /// Per-mul-row witness pushed by CpuChip's trace_fill so
    /// MulChip's main trace mirrors CpuChip's val_b/val_d/result/mul_high
    /// exactly.  Must match the column values CpuChip writes — see
    /// chips/mul.rs's collect path.
    pub mul_entries: Vec<MulEntry>,
    /// Per-bitwise-row witness pushed by CpuChip's trace_fill
    /// so BitwiseChip's main trace mirrors CpuChip's val_b/val_d/result
    /// + and_result + nibble decompositions exactly.
    pub bitwise_entries: Vec<BitwiseEntry>,
    /// Per-compare-or-branch-row witness pushed by CpuChip
    /// so CompareChip's AIR can re-prove the unsigned-LT carry chain.
    pub compare_entries: Vec<CompareEntry>,
    /// Per-divrem-row witness for DivRemChip.
    pub divrem_entries: Vec<DivRemEntry>,
    /// Memory-page Merkle boundary payload, built on the prove path by
    /// [`SideNote::ingest_memory_pages`].  Holds the listed pages' entering /
    /// exit images, the boundary multiproof (leaves + merge schedule + roots),
    /// and seeds `merkle_blake2b_calls`.  `MemoryChip` reads it to inject the
    /// per-page ts=0 boundary writes + closing reads, `MemoryPageChip` produces
    /// the leaf hashes, `MemoryMerkleChip` the merge rows, and
    /// `MemoryRootBoundaryChip` consumes the root.  `None` until ingested (and
    /// on the verify path, which never needs it — the new chips are
    /// unconditionally active and their preprocessed traces are row-index pure).
    #[cfg(feature = "prover")]
    pub memory_pages: Option<MemoryPagePayload>,
    /// The pages the program may touch, and how: `MemoryPageChip`'s
    /// preprocessed regions, so part of its proof's program identity.
    /// Every page writable unless a layout is attached
    /// ([`Self::with_memory_layout`]), as a kernel's is.
    pub memory_layout: crate::chips::memory_page::MemoryLayout,
}

/// The chain-side trace holder: everything a chain pass needs from a traced
/// run — the program-static fields, the initial memory/register state, and
/// the BLAKE2b precompile's call/mem-op streams — with the steps in
/// [`CompactStep`] form (no per-step register snapshots), so a
/// multi-million-step chain resides at ~2.6× less than a full [`SideNote`].
///
/// Windows are materialized per segment by
/// [`crate::segment::CompactSegmentCursor`], which threads the memory image
/// and the register file forward and yields `SideNote`s identical to
/// slicing a full trace ([`crate::segment::segment_side_note`]) — the
/// chips never see this type. Single-proof paths expand the whole run via
/// [`Self::into_side_note`] instead.
pub struct CompactTrace {
    /// The execution trace in compact form (ts-ascending, one per step).
    pub steps: Vec<CompactStep>,
    /// Register file entering `steps[0]` (the interpreter's seeded file) —
    /// the base the per-step [`crate::core::step::RegWrite`]s thread from.
    pub initial_regs: [u64; NUM_REGS],
    /// Program bytecode.
    pub code: Vec<u8>,
    /// Bitmask for instruction validation.
    pub bitmask: Vec<u8>,
    /// Initial memory state (flat_mem entering the traced run).
    pub initial_memory: Vec<u8>,
    /// Program's jump_table (program-static, shared by all segments).
    pub jump_table: Vec<u32>,
    /// The BLAKE2b precompile's call/mem-op streams, exactly as a full
    /// `SideNote` carries them (parallel 1:1, ts-ascending).
    pub blake2b_calls: Vec<crate::chips::blake2b::Blake2bCall>,
    pub blake2b_mem_ops: Vec<crate::core::tracing::Blake2bMemOp>,
    /// The pages the program may touch (program-static).
    pub memory_layout: crate::chips::memory_page::MemoryLayout,
}

impl CompactTrace {
    pub fn num_steps(&self) -> usize {
        self.steps.len()
    }

    /// Expand into the full `SideNote` the single-proof paths hold: steps
    /// with snapshots rebuilt from `initial_regs` and the streams moved
    /// over. Note
    /// `SideNote::initial_regs` stays at its all-zero default (as on the
    /// historical assembly path); `prove` seeds it from
    /// `steps[0].regs_before`.
    pub fn into_side_note(self) -> SideNote {
        let steps = expand_steps(&self.steps, self.initial_regs);
        let mut sn = SideNote::new(steps, self.code, self.bitmask)
            .with_memory(self.initial_memory)
            .with_jump_table(self.jump_table)
            .with_memory_layout(self.memory_layout);
        sn.blake2b_calls = self.blake2b_calls;
        sn.blake2b_mem_ops = self.blake2b_mem_ops;
        sn
    }
}

/// One listed page's entering and exit byte images (each `PAGE_SIZE` bytes).
#[cfg(feature = "prover")]
#[derive(Clone, Debug)]
pub struct MemoryPageImage {
    pub page_idx: u32,
    /// Entering image bytes (root-before leaf input).
    pub before: Vec<u8>,
    /// Exit image bytes (root-after leaf input).
    pub after: Vec<u8>,
}

/// Per-segment memory-page Merkle boundary payload (design §1–§3).
#[cfg(feature = "prover")]
#[derive(Clone, Debug)]
pub struct MemoryPagePayload {
    /// Listed pages with entering/exit images, sorted ascending by page index;
    /// parallel to `multiproof.leaves`.  Always contains page 0.
    pub pages: Vec<MemoryPageImage>,
    /// The boundary multiproof: leaf before/after hashes, the bottom-up merge
    /// schedule, and the two recomputed roots.
    pub multiproof: crate::page_merkle::MerkleMultiproof,
}

/// Single divrem-row witness for the DivRemLookup
/// balance.  div_corr_hi / div_corr_carry are DivRemChip-internal;
/// the 4 sign bits flow from CpuChip via the lookup
/// tuple so DivRemChip can run the sign-correction chains.
#[derive(Clone, Debug)]
pub struct DivRemEntry {
    pub val_b: u64,
    pub val_d: u64,
    pub div_quotient: u64,
    pub div_remainder: u64,
    /// High 8 bytes of the schoolbook output.  Internal to
    /// DivRemChip — pinned by the schoolbook chain on DivU rows and
    /// additionally by the sign-correction chain on DivS rows.
    pub div_corr_hi: [u8; 8],
    /// Per-byte carry of the sign-correction chain.  Internal
    /// witness on DivRemChip.
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
    /// 4 sign bits flowed from CpuChip.  Bound on CpuChip
    /// via nibble lookups; consumed here for the DivS
    /// sign-correction chain.
    pub sign_bit_b: u8,
    pub sign_bit_d: u8,
    pub sign_bit_q: u8,
    pub sign_bit_r: u8,
    /// |val_d| / |div_remainder| via two's-complement
    /// conditional negation + comparison chain.  All six arrays are
    /// DivRemChip-internal; gated on sign_bit_d/sign_bit_r.
    pub abs_d: [u8; 8],
    pub abs_d_carry: [u8; 8],
    pub abs_r: [u8; 8],
    pub abs_r_carry: [u8; 8],
    pub abs_cmp_diff: [u8; 8],
    pub abs_cmp_carry: [u8; 8],
}

/// Single compare-or-branch-row witness for the
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

/// Single bitwise-row witness for the BitwiseLookup balance.
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
    /// Schoolbook low/high outputs (separate from `result`,
    /// which differs per variant — see CpuChip's result-binding logic
    /// for non-rotate Mul64 / RotL64 / MulUpper variants).
    pub unsigned_product_low: u64,
    pub unsigned_product_hi: u64,
    /// Per-position carry of the schoolbook chain (16 bytes).
    /// `mul_carry + 256·mul_carry_hi` reconstructs the full ≤16-bit
    /// carry; busiest at position k=3 for 0xFFFF_FFFF² ≈ 0x3FB.
    pub mul_carry: [u8; 16],
    pub mul_carry_hi: [u8; 16],
    /// Sign-correction terms.
    /// `term_a` = sa·val_d for SU/SS, 0 for UU.
    /// `term_b` = sb·val_b for SS, 0 elsewhere.
    pub mul_corr_term_a: [u8; 8],
    pub mul_corr_term_b: [u8; 8],
    /// Per-byte carry chain for `result + term_a + term_b ≡
    /// unsigned_product_hi (mod 2^64)` on is_mul_upper rows.
    pub mul_corr_carry: [u8; 8],
    /// Bit 7 of val_b's MSB (val_b\[7\] for 64-bit, val_b\[3\]
    /// for 32-bit).  Used by sign correction.
    pub sign_bit_b: u8,
    pub sign_bit_d: u8,
    /// Rotate-class flags driving result-variant dispatch.
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
        Self::new_shared(steps, code.into(), bitmask.into())
    }

    /// Construct a side note while sharing immutable program artifacts.
    /// Refine uses this across machine slices so repeated boundaries retain
    /// one program allocation rather than one copy per child proof.
    pub(crate) fn new_shared(steps: Vec<PvmStep>, code: Arc<[u8]>, bitmask: Arc<[u8]>) -> Self {
        Self {
            steps,
            code,
            bitmask,
            range256_counts: vec![0u32; 256],
            bitwise_and_counts: HashMap::new(),
            bitwise_and_byte_counts: vec![0u32; 1 << 16],
            initial_memory: Vec::new(),
            sparse_initial_memory: None,
            num_initial_mem_entries: 0,
            power_of_two_counts: vec![0u32; 64],
            popcount_counts: vec![0u32; 256],
            bitcount_counts: vec![0u32; 256],
            byte_to_bits_counts: vec![0u32; 256],
            blake2b_calls: Vec::new(),
            blake2b_mem_ops: Vec::new(),
            merkle_blake2b_calls: Vec::new(),
            merkle_blake2b_mults: Vec::new(),
            initial_regs: [0u64; NUM_REGS],
            final_regs: [0u64; NUM_REGS],
            closing_chip_active: false,
            program_memory_counts: HashMap::new(),
            jump_table: Arc::from([]),
            jump_table_counts: Vec::new(),
            mul_entries: Vec::new(),
            bitwise_entries: Vec::new(),
            compare_entries: Vec::new(),
            divrem_entries: Vec::new(),
            #[cfg(feature = "prover")]
            memory_pages: None,
            memory_layout: Default::default(),
        }
    }

    /// Build the memory-page Merkle boundary payload for this segment
    /// (design §0–§3).  Enumerates the touched pages (always adding page 0, so
    /// the listed set is never empty and the new chips stay unconditionally
    /// active), takes the entering image (`initial_memory`) and the exit image
    /// (`replay_writes(.., None)`), recomputes both roots via a boundary
    /// multiproof, and seeds `merkle_blake2b_calls` with the exact compressions
    /// the `Blake2bBoundaryChip` must prove (one per in-circuit consumption,
    /// duplicates kept).  Prove-path only; idempotent (rebuilds from scratch).
    #[cfg(feature = "prover")]
    pub fn ingest_memory_pages(&mut self) {
        use crate::page_merkle;
        let mut touched = page_merkle::touched_pages(self);
        touched.insert(0); // never-empty page set (design §0)
        let sparse_exiting = self
            .sparse_initial_memory
            .as_ref()
            .map(|_| crate::segment::replay_sparse_writes(self, None));
        let dense_exiting = sparse_exiting
            .is_none()
            .then(|| crate::segment::replay_writes(self, None));
        let mp = match (&self.sparse_initial_memory, &sparse_exiting) {
            (Some(entering), Some(exiting)) => {
                page_merkle::build_sparse_multiproof(entering, exiting, &touched)
            }
            _ => page_merkle::build_multiproof(
                &self.initial_memory,
                dense_exiting.as_deref().unwrap_or_default(),
                &touched,
            ),
        };
        // Unique compressions with per-consumption multiplicities: the
        // page/merge chips emit −1 per consumption, the boundary chip
        // produces +EmitMult per unique compression — same balance design
        // §4's one-block-per-consumption scheme held, at far fewer rows.
        let (calls, mults) = match (&self.sparse_initial_memory, &sparse_exiting) {
            (Some(entering), Some(exiting)) => {
                page_merkle::sparse_boundary_blake2b_calls(&mp, entering, exiting)
            }
            _ => page_merkle::boundary_blake2b_calls(
                &mp,
                &self.initial_memory,
                dense_exiting.as_deref().unwrap_or_default(),
            ),
        };
        self.merkle_blake2b_calls = calls;
        self.merkle_blake2b_mults = mults;
        let pages = touched
            .iter()
            .map(|&p| {
                let (before, after) = match (&self.sparse_initial_memory, &sparse_exiting) {
                    (Some(entering), Some(exiting)) => (entering.page(p), exiting.page(p)),
                    _ => (
                        page_merkle::page_bytes(&self.initial_memory, p),
                        page_merkle::page_bytes(dense_exiting.as_deref().unwrap_or_default(), p),
                    ),
                };
                MemoryPageImage {
                    page_idx: p,
                    before: before.to_vec(),
                    after: after.to_vec(),
                }
            })
            .collect();
        self.memory_pages = Some(MemoryPagePayload {
            pages,
            multiproof: mp,
        });
    }

    /// Builder-style setter: attach a program's jump_table to this side note.
    /// Used by tests and prove paths to seed JumpTableChip's preprocessed
    /// table.  No-op for programs that don't use JumpInd / LoadImmJumpInd
    /// (the chip then has zero-multiplicity rows).
    pub fn with_jump_table(mut self, jump_table: Vec<u32>) -> Self {
        self = self.with_shared_jump_table(jump_table.into());
        self
    }

    pub(crate) fn with_shared_jump_table(mut self, jump_table: Arc<[u32]>) -> Self {
        self.jump_table_counts = vec![0u32; jump_table.len()];
        self.jump_table = jump_table;
        self
    }

    /// Attach the program's layout: the pages it may touch, and how.
    pub fn with_memory_layout(mut self, layout: crate::chips::memory_page::MemoryLayout) -> Self {
        self.memory_layout = layout;
        self
    }

    pub fn with_memory(mut self, flat_mem: Vec<u8>) -> Self {
        self.initial_memory = flat_mem;
        self.sparse_initial_memory = None;
        self
    }

    /// Attach a canonical sparse entering-memory image.
    pub fn with_sparse_memory(mut self, image: crate::SparseMemoryImage) -> Self {
        self.initial_memory.clear();
        self.sparse_initial_memory = Some(image);
        self
    }

    pub(crate) fn has_initial_memory(&self) -> bool {
        !self.initial_memory.is_empty() || self.sparse_initial_memory.is_some()
    }

    pub(crate) fn initial_memory_byte(&self, address: u32) -> u8 {
        self.sparse_initial_memory.as_ref().map_or_else(
            || {
                self.initial_memory
                    .get(address as usize)
                    .copied()
                    .unwrap_or(0)
            },
            |image| image.byte(address),
        )
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

    pub fn add_bitwise_and(&mut self, a: u8, b: u8) {
        // Split each byte into nibbles for the 16×16 lookup table
        let a_lo = a & 0x0F;
        let a_hi = (a >> 4) & 0x0F;
        let b_lo = b & 0x0F;
        let b_hi = (b >> 4) & 0x0F;
        *self.bitwise_and_counts.entry((a_lo, b_lo)).or_insert(0) += 1;
        *self.bitwise_and_counts.entry((a_hi, b_hi)).or_insert(0) += 1;
    }

    /// One byte-wide AND lookup into the `BitwiseAndByteChip` table — used by
    /// the blake2b chips (one emission per byte AND, vs the two nibble
    /// emissions `add_bitwise_and` records).
    pub fn add_bitwise_and_byte(&mut self, a: u8, b: u8) {
        self.bitwise_and_byte_counts[((a as usize) << 8) | b as usize] += 1;
    }
}
