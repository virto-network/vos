# Practical proving times for the conservation-of-value transition

Status: PLAN (not started). The succinct-witness work made the transition
proof *ledger-size-independent* and *provable in bounded memory*; this plan
makes it *fast enough to use*. Companion: the verifier-side chain
verification gap (see `succinct-merkle-witness.md`) — several levers below
interact with it, so the two should be designed together even if shipped
separately.

## Where we are (measured)

A 2-account, 1-settled-debit batch with the succinct witness:

- **7.56M PVM steps**, proven as 16 × 500K-step segments.
- **~88 min sequential** wall-clock (debug build, MOBILE FRI blowup 2),
  ~5–7 min/segment, ~6 GB prove working set per segment.
- The full-trace `SideNote` holds ~14–16 GB (≈2 KB/step) — the reason
  segmentation and proving currently share one machine-sized process.
- Trace composition (`measure_transition_trace`): LoadIndU64 1.03M +
  StoreIndU64 1.01M (27% of all steps are 8-byte memory moves), Add64 854K,
  AddImm64 790K, BranchLtU 356K, shifts ~560K. Crypto is already ECALLs
  (blake2b ×3.5K, ristretto ×7) — **steps are spent moving bytes around the
  SMT/multiproof/rkyv plumbing, not hashing**.

Cost scales with the batch (`O(touched · log N)`), so per-segment numbers
are the unit economics: every 500K steps ≈ 5–7 min today.

## Targets

- **T1 (pilot)**: typical 1–5 event batch proves in **< 5 min wall-clock**
  on one beefy dev box. Achievable with quick wins alone (see below).
- **T2 (production)**: **< 1 min** for typical batches on a small prover
  pool; proof bytes + verify cost acceptable for the bridge (ties into
  chain verification / aggregation).

## Levers, in order of (value ÷ effort)

### 0. Measure properly first
- Build a **PVM trace profiler**: map each step's `pc` to an ELF symbol and
  emit a per-function step histogram (the opcode histogram exists; the
  *function* attribution doesn't). One afternoon; everything below should
  be ranked by its output, not by intuition.
- Re-measure prove time on a **release** build of zkpvm/Stwo. All chain
  numbers to date are debug-profile. Likely a multiple, possibly a large
  one; this single datum reshapes the whole plan.

### 1. Parallel segment proving (quick, no soundness surface)
Segments prove independently — the chain is embarrassingly parallel.
- In-process: 2–3 concurrent segments fit a 62 GB box today (shared full
  trace + ~6 GB/segment). Wall-clock → ~⌈16/3⌉ × 6 min ≈ 35 min, before
  release-build gains.
- The blocker for wider fan-out is the **SideNote footprint** (lever 3) and
  `segment_side_note`'s O(a) write-replay per segment (compute prefixes
  once, share).
- Multi-machine later: ship `(witness, [a,b))` to workers; needs nothing
  cryptographic, just orchestration in the prover extension.

### 2. FRI/PCS tuning (cheap, bounded win)
- We already use MOBILE (blowup 2). Audit `pow_bits`, `lifting_log_size`,
  and per-chip `max_constraint_log_degree_bound` for headroom at log19.
- Smaller segments (250K) halve per-segment memory and latency at 2× count
  — relevant for parallelism granularity, not total work.

### 3. Slim the trace plumbing (the big structural lever)
Ranked by the opcode histogram; re-rank with the profiler:
- **Wide memory ops**: a 32-byte copy today costs ~10+ steps (4 loads +
  4 stores + addressing). The SMT path shuffles 32-byte hashes constantly.
  Options: a `memcpy`-style ECALL precompile (with a dedicated chip à la
  blake2b), or grey emitting fused multi-word moves. Eliminating half the
  Load/StoreIndU64 traffic ≈ −25% steps.
- **Composite SMT-node precompile**: `smt_node_hash` = domain || l || r
  through blake2b ECALL, but the buffer assembly is raw steps ×
  (#nodes ≈ touched × 128 × 2 trees-ish). A single ECALL taking two hash
  pointers and a domain tag removes the assembly cost.
- **rkyv access pattern**: measure what fraction of segment 0 is witness
  decode; rkyv is nominally zero-copy — if the guest is deserializing into
  owned structures (it is: `from_bytes` → owned), switching hot paths to
  archived-view access could remove a large constant.
- **Kernel bookkeeping**: `BTreeMap`/clone-heavy paths in `SparseLedger`
  and `apply_batch_refine` run in-guest; profile, then replace hot
  structures with sorted-slice operations (the snapshot module already
  did this dance for the actor).

### 4. SideNote/PvmStep diet (enables 1 at scale)
≈2 KB/step is mostly `regs_before`/`regs_after` arrays per step. Store
register *deltas* (each step writes ≤1 register) + reconstruct on slice;
expected ~10× smaller traces → full trace in ~1.5 GB → wide in-process
parallelism, cheaper segmentation, and tracing of much larger batches.
Touches the tracer, the chips' trace-fill (which read `regs_before` by
index), and `segment_side_note` — mechanical but broad; do after the
profiler confirms nothing bigger is hiding.

### 5. Prover backend (research spike, parallel track)
- Stwo SIMD backend is in use; assess the GPU backend (icicle-stwo) on one
  segment — if a segment proves in seconds on a consumer GPU, levers 1–4
  change priority.

### 6. Architecture (couples with chain verification — design together)
- **Memory continuity**: paged/Merkle memory images (Risc0-style
  continuations) or a shared-challenge memory-handoff argument would make
  segment boundaries *verifier-checkable* AND remove the O(a)
  write-replay from segmentation. This is the soundness gap named in
  `succinct-merkle-witness.md`; it is also a proving-time feature because
  it unlocks distributed proving with verifiable handoffs.
- **Recursive aggregation**: fold the 16 segment proofs into one (one
  commitment, one verify) — fixes the bridge-verification model and
  amortizes verify cost; biggest build on this list.

## Suggested session shape

1. Profiler + release-build measurements (half-day, decides everything).
2. Quick wins: parallel segments + PCS audit → re-measure (target T1).
3. One trace-plumbing lever from §3, chosen by profile, → re-measure.
4. Write the memory-continuity design (with the aggregation track) as the
   follow-on plan.

## Non-goals here

- Verifier-side chain verification mechanics (own plan; §6 only pins the
  coupling).
- Changing the witness format or kernel semantics — Phase 0 shipped; the
  proof statement stays fixed while we make it cheaper.
