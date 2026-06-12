# Roadmap: trustless multi-segment chain verification → recursive aggregation (C)

The long-term target is **C (recursive aggregation)**: fold the N segment proofs
of a `verify_chain` into ONE recursive proof — one proof, one program
commitment, trustless. This roadmap sequences the path there, starting with the
memory-continuity binding that C requires underneath.

Background: `docs/plans/recursion-spike.md` (why C needs A, and the stwo
recursion ecosystem). Phase-1 already landed: `verify_chain_standalone`
(`zkpvm/verifier`, side-note-free, program-identity-pinned; sound for
registers/pc/ts, with memory continuity as the open gap).

## Decision: start with A (Merkle memory), not B

C chains each segment's EXPORTED, in-circuit-BOUND memory commitment
(`post_root_i == pre_root_{i+1}`) and folds segments one at a time. A produces
exactly that per-segment bound root; B (chain-level grand-product over exposed
boundary I/O with a global post-commitment challenge) gives no local per-segment
value to fold and breaks streaming aggregation. So **B is throwaway for C; A is
the substrate C builds on** (and is what RISC0/SP1 use). A is also sound
regardless of boundary sparsity.

**Key decoupling:** the memory-tree hash ≠ the STARK-PCS hash. The recursive
verifier compares per-segment memory roots as a 32-byte equality (never
re-hashes the memory tree), so A's Merkle can use **blake2b (existing
Blake2bChip)** with NO PCS change. Poseidon2-over-M31 is needed only later, for
the STARK PCS (Phase C1). So A ships on today's stack.

## Phase A — Merkle-ize the zkVM RAM, bind `memory_commitment` (SOUNDNESS; ships now)

Goal: replace `memory_commitment = blake3(flat 4MB image)` (unbound metadata)
with an in-circuit-bound Merkle root of the RAM, so `verify_chain_standalone`'s
boundary continuity becomes SOUND for memory. Closes the last money-path gap;
composes to C. **No PCS / stwo change** — uses blake2b (the existing chip).

### Why it's cheap (MEASURED on the real 7.5M-step workload, `measure_memory_boundary`)

Intra-segment memory consistency is already sound (the v6 offline-memory ledger,
zero hashing per access). We only bind the boundary IMAGE — and the cross-segment
boundary is SPARSE: per segment, distinct touched PAGES are

| page size | max touched pages/seg | avg |
|---|---|---|
| 256 B | 227 | 113 |
| 1024 B | 66 | 34 |
| **4096 B** | **23** | **12** |

So a boundary multiproof is over ~tens of page-leaves, not millions of accesses.

### Mechanism — a boundary Merkle MULTIPROOF (reuse the BatchProof DESIGN, in-AIR)

Reuse cipher-clerk's `BatchProof` algorithm (`merkle.rs`: recompute ONE root from
N touched leaves + a `frontier` of cached untouched-subtree hashes; `root_after`
from updated leaves + the SAME frontier — soundness rests on `root==root_before`).
But express it as AIR constraints + the Blake2bChip, over a tree keyed by PAGE
ADDRESS (NOT 128-bit hashed keys). Per segment, prove:
- recompute `initial_root` from the read-before-write page leaves (leaf =
  blake2b(page bytes)) + witnessed frontier siblings;
- recompute `final_root` from the written page leaves (updated) + the SAME
  frontier.
Bind `initial_root`/`final_root` as boundary public inputs (boundary-binding).

### Cost (CRITICAL design lever: tree DEPTH, set by page size)

Blake2bChip = **96 rows / compression**; NO Poseidon in zkpvm (blake2b is the
only in-AIR hash). Cost ≈ (touched-page leaf hashes + ~touched·depth node hashes)
× 96 rows. DEPTH = address_bits − page_bits — so KEY BY PAGE ADDRESS to keep
depth ~10–20 (a 128-deep hashed-key tree like cipher-clerk's would cost ~K·128
hashes — too much). With **4096-B pages** (≤23 touched pages, depth ~10–20):
≈ (23 leaf×32 blocks + 23×~20 nodes) ≈ ~1–2K compressions/segment ≈ **log_size
~17–18** for the boundary Merkle — NON-dominant vs the CpuChip (~2^19–20). Larger
pages → shallower + fewer leaves but bigger leaf hashes; 4096 is the sweet spot
from the measurement. (256-B pages → ~6K comps, log_size ~20: avoid.)

### Surfaces (mapped)

1. **Page abstraction** over the byte ledger; sparse Merkle keyed by page addr.
2. **MemoryMerkleChip** (new): verifies the boundary multiproof as constraints,
   driving blake2b for leaf+node hashes. The Blake2bChip is currently
   ECALL-driven (`blake2b_calls` + `blake2b_mem_ops` binding h/m/out to the
   MEMORY ledger) — the Merkle hashes are NOT guest memory, so EITHER inject
   synthetic `blake2b_calls` from the new chip (like RegisterMemoryClosingChip
   injects synthetic ledger entries) WITHOUT the mem-op binding, OR add a
   separate "boundary-blake2b" path. **OPEN: cleanest blake2b-for-Merkle wiring**
   (the mem-op binding assumption is the one snag — `blake2b/mod.rs` Phase-8
   ECALL binding).
3. **MemoryRootBoundaryChip** (new, mirror `register_memory_boundary.rs`):
   commits `initial_root`/`final_root` columns, bound via boundary_binding.
   `chip_idx` + `BASE_COMPONENTS`: insert `MEMORY_ROOT_BOUNDARY`, shift indices,
   bump `COUNT` (breaks `component_mask` bit positions ⇒ format bump anyway).
4. **SegmentState** (`proof.rs`): ADD `initial_root:[u8;32]`, `final_root:[u8;32]`
   (do NOT reuse `memory_commitment` — keep it as the unbound blake3 hash). FS
   mix in `prove.rs` (after pc/ts) + verifier mirror in `verify.rs`.
   `boundary_binding`: add `expected_memory_root_sum` + `BoundaryChipPositions
   .memory_root_boundary` + a check in `check_boundary_claimed_sums`.
5. **segment.rs** `replay_writes` already reconstructs the entering image — make
   it also compute the entering root + the touched-page frontier witness.
6. **Format bump v6→v7** + history; capstone re-prove (`--release`, box quiet);
   gate test (forged boundary memory REJECTED — mirror
   `ledger_readconsistency_gate`); rebuild prover .so before federation e2e.

## Phase C1 — switch the STARK PCS to Poseidon2-over-M31 (RECURSION PREP; GATED)

Make zkpvm proofs cheap to verify in a circuit: swap the blake2s Merkle +
Fiat-Shamir channel for **Poseidon2-over-M31** (< 10K hashes ⇒ sub-second
recursion, per L2IV/StarkWare). GOOD NEWS: the hash is a TYPE PARAMETER
(`CommitmentSchemeProver<B, MC: MerkleChannel>` / `…Verifier<MC>`), so the swap
is mostly threading the `MC` type through ~22 sites + bumping the wire format
(`Proof.stark_proof: StarkProof<…Hasher>` changes ⇒ verifier-crate lockstep +
format bump). Tradeoff: base proving slows (blake2s is faster per-hash).
**BLOCKER:** stwo has **no M31-native Poseidon2** — only `Poseidon252` over the
252-bit Starknet field (converts M31→felt252; plus a "no SIMD poseidon yet"
TODO). So C1 requires BUILDING/obtaining a `Poseidon2M31MerkleHasher` + channel +
the Poseidon2-over-M31 permutation in stwo. StarkWare's recursion work targets
exactly this hash, so **C is gated on M31-Poseidon2 landing upstream (watch the
stwo `dev` branch) or us building it** — a real external dependency, not a flip.

## Phase C2 — the recursive verifier / aggregator (SUCCINCTNESS; gated on C1)

Fold the N Poseidon2-committed segment proofs into one. Two routes:
- **Native AIR** (Plonk component + Poseidon2-over-M31 builtin, per the L2IV
  "Recursive Proofs in Stwo" design; `recursive-stwo-bitcoin` is a full
  stwo-verifier reference, though emitted as Bitcoin Script). Most control,
  biggest build.
- **Via `stwo-cairo`** (StarkWare-supported): verify zkpvm segment proofs inside
  a Cairo program, prove that. Cross-VM dependency, less control, reuses
  StarkWare's shipping pipeline.
The aggregator verifies each segment + chains the bound memory roots (Phase A) +
register/pc/ts continuity → one proof, one commitment (also dissolves the
variable-segment-size identity nuance from `verify_chain_standalone`).

## Sequencing

**A (now — soundness, no stwo change, MEASURED cheap) → C1 (gated on M31-Poseidon2
existing) → C2 (gated on C1).** A is independently valuable (closes the money-path
gap on the existing flat chain + `verify_chain_standalone`) AND is the substrate
C stands on. C is the succinctness end-state, externally gated on upstream stwo
shipping M31-Poseidon2 (or us building it) — so A is the clear near-term build
and C is "design now, execute when the hash lands". Within A, the natural first
code step is the page abstraction + the MemoryMerkleChip multiproof gadget.
