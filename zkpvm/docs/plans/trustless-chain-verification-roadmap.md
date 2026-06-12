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
with an in-circuit-bound Merkle root of the RAM, so
`verify_chain_standalone`'s boundary continuity becomes SOUND for memory. This
closes the last money-path gap and composes to C.

Mechanism (reuses the succinct-merkle BatchProof DESIGN, now IN-AIR instead of
host-side): intra-segment memory consistency is already sound (the v6 offline
memory-checking ledger). What's unbound is the boundary IMAGE. Prove, per
segment, a Merkle MULTIPROOF over the touched pages:
- the segment's initial-memory reads (read-before-write) are the leaves of
  `initial_root` at their page addresses (recompute `initial_root` from the
  read leaf values + witnessed shared siblings);
- applying the segment's net writes to those leaves, with the SAME siblings
  (untouched subtrees are unchanged), recomputes `final_root`.
Bind `initial_root` / `final_root` into the boundary states via the
boundary-binding mechanism (mirror RegisterMemoryBoundaryChip / Closing).
Hashes = blake2b via Blake2bChip. Cost ≈ (touched pages + frontier siblings)
blake2b per segment — NOT per-page-full-depth.

Tasks:
1. **MEASURE** the per-segment touched-memory boundary (`first_access.len()` /
   distinct touched pages at each segment cut) on the real 7.5M-step workload.
   Decides page granularity + sizes the blake2b cost (KBs of pages = cheap;
   MBs = painful but still sound). This is the one concrete next step; it also
   retroactively confirms A was the right call vs B.
2. **Page granularity** decision (e.g. 64–256-byte pages → sparse Merkle keyed
   by page address, depth = page-address bits; bigger pages = shallower tree
   but a write re-hashes a whole page). Lay a page abstraction over the
   byte-granular ledger.
3. **Memory-Merkle subsystem in the AIR**: a chip (or chips) that verifies the
   boundary multiproof against `initial_root`/`final_root` using Blake2bChip;
   wire the touched-page set from the existing memory ledger.
4. **Boundary chips + binding**: `initial_root`/`final_root` become bound public
   inputs (boundary_binding recompute). SegmentState gains the roots (keep
   `memory_commitment` as the root, or add fields); `verify_chain` /
   `verify_chain_standalone` continuity now bound for memory.
5. **Format bump (v7)** + history; capstone re-prove (`--release`, box quiet);
   rebuild prover .so before federation e2e. Same playbook as the v6
   read-consistency fix.
6. **Gate test**: a from-scratch prover that ships a forged boundary memory
   (initial ≠ prior final) is REJECTED — mirrors `ledger_readconsistency_gate`.

Open design Qs: page size; sparse-Merkle vs fixed-depth; whether to verify the
multiproof in a dedicated chip vs. fold into the memory ledger; how the root
threads across segments at trace-gen (segment.rs `replay_writes` already
reconstructs the entering image — it would compute the entering root too).

## Phase C1 — switch the STARK PCS to Poseidon2-over-M31 (RECURSION PREP)

Make zkpvm proofs cheap to verify in a circuit: replace the blake2s Merkle +
Fiat-Shamir channel in zkpvm's `PcsConfig` with **Poseidon2-over-M31** (the
recursion-friendly hash; < 10K hashes ⇒ sub-second recursive proving per the
L2IV/StarkWare work). stwo ships poseidon hashers + a Poseidon2 hash-AIR
example; the M31 Poseidon2 path may need wiring. Tradeoff: base proving slows
(blake2s is faster per-hash on a CPU); only worth it once committed to C.
Independent of Phase A (A's memory tree stays blake2b).

## Phase C2 — the recursive verifier / aggregator (SUCCINCTNESS)

Fold the N Poseidon2-committed segment proofs into one. Two routes:
- **Native AIR** (Plonk component + Poseidon2-over-M31 builtin, per the L2IV
  "Recursive Proofs in Stwo" design; `recursive-stwo-bitcoin` is a full
  stwo-verifier reference, though emitted as Bitcoin Script). Most control,
  biggest build.
- **Via `stwo-cairo`** (StarkWare-supported): verify zkpvm segment proofs inside
  a Cairo program, prove that. Cross-VM dependency, less control, but reuses
  StarkWare's shipping recursive-proving pipeline.
The aggregator verifies each segment + chains the bound memory roots (Phase A) +
register/pc/ts continuity → one proof, one commitment (also dissolves the
variable-segment-size program-identity nuance noted in `verify_chain_standalone`).

## Sequencing

A (soundness, ships now, no stwo change) → C1 (PCS swap) → C2 (aggregator).
A is independently valuable (closes the money-path gap on the existing flat
chain) AND is the foundation C stands on. C1+C2 are the succinctness end-state,
pursued when the one-proof aggregation is worth the build. First concrete action:
the Phase-A boundary measurement.
