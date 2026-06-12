# Spike: recursive aggregation (approach C) feasibility

**Question:** can we fold the N segment proofs of a `verify_chain` into ONE
recursive proof — verifying each segment + the boundary continuity (incl.
memory) inside a recursive STARK circuit — on this stwo?

**Verdict (revised after a web/ecosystem check — see "Ecosystem" below):**
recursion for stwo proofs is REAL and tractable in the ecosystem (StarkWare
ships circuit-based recursive proving, "minutes → seconds"), but it is NOT in
the stwo CORE crate and is not drop-in for our M31 zkpvm. For OUR zkpvm,
approach C needs: (1) switching zkpvm's PCS from Blake2s to Poseidon2-over-M31
(recursion-friendly hash), and (2) either verifying segment proofs inside a
Cairo program via `stwo-cairo` (cross-VM, heavyweight, the StarkWare-supported
path) or building a native recursive-verifier AIR (Plonk + Poseidon2 builtin,
per the L2IV/StarkWare design; a Bitcoin-Script reference impl exists). Both are
substantial. CRUCIALLY, recursion is ORTHOGONAL to the memory-binding
soundness: even a recursive verifier checks the SAME unbound
`memory_commitment` metadata, so approach A (per-segment in-circuit memory
binding) is required in zkpvm regardless. Recommendation unchanged for the
money-path gap: bind memory continuity with A (Merkle memory) or B (handoff)
now; pursue C as a later succinctness/aggregation layer.

## What a recursive verifier needs vs. what stwo has

A Circle-STARK recursive verifier is the entire stwo verifier re-expressed as
an AIR (constraints), over M31, using a hash cheap to verify in-circuit:

| Verifier op (must become AIR constraints) | In stwo today |
|---|---|
| FRI folding + per-query consistency | host-side Rust only — `core/fri.rs` (**1240 lines**), no `EvalAtRow` form |
| Merkle path verification | host-side — `core/vcs/verifier.rs` |
| OODS sampling + DEEP composition | host-side — `core/verifier.rs` (143 lines) |
| Channel / Fiat-Shamir (Blake2s) | host-side; Blake2s is NOT in-circuit-friendly |
| Constraint composition eval | host-side |

Grounding (searched the stwo checkout):
- **No `EvalAtRow` anywhere in `core/`** — i.e. NONE of the verifier ops are
  written as constraints. There is no FRI-as-AIR, no verifier-as-AIR.
- **No recursive-verifier crate, no recursion example, no recursion docs.**
  Crates are `air-utils`, `constraint-framework`, `examples`
  (blake/plonk/poseidon/state_machine/wide_fibonacci/xor — standard AIRs),
  `std-shims`, `stwo`. The only "recursion" strings are recursive *functions*
  (poly utils), not proof recursion.
- **No usable recursion-friendly hash for M31.** Recursion-friendly hashing
  needs Poseidon-over-M31. stwo ships a Poseidon2 *hash AIR* example (a
  building block) and a `poseidon252_merkle` hasher — but the latter is over
  the 252-bit Starknet field (`starknet_crypto`, `FieldElement252`) and marked
  `#![allow(unused)]`, not M31. The production PCS uses Blake2s (fast prover,
  recursion-hostile).

So building C = implementing a full M31 Circle-STARK verifier AIR (FRI + Merkle
+ OODS + composition) on top of a Poseidon2-over-M31 Merkle/channel that would
also have to be wired into the PCS. This is a multi-person-month effort — the
kind of work the stwo team does upstream — not a near-term project.

## Upstream check (not just the pin) — verdict holds

Verified against live upstream on 2026-06-12 (not only the pinned checkout):
- Our pin `e1286720` (2026-05-04) is on **`dev`**, stwo's active default branch.
  (`main` is a stale 2025 branch — PR #975, toolchain `20250102` — a red
  herring; do not use it as the reference.)
- `dev` HEAD `cca9811` (2026-05-13) is **2 commits ahead** of our pin (a README
  rewrite + a logup-batching tweak). So our pinned stwo is essentially current.
- No recursion on latest `dev`: identical crate layout, no `EvalAtRow`-based
  verifier in `core/`/`prover/`, and none of the 983 remote branches is named
  for recursion/aggregation/verifier-AIR.
- The README lists "proof aggregation" only as a *use case stwo enables*, not a
  shipped feature.
- StarkWare's real recursion path is the sibling repo **`stwo-cairo`** (verify
  stwo proofs inside a Cairo program, then prove that with stwo-cairo) — active
  (pushed 2026-06-11) but indirect and heavyweight for our zkpvm (we'd verify
  zkpvm proofs in Cairo), and it surfaces no reusable native verifier component.

So there is no "just bump stwo" shortcut, and no near-term upstream recursion to
wait on a few weeks for; native AIR recursion remains a multi-month build.

## Ecosystem (web search, 2026-06-12) — recursion IS happening, just not in stwo-core

A repo-only check misses this; a web search for "stwo recursive proofs" surfaces
active, real recursion work:
- **StarkWare blog "minutes to seconds":** circuit-based recursive proving is
  shipping for stwo (validation reduced from minutes to seconds).
- **`stwo-cairo` (StarkWare, the supported path):** a Cairo verifier of stwo
  proofs runs inside the Cairo VM → recursive proving, on-chain verification,
  and proof-aggregation pipelines. To use it for our zkpvm you'd verify zkpvm
  segment proofs inside a Cairo program — a heavyweight cross-VM dependency.
- **L2IV "Recursive Proofs in Stwo" research (with StarkWare):** the native
  recursive verifier = a Plonk component (arithmetic) + a Poseidon2-over-M31
  BUILTIN (hashing). Design-stage series. Key number: < 10,000 Poseidon2-over-M31
  hashes per recursive proof ⇒ sub-second recursive proving is in reach.
- **`recursive-stwo-bitcoin` (Bitcoin-Wildlife-Sanctuary):** a FULL stwo-verifier
  (fiat-shamir, FRI folding, merkle proofs, decommit, OODS) — but emitted as
  BITCOIN SCRIPT via a DSL, not M31 AIR. Proves a stwo-verifier is implementable;
  a useful reference for "what the verifier must compute," not reusable as-is.
- **`stwo-gnark-verifier` (Herodotus):** a Groth16 wrapper for on-chain stwo
  verification (another recursion/wrapping target).

THE ENABLER (consistent across sources): recursion wants the INNER proof on
Poseidon2-over-M31 commitments (not Blake2s) + a Poseidon2 builtin in the
verifier. So adopting C means first switching zkpvm's PCS to Poseidon2-over-M31.

So the corrected read: C is feasible and well-trodden in the ecosystem, but for
our zkpvm it is a PCS change + a verifier build/adopt (native AIR, or Cairo via
stwo-cairo) — a real project, just not the multi-month from-scratch unknown the
repo-only check implied, and not a "bump stwo" freebie either.

## The dependency that reframes C

**Recursion does NOT bind memory continuity by itself.** A recursive aggregator
verifies each segment proof and checks that segment N's *exported* final-memory
commitment equals N+1's *imported* initial one. But that exported commitment
must already be BOUND in-circuit within the segment (a per-segment memory
Merkle root) — otherwise the aggregator is checking the same unbound metadata
the flat chain checks today. So **C sits on top of A** (per-segment in-circuit
memory commitment); you cannot get memory soundness from C without A-like
per-segment binding underneath. C's actual payoff is succinctness (N proofs →
1) + a single program commitment (which also dissolves the variable-segment-
size identity nuance), not the memory binding itself.

## Recommendation

1. **Near term (the money-path soundness):** bind memory continuity with
   **A (Merkle memory)** or **B (grand-product handoff)** on the existing
   N-segment chain + `verify_chain_standalone`. Neither needs recursion. Choose
   A vs B by the cross-segment touched-memory boundary size (measure it — sparse
   ⇒ B is lightest; dense ⇒ A). This closes the actual gap.
2. **Long term (succinctness):** adopt **C (recursion)** as an aggregation
   layer on top of the per-segment memory binding from (1), once upstream stwo
   ships an M31 recursive verifier (or as a dedicated multi-month project).
   Track stwo's recursion roadmap; building it before upstream is unlikely to
   pencil out.

A useful, cheap next step that informs (1): measure the per-segment
touched-memory boundary on the real 7.5M-step workload (`first_access.len()`
per segment cut), which decides A vs B.
