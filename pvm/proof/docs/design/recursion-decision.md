# Recursion / aggregation: decision record

**Question.** Can the N per-segment proofs of a `verify_chain` be folded into ONE
recursive proof — verifying each segment plus boundary (incl. memory) continuity
inside a recursive STARK — on this M31/Blake2s zkpvm?

**Verdict: native FRI-STARK recursion is not viable here (measured), and Track A
does not need it.** Two products share one verifier:

- **Track A — a single light transition, verified directly on-chain.** One small
  program (e.g. a light voucher state transition, a few thousand steps) proves as
  ONE segment and its proof is verified on-chain (JAM PVM / Substrate). No
  recursion. This is complete and shippable, and is exactly what the
  `settlement-verifier` crate does (a verify-only Poseidon2-over-M31 stwo verifier
  that builds `no_std` for the JAM PVM and wasm32). Track A is unaffected by the
  recursion verdict.

- **Track B — fold many segments (the capstone is 76) into one constant-size
  aggregate.** This is where recursion would have paid off, and it is where the
  wall is.

## Why native recursion is dead

Verifying a base segment is Θ(n_queries × committed_columns), and the base trace
is WIDE (~15,775 columns). Both routes blow up on that width:

- **In-AIR self-verify** and **LIFT (verifier-as-guest)**: a single join is
  ~600–750M instructions (~2000× one provable segment) with a ~69 GiB memory
  wall; K-splitting the join diverges rather than converging.
- Root cause: the base width under a **non-homomorphic** (Merkle/FRI) commitment.

The ecosystem confirms the shape of the problem: stwo core ships no verifier-AIR
and no M31-algebraic PCS hasher; Nova-style folding is mathematically
inapplicable to FRI/Blake2s commitments; StarkWare's supported recursion path is
cross-VM (`stwo-cairo`). A de-risk spike showed only that the *PCS foundation*
(a custom Poseidon2-over-M31 Merkle hasher/channel) is plumbing-feasible on
`CpuBackend`; the verifier-as-AIR that would sit on it is a multi-person-month
build, and the width wall above makes the resulting per-join cost intractable
regardless.

Note recursion was never the cross-node delivery mechanism: per-segment proofs
verify independently, so a per-segment **manifest**
(`../plans/roadmap.md`) delivers a chain across nodes with no
crypto change. Recursion's only exclusive payoff is succinctness (one proof for a
single cheap on-chain check).

## Path forward for Track B (open)

Choosing the aggregation primitive is a product decision gated on two forks:

1. **Sum-check / GKR + jagged PCS** (SP1-Hypercube-style, production + audited).
   A sum-check verifier is **width-independent**, which structurally removes the
   wall; M31 and transparency are retained. Cost: a base re-architecture
   (FRI → sum-check).
2. **STARK→SNARK pairing wrap** (Groth16/Plonk over the STARK). Feasible sooner
   and gives an O(1) on-chain verify, but heavy and it forfeits post-quantum at
   the wrap. A wrap is needed anyway for direct EVM verification (the EVM cannot
   verify a FRI-STARK), so native M31 aggregation would only ever sit *beneath* a
   wrap to shrink 76 → 1 before it.

The two forks: (a) is **post-quantum** required end-to-end? — if so the wrap is a
stopgap and the destination is transparent sum-check. (b) does Track B need an
aggregation TREE at all, or does a **streaming prover** (Jolt-style, bounded RAM,
no recursion) fit VOS's refine/accumulate execution model?

Rejected: folding (this project's Nexus origin already retreated from it to the
current Stwo/M31 stack); a narrow app-specific AIR (the zkVM is general-purpose).

## What is usable today

The general-purpose base prover, per-segment (`verify_standalone`) and chain
(`verify_chain`) verification, and the Track-A on-chain verify path all work. The
in-AIR recursion machinery that produced the measurements above is preserved in
git tag `voucher-recursion-archive`; it is not in the working tree.
