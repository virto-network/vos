# Slice 5: proving

Plan, draft 6. The owner chose **proving first**: slice 5 builds proving,
and the Clerk across spaces is slice 6 (`slice-6-clerk.md`, draft 2,
with Fable's review folded in).
- **The approach:** this plan proves the general mechanism, any
  attestable kernel reading committed state, with two targets:
  cipher-clerk's settlement window and a solvency predicate.
- **Draft 6 takes the spikes, the width audit and the owner's answers:**
  - JAM verifies statements in this slice, through a **recursion layer**
    that folds a statement's segment proofs into one final proof;
  - **only the final proof is masked.** Segment proofs and the fold
    proofs between them never leave the space's prover role;
  - each kernel proves over the chips it uses (a shape per kernel);
  - the final proof uses the Blake2s channel, and the proofs it folds use
    Poseidon2-M31.
- **Draft 5 took the owner's earlier answers:**
  - arguments are private by default, `#[public]` marks the public ones,
    and the return value is public;
  - attestable methods may read state through `&self`;
  - no unmasked proof outside tests, so masking comes before wiring.
    Draft 6 narrows this with the owner: none leaves the space's prover
    role.

## What exists

- **Two prover paths:**
  - **The refine path** (`prove_refine`) makes one STARK per machine
    slice, unsegmented. Its bundle carries gas, host boundaries and
    per-slice states, and verification replays it.
  - **The chain path** (`prove_chain`, `verify_chain_standalone`) has
    canonical shapes with an allowlist, segments cut by steps and pages,
    the first segment's initial memory root anchored, and
    `final == next.initial`. It needs no replay by construction.
- **Spike 3 proved a derived kernel on the chain path:**
  - the chain path's tracer serves BLAKE2b (`0x400`) in-AIR, after a
    49-line fix for sparse memory;
  - `settlement::window` over vos-tree multiproofs, derived into a
    43,687-byte kernel, runs about 21 compressions per row read at 10^6
    rows;
  - eight journals take 16 segments at the 32,768-step cut: 425 s,
    6.6 GiB peak, 41.5 MB of proof;
  - the page-Merkle boundary costs 6,585 compressions against the
    kernel's 685;
  - the program commitment depends on the observed profile and the
    channel: one kernel showed eight.
- **Spike 1 verified a real segment on the JAM-only host:** 10.65B gas
  as built, about 2 MB of proof.
- **The width audit:**
  - **The AIR is 13,037 columns.** Ristretto is 42% of them, the BLAKE2b
    chips 23% and the page-Merkle boundary 22%.
  - **Verify gas is linear in columns.**
  - **A shape per kernel is sound** (the prove path already drops gated
    chips): the window kernel uses 22 of 32 chips and 7,519 columns.
  - **Stacked, measured:** the leaf-hash fix, the kernel's shape and
    STANDARD settings bring one segment to 1.17B gas (Blake2s) or 2.39B
    (Poseidon2).
  - **Projected:** every further lever leaves 0.45–0.7B. Flat
    verification of a VM segment cannot meet 100M, and no production
    zkVM attempts it.
  - **A dedicated recursion AIR** verifies one segment for about 13% of
    that segment's proving cost. Its final proof is projected at
    60–150M gas and 100–300 KB, once per statement.
- **Spike 2 designed masking** in our Stwo fork, with the rank check
  built. Fable's review requires R1–R8 before it is built (5.4).
  - **Upstream** has zero-knowledge only in its Starknet privacy
    recursion, which blinds a circuit proof with random valid gates
    seeded from the witness. It has no salts, no composition mask and no
    FRI mask.
- **The pinned Stwo has a completeness bug:** its verifier refuses valid
  proofs whose preprocessed tree sits below the lifting height. Upstream
  fixed it in `74951f79`.

## Goals

1. A derived attestable kernel is proved without replay under one
   program identity, over the chips it uses.
2. Kernels prove facts about committed state, read from witnessed rows
   at roots the proof binds.
3. A statement's segment proofs fold into **one final proof** that binds
   only what the kernel declares public.
4. The final proof is zero-knowledge, and is verified by a public JAM
   agent and by peers alike.
5. The carried items, each closed or named to a slice.

## The public-input model

This is the design 5.1 builds and reviews.
- **Arguments are private unless marked `#[public]`; the return value
  is public, as the claim** (the owner's decision). In `#[attestable]`:
  - the window kernel's window, spaces, currency and cut points are
    public, while its rows and paths are private;
  - the predicate's threshold is public, while its account row is
    private.
- **The final proof's public inputs** are:
  - the program id;
  - the format version;
  - the shape class;
  - the public arguments, in clear;
  - the output bytes, opaque and structured by the kernel;
  - the list of roots read, each tagged with its kind.

  At halt, the guest writes their hash into φ9..12. The recursion
  carries it from the last segment to the final proof.
- **Private inputs** (private arguments, witness rows and paths) are
  bound only inside the proofs.
  - **Segment states become witnesses of the recursion.** The fold
    checks `final == next.initial` and the first segment's anchor, so
    the final proof carries no memory roots or registers.
  - **The anchor splits the initial image** into a public part (code
    and data, bound by the program id) and a private part (arguments
    and witness), so the recursion can check the first without seeing
    the second.
  - **The salt page:** 5.1 decides whether it is still needed. It is
    needed if any root over private memory reaches a public input.
    Inside the space the fold proofs are trusted, as the witness rows
    are.
- **Slice 6 needs no format change:** its rows commitment is part of the
  window kernel's output, its sequence cut points are public arguments,
  and its two-anchor reads are a second root.

## Steps

### 5.0 Spikes, each with its decision rule

1–3 are done, with the width audit:
1. **Verify one real segment on JAM.** It does not fit (above), so JAM
   verifies only a recursion proof.
2. **Masking.** Designed, with the rank check built, in our Stwo fork.
   Fable: sound, with changes R1–R8.
3. **A kernel proved on the chain path.** Done, with BLAKE2b in-AIR.

4. **The recursion stack** (new, run before 5.3):
   - **The circuit stack:** StarkWare's (`starkware-libs/proving`,
     Apache 2.0). It needs a move to that monorepo's Stwo, the
     `nightly-2026-01-15` toolchain and edition 2024. A circuit for our
     AIR's constraints is generated by driving each chip's
     `add_constraints` through a gate-recording `EvalAtRow`.
   - **Our own AIR:** a Poseidon2-M31 recursion AIR, on the archived
     PCS plumbing.
   - **Measure:**
     - a final-shape proof (StarkWare's circuit proof, about 319
       columns) verified on the JAM-only host, at a high blowup with the
       Blake2s channel: its gas and bytes. **This is the go or no-go for
       the venue.** Rule: at most 150M gas unmasked.
     - the port's size: vos-core's prover built against the monorepo's
       Stwo on its toolchain, and the breakage counted and classified;
     - one of our chips verified inside the circuit stack, through the
       generated gates;
     - whether the circuit stack has a Poseidon2-M31 gate, or what one
       costs to add (in-circuit Blake2s costs about 5× the recursion);
     - our own AIR's starting point: what the archive holds.
   - **Rule:** the circuit stack if the port is bounded (weeks, not
     months), one chip verifies in-circuit, and the final-shape gas meets
     the rule. Otherwise our own AIR.
   - **The owner decides** on these numbers: the circuit stack moves the
     toolchain and makes upstream's churn ours.

### 5.1 The program identity, the format, and the shape per kernel (design round, reviewed by Fable)

- **The prover path:** kernels on the chain path, re-run by the prover
  from the `Attest` record (program, public and private arguments,
  witness) exactly as the live inner machine ran them.
- **A shape per kernel:** the kernel's component set, taken from its
  code, plus its pinned `log_sizes` per segment class. The verifier
  accepts exactly that set and those sizes. Otherwise a full-set proof
  of the same kernel verifies at 1.6× the gas.
- **One program id** over:
  - `TRANSPILER_VERSION`;
  - `ProgramHash`;
  - the shape (component set and classes);
  - the channel;
  - the preprocessed root;
  - the public data root of the initial image.

  It is kept in the install's `Derivation`.
- **The public-input model above:** the `#[attestable]` split, the
  guest-written io-hash, the initial image's public and private split,
  and the salt page's fate.
- **The channels:**
  - segment and fold proofs on Poseidon2-M31 (format 25), which the
    recursion verifies cheaply;
  - the final proof on Blake2s, which the PVM verifies 2.0–2.3× cheaper;
  - Blake2s segment proofs (format 24) stay for tests.
- **Taken from the spikes:**
  - the leaf-hash fix (`2000c349`, half the Poseidon2 verify cost);
  - the chain tracer's sparse-memory fix;
  - `prove_canonical_with_config` and the component-mask seam
    (`d165a7b6`);
  - Stwo's completeness fix (`74951f79`), through the fork.
- **The legacy tracer's fate:** retired, or kept as the chain path's
  tracer. If retired, slice 1's exception to the allow-set closes here.

### 5.2 Kernels read committed state, through `&self`

- **Read-only `&self`** (the owner's decision): an attestable method may
  take `&self`, and its table and field reads become witnessed reads
  automatically.
  - The live run records the rows it read and their paths.
  - The prover re-runs with them as the witness.
  - The root they are checked against is published.
  - `&mut self` is refused at compile time: a proof states a fact about a
    state, and the handler that receives the output makes any change.
- **Witnesses:**
  - a list of `(root kind, root, BatchProof)`, absence shown by boundary
    leaves, from the start rather than a single root;
  - rows and paths are verified inside the kernel, at the compress
    level.
- **The root at a live attest's version:**
  - the kernel reads against the latest complete root W ≤ V and its
    version, which the `Attest` records;
  - the statement is "as of W", deterministic across replicas, since the
    complete root at W is replicated state;
  - the batch is not held for the root builder.
- **Serving the prover's paths:** an LSM snapshot pinned at W per
  pending attest, bounded in count, until its proof is made. No tree
  versions are needed.
- **Root kinds by host:** a JAM-deployed agent's map rows are a subtree
  of one whole-keyspace tree, so the roots differ by host. VOS≡JAM holds
  for the output, not the roots, and the agreement test excludes roots.
- **Large witnesses** (rows and paths for up to 16 attests a step) go
  through the result-blob path (4.4a), not inside the log entry.
- **vos-tree's hasher** moves to the compress level.

### 5.3 The recursion layer

Built on spike 4's stack.
- **Verify a segment proof inside the recursion:** our AIR's constraints
  as circuit gates (or our own AIR), the Poseidon2-M31 channel, Merkle
  paths and FRI.
- **Fold 2 to 1:** every node padded to one shape, carrying:
  - the program id;
  - the io-hash from the last segment;
  - the first segment's anchor;
  - the boundary states matched between neighbours.

  The root of the tree is one proof per statement, whatever its segment
  count.
- **The final layer:**
  - switches to the Blake2s channel at a high blowup;
  - uses a fold step above 1 if the verify gas needs it;
  - pins its parameters in the format.
- **Leaks to bound:** the segment count shows only as the tree's depth,
  padded to a class.
- **Tests:**
  - a statement's segments folded and the final proof verified;
  - a tampered segment, a swapped segment and a broken boundary each
    refused;
  - a fold over the wrong program id refused.
- **Measured:** recursion prove time and memory per segment and per
  statement; final proof bytes; verify instructions natively.

### 5.4 Zero-knowledge for the final proof

- **Masked: the final proof only** (the owner's decision). It is
  zero-knowledge over its witness, the folded proofs, so those reveal
  nothing outside.
- **Built to spike 2's design** in our Stwo fork, with Fable's R1–R8
  applied to the final layer:
  1. the rank check;
  2. the claimed sums blinded, and the boundary re-cut;
  3. a rank test of the FRI mask;
  4. hedged randomness, H(OS ‖ witness);
  5. a degree audit (the final layer's AIR is ours or StarkWare's,
     chosen with degree ≤2 where masking needs it);
  6. the parameters pinned in the format;
  7. every carrier audited (no root or state outside the proof);
  8. the cost measured.
- **Gates:**
  - leakage: a simulator test where feasible, and the absence of
    segment states checked;
  - soundness: tests for every masked component.
- **Proofs made before masking lands** exist only inside tests: they are
  never stored or sent.

### 5.5 Proving wired into VOS

- **The prover worker:**
  - a node role inside the space's trust domain;
  - a queue, retries, and placement with its 24 GiB;
  - segment and fold proofs kept only inside the role;
  - final proofs stored as aged, content-addressed blobs;
  - the `Attest` record names its final proof.
- **Only masked final proofs leave the prover role** (the owner's
  decision). The format has no unmasked final proof outside tests.
- **Verification without replay** wherever a final proof arrives: at
  ingress, or by a peer.
- **Tests:**
  - **live ≡ proved:** the prover's standalone re-run produces the live
    run's output and io-hash. This pins the kernel's memory layout, so
    5.7's heap change lands before it or excludes kernels;
  - an attest proved, folded and verified;
  - a tampered final proof refused;
  - the Poseidon2 channel's soundness gates run on the proving path;
  - the prover's memory under the 24 GiB cap, for segments and folds.

### 5.6 The JAM verifier agent

- **A public JAM agent verifies final proofs.**
  - The accepted kernel ids are pinned as constants, set by the owner
    and changed by redeploy. The registry takes this over later.
  - It records each verified statement.
- **A lean verifier:** no constraint-counting preflight, components built
  once, and Blake2s through the precompile where the host serves it
  (software on JAM).
- **Measured:** gas per final proof on the JAM-only host and on PolkaJam,
  against 100M (200M masked).
- **Peers verify the same final proof,** natively.

### 5.7 The carried items

- **Per-target JAM limits (the owner's decision):**
  - a JAM profile about 31 times smaller than VOS's;
  - enforced at run time and named in the install record;
  - statics checked at install;
  - one page price everywhere.
- **DA:** re-export a waiting workflow's pages, or fail it
  deterministically.
- **A heap per kind of invocation:** a bump allocator. It lands before
  5.5's live≡proved test, or excludes kernels.
- **Measurements:** a workflow's resume latency on three processes, and
  a follower's catch-up beyond the kept tail.
- **PolkaJam:** a re-probe on upgrade, and the recompiler run.
- **Ristretto ids 110–114:** carried. Derive refuses a kernel that
  reaches them, so nothing depends on them silently.
- **Prover levers, named to a later slice with their numbers:**
  - narrow BLAKE2b chips: about −2,200 columns, 3–5 weeks;
  - Poseidon2 page hashing (about −1,100 columns, 3–5 weeks), or one
    memory argument across segments (about −2,800 columns and half the
    prover's cells, 6–10 weeks).

  Each lowers the recursion's cost per segment, which is the inner
  proof's columns × queries.

### 5.8 Acceptance

- **Gates:** `ci-full`, `test-proof`, and the checker loop.
- **The window statement and the solvency predicate:**
  - proved over their own shapes;
  - folded into one masked final proof each;
  - verified without replay by a peer and by the JAM verifier agent.
- **Rows measured:**
  - segment prove time and memory per kernel;
  - recursion time and memory per segment and per statement;
  - final proof size;
  - verify gas on JAM, and time natively;
  - masking's cost;
  - compressions per row.
- **Reviews:** the end review (Fable) and the code-quality review (Opus).

## Decisions

**Taken by the owner:**
- arguments are private by default, `#[public]` marks the public ones,
  and the return value is public;
- read-only `&self` for attestable methods, with witnessed reads;
- masking in our Stwo fork;
- JAM verifies, through a recursion layer built in this slice;
- only the final proof is masked, and no unmasked proof leaves the
  space's prover role.

**For the owner after spike 4:**
1. **The recursion stack:** StarkWare's circuit stack, or our own AIR.

**Decided in this draft on the evidence, and the owner's to override:**
- kernels on the chain path (spike 3);
- a shape per kernel, pinned in the program id (the audit);
- Poseidon2-M31 for segment and fold proofs, and Blake2s for the final
  proof (the audit: 2.0–2.3× cheaper to verify on the PVM);
- reads as of the latest complete root W ≤ V;
- shape classes pinned per kernel;
- the prover levers named to a later slice.

## Risks

- **The recursion layer is the longest pole:** about 2–3 months on the
  circuit stack, 4–6 on our own AIR. The circuit stack also moves the
  toolchain and the Stwo version.
- **The final proof's verify gas is projected** (60–150M) until spike 4
  measures a final-shape proof.
- **Masking a recursion AIR that is not ours** (the circuit stack)
  means changing StarkWare's circuit prover in our fork.
- **Prover memory:** segments at the 32k cut fit (6–20 GiB by
  settings); folds are unmeasured.
