# Slice 5: proving

Plan, draft 4. The owner chose **proving first**: slice 5 builds proving,
and the Clerk across spaces is slice 6 (`slice-6-clerk.md`, draft 2,
with Fable's review folded in).
- **The approach:** this plan proves the general mechanism, any
  attestable kernel reading committed state, with two targets:
  cipher-clerk's settlement window and a solvency predicate.
- **Draft 4 folds Fable's review of draft 3:**
  - private arguments never in clear;
  - kernels proved on the chain path, without replay;
  - the root at a live attest's version;
  - one published channel;
  - masking gating the venue decision;
  - the pieces that were missing.

## What exists (the context brief)

- **Two prover paths:**
  - **The refine path** (`prove_refine`) makes one STARK per machine
    slice, unsegmented. Its bundle carries gas, host boundaries and
    per-slice states, and verification replays it: exactly what §11.4
    forbids in a published proof.
  - **The chain path** (`prove_chain`, `verify_chain_standalone`) has
    canonical shapes with an allowlist, segments cut by steps and pages,
    the first segment's initial memory root anchored, and
    `final == next.initial`. It needs no replay by construction.
- **Neither is wired into VOS,** and no derived kernel has been proved.
- **No zero-knowledge** in the pinned Stwo; upstream's successor shows no
  ZK mode.
- **The on-chain verify cost is unknown:** the 10.7M-cycle figure is a
  one-column toy.
- **Kernels read no committed state.**

## Goals

1. A derived attestable kernel is proved and verified without replay,
   under one program identity, in a published format that reveals only
   what the kernel declares public.
2. Kernels prove facts about committed state, read from witnessed rows
   at roots the proof binds.
3. Published proofs are zero-knowledge.
4. The verification venue (JAM or peers) and aggregation are decided,
   on masked proofs.
5. The carried items, each closed or named to a slice.

## The public-input model

This is the design 5.1 builds and reviews.
- **A kernel declares its public and private arguments** in
  `#[attestable]`:
  - the window kernel's window, spaces, currency and cut points are
    public, while its rows and paths are private;
  - the predicate's threshold is public, while its account row is
    private.
- **The public inputs** are:
  - the program id;
  - the format version;
  - the shape class;
  - the public arguments, in clear;
  - the output bytes, opaque and structured by the kernel;
  - the list of roots read, each tagged with its kind.

  At halt, the guest writes their hash into φ9..12, and nothing else.
- **Private inputs** (private arguments, witness rows and paths) are
  bound only inside the proof.
  - The initial memory root is a non-hiding Merkle root, so the kernel's
    initial image includes a **random salt page** that the agent writes
    at the live run and keeps in the `Attest` record.
  - The published format carries segment states only as the io-hash and
    the program id already bind them: registers out, memory roots
    salted.
  - Without this, masking the trace is pointless, because the initial
    root leaks first.
- **Slice 6 needs no format change:** its rows commitment is part of the
  window kernel's output, its sequence cut points are public arguments,
  and its two-anchor reads are a second root.

## Steps

### 5.0 Spikes, each with its decision rule

1. **Verify one real segment on JAM.**
   - **What:** a chain-path segment on the Poseidon2 channel, verified on
     the JAM-only host by the full-AIR verifier as a PVM guest.
   - **Record:** gas, instructions, guest memory (the verifier must
     stream) and proof size against `max_input`, 13.79 MB.
   - **Rule:** about 200M gas and 4 MB or less per segment, **at twice
     the margin** (100M and 2 MB unmasked), since masking may double the
     shape. Otherwise peers verify.
   - Re-run masked after 5.4 before 5.5 decides.
2. **Masking.**
   - **What:**
     - a source read of `starkware-libs/proving`;
     - a design note: salted commitments, randomized trace rows across
       the 32 components and their lookup columns, a masked composition,
       hidden segment states;
     - the toolchain move it forces.
   - **The number:** whether the degree slack fits the existing padding
     rows, or doubles every component's height. A one-component
     prototype gets it.
3. **A kernel proved on the chain path.**
   - **First:** does the chain path's tracer serve `0x400` (BLAKE2b)
     in-AIR? If it can't cheaply, the fallback is the refine path with a
     new published format, at a cost stated.
   - **Then:** prove `settlement::window` over given rows, with vos-tree
     path verification inside, hashing at the compress level.
   - **Record:**
     - steps, memory and proof size;
     - **compressions per row**, which decides how many rows one segment
       holds and is 5.5's input for aggregation.

### 5.1 The program identity, the format, and the prover path (design round, reviewed by Fable)

- **The prover path,** decided on spike 3: kernels on the chain path,
  re-run by the prover from the `Attest` record (program, public and
  private arguments, witness, salt) exactly as the live inner machine ran
  them.
- **One program id** over the derived kernel (per
  `TRANSPILER_VERSION`), the preprocessed root of its shape class, and
  `ProgramHash`, bound and written down.
- **The public-input model above:** the `#[attestable]` split, the
  guest-written io-hash, the salt page, and hidden states.
- **One published channel:** Poseidon2-M31 (format 25), whether JAM or a
  peer verifies, so each statement has one proof. Blake2s (format 24)
  stays for tests inside a space.
- **Shape classes pinned per kernel id:** each kernel has a known maximum
  of steps and compressions. The verifier accepts exactly the pinned
  `log_sizes` per class, replacing allowlist floors that are only
  observed.
- **The legacy tracer's fate:** retired, or kept as the chain path's
  tracer. If retired, slice 1's exception to the allow-set closes here.

### 5.2 Kernels read committed state

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

### 5.3 Proving wired into VOS

- **The prover worker:**
  - a node role inside the space's trust domain;
  - a queue, retries, and placement with its 24 GiB;
  - proofs stored as aged, content-addressed blobs;
  - the `Attest` record names its proof.
- **Verification without replay** wherever a proof arrives: at ingress,
  or by a peer.
- **Unmasked proofs carry a format tag** that only the producing space's
  own verifier accepts, so none can leave the space before 5.4,
  enforced by construction.
- **Tests:**
  - **live ≡ proved:** the prover's standalone re-run produces the live
    run's output and io-hash. This pins the kernel's memory layout, so
    5.6's heap change lands before it or excludes kernels;
  - an attest proved and verified;
  - a tampered proof refused;
  - the Poseidon2 channel's soundness gates run on the proving path;
  - the prover's memory under the 24 GiB cap.

### 5.4 Zero-knowledge (masking)

- **Built to spike 2's design,** in the pinned Stwo or after a move
  upstream.
- **Gates:**
  - leakage: a simulator test where feasible, and hidden segment states
    checked;
  - soundness: tests for every masked component.
- **Measured:** prover time and memory with masking.
- **Then** masked proofs drop the in-space format tag.

### 5.5 Verification at its venue (decided on masked proofs)

- **Spike 1 re-run masked,** then the venue:
  - **JAM:** a public verifier agent, with its gas per proof measured;
    the set of accepted kernel ids is pinned as constants (the owner
    named; redeploy to change), and the registry takes it over later;
  - **or peers:** JAM records statement hashes, and the plan says what
    that gives up.
- **Aggregation,** decided from spike 3's compressions per row and the
  masked verify cost: one segment per statement, chained segments, or a
  recursion or wrap track in a later slice.
- **Prover memory levers,** named with numbers: segments on the chain
  path, and the BLAKE2b chip's ~50 MiB per compression.

### 5.6 The carried items

- **Per-target JAM limits (the owner's decision):**
  - a JAM profile about 31 times smaller than VOS's;
  - enforced at run time and named in the install record;
  - statics checked at install;
  - one page price everywhere.
- **DA:** re-export a waiting workflow's pages, or fail it
  deterministically.
- **A heap per kind of invocation:** a bump allocator. It lands before
  5.3's live≡proved test, or excludes kernels.
- **Measurements:** a workflow's resume latency on three processes, and
  a follower's catch-up beyond the kept tail.
- **PolkaJam:** a re-probe on upgrade, and the recompiler run.
- **Ristretto ids 110–114:** carried. Derive refuses a kernel that
  reaches them, so nothing depends on them silently.

### 5.7 Acceptance

- **Gates:** `ci-full`, `test-proof`, and the checker loop.
- **The window statement and the solvency predicate:** proved with
  masking on the published channel, and verified without replay at the
  decided venue.
- **Rows measured:**
  - prove time and memory per kernel;
  - proof size;
  - verify gas or instructions;
  - masking's cost;
  - compressions per row.
- **Reviews:** the end review (Fable) and the code-quality review (Opus).

## Decisions

**For the owner now:**
1. **The attestable ABI's public/private argument split:** what the
   developer writes.
2. **Unmasked proofs inside a space** before masking: allowed under the
   format tag, or never.

**For the owner after the spikes:**
3. **Masking:** in the pinned Stwo ourselves, or move upstream.
4. **The venue:** JAM or peers, on masked proofs.
5. **Aggregation.**

**Decided in this draft on the review's advice, and the owner's to
override:**
- kernels on the chain path, if spike 3 confirms BLAKE2b in-AIR there;
- Poseidon2-M31 as the one published channel;
- reads as of the latest complete root W ≤ V;
- shape classes pinned per kernel;
- unmasked proofs confined by a format tag.

## Risks

- **Masking is the longest pole,** and may force a Stwo move and a
  toolchain change.
- **A real proof's verification may not fit JAM,** even with the margin.
- **Prover memory:** about 400 compressions per 24 GiB slice; masking
  may double it.
- **The chain path's tracer** may not serve BLAKE2b in-AIR (spike 3
  first).
