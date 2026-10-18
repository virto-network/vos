# The Clerk across spaces (draft)

Plan, draft 2, written for slice 5 before the owner chose proving first.
Its slice number is set when it is scheduled; it follows slice 6.
- **Draft 1** followed the owner's choice of proving plus the Clerk.
- **Draft 2** folds Fable's review of draft 1:
  - why settlement by statement is safe;
  - the statement's shape fixed now;
  - spikes with decision rules;
  - space-qualified transport;
  - the window cut;
  - the rows commitment;
  - the JAM representative and transfer-carried inputs.

## What the survey found

A survey of the code (the context brief, 2026-10-15):
- **No proving is wired into VOS:** the prover proves PVM traces, but
  neither the agent nor the node uses it, and no derived kernel has ever
  been proved.
- **No zero-knowledge:** the pinned Stwo has no masking, and upstream's
  new home shows no ZK mode.
- **The on-chain verify cost is unknown:** every figure (10.7M cycles,
  ~29M gas) verifies a one-column toy proof, while a real segment has
  ~15,800 columns.
- **The Clerk needs pieces VOS lacks:**
  - transport between spaces;
  - space-level roots and anchors;
  - reads of committed rows inside kernels;
  - the JAM agents.

## The split

- **Slice 5: the Clerk across spaces, with settlement by statement,** plus the spikes and
  designs proving needs.
- **Slice 6: proving the statements.**

**Why settlement by statement is safe:**
- **The pairing rule:** `reconcile` accepts only two statements whose
  nets cancel. A lone lying space moves nothing: its counterparty's
  statement differs, the pair doesn't reconcile, and the cost is
  liveness, not value.
- **Collusion:** two colluding spaces can move only an aggregate they
  jointly own, bounded at zero.
- **The real exposure:** space B's window of credits to its members,
  against an A that never settles. The exposure cap and the aggregate
  bound it (rule 7); proofs would not, since A may simply lack funds.
- **What proofs add, in slice 6:**
  - non-equivocation against the anchor chain;
  - auditability of a space's statement, by its members and its
    counterparty.

**The condition:** the statement's shape is final in slice 5, so slice 6
adds a proof without changing it:
- reads are witnessed rows and paths;
- the roots are in the `Attest` record;
- the public output is fixed, including the rows commitment (5.4).

**Clerk first** also settles what reshapes proving: how many rows a
window reads, the witness channel (arguments are capped at 64 KiB), the
public output and the anchor hierarchy.

## Goals

1. **The Clerk across spaces:** cipher-clerk v0.3.0 inside a VOS space;
   payments between two spaces; windows that settle on JAM by statement.
2. **Proving's foundations:**
   - the costs that decide slice 6, measured;
   - one program identity, decided;
   - a window statement proved;
   - masking designed.
3. **The carried items,** each closed or named to a slice.

## Steps

5.0 runs beside 5.1. 5.4 waits on spikes 1 and 3.

### 5.0 Spikes, each with its decision rule

1. **Verify one real segment on JAM.**
   - **What:** a refine-path segment made on the Poseidon2 channel,
     verified on the JAM-only host by the full-AIR verifier as a PVM
     guest.
   - **Record:**
     - gas and instructions;
     - guest memory (the verifier must stream, since a JAM guest has a
       fraction of the 69 GiB the recursion join hit);
     - proof size against `max_input`, 13.79 MB.
   - **Rule:** "fits" means about 200M gas and 4 MB or less per segment,
     so four fit a package. Otherwise peers verify each other's
     statements, and JAM keeps statements and aggregates. Slice 5's
     shape stays the same either way.
2. **Masking.**
   - **What:**
     - a source read of `starkware-libs/proving`;
     - a design note for zero-knowledge in the pinned Stwo, or its
       successor: salted commitments, randomized trace rows across the 25
       components and their lookup columns, a masked composition;
     - the toolchain move it forces.
   - **The one number it must produce:** whether the degree slack fits
     the existing padding rows, or doubles every component's height.
   - A one-component prototype is the cheapest way to get it.
3. **A window statement proved.**
   - **What:** prove `settlement::window` over given rows, with vos-tree
     path verification inside the kernel, hashing at the compress level
     (`blake2b_compress`; `agent/tree/src/hash.rs` still streams, at
     about 5× the steps).
   - **Its output:** compressions per journal, which decides whether
     slice 6 needs chained segments.
   - **Program identity, decided and written down:** one id over the
     preprocessed root, the kernel hash derived per `TRANSPILER_VERSION`,
     and `ProgramHash`.

### 5.1 The Clerk agent in one space

- **Storage:** a `LedgerState` over the SDK's `CommittedMap`s, one table
  per record kind, with point keys only.
- **Authority from ingress:**
  - an owner is derived from an encoded origin (a kind tag plus an id),
    never the raw client key, so identity ids slot in later without a
    migration;
  - the operator's and the registrar's roles map to their owners;
  - **the loss mode, stated:** an account tied to a lost device key is
    unrecoverable until the identity agent exists.
- **Ids** from `ctx.random()`.
- **Methods:**
  - open accounts (the registrar);
  - transfers;
  - two-phase payments with expiry, under the owner's confirmed rule:
    the payee confirms or cancels until expiry, after which the payer,
    the payee or the host may cancel;
  - voids;
  - closing;
  - predicates as queries.
- **The agent rules the library leaves to it:**
  - no voids of payments;
  - the payer is the client's own account;
  - only payments move pseudo-accounts.
- **Tests:**
  - the cipher-clerk corpus scenarios through the agent;
  - VOS≡JAM agreement;
  - the checker loop with the Clerk.
- **Measured:** a transfer's gas on vos-core (the fit check's 175k is
  master's interpreter).

### 5.2 Spaces that know each other (design round first, reviewed by Fable)

- **`SpaceId`:** the hash of the space's creation record, bound to its
  representative's service id on JAM, signed both ways.
- **Pair keys qualified by space:** `(sender space, agent)` and
  `(receiver space, agent)`. `Message.from`, `Deliver`, `Acknowledge`
  and `Behind` carry `SpaceId`. That changes the wire, once.
- **Authentication:**
  - B's ingress verifies A's frames against A's node set (node key →
    space, with epochs) from a peer directory;
  - the receiving agent sees the origin, never a signature;
  - replays are the pair's sequence.
- **The origin is the identity ABI's `Agent { space, id }`:** the Agent
  origin gains a space field. There is no new kind.
- **Delivery:** any node of B relays to its leader; there are no
  cross-space placement queries in v1.
- **The peer directory:** a stand-in the operator configures, in the
  record shape the registry will publish, so the registry slice replaces
  the source, not the type.
- **Backpressure:** rate caps per peer space on the fan-in path.

### 5.3 Payments between spaces

- `payment::send` and `receive` through 5.2's transport;
- the suspense account for refused payments, with its bounce helper;
- **Tests** across two spaces: payments in flight, replays, refusals,
  and suspense.
- **Measured:** a payment's latency between spaces.

### 5.4 Windows, anchors and the statement (design round first, reviewed by Fable)

- **The cut:** windows bound to the pair's sequence numbers.
  - A states "sent through sequence s"; B states "credited through s".
  - Exactly-once ordering makes that well defined, and the anchor root
    proves the rows at that cut.
  - Time-based anchors alone never reconcile under continuous traffic.
  - The cut also defines idle and spanning windows.
- **Anchors:**
  - a space-level root over its agents' roots, at a fixed cadence
    (minutes), on a schedule taken from JAM's time through the
    builder's JAM node;
  - the path map root → agent root → space root is built and checked.
- **The carry-forward of past-anchor reads:**
  - each window's statement takes its earlier rows as those the previous
    statement read;
  - the public output carries a **commitment to the rows it read at its
    later anchor**;
  - the JAM agent keeps that commitment per (A, B, currency) and checks
    that the next statement starts from it.
  - cipher-clerk's `NetFlow` gains it, or is wrapped.
- **Absence at a past anchor:** a pseudo-account row carries its creation
  window, witnessed under the current root, so a row created after the
  earlier anchor counts from zero by its own stamp. The tree keeps no old
  versions.
- **Completeness of the journals:** pseudo-account rows are keyed (peer,
  currency, journal) in an `Ordered` map, so a range proof shows the set
  is whole. That map cannot take the private transform. An incomplete set
  is a liveness failure, since the counterparty's statement won't match,
  not theft.
- **The statement:**
  - an attestable method reading witnessed committed rows (core model
    §11.1's committed-field witnesses into kernels; reads are witnessed
    rows and paths, and the roots go into the `Attest` record);
  - it runs `settlement::window`;
  - its witness channel lifts the 64 KiB argument cap.

### 5.5 The JAM agents

- **A representative agent per space on JAM:** it publishes the space's
  anchors and submits its statements.
- **Transfer-carried inputs:**
  - a public JAM agent takes no origin from its builder, so it receives
    chain-authenticated transfers from representatives, with payloads as
    preimages;
  - core model §12 lists this as unbuilt, so it is a step of its own.
- **The aggregate-balance agent:**
  - it keeps the last settled anchor and the rows commitment per
    (A, B, currency);
  - it reconciles pairs, moves the nets, and refuses an aggregate below
    zero;
  - a space's aggregate is funded and withdrawn by transfers of JAM
    tokens;
  - its builder is run by the root space at first, which can delay
    inputs but never forge them.
- **Registration stand-in:** self-registration by first transfer. The
  representative's service id registers itself, with its `SpaceId` in
  the memo; the builder fills no table.
- **Tests:**
  - the JAM comparison suite;
  - a PolkaJam testnet run with two spaces settling a window.
- **Measured:** the aggregate agent's gas per statement.

### 5.6 Per-target limits (the owner's decision)

- **A JAM profile:**
  - per-step effect caps about 31 times smaller than VOS's, sized so the
    worst step fits a package (its writes, messages and attests at about
    1.15e9 of a package's own work today);
  - enforced at run time;
  - named in the install record.
- **Checked at install:** what is static: heap size, program size, kernel
  count, and each kernel's bound on software BLAKE2b on JAM.
- **One page price everywhere,** unchanged.

### 5.7 The carried items

- **DA:** re-export a waiting workflow's pages before retention, or fail
  it deterministically (pages lost).
- **A heap per kind of invocation:** a bump allocator over the header's
  heap region.
- **Measurements:** a workflow's resume latency on three processes, and
  a follower's catch-up beyond the kept tail.
- **PolkaJam:** a re-probe on upgrade, and the recompiler run once the
  owner's kernel setting is in place.
- **Carried on, by name:**
  - **the private key transform:** not needed here, since 5.4 needs an
    iterating map;
  - **Ristretto ids 110–114 in the prover:** removed in slice 5, chips
    and ids; the Clerk doesn't need them, and slice 7's generic bignum
    chip replaces them;
  - **the identity design's step 3** (credentials, anonymous origins):
    slice 6 or later, with a holder-side prover.

### 5.8 Acceptance

- **Gates:**
  - `ci-full`;
  - the checker loop with workflows and the Clerk;
  - two spaces settling on a PolkaJam testnet.
- **Rows measured:**
  - a payment's gas on vos-core;
  - the window statement's steps and compressions per journal;
  - a cross-space payment's latency;
  - the aggregate agent's gas per statement;
  - the carried measurements.
- **Reviews:** the end review (Fable) and the code-quality review (Opus).

## Decisions for the owner

1. **The split:** Clerk first (recommended), or proving first.
2. **Settlement by statement in slice 5,** safe for the reconcile reason
   above.
3. **The Clerk's owners before the identity agent:** device keys as an
   encoded origin, with the loss mode stated.
4. **Per-journal pseudo-accounts, or one aggregate pair per (peer,
   currency)** maintained by the agent.
   - **The aggregate:** the statement reads two rows at two anchors, so
     completeness and the per-segment journal limit vanish. The sum's
     correctness inside the space is what no one proves anyway in tier 1.
   - It departs from cipher-clerk's per-journal conventions.

**Decided in this draft on the review's advice, and the owner's to
override:**
- transport gets its own design round, and uses the identity ABI's
  origin;
- windows are cut at pair sequence numbers;
- statements may span from the last settled anchor to any later one;
- spike 1's decision rule (about 200M gas and 4 MB per segment);
- registration by the representative's first transfer.

## Risks

- **A real proof's verification may not fit JAM.** Spike 1 decides it
  first, and the slice-5 shape survives either answer.
- **Masking may need a Stwo move** and a toolchain change.
- **Transport between spaces and the cut** are the largest new protocol
  surfaces; each gets a design round and a Fable review.
- **Window statements over many journals** may exceed one segment, about
  4–8 journals by estimate. Decision 4's aggregate removes that risk.
