# The Clerk across spaces (draft)

Plan, draft 2, written for slice 5 before the owner chose proving first.
Its slice number is set when it is scheduled; it follows slice 6.

**What changed since this draft:** proving came first (slices 5 and 6);
slice 6 builds the statements, the space roots and anchors (Unix-time
windows from the genesis, one venue per space), the carried commitment
that replaces two-anchor reads, `&self` reads by a served witness, a JAM
statements service and the design of Kreivo's spaces pallet. The steps
below, renumbered C.0–C.8, are re-read against them where marked; the
rest of the draft stands as written.
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

Proving is built: the recursion folds a window into one final proof
(slice 5; 8,039 columns in the full segment AIR; 96.4M gas, 38M Wasm
instructions unmasked); slice 6 masks it and builds roots, anchors,
`&self` reads and the venues.
- **The Clerk still needs** transport between spaces and its settlement
  handler at the venue; the space-level roots, the anchors and the reads
  of committed rows inside kernels come with slice 6.

## The split

The owner chose proving first; the Clerk follows slice 6.

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
- the public output is fixed, including the rows commitment (C.4).

**Clerk first** also settles what reshapes proving: how many rows a
window reads, the witness channel (the argument cap stays; a statement's
rows arrive as a served witness by hash, under `Limits::served` (proposed; set by 6.0a)), the
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

C.0 runs beside C.1. C.4 waits on spikes 1 and 3.

### C.0 Spikes, each with its decision rule

**Done:** a real segment on JAM (spike 4a: not viable; a final proof
instead); masking (spikes 2 and 6a); a window statement proved (spike 3,
slice 5's 5.15).

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

### C.1 The Clerk agent in one space

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

### C.2 Spaces that know each other (design round first, reviewed by Fable)

- **`SpaceId`** = the hash of the space's genesis (`vos-anchor`); a
  founding node key binds a controller at each venue.
- **Counterparties anchor at the same venue;** a pair on two venues
  settles once one migrates.
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

### C.3 Payments between spaces

- **Time between spaces is the venue's:** a deadline between parties in
  different spaces (a payment's expiry, a timeout, an exposure deadline)
  is the venue's chain time, never a window number or a space's clock.
- **Latency:** authorization is instant, the counterparty crediting
  within its exposure cap; trustless settlement takes about
  `L/2 + D + t_prove + inclusion`.
- `payment::send` and `receive` through C.2's transport;
- the suspense account for refused payments, with its bounce helper;
- **Tests** across two spaces: payments in flight, replays, refusals,
  and suspense.
- **Measured:** a payment's latency between spaces.

### C.4 Windows, anchors and the statement (design round first, reviewed by Fable)

- **The cut:** windows are the space's Unix-time clock; the per-pair
  sequence cut lives in the pair's rows and the statement's output.
  - A states "sent through sequence s"; B states "credited through s".
  - Exactly-once ordering makes that well defined, and the anchor root
    proves the rows at that cut.
- **Anchors:** a space-level root over its agents' roots per window, and
  the path map root → agent root → space root, are slice 6's.
- **The carried commitment:** the handler keeps per (A, B, currency) a
  commitment to the last settled cumulative state; the kernel takes it as
  a `#[public]` argument, the old values privately, and reads the current
  rows at one anchored cut. No old tree or anchor is kept; the
  creation-window stamp is not needed. cipher-clerk's `NetFlow` gains it,
  or is wrapped.
  - **Slice 6's model of it** (6.15, the `window` test actor): the pair's
    two aggregate rows (decision 4), an outgoing and an incoming
    pseudo-account in one aggregate journal, their ids derived from the
    peer and the currency; `c = BLAKE2b-256(domain ‖ peer ‖ currency ‖
    salt ‖ out_dr ‖ out_cr ‖ in_dr ‖ in_cr ‖ seq)`, the rows' running debit
    and credit totals, each of which only grows (a net may fall, on a
    bounce's debit); public the reader's `(agent, instance)`, the peer, the
    currency and `c_prev`; private the opening of `c_prev` and the next
    salt; the kernel traps unless every total is at least the carried one,
    so a cut older than the carried state's settles nothing; output
    `(net, seq, c_new)`, rooted at the cut, no anchor in it. The peer and
    the currency are public so the handler finds the pair's `c` by them;
    the commitment binds them too. It does not bind the stating space: the
    handler keys `c` by the statement's space, which `S_w` binds.
  - **The library change, this slice's:** `settlement::window(space,
    anchor_i, anchor_j, reads)` takes two anchors and per-journal rows; the
    test actor nets the delta itself. cipher-clerk's window takes one cut,
    the pair's aggregate rows and a carried state (the totals, the sequence
    number, the salts), refuses a total below the carried one, drops
    `RowsOutOfOrder` and the anchors from `NetFlow`, and keeps its decoy
    check; the refusal of a pair with the space itself moves to the
    handler, which knows the statement's space.
- **Completeness of the journals:** under decision 4's aggregate rows, a
  pair reads two rows; the range proof over journals is not needed.
- **The statement:**
  - an attestable method reading witnessed committed rows (core model
    §11.1's committed-field witnesses into kernels; reads are witnessed
    rows and paths, and the roots go into the `Attest` record);
  - it runs `settlement::window` at one cut (above);
  - the argument cap stays; a statement's rows arrive as a served
    witness by hash, under `Limits::served` (proposed; set by 6.0a).

### C.5 The venues

- **Settlement on Kreivo first,** a `ClerkSettle` handler in
  `pallet-spaces` (the Kreivo teammate's); the JAM statements service
  beside it.
- **Spaces register at the venue from their genesis,** with a sovereign
  account.
- **The settlement handler:**
  - it keeps the carried commitment per (A, B, currency) beside the
    window of the pair's last settlement, `(c, w_last)`, and takes a
    statement only when its `c_prev` is `c` and its root's window is past
    `w_last`, so the cuts a pair settles at are ordered;
  - it reconciles pairs, moves the nets, and refuses an aggregate below
    zero;
  - it is two-sided, as every value-moving handler is (Fable's review of
    slice 6's design round, finding 9).
- **Tests:** two spaces settling a window at the venue.
- **Measured:** the settlement handler's weight or gas per statement.

### C.6 Per-target limits (the owner's decision)

**Done in slice 5.**

- **A JAM profile:**
  - per-step effect caps about 31 times smaller than VOS's, sized so the
    worst step fits a package (its writes, messages and attests at about
    1.15e9 of a package's own work today);
  - enforced at run time;
  - named in the install record.
- **Checked at install:** what is static: heap size, program size, kernel
  count, and each kernel's bound on software BLAKE2b on JAM.
- **One page price everywhere,** unchanged.

### C.7 The carried items

**Done in slice 5:** the JAM limits, DA, the heap per invocation, the
measurements, Ristretto removed.

- **DA:** re-export a waiting workflow's pages before retention, or fail
  it deterministically (pages lost).
- **A heap per kind of invocation:** a bump allocator over the header's
  heap region.
- **Measurements:** a workflow's resume latency on three processes, and
  a follower's catch-up beyond the kept tail.
- **PolkaJam:** a re-probe on upgrade, and the recompiler run once the
  owner's kernel setting is in place.
- **Carried on, by name:**
  - **the private key transform:** not needed here, since C.4 needs an
    iterating map;
  - **Ristretto ids 110–114 in the prover:** removed in slice 5, chips
    and ids; the Clerk doesn't need them, and slice 7's generic bignum
    chip replaces them;
  - **the identity design's step 3** (credentials, anonymous origins):
    slice 6 or later, with a holder-side prover.

### C.8 Acceptance

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

1. **The split:** the owner chose proving first; the Clerk follows
   slice 6.
2. **Settlement by statement in slice 5,** safe for the reconcile reason
   above.
3. **The Clerk's owners before the identity agent:** device keys as an
   encoded origin, with the loss mode stated.
4. **Per-journal pseudo-accounts, or one aggregate pair per (peer,
   currency)** maintained by the agent.
   - **The aggregate:** the statement reads the pair's two rows at one
     anchored cut against the carried commitment (C.4), so completeness
     and the per-segment journal limit vanish. The sum's
     correctness inside the space is what no one proves anyway in tier 1.
   - It departs from cipher-clerk's per-journal conventions.

**Decided in this draft on the review's advice, and the owner's to
override** (superseded by C.4/C.5 where marked):
- transport gets its own design round, and uses the identity ABI's
  origin;
- windows are cut at pair sequence numbers (superseded: Unix-time
  windows, the pair's sequence cut in its rows, C.4);
- statements may span from the last settled anchor to any later one
  (superseded: the carried commitment, C.4);
- spike 1's decision rule (about 200M gas and 4 MB per segment)
  (superseded: spike 4a, C.0);
- registration by the representative's first transfer (superseded:
  registration at the venue from the genesis, C.5).

## Risks

- ~~A real proof's verification may not fit JAM.~~ Retired: the final
  proof fits (96.4M gas).
- ~~Masking may need a Stwo move and a toolchain change.~~ Retired: it
  needed no Stwo move (spike 6a).
- **Transport between spaces and the cut** are the largest new protocol
  surfaces; each gets a design round and a Fable review.
- **Window statements over many journals** may exceed one segment, about
  4–8 journals by estimate. Decision 4's aggregate removes that risk.
