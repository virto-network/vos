# The Clerk across spaces

A plan of record [proposed]: the Clerk (cipher-clerk v0.3.0) inside a VOS
space, payments between two spaces, and windows that settle at the
spaces' venue by statement. Not built; the `window` test actor
(`agent/test-actors/window`) models its statement.

It builds on what exists:
- **the statements:** a kernel's final proof, masked (format 39), over
  its program id, its space, its `#[public]` arguments, its output and
  the roots it read; the node's prover proves each statement at an
  anchored cut its leader's agents record and submits it to the space's
  venue; a venue judges rooted statements alone (`proving.md` §3.6);
- **the space roots and anchors:** Unix-time windows from the space's
  genesis, a space root per window built by its representative, anchored
  by one registered node key at the space's one venue, for good: a space
  that changes venue founds again under a new genesis, and an
  equivocation ends it (`proving.md` §7);
- **`&self` reads by a served witness,** inline in the read's `Resume`
  input, and the carried commitment, which replaces two-anchor reads
  (C.4);
- **the venues:** the JAM statements service, which VOS ships; Kreivo's
  spaces pallet as a design (`spaces-pallet.md`) with a mock and
  conformance vectors, the pallet the Kreivo teammate's and the node's
  chain transport a port onto the extension host (`open.md`);
- **time between parties is the venue's** (C.3).

What the Clerk still needs: transport between spaces and its settlement
handler at the venue.

## Why settlement by statement is safe

- **The pairing rule:** `reconcile` accepts only two statements whose
  nets cancel. A lone lying space moves nothing: its counterparty's
  statement differs, the pair doesn't reconcile, and the cost is
  liveness, not value.
- **Collusion:** two colluding spaces can move only an aggregate they
  jointly own, bounded at zero.
- **The real exposure:** space B's window of credits to its members,
  against an A that never settles. The exposure cap and the aggregate
  bound it; proofs would not, since A may simply lack funds.
- **What proofs add:**
  - non-equivocation against the anchor chain;
  - auditability of a space's statement, by its members and its
    counterparty.

The statement's shape is fixed: reads are witnessed rows and paths, the
roots are in the `Attest` record, and the public output includes the
carried commitment (C.4).

## C.1 The Clerk agent in one space

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
  - two-phase payments with expiry: the payee confirms or cancels until
    expiry, after which the payer, the payee or the host may cancel;
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
- **Measured:** a transfer's gas on vos-core.

## C.2 Spaces that know each other

- **`SpaceId`** = the hash of the space's genesis (`vos-anchor`); a
  founding node key binds a controller at each venue.
- **Counterparties anchor at the same venue,** for good: a space anchors
  at one venue and never migrates, so a pair on two venues settles only
  once one of them founds again at the other's.
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
  record shape the registry will publish, so the registry replaces the
  source, not the type.
- **Backpressure:** rate caps per peer space on the fan-in path.

## C.3 Payments between spaces

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

## C.4 Windows, anchors and the statement

- **The cut:** windows are the space's Unix-time clock; the per-pair
  sequence cut lives in the pair's rows and the statement's output.
  - A states "sent through sequence s"; B states "credited through s".
  - Exactly-once ordering makes that well defined, and the anchor root
    proves the rows at that cut.
- **Anchors:** a space-level root over its agents' roots per window, and
  the path map root → agent root → space root (`proving.md` §7). The
  venue anchors a window only once its own clock has closed it.
- **The carried commitment:** the handler keeps per (A, B, currency) a
  commitment to the last settled cumulative state; the kernel takes it as
  a `#[public]` argument, the old values privately, and reads the current
  rows at one anchored cut. No old tree or anchor is kept; the
  creation-window stamp is not needed. cipher-clerk's `NetFlow` gains it,
  or is wrapped.
  - **The model** (the `window` test actor): the pair's two aggregate
    rows, an outgoing and an incoming pseudo-account in one aggregate
    journal, their ids derived from the peer and the currency;
    `c = BLAKE2b-256(domain ‖ peer ‖ currency ‖ salt ‖ out_dr ‖ out_cr ‖
    in_dr ‖ in_cr ‖ seq)`, the rows' running debit and credit totals,
    each of which only grows (a net may fall, on a bounce's debit);
    public the reader's `(agent, instance)`, the peer, the currency and
    `c_prev`; private the opening of `c_prev` and the next salt; the
    kernel traps unless every total is at least the carried one, so a cut
    older than the carried state's settles nothing; output `(net, seq,
    c_new)`, rooted at the cut, no anchor in it. The peer and the
    currency are public so the handler finds the pair's `c` by them; the
    commitment binds them too. It does not bind the stating space: the
    handler keys `c` by the statement's space, which `S_w` binds.
  - **The library change:** cipher-clerk's `settlement::window(space,
    anchor_i, anchor_j, reads)` takes two anchors and per-journal rows;
    the test actor nets the delta itself. The window is to take one cut,
    the pair's aggregate rows and a carried state (the totals, the
    sequence number, the salts), refuse a total below the carried one,
    drop `RowsOutOfOrder` and the anchors from `NetFlow`, and keep its
    decoy check; the refusal of a pair with the space itself moves to the
    handler, which knows the statement's space.
- **Completeness of the journals:** with one aggregate pair per (peer,
  currency), a pair reads two rows; no range proof over journals is
  needed.
- **The statement:**
  - an attestable method reading witnessed committed rows (`core-model.md`
    §11.1's committed-field witnesses into kernels; reads are witnessed
    rows and paths, and the roots go into the `Attest` record);
  - it runs `settlement::window` at one cut (above);
  - the argument cap stays; a statement's rows arrive as a served
    witness, inline in the read's `Resume` input, under
    `Limits::served`.

## C.5 The venues

- **Settlement at the space's venue:** a `ClerkSettle` handler in
  Kreivo's `pallet-spaces` (the Kreivo teammate's, from
  `spaces-pallet.md`), and the JAM statements service beside it, which
  records statements alone today and takes the handler as a service
  change. Both counterparties anchor and settle at one venue.
- **Spaces register at the venue from their genesis,** with a sovereign
  account.
- **The settlement handler:**
  - it keeps the carried commitment per (A, B, currency) beside the
    window of the pair's last settlement, `(c, w_last)`, and takes a
    statement only when its `c_prev` is `c` and its root's window is past
    `w_last`, so the cuts a pair settles at are ordered;
  - it reconciles progressively: the two spaces cut at different times,
    so while a transfer is in flight A's claim and B's never agree
    (`net_A ≠ −net_B`), and a handler that waited for them to agree
    would never settle under traffic. Per (A, B, currency) it keeps the
    cumulative claims `C_A = Σ net_A` and `C_B = Σ net_B` and the amount
    moved `M`, and after each accepted statement moves
    `x = min(C_A − M, −C_B − M)` from A's sovereign account to B's when
    `x > 0` (the mirror when both are negative), leaving the rest
    claimed: each side is bounded by the other's claim, so an over-claim
    moves nothing past what the other side states, and an under-claim
    costs the other side liveness alone, within its exposure cap. The
    `seq` in the output counts settlements (redundant with `c`); it is no
    message sequence;
  - `peer` is a space registered at the same venue, and not the
    statement's space;
  - it refuses an aggregate below zero;
  - it is two-sided, as every value-moving handler is: an anchor gives
    ordering and non-equivocation, not integrity.
- **Tests:** two spaces settling a window at the venue; the ledger's
  `Settled` debit and credit totals never fall (the kernel's "no total
  fell" check rests on it), pinned by a test.
- **Measured:** the settlement handler's weight or gas per statement.

## Gates

- the checker loop with workflows and the Clerk;
- two spaces settling at a venue: the JAM statements service on a
  PolkaJam testnet (`just e2e-chain`'s harness), and Kreivo's pallet
  once it exists;
- measured: a payment's gas on vos-core, the window statement's steps
  and compressions per journal, a cross-space payment's latency, the
  settlement handler's gas per statement.

## Design choices

- **Settlement by statement,** safe for the reconcile reason above.
- **The Clerk's owners before the identity agent:** device keys as an
  encoded origin, with the loss mode stated, so identity ids replace
  them without a migration.
- **One aggregate pair per (peer, currency),** maintained by the agent,
  not per-journal pseudo-accounts: the statement reads the pair's two
  rows at one anchored cut against the carried commitment (C.4), so
  completeness and the per-segment journal limit vanish (window
  statements over many journals would exceed one segment at about 4–8
  journals [est]). The sum's correctness inside the space is what no one
  proves anyway. It departs from cipher-clerk's per-journal conventions.
- **Transport gets its own design round,** and uses the identity ABI's
  origin.
- **Windows are Unix-time windows,** the pair's sequence cut in its rows
  (C.4); a statement reads one cut against the carried commitment, not a
  span between two anchors.
- **Registration at the venue from the genesis** (C.5), not by the
  representative's first transfer.

## Risks

- **Transport between spaces and the cut** are the largest new protocol
  surfaces; each gets a design round and an external review.
