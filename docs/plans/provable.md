# `#[provable]` — proofs of actor transitions

Status: **design, revised after adversarial review**. The first draft
tried to make a provable Task re-anchor its invoking parent's committed
`0x02` composite and verify committed reads in-circuit against it. A
four-lens review killed that (six independent blockers): a separate
Task binary can't fold the parent's schema/state-blob, plain rows and
the Task's own state stay unbound, and proven-absence was asserted not
proven. This revision drops `0x02`-in-Task entirely and binds state the
way the voucher pipeline already does soundly — **app-named roots via
`bind_public` over a `BatchProof`** — which the framework now supports
natively (`vos::zk::state::BatchProof`, W4.1). The review notes that
produced this rewrite are archived at the end.

Goal: a developer marks a Task actor `provable`; the system can later
produce — and any third party can verify — a STARK that *this program*,
over an *app-named prior state root*, ran *this transition* to a *named
next root* and replied *these bytes*. cipher-clerk/voucher-check does
exactly this today with hand-rolled machinery; `#[provable]` promotes
the pattern into the framework so the next provable actor writes almost
none of it.

## The load-bearing insight (why the rewrite is sound)

A provable Task is a **pure verifier of a state transition, not a
mutator of live storage**. It:

1. receives, in its witness, the touched leaf values **and a
   `BatchProof`** over the touched keys (both are secret witness data);
2. reconstructs `root_before` from the touched leaves + proof and
   checks it equals the app-named prior root — *this is where every
   input, present or absent, is bound in-circuit* (`BatchProof::root`
   already does inclusion **and** non-inclusion — a lying "absent" or a
   swapped value shifts the reconstructed root and the check fails);
3. applies the transition to the touched leaves and reconstructs
   `root_after` reusing the same frontier;
4. binds `app_public = (root_before, root_after, app-designated bytes)`
   via `vos::zk::bind_public`; the framework folds it into `public'`
   and `io_hash(public', reply)`;
5. returns the reply. **It writes no live committed storage.**

The parent applies the actual mutation in its own (non-proved)
dispatch, against the roots the Task attested. The proof attests the
transition *between two roots the app named and the app verified its
inputs against*. This is `cipher_clerk::succinct::SuccinctTransition
Witness::verify_transition` (`root_before → apply → root_after`),
generalized to `vos::zk::state::BatchProof` over any committed field.

Everything the first draft tried to force into the framework anchor —
schema knowledge, non-inclusion, write coherence, the parent's state
blob — dissolves: the app names its roots, the `BatchProof` binds its
own inputs, and the Task never touches the parent's live tree. The
framework anchor stays `0x01` (state-blob hash) exactly as today.

## What already exists (the assembled machinery)

Landed and gated; `#[provable]` composes it.

- **Witness-delivered Tasks** (`#[actor(task)]`): `(state, msg, rows)`
  patched into `__VOS_WITNESS`; live≡traced images; cold, refine-pure.
- **Framework io-binding** (B2 producer half): at halt the framework
  composes `public' = anchor_kind ‖ anchor ‖ transition_digest ‖
  app_public` and binds `io_hash(public', reply)` into φ[9..12].
  Handlers contribute `app_public` via `vos::zk::bind_public`. The
  digest covers effects *including* the final state write (the B4
  trap).
- **Witnessed reads** (W4.3): the parent names row keys; the host
  stages them from the parent's effective keyspace; named-but-absent =
  proven-absent *for the live read*; an unnamed read panics. Under
  `#[provable]`, soundness does **not** rest on this staging (see the
  insight above) — the `BatchProof` in the witness is what binds the
  reads; staging is just how the leaf bytes + proof reach the guest.
- **`vos::zk::state::BatchProof`** (W4.1): the sparse-Merkle multiproof
  over any fixed key width, with cipher-clerk-parity domains — the
  reconstruction primitive step 2/3 above call. Build host-side from
  sorted leaves; `root()` reconstructs in-guest.
- **Committed storage + roots** (W4.1/4.2): per-field incremental SMT
  roots; `state_root` reads them O(1). The *app* reads these roots
  (`CommittedMap::root()`) to name `root_before`/`root_after` — no
  framework anchor reinterpretation.
- **Replay safety** (A10): invoke effects re-absorb on replay —
  provable Tasks run on replicated parents.
- **Pinning + proving** (B1/B3/B8): `ProvableCatalog` / `vosx zk pin`;
  the prover extension's prove/verify + async job queue.

## Design decisions

### D1 — the unit is a Task actor; the provable handler is a pure verifier

`#[actor(task, provable)]` — an actor-level flag valid only with
`task`. Rationale, from real constraints (not "one entry point," which
the landed two-slot jump prologue contradicts — a blob already hosts
refine IC 0 and accumulate IC 5):

- **Refine-purity.** A proof exists only for a refine-pure execution
  (no FETCH loop, no warm state, deterministic from the witness). A
  `#[actor(task)]` is exactly that unit; a service/refine actor is not.
  This is JAM's own split — refine is the provable phase.
- **Image economy.** A small Task image keeps canonical-shape floors
  and per-segment proving cost down; a provable twin of a large
  service actor would prove the whole service image.
- The A15-era alternative (a provable refine entry beside accumulate in
  one image) is noted and deferred to that track; it changes the
  packaging, not the verifier contract below.

The provable Task is a **pure verifier**: it reads witnessed inputs +
proof, checks them against the named prior root, computes the next
root, binds both, replies. The "extract a Task" pattern for a big
replicated actor (clerk-ledger → an `apply` Task holding the kernel) is
the flagship, and the pure-verifier shape is what makes it work: the
Task never mutates the ledger; `apply_transfer` reads the touched rows,
invokes the Task to *verify and compute the new root*, then applies the
writes itself against that root. The delegation boilerplate is real and
the macro should generate as much of the parent-side "gather touched
leaves + BatchProof + invoke + apply" glue as it can (a follow-up once
the clerk migration shows the shape).

### D2 — state binding is app-named roots, verified in-guest via `BatchProof`

**No `0x02`-in-Task.** The provable Task's framework anchor stays
`0x01` over its delivered state blob (so the Task's own entering state
*is* bound in `public'`, unchanged from today). State-of-the-world
binding is `app_public`:

- The parent, in its live dispatch, reads the touched committed leaves
  and builds a `BatchProof` over their keys (host/guest — the parent
  already walks these rows; `BatchProof::build` from the field's sorted
  leaves). It ships `(leaves, proof, root_before, root_after_claimed?)`
  to the Task as witness — `root_before` is `CommittedMap::root()` at
  dispatch entry.
- The Task verifies `proof.root(touched_before) == root_before`
  (binds every input, present or absent), applies its logic to the
  touched leaves, computes `proof.root(touched_after)` = `root_after`,
  and `bind_public(&AppPublic { root_before, root_after, .. })`.
- The verifier reads `(root_before, root_after)` out of `public'`
  (reconstructed from the record + the app value it holds) and compares
  `root_before` to the state it independently knows — for a
  counterparty bank, its last-known root of the issuer, which is the
  *app's* composite (cipher-clerk's `composite_root_from_subroots`
  under cipher-clerk domains, the value vouchers already sign), **not**
  any VOS `0x02` fold. The framework anchor and the app roots are
  different objects with different audiences; the doc must never
  conflate them (the first draft did).

Consequences that make this sound where the draft wasn't:

- **Plain rows, framework rows, the state blob** are only bound if the
  app puts them in its `BatchProof` / `app_public`. There is no false
  "witnessed ⇒ trusted" claim — the app's proof is the whole binding.
- **Non-inclusion is proven**, not asserted: `BatchProof::root` folds a
  claimed-absent key as the empty leaf; a lying "absent" over an
  occupied slot shifts `root_before` and the equality fails. (The
  cipher-clerk precedent has the should-panic test for a lying oracle.)
- **Writes need no live coherence**: the Task computes `root_after` and
  returns it; the *parent* applies the committed writes in its own
  dispatch, so the parent's guest cache, `CURRENT_ANCHOR`, and
  `__vos_committed_root` recompute exactly as they do for any live
  committed mutation — untouched by proving.
- **Batching works**: `BatchProof` is inherently multi-key
  (cipher-clerk's kernel is `apply_batch`), so N transfers in one Task
  invocation prove together — the first draft's "one provable invoke
  per dispatch" wall (it came from the stale-composite-row problem)
  is gone with `0x02`-in-Task.
- **`insert_with_leaf` parity trees are fine**: the app supplies leaf
  *content* to `BatchProof::build`/`root` (as cipher-clerk does — leaf
  = domain-tag ‖ payload), so clerk-ledger's cipher-clerk-domain leaves
  reconstruct their own roots. The framework never assumes bare-value
  leaves.

**Witness size** is now the app's `BatchProof` (O(touched · log N)
hashes), the design point cipher-clerk already hits (1.56 MB → 2.5 KB
at 5k accounts). A 2-account transfer's proof is ~2 KB — comfortably
under a Task's witness buffer (default 16 KiB, `#[actor(task = N)]`
raises it). The host still enforces the buffer cap (W4.3), refusing an
over-cap witness as `TOO_BIG` rather than corrupting `.bss`.

### D3 — the `ProvableRecord`, split and durable

A proof is produced later; the invocation leaves behind what the prover
needs and, *separately*, what a verifier needs. The draft conflated
them and made records droppable — both wrong.

- **Prover-only material** (`ProvableInput`): the exact witness bytes
  (`encode_task_input_with_rows` output — state, msg, leaves, proof)
  and `task_hash`. This is the complete secret; it re-traces the
  invocation bit-for-bit and never leaves the producing operator.
- **Verifier-facing record** (`ProvableRecord`): `catalog_name`,
  `catalog_version`, `anchor_kind`, `anchor`, `transition_digest`,
  `reply`, `io_hash`, and `app_public` (the roots + app bytes — *not*
  the witness). This is what ships to a counterparty; it discloses no
  private leaf values (fixing the draft's step-3 privacy hole).
- **Capture is caller-opt-in and durable.** `Tasks::spawn_provable(..,
  tag: [u8;32])` sets a flag in the invoke input and carries a
  caller-supplied 32-byte business tag (e.g. the transfer id) — bit 30
  of the length word is the flag, and unknown high bits are
  reserved-must-be-zero so an older host rejects a record-enabled
  invoke cleanly instead of misparsing the length (the wire-compat
  fix). The host persists `ProvableInput` + `ProvableRecord` keyed by
  `(svc, tag)` into the agent's own storage under a reserved
  `__vos_proofrec/` prefix — so they survive restart and CRDT
  soft-restart (the draft's "records regenerate" was false: replay
  short-circuits the child, the effect log holds no invoke input, and
  the parent's state has advanced). The invoke output envelope returns
  the tag so the parent can correlate. Records are pruned by the app
  (a `prune_proof_record(tag)` handler) once a proof is published or
  the settlement window closes — not silently ring-dropped.

### D4 — the verify surface (privacy-preserving, minimal)

- `prove_record(input_bytes)` — async prove job (B8 queue): traces the
  witness against the cataloged blob (**pre-flight**: recompute
  `transition_digest`, `io_hash` and assert they match the stored
  record — the re-trace the draft wrongly put in *verify* belongs
  here, producer-side, where the witness already lives), proves the
  canonical chain, and hands the segments back for the node to publish
  (the prover extension can't `blob_put` — the requester CAS-publishes,
  per the B8 split).
- `verify_record(record_bytes, proof_segments, expected_root_before)` —
  the third-party check, witness-free:
  1. chain-verify segments against the catalog allowlist for
     `(catalog_name, catalog_version)`;
  2. `proof.public_io_hash() == record.io_hash`;
  3. reconstruct `public'` from `(record.anchor_kind, record.anchor,
     record.transition_digest, record.app_public)` and check
     `io_hash(public', record.reply) == record.io_hash` — this is what
     binds the *roots and reply* to the proof (no re-trace, no
     witness);
  4. check `record.app_public.root_before == expected_root_before` —
     the caller's own knowledge of the prior state (the settlement
     check). Absent an expected root, the verifier learns "some
     transition between these two roots was proven," not "over the
     state I know."
  `anchor`, `anchor_kind`, and `reply` are all inside the hashed
  `public'`/`io_hash`, so step 3 cross-checks them — the draft's "step
  4 optional" hole is closed by making the root comparison the explicit
  final check with a named expected input.
- `task_hash` is CAS/routing, **not** identity — identity is the
  commitment allowlist. The catalog gains a `blob_hash` field at pin
  time so `prove_record`'s blob lookup is verifiable; verifier UIs
  report the *catalog name + verified commitments*, never the raw
  `task_hash`.

### D5 — catalog versioning (records outlive re-pins)

Guest-framework rebuilds re-pin (W1 here does; jar Phase-1 and A15
will). `ProvableCatalog` becomes **append-versioned**: `vosx zk pin`
adds a new `(version, commitments, profile, seg_steps, witness_addr,
blob_hash)` entry rather than replacing, and retires nothing. A record
pins the `catalog_version` it was captured under; `verify_record`
checks against that version's allowlist. The blob store retains
superseded task blobs as long as any unpruned record references them.
This makes a month-old settlement proof verifiable after a re-pin —
"superseded pin" and "forged program" stay distinguishable.

### D6 — what the macro emits

`#[actor(task, provable)]` adds, beyond `task`: the `.vos_meta`
`provable` bit (trailing positional-append section); a compile error
without a task buffer; and — as a follow-up, once the clerk migration
fixes the shape — parent-side delegation glue (gather touched leaves,
`BatchProof::build`, `spawn_provable`, apply-on-verified-root). The
io-binding, witnessed reads, and record capture are runtime behavior
shared by all Tasks; `provable` is a publication/discovery mark plus
the record opt-in, not a semantic fork — "every Task is one
`#[provable]` away" stays literal.

## Trust model (say it out loud)

- The **proof** binds: program identity (commitment allowlist), the
  Task's own entering state (`0x01` anchor in `public'`), the applied
  effects (transition digest), the reply, and the app's designated
  public inputs — critically `(root_before, root_after)`.
- **State-of-the-world** soundness is the app's `BatchProof`: every
  leaf the proven logic read is bound to `root_before` in-circuit
  (inclusion and non-inclusion). Rows the app didn't prove against are
  simply not part of the statement — and the app knows exactly which
  those are, because it built the proof.
- The **record** is untrusted courier material; every check re-derives
  from the proof or the verifier's own `expected_root_before`.
- The **msg** is bound only if the app folds it into `app_public` — the
  doc says so; a Task whose reply depends on `msg` beyond the touched
  leaves should bind `hash(msg)`.
- Known gaps, unchanged from the platform: the entering-**image** root
  for witness-injecting programs (masked-root design, roadmap §4.3) —
  program identity rests on the allowlist until it lands; and live
  (non-proved) invocations trust the host as any dispatch does — proofs
  are where adversarial soundness begins.

## Developer-experience must-fixes (from the review)

- **Diagnosis surface.** A missing witnessed row (the common migration
  mistake) currently panics → the guest abort spins gas down → the
  parent sees `OutOfGas`, and the keyless message goes only to node
  stderr. W1 must: name the missing key in the panic, make the abort
  a distinguishable trap (not a gas-burn), and add a dev-mode host
  pre-flight that dry-runs row staging and reports unmatched reads.
- **Correlation.** The `(svc, tag)` keying + tag-in-output-envelope
  (D3) is the answer to "prove transfer 0xAB later" — no fragile
  seq→business-id counting.

## Explicitly out of scope

- `0x02`-in-Task / framework-anchored committed reads (the killed
  approach).
- Handler-level provable twins of refine actors (D1).
- Host auto-expansion of committed prefixes into path rows / an
  auto-derived message→keys oracle — the app names its `BatchProof`.
- Proving warm/FETCH-driven refine dispatches (not refine-pure).
- Record replication across nodes (records are per-producer; a proof,
  once published, is the portable artifact).

## Waves

1. **W1 — the provable-verifier primitive.** A `WitnessedLedger`-style
   helper in `vos::zk::state` (generalizing cipher-clerk's
   `SparseLedger`) that a Task builds from `(leaves, BatchProof,
   root_before)`, panics on any read/write inconsistent with the proof,
   and yields `root_after`. `bind_public` of the roots. Diagnosis
   surface (above). Gate: a committed fixture Task that verifies a
   real transition and whose doctored witness (swapped value, lying
   absent, wrong root) fails to complete a trace. Guest change ⇒ re-pin.
2. **W2 — record capture, durable + split.** `ProvableInput` /
   `ProvableRecord`, the `__vos_proofrec/` persistence, the
   `spawn_provable(tag)` flag + reserved-bits wire rule, tag-in-output,
   φ-register io-hash capture. Gate: record survives a restart and its
   input re-traces to the same io-hash.
3. **W3 — verify surface.** `prove_record` (pre-flight + chain) /
   `verify_record` (witness-free four checks) on the prover extension
   over the B8 queue; `vosx zk prove/verify`. Gate: record → prove
   (release, heavy) → verify all checks, plus rejection of a tampered
   record/reply/root and a wrong `expected_root_before`.
4. **W4 — clerk migration + macro.** Extract clerk-ledger's
   `apply_transfer` kernel into an `apply` provable Task over a
   witnessed `BatchProof`; the `provable` flag + `.vos_meta` bit;
   append-versioned catalog + `blob_hash`; migrate voucher-check onto
   the generalized helper; docs. This is the proof the whole design
   pays for itself — voucher-check should shrink, not grow.

## Landing status (W1–W4)

W1–W3 landed as described. **W4 landed** with these concrete pieces:

- **Parent-side extraction.** `CommittedMap::batch_proof(touched)`
  reads a `vos::zk::state::BatchProof` multiproof (+ each key's raw
  value row) straight off the stored tree's memoized branch refs —
  O(touched·log n), byte-identical to `BatchProof::build` over the full
  leaf set. This is the crux the plan flagged: a 10k-account transfer
  cannot walk every leaf to build a proof.
- **The bridge — `clerk-witness`.** cipher-clerk must not depend on vos
  and vice-versa, so the `LedgerState`-over-six-`WitnessedLedger`s
  adapter lives in its own crate. It runs the REAL cipher-clerk kernel
  as a pure verifier; a parity gate proves it reconstructs
  byte-identical `(root_before, root_after)` to cipher-clerk's own
  `SuccinctTransitionWitness` and a live `VecLedger` apply, and rejects
  swapped / lying-absent / tampered witnesses.
- **The macro flag.** `#[actor(task, provable)]` sets `Actor::PROVABLE`
  → the `.vos_meta` trailing `provable` byte (old blobs decode false);
  the macro rejects `provable` without `task`. `vosx zk pin` notes the
  mark, `vosx describe` surfaces it.
- **The flagship Task — `clerk-apply`.** A real
  `#[actor(task, provable)]` guest that verifies a cipher-clerk batch
  transition through the bridge and binds `app_public = root_before ‖
  root_after ‖ batch_digest`. Its gate traces it exactly as the prover
  would (the proof path), asserts a clean halt, and checks the bound
  roots against a live apply + the framework io-hash over `public'`.

**Deferred (documented, orthogonal to the framework):**

- *Live-drive record capture for precompile Tasks.* clerk-apply uses
  cipher-clerk's `pvm-precompile` (small prove trace), whose Ristretto/
  scalar ECALLs the LIVE `run_task_invoke` path has no host handler for
  yet ("no vos host handler yet, though the tracer has one" —
  `runtime.rs`). So the W4 gate proves clerk-apply via the *trace* (what
  a counterparty verifies) rather than a live invoke. Wiring the
  precompile handlers into `handle_task_hostcall` /
  `handle_refine_hostcall` (which would also let clerk-ledger itself
  adopt the precompiles) is a self-contained runtime follow-up.
- *voucher-check migration.* The bridge's parity gate already
  establishes that `WitnessedLedger` reproduces cipher-clerk's succinct
  verify byte-for-byte, and clerk-apply is a fuller demonstration than
  a voucher-check swap. Migrating voucher-check's guest would change its
  witness wire (six `LedgerWitness` vs the private-field
  `SuccinctTransitionWitness`), break the federation e2e's six witness
  builders, and force another money-path re-pin for marginal in-repo
  shrink (voucher-check's guest is already a ~110-line wrapper; the
  shrinkable machinery lives in cipher-clerk, a separate repo).
- *Parent-side delegation glue + the clerk-ledger production wiring.*
  D6's macro-generated "gather touched leaves + `batch_proof` + invoke +
  apply" boilerplate, and rewiring clerk-ledger's `apply_transfer` to
  spawn the apply Task, follow once the live-drive handler lands.

---

## Review archive (why the rewrite happened)

A four-lens adversarial review of the first draft returned 8 blockers,
25 major, 8 minor. Six blockers were one error — **D2's
`0x02`-in-Task**:

- *Unbindable inputs*: plain `#[storage]` rows, framework rows, and the
  Task's own delivered state were witnessable but folded into no
  anchor; a courier could doctor them in the record and re-derive a
  passing proof.
- *Unbuildable check*: the in-guest "composite fold == seeded anchor"
  needs the parent's field schema, all sibling roots, and the parent's
  state blob — none available to a separate Task binary; a schema
  change would silently break every dependent pinned Task.
- *Assertion not proof*: proven-absent rows were the live-staging
  semantic (host stages `None`), never verified against a root — a
  staged-absent occupied slot would verify.
- *Write incoherence*: the flagship clerk `apply` Task had to mutate
  committed rows, poisoning the parent's guest cache / composite row /
  `CURRENT_ANCHOR` and breaking the W4.4 rebuild-parity invariant.
- *Mechanical*: `expected_anchor` used verbatim breaks every plain Task
  under a committed parent; `insert_with_leaf` parity leaves defeat
  bare-value leaf verification; one provable invoke per dispatch (no
  batching, but cipher-clerk *is* `apply_batch`).

The revision replaces all of it with the app-named-roots + `BatchProof`
model — the working voucher-check pattern, now framework-supported.
The surviving operational findings (durable/split records, witness-free
verify, versioned catalog, correlation tag, diagnosis surface,
wire-compat bits) are folded into D3–D5 and the DX section above.
