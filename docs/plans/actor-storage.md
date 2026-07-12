# Actor storage scale-out — prelude storage types over the agent KV

Goal: actors with large or growing collections (clerk-ledger accounts,
space-registry rows, bridge dedup sets) stop living inside the monolithic
rkyv state blob and instead declare **typed storage handles**
(`StorageMap`, `StorageVec`, `StorageSet`, `StorageValue`) whose entries
are individual rows in the agent's existing key-value store. Reads become
point `STORAGE_R` calls, writes become per-key `Effect::Write`s, and the
guest's memory footprint is bounded by the **touched set per dispatch**,
not the collection size. No new hostcalls — iteration is self-indexed
data, and the eventual commitment tree (`anchor_kind 0x02`) doubles as
the ordered index.

Execution model: work wave by wave, one commit per work item, run the
wave gate before moving on. Waves 1–2 fit one session; waves 3 and 4 are
each their own session. Read this whole file first; then read the files
listed in each item before editing them.

## Why (the walls, measured)

The blob model assumes state of tens of KiB (`vos/src/abi/pvm/alloc.rs:5-8`):

- 256 KiB fixed guest heap, `GROW_HEAP` is a host no-op
  (`alloc.rs:11`, `runtime.rs:1340`); peak live ≈ 4–5× state size.
- 1 MiB halt-output cap carries the full state write
  (`runtime.rs:1264`) → clerk-ledger (~305 B/account) dies near 3k
  accounts.
- 16 KiB provable-Task witness buffer (`vos-macros/src/lib.rs:1350`)
  → a provable clerk caps out near 50 accounts.
- Every mutation re-encodes the whole struct; in CRDT mode every DAG
  node carries the **full state blob** (`Effect::Write{STATE_KEY}` in
  the `EffectLog`), so the replication log grows by state-size per write.
- `ClerkLedger::composite_root` rebuilds an SMT over every account
  **twice per transfer** (`actors/clerk-ledger/src/lib.rs:382,407`).

The seams already exist: `STORAGE_R`(4)/`STORAGE_W`(5) are a real
caller-keyed KV end-to-end (guest wrappers → journaled
`Effect::Write{key,value}`, last-wins per key → `KV_TABLE` "agent_kv" in
the per-agent redb, restored on boot). The state blob is just the one
key everyone uses. `anchor_kind 0x02` (SMT state root) is reserved on
the wire as the sanctioned large-state commitment
(`refine_payload.rs:99-102`), and the touched-leaf sparse-Merkle witness
is already proven at the application layer in cipher-clerk
(witness 1.56 MB → 2.5 KB at 5k accounts).

## Boot checklist (read before any edit)

- `vos/src/refine_payload.rs` — v3 wire: effect tags 0x01–0x04, effects
  apply in wire order, last-wins per key, post-state = final
  `Write{STATE_KEY}`; `transition_digest` covers all effects; anchor
  kinds 0x00/0x01 live, 0x02 reserved-and-rejected.
- `vos/src/runtime.rs` — `ServiceStorage` (`:459-482`, the in-memory
  keyspace), `journaled_read` overlay (`:303`), `STORAGE_R`/`STORAGE_W`
  handlers (`:1365-1386`), `absorb_work_result` anchor check (`:412-439`),
  `take_dispatch_delta` (`:656`).
- `vos/src/commit.rs` — `STATE_TABLE`/`KV_TABLE` (`:323-335`),
  `split_delta`, `LocalCommit::commit` (`:411`), `CrdtCommit`
  (`:955-1056`), `read_kv_rows` eager hydration (`:357-371`).
- `vos/src/actors/context.rs` — `store`/`load` (`:580`, `:244`),
  `pending_writes`, `drain_into_refine_payload` (`:687-717`).
- `vos/src/actors/lifecycle.rs` — `read_persisted_state_owned`
  grow-to-exact read (`:137-155`), `BUF_SIZE = 4096` (`:27`).
- `vos/src/actors/run.rs` — `run_refine_service` cold/warm split,
  `ACTOR_HOLDER`/`CURRENT_ANCHOR` statics (`:452-500`), state-changed
  gate (`:562-586`).
- `vos-macros/src/lib.rs` — rkyv derive injection on the state struct
  (~`:68-99`); `#[msg]` attr parsing (~`:293-315`).
- cipher-clerk `merkle.rs` (`SparseMerkleTree`, depth 128, 16-byte
  keys, `BatchProof`), `view.rs` (`SparseLedger`: panics on unproven
  reads) — the W4 generalization source.
- JAM phase discipline (jar `spec/JarBook/Capability.lean:205-208`):
  `STORAGE_R`/`STORAGE_W` are **accumulate-only** in JAM; vos's
  refine-legal `STORAGE_R` is a deliberate deviation for `local`
  consistency. Nothing in this plan may add a hostcall.
- Recurring trap: PVM e2e tests run prebuilt actor ELFs — **rebuild the
  ELFs** after touching guest-side code or the tests exercise stale
  binaries.
- House rules: no `#[ignore]` tests — fix or delete; timeless comments
  (no phase narrative); `#[repr(u8)]` rkyv enums over const byte groups;
  fix pre-existing failures hit mid-task.

## Non-goals (explicitly out of scope)

- **No new hostcalls.** A `SCAN`/`NEXT_KEY` primitive would break actors
  on a conformant JAM host and buys ~1 ecall per index page over the
  self-indexed layout. Rejected permanently, not deferred.
- **No change to phase legality.** `STORAGE_R`-in-refine stays for
  `local`-consistency actors, documented as a vos-local deviation;
  provable/replicated paths get the witnessed backend (W4) which is the
  JAM-portable one.
- **Lazy host-side hydration.** `read_kv_rows` stays eager (full row
  load at agent boot). Fine at tens of MB; read-through to redb is a
  follow-up when an actual space hurts.
- **Messaging actors** (`msg-log` envelopes, `messenger` plaintext
  history): they already paginate reads; retyping their logs is a
  follow-up after W3 proves the shape.
- **Guest accumulate (A15), masked image root, jar hostcall
  convergence** — parallel tracks; this plan neither blocks nor waits
  on them.
- **Raft InstallSnapshot streaming / CRDT DAG compaction /
  `vosx space export --state`** — noted follow-ups, not in these waves.

## Design decisions (locked — do not re-litigate)

1. **Types, not annotations.** Laziness must live in the field type's
   API (point get/insert/range), so the unit of design is the handle
   type. A `#[storage]` field attribute exists only to tell the macro
   which fields to exclude from the archived blob and what key prefix
   to install. ink!'s retreat from implicit-lazy fields to explicit
   `Mapping` is the precedent: in a metered, provable VM, a host read
   must be visible in the source.
2. **Key layout** (per storage field, all rows in the agent's own
   keyspace): prefix `s/<field>/` (attribute override
   `#[storage(prefix = "...")]`; renaming a field without pinning the
   prefix orphans its rows — part of the actor upgrade contract).
   Within a prefix: value rows `…v/<key>`, index pages `…i/<page_id>`,
   one meta row `…m` (count + sorted `(split_key, page_id)` directory).
   `__vos_actor_state` and the `s/` namespace must never collide —
   the macro rejects a field literally named such that its prefix
   collides with a framework key.
3. **Entry-per-row, index-pages-of-keys.** Each map entry is its own
   row (point read = exactly one value); ordered iteration reads 4 KiB
   index pages holding keys only (~250 × 16 B keys/page), then fetches
   values lazily for the requested window. One directory row covers
   ~200 index pages ≈ 50k keys — enough headroom for every current
   actor; deeper directories are a follow-up.
4. **Iteration without hostcalls, three mechanisms.** (a) Self-indexed
   structures over point reads — legal in JAM accumulate. (b) In W4 the
   unhashed-key SMT doubles as the ordered index; the node rows a
   traversal reads *are* the authentication-path material. (c) For
   refine-phase/provable access, the host prefetches touched
   leaves + multiproof into the witness (`SparseLedger` pattern) — on
   JAM, refine has no storage reads at all, so this is the only
   conformant refine path anyway.
5. **Deletes are a first-class effect.** New wire tag
   `EFFECT_DELETE = 0x05`, `Effect::Delete { key }`. Same journal,
   digest, and replay treatment as `Write`. `Delete{STATE_KEY}` is
   malformed (decode rejects) — state reset is not expressible as an
   effect.
6. **Guest-side buffering is a static journal, not `Context` plumbing.**
   Handles can't reach `ctx` from state-struct fields; the guest is
   single-threaded, so storage handles share a guest-global
   journal + read cache (same pattern as `ACTOR_HOLDER`), overlaid over
   host reads so a dispatch sees its own pending writes/deletes, and
   drained into the `RefinePayload` alongside `Context::pending_writes`.
7. **Interim anchor gap is accepted and documented.** Until W4, storage
   rows sit outside the 0x01 anchor (which hashes only the STATE blob).
   Replication stays correct — Raft replays dispatches, CRDT replays
   effect logs, and keystone's effect-bearing durable-node rule already
   forces a DAG node for non-STATE writes — but anchor verification
   does not cover the rows. Provable actors therefore may not use
   storage types until `anchor_kind 0x02` lands (W4). The A10 bug
   (Task non-STATE effects dropped on replica rebuild) additionally
   gated *Tasks* + storage rows on replicated agents — FIXED: invoke
   effects ride the effect log and replay re-absorbs them.
8. **Per-value soft cap 4 KiB** (fits `BUF_SIZE`, one `STORAGE_R`
   round-trip). Values past the cap read via the grow-to-exact heap
   path with a hard guest-side error at 64 KiB — a quarter of the heap;
   anything bigger belongs in the proof-blob CAS by hash, not in a row.

---

## Wave 1 — wire + host substrate (delete effect, ordered storage)

### 1.1 `Effect::Delete` on the v3 wire

- `vos/src/refine_payload.rs`: add `EFFECT_DELETE = 0x05`,
  `Effect::Delete { key: Vec<u8> }`, encode/decode arms,
  `transition_digest` coverage (it already digests raw effect bytes —
  add the tag to the canonical encoding), decode-reject
  `Delete{STATE_KEY}`.
- `vos/src/runtime.rs`: journal representation — `journal.writes`
  entries become write-or-tombstone so `journaled_read` returns
  "absent" for a pending delete (today `Option<&[u8]>` can't distinguish
  no-entry from tombstone — restructure the overlay accordingly);
  `absorb_effects` applies deletes via the existing
  `ServiceStorage::delete`.
- `vos/src/commit.rs`: `split_delta`/`AgentDelta` carry deletes;
  `LocalCommit::commit` removes the `KV_TABLE` row; `CrdtCommit`
  replay (`replay_logs`) applies deletes; Raft path exercises the same
  `AgentDelta`.
- `vos/src/actors/context.rs`: `Context::remove(key)` queuing a pending
  delete; `drain_into_refine_payload` emits it; guest `load` overlays
  pending deletes as absent.
- Tests: wire round-trip incl. reserved-key rejection; journal overlay
  read-after-delete; Local commit removes the row; CRDT two-replica
  replay converges after delete; digest changes when a delete is added.

### 1.2 `ServiceStorage` → ordered map

- `vos/src/runtime.rs:459-482`: `HashMap<(u32, Vec<u8>), Vec<u8>>` →
  `BTreeMap` (or per-service `BTreeMap<Vec<u8>, Vec<u8>>` inside a
  service map — pick whichever keeps `read`/`write`/`delete` signatures
  stable). Motivation: host-side prefix scans for W4 prefetch and
  streaming snapshots; behavior-neutral otherwise.
- Confirm no test depends on hash iteration order.

**Gate W1**: full `cargo test -p vos` + e2e suite green, ELFs rebuilt.

## Wave 2 — guest storage types + macro wiring

### 2.1 `vos::storage` module (guest-side, `service` feature)

- `StorageValue<T>`: one row, get/set/take.
- `StorageMap<K: FixedKey, V>`: get/insert/remove/contains, ordered
  `iter_from(start) -> impl Iterator` reading index pages lazily;
  layout per decision 2/3. `FixedKey` = fixed-width byte keys
  (`[u8; N]`, u64 via BE encoding) so index pages and, later, SMT paths
  are well-defined; order = byte order.
- `StorageVec<T>`: dense `le64(i)` rows + len row; push/get/swap_remove;
  covers append-only logs (`note_commitments`) and dedup journals.
- `StorageSet<K>`: `StorageMap<K, ()>` (index pages only, no value
  rows).
- Read path: `hostcalls::read` with the 4 KiB stack buffer,
  grow-to-exact fallback (mirror `read_persisted_state_owned`), hard
  error past 64 KiB (decision 8). Values rkyv-encoded with the
  existing `codec::{Encode, Decode}`.

### 2.2 Guest-global storage journal + cache

- New statics beside `ACTOR_HOLDER` (`vos/src/actors/run.rs`):
  per-dispatch read cache and pending write/delete map, keyed by full
  row key. Reads check pending → cache → `STORAGE_R`. Drained into the
  halt payload with the `Context` effects (order within the payload:
  storage-row effects before the final `Write{STATE_KEY}` — the
  state-write-last invariant in `drain_into_refine_payload:699` must
  hold).
- Cache lifetime: cleared at dispatch end in v1 (correct by
  construction). Persisting it across warm restarts is safe
  single-writer but interacts with out-of-band CRDT merges — see open
  questions; do not enable until answered.

### 2.3 `#[storage]` field attribute in `#[actor]`

- `vos-macros/src/lib.rs`: parse `#[storage]` /
  `#[storage(prefix = "…")]` on state-struct fields. Handle types
  implement rkyv `Archive`/`Serialize`/`Deserialize` manually with a
  unit archived form (they carry no persisted data), so the injected
  derives need no surgery; the macro generates
  `__vos_init_storage(&mut self)` installing each handle's prefix from
  the field name, called from `load_or_create` after decode/create.
  Uninitialized handles panic on first use (fail loud).
- Compile-fail tests for prefix collisions and `#[storage]` on
  non-handle types.

### 2.4 Paged-reply helper

- `vos::storage::page_reply` (or similar): fill a reply from an
  iterator up to a row-count + byte budget, return
  `(rows, next_cursor)` — the msg-log `history` pattern
  (`actors/msg-log/src/lib.rs:182-211`) promoted into the prelude so
  W3 handlers don't reinvent it.

### 2.5 Wave-2 e2e

- New PVM test actor with a `StorageMap` populated past the 256 KiB
  heap (≥ 50k small entries via repeated dispatches): point get/insert
  stay O(touched); ordered range query returns paged results; restart
  (cold) preserves rows; non-storage actors' state blob byte-identical
  to before (regression).

**Gate W2**: lib + e2e green; the big-map actor runs within the guest
heap; `STATUS_TOO_BIG` regression suite untouched.

## Wave 3 — adopt in the worst offenders (replication-safe subset)

### 3.1 space-registry

- `actors/space-registry/src/lib.rs:521-600`: move the byte-payload
  collections (`blobs`, `metas`, `extension_metas`) and the large
  row sets (`members`, `auth_grants`, `actor_acls`,
  `used_replication_ids`, `host_mappings`) to storage types. Small
  config-like fields stay in the blob.
- Every full-collection list handler (`programs()`, `agents()`,
  `members()`, `auth_grants()`, `actor_acls()`, `host_mappings()`)
  gains cursor + budget pagination via 2.4; callers in `vosx` updated
  in the same commit (no compat shims — pre-release).
- Registry is CRDT-replicated with signed ops: verify per-key effects
  replay under `registry_canon` signing unchanged (writes are already
  effects; only their granularity changes).

### 3.2 clerk-bridge

- `actors/clerk-bridge/src/lib.rs`: `received` (`:334`) →
  `StorageSet<[u8;32]>`; `window_nets` (`:357`) → `StorageMap`.
  `window::accumulate_neg`'s linear scan becomes a point
  get-or-insert.

### 3.3 NOT clerk-ledger

- The ledger's `composite_root` needs every account; retyping it
  before incremental commitment would turn each transfer into O(N)
  point reads. It moves in W4 where the SMT maintains the root
  incrementally. (Its arrival there also removes today's
  O(N log N)-twice-per-transfer rebuild.)

**Gate W3**: full e2e incl. federation/showcase suites; registry
pagination exercised by a vosx-side test; two-replica CRDT convergence
test over per-key registry writes + deletes — hardened to byte-compare
both replicas' *persisted* KV tables and to cold-restart a replica
with no network attached (pins `commit_rebuilt`).

### W3 hardening (post-review fix arc)

An adversarial review of the W3 branch surfaced one critical and four
major defects, all fixed on the branch before merge:

1. **Post-replay persistence (critical, substrate)** — see open
   question 1's third bullet: `CommitStrategy::commit_rebuilt` swaps
   the whole persisted KV table for the replayed slate.
2. **Authority co-location** — `root`, `revoke_epochs`,
   `actor_revoke_epochs`, `consistency_floors` moved to `#[storage]`
   so a state-blob drift fallback resets authority state as one unit
   (a blob-reset floor beside surviving grant rows resurrected revoked
   admins). Pinned by `registry_authority_survives_state_blob_drift`.
3. **Members cursor** — the identity-phase cursor is the hashed
   32-byte map key (never empty ⇒ can't collide with the phase-start
   sentinel and loop `members_all` forever); `add_identity` refuses
   the empty key. Pinned by `members_pager_terminates_one_row_at_a_time`.
4. **Page byte budget** — 48 KiB, sized against the 256 KiB guest heap
   with ~3× per-row residency (read-cache + decoded + encode), not the
   1 MiB halt cap.
5. **`effective_role` walks iteratively** — one decoded row live at a
   time; a grantor cycle (admin self-re-grant) refuses in ≤ table-size
   hops with O(1) memory instead of OOMing the arena.
6. **Registry unit suite revived** (39 tests; was uncompilable) via a
   std dev-dep + mock reset isolation; `host_mappings()` returns
   `HostMappingPage` with an explicit `more` terminator.

## Wave 4 — committed storage: `anchor_kind 0x02` (B6 / `vos::zk::state`)

### 4.1 Generalize the SMT into vos

- Port cipher-clerk's `SparseMerkleTree`/`BatchProof` into
  `vos::zk::state` with nodes stored as agent KV rows (reserved
  framework prefix, e.g. `__vos_smt/`), raw fixed-width keys as paths
  (in-order traversal = key order; adversarial-key balance is a
  non-issue for internal ids — user-keyed committed maps hash the key
  and forfeit ordered iteration).
- Incremental root maintenance: a dispatch updates only the node rows
  on touched-leaf paths (O(touched · log N) reads + writes, all
  ordinary storage effects).

### 4.2 Composite anchor + wire acceptance

- Anchor = SMT over the agent keyspace with the state blob as one
  designated leaf. Emit `anchor_kind 0x02` from the guest when any
  `#[storage(committed)]` field exists; `refine_payload.rs` decode
  accepts 0x02; `absorb_work_result` verifies against the
  host-maintained root. `anchor_for` grows a root-aware variant.
- The B4 trap applies doubly here: the digest still covers the
  pre-`take_state_write` payload — extend the existing tests.

### 4.3 Witnessed-read backend

- Two-backend read trait behind the handle types: live `STORAGE_R`
  (local mode / accumulate) vs witnessed leaves verified against the
  anchored root (provable Tasks; `SparseLedger` semantics — panic on
  unproven read). Host prefetches touched leaves + multiproof into the
  witness buffer at dispatch staging; the touched-key set comes from
  the actor's declared storage metadata (`.vos_meta` gains a storage
  section — trailing-append evolvable, per the metadata discipline).
- Prefetch needs a host-side touched-set oracle; v1: the caller's
  message names the keys (the clerk kernel already works this way —
  reads only by explicit id). Speculative/discovery reads inside
  provable tasks stay out of scope.

### 4.4 clerk-ledger onto committed storage

- Retype `accounts`/`transfers`/`external_ids`/`voided_transfers`/
  `pending_statuses`/`transfer_roots`/`note_commitments` onto committed
  storage types; `composite_root`/`state_root` served from the
  incremental SMT root.
- Capstone gate: 10k-account ledger e2e — transfers commit in
  O(touched), state root matches a from-scratch rebuild, guest heap
  never exceeded, and a provable transfer's witness is
  O(touched · log N) (the cipher-clerk 2.5 KB result reproduced at the
  actor layer).

**Gate W4**: full gate incl. proving e2e; 0x02 anchors verified
end-to-end; 0x01 actors byte-for-byte unaffected.

### W4 as built (4.1, 4.2, 4.4 landed; 4.3 remaining)

- **4.1** — `vos::zk::state` generalizes the math to any key width
  with parameterized domains (cipher-clerk byte-parity pinned against
  vectors computed by running cipher-clerk itself);
  `vos::storage::CommittedMap` is the row-backed incremental tree:
  node rows only at branching points (every stored node has two
  non-empty children; delete collapses), a root row
  `[count][root hash][top ref]`, spines recomputed off the empty
  chain. Mutations touch O(log n) rows; the structure is a pure
  function of the key set (row-snapshot byte-identity across
  histories); in-order DFS is the ordered index per decision 4b.
- **4.2** — the composite root (state-blob hash folded with the
  committed field roots, declaration order) is ITSELF a framework
  storage row (`__vos_committed_root`), written at halt only when it
  moved. The host's expected-anchor check reads that row through the
  same journal overlay as the state blob — genesis-first-dispatch,
  chained tick iterations, and cold restart all work with zero
  host-side metadata. Guest `CURRENT_ANCHOR` carries the blob hash
  separately (blob-moved ≠ anchor-moved under 0x02). Tasks stay on
  0x01 until 4.3. Fixture: `examples/actors/committed-counter` + e2e.
  The guest-framework change took the expected re-pin (cheap half —
  floors unchanged; drift guard re-proved green), and the catalog
  lockstep test now also pins `unpatched_image_root` trace-only.
- **4.4** — clerk-ledger's six kernel collections are
  `#[storage(committed)]` maps under cipher-clerk's domains with
  canonical leaf contents (`insert_with_leaf`), so the composite stays
  byte-identical to the from-scratch rebuild and vouchers keep
  verifying; `state_root` is O(1); the twice-per-transfer rebuild is
  gone; `create_accounts` batches ~8 signed creates per 4 KiB message.
  Capstone green: 10k accounts through the real PVM, a transfer at
  10k in ~66 ms, and the incremental root byte-equal to a rebuild
  from the raw persisted rows. Sequenced BEFORE 4.3 deliberately: the
  ledger's provable path is app-level (voucher-check +
  `SuccinctTransitionWitness`), so the capstone needs the incremental
  roots, not the generic witnessed backend.
- **4.3** — the witnessed-read backend, as built. The VOST task input
  grew a trailing rows section (`n_rows = 0` encodes as four zero
  bytes — identical to the `.bss` padding, so pre-rows images are
  byte-stable and live≡traced holds through the shared
  `encode_task_input_with_rows`). The touched-set oracle is the
  plan's v1: **the caller names the keys** —
  `Tasks::spawn_raw_with_rows` / `invoke_hash_with_rows` carry them
  in the invoke input (flag bit in the state-length word; service
  invokes untouched), and the host resolves each against the invoking
  parent's EFFECTIVE keyspace: a Task reads the parent's rows and
  folds effects back into the parent, so the parent decides what the
  child sees. Named-but-absent keys stage as proven-absent; the
  guest's dispatch overlay carries the witness and any read of an
  unnamed key panics as unproven (a Task's STORAGE_R is an echo stub
  — the backend never falls through to it). `register_task_blob` now
  records the witness buffer's capacity (`vos::zk::witness_symbol`
  reads the symbol size) and the host refuses over-capacity inputs as
  TOO_BIG instead of overwriting adjacent `.bss`. Gates:
  `task_storage_reads_come_from_the_witness` (present /
  proven-absent / unproven-panic) + the live≡traced pair. A10 fixed
  first (see open question 4), so witnessed Tasks run on replicated
  agents. Deferred: the `.vos_meta` storage section (an auto-derived
  message→keys oracle has no consumer yet — explicit keys are what
  the clerk pattern needs); in-guest tree-consistency checks for
  committed rows (soundness rides the anchor: a doctored witness
  changes the emitted composite and fails the verifier's comparison —
  the SparseLedger model).

## Open questions (resolve before the wave that needs them)

1. **Warm-guest invalidation on out-of-band CRDT merge** — RESOLVED
   (W3 substrate commit). Two parts:
   - *The warm holder is a non-issue.* The warm `ACTOR_HOLDER` blob lives
     only inside a saved continuation (yield → resume), cleared on the
     dispatch's `DONE`. CRDT merges run strictly between top-level
     dispatches (agent-loop Cycle 4, `node.rs`), so no live warm holder
     spans a merge for a completing-handler actor — the registry never
     yields. Storage reads are not cached across dispatches in v1 (2.2),
     so there is no cross-dispatch storage cache to invalidate either.
   - *The real gate was the replay slate.* `soft_restart_crdt` rebuilds
     rows by re-executing the DAG from genesis, but deleted only
     `STATE_KEY` before replaying — onto the live pre-merge storage rows.
     The meta/index rows and `StorageVec` length rows are accumulators
     seeded from current stored bytes, so replay diverged: a `StorageVec`
     doubles its length (positional `push` reads the stale length row),
     the `next_page` allocator + directory rebuild a physical layout that
     is no longer byte-identical across replicas (the state anchor does
     not cover storage rows), and any path-dependent handler reading a
     collection mid-replay sees the final merged map, not the genesis
     progression — under Raft (`linear_history`) that surfaces as a fatal
     `replay diverged` agent tear-down. A `StorageMap`'s *final count*
     self-heals (inserts are membership-gated), so a count-only test does
     not catch it — `StorageVec` length and cross-replica row byte-equality
     do. Fix: `ServiceStorage::clear_service` wipes the whole per-service
     keyspace before replay (preserving only the host-seeded `INIT_KEY`),
     symmetric with the empty slate a cold-boot replay already sees
     (`node.rs` cold path pre-loads only `INIT_KEY`, so it was already
     correct). Tests: `vos::actors::storage::tests::vec_replay_needs_a_cleared_keyspace`
     (final-state proof), `runtime::tests::clear_service_drops_only_that_services_rows`.
     The 3.1 two-replica gate exercises it end-to-end.
   - *The rebuilt slate must also persist wholesale.* Post-replay
     materialization committed only the state blob (`commit_state`), while
     the KV table is written exclusively from *local* dispatch deltas — so
     the rows replay rebuilt for merged **remote** dispatches lived only in
     the in-memory runtime. A cold reopen (`restore_writes`) came back
     missing every remotely-replicated row (a restarted replica answered
     `node_role = 0` for its peers' voters), and a post-merge local delta
     could persist index pages naming value rows the table never held —
     panicking `StorageMapIter` on the first list after restart. Fix:
     `CommitStrategy::commit_rebuilt(state, rows)` atomically writes the
     state and *swaps* the whole KV table for the replayed slate (dropping
     rows the replayed layout no longer produces), implemented for
     `LocalCommit`/`CrdtCommit`/`RaftCommit` and called from both replay
     materialization sites (`soft_restart_crdt`, cold-start replay).
     Tests: `commit_rebuilt_swaps_the_whole_kv_table`,
     `crdt_commit_rebuilt_swaps_rows_without_appending_history`; the 3.1
     gate now also byte-compares both replicas' persisted KV tables and
     cold-restarts a replica with no network attached (both fail without
     the fix).
2. **Registry ordering semantics** (3.1): do any registry consumers
   depend on insertion order of `members`/`agents`? If so those become
   `StorageVec` + side index rather than ordered maps.
3. **SMT leaf domain** (4.1): RESOLVED — per-field trees with a top
   fold. Decision 4b already required it (the unhashed-key SMT doubles
   as the ordered index, which needs a fixed width per tree), and it
   is what lets clerk-ledger's fields carry cipher-clerk's domains for
   voucher parity while the anchor composite folds under vos domains.
   The composite is a linear fold (state hash, then field roots in
   declaration order) rather than a balanced tree — field counts are
   tiny and the fold is what the macro can emit cheaply.
4. **A10 fix ordering** (4.3): RESOLVED — the effect log now records
   each depth-1 invoke's absorbed effects (`InvokeEffects`, a trailing
   wire extension keyed to the reply index) and the replay
   short-circuit re-absorbs them into the recorded scope, so a rebuilt
   replica's journal reproduces what the live children did without
   re-running them. Gate: `replay_reabsorbs_task_effects` (fails with
   the re-absorb disabled). Witnessed Tasks on replicated agents are
   unblocked.
