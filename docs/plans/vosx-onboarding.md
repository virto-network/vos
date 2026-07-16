# vosx onboarding — recipes, invite tokens, role-scoped sync

Goal: getting a node into a space becomes **one command with one argument** —
`vosx space up <token>` — and the manifest stops pretending to be runtime
state. The manifest becomes a *recipe*: consumed at `space new` (genesis) and
`space apply` (explicit reconcile), never at boot. Invite tokens carry a role;
the role decides — via registry-declared floors — what a node may sync, what
it spawns by default, and what peers will serve it. Sync access control moves
from a name-prefix hack (`msg-`) to a per-agent role floor enforced at the
**serving** side, and program blobs finally fetch from peers through the same
gate, closing the "joiner syncs the catalog but every agent sits pending
forever" hole.

Execution model for this plan: work wave by wave, one commit per work item
(item IDs below), run the wave gate before moving on. Each wave ends with an
adversarial self-review pass over the wave's diff (correctness + the specific
risks called out per item) before its gate. Waves 1–2 fit one session; waves
3 and 4 are each their own session. Read this whole file first; then read the
files listed in each item before editing them.

## Boot checklist (read before any edit)

- `vos/src/node.rs:1294` — `sync_serve_allowed`: the existing serving-side
  sync gate. Today it passes everything except `msg-`-prefixed replicas, then
  role-probes the registry (`lookup_caller_role` space-level,
  `lookup_caller_actor_role` per-actor). This plan **generalizes** this
  function; its registry-probe plumbing and call sites
  (`vos/src/node.rs:1740`, `:1754`) are reused as-is.
- `vos/src/network/mod.rs:1610` — how `FetchHeads`/`FetchNode` are served
  (per-peer `sync_rate` flood cap at `:1106`, blocking-task handoff because
  the gate's registry probe blocks). `FetchBlob` (item 2.2) copies this shape.
- `vos/src/network/wire.rs` — frame catalog + encoding conventions. Note
  `Frame::FetchProofBlob`/`ProofBlobReply` (~line 73): the closest precedent
  for blob serving.
- `vos/src/registry.rs` — protocol constants (`AUTH_ROLE_*` at 112–115,
  `NODE_ROLE_*` at 77–78), `canonical_op_bytes`, `pack_auth`. New op
  canonical shapes go here.
- `actors/space-registry/src/lib.rs` — `install` (~606), `add_node` (~971),
  `grant_role` (~1159). The registry's state lives on the storage framework:
  `StorageMap`s for `auth_grants`, `nodes`/`identities`, `revoke_epochs`,
  `consistency_floors`, … (~248–330). The invites table is one more such
  map. `redeem_invite` follows these ops' verify-then-record pattern
  exactly: signature checks are **deterministic** and re-run on CRDT replay;
  anything clock-dependent must NOT be re-checked at replay (see decision
  7). Note the `revoke_epochs` drift-fallback discipline (~288–303): a
  revocation must not be resurrectable by replaying a stale grant — invite
  revocation needs the same monotonicity.
- `vosx/src/commands/space/op_sign.rs` — `op_auth`: CLI-side signing of
  registry ops with the operator's libp2p identity. Invite minting reuses it.
- `vosx/src/commands/space/up.rs` — boot flow. Note: the manifest "peek"
  block (~111–161) is what wave 3 deletes; `collect_agent_policies` reading
  ONLY the manifest is the standing bug where a bare `space up` restart
  silently drops every agent's `tick_ms`/`intra_caps` (item 3.2 fixes this);
  `reconcile_installed_agents`'s `MissingBlob` path (~1293) is where blob
  fetch hooks in (item 2.2); the `hyperspace` persist-to-index block
  (~129–141) is the precedent for "manifest value → index, never needed
  again".
- `vosx/src/commands/space/reconcile.rs` — `Manifest`/`AgentDef`/
  `ExtensionDef` parsing. Survives, repurposed for `space apply`.
- `vosx/src/commands/space/subscriptions.rs` — `LocalConfig` (`local.toml`):
  the node-local policy file that grows in 3.2.
- `vosx/src/spaces_index.rs` — `SpaceEntry`: gains `pending_manifest`;
  pending bearer tokens live in an owner-only per-space secret file (3.1, 3.3).
- **Sequencing**: the actor-storage plan is fully landed on master (merge
  `c3e88a5a`); build the invites table as a `StorageMap` from the start —
  there is no blob-backed alternative to consider. `programs`/`agents`
  remain deliberately unpaginated (blob-backed; PVM actors call them
  arg-free), so the new `sync_role` field rides the existing agent row, not
  a separate map.
- House rules (repo-wide): no `#[ignore]` tests — fix or delete; comments are
  timeless (no phase/sprint narrative); `#[repr(u8)]` rkyv enums over const
  byte groups; if a pre-existing test breaks mid-task, fix it; never add
  Co-Authored-By.

## Non-goals (explicitly out of scope)

- **Confidentiality.** Role-scoped sync is access control, not secrecy: every
  replica that holds state can leak it, and revocation never claws back
  already-synced data. Agents needing real confidentiality use the
  messenger's answer (encrypted payload, gated keys). Nothing here encrypts
  state at rest or on the wire beyond the transport.
- **Hyperspace/federation tokens.** Invites are per-space. The hyperspace
  registry replica stays deliberately ungated (public), as today.
- **NAT traversal / relays / DHT discovery.** Tokens embed plain multiaddrs;
  if the bootnode is unreachable, joining waits. Bootnode rot is accepted
  (tokens are onboarding-only and expire anyway).
- **GitOps-style continuous manifest sync.** `apply` is a one-shot admin op.
  The registry remains the only runtime source of truth; no watcher, no
  drift-correction loop.
- **Multi-identity nodes / operator-vs-node key unification.** Redemption
  grants the role to the **daemon's** peer id (`node.key`) — that is the key
  peers see on sync and remote invokes. The operator CLI keeps driving its
  own daemon locally as today.
- **Migration/back-compat.** Pre-release, single-repo: wire and state shapes
  change in place, dev spaces get wiped, no shims. Update all callers and
  bundled ELFs in the same commit.

## Design decisions (locked — do not re-litigate)

1. **The `up` positional is trivalent**: `space up <arg>` where `<arg>` is
   (a) an existing `.toml` file path → dev-recipe mode (create-if-missing +
   one-shot genesis apply + boot); (b) a `vos1…` token → join-if-needed +
   boot + auto-redeem; (c) anything else → spaces-index lookup by name/id, as
   today. Disambiguation in that order; it is unambiguous because names may
   not start with `vos1` and file-path detection requires the file to exist.
2. **`space join` is deleted; `up --manifest` is deleted.** The token
   subsumes join; recipes subsume boot-time reconcile. `--listen` and
   `--connect` survive (runtime networking overrides, not policy).
3. **Token = pointer + credential, never policy.** Payload (rkyv, version
   byte first): `{v: u8, space_id: [u8;32], name: String, bootnodes:
   Vec<String>, role: u8, expires_at: u64 (unix secs), token_pub: [u8;32],
   admin_sig: [u8;64], token_secret: [u8;32]}`. String form:
   `"vos1" + bs58(payload ‖ blake2b256(payload)[..4])`. What the role means
   (which agents sync/spawn) lives in the registry and can evolve after the
   token is minted.
4. **Delegated-grant chain.** Minting: the admin's operator key signs
   `canonical_op_bytes("invite", [space_id, [role], expires_le, token_pub])`.
   Redemption: the joiner's daemon signs its own node peer-id bytes with
   `token_secret`, then remotely invokes the bootnode registry's
   `redeem_invite(token_pub, role, expires_at, admin_sig, peer_id,
   redeem_sig)`. The handler verifies admin→T→N offline (admin_sig against a
   current-epoch ADMIN key, redeem_sig against token_pub) and records the
   grant + an invites-table row. `redeem_invite` is deliberately callable by
   unauthenticated callers — the cert IS the auth.
5. **Two invite tiers.** Redeemable roles are `member`
   (`AUTH_ROLE_READONLY`) and `developer` (`AUTH_ROLE_DEVELOPER`). Admin grants
   and voter-node enrollment (`add_node` + `NODE_ROLE_VOTER`) stay explicit
   online operations via `space role grant` / `space members add-node`.
   `RaftJoinResult::NotAuthorized` remains the backstop.
6. **Single-use is best-effort, and we say so.** The invites table keys rows
   by `token_pub`; a second redemption with a different peer_id that survives
   a CRDT-partition merge is *detected* (both rows cite one token_pub),
   surfaced in `space members` output with a warning, and resolved by admin
   `revoke_role` — never silently prevented. Short expiries are the real
   mitigation; `space invite` defaults to 7 days.
7. **Expiry is checked once, at admission, against the admitting host's wall
   clock — never at CRDT replay.** Replay re-verifies signatures only
   (deterministic), exactly like `grant_role` today. A replica replaying an
   op after the expiry date must still accept it.
8. **One field drives sync AND spawn: `sync_role` floor on `AgentRow`.**
   Three user-facing levels in manifests/`install`: `sync = "public"`
   (served to any connected peer), `"member"` (caller role ≥
   `AUTH_ROLE_READONLY`), `"private"` (per-actor grant ≥ READONLY, i.e.
   today's `msg-` semantics, generalized). Default for new installs:
   `member`. The floor also defines the **default spawn set**: a node skips
   agents whose floor its own role doesn't meet; `local.toml` subscriptions
   can only narrow that set, never widen it.
9. **Not-a-row floors are hardcoded host-side**: the space registry replica
   serves at `member` (redemption precedes sync — see the ordering note in
   2.1), the hyperspace registry at `public`. `msg-*` special-casing in
   `sync_serve_allowed` is deleted; the messenger's agents install with
   `sync = "private"` to keep identical behavior.
10. **Program blobs fetch at `member` floor.** Floors gate *state*; code is
    space-visible to any member. New `Frame::FetchBlob{hash}`/`BlobReply`,
    served only for hashes present in the registry's program catalog (no
    open CAS for arbitrary bytes), behind the same `sync_rate` flood cap.
11. **Node-local policy lives in `local.toml`, written by `apply`/`new`,
    read by every boot.** `tick_ms`, `intra_caps`, `device_secret` (per
    agent), `cap_policy`, and `[[extension]]` entries move there. The
    replicated half of a manifest goes to the registry; the node-local half
    is persisted to `local.toml` in the same `apply`. A bare `space up`
    reads only registry + `local.toml` + spaces index.
12. **CLI role names, not numbers**: `member` / `developer` / `admin`
    everywhere user-facing, mapped to `AUTH_ROLE_*` in one place.

## End-state interface (operator view)

```
vosx space new <name> [--recipe recipe.toml]     # create; recipe applied once on first up
vosx space up <name | vos1-token | recipe.toml>  # THE command. join/redeem/apply as needed
vosx space invite <space> [--role member|developer] [--expires 7d] [--bootnode <addr>] [list|revoke <prefix>]
vosx space apply <space> <recipe.toml> [--diff] [--upgrade] # explicit reconcile
vosx space export <space>                        # registry → round-trippable recipe (unchanged)
vosx space down|list|info|forget|members|role|subs|… (unchanged)
```

Breaking changes: `space join` removed; `space up --manifest` removed;
`install`/manifest gain `sync = …`; new-install default floor is `member`
(previously everything served publicly); `msg-` prefix magic removed.

---

## Wave 1 — registry: invites table, redemption ops, sync floors

### 1.1 `sync_role` floor on the agent row + `install` op

- `vos/src/registry.rs`: add `SyncFloor` as a `#[repr(u8)]` rkyv enum
  (`Public = 0`, `Member = 1`, `Private = 2`) — enum, not const bytes, per
  house rules. Extend `AgentRow` and the `install` op (+ its canonical
  bytes) with it. Update `RegistryRef` call sites.
- `actors/space-registry/src/lib.rs`: thread the field through `install`,
  persist it on the row, default `Member` when absent from older callers —
  then remove the default once all callers pass it (same commit).
- Rebuild bundled ELFs (`vosx/blobs/*.elf`) — recurring gotcha: stale
  bundled registry blobs make every vosx integration test lie.
- Tests: install round-trips the floor; replay re-verifies unchanged.

### 1.2 Invites table + `redeem_invite` / `revoke_invite`

- `vos/src/registry.rs`: canonical shapes for `"invite"` (signed at mint,
  decision 4), `"redeem_invite"`, `"revoke_invite"`; an `InviteRow {role,
  expires_at, redeemed_by: Vec<Vec<u8>>, revoked: bool}`.
- Storage: `invites: StorageMap<[u8; 32], InviteRow>` keyed by `token_pub`,
  alongside `auth_grants`. Revocation is monotonic — once `revoked` is set,
  no replayed redeem/re-grant may clear it (mirror the `revoke_epochs`
  drift-fallback discipline). Listing (`space members` in 3.4) gets a
  paginated `invites()` query following the members hashed-cursor pattern.
- `actors/space-registry/src/lib.rs`: `redeem_invite` verifies (a)
  `admin_sig` over the invite canonical bytes against a key holding ADMIN at
  the current epoch, (b) `redeem_sig` over `peer_id` against `token_pub`,
  (c) not revoked, (d) role is an offline tier (decision 5 — refuse
  `admin`). On success: record/extend the InviteRow and write the grant with
  the same effect as `grant_role`. **No expiry check in the handler** —
  decision 7; the admitting host checks the clock before relaying (1.3 hook,
  wired in 2.1's serving daemon). `revoke_invite` is admin-signed and flips
  `revoked` (idempotent). Duplicate redemption appends to `redeemed_by` —
  detection, not prevention (decision 6).
- Tests, mirroring the `grant_role` test battery (~2359): happy chain;
  tampered admin_sig; tampered redeem_sig; non-admin minter; revoked token;
  double-redeem records both peers; replay determinism (re-dispatch the op
  stream, same state).

### 1.3 Token codec + mint/verify library

- New `vosx/src/token.rs`: payload struct (decision 3), `mint()` (generates
  the T keypair, signs via `op_sign::op_auth`-style canonical bytes with the
  operator keypair, encodes `vos1…`), `parse()` (checksum + version check →
  payload), `redeem_sig(node_keypair_peer_id, token_secret)`. Expiry parsing
  for `--expires` (`7d`/`24h`/`30m`).
- ed25519 for T: use the same primitives the registry verifies
  (`ed25519-dalek` lives actor-side; the *client* signs with
  `libp2p::identity::Keypair::ed25519_from_bytes(token_secret)` so no new
  crypto dep in vosx).
- Tests: round-trip, checksum corruption, wrong version byte, cross-verify —
  a token minted here passes the actor's `redeem_invite` verification (the
  interop test pattern from `op_sign.rs`).

**Wave 1 gate**: `cargo test -p vos -p space-registry -p vosx` green;
bundled ELFs rebuilt; adversarial review of the verify paths (canonical-byte
field order matches signer byte-for-byte; no replay clock checks).

## Wave 2 — serving-side enforcement: sync gate, blob fetch, spawn filter

### 2.1 Generalize `sync_serve_allowed`

- `vos/src/node.rs:1294`: replace the `msg-` prefix test with a floor lookup:
  resolve `name` → `AgentRow.sync_role` via the registry probe (cache it —
  the probe blocks up to ~5 s; a per-name TTL cache like the role lookups
  use keeps `FetchHeads` serving cheap). `Public` → serve; `Member` →
  `lookup_caller_role ≥ READONLY`; `Private` → per-actor
  `lookup_caller_actor_role ≥ READONLY`. Hardcoded: space-registry replica =
  Member, hyperspace registry = Public (decision 9).
- Ordering note (make it a test): a fresh joiner can reach `redeem_invite`
  by remote invoke *before* it can sync anything — invoke routing is not
  gated by `sync_serve_allowed`; the handler's auth is the cert. After the
  serving node records the grant, its next `FetchHeads` probe sees the role.
  The joiner's redeem retry loop (3.1) absorbs the window.
- Admission hook: expiry is checked against the serving host's wall clock
  before `redeem_invite` reaches the actor (decision 7). Admin is not an
  invite-token role; promotion remains the explicit `space role grant` path.
- Messenger migration: `msg-*` installs set `sync = "private"`; delete the
  prefix constant; the M4/M5 membership-gated-sync tests keep passing
  unchanged in behavior.

### 2.2 Program-blob peer fetch

- `vos/src/network/wire.rs`: `Frame::FetchBlob { hash: [u8;32] }` /
  `Frame::BlobReply { blob: Option<Vec<u8>> }` (chunking is out of scope —
  program ELFs are single-frame-sized like proof blobs; assert a size cap).
- `vos/src/network/mod.rs`: serve mirroring `FetchHeads` (~1610): behind
  `sync_rate`, off-loop, gated: caller role ≥ READONLY **and** the hash is
  in the registry's program catalog. Serving reads the vosx blob cache via a
  host-provided callback on the network service (the cache is vosx-side;
  `vos` stays cache-agnostic — same pattern as the proof-blob store hookup).
- `vosx/src/commands/space/up.rs` (~1293 `MissingBlob` path): on a missing
  blob, fire a fetch to a connected peer (rotate peers across passes),
  verify `blake2b(bytes) == hash`, insert into the cache; the next reconcile
  pass spawns the agent. Replace the "no peer fetch exists yet" warning with
  a "fetching from peer …" info line. Bound: at most N in-flight fetches per
  pass.
- Tests: unit (frame codec, hash-mismatch rejection); the gate refuses a
  stranger and a below-floor peer.

### 2.3 Floor-aware default spawn set

- `vosx/src/commands/space/up.rs` `spawn_installed_agents` +
  `reconcile_installed_agents`: skip rows whose floor exceeds this node's
  role (probe own role once per pass via the local registry — the daemon
  knows its own node peer id). Log once per row (damping set, new
  `RowNote::BelowFloor`). Subscriptions narrow only: `should_spawn` runs
  *after* the floor check.
- Effect worth a test: a `member`-token node in a space with a `private`
  clerk-ledger never spawns it, never fetches its blob, and — 2.1 — is never
  served its state.

**Wave 2 gate**: full `cargo test -p vos` + `elf_integration` green; two-node
smoke: member node syncs `member` agents, is refused a `private` agent's
heads, blob-fetches and spawns a missing program end-to-end.

## Wave 3 — CLI resurface: up/apply/invite/new, local.toml policy

### 3.1 `space up <name|token|recipe>`

- `vosx/src/commands/space/up.rs` + `mod.rs`: trivalent positional
  (decision 1). Token path: parse → upsert `SpaceEntry` (id, name from
  token, bootnodes), write the token to `<data_dir>/.pending-invite.token`
  atomically with owner-only permissions → boot →
  redeem loop from the reconcile tick (retry until the bootnode answers;
  remove the secret on success/expiry — the `hyperspace` persist block is the
  template). Re-running with the token after joining is a no-op join.
  Recipe path: derive name from the recipe's `space = "…"` (error if
  absent), `space new` semantics if unknown, set `pending_manifest`, boot.
- Delete the `--manifest` flag, the boot-time manifest peek, and
  `parse_manifest_file` usage in `up.rs`. `run()` shrinks: index + registry
  + `local.toml` are the only inputs (plus a pending token/manifest, each
  consumed exactly once).
- Token via stdin: `space up -` reads the token from stdin (keeps bearer
  strings out of argv/history for the cautious; document, don't force).
- Tests: arg disambiguation table; pending-token persist/clear;
  second-`up`-with-token idempotence.

### 3.2 `space apply` + node-local policy split (fixes the restart bug)

- New `vosx/src/commands/space/apply.rs`, repurposing `reconcile.rs`
  parsing: connect via `DaemonClient`, diff manifest vs `programs()` /
  `agents()`, then (in order) publish missing blobs, `install` missing
  agents (with their `sync` floor), and flag existing rows whose blob differs.
  Upgrades require both `--upgrade` and an explicit fresh immutable
  `program = "name:version"`; implicit `name:manifest` is initial/idempotent
  apply only. Preflight the full recipe before any mutation. `--diff` prints
  the plan and exits 0 without writing the blob cache, registry, or local.toml.
- Node-local half: `tick_ms`, `intra_caps`, `device_secret` per agent →
  `local.toml` `[agents.<name>]` tables; `cap_policy` + `[[extension]]`
  entries → `local.toml` top level. `LocalConfig` grows accordingly
  (`subscriptions.rs`). `up.rs` builds `AgentPolicies`, device-seed list,
  and extension registrations **from `local.toml` only** — this is the fix
  for the standing bug where a bare restart drops `tick_ms`/`intra_caps`.
- `space new --manifest` (3.3) and the recipe path of `up` (3.1) route
  through the same apply internals against the just-booted local node
  (genesis apply), then clear `pending_manifest`.
- Tests: apply is idempotent (second apply = all skips); `--diff` mutates
  nothing; policy survives a bare restart (regression test for the bug);
  extensions boot from `local.toml` with no manifest anywhere.

### 3.3 `space invite`, `space new --manifest`, delete `space join`

- New `vosx/src/commands/space/invite.rs`: load operator keypair, refuse if
  it doesn't hold ADMIN in the target space (probe via `DaemonClient`),
  mint via `token.rs`, print the `vos1…` string plus a human summary (role,
  expiry, bootnodes — default bootnodes: the running daemon's published
  multiaddrs from `.endpoint`, overridable with `--bootnode`). Only member
  and developer invites are accepted; admin promotion uses `space role grant`.
- `space new`: add `--manifest` (records `pending_manifest`). Delete the
  `Join` variant, `join.rs`, and its `--help` references; `main.rs`
  `BUILTIN_VERBS`/dispatch untouched otherwise.
- `spaces_index.rs`: `pending_manifest: String` (empty = none), serde default;
  invite bearer material never enters the syncable config index.

### 3.4 Export round-trip + `members` surfacing

- `export.rs`: emit `sync = "…"` per agent; emitted recipes must re-apply
  cleanly (`export | apply --diff` shows all-skips — make that a test).
- `members.rs`: list invites (token_pub prefix, role, expiry, redeemed_by
  count, revoked); warn inline on multi-redeemed tokens (decision 6). Add
  `space invite revoke <token_pub-prefix>` wiring `revoke_invite`.

**Wave 3 gate**: `just test` green (fresh guest/extension artifacts); `--help` for every touched verb
reads coherently (no references to join/--manifest); manual smoke: `new
--manifest` → `up` → `export` → `apply --diff` all-skips.

## Wave 4 — end-to-end proof + docs

### 4.1 The onboarding e2e (the point of the whole plan)

- In the vosx integration suite (alongside the existing multi-daemon tests;
  `VOSX_DISABLE_MDNS=1`): admin node runs `new --manifest` (a recipe with a
  `member`-floor counter agent and a `private` agent) → `up` → `invite
  --role member` → second node runs literally `space up <token>` → assert:
  join recorded, redemption lands, registry syncs, counter blob fetched,
  counter spawns and converges, `private` agent absent (not spawned) and its
  heads refused, and a call to the counter works. Then restart node 2 with
  bare `space up <name>` → everything re-attaches with no token/manifest.
- Negative twins: expired token refused at admission; revoked token refused;
  tampered token fails parse.

### 4.2 Partition honesty test

- Double-redemption: same token redeemed at two nodes before they connect;
  after merge, both grants exist, `space members` flags the token — pins
  decision 6's "detect, don't pretend to prevent".

### 4.3 Docs

- `docs/operations.md`: replace the join/manifest runbook with the
  new/invite/up/apply flow; a "day 1 as an operator" and "day 1 as an
  invited member" section each, both ≤ 10 lines of shell.
- Book: update the space-architecture page's onboarding section; one
  paragraph on the trust model (what a floor does and does NOT guarantee —
  the confidentiality non-goal, verbatim).

**Wave 4 gate**: full workspace test suite + `elf_integration` green; both
e2e tests stable across 3 consecutive runs (they're multi-daemon — flakiness
is a bug, not weather).

---

## Risks / review focus

- **Canonical-bytes drift** between minter (`token.rs`), handler
  (`redeem_invite`), and replay is the classic M5-era failure; the interop
  test in 1.3 must cover the exact byte layout, and any field-order change
  is a breaking re-mint.
- **Replay determinism**: no clock, no network, no cache state may influence
  handler accept/reject. Expiry at admission only (decision 7). Review every
  `redeem_invite` branch against this.
- **Gate probe latency**: 2.1 adds a registry probe per (peer, name) on the
  sync path; without the TTL cache a chatty mesh amplifies blocking probes.
  Measure before/after with the elf_integration sync tests.
- **Floor default flip** (`member`): any existing test that relied on
  anonymous sync of arbitrary agents breaks loudly — fix the test's setup to
  redeem/grant first; that breakage is the feature working.
- **Blob serving memory**: `BlobReply` carries whole ELFs; keep the size cap
  and the flood cap on the same counter as heads/node fetches.
