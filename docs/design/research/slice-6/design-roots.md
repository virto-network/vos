# Slice 6 design round: space identity, windows, roots, anchors, `&self` reads

Read-only design, 2026-10-18, on `vos-core` at `31b7938e`. Paths are relative
to the worktree unless they start with `~`. `D` = `docs/design/`.
`clerk-across-spaces.md` is the Clerk's draft, renamed at 6.0d; its line
numbers here are the draft's at `31b7938e`, its step numbers 5.x (now C.x).
Tags: [measured] from the docs, [read] from the code, [est] my arithmetic, not run.

The constraints taken as given: crash-fault trust inside a space; one log per
replicated agent; agents are future JAM services; millions of users; a
chain-bound statement reads at a window cut, to the space root; the space root
commits `(space_id, window)`; one anchor venue per space at a time; Kreivo P0+P1
first, the JAM verifier too.

---

## 0. What exists, in one paragraph

A space is a static file of nodes (`node/host/src/space.rs`: number, ed25519 key,
addresses); it has no id. `SpaceId` exists only in `vos-statement`
(`pvm/proof/statement/src/lib.rs:116`). Agents have a 32-byte identity, the
hash of their `CreationRecord` (`agent/wire/src/peer.rs:137`, `node/host/src/lib.rs`
`identity`), and a `u32` `AgentId`. VOS keeps **one vos-tree per committed map**,
keyed by the transformed key `key'` alone (no map prefix), each leaf
`H("vos/tree/leaf" ‖ len ‖ key' ‖ vh)` with `vh = H("vos/tree/value" ‖ salt ‖ value)`,
the value bare and the salt `H("vos/tree/salt" ‖ seed ‖ key')[..16]`
(`node/host/src/roots/mod.rs:530-560`). The builder **coalesces to the latest
version** and **rewrites tree rows in place**: no root at a chosen version, no old
tree (`roots/mod.rs:362-370`). JAM keeps **one tree over the whole keyspace**, keys
being full row keys (`Owner ‖ instance ‖ Part ‖ tag ‖ transform ‖ key'`), values
the stored, versioned row bytes (`agent/default/src/refine/jam.rs`;
`agent/wire/src/keys.rs`). So a VOS map root is **not** a node of JAM's tree:
the keys, the salts and the leaf values all differ [read]. Attests run
synchronously inside a step on caller-supplied arguments, capped by
`Limits::attest` (`invocation.rs:491`), 64 KiB VOS / 2 KiB JAM; VOS bounds a
kernel's compressions only by its handler's gas, JAM at 4,096 (`cap.rs:195-249`).

---

## 1. `SpaceId`

### Options
| | derivation | cost | rules out |
|---|---|---|---|
| **a** | `H("vos/space/id" ‖ SCALE(SpaceGenesis))`, a creation record | one new type, one file | nothing; ids are self-certifying |
| b | `H(genesis ‖ controller)` | controller must be venue-neutral | rotating the controller without a new id is fine, but a venue account in the preimage ties the id to one chain |
| c | the venue's registration index | none in VOS | migration between venues (the id changes) |
| d | the controller's public key | none | key rotation |

### Recommendation: (a)
```rust
// agent/wire/src/space.rs (new), re-exported by the node; no_std.
pub struct SpaceGenesis {
    pub version: u8,                      // 1
    pub nodes: Vec<(NodeNumber, [u8; 32])>, // founding node keys: the first anchor keys
    pub clock: WindowClock,               // §2
    pub time: u64,                        // ms since the Unix epoch, by the founder
    pub nonce: [u8; 16],                  // two spaces of the same nodes differ
}
pub struct WindowClock { pub origin_ms: u64, pub length_ms: u64 }
pub struct SpaceId(pub [u8; 32]);         // = BLAKE2b-256("vos/space/id" ‖ SCALE(genesis))
```
- **No controller in the genesis.** Controllers are venue accounts. A venue binds
  one at registration by a founding node key's signature over
  `H("vos/space/register" ‖ venue_id ‖ space_id ‖ controller)`: the "signed both
  ways" of `clerk-across-spaces.md:147`, and it stops squatting (nobody else holds a
  founding key).
- **Where it lives:** one type for both sides. Today `SpaceId` is in
  `vos-statement`, which `vos-wire` must not depend on (it pulls the final
  verifier and Stwo). Move `SpaceId`, `RootKind`, `RootRead`, `WindowIndex` and
  the anchor message into a dependency-free no_std crate (`vos-anchor`, just
  `blake2` as `vos-statement` already uses it). `vos-statement` re-exports it,
  `vos-wire` depends on it, and Kreivo gets it through `vos-statement` as
  planned. Cost: a crate split; no encoding change.
- **How agents know it:** `CreationRecord` gains `space: SpaceId`, so an agent's
  identity hash commits its space (correct: an agent belongs to one space). The
  default agent stores it at first install, as it stores `keys::target`. Kernels
  never ask for it: the served witness carries it, and the space root's preimage
  binds it (§3), so a wrong one finds no anchor.
- **The node** gets a `space.genesis` file next to the space file (or a field in
  it). `vosx space up` writes it once.
- Clerk: `SpaceId` in transport pair keys (`clerk-across-spaces.md` 5.2) is this type.
  JAM: the representative service's registration names it.

---

## 2. Windows

### 2.1 The clock
| | clock | for | against |
|---|---|---|---|
| C1 | Kreivo relay block / `WindowLength` (`kreivo-pallet.md:198`) | the venue checks it trivially | nodes need a relay-chain client to cut; the index changes meaning at a JAM migration; block-time jitter |
| C2 | JAM timeslots / slots per window | the same on JAM | the same, mirrored |
| **C3** | **Unix time:** `w = ⌊(t − origin_ms) / length_ms⌋` from the genesis's `WindowClock` | venue-neutral, so migration keeps the index; no chain client on the cut path; the leader's batch time already exists and is monotone (core model §8.4) | venues map their own time to `w` (Kreivo `pallet_timestamp`; JAM slot × 6 s from JAM's era) and must allow skew |
| C4 | a space-local counter in signed anchors | the simplest; gapless checks | the space picks when to anchor, which leaks activity unless the venue rate-limits by its clock, which makes it C3 |
| C5 | per-pair sequence cuts | the Clerk's reconciliation | not a clock: belongs in the Clerk's rows and output (§4.4) |

**Recommendation: C3.** The venue checks `last < w ≤ now_w` and
`w ≥ now_w − AnchorGrace`. A change of `length_ms` is a registry update that
takes effect at a stated future window, renumbering from there
(`origin' = boundary`, `w' = w_switch + …`). This **disagrees with**
`kreivo-pallet.md:198` (relay blocks) and `clerk-across-spaces.md:183-185` (JAM time
via the builder's node). C3 should win: those two disagree with each other,
which is the problem C3 removes.

### 2.2 The length
- **Below, by the anchor path:** cut → each agent's cut build (seconds: the
  builder keeps up at 20k writes/s, `core-model.md` §9.3) → the representative's
  close deadline `D` → one extrinsic (≈ 2 Kreivo blocks, 12–24 s). So `L ≥ ~1 min`.
- **Below, by the prover's throughput, not its latency:** proving pipelines
  across windows, so the bound is `N_stmt × t_prove ≤ P × L` per space, with `P`
  provers. The window statement is 324 s at a 9.2 GiB peak [measured, 16 rows at
  two anchors]; at one anchor (§4.4) about 0.55–0.65 of that, ~180–210 s [est:
  ~345 compressions and ~380k steps against 651 and 632,800].
  At L = 10 min one 16 GiB prover proves ~3 such statements a window [est].
- **Above, by the Clerk:** settlement finality ≈ L/2 (average wait for the cut) +
  D + the live kernel + t_prove + an extrinsic ≈ L/2 + ~4–5 min [est]. The
  exposure to a counterparty that stops settling grows with L.
- **Fees:** one anchor per window per space: 144 a day at 10 min.
- **Recommendation:** the space chooses `length_ms` in **[2 min, 60 min]**,
  default **10 min**; the venue enforces the bounds. The owner's call
  (`proving.md:686,851` defer it here).

### 2.3 The deterministic per-agent cut
| | cut | cost | against |
|---|---|---|---|
| **X1** | **by time, in each agent's own log:** cut(w) is the last version whose batch time is below the boundary `B_w = origin + (w+1)·L`. The first entry with time ≥ `B_w` finalizes it; the leader appends a `Cut` marker when it has nothing else past `B_w` | one tiny entry per window per idle agent; no cross-agent message | leaders' clocks set the cut, within their skew (cuts are deterministic, only their wall time is approximate) |
| X2 | a cut request from the representative through each agent's pair | the cut is where the message lands | a message per agent each way per window; the representative's liveness gates every cut; cuts spread by delivery latency |
| X3 | a global consistent cut (Chandy–Lamport) | consistent across agents | a protocol for an invariant no statement needs: agents are independent logs, cross-agent atomicity is never promised |

**Recommendation: X1.** Why the marker is needed even when idle: without an
entry at or past `B_w`, a new leader whose clock trails could append a batch
timed below `B_w` after the old leader reported the cut. The marker moves the
replicated batch-time mark (core model §8.4) past `B_w`, so no later entry can
fall inside window w. Accumulate, applying the first entry past one or more
boundaries, records `cut(w) = version − 1` for each crossed `w` (they coincide
when an agent was idle or down). An agent down across `B_w` cuts when it comes
back, at the same log position any replica would pick.

---

## 3. Agent roots and the space root

### 3.1 The agent root: make it the same on both hosts
| | layout | cost | rules out |
|---|---|---|---|
| R1 | VOS adopts JAM's whole-keyspace tree | every row hashed on VOS (sessions, outbox, marks, workflows: several system rows a batch), all salted; builder load several-fold | VOS's "plain tables have no root" economy |
| R2 | nest: map trees → an agent tree over `MapId → map root`; JAM's state root becomes `H(tag ‖ agent_root ‖ rest_root)` | +1 path level (~0.25 KB, ~8 compressions) per map a kernel reads; on JAM, each touched map's root re-leafed per package (~160k gas [est at 20k/compression]) | nothing |
| R3 | per-host kinds; venues accept per space | none now | one kernel per host or a kernel with both verifiers: program ids then depend on the host, against "agents are future JAM services" |
| **R4** | **committed rows first in the keyspace:** a new owner byte `Committed = 0x03`, row key `0x03 ‖ instance ‖ tag ‖ transform ‖ key'`; VOS keeps **one tree per agent** over these full keys; the leaf value is the bare value and the salt `salt(seed, full key)` on both hosts | a keyspace layout change in `keys.rs` on both hosts; the builder goes from per-map trees to one per agent (simpler); JAM's tree computes committed leaves the VOS way (bare value, not the versioned framing); fixtures and the window kernel regenerate | nothing; map roots remain, as subtree nodes |

**Recommendation: R4.** In a crit-bit tree with absolute branch levels and
leaves that commit full keys, the keys sharing a byte prefix are exactly the
leaves of one node, whose hash does not depend on the rest of the tree. So:
- **VOS's agent root = the node of JAM's whole tree at prefix `0x03`,**
  byte for byte, with no extra hashing on JAM. A JAM kernel or verifier reaches
  it from JAM's state root by a path of at most 8 branches (the first byte).
- **Map roots stay**, as the nodes at `0x03 ‖ instance ‖ tag ‖ transform`, so
  in-space attests "as of the latest complete root W ≤ V" keep working.
- **One multiproof** covers a kernel's reads across all the agent's maps.
- Cost per opened leaf: +10 key bytes (the leaf preimage stays within one
  128-byte block at today's 50-byte hashed keys). Depth: `log2` of all the
  agent's committed rows instead of one map's (+1–3 levels for a few maps).
- The Poseidon2 root kind (slice 7, `proving.md:697`) is a map outside this
  tree, its own root kind in the agent leaf (below). Not slice 6.
- **This disagrees with** `core-model.md` §9.3 ("No global state root on VOS")
  and `proving.md:693-696` ("roots differ by host; a chain accepts only kinds the
  same on both"). Proving §7 should win on the first (VOS gets agent and space
  roots); R4 makes the second moot (the kinds are equal).

```text
AgentRoot A  = root of the vos-tree over { 0x03‖instance‖tag‖transform‖key' → value }  (empty: H("vos/tree/empty"))
```

### 3.2 The space root
```text
agents_root  = root of the vos-tree over { agent_id as 4 BE bytes → kind(1) ‖ A(32) ‖ window_A(8 LE) },
               salt = 16 zero bytes (the values are roots: nothing to hide)
S_w          = BLAKE2b-256("vos/space/v1" ‖ space_id(32) ‖ w(8 LE) ‖ agents_root(32))   -- 84 bytes, one compression
```
- `kind` 0 = the R4 Blake2b committed tree (the same on both hosts); 1 reserved
  for Poseidon2 (slice 7). `window_A` is the window of the agent's last reported
  root (§3.3): equal to `w` unless the agent missed the close.
- `w` in the preimage makes an idle space's root differ every window, so
  roots never show inactivity, and binds the window as `proving.md:688` decided.
- **Only agents with committed state are leaves** (an install flag, or "has a
  `CommittedMap`"): the tree is over agents, not users.
- **Cost at millions of users:** users are rows inside agent trees, which the
  builder keeps up incrementally (8–25 hashes an update, 20k writes/s). The
  space root rebuilds from scratch each window: 10k agents ≈ 20k compressions
  ≈ 20 ms native [est]; a million agents ≈ 2 s [est], still per window. No
  incremental structure needed in slice 6.

### 3.3 Who builds it, who signs
| | builder | for | against |
|---|---|---|---|
| **B1** | **the representative: a system agent per space** (identity §11), Raft-replicated on ≥ 3 nodes. Each agent's leader, after its cut build, sends `AgentRoot { w, kind, root }` on its pair (exactly-once); the representative's leader appends `Close(w)` at `B_w + D` or when every agent has reported; `S_w` is a pure function of its state at `Close(w)` | the log makes `S_w` unique, so a failover resubmits the same root and honest nodes never equivocate; a missing agent keeps its last leaf with its older `window_A` (liveness for that agent only) | one more agent; one message per agent per window |
| B2 | any node, stateless, from the agents' replicas | no new agent | which agents made it by the deadline is timing, so two nodes can compute two roots: honest equivocation |
| B3 | the controller signs | a slow multisig cannot sign every window (`kreivo-pallet.md:180-185`) | |

**Recommendation: B1, anchors signed by any one registered node key.** Under
crash faults one signature is enough. Say plainly: **an anchor gives ordering and
non-equivocation, not integrity of the space's state** (identity §11:414-417);
a space can anchor any root of its own making, as it can lie about itself in
any statement. A node key holder can equivocate (the venue then suspends the
space, §4.2). Domain-separate the anchor signature from the transport use of
the same key (the message's tag does). The representative is also JAM's
representative service later (identity §10–§11): same `Anchor`, another venue.
`D` default: `min(L/5, 2 min)`.

---

## 4. Anchors

### 4.1 The anchor
```rust
pub struct Anchor {            // vos-anchor
    pub space: SpaceId, pub window: u64, pub kind: RootKind, pub root: [u8; 32],
    pub signer: [u8; 32],      // a registered anchor key
    pub signature: [u8; 64],   // ed25519 over the digest below
}
// digest = BLAKE2b-256("vos/anchor/v1" ‖ venue_id(32) ‖ space ‖ window(8 LE) ‖ kind(1) ‖ root)
// venue_id: Kreivo's genesis hash; on JAM, H(JAM genesis ‖ service id).   ~170 bytes on the wire.
#[repr(u8)] pub enum RootKind { Space = 0 /* S_w over Blake2b trees */, /* 1 reserved: Poseidon2 */ }
```
`RootRead.kind` becomes `RootKind`; an unknown byte is `Refusal::Statement` at
decode. This replaces Kreivo's sketch `{ SpaceWindow = 0, Carried = 1 }`
(`kreivo-pallet.md:105`) if §4.4's recommendation holds.

### 4.2 The table at a venue
- `Anchors: (SpaceId, RootKind, WindowIndex) → root`, `Last: SpaceId → WindowIndex`;
  `Venue::anchored` compares the whole `RootRead` (as `proving.md:657` says).
- **`anchor`:** a registered, unsuspended space; a registered key; the signature;
  `Last < w ≤ now_w`, `w ≥ now_w − AnchorGrace`; gaps allowed.
- **Equivocation:** an anchor for a `(space, kind, w)` already holding another
  root is not stored. The pallet records both and suspends the space (its
  statements refused) until the controller rotates keys. Anyone may submit the
  second signed anchor as evidence, so it is checkable off-line.
- **Pruning:** `on_idle` drops anchors older than `MaxRootAge` (recommend 24 h),
  and `seen` entries whose newest root is older (`kreivo-pallet.md:213-217`).
  Storage per space: 144 × ~80 B a day [est].
- **Who submits:** the representative's leader, as a signed extrinsic from a
  funded account (fees, never feeless), the anchor's own signature inside, so
  the same bytes serve JAM.
- **JAM:** the representative service's accumulate stores anchors; the verifier
  service's `admit` checks `anchored` and `seen` in its accumulate (refine reads
  no state, context M3.6).

### 4.3 Venue migration
Signed `Migrate { space, venue_from, venue_to, from_window }` by the controller,
recorded on both; each venue refuses anchors outside its range. That is all the
"in-code migration ranges" a rooted statement needs (F2 below).

### 4.4 Spans: how the Clerk settles from its last settled anchor
| | mechanism | needs | rules out |
|---|---|---|---|
| S1 | a `Carried` `RootRead` kind: the venue skips the anchor check and the handler compares it with its stored last-settled root | the kernel reads rows at the **old** cut: the old tree kept until the pair settles, unbounded for an idle pair | pruning the space's trees by time |
| S2 | the venue keeps anchors per pair (no pruning while a handler references one) | the same old trees on the space side; unbounded venue storage | the same |
| **S3** | **carry a commitment, not a root:** the handler keeps per `(A, B, currency)` the last settled cumulative state (`c = H(salt ‖ cum_sent ‖ cum_recv ‖ seq)`, or the plain numbers if gross flows may be public); the kernel takes the old values privately and `c_prev` as a `#[public]` argument, reads the current rows at **one** anchored cut, and outputs `(net, seq, c_new)` | the Clerk's pair rows are cumulative per `(peer, currency)` (decision 4's aggregate, `clerk-across-spaces.md:290-295`), with an in-band settle marker on the pair recording `cum(seq)` as a row on each side | statements needing two genuine anchored reads (none known) |

**Recommendation: S3.** It needs no history at all: one anchored root per
statement, anchors prunable at `MaxRootAge`, no tree retention beyond the cut
(§5.4). Reconciliation under continuous traffic: A's marker row says "sent
through seq s: X", B's says "credited through s: Y"; the handler pairs them on
s. That is where the per-pair sequence cut (C5) belongs: in rows and outputs,
not in the window machinery. Spans to any later anchor come free: the delta is
`cum_new − cum_prev`. It also retires the "absence at a past anchor"
creation-window device (`clerk-across-spaces.md:195-199`) and `RootKind::Carried`.
Cost: `cipher_clerk::settlement::window(space, anchor_i, anchor_j, reads)` changes
shape (one anchor, a carried state). The owner's call (context D.12).

### 4.5 F2, the venue binding
| | binding | cost | covers |
|---|---|---|---|
| a | a venue field in the io-hash (`vos/io/v2`) | every kernel's code and id; the venue must be chosen at prove time; a rootless fact needs one proof per venue | all |
| b | a convention in `public_args`, by audit | per kernel | rootless, where it matters |
| c | migration ranges | none: anchors for a window exist on one venue only | rooted |

**Recommendation: (c) for rooted statements, (b) for the rootless ones whose
effect must be single-venue; no `vos/io/v2`.** Value-moving statements are
rooted. A rootless statement accepted at two venues is a true fact twice; if a
handler's effect must happen once across venues, the kernel names the venue in
`public_args`. A double anchor of one window on two venues by a space is its own
lie, and moves only venue-local balances. The owner's call (context D.1).

---

## 5. `&self` attestable reads

### 5.1 The surface
```rust
#[attestable(gas = N)]
pub fn settle(&self, #[public] pair: PairKey, #[public] c_prev: [u8; 32], carried: Carried) -> Out
//            ^ a read-only view: committed fields only, each a WitnessedMap; tables and plain fields fail to compile
```
- The macro lifts `messages.rs:119-130`'s "no self" for `&self` only (`&mut self`
  stays refused: attestable writes, "root after", are not slice 6).
- **Reads are declared, not discovered.** The caller names the keys:
  `ctx.attest_at_cut(Settle { pair, c_prev, carried }).reads(|r| r.pairs.key(&pk)).await`.
  The generated view answers `get` from the verified set and traps on any other
  key. Discovery (a hint precompile or a native dry run, as JAM's builder does)
  is later work; an explicit read set gives one shared multiproof, a size
  known before the run, and no new AIR surface.
- **`#[public]` arguments:** `public_args = SCALE((agent_id, instance_id, p1, p2, …))`,
  in declaration order. The agent and instance lead, so a statement says whose
  rows it read (two instances of one actor in a space are otherwise
  indistinguishable to a venue).
- **The io-hash:** `runtime::attested` becomes
  `attested(public_args, output, roots, io_hash)`, with
  `roots = [RootRead { kind: Space, space, window: w, root: S_w }]`,
  computed by the prologue from what it verified. The preimage keeps
  `vos/io/v1` (its layout already has the three fields).
- Synchronous rootless attests (`ctx.attest`) stay as they are, for in-space
  use and rootless statements.

### 5.2 The served witness, read by the prologue after the arguments
```rust
pub struct Served {                       // SCALE; ~120 B header
    pub space: SpaceId, pub window: u64,
    pub agent: u32, pub instance: u32,
    pub agent_root: [u8; 32],             // A at cut(w)
    pub agents_root: [u8; 32],
    pub space_path: Vec<u8>,              // BatchProof encoding: agent_id → kind ‖ A ‖ window_A, against agents_root
    pub rows: Vec<(Vec<u8>, Option<(Salt, Vec<u8>)>)>, // full row keys, in order; None = absent
    pub rows_proof: Vec<u8>,              // one BatchProof encoding against agent_root
}
```
The prologue: `verify_encoded(rows_proof, agent_root, claims)`;
`verify_encoded(space_path, agents_root, [(agent_be, Some(vh(0-salt, kind‖A‖w)))])`
with `window_A == w`; `S = H("vos/space/v1" ‖ space ‖ w ‖ agents_root)`. A
refusal traps: the attest fails and the workflow sees the error (the
attestable's "cannot fail" holds for its body only).

### 5.3 When it runs: at the next cut, from a workflow
A request made during window w is served at cut(w):
1. a workflow step calls `attest_at_cut(..).await`; the step records a
   pending request `(id, method, args, read set)`; the workflow pauses;
2. cut(w); the agent's builder builds exactly to cut(w) and **holds** (§5.4);
   it generates `rows_proof` for every pending request of w and keeps it with
   the request; the leader sends `AgentRoot` to the representative;
3. the representative closes w, computes `S_w`, keeps `space_path` per agent
   for w, and its leader signs and submits the anchor;
4. the requesting agent's leader fetches `space_path`, assembles `Served`, and
   proposes the resumption; refine runs the kernel live on `args ‖ served` and
   records the `Attest`; the workflow resumes with the output;
5. the prover worker proves it (§6) and submits once anchor(w) is in.

So the read is at the cut that is the space's last anchored cut when the
statement is submitted, as `proving.md:844` decided. Latency to step 4:
`B_w − request + build + D` (seconds to one window). Handlers cannot wait
(core model §8.1), so this needs a workflow, or a command whose request's
result arrives as a later input to a named callback.

### 5.4 Retention: what history the space keeps
| | retention | cost | allows |
|---|---|---|---|
| **W1** | **none past the cut:** the builder stops at each pending cut, the cut build reads values as of cut(w) (an `undo(w, key)` row keeps a value accumulate overwrites before the cut build has read it: crash-safe, only for rows rewritten in the seconds of build lag), proofs for the window's pending requests are generated, then building resumes | proofs generated in ms per request; the builder pauses briefly per window; local "latest complete root" lags by that pause | statements requested before the cut |
| W2 | versioned tree rows (MVCC), kept back to the last anchored cut | ≈ writes × depth node versions a window: at 1k writes/s, 10 min, depth 20, ~12M rows, ~1 GB a window [est]; a versioned `NodeStore` | statements chosen after the cut, at any retained window |
| W3 | an LSM snapshot held from cut to statement | not durable across a restart; pins compaction for minutes | short holds only |

**Recommendation: W1** (with a W3-style snapshot only inside the cut build).
On-demand statements (a credential "balance ≥ Y") read at the *next* cut,
a latency of at most one window, instead of keeping history. W2 stays an
option if the owner wants statements at past windows. The builder change: a
build's target version is `min(latest, next pending cut)`, never past it.
This makes real what `core-model.md` §9.3 already says and the code does not
do: "An attest waits for the root at its window's version."

### 5.5 The witness size: numbers and the cap
**The window kernel today** [measured: 25,989 B witness, 16 rows, two anchors,
a 1M-row map, 651 compressions, 632,800 steps]:
- per (row, anchor): **≈ 812 B**, of which the multiproof's share ≈ 665 B
  (≈ 36 B a level below the proof's shared top: 3 B a branch + 33 B a sibling
  hash, ~16 levels, plus the leaf, 1 + 4 + 50 + 32 B) and the read ≈ 145 B
  (16 B salt, the value, lengths) [est, which reproduces 25,989 within 1%];
- ≈ 20 compressions per (row, anchor) [est: 651 / 32, including the settlement's own hashing].
- So the 64 KiB argument cap holds ~40 rows at two anchors, ~80 at one.

**The path to the space root, once per statement** [est, R4]:
- rows → A: no extra level (A is the tree the rows are proven in), +10 B per opened leaf;
- A → agents_root: `36·log2(agents) + ~45 B` of proof + 41 B leaf value: **≈ 0.45 KB at
  1,024 agents**, **≈ 13 compressions** (10 branches, the leaf, its `vh`, and `S`).
- Under R2 add ≈ 0.25 KB and ≈ 8 compressions per map read.

So `proving.md` §7's "a few dozen more compressions" is ~13–21, and the bytes
are about one more row's worth.

**The real bound is the prover, not the cap.** A served witness of `x` bytes of
paths is ~`x / 36` compressions, each ≈ 35 ms and 50 MiB of proving (core model
§11.2); 1 MiB of paths ≈ 29k compressions ≈ 17 min of proving [est]. The
1M-steps-a-window target (§11.3) is ~1,000 compressions, ~30–40 KB of witness.

**The proposed change:**
- `Limits::attest` keeps capping the **caller's arguments**, the bytes a step
  passes from its memory (VOS 64 KiB, JAM 2 KiB): they are a step's effect.
- A new **`Limits::served`** caps the **host-served witness** of one attest:
  **256 KiB on both** (on JAM it arrives in the package, as JAM witnesses do; there
  the 4,096-compression kernel cap binds first, at ~150 KB of paths [est]).
  It does not count against `attest`. `witness_input = args ‖ served`, its whole
  still within 4 MiB (`proving.md:196`, A.5), which stays the record's ceiling.
- **The record:** `Attest { program, window: Option<u64>, witness_input, output }`
  now, the final proof's hash later (A.5). The served part may move to a blob
  (CAS) referenced by hash once records grow (slice 4's 4.4a path); inline is
  fine for the first milestone (`ATTESTS` 16 × 256 KiB = the 4 MiB work-result cap).
- This **corrects** `clerk-across-spaces.md:59,209` ("the witness channel lifts the
  64 KiB cap"): it does not today, and under this proposal it is the served
  channel, not the argument cap, that grows.

---

## 6. The prover worker

A node extension in the space's trust domain (`core-model.md:902-904`).
- **Consumes:** applied `Attest` records with `window = Some(w)` from the logs of
  the agents it serves, past a per-agent watermark (`proved_through: version`).
  Everything it needs is in the record: `program`, `witness_input`, `output`, and
  through the decoded `Served` header and `#[public]` prefix the `space`, `w`,
  `S_w`, `public_args`. So it computes the **statement id before proving**:
  `id = H("vos/statement/v1" ‖ program_id ‖ space ‖ io_hash)`.
- **Idempotent by statement id:** a local job table `id → state`
  (`queued | proving | proved(proof_hash) | submitted | accepted`); a restart
  rescans from the watermark; `Refusal::Repeated` from a venue counts as accepted.
- **Steps:** re-run the kernel traced on `witness_input`, check the output
  equals the record's; segments → leaves → folds → masked wrap; the proof into
  CAS; a `Proven { id, proof_hash }` input back to the agent (A.5's proof hash);
  wait for anchor(w) at the space's venue; submit; record the verdict.
- **Starts proving at once**, not after the anchor: t_prove (minutes) ≫ the
  anchor's latency (seconds), and a window that never anchors costs one wasted proof.
- **Keeps below the wrap inside the role** (A.5); the carrier audit (M2.8) covers
  its job table, its CAS writes and its logs.
- **Throughput:** `Σ t_prove(stmt) ≤ P × L` per window, or it lags without
  bound. Measured t_prove: 324 s / 9.2 GiB (window kernel, two anchors), 38 s
  (predicate). A lagging worker should report its backlog, and the space should
  not shorten L below it (context C.12).

---

## 7. A first milestone that proves the shape cheaply

**M3.2a: one agent, one window, one anchor, a test venue.**
1. `vos-anchor` crate (`SpaceId`, `RootKind`, `RootRead`, `Anchor`, `space_root`,
   the anchor digest); `SpaceGenesis` and `CreationRecord.space`.
2. R4's keyspace: `0x03` committed rows, one tree per agent, JAM's committed
   leaves aligned. Gate: a VOS agent root equals the JAM whole tree's node at
   `0x03` over the same rows (a VOS≡JAM test over the existing comparison suite).
3. X1's cut: the `Cut` marker, `cut(w)` rows, the builder's target capped at the
   next cut, `undo` rows.
4. The space root by the node directly, one leaf (no representative yet: B1 comes
   in M3.2b); the anchor signed with the node key into `vos_statement::model`'s
   policy (no chain).
5. `#[attestable] fn f(&self, #[public] …)`, explicit read set,
   `attest_at_cut` from a workflow, the served witness, `Limits::served`, the
   io-hash with public args and the root.
6. A new small test actor: one `CommittedMap<Account, Balance>`, a kernel
   "balance(account) ≥ #[public] threshold" at the cut. Prove it unmasked (28) in
   the test harness; `judge` at the model venue: accepted; then the refusals: an
   unanchored root, another window, another space, a stale `window_A`, a
   tampered row, a key outside the read set.
7. **Measure:** the witness bytes and compressions per row and for the path,
   steps, t_prove, and cut-to-statement latency.

**Then:** M3.2b the representative (B1) and several agents, with a missed close;
M3.2c the Clerk on S3; the Kreivo pallet P0 (anchors, equivocation, pruning) in
parallel once step 1's types are fixed, since it depends on nothing else.

---

## 8. Where the docs disagree, and which should win
1. `core-model.md:709-710` "No global state root on VOS" vs `proving.md` §7's
   space root: **proving wins**; core model §9.3 gains agent and space roots.
2. `proving.md:693-696` "roots differ by host" vs R4: **R4**; with it the
   "kinds equal on both hosts" rule holds by construction.
3. `kreivo-pallet.md:198` (relay blocks) vs `clerk-across-spaces.md:183-185` (JAM time):
   **neither; C3** (Unix time in the genesis), the owner's to choose.
4. `kreivo-pallet.md:105,200-204` (`Carried`) and `clerk-across-spaces.md:187-199`
   (two-anchor reads, creation stamps) vs S3: **S3** if the owner takes it.
5. `clerk-across-spaces.md:59,209` (the channel lifts the 64 KiB cap) vs the code
   (`invocation.rs:491`): **the code is right today**; §5.5's `Limits::served` is
   the proposed fix.
6. `proving.md:196` and A.5 (4 MiB) vs the 64 KiB cap: both stand under §5.5,
   4 MiB as the record's ceiling and 64 KiB as the caller's share.
7. `kreivo-pallet.md:205-208` ("read the agent root at the last cut") vs
   `proving.md:679-682` (read to the space root): **proving wins**.
8. `identity-and-authority.md` §11-§12 (anchors and the registry on JAM) vs
   `proving.md` §6 (Kreivo first): **Kreivo first**; the representative of
   §3.3 is the same role on both venues.
9. `core-model.md` §9.3 "An attest waits for the root at its window's version":
   unbuilt; §5.3–5.4 build it.
10. `core-model.md` §9.2's attestable row ("committed fields only, returned
    privately and applied by the caller", writes): slice 6 does `&self` reads
    only.

## 9. The owner's choices, in one list
1. `SpaceId` = the genesis record's hash (§1): recommended (a).
2. The clock and length (§2): recommended C3, L ∈ [2, 60] min, default 10.
3. The agent root (§3.1): recommended R4, a keyspace change on both hosts.
4. The builder and signer (§3.3): recommended B1, one node-key signature.
5. Spans (§4.4, D.12): recommended S3; `RootKind { Space }` only.
6. F2 (§4.5, D.1): recommended (c) plus (b), no `vos/io/v2`.
7. Retention (§5.4): recommended W1; W2 if statements at past windows are wanted.
8. The served cap (§5.5): recommended 256 KiB, outside `attest`.
