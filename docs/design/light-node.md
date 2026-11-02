# The light node, the personal agent, one proving path and Tor

Design, draft 3 [proposed]. The architecture of slice 8
(`slice-8-plan.md`): a light node of VOS on the user's devices, a personal
agent in a space that keeps the user's devices in step, one proving path
for every device statement, payments rebuilt on cipher-clerk as the
showcase of attestable Rust, and clients reaching a space over Tor.
- **Status:** everything here is [proposed] unless tagged [decided] (an
  owner decision, listed in §1.1 by its number, E1–E11, or cited from
  another document) or [built] (what `vos-core` holds at `543c05e07`).
- **Numbers** carry their tag: [measured] (a run, cited), [model] (the
  cell model, `proving.md` §8), [est] (arithmetic on those, unmeasured).
- **It amends:** `proving.md` §8 (the credential AIR retired),
  `identity-and-authority.md` §5–§8 (credentialed calls generalized; the
  personal space unpostponed in the form of §3), `core-model.md` §9.4
  (sealed scopes beside plaintext ones, §3.6) and §10 (forwarding,
  §3.3), and `node-api.md` §6 (the gateway's onion service). Those
  documents keep their text until the steps that change the code change
  them.

**Changes from draft 2:**
- The `Relay` actor, the shared root secret `m`, `k_sync = H(m)` and
  removal by rotation are gone. In their place: a **personal agent** per
  user in a space the user belongs to (§3), MLS among the user's devices
  for keys (§3.4), and per-device secrets as today (E2).
- Sealed scopes: the space's nodes hold the user's encrypted DAG in the
  personal agent's replicated tables and never decrypt it (§3.6).
- Calls reach an agent through any gateway: a node forwards a request for
  an agent it does not replicate (§3.3).
- Rules for device changes against a thief: an admin key behind the
  keystore's prompt, a probation for new devices, a delay with veto for
  removing another device, a recovery key (§3.5).
- A section of edge scenarios (§8), 73 of them, each with its mitigation
  or stated as a known limit.
- The plan splits: the shielded pool and the wallet (P2) move to slice 9,
  cipher-clerk v0.4 still released in slice 8 (§9, N1, the owner's word
  needed: E3 asked for P2 in slice 8).
- arti's hosting status restated from new sources (§6).

## 1. Goals and non-goals

**The owner's direction** (2026-11-02), in their words:

> I thought the library for android was a "light node" of vos that could
> later run pvm programs locally (for local only actors storing user's
> private data, a system that can be used as base for the user private
> space across devices that mostly uses the merkle-crdt sync system). I'm
> not sure I like the idea of maintaining custom circuits; the payments
> system is meant to be a rather elegant example of vos actors, it should
> show without being too complex how a user can write high level
> attestable rust code that could also run in their user's devices. I like
> the fast proof times we accomplished but it shouldn't have come at the
> cost of more crates and pieces to maintain. … I think the clients should
> connect to the ingresses via tor for privacy, arti could be included in
> the ingress so nodes don't learn anything about a user's network
> address.

And: "for the ledger design, I would also assume we use cipher-clerk even
if it means re-designing it." And, on where a user's devices meet:
"regular users don't want to setup always running server infrastructure,
spaces do have always running infra and could offer each user a personal
agent that syncs data lightly with merkle-crdt", with MLS so that "middle
men like a relay can't see the private data while allowing multiple
devices decrypt each other's messages".

### 1.1 The owner's decisions

| # | decision |
|---|---|
| E1 | Retire the credential AIR (format 44) in M1: one proving path; sign-in about 0.6 s until the levers bring it to about 0.45 s. |
| E2 | Per-device secrets, as today: a member leaf, an owner digest and a wallet per device; the personal space syncs everything but secrets; paying from another device's funds is a transfer between one's own devices. |
| E3 | Payments P1 (cipher-clerk's ledger with owner proofs, replacing `purses`) then P2 (the shielded pool and a local wallet). Draft 3 recommends P2 in slice 9 (N1). |
| E4 | No relay held by a gateway: a space has several gateways, and two devices on different ones would never meet. Each user gets a **personal agent** in a space they belong to (the home space): a small log for rare operations (the device set, MLS ordering, quotas), the space's nodes as durable ciphertext replicas of the user's DAG, and an inbox with expiring entries. |
| E5 | The personal agent is owned by a pseudonym, not by the member key. |
| E6 | The space's nodes keep full ciphertext replicas of the user's DAG (durable, a backup), not only expiring mailboxes. |
| E7 | MLS among the user's devices; data sealed under per-epoch keys from the MLS exporter, history readable by new devices through a key archive; removal is an MLS remove and a revocation of that device's leaf, with no global rotation. |
| E8 | Several home spaces allowed (CRDT replicas are free to multiply); slice 8 builds one. |
| E9 | Actors the user installs in the personal agent: later than slice 8; slice 8 builds sync and the inbox. |
| E10 | Anonymous calls (sign-in, spends) go from the device to their target over Tor, never through the personal agent, which would link them. The personal agent holds only ciphertext and what its operators may see. |
| E11 | Plan thoroughly; a Fable review of the design; the edge scenarios that could bite later worked through before code. Q5–Q12 of draft 2 are taken at their recommendations, provisionally (§9). |

### 1.2 Goals

1. **A light node, not a proving library.** `vos-device` becomes a light
   node of VOS: the PVM runtime running local actors, a local store, the
   device prover, a node-API client, merkle-crdt sync and MLS. It runs on
   the phone, inside s4's Android client.
2. **The user's private space across devices.** Local actors hold the
   user's private data (notes, credentials, contacts, the wallet later);
   the user's devices keep them in agreement with merkle-crdt, through a
   personal agent that holds only ciphertext (§3).
3. **One proving path.** Every statement a device proves is an
   `#[attestable(device)]` kernel written in Rust and proved by the general
   zkVM under the device profile. No hand-written circuit outside the
   recursion: the credential AIR (format 44) and its code are deleted.
4. **Payments as the showcase.** A short, readable pair of actors on
   cipher-clerk, whose spend is one Rust function proved on the phone
   (§5). P1, pseudonymous, in slice 8; P2, private, designed here and
   built in slice 9 (N1).
5. **Fewer pieces.** One crate in (`vos-light`), one out (`vos-device`),
   one proving path in place of two. The slice adds arti's and mls-rs's
   dependency trees, two system actors (`Homes`, `Personal`) and the CRDT
   fields; the claim is about what VOS maintains as proving and transport
   code, not a smaller dependency graph.
6. **Network privacy.** Clients reach a space's gateway as a Tor onion
   service, so no node or gateway learns a member's network address.
7. **The rule stays:** `vos` and the node know no JAM and no Kreivo
   [decided, `core-model.md` §13]; the same holds for Tor and for MLS:
   the node stores and orders opaque bytes for them (§3, §6, §7).

### 1.3 Non-goals for slice 8

- The shielded pool and the wallet (P2): designed in §5, built in slice 9
  (N1). cipher-clerk v0.4 is released in slice 8.
- A pool shared across spaces, or one whose integrity does not trust its
  space's operators (`identity-and-authority.md` §8).
- Messaging between members, in a space or across spaces. The personal
  agent's design keeps its door open (§3.10).
- Plaintext Merge scopes on nodes (`core-model.md` §9.4 as designed),
  and the Merge lane on JAM.
- Actors a user installs in their personal agent (E9).
- A second home space mirroring the first, and the protocol that moves a
  user's group to a new home when the old one vanishes (§3.9): designed,
  built later; slice 8 builds the handover between two live homes.
- A personal space shared by more than one person.
- Signature chips, recursion of device proofs, device proofs at a venue.
- iOS: nothing below the secret store is Android-only, but no step builds
  it.
- Our own anonymity network, or mixnets. Tor only.
- The extension host [decided, deferred past the slices].

## 2. The light node

### 2.1 What it embeds, and what it does not

| part | what | from |
|---|---|---|
| **PVM runtime** | the interpreter, its machine pool and inner machines; no JIT (the recompiler is x86-64 Linux only, `pvm/runtime/src/lib.rs`) | `vos-pvm` [built] |
| **the agent program** | the default agent, `vos-agent`: local actors are installed into it as into a node's agent; it gains merge dispatch, CRDT fields' storage and scopes (none exists today in `agent/default` or `agent/sdk-macros`) | `agent/default` [built, extended] |
| **a single-replica host** | refine and accumulate driven by a local loop over a local log; the actor ABI's host calls; no Raft, no leader, no peers | carved from `vos-node` (§7.1) |
| **local store** | fjall, as the node's, with small caches (8–16 MiB block cache [est]) | `vos-node`'s `store` [built] |
| **device prover** | the device profile (format 46, then 47 after the levers, §4.4), masked, `Threads::Auto` | `vos-pvm-proof` and `vos-pvm-recair`'s masked device segment, its recursion prover featured out (§7.1) |
| **node-API client** | the multiplexed `vos-api` client over any futures-io byte stream: an arti onion stream (§6), or SSH's `vos-api` subsystem as today | `vos-api` [built] |
| **sync** | merkle-crdt DAGs of the local actors' Merge fields, its `Store` over fjall, sealed before they leave the device (§3.6) | `support/merkle-crdt` [built, no dependent today] |
| **MLS** | the user's device group: mls-rs on the host side of the light node, native, never in a guest; its storage providers over fjall | mls-rs; the storage providers adapted from the `messaging` branch (§3.4) |
| **secrets** | per device, as today: the member secret from the keystore's HMAC, plus the device's admin key, sync key and MLS state, each wrapped at rest (§3.5) | `vos-device`'s `secret` [built, extended] |
| **Tor** | arti's client, one `TorClient` per process | arti (§6) |

**Not embedded:** Raft (`vos-raft`) and every group loop; ingress serving
of any kind (the light node listens on no socket; sync and calls are
outbound); the peer network (`vos-net`); the recursion prover (folds,
leaves, the wrap), venues, anchors, JAM and Kreivo clients; the
recompiler.

**What a light node is to a space:** a client. It holds no authority in
any space and replicates no Linear state (`core-model.md` §5: member
devices may replicate Merge scopes, never Linear state). It runs actors of
its own (the personal space, §3), proves device kernels of a space's
actors, and calls a space through its gateway.

### 2.2 Process model on Android

**A library behind a facility, in s4's client process** [proposed; Q5
(a), provisional].
- The light node is one Rust crate, `vos-light` (§7.1), linked by s4's
  facility cdylib (today `s4-credential`, `~/src/virto/s4-vos/credential`,
  which links `vos-device`, `vos-api` and `vos-wire` by one VOS revision).
  The facility is renamed `vos.node` and grows the operations of §7.3.
- **One runtime, one arti:** the facility owns a multi-threaded tokio
  runtime today (its `ffi` feature); the light node runs on it, and arti's
  `TorClient` is created once on it.
- **s4's SSH over the same Tor, across a C ABI:** the facility is its own
  `libs4_credential.so`, built on VOS's pinned nightly because s4's client
  cannot build on it (`s4-credential/rust-toolchain.toml`), so no Rust
  object (a `TorClient`, an async stream) crosses to the client. The
  facility opens the onion stream and hands the client one end of a Unix
  socketpair (a file descriptor through the C ABI), pumping bytes between
  it and the `DataStream`; the client runs its SSH over the descriptor as
  over a TCP socket. Not a loopback SOCKS port: any app on the phone can
  reach 127.0.0.1.
- **Lifecycle:** the light node lives while the app is in the foreground
  and for a short grace period after; background sync runs as a
  WorkManager periodic job (Android's floor is 15 minutes), which opens the
  store, bootstraps arti from its cached directory, syncs and exits. No
  foreground service, no persistent socket, no wake lock beyond a job's.
- **Every write is crash-safe:** Android kills a backgrounded process
  without notice, so the light node's local log, its MLS state and its
  push queue are each committed in one fjall batch per step (§8, D6).
- **Isolation (option):** the facility in a separate Android process
  (`android:process=":vos"`, Binder between them) keeps the prover's peak
  and the secrets' unwrapped bytes out of the UI process and lets the OS
  kill it alone. It costs a Binder interface for every operation and a
  second runtime; later, not in slice 8.

### 2.3 Memory and battery budget

| state | budget | basis |
|---|---|---|
| idle, foreground (store open, arti bootstrapped, no proof) | ≤ 96 MiB resident, of which arti ≤ 48 MiB | [est]: interpreter and pool a few MiB, fjall's caches 8–16 MiB, arti's directory and circuits (§6.4), MLS state under 1 MiB for a few devices |
| the facility's `.so` | growth from arti ≤ 10 MB, from mls-rs ≤ 2 MB | [est], to measure (plan 8.1, 8.3) |
| local actor call | ≤ 1 ms on the interpreter | 85 µs an invocation on the node's interpreter [measured, `core-model.md` §14], with the fsync of a local commit dominating |
| proving a sign-in | ≤ 1 GiB peak (target 768 MiB) | 513 MiB [measured, `proving.md` §8] |
| background sync job | ≤ 30 s wall, ≤ 1 MB down a run with nothing new | [est]: arti from a warm directory, one onion connection, one cursor query a scope and one for the device-set log |
| battery | no work while backgrounded beyond the periodic job; no persistent circuit | the design's rule, measured by the plan's PG5 |

Proving is the only heavy phase: about 0.65 s of wall time on the four
big cores at full load a sign-in [measured, `proving.md` §8: 645 ms]. A
phone that signs in twenty times a day spends about 13 s of wall time on
them [est], far below a screen-on minute.

## 3. The personal space and the personal agent

### 3.1 The shape

A user's **personal space** is two things:
- **Local actors on each of the user's devices,** run by the light node,
  holding the user's private data in Merge fields (CRDTs). Each device is
  a full replica and works offline; nothing waits on a network.
- **A personal agent** [decided, E4] in a space the user belongs to (the
  home space): an ordinary agent of that space, run by its nodes, with
  one system actor, `Personal`, installed. It orders the rare operations
  that need one order (the device set, MLS's handshakes), stores the
  user's sealed DAG nodes durably on every replica [decided, E6], and
  holds an inbox. It never holds a key that opens the user's data.

Devices sync with the personal agent, never with each other directly in
slice 8; the agent is where two devices that are never online together
meet. Any gateway of the home space reaches it (§3.3).

**Local first:** a new user's personal space starts on one device with no
personal agent at all. The agent is claimed when the user pairs a second
device or turns on backup, and the claim waits a random interval when
nothing forces it (§3.3), so a claim's time does not follow an
enrollment's.

**The first local actors:**
- the credential book: the spaces the user is a member of, each device's
  handles there, the pinned agents and methods s4's facility pins today,
  and the trees the device keeps synced (§6.7);
- the device book: labels and settings of the user's devices (the device
  set's authority is the personal agent's log, §3.5; this is its
  user-facing mirror);
- the wallet, with P2 in slice 9 (§5.4).

Each actor instance is one sync scope: one merkle-crdt DAG, so a device
syncs scopes, not the whole space (`core-model.md` §9.4's "one DAG per
sync scope"). Deterministic apply: a merge handler's effects depend only
on its operation, so every device that applies a DAG converges.
Randomness and time come from the device that issues an operation and
travel inside it.

### 3.2 What syncs, and the conflict model

- **What syncs:** each scope's DAG nodes, each a batch of CRDT operations
  with stable ids, its parents and its author (`core-model.md` §9.4).
  Never the store's rows, never proofs, never a secret.
- **The CRDT types the SDK gives, first:** `crdt::Set<T>` (an add-wins
  observed-remove set), `crdt::Map<K, V>` (last-writer-wins a key, its
  clock a Lamport counter and the author's id), and `crdt::GSet<T>`
  (grow-only). Storage-backed, as `core-model.md` §9.4 requires.
- **The conflict model** is the types' own: concurrent adds both stay, a
  remove wins only over the adds it observed, a map key's later write wins
  by (counter, author). No operation needs another device's agreement.
- **Where conflicts are real, a log decides:** the device set and the MLS
  group are ordered by the personal agent's log (§3.4, §3.5); a payment
  is decided by the space that holds the ledger. A CRDT never has to
  choose between two such outcomes.
- **Authorship:** each device signs the DAG nodes it authors with its
  sync key (§3.5), an ed25519 key drawn at install. merkle-crdt's
  `DagNode` has no author field (`support/merkle-crdt/src/node.rs`), so
  the author's key, sequence number and signature travel inside the
  payload, which is sealed (§3.6).
- **Incremental apply** [decided, `core-model.md` §9.4]: merkle-crdt's
  DAG and format are reused and its apply path rewritten to apply only
  newly fetched nodes in causal order (about 1.9 µs an operation at 1M
  operations, against 8.7 s for today's full rebuild [measured,
  `core-model.md` §9.4]).

### 3.3 The personal agent: claimed, owned, reached

**Agents exist only by an operator's command today** [built]:
`CreateAgent`, `Install` and `Grant` are operator kinds
(`node/api/src/lib.rs`, `Kind`), the operator names the replicas
(`node/host/src/node/admin.rs`, `create_agent`), no actor can create an
agent, and no agent is ever deleted. Rather than give actors that power,
the design uses a **pool of agents the operator makes ahead of time**:
- **`Homes`**, a system actor installed in the agent that already holds
  the space's credential actor (its ring and tree; an `Auth` guard reads
  the ring of the agent it guards, `node/host/src/credentialed.rs`, so
  `Homes` must live beside it). It keeps the pool: agent ids the operator
  created with `Personal` installed and handed over with
  `homes.stock(ids)`, an operator-role call.
- **The operator's keeper** (a small tool in `tools/`, holding an
  operator key) tops the pool up in bulk: creating an agent costs about
  2 s, 0.15–0.17 s each sixteen at a time [measured, `core-model.md`
  §14.1], so a pool of a few hundred hides creation from users entirely,
  and an agent's creation time says nothing about who will own it.
- **The claim** is a credentialed call, `homes.claim(keys)` under
  `#[msg(credential = Auth("home"))]`: a member proves membership
  anonymously; the pseudonym is the nullifier of scope "home" (stable for
  that device and space, unlinkable to its `member` digest,
  `identity-and-authority.md` §7). `Homes` assigns a pooled agent to the
  pseudonym and sends that agent `assign(keys)` (the claiming device's
  sync and admin keys and the recovery kit's public keys, which seed the
  device set), a message between agents; `Personal` trusts `Principal::Agent(homes)` and nothing else
  for it (the keeper configures `Homes`' agent id at install). It is
  owned by a pseudonym, not the member key [decided, E5].
- **Ownership is a lease** (prior art: a credential renewed by period,
  so leaving needs no revocation that would link the pseudonym to the
  member): `Homes` records `nullifier → (agent, until)`, `until` 35 days
  on. Any device in the agent's device set renews it with a fresh
  `Auth("home")` proof of its own. Each device has its own nullifier under
  E2, so the lease lists the device set's pseudonyms: a device that
  joins names its own nullifier to `Personal` (it computes it without a
  proof), `Personal` passes it to `Homes` by a message, and the device
  renews with proofs under it from then on. Naming another member's
  nullifier only lets that member renew this lease, which harms no one. A member removed from the space can no longer prove, the
  lease lapses, and the agent goes read-only for a grace period (30 days:
  devices may still fetch and export), then `Homes` sends `wipe`, the
  agent clears its tables and returns to the pool. **No agent is
  deleted; an expired one is recycled.** Logs compact; the store
  reclaims rows by compaction.
- **Replicas:** three by default, the space's policy; a pooled agent's
  replica count is fixed when the keeper makes it (`replace` keeps the
  count, `admin.rs`). One replica is allowed by policy for small spaces
  and stated in the device's chrome (§8, B10).
- **Its cost:** about 46 KiB and 1.6 µs/s a replica when idle, 130–140
  KiB an agent across three replicas [measured, `core-model.md` §14];
  10^4 users on a three-node space is about 0.45 GiB and 1.6% of a core a
  node [est]. An idle agent appends nothing at window boundaries
  (`node/host/src/leader/cut.rs`). Unmeasured: 10^4 agents that wake for a
  few commits an hour each, and their session sweeps (plan 8.12's gate).

**Any gateway reaches it: nodes forward** [proposed]. Today a node that
does not replicate an agent answers `Elsewhere { replicas }`
(`node/host/src/node/mod.rs`, `absent`) and a gateway retries only among
the nodes in its own configuration, so a gateway that lists none of an
agent's replicas cannot reach it. Two fixes were weighed:
- **gateways learn placement and connect to every node:** each gateway
  holds QUIC connections and keys for every node, and its configuration
  grows with the space;
- **a node forwards** a request for an agent it does not replicate to one
  of its replicas over the peer network, and relays the answer
  [chosen]. Every node already knows every agent's placement (the
  directory, `node/host/src/node/directory.rs`); `PeerMessage::Forward`
  and `ForwardCredentialed` already carry calls from a replica to its
  leader (`agent/wire/src/peer.rs`). The new message carries the
  **request as received**, before ingress, because only a replica holds
  the agent's ring to verify a credentialed call; the replica that takes
  it runs ingress as for a gateway's request. One hop more inside the
  operator's network; gateways stay as they are, and every agent, not
  only personal ones, becomes reachable through any gateway.

**Sessions:** a device's calls to its personal agent are signed by its
sync key, a client key like any other. A session expires after an hour
idle (`SESSION_EXPIRY_MS`, `agent/wire/src/defaults.rs`), so a phone that
syncs every 15 minutes in the foreground keeps one, and a background job
opens one per run (a commit, then a sweep): at 10^4 users syncing four
times an hour, about 11 session commits a second across a space [est],
small beside the transfers a node sustains. Queries need no session.

### 3.4 Keys: MLS among the user's devices

**The device group** [decided, E7]: one MLS group (RFC 9420) per user,
its members the user's devices, each a leaf whose credential is the
device's sync key and admin key (§3.5). mls-rs runs on the light node's
host side, natively; the node never runs MLS, parses it or holds its
keys. Encrypted handshakes (MLS `PrivateMessage`) and padding.

**The personal agent is the group's delivery service** (RFC 9750 §5.2.1's
"strongly consistent" kind; its prior art in the `messaging` branch's
`msg-ctl`, whose rule carries over):
- Handshakes are calls to `Personal::commit(epoch, effect, handshake,
  welcome)`, made under an active or probation device's sync key. `epoch` is the number the commit
  starts; the agent accepts it only if it is the current epoch plus one,
  refusing `EpochTaken` (another commit won) or `EpochGap`, so one commit
  per epoch, first come first served, the loser rereading and
  re-proposing.
- The agent cannot read a commit and does not validate it. A commit call
  declares its effect in clear (`none`, `add(d)` or `remove(d)`); the
  agent enforces what it can see: who may post (§3.5's states), the epoch
  rule, and that a declared add or remove names a device-set operation
  that has matured in its log (§3.5). **Devices enforce the rest:** a
  device applies a commit only if it is valid MLS and its membership
  change equals its declared effect and that matured operation.
- **A commit no device can apply is a void epoch:** its number is taken,
  and its keys are the previous epoch's (`k(scope, n) = k(scope, n − 1)`).
  MLS processing is deterministic, so every device in the same state
  reaches the same verdict; a device posting garbage (a bug, or a thief
  with the sync key) cannot stall the group, only waste an epoch, and the
  chrome names it. A device whose verdict differs from others' is in a
  fork (§8, B4).
- **Never ahead of the log:** a device merges its own pending commit only
  once the agent accepted it at that epoch (mls-rs's pending-commit
  API, applied on confirmation), the first cause of forks in deployed MLS
  (§8, A9).
- **Retention:** the agent keeps handshakes for 180 days and the newest
  group info; a device offline longer re-pairs (§8, A5). Retention also
  bounds what a "harvest now, decrypt later" adversary can take from a log
  kept by operators, if they honour it (§8, F1).

**Epochs are named by the log:** epoch `n` is the state after the `n`th
accepted commit, void ones included (a device maps the agent's numbers to
MLS's own epoch counter, which a void commit does not advance). Every device that follows the log reaches the same `n`
for the same commits; an operator that shows two devices different
commits for one `n` gives them different keys, which every sealed
envelope then exposes (§3.6).

**The data keys** [decided, E7; prior art: Keyhive's causal keys,
any-sync's key chain, p2panda's data scheme]:
- `k(scope, n) = MLS-Exporter("vos/personal/scope", scope_id, 32)` in
  epoch `n`. One key a scope and epoch, so delivery order does not
  matter (a DAG node is opened by its epoch's key whatever arrives
  first), unlike MLS's per-message ratchet, which a CRDT's unordered,
  repeated delivery would break. When mls-rs offers the extensions
  draft's Safe Exporter (a secret per component, deleted once used), the
  derivation moves to it with `scope_id` its component; the scheme is
  the same.
- **The key archive** of a scope: every past `k(scope, ·)` the scope
  still reads, a union indexed by epoch, sealed under the current
  epoch's key and pushed by the device that commits a new epoch, or by
  any device that finds it missing (one envelope a scope an epoch; 32
  bytes an epoch; duplicates are harmless). A new device derives the
  current key from its Welcome and opens the newest archive; archives are
  monotone, so two archives at different epochs union (§8, C9).
- **No forward secrecy for history, by design:** the personal space must
  let a new device read the past, so whoever holds the current epoch's
  key holds every older one a scope keeps. Forward secrecy is offered
  only by a **history horizon** a scope may set (say, the inbox's 30
  days): keys older than it leave the archive and the agent deletes the
  envelopes sealed under them (§3.6). Post-compromise security holds for
  new data: a removed device learns no key after its removal.
- **The admin key and the archive:** the archive lives on a device under
  its unlock-bound key, as the materialized data does (§3.5); a stolen,
  unlocked phone exposes both, and that is stated (§8, A3).

**The suite:** MLS ciphersuite 1 (X25519, AES-128-GCM, SHA-256,
Ed25519) unless mls-rs offers a maintained hybrid post-quantum suite by
the step (plan 8.3 checks); a later change is a ReInit into a successor
group, its archive resealed, old envelopes left under their old keys,
never two suites in one group (§8, F1).

### 3.5 Device secrets and the rules for changing devices

**Per device** [decided, E2]:

| secret | what for | wrapped at rest under |
|---|---|---|
| the member secret `s` of each space | membership proofs (auth, owner) | none: derived at each use from the keystore's HMAC over the space's handle, behind the user's prompt, as today [built] |
| the **admin key** (ed25519) | signing device-set operations at the personal agent: add, remove, veto, approve | a keystore key requiring strong biometric authentication at every use (BiometricPrompt with `BIOMETRIC_STRONG` alone, no PIN fallback; StrongBox when present). A device without a strong biometric is a **sync-only** device: paired and removed by others, administering nothing |
| the **sync key** (ed25519) | the device's client key at the personal agent (pushes, fetches, commits); signing the DAG nodes it authors | a keystore key bound to the device's unlock, no per-use prompt: a background job has no user to ask |
| the MLS state (leaf keys, group secrets, the key archive) | sealing and opening envelopes, processing commits | the unlock-bound key, kept out of OS backups (§8, A11) |

**Membership authority is the admin key's,** behind the prompt.
- **Signed end to end:** a device-set operation (add, remove, veto,
  approve, handover, collect) carries the admin key's ed25519 signature
  over `(agent, operation, the device-set log's head)`, and it is sent as
  a call under that admin key's own session. The agent checks the session
  at ingress and stores the signature; **every device verifies the
  signature itself** before acting on the operation. The operators run the
  ingress and could append anything to the agent's log, so a device
  trusts an operation only by its signature, never because the log holds
  it (§8, B6). No guest verifies a signature.
- **Time has a floor on the device:** a device acts on a matured
  operation only once its own monotonic clock has seen the operation for
  the delay too (a device offline when it was posted waits the delay from
  when it learns of it), so operators who advance the agent's batch time
  cannot shorten a delay (§8, B7).

A thief holding an unlocked phone, the app open, has the sync key and the
MLS state, so can read what the phone reads; without the owner's
biometric they cannot add a device, remove one, or veto. The admin key
is unwrapped only after the prompt, for a short validity window; the
user's biometrics changing invalidates the wrapping key (Android's
`setInvalidatedByBiometricEnrollment`), and the device then asks another
device, or the recovery key, to register a new admin key (§8, A12).

**The device set** is a table in `Personal`, written only through its log:
each device's sync key, admin key, a sealed label, and a state:

| state | may | how a device enters it |
|---|---|---|
| **probation** (72 h) | sync; commit MLS updates of its own leaf | added by an active device (§3.8) |
| **active** | everything below | probation's end |
| **removing** (72 h) | sync, until removed | another device's `remove` |
| **removed** | nothing; its frontier recorded | the delay's end, or an immediate removal |

- **Adding is immediate, then probation:** pairing (§3.8) needs the
  adding device's admin key; the new device syncs at once, but for 72 h
  it can neither add, remove nor veto, and any active device removes it
  at once. Exposure does not grow by it: a device that could pair already
  held everything the new one receives.
- **Removing another device is delayed:** `remove(d)`, signed by an
  active device's admin key, matures after 72 h unless any other active
  device vetoes it. **A device cannot veto its own removal,** and a
  device being removed cannot remove others. It is immediate when two
  active devices other than its target sign it; the recovery key's
  operations have their own delay (below).
  The delay is measured by the agent's batch time, never a device's clock.
  Every device is told through the inbox (§3.7).
- **Self-removal is immediate.**
- **The removal frontier** (prior art: Keyhive's open problem of
  backdated operations): when a removal matures, the agent records, for
  each scope, the position of the removed device's last accepted
  envelope (§3.6). An envelope authored by a removed device is valid only
  at or before its frontier. Seal-at-push (§3.6) already keeps it from
  sealing under a later epoch; the frontier keeps it from pushing under an
  old one through another path.
- **Then MLS follows the log:** a matured add or remove is carried out
  by the next commit that names it, posted by any active device; devices
  check that the commit's membership change equals the matured
  operation.
- **Probation devices may commit their own updates** (MLS's update of
  their own leaf, for post-compromise security), nothing else.

**The recovery key** [proposed; prior art: Signal's recovery key, Apple's
recovery key and security delay]:
- 32 random bytes shown once as a 24-word phrase, with the home space's
  handle and the personal agent's id beside it (a recovery kit), drawn
  when the personal agent is claimed. Its public halves (ed25519 for
  signing, X25519 for sealing) are registered in the device set as a
  **recovery entry**, not an MLS leaf: it is never online, so as a leaf
  it would be a stale one that every commit encrypts to.
- **What it seals:** every 30 days, and at each device change, an active
  device pushes a recovery envelope (HPKE to the recovery key) holding
  every scope's key archive and scope ids, into a scope of its own whose
  id derives from the recovery public key, so devices do not try to open
  it.
- **What it may do:** any device-set operation, but **after a 7-day delay
  that any active device may veto,** and immediately only together with
  an active device's admin signature. A leaked phrase therefore gives the
  user a week's notice, not the attacker the space; when every device is
  lost, nobody vetoes, and the delay costs only time. Its operations are
  signed end to end like a device's.
- **Restore** (all devices lost, §8, D1): a fresh install enrolls in the
  home space as a new member device (the registrar's ordinary path,
  §3.8), reads the kit, signs a query and calls with the recovery key
  (a client key the agent knows), opens the recovery envelopes, removes
  every old device, starts a new MLS group as its sole member (the old
  group has no reachable member to commit; the agent's control log
  restarts under the new group by the recovery key's `regroup`, delayed as
  its operations are), reseals the archives under the new group, and has its own "home" pseudonym added to the lease: the
  recovery key calls `Personal::reclaim(nullifier)` (the device computes
  its own nullifier without a proof), delayed as above, and at maturity
  `Personal` tells `Homes` to add it; the device renews with a proof under
  it from then on.
- **Not strongly nudged but required:** a claim needs a recovery kit; the
  user may store it, print it or decline to see it again, and the chrome
  says losing every device and the kit loses the personal space.

**What the personal agent's log shows the operators:** the device count
and its changes, each device's two public keys, the times of device
changes and commits, and the recovery entry's existence. Not the labels,
not the data, not which member owns the agent (§3.10).

### 3.6 Sealed scopes: storage and sync

**An amendment to `core-model.md` §9.4:** a sync scope is either
- **plaintext** (§9.4 as designed: nodes validate and apply operations,
  author chains, epoch nodes emitted by Linear steps, the Linear-emitted
  chain): not built in slice 8; or
- **sealed** [this design]: the scope's DAG nodes are ciphertext to every
  node; devices validate (signatures, the device set, frontiers) and
  apply; nodes store, order and serve envelopes, and enforce what they
  can see (who may push, the epoch, quotas). `core-model.md` §9.4's authorization rule
  runs on the devices, against the personal agent's device-set log in
  place of epoch nodes: a node author is valid in epoch `n` if its sync
  key was in the device set (active or probation) when the envelope was
  accepted, and within its frontier if later removed.

**Where the envelopes live: the personal agent's replicated tables,
written through its log** [proposed; N2]. A node cannot apply what it
cannot read, so `core-model.md` §9.4's node machinery (merge dispatch on replicas,
gossip between nodes) would do nothing for a sealed scope; what a sealed
scope needs is durable, replicated storage and an atomic check of the
push's epoch against the device set and the MLS log. The agent's log
gives both, and every push's cost is a commit at a personal rate (a push a
minute while the app is open, one a background job [est]). The
alternative, a node-side Merge store replicated outside Raft, needs a new
peer protocol and still consults the log for the epoch; it is kept for
plaintext scopes.

**An envelope:**
```text
envelope  = header ‖ sealed
header    = { scope: [u8; 16], epoch: u64, len_class: u8 }   (clear; AAD)
sealed    = XChaCha20-Poly1305(k(scope, epoch), nonce, Padmé(body), AAD = header ‖ agent id)
body      = { author: sync key, seq, signature, parents: [cid], ops, view }
view      = { log_index, log_chain }   (the writer's view of the agent's control log)
```
- `scope` is an opaque id the devices derive from the scope's name and a
  group secret (`MLS-Exporter("vos/personal/scope-id", name, 16)` at the
  group's first epoch), so the operators see that scopes exist, not what
  they are.
- **No structure in clear:** parents, author, CIDs and operations are
  inside; the operators see sizes (padded, Padmé: at most 12% overhead),
  times and scope ids, not the DAG's shape (prior art: Beelay leaves
  heads and parent hashes in clear, and its server sees the shape).
- **An envelope's id** is the BLAKE2b-256 of its bytes, so a retried
  push is deduplicated (§8, A10); a node's CID, over its plaintext,
  stays inside.
- **Size:** at most 60 KiB an envelope, under `cap::VALUE` and
  `cap::REQUEST` (64 KiB each, `agent/wire/src/abi/cap.rs`); a larger DAG
  node or checkpoint is chunked into a chain of envelopes. A push call
  carries 64 KiB of arguments: one full envelope, or several small ones;
  pushes pipeline (16 in flight on one channel), each a step of the
  agent. A blob kind for
  large objects through the node's existing blob store is a later lever,
  taken when a measured checkpoint makes chunking the bottleneck (plan
  8.16's gate).

**Seal at push, not at write** [prior art: DCGKA's dominating update]:
a device keeps its unsynced operations in its local store, encrypted at
rest under its own key, and seals them only when it pushes, under the
epoch it read from the agent just before. `Personal::push(scope, epoch,
envelopes)` refuses an epoch other than the current one (`StaleEpoch`),
and the device reseals and retries. So a device that wrote offline
while another was removed cannot hand the removed one new data under an
old key.

**Sync is a cursor, not a walk:** the agent numbers a scope's envelopes
in the order it accepts them; `Personal::since(scope, position)` is a
query returning up to 64 KiB of envelopes from a position, so a device
catches up in a few pipelined queries (16 in flight on one `vos-api`
channel) instead of a round trip a DAG level. Positions reveal only the
arrival order the operators see anyway. Each device keeps, per scope, the
last position applied and the set of its own envelopes accepted; nothing
like set reconciliation is needed while one agent holds the order.

**Fork and rollback detection** [prior art: XMTP's commit logs, SUNDR's
fork consistency]: the agent's **control log** is its device-set
operations and handshakes in log order. Each device keeps the highest
`(log_index, log_chain)` it has seen (`log_chain` a hash chain over the
control log's entries, signatures included) and refuses a log that is
shorter or diverges. Every envelope carries its
writer's view inside; a device that opens an envelope whose view
conflicts with its own raises a fork alarm. An operator who rolls the
agent back, or shows two devices two histories, is detected the next time
either device reads the other's writes. Nodes sign nothing a device can
show a third party, so detection is not proof (§8, B4).

**Checkpoints and compaction:**
- a checkpoint is a scope's state at a frontier, sealed like any envelope
  (chunked), carrying the frontier's CIDs inside; boundaries are
  deterministic (every 4,096 operations, by the operations' count in the
  DAG's causal order) so two devices checkpointing at once produce the
  same state;
- a new device fetches the newest checkpoint and the envelopes after it;
- **garbage collection is a log operation with a delay:**
  `collect(scope, position)` drops envelopes before `position` once a
  checkpoint covering them has been acknowledged by a second device and
  72 h have passed without a veto, so a rogue device cannot erase
  history alone.

**Quotas** (per agent, the space's policy; enforced by `Personal` in
`push` and `commit`): bytes held (say 256 MiB), envelopes a day,
handshakes a day, inbox slots; a refused push leaves the device's queue
intact and the chrome says why. Per agent, not per device: a quota per
device would let the operators tell devices apart by their limits.

**Background sync:** a WorkManager job, in a random minute of its window
(jitter), pushes queued operations, reads the device-set log and each
scope's cursor, applies, and stops. Personal-agent traffic goes only over
Tor, on its own circuits (§6.2): never the clearnet fallback, which
would hand the operators the device's address beside its pseudonym.

### 3.7 The inbox

A table in `Personal`, keyed by `(expiry, id)`, swept by a timer
workflow that deletes expired rows in batches (no expiring rows exist in
the node today; `keys::due` serves only system rows,
`agent/wire/src/keys.rs`).
- **Who writes** in slice 8: the user's devices (device-set
  notifications: "a removal of the phone was requested"), the agent
  itself (lease and quota warnings), and a **pairing slot's** holder
  (§3.8). Others' messages (member messaging) wait for slice 9, with
  sender tokens or proof of work against spam (§8, C7).
- **Who reads:** the user's devices, by their sync keys; a pairing slot
  is read by its two parties.
- Items are sealed to the device group, or to a pairing slot's key; the
  operators see counts, sizes (padded) and times.
- **Bounds:** 64 items, 16 KiB each, a TTL of at most 7 days, pairing
  slots 10 minutes and single-use.

### 3.8 Pairing a new device, and its memberships

1. **The existing device** (A, active) opens a pairing slot at its
   personal agent (`Personal::pair_open`, signed by A's admin key behind
   the prompt): a random slot id, a slot key the agent will accept posts
   under, a 10-minute TTL. A shows a QR code: the home space's onion
   address and the agent's id, the slot id and key, A's ephemeral X25519
   key, and a 128-bit code.
2. **The new device** (B) scans it, draws its sync key, admin key and an
   MLS KeyPackage, and runs `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b` with A
   through the slot, the code its pre-shared key. The code never crosses
   the agent, so an agent that substitutes keys fails the handshake.
3. **B sends** its two public keys and its KeyPackage over the Noise
   channel. **A adds B:** `Personal::add(B's keys)` signed by A's admin
   key, then the MLS commit adding B with B's Welcome. B is in probation
   (§3.5).
4. **B joins:** processes its Welcome, opens the key archives (pushed
   with the commit), fetches each scope's newest checkpoint and the
   envelopes after it, and applies.
5. **B's memberships** (E2: each device has its own secrets): the
   credential book lists the spaces the user belongs to. In each, B needs
   its own leaf. A asks the space's registrar for it:
   `registrar.enroll_device(member(s_B))` under
   `#[msg(credential = Owner)]` from A, which the registrar's policy
   admits up to a number of devices per member. The registrar thereby
   knows that A's and B's leaves are one member's; it already knows each
   member's identity, and the tree still hides which leaf proves.
   - **`once` scopes and several leaves:** a member with three device
     leaves has three nullifiers in a `once` scope (a vote). The design
     keeps one **person leaf** per member in a second ring for agents that
     use `once` (§8, L6; N3).
   - P1's accounts are per owner digest (per device); a payment from
     "the user" comes from one device's account, and moving funds between
     one's devices is a transfer the operators see (§8, L4).

**Removing a device** is §3.5's `remove`, its MLS commit, and, in each
space, `registrar.revoke_device` from another of the user's devices. A
lost device's notes in P2 are slice 9's question (N4).

### 3.9 Home spaces: several, a handover, and a lost home

**Several homes** [decided, E8: allowed, one built]. A second home is
another personal agent holding the same envelopes, a replica the devices
push to as well. **Exactly one home orders the group** (the handshake
home): two logs ordering one MLS group would fork it. A second home
mirrors the first's handshakes, pushed by devices, which also gives
devices a second view against which to check the first for equivocation.
Mirroring is built after slice 8.

**Handover** (built in slice 8, plan 8.17): moving the user to a new
home while both are live.
1. A device claims an agent in the new space (§3.3).
2. It posts `handover(new home, new agent)` to the old agent, signed by
   an active admin key, delayed and vetoable as a removal is (72 h).
3. At maturity, the next commit on the old agent carries a group-context
   extension naming the new home and that log position; the new agent's
   log starts from that commit's hash, and devices accept the new home
   only from it.
4. Devices push every envelope they hold to the new agent; the old agent
   goes read-only, and its lease is released.

What the old operators held they keep; deletion there cannot be
verified, so everything they held stays, to them, held.

**A lost home** (the space vanishes, or turns hostile):
- **slice 8:** devices are full replicas, so nothing is lost but the
  agent. The user claims an agent in another space, creates a new group
  from one device, pairs the others again (QR), and pushes everything:
  pairing and claiming are all it takes.
- **later:** a successor group with a resumption PSK bound to the last
  agreed epoch, so other devices join without a QR; the PSK alone would
  let a stolen phone found one too, so the admin key and the probation
  rules apply to it.

### 3.10 What the operators see, and the door to messaging

**The home space's operators see:**
- that a personal agent exists, when it was assigned (to a pseudonym),
  its lease renewals and its device count over time;
- the device set's public keys and the times of every device change,
  commit, push and fetch (Tor hides from where);
- envelope counts and padded sizes per opaque scope id;
- the recovery entry's existence.

**They do not see:** the data, the scopes' names, the DAG's shape, which
member owns the agent, or the devices' addresses. They can withhold,
delay, roll back or equivocate, which devices detect (§3.6), and delete,
which devices survive (they are full replicas).

**Linkability rules** [decided, E10]:
- sign-in, owner and spend proofs go from the device to their target,
  never through the personal agent;
- the personal agent's traffic has its own Tor isolation group, on its own
  jittered schedule, never triggered by the member's own activity;
- the sync key and the admin key are used nowhere else, and the member
  key signs nothing the personal agent stores;
- no push-notification token (FCM, APNs: tied to a Google or Apple
  account and seen by whoever pushes) is given to any space; devices poll.

**Messaging later** (slice 9): a member-to-member group's delivery
service is an agent, as the personal agent is for the device group; the
user's devices would appear as one member through MLS virtual clients (the
device group as the emulation group), so other members see one leaf per
person, not one per device. The device group built here is that emulation
group; nothing in slice 8 needs to change for it.

## 4. One proving path

### 4.1 What is retired

The credential AIR, format 44 [built, `proving.md` §8], proves auth, owner
and the joint statement in 0.16–0.18 s on the Fairphone 6 [measured, `proving.md` §8]
with proofs of about 0.2 MB, verified in about 2.0 ms [measured,
`node/SECURITY.md`]. It is a hand-written circuit over the recursion AIR's
`p2` and `qm31`: every statement change is a circuit change, a re-pin and
a new fixture. It is retired, and every device statement becomes a device
kernel [proposed, the owner's direction].

**Deleted** (at `543c05e07`, about 3,200 lines and one wire enum's arms):
- `pvm/proof/recair/src/credential/` (`mod.rs`, `circuit.rs`: 609 lines);
- `pvm/proof/recair-air/src/credential.rs` and `masked/credential.rs`
  (256 lines);
- `pvm/proof/final-verifier/src/credential.rs` (352 lines) and the
  `credential-bytes` feature;
- `pvm/proof/recair/tests/credential/` (1,331 lines) and the examples
  `credential_timing`, `credential_stress`, `credential_ingress` (525
  lines);
- the fuzz target `credential_verify_bytes`;
- in `vos-device`: `prove_auth`, `prove_owner`,
  `prove_membership_and_payment`, `verify`, `verify_joint`,
  `CredentialProof`'s format-44 path, `PEAK_BYTES`' credential figure;
- in the node: ingress's format-44 branch and its constants;
  `vos_pvm_proof::format::CREDENTIAL_PROOF` (44 leaves the registry; the
  numbering itself is reset before the first release, `open.md`,
  "Repository");
- the phone bench's credential cases (`tools/phone`), PG1's gate.

**Not deleted:** the recursion AIR's `p2` and `qm31` (the folds and the
wrap use them); the Poseidon2-M31 compression, `0x402` and its chip; the
credential actor and its tree; `H_io`; the device format and its chips.

**No crate disappears by retiring 44 alone.** The crates go with §7.1's
consolidation: `vos-device` folds into `vos-light`, and the light node
links the zkVM and its masking without the recursion's leaves, folds and
wrap (§9 Q9).

### 4.2 Every device statement a kernel in an actor

Sign-in, ownership and spending are `#[attestable(device)]` methods,
each a short Rust function in the actor whose state it concerns:
- **auth** and **owner** in the credential actor (`vos-credentials`), the
  stock kernels every space gets with it;
- **spend** and **join** in the payments actor (§5);
- any actor's own, under the same rules.

```rust
// vos-credentials, beside the tree it proves membership of. Today only
// `auth` exists as a kernel (the `device` test actor's, hand-lean); `owner`
// is new.
#[attestable(device, reference = reference::auth)]
pub fn auth(path: &Path, secret: &Secret, #[public] claim: &AuthClaim) {
    let member = Tag::Member.hash(secret);
    assert_eq!(path.root(Tag::Leaf.hash(&member)), claim.map_root);
    assert_eq!(Tag::Nf.hash(secret).hash(&claim.scope), claim.nullifier);
}

#[attestable(device, reference = reference::owner)]
pub fn owner(secret: &Secret, #[public] claim: &OwnerClaim) {
    assert_eq!(Tag::Owner.hash(secret), claim.owner);
}
```

Each claim struct ends with the call's `binding` (§4.3), which the kernel
carries without reading, as auth's does today.

**High-level code at the lean kernel's cost.** Today's auth kernel takes
1,722 steps because it is written by hand: arguments decoded in place by
`InPlace`, word loads through inline assembly, the path walked in one lane
(`agent/test-actors/device/src/lib.rs`); the same statement written
plainly took 18,733 steps [measured, `proving.md` §8], about ×11, which the
cell model puts at about 3 s on the phone [model]. The tricks move into the
SDK and the toolchain, so the code above is what a developer writes:
- **in-place arguments by the macro:** a device kernel's arguments of fixed
  size (`Digest`, `[Digest; N]`, `Path`, plain structs of them) are decoded
  as references into the argument pages, never copied; the macro lays
  them out siblings-first so they are page-aligned (what `InPlace` and
  `auth_arguments` do by hand today);
- **`vos_sdk::p2`:** `Digest`, `Tag`, `Tag::hash`, `Digest::hash` and
  `Path::root` over `0x402`, written once, lean (the lane walk with
  selects, no branch on the slot's bits), and shared by every kernel and by
  cipher-clerk through its hash trait (§5.3);
- **word loads from the compiler:** the guest target built with LLVM's
  `unaligned-scalar-mem` feature, so an unaligned `u64` load is one `ld`
  (the PVM serves unaligned accesses; today the target's own unaligned
  reads go byte by byte, which is why the kernel uses assembly) [est: to
  measure first, §9 Q7]. A target change rebuilds every guest ELF
  (`pvm/guest/riscv64em-vos.json`), so every pinned blob and program id
  moves: measured on a branch in M0, landed with M2's re-pin;
- **a gate:** the SDK-form auth kernel within 1.15× the hand-lean kernel's
  steps, and the spend kernel's steps recorded beside a hand-lean bound.

### 4.3 What the node checks at ingress

**Credentialed calls generalize to proven calls.** Today a credentialed
call carries a `CredentialPublic` (`Auth` or `Owner`) and a format that
picks the circuit; ingress knows each kind's checks
(`identity-and-authority.md` §5, its 17 checks). Proposed:
- **The request** keeps kind `0x0104` and its envelope (instance, method,
  arguments, nonce, expiry, format, proof) and replaces `public:
  CredentialPublic` with `claim: Vec<u8>`, the kernel's public arguments
  in their SCALE encoding. The format is 46 (or its successor) alone.
- **The guard names the kernel:** `#[msg(proven = auth)]`,
  `#[msg(proven = spend)]`, naming a device kernel of this actor or of the
  agent's credential actor. `#[msg(credential = Auth("login"))]` and
  `#[msg(credential = Owner)]` stay as the SDK's sugar for the stock
  kernels, so purses-style code reads as today.
- **Ingress's generic checks,** in order: the frame, the decode, the
  agent, the space, the format, the sizes, the expiry, the method and its
  guard; then **the binding**: the claim's last field is `C(T(binding),
  W(b))` of this request (the binding digest of §5, its `program` the
  kernel's device program id and its `kind` dropped, the program naming
  the statement); `b` not recorded; a verification slot; then the proof,
  against the device program the node computed from the installed kernel,
  with the io-hash `H_io` of `(claim, empty output, no roots)`.
- **Kernel-specific checks:**
  - **the stock kernels' stay in the node's Rust,** as today
    (`node/host/src/credentialed.rs`, over the replica's rows): auth's
    scope, its root in the ring and fresh, and `once` (whose nullifier is
    auth's claim field); owner's none (the handler compares `ctx.owner()`
    with the live row). Their refusal codes are kept;
  - **an actor's own kernel's run at apply only,** in its handler (the
    pool's anchor in its ring and its nullifiers unseen, §5.5). There is
    no pre-check at ingress: that would need a host-to-guest entry point
    run on an executor before the verification slot, a new cost an
    attacker chooses. A proof for a spent nullifier therefore costs a
    verification, bounded like any other by the PoW and the budget;
  - `once` is defined for auth's guard alone.
- **The origin** a proven call logs: `Anonymous { scope, nullifier }` for
  auth, `Owner(digest)` for owner (both as today), and a new
  `Kernel { program }` for any other kernel (codec index 7: `Principal`
  ends at 4 today, `Identity` 5 and `Jam` 6 reserved; not "Proven", which
  `Input::Proven`, index 9, already names). **The log carries the claim:**
  `Input::Credentialed` (index 10) takes the claim's bytes, capped (1 KiB,
  a spend's about 240), in place of auth's `root`, since apply's freshness
  check and the handler's typed argument both read it; a log entry grows
  by at most the cap.
- **Verification cost and denial of service:** a device proof verifies in
  about 11.7 ms on one x86 core and a wrong PoW is refused in 8.0 ms,
  against 2.0 ms and 0.7 ms for format 44 [measured, `node/SECURITY.md`]:
  the same budget admits about a sixth as many proofs a second. A wrong
  *interaction* PoW, checked before the composition, already costs 5.8 ms
  [measured], so moving the PoW earlier saves about 2 ms, not 7; the bulk
  is the decode, its canonical re-encoding and the verifier's setup, to be
  profiled before any target is set (plan 8.5). The levers of §4.4 shrink
  the columns the verifier reads and so its time. Over Tor, the gateway's
  onion-service defences replace per-address limits (§6.6).

### 4.4 The program-id model, and the cost

**The device program** [built, `proving.md` §8] is computed from the installed kernel
alone: its chips (what its code reaches), each chip's log size from a
reference run, and the preprocessed root over its code, data, regions,
permissions and entry registers; its id the BLAKE2b-256 of a domain, the
format, the chips, the sizes and the root. Today only auth's reference
(`auth_reference`) exists, hard-wired in `vos_pvm_recair::device`.
- **Generalized:** `#[attestable(device, reference = path)]` names a
  function returning the kernel's reference arguments (a public, valid
  witness; the credential actor's `auth_reference` and `owner_reference`,
  the pool's `spend_reference`). The derivation records it; the leader
  computes the program at install by running it, as auth's today; a
  replica that did not install computes it at the first proof naming the
  kernel, as today.
- **Sizes and witnesses:** every chip is padded to the program's sizes, so
  a proof's shape is the program's whatever the witness. A witness whose
  run needs more rows than the reference's fails to prove (an error on the
  device, never a different proof shape); branch-free kernels avoid it,
  and a kernel that branches declares `headroom = k` (each size raised by
  `k` powers of two). The testkit's `device_fits` property test runs
  random witnesses against the reference's sizes.
- **Which kernels see a secret:** the light node puts a member secret or a
  spending key only into kernels whose device programs it computes from
  code it ships (the stock `auth` and `owner`; cipher-clerk's spend in
  slice 9), and refuses to prove one of them if the space's installed
  program differs from its own. A kernel whose bytes a space serves may
  take only the user's public data: otherwise a space could install a
  kernel whose public claim is the secret itself (§8, G2).
- **Pins:** the binding names the program id, so a proof of one kernel
  authorizes nothing under another; a new kernel version is a new id, its
  space's install the only governance step. No venue pins device ids
  (device proofs are not folded, `proving.md` §11, "Device proofs are not folded").

**The cost** (the Fairphone 6, automatic threads):

| statement | today, format 44 | today, format 46 | with the per-program CPU | and word-level memory |
|---|---|---|---|---|
| sign-in (auth) | 164–170 ms [measured] | 581–645 ms, 0.88–0.98 MB [measured, `proving.md` §8] | about 554 ms [model] | about 450 ms [model] |
| ownership (owner) | 161–179 ms [measured] | 0.30–0.40 s [est]: every chip at its 2^10 floor, the CPU half auth's | 0.27–0.36 s [est] | 0.25–0.33 s [est] |
| spend, 1 in 2 out | none | 0.9–1.3 s [est] (§5.7) | 0.8–1.1 s [est] | 0.7–0.95 s [est] |

- **The price of one path:** sign-in costs about 3.5× today's credential
  proof in time and 4.5× in bytes, payment authorization about 2× in time.
  Within the owner's requirement (`proving.md` §1: under a second on a
  2023-or-later phone), not within PG1's 250 ms, which retires with format
  44. Between format 44's retirement (M1, E1) and the levers (M2),
  sign-in proves at 0.58–0.65 s.
- **The levers are the next device format** [decided: the
  per-program CPU and word-level memory are the next device format's]: both change
  the AIR, so they land together as one device format (47), with one
  re-pin of the device programs. The model's 450 ms scales a 607 ms run;
  from the 645 ms gate run it is about 478 ms, so a 0.5 s gate has about a 4%
  margin (the plan sets 0.55 s).
- **Not the node's segment format in slice 8:** a new segment format
  means a new leaf, new folds and a new wrap, and new venue and
  `MANIFEST` pins, far more than a re-pin. The per-program CPU for node
  segments is a later step of its own.

### 4.5 What the formats become

| format | today | after slice 8 |
|---|---|---|
| 39 (final, masked wrap), 41 (node segments) | admitted | kept as they are |
| 44 (credential) | admitted at ingress | retired |
| 46 (device) | admitted for auth's statement | admitted for every device kernel; superseded by 47 |
| 47 (device, per-program CPU, word-level memory) | none | the device format |


## 5. Payments as the showcase

P1 is built in slice 8; P2 (§5.2's second stage, the pool and the wallet)
is designed here and built in slice 9 [proposed, N1], cipher-clerk v0.4
(§5.3) released in slice 8 so that slice 9 starts from it.

### 5.1 The shape

Two actors and one library:
- **`Payments`**, a public actor in the space: cipher-clerk's double-entry
  ledger (transparent accounts held by owner digests) beside a shielded
  pool (note commitments, nullifiers, encrypted notes). It never sees a
  note's value or owner.
- **`Wallet`**, a local actor in the user's personal space (§3): the notes
  the user's devices hold and the nullifiers they have spent, synced across
  the devices, each note marked with the device whose key spends it (E2).
  It plans spends; the light node builds and proves them with the
  device's key, which never enters the actor's state.
- **cipher-clerk**, redesigned (§5.3): the ledger kernel, and a shielded
  module whose spend rule is one `no_std` Rust function, the same function
  the device kernel runs and the reference implementation checks.

**The spend is the showcase:** the kernel the phone proves is
`cipher_clerk::shielded::check` called from a five-line method. There is no
circuit: the rules (owner binding, nullifier derivation, membership,
Faerie Gold, value balance with 64-bit range checks as `checked_add`) are
ordinary Rust, and "the reference check is bit-identical with the
circuit" (cipher-clerk's Phase 3 entry criterion 11) holds by construction.

### 5.2 Staged: pseudonymous first, then notes

1. **P1, pseudonymous** [slice 8, M1]: `Payments` is cipher-clerk's
   L0 kernel in an actor, its user accounts held by `Owner` digests,
   `transfer` under `#[msg(credential = Owner)]` proved by the stock
   `owner` kernel. It replaces the `purses` test actor (a hand-rolled
   ledger) with cipher-clerk's, and keeps today's privacy: a public payer,
   amounts and payees in clear to the operators, custodial `rekey`.
   Accounts are per owner digest, so per device (E2): a payment comes from
   one device's account, and moving funds between one's devices is a
   transfer the operators see linking the two (§8, L4).
2. **P2, private** [slice 9, N1]: the shielded pool and the
   wallet. Payer, payee and amount hidden from the operators and every
   other member inside the pool; deposits into and withdrawals from the
   pool visible as transparent legs.

### 5.3 cipher-clerk, redesigned

cipher-clerk (`~/src/virto/cipher-clerk`, v0.3.0 at `0235d06`; VOS pins
tag `v0.3.0`, `Cargo.toml:241`, and uses its codec, `Account`, `Layer`,
`Value` and `settlement::window` in the `accounts` and `window` test
actors) has a sound transparent kernel (its tests are most of the 315 the
workspace runs with every feature; about 114 are the privacy modules') and a notes
prototype that is not for value (`STATUS.md`): Pedersen commitments on
Ristretto, a BLAKE2b nullifier, a pool that rebuilds its tree on every
insert (F21), no spend proof, and a `pvm-precompile` feature that routes
scalar multiplication to a Ristretto chip VOS removed as unsound
(`core-model.md` §11.2), pinned by a git dependency on VOS at
`9f5337fb`. Its own Phase 3 entry criteria (`docs/viability-plan.md`)
name what a private tier must settle; this design answers them.

**What changes, released as v0.4.0 (breaking) from cipher-clerk's own
repository:**

| # | change | why | Phase 3 item |
|---|---|---|---|
| R1 | **One hash, Poseidon2-M31's compression `C`**, behind a trait `Compress { fn compress(l: &Digest, r: &Digest) -> Digest }`; cipher-clerk ships no permutation; VOS's SDK implements it over `0x402` in a kernel and natively on hosts; cipher-clerk's tests take golden vectors from VOS | the zkVM proves `0x402` in one chip row and BLAKE2b or a curve not at all cheaply; one hash keeps device shapes free of BLAKE2b (`proving.md` §8, `H_io`) | 8 |
| R2 | **Hash commitments, not Pedersen**: `cm = C(C(T(note), [asset, v₀, v₁, v₂, 0…]), C(rho, C(owner, r)))`, value in three 24-bit words; `r` a 248-bit blinding the caller passes (randomness as a parameter, v0.3.0's rule kept). The order lets a pool compute a deposit's `cm` from a public amount, a protocol `rho` and the depositor's `C(owner, r)` (§5.4) | the spend proof checks the balance in Rust, so no homomorphism is needed; no curve in the kernel | 4 |
| R3 | **Keys hash-only, per device**: `sk` per device and pool, 32 random bytes drawn by the light node, wrapped under a per-use keystore key and sealed to the recovery key (N4), never synced (E2); `owner = C(T(note-owner), sk)`, `nk = C(T(note-nf), sk)`; the device proves knowledge of `sk` | spend authorization without an embedded curve: option 1 of item 1 ("the device proves, with `ak = Poseidon(ask)`"); no delegated proving, which the light node does not need | 1, 2 |
| R4 | **Nullifier** `nf = C(nk, C(pool, cm))`, scoped to the pool's id; **`rho` of each output** `C(T(rho), C(nf₀, [i, 0…]))` (two calls), bound to the transaction's first nullifier; **a deposit's `rho`** `C(T(rho-deposit), W(b))`, `b` the deposit call's binding digest, unique and recorded | unique per note, unlinkable to `cm` without `nk`; `rho` fixed by the protocol closes Faerie Gold (F3) for spends and deposits alike; `nk`'s tag apart from the credential's `T(nf)`; a note of one pool spends in no other | 3 |
| R5 | **Fixed-shape transactions**, `Tx<const I, const O>`: `asset` (the transaction's one asset, its fee's too), `anchor`, `nullifiers: [Digest; I]`, `commitments: [Digest; O]`, `memos_hash`, `value_balance: i64` (a withdrawal's amount, or 0), `leg` (the withdrawal's destination account id, or zero), `fee: u64`, `pool: Digest`, `binding`; deposits are not transactions (§5.4) | a proof's shape is its kernel's; two kernels, 1-in-2-out (`spend`) and 2-in-1-out (`join`), cover payments and consolidation; the transparent leg and the fee's asset are in what the proof binds | 4, 5 |
| R6 | **`shielded::check::<H, I, O>(tx, witness) -> Result<(), SpendError>`**: `no_std`, no allocation, fixed arrays, no `BTreeMap`, no panic; `Witness` the input notes, their positions and paths, `sk`, the output notes; plus `shielded::Plan` and `shielded::build` (host side, taking the device's `sk`) | the device kernel's body; the same function runs on hosts as the reference | 11 |
| R7 | **An incremental note tree**: append-only, depth 32, its frontier (33 digests) and a ring of the last 64 anchors in point rows behind a `NoteState` trait (as `LedgerState`), O(32) calls an append | F21; the actor stores it in its tables; the anchor ring mirrors the credential actor's | 7 |
| R8 | **The pool a pseudo-account of the L0 kernel**: a transaction's `value_balance` is one kernel transfer between the payer's or payee's transparent account and the `ShieldedPool` pseudo-account, under the depositor's `Authority` or the proof's | `seal` and `open` kept as the kernel's two legs, not a second ledger | 9 |
| R9 | **Encrypted notes**: a memo per output, X25519 to the recipient's address key and ChaCha20-Poly1305 (the `viewing-keys` envelope's AEAD), a one-byte view tag; outgoing ciphertext under the sender's `ovk`; host side only, never in a kernel; the transaction binds `memos_hash` | note delivery through the pool's feed (§5.4); the recipient checks a note's `owner` against its own on receipt (F8) | 2, 6 |
| R10 | **Deleted**: `notes` (replaced by `shielded`), `pvm-precompile` and its VOS git dependency, `fmd-experimental`, `stealth-experimental` (F8: unspendable), the Ristretto `AuthKey` and Schnorr outside the `signatures` helper the CLI uses | fewer pieces; nothing in VOS uses them; the view tag and scanning replace FMD at this scale | — |
| R11 | **Recovery and refusals** written as tests against `check` and the pool: Faerie Gold, a spend back by the sender, a double spend (at the actor), an anchor out of the ring, a fee or memo-hash mismatch, an overflow, a wrong pool, a mismatched owner on receipt (the wallet's check, R9) | Phase 3's refusal list | 10, 11 |

**Kept as they are:** the L0 kernel (`apply_batch`, `Authority`,
`LedgerState`, the two layers, two-phase transfers, the encodings, the
fit check), payments between spaces and `settlement::window` (the window
test actor's kernel), and `ValueModel` (`Value` the only model; the
confidential model stays on paper: notes make it unnecessary for privacy).
cipher-clerk stays independent of VOS: its kernel depends on no VOS crate
once R10 drops the git dependency, and VOS depends on its tag.

### 5.4 The code a developer writes

The whole of the payments actor's private path, with cipher-clerk doing
the cryptography (sketch; names follow §5.3):

```rust
use cipher_clerk::shielded::{self, Spend, Join, NoteTree};
use vos_sdk::prelude::*;

#[actor]
pub struct Payments {
    clerk: Clerk,                       // cipher-clerk's L0 accounts, in tables
    notes: NoteTree,                    // the frontier and the anchor ring
    spent: Table<Digest, ()>,           // nullifiers
    memos: Table<u64, Memo>,            // a position's encrypted note
}

#[messages]
impl Payments {
    /// Proven on the payer's device; never run by a node.
    #[attestable(device, reference = shielded::reference::<1, 2>)]
    pub fn spend(witness: &Spend, #[public] tx: &shielded::Tx<1, 2>) {
        shielded::check::<P2, 1, 2>(tx, witness).expect("a valid spend");
    }

    #[attestable(device, reference = shielded::reference::<2, 1>)]
    pub fn join(witness: &Join, #[public] tx: &shielded::Tx<2, 1>) {
        shielded::check::<P2, 2, 1>(tx, witness).expect("a valid join");
    }

    /// A proven spend: its nullifiers once, its notes appended.
    #[msg(proven = spend)]
    pub async fn pay(&mut self, ctx: &mut Command<Self>, tx: shielded::Tx<1, 2>,
                     memos: [Memo; 2]) -> Result<(), PayError> {
        self.notes.accepts(&tx.anchor)?;
        tx.memos_hash.matches(&memos)?;
        for nf in tx.nullifiers { self.spent.insert_new(&nf)?; }
        for (cm, memo) in tx.commitments.into_iter().zip(memos) {
            let at = self.notes.append(cm)?;
            self.memos.insert(&at, &memo);
        }
        self.clerk.pool_leg(ctx, tx.value_balance, tx.fee)
    }

    /// A note from a transparent account, under its owner's proof. The pool
    /// computes the commitment itself from the public amount, a `rho` the
    /// call's binding fixes, and the depositor's hidden `C(owner, r)`: a
    /// deposit cannot mint more than it debits, and no two share a `rho`.
    #[msg(credential = Owner)]
    pub async fn deposit(&mut self, ctx: &mut Command<Self>, from: AccountId,
                         hidden: Digest, memo: Memo, amount: u64) -> Result<(), PayError> {
        let rho = shielded::deposit_rho::<P2>(ctx.binding());
        let cm = shielded::commit::<P2>(self.asset(), amount, &rho, &hidden);
        self.clerk.debit_into_pool(ctx, from, amount)?;   // the L0 kernel, the owner's authority
        let at = self.notes.append(cm)?;
        self.memos.insert(&at, &memo);
        Ok(())
    }

    /// The feeds a wallet scans, every wallet all of them: commitments and
    /// memos from a position on, and nullifiers from a position on (never
    /// a query for one nullifier, which would tell the operators which).
    #[msg]
    pub async fn notes_feed(&self, from: u64) -> Page<(Digest, Memo)> { /* … */ }
    #[msg]
    pub async fn spent_feed(&self, from: u64) -> Page<Digest> { /* … */ }
}
```

The wallet, a local actor:

```rust
#[actor]
pub struct Wallet {
    notes: crdt::GSet<Owned>,           // notes received: the note, its position, its device
    spent: crdt::GSet<Digest>,          // nullifiers the user's devices spent or saw spent
    tree: crdt::Map<u64, Digest>,       // the pool's leaves seen so far, for paths
}

#[messages]
impl Wallet {
    #[msg(merge)]
    pub fn received(&mut self, note: Owned) { self.notes.insert(note) }

    #[msg(merge)]
    pub fn spent(&mut self, nf: Digest) { self.spent.insert(nf) }

    #[msg]
    pub fn balance(&self) -> u64 {
        self.unspent().map(|n| n.note.value).sum()
    }

    /// The plan of a spend paying `amount` to `to` from `device`'s notes,
    /// its change back to `device`: the light node builds it with that
    /// device's key, proves it and sends it to the pool.
    #[msg]
    pub fn prepare(&self, device: Owner, to: Address, amount: u64)
                   -> Result<shielded::Plan<1, 2>, PayError> {
        let input = self.pick(device, amount)?;
        Ok(shielded::Plan::new(input, self.path(input.position), to, amount))
    }
}
```

**What the light node does around it** (a `pay` operation of the
facility, §7.3): calls `prepare` on the local wallet, builds the
transaction and its witness with the device's `sk` and fresh randomness
(`shielded::build`), proves the pool's `spend` kernel on them (the kernel's bytes come from the space's
installed package, fetched once and pinned at enrollment), sends the
proven call, and on `Ok` records `spent(nf)`. A local workflow with
device effects (`ctx.prove`, `ctx.call_remote`) would move that glue into
the actor; it is a later extension of the local host (§9 Q8).

### 5.5 What is proved on the device, and what is checked publicly

**Proved on the device** (the `spend` kernel, `shielded::check`):
- the payer knows `sk` behind the input note's `owner`;
- the input note's commitment is a leaf of the pool's tree under `anchor`
  at the witnessed position;
- each nullifier is `C(nk, cm)` of its input;
- each output's commitment is well formed, its `rho` the protocol's;
- `Σ inputs = Σ outputs + fee + value_balance`, every value and sum in
  `u64` with checked arithmetic (the 64-bit range checks);
- the proof binds the call (`binding`), the pool, the anchor, the memos'
  hash, the fee and the transparent leg.

**Checked publicly, by the space:**
- at ingress: the generic checks and the proof against the `spend`
  program (§4.3); no pool-specific pre-check;
- at apply (`pay`): the anchor accepted (newest, or superseded within
  `ROOT_MAX_AGE`, the credential ring's rule); each nullifier inserted
  once (a second is refused, the whole call with it); the memos' hash;
  the commitments appended; the transparent leg applied by cipher-clerk's
  kernel (a withdrawal credits the account `leg` names from the pool's
  pseudo-account);
- at a deposit: the depositor's owner proof, the debit by cipher-clerk's
  kernel, and the commitment computed by the pool (above), so the value a
  note holds is the value debited.

**What the operators learn:** that a spend happened, when, its fee, its
transparent leg if any, and two new commitments; never the payer, the
payee, the amount or which note was spent among those under the anchor.
Over Tor (§6), not the address it came from.

### 5.6 What the pool trusts

- **Authority is the users':** no operator can spend a note (it needs
  `sk`), and there is no `rekey`: the private tier is non-custodial in its
  authority, unlike today's ledger (`identity-and-authority.md` §7).
- **Integrity is the operators':** a space's nodes trust each other
  (`core-model.md` §5); an operator can append a commitment no deposit
  paid for (inflation), refuse a spend, or roll back. Users see the
  pool's transparent total (the pseudo-account's balance) and their own
  notes, not a proof of supply. A pool that needs integrity without
  trusting its host is `identity-and-authority.md` §8's, postponed.
- **The anonymity set** is the pool's notes under the anchors in use: in a
  small space, small. A member who spends right after receiving links
  the two by timing; the wallet waits a random interval before spending a
  fresh note, and joins run when the phone is idle and charging.

### 5.7 The spend's cost

[est] by counting, against the auth kernel (1,722 steps, 43 calls of
`0x402` with `H_io`'s):
- calls: `owner` and `nk` 2, the input's commitment 4, its nullifier 2,
  its path 32, two outputs' `rho` 4 and commitments 8, `H_io` over a claim
  of about 260 bytes 12: about 64, under the Poseidon2 chip's 2^10 floor;
- steps: about 2,800–3,600 in SDK form, so the CPU at 2^12 rows (auth's
  2^11), the memory ledger one power of two above auth's;
- the cell model's time at that size: 0.9–1.3 s on the Fairphone 6 today
  [model, est], 0.7–0.95 s with both levers; peak 0.7–0.9 GiB; a proof of
  about 1.1–1.3 MB.
- `join` (2 in, 1 out) adds a path and a nullifier: about 100 calls,
  4,500–5,500 steps, 2^13 rows, 1.4–1.9 s today [est]; it runs in the
  background, not on a user's tap.
- **The gate** (slice 9's PG4): the spend at most 1.0 s at the median
  with the levers, at most 1.5 s without them.


## 6. Tor via arti

From the research of 2026-11-02; each claim's source is in §6.8, and
"unverified" marks what could not be read first-hand (the Tor Project's
GitLab refused the fetches).

### 6.1 Where the onion service lives: the gateway

**At the gateway, in process** [proposed; the owner: "arti could be
included in the ingress"]:
- The gateway is the space's ingress for clients; it is tokio already
  (`node-api.md` §6), arti's default runtime, and it holds no authority,
  so an onion service there exposes nothing the clearnet routes do not.
- **The node stays Tor-free,** as it stays JAM- and Kreivo-free [decided,
  2026-10-23, by analogy]: a node is reached over its unix socket or QUIC
  with mutual TLS from gateways inside the operator's network; Tor ends at
  the gateway. (The node's runtime is smol, whose arti support is marked
  experimental, another reason not to put it there.)
- **The node API over Tor directly** (no gateway) is not offered: it would
  put arti in the node and expose ingress to every client's DoS without a
  layer that can shed it.

**How it is hosted** (arti-client 0.47's API): `TorClient::launch_onion_service_with_hsid(config, key)`
with the service's key from the gateway's key directory; the returned
stream of `RendRequest`s goes through `tor_hsservice::handle_rend_requests`,
which yields one `StreamRequest` a client stream (a `BEGIN` to a virtual
port); accepting it gives a `DataStream`, `AsyncRead + AsyncWrite` for
futures and tokio. The gateway serves, by virtual port:
- **22:** s4's SSH, the same `s4-server` handler its TCP port runs;
- **80:** the HTTP routes, the same `vos-http` server over the stream
  (`tokio_util::compat`, as today's TCP);
- **7000 (`vos-api`):** the node API's frames over the stream, the kinds
  `vos-api` over SSH relays today plus `Credentialed` and `Call` (the
  personal agent's pushes, commits and device-set operations), with the gateway's leader-aware routing behind it. The light
  node's `vos-api` client runs over the `DataStream` unchanged (a
  multiplexed client over any futures-io stream).

**Tor carries streams, not datagrams:** no QUIC end to end; UDP over Tor
is a proposal (339), not deployed. iroh's experimental Tor transport
tunnels QUIC packets over a stream; we need not, since the gateway already
speaks streams (HTTP, SSH, framed `vos-api`).

**The onion address is the gateway's identity:** self-authenticating, so
a client that pinned it at enrollment needs no TLS certificate for it; the
SSH host key stays pinned as today (§7.3).

### 6.2 The client embedding arti

- **One `TorClient` a process,** created in the light node on the
  facility's tokio runtime (`arti-client` with `default-features = false`
  and `tokio`, `rustls`, `compression` and `onion-service-client`: the
  defaults are `tokio`, `native-tls` and `compression`, and
  `onion-service-client` is not among them; `static` is not taken, since it
  vendors native-tls and so OpenSSL), its
  state directory in the app's private storage so later starts skip the
  cold bootstrap. Zcash's `zcash_client_backend::tor::Client` is the model:
  one client, `isolated_client()` handles, `set_dormant` when the app is
  in the background, persisted state.
- **Isolation by purpose:** each of these gets its own circuit
  (`isolated_client()` or a `StreamPrefs` isolation group), so the
  gateway cannot join them by circuit:
  - root polls and path fetches (one isolation each, as today's drawn
    keys separate them);
  - proven calls (each its own, from a spare: the client keeps one
    circuit to the onion built ahead for the next proven call and builds
    the next spare once it is used, since each isolated circuit to an
    onion service is a new rendezvous, a second or more, heavy-tailed);
  - the personal agent's traffic (its own group, on its own jittered
    schedule, §3.10), never sharing a circuit with the member's proofs;
  - s4's screen session (its own).
- **Dormant and awake:** awake while the app is in the foreground or a sync
  job runs; dormant otherwise (no circuit kept, no timer firing), so
  battery costs come only from the work §2.3 budgets.

### 6.3 The latency model

| phase | time | when it is paid |
|---|---|---|
| cold bootstrap (consensus and about 8,800 microdescriptors, a few MB) | 10–30 s, timing out at 30 s on a lossy network [unverified, onionmasq's log] | first run, or after a long time offline |
| warm bootstrap (cached directory) | about 1–3 s [est] | each app start; hidden behind the UI's own start |
| onion connection (descriptor, introduction and rendezvous circuits) | about 1 to several seconds, heavy-tailed; arti's own issue reports onion connections timing out [unverified, onionperf, arti#2482] | once a purpose a session; pre-built when the app opens (§6.2) |
| a request on an open circuit (six hops each way) | 0.3–1 s round trip [est] | every call |
| a proven call without a spare circuit ready | adds an onion connection, 1 to several seconds | a second proven call within a spare's build time |
| a proof's upload | a device proof is about 0.9 MB (a spend about 1.2 MB [est]); at the 0.5–2 MB/s an onion circuit sustains, 0.5–2 s [est] | every proven call |

**A sign-in end to end** (an open circuit, the path held): prove 0.45–0.65
s, upload 0.5–2 s, the round trip 0.3–1 s, the node's apply 35 ms
[measured, `proving.md` §8]: **about 1.3–3.6 s** [est], against about 0.8 s on the
clearnet. **A private payment:** 2–4.5 s [est]. The proof's bytes are now
the largest term, which makes the device format's proof size a lever of
its own (§4.4): the per-program CPU and word-level memory cut columns, and
so bytes, by the same fraction as cells.

### 6.4 What it costs on the phone

No published figures exist for arti's library size, idle memory or
battery on Android [the research found none]; they are the slice's first
measurement (the plan's step 8.1). The budgets of §2.3 (arti ≤ 48 MiB
resident, ≤ 10 MB of `.so` growth) are targets to measure against, not
known values. The production precedents: Zashi ships arti on Android and
iOS (exchange rates since 2024; transaction submission and fetching in beta
since Zashi 2.1, 2025-08-07, with a prompt to turn Tor off when it is
slow); the Tor Project's own Android VPN (onionmasq) runs arti and is
still in beta; Orbot still bundles C tor.

### 6.5 Fallbacks

- **Tor blocked or failing:** arti's bridges and pluggable transports
  (obfs4 and WebTunnel through a transport binary); a client that cannot
  bootstrap shows it and does not silently degrade.
- **The clearnet gateway, by the space's policy:** a space declares
  `tor = required | preferred | off` in what enrollment pins. Under
  `preferred` the client falls back to the gateway's TLS or SSH address
  after a bootstrap failure, and its chrome says the call is not private;
  under `required` it does not. Recommended default: `preferred` for
  sign-in and the transparent ledger, `required` for the shielded pool's
  calls (the network address is the last link §5.5 leaves). **The
  personal agent's traffic is Tor-only whatever the policy:** over the
  clearnet it would hand the home's operators the device's address beside
  its pseudonym (§3.10); without Tor the personal space waits.

### 6.6 Denial of service without addresses

Every client of an onion service arrives without an address, so the
gateway's per-address limits (`node-api.md` §6: 64 connections and 200
requests a second an address) no longer apply to Tor clients. In their
place:
- **arti's service defences:** introduction-point rate limits and the
  service-side proof of work (`hs-pow`, behind `hs-pow-full` in the
  `experimental` bundle, with LGPL dependencies). C tor's onion-service PoW
  is stable; no arti release up to 2.7.0 declares its service-side PoW or
  its onion-service hosting ready for production, and its in-repository
  `doc/OnionService.md` still says "suitable for testing and
  experimentation only" and lists no DoS protection (last touched
  2025-08, and stale on restricted discovery, so weak evidence either
  way). Turn PoW on when a release declares it; until then the gateway's
  other limits hold alone, and the fallback is C tor beside the gateway
  (§9 Q11).
- **Limits per circuit and per service:** streams per rendezvous circuit,
  requests a second per stream, and a global cap of proven calls in flight
  through the onion (the node's verification budget behind it, `Busy` past
  it).
- **The proof's own cost:** a proven call carries the device format's PoW
  (16 bits), checked before any decommitment; a junk proof costs the node
  5.8–8 ms today [measured, format 46], less once the decode and setup
  are profiled (§4.3).
- **Restricted discovery** (onion-service client authorization): stable
  since arti 1.7.0 (2025-11). Only clients holding an authorized key can
  read the service's descriptor, which hides it from scanners. Not offered
  in slice 8: a key per member makes the descriptor grow with the space
  (its size is bounded), and one key shared by every member is as good
  as public once one member leaks it. A space small enough for per-member
  keys may turn it on later.

### 6.7 What Tor fixes, and what it does not

**Fixes:**
- the network address: no node or gateway learns a member's address, so
  "a proof from the same address still links its nullifier to the digest"
  (`node/SECURITY.md`) ends, since a path fetch and a proof arrive on
  different circuits;
- the root-marking attack's last step (a gateway marking an address's
  root polls) loses its address; it keeps the circuit, which isolation
  per purpose (§6.2) scopes to one poll;
- the personal agent's view: a device's pushes and fetches with no
  address behind them.

**Does not fix:**
- **timing:** a gateway sees when a fetch and a proof arrive; jitter
  (`PathKeeper`'s) spreads them, and syncing the tree (§3, the wallet's
  `tree` and the credential book's) removes path fetches altogether, which
  is the real fix the carried list names;
- **the `map_root` fingerprint** (carried, plan 8.20): fixed by proving against
  the newest root, which a synced tree gives the device, or by logging the
  root's place in the ring in place of the root;
- **small anonymity sets:** a pool or a member tree of fifty is a set of
  fifty however the bytes travel;
- **a global observer** correlating both ends of Tor, and application
  identifiers a client volunteers;
- **Tor's own maturity:** arti hosting is usable and has vanguards (full
  vanguards recommended for long-lived services; vanguards-lite the
  default since 1.2.2), congestion control and CGO stable since 2.5.0, two
  medium-severity DoS fixes in 2.5.0; but its service PoW is not declared
  ready, its documentation is inconsistent about production use, and the
  Tor Project has not recommended it for high-risk onion services; its library crates take breaking minor releases about monthly
  (arti-client 0.45, 0.46 and 0.47 in August, September and October 2026).

**Verdict on arti** [proposed]: ready for the client side (stable since
1.0, shipped by Zashi and Fedimint); usable, not yet hardened, for
hosting, whose DoS defence is the gap. Ship the client path in slice 8;
host the gateway's onion behind a `tor` feature, full vanguards on, PoW
when a release declares it; keep a C tor sidecar as the documented
fallback should the onion be flooded before then (§9 Q11); pin one arti
version a release and budget an upgrade step each slice.

### 6.8 Sources (read 2026-11-02 unless marked)

- arti 1.7.0 (restricted discovery stable):
  https://blog.torproject.org/arti_1_7_0_released/ ; 2.5.1 (unix-socket
  targets; congestion control and CGO on onion circuits experimental):
  https://blog.torproject.org/arti_2_5_1_released/ ; the onion-service
  document: https://gitlab.torproject.org/tpo/core/arti/-/raw/main/doc/OnionService.md

- arti 2.7.0, 2026-10-01: https://blog.torproject.org/arti_2_7_0_released/ ;
  2.6.0: https://blog.torproject.org/arti_2_6_0_released/ ; 2.5.0:
  https://blog.torproject.org/arti_2_5_0_released/
- arti-client's versions: https://crates.io/api/v1/crates/arti-client ;
  its API (`launch_onion_service`, `StreamPrefs`):
  https://docs.rs/arti-client/latest/arti_client/struct.TorClient.html
- features (`onion-service-service` in `full`, not default):
  https://docs.rs/crate/arti-client/latest/features ;
  `tor-hsservice` (`handle_rend_requests`, `hs-pow-full` experimental):
  https://docs.rs/tor-hsservice/latest/tor_hsservice/ ,
  https://docs.rs/crate/tor-hsservice/latest/features ;
  `tor-rtcompat` (`smol` experimental):
  https://docs.rs/crate/tor-rtcompat/latest/features
- vanguards in arti: https://blog.torproject.org/announcing-vanguards-for-arti/
- "proxy and onion service support are ready for use":
  https://arti.torproject.org/core/arti/ ; the older "not recommended for
  production" page, unrevised since 2023:
  https://arti.torproject.org/guides/capability-limitations
- onion connections timing out (unverified, not readable):
  https://gitlab.torproject.org/tpo/core/arti/-/issues/2482 ; onionperf:
  https://metrics.torproject.org/onionperf-latencies.html
- Zcash's arti client: https://docs.rs/zcash_client_backend/latest/zcash_client_backend/tor/struct.Client.html ;
  Zashi 2.1: https://zodl.com/zashi-2-1-enhanced-privacy-with-tor-beta
- Fedimint's connector: https://docs.rs/crate/fedimint-connectors/0.11.2/source/src/tor.rs
- onionmasq's cold bootstrap (unverified):
  https://gitlab.torproject.org/tpo/core/onionmasq/-/issues/161
- iroh's Tor transport (QUIC over Tor streams, C tor):
  https://iroh.computer/blog/tor-custom-transport
- UDP over Tor, a proposal: https://spec.torproject.org/proposals/339-udp-over-tor.html


## 7. Fitting the existing system

### 7.1 Crates

| crate | change |
|---|---|
| `vos-device` (`pvm/device`) | folds into `vos-light`; its secret, wire and path-keeper modules move, its credential prover goes (§4.1) |
| `vos-light` (new, `node/light`) | the light node: the single-replica host, the store, the prover's device path, the node-API client, sync of sealed scopes, the device group over mls-rs, arti's client behind a feature; replaces `vos-device` one for one |
| `vos-node` (`node/host`) | forwarding a request for an agent it does not replicate (§3.3); its executor and store usable without Raft. The crate is about 27.6k lines and depends without option on `vos-pvm-recair`, `vos-venue`, `vos-node-prover`, `vos-net`, `vos-raft`, quinn and the compiler; its `dispatch` is peer-arrival dispatch over `vos-net`, and `calls.rs` reads `vos_raft::Role`. Plan 8.6 opens with a carve-out spike choosing between a `server` feature and moving the executor and store into `vos-light`'s own single-replica host; `credentialed.rs`'s use of `vos_pvm_recair::device` moves either way |
| `vos-pvm-recair` | `credential` deleted; the leaves, folds and wrap behind a `recursion` feature, on by default (the masking needs `context`, `circuit` and `trace`, which stay), so a device links less of the recursion prover (§9 Q9) |
| `vos-pvm-final-verifier` | `credential` and `credential-bytes` deleted |
| `vos-sdk`, `vos-sdk-macros` | `#[attestable(device, reference = …, headroom = …)]`; `#[msg(proven = kernel)]`; in-place kernel arguments; `vos_sdk::p2` (digests, tags, paths); `crdt::{GSet, Set, Map}` and `#[msg(merge)]` on the light node |
| `vos-wire` | `Credentialed.claim` in place of `CredentialPublic`; `CredentialedInput` carries the claim; `Principal::Kernel { program }` (index 7); `CredentialKind` deleted; a peer message carrying a request as received, for forwarding (§3.3) |
| `merkle-crdt` | the incremental apply (`core-model.md` §9.4); the author, its sequence and signature in the payload; a `Store` over fjall; fetching by batch, asynchronously (today's `fetch_missing` walks one node at a time, synchronously, `src/sync.rs`); the `redb` store and feature deleted (one storage engine) |
| `vos-credentials` | the stock `auth` kernel (from the `device` test actor, in SDK form) and a new `owner` kernel, with their references; the stock kernels' ingress checks stay in the node (§4.3); a second ring for person leaves where `once` is used (§3.8, N3) |
| `vos-gateway` | the onion service behind a `tor` feature (§6); a `vos-api` byte-stream port on it; per-circuit limits |
| new system actors | `Homes` (the pool, claims, leases, recycling) and `Personal` (the device set, the MLS log, sealed scopes, the inbox, quotas), each one package; `Payments` (replacing the `purses` test actor) |
| new tool | the operator's keeper, topping up the pool of personal agents (§3.3) |

**Net:** one crate in (`vos-light`), one out (`vos-device`); the
credential AIR's modules, one feature, one format, its fixtures and its
fuzz target out; merkle-crdt's redb out; cipher-clerk's `notes`,
`pvm-precompile`, `fmd-experimental` and `stealth-experimental` and its VOS
dependency out. In: arti's dependency tree (in the gateway and the light
node), mls-rs's (in the light node), three actors, a tool, the SDK's CRDT
fields and merge dispatch, and node forwarding. No proving code beyond the
levers' format.

### 7.2 The node and the gateway

- **The node** gains no transport and no knowledge of Tor, MLS, JAM or
  Kreivo. Its ingress generalizes (§4.3); its install computes a device
  program for every device kernel (§4.4); format 44 goes; it forwards
  requests for agents it does not replicate (§3.3). The personal agent is
  an ordinary agent running ordinary actors: nothing in the node knows
  what a personal agent is.
- **The gateway** keeps HTTP, TLS and SSH, and adds the onion service
  (§6): the same routes and the SSH port behind an onion address, and a
  port carrying the node API's frames over the onion stream. Its relay
  set is wider than the `vos-api` subsystem's today (`NodeKey`, `Time`,
  `AgentInfo`, `Schema`, `Query`; `node/api/src/lib.rs`, `Kind::relayed`):
  it adds `Credentialed` and `Call`, which a light node sends there.
- **Limits that bind the personal agent** [built]: 64 KiB a call's
  arguments, a reply and a row; 256 KiB a step's writes; 16 in flight on
  one `vos-api` channel; one answer a request, no push
  (`agent/wire/src/abi/cap.rs`, `node-api.md` §2). §3.6 sizes envelopes
  and pushes under them.

### 7.3 s4

- **The facility** `vos.credential` becomes `vos.node`: `enroll`,
  `sign_in` and `pay` as today (the trusted chrome, the pins, the two
  prompts [decided, `identity-and-authority.md` §7]), plus `claim` (the
  personal agent, with the recovery kit), `pair` (§3.8), `devices`
  (list, remove, veto, approve; each behind the admin key's prompt),
  `restore` (from a recovery kit) and `move_home` (§3.9).
- **Tor in s4's client:** its SSH connection to the gateway goes to the
  onion address pinned at enrollment, through the facility's `TorClient`;
  the host key is pinned as today.
- **The facility's toolchain:** it builds on VOS's pinned nightly
  (`s4-credential/rust-toolchain.toml`) because of the prover; unchanged.
- **s4's VOS pin** still names a retired device format today (`open.md`,
  "Repository"); it moves with the cleanup's last step, before slice 8's
  first phone session.

### 7.4 The SDK macros and the derivation

- `#[attestable(device)]` methods may take references to fixed-size
  argument types (decoded in place) and declare `reference` and
  `headroom`; the derivation records the reference's symbol and refuses a
  device kernel without one.
- `#[msg(proven = k)]` names a device kernel of the actor or of the agent's
  credential actor; the method's first argument is the kernel's claim
  type, checked equal at compile time (`pay(tx, memos)`: `tx` first).
- A local actor is an ordinary package; `#[actor]` needs no new mode. The
  light node refuses to install one with Linear fields or workflows (the
  derivation's schema says which).
- `Homes` and `Personal` are written with the SDK as any actor is: they are
  the showcase's other half, how far plain actors carry a system feature.

### 7.5 What stays

The node's Raft, store, executors and API; the default agent; the
recursion, the final wrap and its venues (formats 39, 41); statements and
anchors; the credential actor and its Poseidon2 tree; `0x402` and its
chip; `H_io`; the device format's machinery; the gateway's HTTP and SSH;
s4's facility model; cipher-clerk's L0 kernel and settlement.

## 8. Edge scenarios

What could bite this design later, worked through before code. Each
entry names the situation and its consequence, then its handling: a
**mitigation** (with the plan step that builds it) or a **known limit**
(with where it is carried). Sources for prior art are in §8.9.

### 8.1 Devices and keys

**A1. Two devices change the device set at once,** one offline (phone
removes the tablet while the tablet, offline, adds a laptop). Two commits
claim one epoch. *Mitigation:* the agent's log orders them; the first wins
and the other is refused `EpochTaken`; the loser rereads and re-proposes
only if its intent still holds (an add proposed by a device since removed
dies with it). No device commits offline. (8.12, 8.16)

**A2. A device is lost or stolen, locked.** Its keys are wrapped under
keystore keys bound to the unlock and to the prompt; nothing is readable
without them. *Mitigation:* the owner removes it from another device (72
h, or at once with two other devices) or with the recovery key (7 days). (8.17)

**A3. A device is stolen unlocked, the app open,** without the owner's
biometric. The thief reads what the phone reads: the materialized data
and, through the key archive, the history the agent holds. *Known limit,*
inherent to any device that shows the user their data; it cannot change
membership or veto (the admin key needs the prompt). The chrome says
history up to the theft is exposed. (stated in 8.22)

**A4. A thief who also passes the prompt** (coercion, or a biometric the
phone accepts too easily) can add a device, start removals and veto.
*Mitigation:* the admin key accepts only strong biometrics, never the
PIN fallback (§3.5); a removal of another device takes 72 h and its
target cannot veto it, so the owner's other device vetoes the thief's
removals and removes the stolen phone; two active devices remove at once.
*Known limit:* a thief holding the phone and the owner's biometric can
veto the kit's operations on the devices he holds (each may veto the
other's removal). The owner's last remedy is restoring **elsewhere** from
the kit: a new group at a new home, opened from the archives the kit
holds, which no device of the old group can veto or join; the thief keeps
what the phone already held. (8.17)

**A5. A device returns after months.** Within the 180-day retention it
replays the handshakes it missed and derives every epoch's keys (data
keys come from the exporter, so no ratchet window applies). Beyond it,
the handshakes are gone. *Mitigation:* a device silent for 90 days is
marked stale in the chrome and removed by any active device under the
normal delay; past retention it re-pairs (a QR from a live device).
(8.16)

**A6. A long replay on a phone,** killed by Android midway. *Mitigation:*
each commit is applied in one fjall batch with the stored epoch checked
before and after (prior art: XMTP's local commit log); a gap of more than
a few hundred commits prefers re-pairing to replay. (8.16)

**A7. A removed device backdates DAG writes,** sealing under an old epoch
it still knows, with old parents. *Mitigation:* seal-at-push (§3.6) means
the agent takes only the current epoch, which the removed device does not
have; the agent refuses its keys; devices accept its envelopes only at or
before its frontier. (8.16)

**A8. A write made offline leaks to a device removed meanwhile** (DCGKA's
dominating-update case). *Mitigation:* seal at push under the epoch read
just before; `StaleEpoch` otherwise. (8.16)

**A9. A device applies its own commit before the log accepts it,** the
first cause of forks in deployed MLS. *Mitigation:* mls-rs's pending
commit merged only on the agent's acceptance at that epoch. (8.16)

**A10. Retries and leader changes,** a push or commit landing twice or
another commit slipping between. *Mitigation:* envelopes deduplicated by
the hash of their bytes; a commit is accepted once at its epoch; devices
reread the log on every retry. (8.12)

**A11. An OS backup or a cloned phone restores MLS state on a second
device.** Two instances of one leaf fork the group. *Mitigation:* MLS
state, the archive and the push queue are excluded from Android's backup
and wrapped under a hardware key that does not migrate, so a restored
copy cannot open them and starts as a new device (A13). Data sealing uses
random 24-byte nonces, not MLS's secret tree, so a clone does not reuse
nonces on data; a clone's commit forks the group and is detected (B4).
(8.16)

**A12. The user's biometrics change,** and Android invalidates the key
wrapping the admin key. The device syncs but cannot administer.
*Mitigation:* another active device, or the recovery key, registers the
device's new admin key; the device returns to probation, since a new
admin key is as strong as a new device. (8.17)

**A13. The app is reinstalled on the same phone.** Keystore keys are gone;
the phone is a new device, and its old leaf a ghost. *Mitigation:* it
pairs from another device or restores from the kit, then removes the
ghost. (8.17)

**A14. A thief who passed the prompt pairs his own device.** *Mitigation:*
probation: for 72 h the new device cannot add, remove or veto, and any
active device removes it at once. It has received the history the stolen
phone already held, no more. (8.17)

**A15. Clocks are wrong.** *Mitigation:* delays, leases and TTLs run on
the agent's batch time, with the device's monotonic clock as a floor
(B7); device clocks never order CRDT operations (Lamport counters do) or
decide membership; MLS leaf lifetimes are generous (a year, renewed by
updates). (8.12, 8.16)

### 8.2 The home space and its operators

**B1. The operators withhold or delay sync.** Devices cannot tell an
outage from withholding. *Mitigation:* devices work offline and are full
replicas; after 7 days without the agent the chrome offers to move home
(§3.9). (8.16)

**B2. The operators delete envelopes.** *Mitigation:* each device
periodically fetches a random sample of the positions it pushed and
re-pushes what is missing, which also tells the user. (8.16)

**B3. The operators roll the agent back** (a restored snapshot).
*Mitigation:* each device refuses a control log shorter than or diverging
from the highest `(log_index, log_chain)` it saw, and raises an alarm.
(8.16)

**B4. The operators equivocate,** showing two devices different handshakes
for one epoch. The devices then hold different keys. *Mitigation:* every
envelope carries its writer's view; a device that opens (or fails to
open) another device's envelope sees the split and raises a fork alarm;
recovery is moving home and re-pairing (prior art: remove-and-re-add,
never roll back). *Known limit:* nodes sign nothing a device can show a
third party, so the alarm is not proof of misbehaviour; carried with
node-signed answers (`open.md`, "Node-signed roots"). (8.16)

**B5. The operators inject or replay.** They cannot seal (no key), so a
forged envelope fails its AEAD and is dropped; a replayed envelope is a
duplicate (its id, and its CID inside); a replayed commit breaks the
epoch rule and the chain. *Mitigation:* as stated. (8.16)

**B6. The operators forge device-set operations.** They run ingress, so
they can append to the agent's log anything, including "remove the
laptop" in a device's name, and honest devices would carry it out.
*Mitigation:* operations are signed end to end by the admin key and every
device verifies the signature before acting (§3.5); a forged operation is
ignored and raises an alarm. MLS commits authenticate themselves. (8.12,
8.16)

**B7. The operators advance the agent's clock,** maturing a genuine but
hostile removal at once. *Mitigation:* the device's own monotonic elapsed
time is a floor on every delay. (8.16)

**B8. The operators collude with a thief who passed the prompt:** they can
drop the owner's vetoes and order the thief's commits first. *Known
limit:* the home is trusted for availability and order (`core-model.md`
§5); the owner's remedy is two devices' immediate removal and moving home.
Stated in `SECURITY.md`. (8.22)

**B9. The agent loses its quorum.** Sync and device changes stop; local
work continues. *Mitigation:* devices queue and retry; the lease is kept by
`Homes`, a different agent, so it does not lapse for that. (8.12)

**B10. A home with one replica** (a policy for small spaces) holds the
user's backup on one disk. *Mitigation:* the chrome shows the replica
count; devices remain full replicas. *Known limit* for durability against
the user losing every device at the same time as that disk. (8.12)

**B11. The pool runs out.** *Mitigation:* `Homes` answers `PoolEmpty`, the
keeper is alerted, the device stays local-only and retries. (8.12)

**B12. `Homes` assigns one agent twice** (a bug). *Mitigation:* assignment
is a Linear write in `Homes` checked unique; `Personal` refuses `assign`
while owned and not wiped. (8.12)

**B13. A recycled agent keeps its last tenant's residue.** *Mitigation:*
`wipe` clears every table before the agent returns to the pool; the
residue was ciphertext under keys the new tenant never sees; the last
tenant's devices find their keys absent from the new device set and are
refused. (8.12)

**B14. The member leaves or is removed from the home space.** Revoking the
pseudonym would link it to the member. *Mitigation:* the lease simply
lapses (no renewal proof is possible), the agent goes read-only for 30
days, then is wiped; the chrome warns well ahead and offers to move home.
(8.12)

**B15. The home space vanishes or turns hostile.** *Mitigation:* §3.9's
slice-8 path: claim elsewhere, a new group, re-pair, push everything;
nothing is lost while one device holds the data. *Known limit:* devices
must pair again by QR; the successor group with a resumption PSK is
carried to slice 9. (8.17)

**B16. A thief who passed the prompt moves the user's home** to a space he
runs. *Mitigation:* a handover is delayed and vetoable like a removal
(72 h) and signed end to end. (8.17)

### 8.3 Data, storage and quotas

**C1. A buggy or malicious device of the user writes garbage** that opens
correctly. *Mitigation:* apply validates each operation against its CRDT
type and schema; a node that fails is quarantined (kept in the DAG, not
applied) and the chrome names its author device. *Known limit:* excising a
device's range of operations after the fact is carried to slice 9; in
slice 8 the remedy is removing the device. (8.15)

**C2. The DAG grows without bound.** *Mitigation:* checkpoints at
deterministic boundaries and delayed collection (§3.6). (8.16)

**C3. Two devices checkpoint at once.** *Mitigation:* boundaries are
deterministic, so both checkpoints hold the same state; the second is
redundant and dropped by its inner hash on read. (8.16)

**C4. A rogue device collects history to erase it.** *Mitigation:*
`collect` needs a checkpoint a second device acknowledged and a 72 h delay
without a veto. (8.16)

**C5. Quotas fill** (the user's data, or a compromised device of theirs).
*Mitigation:* quotas per agent; a refused push keeps the device's queue
intact; the chrome says why and offers checkpoint-and-collect. (8.12)

**C6. Large objects.** A 1 MiB checkpoint is 17 envelopes and 17 push
calls under today's caps (64 KiB of arguments a call); large log entries
are the log's slow case.
*Mitigation:* chunking (§3.6), and plan 8.12's gate measures pushes of
full 256 KiB steps across many agents. A blob kind through the node's
blob store is the lever if it binds. (8.12, 8.16)

**C7. Inbox spam.** *Mitigation:* in slice 8 only the user's devices, the
agent, and a pairing slot's holder write; slots are single-use and last 10
minutes; 64 items at most. Others' messages, with sender tokens or proof
of work, come with messaging (slice 9). (8.12)

**C8. Sizes and timing describe the user.** *Mitigation:* Padmé padding,
opaque scope ids, the DAG's shape inside the ciphertext, jittered
background pushes. *Known limit:* counts and times remain; cover traffic
is not built. (8.16)

**C9. Two key archives at different epochs.** *Mitigation:* archives are
unions indexed by epoch; a device unions every archive it opens. (8.16)

**C10. Fetching old envelopes on demand reveals what the user reads.**
*Mitigation:* devices are full replicas and fetch everything on a
schedule, never on demand. *Known limit:* a device too small for a full
replica (a watch) is later work. (8.16)

**C11. The phone's storage fills.** *Mitigation:* the local store refuses
writes before the disk fills; sync pauses; the chrome says so. (8.15)

### 8.4 Recovery and the device's life

**D1. Every device is lost; the kit is kept.** *Mitigation:* §3.5's
restore: 7 days, then a new group from the archives; memberships
re-enrolled in each space by its registrar; P1 accounts moved by the
operator's `rekey`; P2 notes (slice 9) swept with keys sealed to the kit
if N4 is taken. *Known limit:* the kit holds keys, not data; the
recovery envelopes and the data are at the home, so a home that is gone
or withholding at that moment leaves the kit nothing to open. A second
home's mirror (slice 9) is the remedy. (8.17)

**D2. Every device and the kit are lost.** *Known limit:* the personal
space is gone; memberships and P1 accounts are recovered by each space's
ordinary process; P2 notes are lost. Stated at the claim. (8.17)

**D3. The recovery phrase leaks.** *Mitigation:* its operations wait 7
days, any active device vetoes them, and a device being removed by the kit
cannot veto its own removal; the user rotates the kit (two devices at
once, or one device and the 7 days). (8.17)

**D4. The kit points at an old home** after a move. *Mitigation:* the
phrase stays valid; the chrome shows the new pointer after every move and
asks the user to update the kit. *Known limit:* a user who never does must
find their agent in the old home's records or lose the backup. (8.17)

**D5. A device sleeps through a veto window** (a laptop off for a long
weekend; Doze deferring the job). *Mitigation:* 72 h for removals, 7 days
for the kit, both chosen against a device checking in at least every
couple of days; the chrome shows pending operations at the next open. No
push notification exists to wake it (L3). *Known limit:* a user whose only
other device sleeps longer than the delay cannot veto in time. (8.17)

**D6. Android kills the process mid-write.** *Mitigation:* the local log,
MLS state and push queue are each written in one fjall batch per step;
pushes and commits are idempotent (A10). (8.6, 8.16)

**D7. A local actor's new version changes its state's shape.** State
migration is unbuilt (`open.md`, "Upgrades"). *Known limit:* a local
actor that changes its CRDT schema starts a new scope and the device
re-imports; carried with upgrades. (8.15)

**D8. A format or kernel change needs an app update** (format 47's
re-pin). Proofs under the old format are refused. *Mitigation:* the light
node computes stock kernels' programs from code it ships and asks for an
update when the space's format moves; the chrome re-confirms a pinned
method when its installed kernel changes. (8.4, 8.10)

### 8.5 Cryptography's future

**F1. Harvest now, decrypt later.** Operators may keep every handshake;
with X25519 broken, they recover every epoch's keys and every envelope.
*Mitigation:* a hybrid post-quantum suite if mls-rs offers a maintained
one (checked in 8.3); otherwise ciphersuite 1 and a ReInit later; 180-day
retention of handshakes, which honest operators keep. *Known limit:* a
hostile operator keeps what it wants. (8.3, 8.16)

**F2. Changing the suite or the protocol.** *Mitigation:* a ReInit into a
successor group, the archives resealed under it, old envelopes left under
their keys; never two suites in one group. A successor group derives new
scope ids, so its envelopes are distinguished without a version byte.
(design; later)

**F3. RFC 9420's exporter is not forward-secure.** *Mitigation:* moot for
history, which the archive keeps on purpose; the derivation moves to the
Safe Exporter when mls-rs has it. (8.16)

**F4. An mls-rs defect, or a change in its state format.** *Mitigation:*
one pinned version a release, an upgrade step a slice; a state the new
version cannot read means re-pairing that device. (8.16)

### 8.6 Proving and payments

**G1. Proofs for spent nullifiers or junk proofs** cost the node a
verification each. *Mitigation:* the format's PoW checked first, the
verification budget answering `Busy`, as today (`node/SECURITY.md`).
(8.5)

**G2. A space installs a kernel that leaks a secret,** for example one
whose public claim must equal the member secret. The device would prove
it, publishing the secret. *Mitigation:* the light node puts a member
secret or a spending key only into kernels whose device programs it
computes from code it ships (the stock `auth` and `owner`, and in slice 9
cipher-clerk's spend), never into a kernel whose bytes a space serves;
other kernels may take only the user's public data. (8.4, 8.6)

**G3. A space upgrades the package holding a stock kernel.** Its program
id changes. *Mitigation:* the device compares the installed program with
its own computation; a mismatch refuses to prove and the chrome says the
space runs another version. (8.4)

**G4. Balances split per device** under P1 (E2). *Known limit:* a payment
comes from one device's account; consolidating is a visible transfer
(L4). P2's notes carry the same split, without the visibility. (8.7)

### 8.7 The network

**H1. The onion is flooded** before arti's service PoW is declared ready.
*Mitigation:* introduction-point limits, per-circuit and per-service
limits, a cap on proven calls in flight, the device format's PoW; the C
tor sidecar as the fallback (§9 Q11). (8.18)

**H2. Tor is blocked.** *Mitigation:* bridges and pluggable transports;
calls to a space may fall back to the clearnet by its policy; the personal
agent's traffic waits. (8.19)

**H3. arti's library breaks monthly.** *Mitigation:* one pinned version a
release, an upgrade step each slice. (8.18, 8.19)

**H4. A background job starts cold** (a 10–30 s bootstrap) and runs out of
time. *Mitigation:* arti's state persisted between runs; a job that does
not finish leaves everything consistent (D6) and the next resumes. (8.19)

**H5. A gateway's onion key is stolen.** The thief can impersonate the
gateway: read, drop and delay what it relays, as any gateway can; it
forges nothing (calls are signed, envelopes sealed). *Known limit:* the
address is pinned at enrollment; re-pinning needs the space's announcement
through another channel. (8.18)

**H6. Forwarding loops or amplification.** *Mitigation:* a forwarded
request is never forwarded again (the receiver answers `Elsewhere` if it
no longer replicates the agent); forwards count against the sending
node's per-peer budget. (8.11)

### 8.8 Linkability and membership

**L1. The claim follows the enrollment in time.** *Mitigation:* the
personal space starts local; the claim waits a random interval of up to a
day unless the user pairs or turns on backup sooner. (8.17)

**L2. One device acts as a member and as the pseudonym.** *Mitigation:*
separate Tor isolation groups per identity, keys used nowhere else,
decorrelated schedules (§3.10). (8.19)

**L3. Push-notification tokens identify the user.** *Mitigation:* none is
given to any space; devices poll. *Known limit:* fresher delivery waits
for a push relay that sees no agent ids, later work. (design)

**L4. P1 transfers between one's own devices** link their owner digests
for the operators. *Known limit:* P1 is pseudonymous; P2 removes it.
(8.7)

**L5. The device count is visible** to the home's operators (the device
set) and, in messaging, to other members. *Known limit* for the home;
MLS virtual clients hide it from other members later. (design)

**L6. `once` scopes with one leaf per device** let a member with three
devices vote three times. *Mitigation:* agents that use `once` install a
second credential ring of **person leaves**, one per member, held by one
of the member's devices and moved by re-enrollment; other scopes use the
device leaves (N3). (8.13)

**L7. The registrar learns which device leaves are one member's**
(`enroll_device`). It already knows each member; the tree still hides
which leaf proves. *Known limit,* stated. (8.13)

**L8. Path fetches and the logged `map_root`** link a member's proofs
(`open.md`, "Tree syncing"). *Mitigation:* the credential book syncs the
tree's leaves through a paged feed, so no path is fetched, and every proof
names the newest root. (8.20)

**L9. Lease renewals reveal the device count over time** (each device
renews under its own nullifier). *Known limit,* the same fact as L5.
(8.12)

### 8.9 Sources for the prior art

- Ink & Switch, Keyhive notebooks 01, 02, 05, 06 (2024-09 to 2026-07):
  https://www.inkandswitch.com/keyhive/notebook/
- Weidner, Kleppmann, Hugenroth, Beresford, "Key Agreement for
  Decentralized Secure Group Messaging with Strong Security Guarantees",
  CCS 2021: https://eprint.iacr.org/2020/1281
- RFC 9420 (MLS) and RFC 9750 (MLS architecture):
  https://www.rfc-editor.org/rfc/rfc9420.html ,
  https://www.rfc-editor.org/rfc/rfc9750.html
- draft-ietf-mls-extensions-10 (the Safe Exporter, 2026-07):
  https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions ;
  draft-ietf-mls-virtual-clients-01 (2026-07):
  https://www.ietf.org/archive/id/draft-ietf-mls-virtual-clients-01.html ;
  draft-kohbrok-mls-dmls-03 (2025-10):
  https://datatracker.ietf.org/doc/draft-kohbrok-mls-dmls/
- H. Chathi, "DMLS vs DMLS", FOSDEM 2026:
  https://www.uhoreg.ca/documents/fosdem-2026/__/dmls_vs_dmls.html
- XMTP XIP-68, fork recovery:
  https://improve.xmtp.org/t/xip-68-automated-fork-recovery/951 ;
  Cryspen on fork resolution: https://cryspen.com/post/mls-fork-resolution/
- any-sync's access control: https://sync.any.org/access-control/ ;
  p2panda-encryption: https://docs.rs/p2panda-encryption
- Signal's backups and linked devices:
  https://support.signal.org/hc/en-us/articles/10074659364122 ; Apple's
  Advanced Data Protection and Stolen Device Protection:
  https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f/web ,
  https://support.apple.com/120340
- Malicious-server attacks on E2EE cloud storage, CCS 2024:
  https://eprint.iacr.org/2024/1616
- Padmé padding, PoPETs 2019:
  https://www.petsymposium.org/popets/2019/popets-2019-0056.php

## 9. Open questions for the owner, and risks

### 9.1 New questions

Ranked by how much of the slice each one moves. Each has options and a
recommendation.

**N1. Move P2 (the shielded pool and the wallet) to slice 9?**
- (a) Slice 8 builds P1, the personal agent and Tor; cipher-clerk v0.4 is
  designed, built and released in its own repository during slice 8; P2
  (the pool, the wallet, the spend kernel, PG4) opens slice 9.
- (b) Keep P2 in slice 8 as E3 asked: the slice grows by about 8–11 weeks
  on its critical path (the wallet is a local actor on the personal space,
  so it follows all of M4), to about 30–36 weeks.
- **Recommended: (a).** The wallet needs the personal space finished
  (sync, pairing, the recovery key, since a lost device's notes are only
  recoverable through it, N4); P2's privacy rests on Tor and on the
  personal agent's unlinkability rules being in place first; and the
  slice is already the largest yet. E3's order (P1, then P2) holds; only
  the slice boundary moves.

**N2. Where sealed scopes live on the nodes?**
- (a) In the personal agent's replicated tables, written through its log
  (§3.6): durable, consistent, the epoch checked atomically against the
  device set and the MLS log; a commit per push at personal rates.
- (b) A node-side Merge store replicated outside Raft by gossip: no log
  entry per push, but a new peer protocol and durability path, and each
  push still consults the log for the epoch.
- **Recommended: (a).** It realizes E6 (nodes as durable ciphertext
  replicas) with no new node machinery; (b) is kept for plaintext scopes,
  where nodes merge what they read.

**N3. `once` scopes under per-device secrets (E2).**
- (a) A second credential ring of **person leaves**, one per member,
  held by one of the member's devices, in agents that use `once` (§3.8,
  L6); every other scope uses device leaves.
- (b) A nullifier key synced across the user's devices, so every device
  of a member derives the same nullifier: a secret that syncs, against E2.
- (c) Accept one vote per device.
- **Recommended: (a).** It keeps E2 and costs a second tree only where a
  space uses `once`.

**N4. Spending keys and recovery (decides the recovery kit's contents in
slice 8, used by P2 in slice 9).**
- (a) Each device's spending key `sk` is random, wrapped under a per-use
  keystore key, and sealed to the recovery key, so a lost device's notes
  are swept to a new device on restore.
- (b) Spending keys bound to hardware, like the member secret: a lost
  device's notes are lost.
- **Recommended: (a).** Cash-like loss is acceptable for a membership
  (re-enrollment fixes it), not for money.

**N5. The device-change parameters.**
- Proposed: probation 72 h; removing another device, a handover and a
  collection 72 h; the recovery key's operations 7 days; immediate with two
  active devices; the admin key behind strong biometrics only; a recovery
  kit required to claim a personal agent; handshakes retained 180 days.
- **Recommended:** these, each a constant of `Personal` a space cannot
  shorten, revisited after PG3′'s flows are timed on real use.

**N6. The MLS suite.**
- (a) Ciphersuite 1 (X25519) now, a ReInit to a hybrid post-quantum
  suite when mls-rs maintains one.
- (b) Make a hybrid suite a precondition of plan 8.16.
- **Recommended: (a), with 8.3 checking mls-rs first:** if a maintained
  hybrid suite exists at that step and fits the phone, take it then.

### 9.2 Draft 2's questions, taken at their recommendations

Provisional [E11]: each stands until the owner says otherwise.
- **Q4** is answered by E4–E10 (the personal agent).
- **Q5** (the light node's process): in s4's client process now, a
  separate `:vos` process when a second app needs the light node (§2.2).
- **Q6** (credentialed calls): generic proven calls,
  `#[msg(proven = k)]`, one ingress path (§4.3).
- **Q7** (SDK kernels as lean as hand-written): measured first, plan 8.2,
  the 1.15× gate; nothing in M2 starts before it.
- **Q8** (local workflows with device effects): glue in the light node's
  Rust for slice 8; a local `#[workflow]` with `ctx.prove` and
  `ctx.call_remote` later.
- **Q9** (the device prover outside `vos-pvm-recair`): a `recursion`
  feature on `vos-pvm-recair`, default on, the light node without it; no
  crate moves.
- **Q10** (the pool's integrity): the operators' for the in-space pool,
  stated in its documentation and chrome; a proved pool designed next.
  Moves with P2 (N1).
- **Q11** (arti for hosting): arti in the gateway behind a `tor` feature,
  PoW when a release declares it. The risk is a flood before then (§8,
  H1); the fallback, should it happen, is C tor beside the gateway
  (stable PoW, a second process and a C dependency, against the owner's
  "arti in the ingress"), kept documented and tested once in 8.18.
- **Q12** (note delivery): memos with view tags in the pool. Moves with P2
  (N1).

### 9.3 Risks

- **The slice's size.** Even with P2 moved, it is the largest so far
  (`slice-8-plan.md`, about 21–28 weeks on five streams); the personal
  space chain (8.6 → 8.15 → 8.16 → 8.17) is the critical path.
- **The Merge lane is unbuilt:** merkle-crdt has no dependent, the SDK
  has no CRDT fields, the incremental apply is a prototype (`core-model.md`
  §9.4). Slice 8 builds the device side and sealed scopes, not plaintext
  scopes on nodes.
- **MLS on the device is new code in a new place:** mls-rs on Android,
  its state under the keystore's keys, a delivery service written as an
  actor. The `messaging` branch built mls-rs for VOS before, in another
  architecture; its storage providers and the one-commit-an-epoch rule
  carry over, nothing else.
- **10^4 personal agents waking a few times an hour** are unmeasured
  (idle agents are: `core-model.md` §14.1); plan 8.12's gate measures them.
- **Proof bytes over Tor** dominate a call's latency (§6.3).
- **cipher-clerk v0.4 is a redesign** of a not-for-value prototype; its
  notes stay not for value until the external audit (`proving.md` §4).
- **Android's background limits** bound how fresh a backgrounded device
  is and how fast it sees a pending removal (§8, D5).
