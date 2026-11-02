# The light node, the personal agent, one proving path and Tor

Design, draft 4 [proposed]. The architecture of slice 8
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

**Changes from draft 3** (its Opus review):
- **Device changes are symmetric:** a target keeps its rights and may
  veto; a contested removal is resolved only by two other devices or the
  recovery kit (§3.5).
- **Key-confirmed epochs** replace void epochs: no data is sealed under an
  epoch until every device in it has confirmed the same keys; a `nack` or
  a timeout voids the commit; proposals are allow-listed (§3.4).
- **The lease is kept by activity,** with membership proven at the claim
  only; an agent is reaped after 360 days unused, and the kit's calls
  count (§3.3).
- **The kit is split:** recovery envelopes at every confirmed epoch, under
  a wrap key whose second half the agent releases only to a matured
  restore, so a leaked kit alone reads nothing (§3.5).
- **Sync keys work after the first unlock,** so background sync runs on a
  locked phone; the device-clock floor is gone (§3.5).
- **Only known keys open sessions** at a personal agent; forwarding has a
  hop rule and its own lane (§3.3).
- **Checkpoints are cut at the agent's positions** and trusted once two
  other devices acknowledge them; history horizons, garbage collection
  and live handover move to later work (§3.6, §3.9).
- **The light node has no log:** local actors are Merge-only, so it runs
  merge and query dispatch over its store, with no refine, accumulate or
  carve-out of `vos-node` (§2.1).
- **E5 restated** against the home's operators, with what they can still
  correlate (§3.10).
- P2 in slice 8 with a device-local wallet, off the critical path, is now
  the recommendation (N1 (c)); MLS against a simpler scheme is asked
  (N7).
- The plan's large steps are split and re-estimated (`slice-8-plan.md`).

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
| E3 | Payments P1 (cipher-clerk's ledger with owner proofs, replacing `purses`) then P2 (the shielded pool and a local wallet), both in slice 8; N1 weighs how. |
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
   (§5). P1, pseudonymous, and P2, private, both in slice 8, P2's wallet
   on each device alone until slice 9 syncs it (N1 (c)).
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

- A wallet synced across devices: P2's wallet stays on the device that
  holds its notes in slice 8 (N1 (c)); slice 9 syncs it.
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
| **merge and query dispatch** | local actors are Merge-only (`#[msg(merge)]` handlers and `&self` queries; `core-model.md` §9.2: a merge handler runs on "any replica or device, no log"), so the light node runs the agent program's merge and query entries over its store, one fjall batch per operation; no refine, no accumulate, no work results, sessions or sweeps; no Raft, no leader, no peers | the executor's host-call layer, reused from `vos-node` without its pipeline (§7.1) |
| **the transpiler** | turning a local actor's ELF into a PVM program, and computing the stock kernels' device programs from the code the light node ships (§4.4) | `vos-pvm-compiler` [built] |
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
  without notice, so each local operation (with its DAG node), each
  change of MLS state and each change of the push queue is committed in
  one fjall batch (§8, D6).
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
  one system actor, `Personal`, installed. It orders the few operations
  that need one order (the device set, the device group's commits),
  stores the user's sealed DAG nodes durably on every replica [decided,
  E6], and holds an inbox. It never holds a key that opens the user's
  data.

Devices sync with the personal agent, never with each other directly in
slice 8; the agent is where two devices that are never online together
meet. Any gateway of the home space reaches it (§3.3).

**Local first:** a new user's personal space starts on one device with no
personal agent. The agent is claimed when the user pairs a second device
or turns on backup.

**The first local actors:**
- the credential book: the spaces the user is a member of, each device's
  handles there, the pinned agents and methods s4's facility pins today.
  The member trees a device keeps for its proofs (§6.7) stay on the
  device, outside any synced scope: a space's whole tree has no place in
  the personal agent;
- the device book: labels and settings of the user's devices (the device
  set's authority is the personal agent's log, §3.5; this is its
  user-facing mirror).

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
  (grow-only). Storage-backed, as `core-model.md` §9.4 requires, and
  **stored per author:** a map keeps the latest write per (key, author)
  and a read takes the latest among authors not filtered out
  (`core-model.md` §9.4, rule 6), so a removed device's writes that a
  device applied before it learned of the removal are filtered at read,
  never unapplied (§3.5's frontier).
- **The conflict model** is the types' own: concurrent adds both stay, a
  remove wins only over the adds it observed, a map key's later write wins
  by (counter, author). No operation needs another device's agreement.
- **Where conflicts are real, a log decides:** the device set and the
  device group are ordered by the personal agent's log (§3.4, §3.5); a
  payment is decided by the space that holds the ledger.
- **Authorship:** each device signs the DAG nodes it authors with its
  sync key (§3.5). merkle-crdt's `DagNode` has no author field
  (`support/merkle-crdt/src/node.rs`), so the author's key, sequence
  number and signature travel inside the payload, which is sealed (§3.6).
- **Operations are versioned:** an operation of a kind a device does not
  know (a newer app on another device) is kept and applied once the
  device updates, never quarantined as garbage, so devices on different
  app versions do not diverge.
- **Incremental apply** [decided, `core-model.md` §9.4]: merkle-crdt's
  DAG and format are reused and its apply path rewritten to apply only
  newly fetched nodes in causal order (about 1.9 µs an operation at 1M
  operations, against 8.7 s for today's full rebuild [measured,
  `core-model.md` §9.4]).

### 3.3 The personal agent: claimed, reached, kept

**Agents exist only by an operator's command today** [built]:
`CreateAgent`, `Install` and `Grant` are operator kinds
(`node/api/src/lib.rs`, `Kind`), the operator names the replicas
(`node/host/src/node/admin.rs`, `create_agent`), no actor can create an
agent, and no agent is ever deleted. Rather than give actors that power,
the design uses a **pool of agents the operator makes ahead of time**:
- **`Homes`**, a system actor installed in the agent that already holds
  the space's credential actor (an `Auth` guard reads the ring of the
  agent it guards, `node/host/src/credentialed.rs`, so `Homes` must live
  beside it). It keeps the pool: agent ids the operator created with
  `Personal` installed and handed over with `homes.stock(ids)`, an
  operator-role call.
- **The operator's keeper** (a small tool in `tools/`, holding an
  operator key) tops the pool up in bulk: it creates agents, installs
  `Personal`, and grants `Principal::Agent(homes)` the role under which
  `Personal` takes `assign` and `wipe` (`Grant`; `Install` carries no
  configuration, `agent/wire/src/ingress.rs`). Creating an agent costs
  about 2 s, 0.15–0.17 s each sixteen at a time [measured,
  `core-model.md` §14.1], so a pool of a few hundred hides creation from
  users, and an agent's creation time says nothing about its owner. The
  keeper also upgrades `Personal` in every pooled and assigned agent, in
  bulk, when a new version ships.
- **The claim** is a credentialed call, `homes.claim(keys, kit)` under
  `#[msg(credential = Auth("home"))]`: a member proves membership
  anonymously; the pseudonym is the nullifier of scope "home" (stable for
  that device and space, unlinkable to its `member` digest,
  `identity-and-authority.md` §7). It is the agent's owner [decided, E5;
  E5's scope is this "home" scope]. `Homes` refuses a nullifier that
  already holds an agent, assigns a pooled agent, records it under the
  nullifier and under `H(the recovery public key)` (`kit`; §3.5), and
  sends the agent `assign(keys, kit)`: the claiming device's sync and
  admin keys and the recovery kit's public keys, which seed the device
  set. `Command::send` is one-way (`agent/sdk/src/context.rs`), so
  `Personal` answers with a message of its own, `assigned` or `refused`,
  and `Homes` releases a refused assignment.
- **"home" is reserved:** the light node proves in that scope only for
  its own claim, and the facility refuses any request naming `Homes`'
  agent and instance, so a space's page cannot make a device publish its
  home pseudonym in the member's context.
- **Kept by activity, not by proofs** [proposed]: membership is proven
  once, at the claim. After that, any call or query a device-set key
  makes counts as activity (`Personal` records the batch time of the
  last one; no proof, no prompt). An agent with no activity for 360 days
  may be reaped: the keeper calls `Personal::reap`, which succeeds only
  then, wipes every table and tells `Homes`, which returns the agent to
  the pool. The check is lazy: nothing runs on a timer, so idle agents
  stay idle (`node/host/src/leader/cut.rs`). A recovery key's call is
  activity too, so a kit stays good for 360 days after the last use of
  any device (§3.5). **No agent is deleted; an unused one is recycled.**
  A recycled agent's tenancy number goes up, so a returning device of
  the old tenant sees "recycled", not a rollback (§8, B13).
- **What activity does not check:** whether the owner is still a member.
  A member who leaves the space keeps their personal agent while they use
  it; the operators cannot evict it without knowing whose it is, which is
  the point of the pseudonym. Space policy bounds it by quota, and a
  periodic re-proof (say yearly, at a sign-in the user makes anyway) is a
  later option (§8, B14).
- **Replicas:** three by default, the space's policy; a pooled agent's
  replica count is fixed when the keeper makes it (`replace` keeps the
  count, `admin.rs`). One replica is allowed by policy for small spaces
  and stated in the device's chrome (§8, B10).
- **Its cost:** about 46 KiB and 1.6 µs/s a replica when idle, 130–140
  KiB an agent across three replicas [measured, `core-model.md` §14];
  10^4 users on a three-node space is about 0.45 GiB of memory and 1.6% of
  a core a node [est]. Storage: a 64 MiB quota an agent by default (§3.6),
  so 10^4 full agents on three replicas is up to about 1.9 TB a space, and
  a Raft snapshot of a full agent is 64 MiB. Unmeasured, and the plan's
  scale gate: 10^4 agents that wake for a few calls an hour, their
  sessions, a full agent's snapshot and a `replace` (plan 8.15).

**Any gateway reaches it: nodes forward** [proposed]. Today a node that
does not replicate an agent answers `Elsewhere { replicas }`
(`node/host/src/node/mod.rs`, `absent`) and a gateway retries only among
the nodes in its own configuration, so a gateway that lists none of an
agent's replicas cannot reach it. Two fixes were weighed: gateways that
learn placement and keep a connection to every node (their configuration
grows with the space), or **nodes that forward** [chosen]:
- A node that does not replicate the agent sends the client's request
  **as received**, before ingress, to one of the replicas, and relays
  the answer. Only a replica holds the agent's ring to verify a
  credentialed call, so the replica that takes it runs ingress as for a
  gateway's request. Every node already knows every agent's placement
  (`node/host/src/node/directory.rs`).
- **The hop rule:** a non-replica forwards once; a replica never forwards
  to a non-replica. A replica that is a follower uses the existing
  `PeerMessage::Forward` and `ForwardCredentialed` to its leader
  (`agent/wire/src/peer.rs`), as for a gateway's request. So a request
  crosses at most two hops inside the operator's network.
- **Its lane:** forwarded requests (a credentialed one up to 1.6 MB) go
  on a peer stream of their own, never on the lane that carries Raft and
  heartbeats (`peer_lanes`), so a burst cannot delay an election.
- **What is never forwarded:** operator kinds (an `Operated` envelope
  names its node, `node-api.md` §4). A forwarded request counts against
  the forwarding node's budget toward that peer.
- Gateways stay as they are, and every agent, not only personal ones,
  becomes reachable through any gateway.

**Only known keys open sessions** [proposed]. Any ed25519 key may open a
session at any agent today, up to `MAX_SESSIONS` (65,536,
`agent/wire/src/defaults.rs`), each a commit, and pooled agents' ids are
sequential (`AgentId`, `agent/wire/src/peer.rs`), so over the onion,
which hides addresses, anyone could exhaust a user's sessions or fill its
log. An agent may set **admission by known keys:** ingress refuses a
session-creating call from a key absent from the agent's admitted-keys
rows, before any commit, as it reads the credential ring today.
`Personal` sets it and admits the device set's keys, the recovery key and
open pairing slots' keys. Gateways add a cap of calls per agent per
circuit (§6.6).

**Sessions:** a device's calls are signed by its sync key. A session
expires after an hour idle (`SESSION_EXPIRY_MS`), so a background job
opens one per run (a commit, then a sweep): at 10^4 users syncing four
times an hour, about 11 session commits a second across a space [est].
Queries need no session.

### 3.4 Keys: MLS among the user's devices, with confirmed epochs

**The device group** [decided, E7]: one MLS group (RFC 9420) per user,
its members the user's devices, each a leaf whose credential is the
device's sync key and admin key (§3.5). mls-rs runs on the light node's
host side, natively; the node never runs MLS, parses it or holds its
keys. Encrypted handshakes (MLS `PrivateMessage`) and padding. §9.1 N7
weighs MLS against a simpler scheme for this group.

**The personal agent orders the group's commits** (RFC 9750 §5.2.1's
"strongly consistent" delivery service; the rule is the `messaging`
branch's `msg-ctl`'s):
- A commit is a call, `Personal::commit(epoch, effect, handshake,
  welcome)`, under a device's sync key. The agent accepts it as the
  **candidate** for `epoch` only if `epoch` is the confirmed epoch plus one
  and no candidate is pending, refusing `EpochTaken` or `EpochGap`; the
  loser rereads and re-proposes.
- **Allowed proposals:** Add, Remove and Update, nothing else; no ReInit,
  no external commit or external join, no PSK, no group-context change.
  A commit's effect is declared in clear (`update`, `add(d)`,
  `remove(d)`); an `add` or `remove` must name a device-set operation
  that has matured, admin-signed (§3.5), which the agent checks.
- **Never ahead of the log:** a device processes a candidate but keeps its
  prior state until the epoch is confirmed (mls-rs's pending commit,
  applied on confirmation), the first cause of forks in deployed MLS (§8,
  A9).

**Key-confirmed epochs** [proposed]: an epoch's keys are used only once
every device in it has shown it holds the same keys.
- After a candidate, every device in the new epoch (the old set, minus a
  removed device, plus an added one) posts, signed end to end by its sync
  key, either `confirm(epoch, h)`, `h = BLAKE2b-256("vos/personal/confirm"
  ‖ agent ‖ epoch ‖ epoch_authenticator)`, or `nack(epoch)` if it cannot
  process the commit.
- **Confirmed:** every device in it has posted `confirm` with the same
  `h`. Each device checks the others' signed confirmations itself; the
  agent's verdict is advisory.
- **Void:** any `nack`, two different `h`, or 72 h without every
  confirmation. Every device drops the candidate and stays on the prior
  epoch; the agent flags the committer in the device set; the epoch
  number is free again.
- **Data is sealed only under a confirmed epoch.** So a commit that is
  valid for some devices and not for others (a committer encrypting good
  path secrets to one subtree and garbage to another) is voided by the
  others' `nack`, and nothing is ever sealed to one side alone. An
  operator showing two devices two different commits gets two different
  `h`, signed by devices it cannot impersonate, and the epoch is void.
- **The cost:** one signed call a device per epoch; epochs change only at
  device changes and updates. A device asleep for more than 72 h voids
  every commit until it returns or is removed (its removal needs no
  confirmation from it, §8, A5). Data keeps flowing meanwhile under the
  confirmed epoch: a device just added reads and writes through the
  archive it received at pairing (§3.8), so only the key change waits.
- **Between a removal's maturity and its confirmed epoch,** the agent
  already refuses the removed device's keys (§3.5); only an agent that
  serves a removed device anyway (its operators colluding with it) could
  hand it data sealed under the prior epoch (§8, B8).

**Retention:** the agent keeps handshakes and confirmations for 180 days;
a device offline longer re-pairs (§8, A5). It keeps no plaintext group
information; the group's public state lives on the devices. Retention
also bounds what a "harvest now, decrypt later" adversary can take from a
log, if the operators honour it (§8, F1).

**The data keys** [decided, E7; prior art: Keyhive's causal keys,
any-sync's key chain, p2panda's data scheme]:
- `k(scope, n) = MLS-Exporter("vos/personal/scope", scope_id, 32)` in
  confirmed epoch `n`. One key a scope and epoch, so delivery order does
  not matter, unlike MLS's per-message ratchet, which a CRDT's unordered,
  repeated delivery would break. When mls-rs offers the Safe Exporter
  (draft-ietf-mls-extensions), the derivation moves to it, `scope_id` its
  component; the scheme is the same.
- **Scope ids** are `BLAKE2b-128("vos/personal/scope-id" ‖ naming ‖ name)`,
  `naming` a random secret drawn when the group is created and carried in
  the archive, so a device that joins at any epoch finds every scope
  (a device that joins cannot run an earlier epoch's exporter).
- **The key archive:** every past `k(scope, ·)` and the naming secret, a
  union indexed by epoch, sealed under the current epoch's key and pushed
  by the committer once an epoch is confirmed, or by any device that
  finds it missing (32 bytes a scope an epoch; duplicates are harmless).
  A new device receives the archive over the pairing channel (§3.8) and
  thereafter from the agent. Two archives that disagree on a key are kept
  whole: every candidate key is tried, and the AEAD decides (§8, C9).
- **No forward secrecy for history, by design:** the personal space must
  let a new device read the past, so whoever holds the current epoch's
  key holds every older one. Post-compromise security holds for new data:
  a removed device learns no key after its removal. Forward secrecy by
  history horizons (dropping old keys and envelopes) is later work.

**The suite:** MLS ciphersuite 1 (X25519, AES-128-GCM, SHA-256, Ed25519)
unless mls-rs offers a maintained hybrid post-quantum suite by plan 8.3
(N6); a later change is a successor group, its archive resealed, old
envelopes left under their keys, never two suites in one group (§8, F2).

### 3.5 Device secrets and the rules for changing devices

**Per device** [decided, E2]:

| secret | what for | wrapped at rest under |
|---|---|---|
| the member secret `s` of each space | membership proofs (auth, owner) | none: derived at each use from the keystore's HMAC over the space's handle, behind the user's prompt (a biometric or the PIN), as today [built, `identity-and-authority.md` §7] |
| the **admin key** (ed25519) | signing device-set operations | a keystore key requiring authentication at every use: a strong biometric (`BIOMETRIC_STRONG`, no PIN) on a phone that has one; the PIN otherwise, which makes the device a **delayed admin** (below) |
| the **sync key** (ed25519) | the device's client key at the personal agent; signing the DAG nodes it authors and its confirmations | a keystore key usable **after the first unlock** since boot, with no per-use authentication and no unlocked-screen requirement, so a background job runs on a locked phone |
| the MLS state and the key archive | sealing and opening envelopes, processing commits | the same after-first-unlock key; kept out of Android's backups (§8, A11) |

- **Why the bars differ:** a sign-in or a P1 transfer is one action the
  user sees; membership changes are lasting control of every device's
  data. The member secret keeps its decided PIN fallback; the admin key
  does not. A shoulder-surfed PIN therefore lets a thief sign in and pay
  from P1 (`rekey` and the space's limits are P1's remedy) but not take
  the personal space (§8, A4; N5).
- **Delayed admins:** a device whose phone has no strong biometric
  administers with its PIN, and every operation it signs, adds included,
  waits the 72 h delay and can be contested. A user whose devices are all
  delayed admins can still pair: the new device simply joins 72 h later.
- **After first unlock:** a phone powered on and unlocked once since boot
  can use the sync key and the MLS state while its screen is locked; a
  thief who keeps it powered and runs code on it (an OS exploit, forensic
  tools) reads the personal space. Before the first unlock nothing opens
  (§8, A2).

**Operations are signed end to end:** every device-set operation (add,
remove, veto, resolve, kit rotation, the recovery key's restore) carries
its signer's ed25519 signature over `(agent, operation, the control log's
head)` and is sent as a call under that key's own session. The agent
checks the session at ingress and stores the signature; **every device
verifies every signature itself** before acting. The operators run
ingress and could append anything to the log, so a device trusts an
operation only by its signature (§8, B6). No guest verifies a signature.
Delays run on the agent's batch time alone, the same for every device; a
device whose clock disagrees with the agent's by more than an hour raises
an alarm and otherwise acts as the log says (§8, B7).

**The device set** is a table in `Personal`, written only through its
log: each device's sync key, admin key, admin class (strong or delayed),
a sealed label and a state: **probation** (72 h from its add: it may sync
and post its own updates and confirmations, not sign operations),
**active**, or **removed** (with its frontier).

**The rules** [proposed; symmetric, with one tie-break]:
1. **Add** (pairing, §3.8): signed by an active strong admin, immediate;
   the new device is in probation for 72 h. Signed by a delayed admin, it
   waits 72 h first.
2. **Remove `d`:** signed by an active device, it is **pending** for 72 h,
   then matures unless contested.
3. **Being targeted suspends no right:** a device with a removal pending
   against it keeps every right, its own veto included.
4. **Veto:** any active device, the target included, may veto a pending
   removal; the removal becomes **contested** and does not mature.
5. **A contest is resolved** only by two active devices other than the
   target signing `resolve`, or by the recovery key, which acts at once in
   a contest. Two removals aimed at each other (thief and owner) are one
   contest.
6. **Immediate removal:** two active devices other than the target sign
   it.
7. **The recovery key's own operations** (restore, kit rotation, removal)
   wait 7 days and are **cancelled** by any active device's veto: a leaked
   kit alone can neither win a contest nor start one it could resolve.
8. **Probation devices** cannot sign operations or veto; they are removed
   like any device.

*The honest limit:* a thief who passes the owner's strong biometric holds
an active device and can always contest. The owner wins with one device
and the kit, or with two other devices. With the kit alone (every other
device lost) the owner cannot win: the kit's operations are cancelled by
the thief's veto, which is exactly the protection a leaked kit needs, and
the two cases look the same to the agent. With neither, nobody wins
(§8, A4).

**The removal frontier:** when a removal matures, the agent records, for
each scope, the position of the removed device's last accepted envelope;
its envelopes after that are invalid, and its writes before it stay
(filtered at read only if a later rule says so, §3.2). The frontier is
the agent's word, so operators colluding with a removed device could
place backdated writes before it (§8, B8).

**The recovery kit** [proposed; prior art: Signal's recovery key, Apple's
recovery key and security delay]:
- Drawn at the claim, required for it: 32 random bytes shown once as a
  24-word phrase, beside the home space's handle and its current onion
  addresses. The kit's public halves (ed25519, X25519) enter the device
  set as a **recovery entry**, not an MLS leaf (never online, it would be
  a stale leaf every commit encrypts to). `Homes` indexes the agent by
  `H(recovery public key)`, so the kit needs no agent id: restore looks
  the agent up, and a new home registers the same hash.
- **A split wrap key:** at the claim the device draws a recovery wrap key
  `R` and splits it, `R = R1 ⊕ R2`. `R1` is sealed (HPKE) to the kit's
  X25519 key and kept at the agent; `R2` is kept at the agent in clear,
  released only to a matured restore. The devices hold `R` in their
  archive.
- **Recovery envelopes, at every confirmed epoch:** the committer pushes
  that epoch's new scope keys (and, at first, the naming secret), sealed
  under `R`, a few hundred bytes, into a scope of their own, so the kit's
  copy of the keys never lags the data (§8, D1).
- **What a leaked kit can do:** nothing at once. It opens `R1` but not
  `R2`; it can only post a restore, which waits 7 days, shows on every
  device and is cancelled by any of them. Operators alone hold `R2` but
  not `R1`. **Operators and a leaked kit together read everything and,
  under N4 (a), spend every device's notes** (§8, D3).
- **Restore** (every device lost, §8, D1): a fresh install enrolls in
  the home space as a member device by the registrar's ordinary process,
  reads the kit, finds the agent by `H(recovery public key)`, and posts
  `restore` with the kit. After 7 days unvetoed, the agent releases `R2`;
  the device opens the recovery envelopes, removes every old device, starts
  a new group as its only member (the agent's control log restarts under
  it), reseals the archives, and its own keys become the device set. The
  kit's calls are activity, so the agent is not reaped meanwhile (§3.3).
  **Restoring elsewhere:** the same restore at the old agent releases
  `R2`; the new group lives at an agent claimed in another space, and the
  data is fetched from the old one.
- **Kit rotation** is an operation: a new kit, a new `R`, a new `R1`,
  and the old `R2` deleted, so the old phrase opens nothing. Signed by
  two active devices it is immediate; by one it is pending 72 h and
  contestable, so a thief with the biometric cannot quietly lock the
  owner's kit out (rule 2–5 apply).

**What the control log shows the operators:** the device count and its
changes, each device's public keys and admin class, the times of device
changes, commits and confirmations, contests, and the recovery entry.
Not the labels, not the data. §3.10 says what that lets them link.

### 3.6 Sealed scopes: storage and sync

**An amendment to `core-model.md` §9.4:** a sync scope is either
- **plaintext** (§9.4 as designed: nodes validate and apply operations,
  author chains, epoch nodes emitted by Linear steps): not built in slice
  8; or
- **sealed** [this design]: the scope's DAG nodes are ciphertext to every
  node; devices validate (signatures, the device set, frontiers) and
  apply; nodes store, order and serve envelopes, and enforce what they
  can see (who may push, the epoch, quotas). `core-model.md` §9.4's
  authorization rule runs on the devices, against the personal agent's
  control log in place of epoch nodes: an author is valid if its sync key
  was in the device set (probation, active, or with a removal pending)
  when its envelope was accepted, and within its frontier if later
  removed.

**Where the envelopes live: the personal agent's replicated tables,
written through its log** [proposed; N2]. A node cannot apply what it
cannot read, so `core-model.md` §9.4's node machinery (merge dispatch on
replicas, gossip between nodes) does nothing for a sealed scope; what a
sealed scope needs is durable replicated storage and an atomic check of
each push against the confirmed epoch and the device set. The agent's log
gives both; every push is a commit at a personal rate. A node-side Merge
store, replicated outside Raft, stays the design for plaintext scopes.

**An envelope:**
```text
envelope  = header ‖ sealed
header    = { scope: [u8; 16], epoch: u64, len_class: u8 }   (clear; AAD)
sealed    = XChaCha20-Poly1305(k(scope, epoch), nonce, Padmé(body), AAD = header ‖ agent id)
body      = { author: sync key, seq, signature, parents: [cid], ops, view }
view      = { log_index, log_chain }   (the writer's view of the agent's control log)
```
- **No structure in clear:** parents, author, CIDs and operations are
  inside; the operators see sizes (padded, Padmé: at most 12% overhead),
  times and opaque scope ids, not the DAG's shape (prior art: Beelay leaves
  heads and parent hashes in clear).
- **An envelope's id** is the BLAKE2b-256 of its bytes. A device keeps
  the sealed bytes in its push queue and reseals only after `StaleEpoch`,
  and the agent deduplicates by id before checking the epoch, so a retry
  is never stored twice (§8, A10).
- **Size:** at most 60 KiB an envelope, under `cap::VALUE` and
  `cap::REQUEST` (64 KiB each, `agent/wire/src/abi/cap.rs`); a larger node
  or checkpoint is chunked. A push call carries 64 KiB of arguments: one
  full envelope or several small ones; pushes pipeline, 16 in flight on
  one channel.

**Seal at push, not at write** [prior art: DCGKA's dominating update]:
a device keeps its unsynced operations in its local store and seals them
only when it pushes, under the confirmed epoch it read just before.
`Personal::push` refuses another epoch (`StaleEpoch`). So a device that
wrote offline while another was removed cannot hand the removed one new
data under an old key.

**Sync is a cursor:** the agent numbers a scope's envelopes in the order
it accepts them; `Personal::since(scope, position)` is a query returning
up to 64 KiB of envelopes from a position, so a device catches up in a few
pipelined queries. Positions reveal only the arrival order the operators
see anyway. With the agent ordering every envelope, the DAG's parents
serve causal integrity inside; merkle-crdt's walk is not needed for
transport.

**Fork and rollback detection** [prior art: XMTP's commit logs, SUNDR's
fork consistency]: the agent's **control log** is its device-set
operations, commits and confirmations in log order. Each device keeps the
highest `(log_index, log_chain)` it has seen (`log_chain` a hash chain
over the entries, signatures included) and refuses a log that is shorter
or diverges; every envelope carries its writer's view inside, so a device
that opens an envelope whose view conflicts with its own raises an alarm.
Confirmed epochs (§3.4) already stop an operator from splitting the keys;
views catch a split of the device set's history. Nodes sign nothing a
device can show a third party, so detection is not proof (§8, B4).

**Checkpoints at the agent's positions** [proposed]:
- a checkpoint is a scope's state after every envelope at or before a
  position `P` whose causal past is complete; every device that has read
  to `P` computes the same state, whatever order it received envelopes in;
- the author pushes it sealed (chunked) with `P` and its state's hash
  inside; another device that recomputes the state at `P` and matches
  posts an acknowledgement, signed by its sync key;
- a new device accepts a checkpoint acknowledged by two devices other than
  its author, or replays from the start; a wrong checkpoint (a buggy
  device, a sync-key thief) is never acknowledged and so never trusted.
- Deleting what a checkpoint covers (garbage collection) is later work:
  the quota lasts.

**Quotas** (per agent; the space's policy; enforced by `Personal`):
bytes held (64 MiB by default), envelopes and commits a day, inbox items.
Admin-signed operations, the commits that carry matured ones, and
confirmations are exempt, so no device can block its own removal by
filling a quota. Each device also has an unadvertised share (at most half
the agent's bytes and calls), so one device cannot starve the others. A
refused push keeps the device's queue intact and the chrome says why. Not
per device in what the operators see: a visible per-device limit would
tell devices apart.

**Background sync:** a WorkManager job, in a random minute of its window,
pushes queued operations, reads the control log and each scope's cursor,
applies, and stops; it raises a local notification (no push service
involved) when a device-set operation is pending. Personal-agent traffic
goes only over Tor, on its own circuits (§6.2).

### 3.7 The inbox

A table in `Personal`, keyed by `(expiry, id)`. **Expiry is lazy:** reads
skip expired items, and each write deletes a few expired ones; no timer
runs.
- **Who writes** in slice 8: the user's devices (notes to one another),
  and a pairing slot's holder (§3.8). Others' messages (member messaging)
  wait for slice 9, with sender tokens or proof of work against spam (§8,
  C7).
- **Who reads:** the user's devices, by their sync keys; a pairing slot
  by its two parties.
- Items are sealed to the device group, or to a pairing slot's key; the
  operators see counts, padded sizes and times.
- **Bounds:** 64 items, 16 KiB each, a TTL of at most 7 days, pairing
  slots 10 minutes and single-use.

### 3.8 Pairing a new device, and its memberships

1. **The existing device** (A, active) opens a pairing slot
   (`Personal::pair_open`, under A's admin key, behind the prompt): a
   random slot id, a slot key the agent admits for that slot alone, a
   10-minute TTL. A shows a QR code: the home's onion addresses and its
   handle, the slot id and key, A's ephemeral X25519 key, and a 128-bit
   code.
2. **The new device** (B) scans it, draws its sync key, admin key and an
   MLS KeyPackage, and runs `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b` with A
   through the slot, the code its pre-shared key. The code never crosses
   the agent, so an agent that substitutes keys fails the handshake.
3. **Over the Noise channel,** B sends its public keys and KeyPackage; A
   sends the key archive, the naming secret and `R` (§3.4, §3.5), so B
   has history even if A is lost a moment later.
4. **A adds B:** `Personal::add(B's keys)`, admin-signed, then the commit
   adding B with B's Welcome; B confirms the epoch with the others, and
   is in probation.
5. **B joins:** fetches each scope's newest acknowledged checkpoint and
   the envelopes after it, and applies.
6. **B's memberships** (E2: each device has its own secrets): B needs its
   own leaf in each space the user belongs to. The registrar's
   `enroll_device(member(s_B), owner(s_B))` is called by A under
   `#[msg(credential = Owner)]`; the registrar keeps a person record
   (member and owner digests of each device, their count, its
   per-member limit), which a credential actor alone cannot (member and
   owner digests are unlinkable by design). **When:** not right after
   pairing, but at A's next ordinary sign-in in that space, on the same
   prompt, so an enrollment in the home space does not follow a device
   change at the personal agent by seconds; the chrome offers "enroll
   now" for a user who accepts that link (§3.10).
   - **`once` scopes and several leaves:** a member with three device
     leaves has three nullifiers in a `once` scope (a vote). Agents that
     use `once` read a second ring of **person leaves**, one per member,
     held by one device and moved by re-enrollment; their guard names the
     ring (§8, L6; N3).
   - P1's accounts are per owner digest, so per device (§5.2).

**Removing a device** is §3.5's removal, its commit, and, in each space,
`registrar.revoke_device` at the user's next sign-in there.

### 3.9 Home spaces: several, and a lost home

**Several homes** [decided, E8: allowed, one built]. A second home is
another personal agent holding the same envelopes, a replica the devices
push to as well. **Exactly one home orders the group;** two logs ordering
one MLS group would fork it. A second home mirroring the first's control
log, and a live handover from one home to another, are later work (§9.4).

**A lost home** (the space vanishes, turns hostile, or the user wants out):
devices are full replicas, so nothing is lost but the agent. The user
claims an agent in another space, creates a new group from one device,
pairs the others again (QR), and pushes everything. The old operators keep
what they held; deletion there cannot be verified.

### 3.10 What the operators see, and the door to messaging

**E5, stated against the home's operators** [decided, E5; restated]: the
personal agent is owned by a pseudonym that outsiders and other members
cannot link to the member. **The home's operators can,** when the home is
also a space where the user is a member (the usual case), by correlating:
- device changes at the agent (adds, removals, restores) with the
  registrar's device enrollments and revocations for one person, and the
  device count at the agent with a person's device count at the
  registrar (deferring enrollments to sign-ins, §3.8, blurs the timing,
  not the counts);
- sync times with sign-in times: foreground sync starts when the user
  opens the app, which is when they sign in (§8, L2);
- the claim with the member's first sign-ins (the claim needs the user's
  prompt, so it cannot be moved to a random moment without asking the user
  again).

A home that is not one of the user's other spaces (E8 allows it) removes
the first item. The chrome recommends one when the user's spaces offer it.

**They see:** that a personal agent exists and when it was assigned, its
activity, its device set's public keys and changes, envelope counts and
padded sizes per opaque scope, and the recovery entry. **They do not
see:** the data, the scopes' names, the DAG's shape, or the devices'
addresses. They can withhold, delay, roll back or equivocate, which
devices detect (§3.4, §3.6), and delete, which devices survive (they are
full replicas).

**Linkability rules** [decided, E10]:
- sign-in, owner and spend proofs go from the device to their target,
  never through the personal agent;
- the personal agent's traffic has its own Tor isolation group, and its
  background schedule is its own;
- the sync key and the admin key are used nowhere else, and the member
  key signs nothing the personal agent stores;
- no push-notification token (FCM, APNs) is given to any space; devices
  poll, and raise local notifications.

**Messaging later** (slice 9): a member-to-member group's delivery service
is an agent, as the personal agent is for the device group. MLS virtual
clients would make the user's devices one leaf in other members' groups,
with the device group as the emulation group; but they share that virtual
leaf's signature and HPKE keys across the user's devices, a secret that
syncs, against E2's letter. Slice 9 asks the owner first (§9.1 N7).

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
- **Which kernels see a secret** [proposed, the slice-8 rule]: the light
  node puts a member secret or a spending key only into kernels whose
  device programs it computes from code it ships: the stock `auth` and
  `owner`, and the pool's `spend` and `join` from its own build of
  cipher-clerk's `shielded::check` (§5.4). It refuses to prove one of
  them if the space's installed program differs from its own. A kernel
  whose bytes a space serves may take only the user's public data:
  otherwise a space could install a kernel whose public claim is the
  secret itself (§8, G2). So in slice 8 a developer's own device kernel
  proves over public data and over data the user explicitly hands it,
  never over keys; a consent model per program id (the chrome naming
  the space, the method and the data) is later work (§9.4).
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

P1 and P2 are both built in slice 8 [decided, E3; how, N1 (c)]: P2's
wallet keeps each device's notes on that device alone, since under E2
only that device's key spends them, so P2 needs proven calls,
cipher-clerk v0.4 and the pool, not the personal space; slice 9 syncs the
wallet across the user's devices.

### 5.1 The shape

Two actors and one library:
- **`Payments`**, a public actor in the space: cipher-clerk's double-entry
  ledger (transparent accounts held by owner digests) beside a shielded
  pool (note commitments, nullifiers, encrypted notes). It never sees a
  note's value or owner.
- **`Wallet`**, a local actor in the user's personal space (§3): the notes
  the device holds and the nullifiers it has spent, each note marked with
  the device whose key spends it (E2); on that device alone in slice 8,
  synced across the user's devices in slice 9.
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
2. **P2, private** [slice 8, N1 (c)]: the shielded pool and the
   wallet. Payer, payee and amount hidden from the operators and every
   other member inside the pool; deposits into and withdrawals from the
   pool visible as transparent legs.

### 5.3 cipher-clerk, redesigned

cipher-clerk (`~/src/virto/cipher-clerk`; VOS pins tag `v0.3.0`, the
merge commit `b841640`, `Cargo.toml:239`, and uses its codec, `Account`, `Layer`,
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
| R3 | **Keys hash-only, per device**: `sk` per device and pool, 32 random bytes drawn by the light node, wrapped under a per-use keystore key; under N4 (a) also sealed under the recovery wrap key `R` (§3.5), so only a matured restore recovers it; `owner = C(T(note-owner), sk)`, `nk = C(T(note-nf), sk)`; the device proves knowledge of `sk` | spend authorization without an embedded curve: option 1 of item 1 ("the device proves, with `ak = Poseidon(ask)`"); no delegated proving, which the light node does not need | 1, 2 |
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

The wallet, a local actor (Merge fields, so slice 9 syncs it by giving
its scope to the personal space; in slice 8 its scope stays on the
device):

```rust
#[actor]
pub struct Wallet {
    notes: crdt::GSet<Owned>,           // notes received: the note, its position, its device
    spent: crdt::GSet<Digest>,          // nullifiers spent or seen spent
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
(`shielded::build`), proves the `spend` kernel on them (its device
program computed from the light node's own build of cipher-clerk and
checked equal to the pool's installed one, §4.4), sends the proven call
over Tor, and on `Ok` records `spent(nf)`. A local workflow with
device effects (`ctx.prove`, `ctx.call_remote`) would move that glue into
the actor; it is a later extension of the local host (§9 Q8).

### 5.5 What is proved on the device, and what is checked publicly

**Proved on the device** (the `spend` kernel, `shielded::check`):
- the payer knows `sk` behind the input note's `owner`;
- the input note's commitment is a leaf of the pool's tree under `anchor`
  at the witnessed position;
- each nullifier is `C(nk, C(pool, cm))` of its input (R4);
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
- **The gate** (the plan's PG4): the spend at most 1.0 s at the median
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
  `vos-api` over SSH relays today plus `Call` (the personal agent's
  pushes, commits and device-set operations) and `Credentialed`, with the
  gateway's leader-aware routing behind it. **`Credentialed` joins the
  onion only once the verifier refuses a junk proof well under 1 ms**
  (plan 8.5's pre-check): without addresses, a flood of junk proofs at
  5.8–8 ms each would deny every member's sign-in (§6.6). The light
  node's `vos-api` client runs over the `DataStream` unchanged (a
  multiplexed client over any futures-io stream).

**Tor carries streams, not datagrams:** no QUIC end to end; UDP over Tor
is a proposal (339), not deployed. iroh's experimental Tor transport
tunnels QUIC packets over a stream; we need not, since the gateway already
speaks streams (HTTP, SSH, framed `vos-api`).

**The onion address is the gateway's identity:** self-authenticating, so
a client that pinned it needs no TLS certificate for it; the SSH host key
stays pinned as today (§7.3). **A space has several gateways, so several
onions** (arti offers no load-balanced onion): enrollment pins the set,
the registrar serves the current set as a query, and a device refreshes
its pinned set through any onion of it. The recovery kit carries the set
current at the claim; a space whose onions have all changed since is
found only by its handle through the registry of spaces, which is not
built (`open.md`, "The registry and the root space"; §8, D4). A gateway
could serve a forged set, as it could forge any answer it relays
(`open.md`, "Node-signed roots").

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
  - the credential tree's feed (§6.7, plan 8.27): one long-lived circuit,
    since every member reads the same feed; until the feed lands, root
    polls and path fetches each take their own, a rendezvous each (about
    120 an hour in the foreground at today's 30 s polls, a cost PG5
    counts);
  - proven calls (each its own, from a spare: the client keeps one
    circuit to the onion built ahead for the next proven call and builds
    the next spare once it is used, since each isolated circuit to an
    onion service is a new rendezvous, a second or more, heavy-tailed);
  - the personal agent's traffic (its own group; its background schedule
    its own, §3.10), never sharing a circuit with the member's proofs;
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
  requests a second per stream, calls per agent per circuit (so one
  circuit cannot fill a personal agent's log), and a global cap of proven
  calls in flight through the onion (the node's verification budget
  behind it, `Busy` past it). Personal agents also admit only known keys
  (§3.3).
- **The proof's own cost:** a proven call carries the device format's PoW
  (16 bits), a grinding parameter more than a price: a junk proof costs
  the node 5.8–8 ms today [measured, format 46]. The pre-check that
  refuses one well under 1 ms (§4.3, plan 8.5) is the precondition for
  `Credentialed` on the onion (§6.1).
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
  (`PathKeeper`'s) spreads them, and keeping each tree from its feed on
  the device (plan 8.27; the wallet's `tree` likewise) removes path
  fetches altogether, which is the real fix the carried list names;
- **the `map_root` fingerprint** (carried, plan 8.27): fixed by proving against
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
| `vos-light` (new, `node/light`) | the light node: merge and query dispatch over its store (no log), the transpiler for local packages and stock kernels, the prover's device path, the node-API client, sync of sealed scopes, the device group over mls-rs, arti's client behind a feature; replaces `vos-device` one for one |
| `vos-node` (`node/host`) | forwarding a request for an agent it does not replicate, with its hop rule and peer stream (§3.3); admission by known keys at ingress (§3.3); ingress and apply reading the ring a guard names (§3.8). The light node does not carve it up: it needs only the executor's host-call layer, which moves to a crate both link (plan 8.6); `credentialed.rs`'s use of `vos_pvm_recair::device` moves with it |
| `vos-pvm-recair` | `credential` deleted; the leaves, folds and wrap behind a `recursion` feature, on by default (the masking needs `context`, `circuit` and `trace`, which stay), so a device links less of the recursion prover (§9 Q9) |
| `vos-pvm-final-verifier` | `credential` and `credential-bytes` deleted |
| `vos-sdk`, `vos-sdk-macros` | `#[attestable(device, reference = …, headroom = …)]`; `#[msg(proven = kernel)]`; in-place kernel arguments; `vos_sdk::p2` (digests, tags, paths); `crdt::{GSet, Set, Map}` and `#[msg(merge)]` on the light node |
| `vos-wire` | `Credentialed.claim` in place of `CredentialPublic`; `CredentialedInput` carries the claim; `Principal::Kernel { program }` (index 7); `CredentialKind` deleted; a peer message carrying a request as received, for forwarding (§3.3) |
| `merkle-crdt` | the incremental apply (`core-model.md` §9.4); the author, its sequence and signature in the payload; a `Store` over fjall; fetching by batch, asynchronously (today's `fetch_missing` walks one node at a time, synchronously, `src/sync.rs`); the `redb` store and feature deleted (one storage engine) |
| `vos-credentials` | the stock `auth` kernel (from the `device` test actor, in SDK form) and a new `owner` kernel, with their references; the stock kernels' ingress checks stay in the node (§4.3); a second ring for person leaves where `once` is used, named by the guard (§3.8, N3); the registrar's person records, `enroll_device` and `revoke_device` |
| `vos-gateway` | the onion service behind a `tor` feature (§6); a `vos-api` byte-stream port on it; per-circuit limits |
| new system actors | `Homes` (the pool, claims, the index by the kit's key) and `Personal` (the device set and its contests, the commit log and confirmations, sealed scopes, checkpoint acknowledgements, the inbox, quotas, activity and reaping), each one package; `Payments` (replacing the `purses` test actor, then the pool) and `Wallet` |
| new tool | the operator's keeper: topping up the pool, granting `Homes` its role, reaping unused agents, upgrading `Personal` in bulk (§3.3) |

**Net:** one crate in (`vos-light`), one out (`vos-device`); the
credential AIR's modules, one feature, one format, its fixtures and its
fuzz target out; merkle-crdt's redb out; cipher-clerk's `notes`,
`pvm-precompile`, `fmd-experimental` and `stealth-experimental` and its VOS
dependency out. In: arti's dependency tree (in the gateway and the light
node), mls-rs's (in the light node), four actors, a tool, the SDK's CRDT
fields and merge dispatch, node forwarding and admission by known keys.
No proving code beyond the levers' format.

### 7.2 The node and the gateway

- **The node** gains no transport and no knowledge of Tor, MLS, JAM or
  Kreivo. Its ingress generalizes (§4.3), refuses a junk proof before
  the verifier's bulk (§6.6) and, for an agent that asks, admits only
  known keys to sessions (§3.3); its install computes a device program for
  every device kernel (§4.4); format 44 goes; it forwards requests for
  agents it does not replicate (§3.3). The personal agent is
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
  personal agent, with the recovery kit), `pair` (§3.8, a QR shown and
  scanned), `devices` (list, remove, veto, resolve, contests, kit
  rotation; each behind the admin key's prompt), `restore` (from a kit),
  `move_home` (§3.9), `wallet` (balance, receive, private pay) and local
  notifications for pending device operations. These are new Kotlin
  screens in s4's client, estimated as their own plan step (8.24).
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

**A1. Two devices change the device set at once,** one offline (the phone
removes the tablet while the tablet, offline, pairs a laptop). *Mitigation:*
the agent's log orders operations and commits; one candidate commit per
epoch (`EpochTaken`); the loser rereads and re-proposes only if its intent
still holds; no device commits offline. (8.13, 8.19)

**A2. A device is lost or stolen, locked.** Before its first unlock since
boot, nothing opens: every key needs the keystore, and the keystore needs
the unlock. After a first unlock, the sync key and the MLS state work
while the screen is locked (§3.5), so a thief who keeps the phone powered
and runs code on it (an OS exploit, forensic tools) reads the personal
space; the admin key and the member secret still need the owner's prompt.
*Mitigation:* the owner removes it from another device (72 h, or at once
with two other devices) or with the kit. *Known limit:* after-first-unlock
exposure, the price of background sync on a locked phone; stated in the
light node's `SECURITY.md`. (8.13, 8.31)

**A3. A device is stolen unlocked, the app open,** without the owner's
biometric. The thief reads what the phone reads, history included, and
holds its sync key: he can push garbage (C1), post nacks (A16) and fill
the device's share of the quota (C5). He cannot sign an operation or veto.
*Known limit* for what the phone shows; the rest is bounded. (8.13, 8.20)

**A4. A thief who passes the owner's strong biometric** (coercion, or a
weak biometric sensor) holds an active device. *Mitigation:* the symmetric
rules (§3.5): he can remove nothing uncontested while the owner vetoes;
the owner wins a contest with one device and the kit, or with two other
devices. *Known limit:* he can always contest; with only the kit left the
owner cannot win, since the kit's own operations are cancelled by his veto
(a leaked kit and a lone owner look alike to the agent). Property-tested
against an adversary holding one active device and its biometric. (8.13)

**A5. A device returns after months.** Within the 180-day retention it
reads the commits and confirmations it missed and derives each confirmed
epoch's keys (data keys come from the exporter, so no ratchet window
applies). *Mitigation:* while it is away, every commit's confirmation
waits for it and voids at 72 h (§3.4), so the group cannot change keys;
a device silent for 30 days is shown as asleep, and any active device
removes it under the normal rules (its removal needs no confirmation from
it). Past retention it re-pairs. (8.19, 8.23)

**A6. A long replay on a phone,** killed by Android midway. *Mitigation:*
each commit is applied in one fjall batch with the stored epoch checked
before and after; a gap of more than a few hundred commits prefers
re-pairing. (8.19)

**A7. A removed device backdates DAG writes.** *Mitigation:* seal at push
takes only the confirmed epoch, which a removed device never learns; the
agent refuses its keys; devices accept its envelopes only up to its
frontier, and the CRDT types filter its writes at read (§3.2). (8.18,
8.20)

**A8. A write made offline leaks to a device removed meanwhile.**
*Mitigation:* seal at push under the confirmed epoch read just before;
`StaleEpoch` otherwise. (8.20)

**A9. A device applies a commit before it is confirmed,** the first cause
of forks in deployed MLS. *Mitigation:* candidates are processed but the
prior state is kept until the epoch is confirmed. (8.19)

**A10. Retries and leader changes.** *Mitigation:* the push queue keeps
sealed bytes and reseals only after `StaleEpoch`; the agent deduplicates
by envelope id before checking the epoch; a commit is a candidate once.
(8.14, 8.20)

**A11. An OS backup or a cloned phone restores MLS state on a second
device.** *Mitigation:* MLS state, the archive and the queue are excluded
from Android's backup and wrapped under a hardware key that does not
migrate, so a restored copy starts as a new device (A13). A clone that
commits produces a candidate the original cannot confirm consistently,
and the epoch is void. (8.19, 8.22)

**A12. The user's biometrics change,** and Android invalidates the key
wrapping the admin key. *Mitigation:* another active device, or the kit,
registers the device's new admin key as an operation; the device returns
to probation. (8.23)

**A13. The app is reinstalled on the same phone.** Keystore keys are gone;
the phone is a new device, its old leaf a ghost. *Mitigation:* it pairs
from another device or restores from the kit, then removes the ghost; a
ghost never confirms, so it is removed like an asleep device (A5). (8.23)

**A14. A thief who passed the prompt pairs his own device.** *Mitigation:*
probation: for 72 h it cannot sign or veto; the owner removes it, and if
the thief's other device vetoes, the contest goes to the kit or two other
devices (A4). It received what the stolen phone already held. (8.13)

**A15. Clocks are wrong.** *Mitigation:* delays, probation, retention and
activity run on the agent's batch time alone, the same for every device;
a device whose clock disagrees by more than an hour raises an alarm and
acts as the log says; Lamport counters order CRDT operations; MLS leaf
lifetimes are a year. (8.13, 8.19)

**A16. A committer forks the group selectively,** encrypting good path
secrets to some devices and garbage to others (any sync-key holder: a
thief with an unlocked phone, a probation device, malware). *Mitigation:*
key-confirmed epochs: the devices that cannot process it post `nack`, the
epoch is void for everyone, nothing was sealed under it, and the committer
is flagged. A device that nacks every commit stalls key changes, not the
group's data, until it is removed. (8.19, 8.21)

**A17. A commit carries a proposal the design does not use** (ReInit, an
external commit, a PSK, a group-context change) to steer the group.
*Mitigation:* devices refuse any commit outside Add, Remove and Update,
and an Add or Remove that does not match a matured signed operation; the
refusal is a `nack`. (8.19)

**A18. A device without a strong biometric.** *Mitigation:* it administers
with its PIN as a delayed admin: every operation it signs waits 72 h and
can be contested; pairing still works, 72 h later (§3.5). (8.13, 8.23)

**A19. A shoulder-surfed PIN.** The thief signs in and pays from P1 (the
member secret keeps its PIN fallback, as decided), but cannot touch the
personal space (strong biometric) unless the device is a delayed admin, in
which case every operation he signs is delayed and contestable. *Known
limit,* stated; P1's remedy is `rekey` (N5). (8.7, 8.13)

### 8.2 The home space and its operators

**B1. The operators withhold or delay sync.** *Mitigation:* devices work
offline and are full replicas; after 7 days without the agent the chrome
offers to move home (§3.9). (8.20)

**B2. The operators delete envelopes.** *Mitigation:* each device fetches
a random sample of positions it pushed, and re-pushes what is missing.
(8.21)

**B3. The operators roll the agent back.** *Mitigation:* each device
refuses a control log shorter than, or diverging from, the highest
`(log_index, log_chain)` it saw, and raises an alarm. (8.21)

**B4. The operators equivocate.** *Mitigation:* on keys, confirmed epochs:
two commits for one epoch give two `h`, signed by devices the operators
cannot impersonate, and the epoch is void; on the device set's history,
the views every envelope carries. Recovery is moving home and re-pairing.
*Known limit:* nodes sign nothing a device can show a third party, so an
alarm is not proof; carried with node-signed answers (`open.md`,
"Node-signed roots"). (8.19, 8.21)

**B5. The operators inject or replay.** A forged envelope fails its AEAD;
a replayed one is a duplicate; a replayed commit breaks the epoch rule.
*Mitigation:* as stated. (8.20)

**B6. The operators forge device-set operations.** They run ingress, so
they can append anything to the log. *Mitigation:* every device verifies
every operation's signature, and every confirmation's, itself. (8.13,
8.19)

**B7. The operators advance the agent's clock,** maturing a genuine but
hostile removal early, or reaping early. *Known limit:* delays trust the
operators' clock; devices alarm on a clock that runs ahead of theirs by
more than an hour. It only helps a thief who already passed the owner's
biometric (A4), or the operators acting alone, whose reach B8 states.
(8.13)

**B8. The operators collude** with a thief who passed the prompt, or with
a removed device. They can drop the owner's vetoes, order the thief's
operations first, place a removed device's backdated writes before its
frontier, and serve it data sealed before its removal's epoch is
confirmed. *Known limit:* the home is trusted for availability, order and
time (`core-model.md` §5); the owner's remedy is two devices' immediate
removal and moving home. Stated in the light node's `SECURITY.md`. (8.31)

**B9. The agent loses its quorum.** Sync and device changes stop; local
work continues. *Mitigation:* devices queue and retry; inactivity is
counted from the last call the agent accepted, so a long outage does not
reap it (the keeper reaps only on the agent's own word). (8.14)

**B10. A home with one replica** holds the backup on one disk.
*Mitigation:* the chrome shows the replica count; devices remain full
replicas. *Known limit:* losing that disk and every device at once.
(8.12)

**B11. The pool runs out.** *Mitigation:* `Homes` answers `PoolEmpty`;
the keeper tops it up; the device stays local-only and retries. (8.12)

**B12. `Homes` assigns one agent twice, or one nullifier claims twice.**
*Mitigation:* assignments and the nullifier index are Linear writes in
`Homes`, checked unique; `Personal` answers `assign` with `assigned` or
`refused`, and `Homes` releases a refused one. (8.12)

**B13. A reaped agent returns to the pool with its last tenant's residue,**
or the last tenant's device returns to it. *Mitigation:* `reap` clears
every table; the residue was ciphertext under keys the new tenant never
holds; the tenancy number goes up, so the old device sees "recycled", not
a rollback. (8.14)

**B14. The member leaves or is removed from the home space.** *Known
limit:* activity keeps the agent; the operators cannot evict a pseudonym
they cannot name. Quotas bound the cost; a yearly re-proof at a sign-in
the user makes anyway is the later option. (§3.3; carried, §9.4)

**B15. The user stops using every device for a long time** with the kit in
a drawer. *Mitigation:* the agent is reapable only after 360 days without
activity, any call by the kit counts, and the chrome says so when the kit
is made. *Known limit:* past 360 days the backup may be gone. (8.14)

**B16. The home space vanishes or turns hostile.** *Mitigation:* claim
elsewhere, a new group, re-pair, push everything; nothing is lost while one
device holds the data. *Known limit:* pairing again by QR; a successor
group and a live handover are later work (§9.4). (8.23)

**B17. Personal agents fill the space's disks.** *Mitigation:* a 64 MiB
default quota (about 1.9 TB for 10^4 users on three replicas); the scale
gate measures a full agent's snapshot install and one `replace`, with
limits it must meet (plan 8.15). (8.15)

**B18. `Personal`'s code is the operators'.** They install and upgrade it,
so its delays and quotas are theirs to change. *Mitigation:* devices
enforce what they verify (signatures, confirmations, frontiers by their
own reading, the allow-listed proposals), not the constants. *Known
limit:* a hostile upgrade is B8. The keeper upgrades every agent in bulk,
and a state migration is written with each new version (state migration
in general is unbuilt, `open.md`, "Upgrades"). (8.12)

### 8.3 Data, storage and quotas

**C1. A device writes garbage** that opens correctly (a bug, or a thief
with the sync key). *Mitigation:* apply validates each operation against
its type and schema; a node that fails is quarantined (kept, not applied)
and the chrome names its author. *Known limit:* excising a device's range
after the fact is later work; the remedy is removing the device. (8.18)

**C2. The DAG grows without bound.** *Mitigation:* checkpoints let new
devices start late; the quota bounds the agent. *Known limit:* garbage
collection is later work. (8.21)

**C3. Two devices checkpoint at once.** *Mitigation:* checkpoints are cut
at agent positions, so both hold the same state at the same `P`. (8.21)

**C4. A wrong checkpoint** (a bug, a thief) misleads a new device.
*Mitigation:* a new device trusts a checkpoint only when two devices other
than its author acknowledged recomputing it, or it replays. (8.21)

**C5. Quotas fill,** perhaps to block the owner's removal of the filler.
*Mitigation:* admin-signed operations, the commits carrying matured ones,
and confirmations are exempt; each device has an unadvertised share of at
most half the agent's bytes and calls. (8.14)

**C6. Large objects.** A 1 MiB checkpoint is 17 envelopes and 17 push
calls under today's caps. *Mitigation:* chunking; the scale gate pushes
full 256 KiB steps among 10^4 agents. A blob kind through the node's blob
store is the lever if chunking binds. (8.15, 8.20)

**C7. Inbox spam.** *Mitigation:* only the user's devices and a pairing
slot's holder write; slots are single-use and last 10 minutes; 64 items at
most; admission by known keys (§3.3). (8.14)

**C8. Sizes and timing describe the user.** *Mitigation:* Padmé padding,
opaque scope ids, the DAG's shape inside the ciphertext, a background
schedule of its own. *Known limit:* counts and times remain; foreground
sync follows app use (L2); no cover traffic. (8.20)

**C9. Two key archives disagree** (a bug, a thief's bogus archive).
*Mitigation:* every candidate key is kept and the AEAD decides. (8.20)

**C10. Fetching on demand reveals what the user reads.** *Mitigation:*
devices are full replicas and fetch everything on a schedule; member trees
for proofs stay device-local, outside the synced scopes. *Known limit:* a
device too small for a full replica is later work. (8.20)

**C11. The phone's storage fills.** *Mitigation:* the local store refuses
writes before the disk fills; sync pauses; the chrome says so. (8.18)

### 8.4 Recovery and the device's life

**D1. Every device is lost; the kit is kept.** *Mitigation:* restore
(§3.5): 7 days, then `R2` released, the recovery envelopes opened (they
follow every confirmed epoch, so no data is lost to lag), a new group;
memberships re-enrolled by each registrar; P1 accounts by `rekey`; P2
notes swept with the keys `R` sealed, under N4 (a). *Known limit:* the kit
holds keys, not data; a home gone or withholding at that moment leaves it
nothing to open. (8.23)

**D2. Every device and the kit are lost.** *Known limit:* the personal
space is gone; memberships and P1 accounts come back by each space's
ordinary process; P2 notes are lost. Stated when the kit is made. (8.23)

**D3. The kit leaks.** *Mitigation:* alone it opens `R1`, not `R2`, so it
reads nothing and spends nothing; its restore waits 7 days, shows on every
device and is cancelled by any of them; the owner rotates the kit, which
deletes the old `R2`. *Known limit:* the operators and a leaked kit
together read everything and, under N4 (a), spend every device's notes.
(8.13, 8.23)

**D4. The kit points at old onions** after the space changed gateways.
*Mitigation:* the kit carries the handle and the onions current at the
claim; the agent is found by the kit's key, not an id (§3.5). *Known
limit:* a space whose onions all changed is found only through the
registry of spaces, not built. (8.23)

**D5. A device sleeps through a veto window.** *Mitigation:* 72 h for
removals, 7 days for the kit; the background job raises a local
notification when an operation is pending. *Known limit:* a user whose
only other device sleeps longer than the delay cannot veto in time. (8.22)

**D6. Android kills the process mid-write.** *Mitigation:* each local
operation, each MLS state change and each queue change is one fjall batch;
pushes and commits are idempotent (A10). (8.6, 8.19)

**D7. A local actor's new version changes its state's shape.** *Known
limit:* state migration is unbuilt; such an actor starts a new scope and
the device re-imports. (8.18; carried, `open.md`, "Upgrades")

**D8. A format or kernel change needs an app update** (format 47).
*Mitigation:* the light node computes stock kernels' programs from code it
ships and asks for an update when they differ from the space's (§4.4).
(8.4, 8.10)

**D9. Devices run different app versions.** *Mitigation:* operations are
versioned; an unknown kind waits for the update instead of being
quarantined, so devices do not diverge. (8.18)

**D10. A device-local wallet's phone is lost** (P2 in slice 8, N1 (c)).
*Mitigation:* under N4 (a) the device's `sk` was sealed under `R` at its
creation, so a restore (D1) sweeps its notes. *Known limit:* before the
kit exists (no personal agent claimed) the notes go with the phone; the
wallet asks for a kit before receiving. (8.30)

### 8.5 Cryptography's future

**F1. Harvest now, decrypt later.** *Mitigation:* a hybrid post-quantum
suite if mls-rs maintains one by 8.3 (N6); otherwise ciphersuite 1 and a
successor group later; 180-day retention of handshakes. *Known limit:* a
hostile operator keeps what it wants. (8.3, 8.19)

**F2. Changing the suite or the protocol.** *Mitigation:* a successor
group, the archives resealed, old envelopes left under their keys; never
two suites in one group; new scope ids distinguish the new group's
envelopes without a version byte. (later)

**F3. RFC 9420's exporter is not forward-secure.** *Mitigation:* moot for
history, which the archive keeps on purpose; the Safe Exporter when
mls-rs has it. (8.19)

**F4. An mls-rs defect, or a change in its state format.** *Mitigation:*
one pinned version a release; a state the new version cannot read means
re-pairing that device. (8.19)

### 8.6 Proving and payments

**G1. Junk proofs.** *Mitigation:* the pre-check refusing a junk proof
well under 1 ms (plan 8.5), the format's PoW, the verification budget
answering `Busy`. (8.5)

**G2. A space installs a kernel that leaks a secret** (its public claim
the member secret). *Mitigation:* secrets enter only kernels the light
node computes from code it ships, the pool's spend among them (§4.4).
(8.4, 8.29)

**G3. A space upgrades a stock kernel's package.** *Mitigation:* the
device compares the installed program with its own and refuses to prove
on a mismatch, saying so. (8.4)

**G4. Balances split per device** (E2). *Known limit:* a payment comes
from one device; consolidating under P1 is a visible transfer (L4), under
P2 a private one. (8.7, 8.30)

**G5. A developer's own kernel wants the user's private data.** *Known
limit:* in slice 8 only data the user explicitly hands it, never keys; a
consent model per program id is later work (§4.4). (8.4)

### 8.7 The network

**H1. The onion is flooded with junk proofs** before arti declares its
service PoW ready. *Mitigation:* `Credentialed` joins the onion only after
the pre-check (§6.1); introduction-point, circuit and per-agent limits; a
cap on proven calls in flight; the C tor sidecar as the fallback (Q11).
(8.5, 8.25)

**H2. Tor is blocked.** *Mitigation:* bridges and pluggable transports;
calls to a space may fall back to the clearnet by its policy; the personal
agent's traffic waits. (8.26)

**H3. arti's library breaks monthly.** *Mitigation:* one pinned version a
release, an upgrade step each slice. (8.25, 8.26)

**H4. A background job starts cold** (a 10–30 s bootstrap). *Mitigation:*
arti's state persisted; an unfinished job leaves everything consistent
(D6) and the next resumes. (8.22)

**H5. A gateway's onion key is stolen.** The thief reads, drops and
delays what that gateway relays, and forges nothing. *Mitigation:* the
pinned set is refreshed from the registrar (§6.1). *Known limit:* answers
are unsigned (`open.md`, "Node-signed roots"). (8.25)

**H6. Forwarding loops, amplification, or starved elections.**
*Mitigation:* the hop rule (a non-replica forwards once; a follower uses
the existing forward to its leader), a peer stream of its own, forwards
counted against the sender's budget, operator kinds never forwarded.
(8.11)

**H7. Strangers flood a personal agent's sessions** over Tor (agent ids
are sequential). *Mitigation:* admission by known keys refuses them at
ingress before any commit; per-agent circuit caps at the gateway. (8.11,
8.25)

**H8. One rendezvous per poll** costs battery. *Mitigation:* the tree
feed on one long-lived circuit (8.27); until then PG5 counts rendezvous.
(8.26, 8.27)

### 8.8 Linkability and membership

**L1. The claim follows the member's first sign-ins.** *Known limit:* the
claim needs the user's prompt, so it happens when the user is present; a
home that is not one of the user's other spaces removes the link to the
registrar (§3.10). (8.23)

**L2. One device acts as a member and as the pseudonym.** *Mitigation:*
separate Tor isolation groups, keys used nowhere else. *Known limit:*
foreground sync starts when the user opens the app, as sign-ins do. (8.26)

**L3. Push-notification tokens identify the user.** *Mitigation:* none is
given to any space; devices poll and raise local notifications. (8.22)

**L4. P1 transfers between one's own devices** link their owner digests.
*Known limit:* P1 is pseudonymous; P2 hides it. (8.7)

**L5. Device changes and counts link the agent to the member** at a home
that is also the user's space (§3.10). *Mitigation:* `enroll_device`
deferred to the next ordinary sign-in; a home-only space recommended.
*Known limit:* counts still match. (8.16, 8.23)

**L6. `once` scopes with one leaf per device.** *Mitigation:* a ring of
person leaves, one per member, named by the guards that use `once` (N3).
(8.16)

**L7. The registrar learns which device leaves are one member's.** It
already knows each member; the tree still hides which leaf proves. *Known
limit,* stated. (8.16)

**L8. Path fetches and the logged `map_root`** link a member's proofs.
*Mitigation:* the credential tree's feed, so no path is fetched and every
proof names the newest root (8.27). (8.27)

**L9. A space's page asks the device to prove in the "home" scope.**
*Mitigation:* the scope is reserved: the facility refuses any request
naming `Homes`' agent and instance. (8.12, 8.23)

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

## 9. Open questions for the owner, risks, and later work

### 9.1 New questions

Ranked by how much of the slice each one moves. Each has options and a
recommendation.

**N1. How P2 (the shielded pool and the wallet) fits.**
- (a) Move P2 to slice 9: slice 8 builds P1, the personal space and Tor;
  cipher-clerk v0.4 is released in slice 8; the pool and a synced wallet
  open slice 9.
- (b) P2 in slice 8 with a synced wallet: the wallet follows all of the
  personal space, adding about 8–11 weeks to the critical path.
- (c) **P2 in slice 8 with a device-local wallet:** under E2 a note is
  spent only by the key of the device that holds it, so the wallet needs
  no sync to work; P2 then needs proven calls (8.4, 8.5), cipher-clerk
  v0.4 (8.28), the pool and the wallet (8.29, 8.30), and Tor for the
  pool's `required` policy, not the personal space. Its own stream, off
  the critical path; slice 9 syncs the wallet. The kit's protection of a
  lost device's notes (N4) arrives with M4 in the same slice.
- **Recommended: (c).** It honours E3 without lengthening the slice's
  critical path. Its costs: a sixth stream; PG4 and P2's flows in the
  slice-end gate; P2's privacy depends on Tor landing (M5), so P2 is
  shown over Tor at M5's end. If the cipher-clerk stream slips, P2 moves
  to slice 9 without holding anything else back, which is (a).

**N2. Where sealed scopes live on the nodes.**
- (a) In the personal agent's replicated tables, written through its log
  (§3.6): durable, consistent, each push checked atomically against the
  confirmed epoch; a commit per push at personal rates.
- (b) A node-side Merge store replicated by gossip outside Raft: no log
  entry per push, but a new peer protocol and durability path, and each
  push still consults the log.
- **Recommended: (a).** It realizes E6 with no new node machinery; (b)
  stays the design for plaintext scopes.

**N3. `once` scopes under per-device secrets (E2).**
- (a) A second ring of **person leaves**, one per member, held by one of
  the member's devices, in agents that use `once`, named by the guard;
  the registrar keeps person records (§3.8).
- (b) A nullifier key synced across the user's devices: a secret that
  syncs, against E2.
- (c) Accept one vote per device.
- **Recommended: (a).** It keeps E2 and costs a second tree only where a
  space uses `once`; it needs ingress and apply to read the ring a guard
  names (plan 8.16).

**N4. Spending keys and recovery.**
- (a) Each device's `sk` is random, wrapped under a per-use keystore key,
  and also sealed under the recovery wrap key `R` (§3.5) at the agent:
  an encrypted secret leaving the device, which E2's "syncs everything
  but secrets" did not foresee. A matured restore (7 days, cancelled by
  any of the user's devices) sweeps a lost device's notes. A leaked kit
  alone cannot spend (it lacks `R2`); **the home's operators together
  with a leaked kit can spend every device's notes at once.**
- (b) Spending keys bound to the device, like the member secret: a lost
  device's notes are lost; nothing about money leaves the device.
- **Recommended: (a).** Losing money with a phone is worse for most users
  than the stated collusion risk; the chrome states both when the kit is
  made, and a user may choose (b) per device.

**N5. The device-change parameters.**
- Proposed: probation 72 h; removing another device 72 h; the kit's
  operations 7 days; immediate with two active devices other than the
  target; contests resolved by two other devices or the kit; the admin
  key behind a strong biometric, the PIN making a delayed admin; the
  member secret keeping its PIN fallback (so P1 money has the lower bar,
  `rekey` its remedy); a kit required to claim; reapable after 360 days
  unused; handshakes retained 180 days; confirmations voided at 72 h.
- **These are the operators' constants:** `Personal` is their code (§8,
  B18). Devices enforce only what they verify: signatures, confirmations,
  allow-listed proposals and the frontiers they read.
- **Recommended:** these values, revisited after PG3′'s flows are timed in
  real use.

**N6. The MLS suite.**
- (a) Ciphersuite 1 (X25519) now; a successor group on a hybrid
  post-quantum suite when mls-rs maintains one.
- (b) A hybrid suite as a precondition of plan 8.19.
- **Recommended: (a), with 8.3 checking mls-rs first:** if a maintained
  hybrid suite exists then and fits the phone, take it.

**N7. MLS (E7), or per-epoch keys sealed to each device's public key?**
- **The simpler scheme:** at each device change or rotation, the device
  that makes it draws a random epoch key, seals it with HPKE to each
  device's X25519 key, and posts the sealed copies with its admin-signed
  operation; scope keys derive from the epoch key; the archive, the kit
  and the cursor are unchanged. Key-confirmed epochs still apply (a
  committer could seal garbage to some devices), with the same
  confirmation step.
- **What MLS buys here:** a standard, analysed protocol and its
  implementation; post-compromise security by updates, which the simple
  scheme matches by rotating the epoch key; tree-based efficiency, which
  does not matter for ten devices; and the path to slice 9's messaging,
  where the device group becomes the emulation group of MLS virtual
  clients, so other members see one leaf per user.
- **What MLS costs here:** mls-rs on the phone and its version churn
  (§8, F4); the TreeKEM state machine, pending commits, the proposal
  allow-list, handshake retention for devices that come back; perhaps
  1–2 weeks of the critical path (8.19) over the simple scheme.
- **Recommended: keep MLS (E7).** With key-confirmed epochs both schemes
  need the same confirmation step, so the simple scheme saves the TreeKEM
  machinery but not the protocol's hard part; MLS's value is slice 9's
  messaging, which the owner named. The comparison is not clear-cut the
  other way. If 8.3 finds mls-rs too heavy on the phone, or slice 9's
  messaging is not taken up through virtual clients, switch to the simple
  scheme then: nothing above the key layer changes.

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
  Rust for slice 8; a local `#[workflow]` later.
- **Q9** (the device prover outside `vos-pvm-recair`): a `recursion`
  feature on `vos-pvm-recair`, default on, the light node without it.
- **Q10** (the pool's integrity): the operators' for the in-space pool,
  stated in its documentation and chrome; a proved pool designed next.
- **Q11** (arti for hosting): arti in the gateway behind a `tor` feature,
  PoW when a release declares it; the risk is a flood before then (§8,
  H1); the fallback is C tor beside the gateway (stable PoW, a second
  process and a C dependency, against the owner's "arti in the
  ingress"), documented and run once in 8.25.
- **Q12** (note delivery): memos with view tags in the pool.

### 9.3 Risks

- **The slice's size:** the largest so far (`slice-8-plan.md`: about
  25–34 weeks with reviews, six streams); the personal space on devices is the
  critical path.
- **The Merge lane is unbuilt:** merkle-crdt has no dependent, the SDK has
  no CRDT fields, the incremental apply is a prototype (`core-model.md`
  §9.4). Slice 8 builds the device side and sealed scopes, not plaintext
  scopes on nodes.
- **MLS on the device is new code in a new place,** with key-confirmed
  epochs on top; the `messaging` branch's storage providers and its
  one-commit-an-epoch rule carry over, nothing else (N7).
- **10^4 personal agents waking a few times an hour** are unmeasured
  (plan 8.15's gate).
- **Proof bytes over Tor** dominate a call's latency (§6.3).
- **cipher-clerk v0.4 is a redesign** of a not-for-value prototype; its
  notes stay not for value until the external audit (`proving.md` §4).
- **Android's background limits** bound how fresh a backgrounded device
  is and how soon it sees a pending removal (§8, D5).

### 9.4 Later work this design leaves

One list, so nothing deferred is lost; `open.md` takes it at the slice's
end.
- A synced wallet (P2's wallet across devices, if N1 (c)).
- Messaging between members, on MLS virtual clients, with the owner's word
  on the shared virtual-leaf keys against E2 (§3.10).
- Plaintext Merge scopes on nodes (`core-model.md` §9.4 as designed).
- Actors the user installs in the personal agent (E9).
- A second home mirroring the first; a live handover between homes; a
  successor group after a lost home (§3.9).
- History horizons (forward secrecy for chosen scopes) and garbage
  collection of covered envelopes (§3.4, §3.6).
- Excising a device's operations after the fact (§8, C1).
- A blob kind for large objects (§8, C6).
- A consent model per program id for developers' kernels over private data
  (§4.4).
- A yearly re-proof of the home's membership (§8, B14).
- Node-signed answers, so an alarm becomes proof (§8, B4).
- Local workflows with device effects (Q8); the light node in its own
  Android process (Q5).
- A device too small for a full replica (§8, C10).
