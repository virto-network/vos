# The light node, the personal agent, one proving path and Tor

Design [proposed]. **Accepted for implementation pending the owner's
sign-off, 2026-11-02.** The architecture of slice 8
(`slice-8-plan.md`): a light node of VOS on the user's devices, a personal
agent in a space that keeps the user's devices in step, one proving path
for every device statement, payments rebuilt on cipher-clerk as the
showcase of attestable Rust, and clients reaching a space over Tor.
- **Status:** everything here is [proposed] unless tagged [decided] (an
  owner decision, listed in §1.1 by its number, E1–E21, or cited from
  another document) or [built] (what `vos-core` holds at `543c05e07`).
- **Numbers** carry their tag: [measured] (a run, cited), [model] (the
  cell model, `proving.md` §8), [est] (arithmetic on those, unmeasured).
- **It amends:** `proving.md` §8 (the credential AIR retired),
  `identity-and-authority.md` §5–§8 (credentialed calls generalized; the
  personal space unpostponed in the form of §3), `core-model.md` §9.4
  (sealed scopes beside plaintext ones, §3.6), and `node-api.md` §2 (the
  frame's transport mark), §3 (admission at ingress) and §6 (the
  gateway's onion service). Those
  documents keep their text until the steps that change the code change
  them.

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
| E3 | Payments P1 (cipher-clerk's ledger with owner proofs, replacing `purses`) then P2 (the shielded pool and a local wallet). The slices: E13. |
| E4 | No relay held by a gateway: a space has several gateways, and two devices on different ones would never meet. Each user gets a **personal agent** in a space they belong to (the home space): a small log for rare operations (the device set, MLS ordering, quotas), the space's nodes as durable ciphertext replicas of the user's DAG, and an inbox with expiring entries. |
| E5 | The personal agent is owned by a pseudonym, not by the member key. |
| E6 | The space's nodes keep full ciphertext replicas of the user's DAG (durable, a backup), not only expiring mailboxes. |
| E7 | MLS among the user's devices; data sealed under per-epoch keys from the MLS exporter, history readable by new devices through a key archive; removal is an MLS remove and a revocation of that device's leaf, with no global rotation. |
| E8 | Several home spaces allowed (CRDT replicas are free to multiply); slice 8 builds one. |
| E9 | Actors the user installs in the personal agent: later than slice 8; slice 8 builds sync and the inbox. |
| E10 | Anonymous calls (sign-in, spends) go from the device to their target over Tor, never through the personal agent, which would link them. The personal agent holds only ciphertext and what its operators may see. |
| E11 | Plan thoroughly; a Fable review of the design; the edge scenarios that could bite later worked through before code. The remaining design questions taken at their recommendations (§9.1). |
| E12 | Keep MLS, built as one shared `vos-mls` layer: the personal space its first user, member messaging and virtual clients later; one stack, fewer pieces. |
| E13 | P2 (the shielded pool, the wallet, PG4) moves to slice 9, built on the finished personal space and Tor. Slice 8 ships P1. |
| E14 | A home-only space by default: a space the user holds no other membership in, hosting personal agents. A user may home in a space they belong to, the app stating that its operators can link the agent to them. |
| E15 | A yearly membership re-proof (`Auth("home")`, one prompt a year) keeps the agent; an expelled member's agent lapses into a grace period, its data recoverable by the kit or a move. |
| E16 | Recovery in slice 8: the phrase or printed kit, and a FIDO2 security key as a kit (the `hmac-secret` path). An encrypted export file is later. |
| E17 | Tor-only is a rule for the personal agent: it refuses anything that did not come through the onion service. Bridges and pluggable transports weighed for slice 8 against later (§6.5). |
| E18 | cipher-clerk v0.4 (the shielded redesign, R1–R11) moves to slice 9 with P2; P1 runs on v0.3.0 unchanged. |
| E19 | No bridges in slice 8: plain Tor only; a network that blocks Tor pauses the personal space's sync, a stated limit. Bridges and pluggable transports later. |
| E20 | Virto runs a public home-only space, listed in the app as the default; others may run their own, and users may pick them. |
| E21 | The light node runs in its own `:vos` Android process behind Binder in slice 8, for crash isolation and background sync without the UI process. |

### 1.2 Goals

1. **A light node, not a proving library.** `vos-device` becomes a light
   node of VOS: the PVM runtime running local actors, a local store, the
   device prover, a node-API client, merkle-crdt sync and MLS
   (`vos-mls`). It runs on
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
   built in slice 9 (E13).
5. **Fewer pieces.** One crate in (`vos-light`), one out (`vos-device`),
   one proving path in place of two. The slice adds arti's and mls-rs's
   dependency trees, `vos-mls`, two system actors (`Homes`, `Personal`)
   and the CRDT fields; the claim is about what VOS maintains as proving and transport
   code, not a smaller dependency graph.
6. **Network privacy.** Clients reach a space's gateway as a Tor onion
   service, so no node or gateway learns a member's network address.
7. **The rule stays:** `vos` and the node know no JAM and no Kreivo
   [decided, `core-model.md` §13]; the same holds for Tor and for MLS:
   the node stores and orders opaque bytes for them (§3, §6, §7).

### 1.3 Non-goals for slice 8

- P2 (the shielded pool, the wallet, PG4) and cipher-clerk v0.4, which
  only P2 needs: designed in §5, built in slice 9 (E13).
- A pool shared across spaces, or one whose integrity does not trust its
  space's operators (`identity-and-authority.md` §8).
- Messaging between members, in a space or across spaces. The personal
  agent's design keeps its door open (§3.10).
- Plaintext Merge scopes on nodes (`core-model.md` §9.4 as designed),
  and the Merge lane on JAM.
- Actors a user installs in their personal agent (E9).
- A second home mirroring the first, a live handover between homes, and
  a successor group after a lost home (§3.9): later. Slice 8 moves home by
  re-pairing.
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
| **release artifacts** | the transpiled programs of the local actors and the stock kernels' device programs, computed at release and embedded with their ELF bytes; the phone runs no transpiler and no reference run (§4.4) | the release build [new] |
| **local store** | fjall, as the node's, with small caches (8–16 MiB block cache [est]) | `vos-node`'s `store` [built] |
| **device prover** | the device profile (format 46, then 47 after the levers, §4.4), masked, `Threads::Auto` | `vos-pvm-proof` and `vos-pvm-recair`'s masked device segment, its recursion prover featured out (§7.1) |
| **node-API client** | the multiplexed `vos-api` client over any futures-io byte stream: an arti onion stream (§6), or SSH's `vos-api` subsystem as today | `vos-api` [built] |
| **sync** | merkle-crdt DAGs of the local actors' Merge fields, its `Store` over fjall, sealed before they leave the device (§3.6) | `support/merkle-crdt` [built, no dependent today] |
| **MLS** | the user's device group, through `vos-mls` over mls-rs, on the host side, native, never in a guest | `vos-mls` [new]; the storage providers and copy-and-swap adapted from the `messaging` branch (§3.4) |
| **secrets** | per device, as today: the member secret from the keystore's HMAC; the admin key in the hardware keystore; the sync key and MLS state wrapped after first unlock; a security-key kit through the `hmac-secret` path (§3.5) | `vos-device`'s `secret` [built, extended] |
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

**Its own Android process, behind Binder** [decided, E21].
- The light node is one Rust crate, `vos-light` (§7.1), linked by s4's
  facility cdylib (today `s4-credential`, `~/src/virto/s4-vos/credential`,
  which links `vos-device`, `vos-api` and `vos-wire` by one VOS revision).
  The facility is renamed `vos.node`, grows the operations of §7.3, and
  runs in a separate process of s4's app (`android:process=":vos"`), which
  s4's UI reaches through one Binder interface.
- **Why its own process:** the prover's 1 GiB peak, the unwrapped sync key
  and archive, and arti's circuits stay out of the UI process; the OS can
  kill one without the other, so a proof or a sync is never lost to the UI
  being swiped away, and a crash in either leaves the other running; the
  background job runs in `:vos` with no UI process at all.
- **The Binder interface** carries the facility's named operations and
  nothing generic (§3.3); its results and errors are typed. The trusted
  chrome (the prompts, the pinned methods) stays in the UI process: a
  per-use keystore key is used with the prompt that authorizes it, so the
  UI process runs the prompt and the keystore operation it binds (the
  member secret's HMAC, or the admin key's signature over bytes `:vos`
  prepared) and hands `:vos` the result. It is tested
  as its own surface: every operation, a killed `:vos` during a proof and
  during a sync, a killed UI during both.
- **One runtime, one arti:** `:vos` owns a multi-threaded tokio runtime;
  the light node runs on it, and arti's `TorClient` is created once on it.
- **s4's SSH over the same Tor:** the facility is its own
  `libs4_credential.so`, built on VOS's pinned nightly because s4's client
  cannot build on it (`s4-credential/rust-toolchain.toml`). `:vos` opens the
  onion stream and hands the UI one end of a Unix socketpair as a
  `ParcelFileDescriptor` over Binder, pumping bytes between it and the
  `DataStream`; the client runs its SSH over the descriptor as over a TCP
  socket. Not a loopback SOCKS port: any app on the phone can reach
  127.0.0.1.
- **Lifecycle:** `:vos` lives while the UI is in the foreground and for a
  short grace period after; background sync runs as a WorkManager periodic
  job in `:vos` (Android's floor is 15 minutes), which opens the store,
  bootstraps arti from its cached directory, syncs and exits. No
  foreground service, no persistent socket, no wake lock beyond a job's.
- **Every write is crash-safe:** Android kills a backgrounded process
  without notice, so each local operation (with its DAG node), each
  change of MLS state and each change of the push queue is committed in
  one fjall batch (§8, D6).

### 2.3 Memory and battery budget

| state | budget | basis |
|---|---|---|
| idle, foreground (store open, arti bootstrapped, no proof) | ≤ 96 MiB resident, of which arti ≤ 48 MiB | [est]: interpreter and pool a few MiB, fjall's caches 8–16 MiB, arti's directory and circuits (§6.4), MLS state under 1 MiB for a few devices |
| the facility's `.so` | growth from arti ≤ 10 MB [provisional until 8.1 measures arm64 with rustls and the onion client]; from `vos-mls` and mls-rs ≤ 2 MB, a limit 8.3 can miss | [est], to measure (plan 8.1, 8.3) |
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
- **A personal agent** [decided, E4] in the user's **home space**: an
  ordinary agent of that space, run by its nodes, with one system actor,
  `Personal`, installed. It orders the few operations that need one order
  (the device set, the device group's commits), stores the user's sealed
  DAG nodes durably on every replica [decided, E6], and holds an inbox.
  It never holds a key that opens the user's data.

**The home is a home-only space by default** [decided, E14]: a space the
user holds no other membership in, run to host personal agents. A user
may choose a space they belong to instead; the app then says plainly that
its operators can link the agent to them (§3.10).

Devices sync with the personal agent, never with each other directly in
slice 8; the agent is where two devices that are never online together
meet. Every gateway of the home lists every node of it as an upstream, so
any gateway reaches the agent (§3.3).

**Local first, backup nudged:** a new user's personal space starts on one
device with no personal agent. The app offers backup (the claim, which is
also where the recovery kit is made, §3.5) at first launch and again
until the user accepts or declines for good, since a single device with
no kit loses everything with the phone (§8, D2).

**The first local actors:**
- the credential book: the spaces the user is a member of, each device's
  handles there, the pinned agents and methods s4's facility pins today.
  The member trees a device keeps for its proofs (§6.7) stay on the
  device, outside any synced scope;
- the device book: labels and settings of the user's devices (the device
  set's authority is the personal agent's log, §3.5; this is its
  user-facing mirror).

Each actor instance is one sync scope: one merkle-crdt DAG
(`core-model.md` §9.4's "one DAG per sync scope"). A merge handler's
effects depend only on its operation, so every device that applies a DAG
converges; randomness and time come from the device that issues an
operation and travel inside it.

### 3.2 What syncs, and the conflict model

- **What syncs:** each scope's DAG nodes, each a batch of CRDT operations
  with stable ids, its parents and its author. Never the store's rows,
  never proofs, never a secret.
- **The CRDT types, first:** `crdt::Set<T>` (add-wins observed-remove),
  `crdt::Map<K, V>` (last-writer-wins a key by a Lamport counter and the
  author's id) and `crdt::GSet<T>`. Storage-backed and **stored per
  author:** a map keeps the latest write per (key, author) and a read
  takes the latest among authors not filtered out (`core-model.md` §9.4,
  rule 6), so a removed device's writes applied before the removal was
  known are filtered at read, never unapplied (§3.5's frontier).
- **The conflict model** is the types' own; no operation needs another
  device's agreement. Where conflicts are real, a log decides: the device
  set and the device group by the personal agent's log, a payment by the
  space that holds the ledger.
- **Authorship:** each device signs the DAG nodes it authors with its
  sync key (§3.5); merkle-crdt's `DagNode` has no author field, so the
  author's key, sequence number and signature travel inside the payload,
  which is sealed (§3.6).
- **Operations are versioned:** an operation of a kind a device does not
  know is kept and applied once the device updates, never quarantined, so
  devices on different app versions do not diverge.
- **Incremental apply** [decided, `core-model.md` §9.4]: only newly
  fetched nodes are applied, in causal order (about 1.9 µs an operation at
  1M operations against 8.7 s for today's full rebuild [measured,
  `core-model.md` §9.4]).

### 3.3 The home and the personal agent

**Membership in a home-only space** [proposed, E14]: a home-only space
admits anyone, priced by work, so that joining it says nothing about the
user's other spaces.
- Its registrar's invitations (`identity-and-authority.md` §6: `invite`
  names a member digest, `claim` enrolls it) gain an **open claim**:
  `claim_open(member, work)`, any caller, admitted when `work` is a proof
  of work over `(space, member, the registrar's current salt)` at the
  difficulty the space sets (about a minute of a phone's cores), within a
  daily cap of open enrollments. Over the onion, the registrar learns
  only that someone joined. A new device's open claim runs in the
  background after pairing; it reads and writes through the archive
  meanwhile (§3.8).
- **Each device joins on its own:** under E2 each device has its own
  member secret, so each device of the user makes its own open claim in
  the home, unlinked to the others at the registrar. The device set in
  `Personal` is what ties them together, and that holds no member
  digests.
- **What bounds abuse is the cap, not the work:** a minute of a phone's
  cores is seconds on a desktop, so the work only stops a trivial loop.
  The daily cap is sized to the home's disk (each claim can grow to 192
  MiB on three replicas) and kept below the keeper's refill rate, so a
  drained pool shows as `PoolEmpty` (§8, B11) rather than a full disk;
  and the **quota ramps:** a new agent holds 8 MiB, rising to 64 MiB after
  its first yearly re-proof, so a Sybil's first year costs the home an
  eighth as much. Nothing an open member does reaches another user's
  agent (known keys, gated queries, one agent a claim). The default home
  is run by Virto, listed in the app, its cap published [decided, E20];
  anyone may run another, and users may pick it.

**When the home is a space the user belongs to,** membership is the
user's ordinary one, and §3.10 says what its operators can then link.

**The pool and the claim:** agents exist only by an operator's command
today (`CreateAgent`, `Install` and `Grant` are operator kinds,
`node/api/src/lib.rs`), so the design keeps a **pool of agents the
operator makes ahead of time**:
- **`Homes`**, a system actor in the agent that holds the home's
  credential actor (an `Auth` guard reads the ring of the agent it guards,
  `node/host/src/credentialed.rs`, so `Homes` lives beside it), keeps the
  pool: agent ids the keeper created with `Personal` installed and handed
  over with `homes.stock(ids)`, an operator-role call.
- **The keeper** (`tools/`, holding an operator key) tops the pool up in
  bulk: create, install `Personal`, and grant `Principal::Agent(homes)`
  the role under which `Personal` takes `assign` (`Grant`; `Install`
  carries no configuration, `agent/wire/src/ingress.rs`). Creating an agent
  costs about 2 s, 0.15–0.17 s each sixteen at a time [measured,
  `core-model.md` §14.1], so a pool of a few hundred hides creation from
  users. It also runs `Personal`'s upgrades (below).
- **The claim:** `homes.claim(keys, kit)` under
  `#[msg(credential = Auth("home"))]`. The pseudonym is the claiming
  device's nullifier in scope "home" [decided, E5]. `Homes` refuses a
  nullifier already holding an agent, assigns a pooled one, indexes it
  under the nullifier and under `H(each recovery public key)` (§3.5), and
  sends it `assign(keys, kit)`; `Command::send` is one-way
  (`agent/sdk/src/context.rs`), so `Personal` answers `assigned` or
  `refused`, and `Homes` releases a refused one. The chrome refuses a
  claim on a device that already holds a personal space's archive, so a
  user's second device never claims a second agent by mistake.
- **"home" is reserved:** the light node proves in that scope only for
  its own claim and re-proofs, and the facility refuses any request
  naming `Homes`' agent and instance.

**The lease: one re-proof a year** [decided, E15]:
- Every device's own "home" nullifier is recorded at its add (the device
  computes it without a proof; `Personal` passes it to `Homes`, which
  refuses one already mapped to another agent).
- Once a year, any device proves `Auth("home")` to `homes.renew(agent)`
  under a recorded nullifier: one prompt a year, at an ordinary sign-in
  when the home is the user's own space, or at a yearly "keep my backup"
  prompt in a home-only one. The lease runs 13 months from the last
  re-proof.
- **A lapsed lease** (the member left, was removed, or never re-proved)
  puts the agent in a **grace period** of 180 days: it refuses pushes and
  any commit but one carrying a removal, and still takes device-set
  operations, `alive` and confirmations, serves the devices' and the
  kit's reads, a restore (§3.5) and the move to another home (§3.9), so
  the data stays recoverable and a stolen phone can still be removed. A
  re-proof ends the grace.
- **On a test home** the delays of §3.5 and the lease are set per space
  (minutes, not days), so the plan's gates can run every flow.
- **Reaping** an agent after its grace, wiping it and returning it to the
  pool, is later work (§9.3): nothing can lapse within slice 8's first
  year.

**Replicas:** three by default, the space's policy, fixed when the keeper
makes the agent. One replica is allowed for small spaces and shown in the
chrome (§8, B10). **Cost:** about 46 KiB and 1.6 µs/s a replica when idle
[measured, `core-model.md` §14]; with a 64 MiB quota (§3.6), 10^4 full
agents on three replicas is about 1.9 TB a space. Unmeasured, and the
plan's scale gate: 10^4 agents waking a few times an hour, a full agent's
snapshot, a `replace` (plan 8.15).

**Reaching the agent: every gateway lists every node.** A node that does
not replicate an agent answers `Elsewhere { replicas }`
(`node/host/src/node/mod.rs`), and a gateway retries toward any upstream
it lists (`node-api.md` §6), so a gateway that lists every node of its
space reaches every agent. That is the configuration a home requires, for
spaces of three to a few dozen nodes. Forwarding between nodes, for a
gateway that lists only some, is later work (§9.3).

**Admission** [proposed]: a personal agent sets two flags that ingress
reads from the agent's own state, as it reads the credential ring:
- **known keys only:** a session-creating call from a key absent from the
  agent's admitted-keys rows is refused. The lookup runs **before** the
  signature check (the key is only an index into the rows; the check that
  the call creates a session reads the session row), so an unknown key
  costs two point reads, not a verification. A key admitted in the last
  batch may be refused until the leader applies it, and the client
  retries. `Personal` admits the device set's sync and admin keys, the
  recovery keys' ed25519 halves and open pairing slots' keys.
- **onion only** [decided, E17]: a request the gateway did not receive on
  its onion service is refused. The gateway marks each request it relays
  with the transport it came in on (a field of the frame,
  `node-api.md` §2); a node treats a missing mark as clearnet (the unix
  socket and test clients send none). The mark is the gateway's word,
  defence in depth against a client bug and against strangers on the
  clearnet, not a privacy guarantee. **The enforcement is the client's,
  in three parts:** the light node routes by destination agent and has no
  clearnet route at all for any kind addressed to the personal agent or to
  `Homes` (not a policy checked at send time); the facility exposes only
  its named operations, never a generic call or query, so no page can
  steer it; and s4's SSH session, whose `vos-api` subsystem relays
  queries under an ephemeral key that `Personal` answers nothing, itself
  runs over Tor (§6.5, §7.3). No facility operation may add a generic
  call.
- **Reads are gated in the handlers:** a `Query` is signed by any key
  (`agent/wire/src/ingress.rs`, `QueryCall`) and admission covers
  sessions, so every `Personal` query checks `Query::caller()`
  (`agent/sdk/src/context.rs`) against the admitted keys and answers
  nothing to others. Other members and outsiders read nothing of a
  personal agent; its operators read its tables (§3.10).

**Sessions:** a device's calls are signed by its sync key; a session
expires after an hour idle (`SESSION_EXPIRY_MS`), so a background job opens
one per run: at 10^4 users syncing four times an hour, about 11 session
commits a second across a space [est].

**`Personal`'s upgrades over agents that hold data** [proposed]:
`Admin::Install` replaces the program and touches no table
(`agent/default/src/refine/admin.rs`), and state migration is unbuilt, so
`Personal`'s storage layout is **append-only across versions:** new tables
and new optional fields, never a changed key or encoding. Each release
installs over a populated agent of the previous release in a test that
reads every envelope and operation back (plan 8.14); the keeper upgrades
in batches and stops on the first refusal. A change that cannot be
append-only waits for state migration (`open.md`, "Upgrades").

### 3.4 Keys: MLS among the user's devices, with confirmed epochs

**One MLS layer for VOS** [decided, E12]: `vos-mls`, a crate over mls-rs
that every MLS user in VOS shares: the user's device group first, member
messaging and MLS virtual clients later. It holds the storage providers
(over fjall), the copy-and-swap of group state (below), the confirmation
hash, and the proposal policy each user sets. mls-rs runs on the light
node's host side, natively; nodes never run MLS, parse it or hold its
keys.

**The device group** [decided, E7]: one MLS group (RFC 9420) per user,
its members the user's devices, each a leaf whose credential carries the
device's sync key and admin key (§3.5). Encrypted handshakes (MLS
`PrivateMessage`) and padding.

**The rejected alternative:** per-epoch random keys sealed (HPKE) to each
device's X25519 key at every device change, with no MLS. It keeps every
property this design uses for the device group (relays read nothing, each
device has its own key, a removed device learns no later key) and drops
mls-rs on the phone, its state machine and its version churn. It was set
aside [E12] because member messaging will use MLS anyway, and one MLS
stack in VOS is fewer pieces than an MLS stack and a second key scheme.

**The personal agent orders the group's commits** (RFC 9750 §5.2.1's
strongly consistent delivery service; the rule is the `messaging` branch's
`msg-ctl`'s):
- A commit is an **admin call** (§3.5), `Personal::commit(epoch, effect,
  handshake, welcome_hash)`: signed by the device's admin key and verified
  at ingress like any client call; the agent checks that the caller is the
  admin key of an active device, and accepts it as the **candidate** for
  `epoch` only if `epoch` is the confirmed epoch plus one and no candidate
  is pending (`EpochTaken`, `EpochGap`). The Welcome, which can exceed what
  the keystore signs in one operation, follows in the commit's evidence
  call, bound by its hash. So no holder of a sync key alone (a phone after
  first unlock, malware in the app's process) can touch the group's keys:
  committing needs the owner's biometric, and a probation device commits
  nothing.
- **Allowed proposals:** Add, Remove and Update, nothing else: no ReInit,
  no external commit or join, no PSK, no group-context change. The
  declared effect (`update`, `add(d)`, `remove(d₁, …)`) names matured,
  admin-signed device-set operations for every Add and Remove (§3.5),
  which the agent checks; **a commit may carry every matured removal at
  once.**
- **Copy and swap:** mls-rs applies a received commit at once
  (`process_incoming_message`; its pending commit covers only a group's
  own commits), and the confirmation needs the commit processed. So a
  device processes a candidate on a **copy** of its group state, keeps the
  prior state as current, and swaps on confirmation or drops the copy on
  a void, as the `messaging` branch's `mls.rs` snapshot and restore did.
  Its own commit, likewise, becomes current only on confirmation (§8, A9).

**Key-confirmed epochs** [proposed]: an epoch's keys are used only once the
devices that are awake have shown they hold the same keys.
- **The confirming set** is the devices of the new epoch that the agent has
  seen within the last 72 h by its batch time, minus every device whose
  removal has matured. **Seen means a call** (a session opening, a push,
  an `alive`, a confirmation), each a commit the log records; a query is
  served from a replica's applied state and records nothing. **The agent
  writes the set into the candidate's log entry,** so it is in
  `log_chain`: every device checks confirmations against that one set, a
  different set shown to different devices is a split log that views
  catch (§3.6), and a device named absent that made a call in the window
  (the reply to every call carries the agent's batch time) sees the entry
  and raises the alarm. Each device in the set posts, signed end to end by
  its sync key, `confirm(epoch, h)`, `h = BLAKE2b-256("vos/personal/confirm"
  ‖ agent ‖ epoch ‖ epoch_authenticator)`, or `nack(epoch)`.
- **Confirmed:** every device in the logged set confirmed with one `h`.
  Each device checks the signed confirmations itself; the agent's verdict
  is advisory. **Void:** a `nack` or a second `h` from the set,
  or 72 h without the set complete; devices drop the copy, the committer
  is flagged, the epoch number is free again. Confirmations and nacks
  from a device whose removal has matured are ignored.
- **Sleepers are deferred, not waited for:** a device outside the
  confirming set processes the confirmed commits when it returns. If it
  cannot (a committer encrypted garbage to it alone, or the operators
  named it absent and the commit excluded it), it raises an alarm naming
  the committer, and re-pairs from another device or, with none to pair
  from, runs a **regroup** (§3.5): nothing is lost, and the awake devices
  never wait.
- **Data is sealed only under a confirmed epoch.** A commit valid for some
  awake devices and not others is voided by their `nack`, so nothing is
  sealed to one side alone; an operator showing two devices two commits
  gets two `h`, signed by devices it cannot impersonate.
- **Against stalls:** a device that nacks every commit stalls key changes,
  not data, until it is removed, and its removal's commit needs nothing
  from it. Two attacker devices that nack each other's removals are both
  removed by one commit carrying both matured removals, their nacks
  ignored. The residual is the operators' alone: holding back a genuine
  admin-signed commit until a device is quiet, and naming it absent, they
  can lock it out until it re-pairs or regroups; they cannot cause a
  commit (§8, B8).
- **Between a removal's maturity and its confirmed epoch** the agent
  already refuses the removed device's keys; only operators serving it
  anyway could hand it data sealed under the prior epoch, for at most 72 h
  after the 72 h removal delay (§8, B8).
- **Updates:** a device updates its leaf when an MLS leaf lifetime nears
  its end (a year), on the same yearly prompt as the home's re-proof
  [E15], and after its admin key is replaced; each is an admin-signed
  commit.

**Retention:** the agent keeps handshakes and confirmations for 180 days
and no plaintext group information; a device away longer re-pairs (§8,
A5).

**The data keys** [decided, E7]:
- `k(scope, n) = MLS-Exporter("vos/personal/scope", scope_id, 32)` in
  confirmed epoch `n`: one key a scope and epoch, so delivery order does
  not matter (MLS's per-message ratchet would not survive a CRDT's
  unordered, repeated delivery). The Safe Exporter replaces it when mls-rs
  has it.
- **Scope ids** are `BLAKE2b-128("vos/personal/scope-id" ‖ naming ‖
  name)`, `naming` a random secret drawn with the group and carried in the
  archive; a restore draws a new one for the scopes it creates, so a leaked
  old `naming` does not unmask new scopes (§8, D3).
- **The key archive:** every past `k(scope, ·)` and the naming secret, a
  union indexed by epoch, sealed under the current epoch's key and pushed
  by the committer once an epoch is confirmed, or by any device that finds
  it missing; a new device receives it over the pairing channel (§3.8).
  Archives that disagree keep every candidate key, and the AEAD decides.
- **No forward secrecy for history, by design;** post-compromise security
  for new data. History horizons are later work (§9.3).

**The suite:** ciphersuite 1 (X25519, AES-128-GCM, SHA-256, Ed25519)
unless mls-rs maintains a hybrid post-quantum suite by plan 8.3 (§9.1); a
later change is a successor group, never two suites in one group (§8, F2).

### 3.5 Device secrets and the rules for changing devices

**Per device** [decided, E2]:

| secret | what for | held as |
|---|---|---|
| the member secret `s` of each space | membership proofs (auth, owner) | derived at each use from the keystore's HMAC over the space's handle, behind the prompt (a biometric or the PIN), as today [built, `identity-and-authority.md` §7]; in the process during a use, as that design states |
| the **admin key** (Ed25519) | the client key of admin calls: device-set operations and commits | **a Keystore signing key in the TEE**, never leaving it: per-use authentication by a strong biometric (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`), with key attestation where the phone offers it. On Android 13 and later only: KeyMint's TEE implementations must support curve 25519 for signing (Ed25519) and StrongBox implementations do not support it (`IKeyMintDevice.aidl`), so the key lives in the TEE, not StrongBox. On a phone with no strong biometric, or on Android 11–12, the device is a **delayed admin** (below) |
| the **sync key** (ed25519) | the client key at the personal agent; signing DAG nodes and confirmations | wrapped under a keystore key usable **after the first unlock** since boot, no per-use prompt, no unlocked-screen requirement: background sync runs on a locked phone |
| the MLS state, the key archive, `R` | sealing and opening envelopes, processing commits | the same after-first-unlock wrap; kept out of Android's backups (§8, A11) |

- **Ed25519 only** [proposed]: ingress client keys are ed25519
  (`agent/wire/src/ingress.rs`), and an admin key is a client key, so
  admin keys are Ed25519 too. A second client-key curve (P-256) at ingress
  would serve only Android 11–12 phones, at the cost of new ingress code
  and its carrier and fuzz cover; those phones are delayed admins instead.
  The device set records whether each admin key's attestation showed a
  TEE key requiring a strong biometric, and the chrome shows an unattested
  one.
- **Why the bars differ:** a sign-in or a P1 transfer is one action the
  user sees; device changes are lasting control of every device's data. So
  the member secret keeps its decided PIN fallback and in-process exposure
  (stated in `SECURITY.md`); the admin key is held where malware with the
  app's process cannot reach it.
- **Delayed admins:** a device that cannot hold the admin key as above
  administers anyway, under a delay: on a phone without a strong
  biometric its TEE key is authenticated by the PIN; on Android 11–12,
  whose keystore has no Ed25519, the admin key is a software Ed25519 key
  wrapped under a per-use-authenticated keystore key, so it is in the
  process during each use. Either way every operation it signs, adds
  included, waits 72 h and can be contested (its commits carry only
  operations already matured), which bounds what malware that captures
  such a key can do.
- **After first unlock:** a phone unlocked once since boot uses the sync
  key and the MLS state while locked; a thief who keeps it powered and
  runs code on it reads the personal space. Before the first unlock
  nothing opens (§8, A2).

**Admin calls, verified at ingress and end to end:**
- **One call, one prompt:** every device-set operation (add, remove, veto,
  resolve, kit rotation, restore, regroup, admin-key replacement) and
  every commit is a one-shot client call whose key is the device's admin
  key (or the kit's, for its own operations), its arguments including the
  control log's head it was made against. The prompt authorizes the one
  signature the call needs; ingress verifies it as it verifies any client
  call, and the agent checks the origin, `Principal::Client(key)`, against
  the device set: whose key it is, and whether that device's state (active,
  seasoned, delayed) allows the operation. No guest verifies a signature
  (`core-model.md` §5: no signed evidence inside guests).
- **Prompts:** pairing is one prompt (the add and its commit are one call,
  §3.8); a removal is the operation's prompt and, once it matures, the
  commit that carries it, made by the next device whose user authenticates
  (the agent already refuses the removed device's keys at maturity); a
  veto, a resolve or a kit rotation is one each; the yearly re-proof and the
  leaf renewal share one.
- **Size:** the keystore signs at most 16 KiB in one Ed25519 operation
  (`IKeyMintDevice.aidl`), so an admin call's arguments stay under 15
  KiB; anything larger (a commit's Welcome) rides in its evidence call,
  bound by hash.
- **The evidence:** the logged request carries no signature, so the device
  that made the call then posts, under its sync key and with no prompt,
  `evidence(operation, message, signature)`: the exact signed call message
  and its signature. The agent stores them as data, compares the message's
  arguments byte for byte with the operation it recorded, and verifies
  nothing. **Every device verifies the signature** against the admin key
  before acting, and acts on no operation without its evidence; the device
  that made the call re-posts the evidence until it is stored. The
  operators run ingress and could append anything to the log, so a device
  trusts an operation only by its signature (§8, B6).
- Delays run on the agent's batch time alone; a device whose clock
  disagrees with the agent's by more than an hour raises an alarm and
  otherwise acts as the log says.

**The device set** (a table in `Personal`): each device's sync key, admin
key and its attestation, its admin class (strong or delayed), its
"home" nullifier, a sealed label and a state: **probation** (72 h from
its add: it may sync and post confirmations, not sign operations or
commits), **active**, or **removed** (with its frontier). A device is
**seasoned** once it has been active for 7 days.

**The rules** [proposed]:
1. **Add** (pairing, §3.8): signed by an active strong admin, immediate;
   the new device is in probation. Signed by a delayed admin, it waits
   72 h first.
2. **Remove `d`:** signed by an active device, **pending** for 72 h, then
   matures unless contested.
3. **Being targeted suspends no right:** a device with a removal pending
   against it keeps every right, its own veto included.
4. **Veto:** any active device, the target included, may veto a pending
   removal; the removal becomes **contested** and does not mature.
5. **A contest is resolved** only by two seasoned active devices other than
   the target signing `resolve`, or by the kit, which acts at once in a
   contest. Two removals aimed at each other are one contest; the
   resolution names which one matures, and the other is dropped. With
   neither two other seasoned devices nor the kit, nothing matures.
6. **Immediate removal:** two seasoned active devices other than the target
   sign it.
7. **The kit** may sign its own operations (restore, kit rotation, a
   removal) and resolve a contest; it may **not veto**. Its operations wait
   7 days and are cancelled by any active device's veto (which needs that
   device's admin key), and a **restore** is cancelled too by
   **liveness**: any device's signed `alive`, posted under its sync key by
   an ordinary sync (no prompt) while the restore is pending, cancels it,
   since a restore asserts that every device is lost.
9. **A device whose removal has matured has no voice:** its vetoes,
   `alive`, confirmations and nacks are ignored, whatever the agent
   stores.
8. **Probation devices** cannot sign operations or veto. **A removal
   pending or contested against a probation device freezes its
   probation** until the removal resolves, so an add cannot ripen into a
   second vote inside a removal's own window.

*What is conceded, and only this:* a thief who passes the owner's strong
biometric holds an active device and can always contest. The owner wins
with one device and the kit, or with two other seasoned devices. With the
kit alone the owner still wins against a thief holding only a sync key (a
phone after first unlock, malware): the kit's `remove` of that phone can
be cancelled only by a veto, which needs the admin key the thief lacks,
so it matures after 7 days; from then the phone's `alive` is ignored, and
the kit's restore matures 7 days later, 14 days in all. With the kit alone
against a thief who also passes the biometric, the owner cannot win: the
thief vetoes, as an owner must be able to against a leaked kit (§8, A4,
D3).

**The removal frontier:** when a removal matures, the agent records, per
scope, the position of the removed device's last accepted envelope; its
envelopes after it are invalid. The frontier is the agent's word (§8, B8).

**Replacing an admin key** (a biometric change invalidates it): another
seasoned active device or the kit signs `admin(d, new key)`. The device
keeps its seasoning; the new key is on probation for 72 h (it signs no
operation until then), since the probation guards the key, not the
device.

**Regroup** (a device that cannot follow the confirmed epoch, with no
device to re-pair from): an active seasoned device runs the restore flow
below signed by its admin key in place of the kit: it needs no `R2` (it
holds `R`), waits 72 h and is vetoable and contestable as a removal is,
and is immediate when two seasoned devices or the kit sign it. It removes
the devices it names, starts a new group with the rest by Welcome, and
the control log restarts under it.

**The recovery kit** [decided, E16; proposed details]:
- **Two kinds,** either or both, each a recovery entry in the device set
  (never an MLS leaf, since it is never online):
  - **a phrase:** 32 random bytes shown once as 24 words, with the home's
    handle (its stable 32-byte handle, not its `SpaceId`, so a re-founded
    home still matches) and its onion addresses; never shown as a QR;
  - **a security key:** a FIDO2 key's `hmac-secret` over a fixed salt,
    through the same YubiKit path the member secret's security-key source
    uses (`identity-and-authority.md` §7), giving the 32 bytes the phrase
    would; it cannot be photographed, and needs its PIN and a touch.

  From the 32 bytes derive the kit's ed25519 (signing) and X25519 (sealing)
  keys. `Homes` indexes the agent by `H(recovery public key)`, so a kit
  needs no agent id: restore looks the agent up.
- **A split wrap key:** the claiming device draws `R = R1 ⊕ R2`; `R1` is
  sealed to each kit's X25519 key and kept at the agent; `R2` is kept at
  the agent, released only to a matured restore. Devices hold `R` in
  their archive.
- **Recovery envelopes at every confirmed epoch:** the committer pushes the
  epoch's new scope keys sealed under `R`, a few hundred bytes, into a
  scope of their own, so the kit's copy never lags (§8, D1).
- **What a leaked kit can do:** nothing at once. It opens `R1`, not `R2`;
  its restore waits 7 days, shows on every device, and dies at the first
  `alive`. The operators alone hold `R2` and not `R1`. The operators and a
  leaked kit together read everything (§8, D3).
- **Restore** (every device lost, §8, D1): a fresh install joins the home
  (§3.3) and every other space by its registrar's ordinary process, reads
  the kit, finds the agent, posts `restore`. After 7 days with no veto and
  no `alive`, the agent releases `R2`; the device opens the recovery
  envelopes, removes every old device, starts a new group as its only
  member (the control log restarts under it), draws a new naming secret
  for new scopes, and **rotates the kit**, since the kit just used may be
  the one that leaked. A restore may target another home: the same restore
  at the old agent releases `R2`, and the new group lives at an agent
  claimed elsewhere.
- **Kit rotation:** a new kit, a new `R`, `R1` sealed to the new kit, the
  old `R2` deleted, and the recovery envelopes re-sealed under the new `R`
  by the device that rotates. Two seasoned active devices make it at once;
  one makes it pending 72 h and contestable.
- **Moving home re-splits the kit:** the new agent holds a new `R2` and
  re-pushed recovery envelopes; until the move completes the kit opens
  nothing at the new home (§3.9).

**What the control log shows the operators:** the device count and its
changes, each device's public keys and admin class, the times of
device changes, commits and confirmations, contests, liveness, and the
recovery entries. Not the labels, not the data.

### 3.6 Sealed scopes: storage and sync

**An amendment to `core-model.md` §9.4:** a sync scope is either
**plaintext** (as `core-model.md` §9.4 designs it; not built in slice 8) or **sealed**: its
DAG nodes are ciphertext to every node; devices validate and apply; nodes
store, order and serve envelopes and enforce what they can see (who may
push, the epoch, quotas). `core-model.md` §9.4's authorization rule runs
on the devices, against the control log: an author is valid if its sync
key was in the device set (probation, active, or with a removal pending)
when its envelope was accepted, and within its frontier if later removed.

**The envelopes live in the personal agent's replicated tables, written
through its log** [decided, §9.1]: durable, and each push checked
atomically against the confirmed epoch and the device set. **The API is
blob-ready:** an envelope's id is its hash, `push` returns its position,
`since` returns `(position, id, bytes)`, so moving the bytes into a blob
store later (media) is a node change with no client change (§9.3).

**An envelope:**
```text
envelope  = header ‖ sealed
header    = { scope: [u8; 16], epoch: u64, nonce: [u8; 24], len_class: u8 }   (clear; AAD)
sealed    = XChaCha20-Poly1305(k(scope, epoch), nonce, Padmé(body), AAD = header ‖ agent id)
body      = { author: sync key, seq, signature, parents: [cid], ops, view, seen }
view      = { log_index, log_chain }        (the writer's view of the control log)
seen      = [(scope, position)]             (the highest position the writer had read, a scope)
```
- **In clear:** sizes (padded, Padmé: at most 12% overhead), times, opaque
  scope ids and the epoch, which counts confirmed key changes. Parents,
  author, CIDs and operations are inside.
- **Retries:** the push queue keeps sealed bytes and reseals only after
  `StaleEpoch`; the agent deduplicates by id before checking the epoch.
- **Size:** at most 60 KiB an envelope, under `cap::VALUE` and
  `cap::REQUEST` (64 KiB, `agent/wire/src/abi/cap.rs`); larger objects
  are chunked; pushes pipeline, 16 in flight on one channel.

**Seal at push:** a device keeps unsynced operations in its local store and
seals them only when it pushes, under the confirmed epoch read just before;
`Personal::push` refuses another (`StaleEpoch`).

**Sync is a cursor:** the agent numbers each scope's envelopes in the
order it accepts them; `since(scope, position)` returns up to 64 KiB from
a position.

**Fork, rollback and partition detection:**
- each device keeps the highest `(log_index, log_chain)` it has seen
  (`log_chain` a hash chain over the control log, signatures included) and
  refuses a log that is shorter or diverges; every envelope carries its
  writer's view, so a split control log shows (§8, B3, B4);
- every envelope also carries its writer's **`seen` positions**: a device
  that opens an envelope whose author had read to position 900 of a scope
  where the device has been served 300 knows it is being shown a part of
  the scope, and raises the alarm (§8, B19). A few bytes a scope; no second
  channel.
- Nodes sign nothing a device can show a third party, so detection is not
  proof.

**Checkpoints at the agent's positions:**
- a checkpoint is a scope's state after every envelope up to a position
  `P` whose causal past is complete, so every device that has read to `P`
  computes the same state; its author pushes it sealed with `P` and the
  state's hash inside;
- **a new device trusts the checkpoint of the device it pairs from:** that
  device already hands it the archive and `R`, and sends the checkpoint's
  hash over the pairing channel (§3.8). A restore, with no pairing device,
  trusts a checkpoint that two devices other than its author acknowledged
  (each having recomputed it), or replays.
- Garbage collection of covered envelopes is later work (§9.3).

**Quotas** (per agent, the space's policy, enforced by `Personal`): bytes
held (8 MiB for a new agent, 64 MiB after its first re-proof, §3.3),
envelopes and commits a day, inbox items.
Admin-signed operations, the commits carrying matured ones, confirmations
and `alive` are exempt, so no device can block its own removal by filling a
quota; each device has an unadvertised share of at most half the agent's
bytes and calls.

**Background sync:** a WorkManager job pushes queued operations, posts
`alive` if a restore is pending, reads the control log and each scope's
cursor, applies, and raises a local notification when an operation is
pending. Android runs it late or not at all in the "rare" and "restricted"
standby buckets, after a force-stop until the app is opened, and under some
OEMs' battery managers; the chrome shows each device's last sync and
recommends the battery-optimization exemption, and PG6 measures these
cases before the device-change windows are pinned (§8, D5).

### 3.7 The inbox

A table in `Personal`, keyed by `(expiry, id)`; **expiry is lazy** (reads
skip expired items, each write deletes a few; no timer).
- **Writers** in slice 8: the user's devices and a pairing slot's holder.
  Others' messages wait for messaging (slice 9).
- **Readers:** the user's devices by their sync keys; a slot by its two
  parties.
- Items are sealed to the device group or a slot's key; bounds: 64 items,
  16 KiB each, a TTL of at most 7 days, pairing slots 10 minutes and
  single-use.

### 3.8 Pairing, memberships, and retiring a phone

**Pairing:**
1. **The existing device** (A, active) opens a pairing slot under its
   sync key (a slot grants nothing; only the add does): a random slot id
   and a slot key the agent admits for that slot alone, 10 minutes. A shows a QR code: the home's
   handle and onion addresses, the slot id and key, A's ephemeral X25519
   key, and a 128-bit code.
2. **The new device** (B) scans it, generates its admin key in its
   keystore, draws its sync key and a KeyPackage, and runs
   `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b` with A through the slot, the code
   its pre-shared key.
3. **Over the Noise channel,** B sends its public keys, the admin key's
   attestation and its KeyPackage; A sends the key archive, the naming
   secret, `R`, and its newest checkpoint's hash per scope.
4. **A adds B in one admin call, on one prompt:** for a strong admin an
   add is immediate, so the add and its commit are one call,
   `commit(epoch, add(B's keys, B's "home" nullifier), handshake,
   welcome_hash)` (B computes its nullifier from its own member secret;
   its membership in the home follows below), with B's Welcome in the
   evidence call. B is in probation, and reads and writes at once through
   the archive. A delayed admin's add is an operation first and its
   commit, after the 72 h, a second call.
5. **B joins:** fetches each scope's checkpoint (A's, by the hash it was
   given) and the envelopes after it.

**Memberships elsewhere** (E2: each device has its own secrets):
- **in every space other than the home, at once,** on the pairing's own
  prompts: A calls each registrar's `enroll_device(member(s_B),
  owner(s_B))` under `#[msg(credential = Owner)]`, one proof per space
  (the member secret's per-use prompt, since the keystore's HMAC is per
  handle and per use: a user in eight spaces answers eight prompts, and
  the chrome lets them defer any space), batched over Tor. Those
  registrars never see the personal agent, so there is nothing to blur;
- **in a home-only space,** B makes its own open claim (§3.3), in the
  background after pairing: no enrollment by A, no link, and no wait on
  the pairing's path;
- **in a home that is the user's own space,** the user chooses "now" (the
  default, since §3.10 already concedes the link there) or "at my next
  sign-in".
- The registrar keeps a person record (each device's member and owner
  digests, their count and a per-member limit), which a credential actor
  alone cannot (member and owner digests are unlinkable by design).
- **`once` scopes** admit one nullifier per device in slice 8 [decided,
  §9.1]: a member with three devices can vote three times where a space
  uses `once`, which the space's chrome states. A ring of person leaves is
  later work (§9.3).

**Removing a device** is §3.5's removal and, in every space other than the
home, `revoke_device` at once from another device, on its prompt.

**Retiring a phone** (the usual replacement, every few years, and the
answer to a stolen phone):
1. pair the new phone from the old one (above), which enrolls it in every
   space;
2. once the new phone shows the user's data, remove the old one: at once
   by two seasoned devices, else the 72 h removal; and revoke its leaves in
   every space;
3. offer to wipe the old phone.

For a stolen phone the user runs steps 2 and 3's revocations from any
remaining device; a user with no other device uses the kit (§3.5) and each
registrar's ordinary process, and the chrome states that cost.

### 3.9 Home spaces: several, and moving home

**Several homes** [decided, E8: allowed, one built]. Exactly one home
orders the group; a second home mirroring the first, and a live handover,
are later work (§9.3).

**Moving home** (the home vanishes, turns hostile, its lease lapses, or
the user wants out): devices are full replicas, so nothing is lost but the
agent. A device claims an agent in another home, creates a new group,
re-splits the kit (a new `R2` at the new agent) and pushes everything,
including recovery envelopes; the other devices pair again by QR. Until
the move completes, the kit opens nothing at the new home. The old
operators keep what they held; deletion there cannot be verified.

### 3.10 What the operators see

**At a home-only space** [E14's default]: the operators see that a
personal agent exists, when it was assigned to a pseudonym, its device set's
public keys and changes, its liveness and sync times, envelope counts and
padded sizes per opaque scope, and its recovery entries. Its members are
pseudonymous open claims, so the registrar's records link the agent to no
one. What remains to correlate: timing and sizes over Tor, and anything a
user's other spaces also see at the same moments (a sign-in somewhere at
the second a device syncs).

**At a home that is the user's own space,** the operators can link the
agent to the member [E5, restated]: device changes at the agent against
device enrollments for one person, device counts against counts, sync
times against sign-in times. The app says so when the user chooses it.

**Other members and outsiders** read nothing of a personal agent (its
queries are gated, §3.3), and reach it only through the onion.

**They do not see** the data, the scopes' names, the DAG's shape, or the
devices' addresses. They can withhold, delay, roll back, equivocate or
partition, which devices detect (§3.4, §3.6), and delete, which devices
survive.

**Linkability rules** [decided, E10, E17]:
- sign-in, owner and spend proofs go from the device to their target,
  never through the personal agent;
- the personal agent's traffic goes only through Tor, refused by the agent
  otherwise, in its own isolation group, on its own background schedule;
- the sync key and the admin key are used nowhere else, and the member key
  signs nothing the personal agent stores;
- no push-notification token (FCM, APNs) is given to any space; devices
  poll, and raise local notifications.

**Messaging later** (slice 9) builds on `vos-mls` [E12]. MLS virtual
clients share a virtual leaf's signature and HPKE keys across the user's
devices, a secret that syncs, against E2's letter: slice 9 asks the owner
first.

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
wrap (§9.1).

### 4.2 Every device statement a kernel in an actor

Sign-in, ownership and spending are `#[attestable(device)]` methods,
each a short Rust function in the actor whose state it concerns:
- **auth** and **owner** in the credential actor (`vos-credentials`), the
  stock kernels every space gets with it;
- **spend** and **join** in the payments actor (§5; slice 9, E13);
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
  measure first, §9.1]. A target change rebuilds every guest ELF
  (`pvm/guest/riscv64em-vos.json`), so every pinned blob and program id
  moves: measured on a branch in M0, landed with M2's re-pin;
- **a gate:** the SDK-form auth kernel within 1.15× the hand-lean kernel's
  steps.

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
  later the pool's `spend_reference`). The derivation records it; the
  leader computes the program at install by running it, as auth's today; a
  replica that did not install computes it at the first proof naming the
  kernel, as today.
- **Sizes and witnesses:** every chip is padded to the program's sizes, so
  a proof's shape is the program's whatever the witness. A witness whose
  run needs more rows than the reference's fails to prove (an error on the
  device, never a different proof shape); branch-free kernels avoid it,
  and a kernel that branches declares `headroom = k` (each size raised by
  `k` powers of two). The testkit's `device_fits` property test runs
  random witnesses against the reference's sizes.
- **Computed at release, on the phone never** [proposed]: the stock
  kernels' device programs, and the transpiled programs of the light
  node's own local actors, are computed by the release build and embedded
  with their ELF bytes. The phone runs no transpiler and no reference run;
  it compares the program id a space installed with the one it embeds, and
  "reproducible" reduces to the app and the space taking the same release
  artifact by hash.
- **Which kernels see a secret** [proposed, the slice-8 rule]: the light
  node puts a member secret (and, in slice 9, a spending key) only into
  kernels it ships, whose programs it embeds: the stock `auth` and
  `owner` (and in slice 9 the pool's `spend` and `join`, from its own
  build of cipher-clerk's `shielded::check`, §5.4). It proves one of them
  only under a program id its compatibility window admits (below). A
  kernel whose bytes a space serves may take only the user's public data:
  otherwise a space could install a kernel whose public claim is the
  secret itself (§8, G2). So in slice 8 a developer's own device kernel
  proves over public data and over data the user explicitly hands it,
  never over keys; a consent model per program id is later work (§9.3).
- **Compatibility windows** [proposed]: so that an app release and a
  space's upgrade need not land on the same day, each stock kernel's guard
  admits a **window** of program ids, at most two: the current release's
  and the previous one's; ingress admits the device formats likewise (at
  most the current and the previous). A program id embeds its format
  (§4.4), so a previous program is only ever verified under the previous
  format.
  - **How a window ends:** a release adds its ids and sets the previous
    release's retirement, 60 days on by default; the space's operator may
    set it to any earlier date, **now** included, when a version is found
    unsound. At the date the entry is deleted, so nothing older than one
    release is ever admitted and no version table grows. The light node
    proves with the newest program it ships that the space admits, and
    when the space admits none it says the app or the space must update.
  - **One claim per window:** two versions in one window must compute
    identical claims (auth's nullifier, owner's digest) with identical
    meaning, so a `once` scope admits a member once whichever version
    proved, and pseudonyms do not change at a release. A kernel whose
    claim changes is a new guard name (a new scope), never a window
    member.
- **Pins:** the binding names the program id, so a proof of one kernel
  authorizes nothing under another. No venue pins device ids (device
  proofs are not folded, `proving.md` §11, "Device proofs are not
  folded").

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
  from the 645 ms gate run it is about 478 ms, so 0.5 s would leave a 4%
  margin. The plan's gate is therefore **0.65 s, with 0.55 s the target:**
  format 47 ships at what it measures under the gate, and if it misses,
  M2 holds and the 4-way CPU split by opcode family (`open.md`, "Proving")
  is the next lever.
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

P1 is built in slice 8 on cipher-clerk v0.3.0's L0 kernel, which it
needs as it is; P2 and cipher-clerk v0.4 (§5.3), which only P2 needs, are
designed here and built in slice 9 on the finished personal space and Tor
[decided, E13].

### 5.1 The shape

Two actors and one library:
- **`Payments`**, a public actor in the space: cipher-clerk's double-entry
  ledger (transparent accounts held by owner digests) beside a shielded
  pool (note commitments, nullifiers, encrypted notes). It never sees a
  note's value or owner.
- **`Wallet`**, a local actor in the user's personal space (§3): the notes
  the user's devices hold and the nullifiers they have spent, each note
  marked with the device whose key spends it (E2), synced across the
  devices through the personal space.
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
2. **P2, private** [slice 9, E13]: the shielded pool and the
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

**What changes, released as v0.4.0 (breaking) in slice 9, with P2, from cipher-clerk's own
repository:**

| # | change | why | Phase 3 item |
|---|---|---|---|
| R1 | **One hash, Poseidon2-M31's compression `C`**, behind a trait `Compress { fn compress(l: &Digest, r: &Digest) -> Digest }`; cipher-clerk ships no permutation; VOS's SDK implements it over `0x402` in a kernel and natively on hosts; cipher-clerk's tests take golden vectors from VOS | the zkVM proves `0x402` in one chip row and BLAKE2b or a curve not at all cheaply; one hash keeps device shapes free of BLAKE2b (`proving.md` §8, `H_io`) | 8 |
| R2 | **Hash commitments, not Pedersen**: `cm = C(C(T(note), [asset, v₀, v₁, v₂, 0…]), C(rho, C(owner, r)))`, value in three 24-bit words; `r` a 248-bit blinding the caller passes (randomness as a parameter, v0.3.0's rule kept). The order lets a pool compute a deposit's `cm` from a public amount, a protocol `rho` and the depositor's `C(owner, r)` (§5.4) | the spend proof checks the balance in Rust, so no homomorphism is needed; no curve in the kernel | 4 |
| R3 | **Keys hash-only, per device**: `sk` per device and pool, 32 random bytes drawn by the light node, wrapped under a per-use keystore key; for recovery, HPKE-sealed to each kit's X25519 key (never under `R`, which every device holds) and stored at the personal agent, released only to a matured restore as `R2` is (§3.5), re-sealed at each kit rotation: no device opens another's `sk`, a leaked kit alone gets nothing before 7 days unvetoed and unrefuted, and the operators with a leaked kit can spend (slice 9 asks the owner, §9.1); `owner = C(T(note-owner), sk)`, `nk = C(T(note-nf), sk)`; the device proves knowledge of `sk` | spend authorization without an embedded curve: option 1 of item 1 ("the device proves, with `ak = Poseidon(ask)`"); no delegated proving, which the light node does not need | 1, 2 |
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

The wallet, a local actor whose scope the personal space syncs:

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
the actor; it is a later extension of the local host (§9.1).

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
- **The gate** (slice 9's PG4, a target until the spend's steps are
  measured): the spend at most 1.0 s at the median
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
  gateway's leader-aware routing behind it. `Credentialed` is behind the
  node's in-flight cap on large requests, per-circuit caps and a cap per
  onion; Tor itself bounds a flood of well-formed junk proofs (about 1 MB
  each) to far below a node's verification budget, and malformed short
  ones fail their decode in microseconds. The pre-check that would refuse
  a well-formed junk proof in under 1 ms is an optimization with a target,
  not a precondition (plan 8.5), and a flood through Tor is measured in M5
  (§6.6). The light node's `vos-api` client runs over the `DataStream`
  unchanged (a multiplexed client over any futures-io stream).

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

### 6.5 Fallbacks, the Tor-only rule, and blocked networks

- **The clearnet gateway, by the space's policy,** for calls to a space
  (not the personal agent): a space declares `tor = required | preferred |
  off` in what enrollment pins. Under `preferred` the client falls back to
  the gateway's TLS or SSH address after a bootstrap failure, and its
  chrome says the call is not private; under `required` it does not.
  Recommended default: `preferred` for sign-in and the transparent ledger,
  `required` for the shielded pool's calls (slice 9).
- **The personal agent is Tor-only, by rule** [decided, E17]: the light
  node has no clearnet route for any kind addressed to the personal agent
  or `Homes`, and the agent refuses a request its gateway did not receive
  on the onion (§3.3). Over the clearnet it would hand the home's operators
  the device's address beside its pseudonym.
- **No bridges in slice 8** [decided, E19]: plain Tor only. Bridges
  (arti's bridge client, which would defeat networks that block Tor by its
  public relay list) and pluggable transports (obfs4 through lyrebird,
  Snowflake, WebTunnel, which defeat deep packet inspection but each bring
  a Go binary run as a managed subprocess on Android) are later work
  (§9.3).
- **What a user behind a network that blocks Tor sees** in slice 8:
  sign-in and P1 calls fall back to the clearnet where the space allows
  it, saying so; the personal space keeps working locally, does not sync,
  and shows "backup paused: this network blocks Tor" with the last sync
  time. **The stated limit:** its timed safeguards run without the device
  meanwhile. It can neither veto a removal (72 h) nor post the `alive`
  that cancels a restore (7 days), so a leaked kit's restore can mature
  against a user whose every device stays behind such a network for a week
  (§8, H2).
- **A wrong clock:** Tor refuses a consensus outside its validity, so a
  phone whose clock was set by hand fails to bootstrap; the chrome names
  the clock as the cause.

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
  (§9.1).
- **Limits per circuit and per service:** streams per rendezvous circuit,
  requests a second per stream, calls per agent per circuit (so one
  circuit cannot fill a personal agent's log), and a global cap of proven
  calls in flight through the onion (the node's verification budget
  behind it, `Busy` past it). Personal agents also admit only known keys
  (§3.3).
- **The proof's own cost:** a proven call carries the device format's PoW
  (16 bits), a grinding parameter more than a price: a well-formed junk
  proof costs the node 5.8–8 ms today [measured, format 46]. Tor's own
  throughput to one onion bounds such proofs to tens a second, below a
  node's budget (about 150 a second a core); M5 measures it, and the
  pre-check (§4.3, plan 8.5) lowers the cost further when it lands.
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
fallback should the onion be flooded before then (§9.1); pin one arti
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
| `vos-light` (new, `node/light`) | the light node: merge and query dispatch over its store (no log), the release artifacts it embeds (local actors' programs, the stock kernels' device programs), the prover's device path, the node-API client, sync of sealed scopes, the device group through `vos-mls`, arti's client behind a feature; replaces `vos-device` one for one |
| `vos-mls` (new, `support/mls`) | one MLS layer for VOS over mls-rs [decided, E12]: storage providers over fjall, copy-and-swap of group state for candidates, the confirmation hash, a proposal policy per user (the device group's: Add, Remove, Update); the device group its first user, messaging later |
| `vos-node` (`node/host`) | admission at ingress for an agent that asks: known keys looked up before the signature, and the gateway's transport mark for onion-only agents (§3.3); the device-format window at ingress (§4.4). The light node does not carve it up: it needs only the executor's host-call layer, which moves to a crate both link (plan 8.6); `credentialed.rs`'s use of `vos_pvm_recair::device` moves with it |
| `vos-pvm-recair` | `credential` deleted; the leaves, folds and wrap behind a `recursion` feature, on by default (the masking needs `context`, `circuit` and `trace`, which stay), so a device links less of the recursion prover (§9.1) |
| `vos-pvm-final-verifier` | `credential` and `credential-bytes` deleted |
| `vos-sdk`, `vos-sdk-macros` | `#[attestable(device, reference = …, headroom = …)]`; `#[msg(proven = kernel)]`; in-place kernel arguments; `vos_sdk::p2` (digests, tags, paths); `crdt::{GSet, Set, Map}` and `#[msg(merge)]` on the light node |
| `vos-wire`, `vos-api` | `Credentialed.claim` in place of `CredentialPublic`; `CredentialedInput` carries the claim; `Principal::Kernel { program }` (index 7); `CredentialKind` deleted; the frame's transport mark (`node-api.md` §2; a missing mark is clearnet, §3.3) |
| `merkle-crdt` | the incremental apply (`core-model.md` §9.4); the author, its sequence and signature in the payload; a `Store` over fjall; fetching by batch, asynchronously (today's `fetch_missing` walks one node at a time, synchronously, `src/sync.rs`); the `redb` store and feature deleted (one storage engine) |
| `vos-credentials` | the stock `auth` kernel (from the `device` test actor, in SDK form) and a new `owner` kernel, with their references; each stock guard's compatibility window of program ids (§4.4); the stock kernels' ingress checks stay in the node (§4.3); the registrar's open claim priced by work (§3.3), its person records, `enroll_device` and `revoke_device` (§3.8) |
| `vos-gateway` | the onion service behind a `tor` feature (§6); a `vos-api` byte-stream port on it; the transport mark on every relayed request; per-circuit, per-agent and per-onion limits; every node of its space listed as an upstream when it serves a home (§3.3) |
| new system actors | `Homes` (the pool, claims, the indexes by nullifier and by kit key, the yearly re-proof and the lease) and `Personal` (the device set and its contests, liveness, the commit log and confirmations, sealed scopes, checkpoint acknowledgements, the inbox, quotas, gated queries, an append-only layout), each one package; `Payments` (replacing the `purses` test actor) |
| new tool | the operator's keeper: topping up the pool, granting `Homes` its role, upgrading `Personal` in batches (§3.3) |

**Net:** two crates in (`vos-light`, `vos-mls`), one out (`vos-device`);
the credential AIR's modules, one feature, one format, its fixtures and its
fuzz target out; merkle-crdt's redb out. In: arti's dependency tree (in
the gateway and the light node), mls-rs's (in `vos-mls`), three actors, a
tool, the SDK's CRDT fields and merge dispatch, and admission at ingress.
No proving code beyond the levers' format.

### 7.2 The node and the gateway

- **The node** gains no transport and no knowledge of Tor, MLS, JAM or
  Kreivo. Its ingress generalizes (§4.3), admits a window of device
  formats (§4.4) and, for an agent that asks, admits only known keys and
  only onion-marked requests (§3.3); its install computes a device program
  for every device kernel (§4.4); format 44 goes. The personal agent is
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
  personal agent at a home-only space by default, with a phrase or
  security-key kit), `pair` (§3.8, a QR shown and scanned, with the
  enrollments in every other space), `retire` (a phone), `devices` (list,
  last sync, remove, veto, resolve, contests, kit rotation, admin-key
  replacement; each behind the admin key's prompt), `restore` (from a
  kit), `move_home` (§3.9), the yearly re-proof (with the leaf renewal on
  the same prompt), and local notifications for pending device
  operations. These are new Kotlin screens in s4's client, their own plan
  step (8.24), over the `:vos` process's Binder interface (§2.2, plan
  8.24b).
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

**A1. Two devices change the device set at once,** one offline.
*Mitigation:* the agent's log orders operations and commits; one candidate
per epoch (`EpochTaken`); the loser rereads and re-proposes only if its
intent still holds; no device commits offline. (8.13, 8.19)

**A2. A device is lost or stolen, locked.** Before its first unlock since
boot nothing opens. After a first unlock the sync key and the MLS state
work while the screen is locked, so a thief who keeps the phone powered
and runs code on it reads the personal space; the admin key stays in the
hardware keystore behind the owner's strong biometric. *Mitigation:* the
owner retires the phone from another device (§3.8) or with the kit.
*Known limit:* after-first-unlock exposure, the price of background sync
on a locked phone; stated in the light node's `SECURITY.md`. (8.13,
8.23a, 8.28)

**A3. A device is stolen unlocked, or malware runs in the app's process.**
Either reads what the phone reads and holds its sync key: it can push
garbage (C1), nack commits (A21), post `alive` and use the device's share
of the quota (C5). It can neither commit nor sign a device-set operation:
both need the admin key, which never leaves the hardware keystore and
signs only after the owner's biometric. The kit removes it even with no
other device (A4). *Known limit* for what the phone shows. (8.13)

**A4. A thief who passes the owner's strong biometric** (coercion, a weak
sensor) holds an active device. *Mitigation:* the symmetric rules (§3.5):
he removes nothing uncontested while the owner vetoes; the owner wins a
contest with one device and the kit, or two other seasoned devices; a
thief holding only a sync key loses even to the kit alone, in 14 days (its
removal cannot be vetoed without the admin key, and a removed device's
`alive` is ignored). *Known limit,* and only this: a thief who passes the
biometric can always contest, so against him the kit alone does not win.
Property-tested against an adversary with one device and its biometric
who may also pair devices, and one with a sync key alone. (8.13)

**A5. A device returns after weeks or months.** *Mitigation:* while away
it is outside the confirming set, so the awake devices are never blocked;
it processes the confirmed commits on return (handshakes are kept 180
days) and re-pairs if one does not process or if it was away longer.
(8.19, 8.23a)

**A6. A long replay on a phone,** killed midway. *Mitigation:* each commit
applied in one fjall batch, the stored epoch checked before and after; a
gap of more than a few hundred commits prefers re-pairing. (8.19)

**A7. A removed device backdates DAG writes.** *Mitigation:* seal at push
takes only the confirmed epoch; the agent refuses its keys; devices accept
its envelopes only up to its frontier, and the CRDT types filter its
writes at read. (8.18a, 8.20)

**A8. A write made offline leaks to a device removed meanwhile.**
*Mitigation:* seal at push under the confirmed epoch read just before;
`StaleEpoch` otherwise. (8.20)

**A9. A device takes a candidate as current before it is confirmed,** the
first cause of forks in deployed MLS. *Mitigation:* candidates are
processed on a copy of the group state and swapped in only on
confirmation (mls-rs applies received commits at once, so the copy is the
mechanism). (8.19)

**A10. Retries and leader changes.** *Mitigation:* the queue keeps sealed
bytes and reseals only after `StaleEpoch`; the agent deduplicates by id
before the epoch check; a commit is a candidate once. (8.12, 8.20)

**A11. An OS backup or a cloned phone restores MLS state on a second
device.** *Mitigation:* MLS state, the archive and the queue are excluded
from Android's backup and wrapped under a key that does not migrate; a
restored copy starts as a new device (A13). A clone's commit cannot be
confirmed consistently and is voided. (8.19, 8.22)

**A12. The user's biometrics change,** invalidating the admin key.
*Mitigation:* another seasoned device, or the kit, signs a replacement
admin key; the device keeps its seasoning, and the new key signs nothing
for 72 h. (8.23b)

**A13. The app is reinstalled on the same phone.** Keystore keys are gone;
the phone is a new device. *Mitigation:* it pairs from another device or
restores from the kit, then removes its own ghost, which never confirms
and so blocks nothing meanwhile. (8.23a)

**A14. A thief who passed the prompt pairs his own device** to gain a
second vote. *Mitigation:* the new device is in probation for 72 h, its
probation frozen while a removal against it is pending or contested, and
it counts for two-device rules only after 7 days' seasoning; so the
owner's removal of it, contested by the thief, cannot be outvoted inside
its own window. (8.13)

**A15. Clocks are wrong.** *Mitigation:* delays, probation, seasoning,
retention and the lease run on the agent's batch time; a device whose
clock disagrees by more than an hour raises an alarm and acts as the log
says; Lamport counters order CRDT operations. (8.13, 8.19)

**A16. A committer forks the group selectively,** good path secrets to
some devices and garbage to others. Committing needs the admin key, so the
committer is the owner's own device or a thief who passed the biometric
(A4). *Mitigation:* an awake target nacks and the epoch is void, nothing
sealed; a sleeping target, outside the logged confirming set, finds on
return that it cannot process the commit, raises an alarm naming the
committer, and re-pairs or regroups (§3.5). (8.19, 8.21)

**A17. A commit carries a proposal the design does not use** (ReInit, an
external commit, a PSK, a group-context change). *Mitigation:* `vos-mls`'s
policy for the device group nacks anything outside Add, Remove and Update,
and any Add or Remove not matching a matured signed operation. (8.19)

**A18. A device without a strong biometric.** *Mitigation:* a delayed
admin: its operations wait 72 h and can be contested; pairing works, 72 h
later. (8.13, 8.23a)

**A19. A shoulder-surfed PIN.** The thief signs in and pays from P1 (the
member secret keeps its decided PIN fallback) but cannot sign a device-set
operation unless the device is a delayed admin, whose operations wait and
can be contested. The owner retires the phone, which revokes its leaves in
every space at once. *Known limit:* P1 money has the lower bar; `rekey` is
its remedy. (8.7, 8.23a)

**A20. Two attacker devices nack each other's removal.** *Mitigation:* one
commit carries both matured removals, and nacks from devices whose
removal has matured are ignored. (8.12, 8.19)

**A21. A device nacks every commit** (a bug, a thief). Key changes stall,
not data. *Mitigation:* its removal's commit needs nothing from it; the
chrome names the device that nacks. (8.19)

**A22. Phone replacement every two or three years.** *Mitigation:* "retire
this phone": pair the new one (enrolled in every space at once), then
remove the old one, revoke its leaves everywhere, and offer to wipe it.
(8.23a, 8.24)

**A23. A sync-key thief waits for the owner's other device to go quiet,**
then commits garbage to it. *Mitigation:* a commit is an admin call,
verified at ingress and by every device through its evidence, so a sync
key alone commits nothing. (8.12, 8.19)

**A24. A device cannot follow the confirmed epoch and has no device to
re-pair from** (a buggy commit, a lost committer, a lockout). *Mitigation:*
a regroup signed by its admin key: 72 h and a veto, or at once with two
seasoned devices or the kit (§3.5). (8.13, 8.23b)

### 8.2 The home space and its operators

**B1. The operators withhold or delay sync.** *Mitigation:* devices work
offline and are full replicas; after 7 days without the agent the chrome
offers to move home. (8.20)

**B2. The operators delete envelopes.** *Mitigation:* each device fetches
a sample of positions it pushed and re-pushes what is missing. (8.21)

**B3. The operators roll the agent back.** *Mitigation:* a control log
shorter than, or diverging from, the highest view a device saw raises an
alarm. (8.21)

**B4. The operators equivocate** on commits or on operations.
*Mitigation:* two commits for one epoch give two signed `h` and a void;
views in envelopes catch a split control log. *Known limit:* nodes sign
nothing a device can show a third party, so an alarm is not proof
(`open.md`, "Node-signed roots"). (8.19, 8.21)

**B5. The operators inject or replay.** A forged envelope fails its AEAD; a
replayed one is a duplicate; a replayed commit breaks the epoch rule.
*Mitigation:* as stated. (8.20)

**B6. The operators forge device-set operations.** *Mitigation:* every
device verifies every operation's and confirmation's signature itself,
from the evidence stored beside it; an operation without evidence moves no
device.
(8.13, 8.19)

**B7. The operators advance the agent's clock,** maturing a hostile
removal or a restore early. *Known limit:* delays trust the operators'
clock; devices alarm on more than an hour's skew; it helps only a thief
who already passed the biometric (A4) or holds the kit (D3), or B8. (8.13)

**B8. The operators collude** with a thief or a removed device: dropping
vetoes, ordering the thief's operations first, placing a removed device's
backdated writes before its frontier, marking awake devices absent, and
serving a removed device data sealed before its removal's epoch is
confirmed, for up to 72 h after the 72 h removal delay, six days in all.
**Acting alone,** they can hold back a genuine admin-signed commit until a
device is quiet and name it absent in the logged confirming set, locking
it out until it re-pairs or regroups; they cannot make a commit.
*Known limit:* the home is trusted for availability, order and time
(`core-model.md` §5); the owner's remedies are two seasoned devices'
immediate removal and moving home. (8.28)

**B9. The agent loses its quorum.** Sync and device changes stop; local
work continues. *Mitigation:* devices queue and retry; the lease counts
re-proofs, not uptime. (8.12)

**B10. A home with one replica.** *Mitigation:* the chrome shows the
replica count; devices remain full replicas. *Known limit:* losing that
disk and every device at once. (8.14)

**B11. The pool runs out,** or the open claims' daily cap is reached.
*Mitigation:* `Homes` answers `PoolEmpty`, the designed symptom (the cap
is kept below the keeper's refill rate so the disk never fills first); the
keeper tops up, the device stays local and retries. (8.14)

**B12. `Homes` assigns one agent twice, or one nullifier twice.**
*Mitigation:* unique Linear indexes in `Homes`; `assigned`/`refused`
replies. (8.14)

**B13. A user's second device claims a second agent** (its nullifier
differs under E2, so `Homes` cannot tell). *Mitigation:* the chrome
refuses a claim on a device that already holds an archive. (8.23a)

**B14. A member is expelled, or stops re-proving.** *Mitigation:* the
lease lapses 13 months after the last re-proof; the agent then refuses
pushes for 180 days of grace but serves reads, a restore and a move, so the
data stays recoverable (E15). Each device's home nullifier is recorded at
its add, so any device can re-prove even after the claiming one is gone.
*Known limit:* reaping after the grace is later work. (8.14)

**B15. The user stops using every device** with the kit in a drawer.
*Mitigation:* the lease needs only one re-proof a year; past it, the grace
leaves 180 days for a restore. (8.14, 8.23b)

**B16. The home vanishes or turns hostile.** *Mitigation:* move home by
re-pairing (§3.9); nothing is lost while one device holds the data.
*Known limit:* the kit opens nothing until the move re-splits it; a
successor group and a live handover are later work. (8.23c)

**B17. Personal agents fill the space's disks.** *Mitigation:* a 64 MiB
default quota; the scale gate measures a full agent's snapshot and a
`replace` against limits. (8.15)

**B18. `Personal` is upgraded over agents that hold data** (`Install`
touches no table; migration is unbuilt). *Mitigation:* an append-only
layout across versions, an upgrade test over a populated agent, and the
keeper upgrading in batches and stopping at the first refusal. *Known
limit:* a hostile upgrade is B8. (8.12, 8.14)

**B19. The operators show each device only its own envelopes**
(partition). *Mitigation:* every envelope carries its writer's `seen`
positions; a reader served less of a scope than a writer had read raises
the alarm. (8.20, 8.21)

**B20. The home space re-founds** (a new `SpaceId`, members re-enroll).
The agents and `Homes`' indexes survive if the agents do; the "home"
scope includes the space, so nullifiers change. *Mitigation:* each device
re-records its new nullifier at its next re-proof; the kit carries the
home's stable handle, not its `SpaceId`. (8.14)

### 8.3 Data, storage and quotas

**C1. A device writes garbage** that opens correctly. *Mitigation:* apply
validates each operation; a node that fails is quarantined and the chrome
names its author. *Known limit:* excising a device's range after the fact
is later work; the remedy is removing the device. (8.18b)

**C2. The DAG grows without bound, or a user stores media.** *Mitigation:*
checkpoints let new devices start late; the quota bounds the agent; the
push API is blob-ready. *Known limit:* garbage collection and a blob
store are later work; media fills the quota fast. (8.20, 8.21)

**C3. Two devices checkpoint at once.** *Mitigation:* checkpoints are cut
at agent positions, so both hold the same state. (8.21)

**C4. A wrong checkpoint.** *Mitigation:* a paired device trusts only its
pairing device's checkpoint, whose hash it got over the pairing channel; a
restore trusts one acknowledged by two devices other than its author, or
replays. (8.21)

**C5. Quotas fill,** perhaps to block the filler's removal. *Mitigation:*
operations, the commits carrying them, confirmations and `alive` are
exempt; each device has an unadvertised share. (8.12)

**C6. Large objects.** A 1 MiB checkpoint is 17 envelopes and 17 pushes.
*Mitigation:* chunking; the scale gate pushes full 256 KiB steps; the API
is blob-ready. (8.15, 8.20)

**C7. Inbox spam.** *Mitigation:* only the user's devices and a slot's
holder write; slots are single-use and last 10 minutes; admission by known
keys. (8.11, 8.12)

**C8. Sizes and timing describe the user.** *Mitigation:* Padmé padding,
opaque scope ids, structure inside the ciphertext. *Known limit:* counts,
times and the epoch counter remain; foreground sync follows app use; no
cover traffic. (8.20)

**C9. Two key archives disagree.** *Mitigation:* every candidate key is
kept and the AEAD decides. (8.20)

**C10. Fetching on demand reveals what the user reads.** *Mitigation:*
devices are full replicas, fetching on a schedule; member trees stay
device-local. *Known limit:* a device too small for a full replica, and
slice 9's wallet mirror of a large pool, are later concerns. (8.20)

**C11. The phone's storage fills.** *Mitigation:* the local store refuses
writes before the disk fills; sync pauses; the chrome says so. (8.18b)

**C12. Years of history for a two-device user.** *Mitigation:* the new
device takes its pairing device's checkpoint, so it never replays from the
start. (8.21)

### 8.4 Recovery and the device's life

**D1. Every device is lost; the kit is kept.** *Mitigation:* restore: 7
days with no veto and no `alive`, then `R2` released, the recovery
envelopes opened (they follow every confirmed epoch), a new group, the kit
rotated; memberships re-enrolled by each registrar's ordinary process,
whose cost the chrome states; P1 accounts by `rekey`. *Known limit:* the
kit holds keys, not data; a home gone or withholding at that moment leaves
it nothing; the encrypted export file is later work (E16). (8.23b)

**D2. Every device and the kit are lost,** or a single device with no
backup dies. *Known limit:* the personal space is gone; memberships and
P1 accounts come back by each space's process. The app offers backup at
first launch and after (§3.1). (8.23a)

**D3. The kit leaks** (a photo of the phrase in the stolen phone's gallery
is the likely way). *Mitigation:* alone it opens `R1`, not `R2`; its
restore waits 7 days and dies at any device's `alive` or veto, and every
device is told loudly for those 7 days; the security-key kit cannot be
photographed, and the chrome never shows the words as a QR; the owner
rotates the kit, deleting the old `R2`; a restore always rotates it.
*Known limit:* the operators and a leaked kit together read everything;
a thief holding the kit, a phone and the owner's biometric wins (A4).
(8.13, 8.23b)

**D4. The kit points at old onions.** *Mitigation:* the kit carries the
handle and the onions at the claim; the agent is found by the kit's key.
*Known limit:* a home whose onions all changed is found only through the
registry of spaces, not built. (8.23b)

**D5. The background job does not run** (the "rare" or "restricted"
bucket, a force-stop, an OEM battery manager, a cold Tor bootstrap that
eats the job's 30 s). *Mitigation:* the chrome shows each device's last
sync and recommends the battery exemption; PG6 measures these cases
before the windows are pinned. *Known limit:* a device whose job never
runs neither vetoes nor posts `alive` until the user opens the app. (8.22)

**D6. Android kills the process mid-write.** *Mitigation:* each local
operation, MLS state change and queue change is one fjall batch; pushes
and commits are idempotent. (8.6, 8.19)

**D7. A local actor's new version changes its state's shape.** *Known
limit:* state migration is unbuilt; such an actor starts a new scope and
the device re-imports. (8.18b)

**D8. An app release and a space's upgrade land days apart.**
*Mitigation:* compatibility windows: each stock guard admits the current
and the previous release's program ids, and ingress the current and
previous device formats, for 60 days or until the operator retires the
previous one, at once if it is found unsound; the two versions compute the
same claims; the light node proves with the newest program the space
admits. (8.4, 8.10)

**D9. Devices run different app versions.** *Mitigation:* versioned
operations; unknown kinds wait for the update. (8.18b)

**D10. The security key is lost** (the kit of that kind). *Mitigation:* a
second kit (the phrase, or a second key) is offered at the claim; rotation
from any seasoned device replaces it. (8.23b)

**D11. The UI is swiped away, or crashes, mid-proof or mid-sync.**
*Mitigation:* the light node runs in its own `:vos` process [E21]; the
UI's death does not touch a proof or a sync, and a crash in `:vos` leaves
the UI to report it. (8.24b)

### 8.5 Cryptography's future

**F1. Harvest now, decrypt later.** *Mitigation:* a hybrid post-quantum
suite if mls-rs maintains one by 8.3; 180-day retention of handshakes.
*Known limit:* a hostile operator keeps what it wants. (8.3, 8.19)

**F2. Changing the suite or the protocol.** *Mitigation:* a successor
group, archives resealed, old envelopes left under their keys; never two
suites in one group. (later)

**F3. RFC 9420's exporter is not forward-secure.** *Mitigation:* moot for
history; the Safe Exporter when mls-rs has it. (8.19)

**F4. An mls-rs defect, or its version churn.** *Mitigation:* `vos-mls`
holds the one pinned version for VOS, upgraded once a slice; a state the
new version cannot read means re-pairing that device. (8.19)

### 8.6 Proving and payments

**G1. Junk proofs.** *Mitigation:* the format's PoW, the in-flight caps
and the verification budget; Tor bounds the rate; the pre-check is a
target. (8.5, 8.25)

**G2. A space installs a kernel that leaks a secret.** *Mitigation:*
secrets enter only kernels the light node ships, by program ids embedded
at release (§4.4). (8.4)

**G3. A space upgrades a stock kernel.** *Mitigation:* the window admits
the previous program for 60 days unless retired sooner, both computing the
same claim; past it, the light node says which side must update. (8.4,
8.10)

**G4. Balances split per device** (E2). *Known limit:* a payment comes
from one device; consolidating under P1 is a visible transfer (L4). (8.7)

**G5. A developer's own kernel wants the user's private data.** *Known
limit:* only data the user hands it, never keys, in slice 8. (8.4)

**G6. PG2′ misses its target.** *Mitigation:* the gate is 0.65 s, the
target 0.55 s; format 47 ships at what it measures under the gate, and the
4-way CPU split is the next lever. (8.10)

### 8.7 The network

**H1. The onion is flooded** before arti's service PoW is declared ready.
*Mitigation:* introduction-point, circuit, per-agent and per-onion caps;
the in-flight cap on large requests; Tor's own throughput bounding junk
proofs; a flood measured in M5; the C tor sidecar as the fallback (Q11).
(8.25)

**H2. Tor is blocked on the user's network.** *Known limit* [decided,
E19]: no bridges in slice 8, so the personal space does not sync there and
says so; its veto and `alive` windows run without the device; calls to a
space may fall back to the clearnet by its policy. Bridges and pluggable
transports are later work (§6.5). (8.26)

**H3. arti's library breaks monthly.** *Mitigation:* one pinned version a
release, an upgrade step each slice. (8.25, 8.26)

**H4. A background job starts cold.** *Mitigation:* arti's state
persisted; an unfinished job leaves everything consistent and the next
resumes (D5). (8.22)

**H5. A gateway's onion key is stolen.** *Mitigation:* the pinned set is
refreshed from the registrar. *Known limit:* answers are unsigned. (8.25)

**H6. A gateway lists only some nodes** of a home. *Mitigation:* a home's
gateways list every node (§3.3); a gateway that cannot reach an agent
answers 421, which the client reports. Forwarding is later work. (8.25)

**H7. Strangers flood a personal agent** (agent ids are sequential).
*Mitigation:* known keys only, looked up before the signature check; the
onion-only mark; per-agent circuit caps; gated queries. (8.11, 8.25)

**H8. One rendezvous per poll.** *Mitigation:* the tree feed on one
long-lived circuit (8.27); PG5 counts rendezvous. (8.26, 8.27)

**H9. A wrong clock stops Tor.** *Mitigation:* the chrome names the clock.
(8.26)

### 8.8 Linkability and membership

**L1. The claim follows the user's sign-ins.** *Mitigation:* at a
home-only space (the default) the user has no other sign-ins there.
*Known limit* at a home that is the user's own space (§3.10). (8.23a)

**L2. One device acts as a member and as the pseudonym.** *Mitigation:*
separate Tor isolation groups, keys used nowhere else. *Known limit:*
foreground sync starts when the user opens the app. (8.26)

**L3. Push-notification tokens identify the user.** *Mitigation:* none is
given to any space; devices poll and raise local notifications. (8.22)

**L4. P1 transfers between one's own devices** link their owner digests.
*Known limit:* P1 is pseudonymous; P2 (slice 9) hides it. (8.7)

**L5. Device changes and counts link the agent to the member.**
*Mitigation:* at a home-only space each device joins by its own open
claim and the registrar has no person to count. *Known limit* at a home
that is the user's own space, stated in the app. (8.14, 8.23a)

**L6. `once` scopes with one leaf per device** admit a member once per
device [decided, §9.1]. *Known limit,* stated in the space's chrome;
person leaves are later work. (8.16)

**L7. The registrar learns which device leaves are one member's**
(`enroll_device`). It already knows each member; the tree still hides
which leaf proves. *Known limit,* stated. (8.16)

**L8. Path fetches and the logged `map_root`** link a member's proofs.
*Mitigation:* the credential tree's feed (8.27). (8.27)

**L9. A space's page asks the device to prove in the "home" scope.**
*Mitigation:* the scope is reserved by the facility. (8.14, 8.23a)

**L10. Other members read a personal agent's control log** (any key may
query). *Mitigation:* `Personal`'s queries answer only admitted keys.
(8.12)

**L11. Open claims at a home-only space are a Sybil door.** *Mitigation:*
a bound on griefing, not a price: the daily cap sized to the home's disk,
the quota ramp (8 MiB until the first re-proof), and work that stops only
the trivial loop; nothing an open member can do reaches another user's
agent. (8.14)

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
  https://www.ietf.org/archive/id/draft-ietf-mls-virtual-clients-01.html
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

## 9. Decisions, risks, and later work

### 9.1 Every question answered

- **P2's slice:** P2, the wallet, PG4 and cipher-clerk v0.4 in slice 9
  [E13, E18]; P1 on cipher-clerk v0.3.0 in slice 8.
- **Where sealed scopes live:** the personal agent's tables through its
  log, with a blob-ready API (§3.6).
- **`once` under per-device secrets:** one nullifier per device in slice
  8, stated; person leaves later.
- **Spending keys and recovery:** with P2 in slice 9, by the mechanism of
  §5.3 R3 (each `sk` HPKE-sealed to the kit's key, released only to a
  matured restore).
- **The device-change parameters:** as §3.5 states them, the windows
  pinned after PG6's measurements of the background job, and set per
  space on test homes.
- **The suite:** ciphersuite 1 unless 8.3 finds a maintained hybrid
  post-quantum suite in mls-rs that fits the phone.
- **MLS or a simpler scheme:** MLS, as one `vos-mls` layer [E12].
- **The home:** a home-only space by default [E14], Virto's listed in the
  app [E20]; **the lease:** a yearly re-proof [E15]; **recovery:** a
  phrase or a security key [E16]; **Tor:** a rule for the personal agent
  [E17], with no bridges in slice 8 [E19].
- **The light node's process:** its own `:vos` process behind Binder
  [E21] (Q5).
- **The remaining design choices,** at their recommendations [E11]:
  generic proven calls, `#[msg(proven = k)]` (Q6); SDK kernels measured
  first, the hand-lean kernels the stock ones if the 1.15× gate misses
  (Q7); glue in the light node's Rust for device effects (Q8); a
  `recursion` feature on `vos-pvm-recair` (Q9); arti in the gateway behind
  a `tor` feature, PoW when a release declares it, a C tor sidecar the
  documented fallback (Q11); the pool's integrity and note delivery with
  P2 (Q10, Q12).

### 9.2 Risks

- **The slice's size:** about 24–34 weeks with reviews
  (`slice-8-plan.md`); the light node's stream is the critical path, with
  s4's screens and the Binder interface at its tail.
- **The Merge lane is unbuilt:** slice 8 builds the device side and sealed
  scopes, not plaintext scopes on nodes.
- **MLS on the device is new code,** with confirmed epochs, admin-signed
  commits and copy-and-swap on top; `vos-mls` carries the `messaging`
  branch's storage providers, snapshot-and-restore and one-commit-an-epoch
  rule, nothing else.
- **10^4 personal agents waking a few times an hour** are unmeasured (plan
  8.15).
- **Android's background limits** decide how soon a device sees a pending
  removal or restore (§8, D5); PG6 measures them.
- **Proof bytes over Tor** dominate a call's latency (§6.3).

### 9.3 Later work this design leaves

One list; `open.md` takes it at the slice's end.
- P2, the wallet, PG4, cipher-clerk v0.4 (slice 9).
- Messaging between members on `vos-mls` and MLS virtual clients, with the
  owner's word on the virtual leaf's shared keys against E2 (§3.10).
- Plaintext Merge scopes on nodes; actors the user installs in the
  personal agent (E9).
- A second home mirroring the first; a live handover; a successor group
  after a lost home; reaping a lapsed agent after its grace, with tenancy
  numbers (§3.3, §3.9).
- Forwarding between nodes, for gateways that list only some (§3.3).
- Person leaves for `once` scopes.
- History horizons and garbage collection of covered envelopes; a blob
  store for media (§3.4, §3.6).
- An encrypted export file under the kit's key [E16].
- Bridges and pluggable transports [E19].
- Excising a device's operations after the fact (§8, C1).
- A consent model per program id for developers' kernels over private data
  (§4.4).
- Node-signed answers, so an alarm becomes proof (§8, B4).
- Local workflows with device effects (Q8).
- A device too small for a full replica (§8, C10).
