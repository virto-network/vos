# The light node, the personal agent, one proving path and Tor

Design, as built: a light node of VOS on the user's devices, a personal
agent in a space that keeps the user's devices in step, one proving path
for every device statement, payments on cipher-clerk as the showcase of
attestable Rust, and clients reaching a space over Tor.
- **Status:** this describes what is built; [decided] marks an owner
  decision (listed in §1.1 by its number, E1–E42, or cited from another
  document), and what is not built is named so and listed in `open.md`.
- **Numbers** carry their tag: [measured] (a run, cited), [model] (the
  cell model, `proving.md` §8), [est] (arithmetic on those, unmeasured),
  [World] (the facility's flows in process over `vos_light::testing`'s
  `Delays::ONION`: a new connection 4 s to its stream, a round trip 0.5 s;
  prompts answered at once; `node/light/android/tests/flows.rs`).

## 1. Goals

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
| E1 | Retire the credential AIR (format 44): one proving path; sign-in about 0.6 s until the levers bring it to about 0.45 s. |
| E2 | Per-device secrets, as today: a member leaf, an owner digest and a wallet per device; the personal space syncs everything but secrets; paying from another device's funds is a transfer between one's own devices. |
| E3 | Payments P1 (cipher-clerk's ledger with owner proofs, replacing `purses`) then P2 (the shielded pool and a local wallet). The order: E13. |
| E4 | No relay held by a gateway: a space has several gateways, and two devices on different ones would never meet. Each user gets a **personal agent** in a space they belong to (the home space): a small log for rare operations (the device set, MLS ordering, quotas), the space's nodes as durable ciphertext replicas of the user's DAG, and an inbox with expiring entries. |
| E5 | The personal agent is owned by a pseudonym, not by the member key. |
| E6 | The space's nodes keep full ciphertext replicas of the user's DAG (durable, a backup), not only expiring mailboxes. |
| E7 | MLS among the user's devices; data sealed under per-epoch keys from the MLS exporter, history readable by new devices through a key archive; removal is an MLS remove and a revocation of that device's leaf, with no global rotation. |
| E8 | Several home spaces allowed (CRDT replicas are free to multiply); one is built. |
| E9 | Actors the user installs in the personal agent: later; sync and the inbox first. |
| E10 | Anonymous calls (sign-in, spends) go from the device to their target over Tor, never through the personal agent, which would link them. The personal agent holds only ciphertext and what its operators may see. |
| E11 | The edge scenarios that could bite later worked through before code (§8); the remaining design questions taken at their recommendations. |
| E12 | Keep MLS, built as one shared `vos-mls` layer: the personal space its first user, member messaging and virtual clients later; one stack, fewer pieces. |
| E13 | P2 (the shielded pool, the wallet, PG4) comes after the personal space and Tor, built on them; P1 first (P2's design: `open.md`). |
| E14 | A home-only space by default: a space the user holds no other membership in, hosting personal agents. A user may home in a space they belong to, the app stating that its operators can link the agent to them. |
| E15 | A yearly membership re-proof (`Auth("home")`, one prompt a year) keeps the agent; an expelled member's agent lapses into a grace period, its data recoverable by the kit. `Homes`' `renew`, the lease and the grace are built; the device's re-proof flow is not (`open.md`); a move makes no call to the old home, so the grace serves the kit's restore. |
| E16 | Recovery: the phrase or printed kit, and a FIDO2 security key as a kit (the `hmac-secret` path). An encrypted export file is later. |
| E17 | Tor-only is a rule for the personal agent: it refuses anything that did not come through the onion service. Bridges and pluggable transports: §6.5. |
| E18 | cipher-clerk v0.4 (the shielded redesign, R1–R11, `open.md`) comes with P2; P1 runs on v0.3.0 unchanged. |
| E19 | No bridges. Reversed for plain bridges by E22. |
| E20 | Virto runs a public home-only space, listed in the app as the default; others may run their own, and users may pick them. |
| E21 | The light node runs in its own `:vos` Android process behind Binder, for crash isolation and background sync without the UI process. |
| E22 | Tor is the light node's default transport for every space, with a per-space opt-out and a plain warning; anonymous (credentialed or proven) calls never leave the client over the clearnet in any space, enforced by the client and optionally by a space's ingress through the gateway's transport mark; a space may declare itself onion-only (the home is, E17); key-signed calls may use the clearnet where the space allows. Plain bridges; obfs4 and Snowflake later. |
| E23 | The gateway's onion serves only SSH; no raw node-API port, and no HTTP (owner, 2026-11-13: port 80 had no client, and an unused protocol on the anonymous side is surface with no user; it opens again when one exists). The light node speaks `vos-api` over SSH over the onion, whose relay set gains `Call` and `Credentialed`; the SSH handshake is paid once per kept-open connection. SSH over QUIC or a roaming transport later, when UDP over Tor exists. |
| E24 | The device set records each admin key's attestation (a TEE key behind a strong biometric) and the verified-boot state; the chrome shows an unattested key or an unverified boot, without changing the device's admin class. |
| E25 | The onion's flood measurement runs on a private Tor test network (chutney) in place of live Tor, a lighter run accepted (§6.6). |
| E26 | A scheduling decision (phone sessions), not recorded here. |
| E27 | A scheduling decision (reviews and acceptance runs), not recorded here. |
| E28 | A joining device's open claim at a home-only space is made by the background job after a random drawn delay from its add, never at the pairing, so the home's operators cannot link the new member to the agent by its time. Not built: no joiner makes an open claim, and only the claiming device is a member of the home (`open.md`). |
| E29 | A device's admin key is replaced (`admin(d, new key)`) on the kit's signature or another seasoned active device's; the new key's 72 h probation stands either way. |
| E30 | No C tor in the product, its tooling or its demo: the gateway hosts its onion with arti in process, the one path; the C tor sidecar, run once to measure it, is removed. A private test network's relays (chutney) may use C tor outside the tree. |
| E31 | The claim asks the home's terms (`opening`) and its agent (`pooled`) first, then shows the kit; the open claim's work and `claim_open` run while the user writes it down. A home that refuses after the kit was shown voids it, says so plainly, and shows new words (2026-11-20). |
| E32 | The kit entered on the restore screen is held in `:vos` for that screen's flows, wiped when the screen closes, when the app goes to the background, and ten minutes at most after its entry (2026-11-20). |
| E33 | "Paired", "Committed" and "Restored" are shown at the first complete follow (this device's confirm posted, the archive kept); the remaining follows run in the background, a failure among them a notice on the overview (2026-11-20). |
| E34 | Leave from the phone itself: the phone removes itself, the other devices commit (§3.5, rule 10) (2026-11-20). |
| E35 | Every reconnect s4 makes by itself keeps the grant of the session it replaces; the new facility session still starts knowing nothing; a session the user starts asks as before (2026-11-20). |
| E36 | One prompt per signature; "Commit now" from a matured removal's notice commits and revokes in one flow (2026-11-20). |
| E37 | A first sign-in waits for the device's leaf (the feed read now and every 5 s, up to a minute, no drawn delay); the timing link this leaves is stated in §6.2 (2026-11-20). |
| E38 | A debuggable build lets the personal-space screens be captured; a release build keeps them from capture (`FLAG_SECURE`) (2026-11-20). |
| E39 | Every device-set call names its place, the log's head its signer read; the agent and every device take it only if no admin call was logged between that place and the call (§3.5, "The place"), so a route cannot replay a vetoed removal (2026-11-20). |
| E40 | `claim` is the one way a personal agent is assigned and its policy set: no `assign`, no `configure` (§3.3) (2026-11-20). |
| E41 | A device is removed on the log it verifies, never on a refusal an agent answers (§3.6) (2026-11-20). |
| E42 | A refusal of a pairing slot's read does not end the joiner's pairing: it reads the slot again until its expiry (§3.8) (2026-11-20). |

**The flows left out** [the owner, 2026-11-17]: four flows that had no
caller in the product, or carried most of the device side's complexity,
are not built (each in `open.md`):
- **Moving home carries nothing** (§3.9): the mover leaves its personal
  space with no call to the old home (its store made anew), claims at the
  new home as a first claim does, and the other devices leave and pair
  again. Valid only while the personal space holds the credential book and
  the device book alone, which every device writes again from what it
  holds; a local actor holding what no device writes again needs the carry
  back first.
- **A restore is at its own home** (§3.5): restoring elsewhere is
  restoring there, then moving. **Scope checkpoints** are not built
  (§3.6): a paired or restored device reads each scope from its start,
  and a home's operators can serve it a shortened scope without an alarm
  at that moment (§8, C4).
- **A regroup keeps its regrouper alone** (§3.5): every other device is
  removed and pairs again.
- **The joiners' open claim (E28) and the yearly re-proof flow** (§3.3,
  §3.8): only the claiming device joins the home; `Homes`' `renew`,
  `Personal`'s lease and its grace are built. Every agent lapses 13 months
  after its claim unless both are built or the home sets a longer lease.

### 1.2 Goals

1. **A light node, not a proving library.** `vos-light` is a light node
   of VOS: the PVM runtime running local actors, a local store, the
   device prover, a node-API client, merkle-crdt sync and MLS
   (`vos-mls`). It runs on the phone, inside s4's Android client.
2. **The user's private space across devices.** Local actors hold the
   user's private data (notes, credentials, contacts, the wallet later);
   the user's devices keep them in agreement with merkle-crdt, through a
   personal agent that holds only ciphertext (§3).
3. **One proving path.** Every statement a device proves is an
   `#[attestable(device)]` kernel written in Rust and proved by the general
   zkVM under the device profile. No hand-written circuit outside the
   recursion (§4.1).
4. **Payments as the showcase.** A short, readable pair of actors on
   cipher-clerk, whose spend is one Rust function proved on the phone
   (§5). P1, pseudonymous, is built; P2, private, is designed in
   `open.md` (E13).
5. **Fewer pieces.** One light node crate (`vos-light`) and one proving
   path. arti's and mls-rs's dependency trees, `vos-mls`, two system
   actors (`Homes`, `Personal`) and the CRDT fields come with it; the
   claim is about what VOS maintains as proving and transport code, not a
   smaller dependency graph.
6. **Network privacy.** Clients reach a space's gateway as a Tor onion
   service by default, and anonymous calls only so, so no node or gateway
   learns a member's network address [E22].
7. **The rule stays:** `vos` and the node know no JAM and no Kreivo
   [decided, `core-model.md` §13]; the same holds for Tor and for MLS:
   the node stores and orders opaque bytes for them (§3, §6, §7).

## 2. The light node

### 2.1 What it embeds, and what it does not

| part | what | from |
|---|---|---|
| **PVM runtime** | the interpreter, its machine pool and inner machines; no JIT (the recompiler is x86-64 Linux only, `pvm/runtime/src/lib.rs`) | `vos-pvm` [built] |
| **the agent program** | the default agent, `vos-agent`: local actors are installed into it as into a node's agent; its merge entry runs `#[msg(merge)]` handlers writing merge fields, and its queries read them filtered (`core-model.md` §9.4) | `agent/default` [built, extended] |
| **merge and query dispatch** | local actors are Merge-only (`#[msg(merge)]` handlers and `&self` queries; `core-model.md` §9.2: a merge handler runs on "any replica or device, no log"), so the light node runs the agent program's merge and query entries over its store, one fjall batch per operation; no refine, no accumulate, no work results, sessions or sweeps; no Raft, no leader, no peers | the executor's host-call layer, reused from `vos-node` without its pipeline (§7.1) |
| **release artifacts** | the transpiled programs of the local actors and the stock kernels' device programs, computed at release and embedded with their ELF bytes; the phone runs no transpiler and no reference run (§4.4) | the release build [built] |
| **local store** | fjall, as the node's, with small caches (8–16 MiB block cache [est]) | `vos-node`'s `store` [built] |
| **device prover** | the device profile (format 47, the per-program CPU and the word ledger, §4.4), masked, `Threads::Auto` | `vos-pvm-proof` and `vos-pvm-device`'s masked device segment, its recursion prover featured out (§7.1) |
| **node-API client** | the multiplexed `vos-api` client over SSH's `vos-api` subsystem, over an arti onion stream (§6) [E23] | `vos-api` [built] |
| **sync** | merkle-crdt DAGs of the local actors' Merge fields, one a local instance, its `Store` over fjall, sealed before they leave the device (§3.6) | `support/merkle-crdt` [built: incremental apply, author chains, `FjallStore`, batched fetching], `vos-light`'s `sync` and `personal` [built: nodes recorded and applied through the merge entry, sealed at push and read by the cursor over `Personal`, §3.6] |
| **MLS** | the user's device group, through `vos-mls` over mls-rs, on the host side, native, never in a guest | `vos-mls` [built]; the storage providers and copy-and-swap adapted from the `messaging` branch (§3.4) |
| **secrets** | per device, as today: the member secret from the keystore's HMAC; the admin key in the hardware keystore; the sync key and MLS state wrapped after first unlock; a security-key kit through the `hmac-secret` path (§3.5) | `vos-light`'s `secret` [built, extended] |
| **Tor** | arti's client, one `TorClient` per process | arti (§6) |

**What the core is, as built** [built, `node/light`, `node/exec`]:
- **The entries:** a call is a merge handler's operation, the agent
  program's merge entry (`Work::Merge`): refine runs the `#[msg(merge)]`
  handler as the operation's author, at the device's time and seed, and
  returns its one step as a work result, whose rows (its merge fields'
  entries) the light node writes itself, so no accumulate runs in the
  PVM. Only a merge handler runs there, and it writes its merge fields
  alone and reads no row (it runs on a new instance's state); anything
  else fails with nothing written
  (`core-model.md` §9.4). An install is a batch of one install through
  refine, applied with the code a node's accumulate runs
  (`vos_wire::apply`).
- **Sync** [built, `vos-light`'s `sync`]: each local instance is one
  scope, a merkle-crdt DAG whose nodes the store's author key signs (drawn
  when the store is made, so an install or a restore is a new author). A
  call is recorded as a node, its rows and the node in one synced batch
  with the light node's own row of the call's time and seed
  (`FjallStore::commit_with`); a peer's nodes are ingested in one batch,
  each operation run through the same merge entry, and each node's
  Lamport clock and its author's cutoff where it equivocates written with
  them. Reads filter the equivocating authors and those the device set
  removed (`Light::cut_off`, one past a removed device's node at its
  frontier, which the sealed read sets, §3.5). Sealing and the cursor over
  `Personal` are §3.6's (`vos_light::personal`).
- **Held and quarantined operations** [built, `vos-light`'s `sync`]: a
  peer's operation the device cannot run yet is held in its scope's rows,
  `Hold::Kind` (a kind the build does not know), `Hold::Release` (a later
  release of its actor than the one installed, §3.2) or `Hold::Fault` (a
  run that faulted here); an install replays its instance's
  (`Light::replay`). One that is invalid is quarantined, never applied:
  `Quarantine::Invalid` (a frame no device records),
  `Quarantine::Failed` (a run that fails where the issuing device records
  an operation only when its run is done, so the author wrote garbage) and
  `Quarantine::CutOff` (an author the device set removed, already cut off
  at its number; an equivocation's forks still apply, filtered at read,
  so devices meeting them in either order agree). An operation of a
  method its release lacks is `Quarantine::Failed(Unknown)`: a later
  release keeps every earlier one's handlers (`core-model.md` §9.4). Each is
  reported by the ingest that met it and listed with its author
  (`Light::held`, `Light::quarantined`), and the sealed read gathers them
  (`Caught::held`, `Caught::quarantined`).
- **Disk room** [built]: before an install, a call, an ingest or a
  replay, the light node asks the store's filesystem for its free room
  (`statvfs`) and refuses below a reserve, 64 MiB by default
  (`RESERVE_BYTES`) [est], with `Error::Full` and nothing written;
  sync pauses, as the sealed read checks first and writes nothing, and
  both resume once room is freed. Cutoffs, the push queue and the device group's writes
  are exempt, being small and what removes a device or gets data off the
  phone. A disk that fills anyway (another app's writes) fails fjall's
  write, which then refuses every write until the store is opened again.
- **The first local actors** [built]: the credential book and the device
  book (§3.1), stock programs (`agent/credential-book`,
  `agent/device-book`) whose types are `vos_wire::books`'.
- **The host-call layer** is `vos-exec`, which `vos-node` and `vos-light`
  link; ingress's device programs (`credentialed.rs`'s use of
  `vos_pvm_device`) stay in the node, as the light node never
  computes one from a kernel once they are release artifacts.
- **Release artifacts** (`vos_light::release`, built behind its `release`
  feature on the host that builds the app): the local actors' packages,
  the agent program, and the device kernels' programs
  (`release::Release`, `vos_pvm_device::Release`: the kernel, its chips, its log sizes, its id, and
  the hash of the ELF it came from, as an install record names it, its
  temporary symbols' names left out). The device library commits a
  program's preprocessed tree from its artifact
  (`DeviceProgram::from_release`), checking the id; it never runs a reference
  or the transpiler, and installs no package another transpiler derived
  (`release::TRANSPILER`).

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
- The light node is one Rust crate, `vos-light` (§7.1), linked by the
  facility's cdylib, `vos-facility` (`node/light/android`, outside the
  workspace, linking `vos-light`, `vos-api` and `vos-wire` by path). The
  facility keeps its name, `vos.credential`, grows the operations of §7.3,
  and runs in a separate process of s4's app (`android:process=":vos"`),
  which serves two Binder interfaces: s4's `IVosNode`, which s4's client
  calls, and the facility's own `IVosPersonal`, which its screens call.
  VOS depends on s4 one way (the facility on `s4-protocol` and
  `s4-credential-contract`, its tests and the gateway on `s4-server`, each
  at one git revision, `just pin-s4`); s4 depends on nothing of VOS.
- **What s4 knows of VOS** is its credential contract alone: `IVosNode`
  (a server's session's `enroll`, `sign_in`, `pay` and `refresh`, the
  carriage of s4's screens and `clearnet`, `foreground`, and the
  enrollments and background runs its own chrome reads), `IVosPrompts`
  (the forms, and the secret sources' and an admin key's prompts: its
  `KeyKind` names an admin key and a kit's security key beside the
  device's sources, for the personal space's prompts), the parcelables of
  both, the service's class name, the host bridges that answer the prompts
  (`KeySources`, `AdminKeyBridge`), a generic hook its debug probe hands
  unknown ops to (`FacilityProbe`, the library's `Probe`) and `parcel!`, the declaration both
  repositories write their parcelables with. The personal space's
  interface (`IVosPersonal`: the jobs' passes, Tor's bridges and opt-outs,
  the claim, pairing, the device set, restore, move) and its types
  (`vos_facility::personal::contract`, package `team.virto.vos.personal`)
  are VOS's own, built into VOS's Android library (`just
  android-facility`: the `:vos` service, the personal space's screens and
  `libvos_facility.so`), which s4's `-Ps4Vos` build links.
- **Why its own process:** the prover's 1 GiB peak, the unwrapped sync key
  and archive, and arti's circuits stay out of the UI process; the OS can
  kill one without the other, so a proof or a sync is never lost to the UI
  being swiped away, and a crash in either leaves the other running; the
  background job runs in `:vos` with no UI process at all.
- **The Binder interfaces** carry the facility's named operations and
  nothing generic (§3.3); their results and errors are typed. The trusted
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
  `libvos_facility.so`, built on VOS's pinned nightly because s4's client
  cannot build on it. s4's client asks each facility it hosts whether it
  carries a host's connection and pins its host key (`Carrier::carry`),
  and refuses on its own connection a key a facility keeps to the ones it
  carries (`Carrier::admit`); a `.onion` host typed in the client can be
  dialed through the same hook. `:vos` opens the onion stream and hands
  the UI one end of a Unix socketpair as a `ParcelFileDescriptor` over
  Binder, pumping bytes between it and the
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
| the facility's `.so` | growth from arti ≤ 10 MB [provisional]; from `vos-mls` and mls-rs ≤ 2 MB | arti: +13.85 MB stripped on arm64, missing the limit by 39% (within twice it); +8.84 MB under fat LTO [measured, §6.4, 2026-11-02]; mls-rs +0.86 MB stripped [measured, arm64-v8a, 2026-11-02, §3.4] |
| local actor call | ≤ 1 ms on the interpreter | 85 µs an invocation on the node's interpreter [measured, `core-model.md` §14], with the fsync of a local commit dominating |
| proving a sign-in | ≤ 1 GiB peak (target 768 MiB) | 513 MiB [measured, `proving.md` §8] |
| background sync job | ≤ 30 s wall, ≤ 1 MB down a run with nothing new | [est]: arti from a warm directory, one onion connection, one cursor query a scope and one for the device-set log |
| battery | no work while backgrounded beyond the periodic job; no persistent circuit | the design's rule, PG5's to measure (§2.4) |

**The light node's local calls, first numbers** [measured, x86-64 dev
host shared with other builds (load 20–55), 2026-11-02, `vos-phone light`,
release, two runs]: the light node opens in 0.2–1.1 s, installs the counter in
43–123 ms, and a call through the merge entry, its synced batch included,
takes 2.0–6.2 ms at p50 and 3.3–19.6 ms at p95; a query 1.1–1.9 ms. The
host's load moves them threefold; the phone's numbers are the gate's run
(`tools/phone/scripts/light.sh`). The host's calls miss the 1 ms budget
above: each is a synced commit, and how much of a call its fsync takes is not
yet split out. If the phone misses it too, a call's durability (synced, or buffered
and synced in a group) is the lever, against §2.2's rule that every write
is crash-safe.

**On the phones** [measured, 2026-11-06, `light.sh`, the notes
actor, a release build]: the Fairphone 6 opens a new store in 263 ms and
reopens it in 125 ms; a call through the merge entry, synced, takes
0.46–0.53 ms p50 and 0.52–1.07 ms p95; a query 22–33 ms. Within the 1 ms
budget. The Pixel 1 opens in 552 and 262 ms; a call takes 7.7–8.1 ms p50
and 12.5–13.2 ms p95, a query 82–116 ms: its storage's fsync, fifteen
times the Fairphone's, misses the budget on an ungated phone. On both,
ten processes killed with SIGKILL 50–800 ms into a run of calls left the
store one prefix of whole operations. Android's standard library has no
file locks, so fjall takes its directory's lock with `flock` there
(the workspace's fjall patch).

Proving is the only heavy phase: about 0.65 s of wall time on the four
big cores at full load a sign-in [measured, `proving.md` §8: 645 ms]. A
phone that signs in twenty times a day spends about 13 s of wall time on
them [est], far below a screen-on minute.

### 2.4 The phone gates

Every gate is on the Fairphone 6 [decided, `proving.md` §8], automatic
threads, three rounds of five, the gate the median of the rounds' medians,
the 95th percentile beside it, each proof verified on the phone and
accepted at a space's ingress. Every gate has a limit it can miss. PG1,
the credential AIR's 250 ms, retired with format 44; PG4, the spend, is
P2's (`open.md`).

| gate | what | limit |
|---|---|---|
| **PG1′ owner** | the stock `owner` kernel | ≤ 0.5 s, ≤ 512 MiB |
| **PG2′ sign-in** | the stock `auth` kernel | at format 47 **the gate 0.65 s, the target 0.55 s** (a miss makes the 4-way CPU split, `open.md`, the next lever); ≤ 1 GiB; the proof ≤ 1.5 MiB |
| **PG3′ flows** | enroll, sign-in and pay (P1); claim at a home-only test space with a phrase kit and with a security-key kit; pair a second device (enrolled in every other space at once); sync both ways; retire a phone; a removal let through, one contested and resolved by the kit, and the kit alone removing a phone that holds only a sync key; a restore cancelled by liveness, then one completed on a fresh install; a regroup keeping its regrouper alone, another device pairing again; move home (two homes: leave, claim, pair again); every secret behind its prompt; on test homes with delays in minutes, a lease that outlasts the session and a low claim difficulty; recorded, as onion runs (the client refuses the clearnet for these by construction; the host suites cover the clearnet paths) | each completes; over Tor at the median: a sign-in ≤ 4 s, a P1 payment ≤ 5 s, pairing ≤ 60 s from the scan to the second device's first read, arti and its SSH connections warm |
| **PG5 footprint** | the light node with arti, `vos-mls` and mls-rs | `.so` growth from `vos-mls` and mls-rs ≤ 2 MB; from arti ≤ 10 MB, provisional; idle ≤ 96 MiB; warm bootstrap ≤ 3 s p50; a day of background jobs ≤ 2% of the battery; ≤ 30 rendezvous an hour in the foreground |
| **PG6 sync** | the background job; a 1 MiB catch-up; a commit | on a locked phone after first unlock: the job ≤ 30 s and ≤ 1 MB down with nothing new, p50; the 1 MiB catch-up over Tor ≤ 20 s p50; a candidate processed on its copy ≤ 200 ms. **Recorded, as inputs to the device-change windows:** the job in the "rare" bucket, after 3 days offline, after a force-stop, and the latency from a pending operation to its local notification |

PG1′ and PG2′ passed at format 46 (against 46's sign-in limit of ≤ 1.0 s)
[measured, Fairphone 6, 2026-11-08]:
`owner` 351.8 ms and ≤ 337 MiB, `auth` 615.6 ms, ≤ 505 MiB and
≤ 0.88 MB, each phone-made sign-in run at the node's ingress
(`proving.md` §8). PG5's arti and `vos-mls` figures and PG6's candidate
are §3.4's and §6.4's. The rest are `open.md`'s.

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

Devices sync with the personal agent, never with each other directly;
the agent is where two devices that are never online together
meet. Every gateway of the home lists every node of it as an upstream, so
any gateway reaches the agent (§3.3).

**Local first, backup nudged:** a new user's personal space starts on one
device with no personal agent. The app offers backup (the claim, which is
also where the recovery kit is made, §3.5) at first launch and again
until the user accepts or declines for good, since a single device with
no kit loses everything with the phone (§8, D2).

**The first local actors** [built: `vos-credential-book`,
`vos-device-book`, their types `vos_wire::books`]:
- the credential book: the spaces the user is a member of, each device's
  handles there, the pinned agents and methods the facility pins today.
  The member trees a device keeps for its proofs (§6.7) stay on the
  device, outside any synced scope;
- the device book: labels and settings of the user's devices (the device
  set's authority is the personal agent's log, §3.5; this is its
  user-facing mirror).

**Before a third local actor is added** [the owner, 2026-11-17]: a move
home carries nothing (§3.9), which is valid only while the personal space
holds just these two books, whose rows every device writes again at the
new home from what it holds. An actor whose rows no device writes again
(a wallet's) needs the move's carry back first (`open.md`).

Each actor instance is one sync scope: one merkle-crdt DAG
(`core-model.md` §9.4's "one DAG per sync scope"). A merge handler's
effects depend only on its operation, so every device that applies a DAG
converges; randomness and time come from the device that issues an
operation and travel inside it.

### 3.2 What syncs, and the conflict model

- **What syncs:** each scope's DAG nodes, each a batch of CRDT operations
  with stable ids, its parents and its author. Never the store's rows,
  never proofs, never a secret.
- **The CRDT types, first** [built, `core-model.md` §9.4]:
  `crdt::Set<T>` (an add/remove set, the latest admitted add or remove by
  Lamport clock then author deciding: a causally later operation always
  wins, concurrent ones resolve alike on every device; add-wins, which
  needs each operation's causal context, is later work), `crdt::Map<K, V>`
  (last-writer-wins a key by a Lamport clock and the author's id) and
  `crdt::GSet<T>`. Storage-backed and **stored per author:** a field keeps
  one entry per (element or key, author) and a read takes the latest among
  authors not filtered out (`core-model.md` §9.4, rule 6), so a removed
  device's writes applied before the removal was known are filtered at
  read, never unapplied (§3.5's frontier), and those that arrive once it
  is known are quarantined, never applied [built]. *Known limit:* a
  removed device's write past its frontier that reaches a device before
  the removal does replaces, and hides, its own earlier write to that
  element; agent-mediated sync refuses its envelopes past its frontier, so
  only a delivery concurrent with the removal reaches it. Keeping each
  author's history of an element exactly is later work.
- **The conflict model** is the types' own; no operation needs another
  device's agreement. Where conflicts are real, a log decides: the device
  set and the device group by the personal agent's log, a payment by the
  space that holds the ledger.
- **Authorship:** each device signs the DAG nodes it authors with its
  sync key (§3.5); merkle-crdt's `DagNode` has no author field, so the
  author's key, sequence number and signature travel inside the payload,
  which is sealed (§3.6).
- **Operations are versioned** [built]: each operation carries the
  release of its actor the issuing device ran (`release::Package`'s
  `release`, numbered from 1), and an operation of a later release, or of
  a kind the build does not know, is held and applied once the device
  updates, never quarantined, so devices on different app versions do not
  diverge. A device holds every operation of a later release, not only
  those of handlers its release lacks, as a later release may change what
  a handler writes; a later release runs every earlier one's operations
  as they ran, and one that cannot starts a new scope (§8, D7). An install
  of an earlier release than the one installed, or of another program
  under the same release, is refused.
- **Incremental apply** [decided, `core-model.md` §9.4; built in
  `support/merkle-crdt`]: only newly fetched nodes are applied, in causal
  order, one fjall batch an ingest; on fjall a node of a batch costs
  63–68 µs at 1M operations, most of it the ed25519 check, and a node
  alone 0.5–0.8 ms, its synced commit [measured, Intel Core Ultra 7 155H, 2026-11-03, `core-model.md`
  §9.4]. Nodes arriving before their parents, as a cursor serves them,
  are held until the parents arrive. Equivocations are found at apply,
  listed, and filtered at read by the types, from the equivocation's
  number on.
- **What the types cost on the light node** [measured, Intel Core Ultra
  7 155H under load, 2026-11-03, `core-model.md` §9.4]: a local operation
  1.6 ms at p50 for each type, its synced commit included; a peer's node
  0.5–1.2 ms in an ingest of 100; a point read 0.6–0.7 ms at 1k and 100k
  keys alike, a scan 100–127 µs a key, three authors' entries a key, one
  cut off.

### 3.3 The home and the personal agent

**Membership in a home-only space** [decided, E14]: a home-only space
admits anyone, priced by work, so that joining it says nothing about the
user's other spaces.
- Its registrar's invitations (`identity-and-authority.md` §6: `invite`
  names a member digest, `claim` enrolls it) gain an **open claim**:
  `claim_open(member, work)`, any caller, admitted when `work` is a proof
  of work over `(space, member, the registrar's current salt)` at the
  difficulty the space sets (about a minute of a phone's cores), within a
  daily cap of open enrollments. Over the onion, the registrar learns
  only that someone joined. Only the claiming device makes one: a device
  paired later holds no leaf at a home-only home (E28, `open.md`). The
  device set in `Personal` ties the user's devices together, and holds no
  member digests.
- **What bounds abuse is the cap, not the work:** a minute of a phone's
  cores is seconds on a desktop, so the work only stops a trivial loop.
  The daily cap is sized to the home's disk (each claim can grow to 192
  MiB on three replicas) and kept below the keeper's refill rate, so a
  drained pool shows as `PoolEmpty` (§8, B11) rather than a full disk;
  and the **quota ramps:** a new agent holds 8 MiB, rising to 64 MiB after
  its first yearly re-proof, so a Sybil's first year costs the home an
  eighth as much. A re-proof lifts it only once five sixths of a lease
  have passed since the claim, where the device's yearly prompt first
  falls (the lease's last sixth): an earlier one renews the lease and lifts
  nothing, so a Sybil cannot re-prove at once for the larger quota
  [built, `Personal::renew`; no device calls it yet, `open.md`]. Nothing an open member does reaches another user's
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
  the role under which `Personal` takes `claim` (`Grant`; `Install`
  carries no configuration, `agent/wire/src/ingress.rs`). Creating an agent
  costs about 2 s, 0.15–0.17 s each sixteen at a time [measured,
  `core-model.md` §14.1], so a pool of a few hundred hides creation from
  users. It also runs `Personal`'s upgrades (below).
- **The claim:** `homes.claim(device, kit, agent)` under
  `#[msg(credential = Auth("home"))]`. The pseudonym is the claiming
  device's nullifier in scope "home" [decided, E5]. `Homes` refuses a
  nullifier already holding an agent, takes the pooled agent the device
  named (`Taken` when another claim took it), indexes it under the
  nullifier and under `H(each recovery public key)` (§3.5), and sends it
  `claim(device, kit, policy, homes)`; `Command::send` is one-way
  (`agent/sdk/src/context.rs`), so `Personal` answers `assigned` or
  `refused`, and `Homes` releases a refused one. The chrome refuses a
  claim on a device that already holds a personal space's archive, so a
  user's second device never claims a second agent by mistake. Its times
  [World]: §6.3.
- **"home" is reserved:** the light node proves in that scope only for
  its own claim, and the facility refuses
  any request naming `Homes`' agent and instance.

**The lease: one re-proof a year** [decided, E15; `Homes`' `renew`, the
lease and the grace built; the device's flow, the yearly prompt and a
joiner's own leaf at the home it needs not built, `open.md`]:
- Every device's own "home" nullifier is recorded at its add (the device
  computes it without a proof; `Personal` passes it to `Homes`, which
  refuses one already mapped to another agent). The person records (§3.8)
  give it no proof: they hold `member` and `owner` digests, from which no
  nullifier follows (it is unlinkable to both by design), and the
  enrollment is the adding device's proof, not the added one's. A
  re-proof is the device's own `Auth("home")`, so it needs a leaf in the
  home (its open claim at a home-only space, its enrollment at a home that
  is the user's own space).
- Once a year, any device proves `Auth("home")` to `homes.renew(agent)`
  under a recorded nullifier: one prompt a year, at an ordinary sign-in
  when the home is the user's own space, or at a yearly "keep my backup"
  prompt in a home-only one. The lease runs 13 months from the last
  re-proof.
- **A lapsed lease** (the member left, was removed, or never re-proved)
  puts the agent in a **grace period** of 180 days: it refuses pushes (but
  the recovery scope's, which the confirmed epoch of a removal's commit
  needs [built]), the inbox, pairing slots, and any commit but one
  carrying a removal and no add, and still takes device-set
  operations, `alive` and confirmations, serves the devices' and the
  kit's reads and a restore (§3.5; a move to another home, §3.9, makes no
  call to the old home), so
  the data stays recoverable and a stolen phone can still be removed. A
  re-proof ends the grace.
- **On a test home** the delays of §3.5 and the lease are set per space
  (minutes, not days), so the phone gates can run every flow (§2.4).
- **Reaping** an agent after its grace, wiping it and returning it to the
  pool, is later work (`open.md`).

**`Homes` as built** [built, `agent/homes`, its wire types
`vos_wire::homes`; tested in the testkit's agent suite,
`agent/testkit/tests/agent/homes.rs`, and on three nodes,
`node/host/tests/served/homes.rs`; where the text above leaves a choice,
this is the one taken]:
- **Its tables,** its struct holding tables alone (the layout
  append-only, as `Personal`'s): every agent stocked with its standing
  (`Pooled`, `Claimed`, `Assigned`, `Retired`, with no times, which would
  link an agent to the ring's enrollments), the claim's nullifier and its
  kit's indexes; the pool, lowest id first; the nullifier and kit-key
  indexes; the terms; the counts.
- **The operator's** (role `operator`): `configure(Terms)`, `Personal`'s
  instance in the pool's agents and the policy each is configured with
  before its claim (the home's delays, lease and quotas, minutes on a test
  home); `stock(agents)`, at most 256 a call, an agent stocked already left
  as it is, so a keeper that lost the answer stocks the page again (34.1M
  gas for 200 [measured, the testkit's agent suite, Core Ultra 7 155H,
  2026-11-07; gas is deterministic], 50M declared); `release(agent)`, a
  claim its agent never answered (its role not granted, a wrong instance)
  dropped and the agent retired.
- **The claim** (`claim(device, kit, agent)` under `Auth("home")`, 0.69M
  gas): the device's `nullifier` must be the proof's (`Nullifier`); a
  nullifier holding an agent is `Claimed`, a kit entry's index holding one
  `KitTaken`, more than four entries or one key twice among the device's
  and the kit's `Malformed` (what `Personal` would refuse, so a refusal
  cannot be repeated against a pooled agent), an empty pool `PoolEmpty`,
  an `agent` not pooled `Taken`, each writing nothing. A kit may be empty
  (no recovery). **The device names the agent** [built]: a kit's
  `R1` is sealed with the agent's identity bound (§3.5), which the device
  must know before its claim, so it reads `pooled` (the lowest pooled
  agent), learns that agent's identity from its record (`AgentInfo`),
  seals to it and claims it; a claim that loses the race is `Taken`, and
  the device seals to the next. The named agent is taken and indexed,
  and sent `claim(device, kit, policy,
  homes)`, `Personal`'s entry for its home: the policy and the claim
  checked whole, answered by message, `assigned`, or `refused` with the
  error and nothing written: the one way an agent is assigned and its
  policy set [E40, built: no `assign` or `configure`]. The
  reply is the agent's id.
  The same claim again (its nullifier and kit) while its answer is awaited
  is sent again, and `Personal` answers `assigned` again to a claim it
  took from the same home, so an answer lost is recovered by the device's
  retry. A refused claim's indexes are dropped and its agent pooled again,
  unless `Personal` says it was assigned already (`Retired`, never pooled
  again).
- **Personal tells its home** (the agent and instance its `claim` named)
  each device's nullifier as its add is confirmed, and the restore's
  device's at its maturity (`record`, refused for a nullifier another agent
  holds), each removed device's as its removal matures (`forget`, so a
  stolen phone renews nothing and the index stays at the device set's
  size), and the kit's signing keys whenever a rotation or a restore
  replaces it (`rekey`, the agent re-indexed under the new keys alone, a
  key indexing another agent left out, and that kit then finding no agent:
  a squatted kit key is the next rotation's to replace). A device's
  nullifier is its own word, as its keys are: the agent's devices could
  record a nullifier not theirs, holding a member who has not claimed out
  of the home, which a nullifier's 32 bytes keep from anyone who never
  saw it. These messages name `Homes`'
  handlers by their ids (`vos_sdk::method_id!`), since `Homes` depends on
  `Personal`'s crate for its own messages; the relayed suites prove the
  ids by the answers taken.
- **The re-proof** (`renew(agent)` under `Auth("home")`): a nullifier
  recorded for that agent, assigned (`NotRecorded`, `Unknown`); it sends
  the agent `renew`, which runs the lease on and lifts the quota to its
  larger size. **Not built:** B20's re-recording after a re-founding, when
  every nullifier changes: a re-proof needs a nullifier recorded, and
  `Personal` records one only at a device's add, so a re-founded home's
  agents lapse into their grace unless a device re-records; the path (a
  device's new nullifier vouched for by its admin key and relayed by
  `Personal`) waits for the re-founding runbook.
- **Reads:** the agent of a nullifier (`agent`), of a kit entry's index
  (`find`, a restore's lookup), an agent's standing (`standing_of`), the
  counts (`tally`), and the stocked agents a page at a time (`agents`,
  which the keeper's upgrade walks).
- **The scope reserved** [built, `vos_light::home`]: `Prover::prove_auth`
  refuses the guard name "home" (`DeviceError::Reserved`), and
  `Prover::prove_home` proves in it only a call of `claim`; a
  device computes its own nullifier there with no proof
  (`home::nullifier`). The facility links the library, so it refuses
  the same; its own operations are unchanged.
- **The open claim's work** (`home::work`): a nonce found on the device's
  threads for the registrar's terms (`identity-and-authority.md` §6),
  which publish the cap. A query reads at the last batch's time, so on a
  home no batch reached for a period the salt served is the one before;
  past two periods its work is refused `Work` and the device asks again.
- **The cap and `PoolEmpty`:** the cap is the registrar's, refusing an
  open claim past it (`Cap`); `PoolEmpty` is `Homes'`, when the pool is
  empty. With the cap below the keeper's refill, members joining at the
  cap every period never drain the pool, and a keeper that stops shows as
  `PoolEmpty` once the pool runs dry
  (`the_cap_keeps_the_pool_and_an_empty_pool_is_pool_empty`).
- **The keeper** [built, `tools/keeper`, `vos-keeper`]: under an operator
  key every node lists, whose client key holds `operator` at the home's
  agent; `top-up --to N` makes agents (created on the home's replicas,
  `Personal` installed with its role `homes`, that role granted to the
  home's agent, sixteen at once by default) and stocks them a page at a
  time, a failure stopping it once the agents made before it are stocked;
  `stock`; `upgrade --elf`, `Personal` installed over every agent `Homes`
  lists when it starts, a batch at a time, stopping after the batch holding
  a refusal; `tally`. It reads the install's answer back, not the agent's
  `version`, which only the onion reaches. On three nodes in one process it
  made and stocked 200 agents in 23.2–26.9 s, sixteen at once; 200 members'
  claims, each proved by the device library (four provers of three threads
  each), were taken in 78.5–84.2 s, about 1.6–1.7 s a proof on one prover,
  and every claim was assigned [measured, the served suite on a debug build
  with the prover's crates optimized, Core Ultra 7 155H, 2026-11-07, two
  runs].
- **The `home` test actor stays, for the node's suites and the scale
  harness alone** (`agent/test-actors/home`): it sends a client's `claim`
  and `renew` on to a personal agent as `Homes` does, without the member's
  proof `Homes` asks first (a proof a claim, about 1.6 s each on a debug
  build, above, for each of the scale harness's thousands of agents), and
  takes `Personal`'s answers. `Personal`'s own suite and the light node's
  claim as the home's agent in process (`vos_testkit::personal::Agent::
  claim`); a home runs `Homes`.

**Replicas:** three by default, the space's policy, fixed when the keeper
makes the agent. One replica is allowed for small spaces and shown in the
chrome (§8, B10). **Cost:** about 46 KiB and 1.6 µs/s a replica when idle
[measured, `core-model.md` §14]; with a 64 MiB quota (§3.6), 10^4 full
agents on three replicas is about 1.9 TB a space.

**The scale gate** (`tools/scale`, `--personal`): 10^4 personal agents on a
three-node space, each pushing and fetching every 15 minutes for an hour,
sessions opening and sweeping, pushes of full steps among them; one agent
filled to 64 MiB, its snapshot installed, and one `replace`. Its limits:
the other agents' commit p99 within 20% of the same run without personal
agents; ≤ 64 KiB resident a personal-agent replica above idle; a full
agent's snapshot installed ≤ 30 s. **The early run** [measured, compumax
nodes c1–c3 and spare c4, sigma the driver, 2026-11-06; the scale test's
load of 64 shards at 5,000 calls a second beside 10,000 personal agents
waking every 15 minutes; the largest push 60 KiB, `Personal`'s envelope
cap; the fill a run of its own]: every call of the three runs succeeded.
The snapshot's limit is met: a 64 MiB agent's replacement installed its
snapshot in 1.04 s. The other two missed as measured:
- **Commit p99:** the transfers' p99 rose from 1.84 s to 2.62 s (+43%),
  one bucket of the harness's histogram, with the nodes' CPU unchanged at
  about 70%. The fill's run, with the same 10,000 agents, was back at
  1.84 s.
- **Memory:** +50–54 KiB a replica right after creation, but +106–111 KiB
  a replica at the load's end, which counts the 255 MiB the agents pushed
  and the store's caches.

**The rerun** [measured, compumax (capped) + sigma, 2026-11-20; the same
layout, each node pinned to four of compumax's 64 threads (16 in all, one
thread of a core each); the transfers' latencies read by the driver at
buckets at most 1% wide; four runs of an hour alternating at 5,000 calls a
second, then a pair at 3,000, added once the 5,000 baseline proved
unsteady; every run with the same build, seed and cap]: the rise is real.
At 5,000 calls a second the load sits at a knee in front of the nodes, as
the early run's did (more than 1,024 requests in flight on a node's
connection in 302 of its 369 intervals), which amplifies it.
- **At 5,000 calls a second:** without personal agents, p50 0.36 s and
  0.31 s, p99 2.88 s and 2.83 s (1.7% apart over the hour, up to 44% in a
  ten-minute block), no errors. Neither held steady: the ten-minute p99
  climbed from 1.2–1.3 s to 3.3–3.8 s with up to 7,200 requests in flight
  on one node's connection against the node's 1,024 streams, while the
  nodes' own queue and batch p99 stayed at 0.52 s in every window: the
  growth is in front of the nodes, in the stream bound and in a user's
  calls going one at a time (a hot user whose rate times latency passes 1
  queues without bound). With the agents, one run tipped over 35 minutes
  in: 485,760 transfers (3.4%) timed out, 58,668 in flight, the answered
  rate from about 5,000 to about 4,300 a second (10 s intervals down to
  2,500). The other held, with no errors, at p50 0.41 s (+33%) and p99
  5.31 s (+87%), above its baseline in every ten-minute block (+34% to
  +167%; the first blocks 1.95 s and 2.59 s against 1.23 s and 1.29 s).
  The nodes' CPU was 63–69% in all four.
- **Where it comes from:** at the nodes' buckets, the commit, the fsync
  and the apply did not move; the batch's p99 rose from 0.52 to 0.79 s;
  the waits for an executor doubled at p99 on two of the three nodes (the
  dry run's 66 to 131 ms, the refine's 57 to 115 ms; the third moved a
  bucket). A few long items appeared on the executors, which were 50–55%
  busy in both runs: the batches' step-gas p99 from about 0.1 to 2.1
  million, the root build's p99.9 from 8 to 41 ms. That is consistent
  with a personal agent's call holding an executor a shard's batch waits
  for, not shown to be it. A few hundred milliseconds more at the node
  became seconds at the driver, through the queue in front of it (the
  calls waiting behind their user's last rose from 567,000 to 919,000).
  Compaction did not differ (the store's workers 32–34% of a core, the
  disk 49–55% busy, its time an I/O no higher with the agents); each node
  led about 3,300–3,500 groups with them against about 20 without; the
  onion mark was not looked at apart.
- **At 3,000 calls a second** (in flight above 1,024 in 26 and 47 of about
  365 intervals, at most about 2,000; CPU 53–60%; no errors): p50 0.14 s
  and 0.15 s (+7%), p99 0.72 s and 0.89 s, **+23%**, the run with agents
  above in five of six ten-minute blocks (−3% to +41%) and climbing (0.63
  to 1.04 s). The executors' waits did not move; the batch, the apply and
  the fsync rose a bucket each, on all three nodes, unexplained. One pair,
  run back to back.
- **The gate reads:** missed in both pairs at 5,000 (the first
  collapsed). At 3,000 not resolved: probably a rise of 20–25%, against
  20%, with no second pair for its spread. A fix to try keeps a long
  personal call off the executors the batches wait for (a lane of its
  own, or the queue ordered by gas); the gate is then run below the knee
  (`api_in_flight` raised, a lower rate, or more users at a lower rate
  each), so that it reads the node and not the driver's queue.
- **Memory:** +56–59 KiB a replica right after creation, in all three runs
  with agents: **met** as the fixed overhead, 5–8 KiB under the limit and
  about 5 KiB more than the early run's through `assign`. At the load's
  end, against the run without them: +87–90 KiB a replica at 3,000 and
  +94–120 KiB at 5,000 (+94–106 and +110–120 for the two pairs), the
  log cache among it (+300 MB a node at 5,000, about +30 KiB a replica).
- **Creation through `claim`:** 10,001 agents in 1,836–1,847 s, 5.4 a
  second. **Wakes:** 40,000 each of `alive`, `since`, `push` and the
  whole wake in every run, none failed; a wake p50 0.59–0.63 s and p99
  2.2–2.3 s at 5,000, 0.22 s and 1.25 s at 3,000.

Beside 2026-11-06 (kernel 7.2, 32 threads online, `performance` on both
hosts, clock within 6 ms), this compumax ran kernel 6.18 with all 64
threads online and its clock 340 ms off the coordinator's (its NTP
source's; the drivers time by their own monotonic clock), sigma's governor
was `powersave`, and the driver's sends went late about six times as often
(both arms alike). The 1.84 s and 2.83 s baselines are not set against
each other. What remains is `open.md`'s.

**The cause** [measured, compumax (capped) + sigma, 2026-11-21; the
rerun's layout and build with every executor job, batch, apply and
writer flush timed exactly on the nodes; 3,000 calls a second for eight
minutes]: where a batch's time goes is measured; what raises it with the
agents is not identified.
- **Eight minutes show no rise.** 2,000 personal agents waking every
  180 s, the same calls a second as 10,000 every 900 s, left the
  transfers' p99 at 590 ms against 610 ms without them; 10,000 agents
  eight minutes after their creation moved nothing at the nodes (a batch
  p50 75 ms in both), the writer's changes a second 3% higher (the wakes'
  own; an idle agent's group writes nothing) and its bytes 2%. In the
  hour-long runs below the first ten-minute block is as flat (594 against
  578 ms) and the gap opens from the second (983 against 664 ms): these
  runs sat inside that window.
- **Where a batch's time goes.** A shard's batch took 75 ms at p50: 6 ms
  to its proposal (refine and dry run, the executors 40–45% busy, a wait
  for one 1.5–1.9 ms at p50), 35 ms to its commit (the synced appends
  here and at a follower) and 32 ms to its apply, of which 29 ms was the
  apply's commit: an apply needs no sync, but it queued behind and then
  rode the writer's next synced flush, which took 18 ms at p50 and ran
  back to back (47 a second, 62 commits each, about 9 MB a second a node).
  Where shards' batches waited past 10 ms for an executor, other shards'
  batches and root builds held them; a personal agent's job, 1.4% of that
  time.
- **Over the hour, at the nodes** (exact means from the histograms'
  sums): the rerun's 3,000 pair had the batch +4%, +11% and +10% on the
  three nodes, its commit +8–11%, the synced flush 21–22 to 23 ms
  (+3–8%), the apply +3–9%; the executors' waits moved both ways. With
  the agents the nodes also ran 10–14 million more steps' gas a second
  (their pushes, even across the hour, as their wakes are) and the log
  cache grew from about 130 to 335 MiB a node over the hour (50–67 MiB
  without); batches a second, root builds, flushes and signature checks
  did not grow with time. Every stage climbed over the hour in both runs
  (the batch 78 to 103 ms without the agents). At 5,000 the executors'
  waits rose too (their means from 6–17 to 8–23 ms).
- **The fix:** a drain's unsynced commits go first, written and answered
  before its sync (`core-model.md` §9.5, the log writer), so an apply
  whose agent has no synced commit before it in the drain waits out the
  flush in progress, not another one after it; nothing durable changes.
  Executor lanes for long calls are not built: at 3,000 the data does
  not show them holding the batches.

**The rerun with the fix** [measured, compumax (capped) + sigma,
2026-11-21; the same layout, cap (each node on four threads), seed and
load; the nodes and guests built at one revision, the driver's harness
with its record written off the sending thread; the nodes' API bound
raised to 4,096 requests in flight so the gate reads the nodes; 3,000
calls a second, calibrated over 600 s (0 errors, the answered rate the
offered, at most 843 in flight, the nodes' CPU 53–57%); four runs of an
hour, (a) (b) (a′) (b′), 10,000 personal agents waking every 900 s in
(b) and (b′); the clock check overridden, compumax's NTP source 140 ms
off]:

| run | transfer p50 / p99 / p99.9 (s) | 10-min block p99 (s) | in flight max | node CPU | RSS end (GiB) |
|---|---|---|---|---|---|
| (a) | 0.122 / 0.725 / 1.16 | 0.59 0.68 0.74 0.79 0.73 0.81 | 1,608 | 59–60% | 1.79–1.81 |
| (b) | 0.131 / 0.840 / 1.36 | 0.64 1.00 0.83 0.75 0.79 0.95 | 2,467 | 58–64% | 2.75–2.78 |
| (a′) | 0.119 / 0.651 / 0.99 | 0.58 0.66 0.65 0.66 0.63 0.74 | 1,498 | 57–63% | 1.71–1.74 |
| (b′) | 0.129 / 0.852 / 1.50 | 0.59 0.98 0.96 0.81 0.74 0.94 | 2,401 | 58–65% | 2.71–2.77 |

- **The gate reads: missed.** +15.8% in the first pair, **+30.9%** in the
  second, +23% pooled (0.846 against 0.688 s), as before the fix. The
  two runs with agents agree within 1.4%; the two without differ by 11%.
  No errors in any run; the driver's sends at worst 2.3 ms late.
- **At the nodes,** the fix took the apply's mean from 37–39 to 22–23 ms
  and the batch's about 10% lower than the rerun's, the commit 8–11%
  higher (its sync now behind the drain's buffered flush, about 41 a
  second at 5 ms); with the agents the batch's mean still rose +2–13%
  per node, the commit +2–9%, the synced flush +1–4%, the node leading
  the most shards' batches the most.
- **Memory:** +55.9–59.2 KiB a replica right after creation (**met**, as
  before); at the load's end, against the run without them, +98–103 KiB
  a replica in the first pair and +105–108 KiB in the second.
- **Wakes:** 40,000 in each run with agents, none failed; a wake p50
  0.20–0.21 s, p99 1.19–1.27 s.
- **Creation through `claim`:** 10,001 agents, a creator's first made one
  creator at a time (sixteen creators dialing together passed a node's
  handshakes a client address may hold at once, and were refused).

**What the agents added on the node thread: idle leaders' looks** [measured,
compumax (capped) + sigma, 2026-11-22; the same layout, cap and load, the
nodes built with frame pointers and sampled with `perf` on node 1's one
runtime thread, which runs every group's driver, leader and apply loop,
for 60 s at 7 and 21 minutes into a 26-minute load; one run with 10,000
personal agents, one without]:
- **What the agents add is idle leaders' looks.** A leader with no input
  looks at what it may have due (a sweep of its due rows, a cut's marker,
  reads to serve, reports, closes, proofs), about ten store reads and
  scans on that thread. Without the agents those looks took 35 and 23 of
  about 10,000 samples; with them 1,010 (9.6%) and 1,808 (16.6%). With
  the looks taken out, the thread's samples were the same in both runs
  (9,100 against 9,245 at 21 minutes).
- **Why they grew.** An idle leader slept at most 5 s before looking at
  its first due row again, and at most 2 s before its next boundary, so a
  clock stepped forward would not leave it asleep past its time. A
  personal agent's wake opens a session, a due row an hour ahead, so from
  its first wake its leader looked every 5 s, about 3,300 leaders on a
  node: their number grows as the agents wake for the first time, one in
  900 s each, which is why the first ten-minute block is flat and the gap
  opens from the second. The transfers' p99 was 0.85 s with the agents and
  0.65 s without them (+30%).
- **The fix:** an idle leader sleeps until its first due row or boundary.
  A node task reads the node's clock against the monotonic clock every
  second, and when the clock has gained more than a second (a step, a
  slew adding up, the host's sleep) it wakes every idle leader to look
  again, so a step is seen within two seconds, no later than before. The
  space's representative first learned (for reports) and a blob arriving
  (a proof to record) wake them too, 256 at a time and 50 ms apart
  (`steps::look_again`): a look took about 150–275 µs of the thread in
  these runs, so a slice holds it at most about 70 ms, and a step at the
  33,000 idle leaders a node of `open.md`'s 100,066 groups is seen by all
  within about 15 s rather than as one burst of several seconds the Raft
  drivers sharing the thread (3 s election timeout) would wait behind
  (`a_wake_comes_in_slices`). With the fix and the agents, the
  looks took 34 and 27 samples, as without them (8–15 idle looks a second
  a node), and the transfers' p99 was 0.78 s in that one 26-minute run.
  The `look` stage of a node's stats counts the idle looks that found
  nothing due.
- **Left as found:** a personal agent's group never compacts its log at
  its rate (1,024 entries a compaction), so its entries stay in memory
  and the store (the log cache 130 to 400 MiB a node over the hour,
  about 7 KiB a wake a replica); and each batch's apply and its leader
  open a range scan of the agent's cut roots, of which two are kept
  (about 16% of the thread in both runs, the scans' setup most of it).
  Neither differed between the runs on that thread.

**The rerun with the looks' fix** [measured, compumax (capped) + sigma,
2026-11-22; as "The rerun with the fix": the same layout, cap, seed,
load and API bound, the nodes and guests built at one revision with the
idle leaders' sleep; calibrated at 3,000 calls a second over 600 s (0
errors, the answered rate the offered, at most 1,634 in flight, the
nodes' CPU 56–60%); four runs of an hour, (a) (b) (a′) (b′); the clock
check passed, compumax and sigma on one NTP source, 1.6 ms apart]:

| run | transfer p50 / p99 / p99.9 (s) | 10-min block p99 (s) | in flight max | node CPU | RSS end (GiB) |
|---|---|---|---|---|---|
| (a) | 0.134 / 1.073 / 2.52 | 0.57 0.72 0.69 1.03 1.19 1.97 | 3,635 | 56–62% | 1.87–1.89 |
| (b) | 0.133 / 0.827 / 1.50 | 0.64 0.95 0.79 0.79 0.86 0.92 | 2,830 | 55–64% | 2.76–2.83 |
| (a′) | 0.118 / 0.664 / 0.98 | 0.56 0.66 0.72 0.64 0.68 0.70 | 1,531 | 59–62% | 1.78–1.82 |
| (b′) | 0.123 / 0.885 / 1.43 | 0.61 0.87 0.99 0.93 0.82 0.96 | 2,349 | 58–62% | 2.86–2.88 |

- **The gate reads: missed.** −23% in the first pair, whose run without
  agents is the outlier (its blocks climbing to 1.97 s, 26 calls
  refused `Behind`, its p99 62% over (a′)'s); **+33%** in the second.
  The runs with agents agree within 7% and match the previous rerun's
  (0.840 and 0.852 s); (a′) matches its (a′) (0.651 s). The sleep did
  not move the p99 with agents: the looks were a cost on the node's
  thread, not the rise.
- **At the nodes,** in the second pair, with the agents the batch's
  mean rose +5–6% per node, the commit +2–8%, the synced flush +3%, the
  wait in the shards' queues +9–11%; the idle looks 8–15 a second a
  node at 0.12–0.14 ms each. The rise at the driver's p99 (+33%) is
  several times the rise in any stage's mean at the nodes.
- **Memory:** +54–58.5 KiB a replica right after creation (**met**); at
  the load's end +254–268 KiB a replica against the node before
  creation.
- **Wakes:** 39,890 in each run with agents' window, none failed; a wake
  p99 1.15 and 1.25 s.

**Reaching the agent: every gateway lists every node.** A node that does
not replicate an agent answers `Elsewhere { replicas }`
(`node/host/src/node/mod.rs`), and a gateway retries toward any upstream
it lists (`node-api.md` §6), so a gateway that lists every node of its
space reaches every agent. That is the configuration a home requires, for
spaces of three to a few dozen nodes. Forwarding between nodes, for a
gateway that lists only some, is later work (`open.md`).

**Admission** [built, `node-api.md` §2–§3]: a personal agent sets two
flags that ingress reads from the agent's own state, as it reads the
credential ring. `Personal` declares them,
`#[actor(known_keys, onion_only)]`; its schema carries them and its
install writes the agent's row `admission` (the declaring instance and
the flags). One actor of an agent declares them, for good: a second
declaring actor at another instance, or a program declaring none
installed over the declaring one, fails the install (`Admission`).
Nothing in the node knows a personal agent: any agent's actor may ask.
- **known keys only:** a session-creating call from a key absent from the
  agent's admitted-keys rows is refused `Admission(UnknownKey)`. The rows
  are the declaring actor's hashed table `admitted`, keyed by the 32-byte
  key, any value (the node reads a row's presence; `Personal` may keep
  what a key is in it). The lookup runs **before** the signature check
  (the key is only an index into the rows; the check that the call
  creates a session reads the session row), so an unknown key costs three
  point reads (the agent's `admission` row, the session's, the key's), no
  verification and no write [measured, the ingress suite on a debug
  build, x86-64 workstation, 2026-11-03: 10^4 attempts, each a session of
  its own, refused with the node's verifications and the agent's applied
  index unchanged, about 0.36 ms each end to end over the socket]. A
  key admitted in the last batch may be refused until the replica that
  takes the call applies it, and the client retries. A call in a session
  the agent holds is not looked up: a key removed keeps its sessions until
  they expire (an hour idle), so `Personal`'s handlers check the caller
  against the device set as well. `Personal` admits the device set's sync
  and admin keys, the recovery keys' ed25519 halves and open pairing
  slots' keys.
- **onion only** [decided, E17]: a request the gateway did not receive on
  its onion service is refused `Admission(OnionOnly)`: a call, a query, a
  workflow read, a credentialed call; a schema read answers none. The
  gateway marks each request it relays with the transport it came in on
  (the frame's `mark`, `node-api.md` §2: 1 clearnet from its HTTP and SSH
  ports, 2 onion from its onion service's, §6.1), never passing a
  client's own on; a node treats a missing mark (0) as clearnet (the unix socket's
  tools and test clients send none). The node trusts the mark as it trusts
  any API client, the gateway being inside the operator's network. The
  mark is the gateway's word, defence in depth against a client bug and
  against strangers on the clearnet, not a privacy guarantee. **The
  enforcement is the client's,
  in three parts:** the light node routes by destination agent and has no
  clearnet route at all for any kind addressed to the personal agent or to
  `Homes` (not a policy checked at send time); the facility exposes only
  its named operations, never a generic call or query, so no page can
  steer it; and every SSH connection the app opens (the light node's
  `vos-api` connections and s4's screens alike) runs over Tor, each on its
  own circuit and SSH key (§6.1, §6.5, §7.3). No facility operation may
  add a generic call.
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

**`Personal`'s upgrades over agents that hold data:**
`Admin::Install` replaces the program and touches no table
(`agent/default/src/refine/admin.rs`), and state migration is unbuilt, so
`Personal`'s storage layout is **append-only across versions:** new
tables, never a changed key or encoding. A field added to a row's type
would not decode what the previous version wrote (the codec has no
optional tail), and an actor's struct stores nothing (`core-model.md`
§9.1: state is rows, a single value a `Cell`, and a changed value type a
new table), so `Personal`'s state is its tables and cells, and its
version answers `version` [built, `agent/personal`]. The upgrade test
installs the next version, built from the same tables, over a populated
agent and reads every row back
(`agent/testkit/tests/agent/personal/upgrade.rs`; it adds no table, since
`#[actor]` gives a field no `#[cfg]`); each release is to install so over
a populated agent of the one before. The keeper upgrades in batches and
stops on the first refusal. The layout
binds from the first release: until then rows change freely. A change that cannot
be append-only waits for state migration (`open.md`, "Upgrades").

**`Personal` as built** [built, `agent/personal`, its wire types
`vos_wire::personal`]: the commit log, the votes and verdicts, evidence,
sealed scopes, acknowledgements, the recovery scope, quotas, the inbox,
pairing slots, the lease and its grace, and gated reads, over the device
set of §3.5 (its rules as built are there): devices with their keys,
class, attestation, nullifier, sealed label, probation, seasoning and
status; the claiming device active at its claim, a strong admin's add
inline in its commit, and the operations with their vetoes, contests,
resolutions and second signatures. Batch time decides lazily: each call
first settles one operation that fell due (a removal's device leaves
`admitted`, a `Matured` entry is logged), refusing with `Settling` while
more are due, which `wake` settles one a call; then the slots that expired
and the pending candidate's timeout. A refused call writes nothing, so its
settling waits for the next call that runs, and a read computes a device's
standing from the time it reads at. **Which time each reading uses**
[built]: a node serves a query at its agent's last batch's time, and a
quiet home runs no batch, so every reading of `Personal` (`overview`'s
`at` and `lapsed`, `devices`' standing, seasoning and `seen`, an
operation's state, the inbox and the slots) is at the time of the agent's
last call, and nothing that fell due since is settled (a matured removal
is logged, and its commit owed, by a call alone). A device's pass that
posts nothing therefore wakes the agent (`wake`, a call that settles and
counts no one seen) when the overview's batch time is older than thirty
minutes by the device's clock (`job::STALE_MS`, two of the background
job's periods: a quiet home is woken every other pass), or an
uncontested operation it verified open has matured by either clock (so
the commit a matured removal owes is raised on the pass after it
matures), then reads the log
and the overview again: the device set's standing, the clock alarm (the
device's clock against the batch time read after the wake) and the commit
owed are at most a pass old. The Devices screen's read wakes the agent
the same way first (`space::Personal::devices`). `seen` stays each
device's last call (below, "Seen means a call"). Delays and maturities
themselves run on batch time alone, as below. The home's
calls (`claim`, `renew`) take the role `homes`; `claim` answers
`Homes` by message (above, "`Homes` as built"). Bounds the rules above leave open: `alive` is logged at
most once an hour a device (the entry logged last answers between), a
vote's signed message names its candidate's log index as well as its
epoch (an epoch's number is free again after a void), an opener holds one
open pairing slot and an agent four, a slot's holder writes four inbox
items and a closed slot's items are deleted, and a removal that matured
inside a candidate's window decides it, as of its maturity, by the other
devices' votes.

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
- **Allowed proposals:** Add and Remove, by value, in a commit with a
  path; a device's `update` is its own commit with a path and no
  proposals. Nothing else: no ReInit, no external commit or join, no PSK,
  no group-context change. The
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

**Key-confirmed epochs** [built]: an epoch's keys are used only once the
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
  ‖ agent ‖ epoch ‖ epoch_authenticator)`, or `nack(epoch)`. **The signed
  vote names the candidate's log index and the log's chain through the
  candidate's entry** [built]: a vote shown to a device whose log differs
  (another confirming set) does not verify there, so two devices shown
  two sets each raise the split-log alarm at the other's vote, and
  neither confirms.
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
  anyway could hand it data sealed under the prior epoch, until the
  user's next commit after the 72 h removal delay (§8, B8), which nothing
  makes without them: every pass raises a commit owed (`Notice::Commit`,
  the chrome's "Commit now") for as long as a matured removal waits for
  one, and for as long as a verdict left the kit's `R` unheld (below).
- **Updates:** any commit of a device's renews its leaf, an admin-signed
  commit ("Commit now" makes one), as does its commit after its admin key
  is replaced. The yearly prompt shared with the home's re-proof [E15] is
  not built: a device that commits nothing for a year leaves a leaf of its
  key package's lifetime, which a later joiner's Welcome refuses
  (`open.md`).

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
  for new data. History horizons are later work (`open.md`).

**The suite:** ciphersuite 1 (X25519, AES-128-GCM, SHA-256, Ed25519), as
mls-rs maintains no hybrid post-quantum suite; a later change is a
successor group, never two suites in one group (§8, F2). None is
maintained [read 2026-11-02]: mls-rs 0.57.0 (2026-10-28) has
`ML_KEM_768_X25519`, X-Wing over suite 1's AEAD, hash and signature, but
on a private code point (65100, "no official PQ cipher suites" in its
source), behind mls-rs-core's `post-quantum` feature, implemented only by
the aws-lc provider under aws-lc-rs's `unstable` feature and used by
mls-rs itself only for benchmarks; the RustCrypto provider has none. The
IETF's `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`
(draft-ietf-mls-pq-ciphersuites-06, 2026-07-21, KEM 0x647a) has no code
point yet. So ciphersuite 1; the successor group follows once a code
point is assigned and a provider ships it outside an unstable feature.

**Measured on mls-rs 0.57** [measured, 2026-11-02; spike outside the
tree; timings on x86 (Core Ultra 7 155H, under load), the `.so` an
arm64-v8a build; the phones' timings below of 2026-11-06]:
- **Features:** `default-features = false` with `private_message` only
  (encrypted handshakes); no `std`, `rayon`, `x509`, `psk`,
  `by_ref_proposal`, `out_of_order`, `prior_epoch`, `custom_proposal` or
  `tree_index`; the RustCrypto provider 0.22 (0.23 then could not share
  a build with russh 0.61's `curve25519-dalek` `=5.0.0-rc.0`; russh 0.65
  takes 5.0.0, so 0.23 now builds beside it, unmeasured).
- **The facility's `.so`** (`libvos_facility.so`, release, arm64,
  stripped as packaged): +0.86 MB with the device-group scenario linked
  (+0.38 MB gzip -9), +0.96 MB with `std`: within PG5's 2 MB (§2.4). The growth
  includes a second RustCrypto generation beside the facility's own.
- **A candidate processed on a copy** (x86): about 1 ms p50 (0.9–3 ms as
  the host's load varied) in a group of 3 or 8, whether the copy is a
  clone of the in-memory group or loaded from its persisted bytes and
  written back; PG6's limit, on the phone, is 200 ms. **On the phones**
  [measured, 2026-11-06; 200 runs, 3 rounds each]: the Fairphone
  6 0.63–0.66 ms p50 in a group of 3, 0.73 ms in a group of 8; the
  Pixel 1 1.22–1.24 ms and 1.40–1.43 ms; loaded from persisted bytes and
  written back, 0.66 and 1.30–1.33 ms. The exporter agrees on three
  devices and the allow-list refuses a `GroupContextExtensions` commit,
  both built and received.
- **Sizes:** a key package 343 B; an update commit 734 B (3 devices) and
  1,374 B (8); add(2) 1,374 B with a 1,387 B Welcome carrying the tree;
  remove 606 B; the persisted group state 1.1–2.7 KB; a held own commit
  (`CommitSecrets`) 2.8 KB.
- **What the API gives, and what `vos-mls` must add:**
  - `Group` is `Clone`, and processing writes nothing to storage, so the
    copy is a clone; a copy is never written through the current
    namespace's storage (it shares the handle).
  - A device's own commit is built with `build_detached` and applied
    with `apply_detached_commit` on confirmation. Building it spends a
    handshake-key generation of the current state (the commit is a
    `PrivateMessage`), so the current state is persisted in the same
    batch as the held commit, and the held commit before the call that
    posts it: a device cannot process its own commit, so a lost one means
    re-pairing. The held commit carries the next epoch's secrets and the
    leaf's signing key, under the same after-first-unlock wrap.
    `apply_detached_commit` checks nothing: `vos-mls` checks that the
    confirmed candidate's hash is the held commit's and that the current
    epoch is the one before, and deletes the held commit on a void.
  - A received commit is processed with the log's batch time
    (`process_incoming_message_with_time`): deterministic, so the copy
    need not be persisted (after a crash the device processes the logged
    candidate again), and with leaf and key-package lifetimes checked;
    without `std` and without a time, mls-rs checks no lifetime.
  - A rival candidate processed on a copy and dropped leaves the next one
    processable; processed in place it does not.
  - `MlsRules::filter_proposals` refuses other proposal types on both
    sending and receiving. Update proposals exist only by reference
    (`by_ref_proposal`), and RFC 9420 never commits a committer's own
    Update by value: the allow-list is Add and Remove by value with a
    path required, and a device's `update` is its own commit with a path
    and no proposals.
  - Handshakes are encrypted, so only devices can check that a commit's
    proposals are the logged effect's: `vos-mls` gives its rules the
    logged effect before processing, and its identity provider checks
    each Add's credential (sync and admin key) against the matured
    operation. A leaf credential change (an admin key replaced) is the
    committer's own update, allowed for that leaf and that new credential
    alone (`Mls::renew`, `Expected::renewed`).
  - The Safe Exporter is not in 0.57.

**As built** (`support/mls`, `node/light/src/group`):
- **`vos-mls`:** mls-rs's storage over a fjall keyspace under a prefix,
  every write staged and committed with the caller's rows in one synced
  batch; a copy reads the current rows and writes to memory alone, and a
  swap moves its writes into the current batch. `Mls::commit` builds
  detached and writes the current state, the held commit and the caller's
  record in one batch before it returns; `Mls::own` applies it on a copy
  only for its handshake's hash and the next epoch; `Mls::swap` refuses a
  copy of another epoch and deletes any held commit; `Mls::void` deletes
  it. `Mls::restart` starts a new group, its commit adding the rest from
  their key packages applied and held beside the current group until the
  swap, which deletes the group left; a member joins it by Welcome from
  the group it is in. The policy refuses, received, anything but Add and
  Remove by value, an external commit, a committer or adds and removals
  not the logged effect, a handshake in the clear and a commit whose
  committer kept its leaf (no path); a leaf's successor must carry the
  same credential, or the one renewal its logged effect allows: a
  replaced admin key's, by its device's own commit (`Mls::renew`, held
  as any commit; the leaf's identity, its sync key, unchanged).
- **The device group (`vos_light::group::DeviceGroup`), sans I/O:** the
  caller reads the log and makes the calls, the admin key signing commits
  and the sync key votes and evidence. A commit's signed call is written
  before it is sent, so its evidence is posted again after a crash until
  the log holds it. Reading the log, a device checks each entry's chain;
  checks each device-set call (operation, veto, second signature,
  resolution) against its signer's key (an active device's admin key, as
  replaced, or the kit entry's), what that signer may sign and the delay
  the configured policy sets; honours a maturity only once the evidence
  supports it (the operation's own, and its delay passed with no verified
  veto of a device with a voice, no rival removal and, for a restore, no
  `alive` since, or a verified second signature, or verified resolutions
  naming it: the kit's, or two seasoned strong devices'), waiting for
  evidence posted after the maturity until the confirm window has passed,
  else an alarm (`Unsigned`), as is a maturity asserted past its entry's
  time; stops at an entry whose batch time goes back; freezes a probation
  under a removal as the agent does; takes a candidate only from a device with a
  voice past its probation, an add only from a strong admin or as a
  matured add operation, for a fresh device number; processes it once
  its evidence verifies, on a copy at the log's time under its logged
  effect, and refuses it unless the copy's members are the device set
  after it; votes; verifies each vote of the set against the voter's sync
  key and this device's log; and decides by its own count, an entry past
  the window deciding as of the window's end as the agent does. The
  agent's verdict is advisory: one this device cannot count raises an
  alarm, and the next candidate stops it (re-pair). A call refused with
  `Settling` is made again after a `wake`, sent at most nine times with
  eight wakes between (`WAKES`), by one owner: a flow's call by the link
  (`AgentLink::settled`), a pass's post by the pass (`job::post_settled`),
  a push by sealed sync (`SealedSync::send`, the rest pushed again after
  each of at most eight wakes); the link sends a post and each push once,
  a push stopping at the first `Settling`. The sync key's calls and its wakes share
  one session and one sequence count, so no wake reuses a call's
  sequence. A flow reads the log as a pass does (`job::log`): each page
  through the onion, a page that does not move past the one before
  refused (`Disordered`).
- **Regroup and restore:** a matured regroup voids the pending candidate
  and removes every device but its regrouper, one added while it was open
  too, and the next commit is the regrouper's new group of it alone
  (`DeviceGroup::regroup`), its epoch the confirmed one plus one, carrying
  every removal, its epochs counting on from the agent's; the others pair
  again from it. A device that cannot
  follow reads on for the device set's operations and takes no candidate
  but its own regroup's, following the others' epochs and the removals
  they carry by the agent's word. A restore's device starts its new group alone
  from what it reads of the agent once the restore matured
  (`DeviceGroup::restore`: the log's head, the device set, the new kit),
  its first commit carrying the removal of every device before it.
- **Keys:** `k(scope, n)` only at the confirmed epoch; the archive holds
  the naming secret, drawn with the store (for the claiming device, with
  its group), and every tracked scope's key of every confirmed epoch,
  recorded in the swap's batch; it seals under the epoch's archive key
  (`MLS-Exporter("vos/personal/archive", "", 32)`, XChaCha20-Poly1305).
  It is pushed to the agent at each confirmed epoch (§3.6, "Sealed sync
  as built"). A store that derived a scope id joins no other group.
- **A replaced admin key** [built]: from the replacement's verified
  maturity the new key signs and the device's next commit renews its
  leaf to it, which the others accept for that device and that key
  alone; a call the new key signs while the maturity's evidence is still
  to come waits for it (the commit is neither processed nor refused) and
  falls if it never verifies, so a late evidence makes no false refusal.
- **The policy's delays** [built]: the claim's configuration (one
  logged before its assignment, or the one beside it) sets the delays
  and windows the device set's rules run on (`operation_delay_ms`,
  `kit_delay_ms`, `probation_ms`, `seasoning_ms`, `confirm_window_ms`); a
  paired device takes its pairing device's. A `Configured` logged later
  is the operators' word, and a lowered delay would mature an operation
  inside the window §3.5's rules give the devices to veto it, which B8
  denies the operators: a device takes from it the quotas, the lease and
  the inbox, keeps each delay and window at the higher of the two
  (`Policy::over`), and raises `Alarm::Policy` for one it lowers; an
  operation then asserted matured inside the kept delay is `Unsigned`.
  `Personal` takes its policy only with its claim (no later call
  configures it), so an honest home logs no lowered delay. Lowering a
  delay would need an operation of the device set's own, signed as §3.5's are; none
  is built. A raised delay is taken: the operators can lengthen any
  delay without bound, which stops removals and restores maturing, a
  withholding B8 concedes them already.
- **Not built here:** a restore's device's view of operations opened
  before its read. A
  device that cannot follow takes the device a confirmed candidate adds
  into its set by the agent's word, so that device's nodes have a known
  author.

**The device group measured** [measured, x86-64 Core Ultra 7 155H under
load (load average 15–20), release, 2026-11-06; `vos-phone group`, the
agent's log scripted, each step one synced fjall batch; the phone's
numbers are the phone session's, `tools/phone/scripts/group.sh`]:
- a group of 3, 40 update rounds: the committer's commit, built and held,
  2.1 ms p50 (7.0 p95); another device's reading of the candidate and its
  evidence, the commit processed on a copy and its vote, 1.7 ms (2.9);
  its reading of the votes, counted and the copy swapped in, 1.4 ms (8.5);
- a group of 8: 3.2 ms (5.0), 2.4 ms (4.6) and 2.0 ms (4.2);
- sizes: an update's handshake 702 B (3 devices) and 830 B (8); the MLS
  state 1,468 B and 3,118 B; what a device keeps of the log 712 B and
  1,337 B; the archive 2,516 B for one scope over 41 epochs (about 61 B a
  key);
- a confirmation round is, at the agent, the commit call, its evidence,
  one vote a device of the set and each device's read of the log: at
  §3.6's measured 2.6–3 ms a call through a node's socket, about 15 ms for
  three devices on a quiet host, before Tor.

### 3.5 Device secrets and the rules for changing devices

**Per device** [decided, E2]:

| secret | what for | held as |
|---|---|---|
| the member secret `s` of each space | membership proofs (auth, owner) | derived at each use from the keystore's HMAC over the space's handle, behind the prompt (a biometric or the PIN), as today [built, `identity-and-authority.md` §7]; in the process during a use, as that design states |
| the **admin key** (Ed25519) | the client key of admin calls: device-set operations and commits | **a Keystore signing key in the TEE**, never leaving it: per-use authentication by a strong biometric (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`), with key attestation where the phone offers it. **Decided by capability, not by version:** the app makes the admin key as a keystore Ed25519 key and reads its attestation; the device is a strong admin only if the key is hardware-backed (attested security level TEE) and a Class 3 biometric is enrolled. KeyMint's TEE implementations must support curve 25519 for signing and StrongBox implementations do not (`IKeyMintDevice.aidl`), so the key lives in the TEE. Ed25519 appears with KeyMint 2 (Android 13), but a newer framework over older TEE firmware (a custom ROM over Keymaster, such as a Pixel 1 on LineageOS 15) has none, or only keystore2's software fallback. Such a device, and any device without a Class 3 biometric, is a **delayed admin** (below) |
| the **sync key** (ed25519) | the client key at the personal agent; signing DAG nodes and confirmations | wrapped under a keystore key usable **after the first unlock** since boot, no per-use prompt, no unlocked-screen requirement: background sync runs on a locked phone |
| the MLS state, the key archive, `R` | sealing and opening envelopes, processing commits | the same after-first-unlock wrap; kept out of Android's backups (§8, A11) |

- **Ed25519 only:** ingress client keys are ed25519
  (`agent/wire/src/ingress.rs`), and an admin key is a client key, so
  admin keys are Ed25519 too. A second client-key curve (P-256) at ingress
  would serve only phones whose TEE has no Ed25519, at the cost of new
  ingress code and its carrier and fuzz cover; those phones are delayed
  admins instead.
  The device set records whether each admin key's attestation showed a
  TEE key requiring a strong biometric, and the attested verified-boot
  state; the chrome shows an unattested key, and a device whose boot is
  unverified (an unlocked bootloader, a custom ROM), without changing its
  admin class [decided, E24].
- **Why the bars differ:** a sign-in or a P1 transfer is one action the
  user sees; device changes are lasting control of every device's data. So
  the member secret keeps its decided PIN fallback and in-process exposure
  (stated in `SECURITY.md`); the admin key is held where malware with the
  app's process cannot reach it.
- **Delayed admins:** a device that cannot hold the admin key as above
  administers anyway, under a delay: on a phone without a strong
  biometric its TEE key is authenticated by the PIN; on a phone whose
  TEE has no Ed25519, the admin key is a software Ed25519 key wrapped
  under a per-use-authenticated AES keystore key, so it is in the
  process during each use. Either way every operation it signs, adds
  included, waits 72 h and can be contested (its commits carry only
  operations already matured), which bounds what malware that captures
  such a key can do.
- **The class as built** [built]: the class is
  the device's own report, as the UI's keystore answered it (`KeyInfo`'s
  security level), not an attestation another device verified: a key that
  is not hardware-backed registers `AdminClass::Delayed`, claimed, paired
  or as a replacement; the verified-boot flag is recorded as reported.
  Verifying the attestation chain, and the PIN-authenticated fallback of a
  phone without a Class 3 biometric, are later work (`open.md`). A
  delayed admin opens no pairing (`Error::DelayedAdmin`, below): a strong
  admin's device pairs it.
- **After first unlock:** a phone unlocked once since boot uses the sync
  key and the MLS state while locked; a thief who keeps it powered and
  runs code on it reads the personal space. Before the first unlock
  nothing opens (§8, A2).

**Measured on the phones** [measured, 2026-11-06; a spike app, its log
host-verified]:
- **Fairphone 6** (KeyMint 3, Android 15, bootloader locked): the admin
  key is an Ed25519 keystore key at security level TEE, its attestation
  chain 5 certificates long to the Key Attestation CA; StrongBox refuses
  Ed25519 (`Unsupported StrongBox EC: ed25519`), as `IKeyMintDevice.aidl`
  says. A Class 3 fingerprint is enrolled, so the device is a **strong
  admin**. Each signature takes one prompt (2.4–2.6 s from the prompt to
  the touch, 9–16 ms to sign); a second signature without a prompt is
  refused. Payloads of 15,360 and 16,384 bytes sign and verify on the
  host; 16,385 bytes fail after the touch (`Invalid input length`), so
  the 15 KiB bound above holds with margin.
- **Pixel 1** (LineageOS on Android 15, Keymaster firmware): no hardware
  Ed25519; the key is keystore2's software fallback, so the device is a
  **delayed admin**. Its fallback works: a software Ed25519 key sealed
  under a per-use-authenticated AES keystore key, opened behind the
  prompt and refused without it.
- **After first unlock:** on the Fairphone a one-off job and five
  periodic jobs (every 15 min for 75 min) ran with the phone locked and
  unwrapped their key each time; the Pixel's one-off job did too.
- **A security key:** a YubiKey's `hmac-secret` through YubiKit over USB
  on the Pixel: the credential made (4.9 s with the touch), the secret
  read twice, the same 32 bytes each time.

**Admin calls, verified at ingress and end to end:**
- **One call, one prompt:** every device-set operation (add, remove, veto,
  resolve, kit rotation, restore, regroup, admin-key replacement) and
  every commit is a one-shot client call whose key is the device's admin
  key (or the kit's, for its own operations); a device-set call names
  its place first, the control log's head it was made against (below,
  "The place"). The prompt authorizes the one
  signature the call needs; ingress verifies it as it verifies any client
  call, and the agent checks the origin, `Principal::Client(key)`, against
  the device set: whose key it is, and whether that device's state (active,
  seasoned, delayed) allows the operation. No guest verifies a signature
  (`core-model.md` §5: no signed evidence inside guests).
- **Prompts:** pairing is one prompt (the add and its commit are one call,
  §3.8); a removal is the operation's prompt and, once it matures, the
  commit that carries it, made by the next device whose user authenticates
  (the agent already refuses the removed device's keys at maturity); a
  veto, a resolve or a kit rotation is one each; a yearly prompt for the
  re-proof and the leaf renewal is not built (`open.md`).
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
  before acting, and acts on no operation without its evidence. The device
  holds the call as signed before it leaves (`DeviceGroup::sending`), and
  every pass posts its evidence until the log holds it, finding the call
  in the log after a kill; the kit's flows keep theirs in the store and
  post it when the kit calls again. **An operation due without its
  evidence is cancelled** (`Unevidenced`), a cosigned one too, so the
  agent and the devices close it alike: a call whose device is lost
  between the call and its evidence wedges nothing, and is made again. A
  cosign or a resolution that would make an operation without its
  evidence mature is refused `Unevidenced`: it is made again once the
  operation's evidence is in, which its author's next pass posts. The
  operators run ingress and could append anything to the log, so a device
  trusts an operation only by its signature (§8, B6).
- **The place** [E39, built]: every device-set call
  (add, remove, replace, rotate, regroup, restore, veto, cosign, resolve)
  names first in its arguments the log's head its signer read before the
  prompt, `Place { next, chain }`: the next index and the chain through the
  entry before it. The agent and every device take the call only at a
  place at or after their floor, the entry after the last admin call
  before it (a device's start, for one that read none; a paired device
  takes its pairing device's), and at or before the call's own entry, the
  chain there the log's. The agent compares it before anything the call's
  batch settles and refuses any other `StaleHead`, logging nothing; a
  device raises `Alarm::Log` and reads no further, as for an entry that
  does not chain. A call logged again elsewhere names a place before the
  call it copies, which every device that read that call has passed: a
  route cannot log a removal once signed, vetoed or cancelled a second
  time and mature it there unvetoed. Entries that are no admin call
  (evidence, votes, `alive`, a renewal, what a batch settles) move no
  floor, so another device's background pass between the reading and the
  call refuses nothing; the cost is that a signed call withheld stays
  takeable until the next admin call is logged. The device reads the log
  to its head just before the prompt (one read, two when there is
  something new), and signs nothing when that log stops at an entry it
  refuses or it is out of the set. The same call made before and taken,
  its answer lost, has its evidence posted rather than being signed again.
  A call refused `StaleHead` (another admin call between the reading and
  the call) or `Settling` (a wake first) is read and signed again, a
  prompt each time, three signatures at most; a route can make up either
  refusal, which costs at most those prompts and takes no device out, and
  a call it forwarded before making one up stays held, its evidence
  posted. The kit's and a restore's calls take the head from the log they
  read or the agent's overview, the agent's word, which binds the place,
  not its truth. Commits are not placed: an epoch and the votes, which
  bind the voters' logs, place them. Why not the call session's `t0` with
  a window, or the devices remembering each call's message: the evidence
  is a separate later entry a route can withhold, so a device that read an
  operation and its veto but never the message has nothing to recognize
  the copy by; the place is checked at the call's own entry. What is left
  is withholding: a device that has not read a veto yet can be shown the
  operation without it, and its maturity at a time the route claims (B7,
  B8).
- Delays run on the agent's batch time alone; a device whose clock
  disagrees with the agent's by more than an hour raises an alarm and
  otherwise acts as the log says. A restored device starts from the
  agent's batch time and the log's policy (the claim's configuration, each
  later one over it), never its own clock or a default.

**The device set** (a table in `Personal`): each device's sync key, admin
key and its attestation, its admin class (strong or delayed), its
"home" nullifier, a sealed label and a state: **probation** (72 h from
its add: it may sync and post confirmations, not sign operations or
commits), **active**, or **removed** (with its frontier). A device is
**seasoned** once it has been active for 7 days.

**The rules:**
1. **Add** (pairing, §3.8): signed by an active strong admin, immediate;
   the new device is in probation. Signed by a delayed admin, it waits
   72 h first.
2. **Remove `d`:** signed by an active device, **pending** for 72 h, then
   matures unless contested. Signed by `d` itself it is `d`'s **leave**
   (rule 10).
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
8. **Probation devices** cannot sign operations or veto, their own leave
   aside (rule 10). **A removal
   pending or contested against a probation device freezes its
   probation** until the removal resolves, so an add cannot ripen into a
   second vote inside a removal's own window.
9. **A device whose removal has matured has no voice:** its vetoes,
   `alive`, confirmations and nacks are ignored, whatever the agent
   stores.
10. **Leave** [E34]: a device removes itself, signed
    by its own admin key, active or on its probation (a frozen one too).
    The leave matures as soon as its evidence is posted, with no delay,
    and no device vetoes, cosigns or resolves it; the other devices commit
    it as any matured removal (the commit re-seals the kit under a new
    `R`; a device on its probation commits once its probation ends, so
    a phone left with only a newly paired one waits for it). The set's
    last live device may not leave: no device would commit it, and a
    restore with the kit replaces it instead; of two leaves open side by
    side, the one maturing last is cancelled (`Alone`).

*Why a leave waits on nothing.* A leave only lowers its signer's power:
it gives up the one voice it had and gains none. The delay and the veto
exist so that a removal a device did not ask for can be answered by it
and by the others; a leave's target is its signer, so its own act is the
consent the delay waits for, and the others have nothing to protect by a
veto: a device can always walk away by deleting its keys, and a veto
could not make it stay, only keep a voice in the set that no one holds.
A thief holding a stolen phone who signs its leave removes the phone the
owner was about to retire (A25). A device that leaves during a contest
that targets it concedes it: the removal of it ends `Moot` with the leave,
its own removal of its rival is cancelled with its silencing, and the
rival keeps its voice. The leave's evidence is what makes it mature, so a
route that holds back the evidence holds back the leave (the device posts
it again at its next pass) and one that drops it leaves it cancelled
`Unevidenced` after the operation delay: neither gives anyone a voice.

*What is conceded, and only this:* a thief who passes the owner's strong
biometric holds an active device and can always contest. The owner wins
with one device and the kit, or with two other seasoned devices whose
admins are strong (two delayed admins resolve nothing). With the
kit alone the owner still wins against a thief holding only a sync key (a
phone after first unlock, malware): the kit's `remove` of that phone can
be cancelled only by a veto, which needs the admin key the thief lacks,
so it matures after 7 days; from then the phone's `alive` is ignored, and
the kit's restore matures 7 days later, 14 days in all. With the kit alone
against a thief who also passes the biometric, the owner cannot win: the
thief vetoes, as an owner must be able to against a leaked kit (§8, A4,
D3). The kit's `remove` and `resolve` are the light node's
`Personal::remove_by_kit` and `resolve_by_kit`, from any install, a fresh
one too: the agent found by the kit's index, the set read under the kit
(`kit_view`), what fell due settled before the call; the facility's
restore screen offers them. A lost phone left powered, whose background
job answers every restore with `alive`, is removed this way first.

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
and is immediate when two seasoned devices or the kit sign it. A regroup
keeps its regrouper alone: it names every other live device, and at its
maturity every device but the regrouper is removed, one added while it
was open too; the new group is the regrouper's alone, the control log
restarts under it, and the others pair again from it.

**The recovery kit** [decided, E16]:
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
  the one that leaked. A restore is at its own home; to land elsewhere,
  restore there, then move (§3.9); restoring straight at another home is
  not built (`open.md`).
- **Kit rotation:** a new kit, a new `R`, `R1` sealed to the new kit, the
  old `R2` deleted, and the recovery envelopes re-sealed under the new `R`
  by the device that rotates. Two seasoned active devices make it at once;
  one makes it pending 72 h and contestable.
- **`R` rotates at every removal** [decided, the owner, 2026-11-06]: the
  device that commits a matured removal draws a new `R`, seals its `R1`
  to each kit entry's X25519 key (no kit holder needed), stores its `R2`
  at the agent and re-seals the recovery scope; so a removed device,
  holding the `R` before, reads nothing pushed there after its removal,
  even with the operators (§3.6, §8 D3).
- **Moving home re-splits the kit:** the new agent holds a new `R2` and
  re-pushed recovery envelopes; until the move completes the kit opens
  nothing at the new home (§3.9).

**The device set as built** [built, `agent/personal/src/devices.rs`,
property-tested in `agent/testkit/tests/agent/personal/adversaries.rs`;
where the rules above leave a choice, this is the one taken]:
- **Operations** (`add`, `remove`, `replace`, `rotate`, `regroup`,
  `restore`), each an admin call logged with its signer and its maturity:
  a device's waits the policy's `operation_delay_ms` (72 h), the kit's its
  `kit_delay_ms` (7 days), and a replacement its `probation_ms` (72 h), the
  new key admitted only at maturity: the new key's probation is the
  replacement's wait, so the old key, while it signs, can veto a
  replacement it did not ask for. `seasoning_ms` (7 days) and the kit's
  daily allowance (`kit_operations_per_day`, 4) are the policy's too; a
  test home sets each in minutes. A device's own removal is its leave
  (rule 10): taken on its probation too, kept apart from the removal
  open against it (one of each a target), its delay only the time its
  evidence has (`operation_delay_ms`, then cancelled `Unevidenced`), and
  matured by the evidence call itself; its maturity cancels the removal
  and the replacement open against the device as `Moot`. A veto or a
  cosign of a leave is refused (`Leaving`), and so is the last live
  device's leave (`Alone`, when opened; cancelled `Alone` when it would
  mature so). Each device checks it the same way
  (`node/light/src/group/set.rs`): its signer's key held on probation,
  its maturity supported only by its own evidence logged before it, the
  maturity asserted at that entry's own time and before the leave's
  deadline; a logged veto or cosign of a leave is invalid. The agent
  verifies no evidence's signature (no guest does, `core-model.md` §5): a
  leaver posting a bad signature is removed by the agent while every
  other device raises `Unsigned`, which needs the leaver's own keys.
- **Vetoes** (`veto`, an active device's admin key, never the kit's):
  a device's operation becomes contested, the kit's is cancelled. A
  contest held only by vetoes lifts when the last vetoer's removal
  matures (rule 9), and the operation matures at its own time or then,
  whichever is later. A device whose removal matures, or which is dropped
  with its void candidate, is **silenced**: its open operations (a
  matured add its commit never carried included) are cancelled and its
  vetoes lifted, as of its removal, by the calls that settle it: an
  `operations` read shows what the agent stores, so a device wakes the
  agent before it acts on one (a lifted contest has nothing to resolve).
- **Contests:** a removal aimed at an open removal of its signer by one
  of its targets, a regroup on either side, is one contest with it.
- **The two-device rules** need two seasoned devices with **strong**
  admins other than the targets: a delayed admin's signature makes
  nothing immediate and resolves nothing (every operation it signs
  waits); its veto counts. The second signature is `cosign(op)`, which
  matures a removal, a kit rotation or a regroup at once, contested or
  not; the kit cosigns only a regroup. `resolve(op, upheld)` names the
  operation that matures, its rival in a pair dropped (or, not upheld,
  the reverse): the kit's acts at once, a device's when a second agrees.
  A replacement upheld still waits out its new key's probation [E29]: it
  matures at its own time, and a device takes no maturity of one
  asserted before it.
- **A frozen probation** keeps the time it had left when the first removal
  against it opened, and runs it from when the last one closes.
- **Keys an operation brings are claimed** while it is open (a matured
  add's until its commit): no pairing slot, add or other operation takes
  them, so none can be squatted to cancel it.
- **`R2` never enters a readable row:** a rotation or a restore names its
  `R2` by `r2_hash` and carries it in its evidence, kept apart and logged
  nowhere; an operation that matures without it is cancelled
  (`Unevidenced`). The kit's evidence must come from the very key that
  signed its operation.
- **A restore carries the next kit:** at maturity every device is
  removed, the restore's device added alone and active, the kit replaced,
  and the previous `R2` released to that device alone (`recovery`) until
  its first confirmed commit, then deleted; so the rotation that follows
  every restore is part of it. A rotation's or a restore's maturity
  cancels the replaced kit's open operations, and records the recovery
  scope's position: the new kit reads only the envelopes after it, those
  re-sealed under its `R`. A device's rotation is a veto of the kit's
  pending rotation or restore, so a leaked kit cannot hold its place.
- **A regroup or a restore voids the pending candidate** (`Regroup`); the
  agent's epochs run on, the new group's first commit being the confirmed
  epoch plus one and carrying the removals.
- **Quotas:** operations, vetoes, second signatures and resolutions count
  against no commit quota, so neither a thief device nor a leaked kit can
  spend the owner's; the kit's operations count against its daily
  allowance, and a device's against its open operations.
- **Bounds:** one open operation of each kind a target (a removal, a
  replacement) or an agent (a rotation or a restore, a regroup); two open
  operations a signer besides its removals; eight live devices. A call
  settles four **steps** before it runs: an operation's maturity, or one
  row of a silencing or of a replaced kit's cancelling, each queued in
  the due index at the time it takes effect, so everything settles in
  time order and no step grows with what an adversary queued. The index
  is keyed by the time, then what falls due (`Due`: an operation's
  maturity by its index, a device's silencing, the kit's retirement, in
  that order at one time), and the open operations by their signer
  (`By`, a device's before the kit's entries), each an enum whose key
  encoding sorts as it does. These keys, and the removed keys' table
  `gone`, are the layout of `Personal`'s first version: a home founded
  on an earlier build is founded again, and a phone clears its data. Every
  handler that settles declares 40M gas [measured, the agent suite on a
  debug build, x86-64 Core Ultra 7 155H, 2026-11-06; gas is
  deterministic]: the worst call in a full set (eight seasoned devices,
  each holding two operations, each vetoed by every other device and
  resolved by one), whether a regroup naming seven of them or a restore
  matures, 13.9M; an ordinary operation, veto or resolution 1.6–3.9M,
  `alive` 0.92M.
- **Reads between calls** compute a device's standing from the removals
  due by their time, which a call may yet cancel in time order (a
  removal's signer removed first); the operations read as the last call
  left them.
- **The place,** each device-set call's first argument (§3.5, "Admin
  calls"): compared at the start of every such handler, before `settle`,
  against the head, the log's chains and `floor`, the index after the last
  admin call logged, so what its batch settles is logged ahead of the
  call.

**The kit and its flows as built** [built, `vos_light::kit`, the device
group and sealed sync, tested against `Personal` in
`node/light/tests/sealed/kit.rs` and `node/light/tests/group/set.rs`;
where the text above leaves a choice, this is the one taken; the
restore's times [World]: §6.3]:
- **The 32 bytes:** a phrase is drawn by the operating system and shown
  as BIP-39's 24 English words (its checksum checked when read back); a
  security key's are its `hmac-secret` over `SHA-256("vos/personal/kit/
  v1")`, behind a `SecurityKey` trait (YubiKit's in the app, a test
  double here). The signing key is the ed25519 seed `BLAKE2b-256(
  "vos/personal/kit/signing" ‖ bytes)`, the sealing key the X25519 secret
  `BLAKE2b-256("vos/personal/kit/sealing" ‖ bytes)`; `Homes` indexes the
  agent by `BLAKE2b-256("vos/personal/kit/index" ‖ signing key)`, which
  `Homes` keeps. The phrase's card carries the home's handle and
  onions beside the words.
- **`R1` sealed to an entry:** an ephemeral X25519 key, `R1` under
  XChaCha20-Poly1305 with a zero nonce and the key `BLAKE2b-256(
  "vos/personal/kit/r1" ‖ agent ‖ ephemeral ‖ sealing ‖ agreement)`, the
  agent's identity as AAD: 80 bytes. A non-contributory agreement is
  refused.
- **Every new `R` is held aside** by the device that drew it (in its
  archive, never pushed) until the log makes it the kit's: the claim's at
  once; a rotation's and a restore's at their verified maturity; a
  commit's at the agent's verdict confirming it, which is where the agent
  installs the commit's `R2` and moves the kit's reading of the recovery
  scope on. A verdict that does not confirm an epoch this device
  confirmed by its own count with a re-sealing commit (a `Void` the
  operators log) names no `R`, and leaves the device holding none it may
  push under: the agent installed no `R2` for the new one, and the one
  before is the removed device's. So nothing reaches the recovery scope
  under either, and the device's next commit re-seals the kit; the
  `Verdict` alarm tells its user to make one. Each admin call names its `R` by `r_hash` (`NewKit::r_hash`),
  and a device takes an `R` another's archive brings only when it is the
  one the log named last, so `R` travels in archives sealed under an
  epoch's archive key, never under an epoch a removed device was in.
  While the log names an `R` a device does not hold, it pushes nothing to
  the recovery scope; while a removal it honours is owed it lets no `R`
  travel at all, so a rotation maturing before the removal's commit (whose
  re-sealed kit is then the old kit's, taken by neither the agent nor the
  devices) leaves its `R` with no removed device. A device-drawn `R` that
  never reached the others (its drawer lost) is re-sealed by the next
  commit of any device that does not hold it.
- **Every commit carrying a removal re-seals the kit**
  (`Effect::rekey`: the kit's own entries, each with a new `R1`, and the
  new `R2` in the evidence beside any Welcome, `Attached`); the agent
  refuses one without (`Rekey`), and so do devices. A commit also
  re-seals after a kit rotation the kit signed, which leaves no device
  holding its `R`. The kit's sealing keys a device seals to are its own
  knowledge: the claim's, or those a verified rotation or restore
  carried, never the agent's word.
- **Restore:** the fresh install draws the next kit's split
  (`group::restoring`, its `R` held in the store) before the kit signs
  `restore`; once it matured the device reads the previous `R2` and the
  entries it went with (`RecoveryView::previous`), opens `R1` with the
  kit, recovers the archive (`personal::recover`), starts its group
  (`DeviceGroup::restore`, the next kit's `R` the kit's) and takes the
  recovered archive in (`DeviceGroup::inherit`): the old group's naming
  secret kept beside its own, so old scopes keep their ids and new ones
  are named afresh. A restore elsewhere is not built (`open.md`).
- **Liveness:** every device with a voice that reads an open restore
  posts `alive` (`Event::Alive`) until the log cancels it, and shows a
  kit-signed operation for as long as it is open (`Alarm::Kit`); the
  owner then rotates the kit.
- **The kit's secrecy on the phone** [built, `node/light/android`'s
  `personal::Sitting`; E32]: a phrase is shown once
  and two of its words are asked back before the claim goes on (a wrong
  one shows the phrase again). Entered, its words are checked one by one
  against the list in the UI as they are typed (the bad word named, the
  list's own completion row, the keyboard's suggestions and learning
  off), then its checksum. The restore screen takes the kit once a
  sitting: the words, or a security key's `hmac-secret` of the kit's
  salt, are held in `:vos` alone (never the UI's process, never written
  or logged) for the next of its flows (reading the devices, removing a
  lost phone, resolving a contest, opening and finishing the restore), and
  zeroized when the screen closes, when the app goes to the background
  (the UI's stop, and `:vos`'s own background signal), when the UI's
  process dies, at most ten minutes after the entry (a flow still running
  then ends holding none), and when a flow finds
  it not a kit or not this space's. So the kit's secret lives minutes in
  `:vos` instead of one call; a flow outside the restore screen (a
  rotation, an admin key's replacement) still asks for it each time. The
  kind of kit a restore was opened with is kept in the facility's
  database (not a secret) so its finish asks only for the kit itself.
- **Delayed admins:** a delayed admin's inline add is refused; its add
  operation waits the operation delay, then its own commit carries it.

**What the control log shows the operators:** the device count and its
changes, each device's public keys and admin class, the times of
device changes, commits and confirmations, contests, liveness, and the
recovery entries. Not the labels, not the data.

### 3.6 Sealed scopes: storage and sync

**Beside `core-model.md` §9.4's scopes:** a sync scope is either
**plaintext** (as `core-model.md` §9.4 designs it; not built on nodes,
`open.md`) or **sealed**: its
DAG nodes are ciphertext to every node; devices validate and apply; nodes
store, order and serve envelopes and enforce what they can see (who may
push, the epoch, quotas). `core-model.md` §9.4's authorization rule runs
on the devices, against the control log: an author is valid if its sync
key was in the device set (probation, active, or with a removal pending)
when its envelope was accepted, and within its frontier if later removed.

**The envelopes live in the personal agent's replicated tables, written
through its log** [decided]: durable, and each push checked
atomically against the confirmed epoch and the device set. **The API is
blob-ready:** an envelope's id is its hash, `push` returns its position,
`since` returns `(position, id, bytes)`, so moving the bytes into a blob
store later (media) is a node change with no client change (`open.md`).

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
  `cap::REQUEST` (64 KiB, `pvm/abi/src/abi/cap.rs`); larger objects
  are chunked; pushes pipeline, 16 in flight on one channel.

**Seal at push:** a device keeps unsynced operations in its local store and
seals them only when it pushes, under the confirmed epoch read just before;
`Personal::push` refuses another (`StaleEpoch`).

**Sync is a cursor:** the agent numbers each scope's envelopes in the
order it accepts them; `since(scope, position)` returns those after a
position, up to 60 KiB and at least one.

**What a push and a read cost** [measured, `Personal` on the default
agent, x86-64 Core Ultra 7 155H, 2026-11-03]: an envelope is three rows
of its own (its id, author and length; its bytes; its id's position) and
five it updates (the scope's last position, the device's frontier, its
last call, the agent's and the device's usage): 492 bytes of keys and
values beyond the envelope's. A push runs 1.61M gas for 1 KiB, 2.87M for
16 KiB and 6.58M for 60 KiB (the arguments' and the row's bytes at 24 gas
each, and the id's hash), within a handler's default 10M; `since`
answering one envelope 0.47M, 1.06M and 2.79M. Round trip through a node's
socket with the onion's mark, a release build, one node
(`node/host/tests/ingress/personal.rs`): a push about 2.6 ms and a push
with its `since` 2.9 ms for 1 KiB, 3.7 and 4.3 ms for 60 KiB on a quiet
host; 5–6 and 6.4–7.8 ms, 12–17 and 16–19 ms with the host's load average
at 18.

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

**Quotas** (per agent, the space's policy, enforced by `Personal`): bytes
held (8 MiB for a new agent, 64 MiB after its first yearly re-proof, §3.3),
envelopes and commits a day, inbox items.
Admin-signed operations, the commits carrying matured ones, confirmations
and `alive` are exempt, so no device can block its own removal by filling a
quota; each device has an unadvertised share of at most half the agent's
bytes and calls. [built: the bytes held are envelopes' and inbox items';
the calls counted are pushes, inbox items and commits carrying no removal;
the share binds while the agent has a second live device, so a sole
device holds the whole quota.]

**Sealed sync as built** [built, `vos_light::sealed` and
`vos_light::personal`, tested against `Personal` in
`node/light/tests/sealed`; where the text above leaves a choice, this is
the one taken; a pass's times [World]: §6.3]:
- **The envelope:** the header as above; the body framed by its length
  (four bytes) and zero-padded to the frame's Padmé length, the padding
  checked on open; `len_class` the padded length's bit length less one,
  checked against the bytes; the nonce the operating system's. A data
  scope's body is the node's bytes (author, sequence, signature, parents,
  operations), the writer's view `(next index, chain)` and its `seen`
  positions, one a scope it syncs (its cursor), cut to the envelope's own
  scope's when they would not fit. One node an envelope: the largest body
  is 59,388 bytes, and a call takes at most 48 KiB of arguments
  (`MAX_ARGUMENTS`), so every node fits with room for its parents; larger
  objects are the actor's to chunk.
- **Seal at push:** `SealedSync::push` seals each outbox node not yet
  queued under the confirmed epoch, writes the queue (one synced batch)
  and sends it 16 envelopes a round trip; each prefix the agent took is
  marked pushed and leaves the queue in one batch with the scope's
  commit. `StaleEpoch` naming the epoch this device confirmed reseals the
  queue's envelopes of earlier epochs; naming a later one stops the push
  for the log. `Settling` is answered with a `wake` and the rest pushed
  again.
- **The cursor:** `SealedSync::catch_up` reads `since` from the scope's
  stored position, checks each envelope's id against its bytes and its
  header against the scope, opens it under the confirmed epoch's key or
  the archive's candidates for an earlier epoch, and applies the page's
  nodes with its last position in one batch. It stops before an envelope
  of a later epoch (`Waiting::Epoch`: follow the log) or of an epoch whose
  key this device lacks (`Waiting::Key`: read the archive); one that does
  not open under any candidate, or holds no body, is passed over and
  reported with its position (B5). Each opened envelope is checked as
  "Detection as built" below says.
- **The archive** lives in a scope of its own, its id from the naming
  secret (`"vos/personal/archive"`, apart from every instance's
  four-byte name). `SealedSync::archive` reads it from its cursor and
  merges every archive sealed at the confirmed epoch (its chunks
  reassembled and checked against their digest), bounded by what any
  device of the epoch may bring (`DeviceGroup::merge_read`): the keys of
  the epochs before the confirmed one (a device exports the confirmed
  epoch's itself, and no device holds a later one); its `R` only when it
  is the one the log named last (by `r_hash`); and no earlier group's
  naming secret or scope, which come from a device's own restore and
  from a pairing alone. An archive names no author at all. So a device, removed later,
  leaves behind no author or key that outlives its removal (A7) (and a
  device that leaves, its own removal, forgets the archive, `R`'s share
  and every scope key with its store once its follow reads the removal
  through, §3.5 rule 10); unless one
  there encodes as this device's whole archive (candidates are kept in
  order, so equal archives encode alike), it pushes its own, chunked,
  under the epoch's archive key. The committer's push and the push of any
  device holding keys the agent's archives lack (a scope it tracked
  alone, a key it recorded mid-epoch) are one rule. Archives of earlier
  epochs are passed over; a later one holds their keys. `R` travels only
  sealed under an epoch's archive key, and a device takes it only as the
  log names it, so no device of the group can replace `R` for the
  others, and a new `R` reaches no device removed before its epoch.
- **`R` and the recovery envelopes:** `R` is held in the archive (the
  one the log made the kit's last, by log index), set by the claim, a
  rotation, a restore or a commit carrying a removal (§3.5) and carried
  by pairing; `SealedSync::recovery` reads the
  recovery scope for what it holds under `R` and pushes, sealed under
  `BLAKE2b-256("vos/personal/recovery" ‖ R)` at the confirmed epoch and
  chunked as the archive is, whatever of this device's archive is not
  there yet: the naming secret and every scope key, so a confirmed epoch's
  keys, a scope tracked mid-epoch and a key merged from another device's
  archive all reach the kit. Each push is the difference, a few hundred
  bytes an epoch. A new `R` reads the scope again and seals the whole
  archive under it. `open_recovery` is the kit's read: every archive it
  opens there, merged.
- **Tor only:** a `Link` names its `Route`; `SealedSync` refuses a link
  whose route is not the onion, and checks it again before every
  request, so no request to the personal agent leaves over the clearnet
  [E17]. The onion transport is §6.2's.
- **Reads asked ahead** [built, `job::Read`, `AgentLink`]: a pass asks
  the overview and the device set with its first log read, and every
  scope's first `since` page together once the log is followed, each on
  the link's one connection, all in flight at once; each answer is taken
  by the read that asks it in its turn. A call the link sends meanwhile
  drops what it may change (a push every answer but the other scopes'
  pages, any other call every one), so a read is answered as it would
  have been in its turn; an overview asked beside a log page that names
  a head short of it is read again before it counts as a rollback. The
  same queries, under the same key, on the same connection: only their
  order in flight changes. A quiet pass is four round trips after the
  node's time instead of nine.
- **A flow is done at its first complete follow** [built, E33,
  `job::complete`]: a pairing (the joiner's), a commit now and
  a restore's finish return once a follow leaves this device in the set
  and following, its vote on a pending candidate posted (the epoch may
  still wait for the other devices'), the archive and the recovery
  envelopes kept with nothing stale and no scope's reading waiting. The
  extra follows each flow used to make before returning (two for a
  joiner, what is left of three after a commit) run after it returns, on
  one thread of the facility's at a time, each holding the space alone,
  the status read meanwhile answered as the flow left it; an embedder
  other than the facility runs them itself (`Personal::follow_behind`)
  or leaves them to the next pass. One that fails stands as a notice
  (`Pending::Unfinished`) until a pass of the personal space runs to its
  end. A page asked ahead that ends a scope short of where another
  scope's writer said it had read is read once more before the
  partition alarm counts it.
- **Not built here:** re-reading an envelope passed
  over once a later archive brings a key that opens it, and garbage
  collection of covered envelopes and of earlier epochs' archives
  (`open.md`).
- **Known limits found here:** a scope's reading stops for good at an
  envelope of an epoch whose key never arrives, or of an epoch past any
  confirmed one, which the operators can plant (as they can withhold, B1);
  the chrome should show a scope waiting long.
- **`R` rotates at every removal** [built, the owner's decision of
  2026-11-06]: the commit carrying a removal re-seals the kit under a new
  `R` (§3.5, "The kit and its flows as built"), and its committer seals
  the whole archive under it once the agent's verdict installs it. A
  removed device holds the `R` before, so with the operators, who serve
  the recovery scope, it reads only what was pushed there before its
  removal: within D3's limit.

**Detection as built** [built, `vos_light::group` and
`vos_light::personal`, the model test of two devices and a hostile agent
in `node/light/tests/sealed/detection.rs`; where the text above leaves a
choice, this is the one taken]:
- **One key:** a light node's author key is the device's sync key
  (`Light::sync_key`), so a node's author is a device of the set, which
  every reader checks.
- **The log's views:** a device writes the log's chain through each
  entry it reads (`g/chain/`, 40 bytes an entry), so a writer's view
  `(index, chain)` is checked against its own reading at that index; a
  view past its cursor is kept (sixteen at most) and checked as it reads
  on, and raises `View` if the agent's head stops short of it. The caller
  hands the agent's head to `DeviceGroup::head` after reading the log to
  its end: one behind the device's view, or diverging at it, is a
  `Rollback` (B3); one past it is kept, the log read again and the head
  given again (the job does both), and a kept head the log still does
  not reach is entries withheld (`Unserved`), the views and the calls
  past the cursor then counted unreached (`View`, `Dropped`). So the
  operators cannot silence them by naming a head one past what they
  serve. An entry served again behind the cursor that does not
  chain as the device read it stops the reading with `Log` (a fork behind
  the cursor). A view before a paired device's first index passes
  unchecked.
- **Calls the agent drops:** the caller gives each admin call the agent
  took, with its log index, to `DeviceGroup::made`; another entry at that
  index, or a head that never reaches it, raises `Dropped`, and a dropped
  veto holds back the maturity of its operation on this device, which
  keeps its voice (B8): the alarm is the owner's to act on.
- **Each envelope read:** positions are dense, so one skipped raises
  `Withheld` and the reading stops before it (`Waiting::Withheld`), as
  reading past it would leave this device's reading of the scope apart
  from the others' for good; an envelope under an epoch before one the scope already
  showed is a push the agent should have refused (`Stale`, passed over;
  A8, B8); a node whose signature is not its header's author's, whose
  author is no device's sync key, or a removed
  device's past its frontier (the agent's `frontier`, asked once a
  reading), is refused (`Author`; A7, B6), and the removed device's author
  is cut off in the light node one past its node at its frontier
  (`Light::cut_off`), the one place a removed author's cutoff comes from:
  its entries read filtered, and its later operations, met in any ingest,
  are quarantined; a writer's `seen` position in
  the envelope's own scope at or past the envelope's position is a
  renumbering, and each `seen` position of a scope this sync reads is
  kept, so a scope read to its served end short of one raises `Partition`
  (B19). What was read at each position (`s/at/`, the node's CID) is
  written before its page applies.
- **The sample audit** (`SealedSync::audit`, B2): every envelope a device
  pushed is recorded by position (`s/own/`); a uniform sample is fetched
  at its positions, the bytes' hash checked against the id the push was
  answered with, and one gone or replaced raises `Deleted` and its node
  is sealed and pushed again.
- **Checkpoints** are not built (`open.md`): every device reads each
  scope from its start, the author of each node checked and each writer's
  `seen` positions kept, so a scope served short of where a writer had
  read it raises `Partition` once an envelope crosses it, never at a
  pairing or a restore by itself. `Personal`'s `acknowledge` and
  `acknowledgements` and their table are built, with no device calling
  them, for the checkpoints.
- **Known limits:** the frontier and the device set a restore reads are
  the agent's word (B8); a device that cannot follow takes the devices
  added meanwhile by the agent's word (§3.4), and their nodes as authored;
  a consistent partition is caught only once an envelope crosses it (a
  `seen` position, a view); the rows by position and the chain rows grow
  until garbage collection (`open.md`). The callers of `made`, `head` and
  `audit` are the background job's and pairing's; the model test drives
  them.

**PG6's catch-up on the clearnet** (§2.4) [measured, x86-64 Core Ultra 7 155H,
load average 5–11, release, 2026-11-06; `node/host/tests/ingress/sealed.rs`
with `VOS_CATCH_UP_ROUNDS=5`: two light nodes in one device group at
`Personal` on a node, every request through the node's socket with the
onion's mark]: a mebibyte of titles in a fresh scope, read from its start,
every envelope opened and its node applied through the merge entry:
- in 1,000-byte operations: 1,049 envelopes, 1,477,977 bytes (the node's
  framing and the padding 41% over the titles), about 26 `since` pages:
  **0.62 s p50**, 0.66 s p95; its push, one call an envelope in turn,
  4.2 s;
- in the largest operations: 22 envelopes, 1,127,830 bytes: **0.16 s
  p50**, 0.18 s p95; its push 0.15 s.

PG6's limit is 20 s. The device's part alone (`vos-phone sync`, the agent
a stand-in in the process, the same host): 0.32 s and 0.09 s; the phones'
numbers wait for the phone session (`tools/phone/scripts/sync.sh`).
**Over Tor** the reads, not the device, set the time: at §6.3's measured
0.15 MB/s and 0.55 s a round trip, the 1.48 MB of small envelopes take
about 10 s to arrive and their 26 sequential pages about 14 s of round
trips, past the limit. The levers: `since` pages asked
ahead (positions are dense, so a device can pipeline the next pages'
requests), and several operations a node, which cuts the framing and the
envelope count (a push of 1,049 envelopes 16 a round trip is 66 round
trips over Tor).

**Background sync:** a WorkManager job pushes queued operations, posts
`alive` if a restore is pending, reads the control log and each scope's
cursor, applies, and raises a local notification when an operation is
pending. Android runs it late or not at all in the "rare" and "restricted"
standby buckets, after a force-stop until the app is opened, and under some
OEMs' battery managers; the chrome shows each device's last sync and
recommends the battery-optimization exemption, and PG6 records these
cases, which the device-change windows are pinned against (§2.4; §8, D5).

**The background job as built** [built, `vos_light::job` and the
facility's `node/light/android/src/job.rs` with its WorkManager worker in
`:vos`; tested in `node/light/tests/sealed/job.rs` against `Personal` and
in the facility's `tests/job.rs` and `killed.rs`]:
- **One pass** (`job::run`) over a `Control` link (sealed sync's `Link`
  with `log`, `overview`, `devices` and the four posts `confirm`, `nack`,
  `evidence` and `alive`, named, nothing generic), refused before anything
  leaves unless it is the onion's: the log followed from the cursor and
  every vote, evidence and `alive` it asks for posted, `Settling` woken
  through, until it asks for nothing; a quiet home woken (above, "Which
  time each reading uses") and the log read again; the head checked
  (`head`) and the clock against the agent's batch time (one clock alarm
  kept, the latest skew's); each scope pushed (the log
  followed again on `StaleEpoch`) and read by its cursor (the log followed
  where a page waits for an epoch, the archive read where it waits for a
  key, four readings at most); the archive and the recovery envelopes
  kept; one of each scope's own pushes audited (`audit`); the device set
  read. A device stuck or
  out reads the log, the overview and the device set and leaves its
  scopes alone. **A device is removed on the log it verifies, never on a
  refusal** [E41, built]: an agent's answer is signed by
  nobody, so a gateway on the route could make up `NotAdmitted` for a
  live device, and a device that took it as its removal would show a
  removal that never happened. So a refusal (`NotAdmitted`, `Removed`)
  stops a pass as any failure does, the device still in the set, and the
  next pass tries again. A removal that matured while the device was off
  (the kit's, another device's, a regroup, a restore) is read on the
  log: the agent serves a removed device's sync key the log through the
  entry that logged its removal (`Matured`) and on while the entries are
  within the confirming window after its maturity (`Personal::log`, the
  table `gone`), where any evidence the maturity rests on is (a cosign's
  or a resolution's, posted after the call that matured it); the device
  follows it as any device does, verifying each operation's and
  confirmation's signature against the keys its own log gave it (B6), and
  is out (`Course::Out`) once that evidence supports its removal, which
  the chrome shows as removed. Its other reads and calls stay refused,
  and past the window it reads nothing more: the same window bounds what
  any device accepts as a maturity's evidence. The choice over a signed
  refusal: the agent holds no key the operators do not (its state is
  replicated on their nodes, and an actor has no secret of its own), so
  an agent's signature would only be the operators' word, while the
  log's evidence is the user's devices' and kit's signatures, which no
  operator or gateway can make. The cost: a removed device's key reads,
  for good, the log through its removal (for a restore or a regroup, the
  operation that removed it: the restored device's keys, its "home"
  nullifier and label, the new kit's public keys), and up to a confirming
  window past it (an add's keys, nullifier and label, the votes, the
  candidates, `alive`), which before it read none of: a stolen phone
  removed and then replaced learns the new phone's nullifier. A device
  whose removal's maturity the log asserted but whose evidence never
  supported it (a cosign's evidence never posted) stays in the set by its
  rules, and pairs again from a code of its own space
  (`DeviceGroup::removal_unsupported`); a removal pending its delay lets
  no device in the set pair again. The Devices screen's own row says
  removed only once the device is out (`space::Personal::devices`). Nor
  does a removal replayed: a route forking the log a device reads, to log
  again a removal of it once signed and vetoed or cancelled and mature it
  unvetoed, logs a call whose place (§3.5, "The place") is behind the
  device's floor, which the device refuses (`Alarm::Log`), reading no
  further on that log [built 2026-11-20; tested in `node/light/tests/
  space.rs`, a route's `World::relog`]. What a gateway can still do is
  withhold, which any route can: a device that has not read a veto yet
  can be shown the operation without it. A post the agent refuses as held already (`Voted`,
  `Evidenced`) or as decided meanwhile (`NoCandidate`, `NotConfirming`) is
  done, the log read on; a page withheld is read again once. A pass that
  stops on an error hands back what it found (`Stopped`), its alarms with
  it. `made` stays the caller of an admin call's (the chrome's).
- **What it leaves** (`Pass`, `Pass::notices`): each verified open
  operation of the device set with the batch time the log took it when
  this pass read it (what a notification's latency is measured from); a
  pending restore (this device posted `alive`; every other device reads
  the kit's operation, `Alarm::Kit`); its removal and that it cannot
  follow, from its course, at every pass while they hold; every alarm
  kept and not yet acknowledged. **Alarms are rows:** each is written in the batch that
  consumes its evidence (the device group's state, a page's positions,
  a scope's watches), or before the write that does (an audit's push
  again), and kept (`DeviceGroup::alarms`, at most
  64, a flood of one kind evicting only its own) until the chrome, its
  user having seen it, acknowledges it (`DeviceGroup::acknowledge`). A
  pass killed or stopped after the request that raised one, or a request
  the operators fail after it, loses none (B3, B4, B19). `Personal`'s
  `devices` gives each device's last call (`DeviceView::seen`, the `seen`
  table the confirming set is drawn from): each device's last call as the
  chrome shows it ("last call at your agent"), for a device whose sync
  made one (a push, a vote, `alive`); a pass with nothing new makes none
  but a `wake`, which counts no device seen (the confirming set is the
  devices that took part, not those that only read), so a quiet device's
  last call is older than its last sync, and the chrome names it so.
- **A pass killed anywhere** leaves the store consistent: every change is
  one synced batch of the group's or sealed sync's, and every request is
  one the agent answers alike when sent again. The test kills a pass
  before and after each of its requests (a push that had something to
  do, a scope to read), restarts the phone from its store and runs the
  next pass: the phones converge and the agent holds each node once.
- **s4's jobs**: WorkManager's periodic jobs (15 minutes, a network up)
  in `:vos` alone (`setDefaultProcessName`, every WorkManager component
  declared in `:vos`, its start-up initializer dropped from the UI
  process), scheduled when the facility opens, two parts each on its own
  schedule (`job::Part`): each enrollment's tree read from its feed if
  due, and the personal space's pass once the device holds one
  (`job::Personal`; the claim's and pairing's facility operations attach
  it); every connection is a stream of the facility's Tor client,
  counted (§7.3). Each run is kept (the latest 64),
  written as started before anything is sent and as finished after, each
  write whole or not at all, so a run its process's death cut short shows
  as never finished; the device's last sync is the latest finished run.
  Notices are posted as local notifications by every sync of `:vos`,
  alerting once while they stand: an operation while a pass reads it open,
  a restore stopped and an alarm for a week after the pass that raised
  them, unless they are of an operation (the restore, the kit's signature
  on one) a later pass reads open no more, which they go with (one clock
  alarm at a time, the latest skew's), every notice through a pass that
  reached nothing. The chrome asks
  for notifications once the facility keeps something, and recommends the
  exemption (Android's own prompt) when the user restricted the app's
  background work or no run finished for a day since the app was
  installed or updated, at most once a week; opening the app opens `:vos`,
  so WorkManager reschedules the job after a force-stop.
- **After first unlock:** the store is in the app's credential-encrypted
  storage, open from the first unlock after boot whether the screen is
  locked or not; the job uses no key behind a prompt (the member secret's
  and the admin key's prompts are the UI's), and the app is not direct-boot
  aware, so no job runs before that unlock.
- **First numbers** [measured, x86-64 Core Ultra 7 155H, debug,
  2026-11-08; again 2026-11-17]: a pass with nothing new on a paired
  phone, 6 requests and 372 bytes of the agent's answers (the log's head,
  the overview, the scope's and the archive's empty pages, the device
  set), no call and so no session; s4's run with nothing new, one enrollment at a
  stand-in gateway, 2 SSH connections (the time, the root), 5.2 KB down
  and 5.6 KB up, 25 ms. The phones' numbers (PG6's 30 s and 1 MB, the
  recorded cases) wait for the phone session.
- **Two jobs over Tor:** the personal pass runs in its own periodic job
  and its own isolation group (`Purpose::Background`, §3.10: the agent's
  traffic on its own background schedule), so the agent's circuits and
  timing do not ride with every space's root polls.

### 3.7 The inbox

A table in `Personal`, keyed by `(expiry, id)`; **expiry is lazy** (reads
skip expired items, each write deletes a few; no timer).
- **Writers:** the user's devices and a pairing slot's holder. Others'
  messages wait for messaging (`open.md`).
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
3. **The check, before anything is handed over** [decided 2026-11-12,
   built]: the handshake's last message (A's) carries nothing; once it is
   written and read, both devices show a six-digit check derived from the
   whole handshake's hash, and A's user confirms that B shows the same
   before A sends anything more (its offer is the channel's first message);
   declined, A sends its decline over the channel instead (its first
   message there, as the offer would be), which B authenticates as A's, and
   leaves the slot open until it expires, so B can read it (A's next
   offer closes it). A refusal of B's slot reads (`NotAdmitted`, as a
   closed slot's are, and which nobody signs) does not end B's pairing: B
   reads the slot again until its expiry [E42, built].
   Someone who photographed the QR and answered
   first holds a handshake of its own, which A's last message ends: B
   cannot read that message and shows no check. No side has a check before
   that message, which A writes after the one it answers, so no answer is
   ground until its check is B's; the slot grants nothing until the user
   has seen whom it pairs.
4. **Over the Noise channel,** B sends its public keys, the admin key's
   attestation and its KeyPackage; A sends the key archive, the naming
   secret and `R`.
5. **A adds B in one admin call, on one prompt:** for a strong admin an
   add is immediate, so the add and its commit are one call,
   `commit(epoch, add(B's keys, B's "home" nullifier), handshake,
   welcome_hash)` (B computes its nullifier from its own member secret),
   with B's Welcome in the
   evidence call. B is in probation, and reads and writes at once through
   the archive. A delayed admin's add is an operation first and its
   commit, after the 72 h, a second call.
6. **B joins:** it reads each scope from its start (checkpoints:
   `open.md`).

**Memberships elsewhere** (E2: each device has its own secrets):
- **in every space other than the home, at once,** on the pairing's own
  prompts: A calls each registrar's `enroll_device(member(s_B),
  owner(s_B))` under `#[msg(credential = Owner)]`, one proof per space
  (the member secret's per-use prompt, since the keystore's HMAC is per
  handle and per use: a user in eight spaces answers eight prompts, and
  the chrome lets them defer any space), batched over Tor; then B calls
  `confirm_device(member)` under its own owner proof, naming its own
  member digest, so its owner digest acts for the person (B's prompt a
  space, on its own device). Those
  registrars never see the personal agent, so there is nothing to blur;
- **in a home-only space,** B makes no open claim and holds no leaf
  there (E28's joiner's claim, after a drawn delay from its add, is not
  built, `open.md`);
- **in a home that is the user's own space,** the user chooses "now" (the
  default, since §3.10 already concedes the link there) or "at my next
  sign-in".
- The registrar keeps a person record (each device's member and owner
  digests, their count and a per-member limit), which a credential actor
  alone cannot (member and owner digests are unlinkable by design).
  [built] The registrar registers a person's first device with both its
  digests (`register(member, owner, limit)`); from then on the person's
  own devices enroll and revoke its devices by their owner proofs, the
  digests they name refused when any person holds them or when the member
  is enrolled or invited, and B's owner digest acts for the person once
  B's own owner proof confirms it (`confirm_device`, one more prompt a
  space on the pairing's path, batched with A's), so no person takes
  another member's public owner digest (`identity-and-authority.md` §6). The credential
  book's `DeviceHandle` holds each device's member and owner digests as
  the record does, so the device that enrolls or revokes another names it
  from the book. The gate: `node/host/tests/served/credentialed.rs`'s
  `a_second_device_is_enrolled_and_revoked_by_its_first_devices_proof`.
- **`once` scopes** admit one nullifier per device [decided]: a member
  with three devices can vote three times where a space uses `once`,
  which the space's chrome states. A ring of person leaves is later work
  (`open.md`).
- **A person's enrollments are counted** [decided, built]: a device
  revoked and another enrolled is a fresh leaf, so a fresh nullifier in
  every scope, and the limit alone bounds the devices held, not the
  pseudonyms a person makes by churning them. The credential actor counts
  a person's devices of a year of batch time (`ENROLLMENT_PERIOD_MS`), those
  it held as the year began and those it enrolled in it, and refuses
  `enroll_device` past its limit and `REPLACEMENTS` (2), `Enrollments`,
  until the next year or the registrar's `reset`. A year is the home's
  span between re-proofs (§3.3), and two replacements a year are a retired
  phone and a lost one, where the usual replacement is every few years
  (below); a user past them asks the registrar, as a user with no device
  left does. So a `once` scope within one period admits a person at most
  its limit and two times, one spanning a period's end at most twice its
  limit and three, and a home that is the user's own space hands it at
  most its limit and two agents a period (§8.2 B13). The registrar expels a person whole
  with `revoke_person`, every device in one write
  (`identity-and-authority.md` §6). The gates:
  `agent/testkit/tests/agent/credentialed.rs`'s
  `a_persons_device_churn_is_held_to_its_enrollments_of_the_period` and
  `agent/testkit/tests/agent/homes.rs`'s
  `device_churn_takes_no_more_agents_than_the_persons_enrollments`.

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

**Pairing, the claim and memberships as built** [built, `vos_light::
pairing`, `vos_light::home`, `vos_light::memberships`; tested against
`Personal` in `node/light/tests/sealed/pairing.rs`, and end to end on three
nodes through their sockets with the onion's mark in
`node/host/tests/served/personal.rs`, at a test home of seconds and an open
claim's difficulty of 4; where the text above leaves a choice, this is the
one taken; times [World]: §6.3]:
- **The claim at a home-only space** (`home::Claim`): the open claim's
  terms (`opening`) and the agent `Homes` answers `pooled` for asked
  first, the two a home can refuse before anything is shown; then the
  kit shown, and while the user writes it down the device's open claim
  (its work, then `claim_open(member, nonce)` in a session of its own,
  its key drawn for that call alone), the home's tree read from its
  feed, the node's time read on a fetch of its own and the proof's
  connection opened ahead, one at a time, each after a pause drawn below
  4 s, as a session's spares are built; then the claim of that agent,
  sealed to its identity (§3.3, "The device names the agent"), with a
  phrase's or a security key's kit or both. The proof's expiry is the
  fetch's reading moved on by the monotonic clock (five minutes at
  most, read again past it or past a step of the device's clock), never
  a time taken before the kit; the tree's root read meanwhile is proved
  on while half its grace (`ROOT_GRACE_MS`) has not passed since, else
  the feed is read on, each page's expiry from the feed's own reading (one
  round trip). A home that refuses the open claim or the claim once the
  kit was shown voids that kit: the claim is abandoned and new words are
  shown with the reason ("the words shown before are void"), at most
  three kits; one unreached keeps the claim and its kit, as a retry
  sends it. The claim (the device, the kit with `R2`, `R`, the
  agent) is held in the store from before its call until the device's
  group starts from the agent's log (`Claim::claimed`, the `R` the kit's
  from the `Assigned` entry), so a retry after a lost answer sends the
  same claim, which `Homes` sends again; a refused one is abandoned and
  the device seals to the next agent. **A second claim is refused** at the
  device (`ClaimError::Held`) when its store holds a personal space's
  archive (a group, a restore's drawn `R`, an earlier group's keys) or a
  claim waits, and at `Homes` for a nullifier recorded (`Claimed`).
- **The QR code** (`pairing::Code`, a version byte then its encoding):
  the home's handle and onions, the agent, its identity and `Personal`'s
  instance (the joiner reaches the slot through them), the slot, the slot
  key's seed, its expiry, the handshake's first message and the 128-bit
  code. The opener is the Noise initiator, so its first message (its
  ephemeral key and its empty payload's tag, 48 bytes) is in the QR. The
  pre-shared key is `BLAKE2b-256("vos/personal/pairing/psk" ‖ code ‖ slot
  ‖ agent)`, the prologue the agent and the slot; each side's Noise
  static key is drawn for the pairing, the pre-shared key authenticating
  both.
- **The messages** go as inbox items to the slot, each id
  `BLAKE2b-128("vos/personal/pairing/item" ‖ slot ‖ side ‖ n)`: the
  joiner's second message, the opener's third carrying the `Offer` (the
  home as `home::Home`, and the memberships to enrol it in), the joiner's
  `Hello` (its `NewDevice` with its "home" nullifier from its own secret
  there, its key package, its handle in each offered space), the
  opener's handover (the `Pairing`, its archive with the naming secret and
  `R`) in as many items as the
  policy's item size takes, and the joiner's acknowledgement by the
  handover's hash: three items of the slot's four. **The commit waits for
  the acknowledgement**, since the add closes the slot and deletes its
  items. Each side lives in memory: a pairing cut short is started again
  from a new slot, the opener closing the old one and abandoning the
  commit `pair` held (`DeviceGroup::abandon`). *Known limits:* the
  pre-shared key enters at the third message, so a joiner holding another
  code fails at the offer and the opener hears nothing until the slot
  expires; a delayed admin's pairing (its add an operation, its commit
  after the delay, past the slot's life) is not built: `pair_offer`
  refuses on a delayed admin (`Error::DelayedAdmin`) before a slot opens,
  and a strong admin's device pairs it, `pair` making a strong admin's
  inline add; the identity a claim's kit is sealed to is
  the answering node's word, so the device asks a second node.
- **Memberships** (`memberships`): once the agent took the commit adding
  the joiner, never for a pairing cut short, the opener holds an
  `Enrollment` a membership (by its space and handle), from the hello's
  handles, until it is made (`enroll_device` under its owner proof) or
  dropped, so the chrome defers any space; the joiner
  holds a confirmation a space (`confirm_device` under its own owner
  proof, once its leaf is there). The memberships offered, and a retired
  device's revocations (`revoke_device`), come from the credential book's
  handles (`memberships::handles_of`); the opener records the new
  device's handle there once its add is confirmed (`memberships::record`).
  The registrar registers a person's first device (`register`) as it
  enrols the member, its own call; the light node calls none of the
  registrar's role methods.
- **The joiner's open claim** is not built (E28, `open.md`):
  only the claiming device makes one (`home::open_claim`, its own work, as
  its claim's membership); a joiner records its "home" nullifier at its
  add, computed with no proof, and holds no leaf at a home-only home, so
  it proves nothing there. At a home that is the user's own space it is
  the opener's enrollment there, as in any space.
- **Retiring a phone:** the successor paired from the old phone (offered
  the old phone's memberships), then the old phone's removal by the other
  devices as §3.5's rules time it, carried by the next commit; the old
  phone, relayed the log, sees `Event::Removed`, which is where the app
  offers to wipe it; its leaves revoked in each space its handles name.
- **The yearly prompt** is not built (E15, `open.md`): no device proves
  `renew`, so the lease runs 13 months from the claim; "Commit now"
  renews the device's leaf.

### 3.9 Home spaces: several, and moving home

**Several homes** [decided, E8: allowed, one built]. Exactly one home
orders the group; a second home mirroring the first, and a live handover,
are later work (`open.md`).

**Moving home** (the home vanishes, turns hostile, its lease lapses, or
the user wants out): devices are full replicas, so nothing is lost but the
agent. A device claims an agent in another home, creates a new group,
re-splits the kit (a new `R2` at the new agent) and writes the books
again there (below); the other devices pair again by QR. Until the move completes, the kit opens nothing
at the new home. The old
operators keep what they held; deletion there cannot be verified.

**Moving home as built** [built, `node/light/android`'s `move_home`;
host-tested in its `tests/personal.rs` and `crashes.rs`; nothing is
carried; where the text above leaves a choice, this is the one taken]:
- **Valid only while the personal space holds the credential book and the
  device book alone** (§3.1), which every device writes again from what it
  holds: a move drops the scopes' history at the old home. A local actor
  whose rows no device writes again (a wallet's) needs the carry back
  before it is installed in the personal space (`open.md`).
- **Leave, claim, pair again:** the mover checks that the new home's
  `Homes` has an agent to give (`pooled`), leaves its personal space with
  no call to the old home (`Space::leave`, §7.3: the light node's store
  made anew, its sync and admin keys new), then claims at the new home as
  a first claim does (§3.8): its open claim there, a new kit split at the
  new agent, its own group alone. Each other device leaves and pairs
  again by QR from a device at the new home (its pairing leaves at the
  offer, §7.3), its handles in the other spaces kept (the offer names
  none), and writes its book rows again there.
- **An interrupted move** is called again: killed before its leave, it
  leaves then; killed after, the device holds no personal space and the
  move is a claim; once claimed, it is refused as at that home already.
  A move to the agent the device has is refused the same way.
- **What the old home keeps:** what it held, for as long as its operators
  keep it: the control log, each scope's ciphertext, the recovery
  envelopes and the old kit's entries. The moved devices are never
  removed there. Its lease lapses 13 months after its claim, then refuses
  pushes and serves reads and a restore for the 180 days' grace
  (B14); reaping is later work (`open.md`). An old kit kept across the move still
  restores there, and reads the history to the move.
- *Known limits:* each scope's id and a reused kit's index at `Homes` are
  the same at both homes, so the two homes' operators together link the
  two agents (each device's sync and admin keys are new); a device that
  missed the move reads on at the old home, no notice telling it of the
  move, until its user pairs it again; the old home's `Homes` keeps the
  moved devices' nullifiers until its lease lapses.

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

## 4. One proving path

### 4.1 Why one path

The credential AIR, format 44, proved auth, owner and the joint statement
in 0.16–0.18 s on the Fairphone 6, with proofs of about 0.2 MB verified in
about 2.0 ms [measured, as `proving.md` §8 and `node/SECURITY.md`
recorded it before the format's deletion]. It was a hand-written circuit
over the recursion AIR's `p2` and `qm31`: every statement change a circuit
change, a re-pin and a new fixture. It is retired [decided, E1], and every
device statement is a device kernel [built: the stock kernels prove auth
and owner]. Kept: the recursion AIR's `p2` and `qm31` (the folds and the
wrap use them); the Poseidon2-M31 compression, `0x402` and its chip; the
credential actor and its tree; `H_io`; the device format and its chips.
The light node links the zkVM and its masking without the recursion's
leaves, folds and wrap (§7.1).

### 4.2 Every device statement a kernel in an actor

Sign-in, ownership and spending are `#[attestable(device)]` methods,
each a short Rust function in the actor whose state it concerns:
- **auth** and **owner** in the credential actor (`vos-credentials`), the
  stock kernels every space gets with it;
- **spend** and **join** in the payments actor, with P2 (`open.md`, E13);
- any actor's own, under the same rules.

```rust
// vos-credentials, beside the tree it proves membership of [built], each
// sized on its reference run.
#[attestable(device, reference = reference::auth)]
pub fn auth(path: &Path, secret: &Secret, #[public] claim: &AuthClaim) {
    let member = Tag::Member.hash(secret);
    assert_eq!(path.root(&Tag::Leaf.hash(&member)), claim.map_root);
    assert_eq!(Tag::Nf.hash(secret).hash(&claim.scope), claim.nullifier);
}

#[attestable(device, reference = reference::owner)]
pub fn owner(secret: &Secret, #[public] claim: &OwnerClaim) {
    assert_eq!(Tag::Owner.hash(secret), claim.owner);
}
```

Each claim struct ends with the call's `binding` (§4.3), which the kernel
carries without reading, as auth's does today.

**High-level code at the lean kernel's cost.** The `device` test actor's
auth kernel takes 1,722 steps because it is written by hand: arguments
decoded in place by `InPlace`, word loads through inline assembly, the path
walked in one lane (`agent/test-actors/device/src/lib.rs`); the same
statement written plainly took 18,733 steps [measured, `proving.md` §8],
about ×11, which the cell model puts at about 3 s on the phone [model].
The tricks are in the SDK [built], so the code above is what a developer
writes (the stock `auth` and `owner` above):
- **in-place arguments by the macro:** a device kernel's arguments by
  reference, `&T` with `T: vos_sdk::p2::InPlace` (`Digest`, `[T; N]`,
  `Path`, integers, and `#[derive(InPlace)]` `#[repr(C)]` structs of them
  with no padding), come first and are read where the witness input left
  them (`vos_sdk::p2::in_place`: the bounds and the alignment checked,
  never a copy); the macro refuses one after an argument by value, since
  each in-place size is whole words and the first lies page-aligned. A
  `Digest` is 8-aligned, so the code moves it as four plain `u64` loads
  and stores. The device argument layout is the arguments' in order, a
  `Path` its 32 siblings then its slot as eight bytes (1,032 bytes), and a
  claim its digests alone: the stock kernels' claims carry no kind byte,
  the guard naming the kernel (§4.3);
- **`vos_sdk::p2`:** `Digest`, `Tag` with `TagHash::hash`, `Digest::hash`
  and `Path::root` over `0x402`, written once, lean (the lane walk with
  selects, no branch on the slot's bits, a digest's equality by every word
  without an early exit), and shared by every kernel and by cipher-clerk
  through its hash trait (`open.md`, "Private payments"). Its unaligned
  word accesses (`load_u64`, `store_u64`, for a public argument appended
  to the device's return) are plain `read_unaligned`/`write_unaligned`;
- **word loads from the compiler:** the guest target is built with LLVM's
  `unaligned-scalar-mem` feature (`pvm/guest/riscv64em-vos.json`), so an
  unaligned `u64` load is one `ld` (the PVM serves unaligned accesses;
  without the feature the target's unaligned reads go byte by byte);
- **the gate** (`device_kernel::sdk_form_kernels_run_within_the_lean_kernels_steps`):
  the SDK-form kernels within 1.15× the hand-lean kernels' steps. **Met**
  [measured, step counts of the traced run on the host, Intel Core Ultra 7
  155H, 2026-11-02]:

| kernel | the target before the feature | with `unaligned-scalar-mem` | and the SDK's words as plain accesses |
|---|---|---|---|
| auth by hand (`device`) | 1,722 | 1,635 | 1,624 |
| auth in SDK form | 1,839 (×1.068) | 1,770 (×1.083) | 1,710 (×1.053) |
| owner by hand (`owner_lean`, over `p2`'s call and word accesses) | 708 | 639 | 604 |
| owner in SDK form | 708 (×1.00) | 639 (×1.00) | 619 (×1.025) |

  The SDK-form auth's device program has the hand-lean one's log sizes
  (the CPU at 2^11 rows, the memory ledger at 2^14) and its proof the same
  size, about 0.88 MB; owner's CPU sits at the 2^10 floor, its proof about
  0.85 MB [measured, the same host]. Its extra steps (about 117) are the
  in-place checks and the digests copied once more into each call's block
  where the hand-lean kernel computes into the lane. With the target
  feature and the SDK's plain accesses, the SDK-form auth (1,710) runs
  under the hand-lean kernel on the target before the feature (1,722). So **the
  SDK-form kernels are the stock ones**, and the hand-lean kernels
  stay as the test actors' references; the fallback (the hand-lean
  kernels shipped as stock, the assembly kept inside `vos_sdk::p2`) is not
  taken.
- **The device end inlined** [measured, step counts of the traced run on
  the host, Intel Core Ultra 7 155H, 2026-11-03]: a crate with several
  device kernels, or a kernel and its reference entry, called
  one outlined `DeviceReturn` end and its part writers. With them
  `#[inline(always)]`, on the target before the feature, the SDK-form auth takes 1,546
  steps (from 1,839) and owner 385 (from 708, `owner_lean` 383); the
  hand-lean auth stays at 1,722. The programs shrink with them: the SDK
  form's auth at the hand-lean one's sizes but one chip a size smaller
  (2^12 rows where it had 2^13), owner two chips a size smaller; proofs
  about 0.88 MB and 0.85 MB as before. The stock kernels in the credential
  actor are these.
- **The transpiler and `unaligned-scalar-mem`** [measured, 2026-11-02, on
  a side branch]: LLVM emits plain misaligned `ld`/`sd`/`lw`/`sw`
  where it emitted byte loops, and the transpiler takes them: the test actors,
  the default agent, the representative and the credential actor rebuilt
  with the feature (every one of their ELFs moves), the SDK's and the
  node's suites (`vos-sdk` through `vos-scale`, about 740 tests) pass but
  for the pinned program ids, which move as expected, and one timing test
  that passes alone; the proof crate's kernel tests pass through the
  device kernels, the balance kernel and the fixtures, the pinned
  constants again failing as expected. The step counts above come from
  it.

### 4.3 What the node checks at ingress

**Credentialed calls generalize to proven calls** [built,
`identity-and-authority.md` §5, `node/SECURITY.md`]. A credentialed call
carried a statement's kind and its public words, and a format that
picked the circuit; a proven call carries the kernel's claim:
- **The request** keeps kind `0x0104` and its envelope (instance, method,
  arguments, nonce, expiry, format, proof) and replaces `public:
  CredentialPublic` with `claim: Vec<u8>`, the kernel's public arguments
  in their SCALE encoding. The format is a device format the node admits:
  47 alone by release (§4.4).
- **The guard names the kernel:** `#[msg(proven = spend)]`, naming a
  device kernel of this actor. `#[msg(credential = Auth("login"))]` and
  `#[msg(credential = Owner)]` name the stock kernels, so purses-style
  code reads as it did: the stock auth kernel's scope needs the guard's
  name, and one spelling serves both. `proven = auth` and `proven = owner`
  are refused, naming that form, unless the actor has its own kernel of
  that name, whose name comes first [built].
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
    pool's anchor in its ring and its nullifiers unseen, `open.md`'s
    P2). There is
    no pre-check at ingress: that would need a host-to-guest entry point
    run on an executor before the verification slot, a new cost an
    attacker chooses. A proof for a spent nullifier therefore costs a
    verification, bounded like any other by the PoW and the budget;
  - `once` is defined for auth's guard alone.
- **The origin** a proven call logs: `Anonymous { scope, nullifier }` for
  auth, `Owner(digest)` for owner, and `Kernel { program }` for any other
  kernel (codec index 7; `Identity` 5 and `Jam` 6 reserved; not "Proven", which
  `Input::Proven`, index 9, already names). **The log carries the claim:**
  `Input::Credentialed` (index 10) takes the claim's bytes, capped (1 KiB,
  a spend's about 240), in place of auth's `root`, since apply's freshness
  check and the handler's typed argument both read it; a log entry grows
  by at most the cap.
- **Verification cost and denial of service:** a device proof verifies in
  about 11.7 ms on one quiet x86 core [measured, `node/SECURITY.md`],
  about six times a format-44 proof's 2.0 ms. **Profiled** [measured,
  Intel Core Ultra 7 155H, one thread, load average 7–21, 2026-11-06;
  `cargo run --release -p vos-phone --example verify_cost`]: the
  verifier's setup, the program's masked format and layout computed per
  proof, took 6.6 ms, and the canonical decode 4.2 ms, of which the
  re-encoding 2.5 ms; a wrong interaction PoW was refused after both. So
  the masked format is computed once (the layout, cheaper, still per
  proof), when a program is installed or pinned,
  and a **pre-check** before the decode reads the proof's leading fields
  (its format, its interaction PoW, its claimed sums, its configuration
  and its roots) and checks the interaction PoW over the program, the
  first two roots and the io-hash, as the verifier's transcript mixes
  them [built]: a wrong interaction PoW, a main root changed, or an honest
  proof sent against another claim's io-hash is refused in 0.017 ms at
  the median and 0.021 ms at the 95th percentile, within the 1 ms
  target. The format allows no more: its interaction PoW is 8 bits, so
  junk ground for 2^8 nonces passes the pre-check, and the next check it
  cannot meet cheaply, the 16-bit PoW, comes after the decode and the
  composition (11–27 ms by the load). A heavier interaction PoW is a
  format change (`open.md`). The levers of §4.4 shrink the columns the
  verifier reads and so its time. Over Tor, the gateway's onion-service
  defences replace per-address limits (§6.6).
- **The binding sweep's budget** [built]: the bindings' due rows are an
  index of their own, so due bindings never hold a session's or a
  workflow's row back, and a batch runs at most 64 proven calls
  (`defaults::BATCH_CREDENTIALED`, refine's rule; the leader holds the
  rest for the next), as many as a sweep forgets, so the sweeps drain
  bindings as fast as batches record them.

### 4.4 The program-id model, and the cost

**The device program** [built, `proving.md` §8] is computed from the installed kernel
alone: its chips (what its code reaches), each chip's log size from a
reference run, and the preprocessed root over its code, data, regions,
permissions and entry registers; its id the BLAKE2b-256 of a domain, the
format, the chips, the sizes and the root.
- **The reference** [built]: `#[attestable(device, reference = path,
  headroom = k)]` names a function returning the kernel's message, its
  reference arguments (a public, valid witness: the credential kernels'
  is `vos_sdk::p2::reference`, a fixed public secret's member at slot 0
  of the empty tree; later the pool's spend's). The macro refuses a device
  kernel without one. It generates an entry, `__vos_reference_<name>`,
  whose run returns the message's encoding, and the derivation links it
  as a **reference program** beside the kernel
  (`Derivation::references`: the method, the program's hash, the
  headroom), refusing a device kernel without one. A device kernel's
  **release** is the three (`DeviceRelease`: kernel, reference,
  headroom). The install computes every device kernel's program from its
  release (`vos_pvm_device::Program::from_kernel`: the reference run, then
  the kernel's run on its output), refusing the install when either fails;
  a replica that did not install computes it from the stored blobs at the
  first proof or window read naming it, once a release.
- **Sizes and witnesses:** every chip is padded to the program's sizes, so
  a proof's shape is the program's whatever the witness. A witness whose
  run needs more rows than the reference's fails to prove (an error on the
  device, never a different proof shape); branch-free kernels avoid it,
  and a kernel that branches declares `headroom = k` (each size raised by
  `k` powers of two, `k` at most 4). `device_fits`
  (`Program::fits`, and the proof crate's
  `random_witnesses_fit_the_reference_programs`) runs random witnesses of
  the stock kernels and of the hand-lean `auth` against their references'
  sizes [built].
- **Computed at release, on the phone never** [built: the release build
  and the device's side; the facility embeds them from this tree's
  guests (`just facility-release`, held by its `tests/release.rs`)]: the
  release build computes each device kernel's program
  from the package's ELF as a node's install does
  (`vos_light::release::devices`), the stock kernels' among them, and the
  app embeds the artifacts (`release::Release`, `vos_pvm_device::Release`: the kernel, its chips and
  log sizes, its id, the ELF's hash) beside the local actors' packages
  (the phone bench's `kernel` command takes one, `tools/phone`). The phone
  runs no transpiler and no reference run: it commits a program's
  preprocessed tree from its artifact and checks the id
  (`DeviceProgram::from_release`). "Reproducible" reduces to the app and the
  space taking the same release artifact, the ELF, by its hash: the
  space's window names the ids the app's artifacts name (the window
  test checks it; the guest blobs are path-independent, `blobs.lock`).
- **Which kernels see a secret** [built]: the light node puts a member
  secret (and, with P2, a spending key) only into kernels it ships, whose
  programs it embeds: the stock `auth` and `owner` (and with P2 the pool's
  `spend` and `join`, from its own build of cipher-clerk's
  `shielded::check`, `open.md`). It proves one of them
  only under a program id its compatibility window admits (below). A
  kernel whose bytes a space serves may take only the user's public data:
  otherwise a space could install a kernel whose public claim is the
  secret itself (§8, G2). So a developer's own device kernel proves over
  public data and over data the user explicitly hands it, never over
  keys; a consent model per program id is later work (`open.md`).
- **Compatibility windows** [built]: so that an app release and a
  space's upgrade need not land on the same day, each guard naming a
  device kernel (the stock kernels' among them) admits a **window** of
  programs, at most two: its release's and the previous one's; ingress
  admits the device formats likewise (at most the current and the
  previous). A program id embeds its format (§4.4), so a previous program
  is only ever verified under the format it was computed in.
  - **Where a window lives:** the installed record
    (`Installed::previous`, one a device kernel, pinned with the
    instance's programs). An install that replaces a device kernel's
    release keeps the replaced one as its previous release, retiring 60
    days after that install's batch time (`RETIREMENT_MS`); one that keeps
    the release keeps the previous one it had; nothing older is ever
    kept, so no version table grows.
  - **How a window ends:** at its date, by the node's clock, ingress
    and the window read stop admitting the previous release, and the next
    install or retirement deletes its entry. The operator may set any
    earlier date, **now** included, when a version is found unsound
    (`Kind::Retire`, `Admin::Retire`, through the agent's log, so every
    replica agrees; `vos agent retire`); a date is never moved later. The
    proven input carries the release its proof was verified against, and
    apply refuses one its kernel's window no longer holds by the batch's
    time (`Refusal::Release`), so a replica behind the retirement, whose
    ingress still admits the release, runs nothing of it
    (`a_retired_release_is_refused_at_apply_behind_a_lagging_replica`).
  - **The formats' window** is the release's, held at apply: the device
    formats its binary verifies, at most two, the previous one retiring at
    the date its release set (60 days after the release that brought the
    next), or any earlier date the operator sets in an agent's log
    (`Kind::Retire`'s `Format` for that agent, `Admin::RetireFormat`, so
    every replica agrees and a restart keeps it; one call for each agent
    that takes proven calls). The log never retires the release's newest
    format (`Forbidden`): its date is never moved later, so the agent
    would admit no proven call until a release with a newer one; a node's
    own configuration still retires it at that node's ingress. With one
    format in the release (47) the log's retirement is reachable only
    once a release brings a second. A proof of a retired
    format is refused `Format` at ingress before anything is decoded, and
    the proven input carries its format, so apply refuses it on every
    replica too (`Refusal::Format`): a node whose configuration admits
    more or fewer, or retires earlier (`Config::device_formats`, a test's)
    only changes what its own ingress takes,
    never what the space runs [decided].
  - **The proof names its program:** ingress computes the binding under
    each program the window admits, and the request's binding must be one
    of them; a proof of a retired or unknown release is refused
    `Binding`, at no verification's cost.
  - **The light node reads the window first** (`Kind::Devices`: the
    formats and each device kernel's programs, ids, formats and dates) and
    proves with the newest program it ships that the window holds, in a
    format it holds (`vos_light::choose`, `wire::devices_request` [built];
    the facility's sign-in and payment read it before their prompt, over
    `Fetch`, the window of the space's credential actor, whose methods the
    stock kernels are, kept ten minutes while it admits the app's programs [built,
    2026-11-18]). When the space admits none it refuses before any prompt,
    use of the secret or proof (`DeviceError::Window`: "the space admits
    none of this app's programs: the app or the space must update"); a window
    a node could not compute whole yet (a blob it does not hold) is marked
    `unavailable`, and the app asks again rather than saying either side
    must update. An app ships its release's artifacts, one per kernel
    (the facility's `release/`) [built]; shipping the previous release's
    beside them, so an app outlives a space's move to the next one, is
    not built (`open.md`).
  - **One claim per window:** two versions in one window must compute
    identical claims (auth's nullifier, owner's digest) with identical
    meaning, so a `once` scope admits a member once whichever version
    proved, and pseudonyms do not change at a release. A kernel whose
    claim changes is a new guard name (a new scope), never a window
    member. The window test signs in through a `once` guard with release
    one's proof and is refused `Once` with release two's: the same
    nullifier (`an_app_one_release_behind_signs_in_until_its_window_closes`).
  - **A release's program in each format admitted** [built]: a node
    computes each window entry's program in every device format it
    admits now, so the window read names each release's program once a
    format (a program id embeds its format) and a proof is verified
    against the release's program in the proof's own format. An app one
    format behind proves the same release in its format until that
    format retires. Format 47's release admits 47 alone; 46 is retired
    and deleted (its byte ledger was not consistent, `open.md`). A
    node's configuration can admit a second device format
    (`Config::device_formats`, a test's: the gate
    `the_previous_device_format_is_admitted_until_it_is_retired` runs a
    proof of the test format 48, `vos_pvm_device::TEST_FORMAT`, and a 47
    proof at one node, refuses the 48 proof `Format` once 48 is retired,
    and has the light node choose 47 where both are admitted and 48 where
    48 alone is).
- **Pins:** the binding names the program id, so a proof of one kernel
  authorizes nothing under another. No venue pins device ids (device
  proofs are not folded, `proving.md` §11, "Device proofs are not
  folded").

**The cost.** Format 47 holds both levers, the per-program CPU and
word-level memory [decided]: both change the AIR, so they came as one
device format, with one re-pin of the device programs. Their cells on the
stock kernels, each measured as a candidate first (`proving.md` §8): the
per-program CPU −9.5% (auth) and −7.8% (owner), word-level memory −19.3%
and −7.3%, the two together −28.8% and −15.1%, against the model's −8.8%,
−17% and −26% for auth; peak −45% and −35% together [measured, x86 dev
machine, 2026-11-09]. The Fairphone 6's figures at 47 are not yet
measured (`open.md`, "The phone gates not yet recorded as passed"); the
Pixel 1's are `proving.md` §8's. PG2′'s gate is 0.65 s with 0.55 s the
target (§2.4), against format 46's 581–645 ms for a sign-in [measured,
`proving.md` §8]: the model's 450 ms with both levers scales a 607 ms run,
and from the 645 ms gate run it is about 478 ms, so 0.5 s would leave a
4% margin.
- **The price of one path:** a sign-in costs about 3.5× the retired
  credential proof in time and 4.5× in bytes, payment authorization about
  2× in time; within the owner's requirement (`proving.md` §1: under a
  second on a 2023-or-later phone).
- **Not the node's segment format:** a new segment format means a new
  leaf, new folds and a new wrap, and new venue and `MANIFEST` pins, far
  more than a re-pin. The per-program CPU for node segments is later work
  (`open.md`, "Proving").

## 5. Payments as the showcase

Payments show how far plain attestable Rust carries a system feature: a
short actor on cipher-clerk (VOS pins its tag `v0.3.0`), whose
authorization is the stock `owner` kernel proved on the phone. P1, the
pseudonymous ledger, is built on cipher-clerk v0.3.0's L0 kernel, which it
needs as it is; P2, the shielded pool and the wallet, and cipher-clerk
v0.4, which only P2 needs, are designed in `open.md`, "Private payments
(P2)" [decided, E13, E18].

### 5.1 The shape

**P1, pseudonymous:** `Payments` is cipher-clerk's
L0 kernel in an actor, its user accounts held by `Owner` digests,
`transfer` under `#[msg(credential = Owner)]` proved by the stock
`owner` kernel. It replaces the `purses` test actor (a hand-rolled
ledger) with cipher-clerk's, and keeps today's privacy: a public payer,
amounts and payees in clear to the operators, custodial `rekey`.
Accounts are per owner digest, so per device (E2): a payment comes from
one device's account, and moving funds between one's devices is a
transfer the operators see linking the two (§8, L4).

### 5.2 P1 as built

[built, `agent/payments`]: one journal and currency; each account
named (its handle for a payee, kept in its row's `user_data`) and held
by one owner digest, opened by an operator's invitation of the name and
the digest; `transfer(to, amount)` pays from the account of the digest
the proof states, so a payment names no payer; `mint` credits from the
space's issuance (a debit-normal account whose owner, like the
journal's registrar, is a non-canonical digest no proof states);
`rekey` moves an account to a new digest and lifts a `freeze`; a
payment to oneself or of nothing is refused; a device reads its own
account by its digest (`held`), and an account's digest and balance are
readable by the agent's callers, as the log's readers see them. The
facility proves with the stock kernels' release artifacts it
embeds, never a kernel a server sends (G2), so the s4 demo signs in by
the stock `auth` kernel alone.

## 6. Tor via arti

From the research of 2026-11-02; each claim's source is in §9, and
"unverified" marks what could not be read first-hand (the Tor Project's
GitLab refused the fetches).

### 6.1 Where the onion service lives: the gateway

**At the gateway, in process** [decided; the owner: "arti could be
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
futures and tokio. **The onion serves SSH, and nothing else** [decided,
E23]: on port 22, the same `s4-server` handler its TCP port runs, with its
`vos-api` subsystem relaying the node API's frames. HTTP stays the
clearnet's.

**What hosting takes in arti-client 0.47** [measured, a spike gateway,
2026-11-02]:
- `launch_onion_service_with_hsid` sits behind the `experimental-api`
  feature as well as `onion-service-service`, and it refuses a nickname
  whose key the keystore already holds. A restarted gateway launches with
  `launch_onion_service`, which takes the stored key: the gateway inserts
  its key once, and arti's keystore in its state directory holds it after
  that.
- The stream types: `RendRequest`s through `handle_rend_requests` give
  `StreamRequest`s whose `request()` is a
  `tor_proto::stream::IncomingStreamRequest`; a `Begin` to port 22 is
  accepted with `Connected::new_empty()`, anything else refused with
  `End::new_misc()`.
- **No loopback carrier:** through a loopback listener every onion
  client would arrive from 127.0.0.1, sharing one address's limits, and
  the gateway could not mark a request as onion-borne; s4-server serves
  any `Listener` (russh's `run_stream` takes any `AsyncRead +
  AsyncWrite`), so the gateway hands it each stream, marked and under
  §6.6's limits ("Built", below).
- Seen from a client, an arti-hosted onion showed no difference from a
  C tor-hosted one [measured, x86, 2026-11-02, n = 20 each]. Isolated
  connections from one warm client to the spike's onion took a median of
  4.6 s (p95 12.3 s, 0 failed); to the Tor Project's C tor-hosted website
  onion, 5.0 s (p95 8.0 s, 2 failed). The descriptor publisher reported
  `DegradedUnreachable` after one HsDir upload timed out, stayed in that
  state for the whole two-hour session, and kept serving.

No third port carries raw node-API frames. **The light node speaks
`vos-api` over SSH over the onion,** as s4 does today, and the subsystem's
relay set (`NodeKey`, `Time`, `AgentInfo`, `Schema`, `Devices`, `Query`;
`node/api/src/lib.rs`, `Kind::relayed`) gains `Call` (the personal agent's
pushes, commits and device-set operations, and member calls) and
`Credentialed`, with the gateway's leader-aware routing behind them.
- **`Credentialed` is capped:** behind the node's in-flight cap on large
  requests, a cap per SSH connection, per circuit and per onion. Tor
  itself bounds a flood of well-formed junk proofs (about 1 MB each) to far
  below a node's verification budget, and malformed short ones fail their
  decode in microseconds. The pre-check refuses well-formed junk whose
  interaction PoW fails in about 0.02 ms; junk ground for its 8 bits
  costs the node the decode and the composition (§4.3) [measured]; a flood
  through Tor is bounded by Tor itself below the node's budget, measured on
  a private Tor test network (§6.6).
- **One SSH connection per isolation group** (§6.2), each authenticated by
  an SSH key drawn for that connection alone, so the gateway cannot join
  two groups by their SSH identity; the `vos-api` frames inside carry
  their own signatures, as today. The handshake is paid once a connection,
  and the connection is kept open while the group is in use (§6.3).
- **Later:** SSH over QUIC, or a roaming transport in the manner of mosh;
  Tor carries streams only, so both wait for UDP over Tor (`open.md`).

**Tor carries streams, not datagrams:** no QUIC end to end; UDP over Tor
is a proposal (339), not deployed. iroh's experimental Tor transport
tunnels QUIC packets over a stream; we need not, since the gateway already
speaks streams (HTTP and SSH).

**The onion address is the gateway's identity:** self-authenticating, so
a client that pinned it needs no TLS certificate for it; the SSH host key
stays pinned as today (§7.3). **A space has several gateways, so several
onions** (arti offers no load-balanced onion): enrollment pins the set,
the registrar serves the current set as a query, and a device refreshes
its pinned set through any onion of it: an enrolled space's at each sync
pass, its home's at the personal space's pass, each once a day; the onions
a home's read no longer names stay pinned beside the new set for 7 days,
so one forged answer cannot leave the device without a way home
[built, 2026-11-18]. A home's routes are kept under a key of their own
(`route::home`, a hash of its handle), apart from every enrolled space's
(`route::space`, a hash of another domain), so no handle an enrollment
names, the home's or its key, reaches them or their opt-out; such an enrollment is refused
unless it names the home's own onion set (a home in a space the user
belongs to). The recovery kit carries the set
current at the claim; a space whose onions have all changed since is
found only by its handle through the registry of spaces, which is not
built (`open.md`, "The registry and the root space"; §8, D4). A gateway
could serve a forged set, as it could forge any answer it relays
(`open.md`, "Node-signed feed heads").

**Built** [built, `node-api.md` §6, `docs/operations.md`]: the
gateway's `tor` feature hosts the onion in process on arti-client 0.47.0
(pinned exactly), full vanguards on, its key from the gateway's own file
inserted once into arti's keystore and checked against it at each start,
arti's service-side PoW behind the `tor-pow` feature and the file's
`pow`, off by default. Port 22 is its own SSH server, marking onion; any
other port is refused `DONE`.
s4-server serves any source of connections (its `Listener`: a TCP
listener, or streams handed over), so each SSH stream is handed to the
onion's SSH server with its circuit's address, a port of it its own: the
circuit's streams are counted, and its `vos-api` channels, requests and
proven calls as an address's; the server serves s4's screens (the demo's,
its claims marked onion) beside the `vos-api` subsystem; no loopback port
carries them. The screens' own calls (the demo's host service) pass no
per-circuit limit: s4's host-service requests name no peer, so only the
server's bound per session holds them; and the onion's SSH server has
s4-server's connection cap (`[onion] ssh_connections`) and no idle
timeout of its own, both
open (§6.6). arti in process is the onion's one host (E30). The
`vos-api` relay set holds `Call` and `Credentialed`. A proven call's
body is read only once it holds its places, the port's, its connection's
and its circuit's, and must then arrive within 30 s.
The registrar serves the onion set (the credential actor's `set_onions`
and `onions`, each onion's key and its SSH host key). A gateway given its
space file starts only if every node of it is an upstream. A space's
nodes may ask the onion's mark of its proven calls, or of every request
(`onion = "anonymous" | "all"`, `node-api.md` §3).

### 6.2 The client embedding arti

- **One `TorClient` a process,** created in the light node on the
  facility's tokio runtime (`arti-client` with `default-features = false`
  and `tokio`, `rustls`, `compression`, `onion-service-client`,
  `bridge-client` and `static-sqlite`: the
  defaults are `tokio`, `native-tls` and `compression`, and
  `onion-service-client` is not among them; `static` is not taken, since it
  vendors native-tls and so OpenSSL, but `static-sqlite`, its other half,
  is: without it the directory cache's rusqlite links the system's
  `libsqlite3`, which the NDK does not offer to apps), its
  state directory in the app's private storage so later starts skip the
  cold bootstrap. Zcash's `zcash_client_backend::tor::Client` is the model:
  one client, `isolated_client()` handles, `set_dormant` when the app is
  in the background, persisted state.
- **What the embedding needs** [measured, 2026-11-02]:
  - With `rustls`, the application installs rustls's process-wide
    `CryptoProvider` before it creates the client; ring's, the one russh
    and the gateway use already, so no second crypto library comes in.
  - arti-client 0.47 declares Rust 1.92. The facility's pinned nightly
    (2025-07-14, a 1.90 nightly) builds it under `--ignore-rust-version`
    once `typed-index-collections` is held at 3.2.3 (3.4 and 3.5 call
    `reverse` in a const fn, not stable on that nightly). No newer
    nightly was found: the one tried (2026-03-20) does not build Stwo at
    the facility's pinned revision (`array_chunks` is gone). So every
    arti upgrade may hit the same wall until the prover's nightly moves,
    and §6.7's upgrade step includes checking this.
  - **A bootstrap through an unreachable bridge never ends:**
    `create_bootstrapped` with one bridge line whose address refused TCP
    ran for 15 minutes, cold and then warm, without an error, until the
    harness stopped it. The light node bounds it, and says "this bridge does
    not answer".
  - **Nothing else ends on its own either:** one run hung after its
    second connection, and in another the SSH connection dropped while a
    channel was opening. The light node puts a deadline on the onion
    connection, the SSH handshake and each `vos-api` request, and treats
    a missed one as a lost connection.
- **Isolation by purpose:** each of these gets its own circuit
  (`isolated_client()` or a `StreamPrefs` isolation group) and its own
  SSH connection under its own SSH key, so the gateway cannot join them by
  circuit or by connection:
  - the credential tree's feed (§6.7): one long-lived circuit, since
    every member reads the same feed, its reads on the connection kept
    open while used, so a poll costs a round trip, not a rendezvous;
  - proven calls, and fetches (the node's time): each its own, from a
    spare (the client keeps one connection a purpose built ahead, its
    SSH handshake done, for the purpose's next request, and builds the
    next once it is used, since each isolated circuit to an onion service
    is a new rendezvous, a second or more, heavy-tailed);
  - the member's own key-signed calls in each space (one group a space);
  - the personal agent's traffic (its own group; its background schedule
    its own, §3.10), never sharing a circuit with the member's proofs;
  - s4's screen session (its own).
- **Dormant and awake:** awake while the app is in the foreground or a sync
  job runs; dormant otherwise (no circuit kept, no timer firing), so
  battery costs come only from the work §2.3 budgets.

**Built** [built, `node/light`'s `tor` feature, `vos_light::tor` and
`vos_light::route`]:
- **One `Tor` a process** on arti-client 0.47.0 (pinned exactly, as the
  gateway's) with the features above: its state and cache under one
  directory the app names, made `0700` if missing, arti's permission
  check on and `ARTI_FS_DISABLE_PERMISSION_CHECKS` ignored (arti's
  `ignore_environment`); pasted lines taken as plain bridges, one naming
  a transport refused; the bootstrap bounded (two minutes by default)
  and its failure named: the clock when arti's error, its last blockage
  (`ClockSkewed`, which arti raises only for expired certificates, a
  gross skew) or its skew estimate (its status naming the clock) blames
  it, or the device's clock is before the pinned arti's release; the
  bridge when a bootstrap through bridges ran out of time; otherwise a
  directory that could not be fetched, the network's blockage, or
  arti's error. A moderate skew that arti's estimate misses reads as the
  directory's failure; the phone session checks which it is.
- **The client** (`Client`) sends a request (the device library's
  `wire` bytes) to a space under a `Purpose`: `Proven`, `Fetch` (the
  node's time, the onion set: each a connection of its own, closed once
  answered), `Feed`, `Member` (one a space), `Personal`, `Background`
  and `Screens`; `Fetch` and `Feed` carry reads alone. Each connection is a stream on an isolation token drawn
  for it, SSH under the pinned host key and an ed25519 key drawn for it,
  and the `vos-api` subsystem multiplexed; a kept-open one is closed
  after five minutes without a request. A fresh connection gets three
  attempts, each on a new circuit through the next onion of the pinned
  set, and one more after five seconds when all three found the onion
  service unpublished or unreachable (arti's `OnionServiceNotFound`,
  `…NotRunning`, `…ConnectionFailed`, `tor::Unpublished`): a service
  just launched has no descriptor on its directories yet, and a burst of
  attempts fails alike [measured, Fairphone 6 and Pixel against the demo
  gateway, 2026-11-19: three of five first contacts with a home's onion
  failed so ("Onion Service not found: Failed to obtain hidden service
  circuit"), and the user's retry a few seconds on went through each
  time]; deadlines: the onion stream 45 s, the SSH handshake 30 s, a
  request 30 s, a proven call 90 s, a missed one closing its
  connection. Each connection is made under its space's routes and the
  awake period: a change of either closes it, requests in flight
  included, so none outlives the route it was chosen for (an opt-in
  ends the clearnet connection at once). The spares (`keep_spares`, one
  for `Proven` and one for `Fetch`) are built one at a time, each after
  a delay drawn below 4 s once it is wanted (the space set, the app in
  the foreground, the last one taken), only in the foreground
  (`set_foreground`: leaving it closes them); each is taken by its
  purpose's next request, carries it alone, and a spare unused for a
  life drawn between 5 and 15 minutes is closed and built anew. A
  caller that keeps spares for itself alone sends with
  `request_with(…, spare)`; the onion set's refresh takes none. Dormant (`set_dormant`) closes every
  connection, the spares and the screens, stops the idle timer, sets
  arti's `DormantMode::Soft`, and refuses every request until woken. s4's screen session is carried as bytes
  between a stream or a descriptor s4 hands over (`screens_fd`, a
  socketpair's end) and the onion's port 22, on a circuit of its own; s4
  speaks SSH over it under its own key and pins the host key returned.
  On the phone, s4's UI hands its end over the `:vos` interface
  (`IVosNode.screens`) when it connects to a gateway a space was enrolled
  through (a space whose routes take neither its onion nor an opt-out
  refused), and accepts that host key alone, under an
  SSH key drawn for the session, never resumed, forwarding no agent; the
  opt-out takes the space's clearnet port, its enrolled host key pinned;
  a gateway no space was enrolled through s4 reaches itself, except an
  onion service, which `:vos` carries over Tor at first contact (and a
  client with no facility refuses to dial). A sign-in or a payment is
  proved only for a session `:vos` carries, or one to a space the user
  opted out of Tor (`Gateway.carried`): on the session s4 made itself to
  enroll, both are refused before any prompt ("reconnect"), and s4
  connects again once an enrollment is made on it, now carried. One
  session never holds both what names the device (its digests, its
  account's owner proof) and a sign-in: either is refused on a session
  that holds the other, so a server cannot join the two (built
  2026-11-18). The user grants `vos.credential` once a session, in s4's
  chrome; every reconnect s4 makes by itself (the one after an
  enrollment, a retry after a dropped connection) keeps the grant of the
  session it replaces, for the same host, port and application, in s4's
  memory alone, and a session the user starts asks as ever (E35;
  built). The new session is the facility's new session all
  the same: it starts knowing nothing (`Learned::Nothing`), never
  inherits what the old one was shown, so a session that showed the
  digests or paid still signs in nothing, and the next one signs in. A
  sign-in's and a payment's form name their stages in s4's chrome while
  they run ("Proving…", "Sending…", and a sign-in waiting
  for the operator's invitation, "Waiting for the space to list your
  device…": `IVosPrompts.stage`). The digests
  show as a code a camera reads (`VOSENROLL1:`, member ‖ owner) and a
  six-digit check the operator's tool shows too
  (`vos_api::enrollment_check`): the check catches a misread code or the wrong
  screen, and proves nothing of who chose the digests (a million tries
  find six digits), so the operator still takes them from the device's
  chrome alone.
  The onion set's refresh (`refresh_onions`, and the home's at the
  personal space's pass) is a **timed fetch** (`Client::fetch_timed`): a
  `Time` and then the one `onions` query whose expiry it sets, on one
  connection of the fetch's isolation opened for the two alone, no spare,
  closed after; any other request is refused before it leaves. A set of
  one to sixteen distinct onions replaces the pinned one, closing the
  space's connections. What the gateway sees of it: one fresh connection
  a day carrying a time read and, half a round trip later, an anonymous
  query for the set every member asks, under a key drawn for it; before,
  the same two on two connections a few seconds apart, which it could
  join by their timing all the same. Every other fetch still carries one
  request.
- **What the gateway learns from connections opened ahead** [built,
  `Client::keep_spares`, the facility's `Session`]: a facility session
  keeps one spare for its proven calls and one for its fetches, reads the
  node's clock itself and keeps the reading, and the space's device
  window is read at its grant (§6.3), so a sign-in or a payment sends one
  request after its confirm, on a connection already open. What the
  gateway sees:
  - **Keys and circuits:** a spare is a connection like any other, its
    own isolation token and an SSH key drawn for it, used for one request
    and closed. Opened ahead or not, no two requests share a key or a
    circuit, and `Proven` still carries proven calls alone.
  - **Open times:** spares are built one at a time, each after a delay
    drawn below 4 s once it is wanted (a session's grant, or its last
    spare's use), never two together and never on a schedule; only while
    a facility session is open and the app is in the foreground. A spare
    left unused lives 5 to 15 minutes, drawn, then is closed and built
    anew, closed at its own drawn time (not on a timer's tick), so the
    gateway sees a connection opened, held without a request, and closed:
    that a device keeps spares, nothing more.
  - **Use times:** a spare is used at the user's confirm, seconds or
    minutes after it opened. Its open time follows the session's grant or
    the session's last request by a few drawn seconds, so the gateway may
    join it to that session by timing: a join the session's server has
    already, since the session asked the call and gets its answer.
  - **One session's alone:** the spares are kept for one facility
    session (its number, `Net::keep_spare`): a new session's grant closes
    the last one's and builds its own, and a session's request never
    takes another's spare (`Net::request_for`; the client takes a spare
    only under the keeping it was built for, and drops one whose build
    began under another). No connection opened in
    one session's time carries another session's request, so a payment's
    session, which names the device's account, and a sign-in's session,
    which must not be joined to it, share no connection, opened ahead or
    not.
  - **The expiry:** a call's expiry is the node's time plus 60 s, in the
    clear in the request, and the gateway answers that time. A gateway
    can mark each connection's answer (seconds apart, within
    `CLOCK_SKEW_MS`) and find the mark again in a proof's expiry: a
    reading of the node's clock ties every call set from it to the
    connection it was read on, and the device's own clock error cancels
    out. So each session reads the node's clock itself, on a fetch of
    its own that carries nothing else, and shares the reading among its
    own calls alone; it is never taken from the feed's connection, which
    every session shares, nor kept for the space. A mark then joins a
    proof to its own session's reading, which the session's server joins
    anyway (tested: `a_proofs_expiry_carries_its_own_sessions_reading_alone`,
    each connection's time ten seconds apart). The window read at the
    grant enters no request's bytes (it only gates which stock program
    is proved), so it goes on the feed's connection and is kept for the
    space.
  - **What is left:** a small gateway can join one session's
    connections by their timing, as before; and a sign-in made seconds
    after the first root holding a new leaf points at that newest member:
    a sign-in with no path waits for the space to list the device,
    reading the feed now and every 5 s for up to a minute (built
    2026-11-20, E37: no drawn delay), so a device's
    first sign-in after its invitation follows the leaf's root by a few
    seconds; a member tapping again shows the same, less tightly; the drawn delays spread the
    open times of several devices' spares into each other, and against a
    single device online nothing does. A session's clock reading is
    renewed every 4 to 12 minutes while the app is in the foreground,
    each a fetch: open times again, none of them joined to another
    session.
  - **Two sessions joined by their timing:** a reconnect s4 makes by
    itself follows the session it replaces within seconds, so its
    server can join the two by timing, as an immediate reconnect always
    let it; keeping the grant adds no prompt the user could notice
    between them, nothing more. What the two sessions held stays apart
    (each its own `Learned`), so the join gives the server the timing it
    had. And s4 now opens a session with no act of the user (a retry
    after a dropped connection asks nothing): the server sees a session,
    granted, that the user did not start, though every call in it still
    asks its own confirmation, so it gets no proof the user did not
    confirm (E35).
  - **Rendezvous (PG5, §2.4):** a foreground hour with a session open costs one
    a kept group (the feed, the member's, the personal agent's: 3), the
    proven spare's lives (4 to 12 unused, one a sign-in otherwise) and the
    clock's readings (5 to 15, about 7.5, each taking the fetch spare and
    one built after it; a fetch spare outliving the next reading's gap
    adds about two): about 3 + 6 + 10 = 19 idle, about 3 + 13 + 10 = 26
    with twelve sign-ins (the client's test on a fast clock, its spares
    outliving every gap: 25), within PG5's 30. That is for one open
    session: each open session reads its own clock, so a second one open
    the hour adds its readings. Before, a sign-in cost two (its time read and its proof):
    3 + 1 + 2 × 12 = 28.
- **The policy** (`Routes`, §6.5): the onion unless the request is
  key-signed (`Member`, `Screens`), the user opted the space out
  (`opt_out`, refused for an onion-only space or one offering no
  clearnet port) and the space offers a clearnet SSH port; otherwise
  refused when no onion is pinned. A kind must match its purpose
  (`Credentialed` only as `Proven`, which carries nothing else).
- **Tested without the network** (`just test-light-tor`): an
  in-process gateway, a russh server per dial, records each
  connection's isolation token, SSH key and kinds: no two connections
  share a token (none compatible by arti's own `Isolation`) or a key,
  and every kind went under its purpose; an anonymous call on a
  clearnet-only path dials nothing; the spares (a fetch's beside a
  proven call's, each used once; none built in the background; one unused
  closed after its life), the retry on a new
  circuit, dormancy, the deadlines, the screens over a socketpair and
  the refresh, concurrent requests sharing one open, a route change and
  a dormancy ending requests in flight each have their test; arti's
  state opens in a private directory and is refused in a world-writable
  one with the override set. arti keys an onion's descriptor and
  introduction state by isolation, so each connection fetches the
  descriptor anew, a retry learns nothing of the failed introduction
  point, and arti keeps each record 48 h: the price of a circuit a
  connection, to be watched in the phone's memory.
- **Over the live network** [measured, x86: Intel Core Ultra 7 155H, a
  home connection in Europe, 2026-11-08; the `onion` example, release,
  against a debug `vos-gateway --features tor` hosting its onion in
  process in front of one node, on the same host; 1 cold and 2 warm
  runs]: bootstrap cold 4.2 s, warm 0.64 and 0.33 s; each group's
  first `Time` (an onion connection, SSH, the subsystem) 7.4–17.5 s, one
  45.1 s (a retry past a 45 s deadline); a `Time` on an open connection
  0.45–1.23 s p50; a fetch 8.3 and 16.5 s, one 95.6 s (two attempts
  failed, the third on a new circuit answered); the spare took the
  proven calls in every run (`spare=true`), each answered in 0.57–1.16 s
  (the node's refusal of a stand-in body); resident memory 24 MiB
  after a warm bootstrap (31 MiB cold), 31–33 MiB with the groups'
  connections open.

### 6.3 The latency model

| phase | time | when it is paid |
|---|---|---|
| cold bootstrap (consensus and about 8,800 microdescriptors, a few MB) | 10–30 s, timing out at 30 s on a lossy network [unverified, onionmasq's log] | first run, or after a long time offline |
| warm bootstrap (cached directory) | about 1–3 s [est] | each app start; hidden behind the UI's own start |
| onion connection (descriptor, introduction and rendezvous circuits) | about 1 to several seconds, heavy-tailed; arti's own issue reports onion connections timing out [unverified, onionperf, arti#2482] | once a purpose a session; pre-built when the app opens (§6.2) |
| an SSH handshake over the circuit (key exchange and user authentication, about three round trips) | about 1–3 s [est] | once a connection, kept open while its group is in use; done ahead for a proven call's spare |
| a request on an open connection (six hops each way) | 0.3–1 s round trip [est] | every call |
| a proven call without a spare ready | adds an onion connection and an SSH handshake, 2 to several seconds | a call in a session's first seconds, or a second proven call within a spare's build time |
| a proof's upload | a device proof is about 0.9 MB (a spend about 1.2 MB [est]); at the 0.5–2 MB/s an onion circuit sustains, 0.5–2 s [est] | every proven call |

**A sign-in end to end** (a spare connected, the path held): prove 0.45–0.65
s, upload 0.5–2 s, the round trip 0.3–1 s, the node's apply 35 ms
[measured, `proving.md` §8]: **about 1.3–3.6 s** [est], against about 0.8 s on the
clearnet. **A private payment:** 2–4.5 s [est]. The proof's bytes are now
the largest term, which makes the device format's proof size a lever of
its own (§4.4): the per-program CPU and word-level memory cut columns, and
so bytes, by the same fraction as cells.

**Measured on a desktop** [measured, x86: Intel Core Ultra 7 155H, a home
connection in Europe; arti-client 0.47.0; 2026-11-02]. A light-node client
with §6.2's feature set reached a spike gateway through the gateway's
in-process arti onion, over the live Tor network. The gateway was
vos-gateway's SSH port with its `vos-api` subsystem, in front of one
node. The runs: 3 cold bootstraps, 5 warm, and a cold and a warm one
through a plain bridge. Each run opened 3–8 connections, each from its
own `isolated_client()`, so each was its own rendezvous. Each connection
went: onion stream, SSH under a fresh key, the `vos-api` channel, a
`Time`. On its last connection a run then made 5–20 `Time` round trips,
three batches of 16 pipelined `Query`s (the counter's `value`), and 1 MiB
uploads on a second SSH channel, each timed to the gateway's 8-byte
acknowledgement. Phone figures come from the phone session (§6.4).

| phase | estimate above | measured: median, range or p95 (n) |
|---|---|---|
| cold bootstrap, empty state | 10–30 s | 4.6 s, 3.9–14.8 s (3) |
| warm bootstrap | 1–3 s | 1.6 s, 1.4–2.7 s (5); the gateway's own 1.1 s |
| bootstrap through a plain bridge | — | cold 8.6 s, warm 1.3 s (1 each), through a vanilla line from `bridges.torproject.org`; the other line given refused TCP (§6.2) |
| cold start to the first onion stream | — | 7.8 s, 35.8 s and 65.7 s (3 runs): the first rendezvous after a cold bootstrap is the slowest |
| onion connection, warm client | 1 to several s | 4.7 s, p95 58 s (30), with one run's five of seven connections at 43–84 s; without that run 3.7 s, p95 13.6 s (28). Against this onion 8 of 52 attempts failed: 4 passed 120 s and 4 failed within 3–5 s ("failed to obtain hidden service circuit") |
| SSH handshake (key exchange, user authentication, the subsystem) | 1–3 s | 3.5 s, p95 5.2 s (30), above the estimate: key exchange 1.1 s, authentication 1.5 s, subsystem 0.9 s |
| a `Time` on an open connection | 0.3–1 s | 0.55 s, the median of 4 runs' medians; the first on a new connection 0.49 s, p95 1.0 s (30) |
| 16 pipelined `Query`s, all answered | — | 1.0 s, p95 1.15 s (12 batches), about two round trips |
| a 1 MiB upload | 0.5–2 s | 6.7 s, 3.8–15.1 s (16 uploads in 6 runs), about 0.15 MB/s; through the bridge 6.3 s cold, 26 s warm |
| the same over loopback TCP, no Tor | — | SSH 47 ms, `Time` under 1 ms, 16 queries about 50 ms, 1 MiB 65 ms |

**What this changes:**
- **The upload dominates.** SSH's 2 MiB channel window does not limit
  it; the onion circuit does, at 0.07–0.27 MB/s (0.15 MB/s at the
  median), not the 0.5–2 MB/s assumed. A sign-in with a spare ready is
  then about 0.6 s of proving plus about 5.5 s for a 0.9 MB proof at the
  median rate, its reply included: **about 6 s**, against the 1.3–3.6 s
  estimated above. A P1 payment carries no proof, so it stays near one
  round trip. The levers: smaller device proofs (format 47 and §4.4's
  levers cut bytes), and an upload split over several circuits.
  Congestion control on onion circuits would be a third; it is listed as
  experimental in arti's 2.5.1 notes (§9) and was not tested.
- **Spares carry the load.** With an onion connection at a median of
  3.7–4.7 s and a tail of tens of seconds, plus 3.5 s of SSH, a purpose's
  connection costs about 8 s at the median. §6.2's spare, built ahead
  with its handshake done, and connections kept open are what make calls
  usable. A call that finds no spare waits that long.
- **Pipelining works:** sixteen queries take about twice one round trip,
  so one SSH connection a purpose carries its group's reads without a
  second rendezvous.

**A payment and a sign-in, from the tap and from the confirm.** UX sets the
bar: a payment competes with tapping a card. Targets: from the confirm to
the answer, at most 2 s with Tor warm (the source's answer, the proof and
one send on a connection already open); from the tap to the form, at most
0.5 s once the session has been open a few seconds. On the Fairphone 6
over the onion before this [measured, Fairphone 6, debug APK, vos-core
91e7c0a24, 2026-11-19]: a payment about 35 s from Pay to Paid, of which
the proof 0.54 s: the form about 6 s after Pay (the device window read on
a fetch of its own), the proof 8–10 s after the confirm (the node's time
read on another fetch, then the Keystore), the send on the spare about
2 s; a sign-in about 22 s from Sign in, the proof 0.68 s. Each fetch was a
new onion connection and an SSH handshake, about 3 s at the gateway.
What the light node does now (§6.2): the session's grant reads the device
window (on the feed's connection) and the node's clock (a fetch, the
reading kept as an offset from the device's clock, moved on by the
monotonic clock) at drawn delays, and
builds the spares; at the tap nothing is read; after the confirm the call
is set from the kept reading and sent on the proven spare; a reading not
held at the tap is read while the user reads the form.

In the World [measured, x86: Intel Core Ultra 7 155H, the facility's
`latency` test over `Delays::ONION` (a connection 4 s to its stream, a
round trip 0.5 s, no rate cap: §6.3's desktop medians), a debug build,
2026-11-20; the session open 25 s before the tap, the user reading the
form 3 s]:

| stage | before (vos-core 7921dd5ad) | after |
|---|---|---|
| payment, tap → form | 8.0 s: the window read on a new connection | 0 ms |
| payment, confirm → paid | 8.5 s: the time read on a new connection 7.5 s, the proof 0.43 s, the send on the spare 0.55 s | 0.83 s: the proof 0.28 s, the send 0.55 s |
| sign-in, tap → form | 0 ms (the window kept from the payment) | 0 ms |
| sign-in, confirm → signed in | 8.7 s: the time read 8.0 s, the proof 0.16 s, the send | 0.69 s: the proof 0.18 s, the send 0.51 s |
| requests after the confirm | the time on a new connection, then the proof | the proof alone, on a connection opened before the confirm |

The SSH handshake is about six round trips (3 s at 0.5 s), the onion
connection 4 s of a fresh connection's 7.5 s, the first request the
rest; spares do both
ahead. How soon after the grant the targets hold [measured, the same]:
tapped 2 s after it, the payment's form came 6.0 s later (the window's
read in flight, one connection), confirm → paid 0.84 s (the clock's read
done while the form was read); at 6 s the form 2.1 s, a sign-in 1.4 s
(its clock read in flight); from 10 s on, both targets (the form at once,
confirm → answer 0.68–0.83 s). So a call in a session's first ten seconds
or so waits for the reads in flight, at most one connection's time,
never a second one. Outside the model: the proof's upload (a payment's
0.75 MB, a sign-in's 0.79 MB: at the desktop's median 0.15 MB/s about
5 s, while the Fairphone 6's spare sent a payment in about 2 s) and the
source's answer (the Keystore, after the user's unlock), each logged on
the phone (`vos.node`'s stage lines).

**The member's flows in the test World** [World: the facility's flows in
process (`node/light/android/tests/flows.rs`) over `Delays::ONION`, a new
connection 4 s to its stream and a round trip 0.5 s, prompts answered at
once; x86 Core Ultra 7 155H, debug; not modelled: batch linger, s4's
screens, reconnects, Tor's bootstrap and tail, Keystore and user time.
Floors, not phone times. Before: vos-core 4caa68985, 2026-11-20; after:
refreshed at the tip, vos-core 89e04682b with the kit's life timed from
its entry, 2026-11-22; to be refreshed at each tip that touches a flow]:

| flow | before | after (refreshed at the tip) | what changed |
|---|---|---|---|
| claim (phrase kit) | 52.0 s, 25 requests | 46.8 s, 23 requests; 13.4 s after "I wrote them down" with 20 s to write | the open claim's work, tree, time and proof connection while the kit is written (E31) |
| claim, circuits at 0.15 MB/s | 57.4 s | 52.8 s | as above |
| first sign-in after the invitation, tapped at once | 12.0 s, 2 attempts (a `NoPath` refusal, tapped again) | 10.9 s, 1 attempt | the sign-in waits for its leaf (E37) |
| pairing, from the scan to both done | 38.9 s, 108 requests (the opener done at 30.2 s) | 22.2 s, 77 requests (the opener at 21.2 s); 2.6 s of follows after it returns | reads asked ahead; done at the first complete follow (E33) |
| a pass (the opener's; the joiner's) | 28.6 s; 27.6 s | 18.6 s; 17.6 s | reads asked ahead |
| commit now (a retired device's removal) | 23.2 s, 46 requests | 8.6 s, 26 requests; 3.1 s of follows after it returns | as pairing |
| restore: the kit's view | 11.1 s | 10.6 s | |
| restore: opened | 4.1 s | 3.5 s | |
| restore: finished after the kit's delay | 33.0 s, 65 requests | 15.3 s, 43 requests; 3.1 s of follows after it returns | as pairing |
| restore: the kit typed | 4–5 times a restore | once a sitting (twice in the test, one mistyped) | the kit held for the restore screen (E32) |
| leave: from the tap to the space cleared | — | 2.7 s, 7 requests | built (E34) |
| leave: the other phone's pass, then its commit now | — | 19.6 s, then 9.1 s | |
| move: leave and claim at another home | 55.5 s | 50.0 s | as the claim |
| the device list | 2.0 s | 1.5 s | |
| the removal posted | 6.1 s | 3.0 s | |

The 0.5 s request and the 4 s connection dominate every row; the values
are the summary `flow:` lines of each run.

### 6.4 What it costs on the phone

No published figures exist for arti's library size, idle memory or
battery on Android [the research found none]; the figures below are the
first. The budgets of §2.3 (arti ≤ 48 MiB
resident, ≤ 10 MB of `.so` growth) are targets to measure against, not
known values. The production precedents: Zashi ships arti on Android and
iOS (exchange rates since 2024; transaction submission and fetching in beta
since Zashi 2.1, 2025-08-07, with a prompt to turn Tor off when it is
slow); the Tor Project's own Android VPN (onionmasq) runs arti and is
still in beta; Orbot still bundles C tor.

**Measured for arm64 and on a desktop** [measured, 2026-11-02;
arti-client 0.47.0 with §6.2's features, plus rustls's ring provider and
tokio's multi-threaded runtime, which the light node brings anyway]:

| what | measured | limit (§2.3) |
|---|---|---|
| the facility's `.so` growth from arti, `aarch64-linux-android`, built as the APK builds it (`cargo ndk -P 30 build --release`, stripped as packaging strips) | 15.16 MB → 29.01 MB: **+13.85 MB** (+5.82 MB gzipped). `compression` accounts for 0.18 MB and `bridge-client` for 0.45 MB. With fat LTO and one codegen unit: 11.35 MB → 20.19 MB, **+8.84 MB** (+4.27 MB gzipped) | ≤ 10 MB, provisional: missed without LTO, met with it |
| the spike client's arm64 binary, with arti and without (both stripped) | 2.84 MB → 16.32 MB: +13.5 MB, the same growth | — |
| resident memory, x86 client (arti bootstrapped, an SSH connection open, idle) | 34–38 MiB, of which arti about 24–27 MiB; the same process over loopback TCP without Tor takes 10.4 MiB. `set_dormant(Soft)` leaves it unchanged: arti does not hand its memory back | ≤ 96 MiB, arti ≤ 48 MiB: met on x86 |
| the gateway hosting the onion (vos-gateway's SSH and arti), x86 | 31–43 MiB, median 37 MiB, over about 2 h (133 one-minute samples) | — |
| the state directory | 8.0 MB after a cold bootstrap: the directory cache 7.98 MB, state and keystore 11–14 kB. 11.4 MB after about 1.5 h of runs, once the directory refreshed | — |
| warm bootstrap, x86 | 1.6 s median (5) | ≤ 3 s p50: met on x86 |

**Measured on the phones** [measured, 2026-11-06; the same probe
as §6.3's, built for `aarch64-linux-android` and run from the shell over
the live Tor network against the spike gateway's onion; 3 cold and 5 warm
bootstraps and a cold and a warm one through the plain bridge on each
phone; the Fairphone 6 (Snapdragon 7s Gen 3, Android 15) and the Pixel 1
(Snapdragon 821, LineageOS on Android 15), one after the other]:

| what | Fairphone 6 | Pixel 1 | limit |
|---|---|---|---|
| warm bootstrap, p50 | **0.80 s** | **2.5 s** | ≤ 3 s p50: met on both |
| cold bootstrap, p50 | 7.2 s | 6.9 s, max 13.8 s | — |
| bootstrap through the bridge, cold / warm | 5.2 s / 0.94 s | 12.4 s / 2.5 s | — |
| cold start to the first onion stream, p50 | 11.4 s | 10.5 s, max 18.0 s | — |
| onion connection, warm client, p50 / p95 | 2.9 s / 7.6 s; 4 of 42 attempts failed | 3.3 s / 11.7 s; 9 of 45 failed | — |
| SSH handshake, p50 | 3.0 s | 3.5 s (key exchange 1.2 s, authentication 1.4 s, subsystem 0.9 s) | — |
| a `Time` on an open connection, p50 | 0.41 s | 0.51 s | — |
| 16 pipelined `Query`s, p50 | 0.57 s | 0.83 s | — |
| a 1 MiB upload, p50 / p95 | **2.4 s** / 4.2 s, about 0.4 MB/s | 3.6 s / 5.5 s | — |
| resident memory, idle with an SSH connection open | **32 MiB** | **27 MiB** (26 MiB dormant, 20 MiB bootstrapped) | ≤ 96 MiB: met on both |
| the state directory | 10.8 MB | 10.9 MB | — |

- **The limits hold on both phones,** the old one included, its warm
  bootstrap near the limit.
- **The sign-in over Tor** at the Fairphone's median: about 0.6 s of
  proving, 2.2 s for the 0.9 MB proof, 0.4 s for the reply: about 3.2 s,
  under PG3′'s 4 s. Upload rates vary by circuit (§6.3's 0.15 MB/s on
  2026-11-02); PG3′'s run over Tor decides.
- **Connections fail often enough to plan for:** 10–20% of fresh onion
  connections failed on the phones, as on the desktop, so the client
  retries on a new circuit and keeps its connections open (§6.2's
  spare).
- **arti's state on Android:** under `/data/local/tmp` arti refused its
  state directory's permissions ("problem with filesystem permissions"),
  so the probe ran with `ARTI_FS_DISABLE_PERMISSION_CHECKS=1`. The app's
  private directory has the modes arti expects, and the light node keeps
  arti's check on and ignores the override (§6.2, "Built").

### 6.5 The Tor policy, bridges, and blocked networks

- **Tor is the default for every space** [decided, E22]: the light node
  reaches every space through its onion. Per space, the user may opt out
  for **key-signed calls** (a member's own signed calls, P1 payments,
  and s4's screens with the space's gateway) where the space allows the
  clearnet, after a plain warning that the space's operators then see the
  device's address, and so can join it to the sign-ins and payments its
  screens ask for there (`OPT_OUT_WARNING`): the proof itself still goes
  over Tor, but the session that asked for it and receives its answer
  does not.
- **Anonymous calls never use the clearnet,** in any space: a credentialed
  or proven call (sign-in, owner proofs, later spends) leaves the client
  only through Tor, whatever the user's or the space's setting; the client
  has no clearnet route for those kinds. A space's ingress may enforce it
  too, refusing them without the gateway's onion mark (§3.3).
- **A space may declare itself onion-only** in what enrollment pins, so no
  clearnet route to it exists at all.
- **The personal agent's home is onion-only, by rule** [decided, E17]: the
  light node has no clearnet route for any kind addressed to the personal
  agent or `Homes`, and the agent refuses a request its gateway did not
  receive on the onion (§3.3). Over the clearnet it would hand the home's
  operators the device's address beside its pseudonym.
- **Plain bridges** [decided, E22]: arti's bridge client with
  bridge lines the user pastes (from the Tor Project's bridge
  distribution), which defeats networks that block Tor by its public relay
  list, as many campus and corporate networks do. Pluggable transports
  (obfs4 through lyrebird, Snowflake, WebTunnel), which defeat deep packet
  inspection but each bring a Go binary run as a managed subprocess on
  Android, are later work (`open.md`).
- **What a user behind a network that blocks Tor by inspection sees:**
  key-signed calls fall back to the clearnet where the space
  allows it and the user opted out for it; anonymous calls and the
  personal space wait, the app saying "this network blocks Tor" with the
  last sync time. **The stated limit:** the personal space's timed
  safeguards run without the device meanwhile. It can neither veto a
  removal (72 h) nor post the `alive` that cancels a restore (7 days), so
  a leaked kit's restore can mature against a user whose every device
  stays behind such a network for a week (§8, H2).
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
  way). PoW is turned on when a release declares it; until then the
  gateway's other limits hold alone.
- **Limits per circuit and per service:** streams per rendezvous circuit,
  requests a second per stream, calls per agent per circuit (so one
  circuit cannot fill a personal agent's log), and a global cap of proven
  calls in flight through the onion (the node's verification budget
  behind it, `Busy` past it). Personal agents also admit only known keys
  (§3.3).
- **The proof's own cost:** a proven call carries the device format's PoW
  (16 bits), a grinding parameter more than a price: well-formed junk is
  refused by the pre-check in about 0.02 ms, and junk ground for the 8-bit
  interaction PoW costs the node 11–27 ms under load [measured, format
  46, §4.3]. Tor's own throughput to one onion bounds such proofs to tens
  a second, below a node's budget (measured below).
- **Restricted discovery** (onion-service client authorization): stable
  since arti 1.7.0 (2025-11). Only clients holding an authorized key can
  read the service's descriptor, which hides it from scanners. Not
  offered: a key per member makes the descriptor grow with the space
  (its size is bounded), and one key shared by every member is as good
  as public once one member leaks it. A space small enough for per-member
  keys may turn it on later.

**The caps as built** [built, `node-api.md` §6; each a key of `[onion]`
with its default, `docs/operations.md`, "The onion service"]: each
circuit counts as an address of its own (its connections, requests in
flight and a second, and streams capped), the circuits at once capped, a
circuit with no stream let go after 60 s; the onion's SSH server's
connections capped, each given 30 s to authenticate; proven calls capped
in flight through the onion, from one connection and from one circuit,
taken from a proven call's header before its body is read: its
connection's and circuit's first (past either the channel is closed),
then the onion's, for which one call a circuit waits (another is closed
at once), so no circuit queues headers ahead of the others; the header
takes its circuit's request token, and the body must then keep its pace:
its time is 5 s plus its length at 40 KiB/s (a 1 MiB upload's slowest
measured, through a bridge, §6.3), at most 30 s, and by 5 s plus its
share of that time as much of it as that share, the whole within it, so
a header whose body never comes, or comes a byte at a time, gives its
places back after about 5 s, and the smallest large body (64 KiB) kept
at its pace after about 6.6 s (`ssh::Pace`); an agent's calls
and proven calls from one circuit rated. *Known limit:* at the defaults,
the members' wait still grows with the circuits an attacker
holds, one waiter each before a member, 16 places [derived, 2026-11-22]:
with headers alone a member waits about C × 5 / 16 s, inside the
gateway's 60 s for up to about 190 circuits; with the smallest large
bodies kept at their pace (about 2.4 KiB/s a place, 38 KiB/s for all 16)
C × 6.6 / 16 s, about 145 circuits; and an attacker who uploads bodies
of 1 MiB or more at the slowest pace (about 28 KiB/s a place, 0.45 MiB/s
for all 16) holds each place the whole 30 s, a member waiting
C × 30 / 16 s, past 60 s at about 32 circuits. The device's own deadline
for a proven call, 90 s (`tor::Config::proven`), covers the gateway's
60 s wait and the body's 30 s, so it lowers none of these. Past them the
defence is the introduction points' rate and arti's proof of work
(`open.md`). Past a
cap on a request already read the gateway answers `Busy` and asks no
node. A flood of junk proven calls the size of a device proof, from eight
connections through a port capped this way, held at most the port's
proven calls behind it, while a member's queries, a session's call and
the member's own proven call on another connection were answered (the
gateway's test 22, in process, no network).

**The flood through Tor** [measured, x86 dev machine, chutney, 2026-11-09;
a spike outside the tree, E25's private Tor test network]: a chutney network of
four authorities and eight relays on loopback, the gateway's arti onion in
process over it (full vanguards, descriptor published in about 0.3 s), and
arti clients over the same network. Eight circuits flooded well-formed
junk proofs (a device proof's valid claim for an enrolled member who never
signs in, so each reaches a verification slot, with about 1 MB of corrupt
proof bytes) while four to six members signed in on circuits of their own,
against a no-flood baseline:
- **The members were served throughout:** every sign-in ran (4/4 and 6/6
  across runs), its pseudonym the node's. A sign-in took about 0.8 s with
  no flood (p99 1.2 s) and 1.9–3.6 s under it (p50; p99 2.2–3.7 s), well
  inside the 30 s a proven call is given.
- **Tor bounded the flood below the node's budget on its own:** a 1 MB
  proof through a three-hop circuit and one verification slot throttled the
  junk to about 15 a second in aggregate through the onion, far below the
  node's verification budget, so the gateway's per-connection, per-circuit
  and global proven caps never had to shed a call (the in-process test 22
  exercises those caps directly). Each junk was refused — the pre-check in
  microseconds, a corrupt body at its decode — and the node's credential
  stage averaged 9–11 ms a call under the load, as §4.3 reports. No member
  sign-in was refused `Busy`, and the whole measurement process (node,
  gateway, arti and the clients together) held under 1.2 GiB.
- **What a private network does not show:** chutney's rendezvous is local,
  so a sign-in's 0.8 s understates live Tor's about 5 s (§6.1) and its
  descriptor publishes in seconds, not the tens live Tor can take; and
  loopback bandwidth lets the junk flow faster than the live network
  would, so the private run is a harder test of the node per junk proof
  and a lighter one of Tor's latency and rendezvous. The caps remain the
  backstop should a live flood outrun the bandwidth bound (§6.7).

### 6.7 What Tor fixes, and what it does not

**Fixes:**
- the network address: no node or gateway learns a member's address, so
  a proof's nullifier links to no address, and a feed read and a proof
  arrive on different circuits;
- the root-marking attack's last step (a gateway marking an address's
  feed) loses its address; it keeps the circuit, which isolation per
  purpose (§6.2) scopes to the feed's connection;
- the personal agent's view: a device's pushes and fetches with no
  address behind them.

**Does not fix:**
- **timing:** a gateway sees when a read and a proof arrive; keeping
  each tree from its feed on the device (below; the wallet's `tree`
  likewise) leaves no query naming the member, and the feed's timer keeps
  its reads apart from proofs, but for a first sign-in waiting for its
  leaf and a claim (below), each about once a device's life;
- **the `map_root` fingerprint:** what a synced tree fixes (below), every
  proof against the newest root the device has read; within a timer
  period of a tree change, the members who have not read it yet still
  stand apart;
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

**The credential tree's feed** [built: the credential actor's
`feed(from)` and `feed_after(root)`, `vos_light::TreeKeeper`,
`Client::read_tree`]:
- **The actor keeps every write of its tree** as a `Change`
  (`vos_wire::credentials`): the leaves it set, each at its slot, and the
  root it left with the batch time it became the root, the entry it left
  in the ring. `feed(from)` serves them in order from the `from`th, as
  many as 48 KiB holds (`FEED_BYTES`, at least one), with the feed's
  length; any caller reads it, as every member reads the same feed.
  `feed_after(root)` serves the page after the last change that left
  `root` (the actor indexes each root by its last write, `roots`), none
  for a root no change left.
- **The query names no place of the device's** [built]: a keeper's first
  read is `feed(0)`, every keeper's first, and every read after is
  `feed_after` the root it holds. The place in the feed is the answers'
  word: a gateway padding them with changes that undo each other would
  leave the device's place its own, a mark in every query after on every
  circuit; the root it is left at is every member's that read as far,
  and a root a gateway forged fails the next proof (`RootUnknown`), not
  silently. *Known limit:* a gateway can still end its answers early, at
  a root of its choosing. One the ring does not hold (a historical root,
  a batch's first) fails every proof, and two such refusals with no
  change read between drop the tree; one the ring holds is one of its 64
  recent roots, shared by every member that read as far, so the mark is a
  few bits at most, and it lasts only the root's grace (below): ninety
  seconds after the change the device was not shown, its proofs meet
  `RootStale` and its keeper reads again. That bounds what is logged
  and what any other party sees; the gateway itself still sees the
  refused proofs it relays, each naming the root it chose, for as long as
  it keeps withholding. Within the grace the mark is the
  split an honest keeper one period behind already shows, which only a
  settled root (below) closes. Of the ways to close it further: a head
  bound to the ring's entry inside the actor alone would show the keeper
  nothing, since every answer, the binding with it, is the gateway's to
  forge; the head bound into the proven statement adds nothing over the
  grace, since the proof already names its root and the ring judges that
  root's age; answers the keeper can authenticate past the gateway (the
  node's signature over a timestamped feed head) are later work
  (`open.md`, "Node-signed feed heads").
- **The root's grace** [built: `defaults::ROOT_GRACE_MS`,
  `credentials::judged_at`]: ingress and the default agent's refine
  accept a superseded root for 90 s after the batch that superseded it,
  while the ring still holds it. The number is two of the feed timer's
  longest gaps: the timer's period is `FEED_PERIOD_MS` (30 s), each read
  drawn between half and one and a half periods after the last, so an
  honest keeper's reads are at most 45 s apart. The first gap is the
  keeper not yet having read a change; the second is the proof it made
  just before that read, proved and carried to the node.
  - **What each judges against:** ingress the node's clock, the one its
    expiry check reads (not the replica's latest batch time, which an
    idle space leaves behind); apply the earlier of the batch's time and
    the call's expiry less `CREDENTIAL_HORIZON_MS` (120 s). Ingress
    refuses an expiry more than the horizon past its clock, so that time
    is no later than the clock of any ingress that admitted the call; and
    apply refuses an expiry before the batch's time, so it is no earlier
    than the batch's time less the horizon. So no replica refuses at
    apply what an ingress admitted on the ring's grace, however long the
    call waits for its batch (but for a ring that has since dropped or
    replaced the root, refused `StaleRoot` at apply), and a revoked or
    held-back root binds every replica within the grace and the horizon,
    3.5 minutes, of its successor's batch, and within the grace at an
    honest ingress. A call expiring sooner than the horizon is judged at
    apply as far before its ingress (s4's 60 s expiry: 60 s). Ingress
    compares the leader's batch time (a ring entry's `since`) with its own
    clock, so it assumes the nodes' clocks within a few seconds of the
    leader's: a leader behind by D shortens the grace at ingress by D,
    out of the margin below, one ahead lengthens it by D; apply's bound
    holds either way.
  - **The margin, an honest phone's:** the grace leaves 45 s for the
    proof and its trip, and for what the first gap leaves out: the feed
    read's own round trip, the feed replica's lag behind the leader, a
    failed read retried (10–20% of fresh onion connections fail, §6.4),
    and clock skew. The slowest proving measured is the Pixel 1's
    `auth`, 1.5 s at format 46 and 0.92 s at 47 (the Fairphone 6's about
    0.6 s) [measured, `proving.md` §8]. The trip without a bridge on the
    Pixel 1, when no spare is built: a fresh onion connection at its 95th
    percentile (11.7 s), an SSH handshake (3.5 s), then a 0.8–0.9 MB
    proof at the slowest onion circuit measured, 0.07 MB/s (about 13 s)
    [measured, §6.3, §6.4]: about 30 s in all, 15 s to spare; a sign-in
    at the median is about 3–6 s. Through the plain bridge (about
    0.04 MB/s warm, §6.3: about 23 s for the proof), or on a connection in
    the desktop's tail (a p95 of 58 s), the call can outlast the grace.
    A call slower than the margin (the client gives a proven call 90 s,
    §6.2) meets `RootStale`, which makes the feed due within 10 s, and
    the proof made again at the newest root, which no grace refuses,
    runs. That retry is the app's, once, with no new prompt: the user
    confirmed the call, not the root (s4 makes the feed due on the answer
    and shows the refusal; its re-release takes the retry).
  - **Not a read before proving:** the keeper still reads on its timer
    alone, since a read just before each proof would join the proofs
    through the feed's circuit (below); the grace is sized to the timer
    instead.
- **Back onto the real feed** [built]: a keeper whose pages are refused,
  or whose root the actor knows no change leaving (a fork a gateway
  served, a re-founded space whose feed starts again), two reads in a
  row drops its tree and reads from `feed(0)` again (`Synced::reset`);
  one such read, as from a replica behind the keeper's, holds nothing
  new. So does one whose proofs meet `RootUnknown` or `RootStale` twice
  with no change read between (`TreeKeeper::unknown`): a root the
  gateway keeps answering with empty pages is left too. A gateway can
  force such a start over each minute or so, a re-read of the whole feed:
  a cost, not a mark, as `feed(0)` is every keeper's.
- **The device keeps the whole tree** (`TreeKeeper`): each page applied
  at once, each slot's last leaf and every node above them computed once,
  and refused whole unless the tree it leaves has the root its last change
  names (the one root a proof uses, which binds every leaf) and its
  changes are in order. The member's path is computed on
  the device, so no query names the member: the path leak ends, and each
  proof is against the newest root the device read. The tree is kept
  outside any synced scope (`encode`, `restore`, the root checked on
  restore), so a restart reads only the changes since.
- **On one long-lived circuit** (`Client::read_tree`, `Purpose::Feed`):
  the node's time and each page on the space's feed connection, which
  carries reads alone, one rendezvous for as long as it stays open (five
  minutes idle). Read on a jittered timer (30 s, between 15 s and 45 s),
  never because a proof is about to be made, since that connection is one
  circuit of the device's and a read before each proof would join the
  proofs through it (two exceptions, each once a device's life at a
  space: a sign-in waiting for its leaf, which reads the feed every 5 s
  until it is listed, and the claim of a personal agent, which reads its
  home's tree while the kit is written down); a page that says more is due at once; `RootUnknown`
  or `RootStale` makes the feed due at once and halves the period.
- **The root in the log:** the claim keeps the root, which the apply
  checks; its place in the ring is the feed's (each change's root and
  batch time). A place in place of the root would hide nothing: relative
  to the newest it moves between ingress and apply, and counted from the
  first it names the root as the digest does. What fixes the fingerprint
  is that every member on the feed proves against the same newest root;
  within one timer period of a tree change, those who have not read it
  yet still stand apart.
- **Bounded against its gateway:** a page at most `FEED_BYTES` (or one
  change of at most 256 leaves), no slot past the lowest never used, as
  the actor places members (so about two nodes a leaf), at most 256 pages
  a read; no path given until a read reaches the feed's end, as a page may
  end between two writes of one batch, whose first root the ring never
  holds.
- **A later lever, a settled root:** proving against the newest root
  older than one timer period (45 s and a margin) in place of the newest
  would give every member who read within the period the same root,
  closing the split above, at up to 45 s more of revocation lag; it needs
  the path at that root, the leaves' values before the changes since.
- **Not yet:** the feed is kept whole, about 77 bytes a single write, on
  the actor and on every device (`open.md`).

**What it costs** [measured, x86: Intel Core Ultra 7 155H; the actor on
the testkit's refine, the keeper in a release build; 2026-11-08; a
throwaway spike]. A feed query is 139 bytes; an answer with nothing new
34 bytes, one with one new enrollment 114.

| tree | pages | bytes to catch up | node, a page | device, all pages | kept on the device, restored in |
|---|---|---|---|---|---|
| 1,001 members, one write each | 2 | 78 KiB | 20 ms | 2 ms | 35 KiB, 2 ms |
| 10,001 members, one write each (the worst case) | 17 | 782 KiB | 25 ms | 17 ms | 352 KiB, 15 ms |
| 100,097 members, 391 writes of 256 | 79 | 3.5 MiB | 33 ms | 109 ms | 3.4 MiB, 96 ms |
| a new enrollment, or nothing new | 1 | 114 B, or 34 B | 6 ms | under 1 ms | — |

- **Over Tor** [est, from §6.3's desktop figures: a round trip 0.55 s,
  the circuit about 0.15 MB/s]: pages go one after another, each naming
  the place the last left, so a catch-up is a round trip a page plus its
  bytes: about 15 s for 10,000 single-write members (17 × 0.55 s and
  782 KiB), about 67 s for 100,000 by `enroll_many`, about 2.4 minutes
  for 100,000 single writes. Once caught up, a poll is one round trip and
  one Tor cell each way, on a connection kept open: at the 30 s timer
  about 120 polls an hour in the foreground, none a rendezvous (H8).
- **On the node:** a poll with nothing new costs about 6 ms of the
  testkit's refine, every member asking every 30 s: 10,000 online members
  are about 330 queries a second, two cores' worth. Every member reads the
  same pages, so a gateway's cache of the feed's answers (by place, until
  the length moves) is the lever, not built.
- **On the phone,** for the phone session to measure: a 10,000-member
  catch-up over Tor (time, bytes), the keeper's page and restore time and its
  memory at 10,000 and 100,000, and the feed connection's rendezvous and
  polls an hour in the foreground (PG5, §2.4).

**Verdict on arti** [decided]: ready for the client side (stable since
1.0, shipped by Zashi and Fedimint); usable, not yet hardened, for
hosting, whose DoS defence is the gap. The client path ships; the
gateway hosts its onion behind a `tor` feature, full vanguards on, PoW
when a release declares it, arti the onion's one host (E30); one arti
version is pinned a release, with an upgrade step budgeted regularly.

## 7. Fitting the existing system

### 7.1 Crates

| crate | what it holds of this design |
|---|---|
| `vos-light` (`node/light`) | the light node: merge and query dispatch over its store (no log), the release artifacts it embeds (local actors' programs, the stock kernels' device programs), the prover's device path, the node-API client, sync of sealed scopes, the device group through `vos-mls`, the personal space's flows (`space`), arti's client behind a feature; its device library (secrets, wire, the tree keeper) |
| `vos-facility` (`node/light/android`, outside the workspace) | the `vos.credential` facility's cdylib and the `:vos` service: the Binder interfaces, Tor, the jobs, the personal space's screens (§2.2, §7.3) |
| `vos-mls` (`support/mls`) | one MLS layer for VOS over mls-rs [decided, E12]: storage providers over fjall, copy-and-swap of group state for candidates, the confirmation hash, a proposal policy per user; the device group its first user (`vos_light::group`) |
| `vos-exec` (`node/exec`) | the executor's host-call layer, which `vos-node` and `vos-light` link; ingress's device programs stay in the node (the light node takes them as release artifacts) |
| `vos-node` (`node/host`) | admission at ingress for an agent that asks: known keys looked up before the signature, and the gateway's transport mark for onion-only agents (§3.3); the device-format window at ingress (§4.4) |
| `vos-pvm-recair` | the leaves, folds and wrap behind a `recursion` feature, on by default (the masking needs `context`, `circuit` and `trace`, which stay), so a device links less of the recursion prover |
| `vos-sdk`, `vos-sdk-macros` | `#[attestable(device, reference = …, headroom = …)]`; `#[msg(proven = kernel)]`; in-place kernel arguments; `vos_sdk::p2` (digests, tags, paths); `crdt::{GSet, Set, Map}` and `#[msg(merge)]` on the light node |
| `vos-wire`, `vos-api` | `Credentialed.claim`, the kernel's public arguments; `CredentialedInput` carries the claim; `Principal::Kernel { program }` (index 7); the frame's transport mark (`node-api.md` §2; a missing mark is clearnet, §3.3) |
| `merkle-crdt` (`support/merkle-crdt`) | the incremental apply (`core-model.md` §9.4); the author, its sequence and signature in the payload; a `Store` over fjall (`FjallStore`, the `fjall` feature; the core stays `no_std`); fetching by batch, sans I/O so an asynchronous client drives the round trips (`Replica::want` and `serve` for a DAG walk, `Replica::cursor` and `ingest` for `since`) |
| `vos-credentials` | the stock `auth` and `owner` kernels, with their references; each stock guard's compatibility window of program ids (§4.4), the kernels' ingress checks staying in the node (§4.3); the registrar's open claim priced by work (§3.3), its person records, `enroll_device` and `revoke_device` (§3.8) |
| `vos-gateway` | the onion service behind a `tor` feature, serving the same SSH as the clearnet and nothing else (§6.1); the SSH `vos-api` subsystem's relay set with `Call` and `Credentialed`, capped per connection, circuit, agent and onion; the transport mark on every relayed request; every node of its space an upstream when given its space file (§3.3) |
| system actors | `Homes` (`agent/homes`: the pool, claims, the indexes by nullifier and by kit key, the yearly re-proof and the lease) and `Personal` (`agent/personal`: the device set and its contests, liveness, the commit log and confirmations, sealed scopes, checkpoint acknowledgements, the inbox, quotas, gated queries, an append-only layout), each one package; `Payments` (`agent/payments`) |
| `vos-keeper` (`tools/keeper`) | the operator's keeper: topping up the pool, granting `Homes` its role, upgrading `Personal` in batches (§3.3) |

**What the `recursion` feature saves** [measured, x86-64 host building
for arm64 Android (NDK 28.2, API 30), stripped, 2026-11-02]: a
facility-shaped `cdylib` linking `vos-light` (a local actor installed,
called and queried; a device kernel proved; the three credential proofs)
is 9,933,368 bytes without the feature and 9,979,576 with it under fat LTO
(46 KB, 0.5%), and 13,684,120 against 13,894,072 without LTO (210 KB,
1.5%): the linker already drops most of the recursion prover a device
never calls. The feature stays (it costs one `cfg` a module and builds the
device's crates faster); its size argument is small.

### 7.2 The node and the gateway

- **The node** gains no transport and no knowledge of Tor, MLS, JAM or
  Kreivo. Its ingress generalizes (§4.3), admits a window of device
  formats (§4.4) and, for an agent that asks, admits only known keys and
  only onion-marked requests (§3.3); its install computes a device program
  for every device kernel (§4.4). The personal agent is
  an ordinary agent running ordinary actors: nothing in the node knows
  what a personal agent is.
- **The gateway** keeps HTTP, TLS and SSH, and adds the onion service
  (§6): the same SSH behind an onion address, and nothing else [E23]. Its
  SSH `vos-api` subsystem relays `NodeKey`, `Time`, `AgentInfo`, `Schema`,
  `Devices` and `Query`, and `Credentialed` and `Call`, which the light
  node sends through it (`node/api/src/lib.rs`, `Kind::relayed`).
- **Limits that bind the personal agent** [built]: 64 KiB a call's
  arguments, a reply and a row; 256 KiB a step's writes; 16 in flight on
  one `vos-api` channel; one answer a request, no push
  (`pvm/abi/src/abi/cap.rs`, `node-api.md` §2). §3.6 sizes envelopes
  and pushes under them.

### 7.3 s4

- **The facility** `vos.credential`: `enroll`, `sign_in` and `pay` as
  today (the trusted chrome, the pins, the two prompts [decided,
  `identity-and-authority.md` §7]), plus `claim` (the personal agent at a
  home-only space by default, with a phrase or security-key kit), `pair`
  (§3.8, a QR shown and scanned, with the enrollments in every other
  space), retiring a phone (`remove` it from the set, then `revoke` its
  leaves in every other space), `devices` (list,
  last sync, remove, veto, resolve, contests, kit rotation, admin-key
  replacement; each behind the admin key's prompt), `restore` (from a
  kit), `move_home` (§3.9), and local notifications for pending device
  operations (the yearly re-proof is not built, `open.md`). These are the
  facility's own screens (its Android library, `team.virto.vos.personal`),
  over the facility's own Binder interface, `IVosPersonal` (§2.2).
- **Tor in s4's client:** its SSH connection to the gateway goes to the
  onion address pinned at enrollment, through the facility's `TorClient`;
  the host key is pinned as today.
- **The facility's toolchain:** it builds on VOS's pinned nightly because
  of the prover, in VOS (`node/light/android`), s4's crates built with
  `--ignore-rust-version`; s4 builds nothing of VOS.

**The facility's wiring as built** [built, `node/light/android`]:
- **Tor**: one arti runtime in `:vos`, its state in `files/tor`, rebuilt
  through pasted bridges (a `BootstrapError` named by its Display); one
  `Client` whose every space is set from the onions pinned at enrollment
  (the enrollment carries the onion set, each onion with its SSH host key),
  its clearnet only the per-space opt-out of key-signed calls, kept with
  each `refresh_onions` answer as rows of the facility's database. Spare
  connections (a proven call's, a fetch's) are kept for the session last
  granted while the app is in the foreground (§6.2); the client is dormant
  in the background and woken around each job. Every request is `client.request` under its
  purpose: a sign-in's and a payment's proof sent by the facility itself
  (`Proven`; the s4 server gets the node's answer, never the request), the
  node's time (`Fetch`, each session's own reading, kept as an offset
  from the device's clock and read again every 4 to 12 minutes), the
  device window and the tree (`Feed`, a `TreeKeeper` kept beside the
  enrollment), open claims (`Member`), the personal agent (`Personal` for
  what the user does, `Background` for its job). s4's screens to an onion
  service no space pins go over Tor too, on a circuit of their own with no
  host key pinned (first contact, the client's known hosts deciding it);
  `:vos` opens no other stream.
- **The personal space**: every flow of §3.8 and §3.9 and the device set's
  operations, named on `IVosPersonal`; the light node under
  `light/`; the admin key in the UI's Keystore (Ed25519, strong biometric
  only, `IVosPrompts.signKey`). A device's new admin key is signed in by
  the kit (maturing after the kit's delay) or by another seasoned device
  (the new key's 72 h probation): the device offers the key as a code
  (`VOSADMN1:`: the device, the key, its attestation's flags), which the
  other scans and signs once the user compares the key check both show; no
  device signs its own key's replacement. The personal space's job
  is a periodic job of its own.
- **Pairing's code and the kit's card** carry each onion with its SSH host
  key, which the joiner pins to reach the home. The card is shown in the
  kit's own form: beside the phrase's words, or after a security key's
  credential is made.
- **The screens** [built]: one activity of plain views
  over `IVosPersonal`, each operation off the main thread with its
  prompts lent and released when it returns or the screen gives it up.
  A release build keeps every one of them and their forms from capture
  (`FLAG_SECURE`); a debuggable build does not, so its screenshots show
  them [E38].
  A home is entered as its code (`VOSHOME1:` and hex: the home as a device
  reaches it, which its operator publishes); a restore takes the home's
  code too, its handle checked against the card. A pairing's code is a QR
  code (`VOSPAIR1:` and hex) while the opener waits, which the user
  cancels (`pairCancel`: the slot closed, a commit made for the joiner
  abandoned). A security-key kit is a discoverable credential with a
  random user handle, so a restore finds it with no id; a key holding
  several kits answers with the newest. "Backup paused" is Tor's bootstrap
  refusal, on the screen and as a notification after a personal pass that
  did not finish.
- **A regroup** [built, `node/light/android`; host-tested in its
  `tests/personal.rs`]: `regroup` names
  every other live device of the set, and once it matured the
  regrouper's "Commit now" starts the new group of it alone
  (`DeviceGroup::regroup`); each other device, out and its sync key
  admitted no more, pairs again from it, leaving the space it held at
  the pairing's offer (`vos_light::space::Personal`'s leave) and joining
  with new sync and admin keys.
- **Leaving** [built, `vos_light::space`]:
  a device gives up its personal space with no call to its agent: a light
  node store made anew under the next generation's directory
  (`light.<n>`), the local actors installed there, then made the
  device's by its first batch (`p/ready`), which keeps the secret source
  and the label and drops the home, the agent, the admin key's public
  half and every flow's state, and named once written (made under
  `light.<n>.partial`); the old directory is deleted after, or at the
  next open, which takes the newest store named. The old admin key stays
  in the UI's keystore, unused (`open.md`). A move home is a leave and a claim
  (§3.9), the new home
  asked first for all it could refuse (its open claim, an agent to give,
  no agent under the device's nullifier); a pairing
  leaves first when the device holds another personal space, or this
  one's once it is out of it on the log it verifies (its removal read
  through, the log followed first) or was never added, and is refused
  while it is in the set, whatever a refusal says. The light node's
  store is laid out anew (`LAYOUT` 10): a phone of an earlier build clears
  the facility's data and claims or pairs again.
- **One engine, the flows in `vos-light`** [built, `vos_light::space`]:
  every flow is `vos_light::space::Personal`'s, over a `Host` (requests,
  routes, proofs, the enrollments) and `Prompts`
  (the kit's words and card, the source, the admin key), refusing with
  `space::Error`; the facility is their adapter. What the device keeps
  of its personal space is rows of the light store (`p/…`), each written
  in the batch of the group change it describes (`Claim::prepare`,
  `DeviceGroup::join`, `group::restoring`), with no state file
  and nothing to reconcile at open. The facility's enrollments, routes,
  bridges, jobs' runs (with why the last personal pass failed) and a
  restore's kit kind are rows of its own database (`facility/`, its
  layout 1), SCALE of its own types, read strictly. `IVosPersonal.status`
  names the phase (with a restore's maturity), Tor's state, the
  memberships owed, the notices standing, the kind of kit a kit's call
  enters and why the last pass did not finish (standing until a pass
  changes it); the personal flows refuse with `Refused` (a `Why` per
  error kind); a notice carries who signed it, whether it is contested,
  an alarm's kind and its `Remedy`. While a flow runs, `:vos` tells the
  screens its stages (`IVosWatcher.stage`, a `Stage`'s byte: the home
  reached, the proof, the kit written, the log followed; a pairing's
  scan, check, handover and approval), no value or secret in any (a
  sign-in's and a payment's stages, and a sign-in's wait for the
  operator's invitation, are words in s4's chrome instead,
  `IVosPrompts.stage`), and each background pass's end
  (`passed`), after which the overview reads its status again; it reads
  it too on each return to the app, and the device list on each return,
  never on a timer. A removed phone's overview offers pairing again and
  a restore with the kit (which, from a device out of its group, leaves
  it first as a pairing does); "Commit now" from a matured removal's
  notice carries it and revokes the removed device in every space its
  handles name in one flow (`commitRemovals`, one prompt a signature).
  Devices offers "Leave this personal space" on a phone with another
  live device in the set: one confirm that says what happens, one
  biometric, then progress in words ("Signing this phone's removal…",
  then "Your agent took this phone's removal: reading it through, then
  clearing this phone…") and the removed screen, "This phone left your
  personal space and keeps nothing of it", with "Pair again" and "Restore
  with your kit" (`Personal::leave`: the removal signed and posted, the
  log read through to `Out` and the store made anew by the follow that
  read it, `Event::Left`; a leave cut short is read through and
  forgotten by the next pass, and one killed between the two shows the
  removed screen, whose pairing and restore forget first; the other
  phones' next pass raises the matured removal's notice to commit it).
  What stays: the secret source's key and the label, as at a fresh
  install, and the Keystore's admin key, which s4 makes and signs with
  and deletes none of; it signs nothing the agent admits from the
  leave's maturity on, as after every other leave of the store. One test
  double for all of it: `vos_light::testing` (`Phone`, `World`,
  `Reach`) and `vos_testkit::personal::Agent`.
- **Pairing after the set changed** [built, `node/light/android`]: the
  opener reads the log and settles what fell due before its pairing's
  commit, and a replaced admin key is taken before any admin call, so a
  device pairs after a kit rotation, admin replacements or a regroup
  (host-tested with a fourth device after each). The commit is confirmed
  only once every recently active device of the set votes within the
  confirm window (72 h by default): a pairing completes while the other
  devices sync.

### 7.4 The SDK macros and the derivation

- `#[attestable(device)]` methods may take references to fixed-size
  argument types (decoded in place, first among the arguments: built,
  §4.2) and declare `reference = path` and `headroom = k` [built, §4.4];
  the macro and the derivation refuse a device kernel without a
  reference, and the derivation records each reference program by its
  hash beside its kernel (`Derivation::references`).
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

What could bite this design, worked through before code [decided, E11].
Each entry names the situation and its consequence, then its handling: a
**mitigation** or a **known limit** (with where it is carried). Sources
for prior art are in §9.

### 8.1 Devices and keys

**A1. Two devices change the device set at once,** one offline.
*Mitigation:* the agent's log orders operations and commits; one candidate
per epoch (`EpochTaken`); the loser rereads and re-proposes only if its
intent still holds; no device commits offline.

**A2. A device is lost or stolen, locked.** Before its first unlock since
boot nothing opens. After a first unlock the sync key and the MLS state
work while the screen is locked, so a thief who keeps the phone powered
and runs code on it reads the personal space; the admin key stays in the
hardware keystore behind the owner's strong biometric. *Mitigation:* the
owner retires the phone from another device (§3.8) or with the kit.
*Known limit:* after-first-unlock exposure, the price of background sync
on a locked phone; stated in the light node's `SECURITY.md`.

**A3. A device is stolen unlocked, or malware runs in the app's process.**
Either reads what the phone reads and holds its sync key: it can push
garbage (C1), nack commits (A21), post `alive` and use the device's share
of the quota (C5). It can neither commit nor sign a device-set operation:
both need the admin key, which never leaves the hardware keystore and
signs only after the owner's biometric. The kit removes it even with no
other device (A4). *Known limit* for what the phone shows.

**A4. A thief who passes the owner's strong biometric** (coercion, a weak
sensor) holds an active device. *Mitigation:* the symmetric rules (§3.5):
he removes nothing uncontested while the owner vetoes; the owner wins a
contest with one device and the kit, or two other seasoned devices with
strong admins; a
thief holding only a sync key loses even to the kit alone, in 14 days (its
removal cannot be vetoed without the admin key, and a removed device's
`alive` is ignored). *Known limit,* and only this: a thief who passes the
biometric can always contest, so against him the kit alone does not win.
Property-tested against an adversary with one device and its biometric
who may also pair devices, and one with a sync key alone, and a leaked kit
against devices that veto (`agent/testkit/tests/agent/personal/
adversaries.rs`): the owner reacting before a paired device's probation
ends removes every thief device within the delay of its first move.

**A5. A device returns after weeks or months.** *Mitigation:* while away
it is outside the confirming set, so the awake devices are never blocked;
it processes the confirmed commits on return (handshakes are kept 180
days) and re-pairs if one does not process or if it was away longer.

**A6. A long replay on a phone,** killed midway. *Mitigation:* each commit
applied in one fjall batch, the stored epoch checked before and after; a
gap of more than a few hundred commits prefers re-pairing.

**A7. A removed device backdates DAG writes.** *Mitigation:* seal at push
takes only the confirmed epoch; the agent refuses its keys; devices accept
its envelopes only up to its frontier, and the CRDT types filter its
writes at read; the light node cuts it off there, so its later operations
are quarantined wherever they arrive [built]. Nor does it leave a
writer behind: an archive names no author, and an archive read takes no
key of an epoch past the confirmed one [built].

**A8. A write made offline leaks to a device removed meanwhile.**
*Mitigation:* seal at push under the confirmed epoch read just before;
`StaleEpoch` otherwise.

**A9. A device takes a candidate as current before it is confirmed,** the
first cause of forks in deployed MLS. *Mitigation:* candidates are
processed on a copy of the group state and swapped in only on
confirmation (mls-rs applies received commits at once, so the copy is the
mechanism).

**A10. Retries and leader changes.** *Mitigation:* the queue keeps sealed
bytes and reseals only after `StaleEpoch`; the agent deduplicates by id
before the epoch check; a commit is a candidate once.

**A11. An OS backup or a cloned phone restores MLS state on a second
device.** *Mitigation:* MLS state, the archive and the queue are excluded
from Android's backup and wrapped under a key that does not migrate; a
restored copy starts as a new device (A13). A clone's commit cannot be
confirmed consistently and is voided.

**A12. The user's biometrics change,** invalidating the admin key.
*Mitigation:* another seasoned device, or the kit, signs a replacement
admin key; the device keeps its seasoning, and the new key signs nothing
for 72 h.

**A13. The app is reinstalled on the same phone.** Keystore keys are gone;
the phone is a new device. *Mitigation:* it pairs from another device or
restores from the kit, then removes its own ghost, which never confirms
and so blocks nothing meanwhile.

**A14. A thief who passed the prompt pairs his own device** to gain a
second vote. *Mitigation:* the new device is in probation for 72 h, its
probation frozen while a removal against it is pending or contested, and
it counts for two-device rules only after 7 days' seasoning; so the
owner's removal of it, contested by the thief, cannot be outvoted inside
its own window.

**A15. Clocks are wrong.** *Mitigation:* delays, probation, seasoning,
retention and the lease run on the agent's batch time; a device whose
clock disagrees by more than an hour raises an alarm and acts as the log
says; Lamport counters order CRDT operations.

**A16. A committer forks the group selectively,** good path secrets to
some devices and garbage to others. Committing needs the admin key, so the
committer is the owner's own device or a thief who passed the biometric
(A4). *Mitigation:* an awake target nacks and the epoch is void, nothing
sealed; a sleeping target, outside the logged confirming set, finds on
return that it cannot process the commit, raises an alarm naming the
committer, and re-pairs or regroups (§3.5).

**A17. A commit carries a proposal the design does not use** (ReInit, an
external commit, a PSK, a group-context change). *Mitigation:* `vos-mls`'s
policy for the device group nacks anything outside Add, Remove and Update,
and any Add or Remove not matching a matured signed operation.

**A18. A device without a strong biometric.** *Mitigation:* a delayed
admin: its operations wait 72 h and can be contested; pairing works, 72 h
later.

**A19. A shoulder-surfed PIN.** The thief signs in and pays from P1 (the
member secret keeps its decided PIN fallback) but cannot sign a device-set
operation unless the device is a delayed admin, whose operations wait and
can be contested. The owner retires the phone, which revokes its leaves in
every space at once. *Known limit:* P1 money has the lower bar; `rekey` is
its remedy.

**A20. Two attacker devices nack each other's removal.** *Mitigation:* one
commit carries both matured removals, and nacks from devices whose
removal has matured are ignored.

**A21. A device nacks every commit** (a bug, a thief). Key changes stall,
not data. *Mitigation:* its removal's commit needs nothing from it; the
chrome names the device that nacks.

**A22. Phone replacement every two or three years.** *Mitigation:* "retire
this phone": pair the new one (enrolled in every space at once), then
remove the old one, revoke its leaves everywhere, and offer to wipe it.

**A23. A sync-key thief waits for the owner's other device to go quiet,**
then commits garbage to it. *Mitigation:* a commit is an admin call,
verified at ingress and by every device through its evidence, so a sync
key alone commits nothing.

**A24. A device cannot follow the confirmed epoch and has no device to
re-pair from** (a buggy commit, a lost committer, a lockout). *Mitigation:*
a regroup signed by its admin key: 72 h and a veto, or at once with two
seasoned devices or the kit (§3.5); it keeps its regrouper alone, and
the other devices pair again from it.

**A25. A device leaves** (its owner retires it from itself; or a thief
holding it, the biometric passed, signs the leave). *Mitigation:* a leave
only lowers its signer's power (§3.5, rule 10): it matures with its
evidence and gives no one a voice, so a thief's leave of a stolen phone
is the retirement the owner wanted, at once. During a contest that
targets the leaver, the leave concedes it: the removal of it ends `Moot`,
the leaver's removal of its rival is cancelled with its silencing.
*Known limit:* until the other devices commit it, the left device's leaf
holds the epoch's keys, as after any matured removal (it forgot them at
once if it was the owner's own leave; a thief who kept a copy reads until
the commit, as A2's thief does before the owner's removal), and the
commit re-seals `R`. The last live device cannot leave (`Alone`): no
device would commit it; a restore with the kit replaces it.

### 8.2 The home space and its operators

**B1. The operators withhold or delay sync.** *Mitigation:* devices work
offline and are full replicas; after 7 days without the agent the chrome
offers to move home.

**B2. The operators delete envelopes.** *Mitigation:* each device fetches
a sample of positions it pushed and re-pushes what is missing.

**B3. The operators roll the agent back.** *Mitigation:* a control log
shorter than, or diverging from, the highest view a device saw raises an
alarm.

**B4. The operators equivocate** on commits or on operations.
*Mitigation:* two commits for one epoch give two signed `h` and a void;
views in envelopes catch a split control log. *Known limit:* nodes sign
nothing a device can show a third party, so an alarm is not proof
(`open.md`, "Node-signed feed heads").

**B5. The operators inject or replay.** A forged envelope fails its AEAD; a
replayed one is a duplicate; a replayed commit breaks the epoch rule; a
replayed device-set call names a place the device has passed (B6).
*Mitigation:* as stated.

**B6. The operators forge device-set operations.** *Mitigation:* every
device verifies every operation's and confirmation's signature itself,
from the evidence stored beside it; an operation without evidence moves no
device. Nor does a refusal: a removed device is out on its removal's
evidence, which the agent serves its key (§3.6, the pass), and a refusal
the route makes up stops a pass, never removes a device (`NotAdmitted`).
Nor a replay: every device-set call names its place, the log's head its
signer read, and is taken only if no admin call was logged between that
place and the call, by the agent and by every device,
so a signed removal once vetoed logged again on a forked log is refused
(§3.5, "The place"; §3.6). *Known limit:* a device that has not read a
veto can be shown the operation without it (withholding, B8).

**B7. The operators advance the agent's clock,** maturing a hostile
removal or a restore early. *Known limit:* delays trust the operators'
clock; devices alarm on more than an hour's skew; it helps only a thief
who already passed the biometric (A4) or holds the kit (D3), or B8.

**B8. The operators collude** with a thief or a removed device: dropping
vetoes, ordering the thief's operations first, placing a removed device's
backdated writes before its frontier, marking awake devices absent, and
serving a removed device data sealed before its removal's epoch is
confirmed, for up to 72 h after the 72 h removal delay, six days in all.
**Acting alone,** they can hold back a genuine admin-signed commit until a
device is quiet and name it absent in the logged confirming set, locking
it out until it re-pairs or regroups; they cannot make a commit. Nor can
they shorten a delay (a later `Configured` lowers none on any device,
§3.4), nor keep the old `R` in force past a removal by logging `Void`
over the devices' own count (§3.5), nor silence a view or a dropped call
by naming a head they do not serve (§3.6) [built].
*Known limit:* the home is trusted for availability, order and time
(`core-model.md` §5); the owner's remedies are two seasoned devices'
immediate removal and moving home.

**B9. The agent loses its quorum.** Sync and device changes stop; local
work continues. *Mitigation:* devices queue and retry; the lease counts
re-proofs, not uptime.

**B10. A home with one replica.** *Mitigation:* the chrome shows the
replica count; devices remain full replicas. *Known limit:* losing that
disk and every device at once.

**B11. The pool runs out,** or the open claims' daily cap is reached.
*Mitigation:* `Homes` answers `PoolEmpty`, the designed symptom (the cap
is kept below the keeper's refill rate so the disk never fills first); the
keeper tops up, the device stays local and retries.

**B12. `Homes` assigns one agent twice, or one nullifier twice.**
*Mitigation:* unique Linear indexes in `Homes`; `assigned`/`refused`
replies.

**B13. A user's second device claims a second agent** (its nullifier
differs under E2, so `Homes` cannot tell). *Mitigation:* the chrome
refuses a claim on a device that already holds an archive. A
person that churns devices instead, revoking one and enrolling another
for a fresh nullifier at each round, is held to its enrollments of the
year at a home that is the user's own space: its limit and two
replacements (§3.8), so at most that many agents a period, each lapsing
13 months after its last re-proof, which a revoked leaf cannot make. At a
home-only space only the claiming device makes an open claim, under the
period's cap.

**B14. A member is expelled, or stops re-proving.** *Mitigation:* the
lease lapses 13 months after the last re-proof; the agent then refuses
pushes for 180 days of grace but serves reads and a restore, so the
data stays recoverable (E15). Each device's home nullifier is recorded at
its add, so a device with a leaf at the home can re-prove even after the
claiming one is gone. *Known limit:* reaping after the grace is later
work; no device re-proves yet, and a joiner holds no leaf at a home-only
home to prove with (`open.md`).

**B15. The user stops using every device** with the kit in a drawer.
*Mitigation:* the lease needs only one re-proof a year; past it, the grace
leaves 180 days for a restore. *Known limit:* the re-proof flow is not
built, so every agent lapses 13 months after its claim (`open.md`).

**B16. The home vanishes or turns hostile.** *Mitigation:* move home by
leaving, claiming at the new home and pairing again (§3.9; nothing
carried): the books are written again by every device. *Known limit:* a scope's history stays at the old home; a reused
kit links the two agents for the two homes' operators together; a
successor group and a live handover are later work.

**B17. Personal agents fill the space's disks.** *Mitigation:* a 64 MiB
default quota; the scale gate measures a full agent's snapshot and a
`replace` against limits.

**B18. `Personal` is upgraded over agents that hold data** (`Install`
touches no table; migration is unbuilt). *Mitigation:* an append-only
layout across versions, an upgrade test over a populated agent, and the
keeper upgrading in batches and stopping at the first refusal. *Known
limit:* a hostile upgrade is B8.

**B19. The operators show each device only its own envelopes**
(partition). *Mitigation:* every envelope carries its writer's `seen`
positions; a reader served less of a scope than a writer had read raises
the alarm.

**B20. The home space re-founds** (a new `SpaceId`, members re-enroll).
The agents and `Homes`' indexes survive if the agents do; the "home"
scope includes the space, so nullifiers change. *Mitigation:* each device
re-records its new nullifier at its next re-proof; the kit carries the
home's stable handle, not its `SpaceId`. *Known limit:* the re-recording
is not built; it waits for the re-founding runbook (§3.3, "`Homes` as
built").

### 8.3 Data, storage and quotas

**C1. A device writes garbage** that opens correctly. *Mitigation:* apply
validates each operation; one that fails is quarantined and the chrome
names its author [built: `Light::quarantined`]. *Known limit:* excising a
device's range after the fact is later work; the remedy is removing the
device.

**C2. The DAG grows without bound, or a user stores media.** *Mitigation:*
the quota bounds the agent; the push API is blob-ready. *Known limit:*
checkpoints, which would let new devices start late, garbage collection
and a blob store are later work (`open.md`); media fills the quota fast.

**C3. Two devices checkpoint at once.** Checkpoints are not built; their
design cuts them at agent positions, so both would hold the same state
(`open.md`).

**C4. A shortened scope served to a new device.** Every device replays
each scope from its start (checkpoints are not built, `open.md`). *Known
limit:* a newly paired or restored device can be served a shortened
scope (its last envelopes withheld) without an alarm: it has read no
position to hold the operators to, and raises `Partition` only once a
later envelope's `seen` position crosses the cut.

**C5. Quotas fill,** perhaps to block the filler's removal. *Mitigation:*
operations, the commits carrying them, confirmations and `alive` are
exempt; each device has an unadvertised share.

**C6. Large objects.** A 1 MiB object is 17 envelopes and 17 pushes.
*Mitigation:* chunking; the scale gate pushes envelopes of the largest
size (§3.3); the API is blob-ready.

**C7. Inbox spam.** *Mitigation:* only the user's devices and a slot's
holder write; slots are single-use and last 10 minutes; admission by known
keys.

**C8. Sizes and timing describe the user.** *Mitigation:* Padmé padding,
opaque scope ids, structure inside the ciphertext. *Known limit:* counts,
times and the epoch counter remain; foreground sync follows app use; no
cover traffic.

**C9. Two key archives disagree.** *Mitigation:* every candidate key is
kept and the AEAD decides.

**C10. Fetching on demand reveals what the user reads.** *Mitigation:*
devices are full replicas, fetching on a schedule; member trees stay
device-local. *Known limit:* a device too small for a full replica, and
a wallet's mirror of a large pool, are later concerns (`open.md`).

**C11. The phone's storage fills.** *Mitigation:* the local store refuses
writes before the disk fills; sync pauses; the chrome says so [built:
`Error::Full` below the reserve, §2.1]. *Known limit:* a disk another app
fills past the reserve fails fjall's write, which refuses every write
until the store is opened again.

**C12. Years of history for a two-device user.** *Known limit:* a new
device replays each scope from its start; taking its pairing device's
checkpoint instead is later work (`open.md`).

### 8.4 Recovery and the device's life

**D1. Every device is lost; the kit is kept.** *Mitigation:* restore: 7
days with no veto and no `alive`, then `R2` released, the recovery
envelopes opened (they follow every confirmed epoch), a new group, the kit
rotated; memberships re-enrolled by each registrar's ordinary process,
whose cost the chrome states; P1 accounts by `rekey`. *Known limit:* the
kit holds keys, not data; a home gone or withholding at that moment leaves
it nothing; the encrypted export file is later work (E16).

**D2. Every device and the kit are lost,** or a single device with no
backup dies. *Known limit:* the personal space is gone; memberships and
P1 accounts come back by each space's process. The app offers backup at
first launch and after (§3.1).

**D3. The kit leaks** (a photo of the phrase in the stolen phone's gallery
is the likely way). *Mitigation:* alone it opens `R1`, not `R2`; its
restore waits 7 days and dies at any device's `alive` or veto, and every
device is told loudly for those 7 days; the security-key kit cannot be
photographed, and the chrome never shows the words as a QR; the owner
rotates the kit, deleting the old `R2`; a restore always rotates it.
*Known limit:* the operators and a leaked kit together read everything;
a thief holding the kit, a phone and the owner's biometric wins (A4). A
removed device is not a leaked kit: `R` rotates at every removal (the
committer draws a new `R`, seals `R1` to the kit and stores `R2` at the
agent), so the operators and a removed device read nothing the recovery
scope holds after its removal.

**D4. The kit points at old onions.** *Mitigation:* the kit carries the
handle and the onions at the claim; the agent is found by the kit's key.
*Known limit:* a home whose onions all changed is found only through the
registry of spaces, not built.

**D5. The background job does not run** (the "rare" or "restricted"
bucket, a force-stop, an OEM battery manager, a cold Tor bootstrap that
eats the job's 30 s). *Mitigation:* the chrome shows each device's last
sync and recommends the battery exemption; PG6 records these cases,
which the windows are pinned against (§2.4). *Known limit:* a device whose job never
runs neither vetoes nor posts `alive` until the user opens the app.

**D6. Android kills the process mid-write.** *Mitigation:* each local
operation, MLS state change and queue change is one fjall batch; pushes
and commits are idempotent.

**D7. A local actor's new version changes its state's shape.** *Known
limit:* state migration is unbuilt; such an actor starts a new scope and
the device re-imports.

**D8. An app release and a space's upgrade land days apart.**
*Mitigation:* compatibility windows: each stock guard admits the current
and the previous release's program ids, and ingress the current and
previous device formats, for 60 days or until the operator retires the
previous one, at once if it is found unsound; the two versions compute the
same claims; the light node proves with the newest program the space
admits.

**D9. Devices run different app versions.** *Mitigation:* versioned
operations; unknown kinds and later releases wait for the update
[built, §3.2].

**D10. The security key is lost** (the kit of that kind). *Mitigation:* a
second kit (the phrase, or a second key) is offered at the claim; rotation
from any seasoned device replaces it.

**D11. The UI is swiped away, or crashes, mid-proof or mid-sync.**
*Mitigation:* the light node runs in its own `:vos` process [E21]; the
UI's death does not touch a proof or a sync, and a crash in `:vos` leaves
the UI to report it.

### 8.5 Cryptography's future

**F1. Harvest now, decrypt later.** *Mitigation:* a hybrid post-quantum
suite once mls-rs maintains one (it does not: an X-Wing suite on a
private code point behind an unstable feature of the aws-lc provider,
§3.4 [read 2026-11-02]), then by a successor group (F2); 180-day
retention of handshakes.
*Known limit:* a hostile operator keeps what it wants.

**F2. Changing the suite or the protocol.** *Mitigation:* a successor
group, archives resealed, old envelopes left under their keys; never two
suites in one group. Later work.

**F3. RFC 9420's exporter is not forward-secure.** *Mitigation:* moot for
history; the Safe Exporter when mls-rs has it.

**F4. An mls-rs defect, or its version churn.** *Mitigation:* `vos-mls`
holds the one pinned version for VOS, upgraded at regular steps; a state the
new version cannot read means re-pairing that device.

### 8.6 Proving and payments

**G1. Junk proofs.** *Mitigation:* the format's PoW, the in-flight caps
and the verification budget; Tor bounds the rate; the pre-check is a
target.

**G2. A space installs a kernel that leaks a secret.** *Mitigation:*
secrets enter only kernels the light node ships, by program ids embedded
at release (§4.4).

**G3. A space upgrades a stock kernel.** *Mitigation:* the window admits
the previous program for 60 days unless retired sooner, both computing the
same claim; past it, the light node says which side must update.

**G4. Balances split per device** (E2). *Known limit:* a payment comes
from one device; consolidating under P1 is a visible transfer (L4).

**G5. A developer's own kernel wants the user's private data.** *Known
limit:* only data the user hands it, never keys (§4.4).

**G6. A sign-in misses its target.** *Mitigation:* PG2′'s gate is 0.65 s,
the target 0.55 s (§2.4); format 47 ships at what it measures under the
gate, and the 4-way CPU split is the next lever (`open.md`).

### 8.7 The network

**H1. The onion is flooded** before arti's service PoW is declared ready.
*Mitigation:* introduction-point, SSH-connection, circuit, per-agent and per-onion caps;
the in-flight cap on large requests; Tor's own throughput bounding junk
proofs; a flood measured through Tor (§6.6).

**H2. Tor is blocked on the user's network.** *Mitigation:* plain bridges
pasted in the chrome defeat blocking by the public relay list [E22].
*Known limit:* against deep packet inspection there is no pluggable
transport, so anonymous calls and the personal space wait, saying so, and
the personal space's veto and `alive` windows run without the device;
key-signed calls may use the clearnet where the space allows it and the
user opted out for it (§6.5).

**H3. arti's library breaks monthly.** *Mitigation:* one pinned version a
release, upgraded at regular steps.

**H4. A background job starts cold.** *Mitigation:* arti's state
persisted; an unfinished job leaves everything consistent and the next
resumes (D5).

**H5. A gateway's onion key is stolen.** *Mitigation:* the pinned set is
refreshed from the registrar. *Known limit:* answers are unsigned.

**H6. A gateway lists only some nodes** of a home. *Mitigation:* a home's
gateways list every node (§3.3); a gateway that cannot reach an agent
answers 421, which the client reports. Forwarding is later work.

**H7. Strangers flood a personal agent** (agent ids are sequential).
*Mitigation:* known keys only, looked up before the signature check; the
onion-only mark; per-agent circuit caps; gated queries.

**H8. One rendezvous per poll.** *Mitigation:* the tree feed on one
long-lived circuit (§6.7); PG5 counts rendezvous (§2.4).

**H9. A wrong clock stops Tor.** *Mitigation:* the chrome names the clock.

**H10. One SSH connection could join two identities.** The light node
reaches every gateway through SSH over the onion (E23); one connection for
everything would let the gateway link the member's calls, proven calls
and the personal agent by their shared SSH session. *Mitigation:* one SSH
connection per isolation group, each on its own circuit and under an SSH
key drawn for it alone; a session's spare connections (a proven call's,
a fetch's) are made ahead, one at a time after drawn delays, each used
once, kept for that session alone (§6.2).

**H11. A user opts out of Tor for a space.** *Mitigation:* the opt-out
covers that space's key-signed calls and its screens only, after a
plain warning that its operators can then join the device's address to
the sign-ins and payments asked on its screens; proofs and the personal
agent stay on Tor whatever the user chooses [E22].

### 8.8 Linkability and membership

**L1. The claim follows the user's sign-ins.** *Mitigation:* at a
home-only space (the default) the user has no other sign-ins there.
*Known limit* at a home that is the user's own space (§3.10).

**L2. One device acts as a member and as the pseudonym.** *Mitigation:*
separate Tor isolation groups, keys used nowhere else. *Known limit:*
foreground sync starts when the user opens the app.

**L3. Push-notification tokens identify the user.** *Mitigation:* none is
given to any space; devices poll and raise local notifications.

**L4. P1 transfers between one's own devices** link their owner digests.
*Known limit:* P1 is pseudonymous; P2 would hide it (`open.md`).

**L5. Device changes and counts link the agent to the member.**
*Mitigation:* at a home-only space only the claiming device joins, by an
open claim, and the registrar has no person to count. *Known limit* at a home
that is the user's own space, stated in the app.

**L6. `once` scopes with one leaf per device** admit a member once per
device [decided]. *Known limit,* stated in the space's chrome;
person leaves are later work (`open.md`).

**L7. The registrar learns which device leaves are one member's**
(`enroll_device`). It already knows each member; the tree still hides
which leaf proves. *Known limit,* stated.

**L8. Path fetches and the logged `map_root`** link a member's proofs.
*Mitigation:* the credential tree's feed; a gateway that ends its
answers early marks the root a logged proof names for the root's grace
alone, 90 s after the change it held back (§6.7). *Known limit:* within the
grace, the split an honest keeper one period behind shows; node-signed
feed heads are later work (`open.md`).

**L9. A space's page asks the device to prove in the "home" scope.**
*Mitigation:* the scope is reserved by the facility.

**L10. Other members read a personal agent's control log** (any key may
query). *Mitigation:* `Personal`'s queries answer only admitted keys.

**L11. Open claims at a home-only space are a Sybil door.** *Mitigation:*
a bound on griefing, not a price: the daily cap sized to the home's disk,
the quota ramp (8 MiB until the first re-proof), and work that stops only
the trivial loop; nothing an open member can do reaches another user's
agent.

## 9. Sources

Read 2026-11-02 unless marked.

**Tor and arti** (§6):

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

**The prior art** (§3, §8):

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
- draft-ietf-mls-pq-ciphersuites-06 (2026-07-21):
  https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-06 ;
  mls-rs 0.57.0 and mls-rs-crypto-awslc 0.27.0 (2026-10-28), their
  sources `mls-rs-core/src/crypto/cipher_suite.rs` and
  `mls-rs-crypto-awslc/src/lib.rs`: https://github.com/awslabs/mls-rs
  (read 2026-11-02)
