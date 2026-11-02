# The light node, one proving path, private payments and Tor

Design, draft 1 [proposed]. The architecture of slice 8
(`slice-8-plan.md`): a light node of VOS on the user's devices, one proving
path for every device statement, payments rebuilt on cipher-clerk as the
showcase of attestable Rust, and clients reaching a space over Tor.
- **Status:** everything here is [proposed] unless tagged [decided] (an
  owner decision, quoted or cited) or [built] (what `vos-core` holds at
  `6c4b4f49a`).
- **Numbers** carry their tag: [measured] (a run, cited), [model] (the
  7.18 cell model, `git show 6c4b4f49a:docs/design/research/slice-7/7.18-cell-model.md`),
  [est] (arithmetic on those, unmeasured).
- **It amends:** `proving.md` §8 (the credential AIR retired),
  `identity-and-authority.md` §5–§8 (credentialed calls generalized, the
  personal space and the shielded pool unpostponed), `core-model.md` §9.4
  (the Merge lane on devices) and `node-api.md` §6 (the gateway's onion
  service). Those documents keep their text until the steps that change
  the code change them.

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
if it means re-designing it."

**Goals:**
1. **A light node, not a proving library.** `vos-device` becomes a light
   node of VOS: the PVM runtime running local actors, a local store, the
   device prover, a node-API client and merkle-crdt sync. It runs on the
   phone, inside s4's Android client.
2. **The user's private space across devices.** Local-only actors hold the
   user's private data (notes, keys, credentials, contacts); the user's
   devices sync them with merkle-crdt, never through a space's Raft log.
3. **One proving path.** Every statement a device proves is an
   `#[attestable(device)]` kernel written in Rust and proved by the general
   zkVM under the device profile. No hand-written circuit outside the
   recursion: the credential AIR (format 44) and its code are deleted.
4. **Payments as the showcase.** A short, readable pair of actors, a public
   payments actor in the space and a wallet actor on the light node, built
   on cipher-clerk, whose spend is one Rust function proved on the phone.
   Private in the note-and-nullifier sense, reached in stages.
5. **Fewer pieces.** No new crate without one retired beside it; the slice
   ends with fewer crates, formats and fixtures than it started with.
6. **Network privacy.** Clients reach a space's gateway as a Tor onion
   service through arti embedded on both ends, so no node or gateway
   learns a member's network address.
7. **The rule stays:** `vos` and the node know no JAM and no Kreivo
   [decided, 2026-10-23]; the same holds for Tor (§6, §7).

**Non-goals for slice 8:**
- A shared shielded pool across spaces, or one whose integrity does not
  trust its space's operators (a JAM agent or a proving space;
  `identity-and-authority.md` §8 and its open question 3). The pool here is
  in one space, private from its operators, its supply integrity theirs
  (§5.6).
- Byzantine devices inside a personal space, or a personal space with more
  than one person.
- Full nodes replicating Merge scopes, and the Merge lane on JAM
  (`core-model.md` §2).
- Signature chips (P-256, ed25519; `proving.md` §8 part 3), recursion of
  device proofs, and device proofs at a venue.
- iOS. The design keeps it possible (nothing here is Android-only below
  the secret store), but no step builds it.
- Our own anonymity network, or mixnets (Nym). Tor only.
- The extension host [decided, deferred past the slices].

## 2. The light node

### 2.1 What it embeds, and what it does not

| part | what | from |
|---|---|---|
| **PVM runtime** | the interpreter, its machine pool and inner machines; no JIT (the recompiler is x86-64 Linux only, `pvm/runtime/src/lib.rs`) | `vos-pvm` [built] |
| **the agent program** | the default agent, `vos-agent`, unchanged: local actors are installed into it as into a node's agent | `agent/default` [built] |
| **a single-replica host** | refine and accumulate driven by a local loop over a local log; the actor ABI's host calls; no Raft, no leader, no peers | carved from `vos-node` (§7.1) |
| **local store** | fjall, as the node's, with small caches (8–16 MiB block cache [est]) | `vos-node`'s `store` [built] |
| **device prover** | the device profile (format 46, or its successor after the levers, §4.4), masked, `Threads::Auto` | `vos-pvm-proof` + the masked device segment, today in `vos-pvm-recair` (§7.1) |
| **node-API client** | the multiplexed `vos-api` client over any futures-io byte stream: an arti onion stream (§6), or SSH's `vos-api` subsystem as today | `vos-api` [built] |
| **sync** | merkle-crdt DAGs of the local actors' Merge fields, its `Store` over fjall, encrypted end to end (§3) | `support/merkle-crdt` [built, no dependent today] |
| **secrets** | the personal-space root secret, wrapped at rest by the platform's keystore (§3.5) | `vos-device`'s `secret` [built, changed] |
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

**Recommended: a library behind a facility, in s4's client process**
[proposed; option (a) of §8 Q5].
- The light node is one Rust crate, `vos-light` (§7.1), linked by s4's
  facility cdylib (today `s4-credential`, `~/src/virto/s4-vos/credential`,
  which links `vos-device`, `vos-api` and `vos-wire` by one VOS revision).
  The facility is renamed `vos.node` and grows the operations of §7.3.
- **One runtime, one arti:** the facility owns a multi-threaded tokio
  runtime today (its `ffi` feature); the light node runs on it, and arti's
  `TorClient` is created once on it. s4's own SSH connection to the
  gateway's onion goes through the same `TorClient`, handed to the client
  as a connector, so a process bootstraps Tor once.
- **Lifecycle:** the light node lives while the app is in the foreground
  and for a short grace period after; background sync runs as a
  WorkManager periodic job (Android's floor is 15 minutes), which opens the
  store, bootstraps arti from its cached directory, syncs and exits. No
  foreground service, no persistent socket, no wake lock beyond a job's.
- **Isolation (option):** the facility in a separate Android process
  (`android:process=":vos"`, Binder between them) keeps the prover's peak
  and the secret's unwrapped bytes out of the UI process and lets the OS
  kill it alone. It costs a Binder interface for every operation and a
  second runtime; recommended later, not in slice 8.

### 2.3 Memory and battery budget

| state | budget | basis |
|---|---|---|
| idle, foreground (store open, arti bootstrapped, no proof) | ≤ 96 MiB resident, of which arti ≤ 48 MiB | [est]: interpreter and pool a few MiB, fjall's caches 8–16 MiB, arti's directory and circuits (§6.4) |
| local actor call | ≤ 1 ms on the interpreter | 85 µs an invocation on the node's interpreter [measured, `core-model.md` §14], with the fsync of a local commit dominating |
| proving a sign-in | ≤ 1 GiB peak (target 768 MiB) | PG2's [decided, S3, S20, S27]; 513 MiB measured [measured, P7] |
| proving a spend (1 in, 2 out) | ≤ 1 GiB peak | [est], §5.7 |
| background sync job | ≤ 30 s wall, ≤ 1 MB down a run with nothing new | [est]: arti from a warm directory, one onion connection, the relay's heads |
| battery | no work while backgrounded beyond the periodic job; no persistent circuit | the design's rule, measured by the plan's PG5 |

Proving is the only heavy phase: 0.6 s of four big cores at full load a
sign-in [measured, P8: 645 ms], about 1 s a spend [est]. A phone that
signs in twenty times a day spends about 15–20 s of big-core time on it
[est], far below a screen-on minute.

## 3. Local actors and the user's private space

### 3.1 The personal space

A **personal space** is the user's devices running the same local actors
on one shared root secret, kept in agreement by merkle-crdt. It is
`identity-and-authority.md` §8's personal space ("the VOS runtime inside
the person's wallet app"), across devices instead of one, and it needs no
node of a space: its devices are its only replicas.
- **Its actors are ordinary actors** (`#[actor]`, `#[messages]`), built and
  installed as any package is, whose state is Merge-lane only: CRDT fields
  and `#[msg(merge)]` handlers (`core-model.md` §9.2), plus `&self`
  queries. A personal space has no Linear state, no workflows touching
  other spaces' logs, and no Raft (`core-model.md` §9.4's "Merge-only
  agents").
- **The first local actors:** the wallet (notes and nullifiers, §5.4), the
  credential book (the spaces the user is a member of, their handles, the
  pinned agents and methods that s4's facility pins today), and the
  device set (§3.4).
- **Each actor instance is one sync scope:** one merkle-crdt DAG, so a
  device syncs scopes, not the whole space (`core-model.md` §9.4's "one
  DAG per sync scope").
- **Deterministic apply:** a merge handler's effects depend only on its
  operation, so every device that applies a DAG converges. Randomness and
  time come from the device that issues an operation and travel inside it.

### 3.2 What syncs, and the conflict model

- **What syncs:** each scope's DAG nodes, each a batch of CRDT operations
  with stable ids, its parents and its author (`core-model.md` §9.4).
  Never the store's rows, never proofs, never the secret.
- **The CRDT types the SDK gives, first:** `crdt::Set<T>` (an add-wins
  observed-remove set), `crdt::Map<K, V>` (last-writer-wins a key, its
  clock a Lamport counter and the author's id), and `crdt::GSet<T>`
  (grow-only). Storage-backed, as `core-model.md` §9.4 requires; the v2
  `List` is not carried.
- **The conflict model** is the types' own: concurrent adds both stay, a
  remove wins only over the adds it observed, a map key's later write wins
  by (counter, author). No operation needs another device's agreement.
- **Where conflicts are real, the public space decides:** two devices that
  spend the same note at once both send a spend; the pool admits one
  nullifier once (§5), refuses the other, and each wallet learns the
  outcome from the pool's feed. The wallet's state is a CRDT (notes
  received, nullifiers spent: two grow-only sets, unspent = their
  difference), so the merge never has to choose.
- **Incremental apply** [decided by S6, `core-model.md` §9.4]: merkle-crdt's
  DAG and sync format are reused and its apply path rewritten to apply only
  newly fetched nodes in causal order (S6's prototype: about 1.9 µs an
  operation at 1M operations, against 8.7 s for today's library).

### 3.3 Transport and encryption

**Encryption:** every DAG node is sealed before it leaves a device.
- `k_sync = BLAKE2b-256("vos/personal/sync/v1" ‖ m)`, `m` the root secret
  (§3.5); a node's sealed form is XChaCha20-Poly1305 under `k_sync` with a
  random 24-byte nonce, its additional data the scope's id.
- **A node's CID is computed over its plaintext,** as merkle-crdt computes
  it (so dedup and causal links work), and **a relay stores it under
  `BLAKE2b-256(k_sync ‖ cid)`**, so a relay cannot confirm a guessed
  operation and sees only sealed bytes, their sizes and their times.
- **Authorship:** each device signs its nodes with an ed25519 author key
  drawn at install (`core-model.md` §9.4's "a device takes a fresh author
  key on every install or restore"); the device set (§3.4) lists the
  author keys; merkle-crdt's `NodeValidator` (`sync_validated`) refuses a
  node whose author is not in the set as of its causal past.

**Transport, in order of preference:**
1. **Through the space's relay, over Tor** [recommended first]: a relay
   actor in a space the user is a member of (§7.2), holding sealed nodes
   per mailbox. A mailbox's id and its write key derive from `m`; the
   space's operators see a mailbox's activity (counts, sizes, times), not
   its contents, and not the devices' addresses (§6). It needs nothing a
   space does not already run: calls and queries over the node API.
2. **Direct, on one network:** two devices on one LAN find each other
   (mDNS) and sync over QUIC authenticated by their author keys. No relay
   learns anything. Later than slice 8 (a listening socket on the phone,
   battery).
3. **Not chosen:** iroh's relays and hole punching (a second network stack
   and its relays beside Tor, and no Tor support), a public
   store-and-forward service (a third party learning the mailbox's
   timing).

**Bootstrapping a device without the whole history:** a device's
checkpoint is a sealed snapshot of a scope's state at a set of heads,
stored at the relay beside the nodes; a new device fetches the newest
checkpoint and the nodes after its heads. The Linear-emitted chain of
`core-model.md` §9.4 is a full node's mechanism and not needed here.

### 3.4 Enrolling a new device

1. **The existing device** (A) draws a pairing code (128 bits) and an
   ephemeral X25519 key, opens a pairing mailbox at the relay, and shows a
   QR code: the relay's space and mailbox, A's ephemeral key, the code.
2. **The new device** (B) scans it, draws its own ephemeral key and an
   author key, and runs a PAKE (CPace over ristretto255, keyed by the
   code) with A through the mailbox. The code authenticates both sides; a
   relay that substitutes keys fails the PAKE.
3. **A sends** `m`, the device set's heads and the newest checkpoints,
   sealed under the PAKE's session key, and adds B's author key to the
   device set (an operation on the device-set scope, signed by A).
4. **B wraps `m`** under its own keystore key (§3.5), syncs, and is a
   device of the personal space. Its member digest in every space is the
   one A already enrolled (§3.5): no space's registrar is involved.

**Removing a device:** a device that holds `m` can derive everything; so
removal is **rotation**: the remaining devices draw `m'`, re-wrap, open new
mailboxes, re-enroll `member(m')` in each space (the registrar's `enroll`
and `revoke`), sweep every note to `m'`'s address (a self-payment, §5),
and drop the old author key from the device set at a cutoff
(`core-model.md` §9.4's cutoff rule). A lost phone locked behind its
keystore's user authentication gives a thief nothing until rotation
completes; an unlocked one may.

### 3.5 Where the member secret lives

**Today** [built, S25, S42, S51]: `s` is derived at each use from a
Keystore HMAC (or a security key's `hmac-secret`) over the space's handle;
the key never leaves the device, and nothing syncs it ("a source that
spans devices is later work").

**Proposed:** one root secret `m` a personal space, 32 random bytes drawn
on its first device, from which every per-space secret derives:
- `s = derive(BLAKE2b-512("vos/device/secret/v2" ‖ handle ‖ m))`, the same
  reduction to eight M31 words as today's `derive_secret`;
- the wallet's spending key `sk` per space, the sync key `k_sync`, the
  mailbox keys: each a BLAKE2b-512 of its own domain and `m`.

**At rest:** `m` is stored wrapped (AES-256-GCM) under a keystore key that
requires user authentication at every use (`BiometricPrompt`,
StrongBox-backed when present), as today's HMAC key is; or wrapped under a
security key's `hmac-secret` output. It crosses into the app's process at
each use, as today's source output `o` does (and `o` already gives `s` for
good, `pvm/device/SECURITY.md`), so the in-use exposure is unchanged; what
changes is that `m` is exportable by design, to pair devices and to back
up.
- **Recovery:** `m` shown once as a 24-word phrase, opt-in; guardians later.
- **The cost:** a hardware-bound secret becomes a synced one. The owner's
  choice (§8 Q2); the alternative keeps per-device secrets, a member leaf
  and a wallet per device, and pays for it in every flow (a payment from
  "the user" is from one device's notes).

## 4. One proving path

### 4.1 What is retired

The credential AIR, format 44 [built, S21–S29, S57], proves auth, owner
and the joint statement in 0.16–0.18 s on the Fairphone 6 [measured, PG1]
with proofs of about 0.2 MB, verified in about 2.0 ms [measured,
`node/SECURITY.md`]. It is a hand-written circuit over the recursion AIR's
`p2` and `qm31`: every statement change is a circuit change, a re-pin and
a new fixture. It is retired, and every device statement becomes a device
kernel [proposed, the owner's direction].

**Deleted** (at `6c4b4f49a`, about 3,200 lines and one wire enum's arms):
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
  `vos_pvm_proof::format::CREDENTIAL_PROOF` (44 retired, its number never
  reused, as 30, 37, 42, 43 and 45 are);
- the phone bench's credential cases (`tools/phone`), PG1's gate.

**Not deleted:** the recursion AIR's `p2` and `qm31` (the folds and the
wrap use them); the Poseidon2-M31 compression, `0x402` and its chip; the
credential actor and its tree; `H_io`; the device format and its chips.

**No crate disappears by retiring 44 alone.** The crates go with §7.1's
consolidation: `vos-device` folds into `vos-light`, and the light node
links the zkVM and its masking without the recursion prover.

### 4.2 Every device statement a kernel in an actor

Sign-in, ownership and spending are `#[attestable(device)]` methods,
each a short Rust function in the actor whose state it concerns:
- **auth** and **owner** in the credential actor (`vos-credentials`), the
  stock kernels every space gets with it;
- **spend** and **join** in the payments actor (§5);
- any actor's own, under the same rules.

```rust
// vos-credentials, beside the tree it proves membership of.
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
  measure first, §8 Q7];
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
- **The kernel-specific checks move to the guard's library code,** run at
  ingress before the proof (cheap) and again at apply (binding):
  - auth's (the scope the guard's name gives, the root in the ring and
    fresh, `once`) are the credential actor's, today in ingress; they
    keep their refusal codes;
  - owner's are none: the handler compares `ctx.owner()` with the live
    row, as today;
  - spend's are the pool's: the anchor in the pool's ring, each nullifier
    unseen (§5.5).
- **The origin** a proven call logs: `Anonymous { scope, nullifier }` for
  auth, `Owner(digest)` for owner (both as today), and a new
  `Proven { kernel }` (codec index 7) for any other kernel, its claim
  passed to the handler as its typed argument. `Input::Credentialed`
  (index 10) carries the claim's digest in place of auth's root, so a log
  entry stays one size.
- **Verification cost and denial of service:** a device proof verifies in
  about 11.7 ms on one x86 core and a wrong PoW is refused in 8.0 ms,
  against 2.0 ms and 0.7 ms for format 44 [measured, `node/SECURITY.md`]:
  the same budget admits about a sixth as many proofs a second. Two
  levers: **the PoW before the composition** (the verifier replays the
  commitments into the channel and checks the grind before evaluating the
  composition at the OODS point; a wrong PoW then costs about the decode,
  ~1 ms [est]); and the levers of §4.4, which shrink the columns the
  verifier evaluates. Over Tor, the gateway's onion-service defences
  replace per-address limits (§6.6).

### 4.4 The program-id model, and the cost

**The device program** [built, S61] is computed from the installed kernel
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
- **Pins:** the binding names the program id, so a proof of one kernel
  authorizes nothing under another; a new kernel version is a new id, its
  space's install the only governance step. No venue pins device ids
  (device proofs are not folded, `proving.md` §12 decision 2).

**The cost** (the Fairphone 6, automatic threads):

| statement | today, format 44 | today, format 46 | with the per-program CPU | and word-level memory |
|---|---|---|---|---|
| sign-in (auth) | 164–170 ms [measured] | 581–645 ms, 0.88–0.98 MB [measured, P7, P8] | about 554 ms [model] | about 450 ms [model] |
| ownership (owner) | 161–179 ms [measured] | 0.30–0.40 s [est]: every chip at its 2^10 floor, the CPU half auth's | 0.27–0.36 s [est] | 0.25–0.33 s [est] |
| spend, 1 in 2 out | none | 0.9–1.3 s [est] (§5.7) | 0.8–1.1 s [est] | 0.7–0.95 s [est] |

- **The price of one path:** sign-in costs about 3.5× today's credential
  proof in time and 4.5× in bytes, payment authorization about 2× in time.
  Within the owner's requirement (`proving.md` §1: under a second on a
  2023-or-later phone), not within PG1's 250 ms, which retires with format
  44.
- **The levers are the next format** [decided, S63: "the per-program CPU
  and word-level memory to the next slice"]: both change the AIR, so they
  land together as one new device format (47) and one node segment format,
  with one re-pin, not two.

### 4.5 What the formats become

| format | today | after slice 8 |
|---|---|---|
| 39 (final, masked wrap), 41 (node segments) | admitted | kept; 41 superseded by the levers' node format if S63's per-program CPU is taken for nodes too |
| 44 (credential) | admitted at ingress | retired |
| 46 (device) | admitted for auth's statement | admitted for every device kernel; superseded by 47 |
| 47 (device, per-program CPU, word-level memory) | none | the device format |

## 5. Payments as the showcase

### 5.1 The shape

Two actors and one library:
- **`Payments`**, a public actor in the space: cipher-clerk's double-entry
  ledger (transparent accounts held by owner digests) beside a shielded
  pool (note commitments, nullifiers, encrypted notes). It never sees a
  note's value or owner.
- **`Wallet`**, a local actor in the user's personal space (§3): the notes
  the user holds and the nullifiers it has spent, synced across the user's
  devices. It builds and proves spends.
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

1. **P1, pseudonymous** [recommended in M1]: `Payments` is cipher-clerk's
   L0 kernel in an actor, its user accounts held by `Owner` digests,
   `transfer` under `#[msg(credential = Owner)]` proved by the stock
   `owner` kernel. It replaces the `purses` test actor (a hand-rolled
   ledger) with cipher-clerk's, and keeps today's privacy: a public payer,
   amounts and payees in clear to the operators, custodial `rekey`.
2. **P2, private** [the slice's showcase, M3]: the shielded pool and the
   wallet. Payer, payee and amount hidden from the operators and every
   other member inside the pool; deposits into and withdrawals from the
   pool visible as transparent legs.

### 5.3 cipher-clerk, redesigned

cipher-clerk (`~/src/virto/cipher-clerk`, v0.3.0 at `0235d06`; VOS pins
tag `v0.3.0`, `Cargo.toml:241`, and uses its codec, `Account`, `Layer`,
`Value` and `settlement::window` in the `accounts` and `window` test
actors) has a sound transparent kernel (about 320 tests) and a notes
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
| R2 | **Hash commitments, not Pedersen**: `cm = C(C(T(note), [asset, v₀, v₁, v₂, 0…]), C(owner, C(rho, r)))`, value in three 24-bit words; `r` a 248-bit blinding the caller passes (randomness as a parameter, v0.3.0's rule kept) | the spend proof checks the balance in Rust, so no homomorphism is needed; no curve in the kernel | 4 |
| R3 | **Keys from one secret, hash-only**: `sk` per space from `m` (§3.5); `owner = C(T(note-owner), sk)`, `nk = C(T(note-nf), sk)`; the device proves knowledge of `sk` | spend authorization without an embedded curve: option 1 of item 1 ("the device proves, with `ak = Poseidon(ask)`"); no delegated proving, which the light node does not need | 1, 2 |
| R4 | **Nullifier** `nf = C(nk, cm)`; **`rho` of each output** `C(T(rho), C(nf₀, [i, 0…]))`, bound to the transaction's first nullifier | unique per note, unlinkable to `cm` without `nk`; `rho` fixed by the protocol closes Faerie Gold (F3); `nk`'s tag apart from the credential's `T(nf)` | 3 |
| R5 | **Fixed-shape transactions**, `Tx<const I, const O>`: `anchor`, `nullifiers: [Digest; I]`, `commitments: [Digest; O]`, `memos_hash`, `value_balance: i64` (the transparent leg: a deposit negative, a withdrawal positive), `fee: u64`, `pool: Digest`, `binding`; one asset a transaction | a proof's shape is its kernel's; two kernels, 1-in-2-out (`spend`) and 2-in-1-out (`join`), cover payments and consolidation | 4, 5 |
| R6 | **`shielded::check::<H, I, O>(tx, witness) -> Result<(), SpendError>`**: `no_std`, no allocation, fixed arrays, no `BTreeMap`, no panic; `Witness` the input notes, their positions and paths, `sk`, the output notes; plus `shielded::build` (host side) | the device kernel's body; the same function runs on hosts as the reference | 11 |
| R7 | **An incremental note tree**: append-only, depth 32, its frontier (33 digests) and a ring of the last 64 anchors in point rows behind a `NoteState` trait (as `LedgerState`), O(32) calls an append | F21; the actor stores it in its tables; the anchor ring mirrors the credential actor's | 7 |
| R8 | **The pool a pseudo-account of the L0 kernel**: a transaction's `value_balance` is one kernel transfer between the payer's or payee's transparent account and the `ShieldedPool` pseudo-account, under the depositor's `Authority` or the proof's | `seal` and `open` kept as the kernel's two legs, not a second ledger | 9 |
| R9 | **Encrypted notes**: a memo per output, X25519 to the recipient's address key and ChaCha20-Poly1305 (the `viewing-keys` envelope's AEAD), a one-byte view tag; outgoing ciphertext under the sender's `ovk`; host side only, never in a kernel; the transaction binds `memos_hash` | note delivery through the pool's feed (§5.4); the recipient checks a note's `owner` against its own on receipt (F8) | 2, 6 |
| R10 | **Deleted**: `notes` (replaced by `shielded`), `pvm-precompile` and its VOS git dependency, `fmd-experimental`, `stealth-experimental` (F8: unspendable), the Ristretto `AuthKey` and Schnorr outside the `signatures` helper the CLI uses | fewer pieces; nothing in VOS uses them; the view tag and scanning replace FMD at this scale | — |
| R11 | **Recovery and refusals** written as tests against `check`: Faerie Gold, a spend back by the sender, a double spend (at the actor), an anchor out of the ring, a fee or memo-hash mismatch, an overflow, a wrong pool | Phase 3's refusal list | 10, 11 |

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

    /// New notes from a transparent account: the payer's owner proof.
    #[msg(credential = Owner)]
    pub async fn deposit(&mut self, ctx: &mut Command<Self>, from: AccountId,
                         note: Digest, memo: Memo, amount: u64) -> Result<(), PayError> { /* … */ }

    /// The feed a wallet scans: commitments and memos from a position on.
    #[msg]
    pub async fn feed(&self, from: u64) -> Page<(Digest, Memo)> { /* … */ }
}
```

The wallet, a local actor:

```rust
#[actor]
pub struct Wallet {
    notes: crdt::GSet<Owned>,           // notes received: the note, its position
    spent: crdt::GSet<Digest>,          // nullifiers this user spent or saw spent
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

    /// A spend paying `amount` to `to`, its change back: built here,
    /// proved by the light node, sent to the pool.
    #[msg]
    pub fn prepare(&self, to: Address, amount: u64, r: Randomness)
                   -> Result<(Spend, shielded::Tx<1, 2>), PayError> {
        let input = self.pick(amount)?;
        let path = self.path(input.position);
        shielded::build::<P2, 1, 2>(&input, &path, &to, amount, r)
    }
}
```

**What the light node does around it** (a `pay` operation of the
facility, §7.3): calls `prepare` on the local wallet, proves the pool's
`spend` kernel on the result (the kernel's bytes come from the space's
installed package, fetched once and pinned at enrollment), sends the
proven call, and on `Ok` records `spent(nf)`. A local workflow with
device effects (`ctx.prove`, `ctx.call_remote`) would move that glue into
the actor; it is a later extension of the local host (§8 Q8).

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
  program (§4.3); the anchor in the ring and the nullifiers unseen as the
  guard's pre-checks;
- at apply (`pay`): the anchor accepted (newest, or superseded within
  `ROOT_MAX_AGE`, the credential ring's rule); each nullifier inserted
  once (a second is refused, the whole call with it); the memos' hash;
  the commitments appended; the transparent leg applied by cipher-clerk's
  kernel (a withdrawal credits the payee's account from the pool's
  pseudo-account; a deposit is the reverse, under the depositor's owner
  proof).

**What the operators learn:** that a spend happened, when, its fee, its
transparent leg if any, and two new commitments; never the payer, the
payee, the amount or which note was spent among those under the anchor.
Over Tor (§6), not the address it came from.

### 5.6 What the pool trusts

- **Authority is the users':** no operator can spend a note (it needs
  `sk`), and there is no `rekey`: the private tier is non-custodial in its
  authority, unlike today's ledger (`identity-and-authority.md` §7, S37).
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
- calls: `owner` and `nk` 2, the input's commitment 4, its nullifier 1,
  its path 32, two outputs' `rho` 2 and commitments 8, `H_io` over a claim
  of about 240 bytes 11: about 60, under the Poseidon2 chip's 2^10 floor;
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
  `vos-api` over SSH relays today plus `Credentialed` and the relay's
  `Call`, with the gateway's leader-aware routing behind it. The light
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
  facility's tokio runtime (`arti-client` with `tokio`, `rustls` and
  `static`, no OpenSSL, `onion-service-client` on, which is a default), its
  state directory in the app's private storage so later starts skip the
  cold bootstrap. Zcash's `zcash_client_backend::tor::Client` is the model:
  one client, `isolated_client()` handles, `set_dormant` when the app is
  in the background, persisted state.
- **Isolation by purpose:** each of these gets its own circuit
  (`isolated_client()` or a `StreamPrefs` isolation group), so the
  gateway cannot join them by circuit:
  - root polls and path fetches (one isolation each, as today's drawn
    keys separate them);
  - proven calls (each its own);
  - the relay's mailbox traffic (its own);
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
| a proof's upload | a device proof is about 0.9 MB (a spend about 1.2 MB [est]); at the 0.5–2 MB/s an onion circuit sustains, 0.5–2 s [est] | every proven call |

**A sign-in end to end** (an open circuit, the path held): prove 0.45–0.65
s, upload 0.5–2 s, the round trip 0.3–1 s, the node's apply 35 ms
[measured, P7]: **about 1.3–3.6 s** [est], against about 0.8 s on the
clearnet. **A private payment:** 2–4.5 s [est]. The proof's bytes are now
the largest term, which makes the device format's proof size a lever of
its own (§8 Q3): the per-program CPU and word-level memory cut columns, and
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
  calls (the network address is the last link §5.5 leaves).

### 6.6 Denial of service without addresses

Every client of an onion service arrives without an address, so the
gateway's per-address limits (`node-api.md` §6: 64 connections and 200
requests a second an address) no longer apply to Tor clients. In their
place:
- **arti's service defences:** introduction-point rate limits and,
  experimental in arti today, the service-side proof of work (`hs-pow`,
  behind `hs-pow-full` in the `experimental` bundle, with LGPL
  dependencies). C tor's onion-service PoW is stable; arti's is not yet
  [unverified status]. Turn it on when it stabilizes; until then the
  gateway's other limits must hold alone.
- **Limits per circuit and per service:** streams per rendezvous circuit,
  requests a second per stream, and a global cap of proven calls in flight
  through the onion (the node's verification budget behind it, `Busy` past
  it).
- **The proof's own cost:** a proven call carries the device format's PoW
  (16 bits), checked before any decommitment; with the verifier's PoW
  moved before the composition (§4.3), a junk proof costs the node about
  1 ms [est].
- **Restricted discovery** (onion-service client authorization) for a
  space whose members are known: only clients holding a key enrolled
  with the space can even reach the service. It hides the service from
  scanners, at the cost of an enrollment step; optional per space.

### 6.7 What Tor fixes, and what it does not

**Fixes:**
- the network address: no node or gateway learns a member's address, so
  "a proof from the same address still links its nullifier to the digest"
  (`node/SECURITY.md`) ends, since a path fetch and a proof arrive on
  different circuits;
- the root-marking attack's last step (a gateway marking an address's
  root polls) loses its address; it keeps the circuit, which isolation
  per purpose (§6.2) scopes to one poll;
- the relay's view of the personal space: a mailbox's traffic with no
  address behind it.

**Does not fix:**
- **timing:** a gateway sees when a fetch and a proof arrive; jitter
  (`PathKeeper`'s) spreads them, and syncing the tree (§3, the wallet's
  `tree` and the credential book's) removes path fetches altogether, which
  is the real fix the carried list names;
- **the `map_root` fingerprint** (carried, M4): fixed by proving against
  the newest root, which a synced tree gives the device, or by logging the
  root's place in the ring in place of the root;
- **small anonymity sets:** a pool or a member tree of fifty is a set of
  fifty however the bytes travel;
- **a global observer** correlating both ends of Tor, and application
  identifiers a client volunteers;
- **Tor's own maturity:** arti hosting is usable and has vanguards (full
  vanguards recommended for long-lived services), but its service PoW is
  experimental, its documentation is inconsistent about production use,
  and the Tor Project has not recommended it for high-risk onion
  services; its library crates take breaking minor releases about monthly
  (arti-client 0.45, 0.46 and 0.47 in August, September and October 2026).

**Verdict on arti** [proposed]: ready for the client side (stable since
1.0, shipped by Zashi and Fedimint); usable, not yet hardened, for
hosting, whose DoS defence is the gap. Ship the client path in slice 8;
host the gateway's onion behind a `tor` feature, full vanguards on, PoW
when arti stabilizes it; pin one arti version a release and budget an
upgrade step each slice.

### 6.8 Sources (read 2026-11-02 unless marked)

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
| `vos-light` (new, `node/light`) | the light node: the single-replica host, the store, the prover's device path, the node-API client, sync, arti's client behind a feature; replaces `vos-device` one for one |
| `vos-node` (`node/host`) | its executor, dispatch and store usable without Raft, the API server, peers, the prover worker or venues: a `server` feature, on by default, holding those; `vos-light` depends on it with `default-features = false` |
| `vos-pvm-recair` | `credential` deleted; the masked device segment (`masked::device`, `device`) and the masking it needs move to `vos-pvm-proof`, so a device links the zkVM and its masking without the recursion prover [est: the masking's dependency on the recursion's `Context` is to be checked first, §8 Q9] |
| `vos-pvm-final-verifier` | `credential` and `credential-bytes` deleted |
| `vos-sdk`, `vos-sdk-macros` | `#[attestable(device, reference = …, headroom = …)]`; `#[msg(proven = kernel)]`; in-place kernel arguments; `vos_sdk::p2` (digests, tags, paths); `crdt::{GSet, Set, Map}` and `#[msg(merge)]` on the light node |
| `vos-wire` | `Credentialed.claim` in place of `CredentialPublic`; `Principal::Proven { kernel }` (index 7); `CredentialKind` deleted |
| `merkle-crdt` | the incremental apply (`core-model.md` §9.4, S6); a `Store` over fjall; the `redb` store and feature deleted (one storage engine) |
| `vos-credentials` | the stock `auth` and `owner` kernels and their references move here from the `device` test actor; the guard checks of §4.3 as its library code |
| `vos-gateway` | the onion service behind a `tor` feature (§6); a `vos-api` byte-stream port on it; per-circuit limits |
| new actors | `Payments` (replacing the `purses` test actor), `Wallet`, the sync relay (§7.2) |

**Net:** one crate in (`vos-light`), one out (`vos-device`); the
credential AIR's modules, one feature, one format, its fixtures and its
fuzz target out; merkle-crdt's redb out; cipher-clerk's four
experimental features and its VOS dependency out. The slice adds no
proving code beyond the levers' format.

### 7.2 The node and the gateway

- **The node** gains no transport and no knowledge of Tor, JAM or Kreivo.
  Its ingress generalizes (§4.3); its install computes a device program
  for every device kernel (§4.4); format 44 goes.
- **The sync relay** is an actor, `Relay`, installed in a space that
  offers it: `put(mailbox, key, sealed)` and `heads`/`get` queries, a
  mailbox's writes authorized by an ed25519 key derived from `m` (a
  client key like any other, its session's signature checked at
  ingress), quotas per mailbox (bytes, entries, age), sealed blobs only.
  It uses the node's replicated tables; nothing in the node or gateway is
  specific to it. A gateway-side blob store is the alternative (§8 Q4).
- **The gateway** keeps HTTP, TLS and SSH, and adds the onion service
  (§6): the same routes and the SSH port behind an onion address, and a
  port carrying the node API's frames over the onion stream, relayed as
  `vos-api` over SSH relays them today (`Time`, `Query`, `Credentialed`
  and the relay's `Call`).

### 7.3 s4

- **The facility** `vos.credential` becomes `vos.node`: `enroll`,
  `sign_in` and `pay` as today (the trusted chrome, the pins, the two
  prompts [decided, S40, S48, S49]), plus `wallet` (balance, receive,
  pay privately), `pair` (§3.4) and `rotate`.
- **Tor in s4's client:** its SSH connection to the gateway goes to the
  onion address pinned at enrollment, through the facility's `TorClient`;
  the host key is pinned as today.
- **The facility's toolchain:** it builds on VOS's pinned nightly
  (`s4-credential/rust-toolchain.toml`) because of the prover; unchanged.

### 7.4 The SDK macros and the derivation

- `#[attestable(device)]` methods may take references to fixed-size
  argument types (decoded in place) and declare `reference` and
  `headroom`; the derivation records the reference's symbol and refuses a
  device kernel without one.
- `#[msg(proven = k)]` names a device kernel of the actor or of the agent's
  credential actor; the method's last argument is the kernel's claim type,
  checked equal at compile time.
- A local actor is an ordinary package; `#[actor]` needs no new mode. The
  light node refuses to install one with Linear fields or workflows (the
  derivation's schema says which).

### 7.5 What stays

The node's Raft, store, executors and API; the default agent; the
recursion, the final wrap and its venues (formats 39, 41); statements and
anchors; the credential actor and its Poseidon2 tree; `0x402` and its
chip; `H_io`; the device format's machinery; the gateway's HTTP and SSH;
s4's facility model; cipher-clerk's L0 kernel and settlement.

## 8. Risks and open questions for the owner

Ranked by how much of the slice each one moves. Each has options and a
recommendation.

**Q1. Retire format 44 now, accepting slower sign-in and payment?**
- (a) Retire it: sign-in 0.58–0.65 s and owner 0.3–0.4 s today [measured,
  est], 0.45 s and 0.25–0.33 s with the levers [model, est]; proofs 4.5×
  larger; ingress verification about 6× dearer. One path, about 3,200
  lines and one format gone.
- (b) Keep it beside the kernels for auth and owner only, retire it once
  the levers land.
- (c) Keep it.
- **Recommended: (a), timed with the levers** (M2): the format-44 code
  goes in the same step that admits format 47, so no release proves
  slower than 0.5 s for sign-in.

**Q2. One synced root secret, or hardware-bound per-device secrets?**
- (a) One root `m` a personal space, wrapped by each device's keystore,
  paired by QR and PAKE, recoverable by a phrase (§3.5). Every flow sees
  one user; rotation on a lost device.
- (b) Per-device secrets from the keystore's HMAC as today (S42): a member
  leaf, an owner digest and a wallet per device; the personal space syncs
  everything but the secrets; paying from another device's notes is a
  transfer between one's own devices.
- **Recommended: (a).** The exposure in use is today's (the source's output
  already crosses into the app and gives `s` for good); (b) makes the
  personal space a set of strangers. It reverses part of S42 ("a source
  that spans devices is later work"), so it is the owner's call.

**Q3. How private is the first payment showcase?**
- (a) P1 then P2 in slice 8 (§5.2): cipher-clerk's L0 ledger with owner
  proofs first, the shielded pool second.
- (b) P2 only, skipping a pseudonymous rebuild.
- (c) P1 only; the pool to slice 9.
- **Recommended: (a).** P1 is a small step that puts cipher-clerk in the
  demo and retires `purses`; P2 is the slice's point but carries its risk
  (cipher-clerk v0.4, the spend's cost, Tor). If P2 slips, P1 still ships.

**Q4. Where the personal space's sync relay lives?**
- (a) A `Relay` actor in a space the user belongs to (§7.2): no new
  service, replicated, quotas as actor logic; its blobs go through the Raft
  log (fine at a personal scale, costly for large checkpoints).
- (b) A blob store in the gateway: cheaper bytes, a new stateful piece
  in a component that holds no state today.
- (c) iroh relays: a second network stack, no Tor.
- **Recommended: (a),** checkpoints capped (and a CAS blob reference for
  large ones, through the node's existing blob store, if the cap binds).

**Q5. The light node's process on Android?**
- (a) In s4's client process, behind the facility (§2.2).
- (b) A separate process (`:vos`) behind Binder.
- (c) A standalone VOS app other apps call.
- **Recommended: (a) now, (b) when a second app needs the light node.**

**Q6. Generalize credentialed calls (`#[msg(proven = k)]`) or add kinds?**
- (a) Generic proven calls (§4.3): one ingress path; auth and owner as
  stock kernels with SDK sugar; a new origin `Proven { kernel }`.
- (b) Keep `CredentialPublic` and add a `Spend` kind.
- **Recommended: (a).** Each new kind under (b) is ingress code; under (a)
  a new kind is an actor's kernel and its guard checks, which is the
  owner's "high level attestable rust code".

**Q7. Make SDK-form kernels as lean as hand-written ones?**
- The risk: the levers' 450 ms assumes the lean kernel's 1,722 steps;
  plainly written, auth took 18,733 [measured]. The SDK's in-place
  arguments, the `p2` helpers and the target's unaligned loads are meant
  to close it; if the target feature does not hold (the transpiler's
  handling of what LLVM emits), the SDK keeps the inline-assembly loads
  inside `vos_sdk::p2`, out of user code.
- **Recommended:** measure first (the plan's step 8.2), with the 1.15×
  gate; nothing else in M2 starts before it.

**Q8. Local workflows with device effects?**
- (a) Glue in the light node's Rust for slice 8 (§5.4): `prepare`, prove,
  send, record.
- (b) A local `#[workflow]` with `ctx.prove` and `ctx.call_remote`, effects
  only the light node serves (a full node answers `WHAT`, `core-model.md`
  §3's JAM-first rule).
- **Recommended: (a) now, (b) in the next slice:** (b) is the more elegant
  showcase but needs workflows in the single-replica host.

**Q9. Can the device prover leave `vos-pvm-recair`?**
- The masked device segment lives in `vos-pvm-recair` (`masked::device`,
  `device`) because the masking does; the light node then links the
  recursion prover it never runs. Moving the masking to `vos-pvm-proof`
  shrinks the `.so` and the dependency graph; whether the masking depends
  on the recursion's `Context` is to be checked.
- **Recommended:** check in M1; move if the masking is separable; leave it
  if not, and record the binary's size either way.

**Q10. The shielded pool's integrity.**
- The in-space pool trusts its operators for supply (§5.6): they can mint
  notes. Options: (a) accept it as the space's tier, as the custodial
  ledger is today; (b) prove the pool's transitions at the venue (each
  window's appends and nullifiers a node-proved statement, anchored), a
  slice of its own; (c) the shared JAM pool, postponed.
- **Recommended: (a) for slice 8, (b) designed next,** stated in the
  pool's documentation and chrome.

**Q11. arti's maturity for hosting.**
- arti's service PoW is experimental and its documentation inconsistent
  (§6.7). Options: (a) arti in the gateway, behind a feature, PoW when
  stable; (b) C tor beside the gateway (stable PoW, a second process and a
  C dependency, against the owner's "arti in the ingress"); (c) wait.
- **Recommended: (a),** with the gateway's per-circuit limits and the
  verifier's early PoW carrying DoS until arti's PoW stabilizes.

**Q12. Note delivery and scanning.**
- Memos in the pool, scanned by trial decryption with a view tag (§5.3
  R9): every wallet downloads every new memo (about 200 bytes a note
  [est]); fine for a space's pool, heavy for a large one. Direct delivery
  through the messenger is the fast path later; FMD is dropped (R10).
- **Recommended:** memos plus view tags in slice 8.

**Risks** (beyond the questions):
- **Proof bytes over Tor** dominate a call's latency (§6.3); a format with
  more queries or a larger blowup to save time costs bytes, and the gate
  should weigh both.
- **The Merge lane is unbuilt in `vos-core`:** merkle-crdt has no
  dependent, the SDK has no CRDT fields, the incremental apply is a
  prototype (S6). M3 builds the device side only.
- **cipher-clerk v0.4 is a redesign** of a not-for-value prototype; its
  notes stay not for value until the external audit (`proving.md` §12:
  "an external audit before value rides on a proof"), whose scope now
  adds the spend kernel and cipher-clerk's `shielded` module and drops the
  credential AIR.
- **Android's background limits** (Doze, WorkManager's 15-minute floor)
  bound how fresh a backgrounded wallet's view is; a payee sees a payment
  when the app opens, or at the next job.
