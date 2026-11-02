# The light node, one proving path, private payments and Tor

Design, draft 2 [proposed], folding the Opus review of draft 1. The
architecture of slice 8 (`slice-8-plan.md`): a light node of VOS on the user's devices, one proving
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
5. **Fewer pieces.** No net new VOS crate (`vos-light` in, `vos-device`
   out), one proving path in place of two, fewer formats, fixtures and
   proving modules. The slice does add arti's dependency tree, three
   actors and the CRDT fields; the claim is about what VOS maintains as
   proving and transport code, not a smaller dependency graph.
6. **Network privacy.** Clients reach a space's gateway as a Tor onion
   service through arti embedded on both ends, so no node or gateway
   learns a member's network address.
7. **The rule stays:** `vos` and the node know no JAM and no Kreivo
   [decided, 2026-10-23]; the same holds for Tor (§6, §7).

**Non-goals for slice 8:**
- A shared shielded pool across spaces, or one whose integrity does not
  trust its space's operators (a JAM agent or a proving space;
  `identity-and-authority.md` §8, and §14's open question 3). The pool here is
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
| **the agent program** | the default agent, `vos-agent`: local actors are installed into it as into a node's agent; it gains merge dispatch, CRDT fields' storage and scopes (none exists today in `agent/default` or `agent/sdk-macros`) | `agent/default` [built, extended] |
| **a single-replica host** | refine and accumulate driven by a local loop over a local log; the actor ABI's host calls; no Raft, no leader, no peers | carved from `vos-node` (§7.1) |
| **local store** | fjall, as the node's, with small caches (8–16 MiB block cache [est]) | `vos-node`'s `store` [built] |
| **device prover** | the device profile (format 46, or its successor after the levers, §4.4), masked, `Threads::Auto` | `vos-pvm-proof` and `vos-pvm-recair`'s masked device segment, its recursion prover featured out (§7.1) |
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
- **Isolation (option):** the facility in a separate Android process
  (`android:process=":vos"`, Binder between them) keeps the prover's peak
  and the secret's unwrapped bytes out of the UI process and lets the OS
  kill it alone. It costs a Binder interface for every operation and a
  second runtime; recommended later, not in slice 8.

### 2.3 Memory and battery budget

| state | budget | basis |
|---|---|---|
| idle, foreground (store open, arti bootstrapped, no proof) | ≤ 96 MiB resident, of which arti ≤ 48 MiB | [est]: interpreter and pool a few MiB, fjall's caches 8–16 MiB, arti's directory and circuits (§6.4) |
| the facility's `.so` | growth from arti ≤ 10 MB | [est], to measure (§6.4) |
| local actor call | ≤ 1 ms on the interpreter | 85 µs an invocation on the node's interpreter [measured, `core-model.md` §14], with the fsync of a local commit dominating |
| proving a sign-in | ≤ 1 GiB peak (target 768 MiB) | PG2's [decided, S3, S20, S27]; 513 MiB measured [measured, P7] |
| proving a spend (1 in, 2 out) | ≤ 1 GiB peak | [est], §5.7 |
| background sync job | ≤ 30 s wall, ≤ 1 MB down a run with nothing new | [est]: arti from a warm directory, one onion connection, the relay's heads |
| battery | no work while backgrounded beyond the periodic job; no persistent circuit | the design's rule, measured by the plan's PG5 |

Proving is the only heavy phase: about 0.65 s of wall time on the four
big cores at full load a sign-in [measured, P8: 645 ms], about 1 s a spend
[est]. A phone that signs in twenty times a day spends about 13 s of wall
time on them [est], far below a screen-on minute.

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
  outcome from the pool's nullifier feed. The wallet's state is a CRDT (notes
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
  key on every install or restore"). merkle-crdt's `DagNode` has no author
  field (`support/merkle-crdt/src/node.rs`), so the author key and the
  signature travel in the payload; `NodeValidator::validate(cid, node)` is
  stateless (`sync.rs`), so it checks the signature alone, and the
  device-set membership is checked when the scope's operations are read
  (filtered, as `core-model.md` §9.4 filters a removed author's).
- **An amendment to `core-model.md` §9.4:** it says "any scope with
  members needs a log, because epochs and removals are Linear steps". A
  personal space has no log: removing a device is rotation (§3.4), a new
  root secret, new scopes and new mailboxes, so the device set is advisory
  (who signed), never the security boundary, and needs no epoch.

**Transport, in order of preference:**
1. **Through the space's relay, over Tor** [recommended first]: a relay
   actor in a space the user is a member of (§7.2), holding sealed nodes
   per mailbox. A mailbox's id and its write key derive from `m`; a
   mailbox is opened by a member's auth proof (§7.2), so its quota is a
   pseudonym's. The space's operators see a mailbox's activity (counts,
   sizes, times) and the pseudonym that opened it, not its contents, and
   not the devices' addresses (§6). The heads a device publishes are
   sealed too (plain CIDs would let operators confirm guessed
   operations). It needs nothing a space does not already run: calls and
   queries over the node API.
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
   author key, and runs a Noise handshake with A through the mailbox
   (`Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b`, the code its pre-shared
   key). The code is 128 bits and never crosses the relay, so a relay that
   substitutes keys fails the handshake; a PAKE would add a primitive for
   a low-entropy code we do not have.
3. **A sends** `m`, the device set's heads and the newest checkpoints over
   the handshake's channel, and adds B's author key to the device set (an
   operation on the device-set scope, signed by A).
4. **B wraps `m`** under its own keystore key (§3.5), syncs, and is a
   device of the personal space. Its member digest in every space is the
   one A already enrolled (§3.5): no space's registrar is involved.

**Removing a device:** a device that holds `m` can derive everything; so
removal is **rotation**: the remaining devices draw `m'`, re-wrap, open new
mailboxes, re-enroll `member(m')` in each space (the registrar's `enroll`
and `revoke`), sweep every note to `m'`'s address (a self-payment, §5),
and drop the old author key from the device set. A lost phone locked
behind its keystore's user authentication gives a thief nothing until
rotation completes; an unlocked one may.
- **Rotation's side effects:** a new `member` digest is a new holder of
  every scope's nullifier, so a `once` scope (a vote) admits the rotated
  member again unless the registrar's policy forbids re-enrollment within
  a round; P1's transparent accounts move by the operator's `rekey`
  (§5.2); the shielded notes move by the sweep alone. The
  same holds today for a revoke and a re-enrollment.

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

**At rest, wrapped one secret at a time:** each derived secret is stored
wrapped (AES-256-GCM) under a keystore key, so a daily use unwraps only
what it needs:
- each space's `s` and `sk` under a key requiring user authentication at
  every use (`BiometricPrompt`, StrongBox-backed when present), as today's
  HMAC key is, or under a security key's `hmac-secret` output; a sign-in
  exposes one space's `s`, as today's per-handle source output `o` does
  (`input = SHA-256("vos/device/input/v1" ‖ handle)`);
- `k_sync` and the mailbox keys under a key bound to the device's unlock
  (no per-use prompt), since a background sync job has no user to ask;
- `m` itself under a per-use key, unwrapped only to pair a device, back
  up, or rotate.

**The exposure widens** where `m` is unwrapped: code in the app's process
during a pairing, a backup or a rotation reads every space's `s`, every
`sk`, the sync key and the wallet, where today one use exposes one
space's `s`. That, and that `m` is exportable by design, is the price of
one user across devices.
- **Migration:** `v2` changes every `member` and `owner` digest, so the
  demo's enrollments and rows are re-enrolled (the registrar's `enroll` and
  `revoke`, the ledger's `rekey`); no production space exists to migrate.
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
links the zkVM and its masking without the recursion's leaves, folds and
wrap (§8 Q9).

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
  measure first, §8 Q7]. A target change rebuilds every guest ELF
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
  profiled before any target is set (plan 8.4). The levers of §4.4 shrink
  the columns the verifier reads and so its time. Over Tor, the gateway's
  onion-service defences replace per-address limits (§6.6).

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
  44. Between format 44's retirement (M1, §8 Q1) and the levers (M2),
  sign-in proves at 0.58–0.65 s.
- **The levers are the next device format** [decided, S63: "the
  per-program CPU and word-level memory to the next slice"]: both change
  the AIR, so they land together as one device format (47), with one
  re-pin of the device programs. The model's 450 ms scales P6's 607 ms;
  from P8's 645 ms it is about 478 ms, so a 0.5 s gate has about a 4%
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
| R3 | **Keys from one secret, hash-only**: `sk` per space from `m` (§3.5); `owner = C(T(note-owner), sk)`, `nk = C(T(note-nf), sk)`; the device proves knowledge of `sk` | spend authorization without an embedded curve: option 1 of item 1 ("the device proves, with `ak = Poseidon(ask)`"); no delegated proving, which the light node does not need | 1, 2 |
| R4 | **Nullifier** `nf = C(nk, C(pool, cm))`, scoped to the pool's id; **`rho` of each output** `C(T(rho), C(nf₀, [i, 0…]))` (two calls), bound to the transaction's first nullifier; **a deposit's `rho`** `C(T(rho-deposit), W(b))`, `b` the deposit call's binding digest, unique and recorded | unique per note, unlinkable to `cm` without `nk`; `rho` fixed by the protocol closes Faerie Gold (F3) for spends and deposits alike; `nk`'s tag apart from the credential's `T(nf)`; a note of one pool spends in no other | 3 |
| R5 | **Fixed-shape transactions**, `Tx<const I, const O>`: `asset` (the transaction's one asset, its fee's too), `anchor`, `nullifiers: [Digest; I]`, `commitments: [Digest; O]`, `memos_hash`, `value_balance: i64` (a withdrawal's amount, or 0), `leg` (the withdrawal's destination account id, or zero), `fee: u64`, `pool: Digest`, `binding`; deposits are not transactions (§5.4) | a proof's shape is its kernel's; two kernels, 1-in-2-out (`spend`) and 2-in-1-out (`join`), cover payments and consolidation; the transparent leg and the fee's asset are in what the proof binds | 4, 5 |
| R6 | **`shielded::check::<H, I, O>(tx, witness) -> Result<(), SpendError>`**: `no_std`, no allocation, fixed arrays, no `BTreeMap`, no panic; `Witness` the input notes, their positions and paths, `sk`, the output notes; plus `shielded::build` (host side) | the device kernel's body; the same function runs on hosts as the reference | 11 |
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
| a proven call without a spare circuit ready | adds an onion connection, 1 to several seconds | a second proven call within a spare's build time |
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
  (16 bits), checked before any decommitment; a junk proof costs the node
  5.8–8 ms today [measured, format 46], less once the decode and setup
  are profiled (§4.3).
- **Restricted discovery** (onion-service client authorization), later:
  only clients holding a key enrolled with the space can reach the
  service, hiding it from scanners. It sits in arti-client's
  `experimental` group today, so it is not offered in slice 8.

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
| `vos-node` (`node/host`) | its executor and store usable without Raft, the API server, peers, the prover worker or venues. Under-scoped as a feature flag: the crate is about 27.6k lines, depends without option on `vos-pvm-recair`, `vos-venue`, `vos-node-prover`, `vos-net`, `vos-raft`, quinn and the compiler; its `dispatch` is peer-arrival dispatch over `vos-net`, and `calls.rs` reads `vos_raft::Role`. Step 8.5 opens with a carve-out spike choosing between a `server` feature and moving the executor and store into `vos-light`'s own single-replica host; `credentialed.rs`'s use of `vos_pvm_recair::device` moves either way |
| `vos-pvm-recair` | `credential` deleted; the leaves, folds and wrap behind a `recursion` feature, on by default (the masking needs `context`, `circuit` and `trace`, which stay), so a device links less of the recursion prover (§8 Q9) |
| `vos-pvm-final-verifier` | `credential` and `credential-bytes` deleted |
| `vos-sdk`, `vos-sdk-macros` | `#[attestable(device, reference = …, headroom = …)]`; `#[msg(proven = kernel)]`; in-place kernel arguments; `vos_sdk::p2` (digests, tags, paths); `crdt::{GSet, Set, Map}` and `#[msg(merge)]` on the light node |
| `vos-wire` | `Credentialed.claim` in place of `CredentialPublic`; `CredentialedInput` carries the claim; `Principal::Kernel { program }` (index 7); `CredentialKind` deleted |
| `merkle-crdt` | the incremental apply (`core-model.md` §9.4, S6); a `Store` over fjall; the `redb` store and feature deleted (one storage engine) |
| `vos-credentials` | the stock `auth` kernel (from the `device` test actor, in SDK form) and a new `owner` kernel, with their references; the stock kernels' ingress checks stay in the node (§4.3) |
| `vos-gateway` | the onion service behind a `tor` feature (§6); a `vos-api` byte-stream port on it; per-circuit limits |
| new actors | `Payments` (replacing the `purses` test actor), `Wallet`, the sync relay (§7.2) |

**Net:** one crate in (`vos-light`), one out (`vos-device`); the
credential AIR's modules, one feature, one format, its fixtures and its
fuzz target out; merkle-crdt's redb out; cipher-clerk's `notes`,
`pvm-precompile`, `fmd-experimental` and `stealth-experimental` and its VOS
dependency out. In: arti's dependency tree (in the gateway and the light
node), three actors, the SDK's CRDT fields and merge dispatch. No proving
code beyond the levers' format.

### 7.2 The node and the gateway

- **The node** gains no transport and no knowledge of Tor, JAM or Kreivo.
  Its ingress generalizes (§4.3); its install computes a device program
  for every device kernel (§4.4); format 44 goes.
- **The sync relay** is an actor, `Relay`, installed in a space that
  offers it. **Admission:** `open(mailbox, key)` is
  `#[msg(credential = Auth("relay"))]`, so only a member opens a mailbox,
  and the quota (mailboxes, bytes, entries, age) is per pseudonym in that
  scope; the mailbox's ed25519 key, derived from `m`, then signs its
  `put(mailbox, key, sealed)` calls (a client key like any other, its
  session's signature checked at ingress), so a sync costs no proof.
  `heads` and `get` are queries; heads are sealed. It uses the node's
  replicated tables; nothing in the node or gateway is specific to it. A
  gateway-side blob store is the alternative (§8 Q4).
- **The gateway** keeps HTTP, TLS and SSH, and adds the onion service
  (§6): the same routes and the SSH port behind an onion address, and a
  port carrying the node API's frames over the onion stream. Its relay
  set is wider than the `vos-api` subsystem's today (`NodeKey`, `Time`,
  `AgentInfo`, `Schema`, `Query`; `node/api/src/lib.rs`, `Kind::relayed`):
  it adds `Credentialed` and `Call`, which a light node sends there.

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
  credential actor; the method's first argument is the kernel's claim
  type, checked equal at compile time (`pay(tx, memos)`: `tx` first).
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
- (b) Keep it beside the kernels until the levers land (M2): the generic
  request (§4.3) replaces `CredentialPublic` in M1, so keeping 44 means a
  second, versioned request body and two ingress paths through M1.
- (c) Keep it.
- **Recommended: (a) in M1** (step 8.4, with the generic request): one
  ingress path from the start; sign-in proves at 0.58–0.65 s until M2's
  format 47 brings it to about 0.45–0.48 s.

**Q2. One synced root secret, or hardware-bound per-device secrets?**
- (a) One root `m` a personal space, its derived secrets wrapped one by
  one by each device's keystore, paired by QR and a Noise handshake,
  recoverable by a phrase (§3.5). Every flow sees one user; rotation on a
  lost device.
- (b) Per-device secrets from the keystore's HMAC as today (S42): a member
  leaf, an owner digest and a wallet per device; the personal space syncs
  everything but the secrets; paying from another device's notes is a
  transfer between one's own devices.
- **Recommended: (a).** A daily use exposes one space's secret, as today;
  pairing, backup and rotation expose `m`, and with it every space's
  secrets and the wallet, a wider exposure than any use today has (§3.5).
  (b) makes the personal space a set of strangers. It reverses part of
  S42 ("a source that spans devices is later work"), so it is the owner's
  call.

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
  stock kernels with SDK sugar; a new origin `Kernel { program }`.
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
  recursion prover it never runs. Checked at `6c4b4f49a`: `recair/src/masked/`
  imports `vos_pvm_recair_air::masked`, recair's `trace` and
  `prove::ProveError`, and the final verifier's `MaskedFormat`,
  `shape_of` and `verify_masked`; `trace` in turn imports `context::Witness`
  and `circuit`. So the masking is not separable from the recursion's core
  modules, and it cannot move into `vos-pvm-proof` either:
  `vos-pvm-final-verifier` depends on `vos-pvm-proof`, so the move makes a
  cycle.
- **Recommended:** a `recursion` feature on `vos-pvm-recair` (default on)
  gating only what the masking does not reach (the leaves, the folds and
  the wrap), `context`, `circuit` and `trace` staying; the light node
  depends on it with `default-features = false`. No crate moves; the
  `.so` size recorded before and after decides whether the feature is
  worth keeping (step 8.5).

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
