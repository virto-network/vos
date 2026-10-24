# Slice 7: simplify and scale, then proofs on the phone

Plan, draft 2, for the owner's answers to its open questions (the last
section). It takes the owner's slice-7 decisions S1–S5
(`research/slice-7/owner-decisions.md`) and the first real phone run
(`research/slice-7/phone-fairphone6-s5kit.txt`). Slice 6's decisions 1–18
stand, except where the owner's answers to the simplification questions
reverse them ("Decisions" lists each reversal).
- **The architecture** is `proving.md` (draft 6) §3–§8, `identity-and-authority.md`
  §5–§7 and slice 6's pins D–F (`slice-6-on-chain.md`). The research is in
  `research/slice-7/`: `simplify.md` (pin D inventoried, eleven candidates
  C1–C11, one question each), `device-params.md` (the device and
  credential parameters counted under masking (c)) and the phone run.
- **This slice builds three milestones:**
  - **M3.9, simplify and scale:** the anchoring protocol simplified by the
    candidates the owner picks; a scale test across the owner's LAN;
  - **M4, the credential AIR:** slice 6's re-pin batch; a credential actor
    keeping a Poseidon2 tree in its own rows; the credential AIR; its
    verifier at a space's ingress; the device library and an Android demo;
  - **M5, the device profile:** the general zkVM on the phone, the auth
    statement in at most 1 s on the Fairphone 6 [decided, S3], **a gate at
    real risk** (M5's outlook, below).
- **Out of the slice:** M6, the signature chips (S1); a Wasm or browser
  prover (S4); iOS (S5); the Kreivo pallet (the teammate's) and its chain
  transport (after the slices, decision 12d).
- **Its log:** `slice-7-progress.md`, beside this plan.

Tags as in slice 6: [measured] by a spike or a step; [model] by the
security tool or a fit; [est] arithmetic on measured numbers, not run;
[decided] the owner's; [proposed] open to review.

## Changes from draft 1

The Opus review of draft 1 (`plan1-review.md`), every finding folded:
- **H1:** M5's projection costed with the wrap's measured masking time
  (×2.0–2.9) and lever 1 as cells (×0.64): about 2.2–3.3 s before levers
  2–3 (M5's outlook); a masked-cost proxy and blowup 2's bytes in 7.0a;
  the CPU split expected (7.18); the gate's fate an early question; M5
  17.5–27.5 weeks.
- **H2:** every standing decision a candidate reverses, under "Decisions"
  and in `simplify.md` §7, one question a candidate.
- **H3:** pay is a proof of knowing `s` behind a public owner digest,
  checked against the live row. **H4:** the Poseidon2 tree lives in a
  credential actor's rows through the native `0x402` (7.9 shrinks).
- **M1:** the Poseidon2 chip in the device format only; the node's segment
  format unchanged; 7.14 off M4's path. **M2:** M4 waits on 7.3, not on
  the scale runs.
- **M3–M5, L3:** C4 asked apart with its full costs and a tombstone; C1's
  limit on the Clerk; C10's opt-in for issuers; C11 added; C5's
  `Unlisted` hands off leadership.
- **M6:** a device proof authorizes what an auth credential does (pin J).
  **M7:** the scale test reworked (cross-shard share, two-minute windows,
  targets from one per-user rate, an identity stand-in, idle timers), and
  trimmed (no venue, no certificates of its own, no ARM deploys).
- **M8:** the binding names space and program; scopes namespaced; no
  shared rate bucket; expiry at apply by batch time; what `Anonymous`
  hides. **M9–M11:** PoW 16 as a phone option; 7.14 at 4–6 weeks with
  format 35's bytes as a gate; item 68 quarantined.
- **The lows:** the relying party asked first; the Android set-up; pin
  K's containment; the teammate's two drops; two builds at phone gates.

## Goals

1. **A protocol a reviewer holds whole:** pin D as the owner trims it,
   one anchor rule written once, one outcome enum on the node.
2. **Scale measured, not extrapolated:** a scripted test on the owner's
   LAN, a million simulated users and tens of thousands of agents in one
   space, the targets met or each gap recorded with its lever.
3. **Credentials on the phone:** a device secret from a real passkey PRF;
   masked auth and payment proofs on the Fairphone 6, verified at a local
   space's ingress; an Android demo end to end.
4. **The general zkVM on the phone:** the auth statement under the device
   profile, masked, in at most 1 s and 1 GiB on the Fairphone 6 [decided,
   S3], or the gap measured lever by lever for the owner to judge.
5. **One re-pin:** slice 6's re-pin batch in one commit; the node's
   segment format unchanged; `H_fold` and the wraps' roots unchanged.
6. **Every item slice 6 carried** placed in a step or carried by name.

**No value rides on a proof in this slice:** the external audit comes
first (slice 6's decision 14); slice 7 adds the credential AIR, the
device shape and its Poseidon2 chip to its scope.

## What exists at the start

- **vos-core** at `f83f744b` (slice 6 accepted); the Stwo pin olanod/stwo
  `c3ec981`.
- **Slice 5's mobile spike** (`spike/s5-mobile`, `ea539e9e`): the auth and
  pay statements as kernels, a floor seam (the shape without the page
  boundary, a cost proxy that does not verify), and the phone kit (a
  static aarch64-musl binary with mimalloc, its runbook). It sits on
  `3713cb42`, **503 commits behind**: the pre-hardening AIR (31 chips,
  the Ristretto chips, no witness-input chip), format 24's Blake2s
  channel.
- **Measured on the gate device** (2026-10-25, the kit's configuration
  `2:38:20`: log blowup 2, so blowup 4, 38 queries, PoW 20; unmasked):
  as built 6.2–6.5 s at 4 threads (2.0 GiB), 5.1 s at 8; the floor
  2.6–3.0 s at 4 threads (0.9 GiB), 2.59 s on the 4 big cores, 2.2 s at
  8; x86 1.72 and 0.84 s at 4 threads. Every proof byte-identical to
  x86's. The ARM factor is about 3.5× [measured].
- **Found while planning** [model, `device-params.md`]: format 37 counts
  61.86 proven bits under masking (c); at 86 queries every masked
  component pads to 2^12 rows, not §8's 2^11.
- **Not built:** a Blake2s-M31 channel in `pcs.rs`; masking for the
  segment chips; any Android, JNI or passkey code; an operator path to the
  representative; a multi-host driver.

## How every step runs

- **A brief per step,** written from this plan and the design docs when
  the step starts; an implementing agent works from it alone, at medium
  effort.
- **Reviews:** one Opus review of every step's diff, its findings folded
  before the next step builds on it; Fable at each milestone's end and at
  the slice's end, never per step. Steps marked **(S)** change soundness,
  the protocol or a state layout: each milestone's Fable review names them
  and checks them first. Review latency is outside the estimates. The
  owner is not paused for between steps.
- **Gates:** `just check` per step; at each milestone's end `just ci-full`
  (fuzz a minute a target, leakage at medium N) and the checker loop; at
  the slice's end `just slice-gate` (leakage at full N, fuzz five minutes
  a target), the checker loop, `just e2e-chain`, the kit's sync check, the
  scale test's final run and the phone gates. Heavy runs one at a time
  under `systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 nice -n 10`,
  `TMPDIR` on disk, builds at `-j8`–`12`.
- **Phone gates** (the s5 kit's approach), **two builds:** the timing
  build with production features (masks from the OS), and a
  `seeded-masks` build whose proofs are checked byte for byte against
  x86's; neither ships. Each a static `aarch64-unknown-linux-musl` binary
  with mimalloc and its fixtures embedded, its SHA-256 recorded; `adb
  push` to `/data/local/tmp`; the device's model, SoC, build, per-CPU
  maximum frequency and battery recorded; battery at least 50%, `dumpsys
  battery` temperature below 35.0 °C at each round's start, battery saver
  off, `svc power stayon usb`, out of its case; 3 rounds of 5 repetitions,
  60 s apart; the gate is the median of the rounds' medians, the 95th
  percentile recorded beside it; each proof verified on the phone and on
  x86. The coordinator runs it over adb when the owner has the phone
  attached and agrees; otherwise the owner runs the kit. Results land as
  JSON lines in `research/slice-7/`.
- **Rules:** slice 6's (`slice-6-on-chain.md`, "How every step runs"):
  commit on `vos-core`, push after reviewed milestones, the fork's pushes
  after Fable, no Kreivo code, timeless comments, no `#[ignore]`, no
  Co-Authored-By, kill by PID only, fix pre-existing failures; every
  measured number tagged in `slice-7-progress.md`.

## The pins

Specs the steps implement, [proposed] unless tagged. Pin D′ depends on
the owner's picks; G–L are M4's and M5's.

### Pin D′: the anchoring protocol, simplified

`simplify.md` §4 states pin D under all eleven candidates; the owner
picks one by one (`simplify.md` §7). Whatever is picked:
- **What stays:** one root per `(space, w)` at a venue, a second root as
  evidence that stops the space, the honest node's own anchor sent as
  evidence; the anchor's signature by a listed key; `Last < w < now_w` by
  the venue's time; `MaxRootAge`; `Seen`; the served path's checks in
  refine; decision 2's rule.
- **The venue core** (C6): `vos_anchor::venue`, `no_std`, the registration,
  anchor, `anchored`, `seen_expiry` and freshness rules as pure functions
  over a `VenueState` trait; `ModelVenue`, the JAM service's accumulate
  and the Kreivo mock call it; the kit vendors it; `spaces-pallet.md` §6.1
  says the pallet calls it.
- **The node's outcome enum** (C5):
  `enum AnchorOutcome { Taken, NotYet, Never(u32), Unlisted(u32), Stopped(u32) }`,
  the raw venue code carried for the log; `Unlisted` makes the leader hand
  off its leadership so a listed replica anchors; one mapping table per
  client, tested against every venue code. Submits:
  `enum SubmitOutcome { Accepted, Refused(u32), Retry }`, a repeat
  `Accepted` at one site.
- **The replicated anchor row** (C3, C11): the representative's close
  writes `anchor(w) = S_w` for a window some agent reported, kept for
  `MaxRootAge`; its leader signs and sends pending rows in window order
  with its node key (C2); nothing is handed back.
- **If C4 is picked:** an ended space's record is a tombstone the venue
  never prunes, and its controller's `dispatch_as_sovereign` stays
  callable, so the sovereign's funds can leave.

### Pin G: the credential actor and its Poseidon2 tree

- **What it is:** `vos-credentials`, an actor installed in the agent whose
  methods it guards (the demo's: the ledger's agent). Its tree is a
  **positional sparse Merkle tree** of Poseidon2-M31, depth 32, kept in
  its own committed rows: `slot(key) → u32` (the next free slot, freed
  slots reused lowest first), `leaf(slot) → Digest`, the non-empty
  `node(level, index) → Digest`, the empty subtrees' digests as constants.
- **The hashes:** through the `0x402` host call (pin H): the VOS host
  serves it natively, a JAM-deployed agent pays the shim's software
  permutation (about 15,800 instructions); so VOS ≡ JAM holds, and the
  tree is as deterministic as any row. `leaf = compress(TAG_LEAF ‖ slot,
  member)` with `member` an 8-M31 digest (fixed length, so injective);
  `node = compress(left, right)`; an empty leaf the zero digest; the tags
  M31 constants from `BLAKE2b("vos/p2/<name>")`.
- **Roots:** a replicated ring `roots[i] = (root, batch_time)` of the last
  64 roots, one written per batch that changed the tree. Enrollment is
  rare: 32 calls of `0x402` a write.
- **Paths:** a query method `path(key) → (root, slot, siblings[32])`, served
  by any replica. **What it reveals:** asking for a path by key tells the
  operators which member is about to prove and when; `Anonymous` hides the
  member from the log's readers and from other agents, not from operators
  (`identity-and-authority.md` §3 and §8: hiding from operators is full
  privacy, postponed). Recorded in `SECURITY.md`.
- **`RootKind` and the representative are untouched:** no venue checks a
  Poseidon2 root in this slice; a later cross-space credential proves its
  root's place under `S_w` by a Blake2b path outside the proof, its issuer
  opting in to report every window (C10).
- **Across agents:** a guard reads only its own agent's state, so a
  credential guards methods of the agent its actor lives in; credentials
  across a space's agents wait for the identity agent replicated on every
  node (`identity-and-authority.md` §6).

### Pin H: the Poseidon2 host call and the device chip

- **The call:** `0x402` (`ECALL_POSEIDON2`), dispatch 102: φ7 points at 64
  bytes (16 M31 words, little-endian u32, each `< p`; a word ≥ p, p itself
  included, traps the live call), φ8 at 32 bytes written with the 8-word
  output of `compress`; no other effect. Served natively by the VOS host
  at a price measured in 7.9; on JAM the guest shim computes it in
  software on `WHAT`.
- **The chip, in the device format only** (M5's 7.15): one permutation a
  row, `p2`'s arithmetic (`permutation_columns`, the S-box pair) as a
  `BuiltInComponent`, about 300 main columns at degree ≤ 3; memory-access
  lookups for the 64 bytes read and 32 written; each input word
  range-checked below p, so a word the live call refuses has no proof; a
  `Poseidon2Call` relation from the CPU's `IsP2Ecall` selector.
- **The node's segment format stays 35:** no node kernel calls `0x402` in
  this slice, `derive` admits it in device kernels and handlers only, and
  `SEGMENT_CHIPS` and the install record's `Shape` stay as they are.
  The node's segment AIR takes the chip at a later re-pin, when a node
  kernel needs it.

### Pin I: the credential statements and their verifier at ingress

- **The AIR:** a recursion-AIR circuit (recair's `Context` and gadgets)
  over the `p2` and `qm31` components, a fixed wiring per statement, so
  its circuit hash is its program id. Two components at least, so the
  claimed sums are blinded (a one-component masked set is not).
- **Format 42, credential proofs** (`device-params.md`): masked (c),
  Blake2s-M31 channel, **blowup 4, 43 queries, PoW 20** (or PoW 16 with 47
  queries, open question 15), interaction PoW 8, fold step 1, affine DEEP
  batching if the fork's Blake2s-M31 path takes it, else by powers; at
  least 62 proven and 100 conjectured bits on its masked shape (62.69 and
  106 [model]); `h = 512`, every component at least 2^11 rows. 30,
  reserved at an unmasked count, is retired unregistered.
- **The scope,** namespaced by the verifier:
  `scope = P2(TAG_SCOPE ‖ BLAKE2b-256(agent ‖ instance ‖ the guard's scope name))`,
  computed by ingress from the method's guard; two agents' "login" never
  share a pseudonym.
- **The binding:** `binding = P2(BLAKE2b-256("vos/cred/binding/v1" ‖ space ‖
  agent ‖ instance ‖ method ‖ program ‖ kind ‖ SCALE(arguments) ‖ nonce ‖
  expires_ms))`: a proof authorizes one call, in one space, under one
  statement.
- **Auth** (`CredentialKind::Auth = 0`), public
  `(kind, map_root, scope, nullifier, binding)`, each 8 M31; private `s`,
  the epoch, the slot and its path. Proves
  `leaf(slot, member(s, epoch))` under `map_root` and
  `nullifier = P2(TAG_NF ‖ s ‖ scope)`.
- **Pay** (`CredentialKind::Owner = 1`), public `(kind, owner, binding)`;
  private `s`. Proves `owner = P2(TAG_OWNER ‖ s)`: a post-quantum
  authorization by the owner of a row, about two permutations. No path,
  no range check: the ledger debits the live row at apply, so its guard
  compares the row's current `owner` with the proof's, and a previous
  owner's proof fails once the row changes hands. A hidden payer waits for
  full privacy (`identity-and-authority.md` §8).
- **The request:** `POST /agents/{id}/calls` with
  `Credentialed { call, kind, proof, public }`, no session (the reserved
  session-less input kind, `identity-and-authority.md` §15 step 0).
- **Ingress checks, in order:** the size (≤ 512 KiB); the format (42, or
  43 for a device proof, pin J); the program id the agent's schema pins
  for the method; the scope recomputed; for auth, `map_root` in the
  credential actor's ring as this replica has applied it (a root it has
  not applied yet is a retryable refusal, the identity replica's lag
  rule); the binding recomputed; `expires_ms` within 120 s of the node's
  clock; then the proof, on an executor. Each refusal a `403` with its
  code. **Load:** a bound per connection and an executor budget for
  verification (past it, `503` and retry), no bucket per scope or method
  that an attacker could drain for everyone.
- **At apply:** the binding refused if `expires_ms` is before the batch
  time, or if its digest is already recorded; the digest recorded until
  `expires_ms` plus the clock skew allowed (60 s) by batch time. So a
  proof replayed at another node runs nowhere twice.
- **The origin logged:** `Anonymous { scope, nullifier }` for auth (a
  pseudonym in its scope; "once in this scope" is the guard's rule) and
  `Owner { digest }` for pay; never the proof (`identity-and-authority.md`
  §5). Guards: `#[msg(credential = Auth("login"))]`,
  `#[msg(credential = Owner)]`.
- **Gate:** the native verify of a credential proof at most 10 ms on one
  x86 core.

### Pin J: the device profile, and format 43

- **The shape:** one segment, at most 2^16 steps; the segment chips
  without the page-Merkle boundary (BLAKE2B_BOUNDARY, MEMORY_PAGE,
  MEMORY_MERKLE, MEMORY_ROOT_BOUNDARY), plus pin H's Poseidon2 chip; the
  run bound by
  - code: PROGRAM_MEMORY, preprocessed;
  - first touches (`ts = 0` ledger entries): the data region from a
    preprocessed data table; stack and heap zero; elsewhere refused;
  - read-only pages: a preprocessed permission table per region;
  - arguments: the witness-input precompile; the output: the io-hash in
    φ9..12 only, no memory root out.
- **Masked** (c) over the segment chips (7.14): the active-chip mask, a
  finalize hook for the 14 chips that finalize unpaired, a per-component
  `h` by the component's offsets (`|O| = 1` components at half the
  floor), the fixed tables padded to the floor.
- **Format 43, device proofs:** Blake2s-M31 channel, parameters chosen by
  7.16 from `device-params.md`'s candidates (blowup 2 with 86–87 queries,
  4 with 43, or 4 with 47 at PoW 16, 8 with 29), at least 62 proven and
  100 conjectured bits on its masked shape. 37, reserved at an unmasked
  count, is retired unregistered.
- **The device program id:** the format, the chip mask, the log sizes and
  the preprocessed roots (program memory, data table, permissions), as a
  segment program's; computed at install, never taken as submitted.
- **What a device proof authorizes at ingress:** exactly what an auth
  credential proof does. A device kernel is an `#[attestable]` method whose
  `public_args` are pin I's auth words `(kind, map_root, scope, nullifier,
  binding)` and whose output is empty; ingress takes the words from the
  request, recomputes the io-hash, verifies the proof against the device
  program id the agent's schema pins for the method, then runs pin I's
  auth checks and logs the same `Anonymous` origin. Payment stays a
  credential proof. Nothing else a device proof states is admitted in this
  slice.
- **Budgets on the Fairphone 6** [decided S3 for time; proposed for the
  rest]: the auth statement at most **1.0 s** (median, the library's
  automatic threads), peak resident at most **1 GiB** (target 768 MiB),
  the proof at most 1.5 MiB; verify at ingress at most 40 ms on one x86
  core.

### Pin K: the device secret from a passkey's PRF

- **The PRF input:** `first = SHA-256("vos/prf/v1" ‖ handle)`, the WebAuthn
  PRF extension's `eval.first`; the client (the platform's WebAuthn
  client, not the authenticator) applies the `"WebAuthn PRF\0"` prefix.
  `handle` is the space's `SpaceId`, or a stable handle that survives a
  re-founding (open question 11).
- **The derivation:** `o` the 32-byte PRF output;
  `w = BLAKE2b-512("vos/device/secret/v1" ‖ handle ‖ o)`;
  `s_i = u64_le(w[8i..8i+8]) mod p` for `i < 8` (bias below 2^-33 an
  element); derived again at each use from a fresh assertion with user
  verification.
- **What a space stores:** `member(s, epoch) = P2(TAG_MEMBER ‖ s ‖ epoch)`
  in the credential actor, `owner = P2(TAG_OWNER ‖ s)` in a ledger row; a
  new passkey or a revocation bumps the epoch and re-enrolls. The handle
  is in the derivation, so one passkey gives unlinkable secrets in two
  spaces.
- **Containment, stated honestly** (in `SECURITY.md`): the library zeroizes
  `s` and its working copies, but the PRF output, equivalent to `s`,
  reaches the app as base64 in a Java string through Credential Manager
  and cannot be zeroized; a Google Password Manager passkey syncs, so `s`
  is bound to the Google account, not to the phone.

### Pin L: the device library

- **Crates:** `vos-device` (the prover API, `std`, aarch64 and x86_64),
  `vos-device-jni` (a thin JNI shim, `extern "system"` functions over byte
  arrays in the workspace codec), built for `aarch64-linux-android` with
  `cargo-ndk` against NDK 27.2, mimalloc, no other C dependency.
- **The API:**

  ```rust
  pub struct DeviceSecret(/* [M31; 8], zeroized on drop */);
  pub fn derive_secret(prf_output: &[u8; 32], handle: &[u8; 32]) -> DeviceSecret;
  pub fn member(secret: &DeviceSecret, epoch: u32) -> Digest;
  pub fn owner(secret: &DeviceSecret) -> Digest;
  pub struct ProverConfig { pub threads: Threads, pub max_memory: u64 }
  pub enum Threads { Auto, Count(usize), Cores(Vec<usize>) }
  pub struct Prover { /* the thread pool, the formats' twiddles */ }
  impl Prover {
      pub fn new(config: ProverConfig) -> Result<Self, DeviceError>;
      pub fn prove_auth(&self, s: &DeviceSecret, witness: &AuthWitness, scope: &Digest,
                        binding: &Binding) -> Result<CredentialProof, DeviceError>;
      pub fn prove_owner(&self, s: &DeviceSecret, binding: &Binding)
                         -> Result<CredentialProof, DeviceError>;
      pub fn prove_kernel(&self, program: &DeviceProgram, arguments: &[u8])
                          -> Result<DeviceProof, DeviceError>;   // M5
  }
  ```
  `Threads::Auto` weights work by core class (7.17); `DeviceError` names
  what failed and no value. No logging of witnesses; the library has no
  `seeded-masks` (pin C's build check covers it).

## M3.9: simplify and scale

Two tracks from the first day: the simplification (7.1–7.3) and the scale
harness (7.4–7.5) meet in the scale runs (7.6). The probes (7.0a, 7.0b),
M4's design round (7.7) and, if the owner agrees (open question 2), M5's
masking of the segment chips (7.14) run beside them.

### 7.0 The docs, the picks and two probes

- **7.0 The docs:** the owner's answers into `owner-decisions.md` and
  "Decisions"; `slice-7-progress.md` opened; `proving.md` §8's floor and
  §11's rows corrected; `core-model.md`'s "Draft 5" heading (slice 6's L8).
- **7.0a The device baseline on today's AIR** (a spike, throwaway code):
  slice 5's floor seam and statements rebased onto `f83f744b` (format 35's
  chips, Blake2s-M31 through the fork's channel); on x86 the as-built and
  floor shapes at log blowup 1 and 2, 4 and 8 threads; **a masked-cost
  proxy:** the floor shape with every column committed at its log size
  + 1 and the composition at + 2 (what masking (c) commits), unmasked
  values, timed and sized; the same kit on the Fairphone 6 by the
  phone-gate protocol. **Output:** today's starting point, the masking
  factor on this shape, and the proof's bytes at blowup 2 with 86–87
  queries against pin J's 1.5 MiB; M5's outlook redone with them, for
  open question 5. **Estimate:** 1–1.5 weeks.
- **7.0b The passkey PRF on the gate device** (a probe): a throwaway app
  creating a passkey with the PRF extension through Credential Manager
  (`androidx.credentials`) under the demo's relying party, then an
  assertion returning `prf.results.first`, twice, equal. PRF for a native
  app through Google Password Manager is not documented: this probe is
  the evidence. **The relying party** (open question 1): a subdomain that
  serves `/.well-known/assetlinks.json` and nothing else (any page there
  could ask for the same PRF input and derive `s`); a demo keystore
  committed, its certificate's SHA-256 in `assetlinks.json`.
  **Fallback:** a FIDO2 security key's `hmac-secret` through a CTAP
  library over USB or NFC (Credential Manager may not pass PRF to a
  security key), applying `SHA-256("WebAuthn PRF\0" ‖ input)` itself so
  its secret equals the PRF path's; else a stored key stands in for the
  PRF in the demo. **Estimate:** 2–3 days.

### 7.1 The venue side simplified (S)

- **What:** the owner's picks among C6 (the venue core), C1 (no
  migration), C4 (equivocation), C8 (registration from the next window)
  and C7 (rooted statements only) at `vos-anchor`, `vos-statement`,
  `ModelVenue`, the JAM statements service, the Kreivo mock and client,
  and jam-dev's client; `spaces-pallet.md` v2 and the conformance vectors
  regenerated once, with a change note: the teammate's first drop (the
  second is 7.8's kit blobs).
- **Folded:** slice 6's F2 (`behind()`'s read on the batch thread goes with
  the client's pre-checks), F3 (with resume, if C4), L4 (strict ed25519,
  and a small-order key refused at registration and when added, with a
  vector), L3's migration half, item 74 (`forward_venue!`), item 29 (the
  control tests), and the info items: duplicate founding keys
  `BadGenesis`, the service's storage read trapping on an undecodable row.
- **Tests:** the core's own suite (every rule, every refusal) run against
  each venue's state; G1–G19 renumbered as the picks leave them; the
  fixtures judged alike at every venue; with C4 the tombstone (an ended
  space's registration replayed, refused).
- **Gate:** every venue calls the core; no anchor-rule logic outside it
  (a grep check in `just check`); the vectors regenerate byte for byte.
- **Dep:** 7.0, the simplification questions, open question 4.
  **Estimate:** 2–3 weeks.

### 7.2 The node's anchoring simplified (S)

- **What:** the owner's picks among C2 (the node key alone), C3 (the
  replicated anchor row, no hand-back) and C5 (the outcome enums) in
  `node/host/src/leader/anchor.rs`, `anchor_keys.rs`, `vos-venue`'s queue
  and trait, the replica rule, the prover worker's submit mapping, and the
  CLI (`vos node anchor-key` removed if C2).
- **Folded:** slice 6's L5 (jam-dev's `push` wedge) and the untested
  once-a-window recheck, both gone with the hand-back.
- **Tests:** anchors in order across a leader change; an unlisted leader
  handing off to a listed replica, which anchors; a delisted node's
  replica refused and replaced; an equivocation stopping the space; an
  aged window settled unsent; every venue code through each client's
  table.
- **Gate:** the checker loop with cuts and the representative; the
  leader's anchoring state and wait paths counted against `simplify.md`
  §4.
- **Dep:** 7.1. **Estimate:** 1.5–2.5 weeks.

### 7.3 Reads, reports and the worker's edges (S)

- **What:** C9 (no re-cuts), C10 (markers, cuts and reports only for
  windows a read waits on, and every window for an agent that opts in)
  and C11 (no anchor for an unreported window), if picked; the prover
  worker's carried edges: slice 6's M3 (a replica that installs a
  snapshot and leads recovers the unproved set from replicated state: an
  "attested, unproven" marker per cut it scans), M4 (`prune` ages out
  every unfinished job; an unfinished job's kernel pinned under
  `NODE_AGENT`), L6 (a)–(f); item 68 (a `closes` row that does not decode,
  open question 17).
- **Tests:** a read served at its own window; `NotClosed` when the close
  misses it; an idle agent appends no marker; an opted-in agent reports
  every window; a window no one reported is not anchored; a leader change
  and a snapshot install with statements queued, each proved once.
- **Gate:** the checker loop; the cut's bench (a write with a cut pending,
  a cut's build with 100 proofs) within 10% of slice 6's.
- **Dep:** 7.2. **Estimate:** 1.5–2.5 weeks.

### 7.4 The scale harness

- **`tools/scale`** (`vos-scale`, a dev crate no shipped crate depends on,
  a `check-no-*` row), driven by an `inventory.toml` of x86_64 hosts (ssh
  address, role, a placement weight, the data disk, the cores to use):
  - `check`: ssh reach, the kernel (the JIT needs Linux ≥ 6.7; an older
    host is excluded or weighted down), clock offsets (refused above
    100 ms), free memory and disk, the CPU;
  - `deploy`: a static musl build of `vos` from a pinned `just release`,
    the guest ELFs, the space file and genesis, by `rsync`;
  - `up`, `down`: nodes under `systemd-run --user` with a memory cap;
    ingress over the node's built-in `--tls` with the node key pinned
    (plain HTTP serves loopback only), no certificates of the harness's
    own; `agents`: creation and installs by the weights; `drive`: the
    drivers (7.5);
  - `collect`: `/stats`, `/agents/*/status`, per-thread `/proc`, disk and
    network counters every 10 s as JSON lines; `report`: one directory a
    run, with its inventory, versions, host facts and summary.
- **Node changes it needs:** a `--config node.toml` exposing `Config`
  (executors, queue, linger, `max_inputs`, `ingress_connections`,
  elections, heartbeat); an admin route and `vos space representative` to
  create the representative; slice 6's L3 (`default-members` without the
  dev crates, so the release build is the one gated). No venue: the runs
  measure the window pipeline to the close, and anchoring is one call a
  window a space.
- **Gate:** a three-host run of 100 agents and 10,000 users from one
  command, collected and reported, on two of the owner's machines at
  least.
- **Dep:** 7.0. **Estimate:** 1.5–2.5 weeks.

### 7.5 The load model and its drivers

- **Users:** `U` simulated users, each an ed25519 key derived from a seed
  and an index (nothing stored), each with an account row in one of `K`
  ledger agents (by hash), a session opened at its first call and kept
  while it acts. **One rate drives every target:** a share `a` of users
  active at once, each making `r` calls a second while active; the
  offered load is `U·a·r` (at `a` = 5%, `r` = 0.1, 5,000 calls a second
  at a million users).
- **Agents:** `K` ledger shards (a test actor with a `CommittedMap` of
  accounts), `I` idle agents (installed, never called), and **a stand-in
  identity agent:** `U` identity rows replicated on every node host, its
  writes at 10 a second (enrollments, revocations) and its snapshots and
  catch-up measured; the per-call ingress read of it is not modeled (no
  such path exists yet).
- **Operations,** open loop (Poisson, latency timed from the scheduled
  send), users drawn Zipf(1.0): transfers (a **cross-shard share** `x`, a
  parameter: random payees give `x = 1 − 1/K`, about 98% at `K = 64`),
  queries on followers, workflows, and reads at a cut (`attest_at_cut`,
  the window pipeline without proving). Each kind reported apart.
- **Drivers:** each signs ahead, multiplexes users over at most 512 kept
  connections a node, and reports per-operation histograms (p50, p99,
  p99.9), the achieved rate and errors by kind every 10 s.
- **Not modeled,** stated in every report: credentialed calls (M4's,
  measured apart in 7.11), cross-space traffic, proving.
- **Gate:** one driver sustains 20k calls a second on one core-pair of a
  driver host; the operation mix within 1% of its target.
- **Dep:** 7.4. **Estimate:** 1–1.5 weeks.

### 7.6 The scale runs

- **The runs,** in order, each 30 minutes steady after a ramp; every run
  that measures windows at `L` = 2 min (15 windows a run):
  1. **the per-replica cost:** 1k, 5k and 10k idle agents: RSS, idle wakes
     and the runtime thread's `late` by group count (the group inbox
     allocated whole at creation, and idle Raft timers, are the suspects;
     quiescing idle groups is the lever), fixed first if it binds;
  2. **the baseline:** `K = 64`, `U = 10^5`, `x` = 98% and again at 30%,
     the rate stepped to the knee;
  3. **users:** `U = 10^6`, `K = 64`, at the T1 rate, then at 80% of the
     knee;
  4. **agents:** `I` stepped 10^4 → 10^5 at the baseline's load;
  5. **faults:** run 3 with a node host killed at minute 10, restarted at
     minute 15;
  6. **soak:** run 3 for 2 hours.
- **Folded:** slice 6's item 53 (one snapshot per idle wake), item 58's
  performance half (the worker's table reads), and the levers the runs
  show binding (the runtime thread, the inbox, idle timers, the signature
  key cache), each a commit with its before and after; the ops notes
  (slice 6's L8, the clock-jump outage, catch-up by log) in
  `docs/operations.md`.
- **Gate:** "The scale test" targets met, or each miss recorded with its
  measured cause and its lever (a step, or carried by name).
- **Dep:** 7.3, 7.5. **Estimate:** 2–4 weeks.

### M3.9 acceptance

- **Gates:** `ci-full`, the checker loop, the scale runs 1–6 reported;
  `simplify.md`'s counts redone after the picks.
- **Reviews:** Fable on 7.1–7.3 and the scale report; then a push.

## The scale test

**Hardware** [decided, S2]: the owner's desktop and other LAN machines,
uneven, on a real network. The topology is the inventory's: 3 to 5 node
hosts, one `vos` process each (the desktop may run two), every agent's 3
replicas on three hosts by weight; 1 or 2 driver hosts; the desktop as
coordinator running `vos-scale`.

**What "users" means:** a user is a key and an account row, not an agent:
an agent holds at most 65,536 live sessions (slice 3's cap), so a million
users active within an hour need at least 16 shard agents; the agent is
the unit of scaling, the row the unit of users.

**Metrics:** per operation p50, p99 and p99.9 at the client and the
achieved rate; per node CPU by thread (the `vos-node` runtime thread
above all), RSS, idle wakes, fsync latency, disk and network bytes; per
agent leader changes; the window pipeline (boundary to cut built, to
report, to close); clock offsets between hosts; cost per user (bytes on
disk, CPU per call) and per idle agent (RSS, CPU, wakes).

**Targets** [proposed; open question 12], from the one rate (`a` = 5%
active at once, `r` = 0.1 calls a second each), checked after run 2 and
adjusted only by the owner:

| | target |
|---|---|
| T1 users | 10^6 users in one space at `U·a·r` = 5,000 calls a second, cross-shard share 98%, client p99 at most 50 ms, no session refused |
| T2 headroom | the knee at least 8× T1's rate (40,000 calls a second) on 4 node hosts or more, client p99 at most 50 ms below it, no leader lost: room for 8 million users at this rate |
| T3 agents | 10^4 agents a space: idle cost at most 5% of a core and 64 MiB of RSS per 1,000 replicas (10^5 measured, a stretch) |
| T4 windows | at L = 2 min, 15 windows, with 1% of agents reading each window: every read served by `B_w + D + 10 s`, none `NotClosed` without a fault; the representative's work a window proportional to readers (C10) |
| T5 faults | a node host killed under load: every agent led again within 5 s, throughput back to 80% within 30 s, the host rejoined within 60 s of its restart |
| T6 soak | 2 hours at T1: RSS flat within 10% after the first 30 minutes, p99 within 20% of the first half hour |

## M4: the credential AIR

7.7, 7.9 and 7.10 may start beside M3.9 (open question 2); 7.8, the
re-pin, waits for 7.3, which changes the agent image last.

### 7.7 The design round

- **What:** pins G, I, K and L checked against the code and the owner's
  answers (open questions 7–11, 15): the actor's rows and its ring, the
  statements' exact public words, the scope and the binding, the ingress
  order and the origins, the library's API; written into `proving.md` §8
  and `identity-and-authority.md` §5–§7.
- **Dep:** 7.0. **Estimate:** 1 week.

### 7.8 The re-pin batch (S)

- **What, one commit** (slice 6's carried list): items 4's guest half,
  17–25 (the `#[repr(u8)]` enums first), 64–66, 67, 69, 16's unmasked
  half, 26 (`SpaceGenesis::version`), 27 (the `ANCHORS` mode out of
  `final-verify.elf`), 28 (the strictness fix, `read_nat` shared), 3's
  `TryFrom<u32>` for `AnchorCode`, 33's `FetchKind`; item 13 (the witness
  digest from `statement_header_words`); item 18's rest (`array::from_fn`
  in `agent/tree`'s hash, `leaf_terms`' named offsets); slice 6's L2
  (`blobs.lock`, checked by `check-no-std`); the fixtures and vectors as
  7.1 left them. 7.1–7.3 change the agent image and the service's blob
  before this, but no hash pins a blob until `blobs.lock`: this is the
  slice's one re-pin, the teammate's second drop (the kit's blobs).
- **Gate:** the stale-fixture test re-pinned once; format 35, `H_FOLD` and
  the wraps' roots byte for byte; `repro-aarch64` equal.
- **Dep:** 7.3. **Estimate:** 1.5–2.5 weeks.

### 7.9 The Poseidon2 host call and the credential actor (S)

- **What:** pin H's `0x402` in the runtime (`precompile.rs`, the refine
  host, the inner machines, the wire's price table) and the guest shim's
  software fallback; pin G's `vos-credentials` actor (enroll, revoke,
  `path`, the ring) as a library actor; its price measured. No change to
  `node/host/src/roots` (so 7.3 and 7.9 do not meet).
- **Tests:** the tree equals a reference built from scratch over random
  enrollments and revocations, on VOS and on the JAM-only host; slots
  reused lowest first; a path verified by the reference; a word ≥ p
  trapping the live call.
- **Dep:** 7.7. **Estimate:** 1–1.5 weeks.

### 7.10 The credential AIR (S)

- **What:** pin I's circuits (auth, owner) on recair's `Context`; a
  `MaskedComponents` set of `p2` and `qm31` (after the test's `P2Only`);
  the Blake2s-M31 channel wired in `pcs.rs` (the fork's
  `Blake2sM31MerkleChannel`); format 42 with its count on its own masked
  shape; the prover and `verify_masked` over it.
- **Gates:** soundness (a wrong path, a nullifier of another secret, an
  owner digest of another secret, a changed binding, each refused) and
  the forgery gates (a prover that skips the path's bits or the leaf's
  tag); a one-component masked set refused; leakage 2, 3 and 5 at N = 500
  in `test-proof` (2,000 at the slice's end); on x86 auth at most 60 ms
  and owner at most 30 ms on 4 threads [est from the masked floor: 2^11
  rows × about 400 columns].
- **Dep:** 7.7, 7.9 (the tree's hashes). **Estimate:** 3–4 weeks.

### 7.11 The verifier at ingress (S)

- **What:** pin I's request, checks, apply rule and origins in
  `node/host/src/ingress.rs` and `calls.rs`; the origin ABI's `Anonymous`
  and `Owner` kinds and the session-less input kind
  (`identity-and-authority.md` §15 step 0); the guards; the replicated
  binding set; a challenge route for clients that want a server nonce.
- **Tests:** each check's refusal in order; a proof replayed at another
  node, refused at apply; an expired binding at apply by batch time; a
  root the replica has not applied (retryable); a proof of one call sent
  with another; two agents' scopes distinct; the origin logged, the proof
  not; a pay proof refused once the row's owner changed.
- **Gate:** pin I's verify time; 1,000 credentialed calls a second on one
  node at p99 within 50 ms of a signed call's.
- **Dep:** 7.10. **Estimate:** 1.5–2.5 weeks.

### 7.12 The device library and the credential phone gate

- **What:** pins K and L for M4 (`prove_auth`, `prove_owner`, the
  derivation), the Android build, and the phone bench (`tools/phone`,
  both builds).
- **Phone gate PG1** (Fairphone 6): auth masked at most **250 ms** (target
  150 ms) and owner at most 150 ms, each within 256 MiB, the 95th
  percentile recorded; verified on the phone and on x86; the seeded
  build's bytes equal to x86's.
- **Dep:** 7.10. **Estimate:** 1.5–2.5 weeks.

### 7.13 The Android demo

- **Scope, minimal:** one Kotlin activity (Views, no Compose), minimum SDK
  34; the library through JNI (`arm64-v8a`); the Gradle wrapper; the demo
  keystore of 7.0b; the phone reaches the development machine's space by
  `adb reverse tcp:7700 tcp:7700`, with a `network_security_config`
  allowing cleartext to `localhost`, so the ingress's plain HTTP on
  loopback serves it.
- **Three buttons:** *Enroll* (create a passkey with PRF, derive `s`, send
  `member(s, 0)` and `owner(s)` to the space's credential and ledger
  actors under an operator-granted invitation); *Sign in* (a PRF
  assertion, the path fetched, auth proved, the call sent, its answer and
  the proving time shown); *Pay* (an amount and a payee, the owner proof,
  the transfer sent, the balance shown).
- **Not in scope:** recovery, several devices, iOS, the Play Store, UI
  beyond the three buttons, storing anything but the credential id.
- **Gate PG3:** the three flows end to end on the Fairphone 6 against a
  local space, recorded (a screen capture and the node's log).
- **Dep:** 7.0b, 7.11, 7.12. **Estimate:** 1.5–2.5 weeks.

### M4 acceptance

- **Gates:** `ci-full`, the checker loop, PG1, PG3.
- **Recorded:** the credential AIR's rows, proof bytes, proving on x86 and
  the phone, verify at ingress; `0x402`'s price; the re-pinned constants.
- **Reviews:** Fable on 7.8–7.11 (the re-pin, the actor and its host call,
  the AIR and its masking, the ingress); then a push.

## M5: the device profile

### M5's outlook

**The gate (S3, ≤ 1 s on the Fairphone 6) is at real risk.** The
projection [est, from slice 5's cells and the phone's floor; 7.0a
corrects it]:

| | factor | time | basis |
|---|---|---|---|
| the floor, 8 threads, blowup 4, unmasked, the stale AIR | | 2.2 s | [measured] |
| lever 1: the statement over a Poseidon2 tree, BLAKE2B's 12.2M of 34.1M cells gone | ×0.64 | 1.41 s | [measured cells] |
| masking (c): every column at twice its rows | ×2.0–2.9 | 2.8–4.1 s | the wrap's ×2.6–2.9 [measured]; ×2.0 the doubled domain alone |
| blowup 2, if its proof fits 1.5 MiB (7.0a) | ×0.8 | **2.25–3.3 s** | [measured, slice 5] |
| lever 2: threads by core class, the preprocessed commitment at install | ×0.9 | 2.0–2.95 s | [measured: 4 threads vs 8; 2–9%] |
| lever 3: a lean kernel (the path walked in place, no copy; CPU, registers and memory are 88% of what remains) | ×0.55–0.7 | 1.1–2.1 s | [model, slice 5; the masked floor bounds it] |
| lever 6: the CPU split by opcode family (the CPU about half of what remains) | ×0.65–0.75 | 0.72–1.55 s | [model] |
| lever 5: word-level memory | ×0.88–0.92 | 0.65–1.4 s | [model] |

So 1 s is reached only at the favourable end, after levers 1–3 and the
CPU split; the unfavourable end stays near 1.4–1.5 s with every lever.
The plan therefore **expects the CPU split** (7.18) and keeps word-level
memory next (7.19), and asks the owner, after 7.0a's masked proxy, whether
the gate stands (open question 5).

### 7.14 Masking the segment chips (S)

- **What:** `MaskedComponents` over the segment AIR's `BuiltInComponent`s:
  the active-chip mask in `draw_relations`, a finalize hook for the 14
  chips that finalize unpaired, a per-component `h` from its offsets, the
  fixed tables' multiplicity columns padded to the floor; the degree audit
  (5,177 constraints at ≤ 3 under (c), slice 6's R5) on the built set.
- **Gates:** soundness 1–10 and leakage 1–7 (slice 6's 6.6) on a masked
  segment of a small kernel; R1 on every column class; **format 35's
  proofs byte for byte** (the shared segment prover unchanged for nodes).
- **Dep:** 7.0a. **Estimate:** 4–6 weeks.

### 7.15 The device shape and its Poseidon2 chip (S)

- **What:** pin J's boundary-free shape (the data table, the first-touch
  rules, the permission table, the io-hash output), pin H's chip, the
  device program id, derivation at install.
- **Forgery gates:** a first touch of a data byte other than the table's,
  a nonzero first touch of stack or heap, a touch outside the regions, a
  write to a read-only page, a second segment; a Poseidon2 output not the
  permutation's, an input word ≥ p (p included), a call without its row:
  each refused.
- **Dep:** 7.14, 7.9 (the call). **Estimate:** 3.5–5.5 weeks.

### 7.16 The device parameters, measured

- **What:** the auth statement (open question 6) under the device shape,
  masked, at the candidates (blowup 2 with 86–87 queries, blowup 4 with 43
  at PoW 20 or 47 at PoW 16, blowup 8 with 29; the Blake2s-M31 channel,
  Blake2b-256 for comparison) on x86, then on the phone; format 43 pinned
  at the fastest candidate within pin J's memory and size budgets, by its
  median and its 95th percentile.
- **Dep:** 7.15. **Estimate:** 1–1.5 weeks.

### 7.17 Levers 1–4

Each measured on the phone before the next.
1. **The statement over the credential actor's Poseidon2 tree** through
   the chip (open question 6): BLAKE2b and the AND table leave the shape.
2. **Threads by core class** (`Threads::Auto`: the A720s and A520s given
   work by their measured rate, not rayon's even split), and the
   preprocessed commitment computed once at install.
3. **A lean kernel:** no argument copy, the path walked in place.
4. **Parameters again:** per-component `h`, blowup, queries and PoW
   re-chosen on the lighter shape.
- **Estimate:** 1.5–2 weeks.

### 7.18 The CPU split by opcode family (expected)

- **What:** the device chips' CPU split into components per opcode family
  (ALU, memory, control, host calls), each with only its columns, so a
  row pays for its family alone (−50–70% of the CPU's cells [model,
  `proving.md` §9]); in the device format only (open question 9); its
  forgery gates per family.
- **Exit:** PG2 passes twice, a day apart, or the owner decides between
  7.19 and the measured time (open question 5).
- **Dep:** 7.17. **Estimate:** 6–10 weeks.

### 7.19 Word-level memory (if PG2 still misses)

- **What:** the device chips' memory argument at word granularity: 4–8×
  fewer MEMORY rows [model]; forgery gates for sub-word access.
- **Dep:** 7.18 and the owner's call. **Estimate:** 4–6 weeks.

### 7.20 The device kernel at ingress, and PG2

- **What:** `prove_kernel` (pin L); pin J's ingress path (a device proof
  authorizing as an auth credential does); the demo's *Sign in* given a
  choice of the general zkVM's auth kernel beside the credential AIR.
- **Phone gate PG2** (Fairphone 6): the auth statement under the device
  profile, masked, **at most 1.0 s** (the median of three rounds' medians,
  the 95th percentile recorded), peak resident at most 1 GiB, proof at
  most 1.5 MiB; verified on the phone and accepted at a space's ingress.
- **Dep:** 7.11, 7.18 (or 7.19). **Estimate:** 1–2 weeks.

### M5 acceptance

- **Gates:** `ci-full`, the checker loop, PG2 (or the owner's call on the
  measured time).
- **Recorded:** the device shape's rows by chip, each lever's effect on
  the phone, the proof's bytes, verify at ingress.
- **Reviews:** Fable on 7.14, 7.15, 7.18 (and 7.19) and the parameters;
  then a push.

## The slice's end

### 7.21 The carrier audit, extended

- **What:** slice 6's R7 audit over the new carriers (the credentialed
  call and its log entry, the `path` query, the library's errors, the JNI
  shim, the demo's log, the phone bench); slice 6's M6 (more needles, a
  run over small values).
- **Dep:** 7.11, 7.20. **Estimate:** 1 week.

### 7.22 Acceptance, the quality review and the carried rest

- **Gates:** `slice-gate`, the checker loop, `just e2e-chain`, the kit's
  sync check, the scale test's run 3 again on the final build, PG1, PG2
  and PG3 on the final build.
- **The carried rest** (behaviour-preserving commits, proof bytes
  unchanged): slice 6's M5(d) (the release binary scanned), M5 (fault text
  out of logs and answers), L1 (a seeded-hash pin of the small masked
  circuit in `check`), L8's `ABOUT` string, L9's rest (`tamper` under
  `seeded-masks`, `ProveError`'s values, a `stwo=warn` default,
  `check-no-faults` in `check`), items 14, 30, 31, 35, 50, 70 and 77; the
  six owner's-call items if the owner agrees (open question 18).
- **Reviews:** the Opus code-quality review, then the slice-end Fable
  review, each folded. **Docs:** `proving.md` draft 7, `core-model.md`,
  `identity-and-authority.md`, "Slice 7 accepted".
- **Estimate:** 3–4 weeks.

## Where the carried items land

| carried from slice 6 | where |
|---|---|
| the slice-7 re-pin batch (quality items 3, 4, 13, 16–28, 33, 64–67, 69), item 18's rest, L2's `blobs.lock` | 7.8 |
| F2, F3, L4, item 74, item 29, the info items (duplicate founding keys, the service's lenient read) | 7.1 |
| `migrate_digest`'s nonce; L3's one-way migration | 7.1 (gone with C1, or carried if C1 is not picked) |
| L5 (jam-dev's `push`), the untested once-a-window recheck | 7.2 (gone with C3) |
| L4 of M3b/M3c (no production prover for rootless statements) | 7.1 (by design with C7; else carried) |
| M3, M4, L6 (a)–(f): the worker's edges; item 68 and its owner call | 7.3 |
| the representative's load lever (6.19's ops note) | 7.3 (C10, C11) |
| items 53, 58's performance half; L8 and the clock and catch-up ops notes | 7.6 |
| L3 (`default-members`, the release build gated) | 7.4 |
| M6, the audit's needles | 7.21 |
| M5(d), M5, L1, L8's rest, L9's rest, items 14, 30, 31, 35, 50, 70, 77 | 7.22 |
| the owner's-call items 1, 5, 34, 46, 54, 58 | 7.22 if the owner agrees, else carried |
| 5.6's phone run | done (2026-10-25); 7.0a repeats it on today's AIR |
| one founding key registers the space anywhere (pin D's known limit) | carried: its lever adds a rule |
| the representative's clock guard (a quorum of follower clocks) | carried unless the scale runs show the skew binding |
| M6(d)'s FRAME-agnostic runner; M6(e)'s code with the port; M3b's deferred Kreivo gates 1–5 | carried: the teammate's pallet and the port, after the slices |
| the prover-time levers (ALU padding, WITNESS_INPUT in the entry class, a leaf over small segments) | carried: node proving is not this slice's |
| the Blake2b hook (decision 4); `getrandom`'s failure (inherent, documented) | carried |
| C-DJUMP, the ledgers' 2^27 gap, the BLAKE2b pointer near 2^32, refine slices' page permissions | the audit's scope |
| the external audit | after slice 6, before value; its scope gains the credential AIR, the device shape, its Poseidon2 chip and their masking |
| the heavy cleanup before master | carried |

## Risks, and the gate that retires each

| risk | gate | when |
|---|---|---|
| **likely:** the device profile misses 1 s on the Fairphone 6 (M5's outlook: 0.65–1.4 s with every lever) | 7.0a's masked proxy on today's AIR first; the owner's call on the gate then (open question 5); 7.17–7.19 in order, each measured on the phone | 7.0a, 7.17–7.19 |
| masking the segment chips costs more than the wrap's factor (the 2^12 floor, padded tables, 14 unpaired chips), or its proofs are too big to send | 7.0a's proxy and bytes; 7.14's gates; per-component `h`; blowup 4 halves the floor and the bytes; pin J's 1.5 MiB | 7.0a, 7.14, 7.16 |
| a device format under its margin (37 counts 61.86 under (c)) | formats 42 and 43 counted on their masked shapes, pinned by tests | 7.10, 7.16 |
| 7.14 breaks the nodes' segment proofs (it edits the shared prover) | format 35's proofs byte for byte | 7.14 |
| Credential Manager returns no PRF to a native app on Android 16 (undocumented) | 7.0b's probe; a security key's `hmac-secret` through a CTAP library; a stored key as the last fallback | 7.0b |
| a page at the relying party derives members' secrets | the subdomain serves `assetlinks.json` only | 7.0b |
| a single-component masked set leaks its claimed sum | two components at least (pin I), a test that a one-component set is refused | 7.10 |
| a credential proof replayed at another node, or across agents or spaces | the binding names the space, agent, method and program; recorded at apply; scopes namespaced | 7.11 |
| ingress becomes a verification DoS target | the size cap first, the cheap checks before the proof, a bound per connection and an executor budget, no shared bucket | 7.11 |
| path fetches reveal which member proves | stated in pin G and `SECURITY.md`; syncing the tree is the later fix | 7.9 |
| the re-pin breaks the kit, the vectors or the teammate's vendored tree | one re-pin (7.8), `blobs.lock`, the vectors regenerated once in 7.1; two drops announced | 7.1, 7.8 |
| simplifying pin D changes a design the teammate is building | open question 4 before 7.1; one regeneration of `spaces-pallet.md` and the vectors | 7.0 |
| a stolen key ends a space for good (if C4 is terminal) | C4 asked apart, with a governance revive as an option; the tombstone | 7.1 |
| per-replica memory, idle timers or the single runtime thread cap agents per node | 7.6's run 1 first; quiescing idle groups the named lever | 7.6 |
| LAN clock skew fails reads or moves windows | `vos-scale check` refuses offsets above 100 ms; C9's fail rate measured | 7.4, 7.6 |
| thermal throttling skews the phone numbers | the runbook's temperature and battery checks, rounds 60 s apart, the 95th percentile recorded | every PG |

## Estimates

| | weeks |
|---|---|
| 7.0, the docs and the probes | 1.5–2 |
| M3.9 simplification (7.1–7.3) | 5–8 |
| M3.9 scale (7.4–7.6) | 4.5–8 |
| M3.9 acceptance | 0.5 |
| M4 (7.7–7.13 and acceptance) | 11.5–17 |
| M5 (7.14–7.18, 7.20 and acceptance) | 17.5–27.5 |
| M5's word-level memory, if needed (7.19) | 4–6 |
| the slice's end (7.21–7.22) | 4–5 |
| **slice 7, engineer-weeks** | **about 44–68, up to 74** |

- **The critical path is M5's chain:** 7.0a → 7.14 → 7.15 → 7.16 → 7.17 →
  7.18 → 7.20 → M5's acceptance → 7.21 → 7.22, about **22–34 weeks** of
  calendar when 7.14 starts beside M3.9 (open question 2), up to 40 with
  7.19.
- **Strictly in order** (M3.9, then M4 and M5), M5's chain starts after
  M3.9's 7–12 weeks: about **29–45**, up to 51.
- **Beside it:** M3.9's two tracks (7.1 → 7.2 → 7.3 → 7.6, and 7.4 → 7.5
  → 7.6); M4's chain (7.7 → 7.9 → 7.10 → 7.11 → 7.13, with 7.8 after 7.3
  and 7.12 after 7.10), about 9–12 weeks, done within M5's.
- **Against `proving.md` §11's 12–20 weeks for M4 and M5:** that row left
  out M3.9, the re-pin, the ingress verifier, the demo, masking the
  segment chips (7.14) and the CPU split.

## Decisions

**Taken by the owner:** S1–S5 (`research/slice-7/owner-decisions.md`).

**What the simplification would reverse** (H2; each asked in
`simplify.md` §7; none reversed until the owner answers):
- **decision 7** (the controller rotates keys; equivocation suspends, then
  resume): its rotation by C2, its resume by C4;
- **decision 8** (migration ranges and the per-program `venue_bound`): by
  C1 and C7;
- **decision 10** (a rootless `Seen` entry never expires): by C7;
- **decision 18** (resume, with the disputed window dead): by C4;
- **`proving.md` §7:** its [decided] equivocation text (C4), its venue
  migration (C1), and "`S_w` over every agent's root" (C10);
- **`spaces-pallet.md`:** §13 questions 2 and 12 (the paired key and the
  rotation calls, C2), §6's calls 5 and 6 (C1, C4), vectors G5, G14, G15
  and G19.

**Settled by the evidence, the owner's to override:** device formats
counted on their masked shapes (30 and 37 retired unregistered, 42 and 43
new); the credential tree in the actor's own rows, `RootKind` untouched
(pin G); the credential AIR as a recair circuit over `p2` and `qm31` (pin
I); the node's segment format unchanged, the Poseidon2 chip in the device
format (pin H, open question 8).

## Open questions

Ranked to be asked one at a time, in this order; each has a
recommendation. The simplification's own eleven questions are
`simplify.md` §7, asked as question 3.

1. **The demo's relying party.** Blocks 7.0b on its first day.
   - (a) A subdomain the owner controls, serving only `assetlinks.json`
     for the demo's package and its committed demo keystore.
   - (b) A FIDO2 security key's `hmac-secret` through a CTAP library.
   - (c) A stored key standing in for the PRF in the demo.
   - **Recommended: (a).**
2. **M5's and M4's groundwork beside M3.9.** Blocks the schedule.
   - (a) 7.0a at once; 7.14 from 7.0a's end, and 7.7, 7.9 and 7.10 from
     7.0, all beside M3.9.
   - (b) Strictly in order: M3.9, then M4, then M5.
   - **Recommended: (a):** the 1 s gate is the slice's largest risk and
     the critical path is M5's; (b) adds about 7–12 weeks.
3. **The simplification candidates,** one at a time (`simplify.md` §7: C6,
   C1, C8, C4, C7, C2, C3, C5, C9, C10, C11). Blocks 7.1. C4 has its own
   costs: a re-founding strands the sovereign's funds and the Clerk's
   pairs, makes members re-enroll, and lets one stolen key end a space.
4. **The Kreivo teammate's design**, if the picks change it. Blocks 7.1.
   - (a) `spaces-pallet.md` v2 and the vectors regenerated in 7.1, the
     teammate told now (two drops: 7.1, 7.8).
   - (b) The handed design frozen; VOS stops using what it drops.
   - (c) Ask the teammate first and decide by how far the pallet is.
   - **Recommended: (c), defaulting to (a).**
5. **S3's gate, given M5's outlook** (0.65–1.4 s with every lever). Asked
   now, answered after 7.0a.
   - (a) Keep ≤ 1 s; build the CPU split (expected) and word-level memory
     if needed.
   - (b) Gate on the measured time after the CPU split, and carry the rest.
   - (c) Move the gate to the budget a flagship meets (about 2× this
     phone: ≤ 2 s here).
   - **Recommended: decide after 7.0a's masked proxy;** until then (a).
6. **The auth statement M5's gate measures.** Blocks 7.16.
   - (a) Slice 5's statement as it is: a BLAKE2b vos-tree path and a
     nullifier.
   - (b) The same statement over the credential actor's Poseidon2 tree
     through the device chip.
   - (c) Both must pass.
   - **Recommended: (b),** with (a) measured: it is the statement a space
     uses once M4 lands, and it drops BLAKE2b from the gate.
7. **The payer.** Blocks 7.7.
   - (a) Public: pay is a proof of knowing `s` behind the row's owner
     digest, bound to the call, checked against the live row (pin I).
   - (b) Hidden: needs a shielded pool, postponed with full privacy.
   - **Recommended: (a).**
8. **The Poseidon2 chip's home.** Blocks 7.15. (a) The device format
   only, the node's segment format unchanged; (b) the node's format too,
   re-pinned in 7.8. **Recommended: (a):** no node kernel needs it yet.
9. **Where M5's levers land.** Blocks 7.18. (a) In the device chips
   alone, the node's format taking them at a later re-pin; (b) in both,
   with a second re-pin at the slice's end. **Recommended: (a).**
10. **What a device proof authorizes at ingress.** Blocks 7.20. (a) What
    an auth credential does (pin J); (b) nothing this slice, device proofs
    verified in the bench only. **Recommended: (a).**
11. **The PRF input's handle.** Blocks 7.7.
    - (a) The `SpaceId`: a re-founding (C4) makes every member re-enroll.
    - (b) A stable 32-byte handle the founder draws once and every
      re-founding keeps.
    - **Recommended: (b) if C4 is terminal, else (a).**
12. **The scale test's targets.** Blocks 7.4.
    - (a) T1–T6 as proposed, from one per-user rate.
    - (b) Users only: T1, T2, T5, T6.
    - (c) Higher: 10^5 agents gated.
    - **Recommended: (a),** adjusted after run 2.
13. **The phone's memory budget.** Blocks 7.12 and 7.16. (a) At most 1
    GiB peak resident, a target of 768 MiB; (b) 768 MiB; (c) 512 MiB.
    **Recommended: (a).**
14. **The thread policy PG2 measures.** Blocks 7.17. (a) The library's
    automatic choice (all cores, weighted by class); (b) the four big
    cores alone; (c) all eight, evenly. **Recommended: (a),** with (b)
    recorded.
15. **The credential format's parameters.** Blocks 7.10.
    - (a) Blowup 4, 43 queries, PoW 20.
    - (b) Blowup 4, 47 queries, PoW 16 (62.66 proven bits): a lighter grind
      on the phone, a slightly bigger proof.
    - (c) Blowup 8, 29 queries.
    - **Recommended: (b)** if 7.12 shows the grind's 95th percentile above
      50 ms, else (a).
16. **The Clerk under C1,** if C1 is taken: counterparties share a venue
    for good. (a) Accepted; (b) C1 refused for it. **Recommended: (a):**
    the Clerk already settles at one venue.
17. **Item 68:** a `closes` row that does not decode is dropped silently
    (`agent/default/src/refine/inputs.rs:122`). (a) Quarantine it (moved
    aside, with an alert), the batch going on; (b) fail the batch, which
    every replica fails alike, halting the representative; (c) keep
    dropping it, with an alert. **Recommended: (a).**
18. **Slice 6's six owner's-call quality items** (1, 5, 34, 46, 54, 58):
    (a) folded in 7.22; (b) carried. **Recommended: (a).**
