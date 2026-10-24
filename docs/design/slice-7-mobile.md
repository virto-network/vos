# Slice 7: simplify and scale, then proofs on the phone

Plan, draft 1, for the owner's answers to its open questions (the last
section). It takes the owner's slice-7 decisions S1–S5
(`research/slice-7/owner-decisions.md`) and the first real phone run
(`research/slice-7/phone-fairphone6-s5kit.txt`). Slice 6's decisions 1–18
stand.
- **The architecture** is `proving.md` (draft 6) §3–§8, `identity-and-authority.md`
  §5–§7 and slice 6's pins D–F (`slice-6-on-chain.md`). The research is in
  `research/slice-7/`: `simplify.md` (pin D inventoried, ten candidates
  C1–C10 for the owner), `device-params.md` (the device and credential
  parameters counted under masking (c)) and the phone run.
- **This slice builds three milestones:**
  - **M3.9, simplify and scale:** the anchoring protocol simplified by the
    candidates the owner picks; a scale test across the owner's LAN;
  - **M4, the credential AIR:** the Poseidon2 map, the Poseidon2 precompile
    chip (with slice 6's re-pin batch, one re-pin for both), the credential
    AIR, its verifier at a space's ingress, the device library and an
    Android demo;
  - **M5, the device profile:** the general zkVM on the phone, the auth
    statement in at most 1 s on the Fairphone 6.
- **Out of the slice:** M6, the signature chips (S1); a Wasm or browser
  prover (S4); iOS (S5); the Kreivo pallet (the teammate's) and its chain
  transport (after the slices, decision 12d).
- **Its log:** `slice-7-progress.md`, beside this plan.

Tags as in slice 6: [measured] by a spike or a step; [model] by the
security tool or a fit; [est] arithmetic on measured numbers, not run;
[decided] the owner's; [proposed] open to review.

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
   S3].
5. **One re-pin:** slice 6's re-pin batch and the Poseidon2 chip's segment
   format in one commit; `H_fold` and the wraps' roots unchanged.
6. **Every item slice 6 carried** placed in a step or carried by name.

**No value rides on a proof in this slice:** the external audit comes
first (slice 6's decision 14); slice 7 adds the credential AIR, the
Poseidon2 chip and the device profile to its scope.

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
  61.86 proven bits under masking (c), under its 2-bit margin; at 86
  queries every masked component pads to 2^12 rows, not §8's 2^11.
- **Not built:** a Blake2s-M31 channel in `pcs.rs` (the fork has it);
  masking for the segment chips (no chip mask in `MaskedComponents`, 14
  chips finalize unpaired, tables at 2^6–2^8 rows); any Android, JNI or
  passkey code; an operator path to the representative or a venue; a
  multi-host driver.

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
- **Phone gates** (the s5 kit's approach): a static `aarch64-unknown-linux-musl`
  bench binary with mimalloc and its fixtures embedded, its SHA-256
  recorded; `adb push` to `/data/local/tmp`; the device's model, SoC,
  build, per-CPU maximum frequency and battery recorded; battery at least
  50%, `dumpsys battery` temperature below 35.0 °C at each round's start,
  battery saver off, `svc power stayon usb`, out of its case; 3 rounds of
  5 repetitions with 60 s between rounds; the gate is the median of the
  rounds' medians; each proof verified on the phone and on x86, and, under
  the bench's seeded seam, byte-identical to x86's. The coordinator runs it
  over adb when the owner has the phone attached and agrees; otherwise the
  owner runs the kit. Results land as JSON lines in `research/slice-7/`.
- **Rules:** slice 6's (`slice-6-on-chain.md`, "How every step runs"):
  commit on `vos-core`, push after reviewed milestones, the fork's pushes
  after Fable, no Kreivo code, timeless comments, no `#[ignore]`, no
  Co-Authored-By, kill by PID only, fix pre-existing failures; every
  measured number tagged in `slice-7-progress.md`.

## The pins

Specs the steps implement, [proposed] unless tagged. Pin D′ depends on
the owner's picks; G–L are M4's and M5's.

### Pin D′: the anchoring protocol, simplified

`simplify.md` §4 states pin D under all ten candidates; the owner picks
(open question 1). Whatever is picked:
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
  `enum AnchorOutcome { Taken, NotYet, Never(u32), Stopped(u32) }`, the raw
  venue code carried for the log; one mapping table per client, tested
  against every venue code. Submits:
  `enum SubmitOutcome { Accepted, Refused(u32), Retry }`, a repeat
  `Accepted` at one site.
- **The replicated anchor row** (C3): the representative's close writes
  `anchor(w) = S_w`, kept for `MaxRootAge`; its leader signs and sends
  pending rows in window order with its node key (C2); nothing is handed
  back.

### Pin G: the Poseidon2 map

- **What it is:** a `CommittedMap` declared `#[committed(poseidon2)]`. Its
  rows stay ordinary committed rows under `0x03`, so the agent root, JAM's
  node at `0x03` and every Blake2b proof are unchanged. The builder also
  keeps a **second index** over the map: an indexed Merkle tree of
  Poseidon2-M31, fixed depth `D = 32`.
- **Positions:** each key takes a slot at its first insert, assigned in
  apply (`slots: key → u32`, the next free slot, freed slots reused
  lowest first), stored as a committed row beside the value so every
  replica and JAM agree; the slot is the leaf's index, its bits the path.
- **The hashes** (`vos-pvm-poseidon2`, width 16, Plonky3's constants):
  `leaf = sponge(TAG_LEAF ‖ slot ‖ P(value))`, `P(value)` the value packed
  31 bits to an element; `node = compress(left, right)` (one permutation,
  8 + 8 elements in, 8 out); an empty leaf the zero digest; the domain
  tags M31 constants from `BLAKE2b("vos/p2/<name>")`. The root is a
  `Digest` (8 M31, 31 bytes packed into 32).
- **Roots:** the builder computes the map's Poseidon2 root at each cut
  and, at most once a second, at the latest version; it keeps those of
  the last 120 s and each cut's of the last two windows, and reports a
  cut's to the representative under `RepKey(agent, 1, w)` (kind 1, which
  its rows already carry), so `S_w` commits to it.
  `RootKind`'s anchors and `RootRead`s stay `Space` only: no venue checks a
  Poseidon2 root in this slice, and a later cross-space credential proves
  its root's place under `S_w` by a Blake2b path outside the proof.
- **Paths:** `GET /agents/{id}/maps/{tag}/path?key=…` answers
  `(root, version, slot, siblings[32])` from the latest build. Fetching a
  path tells the space when a holder proves (`identity-and-authority.md`
  §7): recorded in `SECURITY.md`; syncing the map is the later fix.
- **On JAM:** a Poseidon2 map is an ordinary committed map; JAM agents
  compute no second index in this slice.
- **Gate:** a committed write to a Poseidon2 map stays within 2× a plain
  one on the apply path (the slot row); the builder keeps up with 5k
  Poseidon2-map writes a second [est: 32 permutations a write, SIMD ×16
  across rows].

### Pin H: the Poseidon2 precompile chip, and segment format 41

- **The call:** `0x402` (`ECALL_POSEIDON2`), dispatch 102: φ7 points at 64
  bytes (16 M31 words, little-endian u32, each `< p`, else the call traps
  live and the trace has no proof), φ8 at 32 bytes written with the 8-word
  output of `compress`; no other effect. Served natively by the VOS host
  at a price measured in 7.9; on JAM the guest shim falls back to the
  software permutation (about 15,800 instructions) on `WHAT`.
- **The chip** (`chips/poseidon2.rs`): one permutation a row, `p2`'s
  arithmetic (`permutation_columns`, the S-box pair) as a `BuiltInComponent`,
  about 300 main columns at degree ≤ 3; memory-access lookups for the 64
  bytes read and 32 written; a `Poseidon2Call` relation from the CPU's
  `IsP2Ecall` selector. `OPTIONAL`, so a kernel that never calls it pays
  nothing (a shape per kernel).
- **Format 41:** the segment AIR with the chip, 35's parameters (blowup 4,
  40 queries, PoW 24, interaction PoW 8), Poseidon2-M31 channel. 35 is
  retired when 41 is admitted. `SEGMENT_CHIPS` 25 → 26, so the install
  record's `Shape` changes encoding.
- **What re-pins with it** (7.9): every program id and leaf-circuit hash,
  the segment fixtures and reference shapes, every guest blob; `H_FOLD`
  and the wraps' roots asserted unchanged.

### Pin I: the credential statements and their verifier at ingress

- **The AIR:** a recursion-AIR circuit (recair's `Context` and gadgets)
  over the `p2` and `qm31` components, a fixed wiring per statement, so
  its circuit hash is its program id. Two components at least, so the
  claimed sums are blinded (a one-component masked set is not).
- **Format 42, credential proofs** (`device-params.md`): masked (c),
  Blake2s-M31 channel, **blowup 4, 43 queries, PoW 20, interaction PoW 8,
  fold step 1**, affine DEEP batching if the fork's Blake2s-M31 path takes
  it, else by powers; at least 62 proven and 100 conjectured bits on its
  masked shape; `h = 512`, every component at least 2^11 rows. 30, reserved
  at an unmasked count, is retired unregistered.
- **Auth** (`CredentialKind::Auth = 0`), public:
  `(kind, map_root, scope, nullifier, binding)`, each 8 M31; private: the
  secret `s`, the epoch, the slot and its path. Proves
  `leaf(slot, P(member(s, epoch)))` under `map_root`,
  `nullifier = P2(TAG_NF ‖ s ‖ scope)`, `binding` a public input.
- **Pay** (`CredentialKind::Pay = 1`), public:
  `(kind, map_root, account, amount, nullifier, binding)`; private: `s`,
  the row's slot, path, balance and currency. Proves the row
  `(owner = P2(TAG_OWNER ‖ s), balance, currency)` at `account`'s slot
  under `map_root`, `balance ≥ amount` (a 64-bit range check on
  `balance − amount` in `qm31` rows), and
  `nullifier = P2(TAG_SPEND ‖ s ‖ binding)`. The account is public (open
  question 10).
- **The binding:** `binding = P2(BLAKE2b-256("vos/cred/binding/v1" ‖
  agent ‖ instance ‖ method ‖ SCALE(arguments) ‖ nonce ‖ expires_ms))`: a
  proof authorizes exactly one call.
- **The request:** `POST /agents/{id}/calls` with
  `Credentialed { call, kind, proof, public }`, no session (the reserved
  session-less input kind, `identity-and-authority.md` §15 step 0).
- **Ingress checks, in order:** the size (≤ 512 KiB); the format (42, or
  43 for a device proof); the program id the agent's schema pins for the
  method; `map_root` among the map's kept roots (pin G); the binding
  recomputed; `expires_ms` within
  120 s of the node's clock; then the proof, on an executor, rate-limited
  per scope. Each refusal a `403` with its code.
- **Exactly once:** the binding's digest is recorded in the agent's
  replicated state until `expires_ms` and a second one refused at apply,
  so a proof replayed at another node runs nowhere twice.
- **The origin logged:** `Anonymous { scope, nullifier }` for auth (a
  pseudonym in its scope: "once in this scope" is the guard's rule);
  `Holder { agent, map, key: account }` for pay; never the proof
  (`identity-and-authority.md` §5). Guards: `#[msg(credential = Auth(scope))]`,
  `#[msg(credential = Pay(map))]`.
- **Gate:** the native verify of a credential proof at most 10 ms on one
  x86 core.

### Pin J: the device profile, and format 43

- **The shape:** one segment, at most 2^16 steps; the segment chips of
  format 41 without the page-Merkle boundary (BLAKE2B_BOUNDARY,
  MEMORY_PAGE, MEMORY_MERKLE, MEMORY_ROOT_BOUNDARY); the run bound by
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
  4 with 43, 8 with 29; PoW 20), at least 62 proven and 100 conjectured
  bits on its masked shape. 37, reserved at an unmasked count, is retired
  unregistered.
- **The device program id:** the format, the chip mask, the log sizes and
  the preprocessed roots (program memory, data table, permissions), as a
  segment program's; computed at install, never taken as submitted.
- **Budgets on the Fairphone 6** [decided S3 for time; proposed for the
  rest]: the auth statement at most **1.0 s** (median, 8 threads or the
  library's automatic choice), peak resident at most **1 GiB** (target
  768 MiB), the proof at most 1.5 MiB; verify at ingress at most 40 ms on
  one x86 core.

### Pin K: the device secret from a passkey's PRF

- **The PRF input:** `first = SHA-256("vos/prf/v1" ‖ space)`, the
  WebAuthn PRF extension's `eval.first` (the authenticator applies its own
  `"WebAuthn PRF\0"` prefix); the relying party the demo's domain (open
  question 9).
- **The derivation:** `o` the 32-byte PRF output;
  `w = BLAKE2b-512("vos/device/secret/v1" ‖ space ‖ o)`; `s_i = u64_le(w[8i..8i+8]) mod p`
  for `i < 8` (bias below 2^-33 an element). `s` never leaves the library,
  is zeroized on drop, and is derived again at each use from a fresh PRF
  assertion with user verification.
- **What a space stores:** `member(s, epoch) = P2(TAG_MEMBER ‖ s ‖ epoch)`
  as the credential row's value, `owner = P2(TAG_OWNER ‖ s)` in a ledger
  row; a new passkey or a revocation bumps the epoch and re-enrolls. The
  space is in the derivation, so one passkey gives unlinkable secrets in
  two spaces.

### Pin L: the device library

- **Crates:** `vos-device` (the prover API, `std`, aarch64 and x86_64),
  `vos-device-jni` (a thin JNI shim, `extern "system"` functions over byte
  arrays in the workspace codec), built for `aarch64-linux-android` with
  `cargo-ndk` against NDK 27.2, mimalloc, no other C dependency.
- **The API:**

  ```rust
  pub struct DeviceSecret(/* [M31; 8], zeroized on drop */);
  pub fn derive_secret(prf_output: &[u8; 32], space: &SpaceId) -> DeviceSecret;
  pub fn member(secret: &DeviceSecret, epoch: u32) -> Digest;
  pub fn owner(secret: &DeviceSecret) -> Digest;
  pub struct ProverConfig { pub threads: Threads, pub max_memory: u64 }
  pub enum Threads { Auto, Count(usize), Cores(Vec<usize>) }
  pub struct Prover { /* the thread pool, the formats' twiddles */ }
  impl Prover {
      pub fn new(config: ProverConfig) -> Result<Self, DeviceError>;
      pub fn prove_auth(&self, s: &DeviceSecret, witness: &AuthWitness, scope: &Digest,
                        binding: &Binding) -> Result<CredentialProof, DeviceError>;
      pub fn prove_pay(&self, s: &DeviceSecret, witness: &PayWitness, amount: u64,
                       binding: &Binding) -> Result<CredentialProof, DeviceError>;
      pub fn prove_kernel(&self, program: &DeviceProgram, arguments: &[u8])
                          -> Result<DeviceProof, DeviceError>;   // M5
  }
  ```
  `Threads::Auto` weights work by core class (7.17); `DeviceError` names
  what failed and no value. No logging of witnesses; the library has no
  `seeded-masks` (pin C's build check covers it).

## M3.9: simplify and scale

Two tracks from the first day: the simplification (7.1–7.3) and the scale
harness (7.4–7.5) meet in the scale runs (7.6). The device baseline (7.0a)
and the Android probe (7.0b) run beside them.

### 7.0 The docs, the picks and two probes

- **7.0 The docs:** the owner's answers into "Decisions";
  `slice-7-progress.md` opened; `proving.md` §8's floor and §11's rows
  corrected; `core-model.md`'s "Draft 5" heading (slice 6's L8).
- **7.0a The device baseline on today's AIR** (a spike, throwaway code):
  slice 5's floor seam and statements rebased onto `f83f744b` (format 35's
  chips, Blake2s-M31 through the fork's channel); on x86 the as-built and
  floor shapes at log blowup 1 and 2, 4 and 8 threads; the same kit on the
  Fairphone 6 by the phone-gate protocol. **Output:** today's starting
  point and the stale-AIR correction for every projection in M5.
  **Estimate:** 3–5 days.
- **7.0b The passkey PRF on the gate device** (a probe): a throwaway
  Android app creating a passkey with the PRF extension through
  Credential Manager (`androidx.credentials`) under the demo's relying
  party, then an assertion returning `prf.results.first`, twice, equal.
  **Gate:** the PRF output returned to a native app on Android 16 with
  Google Password Manager. **Fallback:** a FIDO2 security key's
  `hmac-secret` over USB or NFC; else the demo derives from a stored key
  and the PRF waits for the platform. **Needs:** the owner's domain with
  `assetlinks.json` (open question 9). **Estimate:** 2–3 days.

### 7.1 The venue side simplified (S)

- **What:** the owner's picks among C6 (the venue core), C1 (no
  migration), C4 (equivocation terminal), C8 (registration from the next
  window) and C7 (rooted statements only) at `vos-anchor`, `vos-statement`,
  `ModelVenue`, the JAM statements service, the Kreivo mock and client,
  and jam-dev's client; `spaces-pallet.md` v2 and the conformance vectors
  regenerated once, with a change note for the teammate.
- **Folded:** slice 6's F2 (`behind()`'s read on the batch thread goes with
  the client's pre-checks), F3 (with resume), L4 (strict ed25519, and a
  small-order key refused at registration and when added, with a vector),
  L3's migration half, item 74 (`forward_venue!`), item 29 (the control
  tests), and the info items: duplicate founding keys `BadGenesis`, the
  service's storage read trapping on an undecodable row.
- **Tests:** the core's own suite (every rule, every refusal) run against
  each venue's state; G1–G19 renumbered as the picks leave them; the
  fixtures judged alike at every venue.
- **Gate:** every venue calls the core; no anchor-rule logic outside it
  (a grep check in `just check`); the vectors regenerate byte for byte.
- **Dep:** 7.0, open questions 1–2. **Estimate:** 2–3 weeks.

### 7.2 The node's anchoring simplified (S)

- **What:** the owner's picks among C2 (the node key alone), C3 (the
  replicated anchor row, no hand-back) and C5 (the outcome enums) in
  `node/host/src/leader/anchor.rs`, `anchor_keys.rs`, `vos-venue`'s queue
  and trait, the replica rule, the prover worker's submit mapping, and the
  CLI (`vos node anchor-key` removed if C2).
- **Folded:** slice 6's L5 (jam-dev's `push` wedge) and the untested
  once-a-window recheck, both gone with the hand-back.
- **Tests:** the cluster suite rewritten to the new rules: anchors in
  order across a leader change, a delisted node's replica refused and
  replaced, an equivocation stopping the space (C4), an aged window
  settled unsent; every venue code through each client's table.
- **Gate:** the checker loop with cuts and the representative; the
  leader's anchoring state and wait paths counted against `simplify.md`
  §4.
- **Dep:** 7.1. **Estimate:** 1.5–2.5 weeks.

### 7.3 Reads, reports and the worker's edges (S)

- **What:** C9 (no re-cuts) and C10 (markers, cuts and reports only for
  windows a read waits on), if picked; the prover worker's carried edges:
  slice 6's M3 (a replica that installs a snapshot and leads recovers the
  unproved set from replicated state: an "attested, unproven" marker per
  cut it scans), M4 (`prune` ages out every unfinished job; an unfinished
  job's kernel pinned under `NODE_AGENT`), L6 (a)–(f), item 68's owner call
  (open question 13).
- **Tests:** a read served at its own window; `NotClosed` when the close
  misses it; an idle agent appends no marker; a leader change and a
  snapshot install with statements queued, each proved once.
- **Gate:** the checker loop; the cut's bench (a write with a cut pending,
  a cut's build with 100 proofs) within 10% of slice 6's.
- **Dep:** 7.2. **Estimate:** 1.5–2.5 weeks.

### 7.4 The scale harness

- **`tools/scale`** (`vos-scale`, a dev crate no shipped crate depends on,
  a `check-no-*` row), driven by an `inventory.toml` of hosts (ssh address,
  role, a placement weight, the data disk, the cores to use):
  - `check`: ssh reach, the kernel (the JIT needs Linux ≥ 6.7 on x86_64,
    else the host is marked interpreter-only and weighted down), clock
    offsets (refused above 100 ms), free memory and disk, the CPU;
  - `deploy`: static musl builds of `vos` (x86_64, aarch64) from a pinned
    `just release`, the guest ELFs, the space file and genesis, by `rsync`;
  - `up`, `down`: nodes under `systemd-run --user` with a memory cap, TLS
    ingress with pinned node keys; `agents`: creation and installs by the
    weights; `drive`: the drivers (7.5);
  - `collect`: `/stats`, `/agents/*/status`, per-thread `/proc`, disk and
    network counters every 10 s as JSON lines; `report`: one directory a
    run, with its inventory, versions, host facts and summary.
- **Node changes it needs:** a `--config node.toml` exposing `Config`
  (executors, queue, linger, `max_inputs`, `ingress_connections`,
  elections, heartbeat); an admin route and `vos space representative` to
  create the representative; a development-only `scale-venue` feature
  serving `ModelVenue` in the node (`just check-no-scale-venue` keeps it
  out of release builds, as `check-no-jam-dev` does); slice 6's L3
  (`default-members` without the dev crates, so the release build is the
  one gated).
- **Gate:** a three-host run of 100 agents and 10,000 users from one
  command, collected and reported, on two of the owner's machines at
  least.
- **Dep:** 7.0. **Estimate:** 2–3 weeks.

### 7.5 The load model and its drivers

- **Users:** `U` simulated users, each an ed25519 key derived from a seed
  and an index (`key_i = derive(seed, i)`, nothing stored), each with an
  account row in one of `K` ledger agents (by hash of `i`), a session
  opened at its first call and kept while it acts.
- **Agents:** `K` ledger shards (a test actor with a `CommittedMap` of
  accounts and transfers), plus `I` idle agents (installed, never called)
  to measure the per-agent cost and the window pipeline.
- **Operations,** open loop (Poisson at a target rate `R`, latency timed
  from the scheduled send), users drawn Zipf(1.0): 70% transfers within a
  shard (signed calls), 20% queries on followers, 5% transfers across
  shards (pair messages), 4% workflows, 1% reads at a cut
  (`attest_at_cut`, the window pipeline without proving).
- **Drivers:** each signs ahead, multiplexes users over at most 512 kept
  HTTPS connections a node, and reports per-operation histograms (p50,
  p99, p99.9), the achieved rate and errors by kind every 10 s.
- **Gate:** one driver sustains 20k calls a second on one core-pair of a
  driver host (so drivers never bound a run); the operation mix within 1%
  of its target.
- **Dep:** 7.4. **Estimate:** 1–1.5 weeks.

### 7.6 The scale runs

- **The runs,** in order, each 30 minutes steady after a ramp:
  1. **the per-replica cost:** 1k, 5k and 10k idle agents: RSS and the
     runtime thread's `late` by group count (the group inbox allocated
     whole at creation is the suspect), fixed first if it binds;
  2. **the baseline:** `K = 64`, `U = 10^5`, the rate stepped to the knee;
  3. **users:** `U = 10^6`, `K = 64`, at 80% of the knee;
  4. **agents:** `I` stepped 10^4 → 10^5, at the baseline's load;
  5. **faults:** run 3 with a node host killed at minute 10 and restarted
     at minute 15;
  6. **soak:** run 3 for 2 hours.
- **Folded:** slice 6's item 53 (one snapshot per idle wake), item 58's
  performance half (the worker's table reads), and the levers the runs
  show binding (the runtime thread, the inbox, the signature key cache),
  each a commit with its before and after; the ops notes (slice 6's L8,
  the clock-jump outage, catch-up by log) in `docs/operations.md`.
- **Gate:** "The scale test" targets T1–T6 met, or each miss recorded
  with its measured cause and its lever (a step, or carried by name).
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
above all), RSS, fsync latency, disk and network bytes; per agent leader
changes; the window pipeline (boundary to cut built, to report, to close,
to anchor at the scale venue); clock offsets between hosts; cost per user
(bytes on disk, CPU per call) and per idle agent (RSS, CPU).

**Targets** [proposed; open question 8], checked after run 2 (the
baseline) and adjusted only by the owner:

| | target |
|---|---|
| T1 users | 10^6 users in one space, 10^5 of them active within the hour, served at 80% of the knee with no session refused |
| T2 throughput | at least 40,000 committed calls a second across the space for 30 minutes on 4 node hosts or more, client p99 at most 50 ms, no leader lost |
| T3 agents | 10^4 agents a space: idle cost at most 5% of a core and 64 KiB of RSS per 1,000 replicas (10^5 measured, a stretch) |
| T4 windows | at L = 10 min with 1% of agents reading: every read served by `B_w + D + 10 s`, none `NotClosed` without a fault; the representative's work a window proportional to readers (C10) |
| T5 faults | a node host killed under load: every agent led again within 5 s, throughput back to 80% within 30 s, the host rejoined within 60 s of its restart |
| T6 soak | 2 hours at T1's load: RSS flat within 10% after the first 30 minutes, p99 within 20% of the first half hour |

## M4: the credential AIR

### 7.7 The design round

- **What:** pins G, I, K and L checked against the code and the owner's
  answers (open questions 3, 9, 10, 12): the map's slots and their churn,
  the statements' exact public words, the binding, the ingress order and
  the origins, the library's API; written into `proving.md` §8 and
  `identity-and-authority.md` §5–§7.
- **Dep:** M3.9 (or beside it: open question 5). **Estimate:** 1 week.

### 7.8 The Poseidon2 map (S)

- **Files:** `agent/sdk-macros` (`#[committed(poseidon2)]`), `agent/wire`
  (the slot rows, `Rows` gaining the kind), `node/host/src/roots` (the
  builder's second index and its kept roots), the representative's kind-1
  report, the path route, `agent/testkit`.
- **Tests:** the index equals a reference built from scratch over random
  inserts and deletes; slots reused lowest first and equal on every
  replica (checker); a cut's Poseidon2 root reported once; a path verified
  by the reference.
- **Gate:** pin G's.
- **Dep:** 7.7. **Estimate:** 2–3 weeks.

### 7.9 The Poseidon2 chip, format 41 and the re-pin batch (S)

- **What:** pin H: the call in the runtime, `derive`, the tracer, the
  hosts and the guest shim; the CPU's selector; the chip; format 41; its
  forgery gates (a wrong output, an unread input byte, a call without its
  row); 35 retired.
- **The re-pin batch, one commit** (slice 6's carried list): items 4's
  guest half, 17–25 (the `#[repr(u8)]` enums first), 64–66, 67, 68, 69,
  16's unmasked half, 26 (`SpaceGenesis::version`), 27 (the `ANCHORS` mode
  out of `final-verify.elf`), 28 (the strictness fix, `read_nat` shared),
  3's `TryFrom<u32>` for `AnchorCode`, 33's `FetchKind`; item 13 (the
  witness digest from `statement_header_words`); item 18's rest
  (`array::from_fn` in `agent/tree`'s hash, `leaf_terms`' named offsets);
  slice 6's L2 (`blobs.lock`, checked by `check-no-std`); the fixtures and
  vectors 7.1 regenerated. 7.1–7.3 change the agent image and the
  service's blob before this step, but no hash pins a blob until
  `blobs.lock`, so this is the slice's one re-pin.
- **Gate:** the stale-fixture test re-pinned once; `H_FOLD` and the wraps'
  roots byte for byte; `repro-aarch64` equal; the native price of `0x402`
  measured; a window kernel reading a Poseidon2 map through the chip
  against the same read in BLAKE2b (steps, cells, proving).
- **Dep:** 7.1, 7.8. **Estimate:** 2.5–3.5 weeks.

### 7.10 The credential AIR (S)

- **What:** pin I's circuits (auth, pay) on recair's `Context`; a
  `MaskedComponents` set of `p2` and `qm31` (after the test's `P2Only`);
  the Blake2s-M31 channel wired in `pcs.rs` (the fork's
  `Blake2sM31MerkleChannel`); format 42 with its count on its own masked
  shape; the prover and `verify_masked` over it.
- **Gates:** soundness (a wrong path, a balance below the amount, a
  nullifier of another secret, a changed binding, each refused) and the
  forgery gates (a prover that skips the range check or the path's bits);
  leakage 2, 3 and 5 on the credential AIR at N = 500 in `test-proof`
  (2,000 at the slice's end); on x86 auth and pay each at most 60 ms on 4
  threads [est from the masked floor: 2^11 rows × about 400 columns].
- **Dep:** 7.7, 7.8 (the map's hashes); beside 7.9. **Estimate:** 3–4
  weeks.

### 7.11 The verifier at ingress (S)

- **What:** pin I's request, checks and origins in `node/host/src/ingress.rs`
  and `calls.rs`; the origin ABI's `Anonymous` and `Holder` kinds, and the
  session-less input kind (`identity-and-authority.md` §15 step 0); the
  guards; the replicated binding set; a challenge route for clients that
  want a server nonce.
- **Tests:** each check's refusal in order; a proof replayed at another
  node, refused at apply; an expired binding; a root no longer kept; a
  proof of one call sent with another; the origin logged, the proof not.
- **Gate:** pin I's verify time; 1,000 credentialed calls a second on one
  node at p99 within 50 ms of a signed call's.
- **Dep:** 7.10. **Estimate:** 1.5–2.5 weeks.

### 7.12 The device library and the credential phone gate

- **What:** pins K and L for M4 (`prove_auth`, `prove_pay`, the
  derivation), the Android build, and the phone bench (`tools/phone`,
  the kit's protocol).
- **Phone gate PG1** (Fairphone 6): auth and pay masked, each at most
  **250 ms** (target 150 ms) and 256 MiB; verified on the phone and on
  x86; seeded bytes equal to x86's.
- **Dep:** 7.10. **Estimate:** 2–3 weeks.

### 7.13 The Android demo

- **Scope, minimal:** one Kotlin activity (Views, no Compose), minimum SDK
  34; the library through JNI (`arm64-v8a`); the Gradle wrapper; the phone
  reaches the development machine's space by `adb reverse tcp:7700
  tcp:7700`, so the ingress's plain HTTP on loopback serves it.
- **Three buttons:** *Enroll* (create a passkey with PRF, derive `s`, send
  `member(s, 0)` and `owner(s)` to the space's credential and ledger
  actors, which a test actor accepts from an operator-granted invitation);
  *Sign in* (a PRF assertion, the path fetched, auth proved, the call
  sent, its answer and the proving time shown); *Pay* (an amount and a
  payee, pay proved, the transfer sent, the balance shown).
- **Not in scope:** recovery, several devices, iOS, the Play Store, UI
  beyond the three buttons, storing anything but the credential id.
- **Gate PG3:** the three flows end to end on the Fairphone 6 against a
  local space, recorded (a screen capture and the node's log).
- **Dep:** 7.0b, 7.11, 7.12. **Estimate:** 1.5–2.5 weeks.

### M4 acceptance

- **Gates:** `ci-full`, the checker loop, PG1, PG3.
- **Recorded:** the credential AIR's rows, proof bytes, proving on x86 and
  the phone, verify at ingress; the chip's price; the re-pinned constants.
- **Reviews:** Fable on 7.8–7.11 (the map, the chip and the re-pin, the
  AIR and its masking, the ingress); then a push.

## M5: the device profile

### 7.14 Masking the segment chips (S)

- **What:** `MaskedComponents` over the segment AIR's `BuiltInComponent`s:
  the active-chip mask in `draw_relations`, a finalize hook for the 14
  chips that finalize unpaired, a per-component `h` from its offsets, the
  fixed tables' multiplicity columns padded to the floor; the degree audit
  (5,177 constraints at ≤ 3 under (c), slice 6's R5) on the built set.
- **Gates:** soundness 1–10 and leakage 1–7 (slice 6's 6.6) on a masked
  segment of a small kernel; R1 on every column class.
- **Dep:** 7.9 (format 41's chips); 7.0a. **Estimate:** 2.5–4 weeks.

### 7.15 The device shape (S)

- **What:** pin J's boundary-free shape: the data table, the first-touch
  rules, the permission table, the io-hash output; the device program id;
  derivation at install.
- **Forgery gates:** a first touch of a data byte other than the table's,
  a nonzero first touch of stack or heap, a touch outside the regions, a
  write to a read-only page, a second segment: each refused.
- **Dep:** 7.14. **Estimate:** 3–5 weeks.

### 7.16 The device parameters, measured

- **What:** the auth statement (open question 3) under the device shape,
  masked, at `device-params.md`'s candidates (blowup 2, 4, 8; PoW 20; the
  Blake2s-M31 channel, and the Blake2b-256 one for comparison) on x86,
  then PG2's protocol on the phone; format 43 pinned at the fastest
  candidate within pin J's memory and size budgets.
- **Dep:** 7.15. **Estimate:** 1–1.5 weeks.

### 7.17 The levers, in their fallback order

Each measured on the phone before the next; the step stops when PG2 passes
twice in a row, a day apart.
1. **The statement over a Poseidon2 map** through the chip (open question
   3): BLAKE2b and the AND table leave the shape.
2. **Threads weighted by core class** (`Threads::Auto`: the A720s and
   A520s given work by their measured rate, not rayon's even split), and
   the preprocessed commitment computed once at install (2–9% [measured]).
3. **A lean kernel:** no argument copy, the path walked in place (about
   −50% of the CPU's and memory's rows [model, slice 5]).
4. **Parameters again:** per-component `h`, blowup and queries re-chosen.
5. **Word-level memory:** 4–8× fewer MEMORY rows [model] (4–6 weeks).
6. **The CPU split by opcode family:** −50–70% of its cells [model] (6–10
   weeks).
7. **Narrow BLAKE2b,** only if the statement keeps BLAKE2b (3–5 weeks).

Levers 5–7 land in the device chips alone (open question 4); past lever 4
without PG2 the owner chooses (open question 11).
- **Projection** [est; 7.0a corrects it]: the floor's 2.2 s (8 threads,
  34.1M cells, blowup 4, unmasked, the stale AIR) × lever 1's 0.30–0.40
  (BLAKE2B's 12.2M cells and the AND table gone, the mask's 2^12 floor
  added) × masking's 1.7 × blowup 2's 0.8 ≈ **0.9–1.2 s**; levers 2 and 3
  about −10% and −15–25%, so about 0.65–1.0 s; 4–6 are the margin.
- **Estimate:** 2 weeks for levers 1–4; up to 8 more if 5 or 6 is needed.

### 7.18 The device library's kernels, and PG2

- **What:** `prove_kernel` (pin L), the demo's *Sign in* given a choice
  of the general zkVM's auth kernel beside the credential AIR.
- **Phone gate PG2** (Fairphone 6): the auth statement under the device
  profile, masked, **at most 1.0 s** (the median of three rounds' medians),
  peak resident at most 1 GiB, proof at most 1.5 MiB; verified on the
  phone and at a space's ingress.
- **Dep:** 7.16, 7.17. **Estimate:** 1–2 weeks.

### M5 acceptance

- **Gates:** `ci-full`, the checker loop, PG2.
- **Recorded:** the device shape's rows by chip, each lever's effect on
  the phone, the proof's bytes, verify at ingress.
- **Reviews:** Fable on 7.14–7.15 and the parameters; then a push.

## The slice's end

### 7.19 The carrier audit, extended

- **What:** slice 6's R7 audit over the new carriers (the credentialed
  call and its log entry, the path route, the library's errors, the JNI
  shim, the demo's log, the phone bench); slice 6's M6 (more needles, a
  run over small values).
- **Dep:** 7.11, 7.18. **Estimate:** 1 week.

### 7.20 Acceptance, the quality review and the carried rest

- **Gates:** `slice-gate`, the checker loop, `just e2e-chain`, the kit's
  sync check, the scale test's run 3 again on the final build, PG1, PG2
  and PG3 on the final build.
- **The carried rest** (behaviour-preserving commits, proof bytes
  unchanged): slice 6's M5(d) (the release binary scanned), M5 (fault text
  out of logs and answers), L1 (a seeded-hash pin of the small masked
  circuit in `check`), L8's `ABOUT` string, L9's rest (`tamper` under
  `seeded-masks`, `ProveError`'s values, a `stwo=warn` default,
  `check-no-faults` in `check`), items 14, 30, 31, 35, 50, 70 and 77; the
  six owner's-call items if the owner agrees (open question 14).
- **Reviews:** the Opus code-quality review, then the slice-end Fable
  review, each folded. **Docs:** `proving.md` draft 7, `core-model.md`,
  `identity-and-authority.md`, "Slice 7 accepted".
- **Estimate:** 3–4 weeks.

## Where the carried items land

| carried from slice 6 | where |
|---|---|
| the slice-7 re-pin batch (quality items 3, 4, 13, 16–28, 33, 64–69), item 18's rest, L2's `blobs.lock` | 7.9 |
| F2, F3, L4, item 74, item 29, the info items (duplicate founding keys, the service's lenient read) | 7.1 |
| `migrate_digest`'s nonce; L3's one-way migration | 7.1 (gone with C1, or carried if C1 is not picked) |
| L5 (jam-dev's `push`), the untested once-a-window recheck | 7.2 (gone with C3) |
| L4 of M3b/M3c (no production prover for rootless statements) | 7.1 (by design with C7; else carried) |
| M3, M4, L6 (a)–(f): the worker's edges; item 68's owner call | 7.3 |
| the representative's load lever (6.19's ops note) | 7.3 (C10) |
| items 53, 58's performance half; L8 and the clock and catch-up ops notes | 7.6 |
| L3 (`default-members`, the release build gated) | 7.4 |
| M6, the audit's needles | 7.19 |
| M5(d), M5, L1, L8's rest, L9's rest, items 14, 30, 31, 35, 50, 70, 77 | 7.20 |
| the owner's-call items 1, 5, 34, 46, 54, 58 | 7.20 if the owner agrees, else carried |
| 5.6's phone run | done (2026-10-25); 7.0a repeats it on today's AIR |
| one founding key registers the space anywhere (pin D's known limit) | carried: its lever adds a rule |
| the representative's clock guard (a quorum of follower clocks) | carried unless the scale runs show the skew binding |
| M6(d)'s FRAME-agnostic runner; M6(e)'s code with the port; M3b's deferred Kreivo gates 1–5 | carried: the teammate's pallet and the port, after the slices |
| the prover-time levers (ALU padding, WITNESS_INPUT in the entry class, a leaf over small segments) | carried: node proving is not this slice's |
| the Blake2b hook (decision 4); `getrandom`'s failure (inherent, documented) | carried |
| C-DJUMP, the ledgers' 2^27 gap, the BLAKE2b pointer near 2^32, refine slices' page permissions | the audit's scope |
| the external audit | after slice 6, before value; its scope gains the credential AIR, the Poseidon2 chip, the device shape and their masking |
| the heavy cleanup before master | carried |

## Risks, and the gate that retires each

| risk | gate | when |
|---|---|---|
| the device profile misses 1 s on the Fairphone 6, or the numbers behind the projection (a 503-commit-stale AIR) are wrong | 7.0a's baseline on today's AIR first; 7.17's levers in order, each measured on the phone; the owner's call past lever 4 | 7.0a, 7.17 |
| masking the segment chips costs more than (c)'s 1.7 (the 2^12 floor, padded tables, 14 unpaired chips), or its proofs are too big to send | 7.14's gates; per-component `h`; blowup 4 halves the floor and the bytes; pin J's 1.5 MiB | 7.14, 7.16 |
| a device format under its margin (37 counts 61.86 under (c)) | formats 42 and 43 counted on their masked shapes, pinned by tests | 7.10, 7.16 |
| Credential Manager returns no PRF to a native app on Android 16 | 7.0b's probe; a security key's `hmac-secret`; a stored key as the last fallback | 7.0b |
| a single-component masked set leaks its claimed sum | two components at least (pin I), a test that a one-component set is refused | 7.10 |
| the Poseidon2 index slows apply or the builder | pin G's gate | 7.8 |
| the re-pin breaks the kit, the vectors or the teammate's vendored tree | one re-pin (7.9), `blobs.lock`, the vectors regenerated once in 7.1 | 7.1, 7.9 |
| simplifying pin D changes a design the teammate is building | open question 2 before 7.1; one regeneration of `spaces-pallet.md` and the vectors | 7.0 |
| per-replica memory or the single runtime thread caps agents per node | 7.6's run 1 first; the lever a commit, or carried with its number | 7.6 |
| LAN clock skew fails reads or moves windows | `vos-scale check` refuses offsets above 100 ms; C9's fail rate measured | 7.4, 7.6 |
| an uneven host (an older kernel, no JIT) leads and slows its agents | the inventory's weights; interpreter hosts marked | 7.4 |
| credentialed calls make ingress a verification DoS target | the size cap first, the cheap checks before the proof, a rate per scope, pin I's verify budget | 7.11 |
| a path fetch tells the space when a holder proves | recorded in `SECURITY.md`; syncing the map is the later fix | 7.8 |
| thermal throttling skews the phone numbers | the runbook's temperature and battery checks, rounds 60 s apart | every PG |

## Estimates

| | weeks |
|---|---|
| 7.0, the docs and the probes | 1–1.5 |
| M3.9 simplification (7.1–7.3) | 5–8 |
| M3.9 scale (7.4–7.6) | 5–8.5 |
| M3.9 acceptance | 0.5 |
| M4 (7.7–7.13 and acceptance) | 14–20 |
| M5 (7.14–7.18 and acceptance) | 10–15, up to 8 more for levers 5–6 |
| the slice's end (7.19–7.20) | 4–5 |
| **slice 7, engineer-weeks** | **about 40–59, up to 67** |

- **The critical path:** 7.1 → 7.2 → 7.3 → 7.6 → 7.7 → 7.8 → 7.9 → 7.14 →
  7.15 → 7.16 → 7.17 → 7.18 → 7.19 → 7.20, about **26–40 weeks** of
  calendar with three tracks (the scale harness beside the
  simplification; 7.10–7.13 beside 7.14–7.15), up to 48 if levers 5–6 are
  needed.
- **With M5's groundwork beside M3.9** (open question 5: 7.0a at once,
  7.14 on a branch rebased onto 7.9's chips) the path shortens by 4–6
  weeks.
- **Against `proving.md` §11's 12–20 weeks for M4 and M5:** that row left
  out M3.9, the re-pin, the ingress verifier, the demo and 7.14.

## Decisions

**Taken by the owner:** S1–S5 (`research/slice-7/owner-decisions.md`).

**Settled by the evidence, the owner's to override:** device formats counted on their masked shapes (30 and 37 retired
unregistered, 42 and 43 new); the Poseidon2 map as a second index over
ordinary committed rows, `RootKind` untouched (pin G); the credential AIR
as a recair circuit over `p2` and `qm31` (pin I); the Poseidon2 chip in
the node's segment AIR now, so its re-pin is the re-pin batch's (pin H).

## Open questions

Ranked by when they block. Each has a recommendation.

1. **Which simplification candidates** (`simplify.md` C1–C10)? Blocks 7.1.
   - (a) All ten as recommended.
   - (b) The node only (C2, C3, C5, C9, C10): the venues' protocol and the
     teammate's design unchanged.
   - (c) All but C7 (rootless statements and `venue_bound` kept).
   - (d) A set the owner names.
   - **Recommended: (a).** The venue side holds most of the duplicated
     rules (C6) and the rare paths (C1, C4); the node's simplifications
     shrink further once the venue's are taken.
2. **The Kreivo teammate's design**, if the picks change it. Blocks 7.1.
   - (a) `spaces-pallet.md` v2 and the vectors regenerated in 7.1, the
     teammate told with a change note now.
   - (b) The handed design frozen; VOS stops using the calls it drops, the
     pallet keeps them.
   - (c) Ask the teammate first and decide by how far the pallet is.
   - **Recommended: (c), defaulting to (a).**
3. **The auth statement M5's gate measures.** Blocks 7.7 and 7.16.
   - (a) Slice 5's statement as it is: a BLAKE2b vos-tree path at 10^6
     rows and a nullifier.
   - (b) The same statement over a Poseidon2 map through the chip (pin G
     and H).
   - (c) Both must pass 1 s.
   - **Recommended: (b),** with (a) measured and recorded: (b) is the
     statement a space uses once M4 lands, and it drops BLAKE2b from the
     gate, so narrow BLAKE2b leaves the critical path.
4. **Where the M5 levers land.** Blocks 7.17.
   - (a) In the device chips alone; the node's format 41 takes them at a
     later re-pin.
   - (b) In both, with a second re-pin at the slice's end.
   - (c) In both, before 7.9's re-pin (M4 waits).
   - **Recommended: (a):** one re-pin this slice, and the node's proving is
     not the bottleneck.
5. **M5's groundwork beside M3.9.** Blocks the schedule.
   - (a) 7.0a at once and 7.14 on a second track from 7.4's start.
   - (b) Strictly in order: M3.9, then M4, then M5.
   - **Recommended: (a):** the 1 s gate is the slice's largest risk, and
     its first numbers should come first.
6. **The phone's memory budget.** Blocks 7.12 and 7.16.
   - (a) At most 1 GiB peak resident, a target of 768 MiB.
   - (b) At most 768 MiB.
   - (c) At most 512 MiB.
   - **Recommended: (a).**
7. **The thread policy PG2 measures.** Blocks 7.17.
   - (a) The library's automatic choice (all cores, weighted by class).
   - (b) The four big cores alone (cooler, kinder to the battery).
   - (c) All eight, evenly.
   - **Recommended: (a),** with (b) recorded.
8. **The scale test's targets.** Blocks 7.4.
   - (a) T1–T6 as proposed.
   - (b) Users only: T1, T2, T5, T6, no agent count gated.
   - (c) Higher: 10^5 agents gated, 60,000 calls a second.
   - **Recommended: (a),** adjusted after the baseline run.
9. **The demo's relying party.** Blocks 7.0b.
   - (a) A subdomain the owner controls, serving `assetlinks.json` for the
     demo's package and its signing key.
   - (b) A FIDO2 security key's `hmac-secret` instead of a platform passkey.
   - (c) A stored key standing in for the PRF in the demo.
   - **Recommended: (a).**
10. **The payer in a payment proof.** Blocks 7.7.
    - (a) Public: the proof is a post-quantum authorization of a named
      account, its balance check a convenience for the payee.
    - (b) Hidden: needs a shielded pool, postponed with full privacy.
    - **Recommended: (a).**
11. **If PG2 misses after lever 4.** Blocks 7.17's exit.
    - (a) Build lever 5 (word-level memory), then 6.
    - (b) Build lever 6 (the CPU split) first.
    - (c) Accept the measured time as the slice's gate and carry the levers.
    - **Recommended: (a):** cheaper and lower risk than (b).
12. **The credential format's parameters.** Blocks 7.10.
    - (a) Blowup 4, 43 queries.
    - (b) Blowup 8, 29 queries.
    - (c) Format 30's blowup 2 and 86–87 queries.
    - **Recommended: (a):** the same proving cost as (c) at half its bytes;
      (b) shrinks bytes again at a higher FRI cost.
13. **Item 68:** a representative's `closes` row that does not decode is
    dropped silently today (`agent/default/src/refine/inputs.rs:122`).
    - (a) Fail the batch.
    - (b) Keep dropping it, with an alert.
    - **Recommended: (a):** it is deterministic across replicas, and a
      corrupt row should stop, not vanish.
14. **Slice 6's six owner's-call quality items** (1, 5, 34, 46, 54, 58).
    - (a) Folded in 7.20.
    - (b) Carried.
    - **Recommended: (a).**
