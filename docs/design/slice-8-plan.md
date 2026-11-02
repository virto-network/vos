# Slice 8: the light node and the personal agent — plan

**Accepted for implementation, 2026-11-02 (owner sign-off).** The design
is `light-node.md`; this file orders it into milestones, steps, gates and
estimates, and places what slice 7 carried.

- **Status:** the steps take the owner's decisions E1–E23
  (`light-node.md` §1.1) and the answers of its §9.1; no question is
  open.
- **Precondition:** slice 7's cleanup before master: the code and the
  documents (merged at `543c05e07`), the single re-pin that resets the
  version counters, and s4's VOS pin moved off the retired device format
  (`open.md`, "Repository"), before the first phone session.
- **How every step runs:** commit on `vos-core`, timeless comments, no
  `#[ignore]`, no Co-Authored-By, fix pre-existing failures; one Opus
  review a step; a Fable review at each milestone's end and at the slice
  end, with an Opus code-quality review at the slice end folded as a
  behaviour-preserving step; `just check` a step, `ci-full` with fuzz at 1
  minute a target and leakage at medium N at milestones, 5-minute fuzz and
  full-N leakage at the slice end.
- **One heavy run at a time:** proving gates (leakage, `ci-full`, phone
  sessions) and the scale run (8.15) are queued one after another, never
  together.
- **Estimates** are one implementer's weeks, before review; the critical
  path adds reviews at the end.
- **Can start now:** M0, M1 and M2 do not depend on the personal
  agent's protocol.

**Streams:**

| stream | steps |
|---|---|
| A, proving | 8.2, 8.4, 8.5, 8.8, 8.10, then 8.21 |
| B, second proving | 8.3, 8.7, 8.9, then 8.23c |
| C, the light node (the critical path) | 8.6, 8.18a, 8.19, 8.20, 8.23a |
| D, the node side | 8.11–8.16, then 8.23b |
| E, transport | 8.1, 8.17, 8.18b, 8.25, 8.26, 8.27 |
| F, Android and s4 | 8.22, 8.24b, 8.24 (and 8.3's keystore half) |

## Phone gates, restated for one proving path

PG1 (the credential AIR's 250 ms) retires with format 44. Every gate is on
the Fairphone 6 [decided, `proving.md` §8], automatic threads, three rounds
of five, the gate the median of the rounds' medians, the 95th percentile
beside it, each proof verified on the phone and accepted at a space's
ingress. Every gate has a limit it can miss.

| gate | what | limit | when |
|---|---|---|---|
| **PG1′ owner** | the stock `owner` kernel | ≤ 0.5 s, ≤ 512 MiB | M1 (format 46), M2 (47) |
| **PG2′ sign-in** | the stock `auth` kernel | ≤ 1.0 s at format 46; at format 47 **the gate 0.65 s, the target 0.55 s** (a miss holds M2, the 4-way CPU split the next lever); ≤ 1 GiB; the proof ≤ 1.5 MiB | M1, M2, slice end |
| **PG3′ flows** | enroll, sign-in and pay (P1); claim at a home-only test space with a phrase kit and with a security-key kit; pair a second device (enrolled in every other space at once, its open claim in the background); sync both ways; retire a phone; a removal let through, one contested and resolved by the kit, and the kit alone removing a phone that holds only a sync key; a restore cancelled by liveness, then one completed on a fresh install; a regroup; move home (two homes); the yearly re-proof with its leaf renewal; every secret behind its prompt; on test homes with delays and the lease in minutes and a low claim difficulty; recorded | each completes; over Tor at the median: a sign-in ≤ 4 s, a P1 payment ≤ 5 s, pairing ≤ 60 s from the scan to the second device's first read, arti and its SSH connections warm | M1 (P1, clearnet), M4 (the personal space, clearnet), M5 (over Tor), slice end |
| **PG5 footprint** | the light node with arti, `vos-mls` and mls-rs | `.so` growth from `vos-mls` and mls-rs ≤ 2 MB (a miss: trim mls-rs's features, then the owner decides); from arti ≤ 10 MB, provisional until 8.1; idle ≤ 96 MiB; warm bootstrap ≤ 3 s p50; a day of background jobs ≤ 2% of the battery; ≤ 30 rendezvous an hour in the foreground after 8.27 | M0 (first numbers), slice end |
| **PG6 sync** | the background job; a 1 MiB catch-up; a commit | on a locked phone after first unlock: the job ≤ 30 s and ≤ 1 MB down with nothing new, p50; the 1 MiB catch-up over Tor ≤ 20 s p50; a candidate processed on its copy ≤ 200 ms. **Recorded, as inputs to the windows:** the job in the "rare" bucket, after 3 days offline, after a force-stop, and the latency from a pending operation to its local notification | M4 (clearnet), M5 and slice end (Tor) |

PG4 (the spend) is slice 9's [E13].

**The second device** for pairing is the owner's to name (another phone, or
an emulator for the second side); the restore needs a fresh install, and
the security-key kit a FIDO2 key with `hmac-secret` (the owner's YubiKey).

**Phone sessions** (each asked a week ahead): S8-P1 at M0 (arti, mls-rs,
the keystore's keys); S8-P2 at M1's end; S8-P3 at M2's exit and S8-P4 a day
later; S8-P5 at M4's end (two devices, the security key); S8-P6 at M5's end
(over Tor); S8-P7 at the slice end.

## M0 — Measure first (2–3 weeks)

### 8.1 arti on the phone and at a gateway (spike) — E
- arti-client (`default-features = false`; `tokio`, `rustls`,
  `compression`, `onion-service-client`, `bridge-client`) in the
  facility's build; a throwaway gateway hosting an onion service in
  process, with SSH on it.
- **Measure:** the `.so`'s growth, idle memory, cold and warm bootstrap,
  a bootstrap through a plain bridge, onion connection (p50, p95), an SSH
  handshake over it, a 1 MB upload, a `Time` round trip over `vos-api`
  over SSH, 16 pipelined queries.
- **Gate:** PG5's arti numbers within twice their limits, or a recorded
  reason and a re-plan of M5. **Phone:** S8-P1. **Estimate:** 1–1.5
  weeks.

### 8.2 SDK-form kernels, measured — A
- `vos_sdk::p2`; in-place device arguments; `unaligned-scalar-mem` checked
  on a branch (it lands with 8.10's re-pin); `auth` and `owner` in SDK form
  against the hand-lean 1,722 steps.
- **Gate:** ≤ 1.15× the lean kernel's steps, or the fallback (Q7: the
  hand-lean kernels ship as the stock ones). **Estimate:** 1.5–2 weeks.

### 8.3 mls-rs and the keystore on the phone (spike) — B, F
- mls-rs (ciphersuite 1, minimal features) in the facility's build: a
  group of three, create, add, remove, update, the exporter, a candidate
  processed on a copy of the state and swapped; whether a maintained
  hybrid post-quantum suite exists (N6).
- The keystore: an after-first-unlock key used by a WorkManager job on a
  locked Fairphone; an Ed25519 signing key in the TEE with per-use
  `AUTH_BIOMETRIC_STRONG`, signing one admin call of up to 15 KiB per
  prompt, its attestation read; the security key's `hmac-secret` through
  YubiKit.
- **Gate:** PG5's `vos-mls` limit; a candidate processed ≤ 200 ms; the
  locked-phone job works, or PG6's locked-phone limit is dropped and
  stated. **Phone:** S8-P1. **Estimate:** 1–1.5 weeks.

## M1 — One ingress path, the light node's core, P1 (7–9 weeks)

### 8.4 Device programs at release, and compatibility windows — A
- `#[attestable(device, reference = …, headroom = …)]`; the install
  computes each device kernel's program; `device_fits`.
- **At release:** the release build computes the stock kernels' device
  programs and the light node's local actors' programs and embeds them;
  no transpiler on the phone (`light-node.md` §4.4).
- **Windows:** each stock guard admits at most the current and previous
  release's program ids, and ingress the current and previous device
  formats, each with a retirement date, 60 days after the next release by
  default and settable by the operator to any earlier date, now included;
  two versions in a window compute identical claims; the light node
  proves with the newest the space admits.
- **Carried in:** reproducible path-dependent blobs (the app and the
  space take one release artifact by hash).
- **Gate:** an app one release behind signs in at an upgraded space, and
  is refused, with its message, once the window closes or is retired now;
  both versions' proofs yield the same nullifier in one `once` scope; a
  kernel outside the window is refused before proving. **Dep:** 8.2. **Estimate:** 2–3
  weeks.

### 8.5 Proven calls, format 44 deleted — A
- `#[msg(proven = k)]`; `Credentialed.claim`; `CredentialedInput`
  carrying the claim (≤ 1 KiB); `Principal::Kernel` (index 7); the stock
  kernels' checks in the node's Rust; an actor kernel's checks at apply;
  `auth` and `owner` as stock kernels. Format 44 and the credential AIR
  deleted (E1).
- **The pre-check, a target:** the verifier's first milliseconds profiled
  and a well-formed junk proof refused in ≤ 1 ms at p95 if the format
  allows; recorded either way, not a precondition for the onion.
- **Carried in:** the binding sweep's budget.
- **Gate:** the carrier audit over proven calls. **Dep:** 8.4.
  **Estimate:** 2–3 weeks.

### 8.6 The light node's core — C
- `vos-light`: the interpreter and machine pool; merge and query entries
  over fjall, one batch per operation; no log (`light-node.md` §2.1). The
  executor's host-call layer moves out of `vos-node` into a crate both
  link; `vos-device`'s modules placed and the crate deleted; s4's
  facility repointed; `vos-pvm-recair`'s `recursion` feature (Q9). The
  host-call layer is entangled with a 27k-line crate that hard-depends on
  Raft, QUIC and the venue, hence the estimate.
- **Gate:** a local actor installed from release artifacts and called on
  the phone build; a process killed mid-operation leaves the store
  consistent. **Estimate:** 3–4 weeks.

### 8.7 Payments P1 on cipher-clerk v0.3.0 — B
- `Payments` (the L0 kernel, accounts by owner digest, one a device;
  `transfer` under `credential = Owner`), replacing `purses`; s4's demo
  `pay` on it.
- **Dep:** 8.5. **Estimate:** 1.5–2 weeks.

### M1 acceptance
- `ci-full`, the checker loop, PG1′ and PG2′ on format 46, PG3′'s P1 flows
  on the clearnet (S8-P2). Fable.

## M2 — The levers in the device format (5.5–8 weeks with two implementers; parallel)

### 8.8 A per-program CPU — A
- **Dep:** M1. **Estimate:** 3–5 weeks.

### 8.9 Word-level memory — B
- **Dep:** M1. **Estimate:** 4–6 weeks.

### 8.10 Format 47, one re-pin — A
- 8.8 and 8.9 as one device format; `unaligned-scalar-mem` with it; format
  46 kept in the ingress window until its retirement date.
- **Carried in:** the quiet re-measure of `0x402`.
- **Gate:** PG1′ and PG2′ on 47 twice, a day apart (S8-P3, S8-P4); a 46
  proof and a 47 proof accepted at one node in one run; a 46 proof
  refused the moment its retirement is set to now; the light node choosing
  47 when both are admitted and 46 when only 46 is. 46 need not stay
  admitted at the slice's end (version counters reset before the first
  release); the mechanism is what the gate proves, and the previous
  format's fuzz and leakage targets stay until its code is deleted.
  Fable. **Dep:** 8.8, 8.9. **Estimate:** 1.5–2 weeks.

## M3 — The personal agent in the space (stream D, 11–15 weeks from M0)

### 8.11 Admission at ingress
- An agent's admitted-keys rows looked up **before** the signature check
  for a session-creating call; the gateway's transport mark on every
  relayed frame, and onion-only agents refusing unmarked requests.
- **Gate:** an unknown key's 10^4 session attempts write nothing and cost
  no verification; a clearnet request, and one with no mark (the unix
  socket's), to an onion-only agent is refused.
  **Estimate:** 1–1.5 weeks.

### 8.12 `Personal`: commits, envelopes, the inbox
- The commit log (candidates, each an **admin call** whose origin is
  checked against the device set, `EpochTaken`/`EpochGap`, declared effects carrying every matured
  removal), signed confirmations and nacks, the confirming set (devices
  with a call in the last 72 h) written into the candidate's log entry,
  removed devices' votes ignored; the lapsed agent's grace rules (removal
  commits, `alive` and confirmations still taken); sealed scopes (`push` deduplicated then `StaleEpoch`, positions,
  `since` returning `(position, id, bytes)`); checkpoint acknowledgements;
  the recovery scope; quotas, their exemptions and per-device shares; the
  inbox with lazy expiry; queries answering only admitted keys.
- **The append-only layout:** a test installs the next version over a
  populated agent and reads every envelope and operation back.
- **Evidence:** `evidence(operation, message, signature)` stored as data
  beside each admin call's operation, its message's arguments compared
  byte for byte with the operation.
- **Gate:** the §8 scenarios naming 8.12 as tests; a commit from a sync
  key, or from an admin key whose device may not commit, refused.
  **Estimate:** 3–4 weeks.

### 8.13 `Personal`: the device set
- States, admin classes and curves, seasoning; operations signed end to
  end and stored; delays on batch time; vetoes, contests and resolutions;
  immediate removal by two seasoned devices; probation frozen under a
  pending removal; the kit's entries (phrase and security key), its
  operations, its inability to veto; liveness (`alive`) cancelling a
  restore; a matured-removed device's vetoes, `alive`, confirmations and
  nacks ignored; `R1`, `R2` and the release to a matured restore; kit
  rotation and its re-seal; admin-key replacement keeping seasoning;
  `regroup` by an active seasoned device; every delay and the probation
  configurable per space (minutes on a test home).
- **Gate:** property tests against two adversaries (`light-node.md` §8,
  A3, A4, A14): one holding an active device and its biometric who may
  also pair devices: the owner with one device and the kit, or two other
  seasoned devices, always removes it within the delay, and it never
  removes an owner device the owner contests; one holding only a sync
  key: the kit alone removes its device after 7 days unvetoed, and its
  restore matures 7 days later, the removed device's `alive` ignored.
  And: a leaked kit alone completes nothing while a device vetoes.
  **Estimate:** 3–4 weeks.

### 8.14 `Homes`, the keeper, the home-only space
- `Homes` beside the credential actor: `stock`, `claim` under
  `Auth("home")`, the nullifier and kit-key indexes, `PoolEmpty`,
  `assigned`/`refused`, recorded device nullifiers, `renew` and the
  13-month lease, the grace period's rules; the "home" scope reserved in
  the facility.
- The registrar's open claim priced by work, with its daily cap sized to
  the home's disk and below the keeper's refill rate; the quota ramp (8
  MiB, 64 MiB after the first re-proof); the lease and the claim's
  difficulty configurable per space (a test home's in minutes and low).
- The keeper (`tools/`): create, install, `Grant`, stock, upgrade in
  batches.
- **Gate:** a pool of 200 made and claimed; a double claim refused; a
  lapsed agent serving reads, a restore and a removal and refusing pushes;
  an open claim without its work refused; the cap's `PoolEmpty`.
  **Estimate:** 2–2.5 weeks.

### 8.15 The scale gate
- 10^4 personal agents on a three-node space, each pushing and fetching
  every 15 minutes for an hour, sessions opening and sweeping, pushes of
  full 256 KiB steps among them; one agent filled to 64 MiB, its snapshot
  installed, and one `replace`.
- **Gate:** the other agents' commit p99 within 20% of the same run
  without personal agents; ≤ 64 KiB resident a personal-agent replica
  above idle; a full agent's snapshot installed ≤ 30 s. Run alone.
  **Estimate:** 1–1.5 weeks.

### 8.16 Device memberships
- The registrar's person records, `enroll_device` under `credential =
  Owner` with a per-member limit, `revoke_device`; `once` admitting one
  nullifier per device, stated (N3 (c)).
- **Gate:** a second device enrolled and revoked in a space by its first
  device's proof. **Dep:** 8.5. **Estimate:** 1–1.5 weeks.

### M3 acceptance
- `ci-full`, 8.15's gate, 8.13's property tests, the carrier audit over
  `Personal`'s logs. Fable.

## M4 — The personal space on devices

### 8.17 merkle-crdt for devices — E
- The incremental apply; the author, sequence and signature in the
  payload; a `Store` over fjall; batched fetching; `redb` deleted.
- **Estimate:** 2–3 weeks.

### 8.18a The CRDT types and merge dispatch — C
- `crdt::{GSet, Set, Map}` stored per author, read filtered;
  `#[msg(merge)]` and merge dispatch; `core-model.md` §9.4 amended
  (plaintext and sealed scopes). These are the Merge lane's first
  storage-backed types, unbuilt and unmeasured until now, hence the
  estimate.
- **Dep:** 8.6, 8.17's API. **Estimate:** 3–4 weeks.

### 8.18b Local actors, versions, quarantine — E
- Versioned operations, unknown kinds held; validation and quarantine;
  the credential book and the device book; storage-full handling.
- **Dep:** 8.18a. **Estimate:** 2–3 weeks.

### 8.19 `vos-mls` and the device group — C
- `vos-mls` over mls-rs: storage providers over fjall, copy-and-swap, the
  confirmation hash, the device group's proposal policy; in `vos-light`:
  commits as admin calls with their evidence (an Update on the yearly
  prompt), candidates on a
  copy, confirmations against the logged set and nacks, sleepers deferred
  with their alarm, exporter keys, scope ids from the naming secret, the
  key archive.
- **Gate:** a committer that encrypts garbage to one awake device never
  gets data sealed to the other side; to a sleeping one, the sleeper
  alarms and re-pairs or regroups on return; a commit that is not an
  admin call is refused by the agent, and an operation or commit without
  valid evidence moves no device; two attacker
  devices are removed by one commit; every disallowed proposal is nacked;
  two devices shown different confirming sets raise the split-log alarm. **Dep:** 8.3, 8.12, 8.18a.
  **Estimate:** 3.5–5 weeks.

### 8.20 Sealed sync — C
- Envelopes (nonce, Padmé, opaque scope ids, the writer's view and `seen`
  positions inside), seal-at-push, the queue's sealed bytes, the cursor;
  archives at confirmed epochs; recovery envelopes under `R`; Tor-only
  traffic.
- **Gate:** PG6's catch-up on the clearnet. **Dep:** 8.19. **Estimate:**
  2.5–3.5 weeks.

### 8.21 Checkpoints and detection — A
- Checkpoints at agent positions, the pairing device's trusted, two
  acknowledgements for restores; control-log views; `seen` positions
  checked; the sample audit of one's own pushes.
- **Gate:** a model test of two devices and a hostile agent (a rollback,
  equivocation on commits and on operations, a partition, a dropped veto, a
  forged operation, a stale-epoch push, a backdated envelope, a wrong
  checkpoint): each detected or refused as `light-node.md` §8 says.
  **Dep:** 8.20. **Estimate:** 2–3 weeks.

### 8.22 The background job — F
- WorkManager on the after-first-unlock keys; `alive` when a restore is
  pending; local notifications for pending operations; last-sync times;
  the battery-exemption prompt; a killed job leaves everything consistent.
- **Gate:** PG6's job limits on a locked phone, and its recorded cases.
  **Dep:** 8.6, 8.20. **Estimate:** 1–1.5 weeks.

### 8.23a Pairing, claim, memberships, retiring a phone — C
- The claim at a home-only space (the open claim's work, a phrase or
  security-key kit); pairing through an inbox slot (QR, Noise `XXpsk3`;
  the archive, `R` and the checkpoint hash over the channel); the device's
  home nullifier recorded; the new device's open claim in the background
  after pairing; enrollments in every other space at once, deferrable per
  space; retire a phone; the yearly re-proof with the leaf renewal on its
  prompt; refusing a second claim.
- **Dep:** 8.13, 8.14, 8.16, 8.20. **Estimate:** 2–2.5 weeks.

### 8.23b Kits, restore and contests — D
- Kit creation and rotation (phrase, security key); restore here and
  elsewhere, liveness, the forced rotation; the removal, veto, contest and
  resolution flows; delayed admins; admin-key replacement.
- **Dep:** 8.13, 8.20. **Estimate:** 2–2.5 weeks.

### 8.23c Moving home — B
- Claim elsewhere, a new group, the kit re-split, push everything,
  re-pair.
- **Dep:** 8.23a. **Estimate:** 1 week.

### 8.24b The `:vos` process and its Binder interface — F
- The facility in `android:process=":vos"` [E21]; one Binder interface
  carrying its named operations, typed results and errors, nothing
  generic; prompts and their keystore operations in the UI process,
  results handed to `:vos`; the SSH socketpair as a `ParcelFileDescriptor`;
  the background job in `:vos`.
- **Gate:** every operation over Binder; `:vos` killed during a proof and
  during a sync, and the UI killed during both, each leaving the other
  running and the store consistent. **Dep:** 8.6. **Estimate:** 1.5–2
  weeks.

### 8.24 s4's screens — F
- Kotlin screens over 8.24b's interface: the claim and its kits, pairing
  (show and scan a QR), devices (last sync, remove, veto, resolve,
  contests, rotation, admin key, regroup), retire a phone, restore, move
  home, the yearly re-proof, local notifications, "backup paused" on a
  network that blocks Tor; the prompts (strong biometric for the admin
  key).
- **Gate:** each screen drives its flow on the phone. **Dep:** 8.24b,
  8.23a–c's facility operations (developed against stubs first).
  **Estimate:** 3–4 weeks, its last 1–2 weeks after 8.23a.

### M4 acceptance
- `ci-full`, PG3′'s personal-space flows and PG6 on the clearnet (S8-P5),
  8.21's model test, the carrier audit over the light node's and the
  agent's logs. Fable.

## M5 — Tor (stream E)

### 8.25 The gateway's onion service
- A `tor` feature; the onion serving SSH (22) and HTTP (80), the
  clearnet's protocols and nothing else [E23]; the SSH `vos-api`
  subsystem's relay set adding `Call` and `Credentialed` (behind the
  in-flight cap, per-connection, per-circuit, per-agent and per-onion
  caps); the transport mark, and a space's option to refuse anonymous
  calls without it, or to be onion-only [E22]; full vanguards; PoW behind a flag; the onion set
  served by the registrar; every node listed as an upstream; the C tor
  sidecar documented and run once.
- **Gate:** a flood of well-formed junk proofs through Tor measured
  against the node's budget, members' sign-ins still served. **Dep:** 8.1,
  8.5, 8.11. **Estimate:** 2–2.5 weeks.

### 8.26 The client over arti
- One `TorClient`; `vos-api` over SSH over the onion [E23], one SSH
  connection per isolation group under its own SSH key, kept open while
  in use; a spare connected ahead for proven calls; dormant mode; s4's
  screens over the same Tor through a socketpair descriptor; the pinned
  onion set and its refresh; the clock named when bootstrap fails.
- **The Tor policy** [E22]: Tor the default for every space, a per-space
  opt-out for key-signed calls with a plain warning; no clearnet route at
  all for anonymous calls or for the personal agent's and `Homes`' kinds;
  plain bridges pasted in the chrome.
- **Gate:** an anonymous call refused by the client on a clearnet-only
  path; a bootstrap through a pasted bridge on the phone; two isolation
  groups never sharing a circuit or an SSH key in a capture.
- **Dep:** 8.6, 8.25. **Estimate:** 3–4 weeks.

### 8.27 The credential tree's feed
- **Carried in:** tree syncing and the `map_root` fingerprint: each tree
  kept from a paged feed on one long-lived circuit, no path fetched, every
  proof against the newest root, the log keeping the root's place in the
  ring.
- **Dep:** 8.5, 8.18a. **Estimate:** 1.5–2 weeks.

### M5 acceptance
- PG3′ and PG6 over Tor (S8-P6); PG5's rendezvous limit; 8.25's flood
  measurement; the carrier audit with the onion in the path;
  `node/SECURITY.md` and the light node's `SECURITY.md` (what Tor fixes
  and does not; the personal agent's known limits, `light-node.md` §8).
  Fable. **Dep:** M4, 8.26, 8.27.

## M6 — Slice end (2.5–3 weeks)

### 8.28 Documents and the audit's scope
- `proving.md` §8, `identity-and-authority.md` §5–§8, `core-model.md`
  §9.4 and §11, `node-api.md` §2, §3 and §6 rewritten to what was built;
  `light-node.md` to [built]; `open.md` takes `light-node.md` §9.3's list;
  the light node's `SECURITY.md`.
- **Carried in:** the external audit's scope: the device format, the
  Poseidon2 chip, their masking, the stock kernels, the personal agent's
  protocol and `vos-mls`'s use of MLS.

### 8.29 The slice gate
- `ci-full` at slice tier, the checker loop, every phone gate on the final
  build (S8-P7), the slice-end Fable review, the code-quality review
  folded.

## The critical path

- **Stream C:** 8.6 (3–4) → 8.18a (3–4) → 8.19 (3.5–5) → 8.20 (2.5–3.5)
  → 8.23a (2–2.5) = 14–19 weeks, then **8.24's tail** (1–2): 15–21 weeks.
  Its waits: 8.18a on 8.17's API (stream E, week 3–4.5); 8.19 on 8.12
  (stream D, week 4–5.5); 8.23a on 8.13, 8.14 and 8.16 (D, in that order
  after 8.11 and 8.12, week 10–13.5); none later than C reaches them.
- Then M4's acceptance (1–1.5), M5's over Tor with its flood test (1–1.5;
  Tor ready on stream E by week 14.5–20.5), M6 (2.5–3): **19.5–27
  implementer weeks.**
- **The heavy-run queue:** M1's and M2's `ci-full` and phone sessions, M3's
  `ci-full` and 8.15's scale run take turns on the machines: about a week
  on the chain.
- **Reviews** on the chain: a step's Opus review and folds (about 0.3–0.5
  week a step, six steps) and four Fable rounds (M3's to M6's, 0.5–1 week
  of fixes each): about 4–6 weeks.
- **The slice: about 24–34 weeks** on six streams. Off the path: A 12–18
  weeks with 8.21; B 7.5–10.5 with 8.23c; D 13–17.5 with 8.23b; E
  12.5–17 (8.26 grown by the bridges and SSH connections, still off the
  path); F 5.5–7.5 of its own plus 8.3's keystore half.
- **Milestones,** in implementer weeks from the start (before the queue
  and reviews): M0 by week 2–3; M1 by 7–9; M2 by 12–17; M3 by 12–16; M4
  by 16–22.5; M5 by 17–24; M6, the slice's end, by 19.5–27.
- **What starts first:** M0's three spikes (8.1, 8.2, 8.3) and, alongside
  them, 8.6 (the light node's core), 8.11 and 8.12 (`Personal`'s ingress
  admission and commit log) and 8.17 (merkle-crdt): none depends on
  another stream's output.
- **If it slips,** what ships first: M1 and M2 (one proving path, P1,
  format 47); then the personal space on the clearnet (M3, M4); then Tor.

## Carried from slice 7

From slice 7's end review, now in `open.md`:

| item | where |
|---|---|
| the per-program CPU and word-level memory | 8.8, 8.9, 8.10 (the device format; the node's segment format later) |
| tree syncing (the path leak) and the `map_root` fingerprint | 8.27 |
| the binding sweep's budget | 8.5 |
| the quiet re-measure of `0x402` | 8.10 |
| reproducible path-dependent blobs | 8.4 (one release artifact by hash) |
| the external audit's scope | 8.28, rescoped |
| the cleanup before master | the precondition |
| the executors' verification gate on a many-core host; T1's and T6's p99, T5's throughput; T2 and a host's kill | **not in slice 8:** a node-performance track, the owner's to schedule; 8.15 is the only scale run here |
| the per-call identity read; the identity agent replicated per node; the non-repudiation side store | **not in slice 8:** the identity track (`open.md`, "Identity and privacy") |

## Before the first step

The owner's sign-off; the second device; the phone sessions' windows; the
test home-only space for M4 and M5 (Virto's home's shape, E20, with test
delays, lease and claim difficulty).
