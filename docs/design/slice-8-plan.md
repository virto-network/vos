# Slice 8: the light node and the personal agent — plan

**Accepted for implementation, 2026-11-02 (owner sign-off).** The design
is `light-node.md`; this file orders it into milestones, steps, gates and
estimates, and places what slice 7 carried.

- **Status:** the steps take the owner's decisions E1–E30
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
  behaviour-preserving step; `just gate` a step (`just check` is the light
  check while editing), `ci-full` with fuzz at 1
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
| **PG3′ flows** | enroll, sign-in and pay (P1); claim at a home-only test space with a phrase kit and with a security-key kit; pair a second device (enrolled in every other space at once); sync both ways; retire a phone; a removal let through, one contested and resolved by the kit, and the kit alone removing a phone that holds only a sync key; a restore cancelled by liveness, then one completed on a fresh install; a regroup keeping its regrouper alone, another device pairing again; move home (two homes: leave, claim, pair again); every secret behind its prompt; on test homes with delays in minutes, a lease that outlasts the session (no device re-proves, decision 16) and a low claim difficulty; recorded | each completes; over Tor at the median: a sign-in ≤ 4 s, a P1 payment ≤ 5 s, pairing ≤ 60 s from the scan to the second device's first read, arti and its SSH connections warm | M1 (P1) and M4 (the personal space), each an onion run: the client refuses the clearnet by construction for these, and the host suites cover the clearnet paths (owner, 2026-11-12); M5 (over Tor, its flood test), slice end |
| **PG5 footprint** | the light node with arti, `vos-mls` and mls-rs | `.so` growth from `vos-mls` and mls-rs ≤ 2 MB (a miss: trim mls-rs's features, then the owner decides); from arti ≤ 10 MB, provisional until 8.1; idle ≤ 96 MiB; warm bootstrap ≤ 3 s p50; a day of background jobs ≤ 2% of the battery; ≤ 30 rendezvous an hour in the foreground after 8.27 | M0 (first numbers), slice end |
| **PG6 sync** | the background job; a 1 MiB catch-up; a commit | on a locked phone after first unlock: the job ≤ 30 s and ≤ 1 MB down with nothing new, p50; the 1 MiB catch-up over Tor ≤ 20 s p50; a candidate processed on its copy ≤ 200 ms. **Recorded, as inputs to the windows:** the job in the "rare" bucket, after 3 days offline, after a force-stop, and the latency from a pending operation to its local notification | M4, M5 and slice end, over the onion |

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
- **Desktop result** (2026-11-02, `light-node.md` §6.3–§6.4; the phone's
  at S8-P1): PG5's arti numbers pass within twice their limits. The
  `.so` grows +13.85 MB, or +8.84 MB under fat LTO; arti's idle memory is
  about 24–27 MiB; the warm bootstrap takes 1.6 s. Separately, the
  over-Tor sign-in misses PG3′: about 6 s with a spare ready, set by a
  1 MiB upload at about 0.15 MB/s. That is the recorded reason to re-plan
  M5. The choices: shrink the device proof, split the upload over
  circuits, or move PG3′'s over-Tor limit (the owner's call).
- **Phone result** (S8-P1, 2026-11-06, `light-node.md` §6.4): PG5's arti
  limits hold on both phones: warm bootstrap 0.80 s on the Fairphone 6
  and 2.5 s on a Pixel 1, idle memory 32 and 27 MiB. A 1 MiB upload took
  2.4 s at the Fairphone's median, putting the over-Tor sign-in near
  3.2 s, under PG3′'s 4 s; M5 measures it, and the levers above stay
  open if it misses.

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
- **Phone result** (S8-P1, 2026-11-06, `light-node.md` §3.4 and §3.5):
  the gate passes. A candidate is processed in 0.63–0.73 ms on the
  Fairphone 6 and 1.2–1.4 ms on a Pixel 1; the locked-phone job ran and
  unwrapped its key on both phones; the Fairphone's admin key is an
  Ed25519 TEE key, attested, signing up to 16 KiB a prompt; the Pixel 1
  is a delayed admin; the security key's `hmac-secret` reads the same
  32 bytes twice over USB.

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
- **Phone result** (S8-P1, 2026-11-06, `light-node.md` §2.3): the gate
  passes on the Fairphone 6 and on a Pixel 1, once fjall locks with
  `flock` on Android; a call takes 0.5 ms p50 on the Fairphone and 8 ms on
  the Pixel.

### 8.7 Payments P1 on cipher-clerk v0.3.0 — B
- `Payments` (the L0 kernel, accounts by owner digest, one a device;
  `transfer` under `credential = Owner`), replacing `purses`; s4's demo
  `pay` on it.
- **Dep:** 8.5. **Estimate:** 1.5–2 weeks.

### M1 acceptance
- `ci-full`, the checker loop, PG1′ and PG2′ on format 46, PG3′'s P1 flows
  as an onion run (S8-P2; redefined 2026-11-12: the client refuses the
  clearnet for proofs by construction, the host suites cover the clearnet
  paths). Fable.
- **Result so far** (2026-11-08): `ci-full` and the checker loop (seeds
  7901–7912, the cuts in full) pass at vos-core `113eb9499`. PG1′ and PG2′
  pass on the Fairphone 6: `owner` 351.8 ms and ≤ 337 MiB, `auth`
  615.6 ms, ≤ 505 MiB and ≤ 0.88 MB, each phone-made sign-in run at the
  node's ingress (`proving.md` §8). PG3′'s P1 flows are still to run.

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
- **Built:** format 47 (`format::DEVICE_PROOF`: the per-program CPU and
  the word ledger, 46's parameters and masking, 110 / 62 bits on its own
  reference, the word set at 2^17 rows), `vos_pvm_recair::device::FORMAT`;
  46 (`BYTE_DEVICE_PROOF`) kept, proved and verified while its code lives
  (`device::FORMATS`), with its fuzz target (`device_verify_bytes_46`) and
  leakage gate beside 47's. The candidate knobs are gone: the device
  gates run on 47, `vos-phone`'s cell names a format (`47` by default, or
  `46`). The guest target takes `unaligned-scalar-mem`, and the SDK's and
  the device io-hash's unaligned word accesses are plain
  `read_unaligned`/`write_unaligned`: every guest blob and program id
  moved (`blobs.lock`, the pinned constants). Hardening before 47 shipped:
  the word ledger's last row is padding (`IsLast · (1 − IsPadding) = 0`,
  gate `word_ledger_gate::an_all_real_ledger_is_refused`), and the masked
  segment verifier refuses a first timestamp below 1
  (`a_first_timestamp_of_zero_is_refused`). **The ingress window:** 47's
  release retires 46 at once (`DEVICE_FORMATS`, 46's byte ledger is not
  consistent, `open.md`), so the shipped node admits 47 alone; a node
  computes each release's program in every format it admits, and
  `Config::device_formats` admits another (a test's). The gate
  (`the_previous_device_format_is_admitted_until_it_is_retired`): a 46
  proof refused `Format` by default; at one node admitting both, a 47
  proof and a 46 proof run, the light node choosing 47 where both are
  admitted; 46 retired now, its proof made before refused `Format`;
  admitting 46 alone, the light node choosing 46 and its proof run.
- **The quiet re-measure of `0x402`:** 1,925 TSC cycles a native
  compression, ×4.7 a BLAKE2b compression, against the price's four
  [measured, 2026-11-12; `open.md`]; the price is unchanged, the owner's.
- **Still to run:** PG1′ and PG2′ on 47, twice a day apart (S8-P3,
  S8-P4); `proving.md` §8 holds them at 46 until then.

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
- **Early run** (2026-11-06, compumax c1–c3 nodes and c4 spare, sigma
  driver; slice 7's load of 64 shards at 5,000 calls a second beside
  10,000 personal agents waking every 15 minutes; the largest push 60 KiB,
  `Personal`'s envelope cap; the fill a run of its own). Every call of the
  three runs succeeded. The snapshot gate is met: a 64 MiB agent's
  replacement installed its snapshot in 1.04 s. The other two missed as
  measured:
  - **Commit p99:** the transfers' p99 rose from 1.84 s to 2.62 s (+43%),
    one bucket of the harness's histogram, with the nodes' CPU unchanged
    at about 70%. The fill's run, with the same 10,000 agents, was back
    at 1.84 s.
  - **Memory:** +50–54 KiB a replica right after creation, but +106–111
    KiB a replica at the load's end, which counts the 255 MiB the agents
    pushed and the store's caches.
  The rerun splits a replica's memory out of the store's and reads the
  p99 at finer buckets.

### 8.16 Device memberships
- The registrar's person records, `enroll_device` under `credential =
  Owner` with a per-member limit, `revoke_device`; `once` admitting one
  nullifier per device, stated (N3 (c)).
- **Gate:** a second device enrolled and revoked in a space by its first
  device's proof. **Dep:** 8.5. **Estimate:** 1–1.5 weeks.
- **Built** (2026-11-07, `identity-and-authority.md` §6 and §5's `once`,
  `light-node.md` §3.8): the credential actor's `persons`, `owners` and
  `devices` rows; `register` and `limit` under the registrar, a person's
  first device registered by both its digests, its limit 1 to 16;
  `enroll_device`, `confirm_device` (the added device's own owner proof
  binding its owner digest) and `revoke_device` under `credential =
  Owner`; the
  registrar's `revoke` dropping a device from its person; no query answers
  a person. The credential book's `DeviceHandle` carries the owner digest
  beside the member's. `once` stated as one admission a device. The gate:
  `node/host/tests/served/credentialed.rs`'s
  `a_second_device_is_enrolled_and_revoked_by_its_first_devices_proof`,
  with real owner and auth proofs on three nodes; the refusals in
  `agent/testkit/tests/agent/credentialed.rs`. The home nullifier stays
  unproven by the person records (`light-node.md` §3.3).

### M3 acceptance
- `ci-full`, 8.15's gate, 8.13's property tests, the carrier audit over
  `Personal`'s logs. Fable. Run together with M4's (E27): one `ci-full`,
  one carrier audit over both milestones' logs, one Fable review.

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
- **Built** (2026-11-07, `light-node.md` §2.1 and §3.2): operations carry
  their actor's release (`release::Package`'s `release`), and a later
  release's, an unknown kind's and a faulted run's are held and replayed
  by an install; invalid ones, and a removed author's that arrive after
  its cutoff, quarantined and listed with their authors; the sealed read
  cuts a removed device off one past its node at its frontier, the one
  source of that cutoff; `vos-credential-book` and `vos-device-book`
  (`vos_wire::books`); a disk reserve refusing installs, calls, ingests
  and replays (`Error::Full`); `DeviceError::Rejected` carrying ingress's
  refusal. The gate: `node/light/tests/local.rs`.

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
- **Host result** (2026-11-06, `light-node.md` §3.6): a 1 MiB catch-up
  through a node's socket takes 0.62 s p50 in 1,000-byte operations and
  0.16 s in the largest, against 20 s; the phone's part is
  `tools/phone/scripts/sync.sh` (S8-P5). Over Tor its 26 sequential pages
  and 1.5 MB would miss the limit at §6.3's rates: reads asked ahead are
  the lever.

### 8.21 Checkpoints and detection — A
- Checkpoints at agent positions, the pairing device's trusted, two
  acknowledgements for restores; control-log views; `seen` positions
  checked; the sample audit of one's own pushes.
- **Gate:** a model test of two devices and a hostile agent (a rollback,
  equivocation on commits and on operations, a partition, a dropped veto, a
  forged operation, a stale-epoch push, a backdated envelope, a wrong
  checkpoint): each detected or refused as `light-node.md` §8 says.
  **Dep:** 8.20. **Estimate:** 2–3 weeks.
- **Host result** (2026-11-06, `light-node.md` §3.6, "Detection as
  built"): `node/light/tests/sealed/detection.rs`, a test a scenario,
  with the own-push audit (B2) and the checkpoints a paired device and a
  restore's device start from; the sync key is the light node's author.
- **Cut** (2026-11-17, owner's decision 16): the checkpoints move to
  slice 9 (`personal::checkpoint`, `Alarm::Checkpoint`,
  `Pairing::trust` deleted; `Personal`'s `acknowledge` kept, unused).
  A paired or restored device reads each scope from its start, and can be
  served a shortened scope without an alarm (`open.md`,
  `node/light/SECURITY.md`).

### 8.22 The background job — F
- WorkManager on the after-first-unlock keys; `alive` when a restore is
  pending; local notifications for pending operations; last-sync times;
  the battery-exemption prompt; a killed job leaves everything consistent.
- **Gate:** PG6's job limits on a locked phone, and its recorded cases.
  **Dep:** 8.6, 8.20. **Estimate:** 1–1.5 weeks.
- **Host result** (2026-11-08, `light-node.md` §3.6, "The background job
  as built"): `vos_light::job`, the pass over a `Control` link, its notices
  and `DeviceView::seen`; a pass with nothing new 7 requests and 376 bytes (6 and 372 once the checkpoints went, 2026-11-17)
  of answers; a pass killed before or after each request converging at
  the next. s4: WorkManager in `:vos`, the runs kept, the notices as local
  notifications, the exemption's prompt; a quiet run 5.2 KB down at a
  stand-in gateway. The locked-phone run waits for the phone session; the
  personal agent's part on a phone waits for s4's Tor wiring.

### 8.23a Pairing, claim, memberships, retiring a phone — C
- The claim at a home-only space (the open claim's work, a phrase or
  security-key kit); pairing through an inbox slot (QR, Noise `XXpsk3`;
  the archive, `R` and the checkpoint hash over the channel); the device's
  home nullifier recorded; the new device's open claim in the background
  after pairing; enrollments in every other space at once, deferrable per
  space; retire a phone; the yearly re-proof with the leaf renewal on its
  prompt; refusing a second claim.
- **Dep:** 8.13, 8.14, 8.16, 8.20. **Estimate:** 2–2.5 weeks.
- **Built** (2026-11-08, `light-node.md` §3.8 "Pairing, the claim and
  memberships as built"): `vos_light::pairing`, `vos_light::home::Claim`,
  `vos_light::memberships`; `Homes`' claim names the pooled agent the kit
  is sealed to (`pooled`, `Taken`), a kit's seal binding the agent's
  identity; the flows driven in `node/light/tests/sealed/pairing.rs` and
  end to end on three nodes in `node/host/tests/served/personal.rs`.
- **Cut** (2026-11-17, owner's decision 16): the joiner's open claim
  (E28) and the yearly re-proof with its prompt move to slice 9
  (`home::renew_call`, `home::renewal_due`, `Notice::Renew`, the
  facility's `renew` and its claim delay deleted; `Homes.renew`,
  `Personal.renew`, the lease and the grace kept). Every agent lapses 13
  months after its claim until slice 9 ships both or a home sets a longer
  lease (`open.md`).

### 8.23b Kits, restore and contests — D
- Kit creation and rotation (phrase, security key); restore here and
  elsewhere, liveness, the forced rotation; the removal, veto, contest and
  resolution flows; delayed admins; admin-key replacement.
- **Dep:** 8.13, 8.20. **Estimate:** 2–2.5 weeks.
- **Built** (2026-11-06, `light-node.md` §3.5 "The kit and its flows as
  built"): `vos_light::kit`; `R` rotated at every removal [the owner,
  2026-11-06], the commit re-sealing the kit (`Effect::rekey`); a
  replaced admin key's leaf renewed (`vos_mls::Mls::renew`); the gate's
  flows driven through `Personal` in the light tests' home. Pushing a
  restore-elsewhere's old scopes to the new home is 8.23c's.
- **Cut** (2026-11-17, owner's decision 16): restore elsewhere moves to
  slice 9 (restore at the home, then move); a regroup keeps its regrouper
  alone, the other devices pairing again, and the key packages kept
  devices handed over go (`DeviceGroup::regroup_package`, the facility's
  `ops/regroup.rs`, `MAX_REGROUP`).

### 8.23c Moving home — B
- Claim elsewhere, a new group, the kit re-split, push everything,
  re-pair.
- **Dep:** 8.23a. **Estimate:** 1 week.
- **Built** (2026-11-09, `light-node.md` §3.9 "Moving home as built"):
  `vos_light::moving` (`Move`, `finish`, `rejoin`, the `Notice` left at
  the old home, signed) and `SealedSync::carry`; the old set's devices
  carried authors named by the carrying device's keys in the control log
  (`NewDevice::carried`, the claim's or the add's), each bounded per scope
  by what was carried, never by an archive; a re-pair's key package in the next MLS generation beside the
  old group; a restore elsewhere's old scopes carried to its new home.
  Driven in `node/light/tests/sealed/moving.rs` and end to end on two
  homes on three nodes (each its own agent, credential actor and handle,
  in one space) in `node/host/tests/served/moving.rs`.
- **Cut** (2026-11-17, owner's decision 16; `light-node.md` §3.9 amended):
  moving home is leave, claim at the new home, pair again; nothing is
  carried. `vos_light::moving`, `SealedSync::carry`, `NewDevice::carried`
  (`CarriedAuthor`, `CARRIED`), `Waiting::Moving`, `DeviceGroup::rejoin`
  and both moving suites deleted; the facility's `Space::leave` makes the
  light node's store anew (`LAYOUT` 6, `personal.state` version 3).
- **Built** (2026-11-17, fb2 part 2, owner's decision 12, before F2): the
  personal flows moved to `vos_light::space` (`Host` + `Prompts`, a typed
  `Error`), the facility their adapter; one test double
  (`vos_light::testing`, `vos_testkit::personal::Agent`) and a light-level
  flow suite (`node/light/tests/space.rs`: a claim and a pairing, a
  regroup's removal set as the agent's); `personal.state` replaced by
  light-store rows written in the group change's batch (`LAYOUT` 7); the
  facility's enrollments, routes, bridges and runs in its own database
  (`facility/`, strict, its own types); `IVosPersonal.status` and
  `Refused`; method-id constants (`vos_wire::*::method`) and one
  `wire::answer`; `openStream`, the TCP dialer and the probe's `stream` op
  deleted, `Carried.host_key` optional (an onion first contacted).
  Valid only while the personal space holds the two books.

### 8.24b The `:vos` process and its Binder interface — F
- The facility in `android:process=":vos"` [E21]; Binder interfaces
  (s4's `IVosNode`, the facility's own `IVosPersonal`) carrying its named
  operations, typed results and errors, nothing
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
  home, the yearly re-proof (slice 9, decision 16), local notifications, "backup paused" on a
  network that blocks Tor; the prompts (strong biometric for the admin
  key).
- **Gate:** each screen drives its flow on the phone. **Dep:** 8.24b,
  8.23a–c's facility operations (developed against stubs first).
  **Estimate:** 3–4 weeks, its last 1–2 weeks after 8.23a.
- **Part 1 built** (2026-11-09, `light-node.md` §7.3 "The facility's
  wiring as built"): the facility's plumbing the screens call, then in
  s4's `credential/`: Tor in `:vos` (8.26's client side), the tree from
  its feed (8.27's), every personal-space operation on the Binder
  interface (8.22, 8.23a–c), the admin key's prompt, the binding's
  lifecycle (8.24b). Host-tested against homes in process behind an
  in-process gateway (`tests/personal.rs`).
- **Part 2 built** (2026-11-09, `light-node.md` §7.3): the screens, plain
  Android views in Java (the app has no Kotlin) under
  `team.virto.s4.personal`, a launcher entry of their own; QR codes by
  ZXing's core (a home's code and a pairing's, prefix and hex); the
  facility's forms in the app's own dialog. The gateway demo takes the
  node's answer and pins the gateway's onion. The joiner's open claim is
  the background job's after a drawn delay (E28; cut 2026-11-17, decision
  16), and an admin key is
  replaced by the kit or another seasoned device (E29). Host-tested logic
  only: the gate is the phone session.
- **Fixes before the phone session** (2026-11-10, `light-node.md` §7.3):
  a fourth device pairs after a kit rotation, admin replacements or a
  regroup (the opener reads the log before its commit; a replaced admin
  key settled before an admin call); a regroup keeping other devices
  takes their key packages, handed over through the inbox under their
  sync keys, and refuses after a bounded wait naming any device missing
  (cut 2026-11-17, decision 16: a regroup keeps its regrouper alone).
- **The facility moved into VOS** (2026-11-12, owner's call; `light-node.md`
  §2.2): the facility's crate, its tests and test world, its release
  artifacts and their recipe are `node/light/android` (`vos-facility`,
  `libvos_facility.so`), copied from s4 `a677826`; the `:vos` process and
  the screens are its Android library (`just android-facility`), which
  s4's `-Ps4Vos` build takes from a local Maven repository. VOS depends on
  s4 (`s4-protocol`, `s4-credential-contract`, `s4-server`, by git
  revision) and s4 on nothing of VOS: s4 keeps the credential contract,
  its AIDL and its UI side, and its client's facilities may carry a
  host's stream and pin its host key (`Carrier::carry`, `admit`). The
  embedded artifacts are held to this tree's guests by a test
  (`tests/release.rs`), so a guest that moves fails `just gate` until
  `just repin`. One build: `just android-facility` here, then
  `just android-build-vos <repository>` in s4.

### M4 acceptance
- `ci-full`, PG3′'s personal-space flows and PG6 as onion runs (S8-P5;
  redefined 2026-11-12, as M1's),
  8.21's model test, the carrier audit over the light node's and the
  agent's logs. Fable. Combined with M3's (E27); M5's phone runs may
  fold into S8-P7.

## M5 — Tor (stream E)

### 8.25 The gateway's onion service
- A `tor` feature; the onion serving SSH (22) and HTTP (80), the
  clearnet's protocols and nothing else [E23]; the SSH `vos-api`
  subsystem's relay set adding `Call` and `Credentialed` (behind the
  in-flight cap, per-connection, per-circuit, per-agent and per-onion
  caps); the transport mark, and a space's option to refuse anonymous
  calls without it, or to be onion-only [E22]; full vanguards; PoW behind a flag; the onion set
  served by the registrar; every node listed as an upstream; the C tor
  sidecar documented and run once (8.25), then removed (E30): arti in
  process is the onion's one host.
- **Gate:** a flood of well-formed junk proofs through Tor measured
  against the node's budget, members' sign-ins still served. **Dep:** 8.1,
  8.5, 8.11. **Estimate:** 2–2.5 weeks.
- **Measured** [x86 dev machine, chutney, 2026-11-09, E25's private Tor
  test network; `light-node.md` §6.6, `8.25f/spike/flood`]: the gate
  passes. Over a chutney network (four authorities, eight relays on
  loopback), eight circuits flooded ~1 MB junk proofs at the onion while
  members signed in on their own circuits. Every member sign-in ran (4/4,
  6/6), ~0.8 s with no flood and 1.9–3.6 s under it (p50), inside the 30 s
  bound; none was refused `Busy`. Tor itself held the junk to ~15 proofs a
  second through the onion, far below the node's budget, so the gateway's
  caps never had to shed a call (the in-process gateway test exercises the
  caps directly). A private network's rendezvous is local, so it
  understates live Tor's latency (~5 s a sign-in) and lets the junk flow
  faster than the live network would; the gateway code gained an `[onion]`
  `arti` key naming a test network's arti configuration (unknown keys
  refused, so a typo cannot fall back to live Tor).

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
- arti's state in the app's private directory without
  `ARTI_FS_DISABLE_PERMISSION_CHECKS` (S8-P1 needed it under
  `/data/local/tmp`); a fresh onion connection retried on a new circuit
  (10–20% failed on the phones).
- **Gate:** an anonymous call refused by the client on a clearnet-only
  path; a bootstrap through a pasted bridge on the phone; two isolation
  groups never sharing a circuit or an SSH key in a capture.
- **Dep:** 8.6, 8.25. **Estimate:** 3–4 weeks.
- **Built** (2026-11-08, `light-node.md` §6.2 "Built"): `vos_light::route`
  (the policy, unconditional) and `vos_light::tor` behind `vos-light`'s
  `tor` feature (arti-client 0.47.0 with `bridge-client` and
  `static-sqlite`, russh on ring), `just test-light-tor` in `gate`. The
  gate's refusal and capture: `node/light/tests/tor.rs`
  (`an_anonymous_call_is_refused_on_a_clearnet_only_path`,
  `isolation_groups_never_share_a_circuit_or_an_ssh_key`, against an
  in-process gateway recording each connection's isolation token and SSH
  key), `tests/tor_state.rs` for arti's state. Over the live network the
  `onion` example reached a local gateway's onion (§6.2's figures). The
  phone's bridge bootstrap: the same example for arm64, its script and
  expected output, for S8-P6.
- **s4's screens over Tor** (2026-11-10, §6.1 and §6.2 "Built"):
  s4-server serves any `Listener` (a TCP listener, or streams handed
  over); the gateway hands each onion SSH stream to its onion's SSH
  server with its circuit's address, the loopback carrier gone, so the
  onion serves the demo's screens beside `vos-api`, its streams and
  `vos-api` channels counted and capped per circuit (`tests/gateway/ssh.rs`,
  `the_onions_ssh_serves_the_screens_marked_onion_and_limited_per_circuit`,
  the gateway's own screen, streams handed as arti's circuits hand them,
  every place given back; the demo's screens by its e2e on its SSH
  port). The C tor sidecar is removed (E30). The demo (`vos-gateway-demo --data DIR`) hosts its own
  onion through the gateway's arti path. s4's UI hands a socketpair's
  end to `IVosNode.screens`, which `:vos` carries with
  `Client::screens_fd` and answers the host key the space pinned, the one
  s4 accepts; the opt-out
  takes the clearnet port; a space whose routes take neither is refused,
  never dialled; a gateway no space was enrolled through s4 reaches
  itself. A carried session goes under a key drawn for it, never
  resumed, forwarding no agent. Open: the screens' host-service calls
  pass no per-circuit limit (s4's host-service requests name no peer),
  and the onion's SSH server takes s4-server's connection cap (128) with
  no idle timeout. The phone run of PG3′ and PG6 over Tor is M5's.

### 8.27 The credential tree's feed
- **Carried in:** tree syncing and the `map_root` fingerprint: each tree
  kept from a paged feed on one long-lived circuit, no path fetched, every
  proof against the newest root, the log keeping the root's place in the
  ring.
- **Dep:** 8.5, 8.18a. **Estimate:** 1.5–2 weeks.
- **Built** (2026-11-12, `light-node.md` §6.7 "The root's grace"): a
  superseded root accepted for `ROOT_GRACE_MS` (90 s, two of the feed
  timer's longest gaps), not ten minutes, at ingress by the node's clock
  and in the default agent's refine at `credentials::judged_at` (the
  earlier of the batch's time and the expiry less the horizon), so apply
  never refuses what ingress admitted; a gateway's early-ended feed marks
  a root for the grace alone. `vos-agent.elf` and the node moved; the
  device formats and programs did not. Node-signed feed heads: slice 9
  (`open.md`).

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

**Built** (2026-11-11): `vos-gateway-demo --homes 2` (`node/gateway/demo`,
`vos_gateway_demo::home`): two test homes on the demo's node, in its
space, each its agent with the credential actor and `Homes`, a pool the keeper makes and
stocks, open claims at 8 bits of work; behind an onion of their own (its
own SSH host key, no clearnet port); delays in minutes and a day's lease
(`home::SESSION`); each printed as the code the app reads. Driven end to
end by `node/gateway/demo/tests/home.rs`: a claim and a pairing by s4's
facility over the onion in process.
