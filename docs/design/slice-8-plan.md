# Slice 8: the light node and the personal agent — plan

Draft 3 [proposed]. The design is `light-node.md` (draft 3); this file
orders it into milestones, steps, gates and estimates, and places what
slice 7 carried.

- **Status:** [proposed] throughout. The steps take the owner's decisions
  E1–E11 (`light-node.md` §1.1), draft 2's Q5–Q12 at their
  recommendations, provisionally (§9.2), and the recommended answers to
  the new questions N1–N6 (§9.1); a different answer changes the steps it
  names. **N1 moves P2 (the shielded pool and the wallet) to slice 9;**
  E3 asked for it in slice 8, so this needs the owner's word.
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
  full-N leakage at the slice end. cipher-clerk's steps run in its own
  repository and release by tag; VOS takes the tag.
- **Estimates** are one implementer's weeks, before review. The critical
  path assumes five streams: proving (M1's proving steps, then M2's 8.8);
  a second proving implementer (M2's 8.9); the light node and the
  personal space on devices (8.6, 8.14–8.17); the node side and Tor (8.11–
  8.13, 8.18–8.20); cipher-clerk (8.21).

## Phone gates, restated for one proving path

PG1 (the credential AIR's 250 ms) retires with format 44. Every gate is on
the Fairphone 6 [decided, `proving.md` §8], automatic threads, three rounds
of five, the gate the median of the rounds' medians, the 95th percentile
beside it, each proof verified on the phone and accepted at a space's
ingress.

| gate | what | budget | when |
|---|---|---|---|
| **PG1′ owner** | the stock `owner` kernel, SDK form | ≤ 0.5 s, ≤ 512 MiB | M1 (format 46), M2 (47) |
| **PG2′ sign-in** | the stock `auth` kernel, SDK form | ≤ 1.0 s at format 46 (M1); **≤ 0.55 s** at format 47 (M2; the model's 0.45–0.48 s leaves a 0.5 s gate a 4% margin); ≤ 1 GiB (target 768 MiB); the proof ≤ 1.5 MiB | M1, M2, slice end |
| **PG3′ flows** | enroll, sign-in, pay (P1), claim a personal agent (with its recovery kit), pair a second device, sync both ways, remove a device (delayed, then vetoed once and let through once), restore from the kit on a fresh install, move home; through the gateway's onion service, every secret behind the keystore's prompt; recorded (a capture, the gateway's and node's logs) | each flow completes; the latencies recorded beside `light-node.md` §6.3's model | M1 (enroll, sign-in, P1 on the clearnet), M4 (the personal space on the clearnet), M5 (all, over Tor), slice end |
| **PG5 footprint** | the light node with arti and mls-rs: the `.so`'s growth, idle resident memory, warm and cold bootstrap, an onion connection, a day of background syncs' battery | `.so` growth ≤ 12 MB, idle ≤ 96 MiB, warm bootstrap ≤ 3 s p50; the rest recorded | M0 (first numbers), slice end |
| **PG6 sync** | a background sync job with nothing new; a catch-up of 1 MiB of envelopes; a commit's processing on the phone | the job ≤ 30 s wall and ≤ 1 MB down at p50; the catch-up and the commit recorded, over Tor | M4 (clearnet), M5 and slice end (Tor) |

PG4 (the spend) moves with P2 to slice 9 (N1).

**The second device** for pairing is the owner's to name (another phone,
or an emulator for the second side; the restore flow needs a fresh
install, which the Fairphone itself can be).

**Phone sessions** (each asked a week ahead): S8-P1 at M0 (arti and
mls-rs, PG5's first numbers); S8-P2 at M1's end (PG1′, PG2′ on 46, PG3′'s
first flows on the clearnet); S8-P3 at M2's exit and S8-P4 a day later
(PG1′, PG2′ on 47, twice); S8-P5 at M4's end (the personal space's flows,
PG6 on the clearnet, two devices); S8-P6 at M5's end (PG3′ and PG6 over
Tor); S8-P7 at the slice end (every gate on the final build).

## M0 — Measure first (2–3 weeks)

### 8.1 arti on the phone and at a gateway (spike)
- arti-client (`default-features = false`; `tokio`, `rustls`,
  `compression`, `onion-service-client`) linked into the facility's
  build; a throwaway gateway prototype hosting an onion service in
  process (`launch_onion_service_with_hsid`, `handle_rend_requests`) with
  one echo port and one `vos-api` port.
- **Measure:** the `.so`'s growth, idle resident memory, cold and warm
  bootstrap, onion connection time (p50, p95), a 1 MB upload, the round
  trip of a `Time` request, and 16 pipelined queries on one channel; on
  x86 too.
- **Gate:** PG5's first numbers recorded; `light-node.md` §6.3–§6.4
  updated with them. **Phone:** S8-P1. **Dep:** none. **Estimate:** 1–1.5
  weeks.

### 8.2 SDK-form kernels, measured
- `vos_sdk::p2` (`Digest`, `Tag::hash`, `Path::root`, lean, no branch on
  path bits); in-place device arguments by the macro; the guest target's
  `unaligned-scalar-mem` checked through the transpiler on a branch (it
  rebuilds every guest ELF and moves every pinned blob, so it lands only
  with 8.10's re-pin).
- `auth` and `owner` written in SDK form in a test actor; steps counted
  against the hand-lean kernel (1,722).
- **Gate:** the SDK-form auth ≤ 1.15× the lean kernel's steps, or a
  recorded reason and the fallback (`light-node.md` §9.2, Q7).
  **Dep:** none. **Estimate:** 1.5–2 weeks.

### 8.3 mls-rs on the phone (spike)
- mls-rs (the version current at the step, ciphersuite 1, the storage
  providers from the `messaging` branch adapted to fjall) in the
  facility's build; a group of three: create, add, remove, an update, the
  exporter's keys; whether a maintained hybrid post-quantum suite exists
  and what it costs (N6).
- **Measure:** the `.so`'s growth, a commit's processing time and memory
  on the phone, the state's size per device.
- **Gate:** numbers recorded in `light-node.md` §2.3 and §3.4; the suite
  chosen (N6). **Phone:** S8-P1. **Dep:** none. **Estimate:** 1 week.

## M1 — One ingress path, the light node crate, P1 payments (6–9 weeks)

### 8.4 Device programs for every kernel
- `#[attestable(device, reference = …, headroom = …)]`; the derivation
  records the reference and refuses a device kernel without one; the
  install computes each device kernel's program; the testkit's
  `device_fits`.
- **Which kernels see a secret** (`light-node.md` §4.4, §8 G2): the light
  node's own computation of the stock kernels' programs, compared with the
  space's before a secret enters a proof.
- **Carried in:** reproducible path-dependent blobs: a device computes a
  kernel's program id from bytes, so the bytes must be reproducible
  (`open.md`, "Repository").
- **Dep:** 8.2. **Estimate:** 1.5–2 weeks.

### 8.5 Proven calls, and format 44 deleted
- `#[msg(proven = k)]`; `Credentialed.claim`; `CredentialedInput` carrying
  the claim (capped at 1 KiB) in place of `root`; `Principal::Kernel`
  (index 7); the stock kernels' checks (auth's scope, ring and `once`)
  kept in the node's Rust with their refusal codes; an actor kernel's
  checks at apply only; `auth` and `owner` as stock kernels in
  `vos-credentials`, the `device` test actor's hand-lean kernel kept as a
  bench only.
- Format 44 and the credential AIR deleted (`light-node.md` §4.1's list,
  E1); PG1's bench cases go; the phone bench takes the kernels.
- The verifier's first milliseconds profiled (decode, canonical
  re-encoding, setup: a wrong interaction PoW already costs 5.8 ms), and a
  refusal target set from the profile.
- **Carried in:** the binding sweep's budget (`open.md`, "Proving"),
  since the binding rows' writer changes here.
- **Gate:** the carrier audit over proven calls; `node/SECURITY.md` and
  `identity-and-authority.md` §5 restated. **Dep:** 8.4.
  **Estimate:** 2.5–3.5 weeks.

### 8.6 `vos-light`
- **A carve-out spike first** (one week): `vos-node` is about 27.6k lines
  and depends without option on recair, the venue, the node prover,
  `vos-net`, `vos-raft`, quinn and the compiler; its `dispatch` is peer
  dispatch and `calls.rs` reads Raft's role. The spike chooses between a
  `server` feature and a single-replica host of `vos-light`'s own over the
  executor and the store, moved.
- Then: the single-replica host; every local write in one fjall batch per
  step (`light-node.md` §8 D6); `vos-device`'s modules placed (`secret`,
  `wire`, `path` and `call` into `vos-light`'s client side; `kernel`,
  `prover` and `threads` into its prover side, the credential prover
  deleted with 8.5), the crate deleted; `credentialed.rs`'s use of
  `vos_pvm_recair::device` moved; s4's facility repointed.
- `vos-pvm-recair`'s `recursion` feature (Q9: the leaves, folds and wrap
  out of a device's build); the `.so` size recorded before and after.
- **Dep:** none (parallel with 8.4–8.5). **Estimate:** 4–6 weeks.

### 8.7 Payments P1 on cipher-clerk
- `Payments` (the L0 kernel, user accounts held by owner digests, one a
  device, `transfer` under `credential = Owner`), replacing `purses`; s4's
  demo `pay` on it; the chrome shows each device's balance and the
  transfer between one's devices (`light-node.md` §8 G4, L4).
- **Dep:** 8.5. **Estimate:** 1.5–2 weeks.

### M1 acceptance
- **Gates:** `ci-full`, the checker loop, PG1′ and PG2′ on format 46, PG3′'s
  first flows on the clearnet (enroll, sign-in, pay on P1). **Phone:**
  S8-P2. Fable at the milestone's end.

## M2 — The levers in the device format (5.5–8 weeks with two implementers, 8.5–13 with one; parallel with M3 and M4)

### 8.8 A per-program CPU
- The CPU's columns from the program's opcodes (785 → 535–549 [model]),
  in the device format only; the node's segment format is a later step of
  its own (a new leaf, folds, wrap and venue pins; `light-node.md` §4.4).
- **Dep:** M1. **Estimate:** 3–5 weeks.

### 8.9 Word-level memory
- The device memory ledger by words; −17% of auth's cells alone, −26%
  with 8.8 [model, `proving.md` §8].
- **Dep:** M1 (parallel with 8.8, a second implementer).
  **Estimate:** 4–6 weeks.

### 8.10 Format 47, one re-pin
- 8.8 and 8.9 land as one device format (47); the guest target's
  `unaligned-scalar-mem` (8.2) lands with it, so every guest ELF, pinned
  blob and program id moves once; the leakage and fuzz gates on it; the
  light node's update prompt when the space's format moves
  (`light-node.md` §8 D8).
- **Carried in:** the quiet re-measure of `0x402` (with the re-pin).
- **Gate:** PG1′ and PG2′ on format 47 twice, a day apart (S8-P3,
  S8-P4); `ci-full` at milestone tier. Fable at the milestone's end.
- **Dep:** 8.8, 8.9. **Estimate:** 1.5–2 weeks.

## M3 — The personal agent in the space (6–9 weeks; from M0, parallel with M1)

### 8.11 Forwarding for agents a node does not replicate
- A peer message carrying a request as received; the receiving replica
  runs ingress as for a gateway's request; never forwarded twice;
  forwards counted against the per-peer budget (`light-node.md` §3.3, §8
  H6).
- **Gate:** every client kind (`Call`, `Query`, `Credentialed`,
  `Workflow`) through a gateway whose upstreams hold no replica of the
  agent; the end-to-end suites with gateways listing one node each.
- **Dep:** none. **Estimate:** 1.5–2 weeks.

### 8.12 `Homes`, the pool and `Personal`
- **`Homes`** (beside the space's credential actor): `stock` (the
  operator's role), `claim` under `Auth("home")`, the lease (35 days,
  renewal by any device's proof, its pseudonyms), `PoolEmpty`, lapse,
  read-only grace, `wipe` and return to the pool; unique assignment
  (`light-node.md` §8 B11–B14).
- **`Personal`:** the device set and its states (probation, active,
  removing, removed with frontiers), operations signed end to end and
  stored with their signatures, the delays and vetoes on batch time, the
  recovery entry and its 7-day operations; the MLS log (`commit` with
  `EpochTaken`/`EpochGap`, 180-day retention, the matured-operation check
  on adds and removes); sealed scopes (`push` with `StaleEpoch`,
  deduplication, positions, `since`, quotas, delayed `collect`); the
  inbox (TTL table, a sweeping timer workflow, pairing slots); `assign`
  and `wipe` from `Homes` alone; `handover`.
- **The keeper** (`tools/`): tops the pool up in bulk with an operator
  key.
- **Gate:** property tests of the device-set rules (no sequence of
  operations lets a device veto its own removal, act in probation, or
  mature a delay early); a forged operation without its signature never
  leaves the log as valid to a device (the devices' check, tested against
  `Personal`'s log); **10^4 personal agents on a three-node space** each
  waking for a push and a fetch every 15 minutes for an hour, with
  sessions opening and sweeping: resident memory, CPU and the commit
  latency of the space's other agents recorded beside `core-model.md`
  §14.1's idle numbers, and pushes of full 256 KiB steps among them.
- **Dep:** none for the actors; 8.11 for the gate's gateways.
  **Estimate:** 4–6 weeks.

### 8.13 Device memberships
- The registrar's `enroll_device` under `credential = Owner` with a
  per-member device limit, and `revoke_device`; the person-leaf ring for
  agents that use `once` (N3), its enrollment one per member.
- **Gate:** a member with three devices votes once in a `once` scope and
  signs in from each device elsewhere. **Dep:** 8.5. **Estimate:** 1–1.5
  weeks.

### M3 acceptance
- **Gates:** `ci-full`, the 10^4-agent run (8.12), the property tests,
  the carrier audit over `Personal`'s logs (no plaintext of user data, no
  member key). Fable at the milestone's end.

## M4 — The personal space on devices (11.5–16.5 weeks after 8.6)

### 8.14 merkle-crdt for devices
- The incremental apply (`core-model.md` §9.4); the author, sequence and
  signature in the payload; a `Store` over fjall; batched, asynchronous
  fetching; the `redb` store and feature deleted.
- **Dep:** none. **Estimate:** 2–3 weeks.

### 8.15 Local actors on the light node
- `crdt::{GSet, Set, Map}` in the SDK; `#[msg(merge)]` in the macros and
  merge dispatch in the default agent (none exists today); scope storage;
  the single-replica host emitting one DAG a scope; the light node
  refuses Linear fields and workflows in a local package; validation on
  apply with quarantine (`light-node.md` §8 C1); the credential book and
  the device book as the first local actors.
- `core-model.md` §9.4 amended: plaintext and sealed scopes
  (`light-node.md` §3.6).
- **Dep:** 8.6, 8.14. **Estimate:** 5–7 weeks.

### 8.16 The device group and sealed sync
- mls-rs in `vos-light` (the suite of 8.3); the agent as delivery
  service: commits posted and merged only on acceptance, membership
  changes checked against matured, verified device-set operations; epoch
  keys from the exporter, the key archive per scope, history horizons;
  envelopes (Padmé, opaque scope ids, the writer's view inside),
  seal-at-push, cursor sync, fork and rollback detection, the audit of
  one's own pushes; checkpoints at deterministic boundaries; the
  background job (jittered, Tor-only); the device-local floor on delays;
  MLS state out of Android's backups.
- **Gate:** PG6 on the clearnet; a model test of two devices and a
  hostile agent (rollback, equivocation, a dropped veto, a forged
  operation, a stale-epoch push, a backdated envelope from a removed
  device): each detected or refused as `light-node.md` §8 says.
- **Dep:** 8.3, 8.12, 8.15. **Estimate:** 4–6 weeks.

### 8.17 Pairing, removal, recovery and moving home
- Pairing through an inbox slot (QR, `Noise_XXpsk3`), the add and its
  Welcome, probation; `enroll_device` from the paired device (8.13);
  removal with its delay, veto and two-device path; the admin key behind
  `BIOMETRIC_STRONG`, sync-only devices; the recovery kit at the claim,
  recovery envelopes, restore (here or elsewhere), kit rotation; the
  claim's random wait (`light-node.md` §8 L1); handover between two live
  homes; moving after a lost home by re-pairing; the facility's `claim`,
  `pair`, `devices`, `restore` and `move_home` in s4's chrome.
- **Gate:** PG3′'s personal-space flows on the clearnet with two devices
  (S8-P5). **Dep:** 8.16. **Estimate:** 2.5–3.5 weeks.

### M4 acceptance
- **Gates:** `ci-full`, PG3′'s personal-space flows and PG6 on the
  clearnet (S8-P5), the carrier audit over the light node's logs and the
  agent's. Fable at the milestone's end.

## M5 — Tor (5–7 weeks, from M0's 8.1, parallel with M3 and M4)

### 8.18 The gateway's onion service
- A `tor` feature; the onion's key in the gateway's key directory; ports
  22, 80 and `vos-api` (its relay set adding `Credentialed` and `Call`);
  full vanguards; per-circuit and per-service limits and a cap on proven
  calls in flight; PoW behind a flag until a release declares it; the C
  tor sidecar documented and run once as the fallback (Q11).
- **Dep:** 8.1. **Estimate:** 2 weeks.

### 8.19 The client over arti
- One `TorClient` in the light node; isolation by purpose and by
  identity (the member's calls, each proven call, the personal agent's
  traffic, s4's screens); a spare circuit for proven calls; dormant mode;
  s4's SSH over a socketpair descriptor the facility pumps to the onion
  stream (`light-node.md` §2.2); the onion address pinned at enrollment;
  the space's `tor` policy and its fallbacks in the chrome, the personal
  agent's traffic Tor-only.
- **Dep:** 8.6, 8.18. **Estimate:** 2–3 weeks.

### 8.20 The path leak and the root fingerprint
- **Carried in:** tree syncing and the `map_root` fingerprint (`open.md`,
  "Tree syncing"): the credential book syncs the credential tree's leaves
  through a paged feed, so no `path(member)` is fetched and every proof
  names the newest root; the log keeps the root's place in the ring.
- **Dep:** 8.5, 8.15. **Estimate:** 1.5–2 weeks.

### M5 acceptance
- **Gates:** PG3′ and PG6 over Tor, every flow (S8-P6), which needs M4;
  the carrier audit with the onion in the path; `node/SECURITY.md` and a
  light node `SECURITY.md` stating what Tor fixes and what it does not,
  and the personal agent's threat model (`light-node.md` §8). Fable.
  **Dep:** M4, 8.19, 8.20.

## Alongside — cipher-clerk v0.4

### 8.21 cipher-clerk v0.4 (in cipher-clerk's repository)
- A design note reviewed before code (cipher-clerk's Phase 3 rule), then
  R1–R11 (`light-node.md` §5.3): one hash trait, hash commitments, keys
  per device (N4), pool-scoped nullifiers and protocol `rho` (spends and
  deposits), `Tx<I, O>` with its asset and transparent leg,
  `shielded::check`, `Plan`, `build`, `commit` and `deposit_rho`, the
  incremental note tree, the pool leg, memos, the deletions, the refusal
  tests; the fit check extended to the spend on the PVM (its steps
  counted, the spend's cost of `light-node.md` §5.7 checked).
- **Released:** tag `v0.4.0`. VOS takes the tag in slice 9 with P2; in
  slice 8 VOS keeps v0.3.0 for P1 unless v0.4.0's L0 kernel is unchanged
  enough to take at once (the step says which).
- **Dep:** none (starts at M0). **Estimate:** 4–6 weeks.

## M6 — Slice end (2.5–3 weeks)

### 8.22 Documents and the audit's scope
- `proving.md` §8, `identity-and-authority.md` §5–§8, `core-model.md`
  §9.4, §10 and §11, `node-api.md` §3 and §6 rewritten to what was built;
  `light-node.md` to [built]; `open.md` updated (P2, messaging, plaintext
  scopes, user-installed actors, mirroring and the successor group, the
  blob kind, excision, node-signed answers); `SECURITY.md` for the
  personal agent (`light-node.md` §8's known limits, B8 among them).
- **Carried in:** the external audit's scope, now the device format, the
  Poseidon2 chip, their masking, the stock kernels, and the personal
  agent's protocol (the credential AIR out); cipher-clerk's `shielded`
  module and the spend kernel added when P2 lands.

### 8.23 The slice gate
- `ci-full` at slice tier (5-minute fuzz, full-N leakage), the checker
  loop, every phone gate on the final build (S8-P7), the slice-end Fable
  review, the code-quality review folded as a behaviour-preserving step.

## The critical path

- **Proving:** 8.2 → 8.4 → 8.5 → (8.8 ∥ 8.9) → 8.10: 11–15.5 weeks with
  two implementers on M2, 14–20.5 with one.
- **The personal space** (the longest): 8.6 (4–6) → 8.15 (5–7, with 8.14
  beside 8.6) → 8.16 (4–6) → 8.17 (2.5–3.5): **15.5–22.5 weeks** from the
  start, then M4's acceptance. 8.16 also waits on 8.12 (ready by week
  6–8) and 8.3 (week 1).
- **The node side:** 8.11 ∥ 8.12, then 8.13: 5–7.5 weeks, off the
  critical path.
- **Tor:** 8.1 → 8.18 → 8.19, then M5's acceptance after M4.
- **cipher-clerk:** 8.21, 4–6 weeks, off the critical path.

**The slice: about 21–28 weeks** with five streams (the personal space's
chain, M4 and M5's acceptances, then M6's 2.5–3 weeks), 25–33 with four
[est]. If it slips, the order of what ships is: M1 (one proving path and
P1) and M2 (format 47) first; then the personal space on the clearnet
(M3, M4); Tor last. With P2 in slice 8 (N1 (b)), add 8–11 weeks to the
personal-space chain: about 30–36 weeks.

## Slice 9, as this plan leaves it

P2: the shielded pool, the wallet, the spend and join kernels, VOS on
cipher-clerk v0.4, PG4 (Q10, Q12); messaging between members on MLS
virtual clients; plaintext Merge scopes on nodes; actors the user installs
in the personal agent (E9); a second home's mirroring and the successor
group (§3.9); excising a device's operations (§8 C1); the blob kind for
large objects (§8 C6); local workflows with device effects (Q8 (b)); the
light node in its own Android process (Q5 (b)).

## Carried from slice 7

From slice 7's end review, now in `open.md`:

| item | where |
|---|---|
| the per-program CPU and word-level memory | 8.8, 8.9, 8.10 (the device format; the node's segment format later) |
| tree syncing (the path leak) and the `map_root` fingerprint | 8.20 |
| the binding sweep's budget | 8.5 |
| the quiet re-measure of `0x402` | 8.10 |
| reproducible path-dependent blobs | 8.4 |
| the external audit's scope | 8.22, rescoped |
| the cleanup before master | the precondition |
| the executors' verification gate on a many-core host; T1's and T6's p99, T5's throughput; T2 and a host's kill | **not in slice 8:** a node-performance track, the owner's to schedule (it needs compumax and more machines, and shares no code with this slice); 8.12's 10^4-agent run is the only scale measurement here |
| the per-call identity read; the identity agent replicated per node; the non-repudiation side store | **not in slice 8:** the identity track (`open.md`, "Identity and privacy"), unchanged by the light node |

## Open before the steps are pinned

The owner's answers to `light-node.md` §9.1 (N1–N6), and any change to
§9.2's provisional answers; the second device (PG3′); the phone sessions'
windows.
