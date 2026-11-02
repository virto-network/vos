# Slice 8: the light node — plan skeleton

Draft 2 [proposed], a skeleton awaiting the owner's answers to
`light-node.md` §8 before steps are pinned. The design is `light-node.md`;
this file orders it into milestones, steps, gates and estimates, and
places what slice 7 carried. Draft 2 folds the Opus review of both
documents.

- **Status:** [proposed] throughout. The steps assume the recommended
  answers to `light-node.md` §8 (Q1 (a) in M1, Q2 (a), Q3 (a), Q4 (a),
  Q5 (a), Q6 (a), Q8 (a), Q10 (a), Q11 (a)); a different answer changes the
  steps it names.
- **Precondition:** slice 7's heavy cleanup before master, under way as
  this is written (its steps 7.24a, `spikes/` and dead code deleted, and
  7.24b, the history documents folded and deleted), is merged first.
- **How every step runs:** as slice 7's (`slice-7-mobile.md`, "Rules"):
  commit on `vos-core`, timeless comments, no `#[ignore]`, no
  Co-Authored-By, fix pre-existing failures, one Opus review a step, Fable
  at milestone ends and the slice end, a code-quality review at the slice
  end; `just check` a step, `ci-full` with fuzz at 1 minute a target and
  leakage at medium N at milestones, 5-minute fuzz and full-N leakage at
  the slice end. cipher-clerk's steps run in its own repository and
  release by tag; VOS takes the tag.
- **Estimates** are one implementer's weeks, before review. The critical
  path assumes four streams: proving (8.2–8.4, 8.7), a second proving
  implementer for 8.8, the light node and sync (8.5, 8.10–8.13),
  cipher-clerk and Tor (8.14–8.18). With three, 8.8 follows 8.7 and the
  slice grows by 3–5 weeks.

## Phone gates, restated for one proving path

PG1 (the credential AIR's 250 ms) retires with format 44. Every gate is on
the Fairphone 6 [decided, S3, S33], automatic threads, three rounds of
five, the gate the median of the rounds' medians, the 95th percentile
beside it, each proof verified on the phone and accepted at a space's
ingress.

| gate | what | budget | when |
|---|---|---|---|
| **PG1′ owner** | the stock `owner` kernel, SDK form | ≤ 0.5 s, ≤ 512 MiB | M1 (format 46), M2 (47) |
| **PG2′ sign-in** | the stock `auth` kernel, SDK form | ≤ 1.0 s at format 46 (M1); **≤ 0.55 s** at format 47 (M2; the model's 0.45–0.48 s leaves a 0.5 s gate a 4% margin); ≤ 1 GiB (target 768 MiB); the proof ≤ 1.5 MiB | M1, M2, slice end |
| **PG3′ flows** | enroll, sign-in, pay (P1), private pay (P2) and pairing a second device, end to end through the gateway's onion service, the secret behind the keystore's prompt; recorded (a capture, the gateway's and node's logs) | each flow completes; the latencies recorded beside `light-node.md` §6.3's model | M1 (enroll, sign-in, P1 on the clearnet), M4 (all, over Tor), slice end |
| **PG4 spend** | the pool's `spend` kernel (1 in, 2 out) | ≤ 1.5 s at format 46; **≤ 1.0 s** at format 47; ≤ 1 GiB; the proof ≤ 1.5 MiB | M3, slice end |
| **PG5 footprint** | the light node with arti: the `.so`'s growth, idle resident memory, warm and cold bootstrap, an onion connection, a day of background syncs' battery | `.so` growth ≤ 10 MB, idle ≤ 96 MiB, warm bootstrap ≤ 3 s p50; the rest recorded | M0 (first numbers), slice end |

The second device for pairing is the owner's to name (another phone, or an
emulator image for the second side).

**Phone sessions** (each asked a week ahead): S8-P1 at 8.1 (arti, PG5's
first numbers); S8-P2 at M1's end (PG1′, PG2′ on 46, PG3′ on the
clearnet); S8-P3 at M2's exit and S8-P4 a day later (PG1′, PG2′ on 47,
twice); S8-P5 at M3's end (PG4); S8-P6 at M4's end (PG3′ over Tor); S8-P7
at the slice end (every gate on the final build).

## M0 — Measure first (1.5–2.5 weeks)

### 8.1 arti on the phone and at a gateway (spike)
- arti-client (`default-features = false`; `tokio`, `rustls`,
  `compression`, `onion-service-client`) linked into the facility's
  build; a throwaway gateway prototype hosting an onion service in
  process (`launch_onion_service_with_hsid`, `handle_rend_requests`) with
  one echo port and one `vos-api` port.
- **Measure:** the `.so`'s growth, idle resident memory, cold and warm
  bootstrap, onion connection time (p50, p95), a 1 MB upload, the round
  trip of a `Time` request; on x86 too.
- **Gate:** PG5's first numbers recorded; `light-node.md` §6.3–§6.4 updated
  with them. **Phone:** S8-P1. **Dep:** none. **Estimate:** 1–1.5 weeks.

### 8.2 SDK-form kernels, measured
- `vos_sdk::p2` (`Digest`, `Tag::hash`, `Path::root`, lean, no branch on
  path bits); in-place device arguments by the macro; the guest target's
  `unaligned-scalar-mem` checked through the transpiler on a branch (it
  rebuilds every guest ELF and moves every pinned blob, so it lands only
  with 8.9's re-pin).
- `auth` and `owner` written in SDK form in a test actor; steps counted
  against the hand-lean kernel (1,722).
- **Gate:** the SDK-form auth ≤ 1.15× the lean kernel's steps, or a
  recorded reason and the fallback (`light-node.md` §8 Q7).
  **Dep:** none. **Estimate:** 1.5–2 weeks.

## M1 — One ingress path, the light node crate, P1 payments (6–9 weeks)

### 8.3 Device programs for every kernel
- `#[attestable(device, reference = …, headroom = …)]`; the derivation
  records the reference and refuses a device kernel without one; the
  install computes each device kernel's program; the testkit's
  `device_fits`.
- **Carried in:** reproducible path-dependent blobs (S58): a device
  computes a kernel's program id from bytes it fetched, so the bytes must
  be reproducible.
- **Dep:** 8.2. **Estimate:** 1.5–2 weeks.

### 8.4 Proven calls, and format 44 deleted
- `#[msg(proven = k)]`; `Credentialed.claim`; `CredentialedInput` carrying
  the claim (capped at 1 KiB) in place of `root`; `Principal::Kernel`
  (index 7); the stock kernels' checks (auth's scope, ring and `once`)
  kept in the node's Rust with their refusal codes; an actor kernel's
  checks at apply only; `auth` and `owner` as stock kernels in
  `vos-credentials`, the `device` test actor's hand-lean kernel kept as a
  bench only.
- Format 44 and the credential AIR deleted (`light-node.md` §4.1's list,
  Q1 (a)); PG1's bench cases go; the phone bench takes the kernels.
- The verifier's first milliseconds profiled (decode, canonical
  re-encoding, setup: a wrong interaction PoW already costs 5.8 ms), and a
  refusal target set from the profile.
- **Carried in:** the binding sweep's budget (L6), since the binding rows'
  writer changes here.
- **Gate:** the carrier audit over proven calls; `node/SECURITY.md` and
  `identity-and-authority.md` §5 restated. **Dep:** 8.3.
  **Estimate:** 2.5–3.5 weeks.

### 8.5 `vos-light`
- **A carve-out spike first** (one week): `vos-node` is about 27.6k lines
  and depends without option on recair, the venue, the node prover,
  `vos-net`, `vos-raft`, quinn and the compiler; its `dispatch` is peer
  dispatch and `calls.rs` reads Raft's role. The spike chooses between a
  `server` feature and a single-replica host of `vos-light`'s own over the
  executor and the store, moved.
- Then: the single-replica host; `vos-device`'s modules placed (`secret`,
  `wire`, `path` and `call` into `vos-light`'s client side; `kernel`,
  `prover` and `threads` into its prover side, the credential prover
  deleted with 8.4), the crate deleted; `credentialed.rs`'s use of
  `vos_pvm_recair::device` moved; s4's facility repointed.
- `vos-pvm-recair`'s `recursion` feature (`light-node.md` §8 Q9: the
  leaves, folds and wrap out of a device's build); the `.so` size
  recorded before and after.
- **Dep:** none (parallel with 8.3–8.4). **Estimate:** 4–6 weeks.

### 8.6 Payments P1 on cipher-clerk
- `Payments` (the L0 kernel, user accounts held by owner digests,
  `transfer` under `credential = Owner`), replacing `purses`; s4's demo
  `pay` on it.
- **Dep:** 8.4. **Estimate:** 1.5–2 weeks.

### M1 acceptance
- **Gates:** `ci-full`, the checker loop, PG1′ and PG2′ on format 46, PG3′
  on the clearnet (enroll, sign-in, pay on P1). **Phone:** S8-P2. Fable
  at the milestone's end.

## M2 — The levers in the device format (5.5–8 weeks with two implementers, 8.5–13 with one; parallel with M3)

### 8.7 A per-program CPU
- The CPU's columns from the program's opcodes (785 → 535–549 [model]),
  in the device format only; the node's segment format is a later step of
  its own (a new leaf, folds, wrap and venue pins; `light-node.md` §4.4).
- **Dep:** M1. **Estimate:** 3–5 weeks.

### 8.8 Word-level memory
- The device memory ledger by words; −17% of auth's cells alone, −26%
  with 8.7 [model].
- **Dep:** M1 (parallel with 8.7, a second implementer).
  **Estimate:** 4–6 weeks.

### 8.9 Format 47, one re-pin
- 8.7 and 8.8 land as one device format (47); the guest target's
  `unaligned-scalar-mem` (8.2) lands with it, so every guest ELF, pinned
  blob and program id moves once; the leakage and fuzz gates on it.
- **Carried in:** 7.9's quiet re-measure of `0x402` (with the re-pin).
- **Gate:** PG1′ and PG2′ on format 47 twice, a day apart (S8-P3,
  S8-P4); `ci-full` at milestone tier. Fable at the milestone's end.
- **Dep:** 8.7, 8.8. **Estimate:** 1.5–2 weeks.

## M3 — The personal space and private payments (11–16 weeks)

### 8.10 merkle-crdt for devices
- The incremental apply (`core-model.md` §9.4, S6); a `Store` over fjall;
  the `redb` store and feature deleted; the author key and signature in
  the payload, checked by `NodeValidator`.
- **Dep:** none. **Estimate:** 2–3 weeks.

### 8.11 Local actors on the light node
- `crdt::{GSet, Set, Map}` in the SDK; `#[msg(merge)]` in the macros and
  merge dispatch in the default agent (none exists today); scope storage;
  the single-replica host emitting one DAG a scope, sealed nodes, keyed
  storage names; the light node refuses Linear fields and workflows in a
  local package. `core-model.md` §9.4 amended for personal spaces (no
  epochs; removal is rotation).
- **Dep:** 8.5, 8.10. **Estimate:** 5–7 weeks.

### 8.12 The relay and sync
- The `Relay` actor (`open` under an auth credential, quotas per
  pseudonym, a mailbox key for `put`, sealed heads, checkpoints); the
  light node's sync loop over the node API; the WorkManager job.
- **Dep:** 8.4, 8.11. **Estimate:** 2 weeks.

### 8.13 The root secret and pairing
- `m`; its derived secrets wrapped one by one (per-use keys for each
  space's `s` and `sk` and for `m`, an unlock-bound key for the sync
  keys); `s` and `sk` derived from `m` (the `v2` derivation; the demo's
  enrollments and rows re-enrolled and rekeyed); pairing by QR and a
  Noise `XXpsk3` handshake through a mailbox; rotation; the facility's
  `pair` and `rotate` in s4's chrome.
- **Dep:** 8.12. **Estimate:** 2–3 weeks.

### 8.14 cipher-clerk v0.4 (in cipher-clerk's repository)
- A design note reviewed before code (cipher-clerk's Phase 3 rule), then
  R1–R11 (`light-node.md` §5.3): one hash trait, hash commitments, hash
  keys, pool-scoped nullifiers and protocol `rho` (spends and deposits),
  `Tx<I, O>` with its asset and transparent leg, `shielded::check`,
  `build`, `commit` and `deposit_rho`, the incremental note tree, the pool
  leg, memos, the deletions, the refusal tests; the fit check extended to
  the spend on the PVM.
- **Released:** tag `v0.4.0`; VOS takes it.
- **Dep:** none (starts at M0). **Estimate:** 4–6 weeks.

### 8.15 The shielded pool
- `Payments`' `spend` and `join` kernels, `pay`, `deposit` (the
  commitment computed by the pool), `withdraw`, `notes_feed`,
  `spent_feed`; the anchor ring.
- **Gate:** PG4 on format 46 at first, on 47 once M2 lands (S8-P5).
- **Dep:** 8.4, 8.14. **Estimate:** 2–3 weeks.

### 8.16 The wallet
- The `Wallet` local actor; scanning both feeds with view tags; the
  facility's `wallet` operations (balance, receive, private pay), its
  chrome confirming the payee and amount as today's `pay` does [decided,
  S48]; the random wait before spending a fresh note; background joins.
- **Dep:** 8.11, 8.15. **Estimate:** 2–3 weeks.

### M3 acceptance
- **Gates:** `ci-full`, PG4, a private payment between two members and a
  paired second device on the clearnet, the carrier audit over the wallet,
  the relay and the pool. Fable.

## M4 — Tor (5–7 weeks, parallel with M3 after 8.1)

### 8.17 The gateway's onion service
- A `tor` feature; the onion's key in the gateway's key directory; ports
  22, 80 and `vos-api` (its relay set adding `Credentialed` and `Call`);
  full vanguards; per-circuit and per-service limits; PoW behind a flag
  until arti stabilizes it; restricted discovery not offered (arti's
  `experimental` group).
- **Dep:** 8.1. **Estimate:** 2 weeks.

### 8.18 The client over arti
- One `TorClient` in the light node; isolation by purpose with a spare
  circuit for proven calls; dormant mode; s4's SSH over a socketpair
  descriptor the facility pumps to the onion stream (`light-node.md`
  §2.2); the onion address pinned at enrollment; the space's `tor`
  policy and its fallbacks in the chrome.
- **Dep:** 8.5, 8.17. **Estimate:** 2–3 weeks.

### 8.19 The path leak and the root fingerprint
- **Carried in:** tree syncing and the `map_root` fingerprint (M4): the
  credential book syncs the credential tree's leaves through a paged feed,
  as the wallet syncs the pool's, so no `path(member)` is fetched and every
  proof names the newest root; the log keeps the root's place in the ring.
- **Dep:** 8.4, 8.11. **Estimate:** 1.5–2 weeks.

### M4 acceptance
- **Gates:** PG3′ over Tor, every flow (S8-P6), which needs M3's P2 and
  pairing; the carrier audit with the onion in the path; `node/SECURITY.md`
  and a light node `SECURITY.md` stating what Tor fixes and what it does
  not. Fable. **Dep:** M3, 8.18, 8.19.

## M5 — Slice end (2–3 weeks)

### 8.20 Documents and the audit's scope
- `proving.md` §8, `identity-and-authority.md` §5–§8, `core-model.md`
  §9.4 and §11, `node-api.md` §6 rewritten to what was built;
  `light-node.md` to draft 3 [built].
- **Carried in:** the external audit's scope, now the device format, the
  Poseidon2 chip, their masking, the stock kernels, cipher-clerk's
  `shielded` module and the spend kernel (the credential AIR out).

### 8.21 The slice gate
- `ci-full` at slice tier (5-minute fuzz, full-N leakage), the checker
  loop, every phone gate on the final build (S8-P7), the slice-end Fable
  review, the code-quality review folded as a behaviour-preserving step.

## The critical path

- **Proving:** 8.2 → 8.3 → 8.4 → (8.7 ∥ 8.8) → 8.9: 10.5–15.5 weeks with
  two implementers on M2, 13.5–20.5 with one.
- **Light node and sync:** 8.5 → 8.11 (with 8.10 beside 8.5) → 8.12 →
  8.13: 13–18 weeks; this is the longest chain.
- **Payments:** 8.14 (from M0) → 8.15 (after 8.4) → 8.16 (after 8.11):
  about 11.5–16 weeks.
- **Tor:** 8.1 → 8.17 → 8.18, then M4's acceptance after M3.

**The slice: about 18–24 weeks** with four streams, 21–29 with three
[est]. P2 and Tor slip first; P1 and format 47 are the floor that ships if
they do (`light-node.md` §8 Q3).

## Carried from slice 7

From `research/slice-7/slice-end-fable.md` ("Carried to the next slice"),
at `6c4b4f49a`:

| item | where |
|---|---|
| the per-program CPU and word-level memory (S63) | 8.7, 8.8, 8.9 (the device format; the node's segment format later) |
| tree syncing (the path leak) and the `map_root` fingerprint (M4) | 8.19 |
| the binding sweep's budget (L6) | 8.4 |
| 7.9's quiet re-measure of `0x402` | 8.9 |
| reproducible path-dependent blobs (S58) | 8.3 |
| the external audit's scope | 8.20, rescoped |
| the heavy cleanup before master | the precondition (7.24a, 7.24b) |
| S55 (the executors' bound on compumax); T1's and T6's p99, T5's throughput (S59's levers 4–6); T2's and T5's host kill | **not in slice 8:** a node-performance track, the owner's to schedule (it needs compumax and more machines, and shares no code with this slice) |
| the per-call identity read; the identity agent replicated per node; the non-repudiation side store | **not in slice 8:** the identity track (`identity-and-authority.md` §15 step 2), unchanged by the light node |

## Open before the steps are pinned

The owner's answers to `light-node.md` §8 Q1–Q12; the second pairing
device (PG3′); the phone sessions' windows.
