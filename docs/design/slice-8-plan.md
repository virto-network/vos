# Slice 8: the light node and the personal agent — plan

Draft 4 [proposed]. The design is `light-node.md` (draft 4); this file
orders it into milestones, steps, gates and estimates, and places what
slice 7 carried.

- **Status:** [proposed] throughout. The steps take the owner's decisions
  E1–E11 (`light-node.md` §1.1), draft 2's Q5–Q12 at their
  recommendations, provisionally (§9.2), and the recommended answers to
  N1–N7 (§9.1); a different answer changes the steps it names. With N1
  (c), P2 is built in slice 8 on its own stream; with N1 (a), steps
  8.29–8.30 and PG4 move to slice 9 and nothing else changes.
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
- **One heavy run at a time:** proving gates (leakage, `ci-full`, phone
  sessions) and the scale run (8.15) are scheduled one after another on
  the machines, never together; two implementers coding in M2 share the
  queue, not the machine.
- **Estimates** are one implementer's weeks, before review, unless a line
  says otherwise. The critical path is re-derived with reviews at the end.

**Streams:**

| stream | steps |
|---|---|
| A, proving | 8.2, 8.4, 8.5, 8.8, 8.10 |
| B, second proving | 8.3, 8.7, 8.9 |
| C, the light node (the critical path) | 8.6, 8.18, 8.19, 8.20, 8.23 |
| D, the node side | 8.11–8.16, then 8.21 |
| E, transport and Android | 8.1, 8.17, 8.22, 8.24, 8.25–8.27 |
| F, cipher-clerk and P2 | 8.28–8.30 (N1 (c)) |

## Phone gates, restated for one proving path

PG1 (the credential AIR's 250 ms) retires with format 44. Every gate is on
the Fairphone 6 [decided, `proving.md` §8], automatic threads, three rounds
of five, the gate the median of the rounds' medians, the 95th percentile
beside it, each proof verified on the phone and accepted at a space's
ingress. Every gate has a limit it can miss.

| gate | what | limit | when |
|---|---|---|---|
| **PG1′ owner** | the stock `owner` kernel, SDK form | ≤ 0.5 s, ≤ 512 MiB | M1 (format 46), M2 (47) |
| **PG2′ sign-in** | the stock `auth` kernel, SDK form | ≤ 1.0 s at format 46; **≤ 0.55 s** at format 47; ≤ 1 GiB; the proof ≤ 1.5 MiB | M1, M2, slice end |
| **PG3′ flows** | enroll, sign-in and pay (P1); claim with a kit; pair a second device; sync both ways; a removal let through, and one contested and resolved by the kit; restore from the kit on a fresh install; move home (two spaces); every secret behind its prompt; recorded (a capture, the gateway's and node's logs) | each flow completes; over Tor, at the median: a sign-in ≤ 4 s, a P1 payment ≤ 5 s, pairing ≤ 60 s from the scan to the second device's first read | M1 (the P1 flows, clearnet), M4 (the personal-space flows on the clearnet, two local spaces), M5 (over Tor, but moving home), slice end |
| **PG4 spend** (N1 (c)) | the pool's `spend` kernel (1 in, 2 out) | ≤ 1.5 s at format 46, ≤ 1.0 s at 47; ≤ 1 GiB; the proof ≤ 1.5 MiB; a private payment over Tor ≤ 6 s | 8.30, slice end |
| **PG5 footprint** | the light node with arti and mls-rs | `.so` growth ≤ 12 MB; idle ≤ 96 MiB; warm bootstrap ≤ 3 s p50; a day of the background job ≤ 2% of the battery; rendezvous an hour in the foreground ≤ 30 after 8.27 | M0 (first numbers), slice end |
| **PG6 sync** | the background job on a locked phone; a catch-up of 1 MiB of envelopes; a commit's processing and confirmation | the job ≤ 30 s and ≤ 1 MB down with nothing new, p50, on a locked phone; the 1 MiB catch-up over Tor ≤ 20 s p50; a commit processed ≤ 200 ms | M4 (clearnet), M5 and slice end (Tor) |

**The second device** for pairing is the owner's to name (another phone,
or an emulator for the second side; the restore needs a fresh install,
which the Fairphone itself can be).

**Phone sessions** (each asked a week ahead): S8-P1 at M0 (arti, mls-rs,
the keystore's after-first-unlock keys); S8-P2 at M1's end; S8-P3 at M2's
exit and S8-P4 a day later; S8-P5 at M4's end (two devices); S8-P6 at M5's
end (over Tor); S8-P7 at the slice end. PG4 joins the session nearest
8.30's end.

## M0 — Measure first (2–3 weeks)

### 8.1 arti on the phone and at a gateway (spike) — stream E
- arti-client (`default-features = false`; `tokio`, `rustls`,
  `compression`, `onion-service-client`) in the facility's build; a
  throwaway gateway hosting an onion service in process with an echo port
  and a `vos-api` port.
- **Measure:** the `.so`'s growth, idle memory, cold and warm bootstrap,
  onion connection (p50, p95), a 1 MB upload, a `Time` round trip, 16
  pipelined queries on one channel; on x86 too.
- **Gate:** PG5's first numbers within twice their limits, or a recorded
  reason and a re-plan of M5. **Phone:** S8-P1. **Estimate:** 1–1.5
  weeks.

### 8.2 SDK-form kernels, measured — stream A
- `vos_sdk::p2`; in-place device arguments by the macro; the guest
  target's `unaligned-scalar-mem` checked through the transpiler on a
  branch (it lands with 8.10's re-pin).
- `auth` and `owner` in SDK form; steps against the hand-lean 1,722.
- **Gate:** the SDK-form auth ≤ 1.15× the lean kernel's steps, or the
  fallback (`light-node.md` §9.2, Q7). **Estimate:** 1.5–2 weeks.

### 8.3 mls-rs and the keystore on the phone (spike) — stream B
- mls-rs (ciphersuite 1; the `messaging` branch's storage providers
  adapted to fjall) in the facility's build: a group of three, create,
  add, remove, update, the exporter; whether a maintained hybrid
  post-quantum suite exists and what it costs (N6).
- An after-first-unlock keystore key used by a WorkManager job on a locked
  Fairphone; a strong-biometric key refusing the PIN.
- **Gate:** a commit processed ≤ 200 ms and the `.so` growth ≤ 2 MB, or
  N7's simpler scheme taken instead; the locked-phone job works, or PG6's
  locked-phone limit is dropped and stated. **Phone:** S8-P1.
  **Estimate:** 1–1.5 weeks.

## M1 — One ingress path, the light node's core, P1 (6–8 weeks)

### 8.4 Device programs for every kernel — stream A
- `#[attestable(device, reference = …, headroom = …)]`; the install
  computes each device kernel's program; the testkit's `device_fits`; the
  light node's own computation of the stock kernels' programs, compared
  with the space's before a secret enters a proof (`light-node.md` §4.4).
- **Carried in:** reproducible path-dependent blobs.
- **Gate:** a kernel whose program differs from the light node's is
  refused before proving, in a test. **Dep:** 8.2. **Estimate:** 1.5–2
  weeks.

### 8.5 Proven calls, format 44 deleted, the pre-check — stream A
- `#[msg(proven = k)]`; `Credentialed.claim`; `CredentialedInput` carrying
  the claim (≤ 1 KiB); `Principal::Kernel` (index 7); the stock kernels'
  checks kept in the node's Rust; an actor kernel's checks at apply only;
  `auth` and `owner` as stock kernels in `vos-credentials`.
- Format 44 and the credential AIR deleted (E1).
- **The pre-check:** the verifier's first milliseconds profiled (decode,
  canonical re-encoding, setup) and a junk proof refused well under 1 ms.
- **Carried in:** the binding sweep's budget.
- **Gate:** a junk device proof refused in ≤ 1 ms at the 95th percentile
  on one x86 core; the carrier audit over proven calls. **Dep:** 8.4.
  **Estimate:** 2.5–3.5 weeks.

### 8.6 The light node's core — stream C
- `vos-light`: the PVM interpreter and machine pool; the agent program's
  merge and query entries over fjall, one batch per operation; no log, no
  refine or accumulate (`light-node.md` §2.1). The executor's host-call
  layer moves out of `vos-node` into a crate both link; `vos-device`'s
  modules placed and the crate deleted; s4's facility repointed.
- `vos-pvm-recair`'s `recursion` feature (Q9); the `.so` size before and
  after.
- **Gate:** a local actor installed and called on the phone build; a
  process killed mid-operation leaves the store consistent (a fault-
  injection test). **Dep:** none. **Estimate:** 2–3 weeks.

### 8.7 Payments P1 on cipher-clerk — stream B
- `Payments` (the L0 kernel, accounts by owner digest, one a device;
  `transfer` under `credential = Owner`), replacing `purses`; s4's demo
  `pay` on it.
- **Dep:** 8.5. **Estimate:** 1.5–2 weeks.

### M1 acceptance
- `ci-full`, the checker loop, PG1′ and PG2′ on format 46, PG3′'s P1 flows
  on the clearnet (S8-P2). Fable.

## M2 — The levers in the device format (5.5–8 weeks with two implementers; parallel)

### 8.8 A per-program CPU — stream A
- The CPU's columns from the program's opcodes, device format only.
- **Dep:** M1. **Estimate:** 3–5 weeks.

### 8.9 Word-level memory — stream B
- The device memory ledger by words.
- **Dep:** M1. **Estimate:** 4–6 weeks.

### 8.10 Format 47, one re-pin — stream A
- 8.8 and 8.9 as one device format; `unaligned-scalar-mem` with it; every
  guest ELF, blob and program id moves once; the light node's update
  prompt.
- **Carried in:** the quiet re-measure of `0x402`.
- **Gate:** PG1′ and PG2′ on 47 twice, a day apart (S8-P3, S8-P4).
  Fable. **Dep:** 8.8, 8.9. **Estimate:** 1.5–2 weeks.

## M3 — The personal agent in the space (stream D, 10.5–14.5 weeks from M0)

### 8.11 Forwarding and admission by known keys
- A peer message carrying a request as received; the hop rule; its own
  peer stream; operator kinds never forwarded; forwards counted against
  the sender's budget (`light-node.md` §3.3).
- An agent's admitted-keys rows read at ingress, refusing a
  session-creating call from an unknown key before any commit.
- **Gate:** every client kind through a gateway whose upstreams hold no
  replica; a forwarding burst during an election leaves leadership
  unchanged; an unknown key's 10^4 session attempts write nothing.
  **Estimate:** 2–2.5 weeks.

### 8.12 `Homes` and the keeper
- `Homes` beside the credential actor: `stock`, `claim` under
  `Auth("home")`, the nullifier and kit-key indexes, `PoolEmpty`, the
  `assigned`/`refused` reply; the "home" scope reserved in the facility.
- The keeper (`tools/`): create, install, `Grant` the role, stock, reap,
  bulk upgrade of `Personal`.
- **Gate:** a pool of 200 made and claimed; a double claim refused; a
  refused assignment released. **Estimate:** 1.5–2 weeks.

### 8.13 `Personal`: the device set
- States, admin classes, operations signed end to end and stored with
  their signatures; delays on batch time; vetoes, contests and their
  resolution; immediate removal by two; the recovery entry and its 7-day
  operations; kit rotation; `R1`/`R2` and their release to a matured
  restore.
- **Gate:** property tests against an adversary holding one active device
  and its biometric (`light-node.md` §8, A4): the owner with one device
  and the kit, or two other devices, always removes it within the delay;
  it never removes an owner device the owner contests; a leaked kit alone
  completes nothing an active device cancels. **Estimate:** 2–3 weeks.

### 8.14 `Personal`: commits, envelopes and the inbox
- The commit log (candidates, `EpochTaken`/`EpochGap`, declared effects
  against matured operations) and signed confirmations, voided at 72 h;
  sealed scopes (`push` with dedup then `StaleEpoch`, positions, `since`),
  checkpoint acknowledgements, recovery envelopes' scope; quotas and their
  exemptions and per-device shares; the inbox with lazy expiry; activity
  and `reap`; the tenancy number.
- **Gate:** the scenarios of `light-node.md` §8 that name 8.14 as tests.
  **Estimate:** 2–3 weeks.

### 8.15 The scale gate
- 10^4 personal agents on a three-node space, each pushing and fetching
  every 15 minutes for an hour with sessions opening and sweeping, among
  them pushes of full 256 KiB steps; one agent filled to its 64 MiB quota,
  its snapshot installed, and one `replace`.
- **Gate:** the space's other agents' commit p99 within 20% of the same
  run without personal agents; resident memory ≤ 64 KiB a personal-agent
  replica above the idle figure; a full agent's snapshot installed ≤ 30 s;
  the `replace` within its run's time recorded. Scheduled alone (one heavy
  run at a time). **Estimate:** 1–1.5 weeks.

### 8.16 Device memberships
- The registrar's person records (member and owner digests per device,
  counts, a limit), `enroll_device` under `credential = Owner`,
  `revoke_device`; a second credential ring of person leaves; guards
  naming their ring, and ingress and apply reading it
  (`node/host/src/credentialed.rs`'s single ring generalized).
- **Gate:** a member with three devices votes once in a `once` scope and
  signs in from each device elsewhere. **Dep:** 8.5. **Estimate:** 2–2.5
  weeks.

### M3 acceptance
- `ci-full`, 8.15's gate, 8.13's property tests, the carrier audit over
  `Personal`'s logs. Fable.

## M4 — The personal space on devices (stream C, with D and E)

### 8.17 merkle-crdt for devices — stream E
- The incremental apply; the author, sequence and signature in the
  payload; a `Store` over fjall; batched fetching; the `redb` store
  deleted.
- **Dep:** none. **Estimate:** 2–3 weeks.

### 8.18 Local actors and the CRDT types — stream C
- `crdt::{GSet, Set, Map}` stored per author, read filtered (§3.2);
  `#[msg(merge)]` and merge dispatch; versioned operations, unknown ones
  held; validation and quarantine; the credential book and the device
  book; `core-model.md` §9.4 amended (plaintext and sealed scopes).
- **Dep:** 8.6, 8.17. **Estimate:** 4–6 weeks.

### 8.19 The device group — stream C
- mls-rs (or N7's scheme) in `vos-light`; candidates processed, the prior
  state kept; the allow-list; signed confirmations, void on a `nack`, a
  mismatch or 72 h; exporter keys, scope ids from the naming secret, the
  key archive.
- **Gate:** a committer that encrypts garbage to one device never gets
  data sealed to the other side (a test with three devices); every
  disallowed proposal is nacked. **Dep:** 8.3, 8.14, 8.18. **Estimate:**
  3–4 weeks.

### 8.20 Sealed sync — stream C
- Envelopes (Padmé, opaque scope ids, the writer's view inside),
  seal-at-push, the push queue's sealed bytes, the cursor; archives pushed
  at confirmed epochs; recovery envelopes under `R`; the device's quota
  share; Tor-only traffic.
- **Gate:** PG6's catch-up on the clearnet. **Dep:** 8.19. **Estimate:**
  2.5–3.5 weeks.

### 8.21 Checkpoints and detection — stream D
- Checkpoints at agent positions and their acknowledgements; a new
  device's acceptance rule; control-log views, rollback and equivocation
  alarms; the sample audit of one's own pushes.
- **Gate:** a model test of two devices and a hostile agent (a rollback,
  equivocation on commits and on operations, a dropped veto, a forged
  operation, a stale-epoch push, a backdated envelope, a wrong
  checkpoint): each detected or refused as `light-node.md` §8 says.
  **Dep:** 8.20. **Estimate:** 2–3 weeks.

### 8.22 The background job — stream E
- WorkManager, a random minute of its window, on the after-first-unlock
  keys; local notifications for pending operations; the job's state
  consistent if killed.
- **Gate:** PG6's job limits on a locked phone. **Dep:** 8.6, 8.20.
  **Estimate:** 1–1.5 weeks.

### 8.23 Pairing, claim, kit, restore and contests — stream C
- Pairing through an inbox slot (QR, Noise `XXpsk3`), the archive and `R`
  over the channel; the claim with its kit; removal, veto, contest and
  resolution flows; delayed admins; restore here and elsewhere; kit
  rotation; a new admin key after a biometric change; moving home after a
  lost one; `enroll_device` at the next sign-in.
- **Gate:** PG3′'s personal-space flows with two devices on the clearnet,
  two local spaces for the move (S8-P5). **Dep:** 8.13, 8.16, 8.20.
  **Estimate:** 3–4 weeks.

### 8.24 s4's screens — stream E
- Kotlin screens in s4's client: claim and kit, pairing (show and scan a
  QR), devices (list, remove, veto, resolve, contests, kit rotation),
  restore, move home, the wallet (N1 (c)), the prompts (strong biometric
  for the admin key), local notifications.
- **Gate:** each screen drives its flow on the phone. **Dep:** the
  facility operations of 8.23 (developed against their stubs first).
  **Estimate:** 3–4 weeks.

### M4 acceptance
- `ci-full`, PG3′'s personal-space flows and PG6 on the clearnet (S8-P5),
  8.21's model test, the carrier audit over the light node's and the
  agent's logs. Fable.

## M5 — Tor (stream E)

### 8.25 The gateway's onion service
- A `tor` feature; the onion's key; ports 22, 80 and `vos-api` (`Call`,
  and `Credentialed` once 8.5's pre-check gate is met); full vanguards;
  per-circuit, per-agent and per-service limits; PoW behind a flag; the
  onion set served by the registrar; the C tor sidecar documented and run
  once.
- **Dep:** 8.1, 8.5. **Estimate:** 2 weeks.

### 8.26 The client over arti
- One `TorClient`; isolation by purpose and identity; a spare circuit for
  proven calls; dormant mode; s4's SSH over a socketpair descriptor; the
  pinned onion set and its refresh; the space's `tor` policy, the
  personal agent's traffic Tor-only.
- **Dep:** 8.6, 8.25. **Estimate:** 2–3 weeks.

### 8.27 The credential tree's feed
- **Carried in:** tree syncing and the `map_root` fingerprint: the device
  keeps each space's tree from a paged feed on one long-lived circuit, no
  path fetched, every proof against the newest root, the log keeping the
  root's place in the ring.
- **Dep:** 8.5, 8.18. **Estimate:** 1.5–2 weeks.

### M5 acceptance
- PG3′ and PG6 over Tor (S8-P6); PG5's rendezvous limit; the carrier audit
  with the onion in the path; `node/SECURITY.md` and the light node's
  `SECURITY.md` (what Tor fixes and does not; the personal agent's threat
  model, `light-node.md` §8's known limits). Fable. **Dep:** M4, 8.26,
  8.27.

## Alongside — cipher-clerk and P2 (stream F)

### 8.28 cipher-clerk v0.4 (in cipher-clerk's repository)
- A design note reviewed before code, then R1–R11 (`light-node.md`
  §5.3); the fit check extended to the spend on the PVM, its steps
  counted against §5.7.
- **Released:** tag `v0.4.0`. **Dep:** none. **Estimate:** 4–6 weeks.

### 8.29 The pool (N1 (c))
- `Payments`' `spend` and `join` kernels, `pay`, `deposit`, `withdraw`,
  the feeds, the anchor ring; VOS on cipher-clerk v0.4; the light node
  computing the spend program from its own build.
- **Dep:** 8.5, 8.28. **Estimate:** 2–3 weeks.

### 8.30 The device-local wallet and PG4 (N1 (c))
- The `Wallet` local actor, its scope kept on the device; scanning with
  view tags; the facility's `wallet` operations; `sk` sealed under `R`
  (N4 (a)) once a kit exists, and the wallet asking for one before
  receiving; the random wait before spending a fresh note; background
  joins.
- **Gate:** PG4 (the nearest phone session; over Tor once M5 lands).
  **Dep:** 8.18, 8.29. **Estimate:** 2–2.5 weeks.

## M6 — Slice end (2.5–3 weeks)

### 8.31 Documents and the audit's scope
- `proving.md` §8, `identity-and-authority.md` §5–§8, `core-model.md`
  §9.4, §10 and §11, `node-api.md` §3 and §6 rewritten to what was built;
  `light-node.md` to [built]; `open.md` takes `light-node.md` §9.4's list;
  the light node's `SECURITY.md`.
- **Carried in:** the external audit's scope: the device format, the
  Poseidon2 chip, their masking, the stock kernels, the personal agent's
  protocol, cipher-clerk's `shielded` and the spend kernel.

### 8.32 The slice gate
- `ci-full` at slice tier, the checker loop, every phone gate on the final
  build (S8-P7), the slice-end Fable review, the code-quality review
  folded as a behaviour-preserving step.

## The critical path

- **Stream C:** 8.6 (2–3) → 8.18 (4–6) → 8.19 (3–4) → 8.20 (2.5–3.5) →
  8.23 (3–4) = 14.5–20.5 weeks. 8.18 waits on 8.17 (E, ready by week 3–4.5)
  and 8.19 on 8.14 (D, ready by week 7.5–10.5), which can cost up to about
  1.5 weeks: **16–22 weeks.**
- Then M4's acceptance (about 1–1.5), M5's over Tor (about 1, Tor ready
  well before on stream E), M6 (2.5–3): **20.5–28 implementer weeks.**
- **Reviews:** a step's Opus review and its folds on the chain (six steps,
  about 0.3–0.5 week each) and four Fable rounds on the chain (M3's
  through M6's, about 0.5–1 week of fixes each): about 4–6 weeks.
- **The slice: about 25–34 weeks** with six streams (five with N1 (a); the
  path is the same). Off the path: proving 10–14.5 weeks (A), 6.5–9.5 (B),
  the node side 12.5–17.5 including 8.21 (D), transport and Android
  12.5–17 (E), cipher-clerk and P2 8–11.5 (F).
- **If it slips,** what ships first: M1 and M2 (one proving path, P1,
  format 47); then the personal space on the clearnet (M3, M4); then Tor;
  P2 on its own stream moves to slice 9 without holding anything back.

## Carried from slice 7

From slice 7's end review, now in `open.md`:

| item | where |
|---|---|
| the per-program CPU and word-level memory | 8.8, 8.9, 8.10 (the device format; the node's segment format later) |
| tree syncing (the path leak) and the `map_root` fingerprint | 8.27 |
| the binding sweep's budget | 8.5 |
| the quiet re-measure of `0x402` | 8.10 |
| reproducible path-dependent blobs | 8.4 |
| the external audit's scope | 8.31, rescoped |
| the cleanup before master | the precondition |
| the executors' verification gate on a many-core host; T1's and T6's p99, T5's throughput; T2 and a host's kill | **not in slice 8:** a node-performance track, the owner's to schedule; 8.15 is the only scale run here |
| the per-call identity read; the identity agent replicated per node; the non-repudiation side store | **not in slice 8:** the identity track (`open.md`, "Identity and privacy") |

## Open before the steps are pinned

The owner's answers to `light-node.md` §9.1 (N1–N7), and any change to
§9.2's provisional answers; the second device; the phone sessions'
windows.
