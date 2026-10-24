# Review: slice 7 plan, draft 1 (`s7/plan` @ 33b207b3)

Read-only review. Plan = `docs/design/slice-7-mobile.md` (line refs below). Security counts re-derived
by a Python port of `pvm/proof/src/security.rs` (it reproduces format 35's pinned 62.857 and format
37's 62.10 unmasked), in `tmp/s7/calc/sec.py`.

## Verified
- Format 37 under (c) at 86 queries, PoW 20, batching by powers: **61.86** proven bits. 87 queries
  give 62.28; affine batching at 86 gives 62.80.
- `device-params.md`'s table holds for both shapes. Queries needed at PoW 20:
  - blowup 2: 86–87 by powers, 85 affine;
  - blowup 4: 43;
  - blowup 8: 29.
- The mask rows follow `8+3q`, so h is 1,024 at blowup 2 (rows at least 2^12) and 512 at blowup 4
  (2^11).
- Credential format at blowup 4, 43 queries, PoW 20: 62.69 proven, 106 conjectured.
- The M5 projection is correct *as arithmetic*: 2.2 × 0.30–0.40 × 1.7 × 0.8 = 0.90–1.20 s.
- The `simplify.md` code citations I checked match the code: `AnchorRefusal` (8 variants),
  `Anchored` (3), `Status` (4), `UNSETTLED_RECHECK`, `RECUTS`/`CUT_KEEP`/`READ_WINDOWS` in
  `agent/wire`, and `anchor.rs` at 411 lines.

## High

**H1. The M5 projection (lines 682–686) rests on two unsupported factors.**
- **The masking factor 1.7** comes from slice 5's critique (`research/slice-5/critique.md:191`). There
  it is a *memory* factor, design only. The only measured masking cost is the wrap's ×2.6–2.9 in
  time (`proving.md` §5).
- **Lever 1's 0.30–0.40** is not explained by the cited cells. Removing BLAKE2B's 12.2M of 34.1M cells
  leaves 0.64, and the AND table is small. The gain must come from fewer CPU and memory steps, which
  the plan does not show.
- **With 0.64 and a factor of 2.0–2.9,** the auth statement takes about 2.2–3.3 s before levers 2–3.
  The plan states 0.9–1.2 s.
- **Blowup 2's 0.8** assumes 86–87 queries. That likely breaks pin J's 1.5 MiB limit: the kit's floor
  proof was 1.02 MB at 38 queries, and masking adds ×1.31 in bytes.
- **Fix:**
  - add a masked-cost proxy to 7.0a: the floor shape committed at log size + 1, measured on x86 and
    the phone;
  - show lever 1 as a step and cell model;
  - plan levers 5 and/or 6 as *expected*, not contingent. M5 becomes about 16–23 weeks;
  - move Q11 into the first batch of owner questions;
  - in the risk table, rate "1 s missed" as likely.

**H2. The plan reverses standing decisions while saying "Slice 6's decisions 1–18 stand" (line 6).**
Q1(a) reverses:
- decision 7 (the controller rotates keys; equivocation suspends, then resume), by C2 and C4;
- decision 8 (migration ranges and `venue_bound`), by C1 and C7;
- decision 10 (a rootless `Seen` never expires), by C7;
- decision 18 (resume, with the disputed window dead), by C4;
- `proving.md` §7's [decided] equivocation text, and its "`S_w` over every agent's root", by C10;
- `spaces-pallet.md` §13 Q2 and Q12 (the paired key and rotation calls), §6 calls 5 and 6, and
  vectors G5, G14, G15, G19.

**Fix:** list these reversals under "Decisions" and in Q1. Offer the candidates individually, with C4
as its own question (M3).

**H3. The pay statement (pin I, lines 218–225) is redundant under Q10(a).**
- **Nothing in it is needed once the account is public.** The ledger actor debits the live row at
  apply anyway. So the path, the 64-bit range check and the nullifier `P2(TAG_SPEND‖s‖binding)` add
  nothing: exactly-once already comes from the binding set. The range check is self-described as "a
  convenience".
- **The root check is weaker than a live check.** Checking against a root up to 120 s old lets a
  previous owner spend after the row's owner changed.
- **Fix:** pay becomes a proof of knowledge of `s` with `owner = P2(TAG_OWNER‖s)` public, bound to
  `binding`. Ingress or apply compares `owner` with the live row. That removes the path, the range
  gadget and the `Holder` map semantics. A hidden-balance pay statement waits for full privacy (as
  identity §8 already does).
- **Effect:** the Poseidon2 map then serves only the membership set.

**H4. Pin G's roots are kept per node, so the ingress check is nondeterministic, and the second index
is heavy.**
- **Different nodes accept different roots.** Roots are taken "at most once a second at the latest
  version" (line 161). So the set each node keeps differs: a path fetched from node A, proved and sent
  to node B can be refused by B.
- **The index costs a large subsystem:** the builder's second index, a macro attribute, a `Rows`
  kind, slot rows and a kind-1 report.
- **The kind-1 report has no consumer in this slice** (line 165), and it conflicts with C10.
- **Simpler:** the credential actor keeps its Poseidon2 tree in its own committed rows through the
  native `0x402` host call. Enrollment is rare; on JAM the shim's software permutation pays, as
  planned. Its root and a ring of the last K roots are then replicated state: deterministic at every
  node, the same on JAM, with the path served by a query method.
- **What goes:** most of 7.8 (sdk-macros, wire `Rows`, `roots/` builder, the report). The 7.3/7.8
  merge conflict in `node/host/src/roots` goes with it.

## Medium

**M1. The Poseidon2 chip in the node's format 41 (pin H, 7.9) has no consumer this slice.**
- Ingress verifies credentials natively, and JAM agents compute no index. The only user is M5's lever
  1, which Q4(a) puts in the device chips alone.
- **Fix:** admit the chip in the device format only. 7.9 then re-pins slice 6's batch without changing
  the segment AIR. 7.14 no longer waits on 7.9, which leaves the critical path. `SEGMENT_CHIPS` and
  `Shape` stay as they are.
- **Also:** pin H's forgery gates lack *an input word ≥ p (p itself included)*. The live call traps
  there, so the AIR must range-check each word, or live and proved runs diverge.

**M2. The critical path (lines 791–795) chains 7.6 → 7.7 for no technical reason.**
- M4 depends on the re-pin (after 7.3), not on the scale runs.
- **Fix:** start 7.7, 7.8 and 7.10 after 7.0, and gate only 7.9 on 7.3. That saves about 3–5 weeks.
- **Also:** state the real overlaps and conflicts:
  - 7.3 and 7.8 both edit `node/host/src/roots` (moot with H4);
  - 7.14 touches the shared segment prover, so add a gate that format 41 proofs stay byte-identical
    after 7.14.

**M3. C4's costs are understated.** Re-founding changes the `SpaceId`, which strands or resets
everything keyed by it:
- the sovereign account, derived from the `SpaceId` (`spaces-pallet.md` §13 Q3), with its funds and
  deposits;
- the Clerk's pair commitments;
- every member's passkey secret: pin K puts `space` in the PRF input, so everyone re-enrolls;
- issued credentials and nullifiers.

Two more problems:
- **Any one stolen listed key permanently ends the space at its venue.** The honest node's evidence
  does it, so key theft becomes a forced re-founding.
- **A tombstone is needed.** An ended space must stay recorded and never be pruned; otherwise C8's
  nonce-less founder signature can be replayed.

**Fix:** ask C4 separately. Name the sovereign drain and the tombstone. Offer the governance-only
revive as an option. Consider deriving the PRF input from a stable space handle or a per-member salt.

**M4. C1 restricts the Clerk** (`simplify.md` §5 says "no conflict").
- Counterparties must share a venue (`clerk-across-spaces.md` C.5). With no migration, a JAM space and
  a Kreivo space can never settle without re-founding.
- Acceptable, but say it in Q1.

**M5. C10 breaks cross-space credential freshness, and misses its own next step.**
- **Freshness:** identity §7 has a verifier demand the issuer's root within N windows. Under C10 an
  issuing agent reports only when a read waits. **Fix:** an opt-in "report every window" for issuers.
- **The next step (C11, missing):** a window with no reports anchors nothing. Gaps are already legal,
  so this costs nothing. It cuts the anchors that pay a fee, now 144 a day per space, down to the
  windows that are read.

**M6. A device proof (format 43) at ingress authorizes nothing defined** (lines 233, 696).
- Unspecified: how the io-hash maps to scope, nullifier, binding and root, and which origin it
  yields.
- **Fix:** specify this in pin J, or verify device proofs in the bench only this slice.

**M7. Problems in the scale test (7.5, the targets on line 509).**
- **Results that would mislead:**
  - **70% intra-shard transfers** inflate the knee. With K = 64 and random payees, about 98% would
    cross shards. Make the share a parameter, and run it once at a realistic share.
  - **L = 10 min over 30-minute runs gives 3 windows for T4.** Use L = 2 min for the window runs.
  - **The identity agent is not modeled:** identity §6 puts a replica on every node, which at 10^6
    identities is a real cost. List what is not modeled.
- **Targets:**
  - **T3's "64 KiB of RSS per 1,000 replicas"** is 64 B a replica: a typo, presumably 64 MiB.
  - **T1 is a weak bar.** 10^5 active an hour is about 30 calls a second. Derive T1 and T2 from one
    stated per-user rate.
- **Lever:** at 10^4–10^5 agents × 3 replicas, idle Raft heartbeats likely dominate. Name quiescing
  idle groups as the lever.
- **Gold plating:** drop the `scale-venue` feature (anchoring is O(1) a window a space, so measure to
  `close`), TLS on the LAN, and aarch64 node deploys (interpreter-only hosts). That saves about a
  week, and a release-gated feature with its check row.

**M8. The credential request has holes (pin I).**
- **The binding** omits the space and the program id or kind. Add both.
- **The scope** must be namespaced by the verifier, as `H(agent ‖ guard scope)`. Otherwise two agents
  using "login" share one pseudonym.
- **A per-scope rate limit** is effectively one global bucket per method, which an attacker can drain
  for everyone. Limit per connection, plus an executor budget.
- **Expiry at apply** must use batch time, and the binding stays recorded past `expires_ms`.
- **Anonymity:** fetching a path by `key` tells the space *which* member is about to prove, not only
  when (line 170). State that `Anonymous` hides the member from log readers, not from operators.
  That is consistent with identity §8's postponed full privacy, but the plan should say it.

**M9. Proof of work on the phone is an unlisted lever.**
- **The cost:** PoW 20 is 0.028 s on 8 x86 threads (`proving.md` §4). On the phone that is about
  0.1 s on average and about 0.3 s at p95 [est, ARM factor 3.5]: a large share of PG1's 250 ms.
- **The lever:** blowup 4 at PoW 16 needs 47 queries. That keeps 62.09 proven bits on the device
  shape and 62.66 on the credential shape, 110 conjectured, and the same 2^11 floor [model, verified].
- **Fix:** add it to 7.16's candidates and to Q12. Record the p95, not only the median of medians.

**M10. 7.14 (masking the segment chips, 2.5–4 weeks) is optimistic.**
- The scope is 25 chips, 14 that finalize unpaired, 5,177 constraints, and leakage gates 1–7. Masking
  the wrap alone took most of M2.
- **Fix:** 4–6 weeks.

**M11. Q13(a), failing the batch on a corrupt `closes` row, halts the representative.**
- The row is deterministic, so every replica fails the same batch, again and again.
- **Fix:** recommend quarantine plus an alert, or (a) only with the row dropped from the inbox.

## Low

**L1. Q9 (the relying party) and the Android set-up.**
- **Q9 blocks 7.0b at day 1** but is ranked 9th. Move it up.
- **The relying-party subdomain must serve no pages or scripts.** Any page at the relying party can
  ask for the same PRF input and derive `s`.
- **`assetlinks.json`** needs the demo's signing-certificate SHA-256. Commit a demo keystore.
- **`adb reverse` with plain HTTP** needs a `network_security_config` for cleartext to localhost.
- **The `hmac-secret` fallback has two catches:**
  - it must apply `SHA-256("WebAuthn PRF\0"‖input)` itself, or its secret differs from the PRF
    path's;
  - Credential Manager may not pass PRF through to security keys, so it likely needs a CTAP library.
- **PRF support for native apps** through Google Password Manager is not documented officially; reports
  are browser-side. 7.0b's probe is right to gate on it.

**L2. Pin K overstates how contained `s` is.**
- "s never leaves the library": the PRF output, which is equivalent to `s`, arrives as base64 in a
  Java String through Credential Manager. It cannot be zeroized.
- The passkey syncs through Google Password Manager, so `s` is bound to the account, not the device.
- Put both in `SECURITY.md`. Also, the client, not the authenticator, applies the PRF prefix.

**L3. C5's `Never` for an unlisted key should hand off leadership, not settle the window.** Under C3, a
listed replica can still anchor it.

**L4. "One re-pin" means two drops for the teammate:** the vectors at 7.1, then the kit's blobs at 7.9.
Say so. Item 68 sits in both 7.3 and 7.9.

**L5. The phone gates mix two builds.** Byte-identity needs `seeded-masks`, but timings must come from
the production build. Name both builds.

**L6. Pin G wording.**
- "Indexed Merkle tree" is a misnomer: it is a positional sparse tree.
- `P(value)` must be specified as injective for an 8-M31 digest.

## Candidates C1–C10

| | estimate | safety | breaks or conflicts | verdict |
|---|---|---|---|---|
| C1 | credible | right | decision 8; `proving.md` §7; the Clerk restricted (M4); the pallet's calls 5, 24, 28 and G14 | take, with M4 stated |
| C2 | credible | neutral; replacing a node moves all its replicas | decision 7, 6.14b, the pallet's Q12 | take |
| C3 | credible | better | — | take |
| C4 | credible | its costs understated (M3) | decisions 7 and 18; `proving.md` §7 [decided]; G5 and G19 | owner's separate call |
| C5 | credible | neutral; see L3 | — | take |
| C6 | credible, highest value | better | the pallet's §6.1 | take first |
| C7 | credible | neutral | decisions 8 and 10. Anonymous authorities (pallet §11) are not `judge` statements, so no conflict | take |
| C8 | credible | needs M3's tombstone | — | take |
| C9 | credible | liveness only | the agent image (refine), in the re-pin | take |
| C10 | credible | breaks issuer freshness | pin G's kind-1 report; `proving.md` §7's `S_w` | take, with the opt-in |

**Missing simplifications:**
- C11: a window with no reports anchors nothing (M5);
- the Poseidon2 tree in the credential actor's own rows (H4);
- the Poseidon2 chip in the device format only (M1);
- pay as a proof of `owner`'s preimage (H3);
- the scale harness trimmed (M7).

## Open questions

- **Re-rank:** Q9 and Q5 to the top with Q1; Q11 forward (H1).
- **Q1:** per candidate, with the reversals listed (H2) and C4 apart (M3).
- **Q12:** add PoW 16 with 47 queries (M9).
- **Q13:** (b), or a quarantine (M11).
- **Missing questions:**
  - the pay statement's shape under Q10(a) (H3);
  - the chip in the node format or the device format only (M1; draft 1 lists it as settled by the
    evidence);
  - the PRF input's stability across re-founding (M3);
  - what a device proof authorizes at ingress (M6);
  - C10's issuer opt-in, and C11 (M5).

## Verdict

**Not ready for the owner's questions as is.**
- **M3.9** is sound once H2, M3, M4, M5 and M7 are written in: document fixes.
- **M4 and M5 need a targeted draft 2:** pins G, H and I (H3, H4, M1, M6, M8), the M5 projection and
  its estimates (H1, M10), and the critical path (M2).
- **No full redraft is needed.** After draft 2, it is ready for the owner's questions.
