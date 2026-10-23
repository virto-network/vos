# Slice 6: progress

The log of build step 6, against `slice-6-on-chain.md`. Every number is
tagged [measured], [model] or [est]; the research behind the plan is
`research/slice-6/`.

## Step 6.0: the remaining feasibility spikes, and the docs

Throwaway code on local branches, each spike with its gate and fallback
(`slice-6-on-chain.md`, 6.0). The spikes' logs land here as they finish.

### 6.0a: the in-kernel prologue, measured before the keyspace changes

**Built** on `spike/s6-prologue` (`9c284405`, from `27967322`; local, not
pushed, throwaway):
- **`agent/test-actors/prologue`:** attestable methods that run a
  prototype prologue on a hand-assembled `Served`: the rows' `BatchProof`
  against `agent_root` by `verify_encoded`, each row key required to start
  `0x03 ‖ instance`; the space path `RepKey(agent, 0, w) → agent_root`
  against `rep_root`; `S_w`; `public_args`; the io-hash with one
  `RootRead`. The kernel returns `SCALE(KernelReturn)`, capped at
  `Limits::attest`. Three kernels: `holds` (one row, a balance),
  `window` (16 rows, summed) and `probe` (each part switched on or off, to
  cost them by difference);
- **the SDK (spike only):** `runtime::{Root, Rooted, attested_rooted}`,
  and `#[messages]` routing a method that returns `Rooted` to it, so the
  halt's φ9..12 is the io-hash over the three parts, as pin E has it;
- **the fixture:** the agent's map at 1,000,000 rows under R4's full key
  (the +10 B a leaf counted), cipher-clerk accounts as values; the
  representative's tree at 1,024 agents × windows w−2..w (3,072 rows,
  escaped `RepKey`s, seed-derived salts), w = 2,966,000, agent 517;
- **tests** (`pvm/proof/tests/kernel/prologue.rs`): `the_prologue_measures`,
  `the_prologue_refuses` and `the_prologue_proves`, all passing
  [measured].

**Measured** (format 35 segments) [measured]:

| run | steps | compressions | witness input |
|---|---|---|---|
| `holds` (1 row, full prologue) | 33,302 | 40 | 1,710 B |
| `window` (16 rows, full prologue) | 205,841 | 326 | 14,331 B |
| probe 1 row: none / rows / rows+path | 9,488 / 23,559 / 32,755 | 2 / 26 / 40 | 1,704 B |
| probe 16 rows: none / rows / rows+path | 39,821 / 197,011 / 206,223 | 2 / 312 / 326 | 14,333 B |

- **the path** at 1,024 agents: 9,196 steps and **14 compressions** (12
  branches, the leaf and its `vh`), `S_w` one more; `space_path` **506 B**,
  **590 B** with the leaf's salt and the two roots;
- **a row** ((`window` − `holds`) / 15): **19.07 compressions**, **842 B**,
  11,503 steps (about 9,540 the multiproof's, 2,020 the decode and the
  body); the first row pays the multiproof's shared top (24 compressions,
  14,071 steps);
- **the baseline** (decode, `S_w`, `public_args`, the io-hash): 9,488
  steps, 2 compressions;
- **proving** (a shared machine, so the times are noisy): `holds` 2
  segments in 16.3 s, peak heap 4,791 MiB; `window` 11 segments (9 of
  class 1, 2 of class 0) in 182 s, 4,791 / 2,548 MiB. The chain verifies
  against the program with the io-hash recomputed from the split return.
  The recursion was not run (optional);
- **refusals:** the kernel traps on a row's value flipped, the rows' proof
  tampered, the space path tampered, `rep_root` changed and the leaf's
  salt changed.

**Against the estimates** (`design-roots` §5.5): the path was about 13
compressions and 0.45 KB [est], 14 and 506 B measured, since the
representative keeps three windows an agent (+1.6 levels) and the escaped
`RepKey` is 33 B; a row about 20 and 812 B [est], 19.07 and 842 B with
R4's 10 B. **Scaling of the path** [est]: +1 compression, +36 B and about
650 steps a doubling of agents: about 17–18 and 0.7 KB at 10k agents,
about 24 (+1) and 0.95 KB at 1M, still within the gate.

**Gates:**

| gate | bound | measured | verdict |
|---|---|---|---|
| the path at 1,024 agents | ≤ 30 compressions, ≤ 1 KiB | 14 (+1 for `S_w`), 506 B (590 B with salt and roots) | pass |
| a row | ≤ 25 compressions, ≤ 1 KiB | 19.07, 842 B | pass |
| the 16-row kernel | ≤ 1M steps | 205,841 (asserted) | pass |

No fallback: `verify_encoded` spends about 500–650 steps a compression on
byte handling, a 6.13 lever if the 1M-step target tightens, not a blocker.

**The transport: inline** [read]. No host call lets a step's refine read
a blob by hash: the actor ops have none (`agent/wire/src/abi.rs`); the
agent's `historical_lookup` is answered by `AgentPrograms` for pinned or
installing programs only (`node/host/src/pvm.rs`), the testkit alike; no
batch `Input` names a blob; slice 4's 4.4a `LargeResult` carries refine's
output, never its input. A blob path needs a `Resume { served: BlobRef }`,
`AgentPrograms` answering the hashes a batch names, a lookup into the
kernel's input, and on JAM a solicit, a provide and availability.

**The decisions it settles:**
- **`Limits::served` = 128 KiB on VOS,** the `Served` inline in the
  `Resume` input under that cap and not `REQUEST`; `witness_input` = the
  arguments ‖ `SCALE(Served)`, held inline in the `Attest` record. 128 KiB
  holds about 155 rows, about 2,970 compressions and 1.8M steps [est, from
  the measured costs], under JAM's 4,096-compression kernel cap; at a
  1M-step window target a kernel reads about 84 rows (71 KB) [est];
- **an at-cut attest counts 2 against `Limits::attests`** (the review's
  correction of the log's "`ATTESTS` 8 for `attest_at_cut`"): `cap.rs`'s
  attest term `16 × (REQUEST + REPLY + 40)` = 2,097,792 then bounds it,
  since 8 × (64 Ki + 128 Ki + 64 Ki + 40) = 2,097,472 [arithmetic];
- **JAM's `Limits::served`** is its own, 32 KiB [proposed; 6.13 sets it],
  inside CE 133's package bound (6.0b).

**Findings for the plan** (pin E, applied in `e50bb030`): `Served` and
`Closed` carry the representative leaf's salt (`rep_salt`, seed-derived;
a zero salt would break "JAM's tree hashes `0x03` leaves the same way");
the prologue checks each row key's `0x03 ‖ instance` prefix; witness
decoding hits a class's page budget (8 pages at class 1) before its step
budget, so the 16-row kernel takes 11 segments for 206k steps (the first
four class-1 segments hold 10–19k steps each): a larger-page class for
`&self` kernels or decode in place, measured with 6.18.

### 6.0b: the JAM venue's program and PolkaJam

**Built** on `spike/s6-jam` (`c4095bf2`, from `spike/s6-mask`
`5227bf6c`; local, not pushed, throwaway): a `masked-only` feature in
`vos-pvm-final-verifier` (`masked::verify_any` dispatches 39 alone) and
`vos-statement` (`Admitted::verify` through it, so neither 28 nor 40
links); a `jam-service` feature (PolkaJam probe only: the proof in the
work item's payload, fetched whole into the heap, and an `accumulate`
that stores each refine output); `pvm/proof/statement/tests/spike_jam.rs`,
each ELF linked by `link_elf_spi` and run on the JAM-only host on spike
6a's 162,762 B format-39 proof. Release profile (fat LTO, one codegen
unit), nightly-2025-07-14.

**The masked-only program** [measured]:

| build | ELF B | program B | vs 524,288 | total gas | decode | verify |
|---|---|---|---|---|---|---|
| 28, 39, 40, opt 3 (spike 6a's) | 869,592 | 538,683 | 14,395 over | 118,751,802 | 20,292,196 | 98,374,425 |
| **39 alone, opt 3** | 807,816 | **500,205** | **24,083 under** | **118,745,936** | 20,292,196 | 98,368,559 |
| 39 alone, opt `s` | 587,232 | 275,227 | 249,061 under | 165,760,063 | 27,337,533 | 138,336,891 |
| 39 alone, opt `z` | 671,008 | 238,422 | 285,866 under | 307,606,241 | 62,418,479 | 245,063,442 |
| 39 alone + `jam-service`, opt 3 | 812,824 | 502,454 | 21,834 under | 118,740,340 | 20,292,185 | 98,362,949 |

- every run accepted; heap peak 370 KiB, high water 982 KiB;
- dropping 28 and 40 saves 38,478 B (−7.1%) and no gas;
- `s` costs +39.6% gas (over 6.19's 150M gate) and `z` ×2.59 for bytes no
  cap needs: **opt 3 stays the venue's build**;
- stripping does not apply: the ELF's extra bytes are its symbols and the
  relocations `link_elf_spi` reads; stripped copies link to larger
  programs (+2.2–2.4 KB), and the stripped `z` build does not run.

**Gate (informative): passes** at opt 3, 500,205 B under 512 KiB. The
review: this does not make an actor-hosted venue possible, since 118.7M
gas breaks `MAX_HANDLER_GAS` (100M) whatever the bytes, and 6.19's
service (ed25519, the items, accumulate) will likely pass 512 KiB; moot
under the 4,000,000 B service cap.

**PolkaJam v0.8.0** [measured]: `paritytech/polkajam-releases` `v0.8.0`
(2026-10-16), `polkajam-v0.8.0-linux-x86_64.tgz`, sha256
`e90c8ccd07d392c91a12da6db59bfb916f2c0158928c97468a51461f9ecfdfeb`,
under `~/.cache/vos/polkajam/v0.8.0/` (nothing in the repository fetches
it). `polkajam` and `jamt` 0.1.29, GP 0.8.0; `jamt` and the testnet binary
byte-identical to `nightly-2026-10-13`, only `polkajam` differs. On the
interpreter (the recompiler still waits for owner action A2):
- **`just jam-testnet` runs the agent:** its two actors installed, the
  workflow across three later packages (70 pages exported, 104 imported),
  all 8 packages landed at their first attempt, each work result read back
  from DA equal to the simulation's and the VOS node's, the chain's root
  the builder's, no testnet error; refines 0.24M–39.1M gas (JAM-only
  host). **No fallback version is needed;**
- **one statement's refine,** the masked-only service (opt 3, program
  502,454 B) deployed on the testnet, one 174,080 B work item carrying the
  proof, accumulate storing the verdict, read back:

| | PolkaJam v0.8.0 | JAM-only host | Δ |
|---|---|---|---|
| verdict | accept | accept | |
| start → end | **118,707,974** | **118,697,388** | +10,586 |
| fetch (16 KiB probe + 170 KiB) | 52,648 | 42,062 | +10,586 |
| decode | 20,292,292 | 20,292,292 | 0 |
| verify | 98,363,034 | 98,363,034 | 0 |

- **instruction gas agrees to the unit;** the whole difference is
  `fetch`'s price: GP 0.8.0 prices a payload (case 13) at 95 + 96 a KiB
  (`definitions.tex`) [read], the JAM-only host at 10 + 40 a KiB, so
  (95−10)·2 + (96−40)·186 = 10,586 exactly. The host's linear fit was made
  on one length, an import segment (171 gas, flat in GP), so it is right
  for imports only; 6.19 takes GP's per-kind table (the review);
- refine is within the testnet's 1e9 and 6.19's 150M (118.7M); the package
  landed about 13 s after submission.

**The proof's transport** [read, measured]: Gray Paper 0.8.0 bounds no
single payload, only the bundle's sum by W_B = 13,791,360 B. But JAM-NP
CE 133 (work-package submission) caps its first message, `Core Index ++
Work-Package`, at 2 + 200·1024 = **204,802 B**, extrinsics travelling in a
second message under W_B alone (CE 146 alike). PolkaJam enforces it: with
this package's 269 B of overhead, **a 204,533 B payload is accepted and
204,534 B refused** ("Message size 204803 outside expected range
0..=204802", 12 refusals in the debug log), deterministic on the second
testnet; on the first, submissions of 201,584–201,600 B failed
intermittently, unexplained, so any cap keeps a margin. The 174,080 B
item (and 201,584 B ones) landed with verdict accept. **Pin F's 256 KiB
proof does not fit a payload.**

**The decisions it settles** (the review agreeing with the log's option 1,
for a reason the log did not give):
- **the proof as the `Submit` item's extrinsic, the statement in its
  payload:** under W_B, outside CE 133's bound, one package, no
  solicit, provide or availability step, and pin F's bounds uniform at
  every venue (a payload would leave as little as about 136 KiB for the
  proof beside a 64 KiB statement). Read by `fetch` case 4 (85 + 96 a
  KiB, about 16K gas for 160 KB [est]);
- **submitted through PolkaJam's `submitWorkPackage` RPC** with the
  extrinsics beside the package (JIP-2, in the binary's strings; `jamt
  item` takes none), not a CE 133 client of our own (the review's
  correction of the log's tooling cost);
- **[read], not [measured]:** no extrinsic over 200 KiB has landed yet, so
  6.19 measures one first (256 KiB, refined, read with case 4); the
  fallback is the payload with a JAM proof cap of at most 196 KiB −
  |statement|;
- the preimage path stays for the harness alone; opt-level 3; PolkaJam
  v0.8.0 pinned at its sha256; `fetch` priced by GP 0.8.0's per-kind
  table with PolkaJam ≡ JAM-only host to the unit as 6.19's gate.

**A pre-existing defect, found by the review:** the default agent's JAM
builder checks the wrong bound. `node/jam/src/live/` submits each
package with `jamt item <payload>`, the payload the whole batch and its
witness, and `node/jam/src/builder/fit.rs` checks only `payload +
segments·4,104 ≤ MAX_INPUT` (12 MiB, W_B). A package whose payload passes
about 200 KiB is built and then refused by every guarantor, `jamt`
reporting only "Failed to submit … to even a single proxy/guarantor".
Slices 4 and 5's payloads were small; 6.13's inline served on a
JAM-hosted agent, or any batch of large inputs, will meet it. **Carried,
owned by 6.19:** `fits` bounds the payload and the package's framing
within 204,800 B as well, and an input whose own witness cannot fit is
refused or moved to an extrinsic through the same submitter.

### 6.0d: the docs

**The research** was copied into `research/slice-6/` with the plan
(`27967322`). Every reference the plan makes to it resolves. Four
pointers did not, and now do:
- `spaces-pallet.md` cited `../spaces-pallet-research.md`,
  `owner-decisions.md` and `vos-core/docs/design/identity-and-authority.md`;
  they are now paths from the repository's root;
- `spaces-pallet-research.md` and `owner-decisions.md` pointed at the
  staged `stage/spaces-pallet-design.md`, now `docs/design/spaces-pallet.md`;
- `plan3-review.md` names the staged files it reviewed; a line maps them
  to their homes.

**`doc-fixes.md`'s [now] and [decision N] items, applied:**

| doc | applied | left for their step |
|---|---|---|
| `proving.md` | 26: 2–7, 12–20, 22–30, 34, 35 | 1 (6.22), 8 (6.13), 9 (6.15), 10 (6.5), 11 (6.10, 6.19), 21 (6.0a), 31 (6.1, 6.9), 32 (6.13), 33 (6.5) |
| `recursion-air.md` | 8: 1–5, 8–10 | 6, 7 (6.4) |
| `core-model.md` | 11: 4, 6, 9, 10, 12–18 | 1, 5, 7 (6.13); 2, 3 (6.12); 8 (6.18); 11 (6.6) |
| `identity-and-authority.md` | 8: 1–8 | none |
| `research/slice-5/kreivo-pallet.md` | 15, as a note at the top; its body stays the record | none |
| `clerk-across-spaces.md` | 13: 1–3, 5–14 | 4 (6.13) |

81 items in all. Every replaced number was checked against its source:
the masked wrap's against `spike6a-mask-wrap.md`, format 39's counts
against `spike6b-masked-bits.md`, Kreivo's against `spike6c-kreivo.md`,
the estimates against the plan's, and against the code
`Limits::attest` (64 KiB on VOS, 2 KiB on JAM, `agent/wire/src/abi/cap.rs`),
the built `Statement` and its id (`pvm/proof/statement`), the Stwo pin
(olanod/stwo `ab294189`) and the statement fixtures' bytes (375 KB, the
segment fixtures beside them).

**Applied with a change, and why:**
- **Mixed tags** (a decision and a step): `proving.md` 19 (decisions
  10–12; 6.16) and 24 (decisions 1, 6, 7; 6.14), and
  `identity-and-authority.md` 1 (decisions 1, 2, 7; 6.14). Applied now as
  design: the decisions are taken and `spaces-pallet.md` exists. Their
  steps confirm them as built.
- **Not yet true of the code,** so worded as placed rather than done:
  - `core-model.md` 12 (decision 3): the refine-bundle path (format 36)
    is "retired by the owner's decision of 2026-10-19, and deleted at
    slice 6's 6.9", not "deleted"; it is still in the code;
  - `core-model.md` 14 and 17: requirement 4 is "met by the statement
    (slice 5); format 39 at 6.6", and the track's item 9 stays unstruck,
    placed in slice 6, since format 39 is not built yet.
- **`clerk-across-spaces.md` 10** rests on the Clerk's decision 4 (the
  aggregate rows), still open in that draft: written as "under decision
  4's aggregate rows, a pair reads two rows".
- **`clerk-across-spaces.md` 1:** the header says the steps "are re-read
  against them where marked" in place of the item's "(items 2–14)", which
  names `doc-fixes.md`'s items, not anything in the Clerk's doc.
- **`proving.md` 26:** the total is recomputed with slice 6 in full
  (32–49 engineer-weeks, its spikes, acceptance and the slice-5 rest
  included): about 76–118, from 58–89.
- **`proving.md` 28:** the two deferred items became decisions 10 (the
  window length) and 11 (the pallet's home); 11 says it replaces
  decision 7's "in slice 6", which the item did not name.
- **`proving.md` 20:** the JAM proof's transport is written as the item
  has it, the payload unless 6.0b finds it cannot carry the proof; 6.0b
  settles it.

**Not applied:** none of the [now] or [decision N] items was wrong
against the code or the owner's decisions.

**Left as they are,** outside the items: `clerk-across-spaces.md`'s goals
and C.8's acceptance still name the JAM aggregate agent and a PolkaJam
run; they are re-read when the Clerk is scheduled.

**The rename** (decision 15): the Clerk's slice-6 draft is
`clerk-across-spaces.md` by `git mv`, its steps renumbered C.0–C.8, and
every reference in `docs/` follows. The research records that cite the
draft by line keep their numbers, each with a note that they are the
draft's before the rename.

**Commits:** `bf742664` `proving.md`; `c0978c64` `recursion-air.md`;
`0719aaa0` `core-model.md`; `21fb8e4a` `identity-and-authority.md`;
`04e8a3cb` `kreivo-pallet.md`'s note; `d29b36f0` the rename and its
references; `c75c11d5` the Clerk's items; `4a49afa8` the research's
pointers; and this entry.

**Review** (Opus): mostly clean; 2 medium and 4 low findings, folded in
one commit:
- **medium:** `core-model.md` §9.3's agent root stated as built: now
  "[decided; built at slice 6's 6.11 (agent root) and 6.14 (space
  root)]", "VOS will keep"; `proving.md` §3.5's fixed-layout decode sat
  in the "Built (slice 5's 5.14) [measured]" list: now its own "Levers"
  bullet, "format 39 is to decode a fixed layout (6.4)";
- **low:** requirement 4 "met by the statement (slice 5); format 39 at
  6.6", item 9 unstruck; "masked from slice 6" (`identity-and-authority.md`
  §11) and "to be verified in a JAM statements service's refine (slice
  6)" (`core-model.md` §11.1); `Limits::served` "(proposed; set by
  6.0a)" in `proving.md` and the Clerk doc; the JAM transport "(or as a
  preimage; 6.0b decides)"; the Clerk doc's "Decided in this draft"
  marked superseded by C.0, C.4 and C.5 where they are, and its decision
  4's aggregate read at one cut against the carried commitment;
  `proving.md` A.6's long line rewrapped.

**Gates:** docs only, so no `just check`; no reference to the
draft's old name is left in `docs/`.

### 6.0e: a Rust client on a Kreivo dev chain

**Built** on `spike/s6-kclient` (`c47481f9`, from `27967322`; local, not
pushed, throwaway): `spikes/s6-kclient`, a standalone workspace on
nightly-2025-07-14. The runtime: Kreivo master `87f8728`, unmodified,
built with `-p kreivo-runtime` (stable 1.94.1, `wasm32v1-none`, 9 min 14
s): `kreivo_runtime.compact.compressed.wasm`, 2,111,517 B; the client
checks it is pristine (45 pallets, no index 90). The node:
`polkadot-omni-node` from `polkadot-stable2606-2` (1.24.2-72284b37a23),
its sha256 checked as Kreivo's CI does.

**The dev chain:** `omni-node --dev` works, so chopsticks was not needed.
`chain-spec-builder … named-preset development` (`dev_genesis(2281)`),
then `--dev --dev-block-time 2000`. Aura (sr25519), `u32` block numbers,
instant seal (best = finalized), `kreivo-parachain` spec 134,
transaction version 13, metadata V16 (of 14, 15, 16), `Timestamp.Now` on
the wall clock.

**The round trip** [measured]:
1. **the call by hand:** `[0, 7] ++ SCALE(Vec<u8>)` (System,
   `remark_with_event`, both checked against the metadata), 20 B, through
   a `RawCall` payload whose `EncodeAsFields` writes the bytes verbatim;
   `call_data` and the call inside the included extrinsic are asserted
   byte-identical to them. The pinned `[90, call] ++ SCALE(args)` calls
   go this way;
2. **the nonce** by `AccountNonceApi`;
3. **the envelope from the live metadata:**
   `DefaultExtrinsicParamsBuilder::new().mortal(64).nonce(n)`, signed by
   the sr25519 dev key `alice`: a v4 extrinsic of 127 B, its explicit
   extension bytes `00 3500 00 00 00`;
4. **inclusion** by `submit_and_watch`: block 4, extrinsic index 2, found
   by hashing the block's body;
5. **the event** from `System.Events` read as a raw key, delimited
   against the live metadata, filtered by `ApplyExtrinsic(2)`:
   `System::Remarked` decoded by its pinned layout, sender = Alice and
   hash = `blake2_256(remark)` asserted;
6. **raw storage:** `System.Account[alice]` decoded by hand, the nonce
   asserted up by 1; `Timestamp.Now` read raw;
7. **the fee:** 667,629,076 planck for 127 B.

A second run (nonce 1 → 2) and a run on another runtime build passed
alike.

**Gate: passes.** The round trip works with **subxt and subxt-signer
0.51.1** (frame-decode 0.18.1, jsonrpsee 0.26.1), `PolkadotConfig`
unchanged, no `#[subxt]` macro needed; the raw JSON-RPC fallback was
not needed, so 6.17b takes its lower estimate (1.5 weeks).

**Kreivo's transaction extensions,** in metadata order (version 0;
extrinsic versions 4 and 5, subxt encodes 4): `PassAuthenticate`
(explicit `Option<AuthenticateParams>`, sent as None), `CheckNonZeroSender`,
`CheckSpecVersion`, `CheckTxVersion`, `CheckGenesis`, `CheckMortality`,
`CheckNonce`, `CheckWeight`, `ChargeAssetTxPayment` (the whole fee stack
shows as its inner identifier and data, so `ChargeSpaceFee` keeping them,
`spaces-pallet.md` §7, leaves the envelope unchanged, as the design
assumes) and `DynamicMaxBlockWeight`.

**The decisions it settles for 6.17b:**
- **`PassAuthenticate` pinned** to None as a typed `TransactionExtension`:
  subxt has no support for it and encodes it only through frame-decode's
  fallback ("an unknown extension whose type holds an `Option` is None"),
  which a subxt bump or a type change in frame-contrib could alter
  silently;
- **the live extension list checked** against the expected ten in order,
  and an unknown one refused before signing (the review's addition: a new
  extension such as `CheckMetadataHash` would otherwise be defaulted or
  the extrinsic rejected without a clear error);
- the `calls` layer needs only `RawCall` on top of subxt.

**Left open** (the review, not blockers): the workspace build is
untested (subxt's crates behind `kreivo`, VOS on tokio 1.50 where the
spike resolved 1.53.3), so 6.17b's first act is the dependency and `just
check`; `--dev` seals instantly, so finality lag and reorgs are the mock
transport's to test.

### The review

Opus, read-only, on the three logs and branches against the plan at
`bcd4f5b9`, by reading the code (`cap.rs`, `invocation.rs`, `host.rs`,
`node/host/src/pvm.rs`, `node/jam/src/{gas.rs,builder/fit.rs,live/}`,
`refine_host/jam.rs`), recomputing the arithmetic and grepping the
testnet logs and GP 0.8.0's `definitions.tex`. **All three gates pass as
claimed and the numbers are sound.** Its corrections and additions:
- **6.0a's `ATTESTS` 8 rule** was ambiguous (8 at-cut and 8 plain records
  would be about 3.1 MB against the 2.1 MB term): an at-cut attest counts
  2 against `Limits::attests` instead. Even with no rule, 16 plain and 1
  at-cut hold (STEP margin 343 KB, WORKFLOW 153 KB). The kernel's whole
  return is capped at `Limits::attest`, the 40 B framing is re-derived for
  `window` and `roots`, and the workflow's record keeps the attest's
  return, never the `Resume`'s served bytes (`WORKFLOW_ROWS` and
  `gas.rs`'s `RECORD` size it at `REQUEST`);
- **`rep_salt`, not a zero salt,** carried in `Closed` as well as
  `Served`; JAM's own `Limits::served` (32 KiB proposed), with
  `JAM.within(&VOS)`, `gas::effects(&cap::JAM)` and `WORST_JAM_STEP`
  gaining the term;
- **6.0a's untested refusals** (a row of another instance, an absent row,
  a wrong `served.agent`) are 6.13's tests;
- **6.0b's tooling cost:** `submitWorkPackage`, not a CE 133 client; the
  extrinsic transport is [read] until 6.19 measures one;
- **CE 133 binds the default agent's builder** (above), carried to 6.19;
- **6.0e:** the extension list checked as well as `PassAuthenticate`
  pinned; the workspace integration untested.

Its plan edits (pin E's E1–E7, pin F's F1, 6.0's outputs, 6.13's S13a–d,
6.17b's S17a–c, 6.19's S19a–e, risks R1–R3, decisions D1–D3), with 6.1's
powers cap at 76.14 (not 76.15) and the consequences they carry (6.13's
files, 6.18's traced re-run and 6.20's carriers on the inline served;
the dedicated-service decision no longer citing the 512 KiB cap; M3b at
4–5.5 weeks and the slice at 32–48.5, so `proving.md` §11's "about
76–118" total stays within its rounding), applied in `e50bb030`.
`doc-fixes.md`'s items that 6.0a and 6.0b overturn were amended there:
`proving.md` 3, 21 and 32 and the Clerk's 5 to the inline served witness
(at 6.13; 21 is the measurement now), `proving.md` 20 to the extrinsic
transport (at 6.19). The texts 6.0d applied from items 3, 20 and the
Clerk's 5 (`proving.md` §3.2 and §6, `clerk-across-spaces.md`) still
read "by hash" and "6.0b decides" until those steps.

**Commits:** `e50bb030` the plan and `doc-fixes.md`; this entry.

**6.0 done:** the three spikes passed their gates with no fallback
taken, 6.0d's docs applied, and the plan carries their results.

## Step 6.1: format 39 and the masked security count

**The tool** (`pvm/proof/src/security.rs`), ported from spike 6b
(`1b76b028`):
- `SecurityShape::composition_point_doublings` (`j`): the DEEP term is
  multiplied by `2^j`; 0 in every unmasked shape (the registry's and
  `framework_access`' `security_shape`), and a `j` above the degree bound
  is refused;
- `SecurityShape::variant_c()`: from the tallest component's `m`, the
  degree bound `m+2`, the trace length `m+1`, the composition bound `m+2`,
  `j = 1`. It moves only the levels; what the masking commits beside the
  AIR's columns is the caller's to add;
- the search for the best multiplicity is one `Analysis::best`, the other
  terms a named `OtherTerms`; a test-only `term_bits` reports every term
  at the `m` the count is taken at.

**The entry** (`pvm/proof/src/format.rs`):
- `ProofBytes::{Postcard, FixedLayout}`, a new `Format` field (pin A):
  every existing format `Postcard`, 39 `FixedLayout`;
- `MASKED_WRAP`, number 39, pin A's parameters (blowup 32, 24 queries,
  PoW 26, interaction PoW 8, fold step 3, last layer 2^6, affine
  batching, Blake2b-256, `Lossless`), masked, floors 100 / 80,
  `Reserved`;
- `MASKED_WRAP_REFERENCE`: `WRAP_REFERENCE.variant_c()` plus R2's
  blinding (12 main and 8 interaction columns, 2 constraints, fractions
  6, 5 and 7 a row) and the composition's columns as pin A commits them
  (4 whole and R's 8, where the split composition had 8). Every sampled
  column at two samples, as `WRAP_REFERENCE` counts its own: 2 × (458 +
  24) = 964 sampled values, against the spike's 956 with a 4-column R;
- `RETIRED` gains 40, its reason in the doc: never registered, but spike
  6a's measured masked wrap at blowup 64 was made under it. The refusal
  now reads "no format takes it again" (the old "its AIR is superseded"
  was untrue of 40).

**The counts [model]:**

| shape | m | query | batching | fold | ALI | DEEP | logup | count |
|---|---|---|---|---|---|---|---|---|
| 39 (blowup 32, 24 queries) | 5 | **82.70** | 82.79 | 82.98 | 108.38 | 97.68 | 111.60 | 146 / 82 (82.6999) |
| (c) at 28's parameters (shape B) | 4 | 82.60 | **81.74** | 81.93 | 107.70 | 97.00 | 111.60 | 146 / 81 |

- every unmasked format's pinned bits unchanged: 28 at 146 / 82
  (82.60), 30 106 / 62, 32 108 / 63, 35 104 / 62, 36 96 / 57, 37
  106 / 62;
- the least queries that clear 100 / 80 masked, pinned: blowup 16 PoW 26
  28; blowup 32 PoW 20 / 24 / 26 / 28 25 / 24 / 23 / 22, and 23 at fold
  step 2 or a 2^8 last layer; blowup 64 19 (PoW 26 or 28, fold 2 or 3).
  39's own least is 23 (80.84);
- the interaction PoW does not bind 39 (logup 111.60 with it, above 100
  without it, the count the same);
- **by powers** (DIVERGENCE-012 falling): 39 caps at **76.14** (76.136)
  at blowup 32 and **73.64** at blowup 64, however many queries; only
  blowup 8 reaches 80, at 43 queries. The plan and spike 6b say 76.15 and
  73.65: R's 8 columns, at two samples each, add 8 values over the
  spike's 4-column R to the batch by powers (`log2(963/955)` = 0.012
  bits). The affine count does not see them. The two-sample convention
  overcounts R and the composition, which pin B samples once each:
  `sampled_values` is an upper bound on the built batch. **Superseded at
  6.2's fold:** the reference counts the batch exactly, 538 values, and
  the caps are **76.98** and **74.48**, blowup 8 reaching 80 at 41
  queries.

**Docs:** `pvm/proof/SECURITY.md` (39's row, 40 among the retired, the
masked count and what it rests on, DIVERGENCE-011's round list `[3, 3, 3,
2]` and its 0.19-bit margin, DIVERGENCE-012's caps, premise and
fallbacks, the audit's scope); `proving.md` A.4's retired list gains 40
(`doc-fixes.md` 31, its 36 half left for 6.9).

**Tests:** `format_masked_tests.rs` (6: the unmasked counts unmoved and 39's
reference, 39's counts and terms, (c) at 28's parameters, the
least-query grid, the interaction PoW, affine batching needed), and in
`security.rs` the round list `[3, 3, 3, 2]` at `log k = 17` and
`variant_c`'s levels and DEEP doubling. The spike's cost proxies and
printed tables were not ported: they are spike 6b's record.
`cargo test -p vos-pvm-proof --no-default-features --lib`: 96 passed.

**Gates:** `just check` green (1,113 tests, 0 failed).

**Commits:** `cbe03ea7` the tool; `7924e135` format 39, its tests and
`SECURITY.md`; `413910fe` and this line, the record.

**Review:** Fable ACCEPT, every number reproduced independently, the
76.14 flag confirmed; Opus, no defects. Folded in one commit:
- **Fable 1 (low, doc):** `sampled_values` stated as an upper bound
  (R and the composition counted at two samples, sampled once under pin
  B) in `MASKED_WRAP_REFERENCE`'s doc and `SECURITY.md`; the plan's 6.2
  test (and 6.4's check) compare the built shape's `sampled_values ≤`
  the reference's, every other field `==`;
- **Fable 2 (low, doc):** `security.rs`'s module doc and `SECURITY.md`'s
  DIVERGENCE-012 name soundcalc's path, *linear batching*
  (`_get_batching_error` → `get_error_linear`, BCHKS25 Theorem 4.2): the
  BCIKS20 names are ours, so the audit checks that Theorem 1.6's
  affine-space correlated agreement carries BCHKS25's `ε_lin`;
- **Opus (nits):** a test doc ("a `j` above the degree bound is
  refused"), the split helpers' effect stated as FRI's dimension at `2N`
  (`log_degree_bound` `m+1`), `MASKED_WRAP_SAMPLED_COLUMNS` written in its
  doc's order as `(3·4 + 2·4) + 4 − 8 + 8` (the review's `(4 − 8)`
  underflows a `u64` constant), a `SECURITY.md` reflow.

**6.1 accepted.**

**Gates after the fold:** `just check` green (1,113 tests, 0 failed).

## Step 6.2: the masked AIR variant

**The split** (`pvm/proof/recair-air/src/{lib,p2,qm31,h8}.rs`): a
`Body` trait (`FrameworkEval` plus `body()`: the columns, constraints and
relation entries, the fractions not yet finalized); each component's
`evaluate` is `body()` then `finalize_logup_in_pairs()`.
Behaviour-preserving: the stale-fixture test below.

**`masked.rs`** (new, no_std), ported from spike 6a (`c95b46c9`):
- `MASKED_LOG_CONSTRAINT_EXPANSION = 2`; `BlindRelation`
  (`relation!(_, 1)`); `MaskedEval<B: Body>`: the body, 4 blinding main
  columns, one fraction `combine_ef(b) / combine_B(1)`, the pairs, at
  `log_size + 2`;
- the `MaskedComponents` trait: a component set's relations (drawn right
  before `BlindRelation`), its constructor from relations, blinding, log
  sizes and claimed sums (`None` on a count not the set's), its log sizes,
  its preprocessed tree and its components; `WrapComponents` is the
  recursion AIR's (`p2`, `qm31`, `h8`). Where the spike hard-coded the
  three components' widths, every function here reads the set;
- `MaskedComponent` (committed bounds `+1`); `MaskPins` (salt and `R`
  columns) with `MASKED_WRAP_PINS` (8 and 8, pin A);
- `committed_log_sizes` (all four trees: 57 / 381 / 48 / 20, salts, the
  composition and `R` at `m+2`), `air_log_size` (`m+1`, the components'
  own tallest column), `composition_log_degree_bound` (`m+2`),
  `composition_point` (π(z): one doubling, from the two levels),
  `sample_points` and `composition_oods_eval`, each `Option`, no panic
  path (the preprocessed indices are checked before Stwo's
  `mask_points` indexes them).

Wrap-only: leaves, folds and `LOG_CONSTRAINT_EXPANSION` (1) untouched;
the blinding columns exist only in `MaskedEval`.

**The degree audits [measured]** (`recair/tests/circuit/masked.rs`):
- masked `p2` 303 constraints, degrees `[0, 0, 143, 160]`; `qm31` 4,
  `[0, 1, 0, 3]`; `h8` 8, `[0, 1, 1, 6]`: every one ≤ 3, as spike 6a;
- **R5:** the 25 segment chips, each driven through `drive_chip_oods`
  (preprocessed columns from an `InfoEvaluator`, counted as columns):
  5,177 constraints (`SEGMENT_REFERENCE`'s), by degree `[0, 23, 4395,
  759]`, none above 3. (c)'s premise holds for slice 7's segments.

**The masked reference shape from the built components:** read from
`WrapComponents`' own layout, never `framework_access`: `k` the largest
committed bound (17, whole), the masked level 16, the composition 17, the
components' 315 constraints, their fractions from `logup_counts` ((6 <<
14) + (5 << 15) + (7 << 11)), the relations' widest (`Gate`'s 5), `j` from
`composition_point`'s doublings (1), and `sampled_values` as the DEEP
quotient batches pin B's sample points: a two-sample column batches a
third value, its periodicity sample (`deep_values_of_column`). Equal to
`MASKED_WRAP_REFERENCE` in every field but `sampled_values`: **538**
built against the reference's 964 bound (57 preprocessed, 357 + 3·16
main, 28 + 3·12 interaction, 4 + 8 composition and `R`). Count 82.6999
[model], the reference's. No correction to the reference or to 6.1's pin.

**Static checks:** only `MaskedEval` adds to `BlindRelation` (each
unmasked component's `logup_counts` hold `Gate` alone, each masked one
`2^n` blinding fractions; no other recair-air module names it, and
`masked.rs` has one relation entry); no source under `recair/src/{leaf,
fold,verifier}` names `masked::` or the blinding relation.

**Note for the review:** `framework_access`' `security_shape` sums the
samples, not the values the DEEP quotient batches (a two-sample column
batches 3): the segment AIR at 2^20 and 2^16 has 9,020 samples and 10,016
values [measured]. It enters only the count by powers, which the segment
formats use: with 10,016, 35 stays 62.857, 36 goes 57.495 → 57.485, 37
62.129 → 62.104 [model]; every pinned count (62, 57, 62) and floor holds.
Left as found, for the review to place: correcting it moves
`SEGMENT_REFERENCE`.

**Gates:** format 32 untouched: `the_fixtures_are_the_generators` (leaf,
fold and wrap fixtures, `H_fold`, the program ids) passes byte for byte
(200 s); the reference shape equal to the built one but for the bounded
`sampled_values`; `just check` green (1,121 tests, 0 failed), the
recair-air module building no_std for thumbv7em and wasm32.

**Commits:** `13ac14c5` the split; `d1b646d6` `masked.rs` and its tests;
this record.

**Review:** Fable ACCEPT, no soundness defect, the masked transcript's
geometry re-derived independently (π(z) as the composition's point, the
lifted reads, the widths, the 28 twice-sampled columns); Opus, clean but
for quality items. Folded:
- **Fable 1 (medium, count), the note above, fixed:** `security_shape`
  counts `B` as the values the DEEP quotient batches
  (`deep_values_of_column`: the fork draws one coefficient a value, and a
  twice-sampled column batches its periodicity value).
  `SEGMENT_REFERENCE.sampled_values` 9,020 → **10,016** (the device
  reference inherits it), held by `the_reference_shapes_are_the_segment_airs`.
  36 counts 57.485 and 37 62.104 [model], 35 62.857, every pinned count
  and floor unchanged; 32's parameters on the segment shape count 62.74
  (was 62.80), their batching term binding (`proving.md`'s two sentences
  corrected). `MASKED_WRAP_REFERENCE` takes the exact batch, **538**
  (`(57 + 373 + 40 + 4 + 8) + 2·(16 + 3·4)`), where 6.1 bounded it by 964:
  the test now holds the built shape equal to the reference field for
  field. 6.1's pin moves with it: by powers 39 caps at **76.98** at blowup
  32 and **74.48** at blowup 64 [model] (still below 80; the fallback is a
  batching-phase PoW of 4 bits at blowup 32, 6 at 64, or blowup 8 at **41**
  queries, was 43). Updated in `format.rs`, `format_masked_tests.rs`,
  `SECURITY.md` (a paragraph on `B`), the plan (6.1's test, the risk row,
  6.2's test) and 6.1's entry above. The plan's 6.4 asserts
  `n_deep_values` of the verifier's samples equal to 538.
- **Fable 2 (low):** `c` counted as `B` is: the most DEEP values of one
  column, 3 for a twice-sampled column (its periodicity value an opening
  at a third point); `security.rs` states it, and every reference with
  previous-row reads (segment, leaf and fold, wrap, masked wrap,
  credential) carries 3. No count moves at the second decimal.
- **Fable 3 (low):** `each_evaluation_is_its_body_and_its_pairs` in
  recair-air: each component's `evaluate` equals its `body()` and
  `finalize_logup_in_pairs()` on a recording evaluator, constraint for
  constraint and intermediate for intermediate (a dev-dependency on
  constraint-framework's `prover` feature for the recording evaluator), so
  `just check` holds the split, not only the fixtures.
- **Fable 4 (low):** the masked audit reads each component's preprocessed
  columns from an `InfoEvaluator` (and checks them equal to its list), as
  R5 does; the audit's degree walk refuses any name that is neither a
  column, an intermediate nor one of the recording evaluator's constants
  (`claimed_sum`, `column_size`, `<relation>_z`, `<relation>_alpha<i>`).
  The 25 chips pass it too.
- **Fable 5 / Opus 3:** one `MASKED_COLUMN_EXPANSION = 1`;
  `committed_log_sizes` and `air_log_size` read `MaskedComponent`'s bounds,
  the preprocessed tree adds the constant: one rule in one place.
- **Fable 6 (forward):** recorded in the plan: `MaskPins` and `h` on
  `Format` (R6) and a provided `draw(channel) -> (Relations,
  BlindRelation)` (6.3); the verifier checks `log_sizes` against the
  format's pin before `new` (6.4); slice 7's active-chip mask and a
  finalize hook on `Body` (6.2's R5 line).
- **Fable 7 / Opus 1:** the rustfmt-bound source match dropped; the scan
  for the blinding relation moved to `recair/tests/circuit/masked.rs`
  (`only_the_masked_module_names_the_blinding_relation`, over
  `recair-air/src` but `masked.rs`), one `sources()` walker shared with the
  leaves-and-folds check.
- **Opus 2:** R5 asserts its histogram, `[0, 23, 4395, 759]`.
- **Opus 4, 5:** `Body: FrameworkEval + Sync`; `masked.rs`' module doc cites
  `proving.md` §5, `masking-review.md` and the registry; the tests
  `the_masked_trees_match_pin_a`, `the_sample_points_match_pin_b`.

**Gates after the fold:** the stale-fixture test byte for byte; `just
check` green (1,123 tests, 0 failed).

**Commits of the fold:** `1ba943a1` the count; `81811bdc` the AIR and its tests;
this record and the plan's edits.

**6.2 accepted.**

## Step 6.3: the masked prover

**The format's pins (R6)** (`pvm/proof/src/format.rs`): `Masking {
salt_columns, fri_mask_columns, log_mask_rows }` and `Format.masking:
Option<Masking>`, 39's `MASKED_WRAP_MASKING` (8, 8, 8: `h = 256`), `None`
for every unmasked format and for 30 and 37, masked but reserved before
their masking. The type is named `Masking`, not the plan's `MaskPins`:
`vos-pvm-recair-air`'s `MaskPins` (salt and `R` columns, the trees'
layout) stays, since the AIR crate does not depend on the registry;
`MASKED_WRAP_PINS` moved from it to `vos_pvm_recair::masked`, a constant
read from `MASKED_WRAP.masking`, so
`the_masked_reference_shape_is_the_built_wraps` now guards the format's
pins. A test holds 39's `h` within pin A's bounds: at least `2(4·2 +
24·3) = 160`, at most `N/4` and `2N/3` of `h8`'s `2^11`.

**The AIR's side** (`recair-air/src/masked.rs`): the provided
`MaskedComponents::draw(channel) -> (Relations, BlindRelation)`, pin B's
step 5 written once, used by the prover and the tests' verifier.

**The prover** (`pvm/proof/recair/src/masked/`, ported from spike 6a's
`c95b46c9`, `5227bf6c`):
- `prove_masked::<MC: MerkleChannel, C: MaskedProvers>(format,
  MaskedTrace, &MaskRng)`: a `MaskedTrace` is a set's log sizes, its
  preprocessed and main columns, its public values and its interaction trace
  (a closure of the relations and each component's blinding fraction).
  Pin B's order; nothing names the wrap. `MaskedProvers`, the prover-side
  extension of `MaskedComponents`, gives the set's `ComponentProver`s, each
  lifted one level by a local wrapper over recair-air's `MaskedComponent`
  (one lifting rule); `WrapComponents` implements it;
- `MaskLayout` (`layout.rs`), its asserts errors (`h ≤ N/4`, a lost
  coefficient, `v_H·r` not spanning exactly `h` basis elements) plus a new
  one (`v_H·r`'s positions overlapping `f`'s); the layouts built once a
  size, in parallel, across attempts; `mask_columns` in parallel, a seed a
  column;
- `commit_salted` (`salts.rs`): each salt column written straight into
  packed SIMD lanes (`bytemuck` over `PackedM31`), 2^16-word chunks each
  from its own ChaCha20 stream, in parallel; the value `p` drawn again. `R`'s
  8 columns from the same sampler, as uniform coefficients at the
  composition's level;
- **R4** (`rng.rs`): `MaskRng::{Os, Seeded(u64)}`, the seeded variant only
  under `cfg(any(test, feature = "seeded-masks"))`, `MaskRng::new()` the
  OS's; an attempt's ChaCha20 seed is pin C's
  `BLAKE2b-256("vos/mask/seed/v1" ‖ 32 OS bytes ‖ witness digest ‖ attempt
  LE)`, fresh OS bytes each attempt. **Deviation (pin C's [proposed
  detail]):** the witness digest is `BLAKE2b-256("vos/mask/witness/v1" ‖
  each unmasked main column's BLAKE2b-256)`, not the root node's proof
  bytes and output preimage: the generic prover has no root node, and every
  private value is in its main columns. Pin C amended;
- **R1** (`rank.rs`), ported: the classes collected, then checked in
  parallel, by forward elimination; the AIR's level and each column's rows'
  level read from the set (the spike's `composition − 1`). Checked after
  the prover's own out-of-domain check, so an invalid witness is refused
  as such, never retried; a deficient transcript discarded and every mask
  drawn again, at most `MAX_ATTEMPTS = 8`, then `ProveError::MaskRank`;
- R with 8 columns, no R3 check (pin C);
- every spike `assert`/`expect` an error: `ProveError::{MaskRank,
  Masking(&str), Entropy}`; a format without its masking, a set refusing
  its sizes, a composition of another size, sample points that do not fit
  the trees, and **a salt given a sample point**, each refused before
  `prove_values`;
- the blinding (R2): one QM31 a component on its first row, uniform but
  the last, which makes them sum to zero. A set of one component is left
  unblinded (its sum must cancel the public terms alone).

**The recursion AIR's path** (`prove.rs`, `wrap.rs`, `tree.rs`,
`trace.rs`): `prove_masked_on::<MC>(format, circuit, witness, rng,
tamper)` (the wiring checked first); `MainTrace::interaction_with(..,
[Option<FirstRowFraction>; 3])`, `interaction` its `[None; 3]`, the
blinding fraction taken lazily (no allocation on the leaves' and folds'
path). `wrap::prove` is format 39's, from the OS's randomness, replacing
`stwo::prover::prove` for the wrap; `wrap::prove_masked(finalized, rng,
tamper)` returns its `MaskStats`; format 28's path is
`wrap::prove_unmasked(_with)`, which the recursion tests, `wrap_root` and
the fixtures' generator call until the venues take 39 (6.4, 6.5).
`tree::wrap` proves 39, `tree::wrap_with(.., prove)` either. `prove_on`
refuses a masked format.

**The test seam's build check** (`just check-no-seeded-masks`, in `check`
and `ci`): `cargo tree -e features,no-dev` of `vos-cli`, `vos-node` and the
agent shows no `seeded-masks`, and `pvm/proof`'s `debug-internals` does not
name it. The node has no `prover` feature yet: 6.18's adds its build to
the list. `vos-pvm-recair`'s own tests enable the feature through a dev
dependency on itself (verified absent from the `no-dev` tree).

**The tests' masked verifier** (`recair/tests/support/masked_verifier.rs`,
test-only until 6.4's): pin B replayed over any set and channel, on
`CommitmentSchemeVerifier::{commit, verify_values}`; included by path in
`vos-pvm-recair`'s circuit tests and `vos-pvm-proof`'s kernel tests.

**Tests** (`recair/tests/circuit/masked_prover.rs`, small circuits at
`2^9` rows a component, a test format of blowup 4, 4 queries, `h = 64`;
1.2 s in all):
- the mask invariant at `2^6` to `2^17`: `(f' − f)/v_H` on `2N` points off
  `H` interpolates to exactly `h` coefficients in the size-`h` basis, so
  `f' = f` on `H` (Stwo's SIMD backend evaluates no polynomial on a domain
  smaller than its own, so `H` is reached through the divisibility);
  `MaskLayout::new` refuses `h > N/4`;
- R1 refuses `h = 64` at 24 queries (`ProveError::MaskRank` after 8
  attempts) and passes at 4 (1 attempt, rows ≤ 64);
- `fri_mask_coefficients_independent`: `prove_values`' draw replayed (the
  tests' verifier to the DEEP coefficients): an 8-column `R`'s span QM31 on
  4 transcripts; a 4-column `R`'s, a dependent one planted, are caught;
- an invalid witness (a `qm31` limb, a `p2` S-box) refused by the prover
  (`ConstraintsNotSatisfied`), and format 28 refused by the masked path;
- **generic:** a `p2`-only set (`P2Only`, the test's own
  `MaskedComponents` + `MaskedProvers`) proved and verified on
  `Blake2sMerkleChannel` under a format no registry holds; a tampered
  sample and a tampered salt refused;
- two proofs of one witness: the preprocessed root shared, the 3 masked
  roots and every blinded claimed sum different; `MaskRng::Seeded(7)`
  reproduces the proof's bytes, `Seeded(8)` does not.

**The gate:** the window kernel's real masked wrap, in `wrap_root`
(`the_window_wraps`, `test-proof`; also `areas`), under `systemd-run
--user --scope -p MemoryMax=16G -p MemorySwapMax=0 nice -n 10`, verified by
the tests' verifier, its preprocessed root format 28's (pin A) [measured]:

| run | prove | heap peak | process peak resident | bytes (postcard) | R1 | revealed rows | attempts | load (1 min) | format 28, same run |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 12.85 s | 3,627 MiB | 6,161 MiB | 161,263 | 46.8 ms | 80 of 256 | 1 | 14.28 | 5.52 s |
| 2 (R1 parallel) | 13.56 s | 3,627 MiB | 6,097 MiB | 160,584 | 13.4 ms | 80 of 256 | 1 | 21.69 | 11.31 s |

- heap 3.54 GiB ≤ 4.5 (spike 3.45 GiB: the spike measured 3,531 MiB);
  process ≤ 8 GiB (`VmHWM`, reset through `/proc/self/clear_refs` before the
  prove: it holds the window's live data too); R1 ≤ 50 ms in both runs,
  13.4 ms with the classes in parallel;
- **≤ 15 s quiet: not measured quiet.** The machine ran other agents'
  builds, load 14–22; at load 14 the masked wrap took 12.85 s against
  format 28's 5.52 s in the same run (2.33×; spike 6a's best 28 3.88 s,
  which would put 39 near 9 s quiet [est]);
- the process peak's assertion: `wrap_root` now asserts heap ≤ 4,608 MiB,
  resident ≤ 8 GiB and the revealed rows ≤ `h`; the times are printed, not
  asserted, as the 28 wrap's are.

**Gates:** the stale-fixture test (`the_fixtures_are_the_generators`) byte
for byte, formats 28 and 32 untouched (143 s); `just check` green
(1,174 tests, 0 failed), `check-no-seeded-masks` in it; clippy with
`debug-internals` clean.

**Commits:** `aec03f92` the prover, its pins, its tests and the gate; this
record and pin C's amendment.

**For the review (Fable):** the witness digest's deviation (above); the
retry draws fresh OS bytes and the attempt index each time, and R1 runs
after the out-of-domain check; a one-component set is unblinded; the test
seam is a `pub` variant behind `cfg`; `tree::wrap` now proves 39 (no
production caller yet; 6.18's worker will be one).

**Review:** Fable ACCEPT (no soundness or zero-knowledge defect; pin B's
order, every opening R1 counts and the R1 matrix re-derived from the fork;
the retry a public event; the seam unreachable from production), four low
findings and two forward notes; Opus, no blockers. Folded:
- **Fable 1:** `check-no-seeded-masks` is `cargo tree --workspace -e
  features,no-dev` (no root to remember), plus the workspaces built apart
  (`agent/default`, `pvm/proof/fuzz`, `final-verifier/wasm/{run,blob}`),
  and the `debug-internals` line;
- **Fable 2:** the witness digest binds the statement: the format's number,
  configuration, masking and interaction PoW, the log sizes, the Merkle
  channel's name (`type_name::<MC>()`) and the public values, before the
  main columns' digests, so one witness under two formats or channels from
  a replayed OS state never reuses a mask. Pin C amended;
- **Fable 3:** `full_rank` unit tests in `rank.rs`: the `h` points of the
  order-`h` subgroup are dependent, a coset of `h` points off the trace
  domain independent, one point too many refused by its rows;
  `rank_m31`'s own; the out-of-domain points deduplicated by `contains`,
  not adjacent-only;
- **Fable 4a:** `prove_masked`'s doc states a one-component set is
  unblinded, its claimed sum to be checked against a public total; the
  `P2Only` test says its verifier checks none (it tests the transcript);
- **Fable 4b, forward notes:** the plan's 6.5 records that the venues'
  accepted set {39} is the one gate keeping 28 out of production, the
  prover side open (`prove_unmasked`, `prove_on(&WRAP, …)`); its R5 line
  (6.2) gains slice 7's size floor (`log_size ≥ log_mask_rows + 2`) and the
  segments' 128 revealed rows; 6.4's `log_sizes` and widths line names the
  tests' verifier's `fits` check as the model;
- **Opus 1, 2:** `mask_columns` takes `&[&CircleCoefficients]` (no clone of
  the main columns an attempt); `MaskLayout::mask` writes into
  `BaseColumn::zeros(..)` through `as_mut_slice()`;
- **Opus 3:** caller faults have variants of their own,
  `ProveError::{UnmaskedFormat, MaskedFormat, TraceShape(&str)}`
  (`prove_on` refuses a masked format as `MaskedFormat`); `Masking(&str)`
  keeps the layout's refusals, each fragment reworded as a sentence;
- **Opus 4, 5:** the seam's comments name only the prover's tests (a dev
  edge) until 6.5 wires the generator; the tests' verifier's header says it
  is for integration tests and that 6.4 deletes it;
- **Opus 6:** `MaskRng` keeps `Default` (`Os`), loses `new`, is passed by
  value, and `Seeded` is under `cfg(feature = "seeded-masks")` alone;
- **Opus 8:** `wrap_root` takes `masked`, the window's run alone proving
  the masked wrap (not `areas`); the never-failing `revealed_rows ≤ 256`
  is `≤ 160`, pin A's count.

**The gate after the fold** [measured]: the window's masked wrap 9.90 s at
load 7.8 (format 28's 4.45 s in the same run), heap 3,627 MiB, resident
6,235 MiB, 162,037 bytes, R1 7.3 ms, 80 rows, 1 attempt. Under 15 s; the
load still not quiet.

**Gates after the fold:** `just check` green (1,173 tests, 0 failed, on
6.9's merge); clippy with `debug-internals` clean. The fuzz crate's
`Cargo.lock`, which the seam's check resolves, is ignored.

**Commits of the fold:** `823449be`; this record.

**6.3 accepted.**

## Step 6.4: the masked final verifier and the fixed-layout decode

**The verifier** (`pvm/proof/final-verifier/src/`, no_std):
- `masked.rs`: `verify_masked::<MC, C>(format, claim, layout, proof)` over
  any masked component set and Merkle channel, pin B's transcript on
  `CommitmentSchemeVerifier::{commit, verify_values}` (`replay` up to the
  DEEP coefficients, which the prover's tests reuse); `MaskedFormat`, every
  pin the format's (number, configuration and batching, interaction PoW,
  salts, `R`, `h`, log sizes, the trees' widths, the DEEP values), none read
  from the proof; `verify`/`verify_with` the wrap's on Blake2b-256;
- **before any Stwo call:** the proof's log sizes and configuration the
  format's (`Format`), before the set is built at them; the set's trees the
  format's widths 57 / 381 / 48 / 20; `check_shape`: four trees of
  commitments, decommitments, sampled and queried values, each tree's
  sampled and queried columns its width, every column's samples one a
  sample point (the composition tree's 4 coordinates and `R`'s 8 one each,
  its salts none), FRI's inner layers its rounds after the first, the last
  layer `2^6`, every limb canonical; then the circuit (the preprocessed
  root `PREPROCESSED_ROOT_39`);
- **the shape tied to the transcript:** the DEEP values of the verifier's
  own sample points at `z` checked equal to 538 (`DEEP_VALUES`);
- **the trust boundary, named** in the module's doc: the trees' widths
  `verify_values` zips (pinned, held by `check_shape` first) and the FRI
  rounds `FriVerifier::commit` derives from the largest column
  (`FRI_ROUNDS` `[3, 3, 3, 2]`, `fri_rounds` deriving them as commit does);
- `unmasked.rs`: format 28, moved whole, under the `test-formats` feature
  (postcard optional with it); its decode now reads the format word first
  (`Format` on another);
- **dispatch by the statement's format:** `decode(format, accepted, bytes)`
  then `Decoded::verify(words)`, `verify(format, accepted, bytes, words)`;
  a format outside the set or not linked (`LINKED`: `[39]`, `[28, 39]` under
  `test-formats`) is `Format`; never sniffed;
- `layout.rs`, **format 39's bytes:** fixed order, little-endian, `u32`
  counts, no varints; the header (format first, then log sizes and the
  configuration word for word) the format's or `Format`; every count its
  pin (4 trees, the widths, 3 inner layers, 64 last-layer coefficients) or
  bound (2 samples, 24 values a queried column, 528 witness hashes, 192 FRI
  witness values), `Shape` otherwise, and checked against the bytes left
  before any allocation; a limb at or above `p` `Noncanonical`; nothing
  after the last field. Decode and `encode` are inverse: one encoding a
  proof. Limbs are read eight a basic block (the PVM charges a block for
  its loads' latency and its branch);
- constants: `LOG_SIZES`, `PREPROCESSED_ROOT_39` (equal to 28's, its own
  test), `TREE_WIDTHS`, `MAX_PROOF_BYTES` 256 KiB.

**The registry and the prover:** format 39 `Admitted` (`format.rs`,
`SECURITY.md`); `security::fri_rounds` public; `wrap::proof_bytes` emits a
wrap proof by its format's `ProofBytes` (39's fixed layout through the
verifier's `encode`); `masked::verifier_format(format, log_sizes, layout)`
the registry's entry as the verifier pins it.

**The consumers:** `vos-statement` judges 28 through the dispatch, the
verifier's `test-formats` on (6.5 moves it to the accepted set, and the
venue builds to 39 alone); `final-verify.elf`'s words mode and the Wasm
blob's `verify`/`decode` carry the format before the words (the runner
reads `<name>.format`); the tests' masked verifier
(`recair/tests/support/masked_verifier.rs`) deleted, its users on the
final verifier's.

**Tests** (`recair/tests/recursion/masked.rs`, the one-segment run's root
wrapped masked from `MaskRng::Seeded(39)`, 8.1 s, 149,828 B, postcard
160,821 B; and the crate's unit tests):
- the verifier's constants the registry's entry for 39
  (`verifier_format(&MASKED_WRAP, ..) == masked::MASKED_WRAP`), status
  `Admitted`, bytes `FixedLayout`, the circuit's root; FRI's rounds the
  security tool's, `fri_rounds`' and the only count `FriVerifier::commit`
  accepts (3 inner layers; 2 and 4 `InvalidNumFriLayers`);
- spike 6a's 14 tamper cases, each refused with an error as a proof and
  through its bytes, none a panic (OODS `0x13`, Merkle `0x12`, PoW
  `0x15`, logup `0x9`, shape `0x6`, interaction PoW `0x8`, format `0x4`);
- a verifier at 7 or 9 salts or an `R` of 7 or 9 refuses: with 39's widths
  (`Shape`: its set's trees), with the widths its pins lay out (`Shape`: the
  proof's samples); a salt or `R` column more or fewer in the proof
  refused by the shape and at decode;
- cross-format both ways, by bytes and as proofs: `Format` (`0x4`);
- the layout: every truncation and a trailing byte on a pin-shaped proof
  (`Decode`), a spread of truncations and every trailing byte value on the
  real one, the header's every field (`Format`), every count (`Shape`), a
  count the bytes cannot back (`Decode`), each limb kind (`Noncanonical`);
- the window's masked wrap (`test-proof`, `tests/common`) verified by the
  final verifier from its fixed-layout bytes, written for the Wasm harness.

**Fuzzing:** `final_verifier_bytes` and `final_verifier_mutate` run both
goldens, 28's (the fixture) and 39's (the masked test's, under
`target/tmp/wrap`; 6.5's fixtures replace it), each under its own format
through the dispatch; the seed adds 39's. Built and run 180 s each:
497,961 and 6,683 runs, no crash.

**The gate** [measured], the one-segment wrap, `final-verify.elf` (28 and
39 linked, program 608,634 B), JAM-only host:

| format | total gas | lookup | decode | verify | bytes | heap peak |
|---|---|---|---|---|---|---|
| 28 (postcard) | 95,414,225 | 75,420 | 15,716,460 | 79,622,140 | 122,528 | 338 KiB |
| **39 (fixed layout)** | **109,638,368** | 82,458 | **3,758,064** | **105,797,641** | 149,828 | 368 KiB |

- verify 105.8M ≤ 125M; decode 3.76M ≤ 4M (postcard 19.9M at 6.0b; a
  first, per-limb decode measured 6.48M: the PVM's per-block costs, 25 for
  a load and 20 for a branch, are paid per item; the decode's floor is now
  its 1,012 column allocations and the `memcpy` of 2,456 hashes);
- Wasm (`wasm/run`, wasmtime 35): **47,413,788 instructions under the
  PVF's semantics** (≤ 50M), 41,236,828 the client's; 28's 37,996,938 and
  37,454,553; verify 2.6–4.7 ms;
- builds: thumbv7em (`-Zbuild-std`) and wasm32 (`-Zallow-features=`) on the
  pinned nightly, wasm32 and thumbv7em on stable 1.94.1, riscv64em (the
  guest).

**Gates:** `just check` green (1,189 tests, 0 failed); clippy clean.

**For the review (Fable):** the margins are thin (decode 6%, PVF 5%); the
guest's target (`riscv64em-vos.json`) has no `+unaligned-scalar-mem`, so
every limb and hash is read a byte at a time, which the JAM PVM does not
require (unaligned loads are legal), a lever for 6.19's service build;
`vos-statement` still links 28 (`test-formats`) until 6.5; the fuzz
golden for 39 is a test's output, not a checked-in fixture, until 6.5.

**Commits:** `21109480` the step; `975e21ff` this record.

**Review:** Fable ACCEPT (pin B replayed mix for mix against the prover;
every proof-shaped `zip_eq`, index and `unwrap` in `verify_values` closed
by `check_shape` first; the layout canonical and bounded before
allocation; the dispatch never sniffs), five low findings; Opus, no
blockers. Folded (`1fb3f717`):
- **Fable 2:** a third fact left to Stwo, named in `masked.rs` and
  `SECURITY.md`: FRI's bound is the last tree's height less the blowup, so
  the composition tree is the last and tallest commitment
  (`LOG_DEGREE_BOUND` 17; the test holds the tallest column and the whole
  composition tree at it);
- **Fable 3, taken:** the layout pins each column's samples
  (`masked::samples`: 0, 1 or 2 as the format lays them out, a test
  holding it to the sample points column for column) and reads one queried
  count a tree; `encode` returns `None` for a proof the layout cannot hold
  (other samples, unequal queried columns), and the decode refuses those
  shapes itself. Re-measured [measured]: proof 149,828 → **145,796 B**;
  decode 3,758,064 → **3,708,866 gas** (the counts were not the cost);
  verify 105,790,413; total 109,580,903; Wasm under the PVF's semantics
  **47,412,124** instructions (unchanged); proving 10.1 s at load;
- **Fable 1, 4, 5 and the unaligned-load lever, into the plan:** 6.7 the
  fork fix for the last proof-reachable panics (`fri_answers`'
  zero-denominator inverse, about 2^70 hashes [est]; the conjugate line's
  `assert_ne!`); 6.5 `check-no-test-formats`; 6.6 the decode and PVF gates
  on a worst-shape proof or the maximum over ≥ 10 seeds, and
  `+unaligned-scalar-mem` legal on JAM's PVM, measured there or at 6.19
  (6.19 notes it);
- **Opus:** `SECURITY.md`'s masking opening (39 masked, every other proof
  unmasked); one `samples_fit`; `LOG_DEGREE_BOUND` in `HEIGHT`,
  `FRI_ROUNDS`' doc and the tests; the claimed sums read into an array;
  `encode`'s `CAPACITY`; the writer's bytes returned; `unmasked` on
  `masked::TREES`; `Decoded::into_proof` in the fuzz golden; the fuzz
  paths honour `CARGO_TARGET_DIR`; two doc lines reflowed; the plan's 6.22
  item 23: the decode's remaining lever is the allocator over the proof's
  1,012 column vectors, not the layout.

**Gates after the fold:** `just check` green (1,193 tests, 0 failed, on
6.11's merge); clippy clean; the fuzz crate builds.

**6.4 accepted.**

## Step 6.5: `vos-statement` at the accepted set, the fixtures, the harnesses

**`vos-statement`** (pin F):
- **the accepted set:** `admit`'s `format != FORMAT` gone (`FORMAT` with
  it); a statement's format must be one the venue accepts and one this
  build links (`LINKED`, the final verifier's: `[39]`, `[28, 39]` under
  `test-formats`), else `Format` (2); `Admitted` carries the format, and
  the proof is read under it through the verifier's dispatch;
- **`Pin { program, venue_bound }`** in place of the bare id, in `admit`,
  `judge` and the model's `Input`; `Venue::id() -> VenueId`;
  `Refusal::Venue` (code 7): a venue-bound program's statement whose
  `public_args[..32]` is not the venue's id (a shorter one included);
- **the order:** the format; the program; the venue if venue-bound; the
  space; every root anchored (`Venue::anchored` now names the space's range
  and `MaxRootAge`); the io-hash and the id; unseen; the proof;
- **`seen_expiry(statement, clock)`**, pin F's `Seen` rule: a rooted
  statement's entry until `B_wmax + MaxRootAge` (its newest root, whatever
  the roots' order), a rootless one's `u64::MAX`, never; a boundary past
  `u64` keeps it for ever too;
- **`test-formats`** its own feature (the verifier's), off in every normal
  build; the crate's tests enable it on a dev edge; `fixtures` and
  `pvm-guest` do not imply it.

**The model** (`model.rs`): `Policy` gains the venue's id, its time
(`now_ms`), the registered spaces (`Space { id, clock, range: (from_w,
Option<until_w>) }`, the end exclusive: a migration's `from_window`), and
`Seen` entries with their expiry; `anchored` is a registered space, the
window within its range, `now − B_w ≤ MaxRootAge`, and the root listed;
`record` inserts under the `Seen` rule, `advance(now)` drops anchors past
`MaxRootAge` and entries past their expiry; `Input`'s encoding carries
them (a flag byte 0 or 1, else `Noncanonical`).

**The fixtures**, regenerated (`pvm/proof/tests/kernel/fixtures.rs`;
80 s [measured]): `S` (venue-bound, `public_args` the venue's id and a
nonce, two roots) wrapped under 39 from the seeded seam (`MaskRng::Seeded`,
`vos-pvm-proof`'s dev edge enabling `seeded-masks`): `wrap.proof` 145,796
B; under 28: `wrap-28.proof` 123,797 B; the cheating wraps under 39
(`wrap-prefix.proof` 146,052 B, `wrap-midway.proof` 147,076 B: the masked
prover proves the lenient trace, the verifier refuses it `0x109`); a second
kernel's rootless `S0`, one segment, its leaf wrapped under 39:
`wrap-rootless.proof` 146,052 B; `statements.cases` 18,057 B, 29 cases.
The stale test holds every file byte for byte under the seed (a second run:
`the_fixtures_are_the_generators` and `the_fixtures_are_judged` green); the
segment fixtures unchanged. The production venue accepts {39}, the test
venue {28, 39}; both register `S`'s space from window 40 (the default
clock) and judge at window 42's boundary. Each case but the three accepted
is a replay of an accepted statement with one thing changed:

| field | case | code |
|---|---|---|
| the space | the space; another space (a root's); rootless, another space | `0x4` |
| no space (6.10's carried case) | rooted, of no space (`S` claiming `NONE`, its roots `NONE`, registered and anchored) | `0x4` |
| the format | unaccepted format (30); format 28 at a production venue | `0x2` |
| the venue | another venue's statement (`public_args[31]`); replayed at another venue | `0x7` |
| a root's window; a root | a root's window (42 → 43); a root (a byte); unanchored root | `0x5` |
| the nonce | the nonce (`public_args`' last byte) | `0x108` |
| the program | another program than the pin | `0x3` |
| the migration range | migrated before a root's window (`(40, Some(42))`); registered after it (`(42, None)`) | `0x5` |
| time | rooted, replayed past MaxRootAge (`Seen` and anchors dropped) | `0x5` |
| time | rootless, replayed past MaxRootAge (`Seen` kept) | `0x6` |
| the transition, test policy | accepted under 39, replayed under 28; accepted under 28, replayed under 39 (each accepted first by `judge`, then `record`ed) | `0x6` |

and, as before: valid, rootless, format 28 at the test venue (accepted);
tampered (`0x112`), tampered under 28 at the test venue (`0x112`); wrong
program and wrong io-hash (`0x108`); prefix and mid-way (`0x109`);
repeated (`0x6`). The old transition case (successor 38, recorded by id)
is replaced by the real one under {28, 39}.

**Every fixture judged alike** [measured]: the recorded verdict is a build
linking 28 and 39; one linking 39 alone refuses a statement of 28 as `0x2`,
its first check (`Fixture::verdict_linking`):
- natively (the crate's tests, both linked): 29 of 29;
- **Wasm** (`just judge-wasm`): the production blob (39 alone, 323,079 B)
  and the test blob (`--features test-formats`, 392,315 B), each under the
  PVF's semantics and the client's, 29 of 29 each; valid 47,443,561
  instructions under the PVF's semantics (≤ 50M), 46,764,990 the client's;
  rootless 47,506,951; 28 at the test venue 38,314,404 (test blob); a
  refusal before the proof about 11,700;
- **the JAM-only host:** `final-verify.elf` (39 alone) and
  `final-verify-test.elf` (28 beside it), 29 of 29 each; valid 109.7M gas,
  rootless 109.8M, 28 at the test venue 96.5M (test guest), tampered
  70.0M, the words' refusals 14.0–14.2M, every refusal before the proof
  0.1M;
- **the JAM program's size:** production **523,362 B** (ELF 847,536 B),
  within JAM's 4,000,000 B (512 KiB binds nothing: the review below); the
  test guest 610,809 B (ELF 966,040 B; 6.4's two-format program was 608,634 B).
  A test holds the production program within 4,000,000 B and smaller than
  the test one.

**The builds:** `final-verify` and `final-verify-test` are one program
(`src/guest.rs`), two bins; a build of either under the other's features
fails at compile time (a `const` assert on `CARGO_BIN_NAME` and
`test-formats`; checked: `final-verify` under `test-formats` refused).
`check-no-std` builds both, the final verifier and `vos-statement` without
`test-formats` for thumbv7em and wasm32. The Wasm blob gains a
`test-formats` feature (`vos-statement`'s), built into
`target/test-formats` by `judge-wasm`; the runner's `judge` takes the
formats the blob links (`39`, `28,39`). The runner's lock drops postcard.

**`just check-no-test-formats`** (in `check` and `ci`, beside
`check-no-seeded-masks`): every package's enabled features
(`cargo tree -e no-dev -f '{p} {f}'`) of the workspace and of the agent,
the Wasm blob and its runner, none `test-formats`; `vos-statement`'s
`fixtures` and `pvm-guest` do not imply it. The fuzz crate, built apart,
fuzzes 28 too and is no venue. `cargo tree -e features` without `-i` shows
only the features a dependency's declaration names, not those enabled
through another feature (the blob with `--features test-formats` showed
none), so both checks now read `{f}`: `check-no-seeded-masks` had the same
gap.

**The consumers:** the recursion tests run 28 on the test guest and 39 on
the production guest, which refuses 28 as `Format` in its words mode; the
kernels' end-to-end judgements (`judged_statement`, 28, rootless, not
venue-bound) on the test guest; the fuzz goldens are the fixtures' (39's
`valid` and `rootless`, 28's), `statement_decode`'s oracle each accepted
statement's format linked and accepted, its pin, its venue prefix if
venue-bound, the proof the golden of its format and words; the seed reads
the five wraps. Each target 60 s [measured]: `final_verifier_bytes` 72,550
runs, `final_verifier_mutate` 1,234, `statement_decode` 45,088, no crash.

**Docs:** `proving.md` §3.6 (the check order, `Seen` and time) and A.6
(the cases at 39, the table); `spaces-pallet.md` (`judge(&venue, &pin, …)`,
`Pin`, code 7 landed, `seen_expiry`).

**For the review (Fable):**
- the format check refuses an unlinked format as `0x2` even when the
  venue's policy accepts it, so a production venue's verdicts on 28 never
  depend on its policy;
- `Admitted::verify` passes `&[format]` as the accepted set, after `admit`
  checked the venue accepts it;
- `public_args[..32]` compares the raw bytes: the venue's id is the
  kernel's first `#[public]` argument, SCALE of `[u8; 32]` its 32 bytes;
- the model's `anchored` holds the age by the venue's `now_ms`, so
  `anchored` and the `Seen` expiry meet at `now = B_wmax + MaxRootAge`
  (both still alive);
- the production guest's size against 512 KiB (4,000,000 B is JAM's
  bound).

**Gates:** `just check` green (88 test binaries, 1,199 passed, 0 failed;
a first run failed `doc-check` on the final verifier's intra-doc link to
`unmasked`, a module no longer built without `test-formats`, now plain
text); `just judge-wasm`; the fixtures' stale and judged tests;
the test-proof binaries (`gates`, `isa`, `kernel`) build. The milestone's
`test-proof` (the kernels' end-to-end judgements now on the test guest) is
not run here.

**Commits:** `152f4902` the step; `057a134c` this record.

**Reviews:** Fable ACCEPT (`6.5-fable.md`: pin F's order as built, `seen`
before the proof on every host with state; the `Seen` rule and the anchor
age meeting at `now = B_wmax + MaxRootAge`, no race from lazy pruning,
since `anchored` reads the age live; refusing an unlinked format `0x2`
whatever the policy; every field of the id and io-hash preimages
replayed; the `{f}` build checks catching a feature enabled through
another; one guest, two bins; two low findings, three nits, three notes for
6.19); Opus, no correctness defects. Folded (`4202ae3f`):
- **Fable 1:** `MaxRootAge` is never raised in place; a raise is a
  migration that first prunes anchors older than the old bound (a `Seen`
  expiry computed with the old bound, `anchored` with the new, would make
  an unpruned anchor fresh again after its entry was dropped): pin F,
  `spaces-pallet.md` §6.5, 6.19;
- **Fable 2:** `Admitted`'s fields private, `format()` and `id()` its
  accessors, so only `admit` makes one and `verify` cannot be reached
  around its checks;
- **Fable 3, 6, 7, into 6.19:** an undecodable statement is code 1 in the
  service's `Verdict`, as at the pallet; the service's binding bounds are
  4,000,000 B of code, refine ≤ 150M and accumulate ≤ 2M gas, CE 133's
  204,802 B and the guest's `.bss` against JAM's refine memory, so it may
  cross 512 KiB freely; the plan's risk row "the JAM program over 512 KiB"
  retired, and the 512 KiB comparison dropped from this entry, `proving.md`
  and the size test; on JAM refine reads no `Seen`, so a replay costs a
  full refine (about 110M gas) before accumulate's `6`: the defence there
  is the package's cost, not `seen`;
- **Fable 4, Opus 2, 3:** the build checks are one private recipe
  (`_no-feature`): `cargo tree … -e no-dev --target all -f '{f}'`, each
  package's features split and compared whole, for every target;
  `vos-statement`'s `fixtures` and `pvm-guest` checked by `cargo tree -p
  vos-statement --features fixtures,pvm-guest` (each refusal checked: the
  blob, `vos-statement` and `vos-pvm-recair` under the feature fail it);
- **Fable 5:** two fixtures, the roots' order swapped and a root dropped,
  `0x108` at every venue (31 cases, `statements.cases` 19,252 B; the
  proofs byte-identical);
- **Opus 1:** `final-verify` refuses `test-formats` by `compile_error!`
  (the `CARGO_BIN_NAME` assert gone); the guest at `src/bin/guest/mod.rs`;
- **Opus 4–8:** `let spaces = &self.spaces`; the venue prefix by
  `starts_with`; the generator's three `statement.clone()`s dropped and the
  test venue's closure named once; the model's `Range { from, until }` with
  `contains`, `Space::encode_to`/`decode_from`, a redundant annotation
  dropped; the fuzz seed reads every `wrap*.proof` under the fixtures (the
  segment proof is no wrap).

**Gates after the fold** [measured]: `just check` green but for one test
of 6.12's merged before it, `cuts::an_idle_agents_leader_appends_one_marker_at_its_own_clock`
(`node/host/tests/cluster/cuts.rs:141`, "one result appended: []": the
marker's result not yet read when `cut(0)` is), which passed alone three
times and in the whole `cluster` binary twice; that stage rerun in full:
green (95 test binaries, 1,215 tests over both stages). `just judge-wasm`:
31 of 31 fixtures as recorded by each blob under each semantics; valid
47,443,507 instructions under the PVF's semantics; the two new cases about
5.7M. The JAM-only host: 31 of 31 on both guests; the production program
523,607 B (ELF 847,872 B), the test guest's 611,088 B.

**6.5 accepted.**

## Step 6.6: the masking's gates

Branch `s6/gates` (from `vos-core` `4e4b168d`). The full record is the
step's log; the transcript note for Fable, pin B step by step with R1–R4,
`6.6-transcript.md`.

**Built:**
- `masked::prove_masked_unchecked` (under `seeded-masks` only): the prover
  without its out-of-domain check, so a test hands the verifier a forced
  proof; `check-no-seeded-masks` covers it. `MaskStats::classes`, the
  column classes R1 checked. Feature `heavy-gates` (no code) for the
  full-N tests, which `just test-proof` runs.
- The tests (`recair/tests/circuit/masked_gates.rs`, `circuit/leakage.rs`,
  `common/leakage.rs`, `recursion/masked.rs`); what 6.2–6.4 held (S1, S4,
  S5, S7, S10) reused, not duplicated.
- `+unaligned-scalar-mem` in `riscv64em-vos.json`: the JAM refine
  program's ELF 962,768 → 906,904 B, every JAM-host test green on it.
- A `test-proof` failure from before fixed: the registry's round-trip test
  admits 39.

**Soundness gates** [measured]:
- **S2:** the small format at `[8,8,8]` … `[12,12,12]` and three mixed
  sizes, on Blake2b-256 and Poseidon2-M31, all verify, R1 in one attempt;
  `[17,15,12]` on both channels under `heavy-gates`.
- **S3:** `p2`, `qm31` and `h8` tampered at rows 0 and N−1 and across the
  wrap row: the prover refuses, the forced proof is refused by
  `OodsNotMatching`.
- **S6:** a verifier laying the preprocessed columns at `n` refuses a
  proof committed at `n+1`, no panic.
- **S8:** an unbalanced `qm31` relation refused by the logup total; with
  `b_0` set to cancel it, refused by the prover and, forced, by
  `OodsNotMatching`.
- **S9:** 80 malformed shapes (75 of the proof, 5 of the claim; the step
  commit's message says 87): every one an error, none a panic.

**Leakage gates** [measured] (α 10^-3 over the four statistical tests,
Bonferroni within each):
- **R1** on every class, both channels, every size: the classes equal those
  the sample points define (2 uniform, 6 mixed and the wrap).
- **Witness indistinguishability:** a private-witness circuit, small N = 64
  (7,546 hypotheses) and N = 2,000 (`heavy-gates`, 6,000 proofs), smallest
  p 2.4e-4 and 2.7e-4; the real wrap, N = 32, one-segment roots under
  kernels 6,000 and 6,001 (a deviation: their public words differ in the
  program id), 15,161 hypotheses, smallest 1.7e-3; 0 refused each. The
  unmasked control: 3,159 of 3,441 and 10,936 of 11,685 refused.
- **Uniformity:** 0 refused at every size; hidden states: none of 26
  needles found in the fixed layout, postcard or public words (all but the
  halves and the arguments' hash found in the unmasked postcard); fresh
  randomness: no opening shared between two proofs, of one witness or one
  seed; the claimed sums' control; the varying shape each proof's coins'.
- **Power** [est]: regression guards for gross leaks, not evidence of zero
  knowledge (R1 on every proof is the argument): at N = 2,000 a spread leak
  of total variation 0.133 (90%), a concentrated one 0.081.

**The verify gates** [measured], the one-segment masked wrap at 12 seeds,
each on the JAM-only host and by the Wasm blob under the PVF's semantics:

| build | decode max | verify max | Wasm (PVF) max |
|---|---|---|---|
| `+e,+m` | 3,753,586 | 107,205,040 | 47,953,712 |
| `+unaligned-scalar-mem` | 1,854,534 | 88,841,110 | (same blob) |

On this hybrid CPU a thread on an E-core counts nothing on the P-core PMU;
the runner is held to the performance cores.

**Commits:** `03be35ce` (the gates), `cde8d399` (the unaligned loads),
`c743e6ee` (the round-trip test). `just check` green (1,206, 0 failed);
`just test-proof` green (550, 0 failed).

**The review** (Opus), folded in `edb9729d`:
- χ² at 4 buckets for 64 values or fewer a side, the one-sample test exact
  there (a multinomial DP over Σ o²), the two-sample test's rate simulated
  below nominal; the real wrap's uniformity over both witnesses (30,320
  hypotheses); power restated in `SECURITY.md`;
- S3's forced proofs refused by `OodsNotMatching` alone: `qm31` broken on
  padding rows turned to both ends, the wrap row's permutation recomputed
  from another input (the second wrap case dropped);
- the Wasm runner holds itself to the performance cores
  (`sched_setaffinity`) and compiles for `x86_64-unknown-linux-gnu` at
  x86-64-v3, its flags in `RESULT` (`isa=`): counts equal the host's
  (47,953,714 on seed 9; 48,560,787 at v2);
- **the Wasm margin:** the host allocator's 10,632–10,644
  malloc/free calls a verify cost 10.5M instructions (21.9%: an in-guest
  bump allocator, built apart, gives 47.95M → 37.45M on seed 9); the
  verify gates asserted at the worst shape along the seeds' fit (2,768
  witness hashes: 1,732 trace, 1,036 FRI): **Wasm 49,617,103** of 50M,
  decode 1,871,887, verify 91,910,997 [est, extrapolated; asserted].

**After the fold** [measured]: `just check` green (1,206, 0 failed); the
heavy tests unchanged in verdict (wrap N = 32 at 4 buckets: smallest p
1.1e-4 and 4.5e-6, 0 refused; the unmasked control 8,764 of 11,685
refused). **Merged** into `vos-core` as `8e0dc742`; `just check` after
the merge with 6.7: green, 1,228 passed.

**6.6 accepted.**

## Step 6.6b: the final verifier's Wasm count, headroom

6.6 put the masked verify at 49.6M Wasm instructions at the worst shape
against the 50M gate, the host allocator's malloc/free calls about 22% of
it. 6.7's checks moved it to 49.78M. Stwo unchanged.

**Where the allocations were** [measured: a native build of the verifier
under a counting allocator with a backtrace a call, seed 9; its count
equals the blob's host calls within 1%]: 10,715 a decode and verify:
- decode 1,015: 988 column vectors (482 sampled columns with samples, 506
  queried columns), the rest the trees', witnesses' and layers' vectors,
  all of them `CommitmentSchemeProof`'s fields, by value;
- **the component set laid out twice**, 2,104 + 2,100: `verify_with`'s
  layout (dummy relations, for the shape before the transcript) and
  `replay`'s set under the drawn relations, each three
  `FrameworkComponent::new`s whose `InfoEvaluator` runs every body;
- **the sample points made twice**, 537 + 537: at zero for the shape, at
  `z` for `verify_values`;
- the composition at `z` 574 (the constraint framework's
  `PointEvaluator`); Stwo's `verify_values` 3,656.

**Built:**
- `MaskedComponents::bind` (`vos-pvm-recair-air`): the set laid out once,
  evaluated under the drawn relations and the proof's claimed sums by
  `Rebound` components, each the layout's `FrameworkComponent` for its
  columns, masks and preprocessed columns and another evaluation of the
  same body for its constraints, `FrameworkComponent`'s evaluation at a
  point over the layout's columns. A layout depends on no relation or
  claimed sum. `replay` binds `layout` instead of building `C::new`.
- `sample_points_from_zero`: the points at `z` from those at zero in place,
  each point at zero its mask's offset from the identity, so `z` (and
  `π(z)` for the composition's coordinates) added to it gives
  `sample_points(set, z)` exactly. `replay` makes the points once; the
  second `samples_fit` (the same lengths) is gone.
- Tests: the points from zero equal `sample_points` at two points; the
  bound layout's composition at a point equals the set built under the
  same relations and claimed sums (and differs from the unbound
  layout's), its metadata the built set's.
- `SECURITY.md` row 5: format 39's evaluation is `Rebound`, the same code
  over the layout's columns, the same guard.

**Measured** [measured; the 12 gate proofs of 6.6 (seeds 1,000–1,011),
before at `2276ed9a` and after, the same machine]:

| | before | after |
|---|---|---|
| host allocations a verify (Wasm) | 10,646–10,658 | 7,962–7,974 |
| Wasm, PVF, max over seeds | 48,117,322 | 44,778,408 |
| **Wasm at the worst shape** (2,768 hashes, the seeds' fit) | **49,776,401** | **46,433,907** |
| JAM decode max (worst) | 1,814,035 (1.83M) | 1,814,057 (1.83M) |
| JAM verify max (worst) | 89,645,290 (92.71M) | 82,753,115 (85.84M) |
| JAM guest allocations | 10,641–10,653 | 7,957–7,969 |
| production program (ELF) | 481,761 B (795,288) | 485,237 B (807,832) |

The Wasm runner pinned to the performance cores at x86-64-v3; the seeds'
counts repeat. 7.1% under the gate at the worst shape (target ≤ 47.5M).

**What remains** (seed 9, 7,976 native): Stwo's `verify_values` 3,656; the
one layout 2,126 (the constraint framework's `InfoEvaluator`, an
`ArithmeticCounter` allocation an operation, and the preprocessed ids);
decode 1,006 (988 the columns `CommitmentSchemeProof` takes by value); the
composition at `z` 579 (`PointEvaluator`'s masks, `sub_tree`); the sample
points 557 (482 the columns `verify_values` takes by value); ours about 50.
A further cut is the fork's: the layout's `InfoEvaluator` (about 2,100,
about 2.1M instructions) or `verify_values`' own vectors.

**Gates** [measured]: `just check` green, 1,247 passed, 0 failed (the
fuzz corpus replayed among it); `just judge-wasm`: 31 of 31 fixtures as
recorded by each blob under each semantics, valid 44,276,308 instructions
under the PVF's (47,616,003 at 6.7), the three anchor vectors as pinned.
The fixtures unchanged.

**Commit:** `d3a7beeb`.

**The review** (Opus): ACCEPT, one Low, folded in `b353d8ba`: `Rebound`'s
fields private, `Rebound::new` refusing (`None`) an evaluation not at its
layout's log size and constraint bound, used by `WrapComponents::bind`
and the `P2Only` test set; a test of the refusal.

**6.6b accepted.**

## Step 6.7: panic-freedom by construction, and fuzzing in CI

**The lints** (`vos-pvm-final-verifier`, `vos-statement`, `vos-anchor`):
`clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `panic` and
`arithmetic_side_effects` denied outside the tests
(`#![cfg_attr(not(test), deny(..))]` in each `lib.rs`; a probe index made
the build fail). 54 hits fixed or allowed in place:
- fixed: the public words through `as_chunks` and `split_first_chunk`;
  `replay`'s trees and roots destructured (`Shape` otherwise), 28's
  commitments likewise; FRI's rounds and layer count by `checked_sub`;
  the queried columns by `chunks_exact`; the anchor codec's `array` by
  `first_chunk`, `u8` by a one-byte array, the compact's width and the
  bytes left without unchecked arithmetic, the genesis' node order by
  `is_sorted_by`; `judge_bytes`' proof by `get`; 28's degree bound by
  checked arithmetic;
- allowed, each with its reason: QM31's modular addition (the logup sums,
  39 and 28); the compact's big-integer mode (`width` at most 8 past
  `get_mut`); `vos-statement`'s `fixtures` reader (std, the harnesses',
  never a venue's).

**The fork's verify path, audited** at the pin (`ab294189`): 29 rows in
`SECURITY.md` (§ Panic-freedom), every index, `unwrap`, `expect`,
`zip_eq`, `assert` and unchecked arithmetic reachable from format 39's
`verify_masked` and 28's `verify` (`verifier.rs`, `pcs/{verifier,
quotients,utils}.rs`, `vcs_lifted/verifier.rs`, `fri.rs`, `queries.rs`,
`circle.rs`, `air/components.rs`, the constraint framework's point
evaluation), each with its guard: the shape checks (27 rows guarded by
the shape, the verifier's own values or a draw's probability: 2^-108 and
2^-123 for two inversions) and **two with none**, the fork's fix.

**The fork's fix** (`vos/verify-panics` `c3ec981` on `ab294189`, in
`~/src/virto/stwo-s6-panics`, **not pushed**: Fable's review first):
`complex_conjugate_line_coeffs` returns `InvalidStructure` for a sample
point whose `y` is its own conjugate (upstream's `assert_ne!`, 2^-62 a
draw); `denominator_inverses` for a conjugate line through the queried
point (upstream's zero inverse); `column_line_coeffs`,
`quotient_constants`, `accumulate_row_quotients` and `fri_answers` pass
the error on, the prover's callers `expect` it (and vos-core's recursion
witness, `column_line_coeffs`). A unit test each from a constructed point
(y in CM31; `q + u·I`, `q` the queried point). DIVERGENCE-013 in the
fork's log and `SECURITY.md`. The fork's stwo suite (`--features
prover`, 308 tests) and its workspace clippy (all features) green.
- **Finding, against 6.4's review:** the zero denominator is unreachable
  for z on the circle with Im(z.y) ≠ 0, not about 2^70 hashes: it needs
  Im(z) isotropic, and an isotropic Im(z) ≠ 0 with Re(z)·Im(z) = 0 (the
  circle) makes |Re(z)|² = 0 against |Re(z)|² + (2+i)|Im(z)|² = 1 (the
  proof in `denominator_inverses`' doc). The conjugate line's assert is
  the one proof-reachable panic at the pin; both are now errors.

**The temporary pin** (`dad6402d`, marked TEMPORARY LOCAL PIN): stwo and
the constraint framework `[patch]`ed to the fork worktree's path in the
workspace, the fuzz crate and the Wasm blob and runner; the re-pin to the
pushed rev replaces it.

**Fuzzing** (`pvm/proof/fuzz`), seven targets:
- the plan's five are the four before (`final_verifier_bytes`,
  `final_verifier_mutate`, its mutations now in `mutation.rs`,
  `statement_decode`, `prove_verify_roundtrip`) and the structure-aware
  target 6.4's review asked for, **`masked_shape`**; with
  **`masked_bytes`** and **`anchor_decode`**:
  - **`masked_bytes`:** format 39's layout past its pinned header, and
    whole; one encoding, nothing accepted but a golden;
  - **`masked_shape`:** the 39 goldens' queried parts remade within the
    layout's bounds, the transcript-bound parts kept, so every input
    reaches `verify_values`' Merkle checks, the DEEP answers and FRI's
    decommitments (`shape.rs`);
  - **`anchor_decode`:** `SpaceGenesis`, `Anchor`, `Migrate` and `Vector`
    decoded, one encoding each; the clock's window and boundary
    consistent;
- `prove_verify_roundtrip`'s gas 100,000 → 2,000; its runs need
  `target-cpu=native`, which `cargo fuzz`'s RUSTFLAGS replaced: without it
  one proof took over 10 minutes (the 2026-10-18 `slow-unit` artifact),
  with it about 8 s;
- the seed writes `masked_bytes`' and `anchor_decode`'s corpora;
- **the checked-in corpus** `fuzz/replay/<target>/` (cmin'd, at most 200
  inputs of at most 4 KiB a target, 880 files, 266 KB), replayed by `just
  fuzz-replay` in `check` and `ci` (`-O -s none`, native); **`just fuzz`**
  (five minutes a target from the corpus, beside the replay set) in
  `ci-full`; `cargo run --example paths` lists what each input reaches.

**Runs** [measured, 300 s each, six at once under one 16 GiB scope, the
machine loaded]: no crash, no panic, nothing accepted but a golden.

| target | runs | cov | corpus |
|---|---|---|---|
| `final_verifier_bytes` | 137,463 | 5,585 | 617 |
| `final_verifier_mutate` | 1,234 | 5,916 | 702 |
| `statement_decode` | 97,829 | 6,018 | 542 |
| `masked_bytes` | 39,970 | 4,213 | 163 |
| `masked_shape` (`-len_control=0`) | 3,979 | 4,393 | 281 |
| `anchor_decode` | 9,173,521 | 409 | 74 |
| `prove_verify_roundtrip` (`-O -s none`, native) | 37 | 16,166 | 20 |

**The paths the corpus covers** (`examples/paths`):
- 39 by bytes: `Format` (every header word), `Decode`, `Noncanonical`,
  `Shape` (four commitments, a tree's sampled columns, four trees of
  sampled values); 28: `Decode`, `Format`;
- 39 and 28 mutated: `Format`, `Noncanonical`, `Circuit`,
  `InteractionPow`, `Logup`, the shapes (four trees or commitments, a
  column's samples, a tree's queried columns, FRI's layers), OODS, PoW,
  Merkle (queried-value shape, root, witness short and long), FRI (first
  and inner layers' evaluations and commitments, the layer count), and
  accepted (mutations that cancel);
- 39 reshaped: `Noncanonical`, Merkle (shape, root, witness short and
  long), FRI's first and inner layers' evaluations and commitments,
  accepted;
- the venue: `Statement(Short, Noncanonical)`, `Format`, `Program`,
  `Venue`, `Space`, `Unanchored`, `Repeated`, `Proof(Decode, Format,
  Noncanonical, Shape)`;
- the anchor: each decoder's `Short`, `Noncanonical`, `Trailing` and a
  decode;
- not covered: FRI's last layer (its evaluations; its degree, held by the
  layout), the two degenerate DEEP lines (the fork's unit tests).

**Gates:** `just check` green (fmt, docs, the builds without std, both
feature checks, `fuzz-replay` over the 880 inputs, workspace clippy, the
tests) but for one test seen failing once under load,
`cluster::messages::a_reply_outlives_its_leader_stopping` (`left: 0,
right: 1` at `messages.rs:560`), which passed alone three times and in its
whole binary (85 of 85); the stage it stopped rerun in full: 424 passed,
0 failed. The three crates' tests green with and without `test-formats`.

**Commits:** `dad6402d` the temporary local pin; `7bf98c05` the step; this record.
The fork: `c3ec981` on `vos/verify-panics`, unpushed.

**Reviews:** Fable on the fork's fix: push; the coordinator pushed
`vos/verify-panics` (`c3ec9813`) to olanod/stwo. Opus ACCEPT with four
Low findings and four Info (`6.7-review.md`), folded:
- **the re-pin** (`bdb34aff`): stwo and the constraint framework at
  `c3ec9813` in the workspace and the fuzz crate, the four `[patch]`
  blocks gone, no absolute path left from the pin; the three lockfiles
  1d23a02e's but for the source rev (**L2:** the path patch had moved
  stwo's `hashbrown`, 0.16.1 → 0.17.1 at the root and 0.15.5 → 0.16.1 in
  the runner; now unmoved; the runner keeps 6.6's `libc`); SECURITY.md's
  pin and DIVERGENCE-013;
- **L1:** row 30, FRI's line-fold inversions (`fold_line`,
  `fold_circle_into_line`), guarded by the verifier's own domains; "6, 7,
  20 and 30" the only inversions;
- **L3:** the JAM program's payload (`as_chunks::<4>`, `get(used..)`, a
  `get_mut` and saturating cursor, the payload's length by `get`) and the
  Wasm blob's words (`as_chunks`) and malloc size (checked), both roots
  under the denies, linted by `just check-no-std` for their targets (the
  guest's two bins, the blob with and without `test-formats`); the guest's
  allocator allowed with its reason (sums of `Layout` sizes and arena
  offsets), `Request`'s size difference allowed;
- **L4:** `unreachable`, `todo` and `unimplemented` denied too; no
  `assert!` outside the tests, `split_at`/`copy_from_slice` once at equal
  lengths (SECURITY.md);
- **Info:** `shape.rs`'s bounds from `masked::CONFIG` and
  `LOG_DEGREE_BOUND`; `just fuzz`'s sanitized targets under `-a`; the
  recursion witness's `expect` names its precondition; the replay's cost
  (about 38 s warm, 35 s of it the prove target's three inputs) kept in
  `check`.

**Gates after the fold** (`d6545360`) [measured]: `just check` green,
1,228 passed, 0 failed (`RUST_TEST_THREADS=4` under 12 GiB; a first run
at the default threads was OOM-killed at 12 GiB in the recursion tests);
`just judge-wasm`: 31 of 31 fixtures as recorded by each blob under each
semantics, valid 47,616,003 instructions, the three anchor vectors as
pinned.

**6.7 accepted.**

## Step 6.8: the recursion AIR's forgery gates

**Built** on `s6/forgery` (from `27967322`): a new test binary,
`pvm/proof/recair/tests/gates/`, each gate a malicious prover.

**The malicious prover** (`gates/forge.rs`): a copy of `prove_on` that
skips `check_wiring` and Stwo's closing `ConstraintsNotSatisfied` check (a
copy of the pinned `prove_ex` without the comparison, every piece public
in the fork; its doc says to re-check it when the pin moves), and states
any outputs and, optionally, any claimed sums. Helpers: `balance` (every
use carries its yield's value), `settle` (balance, then recompute every
`qm31` row whose output is a yield, to a fixpoint: no `h8` fixpoint, said
in its doc), `rewrite_input` (a `p2` row's permutation over a chosen
input), `force_output`. The refusals by name: `LOGUP` (the claimed sums
and the public terms do not add to zero), `DEEP_ALI` (Stwo's
`OodsNotMatching`), `ANOTHER_CIRCUIT` (the proof is of another circuit).
The control: the forger proves honest traces that verify.

**The gates (20 tests):**
- **`p2`'s modes and chaining** (`p2_modes.rs`): a circuit ending in each
  mode, its last row computed by each other mode's rule (40 of 42 pairs
  differ), a leaf's second block continued from another leaf's row, a leaf
  restarted midway, an absorption chained from the zero digest, a Merkle
  node over another child or in the order its bit does not pick: each
  balanced, each `DEEP_ALI`. The forger's mode model equals the AIR's on
  every honest row.
- **The signed multiplicities, R12** (`multiplicities.rs`): a use carrying
  another value → `LOGUP` (`DEEP_ALI` with the claimed sum moved); an
  output added (the wire's own value too) or dropped → `LOGUP`; a yield
  consumed once more: `check_wiring`'s `Unbalanced`, its proof
  `ANOTHER_CIRCUIT`, `LOGUP` under its own hash; a second yield, balanced:
  `YieldedTwice`, `ANOTHER_CIRCUIT`, and accepted under its own hash
  (asserted). The plan's "negative multiplicity" is this gate: a
  multiplicity is preprocessed, so its only form is a use turned yield.
  The relation sees multiplicities, not yields; §1.1's design (the single
  yield per address is static, the circuit hash pins the wiring) refuses
  it, because every pinned hash comes through `check_wiring`.
- **`assert_one_of`** (`one_of.rs`): a small circuit (3 candidates and an
  empty slot): a hash outside the set with a bit on each candidate, no bit,
  two bits, ½ on two → `LOGUP` as built, `DEEP_ALI` balanced; the fold,
  a child claiming a slot its program does not hold → `["fold: circuit"]`,
  `LOGUP` / `DEEP_ALI` against `H_fold`; the wrap's → exactly
  `["wrap: circuit"]` (not proved: the forger is `P2`-channel, the wrap
  Blake2b).
- **The lanes** (`lanes.rs`): an unread lane set nonzero is accepted with
  the honest statement (it states nothing); a circuit reading lane 1 is
  refused at `finalize` (`UnreadLaneRead { lane: 1 }`); the window
  kernel's leaf, a small kernel's leaf, the fold and the wrap finalize
  (40 / 80 / 176 / 88 rows absorbing in part).
- **The boundary bytes** (`boundary_bytes.rs`): `b + 256` at a byte of
  every field outside φ9..12 and three aliases `(b + 256, b' − 1)`, 12
  forgeries, the interaction PoW reground over the moved transcript →
  `logup`, `oods` with the sums forged; proved → `LOGUP`; one balanced
  leaf forgery (the φ0-out alias; its 40 query paths forced to one root) →
  `DEEP_ALI`; under the proof's own challenges each alias misses the
  claimed sums natively. "logup" here is the Fiat–Shamir binding as much
  as the tuple (the module doc).
- **The pins** (`pins.rs`): no source in the workspace calls
  `preprocessed_columns(` or `circuit_hash(` (however imported) but
  `prove.rs`, the definitions, the in-AIR child hash (`fold/{mod,child}.rs`)
  and the forger.

**In the compiler** (Fable 1, 2): `Circuit::check_reads`, run by
`check_wiring` (so `circuit_commitment`, `prove_on` and `finalize_to`
refuse): `UnreadLaneRead` (the lane audit, `Circuit::unread_lane_reads`),
`FreeOperandRead` (a `qm31` operand of multiplicity 0 under a coefficient
or λ) and `FreeMessageAbsorbed` (a `p2` message of multiplicity 0 with a
nonzero `act` outside a Node row), at address 0 or at any address a wire
holds; a guess read once stays admitted only at an address of its own.
Only entries of nonzero multiplicity hold an address, public uses
included: the re-review asked for "any multiplicity", which refused a
valid `p2` row with no output use (its out addresses 0 and 1 stated, the
`one` wire's row in an h8-only circuit). No production circuit changed;
the test circuits that read unread lanes absorb whole wires. Also:
`assert_one_of` moved to `gadgets` (`pub use` in `fold`), `Qm31Op::apply`
and `reads` shared by the context, `compile/program.rs` and the forger.

**Verdict:** no forgery accepted; M2 not stopped.

**Cost [measured]:** the gates 20 tests, ≈74 s, 3.6 GiB peak, in `just
check`.

**Gates:** the stale-fixture test byte for byte (370 s, 4.0 GiB); recair
circuit 26/26, gates 20/20, recursion 48/48; `just check` green at
`b7740589` (1,130 passed), `e51d7081` (1,134) and `8ac8b135` (1,135), 0
failed.

**Commits:** `b7740589` the gates; `3d5efc86` the fold's sources and
circuit tests, `e51d7081` its gates and docs; `8ac8b135` the re-review's
fixes. Merged into `vos-core` as `17102cf5`, `recursion-air.md`'s §11
conflict resolved: R12 6.8's text, R13 the measured masking costs.
`b59435fb` at the merge: `pins.rs` matches whole identifiers, so Stwo's
`new_with_preprocessed_columns` (the masked components' allocator) is not
a caller.

**Review:** Fable, accept after fixes (every refusal re-derived from the
verifier's source, the gates re-run); Opus, cleanups. Folded:
- **Fable 1, 2 (medium):** the lane audit and the two unchecked members of
  the second-yield class moved into `check_wiring`, above; refusal tests
  in `circuit/gate_vm.rs`.
- **Fable 3 (low):** `pins.rs`, above.
- **Fable 4 (low):** the balanced leaf forgery and the native tuple check,
  above.
- **Fable 5, 6, 7 (low):** the negative multiplicity named; the wrap's
  `assert_one_of` gated; `settle`'s missing `h8` fixpoint noted.
- **Opus:** R12's row rewritten; the forger's helpers
  (`qm31`/`set_qm31`/`set_message_lane`, `add_another_x`, `H8_STARTS`,
  no `Clone` on `Forgery`); `common::kernel::whole_run()` shared; `fields()`
  asserts its end at `BOUNDARY_STATE_BYTES`.
- **The re-check:** merge after two fixes, both in `8ac8b135`: a free read
  at a used wire's address refused (`a_disguised_free_read_is_refused`),
  with the deviation above; `pins.rs` matching `circuit_hash(` however
  imported.

**Carried:** to 6.13 / 6.18: a program id's leaf-circuit hashes are
computed in the prover role; 6.18's gate pins the known constants, but a
venue trusts a submitted id only by recomputing it from the blob (the
second yield shows why: an id computed over an unchecked wiring is a
malicious verifying key for that id). In the plan.

**6.8 accepted.**

## Step 6.9: format 36 retired, the refine-bundle path deleted

Branch `s6/fmt36` (worktree `.worktrees/s6-fmt36`) off `vos-core`
`85c1853b`; merged into `vos-core` as `af330a2c`.

**Commits:** `78b35749` the refine-bundle path deleted (+102 −4,552);
`cfe30c59` format 36 retired (+205 −1,236); `0399fa05` the docs (+50
−86); +352 −5,869 over 54 files; `b9957a18` the review's fold.

**Deleted:**
- `pvm/proof/src/refine.rs` and `refine/` (`collector.rs` with
  `observed_step`, `encode.rs`, `prover.rs`, `tests.rs`), `refine_codec.rs`
  and its tests, and their re-exports (`prove_refine`, `trace_refine*`,
  `verify_refine_bundle_replayed`, `RefineProofBundle`,
  `encode/decode_refine_proof_bundle`);
- `vos-pvm-proof-verifier`: `verify_refine_bundle_authenticated`,
  `RefineProgramCommitmentResolver`, the refine re-exports,
  `tests/refine_bundle.rs`;
- `prove.rs`'s `replay_trace_binding` and `ReplayTraceBinding`;
  `proof.rs`'s `public_io_hash_from_registers` folded into
  `Proof::public_io_hash`;
- with 36: `format::LEGACY_SEGMENT`, `LEGACY_SEGMENT_NUMBER`, `Encoding`
  (only `Lossless` was left, so the enum, `Format.encoding` and
  `exact_params` went: every format takes exactly its parameters);
  `proof/policy.rs` whole (`PcsPolicy`, `check_pcs_policy`,
  `check_shape_policy`, `check_min_security`,
  `MIN_CONJECTURED_SECURITY_BITS`, STANDARD/MOBILE), which existed for 36's
  free parameters; `prove_mobile`, `prove_with_config`,
  `prove_profiled_with_config`, `production_pcs_config(_mobile)`,
  `Target::legacy`; `verify_with_pcs_policy`,
  `verify_standalone_with_pcs_policy`; the zero-bits branch of
  `check_interaction_pow` (every format grinds 8 bits);
- the fixtures `segment-36.{proof,root}` and
  `segment-36-{tampered,wrong-format}.patch`.

**Changed:**
- `prove`, `prove_profiled`, `prove_canonical`,
  `program_commitment_for_profile`, `prove_chain`,
  `prove_with_explicit_components` (its config parameter dropped),
  `prove_with_boundary_override` and the relabel seam produce 35
  (`Target::SEGMENT`); `PROOF_FORMAT_VERSION` is `SEGMENT.number`;
  `verify_with_explicit_components` lost its policy parameter;
- `RETIRED` = `[24, 25, 26, 27, 29, 31, 33, 34, 36, 40]`, 36's reason in its
  doc (the legacy Blake2s segment format, 57 proven bits at its MOBILE
  shape, below the inner formats' 60);
- `kernel.rs`: `load` takes arguments (the window mapped read-only);
  `trace_program(blob, arguments, gas)` beside `trace_kernel` (kernels'
  identities unchanged);
- `pvm/bench`: `precompile_agreement`, `diverse_proof`,
  `precompile_tamper` and `bin/precompile` trace with `trace_program` and
  prove and verify under 35; the tamper test proves the tampered trace and
  verifies against the honest one; `tamper-stark` merged into `tamper`;
- the fixture generator: `FORMATS = [(&SEGMENT, WRAP.number)]`; 35's
  wrong-format patch relabelled 36 → 28 (refused as "does not name segment
  proofs"); 35's proof, root and tampered patch unchanged;
- the tests on 36 moved to 35 (`precompiles`, `chip_isolated`,
  `arith_gate`, `host_verify_boundary_gate`, `alu`, recair `leaves`, the
  verifier's `standalone`, `formats`, `segment_cost`, `program_id`), the
  policy tests and `prove_mobile_smoke` deleted; `benches/prove.rs` on 35,
  its PCS-config and security sweeps deleted; `bin/mobile_bench` on 35;
- docs: `proving.md` A.4 (36's row dropped, the retired list takes it),
  §4's note, the numbers note; `core-model.md` §11.4 (doc-fixes 12);
  `SECURITY.md`; `pvm/proof/README.md`'s example; `docs/status.md`;
  `docs/plans/roadmap.md`.

**Gates:**
- no producer or verifier of 36: the grep for `LEGACY_SEGMENT`,
  `Encoding::Legacy`, `Target::legacy`, `PcsPolicy`, `prove_mobile`,
  `prove_with_config`, `production_pcs_config`, `verify_with_pcs_policy`,
  `refine_codec`, `RefineProofBundle`, `verify_refine_bundle`,
  `prove_refine`, `trace_refine`, `check_min_security` finds only `spikes/`;
  36 is in the code only in `RETIRED` and its doc;
- `pvm/bench` on 35: `precompile_agreement`, `just test-bench-proof`
  (`diverse_proof`, `precompile_tamper`) pass; `precompile prove 10`: 3,395
  steps, prove 3.37 s, verify 0.33 s, 1,717 KiB, peak RSS 1,439 MiB
  [measured, release, format 35]; `precompile tamper 1 call-input` refused
  ("claimed logup sum is not zero");
- `just check` green; the proof suites (`--lib --bins --test gates --test
  isa`, debug-internals: 78, 221, 208 + 3 after the test actors were
  built); `--test kernel` filtered to `fixtures`, `prove_chain`,
  `chain_standalone`, `program_identity`: 11 pass, the generator matching
  every fixture. The full `test-proof` is left to M2's acceptance.

**For 6.22** (quality items gone with the deleted files): item 11
(`observed_step`, `TracingPvm::step` the one recorder), item 25's first
sub-item (`refine_codec` ≡ `refine/encode`; entry 13's 28-bit
decomposition is in `memory.rs` and `register_memory.rs`), item 35's
`verify_refine_bundle_authenticated`.

**Left:** the runtime's observed refine path (`RefineContext::run_observed`
and its types, `InnerMachines::invoke_observed`,
`Machine::continue_observed`; `Machine::resume_observed` still used by
`pvm/bench`); `ChannelKind::Blake2s`, `StarkProofAny::Blake2s` and
`Commitment::Blake2s` (removing them moves postcard's variant indices and
every 35 proof's bytes); `spikes/s5-attestable` and
`spikes/s5-precompile/harness`, which no longer build.

**Review:** Opus ACCEPT with small fixes, folded in `b9957a18`: every
format's `interaction_pow_bits() > 0` asserted; `transcript.rs`'s long doc
line rewrapped; `roadmap.md` names format 36's MOBILE bench; the plan's
6.22 gains entry 21 (the runtime's observed refine path deleted, keeping
`Machine::resume_observed` and `Interpreter::run_observed`; `with_stack!`'s
Blake2s arm to `$unbuilt`; the two refine spikes deleted before master).
Gates: clippy (all targets, debug-internals), the format tests (13),
`doc-check`, `fmt-check` green.

**The merge** (`af330a2c`): one conflict in `format.rs`, 6.3's `masking:
None` on the deleted `LEGACY_SEGMENT`, resolved by dropping the block;
`just check` after the merge 1,170 passed.

**6.9 accepted.**

## Step 6.10: `vos-anchor` and the space's genesis

**Built** on `s6/roots` (from `423ec694`):
- **`pvm/proof/anchor` (`vos-anchor`)**, no_std, `blake2` its one
  dependency, SCALE by hand and canonical (`codec.rs` moved here from
  `vos-statement`, public). Pin D's types: `SpaceGenesis` (a decode
  refusing any version but 1, a non-shortest count, no node, numbers not
  strictly ascending, a short or trailing input; its encoding writes
  `GENESIS_VERSION`), `WindowClock` (`window`, `boundary`, `registrable`
  120,000–3,600,000 ms, `representative`, `DEFAULT` origin 0 and 600,000
  ms), `SpaceId` (`NONE`), `VenueId` (`jam`), `RootKind { Space = 0 }`
  (every other byte `Noncanonical`), `RootRead`, `Anchor`, `Migrate`; the
  digests `space_id`, `space_root` (`S_w`), `anchor_digest`,
  `register_digest` (with `start_window`); the constants, among them
  `MAX_FOUNDING_KEYS` (16). Feature `vectors`: the golden vectors.
- **`vos-statement`** re-exports it, its own codec, `SpaceId`, `RootRead`
  and `blake2` gone; a statement of an unknown root kind is refused at
  decode (code 1 at every venue). `admit`'s space rule: a rooted statement
  claims a space other than `NONE` (code 4; pin F's rule amended).
- **`vos-pvm-precompiles`:** the kernel's own `RootKind` with its `u8`
  wire form (the crate stays dependency-free); both kinds agree on all 256
  bytes (a statement test).
- **Wire and agent:** `vos-pvm-codec` feature `anchor`; `vos-wire`
  re-exports; `CreationRecord.space`; `Admin::Install` gains `space` and
  `clock`; `keys::space()` = `00 19`, `keys::clock()` = `00 1a`;
  `Failure::Space = 14`, `Refused::Space`. The default agent writes target,
  space and clock once, at the first install (a partial set is `Corrupt`),
  and refuses a later install naming another space or clock before the
  target check; the testkit's model the same.
- **Node:** `<space file>.genesis` beside the space file (hex, written
  once); `Space::{genesis, id, clock, found}`, its id cached; without a
  genesis `SpaceId::NONE` and the default clock. `peer::check` refuses a
  record naming another space (`Refusal::OtherSpace`).
- **`vos space up --space <file> [--window-ms] [--origin-ms] [--data]`:**
  founds the genesis of 1 to 16 listed nodes, refuses a non-registrable
  length, an existing genesis and a founding node that holds an agent,
  warns on an origin past the founding time, prints the id and the
  founding procedure (found before the first agent, copy
  `<space>.genesis` beside every node's space file, restart).
- **Fixtures regenerated** (their roots were kind 1): the wrap proofs and
  `statements.cases`; the segment fixtures byte-identical (142 s,
  release [measured]).

**Venues** (3 golden vectors: one founder at window 0; three founders at
w 2,966,001 from 2,966,000; every integer at its top with 64 founders, a
two-byte count): natively (and an independent Python recomputation at
pinning); in Wasm (`just judge-wasm`, PVF and client semantics, a vector
cut short refused; blob 311,263 B [measured]); in the PVM, `final-verify.elf`
mode 2 on the JAM-only host (0.10M / 0.12M / 0.46M gas [measured]; ELF
811,720 B). The 13 statement fixtures judged as recorded at every venue.

**Pin D / `spaces-pallet.md`:** byte for byte, no disagreement.
Under-specified in both: `NodeNumber`'s width inside `SCALE(genesis)`,
now `pub type NodeNumber = u8` in Pin D.

**Tests:** `vos-anchor` (14: encodings field by field, canonical decode,
windows at their edges, registrable lengths, the representative's clock,
unknown root kinds, every digest its preimage, no domain a prefix of
another, migration, the golden vectors); the codec's encodings; the
statement's (unknown kind, the kinds agree, a rooted `NONE` refused);
precompiles; wire bytes; the testkit's
`an_install_into_another_space_than_its_agents_is_refused` (VOS node and
JAM-only host); node `a_space_keeps_its_genesis_beside_its_file`,
`a_wrong_genesis_is_refused`, the peer refusals; cluster
`an_agent_belongs_to_its_nodes_space` and a member founded under another
genesis holding no replica; CLI `a_space_is_founded_once`, the founder
bounds (0, 1, 16, 17), a founding node holding an agent.

**Gates:** `just check` green at `6936e9cb` (1,134 passed, 0 failed; no_std
`vos-anchor` for thumbv7em and wasm32) and at `9476dc13` (1,136 passed, 0
failed); `just judge-wasm`; the stale-fixture test and
`the_fixtures_are_judged` (fixtures unchanged by the fold).

**Commits:** `ca8fbb14` `vos-anchor`, `vos-statement`, precompiles, the
venues' harnesses, the fixtures, `proving.md` §3.6; `6936e9cb` the genesis
(codec, wire, default agent, testkit, node, `vos space up`); `9476dc13`
the fold. Merged into `vos-core` as `85c1853b`.

**Review:** Fable ACCEPT with fixes (all 15 golden digests recomputed
independently, every preimage and encoding agreeing with Pin D and
`spaces-pallet.md`); Opus, sound with findings. Folded in `9476dc13`:
- **Fable 1:** a rooted statement claiming `NONE` refused as `Space`,
  above.
- **Fable 2:** `peer::check` and `Refusal::OtherSpace`, above.
- **Fable 3, Opus 2:** `space up --data` and the founding procedure in
  Pin D, the help, the output and `space.rs`'s doc; write-once kept, no
  adoption from `NONE`.
- **Fable 4, 5:** founders 1 to 16 and `NodeNumber = u8` pinned in Pin D
  (the 64-founder vector stays: it pins the encoding).
- **Fable 8, 9:** `GENESIS_VERSION` written; the origin warning;
  `with_genesis`'s doc.
- **Opus:** the genesis decode's refusals, above; `hex` in `space.rs`;
  `space up`'s duplicate check dropped (`create_new` refuses);
  `WindowClock::DEFAULT` (the testkit, the node, the JAM testnet);
  `Inner::space_and_clock`; `SpaceGenesis::id` removed for `space_id`;
  docs.

**Carried** (in the plan): 6.12 / 6.13: an agent of no space runs no cuts
and refuses `attest_at_cut` (`AttestError::NoSpace`); witness builders
serve target, space and clock together. 6.15: a code-4 fixture (a rooted
statement claiming `NONE`) at the next regeneration. 6.16: the founder
bound 1 to 16 and `NodeNumber` `u8` into `spaces-pallet.md` §3. 6.19: the
service carries no test mode of `final-verify.elf` (mode 2 reports
`ACCEPT` with no statement), or accumulate requires `code == 0`.

**6.10 accepted.**

**`just check` after both merges** (at `85c1853b`): green, 1,168 passed,
0 failed.

## Step 6.11: the agent root, committed rows under `0x03`

Worktree `.worktrees/s6-roots`, branch `s6/roots` off `vos-core` `85c1853b`. Not pushed.

**Built:**
- **The keyspace (`agent/wire/src/keys.rs`):** `Owner::Committed = 0x03`; a
  committed row is `0x03 ‖ instance (4) ‖ tag (4) ‖ transform (1) ‖ key'`, no
  `Part` byte (`Part::Committed` gone; `COMMITTED_PREFIX` = 10, `TABLE_PREFIX`
  stays 11). `is_committed` and `committed_entry` decide from the first byte;
  `owned_by` accepts `0x01 ‖ instance` and `0x03 ‖ instance`;
  `instance_prefix` became `instance_prefixes` (both); `committed_all()` =
  `[0x03]`, the agent root's keys. `rows_prefix`/`row` give the ABI the new
  prefix for `Rows::Committed`, so a handler's committed-map ops and scans
  land under `0x03`.
- **Dirty rows** name the committed row whole: `00 11 ‖ version ‖ row`
  (`dirty(version, row)`, `dirty_entry → (version, row)`; one byte more a
  row than `map_key ‖ key'`); `map_key` gone.
- **The builder's rows:** one tree per agent: `tree_node(level, prefix)`,
  `tree_leaf(row key)`, one `tree_root()` (`02 02`, one `RootRow`) and one
  `built()` (`02 03`) watermark; `tree_roots`/`tree_root_entry` gone.
- **`records::leaf_value(key, stored)`**: the bytes a leaf commits, the bare
  value for a `0x03` key (format byte and version stripped), the stored bytes
  otherwise.
- **`vos_tree::node_at(store, prefix)`**: the node at a byte prefix (the
  subtree over exactly the keys under it), walking branches below the
  prefix's bit length and checking the shared bits; `None` when no key starts
  with it.
- **`node/host/src/roots`:** `AgentStore` (was `MapStore`, no map) over the
  agent's tree, from its top or any node; `Build` reads every dirty row into
  one sorted key set a batch, one `vos_tree::update` a batch, one `RootRow`;
  `finish` completes the tree this build touched or one a cut-short build
  left part-way. Leaves: `Leaf::salted(seed of the writing version, full row
  key, bare value)`. `agent_root(snapshot, agent) → (root, version)`
  (`Building` while a build is part-way); `root(snapshot, agent, map)` = the
  node at `committed_rows(map)`; `prove` opens full row keys under the map's
  node (`Proven.leaves` keys are full rows now); `rows_match_tree(snapshot,
  agent)`.
  - **Mid-build semantics (for Fable):** a map none of whose writes waits is
    read from the tree's top as it stands (its keys a build took were rebuilt
    from their values at that build's version, which nothing later changed);
    a map with a waiting write, and the agent's root, are `Building` until
    the build ends. Before, a map whose own tree was part-way was `Building`
    even with no write waiting; now one whose writes a cut-short build fully
    consumed answers at the agent's version.
- **JAM:** `node/jam/src/store.rs` `stage` and `agent/default/src/refine/jam.rs`
  (the witness's claims, scanned range rows, the writes' root-after) hash
  `leaf_value(key, stored)`: `0x03` leaves the bare value with VOS's salt
  (`salt(seed, full key)`), the witness still carrying stored bytes for
  apply; a `0x03` row that is no value row traps (refine) or is `Corrupt`
  (builder). The salt of a deleted row is no longer computed. `Store::write`
  (`#[doc(hidden)]`) stages and commits rows for tests.
- **The window kernel** (`agent/test-actors/window`): its rows are the
  committed rows of `ACCOUNTS` (instance 0, tag 1, hashed), keys built by
  `keys::row`, so its multiproofs are against the agent's tree (map root =
  agent root for an agent holding that map alone). The test's fixture tree
  is over the same full keys; `inversion` searches the whole key for its
  flipped bit (the shared prefix pushes the first difference past bit 80).
- **Docs:** `core-model.md` §9.3 (one tree per agent, a map's root its node,
  `Building`, the `0x03` bullet in the present tense).

**Tests:**
- **VOS ≡ JAM** (`roots::tests::roots_are_nodes_of_jams_tree`, vos-jam a
  dev-dependency of vos-node): 10 cases, random committed writes over 4 maps
  (two instances, both transforms) across 1–4 versions, built in batches of
  1, 7 or 10,000, with table, struct and `0x04` rows beside them on JAM: the
  agent root = JAM's node at `0x03`, every map root = JAM's node at its
  prefix, both = the root from scratch; one row (a leaf at `0x03`); none
  (empty root, absent node).
- `vos-tree`: `the_node_at_a_prefix_is_the_tree_over_its_keys` (proptest
  256: keys under fixed-width prefixes, every prefix length 0–3 and random
  probes; none, one, many).
- ownership: `instance_keys_never_meet_system_keys_or_other_instances` now
  with committed rows and prefixes (owned only by their instance) and
  dirty, seed, tree and `[0x03]` keys (owned by none); the key layout pinned
  byte for byte; every row key prefix-free with the new tree rows.
- builder: the four unit tests on one tree (agent root checked beside each
  map's; a cut-short build: `Building` for the waiting map and the agent,
  the consumed map answering at the agent's version); `tree_crash` (12
  rounds killed and torn mid-build, resumed to the agent root and each map
  root from scratch, rows on the tree); the cluster's roots tests (full-key
  leaves, agent root).
- `vos-jam`: `a_long_ordered_keys_leaf_counts_two_compressions`: a committed
  row at a 64-byte ordered key of zeros (escaped to 130 B, row 140 B, leaf
  preimage 187 B) hashes in 2 compressions, as `gas::leaf` counts; 64 bytes
  of ones and a 32-byte hashed key, 1.
- the comparison suite (testkit `jam::agreement`, `driven`) unchanged and
  green; replica comparisons (`cluster/common.rs`, `fault_suite.rs`) and
  the crash tests read `0x03` too.

**Gates:**
- **`just check` green** (second run, after the testkit's native witness
  check `shows()` learnt the bare-value leaf: the first run failed there,
  `packages_agree_with_vos_on_scans_and_committed_maps`, the refine itself
  agreeing): 89 test binaries, 1,171 tests [measured]. Logs
  `6.11-check.log` (the failure), `6.11-check2.log`.
- **The checker loop, short:** `EXACTLY_ONCE_SEED` 611, 612, 613 × the three
  exactly-once tests (`vos-node --test served exactly_once`): 9 of 9 green,
  271 s [measured] (`6.11-checker.log`). Also `fault_suite` (five
  processes, replica rows compared with `0x03`): green, 160 s.
- **Fixtures:** none move (the segment kernel is hand-assembled and the
  statements' roots synthetic): `the_fixtures_are_the_generators` and
  `the_fixtures_are_judged` green, no regeneration.
- **The window kernel** (its attest's trace, same machine, before at
  `85c1853b` / after) [measured]: steps 632,800 → 643,587 (+1.70%),
  compressions 651 → 651 (+0%), witness input 25,989 → 26,309 B (+320: 10 B
  a key, 16 keys, 2 proofs), kernel 69,101 → 69,391 B. Within 5%. The
  proving tests (`proves`, `folds`, `wraps`) not run (test-proof, milestone).
- **The builder** (`cargo bench -p vos-node --bench tree -- 1000000 20000
  30`, binaries of both commits, the same machine; it was shared with other
  agents' builds, load 2–20, so pairs were run together or back to back)
  [measured]:

  | run | rows/s built, before → after | from scratch µs/key | most behind |
  |---|---|---|---|
  | quiet pair (load 2–3) | 19,890 → 19,357 (−2.7%) | 26.70 → 28.41 | 28 → 48 |
  | concurrent pair 1 | 15,831 → 15,408 | 73.63 → 74.74 | 115 → 140 |
  | concurrent pair 2 | 12,966 → 14,650 | 58.38 → 62.00 | 186 → 150 |
  | concurrent pair 3 | 17,639 → 16,282 | 48.78 → 55.69 | 58 → 106 |

  Rows built a second within 10% (−2.7% quiet, −0.2% over the concurrent
  pairs' mean); at 20k offered (19.6k delivered by the applier in the after
  run) the builder keeps up as before (19.4k vs 19.9k built, 8.0k vs 3.0k
  rows left at the end, caught up in 0.30 s vs 0.15 s). A build from scratch
  is about 6% slower in every pair [est, not profiled]: node and leaf row
  keys grow 1 byte only, but node row values grow about 20 B (each `Child`
  names a branch prefix or leaf key at least 10 bytes longer, levels
  starting past bit 80), and the salt and leaf hashes run over keys 10
  bytes longer. Sequential runs under load 10–20 (pairs 1–3 of the first
  attempt, 9–13k rows/s both ways) were discarded as noise.

**For Fable:**
- the mid-build rule in `map_top` (a map with no waiting write answers from
  the partial top; a waiting map and the agent root are `Building`), and the
  test that now asserts it (`a_map_left_part_way_is_finished_without_a_write`);
- `waits` still caps its scan at `BATCH` dirty rows (past it, "waits");
- dirty rows carry the whole committed row (`0x03 ‖ …`), so a dirty row
  names no map without parsing the row;
- JAM's leaf rule keyed on the first byte only (`leaf_value`), both in the
  refine (claims, ranges, root-after) and the builder's store; a `0x03`
  row that is no value row traps;
- the window kernel's rows bound to a constant map (`ACCOUNTS`: instance 0,
  tag 1, hashed) rather than an argument;
- no migration of stores written before (the keyspace changed; there is
  no deployed state).

**Commit:** `802ccc36` (one commit, 33 files, +871 −405).

**Reviews:** Fable ACCEPT (`6.11-fable.md`: `node_at` correct, the
equality test strong enough, finding 10's list complete, the mid-build rule
sound; one minor finding, three nits); Opus ACCEPT (naming, a named
committed prefix, the from-scratch cause corrected above).

**The fold** (`2d0db7fc`, 10 files, +89 −37):
- Fable 1: `is_committed` decides from the first byte alone, so a `0x03`
  key too short to name a map and a key is still read as a value row and
  fails (`leaf_value` None: JAM `Corrupt`, refine trap, builder `Corrupt`)
  instead of being hashed as a plain row on JAM alone; `committed_entry`
  keeps its length checks. Round-trip asserts: `is_committed(&[0x03])` and
  of a bare map prefix true, `committed_entry` of both None,
  `leaf_value(&[0x03, 1], &stored(&[1]))` None. Pin E and core-model §9.3:
  every key under `0x03` is a committed value row; anything else stored
  there is corrupt, and both hosts fail on it.
- Fable 2: `roots_are_nodes_of_jams_tree` gives the no-committed-row case
  JAM's sibling rows too (`siblings`), and draws a 64-byte zero `Ordered`
  key and the pair `[1]`/`[1, 0]` among the random keys (3 in 16).
- Fable 3: the window actor's `ACCOUNTS` doc: it stands in for the map an
  attestable `&self` view names (6.13).
- Fable 4: the plan's 6.22 gains a store layout version that `Fjall::open`
  refuses on mismatch; 6.11's builder gate reads "keeps up at 20k committed
  writes a second offered (19.6k delivered), no regression past 10%".
- Opus: the refine's `committed(key, stored)` renamed `leaf_bytes` (the
  local back to `committed`); `keys::instance_rows` and
  `keys::instance_committed`, `instance_prefixes` their pair, the
  `[0]`/`[1]` callers named.
- `just check` green after the fold: 1,171 tests (`6.11-check3.log`).

Commits: `802ccc36` (the step), `2d0db7fc` (the fold).

**Merged** into `vos-core` as `65052f1c`, with one conflict in the plan's
6.22: its items 21 (6.9's leftovers) and 22 (the store layout version)
both kept. `just check` after the merge: green, 1,192 passed.

**6.11 accepted.**

## Step 6.12: window cuts and the held build

Worktree `.worktrees/s6-roots`, branch `s6/roots`. The full record is the
step's log. The tests first (`60eb3583`, brief `6.12-tests.md`), reviewed
by Fable: READY TO BUILD TO (`6.12-tests-fable.md`), its 13 decisions and
§5's test fixes followed.

**Built:**
- **The shared apply, both hosts** (`agent/wire/src/apply.rs`): the
  agent's record (target, space, clock) read from the state before the
  result's steps; a record stored in part, or one that does not decode,
  applies nothing; in an agent of a space, `cut(w)` = the version before
  the result for each w with `p < B_w ≤ t` (p the batch-time mark), by
  arithmetic, at most the newest `MAX_CUTS` = 32. The install cuts nothing.
- **`roots/cuts.rs`:** `CutProof` (rows, salts, values, root, version, the
  proof's encoding), node-local undo rows (`undo(w, row)` = a committed
  row's stored bytes when the writes touch it at a version ≤ a pending
  cut), `at_cut`, `finish` (the root at the cut, the two latest kept, the
  window's undo rows dropped, each pending request's proof off the tree as
  the last batch leaves it); orphaned undo rows swept.
- **`Build`** targets the earliest pending cut, else the latest version;
  a cut already built is finished alone; a cut behind `built` is
  `Corrupt`. The builder builds until nothing is due; cut rows wake it.
- **The node's apply** writes undo rows on the applier's snapshot, only
  when the result applied, never in the dry run.
- **The leader** (`leader/cut.rs`): `cut_wait` to the first boundary after
  an idle agent's mark; the marker, an empty `WorkResult` at the agent's
  version timed by the leader's own clock, proposed through `execute`.
- **JAM:** the record witnessed whole whenever the simulation read any of
  it. The `cuts` feature gone: every cut test runs in `just check`.
- **Docs:** Pin D's `cut(w)` row, Pin E's re-cut, 6.12–6.14 in the plan,
  `core-model.md` §9.3.

**Deviation** (judged required by Fable): the request hook's step is an
`InputRef::Due` step, not `Admin`: `settle` pairs a result's non-due steps
with the batch's inputs in order, so an `Admin` step would answer an
uncovered input. A test seam; 6.13 deleted it.

**Gates** [measured]: `just check` green, 96 suites, 1,186 tests; the
checker loop (seeds 6121–6123 × the three exactly-once tests and the cuts
run through all faults, 2-s windows) 12 of 12 green, 101–135 cuts an
agent; `cut_crash` 12 rounds, 7 killed between a cut and its proofs, all
resumed. The benches (load 12–14): a committed write with a cut pending
5.85–6.71 µs against the 8.6 µs gate; a cut's build with 100 proofs
382–412 ms against 1 s (1,175 ms behind 100 un-compacted builds: a known
sensitivity, not a gate failure).

**Commits:** `2c99857e` (the step), `cd784524` (the bench's phases).

**The reviews:** Fable ACCEPT (`6.12-fable.md`: no protocol or
determinism defect, nine findings, none blocking); Opus: no correctness
defect, quality findings. **The fold** (`59eb975b`):
- Fable 1: `cuts::finish` skips and logs a request that does not decode or
  names no committed value row, the same on every replica, so the cut's
  root and the other proofs land; the plan's 6.13 validates
  `PendingRead.rows`;
- Fable 2–4, 8, 9: the pruning rule, the catch-up cap, `Woke::Built` and
  the cut leaves on JAM carried in the plan (6.14, 6.19); the
  leader-change test waits for equal agent roots; §9.3's node-local rule;
- Opus: the hook asked first and the output re-encoded only on `Some`; the
  served cuts run tours workflows only under `CUTS_FULL`; a marker applied
  as no writes backs off, `Leader::ended_by` shared; the cut and undo key
  parsers pinned; `committed_value` deleted.

**After the fold:** `just check` green, 1,187 tests; the checker with
`CUTS_FULL` 12 of 12 in 733 s (117–142 cuts an agent).

**Merged** into `vos-core` as `d991efd3`. `just check` after the merge
failed once in `cuts::an_idle_agents_leader_appends_one_marker_at_its_own_clock`
("one result appended: []"): the test read the log through the node's
count of applied entries, which moves only once the apply's commit
returns, and two-minute windows let a slow start pass a boundary. Fixed
in `0c82a3c5` (merged as `4213c513`): the applied index read from the
snapshot that commits the cut, windows of an hour with `B_0` most of an
hour off; starved on one core, 13 of 15 and 12 of 12 failures before, 0 of
12 after. 6.13's fold (merged in `2276ed9a`) has the test wait for the
marker's result as for its cut.

**6.12 accepted.**

## Step 6.13: `&self` attestables and the public-input model

On `s6/roots` (from `59eb975b`). The full record is the step's log.

- **Built:** `#[attestable]` on `&self` reading the generated
  `<Actor>View` (`ServedMap`s), `#[public]` arguments and `venue_bound`;
  schema kinds `Stating` and `Reading` beside `Attestable`; the SDK's
  `verify_served` prologue and `attested(public_args, output, roots,
  io_hash)`; `Workflow::attest_at_cut(..).reads(..)` over `Op::AttestAt`,
  refused at once (`NoSpace`, `Unknown`, `Cap`, `Reads`) or paused until
  `B_{w+3}` (`NotClosed`); `Input::Resume` served by the leader once its
  replica built the cut (a stand-in representative until 6.14), checked by
  refine (`Unserved`), run on arguments ‖ served, the `Attest` recorded with
  window, public arguments and `S_w`; derivation of `Reading` kernels with
  192 KiB of argument pages read 64 KiB a call; `Hooks::request_at_cut`
  deleted; JAM's `Limits::served` 32 KiB and its effects.
- **Measured** [measured], against 6.0a on a million-row map and 1,024
  agents: a row 20.07 compressions (19.07 and the view's key hash) and 862 B;
  the path 14 (+1) compressions and 590 B; the sixteen-row prologue 210,019
  steps (+2.0%), the kernel with its sixteen view reads 248,914 (+21%, 2,432
  steps a read); 11 segments at the 32k class, 5 cut short by its 8 pages.
- **Priced** [measured]: `ATTEST` 66,000 apart from a call's machine,
  `CALLER` 6,200, the parts' io-hash 8,000 a block, a served byte 64 of the
  batch's budget (41.5 measured).
- **Checker:** the served cuts run reads through every fault, each read's
  end noted in the reader's state: 363 reads, 342 served, 21 not served in
  time, none failed.
- **The review** (Opus): ACCEPT, folded: a read's kernel spending the
  step's share preempts the step, its `Attest` kept; the parts' check
  (5,233 a block of 8,000) and a valid read's serving (3.89M of 19.35M
  accounted) measured; `at_cut` refuses served bytes past the cap before
  metering; an unreadable schema refused at derivation; 6.14 binds the
  served path to the stored `Closed` rows.

Commits: `19b86fbc` (the step), `3aa04c8c` (the fold).

**6.13 accepted.**

## M2 accepted: the final wrap masked

M2 is 6.1–6.9 and 6.6b: format 39, the masked wrap, its prover, its final
verifier and fixed layout, `vos-statement` at the accepted set {39}, the
masking's gates, panic-freedom and fuzzing, the recursion AIR's forgery
gates, format 36 retired. Its acceptance (the plan's "M2 acceptance") at
`vos-core` `a46956a4`.

**The masked wrap per statement, against format 28** [measured; each
statement's kernel test alone (`--exact`, one test thread, its proving on
every core, `--features debug-internals`), under a 12 GiB scope, the
machine shared with other agents; heap is the counting allocator's peak,
resident the process's `VmHWM` reset before the prove; gas on the JAM-only
host (39 by `final-verify.elf`, 28 by `final-verify-test.elf`); Wasm the
production blob (39) and the test blob (28) under the PVF's semantics,
pinned to the performance cores at x86-64-v3]:

| | the window, 39 | the window, 28 | `areas`, 39 | `areas`, 28 |
|---|---|---|---|---|
| prove | 7.44 s (load 6.8) | 4.55 s | 8.37–8.40 s (load 7.4–7.8); 14.5, 16.8 s at 7.2–9.1 | 5.28–5.96 s |
| heap peak | 3,627 MiB | 2,498 MiB | 3,627 MiB | 2,498 MiB |
| process peak resident | 4,079 MiB | | 3,849–3,890 MiB | |
| R1 | 7.7 ms | | 6.1–8.0 ms | |
| revealed rows, attempts | 80 of 256, 1 | | 80 of 256, 1 | |
| bytes | 148,868 | 122,085 | 144,260–147,844 | 121,098 |
| JAM decode | 1,815,193 | 13,279,989 | 1,804,345 | 13,211,151 |
| JAM verify | 82,980,239 | 66,177,415 | 81,042,863 | 65,851,402 |
| JAM total (the guest) | 84,879,480 | 79,534,547 | 82,930,068 | 79,139,441 |
| Wasm instructions (PVF) | 44,917,286 | 37,977,763 | 43,849,890 | 37,787,387 |
| host allocations (Wasm) | 7,974 | 7,698 | 7,962 | 7,698 |

- The gas and Wasm columns are of the proof each run wrote (the window's
  148,868 B, `areas`' 144,260 B). At the worst shape (6.6b, the 12 gate
  seeds' fit to 2,768 witness hashes): Wasm 46.43M of 50M, JAM verify
  85.84M (target 125M), decode 1.83M (4M).
- **"≤ 15 s quiet": not measured quiet.** Every run shared the machine
  (load 6.8–9.1 at the wrap; a quiet start, 2.3, rose with the run's own
  segments). The masked wrap took 7.44–8.40 s against 28's 4.55–5.96 s in
  the same runs, 1.4–1.7×; the two slow runs (14.5 s, 16.8 s) at the
  highest loads still fit. Accepted at 7.44–8.40 s under load, as Fable's
  review allows.
- A statement's masked wrap is its witness's alone: `areas` (3 segments)
  and the window (27) prove one wrap circuit at the same log sizes, so
  their time, heap and bytes agree within the run's noise and the masks.

**Gates** [measured]:
- **`ci`** (inside `just ci-full`, at `4aba1f07`): green, 110 suites,
  1,349 passed, 0 failed.
- **`test-proof`** (its own run, at `e575f10e`'s recipe): green, 14
  suites, 552 passed, 0 failed, 2,632 s; its `judge-wasm` 31 of 31
  fixtures as recorded under each blob and semantics, the anchor vectors
  as pinned; the masking's heavy gates (leakage at full N, acceptance at
  `[17,15,12]`, the verify gates over 12 seeds) among them.
  - **Failed first, and fixed** (`e575f10e`): under 12 GiB the `kernel`
    binary was OOM-killed three times in a window test (12 GiB peak; alone,
    the window's wrap peaks at 9.4 GiB), on heap earlier tests had freed
    and glibc's arenas kept, and on `reads`' million-row fixture (6.13),
    held for the process's life. The prover tests now hand a finished
    proof's freed heap back (`malloc_trim` in `measured`), and the recipe
    runs each window test, and `reads`, in a process of its own; its doc
    says 12 GiB.
- **`test-bench-proof`:** green, 2 passed, 21 s.
- **`just fuzz`:** the seven targets five minutes each, no crash (2,122 s).
  - **Failed first, and fixed** (`4a48740f`): `final_verifier_bytes`
    accepted a proof "not the golden one": the local corpus held proofs of
    the fixtures before their regeneration (`2f0ad042`), each another
    honest proof of the same words. The seed example now clears the four
    corpora it seeds before seeding them.
- **The checker loop:** seeds 6201–6212 × the three exactly-once tests
  (`vos-node --test served exactly_once`, workflows touring): 36 of 36
  green, load 3.2–6.8 at their starts. The cuts run with tours
  (`CUTS_FULL`, through every fault, 2-s windows), seeds 6201–6206: 6 of 6
  green, 86–145 cuts an agent, 144–235 reads an agent (served, or not
  served in time, none unserved), 799–968 samples holding undo rows.
  - **Failed first, and fixed** (`a46956a4`): the cuts run with tours
    failed 3 of 3 at "every tour started once" (351 against 108): since
    6.13 its reads start workflows at the same agents, which
    `next_workflow` counts beside the tours. `check_tours` now adds the
    workflows the run alongside started (`Alongside::workflows`: the reads
    answered as started, and one more when the run ended on a started
    read's retry, noted under the next tag).
- **`just check` at the head** (`a46956a4`): green, 1,247 passed, 0
  failed.
- **A flake fixed** (`9c19ff5e`):
  `messages::a_reply_outlives_its_leader_stopping` (`left: 0, right: 1`,
  seen under load at 6.7): the test waited on the store's value and outbox,
  then read the runs through the node's applied count, which moves only
  once the apply's commit returns; the runs are now read through the
  applied index the store holds, as 6.12's cut-marker test was fixed. Not
  reproduced on demand (12 runs alone on one core, 12 four at a time:
  green), fixed by the same mechanism.

**Folds before the gates:**
- **6.6b's review** (Opus ACCEPT, one Low): `b353d8ba` (above).
- **Areas' masked wrap** (`4aba1f07`): `wrap_root` always proves format 39
  beside 28, so `test-proof` measures it per statement (6.3's review had
  left it to the window alone).

**Milestone review: Fable ACCEPT** (`M2-fable.md`): no soundness or
zero-knowledge defect, nothing opened beyond the counted points; every
per-step finding folded. Its findings, folded:
- **1 (Low):** the gates run and this table, above; the quiet prove
  recorded as not measured quiet.
- **2 (Low)** (`3494eab5`): pin C as built: both test seams under
  `cfg(feature = "seeded-masks")` alone, `MaskRng`'s `Default`,
  `prove_masked_unchecked` named; R3's argument written in pin C and
  `SECURITY.md`'s zero-knowledge paragraph (R witness-independent; with
  rank-4 coefficients, about 2^-155 from failing, the real and simulated
  batches differ by an R-quotient, so FRI's transcript, its unsalted layer
  trees included, has one distribution; no check runs).
- **3 (Low)** (`2f0ad042`): the witness digest binds the format's channel
  by its pinned tag (`ChannelKind`, `repr(u8)`, explicit discriminants),
  not the Merkle channel's type name; the seeded 39 fixtures regenerated
  once, the stale test byte for byte after (`statements.cases` and the
  four `wrap*.proof` at 39).
- **4 (Info):** no action.
- **5 (Info)** (`3494eab5`): `SECURITY.md`'s audit scope names the
  least-term convention against a union bound (about 81.2 bits for 39;
  24 queries the robust pin).

Commits: `b353d8ba`, `01e7937b` (6.6b's fold and record), `9c19ff5e`,
`2f0ad042`, `3494eab5`, `4aba1f07`, `e575f10e`, `4a48740f`, `a46956a4`,
this record.

**M2 accepted.**

## Step 6.14: the representative and the anchors

On `s6/roots` (from `3aa04c8c`). The full record is the step's log.

- **Built:** `vos-representative` (`agent/representative`), the space's
  agent 0 of its first founding node, replicated on founding nodes alone,
  installed on the representative's clock (origin + `D`, `D = min(L/5, 2
  min)`), its committed roots keyed agent ‖ kind ‖ w and its asks; an
  agent's leader, woken by its builder's finished cut (`Woke::Built`),
  reports its root at the cut once a window (`Input::Report`); the
  representative's cut keeps each asking agent's path (`keys::closing`),
  its leader signs the anchor of `S_w` with its node key for the venue and
  sends each agent one `Closed` (`Input::Close`, by its mark, eight a
  close); the agent keeps the close by window (`keys::closed`) from its
  representative alone; apply re-cuts an unclosed window's reads at the
  next cut (`keys::moved`) and prunes cut, re-cut and close rows past
  `CUT_KEEP` = 4; a read served at the first window of its chain closed
  and proved, a proof kept a window; `serves` binds the served window,
  `rep_root`, `rep_salt` and `space_path` to the agent's close.
  `vos-venue`: `VenueClient` and `ModelVenue` (the anchor rule, repeats,
  equivocation kept as evidence and the space suspended, `judge`). The
  stand-in representative deleted.
- **Priced** [measured]: `SEND` 5,300 and `PAUSE` 9,000 (the larger agent's
  send 4,095 of 5,000 and wait 7,078 of 8,000 failed their spare).
- **Checker loop** (seeds 6141–6144, the three exactly-once tests and the
  cuts run with `CUTS_FULL`, the representative on three nodes): green
  after two fixes the run surfaced, the cuts check waiting for each
  replica's latest cut built, and the reader installed before the run's
  faults (`Alongside::before`); 101–205 reads an agent, none unserved or
  refused by a kernel.
- **The review** (Opus): ACCEPT, one medium and lows, folded (`aec48096`):
  an agent's report removes its own asks with its stale rows, no other
  agent's; an anchor settled on its taking or a refusal for good, the
  venue's `Open` tried again at the next batch in window order;
  `serving_windows` follows at most `RECUTS` moves; the served runs anchor
  at a `ModelVenue`, the cuts check asserting no evidence and each anchor
  `S_w` over the replicas' roots; the representative's replicas founding
  nodes alone; closing scans the window's asks; Pin D, Pin E and 6.17b
  amended.

**Merged** into `vos-core` as `57ddc47b`. The conflicts kept both sides:
the cluster cut tests keep vos-core's hour-long windows and the applied
index the store holds (`representative.rs` reads the same clock, so `D` is
two minutes); the served run keeps vos-core's count of the reads it
started beside the tours (`a46956a4`) and 6.14's `Alongside::before`.
`vos-venue`, written before 6.5's `vos-statement`, took its API after the
merge (`da93992a`): `Pin`, `Venue::id`, `Policy::new` at the linked formats, the
registered spaces in the policy, `Seen` recorded by `Policy::record`.
`just check` after both merges [measured]: green, 91 suites, 1,264
passed, 0 failed, `check-kit` among them.

**6.14 accepted.**

## Step 6.16: the verifier kit and the spaces pallet's design

On `s6/kit` (from `2276ed9a`). The full record is the step's log.

- **Built:** `just vendor-verifier` writes `vos-anchor`, `vos-statement`,
  `vos-pvm-final-verifier`, `vos-pvm-recair-air` and `vos-pvm-poseidon2`
  with concrete manifests (each other by path, Stwo a git dependency at
  `c3ec9813` without default features; no dev-dependencies, tests or bins;
  `test-formats` and `pvm-guest` dropped), the golden fixtures, the
  conformance vectors' hook (6.17), a hashed `.gitattributes` and a
  `VENDOR` file naming the repository, the commit, its tag and the tree's
  BLAKE2b-256. `vos_kit.py sync` checks the hash, vendors the kit anew
  from `VENDOR`'s tag by that tag's script and refuses any file's
  difference; `vos-sync.sh`, kept outside the kit, pins VOS's Codeberg
  repository, checks the tag (resolved without lazy fetch to exactly the
  commit) and runs the tag's script, never the kit's own. `just check-kit`
  (in `check` and `ci`) builds the kit alone for `wasm32v1-none` on 1.94.1,
  `--locked` on its lockfile (`just kit-lock`), refuses a `std` feature in
  any crate it links, and checks tampered, untagged, malformed, moved and
  unknown-tag kits refused. `workspace.package.repository` the Codeberg
  repository.
- **Docs:** `spaces-pallet.md` §3 takes 6.10's genesis, `MaxRootAge` equal
  to `MAX_ROOT_AGE_MS`, `seen_expiry`'s clock, a suspended space's roots
  unanchored; §3.1 the kit and its bootstrap; §6.5's raise extends every
  finite `Seen` expiry; §13 questions 11 and 12 (key rotation not yet
  supported). Pin D amended and a new step, 6.14b, a rotatable anchor key.
- **Measured** [measured]: `just check-kit` 42 s; a Kreivo-style sync 6.7 s.
- **The review** (Opus): REVISE (two high: a kit checking itself, an
  untagged commit accepted; three medium; three low), folded in
  `97dbe618`; the re-check ACCEPT.

**Merged** into `vos-core` as `699cad27` (the `check` recipe's prerequisites
both sides', `check-kit` beside `build-representative`).

**6.16 accepted.**

## Step 6.15: statements at a cut, end to end, on the model venue

On `vos-core` (from `1b7cdd2a`).

**Built:**
- **`balance`** (`agent/test-actors/balance`): a
  `CommittedMap<Account, Balance>` and
  `at_least(&self, #[public] commitment, #[public] threshold, salt, account) -> bool`,
  the commitment `BLAKE2b-256("vos/test/balance/account" ‖ salt ‖ account)`
  checked in the kernel (a mismatch traps), so the account is public only
  through it. Its doc says what the commitment does not hide: one
  commitment stated at several thresholds bounds the balance, and a reused
  commitment links its statements.
- **The window kernel restated under decision 6 (S3)**
  (`agent/test-actors/window`): the pair's two aggregate rows (decision 4:
  an outgoing and an incoming pseudo-account in one aggregate journal, ids
  derived from the peer and the currency);
  `settle(&self, #[public] peer, #[public] currency, #[public] c_prev, carried, salt) -> Settlement { net, seq, c_new }`.
  `c = BLAKE2b-256("vos/test/window/pair" ‖ peer ‖ currency ‖ salt ‖
  out_dr ‖ out_cr ‖ in_dr ‖ in_cr ‖ seq)`, the rows' running debit and
  credit totals, each of which only grows; `carried` opens `c_prev`
  privately, every total read must be at least the carried one (so a cut
  older than the carried state's settles nothing), the net is what the
  space owes at the new totals less at the carried, `c_new` the new totals
  at `seq + 1` under the private `salt`. Rooted (`S_w`), no anchor in its
  output. The peer and the currency are public beside `c_prev`: the
  handler finds the pair's `c` by them, and `c` binds them; `c` does not
  bind the stating space (the handler keys by the statement's space, which
  `S_w` binds). `cipher_clerk::settlement::window` takes two anchors and
  per-journal rows, so the test actor nets the delta itself; the library
  change, and the handler's `(c, w_last)` with its rule that a statement's
  root is past `w_last`, are recorded for the Clerk's slice in
  `clerk-across-spaces.md` C.4 and C.5.
- **`vos-venue`:** `ModelVenue::migrate(&Migrate) -> Result<(),
  MigrateRefusal>` (`spaces-pallet.md` call 5, G14): it ends a space's
  range at the migration's window, once (`AlreadyMigrated`), from a window
  past every one anchored and not before the venue's next (`Window`),
  leaving this venue for another (`Venue`); a root outside the range is not
  anchored, and an anchor at or past it is refused (`Window`).
- **The kernel tests** (`pvm/proof/tests/kernel`): `cut.rs`, shared by
  `reads`, `window_kernel` and `balance`: an agent's tree, a
  representative's tree of agents' roots (with or without the agent's
  row), the read served, the agent's report and the representative's
  `Closed` applied on the testkit before the `Resume`, the whole run
  proved to one root, and a founder-keyed space registered and anchored at
  the `ModelVenue`, its time settable. `common::wrap_root` returns the
  masked (39) bytes too. `window_kernel`'s two-anchor tests are replaced:
  the kernel no longer verifies proofs itself, the SDK's prologue does.
- **`just test-reads`** (in `check` and `test-agent`): the live runs of the
  window, the balance and a 256-row `reads` case, with no proving, so a
  change of the served contract fails `check`.
- **A pre-existing failure fixed:** `reads`' live runs resumed with no
  `Closed` row, so since 6.14's binding of the served path to the close
  every read was `Unserved` (`reads` ran only in `test-proof`, last at M2,
  before 6.14 merged; the live node serves only closed reads, so no product
  bug). `cut::read_live` applies the report and the close first.
- **Another, fixed** (`255179ea`): `vos-node`'s `snapshot_crash` failed
  under load (`Fjall::open`: `AlreadyExists`). fjall 3.1.12 writes its
  `version` marker last, after its lock, its keyspaces' folder and `0.jnl`,
  and takes a store without the marker for a new one, whose creation then
  fails on what the interrupted creation left: a node killed during its
  store's creation could never open it again. `Fjall::open_tuned` clears
  fjall's own entries of a store whose marker is missing or empty and syncs
  the directory before it opens; `a_store_whose_creation_was_cut_short_opens`
  (both markers) fails without the fix.
- **The code-4 fixture** (a rooted statement claiming `SpaceId::NONE`, its
  roots `NONE` and anchored) is in `statements.cases` since 6.5 ("rooted,
  of no space", code 4, judged alike at every venue); nothing to
  regenerate.

**Tests:**
- `window_kernel`: `the_window_settles_at_a_cut` (the statement, its public
  arguments `(agent, instance) ‖ (peer, currency, c_prev)`, its root `S_w`,
  live ≡ traced; the next settlement from `c_new` states net 0, seq + 2);
  `a_carried_state_that_does_not_open_is_refused` (another salt, each
  total, seq; `c_prev` of another peer or currency); `an_older_cut_is_refused`
  (a carried state that opens but whose totals, each in turn, are above
  the rows'); `rows_off_the_cut_are_refused` (a tampered row, a present
  row claimed absent, the agent's row missing from the representative's
  tree, a key outside the read set); all `Failed`.
  `the_window_proves_and_verifies_over_its_shape` (the chain's io-hash over
  the public arguments, output and root);
  `the_windows_leaves_and_folds_prove_and_verify` (its three segments'
  leaves, folded to the whole run's root);
  `the_window_is_stated_at_the_model_venue` (below).
- `balance`: `a_balance_is_stated_at_a_cut` (thresholds below, at and
  above, an absent account; the account in no public byte);
  `a_commitment_that_does_not_open_is_refused`;
  `a_balance_is_accepted_at_the_model_venue` (proved, wrapped masked,
  accepted; another threshold or commitment refused by the proof's words).
- `vos-venue`: `a_migration_ends_the_range` (every refusal, the range, the
  anchor past it refused).
- **Judged at the model venue** (the window's masked proof, format 39;
  the venue pins the program and holds `S_w` anchored by the founder's
  key), each case and the check that refuses it: accepted (0), a repeat
  (6); an unanchored root (5); another window, unanchored (5), and
  anchored there too, by the io-hash (0x108); another space, the space rule
  (4), and its root anchored in a second space of the founder's, by the
  io-hash (0x108); a missing representative row, `S_w` anchored over a
  tree without the agent's row, so the statement's root is unanchored (5);
  a tampered output (0x108); a venue mismatch, the anchor digest binding
  the venue (`Signature` at another, the root unanchored there, 5; code 7
  is the fixtures', the kernel not venue-bound); a window outside the
  migration range, migrated before its anchor (the anchor `Window`, the
  statement 5). A tampered served row and a key outside the read set trap
  the kernel, so no statement exists of them.
- **Latency** (`vos-node` cluster,
  `representative::a_read_is_stated_within_a_window_and_its_close`): three
  nodes, L = 2 min, D = 24 s, the clocks run from `B_0 − 2 s`.

**Measured** [measured; a million-row map under 1,024 agents' roots,
w = 2,966,000; the machine shared, load 5–16]:

| | 6.0a | 6.15 | |
|---|---|---|---|
| a row: compressions (`reads`, sixteen less one) | 19.07 (+1 the view's key hash: 20.07) | 20.07 | 0 |
| a row: witness bytes | 842 | 862 | +2.4% |
| the path: compressions | 14 (+1 `S_w`) | 14 (+1) | 0 |
| the path: bytes (path, salt, roots) | 590 | 590 | 0 |

- a row is `reads`' (`reads_at_a_cut_measure`, its gate a tenth of
  6.0a's); the window reads two;
- **the restated window** (two aggregate rows): **67,147 steps** (gate ≤
  1M), 56 compressions, witness input 2,401 B, kernel 70,734 B; **3
  segments** (two class-1, the halt at class 0); proved end to end in
  **103 s** at load 8–16: segments 40.5 s (peak heap 4,792 MiB), 3 leaves
  10.6 s, 2 folds 7.6 s, the wrap 7.0 s (28) and **24.8 s masked (39,
  148,356 B, heap 3,627 MiB, resident 3,895 MiB)**;
- the first restatement, eight journals' sixteen rows (before the
  review): 387,824 steps, 15 segments, 264 s end to end at load 5–9, a
  row 20.75 compressions and 878 B (+3.4%, +4.3%), about 24k steps (the
  pseudo-account ids by cipher-clerk's software BLAKE2b). Pin D's
  settlement estimate counts `t_prove` about 3.5 min: one prover took 4.4
  min at sixteen rows and 1.7 min at two;
- `balance`: 21,733 steps, 19 compressions, witness 856 B, one segment
  (12.4 s), its leaf 2.2 s, the masked wrap 10.4 s, 147,076 B;
- **latency** from `B_0`: the anchor of `S_0` at the venue in **24.04 s**,
  the read's `Attest` in the agent's log in **24.09 s** (D 24 s; bound
  D + 10 s = 34 s). From a read asked at any time in window w, at most
  L + 24.1 s ≤ L + D + 10 s; the statement is then at the venue after
  `t_prove` and an inclusion.

**Gates:** within 20% of 6.0a (0, +2.4%, 0, 0): pass; the restated
window ≤ 1M steps (67,147): pass; latency ≤ L + D + 10 s at L = 2 min
(24.1 s from `B_w`): pass.

**Commits:** `4fce524e` (the step), `255179ea` (the store's cut-short
creation), the review's fold and this record.

**The review** (Opus): REVISE (small), folded:
- **M1:** the carried state bound neither which rows were summed (a
  private list of journals) nor when (an older anchored cut): now the
  pair's two aggregate rows, keyed by the pair, and running totals no
  statement may lower; the handler's `(c, w_last)` and its later-window
  rule in `clerk-across-spaces.md` C.5; tests of an older cut and of each
  total.
- **M2:** `ModelVenue::migrate` was repeatable, retroactive and took
  `to` = itself: now as call 5 and G14; the migration case migrates before
  the anchor.
- **M3:** `snapshot_crash`'s failure was fjall's cut-short creation, fixed
  (above).
- **Lows:** each venue case names its check; the words' refusal pinned to
  0x108; a `c_prev` of another currency; the balance's commitment
  documented; the live tests in `check`; `t_prove` against Pin D's
  estimate recorded. Binding the stating space into `c` is left to the
  Clerk's handler, which keys by it.

**Gates after the fold:** `just check` green: every recipe and suite
before `test-reads` (97 suites, 1,267 passed, 0 failed), then
`test-reads`, its four test threads killed past 12 GiB at once, set to one
and run alone: 7 passed in 78 s. The changed proving tests run once each,
one at a time under 12 GiB:
`the_window_proves_and_verifies_over_its_shape`,
`the_windows_leaves_and_folds_prove_and_verify`,
`the_window_is_stated_at_the_model_venue`,
`a_balance_is_accepted_at_the_model_venue`: green.

**For Fable:** the restated public inputs (the peer and currency public
beside `c_prev`; `c` binding the pair, the four running totals, the seq
and a salt; a first settlement opening `commitment(Carried::default())`;
the totals' monotonicity standing for the cut's order inside the kernel,
the handler's `w_last` outside it).

**6.15 accepted.**

## Step 6.14b: a rotatable anchor key

On `s6/anchor-key` (from `1b7cdd2a`). The full record is the step's log.

- **Built:** a node's anchor keys in its store (`anchor_keys.rs`): its
  node key, which a founding node's genesis names, then each rotation's,
  an ed25519 seed under the node row `AnchorKey` (`0x0f`), committed and
  synced before it is used or shown, numbered past the last row stored
  (an unreadable one's too), never reused. `Node::rotate_anchor_key` on a
  running node, `vos node anchor-key rotate --data <dir>` on a stopped one.
  The representative's leader signs each anchor with the newest of its
  keys the venue lists (`VenueClient::anchor_keys`); with none listed it
  signs nothing and alerts once a window ("replace this replica, or list
  one of its keys"), the window waiting in order as an `Open` one does,
  and so do the venue's `Key` and `Suspended` refusals; a window past
  `B_w + MaxRootAge` by the leader's clock settles unsent. A replacement
  adds any node holding a listed key, the node added refusing the
  representative otherwise (`Unplaced::CannotRun`). `ModelVenue` keeps
  anchor keys by space: `add_anchor_key`, `remove_anchor_key`, `resume`
  (only once neither equivocating signer is listed; clears the evidence).
- **Tests:** `cluster::anchor_keys`: a rotation anchoring every window, an
  unlisted leader signing nothing, a single founder resumed after an
  equivocation (its window waiting through the suspension, anchored after
  `resume` by the new key), a node that did not found the space
  representing it after a failover, a rotation killed before the venue
  lists its key, a waiting anchor taken up after a leader change; a
  rotation numbered past an unreadable key's row.
- **Docs:** Pin D (the anchor keys row, the representative's replica rule,
  recovery by rotation), `spaces-pallet.md` §6, §9 and q12, 6.17b's
  Kreivo client waits.
- **Gates** [measured]: `just check` green (91 suites, 1,274 passed after
  the fold); the checker loop, seeds 6145–6147 × the three exactly-once
  tests and the cuts run with `CUTS_FULL`: 4 of 4 green each seed.
- **The review** (Opus): ACCEPT, one medium and three lows, folded
  (`ee3d4ad9`): a new leadership of the representative takes up the
  anchors an earlier one left waiting (each window up to the close mark
  whose cut root the replica keeps and whose `S_w` the venue does not
  hold), so a wait survives a leader change within `CUT_KEEP` windows; the
  alert's wording; the key numbering; 6.17b's waits.

**Merged** into `vos-core`. The conflicts in `vos-venue` kept both sides:
6.15's `ModelVenue::migrate` (G14, `MigrateRefusal`) and the space's
range beside 6.14b's anchor keys by space and `resume`.
`just check` after the merge [measured]: green, 92 suites, 1,284 passed,
0 failed.

**6.14b accepted.**

## M3a accepted: roots, anchors and `&self` reads, on the model venue

M3a is 6.10–6.15 and 6.14b: `vos-anchor` and the genesis, the agent root
under `0x03`, window cuts and the held build, `&self` attestables and the
public-input model, the representative and its anchors, a rotatable anchor
key, and statements at a cut on the model venue. Its acceptance (the
plan's "M3a acceptance") at `vos-core` `7acc49e0`.

**Recorded** [measured]:
- **6.15's statements:** a row 20.07 compressions and 862 B (6.0a: 20.07,
  842 B), the path 14 (+1 `S_w`) compressions and 590 B; the restated
  window 67,147 steps in 3 segments, proved end to end in 103 s, its
  masked wrap 24.8 s and 148,356 B (heap 3,627 MiB); the balance 21,733
  steps in one segment, its masked wrap 10.4 s and 147,076 B; from `B_0`
  the anchor of `S_0` at the venue in 24.04 s and the read's `Attest` in
  24.09 s at L = 2 min, D = 24 s (bound D + 10 s).
- **The builder's rate** (6.11's bench): 19,357–19,890 rows a second built
  quiet, 14,650–16,282 under concurrent load; at 20k committed writes a
  second offered (19.6k delivered) it keeps up, 19.4k built, caught up
  0.30 s after the load ends.
- **The cut's cost** (6.12's bench, a million keys, load 12–14): a
  committed write with a cut pending 5.85–6.71 µs (gate 8.6 µs); a cut's
  build with 100 proofs of 16 rows 382–412 ms (gate 1 s), the proofs alone
  80–86 ms.

**Gates** [measured; each under a 12 GiB scope, `nice -n 10`,
`CARGO_BUILD_JOBS=10`, one heavy run at a time]:
- **`ci`** (inside `just ci-full`, at `5de84ad7`): green, 107 suites,
  1,387 passed, 0 failed, about 15.5 min [est: the run's 29.2 min less its
  `test-proof` part].
- **`test-proof`** (at `7acc49e0`): green, 42 suites (each kernel test a
  process), 556 passed, 0 failed, 1,603 s; `judge-wasm` 31 of 31 fixtures
  as recorded; the leakage tests at their medium N among them.
- **`test-bench-proof`:** green, 2 passed, 18 s.
- **`just fuzz 60`:** the seven targets a minute each, no crash, 788 s.
- **The checker loop with cuts and the representative:** seeds 6301–6312
  × the three exactly-once tests and the cuts run with `CUTS_FULL` (the
  representative on three nodes, anchoring at the served harness's
  `ModelVenue`): 48 of 48 green, 871 s, load 1–10 at their starts. Per run
  and agent: 87–238 reads, 77–235 served, 3–32 not served in time, 0
  unserved; 274–716 samples holding undo rows; 5 cut rows kept; the venue
  61–111 anchors a run, one a window, each checked against the replicas'
  roots, no evidence.
- **`just check`** after the fold (`f73a4999`): green, 92 suites, 1,285
  passed, 0 failed, 12.5 min.
- **Failed first, and fixed** (rule: fix what is hit):
  - `ci`'s `test` OOM-killed at 12 GiB in `vos-pvm-recair`'s recursion
    suite, run on every core with the other crates (`5de84ad7`): `test`
    and `check` run the crate four at a time (`just test-recair`; 9.3 GiB
    peak at six).
  - `test-proof`'s `kernel` binary OOM-killed at 12 GiB in
    `kernel_shape::a_chain_not_from_the_entry_is_refused`, after the
    balance's masked wrap, the fixtures and others in one process
    (`7acc49e0`): every kernel test now runs in a process of its own,
    `reads`' apart, as the window's did.

**Milestone review: Fable — accept after fixes, folded** (`M3a-fable.md`,
`f73a4999`): no wrong root, window, row or path gets through any seam
(lagging replica, leader change, clock jump, pruning, migration, key
rotation). Its findings:
- **1 (medium):** any program could rewrite its own agent's
  representative rows by a `Call` of `report` (`Principal::Agent`): an
  agent's report is now a `Body::Report` the representative's refine
  stores natively, as it takes a `Closed` (the row at
  `representative_row`, the ask, the sender's rows and asks before
  `w − 2` dropped, `keys::reports(agent)` its last; nothing for a window at
  or before the last or past the representative's open window + 1, nor in
  an agent without the representative installed); the actor's `report`
  is gone. Tests: a program's and a client's call of `report` write
  nothing; a report two windows ahead stores nothing.
- **2 (medium):** a waiting anchor survived a leader change for two
  windows, not `CUT_KEEP`: the representative's cut roots are kept
  `CUT_KEEP` windows. Test:
  `waiting_anchors_survive_a_failover_through_a_long_wait` (windows 0–2
  closed unsigned, the leader stopped, all anchored by the new leader's
  key once listed, then window 3; it fails keeping two).
- **3 (medium, docs):** `clerk-across-spaces.md` C.5's handler reconciles
  progressively (`C_A`, `C_B`, `M`, moving `min(C_A − M, −C_B − M)`), the
  peer a space registered at the venue and not the statement's, and the
  Clerk's slice pins `Settled`'s totals never falling.
- **4 (low):** an idle representative's leader hands the venue a waiting
  anchor again every 2 s (`anchor_wait`), not only at its next batch.
- **5, 6 (low):** ops notes in the plan: the representative's load linear
  in agents (the lever: report only when reads wait or the root changed);
  a forward jump of its leader's clock cutting up to 32 windows with no
  paths (an alert, later a quorum-clock guard).
- **7 (low, docs):** Pin D and F: a suspended space's anchored roots go
  dark; `spaces-pallet.md` §6: a replica added only while it holds a
  listed key; Pin E's step 2 as built; `seed_waiting`'s doc.

Commits: `7b2c5d0a` (6.14b's merge), `f73a4999` (the fold), `5de84ad7`,
`7acc49e0` (the gates' recipes), this record.

**M3a accepted.**

## Step 6.17: the reference mock and the conformance vectors

On `vos-core` (from `4447127a`).

- **Built:** `node/venue/src/kreivo/mock` (test-only, std), a plain-Rust
  model of `spaces-pallet.md` §4–§8: its storage raw, under the pinned
  keys (`twox128("Spaces") ++ twox128(item) ++` Identity, `Blake2_128Concat`
  and `Twox64Concat` parts, the hashers checked against FRAME's well-known
  keys); its calls decoded whole from `[90, call_index] ++ SCALE(args)`
  (the bounded vectors checked, an undecodable call never included); its
  events, errors and stored values through `parity-scale-codec` derives at
  the design's indices (`anchor`'s argument equal to `vos-anchor`'s
  `Anchor` encoding); every call transactional; holds (`Registration`,
  `Submit`), providers and consumers; `ChargeSpaceFee` behind a switch
  (the sovereign pays for an authority of an active space within the
  window's budget, else the signer; every fee at `FeeBound`); a settable
  `now_ms`; verdicts from `vos_statement::judge` over a `StorageVenue`
  (a suspended or blocked space's roots unanchored). `ModelVenue` stays
  as it is: its state is lists and its refusals `AnchorRefusal`'s; the
  mock reuses `vos-anchor`'s digests and `vos-statement`'s `judge` and
  `seen_expiry`, which `ModelVenue` uses, and nothing else of it matches
  the pallet's storage.
- **The vectors:** `node/venue/conformance/spaces.json` (G1–G18, 18
  vectors, 153 steps; G12 and G13 `fees`) and `mutations.json` (120 proof
  mutants, 284 statement mutants, 12 masked-field mutants; two masked
  tampers no fixed layout holds, named), generated by running each
  scenario through the mock over the golden fixtures, each step's result
  asserted as the design's text gives it; named in `vos_kit.py`'s
  `CONFORMANCE`, so the kit carries them and the sync holds them to the
  tag's; `just conformance` writes them. G4 anchors the open window
  (`WindowInFuture`), then, at `B_w`, the same anchor (`Anchored`).
- **Tests:** `the_mock_passes_every_vector` replays the committed file on
  a fresh mock (each pre-state loaded, each call assembled from its parts
  and the kit's fixture files, everything it did equal to the step);
  `the_vectors_are_the_generators` refuses a stale file, byte for byte;
  the hashers, the errors' indices, the calls' and events' bytes.
- **Recorded in the design** (§10 the files' layout, the fixture space,
  G7's classes; §13 questions 13–15), not guessed:
  - the fixtures' space `[0xa1; 32]` is no genesis's hash, so every
    pre-state holds it as storage; the venue is the fixtures' (their
    statements are venue-bound);
  - G7's "1–7" with §6.3's released repeat: G7 covers 1–5, 7 and `0x1xx`,
    6 is G8's;
  - G13's ninth refusal holds only when the fees fill the budget: with
    `post_dispatch`'s correction to the actual fee it may pass at Kreivo's
    fees (question 13, recommended: debit `FeeBound` uncorrected);
  - unnamed refusals as the mock has them: `migrate` before the next
    window `OutOfRange`, `resume` of an unsuspended space
    `SpaceNotActive`, `BadHandler` unreachable (another handler byte does
    not decode), a `ProgramsOrigin` removal setting `until_ms = now +
    delay`, the delay checked only for a changed `from_ms` or `until_ms`
    (question 14);
  - G16's inner call is Kreivo's `Balances` (10) `transfer_keep_alive`
    (question 15);
  - G4 reaches `BadClock` by setting the time before the space's origin;
    a hold keeps the existential deposit free (the vectors stay off that
    edge); funded accounts start with Balances' provider, and providers
    alone are pinned (a hold's consumer is FRAME's own).
- **Measured** [measured]: generating both files and replaying G1–G18
  take 0.3 s together; `spaces.json` 277 KB, `mutations.json` 129 KB.
- **Gates:** `just check` at `b864c9ac` green, 98 suites, 1,292 passed,
  0 failed, 22.6 min (12 GiB scope, `nice -n 10`, 8 jobs); `check-kit`
  vendors and syncs the vectors with the kit. Its first run failed:
  `check.py` vendors at the commit, so the vectors must be committed
  before it runs.
- **The review** (Opus, `6.17-review.md`): ACCEPT WITH FIXES, all nine
  folded:
  - **1 (high):** G9 let a pallet without the freshness check in
    `anchored` pass, `on_idle` having pruned the anchors first: the rooted
    statement is now resubmitted at `MaxRootAge + 1` before `on_idle`,
    refused 5 and forfeited (6 without the check);
  - **2 (medium):** G18's pre-state `SovereignOf` value was 128 bytes
    (`[0xee; 32]` inferred as `i32`s): `[0xeeu8; 32]`, and the replay now
    checks every pre-state and written entry's key length and value type
    by its item;
  - **3 (medium):** G5 also equivocates with two fresh keys and removes
    the second signer's first: `StillEquivocating` until the first's goes;
  - **4 (medium):** `ProgramsOrigin`'s delay covers any change but setting
    or shortening `until_ms` (`venue_bound` on an active program refused
    `TooEarly`, a G11 step; §13 question 14);
  - **5–7 (low):** G10 pins a submit's `InsufficientSovereignBalance`
    with nothing moved; G1 takes `start_window` at `now_w + 1` and at the
    earliest, G4 an anchor exactly `MaxRootAge` old; the vectors' `about`
    states unlisted accounts unchanged, fee recipients unpinned, and the
    hold's consumer left out;
  - **8 (low):** every mutation code checked equal by `judge` and by the
    mock's `submit` at G7's pre-state; the proof's length and BLAKE2b-256
    pinned in `mutations.json`;
  - **9 (low):** §13 question 14 lists the mock's other choices and notes
    that G14's refusal 5 past `end_window` cannot be reached by calls.
- **After the fold:** `just check` at `ef73f879` green, 98 suites, 1,292
  passed, 0 failed, 14.5 min; G1–G18 now 153 steps, `spaces.json` 303 KB.

**6.17 accepted.**

## Step 6.17b: the node's Kreivo client

The chain transport, the account key and the tooling below were parked
afterwards and removed (see "The Kreivo chain client parked"); the
record stands as built.

On `vos-core` (from `56ab4860`).

- **Built, in `vos-venue`:** `kreivo::KreivoVenue: VenueClient`, in two
  layers:
  - `kreivo::calls`: the pinned call bytes (`[90, call] ++ SCALE(args)`),
    the raw storage keys the node reads, the events, errors and stored
    values by `spaces-pallet.md` §5, §6, §8, written apart from the mock's
    types so the vectors check one against the other; the sovereign
    account's derivation;
  - `kreivo::transport`: the `Transport` trait (sign, send and follow to
    inclusion, raw storage and keys at the best block) and the `Sender`,
    which signs a call once with the signer's next nonce and, after a lost
    answer or a stale nonce, reads the nonce (past it: landed) or sends
    the same bytes again, signing anew with the same nonce only once the
    era has ended: a call is included at most once.
- **The transports:** `kreivo::chain::ChainTransport` behind the `kreivo`
  feature (subxt and subxt-signer =0.51.1, sr25519, the call as a
  `RawCall` payload): `KreivoConfig` is Polkadot's types with Kreivo's
  extensions, `PassAuthenticate` a typed extension that encodes `None`
  after checking its type is an `Option`; the live list is checked
  against the ten in order before signing; events read from
  `System.Events` at the inclusion block by the extrinsic's index. The
  mock transport (`kreivo::mock::transport`, feature `mock`) runs 6.17's
  model, each signer's extrinsics its nonce and call, with faults (an
  answer lost after landing, a send dropped before) and latency. The
  calls layer, the `Sender` and `KreivoVenue` build without either
  feature, so `just check` runs them without subxt.
- **The anchor's hand-over:** `KreivoVenue::anchor` answers from what the
  worker last read (the space's status, range, anchor keys and `Last`,
  the venue's time) and queues: `Anchored::Queued`, a refusal for good,
  or `Open`. One worker thread sends anchors in window order and submits
  in turn, all as the node's account; it reads `Timestamp.Now` before an
  anchor and never sends one for a window the venue has not closed, nor
  while the space is not active or anchors are paused. The errors per §9:
  14 and 15 done; 16 kept until `Timestamp.Now` passes `B_w` plus a block
  (`Options::block_ms`); 17 and 18 dead with an alert; 19 and 20 kept;
  the others and `InvalidTransaction::Payment` an alert. `anchored` reads
  `Anchors` at the best block (a suspended space's roots, a migrated
  window or one past `MaxRootAge` not anchored). A funding alert when
  the paying space's sovereign holds less than 8 submits
  (`Options::per_submit`, one UNIT by default).
- **Submits:** before paying, the pause, `Formats`, `Programs` (refusals
  2 and 3 unsent), `Seen` (a repeat accepted unsent), the paying space's
  status and its window's budget; the verdict from `Accepted { id }`,
  `Refused { 6 }` accepted, `Refused { c }` `NotAccepted::Refused(c)`;
  the configuration's errors and the funds' an alert and
  `NotAccepted::Unjudged`.
- **`VenueClient`** gains `status` (`Status::waits` for suspended or
  blocked), `Anchored::Queued`, and `submit` returning `NotAccepted`
  (a refusal's code, or unjudged) in place of `Refusal`, since a remote
  venue reports codes; `vos_venue::code` replaces `vos_statement::code`
  at its callers.
- **The leader** (`leader/close.rs`) sends nothing while
  `VenueClient::status` says the space waits, and after a `Key` refusal
  hands the anchor over again only once the venue's listing changes or a
  window later by its clock.
- **The key (decision 12):** each node's account key, an sr25519 mini
  secret, made at its first start that asks for it and kept in its store
  (`NodeRow::VenueAccount`) beside its node key and anchor keys, never
  one of them; `AccountSeed`'s `Debug` names it only, and it is zeroed
  when dropped. `Config::venue_with_account` makes the venue's client
  from it at `Node::open`.
- **Tooling** (`vos`, feature `kreivo`): `vos node run --venue kreivo
  --venue-url`, `vos node venue-account`, and `vos space venue register`
  (the founder's signature over the registration digest by the stopped
  founding node's key, `start_window` the venue's open window by
  default), `authority add|remove`, `budget`. `vos_venue::kreivo::
  selectable` refuses Kreivo in a build without debug assertions, until
  M3b's deferred gates 1 and 2 pass; `vos node run --venue kreivo` asks
  it before the feature.
- **Tests:**
  - `the_client_passes_every_vector`: G1–G18's 153 steps, each call
    decoded and encoded again by the client's own types, sent by its
    `Sender` through the mock transport, the result from its decode of
    the dispatch error, the events its decode, every storage write read
    back through the transport, its key rebuilt by the client's builder
    and its value decoded as the client's type;
  - `KreivoVenue` over the mock (`kreivo::tests`): taken at once while the
    chain takes 300 ms; the open window refused, then anchored once the
    venue's time passes `B_w`; `WindowInFuture` held until `B_w` plus a
    block, then sent again; a suspended, blocked or paused space sent
    nothing; the budget's refusal and a short sovereign alerting, a submit
    over budget unsent; a lost answer not sent again and a dropped send
    sent again, each included once; an expired send signed again with its
    nonce; the fixture accepted, its repeat accepted unsent, a tampered
    proof refused with its class, format 30 refused unsent; every pallet
    error's fate and `Refused { 6 }`; the production build refusing Kreivo;
  - the cluster (`tests/cluster/kreivo.rs`, three nodes, each client made
    from its stored key, the mock with fees and a second an extrinsic):
    windows 0–2 land once each, in order, every anchor answered in under
    500 ms; a suspended space sent no anchor until resumed; a refused key
    handed over once within a window through the idle rechecks, once more
    a window later, and the windows land once the venue lists it;
  - the key store: made once, kept, apart from the node and anchor keys,
    never shown; the founder's signature by the node key;
  - the envelope's check refuses a moved, missing or added extension.
- **On a Kreivo dev chain** (6.0e's recipe: omni-node stable2606-2
  `--dev` with the `development` preset, Kreivo 87f8728, spec 134, no
  pallet 90; `examples/kreivo_dev.rs` through `ChainTransport` and the
  `Sender`) [measured]: `System::remark_with_event` as hand-built bytes
  signed by Alice, included, `System::Remarked` read by the extrinsic's
  index with Alice and the remark's hash, the nonce up by one; the same
  nonce again refused `Stale`; a transfer past Alice's balance read as a
  failed dispatch (`Arithmetic`); an unfunded signer's call refused
  `Payment`; `Timestamp.Now`, `System.Account[Alice]` and a key listing
  read raw. The chain's directory under the scratch directory, its PID
  stopped and the directory removed.
- **Gates:** `just check` at `74339d67` green but for one run of
  `snapshots::a_log_compacts_on_its_bytes_and_keeps_a_tail_within_them`
  (`NotLeader(None)`: a leader change under load during its increments,
  no venue in it), which passed alone, 7 of 7 in `snapshots::`; the
  check's remaining suites then green (`cargo test` of the node's crates
  and `test-reads`), 8.5 min and 11.3 min (12 GiB scope, `nice -n 10`,
  8 jobs). `just check` now also runs `clippy-kreivo`: `vos-venue` and
  `vos-cli` with `kreivo` and `mock` linted, and the envelope's tests;
  `doc-check` documents `vos-venue` with both features.
- **The review** (Opus, `6.17b-review.md`): REVISE, every finding folded:
  - **H1:** `Sent::Landed` was read from `system_accountNextIndex`, which
    counts the pool: `Transport::chain_nonce` reads `System.Account`'s
    nonce at the best block for the landed check, the pool's count signs
    only; an anchor landed whose record is not read stays queued, its
    record read before it goes again; the mock has a pool (`nonce` counts
    it, `chain_nonce` does not; `Fault::Pool`, `include_pool`,
    `drop_pool`), and `a_pooled_anchor_lands_once` shows it kept, landed
    once included, and sent again once dropped;
  - **H2:** the chain transport is subxt-rpcs' reconnecting client (a
    first connection given 30 s); a watch reads the best block every 6 s
    of silence and gives up once the era has ended, so the `Sender`
    reads the nonce again; `KreivoVenue::connect` takes a `Connect` that
    the reader thread calls until Kreivo is reached, every anchor `Open`
    until then, so a node starts while Kreivo is down
    (`a_venue_reached_late_anchors_once_reached`); `KreivoVenue::over`
    takes a transport made already;
  - **M3:** an anchor is dropped only when the venue holds it or a later
    window (14, 15, or a `Last` past it), on an equivocation, or for good
    (17, 18, `MaxRootAge`); 21 and 27 a funding alert, kept; 7 and 11–13,
    and any other, an alert and again a window later
    (`a_refused_key_keeps_the_anchor_for_a_window`); the pool's other
    refusals an alert and again after 30 s; "bad signature" and "ancient
    birth block" read as stale, and the mock refuses an extrinsic past
    its era as stale;
  - **M4:** the replay asserts what each call Ok means from its own
    arguments: a registration's `SpaceInfo` (sovereign, controller, the
    genesis's clock, start, registration time) and `SpaceRegistered`; an
    anchor's `Anchored`, record (root, signer, time) and `Last`, or its
    equivocation; a submit's payer; an authority's paired key; a budget;
    every `Spend` at the window of its time. Swapping `SpaceInfo`'s
    `origin_ms` and `length_ms` in the client fails it at G1;
  - **L5 and the JAM merge:** the queue is `vos_venue::queue::AnchorQueue`
    over an `AnchorSend` (`Fate::{Done, Dead, Again(after)}`), its worker
    sending each space's first anchor in window order, so JAM's client
    puts its blocking `land` behind it;
  - **L6:** `selectable` is the `kreivo-unvetted` feature, not
    `debug_assertions`, asked by `ChainTransport::connect` itself; `vos`
    has it as `kreivo-unvetted`, the dev chain's example requires it, and
    `just check`'s `clippy-kreivo` lints with it; it goes once M3b's
    deferred gates 1 and 2 pass;
  - **L7:** the seeds are `Zeroizing` (the store's rows, `AccountSeed`,
    `chain::keypair`'s copy); the accounts are numbered rows,
    `vos node venue-account show|rotate`, a rotation keeping the old and
    printing both, the order (remove the old authority, then add the new
    with the anchor key) and its gap documented; the chain transport takes
    `wss://`, or `ws://` on this host only;
  - **L8:** each space's first anchor goes apart: one space's wait holds
    back only its own windows;
  - **the flake:** `Cluster::increments` follows the agent's leader on
    `NotLeader`, as `increment_at_leader` does, for its 14 callers.
- **On the dev chain again** [measured]: the same checks pass through the
  reconnecting transport.
- **After the fold:** `just check` at `9dbd6ba8` green, 93 suites, 1,345
  passed, 0 failed, 12.2 min (12 GiB scope, `nice -n 10`, 8 jobs).

**6.17b accepted.**


## Step 6.19: the JAM statements service

On `s6/jam` (from `4447127a`). The full record is the step's log.

- **Built:** `vos-statement-service` (`pvm/proof/statement/service`), a
  JAM service for riscv64em on the venue guests' runtime (shared from
  `vos-statement`'s guest). Items `Register`, `Migrate` (on JAM the
  controller is an ed25519 key, signing `BLAKE2b-256("vos/space/migrate"
  ‖ migrate)`), `Anchor` and `Submit`, its statement in the payload (at
  most 64 KiB, as Kreivo bounds it; past it code 1) and its proof the
  item's first extrinsic (`fetch` kind 4). Refine verifies the
  registration's (1 to 16 founders, a registrable clock, a founding
  signer), the migration's and the anchor's ed25519 signatures and runs
  pin F's checks but `anchored` and `seen`, then the proof; its `Verdict`
  at most 2,734 B (a statement of at most 64 roots). Accumulate holds the spaces (clock, controller, keys,
  range, `Last`, suspension), the anchors and their evidence, `Seen` and
  each item's outcome keyed by its payload's hash; applies pin D's anchor
  rule and the registration's start bound at the slot's time (`genesis_ms
  + slot × 6 s`); records a statement only on a code of 0, its roots
  anchored and its id unseen. Anchors, rooted `Seen` entries and outcomes
  are queued by the hour they expire and dropped a few an accumulate; a
  rootless entry is never queued. A deployment's genesis hash, genesis
  time and pins are a block of the program's read-only data that
  `config::configure` fills before deploy: constants, changed by
  redeploy; the service has no test mode.
- **The JAM-only host** prices `fetch` by Gray Paper 0.8.0's per-kind
  table and serves extrinsics (kinds 3, 4); its harness runs a service's
  refine and accumulate.
- **The golden fixtures fail one check each:** unanchored root, a root's
  window and a root now change the venue's anchors, not the statement's
  roots, which moved the io-hash too: the JAM service, verifying before it
  reads its state, refused them `0x108` where the other venues refuse
  `0x5`. Only `statements.cases` changed; the proofs are byte for byte.
- **The builder** fits a package within CE 133's bound (`MAX_PACKAGE`,
  204,800 B: payload, imports' references and 4 KiB of framing) as well as
  `W_B`; a 64-request batch of 256 KiB of arguments splits, 32 in the
  first package.
- **Tooling:** `vos-jam` builds a GP 0.8.0 work package by hand, byte for
  byte `jamt`'s, and submits it with its extrinsics through
  `submitWorkPackage`; `live::statements` is the service's client;
  `vos-venue`'s `JamVenue` the service as a node's venue; `vos jam
  statements` deploys and drives it; `testnet.sh [agent|statements|both]`
  on PolkaJam v0.8.0, its files and chain under `TMPDIR`; `just
  jam-statements-testnet`.
- **Measured** [measured]:
  - the program 595,247 B (ELF 938,456 B), under the 4,000,000 B bound;
  - refine, JAM-only host: a masked statement accepted 84.11M gas (the
    rooted fixture), 83.78M (the rootless one); refused by the proof's
    words 12.05M; refused before the proof 0.11–0.13M; a 256 KiB extrinsic
    read and refused by the verifier 0.21M; `Register` 3.17M, `Anchor`
    3.10M, `Migrate` 3.07M (an ed25519 verify each);
  - accumulate: 75k–115k gas a report on the JAM-only host (its host calls
    at the base); 107,910 on PolkaJam for the accepted statement, by the
    service's own count;
  - **PolkaJam v0.8.0 testnet (interpreter)**, `just
    jam-statements-testnet` and `testnet.sh both` (the agent's 8
    packages, then the service): the 256 KiB extrinsic landed (`0x104`,
    208,160 gas); a space registered, window 3 anchored, an unlisted key
    refused `Key`; the rootless masked statement accepted, 83,778,546 gas
    on PolkaJam and on the JAM-only host, equal to the unit; replayed
    `0x6`; the rooted one, bound to the fixtures' venue, `0x7`; the space
    migrated; a second root `Equivocation`, the space suspended; each item
    about 18 s from submission to its outcome at the finalized block; the
    testnet logging no error.

**The review** (Opus, accept with fixes), folded:
- **F1:** a `write` the host refuses (`FULL`) traps, so the whole
  accumulate reverts; the JAM-only host answers `FULL` for a full storage
  (`ServiceStorage::full`); pin F and an ops note: the balance above the
  threshold, alerted on.
- **F2:** outcomes keyed by `BLAKE2b-256(package hash ‖ payload hash)`, so
  a later package of the same payload cannot overwrite one;
  `submit_package` returns the package's hash.
- **F3:** a `Control { space, nonce, AddKey | RemoveKey | Resume |
  SetController }` item, the controller's, at the space's next nonce; the
  equivocators kept in the space's record, a resume as the model venue's;
  `JamVenue::control`, `status`.
- **F5:** the service created with a least accumulate gas an item (2M);
  at most 64 roots a statement (code 1 past it).
- **F6:** `JamVenue::new` checks the code hash against the configured blob
  and the configuration's genesis against the chain's, its time from the
  configuration; pin D: (genesis, service) fixes the code.
- **F7:** pin F: a statement failing several checks gets its venue's first.
- **F8:** the CE 133 test isolates the bound; `PACKAGE_FRAMING` exact (269
  B, jamt's encoding); a package to the service holds at most 17 items,
  their verdicts within a report; the verdict bound recorded (36,891 B
  before the roots' cap; commit `c8150c54` said 36,972).
- **F4**, at the merge onto 6.17b: `JamVenue::anchor` verifies the
  signature over its digest here and queues the anchor in 6.17b's
  `AnchorQueue`, answering `Queued` at once (under 10 ms with a stalled
  node, tested); the queue's worker lands it (`New`/`Again` done; `Window`,
  `Age`, `Equivocation` dead; `Open` or a transport failure again a slot
  later, the rest a window later). `status` reads the space's record; a
  submit's code is `Refused(code)` (6 the venue holding it accepted), a
  transport failure `Unjudged::Unknown`. The blocking calls a run's tooling
  makes stay on `Jam`.

**Merged** into `vos-core` (the `check` recipe's tests both sides', the
manifests' dependencies both sides'); the conformance vectors and the kit
unchanged by it (`just check-kit`, `just conformance`).

**6.19 accepted.**


## Load-sensitive tests

`vos-node`'s `cluster`, `served` and `cuts` suites, run pinned to two cores
(`taskset -c 0-1`) with sixteen test threads beside four spinning
processes and a loop of 256 MiB `dd … conv=fsync` writes on the same disk:
the load `just check` meets while other worktrees build and prove. Two
cores alone, or with spinners alone, failed nothing once the elections
below were slowed; the syncs are what moved leaders. Every failure was the
test's or its harness's, not a node's:

- **Writer stalls under shared syncs.** Every node of a test shares the
  host's one disk; a sync held past `STALL_AFTER` (1 s) marks the writer
  stalled, and the node stops listing the groups it leads, so they elect
  elsewhere: leaders moved under calls aimed at them (`NotLeader` in
  `membership`, `roots`, `liveness`, `large_results`, `replication`,
  `workflows`; "node 1 leads some" timing out). The bound is now
  `Config::writer_stall`; both harnesses set 5 s. The owner's answer
  (2026-10-23, `owner-decisions.md` 16): the bound defaults to the
  election timeout's upper end (`Config::stall_bound`, 3 s at the
  defaults; `writer_stall` an override), so a slow sync costs leadership
  no sooner than a crash would. The harnesses keep 5 s, past their 2 s
  elections: their nodes share one disk under the load above.
- **Elections of 300–600 ms** (`cluster`) and **40–80 ms** (`served`)
  lapsed when a starved host held a heartbeat; both harnesses now elect in
  1–2 s (`forwarding::a_leader_whose_clock_trails…` "it goes on leading",
  `a_resend_of_a_queued_first_call…` `NotLeader`).
- **Calls at a stale leader.** `Cluster::call_at_leader` sends a request
  again at the agent's leader on `NotLeader` or `TimedOut` (a resend at its
  sequence runs once) until the in-process wait runs out, where
  `increment_at_leader` gave up after ten tries (~2.6 s); `increments`,
  `roots`' writes, the shop's starts and the generic calls of
  `liveness`, `queries`, `membership`, `large_results`, `replication` and
  `workflows` follow it. `Cluster::replace` follows the leader too, on
  `NotLeader`, `InProgress` or `TimedOut` (a leader replacing itself
  answers that when the next leader's announcement outlasts 2 s): a try
  after one that went through finds `out` gone or `inn` placed and waits
  for the final placement. The tests' direct `replace(…).unwrap()`s go
  through it; the overlapping replacements' thread sends again on
  `NotLeader`.
- **A session stale before its first call.** The cluster's session was
  timed at the cluster's start, once for every agent; creating forty
  agents, or twenty writes at each of three, on a loaded host took past
  `SESSION_SKEW_MS` (60 s), and a first call was refused `StaleSession`
  (`a_flaky_then_cut_link_moves_no_term`, the representative's reads).
  Each agent's session is timed at its first call now, by its leader's
  clock as the test sets it.
- **Real time crossing `B_0`.** `a_read_is_stated_within_a_window_and_its_close`
  founds 120 s windows a minute before now and must start its read in
  window 0; a loaded setup took longer ("every replica holds the
  request"). Its clocks are held early in window 0 while it sets up.
- **A served client's session timed ahead.** A client times its next
  session while it uses one, so a clock jump meets sessions timed before
  it; a loaded host took past `SESSION_SKEW_MS` to reach it, and its first
  request was rejected `StaleSession` with no jump to explain it
  (`one_request_at_a_time_applies_once_through_failures`). Before the
  first request of a session timed ahead goes, one older than half the
  skew is timed again, unless the clocks jumped since: none of it was
  sent.
- **Waiting for clients to pause.** A client pauses between requests,
  a touring one once its tour ends: up to `ANSWERED` (60 s) and
  `TOUR_ENDS` (120 s). The wait was `ANSWERED` ("the clients pause" in
  `workflows_apply_once_through_failures`); it is their sum, `PAUSING`,
  in the served run and the process suite.
- **A jump no session met in time.** The run checks that a session timed
  before every clock jumped met the jump; a loaded host's clients reached
  none before the sessions expired at a later fault ("no session met the
  clocks' jump"). The faults wait for one, up to `PAUSING`, after the
  jump.
- **A background drop read at once.** A follower caught up by a snapshot
  drops its old epoch in the background after the switch; two tests read
  it gone at once ("the old epoch is dropped"). They wait for it, and for
  any later stream a loaded host's leader began and the follower no longer
  needs, which the follower drops once idle for 30 s: 45 s, naming the
  epochs left should they stay.
- **Naps shorter than the setup after them.** A workflow's nap of 1 s
  ended before the test lost its page on the leader ("the leader halts"
  timed out); one of 1.5 s ended before the upgrade it should sleep
  through. Naps of 5 s and 10 s, and the leader read after the start.
- **A compaction a minute did not reach.** The served runs hold a follower
  down until its leader compacts past it, for at most a minute, then
  check some node caught up by a snapshot; a loaded host's clients filled
  no compaction in a minute ("no node caught up by a snapshot"). Three
  minutes.
- **Another leader pooling the program.** `replicas_that_never_took_the_install_pool…`
  checks that only the leader pooled the program; a loaded host moved the
  leader, which pooled it again on the new one (and an install that came
  to a leader as it stopped leading pooled it there too). Node 1 now leads
  until the test stops it: the others elect only past 8 s without it.
- **A batch formed before its calls were queued.** The large-result
  tests queue ten calls behind a held refine for one batch past 2 MiB; a
  loaded host built them slower than the leader's 2 ms linger, and the
  leader took the first alone. The requests are built before any is
  queued, and those tests' leaders linger 50 ms.
- **Leadership moved by chance, timed.** A test stops leaders until the
  replica a snapshot caught up leads, within 20 s: within 16 moves now.
- **The attest's and anchor's latency** from `B_0` bounded by `D + 10 s`
  (34.4 s taken): `D + 30 s`, far within the 120 s window.
- **An install answered `TimedOut`.** A loaded host derived the
  install's programs past the node's 30 s answer deadline
  (`a_program_leaves_the_pool_with_its_last_pin`). `install_at_leader`
  sends it again then too, as an install sent again overwrites, within
  twice the in-process wait.
- **A follower's last entry read before it stopped.** The served runs'
  follower held down past compaction was compared with its last entry
  read just before the stop; a loaded host's stop let it take entries
  past it, and it came back by the log ("no node caught up by a
  snapshot", with the compaction logged done). Its bound is the running
  replicas' last entry, read once it is down. (The counter race below
  fails the same check; which of the two the run met is not known.)
- **A switch counted after it shows.** A replica's snapshot switch
  commits its state, then updates the group's, then counts the switch; a
  loaded host let the test read the counter between ("switched once", 0,
  the follower's log starting at the snapshot's index, eight copies at
  once on the two cores failing 2 in 48). The test waits for the count;
  the served runs' "no node caught up by a snapshot" sums the counts
  within an attempt's 2 s. `compacted_past` also waits for every running
  replica now, not the leader alone, so whichever leads must send a
  snapshot.
- **A late result taken for a marker.** `an_agent_of_no_space_gets_no_marker`
  counted any result past its start; an install applied late is one. A
  marker is an empty result, and only those count.
- **Deadlines against real time.** The resend-round tests waited 5 s
  against a 20 s round (6.7 s taken): the round is 60 s, longer than any
  wait for a delivery, and a delivery needing no round has 15 s. The
  overlapping replacements' calls had 3 s (4.7 s taken) against the 10 s a
  held-up call would wait: 6 s, the replacements 30 s. Quiet groups
  elect again within 10 s of their leader's node stopping, not 5 s, with
  elections of one to two seconds. Workflows' computations end within
  60 s, not 20 s. The served cut run's reads, three 2 s windows to be
  served, all ran out ("no read served"): windows of 8 s (4 s still
  served none in one loaded run of three, each read's proof built on the
  starved cores).
- **Diagnosis.** The exactly-once run's convergence wait names what each
  replica holds against what it should.

Gate, under that load: `served` 10/10 and `cuts` 10/10; `cluster` 9/10, its
one failure `a_snapshot_stream_outlasting_the_leaders_deadline_goes_on`'s
"no other stream started: 2 did". One test met only beside another
worktree's builds (load average above 30) was open too:
`a_stale_leader_left_out_of_the_configuration_retires` ("the stale one
still leads"). `just check` green. Both are closed on `s6/carrier`:

- **The snapshot stream's bound.** While the follower is down, the
  leader's streams to it fall silent and end (10 s each), as many as the
  stop lasts; a loaded host's longer stop saw two. The property is of the
  stream the follower answers: `Hooks::delay_chunk(to, sequence, wanted)`
  now sees each chunk's place, and the test asserts that no stream starts
  once the follower has asked for a chunk past the first (`wanted > 0`),
  and that the answered stream ran past the 300 ms deadline. The silent
  ones before it are allowed.
- **The stale leader.** A leader checks its quorum once per the election
  timeout's upper end; the test's elections are (1 s, 6 s), so the cut-off
  leader steps down 6 s at the earliest, while its followers campaign from
  1 s. A loaded host or a late draw may still beat it: the links heal and
  the cut is made again at the leader they settle on, up to five times.
- Under the load above (two cores, four spinners, sixteen threads): both
  tests 8/8, `snapshots` and `membership` whole 3/3.

## Step 6.18: the prover worker and the reproducibility gate

On `s6/worker` (from `9e17ab91`). The full record is the step's log.

- **Built:** `vos-node-prover` (`node/prover`), linked by the node, the
  masked prover behind its `prover` feature. A node-local table
  (`NodeRow::ProverJob`, `ProverMark`): each statement's job by id,
  `queued | proving | proved(proof) | submitted | accepted | refused(code)
  | dead`, and a watermark per agent. Every replica running a prover reads
  its log into jobs through its applied index, and compaction keeps the
  entries past its mark (at most 2^16 behind, then an alert); the leader
  alone proves and submits. For each attest at a cut: the statement
  (format 39, the program id recomputed from the kernel's blob) and its
  id; dead when its anchor would pass `MaxRootAge` by the venue's time
  (`VenueClient::time`) before the proof ends; the kernel re-run on its
  witness (output, public arguments, roots and io-hash the record's, else
  refused); segments at the class of the most steps, leaves, folds and the
  masked wrap (`vos_pvm_recair::tree::prove_final`); the proof kept and
  pinned until its job finishes, recorded through the leader
  (`Input::Proven { window, id, proof }`, `keys::proven(window, id)`,
  `00 23 ‖ window ‖ id`, the first proof alone); submitted once recorded
  and anchored, a repeat accepted, a lost answer again after 30 s,
  doubling. A restart re-queues the job it was proving; a prover's panic
  is caught, three attempts and the statement is refused; a new leader
  takes a recorded statement with the proof fetched from a replica, or
  proves it again past its patience. `JamVenue` answers a statement its
  service holds seen accepted, unsent.
- **The reproducibility gate:** `pvm/proof/src/constants.rs` pins the
  program ids of the window kernel, `balance` and the predicate, `H_fold`
  and the wrap's roots (28, 39), recomputed in `test-proof` with and
  without `debug-internals`; `vos program-id <elf> <method>` (and
  `--circuits`); `just repro-aarch64` (qemu-user, the aarch64 GNU
  toolchain) [measured]: every id and constant equal on aarch64. They pin
  the known programs; a venue or an installer trusts an id only by
  recomputing it from the blob.
- **Tests:** the worker over a model node (a restart mid-proof leaves one
  proof; a duplicate submission accepted once; a leader change proving
  nothing twice; a dead statement skipped; an io-hash mismatch refused; a
  panicking prover refused after three); the masked prover's checks on
  real kernel runs; on three nodes, a read's statement proved, recorded and
  accepted, a recorded statement submitted once across a leader change and
  a compaction, a record applied during a proof proved with the log
  compacting every 8 entries.
- **Throughput gate** [measured, three runs, the machine shared, load
  10–26]: the window statement 40.3–50.0 s (3 segments 22–25 s, leaves
  6.5–9.4, folds 3.6–7.4, the masked wrap 8.0–9.7), `balance` 17.9–28.6
  s, peak resident about 6.0 GiB: three window statements take 121–150 s
  of a 10-minute window, leaving room for 16–27 `balance` statements. **Pass**; the prover-time
  levers are not needed. Cut at a short class instead (before `eae5bed6`)
  the window took 176 s in 17 segments: the gate now asserts at most 4.
- **The review** (Opus, `6.18-review.md`): accept after F1–F5, every
  finding folded (`6b7ec21b`): F1 records lost to compaction (every
  replica scans, compaction held by the mark); F2 `JamVenue::time`; F3
  JAM's seen read before a submit, resubmissions backed off; F4 proofs
  pinned; F5 panics caught, attempts counted; F6–F10 the gate's segments,
  the recipe's names, the sentinel id, debug output, the proven row keyed
  by window.

Commits: `df8dbee8`, `203115ff`, `10de7680`, `46a23037`, `eae5bed6`, the
merge of `vos-core` (`331ab890`), the JAM venue's fold (`b8471312`), `6b7ec21b`,
this record.

**6.18 accepted.**

## The Kreivo chain client parked

On `s6/kreivo-park` (from `9e63e5a9`).

**The owner's decision (2026-10-20, decision 12c).** Slice 6 agreed on
design and kit only for Kreivo (12b): no pallet code from VOS, and a node
client tested against a mock of the designed interface. Step 6.17b went
further: a chain transport on subxt, a fee-paying node key and `vos`
tooling. The owner already has an in-house Substrate client, `sube`
(virto-sdk: metadata-driven, sr25519 through libwallet, a smol runtime).
The chain client is parked, handoff only. Master's
`extensions/substrate`, already on sube over smoldot, is the expected
transport: it is ported onto vos-core's extension host once that host
exists, and `KreivoVenue` reaches it by message through `Transport`. The
owner also decided (12d) that the prover stays built into the node and
the extension host waits until after the slices, so Kreivo is mock-only
until then.

- **Removed:**
  - `node/venue/src/kreivo/chain.rs` (`ChainTransport`) and subxt,
    subxt-signer, scale-info and tokio from `vos-venue`;
  - the `kreivo` and `kreivo-unvetted` features (on `vos-venue` and
    `vos-cli`) and `kreivo::selectable`;
  - `AccountSeed` and `zeroize` in `vos-venue` and `vos-node`;
  - `examples/kreivo_dev.rs`;
  - the node's account key: `NodeRow::VenueAccount` (its tag `0x10` left
    unused), its store reads and writes, `venue_account`,
    `rotate_venue_account`, `Config::venue_with_account` and
    `VenueWithAccount`;
  - `sign_with_node_key`, which only registration used;
  - in `vos`: `node run --venue/--venue-url`, `node venue-account
    show|rotate`, and `space venue register|authority add|remove|budget`
    (`node/cli/src/venue.rs`);
  - the `clippy-kreivo` recipe; `doc-check` now documents `vos-venue`
    with `mock` only.
- **Kept:**
  - `KreivoVenue`, and `Connect`, which the ported transport plugs into;
  - `calls`, `Transport` and the `Sender`;
  - the `AnchorQueue`;
  - the mock and `node/venue/conformance/*.json`, with `just
    conformance`;
  - the kit (`pvm/proof/kit/`, `vendor-verifier`, `vos-sync`,
    `check-kit`, `kit-lock`);
  - every test of `KreivoVenue` over the mock. The cluster's clients now
    sign as an account derived from each node's number.
- **Counts:**
  - code: 20 files, 1,446 lines removed, 20 added;
  - `Cargo.lock`: 221 packages pruned (553 to 332), 2,578 lines removed.
- **The handoff:** `spaces-pallet.md` §9.1 lists what the ported
  transport must provide, from the parked code and its review, marking
  what master's extension covers already:
  - the key's custody and rotation;
  - the envelope;
  - pool-aware signing against a state-nonce landed check;
  - the pool's refusals classified;
  - the watch giving up past the era;
  - reconnect, with the node starting while Kreivo is down;
  - transport security;
  - the last window never moving back;
  - the release gate;
  - the CLI.

  The vectors and the mock are the contract. `slice-6-on-chain.md`'s
  6.17b and 6.21 now say this: 6.21's Kreivo leg runs `KreivoVenue` over
  the mock transport only.
- **Gates:** `just check` at `bc218fcd` green: 101 suites, 1,338 passed,
  0 failed (12 GiB scope, `nice -n 10`, 8 jobs). `just conformance`
  rewrote the vectors byte for byte.
- **The review** (Opus): ready to merge; its findings folded.
  - The cluster test makes one client per node, however many configs a
    node's open retries make.
  - Tag `0x10`'s old layout is documented, and the tag reserved.
  - Who owns the port is stated: VOS, after the slices; the pallet is the
    teammate's; the live leg waits on both.
  - §9.1 notes that the extension reads at finalized blocks only.
  - The envelope is said to be the transport's.
  - `core-model.md` Q18 separates what is decided from what is open.

## Step 6.20: the carrier audit (R7)

On `s6/carrier` (from `bc175ed0`). The full record is the step's log.

- **The harness** (`vos_checker::carriers`), reusable by 6.21's
  `e2e-chain`:
  - **Needles** are what a run knows it must not show, each in its bytes,
    hex, `Debug` list and, for numbers, little-endian and decimal digits:
    - the internals of each proof (`vos_node_prover::Internals`, from
      `MaskedProver::prove_disclosing` over the tree's watch seam,
      `vos_pvm_recair::tree::prove_final_watched`): every segment, leaf
      and fold proof's trees' roots, three windows of its encoding, and
      its output's boundary digests; each segment's step count and
      boundary indices; each boundary's memory root and image commitment
      (never the kernel's public image root); the registers φ0..φ8;
    - from each record (`Attest`): the served rows' values and salts, the
      cut's roots, salt and paths, the arguments not among the public ones,
      and BLAKE2b-256 and BLAKE3 of each and of the witness;
    - each debug output's own text.
  - **Carriers** leave the role or stay within it: every needle is searched
    in those that leave; node proofs, memory roots and register files in
    every carrier. One Aho–Corasick pass a carrier.
  - **Capture:** `Tapped` (any `VenueClient`: anchors and submissions, laid
    out as the model venue, Kreivo's calls and the JAM service's items take
    them), `Logs` (the process's tracing at every level), `Stderr`,
    `Hub::tap` (every frame), `directory` (a node's disk), and
    `assert_searchable` (each needle found when planted, every kind made).
- **The run** (`just test-carriers`, in `test-proof`): three nodes prove a
  read's statement at window 0's cut with the masked prover
  (`masked::Disclosing`), recorded and accepted, every debug output's
  environment set. Carriers: the anchor and the submission in each venue's
  layout, the client's answer, the logs, standard error; every frame by
  class, each node's log entries, work results, prover table and every
  file it wrote. 91 node-proof, 17 row, 28 hash, 9 step, 15 memory-root,
  23 register and 7 debug-output needles; about two minutes.
  **6.21:** `e2e-chain` wraps its venue clients in `Tapped`, proves with
  `Disclosing`, installs `Logs` and `Stderr` before its nodes start, and
  feeds each node's disk, the JAM service's reports and the Kreivo mock's
  extrinsics as carriers; then `assert_searchable` and `assert_clean`.
- **Found and fixed:**
  - **The PVM's instruction trace** (`vos_pvm::interpreter`, `trace!`
    each step: pc, opcode, gas): the prover's re-run of a kernel logged
    its control flow and, by its gas from 2^32, its step count (11.9 MB of
    logs a run; the step and register needles hit). Now under `vos-pvm`'s
    new `debug-internals`, with `GREY_PVM_DEBUG`'s registers at each
    run's entry and exit and its native code dump.
  - **`CPU_DUMP`** (rows 0 and 1 of the CPU trace on stderr) under
    `vos-pvm-proof`'s `debug-internals`; `ZKPVM_PROFILE` compiled out
    rather than `cfg!`-skipped; `CPU_EXPR_DUMP` was already inside a
    `debug-internals` function.
  - **Regression checks:** the run sets every debug environment and
    searches the logs and stderr for each output's text (with
    `vos-pvm/debug-internals` the audit fails on the trace, checked);
    `just check-no-debug-internals` (in `check` and `ci`): no production
    edge enables either feature, and the node's binary built with the
    prover names none of the variables nor the trace's message (with the
    feature it holds the message, checked).
- **The tests' `target/tmp/wrap/`:** final wraps only, of formats 28 (test
  circuits) and 39, their words, formats and judgements' inputs;
  `kernel`'s `wrap_files` checks each proof verifies as a final wrap and
  nothing else is there (checked on 59 files, and a junk proof refused).
- **Not leaks, recorded** (`SECURITY.md`'s table): an agent on JAM ships its
  attests whole, served rows included, in its packages (it keeps no row
  from JAM by design); the operator's `/stats` `refine_gas` and
  `step_gas`, and a proof's time in the logs, show a trace's size, as the
  prover's time does. `RefinePayload` is gone (6.9).
- **`SECURITY.md`** gains "What leaves the prover role", per carrier.
- **Gates:** the audit clean on four runs after the fixes, `just
  test-carriers` among them; `just check` green: 105 suites, 1,358
  passed, 0 failed, `check-no-debug-internals` in it (12 GiB scope, `nice
  -n 10`, 8 jobs).

**The review** (Opus, fix then merge: no leak, the harness's coverage
gaps, which 6.21 inherits), folded:
- **M1:** the run writes rows of high-entropy values past 2^40; a row's
  value that decodes as an integer is a number needle too; at least one
  value needle a row is asserted (41 row and argument needles a run).
- **M2:** a 32-byte needle of M31 limbs (the leaves' and folds' roots and
  digests, memory roots that are) is searched as its decimal limb list
  (`P2Hash([…])`, an array's `Debug`), its `M31(…)` list and its postcard
  varints; every byte needle in upper-case hex too, and its first 16 hex
  characters in carriers that leave; numbers as `0x` hex.
- **M3:** a fourth node in the space replicates neither agent: the frames
  to it and its disk and store leave the role, and are searched for every
  needle.
- **M4:** each node's store is a carrier by its rows (`Fjall::dump`), so
  fjall's compressed blocks hide nothing; the raw scan stays for blobs and
  the other files.
- **L1:** the seams behind features no production edge enables (`vos-pvm-
  recair`'s `watch`, `vos-node-prover`'s and `vos-node`'s `disclosing`),
  checked by `check-no-debug-internals`.
- **L2:** a canary through each capture path (a TRACE line from a node's
  storage thread, a line on stderr from a pool thread, a file in a node's
  directory, a hub frame, a submission through `Tapped`), each asserted in
  its carrier.
- **L3:** hashes under each of `vos-wire`'s and its venues' domains (11);
  numbers big-endian too; the gas a re-run left (2^32 less its steps);
  each part of a kernel's arguments no public argument covers. A number's
  byte forms need four distinct bytes, and a register the run's entry
  state holds (the halt address, the stack's top) is public: the first
  run with the new forms found a heartbeat's counter equal to a step count
  and the halt address in a node's store.
- **L4:** `SECURITY.md`: the node's log is on stderr; an agent's guest log
  lines are its author's text.
- **L5:** `prove_profiled` prints nothing without `debug-internals`; it
  returns the profile.
- **L6:** `wrap_files` fails on an empty directory (it runs after the
  suites, not among them), and a format-28 wrap must be of a test circuit:
  the kernels' predicate, or a circuit wrapped under 39 beside it. It
  caught a stale `window.*` in `vos-core`'s `target/tmp/wrap/`, a format-
  28 wrap of an older window program no test writes any more.
- **L7:** the snapshot stream's span measured from its follower's first
  answer (1.4 s of 36 chunks, against the 300 ms deadline).
- **Quality:** `carriers` split into `needles`, `audit` and `capture`;
  `Logs` on the shared lock; `delay_chunk`'s unused parameters named so;
  the disclosing prover keeps its segments' lengths apart; a record's
  rows split at its arguments' known length.
- **Gates after the fold:** the audit clean on three runs (four nodes,
  about two minutes each; 91 node-proof, 41 row and argument, 182 hash,
  10 step, 15 memory-root, 25 register and 7 debug-output needles; every
  canary in its carrier); `just check` green: 105 suites, 1,360 passed,
  0 failed. `vos-venue`'s `an_anchor_is_answered_at_once` met 10.1 ms
  against its 10 ms bound under load; its bound is 500 ms, the node it
  must not wait on timing out in seconds.

## Step 6.21: the end to end on chain

On `s6/e2e` (from `ede9f2af`). The full record is the step's log.

- **`just e2e-chain`** (`node/host/tests/chain`, `vos-node`'s `chain`
  feature, `testnet.sh chain`): a space of three nodes running `balance`,
  the window actor, the reader and the representative, each node proving
  with the disclosing masked prover (one proof at a time across the
  process), windows of 120 s (`D` 24 s). Outside `check` and `ci-full`,
  as `jam-testnet` is: it needs the PolkaJam binaries and a C compiler.
  About 20 minutes.
  - **Kreivo, the mock only:** the founder funds the sovereign account,
    the controller registers the space from window 0 with a founder's
    signature (`Node::sign_registration`, the node key over pin D's
    registration digest) and adds each node's account as an authority,
    paired with its anchor key, all by the pallet's calls; each node
    anchors and submits through its `KreivoVenue` over the mock's
    transport, a block's 6 s on every extrinsic. Windows 0–2 anchored, a
    balance statement at window 1's cut accepted.
  - **The migration at k = 3:** in window 2 the space is registered at the
    JAM service from 3 and migrated away from the mock from 3; the nodes'
    venue moves to the service once window 2 is anchored at the mock (114 s
    before window 3 closes). Window 3's statement, accepted at JAM, is
    refused at the mock **`0x5`**, its deposit forfeited.
  - **JAM, on PolkaJam v0.8.0 (interpreter):** windows 3–5 anchored, a
    balance and a window statement at each cut, all masked (format 39),
    all accepted. The reader's rootless statements, proved by the run: the
    venue-bound one accepted at its venue and refused at a second
    deployment of the service **`0x7`**; the unbound one accepted at both.
  - **Past `MaxRootAge`:** the testnet's clock is the host's shifted by a
    file's milliseconds (`node/jam/clock-shift.c`, preloaded into its
    nodes): moved 25 h ahead, the chain skips 15,000 slots (1,249 epochs,
    Safrole falling back to its fallback keys) and goes on. Replayed, the
    venue-bound statement at its venue, the unbound one at both venues
    **`0x6`**; window 3's rooted statement **`0x5`**. The production
    constant is untouched.
  - **The carrier audit** (6.20's harness, as 6.20 asked): each venue
    client in `Tapped`, `Disclosing` behind `disclosing`, `Logs` and
    `Stderr` installed before the nodes start; carriers: what each venue
    was sent (anchors, submissions, in each venue's layout), the JAM
    service's work reports from PolkaJam (`workPackageStatus` and
    `workReport`, 14), the mock's signed envelopes, both anchor chains
    (the mock's storage, JAM's anchors for windows 3–5 and the space's
    record), every frame between the nodes, each node's log entries, work
    results, prover table, store rows and disk, the testnet's log and
    chain database, the process's logs and standard error: 252 carriers.
    Needles: 219 node-proof, 67 row and argument, 455 hash, 42 step, 39
    memory-root, 89 register and 7 debug-output (nine statements proved).
    `assert_searchable` and `assert_clean` pass.
- **Found and fixed:**
  - **A chain's own records match numbers by chance.** The testnet's log
    held step counts as `conn_id=2148` and the like, and its database the
    eight bytes of a register at a boundary inside the service's program
    (the same four registers of two window statements, at two boundaries:
    layout values). What the venue was sent is searched whole as carriers
    that leave; a chain's logs and database are now `Reach::Recorded`:
    every needle in its full forms, not a number's digits or bytes nor a
    hash's hex prefix (tested). `SECURITY.md`'s table names the reports,
    the envelopes and the chain's records.
  - **A rootless record's needles:** `Needles::attest` takes a record of no
    window, its witness its arguments alone (tested).
  - **No founder could register at JAM from a node:** `sign_with_node_key`
    went with the Kreivo tooling; `Node::sign_registration` signs pin D's
    registration digest only, and `Jam::register_signed` takes it.
  - **Guarantors take no package for a few slots after the jump:** the
    replays wait five finalized slots; a replay whose package was refused
    or did not land in time is sent again, and one that landed late counts.
- **Added:** `vos_jam`'s `PolkaJam::work_report`; `just clippy-prover`
  lints `vos-node`'s tests with `chain` (the carrier audit's and this
  one). (The review's fold below replaced the landing helpers with a
  watch.)
- **Measured** [measured, the run that passed; the machine shared]:
  - **latency, `B_w` to acceptance** (L 120 s, D 24 s): Kreivo 48.8 s
    (`t_prove` 17.0 s); JAM 60.6–103.5 s, a window's two statements proved
    in turn (`t_prove` 15.6–39.8 s; after its proof 16–21 s: the anchor's
    landing and the submission's, about three slots each). Pin D's
    `L/2 + D + t_prove + inclusion`, for reference only (its `L/2`
    computed, not measured), is 108–140 s with these terms; the gate
    `L + D + t_prove + 30 s` is 189.6–213.8 s: **every statement within
    it**, the slowest 103.5 s against its 213.8 s;
  - **JAM gas:** refine 83.24M–84.13M a statement (a statement accepted,
    repeated or refused alike: the proof is verified before the state is
    read); the last accumulate 286,989 gas (6.19: 83.78M, 107,910);
  - **Kreivo's sovereign account:** funded 100 UNITS, 0.5 held for the
    registration; 3 anchors and 2 submits by the authorities, a fee of 1
    UNIT each (`FeeBound`), the accepted submit's deposit refunded, the
    refused one's 0.5 forfeited: 5.5 UNITS charged in all, asserted; no
    alert; the budget 12 UNITS a window, never reached;
  - **the prover:** 7 statements at cuts in 171.2 s, 24.5 s on average
    (balance 15.6–22.8 s, window 28.9–39.8 s; the rootless 12.7–13.7 s):
    about 25 a 10-minute window, 5 a 120-second one.
- **Runs:** five; the first four failed on the test's own waits (a
  follower's table counted as pending; the replays before the guarantors
  took packages again) and on the chain's records (above); the fifth
  passed whole. Every PolkaJam process stopped by its scope, each run's
  chain directory removed.
- **Gates:** `just e2e-chain` at `f2b69d46` passed (1,158 s; the code since
  unchanged but a test of `vos-venue`'s queue). `just check`: its first
  run 96 suites, 1,354 passed, 1 failed, `vos-venue`'s
  `queue::tests::each_space_waits_apart_and_sends_in_window_order`, a race
  of the test's own (the worker sent window 6, alone in the queue, before
  window 5 was pushed): fixed (`9bf4ed57`), space 1's send held while space
  2's anchors are queued, 30 of 30; then at `9bf4ed57` green, 105 suites,
  1,362 passed, 0 failed, about 14 minutes (12 GiB scope, `nice -n 10`, 8
  jobs).
- **Left out:** the Kreivo leg on a dev chain (M3b's
  deferred gate 2, the teammate's pallet and the ported transport); the
  latency of a request at a random time in its window (pin D's `L/2`),
  computed from the measured terms rather than sampled.

**The review** (Opus, fix then merge), folded (`d678d348`, `5859c409`):
- **1 (medium), the real JAM wire:** `Tapped` re-encodes what a client is
  asked to send, and the anchors the node's `AnchorQueue` landed, their
  reports, the registration and the replays went around it. `PolkaJam`
  has a `watch` (`vos_jam::live::Watch`, none in a node's client), shown
  each package `submit_package` sent and its extrinsics once the node took
  it; each deployment's watch in the run keeps every package (19: JAM `a`
  16, the registration, the anchors, the statements and replays; `b` 3)
  and reads each one's work report while its status names it. Every
  package, extrinsic and report is a carrier that leaves, searched in
  every form. **`Reach::Recorded` kept** for the testnet's log and
  database: what reached the chain is now audited whole and at full
  strength as it went, so the chain's own record of it adds only its own
  numbers, hashes and code, where a number's forms match by chance (run 4:
  connection ids, a register's value in the service's code), and blanking
  the deployed blobs would not stop the log's counters. What `Recorded`
  searches is stated exactly (`carriers/mod.rs`, `needles.rs`,
  `SECURITY.md`): every needle's bytes, whole hex and `Debug` list (and
  M31 limb forms), a register file's bytes; not a hex prefix, a number's
  forms or a debug output's text.
- **2 (medium), canaries:** a TRACE line from a node's thread and a line
  on standard error are asserted in the logs and standard error; the
  chain directory and the log are expected, not skipped; the chain's
  database holds a submitted statement's encoding and its work report as
  plain bytes (asserted: the database is searchable, not compressed or
  erasure-coded where they lie), and its log a report's hash as it names
  it (`0x` and 16 hex characters), asserted.
- **3:** the run's own `Jam` venue is gone; the nodes and the run use the
  production `JamVenue`, wrapped only in `Recorded` and `Tapped`; gas is
  read from the outcome the service keeps of each submission's item in
  any package the watch saw.
- **4:** `Statements::land_package` and `Jam::land_package` removed,
  `anchor_of` crate-private; `PolkaJam::work_report` and
  `Jam::register_signed` kept.
- **5:** `Node::sign_registration` returns none for a node of no space or
  one the genesis does not name
  (`anchor_keys::only_a_founding_node_signs_the_registration`).
- **6:** a replay's package that lands after its wait timed out is kept by
  the watch, its report collected, and its outcome counts; the record says
  a replay is sent again only when its package did not land.
- **7:** pin D's figure is a single reference line, not a column.
- **8:** the test in phases (`Run::start`, `kreivo_leg`, `migrate`,
  `jam_leg`, `rootless`, `judged`, `replays`) and modules (`kernels`,
  `collect`, `measure`).

**After the fold** [measured, run 6, at `5859c409`'s code]: every verdict as
before (Kreivo window 1 accepted; windows 3–5 at JAM, six accepted;
window 3's at Kreivo `0x5`; rootless bound `0`/`0x7`, unbound `0`/`0`;
past `MaxRootAge` `0x6`, `0x6`, `0x6`, rooted `0x5`). Latency: Kreivo
49.7 s; JAM 60.8–97.1 s; gates 191.9–210.3 s, all within; pin D's
reference 108.9–138.4 s. Refine 82.04M–84.74M a statement accepted, the
venue-bound one refused at `b` before its proof 0.11M; last accumulate
286,989. Kreivo: 5.5 UNITS charged, asserted, no alert. Prover: 7
statements at cuts in 170.5 s, 24.4 s on average. Audit: 290 carriers, 19
packages with their extrinsics and reports; needles 219 node-proof, 67
row and argument, 455 hash, 42 step, 39 memory-root, 89 register, 7
debug-output; clean, every canary in its carrier. 1,150 s.
- **Gates after the fold:** `just e2e-chain` passed (run 6, above); `just
  check` at `5859c409` green, 105 suites, 1,363 passed, 0 failed (12 GiB
  scope, `nice -n 10`, 8 jobs).

## M3b and M3c accepted: Kreivo's design and kit, the prover worker, the JAM service, end to end

M3b is 6.16, 6.17 and 6.17b: the verifier kit and the spaces pallet's
design, the reference mock and the conformance vectors, the node's Kreivo
client. M3c is 6.18–6.21: the prover worker and the reproducibility gate,
the JAM statements service, the carrier audit, the end to end on chain.
Their acceptance (the plan's "M3b acceptance", and 6.21's gate) at
`vos-core` `68570481`.

**Gates** [measured; each under a 12 GiB scope, `nice -n 10`,
`CARGO_BUILD_JOBS=10`, `CARGO_INCREMENTAL=0`, one heavy run at a time;
`ci-full`'s recipes run one by one in its order, each heavy part started
only with 14 GB or more available]:
- **`ci`** (at `68570481`): green, 120 suites, 1,465 passed, 0 failed,
  2,093 s (34.9 min, a 30-min wait for memory before `test` not counted).
  Among them M3b's gates: `vos-venue`'s `kreivo::conformance` (the mock
  passing every vector, G1–G18; the client passing them through the mock;
  the vectors their generators', 28 `kreivo` tests in all), and
  `check-kit` (the kit's standalone `wasm32v1-none` build with no std
  feature, its sync check refusing a one-byte change in each of 5
  vendored files, a file added and one removed, a kit's own script, and
  `VENDOR`'s untagged, malformed or moved names).
- **`test-proof`:** green, 47 suites (each kernel test a process), 561
  passed, 0 failed, 3,191 s; `judge-wasm` 31 of 31 fixtures as recorded,
  under both semantics; the leakage tests at their medium N among them;
  the carrier audit (`test-carriers`) clean, 41 carriers, every needle
  kind searched, 87 s.
- **`test-bench-proof`:** green, 2 passed, 19 s.
- **`just fuzz 60`:** the seven targets a minute each, no crash, 826 s
  (`prove_verify_roundtrip` 39 runs in 278 s, its proofs past the
  minute; the others 1,819–14.9M runs).
- **The checker loop with cuts and the representative:** seeds 6401–6412
  × the three exactly-once tests and the cuts run with `CUTS_FULL` (the
  representative on three nodes, anchoring at the served harness's
  `ModelVenue`): 48 of 48 green, 1,490 s, load 4.4–7.3 at each seed's end.
  Per run and agent: 134–371 reads, 110–342 served, 15–48 not served in
  time, 0 unserved; 257–1,228 samples holding undo rows; 5 cut rows kept;
  `S_w` the same on every replica at the representative's two latest
  cuts, each seed; the venue 48–64 anchors a run, one a window, each
  checked against the replicas' roots, no evidence.
- **`just e2e-chain`:** passed at 6.21's fold (run 6, above); `68570481`
  changes only this record, so not rerun.
- **Failed first:** nothing in the code. The loop's first start failed in
  its driver (cargo takes one test filter before `--`; the filters moved
  after it), before any test ran.

**Milestone review: Fable — accept after fixes, folded** (`M3bc-fable.md`,
on `s6/m3bc-fix`): no path by which a wrong statement is accepted or a
forged, replayed or cross-venue anchor lands at either venue; the defects
are in the node's anchor and submission liveness, the audit's coverage
and the vectors' completeness. Its findings:
- **H1 (high):** a pallet ignoring a format's or program's activation
  window passed every vector: G7 now submits the fixture while its format
  is stored but not yet active (2), while its program's `until_ms` is now
  and while its `from_ms` is later (3), then accepted once active. Test:
  `a_broken_pallet_fails_the_vectors` (a mock taking every stored entry as
  active fails G7).
- **M1 (medium):** a queued anchor was never replaced, re-signed or
  alerted on: `AnchorQueue::push` replaces an entry of another signer;
  `Fate::Resign` (JAM's `Key` and `Signature`, Kreivo's 11 and 12, or a
  signer the client's last read no longer lists) drops it and keeps its
  window `unsettled`, which `VenueClient::unsettled` hands the leader,
  who takes it up again and signs with the newest key listed; a window
  the venue refused for good is remembered (`AnchorQueue::dead`) and
  answered `Window`, unsent; `JamSend` alerts on every refusal but
  `Open`. Tests: `a_queued_anchor_whose_key_is_removed_is_signed_again`
  (cluster: queued under K1 in an open window, K1 removed for K2 before
  it lands, landed under K2), the queue's
  `a_window_refused_as_signed_is_unsettled_until_signed_again`, Kreivo's
  `a_refused_key_hands_the_window_back_to_be_signed_again`, JAM's
  `each_anchor_code_has_its_fate`.
- **M2 (medium):** `Unregistered` waits as `Open` does, alerted once; the
  leadership takes up waiting windows again once a window length (and a
  recheck after a hand-back), skipping those refused for good. Test:
  `windows_refused_unregistered_are_anchored_once_registered` (a client
  answering `Unregistered` until it reads the registration; windows 0 and
  1 anchored after, then 2).
- **M3 (medium):** the worker submits again, with the doubling backoff,
  a statement refused 5 or `≥ 0x1000` (`vos_venue::transient`) until its
  anchor ages; 1–4, 7 and `0x1xx` stay final. Test:
  `a_transient_refusal_is_submitted_again` (5, then `0x1001`, then
  accepted; 3 final).
- **M4 (medium):** resolved by decision 17: the JAM client is dev
  tooling, venues attach through extensions, no `vos node run` venue
  option in this slice.
- **M5 (a):** the "gas a re-run left" needle read a boundary's timestamp:
  `Internals::run_steps` holds the run's steps, the needle `2^32 −
  run_steps`. Test: `the_gas_a_rerun_left_is_the_runs`. **(b):** the
  watch saw a package only once the node answered: `submit_package`
  watches before the call and reports the answer after; the end to end
  audits every package watched, and requires a report of each the node
  answered it took. Test: `a_package_is_watched_before_it_is_sent`.
  (c) and (d) carried (the plan's 6.22).
- **M6 (a):** G18 pins the length bounds, a genesis, a statement and a
  proof at each bound and a byte past it (`undecodable`), the calls' long
  runs as `{repeat, count}` parts; **(b):** `PruneCursor` named in
  `spaces-pallet.md` §5 and §6.5, its key the file's `unpinned`;
  **(c):** a `fees` vector pins `Budget`'s key and `window`, `spent`
  masked, and G13 shows an accepted submit's deposit credited back. Tests:
  `a_broken_pallet_fails_the_vectors` (other bounds fail G18, a pallet
  that does not credit back fails G13), `the_prune_cursor_is_unpinned`.
  (d): VOS reviews the teammate's harness (§9.1); (e) stated in §9.1, its
  code carried with the port.
- **Low:** L1 (an anchor's age by the venue's time), L2 (the tooling's
  `land` prefers an applied outcome across its two packages and refuses
  duplicate payloads) and L6 (part of M1) fixed; L7's §9.1 references and
  `SECURITY.md`'s logs row (Stwo's size estimate) fixed; L3 recorded in
  pin D; L3–L5, L7's rest and L8 carried in the plan's 6.22.

Commits: this record.

## The JAM client as development tooling (decision 17)

The owner's decision of 2026-10-23: `vos` and the node know no JAM. A
blob is deployed on JAM with JAM's tooling; a JAM extension running a
light node lets agents call agents on JAM later, once extensions exist
(12d). Until then the JAM client is development and test tooling.

- **Moved** into `tools/jam-dev` (`vos-jam-dev`, `publish = false`): the
  PolkaJam JSON-RPC and `jamt` driver, work packages with extrinsics and
  the statements service's client (`vos_jam_dev::live`, from
  `vos_jam::live`); `Jam` and `JamVenue` (`vos_jam_dev::venue`, from
  `vos_venue::jam`); the `vos jam service | testnet | statements`
  commands, now the `vos-jam-dev` binary's; `testnet.sh` and
  `clock-shift.c`. `just jam-testnet`, `jam-statements-testnet` and
  `e2e-chain` run through it; `vos-node`'s `chain` test takes it as a
  dev-dependency.
- **Kept, shipped:** the JAM statements service; `vos-jam`, the
  agent-as-JAM-service build (the builder, `programs`, the simulation,
  the emulated JAM), now without `base64`, `serde_json`, `hex` or the
  service among its dependencies (`MAX_INPUT` and `MAX_REFINE_OUTPUT`
  public for the dev crate's checks); `vos-venue` with the `VenueClient`
  trait, `ModelVenue`, `AnchorQueue` and the Kreivo client against its
  mock, no longer depending on `vos-jam` or the service.
- **`vos-cli`** has no JAM dependency on a normal edge (its `cli` test
  compares an install's derivation with `vos_jam::programs::derive`'s, a
  dev-dependency); the `vos jam` command is gone.
- **`just check-no-jam-dev`** (in `check` and `ci`): `cargo tree -e
  no-dev --target all` of `vos-cli`, with and without the prover, and of
  `vos-node`, with and without it, holds neither `vos-jam-dev` nor
  `vos-jam`.
- **Docs:** decision 17 in `owner-decisions.md`; 6.19 and 6.21 of the
  plan say the JAM client is tooling, and that the M3b/M3c review's M4
  (no operator path to a venue) is resolved by the decision: venues
  attach through extensions, and no `vos node run` venue option comes in
  this slice; `core-model.md` §18.
