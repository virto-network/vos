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
