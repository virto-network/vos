# Review: slice 6 plan, draft 3, and the spaces-pallet handoff design

Reviewer: Fable, 2026-10-19. Read-only. Against `stage/slice-6-plan.md`
(draft 3), `stage/doc-fixes.md`, `stage/spaces-pallet-design.md`,
`spaces-pallet-research.md`, `owner-decisions.md`, the evidence files,
`vos-core` at `31b7938e`, Kreivo master `87f8728` (+ spike `a7370f1`), and the
SDK sources Kreivo locks (frame-system 48.0.0, sp-runtime 44.0.0,
fc-pallet-gas-transaction-payment 2.3.1).
The staged files are now `docs/design/slice-6-on-chain.md` (draft 4),
`doc-fixes.md` here and `docs/design/spaces-pallet.md`.

## Verdict

**Commit after fixes.** Every draft-1 finding is in draft 3 as a
specification or a test, none regressed; the owner's fifteen decisions are
reflected where they bind, with two small text drifts (findings 10, 11); the
critical path and estimates add up. The spaces-pallet design is implementable
by a teammate without our context, and its fee and account mechanics check
out against the SDK sources. It has one protocol hole an hour fixes
(registration's `start_window` is unsigned: finding 1), one economic gap the
owner's deposit choice widens (an authority can drain the sovereign account
with no bound but block capacity: finding 2), and one client rule that would
lose anchors (`WindowInFuture` is "skipped": finding 3). All fixes are
textual, in the two staged documents and pin D; none changes a step's shape.
Fix 1–7 before the commit (under half a day); the minors may land with 6.0d.

## 1. Draft-1 findings, checked in draft 3

| # | where it landed | holds |
|---|---|---|
| D1 | 6.17b (`node/venue/kreivo`, two layers, subxt or raw RPC), 6.0e, decision 12; critical path 16–26 | yes |
| A1 | pin A (R = 8, p^-5), pin C (no production check; the 4/8 test), 6.3 | yes |
| A2 | 6.6 gate 2 as witness indistinguishability, control, power stated | yes |
| A3 | 6.2's "the masked reference shape from the built components" | yes |
| A4 | pin C's `cargo tree -e features,no-dev -i vos-pvm-recair` per binary; `debug-internals` ⇏ `seeded-masks` | yes |
| A5 | pin A's per-component levels (15, 16, 12; 17; 22) | yes |
| A6 | 6.4 "the trust boundary, named" (widths; `[3,3,3,2]`) | yes |
| B1, B2 | pin A / 6.1 (40's reason); 6.4's registry-equality test | yes |
| C1 | pin E step 3 `Closed { w, rep_root, paths }`; 6.14's leader-change test | yes |
| C2 | pin F, 6.5 (`0x6` past `MaxRootAge`), 6.19, design §2 and §6.3, G9 | yes |
| C3 | pin E "a window not closed in time", 2 re-cuts, `NotClosed`; 6.14 outcomes | yes |
| C4, C5, C6 | 6.5 `range`; 6.10 precompiles `RootKind` with u8 wire; `vos-anchor` SCALE by hand | yes |
| C7 | pin D states the two-sided rule; the design does **not** (finding 12) | partly |
| D2 | superseded by decision 11 (the owner chose the deposit); the design carries it with its cost | yes |
| D3 | M3b acceptance | yes |
| E1–E4 | 6.0b's payload reading; 6.19 accumulate checks the signer; 6.19's tooling; 6.21's JAM leg per decision 12b | yes |
| F1–F4, G | 6.5 F; `commitment`; 6.20 in the path; pin C's build check; 6.12's first test first | yes |

Nothing regressed in the rewrites. The arithmetic: M3a 8–13 + 0.5, M3b 4–6,
M3c 6–9.5, total 32–49; the path 6.0a → … → 6.22 sums to 15.6–25.5 weeks.
M2's line (5.5–8 beside) ends before 6.18 needs it (≥ 8.6 weeks in); 6.17
waits for 6.5 (M2 line) and reaches 6.21 with slack. Correct.

## 2. The owner's decisions

All fifteen are in "Taken by the owner" and bind the right places: 1 (pin D,
6.10), 2 with its chain-time rule (pin D, 6.17, 6.18, 6.19, the risks row)
and the latency paragraph, 3 (6.9), 4 (deferred, the carried table), 5 (6.11),
6 (6.15), 7 (6.14), 8 (pins E–F), 9–11 (the design's §2 defaults), 12/12a/12b
(no pallet code, the mock, JAM-only on-chain e2e, design + kit), 13 (6.22's
twenty items), 14, 15 (6.0d). `w < now_w` is in pin D, the "Settled" list and
design §6.1. Two drifts:

- Decision 11 says "forfeited on refusal"; pin F and design §6.3 refund on
  refusal 6 (a repeat). Right call (two honest nodes can race), and the design
  lists it as §13.4 for the owner to confirm, but the plan's decision 11 text
  states the rule without the exception (finding 11).
- 6.17 "Design changes recorded: the staged design's §6.1 said `≤`" is stale:
  the staged design already says `w < now_w` (finding 10).

Nothing in the decisions is made unsound by the design. Decision 11's
forfeiture does widen finding 2's drain, which is why that finding asks for a
budget rather than a reversal.

## 3. The spaces-pallet design

Checked against the sources it cites: `into_sub_account_truncating` is
`("modl", pallet_id, SCALE(sub))` through `TrailingZeroInput`
(sp-runtime 44 `traits/mod.rs:2023`), so `kv/space` + 32-byte id truncates to
`space[0..20]` as stated; `CheckNonce` refuses a signer with no providers and
no sufficients (frame-system 48 `check_nonce.rs:74-78`); `ChargeGasTxPayment`
is a newtype over its inner extension with `IDENTIFIER = S::IDENTIFIER`,
`Implicit = S::Implicit` (fc 2.3.1 `extensions.rs:72-76`), so the transparent
wrapper is a real pattern; Kreivo's `OnChargeTransaction` is
`FungibleAdapter<Balances, ResolveTo<TreasuryAccount>>` (`currency.rs:57`);
`pallet_timestamp::Moment = u64` (`system.rs:163`); the genesis hash survives
`BlockHash` pruning (frame-system `lib.rs:2102-2106` never removes block 0),
so `VenueId = block_hash(0)` is readable in the runtime; `dec_providers` fails
with `ConsumerRemaining` (finding 9).

### 1. [blocker, design + pin D] `start_window` is outside the registration signature

`register(genesis, controller, start_window, founder_key, founder_sig)` is
callable by any signed account; the digest is
`"vos/space/register" ‖ venue ‖ space ‖ controller`. The genesis is public
(every member has it), and a signed registration sits in the pool before
inclusion. Anyone who sees it can resubmit the same signature with
`start_window = u64::MAX − 1`: the space is then registered, correctly
controlled, and can never anchor (`start_window ≤ w` fails forever); there is
no call that lowers `start_window`, and `migrate` only sets `end_window`. The
deposit is the founder's, the fee the griefer's. Squatting without a founding
key is impossible (the signature), replay across venues is refused (the venue
is in the digest), a duplicate is `SpaceExists`: the rest of registration is
sound.

**Fix.** Put `start_window` in the digest:
`BLAKE2b-256("vos/space/register" ‖ venue ‖ space ‖ controller (32) ‖ start_window (8, LE))`,
in pin D's table, design §3's table, §6.2 step 4, and `vos_anchor::register_digest`'s
signature (6.10's golden vectors). Also require `start_window ≥ now_w − MaxRootAge/length_ms`
at registration (an older start is pointless) and `start_window ≤ now_w + 1`
(a far-future start is the griefing). Add the griefed call to G1 as a refusal.

### 2. [major, design §7] A compromised authority drains the sovereign account at block speed

`ChargeSpaceFee` charges the sovereign for every `anchor`/`submit` an
authority signs, and `submit` forfeits `SubmitDeposit` on any refusal but a
repeat. A node whose sr25519 key leaks (or a rogue operator) submits garbage
proofs: each costs the sovereign the length fee (≈ 0.43 UNITS) plus the
deposit (UNITS/2), at the block's capacity (≈ 20 a block by proof_size, spike
6c): ≈ 18 UNITS a 2-second block, hundreds a minute. The controller's
`remove_authority` is the only brake, and it needs a human to notice. Finding
2 is the question the task asked ("drain attacks by a compromised node"); the
design does not mention it. (The same key can also equivocate and suspend the
space, but that is pin D's accepted cost of one-key anchors; suspension stops
`submit` too, which caps the drain only after an equivocation.)

**Fix.** A per-space spend budget, enforced in `ChargeSpaceFee::validate`
and debited in `prepare`: `Budget: SpaceId → { period_start_ms, spent }`,
`SpaceInfo.max_spend_per_window` set by the controller at registration and by
`set_budget` (call 10), default `8 × (SubmitDeposit + the fee bound)` per
window; beyond it `InvalidTransaction::Payment` (the node gets a funding
alert). Pool validity stays local: `validate` reads the budget as it reads
`Authorities`. Add G13: the ninth submit in a window refused before dispatch,
the sovereign's balance untouched. Record in §13 that fc's
`feat/private-communities` has a per-community `Budget` the fold-in (S2) can
merge with. Also: `validate` must check the sovereign can pay fee **and**
`SubmitDeposit` while staying alive, or a tx is included, pays, and fails
`InsufficientSovereignBalance` in dispatch (now it checks the fee alone).

### 3. [major, design §9 + plan 6.17b] `WindowInFuture` must be retried, not skipped

§9 maps errors 15–18 to "logged and skipped". The representative closes w at
`B_w + D` by its own clock and anchors at once; Kreivo's `Timestamp` lags real
time by up to a block plus the collator's drift, so `now_w == w` at inclusion
is a live case near every boundary when L = 2 min (D = 24 s). A skipped
anchor leaves the window unanchored for good (`Last` then moves past it at
w+1), and every statement of w dies at the venue.

**Fix.** 16 `WindowInFuture` → wait for the venue's `Timestamp.Now` to pass
`B_w` (plus one block) and resubmit; 15 `WindowNotAfterLast` → done (a later
anchor exists: failover); 17 `WindowTooOld` → dead, alert; 18 `OutOfRange` →
dead, alert (migrated). Better: the client reads `Timestamp.Now` before
sending and never submits an anchor the venue would refuse as future. Same
table in 6.17b's "the errors mapped" and G4's expectations; the mock's
`now_ms` makes it testable (anchor at `now_w`, advance, resubmit → `Anchored`).

### 4. [major, design §5–§6] `AnchorRecord` has no signer, so `resume` cannot see the first equivocator

`Equivocations.signer` is the second anchor's key; `AnchorRecord { root, at_ms }`
forgets the first's. `resume` requires "no key named in the space's
`Equivocations` still registered": when the two anchors came from two keys
(the live failover case), the first key stays registered and the space
resumes with it. Which root was wrong is unknowable; both keys must go.

**Fix.** `AnchorRecord { root, at_ms, signer: [u8;32] }`;
`Evidence { first, second, first_signer, second_signer }`; `resume` requires
both removed; `Equivocated` carries both signers. G5 gains the two-key case.
Storage write in G3's vector changes (the mock's raw value).

### 5. [major, design §10] The vectors cannot pin fee amounts, and miss half the calls

G12 "checks who paid" at runtime level, but the vectors hold "balance deltas
of the sovereign, `ForfeitTo` and the signer". Fee amounts depend on the
teammate's weights and Kreivo's fee constants, which our mock cannot know; a
vector with an exact sovereign delta will fail on the real runtime for the
right reasons. And G1–G12 exercise 7 of the 14 calls: no `migrate`
(`AlreadyMigrated`; an anchor at `w ≥ from_window` → `OutOfRange`; a rooted
statement whose root's window is ≥ `end_window` → refusal 5), no
`set_controller`, `remove_anchor_key` of a paired key (`AnchorKeyInUse`),
`dispatch_as_sovereign`, `set_status` block/unblock, `set_format`'s delay,
`on_idle` pruning (an anchor and a rooted `Seen` pruned past `MaxRootAge`, the
rootless one kept), registration refusals (`BadClock`, `BadFounder`,
`SovereignInUse`), or a submit paid by a space other than the statement's.

**Fix.** Split the deltas: pallet-level vectors assert deposit moves exactly
(hold, release, forfeit) and that the signer's balance is unchanged;
runtime-level `fees` vectors assert signs only (sovereign down, signer
unchanged; a non-authority down). Add G13–G18 for the calls above. Say in §10
that the mock emits events through `parity-scale-codec` derives on an enum
whose variants and field order are §8's table, so the bytes are FRAME's and
not hand-rolled (the mock may take `parity-scale-codec` as a dev-dependency;
it is std and test-only, outside decision 9's vendored tree).

### 6. [major, plan A1 + design status] Hand the design over now, not after M3b

A1 names the teammate "after M3b". The teammate's pallet is the long pole of
the Kreivo leg (research §3: 3–5 weeks + 1 for the extension), and it needs
the kit only for `judge`, `space_id`, the digests and the window arithmetic;
storage, calls, governance, holds, providers, `ChargeSpaceFee`, events, errors
and the pallet's own mock runtime need nothing from us. Waiting ten weeks
serializes two independent tracks.

**Fix.** A1: the design at this commit (with findings 1–5 folded), the kit at
6.16, the vectors at 6.17; the design gains a short "Build order for the
teammate" (§0.1): everything but §3's crate calls first, against a stub
`Venue`; the kit replaces the stub. Say which VOS steps each §3 API waits on
(6.10 for `vos_anchor`, 6.5 for code 7 and `Venue::id`).

### 7. [minor, design §6.3] The program is looked up before the format is checked

Pin F's order is format, then program; §6.3 decodes (1), looks up `Programs`
(3), then `judge` checks the format (2). A fixture that fails exactly one
check still agrees across venues, so the vectors pass, but a statement with an
unknown program *and* a retired format reports 3 here and 2 on JAM. Check
`Formats[statement.format]` before the program lookup, or let `judge` take a
`FnOnce(ProgramId) -> Option<Pin>`.

### 8. [minor, design §1 + §6.3] Say what `Record` records

"The Record handler records the accepted ones" has no storage item: the record
is the `Seen` entry plus the `Accepted` event. State it ("Record = the `Seen`
entry and the `Accepted` event; nothing else is stored; later handlers add
their own storage"), and state that `payer` may differ from `statement.space`
(any authority may pay for any statement; the proof is what is judged).

### 9. [minor, design §5–§6] Small semantics the teammate will ask about

- `remove_authority`'s `dec_providers` fails with `ConsumerRemaining` if the
  node's account acquired a consumer; say "best effort: ignore the error, the
  account merely stays alive".
- `add_authority` "adds or updates": say an update replaces the paired key
  (the old key leaves `AnchorKeys`) and refuses a key paired elsewhere
  (`AnchorKeyInUse`).
- `set_status(blocked: false)` "back to its previous state" needs a stored
  previous state; define it as `Active`, or `Suspended` if `Equivocations`
  for the space is non-empty.
- `window(t)` for `t < origin_ms` (none) → `BadClock` at `anchor` and in
  `now_w`; say so.
- §9 "does not need the pallet's metadata": true of the call bytes, not of
  reading `System.Events`, which needs the live metadata to describe pallet
  90 (subxt decodes with it; the client then decodes the pallet's own fields
  by the pinned layout). Write "no compile-time metadata".

### 10. [minor, plan 6.17] Stale sentence

"Design changes recorded: the anchor rule's `w < now_w` (pin D; the staged
design's §6.1 said `≤`)" is false of the staged design. Delete it; keep "G4
gains the open window".

### 11. [minor, plan decisions] Decision 11's text omits the repeat exception

Write "…forfeited on refusal, except a repeat (code 6), which releases it
(two nodes can race); the owner confirms in `spaces-pallet.md` §13.4".

### 12. [minor, design §1 or §6.3] The two-sided rule where the teammate reads it (C7)

One line: "Every value-moving handler admitted later must be two-sided or
spend the submitting space's own escrow: an anchor gives ordering and
non-equivocation, not integrity (pin D)." The teammate will otherwise accept a
one-sided `Credit` handler as the obvious next step.

### 13. [minor, plan 6.17b + 6.21] The register and controller tooling is unowned

§9's table has "register a space (operator tool)" and "rotate its keys
(controller tool)"; 6.17b's Design covers `anchor`, `submit` and `anchored`
only, yet 6.21's mock leg needs `register` and `add_authority` to run. Add to
6.17b's files: `vosx space venue register|authority add|authority remove`
over the same `calls` layer (or a test-only driver, named as such).

### 14. [minor, plan 6.15] Mark 6.15 F

The window kernel's restated public-input shape (`c_prev` public, the
cumulative rows) is the Clerk's protocol inheritance; it deserves Fable's
review like 6.5.

## 4. The mock-based client (6.17, 6.17b): what it proves, what stays a gate

The mock proves: the client's encode/decode is consistent with *our reading*
of the design (call bytes, storage keys, event layouts), its state machine
(no re-sign while a tx may land; `Repeated` as accepted; the error table), and
that the design's rules are executable with the real `judge` over the real
fixtures. That is real assurance for the client's logic and for the design's
internal consistency, and it is the vectors' generator. It cannot prove:
FRAME's actual bytes (derive encodings of `Option<ProgramInfo>`,
`DispatchResult`, the storage hashers under the real prefix), the hold and
provider semantics, who pays under the live extension pipeline, the
`Timestamp` lag (finding 3), block capacity and `MaxExtrinsicLength`, or the
envelope against the teammate's metadata. 6.0e covers the envelope with a
stock call; nothing else is covered until the pallet exists.

**Keep as gates for when the pallet lands** (name them in M3b acceptance as
"deferred Kreivo gates", so they are not lost): (1) G1–G18 pass in the
teammate's pallet mock runtime and the `fees` vectors in Kreivo's runtime
tests; (2) `just e2e-kreivo` on a dev chain with the real client: register,
authority, anchor near a boundary (finding 3), submit, repeat, refusal,
`anchored` read; (3) the vendored tree's sync check in Kreivo's CI; (4) the
teammate's weights with the in-Wasm sweep as `#[benchmark(extra)]`; (5) a
review of `ChargeSpaceFee` as a runtime-wide change (its own, not ours).
Until (1)–(2) pass, the plan should say the `kreivo` venue is not selectable
in a node's production configuration (a `cfg` or a refused config value), so
no space anchors on a chain whose pallet has not met the vectors.

## 5. Critical path, estimates, step order

Correct as computed (§1). Order right: 6.0a first, 6.8 from day one, 6.10
opening M3a and M3b, 6.17 after 6.5. Three tracks are realistic: M2's line;
M3a's line; 6.7–6.9, 6.16–6.17b and 6.19 for the third. Each step names files,
tests, gates with numbers, deps, estimate; sixteen carry F. Missing for a
faster agent: 6.17b's tooling (finding 13); 6.15's F (14); the deferred
Kreivo gates (§4); design §0.1's build order (6). Review latency stays outside
the figures, as stated.

## Summary table

| # | severity | fix |
|---|---|---|
| 1 | blocker | `start_window` into the registration digest (pin D, design §3/§6.2, `register_digest`); bound it at registration; G1 refusal |
| 2 | major | per-space spend budget in `ChargeSpaceFee` (+ `set_budget`); `validate` covers fee + deposit; G13 |
| 3 | major | `WindowInFuture` retried after the venue's clock passes `B_w`; 15 done, 17–18 dead; design §9, 6.17b, G4 |
| 4 | major | `AnchorRecord.signer`; both signers in `Evidence`; `resume` needs both removed; G5 |
| 5 | major | deltas: exact deposits, fee signs only; G13–G18 for the uncovered calls; events through codec derives |
| 6 | major | hand the design over at this commit; §0.1 build order; kit at 6.16, vectors at 6.17 |
| 7–14 | minor | as above (format before program; `Record` defined; providers/update/unblock/`BadClock`/metadata wording; 6.17 stale line; decision 11's exception; two-sided rule in the design; 6.17b tooling; 6.15 F) |
