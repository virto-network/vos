# `pallet-spaces`: a handoff design for Kreivo

Status: a design for the Kreivo teammate who implements it, handed over
when VOS commits its slice-6 plan. VOS writes no pallet code in slice 6.
VOS delivers three things:
- this design, now;
- the verifier crates, packaged for vendoring with a sync check, at VOS
  step 6.16;
- the conformance vectors in §10, at VOS step 6.17, and a node client
  tested against a mock of the interface in §9 (6.17b).

The supporting research, with file:line citations, is
`docs/design/research/slice-6/spaces-pallet-research.md`. `KR` below is Kreivo's `runtime/kreivo/src`
at master 87f8728.

**VOS-side contract, the sources this design follows:**
- `docs/design/slice-6-on-chain.md` (VOS's slice-6 plan): pin D (spaces, windows,
  anchors), pin F (the check order), decisions 9–12;
- `docs/design/research/slice-6/owner-decisions.md` (2026-10-19);
- the background on why anchors and statements exist:
  `docs/design/identity-and-authority.md` §5, §11 and §12, and
  `docs/design/proving.md` §12.

## 0.1 Build order for the teammate

The pallet needs VOS's crates only for §3's calls: `judge`, `space_id`,
the digests, the genesis decode and the window arithmetic. Everything else
needs nothing from VOS. So:
1. **First, against a stub `Venue`:** storage (§5), the calls and their
   origins (§6), governance and the delay (§6.4), holds and providers,
   `on_idle` (§6.5), `ChargeSpaceFee` with its budget (§7), events and
   errors (§8), the pallet's own mock runtime and its tests. A stub crate
   with §3's signatures (`judge` refusing everything, the digests as
   BLAKE2b over the documented preimages) stands in for the kit.
2. **Then the kit replaces the stub,** and §10's vectors run.

What each §3 API waits on, in VOS's plan:

| API | VOS step |
|---|---|
| `vos_anchor` (`SpaceGenesis`, `space_id`, `WindowClock`, `anchor_digest`, `register_digest`, `RootKind`) | 6.10 |
| `vos_statement::judge` over an accepted set, `Venue::id`, refusal code 7 | 6.5 |
| format 39's verifier (the masked proofs) | 6.4 |
| the vendored kit, `VENDOR`, `just vos-sync` | 6.16 |
| the conformance vectors G1–G18 and the mutation lists | 6.17 |

---

## 1. Goals

1. **A space is registered on Kreivo from its VOS genesis.** Its id is the
   genesis hash. It gets a **sovereign account**, the funded account that
   pays its deposits and fees.
2. **A map of the space's current authorities:**
   - each authority is a node's own sr25519 Kreivo account;
   - each is paired with the node's ed25519 anchor key;
   - the space's controller rotates them;
   - an authority's anchor and submit transactions are paid by the
     sovereign account, with no balance on the node.
3. **Anchors:** one root per space, per window, under the anchor rule
   (§6.1), with equivocation caught and the space suspended.
4. **Statements:**
   - `submit` judges a statement and its proof with the vendored
     `vos_statement::judge`;
   - the Record handler records the accepted ones;
   - a refundable deposit is refunded on acceptance and forfeited on
     refusal.
5. **Governance of what is accepted:**
   - formats and programs, by the Virto community origin with a Root
     override, after a 7-day delay;
   - an emergency pause that acts at once.
6. **Built to absorb pallet-communities later** (§12): its sovereign
   account, controller and `dispatch_as_sovereign` mirror the community
   account, admin origin and `dispatch_as_account`.

**Not in this pallet now:**
- value-moving handlers (only `Record` is admitted). **Every value-moving
  handler admitted later must be two-sided or spend the submitting space's
  own escrow:** an anchor gives ordering and non-equivocation, not
  integrity (pin D), so a one-sided `Credit` is not admissible;
- anonymous authentication by proof (§11, a later stage);
- the migration of communities (§12).

## 2. Defaults taken by the owner

| Topic | Default |
|---|---|
| Program and format governance | `ProgramsOrigin` = the Virto community origin, with a 7-day delay; `Root` overrides it with no delay |
| Emergency | `EmergencyOrigin` pauses at once (Root or the Virto community) |
| Handlers | `Record` only |
| Fees | normal length and weight fees on every call, plus a refundable `SubmitDeposit` on `submit`: refunded on acceptance, forfeited to the treasury on refusal; **paid by the space's sovereign account** whenever an authority of the space signs |
| Node authorization | the authorities map: one sr25519 account per node, rotated by the controller |
| Spend budget | per space per window, `8 × (SubmitDeposit + FeeBound)` by default, set by the controller; enforced before inclusion, so a compromised authority cannot drain the sovereign account (§7) |
| Time | every expiry and range uses Kreivo's `pallet_timestamp` (ms). A window number is computed from it with the space's frozen clock, never trusted from the caller |
| Rootless statements | their `Seen` entry never expires (pin F) |

## 3. Glossary and the VOS crates

The vendored crates live under Kreivo's `vendor/vos-verifier/` (decision 9:
vendored with a `VENDOR` file and a sync check). The pallet calls them and
never re-implements their encodings.

| Item | Definition | Crate API the pallet uses |
|---|---|---|
| `SpaceGenesis` | version, founding node keys (ed25519), `WindowClock { origin_ms, length_ms }`, time, nonce (pin D) | `vos_anchor::SpaceGenesis::decode(&[u8])` |
| `SpaceId` | `[u8; 32]` = `BLAKE2b-256("vos/space/id" ‖ SCALE(genesis))` | `vos_anchor::space_id(&genesis)` |
| `VenueId` | Kreivo's genesis block hash | from `frame_system::block_hash(0)` |
| window of time t | `w = ⌊(t − origin_ms) / length_ms⌋`; `B_w = origin_ms + (w+1)·length_ms`; none for `t < origin_ms`, which `anchor` and `now_w` refuse as `BadClock` | `vos_anchor::WindowClock::{window, boundary}` |
| anchor digest | `BLAKE2b-256("vos/anchor/v1" ‖ venue ‖ space ‖ w (8, LE) ‖ kind (1) ‖ root)` | `vos_anchor::anchor_digest(..)` |
| registration digest | `BLAKE2b-256("vos/space/register" ‖ venue ‖ space ‖ controller (32) ‖ start_window (8, LE))` | `vos_anchor::register_digest(venue, space, controller, start_window)` |
| `RootKind` | `u8`; `0` = Space; every other value is refused | `vos_anchor::RootKind` |
| `ProgramId` | `[u32; 8]` (8 M31 words) | `vos_statement::ProgramId` |
| `StatementId` | `[u8; 32]`, returned by `judge` | `vos_statement::StatementId` |
| `Statement` | VOS canonical bytes (not SCALE) | `vos_statement::Statement::decode` |
| verdict | `judge(&venue, &pin, &statement, proof) -> Result<StatementId, Refusal>`, `pin` a `Pin { program, venue_bound }`; `Refusal::code() -> u32` | `vos_statement::{judge, Pin, Venue, Refusal}` |

- **The `Venue` the pallet implements over its storage:**
  - `id()`: the `VenueId`;
  - `accepts(format)`: `Formats[format]` is active now;
  - `anchored(root)`: `Anchors[(root.space, root.kind, root.window)].root == root.root`,
    the window inside the space's range, and `now − B_w ≤ MaxRootAge`;
  - `seen(id)`: `Seen` contains it.
- **The refusal codes (stable, VOS-defined):**

  | Code | Refusal |
  |---|---|
  | 1 | statement |
  | 2 | format |
  | 3 | program |
  | 4 | space |
  | 5 | unanchored |
  | 6 | repeated |
  | 7 | venue |
  | `0x100 \| e` | proof, where e is the final verifier's code |

  - Code 7, `Venue::id` and `Pin` landed in VOS step 6.5; the pallet
    compiles against the tag the `VENDOR` file names.

## 4. Configuration

```rust
pub trait Config: frame_system::Config<AccountId = AccountId32> + pallet_timestamp::Config<Moment = u64> {
    type RuntimeHoldReason: From<HoldReason>;
    type Currency: fungible::MutateHold<AccountId32, Reason = Self::RuntimeHoldReason>
                 + fungible::Mutate<AccountId32> + fungible::BalancedHold<AccountId32>;
    type ProgramsOrigin: EnsureOrigin<OriginFor<Self>>;   // Virto community
    type EmergencyOrigin: EnsureOrigin<OriginFor<Self>>;  // Root or the Virto community
    type StatusOrigin: EnsureOrigin<OriginFor<Self>>;     // Kreivo governance: block or unblock a space
    type ForfeitTo: Get<AccountId32>;                     // TreasuryAccount
    #[pallet::constant] type PalletId: Get<PalletId>;                 // *b"kv/space"
    #[pallet::constant] type RegistrationDeposit: Get<BalanceOf<Self>>;
    #[pallet::constant] type SubmitDeposit: Get<BalanceOf<Self>>;
    #[pallet::constant] type MaxRootAge: Get<u64>;          // 86_400_000 ms
    #[pallet::constant] type ProgramChangeDelay: Get<u64>;  // 604_800_000 ms (7 days)
    #[pallet::constant] type MinWindowMs: Get<u64>;         // 120_000
    #[pallet::constant] type MaxWindowMs: Get<u64>;         // 3_600_000
    #[pallet::constant] type MaxAuthorities: Get<u32>;      // 16
    #[pallet::constant] type MaxAnchorKeys: Get<u32>;       // 16
    #[pallet::constant] type MaxGenesisLen: Get<u32>;       // 2_048
    #[pallet::constant] type MaxStatementLen: Get<u32>;     // 65_536
    #[pallet::constant] type MaxProofLen: Get<u32>;         // 262_144
    #[pallet::constant] type FeeBound: Get<BalanceOf<Self>>;  // the most one anchor or submit's fee can be
    #[pallet::constant] type DefaultSpendPerWindow: Get<BalanceOf<Self>>; // 8 × (SubmitDeposit + FeeBound)
    type WeightInfo: WeightInfo;
}
```

- **In Kreivo:**
  - runtime name `Spaces`, **pallet index 90**. It takes the slot of the
    spike's `VosVerifier`, which never shipped;
  - the storage prefix is `"Spaces"`.
- **Suggested deposits:**
  - `RegistrationDeposit = UNITS / 2`, the same as `CommunityDepositAmount`
    (`KR/config/communities/mod.rs:23`), but held, not paid;
  - `SubmitDeposit = UNITS / 2`, about one masked proof's length fee [est].
  - The owner can tune both.

## 5. Storage

All account ids are `AccountId32`. Hashers are pinned because the node
client and the mock read raw keys.

| Item | Key (hasher) | Value |
|---|---|---|
| `Spaces` | `SpaceId` (Identity) | `SpaceInfo` |
| `SovereignOf` | `AccountId32` (Blake2_128Concat) | `SpaceId` |
| `Authorities` | `SpaceId` (Identity), `AccountId32` (Blake2_128Concat) | `AuthorityInfo { anchor_key: Option<[u8;32]> }` |
| `AnchorKeys` | `SpaceId` (Identity), `[u8;32]` (Identity) | `Option<AccountId32>`, the paired authority if any |
| `Anchors` | `SpaceId` (Identity), `u8` kind (Twox64Concat), `u64` window (Twox64Concat) | `AnchorRecord { root: [u8;32], at_ms: u64, signer: [u8;32] }` |
| `Last` | `SpaceId` (Identity), `u8` kind (Twox64Concat) | `u64` window |
| `Equivocations` | same key as `Anchors` | `Evidence { first: [u8;32], second: [u8;32], first_signer: [u8;32], second_signer: [u8;32] }` |
| `Budget` | `SpaceId` (Identity) | `Spend { window: u64, spent: Balance }`, the window by the venue's time |
| `Formats` | `u32` (Twox64Concat) | `Active { from_ms: u64, until_ms: Option<u64> }` |
| `Programs` | `ProgramId` (Blake2_128Concat) | `ProgramInfo { handler: Handler, venue_bound: bool, active: Active }` |
| `Seen` | `StatementId` (Identity) | `u64` expires_ms; `u64::MAX` = never |
| `Paused` | (value) | `u8` flags: bit 0 submit, bit 1 anchor, bit 2 register |

```rust
pub struct SpaceInfo {
    pub sovereign: AccountId32,
    pub controller: AccountId32,
    pub origin_ms: u64, pub length_ms: u64,     // the frozen clock, from the genesis
    pub start_window: u64,                       // the first window anchored here
    pub end_window: Option<u64>,                 // exclusive; set by `migrate`
    pub status: SpaceStatus,                     // u8 enum
    pub authorities: u8, pub anchor_keys: u8,    // counts
    pub registered_ms: u64,
    pub max_spend_per_window: Balance,           // §7's budget; DefaultSpendPerWindow at registration
}
#[repr(u8)] pub enum SpaceStatus { Active = 0, Suspended = 1 /* equivocation */, Blocked = 2 /* governance */ }
#[repr(u8)] pub enum Handler { Record = 0 }      // others refused at decode until admitted
#[pallet::composite_enum] pub enum HoldReason { Registration, Submit }
```

**The sovereign account:** `T::PalletId::get().into_sub_account_truncating(space_id)`,
which is `b"modl" ‖ b"kv/space" ‖ space_id[0..20]`.
- It is derivable from the genesis before registration, so the founder
  funds it first.
- `register` refuses an account already in `SovereignOf`.
- `register` calls `inc_providers` on it.

**Authority accounts** get `inc_providers` on `add_authority` and
`dec_providers` on removal. Otherwise `CheckNonce` refuses a zero-balance
signer (`frame-system-48.0.0/src/extensions/check_nonce.rs:74-78`).

## 6. Calls

Call indices are pinned. Arguments are SCALE, fixed-width unless marked
compact, and the vectors are `BoundedVec<u8, _>`.

| # | Call | Origin | Effect |
|---|---|---|---|
| 0 | `register(genesis: Vec<u8>, controller: AccountId32, start_window: u64, founder_key: [u8;32], founder_sig: [u8;64])` | any signed (pays its own fee) | §6.2 |
| 1 | `set_controller(space: SpaceId, controller: AccountId32)` | controller | replaces the controller |
| 2 | `add_authority(space: SpaceId, who: AccountId32, anchor_key: Option<[u8;32]>)` | controller | adds an authority, or updates one: an update replaces its paired key (the old key leaves `AnchorKeys`); a key paired with another authority is refused (`AnchorKeyInUse`); `inc_providers(who)` on an add |
| 3 | `remove_authority(space: SpaceId, who: AccountId32)` | controller | removes it and its paired anchor key; `dec_providers(who)` best effort: a `ConsumerRemaining` error is ignored, the account merely stays alive |
| 4 | `remove_anchor_key(space: SpaceId, key: [u8;32])` | controller | removes an unpaired key, such as a founding one |
| 5 | `migrate(space: SpaceId, to: [u8;32], from_window: u64)` | controller | sets `end_window = from_window` (once, ≥ the next window); anchors at `w ≥ from_window` are refused here |
| 6 | `resume(space: SpaceId)` | controller | `Suspended → Active` only when neither signer of any of the space's `Equivocations` (`first_signer`, `second_signer`) is still registered; it then clears them |
| 7 | `anchor(anchor: AnchorArg)` | any signed; the sovereign pays when the signer is an authority of `anchor.space` | §6.1 |
| 8 | `submit(payer: SpaceId, statement: Vec<u8>, proof: Vec<u8>)` | an authority of `payer`; the sovereign pays | §6.3 |
| 9 | `dispatch_as_sovereign(space: SpaceId, call: Box<RuntimeCall>)` | controller | dispatches as `Signed(sovereign)`, as communities' `dispatch_as_account` does |
| 10 | `set_budget(space: SpaceId, max_spend_per_window: Balance)` | controller | sets §7's budget |
| 16 | `set_format(format: u32, active: Active)` | `ProgramsOrigin` or Root | §6.4 |
| 17 | `set_program(program: ProgramId, info: Option<ProgramInfo>)` | `ProgramsOrigin` or Root | §6.4; `None` = remove, subject to the same delay |
| 18 | `set_paused(flags: u8)` | `EmergencyOrigin` | immediate |
| 19 | `set_status(space: SpaceId, blocked: bool)` | `StatusOrigin` | `Blocked`; unblocking sets `Active`, or `Suspended` if the space has `Equivocations` |

`AnchorArg` is pin D's `Anchor`:
`{ space: [u8;32], window: u64, kind: u8, root: [u8;32], signer: [u8;32], signature: [u8;64] }`,
where `signer` is the ed25519 anchor key and `signature` is ed25519 over
the anchor digest.

### 6.1 `anchor`, the anchor rule (pin D)

The checks, in order:
1. not paused (anchor);
2. the space exists and is `Active`;
3. `kind == 0`;
4. `signer ∈ AnchorKeys(space)`;
5. the ed25519 signature over `anchor_digest(venue, space, window, kind, root)`.

Then:
- **If `Anchors(space, kind, window)` exists:**
  - with the same root → `AlreadyAnchored`;
  - with a different root → store `Equivocations` with both roots and
    both signers (the stored record's and this one's), set the status to
    `Suspended`, emit `Equivocated` and `SpaceSuspended`, and return **Ok**
    so the evidence persists. Anyone may submit that second signed anchor.
    Which root was wrong is unknowable, so `resume` needs both keys gone.
- **Otherwise:**
  - `start_window ≤ w`;
  - `w < end_window` when it is set;
  - `Last(space, kind) < w` when present (gaps allowed);
  - `w < now_w`, `now_w` the window of the venue's `now_ms`
    (`BadClock` before the origin): the open window cannot be anchored
    (`WindowInFuture`);
  - `now_ms − B_w ≤ MaxRootAge`.

  Then store `Anchors` (`at_ms = now`, `signer`) and `Last = w`, and emit
  `Anchored`.

### 6.2 `register`

1. Not paused (register).
2. Decode the genesis: version 1; `length_ms` in `[MinWindowMs, MaxWindowMs]`;
   1–`MaxAnchorKeys` founding keys.
3. `space = space_id(genesis)` is not registered.
4. `founder_key` is a founding key, and `founder_sig` verifies over
   `register_digest(venue, space, controller, start_window)`. The window
   is signed, so nobody who sees a registration in the pool can resubmit
   it with another start.
5. `start_window` is bounded by the venue's time:
   `now_w − MaxRootAge / length_ms ≤ start_window ≤ now_w + 1`
   (`BadStartWindow`): an older start is pointless, a far-future one would
   keep the space from ever anchoring.
6. The sovereign account is not in `SovereignOf`.
7. Hold `RegistrationDeposit` on the sovereign account
   (`InsufficientSovereignBalance` otherwise).
8. Store `SpaceInfo` (`Active`, `max_spend_per_window =
   DefaultSpendPerWindow`) with every founding key as an unpaired anchor
   key, and `inc_providers(sovereign)`.
9. Emit `SpaceRegistered`.

The deposit is released only by a later deregistration, which is not in
this version.

### 6.3 `submit` (pin F's order)

Failures that are dispatch errors move no deposit; only the signer's or
the sovereign's fee is spent:
1. paused (submit) → `Paused`;
2. `payer` is not registered or not `Active` → `UnknownSpace` / `SpaceNotActive`;
3. the signer is not in `Authorities(payer)` → `NotAuthority`;
4. the sovereign account cannot hold `SubmitDeposit` → `InsufficientSovereignBalance`.

From step 5 on, the call **returns Ok**, so the deposit's fate persists,
and it reports through events:

5. hold `SubmitDeposit`;
6. decode the statement (refusal 1);
7. `Formats[statement.format]` active now, else refusal 2: the format
   before the program, as pin F orders them, so a statement failing both
   reports 2 at every venue;
8. `program = statement.program` when `Programs` has it active now, else
   refusal 3;
9. `judge(&StorageVenue, &Pin { program, venue_bound }, &statement, &proof)`,
   `venue_bound` the program's `ProgramInfo`. Inside it run the
   format again, the venue prefix when `venue_bound`, the space rule,
   anchored, the io-hash, unseen, and the proof.

`payer` may differ from `statement.space`: any space's authority may pay
for any statement; the proof is what is judged.

The outcome:

| Outcome | Storage | Deposit | Events |
|---|---|---|---|
| `Ok(id)` | `Seen[id]` = `u64::MAX` if rootless, else `B_wmax + MaxRootAge` (newest root's window; `vos_statement::seen_expiry`). That entry and the `Accepted` event are the whole of `Record`: it stores nothing else; later handlers add their own storage | released | `Accepted` |
| refusal 6 (repeated) | – | released | `Refused { code: 6 }`. A race between two nodes is not punished |
| any other refusal | – | transferred to `ForfeitTo` | `Refused { code }`, `DepositForfeited` |

**Weights:**
- declared: `submit_accept`;
- actual: `submit_refused_early` for refusals before the proof (codes 1–7);
- the full weight for a proof refusal, which costs nearly a full verify
  (spike 6c: 2.7 of 4.0 ms).

### 6.4 Formats and programs: the delay

`Active { from_ms, until_ms }`:
- `ProgramsOrigin` must set `from_ms ≥ now + ProgramChangeDelay`, and the
  same for any `until_ms` it sets or shortens, and for a removal, which
  takes effect at `now + delay`;
- **Root** may use `now`;
- `ProgramInfo.handler` must be `Record`;
- the pause is the instant brake.

### 6.5 `on_idle`

- Prune `Anchors` whose `B_w + MaxRootAge < now`, and `Seen` entries whose
  `expires_ms < now`.
- Never prune `Seen` entries at `u64::MAX`.
- Keep `Last`, and keep `Equivocations` until `resume`.
- Bounded by the remaining weight, with a cursor.
- `MaxRootAge` is never raised in place; a raise is a migration that first
  prunes anchors older than the old bound. A `Seen` entry's expiry was
  computed with the old bound while `anchored` reads the new one, so an
  anchor the cursor has not reached would be fresh again after its entry
  was pruned, and a replay accepted (pin F).

## 7. Fees: the sovereign account pays for its authorities

**`ChargeSpaceFee<Runtime, Inner>`** wraps Kreivo's `ChargeTransaction`
(`KR/lib.rs:93`) the way `ChargeGasTxPayment` wraps `ChargeAssetTxPayment`:
- the same `IDENTIFIER`, and the inner extension's encoded data, so the
  extrinsic format and clients do not change;
- the pipeline becomes `SkipCheckIfFeeless<Runtime, ChargeSpaceFee<Runtime, ChargeTransaction>>`.

How it charges:
- **When** the origin is `Signed(who)` and the call is directly
  `Spaces::anchor { anchor }` (space = `anchor.space`) or
  `Spaces::submit { payer, .. }` (space = `payer`), the space is `Active`,
  and `who ∈ Authorities(space)`:
  - compute the normal fee:
    `pallet_transaction_payment::Pallet::compute_fee(len, info, tip)`;
  - `validate`: the sovereign account can pay the fee **and**, for a
    `submit`, `SubmitDeposit` while staying alive, and the space's budget
    for the current window (below) has room for both; else
    `InvalidTransaction::Payment`. Otherwise a transaction would be
    included, pay its fee, and fail `InsufficientSovereignBalance` in
    dispatch;
  - `prepare`: `OnChargeTransaction::withdraw_fee(&sovereign, ..)`, and
    the budget debited by the fee bound plus, for a `submit`, the deposit;
  - `post_dispatch`: `correct_and_deposit_fee(&sovereign, ..)`, which
    refunds unused weight as usual; the budget corrected to the actual fee,
    and credited back a deposit the dispatch released;
  - priority as for a normal signed transaction.
- **Otherwise:** delegate to `Inner`, unchanged. A non-authority pays its
  own fee, and the gas tank and asset payment keep working.
- **Not covered:** batches, proxies and nested calls. They go to `Inner`.

**The budget: a compromised authority cannot drain the sovereign
account.** A node whose sr25519 key leaks, or a rogue operator, could
otherwise submit garbage at block speed, each costing the sovereign a
length fee (about 0.43 UNITS) and a forfeited deposit (UNITS/2), about 20
a block by proof_size: hundreds of UNITS a minute, with the controller's
`remove_authority` the only brake.
- `Budget: SpaceId → Spend { window, spent }`, the window by the venue's
  time through the space's clock; a new window resets `spent`.
- `SpaceInfo.max_spend_per_window`, `DefaultSpendPerWindow` at
  registration (`8 × (SubmitDeposit + FeeBound)`), set by the controller
  with `set_budget`.
- Spending past it is refused in `validate`, before inclusion: the node
  gets `InvalidTransaction::Payment` and raises a funding alert; the
  sovereign's balance is untouched.
- Pool validity stays local: `validate` reads `Budget` as it reads
  `Authorities`.
- frame-contrib's `feat/private-communities` has a per-community `Budget`
  that the communities fold-in (§12, S2) can merge with (§13).

**The pallet-only fallback, if the extension is refused:**
- `#[pallet::feeless_if]` on `anchor` and `submit`, when the signer is an
  authority, the sovereign account holds the fee bound (and the deposit,
  for `submit`), and the budget has room (`OverBudget` otherwise);
- the pallet charges `LengthToFee(encoded call + 256) + WeightToFee(actual)`
  from the sovereign account inside dispatch.

It is approximate, and concurrent pending transactions can overdraw it.
Prefer the extension.

## 8. Events and errors

The variant indices are pinned.

**Events:**

| # | Event |
|---|---|
| 0 | `SpaceRegistered { space, sovereign, controller, origin_ms: u64, length_ms: u64, start_window: u64 }` |
| 1 | `ControllerSet { space, controller }` |
| 2 | `AuthorityAdded { space, who, anchor_key: Option<[u8;32]> }` |
| 3 | `AuthorityRemoved { space, who }` |
| 4 | `AnchorKeyRemoved { space, key }` |
| 5 | `Migrated { space, to: [u8;32], from_window: u64 }` |
| 6 | `Anchored { space, kind: u8, window: u64, root: [u8;32] }` |
| 7 | `Equivocated { space, kind: u8, window: u64, first: [u8;32], second: [u8;32], first_signer: [u8;32], second_signer: [u8;32] }` |
| 8 | `SpaceSuspended { space }` |
| 9 | `SpaceResumed { space }` |
| 10 | `SpaceStatusSet { space, status: u8 }` |
| 11 | `Accepted { id: [u8;32], program: [u32;8], space: [u8;32], payer: SpaceId, output_hash: [u8;32] }` (the Record handler: `output_hash = BLAKE2b-256(statement.output)`) |
| 12 | `Refused { payer: SpaceId, statement_hash: [u8;32], code: u32 }` (`statement_hash = BLAKE2b-256(statement bytes)`) |
| 13 | `DepositForfeited { space, amount: Balance }` |
| 14 | `FormatSet { format: u32, active: Active }` |
| 15 | `ProgramSet { program: [u32;8], info: Option<ProgramInfo> }` |
| 16 | `PausedSet { flags: u8 }` |
| 17 | `SovereignDispatched { space, result: DispatchResult }` |
| 18 | `BudgetSet { space, max_spend_per_window: Balance }` |

**Errors:**

| # | Error |
|---|---|
| 0 | `SpaceExists` |
| 1 | `UnknownSpace` |
| 2 | `BadGenesis` |
| 3 | `BadClock` |
| 4 | `BadFounder` |
| 5 | `SovereignInUse` |
| 6 | `NotController` |
| 7 | `NotAuthority` |
| 8 | `TooManyAuthorities` |
| 9 | `TooManyAnchorKeys` |
| 10 | `AnchorKeyInUse` |
| 11 | `UnknownAnchorKey` |
| 12 | `BadAnchorSignature` |
| 13 | `BadKind` |
| 14 | `AlreadyAnchored` |
| 15 | `WindowNotAfterLast` |
| 16 | `WindowInFuture` |
| 17 | `WindowTooOld` |
| 18 | `OutOfRange` |
| 19 | `SpaceNotActive` |
| 20 | `Paused` |
| 21 | `InsufficientSovereignBalance` |
| 22 | `TooEarly` (the delay) |
| 23 | `StillEquivocating` |
| 24 | `AlreadyMigrated` |
| 25 | `BadHandler` |
| 26 | `BadStartWindow` |
| 27 | `OverBudget` (the pallet-only fallback; the extension refuses in `validate`) |

As `DispatchError::Module { index: 90, error: [i, 0, 0, 0] }`.

## 9. The interface VOS nodes rely on

The node's client (`vos-venue`, feature `kreivo`):
- builds these calls from the **pinned bytes**: `[90, call_index] ++ SCALE(args)`;
- builds the envelope (signed extensions, nonce, era) from Kreivo's live
  metadata;
- needs no compile-time metadata of the pallet: the call bytes are pinned;
  reading `System.Events` uses the live metadata to delimit pallet 90's
  events, whose fields the client then decodes by §8's pinned layout.

| Node action | Call | Signer | Success signal | Errors it maps |
|---|---|---|---|---|
| register a space (operator tool) | 0 | operator's account | `SpaceRegistered` | 0–5, 20, 21, 26 |
| rotate its keys, set the budget (controller tool) | 1–6, 10 | controller | events 1–5, 9, 18 | 6–11, 23, 24 |
| anchor `S_w` (the representative's leader) | 7 | the node's sr25519 authority account | `Anchored` | see below |
| submit a statement (the worker) | 8 | the node's sr25519 authority account | `Accepted { id }` → accepted; `Refused { 6 }` → accepted; `Refused { c }` → `Refusal(c)` | 7, 19–21 → a configuration or funding alert; `InvalidTransaction::Payment` → the budget or the sovereign's funds, an alert |

**The anchor's errors, and what the client does:**
- **before sending,** it reads `Timestamp.Now` and never sends an anchor
  for a window the venue's clock has not closed (`w < now_w` by the venue's
  time);
- 14 `AlreadyAnchored` → done;
- 15 `WindowNotAfterLast` → done: a later anchor exists (a failover
  anchored past it);
- 16 `WindowInFuture` → wait until the venue's `Timestamp.Now` passes
  `B_w` plus one block, then resubmit. Kreivo's timestamp lags real time
  by up to a block and the collator's drift, so near a boundary, above all
  at L = 2 min (D = 24 s), this is a live case; skipping it would leave the
  window unanchored for good;
- 17 `WindowTooOld` → dead: an alert;
- 18 `OutOfRange` → dead (migrated): an alert;
- 11–13 → a bug; 19 → the space is suspended.

**Storage the node reads** (raw keys):
`twox128("Spaces") ++ twox128(item) ++ hashed key`:
- `Spaces[space]`: status, range, sovereign;
- `Authorities[space][self]`;
- `Anchors[space][0][w]`: `VenueClient::anchored`;
- `Last[space][0]`;
- `Seen[id]`;
- `Formats` and `Programs`: a pre-check before paying;
- `Paused`;
- `Budget[space]`: the window's spend, before paying;
- `Timestamp.Now`: the venue's time, before an anchor;
- `System.Account[sovereign]`: a funding alert below N submits;
- `System.Events`, filtered by the extrinsic index.

The **mock** VOS tests against implements exactly this table and §6–§8.

## 10. Conformance vectors

VOS ships `vendor/vos-verifier/conformance/spaces.json`, regenerated by
`just vos-sync`, which also checks it against the VOS tag.
- **Each vector holds:**
  - the constants (deposits, `MaxRootAge`, delay, `PalletId`, venue);
  - a pre-state: timestamp, balances, registered spaces and authorities,
    formats and programs;
  - a list of `(signer, call hex)`;
  - per call: the expected result (Ok, or the module error index), the
    pallet events in SCALE, the storage writes (raw key → value hex), and
    the balance deltas.
- **The deltas, split by what the mock can know:**
  - **pallet-level vectors** run in the pallet's own mock runtime (index
    90, `AccountId32`, `u128` balances, no fee pipeline) and pin the
    deposits exactly: each hold, release and forfeit on the sovereign
    account and `ForfeitTo`, and the signer's balance unchanged;
  - **runtime-level vectors,** marked `fees`, run in Kreivo's integration
    tests and pin **signs only**: the sovereign down, the authority
    signer unchanged, a non-authority down. Fee amounts depend on the
    teammate's weights and Kreivo's fee constants, which the mock cannot
    know.
- **The mock's bytes are FRAME's:** it emits events through
  `parity-scale-codec` derives on an enum whose variants and field order
  are §8's table (and stores values through derives on §5's types), not
  hand-rolled encodings. It takes `parity-scale-codec` as a std, test-only
  dependency, outside the vendored tree.

| Id | Scenario |
|---|---|
| G1 | `register` of the fixture genesis; the sovereign address golden; the deposit held. Refused: the same signature resubmitted with another `start_window` (`BadFounder`), and a `start_window` beyond `now_w + 1` or before `now_w − MaxRootAge / length_ms` (`BadStartWindow`) |
| G2 | `add_authority`, `remove_authority`, providers |
| G3 | `anchor` at w, then w+2 (a gap); `Last` |
| G4 | anchor refusals: a stale w ≤ Last, the open window `now_w` (`WindowInFuture`; then `now_ms` advanced past `B_w` and the same anchor resubmitted → `Anchored`), a future w, older than `MaxRootAge`, out of range, bad signature, kind 1, a `now_ms` before the origin (`BadClock`) |
| G5 | an equivocation by one key, then `Suspended`, `resume` refused until it is removed; and by two keys (the failover case): `Evidence` names both, `resume` refused until both are removed |
| G6 | `submit` of the masked format-39 fixture: `Accepted { id }`; the deposit released |
| G7 | one mutant per refusal class, 1–7 and `0x1xx`: `Refused { code }`, `DepositForfeited` |
| G8 | the same statement twice: `Refused { 6 }`, the deposit released |
| G9 | a rootless statement resubmitted at `MaxRootAge + 1`: refusal 6. A rooted one: refusal 5 |
| G10 | a non-authority submit → `NotAuthority`; pause flags |
| G11 | `set_program` by `ProgramsOrigin` with `from < now + delay` → `TooEarly`; with Root, at once |
| G12 (fees) | signs only: an authority's `anchor` and `submit` debit the sovereign account, not the node; a non-authority pays its own; a submit whose sovereign cannot cover fee and deposit refused in `validate` |
| G13 | the budget: with `max_spend_per_window = 8 × (SubmitDeposit + FeeBound)`, the ninth submit in a window refused before dispatch (`InvalidTransaction::Payment`; `OverBudget` in the fallback), the sovereign's balance untouched; the next window resets it; `set_budget` |
| G14 | `migrate`: `end_window` set; an anchor at `w ≥ from_window` → `OutOfRange`; a rooted statement whose root's window is ≥ `end_window` → refusal 5; a second `migrate` → `AlreadyMigrated` |
| G15 | the controller and keys: `set_controller` (the old controller refused after it); `add_authority` updating a paired key (the old key leaves `AnchorKeys`); a key paired elsewhere → `AnchorKeyInUse`; `remove_anchor_key` of a paired key → `AnchorKeyInUse`, of an unpaired founding key → removed; `remove_authority` with a consumer on the account (best effort) |
| G16 | `dispatch_as_sovereign` (a transfer from the sovereign; `SovereignDispatched`); `set_status` block (submits and anchors refused) and unblock (back to `Active`, or `Suspended` with equivocations); `set_format` under the delay (`TooEarly`; Root at once) |
| G17 | `on_idle`: an anchor and a rooted `Seen` entry pruned past `MaxRootAge`, the rootless entry kept, `Last` and `Equivocations` kept |
| G18 | registration refusals: `BadClock` (a length outside the bounds), `BadFounder` (a key not in the genesis, or a bad signature), `SovereignInUse`, `SpaceExists`; and a submit paid by a space other than the statement's: accepted |

## 11. Later stages: pass, and anonymous authentication

- **A pass authority** works now with no pallet change:
  - an authority's `AccountId32` may be a pass account (one per node);
  - `PassAuthenticate` runs first and yields `Signed(pass_account)`, so
    `ChargeSpaceFee` sees an authority;
  - devices can be the node's ed25519 key through `SubstrateKey`, which
    Kreivo already wires;
  - or an SSH key through `pass-authenticators-ssh`, which exists but is
    not on crates.io or wired in Kreivo;
  - frame-contrib 3.x's device call filters can limit such a device to
    `Spaces::{anchor, submit}`.
- **Anonymous authorities** (after VOS slice 7's credential AIR):
  - the pallet keeps `AuthorityRoot: SpaceId → [u8;32]`, a Merkle root
    over the authority keys, which the controller sets alongside the map;
  - `anchor_anon` and `submit_anon` use `#[pallet::authorize]`. That needs
    `frame_system::AuthorizeCall` in Kreivo's pipeline, which it lacks
    today;
  - each carries a credential proof "a key in R_auth" and a nullifier per
    `(space, kind, w)` or per statement;
  - verification goes through `fc_traits_proof_verifier::ProofVerifier`,
    the trait on the owner's `feat/private-communities` branch;
  - fees and the deposit come from the sovereign account in dispatch,
    since an authorized origin pays nothing at the transaction layer;
  - pool DoS is bounded by `provides` tags, a per-space cap per window,
    and a light proof.

## 12. The path to replacing pallet-communities

| Stage | What | Risk |
|---|---|---|
| S0 (now, the teammate) | `pallet-spaces` as above, plus `ChargeSpaceFee`; communities untouched. A community governs a space by being its controller: the community account, through `dispatch_as_account` | low |
| S1 | Kreivo treats space sovereigns like community accounts where it already special-cases them (pass `SkipConsideration`, payments' sender origin: `KR/config/system.rs:229-234`, `KR/config/payments.rs:34-37`) | low |
| S2 | fold communities' features in: a `SpaceRef { Vos(SpaceId), Legacy(u16) }` key; legacy ids keep the `kv/cmtys` + u16 account and their index for tracks, `MultiAddress::Index` and XCM `Plurality{Index}`; membership, the origin and voting move over (built-in membership, as on `feat/private-communities`); a migration for `Info`, `CommunityIdFor`, `CommunityDecisionMethod`, the vote locks, and the NFT memberships with their gas attributes | high: funds, referenda in flight, XCM |
| S3 | move to frame-contrib, with the VOS verifier behind `ProofVerifier`, implemented in Kreivo's runtime; anonymous authorities (§11) | medium |

## 13. Open questions for the owner (ordered)

Each has a recommended default for the teammate and the owner to confirm.
They do not block VOS's slice 6: its mock and node client follow the
defaults, and another answer regenerates the conformance vectors. Also
recorded: frame-contrib's `feat/private-communities` keeps a per-community
`Budget`, which §7's spend budget can merge with at the communities
fold-in (S2).

1. **How the sovereign account pays for an authority's transaction.**
   - The options: (B) the `ChargeSpaceFee` wrapper; (A′) pallet-only
     `feeless_if` with an in-dispatch charge; (A) nodes pay their own fees,
     topped up from the sovereign account.
   - **Recommended: (B)**, exact fees with no client change.
2. **Anchor signatures.**
   - The options: keep pin D's ed25519 anchor key, paired with each sr25519
     authority; or sign anchors with the sr25519 authority key alone (one
     key per node, but JAM's guest must then verify sr25519).
   - **Recommended: keep ed25519 paired.**
3. **The sovereign account's derivation.**
   - The options: from the `SpaceId`, which can be funded before
     registration; or from a registration index.
   - **Recommended: from the `SpaceId`.**
4. **The deposit on a repeated statement.**
   - **Recommended: refunded,** since two nodes can race the same
     statement. Every other refusal forfeits it, as decided.
5. **The deposit amounts:** `RegistrationDeposit` and `SubmitDeposit`
   (suggested: `UNITS/2` each).
6. **The controller.**
   - The options: an `AccountId`, which may be a person, a multisig, a pass
     account or a community account; or an origin enum.
   - **Recommended: an `AccountId`.**
7. **The name and index:** `Spaces` at 90 (recommended).
8. **Slice 6's on-chain end to end (6.21).**
   - The options: conditional on the teammate's delivery; or a mock end to
     end only.
   - **Recommended: conditional,** with the mock end to end as the
     acceptance gate.
9. **Communities fold-in (S2):** after slice 6 (recommended).
10. **Anonymous authorities:** after slice 7's credential AIR (recommended).
