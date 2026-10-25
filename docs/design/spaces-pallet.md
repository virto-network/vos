# `pallet-spaces`: a handoff design for Kreivo

Status: v2, the design for the Kreivo teammate who implements it. v1 was
handed over with VOS's slice-6 plan; v2 comes with VOS's slice-7 step 7.1,
which simplified the anchoring protocol (`slice-7-mobile.md`, pin D′):
no migration, equivocation ends a space for good, registration from the
venue's next window, rooted statements only, and the venue rules written
once, in `vos_anchor::venue`, which the pallet calls. "Changes from v1"
below lists what moved. VOS writes no pallet code. VOS delivers three
things:
- this design;
- the verifier crates, packaged for vendoring with a sync check (§3.1);
- the conformance vectors in §10, and a node client tested against a mock
  of the interface in §9; the transport that takes that client to a live
  Kreivo node is a port of master's substrate extension (§9.1).

The supporting research, with file:line citations, is
`docs/design/research/slice-6/spaces-pallet-research.md`. `KR` below is Kreivo's `runtime/kreivo/src`
at master 87f8728.

**VOS-side contract, the sources this design follows:**
- `docs/design/slice-7-mobile.md` (VOS's slice-7 plan): pin D′, the
  anchoring protocol simplified, and the owner's decisions S8–S19;
- `docs/design/slice-6-on-chain.md` (VOS's slice-6 plan): pin D (spaces, windows,
  anchors), pin F (the check order), decisions 9–12, as pin D′ amends them;
- `docs/design/research/slice-6/owner-decisions.md` (2026-10-19) and
  `docs/design/research/slice-7/owner-decisions.md`;
- the background on why anchors and statements exist:
  `docs/design/identity-and-authority.md` §5, §11 and §12, and
  `docs/design/proving.md` §12.

## 0. Changes from v1

- **No migration.** Call 5 (`migrate`), `SpaceInfo.end_window`, errors 24
  (`AlreadyMigrated`), 18 (`OutOfRange`) and 28 (`SameVenue`), event 5
  (`Migrated`) and v1's G14 are gone. A space that changes venue founds
  again under a new genesis.
- **Equivocation ends a space for good.** Call 6 (`resume`), error 23
  (`StillEquivocating`), event 9 (`SpaceResumed`) and `set_status`'s
  unblock to `Suspended` are gone. A second root at a window held stores
  the evidence and keeps the first root's record; the status becomes
  `Ended` (`SpaceStatus` index 3; index 1, `Suspended`, retired); event 8
  is `SpaceEnded`. The space is never pruned (a tombstone), its roots are
  refused from then on, its registration deposit is released to the
  sovereign, and `dispatch_as_sovereign` stays callable so its funds can
  leave. v1's G19 is gone; G5 changed.
- **Registration from the venue's next window.** `register` takes no
  `start_window`; the founder signs `(venue, space, controller)`
  (`register_digest`'s preimage loses its last 8 bytes); the space anchors
  from `now_w + 1` (from window 0 when its clock has not started). Error
  26 (`BadStartWindow`) is gone.
- **One anchor key per authority, set once.** `add_authority` of an
  account that is an authority already is refused (`AuthorityExists`,
  29): a node's key changes only by replacing the node. An unpaired
  founding key may be paired with a new authority.
- **Strict ed25519.** Every signature is verified as `ed25519-dalek`'s
  `verify_strict` does, and a key of small order is never listed: a
  genesis holding one is `BadGenesis`, an `add_authority` pairing one is
  `BadAnchorKey` (30). A genesis naming a key twice is `BadGenesis`.
- **Rooted statements only.** `ProgramInfo.venue_bound`, `Pin` and
  refusal 7 (`Venue`) are gone; `judge` takes the program; a statement of
  no root, or of the space `SpaceId::NONE`, is refused 4. `Seen` entries
  all expire. A statement is accepted where its space's roots are
  anchored, which is where the space registered: one venue by the space's
  discipline, not by any venue's rule (§6.2's known limit).
- **The anchor rule as one function.** `vos_anchor::venue` holds the
  registration, the anchor rule, `anchored`, the key-listing rule
  (`add_key`), the freshness and `Seen` expiry as pure functions over two
  traits; the pallet implements them
  over its storage and calls them (§6.1–§6.3). `MaxRootAge`,
  `MinWindowMs` and `MaxWindowMs` leave `Config`: they are the kit's
  constants.
- **A second root at an aged window** is `WindowTooOld`, never evidence,
  whether or not the first is still stored.
- **`anchor` before the space's origin** is `WindowInFuture` (no window
  is closed yet), and an anchor before the space's first window is
  `WindowNotAfterLast`; `BadClock` is a registration's alone.
- **The vectors** are G1–G17, renumbered (§10).

## 0.1 Build order for the teammate

The pallet needs VOS's crates only for §3's calls: the venue rules
(`vos_anchor::venue`), `judge`, `space_id`, the digests, the genesis
decode and the window arithmetic. Everything else
needs nothing from VOS. So:
1. **First, against a stub `Venue`:** storage (§5), the calls and their
   origins (§6), governance and the delay (§6.4), holds and providers,
   `on_idle` (§6.5), `ChargeSpaceFee` with its budget (§7), events and
   errors (§8), the pallet's own mock runtime and its tests. A stub crate
   with §3's signatures (`judge` refusing everything, the digests as
   BLAKE2b over the documented preimages, the venue rules as §6 states
   them) stands in for the kit.
2. **Then the kit replaces the stub,** and §10's vectors run.

Each §3 API is in VOS's tagged crates:

| API | in VOS |
|---|---|
| `vos_anchor` (`SpaceGenesis`, `space_id`, `WindowClock`, `anchor_digest`, `register_digest`, `RootKind`) | landed |
| `vos_anchor::venue` (`registration`, `register`, `anchor`, `anchored`, `seen_expiry`, `small_order`) | landed |
| `vos_statement::judge` over an accepted set | landed |
| format 39's verifier (the masked proofs) | landed |
| the vendored kit, `VENDOR`, the sync check (§3.1) | landed |
| the conformance vectors G1–G17 and the mutation lists | landed |

---

## 1. Goals

1. **A space is registered on Kreivo from its VOS genesis.** Its id is the
   genesis hash. It gets a **sovereign account**, the funded account that
   pays its deposits and fees.
2. **A map of the space's current authorities:**
   - each authority is a node's own sr25519 Kreivo account;
   - each is paired with the node's ed25519 node key, its only anchor
     key;
   - the space's controller adds and removes them: a node's key changes
     only by replacing the node;
   - an authority's anchor and submit transactions are paid by the
     sovereign account, with no balance on the node.
3. **Anchors:** one root per space, per window, under the anchor rule
   (§6.1), with equivocation caught and the space ended for good.
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
- the migration of communities (§12);
- a space's migration to another venue: a space anchors at one venue for
  good, and changes venue by founding again.

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
| Statements | rooted only: a statement of no root is refused (4) |

## 3. Glossary and the VOS crates

The vendored crates live under Kreivo's `vendor/vos-verifier/` (decision 9:
vendored with a `VENDOR` file and a sync check, §3.1). The pallet calls
them and never re-implements their encodings.

| Item | Definition | Crate API the pallet uses |
|---|---|---|
| `SpaceGenesis` | pin D's: the version (1 byte, `GENESIS_VERSION` = 1); the founding nodes, a compact count, then each its number (`NodeNumber`, 1 byte) and ed25519 key (32), numbers strictly ascending; the clock `WindowClock { origin_ms, length_ms }` (8 and 8, LE); the founder's time (8, LE); a nonce (16). The decode is canonical (a shortest compact, at least one node, nothing left over) and reads any count; **the venue registers 1 to 16 founding keys** (`MAX_FOUNDING_KEYS`) | `vos_anchor::SpaceGenesis::decode(&[u8])`, `vos_anchor::MAX_FOUNDING_KEYS` |
| `SpaceId` | `[u8; 32]` = `BLAKE2b-256("vos/space/id" ‖ SCALE(genesis))` | `vos_anchor::space_id(&genesis)` |
| `VenueId` | Kreivo's genesis block hash | from `frame_system::block_hash(0)`, as `vos_anchor::VenueId` |
| window of time t | `w = ⌊(t − origin_ms) / length_ms⌋`; `B_w = origin_ms + (w+1)·length_ms`; none for `t < origin_ms`, when no window is closed | `vos_anchor::WindowClock::{window, boundary}`, both `Option` |
| registrable length | `length_ms` from 120,000 to 3,600,000 ms (`MIN_LENGTH_MS`, `MAX_LENGTH_MS`) | `WindowClock::registrable()` |
| anchor digest | `BLAKE2b-256("vos/anchor/v1" ‖ venue ‖ space ‖ w (8, LE) ‖ kind (1) ‖ root)` | `vos_anchor::anchor_digest(&venue, &space, w, kind, &root)`, `kind` a `RootKind` |
| registration digest | `BLAKE2b-256("vos/space/register" ‖ venue ‖ space ‖ controller (32))` | `vos_anchor::register_digest(&venue, &space, &controller)` |
| `RootKind` | `u8`; `0` = Space; every other value is refused (1 is reserved for slice 7's Poseidon2 root) | `vos_anchor::RootKind::from_u8`, `None` → `BadKind` |
| `MaxRootAge` | 24 h, the kit's constant, which the venue rules read: not a `Config` item, so no pallet can anchor on one bound and expire `Seen` entries on another (§6.5) | `vos_anchor::MAX_ROOT_AGE_MS` |
| `ProgramId` | `[u32; 8]` (8 M31 words) | `vos_statement::ProgramId` |
| `StatementId` | `[u8; 32]`, returned by `judge` | `vos_statement::StatementId` |
| `Statement` | VOS canonical bytes (not SCALE) | `vos_statement::Statement::decode` |
| verdict | `judge(&venue, &program, &statement, proof) -> Result<StatementId, Refusal>`, `program` the statement's, active in `Programs`; `Refusal::code() -> u32` | `vos_statement::{judge, Venue, Refusal}` |
| `Seen` expiry | `B_wmax + MAX_ROOT_AGE_MS` (the newest root's window, through the statement's space's clock) | `vos_statement::seen_expiry(&statement, &clock)`, `clock` from `Spaces[statement.space]` |
| the venue rules | the registration, the anchor rule, what is anchored and a root's freshness, over the venue's state: `Roots { now, space, held }` and `VenueState: Roots { venue, listed, last, verify }`; `Space { clock, start, status }`, `Status { Active, Blocked, Ended }`, `Held { root, signer }` | `vos_anchor::venue::{registration, register, anchor, anchored, small_order}` |

- **The venue rules' state the pallet implements over its storage**
  (`StorageVenue` in VOS's mock, `node/venue/src/kreivo/mock/types.rs`):
  - `now()`: `Timestamp.Now`;
  - `space(id)`: `Spaces[id]` as `Space { clock, start: start_window,
    status }`, `SpaceStatus` mapped one to one;
  - `held(space, kind, w)`: `Anchors[(space, kind, w)]`'s root and signer;
  - `venue()`: the `VenueId`;
  - `listed(space, key)`: `AnchorKeys[space][key]` exists;
  - `last(space, kind)`: `Last[space][kind]`;
  - `verify(key, digest, signature)`: ed25519, strictly (`verify_strict`:
    canonical `R` and `S`, neither `R` nor the key of small order).
- **The `Venue` `judge` reads:**
  - `accepts(format)`: `Formats[format]` is active now (`judge` also
    refuses a format the build does not link);
  - `anchored(root)`: `vos_anchor::venue::anchored` over the state above:
    the space `Active` (an ended or a blocked space's roots are not
    anchored), the root held at its window, and
    `now − B_w ≤ MaxRootAge`;
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
  | `0x100 \| e` | proof, where e is the final verifier's code |

  - Code 7 is retired, never reused. The pallet compiles against the tag
    the `VENDOR` file names.

### 3.1 The kit, and keeping it VOS's

VOS writes the kit; Kreivo vendors it whole and edits none of it.
- **What it holds** (`vendor/vos-verifier/`):
  - `vos-anchor`, `vos-statement`, `vos-pvm-final-verifier`,
    `vos-pvm-recair-air` and `vos-pvm-poseidon2`: their sources, and
    concrete manifests: no workspace inheritance, each other by path,
    Stwo a git dependency at VOS's pin
    (`https://github.com/olanod/stwo`, `rev = c3ec9813…`) with
    `default-features = false`; no dev-dependencies, tests or bins (they
    stay in VOS; `[lib] test = false`, so `cargo test --workspace` in
    Kreivo, which takes path dependencies under its root as members,
    builds none);
  - **no `test-formats` feature:** format 28, the unmasked wrap, which no
    production venue accepts, stays in VOS with the JAM program's
    `pvm-guest`; its code compiles out of the kit, so no Kreivo build can
    link it;
  - `fixtures/`: the golden fixtures, the final proofs and
    `statements.cases`, which `vos-statement`'s `fixtures` feature (std,
    tests and benchmarks only) reads beside the crates. Its cases record
    the verdicts of a build linking 28 and 39; the kit links 39 alone, so
    a case of format 28 is refused as `Format` (2), as
    `Fixture::verdict_linking` gives it;
  - `conformance/`: §10's vectors;
  - `vos_kit.py`, the vendoring and sync script;
  - `.gitattributes` (`* -text`), so a checkout converting line endings
    keeps the kit's bytes;
  - `VENDOR`: the repository (for information), the commit, its tag, the
    Stwo pin and the tree's hash, BLAKE2b-256 over every other file by
    path.
- **Built:** the five crates build alone, with no default features, for
  `wasm32v1-none` on Kreivo's stable 1.94.1, `--locked`, and no crate they
  link has a `std` feature (VOS's `just check-kit`; the target ships core
  and alloc alone, so a crate needing std fails the build itself). The
  runtime depends on `vos-statement` and `vos-anchor` by path, with
  `default-features = false`. **Kreivo's own feature unification is
  outside VOS's check:** a feature another runtime crate enables on a
  shared dependency (`serde`, `num-traits`, `hashbrown`) reaches the kit
  too, so Kreivo's runtime build is the gate there.
- **Vendored** in a VOS checkout from a tag:
  `just vendor-verifier <dir> <tag>`
  (`python3 -I pvm/proof/kit/vos_kit.py vendor <dir> --rev <tag>`).
  Without a revision it vendors the working tree, and `VENDOR` says so if
  that differs from its commit; no sync accepts such a kit, nor one that
  names no tag.
- **The sync check never trusts the kit's own script,** which a change to
  the kit could replace. Kreivo copies `pvm/proof/kit/vos-sync.sh` from
  the VOS tag into its own tree, outside `vendor/` (e.g.
  `scripts/vos-sync.sh`, under CODEOWNERS), and runs it in CI and a
  `just vos-sync` recipe, with bash, git and Python 3.11:

  ```
  scripts/vos-sync.sh vendor/vos-verifier [<a local VOS clone>]
  ```

  The bootstrap pins VOS's canonical repository
  (`https://codeberg.org/Virto/VOS.git`), clones it bare without blobs
  (or takes a local clone given as its argument), checks that the tag
  `VENDOR` names is there, and runs `vos_kit.py` as that tag holds it:
  - **the tree's hash** against `VENDOR`'s;
  - **`VENDOR`'s names:** a tag is required (a name of `A–Z a–z 0–9 . _ /
    -`, not starting with `-`), the commit 40 hex digits, and the tag
    resolved, fetching nothing the clone lacks (`GIT_NO_LAZY_FETCH=1`),
    to exactly that commit: a fork's commit, a pull request's or an
    unreviewed branch's is refused even where the server would hand it
    out by hash;
  - **the kit vendored anew** from the tag by the tag's script, the
    fixtures and the vectors with it, and every file compared, `VENDOR`
    included.

  `VENDOR`'s repository is never used: `vos_kit.py sync` itself clones
  the canonical URL unless `--vos` names a local clone or another
  `https://` URL. In VOS, `just vos-sync <dir>` runs the check against
  the checkout itself, a kit vendored at a commit accepted there alone.
  A re-pin is a new vendor at a new tag and a sync, never an edit under
  `vendor/`.

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
    #[pallet::constant] type ProgramChangeDelay: Get<u64>;  // 604_800_000 ms (7 days)
    #[pallet::constant] type MaxAuthorities: Get<u32>;      // 16
    #[pallet::constant] type MaxAnchorKeys: Get<u32>;       // 16 = vos_anchor::MAX_FOUNDING_KEYS, which add_key reads
    #[pallet::constant] type MaxGenesisLen: Get<u32>;       // 2_048
    #[pallet::constant] type MaxStatementLen: Get<u32>;     // 65_536
    #[pallet::constant] type MaxProofLen: Get<u32>;         // 262_144
    #[pallet::constant] type FeeBound: Get<BalanceOf<Self>>;  // the most one anchor or submit's fee can be
    #[pallet::constant] type DefaultSpendPerWindow: Get<BalanceOf<Self>>; // 8 × (SubmitDeposit + FeeBound)
    type WeightInfo: WeightInfo;
}
```

`MaxRootAge` and the registrable window lengths are not `Config` items:
they are the kit's constants (`vos_anchor::MAX_ROOT_AGE_MS`,
`MIN_LENGTH_MS`, `MAX_LENGTH_MS`), which the venue rules read.

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
| `Equivocations` | same key as `Anchors` | `Evidence { first: [u8;32], second: [u8;32], first_signer: [u8;32], second_signer: [u8;32] }`, kept for good |
| `Budget` | `SpaceId` (Identity) | `Spend { window: u64, spent: Balance }`, the window by the venue's time |
| `Formats` | `u32` (Twox64Concat) | `Active { from_ms: u64, until_ms: Option<u64> }` |
| `Programs` | `ProgramId` (Blake2_128Concat) | `ProgramInfo { handler: Handler, active: Active }` |
| `Seen` | `StatementId` (Identity) | `u64` expires_ms |
| `Paused` | (value) | `u8` flags: bit 0 submit, bit 1 anchor, bit 2 register |
| `PruneCursor` | (value, optional) | the pallet's own: where `on_idle` resumes (§6.5); its layout is the teammate's, and the vectors leave its writes out (§10's `unpinned`) |

```rust
pub struct SpaceInfo {
    pub sovereign: AccountId32,
    pub controller: AccountId32,
    pub origin_ms: u64, pub length_ms: u64,     // the frozen clock, from the genesis
    pub start_window: u64,                       // the first window anchored here: the venue's next at registration
    pub status: SpaceStatus,                     // u8 enum
    pub authorities: u8, pub anchor_keys: u8,    // counts
    pub registered_ms: u64,
    pub max_spend_per_window: Balance,           // §7's budget; DefaultSpendPerWindow at registration
}
#[repr(u8)] pub enum SpaceStatus { Active = 0, /* 1 retired */ Blocked = 2 /* governance */, Ended = 3 /* equivocation, for good */ }
#[repr(u8)] pub enum Handler { Record = 0 }      // others refused at decode until admitted
#[pallet::composite_enum] pub enum HoldReason { Registration, Submit }
```

**The sovereign account:** `T::PalletId::get().into_sub_account_truncating(space_id)`,
which is `b"modl" ‖ b"kv/space" ‖ space_id[0..20]`.
- It is derivable from the genesis before registration, so the founder
  funds it first.
- `register` refuses an account already in `SovereignOf`.
- `register` calls `inc_providers` on it.
- **An ended space is a tombstone:** its `Spaces` entry, `SovereignOf`
  and `Equivocations` are never pruned, so its registration replayed is
  `SpaceExists` and its sovereign account stays its own.

**Authority accounts** get `inc_providers` on `add_authority` and
`dec_providers` on removal. Otherwise `CheckNonce` refuses a zero-balance
signer (`frame-system-48.0.0/src/extensions/check_nonce.rs:74-78`).

## 6. Calls

Call indices are pinned. Arguments are SCALE, fixed-width unless marked
compact, and the vectors are `BoundedVec<u8, _>`.

| # | Call | Origin | Effect |
|---|---|---|---|
| 0 | `register(genesis: Vec<u8>, controller: AccountId32, founder_key: [u8;32], founder_sig: [u8;64])` | any signed (pays its own fee) | §6.2 |
| 1 | `set_controller(space: SpaceId, controller: AccountId32)` | controller | replaces the controller |
| 2 | `add_authority(space: SpaceId, who: AccountId32, anchor_key: Option<[u8;32]>)` | controller | adds an authority, paired with `anchor_key` when given: an account that is an authority already is refused (`AuthorityExists`), a key paired with another authority (`AnchorKeyInUse`); an unpaired listed key, such as a founding one, becomes paired; a key not listed is listed through `vos_anchor::venue::add_key` (small order → `BadAnchorKey`, `MAX_FOUNDING_KEYS` listed → `TooManyAnchorKeys`); `inc_providers(who)` |
| 3 | `remove_authority(space: SpaceId, who: AccountId32)` | controller | removes it and its paired anchor key; `dec_providers(who)` best effort: a `ConsumerRemaining` error is ignored, the account merely stays alive |
| 4 | `remove_anchor_key(space: SpaceId, key: [u8;32])` | controller | removes an unpaired key, such as a founding one |
| 5, 6 | retired (v1's `migrate` and `resume`), never reused | | |
| 7 | `anchor(anchor: AnchorArg)` | any signed; the sovereign pays when the signer is an authority of `anchor.space` | §6.1 |
| 8 | `submit(payer: SpaceId, statement: Vec<u8>, proof: Vec<u8>)` | an authority of `payer`; the sovereign pays | §6.3 |
| 9 | `dispatch_as_sovereign(space: SpaceId, call: Box<RuntimeCall>)` | controller | dispatches as `Signed(sovereign)`, as communities' `dispatch_as_account` does; an ended space's too, so its funds can leave |
| 10 | `set_budget(space: SpaceId, max_spend_per_window: Balance)` | controller | sets §7's budget |
| 16 | `set_format(format: u32, active: Active)` | `ProgramsOrigin` or Root | §6.4 |
| 17 | `set_program(program: ProgramId, info: Option<ProgramInfo>)` | `ProgramsOrigin` or Root | §6.4; `None` = remove, subject to the same delay |
| 18 | `set_paused(flags: u8)` | `EmergencyOrigin` | immediate |
| 19 | `set_status(space: SpaceId, blocked: bool)` | `StatusOrigin` | `Blocked`; unblocking sets `Active`; an ended space is refused (`SpaceNotActive`) |

**Anchor keys, as VOS nodes use them:** a node signs anchors with its own
key that `AnchorKeys` lists for the space, its node key (a founding node's
genesis key), and signs nothing when none is listed. An authority's key is
set once, when it is added: a node's key changes only by replacing the
node (`remove_authority`, then `add_authority` of the new one). A node may
be added as a replica of the space's representative only while it holds a
listed key (checked when it is added).

`AnchorArg` is pin D's `Anchor`:
`{ space: [u8;32], window: u64, kind: u8, root: [u8;32], signer: [u8;32], signature: [u8;64] }`,
where `signer` is the ed25519 anchor key and `signature` is ed25519 over
the anchor digest.

### 6.1 `anchor`, the anchor rule (pin D′)

The pallet checks the pause (anchor) and decodes the kind (`BadKind` for
any but 0), then calls `vos_anchor::venue::anchor(&StorageVenue, &anchor)`,
which decides in this order:
1. the space is registered (`Unregistered` → `UnknownSpace`) and `Active`
   (`Stopped` → `SpaceNotActive`: ended or blocked);
2. `signer ∈ AnchorKeys(space)` (`Key` → `UnknownAnchorKey`);
3. the ed25519 signature over `anchor_digest(venue, space, window, kind,
   root)`, strictly (`Signature` → `BadAnchorSignature`);
4. `now_ms − B_w ≤ MaxRootAge` (`Age` → `WindowTooOld`): before the held
   root, so a second root at an aged window is refused alike whether or
   not `on_idle` has pruned the first;
5. **if `Anchors(space, kind, window)` exists:** the same root → `Again`
   (`AlreadyAnchored`); another root → `Evidence(held)`;
6. otherwise `start_window ≤ w` and `Last(space, kind) < w` when present,
   gaps allowed (`Window` → `WindowNotAfterLast`);
7. `w < now_w`, `now_w` the window of `Timestamp.Now` through the space's
   clock, none before its origin: the open window, a later one, or any
   before the origin cannot be anchored (`Open` → `WindowInFuture`);

and answers `New`. A venue that cannot read state where it checks the
signature (JAM's refine) judges the signature first: an anchor failing
both a state check and its signature is `Signature` there and the state's
refusal here. The codes differ only when two faults coincide. The pallet then writes what it decided:
- **`New`:** store `Anchors` (`at_ms = now`, `signer`) and `Last = w`;
  emit `Anchored`.
- **`Evidence(held)`:** store `Equivocations` with both roots and both
  signers (the stored record's and this one's), keep the first root's
  `Anchors` record, set the status to `Ended`, release the
  `RegistrationDeposit` held on the sovereign account, emit `Equivocated`
  and `SpaceEnded`, and return **Ok** so the evidence persists. Anyone may
  submit that second signed anchor; a VOS node's client does, sending its
  own anchor as the evidence when the pallet holds another root at its
  window. Which root was wrong is unknowable, so neither is trusted again:
  the space's roots are refused from then on (`anchored` reads `Active`),
  it never anchors again, and it founds again under a new genesis.

### 6.2 `register`

1. Not paused (register).
2. Decode the genesis (`SpaceGenesis::decode`: version 1, canonical;
   `BadGenesis` otherwise).
3. `vos_anchor::venue::registration(venue, genesis, controller,
   founder_key, founder_sig, verify)`, which reads no state:
   - 1 to `MAX_FOUNDING_KEYS` (16) founding keys, none twice, none of
     small order (`Genesis` → `BadGenesis`);
   - a registrable `length_ms` (`Clock` → `BadClock`);
   - `founder_key` a founding key, and `founder_sig` its signature over
     `register_digest(venue, space, controller)`, strictly (`Founder` →
     `BadFounder`). No window is signed, so a registration seen in the
     pool can be resubmitted only as itself.
4. `vos_anchor::venue::register(&StorageVenue, &registration)`: the space
   is not registered, ended or not (`Exists` → `SpaceExists`); it answers
   the space's first window, the venue's next: `now_w + 1`, or 0 while the
   venue's time is before the space's origin.
5. The sovereign account is not in `SovereignOf` (`SovereignInUse`).
6. Hold `RegistrationDeposit` on the sovereign account
   (`InsufficientSovereignBalance` otherwise).
7. Store `SpaceInfo` (`start_window` from step 4, `Active`,
   `max_spend_per_window = DefaultSpendPerWindow`) with every founding key
   as an unpaired anchor key, and `inc_providers(sovereign)`.
8. Emit `SpaceRegistered`.

The deposit is released when the space ends (§6.1); a deregistration of a
live space is not in this version.

**Known limit:** any single founding key registers the space here, before
the space's controller does, under a controller of that key's choosing,
and the space cannot register here again: one compromised founder squats
the space at every venue it has not reached. The lever is carried: a
registration co-signed by the controller, or by a founders' quorum. Nor
does any venue see another's registrations: a founder may register the
same genesis here and at another venue. With the same roots anchored at
both, a statement is accepted, and handled, at both; with different roots,
the space forks unseen. One venue a space is the space's discipline, and
an anchor gives no integrity: a value-moving handler is two-sided or spends
the submitting space's own escrow (§1).

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
9. `judge(&StorageVenue, &program, &statement, &proof)`. Inside it run
   the format again, the space rule (at least one root, every root of the
   statement's space, never `SpaceId::NONE`: refusal 4), anchored, the
   io-hash, unseen, and the proof.

`payer` may differ from `statement.space`: any space's authority may pay
for any statement; the proof is what is judged. A statement is accepted
wherever its roots are anchored, here or at another venue the same space
registered at (§6.2's known limit).

The outcome:

| Outcome | Storage | Deposit | Events |
|---|---|---|---|
| `Ok(id)` | `Seen[id]` = `B_wmax + MaxRootAge` (newest root's window; `vos_statement::seen_expiry`). That entry and the `Accepted` event are the whole of `Record`: it stores nothing else; later handlers add their own storage | released | `Accepted` |
| refusal 6 (repeated) | – | released | `Refused { code: 6 }`. A race between two nodes is not punished |
| any other refusal | – | transferred to `ForfeitTo` | `Refused { code }`, `DepositForfeited` |

**Weights:**
- declared: `submit_accept`;
- actual: `submit_refused_early` for refusals before the proof (codes 1–6);
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

- Prune `Anchors` whose `B_w + MaxRootAge < now`
  (`vos_anchor::venue::aged`), and `Seen` entries whose `expires_ms < now`.
- Keep `Last`, `Equivocations` and every `Spaces` entry, an ended space's
  included (its tombstone).
- Bounded by the remaining weight: it may stop part way and resume in a
  later block, keeping where it stopped in `PruneCursor` (§5), the one
  item whose layout this design leaves to the pallet. A pallet that prunes
  all it can each block needs none. Either way the vectors pin every other
  key's writes (§10); `PruneCursor`'s are the file's `unpinned`.
- `MaxRootAge` is the kit's constant, never raised in place. A raise is a
  VOS change of `MAX_ROOT_AGE_MS`, a new kit, and a storage migration that,
  before the new kit takes effect, adds `new − old` to every `Seen`
  expiry: an anchor still fresh stays anchored until `B_w + new`, and its
  statements' entries must last as long, or a replay is accepted once an
  entry computed with the old bound is pruned (pin F). Pruned anchors stay
  pruned: a root older than the old bound was refused already.

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

The variant indices are pinned; a retired index is never reused.

**Events:**

| # | Event |
|---|---|
| 0 | `SpaceRegistered { space, sovereign, controller, origin_ms: u64, length_ms: u64, start_window: u64 }` (`start_window` the venue's next window) |
| 1 | `ControllerSet { space, controller }` |
| 2 | `AuthorityAdded { space, who, anchor_key: Option<[u8;32]> }` |
| 3 | `AuthorityRemoved { space, who }` |
| 4 | `AnchorKeyRemoved { space, key }` |
| 5 | retired (v1's `Migrated`) |
| 6 | `Anchored { space, kind: u8, window: u64, root: [u8;32] }` |
| 7 | `Equivocated { space, kind: u8, window: u64, first: [u8;32], second: [u8;32], first_signer: [u8;32], second_signer: [u8;32] }` |
| 8 | `SpaceEnded { space }` |
| 9 | retired (v1's `SpaceResumed`) |
| 10 | `SpaceStatusSet { space, status: u8 }` |
| 11 | `Accepted { id: [u8;32], program: [u32;8], space: [u8;32], payer: SpaceId, output_hash: [u8;32] }` (the Record handler: `output_hash = BLAKE2b-256(statement.output)`) |
| 12 | `Refused { payer: SpaceId, statement_hash: [u8;32], code: u32 }` (`statement_hash = BLAKE2b-256(statement bytes)`) |
| 13 | `DepositForfeited { space, amount: Balance }` |
| 14 | `FormatSet { format: u32, active: Active }` |
| 15 | `ProgramSet { program: [u32;8], info: Option<ProgramInfo> }` (`ProgramInfo { handler: u8, active: Active }`) |
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
| 18 | retired (v1's `OutOfRange`) |
| 19 | `SpaceNotActive` |
| 20 | `Paused` |
| 21 | `InsufficientSovereignBalance` |
| 22 | `TooEarly` (the delay) |
| 23 | retired (v1's `StillEquivocating`) |
| 24 | retired (v1's `AlreadyMigrated`) |
| 25 | `BadHandler` |
| 26 | retired (v1's `BadStartWindow`) |
| 27 | `OverBudget` (the pallet-only fallback; the extension refuses in `validate`) |
| 28 | retired (v1's `SameVenue`) |
| 29 | `AuthorityExists` (`add_authority` of an account that is one already) |
| 30 | `BadAnchorKey` (`add_authority` pairing a key of small order) |

As `DispatchError::Module { index: 90, error: [i, 0, 0, 0] }`.

## 9. The interface VOS nodes rely on

The node's client (`vos-venue`'s `kreivo` module, over a `Transport`, §9.1):
- builds these calls from the **pinned bytes**: `[90, call_index] ++ SCALE(args)`;
- its transport builds the envelope (signed extensions, nonce, era) from
  Kreivo's live metadata;
- needs no compile-time metadata of the pallet: the call bytes are pinned.
  The transport uses the live metadata to delimit pallet 90's events in
  `System.Events`, and the client decodes their fields by §8's pinned
  layout.

| Node action | Call | Signer | Success signal | Errors it maps |
|---|---|---|---|---|
| register a space (operator tool) | 0 | operator's account | `SpaceRegistered` | 0–5, 20, 21 |
| its authorities, the budget (controller tool) | 1–4, 10 | controller | events 1–4, 18 | 6–11, 29, 30 |
| anchor `S_w` (the representative's leader) | 7 | the node's sr25519 authority account | `Anchored` | see below |
| submit a statement (the worker) | 8 | the node's sr25519 authority account | `Accepted { id }` → accepted; `Refused { 6 }` → accepted; `Refused { c }` → `Refusal(c)` | 7, 19–21 → a configuration or funding alert; `InvalidTransaction::Payment` → the budget or the sovereign's funds, an alert |

**The anchor's outcomes, and what the client does.** The node's leader
knows five outcomes of an anchor (pin D′): taken, not yet, never,
unlisted and stopped, each with the venue's raw code for its log. The
client pre-checks nothing of the anchor rule. It answers from its last
read of the space (not yet while unregistered, unread or paused; stopped
while not active; unlisted while `AnchorKeys` does not list the signer),
and otherwise queues the anchor and sends it. Before sending, it reads
`Anchors[space][0][w]`: the same root held settles it; another root is
sent only when the leader offered the anchor after reading that root (its
divergence guard passed), as the equivocation's evidence. The pallet's
answer, by one table:
- an `Anchored` event of its root, or 14 `AlreadyAnchored` → taken;
- an `Equivocated` event → the space ended: an alert, and nothing more is
  sent for it;
- 15 `WindowNotAfterLast`, 17 `WindowTooOld`, 12 `BadAnchorSignature`,
  13 `BadKind` → never: an alert; signing again with the same key makes
  the same signature;
- 7 `NotAuthority`, 11 `UnknownAnchorKey` → unlisted: the leader hands its
  leadership to a replica whose node key `AnchorKeys` lists;
- 19 `SpaceNotActive` → stopped: no anchor until the space is active;
- 16 `WindowInFuture` → not yet: sent again a block later. Kreivo's
  timestamp lags real time by up to a block and the collator's drift, so
  near a boundary, above all at L = 2 min (D = 24 s), this is a live
  case; skipping it would leave the window unanchored for good;
- 20 `Paused`, 21 and 27, `InvalidTransaction::Payment` (a funding alert:
  a delisted authority pays its own fee, so the client reads the listing
  first) and any other → not yet.

Nothing is handed back to be signed again: a node signs only with its
node key, and the leader offers each window's root again from its
replicated row until the venue holds it, never takes it, or a replica
whose key is listed leads.

**Storage the node reads** (raw keys):
`twox128("Spaces") ++ twox128(item) ++ hashed key`:
- `Spaces[space]`: status, clock, sovereign;
- `Authorities[space][self]`;
- `AnchorKeys[space]`: `VenueClient::anchor_keys`, whether the
  representative's leader may sign with its node key, the replica it
  hands its leadership to when it may not, and whether a node may
  replicate the representative;
- `Anchors[space][0][w]`: `VenueClient::held`, the root at a window the
  leader asks of, and `VenueClient::anchored`;
- `Last[space][0]`: past it, the venue holds no root;
- `Seen[id]`;
- `Formats` and `Programs`: a pre-check before paying;
- `Paused`;
- `Budget[space]`: the window's spend, before paying;
- `Timestamp.Now`: the venue's time, what `anchored` and the budget's
  window read;
- `System.Account[sovereign]`: a funding alert below N submits;
- `System.Events`, filtered by the extrinsic index.

The **mock** VOS tests against implements exactly this table and §6–§8.

### 9.1 The node-side chain transport: master's substrate extension, ported

VOS ships the client's logic, not its chain transport:
- `KreivoVenue`, the `VenueClient` the node anchors and submits through;
- its pinned `calls`;
- the `Sender`, which sends a call at most once;
- the `Transport` trait under them (`node/venue/src/kreivo/transport.rs`).

**Where the transport comes from.** VOS master already has a Substrate
integration on `sube`: `extensions/substrate`. It runs sube over the
smoldot light client and submits externally signed V4 transactions. Its
submission is replay-safe, and it hardens nonces and cancellation. It is
written against master's old extension ABI, and vos-core has no extension
host yet (`core-model.md` §18, open question 18).
- The node-side Kreivo transport is expected to be a port of that
  extension onto vos-core's extension host.
- **Who owns what:**
  - the port is VOS's work, after the planned slices, once the extension
    host exists (owner decision 12d);
  - the pallet is the teammate's;
  - the live Kreivo leg (the client over the port, on a dev chain
    carrying the pallet) waits on both.

  Until then `KreivoVenue` runs over the mock only, including the Kreivo
  leg of the end-to-end run.
- `KreivoVenue` reaches the extension by message, through a `Transport`
  implementation. It plugs in through `KreivoVenue::connect`, whose
  `Connect` the client's reader thread calls until Kreivo is reached.
- An earlier subxt transport, parked unmerged, is
  `node/venue/src/kreivo/chain.rs` at VOS commit `9e63e5a9`. Its review
  (`slice-6-progress.md`) found the behaviours below.

**What the transport must provide** ("ext": master's extension already
covers it; "part": it covers part, and the port finishes it; unmarked: the
port adds it):
- **Signing with the node's sr25519 key.**
  - ext: signing is external, so no key enters the extension. It
    prepares the exact V4 signing payload and checks the signature.
  - The node's side adds the key: one 32-byte mini secret per node, kept
    in the node's store beside its ed25519 node key. It is never the node
    key, never logged, and zeroed when dropped.
  - The node store's `NodeRow` tag `0x10` is reserved: it held these
    seeds, a u64 big-endian number mapped to a 32-byte mini secret, and
    stores from earlier builds may hold such rows. A reuse keeps that
    layout, or takes a new tag.
  - Rotation adds a numbered row and keeps the old key. The controller
    removes the old authority, then adds the new one paired with the
    anchor key, so the node anchors nothing between the two calls.
- **The fee-paying account.** The node's account signs but holds no
  balance: `ChargeSpaceFee` charges the space's sovereign account (§7).
  The node's account needs only the provider `add_authority` gives it.
- **The envelope.**
  - part: the extension builds a metadata-driven V4 envelope, with a
    mortal era.
  - The call goes as its pinned bytes, never as a `pallet/call` path and
    text fields. The client checks that the call bytes in the payload
    equal them.
  - The metadata's signed extensions must be the list the port pins from
    Kreivo's runtime (`KR/lib.rs`), in its order, with §7's
    `ChargeSpaceFee` in `ChargeTransaction`'s place, or nothing is signed.
  - `PassAuthenticate` is pinned to `None` after its type is checked to
    be an `Option`.
- **Nonce and pool.** The `Sender` takes a call as landed only once
  `System.Account`'s nonce at the best block passes it, never by the
  pool's count. It never signs again with another nonce while the first
  may land; it sends the same bytes, and signs anew with the same nonce
  only after the era ends.
  - ext: a frozen request, a durable outcome journal, and the exact
    extrinsic resent on recovery. An automatic nonce stays reserved after
    an ambiguous submit (`NonceUncertain`) until the finalized nonce
    advances or the era expires.
  - The port maps these onto `Transport::nonce`, `chain_nonce`, `sign`
    and `send`, with `Signed::until` set to the era's last block.
- **The pool's refusals, classified** as `SendError` from the
  `1010` / pool answer:
  - `Payment`;
  - `Stale` (outdated, stale, bad signature, ancient birth block);
  - `Future`;
  - `Call`;
  - `Other`;
  - `Lost` for a lost connection, or a watched extrinsic dropped,
    invalidated or usurped; and for the pool's "already imported",
    "temporarily banned" and "priority too low", whose extrinsic may still
    land, so the `Sender` never signs again with a fresh nonce while it
    may.

  part: the extension folds every invalid transaction into one `Chain`
  code.
- **Inclusion.**
  - part: the extension waits for best-chain inclusion or finality and
    returns the extrinsic's index and a dispatch outcome. Its events are
    decoded text, at most 16 of them.
  - The transport needs pallet 90's events as raw `[event_index] ++
    fields`, and `ExtrinsicFailed`'s raw `DispatchError`.
  - Past the era, the transport gives up with `Lost`, so the `Sender`
    reads the nonce again.
- **Reads.** Raw storage at a block by key, and every key under a prefix.
  - part: the extension reads at finalized blocks only, by `pallet/item`
    path, with snapshot-pinned paged maps.
  - The port adds reads by raw key, and best-block reads:
    `Transport::storage`, `keys`, `best` and `chain_nonce` read at the
    best block.
  - What `VenueClient::anchored` answers from must be final: the anchors
    `KreivoVenue` holds and the last window it read are taken from
    finalized blocks, never from a best block's `Anchored` event, or a
    reorg makes the worker submit against a retracted root and forfeit its
    deposit. The client as built marks an anchor held on the event its
    transport reports; the port reports finalized inclusion there, or the
    client reads the record at a finalized block first.
- **Reconnect.**
  - ext: the light client reconnects, and a session whose cleanup is
    uncertain is poisoned and dropped.
  - A node starts while Kreivo is down: `KreivoVenue::connect` answers
    every anchor `Open` until the transport is reached.
- **Transport security.**
  - ext: no public RPC endpoint; smoldot verifies the chain.
- **What `KreivoVenue` keeps, which a transport must not undo:**
  - a refresh never moves a space's last anchored window backwards;
  - an anchor landed whose record is not yet read stays queued;
  - nothing is sent for a window the venue has not closed, nor while the
    space waits.
- **The release gate.** No release build reaches Kreivo until the pallet
  passes G1–G17 in its mock runtime (the `fees` vectors in Kreivo's
  runtime tests) and the client passes an end to end run on a Kreivo dev
  chain over the port (`slice-6-on-chain.md`, the deferred Kreivo
  gates).
- **The CLI,** over `calls::Call` and the `Sender`:
  - the node's Kreivo venue;
  - showing and rotating its account;
  - `register` (call 0). The founder signs `register_digest(venue, space,
    controller)` with the stopped founding node's ed25519 key; the space
    anchors from the venue's next window. The command prints the sovereign
    account first.
  - `authority add|remove` (calls 2–3);
  - `budget` (call 10).

**The contract** is the conformance vectors and the mock:
- `node/venue/conformance/*.json` and the mock that writes them
  (`vos-venue`'s `kreivo-mock` feature; `just conformance` regenerates them);
- the scenarios of `KreivoVenue`'s tests over the mock
  (`node/venue/src/kreivo/tests.rs`, `node/host/tests/cluster/kreivo.rs`),
  which set the mock's state directly: the port states them again over
  its transport against a dev chain carrying the pallet, its state set by
  the pallet's calls (the live Kreivo leg);
- the vectors' replay is the mock's (`conformance/mod.rs`); the
  teammate's harness that runs them against the pallet is reviewed by VOS
  before the pallet is taken as passing G1–G17.

## 10. Conformance vectors

VOS ships `vendor/vos-verifier/conformance/spaces.json` in the kit,
generated in VOS by the mock; the sync check (§3.1) holds it to the VOS
tag's, byte for byte.
- **Each vector holds:**
  - the constants (deposits, delay, `PalletId`, venue; `MaxRootAge` and
    the window lengths are the kit's);
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
- **The files** (`conformance/` in the kit; in VOS `node/venue/conformance`,
  written by `just conformance`, refused stale by `just check`):
  - `spaces.json`: the constants (§4's suggested values, `UNITS =
    10^12`, `FeeBound = UNITS`, the existential deposit `UNITS / 1000`,
    `ForfeitTo` the `py/trsry` pallet account), labels for the accounts and
    anchor keys, and G1–G17. A pre-state is the time, each account's free
    and held balances (`Registration`, `Submit`) and its providers and
    consumers, and the pallet's raw storage. A step is a time, then a call
    (its origin: a signed account, Root, `ProgramsOrigin`,
    `EmergencyOrigin` or `StatusOrigin`; its bytes as hex parts and byte
    ranges of the kit's `fixtures/` files, so a proof is not copied into
    the file once a submit) or `on_idle` with ample weight. Its expectation:
    the result (`ok`, `{"module": i}`, `bad_origin`, `invalid_payment` in
    `validate`, `undecodable` before dispatch), the pallet's events in SCALE
    (without the runtime's index), every raw key whose value changed (`null`
    removed), and each account's deltas. A `fees` vector also names who paid
    the fee, and pins `Budget`'s writes by key and `window`, its `spent`
    masked (`?` a nibble not compared), since that spend sums fees. A
    call's parts may also be `{repeat, count}`, one byte repeated, which
    the length bounds' steps use. `unpinned` lists the raw keys a harness
    leaves out of every step's storage: `PruneCursor`'s (§5, §6.5);
  - `mutations.json`: spike 6c's proof mutants (120) and statement mutants
    (284), and format 39's masked fields tampered (12 the fixed layout
    holds), each a patch of the `valid` fixture's proof or statement and
    the code its judgement reaches at that fixture's venue state, for the
    `#[benchmark(extra)]` sweep.
- **The fixture space:** the fixtures' statements read roots of the space
  `[0xa1; 32]`, which no genesis hashes to, so every pre-state holds it as
  storage (registered from window 40 under the default clock, one
  authority paired with its anchor key) rather than registering it by
  call 0; another space is registered by call. The venue
  (`frame_system::block_hash(0)` in the mock runtime) is the fixtures'.
- **G7** covers codes 1–5 and `0x1xx`: a repeat (6) releases its
  deposit (§6.3), so it is G8's. It then submits the fixture itself while
  its format is retired (`until_ms` now) and while it is not yet active
  (2), while its program's
  `until_ms` is now and while its `from_ms` is later (3), and once it is
  active (accepted): a pallet that checks a format's or program's presence
  and not its window fails it.
- **G17** pins the length bounds (§4): a genesis of `MaxGenesisLen`, a
  statement of `MaxStatementLen` and a proof of `MaxProofLen` bytes decode
  and are judged; a byte more of each is `undecodable`.
- **G13** pins `Budget`'s key and its `window`, and an accepted submit's
  deposit credited back to the window's budget: at `SubmitDeposit + 2 ×
  FeeBound` a window, an accepted submit leaves room for one forfeiting
  submit. G4 sets the time before the space's origin: no window is
  closed, so the anchor is `WindowInFuture`.

| Id | Scenario |
|---|---|
| G1 | register: the fixture genesis's space registered, anchoring from the venue's next window (start_window now_w + 1), its sovereign address `modl ‖ kv/space ‖ space[..20]`, the deposit held; refused: the founder's signature under another controller (BadFounder), a second registration (SpaceExists); a space whose clock has not started registered from window 0 |
| G2 | add_authority (with a paired anchor key, and without), remove_authority (its key leaves AnchorKeys), each account's providers; refused: a non-controller (NotController), an unknown space (UnknownSpace), a second removal (NotAuthority) |
| G3 | anchor at w, then w + 2 (a gap), by an authority and by any signed account; Last follows |
| G4 | anchor refusals: before the space's first window (WindowNotAfterLast), older than MaxRootAge (WindowTooOld), exactly MaxRootAge old taken, the same root again (AlreadyAnchored), the open window now_w and a later one (WindowInFuture), then now_ms at B_w and the same anchor resubmitted (Anchored); a stale w ≤ Last (WindowNotAfterLast); a second root at a held window past MaxRootAge (WindowTooOld: no evidence, the space active); a bad signature (BadAnchorSignature), kind 1 (BadKind), an unlisted key (UnknownAnchorKey), an unknown space (UnknownSpace), now_ms before the origin (WindowInFuture) |
| G5 | an equivocation ends a space: a second root of a window held, signed by another listed key (the failover case: the honest node's anchor as the evidence), Equivocated naming both signers and SpaceEnded, the status Ended (index 3), the registration deposit released to the sovereign; then its anchors refused (SpaceNotActive), the evidence's too, and its roots unanchored (a statement over a window held refused 5); the registration replayed refused (SpaceExists: the space is never pruned); dispatch_as_sovereign still the controller's, the sovereign's funds leaving, the existential deposit kept |
| G6 | submit of the masked format-39 fixture: its two roots anchored, then Accepted { id }, Seen[id] its newest root's B_w + MaxRootAge, the deposit held and released |
| G7 | one mutant per refusal class, each Refused { code } and DepositForfeited: 1 (the statement cut short), 2 (format 30), 3 (a program not in Programs), 4 (a space not its roots'), 5 (a root not anchored), 0x1xx (the proof's byte flipped); 6 is G8's, its deposit released. Then the statement itself against activation windows: 2 while Formats[39].until_ms is now (retired), and while its from_ms is past now; 3 while its program's until_ms is now, and while its from_ms is past now; accepted once now reaches it |
| G8 | the same statement twice: Accepted, then Refused { 6 } with the deposit released |
| G9 | a statement of no root refused 4: venues judge rooted statements alone. A rooted one accepted; at MaxRootAge + 1 past its newest root's B_w, resubmitted before on_idle refused 5 (its anchors held but past MaxRootAge); on_idle prunes its Seen entry; resubmitted, refused 5 |
| G10 | a submit whose sovereign cannot hold the deposit (InsufficientSovereignBalance, nothing moved); a non-authority's submit (NotAuthority); set_paused by a signed account (BadOrigin); each pause flag, by the emergency origin, refusing its call (Paused): bit 0 submit, bit 1 anchor, bit 2 register, each other call unpaused; cleared by Root |
| G11 | set_program by ProgramsOrigin: from_ms before now + delay, or an until_ms set before it, refused (TooEarly); at now + delay taken; Root at once; a signed account (BadOrigin); a removal by ProgramsOrigin sets until_ms = now + delay, Root's removes at once; a change other than setting or shortening until_ms (an active program's from_ms moved) needs from_ms ≥ now + delay (TooEarly); a handler other than Record does not decode |
| G12 (fees) | fees, signs only: a submit whose sovereign cannot cover its fee and deposit refused in validate (InvalidTransaction::Payment), nothing paid; an authority's anchor and submit paid by the sovereign account, the authority unchanged; a non-authority's anchor and submit paid by the signer |
| G13 (fees) | the budget, fees: at 8 × (SubmitDeposit + FeeBound) a window, eight forfeiting submits taken and the ninth refused in validate (InvalidTransaction::Payment; OverBudget in the fallback), the sovereign untouched; the next window resets it; set_budget to two submits' worth, the window's second taken and its third refused; set_budget to SubmitDeposit + 2 × FeeBound, the next window's accepted submit, its deposit credited back, leaving room for one forfeiting submit, and the next refused. The model charges each fee at FeeBound, so eight fill the budget exactly |
| G14 | the controller and keys: set_controller (the old controller then NotController); add_authority of an authority already (AuthorityExists: a node's key changes only by replacing the node), of a key paired elsewhere (AnchorKeyInUse), of a key of small order (BadAnchorKey); an unpaired founding key paired; remove_anchor_key of a paired key (AnchorKeyInUse), of an unpaired founding key (removed), of an unlisted one (UnknownAnchorKey); remove_authority with a consumer on the account, its provider kept (best effort) |
| G15 | dispatch_as_sovereign: a transfer from the sovereign (SovereignDispatched); set_status by a signed account (BadOrigin); blocked: its submits and anchors refused (SpaceNotActive), unblocked back to Active; a blocked space's roots unanchored (5); an ended space neither blocked nor unblocked (SpaceNotActive); set_format by ProgramsOrigin under the delay (TooEarly), at now + delay taken, Root at once |
| G16 | on_idle: at B_w + MaxRootAge of F's newest root, only older anchors pruned; one ms later its anchor and the Seen entry pruned; Last, Equivocations and an ended space's record kept |
| G17 | registration refusals: a window length below vos_anchor::MIN_LENGTH_MS or above MAX_LENGTH_MS (BadClock), 17 founding keys, one key twice, a key of small order or a genesis that does not decode (BadGenesis), a key not in the genesis or another founder's signature (BadFounder), a sovereign already listed (SovereignInUse), an unfunded sovereign (InsufficientSovereignBalance), a second registration (SpaceExists); a submit paid by a space other than the statement's: accepted. The length bounds: a genesis of MaxGenesisLen (2,048) bytes decodes (BadGenesis) and one of a byte more does not (undecodable); a statement of MaxStatementLen (65,536) bytes decodes (refused 1) and a byte more does not; a proof of MaxProofLen (262,144) bytes decodes (judged: S, accepted before, a repeat) and a byte more does not |

**From v1's numbering:** G1–G13 keep their numbers; v1's G14
(`migrate`) and G19 (`resume`) are gone; v1's G15 is G14, G16 is G15, G17
is G16 and G18 is G17. G1, G4, G5, G7, G9, G11, G14, G15, G16 and G17
changed with the picks: registration from the next window, equivocation
ending the space, rooted statements only, `add_authority` setting a key
once, and the small-order keys refused. Every vector's bytes changed:
`SpaceInfo` lost `end_window` and `ProgramInfo` `venue_bound`, so every
pre-state's storage did.

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
2. **Anchor signatures.** Answered (S13): pin D's ed25519 anchor key,
   one per node, paired with its sr25519 authority and set once; verified
   strictly, a key of small order never listed.
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
8. **The on-chain end to end.** Settled: VOS's end to end runs the
   Kreivo leg over the mock, its acceptance gate; the live leg runs once
   the pallet and the port exist.
9. **Communities fold-in (S2):** after slice 6 (recommended).
10. **Anonymous authorities:** after slice 7's credential AIR (recommended).
11. **A blocked space's roots.** Answered: unanchored, as an ended
    space's are (`vos_anchor::venue::anchored` reads `Active`); G15 pins
    it.
12. **Anchor keys beyond the founding ones.** Answered (S13): none. An
    authority's key is set once, by `add_authority`; a node's key changes
    only by replacing the node. A founding key may be paired with a new
    authority, and an unpaired one removed (`remove_anchor_key`). A space
    whose key is stolen and used ends at its first equivocation (§6.1),
    and founds again.
13. **The budget's correction to the actual fee** (§7, G13).
    - `post_dispatch` corrects the budget to the actual fee, so eight
      forfeiting submits spend `8 × (SubmitDeposit + a)` for an actual fee
      `a ≤ FeeBound`, and the ninth is refused only when
      `8 × (FeeBound − a) < SubmitDeposit + FeeBound`: at Kreivo's fees it
      may pass. VOS's mock charges every fee at `FeeBound`, so G13's ninth
      is refused there.
    - The options: keep the correction (the budget a bound on actual spend,
      G13's count read as "the submit past the budget"); or debit the fee
      bound and never correct it.
    - **Recommended: debit `FeeBound` and do not correct it,** so the budget
      bounds spend conservatively and G13 holds as written; the deposit a
      dispatch released is still credited back.
14. **Refusals the design leaves unnamed,** each as the mock has it and
    VOS's vectors pin where they reach one:
    - `BadHandler` is unreachable while `Handler` has one variant: another
      byte fails the call's decode (G11, `undecodable`);
    - a removal by `ProgramsOrigin` (`set_program(_, None)`) sets the
      entry's `until_ms` to `now + ProgramChangeDelay` (or keeps an earlier
      one), Root's removes it at once (G11); its removal of an absent
      program is Ok, with `ProgramSet`, and writes nothing;
    - `ProgramsOrigin`'s delay: a change that only sets or shortens a
      stored entry's `until_ms`, the rest unchanged, needs that `until_ms`
      at `now + ProgramChangeDelay` or later; any other change, a new entry
      or a later or cleared `until_ms` among them, needs `from_ms` (and any
      `until_ms`) at `now + ProgramChangeDelay` or later, else `TooEarly`
      (G11, G15);
    - an anchor before the space's `start_window`: `WindowNotAfterLast`
      (G4), as the venue rules have it;
    - an anchor while the venue's time is before the space's origin:
      `WindowInFuture` (G4);
    - `remove_authority` of an account that is not one: `NotAuthority`
      (G2); `remove_anchor_key` of an unlisted key: `UnknownAnchorKey`
      (G14);
    - `set_status` of an ended space: `SpaceNotActive` (G15);
    - `register` while the venue's time is before the genesis's origin:
      the space anchors from window 0 (G1);
    - `ChargeSpaceFee`'s budget window before the space's origin: window 0
      (no vector).
    - **Recommended:** as above; another answer regenerates the vectors.
15. **`dispatch_as_sovereign`'s inner call** is Kreivo's `RuntimeCall`:
    G15's and G5's are `Balances` (index 10) `transfer_keep_alive` (3) to a
    `MultiAddress::Id`. The pallet's mock runtime places `Balances` at 10
    for them to decode (recommended), or re-encodes that one inner call.
