# Spaces pallet: research for slice 6

2026-10-19. Read-only. The handoff design built on it is
`stage/spaces-pallet-design.md`.

Path keys:
- `FC` = frame-contrib 2.3.1, the version Kreivo uses, in
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/fc-*-2.3.1/`
  (Kreivo pins it at `kreivo-s6-spike/Cargo.toml:63-73`).
- `FCm` = frame-contrib `main` at f95b25e (3.0.0-pre.2), in `ext/frame-contrib`.
- `FCp` = the owner's branch `feat/private-communities` (82d8ab1, pushed to
  origin, not merged), in `~/src/virto/frame-contrib`.
- `K` = `~/src/virto/kreivo-s6-spike` (Kreivo master 87f8728 plus the spike
  commit a7370f1), and `KR` = `K/runtime/kreivo/src`.
- `PA` = `~/src/virto/pass-authenticators` (cf85a9b).
- `SDK` = the polkadot-sdk crates Kreivo locks: frame-system 48.0.0,
  frame-support 48.1.0, pallet-transaction-payment 49.0.0,
  pallet-skip-feeless-payment 23.0.0, sp-runtime 44.0.0. All are in the
  cargo registry.

---

## 1. pallet-communities today

### What a community is

- **Its id** is `Config::CommunityId`, which Kreivo sets to `u16`
  (`K/common/src/lib.rs:16`). `MembershipId` is `u32`.
- **Its record** is `Info: CommunityId → CommunityInfo { state: Active | Blocked }`
  (`FC/communities/src/lib.rs:264-265`, `types.rs:41-59`). There is no
  name or metadata on chain: the manager pallet takes the name only to
  label the referenda track.
- **Its admin** is any `PalletsOrigin`, stored in reverse as
  `CommunityIdFor: PalletsOrigin → CommunityId` (`lib.rs:268-270`).
  `set_admin_origin` moves it (`lib.rs:397-418`). An origin may administer
  one community only (`functions.rs:58-61`).
- **Its origin** is `pallet_communities::Origin { community_id, subset }`, with
  subsets `Member`, `Members{count}`, `Fraction`, `AtLeastRank`
  (`origin.rs:96-132`). `EnsureCommunity` accepts that origin, or a
  caller listed in `CommunityIdFor`, while the community is Active
  (`origin.rs:16-41`).
- **Its sovereign account already exists.** It is
  `PalletId.into_sub_account_truncating(community_id)` (`functions.rs:17-19`),
  with `PalletId(*b"kv/cmtys")` in Kreivo (`KR/config/communities/mod.rs:20`).
  The derivation is `(b"modl", pallet_id, sub)` truncated to 32 bytes
  (`sp-runtime-44.0.0/src/traits/mod.rs:2023-2024`).
  - Registration calls `inc_providers` on it (`functions.rs:74`), so it
    exists with no balance.
  - It acts through `dispatch_as_account`, which needs `MemberMgmtOrigin`
    (`lib.rs:598-613`, `functions.rs:217-226`).
  - It also acts by being signed for: Kreivo's `AdminOrigin` and
    `MemberMgmtOrigin` are `EitherOf<EnsureCommunity, EnsureCommunityAccount>`.
    `EnsureCommunityAccount` maps a signed sub-account back to its id
    (`KR/config/communities/mod.rs:27-32,46-47`).
- **Memberships** are NFTs in `pallet_nfts` Instance2, "CommunityMemberships",
  at index 74 (`KR/config/communities/memberships.rs:33-71`).
  - Collection 0 is the manager's pool of memberships for sale. It is owned
    by the treasury and minted with gas-tank and expiry attributes
    (`K/pallets/communities-manager/src/lib.rs:322-395`).
  - Each community has a collection whose id is its own id
    (`communities-manager/src/lib.rs:291-301`).
  - A rank is an NFT attribute. `add_member` assigns a membership that the
    community account holds (`FC/communities/src/lib.rs:422-439`).
- **Governance:**
  - each community gets one referenda track whose id is the community id,
    in `CommunityTracks` (`pallet_referenda_tracks` Instance2, index 72)
    and `CommunityReferenda` (`pallet_referenda` Instance2, index 73)
    (`KR/config/communities/governance.rs:7-8,37-111`);
  - the decision methods are `Membership | NativeToken | CommunityAsset | Rank`
    (`types.rs:75-80`);
  - votes freeze balances or assets (`lib.rs:254-259,277-297`);
  - every community account is inducted into `KreivoCollective` at rank 0,
    or higher (`communities-manager/src/lib.rs:310-316`).

### How a community is created

- `pallet_communities::create` is closed in production:
  `CreateOrigin = EnsureNever` (`KR/config/communities/mod.rs:40-41`).
- Creation goes through `CommunitiesManager::register`
  (`communities-manager/src/lib.rs:221-239`), with
  `RegisterOrigin = Root (free) | EnsureSignedPays<CommunityDepositAmount = UNITS/2, TreasuryAccount>`
  (`mod.rs:23,34-35,71`).
  - **The deposit is a payment to the treasury, not a hold:** it is a
    `transfer` (`FC/communities/src/functions.rs:63-70`) and is never
    refunded.
- Genesis creates community 1, "root" (`KR/genesis_config_presets.rs:65-68`).

### The gas tank and the feeless paths

- `ChargeTransaction = ChargeGasTxPayment<Runtime, ChargeAssetTxPayment<Runtime>>`,
  inside `SkipCheckIfFeeless` (`KR/lib.rs:93,98-112`).
- **The tank belongs to a membership NFT the signer owns,** not to the
  community account. `NonFungibleGasTank::check_available_gas` iterates
  `F::owned(who)` (`FC/../fc-traits-gas-tank-2.3.1/src/impl_nonfungibles.rs:90-121`),
  and the selector requires the membership not to have expired
  (`KR/config/currency.rs:165-182`).
- **With gas available, the transaction pays no fee at all.** It skips
  length, base and tip, and burns `call_weight` from a weight quota
  (`FC/gas-transaction-payment/src/extensions.rs:96-99,183-190`).
  - A 160 KB proof would therefore travel free, its length uncharged.
  - The quota is weight that governance mints into memberships
    (`communities-manager/src/lib.rs:241-266`). Nobody's balance pays it.
- `SkipCheckIfFeeless` skips the whole charge when a call's
  `#[pallet::feeless_if]` holds (`SDK pallet-skip-feeless-payment-23.0.0/src/lib.rs:161-162`).

### Other pallets that depend on communities

(`grep` over `KR`)

| Where | What it uses |
|---|---|
| `KR/lib.rs:85`, `KR/config/system.rs:89` | `Address = MultiAddress<AccountId, CommunityId>`: `MultiAddress::Index(id)` resolves to the community account |
| `KR/config/system.rs:229-234,280-284` | pass: a community account registers pass accounts for free (`SkipConsideration`, `AsSignedByCommunity`) |
| `KR/config/payments.rs:34-37,61` | payments: sender origin `AsSignedByCommunity`; community accounts detected by the sub-account prefix |
| `KR/config/listings_orders.rs:26-58` | listings: `MerchantId = CommunityId`; inventories owned by community accounts |
| `KR/config/contracts/mod.rs:77-193` | contracts / kreivo-apis: `Group = CommunityId`, app instantiation as the community account, community-administered assets |
| `KR/config/utilities.rs:117` | scheduler: `ScheduleOrigin` includes `AsSignedByCommunity` |
| `KR/xcm_config/communities.rs:14-26`, `KR/xcm_config.rs:85,369,378` | XCM: `Plurality{Index(id)}` ↔ the community account and origin |
| `KR/config/currency.rs:166-182` | gas tank over the `CommunityMemberships` collections |
| `KR/migrations.rs:423-517` | the scheduler-alarm migration covers community referenda |

### On-chain state a replacement would have to migrate

- `Communities`: `Info`, `CommunityIdFor`, `CommunityDecisionMethod`,
  `CommunityVotes`, `CommunityVoteLocks`, and the freezes behind the locks.
- `CommunityMemberships` (nfts Instance2): every collection, item and
  attribute (rank, gas, expiry, the in-progress gas marker).
- `CommunityTracks` and `CommunityReferenda`: tracks, referenda in flight,
  and scheduler alarms.
- `KreivoCollective` ranks of community accounts.
- **Balances, assets, NFTs, listings and contracts held by community accounts.**
  - These can stay where they are only if the account derivation is kept:
    `kv/cmtys` + u16.
  - So a replacement must keep the legacy derivation for existing ids. Any
    new derivation applies to new spaces only.
- External references: `MultiAddress::Index(u16)` in wallets, XCM
  `Plurality{Index}` from other chains, listings' merchant ids.

### The owner's unmerged branch, `FCp`, already moves toward spaces

- Memberships move to built-in storage: `Members: (CommunityId, AccountId) → MemberRecord { rank, nonce, status, role }`
  with roles `Admin | Manager | Member` (`FCp/pallets/communities/src/lib.rs:365-374`,
  `types.rs:89-114`).
- There are per-community Merkle membership roots and sub-roots, set by the
  admin (`lib.rs:311-326,700-738`).
- **An `AnonymousMembership` transaction extension:**
  - it verifies a proof against the root through a generic
    `fc_traits_proof_verifier::ProofVerifier`
    (`FCp/traits/proof-verifier/src/lib.rs:31-46`);
  - it sets a community origin with an `AnonymousMember` subset;
  - it derives a nullifier from the proof leaf and the call hash, stored
    in `UsedNullifiers` (`FCp/pallets/communities/src/extensions.rs:142-310`);
  - the MVP verifier is a plain Merkle path, so it is pseudonymous, not
    zero-knowledge (`verifier.rs:55-107`).
- A per-community gas `Budget` with `set_budget` (`lib.rs:375-378,740-765`,
  `functions.rs:260-290`). It is not yet wired to a fee path.
- **This is the natural host for the "anonymous node" stage,** and its
  `ProofVerifier` trait is the right seam for the VOS statement verifier
  too.

## 2. pallet-pass

- **What it does:**
  - an account is derived from a 32-byte `HashedUserId` by
    `AddressGenerator`. Kreivo uses `()`, which hashes `0^32 ‖ user_id`
    (`FC/pass/src/types.rs:45-62`, `KR/config/system.rs:278`);
  - devices are registered on it (`Devices`, `lib.rs:144-154`), each by an
    attestation checked by a pluggable `Authenticator` (`lib.rs:390-430`);
  - registration takes a registrar consideration (a hold)
    (`lib.rs:226-243`);
  - `add_session_key` maps an ephemeral account to the pass account for up
    to `MaxSessionDuration` (15 min in Kreivo) (`lib.rs:266-315`,
    `KR/config/system.rs:316`).
- **How it dispatches:**
  - `PassAuthenticate` is a transaction extension, the first in Kreivo's
    pipeline (`KR/lib.rs:101`);
  - in a general (bare plus extensions) transaction it carries
    `{device_id, credential}`;
  - it verifies the credential against the inherited implication (the call
    plus the later extensions), and on success replaces the origin with
    `Signed(pass_account)` (`FC/pass/src/extensions.rs:98-140`);
  - so `CheckNonce` and the fee extensions then apply to the pass account
    as to any signer;
  - a session key's signed transaction is also mapped to its pass account
    (`extensions.rs:119-133`);
  - the credentials carry a challenge: a block hash at most 30 min old
    (`KR/config/system.rs:184-209`).
- **Authenticators:**
  - Kreivo wires `WebAuthn` (passkeys) and `SubstrateKey`
    (`KR/config/system.rs:210-225`);
  - `SubstrateKey` takes `MultiSignature`, that is ed25519, sr25519 or
    ecdsa, over `context ‖ challenge ‖ authority`
    (`pass-authenticators-substrate-keys-1.2.0/src/lib.rs:84-120`,
    `signed_message.rs:4-34`). **A VOS node's ed25519 key can be a pass
    device today with no new code;**
  - **an SSH (ed25519, SSHSIG, RFC 8709) authenticator already exists** in
    `PA/authenticators/ssh` (`lib.rs:1-95`, `ssh.rs`). It is version 0.1.0,
    not on crates.io, and not wired into Kreivo. Adding it is a crates.io
    publish plus one line in `composite_authenticator!`;
  - Ethereum, Bitcoin, Solana and Nostr authenticators are in `PA` too.
- **Cost per transaction:**
  - `authenticate()` is 1.54 ms of ref_time, 3 reads and 1 write
    (`KR/weights/pallet_pass.rs:65-73`), plus the authenticator's
    verification: about 36 µs for sr25519 or ed25519
    (`KR/weights/pass_substrate_keys.rs:71-85`);
  - that is about 0.0005 UNITS [est], negligible against a proof's length
    fee;
  - plus about 150 B of credential.
- **Scoping a pass account:**
  - Kreivo's 2.3.1 has no per-device scoping;
  - `FCm` adds per-device call filters, `Admin | Pallets | Calls | Spend`,
    with no escalation (`FCm/pallets/pass/src/filter.rs:1-45`). Under 3.x a
    node device could be limited to `Calls{(spaces, anchor), (spaces, submit)}`;
  - "act as space X's authority" itself is not a pass concept. The pass
    account is just an `AccountId` that the spaces pallet lists as an
    authority.
- **The catch:** if one pass account is shared by several nodes, they share
  one nonce and race, the same problem as decision 12(b). So it should be
  one pass account per node.

## 3. The shape of a spaces pallet

The full design is `stage/spaces-pallet-design.md`.

- **What it keeps from communities:**
  - the sovereign account;
  - an admin or controller origin;
  - `dispatch_as_sovereign`;
  - later: the community origin, tracks, membership and voting.
- **What it adds:**
  - the VOS `SpaceId` from the genesis;
  - the clock;
  - authorities;
  - anchors under pin D's rule;
  - statements under pin F's `judge`;
  - the Record handler;
  - deposits and fees paid by the sovereign account.
- **Sovereign account:** `PalletId(*b"kv/space").into_sub_account_truncating(space_id)`,
  which is `"modl" ‖ "kv/space" ‖ space_id[0..20]`.
  - It is derivable before registration, so a founder can fund it first,
    and the registration deposit is held on it.
  - Collisions: a 2^160 second preimage, or a 2^80 birthday among one's own
    spaces. Registration refuses an account already mapped.
- **How a node-signed transaction charges the sovereign account:**

  | Option | How | Scope | Risk |
  |---|---|---|---|
  | **(B) `ChargeSpaceFee` wrapper extension** (recommended) | wraps `ChargeTransaction` exactly as `ChargeGasTxPayment` does (`KR/lib.rs:93`); when the signer is an authority of the space the call names, `withdraw_fee` and `correct_and_deposit_fee` run on the sovereign account; otherwise the inner extension runs | about 200 lines of runtime-wide code; transparent encoding (same `IDENTIFIER` and data as the inner extension, as the gas wrapper does: `extensions.rs:72`), so no client change | the extension is on every transaction's path; it needs its own review |
  | (A′) pallet-only | `#[pallet::feeless_if(signer is authority ∧ sovereign can pay)]`, then the pallet charges `LengthToFee(encoded call + envelope bound) + WeightToFee` from the sovereign account in dispatch | no runtime change | approximate length; concurrent pending transactions can overdraw, and the extras are included free |
  | (A) node pays, sovereign tops it up | each node account funded from the sovereign account | none | float in N accounts; key compromise drains them |
  | (D) pass | pass account per node | config only | fees still the node's unless combined with (B) |
  | proxy (`pallet_proxy`, index 44) | node as proxy of the sovereign account | none | **the proxy pays its own fee**; no help |

- **Node accounts need `providers > 0`, or `CheckNonce` refuses them with
  `Payment`** (`SDK frame-system-48.0.0/src/extensions/check_nonce.rs:74-78`).
  So the pallet calls `inc_providers` on add and `dec_providers` on removal,
  as pass does in `create_account` (`FC/pass/src/lib.rs:351-363`). Nodes
  then hold no balance.
- **Incremental paths:**

  | Path | Effort (Kreivo side) [est] | Risk |
  |---|---|---|
  | **S0: a new `pallet-spaces` now,** its controller an `AccountId` (which can be a community's account, so community governance drives a space with no new code); communities untouched | 3–5 wk, plus 1 wk for (B) | low; isolated |
  | Extend pallet-communities now | 5–8 wk | frame-contrib is crates.io-only and forbids git dependencies (decision 9), so the verifier must sit behind a trait anyway; it touches the many dependents above |
  | Full replacement with migration now | 8–14 wk | high: funds keyed by `kv/cmtys` accounts, referenda in flight, NFT memberships, XCM pluralities, `MultiAddress::Index` |

  **Recommended:** S0 in Kreivo `pallets/`; then fold the communities
  features in (S2), keeping the legacy `kv/cmtys` derivation for existing
  ids; then move it to frame-contrib, with the verifier behind
  `ProofVerifier` and its implementation in Kreivo's runtime.

## 4. Anonymous node authentication by proof

- **The mechanism exists in the SDK:**
  - `frame_system::AuthorizeCall` (`SDK frame-system-48.0.0/src/extensions/authorize_call.rs:51,68-84`)
    runs a call's `#[pallet::authorize]` closure (`#[pallet::weight_of_authorize]`
    gives its weight);
  - on success the origin becomes `Authorized`;
  - **Kreivo's pipeline lacks it** (`KR/lib.rs:98-112`), so adding it is a
    runtime-wide change and a transaction-version bump;
  - an extension-based alternative is already proven: `FCp`'s
    `AnonymousMembership`.
- **Fees:**
  - a non-signed origin pays nothing at the transaction layer
    (`SDK pallet-transaction-payment-49.0.0/src/lib.rs:1018-1019`);
  - the space's sovereign account must pay in dispatch, which fits the
    owner's model.
- **DoS:**
  - every pool validation verifies the proof, at about 4 ms for a 160 KB
    statement STARK [measured, spike 6c], on every revalidation, with no fee
    for a refused proof;
  - the bounds: `provides` tags `(space, kind, w)` (at most one per window),
    a per-space and per-window cap, priority, and `longevity` of a window;
  - attackers can still burn collator CPU with invalid proofs, so the light
    proof matters.
- **The proof:**
  - "I hold a key in the space's authority set R_auth, once per
    (space, scope)", with a nullifier;
  - R_auth is a pallet-held root, which the controller updates alongside
    the authorities map, or committed in S_w;
  - slice 7's credential AIR (Poseidon2) is the planned light proof;
  - a Merkle-path verifier works now but is pseudonymous (`FCp`'s MVP).
- **What it buys:** the space id is public and the sovereign account pays,
  so anonymity hides only *which* of the space's nodes acted. It is low
  value for anchors.
- **Verdict:** design the hook (R_auth, the authorize call shape) and build
  it after slice 7's credential AIR. **It is not in slice 6.**

## 5. What this changes in our plan

- **6.16:** no pallet code (owner, 2026-10-19). It becomes:
  - the vendored verifier crates with a sync check;
  - the handoff design;
  - the conformance vectors that the Kreivo teammate's pallet must pass.
- **The Kreivo `vos-statements` branch** becomes the teammate's.
- **Pin D:**
  - the controller is an `AccountId`;
  - the space gains a sovereign account, and authorities (sr25519 accounts,
    each paired with an ed25519 anchor key);
  - equivocation is handled inside `anchor`.
- **6.17:**
  - weights and benchmarks move to the teammate;
  - VOS supplies the fixtures and the in-Wasm sweep as a benchmark helper;
  - decision 11 becomes (c), paid by the sovereign account.
- **6.17b:**
  - one sr25519 key per node (decision 12(a)), registered as an authority;
  - no per-node funding;
  - the client builds calls from the pinned indices and encodings, not the
    pallet's metadata (there is none yet), and the envelope from Kreivo's
    live metadata;
  - it is tested against a mock of the interface.
- **6.21:** on-chain end to end is blocked on the teammate's delivery. It
  becomes conditional, or a mock end to end.
- **Decisions 10–12:** folded into the design's defaults. What remains for
  the owner is listed in the design's §13.
