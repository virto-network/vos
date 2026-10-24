# A VOS statement verifier pallet for Kreivo

**Superseded in parts.** The built venue, slice 6's plan
(`../../slice-6-on-chain.md`) and `../../spaces-pallet.md` (the pallet's
handoff design, which replaces this note's pallet) supersede parts of this
note. **Who builds what:** the pallet, `pallet-spaces`, is the Kreivo
teammate's, built from `spaces-pallet.md`; VOS ships the design, the
verifier kit with its sync check (`pvm/proof/kit`, `just check-kit`), the
calls, the `Transport` trait, `KreivoVenue`, a mock of the pallet and the
conformance vectors G1–G18 (`node/venue/conformance/spaces.json`, written
by the mock through `just conformance`). The node's chain client is not
VOS's to build now: the transport is a port of master's substrate
extension (sube over smoldot) onto vos-core's extension host once that
host exists, after the slices (`spaces-pallet.md` §9.1); `KreivoVenue`
runs against the mock until then, and the live Kreivo leg waits on both
the pallet and the port. Where this note and the design differ:
1. **§1, Kreivo's facts** (e4b2af3, stable2603, velocity 12, 500 ms
   blocks): Kreivo master `87f8728` runs stable2606-2 from crates.io,
   velocity 3 (2 s blocks) with block bundling; one core gives about
   666 ms and 3.33 MiB a block.
2. **§2, the interface:** the built `Statement` is `{ format: u32, program:
   ProgramId ([u32; 8]), space, public_args, output, roots }`, with no
   `shape_class`; `io_digest` is the io-hash; the id is
   `H("vos/statement/v1" ‖ program ‖ space ‖ io_hash)`, without the
   format.
3. **§2, `RootKind { SpaceWindow = 0, Carried = 1 }`:** `{ Space = 0 }`,
   1 reserved for Poseidon2; `Carried` retired by the carried commitment
   (the owner's decision 6, 2026-10-19).
4. **§1 and §2, the check order's "the program taken from the proof"
   (modesto's):** the program id is the venue's pin, never the caller's or
   the proof's.
5. **§3, "Programs are tied to one format, since the id includes the
   channel", and §7's migration by new ids:** the program id covers the
   segment format, not the final one; a venue accepts final formats as a
   set.
6. **§4, the clock "RelaychainData's block number / WindowLength" and
   `AnchorGrace`:** windows are Unix time from the space's genesis
   (decision 2); `MaxRootAge` alone.
7. **§4, "chain-bound attests read the agent root at the last window
   cut":** they read to the space root.
8. **§6, the 250 ms weight placeholder and `MaxProofLen = 512 KiB`:**
   3.99 ms measured unmasked on a laptop (×1.3–1.4 masked [est]);
   `MaxProofLen` 256 KiB; a proof's length counts as proof_size, so about
   20 a block on one core, and length sets the fee (about 0.43 UNITS a
   proof).
9. **§7, `PROOF_FORMAT_VERSION` 24/25 as a cargo feature:** formats are
   chosen at run time from the registry.
10. **§8, the toolchain and pin ("vos-core pins stwo e1286720"):** the pin
    is olanod/stwo `c3ec9813` (the kit carries VOS's); the stack builds on Kreivo's stable 1.94.1
    for `wasm32v1-none` with no change and adds 75.7 KiB compressed
    [measured, `../slice-6/spike6c-kreivo.md`].
11. **§9's table, "Blake2s: software in Wasm":** Blake2b-256; JAM serves no
    hash.
12. **§10 Q11, "P2: the Clerk handler (slice 6)":** the Clerk follows
    slice 6.
13. **The home, frame-contrib:** `pallet-spaces` in Kreivo, the verifier
    vendored with a sync check (decision 9); frame-contrib later.
14. **§3, the space registry (`register_space(space_id, binding,
    controller, anchor_keys)`, anchor keys signing directly) and §6's
    fees:** a space registered from its genesis with a sovereign account
    that pays; an authorities map of the nodes' sr25519 accounts paired
    with ed25519 anchor keys; a refundable deposit on `submit`, released on
    acceptance or a repeat and forfeited on any other refusal, beside the
    normal length and weight fees, within a spend budget per window (a
    submit holds at most the deposit and a fee's bound, 1.5 UNIT at the
    design's suggested values); a migration to another venue, one-way,
    set by the controller (decisions 11, 12; `spaces-pallet.md` §§5–8).
15. **§5's `Verified` expiry for every statement:** a rootless statement's
    `Seen` entry never expires.

Design note for slice 5 planning, 2026-10-16. Read-only research: nothing was built or changed.

**Paths:**
- **D** = `vos/.worktrees/vos-core/docs/design`; **V** = `vos/.worktrees/vos-core`.
- `D/clerk-across-spaces.md` is the Clerk's draft, renamed at slice 6's 6.0d; the line numbers
  here are the draft's on 2026-10-16, its step numbers 5.x (now C.x).
- **K** = `~/src/virto/kreivo` (e4b2af3, stable2603); **M** = `~/src/virto/modesto` (3df2915).
- **F** = `~/src/virto/frame-contrib` (`feat/private-communities`). Kreivo pins 0b576914 (`K/Cargo.lock:2464`), absent here.
- **P** = `~/src/gh/polkadot-sdk` (master eb11ef2b85, newer than stable2603: re-check its limits there).
- `audit.md` is this directory's width audit.

## 0. The recommendation

- **One pallet, `pallet-vos-statements`,** in three parts:
  - a registry of spaces, each with an anchor chain;
  - a registry of formats and programs, changed by governance after a delay;
  - `submit(statement, proof)`, which verifies one masked final proof and routes the `Statement` to a compiled
    handler chosen by program id in storage.
- **Public data stays opaque.** The pallet authenticates the program, the format and the roots; handlers decode the
  rest.
- **Fail-closed:** unknown formats, programs, handlers and root kinds are refused, a build without the verifier
  rejects every proof, and the pool never verifies.
- **The JAM verifier agent shares** the verifier core and the `Statement` crate; only the host differs.

## 1. What exists

**Kreivo:**
- **Blocks:** 2 s of ref_time and a 5 MiB PoV (`K/runtime/kreivo/src/config/system.rs:27-31`), and a 5 MiB length,
  75% of it normal (`system.rs:40-41`; `P/cumulus/parachains/common/src/lib.rs:106`). Velocity 12 on Kusama gives
  500 ms blocks (`K/runtime/runtime-constants/src/lib.rs:68-80`), so authoring time binds first.
- **Fees:** `ChargeGasTxPayment`, with a feeless skip (`K/runtime/kreivo/src/lib.rs:95`, `:99-109`). The length fee
  is 10 MILLICENTS a byte (`config/currency.rs:51-59`), which is UNITS/300,000 on Kusama
  (`runtime-constants/src/lib.rs:31-49`).
- **Governance:** `KreivoReferenda` over a ranked collective (`config/collective/governance.rs:9-28`). It has five
  tracks, Root's with a 4-day decision at a 90% floor (`config/collective/tracks.rs:37-140`), and custom origins
  (`config/governance/origins.rs:29-40`). There is no sudo (`lib.rs:221-345`).
- **Communities:** `CommunityId: u16` (`K/common/src/lib.rs:16`).
  - Accounts are `kv/cmtys` sub-accounts (`config/communities/mod.rs:20`; `system.rs:63-77`, `:195-199`).
  - A community is created by Root, or by anyone with a deposit (`mod.rs:34-35`, `:102`).
  - It acts through its own referenda (`config/communities/governance.rs:131-153`), as `EnsureCommunity` or
    `AsSignedByCommunity` (`F/pallets/communities/src/origin.rs:24-57`, `:229-256`).
- **Also:** pass accounts (`system.rs:181-190`, `:240-292`), an ink! chain extension
  (`K/apis/src/contract/chain_extension.rs:11-12`), and `HoldConsideration` deposits (`config/utilities.rs:99-116`) at
  1/100 of Kusama's (`K/runtime/kreivo/src/constants.rs:28-30`).

**Prior art: modesto `crates/settlement`.**
- **Measured:**
  - a flat zkpvm proof verifies in 10.9–14.9 ms (median) in wasmtime, with an ~8 MiB peak, 2 MiB or less of it
    dynamic;
  - proofs are 467–497 KiB at STANDARD and 795–844 KiB at MOBILE, and a tampered one is refused
    (`M/docs/verifier-spike.md:9-19`, `:51-59`, `:71-74`);
  - time is shape-independent (`:61-66`), PoV binds first (`:100-107`), and STANDARD wins (`:109-119`).

  These were Add64 ladders on the format-8 AIR, not our final proof.
- **Size:** the verifier adds 2.17 MiB uncompressed and 0.264 MiB compressed (`M/docs/PLAN.md:746-757`). The
  production runtime is 2.67 MB compact and 0.56 MB compressed, and a real proof settled to relay finality
  (`M/docs/production-roadmap.md:17-20`).
- **The check order it learned** (`M/docs/settlement-binding.md:124-149`; `M/crates/settlement/src/zk.rs:58-108`):
  1. a size cap;
  2. a strict decode, since postcard ignores trailing bytes (`zk.rs:64-73`);
  3. panic guards, since a crafted proof panicked the runtime (`:74-77`);
  4. the program taken from the proof, not the caller (`:78-83`);
  5. the STARK, under a PCS floor;
  6. the io-hash, trusted only after verification (`:84-107`).
- **Also learned:**
  - the io-hash is reimplemented over `sp_io` and pinned by golden vectors from vos (`settlement-binding.md:90-113`;
    `M/crates/settlement/src/binding.rs:31-61`);
  - a nonce sits both in the proof and on chain (`settlement-binding.md:115-122`);
  - the pool does cheap lookups plus a dedup tag (`M/crates/settlement/src/lib.rs:455-472`, `:556`);
  - a build without the verifier uses `RejectVerifier` (`M/crates/stf-core/src/lib.rs:98-112`);
  - changes wait out a 28,800-block delay, except an immediate pause (`M/docs/governance.md:28-59`).
- **Also learned, linking:** stwo's `starknet-ff` dragged `getrandom/js`, `wasm-bindgen` and `std` into the runtime
  (`M/docs/PLAN.md:717-726`; `M/docs/f1b-feasibility.md:6-17`, `:101-109`). A `poseidon252` gate in the owner's Stwo
  fork fixed it (`M/Cargo.toml:83-85`), on stable 1.94.1 (`M/rust-toolchain.toml:2`).
- **Reusable:** the check order and guards, the strict decode, the golden and differential vectors, the fork's
  gating, the size gates, and delay plus pause.
- **Not reusable:** the frameless runtime, running the program on chain (`settlement-binding.md:61-73`; our output is
  public), the flat verifier, and the 2-of-3 envelope.

**Prior art: frame-contrib.**
- **`pallet-zk`** (d8c6c32) shows what to avoid: caller-chosen ids (`pallets/zk/src/lib.rs:86`), open registration
  (`:128-134`), a verify weighted as one read (`:151`), and a stub backend (`stwo.rs:272-274`).
- **`ProofVerifier`** (`F/traits/proof-verifier/src/lib.rs:31-46`) backs anonymous membership. It verifies in
  `validate` (`F/pallets/communities/src/extensions.rs:132`) under a 50M placeholder weight (`:103-106`), with scoped
  nullifiers (`F/pallets/communities/src/lib.rs:327-337`).

**polkadot-sdk limits:**
- **Code and PoV:** code is 3 MiB, decompressing to at most 4× (`P/polkadot/primitives/src/v9/mod.rs:446`;
  `P/polkadot/node/primitives/src/lib.rs:77`), and the relay PoV is 10 MiB (`v9/mod.rs:463`).
- **Execution:** 2 s to back and 12 s to approve (`P/polkadot/primitives/src/v9/executor_params.rs:56-58`), with a
  128 MiB heap (`P/polkadot/node/core/pvf/common/src/executor_interface.rs:46-47`;
  `P/substrate/client/executor/common/src/wasm_runtime.rs:26-30`).
- **Caps:** preimages are 4 MiB (`P/substrate/frame/preimage/src/lib.rs:116`), and length is checked per class
  (`P/substrate/frame/system/src/extensions/check_weight.rs:76-90`).
- **Build target:** `wasm32v1-none`, with no `std` at all (`P/substrate/utils/wasm-builder/src/wasm_project.rs:867-869`,
  `:939-954`).

## 2. The interface (question 1)

```rust
pub type ProgramId = [u8; 32];   // 5.1's id: transpiler, ProgramHash, shape, channel, roots
pub type SpaceId = [u8; 32];     // hash of the space's creation record (slice 6, 5.2)
pub type WindowIndex = u64;      // §4's window clock
pub type HandlerId = u8;         // 0 = Record, built in
#[repr(u8)] pub enum RootKind { SpaceWindow = 0, Carried = 1 }      // shared with VOS
pub struct RootRead { pub kind: RootKind, pub space: SpaceId, pub window: WindowIndex, pub root: [u8; 32] }
pub struct Statement<A: Get<u32>, O: Get<u32>, R: Get<u32>> {
    pub program_id: ProgramId, pub format: u16, pub shape_class: u8,
    pub public_args: BoundedVec<u8, A>,   // opaque: the handler decodes it
    pub output: BoundedVec<u8, O>,        // opaque: the handler decodes it
    pub roots: BoundedVec<RootRead, R>,
}
pub struct FinalPublic { pub program_id: ProgramId, pub shape_class: u8, pub io_digest: [u8; 32] }
pub trait FinalVerifier {                  // runtime-provided; the default is `RejectVerifier`
    fn supports(format: u16) -> bool;
    /// Never panics, and trusts nothing read from the proof until it verifies.
    fn verify(format: u16, proof: &[u8], public: &FinalPublic) -> Result<(), VerifyError>;
}
pub enum VerifyError { Oversize, Malformed, Unsupported, BelowFloor, Invalid }
pub struct Verified<'a> {
    pub id: [u8; 32], pub program_id: ProgramId, pub public_args: &'a [u8], pub output: &'a [u8],
    pub as_of: &'a [(SpaceId, WindowIndex)],   // anchored roots, authenticated by the pallet
    pub carried: &'a [[u8; 32]],               // `Carried` roots, which the handler must check
}
pub trait StatementHandler { const ID: HandlerId; fn max_weight() -> Weight;
    fn handle(s: &Verified) -> Result<Weight, DispatchError>; }      // returns the actual weight
pub trait StatementRouter {                    // `type Handlers = (Record, ClerkSettle, ..)`, by tuple
    fn max_weight() -> Weight;                 // the largest over handlers, refunded after
    fn route(id: HandlerId, s: &Verified) -> Result<Weight, DispatchError>; }  // unknown id: Err
#[pallet::call_index(0)]
#[pallet::weight(T::WeightInfo::submit(proof.len() as u32, statement.roots.len() as u32)
    .saturating_add(T::Handlers::max_weight()))]
pub fn submit(origin: OriginFor<T>, statement: Box<StatementOf<T>>,
              proof: BoundedVec<u8, T::MaxProofLen>) -> DispatchResultWithPostInfo;
```

**The check order in `submit` (normative, cheapest first):**
1. `ensure_signed`. The signer only pays, and no effect depends on who submits, so front-running gains nothing.
2. The pause flags (global, per format, per program, per space).
3. The format is accepted and `T::Verifier::supports` it.
4. The program is active, its format matches, and its pinned set holds `shape_class`.
5. The roots:
   - a `SpaceWindow` root needs a registered, unsuspended space, `Anchors[(space, window)] == root`, and an age within
     `max_root_age`;
   - `Carried` roots only where the spec allows them;
   - at least one fresh anchored root, unless the program is `rootless`.
6. `io_digest = vos_statement::io_digest(args, output, roots)` and
   `id = H("vos/statement/v1" ‖ program_id ‖ format ‖ shape_class ‖ io_digest)`. A known `id` is refused.
7. `T::Verifier::verify(format, &proof, &FinalPublic { .. })`.
8. Insert `Verified[id]`, then `route(program.handler, ..)`. Calls are transactional, so an `Err` undoes the insert.
9. Emit `StatementVerified { id, program_id, as_of, output }` and refund unused handler weight. A failure pays its full
   weight.

**Errors** (none leaves state behind): `ProofTooLarge`, `UnsupportedFormat`, `FormatNotAccepted`, `Paused`;
`UnknownProgram`, `ProgramInactive`, `FormatMismatch`, `ShapeClassNotAllowed`; `UnknownRootKind`, `SpaceUnknown`,
`SpaceSuspended`, `RootNotAnchored`, `RootStale`, `NoFreshRoot`, `CarriedNotAllowed`; `AlreadyVerified`,
`MalformedProof`, `InvalidProof`; and `HandlerMissing`, or the handler's own error.

**Handlers:**
- **`Record`** keeps only `Verified`, read through events, queries or a chain-extension call.
- **Later:** Clerk settlement (slice 6), credentials (§10.10) and space votes on referenda.
- **Every handler** is deterministic, independent of the submitter and weight-bounded, and checks the spaces its
  output names against `as_of`.

## 3. Programs, spaces, who decides (question 2)

- **Formats** are compiled in. `Formats: u16 -> { from, until }` is set by `ProgramsOrigin` after
  `ProgramChangeDelay`, and a format not compiled in is refused.
- **Programs:** `Programs: ProgramId -> { format, shape_classes: u16, handler, max_root_age, allows_carried, rootless,
  owner: Governance | Space(SpaceId), active_from, active_until }`.
  - The delay is lazy (`active_from = now + delay`; identity §12, `D/identity-and-authority.md:446-447`).
  - `ProgramsOrigin` binds programs to any handler. A space's controller binds only to `Record`, with a deposit.
- **Ids are registered, not caller-chosen.**
  - They change per transpiler and build (`D/slice-5-proving.md:168-176`), so a rebuild is a registration.
  - The final proof binds the id (`:231-235`), so no key is kept per program, unlike modesto's per-shape allowlist
    (`M/docs/settlement-binding.md:19-24`).
- **Origins:** `ProgramsOrigin = EitherOf<EnsureRoot, VirtoCommunity>`, the root space as a DAO
  (`D/identity-and-authority.md:448-455`). `EmergencyOrigin` sits on a short track like Black Hole's
  (`tracks.rs:122-139`); it pauses at once, and unpausing waits out the delay.
- **Spaces:** `register_space(space_id, binding, controller, anchor_keys)` holds a deposit.
  - **The controller** (a community account, a multisig or a pass account) rotates keys and deregisters. The name is
    freed after the deposit's delay (`:459-461`).
  - **The anchor keys** are the space's ed25519 node keys signing directly, since anchors cannot wait for referenda.
  - **`binding`** means "signed both ways" (`D/clerk-across-spaces.md:147-148`): the creation record hashes to `space_id`,
    and a node key it names signs `(Kreivo genesis, controller)`.
- **Identity §5 holds** (`D/identity-and-authority.md:133-144`): every input is a chain-authenticated signed origin or
  a proof. Collators can delay inputs, never forge them.

## 4. The roots a statement read (question 3)

- **Anchors:** `anchor(space, window, root)`, signed by an anchor key.
  - The window must exceed the space's last and lie in `[now - AnchorGrace, now - 1]`; gaps are allowed.
  - A second root for one window records `Equivocation` and suspends the space.
  - This is identity §11's root chain (`D/identity-and-authority.md:402-434`): it gives ordering and
    non-equivocation, and proofs give integrity (`:414-417`).
- **Roots carried only in outputs** would be bare claims, with no order, space or freshness, so only anchors
  authenticate roots.
- **The clock:** `RelaychainData`'s block number divided by `WindowLength` (`config/governance/mod.rs:53`). The
  cadence is fixed, so it leaks no activity (`identity-and-authority.md:412-413`).
- **Freshness:**
  - the newest root must be within `max_root_age`, capped by a global `MaxRootAge`, which is also the horizon for
    pruning anchors;
  - the older root of a two-anchor read (`D/slice-5-proving.md:118-120`) is `Carried`, and its handler checks it
    against its own state (`D/clerk-across-spaces.md:187-194`, `:220-222`).
- **"As of W":** 5.2 reads the latest complete root W ≤ V (`D/slice-5-proving.md:209-214`), which no anchor need
  cover.
  - **Proposal:** chain-bound attests read the agent root at the last window cut, which that window's space root
    covers. It stays deterministic, since the cut is replicated.
  - The statement then means "as of window w of S", which is `as_of`.
- **Space binding:** the space root's preimage should commit to `(space_id, window)`, so the proof binds both. As hints,
  the keyed lookup is still sound, and a copied root only lets a space lie about itself.

## 5. Replay and ordering (question 4)

- **Dedup:** `Verified: id -> { program, at, expires_window }` refuses replays. `on_idle` prunes an entry, within a
  bound, once its newest root is stale; a later replay fails `RootStale`, so the set stays bounded.
- **Ordering lives in handlers.**
  - The Clerk binds windows to pair sequence numbers (`D/clerk-across-spaces.md:176-181`).
  - It keeps the last settled anchor and the rows commitment per (A, B, currency), and accepts only a statement
    starting there (`:187-194`, `:220-228`).
  - A statement may span to any later anchor (`:299`).
- **Rootless programs** manage replay in their handler through `ScopedNullifiers::consume(scope, n)`, scoped by
  program and handler, never global (`D/identity-and-authority.md:303-305`).
- **The per-space sequence** is the anchor chain.
- **The pool:** nothing verifies in `validate`. An optional extension provides `("vos-stmt", id)` (modesto's tag,
  `M/crates/settlement/src/lib.rs:463-472`), and gas tanks (`lib.rs:95`) do not sponsor `submit` or `anchor` by default.

## 6. Weights, fees, limits (question 5)

- **Weight, a placeholder until spike 4a:** `Weight::from_parts(250_000_000_000, 8 * 1024)` (250 ms), plus reads per
  root, plus the handler maximum.
  - **Basis:** the final proof is projected at 300–400 columns, 100–300 KB and 60–150M JAM gas (`audit.md:517-570`).
    Modesto's flat proofs took 11–15 ms in Wasm, so 250 ms is deliberately high.
  - **Then:** spike 4a's Wasm figure × 1.5, then a FRAME benchmark.
  - **Velocity 12** also needs `MaxSubmitsPerBlock`, 2 until measured.
- **Size:** `MaxProofLen = 512 KiB`, checked before decode. A 300 KB proof is 6% of the 5 MiB PoV and 8% of the
  3.75 MiB normal length, entering the PoV once; weight binds first.
- **Preimage path:** not below about 1 MiB. It pays the bytes in two PoVs plus a deposit, under a 4 MiB cap. JAM uses
  preimages (`D/clerk-across-spaces.md:215-219`); Kreivo stays inline.
- **Fees:** about 1.0 UNITS of length fee per 300 KB proof on Kusama (0.34 per 100 KB), plus weight. Never feeless
  (`K/runtime/kreivo/src/lib.rs:108`).
- **Deposits:** held for spaces (like a community's UNITS/2, `config/communities/mod.rs:23`) and space-owned programs.
  Anchors and `Verified` are pruned, so they pay fees only. The space pays for its anchors and statements
  (`D/identity-and-authority.md:514-522`).

## 7. Upgrades (question 6)

- **A new format** needs a runtime upgrade (the Root track, a 4-day decision, `tracks.rs:37-58`), then `Formats`.
- **Programs are tied to one format,** since the id includes the channel (`D/slice-5-proving.md:168-176`). Migration
  registers new ids, overlaps them with the old, then sets `active_until` on the old.
- **Retiring a format** waits `ProgramChangeDelay` (7 days proposed; `identity-and-authority.md:446-447`). A soundness
  bug pauses the format at once.
- **The core must choose the format at run time.**
  - The channel, and with it `PROOF_FORMAT_VERSION` 24 or 25, is a cargo feature (`V/pvm/proof/src/proof.rs:180-187`;
    `V/pvm/proof/verifier/Cargo.toml:12`).
  - Feature unification stops one runtime from linking two formats, so the core must dispatch on `format` over its
    generic `MerkleChannel`.
- **Production compiles masked final formats only,** since only masked proofs leave the prover role
  (`D/slice-5-proving.md:284-285`). Test formats sit behind a feature.

## 8. The verifier crate in a runtime (question 7)

- **No `std`:**
  - stwo with `default-features = false`, from the fork with its `poseidon252` gate (`M/docs/PLAN.md:746-757`);
  - serde without defaults (`V/pvm/proof/Cargo.toml:62` already);
  - no `getrandom`. Masking's hedged randomness (`D/slice-5-proving.md:263`) stays behind `prover`.
- **Toolchain:**
  - stwo's verify path builds on stable (`~/.cargo/git/checkouts/stwo-59e22971a65c0edb/e128672/crates/stwo/src/lib.rs:7-10`);
  - vos-core pins `nightly-2025-07-14` (`V/rust-toolchain.toml:2`) and stwo e1286720 (`V/Cargo.toml:123-124`);
  - the circuit stack brings `nightly-2026-01-15` and edition 2024 (`D/slice-5-proving.md:134-137`).
  - **A 5.3 gate:** the final verifier builds on stable for `wasm32v1-none` and `riscv64em-javm`.
- **Size:** modesto's flat-AIR verifier costs 0.264 MiB compressed. A 319-column final AIR should cost less, but
  StarkWare's verifier and Kreivo's current size are unmeasured. Keep modesto's size gates (≥10% headroom under 3 MiB).
- **Memory:** a few MiB (modesto: 2 MiB or less dynamic), against a 128 MiB heap.
- **Safety:** fuzz, guard every index, decode strictly, and use no threads or floats. An authoring panic drops the
  extrinsic unpaid, which is a free denial of service.

## 9. The path to JAM (question 8)

- **Shared:**
  - **`vos-statement`** (no_std): the types, the canonical vos-codec encoding (`V/pvm/codec/src/lib.rs:1-10`),
    `io_digest` and `id`. Its "vos/statement/v1" succeeds modesto's two-field `vos/zk/io/v1`
    (`M/crates/settlement/src/binding.rs:31-61`).
  - **`vos-final-verifier`:** one core with pinned parameters per format, for wasm32 and riscv64em-javm.
  - **Golden fixtures** (valid, tampered, wrong program, stale root) judged alike by every venue.

| | Kreivo | JAM agent |
|---|---|---|
| Execution | one dispatch | refine verifies, accumulate applies |
| Metering | weight | gas |
| Blake2s | software in Wasm | software, with no precompile (`D/slice-5-proving.md:303-305`) |
| Inputs | signed extrinsics | `Jam{service}` transfers |
| Program ids | storage and governance | constants changed by redeploy (`:300-302`) |
| Anchors | pallet storage | witnessed reads in the representative agent |
| Payloads | inline | preimages |

- **Agent roots differ by host** (`:218-220`). Accepting only `SpaceWindow` and `Carried` keeps statements identical.
- **Risk:** equivocation across venues, if a space anchors on both.

## 10. Open questions for the owner

1. **The venue.** If spike 4a puts JAM over budget, Kreivo may be the only venue for a while. Flat segments are
   unmasked, so they cannot go there either. **Recommend:** build it as a full venue.
2. **The space side of registration.** **Recommend:** the creation record names the initial node keys, and one of them
   signs `(genesis, controller)`. Settle it in slice 6's `SpaceId` round.
3. **The space root commits to `(space_id, window)`.** **Recommend:** yes, with both carried in each `RootRead` among
   the public inputs (a small 5.1 change).
4. **Reads aligned to anchors.** **Recommend:** chain-bound attests read at the last window cut (5.2).
5. **The clock and the venues.** **Recommend:** relay time on Kreivo and slot time on JAM, with one anchor venue per
   space at a time and a signed migration point.
6. **Program governance.** **Recommend:** the Virto community origin with a Root override, a 7-day delay, and an
   emergency origin and track.
7. **Formats chosen at run time** in the verifier core. **Recommend:** a deliverable of 5.1 and 5.3.
8. **Fees:** about 1 UNIT per 300 KB proof. **Recommend:** accept it for v1, and revisit it with spike 4a's size,
   perhaps with a length discount per call.
9. **Anonymous submitters** need unlinkable fees. **Recommend:** signed submissions in v1, then a
   `#[pallet::authorize]` bare path with the fee in the proof (`D/identity-and-authority.md:139`, `:521`).
10. **Credentials into communities.** **Recommend:** a `Credential` handler records an approval with a scoped
    nullifier, which the extension checks. It never runs a STARK in `validate`
    (`F/pallets/communities/src/extensions.rs:132`).
11. **Staging.** **Recommend:**
    - P0: the registries, anchors, `RejectVerifier`, `Record` and tests;
    - P1: the real verifier, after 5.4 and spike 4a;
    - P2: the Clerk handler (slice 6).
