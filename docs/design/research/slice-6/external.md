# Slice 6 — external facts (Kreivo, Stwo ZK, JAM, on-chain STARK costs)

Researched 2026-10-18. Confidence tags: **[H]** read in source/spec myself, **[M]** secondary source or my inference from primary material, **[L]** weak / unverified.
Read-only clones (none built or run), not kept: `kreivo` (87f8728, 2026-10-11), `frame-contrib` (f95b25e, 2026-09-24), `stwo-upstream` (826591c, 2026-08-13), `proving` (916aefb5, 2026-10-15), `graypaper` (e537514, 2026-08-26), `zkverify` (e09189c, 2026-10-09), `plonky3` (4615dcd, 2026-10-18), `papers/` (HK24 + Circle STARKs PDFs via web.archive), `crates/` (crates.io sources of polkadot-primitives 25.0.0, cumulus-pallet-parachain-system 0.30.0, sp-io 48.0.0, sp-runtime-interface 37.0.0, frame-system 48.0.0, polkadot-node-primitives 26.0.0, polkadot-node-core-pvf 30.0.0).

---

## Things that contradict or qualify our assumptions (read first)

1. **No Blake2b host call on JAM.** The Graypaper (v0.8.0 tagged 2026-06-03, master to 2026-08-26) has no hashing host call. The full list is Ω_A…Ω_Z plus grow_heap, compile, provide and yield. The "~76M gas with Blake2b through a host precompile" projection therefore has no spec basis today, and **~96M is the real JAM number** [H]. A JAM implementer's PoC (2026-01-10) takes the same "compile the hashes into PVM, no extra host calls" stance. It reports 75–100M gas per ZK verification [M].
2. **The JAM gas model changed.** GP PR #508 (2026-02-25, released in 0.8.0) moved PVM gas to **per-basic-block costs from a simulated CPU pipeline** (decode slots, execution units, reorder buffer). It replaced flat per-instruction gas [H]. Check which model our javm host meters before quoting 96M / 85M / 117–119M. PolkaJam v0.8.0 shipped 2026-10-16 [M, release page].
3. **The verify can't run in Accumulate.** G_A (gas per work-report accumulation) = **10,000,000**, so 96M only fits in **Refine**: G_R = 5,000,000,000 per work package [H]. Refine must verify and emit a small digest. Total work-report output is capped at 48 KiB [H].
4. **Stwo upstream has no ZK in the library itself.** StarkWare's production "privacy" ZK uses only **random blinding rows** in the stwo-circuits recursion. The count is `n_queries + 10`, and there is **no FRI mask polynomial, no randomized composition split and no salted Merkle leaves** [H code, M interpretation]. Haböck–Al Kindi (HK24) say this "on-domain randomization without R(X)" variant has **no ZK proof**. If we want provable HVZK, don't copy the StarkWare budget; use the BSCR mask (details in §2).
5. **Stwo's composition split is a canonical-type ("split at mid") decomposition, not an FFT-type one** [H]. Per HK24 §4, it must be **randomized with t(X)**, and that pushes the low half's degree above its power-of-two bound. This is the hardest engineering item for masking in a Stwo-shaped verifier.
6. **On Kreivo, fees and PoV are driven by proof size, not by verify time.** frame-system 48 adds the **extrinsic length to proof_size** in CheckWeight [H]. A 124–130 KB proof costs ~**0.43 UNITS in length fee**, against ~0.00065 UNITS of weight fee for ~2.1 ms [H arithmetic on Kreivo constants].
7. **Custom host functions are impossible on a Kusama parachain.** Relay validators' PVF host exposes only the standard sp-io interface. zkVerify's speed-ups (native Poseidon2 / BN host calls) work only because zkVerify runs its own relay chain [H code, M reasoning]. Blake2b-256 *is* a standard host call (§1.4).
8. **Our Stwo pin.** Our fork's base `e1286720` is upstream commit 2026-05-04 (#1398, SIMD Keccak). The `starkware-libs/stwo` repo froze at 826591c (2026-08-13); development moved to `starkware-libs/proving` (`crates/stwo`). Upstream has since changed the transcript, so upstream proofs are no longer compatible with our fork (OODS PoW, `mix_fri_config`, lifting) [H]. Details are in §2.6.

---

## 1. Kreivo today

### 1.1 Version, chain, structure [H]
- **Chain:** Kusama parachain, para id **2281** (dev preset), "token-less" (README). Runtime `kreivo-runtime` **0.17.1**, `spec_version 134`, `transaction_version 13`. Tip 87f8728 (2026-10-11, "mint and burn for community-administered assets").
- **SDK:** `polkadot-sdk-version` = **stable2606-2**. All SDK crates come from **crates.io** with no `[patch]` (e.g. sp-io 48.0.0, frame-support 48.1.0, frame-system 48.0.0, cumulus-pallet-parachain-system 0.30.0, polkadot-primitives 25.0.0, substrate-wasm-builder 34.0.1).
- **Release builds:** srtool, since 3e0a5c3 (2026-09-29).
- **Node:** runs on the stock `polkadot-parachain` (omni) node, so there are no custom host functions.
- **Workspace:** `apis` (kreivo-apis, chain-extension-style APIs for contracts), `common`, `runtime/{kreivo,common,runtime-constants}`, `chain-spec-generator`, `integration-tests/emulated`.
- **Local pallets** are path deps under `pallets/`: `communities-manager`, `contracts-store`.
- **Pallet indices in use:** 0–4, 6 Pass, 10–18 (balances/assets/payment, 17 GasTxPayment), 20–24 collators, 30–33 XCM, 42–46 utilities, 50–53 treasury/collective/referenda/black-hole, 60–64 payments/listings/orders, 71–75 communities, 80 Contracts (pallet-contracts 49 + ink 5.1.1), 81 ContractsStore. **82 is reserved** (pallet-revive was removed in 0.17.0). A verifier pallet needs a free index, e.g. in 83–89 or 90+.
- **From frame-contrib (crates.io, v2.3.1, packaged as `fc-*`):** `fc-pallet-communities`, `-gas-transaction-payment`, `-listings`, `-orders`, `-payments`, `-pass`, `-referenda-tracks`, `-black-hole`, `frame-contrib-traits`, `fc-mock-helpers`. Also `pass-authenticators-{webauthn,substrate-keys}` 1.2.0.
  - frame-contrib main is already at **3.0.0-pre.2 (2026-09-22, stable2606-2)**, while Kreivo still pins 2.3.1.

### 1.2 Adding a new pallet [H]
- **frame-contrib convention:**
  - **Lockstep versioning:** one workspace version, one CHANGELOG and one `vX.Y.Z` tag. A new SDK line is a **major**.
  - **Published to crates.io by release-plz.** `pallets/template` (`fc-pallet-template`, `publish = false`) is the crate skeleton: `lib.rs`, `benchmarking.rs`, `weights.rs`, `mock.rs`, `tests.rs`, `impls.rs`, plus features `std` / `runtime-benchmarks` / `try-runtime`.
  - RELEASING.md says consumers **should use crates.io versions**. It warns that bare `git =` deps float with Cargo.lock, and that `?tag=` duplicates crates.
  - Moving tags `polkadot-stableYYMM` exist. A weekly psvm job bumps the SDK.
- **Consequence for us:**
  - **A pallet in frame-contrib must be publishable to crates.io**, so every dependency, including our **Stwo fork** and the no_std verifier crate, must also be on crates.io. `cargo publish` rejects git-only deps. Options:
    - (a) publish the fork and verifier under our own crate names;
    - (b) vendor the verifier into the pallet crate;
    - (c) put the pallet in Kreivo's `pallets/` as a path dep (no publishing; srtool builds fine).
  - The owner's org controls both repos, so (c) is the fastest route and (a) is the clean one [M].
- **Wasm target:** substrate-wasm-builder 34 builds the runtime for a **wasm32 no_std target** (wasm32v1-none on recent toolchains; MVP features, **no SIMD**) [M]. The verifier must be `no_std` with no `getrandom` / `rand` / `std` features leaking in.

### 1.3 Block limits (Kreivo `config/system.rs`, runtime-constants, PR #492 "block bundling", merged 2026-09-22) [H]

**Block bundling:**
- `BLOCK_PROCESSING_VELOCITY = 3`, so the target block time is 2 s.
- Relay slot is 6 s; `RELAY_PARENT_OFFSET = 1`; `UNINCLUDED_SEGMENT_CAPACITY = 3·(3+1) = 12`.
- Collators need stable2606 with `--authoring slot-based`.

**`MaximumBlockWeight = MaxParachainBlockWeight<Runtime, TargetBlockRate>`, per core count:**

| Cores | Per-block limit |
|---|---|
| 1 | 3 blocks share one core: **~666 ms ref_time, ~3.33 MiB proof_size per block** |
| 2 | 1 s, 5 MiB |
| ≥3 | 2 s, 10 MiB |

- The first block of a core may take the whole core (2 s / 10 MiB) via `DynamicMaxBlockWeight`.
- How many cores Kreivo holds on Kusama today: **unknown** [L].

**Other limits:**
- `NORMAL_DISPATCH_RATIO` = 75% (parachains-common).
  - With 1 core, the Normal class gets ≈ **500 ms ref_time and ≈ 2.5 MiB proof_size per block**.
  - Operational gets the full limit, with 25% reserved.
- `MAX_BLOCK_LENGTH = 5 MiB`; Normal class = 75% = **3.75 MiB**.
- Measured overheads (`/cmd bench-overhead`, 2026-09-24, AMD EPYC-Milan):
  - `ExtrinsicBaseWeight` = 108,157 ns;
  - `BlockExecutionWeight` = 919,269 ns.

**Is a ~130 KB extrinsic admissible? Yes.**
- `CheckWeight::check_extrinsic_weight` compares `total_weight + len` against `max_extrinsic` (frame-system 48 `check_weight.rs` l.59–69). The block's consumed proof_size also includes `len`. So 130 KB counts as **130 KB of proof_size**.
- `check_block_length` checks against the 3.75 MiB Normal-class limit.
- Budget with 1 core: **~19 proofs per block** by proof_size (2.5 MiB / 130 KB), against ~200+ by ref_time. With ≥3 cores, ~58 per block.
- Node-side limits (RPC default request size ~15 MiB, pool) are well above 130 KB [M].

**Fees** (`TransactionByteFee = 10 MILLICENTS`; UNITS = 1e12, MILLICENTS = UNITS/3e6; WeightToFee maps ExtrinsicBaseWeight → 0.1 CENT, CENT = UNITS/3000):
- **Length fee for 130 KB ≈ 0.433 UNITS.**
- **Weight fee for 2.1 ms ≈ 0.00065 UNITS** (before the multiplier).
- **Length dominates by ~670×.** A verifier pallet needs a fee policy: feeless/skip-feeless, community gas tanks (`fc-pallet-gas-transaction-payment`), or a deposit/refund scheme [H arithmetic, M policy].

### 1.4 Blake2b-256 in the runtime [H]
- `sp_io::hashing::blake2_256` is a **standard runtime-interface host call** (sp-io 48 `Hashing::blake2_256`, i.e. `sp_crypto_hashing::blake2_256` = unkeyed Blake2b with **outlen 32**). All PVF hosts have it.
  - Kreivo already uses it via `frame_support::Blake2_256` (`config/system.rs`).
- **Per-call mechanics:** it returns `AllocateAndReturnPointer<[u8;32]>`. The host allocates 32 B in the runtime heap and the runtime wrapper frees it (sp-runtime-interface 37 `pass_by.rs` l.750–763). Each call is therefore one Wasm↔host boundary crossing plus an alloc/free pair, which is cheap but non-zero.
- **No published per-call ref_time** exists. Measure in the pallet benchmark: in-Wasm Blake2b vs host call [L on the magnitude].
- **Compatibility:** it matches our Blake2b-256 **only if** ours is unkeyed, unsalted, unpersonalized Blake2b with digest length 32. Truncated Blake2b-512 would not match [H].

### 1.5 Relay limits (Kusama), stable2606 constants [H unless noted]
- `MAX_POV_SIZE = 10 MiB` (polkadot-primitives 25.0.0 `v9/mod.rs:469`). Polkadot ref **1480 "Set PoV size limit to 10 Mb"** passed (~2025) "following the successful enablement of 10 Mb PoVs on Kusama" [M]. Kreivo's runtime assumes 10 MiB per core.
- `MAX_CODE_SIZE` = 5 MiB (constant; the live on-chain `max_code_size` may be lower) [M].
- PVF defaults:
  - **backing execution timeout 2 s, approval 12 s**;
  - logical stack max 65,536 values; native stack 256 MiB;
  - `POV_BOMB_LIMIT` = 4 × MAX_POV_SIZE.
  - Keep the verifier free of deep recursion and huge stack frames.

### 1.6 Benchmarking a ~2 ms verify [H practice, M details]
- **Benchmark:** use `frame-benchmarking` v2 (`#[benchmarks]`) with **real worst-case proof fixtures** per statement shape.
  - Add components only if verify cost varies (e.g. segment count / log size). Our proof shape is fixed, so a constant is fine.
  - Run on the reference machine (Kreivo uses `virto-bench`, AMD EPYC-Milan, and the `/cmd bench` bot) with `--wasm-execution compiled`, steps 50 / repeat 20, giving `WeightInfo::verify()`.
  - proof_size weight then covers only storage reads (VK, statement registry, nullifiers). The proof bytes are counted through `len` (§1.3).
- **Dispatch:**
  - Declare the worst-case weight.
  - Return the actual weight with `PostDispatchInfo` if a cheap pre-parse can bound it (zkVerify parses the proof structure first and refunds).
  - Use a `BoundedVec<u8, MaxProofLen>` so oversized proofs fail at decode.
- **Panics:** a panic inside the runtime traps the whole call. In block building the extrinsic is dropped **without paying a fee**, which makes a malformed-proof panic a free DoS vector. The verifier must be total (return `Err`, never panic), with sizes checked before parsing. Also avoid `unwrap` in the deserialization code.

### 1.7 Existing ZK verifier pallets in the ecosystem
**zkVerify** (Horizen Labs; `zkVerify/zkVerify` e09189c, 2026-10-09) runs its **own relay chain** (`zkv-relay` + `paratest` parachains), not a Kusama/Polkadot parachain [H].
- **Verifiers:** fflonk, groth16, plonky2, risc0, sp1, tee, ultrahonk, ultraplonk, ezkl. They share a `pallet-verifiers` / `hp-verifiers` trait, configure max sizes (e.g. Risc0 `Segment20MaxSize = 350_000` B), and compute weight per proof structure.
- **Wasm-compiled benchmark weights** (laptop CPUs; dates from the weight files) [H]:

| Verifier | Weight | Date / note |
|---|---|---|
| Groth16 BN254 | 2.45 ms | 2025-02-12 |
| Plonky2, Keccak | 1.2–6.2 ms | 2025-04-28 |
| Plonky2, Poseidon | 8–32 ms | 2025-04-28 |
| Risc0 succinct STARK | 25.4 ms | 2025-02-25, with a **native Poseidon2 host call** (`native/src/risc0.rs`) |
| SP1 | 51 ms | 2025-07-01 |
| UltraHonk | 5.6–7.7 ms | 2026-03-12 |

- **Lessons:** they first ported native verifiers to Wasm (node 0.8.0 / runtime 0.10.0, Jan 2025), then **moved hot primitives back to node host functions** (runtime 0.11.0) because Wasm was slow [M, blog]. That route is closed to a Kusama parachain (§ "contradicts" 7).
  - Our ~2.1 ms puts us in the *cheapest* band of their list without any host acceleration.

**pq-stark-polkavm** (samizdatproject; dry-runs 2026-10-11) [M, self-reported]:
- **What it is:** Winterfell 0.13.1 as a pallet-revive contract on Kusama Asset Hub.
- **Cost:** 2.0e11–5.8e11 ref_time (**0.2–0.58 s**) for 26–86 KB proofs, at ~66,743 ref_time per PVM instruction. Keccak runs via a revive host call.
- **Limits it hit:** 128 KiB calldata, 1 MiB code, 1.5 MiB memory, and a 1,000-instruction basic-block limit. That limit **rejected portable Blake3** (a 1,329-instruction block).
- **Takeaway:** a contract route is ~100× costlier than a native pallet. Our 124 KB proof would sit right at the 128 KiB calldata cap.

**Host-call precedents:** Substrate's arkworks EC host calls (`sp-crypto-ec-utils`, from substrate PR 13031) exist in the SDK. I could not confirm that they are enabled in relay validators' PVF host [L]. A hackmd proposal (2024) suggests more curve host calls.

**Kreivo-internal precedent:** fc-traits-authn / pallet-pass now "bind authenticator verification weights through the runtime" (frame-contrib #102/#112, 2026-09-22). That is the in-house pattern for charging crypto-verify weight.

---

## 2. Stwo upstream and zero knowledge

### 2.1 Upstream status [H]
- `starkware-libs/stwo`: last commit 826591c (2026-08-13), README says "Starting from end of July 2026, all development … moved to `starkware-libs/proving`". Tags v2.1.0, v2.2.0, sharp7.2-rc.0. Our pin e1286720 is followed by **22** stwo-repo commits: edition 2024, `gen`→`trace_gen` renames, Blake2s Merkle channel change #1425, `min_lifting_log_size` #1437, query sorting #1422. None is ZK-related.
- `starkware-libs/proving` @ 916aefb5 (2026-10-15) contains `crates/stwo` with **151** commits touching it. Notable ones:
  - **Proof-of-work before the OODS draw**, `OODS_POW_BITS = 16` (f0bf0195, 2026-09-15; logged as "DIVERGENCE-011, defense in depth, not counted in security_bits");
  - `mix_fri_config` via `mix_u32s` (98f027bb, 2026-09-15);
  - config mixing moved to FriConfig (f3ec23b3, 2026-09-02);
  - `pow_bits` into FriConfig (e836666e, 2026-07-27);
  - lifting fixes (6f7ab7c6, 2026-08-19);
  - single-step `fold_line` removed from the FRI verifier (a233f923, 2026-10-05).

  The `proving` repo keeps a "paper–implementation divergence log" (`.claude/skills/paper-implementation-divergence-log.md`), which is useful for our own audit.
- **No ZK in `crates/stwo`:** grep for zk/blind/mask/salt finds only a GKR doc reference. `vcs_lifted` Merkle leaves are **unsalted**. There is no masking polynomial in PCS/FRI, and `split_at_mid` composition is not randomized.
  - `channel_salt` (8b77adaf, 2026-02-01) is a **Fiat–Shamir transcript salt** mixed into the channel. It is not a Merkle-leaf salt, and the circuit prover sets it to 0.

### 2.2 How StarkWare does "privacy" ZK today [H code, M interpretation]
- The Cairo proof (non-ZK) is verified **inside a stwo-circuits recursion circuit**. That circuit's witness gets `add_zk_blinding(context, seed, n_padding)`: ChaCha20-seeded **random rows** in every witness component (qm31_ops, eq, triple_xor, m31_to_u32, blake_g_gate), using trivial `x + 0 = x` gates (`circuit_common/src/finalize.rs`).
  - "include all gates" 2beb2f1e, 2026-06-04;
  - leaf prover / registries bebe8d8c, 2026-08-27;
  - "Account for OODS queries" 38d36327, 2026-08-31.
- **Budget:** `zk_blinding_amount = n_queries + NON_QUERY_INFO_LEAK`, with `NON_QUERY_INFO_LEAK = 10` = "2 OODS queries (4 each since their answers are in QM31) + 2 M31s extra for safety" (`cairo_verifier/src/verify.rs:71–74`).
  - This is exactly HK24 Lemma 1's toy bound **e·n_F + n_D**. It does not cover the quotient-split or FRI-layer leakage that HK24 §2–§4 add. There is no R(X).
  - It is "on-domain" randomization (random rows inside H), which HK24 footnote 3 says they **did not succeed in proving ZK without the FRI mask R(X)**.

### 2.3 Literature [H, read]
- **Circle STARKs** (Haböck, Levit, Papini; eprint 2024/278, PDF dated 2024-12-17):
  - §5.4: "Zero-knowledge is obtained in the usual manner, by inserting sufficient randomness in the encoding of the trace polynomials, and using the [BSCR+19] randomization of FRI, which carries over to the circle without changes. We refer to [HK24]…"
  - App. C: the optimized variant with **D ⊇ H** "is not able to support zero-knowledge".
  - Stwo's canonic cosets keep H and D disjoint (H = odd multiples of g_{n+1}; D = odd multiples of g_{n+B+1}, where g_{n+1} = g_{n+B+1}^{2^B} is even) [M, my check].
- **HK24** — Haböck & Al Kindi, "A note on adding zero-knowledge to STARKs", eprint 2024/1037, revision 2025-02-20. It found ZK gaps (since patched, "none exploitable") in **Plonky2, RISC Zero, Triton** and in Haböck's FRI summary. Its results:

| Setting | Result |
|---|---|
| Toy protocol (Prot. 1+2) | Witness ŵᵢ = wᵢ + v_H·rᵢ, deg rᵢ < h, randomized **outside** H, with **h ≥ e·n_F + n_D** (e = [F:F_p] = 4 for QM31; n_F = # DEEP points; n_D = # FRI queries). Plus a **mask polynomial R(X) ∈ F[X]<|H|+h−1**, committed before the batching challenge λ, with batch h(X) = R(X) + Σᵢ λ^… Σⱼ λ^j (ŵᵢ − vᵢⱼ)/(X − zⱼ). |
| Why R is needed | FRI folding also folds the randomizers, halving their entropy each round. Without R the last layers reveal the witness folds (§2, l.~250–280). With R, Lemma 2 ("decoupling") makes the entire FRI transcript independent of the witness. |
| AIR with FFT-type split q = Σ X^{j−1} q_j(X^d) (not randomizable) | **h ≥ 2·d·(e·n_F + n_D) + n_D** (factor 2 for the g-translate, d for implicit queries). |
| Canonical (monomial) split, §4.1 (randomized GWC19-style: q̂₁ = q₁ + X^k̂·t₁, q̂₂ = q₂ + X^k̂·t₂ − t₁, …, q̂_d = q_d − t_{d−1}) | **h_p ≥ n_F + n_D** and **h ≥ 2·(e·n_F + n_D)**. |
| Lagrange (by-value) split, §4.2 | Same bounds as canonical, with q̂ᵢ = qᵢ + v_{Hᵢ}·tᵢ. |
| Cost, §5 | Prover arithmetic ×(1 + 4/(3·log|H|)), or ×(1 + 1/log|H|) when d·|H| < |D|. One extra commitment (R). Same evaluation domain. |
| App. A: permutation / LogUp | Incompleteness leaks "α ∉ witness values". Fine for statistical ZK with a large field (QM31 ~2^124). Plonky2's several small-field challenges made it worse. |

  The paper calls the quotient decomposition "a source for mistakes, both in literature as well as in software".
- **Plonky3 HidingFriPcs** (fri/src/hiding_pcs.rs, 2026-10-18):
  - masks each column with **N = trace height** random values (doubling the domain);
  - enforces **N ≥ 2·(num_queries + D·num_opening_points)**, citing HK24 §4.2;
  - adds random codewords and a hiding (salted) MMCS (`MerkleTreeHidingMmcs`);
  - its docs say: "Private prover data may be opened only once" and seed from a CSPRNG.
  - Plonky3's circle PCS has no ZK mode [H].
- **Winterfell:** its README still says "NOT perfect zero-knowledge". Issue #9 lists the standard trio: random trailing rows, composition blended with a random low-degree polynomial, and salted trace Merkle [M].
- **Hexens blog** (secondary): masking the witness alone is not enough; mask the DEEP composition too [M].

### 2.4 Standard technique and what it costs us (n_D = 20, e = 4, blowup 64, fold step 3)
| Piece | What | Budget | Proof-size / verify delta |
|---|---|---|---|
| Trace randomization | Off-domain `w + v_H·r` (deg bound becomes \|H\|+h, so the column no longer fits its 2^k bound; needs a split or bigger domain), **or on-domain**: h random rows inside H with constraints disabled by a selector (StarkWare-style; degree stays < \|H\|) | h ≥ m·(e·n_F + n_D), with m = # distinct mask offsets (2 for {0,+1}). n_F=1: **h ≥ 48** for m=2. Unrandomized FFT-type split: 2·2·24+20 = **116** | none in the verifier (the domain may grow if padding is insufficient) |
| Composition split | Randomize `split_at_mid`: q̂_lo = q_lo + π^{L−2}(x)·t, q̂_hi = q_hi − t, deg t < h_p | **h_p ≥ n_F + n_D = 21** | q̂_lo exceeds the 2^{L−1} bound by h_p, so it needs a larger degree bound or a third chunk. FRI degree-bound plumbing changes |
| FRI mask R(X) | BSCR: commit QM31 R of deg < \|H\|+h−1 before λ; add with **coefficient 1 (affine)** in the DEEP batch | n/a | +1 root (or +4 M31 columns in an existing lifted tree); +4 M31 per query plus auth path. A few hundred bytes to ~1–2 KB |
| Hiding Merkle | Salt each leaf (or add ≥ 4–8 random M31 columns per non-public tree, ≥ 124 bits) | — | +16–32 B per opened leaf per tree. Unsalted narrow trees (few columns) allow brute-forcing unopened leaves |
| LogUp claims | Per-component `claimed_sum` is revealed in Stwo proofs and is a non-local function of the witness | Random rows must also feed **balanced random lookup terms**, or reveal only the aggregate | none, if done in the AIR |

- **Affine DEEP batching:** the proximity-gap / correlated-agreement results hold for affine combinations u₀ + Σ λⁱuᵢ. Adding R with coefficient 1 keeps soundness. R must be committed **before** λ and before query sampling [M, standard].
- **Multi-step folds (fold step 3):**
  - **With R:** Lemma 2 decouples all FRI layers, so fold-coset siblings (8 per query per inner layer) and the circle→line sibling don't enter the trace budget. In Stwo the trace is opened only at the query positions; siblings come from the committed first-layer oracle (`FriProof.first_layer.fri_witness`) [H code].
  - **Without R:** every sibling is an extra evaluation of the batched DEEP combination, and the folds degrade the randomizer (HK24 §2). Not fixable by trace randomization alone.
- **Other pitfalls:**
  - OODS point outside H ∪ D. A random QM31 circle point lands in M31 with probability ~2^−93; Stwo samples on the full QM31 circle.
  - Don't count PoW as hiding (grinding doesn't leak).
  - CSPRNG for masks, and never reuse masked commitments across two proofs (Plonky3 "open once").
  - Lifted Merkle: smaller columns' query positions may coincide (fewer leaks, fine).
  - Preprocessed / public trees need no masking.
  - Verifier delta: the verifier mostly just accepts the extra columns and degree bounds. Our modelled 96M→117–119M gas includes these; nothing found contradicts that magnitude [L].

---

## 3. JAM / PolkaJam

### 3.1 Graypaper [H]
- **Version:** latest tag **v0.8.0 (2026-06-03)**, earlier v0.7.2 / v0.7.1. Master continues: e.g. a "compile" host call (#530, 2026-08-19), "Junior services" (#539, 2026-08-10), masked third register (#554, 2026-08-26).
- **Constants (`text/definitions.tex`):**

| Constant | Value |
|---|---|
| G_R (refine gas per work package) | **5,000,000,000** |
| Is-Authorized gas | **50,000,000** |
| G_A (accumulate gas per work-report) | **10,000,000** |
| G_T (total accumulate per block) | **3,500,000,000** |
| Work items per package | **16** |
| W_B max bundle (payloads + extrinsics + imports) | **13,791,360 B** |
| Extrinsics per package | **128** |
| Imports / exports per package | **3,072** each |
| Segment | 4,104 B |
| W_R work-report variable output | **48 KiB** |
| Service code | 4,000,000 B |
| Cores | 341 |
| Slot | 6 s |

  Per-item refine (g) and accumulate (a) limits must satisfy Σg < G_R and Σa < G_A (`work_packages_and_reports.tex` l.120–126).
- **What this means for us:**
  - **96M gas = 1.9% of a work package's refine budget**, so ~50 verifies per WP by gas and ~110 by bundle size (124 KB each).
  - **Not in accumulate.**
  - Refine output should be a statement hash / verdict.
- **Gas model:** per-basic-block simulated CPU cycles (PR #508, 2026-02-25). Host calls are now gas-priced by constants (#517, 2026-06-03).
- **No hash / precompile host call** (see "contradicts" 1). The only Blake2 use is protocol-internal.

### 3.2 PolkaJam [M]
- `paritytech/polkajam-releases` is **binary-only**; source is withheld until the JAM prize is awarded.
- **Releases:**

| Release | Date | Note |
|---|---|---|
| v0.1.27 | 2025-12-02 | protocol 0.7.2 |
| v0.1.28 | Jun 01 (2026) | — |
| v0.1.29 and **v0.8.0** | Oct 16 (2026) | v0.8.0 = first GP-0.8-numbered release |
| nightlies | to 2026-10-18 | — |

- No public JAM testnet was found. A 2025 article listed one as a 2026 goal [L].

### 3.3 STARK verification on JAM [M]
- No public STARK-verifier JAM service was found.
- Closest: **sourabhniyogi** (Polkadot forum, 2026-01-10) built a PoC JAM service for Zcash NU7-style privacy: "verifications taking at most 50ms on a recompiler ≈ 75–100M PVM gas". It compiles Rust→PVM with polkatool, uses **no extra host calls**, and verifies statelessly in refine.
  - It argues against adding host calls ("EC pairings"). This is consistent with our ~96M and with refine placement.
- The "MiniJAM" parachain thread (2026-10) exists; not read.

---

## 4. On-chain STARK verification references (to judge ~2.1 ms / 124 KB)
- **Kreivo by ref_time:** 2.1 ms = 0.4% of a 1-core Normal-class block (500 ms), 0.1% of a full core. **Comfortable** [H arithmetic].
- **Kreivo by size:** 124–130 KB = ~5% of a 1-core Normal-class block's PoV share (2.5 MiB) and ~3.5% of block length. **This is the binding constraint, and it is the fee driver** [H].
- **zkVerify Wasm weights (§1.7):** our 2.1 ms is below Risc0-succinct (25 ms, even with a native Poseidon2 host call), SP1 (51 ms) and Plonky2-Poseidon (8–32 ms). It is comparable to Groth16-BN254 (2.45 ms) and Plonky2-Keccak (1.2–6.2 ms) [H].
- **Kusama AH via pallet-revive** (Winterfell, 2026-10-11): 0.2–0.58 s of weight for 26–86 KB proofs; Groth16 via precompile ≈ 0.02–0.03 s [M]. A native pallet is the right venue.
- **Starknet / S-two** [M]:
  - S-two book benchmark (off-chain): Stwo verify ~15 ms at n = 32,768 Fibonacci, proof ~790 KB (vs Stone ~126 KB, SP1 ~1.3 MB).
  - On-chain Cairo verification of a raw Stwo proof (community repo modeofO/stwo-starknet-verifier): **10–15.9M Cairo steps**, over the tx budget, and 65k–223k felts of calldata vs a 5k-felt cap.
  - Their workable route is a **circuit-recursion proof** (3.79M steps, 35.7k felts), with a Sepolia fact registry live 2026-07-03.
  - StarkWare itself ships S-two proofs to L1 through SHARP (S-two recursion → Stone → Ethereum verifier).
- **Ethereum:** Groth16/PLONK wrapping of RISC Zero / SP1 costs ~200–300k gas. SP1 docs say direct STARK verification "is very expensive" [M].
- **Net:** the 124 KB direct-STARK route is unusual and large by Ethereum standards. On a parachain with a 10 MiB PoV and 5 MiB blocks it is acceptable. The cost lever is proof size (length fee and PoV share), not CPU. A future SNARK/recursion wrap would mainly buy fees and throughput.

---

## Sources
- Kreivo: https://github.com/virto-network/kreivo (87f8728); PR #492 https://github.com/virto-network/kreivo/pull/492
- frame-contrib: https://github.com/virto-network/frame-contrib (f95b25e, RELEASING.md, CHANGELOG 3.0.0-pre.2)
- Stwo: https://github.com/starkware-libs/stwo (826591c); proving: https://github.com/starkware-libs/proving (916aefb5); issue #1 https://github.com/starkware-libs/proving/issues/1
- HK24: https://eprint.iacr.org/2024/1037 (rev. 2025-02-20); Circle STARKs: https://eprint.iacr.org/2024/278 (2024-12-17)
- Plonky3: https://github.com/Plonky3/Plonky3 (fri/src/hiding_pcs.rs); Winterfell issue #9: https://github.com/facebook/winterfell/issues/9; Hexens: https://hexens.io/blog/zk-in-starks
- Graypaper: https://github.com/gavofyork/graypaper (v0.8.0, master e537514); PolkaJam: https://github.com/paritytech/polkajam-releases/releases
- JAM PoC post: https://forum.polkadot.network/t/make-anonymity-coherent-again-proposal-for-privacy-as-first-class-citizen-in-jam/16076/9
- Polkadot 10 MB PoV ref 1480: https://polkadot.polkassembly.io/referenda/1480
- zkVerify: https://github.com/zkVerify/zkVerify (e09189c); blog https://blog.zkverify.io/posts/zkverify-s-node-release-0-8-0-and-runtime-upgrade-0-10-0 , https://blog.zkverify.io/posts/zkverify-runtime-upgrade-0-11-0
- pq-stark-polkavm: https://github.com/samizdatproject/pq-stark-polkavm
- S-two benchmarks: https://docs.starknet.io/learn/S-two-book/benchmarks ; stwo-starknet-verifier: https://github.com/modeofO/stwo-starknet-verifier ; RISC Zero on-chain: https://risczero.com/blog/on-chain-verification ; SP1: https://docs.succinct.xyz/docs/sp1/verification/getting-started
