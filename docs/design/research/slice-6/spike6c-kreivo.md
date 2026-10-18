# Spike 6c: VOS's statement verifier in a real Kreivo runtime

2026-10-18. Throwaway code, committed locally only, nothing pushed.

**Where things are:**
- **Kreivo worktree:** `~/src/virto/kreivo-s6-spike`, branch `spike/s6-verifier`, local commit `a7370f1`.
  - It is based on **`origin/master` 87f8728**: runtime 0.17.1, spec 134, **polkadot-sdk stable2606-2**, every SDK and frame-contrib dependency from crates.io.
  - It is **not** based on `feat/update-stable2603`. A `git fetch` showed master newer, on stable2606, as the coordinator expected. The owner's checkout and branch are untouched.
- **VOS crates:** used read-only by path from `vos-core` 31b7938e (`pvm/proof/statement`). No VOS changes were needed, and no VOS worktree was made.
- **Artifacts:** in `tmp/s6/k/`:
  - logs: `baseline.log`, `with.log`, `with-prod.log`, `base-prod.log`, `bench-build.log`;
  - Wasm copies: `base-prod-wasm/`, `with-prod-wasm/`;
  - bencher output: `bench/` (`run.txt`, `weights.rs`, `bench.json`, `extra.txt`);
  - the fixture dumper: `dump/`, also copied into the pallet;
  - the bencher binary: `bin/`.
- **Machine:** Intel Core Ultra 7 155H, a laptop with P- and E-cores. Another spike was proving at the same time, so timings are noisy (see the spread in §3).

## 0. Verdict

**Linking is a non-problem; packaging is the problem.**
- `vos-statement` → `vos-pvm-final-verifier` → the git-pinned Stwo fork:
  - linked into the Kreivo runtime with **zero dependency-unification fixes and zero source changes**;
  - built on Kreivo's **stable 1.94.1** for **`wasm32v1-none`** with fat LTO.
- The runtime grows by **+75.7 KiB compressed** (+3.9%), leaving **~1.03 MiB under 3 MiB** [measured].
- `submit` on `wrap.proof` benchmarks at **3.99 ms ref_time** (Wasm, compiled) [measured]. That is about 1/125 of the 1-core normal-class time.
- **The binding limit is proof_size, not time:** about **20 proofs per block** on 1 core [est from measured].
- **Panics:** all 13 golden cases and about 400 mutants went through `submit` **inside the Wasm runtime**. All were refused, none trapped [measured].
- **The real obstacle is packaging.** An absolute path dependency outside the repository will not survive srtool or frame-contrib. A production home needs the verifier vendored into Kreivo, or published to crates.io together with the Stwo fork (§5).

## 1. What was built

`pallets/vos-verifier` (`pallet-vos-verifier`), wired into the runtime at **pallet index 90** (82 is reserved).

**Storage, as the venue:**
- `Formats: u32 → ()`;
- `Programs: [u32; 8] → ()`, the registered (pinned) program ids;
- `Anchors: (SpaceId, (kind, window)) → root`;
- `Seen: id → block`.

`StorageVenue<T>` implements `vos_statement::Venue` over them.

**Calls:**
- `submit(statement: BoundedVec<u8, 64 KiB>, proof: BoundedVec<u8, 256 KiB>)`, signed. In order:
  1. `Statement::decode`;
  2. the statement's program must be registered, and that registered id is the pin;
  3. `vos_statement::admit`;
  4. `Admitted::verify`;
  5. on success, `Seen` stores the id and the `Accepted { id }` event is emitted.
- The admin calls `set_format`, `set_program` and `anchor` take `AdminOrigin`, which is Root in the runtime.

**Weight and errors:**
- Declared weight is `submit_accept`. A refusal before the proof refunds down to `submit_refused_early` through `DispatchErrorWithPostInfo`.
- `Error` has one variant per `Refusal` class. `Proof { code: u8 }` carries the final verifier's code, and it compiles as a `PalletError`.
- The pin is keyed by program id: the "handler routed by program id" model in `kreivo-pallet.md` §0. A per-kernel key would also work. Either way the pin is storage, never the caller's.

**Fixtures:**
- `dump/` is a 60-line std tool. It reads `statements.cases` through `vos_statement::fixtures`, re-judges every case natively as a reference, and writes one SCALE file.
- That file holds the 3 proofs and the 13 cases (`model::Input` bytes, proof index, patch). Its size is about 370 KB.
- The pallet `include_bytes!`es it under `cfg(any(test, runtime-benchmarks))` only, so production code size excludes it.

**Tests:**
- Native, through the pallet's mock: 9 passed. They cover accept then repeat, a bad origin, the benchmark suite, and every fixture plus mutation.
- In Wasm: §4.

## 2. Build and integration

### Obstacles and fixes

| Expected obstacle | What happened |
|---|---|
| `blake2 0.10` | Unified with Kreivo's existing 0.10.6. No action. |
| serde / postcard no_std | serde unified *down* to Kreivo's 1.0.228 (VOS locks 1.0.229). postcard 1.1.3 was already in Kreivo's lock. No `std` leaked into the Wasm build. |
| `num-traits` | Unified to 0.2.19. |
| Stwo fork, git rev `ab294189`, no default features | Fetched and built as is. `poseidon252` is off, so there is no `starknet-ff → getrandom/js → std` subtree (modesto's old failure). `rand 0.8`, `hashbrown`, `blake3`, `sha3 0.11`, `tracing`, `itertools` and `indexmap` all unified with versions Kreivo already locks. |
| `vos-pvm-recair-air`, `vos-pvm-poseidon2` | Built as is. |
| New lockfile entries | Only these crates.io packages: `stwo-std-shims 1.0.0`, `educe 0.5.11`, `bytemuck_derive 1.12.1`, `syn 3.0.9` (proc-macro, build-only). Plus the 2 Stwo git crates and 4 VOS path crates, 10 packages in all. |
| Toolchain: VOS pins `nightly-2025-07-14` | **Irrelevant.** A path dependency builds with the *consumer's* toolchain; VOS's `rust-toolchain.toml` is not read. The whole stack builds on stable 1.94.1 with edition 2024. |
| Workspace inheritance | The VOS crates use `edition.workspace = true` and `{ workspace = true }` deps. Cargo resolves these against the VOS workspace root when used as a path dep, and it works. **It also means the build reads `vos/.worktrees/vos-core/Cargo.toml`.** That root's `[patch]` (lsm-tree) does not apply to consumers, which is harmless. |
| Wasm target | The first builds used wasm-builder 34's fallback (`wasm32-unknown-unknown` + `-Zbuild-std` + `RUSTC_BOOTSTRAP`), since `wasm32v1-none` was not installed. **I installed `wasm32v1-none` on the stable toolchain** (`rustup target add`, as Kreivo's CI does), and the final numbers use it. Both targets built with no change. |
| Benchmarks build | Built with `SKIP_PALLET_REVIVE_FIXTURES=1`, as Kreivo's CI does. |
| Bencher version | `polkadot-omni-node 1.21.0`, as installed, fails *every* benchmark, `pallet_balances` included, with no message. **This is a host/runtime ABI mismatch, not ours.** The stable2606-2 `frame-omni-bencher 0.24.0` (the release asset Kreivo's CI downloads, sha256 checked) works. |
| Clippy/fmt | Not run (spike). |

**Build times** (`-j10`, nice, 16 GiB cap):
- a clean `cargo build --release -p kreivo-runtime`: 16 min;
- an incremental rebuild with the pallet: 5 min (release) and 9 min (production Wasm).

### Code size: `WASM_BUILD_TYPE=production` (fat LTO, cgu 1), `wasm32v1-none`, without `runtime-benchmarks` [measured]

| | baseline 87f8728 | + verifier pallet | Δ |
|---|---|---|---|
| `compact.compressed.wasm` (the on-chain blob) | 1,987,619 B (1.896 MiB) | 2,065,161 B (1.970 MiB) | **+77,542 B (+75.7 KiB, +3.9%)** |
| `compact.wasm` (decompressed) | 10,723,988 B | 11,041,716 B | +317,728 B (+310 KiB) |
| `kreivo_runtime.wasm` (raw) | 11,353,029 B | 11,685,151 B | +332,122 B |

- **Headroom under 3 MiB (3,145,728 B):** 1,080,567 B (34%) with the verifier, against 1,158,109 B without [measured].
- **A masked verifier about 1.4× larger:** about +108 KiB compressed, so ≈ 2.10 MB and ~1.0 MiB headroom [est].
- **Decompression limit:**
  - the relay's `validation_code_bomb_limit` is `max_code_size × MAX_VALIDATION_CODE_COMPRESSION_RATIO` (10, `polkadot-runtime-parachains` 25/29 `configuration.rs:54`), so 30 MiB at a 3 MiB code cap [read];
  - 11.0 MB decompressed is well inside it;
  - the deprecated 4× constant would be 12 MiB at 3 MiB, or 20 MiB at the 5 MiB `MAX_CODE_SIZE`; 11.0 MB fits under those too, but tighter.
- **The verifier compresses well.** Standalone it is about 494 KB; inside the runtime it adds 310 KiB decompressed and 76 KiB compressed, because it shares serde, alloc and the rest with the runtime.

The release profile (thin LTO, fallback target) gives the same picture, for reference: 2,061,537 → 2,156,852 B compressed (+95,315 B).

The runtime-benchmarks build is 7.08 MB compressed and 18.3 MB compact. That is irrelevant on chain, and it includes the 370 KB of fixtures.

## 3. Benchmarks

`frame-omni-bencher v1 benchmark pallet --runtime <production+runtime-benchmarks wasm> --pallet pallet_vos_verifier --extrinsic '*' --steps 2 --repeat 20`, run in the Wasm runtime (wasmtime, compiled).

| benchmark | ref_time (median slope) | sample spread (min–max) | reads/writes | recorded PoV | benchmarked PoV (MaxEncodedLen) |
|---|---|---|---|---|---|
| `submit_accept`: the valid case, the full verify of `wrap.proof` (124,025 B) | **3,994 µs = 3.994e9 ps** | 2.66–6.95 ms | 5 r / 1 w | 345 B | 6,134 B |
| `submit_refused_early`: an unaccepted format, refused before the proof (the 124 KB argument is still carried) | **15.1 µs** | 15.5–60 µs | 1 r | 177 B | 3,513 B |
| `submit_refused_tampered`: one byte flipped, `0x112` Stwo Merkle (a near-full verify) | **2,679 µs** | 1.78–3.60 ms | 5 r | 345 B | 6,134 B |

**Wall time:** the bencher's extrinsic time *is* the Wasm execution wall time [measured].

**Against the earlier projection:**
- 38.4M instructions × 0.125 ns (Xeon 8370C) gives 4.8e9 ps [projected].
- Measured: 3.99e9 ps on this laptop.
- Kreivo's reference machine (EPYC-Milan, per `/cmd bench-overhead`) is unmeasured for this, so a production weight must be benchmarked there.
- **For the masked format:** ×1.3–1.4 gives ~5.2–5.6e9 ps [est]. Repeat with bigger `--repeat` on a quiet machine.

### Fit per block

Inputs:
- The extrinsic's encoded length is ≈ 124.4 KB [est]: proof 124,025 + statement 278 + compacts and call index ~7 + signed envelope (MultiAddress, MultiSignature, extensions) ~110.
- frame-system 48's `CheckWeight` adds `len` to proof_size, both in `check_extrinsic_weight` and in the block's consumed weight [read: `frame-system-48.0.0/src/extensions/check_weight.rs:62-63,182-183`].
- So one accepted submit costs ≈ **4.0e9 ps + 0.108 ms base**, and ≈ **6.1 KB + 124.4 KB = ~130.5 KB of proof_size** [est from measured].

| limits (Normal class = 75%) | by ref_time | by proof_size | by length (3.75 MiB normal) | binds |
|---|---|---|---|---|
| 1 core (≈500 ms, ≈2.5 MiB per block under bundling) | ~121 | **~20** | ~31 | **proof_size, ~20 per block** |
| ≥3 cores (1.5 s, 7.5 MiB) | ~365 | ~60 | **~31** | **length, ~31 per block** |

- **A single ~124 KB extrinsic fits easily** [read + arithmetic]:
  - against `max_extrinsic` (≈ the whole normal class);
  - against the 3.75 MiB normal length;
  - against pool and RPC limits.
- **Fees are dominated by length**, not weight:
  - about 0.43 UNITS of length fee at 10 MILLICENTS a byte (external research);
  - against ≈0.0013 UNITS of weight fee for ~4 ms. ExtrinsicBaseWeight (108 µs) maps to 0.1 CENT, so 4.1 ms ≈ 3.8 CENT, with CENT = UNITS/3000 [est].
  - A production pallet needs a fee decision.

## 4. Panic behaviour, in the Wasm runtime [measured]

`judge_every_fixture_and_mutations` is a `#[benchmark(extra)]`. Run by `frame-omni-bencher … --extra`, it executes **inside the runtime Wasm**. It took 139 ms in total and passed every assertion.

**What it checks:**
- **All 13 golden cases through `submit`:** each case reaches its expected error class, and `valid` is accepted. Refusal codes 1–6 map to `Error::{Statement..Repeated}`, and `0x1xx` to `Proof { code }`.
- **120 proof mutants, all required refused:**
  - every one of the first 64 bytes flipped (header, lengths, postcard varints);
  - 48 pseudo-random bytes set to 0xff, 0x00 or ^0x01;
  - 7 truncations (0, 1, 7, 100, 1000, 60,000, len−1 bytes);
  - 9 trailing zero bytes added.
- **About 284 statement mutants against the valid proof, none allowed to be accepted:**
  - every byte XOR 0x5a;
  - 5 truncations;
  - a compact length claiming 2^30 bytes of `public_args`.

**Result:** no trap, no allocation failure; every mutant was refused. A trap would fail the benchmark: an incompatible bencher already showed that failing benchmarks surface. The same suite also passes natively (`cargo test -p pallet-vos-verifier --features runtime-benchmarks`).

**Not covered:** the masked verifier's paths, and fuzzing at scale. This is a smoke test in the real executor, not a replacement for C2's fuzzing.

## 5. `sp_io::hashing::blake2_256` (not built)

- **Possible: yes.**
  - `sp_io::hashing::blake2_256` is unkeyed Blake2b with a 32-byte output, the exact function the wrap uses. The fork's own doc says every hash is "that function of one message, so a host that serves only whole-message Blake2b-256 (Substrate's `blake2_256`) … computes the same digests" (`stwo/src/core/vcs/blake2b_hash.rs:1-5`).
  - It is a standard host call that PVF hosts have, so it needs no custom host function.
- **Where the hook goes:** one type, `stwo::core::vcs::blake2b_hash::Blake2bHasher`, the single hasher behind both `Blake2bChannel` (Fiat–Shamir) and `Blake2bMerkleHasher` (the lifted Merkle).
  - It is streaming (`update`/`finalize`), so the host path must buffer the message and call the host once at `finalize`. `hash_parts` already sees whole messages.
  - Proposed: a fork feature, e.g. `host-blake2b`, under which `Blake2bHasher` keeps a small `Vec<u8>` and calls an `extern "Rust" fn stwo_blake2b_256(&[u8]) -> [u8; 32]`. The pallet, or a 5-line shim crate, defines it with `sp_io::hashing::blake2_256`.
  - Alternatively, a global `fn` pointer set once.
  - `vos_statement::blake2b_256` (the io-hash and the id, 2 calls) can stay software.
- **Why it was not built:** it is a change to the git-pinned fork, so it needs a review and a re-pin. It is not trivial in this spike's rules.
- **Expected gain:** −24 to −36% instructions on Blake2b Merkle work (`spike4a-final-gas.md` §5, measured in a blob), so roughly 4.0 → ~2.8–3.2 ms here [est]. **It does not help the binding limit, which is proof_size.**

## 6. What a production pallet needs

### Crate home and dependency path

- **(c) A pallet in Kreivo's `pallets/` (recommended first).**
  - It is a path dep inside the repository, needs no publishing, and frame-contrib's "no git deps" rule does not apply.
  - **It still needs the verifier stack *inside* Kreivo's repository or fetchable by srtool.** srtool mounts the repository, so the spike's absolute path to `vos/.worktrees/...` will not build there.
  - Options:
    - **(c1) A git dep on the VOS repository** at a pinned rev, with Stwo already a git dep at a rev. Cargo and srtool fetch git deps fine. Kreivo then gains its first git deps, and needs `--locked` and lockfile care.
      - Requirement: the VOS crates' `workspace = true` inheritance resolves against VOS's workspace root, so the whole VOS root manifest must parse in the fetched checkout. It does, but it ties Kreivo's fetch to the VOS monorepo, and that repository is heavy.
    - **(c2) Vendor** `vos-statement`, `vos-pvm-final-verifier`, `vos-pvm-recair-air` and `vos-pvm-poseidon2` into `kreivo/vendor/` with concrete manifests (no workspace inheritance), keeping Stwo as a git dep.
      - It is simple and srtool-safe.
      - A sync check is needed: the fixtures and a hash of the vendored sources against a VOS tag.
- **(a) frame-contrib.**
  - This forces crates.io for *everything*: a published Stwo fork under our own name, e.g. `vos-stwo` (`cargo publish` refuses git deps), plus the four VOS crates.
  - It is the clean long-term route. It needs the concrete-manifest work of (c2) anyway, plus a release process tied to VOS format changes, since every re-pin becomes a publish plus a frame-contrib major.
- **Recommendation:** ship P1 as (c2), vendored in Kreivo, and move to (a) once the masked format stabilizes.

### Weight approach

- Benchmark `submit_accept` (worst case: the full verify), `submit_refused_early` and a proof-refusal case on Kreivo's reference machine. Use the masked fixtures once M2 lands.
- Declare `submit_accept`, and refund to `submit_refused_early` for refusals before the proof (as the spike does).
- A proof refusal costs nearly the full verify (2.7 of 4.0 ms), so do not refund it.
- **The verify cost does not depend on the proof's length, since the format pins the shape.** No length component is needed beyond `MaxProofLen` for PoV.
- **The fee must account for length,** which dominates. Decide it: length discount, deposit-refund, or community gas tanks.

### Code-size headroom

- ~1.03 MiB headroom now, ~1.0 MiB after a 1.4× masked verifier [est].
- **Two formats linked during a transition** (old plus masked) would add roughly another 76–110 KiB [est]. Still fine.
- Keep modesto's ≥10% size gate in CI.

### Production checklist beyond the spike

- **Registries with governance and delay:**
  - `Formats` compiled in, with runtime-accepted ranges;
  - `Programs` with a handler id, `active_from`/`active_until`, and a delay;
  - spaces with a controller and anchor keys;
  - signed `anchor` with equivocation handling.
- **Pruning:** `Seen` and `Anchors` with `on_idle`, bounded; the carried root kind and pruning (M3.1).
- **Safety and plumbing:**
  - `RejectVerifier` for builds without the verifier;
  - an emergency pause;
  - a `Record` handler;
  - a pool extension providing a `("vos-stmt", id)` tag, with no verify in `validate`;
  - `MaxSubmitsPerBlock`, probably unnecessary given the proof_size bound.

## 7. Surprises

1. **Zero unification work.** The whole verifier stack added 10 lockfile packages, 6 of them our own. Every shared crate resolved to the version Kreivo already locks.
2. **Proof_size, not ref_time, is what limits throughput:** 20 per block at 1 core, against ~121 by time. That follows from frame-system 48 counting length as proof_size.
3. **The installed `polkadot-omni-node` 1.21 silently fails every benchmark** against a stable2606 runtime; only the matching `frame-omni-bencher` works. This is worth a line in Kreivo's docs or justfile.
4. **The decompressed runtime is already 10.7 MB.** The real limit is 10× `max_code_size` (30 MiB), not the deprecated 4× constant, and 11.0 MB fits under both, though with less room under the old one.
5. **Workspace inheritance across repositories works for path deps.** But it silently couples the consumer to the producer's root manifest, which matters for git-dep packaging.
6. **No VOS toolchain or nightly is needed anywhere on the verify path.**

## 8. Step list for the production pallet (for a faster agent)

1. **Make the verifier stack consumable without VOS's workspace.** Give the 4 crates concrete `[package]` fields and dependency versions, or generate them with a `cargo package`-style flattening script.
2. **Vendor them into `kreivo/vendor/vos-verifier/`,** or add a git dep on a VOS tag (decide (c1) or (c2) first). Keep Stwo as `git = "https://github.com/olanod/stwo", rev = …`, `default-features = false`.
3. **Add a `just vos-sync` check:** the vendored tree's hash against the VOS tag, plus the golden fixtures re-dumped (the spike's `pallets/vos-verifier/dump` tool, ported to run against the vendored crate).
4. **Create `pallets/vos-statements`** from the spike's `pallets/vos-verifier`:
   - rename;
   - add the registries (formats with ranges, programs with handler/delay/active window, spaces, signed anchors with equivocation);
   - add `Seen` with expiry, an `on_idle` prune, pause, `RejectVerifier`, `AdminOrigin`/`ProgramsOrigin`/`EmergencyOrigin`, and handler dispatch (`Record` first).
5. **Errors:** keep the spike's mapping (`Refusal` → `Error`, `Proof { code: u8 }`) and the refund to an early-refusal weight.
6. **Tests:**
   - native mock tests over all 13 golden cases;
   - the `#[benchmark(extra)] judge_every_fixture_and_mutations` panic sweep, run in CI with the matching `frame-omni-bencher … --extra`;
   - a cargo-fuzz target on `submit`'s decode path.
7. **Runtime wiring:** pallet index 90 (or 83–89), and add it to `define_benchmarks!`. Set `MaxStatementLen` (64 KiB) and `MaxProofLen` (256 KiB, the verifier's `MAX_PROOF_BYTES`).
8. **Benchmarks:** with `frame-omni-bencher` stable2606-2 on the reference machine (`--steps 2 --repeat 50`). Commit `weights/pallet_vos_statements.rs`.
9. **CI:**
   - `wasm32v1-none` production build;
   - a size gate (compressed ≤ 90% of 3 MiB);
   - `SKIP_PALLET_REVIVE_FIXTURES=1` for the benchmarks build.
10. **Fee policy decision** (length-dominated, ~0.43 UNITS a proof), then implement: a skip-feeless rule, a length discount, or gas-tank sponsorship.
11. **When M2 lands:** swap in the masked fixtures and format, re-run 6–9, and confirm headroom (est +110 KiB) and weight (est ×1.3–1.4).
