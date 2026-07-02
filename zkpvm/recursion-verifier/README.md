# recursion-verifier

The verify-only Poseidon2-over-M31 stwo **settlement verifier** for native
recursion: stwo's `verify()` driven by a custom Poseidon2-M31 Merkle channel,
plus the in-AIR constraint re-evaluation at the OODS point. It carries only the
VERIFY side of the recursion stack (no `CpuBackend`/SIMD commitment ops, no
`std`/`rayon`/`blst`), so it builds for both `wasm32-unknown-unknown` and the
JAM PVM (`riscv64em-javm`), and it executes and **ACCEPTS real proofs on the
PVM**.

## Why a separate workspace

This crate is its OWN `[workspace]` (and is in the vos root `exclude` list) so
its Cargo feature resolution never co-resolves with `javm`/prover-stwo. The vos
workspace pins stwo with `std,prover,parallel` (which drag rayon, and javm drags
blst); here stwo is pinned at the same git rev but `default-features = false`.

`vendor/stwo/` is a copy of that rev (trimmed to `stwo` + `constraint-framework`)
with ONE build-config change — `dashmap` made optional + prover-gated — wired via
the `[patch]` in `Cargo.toml`, so a no_std / no-atomics verifier build does not
drag crossbeam-utils. No verifier logic is modified; keep it byte-identical to
upstream except that one change when bumping the stwo rev.

## Building the PVM settlement ELF

The `settle` bin (`--features pvm-settle`) embeds a proof fixture and runs the
full verify; it is the on-chain finish-line gate.

```sh
just build-settle      # from the vos repo root
```

This produces `target/riscv64em-javm/release/settle.elf`, which gates two zkpvm
tests (both SKIP, not fail, if the ELF is absent):

- `cargo test -p zkpvm --test settle_transpile` — the ELF transpiles to JAM PVM
  bytecode (`grey_transpiler::link_elf`).
- `cargo test -p zkpvm --test settle_run` — the transpiled blob executes on the
  tracing PVM and ACCEPTS the honest fixture (`a0 = 0xACCE`), reporting the
  on-chain cycle count.

The ELF is intentionally NOT committed (it would go stale whenever the verifier
source changes); rebuild it with `just build-settle` after any change here.

The embedded fixture (`fixtures/bool_proof.postcard`) IS committed. Regenerate it
ONLY if the proof wire format changes, then rebuild the ELF:

```sh
cargo test -p zkpvm --test settle_fixture   # regenerates the postcard fixture
just build-settle
```

Requirements: the pinned nightly + `rust-src` (the ELF build uses `-Zbuild-std`).
The wasm32 build (`cargo build --release --target wasm32-unknown-unknown`) needs
no special toolchain.
