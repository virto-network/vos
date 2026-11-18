# PVM guest toolchain

Everything a Rust guest needs to build a Gray Paper 0.8.0 standard program:

- `riscv64em-vos.json`: the target (RV64EM, `lp64e`, no atomics, PIE, `ld.lld`
  with `--emit-relocs`).
- `pvm.ld`: the standard-program layout. Read-only data starts at `0x10000`
  (Z_Z). Read-write data, including `.bss`, starts at `2 * Z_Z` plus the
  read-only zone, set explicitly: without it, a program with no initialized
  data places `.bss` in the read-only zone and linking fails. Code has its own
  address space.
- `config.toml`: the cargo configuration (`build-std`, the linker script).
- `rust-toolchain.toml`: the pinned guest nightly.

The repository's guest workspaces (`agent/programs`, `agent/test-actors`)
point at these files rather than copying them: their `.cargo/config.toml`
links with `-T../../pvm/guest/pvm.ld`, and they build with `--target
../../pvm/guest/riscv64em-vos.json` under this toolchain. The venue guests
(`final-verify`, `statement-service`) are of the main workspace and build
for their own target, `pvm/proof/statement/riscv64em-vos.json`, which
differs from this one in one field: its `max-atomic-width` is 64, not 0.
The final verifier's graph (Stwo's foldhash seed and tracing-core's
callsites) needs `core::sync::atomic`, which a width of 0 removes; with
64 and no `a` extension LLVM lowers each atomic to a libcall, and the
venue guests' runtime (`pvm/proof/statement/src/bin/guest/runtime.rs`)
defines each as its plain counterpart, a PVM invocation being
single-threaded. An agent program needs no atomics, and this target keeps
them out of it. A guest
outside the repository copies the first three files and builds with `cargo
build --release --target riscv64em-vos.json`. The ELF becomes a standard
program through `vos_pvm_compiler::link_elf_spi`.

A guest whose bytes are pinned (`blobs.lock`, a program id) builds the
same in every checkout: the agent programs trim their source paths
(`trim-paths`), the venue guests remap theirs, and a workspace whose path
dependencies lie outside its root builds from a fixed path, the
justfile's `_at-fixed-path` (`pvm/proof/README.md`, "Pins, and
re-pinning").

Host calls use `li t0, <id>; csrw 0x801, zero; ecall`, which the compiler
lowers to `ecalli <id>`.
