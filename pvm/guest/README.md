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

A guest crate copies the first three files, uses this toolchain, and builds
with `cargo build --release --target riscv64em-vos.json`. The ELF becomes a
standard program through `vos_pvm_compiler::link_elf_spi`.

Host calls use `li t0, <id>; csrw 0x801, zero; ecall`, which the compiler
lowers to `ecalli <id>`.
