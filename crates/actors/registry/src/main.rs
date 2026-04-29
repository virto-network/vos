//! Bin entry. `vos::pvm_main!` emits `_start` / `accumulate`
//! and the `.vos_meta` static for the riscv64 build. The bin
//! is only meaningful on riscv64 (the PVM target enforced by
//! `rust-toolchain.toml`), so we mark it `#![no_main]` and
//! rely on `_start` as the entry point.

#![no_std]
#![no_main]

vos::pvm_main!(registry::Registry);
