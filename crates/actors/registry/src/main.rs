//! Bin entry. The actor framework's `_start` / `accumulate` PVM
//! symbols come from the `#[messages]` expansion in `lib.rs`
//! (gated on `target_arch = "riscv64"`); when the bin links the
//! lib for the riscv64 target, those symbols propagate. On host
//! targets there's nothing to run and `fn main` is just here to
//! satisfy cargo.

#![no_std]

#[allow(unused_imports)]
use registry::Registry;

fn main() {}
