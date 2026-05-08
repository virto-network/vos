// PVM bin entry. The actor's `_start` and `#[panic_handler]`
// lang items live in the lib's rlib (`src/lib.rs`); `extern
// crate math;` is what forces the linker to pull them
// into this executable. The riscv64 / wasm32 targets get
// `-Zcrate-attr=no_main` from `.cargo/config.toml`, so no
// `fn main()` is needed there — we add one only for host
// builds, where it's a no-op.

extern crate math;

#[cfg(not(any(target_arch = "riscv64", target_arch = "wasm32")))]
fn main() {}
