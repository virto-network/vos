// PVM entry-point for the actor. The build splits the same
// source between two targets:
//
//   * `[lib]` (`src/lib.rs`) — rlib + cdylib, used by other
//     crates as a Ref source and by workers as a `.so`. Built
//     with `default-features = false` so the actor framework
//     macro skips emitting `_start`.
//   * `[[bin]]` (this file, gated on the `bin` feature) — the
//     riscv64 / wasm32 entry-point ELF that `vosx run` consumes.
//     Pulls in the same actor body via `include!` so we don't
//     duplicate the source. The macro emits `_start` here
//     because the `bin` feature is on.
//
// Splitting the bin path off lib.rs is what silences cargo's
// `file ... found to be present in multiple build targets`
// warning — same content reaches both targets, but Cargo sees
// distinct paths.

include!("lib.rs");
