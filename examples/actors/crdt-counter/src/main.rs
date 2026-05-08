// PVM entry-point for the actor. The actor source lives in
// `src/lib.rs`; this file just `include!`s it so the `[lib]`
// and `[[bin]]` Cargo targets resolve to distinct paths,
// silencing cargo's "found to be present in multiple build
// targets" warning. The macro framework's `_start` emission is
// gated on the `bin` feature (default-on), so the lib build
// (default-features = false) skips it and the bin build
// includes it.

include!("lib.rs");
