//! The masked segment (`vos_pvm_proof::masked`, variant (c)): the segment
//! AIR's chips proved masked over a small kernel's run and verified by the
//! final verifier's masked verifier, and the masking's soundness and
//! leakage gates on it (`docs/design/proving.md` §5).

#[path = "../common/mod.rs"]
mod common;

mod gates;
mod leakage;
mod support;
