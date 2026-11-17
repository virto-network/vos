//! The circuits' constants (`vos_pvm_proof::constants`), recomputed from
//! their circuits: `H_fold` from the fold circuit and the wrap's
//! preprocessed root from the wrap circuit. The known programs' ids, from
//! the test actors' ELFs, are `vos-kernel-tests`' `constants::`.
//! `test-proof` runs it under both of the prover's feature sets; under
//! `VOS_PINS=write` (`just repin`) it writes `H_fold` if it moved, but not
//! the wrap's root, the final verifier's own (a venue's verifying key),
//! which a circuit change moves by hand.

use vos_pvm_proof::constants;
use vos_pvm_recair::fold::FoldCircuit;
use vos_pvm_recair::wrap::WrapCircuit;

/// Each circuit's constant is what its circuit computes, the wrap's root
/// the final verifier's.
#[test]
fn the_circuits_constants_are_the_repositorys() {
    let computed = FoldCircuit::word().0.map(|word| word.0);
    if computed != constants::H_FOLD && std::env::var("VOS_PINS").as_deref() == Ok("write") {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/constants.rs");
        crate::common::write_constants(
            &path,
            [("H_FOLD", computed.map(u64::from).to_vec())].into_iter(),
        );
    } else {
        assert_eq!(computed, constants::H_FOLD, "H_FOLD moved: `just repin`");
    }
    assert_eq!(
        WrapCircuit::get().masked_preprocessed_root().0,
        constants::PREPROCESSED_ROOT_39,
        "the wrap circuit's root moved: a new venue verifying key, written by hand into \
         `vos-pvm-final-verifier`'s `PREPROCESSED_ROOT_39`"
    );
}
