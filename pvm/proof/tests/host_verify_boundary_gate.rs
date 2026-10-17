//! The host verifier's verdict on a production proof does not depend on the
//! side note's `closing_chip_active` flag.
//!
//! The flag tells the prover whether to fill the closing chip and add the
//! register ledger's closing reads; the verifier reads only the side note's
//! program and component set, mixes every proof's boundary states, and binds
//! them to the boundary chips' claimed sums. So:
//! - an honest proof verifies against a side note with the flag cleared;
//! - an honest proof whose final registers are edited after proving is
//!   refused: the transcript draws other relation elements, and the claimed
//!   sums no longer match the shipped states;
//! - a proof made with the flag cleared, whose closing chip carries no rows,
//!   is refused under the production mask, its final registers edited or not,
//!   against either side note.

mod common;

use common::*;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm_proof::{SideNote, active_components, production_pcs_config, prove, verify};

#[test]
fn the_closing_flag_has_no_say_in_verification() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = 5;
    regs[2] = 7;
    let (code, bitmask) = three_reg_program(Opcode::Add64, 9, 1, 2);
    let steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);

    let mut honest_note = SideNote::new(steps.clone(), code.clone(), bitmask.clone());
    let honest = prove(&mut honest_note).expect("honest prove");
    assert!(honest_note.closing_chip_active);
    let mut cleared_note = SideNote::new(steps, code, bitmask);
    assert!(!cleared_note.closing_chip_active);
    verify(honest.clone(), &cleared_note).expect("an honest proof verifies under a cleared flag");

    let mut tampered = honest.clone();
    tampered.final_state.registers[9] ^= 1;
    assert!(
        verify(tampered, &honest_note).is_err(),
        "host verify accepted final registers edited after proving"
    );

    // The production component set proven with the flag cleared, under the
    // production mask: its closing chip carries no rows.
    let components = active_components(&cleared_note);
    let mut emptied = vos_pvm_proof::prove_with_explicit_components(
        &mut cleared_note,
        production_pcs_config(),
        &components,
    )
    .expect("the prove with the flag cleared completes");
    assert!(!cleared_note.closing_chip_active);
    emptied.component_mask = honest.component_mask;
    let mut edited = emptied.clone();
    edited.final_state.registers[9] ^= 1;
    for proof in [emptied, edited] {
        for note in [&cleared_note, &honest_note] {
            assert!(
                verify(proof.clone(), note).is_err(),
                "SOUNDNESS GAP: host verify accepted a proof without closing rows"
            );
        }
    }
}
