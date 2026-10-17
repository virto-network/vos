//! The host verifier binds a production proof's public boundary states
//! whatever the side note says.
//!
//! `verify` takes a side note, which the prover derives. Its
//! `closing_chip_active` flag tells the prover whether to mix the boundary
//! states into the transcript; the verifier must not let it switch off the
//! mix or the boundary-binding check on the production path, where the
//! boundary chips are always present. A proof built without the mix, its
//! final registers then forged, is refused against a side note with the flag
//! cleared, as `verify_standalone` refuses it.

mod common;

use common::*;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm_proof::{SideNote, active_components, production_pcs_config, prove};

#[test]
fn a_cleared_closing_flag_does_not_unbind_the_boundary() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = 5;
    regs[2] = 7;
    let (code, bitmask) = three_reg_program(Opcode::Add64, 9, 1, 2);
    let steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);

    let mut honest_note = SideNote::new(steps.clone(), code.clone(), bitmask.clone());
    let honest = prove(&mut honest_note).expect("honest prove");

    // The forger proves the production component set without the
    // boundary-state mix, takes the production mask, and lies about the
    // final registers it ships.
    let mut note = SideNote::new(steps, code, bitmask);
    assert!(!note.closing_chip_active);
    let components = active_components(&note);
    let mut forged = vos_pvm_proof::prove_with_explicit_components(
        &mut note,
        production_pcs_config(),
        &components,
    )
    .expect("the forger's prove completes");
    assert!(!note.closing_chip_active);
    forged.component_mask = honest.component_mask;
    forged.final_state.registers[9] ^= 1;
    assert!(
        vos_pvm_proof::verify(forged, &note).is_err(),
        "SOUNDNESS GAP: host verify accepted forged final registers under a cleared closing flag"
    );
}
