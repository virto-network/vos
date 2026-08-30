#![cfg(feature = "debug-internals")]

//! AIR gates for standard-v0.8 scalar-memory address validity.
//!
//! A standard load/store may complete only when every touched cyclic address
//! is outside the protected initialization zone.  For the scalar widths this
//! is equivalent to requiring an above-zone base and no wrap through 2^32.
//! Jar keeps its frozen memory behavior and is deliberately not subject to
//! this profile-scoped CPU constraint.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{IsaMode, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::chips::CpuChip;
use vos_pvm_proof::chips::cpu::Column;
use vos_pvm_proof::core::step::NUM_REGS;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::trace::component::ComponentTrace;
use vos_pvm_proof::{AirColumn, SideNote};

fn assert_chip(chip: &CpuChip, trace: &ComponentTrace, side_note: &SideNote) -> Result<(), String> {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel);
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
    }))
    .map_err(|panic| {
        panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
    })
}

fn store_load_u64_side_note(address: u32, isa_mode: IsaMode) -> SideNote {
    let code = vec![
        Opcode::StoreIndU64 as u8,
        0x10,
        0,
        0,
        0,
        0, // source φ0, base φ1, offset 0
        Opcode::LoadIndU64 as u8,
        0x12,
        0,
        0,
        0,
        0, // destination φ2, base φ1, offset 0
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 0x8877_6655_4433_2211;
    regs[1] = u64::from(address);
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new_with_isa_mode(pvm, isa_mode);
    let _ = tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 3, "store, load and terminal instruction");

    let mut side_note = SideNote::new(steps, code, bitmask).with_isa_mode(isa_mode);
    for index in 0..NUM_REGS {
        side_note.initial_regs[index] = side_note.steps[0].regs_before[index];
        side_note.final_regs[index] = side_note.steps[2].regs_after[index];
    }
    side_note
}

fn load_u8_offset_one_side_note() -> SideNote {
    let code = vec![
        Opcode::LoadIndU8 as u8,
        0x12,
        1,
        0,
        0,
        0, // destination φ2, base φ1, offset 1
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[1] = u64::from(PVM_ZONE_SIZE - 1);
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new_conformance(pvm);
    let _ = tracing.run();
    let steps = tracing.into_trace();
    assert_eq!(steps.len(), 2, "load and terminal instruction");

    let mut side_note = SideNote::new(steps, code, bitmask);
    for index in 0..NUM_REGS {
        side_note.initial_regs[index] = side_note.steps[0].regs_before[index];
        side_note.final_regs[index] = side_note.steps[1].regs_after[index];
    }
    side_note
}

fn set_trace_cell(trace: &mut ComponentTrace, column: Column, index: usize, value: BaseField) {
    trace.original_trace[column.offset() + index].as_mut_slice()[0] = value;
}

/// Model a from-scratch prover claiming that a Standard memory instruction
/// completed at `address`.  Starting from an honest above-zone execution keeps
/// opcode decoding, PC flow, values and widths canonical; rewriting the base
/// register and access records makes the address equation self-consistent.
fn forge_completed_address(side_note: &mut SideNote, address: u32) {
    for step in &mut side_note.steps {
        step.regs_before[1] = u64::from(address);
        step.regs_after[1] = u64::from(address);
        if let Some(read) = &mut step.mem_read {
            read.address = address;
        }
        if let Some(write) = &mut step.mem_write {
            write.address = address;
        }
    }
    side_note.initial_regs[1] = u64::from(address);
    side_note.final_regs[1] = u64::from(address);
}

#[test]
fn standard_exact_zone_boundary_satisfies_cpu_air() {
    let mut side_note = store_load_u64_side_note(PVM_ZONE_SIZE, IsaMode::Conformance);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note)
        .expect("an access beginning exactly at 0x10000 must be accepted");
}

#[test]
fn standard_forged_completed_low_zone_access_is_rejected() {
    let mut side_note = store_load_u64_side_note(PVM_ZONE_SIZE, IsaMode::Conformance);
    forge_completed_address(&mut side_note, PVM_ZONE_SIZE - 8);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert!(
        assert_chip(&chip, &trace, &side_note).is_err(),
        "SOUNDNESS GAP: CpuChip accepted a completed Standard access below 0x10000"
    );
}

#[test]
fn standard_indirect_address_cannot_hide_low_zone_in_noncanonical_limbs() {
    let mut side_note = load_u8_offset_one_side_note();
    let chip = CpuChip;
    let mut trace = chip.generate_component_trace(&mut side_note);

    // Forge the field-valued indirect-address chain for
    // 0xffff_ffff + 1 = 0 while keeping the byte-level MemoryAccess tuple
    // canonical at address zero. Before the protected-zone predicate was
    // derived from that tuple, the raw limbs [256, 255, 255, -1] made its
    // apparent high word nonzero and bypassed the guard.
    for index in 0..8 {
        set_trace_cell(&mut trace, Column::ValB, index, BaseField::from(255u32));
    }
    for (index, value) in [
        BaseField::from(256u32),
        BaseField::from(255u32),
        BaseField::from(255u32),
        -BaseField::from(1u32),
    ]
    .into_iter()
    .enumerate()
    {
        set_trace_cell(&mut trace, Column::MemAddr, index, value);
    }
    for (index, value) in [0u32, 0, 0, 1].into_iter().enumerate() {
        set_trace_cell(
            &mut trace,
            Column::MemAddrCarry,
            index,
            BaseField::from(value),
        );
    }
    for column in [
        Column::MemByteAddrCarry1,
        Column::MemByteAddrCarry2,
        Column::MemByteAddrCarry3,
    ] {
        for index in 0..8 {
            set_trace_cell(&mut trace, column, index, BaseField::from(1u32));
        }
    }
    set_trace_cell(
        &mut trace,
        Column::MemLastAddrCarryH,
        0,
        BaseField::from(1u32),
    );

    // Solve the former raw-limb product exactly: (-1) * 256. The corrected
    // AIR instead derives canonical_high_word=0 from the byte-0 lookup and
    // rejects this nonzero witness.
    let former_product = -BaseField::from(256u32);
    set_trace_cell(&mut trace, Column::MemRangeProductH, 0, former_product);
    set_trace_cell(&mut trace, Column::MemRangeInv, 0, former_product.inverse());
    set_trace_cell(
        &mut trace,
        Column::MemRangeTimesInvH,
        0,
        BaseField::from(1u32),
    );

    assert!(
        assert_chip(&chip, &trace, &side_note).is_err(),
        "SOUNDNESS GAP: CpuChip accepted a low-zone access hidden in noncanonical address limbs"
    );
}

#[test]
fn standard_forged_completed_wrapping_access_is_rejected() {
    let mut side_note = store_load_u64_side_note(PVM_ZONE_SIZE, IsaMode::Conformance);
    forge_completed_address(&mut side_note, u32::MAX - 3);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert!(
        assert_chip(&chip, &trace, &side_note).is_err(),
        "SOUNDNESS GAP: CpuChip accepted a completed Standard u64 access wrapping through zero"
    );
}

#[test]
fn standard_nonwrapping_lower_24_bit_carry_satisfies_cpu_air() {
    let mut side_note = store_load_u64_side_note(PVM_ZONE_SIZE, IsaMode::Conformance);
    // Adding width - 1 carries from address byte 2 into byte 3, but does not
    // wrap the u32 address space. This distinguishes MemByteAddrCarry3 from
    // the final carry out of byte 3.
    forge_completed_address(&mut side_note, 0x00ff_ffff);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note)
        .expect("a lower-24-bit carry without u32 wrap must remain valid");
}

#[test]
fn jar_low_zone_access_preserves_frozen_cpu_air_behavior() {
    let mut side_note = store_load_u64_side_note(0x2000, IsaMode::Jar);
    let chip = CpuChip;
    let trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note)
        .expect("the Standard-only zone guard must not change frozen Jar memory semantics");
}
