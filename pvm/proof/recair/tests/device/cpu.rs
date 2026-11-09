//! The per-program CPU (`docs/design/proving.md` §8): a device program's
//! CPU cut to the columns its code sets, under a format that takes it
//! (`Cpu::PerProgram`); its columns the program's, bound by its id and its
//! transcript, and an instruction its code does not hold unprovable under
//! it.

use stwo::core::channel::MerkleChannel;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use vos_pvm::instruction::Opcode;
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::chips::CpuColumns;
use vos_pvm_proof::core::ecall::{ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
use vos_pvm_proof::format::ChannelKind;
use vos_pvm_proof::format::{Cpu, Format};
use vos_pvm_recair::device::program_id;
use vos_pvm_recair::masked::device::{DeviceProgram, prove_device_forced, verify_device};
use vos_pvm_recair::masked::{Checks, MaskRng};

use crate::support::{
    HEAP, RO_BASE, RW_BASE, blob, io_and_halt, program, prove, run, small_format, verify, witness,
};

type B2 = Blake2sM31MerkleChannel;
type Program = DeviceProgram<<B2 as MerkleChannel>::H>;

/// The device tests' small format on Blake2s-M31 with the per-program
/// CPU.
fn per_program() -> Format {
    Format {
        cpu: Cpu::PerProgram,
        ..full()
    }
}

/// The device tests' small format on Blake2s-M31 with the full CPU.
fn full() -> Format {
    Format {
        cpu: Cpu::Full,
        ..small_format(ChannelKind::Blake2sM31, 6, 4)
    }
}

/// [`blob`] with a division before its halt: a kernel whose code holds an
/// opcode [`blob`]'s does not, and so CPU columns it lacks.
fn dividing() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_ro_data(crate::support::RO_DATA.to_vec())
        .set_rw_data(crate::support::RW_DATA.to_vec())
        .set_heap_pages(1)
        .set_stack_pages(1);
    asm.add_imm_64(Reg::S0, Reg::SP, -128)
        .move_reg(Reg::A0, Reg::S0)
        .load_imm(Reg::A1, 64)
        .ecalli(ECALL_WITNESS_INPUT)
        .move_reg(Reg::A0, Reg::S0)
        .add_imm_64(Reg::A1, Reg::S0, 64)
        .ecalli(ECALL_POSEIDON2)
        .load_u8(Reg::T0, RO_BASE + 3)
        .load_u64(Reg::T1, RW_BASE)
        .store_u64(Reg::T1, HEAP + 8);
    // T2 = T1 / T0, a word of the data over a byte of it.
    asm.emit_raw(Opcode::DivU64 as u8, true);
    asm.emit_raw(Reg::T1 as u8 | (Reg::T0 as u8) << 4, false);
    asm.emit_raw(Reg::T2 as u8, false);
    io_and_halt(&mut asm);
    asm.build()
}

/// A kernel's run proves and verifies under its per-program CPU, every
/// witness under one program, the CPU narrower than the full one and the
/// code's own; the full CPU's program of the same kernel is another
/// program, by its id and its transcript, and neither verifies the other's
/// proofs.
#[test]
fn a_per_program_cpu_proves_its_kernel() {
    let narrow = program::<B2>(&per_program(), &blob());
    let code = vos_pvm_proof::kernel::kernel_side_note(&blob()).expect("a kernel");
    assert_eq!(narrow.cpu, CpuColumns::of_code(&code.code, &code.bitmask));
    assert!(narrow.cpu.width() < CpuColumns::ALL.width());
    for seed in [1, 2] {
        let (proof, _) = prove::<B2>(
            &per_program(),
            &narrow,
            &blob(),
            &witness(seed),
            MaskRng::Seeded(seed),
        )
        .expect("proves");
        verify::<B2>(&per_program(), &narrow, &proof).expect("verifies");
    }
    let whole_cpu = program::<B2>(&full(), &blob());
    assert_eq!(whole_cpu.cpu, CpuColumns::ALL);
    assert_eq!(whole_cpu.circuit, narrow.circuit);
    assert_ne!(
        program_id(&full(), &whole_cpu),
        program_id(&per_program(), &narrow)
    );
    assert_ne!(whole_cpu.header(), narrow.header());
    let (cut, _) = prove::<B2>(
        &per_program(),
        &narrow,
        &blob(),
        &witness(1),
        MaskRng::Seeded(3),
    )
    .expect("proves");
    let (whole, _) = prove::<B2>(
        &full(),
        &whole_cpu,
        &blob(),
        &witness(1),
        MaskRng::Seeded(3),
    )
    .expect("proves");
    assert!(verify::<B2>(&full(), &whole_cpu, &cut).is_err());
    assert!(verify::<B2>(&per_program(), &narrow, &whole).is_err());
}

/// A program's id and transcript name its CPU: the kernel's program with
/// another kernel's columns is another id, and a proof under either is
/// refused under the other, though the runs and the code are the same.
#[test]
fn a_program_with_another_programs_cpu_is_another_program() {
    let narrow = program::<B2>(&per_program(), &blob());
    let other = program::<B2>(&per_program(), &dividing());
    assert_ne!(other.cpu, narrow.cpu);
    assert!(other.cpu.covers(&narrow.cpu));
    let borrowed = Program {
        cpu: other.cpu,
        ..narrow.clone()
    };
    assert_ne!(
        program_id(&per_program(), &borrowed),
        program_id(&per_program(), &narrow)
    );
    let (honest, _) = prove::<B2>(
        &per_program(),
        &narrow,
        &blob(),
        &witness(1),
        MaskRng::Seeded(5),
    )
    .expect("proves");
    let (wider, _) = prove::<B2>(
        &per_program(),
        &borrowed,
        &blob(),
        &witness(1),
        MaskRng::Seeded(5),
    )
    .expect("proves under the wider CPU");
    verify::<B2>(&per_program(), &borrowed, &wider).expect("verifies under its own CPU");
    assert!(verify::<B2>(&per_program(), &narrow, &wider).is_err());
    assert!(verify::<B2>(&per_program(), &borrowed, &honest).is_err());
}

/// An instruction outside the program's CPU is refused: the dividing
/// kernel's run proved under its own code but [`blob`]'s CPU, which has
/// no division's columns. Its division's flags, which its code fixes, are
/// not the cut columns' zeros: the verifier refuses its proof, the honest
/// prover's and one forced past the prover's check.
#[test]
fn an_instruction_outside_the_programs_cpu_is_refused() {
    let honest = program::<B2>(&per_program(), &dividing());
    let narrow = program::<B2>(&per_program(), &blob()).cpu;
    assert!(!narrow.covers(&honest.cpu));
    let forged = Program {
        cpu: narrow,
        ..honest.clone()
    };
    let side_note = || run(&dividing(), &witness(1));
    if let Ok((proof, _)) = prove::<B2>(
        &per_program(),
        &forged,
        &dividing(),
        &witness(1),
        MaskRng::Seeded(7),
    ) {
        assert!(verify::<B2>(&per_program(), &forged, &proof).is_err());
    }
    let (proof, _) = prove_device_forced::<B2>(
        &per_program(),
        &forged,
        &mut side_note(),
        MaskRng::Seeded(7),
        |_| {},
        |_, _| {},
        Checks {
            constraints: false,
            public_unblinded: true,
        },
    )
    .expect("a forced proof");
    assert!(verify_device::<B2>(&per_program(), &forged, &proof).is_err());
    let (proof, _) = prove::<B2>(
        &per_program(),
        &honest,
        &dividing(),
        &witness(1),
        MaskRng::Seeded(7),
    )
    .expect("proves under its own CPU");
    verify::<B2>(&per_program(), &honest, &proof).expect("verifies");
}
