//! The device program `device_verify_bytes` verifies under, and the seeds
//! prove: a small kernel's, which reads 16 witness bytes, states a fixed
//! io-hash and halts, installed on a reference of 16 bytes.

use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::core::ecall::ECALL_WITNESS_INPUT;
use vos_pvm_recair::device::Program;

/// The words the kernel leaves in φ9..12, its io-hash.
const IO: [u32; 4] = [0x4433_2211, 0x0807_0605, 0x7f00_00ff, 0x1abc_def0];

/// The kernel's witness: 16 bytes.
pub const WITNESS: [u8; 16] = [7; 16];

/// The kernel.
fn kernel() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1)
        .add_imm_64(Reg::S0, Reg::SP, -16)
        .move_reg(Reg::A0, Reg::S0)
        .load_imm(Reg::A1, 16)
        .ecalli(ECALL_WITNESS_INPUT);
    for (register, word) in [Reg::A2, Reg::A3, Reg::A4, Reg::A5].into_iter().zip(IO) {
        asm.load_imm(register, word as i32);
    }
    for register in [Reg::A0, Reg::A1, Reg::S0] {
        asm.load_imm(register, 0);
    }
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

/// The program.
pub fn program() -> Program {
    Program::install(&kernel(), &WITNESS, 0).expect("the kernel installs")
}
