//! An install's record of a kernel's shape, refused where a venue building
//! its leaves would otherwise panic.

use vos_abi::ids::{MethodId, ProgramHash};
use vos_abi::records::{Kernel, SegmentClass};
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_proof::chip_idx;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::program_id::KernelError;
use vos_pvm_proof::shape::{KernelShape, ShapeError};

/// A kernel counting to 1,000, its code more than a lane's 16 bytes.
fn blob() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_heap_pages(1).set_stack_pages(1);
    asm.load_imm(Reg::T2, 0).fallthrough();
    let start = asm.current_offset();
    asm.add_imm_64(Reg::T2, Reg::T2, 1);
    let here = asm.current_offset();
    asm.branch_lt_u_imm(Reg::T2, 1000, start.wrapping_sub(here));
    for register in [Reg::A0, Reg::A1, Reg::T2] {
        asm.load_imm(register, 0);
    }
    asm.jump_ind(Reg::RA, 0);
    asm.build()
}

fn record(blob: &[u8]) -> Kernel {
    Kernel {
        method: MethodId(1),
        program: ProgramHash::of(blob),
        image_root: vos_pvm_program::parse_standard_program(blob)
            .and_then(|program| program.image_root())
            .expect("a standard program"),
        shape: vos_pvm_compiler::shape::kernel_shape(blob).expect("a standard program"),
    }
}

/// Every class of `blob`'s record changed by `change`.
fn changed(blob: &[u8], change: &dyn Fn(&mut SegmentClass)) -> Kernel {
    let mut record = record(blob);
    record.shape.classes.iter_mut().for_each(change);
    record
}

/// A record a venue builds its leaves from is refused, never panicked on:
/// a class of no page, of a step shift past a word, of a fixed table short
/// of its entries, of a code larger than its chip, or whose proofs count
/// below the format's security floor (refused before its preprocessed
/// root's columns are generated).
#[test]
fn a_hostile_install_record_is_refused() {
    let blob = blob();
    let refusal = |change: &dyn Fn(&mut SegmentClass)| {
        vos_pvm_recair::leaf::kernel_program(
            &blob,
            &changed(&blob, change),
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .map(|_| ())
    };
    assert_eq!(refusal(&|_| {}), Ok(()));
    assert_eq!(
        refusal(&|class| class.pages = 0),
        Err(KernelError::Shape(ShapeError::Pages))
    );
    assert_eq!(
        refusal(&|class| class.log_steps = 64),
        Err(KernelError::Shape(ShapeError::Steps))
    );
    assert_eq!(
        refusal(&|class| class.log_sizes[chip_idx::POWER_OF_TWO] = 4),
        Err(KernelError::Shape(ShapeError::Table))
    );
    assert_eq!(
        refusal(&|class| class.log_sizes[chip_idx::PROGRAM_MEMORY] = 4),
        Err(KernelError::Preprocessed)
    );
    let tall = |class: &mut SegmentClass| {
        for size in class.log_sizes.iter_mut().filter(|size| **size != 0) {
            *size = 22;
        }
    };
    assert_eq!(refusal(&tall), Err(KernelError::Preprocessed));
    let shape = KernelShape::try_from(&changed(&blob, &tall).shape).expect("a shape that cuts");
    assert_eq!(shape.check_security(&SEGMENT), Err(ShapeError::Security));
}
