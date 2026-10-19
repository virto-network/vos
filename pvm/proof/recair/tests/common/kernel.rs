//! A small kernel: a standard program that sets its io-hash in φ9..12 and
//! halts, traced from the loader's layout.

use vos_pvm_proof::program_id::ENTRY_TIMESTAMP;
use vos_pvm_recair::leaf::State;

/// The kernel's io-hash words, φ9..12; φ12's sign-extends, so its high
/// bytes are 0xff.
pub const IO: [u32; 4] = [0x4433_2211, 0x0807_0605, 0x7f00_00ff, 0x9abc_def0];

/// A standard program that sets φ8, the output's length, to 0 and φ9..12
/// to [`IO`], then returns to φ0, the halt address.
pub fn blob() -> Vec<u8> {
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    for (register, value) in [(8u8, 0u32)].into_iter().chain((9..13).zip(IO)) {
        code.extend_from_slice(&[51, register]);
        code.extend_from_slice(&value.to_le_bytes());
        bitmask.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    }
    code.extend_from_slice(&[50, 0]);
    bitmask.extend_from_slice(&[1, 0]);
    vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 1,
        stack_size: 4096,
        code: vos_pvm_program::CodeBlob {
            jump_table: vec![],
            code,
            bitmask,
        },
    })
    .expect("a standard program")
}

/// The state the kernel's run starts at, from the loader's layout.
pub fn entry(blob: &[u8]) -> State {
    let program = vos_pvm_program::parse_standard_program(blob).expect("standard");
    State {
        registers: program.layout(&[]).expect("lays out").registers,
        pc: 0,
        timestamp: ENTRY_TIMESTAMP,
        memory_root: program.image_root().expect("an image root"),
    }
}

/// The kernel's whole run proved as one segment under format 35, once a
/// test binary.
pub fn whole_run() -> &'static vos_pvm_proof::Proof {
    static WHOLE: std::sync::OnceLock<vos_pvm_proof::Proof> = std::sync::OnceLock::new();
    WHOLE.get_or_init(|| {
        let blob = blob();
        let trace = vos_pvm_proof::kernel::trace_kernel(&blob, &[], 1_000).expect("halts");
        let steps = trace.side_note.steps.len();
        let mut cursor = vos_pvm_proof::segment::SegmentCursor::new(&trace.side_note);
        vos_pvm_proof::prove_canonical_format(
            &mut cursor.side_note(0, steps),
            &[],
            &vos_pvm_proof::format::SEGMENT,
        )
        .expect("proves")
    })
}
