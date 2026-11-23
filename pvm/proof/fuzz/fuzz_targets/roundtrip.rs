//! A program's run proved and verified as `prove_verify_roundtrip` does it
//! and `examples/paths.rs` labels it: its code run on a machine whose one
//! page past the protected zone its registers may name, its precompile
//! calls served, the trace proved and verified against its own root; and
//! the code laid out as a kernel, run to its halt, proved in its shape's
//! segments, each verified against its class's root.

#![allow(dead_code)]

use arbitrary::Arbitrary;

use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{PVM_REGISTER_COUNT, PVM_ZONE_SIZE};

use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{kernel_side_note, trace_kernel, KernelTraceError};
use vos_pvm_proof::shape::KernelShape;
use vos_pvm_proof::{program_commitment_for_shape, prove, prove_kernel, SegmentError};
use vos_pvm_proof_verifier::verify_standalone;

/// Bounds for fuzz input — keep proving fast (single-digit seconds per
/// case) so the fuzzer covers ground.
pub const MAX_CODE_BYTES: usize = 64;
/// The machine's memory: the protected zone and one page past it, which a
/// register may name, so a load or a store completes.
pub const MEMORY_BYTES: usize = PVM_ZONE_SIZE as usize + 4096;
/// The gas a run gets: a looping program's trace stays a few thousand
/// steps, proved in seconds.
pub const GAS: vos_pvm::Gas = 2_000;

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    /// Raw program bytes — at most MAX_CODE_BYTES.
    pub code: Vec<u8>,
    /// Initial register state, truncated to the register count.
    pub regs: Vec<u64>,
    /// Which bytes start an instruction, the low bit of each; past its end,
    /// and when empty, every byte does, so the fuzzer need not learn the
    /// bitmask's format, and an operand is read only where it is given.
    pub bitmask: Vec<u8>,
}

/// `input`'s `arbitrary` encoding, which [`FuzzInput`] decodes back: each
/// element of a list after a byte of low bit 1, the list closed by a 0.
pub fn encode(input: &FuzzInput) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &byte in &input.code {
        bytes.extend([1, byte]);
    }
    bytes.push(0);
    for &register in &input.regs {
        bytes.push(1);
        bytes.extend(register.to_le_bytes());
    }
    bytes.push(0);
    for &byte in &input.bitmask {
        bytes.extend([1, byte]);
    }
    bytes
}

/// What a run of `input` reached: a verdict each of its two runs, and
/// what its raw run touched.
pub fn run(input: &FuzzInput) -> Vec<String> {
    let mut code = input.code.clone();
    code.truncate(MAX_CODE_BYTES);
    if code.is_empty() {
        return vec!["no code".into()];
    }
    let mut bitmask: Vec<u8> = (0..code.len())
        .map(|i| input.bitmask.get(i).map_or(1, |byte| byte & 1))
        .collect();
    bitmask[0] = 1;
    // A trap last, its own instruction, so the interpreter exits cleanly.
    if code.last() != Some(&(Opcode::Trap as u8)) {
        if code.len() == MAX_CODE_BYTES {
            *code.last_mut().unwrap() = Opcode::Trap as u8;
            *bitmask.last_mut().unwrap() = 1;
        } else {
            code.push(Opcode::Trap as u8);
            bitmask.push(1);
        }
    }
    let mut verdicts = raw(&code, &bitmask, &input.regs);
    verdicts.extend(kernel(&code, &bitmask));
    verdicts
}

/// The raw run: proved over its natural shape, verified against its root.
fn raw(code: &[u8], bitmask: &[u8], regs: &[u64]) -> Vec<String> {
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    for (slot, &value) in registers.iter_mut().zip(regs) {
        *slot = value;
    }
    let pvm = Interpreter::new(
        code.to_vec(),
        bitmask.to_vec(),
        vec![],
        registers,
        vec![0u8; MEMORY_BYTES],
        GAS,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run_with_precompiles();
    let mut side_note = tracing
        .into_side_note()
        .with_memory(vec![0u8; MEMORY_BYTES]);
    if side_note.steps.is_empty() {
        return vec!["raw: no step".into()];
    }
    let mut verdicts = Vec::new();
    if side_note
        .steps
        .iter()
        .any(|step| step.mem_read.is_some() || step.mem_write.is_some())
    {
        verdicts.push("raw: a memory access".into());
    }
    if !side_note.blake2b_mem_ops.is_empty() || !side_note.poseidon2_ops.is_empty() {
        verdicts.push("raw: a precompile".into());
    }
    match prove(&mut side_note) {
        Ok(proof) => {
            let root = proof
                .preprocessed_commitment()
                .expect("a preprocessed root");
            verify_standalone(proof, root).expect("an honest raw proof verifies");
            verdicts.push("raw: proved".into());
        }
        Err(error) => verdicts.push(format!("raw: {}", refused(&error))),
    }
    verdicts
}

/// The code laid out as a kernel and run to its halt: proved in its shape's
/// segments, each verified against its class's root.
fn kernel(code: &[u8], bitmask: &[u8]) -> Vec<String> {
    let Some(blob) = kernel_blob(code, bitmask) else {
        return vec!["kernel: not a standard program".into()];
    };
    let trace = match trace_kernel(&blob, &[], GAS) {
        Ok(trace) => trace,
        Err(error) => return vec![format!("kernel: {}", traced(&error))],
    };
    let mut verdicts = Vec::new();
    if !trace.side_note.blake2b_mem_ops.is_empty() || !trace.side_note.poseidon2_ops.is_empty() {
        verdicts.push("kernel: a precompile".into());
    }
    let shape = vos_pvm_compiler::shape::kernel_shape(&blob)
        .and_then(|record| KernelShape::try_from(&record).ok())
        .expect("a traced kernel's shape");
    let program = kernel_side_note(&blob).expect("a traced kernel's program");
    let segments = match prove_kernel(&trace.side_note, &shape, 1, &SEGMENT) {
        Ok(segments) => segments,
        Err(error) => {
            verdicts.push(format!("kernel: {}", refused(&error)));
            return verdicts;
        }
    };
    for segment in segments {
        let class = shape.segment(segment.class).expect("a class");
        let root = program_commitment_for_shape(&program, &class, &SEGMENT).expect("its root");
        verify_standalone(segment.proof, root).expect("an honest segment verifies");
    }
    verdicts.push("kernel: proved".into());
    verdicts
}

/// `code` laid out as a kernel: a heap page and a stack page, no data.
fn kernel_blob(code: &[u8], bitmask: &[u8]) -> Option<Vec<u8>> {
    vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 1,
        stack_size: 4096,
        code: vos_pvm_program::CodeBlob {
            jump_table: vec![],
            code: code.to_vec(),
            bitmask: bitmask.to_vec(),
        },
    })
}

/// A trace's refusal, by its variant.
fn traced(error: &KernelTraceError) -> String {
    let debug = format!("{error:?}");
    debug
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or(&debug)
        .to_owned()
}

/// A proof's refusal, by its kind, and only the kinds an honest trace of
/// this target may meet: a static jump to the halt address, a run stopped
/// where no proof ends one (a fault, a panic at a transfer, out of gas but
/// at a trap or a host call), a window no class holds or more segments
/// than the gas buys. Any other, an honest trace's constraints unsatisfied
/// among them, is a bug of the prover, and panics.
fn refused(error: &SegmentError) -> String {
    match error {
        SegmentError::Transfer => "transfer".into(),
        SegmentError::Stop => "stop".into(),
        SegmentError::Shape { overflow: true, .. } => "shape".into(),
        SegmentError::Segments => "segments".into(),
        other => panic!("an honest trace refused: {other:?}"),
    }
}

/// The seeds a corpus of this target starts from beside the fuzzer's: a raw
/// run that loads, stores and compresses in the page past the zone, a
/// kernel that compresses in its heap and halts, a static jump to the
/// halt address, which no proof takes, and raw runs that stop where no
/// proof ends one: a load in the protected zone, a branch to no block
/// start, a dynamic jump to no table entry and a loop out of gas at an
/// addition. Each its name and its encoding.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    use vos_pvm_compiler::assembler::{Assembler, Reg};
    let parts = |asm: &mut Assembler| {
        let blob = asm.build();
        let program = vos_pvm_program::parse_standard_program(&blob).expect("a standard program");
        (program.code.code, program.code.bitmask)
    };
    let page = u64::from(PVM_ZONE_SIZE);
    let mut raw = Assembler::new();
    raw.load_ind_u64(Reg::T0, Reg::S0, 0)
        .store_ind_u64(Reg::T0, Reg::S0, 128)
        .ecalli(vos_pvm::precompile::BLAKE2B_COMPRESS as u32)
        .trap();
    let (code, bitmask) = parts(&mut raw);
    let mut regs = vec![0u64; PVM_REGISTER_COUNT];
    regs[Reg::S0 as usize] = page;
    regs[Reg::A0 as usize] = page;
    regs[Reg::A1 as usize] = page + 64;
    let raw = FuzzInput {
        code,
        regs,
        bitmask,
    };

    let heap = kernel_blob(&[0], &[1])
        .and_then(|blob| {
            Some(
                vos_pvm_program::parse_standard_program(&blob)?
                    .layout(&[])?
                    .rw
                    .base,
            )
        })
        .expect("a kernel's layout");
    let mut kernel = Assembler::new();
    kernel
        .load_imm_64(Reg::A0, heap)
        .load_imm_64(Reg::A1, heap + 64)
        .ecalli(vos_pvm::precompile::BLAKE2B_COMPRESS as u32);
    for register in [Reg::A0, Reg::A1] {
        kernel.load_imm(register, 0);
    }
    kernel.jump_ind(Reg::RA, 0);
    let (code, bitmask) = parts(&mut kernel);
    let kernel = FuzzInput {
        code,
        regs: vec![],
        bitmask,
    };
    // A static jump to the halt address, `PVM_HALT_ADDR` as the offset from
    // the code's start: the raw run halts and its proof is refused.
    let halt = FuzzInput {
        code: [
            &[Opcode::Jump as u8][..],
            &(vos_pvm::PVM_HALT_ADDR as u32).to_le_bytes(),
        ]
        .concat(),
        regs: vec![],
        bitmask: vec![1, 0, 0, 0, 0],
    };
    let stop = |code: Vec<u8>, regs: Vec<u64>, bitmask: Vec<u8>| {
        encode(&FuzzInput {
            code,
            regs,
            bitmask,
        })
    };
    // φ0 + 0, in the zone.
    let zone_load = stop(vec![Opcode::LoadIndU64 as u8], vec![], vec![]);
    // A load of φ5's page, past the zone, completes (its register byte is
    // the branch's opcode); the branch after it names itself, which follows
    // no terminator.
    let branch = stop(
        vec![Opcode::LoadIndU64 as u8, Opcode::BranchNeImm as u8],
        vec![0, 0, 0, 0, 0, page],
        vec![],
    );
    // A jump to φ0 = 7, which no table entry holds.
    let dynamic_jump = stop(vec![Opcode::JumpInd as u8, 0], vec![7], vec![1, 0]);
    // φ0 += 1 and back, until the gas runs out at the addition.
    let out_of_gas = stop(
        [
            &[Opcode::AddImm64 as u8, 0, 1, Opcode::Jump as u8][..],
            &(-3i32).to_le_bytes(),
        ]
        .concat(),
        vec![],
        vec![1, 0, 0, 1, 0, 0, 0, 0],
    );
    vec![
        ("memory-and-blake2b", encode(&raw)),
        ("kernel-blake2b", encode(&kernel)),
        ("static-jump-to-halt", encode(&halt)),
        ("stop-zone-load", zone_load),
        ("stop-branch", branch),
        ("stop-dynamic-jump", dynamic_jump),
        ("stop-out-of-gas", out_of_gas),
    ]
}
