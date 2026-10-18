//! Test helpers shared across the test binaries (`gates`, `isa`, `kernel`),
//! each of which includes this module as `common`.

#![allow(dead_code)]

/// The venue's JAM refine program on the JAM-only host.
#[path = "../../statement/tests/support/jam.rs"]
pub mod jam;

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;

use vos_pvm_proof::core::step::PvmStep;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::{prove, verify};

/// Default flat memory size used by every helper here.  4 MB is enough for
/// every existing test program; bump per-call if a future test needs more.
const DEFAULT_FLAT_MEM: usize = 4 * 1024 * 1024;

/// Default gas + max-steps that programs run with.  Generous because tests
/// typically have ≤ 50 steps.
const DEFAULT_GAS: u64 = 10_000;

/// Encode a TwoReg instruction at `code[0..2]`: opcode byte then a packed
/// register byte where `rd` lands in the low 4 bits and `ra` in the high 4.
/// JAVM's TwoReg category covers all the BitManip ops, MoveReg, and the
/// 2-arg variants that don't take an immediate.
///
/// The returned `(code, bitmask)` ends with `Trap` so the trace terminates
/// cleanly.  Bitmask follows `[1, 0, 1]`: byte 0 starts a basic block (the
/// real op), byte 1 is the inline reg byte (not a basic-block start),
/// byte 2 starts the next basic block (Trap).
pub fn two_reg_program(op: Opcode, rd: u8, ra: u8) -> (Vec<u8>, Vec<u8>) {
    assert!(rd < 13, "rd out of range (PVM has 13 registers)");
    assert!(ra < 13, "ra out of range (PVM has 13 registers)");
    let reg_byte = (ra << 4) | (rd & 0xF);
    let code = vec![op as u8, reg_byte, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 1];
    (code, bitmask)
}

/// Run a program in the tracing interpreter and return the recorded steps.
/// Asserts the standard interpreter exits with `Panic` after recording the
/// terminal opcode-0 (`Trap`) row.
pub fn trace_until_opcode_zero(
    code: Vec<u8>,
    bitmask: Vec<u8>,
    regs: [u64; PVM_REGISTER_COUNT],
) -> Vec<PvmStep> {
    let pvm = Interpreter::new(
        code,
        bitmask,
        vec![],
        regs,
        vec![0u8; DEFAULT_FLAT_MEM],
        DEFAULT_GAS,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(
        exit,
        vos_pvm::ExitReason::Panic,
        "expected standard Panic exit"
    );
    tracing.into_trace()
}

/// Build a side note from steps + code + bitmask, then prove and verify.
/// Panics if either side fails — this is the positive-test happy path.
pub fn prove_and_verify(steps: Vec<PvmStep>, code: &[u8], bitmask: &[u8]) {
    let mut side_note = vos_pvm_proof::SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    let proof = prove(&mut side_note).expect("proving failed");
    verify(proof, &side_note).expect("verification failed");
}

/// Convenience: trace a TwoReg program with `regs[ra] = input`, then run
/// `prove_and_verify`.  Asserts `regs_after[rd] == expected`.
pub fn prove_two_reg(op: Opcode, rd: u8, ra: u8, input: u64, expected: u64) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input;
    let (code, bitmask) = two_reg_program(op, rd, ra);
    let steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    assert_eq!(
        steps[0].regs_after[rd as usize], expected,
        "{op:?} φ[{rd}] = 0x{:x}, expected 0x{expected:x}",
        steps[0].regs_after[rd as usize]
    );
    prove_and_verify(steps, &code, &bitmask);
}

/// Make register `reg` hold `forged` after the first step, in that step
/// and every later one, as a prover forging the step's result does: the
/// register ledger and the closing state then agree with the forgery, so
/// only the step's own constraints can refuse it.
pub fn forge_first_result(steps: &mut [PvmStep], reg: usize, forged: u64) {
    assert_ne!(steps[0].regs_after[reg], forged, "the forgery must differ");
    steps[0].regs_after[reg] = forged;
    for step in steps.iter_mut().skip(1) {
        step.regs_before[reg] = forged;
        step.regs_after[reg] = forged;
    }
}

/// Convenience for negative tests: trace a TwoReg program, forge `rd`'s
/// result (`forge_first_result`), then attempt prove + verify.
/// Caller wraps in `#[should_panic(expected = "ConstraintsNotSatisfied")]`.
pub fn forge_two_reg_result(op: Opcode, rd: u8, ra: u8, input: u64, forged: u64) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input;
    let (code, bitmask) = two_reg_program(op, rd, ra);
    let mut steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    forge_first_result(&mut steps, rd as usize, forged);
    prove_and_verify(steps, &code, &bitmask);
}

/// Negative-test helper: trace a TwoReg program, mutate one of
/// `steps[0]`'s instruction-tuple columns (opcode/imm/reg_a/reg_b/reg_d/
/// skip_len), then prove + verify.  The ProgramMemory consumer demands a
/// tuple matching the canonical decoding of `code` at the step's PC, so
/// any mismatch should make verification fail.  Caller wraps in
/// `#[should_panic(expected = "ConstraintsNotSatisfied")]`.
pub fn forge_step_field<F>(op: Opcode, rd: u8, ra: u8, input: u64, mutate: F)
where
    F: FnOnce(&mut PvmStep),
{
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input;
    let (code, bitmask) = two_reg_program(op, rd, ra);
    let mut steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    mutate(&mut steps[0]);
    prove_and_verify(steps, &code, &bitmask);
}

/// Encode a ThreeReg instruction at `code[0..3]`: opcode + reg_byte (rb in hi
/// nibble, ra in lo nibble) + rd byte.  Used by ALU ops (Add64, Sub64, Mul64,
/// And, Or, Xor, shift, compare).  Returns (code, bitmask) ending with Trap.
pub fn three_reg_program(op: Opcode, rd: u8, ra: u8, rb: u8) -> (Vec<u8>, Vec<u8>) {
    assert!(
        rd < 13 && ra < 13 && rb < 13,
        "reg out of range (PVM has 13 regs)"
    );
    let reg_byte = (rb << 4) | (ra & 0xF);
    let code = vec![op as u8, reg_byte, rd, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    (code, bitmask)
}

/// Trace a ThreeReg program with the given registers.
pub fn trace_three_reg(
    op: Opcode,
    rd: u8,
    ra: u8,
    rb: u8,
    regs: [u64; PVM_REGISTER_COUNT],
) -> Vec<PvmStep> {
    let (code, bitmask) = three_reg_program(op, rd, ra, rb);
    trace_until_opcode_zero(code, bitmask, regs)
}

/// Trace a ThreeReg program with given (input_a, input_b) in the source
/// registers, then prove+verify.  Asserts the destination register holds
/// `expected`.
pub fn prove_three_reg(
    op: Opcode,
    rd: u8,
    ra: u8,
    rb: u8,
    input_a: u64,
    input_b: u64,
    expected: u64,
) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input_a;
    regs[rb as usize] = input_b;
    let (code, bitmask) = three_reg_program(op, rd, ra, rb);
    let steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    assert_eq!(
        steps[0].regs_after[rd as usize], expected,
        "{op:?} φ[{rd}] = 0x{:x}, expected 0x{expected:x}",
        steps[0].regs_after[rd as usize]
    );
    prove_and_verify(steps, &code, &bitmask);
}

/// Negative test for ThreeReg ops: trace, forge `rd`'s result
/// (`forge_first_result`), prove+verify.
pub fn forge_three_reg_result(
    op: Opcode,
    rd: u8,
    ra: u8,
    rb: u8,
    input_a: u64,
    input_b: u64,
    forged: u64,
) {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = input_a;
    regs[rb as usize] = input_b;
    let (code, bitmask) = three_reg_program(op, rd, ra, rb);
    let mut steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    forge_first_result(&mut steps, rd as usize, forged);
    prove_and_verify(steps, &code, &bitmask);
}

/// A kernel's program under `format`, as its install records the kernel:
/// each class's preprocessed root computed from its code alone.
pub fn kernel_program(
    blob: &[u8],
    record: &vos_wire::records::Kernel,
    format: &'static vos_pvm_proof::format::Format,
) -> vos_pvm_proof::program_id::KernelProgram {
    let shape =
        vos_pvm_proof::shape::KernelShape::try_from(&record.shape).expect("an install's shape");
    let side_note = vos_pvm_proof::kernel::kernel_side_note(blob).expect("a standard program");
    let preprocessed_roots = (0..shape.classes.len())
        .map(|class| {
            vos_pvm_proof::program_commitment_for_shape(
                &side_note,
                &shape.segment(class).expect("a class"),
                format,
            )
            .expect("the class's root")
        })
        .collect();
    vos_pvm_proof::program_id::KernelProgram {
        transpiler: vos_pvm_compiler::TRANSPILER_VERSION,
        program: record.program.0,
        shape,
        format: format.number,
        preprocessed_roots,
        image_root: record.image_root,
        leaf_circuits: vos_pvm_proof::program_id::LeafCircuits::None,
    }
}

/// The system allocator, counting the bytes allocated and their peak: a
/// test binary that measures a prover's memory installs it as its global
/// allocator. A resident-set figure would miss memory the allocator keeps
/// from an earlier proof and hands to the next.
pub struct Counting;

static ALLOCATED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        use std::sync::atomic::Ordering::Relaxed;
        // SAFETY: the caller's contract for `GlobalAlloc::alloc`.
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        if !pointer.is_null() {
            let allocated = ALLOCATED.fetch_add(layout.size(), Relaxed) + layout.size();
            PEAK.fetch_max(allocated, Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: the caller's contract for `GlobalAlloc::dealloc`.
        unsafe { std::alloc::System.dealloc(pointer, layout) };
        ALLOCATED.fetch_sub(layout.size(), std::sync::atomic::Ordering::Relaxed);
    }
}

/// `work`'s result, its time, and its peak heap past the allocations
/// before it, in MiB (0 unless the binary installs [`Counting`]).
pub fn measured<T>(work: impl FnOnce() -> T) -> (T, std::time::Duration, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    let base = ALLOCATED.load(Relaxed);
    PEAK.store(base, Relaxed);
    let started = std::time::Instant::now();
    let result = work();
    let elapsed = started.elapsed();
    (result, elapsed, ((PEAK.load(Relaxed) - base) >> 20) as u64)
}

/// What a node, a leaf or a fold, measured: its rows, its proving time and its peak
/// heap over the allocations before it (0 unless the binary installs
/// [`Counting`]); the node, its proof and the output it states.
pub struct NodeRun {
    pub rows: [usize; 3],
    pub finalized: [usize; 3],
    pub proving: std::time::Duration,
    pub peak_mib: u64,
    pub node: vos_pvm_recair::tree::Node,
}

/// `proof`, a segment of `program`'s class `class`, verified in its leaf at
/// `position` under the fold word `fold_word`, as natively (its transcript
/// the native recorder's, permutation for permutation, and no mismatch);
/// the leaf within the padded shape, its circuit's hash the program's for
/// the class, proved and verified, its public output the native output's
/// digest.
pub fn prove_leaf(
    program: &vos_pvm_proof::program_id::KernelProgram,
    entry: &vos_pvm_proof::program_id::KernelEntry,
    class: usize,
    proof: &vos_pvm_proof::Proof,
    position: u32,
    fold_word: vos_pvm_proof::poseidon2::P2Hash,
) -> NodeRun {
    use stwo::core::fields::qm31::SecureField;
    use vos_pvm_proof::poseidon2::P2Hash;
    use vos_pvm_proof::program_id::LeafCircuits;
    use vos_pvm_recair::leaf::{LeafCircuit, PADDED_ROWS};
    use vos_pvm_recair::verifier::witness::digest_wires;

    let leaf = LeafCircuit::of_class(program, entry, class);
    let (values, output) = leaf
        .values(proof, P2Hash(program.id().0), fold_word, position)
        .expect("the segment's values");

    let mut transcript = vos_pvm_recair::Context::<SecureField>::new();
    let verified =
        vos_pvm_recair::verifier::verify_segment(&mut transcript, &leaf.shape, &values.segment);
    let records = vos_pvm_proof::extract_recursion_data(proof)
        .transcript
        .records;
    let permutations = verified.channel.transcript().permutations();
    assert_eq!(permutations.len(), records.len());
    for (i, (permutation, record)) in permutations.iter().zip(&records).enumerate() {
        let words = record.output.map(|w| vos_pvm_poseidon2::M31::new(w.0));
        assert_eq!(
            *permutation,
            vos_pvm_recair::value::wires_of(words),
            "permutation {i}"
        );
    }
    drop(transcript);

    let context = leaf.build(&values);
    let rows = context.rows();
    assert!(
        rows.iter()
            .zip(PADDED_ROWS)
            .all(|(&rows, padded)| rows <= padded),
        "{rows:?}"
    );
    // A derivation's bound: the built rows exactly, and the finalizing's
    // within its allowance.
    let mut sizes = program.shape.classes[class].log_sizes.iter();
    let record: [u8; 25] = core::array::from_fn(|chip| {
        if program.shape.components & 1 << chip != 0 {
            *sizes.next().expect("a size a chip")
        } else {
            0
        }
    });
    let terms = vos_pvm_compiler::leaf::leaf_terms(program.shape.components, &record);
    assert_eq!(terms.rows(), rows, "the derivation's rows");
    let finalized = context.finalized_rows();
    assert!(
        finalized[1] - rows[1] <= vos_pvm_compiler::leaf::FINALIZE,
        "{finalized:?} against {rows:?}"
    );
    assert_eq!([finalized[0], finalized[2]], [rows[0], rows[2]]);
    let filled = context
        .finalize_to(Some(PADDED_ROWS))
        .expect("the wiring checks");
    let (_, hash) = vos_pvm_recair::circuit_commitment(&filled.circuit).expect("checks");
    let LeafCircuits::Hashes(hashes) = &program.leaf_circuits else {
        panic!("a program with its leaf circuits")
    };
    assert_eq!(
        hashes[class].0.map(|word| word.0),
        hash.map(|word| word.value()),
        "the class's leaf circuit"
    );

    let (leaf_proof, proving, peak_mib) =
        measured(|| vos_pvm_recair::prove(&filled.circuit, &filled.witness).expect("proves"));
    assert_eq!(
        leaf_proof.outputs,
        digest_wires(&output.digest()).to_vec(),
        "the leaf states the native output"
    );
    vos_pvm_recair::verify(leaf_proof.clone(), &hash).expect("the leaf verifies");
    NodeRun {
        rows,
        finalized,
        proving,
        peak_mib,
        node: vos_pvm_recair::tree::Node {
            proof: leaf_proof,
            output,
        },
    }
}

/// The fold of `left` and `right`, nodes of `program`'s run under the fold
/// word `fold_word`, the fold circuit's hash: verified as natively (no
/// mismatch), within the padded shape, proved and verified against
/// `fold_word`, its public output the native output's digest. Its rows
/// finalized, proving time and peak heap (0 unless the binary installs
/// [`Counting`]), its proof and output.
pub fn prove_fold(
    fold: &vos_pvm_recair::fold::FoldCircuit,
    program: &vos_pvm_proof::program_id::KernelProgram,
    left: &NodeRun,
    right: &NodeRun,
    fold_word: vos_pvm_proof::poseidon2::P2Hash,
) -> NodeRun {
    use vos_pvm_recair::leaf::PADDED_ROWS;
    use vos_pvm_recair::verifier::witness::digest_wires;

    let (values, output) = fold
        .values(
            left.node.proved(),
            right.node.proved(),
            &program.id_preimage(),
            fold_word,
        )
        .expect("the children's values");
    let context = fold.build(&values);
    let rows = context.rows();
    let finalized = context.finalized_rows();
    let filled = context
        .finalize_to(Some(PADDED_ROWS))
        .expect("the wiring checks");
    let (fold_proof, proving, peak_mib) =
        measured(|| vos_pvm_recair::prove(&filled.circuit, &filled.witness).expect("proves"));
    assert_eq!(
        fold_proof.outputs,
        digest_wires(&output.digest()).to_vec(),
        "the fold states the native output"
    );
    let hash = fold_word.0.map(|word| vos_pvm_poseidon2::M31::new(word.0));
    vos_pvm_recair::verify(fold_proof.clone(), &hash).expect("the fold verifies");
    NodeRun {
        rows,
        finalized,
        proving,
        peak_mib,
        node: vos_pvm_recair::tree::Node {
            proof: fold_proof,
            output,
        },
    }
}

/// `root`, the root of a whole run of `program`, wrapped under format 28 on
/// the Blake2b-256 channel within 2^17 rows and 8 GiB of heap, and verified
/// by `vos-pvm-final-verifier`, its statement the program's id and the root's
/// io-hash: the proof's bytes (postcard) and its public words.
pub fn wrap_root(
    name: &str,
    program: &vos_pvm_proof::program_id::KernelProgram,
    root: &NodeRun,
) -> (Vec<u8>, [u32; vos_pvm_final_verifier::PUBLIC_WORDS]) {
    use vos_pvm_recair::wrap::{self, WrapCircuit};

    let circuit = WrapCircuit::get();
    let (values, statement) = circuit
        .values(root.node.proved(), &program.id_preimage())
        .expect("the root's values");
    let finalized = circuit
        .build(&values)
        .finalize()
        .expect("the wrap's wiring checks");
    let log_sizes = finalized.circuit.log_sizes();
    assert_eq!(log_sizes, vos_pvm_final_verifier::LOG_SIZES);
    assert!(log_sizes.iter().all(|&log| log <= 17));
    let words = wrap::public_words(&finalized);
    let (proof, proving, peak_mib) = measured(|| wrap::prove(&finalized).expect("the wrap proves"));
    let bytes = postcard::to_allocvec(&proof).expect("encodes");
    eprintln!(
        "{name}'s wrap: {log_sizes:?} log sizes, proved in {:.2}s, its peak heap {peak_mib} MiB, \
         {} bytes",
        proving.as_secs_f64(),
        bytes.len()
    );
    assert!(peak_mib <= 8 << 10, "{peak_mib} MiB");
    let verified = vos_pvm_final_verifier::verify_bytes(&bytes, &words).expect("the wrap verifies");
    assert_eq!(verified, statement);
    assert_eq!(statement.program, program.id().0.map(|word| word.0));
    assert_eq!(statement.io_hash, root.node.output.io_hash);
    (bytes, words)
}

/// `statement`, the run's: its io-hash the run's `io_hash`, judged against
/// the wrap `proof` by a venue that pins its program, accepts format 28 and
/// anchors its roots, natively and on the JAM-only host by the venue's
/// refine program; the judgement's input.
pub fn judged_statement(
    statement: vos_statement::Statement,
    io_hash: &[u8],
    proof: &[u8],
) -> vos_statement::model::Input {
    assert_eq!(statement.io_hash()[..], io_hash[..]);
    let input = vos_statement::model::Input {
        program: statement.program,
        policy: vos_statement::model::Policy {
            formats: vec![vos_statement::FORMAT],
            anchors: statement.roots.clone(),
            seen: Vec::new(),
        },
        statement,
    };
    let id = input.judge(proof).expect("the venue accepts the statement");
    assert_eq!(id, input.statement.id());
    let (program, _) = jam::program();
    let (gas, report) = jam::run(&program, &jam::judge_request(&input), proof);
    let [start, lookup, _, end] = report.gas;
    eprintln!(
        "judged on the JAM-only host: {gas} gas ({:.1}M), lookup {}, the judgement {}; heap \
         peak {} KiB; id {}",
        gas as f64 / 1e6,
        start - lookup,
        lookup - end,
        report.peak_live >> 10,
        id.0.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    assert_eq!(report.verdict, jam::ACCEPT, "{}", report.error);
    assert_eq!(report.code, 0);
    assert_eq!(report.id, id.0);
    assert!(gas <= 150_000_000, "{gas} gas");
    input
}

/// A wrap's proof (postcard), its public words (24 little-endian `u32`s)
/// and its judgement's input, under the target's tmp directory as
/// `wrap/<name>.{proof,words,input}`, for the Wasm harness.
pub fn write_wrap(
    name: &str,
    proof: &[u8],
    words: &[u32; vos_pvm_final_verifier::PUBLIC_WORDS],
    input: &vos_statement::model::Input,
) {
    let directory = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("wrap");
    std::fs::create_dir_all(&directory).expect("the wrap's directory");
    let words: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    for (extension, bytes) in [
        ("proof", proof),
        ("words", &words),
        ("input", &input.encode()),
    ] {
        std::fs::write(directory.join(format!("{name}.{extension}")), bytes).expect("writes");
    }
}

/// `instructions` as code, each one's start marked in the bitmask, with no
/// jump table.
pub fn code_of(instructions: &[Vec<u8>]) -> vos_pvm_program::CodeBlob {
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    for instruction in instructions {
        code.extend_from_slice(instruction);
        bitmask.push(1);
        bitmask.resize(code.len(), 0);
    }
    vos_pvm_program::CodeBlob {
        jump_table: vec![],
        code,
        bitmask,
    }
}

/// A standard program of `instructions`, laid out as the loader lays it
/// out: no data, one heap page, a 4 KiB stack.
pub fn standard_program(instructions: &[Vec<u8>]) -> Vec<u8> {
    vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 1,
        stack_size: 4096,
        code: code_of(instructions),
    })
    .expect("a standard program")
}
