#![cfg(feature = "prover")]

//! A kernel's shape: the chips its code can reach, which its install
//! records, and the log sizes of each class of its segments. A kernel's
//! segments prove over exactly that shape, and verify against its program,
//! the preimage of its program id; a proof over the full set of chips,
//! missing a chip, or at another log size is refused before any
//! cryptographic check.
//!
//! The kernels are the `kernels` test actor's (`just build-test-actors`):
//! `digest` hashes its input through the BLAKE2b precompile, as the window
//! kernel does, and `areas` computes over its input and hashes only its
//! io-hash, as a solvency predicate; its run verifies in its leaf, and
//! end to end, its leaves folded and wrapped, as a venue judges it.

use crate::common;

use vos_pvm::instruction::Opcode;
use vos_pvm_compiler::shape::{self as derived_shape, chip};
use vos_pvm_proof::chip_idx;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTrace, kernel_side_note, trace_kernel};
use vos_pvm_proof::program_id::{KernelEntry, KernelProgram, LeafCircuits};
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::shape::{KernelShape, SegmentShape};
use vos_pvm_proof::{
    Proof, ProvingError, program_commitment_for_shape, program_commitment_of_proof,
    prove_canonical_format, prove_kernel, prove_shaped,
};
use vos_pvm_proof_verifier::{
    ENTRY_TIMESTAMP, HALT_PC, verify_kernel_chain, verify_kernel_segment, verify_standalone,
};
use vos_testkit::Testkit;
use vos_testkit::programs::{derivation, derived, method, package};
use vos_wire::Encode;
use vos_wire::abi::cap::Target;
use vos_wire::ids::{AgentId, InstanceId, Principal, ProgramHash};
use vos_wire::result::Attest;

const GAS: u64 = 100_000_000;

/// A kernel of the `kernels` actor, as its install records it, and a run of
/// it.
struct Kernel {
    blob: Vec<u8>,
    record: vos_wire::records::Kernel,
    trace: KernelTrace,
}

impl Kernel {
    fn shape(&self) -> KernelShape {
        KernelShape::try_from(&self.record.shape).expect("an install's shape")
    }

    /// Its entry, from its blob.
    fn entry(&self) -> KernelEntry {
        KernelEntry::of(&self.program(), &self.blob).expect("the program's blob")
    }

    /// Its program, each class's preprocessed root computed from its code.
    fn program(&self) -> KernelProgram {
        let shape = self.shape();
        let side_note = kernel_side_note(&self.blob).expect("a standard program");
        let preprocessed_roots = (0..shape.classes.len())
            .map(|class| {
                program_commitment_for_shape(&side_note, &shape.segment(class).unwrap(), &SEGMENT)
                    .expect("the class's root")
            })
            .collect();
        KernelProgram {
            transpiler: vos_pvm_compiler::TRANSPILER_VERSION,
            program: self.record.program.0,
            shape,
            format: SEGMENT.number,
            preprocessed_roots,
            image_root: self.record.image_root,
            leaf_circuits: LeafCircuits::None,
        }
    }

    /// The whole run as one segment.
    fn whole(&self) -> vos_pvm_proof::SideNote {
        let steps = self.trace.side_note.steps.len();
        SegmentCursor::new(&self.trace.side_note).side_note(0, steps)
    }
}

/// The kernels of one live run of `check` on `values`, by method name.
fn kernels(values: &[u64]) -> Vec<(&'static str, Kernel)> {
    let derived = derived("kernels");
    let install = derivation(&package("kernels"), &derived);
    let mut kit = Testkit::new(AgentId(7));
    kit.install_derived(Target::Vos, InstanceId(9), &derived, &[])
        .expect("installs");
    let step = kit.command(
        Principal::Client([1; 32]),
        InstanceId(9),
        method(&derived.actor, "check"),
        &values.to_vec().encode(),
    );
    let attests: Vec<Attest> = step.attests;
    ["digest", "named", "areas"]
        .into_iter()
        .zip(attests)
        .map(|(name, attest)| {
            let blob = derived
                .kernels
                .iter()
                .map(|(_, kernel)| kernel)
                .find(|kernel| ProgramHash::of(kernel) == attest.program)
                .expect("a derived kernel")
                .clone();
            let record = install
                .kernels
                .iter()
                .find(|kernel| kernel.program == attest.program)
                .expect("its install's record")
                .clone();
            let trace = trace_kernel(&blob, &attest.witness_input, GAS).expect("re-runs");
            (
                name,
                Kernel {
                    blob,
                    record,
                    trace,
                },
            )
        })
        .collect()
}

fn kernel(name: &str, values: &[u64]) -> Kernel {
    kernels(values)
        .into_iter()
        .find(|(kernel, _)| *kernel == name)
        .map(|(_, kernel)| kernel)
        .unwrap()
}

/// The derivation's chips are the AIR's: its order, the chips every proof
/// holds, and, opcode by opcode, the chips a step of it activates.
#[test]
fn derive_reads_the_airs_chips() {
    assert_eq!(chip::COUNT, chip_idx::COUNT);
    assert_eq!(derived_shape::ALWAYS, chip_idx::ALWAYS);
    for (derived, air) in [
        (chip::CPU, chip_idx::CPU),
        (chip::BLAKE2B, chip_idx::BLAKE2B),
        (chip::BLAKE2B_BOUNDARY, chip_idx::BLAKE2B_BOUNDARY),
        (chip::MEMORY, chip_idx::MEMORY),
        (chip::MEMORY_PAGE, chip_idx::MEMORY_PAGE),
        (chip::MEMORY_MERKLE, chip_idx::MEMORY_MERKLE),
        (chip::MEMORY_ROOT_BOUNDARY, chip_idx::MEMORY_ROOT_BOUNDARY),
        (chip::REGISTER_MEMORY, chip_idx::REGISTER_MEMORY),
        (
            chip::REGISTER_MEMORY_BOUNDARY,
            chip_idx::REGISTER_MEMORY_BOUNDARY,
        ),
        (
            chip::REGISTER_MEMORY_CLOSING,
            chip_idx::REGISTER_MEMORY_CLOSING,
        ),
        (chip::PROGRAM_BOUNDARY, chip_idx::PROGRAM_BOUNDARY),
        (chip::PROGRAM_MEMORY, chip_idx::PROGRAM_MEMORY),
        (chip::JUMP_TABLE, chip_idx::JUMP_TABLE),
        (chip::WITNESS_INPUT, chip_idx::WITNESS_INPUT),
        (
            chip::RANGE_MULTIPLICITY_256,
            chip_idx::RANGE_MULTIPLICITY_256,
        ),
        (chip::BITWISE_LOOKUP, chip_idx::BITWISE_LOOKUP),
        (chip::POWER_OF_TWO, chip_idx::POWER_OF_TWO),
        (chip::POPCOUNT, chip_idx::POPCOUNT),
        (chip::BITCOUNT, chip_idx::BITCOUNT),
        (chip::BYTE_TO_BITS, chip_idx::BYTE_TO_BITS),
        (chip::MUL, chip_idx::MUL),
        (chip::BITWISE, chip_idx::BITWISE),
        (chip::COMPARE, chip_idx::COMPARE),
        (chip::DIVREM, chip_idx::DIVREM),
        (chip::BITWISE_AND_BYTE, chip_idx::BITWISE_AND_BYTE),
    ] {
        assert_eq!(derived, air);
    }
    let mut opcodes = 0;
    for byte in 0..=u8::MAX {
        let Some(op) = Opcode::from_byte(byte) else {
            continue;
        };
        opcodes += 1;
        assert_eq!(
            derived_shape::opcode_chips(op) | chip_idx::ALWAYS,
            vos_pvm_proof::opcode_component_mask(op),
            "{op:?}"
        );
    }
    assert!(opcodes > 100, "{opcodes}");
}

/// A kernel's run uses only chips of its shape, and the shape its install
/// recorded is its code's, the witness input and BLAKE2b, of its io-hash,
/// among them.
#[test]
fn a_kernels_runs_stay_in_its_shape() {
    for (name, kernel) in kernels(&(0..40).collect::<Vec<_>>()) {
        let shape = kernel.shape();
        shape.check().unwrap();
        assert_eq!(
            Some(&kernel.record.shape),
            derived_shape::kernel_shape(&kernel.blob).as_ref()
        );
        let used = vos_pvm_proof::active_component_mask(&kernel.whole());
        assert_eq!(used & !shape.components, 0, "{name}");
        // Every kernel reads its arguments and hashes its io-hash.
        let io = 1 << chip_idx::BLAKE2B | 1 << chip_idx::WITNESS_INPUT | 1 << chip_idx::COMPARE;
        assert_eq!(shape.components & io, io, "{name}");
        assert_ne!(shape.components, chip_idx::ALL, "{name}");
    }
}

/// `digest` and `areas` prove over their shapes, each segment at the first
/// class that holds it, and their chains verify against their programs,
/// every segment's preprocessed root its class's.
#[test]
fn kernels_prove_and_verify_over_their_shapes() {
    let values: Vec<u64> = (0..200).collect();
    for name in ["digest", "areas"] {
        let kernel = kernel(name, &values);
        let program = kernel.program();
        let segments = prove_kernel(&kernel.trace.side_note, &program.shape, 0, &SEGMENT)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(!segments.is_empty());
        for segment in &segments {
            assert_eq!(
                program_commitment_of_proof(&segment.proof),
                program.preprocessed_roots[segment.class],
                "{name}"
            );
            assert_eq!(
                verify_kernel_segment(segment.proof.clone(), &program).unwrap(),
                segment.class
            );
            eprintln!(
                "{name}: steps {:?}, class {}, log sizes {:?}",
                segment.steps, segment.class, segment.proof.log_sizes
            );
        }
        let proofs: Vec<Proof> = segments.into_iter().map(|segment| segment.proof).collect();
        let registers = verify_kernel_chain(proofs, &program, &kernel.entry()).unwrap();
        let io_hash: Vec<u8> = registers[9..13]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(io_hash, kernel.trace.io_hash, "{name}");
        eprintln!("{name}: program id {:02x?}", &program.id().to_bytes()[..8]);
    }
}

/// `areas`'s run on three sides, its program, and its first class's
/// segment shape, which holds the run as one segment.
fn areas() -> (Kernel, KernelProgram, SegmentShape) {
    let kernel = kernel("areas", &[3, 4, 5]);
    let program = kernel.program();
    let shape = program.shape.segment(0).unwrap();
    (kernel, program, shape)
}

/// A proof of the same run over the full set of chips verifies on its own,
/// a valid run, but not as the kernel's: its chips are more than its shape.
#[test]
fn a_full_set_proof_is_refused() {
    let (kernel, program, _) = areas();
    let full = prove_canonical_format(&mut kernel.whole(), &[], &SEGMENT).unwrap();
    assert_eq!(full.component_mask, chip_idx::ALL);
    verify_standalone(full.clone(), program_commitment_of_proof(&full)).unwrap();
    let error = verify_kernel_segment(full, &program).unwrap_err();
    assert!(error.to_string().contains("more"), "{error}");
}

/// A kernel whose code reaches a count of set bits on a path it never
/// takes: it jumps over the count, then halts with an empty output.
fn skipping() -> Vec<u8> {
    common::standard_program(&[
        vec![40, 5],             // jump to 5
        vec![101, 0x00],         // count the set bits of φ0, never run
        vec![1],                 // fallthrough: 5 starts a block
        vec![51, 8, 0, 0, 0, 0], // φ8 = 0, the output's length
        vec![50, 0],             // to φ0, the halt address
    ])
}

/// A proof of a run without a chip of its shape the run does not use
/// verifies on its own, but not as the kernel's: its chips are fewer than
/// its shape. The kernels of the `kernels` actor use every chip their code
/// reaches on any input, so the kernel is one that skips a count of set
/// bits.
#[test]
fn a_proof_missing_a_chip_is_refused() {
    let blob = skipping();
    let record = derived_shape::kernel_shape(&blob).unwrap();
    assert_ne!(record.chips & 1 << chip_idx::POPCOUNT, 0);
    let image_root = vos_pvm_program::parse_standard_program(&blob)
        .and_then(|program| program.image_root())
        .unwrap();
    let kernel = Kernel {
        trace: trace_kernel(&blob, &[], GAS).expect("halts"),
        record: vos_wire::records::Kernel {
            method: vos_wire::ids::MethodId(1),
            program: ProgramHash::of(&blob),
            image_root,
            shape: record,
        },
        blob,
    };
    let program = kernel.program();
    let shape = program.shape.segment(0).unwrap();
    let used = vos_pvm_proof::active_component_mask(&kernel.whole());
    assert_eq!(shape.components & !used, 1 << chip_idx::POPCOUNT);
    let position = (0..chip_idx::POPCOUNT)
        .filter(|chip| shape.components & 1 << chip != 0)
        .count();
    let mut fewer = shape.clone();
    fewer.components &= !(1 << chip_idx::POPCOUNT);
    fewer.log_sizes.remove(position);
    let proof = prove_shaped(&mut kernel.whole(), &fewer, &SEGMENT).unwrap();
    verify_standalone(proof.clone(), program_commitment_of_proof(&proof)).unwrap();
    let error = verify_kernel_segment(proof, &program).unwrap_err();
    assert!(error.to_string().contains("fewer"), "{error}");
    // Over its shape, the run proves and verifies as the kernel's.
    let proof = prove_shaped(&mut kernel.whole(), &shape, &SEGMENT).unwrap();
    assert_eq!(verify_kernel_segment(proof, &program).unwrap(), 0);
}

/// A proof of the same run over the shape's chips at a log size no class
/// gives verifies on its own, but not as the kernel's.
#[test]
fn a_proof_at_another_log_size_is_refused() {
    let (kernel, program, shape) = areas();
    let mut larger = shape.clone();
    larger.log_sizes[chip_idx::CPU] += 1;
    let proof = prove_shaped(&mut kernel.whole(), &larger, &SEGMENT).unwrap();
    verify_standalone(proof.clone(), program_commitment_of_proof(&proof)).unwrap();
    let error = verify_kernel_segment(proof, &program).unwrap_err();
    assert!(error.to_string().contains("no class"), "{error}");
}

/// A shape without a chip the run needs proves nothing a verifier accepts:
/// the CPU's requests to it go unanswered, so the logup sum is not zero.
#[test]
fn a_run_needing_a_dropped_chip_does_not_verify() {
    let (kernel, _, shape) = areas();
    let used = vos_pvm_proof::active_component_mask(&kernel.whole());
    let needed = used & chip_idx::OPTIONAL & 1 << chip_idx::MUL;
    assert_ne!(needed, 0, "areas multiplies");
    let position = (0..chip_idx::MUL)
        .filter(|chip| shape.components & 1 << chip != 0)
        .count();
    let mut fewer = shape.clone();
    fewer.components &= !needed;
    fewer.log_sizes.remove(position);
    match prove_shaped(&mut kernel.whole(), &fewer, &SEGMENT) {
        Ok(proof) => {
            let error =
                verify_standalone(proof.clone(), program_commitment_of_proof(&proof)).unwrap_err();
            assert!(error.to_string().contains("logup sum"), "{error}");
        }
        Err(error) => panic!("the forgery proves, and is refused at verify: {error}"),
    }
}

/// A shape whose sizes a run's rows overflow is refused by the prover,
/// naming the chip.
#[test]
fn a_segment_past_its_class_is_refused() {
    let (kernel, _, shape) = areas();
    let mut smaller = shape.clone();
    smaller.log_sizes[chip_idx::CPU] = 4;
    match prove_shaped(&mut kernel.whole(), &smaller, &SEGMENT) {
        Err(ProvingError::Shape {
            chip, pinned: 4, ..
        }) => assert_eq!(chip, chip_idx::CPU),
        other => panic!("{:?}", other.map(|proof| proof.log_sizes)),
    }
}

/// A kernel's entry is its loader's: its first step's pc, and the registers
/// its blob's layout gives; a halt ends a run at the halt pc. A blob other
/// than the program's is refused.
#[test]
fn a_kernels_entry_is_its_loaders() {
    let (kernel, program, _) = areas();
    let entry = kernel.entry();
    let first = &kernel.trace.side_note.steps[0];
    assert_eq!((first.pc, first.timestamp), (entry.pc, ENTRY_TIMESTAMP));
    assert_eq!(entry.registers[0], u64::from(HALT_PC));
    assert_eq!(HALT_PC, vos_pvm::PVM_HALT_ADDR as u32);
    let mut other = kernel.blob.clone();
    *other.last_mut().unwrap() ^= 1;
    assert!(KernelEntry::of(&program, &other).is_err());
}

/// A chain that does not start where the loader starts the kernel is
/// refused before any cryptographic check: one proved from mid-run, and
/// one whose first state names another timestamp, pc or registers.
#[test]
fn a_chain_not_from_the_entry_is_refused() {
    let (kernel, program, shape) = areas();
    let entry = kernel.entry();
    let steps = kernel.trace.side_note.steps.len();
    let mut tail = SegmentCursor::new(&kernel.trace.side_note).side_note(2, steps);
    let proof = prove_shaped(&mut tail, &shape, &SEGMENT).unwrap();
    assert_eq!(verify_kernel_segment(proof.clone(), &program).unwrap(), 0);
    let error = verify_kernel_chain(vec![proof], &program, &entry).unwrap_err();
    assert!(error.to_string().contains("first timestamp"), "{error}");

    let proof = prove_shaped(&mut kernel.whole(), &shape, &SEGMENT).unwrap();
    type Change = (fn(&mut Proof), &'static str);
    let changes: [Change; 3] = [
        (|p| p.initial_state.timestamp += 1, "first timestamp"),
        (|p| p.initial_state.pc += 1, "entry"),
        (|p| p.initial_state.registers[1] -= 8, "registers"),
    ];
    for (change, reason) in changes {
        let mut changed = proof.clone();
        change(&mut changed);
        let error = verify_kernel_chain(vec![changed], &program, &entry).unwrap_err();
        assert!(error.to_string().contains(reason), "{error}");
    }
    verify_kernel_chain(vec![proof], &program, &entry).unwrap();
}

/// A chain that does not end at the halt is refused: a run proved up to
/// its last step verifies as a segment of the kernel, but not as its run.
#[test]
fn a_chain_not_ending_at_the_halt_is_refused() {
    let (kernel, program, shape) = areas();
    let steps = kernel.trace.side_note.steps.len();
    let mut head = SegmentCursor::new(&kernel.trace.side_note).side_note(0, steps - 1);
    let proof = prove_shaped(&mut head, &shape, &SEGMENT).unwrap();
    assert_ne!(proof.final_state.pc, HALT_PC);
    assert_eq!(verify_kernel_segment(proof.clone(), &program).unwrap(), 0);
    let error = verify_kernel_chain(vec![proof], &program, &kernel.entry()).unwrap_err();
    assert!(error.to_string().contains("halt"), "{error}");
}

/// `areas`, a solvency predicate's kind of kernel, its run one segment of
/// class 0, verified in its leaf as natively: the leaf states the entry,
/// the halt and the run's io-hash, within the padded shape, proved and
/// verified, its circuit the program's class-0 leaf circuit.
#[test]
fn a_predicates_leaf_proves_and_verifies() {
    let (kernel, _, shape) = areas();
    let (program, entry) = vos_pvm_recair::leaf::kernel_program(
        &kernel.blob,
        &kernel.record,
        vos_pvm_compiler::TRANSPILER_VERSION,
        &SEGMENT,
    )
    .expect("the kernel's program");
    assert_eq!(entry, kernel.entry());
    let proof = prove_shaped(&mut kernel.whole(), &shape, &SEGMENT).unwrap();
    let fold_word = vos_pvm_proof::poseidon2::P2Hash(core::array::from_fn(|i| {
        stwo::core::fields::m31::BaseField::from(7_000 + i as u32)
    }));
    let leaf = common::prove_leaf(&program, &entry, 0, &proof, 0, fold_word);
    eprintln!(
        "areas: {} chips; its leaf {:?} rows ({:?} finalized), proved in {:.2}s, its peak \
         heap {} MiB",
        proof.log_sizes.len(),
        leaf.rows,
        leaf.finalized,
        leaf.proving.as_secs_f64(),
        leaf.peak_mib
    );
    assert!(leaf.node.output.entry && leaf.node.output.halt);
    assert_eq!(leaf.node.output.io_hash, kernel.trace.io_hash);
}

/// `areas`, the solvency predicate's kind, end to end: its run cut in three
/// segments of class 0, each verified in its leaf, the leaves folded to one
/// root stating the whole run, wrapped under format 28 and verified by
/// `vos-pvm-final-verifier`; its statement (rootless, its output the areas'
/// sum) recomputes the run's io-hash, and a venue pinning its program
/// accepts it, natively and on the JAM-only host. The wrap and the
/// judgement's input are written for the Wasm harness,
/// `wrap/predicate.{proof,words,input}` under the target's tmp directory.
#[test]
fn the_predicate_wraps() {
    use vos_pvm_recair::fold::FoldCircuit;

    let (kernel, _, shape) = areas();
    let (program, entry) = vos_pvm_recair::leaf::kernel_program(
        &kernel.blob,
        &kernel.record,
        vos_pvm_compiler::TRANSPILER_VERSION,
        &SEGMENT,
    )
    .expect("the kernel's program");
    let steps = kernel.trace.side_note.steps.len();
    let cuts = [
        (0, steps / 3),
        (steps / 3, 2 * steps / 3),
        (2 * steps / 3, steps),
    ];
    let word = FoldCircuit::word();
    let mut totals = common::Totals::default();
    let mut cursor = SegmentCursor::new(&kernel.trace.side_note);
    let mut leaves = Vec::with_capacity(cuts.len());
    for (position, &(a, b)) in cuts.iter().enumerate() {
        let (proof, segment, segment_peak) = common::measured(|| {
            prove_shaped(&mut cursor.side_note(a, b), &shape, &SEGMENT).unwrap()
        });
        let leaf = common::prove_leaf(&program, &entry, 0, &proof, position as u32, word);
        eprintln!(
            "areas: segment {position} ({a}..{b}) proved in {:.2}s, its peak heap {segment_peak} \
             MiB; its leaf in {:.2}s, its peak heap {} MiB",
            segment.as_secs_f64(),
            leaf.proving.as_secs_f64(),
            leaf.peak_mib,
        );
        totals.segments.add(segment, segment_peak);
        totals.leaves.add(leaf.proving, leaf.peak_mib);
        leaves.push(leaf);
    }
    let fold = FoldCircuit::new();
    let head = common::prove_fold(&fold, &program, &leaves[0], &leaves[1], word);
    let root = common::prove_fold(&fold, &program, &head, &leaves[2], word);
    for node in [&head, &root] {
        totals.folds.add(node.proving, node.peak_mib);
    }
    eprintln!(
        "areas: two folds in {:.2}s and {:.2}s",
        head.proving.as_secs_f64(),
        root.proving.as_secs_f64()
    );
    assert_eq!((root.node.output.first, root.node.output.last), (0, 2));
    assert!(
        root.node.output.entry && root.node.output.halt,
        "the whole run"
    );
    assert_eq!(root.node.output.io_hash, kernel.trace.io_hash);

    let (bytes, words) = common::wrap_root("areas", &program, &root, &mut totals.wrap);
    totals.report("areas");
    let input = common::judged_statement(
        vos_statement::Statement {
            format: vos_pvm_final_verifier::unmasked::FORMAT,
            program: vos_statement::ProgramId(program.id().0.map(|word| word.0)),
            // Rootless: of no space.
            space: vos_statement::SpaceId::NONE,
            public_args: Vec::new(),
            output: kernel.trace.output.clone(),
            roots: Vec::new(),
        },
        &kernel.trace.io_hash,
        &bytes,
    );
    common::write_wrap("predicate", &bytes, &words, &input);
}
