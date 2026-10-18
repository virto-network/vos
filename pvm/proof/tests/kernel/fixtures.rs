#![cfg(feature = "prover")]

//! The fixtures under `pvm/proof/fixtures` (`proving.md` A.6), and their
//! generator: the segment fixtures, and the golden statements every venue
//! judges ([`statements`]).
//!
//! For each admitted segment format, a fixed small kernel's run proved as
//! one segment of its program:
//! - `segment-<n>.proof`, the proof, which verifies;
//! - `segment-<n>.root`, its class's preprocessed root, which a venue
//!   verifies it against;
//! - `segment-<n>-tampered.patch`, the proof with one out-of-domain sample
//!   of its main trace changed, which is refused;
//! - `segment-<n>-wrong-format.patch`, the proof under the other segment
//!   format's number, which is refused.
//!
//! Each file is a postcard encoding. A proof is most of a megabyte, so the
//! two refused proofs are kept as patches of the valid one's bytes
//! ([`Patch`]): a venue applies the patch and judges the bytes it gets.
//!
//! The generator makes the fixtures again on every run, and a fixture whose
//! bytes differ from its generator's is stale: `just fixtures` writes them
//! anew, at a format bump or a change of the AIR, the shape or the kernel
//! below.

use crate::common;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use stwo::core::fields::qm31::SecureField;
use vos_pvm::instruction::Opcode;
use vos_pvm_compiler::shape::kernel_shape;
use vos_pvm_proof::format::{Format, LEGACY_SEGMENT, SEGMENT};
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::pcs::{Commitment, StarkProofAny};
use vos_pvm_proof::program_id::KernelProgram;
use vos_pvm_proof::{Proof, prove_kernel};
use vos_pvm_proof_verifier::{verify_kernel_segment, verify_standalone};
use vos_wire::ids::{MethodId, ProgramHash};

/// The admitted segment formats, each with the one its wrong-format
/// fixture is relabelled to.
const FORMATS: [(&Format, u32); 2] = [
    (&SEGMENT, LEGACY_SEGMENT.number),
    (&LEGACY_SEGMENT, SEGMENT.number),
];

/// Set to `write` to write the fixtures instead of comparing them.
const MODE: &str = "VOS_FIXTURES";

/// Bytes made from a proof's: `removed` bytes at `offset` replaced by
/// `inserted`.
#[derive(Debug, Serialize, Deserialize)]
struct Patch {
    offset: u32,
    removed: u32,
    inserted: Vec<u8>,
}

impl Patch {
    /// The patch that makes `to` from `from`: the bytes between their
    /// common prefix and their common suffix.
    fn between(from: &[u8], to: &[u8]) -> Self {
        let prefix = from.iter().zip(to).take_while(|(a, b)| a == b).count();
        let suffix = from[prefix..]
            .iter()
            .rev()
            .zip(to[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Patch {
            offset: prefix as u32,
            removed: (from.len() - prefix - suffix) as u32,
            inserted: to[prefix..to.len() - suffix].to_vec(),
        }
    }

    fn apply(&self, bytes: &[u8]) -> Vec<u8> {
        let (offset, removed) = (self.offset as usize, self.removed as usize);
        [
            &bytes[..offset],
            &self.inserted[..],
            &bytes[offset + removed..],
        ]
        .concat()
    }
}

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// `load_imm`: a register set to a small constant.
fn load(register: u8, value: u8) -> Vec<u8> {
    vec![Opcode::LoadImm as u8, register, value, 0, 0, 0]
}

/// The kernel: two constants, their product and sum, then a halt with an
/// empty output.
fn kernel() -> Vec<u8> {
    common::standard_program(&[
        load(2, 5),
        load(3, 7),
        vec![Opcode::Mul64 as u8, 3 << 4 | 2, 4],
        vec![Opcode::Add64 as u8, 4 << 4 | 2, 5],
        load(8, 0),
        vec![Opcode::JumpInd as u8, 0],
    ])
}

/// A kernel's record, as its install would make it.
fn record(blob: &[u8]) -> vos_wire::records::Kernel {
    vos_wire::records::Kernel {
        method: MethodId(1),
        program: ProgramHash::of(blob),
        image_root: vos_pvm_program::parse_standard_program(blob)
            .and_then(|program| program.image_root())
            .expect("an image root"),
        shape: kernel_shape(blob).expect("a shape"),
    }
}

/// The kernel's program under `format`.
fn program(blob: &[u8], format: &'static Format) -> KernelProgram {
    common::kernel_program(blob, &record(blob), format)
}

/// One format's fixtures, by file name.
fn generate(format: &'static Format, other: u32) -> Vec<(String, Vec<u8>)> {
    let blob = kernel();
    let program = program(&blob, format);
    let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
    let mut segments = prove_kernel(&trace.side_note, &program.shape, 0, format).expect("proves");
    assert_eq!(segments.len(), 1, "the run is one segment");
    let segment = segments.remove(0);
    let proof = segment.proof;

    let mut tampered = proof.clone();
    let sample = |values: &mut Vec<Vec<Vec<SecureField>>>| {
        values[1][0][0] += SecureField::from_u32_unchecked(1, 0, 0, 0);
    };
    match &mut tampered.stark_proof {
        StarkProofAny::Blake2s(stark) => sample(&mut stark.0.sampled_values.0),
        StarkProofAny::Poseidon2M31(stark) => sample(&mut stark.0.sampled_values.0),
    }
    let mut wrong_format = proof.clone();
    wrong_format.format_version = other;

    let n = format.number;
    let encode = |proof: &Proof| postcard::to_allocvec(proof).expect("encodes");
    let valid = encode(&proof);
    let patch = |to: &Proof| {
        let patch = Patch::between(&valid, &encode(to));
        postcard::to_allocvec(&patch).expect("encodes")
    };
    vec![
        (format!("segment-{n}.root"), {
            postcard::to_allocvec(&program.preprocessed_roots[segment.class]).expect("encodes")
        }),
        (format!("segment-{n}-tampered.patch"), patch(&tampered)),
        (
            format!("segment-{n}-wrong-format.patch"),
            patch(&wrong_format),
        ),
        (format!("segment-{n}.proof"), valid),
    ]
}

fn read(name: &str) -> Vec<u8> {
    let path = directory().join(name);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{}: {error}; `just fixtures` writes the fixtures",
            path.display()
        )
    })
}

/// Format `n`'s proof, patched by `patch` if given.
fn proof(n: u32, patch: Option<&str>) -> Proof {
    let mut bytes = read(&format!("segment-{n}.proof"));
    if let Some(patch) = patch {
        let patch: Patch =
            postcard::from_bytes(&read(&format!("segment-{n}-{patch}.patch"))).expect("a patch");
        bytes = patch.apply(&bytes);
    }
    postcard::from_bytes(&bytes).expect("a proof")
}

/// Every fixture is the generator's, byte for byte: proving is
/// deterministic, so a difference is a change of the AIR, a format, the
/// shape or the kernel, and the fixtures are written anew.
#[test]
fn the_fixtures_are_the_generators() {
    let write = std::env::var(MODE).is_ok_and(|mode| mode == "write");
    let mut stale = Vec::new();
    let generated = FORMATS
        .into_iter()
        .flat_map(|(format, other)| generate(format, other))
        .chain(statements::generate());
    for (name, bytes) in generated {
        if write {
            std::fs::create_dir_all(directory()).expect("the fixtures' directory");
            std::fs::write(directory().join(&name), &bytes).expect("writes");
            eprintln!("{name}: {} bytes", bytes.len());
        } else if std::fs::read(directory().join(&name)).ok().as_ref() != Some(&bytes) {
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "stale fixtures under pvm/proof/fixtures: {stale:?}. The generator \
         (pvm/proof/tests/kernel/fixtures.rs) makes other bytes: the AIR, a format, \
         the shape or the kernel changed. Run `just fixtures` to write them \
         anew, check the diff is the change you meant, and commit them."
    );
}

/// The fixtures as every venue judges them: the proof verifies against its
/// root, and as its kernel's segment; the tampered proof and the proof
/// under the wrong format are refused.
#[test]
fn the_fixtures_are_judged() {
    let blob = kernel();
    for (format, _) in FORMATS {
        let n = format.number;
        let root: Commitment =
            postcard::from_bytes(&read(&format!("segment-{n}.root"))).expect("a root");
        let program = program(&blob, format);
        assert_eq!(program.preprocessed_roots[0], root);

        let valid = proof(n, None);
        assert_eq!(valid.format_version, n);
        verify_standalone(valid.clone(), root).expect("the proof verifies");
        assert_eq!(verify_kernel_segment(valid, &program).unwrap(), 0);

        let tampered = proof(n, Some("tampered"));
        assert!(verify_standalone(tampered.clone(), root).is_err());
        assert!(verify_kernel_segment(tampered, &program).is_err());

        let wrong = proof(n, Some("wrong-format"));
        assert_ne!(wrong.format_version, n);
        let error = verify_standalone(wrong.clone(), root).unwrap_err();
        eprintln!("{n}: under the wrong format: {error}");
        let error = verify_kernel_segment(wrong, &program).unwrap_err();
        assert!(error.to_string().contains("format"), "{error}");
    }
}

/// The golden statements (`proving.md` A.6), which every venue judges
/// alike: natively, in Wasm and on the JAM-only host (`vos-statement`'s
/// fixtures test, the Wasm harness's `judge`).
///
/// The kernel states a fixed statement `S`: it sets φ9..12 to `S`'s
/// io-hash, an output of its own, two roots of its space read, then halts.
/// Its run, cut in three segments, is proved at its class, its leaves folded
/// to a root and the root wrapped: `wrap.proof`. Two roots that are not a
/// whole run, wrapped as a cheating prover would (the wrap circuit's checks
/// failing, proved anyway): `wrap-prefix.proof`, the first two segments,
/// which set the io-hash but never halt; `wrap-midway.proof`, the last two,
/// labelled from position 0, which never start at the entry.
///
/// The venue pins the kernel's program id, accepts format 28, anchors `S`'s
/// two roots and has accepted one other statement. The cases
/// (`statements.cases`), each a venue's state, a statement and a proof:
/// - **valid:** `S` and its wrap, accepted;
/// - **tampered:** a byte of the wrap flipped;
/// - **wrong program:** the venue pins another program, which the statement
///   names, and the wrap is this kernel's;
/// - **unanchored root:** `S` with its first root an older window's,
///   which the venue does not anchor;
/// - **prefix**, **mid-way:** `S` with the wraps of a part of the run;
/// - **repeated:** `S` after the venue accepted it;
/// - **unaccepted format:** `S` under format 30;
/// - **wrong io-hash:** `S` with its output changed;
/// - **another program than the pin:** the statement names another program
///   than the one the venue pinned;
/// - **another space:** a root of another space than `S`'s;
/// - **rootless, another space:** `S` without its roots, its space still
///   claimed: a rootless statement belongs to no space, since nothing
///   binds it there and each space would give one proof another id.
/// - **the same run, another accepted format:** `S` at a venue in a
///   transition, accepting format 28 and a successor, which accepted `S`'s
///   run under the successor: the same statement, refused as a repeat,
///   since the id does not hash the format. The successor is 38, a number
///   no format holds; this verifier reads 28 alone, so the case records the
///   successor's acceptance as the id the venue keeps, which is all its
///   repeat check reads.
mod statements {
    use stwo::core::fields::qm31::SecureField;
    use vos_pvm::instruction::Opcode;
    use vos_pvm_final_verifier::WrapProof;
    use vos_pvm_proof::format::SEGMENT;
    use vos_pvm_proof::kernel::trace_kernel;
    use vos_pvm_proof::program_id::{KernelEntry, KernelProgram};
    use vos_pvm_proof::prove_shaped;
    use vos_pvm_proof::segment::SegmentCursor;
    use vos_pvm_recair::Context;
    use vos_pvm_recair::fold::FoldCircuit;
    use vos_pvm_recair::wrap::{self, WrapCircuit};
    use vos_statement::fixtures::{CASES, Case, Patch};
    use vos_statement::model::{Input, Policy};
    use vos_statement::{FORMAT, ProgramId, RootRead, SpaceId, Statement, StatementId};

    use super::common::{self, NodeRun};
    use super::{load, record};

    const SPACE: SpaceId = SpaceId([0xA1; 32]);
    /// A final format a venue in a transition accepts beside 28: a number
    /// no format holds.
    const SUCCESSOR: u32 = 38;
    /// The run's cuts: the io-hash set in the first two, the halt in the
    /// last.
    const CUTS: [(usize, usize); 3] = [(0, 2), (2, 5), (5, 6)];

    fn root(window: u64, byte: u8) -> RootRead {
        RootRead {
            kind: 1,
            space: SPACE,
            window,
            root: [byte; 32],
        }
    }

    /// `S`, its program left to fill.
    fn statement() -> Statement {
        Statement {
            format: FORMAT,
            program: ProgramId([0; 8]),
            space: SPACE,
            public_args: b"nonce 7".to_vec(),
            output: b"the statement's output".to_vec(),
            roots: vec![root(41, 0x41), root(42, 0x42)],
        }
    }

    /// The kernel stating `io_hash`: φ8, the output's length, 0; φ9..12 the
    /// io-hash's bytes, eight a register, little-endian; then the halt.
    fn kernel(io_hash: &[u8; 32]) -> Vec<u8> {
        let mut instructions = vec![load(8, 0)];
        for (register, bytes) in (9..).zip(io_hash.chunks_exact(8)) {
            let mut instruction = vec![Opcode::LoadImm64 as u8, register];
            instruction.extend_from_slice(bytes);
            instructions.push(instruction);
        }
        instructions.push(vec![Opcode::JumpInd as u8, 0]);
        common::standard_program(&instructions)
    }

    /// The wrap of `root`, proved: as the circuit requires it, or, with
    /// `lenient`, over a root its checks refuse, as a cheating prover would.
    fn wrap_of(root: &NodeRun, program: &KernelProgram, lenient: bool) -> WrapProof {
        let circuit = WrapCircuit::get();
        let (values, _) = circuit
            .values(root.node.proved(), &program.id_preimage())
            .expect("the root's values");
        let mut context = Context::<SecureField>::with_layout(wrap::LAYOUT);
        if lenient {
            context = context.lenient();
        }
        let lanes = circuit.verify(&mut context, &values);
        context.set_output_lanes(&lanes);
        let pieces: Vec<&str> = context.mismatches().iter().map(|m| m.piece).collect();
        assert_eq!(!pieces.is_empty(), lenient, "{pieces:?}");
        let finalized = context.finalize().expect("the wrap's wiring checks");
        wrap::prove(&finalized).expect("the wrap proves")
    }

    /// The fixtures, by file name.
    pub fn generate() -> Vec<(String, Vec<u8>)> {
        let base = statement();
        let blob = kernel(&base.io_hash());
        let (program, entry): (KernelProgram, KernelEntry) = vos_pvm_recair::leaf::kernel_program(
            &blob,
            &record(&blob),
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .expect("the kernel's program");
        let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
        assert_eq!(trace.side_note.steps.len(), CUTS[2].1);
        assert_eq!(trace.io_hash, base.io_hash());
        let shape = program.shape.segment(0).expect("class 0");
        let mut cursor = SegmentCursor::new(&trace.side_note);
        let segments: Vec<_> = CUTS
            .iter()
            .map(|&(a, b)| {
                prove_shaped(&mut cursor.side_note(a, b), &shape, &SEGMENT).expect("proves")
            })
            .collect();
        let word = FoldCircuit::word();
        let fold = FoldCircuit::new();
        let leaf = |segment: usize, position: u32| {
            common::prove_leaf(&program, &entry, 0, &segments[segment], position, word)
        };
        let leaves: Vec<NodeRun> = (0..CUTS.len()).map(|s| leaf(s, s as u32)).collect();
        let fold_of = |left: &NodeRun, right: &NodeRun| {
            common::prove_fold(&fold, &program, left, right, word)
        };

        let head = fold_of(&leaves[0], &leaves[1]);
        let whole = fold_of(&head, &leaves[2]);
        assert!(whole.node.output.entry && whole.node.output.halt);
        assert!(head.node.output.entry && !head.node.output.halt);
        assert_eq!(
            head.node.output.io_hash,
            base.io_hash(),
            "the prefix states S"
        );
        let tail = fold_of(&leaf(1, 0), &leaf(2, 1));
        assert!(!tail.node.output.entry && tail.node.output.halt && tail.node.output.first == 0);

        let encode = |proof: &WrapProof| postcard::to_allocvec(proof).expect("encodes");
        let valid = encode(&wrap_of(&whole, &program, false));
        let prefix = encode(&wrap_of(&head, &program, true));
        let midway = encode(&wrap_of(&tail, &program, true));

        let pinned = ProgramId(program.id().0.map(|word| word.0));
        let other = ProgramId(pinned.0.map(|word| (word + 1) % ((1 << 31) - 1)));
        let s = Statement {
            program: pinned,
            ..base
        };
        let policy = Policy {
            formats: vec![FORMAT],
            anchors: s.roots.clone(),
            seen: vec![StatementId(vos_statement::blake2b_256(&[
                b"an earlier statement",
            ]))],
        };
        let input = |change: &dyn Fn(&mut Input)| {
            let mut input = Input {
                program: pinned,
                policy: policy.clone(),
                statement: s.clone(),
            };
            change(&mut input);
            input
        };
        let mut flipped = valid.clone();
        flipped[valid.len() / 2] ^= 1;
        type Class = fn(u32) -> bool;
        let accepted: Class = |code| code == 0;
        let by_proof: Class = |code| code >> 8 == 1;
        let by_words: Class = |code| code == 0x108 || code == 0x109;
        let cases: Vec<(&str, &str, Option<Patch>, Input, Class)> = vec![
            ("valid", "wrap.proof", None, input(&|_| {}), accepted),
            (
                "tampered",
                "wrap.proof",
                Some(Patch::between(&valid, &flipped)),
                input(&|_| {}),
                by_proof,
            ),
            (
                "wrong program",
                "wrap.proof",
                None,
                input(&|i| {
                    i.program = other;
                    i.statement.program = other;
                }),
                by_words,
            ),
            (
                "unanchored root",
                "wrap.proof",
                None,
                input(&|i| i.statement.roots[0] = root(40, 0x40)),
                |code| code == 5,
            ),
            (
                "prefix",
                "wrap-prefix.proof",
                None,
                input(&|_| {}),
                by_proof,
            ),
            (
                "mid-way",
                "wrap-midway.proof",
                None,
                input(&|_| {}),
                by_proof,
            ),
            (
                "repeated",
                "wrap.proof",
                None,
                input(&|i| i.policy.seen.push(i.statement.id())),
                |code| code == 6,
            ),
            (
                "unaccepted format",
                "wrap.proof",
                None,
                input(&|i| i.statement.format = 30),
                |code| code == 2,
            ),
            (
                "wrong io-hash",
                "wrap.proof",
                None,
                input(&|i| i.statement.output.push(0)),
                by_words,
            ),
            (
                "another program than the pin",
                "wrap.proof",
                None,
                input(&|i| i.statement.program = other),
                |code| code == 3,
            ),
            (
                "another space",
                "wrap.proof",
                None,
                input(&|i| i.statement.roots[1].space = SpaceId([0xB2; 32])),
                |code| code == 4,
            ),
            (
                "rootless, another space",
                "wrap.proof",
                None,
                input(&|i| i.statement.roots.clear()),
                |code| code == 4,
            ),
            (
                "the same run, another accepted format",
                "wrap.proof",
                None,
                input(&|i| {
                    let successor = Statement {
                        format: SUCCESSOR,
                        ..i.statement.clone()
                    };
                    i.policy.formats.push(SUCCESSOR);
                    i.policy.seen.push(successor.id());
                }),
                |code| code == 6,
            ),
        ];
        let proofs = [
            ("wrap.proof", &valid),
            ("wrap-prefix.proof", &prefix),
            ("wrap-midway.proof", &midway),
        ];
        let cases: Vec<Case> = cases
            .into_iter()
            .map(|(name, file, patch, input, class)| {
                let proof = proofs.iter().find(|(f, _)| *f == file).unwrap().1;
                let proof = patch
                    .as_ref()
                    .map_or(proof.clone(), |patch| patch.apply(proof));
                let verdict = vos_statement::code(&input.judge(&proof));
                assert!(class(verdict), "{name}: {verdict:#x}");
                eprintln!("{name}: {verdict:#x}");
                Case {
                    name: name.into(),
                    proof: file.into(),
                    patch,
                    input,
                    verdict,
                }
            })
            .collect();
        proofs
            .into_iter()
            .map(|(name, bytes)| (name.to_string(), bytes.clone()))
            .chain([(CASES.to_string(), vos_statement::fixtures::encode(&cases))])
            .collect()
    }
}
