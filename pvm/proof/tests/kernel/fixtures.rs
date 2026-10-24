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
use vos_pvm_proof::format::{Format, SEGMENT, WRAP};
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::pcs::{Commitment, StarkProofAny};
use vos_pvm_proof::program_id::KernelProgram;
use vos_pvm_proof::{Proof, prove_kernel};
use vos_pvm_proof_verifier::{verify_kernel_segment, verify_standalone};
use vos_wire::ids::{MethodId, ProgramHash};

/// The admitted segment formats, each with the one its wrong-format
/// fixture is relabelled to: the wrap's, admitted but no segment format.
const FORMATS: [(&Format, u32); 1] = [(&SEGMENT, WRAP.number)];

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
/// fixtures test, the Wasm harness's `judge`), each build by the formats it
/// links (`vos_statement::fixtures::Fixture::verdict_linking`).
///
/// The kernel states a fixed statement `S`: it sets φ9..12 to `S`'s
/// io-hash, an output of its own, two roots of its space read and its
/// `public_args` the venue's id and a nonce, as a venue-bound program's,
/// then halts. Its run, cut in three segments, is proved at its class, its
/// leaves folded to a root and the root wrapped under `format::MASKED_WRAP`, masked
/// from the seeded test seam (`MaskRng::Seeded`, so the bytes are the
/// generator's every run): `wrap.proof`; and under `format::WRAP`:
/// `wrap-28.proof`. Two roots that are not a whole run, wrapped under 39 as
/// a cheating prover would (the wrap circuit's checks failing, proved
/// anyway): `wrap-prefix.proof`, the first two segments, which set the
/// io-hash but never halt; `wrap-midway.proof`, the last two, labelled from
/// position 0, which never start at the entry. A second kernel states a
/// rootless statement `S0`, of no space, in one segment, its leaf wrapped
/// under 39: `wrap-rootless.proof`.
///
/// The production venue pins the kernel's program id, venue-bound, accepts
/// `format::MASKED_WRAP`, registers `S`'s space from window 40, anchors `S`'s two roots
/// (windows 41 and 42), judges at window 42's boundary and has accepted one
/// other statement. The test venue is the same and accepts 28 beside 39.
/// The cases (`statements.cases`), each a venue's state, a statement and a
/// proof, each but the valid ones a replay of a valid statement with one
/// thing changed, so each fails one check alone: a venue that verifies the
/// proof before it reads its state (the JAM service's refine) reaches the
/// same class as one that reads its state first:
/// - **valid:** `S` and its wrap, accepted; **rootless:** `S0` and its
///   wrap, accepted (its own program pinned);
/// - **tampered:** a byte of the wrap flipped;
/// - **wrong program:** the venue pins another program, which the statement
///   names, and the wrap is this kernel's;
/// - **unanchored root:** `S` at a venue that does not anchor its first
///   root;
/// - **prefix**, **mid-way:** `S` with the wraps of a part of the run;
/// - **repeated:** `S` after the venue accepted it;
/// - **unaccepted format:** `S` under `format::CREDENTIAL_PROOF`;
/// - **`format::WRAP` at a production venue:** `S` under 28, with its wrap;
/// - **wrong io-hash:** `S` with its output changed;
/// - **another program than the pin:** the statement names another program
///   than the one the venue pinned;
/// - **another space:** a root of another space than `S`'s;
/// - **the space:** `S` claiming another space than its roots';
/// - **rootless, another space:** `S` without its roots, its space still
///   claimed: a rootless statement belongs to no space, since nothing
///   binds it there and each space would give one proof another id;
/// - **rooted, of no space:** `S` claiming `SpaceId::NONE`, its roots of
///   none too and anchored: no space has the id `NONE`;
/// - **another venue's statement:** `S` with `public_args` naming another
///   venue; **replayed at another venue:** `S` at a venue of another id;
/// - **a root's window**, **a root:** `S` at a venue that holds its second
///   root at another window, or another root at its window;
/// - **the nonce:** `S` with its nonce changed; **the roots' order:** its
///   two roots swapped; **a root dropped:** its second root left out; each
///   bound by the proof's words through the io-hash;
/// - **migrated before a root's window:** the venue's range for `S`'s
///   space ends at window 42; **registered after a root's window:** it
///   starts at 42;
/// - **rooted, replayed past MaxRootAge:** `S` accepted, then the venue's
///   time past its newest root's `MaxRootAge`: its `Seen` entry and its
///   anchors dropped, it is unanchored;
/// - **rootless, replayed past MaxRootAge:** `S0` accepted, then the same
///   time passed: its `Seen` entry kept, it is repeated;
/// - **the test policy:** `S` under 28 at the test venue, accepted; its
///   wrap's byte flipped; and the transition both ways, `S` accepted under
///   39 and replayed under 28, and accepted under 28 and replayed under 39,
///   each repeated, since the id does not hash the format.
mod statements {
    use stwo::core::fields::qm31::SecureField;
    use vos_pvm::instruction::Opcode;
    use vos_pvm_final_verifier::{WrapProof, masked, unmasked};
    use vos_pvm_proof::format::SEGMENT;
    use vos_pvm_proof::kernel::trace_kernel;
    use vos_pvm_proof::program_id::{KernelEntry, KernelProgram};
    use vos_pvm_proof::prove_shaped;
    use vos_pvm_proof::segment::SegmentCursor;
    use vos_pvm_recair::Context;
    use vos_pvm_recair::fold::FoldCircuit;
    use vos_pvm_recair::masked::MaskRng;
    use vos_pvm_recair::wrap::{self, WrapCircuit};
    use vos_statement::fixtures::{CASES, Case, Patch};
    use vos_statement::model::{Input, Policy, Range, Space};
    use vos_statement::{
        MAX_ROOT_AGE_MS, Pin, ProgramId, RootKind, RootRead, SpaceId, Statement, StatementId,
        VenueId, WindowClock,
    };

    use super::common::{self, NodeRun};
    use super::record;

    const SPACE: SpaceId = SpaceId([0xA1; 32]);
    const OTHER_SPACE: SpaceId = SpaceId([0xB2; 32]);
    /// The masks' seed: the masked wraps are the generator's byte for byte.
    const SEED: u64 = 0x6_05;
    /// The run's cuts: the io-hash set in the first two, the halt in the
    /// last.
    const CUTS: [(usize, usize); 3] = [(0, 2), (2, 5), (5, 6)];
    /// The space's clock: windows of 10 minutes from the Unix epoch.
    const CLOCK: WindowClock = WindowClock::DEFAULT;
    /// The venues' time: window 42's boundary, so windows 41 and 42 are
    /// closed and anchored.
    const NOW: u64 = 43 * 600_000;

    /// The venue: a JAM service's.
    fn venue() -> VenueId {
        VenueId::jam(&[0x4A; 32], 7)
    }

    fn root(window: u64, byte: u8) -> RootRead {
        RootRead {
            kind: RootKind::Space,
            space: SPACE,
            window,
            root: [byte; 32],
        }
    }

    /// `S`, its program left to fill: venue-bound, its `public_args` the
    /// venue's id and a nonce.
    fn statement() -> Statement {
        Statement {
            format: masked::FORMAT,
            program: ProgramId([0; 8]),
            space: SPACE,
            public_args: [&venue().0[..], b"nonce 7"].concat(),
            output: b"the statement's output".to_vec(),
            roots: vec![root(41, 0x41), root(42, 0x42)],
        }
    }

    /// `S0`, its program left to fill: rootless, of no space.
    fn rootless() -> Statement {
        Statement {
            format: masked::FORMAT,
            program: ProgramId([0; 8]),
            space: SpaceId::NONE,
            public_args: [&venue().0[..], b"nonce 8"].concat(),
            output: b"the rootless statement's output".to_vec(),
            roots: Vec::new(),
        }
    }

    /// The kernel stating `io_hash`: φ8, the output's length, 0; φ9..12 the
    /// io-hash's bytes, eight a register, little-endian; then the halt.
    fn kernel(io_hash: &[u8; 32]) -> Vec<u8> {
        let mut instructions = vec![super::load(8, 0)];
        for (register, bytes) in (9..).zip(io_hash.chunks_exact(8)) {
            let mut instruction = vec![Opcode::LoadImm64 as u8, register];
            instruction.extend_from_slice(bytes);
            instructions.push(instruction);
        }
        instructions.push(vec![Opcode::JumpInd as u8, 0]);
        common::standard_program(&instructions)
    }

    /// A kernel stating `statement`: its program, its entry and its run's
    /// segments, cut at `cuts`.
    fn proved(
        statement: &Statement,
        cuts: &[(usize, usize)],
    ) -> (KernelProgram, KernelEntry, Vec<vos_pvm_proof::Proof>) {
        let blob = kernel(&statement.io_hash());
        let (program, entry) = vos_pvm_recair::leaf::kernel_program(
            &blob,
            &record(&blob),
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .expect("the kernel's program");
        let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
        assert_eq!(trace.side_note.steps.len(), cuts[cuts.len() - 1].1);
        assert_eq!(trace.io_hash, statement.io_hash());
        let shape = program.shape.segment(0).expect("class 0");
        let mut cursor = SegmentCursor::new(&trace.side_note);
        let segments = cuts
            .iter()
            .map(|&(a, b)| {
                prove_shaped(&mut cursor.side_note(a, b), &shape, &SEGMENT).expect("proves")
            })
            .collect();
        (program, entry, segments)
    }

    /// The finalized wrap of `root`: as the circuit requires it, or, with
    /// `lenient`, over a root its checks refuse, as a cheating prover would.
    fn finalized(
        root: &NodeRun,
        program: &KernelProgram,
        lenient: bool,
    ) -> vos_pvm_recair::Finalized<SecureField> {
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
        context.finalize().expect("the wrap's wiring checks")
    }

    /// The wrap of `root` under `format::MASKED_WRAP`, masked from the seeded seam: its
    /// fixed layout.
    fn masked_wrap(root: &NodeRun, program: &KernelProgram, lenient: bool) -> Vec<u8> {
        let (proof, _) = wrap::prove_masked(
            &finalized(root, program, lenient),
            MaskRng::Seeded(SEED),
            |_| {},
        )
        .expect("the wrap proves");
        assert_eq!(proof.format_version, masked::FORMAT);
        wrap::proof_bytes(&proof).expect("the fixed layout holds it")
    }

    /// The wrap of `root` under `format::WRAP`: postcard.
    fn unmasked_wrap(root: &NodeRun, program: &KernelProgram) -> Vec<u8> {
        let proof: WrapProof =
            wrap::prove_unmasked(&finalized(root, program, false)).expect("the wrap proves");
        assert_eq!(proof.format_version, unmasked::FORMAT);
        postcard::to_allocvec(&proof).expect("encodes")
    }

    /// The fixtures, by file name.
    pub fn generate() -> Vec<(String, Vec<u8>)> {
        let base = statement();
        let (program, entry, segments) = proved(&base, &CUTS);
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

        let valid = masked_wrap(&whole, &program, false);
        let prefix = masked_wrap(&head, &program, true);
        let midway = masked_wrap(&tail, &program, true);
        let valid_28 = unmasked_wrap(&whole, &program);

        let lone = rootless();
        let (lone_program, lone_entry, lone_segments) = proved(&lone, &[(0, 6)]);
        let lone_leaf =
            common::prove_leaf(&lone_program, &lone_entry, 0, &lone_segments[0], 0, word);
        assert!(lone_leaf.node.output.entry && lone_leaf.node.output.halt);
        let valid_rootless = masked_wrap(&lone_leaf, &lone_program, false);

        let pinned = ProgramId(program.id().0.map(|word| word.0));
        let other = ProgramId(pinned.0.map(|word| (word + 1) % ((1 << 31) - 1)));
        let s = Statement {
            program: pinned,
            ..base
        };
        let s0 = Statement {
            program: ProgramId(lone_program.id().0.map(|word| word.0)),
            ..lone
        };
        let production = {
            let mut policy = Policy::new(venue(), NOW, &[masked::FORMAT]);
            policy.spaces.push(Space {
                id: SPACE,
                clock: CLOCK,
                range: Range {
                    from: 40,
                    until: None,
                },
            });
            policy.anchors = s.roots.clone();
            policy.seen.push((
                StatementId(vos_statement::blake2b_256(&[b"an earlier statement"])),
                u64::MAX,
            ));
            policy
        };
        let test = Policy {
            formats: vec![unmasked::FORMAT, masked::FORMAT],
            ..production.clone()
        };
        let input = |change: &dyn Fn(&mut Input)| {
            let mut input = Input {
                pin: Pin {
                    program: pinned,
                    venue_bound: true,
                },
                policy: production.clone(),
                statement: s.clone(),
            };
            change(&mut input);
            input
        };
        let rootless_input = |change: &dyn Fn(&mut Input)| {
            input(&|i| {
                i.pin.program = s0.program;
                i.statement = s0.clone();
                change(i);
            })
        };
        // The venue's time past the newest root's `MaxRootAge`.
        let past = CLOCK.boundary(42).unwrap() + MAX_ROOT_AGE_MS + 1;
        let under_28 = |i: &mut Input| i.statement.format = unmasked::FORMAT;
        // `S` under 28 at the test venue.
        let at_test_venue_28 = |i: &mut Input| {
            i.policy = test.clone();
            under_28(i);
        };
        // `S` accepted under `format`'s wrap at the test venue, then recorded.
        let accepted_under = |format: u32, proof: &[u8]| {
            let accepted = input(&|i| {
                i.policy = test.clone();
                i.statement.format = format;
            });
            let id = accepted.judge(proof).expect("S accepted");
            assert_eq!(id, s.id(), "S under {format}");
            let mut policy = accepted.policy;
            policy.record(&accepted.statement);
            policy
        };
        let after_39 = accepted_under(masked::FORMAT, &valid);
        let after_28 = accepted_under(unmasked::FORMAT, &valid_28);

        let flip = |bytes: &Vec<u8>| {
            let mut flipped = bytes.clone();
            flipped[bytes.len() / 2] ^= 1;
            Patch::between(bytes, &flipped)
        };
        type Class = fn(u32) -> bool;
        let accepted: Class = |code| code == 0;
        let by_proof: Class = |code| code >> 8 == 1;
        let by_words: Class = |code| code == 0x108 || code == 0x109;
        let cases: Vec<(&str, &str, Option<Patch>, Input, Class)> = vec![
            ("valid", "wrap.proof", None, input(&|_| {}), accepted),
            (
                "rootless",
                "wrap-rootless.proof",
                None,
                rootless_input(&|_| {}),
                accepted,
            ),
            (
                "tampered",
                "wrap.proof",
                Some(flip(&valid)),
                input(&|_| {}),
                by_proof,
            ),
            (
                "wrong program",
                "wrap.proof",
                None,
                input(&|i| {
                    i.pin.program = other;
                    i.statement.program = other;
                }),
                by_words,
            ),
            (
                "unanchored root",
                "wrap.proof",
                None,
                input(&|i| {
                    i.policy.anchors.remove(0);
                }),
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
                input(&|i| i.policy.record(&i.statement)),
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
                "format 28 at a production venue",
                "wrap-28.proof",
                None,
                input(&under_28),
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
                input(&|i| i.statement.roots[1].space = OTHER_SPACE),
                |code| code == 4,
            ),
            (
                "the space",
                "wrap.proof",
                None,
                input(&|i| i.statement.space = OTHER_SPACE),
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
                "rooted, of no space",
                "wrap.proof",
                None,
                input(&|i| {
                    i.statement.space = SpaceId::NONE;
                    for root in &mut i.statement.roots {
                        root.space = SpaceId::NONE;
                    }
                    i.policy.spaces[0].id = SpaceId::NONE;
                    i.policy.anchors = i.statement.roots.clone();
                }),
                |code| code == 4,
            ),
            (
                "another venue's statement",
                "wrap.proof",
                None,
                input(&|i| i.statement.public_args[31] ^= 1),
                |code| code == 7,
            ),
            (
                "replayed at another venue",
                "wrap.proof",
                None,
                input(&|i| i.policy.venue = VenueId::jam(&[0x4A; 32], 8)),
                |code| code == 7,
            ),
            (
                "a root's window",
                "wrap.proof",
                None,
                input(&|i| i.policy.anchors[1].window = 43),
                |code| code == 5,
            ),
            (
                "a root",
                "wrap.proof",
                None,
                input(&|i| i.policy.anchors[1].root[31] ^= 1),
                |code| code == 5,
            ),
            (
                "the nonce",
                "wrap.proof",
                None,
                input(&|i| *i.statement.public_args.last_mut().unwrap() ^= 1),
                by_words,
            ),
            (
                "the roots' order",
                "wrap.proof",
                None,
                input(&|i| i.statement.roots.swap(0, 1)),
                by_words,
            ),
            (
                "a root dropped",
                "wrap.proof",
                None,
                input(&|i| {
                    i.statement.roots.pop();
                }),
                by_words,
            ),
            (
                "migrated before a root's window",
                "wrap.proof",
                None,
                input(&|i| {
                    i.policy.spaces[0].range = Range {
                        from: 40,
                        until: Some(42),
                    }
                }),
                |code| code == 5,
            ),
            (
                "registered after a root's window",
                "wrap.proof",
                None,
                input(&|i| {
                    i.policy.spaces[0].range = Range {
                        from: 42,
                        until: None,
                    }
                }),
                |code| code == 5,
            ),
            (
                "rooted, replayed past MaxRootAge",
                "wrap.proof",
                None,
                input(&|i| {
                    i.policy.record(&i.statement);
                    i.policy.advance(past);
                }),
                |code| code == 5,
            ),
            (
                "rootless, replayed past MaxRootAge",
                "wrap-rootless.proof",
                None,
                rootless_input(&|i| {
                    i.policy.record(&i.statement);
                    i.policy.advance(past);
                }),
                |code| code == 6,
            ),
            (
                "format 28 at the test venue",
                "wrap-28.proof",
                None,
                input(&at_test_venue_28),
                accepted,
            ),
            (
                "tampered, format 28 at the test venue",
                "wrap-28.proof",
                Some(flip(&valid_28)),
                input(&at_test_venue_28),
                by_proof,
            ),
            (
                "accepted under 39, replayed under 28",
                "wrap-28.proof",
                None,
                input(&|i| {
                    i.policy = after_39.clone();
                    under_28(i);
                }),
                |code| code == 6,
            ),
            (
                "accepted under 28, replayed under 39",
                "wrap.proof",
                None,
                input(&|i| i.policy = after_28.clone()),
                |code| code == 6,
            ),
        ];
        let proofs = [
            ("wrap.proof", &valid),
            ("wrap-rootless.proof", &valid_rootless),
            ("wrap-prefix.proof", &prefix),
            ("wrap-midway.proof", &midway),
            ("wrap-28.proof", &valid_28),
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
