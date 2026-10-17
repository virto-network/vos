#![cfg(feature = "prover")]

//! The segment fixtures under `pvm/proof/fixtures` (`proving.md` A.6), and
//! their generator. For each admitted segment format, a fixed small
//! kernel's run proved as one segment of its program:
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

mod common;

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

/// The kernel: two constants, their product and sum, then a halt with an
/// empty output.
fn kernel() -> Vec<u8> {
    let load = |register: u8, value: u8| [Opcode::LoadImm as u8, register, value, 0, 0, 0];
    let mut code = Vec::new();
    let mut starts = Vec::new();
    for instruction in [
        &load(2, 5)[..],
        &load(3, 7),
        &[Opcode::Mul64 as u8, 3 << 4 | 2, 4],
        &[Opcode::Add64 as u8, 4 << 4 | 2, 5],
        &load(8, 0),
        &[Opcode::JumpInd as u8, 0],
    ] {
        starts.push(code.len());
        code.extend_from_slice(instruction);
    }
    let mut bitmask = vec![0; code.len()];
    for start in starts {
        bitmask[start] = 1;
    }
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

/// The kernel's program under `format`.
fn program(blob: &[u8], format: &'static Format) -> KernelProgram {
    let record = vos_wire::records::Kernel {
        method: MethodId(1),
        program: ProgramHash::of(blob),
        image_root: vos_pvm_program::parse_standard_program(blob)
            .and_then(|program| program.image_root())
            .expect("an image root"),
        shape: kernel_shape(blob).expect("a shape"),
    };
    common::kernel_program(blob, &record, format)
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
    for (format, other) in FORMATS {
        for (name, bytes) in generate(format, other) {
            if write {
                std::fs::create_dir_all(directory()).expect("the fixtures' directory");
                std::fs::write(directory().join(&name), &bytes).expect("writes");
                eprintln!("{name}: {} bytes", bytes.len());
            } else if std::fs::read(directory().join(&name)).ok().as_ref() != Some(&bytes) {
                stale.push(name);
            }
        }
    }
    assert!(
        stale.is_empty(),
        "stale fixtures under pvm/proof/fixtures: {stale:?}. The generator \
         (pvm/proof/tests/fixtures.rs) makes other bytes: the AIR, a format, \
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
