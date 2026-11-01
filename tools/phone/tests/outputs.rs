//! The phone bench's outputs carry no secret: its `run`, `verify` and
//! `kernel` commands, run as a phone runs them, their standard output (the
//! JSON lines), standard error and the proofs they write searched for the
//! member's secret, the device kernel's arguments and the member's place
//! (`vos_checker::carriers`).

use std::path::Path;
use std::process::Command;

use vos_checker::carriers::{Audit, Kind, Reach};
use vos_pvm_recair::device::{auth_arguments, auth_public};
use vos_wire::SpaceId;
use vos_wire::credentials::{self as tree, DEPTH, EMPTY, Siblings, Tag, Words, leaf, root_of};
use vos_wire::ids::{AgentId, InstanceId};

/// The bench's own fixed member (`main.rs`): its source's output and the
/// space's handle, its slot and its path's occupied siblings.
const SOURCE_OUTPUT: [u8; 32] = [0x6f; 32];
const HANDLE: [u8; 32] = [0x48; 32];
const SLOT: u32 = 0x1234_5678;

fn siblings() -> [Words; DEPTH] {
    let mut siblings: [Words; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
    for (n, level) in [0, 5, 17].into_iter().enumerate() {
        siblings[level] = core::array::from_fn(|i| (n as u32 + 1) * 1_000_003 + i as u32);
    }
    siblings
}

/// The bench run with `args`: its standard output and error, as carriers.
fn run(audit: &mut Audit, name: &str, args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_vos-phone"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty(), "{name} printed its lines");
    audit.carrier(
        format!("{name}: standard output"),
        Reach::Leaves,
        output.stdout,
    );
    audit.carrier(
        format!("{name}: standard error"),
        Reach::Leaves,
        output.stderr,
    );
}

/// Every file under `dir`, as carriers.
fn files(audit: &mut Audit, dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        audit.carrier(path.display().to_string(), Reach::Leaves, bytes);
    }
}

#[test]
fn the_benchs_lines_and_proofs_hold_no_secret() {
    let mut audit = Audit::default();
    let words = audit
        .needles
        .device_secret("the bench's member", &SOURCE_OUTPUT, &HANDLE);
    let member = tree::digest(&tree::compress(&Tag::Member.block(), &words));
    let siblings = siblings();
    let root = root_of(&leaf(&tree::words(&member).unwrap()), SLOT, &siblings);
    let path = tree::Path {
        root: tree::digest(&root),
        slot: SLOT,
        siblings: Siblings(siblings.map(|sibling| tree::digest(&sibling))),
    };
    audit
        .needles
        .member_place("the bench's member", &member, &path);

    // A device kernel's witness input for auth's statement by the member.
    let scope = tree::scope(&SpaceId([0x53; 32]), AgentId(7), InstanceId(3), b"login");
    let nullifier = tree::digest(&tree::compress(
        &tree::compress(&Tag::Nf.block(), &words),
        &tree::words(&scope).unwrap(),
    ));
    let binding = tree::binding(&[0x62; 32]);
    let public = auth_public(&path.root, &scope, &nullifier, &binding);
    let input = auth_arguments(&siblings, &words, SLOT, &public);
    audit
        .needles
        .kernel_arguments("the bench's member", &input, public.len());

    let dir = tempfile::tempdir().unwrap();
    let proofs = dir.path().join("proofs");
    let kernel = dir.path().join("kernel");
    let witness = dir.path().join("input");
    let proved = dir.path().join("kernel.proof");
    std::fs::write(&kernel, vos_testkit::programs::kernel("device", "auth")).unwrap();
    std::fs::write(&witness, &input).unwrap();
    let out = proofs.to_str().unwrap();
    run(
        &mut audit,
        "run",
        &[
            "run",
            "--reps",
            "1",
            "--threads",
            "4",
            "--grind",
            "2",
            "--out",
            out,
        ],
    );
    run(&mut audit, "verify", &["verify", out]);
    run(
        &mut audit,
        "kernel",
        &[
            "kernel",
            "--kernel",
            kernel.to_str().unwrap(),
            "--input",
            witness.to_str().unwrap(),
            "--out",
            proved.to_str().unwrap(),
            "--threads",
            "4",
        ],
    );
    files(&mut audit, &proofs);
    audit.carrier(
        "the kernel's proof",
        Reach::Leaves,
        std::fs::read(&proved).unwrap(),
    );

    eprintln!("{}", audit.summary());
    audit.assert_searchable(&[Kind::DeviceSecret, Kind::MemberPlace]);
    audit.assert_clean();
}
