//! The phone bench's outputs carry no secret: its `run`, `verify` and
//! `kernel` commands, run as a phone runs them, their standard output (the
//! JSON lines), standard error and the proofs they write searched for the
//! member's secret, the device kernel's arguments and the member's place
//! (`vos_checker::carriers`).

use std::path::Path;
use std::process::Command;

use vos_abi::credentials as tree;
use vos_abi::credentials::{Tag, member_root};
use vos_abi::ids::{AgentId, InstanceId};
use vos_abi::{Encode, SpaceId};
use vos_checker::carriers::{Audit, Kind, Reach};
use vos_wire::credentials::{AuthClaim, Siblings, binding, scope};

#[allow(dead_code)]
#[path = "../src/member.rs"]
mod member;

use member::{HANDLE, SLOT, SOURCE_OUTPUT, siblings};

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
    let root = member_root(&tree::words(&member).unwrap(), SLOT, &siblings);
    let path = vos_wire::credentials::Path {
        root: tree::digest(&root),
        slot: SLOT,
        siblings: Siblings(siblings.map(|sibling| tree::digest(&sibling))),
    };
    audit
        .needles
        .member_place("the bench's member", &member, &path);

    // The stock auth kernel's witness input by the member: the path's
    // siblings and its slot's eight bytes, the secret, the claim.
    let scope = scope(&SpaceId([0x53; 32]), AgentId(7), InstanceId(3), b"login");
    let nullifier = tree::digest(&tree::compress(
        &tree::compress(&Tag::Nf.block(), &words),
        &tree::words(&scope).unwrap(),
    ));
    let claim = AuthClaim {
        map_root: path.root,
        scope,
        nullifier,
        binding: binding(&[0x62; 32]),
    }
    .encode();
    let mut input = path.siblings.0.concat();
    input.extend_from_slice(&u64::from(SLOT).to_le_bytes());
    input.extend_from_slice(&tree::digest(&words));
    input.extend_from_slice(&claim);
    audit
        .needles
        .kernel_arguments("the bench's member", &input, claim.len());

    let dir = tempfile::tempdir().unwrap();
    let proofs = dir.path().join("proofs");
    let kernel = dir.path().join("kernel");
    let witness = dir.path().join("input");
    let proved = dir.path().join("kernel.proof");
    let elf = std::fs::read(vos_testkit::programs::program_elf("vos-credentials")).unwrap();
    let device = vos_light::release::device(&elf, "auth").unwrap();
    std::fs::write(&kernel, vos_abi::Encode::encode(&device)).unwrap();
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
            "--device",
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
