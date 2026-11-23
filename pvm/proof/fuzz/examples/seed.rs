//! Seeds the corpora of the targets that start from the golden fixtures
//! (`pvm/proof/fixtures`) and vectors: `final_verifier_bytes` with every
//! wrap there, `masked_bytes` with `format::MASKED_WRAP`'s past their header,
//! `statement_decode` with every fixture's judgement (its input, then its
//! proof) and its statement alone, `anchor_decode` with `vos-anchor`'s
//! golden vectors, their geneses, an anchor and a migration of each,
//! `device_verify_bytes` with the golden device proof
//! (`device-golden.proof`, its io-hash first) and `device_verify_mutate`
//! with no mutation; `derive_elf` with the compiler's test ELF and the
//! venue guests built in this checkout (`target/riscv64em-vos/release`),
//! `program_blob` with the device kernel, the actor and kernels derived from
//! that ELF and a Gray Paper service program (the PVM's accumulate vector),
//! `service_item` with each fixture's statement and its proof, and a
//! registration, an anchor and a control of each golden vector; and
//! `prove_verify_roundtrip` with a raw run's memory accesses and
//! compression past the zone, a kernel's compression, a static jump to
//! the halt address and runs that stop where no proof ends one
//! (`roundtrip::seeds`), beside the corpus' programs.
//!
//! The golden device proof is kept while the device program accepts it, so
//! the mutation corpus replays against the same proof; it is proved and
//! written anew when the program does not.
//!
//! Those corpora are cleared first: a masked fixture regenerated is
//! another honest proof of the same words, so a proof of an earlier
//! fixture left in a corpus verifies, and the targets' oracle (every
//! accepted proof the golden one) refuses it.
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --example seed
//! ```

use std::path::Path;

use vos_anchor::vectors;
use vos_anchor::{Anchor, RootKind};
use vos_pvm_device::MaskRng;
use vos_statement::fixtures;
use vos_statement_service::item::{Control, Item, Op, Register, SignedControl};

#[path = "../fuzz_targets/device_golden.rs"]
mod device_golden;
#[path = "../fuzz_targets/device_program.rs"]
mod device_program;
#[path = "../fuzz_targets/roundtrip.rs"]
mod roundtrip;
#[path = "../fuzz_targets/service.rs"]
mod service;

/// The golden device proof's bytes, its io-hash first: the kept one while
/// the program accepts it, else an honest proof written anew.
fn device_golden() -> Vec<u8> {
    let program = device_program::program();
    let kept = std::fs::read(device_golden::FILE).ok().filter(|bytes| {
        bytes
            .split_first_chunk::<32>()
            .is_some_and(|(io, proof)| program.verify(io, proof).is_ok())
    });
    kept.unwrap_or_else(|| {
        let (proof, _) = program
            .prove(&device_program::WITNESS, MaskRng::Os)
            .expect("the kernel proves");
        let bytes = [
            &proof.io[..],
            &program.encode(&proof.proof).expect("encodes"),
        ]
        .concat();
        std::fs::write(device_golden::FILE, &bytes).expect("writes the golden device proof");
        println!("{} written anew", device_golden::FILE);
        bytes
    })
}

/// The service program of the PVM's accumulate vector: its first preimage,
/// its metadata stripped.
fn service_program() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../runtime/tests/fixtures/accumulate_ready_queued_reports-1.input.gp072_tiny.json",
    );
    let text = std::fs::read_to_string(&path).expect("the accumulate vector");
    let at = text.find("\"blob\": \"0x").expect("a preimage blob") + "\"blob\": \"0x".len();
    let hex = &text[at..at + text[at..].find('"').expect("the blob's end")];
    let blob: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let (len, read) = vos_pvm::spi::read_nat(&blob, 0).expect("the metadata's length");
    blob[read + len as usize..].to_vec()
}

/// `format::MASKED_WRAP`'s header in its fixed layout: the format and ten
/// words.
const MASKED_HEADER: usize = 4 * 11;

fn main() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for target in [
        "final_verifier_bytes",
        "masked_bytes",
        "statement_decode",
        "anchor_decode",
        "device_verify_bytes",
        "device_verify_mutate",
        "derive_elf",
        "program_blob",
        "service_item",
    ] {
        match std::fs::remove_dir_all(corpus.join(target)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                panic!("clears the {target} corpus: {error}")
            }
            _ => {}
        }
    }
    let write = |target: &str, name: &str, bytes: &[u8]| {
        let directory = corpus.join(target);
        std::fs::create_dir_all(&directory).expect("the corpus' directory");
        std::fs::write(directory.join(name), bytes).expect("writes");
    };
    for (name, bytes) in roundtrip::seeds() {
        write("prove_verify_roundtrip", name, &bytes);
    }
    let directory = fixtures::directory();
    let mut wraps = 0;
    for entry in std::fs::read_dir(&directory).expect("the fixtures' directory") {
        let path = entry.expect("an entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.starts_with("wrap") && name.ends_with(".proof") {
            let bytes = std::fs::read(&path).expect("the wrap");
            write("final_verifier_bytes", name, &bytes);
            if bytes.starts_with(&39u32.to_le_bytes()) {
                write("masked_bytes", name, &bytes[MASKED_HEADER..]);
            }
            wraps += 1;
        }
    }
    assert!(wraps > 0, "no wrap under {}", directory.display());
    let all = fixtures::load(&directory);
    for fixture in &all {
        let name = fixture.name.replace([' ', ','], "-");
        write(
            "statement_decode",
            &format!("{name}.judgement"),
            &fixture.bytes(),
        );
        write(
            "statement_decode",
            &format!("{name}.statement"),
            &fixture.input.statement.encode(),
        );
    }
    for (at, golden) in vectors::golden().iter().enumerate() {
        let vector = &golden.vector;
        let digests = vector.digests();
        write("anchor_decode", &format!("vector-{at}"), &vector.encode());
        write(
            "anchor_decode",
            &format!("genesis-{at}"),
            &vector.genesis.encode(),
        );
        let anchor = Anchor {
            space: digests.space,
            window: vector.window,
            kind: RootKind::Space,
            root: digests.space_root,
            signer: vector.genesis.nodes.first().map_or([0; 32], |node| node.1),
            signature: [0x5a; 64],
        };
        write("anchor_decode", &format!("anchor-{at}"), &anchor.encode());
        let key = anchor.signer;
        let items = [
            (
                "register",
                Item::Register(Register {
                    genesis: vector.genesis.clone(),
                    controller: key,
                    founder_key: key,
                    signature: [0x5a; 64],
                }),
            ),
            ("anchor", Item::Anchor(anchor)),
            (
                "control",
                Item::Control(SignedControl {
                    control: Control {
                        space: digests.space,
                        nonce: 1,
                        op: Op::AddKey([0x11; 32]),
                    },
                    controller: key,
                    signature: [0x5a; 64],
                }),
            ),
        ];
        for (kind, item) in items {
            write(
                "service_item",
                &format!("{kind}-{at}"),
                &service::frame(&item.encode(), None),
            );
        }
    }
    for fixture in &all {
        let name = fixture.name.replace([' ', ','], "-");
        let item = Item::Submit(fixture.input.statement.encode()).encode();
        write(
            "service_item",
            &format!("submit-{name}"),
            &service::frame(&item, Some(&fixture.proof)),
        );
    }
    write("device_verify_bytes", "honest", &device_golden());
    write("device_verify_mutate", "golden", &[]);
    let elf = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compiler/tests/fixtures/roomy.elf"),
    )
    .expect("the compiler's test ELF");
    write("derive_elf", "roomy.elf", &elf);
    let guests =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target/riscv64em-vos/release");
    for entry in std::fs::read_dir(&guests).into_iter().flatten() {
        let path = entry.expect("an entry").path();
        if path.extension().is_some_and(|extension| extension == "elf") {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            write("derive_elf", name, &std::fs::read(&path).expect("a guest"));
        }
    }
    write("program_blob", "device-kernel", &device_program::kernel());
    write("program_blob", "service", &service_program());
    let derived = vos_pvm_compiler::derive(&elf).expect("the test ELF derives");
    write("program_blob", "roomy-actor", &derived.actor);
    for (method, kernel) in &derived.kernels {
        write("program_blob", &format!("roomy-kernel-{method}"), kernel);
    }
    println!("{} fixtures seeded under {}", all.len(), corpus.display());
}
