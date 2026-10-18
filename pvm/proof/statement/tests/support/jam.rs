//! The venue's JAM refine program (`final-verify.elf`, built by `just
//! check-no-std`) on the JAM-only host, at PolkaJam's prices: the request
//! as work item 0's payload and the proof as a preimage of the running
//! service. Shared by the tests that run it, each including this file.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use vos_final_verifier::PUBLIC_WORDS;
use vos_pvm::refine_host::{JamItem, JamRefine, Preimages, RefineContext};
use vos_statement::model::Input;

/// The guest's verdicts.
pub const ACCEPT: u64 = 1;
pub const REJECT: u64 = 0;
pub const UNDECODABLE: u64 = 4;

const SERVICE: u64 = 7;

/// What the guest reports: its verdict, the gas left at its start, after
/// the proof's lookup, after its decode and at its end; the proof's
/// length; its heap's peak, high-water mark and allocations; a refusal's
/// text; a judgement's code and an accepted statement's id.
#[derive(Debug)]
pub struct GuestReport {
    pub verdict: u64,
    pub gas: [u64; 4],
    pub peak_live: u64,
    pub high_water: u64,
    pub allocs: u64,
    pub error: String,
    pub code: u64,
    pub id: [u8; 32],
}

/// The guest, linked: `target/riscv64em-vos/release/final-verify.elf` of
/// the workspace holding the crate that includes this file.
pub fn program() -> (Vec<u8>, usize) {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .find(|dir| dir.join("Cargo.lock").exists() && dir.join("pvm").is_dir())
        .expect("the workspace's root");
    let path = root.join("target/riscv64em-vos/release/final-verify.elf");
    let elf = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{} missing ({error}); run `just check-no-std`",
            path.display()
        )
    });
    let program = vos_pvm_compiler::link_elf_spi(&elf).expect("links the guest");
    (program, elf.len())
}

/// A request to verify a proof against `words`.
pub fn words_request(words: &[u32; PUBLIC_WORDS]) -> Vec<u8> {
    let mut request = vec![0];
    request.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    request
}

/// A request to judge a statement: `input`, then the proof.
pub fn judge_request(input: &Input) -> Vec<u8> {
    [&[1][..], &input.encode()].concat()
}

/// The guest run on `request` and `proof`: its gas and its report.
pub fn run(program: &[u8], request: &[u8], proof: &[u8]) -> (u64, GuestReport) {
    struct Store(BTreeMap<[u8; 32], Vec<u8>>);
    impl Preimages for Store {
        fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
            (service == SERVICE)
                .then(|| self.0.get(hash).cloned())
                .flatten()
        }
    }
    let hash = vos_statement::blake2b_256(&[proof]);
    let mut payload = request.to_vec();
    payload.extend_from_slice(&hash);
    payload.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    let jam = JamRefine {
        service: SERVICE,
        items: vec![JamItem {
            payload,
            imports: Vec::new(),
        }],
        preimages: Some(Arc::new(Store(BTreeMap::from([(hash, proof.to_vec())])))),
        ..JamRefine::default()
    };
    let context = RefineContext::load(program, &[], 10_000_000_000).expect("loads the guest");
    let run = context.try_run_jam(jam).expect("the JAM-only host");
    let invocation = &run.invocation;
    assert_ne!(invocation.registers[7], 0xDEAD, "the guest panicked");
    let bytes = invocation.output_bounded(4096).expect("the guest's report");
    let word = |i: usize| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap());
    let error_len = (word(9) as usize).min(192);
    let report = GuestReport {
        verdict: word(0),
        gas: [word(1), word(2), word(3), word(4)],
        peak_live: word(6),
        high_water: word(7),
        allocs: word(8),
        error: String::from_utf8_lossy(&bytes[80..80 + error_len]).into_owned(),
        code: word(34),
        id: bytes[280..312].try_into().unwrap(),
    };
    (invocation.gas_used, report)
}
