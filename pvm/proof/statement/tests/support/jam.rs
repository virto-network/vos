//! The venue's JAM programs on the JAM-only host, at PolkaJam's prices:
//! the refine program (`final-verify.elf`, linking format 39 alone, and
//! `final-verify-test.elf`, linking 28 beside it), its request as work item
//! 0's payload and the proof as a preimage of the running service; and any
//! service's refine and accumulate (`statement-service.elf`'s), each built
//! by `just check-no-std`. Shared by the tests that run them, each including
//! this file.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::AccumulateContext;
use vos_pvm::refine::PreparedProgram;
use vos_pvm::refine_host::{JamItem, JamRefine, Preimages, RefineContext};
use vos_statement::model::Input;
use vos_statement::vos_pvm_final_verifier::PUBLIC_WORDS;

/// The guest's verdicts.
pub const ACCEPT: u64 = 1;
pub const REJECT: u64 = 0;
pub const BAD_PAYLOAD: u64 = 2;
pub const UNDECODABLE: u64 = 4;

const SERVICE: u64 = 7;

/// What the guest reports: its verdict, the gas left at its start, after
/// the proof's lookup, after its decode and at its end; the proof's
/// length; its heap's peak, high-water mark and allocations; a refusal's
/// text; a judgement's code and an accepted statement's id; a golden
/// vector's digests.
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
    pub digests: Vec<u8>,
}

/// The production guest, linking format 39 alone, linked: its program and
/// its ELF's length.
pub fn program() -> (Vec<u8>, usize) {
    guest("final-verify")
}

/// The test guest, linking format 28 beside 39, linked: its program and its
/// ELF's length.
pub fn test_program() -> (Vec<u8>, usize) {
    guest("final-verify-test")
}

/// `target/riscv64em-vos/release/<name>.elf` of the workspace holding the
/// crate that includes this file, linked: its program and its ELF's length.
pub fn guest(name: &str) -> (Vec<u8>, usize) {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .find(|dir| dir.join("Cargo.lock").exists() && dir.join("pvm").is_dir())
        .expect("the workspace's root");
    let path = root.join(format!("target/riscv64em-vos/release/{name}.elf"));
    let elf = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{} missing ({error}); run `just check-no-std`",
            path.display()
        )
    });
    let program = vos_pvm_compiler::link_elf_spi(&elf).expect("links the guest");
    (program, elf.len())
}

/// A request to verify a proof of `format` against `words`.
pub fn words_request(format: u32, words: &[u32; PUBLIC_WORDS]) -> Vec<u8> {
    let mut request = vec![0];
    request.extend(format.to_le_bytes());
    request.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    request
}

/// A request to judge a statement: `input`, then the proof.
pub fn judge_request(input: &Input) -> Vec<u8> {
    [&[1][..], &input.encode()].concat()
}

/// A request to compute a golden vector's digests: its encoding.
pub fn anchors_request(vector: &[u8]) -> Vec<u8> {
    [&[2][..], vector].concat()
}

/// The guest run on `request` and `proof`: its gas and its report.
pub fn run(program: &[u8], request: &[u8], proof: &[u8]) -> (u64, GuestReport) {
    let hash = vos_statement::blake2b_256(&[proof]);
    let mut payload = request.to_vec();
    payload.extend_from_slice(&hash);
    payload.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    run_payload(program, payload, Some(proof))
}

/// The guest run on `payload` as work item 0's, `proof` a preimage of the
/// service if any: its gas and its report.
pub fn run_payload(program: &[u8], payload: Vec<u8>, proof: Option<&[u8]>) -> (u64, GuestReport) {
    struct Store(BTreeMap<[u8; 32], Vec<u8>>);
    impl Preimages for Store {
        fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
            (service == SERVICE)
                .then(|| self.0.get(hash).cloned())
                .flatten()
        }
    }
    let preimages = proof.map(|proof| (vos_statement::blake2b_256(&[proof]), proof.to_vec()));
    let jam = JamRefine {
        service: SERVICE,
        items: vec![JamItem {
            payload,
            ..JamItem::default()
        }],
        preimages: Some(Arc::new(Store(preimages.into_iter().collect()))),
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
        digests: bytes[312..472].to_vec(),
    };
    (invocation.gas_used, report)
}

/// A service's refine of item `jam.item` on the JAM-only host: its exit,
/// the gas it took and its output.
#[derive(Debug)]
pub struct Refined {
    pub exit: ExitReason,
    pub gas: u64,
    pub output: Vec<u8>,
}

/// `program`'s refine, given `args` (`E(c, i, s, ↕payload, H(p))`) and
/// `jam`, with `gas`.
pub fn refine(program: &[u8], args: &[u8], jam: JamRefine, gas: u64) -> Refined {
    let context = RefineContext::load(program, args, gas).expect("loads the program");
    let run = context.try_run_jam(jam).expect("the JAM-only host");
    let invocation = run.invocation;
    assert_ne!(invocation.registers[7], 0xDEAD, "the program panicked");
    let output = match invocation.exit {
        ExitReason::Halt => invocation.output_bounded(1 << 20).unwrap_or_default(),
        _ => Vec::new(),
    };
    Refined {
        exit: invocation.exit,
        gas: invocation.gas_used,
        output,
    }
}

/// `program`'s accumulate as service `service` at `slot` over `inputs`
/// (each `fetch` kind 15's), on `storage`, with `gas`: its exit and the gas
/// it took. The host charges each call the accumulate host's base, not
/// PolkaJam's per-call prices.
pub fn accumulate(
    program: &PreparedProgram,
    slot: u64,
    service: u64,
    inputs: &[Vec<u8>],
    storage: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    gas: u64,
) -> (ExitReason, u64) {
    let invocation = AccumulateContext::load(program, slot, service, inputs, gas, storage)
        .expect("loads the program at accumulate")
        .try_run()
        .expect("the accumulate host");
    (invocation.exit, invocation.gas_used)
}
