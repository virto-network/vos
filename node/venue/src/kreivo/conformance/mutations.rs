//! The mutation lists (`slice-6-on-chain.md` 6.17), as data for the
//! teammate's benchmark helper: spike 6c's in-Wasm sweep (its proof and
//! statement mutants) and `format::MASKED_WRAP`'s masked fields tampered (spike 6a's
//! cases, `vos-pvm-recair`'s `every_masked_field_tampered_is_refused`), each
//! a patch of the `valid` fixture's proof or statement and the code its
//! judgement reaches at the fixture's venue state: `judge`'s on the
//! fixture's model input, and the mock's `submit` at G7's pre-state, the
//! two asserted equal.

use serde::Serialize;
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use vos_pvm_final_verifier::{WrapProof, masked};
use vos_statement::fixtures::Patch;
use vos_statement::model::Input;
use vos_statement::{Statement, code};

use parity_scale_codec::Encode;

use super::scenarios::{self, AUTHORITY_F, F};
use super::{Fixtures, hex};
use crate::kreivo::mock::types::{Call, Event, RuntimeCall};
use crate::kreivo::mock::{Chain, Origin, Verdict};

/// A statement's and a proof's code, by the model input's `judge` and by
/// the mock's `submit` at G7's pre-state, asserted equal.
struct Judge<'a> {
    input: &'a Input,
    chain: Chain,
}

impl Judge<'_> {
    fn code(&self, statement: &[u8], proof: &[u8]) -> u32 {
        let judged = match Statement::decode(statement) {
            Err(error) => vos_statement::Refusal::Statement(error).code(),
            Ok(decoded) => code(
                &Input {
                    statement: decoded,
                    ..self.input.clone()
                }
                .judge(proof),
            ),
        };
        let call = RuntimeCall::Spaces(Call::Submit {
            payer: F,
            statement: statement.to_vec(),
            proof: proof.to_vec(),
        });
        let mut chain = self.chain.clone();
        let outcome = chain.submit(Origin::Signed(AUTHORITY_F), &call.encode());
        assert_eq!(outcome.verdict, Verdict::Ok);
        let submitted = match outcome.events.first() {
            Some(Event::Refused { code, .. }) => *code,
            Some(Event::Accepted { .. }) => 0,
            events => panic!("{events:?}"),
        };
        assert_eq!(submitted, judged, "the pallet's path and judge's");
        judged
    }
}

#[derive(Debug, Serialize)]
pub struct Lists {
    pub about: Vec<String>,
    /// The case of the kit's `fixtures/statements.cases` the mutants are
    /// of: its venue state, statement and proof.
    pub base: String,
    pub proof: String,
    /// The proof file's length and BLAKE2b-256, so a helper reading another
    /// file fails at once.
    pub proof_length: usize,
    pub proof_blake2b_256: String,
    pub statement: String,
    pub proof_mutants: Vec<Mutant>,
    pub statement_mutants: Vec<Mutant>,
    pub masked_field_mutants: Vec<Mutant>,
    /// Masked-field tampers no fixed layout holds, so not bytes: their
    /// refusal is the layout's decode, which the proof mutants cover.
    pub masked_fields_without_bytes: Vec<String>,
}

/// A mutant: `removed` bytes at `offset` replaced by `inserted`, and its
/// verdict's code (never 0).
#[derive(Debug, Serialize)]
pub struct Mutant {
    pub name: String,
    pub offset: u32,
    pub removed: u32,
    pub inserted: String,
    pub code: u32,
}

fn mutant(name: String, from: &[u8], to: &[u8], code: u32) -> Mutant {
    assert_ne!(code, 0, "{name} accepted");
    let patch = Patch::between(from, to);
    assert_eq!(patch.apply(from), to);
    Mutant {
        name,
        offset: patch.offset,
        removed: patch.removed,
        inserted: hex(&patch.inserted),
        code,
    }
}

/// SplitMix64, the offsets' source.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Spike 6c's proof mutants: each of the first 64 bytes XOR 0xff; 48
/// pseudo-random bytes past them set to 0xff, 0x00, or XOR 0x01 (XOR 0x01
/// where the byte already holds the value); 7 truncations; 9 zero bytes
/// appended.
fn proof_mutants(judge: &Judge, proof: &[u8]) -> Vec<Mutant> {
    let statement = judge.input.statement.encode();
    let judged = |name: String, mutated: Vec<u8>| {
        let code = judge.code(&statement, &mutated);
        mutant(name, proof, &mutated, code)
    };
    let mut mutants = Vec::new();
    for at in 0..64 {
        let mut mutated = proof.to_vec();
        mutated[at] ^= 0xff;
        mutants.push(judged(format!("byte {at} XOR 0xff"), mutated));
    }
    let mut state = 0x6c;
    for n in 0..48 {
        let at = 64 + (splitmix(&mut state) % (proof.len() as u64 - 64)) as usize;
        let mut mutated = proof.to_vec();
        let (name, value) = match n % 3 {
            0 if proof[at] != 0xff => (format!("byte {at} set to 0xff"), 0xff),
            1 if proof[at] != 0x00 => (format!("byte {at} set to 0x00"), 0x00),
            _ => (format!("byte {at} XOR 0x01"), proof[at] ^ 0x01),
        };
        mutated[at] = value;
        mutants.push(judged(name, mutated));
    }
    for length in [0, 1, 7, 100, 1_000, 60_000, proof.len() - 1] {
        mutants.push(judged(
            format!("cut to {length} bytes"),
            proof[..length].to_vec(),
        ));
    }
    let mut longer = proof.to_vec();
    longer.extend_from_slice(&[0; 9]);
    mutants.push(judged("9 zero bytes appended".to_string(), longer));
    mutants
}

/// Spike 6c's statement mutants, against the valid proof: each byte XOR
/// 0x5a; 5 truncations; `public_args`' compact length claiming 2^30 bytes.
fn statement_mutants(judge: &Judge, proof: &[u8]) -> Vec<Mutant> {
    let input = judge.input;
    let statement = input.statement.encode();
    let judged = |name: String, mutated: Vec<u8>| {
        let code = judge.code(&mutated, proof);
        mutant(name, &statement, &mutated, code)
    };
    let mut mutants = Vec::new();
    for at in 0..statement.len() {
        let mut mutated = statement.clone();
        mutated[at] ^= 0x5a;
        mutants.push(judged(format!("byte {at} XOR 0x5a"), mutated));
    }
    for length in [0, 1, 36, statement.len() / 2, statement.len() - 1] {
        mutants.push(judged(
            format!("cut to {length} bytes"),
            statement[..length].to_vec(),
        ));
    }
    // The format (4), the program (32), the space (32), then `public_args`'
    // one-byte compact length.
    let at = 4 + 32 + 32;
    assert_eq!(
        statement[at],
        (input.statement.public_args.len() as u8) << 2
    );
    let claim = [
        &statement[..at],
        &[0x03, 0, 0, 0, 0x40],
        &statement[at + 1..],
    ]
    .concat();
    mutants.push(judged(
        "public_args' length claiming 2^30 bytes".to_string(),
        claim,
    ));
    mutants
}

fn bump(value: &mut BaseField) {
    *value = BaseField::from((value.0 + 1) % P);
}

/// `format::MASKED_WRAP`'s masked fields tampered, each re-encoded in the fixed
/// layout: those it holds as mutants, the others by name.
fn masked_field_mutants(judge: &Judge, proof: &[u8]) -> (Vec<Mutant>, Vec<String>) {
    let statement = judge.input.statement.encode();
    let decoded = masked::decode(proof).expect("the fixture decodes");
    let one = SecureField::from(BaseField::from(1u32));
    type Tamper = Box<dyn Fn(&mut WrapProof)>;
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "an OODS sample of a masked main column",
            Box::new(move |p| p.stark_proof.0.sampled_values[1][0][0] += one),
        ),
        (
            "an OODS sample of a masked interaction column",
            Box::new(move |p| p.stark_proof.0.sampled_values[2][0][0] += one),
        ),
        (
            "a queried main value",
            Box::new(|p| bump(&mut p.stark_proof.0.queried_values[1][0][0])),
        ),
        (
            "a queried salt (main)",
            Box::new(|p| {
                let tree = &mut p.stark_proof.0.queried_values[1];
                let last = tree.len() - 1;
                bump(&mut tree[last][0])
            }),
        ),
        (
            "a queried salt (composition)",
            Box::new(|p| {
                let tree = &mut p.stark_proof.0.queried_values[3];
                let last = tree.len() - 1;
                bump(&mut tree[last][0])
            }),
        ),
        (
            "the FRI mask's sample",
            Box::new(move |p| p.stark_proof.0.sampled_values[3][4][0] += one),
        ),
        (
            "a composition sample",
            Box::new(move |p| p.stark_proof.0.sampled_values[3][0][0] += one),
        ),
        (
            "a blinded claimed sum",
            Box::new(move |p| p.claimed_sums[0] += one),
        ),
        (
            "two blinded claimed sums, their total kept",
            Box::new(move |p| {
                p.claimed_sums[0] += one;
                p.claimed_sums[1] -= one;
            }),
        ),
        (
            "a salt column dropped from the main tree",
            Box::new(|p| {
                p.stark_proof.0.queried_values[1].pop();
            }),
        ),
        (
            "a sample dropped",
            Box::new(|p| {
                p.stark_proof.0.sampled_values[1][0].pop();
            }),
        ),
        (
            "the FRI mask's samples dropped",
            Box::new(|p| p.stark_proof.0.sampled_values[3][4].clear()),
        ),
        ("the interaction PoW", Box::new(|p| p.interaction_pow ^= 1)),
        ("the format number", Box::new(|p| p.format_version = 28)),
    ];
    let mut mutants = Vec::new();
    let mut without = Vec::new();
    for (name, tamper) in cases {
        let mut tampered = decoded.clone();
        tamper(&mut tampered);
        match masked::encode(&tampered) {
            Some(bytes) => {
                let code = judge.code(&statement, &bytes);
                assert_eq!(code >> 8, 1, "{name}: refused by its proof");
                mutants.push(mutant(name.to_string(), proof, &bytes, code));
            }
            None => without.push(name.to_string()),
        }
    }
    (mutants, without)
}

pub fn lists(fx: &Fixtures) -> Lists {
    let input = &fx.valid;
    let proof = &fx.proof;
    let judge = Judge {
        input,
        chain: scenarios::g7_chain(fx),
    };
    assert_eq!(
        judge.code(&input.statement.encode(), proof),
        0,
        "the base is accepted"
    );
    let proof_mutants = proof_mutants(&judge, proof);
    let statement_mutants = statement_mutants(&judge, proof);
    assert_eq!((proof_mutants.len(), statement_mutants.len()), (120, 284));
    let (masked_field_mutants, masked_fields_without_bytes) = masked_field_mutants(&judge, proof);
    Lists {
        about: ABOUT.iter().map(|line| line.to_string()).collect(),
        base: "valid".to_string(),
        proof: "wrap.proof".to_string(),
        proof_length: proof.len(),
        proof_blake2b_256: hex(&vos_statement::blake2b_256(&[proof])),
        statement: hex(&input.statement.encode()),
        proof_mutants,
        statement_mutants,
        masked_field_mutants,
        masked_fields_without_bytes,
    }
}

const ABOUT: &[&str] = &[
    "VOS's mutation lists for Kreivo's spaces pallet (docs/design/spaces-pallet.md §10, the in-Wasm sweep of spike 6c), generated in VOS (`just conformance`); the teammate's `#[benchmark(extra)]` runs them through submit inside the runtime, every one refused, none trapping.",
    "Each mutant patches the `valid` case of the kit's fixtures/statements.cases: proof_mutants and masked_field_mutants its proof (fixtures/wrap.proof), statement_mutants its statement (`statement`, hex), against the valid proof. A patch replaces `removed` bytes at `offset` with `inserted` (hex).",
    "code is the verdict at that case's venue state (its accepted formats, pinned program, registered space and anchored roots: in the pallet, Formats, Programs, Spaces and Anchors as G7's pre-state holds them), checked in VOS both by judge on that case and by the mock's submit at G7's pre-state: 1 a statement that does not decode, 2–7 the venue's checks, 0x100 | e the final verifier's error e.",
];
