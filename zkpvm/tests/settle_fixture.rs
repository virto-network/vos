//! Generates the settlement-verifier proof fixture and de-risks the wire format
//! on host before the PVM run.
//!
//! Produces a `StarkProof<P2MerkleHasher>` of a TRIVIAL boolean AIR
//! (`x·(x−1)=0`) committed under the recursion Poseidon2-M31 stack, postcard-
//! serializes it to `settlement-verifier/fixtures/bool_proof.postcard`, and
//! round-trips it (deserialize → verify) on host. The settlement bin
//! (`settlement-verifier/src/bin/settle.rs`) `include_bytes!`es the same fixture
//! and runs the SAME verify on JAM PVM, so this test pins both the wire format
//! and the verify-driver shape the PVM side must reproduce.
//!
//! A trivial AIR is deliberate: the FRI-verify + Poseidon2 Merkle-decommit +
//! OODS machinery (what dominates the on-chain verify cost) is independent of
//! constraint count, so this yields a representative settlement-verify proof
//! without the full 31-chip segment AIR.

use num_traits::One;
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};
// The production Poseidon2-M31 stack (these carry serde, unlike the
// test-support `recursion_common` mirror). The settlement bin uses the
// structurally-identical promoted copies in `settlement-verifier`.
use zkpvm::poseidon2::{P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel};

/// MOBILE PCS config — MUST match `settlement-verifier`'s `mobile_config()`
/// (blowup 2, 38 queries, 20-bit PoW), or the verifier replays a different
/// transcript and rejects the proof.
fn mobile_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 2, 38, 1),
        lifting_log_size: None,
    }
}

/// Trace log-size of the fixture proof. Small, but `>` the FRI blowup so the
/// real query/decommit path runs.
pub const FIXTURE_LOG: u32 = 5;

/// The trivial settlement AIR: one main column constrained boolean.
struct BoolEval;
impl FrameworkEval for BoolEval {
    fn log_size(&self) -> u32 {
        FIXTURE_LOG
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        FIXTURE_LOG + 1 // degree 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let x = eval.next_trace_mask();
        eval.add_constraint(x.clone() * (x - E::F::one()));
        eval
    }
}

fn build_component() -> FrameworkComponent<BoolEval> {
    FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        BoolEval,
        SecureField::default(),
    )
}

fn prove_bool() -> StarkProof<P2MerkleHasher> {
    let config = mobile_config();
    let n = 1usize << FIXTURE_LOG;
    // All-zero boolean column (0 satisfies x·(x−1)=0); a valid low-degree trace.
    let col = Col::<CpuBackend, BaseField>::zeros(n);
    let trace = vec![CircleEvaluation::new(
        CanonicCoset::new(FIXTURE_LOG).circle_domain(),
        col,
    )];

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(FIXTURE_LOG + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    // tree 0: preprocessed (empty); tree 1: main. No logup ⇒ no interaction tree.
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace);
    tb.commit(channel);

    let component = build_component();
    prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs).expect("prove bool AIR")
}

/// The driver the PVM `settle` bin mirrors: rebuild the component from
/// constants, replay the 2-tree commitment transcript, verify.
fn verify_bool(proof: StarkProof<P2MerkleHasher>) -> Result<(), String> {
    let config = mobile_config();
    let component = build_component();
    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof).map_err(|e| format!("{e:?}"))
}

#[test]
fn generate_and_roundtrip_fixture() {
    let proof = prove_bool();

    // Sanity: the freshly-produced proof verifies.
    verify_bool(proof.clone()).expect("honest proof must verify");

    // Wire format: postcard round-trip must preserve verifiability.
    let bytes = postcard::to_allocvec(&proof).expect("postcard serialize");
    let proof2: StarkProof<P2MerkleHasher> =
        postcard::from_bytes(&bytes).expect("postcard deserialize");
    verify_bool(proof2).expect("postcard round-tripped proof must verify");

    // A tampered byte must break verification (rejection path the PVM run checks).
    let mut tampered = bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    let tamper_rejected = match postcard::from_bytes::<StarkProof<P2MerkleHasher>>(&tampered) {
        Ok(p) => verify_bool(p).is_err(),
        Err(_) => true, // decode failure is also a rejection
    };
    assert!(tamper_rejected, "a tampered proof must NOT verify");

    // Emit the fixture the settlement bin embeds.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/settlement-verifier/fixtures");
    std::fs::create_dir_all(dir).expect("create fixtures dir");
    let path = format!("{dir}/bool_proof.postcard");
    std::fs::write(&path, &bytes).expect("write fixture");

    eprintln!(
        "fixture: bool AIR log={FIXTURE_LOG}, {} commitments, postcard {} bytes → {path}",
        proof.commitments.len(),
        bytes.len()
    );
}
