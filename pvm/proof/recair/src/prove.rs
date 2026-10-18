//! Native proving and verifying of a circuit on the Poseidon2-M31 channel,
//! under format 32 (`vos_pvm_proof::format::LEAF_FOLD`), the recursion AIR's
//! format for leaves and folds, at its exact parameters; and proving under
//! any format of the recursion AIR on its channel ([`prove_on`]), the wrap's
//! (28) on Blake2b-256, which `vos-final-verifier` verifies.
//!
//! **The transcript**, as the prover runs it and the verifier replays it:
//! 1. the proof's domain, the format and the PCS configuration, then the
//!    components' log sizes (`vos_pvm_proof::proof::mix_statement_header`);
//! 2. the preprocessed root, then the main trace's root;
//! 3. the outputs' values, in their addresses' order, which the public logup
//!    terms read, before any challenge is drawn;
//! 4. the interaction PoW nonce;
//! 5. the `Gate` relation's challenges;
//! 6. the three claimed sums, then the interaction root; then Stwo's
//!    protocol.
//!
//! The verifier pins the circuit by its hash
//! ([`vos_recair_air::circuit_hash`]), which binds the preprocessed root, the
//! log sizes and the format's parameters.

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, ComponentProver, ProvingError};
use vos_pvm_poseidon2::{Digest, M31};
use vos_pvm_proof::format::{ChannelKind, Format, LEAF_FOLD, ProofKind};
use vos_pvm_proof::pcs::ProofHash;
use vos_pvm_proof::poseidon2::{P2Hash, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel};
use vos_pvm_proof::proof::{
    MAX_FRI_QUERIES, MAX_MERKLE_WITNESS_HASHES, MAX_PROOF_LOG_SIZE, MIN_PROOF_LOG_SIZE,
    PROOF_COMMITMENT_TREE_COUNT, check_format_security, check_interaction_pow,
    mix_statement_header,
};
use vos_recair_air::gate::{GATE_WIDTH, Layout, public_logup_sum};
use vos_recair_air::{
    Components, GateRelation, LOG_CONSTRAINT_EXPANSION, LogSizes, preprocessed_log_sizes,
};

use crate::circuit::{Circuit, WiringError};
use crate::context::Witness;
use crate::trace::{self, Evaluations, MainTrace};

/// The format a recursion AIR proof carries.
pub const FORMAT: &Format = &LEAF_FOLD;

/// A proof of a circuit's witness, on the Poseidon2-M31 trees unless said.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecairProof<H: MerkleHasherLifted = P2MerkleHasher> {
    pub format_version: u32,
    /// `p2`, `qm31`, `h8`.
    pub log_sizes: LogSizes,
    /// The outputs' values, in their addresses' order: a node's from 3.
    pub outputs: Vec<SecureField>,
    pub interaction_pow: u64,
    pub claimed_sums: [SecureField; 3],
    pub stark_proof: StarkProof<H>,
}

/// Why a proof is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError(pub String);

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VerifyError {}

impl From<String> for VerifyError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

/// Why a circuit is not proved.
#[derive(Clone, Debug)]
pub enum ProveError {
    /// The circuit's wiring fails the static check.
    Wiring(WiringError),
    /// Stwo refused, as it does a witness that breaks a constraint.
    Stwo(ProvingError),
}

impl core::fmt::Display for ProveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wiring(error) => write!(f, "the wiring: {error}"),
            Self::Stwo(error) => write!(f, "Stwo proving: {error}"),
        }
    }
}

impl std::error::Error for ProveError {}

/// The format's parameters as the circuit hash takes them.
pub(crate) fn hashed_params(format: &Format) -> [u32; 6] {
    let params = format.params;
    [
        params.log_blowup,
        params.n_queries as u32,
        params.pow_bits,
        params.fold_step,
        params.log_last_layer,
        params.interaction_pow_bits,
    ]
}

fn digest_of_root(root: &P2Hash) -> Digest {
    root.0.map(|limb| M31::from(limb.0))
}

/// The hash of a circuit whose preprocessed tree has `root`, at `log_sizes`.
pub fn circuit_hash_of(log_sizes: &LogSizes, root: &P2Hash) -> Digest {
    vos_recair_air::circuit_hash(
        FORMAT.number,
        hashed_params(FORMAT),
        log_sizes,
        &digest_of_root(root),
    )
}

fn twiddle_log_size(log_sizes: &LogSizes, config: &PcsConfig) -> u32 {
    log_sizes.iter().max().copied().unwrap_or(0)
        + LOG_CONSTRAINT_EXPANSION
        + config.fri_config.log_blowup_factor
}

/// The preprocessed tree's root, and the circuit's hash, of a circuit whose
/// wiring checks.
pub fn circuit_commitment(circuit: &Circuit) -> Result<(P2Hash, Digest), WiringError> {
    let root = preprocessed_root_on::<P2MerkleChannel>(FORMAT, circuit)?;
    Ok((root, circuit_hash_of(&circuit.log_sizes(), &root)))
}

/// The preprocessed tree's root of a circuit whose wiring checks, committed
/// on `MC`'s trees under `format`'s blowup.
pub fn preprocessed_root_on<MC: MerkleChannel>(
    format: &Format,
    circuit: &Circuit,
) -> Result<<MC::H as MerkleHasherLifted>::Hash, WiringError>
where
    SimdBackend: BackendForChannel<MC>,
{
    circuit.check_wiring()?;
    let log_sizes = circuit.log_sizes();
    let config = format.pcs_config();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(twiddle_log_size(&log_sizes, &config))
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    let mut builder = scheme.tree_builder();
    builder.extend_evals(preprocessed_evaluations(circuit));
    builder.commit(&mut MC::C::default());
    Ok(scheme.roots()[0])
}

fn preprocessed_evaluations(circuit: &Circuit) -> Evaluations {
    let log_sizes = circuit.log_sizes();
    trace::preprocessed_columns(circuit)
        .iter()
        .zip(log_sizes)
        .flat_map(|(columns, log_size)| trace::evaluations(columns, log_size))
        .collect()
}

/// Proves `witness` over `circuit`, whose wiring must check.
pub fn prove(circuit: &Circuit, witness: &Witness<SecureField>) -> Result<RecairProof, ProveError> {
    prove_with(circuit, witness, |_| {})
}

/// [`prove`], with the main trace passed through `tamper` before it is
/// committed: a seam for the refusal tests.
pub fn prove_with(
    circuit: &Circuit,
    witness: &Witness<SecureField>,
    tamper: impl FnOnce(&mut MainTrace),
) -> Result<RecairProof, ProveError> {
    prove_on::<P2MerkleChannel>(FORMAT, circuit, witness, tamper)
}

/// Proves `witness` over `circuit` under `format`, a format of the
/// recursion AIR, on `MC`, its channel; the main trace passed through
/// `tamper` before it is committed.
pub fn prove_on<MC: MerkleChannel>(
    format: &Format,
    circuit: &Circuit,
    witness: &Witness<SecureField>,
    tamper: impl FnOnce(&mut MainTrace),
) -> Result<RecairProof<MC::H>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    circuit.check_wiring().map_err(ProveError::Wiring)?;
    let log_sizes = circuit.log_sizes();
    let config = format.pcs_config();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(twiddle_log_size(&log_sizes, &config))
            .circle_domain()
            .half_coset,
    );
    let channel = &mut MC::C::default();
    mix_statement_header(channel, format.number, &config, &log_sizes);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut builder = scheme.tree_builder();
    builder.extend_evals(preprocessed_evaluations(circuit));
    builder.commit(channel);

    let mut main = trace::main_trace(circuit, witness);
    tamper(&mut main);
    let mut builder = scheme.tree_builder();
    for (columns, &log_size) in main.columns.iter().zip(&log_sizes) {
        builder.extend_evals(trace::evaluations(columns, log_size));
    }
    builder.commit(channel);

    let outputs: Vec<SecureField> = witness.outputs.clone();
    channel.mix_felts(&outputs);
    let interaction_pow = <SimdBackend as stwo::core::proof_of_work::GrindOps<MC::C>>::grind(
        channel,
        format.interaction_pow_bits(),
    );
    channel.mix_u64(interaction_pow);
    let relation = GateRelation::draw(channel);

    let interaction = main.interaction(circuit, &relation);
    let claimed_sums = [0, 1, 2].map(|i| interaction[i].1);
    let mut builder = scheme.tree_builder();
    for (evaluations, _) in interaction {
        builder.extend_evals(evaluations);
    }
    channel.mix_felts(&claimed_sums);
    builder.commit(channel);

    let components = Components::new(&relation, &log_sizes, &claimed_sums);
    let provers: [&dyn ComponentProver<SimdBackend>; 3] =
        [&components.p2, &components.qm31, &components.h8];
    let stark_proof = stwo::prover::prove::<SimdBackend, MC>(&provers, channel, scheme)
        .map_err(ProveError::Stwo)?;
    Ok(RecairProof {
        format_version: format.number,
        log_sizes,
        outputs,
        interaction_pow,
        claimed_sums,
        stark_proof,
    })
}

/// Each tree's column log sizes, the preprocessed tree's in its commitment
/// order.
pub(crate) fn committed_log_sizes(
    components: &Components,
    log_sizes: &LogSizes,
) -> TreeVec<Vec<u32>> {
    let mut sizes = TreeVec::concat_cols(
        components
            .as_dyn()
            .into_iter()
            .map(|component| component.trace_log_degree_bounds()),
    );
    sizes[0] = preprocessed_log_sizes(log_sizes);
    sizes
}

/// The bounds a proof's vectors must meet before any is indexed.
fn preflight(proof: &RecairProof, format: &Format) -> Result<(), VerifyError> {
    let stark = &proof.stark_proof;
    if proof.format_version != format.number
        || format.kind != ProofKind::LeafFold
        || format.channel != ChannelKind::Poseidon2M31
    {
        return Err(VerifyError(format!(
            "proof format {} is not the recursion AIR's",
            proof.format_version
        )));
    }
    if format.verifier_config(&stark.config) != format.pcs_config() {
        return Err(VerifyError(format!(
            "proof parameters differ from format {}'s",
            format.number
        )));
    }
    if let Some(log_size) = proof
        .log_sizes
        .iter()
        .find(|&&log_size| !(MIN_PROOF_LOG_SIZE..=MAX_PROOF_LOG_SIZE).contains(&log_size))
    {
        return Err(VerifyError(format!(
            "component log size {log_size} is outside {MIN_PROOF_LOG_SIZE}..={MAX_PROOF_LOG_SIZE}"
        )));
    }
    if proof.outputs.len() > (1usize << MAX_PROOF_LOG_SIZE) {
        return Err(VerifyError("too many outputs".into()));
    }
    if [
        stark.commitments.len(),
        stark.sampled_values.len(),
        stark.decommitments.len(),
        stark.queried_values.len(),
    ] != [PROOF_COMMITMENT_TREE_COUNT; 4]
    {
        return Err(VerifyError(format!(
            "a Stwo proof has exactly {PROOF_COMMITMENT_TREE_COUNT} trees"
        )));
    }
    if stark
        .decommitments
        .iter()
        .any(|decommitment| decommitment.hash_witness.len() > MAX_MERKLE_WITNESS_HASHES)
    {
        return Err(VerifyError(
            "a trace Merkle witness exceeds its bound".into(),
        ));
    }
    let fri = &stark.fri_proof;
    let bounded = |layer: &stwo::core::fri::FriLayerProof<P2MerkleHasher>| {
        layer.fri_witness.len() <= MAX_FRI_QUERIES
            && layer.decommitment.hash_witness.len() <= MAX_MERKLE_WITNESS_HASHES
    };
    if !bounded(&fri.first_layer) || !fri.inner_layers.iter().all(bounded) {
        return Err(VerifyError(
            "a FRI layer's witness exceeds its bound".into(),
        ));
    }
    if fri.last_layer_poly.iter().count() != 1usize << format.params.log_last_layer {
        return Err(VerifyError(
            "the FRI last layer has the wrong length".into(),
        ));
    }
    let canonical = |value: &SecureField| {
        value
            .to_m31_array()
            .iter()
            .all(|limb| limb.0 < stwo::core::fields::m31::P)
    };
    if !proof
        .outputs
        .iter()
        .chain(&proof.claimed_sums)
        .all(canonical)
        || !vos_pvm_proof::proof::stark_fields_are_canonical(stark, ProofHash::is_canonical)
    {
        return Err(VerifyError("the proof has a noncanonical M31 limb".into()));
    }
    Ok(())
}

/// Verifies `proof` against the circuit whose hash is `circuit_hash`.
pub fn verify(proof: RecairProof, circuit_hash: &Digest) -> Result<(), VerifyError> {
    let format = FORMAT;
    preflight(&proof, format)?;
    let stark = &proof.stark_proof;
    let log_sizes = proof.log_sizes;
    if circuit_hash_of(&log_sizes, &stark.commitments[0]) != *circuit_hash {
        return Err(VerifyError("the proof is of another circuit".into()));
    }

    // The layout and the security count do not depend on the challenges.
    let config = format.pcs_config();
    let layout = Components::new(&GateRelation::dummy(), &log_sizes, &proof.claimed_sums);
    let trace_log_sizes = committed_log_sizes(&layout, &log_sizes);
    let (protocol, mut shape) = vos_pvm_proof::framework_access::preflight_component_dimensions(
        &config,
        stark,
        &layout.as_dyn(),
        &trace_log_sizes,
    )?;
    shape.relation_width = GATE_WIDTH as u64;
    check_format_security(format, &config, &shape)?;

    let channel = &mut Poseidon2M31Channel::default();
    mix_statement_header(channel, format.number, &config, &log_sizes);
    let scheme = &mut CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    scheme.commit(stark.commitments[0], &trace_log_sizes[0], channel);
    scheme.commit(stark.commitments[1], &trace_log_sizes[1], channel);
    channel.mix_felts(&proof.outputs);
    check_interaction_pow(channel, format, proof.interaction_pow)?;
    let relation = GateRelation::draw(channel);
    channel.mix_felts(&proof.claimed_sums);
    scheme.commit(stark.commitments[2], &trace_log_sizes[2], channel);

    let layout = Layout::node(proof.outputs.len() as u32);
    let total = proof.claimed_sums.iter().copied().sum::<SecureField>()
        + public_logup_sum(
            &relation,
            layout.public_terms(proof.outputs.iter().copied()),
        );
    if !total.is_zero() {
        return Err(VerifyError(
            "the claimed sums and the public terms do not add to zero".into(),
        ));
    }

    let queries = vos_pvm_proof::proof::expected_fiat_shamir_query_count::<P2MerkleChannel>(
        channel,
        stark,
        &config,
        protocol,
        &[
            trace_log_sizes[0].clone(),
            trace_log_sizes[1].clone(),
            trace_log_sizes[2].clone(),
            vec![protocol.max_log_degree_bound; 8],
        ],
    )?;
    if queries != protocol.query_count {
        return Err(VerifyError(
            "queried-value rows differ from the Fiat-Shamir query positions".into(),
        ));
    }

    let components = Components::new(&relation, &log_sizes, &proof.claimed_sums);
    stwo::core::verifier::verify(&components.as_dyn(), channel, scheme, proof.stark_proof)
        .map_err(|error| VerifyError(format!("Stwo verification: {error}")))
}
