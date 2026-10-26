//! The credential prover (`docs/design/proving.md` §8): a statement's
//! circuit ([`mod@circuit`]) proved masked over the credential AIR's set, the
//! recursion AIR's `p2` and `qm31` (`vos_pvm_recair_air::masked::
//! CredentialComponents`), under format 42 on the Blake2s-M31 channel
//! ([`prove`]); the final verifier's [`vos_pvm_final_verifier::credential`]
//! verifies it.
//!
//! - **The program** of a kind is its circuit, built from no witness
//!   ([`circuit()`]), and its preprocessed root under the format
//!   ([`preprocessed_root`]); the final verifier pins both kinds' roots and
//!   program ids, which the tests compute here.
//! - **The witness is checked first:** a statement its witness does not
//!   satisfy (a path to another root, a nullifier or an owner digest of
//!   another secret) is refused before any proving ([`ProveError::Witness`],
//!   naming the piece).
//! - **The shape is the program's:** every component at [`circuit::ROWS`],
//!   the masking's floor, whatever the statement; the auth circuit's rows
//!   do not depend on the slot.

pub mod circuit;

use stwo::core::channel::MerkleChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, ComponentProver};
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::credential::CredentialProof;
use vos_pvm_final_verifier::masked::{Claim, verify_masked};
use vos_pvm_proof::format::{CREDENTIAL_PROOF, Format};
use vos_pvm_recair_air::GateRelation;
use vos_pvm_recair_air::credential::{self as statements, CredentialKind};
use vos_pvm_recair_air::masked::CredentialComponents;

pub use circuit::{AuthPublic, AuthWitness, Forge, OwnerPublic, ROWS, Statement, Tags, Words};

use crate::circuit::Circuit;
use crate::context::{Finalized, Witness};
use crate::masked::{self, Checks, MaskRng, MaskStats, MaskedProof, MaskedProvers, MaskedTrace};
use crate::prove::ProveError;
use crate::trace::{self, Evaluations, FirstRowFraction, MainTrace};
use crate::value::NoValue;

impl MaskedProvers for CredentialComponents {
    fn provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        vec![&self.p2, &self.qm31]
    }
}

/// The components' log sizes, `p2` and `qm31`.
pub const LOG_SIZES: [u32; 2] = vos_pvm_final_verifier::credential::LOG_SIZES;

const _: () = assert!(ROWS[0] == 1 << LOG_SIZES[0] && ROWS[1] == 1 << LOG_SIZES[1]);

/// The circuit of `kind`'s statement (`None`, membership and payment), its
/// wiring alone.
pub fn circuit(kind: Option<CredentialKind>) -> Circuit {
    circuit::finalize::<NoValue>(&circuit::blank(kind), &Forge::NONE)
        .expect("a credential circuit's wiring checks")
        .0
        .circuit
}

/// `statement`'s circuit and its witness's values, refused when a word of
/// it is at or above `p`, or the witness does not satisfy it, by the piece
/// that refuses it.
pub fn witness(statement: &Statement) -> Result<Finalized<SecureField>, ProveError> {
    if !statement.is_canonical() {
        return Err(ProveError::Witness("a word at or above p"));
    }
    let (finalized, mismatches) =
        circuit::finalize::<SecureField>(statement, &Forge::NONE).map_err(ProveError::Wiring)?;
    match mismatches.first() {
        Some(mismatch) => Err(ProveError::Witness(mismatch.piece)),
        None => Ok(finalized),
    }
}

/// `statement` built as `forge` builds it, whatever its witness leaves
/// unsatisfied: a forger's circuit and witness, which the gates prove
/// against their own circuit or the pinned one. Only the prover's tests have
/// it (`seeded-masks`).
#[cfg(feature = "seeded-masks")]
pub fn forge(
    statement: &Statement,
    forge: &Forge,
) -> (Finalized<SecureField>, Vec<crate::context::Mismatch>) {
    circuit::finalize::<SecureField>(statement, forge).expect("the forged wiring checks")
}

/// The preprocessed columns of a credential circuit, in commitment order.
fn preprocessed(circuit: &Circuit) -> Evaluations {
    let [p2, qm31, _] = trace::preprocessed_columns(circuit);
    let [p2_log, qm31_log] = circuit.log_sizes_without_h8();
    trace::evaluations(&p2, p2_log)
        .into_iter()
        .chain(trace::evaluations(&qm31, qm31_log))
        .collect()
}

/// `circuit`'s preprocessed root as the masked `format` commits it on
/// `MC`'s trees: its columns extended one level, under the format's blowup.
pub fn preprocessed_root<MC: MerkleChannel>(
    format: &Format,
    circuit: &Circuit,
) -> Result<<MC::H as MerkleHasherLifted>::Hash, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    circuit
        .check_wiring_without_h8()
        .map_err(ProveError::Wiring)?;
    let lifting = masked::lifting_log_size(format, &circuit.log_sizes_without_h8())
        .ok_or(ProveError::TraceShape("a component's log size overflows"))?;
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(lifting).circle_domain().half_coset);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(format.pcs_config(), &twiddles);
    let mut builder = scheme.tree_builder();
    builder.extend_polys(masked::extend_preprocessed(
        preprocessed(circuit),
        &twiddles,
    ));
    builder.commit(&mut MC::C::default());
    Ok(scheme.roots()[0])
}

/// The program id of `kind`'s circuit under format 42: its circuit hash
/// (`vos_pvm_recair_air::credential::program_id`).
pub fn program_id(kind: CredentialKind) -> [u8; 32] {
    let root =
        preprocessed_root::<Blake2sM31MerkleChannel>(&CREDENTIAL_PROOF, &circuit(Some(kind)))
            .expect("a credential circuit's wiring checks");
    statements::program_id(
        CREDENTIAL_PROOF.number,
        vos_pvm_final_verifier::credential::PARAMS,
        &LOG_SIZES,
        &root.0,
    )
    .expect("a Blake2s-M31 root's words are below p")
}

/// Proves `statement` under format 42 on the Blake2s-M31 channel, its masks
/// from `rng`; the witness checked first.
pub fn prove(
    statement: &Statement,
    rng: MaskRng,
) -> Result<(CredentialProof, MaskStats), ProveError> {
    let finalized = witness(statement)?;
    let (proof, stats) = prove_on::<Blake2sM31MerkleChannel>(
        &CREDENTIAL_PROOF,
        &finalized.circuit,
        &finalized.witness,
        rng,
    )?;
    let claimed_sums = proof
        .claimed_sums
        .try_into()
        .map_err(|_| ProveError::TraceShape("one claimed sum per component expected"))?;
    Ok((
        CredentialProof {
            format_version: CREDENTIAL_PROOF.number,
            interaction_pow: proof.interaction_pow,
            claimed_sums,
            stark_proof: proof.stark_proof,
        },
        stats,
    ))
}

/// Proves `witness` over the credential `circuit` masked under `format` on
/// `MC`, its public values the outputs'.
pub fn prove_on<MC: MerkleChannel>(
    format: &Format,
    circuit: &Circuit,
    witness: &Witness<SecureField>,
    rng: MaskRng,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_with::<MC>(format, circuit, witness, rng, |_| {}, Checks::ALL)
}

/// [`prove_on`], the main trace through `tamper` before it is masked, the
/// prover held to `checks`: the forgery gates' forced proofs. Only the
/// prover's tests have it (`seeded-masks`).
#[cfg(feature = "seeded-masks")]
pub fn prove_forced<MC: MerkleChannel>(
    format: &Format,
    circuit: &Circuit,
    witness: &Witness<SecureField>,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MainTrace),
    checks: Checks,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_with::<MC>(format, circuit, witness, rng, tamper, checks)
}

fn prove_with<MC: MerkleChannel>(
    format: &Format,
    circuit: &Circuit,
    witness: &Witness<SecureField>,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MainTrace),
    checks: Checks,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    circuit
        .check_wiring_without_h8()
        .map_err(ProveError::Wiring)?;
    let log_sizes = circuit.log_sizes_without_h8();
    let mut main = trace::main_trace(circuit, witness);
    tamper(&mut main);
    let main_columns: Vec<Evaluations> = main.columns[..2]
        .iter()
        .zip(log_sizes)
        .map(|(columns, log_size)| trace::evaluations(columns, log_size))
        .collect();
    let interaction = |relation: &GateRelation, blinding: &[FirstRowFraction]| {
        let extra = [0, 1].map(|component| blinding.get(component).copied());
        main.interaction_without_h8(circuit, relation, extra).into()
    };
    masked::prove_masked_checked::<MC, CredentialComponents>(
        format,
        MaskedTrace {
            active: (),
            log_sizes: &log_sizes,
            preprocessed: preprocessed(circuit),
            main: &|component: usize| {
                main_columns[component]
                    .iter()
                    .map(|column| &column.values)
                    .collect()
            },
            public: &witness.outputs,
            interaction: &interaction,
        },
        rng,
        checks,
    )
}

/// Verifies `proof` of the credential circuit whose preprocessed root is
/// `root`, masked under `format` on `MC`, against its public `words`: the
/// final verifier's masked verifier over the credential set, as format 42's
/// verifier runs it on any channel and format.
pub fn verify_on<MC: MerkleChannel>(
    format: &Format,
    root: <MC::H as MerkleHasherLifted>::Hash,
    words: &[u32],
    proof: &MaskedProof<MC::H>,
) -> Result<(), Error> {
    let public = statements::public_values(words).ok_or(Error::PublicWords)?;
    let public_sum = |relation: &GateRelation| statements::public_sum(relation, &public);
    let layout = CredentialComponents::layout(&LOG_SIZES);
    let pinned = masked::verifier_format(format, &LOG_SIZES, &layout).ok_or(Error::Format)?;
    verify_masked::<MC, CredentialComponents>(
        &pinned,
        &Claim {
            log_sizes: &LOG_SIZES,
            circuit: Some(root),
            public: &public,
            public_sum: Some(&public_sum),
            bound_sums: None,
            interaction_pow: proof.interaction_pow,
            claimed_sums: &proof.claimed_sums,
        },
        &layout,
        proof.stark_proof.clone(),
    )
}
