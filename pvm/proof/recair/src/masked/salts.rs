//! A salted tree: its polynomials extended under the blowup, then uniform
//! salt columns at the lifting height, never sampled, so a decommitted leaf
//! hides its columns' values behind 248 random bits.

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;
use stwo::core::channel::MerkleChannel;
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{N_LANES, PackedBaseField};
use stwo::prover::poly::circle::{CircleCoefficients, CircleEvaluation, PolyOps};
use stwo::prover::vcs_lifted::prover::MerkleProverLifted;
use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver, Poly};

/// Words a parallel chunk of a uniform column fills from its own stream.
const CHUNK_WORDS: usize = 1 << 16;

/// `2^log_size` uniform M31 values, written straight into packed SIMD
/// lanes: chunk `i` from `seed`'s ChaCha20 stream `i`, 31 bits a word, the
/// value `p` drawn again.
pub(crate) fn uniform_column(seed: [u8; 32], log_size: u32) -> BaseColumn {
    let length = 1usize << log_size;
    let mut data =
        vec![<PackedBaseField as bytemuck::Zeroable>::zeroed(); length.div_ceil(N_LANES)];
    let words: &mut [u32] = bytemuck::cast_slice_mut(&mut data);
    words
        .par_chunks_mut(CHUNK_WORDS)
        .enumerate()
        .for_each(|(stream, chunk)| {
            let mut rng = ChaCha20Rng::from_seed(seed);
            rng.set_stream(stream as u64);
            rng.fill(chunk);
            for word in chunk {
                *word &= P;
                while *word == P {
                    *word = rng.next_u32() & P;
                }
            }
        });
    BaseColumn { data, length }
}

/// A uniform polynomial of `2^log_size` coefficients.
pub(crate) fn uniform_poly(seed: [u8; 32], log_size: u32) -> CircleCoefficients<SimdBackend> {
    CircleCoefficients::new(uniform_column(seed, log_size))
}

/// Commits `polys` and `salt_columns` uniform columns at `lifting_log_size`
/// as one tree, its root mixed into `channel`.
pub(crate) fn commit_salted<MC: MerkleChannel>(
    scheme: &mut CommitmentSchemeProver<'_, SimdBackend, MC>,
    polys: Vec<CircleCoefficients<SimdBackend>>,
    lifting_log_size: u32,
    salt_columns: usize,
    rng: &mut ChaCha20Rng,
    channel: &mut MC::C,
) where
    SimdBackend: BackendForChannel<MC>,
{
    let mut polynomials = SimdBackend::evaluate_polynomials(
        polys,
        scheme.config.fri_config.log_blowup_factor,
        scheme.twiddles,
        scheme.store_polynomials_coefficients,
        &scheme.base_column_pool,
    );
    let seeds: Vec<[u8; 32]> = (0..salt_columns).map(|_| rng.r#gen()).collect();
    let domain = CanonicCoset::new(lifting_log_size).circle_domain();
    let salts: Vec<BaseColumn> = seeds
        .into_par_iter()
        .map(|seed| uniform_column(seed, lifting_log_size))
        .collect();
    polynomials.extend(salts.into_iter().map(|values| {
        Poly::new(
            None,
            CircleEvaluation::<SimdBackend, BaseField, _>::new(domain, values),
        )
    }));
    let commitment = MerkleProverLifted::<SimdBackend, MC::H>::commit(
        polynomials.iter().map(|poly| &poly.evals.values).collect(),
        lifting_log_size,
        0,
    );
    scheme.commit_tree(
        MaybeOwned::Owned(CommitmentTreeProver {
            polynomials,
            commitment,
        }),
        channel,
    );
}
