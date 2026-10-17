//! The Fiat-Shamir transcript: a duplex over the permutation.
//!
//! The transcript holds an eight-word digest and a count of the draws since
//! the digest last changed.
//! - **An absorption** starts from the digest in the first eight words and
//!   zeros, adds each eight-word chunk of its values into the last eight words
//!   and permutes after each (once for no values), and keeps the first eight
//!   words as the new digest.
//! - **A draw** permutes the digest, the draw count and [`DRAW_DOMAIN`], and
//!   returns the first eight words; the count advances.
//! - **The PoW check** permutes the digest and the bit count, then that
//!   state's first eight words and the nonce's four 16-bit limbs; the nonce
//!   passes when the first word has as many trailing zeros. It leaves the
//!   transcript as it was.
//!
//! **The encodings are lossless:** a u64, and so a PoW nonce, enters as four
//! 16-bit limbs and a u32 as two, so no value ≥ p folds onto a smaller one.

use crate::field::M31;
use crate::permutation::{N_STATE, permute};
use crate::sponge::{Digest, RATE, digest_of};

/// The domain word of a draw's permutation.
pub const DRAW_DOMAIN: u32 = 3;

/// Which transcript operation ran a permutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermKind {
    /// An absorption's step: one chunk added in.
    Absorb,
    /// A draw.
    Squeeze,
    /// One of the PoW check's two permutations.
    Pow,
}

/// Sees every permutation a transcript runs, in order.
pub trait Observer {
    /// The permutation of `input` into `output`, run by `kind`. `first_chunk`
    /// is false only on an absorption's chunks after its first, whose last
    /// eight words carry the previous chunk's permuted state.
    fn permuted(
        &mut self,
        kind: PermKind,
        first_chunk: bool,
        input: &[M31; N_STATE],
        output: &[M31; N_STATE],
    );
}

/// No observer.
impl Observer for () {
    fn permuted(&mut self, _: PermKind, _: bool, _: &[M31; N_STATE], _: &[M31; N_STATE]) {}
}

/// The transcript's state; see the module's documentation.
#[derive(Clone, Debug, Default)]
pub struct Transcript {
    digest: Digest,
    n_draws: u32,
}

fn observed_permute(
    observer: &mut impl Observer,
    kind: PermKind,
    first_chunk: bool,
    state: &mut [M31; N_STATE],
) {
    let input = *state;
    permute(state);
    observer.permuted(kind, first_chunk, &input, state);
}

impl Transcript {
    /// The digest.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn seeded(&self) -> [M31; N_STATE] {
        let mut state = [M31::ZERO; N_STATE];
        state[..8].copy_from_slice(&self.digest);
        state
    }

    /// Absorb `values` as one run.
    pub fn absorb(&mut self, values: &[M31], observer: &mut impl Observer) {
        let mut state = self.seeded();
        if values.is_empty() {
            observed_permute(observer, PermKind::Absorb, true, &mut state);
        }
        for (index, chunk) in values.chunks(RATE).enumerate() {
            for (word, &value) in state[8..].iter_mut().zip(chunk) {
                *word += value;
            }
            observed_permute(observer, PermKind::Absorb, index == 0, &mut state);
        }
        self.digest = digest_of(&state);
        self.n_draws = 0;
    }

    /// Draw eight words.
    pub fn squeeze(&mut self, observer: &mut impl Observer) -> Digest {
        let mut state = self.seeded();
        state[8] = M31::from(self.n_draws);
        state[9] = M31::from(DRAW_DOMAIN);
        observed_permute(observer, PermKind::Squeeze, true, &mut state);
        self.n_draws += 1;
        digest_of(&state)
    }

    /// The first eight words of the PoW check's first permutation, which the
    /// nonce does not enter.
    pub fn pow_prefix(&self, n_bits: u32) -> Digest {
        let mut state = self.seeded();
        state[8] = M31::from(n_bits);
        permute(&mut state);
        digest_of(&state)
    }

    /// Whether `nonce` carries `n_bits` of work over the digest.
    pub fn verify_pow_nonce(&self, n_bits: u32, nonce: u64, observer: &mut impl Observer) -> bool {
        let mut first = self.seeded();
        first[8] = M31::from(n_bits);
        observed_permute(observer, PermKind::Pow, true, &mut first);
        pow_passes(&digest_of(&first), n_bits, nonce, observer)
    }
}

/// Whether `nonce` passes over a PoW check's first eight words `prefix`
/// (see [`Transcript::pow_prefix`]).
pub fn pow_passes(prefix: &Digest, n_bits: u32, nonce: u64, observer: &mut impl Observer) -> bool {
    let mut state = [M31::ZERO; N_STATE];
    state[..8].copy_from_slice(prefix);
    state[8..12].copy_from_slice(&u64_limbs(nonce));
    observed_permute(observer, PermKind::Pow, true, &mut state);
    state[0].value().trailing_zeros() >= n_bits
}

/// A u64's four 16-bit limbs, little-endian: every value its own words, so no
/// two values absorb alike.
pub fn u64_limbs(value: u64) -> [M31; 4] {
    core::array::from_fn(|i| M31::new(((value >> (16 * i)) & 0xffff) as u32))
}

/// A u32's two 16-bit limbs, little-endian.
pub fn u32_limbs(value: u32) -> [M31; 2] {
    core::array::from_fn(|i| M31::new((value >> (16 * i)) & 0xffff))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Count(usize, usize);

    impl Observer for Count {
        fn permuted(&mut self, _: PermKind, first: bool, _: &[M31; N_STATE], _: &[M31; N_STATE]) {
            self.0 += 1;
            self.1 += usize::from(!first);
        }
    }

    #[test]
    fn an_absorption_permutes_a_chunk_at_a_time_and_resets_the_draws() {
        let mut transcript = Transcript::default();
        let mut count = Count(0, 0);
        transcript.absorb(&[], &mut count);
        assert_eq!((count.0, count.1), (1, 0));
        let values: [M31; 17] = core::array::from_fn(|i| M31::new(i as u32));
        transcript.absorb(&values, &mut count);
        assert_eq!((count.0, count.1), (4, 2));

        let first = transcript.clone().squeeze(&mut ());
        assert_ne!(transcript.squeeze(&mut ()), transcript.squeeze(&mut ()));
        transcript.absorb(&values, &mut ());
        assert_ne!(transcript.clone().squeeze(&mut ()), first);
    }

    #[test]
    fn the_limbs_are_lossless() {
        let p = u64::from(crate::field::P);
        let values = [0, 1, p, p + 1, 5 << 32, (5 + p) << 32, u64::MAX];
        for (i, &a) in values.iter().enumerate() {
            for &b in &values[i + 1..] {
                assert_ne!(u64_limbs(a), u64_limbs(b));
            }
        }
        assert_ne!(u32_limbs(0), u32_limbs(p as u32));
    }

    #[test]
    fn the_pow_check_splits_at_its_prefix() {
        let mut transcript = Transcript::default();
        transcript.absorb(&[M31::new(9)], &mut ());
        let prefix = transcript.pow_prefix(6);
        for nonce in 0..200 {
            assert_eq!(
                transcript.verify_pow_nonce(6, nonce, &mut ()),
                pow_passes(&prefix, 6, nonce, &mut ())
            );
        }
        assert!((0..200).any(|nonce| transcript.verify_pow_nonce(6, nonce, &mut ())));
    }
}
