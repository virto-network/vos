//! The commitment's modes: a leaf is a sponge over its row, a node the
//! compression of its two children.

use crate::field::M31;
use crate::permutation::{N_STATE, permute};

/// The words a sponge absorbs a permutation.
pub const RATE: usize = 8;

/// A hash: the first eight words of a state.
pub type Digest = [M31; 8];

/// The first eight words of `state`.
pub fn digest_of(state: &[M31; N_STATE]) -> Digest {
    core::array::from_fn(|i| state[i])
}

/// A node over its two children: the first eight words of the permutation of
/// `left ‖ right`.
pub fn compress(left: &Digest, right: &Digest) -> Digest {
    let mut state = [M31::ZERO; N_STATE];
    state[..8].copy_from_slice(left);
    state[8..].copy_from_slice(right);
    permute(&mut state);
    digest_of(&state)
}

/// A leaf's sponge: the row's words, a one, and zeros to a whole block, added
/// into the first [`RATE`] words a block at a time, each block followed by a
/// permutation; the hash is the first eight words. However the row is split
/// across [`LeafSponge::absorb`] calls, the hash is the same.
#[derive(Clone, Debug, Default)]
pub struct LeafSponge {
    state: [M31; N_STATE],
    buffer: [M31; RATE],
    buffered: usize,
}

impl LeafSponge {
    /// Append `values` to the row.
    pub fn absorb(&mut self, values: impl IntoIterator<Item = M31>) {
        for value in values {
            self.buffer[self.buffered] = value;
            self.buffered += 1;
            if self.buffered == RATE {
                self.absorb_block();
            }
        }
    }

    /// The hash of the row.
    pub fn finalize(mut self) -> Digest {
        self.buffer[self.buffered] = M31::ONE;
        self.buffer[self.buffered + 1..].fill(M31::ZERO);
        self.absorb_block();
        digest_of(&self.state)
    }

    /// The state after the whole blocks absorbed so far.
    pub fn state(&self) -> &[M31; N_STATE] {
        &self.state
    }

    /// The words waiting for a whole block, fewer than [`RATE`].
    pub fn buffered(&self) -> &[M31] {
        &self.buffer[..self.buffered]
    }

    fn absorb_block(&mut self) {
        for (word, &value) in self.state.iter_mut().zip(&self.buffer) {
            *word += value;
        }
        permute(&mut self.state);
        self.buffered = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sponge a leaf is defined as, over the whole padded row at once.
    fn leaf_hash(row: &[M31]) -> Digest {
        let blocks = (row.len() + 1).div_ceil(RATE);
        let word = |i: usize| match i.cmp(&row.len()) {
            core::cmp::Ordering::Less => row[i],
            core::cmp::Ordering::Equal => M31::ONE,
            core::cmp::Ordering::Greater => M31::ZERO,
        };
        let mut state = [M31::ZERO; N_STATE];
        for block in 0..blocks {
            for (lane, value) in state.iter_mut().enumerate().take(RATE) {
                *value += word(block * RATE + lane);
            }
            permute(&mut state);
        }
        digest_of(&state)
    }

    #[test]
    fn a_leaf_hashes_the_same_however_its_row_is_split() {
        let row: [M31; 53] = core::array::from_fn(|i| M31::new(i as u32 * 7919 + 1));
        let expected = leaf_hash(&row);
        let splits: [&[usize]; 6] = [
            &[53],
            &[1; 53],
            &[3, 0, 5, 8, 13, 24],
            &[7, 1, 16, 29],
            &[RATE, RATE, RATE, 29],
            &[0, 50, 3],
        ];
        for split in splits {
            let mut sponge = LeafSponge::default();
            let mut rest = row.as_slice();
            for &len in split {
                let (part, tail) = rest.split_at(len);
                sponge.absorb(part.iter().copied());
                rest = tail;
            }
            assert!(rest.is_empty());
            assert_eq!(sponge.finalize(), expected, "split {split:?}");
        }
    }

    #[test]
    fn an_empty_row_and_whole_blocks_pad_with_a_block() {
        for len in [0, RATE, 2 * RATE] {
            let row: [M31; 16] = core::array::from_fn(|i| M31::new(i as u32 + 3));
            let mut sponge = LeafSponge::default();
            sponge.absorb(row[..len].iter().copied());
            assert_eq!(sponge.finalize(), leaf_hash(&row[..len]), "{len} words");
        }
    }
}
