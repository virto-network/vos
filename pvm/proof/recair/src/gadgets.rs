//! The Poseidon2 modes as a circuit uses them, each the `vos_pvm_poseidon2`
//! mode it mirrors: a Merkle leaf's sponge ([`leaf_hash`]), a path step
//! ([`node`]), and the Fiat-Shamir transcript ([`TranscriptGadget`]); and
//! a one-hot choice among candidate hashes ([`assert_one_of`]).
//!
//! Values travel packed, four M31 limbs a wire, so a block of eight is two
//! wires.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_poseidon2::{DRAW_DOMAIN, RATE};

use crate::context::{Bit, Context, Message, P2Handle, P2Row, Var};
use crate::value::Value;
use crate::verifier::bits::linear;
use vos_pvm_recair_air::p2::P2Mode;

fn zero_message<V: Value>() -> Message<V> {
    Message::Free(V::from_qm31(SecureField::zero()))
}

/// The two message wires of block `block` of `wires`, free zeros past the
/// end.
fn block_messages<V: Value>(wires: &[Var], block: usize) -> [Message<V>; 2] {
    [0, 1].map(|w| match wires.get(2 * block + w) {
        Some(&var) => Message::Wire(var),
        None => zero_message(),
    })
}

/// `act` over block `block` of a run of `n_values`: one where a value is.
fn active_lanes(block: usize, n_values: usize) -> [BaseField; RATE] {
    core::array::from_fn(|j| {
        if RATE * block + j < n_values {
            BaseField::one()
        } else {
            BaseField::zero()
        }
    })
}

/// A Merkle leaf's hash over `n_values` values packed in `wires`, as
/// `LeafSponge` hashes it: a block of eight at a time, the first in
/// leaf-start mode and the others chained, a one after the values and zeros
/// to a whole block. The wires are yielded here when they are guesses.
pub fn leaf_hash<V: Value>(
    context: &mut Context<V>,
    wires: &[Var],
    n_values: usize,
) -> P2Handle<V> {
    assert_eq!(wires.len(), n_values.div_ceil(4), "four values a wire");
    let n_blocks = (n_values + 1).div_ceil(RATE);
    let mut prev: Option<P2Handle<V>> = None;
    for block in 0..n_blocks {
        let mut c = [BaseField::zero(); 10];
        if let Some(lane) = n_values
            .checked_sub(RATE * block)
            .filter(|&lane| lane < RATE)
        {
            c[lane] = BaseField::one();
        }
        let mode = if block == 0 {
            P2Mode::LeafStart
        } else {
            P2Mode::LeafContinue
        };
        let row = P2Row {
            prev: prev.as_ref(),
            m: block_messages(wires, block),
            act: active_lanes(block, n_values),
            c,
            ..P2Row::new(mode)
        };
        prev = Some(context.p2(row));
    }
    prev.expect("a leaf has a block")
}

/// A Merkle node over `child`, the row below, and `sibling`: `compress(child,
/// sibling)` when `bit` is 0, `compress(sibling, child)` when it is 1. The
/// row's input is linear in the bit, so a non-bit would pick a blend of the
/// two orders: [`Bit`] is made only by a constraint. The output is `out` when
/// given.
pub fn node<V: Value>(
    context: &mut Context<V>,
    child: &P2Handle<V>,
    sibling: [Message<V>; 2],
    bit: Bit,
    out: Option<[Var; 2]>,
) -> P2Handle<V> {
    context.p2(P2Row {
        prev: Some(child),
        m: sibling,
        bit: Some(bit),
        out,
        ..P2Row::new(P2Mode::Node)
    })
}

/// The Fiat-Shamir transcript of `vos_pvm_poseidon2::Transcript`, in rows.
///
/// Absorptions chain from one another, so their rows form one chain; a draw
/// and the PoW's first permutation are wired rows over the digest's wires.
#[derive(Clone, Debug)]
pub struct TranscriptGadget<V> {
    digest: [Var; 2],
    last_absorption: Option<P2Handle<V>>,
    n_draws: u32,
    permutations: Vec<[V; 4]>,
}

impl<V: Value> TranscriptGadget<V> {
    /// The transcript at its zero digest.
    pub fn new(context: &Context<V>) -> Self {
        Self {
            digest: [context.zero(); 2],
            last_absorption: None,
            n_draws: 0,
            permutations: Vec::new(),
        }
    }

    /// Every permutation's output state, in the transcript's order: what a
    /// native recorder's records hold.
    pub fn permutations(&self) -> &[[V; 4]] {
        &self.permutations
    }

    /// The digest's two wires.
    pub fn digest(&self) -> [Var; 2] {
        self.digest
    }

    /// Absorbs `n_values` values packed in `wires` as one run: eight a
    /// permutation into the last eight words, over the digest; one
    /// permutation for no values.
    pub fn absorb(&mut self, context: &mut Context<V>, wires: &[Var], n_values: usize) {
        assert_eq!(wires.len(), n_values.div_ceil(4), "four values a wire");
        let n_chunks = n_values.div_ceil(RATE).max(1);
        let mut prev = self.last_absorption.take();
        for chunk in 0..n_chunks {
            let mode = match (chunk, &prev) {
                (0, None) => P2Mode::ChannelStart,
                (0, Some(_)) => P2Mode::ChannelFirst,
                _ => P2Mode::ChannelContinue,
            };
            let row = P2Row {
                prev: prev.as_ref(),
                m: block_messages(wires, chunk),
                act: active_lanes(chunk, n_values),
                ..P2Row::new(mode)
            };
            let handle = context.p2(row);
            self.permutations.push(handle.state);
            prev = Some(handle);
        }
        let last = prev.expect("an absorption permutes");
        self.digest = last.digest;
        self.last_absorption = Some(last);
        self.n_draws = 0;
    }

    /// Draws eight words, as two wires: the permutation of the digest, the
    /// draw count and the draw domain.
    pub fn squeeze(&mut self, context: &mut Context<V>) -> [Var; 2] {
        let mut c = [BaseField::zero(); 10];
        c[8] = BaseField::from(self.n_draws);
        c[9] = BaseField::from(DRAW_DOMAIN);
        let handle = context.p2(P2Row {
            m: self.digest.map(Message::Wire),
            act: [BaseField::one(); RATE],
            c,
            ..P2Row::new(P2Mode::Wired)
        });
        self.permutations.push(handle.state);
        self.n_draws += 1;
        handle.digest
    }

    /// The PoW check's two permutations over `nonce`, the wire of its four
    /// 16-bit limbs: the digest and `n_bits`, then that state's first eight
    /// words and the nonce. The second row's first word is the one whose
    /// trailing zeros count. The transcript is left as it was.
    pub fn pow(&mut self, context: &mut Context<V>, n_bits: u32, nonce: Var) -> P2Handle<V> {
        let mut c = [BaseField::zero(); 10];
        c[8] = BaseField::from(n_bits);
        let first = context.p2(P2Row {
            m: self.digest.map(Message::Wire),
            act: [BaseField::one(); RATE],
            c,
            ..P2Row::new(P2Mode::Wired)
        });
        self.permutations.push(first.state);
        let mut act = [BaseField::zero(); RATE];
        act[..4].fill(BaseField::one());
        let second = context.p2(P2Row {
            prev: Some(&first),
            m: [Message::Wire(nonce), zero_message()],
            act,
            ..P2Row::new(P2Mode::ChannelFirst)
        });
        self.permutations.push(second.state);
        second
    }
}

/// `Σ bits = 1` and, for each bit, `bit·(hash − candidate) = 0`: `hash` is
/// the candidate the one set bit picks.
pub fn assert_one_of<V: Value>(
    context: &mut Context<V>,
    hash: [Var; 2],
    candidates: &[[Var; 2]],
    bits: &[Bit],
) {
    assert_eq!(bits.len(), candidates.len(), "a bit a candidate");
    let terms: Vec<(BaseField, Var)> = bits
        .iter()
        .map(|bit| (BaseField::one(), bit.var()))
        .collect();
    let one = context.one();
    linear(context, &terms, Some(one));
    for (&bit, candidate) in bits.iter().zip(candidates) {
        for (&wire, &candidate) in hash.iter().zip(candidate) {
            context.assert_eq_if(bit, wire, candidate);
        }
    }
}
