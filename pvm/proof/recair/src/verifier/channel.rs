//! The Poseidon2-M31 channel in rows (`recursion-air.md` §4.2): the
//! segment verifier's Fiat-Shamir transcript exactly as
//! `Poseidon2M31Channel` runs it, on the lossless encodings (`proving.md`
//! A.3): a u64 as four 16-bit limbs, a byte or an M31 as one word, a felt
//! as its four limbs, a root as its eight.
//!
//! - **Draws:** a felt is the first wire of a squeeze, two felts both; eight
//!   words are a squeeze's two wires.
//! - **PoW:** the check's two permutations, then the first word's trailing
//!   zeros ([`bits::assert_trailing_zeros`]); the nonce, mixed after, is the
//!   wire of its four limbs, each range-checked to 16 bits
//!   ([`bits::assert_u16_limbs`]): the circuit accepts exactly the nonces a
//!   u64 encodes, as the native verifier does.
//! - **Queries:** each a drawn word's canonical bit decomposition, its
//!   position the low bits, as Stwo's `draw_queries` masks it.
//!
//! The absorptions carry no length or tag: the circuit fixes the
//! transcript's shape.

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use super::bits;
use crate::context::{Bit, Context, Var};
use crate::gadgets::TranscriptGadget;
use crate::value::Value;

/// The verifier's channel.
#[derive(Clone, Debug)]
pub struct Channel<V> {
    transcript: TranscriptGadget<V>,
}

/// A u64's four 16-bit limbs as one wire's value.
pub fn u64_wire(value: u64) -> SecureField {
    SecureField::from_m31_array(core::array::from_fn(|i| {
        BaseField::from(((value >> (16 * i)) & 0xffff) as u32)
    }))
}

impl<V: Value> Channel<V> {
    pub fn new(context: &Context<V>) -> Self {
        Self {
            transcript: TranscriptGadget::new(context),
        }
    }

    /// The transcript and its permutations.
    pub fn transcript(&self) -> &TranscriptGadget<V> {
        &self.transcript
    }

    /// `mix_u64` of a constant.
    pub fn mix_u64(&mut self, context: &mut Context<V>, value: u64) {
        let wire = context.constant(u64_wire(value));
        self.mix_wire(context, wire);
    }

    /// `mix_u64` of the value whose four limbs `wire` holds.
    pub(crate) fn mix_wire(&mut self, context: &mut Context<V>, wire: Var) {
        self.transcript.absorb(context, &[wire], 4);
    }

    /// `mix_root`: the eight words of a digest.
    pub fn mix_root(&mut self, context: &mut Context<V>, root: [Var; 2]) {
        self.transcript.absorb(context, &root, 8);
    }

    /// `mix_felts`: four words a felt, as one run.
    pub fn mix_felts(&mut self, context: &mut Context<V>, felts: &[Var]) {
        self.transcript.absorb(context, felts, 4 * felts.len());
    }

    /// `mix_m31s` of `n_values` words packed four a wire, as one run.
    pub fn mix_m31s(&mut self, context: &mut Context<V>, wires: &[Var], n_values: usize) {
        self.transcript.absorb(context, wires, n_values);
    }

    /// `draw_secure_felt`.
    pub(crate) fn draw_felt(&mut self, context: &mut Context<V>) -> Var {
        self.transcript.squeeze(context)[0]
    }

    /// `draw_secure_felts(2)`: one squeeze.
    pub(crate) fn draw_felts(&mut self, context: &mut Context<V>) -> [Var; 2] {
        self.transcript.squeeze(context)
    }

    /// `verify_pow_nonce(n_bits, nonce)`, then `mix_u64(nonce)`: `nonce`
    /// the four 16-bit limbs of a u64.
    pub fn check_pow(&mut self, context: &mut Context<V>, n_bits: u32, nonce: Var) {
        bits::assert_u16_limbs(context, nonce);
        let check = self.transcript.pow(context, n_bits, nonce);
        let word = context.limb(check.digest[0], 0);
        bits::assert_trailing_zeros(context, word, n_bits);
        self.mix_wire(context, nonce);
    }

    /// Stwo's `draw_queries(n_queries, log_size)`: eight words a squeeze,
    /// each position the word's low `log_size` bits, least significant
    /// first; drawn in order, repeats kept.
    pub fn draw_queries(
        &mut self,
        context: &mut Context<V>,
        n_queries: usize,
        log_size: u32,
    ) -> Vec<Vec<Bit>> {
        let mut queries = Vec::with_capacity(n_queries);
        while queries.len() < n_queries {
            let words = self.transcript.squeeze(context);
            for lane in 0..8 {
                if queries.len() == n_queries {
                    break;
                }
                let word = context.limb(words[lane / 4], lane % 4);
                let bits = bits::decompose_word(context, word);
                queries.push(bits[..log_size as usize].to_vec());
            }
        }
        queries
    }
}
