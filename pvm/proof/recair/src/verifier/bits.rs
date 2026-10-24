//! Bits, and the checks the verifier builds on them: a drawn word's
//! canonical decomposition (a query's position), a PoW's trailing zeros and
//! a nonce's 16-bit limbs.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use crate::circuit::Qm31Op;
use crate::context::{Bit, Context, Var};
use crate::value::Value;

/// The M31 a wire's first limb holds, when the context holds values.
pub(crate) fn m31_of<V: Value>(value: V) -> Option<u32> {
    value.to_qm31().map(|value| value.to_m31_array()[0].0)
}

/// `n` bits of `value`, least significant first, each guessed and
/// constrained to a bit; zeros without a value.
pub fn guess_bits<V: Value>(context: &mut Context<V>, value: Option<u32>, n: u32) -> Vec<Bit> {
    (0..n)
        .map(|i| {
            let bit = value.map_or(0, |value| (value >> i) & 1);
            let var = context.guess(V::from_qm31(SecureField::from(BaseField::from(bit))));
            context.assert_bit(var)
        })
        .collect()
}

/// `Σ k_i·x_i` over `terms`, three in the first row and two in each next,
/// the last row's output `out` when given (an equality) and a new wire
/// otherwise.
pub fn linear<V: Value>(
    context: &mut Context<V>,
    terms: &[(BaseField, Var)],
    out: Option<Var>,
) -> Var {
    if terms.is_empty() {
        let zero = context.zero();
        if let Some(out) = out {
            context.assert_eq(zero, out);
        }
        return out.unwrap_or(zero);
    }
    let first = terms.len().min(3);
    let mut rest = terms[first..].chunks(2);
    let n_rows = 1 + rest.len();
    let row = |context: &mut Context<V>, op: Qm31Op, operands: [Option<Var>; 3], last: bool| {
        let [a, b, c] = operands;
        match (last, out) {
            (true, Some(out)) => {
                context.qm31_into(op, a, b, c, out);
                out
            }
            _ => context.qm31(op, a, b, c),
        }
    };
    let pick = |i: usize| terms.get(i).copied();
    let mut op = Qm31Op::default();
    let [a, b, c] = [0, 1, 2].map(|i| (i < first).then(|| pick(i)).flatten());
    op.k_a = a.map_or(BaseField::zero(), |t| t.0);
    op.k_b = b.map_or(BaseField::zero(), |t| t.0);
    op.k_c = c.map_or(BaseField::zero(), |t| t.0);
    let mut acc = row(
        context,
        op,
        [a.map(|t| t.1), b.map(|t| t.1), c.map(|t| t.1)],
        n_rows == 1,
    );
    let mut built = 1;
    for pair in rest.by_ref() {
        built += 1;
        let op = Qm31Op {
            k_a: BaseField::one(),
            k_b: pair[0].0,
            k_c: pair.get(1).map_or(BaseField::zero(), |t| t.0),
            ..Default::default()
        };
        acc = row(
            context,
            op,
            [Some(acc), Some(pair[0].1), pair.get(1).map(|t| t.1)],
            built == n_rows,
        );
    }
    acc
}

/// `Σ 2^(shift+i)·bits_i`, written to `out` when given.
pub fn recompose<V: Value>(
    context: &mut Context<V>,
    bits: &[Bit],
    shift: u32,
    out: Option<Var>,
) -> Var {
    assert!(shift as usize + bits.len() <= 31, "an M31's bits");
    let terms: Vec<(BaseField, Var)> = bits
        .iter()
        .enumerate()
        .map(|(i, bit)| (BaseField::from(1u32 << (shift as usize + i)), bit.var()))
        .collect();
    linear(context, &terms, out)
}

/// The 31 bits of the M31 `word`, least significant first: they recompose
/// it, and they are not all one, the other decomposition of zero
/// (`2^31 − 1 = p`). 63 rows.
pub(crate) fn decompose_word<V: Value>(context: &mut Context<V>, word: Var) -> Vec<Bit> {
    let value = m31_of(context.value(word));
    let bits = guess_bits(context, value, 31);
    check_word_bits(context, word, &bits);
    bits
}

/// `bits`, 31 of them, are the canonical decomposition of the M31 `word`:
/// they recompose it and are not all one.
pub fn check_word_bits<V: Value>(context: &mut Context<V>, word: Var, bits: &[Bit]) {
    assert_eq!(bits.len(), 31, "an M31's bits");
    recompose(context, bits, 0, Some(word));
    let mut terms: Vec<(BaseField, Var)> = bits
        .iter()
        .map(|bit| (BaseField::one(), bit.var()))
        .collect();
    terms.push((-BaseField::from(31), context.one()));
    let excess = linear(context, &terms, None);
    context.inverse(excess);
}

/// The M31 `word` has at least `n_bits` trailing zeros: `word = 2^n·h` with
/// `h` of `31 − n` bits. `2^n·h` is below `2^31 − 1` and even, so it is the
/// integer `word` itself.
pub fn assert_trailing_zeros<V: Value>(context: &mut Context<V>, word: Var, n_bits: u32) {
    assert!((1..31).contains(&n_bits), "a PoW of 1 to 30 bits");
    let high = m31_of(context.value(word)).map(|word| word >> n_bits);
    let bits = guess_bits(context, high, 31 - n_bits);
    recompose(context, &bits, n_bits, Some(word));
}

/// Each of `wire`'s four limbs is below `2^16`: the wire is a u64's four
/// 16-bit limbs, as `mix_u64` absorbs them. A limb's 16 bits recompose it,
/// and `Σ 2^i·b_i < p`, so the limb is that integer. 100 rows.
pub fn assert_u16_limbs<V: Value>(context: &mut Context<V>, wire: Var) {
    let limbs = context
        .value(wire)
        .to_qm31()
        .map(|value| value.to_m31_array().map(|limb| limb.0));
    for lane in 0..4 {
        let limb = context.limb(wire, lane);
        let bits = guess_bits(context, limbs.map(|limbs| limbs[lane]), 16);
        recompose(context, &bits, 0, Some(limb));
    }
}
