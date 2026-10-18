//! Random circuits over every gate and mode, built through one code path for
//! the wiring alone and for the witness.

#![allow(dead_code)]

pub mod kernel;

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_recair::gadgets::{TranscriptGadget, leaf_hash, node};
use vos_pvm_recair::verifier::witness::pack;
use vos_pvm_recair::{Bit, Context, Message, P2Handle, Qm31Op, Value, Var};

/// SplitMix64.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn m31(&mut self) -> BaseField {
        BaseField::from((self.next_u64() % ((1 << 31) - 1)) as u32)
    }

    pub fn qm31(&mut self) -> SecureField {
        SecureField::from_m31_array(core::array::from_fn(|_| self.m31()))
    }

    fn pick(&mut self, wires: &[Var]) -> Var {
        wires[self.below(wires.len())]
    }
}

pub fn m31_value<V: Value>(value: u32) -> V {
    V::from_qm31(SecureField::from(BaseField::from(value)))
}

/// A random circuit of about `gates` gates, every gate kind and every `p2`
/// mode among them, with two outputs. The choices depend on the seed alone,
/// so the circuit is the same whatever `V` is.
pub fn random_circuit<V: Value>(seed: u64, gates: usize) -> Context<V> {
    let mut rng = Rng::new(seed);
    let mut context = Context::<V>::with_outputs(2);
    let mut wires: Vec<Var> = vec![context.one(), context.u()];
    for _ in 0..4 {
        let value = V::from_qm31(rng.qm31());
        wires.push(context.guess(value));
    }
    // Rows a chained row may follow: those without a successor.
    let mut open: Vec<P2Handle<V>> = Vec::new();
    let mut transcript = TranscriptGadget::new(&context);
    while context.rows().iter().sum::<usize>() < gates {
        match rng.below(16) {
            0 => {
                let (a, b) = (rng.pick(&wires), rng.pick(&wires));
                wires.push(context.add(a, b));
            }
            1 => {
                let (a, b) = (rng.pick(&wires), rng.pick(&wires));
                wires.push(context.sub(a, b));
            }
            2 => {
                let (a, b) = (rng.pick(&wires), rng.pick(&wires));
                wires.push(context.mul(a, b));
            }
            3 => {
                let (a, b) = (rng.pick(&wires), rng.pick(&wires));
                wires.push(context.pointwise_mul(a, b));
            }
            4 => {
                let (a, b, c) = (rng.pick(&wires), rng.pick(&wires), rng.pick(&wires));
                wires.push(context.mul_add(a, b, c));
            }
            5 => {
                // The full linear form at random coefficients.
                let op = Qm31Op {
                    k_m: rng.m31(),
                    k_p: rng.m31(),
                    k_a: rng.m31(),
                    k_b: rng.m31(),
                    k_c: rng.m31(),
                    lanes: core::array::from_fn(|_| rng.m31()),
                };
                let (a, b, c) = (rng.pick(&wires), rng.pick(&wires), rng.pick(&wires));
                wires.push(context.qm31(op, Some(a), Some(b), Some(c)));
            }
            6 => {
                let a = rng.pick(&wires);
                let j = rng.below(4);
                wires.push(context.limb(a, j));
            }
            7 => {
                // A wire may be zero (`a − a`); a fresh guess added makes it
                // nonzero but for a negligible chance.
                let value = V::from_qm31(rng.qm31());
                let shift = context.guess(value);
                let a = rng.pick(&wires);
                let a = context.add(a, shift);
                wires.push(context.inverse(a));
            }
            8 => {
                let value = rng.qm31();
                let constant = context.constant(value);
                let a = rng.pick(&wires);
                wires.push(context.mul(a, constant));
                let small = context.constant_m31(rng.below(1000) as u32);
                wires.push(context.add(a, small));
            }
            9 => {
                // A guess yielded by the gate whose output must equal it.
                let (a, b) = (rng.pick(&wires), rng.pick(&wires));
                let value = context.value(a) + context.value(b);
                let guess = context.guess(value);
                context.qm31_into(
                    Qm31Op {
                        k_a: BaseField::from(1),
                        k_b: BaseField::from(1),
                        ..Default::default()
                    },
                    Some(a),
                    Some(b),
                    None,
                    guess,
                );
                wires.push(guess);
            }
            10 | 11 => {
                let [acc, step, mu, v0, v1] = core::array::from_fn(|_| rng.pick(&wires));
                wires.push(context.h8(acc, step, mu, [v0, v1]));
            }
            12 => {
                let n_values = rng.below(20);
                let row: Vec<Var> = (0..n_values.div_ceil(4))
                    .map(|_| {
                        if rng.below(2) == 0 {
                            rng.pick(&wires)
                        } else {
                            let value = V::from_qm31(rng.qm31());
                            context.guess(value)
                        }
                    })
                    .collect();
                let leaf = leaf_hash(&mut context, &row, n_values);
                wires.extend(leaf.digest);
                open.push(leaf);
            }
            13 if !open.is_empty() => {
                let child = open.swap_remove(rng.below(open.len()));
                let bit = context.guess(m31_value(rng.below(2) as u32));
                let bit = context.assert_bit(bit);
                let sibling = if rng.below(2) == 0 {
                    [0, 1].map(|_| Message::Free(V::from_qm31(rng.qm31())))
                } else {
                    [0, 1].map(|_| Message::Wire(rng.pick(&wires)))
                };
                let parent = node(&mut context, &child, sibling, bit, None);
                wires.extend(parent.digest);
                open.push(parent);
            }
            14 => {
                let n_values = rng.below(20);
                let values: Vec<Var> = (0..n_values.div_ceil(4))
                    .map(|_| rng.pick(&wires))
                    .collect();
                transcript.absorb(&mut context, &values, n_values);
                wires.extend(transcript.squeeze(&mut context));
            }
            15 => {
                let nonce = rng.pick(&wires);
                let check = transcript.pow(&mut context, rng.below(30) as u32, nonce);
                wires.extend(check.digest);
            }
            _ => {}
        }
    }
    let outputs = [rng.pick(&wires), rng.pick(&wires)];
    context.set_outputs(&outputs);
    context
}

pub fn words(values: &[BaseField]) -> Vec<vos_pvm_poseidon2::M31> {
    values
        .iter()
        .map(|value| vos_pvm_poseidon2::M31::new(value.0))
        .collect()
}

/// Eight words as two wires' values.
pub fn digest_wires(digest: &vos_pvm_poseidon2::Digest) -> [SecureField; 2] {
    let values: Vec<BaseField> = digest
        .iter()
        .map(|word| BaseField::from(word.value()))
        .collect();
    let packed = pack(&values);
    [packed[0], packed[1]]
}

/// The window kernel's class-1 leaf topology: its mask and log sizes.
pub const WINDOW_MASK: u32 = 0x01f9_ffff;
pub const WINDOW_LOG_SIZES: [u32; 23] = [
    15, 14, 16, 18, 9, 8, 4, 17, 4, 4, 4, 16, 8, 16, 8, 8, 6, 8, 15, 15, 15, 15, 16,
];

/// `context`'s rows, in all and by piece, to stderr.
pub fn print_rows(name: &str, context: &Context<impl Value>) {
    eprintln!("{name}: {:?} rows (p2, qm31, h8)", context.rows());
    for (piece, rows) in context.piece_rows() {
        eprintln!("  {piece}: {rows:?}");
    }
}

/// The position `bits` hold, low bit first.
pub fn position_of(context: &Context<SecureField>, bits: &[Bit]) -> usize {
    bits.iter()
        .enumerate()
        .map(|(i, bit)| usize::from(context.value(bit.var()) == SecureField::one()) << i)
        .sum()
}

/// `value` moved by one.
pub fn bump(value: &mut SecureField) {
    *value += SecureField::one();
}
