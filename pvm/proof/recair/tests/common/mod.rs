//! Random circuits over every gate and mode, built through one code path for
//! the wiring alone and for the witness.

#![allow(dead_code)]

pub mod kernel;
pub mod leakage;

use std::sync::OnceLock;

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_recair::gadgets::{TranscriptGadget, leaf_hash, node};
use vos_pvm_recair::verifier::witness::pack;
use vos_pvm_recair::{
    Bit, Context, Finalized, Message, P2Handle, Qm31Op, Value, Var, circuit_commitment, prove,
    verify,
};

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
                // A wire absorbed in part is a fresh guess: no other gate
                // reads the lanes the leaf leaves unread.
                let n_values = rng.below(20);
                let row: Vec<Var> = (0..n_values.div_ceil(4))
                    .map(|w| {
                        if rng.below(2) == 0 && 4 * (w + 1) <= n_values {
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
                    .map(|w| {
                        if 4 * (w + 1) <= n_values {
                            rng.pick(&wires)
                        } else {
                            let value = V::from_qm31(rng.qm31());
                            context.guess(value)
                        }
                    })
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

/// The circuit's transcript is `transcript`, the native verifier's recorded
/// one, permutation for permutation.
pub fn assert_transcript_is(
    circuit: &TranscriptGadget<SecureField>,
    transcript: &vos_pvm_proof::RecursionTranscript,
) {
    let permutations = circuit.permutations();
    assert_eq!(permutations.len(), transcript.records.len());
    for (i, (permutation, record)) in permutations.iter().zip(&transcript.records).enumerate() {
        let words = record.output.map(|w| vos_pvm_poseidon2::M31::new(w.0));
        assert_eq!(
            *permutation,
            vos_pvm_recair::value::wires_of(words),
            "permutation {i}"
        );
    }
}

/// Proves `finalized` and verifies the proof against its circuit's hash:
/// the hash and the proof.
pub fn prove_and_verify(
    finalized: &Finalized<SecureField>,
) -> (vos_pvm_poseidon2::Digest, vos_pvm_recair::RecairProof) {
    let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
    let proof = prove(&finalized.circuit, &finalized.witness).expect("proves");
    verify(proof.clone(), &hash).expect("verifies");
    (hash, proof)
}

/// Whether `finalized`'s witness does not prove, or its proof does not
/// verify.
pub fn is_refused(finalized: &Finalized<SecureField>) -> bool {
    match prove(&finalized.circuit, &finalized.witness) {
        Err(_) => true,
        Ok(proof) => {
            let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
            verify(proof, &hash).is_err()
        }
    }
}

/// The format-35 segment fixture's proof.
pub fn segment_fixture() -> vos_pvm_proof::Proof {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/segment-35.proof"
    ))
    .expect("the format-35 fixture");
    postcard::from_bytes(&bytes).expect("a proof")
}

/// A run of six Add64s proved under format 35 over all 25 chips, the ones
/// it does not use padded; proved once a test binary.
pub fn full_shape_proof() -> &'static vos_pvm_proof::Proof {
    use vos_pvm::instruction::Opcode;
    use vos_pvm::interpreter::Interpreter;
    use vos_pvm_proof::core::tracing::TracingPvm;

    static FULL: OnceLock<vos_pvm_proof::Proof> = OnceLock::new();
    FULL.get_or_init(|| {
        let mut code = Vec::new();
        let mut bitmask = Vec::new();
        for register in 2..8 {
            code.extend_from_slice(&[Opcode::Add64 as u8, 0x10 | (register - 1), register]);
            bitmask.extend_from_slice(&[1, 0, 0]);
        }
        code.push(Opcode::Trap as u8);
        bitmask.push(1);
        let mut registers = [0u64; vos_pvm::PVM_REGISTER_COUNT];
        registers[0] = 100;
        registers[1] = 1;
        let memory = vec![0u8; 64 * 1024];
        let pvm = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            registers,
            memory.clone(),
            10_000,
        );
        let mut tracing = TracingPvm::new(pvm);
        tracing.run();
        let mut side_note =
            vos_pvm_proof::SideNote::new(tracing.into_trace(), code, bitmask).with_memory(memory);
        let started = std::time::Instant::now();
        let proof = vos_pvm_proof::prove_canonical_format(
            &mut side_note,
            &[],
            &vos_pvm_proof::format::SEGMENT,
        )
        .expect("proves");
        eprintln!(
            "proved over every chip in {:.1}s",
            started.elapsed().as_secs_f64()
        );
        assert_eq!(proof.component_mask, vos_pvm_proof::chip_idx::ALL);
        proof
    })
}
