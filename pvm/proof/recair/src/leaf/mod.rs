//! A kernel leaf (`proving.md` §3.3, A.3): one segment proof of a kernel's
//! class verified in a circuit ([`verify_segment`]), and the node output it
//! states, an 8-word digest of its preimage ([`NodeOutput`]) at the reserved
//! addresses 3–4.
//!
//! **One circuit per (kernel, class),** a [`LeafCircuit`]: the class's
//! segment shape, with the boundary chips and the class's preprocessed root,
//! and the kernel's entry state, are its constants. Its hash pins the
//! kernel's code, shape and entry.
//!
//! **Its own work** reads the boundary states' 296 bytes, four a wire, as
//! the channel absorbed them. Every field falls on whole wires, so each use
//! takes the wires as they are:
//! - **the entry and exit state digests,** each the leaf sponge over 37 of
//!   the wires, 148 bytes in A.3's order;
//! - **the entry flag,** a bit the prover states: when it is one, every
//!   entry wire equals the constant's, `e·(w − k) = 0` a wire, so the entry
//!   state is the kernel's pc, ts 1, the loader's registers and the image
//!   root;
//! - **the halt flag,** likewise: when it is one, `pc_out` is
//!   `PVM_HALT_ADDR`;
//! - **the io-hash:** φ9..12's 32 bytes, each range-checked to 8 bits, then
//!   16 limbs `b0 + 256·b1`, the only lossy use of the bytes;
//! - **the initial ts is not zero,** as the native verifier refuses a
//!   segment starting at ts 0 (memory-boundary anchoring): one of its two
//!   wires is inverted, so one of its eight bytes is not zero.
//!
//! **A flag states its conditions; zero states nothing.** The fold takes the
//! entry flag from its left child and the halt flag from its right, and the
//! wrap refuses a root without both, so a flag left at zero costs the prover
//! its statement and gains it nothing. The program id and W are witnesses
//! the fold binds (`proving.md` §3.4); the position `(p, p)` is free.
//!
//! Every other use of the boundary bytes is exact on M31 values (`proving.md`
//! A.3): the transcript, the digests, the flags' comparisons. A value of 256
//! or more there aliases no other state.

mod output;
mod program;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_proof::Proof;
use vos_pvm_proof::format::LEAF_FOLD_LOG_SIZES;
use vos_pvm_proof::pcs::Commitment;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{ENTRY_TIMESTAMP, HALT_PC, KernelEntry, KernelProgram};

use crate::circuit::Qm31Op;
use crate::context::{Bit, Context, Finalized, Var};
use crate::gadgets::leaf_hash;
use crate::value::Value;
use crate::verifier::bits::{guess_bits, m31_of, recompose};
use crate::verifier::witness::{digest_wires, pack};
use crate::verifier::{SegmentShape, SegmentValues, WitnessError, verify_segment};

pub use output::{
    NodeOutput, PREIMAGE_WORDS, STATE_WORDS, State, io_hash_limbs, io_hash_of, preimage,
};
pub use program::{LEAF_CIRCUITS_VERSION, kernel_program, leaf_circuit_hashes};

/// The padded shape of every leaf and fold (`proving.md` §3.4, A.4's format
/// 32, [`LEAF_FOLD_LOG_SIZES`]): `p2`, `qm31` and `h8` rows.
pub const PADDED_ROWS: [usize; 3] = [
    1 << LEAF_FOLD_LOG_SIZES[0],
    1 << LEAF_FOLD_LOG_SIZES[1],
    1 << LEAF_FOLD_LOG_SIZES[2],
];

/// The boundary states' wires, four bytes a wire, in
/// `vos_pvm_proof::boundary_binding::boundary_state_bytes`' order: the 13
/// registers in (26 wires), the 13 out (26), pc in (1), ts in (2), pc out
/// (1), ts out (2), the memory root in (8) and out (8).
mod wires {
    use core::ops::Range;

    pub const REGISTERS_IN: Range<usize> = 0..26;
    pub const REGISTERS_OUT: Range<usize> = 26..52;
    pub const PC_IN: usize = 52;
    pub const TS_IN: Range<usize> = 53..55;
    pub const PC_OUT: usize = 55;
    pub const TS_OUT: Range<usize> = 56..58;
    pub const ROOT_IN: Range<usize> = 58..66;
    pub const ROOT_OUT: Range<usize> = 66..74;
    /// φ9..12 of the registers out.
    pub const IO_HASH: Range<usize> = 44..52;

    /// The entry state's wires in the digest's order: registers, pc, ts,
    /// root.
    pub fn entry() -> Vec<usize> {
        REGISTERS_IN
            .chain([PC_IN])
            .chain(TS_IN)
            .chain(ROOT_IN)
            .collect()
    }

    /// The exit state's.
    pub fn exit() -> Vec<usize> {
        REGISTERS_OUT
            .chain([PC_OUT])
            .chain(TS_OUT)
            .chain(ROOT_OUT)
            .collect()
    }
}

/// A leaf circuit: a kernel's class.
pub struct LeafCircuit {
    pub shape: SegmentShape,
    /// The state the kernel's run starts at: the entry flag's constants.
    pub entry: State,
}

/// The values a leaf circuit guesses beyond its segment's.
#[derive(Clone, Debug)]
pub struct LeafValues<V> {
    pub segment: SegmentValues<V>,
    pub program: [V; 2],
    pub fold_word: [V; 2],
    /// The positions the prover states, `first` and `last`: equal in a
    /// leaf.
    pub first: V,
    pub last: V,
    /// The flags the prover states, each 0 or 1.
    pub entry: V,
    pub halt: V,
    /// The io-hash's 16 limbs the prover states, four a wire: each lane is
    /// checked against φ9..12's bytes.
    pub io_hash: [V; 4],
}

/// A leaf's wires: its output digest and its flags.
#[derive(Clone, Copy, Debug)]
pub struct LeafWires {
    pub digest: [Var; 2],
    pub entry: Bit,
    pub halt: Bit,
}

/// The state a kernel's run starts at: its entry's pc and the loader's
/// registers ([`KernelEntry::of`], from the loader's layout), at
/// [`ENTRY_TIMESTAMP`], over the kernel's image root.
pub fn entry_state(program: &KernelProgram, entry: &KernelEntry) -> State {
    State {
        registers: entry.registers,
        pc: entry.pc,
        timestamp: ENTRY_TIMESTAMP,
        memory_root: program.image_root,
    }
}

/// Four M31 values packed in one wire's value.
fn pack4<V: Value>(values: [V; 4]) -> V {
    (0..4).fold(V::from_qm31(SecureField::zero()), |packed, j| {
        let mut basis = [BaseField::zero(); 4];
        basis[j] = BaseField::one();
        packed + values[j] * V::from_qm31(SecureField::from_m31_array(basis))
    })
}

/// A state's bytes, four a wire, as constants.
fn state_constants<V: Value>(context: &mut Context<V>, state: &State) -> Vec<Var> {
    let bytes: Vec<BaseField> = state
        .bytes()
        .iter()
        .map(|&byte| BaseField::from(u32::from(byte)))
        .collect();
    pack(&bytes)
        .into_iter()
        .map(|value| context.constant(value))
        .collect()
}

/// The initial ts is not zero: one of its two wires, picked by a guessed
/// bit, has an inverse.
fn assert_ts_nonzero<V: Value>(context: &mut Context<V>, ts: [Var; 2]) {
    let low_is_zero = context
        .value(ts[0])
        .to_qm31()
        .is_some_and(|value| value == SecureField::zero());
    let pick = context.guess(V::from_qm31(SecureField::from(BaseField::from(u32::from(
        low_is_zero,
    )))));
    let pick = context.assert_bit(pick);
    let difference = context.sub(ts[1], ts[0]);
    let picked = context.mul_add(pick.var(), difference, ts[0]);
    context.inverse(picked);
}

/// φ9..12's 32 bytes, each range-checked to 8 bits, as the io-hash's 16
/// limbs `b0 + 256·b1`: `stated`, four a wire, each lane checked against
/// its limb.
fn io_hash<V: Value>(context: &mut Context<V>, boundary: &[Var], stated: &[V; 4]) -> [Var; 4] {
    let wires = &boundary[wires::IO_HASH];
    for &wire in wires {
        for lane in 0..4 {
            let byte = context.limb(wire, lane);
            let bits = guess_bits(context, m31_of(context.value(byte)), 8);
            recompose(context, &bits, 0, Some(byte));
        }
    }
    core::array::from_fn(|k| {
        let limbs: [(Var, [u32; 4]); 4] = core::array::from_fn(|j| {
            let limb = 4 * k + j;
            let lanes = if limb.is_multiple_of(2) {
                [1, 256, 0, 0]
            } else {
                [0, 0, 1, 256]
            };
            (wires[limb / 2], lanes)
        });
        let packed = context.guess(stated[k]);
        for (j, (wire, lanes)) in limbs.into_iter().enumerate() {
            let limb = context.lane_sum(wire, lanes);
            context.assert_lane(packed, j, limb);
        }
        packed
    })
}

impl LeafCircuit {
    /// The leaf circuit of a segment of `shape`, a kernel's class, whose run
    /// starts at `entry`.
    ///
    /// # Panics
    /// When `shape` has no boundary chips: a leaf verifies a segment, whose
    /// shape [`SegmentShape::new`] or [`SegmentShape::of`] builds.
    pub fn new(shape: SegmentShape, entry: State) -> Self {
        assert!(
            shape.boundary.is_some(),
            "a segment's shape, with the boundary chips"
        );
        Self { shape, entry }
    }

    /// The leaf circuit of `program`'s class `class`, the kernel's run
    /// starting at `entry`.
    ///
    /// # Panics
    /// When `program` has no such class, its format is not one a segment
    /// circuit verifies, or its root is not a Poseidon2-M31 root.
    pub fn of_class(program: &KernelProgram, entry: &KernelEntry, class: usize) -> Self {
        let format = vos_pvm_proof::format::lookup(program.format).expect("a known format");
        let segment = program.shape.segment(class).expect("a class of the shape");
        let Commitment::Poseidon2M31(root) = program.preprocessed_roots[class] else {
            panic!("a Poseidon2-M31 preprocessed root")
        };
        Self::new(
            SegmentShape::new(format, segment.components, &segment.log_sizes, root),
            entry_state(program, entry),
        )
    }

    /// The leaf's work on `values`, in `context`: the segment verified, then
    /// the leaf's own, its rows under the pieces `leaf: flags`, `leaf:
    /// io-hash`, `leaf: digests` and `leaf: output`. The outputs are left to
    /// the caller.
    pub fn verify<V: Value>(&self, context: &mut Context<V>, values: &LeafValues<V>) -> LeafWires {
        let verified = verify_segment(context, &self.shape, &values.segment);
        context.piece("leaf: flags");
        let boundary = &verified.boundary;
        let zero = context.zero();

        let program = values.program.map(|value| context.guess(value));
        let fold_word = values.fold_word.map(|value| context.guess(value));
        let scalars = context.guess(pack4([
            values.first,
            values.last,
            values.entry,
            values.halt,
        ]));
        // `first == last`.
        context.qm31_into(
            Qm31Op {
                lanes: [
                    BaseField::one(),
                    -BaseField::one(),
                    BaseField::zero(),
                    BaseField::zero(),
                ],
                ..Default::default()
            },
            None,
            None,
            Some(scalars),
            zero,
        );
        let [entry, halt] = [2, 3].map(|lane| {
            let flag = context.limb(scalars, lane);
            context.assert_bit(flag)
        });

        let constants = state_constants(context, &self.entry);
        for (index, constant) in wires::entry().into_iter().zip(constants) {
            context.assert_eq_if(entry, boundary[index], constant);
        }
        let halt_pc: Vec<BaseField> = HALT_PC
            .to_le_bytes()
            .iter()
            .map(|&byte| BaseField::from(u32::from(byte)))
            .collect();
        let halt_pc = context.constant(pack(&halt_pc)[0]);
        context.assert_eq_if(halt, boundary[wires::PC_OUT], halt_pc);
        assert_ts_nonzero(
            context,
            [
                boundary[wires::TS_IN.start],
                boundary[wires::TS_IN.start + 1],
            ],
        );
        context.piece("leaf: io-hash");
        let io_hash = io_hash(context, boundary, &values.io_hash);

        context.piece("leaf: digests");
        let digests = [wires::entry(), wires::exit()].map(|state| {
            let state: Vec<Var> = state.into_iter().map(|index| boundary[index]).collect();
            leaf_hash(context, &state, STATE_WORDS).digest
        });
        context.piece("leaf: output");
        let mut preimage = Vec::with_capacity(PREIMAGE_WORDS / 4);
        preimage.extend(program);
        preimage.push(scalars);
        preimage.extend(digests[0]);
        preimage.extend(digests[1]);
        preimage.extend(io_hash);
        preimage.extend(fold_word);
        let digest = leaf_hash(context, &preimage, PREIMAGE_WORDS).digest;
        LeafWires {
            digest,
            entry,
            halt,
        }
    }

    /// The leaf circuit over `values`, its output digest at the reserved
    /// addresses.
    pub fn build<V: Value>(&self, values: &LeafValues<V>) -> Context<V> {
        let mut context = Context::with_outputs(2);
        let wires = self.verify(&mut context, values);
        context.set_outputs(&wires.digest);
        context
    }

    /// [`LeafCircuit::build`], finalized at the padded shape.
    ///
    /// # Panics
    /// When the circuit outgrows the padded shape, which a kernel's
    /// derivation refuses, or its wiring does not check.
    pub fn finalize<V: Value>(&self, values: &LeafValues<V>) -> Finalized<V> {
        self.build(values)
            .finalize_to(Some(PADDED_ROWS))
            .expect("a leaf within the padded shape")
    }

    /// Its wiring, without values, finalized at the padded shape.
    pub fn topology(&self) -> Finalized<crate::NoValue> {
        self.finalize(&LeafValues::blank(&self.shape))
    }

    /// Its hash, the circuit hash a fold recomputes.
    pub fn hash(&self) -> P2Hash {
        let topology = self.topology();
        let (_, hash) =
            crate::circuit_commitment(&topology.circuit).expect("a leaf's wiring checks");
        P2Hash(hash.map(|word| BaseField::from(word.value())))
    }

    /// The values of `proof`, a valid segment proof of its shape, as the
    /// leaf at `position` of a run of the program `program`, the fold word
    /// `fold_word`; and the output they state, its flags each set when its
    /// conditions hold.
    pub fn values(
        &self,
        proof: &Proof,
        program: P2Hash,
        fold_word: P2Hash,
        position: u32,
    ) -> Result<(LeafValues<SecureField>, NodeOutput), WitnessError> {
        let segment = SegmentValues::from_proof(&self.shape, proof)?;
        let initial = State::from(&proof.initial_state);
        let output = NodeOutput {
            program,
            first: position,
            last: position,
            entry: initial == self.entry,
            halt: proof.final_state.pc == HALT_PC,
            entry_digest: initial.digest(),
            exit_digest: State::from(&proof.final_state).digest(),
            io_hash: io_hash_of(&proof.final_state.registers),
            fold_word,
        };
        let m31 = |value: u32| SecureField::from(BaseField::from(value));
        let limbs = pack(&io_hash_limbs(&output.io_hash));
        let values = LeafValues {
            segment,
            program: digest_wires(&program),
            fold_word: digest_wires(&fold_word),
            first: m31(position),
            last: m31(position),
            entry: m31(output.entry.into()),
            halt: m31(output.halt.into()),
            io_hash: core::array::from_fn(|k| limbs[k]),
        };
        Ok((values, output))
    }
}

impl<V: Value> LeafValues<V> {
    /// The layout of a leaf of `shape`'s values, every value zero (or no
    /// value).
    pub fn blank(shape: &SegmentShape) -> Self {
        let zero = V::from_qm31(SecureField::zero());
        Self {
            segment: SegmentValues::blank(shape),
            program: [zero; 2],
            fold_word: [zero; 2],
            first: zero,
            last: zero,
            entry: zero,
            halt: zero,
            io_hash: [zero; 4],
        }
    }
}
