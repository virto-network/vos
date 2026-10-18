//! A fold node (`proving.md` §3.4, A.3; `recursion-air.md` §6): two child
//! proofs of the padded shape, each a leaf's or a fold's, verified in one
//! circuit, and the node output their run states.
//!
//! **One circuit for every fold,** a [`FoldCircuit`]: its constants are the
//! child's shape alone ([`ChildShape::padded`]); the program, the children's
//! circuits and the fold word W are witnesses. Its hash is W's true value,
//! which the wrap holds as a constant.
//!
//! **For each child** ([`child`]):
//! - its proof verified, its output digest's two wires the proof's outputs;
//! - its circuit hash recomputed from its preprocessed root;
//! - its output's 52-word preimage, a witness, re-hashed to that digest.
//!
//! **The circuit set:** each child's circuit hash is one of the program's
//! leaf-circuit hashes or W (a one-hot choice over them), **and** the child
//! carries W. The fold copies W to its output. The wrap checks the root's W
//! against the fold circuit's hash, so by induction every fold in a tree
//! carries it, and every fold child is a leaf of the program or a true fold.
//!
//! **The program:** the id's preimage (`vos_pvm_proof::program_id`'s
//! [`ID_WORDS`]: the kernel's digest, the leaf-circuit slot, its hashes) is
//! a witness, the id recomputed from it; both children carry that id, and
//! the leaf-circuit hashes above are that preimage's. A leaf's program id is
//! a free witness of the leaf, so this is what binds it.
//!
//! **The run:** adjacency, `left.last + 1 == right.first`; continuity,
//! `left.exit == right.entry`, the digests; the ends: the entry flag and
//! digest and `first` from the left, the halt flag, exit digest, io-hash and
//! `last` from the right, each taken from its side alone. A fold does not
//! refuse a run without an entry or a halt: it states none, and the wrap
//! refuses a root without both.
//!
//! **Its output** is a node output as a leaf's ([`NodeOutput`], A.3), its
//! digest at the reserved addresses 3–4: a fold is itself a child.

pub mod child;

use std::sync::OnceLock;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{ID_WORDS, IdPreimage, MAX_LEAF_CIRCUITS};

use crate::circuit::Qm31Op;
use crate::context::{Bit, Context, Finalized, Var};
use crate::gadgets::leaf_hash;
use crate::leaf::{NodeOutput, PADDED_ROWS, PREIMAGE_WORDS, preimage};
use crate::prove::{RecairProof, circuit_hash_of};
use crate::value::Value;
use crate::verifier::WitnessError;
use crate::verifier::bits::linear;
use crate::verifier::witness::{digest_wires, pack};

use child::{ChildShape, ChildValues, circuit_hash, verify_child};

/// The program id's preimage's wires.
pub const PROGRAM_WIRES: usize = ID_WORDS / 4;

/// The circuits a child's may be: the program's leaf circuits, then W.
pub const CIRCUITS: usize = MAX_LEAF_CIRCUITS + 1;

/// The first leaf-circuit hash's wire in the id's preimage, after the
/// kernel's digest and the slot's version and count; each hash two wires.
pub(crate) const FIRST_HASH_WIRE: usize = (ID_WORDS - 8 * MAX_LEAF_CIRCUITS) / 4;

/// The fold circuit.
pub struct FoldCircuit {
    pub child: &'static ChildShape,
}

impl Default for FoldCircuit {
    fn default() -> Self {
        Self::new()
    }
}

/// A child's values, as the fold guesses them.
#[derive(Clone, Debug)]
pub struct FoldChild<V> {
    pub proof: ChildValues<V>,
    /// Its output digest's two wires: its proof's outputs.
    pub output: [V; 2],
    /// Its output's preimage, four words a wire.
    pub preimage: [V; preimage::WIRES],
    /// Which of the program's leaf circuits, or W, its circuit is: one bit
    /// a candidate, in [`CIRCUITS`]' order.
    pub circuit: [V; CIRCUITS],
}

/// The values a fold circuit guesses.
#[derive(Clone, Debug)]
pub struct FoldValues<V> {
    pub children: [FoldChild<V>; 2],
    /// The program id's preimage, four words a wire.
    pub program: [V; PROGRAM_WIRES],
    pub fold_word: [V; 2],
}

/// A child, proved: its proof and the output its proof states.
#[derive(Clone, Copy, Debug)]
pub struct Proved<'a> {
    pub proof: &'a RecairProof,
    pub output: &'a NodeOutput,
}

/// A child's wires the fold's own checks read.
pub(crate) struct ChildWires {
    pub hash: [Var; 2],
    pub preimage: Vec<Var>,
    pub circuit: Vec<Bit>,
}

/// A child's proof verified, its output digest's two wires the proof's
/// outputs; its circuit hash recomputed from its preprocessed root and its
/// circuit bits guessed, under `pieces[0]`; its preimage re-hashed to its
/// output digest, under `pieces[1]`.
pub(crate) fn verify_node<V: Value>(
    context: &mut Context<V>,
    shape: &ChildShape,
    child: &FoldChild<V>,
    pieces: [&'static str; 2],
) -> ChildWires {
    let output = context.guess_pair(child.output);
    let verified = verify_child(context, shape, &child.proof, output);
    context.piece(pieces[0]);
    let hash = circuit_hash(context, &shape.log_sizes, verified.preprocessed_root);
    let circuit = child
        .circuit
        .iter()
        .map(|&bit| {
            let bit = context.guess(bit);
            context.assert_bit(bit)
        })
        .collect();
    context.piece(pieces[1]);
    let preimage: Vec<Var> = child.preimage.iter().map(|&v| context.guess(v)).collect();
    let digest = leaf_hash(context, &preimage, PREIMAGE_WORDS).digest;
    for (digest, output) in digest.into_iter().zip(output) {
        context.assert_eq(digest, output);
    }
    ChildWires {
        hash,
        preimage,
        circuit,
    }
}

/// The program's leaf-circuit hashes in the id's preimage `program`, two
/// wires each.
pub(crate) fn leaf_circuit_wires(program: &[Var]) -> impl Iterator<Item = [Var; 2]> + '_ {
    (0..MAX_LEAF_CIRCUITS).map(move |k| {
        let wire = FIRST_HASH_WIRE + 2 * k;
        [program[wire], program[wire + 1]]
    })
}

/// `Σ bits = 1` and, for each bit, `bit·(hash − candidate) = 0`: `hash` is
/// the candidate the one set bit picks.
pub(crate) fn assert_one_of<V: Value>(
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

/// A constant wire of four M31 lanes.
fn lanes<V: Value>(context: &mut Context<V>, lanes: [u32; 4]) -> Var {
    context.constant(SecureField::from_m31_array(lanes.map(BaseField::from)))
}

impl FoldCircuit {
    /// The fold circuit, over children of the padded shape.
    pub fn new() -> Self {
        Self {
            child: ChildShape::padded(),
        }
    }

    /// The fold's work on `values`, in `context`: each child verified, its
    /// circuit hashed and its preimage re-hashed, then the fold's own
    /// checks, its rows under the pieces `fold: circuit`, `fold: preimage`,
    /// `fold: program`, `fold: adjacency`, `fold: continuity` and `fold:
    /// output`. Its output digest's wires; the outputs are left to the
    /// caller.
    pub fn verify<V: Value>(&self, context: &mut Context<V>, values: &FoldValues<V>) -> [Var; 2] {
        let children = values.children.each_ref().map(|child| {
            verify_node(
                context,
                self.child,
                child,
                ["fold: circuit", "fold: preimage"],
            )
        });

        context.piece("fold: program");
        let program: Vec<Var> = values.program.iter().map(|&v| context.guess(v)).collect();
        let id = leaf_hash(context, &program, ID_WORDS).digest;
        for child in &children {
            for (&wire, id) in child.preimage[preimage::PROGRAM].iter().zip(id) {
                context.assert_eq(wire, id);
            }
        }

        context.piece("fold: circuit");
        let fold_word = context.guess_pair(values.fold_word);
        let candidates: Vec<[Var; 2]> = leaf_circuit_wires(&program).chain([fold_word]).collect();
        for child in &children {
            for (&wire, fold_word) in child.preimage[preimage::FOLD_WORD].iter().zip(fold_word) {
                context.assert_eq(wire, fold_word);
            }
            assert_one_of(context, child.hash, &candidates, &child.circuit);
        }

        let [left, right] = &children.map(|child| child.preimage);
        context.piece("fold: adjacency");
        // `1 + left.last − right.first = 0`.
        let first = context.limb(right[preimage::SCALARS], 0);
        let one = context.one();
        let zero = context.zero();
        context.qm31_into(
            Qm31Op {
                k_a: BaseField::one(),
                k_b: -BaseField::one(),
                lanes: [0, 1, 0, 0].map(BaseField::from),
                ..Default::default()
            },
            Some(one),
            Some(first),
            Some(left[preimage::SCALARS]),
            zero,
        );

        context.piece("fold: continuity");
        for (&exit, &entry) in left[preimage::EXIT_DIGEST]
            .iter()
            .zip(&right[preimage::ENTRY_DIGEST])
        {
            context.assert_eq(exit, entry);
        }

        context.piece("fold: output");
        // `[left.first, right.last, left.entry, right.halt]`.
        let left_lanes = lanes(context, [1, 0, 1, 0]);
        let right_lanes = lanes(context, [0, 1, 0, 1]);
        let from_left = context.pointwise_mul(left[preimage::SCALARS], left_lanes);
        let scalars = context.qm31(
            Qm31Op {
                k_p: BaseField::one(),
                k_c: BaseField::one(),
                ..Default::default()
            },
            Some(right[preimage::SCALARS]),
            Some(right_lanes),
            Some(from_left),
        );
        let mut output = Vec::with_capacity(preimage::WIRES);
        output.extend(id);
        output.push(scalars);
        output.extend_from_slice(&left[preimage::ENTRY_DIGEST]);
        output.extend_from_slice(&right[preimage::EXIT_DIGEST]);
        output.extend_from_slice(&right[preimage::IO_HASH]);
        output.extend(fold_word);
        leaf_hash(context, &output, PREIMAGE_WORDS).digest
    }

    /// The fold circuit over `values`, its output digest at the reserved
    /// addresses.
    pub fn build<V: Value>(&self, values: &FoldValues<V>) -> Context<V> {
        let mut context = Context::with_outputs(2);
        let digest = self.verify(&mut context, values);
        context.set_outputs(&digest);
        context
    }

    /// [`FoldCircuit::build`], finalized at the padded shape.
    ///
    /// # Panics
    /// When the circuit outgrows the padded shape, or its wiring does not
    /// check.
    pub fn finalize<V: Value>(&self, values: &FoldValues<V>) -> Finalized<V> {
        self.build(values)
            .finalize_to(Some(PADDED_ROWS))
            .expect("a fold within the padded shape")
    }

    /// Its wiring, without values, finalized at the padded shape.
    pub fn topology(&self) -> Finalized<crate::NoValue> {
        self.finalize(&FoldValues::blank(self.child))
    }

    /// Its hash: the fold word W of every node of a tree.
    pub fn hash(&self) -> P2Hash {
        let topology = self.topology();
        let (_, hash) =
            crate::circuit_commitment(&topology.circuit).expect("a fold's wiring checks");
        P2Hash(hash.map(|word| BaseField::from(word.value())))
    }

    /// [`FoldCircuit::hash`] of the fold circuit over the padded shape,
    /// computed once: `H_fold`, the wrap's constant.
    pub fn word() -> P2Hash {
        static WORD: OnceLock<P2Hash> = OnceLock::new();
        *WORD.get_or_init(|| Self::new().hash())
    }

    /// The values of a fold of `left` and `right`, valid proofs of the
    /// padded shape, under the program whose id's preimage is `program`
    /// and the fold word `fold_word`; and the output they state.
    ///
    /// A child's circuit is the first of the program's leaf circuits its
    /// hash equals, or W; one that is neither sets no bit, which the circuit
    /// refuses.
    ///
    /// # Panics
    /// When a proof does not verify natively.
    pub fn values(
        &self,
        left: Proved<'_>,
        right: Proved<'_>,
        program: &IdPreimage,
        fold_word: P2Hash,
    ) -> Result<(FoldValues<SecureField>, NodeOutput), WitnessError> {
        let children = [
            FoldChild::of(self.child, left, program, fold_word)?,
            FoldChild::of(self.child, right, program, fold_word)?,
        ];
        let mut output = NodeOutput::fold(left.output, right.output);
        output.program = P2Hash(program.id().0);
        output.fold_word = fold_word;
        let words = pack(&program.words());
        let values = FoldValues {
            children,
            program: core::array::from_fn(|k| words[k]),
            fold_word: digest_wires(&fold_word),
        };
        Ok((values, output))
    }
}

impl FoldChild<SecureField> {
    /// The values of `proved`, a valid proof of `shape`, as a node under the
    /// program whose id's preimage is `program` and the fold word
    /// `fold_word`. Its circuit is the first of the program's leaf circuits
    /// its hash equals, or W; one that is neither sets no bit, which a
    /// circuit refuses.
    ///
    /// # Panics
    /// When the proof does not verify natively.
    pub fn of(
        shape: &ChildShape,
        proved: Proved<'_>,
        program: &IdPreimage,
        fold_word: P2Hash,
    ) -> Result<Self, WitnessError> {
        let proof = ChildValues::from_proof(shape, proved.proof)?;
        let root = proved.proof.stark_proof.commitments[0];
        let hash = circuit_hash_of(&proved.proof.log_sizes, &root);
        let hash = P2Hash(hash.map(|word| BaseField::from(word.value())));
        let choice = program
            .leaf_circuits
            .hashes()
            .iter()
            .position(|&leaf| leaf == hash)
            .or((hash == fold_word).then_some(MAX_LEAF_CIRCUITS));
        let output: [SecureField; 2] = proved
            .proof
            .outputs
            .clone()
            .try_into()
            .expect("a node's two output wires");
        Ok(Self {
            proof,
            output,
            preimage: proved.output.preimage_wires(),
            circuit: core::array::from_fn(|k| {
                SecureField::from(BaseField::from(u32::from(choice == Some(k))))
            }),
        })
    }
}

impl<V: Value> FoldChild<V> {
    /// The layout of a node's values over `shape`, every value zero (or no
    /// value).
    pub fn blank(shape: &ChildShape) -> Self {
        let zero = V::from_qm31(SecureField::zero());
        Self {
            proof: ChildValues::blank(shape),
            output: [zero; 2],
            preimage: [zero; preimage::WIRES],
            circuit: [zero; CIRCUITS],
        }
    }
}

impl<V: Value> FoldValues<V> {
    /// The layout of a fold's values over children of `shape`, every value
    /// zero (or no value).
    pub fn blank(shape: &ChildShape) -> Self {
        let zero = V::from_qm31(SecureField::zero());
        let child = FoldChild::blank(shape);
        Self {
            children: [child.clone(), child],
            program: [zero; PROGRAM_WIRES],
            fold_word: [zero; 2],
        }
    }
}
