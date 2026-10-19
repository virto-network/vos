//! The final wrap (`proving.md` §3.5, A.3; `recursion-air.md` §7): a 1-to-1
//! node over a tree's root, proved masked under format 39 on the Blake2b-256
//! channel ([`prove`]), or unmasked under format 28, which
//! `vos-pvm-final-verifier` verifies against 24 public words
//! ([`prove_unmasked`]).
//!
//! **What it checks of the root,** a node of the padded shape (format 32), a
//! fold's or, for a run of one segment, a leaf's:
//! - its proof, verified with its output digest's two wires as the proof's
//!   outputs (the in-circuit verifier's pieces, as a fold verifies a
//!   child);
//! - **the circuit set:** its circuit hash, recomputed from its preprocessed
//!   root, is one of the program's leaf-circuit hashes or `H_fold`
//!   ([`FoldCircuit::word`], a constant): a one-hot choice. The program id's
//!   44-word preimage is a witness, the id recomputed from it, as in the
//!   fold;
//! - its 52-word preimage, a witness, re-hashed to its output digest;
//! - `preimage.W == H_fold`, `first == 0`, the entry flag 1 and the halt
//!   flag 1, and its program id the recomputed one. `last` is free.
//!
//! By induction over the folds (`fold`'s module), a root carrying `H_fold`
//! whose circuit is the fold circuit's or one of the program's leaves states
//! a run of the program's segments, joined in order, from its entry to its
//! halt.
//!
//! **Its public words,** the program id (8) and the io-hash's 16 limbs, as
//! the root's preimage carries them, sit at the wrap's addresses 0–23, one
//! word a wire (a lane of the preimage's wire, one row each), with zero, one
//! and `u` after them ([`LAYOUT`]).

use std::sync::OnceLock;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::{Blake2bMerkleChannel, Blake2bMerkleHasher};
use vos_pvm_final_verifier::{PUBLIC_WORDS, Statement, WrapProof};
use vos_pvm_proof::format::{MASKED_WRAP, ProofBytes, WRAP, lookup};
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{ID_WORDS, IdPreimage};
use vos_pvm_recair_air::gate::Layout;

use crate::context::{Context, Finalized, Var};
use crate::fold::child::ChildShape;
use crate::fold::{
    FoldChild, FoldCircuit, PROGRAM_WIRES, Proved, assert_one_of, leaf_circuit_wires, verify_node,
};
use crate::gadgets::leaf_hash;
use crate::leaf::preimage;
use crate::masked::{MaskRng, MaskStats};
use crate::prove::{ProveError, RecairProof, prove_masked_on, prove_on};
use crate::trace::MainTrace;
use crate::value::{NoValue, Value};
use crate::verifier::WitnessError;
use crate::verifier::witness::{digest_wires, pack};

/// The wrap's reserved wires: its 24 public words at 0–23, then zero, one
/// and `u`.
pub const LAYOUT: Layout = vos_pvm_final_verifier::LAYOUT;

/// The wrap circuit: its constants are the root's shape and `H_fold`.
pub struct WrapCircuit {
    pub root: &'static ChildShape,
    /// `H_fold`, the fold circuit's hash: every node's W.
    pub fold_word: P2Hash,
}

/// The values the wrap circuit guesses.
#[derive(Clone, Debug)]
pub struct WrapValues<V> {
    /// The root, as a fold guesses a child.
    pub root: FoldChild<V>,
    /// The program id's preimage, four words a wire.
    pub program: [V; PROGRAM_WIRES],
}

impl WrapCircuit {
    /// The wrap circuit, over a root of the padded shape, built once.
    pub fn get() -> &'static Self {
        static WRAP_CIRCUIT: OnceLock<WrapCircuit> = OnceLock::new();
        WRAP_CIRCUIT.get_or_init(|| Self {
            root: ChildShape::padded(),
            fold_word: FoldCircuit::word(),
        })
    }

    /// The wrap's work on `values`, in `context`: the root verified, its
    /// circuit, preimage, program and run checked, under the pieces `wrap:
    /// circuit`, `wrap: preimage`, `wrap: program` and `wrap: run`. The
    /// public words' sources, each a wire and a lane, in their order.
    pub fn verify<V: Value>(
        &self,
        context: &mut Context<V>,
        values: &WrapValues<V>,
    ) -> Vec<(Var, usize)> {
        let root = verify_node(
            context,
            self.root,
            &values.root,
            ["wrap: circuit", "wrap: preimage"],
        );

        context.piece("wrap: program");
        let program: Vec<Var> = values.program.iter().map(|&v| context.guess(v)).collect();
        let id = leaf_hash(context, &program, ID_WORDS).digest;
        for (&wire, id) in root.preimage[preimage::PROGRAM].iter().zip(id) {
            context.assert_eq(wire, id);
        }

        context.piece("wrap: circuit");
        let fold_word = digest_wires(&self.fold_word).map(|wire| context.constant(wire));
        let candidates: Vec<[Var; 2]> = leaf_circuit_wires(&program).chain([fold_word]).collect();
        assert_one_of(context, root.hash, &candidates, &root.circuit);
        for (&wire, fold_word) in root.preimage[preimage::FOLD_WORD].iter().zip(fold_word) {
            context.assert_eq(wire, fold_word);
        }

        context.piece("wrap: run");
        // `[first, last, entry, halt]`: first 0, entry 1, halt 1.
        let scalars = root.preimage[preimage::SCALARS];
        let (zero, one) = (context.zero(), context.one());
        context.assert_lane(scalars, 0, zero);
        context.assert_lane(scalars, 2, one);
        context.assert_lane(scalars, 3, one);

        context.piece("wrap: public");
        root.preimage[preimage::PROGRAM]
            .iter()
            .chain(&root.preimage[preimage::IO_HASH])
            .flat_map(|&wire| (0..4).map(move |lane| (wire, lane)))
            .collect()
    }

    /// The wrap circuit over `values`, its public words at the reserved
    /// addresses.
    pub fn build<V: Value>(&self, values: &WrapValues<V>) -> Context<V> {
        let mut context = Context::with_layout(LAYOUT);
        let lanes = self.verify(&mut context, values);
        context.set_output_lanes(&lanes);
        context
    }

    /// [`WrapCircuit::build`], finalized at its own sizes.
    ///
    /// # Panics
    /// When its wiring does not check.
    pub fn finalize<V: Value>(&self, values: &WrapValues<V>) -> Finalized<V> {
        self.build(values)
            .finalize()
            .expect("the wrap's wiring checks")
    }

    /// Its wiring, without values.
    pub fn topology(&self) -> Finalized<NoValue> {
        self.finalize(&WrapValues::blank(self.root))
    }

    /// Its preprocessed tree's root on format 28's Blake2b-256 trees: what
    /// `vos-pvm-final-verifier` pins.
    pub fn preprocessed_root(&self) -> Blake2bHash {
        crate::prove::preprocessed_root_on::<Blake2bMerkleChannel>(&WRAP, &self.topology().circuit)
            .expect("the wrap's wiring checks")
    }

    /// The values of the wrap of `root`, a valid proof of the padded shape,
    /// under the program whose id's preimage is `program`; and the statement
    /// its output carries, its program id and io-hash.
    ///
    /// # Panics
    /// When the root's proof does not verify natively.
    pub fn values(
        &self,
        root: Proved<'_>,
        program: &IdPreimage,
    ) -> Result<(WrapValues<SecureField>, Statement), WitnessError> {
        let node = FoldChild::of(self.root, root, program, self.fold_word)?;
        let words = pack(&program.words());
        let statement = Statement {
            program: root.output.program.0.map(|word| word.0),
            io_hash: root.output.io_hash,
        };
        let values = WrapValues {
            root: node,
            program: core::array::from_fn(|k| words[k]),
        };
        Ok((values, statement))
    }
}

impl<V: Value> WrapValues<V> {
    /// The layout of the wrap's values over a root of `shape`, every value
    /// zero (or no value).
    pub fn blank(shape: &ChildShape) -> Self {
        Self {
            root: FoldChild::blank(shape),
            program: [V::from_qm31(SecureField::from(BaseField::from(0))); PROGRAM_WIRES],
        }
    }
}

/// Proves a finalized wrap circuit masked under format 39, on the Blake2b-256
/// channel, from the operating system's randomness.
pub fn prove(finalized: &Finalized<SecureField>) -> Result<WrapProof, ProveError> {
    prove_masked(finalized, MaskRng::default(), |_| {}).map(|(proof, _)| proof)
}

/// [`prove`] from `rng`, with the main trace passed through `tamper` before
/// it is masked; and what the prove measured.
pub fn prove_masked(
    finalized: &Finalized<SecureField>,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MainTrace),
) -> Result<(WrapProof, MaskStats), ProveError> {
    let (proof, stats) = prove_masked_on::<Blake2bMerkleChannel>(
        &MASKED_WRAP,
        &finalized.circuit,
        &finalized.witness,
        rng,
        tamper,
    )?;
    Ok((wrap_proof(proof), stats))
}

/// Proves a finalized wrap circuit unmasked under format 28, on the
/// Blake2b-256 channel: what the tests and the fixtures verify until the
/// venues take format 39.
pub fn prove_unmasked(finalized: &Finalized<SecureField>) -> Result<WrapProof, ProveError> {
    prove_unmasked_with(finalized, |_| {})
}

/// [`prove_unmasked`], with the main trace passed through `tamper` before it
/// is committed: a seam for the refusal tests.
pub fn prove_unmasked_with(
    finalized: &Finalized<SecureField>,
    tamper: impl FnOnce(&mut MainTrace),
) -> Result<WrapProof, ProveError> {
    let proof =
        prove_on::<Blake2bMerkleChannel>(&WRAP, &finalized.circuit, &finalized.witness, tamper)?;
    Ok(wrap_proof(proof))
}

fn wrap_proof(proof: RecairProof<Blake2bMerkleHasher>) -> WrapProof {
    WrapProof {
        format_version: proof.format_version,
        log_sizes: proof.log_sizes,
        interaction_pow: proof.interaction_pow,
        claimed_sums: proof.claimed_sums,
        stark_proof: proof.stark_proof,
    }
}

/// A wrap proof's bytes as its format lays them out
/// (`vos_pvm_proof::format::Format::bytes`): format 39's fixed layout
/// (`vos_pvm_final_verifier::masked::encode`), the one encoding its
/// verifier reads, or postcard's; `None` for a format the registry does not
/// hold, or a proof its layout cannot hold.
pub fn proof_bytes(proof: &WrapProof) -> Option<Vec<u8>> {
    match lookup(proof.format_version)?.bytes {
        ProofBytes::FixedLayout => vos_pvm_final_verifier::masked::encode(proof),
        ProofBytes::Postcard => postcard::to_allocvec(proof).ok(),
    }
}

/// The public words a finalized wrap circuit's witness states.
pub fn public_words(finalized: &Finalized<SecureField>) -> [u32; PUBLIC_WORDS] {
    core::array::from_fn(|i| finalized.witness.outputs[i].to_m31_array()[0].0)
}
