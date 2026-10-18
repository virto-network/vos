//! A run's tree, proved node by node (`proving.md` §3.4): each segment's
//! leaf, the fold of two nodes, and the wrap of the root. Every node is of
//! the padded shape.

use vos_pvm_final_verifier::{PUBLIC_WORDS, Statement, WrapProof};
use vos_pvm_proof::Proof;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::IdPreimage;

use crate::fold::{FoldCircuit, Proved};
use crate::leaf::{LeafCircuit, NodeOutput};
use crate::prove::{ProveError, RecairProof};
use crate::verifier::WitnessError;
use crate::wrap::{self, WrapCircuit};

/// A node of a tree, proved: its proof and the output it states.
#[derive(Clone, Debug)]
pub struct Node {
    pub proof: RecairProof,
    pub output: NodeOutput,
}

impl Node {
    /// The node as a fold's or the wrap's child.
    pub fn proved(&self) -> Proved<'_> {
        Proved {
            proof: &self.proof,
            output: &self.output,
        }
    }
}

/// Why a node cannot be proved.
#[derive(Debug)]
pub enum TreeError {
    /// A child's or a segment's values cannot be laid out.
    Witness(WitnessError),
    /// The circuit does not prove.
    Prove(ProveError),
}

impl From<WitnessError> for TreeError {
    fn from(error: WitnessError) -> Self {
        Self::Witness(error)
    }
}

impl From<ProveError> for TreeError {
    fn from(error: ProveError) -> Self {
        Self::Prove(error)
    }
}

/// `segment`'s leaf, `circuit`, at `position` of a run of the program
/// `program` under the fold word `fold_word`, proved.
pub fn leaf(
    circuit: &LeafCircuit,
    segment: &Proof,
    program: P2Hash,
    fold_word: P2Hash,
    position: u32,
) -> Result<Node, TreeError> {
    let (values, output) = circuit.values(segment, program, fold_word, position)?;
    let finalized = circuit.finalize(&values);
    let proof = crate::prove(&finalized.circuit, &finalized.witness)?;
    Ok(Node { proof, output })
}

/// The fold of `left` and `right` under the program whose id's preimage is
/// `program` and the fold word `fold_word`, proved.
pub fn fold(
    circuit: &FoldCircuit,
    left: &Node,
    right: &Node,
    program: &IdPreimage,
    fold_word: P2Hash,
) -> Result<Node, TreeError> {
    let (values, output) = circuit.values(left.proved(), right.proved(), program, fold_word)?;
    let finalized = circuit.finalize(&values);
    let proof = crate::prove(&finalized.circuit, &finalized.witness)?;
    Ok(Node { proof, output })
}

/// The wrap of `root` under the program whose id's preimage is `program`,
/// proved: its proof, the statement it carries and its public words.
pub fn wrap(
    root: &Node,
    program: &IdPreimage,
) -> Result<(WrapProof, Statement, [u32; PUBLIC_WORDS]), TreeError> {
    let circuit = WrapCircuit::get();
    let (values, statement) = circuit.values(root.proved(), program)?;
    let finalized = circuit.finalize(&values);
    let words = wrap::public_words(&finalized);
    let proof = wrap::prove(&finalized)?;
    Ok((proof, statement, words))
}
