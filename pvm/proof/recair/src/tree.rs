//! A run's tree, proved node by node (`proving.md` §3.4): each segment's
//! leaf, the fold of two nodes, and the wrap of the root. Every node is of
//! the padded shape.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use stwo::core::fields::qm31::SecureField;
use vos_pvm_final_verifier::{PUBLIC_WORDS, Statement, WrapProof};
use vos_pvm_proof::format::SEGMENT;
#[cfg(feature = "watch")]
use vos_pvm_proof::pcs::ProofHash;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{IdPreimage, KernelEntry, KernelProgram};
use vos_pvm_proof::shape::KernelShape;
use vos_pvm_proof::{KernelSegment, Proof, ProvingError, SideNote};

use crate::context::Finalized;
use crate::fold::{FoldCircuit, Proved};
use crate::leaf::{LeafCircuit, NodeOutput};
use crate::masked::{Drawn, drawn_in};
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
    /// A segment of the run does not prove in its program's shape.
    Segment(ProvingError),
    /// The run has no step.
    Empty,
    /// The wrap's proof does not fit its format's layout.
    Bytes,
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

/// What a run's proofs took: how many of each kind, and the time each kind
/// took in all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub segments: usize,
    pub leaves: usize,
    pub folds: usize,
    pub segments_took: Duration,
    pub leaves_took: Duration,
    pub folds_took: Duration,
    /// The wrap's, by [`prove_final`].
    pub wrap_took: Duration,
}

impl Stats {
    /// Their time in all.
    pub fn took(&self) -> Duration {
        self.segments_took + self.leaves_took + self.folds_took + self.wrap_took
    }
}

/// A proof of a run's tree as it is built, before the wrap: what never
/// leaves the prover role. Shown to a watcher only under the `watch`
/// feature, a carrier audit's (`prove_run_watched`).
pub enum Built<'a> {
    /// A segment's proof, at its position.
    Segment(&'a KernelSegment),
    /// A segment's leaf.
    Leaf(&'a Node),
    /// The fold of two nodes.
    Fold(&'a Node),
    /// The masked wrap's randomness, as it was drawn
    /// ([`crate::masked::drawn_in`]); its proof, the final one, is public.
    Wrap(&'a [Drawn]),
}

#[cfg(feature = "watch")]
impl Built<'_> {
    /// Its proof's trees' roots, in tree order: none for the wrap's.
    pub fn roots(&self) -> Vec<[u8; 32]> {
        match self {
            Self::Wrap(_) => Vec::new(),
            Self::Segment(segment) => segment
                .proof
                .stark_proof
                .commitments()
                .iter()
                .map(|root| root.to_bytes())
                .collect(),
            Self::Leaf(node) | Self::Fold(node) => node
                .proof
                .stark_proof
                .0
                .commitments
                .iter()
                .map(ProofHash::to_bytes)
                .collect(),
        }
    }

    /// Its proof's serde form, as postcard lays it out: none for the
    /// wrap's.
    pub fn encoding(&self) -> Vec<u8> {
        match self {
            Self::Wrap(_) => Ok(Vec::new()),
            Self::Segment(segment) => postcard::to_allocvec(&segment.proof),
            Self::Leaf(node) | Self::Fold(node) => postcard::to_allocvec(&node.proof),
        }
        .unwrap_or_default()
    }
}

/// The class whose budgets a run of `shape` is cut by: the first of the
/// most steps, so a run is cut in as few segments as its steps need (a
/// window its pages overflow is cut again, by `prove_kernel`).
pub fn cut_class(shape: &KernelShape) -> usize {
    shape
        .classes
        .iter()
        .enumerate()
        .max_by_key(|(class, sizes)| (sizes.log_steps, core::cmp::Reverse(*class)))
        .map_or(0, |(class, _)| class)
}

/// `run`, a whole run of `program` from `entry` to its halt (its tracer's
/// side note), proved to one root: cut by the budgets of its class of the
/// most steps (the first such), its steps and its pages, and
/// each segment proved at the first class that holds it
/// ([`vos_pvm_proof::prove_kernel`]), each verified in its class's leaf at
/// its position, and the leaves folded in adjacent pairs, an odd node
/// carried up a level. The root states the run from its entry to its
/// halt, its io-hash the run's.
pub fn prove_run(
    program: &KernelProgram,
    entry: &KernelEntry,
    run: &SideNote,
) -> Result<(Node, Stats), TreeError> {
    run_watched(program, entry, run, &mut |_| {})
}

/// [`prove_run`], each segment, leaf and fold shown to `watch` as it is
/// proved.
#[cfg(feature = "watch")]
pub fn prove_run_watched(
    program: &KernelProgram,
    entry: &KernelEntry,
    run: &SideNote,
    watch: &mut dyn FnMut(Built<'_>),
) -> Result<(Node, Stats), TreeError> {
    run_watched(program, entry, run, watch)
}

fn run_watched(
    program: &KernelProgram,
    entry: &KernelEntry,
    run: &SideNote,
    watch: &mut dyn FnMut(Built<'_>),
) -> Result<(Node, Stats), TreeError> {
    let cut = cut_class(&program.shape);
    let started = Instant::now();
    let segments = vos_pvm_proof::prove_kernel(run, &program.shape, cut, &SEGMENT)
        .map_err(TreeError::Segment)?;
    let mut stats = Stats {
        segments: segments.len(),
        segments_took: started.elapsed(),
        ..Stats::default()
    };
    let started = Instant::now();
    let id = P2Hash(program.id().0);
    let fold_word = FoldCircuit::word();
    let mut circuits = BTreeMap::new();
    let mut nodes = Vec::with_capacity(segments.len());
    for (position, segment) in segments.into_iter().enumerate() {
        watch(Built::Segment(&segment));
        let circuit = circuits
            .entry(segment.class)
            .or_insert_with(|| LeafCircuit::of_class(program, entry, segment.class));
        let node = leaf(circuit, &segment.proof, id, fold_word, position as u32)?;
        watch(Built::Leaf(&node));
        nodes.push(node);
        stats.leaves += 1;
    }
    stats.leaves_took = started.elapsed();
    let started = Instant::now();
    let preimage = program.id_preimage();
    let circuit = FoldCircuit::new();
    while nodes.len() > 1 {
        let mut level = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut pending = nodes.into_iter();
        while let Some(left) = pending.next() {
            match pending.next() {
                Some(right) => {
                    let node = fold(&circuit, &left, &right, &preimage, fold_word)?;
                    watch(Built::Fold(&node));
                    level.push(node);
                    stats.folds += 1;
                }
                None => level.push(left),
            }
        }
        nodes = level;
    }
    stats.folds_took = started.elapsed();
    let root = nodes.pop().ok_or(TreeError::Empty)?;
    Ok((root, stats))
}

/// `run`, a whole run of `program` from `entry` to its halt, proved to its
/// final proof: [`prove_run`], then the root's [`wrap()`], masked under
/// `format::MASKED_WRAP`, its bytes the format's fixed layout; and what each stage
/// took. The statement it proves is the program's id and the run's
/// io-hash.
pub fn prove_final(
    program: &KernelProgram,
    entry: &KernelEntry,
    run: &SideNote,
) -> Result<(Vec<u8>, Stats), TreeError> {
    final_watched(program, entry, run, &mut |_| {})
}

/// [`prove_final`], each segment, leaf and fold shown to `watch` as it is
/// proved ([`prove_run_watched`]), then the wrap's randomness.
#[cfg(feature = "watch")]
pub fn prove_final_watched(
    program: &KernelProgram,
    entry: &KernelEntry,
    run: &SideNote,
    watch: &mut dyn FnMut(Built<'_>),
) -> Result<(Vec<u8>, Stats), TreeError> {
    final_watched(program, entry, run, watch)
}

fn final_watched(
    program: &KernelProgram,
    entry: &KernelEntry,
    run: &SideNote,
    watch: &mut dyn FnMut(Built<'_>),
) -> Result<(Vec<u8>, Stats), TreeError> {
    let (root, mut stats) = run_watched(program, entry, run, watch)?;
    let started = Instant::now();
    let (wrapped, drawn) = drawn_in(|| wrap(&root, &program.id_preimage()));
    let (proof, ..) = wrapped?;
    watch(Built::Wrap(&drawn));
    let bytes = crate::wrap::proof_bytes(&proof).ok_or(TreeError::Bytes)?;
    stats.wrap_took = started.elapsed();
    Ok((bytes, stats))
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
/// proved masked under `format::MASKED_WRAP` ([`wrap::prove`]): its proof, the statement
/// it carries and its public words.
pub fn wrap(
    root: &Node,
    program: &IdPreimage,
) -> Result<(WrapProof, Statement, [u32; PUBLIC_WORDS]), TreeError> {
    wrap_with(root, program, wrap::prove)
}

/// [`wrap()`], proved by `prove`.
pub fn wrap_with(
    root: &Node,
    program: &IdPreimage,
    prove: impl FnOnce(&Finalized<SecureField>) -> Result<WrapProof, ProveError>,
) -> Result<(WrapProof, Statement, [u32; PUBLIC_WORDS]), TreeError> {
    let circuit = WrapCircuit::get();
    let (values, statement) = circuit.values(root.proved(), program)?;
    let finalized = circuit.finalize(&values);
    let words = wrap::public_words(&finalized);
    let proof = prove(&finalized)?;
    Ok((proof, statement, words))
}

#[cfg(test)]
mod tests {
    use vos_pvm_proof::shape::{KernelShape, SegmentClass};

    use super::cut_class;

    fn shape(classes: &[(u8, u16)]) -> KernelShape {
        KernelShape {
            components: 0,
            classes: classes
                .iter()
                .map(|&(log_steps, pages)| SegmentClass {
                    log_steps,
                    pages,
                    log_sizes: Vec::new(),
                })
                .collect(),
        }
    }

    /// A run is cut by its class of the most steps, the first such: the
    /// derivation's classes, short, 32k and short with room for an
    /// argument, cut at the 32k one.
    #[test]
    fn a_run_is_cut_by_its_class_of_the_most_steps() {
        assert_eq!(cut_class(&shape(&[(12, 8), (15, 8), (12, 24)])), 1);
        assert_eq!(cut_class(&shape(&[(15, 8), (15, 24)])), 0);
        assert_eq!(cut_class(&shape(&[(12, 8)])), 0);
        assert_eq!(cut_class(&shape(&[])), 0);
    }
}
