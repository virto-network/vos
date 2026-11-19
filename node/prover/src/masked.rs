//! The production prover: a kernel's run re-traced on its record's witness
//! and checked against the record, then proved segment by segment, each
//! segment verified in its class's leaf, the leaves folded to one root, and
//! the root wrapped masked under `format::MASKED_WRAP` (`proving.md` §5).
//!
//! The kernel's program id is recomputed from its blob alone: its shape
//! from its code, its image root from its memory, each class's
//! preprocessed root and leaf circuit from both. An id is never taken from
//! the record or from another node.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vos_abi::Decode;
use vos_abi::ids::{MethodId, ProgramHash};
use vos_abi::records::Kernel;
use vos_abi::result::{Attest, KernelReturn};
use vos_pvm_proof::core::step::CompactStep;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTrace, KernelTraceError, trace_kernel};
use vos_pvm_proof::program_id::{KernelEntry, KernelProgram};
use vos_pvm_proof::shape::KernelShape;
use vos_pvm_proof::{KernelPlan, SegmentError, SideNote};
use vos_pvm_recair::tree::{Stats, TreeError};
use vos_venue::vos_statement::ProgramId;

use crate::RERUN_GAS;
#[cfg(feature = "disclosing")]
use crate::internals::{Internals, NodeProof};
use crate::worker::{Prover, StatementError};

/// A kernel's program and its run's entry, recomputed from its blob.
type Program = Arc<(KernelProgram, KernelEntry)>;

/// The masked prover, its kernels' programs computed once each.
#[derive(Default)]
pub struct MaskedProver {
    programs: Mutex<HashMap<ProgramHash, Program>>,
}

/// The install's record of `blob`, a kernel, recomputed from it: its hash,
/// its shape from its code and its image root.
pub fn kernel_record(blob: &[u8]) -> Result<Kernel, &'static str> {
    let shape = vos_pvm_compiler::shape::kernel_shape(blob).ok_or("not a kernel's program")?;
    let image_root = vos_pvm_program::parse_standard_program(blob)
        .and_then(|program| program.image_root())
        .ok_or("not a standard program")?;
    Ok(Kernel {
        method: MethodId(0),
        program: ProgramHash::of(blob),
        image_root,
        shape,
    })
}

impl MaskedProver {
    pub fn new() -> Self {
        Self::default()
    }

    /// `kernel`'s program and entry, from its blob.
    fn kernel(&self, kernel: &[u8]) -> Result<Program, StatementError> {
        let hash = ProgramHash::of(kernel);
        if let Some(program) = self.programs().get(&hash) {
            return Ok(Arc::clone(program));
        }
        let record = kernel_record(kernel).map_err(StatementError::Kernel)?;
        let program = vos_pvm_recair::leaf::kernel_program(
            kernel,
            &record,
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .map_err(|error| StatementError::Kernel(error.reason()))?;
        let program = Arc::new(program);
        self.programs().insert(hash, Arc::clone(&program));
        Ok(program)
    }

    /// The kernels whose programs it computed so far.
    pub fn computed(&self) -> usize {
        self.programs().len()
    }

    fn programs(&self) -> std::sync::MutexGuard<'_, HashMap<ProgramHash, Program>> {
        lock(&self.programs)
    }

    /// `kernel` re-run on `attest`'s witness: its trace, when the run reads
    /// the witness whole and returns the record's public arguments, output
    /// and roots, its io-hash theirs. A kernel of no public part returns its
    /// output alone, so its record has none.
    pub fn rerun(&self, kernel: &[u8], attest: &Attest) -> Result<KernelTrace, StatementError> {
        let trace = trace_kernel(kernel, &attest.witness_input, RERUN_GAS)
            .map_err(|error| not_rerun(&error))?;
        let parts = KernelReturn {
            public_args: attest.public_args.clone(),
            output: attest.output.clone(),
            roots: attest.roots.clone(),
        };
        let returned = match KernelReturn::decode_exact(&trace.output) {
            Some(returned) => returned == parts,
            None => {
                parts.public_args.is_empty()
                    && parts.roots.is_empty()
                    && trace.output == parts.output
            }
        };
        if !returned {
            return Err(StatementError::Rerun(
                "the re-run returns other public arguments, output or roots than the record's",
            ));
        }
        if trace.io_hash != parts.io_hash() {
            return Err(StatementError::Rerun(
                "the re-run's io-hash is not the record's",
            ));
        }
        let read: usize = trace.reads.iter().map(|read| read.count).sum();
        if read != attest.witness_input.len() {
            return Err(StatementError::Rerun(
                "the re-run does not read the witness whole",
            ));
        }
        Ok(trace)
    }

    /// [`Prover::prove`], and the internals it built the proof from, which
    /// never leave the prover role: what a carrier audit looks for.
    #[cfg(feature = "disclosing")]
    pub fn prove_disclosing(
        &self,
        kernel: &[u8],
        attest: &Attest,
    ) -> Result<(Vec<u8>, Internals), StatementError> {
        use vos_pvm_recair::tree::Built;
        let public_root = kernel_record(kernel)
            .map_err(StatementError::Kernel)?
            .image_root;
        let mut internals = Internals::default();
        let mut lengths: Vec<u64> = Vec::new();
        let (mut leaves, mut folds) = (0, 0);
        let mut watch = |built: Built<'_>| {
            let (name, digests) = match &built {
                Built::Wrap(drawn) => {
                    internals.wrap_randomness.extend(
                        drawn
                            .iter()
                            .map(|drawn| (drawn.what.to_string(), drawn.bytes.clone())),
                    );
                    return;
                }
                Built::Segment(segment) => {
                    let (first, last) = segment.steps;
                    lengths.push((last - first) as u64);
                    for state in [&segment.proof.initial_state, &segment.proof.final_state] {
                        internals.steps.push(state.timestamp);
                        internals.registers.push(state.registers);
                        let root = state.memory_root;
                        if root != public_root && root != [0; 32] {
                            internals.memory_roots.push(root);
                        }
                    }
                    (format!("segment {}", lengths.len() - 1), Vec::new())
                }
                Built::Leaf(node) | Built::Fold(node) => {
                    let name = if matches!(built, Built::Leaf(_)) {
                        leaves += 1;
                        format!("leaf {}", leaves - 1)
                    } else {
                        folds += 1;
                        format!("fold {}", folds - 1)
                    };
                    let digests = vec![
                        node.output.entry_digest.to_bytes(),
                        node.output.exit_digest.to_bytes(),
                    ];
                    (name, digests)
                }
            };
            internals.proofs.push(NodeProof {
                name,
                roots: built.roots(),
                encoding: built.encoding(),
                digests,
            });
        };
        let (proof, _) = self.proved(kernel, attest, |program, entry, run| {
            vos_pvm_recair::tree::prove_final_watched(program, entry, run, &mut watch)
        })?;
        internals.run_steps = lengths.iter().sum();
        internals.steps.extend(lengths);
        Ok((proof, internals))
    }

    /// `kernel` re-run on `attest`'s witness, its run planned ([`plan`]),
    /// and proved by `prove`: a run the plan shows past what its gas buys
    /// is refused before the kernel's program is computed or anything
    /// proved. The prover plans the run again as it proves, and refuses
    /// it too should a window its pages overflow be cut past the bound.
    fn proved(
        &self,
        kernel: &[u8],
        attest: &Attest,
        prove: impl FnOnce(
            &KernelProgram,
            &KernelEntry,
            &SideNote<CompactStep>,
        ) -> Result<(Vec<u8>, Stats), TreeError>,
    ) -> Result<(Vec<u8>, Stats), StatementError> {
        let trace = self.rerun(kernel, attest)?;
        plan(kernel, &trace.side_note)?;
        let program = self.kernel(kernel)?;
        let (program, entry) = &*program;
        prove(program, entry, &trace.side_note).map_err(|error| match error {
            TreeError::Segment(error) => not_proved(&error),
            // The run does not fit its kernel's shape: no proof of it can
            // be made.
            TreeError::Empty => StatementError::Kernel("the run does not fit its kernel's shape"),
            error @ (TreeError::Witness(_) | TreeError::Prove(_) | TreeError::Bytes) => {
                StatementError::Failed(failed(&error))
            }
        })
    }
}

/// The price of a statement's proof, and its bound: the attest that made
/// the record paid `price::ATTEST` and its kernel's gas, which buy the
/// run's first segment and one more for each
/// [`vos_pvm_proof::SEGMENT_GAS`] of the gas
/// ([`vos_pvm_proof::max_segments`]). `kernel`'s run `run` is planned
/// ([`vos_pvm_proof::plan_kernel`], cut by its class of the most steps, as
/// the prover first cuts it) before anything is proved: its segments, or a
/// refusal for good of a run that takes more than its gas buys, or more
/// steps than a proof orders. Planning traces nothing; it builds each
/// window's side note and page multiproof, which the prover builds again.
pub fn plan(kernel: &[u8], run: &SideNote<CompactStep>) -> Result<KernelPlan, StatementError> {
    let record = kernel_record(kernel).map_err(StatementError::Kernel)?;
    let shape = KernelShape::try_from(&record.shape)
        .map_err(|error| StatementError::Kernel(error.reason()))?;
    vos_pvm_proof::plan_kernel(run, &shape, vos_pvm_recair::tree::cut_class(&shape))
        .map_err(|error| not_proved(&error))
}

/// Why a run's segments do not prove, by the prover's refusal: a run its
/// kernel's shape or its gas cannot hold, refused for good, or the prover's
/// own failure, tried again.
fn not_proved(error: &SegmentError) -> StatementError {
    use StatementError::{Bound, Failed, Kernel};
    match error {
        SegmentError::Shape { .. } | SegmentError::MalformedShape => {
            Kernel("the run does not fit its kernel's shape")
        }
        SegmentError::Transfer => Kernel("the kernel transfers to the halt address"),
        SegmentError::Segments => Bound("the run takes more segments than its gas buys"),
        SegmentError::RunLength => Bound("the run is past a proof's steps"),
        SegmentError::Stwo(_) => Failed("a segment does not prove"),
        SegmentError::FormatNotAdmitted(_) => Failed("the segment format is not admitted"),
        SegmentError::NoMemoryLayout => Failed("a segment has no memory layout"),
    }
}

/// Why a kernel does not re-run on a record's witness, by the tracer's
/// refusal alone: a kernel no proof of which can be made, a witness that is
/// not the record's run, or the host's own failure, tried again.
fn not_rerun(error: &KernelTraceError) -> StatementError {
    use StatementError::{Failed, Kernel, Rerun};
    match error {
        KernelTraceError::Program => Kernel("the kernel is not a standard program"),
        KernelTraceError::NotCanonical => {
            Kernel("the kernel's blob is not its program's one encoding")
        }
        KernelTraceError::Code => Kernel("the kernel's code is past a proof's program memory"),
        KernelTraceError::Transfer => Kernel("the kernel transfers to no basic block start"),
        KernelTraceError::Input => Rerun("the witness is past a witness input's cap"),
        KernelTraceError::Exit => Rerun("the kernel does not halt on the witness"),
        KernelTraceError::Output => Rerun("the kernel's output is not readable"),
        KernelTraceError::Unread => Rerun("the kernel reads less than the witness"),
        KernelTraceError::Steps => {
            StatementError::Bound("the kernel's run is past a proof's steps")
        }
        KernelTraceError::Allocation => Failed("the kernel's output could not be allocated"),
    }
}

/// `mutex`, locked, as a holder that panicked left it.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What failed, and nothing of the values it failed on: an error's `Debug`
/// may hold a run's.
fn failed(error: &TreeError) -> &'static str {
    match error {
        TreeError::Witness(_) => "a node's values do not lay out",
        TreeError::Prove(_) => "a node's circuit does not prove",
        TreeError::Segment(_) => "a segment does not prove",
        TreeError::Empty => "the run has no step",
        TreeError::Bytes => "the wrap does not fit its format's layout",
    }
}

impl Prover for MaskedProver {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, StatementError> {
        let program = self.kernel(kernel)?;
        Ok(program.0.id())
    }

    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, StatementError> {
        self.proved(kernel, attest, vos_pvm_recair::tree::prove_final)
            .map(|(bytes, _)| bytes)
    }
}

/// The masked prover, keeping each statement's record and the internals it
/// built the proof from: a carrier audit's prover, which knows what no
/// carrier may hold.
#[cfg(feature = "disclosing")]
#[derive(Default)]
pub struct Disclosing {
    masked: MaskedProver,
    made: Mutex<Vec<(Attest, Internals)>>,
}

#[cfg(feature = "disclosing")]
impl Disclosing {
    /// Every statement proved so far: its record and its proof's internals.
    pub fn made(&self) -> Vec<(Attest, Internals)> {
        lock(&self.made).clone()
    }
}

#[cfg(feature = "disclosing")]
impl Prover for Disclosing {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, StatementError> {
        self.masked.program(kernel)
    }

    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, StatementError> {
        let (proof, internals) = self.masked.prove_disclosing(kernel, attest)?;
        lock(&self.made).push((attest.clone(), internals));
        Ok(proof)
    }
}
