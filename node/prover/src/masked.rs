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

use vos_pvm_proof::SideNote;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTrace, trace_kernel};
use vos_pvm_proof::program_id::{KernelEntry, KernelProgram};
use vos_pvm_recair::tree::{Stats, TreeError};
use vos_venue::vos_statement::ProgramId;
use vos_wire::Decode;
use vos_wire::ids::{MethodId, ProgramHash};
use vos_wire::records::Kernel;
use vos_wire::result::{Attest, KernelReturn};

#[cfg(feature = "disclosing")]
use crate::internals::{Internals, NodeProof};
use crate::worker::{ProveError, Prover};

/// The gas a re-run is given: a kernel's own limit bounds the live run
/// whose record it repeats, so this bounds nothing an honest record needs.
const RERUN_GAS: u64 = 1 << 32;

/// A kernel's program and its run's entry, recomputed from its blob.
type Program = Arc<(KernelProgram, KernelEntry)>;

/// The masked prover, its kernels' programs computed once each.
#[derive(Default)]
pub struct MaskedProver {
    programs: Mutex<HashMap<ProgramHash, Program>>,
}

/// The install's record of `blob`, a kernel, recomputed from it: its hash,
/// its shape from its code and its image root.
pub fn kernel_record(blob: &[u8]) -> Result<Kernel, String> {
    let shape = vos_pvm_compiler::shape::kernel_shape(blob)
        .ok_or_else(|| String::from("not a kernel's program"))?;
    let image_root = vos_pvm_program::parse_standard_program(blob)
        .and_then(|program| program.image_root())
        .ok_or_else(|| String::from("not a standard program"))?;
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
    fn kernel(&self, kernel: &[u8]) -> Result<Program, ProveError> {
        let hash = ProgramHash::of(kernel);
        if let Some(program) = self.lock().get(&hash) {
            return Ok(Arc::clone(program));
        }
        let record = kernel_record(kernel).map_err(ProveError::Kernel)?;
        let program = vos_pvm_recair::leaf::kernel_program(
            kernel,
            &record,
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .map_err(ProveError::Kernel)?;
        let program = Arc::new(program);
        self.lock().insert(hash, Arc::clone(&program));
        Ok(program)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ProgramHash, Program>> {
        self.programs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `kernel` re-run on `attest`'s witness: its trace, when the run reads
    /// the witness whole and returns the record's public arguments, output
    /// and roots, its io-hash theirs. A kernel of no public part returns its
    /// output alone, so its record has none.
    pub fn rerun(&self, kernel: &[u8], attest: &Attest) -> Result<KernelTrace, ProveError> {
        let trace = trace_kernel(kernel, &attest.witness_input, RERUN_GAS)
            .map_err(|error| ProveError::Rerun(format!("the kernel does not re-run: {error:?}")))?;
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
            return Err(ProveError::Rerun(
                "the re-run returns other public arguments, output or roots than the record's"
                    .into(),
            ));
        }
        if trace.io_hash != parts.io_hash() {
            return Err(ProveError::Rerun(
                "the re-run's io-hash is not the record's".into(),
            ));
        }
        let read: usize = trace.reads.iter().map(|read| read.count).sum();
        if read != attest.witness_input.len() {
            return Err(ProveError::Rerun(format!(
                "the re-run reads {read} of the witness's {} bytes",
                attest.witness_input.len()
            )));
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
    ) -> Result<(Vec<u8>, Internals), ProveError> {
        use vos_pvm_recair::tree::Built;
        let public_root = kernel_record(kernel)
            .map_err(ProveError::Kernel)?
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
                        for root in [state.memory_root, state.memory_commitment] {
                            if root != public_root && root != [0; 32] {
                                internals.memory_roots.push(root);
                            }
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

    /// `kernel` re-run on `attest`'s witness and its run proved by `prove`.
    fn proved(
        &self,
        kernel: &[u8],
        attest: &Attest,
        prove: impl FnOnce(
            &KernelProgram,
            &KernelEntry,
            &SideNote,
        ) -> Result<(Vec<u8>, Stats), TreeError>,
    ) -> Result<(Vec<u8>, Stats), ProveError> {
        let program = self.kernel(kernel)?;
        let (program, entry) = &*program;
        let trace = self.rerun(kernel, attest)?;
        prove(program, entry, &trace.side_note).map_err(|error| {
            use vos_pvm_proof::ProvingError;
            match error {
                // The run does not fit its kernel's shape: no proof of it
                // can be made.
                TreeError::Empty
                | TreeError::Segment(ProvingError::Shape { .. } | ProvingError::MalformedShape) => {
                    ProveError::Kernel(format!("{error:?}"))
                }
                error => ProveError::Failed(failed(&error).into()),
            }
        })
    }
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
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError> {
        let program = self.kernel(kernel)?;
        Ok(ProgramId(program.0.id().words()))
    }

    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
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
        self.made
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[cfg(feature = "disclosing")]
impl Prover for Disclosing {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError> {
        self.masked.program(kernel)
    }

    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        let (proof, internals) = self.masked.prove_disclosing(kernel, attest)?;
        self.made
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((attest.clone(), internals));
        Ok(proof)
    }
}
