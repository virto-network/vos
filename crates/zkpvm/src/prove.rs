use stwo::{
    core::{
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        fri::FriConfig,
        pcs::PcsConfig,
        poly::circle::CanonicCoset,
        vcs::blake2_merkle::Blake2sMerkleChannel,
    },
    prover::{
        backend::simd::SimdBackend, poly::circle::PolyOps, CommitmentSchemeProver, ComponentProver,
        ProvingError,
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::trace::{
    component::ComponentTrace,
    eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX},
};

use super::BASE_COMPONENTS;
use crate::{lookups::AllLookupElements, side_note::SideNote};

pub use crate::proof::{Proof, SegmentState, PROOF_FORMAT_VERSION};

/// Timing breakdown of the proving pipeline.
#[derive(Clone, Debug)]
pub struct ProveProfile {
    pub trace_gen: std::time::Duration,
    pub preprocess_commit: std::time::Duration,
    pub main_commit: std::time::Duration,
    pub interaction_gen: std::time::Duration,
    pub interaction_commit: std::time::Duration,
    pub stark_prove: std::time::Duration,
    pub log_sizes: Vec<u32>,
    pub total_main_columns: usize,
    pub total_interaction_columns: usize,
}

impl std::fmt::Display for ProveProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self.trace_gen + self.preprocess_commit + self.main_commit
            + self.interaction_gen + self.interaction_commit + self.stark_prove;
        writeln!(f, "  trace_gen:          {:>10.2?}  ({:.0}%)", self.trace_gen, pct(self.trace_gen, total))?;
        writeln!(f, "  preprocess_commit:  {:>10.2?}  ({:.0}%)", self.preprocess_commit, pct(self.preprocess_commit, total))?;
        writeln!(f, "  main_commit:        {:>10.2?}  ({:.0}%)", self.main_commit, pct(self.main_commit, total))?;
        writeln!(f, "  interaction_gen:    {:>10.2?}  ({:.0}%)", self.interaction_gen, pct(self.interaction_gen, total))?;
        writeln!(f, "  interaction_commit: {:>10.2?}  ({:.0}%)", self.interaction_commit, pct(self.interaction_commit, total))?;
        writeln!(f, "  stark_prove (FRI):  {:>10.2?}  ({:.0}%)", self.stark_prove, pct(self.stark_prove, total))?;
        writeln!(f, "  total:              {total:>10.2?}")?;
        writeln!(f, "  log_sizes: {:?}", self.log_sizes)?;
        writeln!(f, "  main_cols: {}, interaction_cols: {}", self.total_main_columns, self.total_interaction_columns)?;
        Ok(())
    }
}

fn pct(part: std::time::Duration, total: std::time::Duration) -> f64 {
    100.0 * part.as_secs_f64() / total.as_secs_f64()
}

/// 96-bit security: blowup=16, 19 FRI queries, 20-bit PoW.
///
/// Conservative shape that minimises proof size (~600 KB at log14).
/// Suitable for server-side proving where prove time is less critical
/// than the on-disk / on-chain proof footprint.
pub fn production_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 4, 19),
    }
}

/// 96-bit security: blowup=4, 38 FRI queries, 20-bit PoW.
///
/// Mobile / low-latency shape: ~2.5× faster prove than
/// `production_pcs_config()` at the cost of ~1.4× larger proof
/// (~850 KB at log14).  Same conjectured 96-bit security
/// (`pow_bits + n_queries · log_blowup_factor = 20 + 38·2 = 96`).
///
/// At log14 on a 22-core desktop: 2.10 s prove (vs 5.23 s with the
/// standard config) — fast enough to beat Nexus zkVM 2.x's 2.37 s.
/// Verifier-side, callers must use `PcsPolicy::MOBILE` (or
/// stricter) when verifying proofs produced with this config.
pub fn production_pcs_config_mobile() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 2, 38),
    }
}

pub fn prove(side_note: &mut SideNote) -> Result<Proof, ProvingError> {
    let (proof, _) = prove_impl(side_note, production_pcs_config(), false)?;
    Ok(proof)
}

pub fn prove_with_config(side_note: &mut SideNote, config: PcsConfig) -> Result<Proof, ProvingError> {
    let (proof, _) = prove_impl(side_note, config, false)?;
    Ok(proof)
}

pub fn prove_profiled(side_note: &mut SideNote) -> Result<(Proof, ProveProfile), ProvingError> {
    prove_impl(side_note, production_pcs_config(), true)
}

pub fn prove_profiled_with_config(side_note: &mut SideNote, config: PcsConfig) -> Result<(Proof, ProveProfile), ProvingError> {
    prove_impl(side_note, config, true)
}

/// Debug: print per-component claimed sums (logup) and check if they balance.
///
/// Gated behind the `debug-internals` feature — production builds
/// don't expose this.  Useful when adding a new constraint and the
/// regression sweep fails: per-component sums help distinguish
/// "ConstraintsNotSatisfied" (some chip writes a wrong column value)
/// from "claimed logup sum is not zero" (lookup imbalance — usually
/// a missing emission or wrong multiplicity).
#[cfg(feature = "debug-internals")]
pub fn debug_claimed_sums(side_note: &mut SideNote) {
    use num_traits::Zero;
    let components = BASE_COMPONENTS;
    let component_names = [
        "CpuChip", "Blake2b", "MemoryChip", "MemBoundary",
        "RegMemory", "RegMemBoundary",
        "ProgBoundary", "ProgMemory", "JumpTable",
        "Range256", "BitwiseLookup", "PowerOfTwo",
        "Popcount", "Bitcount",
    ];

    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();

    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    for c in components { c.draw_lookup_elements(&mut lookup_elements, channel); }

    let mut total = SecureField::zero();
    for (i, (c, trace)) in components.iter().zip(traces).enumerate() {
        let (_, claimed_sum) = c.generate_interaction_trace(trace, side_note, &lookup_elements);
        let name = component_names.get(i).unwrap_or(&"?");
        eprintln!("  {name:>15}: {claimed_sum:?}");
        total += claimed_sum;
    }
    eprintln!("  {:>15}: {total:?}", "total");
    if total.is_zero() {
        eprintln!("  Logup sums BALANCE (zero)");
    } else {
        eprintln!("  Logup sums DO NOT BALANCE");
    }
}

/// Compute blake3 hash of final memory state by applying all writes to
/// initial memory.
///
/// Cost: O(initial_memory.len() + Σ writes).  Allocates a full clone
/// of `initial_memory`, so for actor binaries with multi-MB memory
/// regions this dominates `prove`'s memory footprint.  Future work
/// could swap this for an in-place Merkle commitment over the byte-
/// level memory ledger (which we already build for the MemoryChip).
fn compute_final_memory_commitment(initial_memory: &[u8], steps: &[crate::core::step::PvmStep]) -> [u8; 32] {
    let mut mem = initial_memory.to_vec();
    for step in steps {
        if let Some(ref w) = step.mem_write {
            let addr = w.address as usize;
            let bytes = w.value.to_le_bytes();
            let sz = w.size as usize;
            // Grow `mem` if a write goes past the current end.  Honest
            // PvmStep entries are bounded by the interpreter's memory
            // size, so this should never fire in normal operation —
            // but trust-but-verify since `steps` is caller-supplied.
            if addr + sz > mem.len() {
                mem.resize(addr + sz, 0);
            }
            mem[addr..addr + sz].copy_from_slice(&bytes[..sz]);
        }
    }
    *blake3::hash(&mem).as_bytes()
}

fn prove_impl(side_note: &mut SideNote, config: PcsConfig, profile: bool) -> Result<(Proof, ProveProfile), ProvingError> {
    use std::time::Instant;
    let components = BASE_COMPONENTS;

    // Phase 9a: backfill initial_regs from the first step's regs_before if the
    // caller left it at the default all-zero but the tracer recorded non-zero
    // initial state.  Pre-Phase-9 tests won't notice since nothing consumes
    // this yet; downstream RegisterMemoryBoundaryChip (9b) needs it populated.
    if !side_note.steps.is_empty()
        && side_note.initial_regs.iter().all(|&r| r == 0)
    {
        let first = &side_note.steps[0];
        let n = crate::core::step::NUM_REGS.min(first.regs_before.len());
        side_note.initial_regs[..n].copy_from_slice(&first.regs_before[..n]);
    }

    let t = Instant::now();
    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();
    let log_sizes: Vec<u32> = traces.iter().map(ComponentTrace::log_size).collect();
    let trace_gen = t.elapsed();

    let max_constraint_log_degree_bound = components
        .iter()
        .zip(&log_sizes)
        .map(|(c, &log_size)| c.max_constraint_log_degree_bound(log_size))
        .max()
        .unwrap_or(0);

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut Blake2sChannel::default();

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
    log_sizes.iter().for_each(|log_size| {
        prover_channel.mix_u64(*log_size as u64);
    });

    // Preprocessed trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    for component_trace in &traces {
        tree_builder.extend_evals(component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
    }
    tree_builder.commit(prover_channel);
    let preprocess_commit = t.elapsed();

    // Main trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_main_columns = 0;
    for component_trace in &traces {
        let evals = component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX);
        total_main_columns += evals.len();
        tree_builder.extend_evals(evals);
    }
    tree_builder.commit(prover_channel);
    let main_commit = t.elapsed();

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, prover_channel));

    // Interaction trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_interaction_columns = 0;
    let claimed_sums: Vec<SecureField> = components
        .iter()
        .zip(traces)
        .map(|(c, component_trace)| {
            let (interaction_trace, claimed_sum) =
                c.generate_interaction_trace(component_trace, side_note, &lookup_elements);
            total_interaction_columns += interaction_trace.len();
            tree_builder.extend_evals(interaction_trace);
            claimed_sum
        })
        .collect();
    let interaction_gen = t.elapsed();

    let t = Instant::now();
    prover_channel.mix_felts(&claimed_sums);
    tree_builder.commit(prover_channel);
    let interaction_commit = t.elapsed();

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let components: Vec<Box<dyn ComponentProver<SimdBackend>>> = components
        .iter()
        .zip(&log_sizes)
        .zip(&claimed_sums)
        .map(|((c, log_size), claimed_sum)| {
            c.to_component_prover(
                tree_span_provider,
                &lookup_elements,
                *log_size,
                *claimed_sum,
            )
        })
        .collect();
    let components_ref: Vec<&dyn ComponentProver<SimdBackend>> =
        components.iter().map(|c| &**c).collect();

    let t = Instant::now();
    let proof = stwo::prover::prove::<SimdBackend, Blake2sMerkleChannel>(
        &components_ref,
        prover_channel,
        commitment_scheme,
    )?;
    let stark_prove = t.elapsed();

    let num_components = BASE_COMPONENTS.len();
    let prof = ProveProfile {
        trace_gen, preprocess_commit, main_commit,
        interaction_gen, interaction_commit, stark_prove,
        log_sizes: log_sizes.clone(),
        total_main_columns, total_interaction_columns,
    };

    if profile {
        eprintln!("{prof}");
    }

    // Compute segment boundary states
    let initial_state = if side_note.steps.is_empty() {
        SegmentState { pc: 0, timestamp: 0, registers: [0; 13], memory_commitment: [0; 32] }
    } else {
        let first = &side_note.steps[0];
        let mut regs = [0u64; 13];
        regs[..first.regs_before.len().min(13)].copy_from_slice(&first.regs_before[..13.min(first.regs_before.len())]);
        SegmentState {
            pc: first.pc,
            timestamp: first.timestamp,
            registers: regs,
            memory_commitment: *blake3::hash(&side_note.initial_memory).as_bytes(),
        }
    };
    let final_state = if side_note.steps.is_empty() {
        SegmentState { pc: 0, timestamp: 0, registers: [0; 13], memory_commitment: [0; 32] }
    } else {
        let last = &side_note.steps[side_note.steps.len() - 1];
        let mut regs = [0u64; 13];
        regs[..last.regs_after.len().min(13)].copy_from_slice(&last.regs_after[..13.min(last.regs_after.len())]);
        // Final memory = initial memory with all writes applied
        // For now, hash the initial memory (full memory tracking is future work)
        SegmentState {
            pc: last.next_pc,
            timestamp: last.timestamp + 1,
            registers: regs,
            memory_commitment: compute_final_memory_commitment(&side_note.initial_memory, &side_note.steps),
        }
    };

    Ok((Proof {
        format_version: PROOF_FORMAT_VERSION,
        stark_proof: proof,
        claimed_sums,
        num_components,
        log_sizes,
        pcs_config: config,
        initial_state,
        final_state,
    }, prof))
}
