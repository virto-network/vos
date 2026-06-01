use stwo::{
    core::{
        ColumnVec,
        channel::{Blake2sChannel, Channel},
        fields::{m31::BaseField, qm31::SecureField},
        fri::FriConfig,
        pcs::PcsConfig,
        poly::circle::CanonicCoset,
        vcs_lifted::blake2_merkle::Blake2sMerkleChannel,
    },
    prover::{
        CommitmentSchemeProver, ComponentProver, ProvingError,
        backend::simd::SimdBackend,
        poly::{
            BitReversedOrder,
            circle::{CircleEvaluation, PolyOps},
        },
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::trace::{
    component::ComponentTrace,
    eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX},
};

// Phase 60: prove_impl uses super::active_components(side_note) instead
// of the static BASE_COMPONENTS list to skip dormant chips.
use crate::{lookups::AllLookupElements, side_note::SideNote};

pub use crate::proof::{PROOF_FORMAT_VERSION, Proof, SegmentState};

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
        let total = self.trace_gen
            + self.preprocess_commit
            + self.main_commit
            + self.interaction_gen
            + self.interaction_commit
            + self.stark_prove;
        writeln!(
            f,
            "  trace_gen:          {:>10.2?}  ({:.0}%)",
            self.trace_gen,
            pct(self.trace_gen, total)
        )?;
        writeln!(
            f,
            "  preprocess_commit:  {:>10.2?}  ({:.0}%)",
            self.preprocess_commit,
            pct(self.preprocess_commit, total)
        )?;
        writeln!(
            f,
            "  main_commit:        {:>10.2?}  ({:.0}%)",
            self.main_commit,
            pct(self.main_commit, total)
        )?;
        writeln!(
            f,
            "  interaction_gen:    {:>10.2?}  ({:.0}%)",
            self.interaction_gen,
            pct(self.interaction_gen, total)
        )?;
        writeln!(
            f,
            "  interaction_commit: {:>10.2?}  ({:.0}%)",
            self.interaction_commit,
            pct(self.interaction_commit, total)
        )?;
        writeln!(
            f,
            "  stark_prove (FRI):  {:>10.2?}  ({:.0}%)",
            self.stark_prove,
            pct(self.stark_prove, total)
        )?;
        writeln!(f, "  total:              {total:>10.2?}")?;
        writeln!(f, "  log_sizes: {:?}", self.log_sizes)?;
        writeln!(
            f,
            "  main_cols: {}, interaction_cols: {}",
            self.total_main_columns, self.total_interaction_columns
        )?;
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
        fri_config: FriConfig::new(0, 4, 19, 1),
        // Stwo v2.x lifted protocol; `None` lets `try_get_lifting_log_size`
        // default it to `log_trace_size`.  See crates/zkpvm/STWO_2.2.0_MIGRATION.md.
        lifting_log_size: None,
    }
}

/// Cap rayon's global thread pool at a sensible default for our
/// workload, unless the user has explicitly set `RAYON_NUM_THREADS`
/// or initialised their own pool.  Idempotent — safe to call many
/// times; only the first effective call wins (we use a `OnceLock`
/// guard around `ThreadPoolBuilder::build_global`).
///
/// Why cap at all?  At log14 MOBILE config on a 22-logical-core
/// desktop we measured (median of 3):
///   - default 22 threads: 2.26 s prove
///   - 10 threads:         1.83 s prove   (-19%)
///   - 8 threads:          1.88 s prove   (-17%)
/// Past ~10 threads memory-bandwidth contention overtakes parallel
/// gains.  Cap = `min(logical_cpus, 10)` matches phones (4-8 cores
/// → no cap) and keeps desktops in the sweet spot.
///
/// Returns the number of threads the pool ended up with.
pub fn install_thread_pool() -> usize {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<usize> = OnceLock::new();
    *INSTALLED.get_or_init(|| {
        // Honour explicit RAYON_NUM_THREADS — user knows best.
        if std::env::var_os("RAYON_NUM_THREADS").is_some() {
            return rayon::current_num_threads();
        }
        let logical = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let target = logical.min(10);
        // build_global panics if a pool already exists; ignore that
        // case (e.g., test harness, downstream lib that set its own).
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(target)
            .build_global();
        rayon::current_num_threads()
    })
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
        fri_config: FriConfig::new(0, 2, 38, 1),
        lifting_log_size: None,
    }
}

pub fn prove(side_note: &mut SideNote) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let (proof, _) = prove_impl(side_note, production_pcs_config(), false)?;
    Ok(proof)
}

/// Prove using the MOBILE PCS config — the recommended path for
/// latency-sensitive flows like *private tap-to-pay*.
///
/// Same 96-bit conjectured security as `prove()` but ~2× faster on
/// real PVM workloads (clerk-private-pay-bench: ~0.7 s vs ~1.4 s on
/// the reference Intel Core Ultra 7 155H).  Cost: proof size ~1.6×
/// larger.  Acceptable trade for tap-to-pay where prove time
/// dominates user experience.
///
/// Verifier-side, callers MUST use `verify_with_pcs_policy(proof,
/// side_note, &PcsPolicy::MOBILE)` (or stricter) — the default
/// `verify()` enforces the STANDARD policy and rejects MOBILE
/// proofs.
pub fn prove_mobile(side_note: &mut SideNote) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let (proof, _) = prove_impl(side_note, production_pcs_config_mobile(), false)?;
    Ok(proof)
}

pub fn prove_with_config(
    side_note: &mut SideNote,
    config: PcsConfig,
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let (proof, _) = prove_impl(side_note, config, false)?;
    Ok(proof)
}

pub fn prove_profiled(side_note: &mut SideNote) -> Result<(Proof, ProveProfile), ProvingError> {
    install_thread_pool();
    prove_impl(side_note, production_pcs_config(), true)
}

pub fn prove_profiled_with_config(
    side_note: &mut SideNote,
    config: PcsConfig,
) -> Result<(Proof, ProveProfile), ProvingError> {
    install_thread_pool();
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
    let components = crate::BASE_COMPONENTS;
    let component_names = [
        "CpuChip",
        "Blake2b",
        "MemoryChip",
        "MemBoundary",
        "RegMemory",
        "RegMemBoundary",
        "ProgBoundary",
        "ProgMemory",
        "JumpTable",
        "Range256",
        "BitwiseLookup",
        "PowerOfTwo",
        "Popcount",
        "Bitcount",
    ];

    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();

    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel);
    }

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

/// Phase I.0 debug: pinpoint the failing constraint when prove fails with
/// `ConstraintsNotSatisfied`.  Generates the same main + interaction trace
/// that `prove_with_explicit_components` would, then runs Stwo's
/// `AssertEvaluator` row-by-row and panics with `row #X, constraint #Y`
/// at the first mismatch.
#[cfg(feature = "debug-internals")]
pub fn debug_assert_constraints_explicit(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
) {
    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();

    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel);
    }

    for (i, (c, trace)) in components.iter().zip(traces.iter()).enumerate() {
        let (interaction_trace, claimed_sum) =
            c.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        eprintln!("  [{i}] asserting constraints (claimed_sum={claimed_sum:?})…");
        c.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
        eprintln!("  [{i}] all constraints OK");
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
fn compute_final_memory_commitment(
    initial_memory: &[u8],
    steps: &[crate::core::step::PvmStep],
) -> [u8; 32] {
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

fn prove_impl(
    side_note: &mut SideNote,
    config: PcsConfig,
    profile: bool,
) -> Result<(Proof, ProveProfile), ProvingError> {
    // Phase Z0: the default path always uses BASE_COMPONENTS which
    // includes `RegisterMemoryClosingChip`. Mark the side_note so the
    // ledger augmentation + FS-transcript mix engage and
    // `proof.final_state.registers` becomes a load-bearing public
    // output. Chip-isolated callers (`prove_with_explicit_components`)
    // opt-in themselves only if their slice contains the closing chip.
    side_note.closing_chip_active = true;
    // Phase 60: filter BASE_COMPONENTS to active chips for THIS trace.
    // Verifier reconstructs the same list via active_components_verifier().
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let component_mask = super::active_component_mask(side_note);
    prove_impl_with_components(side_note, config, profile, components, component_mask)
}

/// Phase I.0: chip-isolated prove path.  Bypasses `active_components` so
/// callers can pick an arbitrary component slice — used by the chip-rewrite
/// validation harness to prove a single high-bound chip + its lookup
/// closure without dragging in always-active CpuChip.  See
/// `STWO_PHASE_I_BLAKE2B.md`.  Proofs produced here have
/// `component_mask = 0` and are not verifiable via `verify_standalone`;
/// pair only with `verify_with_explicit_components`.
pub fn prove_with_explicit_components(
    side_note: &mut SideNote,
    config: PcsConfig,
    components: &[&'static dyn crate::framework::MachineProverComponent],
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let (proof, _) = prove_impl_with_components(side_note, config, false, components, 0)?;
    Ok(proof)
}

fn prove_impl_with_components(
    side_note: &mut SideNote,
    config: PcsConfig,
    profile: bool,
    components: &[&dyn crate::framework::MachineProverComponent],
    component_mask: u32,
) -> Result<(Proof, ProveProfile), ProvingError> {
    use std::time::Instant;

    // Phase 9a: backfill initial_regs from the first step's regs_before if the
    // caller left it at the default all-zero but the tracer recorded non-zero
    // initial state.  Pre-Phase-9 tests won't notice since nothing consumes
    // this yet; downstream RegisterMemoryBoundaryChip (9b) needs it populated.
    if !side_note.steps.is_empty() && side_note.initial_regs.iter().all(|&r| r == 0) {
        let first = &side_note.steps[0];
        let n = crate::core::step::NUM_REGS.min(first.regs_before.len());
        side_note.initial_regs[..n].copy_from_slice(&first.regs_before[..n]);
    }

    // Phase Z0: backfill final_regs from the last step's regs_after
    // when the closing chip is in the component set. Always overwrite
    // (not gated on all-zero like initial_regs) so a caller that
    // constructed the SideNote with stale final_regs can't accidentally
    // produce a proof whose claimed final state diverges from the
    // actual trace's last step. Skipped for chip-isolated harnesses
    // that opted out of the closing chip — those proofs leave
    // `final_regs` untouched (the field is unused without the chip).
    if side_note.closing_chip_active && !side_note.steps.is_empty() {
        let last = &side_note.steps[side_note.steps.len() - 1];
        let n = crate::core::step::NUM_REGS.min(last.regs_after.len());
        side_note.final_regs = [0u64; crate::core::step::NUM_REGS];
        side_note.final_regs[..n].copy_from_slice(&last.regs_after[..n]);
    }

    // Trace gen — split into a sequential *producer* pass and a parallel
    // *consumer* pass.  Producers (CpuChip, Blake2bChip) write per-row
    // multiplicities + entries into `side_note` while filling their main
    // trace; consumer chips (ALU/range/lookup tables, boundary chips,
    // memory ledgers, RistrettoChip, …) only read those, so they run on
    // rayon with shared `&SideNote`.  Mirrors the producer/consumer
    // split already used by interaction-trace generation a few stages
    // below.  Measured saving on log17 clerk-private-pay-bench (MOBILE):
    // ~130 ms → ~70 ms of trace_gen.
    let t = Instant::now();
    let mut traces: Vec<Option<ComponentTrace>> = (0..components.len()).map(|_| None).collect();
    for (i, c) in components.iter().enumerate() {
        if c.is_producer() {
            traces[i] = Some(c.generate_component_trace(side_note));
        }
    }
    {
        use rayon::prelude::*;
        let consumer_idxs: Vec<usize> = components
            .iter()
            .enumerate()
            .filter_map(|(i, c)| (!c.is_producer()).then_some(i))
            .collect();
        let snr: &SideNote = side_note;
        let consumer_traces: Vec<(usize, ComponentTrace)> = consumer_idxs
            .par_iter()
            .map(|&i| (i, components[i].generate_component_trace_immut(snr)))
            .collect();
        for (i, t) in consumer_traces {
            traces[i] = Some(t);
        }
    }
    let traces: Vec<ComponentTrace> = traces.into_iter().map(|x| x.unwrap()).collect();
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
    // Stwo v2.x requires polynomial coefficients to be stored — without
    // this, ComponentProver::get_evaluation_on_domain panics with "The
    // polynomial's coefficients are not stored".  The toggle costs some
    // memory but is the only supported path for our chip shape.
    commitment_scheme.set_store_polynomials_coefficients();
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

    // Phase Z0: bind `proof.initial_state.registers` and
    // `proof.final_state.registers` into the FS transcript. Mirrored
    // by the verifier; any post-prove tamper of either field shifts
    // the lookup-element challenges the verifier draws, so the
    // committed interaction trace no longer satisfies the constraint
    // system. Both are gated on `closing_chip_active` because the
    // initial-state binding ships paired with the closing chip in
    // production (BASE_COMPONENTS includes both the boundary and
    // closing chips, set together by `prove_impl`). Chip-isolated
    // harnesses that opted out leave both bindings off, matching
    // their `component_mask = 0` proof shape.
    //
    // Order is initial-then-final, deterministic and stable across
    // versions. Verifier must mix in the same order.
    if side_note.closing_chip_active {
        for r in &side_note.initial_regs {
            prover_channel.mix_u64(*r);
        }
        for r in &side_note.final_regs {
            prover_channel.mix_u64(*r);
        }
    }

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, prover_channel));

    // Interaction trace — parallelize per-chip generation across rayon
    // threads.  Each `generate_interaction_trace` call only borrows
    // `&SideNote` and `&AllLookupElements` immutably and consumes its
    // own owned `ComponentTrace`, so the bodies are independent.  Only
    // `tree_builder.extend_evals` is mutating, so we do that
    // sequentially after the parallel pass.
    //
    // Measured win at log17 clerk-private-pay-bench (MOBILE config):
    // ~140 ms → ~50–70 ms with the default thread pool cap (10
    // threads); brings total prove time from 0.71 s to ~0.62 s.
    let t = Instant::now();
    #[allow(clippy::type_complexity)]
    let interaction_results: Vec<(
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    )> = {
        use rayon::prelude::*;
        components
            .par_iter()
            .zip(traces.into_par_iter())
            .map(|(c, component_trace)| {
                c.generate_interaction_trace(component_trace, side_note, &lookup_elements)
            })
            .collect()
    };
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_interaction_columns = 0;
    let mut claimed_sums: Vec<SecureField> = Vec::with_capacity(interaction_results.len());
    for (interaction_trace, claimed_sum) in interaction_results {
        total_interaction_columns += interaction_trace.len();
        tree_builder.extend_evals(interaction_trace);
        claimed_sums.push(claimed_sum);
    }
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

    let num_components = components.len();
    let prof = ProveProfile {
        trace_gen,
        preprocess_commit,
        main_commit,
        interaction_gen,
        interaction_commit,
        stark_prove,
        log_sizes: log_sizes.clone(),
        total_main_columns,
        total_interaction_columns,
    };

    if profile {
        eprintln!("{prof}");
    }

    // Compute segment boundary states. `initial_state.registers` is
    // sourced from `side_note.initial_regs` (the same field the
    // boundary chip's main trace emits from), not `first.regs_before`,
    // so the proof field and the chip's committed values are equal
    // by construction. The Z0-init FS-transcript mix relies on this
    // invariant — if the proof field could diverge from what the chip
    // committed, the verifier would mix bytes that don't match what
    // the prover mixed and honest proofs would fail to verify.
    //
    // For non-empty traces this is equivalent to `first.regs_before`
    // because the constraint system already requires
    // `initial_regs == first.regs_before` (boundary chip producers
    // balance CpuChip first-step read consumers via the ledger).
    let initial_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
            memory_commitment: [0; 32],
        }
    } else {
        let first = &side_note.steps[0];
        SegmentState {
            pc: first.pc,
            timestamp: first.timestamp,
            registers: side_note.initial_regs,
            memory_commitment: *blake3::hash(&side_note.initial_memory).as_bytes(),
        }
    };
    let final_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
            memory_commitment: [0; 32],
        }
    } else {
        let last = &side_note.steps[side_note.steps.len() - 1];
        let mut regs = [0u64; 13];
        regs[..last.regs_after.len().min(13)]
            .copy_from_slice(&last.regs_after[..13.min(last.regs_after.len())]);
        // Final memory = initial memory with all writes applied
        // For now, hash the initial memory (full memory tracking is future work)
        SegmentState {
            pc: last.next_pc,
            timestamp: last.timestamp + 1,
            registers: regs,
            memory_commitment: compute_final_memory_commitment(
                &side_note.initial_memory,
                &side_note.steps,
            ),
        }
    };

    // Phase 60: caller supplies the bitmask (empty for chip-isolated harness).
    Ok((
        Proof {
            format_version: PROOF_FORMAT_VERSION,
            stark_proof: proof,
            claimed_sums,
            num_components,
            log_sizes,
            component_mask,
            pcs_config: config,
            initial_state,
            final_state,
        },
        prof,
    ))
}
