use stwo::{
    core::{
        ColumnVec,
        channel::Channel,
        fields::{m31::BaseField, qm31::SecureField},
        fri::FriConfig,
        pcs::PcsConfig,
        poly::circle::CanonicCoset,
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

use crate::recursion_pcs::{ProverBackend, ProverChannel, ProverMerkleChannel, for_commit};

use crate::trace::{
    component::ComponentTrace,
    eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX},
};

// prove_impl uses super::active_components(side_note) instead
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
/// real PVM workloads (a ristretto-heavy workload: ~0.7 s vs ~1.4 s on
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
///
/// Returns `true` iff the total logup sum is zero (the trace would pass the
/// verifier's "claimed logup sum is not zero" check). Callers that only want
/// the printout can ignore the result.
#[cfg(feature = "debug-internals")]
pub fn debug_claimed_sums(side_note: &mut SideNote) -> bool {
    use num_traits::Zero;
    let components = crate::BASE_COMPONENTS;
    // Aligned 1:1 with `BASE_COMPONENTS` (lib.rs). The previous list stopped
    // at 14 names AND skipped `RegMemClosing`, so every label from index 6 on
    // was wrong — fixed here so the per-component breakdown is trustworthy.
    let component_names = [
        "CpuChip",
        "Blake2b",
        "Blake2bBoundary",
        "MemoryChip",
        "MemoryPage",
        "MemoryMerkle",
        "MemoryRootBoundary",
        "RegMemory",
        "RegMemBoundary",
        "RegMemClosing",
        "ProgBoundary",
        "ProgMemory",
        "JumpTable",
        "Range256",
        "BitwiseLookup",
        "PowerOfTwo",
        "Popcount",
        "Bitcount",
        "ByteToBits",
        "Mul",
        "Bitwise",
        "Compare",
        "DivRem",
        "Ristretto",
        "RistrettoEcall",
        "RistCombTable",
        "RistFixedBaseConsumer",
        "RistCombAnchor",
        "RistCombScalarBoundary",
        "RistCombCompress",
        "RistCombCompressOutput",
    ];

    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(side_note))
        .collect();

    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut ProverChannel::default();
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
    let balances = total.is_zero();
    if balances {
        eprintln!("  Logup sums BALANCE (zero)");
    } else {
        eprintln!("  Logup sums DO NOT BALANCE");
    }
    balances
}

/// Debug: pinpoint the failing constraint when prove fails with
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
    let channel = &mut ProverChannel::default();
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

/// Memory-frugal variant of [`debug_assert_constraints_explicit`] for traces
/// too large to materialise every component trace at once (the explicit
/// version's `traces: Vec<ComponentTrace>` holds them all and OOMs on
/// multi-million-step actor traces).
///
/// Builds + asserts **one component at a time**, dropping each trace before
/// the next, so peak memory is the single largest chip's trace rather than
/// the sum across all chips. Mirrors `prove_impl_with_components`'s
/// producer/consumer split: the `is_producer()` chips run first
/// (sequentially — they mutate `side_note`'s lookup-multiplicity counts),
/// then the consumer chips read the now-complete counts via the immutable
/// trace-gen path. Per-chip `debug_assert_constraints` is self-contained (it
/// checks each chip's own constraints + logup against that chip's own
/// `claimed_sum`), so the cross-chip lookup balance isn't needed here — only
/// the per-chip constraint satisfaction, which is exactly what catches a
/// `ConstraintsNotSatisfied`.
#[cfg(feature = "debug-internals")]
pub fn debug_assert_constraints_streaming(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
) {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut ProverChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel);
    }

    // Pass 1 — PRODUCERS (sequential, mutate counts → must complete before
    // any consumer trace is built).
    for (i, c) in components.iter().enumerate() {
        if !c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace(side_note);
        let (interaction_trace, claimed_sum) =
            c.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        eprintln!("  [{i}] producer: asserting (claimed_sum={claimed_sum:?})…");
        c.debug_assert_constraints(&trace, &interaction_trace, &lookup_elements, claimed_sum);
        eprintln!("  [{i}] producer: OK");
    }

    // Pass 2 — CONSUMERS (read complete counts; no mutation).
    for (i, c) in components.iter().enumerate() {
        if c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace_immut(side_note);
        let (interaction_trace, claimed_sum) =
            c.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        eprintln!("  [{i}] consumer: asserting (claimed_sum={claimed_sum:?})…");
        c.debug_assert_constraints(&trace, &interaction_trace, &lookup_elements, claimed_sum);
        eprintln!("  [{i}] consumer: OK");
    }
}

/// Memory-frugal variant of [`debug_claimed_sums`]: accumulate the GLOBAL
/// logup claimed-sum one component at a time (dropping each trace before the
/// next), so a multi-million-step trace whose component traces can't all be
/// materialised at once still gets a balance verdict. Mirrors
/// [`debug_assert_constraints_streaming`]'s producer-then-consumer ordering
/// (producers mutate the lookup-multiplicity counts the consumers read).
///
/// Returns `true` iff the total is zero — i.e. the trace would pass the
/// verifier's "claimed logup sum is not zero" check. Lets us answer "does the
/// FULL trace balance?" (→ a segment imbalance is a boundary artifact) vs.
/// "does it not?" (→ a real per-chip bug in some region) without OOM.
#[cfg(feature = "debug-internals")]
pub fn debug_claimed_sums_streaming(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
) -> bool {
    use num_traits::Zero;
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut ProverChannel::default();
    for c in components {
        c.draw_lookup_elements(&mut lookup_elements, channel);
    }

    let mut total = SecureField::zero();
    // Pass 1 — PRODUCERS (sequential, mutate counts → must complete before
    // any consumer trace is built).
    for (i, c) in components.iter().enumerate() {
        if !c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace(side_note);
        let (_it, claimed_sum) = c.generate_interaction_trace(trace, side_note, &lookup_elements);
        eprintln!("  [{i}] producer: claimed_sum={claimed_sum:?}");
        total += claimed_sum;
    }
    // Pass 2 — CONSUMERS (read complete counts; no mutation).
    for (i, c) in components.iter().enumerate() {
        if c.is_producer() {
            continue;
        }
        let trace = c.generate_component_trace_immut(side_note);
        let (_it, claimed_sum) = c.generate_interaction_trace(trace, side_note, &lookup_elements);
        eprintln!("  [{i}] consumer: claimed_sum={claimed_sum:?}");
        total += claimed_sum;
    }
    eprintln!("  total: {total:?}");
    let balances = total.is_zero();
    eprintln!(
        "  full-trace logup {}",
        if balances {
            "BALANCES (zero)"
        } else {
            "DOES NOT BALANCE"
        }
    );
    balances
}

/// Compute blake3 hash of final memory state by applying all writes to
/// initial memory.
///
/// Cost: O(initial_memory.len() + Σ writes).  Allocates a full clone
/// of `initial_memory`, so for actor binaries with multi-MB memory
/// regions this dominates `prove`'s memory footprint.  Future work
/// could swap this for an in-place Merkle commitment over the byte-
/// level memory ledger (which we already build for the MemoryChip).
/// The entering / exit RAM page-Merkle roots for this segment, from
/// the ingested page payload.  Falls back to the all-zero root only on the
/// never-proved empty path (no payload).
fn segment_memory_roots(side_note: &SideNote) -> ([u8; 32], [u8; 32]) {
    match &side_note.memory_pages {
        Some(p) => (p.multiproof.root_before, p.multiproof.root_after),
        None => ([0u8; 32], [0u8; 32]),
    }
}

fn compute_final_memory_commitment(side_note: &SideNote) -> [u8; 32] {
    // Replay ALL of this (segment's) writes — regular stores AND precompile
    // output writes (blake2b / ristretto / scalar-*, which live in
    // `*_mem_ops`, not `step.mem_write`) — over the initial memory. Using
    // step writes alone leaves precompile-output bytes stale, so a downstream
    // segment's initial-memory commitment (which DOES reflect those writes,
    // via `segment::replay_writes`) would mismatch and `verify_chain`'s
    // boundary-continuity check would reject. `ts_upper = None` ⇒ all writes.
    let mem = crate::segment::replay_writes(side_note, None);
    *blake3::hash(&mem).as_bytes()
}

/// Normalize a `SideNote` the way the production prove path does before
/// trace generation: activate the closing chip (ledger augmentation +
/// FS-transcript mix + component selection all key off it) and backfill
/// the initial/final register images from the trace.
///
/// Verification paths that RE-DERIVE a side note — e.g. re-slicing a
/// segment of a fully-traced run to check a proof chain — MUST apply the
/// same normalization before calling `verify`/`verify_with_pcs_policy`,
/// or the verifier's Fiat-Shamir transcript diverges from the prover's
/// and honest proofs fail with `OodsNotMatching`. `prove` applies it
/// itself; calling this twice is idempotent.
pub fn prepare_side_note_for_verification(side_note: &mut SideNote) {
    // The default path always uses BASE_COMPONENTS which
    // includes `RegisterMemoryClosingChip`. Mark the side_note so the
    // ledger augmentation + FS-transcript mix engage and
    // `proof.final_state.registers` becomes a load-bearing public
    // output. Chip-isolated callers (`prove_with_explicit_components`)
    // opt-in themselves only if their slice contains the closing chip.
    side_note.closing_chip_active = true;
    backfill_initial_regs(side_note);
    backfill_final_regs(side_note);
}

/// Backfill `initial_regs` from the first step's `regs_before` if the
/// caller left it at the default all-zero but the tracer recorded
/// non-zero initial state (segment slicers set it explicitly).
fn backfill_initial_regs(side_note: &mut SideNote) {
    if !side_note.steps.is_empty() && side_note.initial_regs.iter().all(|&r| r == 0) {
        let first = &side_note.steps[0];
        let n = crate::core::step::NUM_REGS.min(first.regs_before.len());
        side_note.initial_regs[..n].copy_from_slice(&first.regs_before[..n]);
    }
}

/// Backfill `final_regs` from the last step's `regs_after`. Always
/// overwrites (not gated on all-zero like `initial_regs`) so a stale
/// value can never ship as the claimed final state.
fn backfill_final_regs(side_note: &mut SideNote) {
    if !side_note.steps.is_empty() {
        let last = &side_note.steps[side_note.steps.len() - 1];
        let n = crate::core::step::NUM_REGS.min(last.regs_after.len());
        side_note.final_regs = [0u64; crate::core::step::NUM_REGS];
        side_note.final_regs[..n].copy_from_slice(&last.regs_after[..n]);
    }
}

fn prove_impl(
    side_note: &mut SideNote,
    config: PcsConfig,
    profile: bool,
) -> Result<(Proof, ProveProfile), ProvingError> {
    prepare_side_note_for_verification(side_note);
    // Filter BASE_COMPONENTS to active chips for THIS trace.
    // Verifier reconstructs the same list via active_components_verifier().
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let component_mask = super::active_component_mask(side_note);
    prove_impl_with_components(side_note, config, profile, components, component_mask, &[])
}

/// Chip-isolated prove path.  Bypasses `active_components` so
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
    let (proof, _) = prove_impl_with_components(side_note, config, false, components, 0, &[])?;
    Ok(proof)
}

/// Canonical-shape proving (federation wire-through W0).
///
/// Proves with the FULL `BASE_COMPONENTS` set present (constant
/// `component_mask`, all 31 bits) and every forcing-set chip's main trace
/// padded up to the per-chip floor in `min_log_sizes` (indexed by
/// [`chip_idx`](crate::chip_idx)), so the preprocessed-trace commitment —
/// the program identity — is identical for every segment of a program
/// regardless of the witness.  That is what lets ONE published program
/// commitment pin a whole *heterogeneous* segment chain via
/// `verify_chain_standalone`: the per-segment active set is constant (full
/// mask) and the preprocessed-bearing chips' `log_size`s are pinned.
///
/// Uses the MOBILE PCS config (the federation policy — verifiers must use
/// `PcsPolicy::MOBILE`).  `min_log_sizes` shorter than the component count
/// is zero-padded; a 0 floor means "natural size" (the fixed-table chips,
/// already uniform, need no floor).  Forced sizes MUST stay `<=
/// DEFAULT_MAX_LOG_SIZE` (24) or the verifier rejects.
pub fn prove_canonical(
    side_note: &mut SideNote,
    min_log_sizes: &[u32],
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    prepare_side_note_for_verification(side_note);
    let components = super::all_components();
    // Full set present ⇒ constant mask = all 31 component bits set.
    let component_mask = (1u32 << super::chip_idx::COUNT) - 1;
    let (proof, _) = prove_impl_with_components_overridden(
        side_note,
        production_pcs_config_mobile(),
        false,
        components,
        component_mask,
        None,
        min_log_sizes,
    )?;
    Ok(proof)
}

/// Canonical-shape profiling (federation wire-through W0): the NATURAL
/// (unforced) main-trace `log_size` each of the given components would use for
/// `side_note`. The per-segment max of these over a full trace is the
/// `min_log_size` profile `prove_canonical` pads to (so every segment's forced
/// chips share one `log_size`). Mirrors `prove`'s trace-gen prep (`prepare` +
/// `ingest_memory_pages`, so page/merkle-bearing chips report their real size)
/// but stops at `log_size` — no commit, no FRI. `indices` are positions in
/// [`all_components`](crate::all_components) / [`chip_idx`](crate::chip_idx).
pub fn natural_log_sizes_for(side_note: &mut SideNote, indices: &[usize]) -> Vec<u32> {
    prepare_side_note_for_verification(side_note);
    side_note.ingest_memory_pages();
    let comps = super::all_components();
    indices
        .iter()
        .map(|&i| {
            let c = comps[i];
            let trace = if c.is_producer() {
                c.generate_component_trace(side_note)
            } else {
                c.generate_component_trace_immut(side_note)
            };
            trace.log_size()
        })
        .collect()
}

/// The canonical forcing profile for `seg_steps`-step windows of `full`: the
/// per-chip elementwise MAX of every window's natural main-trace `log_size`
/// (via [`natural_log_sizes_for`]) — the `min_log_sizes` under which
/// [`prove_canonical`] gives all of a chain's windows an identical shape.
/// Chips whose size is already uniform get their own size back (forcing is a
/// no-op); varying chips get the chain-wide max, so the windows collapse onto
/// the minimal canonical-shape set (distinct shapes remain only where content
/// differs beyond size, e.g. fixed-base-comb call count). The floors are the
/// observed per-window maxima for THIS trace's op pattern, not a proven
/// bound — a deployment's drift guard + allowlist-coverage gate catch a
/// reshaped transition. `None` when the trace is empty, `seg_steps` is zero,
/// or any floor exceeds [`DEFAULT_MAX_LOG_SIZE`](crate::DEFAULT_MAX_LOG_SIZE)
/// (such a profile could only ever produce verifier-rejected proofs).
pub fn canonical_profile_for(full: &SideNote, seg_steps: usize) -> Option<Vec<u32>> {
    if seg_steps == 0 {
        return None;
    }
    canonical_profile_for_bounds(
        full,
        &crate::segment::segment_bounds(full.steps.len(), seg_steps),
    )
}

/// [`canonical_profile_for`] over explicit window bounds — the floors for a
/// content-budgeted cut ([`crate::segment::segment_bounds_budgeted`]), or
/// any other deterministic segmentation. Same guarantees and refusals.
/// `bounds` must be in ascending step order (every segmentation here
/// produces them so): the windows are sliced by one forward
/// [`crate::segment::SegmentCursor`] pass, O(N) in the trace length
/// instead of the per-window prefix replay's O(N²).
pub fn canonical_profile_for_bounds(
    full: &SideNote,
    bounds: &[(usize, usize)],
) -> Option<Vec<u32>> {
    if bounds.is_empty() {
        return None;
    }
    let indices: Vec<usize> = (0..super::chip_idx::COUNT).collect();
    let mut floors = vec![0u32; indices.len()];
    let mut cursor = crate::segment::SegmentCursor::new(full);
    for &(a, b) in bounds {
        let mut sn = cursor.side_note(a, b);
        for (floor, natural) in floors.iter_mut().zip(natural_log_sizes_for(&mut sn, &indices)) {
            *floor = (*floor).max(natural);
        }
    }
    floors
        .iter()
        .all(|&f| f <= crate::DEFAULT_MAX_LOG_SIZE)
        .then_some(floors)
}

fn prove_impl_with_components(
    side_note: &mut SideNote,
    config: PcsConfig,
    profile: bool,
    components: &[&dyn crate::framework::MachineProverComponent],
    component_mask: u32,
    min_log_sizes: &[u32],
) -> Result<(Proof, ProveProfile), ProvingError> {
    prove_impl_with_components_overridden(
        side_note,
        config,
        profile,
        components,
        component_mask,
        None,
        min_log_sizes,
    )
}

/// Prove with caller-supplied boundary metadata in place of the
/// trace-derived `proof.{initial,final}_state`: the chips commit the
/// honest trace columns, but the FS-transcript mix and the shipped
/// metadata fields carry the caller's values instead.
///
/// This reproduces exactly what a from-scratch malicious prover can do —
/// run the whole pipeline with lying boundary metadata that is
/// self-consistent with its own transcript. It exists so the
/// boundary-binding gate test (`tests/boundary_binding.rs`) can assert
/// such proofs are REJECTED by `verify` / `verify_standalone`. It grants
/// no capability an adversary lacks, but it is not part of the supported
/// proving API.
#[doc(hidden)]
pub fn prove_with_boundary_override(
    side_note: &mut SideNote,
    initial_state: SegmentState,
    final_state: SegmentState,
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    prepare_side_note_for_verification(side_note);
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let component_mask = super::active_component_mask(side_note);
    let (proof, _) = prove_impl_with_components_overridden(
        side_note,
        production_pcs_config(),
        false,
        components,
        component_mask,
        Some((initial_state, final_state)),
        &[],
    )?;
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
fn prove_impl_with_components_overridden(
    side_note: &mut SideNote,
    config: PcsConfig,
    profile: bool,
    components: &[&dyn crate::framework::MachineProverComponent],
    component_mask: u32,
    boundary_override: Option<(SegmentState, SegmentState)>,
    min_log_sizes: &[u32],
) -> Result<(Proof, ProveProfile), ProvingError> {
    use std::time::Instant;

    // RegisterMemoryBoundaryChip needs `initial_regs`
    // populated.
    backfill_initial_regs(side_note);

    // Refresh `final_regs` when the closing chip is in the
    // component set, so a caller that constructed the SideNote with
    // stale final_regs can't accidentally produce a proof whose
    // claimed final state diverges from the actual trace's last step.
    // Skipped for chip-isolated harnesses that opted out of the
    // closing chip — those proofs leave `final_regs` untouched (the
    // field is unused without the chip).
    if side_note.closing_chip_active {
        backfill_final_regs(side_note);
    }

    // Build the memory-page Merkle boundary payload (listed pages,
    // entering/exit images, multiproof, merge schedule, `merkle_blake2b_calls`)
    // before trace generation — `MemoryChip` injects the per-page ledger entries
    // from it, `MemoryPageChip` / `MemoryMerkleChip` / `MemoryRootBoundaryChip`
    // produce the leaf/merge/root tuples, and `Blake2bBoundaryChip` proves the
    // compressions.  Prove-path only; idempotent.
    side_note.ingest_memory_pages();

    // Trace gen — split into a sequential *producer* pass and a parallel
    // *consumer* pass.  Producers (CpuChip, Blake2bChip) write per-row
    // multiplicities + entries into `side_note` while filling their main
    // trace; consumer chips (ALU/range/lookup tables, boundary chips,
    // memory ledgers, RistrettoChip, …) only read those, so they run on
    // rayon with shared `&SideNote`.  Mirrors the producer/consumer
    // split already used by interaction-trace generation a few stages
    // below.  Measured saving on log17 a ristretto-heavy workload (MOBILE):
    // ~130 ms → ~70 ms of trace_gen.
    let t = Instant::now();
    let mut traces: Vec<Option<ComponentTrace>> = (0..components.len()).map(|_| None).collect();
    // `min_log_sizes` (canonical-shape proving) is empty on the natural
    // paths ⇒ `unwrap_or(0)` ⇒ each chip proves at its natural size.
    for (i, c) in components.iter().enumerate() {
        if c.is_producer() {
            let min_log_size = min_log_sizes.get(i).copied().unwrap_or(0);
            traces[i] = Some(c.generate_component_trace_min(side_note, min_log_size));
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
            .map(|&i| {
                let min_log_size = min_log_sizes.get(i).copied().unwrap_or(0);
                (
                    i,
                    components[i].generate_component_trace_immut_min(snr, min_log_size),
                )
            })
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

    let twiddles = ProverBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut ProverChannel::default();

    let mut commitment_scheme =
        CommitmentSchemeProver::<ProverBackend, ProverMerkleChannel>::new(config, &twiddles);
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
        // `for_commit` transplants the SimdBackend-generated columns into the
        // commitment scheme's backend (identity on SimdBackend; `to_cpu` under
        // `poseidon2-channel`, whose Poseidon2-M31 commit ops are CpuBackend-only).
        tree_builder.extend_evals(for_commit(
            component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX),
        ));
    }
    tree_builder.commit(prover_channel);
    let preprocess_commit = t.elapsed();

    // Main trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_main_columns = 0;
    for component_trace in &traces {
        let evals = for_commit(component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX));
        total_main_columns += evals.len();
        tree_builder.extend_evals(evals);
    }
    tree_builder.commit(prover_channel);
    let main_commit = t.elapsed();

    // Mix the boundary `SegmentState` fields into the FS transcript.
    // Two effects: a FINISHED proof is tamper-evident (editing
    // initial/final registers, pc or timestamp post-prove shifts the
    // challenges the verifier draws, so the committed interaction trace
    // no longer satisfies the constraint system), and the lookup
    // elements drawn next depend on the claimed boundary states — the
    // precondition for the verifier-side boundary-binding check, which
    // recomputes each boundary chip's claimed sum from
    // `proof.{initial,final}_state` and rejects from-scratch provers
    // that ship metadata diverging from the committed boundary columns
    // (see `boundary_binding`). Gated on `closing_chip_active` because
    // production always ships the boundary + closing chips together
    // (BASE_COMPONENTS, set by `prove_impl`); chip-isolated harnesses
    // that opted out leave the mix off, matching their
    // `component_mask = 0` proof shape.
    //
    // Order (initial regs, final regs, initial pc, initial ts, final
    // pc, final ts) is deterministic and stable; the verifier MUST mix
    // identically. `memory_commitment` is NOT mixed (it is a hash
    // computed outside the circuit) and stays OUTSIDE the binding.
    if side_note.closing_chip_active {
        let (initial_regs, final_regs) = match &boundary_override {
            Some((ini, fin)) => (ini.registers, fin.registers),
            None => (side_note.initial_regs, side_note.final_regs),
        };
        for r in &initial_regs {
            prover_channel.mix_u64(*r);
        }
        for r in &final_regs {
            prover_channel.mix_u64(*r);
        }
        let (initial_pc, initial_ts, final_pc, final_ts) = match &boundary_override {
            Some((ini, fin)) => (ini.pc as u64, ini.timestamp, fin.pc as u64, fin.timestamp),
            None => match (side_note.steps.first(), side_note.steps.last()) {
                (Some(first), Some(last)) => (
                    first.pc as u64,
                    first.timestamp,
                    last.next_pc as u64,
                    last.timestamp + 1,
                ),
                _ => (0, 0, 0, 0),
            },
        };
        prover_channel.mix_u64(initial_pc);
        prover_channel.mix_u64(initial_ts);
        prover_channel.mix_u64(final_pc);
        prover_channel.mix_u64(final_ts);

        // Format v7: mix the entering / exit RAM Merkle roots right
        // after final_ts and before the lookup-element draw, so the verifier's
        // MemoryRootBoundary claimed-sum recomputation is sound (the roots are
        // public inputs the lookup elements are drawn against).  Order: entering
        // root, then exit root, each as 4 LE u64 words.
        let (initial_root, final_root) = match &boundary_override {
            Some((ini, fin)) => (ini.memory_root, fin.memory_root),
            None => segment_memory_roots(side_note),
        };
        for chunk in initial_root.chunks_exact(8) {
            prover_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        for chunk in final_root.chunks_exact(8) {
            prover_channel.mix_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
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
    // Measured win at log17 a ristretto-heavy workload (MOBILE config):
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
        tree_builder.extend_evals(for_commit(interaction_trace));
        claimed_sums.push(claimed_sum);
    }
    let interaction_gen = t.elapsed();

    let t = Instant::now();
    prover_channel.mix_felts(&claimed_sums);
    tree_builder.commit(prover_channel);
    let interaction_commit = t.elapsed();

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let components: Vec<Box<dyn ComponentProver<ProverBackend>>> = components
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
    let components_ref: Vec<&dyn ComponentProver<ProverBackend>> =
        components.iter().map(|c| &**c).collect();

    let t = Instant::now();
    let proof = stwo::prover::prove::<ProverBackend, ProverMerkleChannel>(
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

    // Print on the explicit `profile` flag, or whenever `ZKPVM_PROFILE` is set
    // in the environment (so the phase breakdown is reachable through paths
    // that hard-code `profile = false`, e.g. `prove_canonical`).
    if profile || std::env::var_os("ZKPVM_PROFILE").is_some() {
        eprintln!("{prof}");
    }

    // Compute segment boundary states. `initial_state.registers` is
    // sourced from `side_note.initial_regs` (the same field the
    // boundary chip's main trace emits from), not `first.regs_before`,
    // so the proof field and the chip's committed values are equal
    // by construction. The closing-chip FS-transcript mix relies on this
    // invariant — if the proof field could diverge from what the chip
    // committed, the verifier would mix bytes that don't match what
    // the prover mixed and honest proofs would fail to verify.
    //
    // For non-empty traces this is equivalent to `first.regs_before`
    // because the constraint system already requires
    // `initial_regs == first.regs_before` (boundary chip producers
    // balance CpuChip first-step read consumers via the ledger).
    // Memory-page Merkle roots: entering root on initial_state, exit root on final_state —
    // the same values mixed into the FS transcript above and bound by
    // MemoryRootBoundaryChip, so the proof fields equal the committed columns.
    let (root_before, root_after) = segment_memory_roots(side_note);
    let initial_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
            memory_commitment: [0; 32],
            memory_root: root_before,
        }
    } else {
        let first = &side_note.steps[0];
        SegmentState {
            pc: first.pc,
            timestamp: first.timestamp,
            registers: side_note.initial_regs,
            memory_commitment: *blake3::hash(&side_note.initial_memory).as_bytes(),
            memory_root: root_before,
        }
    };
    let final_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
            memory_commitment: [0; 32],
            memory_root: root_after,
        }
    } else {
        let last = &side_note.steps[side_note.steps.len() - 1];
        let mut regs = [0u64; 13];
        regs[..last.regs_after.len().min(13)]
            .copy_from_slice(&last.regs_after[..13.min(last.regs_after.len())]);
        // Final memory = initial memory with all writes applied.
        SegmentState {
            pc: last.next_pc,
            timestamp: last.timestamp + 1,
            registers: regs,
            memory_commitment: compute_final_memory_commitment(side_note),
            memory_root: root_after,
        }
    };

    // The forgery seam ships the caller's states verbatim — the same
    // values the mix above committed to the transcript.
    let (initial_state, final_state) = match boundary_override {
        Some((ini, fin)) => (ini, fin),
        None => (initial_state, final_state),
    };

    // Caller supplies the bitmask (empty for chip-isolated harness).
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
