// vos-pvm-proof-verifier: standalone verification for PVM zkVM proofs.
//
// This crate provides a verify function that does NOT require the full
// execution trace (SideNote). It only needs the proof and the expected
// preprocessed trace commitment (which is deterministic per program).
//
// no_std-ready: the verifier path of vos-pvm-proof pulls only verifier-side stwo,
// alloc::*, and core::*.  Builds for wasm32-unknown-unknown (`just
// wasm-verifier`): `vos_pvm` is prover-only in vos-pvm-proof (it doesn't build on
// 32-bit targets — CODE_WINDOW_SIZE = 1 << 32 overflows usize), and the
// workspace stwo pin is feature-less, with `std,prover,parallel` added
// back only by vos-pvm-proof's `prover` feature — so this crate's normal-dep graph
// carries no vos_pvm / rayon / vos-pvm-proof-blake3.

#![no_std]

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, format, string::ToString, vec::Vec};
use num_traits::Zero;
use stwo::core::{
    air::Component,
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, TreeVec},
    verifier::VerificationError,
};
use stwo_constraint_framework::{PREPROCESSED_TRACE_IDX, TraceLocationAllocator};

// A proof's format selects its channel at run time; one build reads every
// admitted format.
use vos_pvm_proof::format::{Encoding, Format};
use vos_pvm_proof::pcs::{PcsStack, ProofHash};

// The proof type, the format registry `verify_standalone` admits a proof's
// number from, and the number the default prover produces.
pub use vos_pvm_proof::format;
pub use vos_pvm_proof::program_id::{
    ENTRY_TIMESTAMP, HALT_PC, KernelEntry, KernelProgram, LeafCircuits, ProgramId,
};
pub use vos_pvm_proof::refine::{
    MAX_REFINE_CHILD_COMPONENTS, MAX_REFINE_HOST_BOUNDARIES, MAX_REFINE_PROOF_SLICES,
    REFINE_BUNDLE_FORMAT_VERSION, REFINE_CHILD_COMMITMENT_COUNT, RefineBundleVerification,
    RefineMachineId, RefineProgramId, RefineProofBundle, RefineSliceExit,
    refine_arguments_commitment, refine_bundle_cardinality_is_valid, refine_bundle_commitment,
    refine_bundle_execution_commitment, refine_bundle_terminal_public_io, refine_program_id,
};
pub use vos_pvm_proof::shape::{KernelShape, SegmentClass};
pub use vos_pvm_proof::{PROOF_FORMAT_VERSION, Proof};
// PcsPolicy floor — see SECURITY.md "Proof shape". `check_min_security` /
// `conjectured_security_bits` / `MIN_CONJECTURED_SECURITY_BITS` are the
// conjectured-security floor the DEFAULT `verify_standalone` path enforces
// (accepts any 96-bit-secure shape, STANDARD and MOBILE both); the per-field
// `PcsPolicy` + `check_pcs_policy` are the exact-pin path.
pub use vos_pvm_proof::proof::{
    MIN_CONJECTURED_SECURITY_BITS, PcsPolicy, STANDARD_MIN_FRI_LOG_BLOWUP,
    STANDARD_MIN_FRI_QUERIES, STANDARD_MIN_POW_BITS, check_min_security, check_pcs_policy,
    conjectured_security_bits,
};

use vos_pvm_proof::framework_access::{
    AllLookupElements, create_verifier_components, draw_all_lookup_elements,
};

/// Verification hash type — the preprocessed-trace Merkle root, in the hash
/// of the proof's format.
pub use vos_pvm_proof::pcs::Commitment as CommitmentHash;

/// Default per-component log_size cap used by `verify_standalone`.
///
/// At log_size = 24 each chip's main trace has 2^24 ≈ 16M rows; the
/// FRI/Merkle phase commits those plus the preprocessed and
/// interaction traces.  This is well above the largest trace the
/// `prove_vos_actor` benchmark suite produces and well below the
/// log_size where verification CPU/memory cost becomes onerous.
///
/// Callers who need to accept larger proofs (e.g. for batched
/// proving over very long executions) should call
/// `verify_standalone_with_max_log_size` with an explicit bound.
pub const DEFAULT_MAX_LOG_SIZE: u32 = 24;

/// Trusted mapping from an exact Refine machine/program identity and proof
/// shape to its preprocessed-trace commitment.
///
/// The mapping must come from an authenticated program catalog or equivalent
/// admission record, never from the presented bundle itself. A PVM program's
/// preprocessed commitment also depends on its selected component/log-size
/// profile and exact PCS configuration, so the complete shape (including an
/// explicit lifting choice) is part of the lookup key.
pub trait RefineProgramCommitmentResolver {
    fn resolve_preprocessed_commitment(
        &self,
        identity: RefineMachineId,
        proof_format_version: u32,
        component_mask: u32,
        log_sizes: &[u32],
        pcs_config: &stwo::core::pcs::PcsConfig,
    ) -> Option<CommitmentHash>;
}

impl<F> RefineProgramCommitmentResolver for F
where
    F: Fn(RefineMachineId, u32, u32, &[u32], &stwo::core::pcs::PcsConfig) -> Option<CommitmentHash>,
{
    fn resolve_preprocessed_commitment(
        &self,
        identity: RefineMachineId,
        proof_format_version: u32,
        component_mask: u32,
        log_sizes: &[u32],
        pcs_config: &stwo::core::pcs::PcsConfig,
    ) -> Option<CommitmentHash> {
        self(
            identity,
            proof_format_version,
            component_mask,
            log_sizes,
            pcs_config,
        )
    }
}

/// Verify every child STARK and the canonical Refine boundary transcript.
///
/// This deliberately returns [`RefineBundleVerification::ReplayRequired`]
/// rather than `()` or `true`: a proof-only verifier cannot bind the bundle's
/// native machine-state hashes and exit reasons to the child proof statements,
/// or establish the native semantics of host calls 9..=14. Prover-enabled
/// hosts close those boundaries with
/// `vos_pvm_proof::verify_refine_bundle_replayed`, using exact outer
/// program/argument bytes and gas. `program_commitments` must be a trusted
/// external mapping; requiring it prevents a valid proof for an arbitrary
/// program from being relabelled with a different
/// [`RefineMachineId::program`](RefineMachineId::program).
pub fn verify_refine_bundle_authenticated<R: RefineProgramCommitmentResolver + ?Sized>(
    bundle: &RefineProofBundle,
    expected_outer_program: RefineProgramId,
    expected_arguments_commitment: [u8; 32],
    expected_gas_limit: u64,
    program_commitments: &R,
) -> Result<RefineBundleVerification, VerificationError> {
    // Must precede transcript construction, resolver callbacks, proof clones,
    // and cryptographic work. Every collection length encoded as u32 in the
    // transcript is bounded here.
    if !refine_bundle_cardinality_is_valid(bundle) {
        return Err(VerificationError::InvalidStructure(
            "Refine bundle cardinality is noncanonical".to_string(),
        ));
    }
    if bundle.format_version != REFINE_BUNDLE_FORMAT_VERSION {
        return Err(VerificationError::InvalidStructure(
            "Refine bundle format version mismatch".to_string(),
        ));
    }
    if bundle.outer_program != expected_outer_program
        || bundle.arguments_commitment != expected_arguments_commitment
        || bundle.gas_limit != expected_gas_limit
    {
        return Err(VerificationError::InvalidStructure(
            "Refine invocation identity/arguments/gas mismatch".to_string(),
        ));
    }
    if bundle.transcript_commitment != refine_bundle_commitment(bundle) {
        return Err(VerificationError::InvalidStructure(
            "Refine transcript commitment mismatch".to_string(),
        ));
    }
    let mut identities = BTreeMap::<(u32, u64), RefineProgramId>::new();
    for (index, slice) in bundle.slices.iter().enumerate() {
        if slice.order != index as u32 {
            return Err(VerificationError::InvalidStructure(
                "Refine machine slices are reordered".to_string(),
            ));
        }
        match slice.identity {
            RefineMachineId::Outer { program } if program == bundle.outer_program => {}
            RefineMachineId::Outer { .. } => {
                return Err(VerificationError::InvalidStructure(
                    "Refine outer slice has the wrong program identity".to_string(),
                ));
            }
            RefineMachineId::Inner {
                slot,
                generation,
                program,
            } => {
                if identities
                    .insert((slot, generation), program)
                    .is_some_and(|previous| previous != program)
                {
                    return Err(VerificationError::InvalidStructure(
                        "Refine inner slot/generation aliases two programs".to_string(),
                    ));
                }
            }
        }
        let Some(actual_program_commitment) = slice.proof.preprocessed_commitment() else {
            return Err(VerificationError::InvalidStructure(
                "Refine child proof has no preprocessed commitment".to_string(),
            ));
        };
        let Some(expected_program_commitment) = program_commitments
            .resolve_preprocessed_commitment(
                slice.identity,
                slice.proof.format_version,
                slice.proof.component_mask,
                &slice.proof.log_sizes,
                &slice.proof.pcs_config,
            )
        else {
            return Err(VerificationError::InvalidStructure(
                "Refine machine/program proof shape has no trusted commitment".to_string(),
            ));
        };
        if actual_program_commitment != expected_program_commitment {
            return Err(VerificationError::InvalidStructure(
                "Refine child proof does not match its trusted program commitment".to_string(),
            ));
        }
    }

    if !matches!(bundle.slices[0].identity, RefineMachineId::Outer { .. }) {
        return Err(VerificationError::InvalidStructure(
            "Refine closure must start in the outer runtime".to_string(),
        ));
    }
    // Walk the closure in execution order. This proves structural coverage,
    // not host semantics: every handled outer host exit has exactly one
    // boundary, only INVOKE may enclose one inner slice, and every other
    // slice is the next outer continuation. A final handled host call can
    // end in Panic/OutOfGas during native dispatch without another machine
    // slice; replay is what proves that terminal transition.
    let mut slice_index = 0usize;
    let mut boundary_index = 0usize;
    while slice_index < bundle.slices.len() {
        let outer = &bundle.slices[slice_index];
        if !matches!(outer.identity, RefineMachineId::Outer { .. }) {
            return Err(VerificationError::InvalidStructure(
                "Refine inner slice is outside an INVOKE boundary".to_string(),
            ));
        }
        let RefineSliceExit::HostCall(call) = outer.exit else {
            if slice_index + 1 != bundle.slices.len()
                || outer.exit != bundle.result
                || boundary_index != bundle.host_boundaries.len()
            {
                return Err(VerificationError::InvalidStructure(
                    "Refine terminal result or slice coverage is noncanonical".to_string(),
                ));
            }
            slice_index += 1;
            continue;
        };
        let Ok(call) = u8::try_from(call) else {
            return Err(VerificationError::InvalidStructure(
                "Refine outer host call is outside the standard call range".to_string(),
            ));
        };
        if !(9..=14).contains(&call) {
            return Err(VerificationError::InvalidStructure(
                "Refine outer host call is outside the standard call range".to_string(),
            ));
        }
        let Some(boundary) = bundle.host_boundaries.get(boundary_index) else {
            return Err(VerificationError::InvalidStructure(
                "Refine outer host call has no matching boundary".to_string(),
            ));
        };
        let expected_before = slice_index + 1;
        if boundary.call != call || boundary.slices_before as usize != expected_before {
            return Err(VerificationError::InvalidStructure(
                "Refine host boundary does not match its outer call".to_string(),
            ));
        }
        if boundary.registers_before != outer.proof.final_state.registers {
            return Err(VerificationError::InvalidStructure(
                "Refine host boundary input registers differ from the child proof exit".to_string(),
            ));
        }
        let expected_after = if call == 13 {
            match bundle.slices.get(expected_before) {
                Some(slice) if matches!(slice.identity, RefineMachineId::Inner { .. }) => {
                    expected_before + 1
                }
                _ => expected_before,
            }
        } else {
            expected_before
        };
        if boundary.slices_after as usize != expected_after {
            return Err(VerificationError::InvalidStructure(
                "Refine host boundary encloses a noncanonical slice range".to_string(),
            ));
        }
        if let Some(next_outer) = bundle.slices.get(expected_after)
            && (!matches!(next_outer.identity, RefineMachineId::Outer { .. })
                || boundary.registers_after != next_outer.proof.initial_state.registers)
        {
            return Err(VerificationError::InvalidStructure(
                "Refine host boundary output registers differ from the next outer proof entry"
                    .to_string(),
            ));
        }
        boundary_index += 1;
        slice_index = expected_after;

        if slice_index == bundle.slices.len()
            && (expected_after != expected_before
                || !matches!(
                    bundle.result,
                    RefineSliceExit::Panic | RefineSliceExit::OutOfGas
                )
                || boundary_index != bundle.host_boundaries.len())
        {
            return Err(VerificationError::InvalidStructure(
                "Refine final host transition/result is noncanonical".to_string(),
            ));
        }
    }
    if boundary_index != bundle.host_boundaries.len() {
        return Err(VerificationError::InvalidStructure(
            "Refine bundle has an extra host boundary".to_string(),
        ));
    }

    // Perform expensive cryptographic verification only after all bounded
    // structural checks. The checked access above makes an empty commitment
    // vector a normal hostile-input error rather than a panic.
    for slice in &bundle.slices {
        let Some(program_commitment) = slice.proof.preprocessed_commitment() else {
            return Err(VerificationError::InvalidStructure(
                "Refine child proof has no preprocessed commitment".to_string(),
            ));
        };
        verify_standalone(slice.proof.clone(), program_commitment)?;
    }

    Ok(RefineBundleVerification::ReplayRequired {
        transcript_commitment: bundle.transcript_commitment,
    })
}

/// Verify a PVM execution proof.
///
/// # Arguments
/// * `proof` - The STARK proof with claimed sums and log sizes
/// * `preprocessed_commitment` - The expected Merkle root of the preprocessed trace.
///   This is deterministic per program (bytecode + initial memory layout).
///   The caller must compute this once per program and provide it here.
///
/// # Returns
/// `Ok(())` if the proof is valid, `Err(VerificationError)` otherwise.
pub fn verify_standalone(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
) -> Result<(), VerificationError> {
    // Default: the conjectured-security floor, which accepts any 96-bit-secure
    // shape (STANDARD and MOBILE both) while rejecting degenerate FRI shapes.
    // `None` selects that floor; the strict `verify_standalone_with_pcs_policy`
    // path passes an exact `PcsPolicy`.
    verify_standalone_shaped(proof, preprocessed_commitment, DEFAULT_MAX_LOG_SIZE, None)
}

/// Same as `verify_standalone` but with a caller-supplied per-component
/// `log_size` cap.  Use this when you need to accept proofs over larger
/// traces than `DEFAULT_MAX_LOG_SIZE` admits, or — more usefully —
/// tighten the cap for a specific deployment that knows its proof
/// shapes are smaller.
///
/// Reject path: any `log_size > max_log_size` returns
/// `InvalidStructure` before the verifier touches commitments,
/// preventing a malicious prover from forcing the verifier into a
/// giant Merkle commitment phase.
pub fn verify_standalone_with_max_log_size(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
    max_log_size: u32,
) -> Result<(), VerificationError> {
    // Shares `verify_standalone`'s default FRI-shape floor (conjectured
    // security). Only the log_size cap differs.
    verify_standalone_shaped(proof, preprocessed_commitment, max_log_size, None)
}

/// Enforce a custom `PcsPolicy` (FRI shape + PoW floor)
/// on `proof.pcs_config`.  The default `verify_standalone` accepts any shape
/// meeting the conjectured-security floor; reach for this to pin an EXACT
/// shape (stricter deployments) or to accept a looser test-harness shape.
/// See SECURITY.md "Proof shape".
pub fn verify_standalone_with_pcs_policy(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
    policy: &PcsPolicy,
) -> Result<(), VerificationError> {
    verify_standalone_shaped(
        proof,
        preprocessed_commitment,
        DEFAULT_MAX_LOG_SIZE,
        Some(policy),
    )
}

/// Both knobs at once — the explicit-`PcsPolicy` funnel (strict per-field
/// pin). The default `verify_standalone` / `verify_standalone_with_max_log_size`
/// paths use the conjectured-security floor instead (via `verify_standalone_shaped`).
pub fn verify_standalone_with_options(
    proof: Proof,
    preprocessed_commitment: CommitmentHash,
    max_log_size: u32,
    policy: &PcsPolicy,
) -> Result<(), VerificationError> {
    verify_standalone_shaped(proof, preprocessed_commitment, max_log_size, Some(policy))
}

/// Shared verify funnel. `policy` selects the FRI-shape floor: `None` = the
/// conjectured-security floor (the default paths — accepts STANDARD and
/// MOBILE), `Some(p)` = an exact `PcsPolicy` pin (the strict `*_with_pcs_policy`
/// path). All four public `verify_standalone*` entry points funnel here.
fn verify_standalone_shaped(
    mut proof: Proof,
    preprocessed_commitment: CommitmentHash,
    max_log_size: u32,
    policy: Option<&PcsPolicy>,
) -> Result<(), VerificationError> {
    let format = preflight_standalone(&mut proof, max_log_size)?;
    vos_pvm_proof::proof::check_shape_policy(format, &proof.pcs_config, policy)
        .map_err(VerificationError::InvalidStructure)?;
    vos_pvm_proof::with_stack!(format.channel, Stack => {
        verify_standalone_on::<Stack>(proof, format, preprocessed_commitment)
    }, unbuilt => Err(VerificationError::InvalidStructure(format!(
        "format {}'s channel is not built",
        format.number
    ))))
}

/// What every standalone path checks before any cryptographic work, and
/// every later length check assumes: the proof's structure, every log size
/// under `max_log_size` (so a malicious prover can't force arbitrarily large
/// Merkle commitments), its format, admitted and with its Stark proof on the
/// format's channel, and a component mask this AIR generation binds.
fn preflight_standalone(
    proof: &mut Proof,
    max_log_size: u32,
) -> Result<&'static Format, VerificationError> {
    let format = vos_pvm_proof::proof::preflight_proof_structure(proof, max_log_size)
        .map_err(VerificationError::InvalidStructure)?;
    // `component_mask = 0` is a back-compat sentinel meaning "fall back
    // to count-based inference over the full BASE_COMPONENTS", predating
    // dynamic chip selection. With `format_version` bumped past those
    // proofs, the only producer of `mask = 0` is the chip-isolated
    // `prove_with_explicit_components` path, whose proofs are documented
    // as "not verifiable via verify_standalone".
    //
    // Reject early, before any cryptographic work: such a proof names no
    // positions for the boundary chips, through which the standalone
    // verifier binds `proof.{initial,final}_state`.
    if proof.component_mask == 0 {
        return Err(VerificationError::InvalidStructure(
            "component_mask = 0 is invalid at format_version >= 2 \
             (chip-isolated proofs must use verify_with_explicit_components)"
                .to_string(),
        ));
    }
    let supported_mask = 1u32
        .checked_shl(vos_pvm_proof::chip_idx::COUNT as u32)
        .map_or(u32::MAX, |end| end - 1);
    if proof.component_mask & !supported_mask != 0 {
        return Err(VerificationError::InvalidStructure(
            "component_mask selects a component outside this AIR generation".to_string(),
        ));
    }
    if proof.component_mask.count_ones() as usize != proof.num_components {
        return Err(VerificationError::InvalidStructure(
            "component_mask popcount does not match num_components".to_string(),
        ));
    }
    Ok(format)
}

/// The AIR's trace log sizes for a proof's `log_sizes`, `component_mask`
/// and `claimed_sums`, its protocol shape, and the shape its security counts
/// are taken at.
fn standalone_shape<MC: PcsStack>(
    log_sizes: &[u32],
    component_mask: u32,
    claimed_sums: &[SecureField],
    config: &stwo::core::pcs::PcsConfig,
    stark: &stwo::core::proof::StarkProof<MC::H>,
) -> Result<
    (
        TreeVec<Vec<u32>>,
        vos_pvm_proof::proof::ProofProtocolShape,
        vos_pvm_proof::security::SecurityShape,
    ),
    VerificationError,
> {
    let (trace_sizes, preprocessed_sizes) =
        create_verifier_components::trace_and_preprocessed_sizes(log_sizes, component_mask);
    let mut expected_log_sizes = TreeVec::concat_cols(trace_sizes.into_iter());
    if expected_log_sizes.len() != 3 {
        return Err(VerificationError::InvalidStructure(
            "selected AIR has a noncanonical trace-tree count".to_string(),
        ));
    }
    expected_log_sizes[0] = preprocessed_sizes;
    let mut dummy_lookup = AllLookupElements::default();
    let mut dummy_channel = MC::C::default();
    draw_all_lookup_elements(&mut dummy_lookup, &mut dummy_channel, component_mask);
    let dummy_allocator = &mut TraceLocationAllocator::default();
    let shape_components = create_verifier_components::components(
        dummy_allocator,
        &dummy_lookup,
        log_sizes,
        claimed_sums,
        component_mask,
    );
    let shape_component_refs: Vec<&dyn Component> = shape_components
        .iter()
        .map(|component| &**component)
        .collect();
    let (protocol_shape, security_shape) =
        vos_pvm_proof::framework_access::preflight_component_dimensions(
            config,
            stark,
            &shape_component_refs,
            &expected_log_sizes,
        )
        .map_err(VerificationError::InvalidStructure)?;
    Ok((expected_log_sizes, protocol_shape, security_shape))
}

/// A proof's two security counts ([`vos_pvm_proof::security`]), at its own
/// parameters and shape, after the structural checks `verify_standalone`
/// runs first. No cryptographic check is made.
pub fn proof_security_bits(
    proof: &Proof,
) -> Result<vos_pvm_proof::security::SecurityBits, VerificationError> {
    let mut proof = proof.clone();
    let format = preflight_standalone(&mut proof, DEFAULT_MAX_LOG_SIZE)?;
    let shape = vos_pvm_proof::with_stack!(format.channel, Stack => {
        let stark = Stack::stark(&proof.stark_proof).ok_or_else(|| {
            VerificationError::InvalidStructure("Stark proof channel differs".to_string())
        })?;
        standalone_shape::<Stack>(
            &proof.log_sizes,
            proof.component_mask,
            &proof.claimed_sums,
            &proof.pcs_config,
            stark,
        )?
        .2
    }, unbuilt => return Err(VerificationError::InvalidStructure(format!(
        "format {}'s channel is not built",
        format.number
    ))));
    vos_pvm_proof::proof::format_security_bits(format, &proof.pcs_config, &shape)
        .map_err(VerificationError::InvalidStructure)
}

fn verify_standalone_on<MC: PcsStack>(
    proof: Proof,
    format: &'static Format,
    preprocessed_commitment: CommitmentHash,
) -> Result<(), VerificationError> {
    let stark = MC::stark(&proof.stark_proof).ok_or_else(|| {
        VerificationError::InvalidStructure("Stark proof channel differs".to_string())
    })?;
    let (log_sizes, protocol_shape, security_shape) = standalone_shape::<MC>(
        &proof.log_sizes,
        proof.component_mask,
        &proof.claimed_sums,
        &proof.pcs_config,
        stark,
    )?;
    // The format's floors, counted at this proof's own parameters and
    // shape, and its exact parameters.
    if format.encoding == Encoding::Lossless {
        vos_pvm_proof::proof::check_format_security(format, &proof.pcs_config, &security_shape)
            .map_err(VerificationError::InvalidStructure)?;
    }

    if proof.claimed_sums.len() != proof.num_components {
        return Err(VerificationError::InvalidStructure(
            "claimed sums len mismatch".to_string(),
        ));
    }
    if proof.log_sizes.len() != proof.num_components {
        return Err(VerificationError::InvalidStructure(
            "log sizes len mismatch".to_string(),
        ));
    }
    // Reject `initial_state.timestamp < 1` per segment (the production
    // consumer verifies single proofs here, not only the chain wrapper).  Step timestamps start at 1, so `initial_ts ≥ 1` excludes the
    // ts=0 per-page boundary writes from being forged as real steps, and (with
    // the CpuChip ts-chain) lands every step ts in [initial_ts, final_ts).
    if proof.initial_state.timestamp < 1 {
        return Err(VerificationError::InvalidStructure(
            "initial_state.timestamp must be >= 1 (memory-boundary anchoring)".to_string(),
        ));
    }

    let actual_preprocessed = stark.commitments[PREPROCESSED_TRACE_IDX].into_commitment();
    if actual_preprocessed != preprocessed_commitment {
        return Err(VerificationError::InvalidStructure(format!(
            "preprocessed commitment mismatch: expected {preprocessed_commitment}, got {actual_preprocessed}"
        )));
    }

    // The transcript through the interaction root, as the prover ran it: the
    // boundary states (the `component_mask = 0` reject above guarantees a
    // proof with the boundary and closing chips) and the interaction PoW
    // precede the relation elements, which therefore depend on the claimed
    // boundary states. `memory_commitment` stays unmixed (computed outside
    // the circuit). The proof's own PCS config: a legacy proof carries its
    // own, and every other format's equals the format's, checked above; the
    // DEEP batching is the format's, which a proof does not carry.
    let verifier_channel = &mut MC::C::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<MC>::new(format.verifier_config(&proof.pcs_config));
    let lookup_elements = vos_pvm_proof::proof::replay_prefix::<MC>(
        &proof,
        stark,
        format,
        &log_sizes,
        verifier_channel,
        commitment_scheme,
        |channel| {
            let mut lookup_elements = AllLookupElements::default();
            draw_all_lookup_elements(&mut lookup_elements, channel, proof.component_mask);
            lookup_elements
        },
    )
    .map_err(VerificationError::InvalidStructure)?;

    // Verify logup sum = 0
    if proof.claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    // Boundary public-input binding: each boundary chip's
    // claimed sum must equal the value recomputed from the proof's
    // public boundary states with the drawn lookup elements. This
    // BINDS `proof.{initial,final}_state` to the committed boundary
    // COLUMNS; the transcript's mix alone is only tamper-evidence against
    // post-prove edits, not against a from-scratch prover. pc/timestamp
    // columns are pinned to the trace by CpuChip program-execution
    // chaining; the register columns (and the voucher io-hash read from
    // `final_state.registers[9..13]`) are pinned to the trace by
    // `RegisterMemoryChip` read-consistency (a cross-row
    // `#[mask_next_row]` `prev_value` binding, a range-checked
    // `(reg, ts)` sortedness gadget, and an `is_write` tuple limb),
    // which is sound against a from-scratch prover (gate:
    // `pvm/proof/tests/ledger_readconsistency_gate.rs`) — see
    // `vos_pvm_proof::boundary_binding` and `chips/register_memory_closing.rs`.
    // So registers/pc/timestamp are all genuine bound public inputs. A
    // mask missing any binding
    // chip cannot bind its boundary states and is rejected outright (all
    // three are unconditionally active in the production prove path).
    let Some(boundary_positions) =
        vos_pvm_proof::boundary_binding::boundary_positions_in_mask(proof.component_mask)
    else {
        return Err(VerificationError::InvalidStructure(
            "component_mask lacks a boundary-binding chip \
             (RegisterMemoryBoundary / RegisterMemoryClosing / ProgramBoundary)"
                .to_string(),
        ));
    };
    vos_pvm_proof::boundary_binding::check_boundary_claimed_sums(
        &proof.initial_state,
        &proof.final_state,
        &lookup_elements,
        &proof.claimed_sums,
        &boundary_positions,
    )
    .map_err(|msg| VerificationError::InvalidStructure(msg.to_string()))?;

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: Vec<Box<dyn Component>> = create_verifier_components::components(
        tree_span_provider,
        &lookup_elements,
        &proof.log_sizes,
        &proof.claimed_sums,
        proof.component_mask,
    );
    let components_ref: Vec<&dyn Component> = verifier_components.iter().map(|c| &**c).collect();

    let sampled_queries = vos_pvm_proof::proof::expected_fiat_shamir_query_count::<MC>(
        verifier_channel,
        stark,
        &proof.pcs_config,
        protocol_shape,
        &log_sizes,
    )
    .map_err(VerificationError::InvalidStructure)?;
    if sampled_queries != protocol_shape.query_count {
        return Err(VerificationError::InvalidStructure(
            "queried-value rows differ from Fiat-Shamir query positions".to_string(),
        ));
    }

    let stark_proof = MC::from_any(proof.stark_proof).expect("the channel checked above");
    stwo::core::verifier::verify(
        &components_ref,
        verifier_channel,
        commitment_scheme,
        stark_proof,
    )
}

/// Verify a CHAIN of segment proofs WITHOUT any side note — the trustless
/// counterpart to `vos_pvm_proof::verify_chain` (which needs prover-supplied
/// `SideNote`s and never pins program identity).
///
/// Each segment is verified via [`verify_standalone`] against the SAME
/// `preprocessed_commitment`, so the chain (a) needs no prover-supplied
/// trace data and (b) pins every segment to ONE program identity (a
/// from-scratch prover cannot splice in a segment of a different program).
/// Consecutive segments must chain: `proofs[i].final_state ==
/// proofs[i+1].initial_state`.
///
/// SOUNDNESS SCOPE — the boundary-continuity equality is BOUND in-circuit
/// for every continued field, so an accepted chain proves genuine state
/// continuity (not mere tamper-evidence): registers via the register-ledger
/// read-consistency binding, pc/timestamp via CpuChip program-execution
/// chaining, and `SegmentState.memory_root` via the in-AIR page-Merkle trie
/// (`Memory{Page,Merkle,RootBoundary}Chip` force `memory_root` to be the
/// genuine blake2b Merkle root of the listed RAM pages, and
/// `check_boundary_claimed_sums` pins it to the public boundary state). The
/// entering image is anchored by `expected_initial_root`; the returned final
/// root pins the post-state. (`SegmentState.memory_commitment`, a
/// `blake3(flat_mem)` field, is unbound but vestigial — `memory_root`
/// supersedes it for continuity.) So a chain accepted here proves: one
/// program, per-segment validity, and full register / pc / timestamp /
/// memory continuity from `expected_initial_root` to the returned final
/// root.
///
/// PRECONDITION — every segment must share `preprocessed_commitment`, i.e.
/// have the SAME per-component `log_sizes` (the program commitment is the
/// preprocessed-trace Merkle root, which is size-dependent). Deployments
/// that segment a long trace should pad all segments to one uniform size
/// so a single published commitment pins them all; a chain whose last
/// segment is smaller would currently need its own commitment (a
/// per-segment-commitment variant is future work).
pub fn verify_chain_standalone(
    proofs: &[Proof],
    preprocessed_commitment: CommitmentHash,
    expected_initial_root: [u8; 32],
) -> Result<[u8; 32], VerificationError> {
    // Default: the conjectured-security floor, so a canonical MOBILE chain
    // (`vos_pvm_proof::prove_chain`) verifies without the caller naming
    // `PcsPolicy::MOBILE`. `None` selects that floor; the explicit
    // `verify_chain_standalone_with_options` path passes a `PcsPolicy`.
    verify_chain_standalone_shaped(
        proofs,
        preprocessed_commitment,
        expected_initial_root,
        DEFAULT_MAX_LOG_SIZE,
        None,
    )
}

/// [`verify_chain_standalone`] with explicit `max_log_size` cap + `PcsPolicy`.
///
/// The strict-pin counterpart to `verify_chain_standalone` (which uses the
/// conjectured-security floor): every segment is verified against the exact
/// `policy` shape. `expected_initial_root` is the page-Merkle root of the
/// program's starting RAM image — the memory analogue of the program
/// commitment — checked against `proofs[0].initial_state.memory_root`.  On
/// success returns the chain's final root
/// (`proofs.last().final_state.memory_root`) so the caller can pin the
/// post-state.  Callers compute `expected_initial_root` host-side via
/// `vos_pvm_proof::page_merkle::image_root` over the input image.
pub fn verify_chain_standalone_with_options(
    proofs: &[Proof],
    preprocessed_commitment: CommitmentHash,
    expected_initial_root: [u8; 32],
    max_log_size: u32,
    policy: &PcsPolicy,
) -> Result<[u8; 32], VerificationError> {
    verify_chain_standalone_shaped(
        proofs,
        preprocessed_commitment,
        expected_initial_root,
        max_log_size,
        Some(policy),
    )
}

/// Shared chain-verify funnel. `policy`: `None` = the conjectured-security
/// floor (the default `verify_chain_standalone` — accepts STANDARD and
/// MOBILE), `Some(p)` = an exact `PcsPolicy` pin
/// (`verify_chain_standalone_with_options`).
fn verify_chain_standalone_shaped(
    proofs: &[Proof],
    preprocessed_commitment: CommitmentHash,
    expected_initial_root: [u8; 32],
    max_log_size: u32,
    policy: Option<&PcsPolicy>,
) -> Result<[u8; 32], VerificationError> {
    if proofs.is_empty() {
        return Err(VerificationError::InvalidStructure(
            "verify_chain_standalone: empty proof chain".to_string(),
        ));
    }
    // Anchor the chain's entering image — proofs[0] must start from the
    // verifier-supplied expected root (the memory analogue of program identity).
    if proofs[0].initial_state.memory_root != expected_initial_root {
        return Err(VerificationError::InvalidStructure(
            "verify_chain_standalone: proofs[0].initial_state.memory_root \
             does not match expected_initial_root"
                .to_string(),
        ));
    }
    // Boundary continuity: each segment's final state must equal the next
    // segment's initial state.  Bound for registers/pc/timestamp (and the
    // memory root) by each segment's in-circuit boundary binding.
    for window in proofs.windows(2) {
        if window[0].final_state != window[1].initial_state {
            return Err(VerificationError::InvalidStructure(format!(
                "segment chain broken: final state at ts={} does not match next initial at ts={}",
                window[0].final_state.timestamp, window[1].initial_state.timestamp,
            )));
        }
    }
    // Each segment verifies standalone against the SAME program commitment:
    // no side note, and program identity is pinned across the whole chain.
    for proof in proofs {
        verify_standalone_shaped(proof.clone(), preprocessed_commitment, max_log_size, policy)?;
    }
    Ok(proofs[proofs.len() - 1].final_state.memory_root)
}

/// Like [`verify_chain_standalone`], but pins program identity to a small
/// published SET of allowed commitments instead of a single one.
///
/// WHY a set: canonical-shape proving (forcing each preprocessed-bearing chip
/// to a fixed `log_size`) makes a program's preprocessed columns identical
/// across segments, so one program at one forced profile has one canonical
/// commitment. A deployment that accepts several shapes (several forced
/// profiles, or several versions of the program) publishes one commitment
/// per shape. Each is WITNESS-INDEPENDENT (a function of the program and the
/// forced profile, not of its inputs), so the allowlist is a fixed
/// per-deployment constant.
///
/// SOUNDNESS: every segment's commitment must be IN the allowlist (a
/// from-scratch prover splicing a foreign program produces a commitment in no
/// listed shape), and each segment then verifies standalone against its own
/// commitment.  Combined with the same boundary-continuity + anchoring as
/// [`verify_chain_standalone`], an accepted chain proves: the program is one
/// of the published canonical shapes, per-segment validity, and
/// full register / pc / timestamp / memory continuity.
///
/// PRECONDITION: the prover used canonical-shape proving (`vos_pvm_proof::prove_canonical`
/// with the deployment's per-chip `min_log_size` profile) so the forced
/// `log_size`s are constant across the chain; otherwise log_size variation
/// would produce commitments outside the allowlist.
pub fn verify_chain_standalone_allowlist(
    proofs: &[Proof],
    allowed_commitments: &[CommitmentHash],
    expected_initial_root: [u8; 32],
    max_log_size: u32,
    policy: &PcsPolicy,
) -> Result<[u8; 32], VerificationError> {
    if proofs.is_empty() {
        return Err(VerificationError::InvalidStructure(
            "verify_chain_standalone_allowlist: empty proof chain".to_string(),
        ));
    }
    if allowed_commitments.is_empty() {
        return Err(VerificationError::InvalidStructure(
            "verify_chain_standalone_allowlist: empty commitment allowlist".to_string(),
        ));
    }
    // Anchor the entering image (memory analogue of program identity).
    if proofs[0].initial_state.memory_root != expected_initial_root {
        return Err(VerificationError::InvalidStructure(
            "verify_chain_standalone_allowlist: proofs[0].initial_state.memory_root \
             does not match expected_initial_root"
                .to_string(),
        ));
    }
    // Boundary continuity across the chain.
    for window in proofs.windows(2) {
        if window[0].final_state != window[1].initial_state {
            return Err(VerificationError::InvalidStructure(format!(
                "segment chain broken: final state at ts={} does not match next initial at ts={}",
                window[0].final_state.timestamp, window[1].initial_state.timestamp,
            )));
        }
    }
    // Each segment's program commitment must be in the published allowlist,
    // then it verifies standalone against that (its own) commitment.
    for proof in proofs {
        let Some(actual) = proof.preprocessed_commitment() else {
            return Err(VerificationError::InvalidStructure(
                "verify_chain_standalone_allowlist: a segment has no program commitment"
                    .to_string(),
            ));
        };
        if !allowed_commitments.contains(&actual) {
            return Err(VerificationError::InvalidStructure(
                "verify_chain_standalone_allowlist: a segment's program commitment \
                 is not in the published allowlist"
                    .to_string(),
            ));
        }
        verify_standalone_with_options(proof.clone(), actual, max_log_size, policy)?;
    }
    Ok(proofs[proofs.len() - 1].final_state.memory_root)
}

/// The class of a segment of a kernel's run, from its structure alone: its
/// format the kernel's, its chips exactly the shape's, more or fewer
/// refused, its log sizes exactly one class's.
fn kernel_segment_class(
    proof: &Proof,
    program: &KernelProgram,
) -> Result<usize, VerificationError> {
    if proof.format_version != program.format {
        return Err(VerificationError::InvalidStructure(format!(
            "the proof's format {} is not its kernel's, {}",
            proof.format_version, program.format
        )));
    }
    program
        .shape
        .class_of(proof.component_mask, &proof.log_sizes)
        .map_err(VerificationError::InvalidStructure)
}

/// Verify a segment of a kernel's run against its program, the preimage of
/// its program id ([`vos_pvm_proof::program_id`]): its format, its chips
/// exactly the shape's, more or fewer refused, its log sizes exactly one
/// class's, then [`verify_standalone`] against that class's preprocessed
/// root. The shape is checked before any cryptographic work, so a proof of
/// another shape costs its structure alone. Returns the segment's class.
pub fn verify_kernel_segment(
    proof: Proof,
    program: &KernelProgram,
) -> Result<usize, VerificationError> {
    program
        .check()
        .map_err(VerificationError::InvalidStructure)?;
    let class = kernel_segment_class(&proof, program)?;
    verify_standalone(proof, program.preprocessed_roots[class])?;
    Ok(class)
}

/// Verify a whole run of a kernel, a chain of its segments, against its
/// program and its entry ([`KernelEntry::of`] the kernel's blob): the first
/// segment starts where the loader starts the kernel, at its entry pc, at
/// timestamp 1, with the loader's registers and the kernel's image root;
/// each continues the one before; the last ends at the halt; and each is a
/// segment of the kernel ([`verify_kernel_segment`]). Every structural
/// check runs before any cryptographic one, and verifying a proof consumes
/// it, so the chain is taken whole. Returns the run's final
/// registers: its output's address and length in φ7 and φ8, its io-hash
/// in φ9 to φ12.
pub fn verify_kernel_chain(
    proofs: Vec<Proof>,
    program: &KernelProgram,
    entry: &KernelEntry,
) -> Result<[u64; 13], VerificationError> {
    let refuse = |reason: &str| {
        Err(VerificationError::InvalidStructure(format!(
            "verify_kernel_chain: {reason}"
        )))
    };
    let (Some(first), Some(last)) = (proofs.first(), proofs.last()) else {
        return refuse("empty proof chain");
    };
    program
        .check()
        .map_err(VerificationError::InvalidStructure)?;
    let start = &first.initial_state;
    if start.timestamp != ENTRY_TIMESTAMP {
        return refuse("the first segment does not start at the run's first timestamp");
    }
    if start.pc != entry.pc {
        return refuse("the first segment does not start at the kernel's entry");
    }
    if start.registers != entry.registers {
        return refuse("the first segment does not start with the loader's registers");
    }
    if start.memory_root != program.image_root {
        return refuse("the first segment does not start at the kernel's image root");
    }
    if last.final_state.pc != HALT_PC {
        return refuse("the last segment does not end at the halt");
    }
    for window in proofs.windows(2) {
        if window[0].final_state != window[1].initial_state {
            return Err(VerificationError::InvalidStructure(format!(
                "segment chain broken: final state at ts={} does not match next initial at ts={}",
                window[0].final_state.timestamp, window[1].initial_state.timestamp,
            )));
        }
    }
    let classes = proofs
        .iter()
        .map(|proof| kernel_segment_class(proof, program))
        .collect::<Result<Vec<_>, _>>()?;
    let registers = last.final_state.registers;
    for (proof, class) in proofs.into_iter().zip(classes) {
        verify_standalone(proof, program.preprocessed_roots[class])?;
    }
    Ok(registers)
}
