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

use alloc::{boxed::Box, format, string::ToString, vec::Vec};
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
use vos_pvm_proof::format::Format;
use vos_pvm_proof::pcs::{PcsStack, ProofHash};

// The proof type, the format registry `verify_standalone` admits a proof's
// number from, and the number the default prover produces.
pub use vos_pvm_proof::format;
pub use vos_pvm_proof::program_id::{
    ENTRY_TIMESTAMP, HALT_PC, KernelEntry, KernelProgram, LeafCircuits, ProgramId,
};
pub use vos_pvm_proof::shape::{KernelShape, SegmentClass};
pub use vos_pvm_proof::{PROOF_FORMAT_VERSION, Proof};

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
    verify_standalone_shaped(proof, preprocessed_commitment, DEFAULT_MAX_LOG_SIZE)
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
    verify_standalone_shaped(proof, preprocessed_commitment, max_log_size)
}

/// Shared verify funnel: the public `verify_standalone*` entry points
/// funnel here.
fn verify_standalone_shaped(
    mut proof: Proof,
    preprocessed_commitment: CommitmentHash,
    max_log_size: u32,
) -> Result<(), VerificationError> {
    let format = preflight_standalone(&mut proof, max_log_size)?;
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
    vos_pvm_proof::proof::check_format_security(format, &proof.pcs_config, &security_shape)
        .map_err(VerificationError::InvalidStructure)?;

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
    // the circuit). The proof's own PCS config, the format's, checked above;
    // the DEEP batching is the format's, which a proof does not carry.
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
    // `pvm/proof/tests/gates/ledger_readconsistency_gate.rs`) — see
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
        verify_standalone_shaped(proof.clone(), preprocessed_commitment, DEFAULT_MAX_LOG_SIZE)?;
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
