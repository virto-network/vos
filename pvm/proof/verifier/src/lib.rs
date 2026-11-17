//! The native verifier of a segment proof (format 41), from the proof and
//! its program's preprocessed root alone, no trace.
//!
//! [`verify_standalone`] is the reference a leaf circuit is held to: the
//! recursion's in-AIR verifier (`vos-pvm-recair`'s leaf) replays the checks
//! it makes (`docs/design/proving.md` A.1), and the recursion's tests hold
//! the leaf to it. No production path calls it: a node verifies a kernel's
//! segments inside its leaves, and a venue the wrap alone.
//! [`verify_kernel_segment`] and [`verify_kernel_chain`] add a kernel's
//! shape and entry, its program id's preimage.
//!
//! **No production build links this crate.** It is the reference the
//! leaf is tested against and the compile check of `vos-pvm-proof`'s
//! verifier-only configuration (`just check-no-std`); nodes and venues
//! verify through the leaf, the wrap and the device verifier instead
//! (`../AUDIT.md`).
//!
//! `no_std`: `vos-pvm-proof` without its `prover` feature pulls no `vos_pvm`
//! and no rayon, and builds for `wasm32-unknown-unknown`.

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

// The proof type, and the format registry `verify_standalone` admits a
// proof's number from.
pub use vos_pvm_proof::Proof;
pub use vos_pvm_proof::format;
pub use vos_pvm_proof::program_id::{
    ENTRY_TIMESTAMP, HALT_PC, KernelEntry, KernelProgram, LeafCircuits, ProgramId,
};
pub use vos_pvm_proof::shape::{ClassShape, KernelShape};

use vos_pvm_proof::framework_access::{
    AllLookupElements, create_verifier_components, draw_all_lookup_elements,
};

/// Verification hash type — the preprocessed-trace Merkle root, in the hash
/// of the proof's format.
pub use vos_pvm_proof::pcs::Commitment as CommitmentHash;

/// The per-component log size cap `verify_standalone` applies, the
/// protocol's.
pub use vos_pvm_proof::proof::MAX_PROOF_LOG_SIZE as DEFAULT_MAX_LOG_SIZE;

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
    mut proof: Proof,
    preprocessed_commitment: CommitmentHash,
) -> Result<(), VerificationError> {
    let format = preflight_standalone(&mut proof, DEFAULT_MAX_LOG_SIZE)?;
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
    let format = vos_pvm_proof::proof::preflight_proof_structure(proof, max_log_size)?;
    // `component_mask = 0` reads as every chip, and its only producer is
    // the chip-isolated `prove_with_explicit_components` path, whose proofs
    // are not verifiable via `verify_standalone`.
    //
    // Reject early, before any cryptographic work: such a proof names no
    // positions for the boundary chips, through which the standalone
    // verifier binds `proof.{initial,final}_state`.
    if proof.component_mask == 0 {
        return Err(VerificationError::InvalidStructure(
            "component_mask = 0 is invalid here \
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
        )?;
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
    Ok(vos_pvm_proof::proof::format_security_bits(
        format,
        &proof.pcs_config,
        &shape,
    )?)
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
    vos_pvm_proof::proof::check_format_security(format, &proof.pcs_config, &security_shape)?;

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
    // boundary states. The proof's own PCS config, the format's, checked above;
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
    )?;

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
    )?;
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
        .map_err(VerificationError::from)
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
    program.check()?;
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
    program.check()?;
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
    vos_pvm_proof::proof::check_continuity(&proofs)?;
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
