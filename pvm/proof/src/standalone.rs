//! The native verifier of a segment proof, from the proof and its
//! program's preprocessed root alone, no trace: the one copy of its checks.
//! `vos-pvm-proof-verifier` re-exports it as its `verify_standalone`, the
//! reference a leaf circuit is held to; [`crate::verify`] (the prover's,
//! with the side note) is this verifier against the root it commits again
//! from the side note.
//!
//! The order: the proof's structure and its component mask; its shape and
//! dimensions against the AIR the mask selects; the format's floors and
//! parameters; the boundary timestamps' range; the preprocessed root; the
//! transcript through the interaction root; the logup sum; the boundary
//! binding; the query count; then Stwo's verifier.

use alloc::{boxed::Box, format, string::ToString, vec::Vec};
use num_traits::Zero;
use stwo::core::{
    air::Component,
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
    proof::StarkProof,
    verifier::VerificationError,
};
use stwo_constraint_framework::{PREPROCESSED_TRACE_IDX, TraceLocationAllocator};

use crate::format::Format;
use crate::framework_access::{
    AllLookupElements, create_verifier_components, draw_all_lookup_elements,
};
use crate::pcs::{Commitment, PcsStack, ProofHash};
use crate::proof::{MAX_PROOF_LOG_SIZE, Proof};

/// The bound on a segment's boundary timestamps: both of a verified
/// segment's lie in `[1, 2^28)`.
///
/// The ledgers compare timestamps reduced into M31: the key `2·ts +
/// is_write`, checked to grow by under 2^28 from one access of a register
/// or a byte to the next (`chips/register_memory.rs`, `chips/memory.rs`),
/// so two accesses about 2^30 steps apart alias. The CPU's timestamp is a
/// 64-bit counter nothing else bounds (no gas is proved). What keeps the
/// alias unreachable is the segment's own anchor: every register's and
/// every byte's chain starts at a `ts = 0` boundary write, so its first
/// access lies under 2^27 (mod p/2), and the segment's steps, at most its
/// class's, keep every later one far under 2^28. A segment whose
/// timestamps lie in `[2^27, p/2)` is therefore unprovable, a soundness
/// bound and not a completeness limit alone, and a run, its segments
/// contiguous from ts 1, cannot cross that zone. This bound states the same
/// for a single segment verified alone, where nothing else bounds its
/// initial timestamp. The leaf circuit does not range-check the
/// timestamp's bytes; it rests on the fold chain's induction instead
/// (`vos_pvm_recair::leaf`, `docs/design/open.md`).
pub const TIMESTAMP_BOUND: u64 = 1 << 28;

/// Verify a segment proof against its program's preprocessed root,
/// `preprocessed_commitment`: the class's program identity (its code,
/// layout and permissions at its shape), which the caller computes once per
/// program.
pub fn verify_standalone(
    proof: Proof,
    preprocessed_commitment: Commitment,
) -> Result<(), VerificationError> {
    verify_at(proof, |_, _| Ok(preprocessed_commitment))
}

/// [`verify_standalone`], the root `root` returns for the proof and its
/// format, called after every structural and parameter check, before any
/// cryptographic one.
pub(crate) fn verify_at(
    mut proof: Proof,
    root: impl FnOnce(&'static Format, &Proof) -> Result<Commitment, VerificationError>,
) -> Result<(), VerificationError> {
    let format = preflight(&mut proof, MAX_PROOF_LOG_SIZE)?;
    crate::with_stack!(format.channel, Stack => {
        verify_on::<Stack>(proof, format, root)
    }, unbuilt => Err(VerificationError::InvalidStructure(format!(
        "format {}'s channel is not built",
        format.number
    ))))
}

/// What every path checks before any cryptographic work, and every later
/// length check assumes: the proof's structure, every log size under
/// `max_log_size` (so a malicious prover can't force arbitrarily large
/// Merkle commitments), its format, admitted and with its Stark proof on the
/// format's channel, and a component mask this AIR generation binds.
fn preflight(proof: &mut Proof, max_log_size: u32) -> Result<&'static Format, VerificationError> {
    let format = crate::proof::preflight_proof_structure(proof, max_log_size)?;
    // `component_mask = 0` reads as every chip, and its only producer is
    // the chip-isolated `prove_with_explicit_components` path, whose proofs
    // are not verifiable here.
    //
    // Reject early, before any cryptographic work: such a proof names no
    // positions for the boundary chips, through which the verifier binds
    // `proof.{initial,final}_state`.
    if proof.component_mask == 0 {
        return Err(VerificationError::InvalidStructure(
            "component_mask = 0 is invalid here \
             (chip-isolated proofs must use verify_with_explicit_components)"
                .to_string(),
        ));
    }
    let supported_mask = 1u32
        .checked_shl(crate::chip_idx::COUNT as u32)
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
fn shape<MC: PcsStack>(
    log_sizes: &[u32],
    component_mask: u32,
    claimed_sums: &[SecureField],
    config: &PcsConfig,
    stark: &StarkProof<MC::H>,
) -> Result<
    (
        TreeVec<Vec<u32>>,
        crate::proof::ProofProtocolShape,
        crate::security::SecurityShape,
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
    let (protocol_shape, security_shape) = crate::framework_access::preflight_component_dimensions(
        config,
        stark,
        &shape_component_refs,
        &expected_log_sizes,
    )?;
    Ok((expected_log_sizes, protocol_shape, security_shape))
}

/// A proof's two security counts ([`crate::security`]), at its own
/// parameters and shape, after the structural checks [`verify_standalone`]
/// runs first. No cryptographic check is made.
pub fn proof_security_bits(
    proof: &Proof,
) -> Result<crate::security::SecurityBits, VerificationError> {
    let mut proof = proof.clone();
    let format = preflight(&mut proof, MAX_PROOF_LOG_SIZE)?;
    let config = format.verifier_config(&proof.pcs_config);
    let shape = crate::with_stack!(format.channel, Stack => {
        let stark = Stack::stark(&proof.stark_proof).ok_or_else(|| {
            VerificationError::InvalidStructure("Stark proof channel differs".to_string())
        })?;
        shape::<Stack>(
            &proof.log_sizes,
            proof.component_mask,
            &proof.claimed_sums,
            &config,
            stark,
        )?
        .2
    }, unbuilt => return Err(VerificationError::InvalidStructure(format!(
        "format {}'s channel is not built",
        format.number
    ))));
    Ok(crate::proof::format_security_bits(format, &config, &shape)?)
}

fn verify_on<MC: PcsStack>(
    proof: Proof,
    format: &'static Format,
    root: impl FnOnce(&'static Format, &Proof) -> Result<Commitment, VerificationError>,
) -> Result<(), VerificationError> {
    // The proof's parameters with its format's DEEP batching, which a proof
    // does not carry.
    let config = format.verifier_config(&proof.pcs_config);
    let stark = MC::stark(&proof.stark_proof).ok_or_else(|| {
        VerificationError::InvalidStructure("Stark proof channel differs".to_string())
    })?;
    let (log_sizes, protocol_shape, security_shape) = shape::<MC>(
        &proof.log_sizes,
        proof.component_mask,
        &proof.claimed_sums,
        &config,
        stark,
    )?;
    // The format's floors, counted at this proof's own parameters and
    // shape, and its exact parameters.
    crate::proof::check_format_security(format, &config, &security_shape)?;

    // Step timestamps start at 1, so `initial_ts ≥ 1` excludes the ts = 0
    // per-page and per-register boundary writes from being forged as real
    // steps, and (with the CpuChip ts-chain) lands every step ts in
    // [initial_ts, final_ts). Both under `TIMESTAMP_BOUND`, the range the
    // ledgers' mod-p comparison is sound in.
    if proof.initial_state.timestamp < 1 {
        return Err(VerificationError::InvalidStructure(
            "initial_state.timestamp must be >= 1 (memory-boundary anchoring)".to_string(),
        ));
    }
    if proof.initial_state.timestamp >= TIMESTAMP_BOUND
        || proof.final_state.timestamp >= TIMESTAMP_BOUND
    {
        return Err(VerificationError::InvalidStructure(
            "a boundary timestamp at or above 2^28 (the ledgers' range)".to_string(),
        ));
    }

    let expected = root(format, &proof)?;
    let actual = stark.commitments[PREPROCESSED_TRACE_IDX].into_commitment();
    if actual != expected {
        return Err(VerificationError::InvalidStructure(format!(
            "preprocessed commitment mismatch: expected {expected}, got {actual}"
        )));
    }

    // The transcript through the interaction root, as the prover ran it: the
    // boundary states (the `component_mask = 0` reject above guarantees a
    // proof with the boundary and closing chips) and the interaction PoW
    // precede the relation elements, which therefore depend on the claimed
    // boundary states.
    let verifier_channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);
    let lookup_elements = crate::proof::replay_prefix::<MC>(
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

    if proof.claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    // Boundary public-input binding: each boundary chip's claimed sum must
    // equal the value recomputed from the proof's public boundary states
    // with the drawn lookup elements. This BINDS `proof.{initial,final}_state`
    // to the committed boundary columns; the transcript's mix alone is only
    // tamper-evidence against post-prove edits, not against a from-scratch
    // prover. pc/timestamp columns are pinned to the trace by CpuChip
    // program-execution chaining; the register columns (and the io-hash read
    // from `final_state.registers[9..13]`) are pinned to the trace by
    // `RegisterMemoryChip` read-consistency (a cross-row `#[mask_next_row]`
    // `prev_value` binding, a range-checked `(reg, ts)` sortedness gadget,
    // and an `is_write` tuple limb), which is sound against a from-scratch
    // prover (gate: `pvm/proof/tests/gates/ledger_readconsistency_gate.rs`;
    // `crate::boundary_binding`, `chips/register_memory_closing.rs`). A mask
    // missing any binding chip cannot bind its boundary states and is
    // refused outright (all three are active in every production proof).
    let Some(boundary_positions) =
        crate::boundary_binding::boundary_positions_in_mask(proof.component_mask)
    else {
        return Err(VerificationError::InvalidStructure(
            "component_mask lacks a boundary-binding chip \
             (RegisterMemoryBoundary / RegisterMemoryClosing / ProgramBoundary)"
                .to_string(),
        ));
    };
    crate::boundary_binding::check_boundary_claimed_sums(
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

    let sampled_queries = crate::proof::expected_fiat_shamir_query_count::<MC>(
        verifier_channel,
        stark,
        &config,
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
