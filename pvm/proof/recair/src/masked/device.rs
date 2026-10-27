//! The device profile's masked segment (`docs/design/slice-7-mobile.md`,
//! pin J): a kernel's whole run proved masked over the device's chip set
//! (`vos_pvm_proof::device`), verified against its program.
//!
//! - **The program** ([`DeviceProgram`], [`install`]) is computed from the
//!   kernel alone, never taken from a proof: its chips (what its code can
//!   reach), a log size each, its layout, and the preprocessed root those
//!   commit (its code, its data table, its regions and permissions, its
//!   entry registers). The transcript mixes its chips right after the
//!   header ([`DeviceProgram::header`]), beside the format, the log sizes
//!   and, as the first commitment, the root.
//! - **The proof** ([`DeviceProof`]) states the io-hash, φ9..12 at the
//!   halt, and nothing else: the public values after the main tree's root
//!   are its 32 bytes, DeviceIoChip's claimed sum the one the verifier
//!   recomputes from them, every other blinded.
//! - **The trace is the program's shape** (pin J's witness-independent
//!   trace): every chip at its program's log size, the prover refusing a run
//!   that needs more ([`vos_pvm_proof::ProvingError::Shape`]), so a proof's
//!   shape never depends on its witness. A kernel whose step count does not depend on its
//!   witness (branch-free) proves every witness under one program.

use num_traits::Zero;
use stwo::core::channel::MerkleChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, ComponentProver};
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::masked::{Claim, MaskedFormat, verify_masked};
use vos_pvm_proof::device::{DEVICE_MAX_LOG_SIZE, DeviceLayout, device_chips_of_code};
use vos_pvm_proof::format::Format;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::masked::{
    ChipSet, Components, DeviceComponents, DeviceSizes, MaskedDeviceTrace, device_bound_sums,
    device_preprocessed, device_public_values, masked_device_trace,
};
use vos_pvm_proof::side_note::SideNote;
use vos_pvm_recair_air::masked::MaskedComponents;

use super::{Checks, MaskRng, MaskStats, MaskedProof, MaskedProvers, MaskedTrace, mask_rows};
use crate::prove::ProveError;
use crate::trace::FirstRowFraction;

impl<S: ChipSet> MaskedProvers for Components<S> {
    fn provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        Components::provers(self)
    }
}

/// The word the transcript mixes before a device program's chips.
pub const DEVICE_PROGRAM_TAG: u64 = u64::from_le_bytes(*b"VOS/DEV1");

/// A device program, as its verifier pins it: its chips, their log sizes,
/// its layout and the preprocessed root they commit under its format.
#[derive(Clone, Debug)]
pub struct DeviceProgram<H: MerkleHasherLifted> {
    /// The chips, a device mask (`vos_pvm_proof::device::device_chip`).
    pub active: u32,
    /// Each chip's log size, in `DEVICE_ORDER`.
    pub log_sizes: Vec<u32>,
    pub layout: DeviceLayout,
    /// The preprocessed root.
    pub circuit: H::Hash,
}

impl<H: MerkleHasherLifted> DeviceProgram<H> {
    /// The words the transcript mixes right after the header: the tag and
    /// the chips. The header holds the format and the log sizes; the first
    /// commitment, the preprocessed root.
    pub fn header(&self) -> [u64; 2] {
        [DEVICE_PROGRAM_TAG, u64::from(self.active)]
    }
}

/// A device proof: the io-hash it states and the masked proof.
#[derive(Clone, Debug)]
pub struct DeviceProof<H: MerkleHasherLifted> {
    /// φ9..12 at the halt, 32 LE bytes.
    pub io: [u8; 32],
    pub proof: MaskedProof<H>,
}

/// Each of the chips `active` names padded to four times its `h` under
/// `format` ([`mask_rows`]), in `DEVICE_ORDER`: the least log sizes a
/// device program's chips may take. `None` for an unmasked format or a mask
/// that is not a device's.
pub fn device_floors(format: &Format, active: u32) -> Option<Vec<u32>> {
    let any = format.masking?.log_mask_rows + 2;
    let chips = vos_pvm_proof::masked::Device::chips(active)?;
    let layout = DeviceComponents::layout(active, &vec![any; chips.len()])?;
    Some(mask_rows(format, &layout)?.iter().map(|h| h + 2).collect())
}

/// The device shape of kernel `blob` under `format`: the chips its code can
/// reach, and a log size each at least `reference`'s run needs and at least
/// its floor ([`device_floors`]). `reference` is a traced run of the kernel
/// (its witness any); the sizes it needs are the program's when the kernel
/// is branch-free.
pub fn device_shape(
    format: &Format,
    blob: &[u8],
    reference: &mut SideNote,
) -> Result<(u32, Vec<u32>), ProveError> {
    let layout =
        DeviceLayout::of_program(blob).ok_or(ProveError::TraceShape("not a standard program"))?;
    let active = device_chips_of_code(&reference.code, &reference.bitmask);
    let floors = device_floors(format, active).ok_or(ProveError::TraceShape(
        "the format's masking does not fit the chips",
    ))?;
    let trace = masked_device_trace(reference, &layout, active, DeviceSizes::AtLeast(&floors))
        .map_err(|error| ProveError::Segment(error.to_string()))?;
    Ok((active, trace.log_sizes.clone()))
}

/// Kernel `blob`'s device program under `format` on `MC`'s trees, at the
/// chips `active` and the log sizes `log_sizes`: its layout and its
/// preprocessed root, computed from the kernel alone. Refused when `active`
/// is not the chips its code reaches, a log size is under its floor, or one
/// is above `DEVICE_MAX_LOG_SIZE`, where the format's count stops holding.
pub fn install<MC: MerkleChannel>(
    format: &Format,
    blob: &[u8],
    active: u32,
    log_sizes: &[u32],
) -> Result<DeviceProgram<MC::H>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let layout =
        DeviceLayout::of_program(blob).ok_or(ProveError::TraceShape("not a standard program"))?;
    if !layout.is_disjoint() {
        return Err(ProveError::TraceShape("the layout's regions overlap"));
    }
    let code = vos_pvm_proof::kernel::kernel_side_note(blob)
        .map_err(|error| ProveError::Segment(format!("{error:?}")))?;
    if active != device_chips_of_code(&code.code, &code.bitmask) {
        return Err(ProveError::TraceShape("the chips are not the code's"));
    }
    let floors = device_floors(format, active).ok_or(ProveError::TraceShape(
        "the format's masking does not fit the chips",
    ))?;
    if floors.len() != log_sizes.len() || log_sizes.iter().zip(&floors).any(|(s, f)| s < f) {
        return Err(ProveError::TraceShape("a log size under its floor"));
    }
    if log_sizes.iter().any(|&size| size > DEVICE_MAX_LOG_SIZE) {
        return Err(ProveError::TraceShape(
            "a log size above the device format's reference",
        ));
    }
    let preprocessed = device_preprocessed(&code, &layout, active, log_sizes)
        .map_err(|error| ProveError::Segment(error.to_string()))?;
    let lifting = super::lifting_log_size(format, log_sizes)
        .ok_or(ProveError::TraceShape("a component's log size overflows"))?;
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(lifting).circle_domain().half_coset);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(format.pcs_config(), &twiddles);
    let mut builder = scheme.tree_builder();
    builder.extend_polys(super::extend_preprocessed(preprocessed, &twiddles));
    builder.commit(&mut MC::C::default());
    Ok(DeviceProgram {
        active,
        log_sizes: log_sizes.to_vec(),
        layout,
        circuit: scheme.roots()[0],
    })
}

/// `side_note`'s run of `program`'s kernel, traced whole, proved masked
/// under `format` on `MC`'s trees and channel at the program's shape, its
/// masks from `rng`. A run that needs more rows than the program's shape is
/// refused.
pub fn prove_device<MC: MerkleChannel>(
    format: &Format,
    program: &DeviceProgram<MC::H>,
    side_note: &mut SideNote,
    rng: MaskRng,
) -> Result<(DeviceProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_device_with::<MC>(
        format,
        program,
        side_note,
        rng,
        |_| {},
        |_, _| {},
        Checks::ALL,
    )
}

/// [`prove_device`], the trace through `tamper` before it is committed,
/// each chip's blinding fraction through `blind`, the prover held to
/// `checks` alone: the forgery gates' forced proofs. Only the tests' dev
/// edge has it (`seeded-masks`).
#[cfg(feature = "seeded-masks")]
pub fn prove_device_forced<MC: MerkleChannel>(
    format: &Format,
    program: &DeviceProgram<MC::H>,
    side_note: &mut SideNote,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MaskedDeviceTrace),
    blind: impl Fn(&AllLookupElements, &mut [FirstRowFraction]),
    checks: Checks,
) -> Result<(DeviceProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_device_with::<MC>(format, program, side_note, rng, tamper, blind, checks)
}

/// `side_note`'s run traced at `program`'s shape: what a forged trace starts
/// from in the forgery gates.
pub fn device_trace<H: MerkleHasherLifted>(
    program: &DeviceProgram<H>,
    side_note: &mut SideNote,
) -> Result<MaskedDeviceTrace, ProveError> {
    masked_device_trace(
        side_note,
        &program.layout,
        program.active,
        DeviceSizes::Pinned(&program.log_sizes),
    )
    .map_err(|error| ProveError::Segment(error.to_string()))
}

fn prove_device_with<MC: MerkleChannel>(
    format: &Format,
    program: &DeviceProgram<MC::H>,
    side_note: &mut SideNote,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MaskedDeviceTrace),
    blind: impl Fn(&AllLookupElements, &mut [FirstRowFraction]),
    checks: Checks,
) -> Result<(DeviceProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let mut trace = device_trace(program, side_note)?;
    let side_note: &SideNote = side_note;
    tamper(&mut trace);
    let public = trace.public();
    let interaction = |relations: &AllLookupElements, blinding: &[FirstRowFraction]| {
        let mut fractions = blinding.to_vec();
        blind(relations, &mut fractions);
        let fractions: Vec<(SecureField, SecureField)> = fractions
            .iter()
            .map(|fraction| (fraction.numerator, fraction.denominator))
            .collect();
        trace.interaction(side_note, relations, &fractions)
    };
    let masked = MaskedTrace {
        active: program.active,
        log_sizes: &trace.log_sizes,
        preprocessed: trace.preprocessed(),
        main: &|chip: usize| trace.main(chip),
        public: &public,
        interaction: &interaction,
    };
    let (proof, stats) = super::prove_masked_program::<MC, DeviceComponents>(
        format,
        &program.header(),
        masked,
        rng,
        checks,
    )?;
    Ok((
        DeviceProof {
            io: trace.io,
            proof,
        },
        stats,
    ))
}

/// The masked format `format` pins for `program`, as its verifier takes it,
/// and its chips laid out.
pub fn device_format<'a, H: MerkleHasherLifted>(
    format: &Format,
    program: &'a DeviceProgram<H>,
    header: &'a [u64],
) -> Option<(MaskedFormat<'a>, DeviceComponents)> {
    let layout = DeviceComponents::layout(program.active, &program.log_sizes)?;
    let masked = super::verifier_format(format, &program.log_sizes, &layout)?;
    Some((
        MaskedFormat {
            program: header,
            ..masked
        },
        layout,
    ))
}

/// Verifies `proof` of `program` under `format`: the masked transcript with
/// the program's chips mixed after the header, the preprocessed root the
/// program's, the claimed sums' total zero and DeviceIoChip's the one the
/// io-hash fixes. Nothing of the program is read from the proof.
pub fn verify_device<MC: MerkleChannel>(
    format: &Format,
    program: &DeviceProgram<MC::H>,
    proof: &DeviceProof<MC::H>,
) -> Result<(), Error> {
    let header = program.header();
    let (masked, layout) = device_format(format, program, &header).ok_or(Error::Format)?;
    let public = device_public_values(&proof.io);
    let zero = |_: &AllLookupElements| SecureField::zero();
    let bound = |relations: &AllLookupElements, sums: &[SecureField]| {
        device_bound_sums(program.active, &proof.io, relations, sums)
    };
    let claim = Claim {
        log_sizes: &program.log_sizes,
        circuit: Some(program.circuit),
        public: &public,
        public_sum: Some(&zero),
        bound_sums: Some(&bound),
        interaction_pow: proof.proof.interaction_pow,
        claimed_sums: &proof.proof.claimed_sums,
    };
    verify_masked::<MC, DeviceComponents>(&masked, &claim, &layout, proof.proof.stark_proof.clone())
}
