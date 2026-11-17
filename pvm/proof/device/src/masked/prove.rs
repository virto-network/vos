//! A device program's prover: its install, its kernel's runs traced at its
//! shape and proved masked.

use stwo::core::channel::MerkleChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_proof::chips::CpuColumns;
use vos_pvm_proof::device::{DEVICE_MAX_LOG_SIZE, DeviceLayout, DeviceShape, device_chips_of_code};
use vos_pvm_proof::format::Format;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::masked::{
    DeviceComponents, DeviceSizes, MaskedDeviceTrace, device_preprocessed, masked_device_trace,
};
use vos_pvm_proof::side_note::SideNote;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::masked::{Checks, Committed, MaskRng, MaskStats, MaskedTrace};
use vos_pvm_recair::trace::FirstRowFraction;
use vos_pvm_recair_air::masking::MaskedComponents;

use super::verify::{device_floors, device_format};
use super::{DeviceProgram, DeviceProof};
use crate::Error;

/// The device shape of kernel `blob` under `format`: the chips its code can
/// reach, and a log size each at least `reference`'s run needs and at least
/// its floor ([`device_floors`]). `reference` is a traced run of the kernel
/// (its witness any); the sizes it needs are the program's when the kernel
/// is branch-free.
pub fn device_shape(
    format: &Format,
    blob: &[u8],
    reference: &mut SideNote,
) -> Result<(u32, Vec<u32>), Error> {
    let layout = DeviceLayout::of_program(blob).ok_or(Error::Layout)?;
    let active = device_chips_of_code(&reference.code, &reference.bitmask);
    let shape = DeviceShape {
        chips: active,
        cpu: CpuColumns::of_code(&reference.code, &reference.bitmask),
    };
    let floors = device_floors(format, shape).ok_or(Error::Masking)?;
    let trace = masked_device_trace(reference, &layout, shape, DeviceSizes::AtLeast(&floors))
        .map_err(|_| Error::Trace)?;
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
) -> Result<DeviceProgram<MC::H>, Error>
where
    SimdBackend: BackendForChannel<MC>,
{
    DeviceProver::<MC>::install(format, blob, active, log_sizes).map(|prover| prover.program)
}

/// A device program as its prover keeps it from the install: the program
/// under its format, and what every proof of it shares, computed once
/// ([`Committed`]): the twiddles and the preprocessed tree, which each
/// proof borrows rather than committing it again.
pub struct DeviceProver<MC: MerkleChannel>
where
    SimdBackend: BackendForChannel<MC>,
{
    format: Format,
    program: DeviceProgram<MC::H>,
    committed: Committed<MC>,
}

impl<MC: MerkleChannel> DeviceProver<MC>
where
    SimdBackend: BackendForChannel<MC>,
{
    /// [`install`], its preprocessed tree kept for the proofs.
    pub fn install(
        format: &Format,
        blob: &[u8],
        active: u32,
        log_sizes: &[u32],
    ) -> Result<Self, Error> {
        let layout = DeviceLayout::of_program(blob).ok_or(Error::Layout)?;
        if !layout.is_disjoint() {
            return Err(Error::Layout);
        }
        let code = vos_pvm_proof::kernel::kernel_side_note(blob).map_err(|_| Error::Layout)?;
        if active != device_chips_of_code(&code.code, &code.bitmask) {
            return Err(Error::Chips);
        }
        let shape = DeviceShape {
            chips: active,
            cpu: CpuColumns::of_code(&code.code, &code.bitmask),
        };
        let floors = device_floors(format, shape).ok_or(Error::Masking)?;
        if floors.len() != log_sizes.len() {
            return Err(Error::Sizes);
        }
        if let Some(chip) = log_sizes
            .iter()
            .zip(&floors)
            .position(|(size, floor)| size < floor)
        {
            return Err(Error::Floor { chip });
        }
        if let Some((chip, &needs)) = log_sizes
            .iter()
            .enumerate()
            .find(|(_, size)| **size > DEVICE_MAX_LOG_SIZE)
        {
            return Err(Error::Ceiling { chip, needs });
        }
        let preprocessed =
            device_preprocessed(&code, &layout, shape, log_sizes).map_err(|_| Error::Trace)?;
        let committed =
            Committed::<MC>::new(format, log_sizes, preprocessed).ok_or(Error::Sizes)?;
        Ok(Self {
            format: *format,
            program: DeviceProgram {
                active,
                cpu: shape.cpu,
                log_sizes: log_sizes.to_vec(),
                layout,
                circuit: committed.root(),
            },
            committed,
        })
    }

    /// Its format.
    pub fn format(&self) -> &Format {
        &self.format
    }

    /// Its program, as its verifier pins it.
    pub fn program(&self) -> &DeviceProgram<MC::H> {
        &self.program
    }

    /// [`prove_device`] of its program under its format, the preprocessed
    /// tree the install's.
    pub fn prove(
        &self,
        side_note: &mut SideNote,
        rng: MaskRng,
    ) -> Result<(DeviceProof<MC::H>, MaskStats), Error> {
        prove_device_with::<MC>(
            &self.format,
            &self.program,
            Some(&self.committed),
            side_note,
            rng,
            |_| {},
            |_, _| {},
            Checks::ALL,
        )
    }
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
) -> Result<(DeviceProof<MC::H>, MaskStats), Error>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_device_with::<MC>(
        format,
        program,
        None,
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
) -> Result<(DeviceProof<MC::H>, MaskStats), Error>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_device_with::<MC>(format, program, None, side_note, rng, tamper, blind, checks)
}

/// `side_note`'s run traced at `program`'s shape: what a forged trace starts
/// from in the forgery gates.
pub fn device_trace<H: MerkleHasherLifted>(
    program: &DeviceProgram<H>,
    side_note: &mut SideNote,
) -> Result<MaskedDeviceTrace, Error> {
    masked_device_trace(
        side_note,
        &program.layout,
        program.shape(),
        DeviceSizes::Pinned(&program.log_sizes),
    )
    .map_err(|_| Error::Fit)
}

#[allow(clippy::too_many_arguments)]
fn prove_device_with<MC: MerkleChannel>(
    format: &Format,
    program: &DeviceProgram<MC::H>,
    committed: Option<&Committed<MC>>,
    side_note: &mut SideNote,
    rng: MaskRng,
    tamper: impl FnOnce(&mut MaskedDeviceTrace),
    blind: impl Fn(&AllLookupElements, &mut [FirstRowFraction]),
    checks: Checks,
) -> Result<(DeviceProof<MC::H>, MaskStats), Error>
where
    SimdBackend: BackendForChannel<MC>,
{
    device_format(format, program, &program.header()).ok_or(Error::Sizes)?;
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
        active: program.shape(),
        log_sizes: &trace.log_sizes,
        preprocessed: match committed {
            Some(_) => Vec::new(),
            None => trace.preprocessed(),
        },
        main: &|chip: usize| trace.main(chip),
        public: &public,
        interaction: &interaction,
    };
    let (proof, stats) =
        prove_masked::<MC>(format, &program.header(), masked, committed, rng, checks)?;
    Ok((
        DeviceProof {
            io: trace.io,
            proof,
        },
        stats,
    ))
}

/// The masked prover on `program`'s words, held to every check; a forced
/// proof's `checks` only on the tests' dev edge (`seeded-masks`), so a
/// production build has no path to a proof the prover's own checks refuse.
fn prove_masked<MC: MerkleChannel>(
    format: &Format,
    program: &[u64],
    trace: MaskedTrace<
        '_,
        <DeviceComponents as MaskedComponents>::Relations,
        <DeviceComponents as MaskedComponents>::Active,
    >,
    committed: Option<&Committed<MC>>,
    rng: MaskRng,
    checks: Checks,
) -> Result<(vos_pvm_recair::masked::MaskedProof<MC::H>, MaskStats), Error>
where
    SimdBackend: BackendForChannel<MC>,
{
    #[cfg(feature = "seeded-masks")]
    let proved = vos_pvm_recair::masked::prove_masked_program_forced::<MC, DeviceComponents>(
        format, program, trace, committed, rng, checks,
    );
    #[cfg(not(feature = "seeded-masks"))]
    let proved = {
        let Checks { .. } = checks;
        vos_pvm_recair::masked::prove_masked_program::<MC, DeviceComponents>(
            format, program, trace, committed, rng,
        )
    };
    // The masked prover's other refusals (R1's, the randomness', its own
    // checks of the trace's shape) are the prover's: their reasons name a
    // run's rows, and are not passed on.
    proved.map_err(|error| match error {
        ProveError::Stwo(stwo::prover::ProvingError::ConstraintsNotSatisfied) => Error::Unsatisfied,
        _ => Error::Prove,
    })
}
