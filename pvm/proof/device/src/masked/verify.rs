//! A device program's verifier: the masked format it pins, and a proof's
//! check against it.

use num_traits::Zero;
use stwo::core::channel::MerkleChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::masking::{Claim, MaskedFormat, verify_masked};
use vos_pvm_proof::device::{DEVICE_MAX_LOG_SIZE, DeviceShape};
use vos_pvm_proof::format::Format;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::masked::{DeviceComponents, device_bound_sums, device_public_values};
use vos_pvm_recair::masked::{Reveal, mask_rows, reveals, verifier_format};
use vos_pvm_recair_air::masking::MaskedComponents;

use super::{DeviceProgram, DeviceProof};

/// Each of the chips `active` names padded to four times its `h` under
/// `format` ([`mask_rows`]), in `DEVICE_ORDER`: the least log sizes a
/// device program's chips may take. `None` for an unmasked format, a mask
/// that is not a device's, or a chip whose `h` is below the rows a column
/// of it reveals ([`Reveal`], `proving.md` §5), which R1 would refuse on
/// every transcript: such a format is refused at the install, before any
/// proof.
pub fn device_floors(format: &Format, shape: DeviceShape) -> Option<Vec<u32>> {
    let any = format.masking?.log_mask_rows + 2;
    let chips = DeviceComponents::chips(shape)?;
    let layout = DeviceComponents::layout(shape, &vec![any; chips.len()])?;
    let rows = mask_rows(format, &layout)?;
    let covered = reveals(format, &layout)?
        .iter()
        .zip(&rows)
        .all(|(reveal, &h)| reveal.rows <= 1 << h);
    covered.then(|| rows.iter().map(|h| h + 2).collect())
}

/// What each of the chips `active` names, at `log_sizes`, reveals of its
/// randomizer under `format` ([`Reveal`]), beside its `log2 h`
/// ([`mask_rows`]), in `DEVICE_ORDER`. `None` for an unmasked format or a
/// shape the device set refuses.
pub fn device_reveals(
    format: &Format,
    shape: DeviceShape,
    log_sizes: &[u32],
) -> Option<Vec<(Reveal, u32)>> {
    let layout = DeviceComponents::layout(shape, log_sizes)?;
    let reveals = reveals(format, &layout)?;
    let rows = mask_rows(format, &layout)?;
    Some(reveals.into_iter().zip(rows).collect())
}

/// The masked format `format` pins for `program`, as its verifier takes it,
/// and its chips laid out. `None` when a log size is under its floor or
/// above `DEVICE_MAX_LOG_SIZE`, where the device format's count stops
/// holding: the prover and the verifier both refuse such a program,
/// however it was made.
pub fn device_format<'a, H: MerkleHasherLifted>(
    format: &Format,
    program: &'a DeviceProgram<H>,
    header: &'a [u64],
) -> Option<(MaskedFormat<'a>, DeviceComponents)> {
    let floors = device_floors(format, program.shape())?;
    let fits = floors.len() == program.log_sizes.len()
        && program
            .log_sizes
            .iter()
            .zip(&floors)
            .all(|(&size, &floor)| floor <= size && size <= DEVICE_MAX_LOG_SIZE);
    if !fits {
        return None;
    }
    let layout = DeviceComponents::layout(program.shape(), &program.log_sizes)?;
    let masked = verifier_format(format, &program.log_sizes, &layout)?;
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
    let (masked, _) = device_format(format, program, &header).ok_or(Error::Format)?;
    verify_device_in::<MC>(&masked, program, proof.clone())
}

/// [`verify_device`] under `masked`, the program's masked format as
/// [`device_format`] gives it: a verifier holding a program computes that
/// once.
pub fn verify_device_in<MC: MerkleChannel>(
    masked: &MaskedFormat<'_>,
    program: &DeviceProgram<MC::H>,
    proof: DeviceProof<MC::H>,
) -> Result<(), Error> {
    let layout =
        DeviceComponents::layout(program.shape(), &program.log_sizes).ok_or(Error::Format)?;
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
    verify_masked::<MC, DeviceComponents>(masked, &claim, &layout, proof.proof.stark_proof)
}
