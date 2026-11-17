//! A device program's verifier: its id, a proof's bytes and their check.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use vos_pvm_final_verifier::masking::MaskedFormat;
use vos_pvm_proof::format::Format;
use vos_pvm_recair::masked::MaskedProof;

use super::{DeviceProgramId, Hasher, MAX_PROOF_BYTES, Refusal};

use crate::masked::{DeviceProgram, DeviceProof, device_format, verify_device_in};

/// The domain a program id hashes first.
const PROGRAM_DOMAIN: &[u8] = b"vos/device/program/v1";

/// A program's masked format, its log sizes and words left out: computed
/// once, at its install ([`masked`]).
pub(super) type Masked = MaskedFormat<'static>;

/// `program`'s masked format under `format`, its log sizes and words left
/// for each verification to fill in from the program.
pub(super) fn masked(format: &Format, program: &DeviceProgram<Hasher>) -> Option<Masked> {
    let header = program.header();
    let (masked, _) = device_format(format, program, &header)?;
    Some(MaskedFormat {
        log_sizes: &[],
        program: &[],
        ..masked
    })
}

/// A device program as its verifier keeps it: the program, its masked
/// format and the id.
#[derive(Clone, Debug)]
pub struct Verifier {
    pub(super) format: Format,
    pub(super) program: DeviceProgram<Hasher>,
    pub(super) id: DeviceProgramId,
    pub(super) masked: Masked,
}

impl Verifier {
    /// Its id, which a binding names.
    pub fn id(&self) -> &DeviceProgramId {
        &self.id
    }

    /// The device format it verifies under.
    pub fn format(&self) -> &Format {
        &self.format
    }

    /// Verifies the proof in `bytes` ([`decode`]) of this program's kernel
    /// stating the io-hash `io`.
    pub fn verify(&self, io: &[u8; 32], bytes: &[u8]) -> Result<(), Refusal> {
        verify(&self.format, &self.program, &self.masked, io, bytes)
    }
}

pub(super) fn verify(
    format: &Format,
    program: &DeviceProgram<Hasher>,
    masked: &Masked,
    io: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Refusal> {
    let header = program.header();
    let masked = MaskedFormat {
        log_sizes: &program.log_sizes,
        program: &header,
        ..*masked
    };
    precheck(format, &masked, io, bytes)?;
    let proof = DeviceProof {
        io: *io,
        proof: decode(format, bytes)?,
    };
    verify_device_in::<Blake2sM31MerkleChannel>(&masked, program, proof).map_err(Refusal::of)
}

/// A proof's encoding's leading fields, as [`Wire`] and its STARK proof
/// start: what the interaction PoW is checked over.
#[derive(serde::Deserialize)]
struct Head {
    format_version: u32,
    interaction_pow: u64,
    #[allow(dead_code, reason = "read past, to reach the commitments")]
    claimed_sums: Vec<stwo::core::fields::qm31::SecureField>,
    #[allow(dead_code, reason = "read past, to reach the commitments")]
    config: stwo::core::pcs::PcsConfig,
    commitments: Vec<Blake2sHash>,
}

/// The device verifier's pre-check, before the proof is decoded whole: its
/// length within [`MAX_PROOF_BYTES`], its leading fields read, its format
/// `format`, and its interaction PoW holding over the program `masked`
/// names, its roots and `io` as the verifier's transcript mixes them. A proof it refuses,
/// the verifier refuses; well-formed junk that has not ground the
/// interaction PoW is refused here, at a small fraction of a decode.
fn precheck(
    format: &Format,
    masked: &MaskedFormat<'_>,
    io: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Refusal> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Refusal::Length);
    }
    let (head, _): (Head, &[u8]) = postcard::take_from_bytes(bytes).map_err(|_| Refusal::Decode)?;
    if head.format_version != format.number {
        return Err(Refusal::Format);
    }
    let public = vos_pvm_proof::masked::device_public_values(io);
    let holds = vos_pvm_final_verifier::masking::interaction_pow_holds::<Blake2sM31MerkleChannel>(
        masked,
        &public,
        &head.commitments,
        head.interaction_pow,
    );
    holds.then_some(()).ok_or(Refusal::InteractionPow)
}

impl DeviceProgramId {
    /// The id of `program` under `format`: BLAKE2b-256 of the domain, the
    /// format's number, its parameters (log blowup, queries, PoW, fold
    /// step, log last layer, interaction PoW, `log h`), the chips, the count
    /// of log sizes and each, when the CPU is cut its column words (eight
    /// little-endian bytes each), the word ledger's tag (eight
    /// little-endian bytes, `DEVICE_WORD_MEMORY_TAG`), and the preprocessed
    /// root, every other integer four little-endian bytes.
    pub fn of(format: &Format, program: &DeviceProgram<Hasher>) -> Self {
        let params = &format.params;
        let log_mask_rows = format.masking.map_or(0, |masking| masking.log_mask_rows);
        let mut hash = Blake2b::<U32>::new();
        hash.update(PROGRAM_DOMAIN);
        for word in [
            format.number,
            params.log_blowup,
            params.n_queries as u32,
            params.pow_bits,
            params.fold_step,
            params.log_last_layer,
            params.interaction_pow_bits,
            log_mask_rows,
            program.active,
            program.log_sizes.len() as u32,
        ]
        .into_iter()
        .chain(program.log_sizes.iter().copied())
        {
            hash.update(word.to_le_bytes());
        }
        if program.cpu != vos_pvm_proof::chips::CpuColumns::ALL {
            for word in program.cpu.words() {
                hash.update(word.to_le_bytes());
            }
        }
        hash.update(crate::masked::DEVICE_WORD_MEMORY_TAG.to_le_bytes());
        let Blake2sHash(root) = program.circuit;
        hash.update(root);
        Self(hash.finalize().into())
    }
}

/// The canonical encoding of a device proof's masked part.
#[derive(serde::Serialize, serde::Deserialize)]
struct Wire {
    format_version: u32,
    interaction_pow: u64,
    claimed_sums: Vec<stwo::core::fields::qm31::SecureField>,
    stark_proof: stwo::core::proof::StarkProof<Hasher>,
}

/// `proof`'s bytes under the device format `format`, the one encoding
/// [`decode`] reads; `None` when it cannot be encoded.
pub fn encode(format: &Format, proof: &MaskedProof<Hasher>) -> Option<Vec<u8>> {
    postcard::to_allocvec(&Wire {
        format_version: format.number,
        interaction_pow: proof.interaction_pow,
        claimed_sums: proof.claimed_sums.clone(),
        stark_proof: proof.stark_proof.clone(),
    })
    .ok()
}

/// The proof in `bytes` under the device format `format`: at most
/// [`MAX_PROOF_BYTES`], read whole and canonical (re-encoded, the same
/// bytes).
pub fn decode(format: &Format, bytes: &[u8]) -> Result<MaskedProof<Hasher>, Refusal> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Refusal::Length);
    }
    let (wire, rest): (Wire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| Refusal::Decode)?;
    if wire.format_version != format.number {
        return Err(Refusal::Format);
    }
    let proof = MaskedProof {
        interaction_pow: wire.interaction_pow,
        claimed_sums: wire.claimed_sums,
        stark_proof: wire.stark_proof,
    };
    if !rest.is_empty() || encode(format, &proof).as_deref() != Some(bytes) {
        return Err(Refusal::Decode);
    }
    Ok(proof)
}

/// The io-hash a device kernel states for its claim `claim`, its public
/// arguments' encoding: `H_io` of `claim`, no output and no root. `None`
/// past `H_io`'s bound.
pub fn claim_io(claim: &[u8]) -> Option<[u8; 32]> {
    vos_pvm_precompiles::compute_device_io_hash(claim, &[], &[])
}

#[cfg(test)]
mod tests {
    use super::super::FORMAT;
    use super::*;

    /// A decode refuses bytes past the cap, of another format, cut or with
    /// a byte more.
    #[test]
    fn a_decode_refuses_what_is_not_one_proof() {
        assert!(matches!(
            decode(&FORMAT, &vec![0; MAX_PROOF_BYTES + 1]),
            Err(Refusal::Length)
        ));
        assert!(decode(&FORMAT, &[]).is_err());
        let mut other = Vec::new();
        other.extend_from_slice(&postcard::to_allocvec(&44u32).unwrap());
        assert!(decode(&FORMAT, &other).is_err());
    }
}
