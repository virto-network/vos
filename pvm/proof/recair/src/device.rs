//! Device programs as a space's ingress and a member's device both take
//! them (`slice-7-mobile.md` pin J, `proving.md` §8): a device kernel's
//! program under format 45, its id, a proof's bytes, and the auth
//! statement's arguments and io-hash.
//!
//! - **The program** ([`Program`]) is computed from the kernel alone: the
//!   chips its code reaches (`device_chips_of_code`), and a log size each
//!   that a reference run needs, at least the masking's floor and at most
//!   `DEVICE_MAX_LOG_SIZE`; its preprocessed root committed then. A
//!   kernel that authorizes as auth's credential does ([`Program::auth`])
//!   takes [`auth_reference`] as its reference run's arguments, so every
//!   node computes the same program from the installed kernel, and the
//!   device the same from the same kernel: nothing of the program is taken
//!   from a request.
//! - **The trace is the program's shape:** the prover pads every chip to
//!   the program's log sizes and refuses a run that needs more, so a
//!   branch-free kernel proves every witness under one program, its
//!   proof's shape the same.
//! - **The id** ([`Program::id`]) is what a binding names: BLAKE2b-256 of
//!   a domain, the format's number and parameters, the chips, the log
//!   sizes and the preprocessed root, every one of which the transcript
//!   also mixes.
//! - **A proof's bytes** ([`encode`], [`decode`]) are the masked proof's
//!   postcard encoding, at most [`MAX_PROOF_BYTES`] and canonical. They
//!   hold no io-hash: the verifier takes the io-hash from the caller, who
//!   computes it from the words it holds ([`auth_io`]).
//! - **Auth's statement as a device kernel** states the SCALE encoding of
//!   `CredentialPublic::Auth` (the kind byte, then `map_root`, `scope`,
//!   `nullifier` and `binding`) as its public arguments and no output; its
//!   arguments are the siblings, the secret, the slot and those public
//!   bytes, in that order ([`auth_arguments`]).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::format::{DEVICE_PROOF, Format};
use vos_wire::credentials::{self, DEPTH, EMPTY, Tag, Words};

use crate::masked::device::{DeviceProgram, DeviceProof, DeviceProver, device_shape};
use crate::masked::{MaskRng, MaskStats, MaskedProof};
use crate::prove::ProveError;

/// The device format: format 45.
pub const FORMAT: Format = DEVICE_PROOF;

/// The longest device proof a decode reads, in bytes: ingress's cap.
pub const MAX_PROOF_BYTES: usize = 1536 << 10;

/// The most gas a device kernel's run is traced with, about a million: a
/// step a unit (eight times the most steps the device format's CPU holds,
/// `2^DEVICE_MAX_LOG_SIZE`), a Poseidon2 call 2,400 (auth's 43 take about a
/// tenth of it). A longer run stops out of gas rather than being traced
/// far past any program's shape.
pub const GAS: u64 = 8 << vos_pvm_proof::device::DEVICE_MAX_LOG_SIZE;

/// The bytes of auth's public arguments: the kind byte and four digests.
pub const AUTH_PUBLIC_BYTES: usize = 1 + 4 * 32;

/// The bytes of auth's arguments: the siblings, the secret, the slot and
/// the public arguments.
pub const AUTH_ARGUMENTS_BYTES: usize = DEPTH * 32 + 32 + 4 + AUTH_PUBLIC_BYTES;

/// The domain a program id hashes first.
const PROGRAM_DOMAIN: &[u8] = b"vos/device/program/v1";

type Hasher = Blake2sM31MerkleHasher;

/// A device kernel's program under format 45, as its prover and its
/// verifier pin it, and the kernel it proves.
pub struct Program {
    prover: DeviceProver<Blake2sM31MerkleChannel>,
    kernel: Vec<u8>,
    id: [u8; 32],
}

impl Program {
    /// Kernel `kernel`'s program, its log sizes the ones its run on
    /// `reference` needs (each at least its floor). Refused when the kernel
    /// does not run to its halt on `reference`, or its run needs a chip past
    /// `DEVICE_MAX_LOG_SIZE`.
    pub fn install(kernel: &[u8], reference: &[u8]) -> Result<Self, ProveError> {
        let mut run = trace(kernel, reference)?;
        let (active, log_sizes) = device_shape(&FORMAT, kernel, &mut run)?;
        let prover =
            DeviceProver::<Blake2sM31MerkleChannel>::install(&FORMAT, kernel, active, &log_sizes)?;
        let id = program_id(&FORMAT, prover.program());
        Ok(Self {
            prover,
            kernel: kernel.to_vec(),
            id,
        })
    }

    /// The program of `kernel`, a device kernel of auth's statement: its
    /// reference run on [`auth_reference`].
    pub fn auth(kernel: &[u8]) -> Result<Self, ProveError> {
        Self::install(kernel, &auth_reference())
    }

    /// Its id, which a binding names.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// The program as the verifier pins it: its chips, log sizes, layout
    /// and root.
    pub fn program(&self) -> &DeviceProgram<Hasher> {
        self.prover.program()
    }

    /// Each chip's log size, in `DEVICE_ORDER`.
    pub fn log_sizes(&self) -> &[u32] {
        &self.program().log_sizes
    }

    /// The kernel it proves.
    pub fn kernel(&self) -> &[u8] {
        &self.kernel
    }

    /// The kernel's run on `arguments`, through its witness input, proved
    /// under the program, its masks from `rng`. A run that does not halt,
    /// or needs more rows than the program's shape, is refused.
    pub fn prove(
        &self,
        arguments: &[u8],
        rng: MaskRng,
    ) -> Result<(DeviceProof<Hasher>, MaskStats), ProveError> {
        let mut run = trace(&self.kernel, arguments)?;
        let proved = self.prover.prove(&mut run, rng);
        drop(run);
        proved
    }

    /// Verifies the proof in `bytes` ([`decode`]) of this program's kernel
    /// stating the io-hash `io`.
    pub fn verify(&self, io: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        verify(self.program(), io, bytes)
    }

    /// What a verifier keeps of it: the program and its id, without the
    /// prover's committed tree.
    pub fn verifier(&self) -> Verifier {
        Verifier {
            program: self.program().clone(),
            id: self.id,
        }
    }
}

/// A device program as its verifier keeps it: what [`Program::verify`]
/// reads, and the id.
#[derive(Clone, Debug)]
pub struct Verifier {
    program: DeviceProgram<Hasher>,
    id: [u8; 32],
}

impl Verifier {
    /// Its id, which a binding names.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// [`Program::verify`].
    pub fn verify(&self, io: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        verify(&self.program, io, bytes)
    }
}

fn verify(program: &DeviceProgram<Hasher>, io: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
    let proof = DeviceProof {
        io: *io,
        proof: decode(bytes)?,
    };
    crate::masked::device::verify_device::<Blake2sM31MerkleChannel>(&FORMAT, program, &proof)
}

/// `kernel`'s run on `arguments`, traced to its halt.
fn trace(
    kernel: &[u8],
    arguments: &[u8],
) -> Result<vos_pvm_proof::side_note::SideNote, ProveError> {
    vos_pvm_proof::kernel::trace_device_kernel(kernel, arguments, GAS)
        .map(|trace| trace.side_note)
        .map_err(|error| ProveError::Segment(format!("{error:?}")))
}

/// The id of `program` under `format`: BLAKE2b-256 of the domain, the
/// format's number, its parameters (log blowup, queries, PoW, fold step,
/// log last layer, interaction PoW, `log h`), the chips, the count of log
/// sizes and each, and the preprocessed root, every integer four
/// little-endian bytes.
pub fn program_id(format: &Format, program: &DeviceProgram<Hasher>) -> [u8; 32] {
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
    let Blake2sHash(root) = program.circuit;
    hash.update(root);
    hash.finalize().into()
}

/// The canonical encoding of a device proof's masked part.
#[derive(serde::Serialize, serde::Deserialize)]
struct Wire {
    format_version: u32,
    interaction_pow: u64,
    claimed_sums: Vec<stwo::core::fields::qm31::SecureField>,
    stark_proof: stwo::core::proof::StarkProof<Hasher>,
}

/// `proof`'s bytes, the one encoding [`decode`] reads; `None` when it
/// cannot be encoded.
pub fn encode(proof: &MaskedProof<Hasher>) -> Option<Vec<u8>> {
    postcard::to_allocvec(&Wire {
        format_version: FORMAT.number,
        interaction_pow: proof.interaction_pow,
        claimed_sums: proof.claimed_sums.clone(),
        stark_proof: proof.stark_proof.clone(),
    })
    .ok()
}

/// The proof in `bytes`: at most [`MAX_PROOF_BYTES`], read whole and
/// canonical (re-encoded, the same bytes), its format 45.
pub fn decode(bytes: &[u8]) -> Result<MaskedProof<Hasher>, Error> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::Length);
    }
    let (wire, rest): (Wire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| Error::Decode)?;
    if wire.format_version != FORMAT.number {
        return Err(Error::Format);
    }
    let proof = MaskedProof {
        interaction_pow: wire.interaction_pow,
        claimed_sums: wire.claimed_sums,
        stark_proof: wire.stark_proof,
    };
    if !rest.is_empty() || encode(&proof).as_deref() != Some(bytes) {
        return Err(Error::Decode);
    }
    Ok(proof)
}

/// The io-hash a device kernel of auth's statement states for the public
/// arguments `public` (the SCALE encoding of `CredentialPublic::Auth`):
/// `H_io` of `public`, no output and no root. `None` past `H_io`'s bound.
pub fn auth_io(public: &[u8]) -> Option<[u8; 32]> {
    vos_pvm_precompiles::compute_device_io_hash(public, &[], &[])
}

/// Auth's arguments for a device kernel: the 32 siblings from the leaf's
/// level up, the secret's 32 bytes, the slot (four little-endian bytes)
/// and the public arguments `public`.
pub fn auth_arguments(
    siblings: &[Words; DEPTH],
    secret: &Words,
    slot: u32,
    public: &[u8; AUTH_PUBLIC_BYTES],
) -> Vec<u8> {
    let mut arguments = Vec::with_capacity(AUTH_ARGUMENTS_BYTES);
    for sibling in siblings {
        arguments.extend_from_slice(&credentials::digest(sibling));
    }
    arguments.extend_from_slice(&credentials::digest(secret));
    arguments.extend_from_slice(&slot.to_le_bytes());
    arguments.extend_from_slice(public);
    arguments
}

/// Auth's public arguments: kind 0, then the four digests.
pub fn auth_public(
    map_root: &[u8; 32],
    scope: &[u8; 32],
    nullifier: &[u8; 32],
    binding: &[u8; 32],
) -> [u8; AUTH_PUBLIC_BYTES] {
    let mut public = [0; AUTH_PUBLIC_BYTES];
    for (at, digest) in [map_root, scope, nullifier, binding]
        .into_iter()
        .enumerate()
    {
        public[1 + 32 * at..33 + 32 * at].copy_from_slice(digest);
    }
    public
}

/// The reference run's arguments of an auth kernel: a fixed secret's
/// member at slot 0 of the empty tree, its nullifier in a fixed scope, a
/// fixed binding. A public statement of no member of any space: the
/// secret's words are the constants below, known to all.
pub fn auth_reference() -> Vec<u8> {
    let secret: Words = core::array::from_fn(|i| 0x7e1e_0000 + i as u32);
    let scope: Words = core::array::from_fn(|i| 0x5c0e_0000 + i as u32);
    let binding: Words = core::array::from_fn(|i| 0x0b1d_0000 + i as u32);
    let siblings: [Words; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
    let member = credentials::compress(&Tag::Member.block(), &secret);
    let root = credentials::root_of(&credentials::leaf(&member), 0, &siblings);
    let nullifier =
        credentials::compress(&credentials::compress(&Tag::Nf.block(), &secret), &scope);
    let public = auth_public(
        &credentials::digest(&root),
        &credentials::digest(&scope),
        &credentials::digest(&nullifier),
        &credentials::digest(&binding),
    );
    auth_arguments(&siblings, &secret, 0, &public)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Auth's arguments are laid out as the device kernel reads them, its
    /// public bytes last; the reference's io-hash is `H_io` of them.
    #[test]
    fn auth_arguments_are_laid_out_as_the_kernel_reads_them() {
        let reference = auth_reference();
        assert_eq!(reference.len(), AUTH_ARGUMENTS_BYTES);
        let public = &reference[AUTH_ARGUMENTS_BYTES - AUTH_PUBLIC_BYTES..];
        assert_eq!(public[0], 0, "auth's kind");
        assert_eq!(
            auth_io(public),
            vos_pvm_precompiles::compute_device_io_hash(public, &[], &[])
        );
    }

    /// A decode refuses bytes past the cap, of another format, cut or with
    /// a byte more.
    #[test]
    fn a_decode_refuses_what_is_not_one_proof() {
        assert!(matches!(
            decode(&vec![0; MAX_PROOF_BYTES + 1]),
            Err(Error::Length)
        ));
        assert!(decode(&[]).is_err());
        let mut other = Vec::new();
        other.extend_from_slice(&postcard::to_allocvec(&44u32).unwrap());
        assert!(decode(&other).is_err());
    }
}
