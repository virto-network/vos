//! The device profile (`proving.md` §8): a device kernel's program under a
//! device format (47, [`FORMAT`]; [`FORMATS`] the ones this build proves
//! and verifies), its id, a run of it proved masked on the Blake2s-M31
//! channel, a proof's bytes, and the auth statement's arguments and
//! io-hash. A space's ingress and a member's device both take it; it links
//! the masked prover without the recursion.
//!
//! - **The program** ([`Program`]) is computed from the kernel alone: the
//!   chips its code reaches (`device_chips_of_code`), and a log size each
//!   that its reference run needs, raised by its headroom, at least the
//!   masking's floor and at most `DEVICE_MAX_LOG_SIZE`; its preprocessed
//!   root committed then. The reference run's arguments are what the
//!   kernel's reference program returns ([`Program::from_kernel`]), so
//!   every node computes the same program from the installed kernel, and a
//!   release the same from the same package: nothing of the program is
//!   taken from a request. A release artifact ([`Release`]) embeds the
//!   program's shape and id ([`Program::from_release`]), so a device runs
//!   neither the reference nor the transpiler. The reference program and
//!   the reference arguments are distinct types ([`ReferenceProgram`],
//!   [`ReferenceArguments`]), so one is never passed for the other.
//! - **The trace is the program's shape:** the prover pads every chip to
//!   the program's log sizes and refuses a run that needs more
//!   ([`Error::Fit`]), so a branch-free kernel proves every witness under
//!   one program, its proof's shape the same.
//! - **The id** ([`DeviceProgramId`]) is what a binding names: BLAKE2b-256
//!   of a domain, the format's number and parameters, the chips, the log
//!   sizes and the preprocessed root, every one of which the transcript
//!   also mixes.
//! - **A proof's bytes** ([`encode`], [`decode`]) are the masked proof's
//!   postcard encoding, at most [`MAX_PROOF_BYTES`] and canonical. They
//!   hold no io-hash: the verifier takes the io-hash from the caller, who
//!   computes it from the claim it holds ([`claim_io`]), and refuses a
//!   proof with a [`Refusal`].
//! - **Errors** ([`Error`], [`Refusal`]) hold no value of a run, so any may
//!   be logged.
//! - **The masked segment** ([`masked`]) is the layer under the program:
//!   the device chip set proved and verified masked, which the forgery and
//!   leakage gates drive directly.
//! - **The hand-lean auth kernel** (the `device` test actor's, the
//!   reference the SDK form is measured against) states a kind byte, then
//!   `map_root`, `scope`, `nullifier` and `binding`, as its public
//!   arguments and no output; its arguments are the siblings, the secret,
//!   the slot and those public bytes, in that order ([`auth_arguments`]).

use vos_abi::credentials::{self, DEPTH, EMPTY, Tag, Words};
use vos_abi::ids::MethodId;
use vos_abi::{Decode, Encode};
use vos_pvm_proof::format::{DEVICE_PROOF, Format};

mod error;
pub mod masked;
mod prove;
mod verify;

pub use error::{Error, Refusal};
pub use prove::{GAS, Program, REFERENCE_GAS};
pub use verify::{Verifier, claim_io, decode, encode};
pub use vos_pvm_recair::masked::{MaskRng, MaskStats, MaskedProof};

/// A device program's id, which a binding names ([`Program::id`]): a hash
/// of the format and the program, distinct from a kernel's segment program
/// id (`vos_pvm_proof::program_id::ProgramId`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceProgramId(pub [u8; 32]);

/// A device kernel's reference program: the blob whose run returns the
/// kernel's reference arguments.
#[derive(Clone, Copy, Debug)]
pub struct ReferenceProgram<'a>(pub &'a [u8]);

/// A device kernel's reference arguments: what its reference program
/// returns, the run a program's log sizes are measured on.
#[derive(Clone, Copy, Debug)]
pub struct ReferenceArguments<'a>(pub &'a [u8]);

/// A device kernel's release artifact (`light-node.md` §4.4): method
/// `method`'s kernel of the package whose ELF hash is `elf`, and its device
/// program as every node computes it from that package
/// ([`Program::from_kernel`]): its format, its chips, its log sizes and its
/// id. A device commits the program's preprocessed tree from these
/// ([`Program::from_release`]) and checks the id it gets.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Release {
    pub elf: [u8; 32],
    pub method: MethodId,
    pub kernel: Vec<u8>,
    pub format: u32,
    pub chips: u32,
    pub log_sizes: Vec<u32>,
    /// The program's id, its [`DeviceProgramId`]'s bytes.
    pub id: [u8; 32],
}

/// The device format: format 47, the per-program CPU and the word ledger.
pub const FORMAT: Format = DEVICE_PROOF;

/// A second device format, for the tests of a node's format window: the
/// device format's AIR and parameters under number 48, which no release
/// admits (`vos_wire::defaults::DEVICE_FORMATS`). Behind
/// `test-device-format`, which no production build enables.
#[cfg(feature = "test-device-format")]
pub const TEST_FORMAT: Format = Format {
    number: 48,
    ..DEVICE_PROOF
};

/// The device formats this build proves and verifies, newest first.
#[cfg(not(feature = "test-device-format"))]
pub const FORMATS: &[Format] = &[FORMAT];
/// The device formats this build proves and verifies, newest first: the
/// device format and [`TEST_FORMAT`].
#[cfg(feature = "test-device-format")]
pub const FORMATS: &[Format] = &[FORMAT, TEST_FORMAT];

/// The device format numbered `number`, if this build proves and verifies
/// it ([`FORMATS`]).
pub fn format(number: u32) -> Option<&'static Format> {
    FORMATS.iter().find(|format| format.number == number)
}

/// The longest device proof a decode reads, in bytes: ingress's cap.
pub const MAX_PROOF_BYTES: usize = 1536 << 10;

/// The bytes of auth's public arguments: the kind byte and four digests.
pub const AUTH_PUBLIC_BYTES: usize = 1 + 4 * 32;

/// The bytes of auth's arguments: the siblings, the secret, the slot and
/// the public arguments.
pub const AUTH_ARGUMENTS_BYTES: usize = DEPTH * 32 + 32 + 4 + AUTH_PUBLIC_BYTES;

type Hasher = stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher;

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

/// The reference run's arguments of an auth kernel in the hand-lean
/// layout ([`auth_arguments`]), which the `device` test actor's reference
/// returns: a fixed secret's member at slot 0 of the empty tree, its
/// nullifier in a fixed scope, a fixed binding. A public statement of no
/// member of any space: the secret's words are the constants below, known
/// to all.
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
            claim_io(public),
            vos_pvm_precompiles::compute_device_io_hash(public, &[], &[])
        );
    }
}
