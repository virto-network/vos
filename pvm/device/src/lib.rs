//! The device library (`docs/design/proving.md` §8, `slice-7-mobile.md`
//! pins K and L): what a member's phone runs to prove facts about its
//! device secret to its space's ingress, and nothing a client or a gateway
//! has to encode itself.
//!
//! - **The secret** ([`derive_secret`]) is derived again at each use from a
//!   secret source's 32-byte output for the space's handle, whose message
//!   is [`source_input`]; [`member`] and [`owner`] are the digests a space
//!   stores. A [`DeviceSecret`] is zeroized on drop and has no `Clone` and
//!   no `Debug`.
//! - **The proofs** ([`Prover`]): auth, a member's leaf under the credential
//!   actor's root with its nullifier in a scope; owner, the secret behind a
//!   row's owner digest; and membership and payment together, measured and
//!   admitted nowhere. A [`Call`] names what a proof authorizes; the scope
//!   and the binding are computed here, from it. [`verify`] checks a proof
//!   against its call as ingress does.
//! - **The wire** ([`mod@wire`]): the node-API requests a client sends for
//!   its time, its path, the root and a credentialed call, and the answers
//!   it decodes.
//! - **The path** ([`PathKeeper`]) is fetched apart from proofs: when the
//!   root moves and on a jittered timer, never because a proof is about to
//!   be made; an answer that the root is unknown drops it.
//!
//! The format is the registry's credential format
//! ([`vos_pvm_proof::format::CREDENTIAL_PROOF`]). No witness is logged, and
//! its proofs' masks are the operating system's (a seeded stream exists
//! only under the `seeded-masks` test seam, which no production build
//! enables). `SECURITY.md` states what the secret is exposed to.

mod call;
mod path;
mod prover;
mod secret;
pub mod wire;

pub use call::{Call, NAME_BYTES, scope};
pub use path::PathKeeper;
pub use prover::{
    CredentialProof, CredentialPublic, JointProof, JointPublic, PEAK_BYTES, Prover, ProverConfig,
    Threads, verify, verify_joint,
};
pub use secret::{DeviceSecret, derive_secret, member, owner, source_input};

use vos_wire::credentials::{self, P};

/// The credential format's number, the registry's.
pub const FORMAT: u32 = vos_pvm_proof::format::CREDENTIAL_PROOF.number;

const _: () = assert!(FORMAT == vos_pvm_final_verifier::credential::FORMAT);

/// A digest: eight M31 words, each below `p`. Its bytes are the words as
/// little-endian `u32`s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Digest(pub [u32; 8]);

impl Digest {
    /// The digest whose bytes are `bytes`; `None` when a word is at or
    /// above `p`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        credentials::words(bytes).map(Digest)
    }

    /// Its 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        credentials::digest(&self.0)
    }

    fn is_canonical(&self) -> bool {
        self.0.iter().all(|&word| word < P)
    }
}

/// A member's place in the credential actor's tree, as `path(member)`
/// answers it: the tree's root, the member's slot and the 32 siblings from
/// its leaf up. Its `Debug` shows neither: they place the member's leaf.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthWitness {
    pub root: Digest,
    pub slot: u32,
    pub siblings: [Digest; credentials::DEPTH],
}

impl core::fmt::Debug for AuthWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthWitness").finish_non_exhaustive()
    }
}

impl AuthWitness {
    /// Whether it places `member`'s leaf under its root.
    pub fn proves(&self, member: &Digest) -> bool {
        let siblings = self.siblings.map(|sibling| sibling.0);
        self.root.is_canonical()
            && member.is_canonical()
            && self.siblings.iter().all(Digest::is_canonical)
            && credentials::root_of(&credentials::leaf(&member.0), self.slot, &siblings)
                == self.root.0
    }
}

/// What failed, and no value: no secret, witness or proof byte is carried
/// or shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceError {
    /// The prover's configuration, or a call or scope name outside its
    /// bounds.
    Config,
    /// The configuration's memory is below what a proof takes.
    Memory,
    /// The witness does not satisfy the statement: a path to another root,
    /// a member not its secret's.
    Witness,
    /// The prover failed, or the operating system's randomness did.
    Prove,
    /// An answer that does not decode, or is not the request's outcome.
    Decode,
    /// A proof that does not verify against its call.
    Verify,
}

impl core::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            DeviceError::Config => "the configuration or the call is out of bounds",
            DeviceError::Memory => "the memory allowed is below a proof's",
            DeviceError::Witness => "the witness does not satisfy the statement",
            DeviceError::Prove => "the prover failed",
            DeviceError::Decode => "the answer does not decode",
            DeviceError::Verify => "the proof does not verify",
        })
    }
}

impl std::error::Error for DeviceError {}
