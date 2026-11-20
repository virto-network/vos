//! The light node (`docs/design/light-node.md` §2): what a member's phone
//! runs as VOS. Each module's header says more.
//!
//! - **Local actors** ([`Light`]): one local agent on the interpreter over
//!   the light node's own store ([`Store`]), its programs release
//!   artifacts ([`release`]).
//! - **Sync** ([`mod@sync`]): each local instance one merkle-crdt scope.
//! - **The device group** ([`group`]): the user's devices as one MLS group,
//!   and the key archive.
//! - **Sealed sync** ([`personal`]): each scope's nodes sealed ([`sealed`])
//!   and read at the personal agent, over the onion alone.
//! - **The personal space's flows** ([`space`]) and **the background pass**
//!   ([`job`]).
//! - **The home** ([`home`]), **pairing** ([`pairing`]), **memberships**
//!   ([`memberships`]) and **the recovery kit** ([`kit`]).
//! - **The Tor policy** ([`route`]) and **the client over arti** (`tor`,
//!   the `tor` feature).
//!
//! **The device library** (`docs/design/proving.md` §8): what the phone
//! runs to prove facts about its device secret to its space's ingress, and
//! nothing a client or a gateway has to encode itself.
//!
//! - **The secret** ([`derive_secret`]) is derived again at each use from a
//!   secret source's 32-byte output for the space's handle, whose message
//!   is [`source_input`]; [`member`] and [`owner`] are the digests a space
//!   stores. A [`DeviceSecret`] is zeroized on drop and has no `Clone` and
//!   no `Debug`.
//! - **Proven calls** ([`Prover`]): a device kernel's run proved under the
//!   program's device format, against the program ingress computes from the
//!   same kernel, which the app embeds as a release artifact
//!   ([`release::Release`], [`DeviceProgram`]). The stock kernels of the
//!   credential actor take the secret: auth, a member's leaf under the
//!   actor's root with its nullifier in a scope ([`Prover::prove_auth`]);
//!   owner, the secret behind a row's owner digest
//!   ([`Prover::prove_owner`]). Any other kernel takes only public data
//!   ([`Prover::prove_kernel`]). A [`Call`] names what a proof authorizes;
//!   the scope and the binding are computed here, from it. [`verify`]
//!   checks a proof against its call as ingress does.
//! - **Windows:** the app proves with the newest program it ships that the
//!   space's compatibility window admits ([`choose`], the window read by
//!   [`wire::devices_request`]), and refuses before proving when it admits
//!   none.
//! - **The wire** ([`mod@wire`]): the node-API requests a client sends for
//!   its time, the tree's feed and a credentialed call, and the answers
//!   it decodes.
//! - **The tree** ([`TreeKeeper`]): the credential actor's whole tree,
//!   kept from its feed on a jittered timer, each page checked against the
//!   root its last change names; the member's path computed on the device,
//!   so no query names the member, and its proofs made against the newest
//!   root it read.
//!
//! The release artifacts are computed in the registry's device format
//! ([`vos_pvm_device::FORMAT`]); a program proves in its artifact's format,
//! one this build proves ([`vos_pvm_device::FORMATS`]). No witness is
//! logged, and its proofs' masks are the operating system's (a seeded
//! stream exists only under the `seeded-masks` test seam, which no
//! production build enables). `SECURITY.md` states what the secret is
//! exposed to.

mod call;
pub mod group;
pub mod home;
pub mod job;
mod kernel;
pub mod kit;
mod light;
pub mod memberships;
pub mod pairing;
pub mod personal;
mod prover;
pub mod release;
pub mod route;
pub mod sealed;
mod secret;
pub mod space;
pub mod store;
pub mod sync;
#[cfg(feature = "testing")]
pub mod testing;
mod threads;
#[cfg(feature = "tor")]
pub mod tor;
mod tree;
pub mod wire;

pub use call::{Call, NAME_BYTES, method_id, scope, transfer_arguments};
pub use kernel::{DEVICE_FORMAT, DeviceProgram, DeviceProof, choose, claim_io};
pub use light::{
    Config, Disk, Error, Ingest, LOCAL, Light, MAX_ARGUMENTS, Queued, RESERVE_BYTES, Replayed,
    ScopeError,
};
pub use prover::{PEAK_BYTES, Proven, Prover, ProverConfig, STACK_BYTES, Threads, verify};
pub use secret::{DeviceSecret, derive_secret, member, owner, source_input};
pub use store::{Store, StoreError};
pub use threads::thread_pool;
pub use tree::{Synced, TreeKeeper};
pub use vos_pvm_device::Error as ProgramError;

use vos_abi::credentials::{self, P};
use vos_wire::ingress::Rejection;

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

/// A member's place in the credential actor's tree, as
/// [`TreeKeeper::witness`] computes it: the tree's root, the member's slot and the 32 siblings from
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
            && credentials::member_root(&member.0, self.slot, &siblings) == self.root.0
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
    /// The device program could not be made, or a run of it not proved:
    /// why, as the device profile says (`vos_pvm_device::Error`, which
    /// holds no value of a run). Shown as [`DeviceError::Prove`] is.
    Program(ProgramError),
    /// An answer that does not decode, or is not the request's outcome.
    Decode,
    /// A proof that does not verify against its call.
    Verify,
    /// The space admits none of the programs this app ships for the
    /// kernel (`light-node.md` §4.4): its compatibility window closed, or
    /// the app is newer than the space; refused before proving.
    Window,
    /// The node could not compute one of the window's programs yet: ask
    /// again, or another replica.
    Unavailable,
    /// A proof in the home's reserved scope for a call that is not its
    /// claim (`light-node.md` §3.3).
    Reserved,
    /// The node's ingress refused the request, before its agent saw it:
    /// why, as the node said (an admission the agent asks, a stale query, a
    /// replica behind).
    Rejected(Rejection),
}

impl core::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            DeviceError::Config => "the configuration or the call is out of bounds",
            DeviceError::Memory => "the memory allowed is below a proof's",
            DeviceError::Witness => "the witness does not satisfy the statement",
            DeviceError::Prove | DeviceError::Program(_) => "the prover failed",
            DeviceError::Decode => "the answer does not decode",
            DeviceError::Verify => "the proof does not verify",
            DeviceError::Unavailable => "the node holds the space's programs not yet: ask again",
            DeviceError::Reserved => "the home's scope proves only its claim",
            DeviceError::Rejected(rejection) => {
                return write!(f, "the node's ingress refused the request: {rejection:?}");
            }
            DeviceError::Window => {
                "the space admits none of this app's programs for the kernel: the app or the \
                 space must update"
            }
        })
    }
}

impl std::error::Error for DeviceError {}

/// The BLAKE2b-256 digest of `parts` under `domain`, apart from every other
/// domain's.
pub(crate) fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use blake2::Digest as _;
    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
