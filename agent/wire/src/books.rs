//! The light node's first local actors' wire types (`light-node.md` §3.1):
//! what the credential book and the device book take and answer, so the
//! app reads their queries without either actor's crate.
//!
//! - **The credential book:** each space the user is a member of
//!   ([`Enrolled`]), each device's handle and digests there
//!   ([`DeviceHandle`]) and each method pinned ([`Pinned`]).
//! - **The device book:** each device's label and settings, by its id in
//!   the device set; its bounds are [`LABEL_BYTES`], [`SETTING_BYTES`] and
//!   [`VALUE_BYTES`].

use alloc::string::String;
use alloc::vec::Vec;

use scale::{Decode, Encode};

/// The credential book's handlers.
pub mod credential_book {
    methods! {
        JOIN = "join";
        LEAVE = "leave";
        HANDLE = "handle";
        UNHANDLE = "unhandle";
        PIN = "pin";
        UNPIN = "unpin";
        MEMBER_OF = "member_of";
        SPACES = "spaces";
        HANDLES = "handles";
        PINS = "pins";
    }
}

/// The device book's handlers.
pub mod device_book {
    methods! {
        LABEL = "label";
        UNLABEL = "unlabel";
        SET = "set";
        UNSET = "unset";
        LABEL_OF = "label_of";
        LABELS = "labels";
        SETTINGS = "settings";
    }
}

/// The most bytes a space's name, a pinned method's, or a guard's scope
/// takes; none is empty.
pub const NAME_BYTES: usize = 64;

/// The most agents a membership lists.
pub const AGENTS: usize = 16;

/// The most bytes a device's label takes.
pub const LABEL_BYTES: usize = 64;

/// The most bytes a setting's name takes; none is empty.
pub const SETTING_BYTES: usize = 32;

/// The most bytes a setting's value takes.
pub const VALUE_BYTES: usize = 1024;

/// A space's id.
pub type Space = [u8; 32];

/// An actor's place in a space: its agent and instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Location {
    pub agent: u32,
    pub instance: u32,
}

/// An agent of a space, and the identity its queries are signed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Agent {
    pub agent: u32,
    pub identity: [u8; 32],
}

/// A space the user is a member of, as the user confirmed it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Enrolled {
    pub name: String,
    /// The credential actor, whose tree the members' leaves are in.
    pub credentials: Location,
    pub agents: Vec<Agent>,
}

/// A device's handle in a space, which its secret source is asked for,
/// and the member and owner digests of its secret there: the device as the
/// registrar's person record holds it, which another of the user's devices
/// names to `enroll_device` and `revoke_device`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DeviceHandle {
    pub handle: [u8; 32],
    pub member: [u8; 32],
    pub owner: [u8; 32],
}

/// The guard a pinned method proves under.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Guard {
    /// Membership, its nullifier in the scope `scope`; `once` admits each
    /// device's nullifier once there, so a member once a device.
    #[codec(index = 0)]
    Auth { scope: String, once: bool },
    /// Ownership of a ledger account.
    #[codec(index = 1)]
    Owner,
}

/// A method a device may prove for: where, its name, and its guard.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Pinned {
    pub at: Location,
    pub method: String,
    pub guard: Guard,
}

/// What a book's merge handler refuses: its operation is never recorded,
/// and a device applying a peer's quarantines it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum BookError {
    /// A name, a label or a value past its bound or empty where it may not
    /// be, or a membership's agents past [`AGENTS`].
    #[codec(index = 0)]
    Bounds,
}

/// Whether `name` is one the credential book keeps: 1 to [`NAME_BYTES`]
/// bytes.
pub fn named(name: &str) -> bool {
    !name.is_empty() && name.len() <= NAME_BYTES
}
