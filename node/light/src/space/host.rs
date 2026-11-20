//! What the personal space's flows take from the app that embeds them: its
//! [`Host`] (the network, the prover, the enrollments it keeps, its clock)
//! and the user's [`Prompts`]. Both block: every flow runs on the thread
//! of the operation that called it.

use std::time::Duration;

use vos_wire::credentials::Onion;
use zeroize::Zeroizing;

use super::Error;
use crate::route::{Purpose, Route};
use crate::{AuthWitness, Call, DeviceSecret};

/// The app's side of the personal space.
pub trait Host: Send + Sync + 'static {
    /// `request` (a `vos-api` request) sent over the routes kept under
    /// `space` (an enrolled space's key, [`crate::route::space`], or a
    /// home's, [`crate::route::home`]), under `purpose`, its own connection's: the
    /// answer's body, or why there is none.
    fn request(
        &self,
        space: &[u8; 32],
        purpose: Purpose,
        request: &[u8],
    ) -> Result<Vec<u8>, String>;

    /// `requests` sent as [`Host::request`] sends each, under `purpose`:
    /// on a kept-open purpose's connection all in flight at once, so they
    /// cost one round trip; a one-shot purpose's each on a connection of
    /// its own. Each one's answer, in order.
    fn requests(
        &self,
        space: &[u8; 32],
        purpose: Purpose,
        requests: &[Vec<u8>],
    ) -> Vec<Result<Vec<u8>, String>> {
        requests
            .iter()
            .map(|request| self.request(space, purpose, request))
            .collect()
    }

    /// The routes of a home, kept under its key `home`
    /// ([`crate::route::home`]): its `onions`, onion only.
    fn pin(&self, home: &[u8; 32], onions: &[Onion]);

    /// The route a request of `purpose` over the routes kept under `space`
    /// takes now.
    fn route(&self, space: &[u8; 32], purpose: Purpose) -> Route;

    /// `proof` made, one at a time beside the app's other proofs: the
    /// proven call's request, as [`crate::wire::credentialed`] makes it.
    fn prove(&self, proof: Proof) -> Result<Vec<u8>, Error>;

    /// The device's enrollments in spaces other than its homes, as the
    /// credential book records them and an owner proof there takes them.
    fn enrollments(&self) -> Result<Vec<Enrolled>, String>;

    /// The device's clock, in milliseconds since the Unix epoch.
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64)
    }

    /// A flow's wait between two reads of a slot or a log.
    fn sleep(&self, wait: Duration) {
        std::thread::sleep(wait);
    }
}

/// What a flow asks proved: `Homes`' claim in the scope "home" under the
/// device's secret at its home, or a registrar's call under its owner
/// secret in another space.
pub enum Proof {
    Home {
        secret: Box<DeviceSecret>,
        witness: Box<AuthWitness>,
        call: Call,
    },
    Owner {
        secret: Box<DeviceSecret>,
        call: Call,
    },
}

/// An enrollment of this device in a space: the space and its handle, the
/// member and owner digests there, the source its secret is derived from
/// (as [`Prompts::evaluate_source`] names it), the credential actor and the
/// agents the space names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    pub space: [u8; 32],
    pub handle: [u8; 32],
    pub member: [u8; 32],
    pub owner: [u8; 32],
    pub source: Vec<u8>,
    /// The credential actor's agent and instance.
    pub credentials: (u32, u32),
    /// Each agent of the space and its identity.
    pub agents: Vec<(u32, [u8; 32])>,
}

/// An admin key's public half and what its attestation showed, as the
/// UI's keystore made it behind a strong biometric.
#[derive(Clone, Copy, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct AdminKey {
    pub key: [u8; 32],
    pub hardware: bool,
    pub verified_boot: bool,
}

impl AdminKey {
    /// The class the device set records it in: a strong admin only when
    /// the key is hardware-backed, a delayed one otherwise. The flags are
    /// the device's own report until an attestation is verified.
    pub fn class(&self) -> vos_wire::personal::AdminClass {
        if self.hardware {
            vos_wire::personal::AdminClass::Strong
        } else {
            vos_wire::personal::AdminClass::Delayed
        }
    }
}

/// A kit's card, shown with it: the home a restore goes to, by its handle
/// (stable across a re-founding), and each onion with its SSH host key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    pub handle: [u8; 32],
    pub onions: Vec<Onion>,
}

/// Another device's new admin key, which this device's admin key is asked
/// to sign: the device, its label, the key's check (its first 8 bytes in
/// hex, which that device shows too) and where the key is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub device: u32,
    pub label: String,
    pub check: String,
    pub hardware: bool,
}

/// The user's prompts, each blocking until they answer. A prompt is asked
/// only inside a flow the user started; none outside one.
pub trait Prompts {
    /// A new phrase kit's 24 `words`, shown once beside its `card`:
    /// whether the user wrote them down.
    fn show_phrase(&self, words: &str, card: &Card) -> bool;
    /// A new security-key kit's `card`: whether the user wrote it down.
    fn show_card(&self, card: &Card) -> bool;
    /// The kit's 24 words, entered; `None` when the user declined.
    fn enter_phrase(&self) -> Option<Zeroizing<String>>;
    /// Whether the user approves another device's new admin key.
    fn approve_admin(&self, approval: &Approval) -> bool;
    /// On the device that showed a pairing code: whether the user confirms
    /// the new device shows this `check` too. Nothing is handed over until
    /// they do.
    fn confirm_pairing(&self, check: &str) -> bool;
    /// On the new device: the pairing's `check`, shown while the user
    /// confirms it on the other device; whether they go on.
    fn show_pairing(&self, check: &str) -> bool;

    /// A new secret source's key: its reference, which
    /// [`Prompts::evaluate_source`] takes.
    fn create_source(&self) -> Result<Vec<u8>, Error>;
    /// The source `source`'s 32-byte output for `input`, at its prompt.
    fn evaluate_source(
        &self,
        source: &[u8],
        input: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, Error>;
    /// A new kit's security-key credential: its id.
    fn create_kit_key(&self) -> Result<Vec<u8>, Error>;
    /// A kit's security key's `hmac-secret` of `salt`, its credential `id`
    /// (empty: the key's discoverable credential).
    fn kit_secret(&self, id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error>;
    /// A new admin key, in the UI's keystore behind a strong biometric.
    fn create_admin(&self) -> Result<AdminKey, Error>;
    /// The admin key `key`'s Ed25519 signature over `message`, prepared
    /// here, after the biometric.
    fn sign_admin(&self, key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Error>;
}
