// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's own interface's types (`IVosPersonal`, under the AAR's
//! `src/main/aidl`, package `team.virto.vos.personal`), each declared once
//! with s4's `parcel!` or `byte_enum!`: the background jobs' passes and what
//! they raise, and the personal space's flows' requests and results (VOS's
//! `light-node.md` §3.3–§3.9): the claim at a home with its recovery kit,
//! pairing, the memberships a pairing leaves, the device set, a restore
//! from the kit and a move home. [`REGISTRY`] lists them, held to the AIDL
//! in the tests; under the `jni` feature each is its parcelable.

use s4_credential_contract::{MAX_ONIONS, Onion, byte_enum, parcel};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Code, Refusal};

/// The interface's AIDL source root, beside this crate.
pub const AIDL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/aar/src/main/aidl");

/// The intent action `VosNodeService` serves the interface for.
pub const ACTION: &str = "team.virto.vos.personal.IVosPersonal";

/// A device's label, at most this many bytes (`vos_wire::books::LABEL_BYTES`).
pub const MAX_LABEL: usize = 64;
/// The most devices one regroup names.
pub const MAX_REGROUP: usize = 16;

byte_enum! {
    package "team.virto.vos.personal";
    /// What a local notification raises: a pending operation of the device
    /// set, a pending restore, this device's removal, the yearly re-proof,
    /// or an alarm.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum Pending {
        /// A device added by a delayed admin.
        Add = 0 as ADD,
        Remove = 1 as REMOVE,
        /// A device's admin key replaced.
        Replace = 2 as REPLACE,
        /// The recovery kit replaced.
        Rotate = 3 as ROTATE,
        /// The devices named removed and a new group started.
        Regroup = 4 as REGROUP,
        /// Every device removed by the kit's restore, signed by the kit.
        Restore = 5 as RESTORE,
        /// A restore is pending: this device answered it with `alive`.
        Restoring = 6 as RESTORING,
        /// This device is out of its group.
        Removed = 7 as REMOVED,
        /// The yearly re-proof is due.
        Renew = 8 as RENEW,
        /// The personal space raised an alarm: `detail` names it.
        Alarm = 9 as ALARM,
        /// This device cannot follow its group: it re-pairs, or regroups.
        Stuck = 10 as STUCK,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// What a recovery kit is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum KitKind {
        /// 24 words, shown once in the chrome and written down.
        Phrase = 1 as PHRASE,
        /// A FIDO2 security key's `hmac-secret`.
        SecurityKey = 2 as SECURITY_KEY,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// What a membership waits for on this device.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Owed {
        /// Another device of the person to enroll there, by this device's
        /// owner proof: deferrable.
        Enroll = 0 as ENROLL,
        /// This device's own confirmation there, once its leaf is in.
        Confirm = 1 as CONFIRM,
    }
}

parcel! {
    package "team.virto.vos.personal";
    registry REGISTRY with [Pending, KitKind, Owed];

    /// One pass of the facility's sync, a background job's: of the
    /// enrollments kept, how many synced and how many failed (the personal
    /// space's pass counted with them); the bytes its connections read and
    /// wrote, its length; what the chrome raises; and each of the person's
    /// devices' last call at the personal agent.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Synced {
        pub enrollments: u32 => int,
        pub synced: u32 => int,
        pub failed: u32 => int,
        pub bytes_down: u64 => long,
        pub bytes_up: u64 => long,
        pub millis: u64 => long,
        pub notices: Vec<Notice> => Notice[],
        pub seen: Vec<Seen> => Seen[],
    }

    /// One thing the chrome raises: an operation's at its log `index`,
    /// taken at `at` (the agent's time, 0 when this pass did not read it)
    /// and maturing at `matures` unless vetoed; `fresh` when no pass raised
    /// it before, so its notification alerts.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Notice {
        pub pending: Pending => enum Pending,
        pub index: u64 => long,
        pub at: u64 => long,
        pub matures: u64 => long,
        pub fresh: bool => boolean,
        pub detail: String => String,
    }

    /// A device of the person's set, and its last call the personal agent
    /// took (its time, 0 before any).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Seen {
        pub device: u32 => long,
        pub at: u64 => long,
    }

    /// A home as the device reaches it: its space and handle, the agent
    /// holding its credential actor and `Homes`, with the identity calls to
    /// it are signed for, their instances, and its onions (a home is
    /// onion-only).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Home {
        pub space: [u8; 32] => byte[],
        pub handle: [u8; 32] => byte[],
        pub agent: u32 => long,
        pub identity: [u8; 32] => byte[],
        pub homes: u32 => long,
        pub credentials: u32 => long,
        pub onions: Vec<Onion> => Onion[],
    }

    /// `claim`: a personal agent at `home` with a kit of `kit`, this device
    /// named `label` to the user's other devices. `restore` and `move_home`
    /// take the same: the home, the new kit.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Claim as ClaimRequest {
        pub home: Home => Home,
        pub kit: KitKind => enum KitKind,
        pub label: String => String,
    }

    /// A claim's (or a restore's) result: the agent, and this device's id
    /// in its set.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Claimed {
        pub agent: u32 => long,
        pub device: u32 => long,
    }

    /// `pair_offer`'s result: the QR code's bytes, which hold the pairing's
    /// one-time code, and when the slot expires (the agent's time).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PairCode {
        pub code: Zeroizing<Vec<u8>> => byte[],
        pub expires_ms: u64 => long,
    }

    /// A pairing's result: the new device's id, and the memberships it is
    /// to be enrolled in (the opener's) or to confirm (the joiner's).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Paired {
        pub device: u32 => long,
        pub memberships: u32 => int,
    }

    /// A membership in a space other than the home: the space, its handle,
    /// its credential actor's agent and instance, and what is owed there.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Membership {
        pub space: [u8; 32] => byte[],
        pub handle: [u8; 32] => byte[],
        pub agent: u32 => long,
        pub instance: u32 => long,
        pub owed: Owed => enum Owed,
    }

    /// A device of the set, as the chrome lists it: its id and label,
    /// whether its admin is strong, its standing
    /// (`vos_wire::personal::Standing`'s index), its last call the agent
    /// took (0 before any), whether a removal of it matured, and whether it
    /// is this device.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Device {
        pub id: u32 => long,
        pub label: String => String,
        pub strong: bool => boolean,
        pub standing: u8 => byte,
        pub seen: u64 => long,
        pub removed: bool => boolean,
        pub me: bool => boolean,
    }

    /// An admin call the agent took: its log index and batch time.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Posted {
        pub index: u64 => long,
        pub at: u64 => long,
    }

    /// `move_home`'s result: the new agent, and the envelopes carried
    /// there.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Moved {
        pub agent: u32 => long,
        pub carried: u64 => long,
    }
}

fn bad(message: impl Into<String>) -> Refusal {
    Refusal::new(Code::Arguments, message)
}

impl Home {
    /// Within its bounds: 1 to [`MAX_ONIONS`] distinct onions.
    pub fn check(self) -> Result<Self, Refusal> {
        if self.onions.is_empty() || self.onions.len() > MAX_ONIONS {
            return Err(bad(format!(
                "a home pins 1 to {MAX_ONIONS} onions: it is onion-only"
            )));
        }
        if self
            .onions
            .iter()
            .enumerate()
            .any(|(at, onion)| self.onions[..at].iter().any(|seen| seen.key == onion.key))
        {
            return Err(bad("an onion is pinned twice"));
        }
        Ok(self)
    }
}

/// A device's label: 1 to [`MAX_LABEL`] ASCII letters, digits, spaces,
/// `.`, `_` or `-`, so the other devices' chrome shows it as it reads.
pub fn label(text: &str) -> Result<(), Refusal> {
    let plain = text
        .split(' ')
        .all(|word| s4_credential_contract::plain(word, false));
    if (1..=MAX_LABEL).contains(&text.len()) && plain {
        Ok(())
    } else {
        Err(bad(format!(
            "a device's label is 1 to {MAX_LABEL} ASCII letters, digits, spaces, `.`, `_` or `-`"
        )))
    }
}

impl Claim {
    pub fn check(self) -> Result<Self, Refusal> {
        label(&self.label)?;
        Ok(Self {
            home: self.home.check()?,
            ..self
        })
    }
}
