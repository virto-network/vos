//! The local role hierarchy + per-space role mapping.

/// Local role hierarchy. `Reader` can page ciphertext; `Poster`
/// can append. Confidentiality does not depend on `Reader` —
/// bodies are E2E-encrypted — but gating writes keeps the log
/// from being a spam sink for anyone below space-Member.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum MsgLogRole {
    None = 0,
    Reader = 1,
    Poster = 2,
}

impl vos::RoleByte for MsgLogRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Poster),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Space-tier mapping: every enrolled space member may post to
/// channels (channel membership proper is enforced by MLS — a
/// non-member's envelope is undecryptable noise); guests get
/// nothing.
pub const MSG_LOG_SPACE_ROLE_MAP: vos::SpaceRoleMap<MsgLogRole> = vos::SpaceRoleMap {
    admin: Some(MsgLogRole::Poster),
    developer: Some(MsgLogRole::Poster),
    member: Some(MsgLogRole::Poster),
    guest: None,
};
