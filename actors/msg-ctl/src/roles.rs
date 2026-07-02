//! Local role hierarchy + per-space role mapping.

/// Local role hierarchy. Any space member may submit commits —
/// whether a commit is *cryptographically* valid is MLS's job
/// (a non-member can't produce one the group accepts); the role
/// gate just keeps strangers from growing the chain.
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
pub enum MsgCtlRole {
    None = 0,
    Reader = 1,
    Committer = 2,
}

impl vos::RoleByte for MsgCtlRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Committer),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

pub const MSG_CTL_SPACE_ROLE_MAP: vos::SpaceRoleMap<MsgCtlRole> = vos::SpaceRoleMap {
    admin: Some(MsgCtlRole::Committer),
    developer: Some(MsgCtlRole::Committer),
    member: Some(MsgCtlRole::Committer),
    guest: None,
};
