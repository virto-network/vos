//! The local role hierarchy + per-space role mapping.

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
pub enum MsgDirectoryRole {
    None = 0,
    Reader = 1,
    Publisher = 2,
}

impl vos::RoleByte for MsgDirectoryRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Publisher),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

pub const MSG_DIRECTORY_SPACE_ROLE_MAP: vos::SpaceRoleMap<MsgDirectoryRole> = vos::SpaceRoleMap {
    admin: Some(MsgDirectoryRole::Publisher),
    developer: Some(MsgDirectoryRole::Publisher),
    member: Some(MsgDirectoryRole::Publisher),
    guest: None,
};
