//! The `ChronosRole` gate and its per-space role mapping.

/// Reads (`now`/`epoch`/`current`/`latest_final`/`randomness_at`/`round_at`/
/// `round`/`range`) are **public** — bare `#[msg]` handlers carry no role check,
/// so any caller past the libp2p auth gate may read, by design: chronos exposes
/// only publicly-recomputable values. Advancing the clock/chain (`init`/
/// `advance`) is the privileged feeder operation, gated to `Advancer`; in
/// production the Raft leader's node drives it (a `System` caller bypasses the
/// gate). `default_role` only labels intent here — it is not consulted for the
/// unguarded read handlers.
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
pub enum ChronosRole {
    None = 0,
    Reader = 1,
    Advancer = 2,
}

impl vos::RoleByte for ChronosRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Advancer),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

pub const CHRONOS_SPACE_ROLE_MAP: vos::SpaceRoleMap<ChronosRole> = vos::SpaceRoleMap {
    admin: Some(ChronosRole::Advancer),
    developer: Some(ChronosRole::Reader),
    member: Some(ChronosRole::Reader),
    guest: None,
};
