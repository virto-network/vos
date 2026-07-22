//! The clerk-settle role hierarchy + per-space role mapping.
//!
//! The venue actor answers any peer that can route to its `ServiceId`, so
//! the money-path mutators (`register_bank`, `settle_window`) are role-gated.
//! The venue operator must supply an explicit space role; System and Actor
//! origins do not receive ambient administrator authority.
//!
//! `submit_claim` is deliberately NOT gated: submitting banks are not
//! members of the venue space, so a role gate could never carry them. Its
//! authentication is the claim signature verified against the registered
//! bank key (mirroring `clerk-bridge::submit_voucher`).

/// Ordered: `Operator` >= `Member` >= `None`, so an `Operator` also
/// satisfies a `Member` gate, while a `Member` cannot satisfy an
/// `Operator` gate.
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
pub enum ClerkSettleRole {
    /// No access.
    None = 0,
    /// May read the watch-view surface (banks / claims / settled windows).
    Member = 1,
    /// May register banks and settle windows (the venue operator).
    Operator = 2,
}

impl vos::RoleByte for ClerkSettleRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Member),
            2 => Some(Self::Operator),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Space roles → clerk-settle roles. A space admin/developer operates the
/// venue; a space member may watch; a guest gets nothing. (The watch-view
/// reads are ungated `#[msg]` handlers today — commitments carry no
/// amounts — so `Member` is reserved for a future gated read surface.)
pub const CLERK_SETTLE_SPACE_ROLE_MAP: vos::SpaceRoleMap<ClerkSettleRole> = vos::SpaceRoleMap {
    admin: Some(ClerkSettleRole::Operator),
    developer: Some(ClerkSettleRole::Operator),
    member: Some(ClerkSettleRole::Member),
    guest: None,
};
