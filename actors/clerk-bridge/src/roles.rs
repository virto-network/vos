//! The clerk-bridge role hierarchy + per-space role mapping.
//!
//! The bridge's verify-and-open handlers (`submit_voucher`,
//! `redeem_voucher`) stay ungated: the voucher path authenticates by the
//! issuer's signature, not by space membership. Setup, issuer signing, claim
//! signing, and settlement-window controls are operator-gated.
//!
//! The signing-control handlers additionally reject the legacy same-node
//! `Caller::Actor` bypass: only `System` or an authenticated member carrying
//! `Operator` may bind keys, change peer trust, issue, or sign claims. Under
//! Raft leader-forward the peer must hold the `Admin`/`Developer` grant.

/// Ordered: `Operator` >= `Member` >= `None`.
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
pub enum ClerkBridgeRole {
    /// No access.
    None = 0,
    /// Reserved for a future gated read surface.
    Member = 1,
    /// May steer settlement accounting — rotate windows, reset anchors
    /// (the bank operator).
    Operator = 2,
}

impl vos::RoleByte for ClerkBridgeRole {
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

/// Space roles → clerk-bridge roles. A space admin/developer operates the
/// bank's bridge; a space member gets the (reserved) read tier; a guest
/// gets nothing.
pub const CLERK_BRIDGE_SPACE_ROLE_MAP: vos::SpaceRoleMap<ClerkBridgeRole> = vos::SpaceRoleMap {
    admin: Some(ClerkBridgeRole::Operator),
    developer: Some(ClerkBridgeRole::Operator),
    member: Some(ClerkBridgeRole::Member),
    guest: None,
};
