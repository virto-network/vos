//! The clerk-bridge role hierarchy + per-space role mapping.
//!
//! The bridge's verify-and-open handlers (`submit_voucher`,
//! `redeem_voucher`) and its setup handlers (`bootstrap`, `register_peer`,
//! `set_prover`) stay ungated `#[msg]`: the voucher path authenticates by
//! the issuer's signature, not by space membership, exactly as documented
//! on the actor. Only the **operator controls** that steer settlement
//! accounting — `window_rotate` (bracket a settlement window) and
//! `anchor_reset` (post-settlement wedge recovery) — are role-gated.
//!
//! Host and actor origins receive no ambient role. A bank operator supplies an
//! explicit `Admin`/`Developer` grant, while an internal actor uses a declared
//! capability or actor-local grant. Under Raft leader-forward the caller is
//! attributed to the forwarding node's peer, so every voter that may forward
//! an operator call must hold the corresponding grant.

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
