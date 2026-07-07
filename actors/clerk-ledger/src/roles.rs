//! The clerk-ledger role hierarchy + per-space role mapping.
//!
//! Confined-tier ledgers still answer any peer that can route to their
//! `ServiceId` (the ACL is the only gate at that boundary), so the money-path
//! mutators and the balance/transfer reads are role-gated. `Caller::System`
//! and `Caller::Actor` map to `SpaceRole::Admin` and bypass these checks, so
//! the operator (driving via the daemon) and the clerk-bridge (an actor,
//! crediting on redeem) are unaffected — the gate bites only external peers.

/// Ordered: `Operator` >= `Member` >= `None`, so an `Operator` also satisfies a
/// `Member` gate (can read), while a `Member` cannot satisfy an `Operator` gate
/// (cannot mutate).
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
pub enum ClerkLedgerRole {
    /// No access.
    None = 0,
    /// May read balance/transfer commitments + state roots (the bank's users).
    Member = 1,
    /// May mutate the ledger — bootstrap, create accounts, apply batches
    /// (move value), append note commitments (the bank operator).
    Operator = 2,
}

impl vos::RoleByte for ClerkLedgerRole {
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

/// Space roles → clerk-ledger roles. A space admin/developer operates the bank;
/// a space member is one of its users (read-only); a guest gets nothing.
pub const CLERK_LEDGER_SPACE_ROLE_MAP: vos::SpaceRoleMap<ClerkLedgerRole> = vos::SpaceRoleMap {
    admin: Some(ClerkLedgerRole::Operator),
    developer: Some(ClerkLedgerRole::Operator),
    member: Some(ClerkLedgerRole::Member),
    guest: None,
};
