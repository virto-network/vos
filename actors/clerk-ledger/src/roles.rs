//! The clerk-ledger role hierarchy + per-space role mapping.
//!
//! Confined-tier ledgers still answer any peer that can route to their
//! `ServiceId` (the ACL is the only gate at that boundary), so the money-path
//! mutators and the balance/transfer reads are role-gated. Producer-record
//! export and pruning add a stricter origin check: only the host operator or
//! an authenticated member carrying `Operator` may reach proving material.

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

/// Portable Agent role identities. The signed Agent method policy uses exact
/// identities, not the legacy ordered role-byte comparison. Derive these from
/// SHA-256 of `vos/clerk-ledger/role/{operator,member}/v1`.
#[cfg(feature = "agent")]
pub const CLERK_OPERATOR_AGENT_ROLE: vos::agent::sdk::RoleId = vos::agent::sdk::RoleId([
    0x07, 0x27, 0x70, 0x73, 0x13, 0xc8, 0xa3, 0xab, 0x99, 0x9f, 0xf2, 0xad, 0x14, 0xfe, 0xc1, 0xa5,
    0xbb, 0x5d, 0x12, 0x4f, 0x9b, 0x09, 0xaf, 0x3d, 0x6f, 0xf1, 0xbd, 0xd5, 0x59, 0x79, 0x19, 0xb2,
]);

#[cfg(feature = "agent")]
pub const CLERK_MEMBER_AGENT_ROLE: vos::agent::sdk::RoleId = vos::agent::sdk::RoleId([
    0xa1, 0xb1, 0x2a, 0x80, 0x0f, 0x4d, 0xc4, 0xd9, 0x97, 0x07, 0xdd, 0xb3, 0x9f, 0x91, 0x40, 0x3b,
    0xc9, 0xb8, 0xb8, 0x7a, 0x1e, 0xb1, 0x4a, 0xea, 0xeb, 0x14, 0xfc, 0x1a, 0x63, 0xd2, 0x8a, 0x21,
]);
