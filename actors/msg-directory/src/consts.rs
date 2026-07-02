//! Tunable constants: the KeyPackage-hash domain tag and sizing/quota bounds.

/// Domain tag for KeyPackage hashes. The canonical computation for
/// the whole messaging stack: the publisher hashes the serialized
/// KeyPackage it minted, the directory dedupes by it, and the
/// Welcome routing hint on the msg-ctl chain carries the same
/// value so a joiner recognises which record admits it.
pub const KP_HASH_DOMAIN_TAG: &[u8] = b"vos-msg-kp/v1";

/// Bound on one serialized KeyPackage (typically a few hundred
/// bytes for the pinned ciphersuite).
pub const MAX_KP_BYTES: usize = 4 * 1024;

/// Bound on operator-controlled identity/name strings (nickname,
/// channel name, creator). Replicated to every node, so cap them so
/// a member can't bloat shared state with a giant string.
pub const MAX_NAME_BYTES: usize = 128;

/// Bound on a member's *live* (unclaimed) packages — caps the
/// inventory waiting to be claimed without ever locking a member
/// out of replenishing once their packages are spent. Claimed
/// rows are retained for the single-use marker but don't count.
pub const MAX_KPS_PER_MEMBER: usize = 16;

/// Byte budget for one `channels` page.
pub const PAGE_BYTE_BUDGET: usize = 12 * 1024;
