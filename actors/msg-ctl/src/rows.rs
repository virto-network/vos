//! Wire types: the commit chain's rows and reply shapes, plus the
//! content-derived commit id.

use alloc::vec::Vec;

use crate::Status;
use crate::consts::COMMIT_ID_DOMAIN_TAG;

/// One accepted commit. `epoch` is the epoch the commit was
/// *created at*; processing it advances the group to `epoch + 1`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CommitRow {
    /// Content-derived id — see [`commit_record_id`]. What a
    /// losing committer compares against to confirm its own
    /// commit lost.
    pub id: [u8; 32],
    pub epoch: u64,
    /// Sender wall clock, display only.
    pub ts_ms: u64,
    /// Opaque MLS Commit message.
    pub commit_body: Vec<u8>,
    /// Opaque MLS Welcome for members this commit added; empty
    /// when the commit added nobody.
    pub welcome: Vec<u8>,
    /// Opaque routing token accompanying a Welcome. The inviter
    /// supplies fresh random bytes — deliberately NOT derived from
    /// the joiner's public KeyPackage, since a public-derivable
    /// token would let anyone holding the directory and this chain
    /// map joins back to nicknames. Joiners recognise their Welcome
    /// by trial-decryption; this actor only enforces presence.
    /// Zeroed when `welcome` is empty.
    pub welcome_hint: [u8; 32],
}

/// Reply shape for `commit`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CommitOutcome {
    /// `Status::Ok` means this commit is the epoch's winner.
    pub status: Status,
    /// The epoch the chain expects next (= its current length).
    /// On `EpochTaken`/`EpochGap` this tells the caller how
    /// far behind/ahead it is.
    pub next_epoch: u64,
}

/// Reply shape for `head` — enough for a poller to decide
/// whether new commits exist.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CtlHead {
    pub next_epoch: u64,
}

/// Content-derived id over every field of the record.
pub fn commit_record_id(
    epoch: u64,
    ts_ms: u64,
    commit_body: &[u8],
    welcome: &[u8],
    welcome_hint: &[u8; 32],
) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        COMMIT_ID_DOMAIN_TAG,
        &[
            &epoch.to_le_bytes(),
            &ts_ms.to_le_bytes(),
            commit_body,
            welcome,
            welcome_hint,
        ],
    )
}
