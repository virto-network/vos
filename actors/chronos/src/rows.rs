//! Wire/state row types: the beacon chain, committee keys and reveals, and
//! `advance`'s outcome.

use alloc::vec::Vec;

use crate::Status;

/// One committed round of the beacon chain — one folded epoch. Self-verifying:
/// recomputing `H(domain ‖ prev ‖ round ‖ slot ‖ entropy)` must equal `beacon`
/// ([`crate::verify_round`]).
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BeaconRound {
    /// Dense round index: `+1` per folded epoch, contiguous, genesis is 0. The
    /// linkage anchor for [`crate::verify_chain`]. (Distinct from
    /// `slot / SLOTS_PER_EPOCH`, the wall-epoch, which is sparse when the clock
    /// skips epochs.)
    pub round: u64,
    /// The slot at which this round **opened** — when its input `α` was fixed
    /// (for a committee-less round this is also the fold slot, since it opens and
    /// folds in one `advance`). The clock context of the round; its wall-epoch is
    /// `slot / SLOTS_PER_EPOCH`. `0` for genesis. Strictly ascending across
    /// rounds (one round opens per crossed epoch), and bound into `beacon` so it
    /// cannot be relabelled against an untrusted server.
    pub slot: u64,
    /// The previous round's beacon (`[0; 32]` for the genesis round 0).
    pub prev: [u8; 32],
    /// The entropy folded in this round (`[0; 32]` for the genesis round 0).
    pub entropy: [u8; 32],
    pub beacon: [u8; 32],
}

/// One committee member's enrolled VRF public key. `voter` is the node's
/// `peer_id` multihash bytes — the same identity the registry stores as a
/// `MemberRow.key` for a `NODE_ROLE_VOTER` node, and the same bytes a libp2p
/// inbound carries as [`vos::Caller::Peer`]. `pubkey` is a canonical
/// Ristretto255 VRF public key ([`vrf::PublicKey`]); it is **public** — chronos
/// holds no secret key material.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct VoterKey {
    pub voter: Vec<u8>,
    pub pubkey: [u8; 32],
}

/// One committee member's reveal collected in an open round. `beta` is the
/// VRF output cached at acceptance (the proof is verified once, on arrival, not
/// re-verified at fold time). `proof` is the 80-byte wire proof, retained so the
/// folded round stays publicly re-verifiable ([`RoundProofSet`]).
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub(crate) struct StoredReveal {
    pub(crate) voter: Vec<u8>,
    pub(crate) pubkey: [u8; 32],
    pub(crate) proof: Vec<u8>,
    pub(crate) beta: Vec<u8>,
}

/// An open round collecting committee reveals before it folds. Held in
/// [`crate::Chronos::pending`] from the epoch it opens until its reveal window
/// closes. The `snapshot` fixes the authorized+enrolled committee **at open
/// time**, so a voter cannot re-enrol a favourable key once `alpha` is known
/// (anti key-shopping); reveals are verified against this snapshot, not the
/// live keys.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub(crate) struct RoundDraft {
    pub(crate) round: u64,
    pub(crate) open_slot: u64,
    /// The epoch at/after which this round folds: its open epoch for an empty
    /// committee (fold immediately), else open epoch + [`crate::REVEAL_WINDOW_EPOCHS`].
    pub(crate) fold_epoch: u64,
    pub(crate) alpha: [u8; 32],
    pub(crate) snapshot: Vec<VoterKey>,
    pub(crate) reveals: Vec<StoredReveal>,
}

/// One reveal's public verification material in a folded round.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RevealProof {
    pub voter: Vec<u8>,
    pub pubkey: [u8; 32],
    pub proof: Vec<u8>,
}

/// The committee proof material for a folded round — everything needed to
/// re-derive its entropy independently ([`crate::verify_combine`]): the round's
/// `alpha` and each counted reveal's `(pubkey, proof)`. Empty `reveals` marks a
/// degraded round folded on the leader entropy (no committee reveal arrived).
/// Retained in lockstep with the beacon history.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct RoundProofSet {
    pub round: u64,
    pub alpha: [u8; 32],
    pub reveals: Vec<RevealProof>,
}

/// A round currently open for reveals, as surfaced by [`crate::Chronos::open_rounds`].
/// A voter proves over `alpha` and posts a [`crate::Chronos::reveal`] before the
/// clock reaches `fold_epoch`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct OpenRound {
    pub round: u64,
    pub alpha: [u8; 32],
    pub open_slot: u64,
    pub fold_epoch: u64,
}

/// Result of an `advance`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AdvanceOutcome {
    pub status: Status,
    /// The clock after the advance (the freshly-stamped slot on success).
    pub slot: u64,
    /// The head round number after the advance — bumped iff `folded`.
    pub round: u64,
    /// The head beacon after the advance — changed iff `folded`.
    pub beacon: [u8; 32],
    /// Whether this advance crossed an epoch boundary and folded a new round.
    /// A plain clock tick within the current epoch stamps the slot with
    /// `folded == false` and leaves the chain untouched.
    pub folded: bool,
}
