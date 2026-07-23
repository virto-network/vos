//! Chronos protocol — the feeder-facing wire types, constants, committee
//! codec, and a dynamic-dispatch [`ChronosRef`] client, shared by the
//! `chronos` PVM actor (which `pub use`s them back) and the host-side
//! [`crate::chronos_feed`] feeder.
//!
//! Only the surface the feeder touches lives here (the clock/committee/reveal
//! request-reply protocol). The beacon-chain derivations, the RBAC role map,
//! and the reveal-collection internals stay in the actor crate. Everything
//! here is `no_std` + `alloc` only and pulls no VRF/crypto — the feeder's VRF
//! use is confined to [`crate::chronos_feed`], behind the `network` feature.

use alloc::vec::Vec;

// ── Status ────────────────────────────────────────────────────────

/// Return status of every chronos `#[msg]` handler. The `#[repr(u8)]`
/// discriminants are wire-stable — reordering or renumbering variants shifts
/// the rkyv archive bytes and breaks peer nodes running older builds.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    /// Entropy was not exactly [`ENTROPY_LEN`] bytes, or the domain was too
    /// large.
    InvalidInput = 1,
    /// `advance` was called before `init`.
    NotInitialized = 2,
    /// `init` was called on an already-initialised service (one-shot).
    AlreadyInitialized = 3,
    /// The proposed slot did not move the clock strictly forward (`slot <= now`).
    StaleSlot = 4,
    /// The proposed slot leapt more than [`MAX_SLOT_JUMP`] past the current
    /// slot on a non-establishing advance (the future-drift cap).
    SlotJumpTooLarge = 5,
    /// Reserved, unused. The committee handlers are authenticated
    /// cryptographically (a chronos handler runs on the raft apply path,
    /// where the originating caller is not preserved), so no handler
    /// returns a caller-based authorization error.
    Unauthorized = 6,
    /// The voter is not in the authorized committee (`Chronos::set_committee`)
    /// — enrolment and reveals are only accepted from registry voters.
    NotAVoter = 7,
    /// A reveal named a round that is not currently open — it was never
    /// opened, or its reveal window already closed and it folded.
    NoSuchRound = 8,
    /// A reveal's VRF proof did not verify against the voter's enrolled key
    /// over the round's input `α`.
    BadProof = 9,
    /// An `enrol_voter` tried to bind a *different* key to a voter that
    /// already has one. The first key wins; there is no key rotation.
    KeyLocked = 10,
}

/// The future-drift cap: a non-establishing `advance` may leap at most this
/// many slots past the current one. The feeder pre-clamps its proposal to
/// `now() + MAX_SLOT_JUMP`, and the actor enforces the same bound, so a stale
/// or malicious wall clock can never jump the beacon arbitrarily far ahead.
pub const MAX_SLOT_JUMP: u64 = 14_400;

// ── Rows ──────────────────────────────────────────────────────────

/// One committee member's enrolled VRF public key. `voter` is the node's
/// `peer_id` multihash bytes — the same identity the registry stores as a
/// `MemberRow.key` for a `NODE_ROLE_VOTER` node, and the same bytes a libp2p
/// inbound carries as `vos::Caller::Peer`. `pubkey` is a canonical Ristretto255
/// VRF public key; it is **public** — chronos holds no secret key material.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct VoterKey {
    pub voter: Vec<u8>,
    pub pubkey: [u8; 32],
}

/// A round currently open for reveals, as surfaced by `Chronos::open_rounds`.
/// A voter proves over `alpha` and posts a `Chronos::reveal` before the clock
/// reaches `fold_epoch`.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct OpenRound {
    pub round: u64,
    pub alpha: [u8; 32],
    pub open_slot: u64,
    pub fold_epoch: u64,
}

/// Result of an `advance`.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
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

// ── Committee codec ───────────────────────────────────────────────

/// Upper bound on committee size, so a malformed [`encode_committee`] blob can
/// never drive an unbounded allocation.
pub const MAX_COMMITTEE: usize = 1024;
const MAX_VOTER_ID_LEN: usize = 256;

/// Wire codec for the voter list passed to `Chronos::set_committee`. A handler
/// parameter must map to a [`crate::value::Value`] variant and there is no
/// `Vec<Vec<u8>>` variant, so the variable-length `peer_id` list is flattened
/// into one length-prefixed blob: a `u16` count, then per voter a `u16` length
/// and that many bytes, all little-endian. Exported so the feeder encodes
/// identically.
pub fn encode_committee(voters: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(voters.len() as u16).to_le_bytes());
    for v in voters {
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// Inverse of [`encode_committee`]. Returns `None` on a malformed blob: a bad
/// length prefix, trailing garbage, an over-long voter id, or more than
/// [`MAX_COMMITTEE`] entries.
pub fn decode_committee(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut p = 0usize;
    let count = u16::from_le_bytes(bytes.get(p..p + 2)?.try_into().ok()?) as usize;
    p += 2;
    if count > MAX_COMMITTEE {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u16::from_le_bytes(bytes.get(p..p + 2)?.try_into().ok()?) as usize;
        p += 2;
        if len > MAX_VOTER_ID_LEN {
            return None;
        }
        out.push(bytes.get(p..p + len)?.to_vec());
        p += len;
    }
    if p != bytes.len() {
        return None; // trailing garbage
    }
    Some(out)
}

// ── Dynamic chronos client ────────────────────────────────────────
//
// [`ChronosRef`] mirrors the actor's macro-generated `ChronosRef` on the
// dynamic-dispatch wire (Msg name = handler name, arg keys = param names,
// TAG_DYNAMIC-framed, reply `Value` decoded back into the types above) so the
// host feeder can drive the clock without depending on the actor crate.
// Generic over `Invoker`; the feeder always invokes with `&VosNode`.

use crate::actors::client::{ClientError, Invoker};
use crate::actors::codec::Encode;
use crate::value::{Msg, TAG_DYNAMIC, Value};

/// rkyv-decode a `Value::Bytes` reply into `T` (checked access), mirroring the
/// generated client's reply decode.
fn decode_rkyv<T: crate::Decode>(value: Value) -> Result<T, ClientError> {
    match value {
        Value::Bytes(b) => T::try_decode(&b).ok_or(ClientError::Decode),
        other => Err(ClientError::UnexpectedReply(alloc::format!("{other:?}"))),
    }
}

/// Typed reference to a chronos instance, addressed by `ServiceId`.
#[derive(Copy, Clone)]
pub struct ChronosRef {
    target: crate::abi::service::ServiceId,
}

impl ChronosRef {
    /// Bind to an explicit chronos `ServiceId`. Cheap; copy freely.
    pub const fn at(target: crate::abi::service::ServiceId) -> Self {
        Self { target }
    }

    async fn call<I: Invoker>(&self, inv: &mut I, msg: Msg) -> Result<Value, ClientError> {
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        inv.invoke(self.target, payload).await
    }

    pub async fn init<I: Invoker>(
        &self,
        inv: &mut I,
        domain: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(inv, Msg::new("init").with("domain", domain))
                .await?,
        )
    }

    pub async fn now<I: Invoker>(&self, inv: &mut I) -> Result<u64, ClientError> {
        let v = self.call(inv, Msg::new("now")).await?;
        v.as_u64()
            .ok_or_else(|| ClientError::UnexpectedReply(alloc::format!("{v:?}")))
    }

    pub async fn advance<I: Invoker>(
        &self,
        inv: &mut I,
        slot: u64,
        entropy: Vec<u8>,
    ) -> Result<AdvanceOutcome, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("advance")
                    .with("slot", slot)
                    .with("entropy", entropy),
            )
            .await?,
        )
    }

    pub async fn set_committee<I: Invoker>(
        &self,
        inv: &mut I,
        voters: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(inv, Msg::new("set_committee").with("voters", voters))
                .await?,
        )
    }

    pub async fn enrol_voter<I: Invoker>(
        &self,
        inv: &mut I,
        voter_id: Vec<u8>,
        pubkey: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("enrol_voter")
                    .with("voter_id", voter_id)
                    .with("pubkey", pubkey),
            )
            .await?,
        )
    }

    pub async fn committee<I: Invoker>(&self, inv: &mut I) -> Result<Vec<VoterKey>, ClientError> {
        decode_rkyv(self.call(inv, Msg::new("committee")).await?)
    }

    pub async fn open_rounds<I: Invoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<OpenRound>, ClientError> {
        decode_rkyv(self.call(inv, Msg::new("open_rounds")).await?)
    }

    pub async fn reveal<I: Invoker>(
        &self,
        inv: &mut I,
        voter_id: Vec<u8>,
        round: u64,
        proof: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("reveal")
                    .with("voter_id", voter_id)
                    .with("round", round)
                    .with("proof", proof),
            )
            .await?,
        )
    }
}
