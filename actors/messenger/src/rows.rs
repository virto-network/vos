//! Persisted state shapes: the decrypted message and per-channel local view.

use alloc::string::String;
use alloc::vec::Vec;

/// One decrypted message in the node-local store. Ordering is by
/// `(lamport, ts_ms, sender)` — same convergent key the log uses,
/// with display ties broken arbitrarily-but-stably.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PlainMessage {
    pub lamport: u64,
    pub ts_ms: u64,
    pub sender: String,
    pub text: String,
}

/// Local view of one channel.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ChannelEntry {
    pub name: String,
    /// `false` while waiting for a Welcome.
    pub joined: bool,
    /// `true` after the chain evicted us — the channel sits idle
    /// (history kept, no decryption possible) until a re-invite's
    /// Welcome arrives.
    pub removed: bool,
    /// `true` once a commit on the chain couldn't be applied to our
    /// group: the channel is frozen at its current epoch (no further
    /// commits processed, no new messages decrypted) pending repair,
    /// rather than re-fetching the bad record forever.
    pub desynced: bool,
    /// First epoch we hold keys for; envelopes below it are
    /// undecryptable history by MLS design.
    pub join_epoch: u64,
    /// Unjoined: ctl-chain scan position. Joined: next chain
    /// record to process.
    pub next_epoch: u64,
    /// Log read cursor (last consumed envelope).
    pub cursor_lamport: u64,
    pub cursor_id: Vec<u8>,
    /// Highest lamport seen anywhere in the channel — `send`
    /// stamps `max + 1`.
    pub max_lamport: u64,
    /// Envelope ids of our own posts not yet echoed back by the
    /// log drain (displayed at send time; MLS can't decrypt own
    /// traffic).
    pub own_ids: Vec<[u8; 32]>,
    /// The decrypted conversation.
    pub messages: Vec<PlainMessage>,
}
