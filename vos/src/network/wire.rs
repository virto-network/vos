//! Wire format for inter-node messages over libp2p.
//!
//! All multi-byte integers are little-endian. The first byte of each
//! frame is a tag that discriminates the kind. There is no separate
//! envelope around frames — the libp2p `request_response` codec
//! length-prefixes the bytes for us.
//!
//! Cycle 2 frames:
//!
//! - [`Frame::Hello`] — exchanged once per connection so peers learn
//!   each other's `node_prefix`. Sent as a request; the receiver's
//!   own `Hello` rides back as the response.
//! - [`Frame::Tell`] — fire-and-forget envelope addressed to a
//!   service on the remote node. The response slot carries
//!   [`Frame::Ack`].
//! - [`Frame::InvokeRequest`] / [`Frame::InvokeReply`] — synchronous
//!   request/reply pair, one round trip per call. Reuses the
//!   `chain` field from [`crate::node`] for cross-node cycle and
//!   depth detection.
//!
//! Cycle 3 frames (CRDT replication):
//!
//! - [`Frame::FetchHeads`] / [`Frame::Heads`] — "what are your
//!   merkle-clock roots for this replication group?" Carries a
//!   32-byte `replication_id` (typically `blake2b(blob || name)`)
//!   so peers don't need a shared ServiceId.
//! - [`Frame::FetchNode`] / [`Frame::NodeReply`] — point-fetch a
//!   single DAG node by CID. The reply slot carries
//!   `Some(node_bytes)` when the peer has the node, `None`
//!   otherwise.
//!
//! The encoding is deliberately hand-rolled (no serde / rkyv): the
//! schema is small, framing the wire format ourselves makes
//! versioning explicit, and we sidestep pulling another serializer
//! into the network feature's dep tree.

const TAG_HELLO: u8 = 0x10;
const TAG_TELL: u8 = 0x01;
const TAG_INVOKE_REQ: u8 = 0x02;
const TAG_INVOKE_REPLY: u8 = 0x03;
const TAG_ACK: u8 = 0x04;
const TAG_FETCH_HEADS: u8 = 0x20;
const TAG_HEADS: u8 = 0x21;
const TAG_FETCH_NODE: u8 = 0x22;
const TAG_NODE_REPLY: u8 = 0x23;
// Raft RPCs. 0x30..=0x35 reserved for the basic election +
// replication round; 0x36 reserved for follower→leader propose
// forwarding (later phase); 0x37..=0x38 for snapshot install
// (phase 7).
const TAG_RAFT_APPEND_REQ: u8 = 0x30;
const TAG_RAFT_APPEND_RESP: u8 = 0x31;
const TAG_RAFT_VOTE_REQ: u8 = 0x32;
const TAG_RAFT_VOTE_RESP: u8 = 0x33;
const TAG_RAFT_INSTALL_REQ: u8 = 0x37;
const TAG_RAFT_INSTALL_RESP: u8 = 0x38;
// Dynamic membership / cluster discovery (Phase B, second half).
// `RAFT_JOIN_*` lets a fresh node ask an existing replica to
// add it as a voter. `MANIFEST_*` lets a fresh node fetch the
// space.toml + actor blobs from a bootnode so `vosx join`
// works without the operator pre-distributing the manifest.
const TAG_RAFT_JOIN_REQ: u8 = 0x40;
const TAG_RAFT_JOIN_RESP: u8 = 0x41;
const TAG_MANIFEST_REQ: u8 = 0x42;
const TAG_MANIFEST_RESP: u8 = 0x43;
// Operator cluster-status tooling queries each peer for the
// per-group Raft state (role, term, last_applied, commit_index,
// members, leader hint) so the operator can see who's leader
// and whether followers are caught up.
const TAG_RAFT_STATUS_REQ: u8 = 0x44;
const TAG_RAFT_STATUS_RESP: u8 = 0x45;
// Content-addressed proof-blob fetch. Consumers ship the 32-byte
// hash carried by a Mode::External voucher; producers (or any
// node that has the bytes cached) serve them back. Large STARK
// payloads (~1.4 MiB today) ride a single frame thanks to the
// `MAX_FRAME_BYTES` cap below — chunked transport lands in a
// later cycle once production proofs start to push past it.
const TAG_FETCH_PROOF_BLOB: u8 = 0x50;
const TAG_PROOF_BLOB_REPLY: u8 = 0x51;

/// CIDs are 32-byte blake2b hashes (matches `commit::Blake2b` in
/// `vos`). A wider hasher would require a wire-format bump.
pub const CID_BYTES: usize = 32;

/// Replication group identifier — 32 bytes. Same shape as a CID
/// but carries a different meaning: a stable namespace shared by
/// every replica of a logical actor (typically
/// `blake2b(blob || actor_name)`).
pub const REPLICATION_ID_BYTES: usize = 32;

/// Cap on the number of roots a peer can claim in a single
/// `Heads` reply. Roots in a healthy CRDT graph are tiny in
/// number; this stops a malicious peer from forcing a large
/// alloc. Realistic actor traffic stays in single digits.
const MAX_HEADS: usize = 256;

/// Cap on the number of log entries carried in one
/// `AppendEntriesReq`. Healthy replication uses small batches;
/// a bigger payload should be split across multiple RPCs.
/// Bounds the per-frame allocation a malicious peer can force.
const MAX_RAFT_ENTRIES: usize = 1024;

/// Cap on the number of voters listed inside a single
/// `RaftEntryKind::ConfigChange` (per-list — applies to
/// `members` and to `joint_old` independently). Realistic Raft
/// clusters stay in single digits; this bounds the alloc a
/// malicious peer can force in either list.
const MAX_RAFT_MEMBERS: usize = 256;

/// Wire-side discriminant for [`RaftEntry::kind`]. Mirrors
/// `vos_raft::log_entry::EntryKind`'s reserved tag values: `0`
/// for application data, `1` for membership transitions.
const RAFT_ENTRY_KIND_DATA: u8 = 0;
const RAFT_ENTRY_KIND_CONFIG_CHANGE: u8 = 1;

/// Cap on the number of actor blobs ferried in a single
/// [`Frame::ManifestResp`]. A space declaring more agents than
/// this should land them via a follow-up streaming protocol;
/// realistic spaces stay well under the cap.
const MANIFEST_MAX_BLOBS: usize = 256;

/// Hard cap on a single encoded frame. Matches the producer-side
/// reply cap in `node.rs` so an oversized payload is rejected at
/// the same boundary regardless of whether it's local or networked.
///
/// 8 MiB accommodates STARK proof bodies riding a single
/// [`Frame::ProofBlobReply`] (the prover extension's prove path
/// produces ~1.4 MiB; future production-config proofs may exceed
/// 2 MiB) without admitting unboundedly large frames. Other frame
/// types stay tiny in practice; an attacker who tries to push 8 MiB
/// of, say, an `InvokeRequest` still pays the libp2p handshake cost
/// and downstream code paths cap their own payloads independently.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of hops carried in an `InvokeRequest` chain.
/// Mirrors `MAX_CROSS_AGENT_DEPTH` in `node.rs`. Encoded as a u32
/// length prefix; this cap stops a malicious peer from triggering
/// gigabyte allocations by claiming an absurd chain length.
const MAX_CHAIN_LEN: usize = 32;

/// One frame on the wire. See module docs for tag layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        node_prefix: u16,
    },
    Tell {
        from: u32,
        to: u32,
        payload: Vec<u8>,
    },
    InvokeRequest {
        from: u32,
        to: u32,
        chain: Vec<u32>,
        msg: Vec<u8>,
    },
    InvokeReply {
        payload: Vec<u8>,
    },
    /// "What are your merkle-clock roots for this replication
    /// group?" Sent as a request; reply rides back as
    /// [`Frame::Heads`].
    FetchHeads {
        replication_id: [u8; REPLICATION_ID_BYTES],
    },
    /// Reply to [`Frame::FetchHeads`].
    Heads {
        replication_id: [u8; REPLICATION_ID_BYTES],
        roots: Vec<[u8; CID_BYTES]>,
    },
    /// Point-fetch a single DAG node. Sent as a request; reply
    /// rides back as [`Frame::NodeReply`].
    FetchNode {
        replication_id: [u8; REPLICATION_ID_BYTES],
        cid: [u8; CID_BYTES],
    },
    /// Reply to [`Frame::FetchNode`]. `None` means the peer
    /// doesn't have the node — typically a transient state
    /// during sync, not an error.
    NodeReply {
        node: Option<Vec<u8>>,
    },
    /// Empty acknowledgement — used as the response slot for
    /// fire-and-forget `Tell` so the request_response behaviour
    /// has something to deliver.
    Ack,
    /// Raft `AppendEntries` RPC — leader replicating log entries
    /// to followers. Heartbeats use the same frame with an empty
    /// `entries` vec.
    RaftAppendReq {
        replication_id: [u8; REPLICATION_ID_BYTES],
        term: u64,
        leader_prefix: u16,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entries: Vec<RaftEntry>,
    },
    /// Reply to [`Frame::RaftAppendReq`]. `match_index` is the
    /// last log index the follower has replicated when `success`
    /// is true; ignored otherwise.
    RaftAppendResp {
        term: u64,
        success: bool,
        match_index: u64,
    },
    /// Raft `RequestVote` RPC — candidate soliciting votes.
    RaftVoteReq {
        replication_id: [u8; REPLICATION_ID_BYTES],
        term: u64,
        candidate_prefix: u16,
        last_log_index: u64,
        last_log_term: u64,
    },
    /// Reply to [`Frame::RaftVoteReq`].
    RaftVoteResp {
        term: u64,
        vote_granted: bool,
    },
    /// Raft `InstallSnapshot` RPC — the leader hands a far-behind
    /// follower the actor state at `last_included_index`/term so
    /// the follower doesn't need a log replay it can no longer
    /// reconstruct (the entries have been compacted away).
    /// Single-shot for now; chunked support is a later phase.
    RaftInstallSnapshotReq {
        replication_id: [u8; REPLICATION_ID_BYTES],
        term: u64,
        leader_prefix: u16,
        last_included_index: u64,
        last_included_term: u64,
        /// Opaque actor state at `last_included_index`. Bounded
        /// by `MAX_FRAME_BYTES` (1 MB) like every other length-
        /// prefixed payload.
        snapshot: Vec<u8>,
    },
    /// Reply to [`Frame::RaftInstallSnapshotReq`].
    RaftInstallSnapshotResp {
        term: u64,
    },
    /// Cluster join request — a fresh node asks an existing
    /// replica of `replication_id` to add it as a voter via
    /// joint consensus. Receivers that aren't the leader respond
    /// with [`RaftJoinResult::NotLeader`] + a leader hint;
    /// leaders compute `new_members = current ∪ {joiner_prefix}`
    /// and reply with the joint-entry index once it commits.
    RaftJoinReq {
        replication_id: [u8; REPLICATION_ID_BYTES],
        joiner_prefix: u16,
    },
    /// Reply to [`Frame::RaftJoinReq`].
    RaftJoinResp {
        result: RaftJoinResult,
    },
    /// Manifest fetch — joiner asks bootnode "what space.toml
    /// are you running, and what actor blobs do I need to match
    /// it?". No replication_id; one manifest per node.
    ManifestReq,
    /// Reply to [`Frame::ManifestReq`]. `toml_bytes` is the raw
    /// `space.toml` content; `blobs` is one entry per actor
    /// referenced by the manifest carrying the actor's NAME (as
    /// it appears in `[[agent]] name = …`) and its compiled PVM
    /// blob bytes. Joiners write the blobs into a local cache
    /// keyed by `name` so the actor binary on disk matches the
    /// bootnode's exactly — important for replication_id
    /// derivation (`blake2b(blob || name)`).
    ManifestResp {
        toml_bytes: Vec<u8>,
        blobs: Vec<ManifestBlob>,
    },
    /// Raft status query — a cluster-status reporter asks each
    /// peer "what's your view of replication group X?". Receiver
    /// answers from its [`vos_raft::WorkerSnapshot`].
    RaftStatusReq {
        replication_id: [u8; REPLICATION_ID_BYTES],
    },
    /// Reply to [`Frame::RaftStatusReq`]. `present = false`
    /// means the receiver isn't running this group; the other
    /// fields are zero in that case. Otherwise they mirror
    /// the worker's snapshot.
    RaftStatusResp {
        present: bool,
        role: u8, // 0 = Follower, 1 = PreCandidate, 2 = Candidate, 3 = Leader
        current_term: u64,
        commit_index: u64,
        last_log_index: u64,
        members: Vec<u16>,
        leader_hint: Option<u16>,
    },
    /// Point-fetch a content-addressed proof blob by its 32-byte
    /// hash. Sent as a request; reply rides back as
    /// [`Frame::ProofBlobReply`]. The hash is domain-tagged
    /// blake2b-256 of the blob bytes (see
    /// `node::proof_blob_hash`); receivers either hold the blob
    /// in their local proof-blob store or don't.
    FetchProofBlob {
        hash: [u8; 32],
    },
    /// Reply to [`Frame::FetchProofBlob`]. `None` means the peer
    /// doesn't have the blob (typical when the consumer is asking
    /// the wrong producer first; the consumer can try another
    /// peer). Real STARK bytes ride here; bounded by
    /// `MAX_FRAME_BYTES` (8 MiB) — production proofs exceeding
    /// that need the chunked transport reserved for a later cycle.
    ProofBlobReply {
        blob: Option<Vec<u8>>,
    },
}

/// One actor's name + compiled PVM blob, as ferried by
/// [`Frame::ManifestResp`]. Each blob is bounded by
/// `MAX_FRAME_BYTES` like every other length-prefixed payload —
/// large actor bundles need a follow-up streaming protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBlob {
    pub name: String,
    pub blob: Vec<u8>,
}

/// Outcome of a [`Frame::RaftJoinReq`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaftJoinResult {
    /// The leader proposed a joint-consensus entry adding the
    /// joiner as a voter. `joint_index` is the log index of the
    /// joint entry; the joiner can poll its own
    /// `WorkerSnapshot::commit_index >= joint_index + 1` to know
    /// the retire entry has committed and it's now a steady-state
    /// voter.
    Accepted { joint_index: u64 },
    /// The receiver is not the leader of this replication group.
    /// `leader_hint` is the prefix it last saw as leader, if any —
    /// the joiner should retry the request against that peer.
    NotLeader { leader_hint: Option<u16> },
    /// The receiver isn't running the requested replication group
    /// at all. Joiner picks another bootnode.
    UnknownGroup,
    /// `change_membership` rejected the proposal — typically
    /// because another joint-consensus change is in flight.
    /// Joiner backs off and retries.
    Busy,
}

/// One log entry carried inside an [`Frame::RaftAppendReq`].
///
/// `Data` entries ferry the raw `EffectLog::to_bytes()` blob
/// the leader has in its `raft_log` table — the receiver
/// writes it straight back out without re-encoding.
/// `ConfigChange` entries carry the new membership view (and,
/// for joint-consensus phases, the previous view too); the
/// vos-raft worker consumes them to update its quorum
/// computation and the host's apply path skips them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftEntry {
    pub term: u64,
    pub kind: RaftEntryKind,
}

/// Variant tag inside a [`RaftEntry`]. Mirrors
/// `vos_raft::log_entry::EntryKind` over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaftEntryKind {
    /// Application data — opaque to the consensus layer.
    Data { payload: Vec<u8> },
    /// Cluster membership transition (Ongaro thesis §4.3).
    /// `members` is the configuration the cluster transitions
    /// *to*. `joint_old = Some(...)` indicates the joint phase;
    /// `None` retires it.
    ConfigChange {
        joint_old: Option<Vec<u16>>,
        members: Vec<u16>,
    },
}

impl RaftEntry {
    /// Convenience — build a `Data` variant.
    pub fn data(term: u64, payload: Vec<u8>) -> Self {
        Self {
            term,
            kind: RaftEntryKind::Data { payload },
        }
    }

    /// Convenience — build a `ConfigChange` variant.
    pub fn config_change(term: u64, joint_old: Option<Vec<u16>>, members: Vec<u16>) -> Self {
        Self {
            term,
            kind: RaftEntryKind::ConfigChange { joint_old, members },
        }
    }
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Frame::Hello { node_prefix } => {
                out.push(TAG_HELLO);
                out.extend_from_slice(&node_prefix.to_le_bytes());
            }
            Frame::Tell { from, to, payload } => {
                out.push(TAG_TELL);
                out.extend_from_slice(&from.to_le_bytes());
                out.extend_from_slice(&to.to_le_bytes());
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
            }
            Frame::InvokeRequest {
                from,
                to,
                chain,
                msg,
            } => {
                out.push(TAG_INVOKE_REQ);
                out.extend_from_slice(&from.to_le_bytes());
                out.extend_from_slice(&to.to_le_bytes());
                out.extend_from_slice(&(chain.len() as u32).to_le_bytes());
                for hop in chain {
                    out.extend_from_slice(&hop.to_le_bytes());
                }
                out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
                out.extend_from_slice(msg);
            }
            Frame::InvokeReply { payload } => {
                out.push(TAG_INVOKE_REPLY);
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
            }
            Frame::FetchHeads { replication_id } => {
                out.push(TAG_FETCH_HEADS);
                out.extend_from_slice(replication_id);
            }
            Frame::Heads {
                replication_id,
                roots,
            } => {
                out.push(TAG_HEADS);
                out.extend_from_slice(replication_id);
                out.extend_from_slice(&(roots.len() as u32).to_le_bytes());
                for cid in roots {
                    out.extend_from_slice(cid);
                }
            }
            Frame::FetchNode {
                replication_id,
                cid,
            } => {
                out.push(TAG_FETCH_NODE);
                out.extend_from_slice(replication_id);
                out.extend_from_slice(cid);
            }
            Frame::NodeReply { node } => {
                out.push(TAG_NODE_REPLY);
                match node {
                    Some(bytes) => {
                        out.push(1);
                        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                        out.extend_from_slice(bytes);
                    }
                    None => {
                        out.push(0);
                    }
                }
            }
            Frame::Ack => {
                out.push(TAG_ACK);
            }
            Frame::RaftAppendReq {
                replication_id,
                term,
                leader_prefix,
                prev_log_index,
                prev_log_term,
                leader_commit,
                entries,
            } => {
                out.push(TAG_RAFT_APPEND_REQ);
                out.extend_from_slice(replication_id);
                out.extend_from_slice(&term.to_le_bytes());
                out.extend_from_slice(&leader_prefix.to_le_bytes());
                out.extend_from_slice(&prev_log_index.to_le_bytes());
                out.extend_from_slice(&prev_log_term.to_le_bytes());
                out.extend_from_slice(&leader_commit.to_le_bytes());
                out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
                for e in entries {
                    out.extend_from_slice(&e.term.to_le_bytes());
                    match &e.kind {
                        RaftEntryKind::Data { payload } => {
                            out.push(RAFT_ENTRY_KIND_DATA);
                            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                            out.extend_from_slice(payload);
                        }
                        RaftEntryKind::ConfigChange { joint_old, members } => {
                            out.push(RAFT_ENTRY_KIND_CONFIG_CHANGE);
                            match joint_old {
                                Some(prev) => {
                                    out.push(1);
                                    out.extend_from_slice(&(prev.len() as u16).to_le_bytes());
                                    for n in prev {
                                        out.extend_from_slice(&n.to_le_bytes());
                                    }
                                }
                                None => out.push(0),
                            }
                            out.extend_from_slice(&(members.len() as u16).to_le_bytes());
                            for n in members {
                                out.extend_from_slice(&n.to_le_bytes());
                            }
                        }
                    }
                }
            }
            Frame::RaftAppendResp {
                term,
                success,
                match_index,
            } => {
                out.push(TAG_RAFT_APPEND_RESP);
                out.extend_from_slice(&term.to_le_bytes());
                out.push(if *success { 1 } else { 0 });
                out.extend_from_slice(&match_index.to_le_bytes());
            }
            Frame::RaftVoteReq {
                replication_id,
                term,
                candidate_prefix,
                last_log_index,
                last_log_term,
            } => {
                out.push(TAG_RAFT_VOTE_REQ);
                out.extend_from_slice(replication_id);
                out.extend_from_slice(&term.to_le_bytes());
                out.extend_from_slice(&candidate_prefix.to_le_bytes());
                out.extend_from_slice(&last_log_index.to_le_bytes());
                out.extend_from_slice(&last_log_term.to_le_bytes());
            }
            Frame::RaftVoteResp { term, vote_granted } => {
                out.push(TAG_RAFT_VOTE_RESP);
                out.extend_from_slice(&term.to_le_bytes());
                out.push(if *vote_granted { 1 } else { 0 });
            }
            Frame::RaftInstallSnapshotReq {
                replication_id,
                term,
                leader_prefix,
                last_included_index,
                last_included_term,
                snapshot,
            } => {
                out.push(TAG_RAFT_INSTALL_REQ);
                out.extend_from_slice(replication_id);
                out.extend_from_slice(&term.to_le_bytes());
                out.extend_from_slice(&leader_prefix.to_le_bytes());
                out.extend_from_slice(&last_included_index.to_le_bytes());
                out.extend_from_slice(&last_included_term.to_le_bytes());
                out.extend_from_slice(&(snapshot.len() as u32).to_le_bytes());
                out.extend_from_slice(snapshot);
            }
            Frame::RaftInstallSnapshotResp { term } => {
                out.push(TAG_RAFT_INSTALL_RESP);
                out.extend_from_slice(&term.to_le_bytes());
            }
            Frame::RaftJoinReq {
                replication_id,
                joiner_prefix,
            } => {
                out.push(TAG_RAFT_JOIN_REQ);
                out.extend_from_slice(replication_id);
                out.extend_from_slice(&joiner_prefix.to_le_bytes());
            }
            Frame::RaftJoinResp { result } => {
                out.push(TAG_RAFT_JOIN_RESP);
                match result {
                    RaftJoinResult::Accepted { joint_index } => {
                        out.push(0);
                        out.extend_from_slice(&joint_index.to_le_bytes());
                    }
                    RaftJoinResult::NotLeader { leader_hint } => {
                        out.push(1);
                        match leader_hint {
                            Some(p) => {
                                out.push(1);
                                out.extend_from_slice(&p.to_le_bytes());
                            }
                            None => out.push(0),
                        }
                    }
                    RaftJoinResult::UnknownGroup => out.push(2),
                    RaftJoinResult::Busy => out.push(3),
                }
            }
            Frame::ManifestReq => {
                out.push(TAG_MANIFEST_REQ);
            }
            Frame::ManifestResp { toml_bytes, blobs } => {
                out.push(TAG_MANIFEST_RESP);
                out.extend_from_slice(&(toml_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(toml_bytes);
                out.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
                for b in blobs {
                    let name_bytes = b.name.as_bytes();
                    out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                    out.extend_from_slice(name_bytes);
                    out.extend_from_slice(&(b.blob.len() as u32).to_le_bytes());
                    out.extend_from_slice(&b.blob);
                }
            }
            Frame::RaftStatusReq { replication_id } => {
                out.push(TAG_RAFT_STATUS_REQ);
                out.extend_from_slice(replication_id);
            }
            Frame::RaftStatusResp {
                present,
                role,
                current_term,
                commit_index,
                last_log_index,
                members,
                leader_hint,
            } => {
                out.push(TAG_RAFT_STATUS_RESP);
                out.push(if *present { 1 } else { 0 });
                out.push(*role);
                out.extend_from_slice(&current_term.to_le_bytes());
                out.extend_from_slice(&commit_index.to_le_bytes());
                out.extend_from_slice(&last_log_index.to_le_bytes());
                out.extend_from_slice(&(members.len() as u16).to_le_bytes());
                for m in members {
                    out.extend_from_slice(&m.to_le_bytes());
                }
                match leader_hint {
                    Some(h) => {
                        out.push(1);
                        out.extend_from_slice(&h.to_le_bytes());
                    }
                    None => out.push(0),
                }
            }
            Frame::FetchProofBlob { hash } => {
                out.push(TAG_FETCH_PROOF_BLOB);
                out.extend_from_slice(hash);
            }
            Frame::ProofBlobReply { blob } => {
                out.push(TAG_PROOF_BLOB_REPLY);
                match blob {
                    Some(bytes) => {
                        out.push(1);
                        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                        out.extend_from_slice(bytes);
                    }
                    None => {
                        out.push(0);
                    }
                }
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let frame = match tag {
            TAG_HELLO => Frame::Hello {
                node_prefix: r.u16()?,
            },
            TAG_TELL => Frame::Tell {
                from: r.u32()?,
                to: r.u32()?,
                payload: r.bytes_with_len_prefix()?,
            },
            TAG_INVOKE_REQ => {
                let from = r.u32()?;
                let to = r.u32()?;
                let chain_len = r.u32()? as usize;
                if chain_len > MAX_CHAIN_LEN {
                    return Err(FrameError::ChainTooLong(chain_len));
                }
                let mut chain = Vec::with_capacity(chain_len);
                for _ in 0..chain_len {
                    chain.push(r.u32()?);
                }
                let msg = r.bytes_with_len_prefix()?;
                Frame::InvokeRequest {
                    from,
                    to,
                    chain,
                    msg,
                }
            }
            TAG_INVOKE_REPLY => Frame::InvokeReply {
                payload: r.bytes_with_len_prefix()?,
            },
            TAG_FETCH_HEADS => Frame::FetchHeads {
                replication_id: r.fixed::<REPLICATION_ID_BYTES>()?,
            },
            TAG_HEADS => {
                let replication_id = r.fixed::<REPLICATION_ID_BYTES>()?;
                let count = r.u32()? as usize;
                if count > MAX_HEADS {
                    return Err(FrameError::HeadsTooMany(count));
                }
                let mut roots = Vec::with_capacity(count);
                for _ in 0..count {
                    roots.push(r.fixed::<CID_BYTES>()?);
                }
                Frame::Heads {
                    replication_id,
                    roots,
                }
            }
            TAG_FETCH_NODE => Frame::FetchNode {
                replication_id: r.fixed::<REPLICATION_ID_BYTES>()?,
                cid: r.fixed::<CID_BYTES>()?,
            },
            TAG_NODE_REPLY => {
                let present = r.u8()?;
                let node = match present {
                    0 => None,
                    1 => Some(r.bytes_with_len_prefix()?),
                    other => return Err(FrameError::BadOption(other)),
                };
                Frame::NodeReply { node }
            }
            TAG_ACK => Frame::Ack,
            TAG_RAFT_APPEND_REQ => {
                let replication_id = r.fixed::<REPLICATION_ID_BYTES>()?;
                let term = r.u64()?;
                let leader_prefix = r.u16()?;
                let prev_log_index = r.u64()?;
                let prev_log_term = r.u64()?;
                let leader_commit = r.u64()?;
                let n = r.u32()? as usize;
                if n > MAX_RAFT_ENTRIES {
                    return Err(FrameError::RaftEntriesTooMany(n));
                }
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    let entry_term = r.u64()?;
                    let kind_tag = r.u8()?;
                    let kind = match kind_tag {
                        RAFT_ENTRY_KIND_DATA => {
                            let payload = r.bytes_with_len_prefix()?;
                            RaftEntryKind::Data { payload }
                        }
                        RAFT_ENTRY_KIND_CONFIG_CHANGE => {
                            let joint_old_present = r.u8()?;
                            let joint_old = match joint_old_present {
                                0 => None,
                                1 => {
                                    let len = r.u16()? as usize;
                                    if len > MAX_RAFT_MEMBERS {
                                        return Err(FrameError::RaftMembersTooMany(len));
                                    }
                                    let mut v = Vec::with_capacity(len);
                                    for _ in 0..len {
                                        v.push(r.u16()?);
                                    }
                                    Some(v)
                                }
                                other => return Err(FrameError::BadOption(other)),
                            };
                            let len = r.u16()? as usize;
                            if len > MAX_RAFT_MEMBERS {
                                return Err(FrameError::RaftMembersTooMany(len));
                            }
                            let mut members = Vec::with_capacity(len);
                            for _ in 0..len {
                                members.push(r.u16()?);
                            }
                            RaftEntryKind::ConfigChange { joint_old, members }
                        }
                        other => return Err(FrameError::BadRaftEntryKind(other)),
                    };
                    entries.push(RaftEntry {
                        term: entry_term,
                        kind,
                    });
                }
                Frame::RaftAppendReq {
                    replication_id,
                    term,
                    leader_prefix,
                    prev_log_index,
                    prev_log_term,
                    leader_commit,
                    entries,
                }
            }
            TAG_RAFT_APPEND_RESP => {
                let term = r.u64()?;
                let success = match r.u8()? {
                    0 => false,
                    1 => true,
                    other => return Err(FrameError::BadOption(other)),
                };
                let match_index = r.u64()?;
                Frame::RaftAppendResp {
                    term,
                    success,
                    match_index,
                }
            }
            TAG_RAFT_VOTE_REQ => Frame::RaftVoteReq {
                replication_id: r.fixed::<REPLICATION_ID_BYTES>()?,
                term: r.u64()?,
                candidate_prefix: r.u16()?,
                last_log_index: r.u64()?,
                last_log_term: r.u64()?,
            },
            TAG_RAFT_VOTE_RESP => {
                let term = r.u64()?;
                let vote_granted = match r.u8()? {
                    0 => false,
                    1 => true,
                    other => return Err(FrameError::BadOption(other)),
                };
                Frame::RaftVoteResp { term, vote_granted }
            }
            TAG_RAFT_INSTALL_REQ => {
                let replication_id = r.fixed::<REPLICATION_ID_BYTES>()?;
                let term = r.u64()?;
                let leader_prefix = r.u16()?;
                let last_included_index = r.u64()?;
                let last_included_term = r.u64()?;
                let snapshot = r.bytes_with_len_prefix()?;
                Frame::RaftInstallSnapshotReq {
                    replication_id,
                    term,
                    leader_prefix,
                    last_included_index,
                    last_included_term,
                    snapshot,
                }
            }
            TAG_RAFT_INSTALL_RESP => Frame::RaftInstallSnapshotResp { term: r.u64()? },
            TAG_RAFT_JOIN_REQ => Frame::RaftJoinReq {
                replication_id: r.fixed::<REPLICATION_ID_BYTES>()?,
                joiner_prefix: r.u16()?,
            },
            TAG_RAFT_JOIN_RESP => {
                let variant = r.u8()?;
                let result = match variant {
                    0 => RaftJoinResult::Accepted {
                        joint_index: r.u64()?,
                    },
                    1 => {
                        let leader_hint = match r.u8()? {
                            0 => None,
                            1 => Some(r.u16()?),
                            other => return Err(FrameError::BadOption(other)),
                        };
                        RaftJoinResult::NotLeader { leader_hint }
                    }
                    2 => RaftJoinResult::UnknownGroup,
                    3 => RaftJoinResult::Busy,
                    other => return Err(FrameError::BadOption(other)),
                };
                Frame::RaftJoinResp { result }
            }
            TAG_MANIFEST_REQ => Frame::ManifestReq,
            TAG_MANIFEST_RESP => {
                let toml_bytes = r.bytes_with_len_prefix()?;
                let n_blobs = r.u32()? as usize;
                if n_blobs > MANIFEST_MAX_BLOBS {
                    return Err(FrameError::ManifestTooManyBlobs(n_blobs));
                }
                let mut blobs = Vec::with_capacity(n_blobs);
                for _ in 0..n_blobs {
                    let name_bytes = r.bytes_with_len_prefix()?;
                    let name =
                        String::from_utf8(name_bytes).map_err(|_| FrameError::ManifestBadName)?;
                    let blob = r.bytes_with_len_prefix()?;
                    blobs.push(ManifestBlob { name, blob });
                }
                Frame::ManifestResp { toml_bytes, blobs }
            }
            TAG_RAFT_STATUS_REQ => Frame::RaftStatusReq {
                replication_id: r.fixed::<REPLICATION_ID_BYTES>()?,
            },
            TAG_RAFT_STATUS_RESP => {
                let present = match r.u8()? {
                    0 => false,
                    1 => true,
                    other => return Err(FrameError::BadOption(other)),
                };
                let role = r.u8()?;
                let current_term = r.u64()?;
                let commit_index = r.u64()?;
                let last_log_index = r.u64()?;
                let n = r.u16()? as usize;
                if n > MAX_RAFT_MEMBERS {
                    return Err(FrameError::RaftMembersTooMany(n));
                }
                let mut members = Vec::with_capacity(n);
                for _ in 0..n {
                    members.push(r.u16()?);
                }
                let leader_hint = match r.u8()? {
                    0 => None,
                    1 => Some(r.u16()?),
                    other => return Err(FrameError::BadOption(other)),
                };
                Frame::RaftStatusResp {
                    present,
                    role,
                    current_term,
                    commit_index,
                    last_log_index,
                    members,
                    leader_hint,
                }
            }
            TAG_FETCH_PROOF_BLOB => Frame::FetchProofBlob {
                hash: r.fixed::<32>()?,
            },
            TAG_PROOF_BLOB_REPLY => {
                let present = r.u8()?;
                let blob = match present {
                    0 => None,
                    1 => Some(r.bytes_with_len_prefix()?),
                    other => return Err(FrameError::BadOption(other)),
                };
                Frame::ProofBlobReply { blob }
            }
            other => return Err(FrameError::UnknownTag(other)),
        };
        if !r.is_empty() {
            return Err(FrameError::TrailingBytes(r.remaining()));
        }
        Ok(frame)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    UnknownTag(u8),
    ChainTooLong(usize),
    PayloadTooLarge(usize),
    TrailingBytes(usize),
    HeadsTooMany(usize),
    BadOption(u8),
    RaftEntriesTooMany(usize),
    RaftMembersTooMany(usize),
    BadRaftEntryKind(u8),
    ManifestTooManyBlobs(usize),
    ManifestBadName,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::Truncated => write!(f, "frame truncated"),
            FrameError::UnknownTag(t) => write!(f, "unknown frame tag {t:#04x}"),
            FrameError::ChainTooLong(n) => {
                write!(f, "chain length {n} exceeds cap {MAX_CHAIN_LEN}")
            }
            FrameError::PayloadTooLarge(n) => {
                write!(f, "payload length {n} exceeds cap {MAX_FRAME_BYTES}")
            }
            FrameError::TrailingBytes(n) => write!(f, "{n} trailing bytes after frame"),
            FrameError::HeadsTooMany(n) => {
                write!(f, "heads count {n} exceeds cap {MAX_HEADS}")
            }
            FrameError::BadOption(b) => write!(f, "invalid Option discriminant {b}"),
            FrameError::RaftEntriesTooMany(n) => {
                write!(f, "raft entry count {n} exceeds cap {MAX_RAFT_ENTRIES}")
            }
            FrameError::RaftMembersTooMany(n) => {
                write!(
                    f,
                    "raft member list length {n} exceeds cap {MAX_RAFT_MEMBERS}"
                )
            }
            FrameError::BadRaftEntryKind(b) => {
                write!(f, "invalid raft entry kind discriminant {b}")
            }
            FrameError::ManifestTooManyBlobs(n) => {
                write!(
                    f,
                    "manifest blob count {n} exceeds cap {MANIFEST_MAX_BLOBS}"
                )
            }
            FrameError::ManifestBadName => {
                write!(f, "manifest blob name was not valid UTF-8")
            }
        }
    }
}

impl std::error::Error for FrameError {}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        if self.pos + n > self.buf.len() {
            return Err(FrameError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, FrameError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, FrameError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, FrameError> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
    fn bytes_with_len_prefix(&mut self) -> Result<Vec<u8>, FrameError> {
        let len = self.u32()? as usize;
        if len > MAX_FRAME_BYTES {
            return Err(FrameError::PayloadTooLarge(len));
        }
        Ok(self.take(len)?.to_vec())
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn hello_roundtrip() {
        roundtrip(Frame::Hello {
            node_prefix: 0x42AB,
        });
        roundtrip(Frame::Hello { node_prefix: 0 });
        roundtrip(Frame::Hello {
            node_prefix: u16::MAX,
        });
    }

    #[test]
    fn tell_roundtrip() {
        roundtrip(Frame::Tell {
            from: 0x00010002,
            to: 0x00030004,
            payload: vec![],
        });
        roundtrip(Frame::Tell {
            from: 0xDEADBEEF,
            to: 0xCAFEF00D,
            payload: b"hello world".to_vec(),
        });
    }

    #[test]
    fn invoke_request_roundtrip() {
        roundtrip(Frame::InvokeRequest {
            from: 1,
            to: 2,
            chain: vec![],
            msg: vec![],
        });
        roundtrip(Frame::InvokeRequest {
            from: 1,
            to: 2,
            chain: vec![1, 2, 3, 4],
            msg: b"payload".to_vec(),
        });
    }

    #[test]
    fn invoke_reply_roundtrip() {
        roundtrip(Frame::InvokeReply { payload: vec![] });
        roundtrip(Frame::InvokeReply {
            payload: vec![0x00, 0xFF, 0x42],
        });
    }

    #[test]
    fn ack_roundtrip() {
        roundtrip(Frame::Ack);
    }

    #[test]
    fn fetch_heads_roundtrip() {
        roundtrip(Frame::FetchHeads {
            replication_id: [0u8; REPLICATION_ID_BYTES],
        });
        let mut id = [0u8; REPLICATION_ID_BYTES];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        roundtrip(Frame::FetchHeads { replication_id: id });
    }

    #[test]
    fn heads_roundtrip() {
        roundtrip(Frame::Heads {
            replication_id: [0xAA; REPLICATION_ID_BYTES],
            roots: vec![],
        });
        roundtrip(Frame::Heads {
            replication_id: [0xAA; REPLICATION_ID_BYTES],
            roots: vec![[0xBB; CID_BYTES], [0xCC; CID_BYTES]],
        });
    }

    #[test]
    fn fetch_node_roundtrip() {
        roundtrip(Frame::FetchNode {
            replication_id: [0x01; REPLICATION_ID_BYTES],
            cid: [0x02; CID_BYTES],
        });
    }

    #[test]
    fn node_reply_roundtrip() {
        roundtrip(Frame::NodeReply { node: None });
        roundtrip(Frame::NodeReply {
            node: Some(b"opaque dag node bytes".to_vec()),
        });
    }

    #[test]
    fn heads_count_capped() {
        let mut bad = Vec::new();
        bad.push(TAG_HEADS);
        bad.extend_from_slice(&[0u8; REPLICATION_ID_BYTES]);
        // claim 10_000 heads
        bad.extend_from_slice(&(10_000u32).to_le_bytes());
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::HeadsTooMany(10_000))
        ));
    }

    #[test]
    fn node_reply_bad_option_rejected() {
        let mut bad = Vec::new();
        bad.push(TAG_NODE_REPLY);
        bad.push(2); // not 0 or 1
        assert!(matches!(Frame::decode(&bad), Err(FrameError::BadOption(2))));
    }

    #[test]
    fn fetch_proof_blob_roundtrip() {
        roundtrip(Frame::FetchProofBlob { hash: [0xAB; 32] });
    }

    #[test]
    fn proof_blob_reply_roundtrip() {
        roundtrip(Frame::ProofBlobReply { blob: None });
        roundtrip(Frame::ProofBlobReply {
            blob: Some(b"stark proof body".to_vec()),
        });
        // Large blob — exercises the MAX_FRAME_BYTES lift.
        let big = vec![0x55u8; 2 * 1024 * 1024];
        roundtrip(Frame::ProofBlobReply { blob: Some(big) });
    }

    #[test]
    fn proof_blob_reply_bad_option_rejected() {
        let mut bad = Vec::new();
        bad.push(TAG_PROOF_BLOB_REPLY);
        bad.push(2);
        assert!(matches!(Frame::decode(&bad), Err(FrameError::BadOption(2))));
    }

    #[test]
    fn truncated_input_rejected() {
        // Just the tag, no body.
        assert!(matches!(
            Frame::decode(&[TAG_HELLO]),
            Err(FrameError::Truncated)
        ));
        // Tell with zero-length payload but missing the length field.
        assert!(matches!(
            Frame::decode(&[TAG_TELL, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn unknown_tag_rejected() {
        assert!(matches!(
            Frame::decode(&[0xFE]),
            Err(FrameError::UnknownTag(0xFE))
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bad = Frame::Ack.encode();
        bad.push(0x99);
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::TrailingBytes(1))
        ));
    }

    #[test]
    fn chain_length_capped() {
        // Forge a frame claiming a chain of 1_000 entries.
        let mut bad = Vec::new();
        bad.push(TAG_INVOKE_REQ);
        bad.extend_from_slice(&0u32.to_le_bytes()); // from
        bad.extend_from_slice(&0u32.to_le_bytes()); // to
        bad.extend_from_slice(&(1_000u32).to_le_bytes()); // chain_len
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::ChainTooLong(1_000))
        ));
    }

    #[test]
    fn payload_length_capped() {
        // Forge a frame claiming a 10 MiB payload.
        let mut bad = Vec::new();
        bad.push(TAG_TELL);
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&(10 * 1024 * 1024u32).to_le_bytes());
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::PayloadTooLarge(_))
        ));
    }

    // ── Raft frames ─────────────────────────────────────────────

    #[test]
    fn raft_append_req_roundtrip_empty_entries_is_heartbeat() {
        roundtrip(Frame::RaftAppendReq {
            replication_id: [0xAA; REPLICATION_ID_BYTES],
            term: 7,
            leader_prefix: 0x1234,
            prev_log_index: 42,
            prev_log_term: 6,
            leader_commit: 41,
            entries: vec![],
        });
    }

    #[test]
    fn raft_append_req_roundtrip_with_entries() {
        roundtrip(Frame::RaftAppendReq {
            replication_id: [0xAA; REPLICATION_ID_BYTES],
            term: 7,
            leader_prefix: 0x1234,
            prev_log_index: 42,
            prev_log_term: 6,
            leader_commit: 43,
            entries: vec![
                RaftEntry::data(6, vec![]),
                RaftEntry::data(7, b"first entry".to_vec()),
                RaftEntry::data(7, vec![0x99; 4096]),
                // ConfigChange variant — joint phase carrying the
                // previous member set + the new one.
                RaftEntry::config_change(
                    7,
                    Some(vec![0xAAAA, 0xBBBB]),
                    vec![0xAAAA, 0xBBBB, 0xCCCC],
                ),
                // ConfigChange retire — joint_old=None, just the
                // final members list.
                RaftEntry::config_change(8, None, vec![0xAAAA, 0xBBBB, 0xCCCC]),
            ],
        });
    }

    #[test]
    fn raft_append_resp_roundtrip_success_and_failure() {
        roundtrip(Frame::RaftAppendResp {
            term: 7,
            success: true,
            match_index: 42,
        });
        roundtrip(Frame::RaftAppendResp {
            term: 7,
            success: false,
            match_index: 0,
        });
    }

    #[test]
    fn raft_vote_req_roundtrip() {
        roundtrip(Frame::RaftVoteReq {
            replication_id: [0x11; REPLICATION_ID_BYTES],
            term: 9,
            candidate_prefix: 0xBEEF,
            last_log_index: 100,
            last_log_term: 8,
        });
    }

    #[test]
    fn raft_vote_resp_roundtrip() {
        roundtrip(Frame::RaftVoteResp {
            term: 9,
            vote_granted: true,
        });
        roundtrip(Frame::RaftVoteResp {
            term: 9,
            vote_granted: false,
        });
    }

    #[test]
    fn raft_append_resp_bad_success_byte_rejected() {
        let mut bad = Vec::new();
        bad.push(TAG_RAFT_APPEND_RESP);
        bad.extend_from_slice(&0u64.to_le_bytes()); // term
        bad.push(2); // not 0 or 1
        bad.extend_from_slice(&0u64.to_le_bytes()); // match_index
        assert!(matches!(Frame::decode(&bad), Err(FrameError::BadOption(2))));
    }

    #[test]
    fn raft_vote_resp_bad_granted_byte_rejected() {
        let mut bad = Vec::new();
        bad.push(TAG_RAFT_VOTE_RESP);
        bad.extend_from_slice(&0u64.to_le_bytes()); // term
        bad.push(7); // not 0 or 1
        assert!(matches!(Frame::decode(&bad), Err(FrameError::BadOption(7))));
    }

    #[test]
    fn raft_install_snapshot_req_roundtrip() {
        roundtrip(Frame::RaftInstallSnapshotReq {
            replication_id: [0x22; REPLICATION_ID_BYTES],
            term: 9,
            leader_prefix: 0xAAAA,
            last_included_index: 100,
            last_included_term: 8,
            snapshot: b"opaque actor state".to_vec(),
        });
        // Empty snapshot — degenerate but valid.
        roundtrip(Frame::RaftInstallSnapshotReq {
            replication_id: [0x22; REPLICATION_ID_BYTES],
            term: 1,
            leader_prefix: 0,
            last_included_index: 0,
            last_included_term: 0,
            snapshot: vec![],
        });
    }

    #[test]
    fn raft_install_snapshot_resp_roundtrip() {
        roundtrip(Frame::RaftInstallSnapshotResp { term: 9 });
    }

    #[test]
    fn raft_append_entries_count_capped() {
        let mut bad = Vec::new();
        bad.push(TAG_RAFT_APPEND_REQ);
        bad.extend_from_slice(&[0u8; REPLICATION_ID_BYTES]);
        bad.extend_from_slice(&0u64.to_le_bytes()); // term
        bad.extend_from_slice(&0u16.to_le_bytes()); // leader_prefix
        bad.extend_from_slice(&0u64.to_le_bytes()); // prev_log_index
        bad.extend_from_slice(&0u64.to_le_bytes()); // prev_log_term
        bad.extend_from_slice(&0u64.to_le_bytes()); // leader_commit
        bad.extend_from_slice(&100_000u32.to_le_bytes()); // entries count
        assert!(matches!(
            Frame::decode(&bad),
            Err(FrameError::RaftEntriesTooMany(100_000))
        ));
    }
}
