//! Space-registry protocol — the wire types, constants, and canonical
//! signing-byte encodings shared by the `space-registry` PVM actor
//! (verifier), the `vosx` CLI (signer/reader), and the daemon's
//! sign-on-relay path.
//!
//! These used to live in the `space-registry` actor crate, which forced
//! a mirror here (`registry_canon`) because `vos` can't depend on an
//! actor crate that already depends on `vos`. Hoisting the protocol into
//! `vos` ends that cycle: the actor now `pub use`s these back, so there
//! is one source of truth for the consensus-critical byte layouts and
//! the drift-pin cross-check test is no longer needed.
//!
//! Everything here is `no_std` + `alloc` only — the row types must
//! compile for the actor's `service`/`wasm` builds. The verifier-side
//! `verify_op_sig` (ed25519) deliberately STAYS in the actor so its
//! `ed25519-dalek` dependency never reaches `vos`; it consumes
//! [`ed25519_pubkey_from_peer_id`] from here.

use alloc::string::String;
use alloc::vec::Vec;

// ── Programs ──────────────────────────────────────────────────────

/// One row in the program catalog.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ProgramRow {
    pub name: String,
    pub version: String,
    pub hash: [u8; 32],
}

/// One row in the agent (installed-instance) table.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AgentRow {
    pub instance_name: String,
    /// Pinned at install time so a program retag never silently
    /// changes the code an agent runs.
    pub program_hash: [u8; 32],
    /// Display-only references to the program catalog. Agents
    /// resolve code via `program_hash`; these are for
    /// `space agents` listings and manifest export.
    pub program_name: String,
    pub program_version: String,
    pub replication_id: [u8; 32],
    /// 0 = Ephemeral, 1 = Local, 2 = Crdt, 3 = Raft. Mirrors
    /// `vos::node::Consistency` discriminants.
    pub consistency: u8,
    /// Opt this node-confined (`Local`/`Ephemeral`) agent OUT of the
    /// device-confinement gate so remote peers can reach it — for the
    /// network-served bridges (`clerk-bridge`, `space-bridge`). `false`
    /// (confined, device-private) by default; `Crdt`/`Raft` agents are never
    /// confined and ignore it. See
    /// [`vos::node::AgentConfig::network_reachable`].
    pub network_reachable: bool,
    /// rkyv-encoded `vos::init::InitArgs` captured at install
    /// time. New replicas use this to bootstrap their copy of
    /// the agent before its first message arrives. Empty when
    /// the agent was installed without init args.
    pub install_args: Vec<u8>,
    /// Optional one-shot messages to dispatch when the agent
    /// is first cold-started. rkyv-encoded `Vec<Vec<u8>>`
    /// where each inner `Vec<u8>` is a `[TAG_DYNAMIC] + rkyv(Msg)`
    /// payload. Reconciled from the manifest's `on_start = [{msg=…}]`
    /// list. Empty when the agent has no on_start.
    pub install_payloads: Vec<u8>,
}

// ── Members ──────────────────────────────────────────────────────

/// Member kind discriminant.
pub const MEMBER_KIND_NODE: u8 = 0;
pub const MEMBER_KIND_IDENTITY: u8 = 1;

/// Node role discriminant (only meaningful when `kind = Node`).
pub const NODE_ROLE_VOTER: u8 = 0;
pub const NODE_ROLE_OBSERVER: u8 = 1;

/// Identity proof-kind discriminant (only meaningful when
/// `kind = Identity`).
pub const PROOF_KIND_MERKLE_INCLUSION: u8 = 0;
pub const PROOF_KIND_ZK: u8 = 1;

/// One row in the member table — discriminated union over
/// `Node` and `Identity` shapes flattened into a single record
/// so the wire format stays a single `Vec<MemberRow>` query.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct MemberRow {
    /// `MEMBER_KIND_NODE` or `MEMBER_KIND_IDENTITY`.
    pub kind: u8,
    /// `peer_id` bytes (Node) or `public_key` bytes (Identity).
    pub key: Vec<u8>,
    /// Node prefix; 0 when `kind = Identity`.
    pub prefix: u16,
    /// `NODE_ROLE_*` value; 0 when `kind = Identity`.
    pub role: u8,
    /// `PROOF_KIND_*` value; 0 when `kind = Node`.
    pub proof_kind: u8,
    /// Serialized proof bytes; empty when `kind = Node`.
    pub proof_data: Vec<u8>,
}

// ── Auth grants ───────────────────────────────────────────────────
//
// Hierarchy: `ADMIN > DEVELOPER > READONLY > NONE`. Unenrolled peers
// default to `NONE`. The dispatch-layer gate in
// `vos::node::dispatch_invoke` compares the *required* role for a
// handler against the caller's *granted* role.

pub const AUTH_ROLE_NONE: u8 = 0;
pub const AUTH_ROLE_READONLY: u8 = 1;
pub const AUTH_ROLE_DEVELOPER: u8 = 2;
pub const AUTH_ROLE_ADMIN: u8 = 3;

/// Per-PeerId auth grant. `peer_id` is the libp2p PeerId in
/// multihash bytes (same encoding as `MemberRow.key` when
/// `kind = Node`); `role` is one of the `AUTH_ROLE_*` constants.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AuthGrantRow {
    pub peer_id: Vec<u8>,
    pub role: u8,
    /// Monotonic grant epoch. A grant only takes effect while its
    /// epoch is strictly above the peer's `revoke_epochs` high-water,
    /// so a replayed (stale-epoch) grant can never resurrect a revoked
    /// role and a fresh re-grant must carry a higher epoch (the CLI
    /// reads the peer's epoch and signs `epoch + 1`).
    pub epoch: u64,
    /// PeerId of the op's signer — the delegator. Authority is resolved
    /// on demand by the actor's `effective_role`: this grant counts only
    /// if `grantor` is itself the genesis root or a transitively-effective
    /// admin, so revoking a delegator voids its whole subtree regardless
    /// of replay order.
    pub grantor: Vec<u8>,
}

/// Per-(PeerId, agent_name) ACL row — the actor-local override table.
/// Lookup precedence in the dispatch path is `actor_acls` keyed on
/// `(peer_id, agent_name)`, falling back to `auth_grants` keyed on
/// `peer_id` (space-level). `role` discriminants are interpreted in the
/// *target actor's* `Role` enum; the registry stores them opaquely.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ActorAclRow {
    pub peer_id: Vec<u8>,
    pub agent_name: String,
    pub role: u8,
    /// Monotonic grant epoch — see [`AuthGrantRow::epoch`]. Compared
    /// against the matching per-actor revoke high-water.
    pub epoch: u64,
    /// PeerId of the delegator. The actor-local grant counts only if the
    /// grantor is a transitively-effective *space* admin.
    pub grantor: Vec<u8>,
}

// ── Result codes ─────────────────────────────────────────────────

/// Status returned by a mutation handler. `Ok` is always `0`.
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// A `(name, version)` tag already exists bound to a different hash.
    TagConflict = 1,
    /// The referenced row doesn't exist.
    NotFound = 2,
    /// A program can't be unpublished while an agent still references it.
    InUse = 3,
    /// The referenced program isn't in the catalog.
    ProgramNotFound = 4,
    /// An agent with this `instance_name` is already installed.
    InstanceExists = 5,
    /// A byte field wasn't the expected fixed length.
    BadHash = 6,
    /// The caller's PeerId doesn't carry the auth role required for this
    /// handler. Distinct from `NotFound` so clients can surface
    /// "permission denied" specifically.
    Forbidden = 7,
    /// Hyperspace `register_remote`: the supplied `host_prefix` doesn't
    /// match any registered node prefix.
    BadPrefix = 8,
    /// Monotone-locality guard: `install` refused to (re)create an
    /// instance at a *wider* consistency tier than the narrowest one the
    /// same `instance_name` was ever installed at.
    ConsistencyWidenDenied = 9,
    /// Anti-replay guard: `install` refused because its `replication_id`
    /// was already consumed by a prior install.
    ReplicationIdReused = 10,
    /// Compare-and-swap guard: `upgrade` refused because the instance's
    /// live program hash no longer matches the `from_hash` the op was
    /// authored against.
    StaleUpgrade = 11,
}

impl Status {
    /// Decode a status byte (the over-the-wire discriminant) back into a
    /// `Status`. `None` for an unknown byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::TagConflict),
            2 => Some(Self::NotFound),
            3 => Some(Self::InUse),
            4 => Some(Self::ProgramNotFound),
            5 => Some(Self::InstanceExists),
            6 => Some(Self::BadHash),
            7 => Some(Self::Forbidden),
            8 => Some(Self::BadPrefix),
            9 => Some(Self::ConsistencyWidenDenied),
            10 => Some(Self::ReplicationIdReused),
            11 => Some(Self::StaleUpgrade),
            _ => None,
        }
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::TagConflict => "tag conflict",
            Status::NotFound => "not found",
            Status::InUse => "in use",
            Status::ProgramNotFound => "program not found",
            Status::InstanceExists => "instance exists",
            Status::BadHash => "bad hash",
            Status::Forbidden => "forbidden",
            Status::BadPrefix => "bad prefix",
            Status::ConsistencyWidenDenied => "consistency widen denied",
            Status::ReplicationIdReused => "replication id reused",
            Status::StaleUpgrade => "stale upgrade",
        })
    }
}

// ── Signing-byte builders (consensus-critical: byte-exact) ─────────

/// Domain tag for registry-op author signatures.
pub const REGISTRY_OP_DOMAIN: &[u8] = b"vos-registry-op/v1";

/// ed25519 signature length.
pub const OP_SIG_LEN: usize = 64;

/// Canonical byte string a mutation's author signs. Layout:
/// `domain || u16(op.len) || op || (u32(field.len) || field)*`.
/// The signer (CLI/daemon) and the verifier (actor) build these from the
/// same logical args, so the bytes match exactly without re-encoding the
/// wire `Msg`.
pub fn canonical_op_bytes(op: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(REGISTRY_OP_DOMAIN);
    out.extend_from_slice(&(op.len() as u16).to_le_bytes());
    out.extend_from_slice(op.as_bytes());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// Pack an authorization blob: `signer_peer_id || signature(64)`.
/// `signer_peer_id` is libp2p multihash bytes (same encoding as
/// [`AuthGrantRow::peer_id`]); the verifier splits at `len - 64`.
pub fn pack_auth(signer_peer_id: &[u8], sig: &[u8; OP_SIG_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(signer_peer_id.len() + OP_SIG_LEN);
    out.extend_from_slice(signer_peer_id);
    out.extend_from_slice(sig);
    out
}

/// Extract the raw 32-byte ed25519 public key embedded in a libp2p
/// PeerId. For ed25519, a PeerId is the identity-multihash of the
/// protobuf-encoded public key, a fixed 38-byte shape:
///
/// ```text
/// 00 24 08 01 12 20 <32-byte ed25519 key>
/// │  │  └──────────┴ protobuf PublicKey { KeyType::Ed25519=1, key[32] }
/// │  └ multihash length 0x24 = 36
/// └ multihash code 0x00 = identity
/// ```
///
/// Returns `None` for any other shape. Verifier-side `verify_op_sig`
/// (in the actor, where the ed25519 dep lives) consumes this.
pub fn ed25519_pubkey_from_peer_id(peer_id: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    if peer_id.len() != 38 || peer_id[..6] != PREFIX {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&peer_id[6..]);
    Some(key)
}

/// Domain tag for the MLS identity-binding signature (the messenger's
/// `vos-msg/identity-binding/v1`). Separate from [`REGISTRY_OP_DOMAIN`]
/// so a registry-op signature can never be replayed as a binding cert.
pub const BINDING_DOMAIN: &[u8] = b"vos-msg/identity-binding/v1";

/// Canonical bytes the operator's identity key signs to bind an MLS
/// signature key to a space PeerId: `domain || u16(mls_pubkey.len) ||
/// mls_pubkey || u16(peer_id.len) || peer_id || space_id`. Shared so the
/// messenger actor (which verifies the cert on every leaf) and the CLI
/// (which produces it) build identical bytes from one source.
pub fn binding_signed_bytes(mls_pubkey: &[u8], peer_id: &[u8], space_id: &[u8; 32]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(BINDING_DOMAIN.len() + 4 + mls_pubkey.len() + peer_id.len() + 32);
    out.extend_from_slice(BINDING_DOMAIN);
    out.extend_from_slice(&(mls_pubkey.len() as u16).to_le_bytes());
    out.extend_from_slice(mls_pubkey);
    out.extend_from_slice(&(peer_id.len() as u16).to_le_bytes());
    out.extend_from_slice(peer_id);
    out.extend_from_slice(space_id);
    out
}

// ── Sign-on-relay (host/daemon side) ──────────────────────────────
//
// Folded in from the former `registry_canon` module. The catalog
// mutators (`install`/`publish`/…) are author-signed and re-verified on
// every replica's replay. A keyless PVM agent (the messenger cloning a
// channel's actor pair) and the daemon's own manifest reconcile can't
// carry a CLI signature, so the daemon signs these ops as they reach the
// registry — at `handle_invoke_request`, the one funnel every invoke
// converges on — with the operator key it loaded at boot. It rebuilds
// the exact bytes the registry verifies via [`canonical_op_bytes`].

use alloc::sync::Arc;

use crate::actors::codec::Encode;
use crate::value::{Msg, TAG_DYNAMIC, Value};

/// Signs the canonical bytes of a registry op and returns the packed
/// `auth` blob (`signer_peer_id || sig(64)`), or `None` if signing
/// fails. Built by the daemon at boot from the operator's libp2p
/// identity and held by the space-registry agent thread.
pub(crate) type CatalogOpSigner = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// If `msg` is one of the signed catalog mutators, rebuild the exact
/// canonical bytes its author signs — the same fields, in the same order
/// and encoding the registry handler passes to [`canonical_op_bytes`].
/// `None` for any other method or if a required arg is missing or
/// ill-typed (fail closed). `register_remote` is deliberately absent — it
/// is the hyperspace surface with a separate trust model.
fn catalog_op_canonical(msg: &Msg) -> Option<Vec<u8>> {
    let a = &msg.args;
    let canon = match msg.name.as_str() {
        "publish" => {
            let name = a.get_str("name")?;
            let version = a.get_str("version")?;
            let hash = a.get_bytes("hash")?;
            canonical_op_bytes("publish", &[name.as_bytes(), version.as_bytes(), &hash])
        }
        "unpublish" => {
            let name = a.get_str("name")?;
            let version = a.get_str("version")?;
            canonical_op_bytes("unpublish", &[name.as_bytes(), version.as_bytes()])
        }
        "install" => {
            let instance_name = a.get_str("instance_name")?;
            let program_name = a.get_str("program_name")?;
            let program_version = a.get_str("program_version")?;
            let program_hash = a.get_bytes("program_hash")?;
            let replication_id = a.get_bytes("replication_id")?;
            let consistency = a.get_u8("consistency")?;
            let install_args = a.get_bytes("install_args")?;
            let install_payloads = a.get_bytes("install_payloads")?;
            // Absent field (e.g. an older client) defaults to false (confined),
            // matching the mutator's decode of a missing bool param.
            let network_reachable = a.get_bool("network_reachable").unwrap_or(false);
            canonical_op_bytes(
                "install",
                &[
                    instance_name.as_bytes(),
                    program_name.as_bytes(),
                    program_version.as_bytes(),
                    &program_hash,
                    &replication_id,
                    &[consistency],
                    &install_args,
                    &install_payloads,
                    &[network_reachable as u8],
                ],
            )
        }
        "uninstall" => {
            let instance_name = a.get_str("instance_name")?;
            canonical_op_bytes("uninstall", &[instance_name.as_bytes()])
        }
        "upgrade" => {
            let instance_name = a.get_str("instance_name")?;
            let new_program_name = a.get_str("new_program_name")?;
            let new_program_version = a.get_str("new_program_version")?;
            let new_program_hash = a.get_bytes("new_program_hash")?;
            let from_hash = a.get_bytes("from_hash")?;
            canonical_op_bytes(
                "upgrade",
                &[
                    instance_name.as_bytes(),
                    new_program_name.as_bytes(),
                    new_program_version.as_bytes(),
                    &new_program_hash,
                    &from_hash,
                ],
            )
        }
        "register_meta" => {
            let program_hash = a.get_bytes("program_hash")?;
            let blob = a.get_bytes("blob")?;
            canonical_op_bytes("register_meta", &[&program_hash, &blob])
        }
        "register_extension_meta" => {
            let instance_name = a.get_str("instance_name")?;
            let blob = a.get_bytes("blob")?;
            canonical_op_bytes("register_extension_meta", &[instance_name.as_bytes(), &blob])
        }
        _ => return None,
    };
    Some(canon)
}

/// Implements the sign-on-relay step: if `payload` (`[TAG_DYNAMIC][rkyv Msg]`)
/// targets a signed catalog mutator, rebuild its canonical bytes, sign
/// them with `signer`, and return a re-encoded payload carrying the
/// operator's `auth` blob (replacing any caller-supplied placeholder).
/// `None` leaves the original payload untouched.
pub(crate) fn sign_catalog_op_on_relay(
    payload: &[u8],
    signer: &CatalogOpSigner,
) -> Option<Vec<u8>> {
    if !payload.starts_with(&[TAG_DYNAMIC]) {
        return None;
    }
    let mut msg = <Msg as crate::Decode>::try_decode(&payload[1..])?;
    let canonical = catalog_op_canonical(&msg)?;
    let auth = signer(&canonical)?;
    // The registry reads the first `auth` arg; drop any caller-supplied
    // placeholder so the operator's signature is the one it sees.
    msg.args.0.retain(|(k, _)| k != "auth");
    msg.args.0.push((String::from("auth"), Value::Bytes(auth)));
    let encoded = msg.encode();
    let mut out = Vec::with_capacity(1 + encoded.len());
    out.push(TAG_DYNAMIC);
    out.extend_from_slice(&encoded);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the per-method field ordering `catalog_op_canonical` feeds
    /// into `canonical_op_bytes` — the consensus-critical layout the
    /// signer and the actor verifier must agree on. (This is the
    /// successor to the old `registry_canon` drift-pin: with one source
    /// of truth, it asserts the canonical builder itself, not a mirror.)
    #[test]
    fn catalog_op_canonical_matches_canonical_bytes_for_every_op() {
        let m = Msg::new("install")
            .with("instance_name", "msg-x-log")
            .with("program_name", "p")
            .with("program_version", "1")
            .with("program_hash", alloc::vec![7u8; 32])
            .with("replication_id", alloc::vec![9u8; 32])
            .with("consistency", 2u64)
            .with("install_args", alloc::vec![1u8, 2, 3])
            .with("install_payloads", Vec::<u8>::new())
            .with("network_reachable", true);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes(
                "install",
                &[
                    b"msg-x-log",
                    b"p",
                    b"1",
                    &[7u8; 32],
                    &[9u8; 32],
                    &[2u8],
                    &[1u8, 2, 3],
                    &[],
                    &[1u8],
                ],
            ),
        );

        let m = Msg::new("publish")
            .with("name", "p")
            .with("version", "1")
            .with("hash", alloc::vec![7u8; 32]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("publish", &[b"p", b"1", &[7u8; 32]]),
        );

        let m = Msg::new("unpublish").with("name", "p").with("version", "1");
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("unpublish", &[b"p", b"1"]),
        );

        let m = Msg::new("uninstall").with("instance_name", "msg-x-log");
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("uninstall", &[b"msg-x-log"]),
        );

        let m = Msg::new("register_meta")
            .with("program_hash", alloc::vec![7u8; 32])
            .with("blob", alloc::vec![1u8, 2, 3]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("register_meta", &[&[7u8; 32], &[1u8, 2, 3]]),
        );

        let m = Msg::new("register_extension_meta")
            .with("instance_name", "gateway")
            .with("blob", alloc::vec![9u8, 8]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("register_extension_meta", &[b"gateway", &[9u8, 8]]),
        );

        let m = Msg::new("upgrade")
            .with("instance_name", "msg-x-log")
            .with("new_program_name", "p")
            .with("new_program_version", "2")
            .with("new_program_hash", alloc::vec![5u8; 32])
            .with("from_hash", alloc::vec![7u8; 32]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("upgrade", &[b"msg-x-log", b"p", b"2", &[5u8; 32], &[7u8; 32]]),
        );
    }

    #[test]
    fn non_catalog_method_is_not_signed() {
        assert!(catalog_op_canonical(&Msg::new("agents")).is_none());
        let grant = Msg::new("grant_role")
            .with("peer_id", alloc::vec![1u8; 38])
            .with("role", 3u8);
        assert!(catalog_op_canonical(&grant).is_none());
        // register_remote is out of scope (hyperspace trust model).
        let rr = Msg::new("register_remote")
            .with("instance_name", "x")
            .with("host_prefix", 5u32);
        assert!(catalog_op_canonical(&rr).is_none());
    }

    #[test]
    fn sign_on_relay_injects_single_auth_over_the_canonical() {
        let captured: Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
        let seen = captured.clone();
        let signer: CatalogOpSigner = Arc::new(move |canon: &[u8]| {
            *seen.lock().unwrap() = canon.to_vec();
            Some(alloc::vec![0xABu8; 70])
        });

        // typed-wrapper style: carries an empty `auth` placeholder.
        let m = Msg::new("uninstall")
            .with("instance_name", "x")
            .with("auth", Vec::<u8>::new());
        let mut payload = alloc::vec![TAG_DYNAMIC];
        payload.extend_from_slice(&m.encode());

        let signed = sign_catalog_op_on_relay(&payload, &signer).expect("catalog op signed");
        assert_eq!(
            *captured.lock().unwrap(),
            canonical_op_bytes("uninstall", &[b"x"]),
        );
        let decoded = <Msg as crate::Decode>::try_decode(&signed[1..]).unwrap();
        let auths = decoded.args.0.iter().filter(|(k, _)| k == "auth").count();
        assert_eq!(auths, 1, "exactly one auth arg after signing");
        assert_eq!(decoded.args.get_bytes("auth").unwrap(), alloc::vec![0xABu8; 70]);
    }

    #[test]
    fn non_dynamic_payload_is_left_untouched() {
        let signer: CatalogOpSigner = Arc::new(|_| Some(alloc::vec![0u8; 70]));
        assert!(sign_catalog_op_on_relay(&[0x01, 0x02, 0x03], &signer).is_none());
    }

    #[test]
    fn ed25519_pubkey_extracts_from_valid_peer_id() {
        let mut pid = alloc::vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        pid.extend_from_slice(&[42u8; 32]);
        assert_eq!(ed25519_pubkey_from_peer_id(&pid), Some([42u8; 32]));
        assert!(ed25519_pubkey_from_peer_id(&[0u8; 10]).is_none());
    }
}
