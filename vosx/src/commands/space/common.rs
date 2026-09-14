//! Shared helpers for `vosx space *` commands.
//!
//! Mostly host-side concerns: CLI string parsing, tabular
//! formatting, and the blake2b derivations that vosx needs
//! before the daemon is even up. The cross-target
//! `instance_service_id` lives in `vos::registry` since the
//! actor's `resolve` handler also needs it.

use vos::abi::service::ServiceId;
use vos::node::Consistency;
use vos::registry::PublicationId;
use vos::service::InstallationId;

/// Resolve an optional space selector for commands that can safely infer a
/// single local space. This is shared by non-space namespaces such as `zk`
/// without reviving the retired dynamic command dispatcher.
pub(crate) fn resolve_space(arg: Option<&str>) -> anyhow::Result<String> {
    use anyhow::Context as _;

    if let Some(space) = arg {
        return Ok(space.to_string());
    }
    if let Ok(space) = std::env::var("VOSX_SPACE")
        && !space.is_empty()
    {
        return Ok(space);
    }
    let index = crate::spaces_index::load().context("loading spaces index")?;
    match index.spaces.as_slice() {
        [only] => Ok(only.name.clone()),
        [] => anyhow::bail!(
            "no spaces registered; create one with `vosx space new <name>` or pass `--space <name>`"
        ),
        many => anyhow::bail!(
            "multiple spaces registered: {}; pass `--space <name>` or set VOSX_SPACE",
            many.iter()
                .map(|space| space.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    }
}

fn mint_nonzero_registry_nonce(label: &str) -> anyhow::Result<[u8; 32]> {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| anyhow::anyhow!("mint {label}: {error}"))?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
}

/// Mint the unique generation carried by one successful catalog tag move.
pub fn mint_publication_id() -> anyhow::Result<PublicationId> {
    mint_nonzero_registry_nonce("catalog publication ID").map(PublicationId::new)
}

/// Mint the permanently burned identity of one installation attempt.
pub fn mint_installation_id() -> anyhow::Result<InstallationId> {
    mint_nonzero_registry_nonce("registry installation ID").map(InstallationId::new)
}

/// Validate a catalog name. Package hashes, not user-chosen tags, identify
/// immutable artifacts; a name is only the movable catalog pointer.
pub fn parse_program_name(s: &str) -> anyhow::Result<String> {
    parse_registry_slug("program name", s)
}

/// Validate an installed service/system-actor name at the CLI boundary.
pub fn parse_instance_name(s: &str) -> anyhow::Result<String> {
    parse_registry_slug("instance name", s)
}

/// Parse the clean-cutover replication identity accepted by service installs.
/// Zero formerly doubled as an "off" sentinel; it is no longer an identity.
pub fn parse_nonzero_replication_id(value: &str) -> anyhow::Result<[u8; 32]> {
    if value == "off" {
        anyhow::bail!(
            "replication_id = 'off' is not supported; use consistency = 'local' with a nonzero identity"
        );
    }
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .map_err(|_| anyhow::anyhow!("replication_id must be hex"))?;
    let id: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("replication_id must be 32 bytes"))?;
    if id == [0; 32] {
        anyhow::bail!("replication_id must be nonzero");
    }
    Ok(id)
}

fn parse_registry_slug(label: &str, s: &str) -> anyhow::Result<String> {
    if !vos::registry::is_canonical_registry_slug(s) {
        anyhow::bail!(
            "{label} must be a canonical registry slug: 1..=63 ASCII bytes, start and end with a lowercase letter or digit, and contain only lowercase letters, digits, or '-'"
        );
    }
    Ok(s.to_string())
}

/// Truncate `s` to at most `max` chars (byte-indexed — only
/// used on ASCII identifiers from the registry, where char and
/// byte boundaries coincide). Cheap helper for `{:<N}` table
/// columns where over-long values would push the layout.
pub fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}

/// Deterministic per-node `ServiceId` for an installed agent.
/// Thin wrapper around `vos::registry::instance_service_id` that
/// returns the typed `ServiceId` host code prefers; the formula
/// itself lives in `vos::registry` (the actor's `resolve` handler
/// calls the same fn) so both sides agree by construction.
pub fn instance_service_id(instance_name: &str, prefix: u16) -> ServiceId {
    ServiceId(vos::registry::instance_service_id(instance_name, prefix))
}

/// Stable logical service identity for one installed service root-tree incarnation.
///
/// The daemon route remains node-local. The
/// guest-owned identity is scoped to the space and registry installation, so
/// it survives process restarts but a tombstoned name reinstalled with the
/// required fresh replication id cannot inherit the deleted actor's state or
/// deduplication history.
pub fn service_root_service_id(
    space: vos::service::SpaceId,
    instance: &str,
    replication_id: [u8; 32],
) -> vos::service::RootServiceId {
    vos::service::RootServiceId(
        vos::service::Hash::digest(
            b"vos/installed-root-service/service",
            &[&space.0, instance.as_bytes(), &replication_id],
        )
        .0,
    )
}

/// Stable application identity of the root actor owned by an installed service
/// service. Deployment and program identities may change through an upgrade;
/// the actor identity does not.
pub fn service_root_actor_id(
    service: vos::service::RootServiceId,
    instance: &str,
) -> vos::service::ActorId {
    vos::service::ActorId(
        vos::service::Hash::digest(
            b"vos/installed-root-actor/service",
            &[&service.0, instance.as_bytes()],
        )
        .0,
    )
}

/// Map a registry-stored `consistency` u8 to the host enum.
/// `space_registry` defines the numeric assignments (Ephemeral
/// = 0, Local = 1, Crdt = 2, Raft = 3); `vos::node::Consistency`
/// is the host-side enum the runtime spawns agents with. Returns
/// `None` for any unrecognised value so callers can decide
/// whether to skip-and-warn or hard-fail.
pub fn consistency_from_u8(c: u8) -> Option<Consistency> {
    match c {
        0 => Some(Consistency::Ephemeral),
        1 => Some(Consistency::Local),
        2 => Some(Consistency::Crdt),
        3 => Some(Consistency::Raft),
        _ => None,
    }
}

/// Per-space registry replication-id: blake2b("vos-space-registry"
/// || space_id). Deterministic from `space_id` so any two replicas
/// of the same space subscribe to the same gossipsub topic.
pub fn registry_replication_id(space_id: &[u8; 32]) -> [u8; 32] {
    vos::crypto::blake2b_hash(b"vos-space-registry", &[&[0u8], space_id])
}

/// Per-hyperspace registry replication-id: blake2b("vos-hyperspace"
/// || hyperspace_name). All member spaces of the same hyperspace
/// derive the same id from the shared name and so subscribe to the
/// same gossipsub topic for the hyperspace registry. Distinct from
/// `registry_replication_id` (which is per-space) so a node hosting
/// both replicas keeps them in separate replication groups.
///
/// Wired into the boot path when a recipe sets `hyperspace`:
/// `space up` spawns a registry replica into the hyperspace's
/// replication group.
#[allow(dead_code)]
pub fn derive_hyperspace_id(hyperspace_name: &str) -> [u8; 32] {
    vos::crypto::blake2b_hash(b"vos-hyperspace", &[&[0u8], hyperspace_name.as_bytes()])
}

/// Compute a space's id from the registry's genesis DAG root.
/// Stable for the lifetime of the space and verifiable by any
/// joiner that fetches the genesis snapshot. Host-only
/// (called before any daemon is up).
pub fn derive_space_id(genesis_dag_root: &[u8; 32]) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        vos::registry::SPACE_ID_DOMAIN_TAG,
        &[&[0u8], genesis_dag_root],
    )
}

/// Select the actual signing-root anchor, never the empty initialization
/// event. Validate the stored CID as well as the complete replay framing.
pub(super) fn registry_genesis_cid(key: &[u8], node: &[u8]) -> Option<[u8; 32]> {
    let cid: [u8; 32] = key.try_into().ok()?;
    if vos::crypto::blake2b_hash::<32>(b"", &[node]) != cid {
        return None;
    }
    let request = vos::node::registry_replay_node_request(node).ok()??;
    if request.name != "set_root" || !genesis_node_validator(derive_space_id(&cid))(&cid, node) {
        return None;
    }
    Some(cid)
}

/// A [`NodeValidator`](vos::commit::NodeValidator) that binds the
/// registry's replay boundary and two genesis anchors to `space_id`: it
/// rejects malformed/non-canonical DAG and dynamic-message wires, unknown or
/// misshapen registry methods, impossible reply transcripts, any peer-merged
/// `set_root` DAG node whose CID doesn't derive `space_id`, and any
/// `set_space_id` node carrying a value other than `space_id`.
///
/// `insert_node` checks the generic current node wire and
/// `CID == hash(bytes)`, but neither check authenticates registry semantics;
/// replay orders concurrent origin nodes by ascending CID — so without this gate a
/// space member could author a second `set_root{attacker}`, grind its
/// `origin` until the node's CID sorts below the genuine genesis, serve
/// it as a head, and on the next sync→replay see the forged root applied
/// first (`set_root` is first-write-wins) → registry authority takeover.
/// Grinding a CID to sort low is cheap; grinding one to derive a
/// *specific* `space_id` is a second-preimage attack on blake2b, so the
/// genuine genesis (whose CID derives `space_id` by construction) is the
/// only `set_root` this accepts.
///
/// `set_space_id` has the identical exposure — unsigned, first-write-wins,
/// re-derived from the DAG on every `soft_restart_crdt` replay — and
/// `redeem_invite` binds the anchored value, so a forged concurrent
/// `set_space_id` that sorts first would permanently poison the anchor
/// (invite-redemption DoS, or a cross-space redeem when the forged value
/// is a sibling space's id). The value is public and known here, so the
/// gate is exact: only this space's own id may anchor, and a wrong-valued
/// node never enters the DAG regardless of replay ordering.
pub fn genesis_node_validator(space_id: [u8; 32]) -> vos::commit::NodeValidator {
    std::sync::Arc::new(move |cid: &[u8; 32], node_bytes: &[u8]| -> bool {
        // The typed decoder validates the complete DagNode, including hostile
        // length fields and child framing. The inner predicate is also used by
        // cold and mid-flight registry replay, so ingress cannot admit a log
        // that replay will later fail-stop on.
        let Ok(decoded) = vos::node::registry_replay_node_request(node_bytes) else {
            return false;
        };
        let Some(decoded) = decoded else {
            // The host's empty on-start kick is the sole non-dynamic log.
            return true;
        };
        // `set_space_id` anchors the value `redeem_invite` binds: accept
        // only this space's own id, so no forged value can enter the DAG.
        if decoded.name == "set_space_id" {
            return decoded.args.get_bytes("space_id").as_deref() == Some(space_id.as_slice());
        }
        // `set_root` is both replay-schema-checked and genesis-bound by CID;
        // every other current, exactly shaped registry op flows through.
        if decoded.name != "set_root" {
            return true;
        }
        decoded.args.get_u32("schema_version") == Some(vos::registry::REGISTRY_SCHEMA_VERSION)
            && decoded.args.get_bytes("schema_hash").as_deref()
                == Some(vos::registry::REGISTRY_SCHEMA_HASH.as_slice())
            && decoded
                .args
                .get_bytes("root")
                .is_some_and(|root| !root.is_empty())
            && derive_space_id(cid) == space_id
    })
}

/// Auto-derive a `replication_id` for an installed agent.
/// `blake2b("vos-replication-id" || space_id || 0 || instance_name || 0
/// || program_hash)`. Two replicas that install the same program under the
/// same `instance_name` IN THE SAME SPACE auto-discover each other on the
/// gossipsub topic this id maps to. Scoping by `space_id` is load-bearing:
/// without it, two DIFFERENT spaces that name an agent identically with the
/// same ELF (bank-a and bank-b both running `clerk-ledger`) would collide
/// into ONE replication group and silently merge their Raft ledgers.
/// Deterministic in its inputs. Host-only — set at install time from vosx
/// and stored on the registry's `AgentRow`.
pub fn auto_replication_id(
    space_id: &[u8; 32],
    instance_name: &str,
    program_hash: &[u8; 32],
) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        b"vos-replication-id",
        &[
            space_id,
            &[0u8],
            instance_name.as_bytes(),
            &[0u8],
            program_hash,
        ],
    )
}

/// Render a registry-stored consistency u8 as the canonical
/// CLI string. Inverse of `parse_consistency`.
pub fn consistency_name(c: u8) -> &'static str {
    match c {
        0 => "ephemeral",
        1 => "local",
        2 => "crdt",
        3 => "raft",
        _ => "unknown",
    }
}

/// Parse a CLI consistency string to the registry-stored u8.
/// Inverse of `consistency_name`. Returns `None` for unknown
/// inputs so callers can surface a usage error.
pub fn parse_consistency(name: &str) -> Option<u8> {
    match name {
        "ephemeral" => Some(0),
        "local" => Some(1),
        "crdt" => Some(2),
        "raft" => Some(3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_log(message: vos::value::Msg) -> vos::effect_log::EffectLog {
        use vos::Encode as _;

        let mut payload = vec![vos::value::TAG_DYNAMIC];
        payload.extend_from_slice(&message.encode());
        vos::effect_log::EffectLog::for_msg(payload)
    }

    fn registry_node(
        log: vos::effect_log::EffectLog,
        seq: u64,
        children: &[[u8; 32]],
    ) -> ([u8; 32], Vec<u8>) {
        let event = vos::effect_log::CrdtEvent::new([0x71; 32], seq, log);
        let payload = event.to_bytes();
        let mut node = (payload.len() as u64).to_le_bytes().to_vec();
        node.extend_from_slice(&payload);
        node.extend_from_slice(&(children.len() as u64).to_le_bytes());
        for child in children {
            node.extend_from_slice(child);
        }
        let hash = blake2b_simd::Params::new().hash_length(32).hash(&node);
        let cid = hash
            .as_bytes()
            .try_into()
            .expect("blake2b was configured for a 32-byte CID");
        (cid, node)
    }

    struct RemoveTempDir(std::path::PathBuf);

    impl Drop for RemoveTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_registry_db(label: &str) -> (std::path::PathBuf, RemoveTempDir) {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vosx-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&dir).unwrap();
        (dir.join("registry.redb"), RemoveTempDir(dir))
    }

    #[test]
    fn cli_registry_names_use_the_canonical_shared_slug_predicate() {
        for valid in ["a", "0", "counter", "counter-v2", &"a".repeat(63)] {
            assert_eq!(parse_program_name(valid).unwrap(), valid);
            assert_eq!(parse_instance_name(valid).unwrap(), valid);
            assert!(vos::registry::is_canonical_registry_slug(valid));
        }
        for invalid in [
            "",
            "Counter",
            "counter_name",
            "counter/name",
            "counter:tag",
            "counter@hash",
            "-counter",
            "counter-",
            "é",
            &"a".repeat(64),
        ] {
            assert!(parse_program_name(invalid).is_err(), "accepted {invalid:?}");
            assert!(
                parse_instance_name(invalid).is_err(),
                "accepted {invalid:?}"
            );
            assert!(!vos::registry::is_canonical_registry_slug(invalid));
        }
    }

    #[test]
    fn explicit_replication_identity_rejects_legacy_off_and_zero() {
        assert!(parse_nonzero_replication_id("off").is_err());
        assert!(parse_nonzero_replication_id(&"00".repeat(32)).is_err());
        assert_eq!(
            parse_nonzero_replication_id(&format!("0x{}", "11".repeat(32))).unwrap(),
            [0x11; 32],
        );
    }

    #[test]
    fn truncate_passes_short_strings_through() {
        assert_eq!(truncate("hi", 10), "hi");
    }

    #[test]
    fn truncate_clips_at_max() {
        assert_eq!(truncate("0123456789abc", 5), "01234");
    }

    #[test]
    fn instance_service_id_is_deterministic() {
        let a = instance_service_id("counter", 0xC0DE);
        let b = instance_service_id("counter", 0xC0DE);
        assert_eq!(a, b);
        // Prefix is honored.
        assert_eq!(a.0 >> 16, 0xC0DE);
    }

    #[test]
    fn instance_service_id_avoids_reserved_low_ids() {
        // No matter the name, the local half should be ≥ 0x100
        // and < 0x8000.
        for name in ["", "a", "counter", "very-long-instance-name"] {
            let id = instance_service_id(name, 0);
            let local = (id.0 & 0xFFFF) as u16;
            assert!((0x100..0x8000).contains(&local), "got 0x{local:04x}");
        }
    }

    #[test]
    fn service_root_tree_identity_is_stable_and_installation_scoped() {
        let first = service_root_service_id(vos::service::SpaceId([1; 32]), "counter", [3; 32]);
        let same = service_root_service_id(vos::service::SpaceId([1; 32]), "counter", [3; 32]);
        let other_space =
            service_root_service_id(vos::service::SpaceId([2; 32]), "counter", [3; 32]);
        let other_name = service_root_service_id(vos::service::SpaceId([1; 32]), "ledger", [3; 32]);
        let reinstalled =
            service_root_service_id(vos::service::SpaceId([1; 32]), "counter", [4; 32]);

        assert_eq!(first, same);
        assert_ne!(first, other_space);
        assert_ne!(first, other_name);
        assert_ne!(first, reinstalled);
        assert_ne!(first, vos::service::RootServiceId::ZERO);
    }

    #[test]
    fn service_root_actor_identity_is_stable_across_deployments() {
        let service = service_root_service_id(vos::service::SpaceId([3; 32]), "counter", [5; 32]);
        let actor = service_root_actor_id(service, "counter");

        assert_eq!(actor, service_root_actor_id(service, "counter"));
        assert_ne!(actor, service_root_actor_id(service, "counter-child"));
        assert_ne!(actor, vos::service::ActorId::ZERO);
    }

    #[test]
    fn genesis_selection_binds_root_not_empty_initialization() {
        let (empty_cid, empty) = registry_node(vos::effect_log::EffectLog::for_msg(vec![]), 0, &[]);
        let root_message = |root: u8| {
            vos::value::Msg::new("set_root")
                .with("root", vec![root; 38])
                .with("schema_version", vos::registry::REGISTRY_SCHEMA_VERSION)
                .with("schema_hash", vos::registry::REGISTRY_SCHEMA_HASH.to_vec())
        };
        let (root_cid, root) = registry_node(registry_log(root_message(0xaa)), 1, &[empty_cid]);
        let (other_cid, other) = registry_node(registry_log(root_message(0xbb)), 1, &[empty_cid]);
        assert_eq!(registry_genesis_cid(&empty_cid, &empty), None);
        assert_eq!(registry_genesis_cid(&root_cid, &root), Some(root_cid));
        assert_eq!(registry_genesis_cid(&other_cid, &other), Some(other_cid));
        assert_ne!(derive_space_id(&root_cid), derive_space_id(&other_cid));
        assert_eq!(registry_genesis_cid(&empty_cid, &root), None);
        assert_eq!(registry_genesis_cid(&root_cid[..31], &root), None);
        let mut malformed = root.clone();
        malformed.push(0);
        let malformed_cid = vos::crypto::blake2b_hash::<32>(b"", &[&malformed]);
        assert_eq!(registry_genesis_cid(&malformed_cid, &malformed), None);
        let (bad_cid, bad) = registry_node(
            registry_log(
                vos::value::Msg::new("set_root")
                    .with("root", vec![0xaau8; 38])
                    .with("schema_version", vos::registry::REGISTRY_SCHEMA_VERSION + 1)
                    .with("schema_hash", vos::registry::REGISTRY_SCHEMA_HASH.to_vec()),
            ),
            1,
            &[empty_cid],
        );
        assert_eq!(registry_genesis_cid(&bad_cid, &bad), None);

        let (path, _remove) = temp_registry_db("root-anchor");
        let write = |records: &[([u8; 32], Vec<u8>)]| {
            let db = redb::Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn
                    .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("dag"))
                    .unwrap();
                for (cid, bytes) in records {
                    table.insert(cid.as_slice(), bytes.as_slice()).unwrap();
                }
            }
            txn.commit().unwrap();
        };
        write(&[(empty_cid, empty), (root_cid, root)]);
        assert_eq!(
            super::super::new::read_genesis_root(&path).unwrap(),
            root_cid
        );
        let verify = |id| {
            super::super::verify::verify_with_timeout(&path, &id, std::time::Duration::ZERO)
                .unwrap()
        };
        assert!(
            matches!(verify(derive_space_id(&root_cid)), super::super::verify::VerifyOutcome::Verified { genesis_cid } if genesis_cid == root_cid)
        );
        assert!(matches!(
            verify(derive_space_id(&empty_cid)),
            super::super::verify::VerifyOutcome::Mismatch { .. }
        ));
        write(&[(other_cid, other)]);
        assert!(
            super::super::new::read_genesis_root(&path).is_err(),
            "creation must reject ambiguous roots"
        );
        assert!(
            matches!(verify(derive_space_id(&root_cid)), super::super::verify::VerifyOutcome::Verified { genesis_cid } if genesis_cid == root_cid)
        );
        assert!(
            matches!(verify(derive_space_id(&other_cid)), super::super::verify::VerifyOutcome::Verified { genesis_cid } if genesis_cid == other_cid)
        );
    }

    #[test]
    fn genesis_validator_binds_set_root_to_space_id() {
        // A DagNode wire ([payload_len:u64][CrdtEvent][n_children:u64])
        // wrapping one canonical registry request.
        fn node_for(message: vos::value::Msg) -> Vec<u8> {
            registry_node(registry_log(message), 0, &[]).1
        }

        let genuine_cid = [7u8; 32];
        let space_id = derive_space_id(&genuine_cid);
        let v = genesis_node_validator(space_id);

        let set_root = node_for(
            vos::value::Msg::new("set_root")
                .with("root", vec![0xAAu8; 38])
                .with("schema_version", vos::registry::REGISTRY_SCHEMA_VERSION)
                .with("schema_hash", vos::registry::REGISTRY_SCHEMA_HASH.to_vec()),
        );
        // The genuine genesis: its CID derives the advertised space_id.
        assert!(v(&genuine_cid, &set_root), "genuine genesis accepted");
        // A forged set_root: any other CID derives a different space_id.
        assert!(
            !v(&[9u8; 32], &set_root),
            "forged set_root (wrong derived space_id) rejected",
        );
        // Non-genesis ops flow through regardless of CID.
        assert!(
            v(&[9u8; 32], &node_for(vos::value::Msg::new("protocol"))),
            "non-set_root op is not genesis-gated",
        );
        assert!(
            !v(
                &genuine_cid,
                &node_for(
                    vos::value::Msg::new("set_root")
                        .with("root", vec![0xAAu8; 38])
                        .with("schema_version", vos::registry::REGISTRY_SCHEMA_VERSION - 1)
                        .with("schema_hash", vos::registry::REGISTRY_SCHEMA_HASH.to_vec(),),
                ),
            ),
            "schema-incompatible genesis is rejected before replay",
        );
    }

    #[test]
    fn genesis_validator_binds_set_space_id_to_the_known_value() {
        fn set_space_id_node(value: &[u8]) -> Vec<u8> {
            registry_node(
                registry_log(vos::value::Msg::new("set_space_id").with("space_id", value.to_vec())),
                0,
                &[],
            )
            .1
        }

        let space_id = [0x5au8; 32];
        let v = genesis_node_validator(space_id);
        // The genuine anchor (this space's id) is accepted — CID irrelevant.
        assert!(
            v(&[1u8; 32], &set_space_id_node(&space_id)),
            "genuine space_id accepted"
        );
        // A forged set_space_id carrying a sibling space's id (or a bogus
        // one) is rejected at ingest — so a member can't grind a concurrent
        // node that sorts first on replay and poisons the anchor.
        assert!(
            !v(&[0u8; 32], &set_space_id_node(&[0x11u8; 32])),
            "forged set_space_id(sibling id) rejected regardless of CID",
        );
        assert!(
            !v(&[0u8; 32], &set_space_id_node(&[0xFFu8; 32])),
            "forged set_space_id(bogus id) rejected — closes the invite-DoS vector",
        );
    }

    #[test]
    fn registry_replay_allowlist_matches_the_actor_entrypoints() {
        let actor_methods = space_registry::SpaceRegistryMsg::META.messages;
        assert_eq!(
            vos::node::REGISTRY_REPLAY_METHODS.len(),
            actor_methods.len(),
            "registry replay allowlist and actor entrypoint count drifted",
        );
        for (allowed, actor) in vos::node::REGISTRY_REPLAY_METHODS.iter().zip(actor_methods) {
            assert_eq!(allowed.name, actor.name);
            assert_eq!(allowed.fields.len(), actor.fields.len(), "{}", actor.name);
            for ((allowed_name, allowed_kind), actor_field) in
                allowed.fields.iter().zip(actor.fields)
            {
                assert_eq!(*allowed_name, actor_field.name, "{}", actor.name);
                assert_eq!(
                    allowed_kind.metadata_type(),
                    actor_field.ty,
                    "{}.{allowed_name}",
                    actor.name,
                );
            }
        }
    }

    #[test]
    fn genesis_validator_fails_closed_on_hostile_and_noncanonical_node_wires() {
        let validator = genesis_node_validator([0x61; 32]);

        let huge_length = u64::MAX.to_le_bytes();
        assert!(
            !validator(&[0; 32], &huge_length),
            "u64::MAX payload length must return false without offset overflow",
        );

        let (_, mut trailing) =
            registry_node(registry_log(vos::value::Msg::new("protocol")), 0, &[]);
        trailing.push(0);
        assert!(!validator(&[0; 32], &trailing));

        let (_, mut zero_invocation) =
            registry_node(registry_log(vos::value::Msg::new("protocol")), 1, &[]);
        let payload_len =
            usize::try_from(u64::from_le_bytes(zero_invocation[..8].try_into().unwrap())).unwrap();
        zero_invocation[8 + payload_len - 32..8 + payload_len].fill(0);
        assert!(
            !validator(&[0; 32], &zero_invocation),
            "a zero invocation id that typed decode would normalize is non-canonical",
        );
    }

    #[test]
    fn rejected_registry_nodes_never_advance_or_persist_roots() {
        use vos::commit::CommitStrategy as _;

        let (path, _remove) = temp_registry_db("registry-admission");
        let space_id = [0x62; 32];
        let validator = genesis_node_validator(space_id);
        let mut commit = vos::commit::CrdtCommit::open(&path, [0x70; 32]).unwrap();
        commit.set_node_validator(Some(validator));

        let (good_cid, good_node) = registry_node(
            registry_log(vos::value::Msg::new("set_space_id").with("space_id", space_id.to_vec())),
            0,
            &[],
        );
        assert!(commit.insert_node(&good_cid, &good_node).unwrap());
        commit.compact_roots().unwrap();
        assert_eq!(commit.root_bytes(), vec![good_cid]);

        let mut forged_reply = registry_log(vos::value::Msg::new("protocol"));
        forged_reply.record_reply(vec![0x99]);
        let bad_logs = vec![
            vos::effect_log::EffectLog::for_msg(vec![vos::value::TAG_DYNAMIC, 0xff, 0x00, 0x01]),
            vos::effect_log::EffectLog::for_msg(b"nondynamic result".to_vec()),
            registry_log(vos::value::Msg::new("unknown_registry_method")),
            registry_log(vos::value::Msg::new("set_space_id")),
            forged_reply,
        ];

        let mut rejected_cids = Vec::new();
        for (index, log) in bad_logs.into_iter().enumerate() {
            let (cid, node) = registry_node(log, index as u64 + 1, &[good_cid]);
            assert!(
                !commit.insert_node(&cid, &node).unwrap(),
                "bad node #{index} was admitted",
            );
            assert!(commit.get_node_bytes(&cid).unwrap().is_none());
            assert_eq!(
                commit.root_bytes(),
                vec![good_cid],
                "rejected node #{index} advanced the in-memory root",
            );
            rejected_cids.push(cid);
        }
        commit.compact_roots().unwrap();
        assert_eq!(commit.root_bytes(), vec![good_cid]);
        drop(commit);

        let reopened = vos::commit::CrdtCommit::open(&path, [0x70; 32]).unwrap();
        assert_eq!(
            reopened.root_bytes(),
            vec![good_cid],
            "rejected heads must not become durable roots",
        );
        for cid in rejected_cids {
            assert!(reopened.get_node_bytes(&cid).unwrap().is_none());
        }
        let logs = reopened
            .replay_logs()
            .expect("reopen must retain a healthy replay history");
        assert_eq!(logs.len(), 1);
        assert!(matches!(
            vos::node::registry_replay_request(&logs[0]),
            Ok(Some(message)) if message.name == "set_space_id"
        ));
    }

    #[test]
    fn consistency_from_u8_round_trips_known_codes() {
        assert!(matches!(
            consistency_from_u8(0),
            Some(Consistency::Ephemeral)
        ));
        assert!(matches!(consistency_from_u8(1), Some(Consistency::Local)));
        assert!(matches!(consistency_from_u8(2), Some(Consistency::Crdt)));
        assert!(matches!(consistency_from_u8(3), Some(Consistency::Raft)));
        assert!(consistency_from_u8(4).is_none());
        assert!(consistency_from_u8(255).is_none());
    }

    #[test]
    fn registry_replication_id_is_deterministic_per_space() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        assert_eq!(registry_replication_id(&s1), registry_replication_id(&s1));
        assert_ne!(registry_replication_id(&s1), registry_replication_id(&s2));
    }

    #[test]
    fn hyperspace_id_is_deterministic_per_name() {
        let a = derive_hyperspace_id("bank-federation");
        let b = derive_hyperspace_id("bank-federation");
        let c = derive_hyperspace_id("kunekt-test");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn hyperspace_id_distinct_from_space_registry_id() {
        // A space whose space_id, by improbable coincidence, contains
        // the hyperspace name's bytes must NOT collide with the
        // hyperspace registry's id. The two derivations use distinct
        // domain tags, so this holds by construction; the test just
        // pins the property.
        let space_id = [0u8; 32];
        let hs = derive_hyperspace_id("bank-federation");
        let reg = registry_replication_id(&space_id);
        assert_ne!(hs, reg);
    }

    #[test]
    fn space_id_is_domain_tagged() {
        let root = [0xABu8; 32];
        let id = derive_space_id(&root);
        assert_eq!(id, derive_space_id(&root));
        let mut other = root;
        other[0] = 0xAC;
        assert_ne!(id, derive_space_id(&other));
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn replication_id_includes_instance_name() {
        let space = [0x11u8; 32];
        let h = [0xCDu8; 32];
        let a = auto_replication_id(&space, "alpha", &h);
        let b = auto_replication_id(&space, "beta", &h);
        assert_ne!(a, b);
    }

    #[test]
    fn replication_id_is_space_scoped() {
        // Two DIFFERENT spaces installing the same (instance_name, blob) must
        // get DISTINCT replication ids — otherwise bank-a's and bank-b's
        // identically-named `clerk-ledger` would merge into one Raft group.
        let h = [0xCDu8; 32];
        let space_a = [0x01u8; 32];
        let space_b = [0x02u8; 32];
        assert_ne!(
            auto_replication_id(&space_a, "clerk-ledger", &h),
            auto_replication_id(&space_b, "clerk-ledger", &h),
            "same (name, blob) in different spaces must not collide",
        );
        // Deterministic: the SAME (space, name, blob) is stable across calls.
        assert_eq!(
            auto_replication_id(&space_a, "clerk-ledger", &h),
            auto_replication_id(&space_a, "clerk-ledger", &h),
            "same space + name + blob must be stable",
        );
    }

    #[test]
    fn consistency_roundtrip() {
        for d in 0u8..=3 {
            let name = consistency_name(d);
            assert_eq!(parse_consistency(name), Some(d));
        }
        assert_eq!(consistency_name(99), "unknown");
        assert_eq!(parse_consistency("nonsense"), None);
    }
}
