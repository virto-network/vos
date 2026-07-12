//! Shared helpers for `vosx space *` commands.
//!
//! Mostly host-side concerns: CLI string parsing, tabular
//! formatting, and the blake2b derivations that vosx needs
//! before the daemon is even up. The cross-target
//! `instance_service_id` lives in `vos::registry` since the
//! actor's `resolve` handler also needs it.

use vos::abi::service::ServiceId;
use vos::node::Consistency;

/// Parse `name` or `name:version`. Bare `name` ⇒ `name:latest`.
/// Empty halves (`":1.0"`, `"foo:"`) are rejected.
pub fn parse_program_ref(s: &str) -> anyhow::Result<(String, String)> {
    if let Some((n, v)) = s.split_once(':') {
        if n.is_empty() || v.is_empty() {
            anyhow::bail!("program ref '{s}' must be 'name' or 'name:version'");
        }
        Ok((n.to_string(), v.to_string()))
    } else {
        Ok((s.to_string(), "latest".to_string()))
    }
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

/// Per-space registry replication-id: blake2b("vos-space-registry/v1"
/// || space_id). Deterministic from `space_id` so any two replicas
/// of the same space subscribe to the same gossipsub topic.
pub fn registry_replication_id(space_id: &[u8; 32]) -> [u8; 32] {
    vos::crypto::blake2b_hash(b"vos-space-registry/v1", &[&[0u8], space_id])
}

/// Per-hyperspace registry replication-id: blake2b("vos-hyperspace/v1"
/// || hyperspace_name). All member spaces of the same hyperspace
/// derive the same id from the shared name and so subscribe to the
/// same gossipsub topic for the hyperspace registry. Distinct from
/// `registry_replication_id` (which is per-space) so a node hosting
/// both replicas keeps them in separate replication groups.
///
/// Wired into the boot path in Phase 1.3 (`space up` spawns the
/// hyperspace registry replica when a manifest sets the field).
#[allow(dead_code)]
pub fn derive_hyperspace_id(hyperspace_name: &str) -> [u8; 32] {
    vos::crypto::blake2b_hash(b"vos-hyperspace/v1", &[&[0u8], hyperspace_name.as_bytes()])
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

/// A [`NodeValidator`](vos::commit::NodeValidator) that binds the
/// registry's two genesis anchors to `space_id`: it rejects any
/// peer-merged `set_root` DAG node whose CID doesn't derive `space_id`,
/// rejects any `set_space_id` node carrying a value other than
/// `space_id`, and passes every other node through.
///
/// `insert_node` only checks `CID == hash(bytes)`, and replay orders
/// concurrent origin nodes by ascending CID — so without this gate a
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
        // DagNode wire: [payload_len:u64 LE][payload(CrdtEvent)][children…].
        if node_bytes.len() < 8 {
            return true;
        }
        let payload_len = u64::from_le_bytes(node_bytes[..8].try_into().unwrap()) as usize;
        let Some(payload) = node_bytes.get(8..8 + payload_len) else {
            return true;
        };
        let Some(event) = vos::effect_log::CrdtEvent::from_bytes(payload) else {
            return true;
        };
        let msg = &event.log.msg; // [TAG_DYNAMIC][rkyv Msg]
        if msg.first() != Some(&vos::value::TAG_DYNAMIC) {
            return true;
        }
        let Some(decoded) = <vos::value::Msg as vos::Decode>::try_decode(&msg[1..]) else {
            return true;
        };
        // `set_space_id` anchors the value `redeem_invite` binds: accept
        // only this space's own id, so no forged value can enter the DAG.
        if decoded.name == "set_space_id" {
            return decoded.args.get_bytes("space_id").as_deref() == Some(space_id.as_slice());
        }
        // `set_root` is genesis-bound by CID; every other op flows through.
        if decoded.name != "set_root" {
            return true;
        }
        derive_space_id(cid) == space_id
    })
}

/// Auto-derive a `replication_id` for an installed agent.
/// `blake2b("vos-replication-id/v1" || space_id || 0 || instance_name || 0
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
        b"vos-replication-id/v1",
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

    #[test]
    fn parses_versioned_ref() {
        assert_eq!(
            parse_program_ref("counter:1.0").unwrap(),
            ("counter".into(), "1.0".into()),
        );
    }

    #[test]
    fn parses_bare_name_to_latest() {
        assert_eq!(
            parse_program_ref("counter").unwrap(),
            ("counter".into(), "latest".into()),
        );
    }

    #[test]
    fn rejects_empty_halves() {
        assert!(parse_program_ref(":1.0").is_err());
        assert!(parse_program_ref("counter:").is_err());
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
            assert!(local >= 0x100 && local < 0x8000, "got 0x{local:04x}");
        }
    }

    #[test]
    fn genesis_validator_binds_set_root_to_space_id() {
        use vos::Encode;
        // A DagNode wire ([payload_len:u64][CrdtEvent][n_children:u64])
        // wrapping a registry op named `name`.
        fn node_for(name: &str) -> Vec<u8> {
            let m = vos::value::Msg::new(name).with("root", vec![0xAAu8; 38]);
            let mut msg = vec![vos::value::TAG_DYNAMIC];
            msg.extend_from_slice(&m.encode());
            let event =
                vos::effect_log::CrdtEvent::new([0u8; 32], 0, vos::effect_log::EffectLog::for_msg(msg));
            let payload = event.to_bytes();
            let mut node = (payload.len() as u64).to_le_bytes().to_vec();
            node.extend_from_slice(&payload);
            node.extend_from_slice(&0u64.to_le_bytes()); // no children
            node
        }

        let genuine_cid = [7u8; 32];
        let space_id = derive_space_id(&genuine_cid);
        let v = genesis_node_validator(space_id);

        let set_root = node_for("set_root");
        // The genuine genesis: its CID derives the advertised space_id.
        assert!(v(&genuine_cid, &set_root), "genuine genesis accepted");
        // A forged set_root: any other CID derives a different space_id.
        assert!(
            !v(&[9u8; 32], &set_root),
            "forged set_root (wrong derived space_id) rejected",
        );
        // Non-genesis ops flow through regardless of CID.
        assert!(
            v(&[9u8; 32], &node_for("grant_role")),
            "non-set_root op is not genesis-gated",
        );
    }

    #[test]
    fn genesis_validator_binds_set_space_id_to_the_known_value() {
        use vos::Encode;
        fn set_space_id_node(value: &[u8]) -> Vec<u8> {
            let m = vos::value::Msg::new("set_space_id").with("space_id", value.to_vec());
            let mut msg = vec![vos::value::TAG_DYNAMIC];
            msg.extend_from_slice(&m.encode());
            let event =
                vos::effect_log::CrdtEvent::new([0u8; 32], 0, vos::effect_log::EffectLog::for_msg(msg));
            let payload = event.to_bytes();
            let mut node = (payload.len() as u64).to_le_bytes().to_vec();
            node.extend_from_slice(&payload);
            node.extend_from_slice(&0u64.to_le_bytes());
            node
        }

        let space_id = [0x5au8; 32];
        let v = genesis_node_validator(space_id);
        // The genuine anchor (this space's id) is accepted — CID irrelevant.
        assert!(v(&[1u8; 32], &set_space_id_node(&space_id)), "genuine space_id accepted");
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
