//! Shared helpers for `vosx space *` commands.
//!
//! Mostly host-side concerns: CLI string parsing, tabular
//! formatting, and the blake2b derivations that vosx needs
//! before the daemon is even up. The cross-target
//! `instance_service_id` lives in the space-registry crate
//! since the actor's `resolve` handler also needs it.

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
/// Thin wrapper around `space_registry::instance_service_id`
/// that returns the typed `ServiceId` host code prefers; the
/// formula itself lives next to the registry actor's `resolve`
/// handler so both sides agree by construction.
pub fn instance_service_id(instance_name: &str, prefix: u16) -> ServiceId {
    ServiceId(space_registry::instance_service_id(instance_name, prefix))
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

/// Compute a space's id from the registry's genesis DAG root.
/// Stable for the lifetime of the space and verifiable by any
/// joiner that fetches the genesis snapshot. Host-only
/// (called before any daemon is up).
pub fn derive_space_id(genesis_dag_root: &[u8; 32]) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        space_registry::SPACE_ID_DOMAIN_TAG,
        &[&[0u8], genesis_dag_root],
    )
}

/// Auto-derive a `replication_id` for an installed agent.
/// `blake2b("vos-replication-id/v1" || instance_name || 0 || program_hash)`.
/// Two replicas that install the same program with the same
/// `instance_name` auto-discover each other on the gossipsub
/// topic this id maps to. Host-only — set at install time
/// from vosx and stored on the registry's `AgentRow`.
pub fn auto_replication_id(instance_name: &str, program_hash: &[u8; 32]) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        b"vos-replication-id/v1",
        &[&[0u8], instance_name.as_bytes(), &[0u8], program_hash],
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
    fn consistency_from_u8_round_trips_known_codes() {
        assert!(matches!(consistency_from_u8(0), Some(Consistency::Ephemeral)));
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
        let h = [0xCDu8; 32];
        let a = auto_replication_id("alpha", &h);
        let b = auto_replication_id("beta", &h);
        assert_ne!(a, b);
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
