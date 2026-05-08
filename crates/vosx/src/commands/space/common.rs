//! Shared helpers for `vosx space *` commands.
//!
//! - `parse_program_ref` — splits `name[:version]`, defaulting
//!   bare names to `:latest`. Used by publish / install / upgrade.
//! - `truncate` — left-truncate a string to a column width for
//!   tabular output.
//! - `instance_service_id` / `registry_replication_id` — the two
//!   deterministic id derivations that need to agree across
//!   `up`, `reconcile`, `client`.

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
///
/// `prefix` is the node's 16-bit identity prefix; the low 16
/// bits are derived from `instance_name` and clamped to
/// `[0x100, 0x7FFF]` so they can't collide with `ServiceId::REGISTRY`
/// (= 0) or any reserved low system ids. Stable across restarts
/// of the same node so each instance's redb path persists.
pub fn instance_service_id(instance_name: &str, prefix: u16) -> ServiceId {
    let mut h = blake2b_simd::Params::new().hash_length(2).to_state();
    h.update(b"vos-instance-svc-id/v1");
    h.update(&[0u8]);
    h.update(instance_name.as_bytes());
    let bytes = h.finalize();
    let buf = bytes.as_bytes();
    let raw = u16::from_le_bytes([buf[0], buf[1]]);
    let local = (raw & 0x7FFF).max(0x100);
    ServiceId(((prefix as u32) << 16) | (local as u32))
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
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-space-registry/v1");
    h.update(&[0u8]);
    h.update(space_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
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
}
