//! Clean-break guard for `AgentRow::install_payloads`.
//!
//! The registry stores a single `Vec<u8>` per agent for any
//! one-shot messages we should dispatch on cold start (set by
//! the recipe reconciler — `space apply` or genesis apply — from
//! a recipe's `[[agent.on_start]]` table). V2 rejects non-empty host-owned
//! lifecycle payloads; this helper now accepts only the empty registry field
//! while the catalog row schema is cut over.
//!
//! Convention: empty input ⇔ empty bytes. The registry treats
//! `install_payloads.is_empty()` as "no on-start dispatch".

/// Encode a list of pre-framed wire payloads into the bytes
/// stored on `AgentRow::install_payloads`. Returns an empty
/// `Vec` when there are no payloads so the registry row stays
/// compact.
pub fn encode(payloads: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    if !payloads.is_empty() {
        anyhow::bail!(
            "VOS v2 does not encode host-owned on_start payloads; invoke initialization as typed \
             durable actor work"
        );
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payloads_encode_as_empty_bytes() {
        let bytes = encode(&[]).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn nonempty_payloads_are_rejected() {
        let payloads = vec![b"hello".to_vec(), b"world".to_vec(), Vec::new()];
        assert!(encode(&payloads).is_err());
    }
}
