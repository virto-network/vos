//! rkyv codec for `AgentRow::install_payloads`.
//!
//! The registry stores a single `Vec<u8>` per agent for any
//! one-shot messages we should dispatch on cold start (set by
//! `space up --manifest`'s reconciler from a manifest's
//! `[[agent.on_start]]` table). On the wire the natural shape
//! is `Vec<Vec<u8>>`, so we rkyv-encode that and unpack it on
//! the daemon side.
//!
//! Convention: empty input ⇔ empty bytes. The registry treats
//! `install_payloads.is_empty()` as "no on-start dispatch".

/// Encode a list of pre-framed wire payloads into the bytes
/// stored on `AgentRow::install_payloads`. Returns an empty
/// `Vec` when there are no payloads so the registry row stays
/// compact.
pub fn encode(payloads: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    if payloads.is_empty() {
        return Ok(Vec::new());
    }
    Ok(
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&payloads.to_vec())
            .map_err(|e| anyhow::anyhow!("rkyv encode install_payloads: {e}"))?
            .to_vec(),
    )
}

/// Decode the `install_payloads` field back into the inner
/// list. Empty input → empty list. Validation goes through
/// `vos::Decode::try_decode`, so structurally invalid bytes
/// surface as an error rather than panicking the daemon.
pub fn decode(bytes: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    <Vec<Vec<u8>> as vos::Decode>::try_decode(bytes)
        .ok_or_else(|| anyhow::anyhow!("rkyv decode install_payloads: invalid bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_round_trips_to_empty_bytes() {
        let bytes = encode(&[]).unwrap();
        assert!(bytes.is_empty());
        let back = decode(&bytes).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn nonempty_round_trips() {
        let payloads = vec![b"hello".to_vec(), b"world".to_vec(), Vec::new()];
        let bytes = encode(&payloads).unwrap();
        assert!(!bytes.is_empty());
        let back = decode(&bytes).unwrap();
        assert_eq!(back, payloads);
    }

    #[test]
    fn corrupt_bytes_error_rather_than_panic() {
        // Random non-rkyv bytes shouldn't deserialize.
        let bogus = vec![0xFFu8; 32];
        assert!(decode(&bogus).is_err());
    }
}
