//! Tunable constants: the envelope-id domain tag, MLS framing prefix, and
//! sizing/paging bounds.

/// Domain tag for envelope ids: `blake2b("vos-msg-envelope/v1" ‖
/// fields)`. Content-derived, so equal envelopes deduplicate and
/// every replica computes the same id without coordination.
pub const ENVELOPE_ID_DOMAIN_TAG: &[u8] = b"vos-msg-envelope/v1";

/// Upper bound on one envelope's ciphertext body. Keeps a single
/// envelope well under the dispatch reply cap and the 8 MiB
/// replication frame; attachments belong in a blob store, not
/// the message log.
pub const MAX_BODY_BYTES: usize = 48 * 1024;

/// Leading bytes of a TLS-serialized MLS `MLSMessage` carrying an
/// application message: `ProtocolVersion::Mls10` (u16 = 1) followed
/// by `WireFormat::PrivateMessage` (u16 = 2). The data plane carries
/// only these. The actor can't decrypt (all crypto is at the edge),
/// but rejecting bodies that aren't even MLS PrivateMessage framing
/// keeps junk out of the grow-only replicated log — a malformed body
/// can never deduplicate against a real one or waste every replica's
/// storage. Real MLS validation still happens in the messenger.
pub const MLS_PRIVATE_MESSAGE_PREFIX: [u8; 4] = [0x00, 0x01, 0x00, 0x02];

/// Soft byte budget for one `history` page. The host's hard reply
/// ceiling is much higher (8 MiB producer cap), so this is a
/// pagination-ergonomics target, not a correctness bound — it keeps
/// pages small and predictable. A single envelope larger than the
/// budget is still returned alone (progress is never starved).
pub const HISTORY_BYTE_BUDGET: usize = 12 * 1024;

/// Hard cap on rows per `history` page, independent of size.
pub const HISTORY_MAX_ROWS: u32 = 64;
