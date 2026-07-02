//! Tunable constants: the commit-id domain tag and sizing/paging bounds.

/// Domain tag for commit-record ids.
pub const COMMIT_ID_DOMAIN_TAG: &[u8] = b"vos-msg-commit/v1";

/// Per-field ciphertext bound. Keeps a `CommitRow` small and a
/// `commits` page predictable; the host's hard reply ceiling is far
/// higher (8 MiB), so this is a sizing choice, not a correctness
/// bound. Commit + welcome together are also held under
/// [`crate::MAX_ROW_BYTES`].
pub const MAX_BODY_BYTES: usize = 8 * 1024;

/// Combined bound on `commit_body + welcome` so one row stays small.
/// Generous for small groups (an OpenMLS Welcome for a handful of
/// members is a few KiB); larger groups need welcome-by-blob-
/// reference, which can land without changing this actor's chain
/// semantics.
pub const MAX_ROW_BYTES: usize = 12 * 1024;

/// Byte budget for one `commits` page (same dispatch-cap
/// reasoning as msg-log's history paging).
pub const PAGE_BYTE_BUDGET: usize = 12 * 1024;

/// Hard cap on rows per `commits` page.
pub const PAGE_MAX_ROWS: u32 = 16;
