use core::fmt::Debug;

/// A cryptographic hash function used for content addressing.
///
/// Implementations provide the hash algorithm that determines how
/// content identifiers (CIDs) are computed for DAG nodes.
///
/// # Example
///
/// ```ignore
/// use sha2::{Sha256, Digest};
///
/// struct Sha256Hasher;
///
/// impl merkle_crdt::Hasher for Sha256Hasher {
///     type Output = [u8; 32];
///     fn hash(data: &[u8]) -> [u8; 32] {
///         Sha256::new().chain_update(data).finalize().into()
///     }
/// }
/// ```
pub trait Hasher {
    /// The fixed-size hash digest (e.g. `[u8; 32]` for SHA-256).
    type Output: Clone + Eq + Ord + core::hash::Hash + Debug + AsRef<[u8]>;

    /// Hash arbitrary bytes and return the digest.
    fn hash(data: &[u8]) -> Self::Output;
}
