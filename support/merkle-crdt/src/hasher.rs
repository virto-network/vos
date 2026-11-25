use crate::encode::Decode;
use core::fmt::Debug;

/// A cryptographic hash function used for content addressing.
///
/// Implementations provide the hash algorithm that determines how
/// content identifiers (CIDs) are computed for DAG nodes. A CID is the
/// hash of a node's bytes with no domain tag: a caller that names other
/// objects with the same hash keeps them apart itself.
///
/// # Example
///
/// ```
/// use blake2::{digest::consts::U32, Blake2b, Digest};
///
/// struct Blake2b256;
///
/// impl merkle_crdt::Hasher for Blake2b256 {
///     type Output = [u8; 32];
///     fn hash(data: &[u8]) -> [u8; 32] {
///         Blake2b::<U32>::digest(data).into()
///     }
/// }
/// ```
pub trait Hasher {
    /// The fixed-size hash digest (e.g. `[u8; 32]` for SHA-256): a byte
    /// array, not empty, whose size in memory is its encoded length, since
    /// a node's parents are read as consecutive digests of that width.
    type Output: Clone + Eq + Ord + core::hash::Hash + Debug + AsRef<[u8]> + Decode;

    /// Hash arbitrary bytes and return the digest.
    fn hash(data: &[u8]) -> Self::Output;
}
