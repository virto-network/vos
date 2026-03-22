use crate::Hasher;
use core::{cmp, fmt, hash};

/// Content identifier: a hash digest that uniquely identifies a DAG node.
///
/// Two nodes with the same CID are guaranteed to have identical content
/// (payload and children), assuming a collision-resistant hash function.
pub struct Cid<H: Hasher>(pub H::Output);

impl<H: Hasher> Clone for Cid<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<H: Hasher> PartialEq for Cid<H> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<H: Hasher> Eq for Cid<H> {}

impl<H: Hasher> PartialOrd for Cid<H> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<H: Hasher> Ord for Cid<H> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<H: Hasher> hash::Hash for Cid<H> {
    fn hash<Ha: hash::Hasher>(&self, state: &mut Ha) {
        self.0.hash(state)
    }
}

impl<H: Hasher> fmt::Debug for Cid<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({})", self)
    }
}

impl<H: Hasher> fmt::Display for Cid<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<H: Hasher> AsRef<[u8]> for Cid<H> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
