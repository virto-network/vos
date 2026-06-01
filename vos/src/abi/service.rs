//! Service identity type.
//!
//! A `ServiceId` is a u32 that encodes topology:
//!
//! ```text
//! [node_prefix: 16 bits][local_id: 16 bits]
//! ```
//!
//! - **node_prefix** (bits 31..16): identifies the node in the network.
//!   0 = local/unscoped (backwards compatible with existing actors).
//! - **local_id** (bits 15..0): per-node service counter.
//!   0 = reserved for the registry service.
//!
//! JAM sees the full u32 — no protocol changes needed. Routing checks
//! the prefix: matching prefix → local delivery, different → forward
//! to the network layer.

/// Unique identifier for a service within the VOS network.
///
/// Encodes `[node_prefix:16][local_id:16]` in a single u32.
/// Backwards compatible: IDs with prefix 0 behave like plain counters.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceId(pub u32);

impl ServiceId {
    /// The space-local registry service — well-known ID 0 on every
    /// node. Holds the catalog for the space the node belongs to.
    pub const REGISTRY: Self = Self(0);

    /// The hyperspace registry service — well-known ID 1 on every
    /// node that participates in a hyperspace. Holds the catalog
    /// shared across all member spaces of the hyperspace, so
    /// `resolve` can fall through from the local registry to find
    /// agents in peer spaces. Empty / not-spawned on nodes whose
    /// space manifest doesn't set a hyperspace.
    pub const HYPERSPACE_REGISTRY: Self = Self(1);

    /// Construct a ServiceId from a node prefix and local ID.
    pub const fn new(node_prefix: u16, local_id: u16) -> Self {
        Self(((node_prefix as u32) << 16) | (local_id as u32))
    }

    /// The node prefix (upper 16 bits). 0 = local/unscoped.
    pub const fn node_prefix(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// The local service ID within the node (lower 16 bits).
    pub const fn local_id(self) -> u16 {
        self.0 as u16
    }

    /// Check if this ID belongs to a given node prefix.
    pub const fn is_on_node(self, prefix: u16) -> bool {
        self.node_prefix() == prefix
    }

    /// Check if this ID is unscoped (prefix 0, backwards compat).
    pub const fn is_local(self) -> bool {
        self.node_prefix() == 0
    }
}

impl core::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let prefix = self.node_prefix();
        let local = self.local_id();
        if prefix == 0 {
            write!(f, "svc:{local}")
        } else {
            write!(f, "svc:{prefix:04x}:{local}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_slots_are_distinct() {
        assert_ne!(ServiceId::REGISTRY, ServiceId::HYPERSPACE_REGISTRY);
        assert_eq!(ServiceId::REGISTRY.local_id(), 0);
        assert_eq!(ServiceId::HYPERSPACE_REGISTRY.local_id(), 1);
        assert!(ServiceId::REGISTRY.is_local());
        assert!(ServiceId::HYPERSPACE_REGISTRY.is_local());
    }
}
