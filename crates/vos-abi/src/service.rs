//! Service identity type.

/// Unique identifier for a service (actor) within the VOS runtime.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceId(pub u32);
