use core::fmt;

macro_rules! id_type {
    ($name:ident, $label:literal) => {
        #[repr(transparent)]
        #[derive(
            crate::rkyv::Archive,
            crate::rkyv::Serialize,
            crate::rkyv::Deserialize,
            Clone,
            Copy,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
        )]
        #[rkyv(crate = crate::rkyv)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, "("))?;
                for byte in &self.0[..4] {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str("…)")
            }
        }
    };
}

id_type!(Hash, "Hash");
id_type!(SpaceId, "SpaceId");
id_type!(RootServiceId, "RootServiceId");
id_type!(ActorId, "ActorId");
id_type!(SubjectId, "SubjectId");
id_type!(ProducerId, "ProducerId");
id_type!(ProgramId, "ProgramId");
id_type!(DeploymentId, "DeploymentId");
id_type!(InvocationId, "InvocationId");
id_type!(CallId, "CallId");
id_type!(ChangeId, "ChangeId");
id_type!(OperationId, "OperationId");
id_type!(SystemCapabilityId, "SystemCapabilityId");

impl Hash {
    pub fn digest(domain: &[u8], parts: &[&[u8]]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(domain, parts))
    }
}

impl ProgramId {
    /// Canonical PVM bytes, not an ELF or a JIT artifact, define program
    /// identity.
    pub fn of_pvm(pvm: &[u8]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(b"vos/program/v2", &[pvm]))
    }
}

impl ActorId {
    /// Stable identity of an owned child in its parent's namespace. Retries
    /// of the same spawn request therefore address one actor, while the
    /// parent's globally unique identity keeps equal child names in separate
    /// trees distinct.
    pub fn owned_child(parent: Self, name: &str) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/owned-child/v2",
            &[&parent.0, name.as_bytes()],
        ))
    }
}

impl ProducerId {
    pub fn of_public_key(public_key: &[u8]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/producer/v2",
            &[public_key],
        ))
    }
}

impl SubjectId {
    /// Canonical v2 identity of a transport-authenticated peer. The raw
    /// libp2p multihash remains a host credential; actor wires carry only this
    /// fixed-width, domain-separated subject.
    pub fn of_authenticated_peer(peer_id: &[u8]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/peer-subject/v2",
            &[peer_id],
        ))
    }
}

impl InvocationId {
    /// Derive a stable invocation identifier from an application namespace and
    /// caller-provided nonce.
    pub fn derive(namespace: &[u8], nonce: &[u8]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/invocation/v2",
            &[namespace, nonce],
        ))
    }

    /// The nth await in an invocation always derives the same call id. Retries
    /// therefore address the same durable request.
    pub fn call_id(self, await_ordinal: u64) -> CallId {
        CallId(crate::crypto::blake2b_hash::<32>(
            b"vos/call/v2",
            &[&self.0, &await_ordinal.to_le_bytes()],
        ))
    }

    /// Stable completion identifier for the invocation itself. Durable actor
    /// awaits use [`Self::call_id`]; a root caller has no await ordinal, so its
    /// reply preserves the already unique invocation bytes under the `CallId`
    /// type instead of invoking a guest-side hashing precompile.
    pub const fn root_reply_id(self) -> CallId {
        CallId(self.0)
    }

    /// Stable target-side workflow identity for a durable actor call. The
    /// source invocation and await ordinal remain committed in the message;
    /// this domain-separated ID names the callee's independently deduplicated
    /// workflow.
    pub fn for_call(call: CallId) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/call-invocation/v2",
            &[&call.0],
        ))
    }
}

impl ChangeId {
    /// Stable operation identity within one atomically batched CRDT change.
    pub fn operation(self, actor: ActorId, field: Hash, ordinal: u32) -> OperationId {
        OperationId(crate::crypto::blake2b_hash::<32>(
            b"vos/crdt-operation-id/v2",
            &[&self.0, &actor.0, &field.0, &ordinal.to_le_bytes()],
        ))
    }
}

/// Authenticated origin presented to an actor. `System` is only an identity
/// class; authorization still requires a matching platform capability in the
/// work envelope.
#[derive(
    crate::rkyv::Archive,
    crate::rkyv::Serialize,
    crate::rkyv::Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[rkyv(crate = crate::rkyv)]
pub enum Origin {
    Anonymous,
    Member(SubjectId),
    Actor(ActorId),
    System,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_ids_are_stable_and_ordinal_scoped() {
        let invocation = InvocationId::derive(b"test", b"nonce");
        assert_eq!(invocation.call_id(3), invocation.call_id(3));
        assert_ne!(invocation.call_id(3), invocation.call_id(4));
        assert_eq!(invocation.root_reply_id().0, invocation.0);
        assert_eq!(
            InvocationId::for_call(invocation.call_id(3)),
            InvocationId::for_call(invocation.call_id(3))
        );
        assert_ne!(
            InvocationId::for_call(invocation.call_id(3)),
            InvocationId::for_call(invocation.call_id(4))
        );
    }

    #[test]
    fn program_id_uses_canonical_bytes() {
        assert_eq!(ProgramId::of_pvm(b"pvm"), ProgramId::of_pvm(b"pvm"));
        assert_ne!(ProgramId::of_pvm(b"pvm"), ProgramId::of_pvm(b"elf"));
    }

    #[test]
    fn owned_child_ids_are_parent_and_name_scoped() {
        let parent = ActorId([1; 32]);
        assert_eq!(
            ActorId::owned_child(parent, "worker"),
            ActorId::owned_child(parent, "worker")
        );
        assert_ne!(
            ActorId::owned_child(parent, "worker"),
            ActorId::owned_child(parent, "other")
        );
        assert_ne!(
            ActorId::owned_child(parent, "worker"),
            ActorId::owned_child(ActorId([2; 32]), "worker")
        );
    }

    #[test]
    fn authenticated_peer_subjects_are_stable_and_peer_scoped() {
        assert_eq!(
            SubjectId::of_authenticated_peer(b"peer-a"),
            SubjectId::of_authenticated_peer(b"peer-a")
        );
        assert_ne!(
            SubjectId::of_authenticated_peer(b"peer-a"),
            SubjectId::of_authenticated_peer(b"peer-b")
        );
    }

    #[test]
    fn typed_origin_round_trips_as_actor_state() {
        let origin = Origin::Member(SubjectId([7; 32]));
        let bytes = crate::Encode::encode(&origin);
        assert_eq!(<Origin as crate::Decode>::try_decode(&bytes), Some(origin));
    }
}
