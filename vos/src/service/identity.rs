use core::fmt;

macro_rules! id_type {
    ($name:ident, $label:literal) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
id_type!(CapabilityId, "CapabilityId");
id_type!(RoleId, "RoleId");

impl Hash {
    pub fn digest(domain: &[u8], parts: &[&[u8]]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(domain, parts))
    }
}

impl CapabilityId {
    /// Stable identifier for one space-level permission.
    pub fn named(name: &str) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/capability/service",
            &[name.as_bytes()],
        ))
    }
}

impl RoleId {
    /// Stable identifier for a named role inside one space.
    pub fn named(space: SpaceId, name: &str) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/role/service",
            &[space.as_bytes(), name.as_bytes()],
        ))
    }
}

impl ProgramId {
    /// Canonical PVM bytes, not an ELF or a JIT artifact, define program
    /// identity.
    pub fn of_pvm(pvm: &[u8]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/program/service",
            &[pvm],
        ))
    }
}

impl SubjectId {
    /// Canonical service identity of a transport-authenticated peer. The raw
    /// libp2p multihash remains a host credential; actor wires carry only this
    /// fixed-width, domain-separated subject.
    pub fn of_authenticated_peer(peer_id: &[u8]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/subject/service",
            &[peer_id],
        ))
    }

    /// Stable identity for a host-validated ingress credential. The secret
    /// itself never enters actor arguments or durable service state.
    pub fn of_ingress_credential(credential_id: &[u8; 32]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/subject/ingress-credential",
            &[credential_id],
        ))
    }
}

impl ActorId {
    /// Stable identity of one owned child in its parent's namespace.
    /// Replaying the same spawn therefore addresses the same actor, while
    /// equal names below different globally unique parents remain distinct.
    pub fn owned_child(parent: Self, name: &str) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/owned-child/service",
            &[&parent.0, name.as_bytes()],
        ))
    }
}

impl ProducerId {
    pub fn of_public_key(public_key: &[u8]) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/producer/service",
            &[public_key],
        ))
    }
}

impl InvocationId {
    /// Marker reserved for ingress mutations carrying a caller-owned
    /// idempotency key. Only this namespace is eligible for bounded,
    /// host-retained response recovery after publication acknowledgement.
    const INGRESS_IDEMPOTENCY_PREFIX: [u8; 8] = *b"VOSINGR!";

    /// Derive a stable invocation identifier from an application namespace and
    /// caller-provided nonce.
    pub fn derive(namespace: &[u8], nonce: &[u8]) -> Self {
        let namespace_len = (namespace.len() as u64).to_le_bytes();
        let nonce_len = (nonce.len() as u64).to_le_bytes();
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/invocation/service",
            &[&namespace_len, namespace, &nonce_len, nonce],
        ))
    }

    /// Derive the durable identity of one ingress operation. `ingress`
    /// separates protocol namespaces; callers must reuse `key` only for the
    /// exact same operation.
    pub fn for_ingress_idempotency(
        subject: SubjectId,
        target: ActorId,
        ingress: &str,
        key: &[u8],
    ) -> Self {
        let mut nonce = alloc::vec::Vec::with_capacity(64 + ingress.len() + key.len() + 16);
        nonce.extend_from_slice(&subject.0);
        nonce.extend_from_slice(&target.0);
        nonce.extend_from_slice(&(ingress.len() as u64).to_le_bytes());
        nonce.extend_from_slice(ingress.as_bytes());
        nonce.extend_from_slice(&(key.len() as u64).to_le_bytes());
        nonce.extend_from_slice(key);
        let mut invocation = Self::derive(b"vos/ingress/idempotency-key", &nonce);
        invocation.0[..Self::INGRESS_IDEMPOTENCY_PREFIX.len()]
            .copy_from_slice(&Self::INGRESS_IDEMPOTENCY_PREFIX);
        invocation
    }

    pub(crate) fn retains_idempotent_result(self) -> bool {
        self.0.starts_with(&Self::INGRESS_IDEMPOTENCY_PREFIX)
    }

    /// The nth await in an invocation always derives the same call id. Retries
    /// therefore address the same durable request.
    pub fn call_id(self, await_ordinal: u64) -> CallId {
        CallId(crate::crypto::blake2b_hash::<32>(
            b"vos/call/service",
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
            b"vos/call-invocation/service",
            &[&call.0],
        ))
    }
}

impl ChangeId {
    /// Stable operation identity within one atomically batched CRDT change.
    pub fn operation(
        self,
        actor: ActorId,
        dispatch_ordinal: u32,
        field: Hash,
        operation_ordinal: u32,
    ) -> OperationId {
        OperationId(crate::crypto::blake2b_hash::<32>(
            b"vos/crdt-operation-id/service",
            &[
                &self.0,
                &actor.0,
                &dispatch_ordinal.to_le_bytes(),
                &field.0,
                &operation_ordinal.to_le_bytes(),
            ],
        ))
    }
}

/// Authenticated origin presented to an actor. `System` is only an identity
/// class; authorization still requires a matching platform capability in the
/// work envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    fn invocation_ids_frame_variable_length_inputs() {
        assert_ne!(
            InvocationId::derive(b"ab", b"c"),
            InvocationId::derive(b"a", b"bc")
        );
    }

    #[test]
    fn named_capabilities_and_roles_are_domain_separated() {
        let capability = CapabilityId::named("agent.invoke");
        assert_eq!(capability, CapabilityId::named("agent.invoke"));
        assert_ne!(capability, CapabilityId::named("agent.create.local"));

        let space = SpaceId([9; 32]);
        let role = RoleId::named(space, "developer");
        assert_eq!(role, RoleId::named(space, "developer"));
        assert_ne!(role, RoleId::named(space, "member"));
        assert_ne!(role.0, capability.0);
    }

    #[test]
    fn program_id_uses_canonical_bytes() {
        assert_eq!(ProgramId::of_pvm(b"pvm"), ProgramId::of_pvm(b"pvm"));
        assert_ne!(ProgramId::of_pvm(b"pvm"), ProgramId::of_pvm(b"elf"));
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
}
