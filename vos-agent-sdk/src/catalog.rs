//! Canonical protocol shared by clean system-catalog hosts and actors.
//!
//! Catalog mutations are self-contained, bounded messages.  The authority
//! receipt is evidence for exactly one canonical mutation request; callers
//! and relay transports never become ambient catalog authority.

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU64;

use crate::authority::{
    AgentAuthorityBinding, AuthorityOperationKind, AuthorityReceipt, AuthorityVerifier,
};
use crate::{
    ActorId, AgentId, AgentIdentity, AgentProfile, BlobRef, DeploymentId, Hash, InvocationContext,
    InvocationId, InvocationRoleClaims, MethodMode, ProgramId, SpaceId,
};

/// Maximum UTF-8 bytes in one independently mutable catalog namespace.
pub const MAX_CATALOG_NAMESPACE_BYTES: usize = 96;
/// Maximum UTF-8 bytes in one alias within a catalog namespace.
pub const MAX_CATALOG_ALIAS_BYTES: usize = 96;
/// Maximum entries returned by one bounded catalog page.
pub const MAX_CATALOG_PAGE_ENTRIES: usize = 4;

/// Exact installed route and trust anchor for one clean system-catalog actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogActorTarget {
    pub space: SpaceId,
    pub system_agent: AgentId,
    pub system_runtime_deployment: DeploymentId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub authority: AgentAuthorityBinding,
}

impl CatalogActorTarget {
    pub fn is_valid(self) -> bool {
        self.space != SpaceId::ZERO
            && self.system_agent != AgentId::ZERO
            && self.system_runtime_deployment != DeploymentId::ZERO
            && self.actor != ActorId::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.program != ProgramId::ZERO
            && self.authority.is_valid()
    }
}

/// A byte-exact, case-sensitive alias. No host-dependent normalization is
/// applied: UTF-8 bytes are the namespace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CatalogAlias {
    pub namespace: String,
    pub name: String,
}

impl CatalogAlias {
    pub fn is_valid(&self) -> bool {
        valid_name(&self.namespace, MAX_CATALOG_NAMESPACE_BYTES)
            && valid_name(&self.name, MAX_CATALOG_ALIAS_BYTES)
    }
}

fn valid_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.as_bytes().contains(&0)
        && !value.chars().any(char::is_control)
}

/// Exact public identity and content advertised under an alias.
///
/// Publication is deliberately limited to Shared Agents. Local and Private
/// identities are invalid protocol values, including for withdrawals, so
/// they cannot be smuggled into replicated catalog history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogPublication {
    pub identity: AgentIdentity,
    pub actor: ActorId,
    pub actor_deployment: DeploymentId,
    pub actor_program: ProgramId,
    pub actor_package: BlobRef,
    pub content: BlobRef,
}

impl CatalogPublication {
    pub fn is_valid(&self) -> bool {
        self.identity.space != SpaceId::ZERO
            && self.identity.agent != AgentId::ZERO
            && self.identity.owner != crate::PrincipalId::ZERO
            && self.identity.profile == AgentProfile::Shared
            && self.identity.runtime_deployment != DeploymentId::ZERO
            && self.identity.runtime_program != ProgramId::ZERO
            && self.identity.runtime_producer != crate::ProducerId::ZERO
            && self.actor != ActorId::ZERO
            && self.actor_deployment != DeploymentId::ZERO
            && self.actor_program != ProgramId::ZERO
            && valid_blob(&self.actor_package)
            && valid_blob(&self.content)
    }
}

fn valid_blob(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO
        && reference.len != 0
        && reference.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
}

/// One grow-only catalog operation. A withdrawal carries the exact prior
/// publication shape it supersedes, avoiding an untyped alias tombstone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CatalogMutationKind {
    Publish = 0,
    Withdraw = 1,
}

/// Canonical request authorized by a `PublishCatalog` authority receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogMutationRequest {
    pub invocation: InvocationId,
    pub catalog: CatalogActorTarget,
    pub alias: CatalogAlias,
    pub generation: NonZeroU64,
    pub kind: CatalogMutationKind,
    pub publication: CatalogPublication,
}

impl CatalogMutationRequest {
    pub fn validate_shape(&self) -> Result<(), CatalogProtocolError> {
        if self.invocation == InvocationId::ZERO
            || !self.catalog.is_valid()
            || !self.alias.is_valid()
            || !self.publication.is_valid()
            || self.catalog.space != self.publication.identity.space
        {
            return Err(CatalogProtocolError::InvalidRequest);
        }
        if crate::wire::catalog_mutation_request_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(CatalogProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Commitment of the complete canonical CMT1 request, including its
    /// invocation ID. This is the only value accepted in the receipt selector.
    pub fn commitment(&self) -> Hash {
        crate::wire::catalog_mutation_request_commitment(self)
    }

    /// Stable semantic ordering key used only to resolve concurrent
    /// operations with the same nonzero generation. Invocation retries do not
    /// get ordering power merely by choosing another invocation ID.
    pub fn mutation_commitment(&self) -> Hash {
        crate::wire::catalog_mutation_semantic_commitment(self)
    }
}

/// A mutation plus its exact guest-verifiable policy receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogMutationCall {
    pub request: CatalogMutationRequest,
    pub authority: AuthorityReceipt,
}

impl CatalogMutationCall {
    pub fn validate_shape(&self) -> Result<(), CatalogProtocolError> {
        self.request.validate_shape()?;
        self.authority
            .validate_shape()
            .map_err(|_| CatalogProtocolError::InvalidAuthority)?;
        let selector = &self.authority.selector;
        if selector.operation != AuthorityOperationKind::PublishCatalog
            || selector.space != self.request.publication.identity.space
            || selector.agent != self.request.publication.identity.agent
            || selector.runtime_deployment != self.request.publication.identity.runtime_deployment
            || selector.actor.is_some()
            || selector.actor_deployment.is_some()
            || selector.request != self.request.commitment()
        {
            return Err(CatalogProtocolError::MismatchedAuthority);
        }
        if crate::wire::catalog_mutation_call_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(CatalogProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Verify against the independently installed catalog target and signer.
    pub fn verify_at<V: AuthorityVerifier>(
        &self,
        installed: CatalogActorTarget,
        logical_slot: u64,
        verifier: &V,
    ) -> Result<(), CatalogProtocolError> {
        self.validate_shape()?;
        if self.request.catalog != installed || !installed.authority.accepts(&self.authority) {
            return Err(CatalogProtocolError::MismatchedAuthority);
        }
        self.authority
            .verify_at(logical_slot, verifier)
            .map_err(|_| CatalogProtocolError::InvalidAuthority)
    }

    /// Bind an exact canonical call to its Merge-lane actor invocation. The
    /// signed receipt is the authority; relay identity, roles, and
    /// capabilities are never policy inputs.
    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.request.invocation
            && context.actor == self.request.catalog.actor
            && context.mode == MethodMode::Merge
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }

    /// Commitment of the complete canonical CMC1 call, including signature.
    pub fn commitment(&self) -> Hash {
        crate::wire::catalog_mutation_call_commitment(self)
    }
}

/// Deterministic exact-retry reply for one accepted mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogMutationResult {
    pub invocation: InvocationId,
    pub request: Hash,
    pub mutation: Hash,
    pub call: Hash,
}

impl CatalogMutationResult {
    pub fn from_call(call: &CatalogMutationCall) -> Result<Self, CatalogProtocolError> {
        call.validate_shape()?;
        Ok(Self {
            invocation: call.request.invocation,
            request: call.request.commitment(),
            mutation: call.request.mutation_commitment(),
            call: call.commitment(),
        })
    }

    pub fn matches_call(self, call: &CatalogMutationCall) -> bool {
        Self::from_call(call).is_ok_and(|expected| expected == self)
    }

    pub fn is_valid(self) -> bool {
        self.invocation != InvocationId::ZERO
            && self.request != Hash::ZERO
            && self.mutation != Hash::ZERO
            && self.call != Hash::ZERO
    }
}

/// One visible, independently inspectable catalog entry. Only winning Publish
/// operations appear in a page; withdrawals remain in actor history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    pub request: CatalogMutationRequest,
    pub authority: AuthorityReceipt,
}

impl CatalogEntry {
    pub fn from_call(call: &CatalogMutationCall) -> Result<Self, CatalogProtocolError> {
        call.validate_shape()?;
        if call.request.kind != CatalogMutationKind::Publish {
            return Err(CatalogProtocolError::InvalidEntry);
        }
        Ok(Self {
            request: call.request.clone(),
            authority: call.authority.clone(),
        })
    }

    pub fn validate_shape(&self) -> Result<(), CatalogProtocolError> {
        if self.request.kind != CatalogMutationKind::Publish {
            return Err(CatalogProtocolError::InvalidEntry);
        }
        CatalogMutationCall {
            request: self.request.clone(),
            authority: self.authority.clone(),
        }
        .validate_shape()
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::catalog_entry_commitment(self)
    }
}

/// Stable, exclusive alias-name cursor within one exact namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogPageRequest {
    pub catalog: CatalogActorTarget,
    pub namespace: String,
    pub after: Option<String>,
    pub limit: u16,
}

impl CatalogPageRequest {
    pub fn validate_shape(&self) -> Result<(), CatalogProtocolError> {
        if !self.catalog.is_valid()
            || !valid_name(&self.namespace, MAX_CATALOG_NAMESPACE_BYTES)
            || self
                .after
                .as_deref()
                .is_some_and(|value| !valid_name(value, MAX_CATALOG_ALIAS_BYTES))
            || self.limit == 0
            || usize::from(self.limit) > MAX_CATALOG_PAGE_ENTRIES
        {
            return Err(CatalogProtocolError::InvalidPage);
        }
        Ok(())
    }
}

/// Canonical stable page ordered by alias name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogPage {
    pub catalog: CatalogActorTarget,
    pub namespace: String,
    pub entries: Vec<CatalogEntry>,
    pub next: Option<String>,
}

impl CatalogPage {
    pub fn validate_shape(&self) -> Result<(), CatalogProtocolError> {
        if !self.catalog.is_valid()
            || !valid_name(&self.namespace, MAX_CATALOG_NAMESPACE_BYTES)
            || self.entries.len() > MAX_CATALOG_PAGE_ENTRIES
            || self
                .next
                .as_deref()
                .is_some_and(|value| !valid_name(value, MAX_CATALOG_ALIAS_BYTES))
        {
            return Err(CatalogProtocolError::InvalidPage);
        }
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            entry.validate_shape()?;
            if entry.request.catalog != self.catalog
                || entry.request.alias.namespace != self.namespace
                || previous.is_some_and(|value| value >= entry.request.alias.name.as_str())
            {
                return Err(CatalogProtocolError::InvalidPage);
            }
            previous = Some(entry.request.alias.name.as_str());
        }
        if self
            .next
            .as_deref()
            .is_some_and(|next| previous != Some(next))
            || self.next.is_some() && self.entries.is_empty()
        {
            return Err(CatalogProtocolError::InvalidPage);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogProtocolError {
    InvalidRequest,
    InvalidAuthority,
    MismatchedAuthority,
    InvalidEntry,
    InvalidPage,
    LimitExceeded,
}

impl core::fmt::Display for CatalogProtocolError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid catalog protocol value: {self:?}")
    }
}

impl core::error::Error for CatalogProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    use crate::authority::{
        AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots, AuthorityReceiptSelector,
    };
    use crate::wire::{
        CanonicalWire, MAX_CATALOG_ENTRY_WIRE_BYTES, MAX_CATALOG_MUTATION_CALL_WIRE_BYTES,
        MAX_CATALOG_MUTATION_REQUEST_WIRE_BYTES, MAX_CATALOG_PAGE_WIRE_BYTES,
    };
    use crate::{InvocationOrigin, PrincipalId, ProducerId};

    const SLOT: u64 = 40;

    fn blob(byte: u8, len: u64) -> BlobRef {
        BlobRef {
            hash: Hash([byte; 32]),
            len,
        }
    }

    fn target() -> CatalogActorTarget {
        let public_key = [0x31; 32];
        CatalogActorTarget {
            space: SpaceId([0x11; 32]),
            system_agent: AgentId([0x12; 32]),
            system_runtime_deployment: DeploymentId([0x13; 32]),
            actor: ActorId([0x14; 32]),
            deployment: DeploymentId([0x15; 32]),
            program: ProgramId([0x16; 32]),
            authority: AgentAuthorityBinding {
                policy: Hash([0x21; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x22; 32]),
                    actor: ActorId([0x23; 32]),
                    deployment: DeploymentId([0x24; 32]),
                    program: ProgramId([0x25; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 7,
            },
        }
    }

    fn publication(profile: AgentProfile) -> CatalogPublication {
        CatalogPublication {
            identity: AgentIdentity {
                space: target().space,
                agent: AgentId([0x41; 32]),
                owner: PrincipalId([0x42; 32]),
                profile,
                runtime_deployment: DeploymentId([0x43; 32]),
                runtime_program: ProgramId([0x44; 32]),
                runtime_producer: ProducerId([0x45; 32]),
            },
            actor: ActorId([0x46; 32]),
            actor_deployment: DeploymentId([0x47; 32]),
            actor_program: ProgramId([0x48; 32]),
            actor_package: blob(0x49, 17),
            content: blob(0x4a, 19),
        }
    }

    fn request(invocation: u8, alias: &str) -> CatalogMutationRequest {
        CatalogMutationRequest {
            invocation: InvocationId([invocation; 32]),
            catalog: target(),
            alias: CatalogAlias {
                namespace: "apps".into(),
                name: alias.into(),
            },
            generation: NonZeroU64::new(3).unwrap(),
            kind: CatalogMutationKind::Publish,
            publication: publication(AgentProfile::Shared),
        }
    }

    fn signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let first = Hash::digest(b"vos/catalog/test-signature/a", &[public_key, message]);
        let second = Hash::digest(b"vos/catalog/test-signature/b", &[public_key, message]);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        signature
    }

    struct TestVerifier;

    impl AuthorityVerifier for TestVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], candidate: &[u8; 64]) -> bool {
            *candidate == signature(public_key, message)
        }
    }

    fn resign(call: &mut CatalogMutationCall) {
        call.authority.selector.request = call.request.commitment();
        call.authority.signature = [1; 64];
        call.authority.signature =
            signature(&call.authority.public_key, &call.authority.signing_bytes());
    }

    fn call(invocation: u8, alias: &str) -> CatalogMutationCall {
        let request = request(invocation, alias);
        let authority = target().authority;
        let mut call = CatalogMutationCall {
            authority: AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: authority.policy,
                    issuer: authority.issuer,
                    space: request.publication.identity.space,
                    agent: request.publication.identity.agent,
                    operation: AuthorityOperationKind::PublishCatalog,
                    runtime_deployment: request.publication.identity.runtime_deployment,
                    actor: None,
                    actor_deployment: None,
                    evidence: AuthorityEvidence {
                        package: Some(blob(0x51, 23)),
                        proof: Some(blob(0x52, 29)),
                        commitment: Hash([0x53; 32]),
                    },
                    lane_roots: AuthorityLaneRoots {
                        control: Some(Hash([0x54; 32])),
                        linear: Some(Hash([0x55; 32])),
                        merge: Some(Hash([0x56; 32])),
                        local: None,
                    },
                    epoch: 9,
                    decision_sequence: 0,
                    acknowledged_through: 0,
                    valid_from: 32,
                    expires_at: 64,
                    request: request.commitment(),
                },
                public_key: authority.public_key,
                signature: [1; 64],
            },
            request,
        };
        resign(&mut call);
        call
    }

    fn context(call: &CatalogMutationCall) -> InvocationContext {
        InvocationContext {
            invocation: call.request.invocation,
            actor: call.request.catalog.actor,
            mode: MethodMode::Merge,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot: SLOT,
        }
    }

    #[test]
    fn catalog_wires_are_canonical_bounded_and_have_stable_golden_commitments() {
        let call = call(0x61, "editor");
        let request_bytes = call.request.encode().unwrap();
        let call_bytes = call.encode().unwrap();
        let result = CatalogMutationResult::from_call(&call).unwrap();
        let result_bytes = result.encode().unwrap();
        let entry = CatalogEntry::from_call(&call).unwrap();
        let entry_bytes = entry.encode().unwrap();
        let page_request = CatalogPageRequest {
            catalog: target(),
            namespace: "apps".into(),
            after: None,
            limit: 1,
        };
        let page = CatalogPage {
            catalog: target(),
            namespace: "apps".into(),
            entries: vec![entry.clone()],
            next: None,
        };
        let page_bytes = page.encode().unwrap();

        assert_eq!(
            CatalogMutationRequest::decode(&request_bytes).unwrap(),
            call.request
        );
        assert_eq!(CatalogMutationCall::decode(&call_bytes).unwrap(), call);
        assert_eq!(
            CatalogMutationResult::decode(&result_bytes).unwrap(),
            result
        );
        assert_eq!(CatalogEntry::decode(&entry_bytes).unwrap(), entry);
        assert_eq!(
            CatalogPageRequest::decode(&page_request.encode().unwrap()).unwrap(),
            page_request
        );
        assert_eq!(CatalogPage::decode(&page_bytes).unwrap(), page);
        assert!(request_bytes.len() <= MAX_CATALOG_MUTATION_REQUEST_WIRE_BYTES);
        assert!(call_bytes.len() <= MAX_CATALOG_MUTATION_CALL_WIRE_BYTES);
        assert!(entry_bytes.len() <= MAX_CATALOG_ENTRY_WIRE_BYTES);
        assert!(page_bytes.len() <= MAX_CATALOG_PAGE_WIRE_BYTES);
        assert_eq!(
            call.request.commitment(),
            Hash::digest(b"vos/agent/catalog-mutation-request/v1", &[&request_bytes])
        );

        assert_eq!(
            Hash::digest(b"vos/catalog/test/golden/request", &[&request_bytes]),
            Hash([
                77, 113, 169, 135, 54, 254, 146, 187, 120, 241, 91, 128, 110, 152, 239, 144, 19,
                128, 134, 178, 255, 83, 184, 74, 86, 107, 55, 47, 46, 187, 96, 136,
            ])
        );
        assert_eq!(
            Hash::digest(b"vos/catalog/test/golden/call", &[&call_bytes]),
            Hash([
                83, 239, 187, 94, 101, 228, 166, 183, 7, 0, 31, 41, 26, 178, 249, 64, 45, 87, 79,
                231, 8, 56, 172, 58, 126, 37, 170, 39, 82, 28, 121, 195,
            ])
        );
        assert_eq!(
            Hash::digest(b"vos/catalog/test/golden/page", &[&page_bytes]),
            Hash([
                77, 87, 156, 200, 25, 171, 76, 252, 22, 192, 62, 138, 47, 162, 141, 156, 207, 191,
                53, 111, 93, 111, 158, 195, 202, 137, 23, 118, 191, 67, 24, 153,
            ])
        );
    }

    #[test]
    fn authority_and_context_are_exact_and_forgery_fails_closed() {
        let call = call(0x62, "shell");
        assert!(call.verify_at(target(), SLOT, &TestVerifier).is_ok());
        assert!(call.matches_invocation_context(&context(&call)));

        let mut forged = call.clone();
        forged.authority.signature[0] ^= 1;
        assert!(forged.verify_at(target(), SLOT, &TestVerifier).is_err());

        let mut wrong_signer = target();
        wrong_signer.authority.policy = Hash([0x99; 32]);
        assert!(call.verify_at(wrong_signer, SLOT, &TestVerifier).is_err());

        let mut wrong_context = context(&call);
        wrong_context.mode = MethodMode::Linear;
        assert!(!call.matches_invocation_context(&wrong_context));
        wrong_context = context(&call);
        wrong_context.origin.capability = Some(crate::CapabilityId([0x77; 32]));
        assert!(!call.matches_invocation_context(&wrong_context));
    }

    #[test]
    fn receipt_commitment_binds_all_catalog_targets_and_references() {
        let original = call(0x63, "notes");
        let mutations: Vec<fn(&mut CatalogMutationRequest)> = vec![
            |request| request.catalog.space.0[0] ^= 1,
            |request| request.publication.identity.space.0[0] ^= 1,
            |request| request.publication.identity.agent.0[0] ^= 1,
            |request| request.publication.identity.runtime_deployment.0[0] ^= 1,
            |request| request.publication.actor.0[0] ^= 1,
            |request| request.publication.actor_package.hash.0[0] ^= 1,
            |request| request.publication.content.hash.0[0] ^= 1,
            |request| request.alias.namespace.push('x'),
            |request| request.alias.name.push('x'),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed.request);
            assert_ne!(changed.request.commitment(), original.request.commitment());
            assert!(changed.validate_shape().is_err());
        }
    }

    #[test]
    fn local_private_and_invalid_names_are_not_catalog_messages() {
        for profile in [AgentProfile::Local, AgentProfile::Private] {
            let mut request = request(0x64, "private");
            request.publication = publication(profile);
            assert!(request.validate_shape().is_err());
            assert!(request.encode().is_err());
        }
        let mut request = request(0x65, "bad");
        request.alias.namespace = format!("{}x", "n".repeat(MAX_CATALOG_NAMESPACE_BYTES));
        assert!(request.validate_shape().is_err());
        request.alias.namespace = "apps".into();
        request.alias.name = "bad\0alias".into();
        assert!(request.validate_shape().is_err());
    }

    #[test]
    fn prior_abi_unknown_tags_trailing_and_oversized_pages_are_rejected() {
        let call = call(0x66, "viewer");
        let mut prior = call.encode().unwrap();
        prior[4] ^= 1;
        assert!(CatalogMutationCall::decode(&prior).is_err());

        let mut unknown = call.request.encode().unwrap();
        // Kind immediately precedes the fixed 369-byte publication suffix.
        let kind = unknown.len() - 369 - 1;
        unknown[kind] = 9;
        assert!(CatalogMutationRequest::decode(&unknown).is_err());

        let mut trailing = call.encode().unwrap();
        trailing.push(0);
        assert!(CatalogMutationCall::decode(&trailing).is_err());

        let mut hostile_namespace = call.request.encode().unwrap();
        let namespace = hostile_namespace
            .windows(8)
            .position(|window| window == [4, 0, 0, 0, b'a', b'p', b'p', b's'])
            .unwrap();
        hostile_namespace[namespace..namespace + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(CatalogMutationRequest::decode(&hostile_namespace).is_err());

        let entry = CatalogEntry::from_call(&call).unwrap();
        let valid_page = CatalogPage {
            catalog: target(),
            namespace: "apps".into(),
            entries: vec![entry.clone()],
            next: None,
        };
        let mut hostile_count = valid_page.encode().unwrap();
        // Header (36) + catalog target (424) + namespace frame (8).
        hostile_count[468..472]
            .copy_from_slice(&((MAX_CATALOG_PAGE_ENTRIES + 1) as u32).to_le_bytes());
        assert!(CatalogPage::decode(&hostile_count).is_err());

        let page = CatalogPage {
            catalog: target(),
            namespace: "apps".into(),
            entries: vec![entry; MAX_CATALOG_PAGE_ENTRIES + 1],
            next: None,
        };
        assert!(page.encode().is_err());
    }

    #[test]
    fn maximum_canonical_page_remains_inside_actor_reply_bound() {
        let namespace = "n".repeat(MAX_CATALOG_NAMESPACE_BYTES);
        let mut entries = Vec::new();
        for index in 0..MAX_CATALOG_PAGE_ENTRIES {
            let mut call = call(0x70 + index as u8, &format!("{index:02}"));
            call.request.alias.namespace = namespace.clone();
            call.request.alias.name =
                format!("{index:02}{}", "a".repeat(MAX_CATALOG_ALIAS_BYTES - 2));
            call.request.publication.actor_package.len = crate::MAX_CATALOG_ARTIFACT_BYTES;
            call.request.publication.content.len = crate::MAX_CATALOG_ARTIFACT_BYTES;
            resign(&mut call);
            entries.push(CatalogEntry::from_call(&call).unwrap());
        }
        let page = CatalogPage {
            catalog: target(),
            namespace,
            entries,
            next: None,
        };
        let bytes = page.encode().unwrap();
        assert!(bytes.len() <= crate::MAX_INVOCATION_REPLY_BYTES);
        assert_eq!(CatalogPage::decode(&bytes).unwrap(), page);
    }
}
