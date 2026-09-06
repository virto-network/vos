//! Clean portable system catalog for Shared Agents.
//!
//! Mutations accept only canonical CMC1 calls with guest-verified authority
//! receipts. State is a bounded grow-only operation set; visible aliases are
//! a deterministic projection and therefore converge under any delivery order.

#![cfg_attr(target_arch = "riscv64", no_std)]

use alloc::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use vos::agent_sdk::authority::{AgentAuthorityBinding, AuthorityIssuer, AuthorityVerifier};
use vos::agent_sdk::catalog::{
    CatalogActorTarget, CatalogEntry, CatalogMutationCall, CatalogMutationKind,
    CatalogMutationResult, CatalogPage, CatalogPageRequest, MAX_CATALOG_PAGE_ENTRIES,
};
use vos::agent_sdk::wire::{CanonicalWire as _, MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES};
use vos::agent_sdk::{
    ActorId, AgentId, DeploymentId, Hash, InvocationContext, MAX_INVOCATION_MESSAGE_BYTES,
    MAX_INVOCATION_REPLY_BYTES, MAX_RUNTIME_STATE_BYTES, PrincipalId, ProducerId, ProgramId,
    RUNTIME_ABI_ID, SpaceId,
};
use vos::prelude::*;

pub const SYSTEM_CATALOG_CONFIGURATION_MAGIC: [u8; 4] = *b"SCC1";
pub const MAX_CATALOG_OPERATIONS: usize = 256;
pub const MAX_RETAINED_CATALOG_WIRE_BYTES: usize = MAX_CATALOG_OPERATIONS
    * (MAX_INVOCATION_MESSAGE_BYTES + MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES);

const CONFIG_FIXED_FIELDS: usize = 13;
const CONFIG_ENCODED_BYTES: usize =
    SYSTEM_CATALOG_CONFIGURATION_MAGIC.len() + 32 + CONFIG_FIXED_FIELDS * 32 + 8;

const _: () = assert!(MAX_RETAINED_CATALOG_WIRE_BYTES < MAX_RUNTIME_STATE_BYTES);

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CatalogIssuerState {
    pub principal: [u8; 32],
    pub actor: [u8; 32],
    pub deployment: [u8; 32],
    pub program: [u8; 32],
    pub producer: [u8; 32],
}

impl CatalogIssuerState {
    fn sdk(self) -> AuthorityIssuer {
        AuthorityIssuer {
            principal: PrincipalId(self.principal),
            actor: ActorId(self.actor),
            deployment: DeploymentId(self.deployment),
            program: ProgramId(self.program),
            producer: ProducerId(self.producer),
        }
    }
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CatalogAuthorityState {
    pub policy: [u8; 32],
    pub issuer: CatalogIssuerState,
    pub public_key: [u8; 32],
    pub initial_epoch: u64,
}

impl CatalogAuthorityState {
    fn sdk(self) -> AgentAuthorityBinding {
        AgentAuthorityBinding {
            policy: Hash(self.policy),
            issuer: self.issuer.sdk(),
            public_key: self.public_key,
            initial_epoch: self.initial_epoch,
        }
    }
}

/// Immutable installation configuration. It is the trust decision against
/// which every self-describing authority receipt is checked.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SystemCatalogConfiguration {
    pub space: [u8; 32],
    pub system_agent: [u8; 32],
    pub system_runtime_deployment: [u8; 32],
    pub actor: [u8; 32],
    pub deployment: [u8; 32],
    pub program: [u8; 32],
    pub authority: CatalogAuthorityState,
}

impl SystemCatalogConfiguration {
    fn sdk(self) -> CatalogActorTarget {
        CatalogActorTarget {
            space: SpaceId(self.space),
            system_agent: AgentId(self.system_agent),
            system_runtime_deployment: DeploymentId(self.system_runtime_deployment),
            actor: ActorId(self.actor),
            deployment: DeploymentId(self.deployment),
            program: ProgramId(self.program),
            authority: self.authority.sdk(),
        }
    }

    pub fn is_valid(self) -> bool {
        self.sdk().is_valid()
            && VerifyingKey::from_bytes(&self.authority.public_key).is_ok_and(|key| !key.is_weak())
    }

    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONFIG_ENCODED_BYTES);
        bytes.extend_from_slice(&SYSTEM_CATALOG_CONFIGURATION_MAGIC);
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        bytes.extend_from_slice(&self.space);
        bytes.extend_from_slice(&self.system_agent);
        bytes.extend_from_slice(&self.system_runtime_deployment);
        bytes.extend_from_slice(&self.actor);
        bytes.extend_from_slice(&self.deployment);
        bytes.extend_from_slice(&self.program);
        bytes.extend_from_slice(&self.authority.policy);
        bytes.extend_from_slice(&self.authority.issuer.principal);
        bytes.extend_from_slice(&self.authority.issuer.actor);
        bytes.extend_from_slice(&self.authority.issuer.deployment);
        bytes.extend_from_slice(&self.authority.issuer.program);
        bytes.extend_from_slice(&self.authority.issuer.producer);
        bytes.extend_from_slice(&self.authority.public_key);
        bytes.extend_from_slice(&self.authority.initial_epoch.to_le_bytes());
        bytes
    }

    /// Decode exactly SCC1+r8. There is no prior-generation or legacy path.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CONFIG_ENCODED_BYTES
            || bytes.get(..4) != Some(SYSTEM_CATALOG_CONFIGURATION_MAGIC.as_slice())
            || bytes.get(4..36) != Some(RUNTIME_ABI_ID.as_bytes().as_slice())
        {
            return None;
        }
        let mut cursor = 36;
        let value = Self {
            space: take_fixed(bytes, &mut cursor)?,
            system_agent: take_fixed(bytes, &mut cursor)?,
            system_runtime_deployment: take_fixed(bytes, &mut cursor)?,
            actor: take_fixed(bytes, &mut cursor)?,
            deployment: take_fixed(bytes, &mut cursor)?,
            program: take_fixed(bytes, &mut cursor)?,
            authority: CatalogAuthorityState {
                policy: take_fixed(bytes, &mut cursor)?,
                issuer: CatalogIssuerState {
                    principal: take_fixed(bytes, &mut cursor)?,
                    actor: take_fixed(bytes, &mut cursor)?,
                    deployment: take_fixed(bytes, &mut cursor)?,
                    program: take_fixed(bytes, &mut cursor)?,
                    producer: take_fixed(bytes, &mut cursor)?,
                },
                public_key: take_fixed(bytes, &mut cursor)?,
                initial_epoch: u64::from_le_bytes(
                    bytes.get(cursor..cursor.checked_add(8)?)?.try_into().ok()?,
                ),
            },
        };
        cursor += 8;
        (cursor == bytes.len() && value.is_valid()).then_some(value)
    }
}

fn take_fixed(bytes: &[u8], cursor: &mut usize) -> Option<[u8; 32]> {
    let value = bytes
        .get(*cursor..cursor.checked_add(32)?)?
        .try_into()
        .ok()?;
    *cursor += 32;
    Some(value)
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CatalogOperationState {
    pub invocation: [u8; 32],
    pub request: [u8; 32],
    pub mutation: [u8; 32],
    pub call: [u8; 32],
    pub call_bytes: Vec<u8>,
    pub reply_bytes: Vec<u8>,
}

#[actor(agent, state_version = 1)]
pub struct SystemCatalog {
    #[state(const)]
    configuration: SystemCatalogConfiguration,
    operations: crdt::Map<[u8; 32], CatalogOperationState>,
}

#[messages(agent)]
impl SystemCatalog {
    fn new(configuration: &[u8]) -> Self {
        let Some(configuration) = SystemCatalogConfiguration::decode(configuration) else {
            return Self {
                configuration: SystemCatalogConfiguration::default(),
                operations: crdt::Map::default(),
            };
        };
        Self {
            configuration,
            operations: crdt::Map::default(),
        }
    }

    /// Accept exactly one canonical signed Merge operation. Denials return an
    /// empty byte string and do not mutate replicated state.
    #[msg(merge)]
    fn mutate(&mut self, call: Vec<u8>, ctx: &mut Context<Self>) -> Vec<u8> {
        let Some(context) = ctx.agent_invocation_context().copied() else {
            return Vec::new();
        };
        apply_catalog_mutation(&self.configuration, &mut self.operations, &call, &context)
    }

    /// Return one stable alias-name page. Invalid requests or state fail
    /// closed with an empty byte string.
    #[msg(query)]
    fn page(&self, request: Vec<u8>) -> Vec<u8> {
        catalog_page(&self.configuration, &self.operations, &request)
    }
}

struct Ed25519AuthorityVerifier;

impl AuthorityVerifier for Ed25519AuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        if verifying_key.is_weak() {
            return false;
        }
        verifying_key
            .verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}

fn apply_catalog_mutation(
    configuration: &SystemCatalogConfiguration,
    operations: &mut crdt::Map<[u8; 32], CatalogOperationState>,
    encoded_call: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    if encoded_call.is_empty()
        || encoded_call.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !catalog_state_is_valid(configuration, operations)
    {
        return Vec::new();
    }
    let Ok(call) = CatalogMutationCall::decode(encoded_call) else {
        return Vec::new();
    };
    let target = configuration.sdk();
    if call.request.catalog != target || !call.matches_invocation_context(context) {
        return Vec::new();
    }
    let key = call.request.invocation.0;
    if let Some(record) = operations.get(&key) {
        return if operations.conflicts(&key).next().is_none()
            && record.call_bytes.as_slice() == encoded_call
        {
            record.reply_bytes.clone()
        } else {
            Vec::new()
        };
    }
    if operations.len() >= MAX_CATALOG_OPERATIONS
        || call
            .verify_at(target, context.observed_slot, &Ed25519AuthorityVerifier)
            .is_err()
    {
        return Vec::new();
    }
    let Ok(result) = CatalogMutationResult::from_call(&call) else {
        return Vec::new();
    };
    let Ok(reply_bytes) = result.encode() else {
        return Vec::new();
    };
    if reply_bytes.len() > MAX_INVOCATION_REPLY_BYTES {
        return Vec::new();
    }
    let record = CatalogOperationState {
        invocation: key,
        request: result.request.0,
        mutation: result.mutation.0,
        call: result.call.0,
        call_bytes: encoded_call.to_vec(),
        reply_bytes: reply_bytes.clone(),
    };
    if operations.insert(key, record).is_err() {
        return Vec::new();
    }
    reply_bytes
}

fn catalog_state_is_valid(
    configuration: &SystemCatalogConfiguration,
    operations: &crdt::Map<[u8; 32], CatalogOperationState>,
) -> bool {
    configuration.is_valid()
        && operations.len() <= MAX_CATALOG_OPERATIONS
        && operations.iter().all(|(key, record)| {
            if *key == [0; 32]
                || operations.conflicts(key).next().is_some()
                || record.invocation != *key
                || record.request == [0; 32]
                || record.mutation == [0; 32]
                || record.call == [0; 32]
                || record.call_bytes.is_empty()
                || record.call_bytes.len() > MAX_INVOCATION_MESSAGE_BYTES
                || record.reply_bytes.is_empty()
                || record.reply_bytes.len() > MAX_INVOCATION_REPLY_BYTES
            {
                return false;
            }
            let Ok(call) = CatalogMutationCall::decode(&record.call_bytes) else {
                return false;
            };
            let Ok(result) = CatalogMutationResult::decode(&record.reply_bytes) else {
                return false;
            };
            call.request.invocation.0 == *key
                && call.request.catalog == configuration.sdk()
                && result.matches_call(&call)
                && record.request == result.request.0
                && record.mutation == result.mutation.0
                && record.call == result.call.0
                // Stored evidence remains cryptographically inspectable after
                // its acceptance window closes; validate at its own valid_from.
                && call
                    .verify_at(
                        configuration.sdk(),
                        call.authority.selector.valid_from,
                        &Ed25519AuthorityVerifier,
                    )
                    .is_ok()
        })
}

type CatalogPrecedence = (u64, [u8; 32], [u8; 32]);

fn catalog_page(
    configuration: &SystemCatalogConfiguration,
    operations: &crdt::Map<[u8; 32], CatalogOperationState>,
    encoded_request: &[u8],
) -> Vec<u8> {
    if encoded_request.is_empty()
        || encoded_request.len() > MAX_INVOCATION_MESSAGE_BYTES
        || !catalog_state_is_valid(configuration, operations)
    {
        return Vec::new();
    }
    let Ok(request) = CatalogPageRequest::decode(encoded_request) else {
        return Vec::new();
    };
    let target = configuration.sdk();
    if request.catalog != target {
        return Vec::new();
    }

    let mut winners: BTreeMap<String, (CatalogPrecedence, CatalogMutationCall)> = BTreeMap::new();
    for (_, record) in operations.iter() {
        let Ok(call) = CatalogMutationCall::decode(&record.call_bytes) else {
            return Vec::new();
        };
        if call.request.alias.namespace != request.namespace {
            continue;
        }
        let precedence = (
            call.request.generation.get(),
            call.request.mutation_commitment().0,
            call.commitment().0,
        );
        let alias = call.request.alias.name.clone();
        let replace = winners
            .get(&alias)
            .is_none_or(|(current, _)| precedence > *current);
        if replace {
            winners.insert(alias, (precedence, call));
        }
    }

    let limit = usize::from(request.limit).min(MAX_CATALOG_PAGE_ENTRIES);
    let mut entries = Vec::with_capacity(limit);
    let mut has_more = false;
    for (alias, (_, call)) in winners {
        if request.after.as_ref().is_some_and(|after| alias <= *after)
            || call.request.kind == CatalogMutationKind::Withdraw
        {
            continue;
        }
        if entries.len() == limit {
            has_more = true;
            break;
        }
        let Ok(entry) = CatalogEntry::from_call(&call) else {
            return Vec::new();
        };
        entries.push(entry);
    }
    let next = has_more
        .then(|| entries.last().map(|entry| entry.request.alias.name.clone()))
        .flatten();
    let page = CatalogPage {
        catalog: target,
        namespace: request.namespace,
        entries,
        next,
    };
    page.encode().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::format;
    use alloc::vec;
    use core::num::NonZeroU64;

    use ed25519_dalek::{Signer as _, SigningKey};
    use vos::Message;
    use vos::abi::service::ServiceId;
    use vos::agent::StateLane;
    use vos::agent_sdk::InvocationId as AgentInvocationId;
    use vos::agent_sdk::authority::{
        AuthorityEvidence, AuthorityLaneRoots, AuthorityOperationKind, AuthorityReceipt,
        AuthorityReceiptSelector,
    };
    use vos::agent_sdk::catalog::{CatalogAlias, CatalogPublication};
    use vos::agent_sdk::{
        AgentIdentity, AgentProfile, BlobRef, InvocationOrigin, InvocationRoleClaims, MethodMode,
    };

    const OBSERVED_SLOT: u64 = 100;

    fn signing() -> SigningKey {
        SigningKey::from_bytes(&[0x71; 32])
    }

    fn configuration() -> SystemCatalogConfiguration {
        let public_key = signing().verifying_key().to_bytes();
        SystemCatalogConfiguration {
            space: [0x11; 32],
            system_agent: [0x12; 32],
            system_runtime_deployment: [0x13; 32],
            actor: [0x14; 32],
            deployment: [0x15; 32],
            program: [0x16; 32],
            authority: CatalogAuthorityState {
                policy: [0x21; 32],
                issuer: CatalogIssuerState {
                    principal: [0x22; 32],
                    actor: [0x23; 32],
                    deployment: [0x24; 32],
                    program: [0x25; 32],
                    producer: ProducerId::of_public_key(&public_key).0,
                },
                public_key,
                initial_epoch: 7,
            },
        }
    }

    fn actor() -> SystemCatalog {
        SystemCatalog::new(&configuration().encode())
    }

    fn invocation(index: u64) -> AgentInvocationId {
        AgentInvocationId(
            Hash::digest(
                b"vos/system-catalog/test-invocation",
                &[&index.to_le_bytes()],
            )
            .0,
        )
    }

    fn blob(byte: u8) -> BlobRef {
        BlobRef {
            hash: Hash([byte; 32]),
            len: u64::from(byte) + 1,
        }
    }

    fn publication(content: u8, profile: AgentProfile) -> CatalogPublication {
        CatalogPublication {
            identity: AgentIdentity {
                space: SpaceId(configuration().space),
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
            actor_package: blob(0x49),
            content: blob(content),
        }
    }

    fn resign(call: &mut CatalogMutationCall) {
        call.authority.selector.request = call.request.commitment();
        call.authority.signature = [1; 64];
        call.authority.signature = signing().sign(&call.authority.signing_bytes()).to_bytes();
    }

    fn call(
        invocation: AgentInvocationId,
        namespace: &str,
        alias: &str,
        generation: u64,
        kind: CatalogMutationKind,
        content: u8,
    ) -> CatalogMutationCall {
        let config = configuration();
        let request = vos::agent_sdk::catalog::CatalogMutationRequest {
            invocation,
            catalog: config.sdk(),
            alias: CatalogAlias {
                namespace: namespace.into(),
                name: alias.into(),
            },
            generation: NonZeroU64::new(generation).unwrap(),
            kind,
            publication: publication(content, AgentProfile::Shared),
        };
        let mut call = CatalogMutationCall {
            authority: AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: config.authority.sdk().policy,
                    issuer: config.authority.sdk().issuer,
                    space: request.publication.identity.space,
                    agent: request.publication.identity.agent,
                    operation: AuthorityOperationKind::PublishCatalog,
                    runtime_deployment: request.publication.identity.runtime_deployment,
                    actor: None,
                    actor_deployment: None,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: Hash([0x51; 32]),
                    },
                    lane_roots: AuthorityLaneRoots {
                        control: Some(Hash([0x52; 32])),
                        linear: Some(Hash([0x53; 32])),
                        merge: Some(Hash([0x54; 32])),
                        local: None,
                    },
                    epoch: 9,
                    decision_sequence: 0,
                    acknowledged_through: 0,
                    valid_from: 90,
                    expires_at: 120,
                    request: request.commitment(),
                },
                public_key: config.authority.public_key,
                signature: [1; 64],
            },
            request,
        };
        resign(&mut call);
        call
    }

    fn context(call: &CatalogMutationCall, observed_slot: u64) -> InvocationContext {
        InvocationContext {
            invocation: call.request.invocation,
            actor: call.request.catalog.actor,
            mode: MethodMode::Merge,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            observed_slot,
        }
    }

    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut context = core::task::Context::from_waker(waker);
        let mut future = core::pin::pin!(future);
        loop {
            if let core::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn dispatch_bytes(
        actor: &mut SystemCatalog,
        bytes: Vec<u8>,
        invocation_context: InvocationContext,
    ) -> Vec<u8> {
        let mut ctx = Context::new(ServiceId(0));
        ctx.__set_agent_invocation_context(invocation_context);
        crdt::with_change(crdt::ChangeId(invocation_context.invocation.0), || {
            Ok(block_on(<SystemCatalog as Message<Mutate>>::handle(
                actor,
                Mutate { call: bytes },
                &mut ctx,
            )))
        })
        .unwrap()
    }

    fn dispatch(actor: &mut SystemCatalog, call: &CatalogMutationCall) -> Vec<u8> {
        dispatch_bytes(
            actor,
            call.encode().expect("valid CMC1 fixture"),
            context(call, OBSERVED_SLOT),
        )
    }

    fn query(
        actor: &SystemCatalog,
        namespace: &str,
        after: Option<&str>,
        limit: u16,
    ) -> CatalogPage {
        let request = CatalogPageRequest {
            catalog: configuration().sdk(),
            namespace: namespace.into(),
            after: after.map(Into::into),
            limit,
        };
        let bytes = catalog_page(
            &actor.configuration,
            &actor.operations,
            &request.encode().unwrap(),
        );
        CatalogPage::decode(&bytes).expect("valid CAP1 reply")
    }

    fn operation_state(call: &CatalogMutationCall) -> CatalogOperationState {
        let result = CatalogMutationResult::from_call(call).unwrap();
        CatalogOperationState {
            invocation: call.request.invocation.0,
            request: result.request.0,
            mutation: result.mutation.0,
            call: result.call.0,
            call_bytes: call.encode().unwrap(),
            reply_bytes: result.encode().unwrap(),
        }
    }

    #[test]
    fn constructor_is_exact_r8_and_has_no_fallback() {
        let config = configuration();
        let bytes = config.encode();
        assert_eq!(SystemCatalogConfiguration::decode(&bytes), Some(config));

        let mut prior = bytes.clone();
        prior[4] ^= 1;
        assert!(SystemCatalogConfiguration::decode(&prior).is_none());
        let mut old_magic = bytes.clone();
        old_magic[..4].copy_from_slice(b"SCC0");
        assert!(SystemCatalogConfiguration::decode(&old_magic).is_none());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(SystemCatalogConfiguration::decode(&trailing).is_none());

        // A small-order Ed25519 point is structurally decodable and can be
        // made to satisfy the producer-id relation, but must never become an
        // authority trust anchor.
        let mut weak_key = [0; 32];
        weak_key[0] = 1;
        assert!(VerifyingKey::from_bytes(&weak_key).is_ok_and(|key| key.is_weak()));
        let mut weak = config;
        weak.authority.public_key = weak_key;
        weak.authority.issuer.producer = ProducerId::of_public_key(&weak_key).0;
        assert!(weak.sdk().is_valid());
        assert!(!weak.is_valid());
        assert!(SystemCatalogConfiguration::decode(&weak.encode()).is_none());
    }

    #[test]
    fn signed_shared_mutation_retries_byte_identically_after_expiry() {
        let mut actor = actor();
        let call = call(
            invocation(1),
            "apps",
            "editor",
            1,
            CatalogMutationKind::Publish,
            0x61,
        );
        let first = dispatch(&mut actor, &call);
        assert!(!first.is_empty());
        assert!(
            CatalogMutationResult::decode(&first)
                .unwrap()
                .matches_call(&call)
        );
        let state = <SystemCatalog as vos::Actor>::__save_agent_lane(&actor, StateLane::Merge);

        let retry = dispatch_bytes(
            &mut actor,
            call.encode().unwrap(),
            context(&call, call.authority.selector.expires_at + 1),
        );
        assert_eq!(retry, first);
        assert_eq!(
            <SystemCatalog as vos::Actor>::__save_agent_lane(&actor, StateLane::Merge),
            state
        );

        let mut restarted = <SystemCatalog as vos::Actor>::__load_agent_state(
            Some(&configuration().encode()),
            None,
            Some(&state),
            None,
        )
        .expect("valid durable Merge restart");
        assert_eq!(dispatch(&mut restarted, &call), first);
    }

    #[test]
    fn forged_mismatched_and_non_shared_calls_never_mutate() {
        let base = call(
            invocation(2),
            "apps",
            "terminal",
            1,
            CatalogMutationKind::Publish,
            0x62,
        );
        let mut forged = base.clone();
        forged.authority.signature[0] ^= 1;
        let mut catalog_actor = actor();
        let before = catalog_actor.encode();
        assert!(
            dispatch_bytes(
                &mut catalog_actor,
                forged.encode().unwrap(),
                context(&forged, OBSERVED_SLOT)
            )
            .is_empty()
        );
        assert_eq!(catalog_actor.encode(), before);

        let mut mismatched_namespace = base.clone();
        mismatched_namespace.request.alias.namespace = "other".into();
        assert!(mismatched_namespace.encode().is_err());
        let mut mismatched_package = base.clone();
        mismatched_package.request.publication.actor_package.hash.0[0] ^= 1;
        assert!(mismatched_package.encode().is_err());
        let mut mismatched_agent = base.clone();
        mismatched_agent.authority.selector.agent.0[0] ^= 1;
        assert!(mismatched_agent.encode().is_err());

        for profile in [AgentProfile::Local, AgentProfile::Private] {
            let mut value = base.clone();
            value.request.publication = publication(0x63, profile);
            assert!(value.encode().is_err());
        }

        let mut wrong_catalog = base.clone();
        wrong_catalog.request.catalog.actor = ActorId([0x99; 32]);
        resign(&mut wrong_catalog);
        let mut actor = actor();
        assert!(
            dispatch_bytes(
                &mut actor,
                wrong_catalog.encode().unwrap(),
                context(&wrong_catalog, OBSERVED_SLOT),
            )
            .is_empty()
        );
        assert!(actor.operations.is_empty());
    }

    #[test]
    fn same_invocation_different_bytes_is_rejected_without_mutation() {
        let mut actor = actor();
        let original = call(
            invocation(3),
            "apps",
            "mail",
            1,
            CatalogMutationKind::Publish,
            0x64,
        );
        assert!(!dispatch(&mut actor, &original).is_empty());
        let before = actor.encode();

        let conflict = call(
            original.request.invocation,
            "apps",
            "calendar",
            1,
            CatalogMutationKind::Publish,
            0x65,
        );
        assert!(dispatch(&mut actor, &conflict).is_empty());
        assert_eq!(actor.encode(), before);
    }

    #[test]
    fn stale_reordered_duplicate_and_withdrawal_projection_is_stable() {
        let high = call(
            invocation(4),
            "apps",
            "editor",
            9,
            CatalogMutationKind::Publish,
            0x70,
        );
        let stale = call(
            invocation(5),
            "apps",
            "editor",
            2,
            CatalogMutationKind::Publish,
            0x71,
        );
        let withdraw = call(
            invocation(6),
            "apps",
            "editor",
            10,
            CatalogMutationKind::Withdraw,
            0x70,
        );
        let mut actor = actor();
        assert!(!dispatch(&mut actor, &high).is_empty());
        let stale_reply = dispatch(&mut actor, &stale);
        assert!(!stale_reply.is_empty());
        assert_eq!(
            query(&actor, "apps", None, 4).entries[0].request,
            high.request
        );
        assert_eq!(dispatch(&mut actor, &stale), stale_reply);
        assert!(!dispatch(&mut actor, &withdraw).is_empty());
        assert!(query(&actor, "apps", None, 4).entries.is_empty());
    }

    #[test]
    fn concurrent_operations_converge_in_opposite_merge_order() {
        let left_call = call(
            invocation(7),
            "apps",
            "browser",
            4,
            CatalogMutationKind::Publish,
            0x72,
        );
        let right_call = call(
            invocation(8),
            "apps",
            "browser",
            4,
            CatalogMutationKind::Publish,
            0x73,
        );
        let mut left = actor();
        let mut right = actor();
        assert!(!dispatch(&mut left, &left_call).is_empty());
        assert!(!dispatch(&mut right, &right_call).is_empty());

        let mut left_first = actor();
        <SystemCatalog as vos::Actor>::__merge_crdt(&mut left_first, &left).unwrap();
        <SystemCatalog as vos::Actor>::__merge_crdt(&mut left_first, &right).unwrap();
        let mut right_first = actor();
        <SystemCatalog as vos::Actor>::__merge_crdt(&mut right_first, &right).unwrap();
        <SystemCatalog as vos::Actor>::__merge_crdt(&mut right_first, &left).unwrap();

        let left_page = query(&left_first, "apps", None, 4);
        let right_page = query(&right_first, "apps", None, 4);
        assert_eq!(left_page, right_page);
        let expected = if (
            left_call.request.mutation_commitment().0,
            left_call.commitment().0,
        ) > (
            right_call.request.mutation_commitment().0,
            right_call.commitment().0,
        ) {
            left_call.request
        } else {
            right_call.request
        };
        assert_eq!(left_page.entries[0].request, expected);
    }

    #[test]
    fn conflicting_full_invocation_ids_make_merge_fail_closed() {
        let invocation = invocation(9);
        let first = call(
            invocation,
            "apps",
            "one",
            1,
            CatalogMutationKind::Publish,
            0x74,
        );
        let second = call(
            invocation,
            "apps",
            "two",
            1,
            CatalogMutationKind::Publish,
            0x75,
        );
        let mut left = actor();
        let mut right = actor();
        assert!(!dispatch(&mut left, &first).is_empty());
        assert!(!dispatch(&mut right, &second).is_empty());
        assert!(<SystemCatalog as vos::Actor>::__merge_crdt(&mut left, &right).is_err());
    }

    #[test]
    fn duplicate_concurrent_delivery_is_idempotent() {
        let call = call(
            invocation(10),
            "apps",
            "duplicate",
            1,
            CatalogMutationKind::Publish,
            0x77,
        );
        let mut left = actor();
        let mut right = actor();
        let left_reply = dispatch(&mut left, &call);
        let right_reply = dispatch(&mut right, &call);
        assert_eq!(left_reply, right_reply);
        <SystemCatalog as vos::Actor>::__merge_crdt(&mut left, &right).unwrap();
        assert_eq!(left.operations.len(), 1);
        assert_eq!(query(&left, "apps", None, 4).entries.len(), 1);
        assert_eq!(dispatch(&mut left, &call), left_reply);
    }

    #[test]
    fn pagination_is_sorted_stable_and_exclusive() {
        let mut actor = actor();
        for (index, alias) in ["echo", "alpha", "delta", "bravo", "charlie"]
            .into_iter()
            .enumerate()
        {
            let call = call(
                invocation(20 + index as u64),
                "tools",
                alias,
                1,
                CatalogMutationKind::Publish,
                0x80 + index as u8,
            );
            assert!(!dispatch(&mut actor, &call).is_empty());
        }
        let first = query(&actor, "tools", None, 2);
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| entry.request.alias.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "bravo"]
        );
        assert_eq!(first.next.as_deref(), Some("bravo"));
        let second = query(&actor, "tools", first.next.as_deref(), 2);
        assert_eq!(
            second
                .entries
                .iter()
                .map(|entry| entry.request.alias.name.as_str())
                .collect::<Vec<_>>(),
            vec!["charlie", "delta"]
        );
        assert_eq!(second.next.as_deref(), Some("delta"));
        let last = query(&actor, "tools", second.next.as_deref(), 2);
        assert_eq!(last.entries[0].request.alias.name, "echo");
        assert_eq!(last.next, None);
    }

    #[test]
    fn operation_and_state_bounds_fail_closed() {
        let mut actor = actor();
        for index in 0..MAX_CATALOG_OPERATIONS {
            let call = call(
                invocation(1_000 + index as u64),
                "bounded",
                &format!("entry-{index:03}"),
                1,
                CatalogMutationKind::Publish,
                (index % 200 + 1) as u8,
            );
            actor
                .operations
                .insert_with_id(
                    crdt::ChangeId(call.request.invocation.0).operation(0),
                    call.request.invocation.0,
                    operation_state(&call),
                )
                .unwrap();
        }
        assert!(catalog_state_is_valid(
            &actor.configuration,
            &actor.operations
        ));
        assert!(
            <SystemCatalog as vos::Actor>::__save_agent_lane(&actor, StateLane::Merge).len()
                <= MAX_RUNTIME_STATE_BYTES
        );

        let overflow = call(
            invocation(9_999),
            "bounded",
            "overflow",
            1,
            CatalogMutationKind::Publish,
            0x76,
        );
        let before = actor.encode();
        assert!(dispatch(&mut actor, &overflow).is_empty());
        assert_eq!(actor.encode(), before);

        actor
            .operations
            .insert_with_id(
                crdt::ChangeId(overflow.request.invocation.0).operation(0),
                overflow.request.invocation.0,
                operation_state(&overflow),
            )
            .unwrap();
        assert!(!catalog_state_is_valid(
            &actor.configuration,
            &actor.operations
        ));
        let request = CatalogPageRequest {
            catalog: configuration().sdk(),
            namespace: "bounded".into(),
            after: None,
            limit: 1,
        };
        assert!(
            catalog_page(
                &actor.configuration,
                &actor.operations,
                &request.encode().unwrap()
            )
            .is_empty()
        );
    }
}
