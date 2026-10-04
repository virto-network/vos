//! Exact public Shared lifecycle inputs, never policy or genesis approval.

use crate::agent::clean_bootstrap::RawCredentialVerifier;
use crate::agent::clean_management_intent::CleanManagementIntent;
use crate::agent::package_admission::{AdmittedActorPackage, admit_actor_package};
use crate::agent::sdk::authority::AuthorityCredentialCall;
use crate::agent::sdk::wire::CanonicalWire as _;
use crate::agent::sdk::{AgentProfile, InstallActor, ManagementRequest};
use crate::service::wire::{DecodeError, Decoder, Encoder};

/// Exact signed completion of the coordinator's Create application. This is
/// not evidence that other members are admitted or a quorum is serving.
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedCreateApplication {
    acknowledgement: crate::agent::sdk::authority::ManagementApplicationAck,
    archive: crate::agent::genesis::AgentGenesisArchiveRecord,
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
impl SharedCreateApplication {
    pub fn acknowledgement(&self) -> &crate::agent::sdk::authority::ManagementApplicationAck {
        &self.acknowledgement
    }

    pub fn archive(&self) -> &crate::agent::genesis::AgentGenesisArchiveRecord {
        &self.archive
    }
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedCreateDisposition {
    Applied(SharedCreateApplication),
    Denied(super::SharedCreateDenial),
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
pub type SharedCreateResult =
    Result<SharedCreateDisposition, crate::agent::production_owner::AgentProductionOwnerError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedInstallDisposition {
    Applied(crate::agent::sdk::authority::ManagementApplicationAck),
    Denied(super::SharedInstallDenial),
    Failed(crate::agent::sdk::authority::ManagementApplicationFailure),
}

pub type SharedInstallResult =
    Result<SharedInstallDisposition, crate::agent::production_owner::AgentProductionOwnerError>;

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
use crate::agent::genesis::{AgentReplicaCommittee, MAX_AGENT_REPLICA_COMMITTEE_BYTES};
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
use crate::agent::package_admission::{AdmittedStateRuntimePackage, admit_state_runtime_package};
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
use crate::agent::sdk::AgentDescriptor;
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
use crate::service::wire::ServiceWire as _;

/// SCQ1 binds an exact signed Create, external-state runtime package and
/// canonical authenticated fixed-three roster. Successful decoding does not
/// establish Authority approval, replica readiness or permission to publish.
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
#[derive(Clone)]
pub struct SharedCreateSubmission {
    descriptor: AgentDescriptor,
    call: AuthorityCredentialCall,
    runtime: AdmittedStateRuntimePackage,
    committee: AgentReplicaCommittee,
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
impl SharedCreateSubmission {
    pub const MAX_BYTES: usize =
        super::LocalCreateSubmission::MAX_BYTES + 4 + MAX_AGENT_REPLICA_COMMITTEE_BYTES;

    const MAX_APPLICATION_RESPONSE_BYTES: usize = 13
        + crate::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
        + crate::agent::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES;

    pub const MAX_RESPONSE_BYTES: usize =
        if Self::MAX_APPLICATION_RESPONSE_BYTES > 9 + super::SharedCreateDenial::MAX_BYTES {
            Self::MAX_APPLICATION_RESPONSE_BYTES
        } else {
            9 + super::SharedCreateDenial::MAX_BYTES
        };

    pub fn verify_denial(&self, bytes: &[u8]) -> Result<super::SharedCreateDenial, DecodeError> {
        super::SharedCreateDenial::verify(&self.descriptor, &self.call, bytes)
    }

    /// Verify against independently retained request bytes. A valid signed
    /// ACK and archive prove only the claimed application, not cluster readiness.
    pub fn applied(
        &self,
        acknowledgement: crate::agent::sdk::authority::ManagementApplicationAck,
        archive: crate::agent::genesis::AgentGenesisArchiveRecord,
    ) -> Result<SharedCreateDisposition, DecodeError> {
        self.verify_application(&acknowledgement, &archive)?;
        Ok(SharedCreateDisposition::Applied(SharedCreateApplication {
            acknowledgement,
            archive,
        }))
    }

    fn verify_application(
        &self,
        acknowledgement: &crate::agent::sdk::authority::ManagementApplicationAck,
        archive: &crate::agent::genesis::AgentGenesisArchiveRecord,
    ) -> Result<(), DecodeError> {
        let request = ManagementRequest::Create(Box::new(self.descriptor.clone()));
        verify_application_ack(&self.call, &request, acknowledgement)?;
        let provision = archive.provision();
        provision
            .validate()
            .map_err(|_| DecodeError::NonCanonical)?;
        crate::agent::genesis::validate_agent_genesis_catalog(
            provision.proposal(),
            archive.catalog(),
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        let proposal = provision.proposal();
        let crate::agent::journal::ReplayOperation::CleanManage {
            request: created,
            authority: receipt,
            observed_slot,
        } = &proposal.create().operation
        else {
            return Err(DecodeError::NonCanonical);
        };
        if created != &request
            || receipt != &acknowledgement.receipt
            || *observed_slot != acknowledgement.applied_at
            || provision.replicas() != &self.committee
            || provision.evidence().claim().system_agent().0 != self.call.authority.system_agent.0
            || archive.catalog()[0].bytes != self.runtime.exact_bytes()
            || proposal.create().runtime
                != self
                    .runtime
                    .binding(proposal.locator().space, proposal.locator().agent)
                    .map_err(|_| DecodeError::NonCanonical)?
            || acknowledgement.application
                != crate::agent::sdk::ManagementReply::Created(self.descriptor.identity.clone())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub fn encode_response(
        &self,
        disposition: &SharedCreateDisposition,
    ) -> Result<Vec<u8>, DecodeError> {
        let mut bytes = b"SCR1".to_vec();
        let mut encoder = Encoder(&mut bytes);
        match disposition {
            SharedCreateDisposition::Applied(application) => {
                self.verify_application(&application.acknowledgement, &application.archive)?;
                encoder.u8(0); // Existing Applied bytes; explicitly not Ready.
                encoder.bytes(
                    &application
                        .acknowledgement
                        .encode()
                        .map_err(|_| DecodeError::NonCanonical)?,
                );
                encoder.bytes(&application.archive.encode());
            }
            SharedCreateDisposition::Denied(denial) => {
                self.verify_denial(denial.exact_bytes())?;
                encoder.u8(1);
                encoder.bytes(denial.exact_bytes());
            }
        }
        if bytes.len() > Self::MAX_RESPONSE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(bytes)
    }

    pub fn decode_response(&self, bytes: &[u8]) -> Result<SharedCreateDisposition, DecodeError> {
        let mut decoder = submission_decoder(bytes, b"SCR1", Self::MAX_RESPONSE_BYTES)?;
        match decoder.u8()? {
            0 => {}
            1 => {
                let denial = bounded_bytes(&mut decoder, super::SharedCreateDenial::MAX_BYTES)?;
                if !decoder.exhausted() {
                    return Err(DecodeError::TrailingBytes);
                }
                return self
                    .verify_denial(denial)
                    .map(SharedCreateDisposition::Denied);
            }
            _ => return Err(DecodeError::InvalidTag),
        }
        let acknowledgement = bounded_bytes(
            &mut decoder,
            crate::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
        )?;
        let archive = bounded_bytes(
            &mut decoder,
            crate::agent::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES,
        )?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        let acknowledgement =
            crate::agent::sdk::authority::ManagementApplicationAck::decode(acknowledgement)
                .map_err(|_| DecodeError::NonCanonical)?;
        let archive = crate::agent::genesis::AgentGenesisArchiveRecord::decode(archive)
            .map_err(|_| DecodeError::NonCanonical)?;
        self.applied(acknowledgement, archive)
    }

    pub fn new(
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedStateRuntimePackage,
        committee: AgentReplicaCommittee,
    ) -> Result<Self, DecodeError> {
        if !crate::agent::replay::external_shared_descriptor_supported(&descriptor)
            || descriptor.runtime_package != *runtime.package_ref()
            || descriptor.identity.runtime_deployment != runtime.deployment()
            || descriptor.identity.runtime_program != runtime.program()
            || descriptor.identity.runtime_producer != runtime.manifest().signing.producer
            || descriptor.runtime_contract != runtime.manifest().contract
            || descriptor.capabilities != runtime.manifest().capabilities
        {
            return Err(DecodeError::NonCanonical);
        }
        committee
            .validate_for_clean_descriptor(&descriptor)
            .map_err(|_| DecodeError::NonCanonical)?;
        verify_intent(
            ManagementRequest::Create(Box::new(descriptor.clone())),
            &call,
        )?;
        Ok(Self {
            descriptor,
            call,
            runtime,
            committee,
        })
    }

    pub fn descriptor(&self) -> &AgentDescriptor {
        &self.descriptor
    }
    pub fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }
    pub fn runtime(&self) -> &AdmittedStateRuntimePackage {
        &self.runtime
    }
    pub fn committee(&self) -> &AgentReplicaCommittee {
        &self.committee
    }
    pub(crate) fn has_transport_node_claim(&self) -> bool {
        self.call.authenticated_node.is_some()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"SCQ1".to_vec();
        let mut encoder = Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Create(Box::new(self.descriptor.clone()))
                .encode()
                .expect("validated Shared Create"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.runtime.exact_bytes());
        encoder.bytes(&self.committee.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = submission_decoder(bytes, b"SCQ1", Self::MAX_BYTES)?;
        let (request, call, package) = decode_inputs(&mut decoder)?;
        let committee = bounded_bytes(&mut decoder, MAX_AGENT_REPLICA_COMMITTEE_BYTES)?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        let ManagementRequest::Create(descriptor) = request else {
            return Err(DecodeError::NonCanonical);
        };
        let runtime =
            admit_state_runtime_package(package).map_err(|_| DecodeError::NonCanonical)?;
        let committee =
            AgentReplicaCommittee::decode(committee).map_err(|_| DecodeError::NonCanonical)?;
        Self::new(*descriptor, call, runtime, committee)
    }

    pub fn into_parts(
        self,
    ) -> (
        AgentDescriptor,
        AuthorityCredentialCall,
        AdmittedStateRuntimePackage,
        AgentReplicaCommittee,
    ) {
        (self.descriptor, self.call, self.runtime, self.committee)
    }
}

/// SIQ1 carries an exact signed Shared Install and admitted actor package.
/// It grants no runtime/lifecycle authority and does not assert availability.
#[derive(Clone)]
pub struct SharedInstallSubmission {
    install: InstallActor,
    call: AuthorityCredentialCall,
    package: AdmittedActorPackage,
}

impl SharedInstallSubmission {
    pub const MAX_BYTES: usize = super::LocalCreateSubmission::MAX_BYTES;

    const MAX_APPLICATION_BYTES: usize =
        if crate::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
            > crate::agent::sdk::authority::ManagementApplicationFailure::MAX_ENCODED_BYTES
        {
            crate::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
        } else {
            crate::agent::sdk::authority::ManagementApplicationFailure::MAX_ENCODED_BYTES
        };

    pub const MAX_RESPONSE_BYTES: usize =
        9 + if Self::MAX_APPLICATION_BYTES > super::SharedInstallDenial::MAX_BYTES {
            Self::MAX_APPLICATION_BYTES
        } else {
            super::SharedInstallDenial::MAX_BYTES
        };

    pub fn encode_response(
        &self,
        disposition: &SharedInstallDisposition,
    ) -> Result<Vec<u8>, DecodeError> {
        let (tag, payload) = match disposition {
            SharedInstallDisposition::Applied(acknowledgement) => {
                verify_application_ack(
                    &self.call,
                    &ManagementRequest::Install(Box::new(self.install.clone())),
                    acknowledgement,
                )?;
                (
                    0,
                    acknowledgement
                        .encode()
                        .map_err(|_| DecodeError::NonCanonical)?,
                )
            }
            SharedInstallDisposition::Denied(denial) => {
                super::SharedInstallDenial::verify(
                    &self.install,
                    &self.call,
                    denial.exact_bytes(),
                )?;
                (1, denial.exact_bytes().to_vec())
            }
            SharedInstallDisposition::Failed(failure) => {
                verify_application_failure(
                    &self.call,
                    &ManagementRequest::Install(Box::new(self.install.clone())),
                    failure,
                )?;
                (2, failure.encode().map_err(|_| DecodeError::NonCanonical)?)
            }
        };
        let mut bytes = b"SIR1".to_vec();
        let mut encoder = Encoder(&mut bytes);
        encoder.u8(tag);
        encoder.bytes(&payload);
        if bytes.len() > Self::MAX_RESPONSE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(bytes)
    }

    pub fn decode_response(&self, bytes: &[u8]) -> Result<SharedInstallDisposition, DecodeError> {
        let mut decoder = submission_decoder(bytes, b"SIR1", Self::MAX_RESPONSE_BYTES)?;
        let tag = decoder.u8()?;
        let limit = match tag {
            0 => crate::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES,
            1 => super::SharedInstallDenial::MAX_BYTES,
            2 => crate::agent::sdk::authority::ManagementApplicationFailure::MAX_ENCODED_BYTES,
            _ => return Err(DecodeError::InvalidTag),
        };
        let payload = bounded_bytes(&mut decoder, limit)?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        match tag {
            0 => {
                let acknowledgement =
                    crate::agent::sdk::authority::ManagementApplicationAck::decode(payload)
                        .map_err(|_| DecodeError::NonCanonical)?;
                verify_application_ack(
                    &self.call,
                    &ManagementRequest::Install(Box::new(self.install.clone())),
                    &acknowledgement,
                )?;
                Ok(SharedInstallDisposition::Applied(acknowledgement))
            }
            1 => Ok(SharedInstallDisposition::Denied(
                super::SharedInstallDenial::verify(&self.install, &self.call, payload)?,
            )),
            _ => {
                let failure =
                    crate::agent::sdk::authority::ManagementApplicationFailure::decode(payload)
                        .map_err(|_| DecodeError::NonCanonical)?;
                verify_application_failure(
                    &self.call,
                    &ManagementRequest::Install(Box::new(self.install.clone())),
                    &failure,
                )?;
                Ok(SharedInstallDisposition::Failed(failure))
            }
        }
    }

    pub fn new(
        install: InstallActor,
        call: AuthorityCredentialCall,
        package: AdmittedActorPackage,
    ) -> Result<Self, DecodeError> {
        if call.managed.profile != AgentProfile::Shared
            || install.package != *package.package_ref()
            || install.entry.deployment != package.deployment()
            || install.entry.program != package.program()
            || install.producer != package.producer()
        {
            return Err(DecodeError::NonCanonical);
        }
        install
            .validate_for_profile(AgentProfile::Shared)
            .map_err(|_| DecodeError::NonCanonical)?;
        verify_intent(ManagementRequest::Install(Box::new(install.clone())), &call)?;
        Ok(Self {
            install,
            call,
            package,
        })
    }

    pub fn install(&self) -> &InstallActor {
        &self.install
    }
    pub fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }
    pub fn package(&self) -> &AdmittedActorPackage {
        &self.package
    }
    pub(crate) fn has_transport_node_claim(&self) -> bool {
        self.call.authenticated_node.is_some()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"SIQ1".to_vec();
        let mut encoder = Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Install(Box::new(self.install.clone()))
                .encode()
                .expect("validated Shared Install"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.package.exact_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = submission_decoder(bytes, b"SIQ1", Self::MAX_BYTES)?;
        let (request, call, package) = decode_inputs(&mut decoder)?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        let ManagementRequest::Install(install) = request else {
            return Err(DecodeError::NonCanonical);
        };
        let package = admit_actor_package(package).map_err(|_| DecodeError::NonCanonical)?;
        Self::new(*install, call, package)
    }

    pub fn into_parts(self) -> (InstallActor, AuthorityCredentialCall, AdmittedActorPackage) {
        (self.install, self.call, self.package)
    }
}

fn verify_intent(
    request: ManagementRequest,
    call: &AuthorityCredentialCall,
) -> Result<(), DecodeError> {
    CleanManagementIntent::new(
        call.authority,
        call.managed,
        request,
        call.clone(),
        &RawCredentialVerifier,
    )
    .map(|_| ())
}

fn verify_application_ack(
    call: &AuthorityCredentialCall,
    request: &ManagementRequest,
    acknowledgement: &crate::agent::sdk::authority::ManagementApplicationAck,
) -> Result<(), DecodeError> {
    use crate::agent::sdk::authority::ManagementApproval;
    verify_intent(request.clone(), call)?;
    let selector = &acknowledgement.receipt.selector;
    let approval = ManagementApproval::from_call(
        call,
        acknowledgement.authorization_sequence,
        selector.evidence.clone(),
        selector.lane_roots,
        selector.epoch,
        selector.valid_from,
        selector.expires_at,
    )
    .map_err(|_| DecodeError::NonCanonical)?;
    if !acknowledgement.matches_pending(call, &approval)
        || acknowledgement.request != request.commitment()
        || acknowledgement.verify_with(&RawCredentialVerifier).is_err()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn verify_application_failure(
    call: &AuthorityCredentialCall,
    request: &ManagementRequest,
    failure: &crate::agent::sdk::authority::ManagementApplicationFailure,
) -> Result<(), DecodeError> {
    use crate::agent::sdk::authority::ManagementApproval;
    verify_intent(request.clone(), call)?;
    let selector = &failure.receipt.selector;
    let approval = ManagementApproval::from_call(
        call,
        failure.authorization_sequence,
        selector.evidence.clone(),
        selector.lane_roots,
        selector.epoch,
        selector.valid_from,
        selector.expires_at,
    )
    .map_err(|_| DecodeError::NonCanonical)?;
    if !failure.matches_pending(call, &approval)
        || failure.request != request.commitment()
        || failure.verify_with(&RawCredentialVerifier).is_err()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn submission_decoder<'a>(
    bytes: &'a [u8],
    magic: &[u8; 4],
    limit: usize,
) -> Result<Decoder<'a>, DecodeError> {
    if bytes.len() > limit {
        return Err(DecodeError::LimitExceeded);
    }
    if bytes.get(..4) != Some(magic.as_slice()) {
        return Err(DecodeError::InvalidTag);
    }
    Ok(Decoder::new(&bytes[4..]))
}

fn bounded_bytes<'a>(decoder: &mut Decoder<'a>, limit: usize) -> Result<&'a [u8], DecodeError> {
    let length = decoder.u32()? as usize;
    if length > limit {
        return Err(DecodeError::LimitExceeded);
    }
    decoder.take(length)
}

fn decode_inputs<'a>(
    decoder: &mut Decoder<'a>,
) -> Result<(ManagementRequest, AuthorityCredentialCall, &'a [u8]), DecodeError> {
    let request = bounded_bytes(
        decoder,
        crate::agent::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES,
    )?;
    let call = bounded_bytes(
        decoder,
        crate::agent::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES,
    )?;
    let package = bounded_bytes(
        decoder,
        crate::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES,
    )?;
    let request = ManagementRequest::decode(request).map_err(|_| DecodeError::NonCanonical)?;
    let call = AuthorityCredentialCall::decode(call).map_err(|_| DecodeError::NonCanonical)?;
    Ok((request, call, package))
}

#[cfg(all(
    test,
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
pub(crate) use tests::shared_submissions_for_test;

#[cfg(all(
    test,
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
mod tests {
    use super::*;
    use crate::agent::genesis::{AgentReplicaMember, derive_replica_raft_slot};
    use crate::agent::sdk;
    use core::num::NonZeroU64;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sdk::authority::{
        AgentAuthorityBinding, AuthorityActorTarget, AuthorityIssuer, ManagedAgentTarget,
    };
    use vos_pvm_compiler::assembler::Assembler;

    fn fixture() -> (
        AgentDescriptor,
        AdmittedStateRuntimePackage,
        AgentReplicaCommittee,
    ) {
        let key = SigningKey::from_bytes(&[0x81; 32]);
        let public = key.verifying_key().to_bytes();
        let owner = sdk::PrincipalId::of_public_key(&public);
        let space = sdk::SpaceId([0x82; 32]);
        let nonce = sdk::Hash([0x83; 32]);
        let agent = sdk::AgentId::derive(space, owner, nonce.as_bytes());
        let runtime = crate::agent::package_admission::tests::admitted_state_fixture_limits(
            Assembler::new().trap().build_standard(),
            sdk::LaneSet::of(sdk::StateLane::Linear),
            sdk::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES as u32,
        );
        let mut members = (0..3)
            .map(|index| {
                let public = SigningKey::from_bytes(&[0x90 + index; 32])
                    .verifying_key()
                    .to_bytes();
                let mut peer = vec![0, 0x24, 8, 1, 0x12, 0x20];
                peer.extend_from_slice(&public);
                AgentReplicaMember::new(
                    crate::agent::AgentReplica {
                        node: crate::service::NodeId::of_authenticated_peer(&peer),
                        principal: crate::service::PrincipalId(public),
                        role: crate::agent::ReplicaRole::Voter,
                    },
                    peer.clone(),
                    public,
                    Some(derive_replica_raft_slot(&peer)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.replica().node);
        let committee = AgentReplicaCommittee::new(
            crate::service::SpaceId(space.0),
            crate::service::AgentId(agent.0),
            crate::agent::AgentProfile::Shared,
            members,
        )
        .unwrap();
        let descriptor = AgentDescriptor {
            identity: sdk::AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.manifest().signing.producer,
                transition_producer: sdk::ProducerId::of_public_key(&public),
            },
            creation_nonce: nonce,
            authority: AgentAuthorityBinding {
                policy: sdk::Hash([0x84; 32]),
                issuer: AuthorityIssuer {
                    principal: owner,
                    actor: sdk::ActorId([0x85; 32]),
                    deployment: sdk::DeploymentId([0x86; 32]),
                    program: sdk::ProgramId([0x87; 32]),
                    producer: sdk::ProducerId::of_public_key(&public),
                },
                public_key: public,
                initial_epoch: 1,
            },
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.manifest().capabilities,
            replicas: committee
                .members()
                .iter()
                .map(|member| {
                    let replica = member.replica();
                    sdk::AgentReplica {
                        node: sdk::NodeId(replica.node.0),
                        principal: sdk::PrincipalId(replica.principal.0),
                        role: sdk::ReplicaRole::Voter,
                    }
                })
                .collect(),
        };
        (descriptor, runtime, committee)
    }

    fn call(descriptor: &AgentDescriptor, request: &ManagementRequest) -> AuthorityCredentialCall {
        let key = SigningKey::from_bytes(&[0x81; 32]);
        let public = key.verifying_key().to_bytes();
        let identity = &descriptor.identity;
        let mut call = AuthorityCredentialCall {
            invocation: sdk::InvocationId::ZERO,
            authority: AuthorityActorTarget {
                space: identity.space,
                system_agent: sdk::AgentId([0x88; 32]),
                system_runtime_deployment: sdk::DeploymentId([0x89; 32]),
                binding: descriptor.authority,
            },
            managed: ManagedAgentTarget {
                space: identity.space,
                agent: identity.agent,
                owner: identity.owner,
                profile: identity.profile,
                runtime_deployment: identity.runtime_deployment,
                transition_producer: identity.transition_producer,
            },
            principal: identity.owner,
            credential: sdk::CredentialId::of_public_key(&public),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key: public,
            authenticated_node: None,
            requested_valid_from: 10,
            requested_expires_at: 30,
            plan: request.authorization_plan().unwrap(),
            signature: [0; 64],
        };
        resign(&mut call);
        call
    }

    fn resign(call: &mut AuthorityCredentialCall) {
        call.invocation = call.expected_invocation();
        call.signature = SigningKey::from_bytes(&[0x81; 32])
            .sign(&call.signing_bytes())
            .to_bytes();
    }

    fn install_fixture(descriptor: &AgentDescriptor) -> (InstallActor, AdmittedActorPackage) {
        let package = crate::agent::package_admission::admitted_standard_actor_for_test(
            "shared-worker",
            sdk::StateLane::Linear,
            0x94,
        );
        let schema = sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        let entry = sdk::ActorEntry {
            actor: sdk::ActorId::top_level(descriptor.identity.agent, "shared-worker"),
            name: "shared-worker".into(),
            parent: None,
            deployment: package.deployment(),
            program: package.program(),
            package: package.package_ref().clone(),
            agent_schema: package.manifest().state_lane_schema.clone(),
            method_policy: package.manifest().method_policy.clone(),
            constructor_abi: schema.constructor_abi().unwrap(),
            installation_data: None,
            state_layout: schema.state_layout_hash().unwrap(),
            lanes: package.requirements().lanes,
            suspended: false,
        };
        let install = InstallActor {
            installation_id: sdk::InstallationId([0x95; 32]),
            registry_reservation: sdk::Hash([0x96; 32]),
            producer: package.producer(),
            package: entry.package.clone(),
            agent_schema: entry.agent_schema.clone(),
            method_policy: entry.method_policy.clone(),
            constructor_abi: entry.constructor_abi,
            installation_data: None,
            state_layout: entry.state_layout,
            entry,
            contract: package.manifest().contract,
            requirements: package.requirements(),
        };
        (install, package)
    }

    fn envelope(magic: &[u8; 4], fields: &[&[u8]]) -> Vec<u8> {
        let mut bytes = magic.to_vec();
        let mut encoder = Encoder(&mut bytes);
        for field in fields {
            encoder.bytes(field);
        }
        bytes
    }

    pub(crate) fn shared_submissions_for_test(
        transport_claim: bool,
    ) -> (SharedCreateSubmission, SharedInstallSubmission) {
        let (descriptor, runtime, committee) = fixture();
        let mut create_call = call(
            &descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        let (install, package) = install_fixture(&descriptor);
        let mut install_call = call(
            &descriptor,
            &ManagementRequest::Install(Box::new(install.clone())),
        );
        if transport_claim {
            create_call.authenticated_node = Some(descriptor.replicas[0].node);
            resign(&mut create_call);
            install_call.authenticated_node = Some(descriptor.replicas[0].node);
            resign(&mut install_call);
        }
        (
            SharedCreateSubmission::new(descriptor, create_call, runtime, committee).unwrap(),
            SharedInstallSubmission::new(install, install_call, package).unwrap(),
        )
    }

    fn install_ack(
        submission: &SharedInstallSubmission,
    ) -> sdk::authority::ManagementApplicationAck {
        use sdk::authority::*;
        let call = submission.call();
        let request = ManagementRequest::Install(Box::new(submission.install().clone()));
        let approval = ManagementApproval::from_call(
            call,
            NonZeroU64::new(2).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: sdk::Hash([0xa1; 32]),
            },
            AuthorityLaneRoots::default(),
            1,
            10,
            30,
        )
        .unwrap();
        let (actor, actor_deployment) = request
            .authority_actor()
            .map_or((None, None), |(actor, deployment)| {
                (Some(actor), Some(deployment))
            });
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: call.authority.binding.policy,
                issuer: call.authority.binding.issuer,
                space: call.managed.space,
                agent: call.managed.agent,
                operation: request.authority_operation().unwrap(),
                runtime_deployment: call.managed.runtime_deployment,
                actor,
                actor_deployment,
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: 1,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: 10,
                expires_at: 30,
                request: request.commitment(),
            },
            public_key: call.authority.binding.public_key,
            signature: [0; 64],
        };
        let key = SigningKey::from_bytes(&[0x81; 32]);
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        let mut acknowledgement = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: request.commitment(),
            receipt,
            application: sdk::ManagementReply::Installed(submission.install().entry.clone()),
            reopened_state: sdk::Hash([0xa2; 32]),
            applied_at: 10,
            signature: [0; 64],
        };
        acknowledgement.signature = key.sign(&acknowledgement.signing_bytes()).to_bytes();
        acknowledgement
    }

    fn create_denial_certificate(submission: &SharedCreateSubmission) -> Vec<u8> {
        use crate::agent::clean_management_intent::{
            CleanManagementIntentSlot, ManagementJournalAnchor,
        };
        struct Store(Vec<u8>);
        impl crate::agent::clean_authority_issuer::CleanManagementIssuerStore for Store {
            type Error = ();
            fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(Some(self.0.clone()))
            }
            fn commit(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
                self.0 = bytes.to_vec();
                Ok(())
            }
        }
        let call = submission.call();
        let intent = CleanManagementIntent::new(
            call.authority,
            call.managed,
            ManagementRequest::Create(Box::new(submission.descriptor().clone())),
            call.clone(),
            &RawCredentialVerifier,
        )
        .unwrap();
        let invocation = sdk::InvocationWork {
            space: call.authority.space,
            agent: call.authority.system_agent,
            runtime_deployment: call.authority.system_runtime_deployment,
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            incarnation: sdk::Hash([0xb1; 32]),
            deployment: call.authority.binding.issuer.deployment,
            program: call.authority.binding.issuer.program,
            mode: sdk::MethodMode::Linear,
            origin: intent.authorization_origin(),
            roles: sdk::InvocationRoleClaims::none(),
            message: intent.authorization_message(),
            installation_data: None,
            availability: vec![],
            gas: 1,
            recovery_only: false,
        };
        let authorization = sdk::InvocationAuthorization::PublicPreflight(
            sdk::PublicPreflight::for_work(&invocation, 10),
        );
        let work = sdk::RuntimeWork::Invoke {
            context: sdk::RuntimeExecutionContext::Direct,
            state: sdk::RuntimeState::default(),
            invocation: Box::new(invocation),
            authorization: Box::new(authorization),
            observed_slot: 10,
        };
        let mut slot = CleanManagementIntentSlot::open(Store(intent.encode())).unwrap();
        slot.pledge_authorization_work(
            work,
            ManagementJournalAnchor {
                genesis: crate::agent::journal::AgentJournalGenesisId([0xb2; 32]),
                admission: crate::agent::genesis::AgentGenesisAdmissionId::from_bytes([0xb3; 32]),
                runtime: crate::service::Hash([0xb4; 32]),
                ordered: crate::agent::journal::OrderedBase {
                    index: 0,
                    head: None,
                },
            },
        )
        .unwrap();
        // Signature/codec qualification only. The native denial restart tests
        // separately establish actual policy replay and retirement prerequisites.
        let key = SigningKey::from_bytes(&[0x81; 32]);
        slot.commit_denial(key.sign(&slot.denial_signing_bytes().unwrap()).to_bytes())
            .unwrap();
        slot.load_denial_certificate().unwrap().unwrap()
    }

    #[test]
    fn shared_create_signed_denial_binds_the_exact_retained_request_and_call() {
        let (create, install) = shared_submissions_for_test(false);
        let certificate = create_denial_certificate(&create);
        let disposition =
            SharedCreateDisposition::Denied(create.verify_denial(&certificate).unwrap());
        let response = create.encode_response(&disposition).unwrap();
        assert_eq!(&response[..5], b"SCR1\x01");
        assert_eq!(create.decode_response(&response).unwrap(), disposition);
        assert!(install.decode_response(&response).is_err());
        for index in [0, response.len() - 1] {
            let mut changed = response.clone();
            changed[index] ^= 1;
            assert!(create.decode_response(&changed).is_err());
        }
        for tag in [0, 2] {
            let mut changed = response.clone();
            changed[4] = tag;
            assert!(create.decode_response(&changed).is_err());
        }
        let mut trailing = response.clone();
        trailing.push(0);
        assert!(matches!(
            create.decode_response(&trailing),
            Err(DecodeError::TrailingBytes)
        ));
        let mut another_call = create.call().clone();
        another_call.request_sequence = NonZeroU64::new(2).unwrap();
        resign(&mut another_call);
        let another = SharedCreateSubmission::new(
            create.descriptor().clone(),
            another_call,
            create.runtime().clone(),
            create.committee().clone(),
        )
        .unwrap();
        assert!(another.verify_denial(&certificate).is_err());
        assert!(another.decode_response(&response).is_err());
        assert!(another.encode_response(&disposition).is_err());
        let mut descriptor = create.descriptor().clone();
        descriptor.replicas[0].principal = sdk::PrincipalId([0xb5; 32]);
        assert!(
            super::super::SharedCreateDenial::verify(&descriptor, create.call(), &certificate)
                .is_err()
        );
        assert!(create.decode_response(b"SCR1\x01\x04\0\0\0CND1").is_err());
    }

    #[test]
    fn shared_install_response_verifies_the_exact_retained_request_and_signatures() {
        let (create, install) = shared_submissions_for_test(false);
        let acknowledgement = install_ack(&install);
        let disposition = SharedInstallDisposition::Applied(acknowledgement.clone());
        let bytes = install.encode_response(&disposition).unwrap();
        assert_eq!(install.decode_response(&bytes).unwrap(), disposition);
        for index in [0, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(install.decode_response(&changed).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(matches!(
            install.decode_response(&changed),
            Err(DecodeError::TrailingBytes)
        ));
        let mut changed = bytes.clone();
        changed[4] = 3;
        assert!(matches!(
            install.decode_response(&changed),
            Err(DecodeError::InvalidTag)
        ));
        let mut another_call = install.call().clone();
        another_call.request_sequence = NonZeroU64::new(2).unwrap();
        resign(&mut another_call);
        let another = SharedInstallSubmission::new(
            install.install().clone(),
            another_call,
            install.package().clone(),
        )
        .unwrap();
        assert!(another.decode_response(&bytes).is_err());
        let mut changed = acknowledgement;
        changed.signature[0] ^= 1;
        assert!(
            install
                .encode_response(&SharedInstallDisposition::Applied(changed))
                .is_err()
        );
        assert!(create.decode_response(&bytes).is_err());
        assert!(create.decode_response(b"SCR1\x01").is_err());
        assert!(install.decode_response(b"SIR1\x01\x04\0\0\0CND1").is_err());
    }

    #[test]
    fn shared_install_signed_failure_is_distinct_exact_terminal_evidence() {
        let (_, submission) = shared_submissions_for_test(false);
        let ack = install_ack(&submission);
        let mut failure = sdk::authority::ManagementApplicationFailure {
            authorization_invocation: ack.authorization_invocation,
            acknowledgement_invocation: ack.acknowledgement_invocation,
            authority: ack.authority,
            managed: ack.managed,
            credential_call: ack.credential_call,
            approval: ack.approval,
            authorization_sequence: ack.authorization_sequence,
            request: ack.request,
            receipt: ack.receipt,
            error: sdk::ManagementError::AlreadyExists,
            reopened_state: ack.reopened_state,
            failed_at: ack.applied_at,
            signature: [0; 64],
        };
        let key = SigningKey::from_bytes(&[0x81; 32]);
        failure.signature = key.sign(&failure.signing_bytes()).to_bytes();
        let disposition = SharedInstallDisposition::Failed(failure.clone());
        let bytes = submission.encode_response(&disposition).unwrap();
        assert_eq!(bytes[4], 2);
        assert_eq!(submission.decode_response(&bytes).unwrap(), disposition);
        let mut changed = bytes.clone();
        changed[4] = 0;
        assert!(submission.decode_response(&changed).is_err());
        let mut changed = failure.clone();
        changed.signature[0] ^= 1;
        assert!(
            submission
                .encode_response(&SharedInstallDisposition::Failed(changed))
                .is_err()
        );
        let mut changed = failure.clone();
        changed.error = sdk::ManagementError::ResourceLimit;
        assert!(
            submission
                .encode_response(&SharedInstallDisposition::Failed(changed))
                .is_err()
        );
        // Expired-before-application receipts remain authenticated at their
        // final valid slot; the signed terminal must name an actual later slot.
        failure.error = sdk::ManagementError::ExpiredBeforeApplication;
        failure.failed_at = failure.receipt.selector.expires_at + 1;
        failure.signature = key.sign(&failure.signing_bytes()).to_bytes();
        let disposition = SharedInstallDisposition::Failed(failure.clone());
        let bytes = submission.encode_response(&disposition).unwrap();
        assert_eq!(submission.decode_response(&bytes).unwrap(), disposition);
        failure.failed_at -= 1;
        failure.signature = key.sign(&failure.signing_bytes()).to_bytes();
        assert!(
            submission
                .encode_response(&SharedInstallDisposition::Failed(failure))
                .is_err()
        );
    }

    #[test]
    fn shared_lifecycle_queue_retains_the_existing_capacity_and_closes_both_variants() {
        use crate::agent::local_lifecycle::{
            LOCAL_LIFECYCLE_QUEUE_CAPACITY, LocalLifecycleIngressError, LocalLifecycleQueue,
            PendingLocalLifecycle,
        };
        let (create, install) = shared_submissions_for_test(false);
        let queue = LocalLifecycleQueue::default();
        assert!(matches!(
            queue.submit_shared_create(create.clone(), false),
            Err(LocalLifecycleIngressError::Unavailable)
        ));
        assert!(matches!(
            queue.submit_shared_install(install.clone(), false),
            Err(LocalLifecycleIngressError::Unavailable)
        ));
        queue.open().unwrap();
        let create_reply = queue.submit_shared_create(create.clone(), true).unwrap();
        let mut install_replies = Vec::new();
        for _ in 1..LOCAL_LIFECYCLE_QUEUE_CAPACITY {
            install_replies.push(queue.submit_shared_install(install.clone(), true).unwrap());
        }
        assert!(matches!(
            queue.submit_shared_create(create.clone(), false),
            Err(LocalLifecycleIngressError::Busy)
        ));
        let PendingLocalLifecycle::CreateShared {
            submission,
            retained_only,
            reply,
        } = queue.pop().unwrap().unwrap()
        else {
            panic!("wrong queue variant");
        };
        assert_eq!(submission.encode(), create.encode());
        assert!(retained_only);
        let error = crate::agent::production_owner::AgentProductionOwnerError::InvalidConfiguration;
        reply.try_send(Err(error)).unwrap();
        assert_eq!(create_reply.recv().unwrap(), Err(error));
        let create_reply = queue.submit_shared_create(create, false).unwrap();
        let PendingLocalLifecycle::InstallShared {
            submission,
            retained_only,
            reply,
        } = queue.pop().unwrap().unwrap()
        else {
            panic!("wrong queue variant");
        };
        assert_eq!(submission.encode(), install.encode());
        assert!(retained_only);
        reply.try_send(Err(error)).unwrap();
        assert_eq!(install_replies.remove(0).recv().unwrap(), Err(error));
        // Dropping a caller does not cancel the already accepted operation.
        drop(install_replies.remove(0));
        queue.close();
        assert_eq!(create_reply.recv().unwrap(), Err(error));
        for receiver in install_replies {
            assert_eq!(receiver.recv().unwrap(), Err(error));
        }
        assert!(queue.pop().unwrap().is_none());
        assert!(matches!(
            queue.submit_shared_install(install, false),
            Err(LocalLifecycleIngressError::Unavailable)
        ));
    }

    #[cfg(feature = "network")]
    #[test]
    fn shared_lifecycle_ingress_refuses_both_variants_after_node_shutdown() {
        use crate::agent::local_lifecycle::LocalLifecycleIngressError;
        let (create, install) = shared_submissions_for_test(false);
        let node = crate::node::VosNode::new();
        let handle = node.ingress_handle();
        node.shutdown();
        assert!(matches!(
            handle.create_clean_shared_agent(create),
            Err(LocalLifecycleIngressError::Unavailable)
        ));
        assert!(matches!(
            handle.install_clean_shared_actor(install),
            Err(LocalLifecycleIngressError::Unavailable)
        ));
    }

    #[test]
    fn shared_create_submission_roundtrip_preserves_exact_signed_inputs() {
        let (descriptor, runtime, committee) = fixture();
        let signed = call(
            &descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        let submission = SharedCreateSubmission::new(
            descriptor.clone(),
            signed.clone(),
            runtime.clone(),
            committee.clone(),
        )
        .unwrap();
        assert_eq!(submission.descriptor(), &descriptor);
        assert_eq!(submission.call(), &signed);
        assert_eq!(submission.runtime().exact_bytes(), runtime.exact_bytes());
        assert_eq!(submission.committee(), &committee);
        assert!(!submission.has_transport_node_claim());
        let bytes = submission.encode();
        let decoded = SharedCreateSubmission::decode(&bytes).unwrap();
        assert_eq!(decoded.encode(), bytes);
        let (restored, signed_again, admitted, roster) = decoded.into_parts();
        assert_eq!(restored, descriptor);
        assert_eq!(signed_again, signed);
        assert_eq!(admitted.exact_bytes(), runtime.exact_bytes());
        assert_eq!(roster, committee);
    }

    #[test]
    fn shared_create_submission_rejects_request_roster_and_runtime_substitution() {
        let (descriptor, runtime, committee) = fixture();
        let signed = call(
            &descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        let mut changed = descriptor.clone();
        changed.replicas[0].principal.0[0] ^= 1;
        let resigned = call(
            &changed,
            &ManagementRequest::Create(Box::new(changed.clone())),
        );
        assert!(
            SharedCreateSubmission::new(changed, resigned, runtime.clone(), committee.clone())
                .is_err()
        );
        let mut changed = descriptor.clone();
        changed.capabilities.max_actors -= 1;
        let resigned = call(
            &changed,
            &ManagementRequest::Create(Box::new(changed.clone())),
        );
        assert!(
            SharedCreateSubmission::new(changed, resigned, runtime.clone(), committee.clone())
                .is_err()
        );
        let mut changed = descriptor.clone();
        changed.replicas.pop();
        let resigned = call(
            &changed,
            &ManagementRequest::Create(Box::new(changed.clone())),
        );
        assert!(
            SharedCreateSubmission::new(changed, resigned, runtime.clone(), committee.clone())
                .is_err()
        );
        let mut changed = descriptor.clone();
        changed.creation_nonce.0[0] ^= 1;
        assert!(
            SharedCreateSubmission::new(
                changed,
                signed.clone(),
                runtime.clone(),
                committee.clone()
            )
            .is_err()
        );
        let mut forged = signed.clone();
        forged.signature[0] ^= 1;
        assert!(
            SharedCreateSubmission::new(
                descriptor.clone(),
                forged,
                runtime.clone(),
                committee.clone()
            )
            .is_err()
        );
        let request = ManagementRequest::Create(Box::new(descriptor))
            .encode()
            .unwrap();
        let image = crate::agent::package_admission::admitted_runtime_program_for_test(
            "image-fixture",
            0x95,
            &Assembler::new().trap().build_standard(),
        );
        let bytes = envelope(
            b"SCQ1",
            &[
                &request,
                &signed.encode().unwrap(),
                image.exact_bytes(),
                &committee.encode(),
            ],
        );
        assert!(SharedCreateSubmission::decode(&bytes).is_err());
    }

    #[test]
    fn shared_submission_tags_truncation_and_trailing_data_are_strict() {
        let (descriptor, runtime, committee) = fixture();
        let signed = call(
            &descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        let bytes = SharedCreateSubmission::new(descriptor.clone(), signed, runtime, committee)
            .unwrap()
            .encode();
        for length in [0, 3, 4, bytes.len() - 1] {
            assert!(SharedCreateSubmission::decode(&bytes[..length]).is_err());
        }
        let mut changed = bytes.clone();
        changed.extend_from_slice(&[0]);
        assert!(matches!(
            SharedCreateSubmission::decode(&changed),
            Err(DecodeError::TrailingBytes)
        ));
        let mut changed = bytes;
        changed[..4].copy_from_slice(b"LCQ2");
        assert!(matches!(
            SharedCreateSubmission::decode(&changed),
            Err(DecodeError::InvalidTag)
        ));
        let (install, package) = install_fixture(&descriptor);
        let signed = call(
            &descriptor,
            &ManagementRequest::Install(Box::new(install.clone())),
        );
        let bytes = SharedInstallSubmission::new(install, signed, package)
            .unwrap()
            .encode();
        for length in [0, 3, 4, bytes.len() - 1] {
            assert!(SharedInstallSubmission::decode(&bytes[..length]).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(matches!(
            SharedInstallSubmission::decode(&changed),
            Err(DecodeError::TrailingBytes)
        ));
        let mut changed = bytes;
        changed[..4].copy_from_slice(b"LIQ1");
        assert!(matches!(
            SharedInstallSubmission::decode(&changed),
            Err(DecodeError::InvalidTag)
        ));
    }

    #[test]
    fn shared_submission_nested_lengths_fail_before_allocation() {
        let (descriptor, runtime, committee) = fixture();
        let signed = call(
            &descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
        );
        let request = ManagementRequest::Create(Box::new(descriptor))
            .encode()
            .unwrap();
        let call = signed.encode().unwrap();
        let fields = [
            &request[..],
            &call[..],
            runtime.exact_bytes(),
            &committee.encode()[..],
        ];
        let limits = [
            sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES,
            sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES,
            sdk::package::MAX_PACKAGE_ENCODED_BYTES,
            MAX_AGENT_REPLICA_COMMITTEE_BYTES,
        ];
        for (index, limit) in limits.into_iter().enumerate() {
            let mut bytes = envelope(b"SCQ1", &fields[..index]);
            bytes.extend_from_slice(&((limit + 1) as u32).to_le_bytes());
            assert!(
                matches!(
                    SharedCreateSubmission::decode(&bytes),
                    Err(DecodeError::LimitExceeded)
                ),
                "field {index}"
            );
        }
        for (index, limit) in limits[..3].iter().enumerate() {
            let mut bytes = envelope(b"SIQ1", &fields[..index]);
            bytes.extend_from_slice(&((limit + 1) as u32).to_le_bytes());
            assert!(
                matches!(
                    SharedInstallSubmission::decode(&bytes),
                    Err(DecodeError::LimitExceeded)
                ),
                "field {index}"
            );
        }
    }

    #[test]
    fn shared_install_submission_roundtrip_and_transport_claim_remain_untrusted() {
        let (descriptor, _, _) = fixture();
        let (install, package) = install_fixture(&descriptor);
        let mut signed = call(
            &descriptor,
            &ManagementRequest::Install(Box::new(install.clone())),
        );
        signed.authenticated_node = Some(descriptor.replicas[0].node);
        resign(&mut signed);
        let submission =
            SharedInstallSubmission::new(install.clone(), signed.clone(), package.clone()).unwrap();
        assert!(submission.has_transport_node_claim());
        assert_eq!(submission.install(), &install);
        assert_eq!(submission.call(), &signed);
        assert_eq!(submission.package().exact_bytes(), package.exact_bytes());
        let bytes = submission.encode();
        let decoded = SharedInstallSubmission::decode(&bytes).unwrap();
        assert_eq!(decoded.encode(), bytes);
        let (restored, signed_again, admitted) = decoded.into_parts();
        assert_eq!(restored, install);
        assert_eq!(signed_again, signed);
        assert_eq!(admitted.exact_bytes(), package.exact_bytes());
    }

    #[test]
    fn shared_install_submission_rejects_profile_request_package_and_signature_substitution() {
        let (descriptor, _, _) = fixture();
        let (install, package) = install_fixture(&descriptor);
        let signed = call(
            &descriptor,
            &ManagementRequest::Install(Box::new(install.clone())),
        );
        let mut changed = install.clone();
        changed.package.len += 1;
        changed.entry.package = changed.package.clone();
        let resigned = call(
            &descriptor,
            &ManagementRequest::Install(Box::new(changed.clone())),
        );
        assert!(SharedInstallSubmission::new(changed, resigned, package.clone()).is_err());
        let mut changed = install.clone();
        changed.installation_id.0[0] ^= 1;
        assert!(SharedInstallSubmission::new(changed, signed.clone(), package.clone()).is_err());
        let mut forged = signed.clone();
        forged.signature[0] ^= 1;
        assert!(SharedInstallSubmission::new(install.clone(), forged, package.clone()).is_err());
        let mut local = signed.clone();
        local.managed.profile = AgentProfile::Local;
        resign(&mut local);
        assert!(SharedInstallSubmission::new(install.clone(), local, package.clone()).is_err());
        let create = ManagementRequest::Create(Box::new(descriptor.clone()));
        let create_call = call(&descriptor, &create);
        let bytes = envelope(
            b"SIQ1",
            &[
                &create.encode().unwrap(),
                &create_call.encode().unwrap(),
                package.exact_bytes(),
            ],
        );
        assert!(SharedInstallSubmission::decode(&bytes).is_err());
        let mut bytes = SharedInstallSubmission::new(install, signed, package)
            .unwrap()
            .encode();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(SharedInstallSubmission::decode(&bytes).is_err());
    }
}
