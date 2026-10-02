//! Exact Shared client delivery under the existing file/credential leases.
//! A signed application terminal resolves its management sequence, never
//! member admission, cluster readiness, or permission to expose a route.

use super::*;
use vos::agent::local_lifecycle::{
    SharedCreateDisposition, SharedCreateSubmission, SharedInstallDisposition,
    SharedInstallSubmission,
};
use vos::agent::sdk::{CredentialId, Hash, SpaceId};

/// Immutable SCQ1 and request-bound SCR1 under one independent writer lease.
pub(crate) struct CleanSharedCreateFile {
    request: ExactFileStore,
    response: ExactFileStore,
}

impl CleanSharedCreateFile {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &[
                LOCK_FILE,
                "shared-create.request",
                "shared-create.request.next",
                "shared-create.response",
                "shared-create.response.next",
            ],
        )?);
        Ok(Self {
            request: ExactFileStore::new(root.clone(), StoreRole::SharedCreateRequest),
            response: ExactFileStore::new(root, StoreRole::SharedCreateResponse),
        })
    }

    fn decode_request(bytes: &[u8]) -> Result<SharedCreateSubmission, CleanFileStoreError> {
        if bytes.len() > SharedCreateSubmission::MAX_BYTES {
            return Err(CleanFileStoreError::Oversized);
        }
        let submission =
            SharedCreateSubmission::decode(bytes).map_err(|_| CleanFileStoreError::Corrupt)?;
        if submission.call().authenticated_node.is_some() {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(submission)
    }

    pub(crate) fn load_request(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self.request.load(SharedCreateSubmission::MAX_BYTES)?;
        if let Some(bytes) = &bytes {
            Self::decode_request(bytes)?;
            // Also repairs an ambiguous successful rename by syncing again.
            self.request.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_request(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        Self::decode_request(bytes)?;
        // New caller input must not reconstruct an orphan response's request.
        self.load_response()?;
        self.request.commit_with_replacement(bytes, false)
    }

    fn verify_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        let request = self.load_request()?.ok_or(CleanFileStoreError::Corrupt)?;
        Self::decode_request(&request)?
            .decode_response(bytes)
            .map(|_| ())
            .map_err(|_| CleanFileStoreError::Corrupt)
    }

    pub(crate) fn load_response(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .response
            .load(SharedCreateSubmission::MAX_RESPONSE_BYTES)?;
        if let Some(bytes) = &bytes {
            self.verify_response(bytes)?;
            self.response.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.verify_response(bytes)?;
        self.response.commit_with_replacement(bytes, false)
    }
}

/// Immutable SIQ1 and exact SIR1 terminal under one independent writer lease.
pub(crate) struct CleanSharedInstallFile {
    request: ExactFileStore,
    response: ExactFileStore,
}

impl CleanSharedInstallFile {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &[
                LOCK_FILE,
                "shared-install.request",
                "shared-install.request.next",
                "shared-install.response",
                "shared-install.response.next",
            ],
        )?);
        Ok(Self {
            request: ExactFileStore::new(root.clone(), StoreRole::SharedInstallRequest),
            response: ExactFileStore::new(root, StoreRole::SharedInstallResponse),
        })
    }

    fn decode_request(bytes: &[u8]) -> Result<SharedInstallSubmission, CleanFileStoreError> {
        if bytes.len() > SharedInstallSubmission::MAX_BYTES {
            return Err(CleanFileStoreError::Oversized);
        }
        let submission =
            SharedInstallSubmission::decode(bytes).map_err(|_| CleanFileStoreError::Corrupt)?;
        if submission.call().authenticated_node.is_some() {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(submission)
    }

    pub(crate) fn load_request(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self.request.load(SharedInstallSubmission::MAX_BYTES)?;
        if let Some(bytes) = &bytes {
            Self::decode_request(bytes)?;
            self.request.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_request(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        Self::decode_request(bytes)?;
        self.load_response()?;
        self.request.commit_with_replacement(bytes, false)
    }

    fn verify_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        let request = self.load_request()?.ok_or(CleanFileStoreError::Corrupt)?;
        Self::decode_request(&request)?
            .decode_response(bytes)
            .map(|_| ())
            .map_err(|_| CleanFileStoreError::Corrupt)
    }

    pub(crate) fn load_response(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .response
            .load(SharedInstallSubmission::MAX_RESPONSE_BYTES)?;
        if let Some(bytes) = &bytes {
            self.verify_response(bytes)?;
            self.response.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.verify_response(bytes)?;
        self.response.commit_with_replacement(bytes, false)
    }
}

impl CleanCredentialReservation {
    /// Verified SCR1 resolves only the exact credential attempt: Applied is
    /// not Ready, and only an actual signed CND1 makes the attempt Denied.
    pub(crate) fn complete_shared_create(
        &mut self,
        delivery: &mut CleanSharedCreateFile,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        let request = delivery
            .load_request()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let response = delivery
            .load_response()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let submission = CleanSharedCreateFile::decode_request(&request)?;
        let (terminal, status) = match submission
            .decode_response(&response)
            .map_err(|_| CleanFileStoreError::Corrupt)?
        {
            SharedCreateDisposition::Applied(application) => (
                application.acknowledgement().commitment(),
                CredentialReservationStatus::Completed,
            ),
            SharedCreateDisposition::Denied(denial) => (
                Hash::digest(
                    b"vos/shared-create/retained-denial/v1",
                    &[denial.exact_bytes()],
                ),
                CredentialReservationStatus::Denied,
            ),
        };
        self.complete_shared_terminal(
            submission.descriptor().identity.space,
            submission.call().credential,
            submission.descriptor().creation_nonce,
            Hash::digest(b"vos/shared-create/retained-request/v1", &[&request]),
            terminal,
            status,
        )
    }

    /// Re-verify the independently durable SIQ1/SIR1 before consuming its
    /// sequence. An approved signed failure is Completed; only CND1 is Denied.
    pub(crate) fn complete_shared_install(
        &mut self,
        delivery: &mut CleanSharedInstallFile,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        let request = delivery
            .load_request()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let response = delivery
            .load_response()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let submission = CleanSharedInstallFile::decode_request(&request)?;
        let disposition = submission
            .decode_response(&response)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let (terminal, status) = match disposition {
            SharedInstallDisposition::Applied(acknowledgement) => (
                acknowledgement.commitment(),
                CredentialReservationStatus::Completed,
            ),
            SharedInstallDisposition::Failed(failure) => {
                (failure.commitment(), CredentialReservationStatus::Completed)
            }
            SharedInstallDisposition::Denied(denial) => (
                Hash::digest(
                    b"vos/shared-install/retained-denial/v1",
                    &[denial.exact_bytes()],
                ),
                CredentialReservationStatus::Denied,
            ),
        };
        self.complete_shared_terminal(
            submission.call().managed.space,
            submission.call().credential,
            Hash(submission.install().installation_id.0),
            Hash::digest(b"vos/shared-install/retained-request/v1", &[&request]),
            terminal,
            status,
        )
    }

    fn complete_shared_terminal(
        &mut self,
        space: SpaceId,
        credential: CredentialId,
        nonce: Hash,
        request: Hash,
        terminal: Hash,
        status: CredentialReservationStatus,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        if space != self.space || credential != self.credential {
            return Err(CleanFileStoreError::Corrupt);
        }
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let mut completed = self.image(nonce, Some((request, terminal)));
        completed[100] = match status {
            CredentialReservationStatus::Completed => 1,
            CredentialReservationStatus::Denied => 2,
            CredentialReservationStatus::Pending => return Err(CleanFileStoreError::Corrupt),
        };
        if current[100] != 0 && current != completed {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.store.commit(&completed)?;
        Ok(status)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{Fixture, stage};
    use super::*;
    use core::num::NonZeroU64;
    use vos::agent::sdk::authority::*;
    use vos::agent::sdk::package::{PackageEnvelope, PackageManifest};
    use vos::agent::sdk::*;

    // Admission/codec fixture only; the image program is deliberately not
    // executed as an external guest. Physical lifecycle qualification is separate.
    pub(crate) fn submissions() -> (
        libp2p::identity::Keypair,
        SharedCreateSubmission,
        SharedInstallSubmission,
    ) {
        let (operator, authority, mut descriptor, image) =
            super::super::super::local_create::tests::fixture();
        let (_, original, _) = super::super::super::local_create::prepare(
            &operator,
            authority,
            descriptor.clone(),
            image.clone(),
            NonZeroU64::new(1).unwrap(),
            10,
            30,
        )
        .unwrap()
        .into_parts();
        let mut envelope = PackageEnvelope::decode(image.exact_bytes()).unwrap();
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            unreachable!()
        };
        manifest.contract = contract::RuntimePackageContract::experimental_state_blocks();
        manifest.external_state_limits = Some(contract::ExternalStateResourceLimits {
            max_rows_per_lane: 1_000_000,
            max_row_bytes_per_lane: 1 << 30,
        });
        manifest.capabilities.lanes = LaneSet::of(StateLane::Linear);
        manifest.capabilities.scheduling = false;
        manifest.capabilities.proof_systems = ProofSystemSet::EMPTY;
        envelope.manifest.signing_mut().signature = operator
            .sign(&envelope.signing_bytes().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let runtime =
            vos::agent::package_admission::admit_state_runtime_package(&envelope.encode().unwrap())
                .unwrap();
        descriptor.identity.profile = AgentProfile::Shared;
        descriptor.identity.runtime_deployment = runtime.deployment();
        descriptor.identity.runtime_program = runtime.program();
        descriptor.identity.runtime_producer = runtime.manifest().signing.producer;
        descriptor.runtime_package = runtime.package_ref().clone();
        descriptor.runtime_contract = runtime.manifest().contract;
        descriptor.capabilities = runtime.manifest().capabilities;
        let mut members = [0x46, 0x47, 0x48]
            .into_iter()
            .map(|seed| {
                let node = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
                let peer = node.public().to_peer_id().to_bytes();
                vos::agent::genesis::AgentReplicaMember::new(
                    vos::agent::AgentReplica {
                        node: vos::service::NodeId::of_authenticated_peer(&peer),
                        principal: vos::service::PrincipalId(descriptor.identity.owner.0),
                        role: vos::agent::ReplicaRole::Voter,
                    },
                    peer.clone(),
                    node.public().try_into_ed25519().unwrap().to_bytes(),
                    Some(vos::agent::genesis::derive_replica_raft_slot(&peer)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.replica().node);
        descriptor.replicas = members
            .iter()
            .map(|member| AgentReplica {
                node: NodeId(member.replica().node.0),
                principal: PrincipalId(member.replica().principal.0),
                role: ReplicaRole::Voter,
            })
            .collect();
        let committee = vos::agent::genesis::AgentReplicaCommittee::new(
            vos::service::SpaceId(descriptor.identity.space.0),
            vos::service::AgentId(descriptor.identity.agent.0),
            vos::agent::AgentProfile::Shared,
            members,
        )
        .unwrap();
        let call = |request: &ManagementRequest, sequence| {
            let mut call = original.clone();
            call.managed.profile = AgentProfile::Shared;
            call.managed.runtime_deployment = runtime.deployment();
            call.request_sequence = NonZeroU64::new(sequence).unwrap();
            call.plan = request.authorization_plan().unwrap();
            call.invocation = call.expected_invocation();
            call.signature = operator
                .sign(&call.signing_bytes())
                .unwrap()
                .try_into()
                .unwrap();
            call
        };
        let create_call = call(&ManagementRequest::Create(Box::new(descriptor.clone())), 1);
        let package = vos::agent::package_admission::admit_actor_package(include_bytes!(
            "../../../../blobs/system_authority.vos"
        ))
        .unwrap();
        // The supported external Shared contract is Linear-only; Catalog is
        // Merge-based and must remain incompatible with this fixture/runtime.
        package
            .envelope()
            .require_compatible_with(descriptor.runtime_contract, descriptor.capabilities)
            .unwrap();
        let install = super::super::super::local_install::build_install(
            descriptor.identity.agent,
            InstallationId([0x51; 32]),
            Hash([0x52; 32]),
            "authority".into(),
            None,
            Some(vec![1]),
            &package,
        )
        .unwrap();
        let install_call = call(&ManagementRequest::Install(Box::new(install.clone())), 2);
        let create =
            SharedCreateSubmission::new(descriptor, create_call, runtime, committee).unwrap();
        let install = SharedInstallSubmission::new(install, install_call, package).unwrap();
        (operator, create, install)
    }

    pub(crate) fn acknowledgement(
        operator: &libp2p::identity::Keypair,
        submission: &SharedInstallSubmission,
    ) -> ManagementApplicationAck {
        let call = submission.call();
        let approval = ManagementApproval::from_call(
            call,
            NonZeroU64::new(3).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([10; 32]),
            },
            AuthorityLaneRoots::default(),
            1,
            10,
            30,
        )
        .unwrap();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: call.authority.binding.policy,
                issuer: call.authority.binding.issuer,
                space: call.managed.space,
                agent: call.managed.agent,
                operation: call.plan.authority_operation(),
                runtime_deployment: call.managed.runtime_deployment,
                actor: Some(submission.install().entry.actor),
                actor_deployment: Some(submission.install().entry.deployment),
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: 1,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: 10,
                expires_at: 30,
                request: approval.plan_commitment,
            },
            public_key: call.authority.binding.public_key,
            signature: [0; 64],
        };
        receipt.signature = operator
            .sign(&receipt.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.plan_commitment,
            receipt,
            application: ManagementReply::Installed(submission.install().entry.clone()),
            reopened_state: Hash([11; 32]),
            applied_at: 20,
            signature: [0; 64],
        };
        ack.signature = operator
            .sign(&ack.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        ack
    }

    #[test]
    fn shared_requests_are_type_bound_immutable_leased_and_recover_exact_stages() {
        let (operator, create, install) = submissions();
        let fixture = Fixture::new("shared-create-client");
        let mut store = CleanSharedCreateFile::open_or_create(&fixture.root).unwrap();
        assert!(matches!(
            CleanSharedCreateFile::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(store.publish_request(&install.encode()).is_err());
        assert!(store.publish_request(b"LCQ1").is_err());
        let mut transport_call = create.call().clone();
        transport_call.authenticated_node = Some(create.descriptor().replicas[0].node);
        transport_call.invocation = transport_call.expected_invocation();
        transport_call.signature = operator
            .sign(&transport_call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let transport_claim = SharedCreateSubmission::new(
            create.descriptor().clone(),
            transport_call,
            create.runtime().clone(),
            create.committee().clone(),
        )
        .unwrap();
        assert!(store.publish_request(&transport_claim.encode()).is_err());
        assert_eq!(store.load_request().unwrap(), None);
        let request = create.encode();
        let fault =
            SharedManagementStageFault::arm(&fixture.root, StoreRole::SharedCreateRequest, 1);
        assert!(store.publish_request(&request).is_err());
        assert!(fault.fired());
        drop(fault);
        drop(store);
        let mut store = CleanSharedCreateFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request.clone()));
        store.publish_request(&request).unwrap();
        let mut different_call = create.call().clone();
        different_call.request_sequence = NonZeroU64::new(2).unwrap();
        different_call.invocation = different_call.expected_invocation();
        different_call.signature = operator
            .sign(&different_call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let replacement = SharedCreateSubmission::new(
            create.descriptor().clone(),
            different_call,
            create.runtime().clone(),
            create.committee().clone(),
        )
        .unwrap();
        assert!(matches!(
            store.publish_request(&replacement.encode()),
            Err(CleanFileStoreError::RequestConflict)
        ));
        // An invalid signature is rejected before immutable storage is touched.
        let mut different = request.clone();
        *different.last_mut().unwrap() ^= 1;
        assert!(store.publish_request(&different).is_err());
        assert_eq!(store.load_request().unwrap(), Some(request));
        assert!(store.publish_response(b"SCR1\x01").is_err());
        assert_eq!(store.load_response().unwrap(), None);
        assert!(matches!(
            CleanLocalInstallFile::open_or_create(&fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
        for (tag, role) in [
            (52, StoreRole::SharedInstallHandoff),
            (53, StoreRole::SharedCreateRequest),
            (54, StoreRole::SharedCreateResponse),
            (55, StoreRole::SharedInstallRequest),
            (56, StoreRole::SharedInstallResponse),
        ] {
            assert_eq!(StoreRole::from_byte(tag), Some(role));
        }
    }

    #[test]
    fn orphan_or_wrong_role_response_cannot_reconstruct_its_request() {
        let (_, create, _) = submissions();
        for wrong_role in [false, true] {
            let fixture = Fixture::new("shared-orphan-client");
            let mut store = CleanSharedCreateFile::open_or_create(&fixture.root).unwrap();
            if wrong_role {
                let encoded =
                    encode_envelope(StoreRole::SharedInstallResponse, None, b"SIR1").unwrap();
                super::super::tests::write_private(
                    &fixture.root.join("shared-create.response"),
                    &encoded,
                );
            } else {
                stage(&store.response, None, b"SCR1\x00");
            }
            assert!(store.load_response().is_err());
            assert!(store.publish_request(&create.encode()).is_err());
            assert_eq!(store.load_request().unwrap(), None);
        }
    }

    #[test]
    fn shared_create_denial_is_exact_durable_and_closes_only_its_credential_attempt() {
        let (operator, submission, install) = submissions();
        let fixture = Fixture::new("shared-create-denied-client");
        let mut store = CleanSharedCreateFile::open_or_create(&fixture.root).unwrap();
        let request = submission.encode();
        store.publish_request(&request).unwrap();
        let call = submission.call();
        let nonce = submission.descriptor().creation_nonce;
        let mut reservation = CleanCredentialReservation::open_or_create(
            &fixture.parent,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        reservation.reserve(nonce).unwrap();
        let before = fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap();
        for malformed in [b"forbidden".as_slice(), b"SCR1\x01\x04\0\0\0CND1"] {
            assert!(store.publish_response(malformed).is_err());
            assert!(reservation.complete_shared_create(&mut store).is_err());
            assert_eq!(
                fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap(),
                before
            );
        }
        let certificate = super::super::super::local_create::tests::denial_for_create(
            &operator,
            submission.descriptor().clone(),
            call.clone(),
        );
        let disposition =
            SharedCreateDisposition::Denied(submission.verify_denial(&certificate).unwrap());
        let response = submission.encode_response(&disposition).unwrap();
        assert_eq!(&response[..5], b"SCR1\x01");
        assert_eq!(submission.decode_response(&response).unwrap(), disposition);
        assert!(install.decode_response(&response).is_err());
        for index in [0, response.len() - 1] {
            let mut corrupt = response.clone();
            corrupt[index] ^= 1;
            assert!(store.publish_response(&corrupt).is_err());
        }
        let mut trailing = response.clone();
        trailing.push(0);
        assert!(store.publish_response(&trailing).is_err());
        let mut another_call = call.clone();
        another_call.request_sequence = NonZeroU64::new(4).unwrap();
        another_call.invocation = another_call.expected_invocation();
        another_call.signature = operator
            .sign(&another_call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let another = SharedCreateSubmission::new(
            submission.descriptor().clone(),
            another_call.clone(),
            submission.runtime().clone(),
            submission.committee().clone(),
        )
        .unwrap();
        let other_certificate = super::super::super::local_create::tests::denial_for_create(
            &operator,
            another.descriptor().clone(),
            another_call,
        );
        let substituted = another
            .encode_response(&SharedCreateDisposition::Denied(
                another.verify_denial(&other_certificate).unwrap(),
            ))
            .unwrap();
        assert!(store.publish_response(&substituted).is_err());
        assert!(reservation.complete_shared_create(&mut store).is_err());
        let fault =
            SharedManagementStageFault::arm(&fixture.root, StoreRole::SharedCreateResponse, 1);
        assert!(store.publish_response(&response).is_err());
        assert!(fault.fired());
        drop(fault);
        drop(store);
        let mut store = CleanSharedCreateFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request));
        assert_eq!(store.load_response().unwrap(), Some(response.clone()));
        assert!(matches!(
            CleanSharedCreateFile::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        let wrong = Fixture::new("shared-create-denied-wrong-owner");
        for (space, credential, reserved_nonce) in [
            (call.managed.space, CredentialId([0x72; 32]), nonce),
            (SpaceId([0x73; 32]), call.credential, nonce),
            (call.managed.space, call.credential, Hash([0x74; 32])),
        ] {
            let mut other =
                CleanCredentialReservation::open_or_create(&wrong.parent, space, credential)
                    .unwrap();
            other.reserve(reserved_nonce).unwrap();
            let before = fs::read(other.store.root.path.join(RESERVATION_FILE)).unwrap();
            assert!(other.complete_shared_create(&mut store).is_err());
            assert_eq!(
                fs::read(other.store.root.path.join(RESERVATION_FILE)).unwrap(),
                before
            );
        }
        assert_eq!(
            reservation.complete_shared_create(&mut store).unwrap(),
            CredentialReservationStatus::Denied
        );
        drop(reservation);
        let mut reservation = CleanCredentialReservation::open_or_create(
            &fixture.parent,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        assert_eq!(
            reservation.complete_shared_create(&mut store).unwrap(),
            CredentialReservationStatus::Denied
        );
        assert!(store.publish_response(&substituted).is_err());
        assert_eq!(store.load_response().unwrap(), Some(response));
        reservation.reserve(Hash([0x75; 32])).unwrap();
        let before = fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap();
        assert!(reservation.complete_shared_create(&mut store).is_err());
        assert_eq!(
            fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap(),
            before
        );
    }

    #[test]
    fn shared_install_completion_requires_exact_nonce_credential_and_retained_terminal() {
        let (operator, _, submission) = submissions();
        let fixture = Fixture::new("shared-install-client");
        let mut store = CleanSharedInstallFile::open_or_create(&fixture.root).unwrap();
        let request = submission.encode();
        store.publish_request(&request).unwrap();
        let call = submission.call();
        let nonce = Hash(submission.install().installation_id.0);
        let mut reservation = CleanCredentialReservation::open_or_create(
            &fixture.parent,
            call.managed.space,
            call.credential,
        )
        .unwrap();
        reservation.reserve(nonce).unwrap();
        let before = fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap();
        assert!(reservation.complete_shared_install(&mut store).is_err());
        assert_eq!(
            fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap(),
            before
        );
        let ack = acknowledgement(&operator, &submission);
        let response = submission
            .encode_response(&SharedInstallDisposition::Applied(ack))
            .unwrap();
        let mut corrupt = response.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(store.publish_response(&corrupt).is_err());
        let fault =
            SharedManagementStageFault::arm(&fixture.root, StoreRole::SharedInstallResponse, 1);
        assert!(store.publish_response(&response).is_err());
        assert!(fault.fired());
        drop(fault);
        drop(store);
        let mut store = CleanSharedInstallFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request));
        assert_eq!(store.load_response().unwrap(), Some(response.clone()));
        assert!(matches!(
            CleanSharedInstallFile::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        let wrong = Fixture::new("shared-install-wrong-owner");
        for (space, credential, reserved_nonce) in [
            (call.managed.space, CredentialId([0x72; 32]), nonce),
            (SpaceId([0x73; 32]), call.credential, nonce),
            (call.managed.space, call.credential, Hash([0x74; 32])),
        ] {
            let mut other =
                CleanCredentialReservation::open_or_create(&wrong.parent, space, credential)
                    .unwrap();
            other.reserve(reserved_nonce).unwrap();
            let before = fs::read(other.store.root.path.join(RESERVATION_FILE)).unwrap();
            assert!(other.complete_shared_install(&mut store).is_err());
            assert_eq!(
                fs::read(other.store.root.path.join(RESERVATION_FILE)).unwrap(),
                before
            );
            assert_eq!(
                other.current().unwrap(),
                Some((reserved_nonce, CredentialReservationStatus::Pending))
            );
        }
        assert_eq!(
            reservation.complete_shared_install(&mut store).unwrap(),
            CredentialReservationStatus::Completed
        );
        assert_eq!(
            reservation.complete_shared_install(&mut store).unwrap(),
            CredentialReservationStatus::Completed
        );
        let mut another_call = call.clone();
        another_call.request_sequence = NonZeroU64::new(4).unwrap();
        another_call.invocation = another_call.expected_invocation();
        another_call.signature = operator
            .sign(&another_call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let another = SharedInstallSubmission::new(
            submission.install().clone(),
            another_call,
            submission.package().clone(),
        )
        .unwrap();
        let substituted = another
            .encode_response(&SharedInstallDisposition::Applied(acknowledgement(
                &operator, &another,
            )))
            .unwrap();
        assert!(store.publish_response(&substituted).is_err());
        assert!(store.publish_request(&another.encode()).is_err());
        assert_eq!(store.load_response().unwrap(), Some(response));
        reservation.reserve(Hash([0x75; 32])).unwrap();
        let before = fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap();
        assert!(reservation.complete_shared_install(&mut store).is_err());
        assert_eq!(
            fs::read(reservation.store.root.path.join(RESERVATION_FILE)).unwrap(),
            before
        );
    }

    #[test]
    fn signed_install_failure_completes_but_unsigned_denial_does_not() {
        let (operator, _, submission) = submissions();
        let fixture = Fixture::new("shared-install-failure-client");
        let mut store = CleanSharedInstallFile::open_or_create(&fixture.root).unwrap();
        store.publish_request(&submission.encode()).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &fixture.parent,
            submission.call().managed.space,
            submission.call().credential,
        )
        .unwrap();
        let nonce = Hash(submission.install().installation_id.0);
        reservation.reserve(nonce).unwrap();
        assert!(store.publish_response(b"SIR1\x01\x04\0\0\0CND1").is_err());
        assert!(reservation.complete_shared_install(&mut store).is_err());
        let ack = acknowledgement(&operator, &submission);
        let mut failure = ManagementApplicationFailure {
            authorization_invocation: ack.authorization_invocation,
            acknowledgement_invocation: ack.acknowledgement_invocation,
            authority: ack.authority,
            managed: ack.managed,
            credential_call: ack.credential_call,
            approval: ack.approval,
            authorization_sequence: ack.authorization_sequence,
            request: ack.request,
            receipt: ack.receipt,
            error: ManagementError::AlreadyExists,
            reopened_state: ack.reopened_state,
            failed_at: ack.applied_at,
            signature: [0; 64],
        };
        failure.signature = operator
            .sign(&failure.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let response = submission
            .encode_response(&SharedInstallDisposition::Failed(failure))
            .unwrap();
        store.publish_response(&response).unwrap();
        assert_eq!(
            reservation.complete_shared_install(&mut store).unwrap(),
            CredentialReservationStatus::Completed
        );
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Completed))
        );
    }
}
