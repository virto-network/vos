//! Crash-safe cross-node Private replica establishment.
//!
//! Source PVRI/PCRS/PAPL values are accepted only as bounded verification
//! carriers. The destination always constructs its own PVRI and PAPL chain;
//! the only cross-node runtime convergence target is the authority-signed PSP.

use super::*;
use subtle::ConstantTimeEq;

use super::super::private_store::{
    EncryptedBackupReplayRow, VerifiedEncryptedBackup, encrypted_backup_genesis_claim,
};

pub(super) const ESTABLISHMENT_PLAN_FILE: &str = "establishment.plan";
pub(super) const ESTABLISHMENT_PLAN_WRITE_FILE: &str = "establishment.plan.write";
pub(super) const ESTABLISHMENT_RECEIPT_FILE: &str = "establishment.receipt";
pub(super) const ESTABLISHMENT_RECEIPT_WRITE_FILE: &str = "establishment.receipt.write";
// `PVEP` was the retired generation-one pending-evidence frame. Keep the
// establishment namespace type-unique so a future shared decoder cannot
// confuse an authenticated replay plan with Store transaction debris.
const ESTABLISHMENT_PLAN_MAGIC: &[u8; 4] = b"PVES";
const ESTABLISHMENT_PLAN_VERSION: u16 = 1;
const ESTABLISHMENT_RECEIPT_MAGIC: &[u8; 4] = b"PVER";
const ESTABLISHMENT_RECEIPT_VERSION: u16 = 1;
const ESTABLISHMENT_PLAN_HASH_DOMAIN: &[u8] = b"vos/private/replica-establishment-plan/v1";
const ESTABLISHMENT_RECEIPT_HASH_DOMAIN: &[u8] = b"vos/private/replica-establishment-receipt/v1";
const ESTABLISHMENT_SOURCE_HASH_DOMAIN: &[u8] = b"vos/private/replica-establishment-source/v1";
const ESTABLISHMENT_IDENTITY_HASH_DOMAIN: &[u8] = b"vos/private/replica-establishment-identity/v1";
const ESTABLISHMENT_HEADER_BYTES: usize = 4 + 2 + 32;
const MANAGED_AGENT_TARGET_WIRE_BYTES: usize = 5 * 32 + 1;
const AUTHORITY_BINDING_WIRE_BYTES: usize = 7 * 32 + 8;
const AUTHORITY_TARGET_WIRE_BYTES: usize = 3 * 32 + AUTHORITY_BINDING_WIRE_BYTES;
const ESTABLISHMENT_COMPLETION_WIRE_BYTES: usize = 4 * 32;
const ESTABLISHMENT_AUTHENTICATOR_BYTES: usize = 32;

fn encode_managed_target(encoder: &mut Encoder<'_>, route: ManagedAgentTarget) {
    encoder.fixed(route.space.as_bytes());
    encoder.fixed(route.agent.as_bytes());
    encoder.fixed(route.owner.as_bytes());
    encoder.u8(route.profile as u8);
    encoder.fixed(route.runtime_deployment.as_bytes());
    encoder.fixed(route.transition_producer.as_bytes());
}

fn decode_managed_target(
    decoder: &mut Decoder<'_>,
) -> Result<ManagedAgentTarget, vos_protocol::wire::DecodeError> {
    let route = ManagedAgentTarget {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        owner: PrincipalId(decoder.fixed()?),
        profile: match decoder.u8()? {
            0 => AgentProfile::Local,
            1 => AgentProfile::Shared,
            2 => AgentProfile::Private,
            _ => return Err(vos_protocol::wire::DecodeError::InvalidTag),
        },
        runtime_deployment: DeploymentId(decoder.fixed()?),
        transition_producer: ProducerId(decoder.fixed()?),
    };
    route
        .is_valid()
        .then_some(route)
        .ok_or(vos_protocol::wire::DecodeError::NonCanonical)
}
// Header + route + owner + length-prefixed destination + authority + source
// hash + gas + length-prefixed archive + optional completion + authenticator.
const MAX_ESTABLISHMENT_PLAN_BYTES: usize = ESTABLISHMENT_HEADER_BYTES
    + MANAGED_AGENT_TARGET_WIRE_BYTES
    + 32
    + 4
    + MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES
    + AUTHORITY_TARGET_WIRE_BYTES
    + 32
    + 8
    + 4
    + MAX_PRIVATE_HOST_ARCHIVE_BYTES
    + 1
    + ESTABLISHMENT_COMPLETION_WIRE_BYTES
    + ESTABLISHMENT_AUTHENTICATOR_BYTES;
// Receipt omits the archive and encodes its required completion directly.
const MAX_ESTABLISHMENT_RECEIPT_BYTES: usize = ESTABLISHMENT_HEADER_BYTES
    + MANAGED_AGENT_TARGET_WIRE_BYTES
    + 32
    + 4
    + MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES
    + AUTHORITY_TARGET_WIRE_BYTES
    + 32
    + 8
    + ESTABLISHMENT_COMPLETION_WIRE_BYTES
    + ESTABLISHMENT_AUTHENTICATOR_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedPrivateReplicaEstablishment {
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
    source_hash: Hash,
    management_gas: u64,
}

impl PreparedPrivateReplicaEstablishment {
    pub(crate) const fn route(&self) -> ManagedAgentTarget {
        self.route
    }

    pub(crate) const fn source_hash(&self) -> Hash {
        self.source_hash
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateReplicaEstablishmentDisposition {
    Published,
    AlreadyPresent,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplicaEstablishmentStop {
    Never,
    AfterGenesisStore,
    AfterGenesisDescriptor,
    AfterGenesisRuntime,
    AfterGenesisBootstrap,
    AfterGenesisRuntimeImage,
    AfterReplayStoreCommitted,
    AfterReplayEvidenceStaged,
    AfterReplayProvenanceStaged,
    AfterReplayEvidencePending,
    AfterReplayProvenancePublished,
    AfterReplayEvidencePublished,
    AfterReplayEvidenceRetired,
    AfterObjectPrefix,
    BeforeRuntimeSealed,
    AfterRuntimeSealed,
    AfterCompletionPlanTemporary,
    AfterCompletionPlanCommitted,
    AfterStageRenamed,
    AfterReceiptTemporary,
    AfterReceiptPublished,
    AfterPlanRetired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplicaEstablishmentCompletion {
    store: Hash,
    runtime_image: Hash,
    runtime_lineage: Hash,
    establishment_tag: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplicaEstablishmentPlan {
    route: ManagedAgentTarget,
    owner: PrincipalId,
    destination: PrivateNodeIdentity,
    authority: AuthorityActorTarget,
    source_hash: Hash,
    management_gas: u64,
    archive: Vec<u8>,
    completion: Option<ReplicaEstablishmentCompletion>,
}

/// Small node-authenticated publication receipt retained in the live slot.
/// It makes exact post-publication retries distinguishable from a conflicting
/// independently-created lineage without retaining the source archive.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplicaEstablishmentReceipt {
    route: ManagedAgentTarget,
    owner: PrincipalId,
    destination: PrivateNodeIdentity,
    authority: AuthorityActorTarget,
    source_hash: Hash,
    management_gas: u64,
    completion: ReplicaEstablishmentCompletion,
}

#[derive(Clone)]
struct VerifiedReplicaReplayRow {
    index: super::super::private_store::StoredControlIndex,
    control: PrivateControlRecord,
    source_application: PrivateRuntimeApplication,
    source_evidence: Vec<u8>,
    source_stable_projection: Hash,
}

struct VerifiedReplicaSource {
    backup: VerifiedEncryptedBackup,
    plaintext: AgentPlaintext,
    creation_receipt: AuthorityReceipt,
    data_keys: BTreeMap<u64, PrivateDataKey>,
    rows: Vec<VerifiedReplicaReplayRow>,
    final_target: PrivateStoreCorePosition,
    genesis_state: RuntimeState,
}

struct StagedPrivateReplicaRuntime {
    store: PrivateStore,
    descriptor: AgentDescriptor,
    runtime_package: Zeroizing<Vec<u8>>,
    bootstrap_metadata: Zeroizing<Vec<u8>>,
    runtime_image: PrivateRuntimeImage,
    data_keys: BTreeMap<u64, PrivateDataKey>,
}

impl PrivateAgentHost {
    /// Authenticate one complete portable archive before creating any staged
    /// destination state, then durably retain only its canonical ciphertext
    /// replay capsule. Source-node PSI values are deliberately removed.
    pub(crate) fn prepare_replica_establishment<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        route: ManagedAgentTarget,
        archive_bytes: &[u8],
        authority: AuthorityActorTarget,
        node_authority: &V,
    ) -> Result<PreparedPrivateReplicaEstablishment, PrivateAgentHostError> {
        self.verify_root_scope()?;
        if !route.is_valid()
            || route.profile != AgentProfile::Private
            || route.owner != self.scope.owner
            || !authority.is_valid()
            || route.space != self.scope.space
            || authority.space != route.space
        {
            return Err(PrivateAgentHostError::InvalidScope);
        }

        let mut archive = decode_host_archive(archive_bytes, true)?;
        if archive.space != route.space || archive.agent != route.agent {
            return Err(PrivateAgentHostError::InvalidScope);
        }
        // PSI1 is destination-local provenance, never portable authority.
        archive.stable_import_certificates.clear();
        let sanitized_archive =
            encode_host_archive(&archive, true, MAX_PRIVATE_HOST_ARCHIVE_BYTES)?;
        let source_hash = Hash::digest(
            ESTABLISHMENT_SOURCE_HASH_DOMAIN,
            &[sanitized_archive.as_slice()],
        );
        let stage = self.creating_path(route.agent);
        let destination = self.agent_path(route.agent);
        let stage_exists = fs::symlink_metadata(&stage).is_ok();
        let destination_exists = fs::symlink_metadata(&destination).is_ok();
        if stage_exists && destination_exists {
            let plan = read_replica_establishment_plan(&stage, &self.node_key)?;
            require_exact_plan_request(
                &plan,
                route,
                self.scope.owner,
                &self.scope.local_node,
                authority,
                source_hash,
            )?;
            let completion = plan
                .completion
                .clone()
                .ok_or(PrivateAgentHostError::Corrupt)?;
            publish_completed_replica_establishment(self, &plan, &completion, node_authority)?;
            return Ok(PreparedPrivateReplicaEstablishment {
                route,
                authority: plan.authority,
                source_hash,
                management_gas: plan.management_gas,
            });
        }
        if destination_exists
            && fs::symlink_metadata(destination.join(ESTABLISHMENT_PLAN_FILE)).is_ok()
        {
            require_real_directory(&destination)?;
            let plan = read_replica_establishment_plan(&destination, &self.node_key)?;
            require_exact_plan_request(
                &plan,
                route,
                self.scope.owner,
                &self.scope.local_node,
                authority,
                source_hash,
            )?;
            let completion = plan
                .completion
                .clone()
                .ok_or(PrivateAgentHostError::Corrupt)?;
            publish_completed_replica_establishment(self, &plan, &completion, node_authority)?;
            return Ok(PreparedPrivateReplicaEstablishment {
                route,
                authority: plan.authority,
                source_hash,
                management_gas: plan.management_gas,
            });
        }
        if self.agents.contains_key(&route.agent) || destination_exists {
            if !destination_exists {
                return Err(PrivateAgentHostError::Corrupt);
            }
            require_real_directory(&destination)?;
            if fs::symlink_metadata(destination.join(ESTABLISHMENT_RECEIPT_FILE)).is_err() {
                return Err(if self.agents.contains_key(&route.agent) {
                    PrivateAgentHostError::Corrupt
                } else {
                    PrivateAgentHostError::AlreadyExists
                });
            }
            let receipt = read_replica_establishment_receipt(&destination, &self.node_key)?;
            require_exact_receipt_request(
                &receipt,
                route,
                self.scope.owner,
                &self.scope.local_node,
                authority,
                source_hash,
            )?;
            if let Some(hosted) = self.agents.get(&route.agent) {
                authenticate_hosted_replica_establishment_receipt(hosted, &receipt, &self.scope)?;
            }
            return Ok(PreparedPrivateReplicaEstablishment {
                route,
                authority: receipt.authority,
                source_hash,
                management_gas: receipt.management_gas,
            });
        }
        if stage_exists {
            require_real_directory(&stage)?;
            let plan = read_replica_establishment_plan(&stage, &self.node_key)?;
            require_exact_plan_request(
                &plan,
                route,
                self.scope.owner,
                &self.scope.local_node,
                authority,
                source_hash,
            )?;
            sync_directory(&stage)?;
            sync_directory(&self.root.join(CREATING_DIRECTORY))?;
            return Ok(PreparedPrivateReplicaEstablishment {
                route,
                authority: plan.authority,
                source_hash,
                management_gas: plan.management_gas,
            });
        }

        self.require_new_private_agent_reservation_capacity(route.agent)?;

        // This is the sole pre-write source admission. Exact staged or live
        // retries above rely on the destination-authenticated plan/receipt
        // and therefore neither re-execute Create nor revalidate a new input.
        let _verified = authenticate_replica_source(
            &archive,
            route,
            authority,
            &self.scope,
            &self.node_key,
            self.management_gas,
            source_hash,
            node_authority,
        )?;

        let plan = ReplicaEstablishmentPlan {
            route,
            owner: self.scope.owner,
            destination: self.scope.local_node.clone(),
            authority,
            source_hash,
            management_gas: self.management_gas,
            archive: sanitized_archive,
            completion: None,
        };
        let bytes = encode_replica_establishment_plan(&plan, &self.node_key)?;
        fs::create_dir(&stage).map_err(map_io)?;
        if let Err(error) = publish_replica_establishment_plan(&stage, &bytes) {
            let _ = fs::remove_dir_all(&stage);
            let _ = sync_directory(&self.root.join(CREATING_DIRECTORY));
            return Err(error);
        }
        sync_directory(&self.root.join(CREATING_DIRECTORY))?;
        Ok(PreparedPrivateReplicaEstablishment {
            route,
            authority,
            source_hash,
            management_gas: self.management_gas,
        })
    }

    /// Resume an authenticated unpublished establishment plan. Progress is
    /// inferred from the Store/PVRI/PAPL/PSE/PSI prefix; no plaintext key or
    /// caller-selected phase is persisted.
    pub(crate) fn resume_replica_establishment<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        prepared: PreparedPrivateReplicaEstablishment,
        node_authority: &V,
    ) -> Result<PrivateReplicaEstablishmentDisposition, PrivateAgentHostError> {
        self.resume_replica_establishment_inner(
            prepared,
            node_authority,
            ReplicaEstablishmentStop::Never,
        )
    }

    #[cfg(test)]
    pub(super) fn resume_replica_establishment_with_stop<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        prepared: PreparedPrivateReplicaEstablishment,
        node_authority: &V,
        stop: ReplicaEstablishmentStop,
    ) -> Result<PrivateReplicaEstablishmentDisposition, PrivateAgentHostError> {
        self.resume_replica_establishment_inner(prepared, node_authority, stop)
    }

    fn resume_replica_establishment_inner<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        prepared: PreparedPrivateReplicaEstablishment,
        node_authority: &V,
        stop: ReplicaEstablishmentStop,
    ) -> Result<PrivateReplicaEstablishmentDisposition, PrivateAgentHostError> {
        self.verify_root_scope()?;
        let agent = prepared.route.agent;
        let stage = self.creating_path(agent);
        let destination = self.agent_path(agent);
        let stage_exists = fs::symlink_metadata(&stage).is_ok();
        let destination_exists = fs::symlink_metadata(&destination).is_ok();
        if stage_exists && destination_exists {
            let plan = read_replica_establishment_plan(&stage, &self.node_key)?;
            require_exact_plan_prepared(&plan, prepared, &self.scope)?;
            let completion = plan
                .completion
                .clone()
                .ok_or(PrivateAgentHostError::Corrupt)?;
            publish_completed_replica_establishment_with_stop(
                self,
                &plan,
                &completion,
                node_authority,
                stop,
            )?;
            return Ok(PrivateReplicaEstablishmentDisposition::Published);
        }
        if self.agents.contains_key(&agent) {
            let receipt = read_replica_establishment_receipt(&destination, &self.node_key)?;
            require_exact_receipt_prepared(&receipt, prepared, &self.scope)?;
            let hosted = self
                .agents
                .get(&agent)
                .ok_or(PrivateAgentHostError::Corrupt)?;
            authenticate_hosted_replica_establishment_receipt(hosted, &receipt, &self.scope)?;
            return Ok(PrivateReplicaEstablishmentDisposition::AlreadyPresent);
        }
        if destination_exists {
            require_real_directory(&destination)?;
            if fs::symlink_metadata(destination.join(ESTABLISHMENT_PLAN_FILE)).is_ok() {
                let plan = read_replica_establishment_plan(&destination, &self.node_key)?;
                require_exact_plan_prepared(&plan, prepared, &self.scope)?;
                let completion = plan
                    .completion
                    .clone()
                    .ok_or(PrivateAgentHostError::Corrupt)?;
                publish_completed_replica_establishment_with_stop(
                    self,
                    &plan,
                    &completion,
                    node_authority,
                    stop,
                )?;
                return Ok(PrivateReplicaEstablishmentDisposition::Published);
            }
            let receipt = read_replica_establishment_receipt(&destination, &self.node_key)?;
            require_exact_receipt_prepared(&receipt, prepared, &self.scope)?;
            let hosted = open_completed_replica_establishment_receipt(
                &destination,
                &receipt,
                &self.scope,
                &self.node_key,
                node_authority,
            )?;
            if self.agents.insert(agent, hosted).is_some() {
                return Err(PrivateAgentHostError::Alias);
            }
            return Ok(PrivateReplicaEstablishmentDisposition::AlreadyPresent);
        }
        let mut plan = read_replica_establishment_plan(&stage, &self.node_key)?;
        require_exact_plan_prepared(&plan, prepared, &self.scope)?;
        let archive = decode_host_archive(&plan.archive, true)?;
        if !archive.stable_import_certificates.is_empty() {
            return Err(PrivateAgentHostError::Corrupt);
        }
        let mut source = authenticate_replica_source(
            &archive,
            plan.route,
            plan.authority,
            &self.scope,
            &self.node_key,
            plan.management_gas,
            plan.source_hash,
            node_authority,
        )?;

        if let Some(completion) = &plan.completion {
            publish_completed_replica_establishment_with_stop(
                self,
                &plan,
                completion,
                node_authority,
                stop,
            )?;
            return Ok(PrivateReplicaEstablishmentDisposition::Published);
        }

        let establishment_identity = replica_establishment_identity_commitment(
            plan.route,
            plan.owner,
            &plan.destination,
            plan.authority,
            plan.source_hash,
            plan.management_gas,
        )?;
        let staged = open_or_create_replica_genesis(
            &stage,
            &mut source,
            &self.scope.local_node,
            establishment_identity,
            node_authority,
            stop,
        )?;
        let mut staged = replay_replica_controls(
            &stage,
            staged,
            &source.rows,
            plan.route,
            plan.authority,
            &self.scope.local_node,
            &self.node_key,
            plan.management_gas,
            node_authority,
            stop,
        )?;
        import_replica_objects(
            &stage,
            &mut staged,
            &source,
            &self.scope.local_node,
            &self.node_key,
            stop,
        )?;
        if staged.store.core_position()? != source.final_target {
            return Err(PrivateAgentHostError::Corrupt);
        }
        let final_lineage = staged.runtime_image.lineage_commitment();
        let expected_seal = PrivateRuntimeImage::replica_establishment_seal(
            establishment_identity,
            source.final_target.commitment(),
            final_lineage,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
        replica_establishment_stop(stop, ReplicaEstablishmentStop::BeforeRuntimeSealed)?;
        let sealed = staged
            .runtime_image
            .seal_replica_establishment(establishment_identity, source.final_target)
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        if staged.runtime_image.establishment_completion() != Some(expected_seal) {
            let key = staged
                .data_keys
                .get(&sealed.store().epoch())
                .ok_or(PrivateAgentHostError::Unauthorized)?;
            replace_regular_file_synced(
                &stage.join(RUNTIME_STATE_FILE),
                &encrypt_runtime_image_sidecar(key, &sealed)?,
            )?;
        }
        staged.runtime_image = sealed;
        replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterRuntimeSealed)?;
        let final_image = staged.runtime_image.commitment();
        let completion = ReplicaEstablishmentCompletion {
            store: source.final_target.commitment(),
            runtime_image: final_image,
            runtime_lineage: final_lineage,
            establishment_tag: expected_seal,
        };
        drop(staged);
        plan.completion = Some(completion.clone());
        replace_replica_establishment_plan_with_stop(
            &stage,
            &encode_replica_establishment_plan(&plan, &self.node_key)?,
            stop,
        )?;
        publish_completed_replica_establishment_with_stop(
            self,
            &plan,
            &completion,
            node_authority,
            stop,
        )?;
        Ok(PrivateReplicaEstablishmentDisposition::Published)
    }

    /// Authenticate, durably stage, replay, and publish one cross-node
    /// replica in a single call. The split prepare/resume API remains
    /// available to crash-injection and orchestration callers.
    pub(crate) fn establish_replica<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        route: ManagedAgentTarget,
        archive_bytes: &[u8],
        authority: AuthorityActorTarget,
        node_authority: &V,
    ) -> Result<PrivateReplicaEstablishmentDisposition, PrivateAgentHostError> {
        let prepared =
            self.prepare_replica_establishment(route, archive_bytes, authority, node_authority)?;
        self.resume_replica_establishment(prepared, node_authority)
    }
}

fn require_exact_plan_request(
    plan: &ReplicaEstablishmentPlan,
    route: ManagedAgentTarget,
    owner: PrincipalId,
    destination: &PrivateNodeIdentity,
    authority: AuthorityActorTarget,
    source_hash: Hash,
) -> Result<(), PrivateAgentHostError> {
    if plan.route != route
        || plan.owner != owner
        || &plan.destination != destination
        || plan.authority != authority
        || plan.source_hash != source_hash
        || plan.source_hash == Hash::ZERO
    {
        return Err(PrivateAgentHostError::Alias);
    }
    Ok(())
}

fn replica_establishment_identity_commitment(
    route: ManagedAgentTarget,
    owner: PrincipalId,
    destination: &PrivateNodeIdentity,
    authority: AuthorityActorTarget,
    source_hash: Hash,
    management_gas: u64,
) -> Result<Hash, PrivateAgentHostError> {
    if !route.is_valid()
        || route.owner != owner
        || route.profile != AgentProfile::Private
        || owner == PrincipalId::ZERO
        || !destination.validate()
        || destination.principal != owner
        || !authority.is_valid()
        || authority.space != route.space
        || source_hash == Hash::ZERO
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    let destination = destination
        .encode()
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    let mut preimage = Vec::new();
    let mut encoder = Encoder(&mut preimage);
    encode_managed_target(&mut encoder, route);
    encoder.fixed(owner.as_bytes());
    encoder.bytes(&destination);
    encoder.fixed(authority.space.as_bytes());
    encoder.fixed(authority.system_agent.as_bytes());
    encoder.fixed(authority.system_runtime_deployment.as_bytes());
    encode_authority_binding(&mut encoder, authority.binding);
    encoder.fixed(source_hash.as_bytes());
    encoder.u64(management_gas);
    let commitment = Hash::digest(ESTABLISHMENT_IDENTITY_HASH_DOMAIN, &[&preimage]);
    if commitment == Hash::ZERO {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    Ok(commitment)
}

fn require_replica_establishment_completion_tag(
    establishment_identity: Hash,
    completion: &ReplicaEstablishmentCompletion,
) -> Result<(), PrivateAgentHostError> {
    if completion.store == Hash::ZERO
        || completion.runtime_image == Hash::ZERO
        || completion.runtime_lineage == Hash::ZERO
        || completion.establishment_tag == Hash::ZERO
        || PrivateRuntimeImage::replica_establishment_seal(
            establishment_identity,
            completion.store,
            completion.runtime_lineage,
        )
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?
            != completion.establishment_tag
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    Ok(())
}

fn require_exact_plan_prepared(
    plan: &ReplicaEstablishmentPlan,
    prepared: PreparedPrivateReplicaEstablishment,
    scope: &RootScope,
) -> Result<(), PrivateAgentHostError> {
    require_exact_plan_request(
        plan,
        prepared.route,
        scope.owner,
        &scope.local_node,
        prepared.authority,
        prepared.source_hash,
    )?;
    if plan.management_gas != prepared.management_gas {
        return Err(PrivateAgentHostError::Alias);
    }
    Ok(())
}

fn require_exact_receipt_request(
    receipt: &ReplicaEstablishmentReceipt,
    route: ManagedAgentTarget,
    owner: PrincipalId,
    destination: &PrivateNodeIdentity,
    authority: AuthorityActorTarget,
    source_hash: Hash,
) -> Result<(), PrivateAgentHostError> {
    if receipt.route != route
        || receipt.owner != owner
        || &receipt.destination != destination
        || receipt.authority != authority
        || receipt.source_hash != source_hash
        || receipt.source_hash == Hash::ZERO
    {
        return Err(PrivateAgentHostError::Alias);
    }
    Ok(())
}

fn require_exact_receipt_prepared(
    receipt: &ReplicaEstablishmentReceipt,
    prepared: PreparedPrivateReplicaEstablishment,
    scope: &RootScope,
) -> Result<(), PrivateAgentHostError> {
    require_exact_receipt_request(
        receipt,
        prepared.route,
        scope.owner,
        &scope.local_node,
        prepared.authority,
        prepared.source_hash,
    )?;
    if receipt.management_gas != prepared.management_gas {
        return Err(PrivateAgentHostError::Alias);
    }
    Ok(())
}

fn encode_replica_establishment_plan(
    plan: &ReplicaEstablishmentPlan,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<Vec<u8>, PrivateAgentHostError> {
    if !plan.route.is_valid()
        || plan.route.owner != plan.owner
        || plan.route.profile != AgentProfile::Private
        || plan.owner == PrincipalId::ZERO
        || !plan.destination.validate()
        || plan.destination.principal != plan.owner
        || plan.destination.encryption_public_key != node_key.public_key()
        || !plan.authority.is_valid()
        || plan.authority.space != plan.route.space
        || plan.source_hash == Hash::ZERO
        || plan.archive.len() > MAX_PRIVATE_HOST_ARCHIVE_BYTES
        || plan.completion.as_ref().is_some_and(|completion| {
            completion.store == Hash::ZERO
                || completion.runtime_image == Hash::ZERO
                || completion.runtime_lineage == Hash::ZERO
                || completion.establishment_tag == Hash::ZERO
        })
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    if let Some(completion) = &plan.completion {
        require_replica_establishment_completion_tag(
            replica_establishment_identity_commitment(
                plan.route,
                plan.owner,
                &plan.destination,
                plan.authority,
                plan.source_hash,
                plan.management_gas,
            )?,
            completion,
        )?;
    }
    let destination = plan
        .destination
        .encode()
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ESTABLISHMENT_PLAN_MAGIC);
    bytes.extend_from_slice(&ESTABLISHMENT_PLAN_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encode_managed_target(&mut encoder, plan.route);
    encoder.fixed(plan.owner.as_bytes());
    encoder.bytes(&destination);
    encoder.fixed(plan.authority.space.as_bytes());
    encoder.fixed(plan.authority.system_agent.as_bytes());
    encoder.fixed(plan.authority.system_runtime_deployment.as_bytes());
    encode_authority_binding(&mut encoder, plan.authority.binding);
    encoder.fixed(plan.source_hash.as_bytes());
    encoder.u64(plan.management_gas);
    encoder.bytes(&plan.archive);
    encoder.option(&plan.completion, |encoder, completion| {
        encoder.fixed(completion.store.as_bytes());
        encoder.fixed(completion.runtime_image.as_bytes());
        encoder.fixed(completion.runtime_lineage.as_bytes());
        encoder.fixed(completion.establishment_tag.as_bytes());
    });
    if bytes.len().saturating_add(32) > MAX_ESTABLISHMENT_PLAN_BYTES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let hash = Hash::digest(ESTABLISHMENT_PLAN_HASH_DOMAIN, &[&bytes]);
    let authenticator = node_key.replica_establishment_plan_authenticator(hash)?;
    bytes.extend_from_slice(authenticator.as_bytes());
    Ok(bytes)
}

fn decode_replica_establishment_plan(
    bytes: &[u8],
    node_key: &PrivateNodeDecryptionKey,
) -> Result<ReplicaEstablishmentPlan, PrivateAgentHostError> {
    if bytes.len() > MAX_ESTABLISHMENT_PLAN_BYTES || bytes.len() < 32 {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let authenticated_len = bytes
        .len()
        .checked_sub(32)
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4).map_err(map_decode)? != ESTABLISHMENT_PLAN_MAGIC
        || decoder.u16().map_err(map_decode)? != ESTABLISHMENT_PLAN_VERSION
        || Hash(decoder.fixed().map_err(map_decode)?) != vos_agent_sdk::RUNTIME_ABI_ID
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let route = decode_managed_target(&mut decoder).map_err(map_decode)?;
    let owner = PrincipalId(decoder.fixed().map_err(map_decode)?);
    let destination_wire = decoder
        .bytes_bounded(MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES)
        .map_err(map_decode)?;
    let destination = PrivateNodeIdentity::decode(&destination_wire)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let authority = AuthorityActorTarget {
        space: SpaceId(decoder.fixed().map_err(map_decode)?),
        system_agent: AgentId(decoder.fixed().map_err(map_decode)?),
        system_runtime_deployment: DeploymentId(decoder.fixed().map_err(map_decode)?),
        binding: decode_authority_binding(&mut decoder).map_err(map_decode)?,
    };
    let plan = ReplicaEstablishmentPlan {
        route,
        owner,
        destination,
        authority,
        source_hash: Hash(decoder.fixed().map_err(map_decode)?),
        management_gas: decoder.u64().map_err(map_decode)?,
        archive: decode_establishment_archive(&mut decoder).map_err(map_decode)?,
        completion: match decoder.u8().map_err(map_decode)? {
            0 => None,
            1 => Some(ReplicaEstablishmentCompletion {
                store: Hash(decoder.fixed().map_err(map_decode)?),
                runtime_image: Hash(decoder.fixed().map_err(map_decode)?),
                runtime_lineage: Hash(decoder.fixed().map_err(map_decode)?),
                establishment_tag: Hash(decoder.fixed().map_err(map_decode)?),
            }),
            _ => return Err(PrivateAgentHostError::Corrupt),
        },
    };
    let authenticator = Hash(decoder.fixed().map_err(map_decode)?);
    let expected_authenticator =
        node_key.replica_establishment_plan_authenticator(Hash::digest(
            ESTABLISHMENT_PLAN_HASH_DOMAIN,
            &[&bytes[..authenticated_len]],
        ))?;
    let exhausted = decoder.exhausted();
    let exact_length = authenticated_len + 32 == bytes.len();
    let authentic = bool::from(
        expected_authenticator
            .as_bytes()
            .ct_eq(authenticator.as_bytes()),
    );
    let canonical = encode_replica_establishment_plan(&plan, node_key)?;
    if !exhausted || !exact_length || !authentic || canonical.as_slice() != bytes {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(plan)
}

fn decode_establishment_archive(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, DecodeError> {
    // The shared consensus-wire decoder deliberately caps a single dynamic
    // field at 64 MiB. A complete encrypted HostArchive has its own stricter
    // schema cap and may validly reach 160 MiB, so decode this one capsule
    // against that explicit bound without weakening the shared codec.
    let len = decoder.u32()? as usize;
    if len > MAX_PRIVATE_HOST_ARCHIVE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let source = decoder.take(len)?;
    let mut archive = Vec::new();
    archive
        .try_reserve_exact(len)
        .map_err(|_| DecodeError::LimitExceeded)?;
    archive.extend_from_slice(source);
    Ok(archive)
}

#[cfg(test)]
pub(super) fn decode_replica_establishment_plan_for_test(
    bytes: &[u8],
    node_key: &PrivateNodeDecryptionKey,
) -> Result<(), PrivateAgentHostError> {
    decode_replica_establishment_plan(bytes, node_key).map(drop)
}

fn read_replica_establishment_plan(
    slot: &Path,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<ReplicaEstablishmentPlan, PrivateAgentHostError> {
    let temporary = slot.join(ESTABLISHMENT_PLAN_WRITE_FILE);
    if fs::symlink_metadata(&temporary).is_ok() {
        require_regular_file(&temporary)?;
        remove_regular_file_if_present(&temporary)?;
        sync_directory(slot)?;
    }
    let bytes = read_bounded_file(
        &slot.join(ESTABLISHMENT_PLAN_FILE),
        MAX_ESTABLISHMENT_PLAN_BYTES,
    )?;
    decode_replica_establishment_plan(&bytes, node_key)
}

fn publish_replica_establishment_plan(
    slot: &Path,
    bytes: &[u8],
) -> Result<(), PrivateAgentHostError> {
    let temporary = slot.join(ESTABLISHMENT_PLAN_WRITE_FILE);
    let canonical = slot.join(ESTABLISHMENT_PLAN_FILE);
    write_new_synced(&temporary, bytes)?;
    fs::rename(temporary, canonical).map_err(map_io)?;
    sync_directory(slot)
}

fn replace_replica_establishment_plan_with_stop(
    slot: &Path,
    bytes: &[u8],
    stop: ReplicaEstablishmentStop,
) -> Result<(), PrivateAgentHostError> {
    let temporary = slot.join(ESTABLISHMENT_PLAN_WRITE_FILE);
    let canonical = slot.join(ESTABLISHMENT_PLAN_FILE);
    require_regular_file(&canonical)?;
    remove_regular_file_if_present(&temporary)?;
    write_new_synced(&temporary, bytes)?;
    replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterCompletionPlanTemporary)?;
    fs::rename(temporary, canonical).map_err(map_io)?;
    sync_directory(slot)?;
    replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterCompletionPlanCommitted)
}

fn replica_establishment_receipt_from_plan(
    plan: &ReplicaEstablishmentPlan,
) -> Result<ReplicaEstablishmentReceipt, PrivateAgentHostError> {
    Ok(ReplicaEstablishmentReceipt {
        route: plan.route,
        owner: plan.owner,
        destination: plan.destination.clone(),
        authority: plan.authority,
        source_hash: plan.source_hash,
        management_gas: plan.management_gas,
        completion: plan
            .completion
            .clone()
            .ok_or(PrivateAgentHostError::Corrupt)?,
    })
}

fn encode_replica_establishment_receipt(
    receipt: &ReplicaEstablishmentReceipt,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<Vec<u8>, PrivateAgentHostError> {
    if !receipt.route.is_valid()
        || receipt.route.owner != receipt.owner
        || receipt.route.profile != AgentProfile::Private
        || receipt.owner == PrincipalId::ZERO
        || !receipt.destination.validate()
        || receipt.destination.principal != receipt.owner
        || receipt.destination.encryption_public_key != node_key.public_key()
        || !receipt.authority.is_valid()
        || receipt.authority.space != receipt.route.space
        || receipt.source_hash == Hash::ZERO
        || receipt.completion.store == Hash::ZERO
        || receipt.completion.runtime_image == Hash::ZERO
        || receipt.completion.runtime_lineage == Hash::ZERO
        || receipt.completion.establishment_tag == Hash::ZERO
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    require_replica_establishment_completion_tag(
        replica_establishment_identity_commitment(
            receipt.route,
            receipt.owner,
            &receipt.destination,
            receipt.authority,
            receipt.source_hash,
            receipt.management_gas,
        )?,
        &receipt.completion,
    )?;
    let destination = receipt
        .destination
        .encode()
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ESTABLISHMENT_RECEIPT_MAGIC);
    bytes.extend_from_slice(&ESTABLISHMENT_RECEIPT_VERSION.to_le_bytes());
    bytes.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encode_managed_target(&mut encoder, receipt.route);
    encoder.fixed(receipt.owner.as_bytes());
    encoder.bytes(&destination);
    encoder.fixed(receipt.authority.space.as_bytes());
    encoder.fixed(receipt.authority.system_agent.as_bytes());
    encoder.fixed(receipt.authority.system_runtime_deployment.as_bytes());
    encode_authority_binding(&mut encoder, receipt.authority.binding);
    encoder.fixed(receipt.source_hash.as_bytes());
    encoder.u64(receipt.management_gas);
    encoder.fixed(receipt.completion.store.as_bytes());
    encoder.fixed(receipt.completion.runtime_image.as_bytes());
    encoder.fixed(receipt.completion.runtime_lineage.as_bytes());
    encoder.fixed(receipt.completion.establishment_tag.as_bytes());
    if bytes.len().saturating_add(32) > MAX_ESTABLISHMENT_RECEIPT_BYTES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let hash = Hash::digest(ESTABLISHMENT_RECEIPT_HASH_DOMAIN, &[&bytes]);
    let authenticator = node_key.replica_establishment_plan_authenticator(hash)?;
    bytes.extend_from_slice(authenticator.as_bytes());
    Ok(bytes)
}

fn decode_replica_establishment_receipt(
    bytes: &[u8],
    node_key: &PrivateNodeDecryptionKey,
) -> Result<ReplicaEstablishmentReceipt, PrivateAgentHostError> {
    if bytes.len() > MAX_ESTABLISHMENT_RECEIPT_BYTES || bytes.len() < 32 {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    let authenticated_len = bytes
        .len()
        .checked_sub(32)
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4).map_err(map_decode)? != ESTABLISHMENT_RECEIPT_MAGIC
        || decoder.u16().map_err(map_decode)? != ESTABLISHMENT_RECEIPT_VERSION
        || Hash(decoder.fixed().map_err(map_decode)?) != vos_agent_sdk::RUNTIME_ABI_ID
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let receipt = ReplicaEstablishmentReceipt {
        route: decode_managed_target(&mut decoder).map_err(map_decode)?,
        owner: PrincipalId(decoder.fixed().map_err(map_decode)?),
        destination: PrivateNodeIdentity::decode(
            &decoder
                .bytes_bounded(MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES)
                .map_err(map_decode)?,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?,
        authority: AuthorityActorTarget {
            space: SpaceId(decoder.fixed().map_err(map_decode)?),
            system_agent: AgentId(decoder.fixed().map_err(map_decode)?),
            system_runtime_deployment: DeploymentId(decoder.fixed().map_err(map_decode)?),
            binding: decode_authority_binding(&mut decoder).map_err(map_decode)?,
        },
        source_hash: Hash(decoder.fixed().map_err(map_decode)?),
        management_gas: decoder.u64().map_err(map_decode)?,
        completion: ReplicaEstablishmentCompletion {
            store: Hash(decoder.fixed().map_err(map_decode)?),
            runtime_image: Hash(decoder.fixed().map_err(map_decode)?),
            runtime_lineage: Hash(decoder.fixed().map_err(map_decode)?),
            establishment_tag: Hash(decoder.fixed().map_err(map_decode)?),
        },
    };
    let authenticator = Hash(decoder.fixed().map_err(map_decode)?);
    let expected_authenticator =
        node_key.replica_establishment_plan_authenticator(Hash::digest(
            ESTABLISHMENT_RECEIPT_HASH_DOMAIN,
            &[&bytes[..authenticated_len]],
        ))?;
    if !decoder.exhausted()
        || authenticated_len + 32 != bytes.len()
        || !bool::from(
            expected_authenticator
                .as_bytes()
                .ct_eq(authenticator.as_bytes()),
        )
        || encode_replica_establishment_receipt(&receipt, node_key)?.as_slice() != bytes
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(receipt)
}

#[cfg(test)]
pub(super) fn decode_replica_establishment_receipt_for_test(
    bytes: &[u8],
    node_key: &PrivateNodeDecryptionKey,
) -> Result<(), PrivateAgentHostError> {
    decode_replica_establishment_receipt(bytes, node_key).map(drop)
}

#[cfg(test)]
pub(super) fn maximum_replica_establishment_codec_lengths_for_test(
    template: &[u8],
    node_key: &PrivateNodeDecryptionKey,
) -> Result<(usize, usize), PrivateAgentHostError> {
    let mut plan = decode_replica_establishment_plan(template, node_key)?;
    plan.destination.transport_identity =
        vec![0xa5; vos_agent_sdk::private::MAX_TRANSPORT_IDENTITY_BYTES];
    plan.destination.node = NodeId::of_authenticated_peer(&plan.destination.transport_identity);
    plan.archive.resize(MAX_PRIVATE_HOST_ARCHIVE_BYTES, 0x5a);
    let establishment_identity = replica_establishment_identity_commitment(
        plan.route,
        plan.owner,
        &plan.destination,
        plan.authority,
        plan.source_hash,
        plan.management_gas,
    )?;
    let store = Hash([0x61; 32]);
    let runtime_lineage = Hash([0x62; 32]);
    plan.completion = Some(ReplicaEstablishmentCompletion {
        store,
        runtime_image: Hash([0x63; 32]),
        runtime_lineage,
        establishment_tag: PrivateRuntimeImage::replica_establishment_seal(
            establishment_identity,
            store,
            runtime_lineage,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?,
    });

    let encoded_plan = encode_replica_establishment_plan(&plan, node_key)?;
    let plan_len = encoded_plan.len();
    if plan_len > MAX_ESTABLISHMENT_PLAN_BYTES {
        return Err(PrivateAgentHostError::Corrupt);
    }
    if decode_replica_establishment_plan(&encoded_plan, node_key)? != plan {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let receipt = replica_establishment_receipt_from_plan(&plan)?;
    let encoded_receipt = encode_replica_establishment_receipt(&receipt, node_key)?;
    let receipt_len = encoded_receipt.len();
    if receipt_len > MAX_ESTABLISHMENT_RECEIPT_BYTES {
        return Err(PrivateAgentHostError::Corrupt);
    }
    if decode_replica_establishment_receipt(&encoded_receipt, node_key)? != receipt {
        return Err(PrivateAgentHostError::Corrupt);
    }

    let mut oversized = encoded_plan;
    oversized.resize(MAX_ESTABLISHMENT_PLAN_BYTES + 1, 0);
    if decode_replica_establishment_plan(&oversized, node_key)
        != Err(PrivateAgentHostError::LimitExceeded)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok((plan_len, receipt_len))
}

fn cleanup_replica_establishment_receipt_write(slot: &Path) -> Result<(), PrivateAgentHostError> {
    let temporary = slot.join(ESTABLISHMENT_RECEIPT_WRITE_FILE);
    if fs::symlink_metadata(&temporary).is_ok() {
        require_regular_file(&temporary)?;
        remove_regular_file_if_present(&temporary)?;
        sync_directory(slot)?;
    }
    Ok(())
}

fn read_replica_establishment_receipt(
    slot: &Path,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<ReplicaEstablishmentReceipt, PrivateAgentHostError> {
    cleanup_replica_establishment_receipt_write(slot)?;
    let bytes = read_bounded_file(
        &slot.join(ESTABLISHMENT_RECEIPT_FILE),
        MAX_ESTABLISHMENT_RECEIPT_BYTES,
    )?;
    decode_replica_establishment_receipt(&bytes, node_key)
}

fn publish_replica_establishment_receipt(
    slot: &Path,
    receipt: &ReplicaEstablishmentReceipt,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<(), PrivateAgentHostError> {
    publish_replica_establishment_receipt_with_stop(
        slot,
        receipt,
        node_key,
        ReplicaEstablishmentStop::Never,
    )
}

fn publish_replica_establishment_receipt_with_stop(
    slot: &Path,
    receipt: &ReplicaEstablishmentReceipt,
    node_key: &PrivateNodeDecryptionKey,
    stop: ReplicaEstablishmentStop,
) -> Result<(), PrivateAgentHostError> {
    cleanup_replica_establishment_receipt_write(slot)?;
    let canonical = slot.join(ESTABLISHMENT_RECEIPT_FILE);
    if fs::symlink_metadata(&canonical).is_ok() {
        if read_replica_establishment_receipt(slot, node_key)? != *receipt {
            return Err(PrivateAgentHostError::Alias);
        }
        return Ok(());
    }
    let bytes = encode_replica_establishment_receipt(receipt, node_key)?;
    let temporary = slot.join(ESTABLISHMENT_RECEIPT_WRITE_FILE);
    write_new_synced(&temporary, &bytes)?;
    replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterReceiptTemporary)?;
    fs::rename(&temporary, &canonical).map_err(map_io)?;
    sync_directory(slot)?;
    replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterReceiptPublished)
}

#[cfg(test)]
pub(super) fn rewrite_replica_establishment_receipt_lineage_for_test(
    slot: &Path,
    node_key: &PrivateNodeDecryptionKey,
    runtime_lineage: Hash,
) -> Result<(), PrivateAgentHostError> {
    if runtime_lineage == Hash::ZERO {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    let mut receipt = read_replica_establishment_receipt(slot, node_key)?;
    let identity = replica_establishment_identity_commitment(
        receipt.route,
        receipt.owner,
        &receipt.destination,
        receipt.authority,
        receipt.source_hash,
        receipt.management_gas,
    )?;
    receipt.completion.runtime_lineage = runtime_lineage;
    receipt.completion.establishment_tag = PrivateRuntimeImage::replica_establishment_seal(
        identity,
        receipt.completion.store,
        runtime_lineage,
    )
    .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    replace_regular_file_synced(
        &slot.join(ESTABLISHMENT_RECEIPT_FILE),
        &encode_replica_establishment_receipt(&receipt, node_key)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn authenticate_replica_source<V: PrivateNodeAuthorityVerifier>(
    archive: &HostArchive,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
    scope: &RootScope,
    node_key: &PrivateNodeDecryptionKey,
    management_gas: u64,
    source_hash: Hash,
    node_authority: &V,
) -> Result<VerifiedReplicaSource, PrivateAgentHostError> {
    if !route.is_valid()
        || route.profile != AgentProfile::Private
        || route.owner != scope.owner
        || archive.space != route.space
        || archive.agent != route.agent
        || route.space != scope.space
        || authority.space != route.space
        || !archive.stable_import_certificates.is_empty()
    {
        return Err(PrivateAgentHostError::InvalidScope);
    }
    let canonical_archive = encode_host_archive(archive, true, MAX_PRIVATE_HOST_ARCHIVE_BYTES)?;
    if Hash::digest(
        ESTABLISHMENT_SOURCE_HASH_DOMAIN,
        &[canonical_archive.as_slice()],
    ) != source_hash
    {
        return Err(PrivateAgentHostError::Alias);
    }

    // This first parse is explicitly not a trust boundary. The signed Create
    // descriptor below closes the recovery-key binding after PVB3 has proved
    // the complete internally consistent Store/control chain.
    let claim = encrypted_backup_genesis_claim(&archive.store)?;
    let backup = verify_encrypted_backup(
        &archive.store,
        route.space,
        route.agent,
        scope.owner,
        claim.recovery_public_key(),
        claim.recovery_encryption_public_key(),
        node_authority,
    )?;
    let replay_rows = backup.replay_rows()?;
    require_exact_local_member(backup.final_authorized_nodes(), &scope.local_node)?;
    let (data_keys, has_historical_admission) =
        unwrap_replica_archive_keyring(&backup, &replay_rows, &scope.local_node, node_key)?;
    if !has_historical_admission || data_keys.len() != backup.key_epochs().len() {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    for epoch in backup.key_epochs() {
        if data_keys
            .get(&epoch.epoch)
            .is_none_or(|key| key.commitment() != epoch.data_key_commitment)
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
    }
    let final_epoch = backup
        .key_epochs()
        .last()
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let _final_owner_key = unwrap_owner_key(final_epoch, &scope.local_node, node_key)?;
    let final_data_key = data_keys
        .get(&final_epoch.epoch)
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let plaintext = decrypt_archive_plaintext(archive, final_epoch.epoch, final_data_key)?;
    validate_archive_plaintext(&plaintext, route.space, route.agent, scope.owner)?;
    validate_replica_descriptor_and_package(
        &plaintext,
        &backup,
        route,
        authority,
        claim.recovery_public_key(),
        claim.recovery_encryption_public_key(),
    )?;
    let admitted_runtime = admit_runtime_package(&plaintext.runtime_package)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;

    let creation_receipt =
        extract_archive_creation_receipt(archive, final_epoch.epoch, final_data_key)?;
    validate_private_creation_receipt(
        &plaintext.descriptor,
        &creation_receipt,
        creation_receipt.selector.valid_from,
    )?;
    let recovery_recipient = DurableRecoveryRecipient::from_durable_keystore(
        claim.recovery_public_key(),
        claim.recovery_encryption_public_key(),
    )?;
    let create = PrivateAgentCreate {
        descriptor: &plaintext.descriptor,
        nodes: backup.genesis_nodes(),
        recovery_recipient,
        runtime_package: &admitted_runtime,
        bootstrap_metadata: &plaintext.bootstrap_metadata,
        creation_receipt: &creation_receipt,
        observed_at: creation_receipt.selector.valid_from,
    };
    let genesis_state = execute_private_runtime_genesis(&create, management_gas)?;
    let genesis_stable = super::super::private_runtime::PrivateRuntimeStableProjection::genesis(
        route,
        plaintext.descriptor.commitment(),
        plaintext.descriptor.runtime_package.clone(),
        creation_receipt.commitment(),
        plaintext.descriptor.initial_resource_policy(),
        &genesis_state.control,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;

    let mut rows = Vec::new();
    rows.try_reserve_exact(replay_rows.len())
        .map_err(|_| PrivateAgentHostError::LimitExceeded)?;
    let mut prior_stable = genesis_stable;
    let mut prior_applied_at = creation_receipt.selector.valid_from;
    let mut replayed_state = genesis_state.clone();
    for row in replay_rows {
        let source_application = row.source_runtime_application();
        let source_stable_projection = source_application
            .successor_stable_projection()
            .ok_or(PrivateAgentHostError::Corrupt)?
            .commitment();
        authenticate_replica_source_runtime_application_endpoint(
            &plaintext.descriptor,
            row.control(),
            row.index().resulting_epoch,
            source_application,
            row.source_authority_evidence(),
            route,
            authority,
        )?;
        if source_application.predecessor_stable_projection() != &prior_stable
            || source_application.applied_at() < prior_applied_at
        {
            return Err(PrivateAgentHostError::Corrupt);
        }
        replayed_state = preflight_replica_runtime_row(
            &admitted_runtime,
            route,
            management_gas,
            &prior_stable,
            &replayed_state,
            row.control(),
            source_application,
        )?;
        prior_stable = source_application
            .successor_stable_projection()
            .ok_or(PrivateAgentHostError::Corrupt)?
            .clone();
        prior_applied_at = source_application.applied_at();
        rows.push(VerifiedReplicaReplayRow {
            index: row.index().clone(),
            control: row.control().clone(),
            source_application: source_application.clone(),
            source_evidence: row.source_authority_evidence().to_vec(),
            source_stable_projection,
        });
    }

    for object in backup.objects() {
        let key = data_keys
            .get(&object.epoch)
            .ok_or(PrivateAgentHostError::Corrupt)?;
        let plaintext = Zeroizing::new(decrypt_private_object(key, object)?);
        drop(plaintext);
    }
    let final_target = backup.final_target()?;
    Ok(VerifiedReplicaSource {
        backup,
        plaintext,
        creation_receipt,
        data_keys,
        rows,
        final_target,
        genesis_state,
    })
}

/// Authenticate a source replay row without adopting its node-local reopen
/// commitment.  A source archive may itself come from an imported replica:
/// its PAPL is then destination-local while its authority PSE necessarily
/// names the earlier executor's PCRS.  The signed PSP is the sole portable
/// convergence target, so neither source PCRS nor source PSI participates in
/// destination admission.
#[allow(clippy::too_many_arguments)]
fn authenticate_replica_source_runtime_application_endpoint(
    descriptor: &AgentDescriptor,
    control: &PrivateControlRecord,
    resulting_epoch: u64,
    application: &PrivateRuntimeApplication,
    evidence_wire: &[u8],
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
) -> Result<(), PrivateAgentHostError> {
    application
        .verify_with(
            descriptor,
            &RawAuthorityVerifier,
            &RawRecoveryAuthorityProofVerifier,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let successor = application
        .successor_stable_projection()
        .ok_or(PrivateAgentHostError::Corrupt)?;
    if !application.is_complete()
        || application.managed() != route
        || application.control() != control
        || application.expected_successor_store().control_head() != Some(control.commitment())
        || application.expected_successor_store().epoch() != resulting_epoch
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let evidence = PrivateControlAuthorityEvidence::decode(evidence_wire)?;
    let issuance = AuthorityOperationIssuanceAck::decode(&evidence.issuance_ack)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let application_ack = PrivateControlApplicationAck::decode(&evidence.application_ack)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if authority.space != route.space
        || authority.binding != descriptor.authority
        || application.issuance() != &issuance
        || application_ack.application.stable_projection != successor.commitment()
        || application_ack.application.applied_at != application.applied_at()
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    evidence.verify_for_stable_projection(
        control,
        resulting_epoch,
        successor.commitment(),
        route,
        authority,
    )?;
    Ok(())
}

fn preflight_replica_runtime_row(
    runtime: &AdmittedRuntimePackage,
    route: ManagedAgentTarget,
    management_gas: u64,
    predecessor_projection: &super::super::private_runtime::PrivateRuntimeStableProjection,
    predecessor_state: &RuntimeState,
    control: &PrivateControlRecord,
    application: &PrivateRuntimeApplication,
) -> Result<RuntimeState, PrivateAgentHostError> {
    let (state, success) = match &control.operation {
        PrivateControlOperation::Invite { .. }
        | PrivateControlOperation::Revoke { .. }
        | PrivateControlOperation::RotateKeys { .. }
        | PrivateControlOperation::Recover { .. } => (
            predecessor_state.clone(),
            PrivateRuntimeSuccess::ControlOnly,
        ),
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => {
            let mutation = application
                .mutation()
                .cloned()
                .ok_or(PrivateAgentHostError::Corrupt)?;
            let request = ManagementRequest::PrivateControl {
                control: Box::new(control.clone()),
                mutation: Box::new(mutation),
            };
            if !request.is_valid() {
                return Err(PrivateAgentHostError::InvalidArtifact);
            }
            let work = RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: route.space,
                agent: route.agent,
                runtime_deployment: route.runtime_deployment,
                state: predecessor_state.clone(),
                request: Box::new(request.clone()),
                authority: Some(Box::new(application.receipt().clone())),
                observed_slot: application.applied_at(),
            };
            let wire = work
                .encode()
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            let transition = execute_canonical_wire::<RuntimeTransition>(
                runtime.program_bytes(),
                management_gas,
                &wire,
            )
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            match classify_private_runtime_control_transition_for_replay(
                route,
                predecessor_state,
                predecessor_projection.active_resource_policy(),
                &request,
                transition,
            )
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?
            {
                PrivateRuntimeControlDisposition::Applied { state, success } => (state, success),
                PrivateRuntimeControlDisposition::RetiredUnapplied { .. } => {
                    return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
                }
            }
        }
    };
    let successor = application
        .successor_stable_projection()
        .ok_or(PrivateAgentHostError::Corrupt)?;
    if application.success() != Some(&success)
        || !successor.matches_replayed_successor(
            predecessor_projection,
            control,
            application.full_replay(),
            &success,
            &state,
        )
    {
        return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
    }
    Ok(state)
}

fn validate_replica_descriptor_and_package(
    plaintext: &AgentPlaintext,
    backup: &VerifiedEncryptedBackup,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
    recovery_public_key: [u8; 32],
    recovery_encryption_public_key: [u8; 32],
) -> Result<(), PrivateAgentHostError> {
    let descriptor = &plaintext.descriptor;
    descriptor
        .validate()
        .map_err(|_| PrivateAgentHostError::InvalidDescriptor)?;
    if descriptor.identity.profile != AgentProfile::Private
        || managed_target_for_descriptor(descriptor) != route
        || descriptor.identity.owner != backup.binding().owner
        || descriptor.authority != authority.binding
        || descriptor.private_recovery
            != Some(PrivateRecoveryBinding {
                signing_key_commitment: recovery_signing_public_key_commitment(
                    &recovery_public_key,
                ),
                encryption_public_key: recovery_encryption_public_key,
            })
        || descriptor.replicas.len() != backup.genesis_nodes().len()
    {
        return Err(PrivateAgentHostError::InvalidDescriptor);
    }
    for (replica, node) in descriptor.replicas.iter().zip(backup.genesis_nodes()) {
        if replica.node != node.node
            || replica.principal != node.principal
            || replica.principal != descriptor.identity.owner
            || replica.role != ReplicaRole::Observer
        {
            return Err(PrivateAgentHostError::InvalidMembership);
        }
    }
    let admitted = admit_runtime_package(&plaintext.runtime_package)
        .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    if descriptor.runtime_package != *admitted.package_ref()
        || descriptor.identity.runtime_deployment != admitted.deployment()
        || descriptor.identity.runtime_program != admitted.program()
        || descriptor.identity.runtime_producer != admitted.producer()
        || descriptor.runtime_contract != admitted.manifest().contract
        || descriptor.capabilities != admitted.capabilities()
        || plaintext.runtime_package.len() > MAX_PRIVATE_CIPHERTEXT_BYTES.saturating_sub(256)
        || plaintext.bootstrap_metadata.len() > MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES
    {
        return Err(PrivateAgentHostError::InvalidArtifact);
    }
    Ok(())
}

fn extract_archive_creation_receipt(
    archive: &HostArchive,
    epoch: u64,
    data_key: &PrivateDataKey,
) -> Result<AuthorityReceipt, PrivateAgentHostError> {
    let object = EncryptedPrivateObject::decode(&archive.runtime_state)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if object.space != archive.space
        || object.agent != archive.agent
        || object.epoch != epoch
        || object.kind != EncryptedObjectKind::Snapshot
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let plaintext = Zeroizing::new(decrypt_private_object(data_key, &object)?);
    if plaintext.len() > MAX_PRIVATE_RUNTIME_IMAGE_WIRE_BYTES {
        return Err(PrivateAgentHostError::LimitExceeded);
    }
    // Decode only to obtain the signed Create preimage. No source PVRI field
    // participates in destination construction or lineage.
    let image =
        PrivateRuntimeImage::decode(&plaintext).map_err(|_| PrivateAgentHostError::Corrupt)?;
    Ok(image.creation_receipt().clone())
}

fn unwrap_replica_archive_keyring(
    backup: &VerifiedEncryptedBackup,
    rows: &[EncryptedBackupReplayRow<'_>],
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<(BTreeMap<u64, PrivateDataKey>, bool), PrivateAgentHostError> {
    let mut keys = BTreeMap::new();
    let mut admitted = backup
        .genesis_nodes()
        .binary_search_by_key(&local_node.node, |candidate| candidate.node)
        .is_ok_and(|position| backup.genesis_nodes().get(position) == Some(local_node));

    for epoch in backup.key_epochs() {
        let exact_seal = epoch.sealed_data_keys.iter().any(|sealed| {
            sealed.node == local_node.node
                && sealed.recipient_key == local_node.encryption_public_key
        });
        if exact_seal {
            insert_replica_data_key(
                &mut keys,
                epoch.epoch,
                unwrap_data_key(epoch, local_node, node_key)?,
            )?;
        }
    }
    for row in rows {
        match &row.control().operation {
            PrivateControlOperation::Invite { node, epoch, .. } if node == local_node => {
                let position = backup
                    .key_epochs()
                    .binary_search_by_key(epoch, |candidate| candidate.epoch)
                    .map_err(|_| PrivateAgentHostError::Corrupt)?;
                let historical = unwrap_invite_history_grants(
                    row.control(),
                    &backup.key_epochs()[..=position],
                    backup.binding().owner,
                    local_node,
                    node_key,
                )?;
                for (epoch, key) in historical {
                    insert_replica_data_key(&mut keys, epoch, key)?;
                }
                admitted = true;
            }
            PrivateControlOperation::Recover {
                next_epoch,
                replacement_nodes,
                historical_keyring,
                ..
            } if replacement_nodes
                .binary_search_by_key(&local_node.node, |candidate| candidate.node)
                .is_ok_and(|position| replacement_nodes.get(position) == Some(local_node)) =>
            {
                let position = backup
                    .key_epochs()
                    .binary_search_by_key(&next_epoch.epoch, |candidate| candidate.epoch)
                    .map_err(|_| PrivateAgentHostError::Corrupt)?;
                if position == 0 {
                    return Err(PrivateAgentHostError::Corrupt);
                }
                let historical = unwrap_recovery_keyring(
                    historical_keyring,
                    &backup.key_epochs()[..position],
                    local_node,
                    node_key,
                )?;
                for (epoch, key) in historical {
                    insert_replica_data_key(&mut keys, epoch, key)?;
                }
                admitted = true;
            }
            _ => {}
        }
    }
    Ok((keys, admitted))
}

fn insert_replica_data_key(
    keys: &mut BTreeMap<u64, PrivateDataKey>,
    epoch: u64,
    key: PrivateDataKey,
) -> Result<(), PrivateAgentHostError> {
    if let Some(existing) = keys.get(&epoch) {
        if existing.commitment() != key.commitment() {
            return Err(PrivateAgentHostError::Corrupt);
        }
    } else {
        keys.insert(epoch, key);
    }
    Ok(())
}

fn open_or_create_replica_genesis<V: PrivateNodeAuthorityVerifier>(
    stage: &Path,
    source: &mut VerifiedReplicaSource,
    local_node: &PrivateNodeIdentity,
    establishment_identity: Hash,
    node_authority: &V,
    stop: ReplicaEstablishmentStop,
) -> Result<StagedPrivateReplicaRuntime, PrivateAgentHostError> {
    let store_root = stage.join(STORE_DIRECTORY);
    let mut store = match fs::symlink_metadata(&store_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(PrivateAgentHostError::Corrupt);
            }
            match PrivateStore::open(
                &store_root,
                source.final_target.space(),
                source.final_target.agent(),
                node_authority,
            ) {
                Ok(store) => store,
                Err(_) if !replica_stage_has_runtime_state(stage)? => {
                    // The authenticated plan makes an unopenable pre-PVRI
                    // Store creation an unreachable derived prefix. No source
                    // or caller-owned state is removed here.
                    fs::remove_dir_all(&store_root).map_err(map_io)?;
                    sync_directory(stage)?;
                    PrivateStore::create_empty_from_verified_genesis(
                        &store_root,
                        &source.backup,
                        node_authority,
                    )?
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PrivateStore::create_empty_from_verified_genesis(
                &store_root,
                &source.backup,
                node_authority,
            )?
        }
        Err(_) => return Err(PrivateAgentHostError::Io),
    };
    replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterGenesisStore)?;

    let genesis_store = store.core_position()?;
    if genesis_store.control_count() != 0
        || genesis_store.control_head().is_some()
        || genesis_store.next_sequence() != 0
        || genesis_store.object_count() != 0
    {
        // A durable replay prefix is handled below; only a true genesis Store
        // may be used to construct an absent canonical PVRI.
        if fs::symlink_metadata(stage.join(RUNTIME_STATE_FILE)).is_err() {
            return Err(PrivateAgentHostError::Corrupt);
        }
    }
    let key_epochs = private_runtime_key_epoch_commitments(&store)?;
    let genesis_key = source
        .data_keys
        .get(&0)
        .ok_or(PrivateAgentHostError::Unauthorized)?;

    if fs::symlink_metadata(stage.join(RUNTIME_STATE_FILE)).is_err() {
        let capability =
            super::super::private_runtime::PrivateRuntimeReplicaEstablishment::bind_verified_source(
                &source.plaintext.descriptor,
                local_node,
                genesis_store,
                &key_epochs,
                source.backup.final_authorized_nodes(),
                establishment_identity,
            )
            .map_err(|_| PrivateAgentHostError::Corrupt)?;
        let genesis = PrivateRuntimeImage::genesis_for_established_replica(
            &source.plaintext.descriptor,
            capability,
            source.genesis_state.clone(),
            genesis_store,
            key_epochs,
            source.creation_receipt.clone(),
            source.creation_receipt.selector.valid_from,
            &RawAuthorityVerifier,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
        ensure_replica_genesis_sidecar(
            stage,
            DESCRIPTOR_FILE,
            EncryptedObjectKind::Index,
            genesis_store.space(),
            genesis_store.agent(),
            genesis_key,
            &encode_descriptor_metadata(0, &source.plaintext.descriptor)?,
        )?;
        replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterGenesisDescriptor)?;
        ensure_replica_genesis_sidecar(
            stage,
            RUNTIME_FILE,
            EncryptedObjectKind::Package,
            genesis_store.space(),
            genesis_store.agent(),
            genesis_key,
            &encode_bytes_metadata(
                RUNTIME_MAGIC,
                0,
                &source.plaintext.runtime_package,
                MAX_PRIVATE_CIPHERTEXT_BYTES.saturating_sub(16),
            )?,
        )?;
        replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterGenesisRuntime)?;
        ensure_replica_genesis_sidecar(
            stage,
            BOOTSTRAP_FILE,
            EncryptedObjectKind::Blob,
            genesis_store.space(),
            genesis_store.agent(),
            genesis_key,
            &encode_bytes_metadata(
                BOOTSTRAP_MAGIC,
                0,
                &source.plaintext.bootstrap_metadata,
                MAX_PRIVATE_BOOTSTRAP_METADATA_BYTES,
            )?,
        )?;
        replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterGenesisBootstrap)?;
        write_exact_or_new_synced(
            &stage.join(RUNTIME_STATE_FILE),
            &encrypt_runtime_image_sidecar(genesis_key, &genesis)?,
        )?;
        replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterGenesisRuntimeImage)?;
        sync_directory(stage)?;
    }

    // Drop the creation handle before reopening every persisted preimage.
    drop(store);
    store = PrivateStore::open(
        &store_root,
        source.final_target.space(),
        source.final_target.agent(),
        node_authority,
    )?;
    let current_key = source
        .data_keys
        .get(&store.binding().epoch)
        .ok_or(PrivateAgentHostError::Unauthorized)?;
    let plaintext = reconcile_and_open_sidecars(stage, &store, current_key)?;
    if !recovery_plaintext_is_compatible(&source.plaintext, &plaintext) {
        return Err(PrivateAgentHostError::Alias);
    }
    let data_keys = core::mem::take(&mut source.data_keys);
    // This namespace is still protected by the authenticated establishment
    // plan.  A stop after Store+PAPL commit can leave the newest Recover
    // deliberately pending until its source evidence is attached below, so
    // the ordinary live-agent reconciler is too strict here.
    let runtime_image = reconcile_unpublished_replica_runtime_image(
        stage,
        &store,
        &plaintext.descriptor,
        local_node,
        &data_keys,
    )?;
    Ok(StagedPrivateReplicaRuntime {
        store,
        descriptor: plaintext.descriptor,
        runtime_package: plaintext.runtime_package,
        bootstrap_metadata: plaintext.bootstrap_metadata,
        runtime_image,
        data_keys,
    })
}

fn replica_establishment_stop(
    actual: ReplicaEstablishmentStop,
    boundary: ReplicaEstablishmentStop,
) -> Result<(), PrivateAgentHostError> {
    #[cfg(test)]
    if actual == boundary {
        return Err(PrivateAgentHostError::Store(PrivateStoreError::Interrupted));
    }
    let _ = (actual, boundary);
    Ok(())
}

fn replica_store_commit_stop(
    stop: ReplicaEstablishmentStop,
) -> super::super::private_store::CommitStop {
    #[cfg(test)]
    if stop == ReplicaEstablishmentStop::AfterReplayStoreCommitted {
        return super::super::private_store::CommitStop::AfterIndex;
    }
    let _ = stop;
    super::super::private_store::CommitStop::Never
}

fn replica_evidence_commit_stop(stop: ReplicaEstablishmentStop) -> ControlEvidenceCommitStop {
    #[cfg(test)]
    {
        return match stop {
            ReplicaEstablishmentStop::AfterReplayEvidenceStaged => {
                ControlEvidenceCommitStop::AfterEvidenceStaged
            }
            ReplicaEstablishmentStop::AfterReplayProvenanceStaged => {
                ControlEvidenceCommitStop::AfterStaged
            }
            ReplicaEstablishmentStop::AfterReplayEvidencePending => {
                ControlEvidenceCommitStop::AfterPending
            }
            ReplicaEstablishmentStop::AfterReplayProvenancePublished => {
                ControlEvidenceCommitStop::AfterCertificatePublished
            }
            ReplicaEstablishmentStop::AfterReplayEvidencePublished => {
                ControlEvidenceCommitStop::AfterPublished
            }
            ReplicaEstablishmentStop::AfterReplayEvidenceRetired => {
                ControlEvidenceCommitStop::AfterRetired
            }
            _ => ControlEvidenceCommitStop::Never,
        };
    }
    #[cfg(not(test))]
    {
        let _ = stop;
        ControlEvidenceCommitStop::Never
    }
}

#[allow(clippy::too_many_arguments)]
fn ensure_replica_genesis_sidecar(
    stage: &Path,
    name: &str,
    kind: EncryptedObjectKind,
    space: SpaceId,
    agent: AgentId,
    key: &PrivateDataKey,
    expected_plaintext: &[u8],
) -> Result<(), PrivateAgentHostError> {
    let path = stage.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(PrivateAgentHostError::Corrupt);
            }
            let wire = read_sidecar_wire(stage, name)?;
            let plaintext = decrypt_archive_sidecar(&wire, space, agent, 0, kind, key)?;
            if plaintext.as_slice() != expected_plaintext {
                return Err(PrivateAgentHostError::Alias);
            }
            remove_regular_file_if_present(&stage.join(format!("{name}{WRITE_SUFFIX}")))?;
            sync_directory(stage)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let wire = encrypt_private_object(key, space, agent, 0, kind, expected_plaintext)?
                .encode()
                .map_err(|_| PrivateAgentHostError::Corrupt)?;
            write_exact_or_new_synced(&path, &wire)
        }
        Err(_) => Err(PrivateAgentHostError::Io),
    }
}

fn replica_stage_has_runtime_state(stage: &Path) -> Result<bool, PrivateAgentHostError> {
    if fs::symlink_metadata(stage.join(RUNTIME_STATE_FILE)).is_ok() {
        return Ok(true);
    }
    Ok(find_staged_runtime_image(stage)?.is_some())
}

#[allow(clippy::too_many_arguments)]
fn replay_replica_controls<V: PrivateNodeAuthorityVerifier>(
    stage: &Path,
    mut staged: StagedPrivateReplicaRuntime,
    rows: &[VerifiedReplicaReplayRow],
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    management_gas: u64,
    node_authority: &V,
    stop: ReplicaEstablishmentStop,
) -> Result<StagedPrivateReplicaRuntime, PrivateAgentHostError> {
    for row in rows {
        let exists = staged.store.control_is_exact(
            row.control.commitment(),
            &row.control
                .encode()
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?,
        )?;
        if !exists {
            require_resolved_runtime_application_head(&staged.store)?;
            staged
                .store
                .validate_next_control(&row.control, node_authority)?;
            apply_replica_replay_row(
                stage,
                &mut staged,
                row,
                route,
                management_gas,
                node_authority,
                stop,
            )?;
        }

        validate_existing_replica_replay_row(&staged, row, route, local_node, node_key)?;
        let entry = staged
            .store
            .indexed_controls()
            .iter()
            .find(|entry| entry.commitment == row.control.commitment())
            .ok_or(PrivateAgentHostError::Corrupt)?
            .clone();
        let evidence = staged.store.read_control_authority_evidence(&entry)?;
        if evidence.is_none() {
            if staged.store.binding().control_head != Some(row.control.commitment()) {
                return Err(PrivateAgentHostError::Corrupt);
            }
            // Reopen exact Store/PVRI/PAPL bytes from disk before minting any
            // destination provenance. This narrow unpublished check permits
            // a pending Recover solely under the authenticated plan.
            staged =
                reopen_staged_replica(stage, staged, local_node, node_key, node_authority, false)?;
            persist_replica_replay_evidence(
                &mut staged,
                row,
                route,
                authority,
                local_node,
                node_key,
                stop,
            )?;
        }
        staged = reopen_staged_replica(stage, staged, local_node, node_key, node_authority, true)?;
        validate_existing_replica_replay_row(&staged, row, route, local_node, node_key)?;
    }

    Ok(staged)
}

fn apply_replica_replay_row<V: PrivateNodeAuthorityVerifier>(
    stage: &Path,
    staged: &mut StagedPrivateReplicaRuntime,
    row: &VerifiedReplicaReplayRow,
    route: ManagedAgentTarget,
    management_gas: u64,
    node_authority: &V,
    stop: ReplicaEstablishmentStop,
) -> Result<(), PrivateAgentHostError> {
    let preview = staged
        .store
        .preview_control_position(&row.control, node_authority)?;
    if preview.disposition() != PutDisposition::Inserted {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let (successor, completed) = build_replica_replay_application(
        staged,
        row,
        route,
        management_gas,
        preview.position(),
        preview.key_epoch_commitments().to_vec(),
    )?;

    let prior_epoch = staged.store.binding().epoch;
    let successor_epoch = preview.position().epoch();
    if successor_epoch != prior_epoch {
        let data_key = staged
            .data_keys
            .get(&successor_epoch)
            .ok_or(PrivateAgentHostError::Unauthorized)?;
        stage_replica_metadata(stage, successor_epoch, data_key, staged)?;
    }
    let runtime_key = staged
        .data_keys
        .get(&successor_epoch)
        .ok_or(PrivateAgentHostError::Unauthorized)?;
    stage_runtime_image_for_application(
        stage,
        runtime_key,
        &successor,
        row.control.commitment(),
        PrivateRuntimeApplicationStop::Never,
    )?;
    staged
        .store
        .append_control_with_runtime_application_with_stop_for_runtime(
            &row.control,
            &completed,
            node_authority,
            replica_store_commit_stop(stop),
        )?;
    if successor_epoch != prior_epoch {
        promote_application_sidecars(stage, successor_epoch, PrivateRuntimeApplicationStop::Never)?;
    }
    promote_runtime_image_for_application(
        stage,
        row.control.commitment(),
        PrivateRuntimeApplicationStop::Never,
    )?;
    staged.runtime_image = successor;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_replica_replay_application(
    staged: &StagedPrivateReplicaRuntime,
    row: &VerifiedReplicaReplayRow,
    route: ManagedAgentTarget,
    management_gas: u64,
    successor_store: PrivateStoreCorePosition,
    successor_key_epochs: Vec<PrivateKeyEpochCommitment>,
) -> Result<(PrivateRuntimeImage, PrivateRuntimeApplication), PrivateAgentHostError> {
    let pending = PrivateRuntimeApplication::pending(
        &staged.descriptor,
        &staged.runtime_image,
        row.control.clone(),
        row.source_application.mutation().cloned(),
        row.source_application.recovery_authority_proof().cloned(),
        row.source_application.receipt().clone(),
        row.source_application.issuance().clone(),
        row.source_application.applied_at(),
        successor_store,
        &RawAuthorityVerifier,
        &RawRecoveryAuthorityProofVerifier,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;

    let (state, success) = match &row.control.operation {
        PrivateControlOperation::Invite { .. }
        | PrivateControlOperation::Revoke { .. }
        | PrivateControlOperation::RotateKeys { .. }
        | PrivateControlOperation::Recover { .. } => (
            staged.runtime_image.state().clone(),
            PrivateRuntimeSuccess::ControlOnly,
        ),
        PrivateControlOperation::SetResourcePolicy { .. }
        | PrivateControlOperation::ActorLifecycle { .. } => {
            let mutation = row
                .source_application
                .mutation()
                .cloned()
                .ok_or(PrivateAgentHostError::Corrupt)?;
            let management = ManagementRequest::PrivateControl {
                control: Box::new(row.control.clone()),
                mutation: Box::new(mutation),
            };
            if !management.is_valid() {
                return Err(PrivateAgentHostError::InvalidArtifact);
            }
            let work = RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: route.space,
                agent: route.agent,
                runtime_deployment: route.runtime_deployment,
                state: staged.runtime_image.state().clone(),
                request: Box::new(management.clone()),
                authority: Some(Box::new(row.source_application.receipt().clone())),
                observed_slot: row.source_application.applied_at(),
            };
            let wire = work
                .encode()
                .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            let admitted = admit_runtime_package(&staged.runtime_package)
                .map_err(|_| PrivateAgentHostError::Corrupt)?;
            let transition = execute_canonical_wire::<RuntimeTransition>(
                admitted.program_bytes(),
                management_gas,
                &wire,
            )
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
            match classify_private_runtime_control_transition(
                &staged.runtime_image,
                &management,
                transition,
            )
            .map_err(|_| PrivateAgentHostError::InvalidArtifact)?
            {
                PrivateRuntimeControlDisposition::Applied { state, success } => (state, success),
                PrivateRuntimeControlDisposition::RetiredUnapplied { .. } => {
                    return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
                }
            }
        }
    };
    let successor = PrivateRuntimeImage::successor(
        &staged.descriptor,
        &staged.runtime_image,
        &pending,
        &success,
        state,
        successor_key_epochs,
        &RawAuthorityVerifier,
        &RawRecoveryAuthorityProofVerifier,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let completed = pending
        .complete(
            &staged.descriptor,
            &staged.runtime_image,
            &successor,
            success,
            &RawAuthorityVerifier,
            &RawRecoveryAuthorityProofVerifier,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if completed
        .successor_stable_projection()
        .map(|projection| projection.commitment())
        != Some(row.source_stable_projection)
    {
        return Err(PrivateAgentHostError::Sync(PrivateSyncError::Tampered));
    }

    Ok((successor, completed))
}

fn stage_replica_metadata(
    stage: &Path,
    epoch: u64,
    data_key: &PrivateDataKey,
    staged: &StagedPrivateReplicaRuntime,
) -> Result<(), PrivateAgentHostError> {
    let plaintext = AgentPlaintext {
        descriptor: staged.descriptor.clone(),
        runtime_package: Zeroizing::new(staged.runtime_package.to_vec()),
        bootstrap_metadata: Zeroizing::new(staged.bootstrap_metadata.to_vec()),
    };
    let sidecars = encrypt_sidecars(
        staged.descriptor.identity.space,
        staged.descriptor.identity.agent,
        epoch,
        data_key,
        &plaintext,
    )?;
    replace_staged_file(stage, DESCRIPTOR_FILE, epoch, &sidecars.descriptor)?;
    replace_staged_file(stage, RUNTIME_FILE, epoch, &sidecars.runtime)?;
    replace_staged_file(stage, BOOTSTRAP_FILE, epoch, &sidecars.bootstrap)?;
    sync_directory(stage)
}

fn validate_existing_replica_replay_row(
    staged: &StagedPrivateReplicaRuntime,
    row: &VerifiedReplicaReplayRow,
    route: ManagedAgentTarget,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
) -> Result<(), PrivateAgentHostError> {
    let entry = staged
        .store
        .indexed_controls()
        .iter()
        .find(|entry| entry.commitment == row.control.commitment())
        .ok_or(PrivateAgentHostError::Corrupt)?;
    if entry.sequence != row.index.sequence
        || entry.resulting_epoch != row.index.resulting_epoch
        || entry.previous != row.index.previous
        || entry.superseded_heads != row.index.superseded_heads
    {
        return Err(PrivateAgentHostError::Alias);
    }
    let application = staged
        .store
        .read_runtime_application(entry.commitment)?
        .ok_or(PrivateAgentHostError::Corrupt)?;
    application
        .verify_with(
            &staged.descriptor,
            &RawAuthorityVerifier,
            &RawRecoveryAuthorityProofVerifier,
        )
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if application.managed() != route
        || application.node() != local_node.node
        || application.control() != &row.control
        || application.mutation() != row.source_application.mutation()
        || application.recovery_authority_proof()
            != row.source_application.recovery_authority_proof()
        || application.receipt() != row.source_application.receipt()
        || application.issuance() != row.source_application.issuance()
        || application.applied_at() != row.source_application.applied_at()
        || application
            .successor_stable_projection()
            .map(|projection| projection.commitment())
            != Some(row.source_stable_projection)
    {
        return Err(PrivateAgentHostError::Alias);
    }
    let evidence = staged.store.read_control_authority_evidence(entry)?;
    let certificate = staged.store.read_stable_import_certificate(entry)?;
    match (evidence.as_deref(), certificate.as_deref()) {
        (None, None) if staged.store.binding().control_head == Some(entry.commitment) => Ok(()),
        (Some(evidence), None) if evidence == row.source_evidence => {
            authenticate_local_runtime_application_endpoint(
                &staged.descriptor,
                &row.control,
                entry.resulting_epoch,
                &application,
                evidence,
            )
        }
        (Some(evidence), Some(certificate)) if evidence == row.source_evidence => {
            authenticate_imported_runtime_application_endpoint(
                &staged.descriptor,
                &row.control,
                entry.resulting_epoch,
                &application,
                evidence,
                certificate,
                local_node,
                node_key,
            )
        }
        _ => Err(PrivateAgentHostError::Alias),
    }
}

fn persist_replica_replay_evidence(
    staged: &mut StagedPrivateReplicaRuntime,
    row: &VerifiedReplicaReplayRow,
    route: ManagedAgentTarget,
    authority: AuthorityActorTarget,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    stop: ReplicaEstablishmentStop,
) -> Result<(), PrivateAgentHostError> {
    if authority.binding != staged.descriptor.authority {
        return Err(PrivateAgentHostError::Unauthorized);
    }
    let application = staged
        .store
        .read_runtime_application(row.control.commitment())?
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let evidence = PrivateControlAuthorityEvidence::decode(&row.source_evidence)?;
    let source_evidence = evidence.commitment()?;
    if authenticate_local_runtime_application_endpoint(
        &staged.descriptor,
        &row.control,
        row.index.resulting_epoch,
        &application,
        &row.source_evidence,
    )
    .is_ok()
    {
        staged
            .store
            .persist_control_authority_evidence_with_stop_for_runtime(
                row.control.commitment(),
                &row.source_evidence,
                replica_evidence_commit_stop(stop),
            )?;
        return Ok(());
    }
    let certificate = PrivateStableImportCertificate::issue(
        route,
        staged.store.binding().owner,
        staged.descriptor.commitment(),
        local_node,
        row.control.commitment(),
        application.commitment(),
        source_evidence,
        row.source_stable_projection,
        node_key,
    )?
    .encode()
    .map_err(|_| PrivateAgentHostError::InvalidArtifact)?;
    authenticate_imported_runtime_application_endpoint(
        &staged.descriptor,
        &row.control,
        row.index.resulting_epoch,
        &application,
        &row.source_evidence,
        &certificate,
        local_node,
        node_key,
    )?;
    staged
        .store
        .persist_imported_control_authority_evidence_with_stop_for_runtime(
            row.control.commitment(),
            &row.source_evidence,
            &certificate,
            replica_evidence_commit_stop(stop),
        )?;
    Ok(())
}

fn reopen_staged_replica<V: PrivateNodeAuthorityVerifier>(
    stage: &Path,
    staged: StagedPrivateReplicaRuntime,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    node_authority: &V,
    require_resolved_lineage: bool,
) -> Result<StagedPrivateReplicaRuntime, PrivateAgentHostError> {
    let StagedPrivateReplicaRuntime {
        store,
        descriptor,
        runtime_package,
        bootstrap_metadata,
        runtime_image: _,
        data_keys,
    } = staged;
    let binding = store.binding();
    drop(store);
    let store = PrivateStore::open(
        stage.join(STORE_DIRECTORY),
        binding.space,
        binding.agent,
        node_authority,
    )?;
    let current_key = data_keys
        .get(&store.binding().epoch)
        .ok_or(PrivateAgentHostError::Unauthorized)?;
    let plaintext = reconcile_and_open_sidecars(stage, &store, current_key)?;
    if plaintext.descriptor != descriptor
        || plaintext.runtime_package.as_slice() != runtime_package.as_slice()
        || plaintext.bootstrap_metadata.as_slice() != bootstrap_metadata.as_slice()
    {
        return Err(PrivateAgentHostError::Alias);
    }
    let runtime_image = if require_resolved_lineage {
        reconcile_and_open_runtime_image(
            stage,
            &store,
            &descriptor,
            local_node,
            node_key,
            &data_keys,
        )?
    } else {
        reconcile_unpublished_replica_runtime_image(
            stage,
            &store,
            &descriptor,
            local_node,
            &data_keys,
        )?
    };
    Ok(StagedPrivateReplicaRuntime {
        store,
        descriptor,
        runtime_package,
        bootstrap_metadata,
        runtime_image,
        data_keys,
    })
}

fn reconcile_unpublished_replica_runtime_image(
    stage: &Path,
    store: &PrivateStore,
    descriptor: &AgentDescriptor,
    local_node: &PrivateNodeIdentity,
    data_keys: &BTreeMap<u64, PrivateDataKey>,
) -> Result<PrivateRuntimeImage, PrivateAgentHostError> {
    let current_store = store.core_position()?;
    let current_key_epochs = private_runtime_key_epoch_commitments(store)?;
    let canonical_path = stage.join(RUNTIME_STATE_FILE);
    let canonical = read_and_authenticate_runtime_image(
        &canonical_path,
        current_store.space(),
        current_store.agent(),
        descriptor,
        local_node.node,
        data_keys,
    )?;
    let staged = find_staged_runtime_image(stage)?;
    if runtime_image_matches_store(&canonical, current_store, &current_key_epochs) {
        if let Some((path, _)) = staged {
            remove_regular_file_if_present(&path)?;
            sync_directory(stage)?;
        }
        return Ok(canonical);
    }
    if canonical.key_epochs() == current_key_epochs
        && let Ok(rebound) = canonical.rebind_store_objects(current_store)
    {
        let key = data_keys
            .get(&current_store.epoch())
            .ok_or(PrivateAgentHostError::Corrupt)?;
        replace_regular_file_synced(
            &canonical_path,
            &encrypt_runtime_image_sidecar(key, &rebound)?,
        )?;
        if let Some((path, _)) = staged {
            remove_regular_file_if_present(&path)?;
            sync_directory(stage)?;
        }
        return Ok(rebound);
    }
    let Some((staged_path, staged_control)) = staged else {
        return Err(PrivateAgentHostError::Corrupt);
    };
    let successor = read_and_authenticate_runtime_image(
        &staged_path,
        current_store.space(),
        current_store.agent(),
        descriptor,
        local_node.node,
        data_keys,
    )?;
    if successor.stable_projection().control_head() != Some(staged_control)
        || !runtime_image_matches_store(&successor, current_store, &current_key_epochs)
        || !runtime_image_is_direct_successor(&canonical, &successor)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    let entry = store
        .indexed_controls()
        .last()
        .filter(|entry| entry.commitment == staged_control)
        .ok_or(PrivateAgentHostError::Corrupt)?;
    let application = store
        .read_runtime_application(entry.commitment)?
        .ok_or(PrivateAgentHostError::Corrupt)?;
    PrivateControlReopenedState::new(application, current_store, successor.clone())
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    fs::rename(&staged_path, &canonical_path).map_err(map_io)?;
    sync_directory(stage)?;
    Ok(successor)
}

fn import_replica_objects(
    stage: &Path,
    staged: &mut StagedPrivateReplicaRuntime,
    source: &VerifiedReplicaSource,
    local_node: &PrivateNodeIdentity,
    node_key: &PrivateNodeDecryptionKey,
    stop: ReplicaEstablishmentStop,
) -> Result<(), PrivateAgentHostError> {
    require_resolved_runtime_application_head(&staged.store)?;
    let objects = source.backup.objects();
    for (position, object) in objects.iter().enumerate() {
        staged.store.put_object(object)?;
        if position == 0 && objects.len() > 1 {
            replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterObjectPrefix)?;
        }
    }
    if staged.store.core_position()? != source.final_target {
        return Err(PrivateAgentHostError::Corrupt);
    }
    // Rebind once after the complete object batch. `reopen_staged_replica`
    // also repairs any strict object-growth prefix left by a crash.
    let successor = staged
        .runtime_image
        .rebind_store_objects(staged.store.core_position()?)
        .map_err(|_| PrivateAgentHostError::Corrupt)?;
    let key = staged
        .data_keys
        .get(&successor.store().epoch())
        .ok_or(PrivateAgentHostError::Unauthorized)?;
    replace_regular_file_synced(
        &stage.join(RUNTIME_STATE_FILE),
        &encrypt_runtime_image_sidecar(key, &successor)?,
    )?;
    staged.runtime_image = successor;
    authenticate_runtime_application_lineage(
        &staged.store,
        &staged.descriptor,
        &staged.runtime_image,
        local_node,
        node_key,
    )?;
    Ok(())
}

fn publish_completed_replica_establishment<V: PrivateNodeAuthorityVerifier>(
    host: &mut PrivateAgentHost,
    plan: &ReplicaEstablishmentPlan,
    completion: &ReplicaEstablishmentCompletion,
    node_authority: &V,
) -> Result<(), PrivateAgentHostError> {
    publish_completed_replica_establishment_with_stop(
        host,
        plan,
        completion,
        node_authority,
        ReplicaEstablishmentStop::Never,
    )
}

fn publish_completed_replica_establishment_with_stop<V: PrivateNodeAuthorityVerifier>(
    host: &mut PrivateAgentHost,
    plan: &ReplicaEstablishmentPlan,
    completion: &ReplicaEstablishmentCompletion,
    node_authority: &V,
    stop: ReplicaEstablishmentStop,
) -> Result<(), PrivateAgentHostError> {
    let stage = host.creating_path(plan.route.agent);
    let destination = host.agent_path(plan.route.agent);
    let mut stage_exists = fs::symlink_metadata(&stage).is_ok();
    let destination_exists = fs::symlink_metadata(&destination).is_ok();
    if stage_exists && destination_exists {
        require_real_directory(&stage)?;
        require_real_directory(&destination)?;
        let staged_plan = read_replica_establishment_plan(&stage, &host.node_key)?;
        if &staged_plan != plan {
            return Err(PrivateAgentHostError::Alias);
        }
        if fs::symlink_metadata(destination.join(ESTABLISHMENT_PLAN_FILE)).is_ok() {
            if read_replica_establishment_plan(&destination, &host.node_key)? != staged_plan {
                return Err(PrivateAgentHostError::Alias);
            }
        } else {
            let receipt = read_replica_establishment_receipt(&destination, &host.node_key)?;
            if receipt != replica_establishment_receipt_from_plan(&staged_plan)? {
                return Err(PrivateAgentHostError::Alias);
            }
        }
        reconcile_exact_duplicate_slot(
            &stage,
            &destination,
            host.scope.space,
            host.scope.owner,
            &host.scope.local_node,
            &host.node_key,
            node_authority,
        )?;
        retire_exact_duplicate_slot(
            &stage,
            &host.root.join(CREATING_DIRECTORY),
            plan.route.agent,
        )?;
        stage_exists = false;
    }
    if !stage_exists && !destination_exists {
        return Err(PrivateAgentHostError::NotFound);
    }
    if destination_exists {
        cleanup_replica_establishment_receipt_write(&destination)?;
    }
    let current = if stage_exists { &stage } else { &destination };
    if !stage_exists && fs::symlink_metadata(current.join(ESTABLISHMENT_PLAN_FILE)).is_err() {
        let receipt = read_replica_establishment_receipt(current, &host.node_key)?;
        if receipt != replica_establishment_receipt_from_plan(plan)? {
            return Err(PrivateAgentHostError::Alias);
        }
        let hosted = open_completed_replica_establishment_receipt(
            current,
            &receipt,
            &host.scope,
            &host.node_key,
            node_authority,
        )?;
        if host.agents.insert(plan.route.agent, hosted).is_some() {
            return Err(PrivateAgentHostError::Alias);
        }
        return Ok(());
    }
    let persisted = read_replica_establishment_plan(current, &host.node_key)?;
    if &persisted != plan || persisted.completion.as_ref() != Some(completion) {
        return Err(PrivateAgentHostError::Alias);
    }
    let hosted = open_completed_replica_establishment(
        current,
        plan,
        completion,
        &host.scope,
        &host.node_key,
        node_authority,
    )?;
    drop(hosted);
    if stage_exists {
        host.require_private_agent_publication_capacity(plan.route.agent)?;
        fs::rename(&stage, &destination).map_err(map_io)?;
        replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterStageRenamed)?;
        sync_directory(&host.root)?;
        sync_directory(&host.root.join(CREATING_DIRECTORY))?;
    }
    let hosted = open_completed_replica_establishment(
        &destination,
        plan,
        completion,
        &host.scope,
        &host.node_key,
        node_authority,
    )?;
    // The authenticated completion marker deliberately crosses the rename.
    // Replace its bulky replay capsule with a small authenticated receipt
    // only after the live namespace itself has reopened exactly.
    let receipt = replica_establishment_receipt_from_plan(plan)?;
    publish_replica_establishment_receipt_with_stop(&destination, &receipt, &host.node_key, stop)?;
    remove_regular_file_if_present(&destination.join(ESTABLISHMENT_PLAN_FILE))?;
    replica_establishment_stop(stop, ReplicaEstablishmentStop::AfterPlanRetired)?;
    remove_regular_file_if_present(&destination.join(ESTABLISHMENT_PLAN_WRITE_FILE))?;
    sync_directory(&destination)?;
    if host.agents.insert(plan.route.agent, hosted).is_some() {
        return Err(PrivateAgentHostError::Alias);
    }
    Ok(())
}

fn open_completed_replica_establishment_receipt<V: PrivateNodeAuthorityVerifier>(
    slot: &Path,
    receipt: &ReplicaEstablishmentReceipt,
    scope: &RootScope,
    node_key: &PrivateNodeDecryptionKey,
    node_authority: &V,
) -> Result<HostedPrivateAgent, PrivateAgentHostError> {
    if receipt.route.space != scope.space
        || receipt.owner != scope.owner
        || receipt.destination != scope.local_node
    {
        return Err(PrivateAgentHostError::InvalidScope);
    }
    let hosted = open_hosted_agent(
        slot,
        scope.space,
        scope.owner,
        &scope.local_node,
        node_key,
        node_authority,
    )?;
    authenticate_hosted_replica_establishment_receipt(&hosted, receipt, scope)?;
    Ok(hosted)
}

fn authenticate_hosted_replica_establishment_receipt(
    hosted: &HostedPrivateAgent,
    receipt: &ReplicaEstablishmentReceipt,
    scope: &RootScope,
) -> Result<(), PrivateAgentHostError> {
    let establishment_identity = replica_establishment_identity_commitment(
        receipt.route,
        receipt.owner,
        &receipt.destination,
        receipt.authority,
        receipt.source_hash,
        receipt.management_gas,
    )?;
    let expected_tag = PrivateRuntimeImage::replica_establishment_seal(
        establishment_identity,
        receipt.completion.store,
        receipt.completion.runtime_lineage,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if receipt.route.space != scope.space
        || receipt.owner != scope.owner
        || receipt.destination != scope.local_node
        || managed_target_for_descriptor(&hosted.descriptor) != receipt.route
        || hosted.descriptor.authority != receipt.authority.binding
        || receipt.completion.establishment_tag != expected_tag
        || hosted.runtime_image.establishment_origin() != Some(establishment_identity)
        || hosted.runtime_image.establishment_completion() != Some(expected_tag)
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(())
}

fn open_completed_replica_establishment<V: PrivateNodeAuthorityVerifier>(
    slot: &Path,
    plan: &ReplicaEstablishmentPlan,
    completion: &ReplicaEstablishmentCompletion,
    scope: &RootScope,
    node_key: &PrivateNodeDecryptionKey,
    node_authority: &V,
) -> Result<HostedPrivateAgent, PrivateAgentHostError> {
    if plan.completion.as_ref() != Some(completion)
        || plan.route.space != scope.space
        || plan.owner != scope.owner
        || plan.destination != scope.local_node
    {
        return Err(PrivateAgentHostError::InvalidScope);
    }
    let hosted = open_hosted_agent(
        slot,
        scope.space,
        scope.owner,
        &scope.local_node,
        node_key,
        node_authority,
    )?;
    require_resolved_runtime_application_head(&hosted.store)?;
    let establishment_identity = replica_establishment_identity_commitment(
        plan.route,
        plan.owner,
        &plan.destination,
        plan.authority,
        plan.source_hash,
        plan.management_gas,
    )?;
    let expected_tag = PrivateRuntimeImage::replica_establishment_seal(
        establishment_identity,
        completion.store,
        completion.runtime_lineage,
    )
    .map_err(|_| PrivateAgentHostError::Corrupt)?;
    if managed_target_for_descriptor(&hosted.descriptor) != plan.route
        || hosted.descriptor.authority != plan.authority.binding
        || completion.establishment_tag != expected_tag
        || hosted.runtime_image.establishment_origin() != Some(establishment_identity)
        || hosted.runtime_image.establishment_completion() != Some(expected_tag)
        || hosted.store.core_position()?.commitment() != completion.store
        || hosted.runtime_image.commitment() != completion.runtime_image
        || hosted.runtime_image.lineage_commitment() != completion.runtime_lineage
    {
        return Err(PrivateAgentHostError::Corrupt);
    }
    Ok(hosted)
}

impl PrivateAgentHost {
    /// Complete or clean any authenticated establishment marker which crossed
    /// the stage-to-live rename before a process stopped.
    pub(super) fn recover_live_replica_establishments<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        node_authority: &V,
    ) -> Result<(), PrivateAgentHostError> {
        for agent in scan_root(&self.root)? {
            let slot = self.agent_path(agent);
            cleanup_replica_establishment_receipt_write(&slot)?;
            if fs::symlink_metadata(slot.join(ESTABLISHMENT_PLAN_FILE)).is_ok() {
                let plan = read_replica_establishment_plan(&slot, &self.node_key)?;
                let completion = plan
                    .completion
                    .clone()
                    .ok_or(PrivateAgentHostError::Corrupt)?;
                publish_completed_replica_establishment(self, &plan, &completion, node_authority)?;
                continue;
            }
            if fs::symlink_metadata(slot.join(ESTABLISHMENT_RECEIPT_FILE)).is_err() {
                continue;
            }
            let receipt = read_replica_establishment_receipt(&slot, &self.node_key)?;
            if let Some(existing) = self.agents.get(&agent) {
                // `recover_creating` may have published and inserted this
                // completed stage earlier in the same startup pass. Validate
                // that exact loaded slot before attempting another Store
                // open: its existing Store handle deliberately retains the
                // single-writer lock.
                authenticate_hosted_replica_establishment_receipt(existing, &receipt, &self.scope)?;
                continue;
            }
            let hosted = open_completed_replica_establishment_receipt(
                &slot,
                &receipt,
                &self.scope,
                &self.node_key,
                node_authority,
            )?;
            if self.agents.insert(agent, hosted).is_some() {
                return Err(PrivateAgentHostError::Alias);
            }
        }
        Ok(())
    }
}

/// Return true when `slot` is an establishment namespace. An incomplete
/// authenticated plan remains inert; a completed plan is published with its
/// marker intact and then reopened/cleaned through the same live path.
pub(super) fn recover_staged_replica_establishment<V: PrivateNodeAuthorityVerifier>(
    host: &mut PrivateAgentHost,
    agent: AgentId,
    node_authority: &V,
) -> Result<bool, PrivateAgentHostError> {
    let stage = host.creating_path(agent);
    let canonical = stage.join(ESTABLISHMENT_PLAN_FILE);
    let temporary = stage.join(ESTABLISHMENT_PLAN_WRITE_FILE);
    if fs::symlink_metadata(&canonical).is_err() {
        if fs::symlink_metadata(&temporary).is_err() {
            return Ok(false);
        }
        require_regular_file(&temporary)?;
        // No derived state is reachable before the canonical authenticated
        // plan exists. A lone write is therefore an unpublished preparation.
        fs::remove_dir_all(&stage).map_err(map_io)?;
        sync_directory(&host.root.join(CREATING_DIRECTORY))?;
        return Ok(true);
    }
    let plan = read_replica_establishment_plan(&stage, &host.node_key)?;
    if plan.route.space != host.scope.space
        || plan.route.agent != agent
        || plan.owner != host.scope.owner
        || plan.destination != host.scope.local_node
    {
        return Err(PrivateAgentHostError::InvalidScope);
    }
    let Some(completion) = plan.completion.clone() else {
        return Ok(true);
    };
    match host.require_private_agent_publication_capacity(agent) {
        Ok(()) => {}
        Err(PrivateAgentHostError::LimitExceeded) => {
            // Capacity is a runtime publication gate, not root corruption. Keep a
            // completed authenticated stage inert so the existing live set can
            // reopen without self-bricking; an explicit resume remains bounded.
            return Ok(true);
        }
        Err(error) => return Err(error),
    }
    publish_completed_replica_establishment(host, &plan, &completion, node_authority)?;
    Ok(true)
}
