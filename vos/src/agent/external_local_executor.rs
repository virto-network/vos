//! Signed, runtime-independent replay adapter for the experimental Local
//! journal. It owns no filesystem authority: the lifecycle owner must first
//! select the exact admitted package and genesis, then retain the locked store.

use super::driver::{DEFAULT_MANAGEMENT_GAS, SdkManagementArtifacts};
use super::execution::MAX_EXECUTION_GAS;
use super::journal::{
    AgentJournalGenesis, CanonicalJournalRecord, LaneCursor, LaneStateManifest, ReplayInput,
    ReplayInputId, ReplayOperation, RuntimeBinding,
};
use super::journal_store::CatalogBlobResolver;
use super::local_journal_driver::LocalReplayExecutorError;
use super::package_admission::{AdmittedStateRuntimePackage, admit_actor_package};
use super::replay::{
    ReplayExecutor, ReplayExternalExecution, ReplayPosition, ReplayTransition, ScopedBlockReader,
};
use super::state_block_pvm::{BlockPvmError, MultiLaneStateBlockHost};
use super::wire::RuntimeState;
use crate::agent_sdk::{
    AgentDescriptor, AgentProfile, InvocationAuthorization, InvocationRetirement,
    ManagementRequest, state_blocks::ReadBudget,
};
use crate::service::{AgentId, BlobRef, SpaceId};

/// Stable across CMI4 authorization/finalization envelope updates. The
/// request and credential call are immutable for one pledged Create, so the
/// file slot cannot be rebound by a later lifecycle phase or another caller.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) fn external_local_create_intent_hash(
    intent: &super::clean_management_intent::CleanManagementIntent,
) -> crate::service::Hash {
    crate::service::Hash::digest(
        b"vos/agent/local/external-create-intent/v1",
        &[
            &intent.request().commitment().0,
            &intent.call().commitment().0,
        ],
    )
}

#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) fn state_runtime_matches_descriptor(
    descriptor: &AgentDescriptor,
    runtime: &AdmittedStateRuntimePackage,
) -> bool {
    descriptor.validate().is_ok()
        && descriptor.identity.profile == AgentProfile::Local
        && descriptor.runtime_package == *runtime.package_ref()
        && descriptor.identity.runtime_deployment == runtime.deployment()
        && descriptor.identity.runtime_program == runtime.program()
        && descriptor.identity.runtime_producer == runtime.manifest().signing.producer
        && descriptor.runtime_contract == runtime.manifest().contract
        && descriptor.capabilities == runtime.manifest().capabilities
}

/// Reconstructed only from the existing signed Local lifecycle's durable
/// intent/runtime sidecar and the exact receipt recovered from its issuer.
/// Preparing this value executes physical Create but does not stage a journal,
/// sign an application ACK, or expose a route. The lifecycle caller must first
/// authenticate the retained authorization anchor against its independently
/// selected system journal; the intent image alone cannot prove that anchor.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct RetainedExternalLocalCreate {
    seal: super::replay::ReplaySealedExternalLocalGenesis,
    runtime_package: Vec<u8>,
    intent: crate::service::Hash,
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl RetainedExternalLocalCreate {
    pub(crate) fn prepare<B: super::clean_authority_issuer::CleanManagementRuntimeStore>(
        slot: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
        selected_authority: crate::agent_sdk::authority::AuthorityActorTarget,
        issued_receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        selected_node: crate::agent_sdk::NodeId,
    ) -> Result<Self, super::shared_host::SharedAgentHostError> {
        use super::shared_host::SharedAgentHostError;
        use crate::agent_sdk::{self as sdk, AgentProfile, ManagementRequest, RuntimeWork};

        if selected_node == sdk::NodeId::ZERO
            || slot
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let intent = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
        let ManagementRequest::Create(descriptor) = intent.request() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let descriptor = descriptor.as_ref().clone();
        if descriptor.identity.profile != AgentProfile::Local
            || descriptor.identity.space != selected_authority.space
            || descriptor.authority != selected_authority.binding
            || descriptor.replicas.len() != 1
            || descriptor.replicas[0].node != selected_node
            || descriptor.replicas[0].role != sdk::ReplicaRole::Voter
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        intent
            .verify(
                selected_authority,
                intent.call().managed,
                &super::clean_bootstrap::RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let request = intent.request().clone();
        let intent_hash = external_local_create_intent_hash(intent);
        let Some(RuntimeWork::Invoke { observed_slot, .. }) = slot
            .authorization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let observed_slot = *observed_slot;
        super::driver::verify_clean_management_receipt(
            &descriptor,
            &request,
            issued_receipt,
            observed_slot,
            true,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let runtime_package = slot
            .load_runtime()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        let runtime = super::package_admission::admit_state_runtime_package(&runtime_package)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if !state_runtime_matches_descriptor(&descriptor, &runtime) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let binding = runtime
            .binding(
                SpaceId(descriptor.identity.space.0),
                AgentId(descriptor.identity.agent.0),
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let replica = descriptor.replicas[0];
        let seal = super::local_journal_driver::LocalJournalAgentDriver::<
            super::journal_store::MemoryAgentJournalStore,
        >::prepare_external_local_genesis(
            ReplayInput {
                runtime: binding,
                operation: ReplayOperation::CleanManage {
                    request,
                    authority: issued_receipt.clone(),
                    observed_slot,
                },
            },
            super::AgentReplica {
                node: crate::service::NodeId(replica.node.0),
                principal: crate::service::PrincipalId(replica.principal.0),
                role: super::ReplicaRole::Voter,
            },
            &[super::execution::RuntimeBlob {
                reference: BlobRef {
                    hash: crate::service::Hash(runtime.package_ref().hash.0),
                    len: runtime.package_ref().len,
                },
                bytes: runtime_package.clone(),
            }],
            crate::service::NodeId(selected_node.0),
        )
        .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok(Self {
            seal,
            runtime_package,
            intent: intent_hash,
        })
    }

    pub(crate) fn intent(&self) -> crate::service::Hash {
        self.intent
    }

    /// Stage exact catalog bytes and the complete checkpoint-bearing Create
    /// closure under this signed intent's locked slot. Exposure is a durable
    /// storage marker, not route publication or Authority finalization. A
    /// crash can repeat this method only while the generation is still at its
    /// initial head; finalized retries with later work reopen the owner and
    /// verify the old ACK instead.
    pub(crate) fn publish_initial(
        self,
        slot: super::journal_store::FileLocalAgentJournalSlot,
        budget: &mut ReadBudget,
    ) -> Result<ExternalLocalJournalOwner, super::journal_store::JournalStoreError> {
        use super::journal_store::{AgentJournalStore, JournalBlobClass, JournalStoreError};
        if slot.intent() != self.intent {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let mut store = slot.open_external_genesis(&self.seal, false, budget)?;
        store.put_blob(
            JournalBlobClass::CatalogArtifact,
            &self.seal.genesis().runtime().package,
            &self.runtime_package,
        )?;
        store.initialize_external_local(&self.seal, budget)?;
        store.commit_external_genesis_exposure(&self.seal, self.intent, budget)?;
        let owner = ExternalLocalJournalOwner::adopt_initial_store(store, self.seal, budget)?;
        owner.observe_create_application()?;
        Ok(owner)
    }

    pub(crate) fn into_parts(self) -> (super::replay::ReplaySealedExternalLocalGenesis, Vec<u8>) {
        (self.seal, self.runtime_package)
    }
}

struct AuthenticatedExternalInput {
    input: ReplayInputId,
    before: RuntimeState,
    position: ReplayPosition,
}

/// The greatest valid directory cursor strictly below one nonzero ActorId.
/// InspectActors is exclusive of `after`, so a one-entry page is a targeted
/// lookup even when unrelated actors occupy the same Agent directory.
pub(crate) fn actor_cursor_before(
    actor: crate::agent_sdk::ActorId,
) -> Option<crate::agent_sdk::ActorId> {
    if actor == crate::agent_sdk::ActorId::ZERO {
        return None;
    }
    let mut bytes = actor.0;
    for byte in bytes.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            break;
        }
        *byte = u8::MAX;
    }
    (bytes != [0; 32]).then_some(crate::agent_sdk::ActorId(bytes))
}

/// Reconstruct one immutable route closure from an authenticated directory
/// record and exact catalog blobs. The caller supplies only a resolver owned
/// by its pinned journal; every returned byte is checked against the signed
/// package and current directory, including schema and constructor layout.
#[cfg(all(target_os = "linux", feature = "storage"))]
fn physical_material_from_catalog(
    descriptor: &AgentDescriptor,
    record: crate::agent_sdk::ActorDirectoryRecord,
    observed_slot: u64,
    mut load: impl FnMut(
        &crate::agent_sdk::BlobRef,
    ) -> Result<Vec<u8>, super::journal_store::JournalStoreError>,
) -> Result<
    super::invocation_preparation::PhysicalInvocationMaterial,
    super::journal_store::JournalStoreError,
> {
    use super::journal_store::JournalStoreError;
    use crate::agent_sdk::{self as sdk, RuntimeBlob};

    fn exact(
        reference: &sdk::BlobRef,
        load: &mut impl FnMut(&sdk::BlobRef) -> Result<Vec<u8>, JournalStoreError>,
    ) -> Result<Vec<u8>, JournalStoreError> {
        let bytes = load(reference)?;
        reference
            .matches(&bytes)
            .then_some(bytes)
            .ok_or(JournalStoreError::Corrupt)
    }

    if descriptor.validate().is_err()
        || descriptor.identity.profile != AgentProfile::Local
        || record.validate().is_err()
        || record.entry.suspended
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    let entry = &record.entry;
    let package_bytes = exact(&entry.package, &mut load)?;
    let package = admit_actor_package(&package_bytes).map_err(|_| JournalStoreError::Corrupt)?;
    let program = exact(&package.manifest().program, &mut load)?;
    let schema = exact(&entry.agent_schema, &mut load)?;
    let policies = exact(&entry.method_policy, &mut load)?;
    let parsed = sdk::schema::decode(&schema).map_err(|_| JournalStoreError::Corrupt)?;
    let installation_data = entry
        .installation_data
        .as_ref()
        .map(|reference| {
            exact(reference, &mut load).map(|bytes| RuntimeBlob {
                reference: reference.clone(),
                bytes,
            })
        })
        .transpose()?;
    if package.deployment() != entry.deployment
        || package.program() != entry.program
        || package.package_ref() != &entry.package
        || package.manifest().state_lane_schema != entry.agent_schema
        || package.manifest().method_policy != entry.method_policy
        || program != package.program_bytes()
        || schema != package.state_lane_schema_bytes()
        || policies != package.method_policy_bytes()
        || parsed
            .constructor_abi()
            .map_err(|_| JournalStoreError::Corrupt)?
            != entry.constructor_abi
        || parsed
            .state_layout_hash()
            .map_err(|_| JournalStoreError::Corrupt)?
            != entry.state_layout
        || parsed.lanes() != entry.lanes
        || parsed.requires_installation_data() != installation_data.is_some()
        || !package.requirements().supported_by(AgentProfile::Local)
        || !descriptor
            .runtime_contract
            .supports(package.manifest().contract)
        || !descriptor.capabilities.satisfies(package.requirements())
    {
        return Err(JournalStoreError::Corrupt);
    }
    let schema_ref = entry.agent_schema.clone();
    let policy_ref = entry.method_policy.clone();
    Ok(super::invocation_preparation::PhysicalInvocationMaterial {
        descriptor: descriptor.clone(),
        install_request: record.install_request,
        actor: record,
        producer: package.producer(),
        contract: package.manifest().contract,
        requirements: package.requirements(),
        root_provenance: false,
        observed_slot,
        program: RuntimeBlob {
            reference: package.manifest().program.clone(),
            bytes: program,
        },
        schema: RuntimeBlob {
            reference: schema_ref,
            bytes: schema,
        },
        policies: RuntimeBlob {
            reference: policy_ref,
            bytes: policies,
        },
        installation_data,
    })
}

/// A Create result re-observed from the locked external Local journal's
/// authenticated initial head. It is application evidence for the existing
/// management issuer, not Authority approval or route-publication finality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExternalLocalManagementObservation {
    receipt: crate::agent_sdk::authority::AuthorityReceipt,
    result: crate::agent_sdk::ManagementReply,
    reopened_state: crate::agent_sdk::Hash,
    applied_at: u64,
}

impl ExternalLocalManagementObservation {
    #[cfg(test)]
    pub(crate) fn for_issuer_test(
        receipt: crate::agent_sdk::authority::AuthorityReceipt,
        result: crate::agent_sdk::ManagementReply,
        reopened_state: crate::agent_sdk::Hash,
        applied_at: u64,
    ) -> Self {
        Self {
            receipt,
            result,
            reopened_state,
            applied_at,
        }
    }

    pub(crate) fn receipt(&self) -> &crate::agent_sdk::authority::AuthorityReceipt {
        &self.receipt
    }

    pub(crate) fn result(&self) -> &crate::agent_sdk::ManagementReply {
        &self.result
    }

    pub(crate) fn reopened_state(&self) -> crate::agent_sdk::Hash {
        self.reopened_state
    }

    pub(crate) fn applied_at(&self) -> u64 {
        self.applied_at
    }
}

/// One admitted external runtime, immutable actor catalog resolver and exact
/// genesis descriptor. No standard-runtime private state is decoded here.
/// Unsupported lifecycle forms fail closed until their external lane and
/// publication semantics are qualified.
pub(crate) struct ExternalLocalReplayExecutor<R> {
    runtime: AdmittedStateRuntimePackage,
    descriptor: AgentDescriptor,
    resolver: R,
    seeded: bool,
    authenticated: Option<AuthenticatedExternalInput>,
    pending: Option<ReplayExternalExecution>,
}

impl<R: CatalogBlobResolver> ExternalLocalReplayExecutor<R> {
    pub(crate) fn new(
        runtime: AdmittedStateRuntimePackage,
        descriptor: AgentDescriptor,
        resolver: R,
    ) -> Result<Self, LocalReplayExecutorError> {
        let binding = runtime
            .binding(
                SpaceId(descriptor.identity.space.0),
                AgentId(descriptor.identity.agent.0),
            )
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        if descriptor.validate().is_err()
            || descriptor.identity.profile != AgentProfile::Local
            || descriptor.replicas.len() != 1
            || descriptor.identity.runtime_deployment != runtime.deployment()
            || descriptor.identity.runtime_program != runtime.program()
            || descriptor.identity.runtime_producer != runtime.manifest().signing.producer
            || descriptor.runtime_package != *runtime.package_ref()
            || descriptor.runtime_contract != runtime.manifest().contract
            || descriptor.capabilities != runtime.manifest().capabilities
            || binding.validate().is_err()
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(Self {
            runtime,
            descriptor,
            resolver,
            seeded: false,
            authenticated: None,
            pending: None,
        })
    }

    fn binding(&self) -> Result<RuntimeBinding, LocalReplayExecutorError> {
        self.runtime
            .binding(
                SpaceId(self.descriptor.identity.space.0),
                AgentId(self.descriptor.identity.agent.0),
            )
            .map_err(|_| LocalReplayExecutorError::InvalidState)
    }

    fn load(&self, reference: &BlobRef) -> Result<Vec<u8>, LocalReplayExecutorError> {
        let bytes = self
            .resolver
            .load_catalog(reference)?
            .ok_or_else(|| LocalReplayExecutorError::ArtifactUnavailable(reference.clone()))?;
        if !reference.matches(&bytes) {
            return Err(LocalReplayExecutorError::InvalidArtifact(reference.clone()));
        }
        Ok(bytes)
    }

    fn check_install(&self, request: &ManagementRequest) -> Result<(), LocalReplayExecutorError> {
        let ManagementRequest::Install(install) = request else {
            return Err(LocalReplayExecutorError::InvalidRequest);
        };
        let package_ref = BlobRef {
            hash: crate::service::Hash(install.package.hash.0),
            len: install.package.len,
        };
        let package = admit_actor_package(&self.load(&package_ref)?)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
        super::driver::validate_sdk_management_artifacts(
            &self.descriptor,
            request,
            SdkManagementArtifacts::Actor(&package),
        )
        .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref))?;
        for (reference, expected) in [
            (&install.agent_schema, package.state_lane_schema_bytes()),
            (&install.method_policy, package.method_policy_bytes()),
        ] {
            let reference = BlobRef {
                hash: crate::service::Hash(reference.hash.0),
                len: reference.len,
            };
            if self.load(&reference)? != expected {
                return Err(LocalReplayExecutorError::InvalidArtifact(reference));
            }
        }
        if let Some(data) = &install.installation_data {
            let reference = BlobRef {
                hash: crate::service::Hash(data.reference.hash.0),
                len: data.reference.len,
            };
            if self.load(&reference)? != data.bytes {
                return Err(LocalReplayExecutorError::InvalidArtifact(reference));
            }
        }
        Ok(())
    }

    fn check_authorization(
        &self,
        work: &InvocationRetirement,
        authorization: &InvocationAuthorization,
    ) -> Result<(), LocalReplayExecutorError> {
        if !work.validate()
            || !authorization.matches_retirement(work)
            || work.space != self.descriptor.identity.space
            || work.agent != self.descriptor.identity.agent
            || work.runtime_deployment != self.descriptor.identity.runtime_deployment
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        if let InvocationAuthorization::AuthorityReceipt(receipt) = authorization
            && (!self.descriptor.authority.accepts(receipt)
                || !super::authority::verify_raw_ed25519(
                    &receipt.public_key,
                    &receipt.signing_bytes(),
                    &receipt.signature,
                ))
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        Ok(())
    }

    fn gas(&self, operation: &ReplayOperation) -> Result<u64, LocalReplayExecutorError> {
        let actor = match operation {
            ReplayOperation::CleanInvoke { work, .. } => {
                if work.gas > MAX_EXECUTION_GAS {
                    return Err(LocalReplayExecutorError::InvalidRequest);
                }
                work.gas
            }
            ReplayOperation::CleanManage { .. } | ReplayOperation::CleanAcknowledge { .. } => 0,
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
        };
        DEFAULT_MANAGEMENT_GAS
            .checked_add(actor)
            .ok_or(LocalReplayExecutorError::InvalidRequest)
    }
}

impl<R: CatalogBlobResolver> ReplayExecutor for ExternalLocalReplayExecutor<R> {
    type Error = LocalReplayExecutorError;

    fn seed_genesis(&mut self, genesis: &AgentJournalGenesis) -> Result<(), Self::Error> {
        self.seeded = false;
        self.authenticated = None;
        self.pending = None;
        let ReplayOperation::CleanManage {
            request: ManagementRequest::Create(descriptor),
            authority,
            observed_slot,
        } = &genesis.create.operation
        else {
            return Err(LocalReplayExecutorError::InvalidState);
        };
        if genesis.create.runtime != self.binding()? || descriptor.as_ref() != &self.descriptor {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        super::driver::verify_clean_management_receipt(
            &self.descriptor,
            &ManagementRequest::Create(descriptor.clone()),
            authority,
            *observed_slot,
            false,
        )
        .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        self.seeded = true;
        Ok(())
    }

    fn trusted_clean_descriptor(
        &self,
        runtime: &RuntimeBinding,
    ) -> Result<Option<AgentDescriptor>, Self::Error> {
        if !self.seeded || *runtime != self.binding()? {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(Some(self.descriptor.clone()))
    }

    fn verify_merge_event(&mut self, _: &super::journal::MergeEvent) -> Result<bool, Self::Error> {
        Err(LocalReplayExecutorError::InvalidRequest)
    }

    fn authenticate(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<(), Self::Error> {
        self.authenticated = None;
        self.pending = None;
        if !self.seeded || input.runtime != self.binding()? || position == ReplayPosition::Genesis {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        match &input.operation {
            ReplayOperation::CleanManage {
                request,
                authority,
                observed_slot,
            } => {
                self.check_install(request)?;
                super::driver::verify_clean_management_receipt(
                    &self.descriptor,
                    request,
                    authority,
                    *observed_slot,
                    false,
                )
                .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
            }
            ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
                ..
            } => {
                if !work.validate() || !authorization.matches_invoke(work, *observed_slot) {
                    return Err(LocalReplayExecutorError::InvalidAuthority);
                }
                self.check_authorization(&InvocationRetirement::from_work(work), authorization)?;
            }
            ReplayOperation::CleanAcknowledge {
                work,
                authorization,
                ..
            } => self.check_authorization(work, authorization)?,
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
        }
        self.authenticated = Some(AuthenticatedExternalInput {
            input: input.id(),
            before: before.clone(),
            position,
        });
        Ok(())
    }

    fn execute(
        &mut self,
        _: &ReplayInput,
        _: &RuntimeState,
        _: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error> {
        Err(LocalReplayExecutorError::InvalidRequest)
    }

    fn execute_with_external_state(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        genesis: &AgentJournalGenesis,
        lanes: &[(LaneStateManifest, LaneCursor)],
        reader: &dyn ScopedBlockReader,
        budget: &mut ReadBudget,
    ) -> Result<ReplayTransition, Self::Error> {
        self.pending = None;
        let authenticated = self
            .authenticated
            .take()
            .ok_or(LocalReplayExecutorError::InvalidAuthority)?;
        if authenticated.input != input.id()
            || authenticated.before != *before
            || authenticated.position != position
            || genesis.create.runtime != self.binding()?
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        let gas = self.gas(&input.operation)?;
        let execution = MultiLaneStateBlockHost {
            store: reader,
            budget,
        }
        .execute_admitted_journal(&self.runtime, genesis, input, before, position, lanes, gas)
        .map_err(|error| match error {
            BlockPvmError::Exit { reason, pc } => {
                LocalReplayExecutorError::RuntimeExit { reason, pc }
            }
            BlockPvmError::InvalidRequest | BlockPvmError::ProgramMismatch => {
                LocalReplayExecutorError::InvalidRequest
            }
            _ => LocalReplayExecutorError::RuntimeOutput,
        })?;
        if let ReplayOperation::CleanManage { request, .. } = &input.operation
            && !super::driver::sdk_management_reply_matches(
                &self.descriptor,
                request,
                &execution.output().transition().outcome,
            )
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        let transition = execution.transition().clone();
        self.pending = Some(execution);
        Ok(transition)
    }

    fn clean_management_transition_result(
        &self,
        input: &ReplayInput,
        transition: &ReplayTransition,
    ) -> Option<Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>> {
        self.pending
            .as_ref()?
            .management_result_for(input, transition)
    }

    fn take_external_execution(&mut self) -> Result<Option<ReplayExternalExecution>, Self::Error> {
        Ok(self.pending.take())
    }
}

/// The exposed Local generation's locked store, authenticated replay cursor,
/// and catalog-bound physical executor share one owner lifetime. The caller
/// must first select the exact durable external Create intent and seal; this
/// type neither issues Authority receipts nor publishes an ingress route.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct ExternalLocalJournalOwner {
    seal: super::replay::ReplaySealedExternalLocalGenesis,
    cursor: super::replay::PinnedExternalJournal<
        Box<super::journal_store::FileAgentJournalStore>,
        super::journal_store::FileAgentJournalStore,
    >,
    executor: ExternalLocalReplayExecutor<super::journal_store::FileCatalogBlobResolver>,
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl ExternalLocalJournalOwner {
    fn executor_from_store(
        store: &super::journal_store::FileAgentJournalStore,
        seal: &super::replay::ReplaySealedExternalLocalGenesis,
    ) -> Result<
        ExternalLocalReplayExecutor<super::journal_store::FileCatalogBlobResolver>,
        super::journal_store::JournalStoreError,
    > {
        use super::journal_store::{CatalogBlobResolverFactory, JournalStoreError};
        let resolver = store.catalog_blob_resolver()?;
        let package = &seal.genesis().runtime().package;
        let bytes = resolver
            .load_catalog(package)?
            .ok_or(JournalStoreError::MissingObject)?;
        let runtime = super::package_admission::admit_state_runtime_package(&bytes)
            .map_err(|_| JournalStoreError::Corrupt)?;
        let ReplayOperation::CleanManage {
            request: ManagementRequest::Create(descriptor),
            ..
        } = &seal.genesis().create.operation
        else {
            return Err(JournalStoreError::Corrupt);
        };
        ExternalLocalReplayExecutor::new(runtime, descriptor.as_ref().clone(), resolver)
            .map_err(|_| JournalStoreError::Corrupt)
    }

    pub(crate) fn open(
        slot: super::journal_store::FileLocalAgentJournalSlot,
        seal: super::replay::ReplaySealedExternalLocalGenesis,
        budget: &mut ReadBudget,
    ) -> Result<Self, super::journal_store::JournalStoreError> {
        let (store, executor, validated) = slot.open_external_journal_with_executor(
            &seal,
            |store| Self::executor_from_store(store, &seal),
            &super::replay::NoPrunedOrderedBases,
            budget,
        )?;
        let cursor =
            super::replay::PinnedExternalJournal::open_validated(Box::new(store), validated)?;
        Ok(Self {
            seal,
            cursor,
            executor,
        })
    }

    fn adopt_initial_store(
        mut store: super::journal_store::FileAgentJournalStore,
        seal: super::replay::ReplaySealedExternalLocalGenesis,
        budget: &mut ReadBudget,
    ) -> Result<Self, super::journal_store::JournalStoreError> {
        use super::journal_store::{AgentJournalStore, JournalStoreError};
        let initial = seal
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if store.heads()?.as_ref() != Some(&initial) {
            return Err(JournalStoreError::Conflict);
        }
        let mut executor = Self::executor_from_store(&store, &seal)?;
        let validated = super::replay::validate_external_genesis_head(
            &mut store,
            &seal,
            &initial,
            &mut executor,
            &super::replay::NoPrunedOrderedBases,
            budget,
        )?;
        let cursor =
            super::replay::PinnedExternalJournal::open_validated(Box::new(store), validated)?;
        Ok(Self {
            seal,
            cursor,
            executor,
        })
    }

    pub(crate) fn materialization(
        &self,
    ) -> Result<&super::replay::ReplayMaterialization, super::journal_store::JournalStoreError>
    {
        self.cursor.materialization()
    }

    /// The issuer may sign Create application only after the initial
    /// checkpoint-bearing head is durably reopened and exactly matches this
    /// owner seal. Later journal work cannot be mistaken for the first Create
    /// observation; result and receipt come from replay, never caller input.
    pub(crate) fn observe_create_application(
        &self,
    ) -> Result<ExternalLocalManagementObservation, super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;

        let initial = self
            .seal
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let expected = super::replay::clean_create_management_evidence(&self.seal.genesis().create)
            .ok_or(JournalStoreError::NonCanonical)?;
        let ReplayOperation::CleanManage { authority, .. } = &self.seal.genesis().create.operation
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        self.cursor.inspect(|_, recovered| {
            if recovered.heads() != &initial
                || recovered.clean_management_evidence() != Some(&expected)
                || recovered.state() != self.seal.post_create()
            {
                return Err(JournalStoreError::Conflict);
            }
            let Ok(result) = &expected.result else {
                return Err(JournalStoreError::Corrupt);
            };
            Ok(ExternalLocalManagementObservation {
                receipt: authority.clone(),
                result: result.clone(),
                reopened_state: crate::agent_sdk::Hash::digest(
                    b"vos/agent/local/reopened-external-head/v1",
                    &[&recovered.heads_id().0],
                ),
                applied_at: expected.observed_slot,
            })
        })
    }

    /// A finalized exact retry may find later Install/Invoke work at the
    /// durable head. It must verify the original signed Create ACK against the
    /// authenticated generation, not re-observe the latest management result
    /// or issue another ACK. Only the issuer's finalized-record recovery may
    /// supply this acknowledgement; this check does not establish Authority
    /// actor finality on its own.
    pub(crate) fn verify_finalized_create_ack(
        &self,
        acknowledgement: &crate::agent_sdk::authority::ManagementApplicationAck,
    ) -> Result<(), super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;
        use crate::agent_sdk::{Hash, ManagementReply, ManagementRequest};

        let ReplayOperation::CleanManage {
            request: ManagementRequest::Create(descriptor),
            authority,
            observed_slot,
        } = &self.seal.genesis().create.operation
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        let initial = self
            .seal
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let expected_state = Hash::digest(
            b"vos/agent/local/reopened-external-head/v1",
            &[&initial.id().0],
        );
        if acknowledgement.validate_shape().is_err()
            || acknowledgement.receipt != *authority
            || acknowledgement.request
                != ManagementRequest::Create(descriptor.clone()).replay_commitment()
            || acknowledgement.application != ManagementReply::Created(descriptor.identity.clone())
            || acknowledgement.reopened_state != expected_state
            || acknowledgement.applied_at != *observed_slot
            || acknowledgement.managed.space != descriptor.identity.space
            || acknowledgement.managed.agent != descriptor.identity.agent
            || acknowledgement.managed.owner != descriptor.identity.owner
            || acknowledgement.managed.profile != descriptor.identity.profile
            || acknowledgement.managed.runtime_deployment != descriptor.identity.runtime_deployment
            || acknowledgement.managed.transition_producer
                != descriptor.identity.transition_producer
            || acknowledgement.authority.binding != descriptor.authority
            // Actor authorization and issuer decision sequences are distinct
            // replay clocks. The finalized issuer record binds the former to
            // its approval; the receipt and both signatures are checked here.
            || acknowledgement
                .verify_with(&super::clean_bootstrap::RawCredentialVerifier)
                .is_err()
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        self.cursor.inspect(|store, recovered| {
            self.seal
                .validate_checkpoint_scope(store, recovered.heads())?;
            if recovered.heads() == &initial
                && (recovered.clean_management_evidence()
                    != super::replay::clean_create_management_evidence(&self.seal.genesis().create)
                        .as_ref()
                    || recovered.state() != self.seal.post_create())
            {
                return Err(JournalStoreError::Conflict);
            }
            Ok(())
        })
    }

    /// Inspect the installed directory against this owner's exact pinned
    /// roots and locked store. Read-only guest output cannot publish changes
    /// or replace the authenticated cursor. This is an internal route-building
    /// primitive, not admission of a public route or lifecycle operation.
    pub(crate) fn inspect_actors(
        &self,
        after: Option<crate::agent_sdk::ActorId>,
        limit: u16,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<crate::agent_sdk::ActorDirectoryPage, super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;
        use crate::agent_sdk::{self as sdk, RuntimeOutcome, state_execution::StateExecutionWork};

        let binding = self
            .executor
            .binding()
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        self.cursor.inspect(|store, recovered| {
            if recovered.runtime() != &binding {
                return Err(JournalStoreError::ScopeMismatch);
            }
            let state = sdk::RuntimeState {
                control: recovered.state().control.clone(),
                linear: recovered.state().linear.clone(),
                merge: recovered.state().merge.clone(),
                local: recovered.state().local.clone(),
            };
            let work = StateExecutionWork::new(
                sdk::RuntimeWork::Manage {
                    context: sdk::RuntimeExecutionContext::Direct,
                    space: self.executor.descriptor.identity.space,
                    agent: self.executor.descriptor.identity.agent,
                    runtime_deployment: self.executor.runtime.deployment(),
                    state,
                    request: Box::new(ManagementRequest::InspectActors { after, limit }),
                    authority: None,
                    observed_slot,
                },
                recovered.external_inspection_lanes()?,
                self.executor.runtime.external_state_limits(),
            )
            .map_err(|_| JournalStoreError::NonCanonical)?;
            let output = MultiLaneStateBlockHost { store, budget }
                .execute_admitted_work(&self.executor.runtime, &work, DEFAULT_MANAGEMENT_GAS)
                .map_err(|_| JournalStoreError::Unavailable)?;
            match &output.transition().outcome {
                RuntimeOutcome::Management(Ok(sdk::ManagementReply::Actors(page))) => {
                    if page.entries.len() > usize::from(limit)
                        || page.entries.first().is_some_and(|record| {
                            after.is_some_and(|after| record.entry.actor <= after)
                        })
                        || (page.next.is_some() && page.entries.len() != usize::from(limit))
                    {
                        return Err(JournalStoreError::Corrupt);
                    }
                    Ok(page.clone())
                }
                _ => Err(JournalStoreError::Unavailable),
            }
        })
    }

    /// One guest directory execution for a single ActorId. This avoids
    /// fetching every page for routed work, though the current ABI still
    /// transports the runtime's complete metadata for this one execution.
    pub(crate) fn inspect_actor(
        &self,
        actor: crate::agent_sdk::ActorId,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<
        Option<crate::agent_sdk::ActorDirectoryRecord>,
        super::journal_store::JournalStoreError,
    > {
        if actor == crate::agent_sdk::ActorId::ZERO {
            return Err(super::journal_store::JournalStoreError::NonCanonical);
        }
        let page = self.inspect_actors(actor_cursor_before(actor), 1, observed_slot, budget)?;
        Ok(page
            .entries
            .into_iter()
            .next()
            .filter(|record| record.entry.actor == actor))
    }

    /// Build the current Local route identities from this authenticated
    /// journal's runtime directory. This does not publish or authorize a
    /// route; the lifecycle controller must finish recovery/finality first.
    pub(crate) fn route_identities(
        &self,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<Vec<super::supervisor::AgentRouteIdentity>, super::supervisor::AgentRouteError>
    {
        use super::supervisor::AgentRouteError;
        let descriptor = &self.executor.descriptor;
        let records = super::supervisor_adapters::collect_actor_directory(
            descriptor.capabilities.max_actors as usize,
            |after, limit| {
                self.inspect_actors(after, limit, observed_slot, budget)
                    .map_err(|_| AgentRouteError::Unavailable)
            },
        )?;
        super::supervisor_adapters::route_identities(descriptor, records, AgentProfile::Local)
    }

    /// Resolve one installed Actor's complete immutable invocation inputs
    /// from the current authenticated runtime directory and pinned catalog.
    /// Ingress must still compare the returned material to its route snapshot
    /// and authorize the exact signed work before execution.
    pub(crate) fn physical_invocation_material(
        &self,
        actor: crate::agent_sdk::ActorId,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<
        super::invocation_preparation::PhysicalInvocationMaterial,
        super::journal_store::JournalStoreError,
    > {
        use super::journal_store::JournalStoreError;
        let record = self
            .inspect_actor(actor, observed_slot, budget)?
            .ok_or(JournalStoreError::MissingObject)?;
        physical_material_from_catalog(
            &self.executor.descriptor,
            record,
            observed_slot,
            |reference| {
                let reference = BlobRef {
                    hash: crate::service::Hash(reference.hash.0),
                    len: reference.len,
                };
                self.executor
                    .resolver
                    .load_catalog(&reference)?
                    .ok_or(JournalStoreError::MissingObject)
            },
        )
    }

    pub(crate) fn apply_ordered(
        &mut self,
        entry: &super::journal::OrderedEntry,
        budget: &mut ReadBudget,
    ) -> Result<
        super::replay::ExternalJournalCommit,
        super::replay::MaterializeError<core::convert::Infallible, LocalReplayExecutorError>,
    > {
        self.cursor.apply(
            &mut self.executor,
            super::replay::ExternalJournalEntry::Ordered(entry),
            budget,
        )
    }

    pub(crate) fn apply_local(
        &mut self,
        entry: &super::journal::LocalEntry,
        budget: &mut ReadBudget,
    ) -> Result<
        super::replay::ExternalJournalCommit,
        super::replay::MaterializeError<core::convert::Infallible, LocalReplayExecutorError>,
    > {
        self.cursor.apply(
            &mut self.executor,
            super::replay::ExternalJournalEntry::Local(entry),
            budget,
        )
    }

    pub(crate) fn checkpoint(
        &mut self,
        budget: &mut ReadBudget,
    ) -> Result<super::journal_store::JournalPublication, super::replay::RecoveryError> {
        self.cursor.checkpoint(&self.seal, budget)
    }
}

#[cfg(test)]
mod tests {
    use super::actor_cursor_before;
    use crate::agent_sdk::ActorId;

    #[test]
    fn targeted_actor_cursor_handles_first_id_and_borrow() {
        assert_eq!(actor_cursor_before(ActorId::ZERO), None);
        let mut first = [0; 32];
        first[31] = 1;
        assert_eq!(actor_cursor_before(ActorId(first)), None);
        first[30] = 1;
        first[31] = 0;
        let mut expected = [0; 32];
        expected[31] = u8::MAX;
        assert_eq!(actor_cursor_before(ActorId(first)), Some(ActorId(expected)));
        assert!(ActorId(expected) < ActorId(first));
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    #[test]
    fn external_material_requires_exact_current_actor_artifacts() {
        use std::collections::BTreeMap;

        use super::physical_material_from_catalog;
        use crate::agent::journal::ReplayOperation;
        use crate::agent::journal_store::JournalStoreError;
        use crate::agent::package_admission::tests::{
            admitted_actor_fixture, admitted_state_fixture,
        };
        use crate::agent_sdk::{self as sdk, Hash, InstallationId};

        let runtime = admitted_state_fixture(
            vos_pvm_compiler::assembler::Assembler::new()
                .trap()
                .build_standard(),
        );
        let (create, _, _) = crate::agent::replay::tests::external_create_fixture(&runtime);
        let ReplayOperation::CleanManage {
            request: sdk::ManagementRequest::Create(descriptor),
            ..
        } = create.operation
        else {
            unreachable!()
        };
        let package = admitted_actor_fixture();
        let schema = sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        let record = sdk::ActorDirectoryRecord {
            entry: sdk::ActorEntry {
                actor: ActorId([0x21; 32]),
                name: "fixture".into(),
                parent: None,
                deployment: package.deployment(),
                program: package.program(),
                package: package.package_ref().clone(),
                agent_schema: package.manifest().state_lane_schema.clone(),
                method_policy: package.manifest().method_policy.clone(),
                constructor_abi: schema.constructor_abi().unwrap(),
                installation_data: None,
                state_layout: schema.state_layout_hash().unwrap(),
                lanes: schema.lanes(),
                suspended: false,
            },
            incarnation: Hash([0x22; 32]),
            installation_id: InstallationId([0x23; 32]),
            registry_reservation: Hash([0x24; 32]),
            install_request: Hash([0x25; 32]),
        };
        let mut blobs = BTreeMap::from([
            (
                package.package_ref().clone(),
                package.exact_bytes().to_vec(),
            ),
            (
                package.manifest().program.clone(),
                package.program_bytes().to_vec(),
            ),
            (
                package.manifest().state_lane_schema.clone(),
                package.state_lane_schema_bytes().to_vec(),
            ),
            (
                package.manifest().method_policy.clone(),
                package.method_policy_bytes().to_vec(),
            ),
        ]);
        let resolve = |record: sdk::ActorDirectoryRecord,
                       blobs: &BTreeMap<sdk::BlobRef, Vec<u8>>| {
            physical_material_from_catalog(&descriptor, record, 10, |reference| {
                blobs
                    .get(reference)
                    .cloned()
                    .ok_or(JournalStoreError::MissingObject)
            })
        };
        let material = resolve(record.clone(), &blobs).unwrap();
        assert_eq!(material.actor, record);
        assert_eq!(material.program.bytes, package.program_bytes());
        assert_eq!(material.producer, package.producer());
        assert!(!material.root_provenance);

        let mut wrong_layout = record.clone();
        wrong_layout.entry.state_layout.0[0] ^= 1;
        assert_eq!(
            resolve(wrong_layout, &blobs),
            Err(JournalStoreError::Corrupt)
        );
        let mut suspended = record.clone();
        suspended.entry.suspended = true;
        assert_eq!(
            resolve(suspended, &blobs),
            Err(JournalStoreError::ScopeMismatch)
        );
        blobs.get_mut(&record.entry.agent_schema).unwrap()[0] ^= 1;
        assert_eq!(
            resolve(record.clone(), &blobs),
            Err(JournalStoreError::Corrupt)
        );
        blobs.remove(&record.entry.agent_schema);
        assert_eq!(
            resolve(record, &blobs),
            Err(JournalStoreError::MissingObject)
        );
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn retained_signed_external_create_reconstructs_physical_seal() {
        use super::RetainedExternalLocalCreate;
        use crate::agent::{
            clean_authority_issuer::{CleanManagementIssuerStore, CleanManagementRuntimeStore},
            clean_management_intent::{
                CleanManagementIntent, CleanManagementIntentSlot, ManagementJournalAnchor,
            },
            genesis::AgentGenesisAdmissionId,
            journal::{AgentJournalGenesisId, OrderedBase, ReplayOperation},
            journal_store::FileLocalAgentJournalSlot,
        };
        use crate::agent_sdk::{
            self as sdk,
            authority::{AuthorityActorTarget, AuthorityCredentialCall, ManagedAgentTarget},
        };
        use ed25519_dalek::{Signer as _, SigningKey};
        use std::num::NonZeroU64;

        #[derive(Default)]
        struct Store {
            intent: Option<Vec<u8>>,
            runtime: Option<Vec<u8>>,
        }
        impl CleanManagementIssuerStore for Store {
            type Error = ();
            fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.intent.clone())
            }
            fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                self.intent = Some(image.to_vec());
                Ok(())
            }
        }
        impl CleanManagementRuntimeStore for Store {
            fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.runtime.clone())
            }
            fn commit_runtime(&mut self, package: &[u8]) -> Result<(), Self::Error> {
                self.runtime = Some(package.to_vec());
                Ok(())
            }
        }

        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
        let program = vos_pvm_compiler::link_elf_spi(
            &std::fs::read(
                target.join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf"),
            )
            .expect("build experimental standard guest first"),
        )
        .unwrap();
        let admitted = crate::agent::package_admission::tests::admitted_state_fixture(program);
        let (create, replica, _) = crate::agent::replay::tests::external_create_fixture(&admitted);
        let ReplayOperation::CleanManage {
            request: request @ sdk::ManagementRequest::Create(descriptor),
            authority: receipt,
            observed_slot,
        } = &create.operation
        else {
            unreachable!()
        };
        let identity = &descriptor.identity;
        let authority = AuthorityActorTarget {
            space: identity.space,
            system_agent: sdk::AgentId([0x91; 32]),
            system_runtime_deployment: sdk::DeploymentId([0x92; 32]),
            binding: descriptor.authority,
        };
        let managed = ManagedAgentTarget {
            space: identity.space,
            agent: identity.agent,
            owner: identity.owner,
            profile: identity.profile,
            runtime_deployment: identity.runtime_deployment,
            transition_producer: identity.transition_producer,
        };
        let credential_key = SigningKey::from_bytes(&[0x93; 32]);
        let credential_public_key = credential_key.verifying_key().to_bytes();
        let mut call = AuthorityCredentialCall {
            invocation: sdk::InvocationId::ZERO,
            authority,
            managed,
            principal: identity.owner,
            credential: sdk::CredentialId::of_public_key(&credential_public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key,
            authenticated_node: Some(replica.node),
            requested_valid_from: *observed_slot,
            requested_expires_at: observed_slot + 20,
            plan: request.authorization_plan().unwrap(),
            signature: [0; 64],
        };
        call.invocation = call.expected_invocation();
        call.signature = credential_key.sign(&call.signing_bytes()).to_bytes();
        let intent = CleanManagementIntent::new(
            authority,
            managed,
            request.clone(),
            call.clone(),
            &crate::agent::clean_bootstrap::RawCredentialVerifier,
        )
        .unwrap();
        let work = sdk::InvocationWork {
            space: authority.space,
            agent: authority.system_agent,
            runtime_deployment: authority.system_runtime_deployment,
            invocation: call.invocation,
            actor: authority.binding.issuer.actor,
            incarnation: sdk::Hash([0x94; 32]),
            deployment: authority.binding.issuer.deployment,
            program: authority.binding.issuer.program,
            mode: sdk::MethodMode::Linear,
            origin: intent.authorization_origin(),
            roles: sdk::InvocationRoleClaims::none(),
            message: intent.authorization_message(),
            installation_data: None,
            availability: Vec::new(),
            gas: 1_000_000,
            recovery_only: false,
        };
        let authorization = sdk::InvocationAuthorization::PublicPreflight(
            sdk::PublicPreflight::for_work(&work, *observed_slot),
        );
        let mut slot = CleanManagementIntentSlot::open(Store::default()).unwrap();
        slot.pledge(intent).unwrap();
        slot.retain_runtime(admitted.exact_bytes()).unwrap();
        slot.pledge_authorization_work(
            sdk::RuntimeWork::Invoke {
                context: sdk::RuntimeExecutionContext::Direct,
                state: sdk::RuntimeState::default(),
                invocation: Box::new(work),
                authorization: Box::new(authorization),
                observed_slot: *observed_slot,
            },
            ManagementJournalAnchor {
                genesis: AgentJournalGenesisId([0x95; 32]),
                admission: AgentGenesisAdmissionId::from_bytes([0x96; 32]),
                runtime: crate::service::Hash([0x97; 32]),
                ordered: OrderedBase::post_genesis(),
            },
        )
        .unwrap();
        let mut slot = CleanManagementIntentSlot::open(slot.into_store()).unwrap();
        let (seal, runtime) =
            RetainedExternalLocalCreate::prepare(&mut slot, authority, receipt, replica.node)
                .unwrap()
                .into_parts();
        assert_eq!(seal.genesis().create, create);
        assert_eq!(runtime, admitted.exact_bytes());
        let mut altered_receipt = receipt.clone();
        altered_receipt.signature[0] ^= 1;
        assert!(
            RetainedExternalLocalCreate::prepare(
                &mut slot,
                authority,
                &altered_receipt,
                replica.node,
            )
            .is_err()
        );
        assert!(
            RetainedExternalLocalCreate::prepare(
                &mut slot,
                authority,
                receipt,
                sdk::NodeId([0x98; 32]),
            )
            .is_err()
        );
        struct TestDirectory(std::path::PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TestDirectory(target.join("task-tmp").join(format!(
            "retained-external-create-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
        std::fs::create_dir_all(&directory.0).unwrap();
        let agent_hex = identity
            .agent
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let agent_root = directory.0.join(format!("{agent_hex}.agent"));
        let agent_lock = directory.0.join(format!("{agent_hex}.agent-lock"));
        let parent = std::fs::File::open(&directory.0).unwrap();
        let prepared =
            RetainedExternalLocalCreate::prepare(&mut slot, authority, receipt, replica.node)
                .unwrap();
        let intent_hash = prepared.intent();
        let file_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            agent_root.clone(),
            agent_lock.clone(),
            crate::service::NodeId(replica.node.0),
            intent_hash,
            &parent,
            &parent,
        )
        .unwrap();
        file_slot.verify_absent().unwrap();
        let owner = prepared
            .publish_initial(
                file_slot,
                &mut sdk::state_blocks::ReadBudget::new(10000, 10000000),
            )
            .unwrap();
        assert_eq!(
            owner.observe_create_application().unwrap().receipt(),
            receipt
        );
        let first_head = owner.materialization().unwrap().heads().clone();
        drop(owner);
        let prepared =
            RetainedExternalLocalCreate::prepare(&mut slot, authority, receipt, replica.node)
                .unwrap();
        assert_eq!(prepared.intent(), intent_hash);
        let file_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            agent_root,
            agent_lock,
            crate::service::NodeId(replica.node.0),
            intent_hash,
            &parent,
            &parent,
        )
        .unwrap();
        assert!(matches!(
            file_slot.verify_absent(),
            Err(crate::agent::journal_store::JournalStoreError::Conflict)
        ));
        let owner = prepared
            .publish_initial(
                file_slot,
                &mut sdk::state_blocks::ReadBudget::new(10000, 10000000),
            )
            .unwrap();
        assert_eq!(owner.materialization().unwrap().heads(), &first_head);
        drop(owner);
        let mut store = slot.into_store();
        store.runtime.as_mut().unwrap()[0] ^= 1;
        let mut corrupt = CleanManagementIntentSlot::open(store).unwrap();
        assert!(
            RetainedExternalLocalCreate::prepare(&mut corrupt, authority, receipt, replica.node,)
                .is_err()
        );
    }
}
