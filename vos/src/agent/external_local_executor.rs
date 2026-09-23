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

struct AuthenticatedExternalInput {
    input: ReplayInputId,
    before: RuntimeState,
    position: ReplayPosition,
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
    pub(crate) fn open(
        slot: super::journal_store::FileLocalAgentJournalSlot,
        seal: super::replay::ReplaySealedExternalLocalGenesis,
        budget: &mut ReadBudget,
    ) -> Result<Self, super::journal_store::JournalStoreError> {
        use super::journal_store::{CatalogBlobResolverFactory, JournalStoreError};
        let (store, mut executor) = slot.open_external_journal_with_executor(
            &seal,
            |store| {
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
            },
            &super::replay::NoPrunedOrderedBases,
            budget,
        )?;
        let cursor = super::replay::PinnedExternalJournal::open(
            Box::new(store),
            &seal,
            &mut executor,
            &super::replay::NoPrunedOrderedBases,
            budget,
        )
        .map_err(|_| JournalStoreError::Unavailable)?;
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
