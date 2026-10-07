//! Physical Shared-Agent journal application.
//!
//! This is the narrow bridge between a committed per-Agent Raft log and the
//! generic lane journal/replay engine. Raft never publishes a journal record
//! directly: every ordinary slot is first reserved by the generation ledger,
//! artifact commands cross a durable staging boundary, and Ordered commands
//! cross replay's opaque [`PublishedSharedOrdered`] receipt before the Raft
//! application cursor advances.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::driver::{AgentTrustProvider, SdkManagementArtifacts};
use super::execution::RuntimeBlob;
use super::journal::{
    CanonicalJournalRecord, LocalEntry, MergeEvent, MergeFrontier, OrderedBase, OrderedEntry,
    PersistedLane, ReplayInput, ReplayInputId, ReplayOperation,
};
use super::journal_store::{
    AgentJournalGarbageCollection, AgentJournalStore, CatalogBlobResolver,
    CatalogBlobResolverFactory, GcLimits, JournalBlobClass, JournalGc, JournalStoreError,
    MemoryAgentJournalStore, PortableJournalCheckpoint, PortableJournalLimits,
    ReverifiedRootJournalStore, SharedOrderedCommitRetirementStore, SharedOrderedCommitStore,
    TransitionProofPublicationStore, export_portable_journal_checkpoint, validate_gc_limits,
};
use super::local_journal_driver::{
    AttestedReplayTransitionProvider, LocalMergeAuthenticator, LocalReplayExecutorError,
    StandardLocalReplayExecutor, recent_clean_local_operation, recent_clean_management_operation,
    recent_clean_merge_operation, recent_clean_ordered_operation,
};
use super::replay::{
    CommittedSharedOrdered, MaterializeError, NoPrunedOrderedBases, ReplayExecutor,
    ReplayMaterialization, ReplayPreparation, ReplaySource, SharedReplayPreparation,
    materialize_current, prepare_local, prepare_merge, prepare_shared_checkpoint,
    prepare_shared_ordered, validate_published_shared_checkpoint,
};
use super::shared_commit::{
    OrderedCommitClaim, SharedAgentCommonSnapshotCertificate, SharedAgentCommonSnapshotClaim,
    SharedAgentLocalSnapshotBinding, SharedAgentPortableSnapshotCertificate,
    SharedAgentPortableSnapshotClaim, SharedAgentSnapshotCertificate, SharedAgentSnapshotClaim,
    SharedCommitError, VerifiedSharedAgentPortableSnapshot,
};
use super::shared_raft::{
    ARTIFACT_CHUNK_DATA_BYTES, AgentGenerationRouteKey, AgentRaftApplicationErrorV2,
    AgentRaftApplicationLedgerV2, AgentRaftAuditDisposition, AgentRaftCommand,
    AgentRaftFoundationApplyOutcomeV2, AgentRaftJournalAuditV2, AgentRaftOrderedJournalAnchorV2,
    AgentRaftPendingOrderedV2, ArtifactBatchId, ArtifactBatchManifest, ArtifactChunk,
    CommittedSharedRaftSlot, InstalledAgentRaftSnapshotV2,
};

#[cfg(all(feature = "network", target_os = "linux"))]
mod forwarded_management;
use super::shared_recovery::{
    SharedRecoveryManifest, SharedRecoveryObservation, VerifiedSharedRecoveryObservation,
};
use super::wire::RuntimeState;
use super::{AgentProfile, ReplicaRole};
use crate::service::wire::ServiceWire;
use crate::service::{BlobRef, Hash, NodeId};

type SharedReplayError = MaterializeError<core::convert::Infallible, LocalReplayExecutorError>;

fn management_admission_cost_started() -> Option<std::time::Instant> {
    std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS")
        .is_some()
        .then(std::time::Instant::now)
}

fn trace_management_admission_cost(
    phase: &'static str,
    started: Option<std::time::Instant>,
    items: usize,
    success: bool,
) {
    if let Some(started) = started {
        tracing::debug!(
            phase,
            elapsed_us = started.elapsed().as_micros() as u64,
            items = items.min(super::journal::MAX_REPLAY_SUFFIX_ENTRIES),
            success,
            "Shared management admission cost"
        );
    }
}

fn clean_outcome_kind(outcome: Option<&crate::agent_sdk::RuntimeOutcome>) -> &'static str {
    use crate::agent_sdk::RuntimeOutcome;
    match outcome {
        None => "missing",
        Some(RuntimeOutcome::Acknowledged(Ok(_))) => "ack_ok",
        Some(RuntimeOutcome::Acknowledged(Err(_))) => "ack_err",
        Some(RuntimeOutcome::Completed(Ok(_))) => "completed_ok",
        Some(RuntimeOutcome::Completed(Err(_))) => "completed_err",
        Some(RuntimeOutcome::Yielded(_)) => "yielded",
        Some(RuntimeOutcome::Management(Ok(_))) => "management_ok",
        Some(RuntimeOutcome::Management(Err(_))) => "management_err",
    }
}

// Every unpruned recovery observation is checked against a freshly replayed
// result. Physical metadata slots do not consume this Ordered-result cache.
const _: () = assert!(
    super::local_journal_driver::MAX_PENDING_CLEAN_INVOCATION_RESULTS
        >= super::journal::MAX_REPLAY_SUFFIX_ENTRIES
);

fn validate_replayed_recovery<R: CatalogBlobResolver>(
    ledger: &AgentRaftApplicationLedgerV2,
    executor: &StandardLocalReplayExecutor<R>,
) -> Result<(), SharedJournalDriverError> {
    let evidence = ledger.recovery_replay_evidence()?;
    validate_recovery_replay_evidence(&evidence, |entry, input| {
        executor.clean_ordered_result_at(entry, input)
    })
}

fn validate_recovery_replay_evidence(
    evidence: &[(
        super::journal::OrderedEntryId,
        ReplayInputId,
        Option<crate::agent_sdk::RuntimeOutcome>,
    )],
    outcome_at: impl Fn(
        super::journal::OrderedEntryId,
        ReplayInputId,
    ) -> Option<crate::agent_sdk::RuntimeOutcome>,
) -> Result<(), SharedJournalDriverError> {
    for (entry, input, recorded) in evidence {
        let replayed = outcome_at(*entry, *input);
        let matches = match recorded {
            Some(expected) => replayed.as_ref() == Some(expected),
            None => matches!(
                replayed,
                Some(crate::agent_sdk::RuntimeOutcome::Acknowledged(Err(_)))
            ),
        };
        if !matches {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
    }
    Ok(())
}

fn unique_recovery_observations(
    manifest: &SharedRecoveryManifest,
) -> Vec<&SharedRecoveryObservation> {
    let mut unique = Vec::with_capacity(super::shared_recovery::MAX_SHARED_RECOVERY_SLOTS * 2);
    for observation in manifest.observations() {
        // Equality includes the complete input, claim and outcome. Index or
        // invocation identity alone cannot authorize skipping another proof.
        if !unique.contains(&observation) {
            unique.push(observation);
        }
    }
    unique
}

/// Capacity selection only. The caller has verified the live manifest and any
/// proposed registration; replacement never manufactures evidence for its new
/// member. A positive ACK is not a denial and must not enter denial recovery.
fn management_retention_headroom<'a>(
    heads: &super::journal::JournalHeads,
    manifest: &'a SharedRecoveryManifest,
    incoming: Option<
        &'a super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
    >,
) -> Result<
    (
        Vec<(
            &'a super::clean_management_intent::ManagementJournalAnchor,
            &'a crate::agent_sdk::RuntimeWork,
        )>,
        usize,
        usize,
    ),
    SharedJournalDriverError,
> {
    let scopes = manifest
        .management_slots()
        .iter()
        .filter(|slot| {
            !slot.is_released() && incoming.is_none_or(|request| request.owner() != slot.owner())
        })
        .map(|slot| (slot.owner(), slot.members()))
        .chain(incoming.map(|request| (request.owner(), request.members())));
    let mut pending = Vec::new();
    let mut future_entries = 0usize;
    let mut future_bytes = 0usize;
    for (owner, members) in scopes {
        let root = members
            .first()
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        // Preserve the initial finalization reserve for every unreleased
        // family, even when its root approval was already acknowledged.
        let (entries, bytes) = management_finalization_headroom(heads, root.envelope())?;
        future_entries = future_entries
            .checked_add(entries)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        future_bytes = future_bytes
            .checked_add(bytes)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let retained = manifest
            .management_slot(owner)
            .filter(|slot| !slot.is_released());
        for member in members {
            let acknowledged = retained.is_some_and(|slot| {
                slot.members()
                    .iter()
                    .zip(slot.members_evidence())
                    .any(|(saved, evidence)| {
                        saved == member && evidence.acknowledgement().is_some()
                    })
            });
            // Exact delivery holders share one pending runtime invocation.
            // Keep every family's future reserve above; differing same-ID
            // pairs remain present for the checked budget's original refusal.
            if !acknowledged && !pending.contains(&(member.anchor(), member.envelope())) {
                pending.push((member.anchor(), member.envelope()));
            }
        }
    }
    Ok((pending, future_entries, future_bytes))
}

/// The same conservative future Invoke/ACK framing used by fresh management
/// admission. No placeholder result or runtime effect is created or admitted.
fn management_finalization_headroom(
    heads: &super::journal::JournalHeads,
    envelope: &crate::agent_sdk::RuntimeWork,
) -> Result<(usize, usize), SharedJournalDriverError> {
    let crate::agent_sdk::RuntimeWork::Invoke {
        context,
        invocation,
        authorization,
        observed_slot,
        ..
    } = envelope
    else {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    };
    let mut future_bytes = 0usize;
    for operation in [
        ReplayOperation::CleanInvoke {
            context: *context,
            work: (**invocation).clone(),
            authorization: (**authorization).clone(),
            observed_slot: *observed_slot,
        },
        ReplayOperation::CleanAcknowledge {
            context: *context,
            expected_live: None,
            work: crate::agent_sdk::InvocationRetirement::from_work(invocation),
            authorization: (**authorization).clone(),
        },
    ] {
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: None,
            input: ReplayInput {
                runtime: heads.runtime.clone(),
                operation,
            },
        };
        // A currently absent parent may become a 32-byte hash. Finalization
        // replaces fixed-size identities and may use the full message limit.
        future_bytes = future_bytes
            .checked_add(entry.encode().len())
            .and_then(|bytes| bytes.checked_add(crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES))
            .and_then(|bytes| bytes.checked_add(32))
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    }
    Ok((2, future_bytes))
}

// A verified first capsule may outlive recent suffix evidence. Two absences
// cannot substitute for that capsule or excuse a late/substituted anchor.
fn management_pending_input_matches_anchor(
    recent: Option<ReplayInputId>,
    anchored: Option<ReplayInputId>,
    capsule: Option<ReplayInputId>,
) -> bool {
    recent == anchored || capsule.is_some_and(|input| anchored == Some(input))
}

/// Selection only, after the caller verifies live provenance and the certified
/// baseline. A baseline-retained capsule that no longer has a live owner is
/// not resurrected, and equality includes input, outcome and the entire claim.
fn certified_live_recovery_observation<'a>(
    live: &'a SharedRecoveryManifest,
    baseline: Option<&SharedRecoveryManifest>,
    requested: &SharedRecoveryObservation,
) -> Option<&'a SharedRecoveryObservation> {
    let baseline = baseline?;
    let observation = live
        .observations()
        .into_iter()
        .find(|observation| *observation == requested)?;
    baseline
        .observations()
        .into_iter()
        .any(|certified| certified == observation)
        .then_some(observation)
}

// This is selection, not authentication. The budget's verified live view and
// the freshly audited common-authority view must agree in their entirety:
// matching one requested capsule alone cannot authorize call-local reuse.
fn certified_budget_recovery_observation<'a>(
    budget: &SharedRecoveryManifest,
    live: &'a SharedRecoveryManifest,
    baseline: Option<&SharedRecoveryManifest>,
    requested: &SharedRecoveryObservation,
) -> Option<&'a SharedRecoveryObservation> {
    (budget == live)
        .then(|| certified_live_recovery_observation(live, baseline, requested))
        .flatten()
}

/// Selection only after provenance verification. An invocation collision is
/// never evidence of absence, and a different captured anchor cannot recover
/// this member even when its work bytes happen to match.
fn exact_retained_management_member<'a>(
    manifest: &'a SharedRecoveryManifest,
    anchor: Option<OrderedBase>,
    envelope: &crate::agent_sdk::RuntimeWork,
) -> Result<
    Option<&'a super::shared_recovery::management::SharedManagementRecoveryMemberEvidence>,
    SharedJournalDriverError,
> {
    let crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } = envelope else {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    };
    let mut retained = None;
    for slot in manifest.management_slots() {
        for (member, evidence) in slot.members().iter().zip(slot.members_evidence()) {
            if member.work().invocation != invocation.invocation {
                continue;
            }
            if member.envelope() != envelope
                || anchor.is_some_and(|anchor| member.anchor().ordered != anchor)
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if retained.is_some_and(|prior| prior != evidence) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            retained = Some(evidence);
        }
    }
    Ok(retained)
}

/// A fresh management Invoke cannot pass an earlier admitted immutable clock.
/// Selection is over already authenticated custody, not Standard private state.
/// Exact outcomes are selected before this guard; committed replay is unchanged.
fn management_first_invoke_clock_ready(
    manifest: &SharedRecoveryManifest,
    observed_slot: u64,
) -> Result<bool, SharedJournalDriverError> {
    for slot in manifest
        .management_slots()
        .iter()
        .filter(|slot| !slot.is_released())
    {
        for (member, evidence) in slot.members().iter().zip(slot.members_evidence()) {
            if evidence.invoke().is_some() {
                continue;
            }
            let crate::agent_sdk::RuntimeWork::Invoke {
                observed_slot: accepted_slot,
                ..
            } = member.envelope()
            else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            if *accepted_slot < observed_slot {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// A caller may recover retained outcomes, not execution permission. Match the
/// complete public preflight work before choosing the original physical input.
fn retained_management_operation<'a>(
    manifest: &'a SharedRecoveryManifest,
    operation: &ReplayOperation,
) -> Result<Option<&'a SharedRecoveryObservation>, SharedJournalDriverError> {
    let requested = match operation {
        ReplayOperation::CleanInvoke { work, .. } | ReplayOperation::CleanResume { work, .. } => {
            work.invocation
        }
        ReplayOperation::CleanAcknowledge { work, .. } => work.invocation,
        _ => return Ok(None),
    };
    let mut retained = None;
    for slot in manifest.management_slots() {
        for (member, evidence) in slot.members().iter().zip(slot.members_evidence()) {
            if member.work().invocation != requested {
                continue;
            }
            let matches = match operation {
                ReplayOperation::CleanInvoke {
                    context,
                    work,
                    authorization,
                    ..
                } => {
                    *context == crate::agent_sdk::RuntimeExecutionContext::Direct
                        && member.work() == work
                        && member.authorization() == authorization
                }
                ReplayOperation::CleanAcknowledge {
                    context,
                    expected_live: None,
                    work,
                    authorization,
                } => {
                    *context == crate::agent_sdk::RuntimeExecutionContext::Direct
                        && crate::agent_sdk::InvocationRetirement::from_work(member.work()) == *work
                        && member.authorization() == authorization
                }
                _ => false,
            };
            if !matches {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            let observation = if matches!(operation, ReplayOperation::CleanAcknowledge { .. }) {
                evidence.acknowledgement()
            } else {
                evidence.invoke()
            };
            if let Some(observation) = observation {
                if retained.is_some_and(|prior| prior != observation) {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                retained = Some(observation);
            }
        }
    }
    Ok(retained)
}

/// The manifest has already passed this owner's exact provenance checks.
/// A later ordinary retry outcome must never replace the certified first
/// Invoke response returned under its retained input/availability claim.
fn retained_acknowledged_projection_outcome(
    manifest: Option<&SharedRecoveryManifest>,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    input: ReplayInputId,
    legacy: impl FnOnce() -> Option<crate::agent_sdk::RuntimeOutcome>,
) -> Option<crate::agent_sdk::RuntimeOutcome> {
    manifest
        .and_then(|manifest| {
            manifest.management_slots().iter().find_map(|slot| {
                slot.members()
                    .iter()
                    .zip(slot.members_evidence())
                    .find_map(|(member, evidence)| {
                        (member.work() == work
                            && member.authorization() == authorization
                            && evidence.acknowledgement().is_some())
                        .then(|| evidence.invoke())
                        .flatten()
                        .filter(|observation| observation.input_id() == input)
                    })
            })
        })
        .map(|observation| observation.outcome().clone())
        .or_else(legacy)
}

fn materialize_shared_image<S, E>(
    store: &mut S,
    executor: &mut E,
    ledger: &AgentRaftApplicationLedgerV2,
) -> Result<ReplayMaterialization, SharedReplayError>
where
    S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
    E: ReplayExecutor<Error = LocalReplayExecutorError>,
{
    let authority = ledger.common_snapshot_authority().map_err(|_| {
        super::replay::ReplayError::Source(
            super::replay::ReplayMaterializationSourceError::Journal(JournalStoreError::Corrupt),
        )
    })?;
    if let Some((certificate, binding)) = authority {
        super::replay::materialize_common_checkpoint(
            store,
            executor,
            &NoPrunedOrderedBases,
            &certificate,
            &binding,
        )
    } else {
        materialize_current(store, executor, &NoPrunedOrderedBases)
    }
}

/// Select external checkpoint authority only from the independently audited
/// paired ledger. A bare external genesis still admits its initial checkpoint
/// only; persisted later roots cannot select their own recovery authority.
#[cfg(feature = "experimental-state-blocks")]
fn materialize_external_shared_current<S, E>(
    store: &mut S,
    executor: &mut E,
    ledger: &AgentRaftApplicationLedgerV2,
    genesis: &super::replay::ReplaySealedExternalGenesis,
    budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
) -> Result<
    (
        ReplayMaterialization,
        super::replay::SharedExternalAvailability,
    ),
    SharedJournalDriverError,
>
where
    S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
    E: ReplayExecutor<Error = LocalReplayExecutorError>,
{
    let heads = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
    if let Some((certificate, binding)) = ledger.common_snapshot_authority()? {
        let validated = super::replay::validate_external_common_checkpoint_head(
            store,
            genesis,
            &heads,
            executor,
            &NoPrunedOrderedBases,
            &certificate,
            &binding,
            budget,
        )?;
        validated
            .into_external_common_shared_availability(store, genesis, &certificate, &binding)
            .map_err(Into::into)
    } else {
        let validated = super::replay::validate_external_genesis_head(
            store,
            genesis,
            &heads,
            executor,
            &NoPrunedOrderedBases,
            budget,
        )?;
        validated
            .into_shared_availability(store, genesis)
            .map_err(Into::into)
    }
}

#[cfg(feature = "experimental-state-blocks")]
const EXTERNAL_OPERATION_FETCHES: u32 = 10_000;
#[cfg(feature = "experimental-state-blocks")]
const EXTERNAL_OPERATION_BYTES: u64 = 10_000_000;

#[cfg(feature = "experimental-state-blocks")]
fn external_recovery_limits() -> (u32, u64) {
    use crate::agent_sdk::{state_blocks, state_change, state_tree};
    let blocks = state_change::MAX_STATE_CHANGE_BLOCKS as u32;
    let bytes = state_change::MAX_STATE_CHANGE_BYTES as u64;
    let entries = super::journal::MAX_REPLAY_SUFFIX_ENTRIES as u32;
    // Genesis starts from empty roots, so every tree node is emitted in one
    // bounded change. Chunk references may repeat across leaves, requiring up
    // to a full maximum value read per emitted node. Reserve two base audits.
    // Common external checkpoints additionally require a separately audited
    // ledger certificate and local binding; raw genesis opens stay initial-only.
    let chunks =
        state_tree::MAX_TREE_VALUE_BYTES.div_ceil(state_blocks::MAX_STATE_BLOCK_BYTES) as u32;
    let genesis_fetches = 2 * blocks * (1 + chunks);
    let genesis_bytes = 2 * (bytes + u64::from(blocks) * state_tree::MAX_TREE_VALUE_BYTES as u64);
    // Recovery repeats live execution+reuse checks, and additionally fetches
    // every newly emitted block. The entire maximum legal suffix must reopen,
    // not merely the first operations that fit an unrelated aggregate cap.
    (
        genesis_fetches + entries * (EXTERNAL_OPERATION_FETCHES + blocks),
        genesis_bytes + u64::from(entries) * (EXTERNAL_OPERATION_BYTES + bytes),
    )
}

/// Non-transferable evidence from the exclusive physical journal owner. This
/// is local applied availability, not a quorum certificate or an import seal.
pub(crate) struct VerifiedSharedOrderedAvailability {
    _store: super::shared_raft::JournalStoreInstanceId,
    _epoch: u64,
    _claim: OrderedCommitClaim,
}

/// Exact retained guest disposition inspected at the current authenticated
/// external head. This is deliberately not a historical replay-input token or
/// a transferable quorum certificate. Peer I/O requires fresh revalidation by
/// this same live physical owner before its outcome may be delivered.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) struct RetainedExternalReplyProof {
    store: super::shared_raft::JournalStoreInstanceId,
    epoch: u64,
    heads: super::journal::JournalHeadsId,
    inspection_slot: u64,
    acknowledge: bool,
    retirement: crate::agent_sdk::Hash,
    authorization: crate::agent_sdk::Hash,
    claim: OrderedCommitClaim,
    outcome: crate::agent_sdk::RuntimeOutcome,
}

#[cfg(feature = "experimental-state-blocks")]
impl RetainedExternalReplyProof {
    pub(crate) const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub(crate) const fn outcome(&self) -> &crate::agent_sdk::RuntimeOutcome {
        &self.outcome
    }

    pub(crate) const fn heads(&self) -> super::journal::JournalHeadsId {
        self.heads
    }
}

#[cfg(feature = "experimental-state-blocks")]
fn retained_external_request_kind(request: &CleanInvocationReplayRequest) -> Option<bool> {
    use crate::agent_sdk::{InvocationAuthorization, MethodMode, RuntimeExecutionContext};
    if !matches!(
        request.work().mode,
        MethodMode::Linear | MethodMode::LinearizableQuery
    ) || !matches!(
        request.authorization(),
        InvocationAuthorization::AuthorityReceipt(_)
    ) {
        return None;
    }
    match request {
        CleanInvocationReplayRequest::Invoke {
            context: RuntimeExecutionContext::Direct,
            ..
        } => Some(false),
        CleanInvocationReplayRequest::Acknowledge { .. } => Some(true),
        _ => None,
    }
}

/// Only the guest's explicit absent result can fall back to fresh admission.
/// A retained result on ACK still needs a real Ordered retirement; an already
/// acknowledged Invoke must never be rerun as unseen application work.
#[cfg(feature = "experimental-state-blocks")]
fn retained_external_reply_outcome(
    retirement: &crate::agent_sdk::InvocationRetirement,
    authorization: crate::agent_sdk::Hash,
    acknowledge: bool,
    outcome: crate::agent_sdk::RuntimeOutcome,
) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedJournalDriverError> {
    use crate::agent_sdk::{InvocationError, RuntimeOutcome};
    let invalid = || SharedJournalDriverError::Executor(LocalReplayExecutorError::InvalidRequest);
    match &outcome {
        RuntimeOutcome::Completed(Err(InvocationError::NotReady)) => Ok(None),
        RuntimeOutcome::Completed(Ok(reply))
            if reply.invocation == retirement.invocation
                && reply.actor == retirement.actor
                && reply.incarnation == retirement.incarnation
                && reply.deployment == retirement.deployment
                && reply.mode == retirement.mode
                && reply.lane == retirement.mode.write_lane()
                && reply.gas_remaining <= retirement.gas =>
        {
            Ok((!acknowledge).then_some(outcome))
        }
        RuntimeOutcome::Completed(Err(error)) if error.is_durable_exact_outcome() => {
            Ok((!acknowledge).then_some(outcome))
        }
        RuntimeOutcome::Acknowledged(Ok(reply))
            if reply.validate()
                && reply.invocation == retirement.invocation
                && reply.actor == retirement.actor
                && reply.incarnation == retirement.incarnation
                && reply.deployment == retirement.deployment
                && reply.mode == retirement.mode
                && reply.work == retirement.commitment()
                && reply.authorization == authorization =>
        {
            if acknowledge {
                Ok(Some(outcome))
            } else {
                Err(invalid())
            }
        }
        _ => Err(invalid()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SharedArtifactStagerError {
    Unavailable,
    Conflict,
    Corrupt,
    LimitExceeded,
}

/// Durable artifact-batch staging owned by the physical Shared host.
///
/// `load_complete` is non-consuming so an Ordered publication that loses its
/// response can be replayed without reconstructing bytes from an untrusted
/// source. `retire` is cleanup only and happens after both journal publication
/// and atomic Raft cursor advancement.
pub(crate) trait SharedArtifactStager {
    /// Re-audit the complete durable namespace against the exact generation.
    /// Drivers call this before accepting any replay/ledger state on reopen.
    fn audit(&self, generation: AgentGenerationRouteKey) -> Result<(), SharedArtifactStagerError>;

    fn stage(&mut self, chunk: &ArtifactChunk) -> Result<(), SharedArtifactStagerError>;

    /// Return true only when this exact canonical chunk is already durable.
    /// A conflicting manifest or byte body is corruption, never a cache hit.
    fn contains(&self, chunk: &ArtifactChunk) -> Result<bool, SharedArtifactStagerError>;

    fn abort(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError>;

    fn load_complete(
        &self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(ArtifactBatchManifest, Vec<RuntimeBlob>), SharedArtifactStagerError>;

    fn retire(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError>;
}

/// Opaque proof that the configured durable stager returned and the driver
/// content-validated the complete batch for this exact committee route.
/// Fields and construction remain private to this module; replay can inspect
/// but cannot manufacture the capability.
pub(crate) struct ValidatedSharedArtifactBatch {
    route: super::shared_raft::AgentRouteKey,
    batch: ArtifactBatchId,
}

impl ValidatedSharedArtifactBatch {
    fn new(route: super::shared_raft::AgentRouteKey, batch: ArtifactBatchId) -> Self {
        Self { route, batch }
    }

    pub(super) const fn route(&self) -> super::shared_raft::AgentRouteKey {
        self.route
    }

    pub(super) const fn batch(&self) -> ArtifactBatchId {
        self.batch
    }
}

const STAGING_ROUTE_FILE: &str = "generation.route";
const STAGING_MANIFEST_FILE: &str = "manifest";
const STAGING_NEXT_SUFFIX: &str = ".next";
const STAGING_CHUNK_SUFFIX: &str = ".chunk";
const STAGING_FILE_OVERHEAD_BYTES: usize = 1024;

/// Filesystem-backed staging for one exact Shared journal generation.
///
/// The generation binding is an immutable canonical file outside the batch
/// directories. Every manifest and chunk is installed by a create-new staged
/// file followed by rename+directory fsync. Existing bytes are accepted only
/// as an exact retry. Startup scans the complete namespace and rejects unknown
/// entries, symlinks, noncanonical names, and partial staged files rather than
/// treating ambiguous residue as an empty batch.
#[cfg(target_os = "linux")]
pub(crate) struct FileSharedArtifactStager {
    root: PathBuf,
    generation: AgentGenerationRouteKey,
}

#[cfg(target_os = "linux")]
impl FileSharedArtifactStager {
    pub(crate) fn open(
        root: impl Into<PathBuf>,
        generation: AgentGenerationRouteKey,
    ) -> Result<Self, SharedArtifactStagerError> {
        generation
            .validate()
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        let root = root.into();
        ensure_plain_directory(&root)?;
        let route_path = root.join(STAGING_ROUTE_FILE);
        install_immutable_file(&route_path, &generation.encode())?;
        let stager = Self { root, generation };
        #[cfg(feature = "network")]
        forwarded_management::discard_forwarded_install_uploads(&stager)?;
        stager.audit_namespace()?;
        Ok(stager)
    }

    pub(crate) const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }

    fn audit_namespace(&self) -> Result<(), SharedArtifactStagerError> {
        let route = read_regular_bounded(
            &self.root.join(STAGING_ROUTE_FILE),
            super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES + STAGING_FILE_OVERHEAD_BYTES,
        )?;
        let decoded = AgentGenerationRouteKey::decode(&route)
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if decoded != self.generation || decoded.encode() != route {
            return Err(SharedArtifactStagerError::Conflict);
        }
        for entry in fs::read_dir(&self.root).map_err(|_| SharedArtifactStagerError::Unavailable)? {
            let entry = entry.map_err(|_| SharedArtifactStagerError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SharedArtifactStagerError::Corrupt)?;
            if name == STAGING_ROUTE_FILE {
                require_regular(&entry.path())?;
                continue;
            }
            #[cfg(feature = "network")]
            if name == forwarded_management::FORWARDED_INSTALL_DIRECTORY {
                forwarded_management::audit_forwarded_install_uploads(self)?;
                continue;
            }
            let batch = decode_batch_directory_name(&name)?;
            require_directory(&entry.path())?;
            self.audit_batch(batch, &entry.path(), false)?;
        }
        Ok(())
    }

    fn batch_path(&self, batch: ArtifactBatchId) -> PathBuf {
        self.root.join(encode_hex(batch.as_bytes()))
    }

    fn manifest(
        &self,
        batch: ArtifactBatchId,
        path: &Path,
    ) -> Result<ArtifactBatchManifest, SharedArtifactStagerError> {
        let bytes = read_regular_bounded(
            &path.join(STAGING_MANIFEST_FILE),
            super::shared_raft::MAX_ARTIFACT_BATCH_MANIFEST_BYTES + STAGING_FILE_OVERHEAD_BYTES,
        )?;
        let manifest = ArtifactBatchManifest::decode(&bytes)
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if manifest.encode() != bytes
            || manifest.id() != batch
            || manifest.route().generation() != self.generation
        {
            return Err(SharedArtifactStagerError::Conflict);
        }
        Ok(manifest)
    }

    fn audit_batch(
        &self,
        batch: ArtifactBatchId,
        path: &Path,
        require_complete: bool,
    ) -> Result<ArtifactBatchManifest, SharedArtifactStagerError> {
        let manifest = self.manifest(batch, path)?;
        let mut expected = BTreeSet::new();
        expected.insert(STAGING_MANIFEST_FILE.to_owned());
        for (artifact_index, reference) in manifest.artifacts().iter().enumerate() {
            let mut offset = 0_u64;
            while offset < reference.len {
                expected.insert(chunk_file_name(artifact_index as u32, offset));
                offset = offset
                    .checked_add(super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES as u64)
                    .ok_or(SharedArtifactStagerError::LimitExceeded)?;
            }
        }
        for entry in fs::read_dir(path).map_err(|_| SharedArtifactStagerError::Unavailable)? {
            let entry = entry.map_err(|_| SharedArtifactStagerError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SharedArtifactStagerError::Corrupt)?;
            if !expected.contains(&name) {
                return Err(SharedArtifactStagerError::Corrupt);
            }
            require_regular(&entry.path())?;
        }
        if require_complete {
            for name in expected {
                require_regular(&path.join(name))?;
            }
        }
        Ok(manifest)
    }

    fn remove_batch(&self, batch: ArtifactBatchId) -> Result<(), SharedArtifactStagerError> {
        let path = self.batch_path(batch);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(SharedArtifactStagerError::Unavailable),
        }
        require_directory(&path)?;
        self.audit_batch(batch, &path, false)?;
        for entry in fs::read_dir(&path).map_err(|_| SharedArtifactStagerError::Unavailable)? {
            let entry = entry.map_err(|_| SharedArtifactStagerError::Unavailable)?;
            require_regular(&entry.path())?;
            fs::remove_file(entry.path()).map_err(|_| SharedArtifactStagerError::Unavailable)?;
        }
        fs::remove_dir(&path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
        sync_directory(&self.root)
    }
}

#[cfg(target_os = "linux")]
impl SharedArtifactStager for FileSharedArtifactStager {
    fn audit(&self, generation: AgentGenerationRouteKey) -> Result<(), SharedArtifactStagerError> {
        if generation != self.generation {
            return Err(SharedArtifactStagerError::Conflict);
        }
        self.audit_namespace()
    }

    fn stage(&mut self, chunk: &ArtifactChunk) -> Result<(), SharedArtifactStagerError> {
        chunk
            .validate()
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if chunk.manifest().route().generation() != self.generation {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let path = self.batch_path(chunk.batch());
        ensure_plain_directory(&path)?;
        install_immutable_file(
            &path.join(STAGING_MANIFEST_FILE),
            &chunk.manifest().encode(),
        )?;
        let existing = self.manifest(chunk.batch(), &path)?;
        if &existing != chunk.manifest() {
            return Err(SharedArtifactStagerError::Conflict);
        }
        install_immutable_file(
            &path.join(chunk_file_name(chunk.artifact_index(), chunk.offset())),
            chunk.bytes(),
        )?;
        self.audit_batch(chunk.batch(), &path, false)?;
        Ok(())
    }

    fn contains(&self, chunk: &ArtifactChunk) -> Result<bool, SharedArtifactStagerError> {
        chunk
            .validate()
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if chunk.manifest().route().generation() != self.generation {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let path = self.batch_path(chunk.batch());
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(SharedArtifactStagerError::Unavailable),
            Ok(_) => require_directory(&path)?,
        }
        if self.manifest(chunk.batch(), &path)? != *chunk.manifest() {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let chunk_path = path.join(chunk_file_name(chunk.artifact_index(), chunk.offset()));
        match fs::symlink_metadata(&chunk_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(SharedArtifactStagerError::Unavailable),
            Ok(_) => {
                require_regular(&chunk_path)?;
                let bytes = read_regular_bounded(
                    &chunk_path,
                    super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES + STAGING_FILE_OVERHEAD_BYTES,
                )?;
                if bytes != chunk.bytes() {
                    return Err(SharedArtifactStagerError::Conflict);
                }
                Ok(true)
            }
        }
    }

    fn abort(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError> {
        if route.generation() != self.generation || batch == ArtifactBatchId::ZERO {
            return Err(SharedArtifactStagerError::Conflict);
        }
        self.remove_batch(batch)
    }

    fn load_complete(
        &self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(ArtifactBatchManifest, Vec<RuntimeBlob>), SharedArtifactStagerError> {
        if batch == ArtifactBatchId::ZERO || route.generation() != self.generation {
            return Err(SharedArtifactStagerError::Corrupt);
        }
        let path = self.batch_path(batch);
        require_directory(&path)?;
        let manifest = self.audit_batch(batch, &path, true)?;
        if manifest.route() != route {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let mut blobs = Vec::new();
        blobs
            .try_reserve(manifest.artifacts().len())
            .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
        for (artifact_index, reference) in manifest.artifacts().iter().enumerate() {
            let capacity = usize::try_from(reference.len)
                .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
            let mut offset = 0_u64;
            while offset < reference.len {
                let chunk = read_regular_bounded(
                    &path.join(chunk_file_name(artifact_index as u32, offset)),
                    super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES + STAGING_FILE_OVERHEAD_BYTES,
                )?;
                let expected = (reference.len - offset)
                    .min(super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES as u64)
                    as usize;
                if chunk.len() != expected {
                    return Err(SharedArtifactStagerError::Corrupt);
                }
                bytes.extend_from_slice(&chunk);
                offset = offset
                    .checked_add(super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES as u64)
                    .ok_or(SharedArtifactStagerError::LimitExceeded)?;
            }
            if bytes.len() != capacity || !reference.matches(&bytes) {
                return Err(SharedArtifactStagerError::Corrupt);
            }
            blobs.push(RuntimeBlob {
                reference: reference.clone(),
                bytes,
            });
        }
        Ok((manifest, blobs))
    }

    fn retire(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError> {
        if route.generation() != self.generation || batch == ArtifactBatchId::ZERO {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let path = self.batch_path(batch);
        if path.exists() {
            let manifest = self.manifest(batch, &path)?;
            if manifest.route() != route {
                return Err(SharedArtifactStagerError::Conflict);
            }
        }
        self.remove_batch(batch)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn install_immutable_file(
    path: &Path,
    bytes: &[u8],
) -> Result<(), SharedArtifactStagerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let existing = read_regular_bounded(path, bytes.len().saturating_add(1))?;
            if existing != bytes {
                return Err(SharedArtifactStagerError::Conflict);
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(SharedArtifactStagerError::Corrupt)?;
            let staged = path.with_file_name(format!("{name}{STAGING_NEXT_SUFFIX}"));
            match fs::symlink_metadata(&staged) {
                Ok(_) => {
                    use std::os::unix::fs::MetadataExt as _;

                    let staged_bytes =
                        read_regular_bounded(&staged, bytes.len().saturating_add(1))?;
                    let canonical_meta =
                        fs::metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
                    let staged_meta = fs::metadata(&staged)
                        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
                    if staged_bytes != bytes
                        || canonical_meta.dev() != staged_meta.dev()
                        || canonical_meta.ino() != staged_meta.ino()
                    {
                        return Err(SharedArtifactStagerError::Conflict);
                    }
                    sync_exact_immutable_file(path, bytes)?;
                    fs::remove_file(&staged).map_err(|_| SharedArtifactStagerError::Unavailable)?;
                    let parent = path.parent().ok_or(SharedArtifactStagerError::Corrupt)?;
                    sync_directory(parent)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    sync_exact_immutable_file(path, bytes)?;
                    sync_directory(path.parent().ok_or(SharedArtifactStagerError::Corrupt)?)?;
                }
                Err(_) => return Err(SharedArtifactStagerError::Unavailable),
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(SharedArtifactStagerError::Unavailable),
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SharedArtifactStagerError::Corrupt)?;
    let staged = path.with_file_name(format!("{name}{STAGING_NEXT_SUFFIX}"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    match options.open(&staged) {
        Ok(mut file) => {
            file.write_all(bytes)
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
            file.sync_all()
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular_bounded(&staged, bytes.len().saturating_add(1))?;
            if existing != bytes {
                return Err(SharedArtifactStagerError::Conflict);
            }
            // Readable bytes can remain after an interrupted/failed sync.
            // A retry must establish durability before publishing their name.
            sync_exact_immutable_file(&staged, bytes)?;
        }
        Err(_) => return Err(SharedArtifactStagerError::Unavailable),
    }
    // `hard_link` is the portable create-if-absent publication primitive on
    // Linux. Unlike rename it never replaces a concurrently introduced live
    // entry. The generation host owns the directory, but retaining this
    // property also makes namespace attacks fail closed.
    match fs::hard_link(&staged, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular_bounded(path, bytes.len().saturating_add(1))?;
            if existing != bytes {
                return Err(SharedArtifactStagerError::Conflict);
            }
            sync_exact_immutable_file(path, bytes)?;
        }
        Err(_) => return Err(SharedArtifactStagerError::Unavailable),
    }
    fs::remove_file(&staged).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let parent = path.parent().ok_or(SharedArtifactStagerError::Corrupt)?;
    sync_directory(parent)
}

/// Reestablish durability of the exact already retained inode without changing
/// names. In particular, a complete staged recovery record is not automatically
/// durable merely because it can be read after a process interruption.
#[cfg(target_os = "linux")]
pub(super) fn sync_exact_immutable_file(
    path: &Path,
    expected: &[u8],
) -> Result<(), SharedArtifactStagerError> {
    use std::os::unix::fs::MetadataExt as _;

    require_regular(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let opened = file
        .metadata()
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(expected.len().saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if bytes != expected {
        return Err(SharedArtifactStagerError::Conflict);
    }
    file.sync_all()
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if !named.file_type().is_file()
        || named.file_type().is_symlink()
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
        || named.len() != expected.len() as u64
    {
        return Err(SharedArtifactStagerError::Conflict);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn read_regular_bounded(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, SharedArtifactStagerError> {
    require_regular(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let length = file
        .metadata()
        .map_err(|_| SharedArtifactStagerError::Unavailable)?
        .len();
    if length > maximum as u64 {
        return Err(SharedArtifactStagerError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
    file.take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(SharedArtifactStagerError::LimitExceeded);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn ensure_plain_directory(path: &Path) -> Result<(), SharedArtifactStagerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
            let parent = path.parent().ok_or(SharedArtifactStagerError::Corrupt)?;
            sync_directory(parent)
        }
        Err(_) => Err(SharedArtifactStagerError::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn require_directory(path: &Path) -> Result<(), SharedArtifactStagerError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(SharedArtifactStagerError::Corrupt)
    }
}

#[cfg(target_os = "linux")]
fn require_regular(path: &Path) -> Result<(), SharedArtifactStagerError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(SharedArtifactStagerError::Corrupt)
    }
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> Result<(), SharedArtifactStagerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SharedArtifactStagerError::Unavailable)
}

#[cfg(target_os = "linux")]
fn chunk_file_name(artifact_index: u32, offset: u64) -> String {
    format!("{artifact_index:08x}-{offset:016x}{STAGING_CHUNK_SUFFIX}")
}

#[cfg(target_os = "linux")]
fn decode_batch_directory_name(name: &str) -> Result<ArtifactBatchId, SharedArtifactStagerError> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SharedArtifactStagerError::Corrupt);
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let position = index * 2;
        *byte = u8::from_str_radix(&name[position..position + 2], 16)
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
    }
    let batch = ArtifactBatchId::from_bytes(bytes);
    if batch == ArtifactBatchId::ZERO || encode_hex(batch.as_bytes()) != name {
        return Err(SharedArtifactStagerError::Corrupt);
    }
    Ok(batch)
}

#[cfg(target_os = "linux")]
fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SharedPhysicalApplyOutcome {
    Applied { index: u64 },
    Duplicate { index: u64 },
    Idle,
}

/// Publication state of one canonical Merge object. Content storage is not a
/// substitute for reachability from the authenticated journal head: fetched
/// parents are durably staged before their complete closure is available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SharedMergeObject {
    Missing,
    Staged(Vec<u8>),
    Published(Vec<u8>),
}

/// Deterministic test executor used only to create a fully authenticated
/// Local-head suffix around the snapshot predecessor regression. Production
/// Shared replay always uses `StandardLocalReplayExecutor` above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SharedSnapshotCompactionOutcome {
    pub(crate) bindings_removed: usize,
    pub(crate) bindings_remaining: usize,
    pub(crate) journal: Option<JournalGc>,
}

#[derive(Debug)]
pub(crate) enum SharedJournalDriverError {
    Store(JournalStoreError),
    Replay(SharedReplayError),
    Ledger(AgentRaftApplicationErrorV2),
    Artifact(SharedArtifactStagerError),
    WrongReplica,
    InvalidProfile,
    InvalidArtifactBatch,
    CrossStoreMismatch,
    Snapshot(SharedCommitError),
    Executor(LocalReplayExecutorError),
}

impl From<JournalStoreError> for SharedJournalDriverError {
    fn from(error: JournalStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<SharedReplayError> for SharedJournalDriverError {
    fn from(error: SharedReplayError) -> Self {
        Self::Replay(error)
    }
}

impl From<AgentRaftApplicationErrorV2> for SharedJournalDriverError {
    fn from(error: AgentRaftApplicationErrorV2) -> Self {
        Self::Ledger(error)
    }
}

impl From<SharedArtifactStagerError> for SharedJournalDriverError {
    fn from(error: SharedArtifactStagerError) -> Self {
        Self::Artifact(error)
    }
}

impl From<SharedCommitError> for SharedJournalDriverError {
    fn from(error: SharedCommitError) -> Self {
        Self::Snapshot(error)
    }
}

impl From<LocalReplayExecutorError> for SharedJournalDriverError {
    fn from(error: LocalReplayExecutorError) -> Self {
        Self::Executor(error)
    }
}

/// Canonical Raft proposal and replay correlation for one clean ordered
/// invocation. No mutable journal state changes while this value is built.
pub(crate) enum PreparedCleanOrdered {
    Retained {
        input: ReplayInputId,
        outcome: crate::agent_sdk::RuntimeOutcome,
    },
    Proposal {
        input: ReplayInputId,
        payload: Vec<u8>,
    },
}

impl PreparedCleanOrdered {
    pub(crate) const fn input(&self) -> ReplayInputId {
        match self {
            Self::Retained { input, .. } | Self::Proposal { input, .. } => *input,
        }
    }

    pub(crate) fn retained(&self) -> Option<&crate::agent_sdk::RuntimeOutcome> {
        match self {
            Self::Retained { outcome, .. } => Some(outcome),
            Self::Proposal { .. } => None,
        }
    }

    pub(crate) fn into_payload(self) -> Option<Vec<u8>> {
        match self {
            Self::Retained { .. } => None,
            Self::Proposal { payload, .. } => Some(payload),
        }
    }
}

/// Exact clean invocation-lifecycle request before its trusted observation
/// slot is fixed by the physical driver. No ResumeWork is accepted here: the
/// yielded selector is only a concurrency token and replay reconstructs the
/// executable resume from durable guest state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CleanInvocationReplayRequest {
    Invoke {
        context: crate::agent_sdk::RuntimeExecutionContext,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    },
    Resume {
        context: crate::agent_sdk::RuntimeExecutionContext,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
    },
    Acknowledge {
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    },
}

/// Cursor immediately preceding one canonical actor key. `InspectActors`
/// uses an exclusive cursor, so a one-entry request from this value is a
/// keyed lookup without adding a second directory authority surface.
fn exclusive_actor_predecessor(
    target: crate::agent_sdk::ActorId,
) -> Option<crate::agent_sdk::ActorId> {
    if target == crate::agent_sdk::ActorId::ZERO {
        return None;
    }
    let mut predecessor = target.0;
    for byte in predecessor.iter_mut().rev() {
        if *byte == 0 {
            *byte = u8::MAX;
        } else {
            *byte -= 1;
            let predecessor = crate::agent_sdk::ActorId(predecessor);
            // `InspectActors` rejects an explicit zero cursor. For the
            // smallest valid ActorId, an absent cursor is the exact
            // exclusive predecessor and still yields a one-record lookup.
            return (predecessor != crate::agent_sdk::ActorId::ZERO).then_some(predecessor);
        }
    }
    None
}

impl CleanInvocationReplayRequest {
    pub(crate) const fn work(&self) -> &crate::agent_sdk::InvocationWork {
        match self {
            Self::Invoke { work, .. }
            | Self::Resume { work, .. }
            | Self::Acknowledge { work, .. } => work,
        }
    }

    pub(crate) const fn authorization(&self) -> &crate::agent_sdk::InvocationAuthorization {
        match self {
            Self::Invoke { authorization, .. }
            | Self::Resume { authorization, .. }
            | Self::Acknowledge { authorization, .. } => authorization,
        }
    }

    fn into_operation(self, observed_slot: u64) -> ReplayOperation {
        match self {
            Self::Invoke {
                context,
                work,
                authorization,
            } => ReplayOperation::CleanInvoke {
                context,
                work,
                authorization,
                observed_slot,
            },
            Self::Resume {
                context,
                work,
                authorization,
                yielded,
            } => ReplayOperation::CleanResume {
                context,
                expected_live: None,
                work,
                authorization,
                yielded,
                observed_slot,
            },
            Self::Acknowledge {
                work,
                authorization,
            } => ReplayOperation::CleanAcknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                expected_live: None,
                work: crate::agent_sdk::InvocationRetirement::from_work(&work),
                authorization,
            },
        }
    }
}

/// Result of clean management proposal preparation. An unchanged denial is
/// nondurable and allocates no Raft slot. A successful no-op returns an
/// Ordered command unless a bounded durable suffix lookup proves this exact
/// request and receipt were already committed.
#[derive(Debug)]
pub(crate) enum PreparedCleanManagement {
    Denied {
        outcome: crate::agent_sdk::RuntimeOutcome,
        observed_slot: u64,
    },
    Retained {
        input: ReplayInputId,
        outcome: crate::agent_sdk::RuntimeOutcome,
        observed_slot: u64,
    },
    Proposal {
        input: ReplayInputId,
        observed_slot: u64,
        commands: Vec<Vec<u8>>,
    },
}

/// Created only by the locked journal driver's fresh replay boundary. A caller
/// must retain lifecycle ordering until it durably pledges the signed terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedInstallObservation {
    managed: crate::agent_sdk::authority::ManagedAgentTarget,
    receipt: crate::agent_sdk::authority::AuthorityReceipt,
    result: Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>,
    reopened_state: crate::agent_sdk::Hash,
    applied_at: u64,
}

impl SharedInstallObservation {
    pub(crate) fn managed(&self) -> crate::agent_sdk::authority::ManagedAgentTarget {
        self.managed
    }
    pub(crate) fn receipt(&self) -> &crate::agent_sdk::authority::AuthorityReceipt {
        &self.receipt
    }
    pub(crate) fn result(
        &self,
    ) -> &Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError> {
        &self.result
    }
    pub(crate) fn reopened_state(&self) -> crate::agent_sdk::Hash {
        self.reopened_state
    }
    pub(crate) fn applied_at(&self) -> u64 {
        self.applied_at
    }
}

impl PreparedCleanManagement {
    pub(crate) const fn input(&self) -> Option<ReplayInputId> {
        match self {
            Self::Denied { .. } => None,
            Self::Retained { input, .. } | Self::Proposal { input, .. } => Some(*input),
        }
    }

    pub(crate) const fn observed_slot(&self) -> u64 {
        match self {
            Self::Denied { observed_slot, .. }
            | Self::Retained { observed_slot, .. }
            | Self::Proposal { observed_slot, .. } => *observed_slot,
        }
    }

    pub(crate) fn denied(&self) -> Option<&crate::agent_sdk::RuntimeOutcome> {
        match self {
            Self::Denied { outcome, .. } => Some(outcome),
            Self::Retained { .. } | Self::Proposal { .. } => None,
        }
    }

    pub(crate) fn retained(&self) -> Option<&crate::agent_sdk::RuntimeOutcome> {
        match self {
            Self::Retained { outcome, .. } => Some(outcome),
            Self::Denied { .. } | Self::Proposal { .. } => None,
        }
    }

    pub(crate) fn into_commands(self) -> Vec<Vec<u8>> {
        match self {
            Self::Denied { .. } | Self::Retained { .. } => Vec::new(),
            Self::Proposal { commands, .. } => commands,
        }
    }
}

/// One independently durable physical Shared replica.
pub(crate) struct SharedJournalAgentDriver<S, A>
where
    S: AgentJournalStore
        + ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + SharedOrderedCommitStore
        + SharedOrderedCommitRetirementStore
        + AgentJournalGarbageCollection
        + TransitionProofPublicationStore,
    A: SharedArtifactStager,
{
    store: S,
    artifacts: A,
    executor: StandardLocalReplayExecutor<S::Resolver>,
    materialization: ReplayMaterialization,
    ledger: AgentRaftApplicationLedgerV2,
    local_node: NodeId,
    replay_trust: Arc<dyn AgentTrustProvider>,
    replay_merge: Arc<dyn LocalMergeAuthenticator>,
    /// Reconstructed from the certified baseline and exact applied suffix on
    /// open; advanced only by successful expiry application. Mutable manifest
    /// bytes cannot lower or invent this trusted admission floor on hot reads.
    #[cfg(feature = "experimental-state-blocks")]
    external: Option<SharedExternalOwner>,
}

#[cfg(feature = "experimental-state-blocks")]
struct SharedExternalOwner {
    genesis: Arc<super::replay::ReplaySealedExternalGenesis>,
    availability: super::replay::SharedExternalAvailability,
}

impl<S, A> SharedJournalAgentDriver<S, A>
where
    S: AgentJournalStore
        + ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + SharedOrderedCommitStore
        + SharedOrderedCommitRetirementStore
        + AgentJournalGarbageCollection
        + TransitionProofPublicationStore,
    A: SharedArtifactStager,
{
    pub(crate) fn open(
        store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        Self::open_with_optional_attested_transition_provider(
            store,
            artifacts,
            ledger,
            trust,
            merge,
            None,
            #[cfg(feature = "experimental-state-blocks")]
            None,
        )
    }

    /// Explicit internal selection from independently certified genesis.
    /// Ordinary image opens never reinterpret external descriptor bytes.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn open_external(
        store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<super::replay::ReplaySealedExternalGenesis>,
    ) -> Result<Self, SharedJournalDriverError> {
        if !genesis.is_shared() {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        Self::open_with_optional_attested_transition_provider(
            store,
            artifacts,
            ledger,
            trust,
            merge,
            None,
            Some(genesis),
        )
    }

    /// Open a Shared replica with the producer/journal coordinator installed
    /// before replaying any retained Attested suffix.
    pub(crate) fn open_with_attested_transition_provider(
        store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Box<dyn AttestedReplayTransitionProvider>,
    ) -> Result<Self, SharedJournalDriverError> {
        Self::open_with_optional_attested_transition_provider(
            store,
            artifacts,
            ledger,
            trust,
            merge,
            Some(provider),
            #[cfg(feature = "experimental-state-blocks")]
            None,
        )
    }

    fn open_with_optional_attested_transition_provider(
        mut store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Option<Box<dyn AttestedReplayTransitionProvider>>,
        #[cfg(feature = "experimental-state-blocks")] external_genesis: Option<
            Arc<super::replay::ReplaySealedExternalGenesis>,
        >,
    ) -> Result<Self, SharedJournalDriverError> {
        let started = std::time::Instant::now();
        let report_phase = |phase: &'static str| {
            tracing::debug!(
                phase,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Shared journal driver open phase complete"
            );
        };
        let local_node = merge.node();
        if local_node != ledger.local_node() {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        artifacts.audit(ledger.generation())?;
        report_phase("artifact_audit");
        let committees = ledger.committee_history()?;
        report_phase("committee_history");
        let resolver = store.catalog_blob_resolver()?;
        let mut executor = StandardLocalReplayExecutor::new_shared(
            resolver,
            trust.clone(),
            merge.clone(),
            committees,
        );
        if let Some(provider) = provider {
            executor.replace_attested_transition_provider(provider);
        }
        report_phase("executor_setup");
        #[cfg(feature = "experimental-state-blocks")]
        let (materialization, external) = if let Some(genesis) = external_genesis {
            let (materialization, availability) = materialize_external_shared_current(
                &mut store,
                &mut executor,
                &ledger,
                &genesis,
                &mut Self::external_recovery_budget(),
            )?;
            (
                materialization,
                Some(SharedExternalOwner {
                    genesis,
                    availability,
                }),
            )
        } else {
            (
                materialize_shared_image(&mut store, &mut executor, &ledger)?,
                None,
            )
        };
        #[cfg(not(feature = "experimental-state-blocks"))]
        let materialization = materialize_shared_image(&mut store, &mut executor, &ledger)?;
        report_phase("materialize_current");
        validate_replayed_recovery(&ledger, &executor)?;
        let active = ledger.active_committee()?;
        let route = ledger.generation();
        let (space, agent, shared_profile) = if executor.seeded_clean_descriptor().is_some() {
            let descriptor =
                executor.trusted_current_clean_descriptor(materialization.runtime())?;
            (
                crate::service::SpaceId(descriptor.identity.space.0),
                crate::service::AgentId(descriptor.identity.agent.0),
                descriptor.identity.profile == crate::agent_sdk::AgentProfile::Shared,
            )
        } else {
            let config = super::wire::decode_standard_runtime_state(materialization.state())
                .map_err(|_| SharedJournalDriverError::InvalidProfile)?
                .config
                .ok_or(SharedJournalDriverError::InvalidProfile)?;
            (
                config.identity.space,
                config.identity.agent,
                config.identity.profile == AgentProfile::Shared,
            )
        };
        if !shared_profile
            || active.profile() != AgentProfile::Shared
            || active.validate().is_err()
            || active.space() != space
            || active.agent() != agent
            || route.space() != space
            || route.agent() != agent
            || route.genesis() != materialization.heads().genesis
            || route.admission() != materialization.heads().admission
            || materialization.heads().node != local_node
            || store.instance_id() != ledger.journal_store()
        {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        let audit = ledger.journal_audit()?;
        report_phase("profile_and_ledger_audit");
        if let Some(snapshot) = &audit.snapshot {
            #[cfg(feature = "experimental-state-blocks")]
            let validated = if let Some(external) = &external {
                super::replay::validate_published_external_shared_checkpoint(
                    &mut store,
                    &materialization,
                    &snapshot.claim,
                    &external.genesis,
                    &external.availability,
                    &mut Self::external_recovery_budget(),
                )
                .map_err(SharedJournalDriverError::from)
            } else {
                validate_published_shared_checkpoint(&store, &materialization, &snapshot.claim)
                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)
            };
            #[cfg(not(feature = "experimental-state-blocks"))]
            let validated =
                validate_published_shared_checkpoint(&store, &materialization, &snapshot.claim)
                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch);
            validated.map_err(|error| {
                tracing::warn!(
                    ?error,
                    checkpoint_matches =
                        materialization.heads().checkpoint == Some(snapshot.claim.checkpoint()),
                    current_ordered_index = materialization.heads().ordered_index,
                    snapshot_ordered_index = snapshot.claim.ordered().ordered().index,
                    "Shared journal open checkpoint validation failed"
                );
                SharedJournalDriverError::CrossStoreMismatch
            })?;
        }
        report_phase("published_checkpoint_validation");
        reconcile_journal_ledger(&store, &materialization, ledger.journal_store(), &audit)
            .map_err(|error| {
                tracing::warn!(?error, "Shared journal open ledger reconciliation failed");
                error
            })?;
        report_phase("reconcile_journal_ledger");
        store.finish_reverified_open()?;
        report_phase("finish_reverified_open");
        Ok(Self {
            store,
            artifacts,
            executor,
            materialization,
            ledger,
            local_node,
            replay_trust: trust,
            replay_merge: merge,
            #[cfg(feature = "experimental-state-blocks")]
            external,
        })
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn external_recovery_budget() -> crate::agent_sdk::state_blocks::ReadBudget {
        let (fetches, bytes) = external_recovery_limits();
        crate::agent_sdk::state_blocks::ReadBudget::new(fetches, bytes)
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn external_operation_budget() -> crate::agent_sdk::state_blocks::ReadBudget {
        crate::agent_sdk::state_blocks::ReadBudget::new(
            EXTERNAL_OPERATION_FETCHES,
            EXTERNAL_OPERATION_BYTES,
        )
    }

    /// Re-materialize the durable journal using a fresh verifier/result cache
    /// before treating a retained Direct terminal result as lifecycle evidence.
    /// Missing/pruned results and histories requiring an unavailable attested
    /// replay provider fail closed; no new invocation is proposed here.
    pub(crate) fn replay_durable_clean_terminal(
        &mut self,
        request: CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.replay_durable_clean_terminal_with_input(request, None)
    }

    pub(crate) fn replay_durable_management_denial(
        &mut self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let input = self
            .management_denial_invocation_after(anchor, envelope)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = envelope
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        self.replay_durable_clean_terminal_with_input(
            CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
            },
            Some(input),
        )
    }

    fn replay_durable_clean_terminal_with_input(
        &mut self,
        request: CleanInvocationReplayRequest,
        anchored_input: Option<ReplayInputId>,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        // Scope nested physical executions without logging request contents or
        // changing the fresh-verifier boundary used for lifecycle evidence.
        let span = tracing::debug_span!(
            "durable_terminal_verification",
            ordered_index = self.materialization.heads().ordered_index,
            anchored = anchored_input.is_some(),
        );
        let _entered = span.enter();
        let started = std::time::Instant::now();
        let operation = request.into_operation(0);
        if let Some(manifest) = self.verified_recovery_manifest()?
            && let Some(observation) = retained_management_operation(&manifest, &operation)?
        {
            if anchored_input.is_some_and(|input| input != observation.input_id()) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            // This exact selector and its availability check share the one
            // freshly verified immutable live view. The existing availability
            // helper still checks the physical anchor or complete certified
            // archived closure; no proof survives this borrowed call.
            self.available_ordered_claim_in_management_budget(
                observation.input_id(),
                Some(&manifest),
                &mut None,
            )?;
            if !matches!(
                observation.outcome(),
                crate::agent_sdk::RuntimeOutcome::Completed(_)
            ) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            return Ok(observation.outcome().clone());
        }
        let (recovered, executor) = self.replay_verified_current()?;
        let input = if let Some(input) = anchored_input {
            input
        } else {
            recent_clean_ordered_operation(&self.store, &recovered, &operation)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?
        };
        let outcome = executor
            .clean_ordered_result(input)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if !matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(_)) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros() as u64,
            "durable terminal verification complete"
        );
        Ok(outcome)
    }

    fn replay_verified_current(
        &mut self,
    ) -> Result<
        (
            ReplayMaterialization,
            StandardLocalReplayExecutor<S::Resolver>,
        ),
        SharedJournalDriverError,
    > {
        let started = std::time::Instant::now();
        let resolver = self.store.catalog_blob_resolver()?;
        let mut executor = StandardLocalReplayExecutor::new_shared(
            resolver,
            self.replay_trust.clone(),
            self.replay_merge.clone(),
            self.ledger.committee_history()?,
        );
        let setup_us = started.elapsed().as_micros() as u64;
        let materialize_started = std::time::Instant::now();
        #[cfg(feature = "experimental-state-blocks")]
        let (recovered, recovered_availability) = if let Some(external) = &self.external {
            let recovered = materialize_external_shared_current(
                &mut self.store,
                &mut executor,
                &self.ledger,
                &external.genesis,
                &mut Self::external_recovery_budget(),
            );
            match recovered {
                Ok((recovered, availability)) => (Ok(recovered), Some(availability)),
                Err(error) => (Err(error), None),
            }
        } else {
            (
                materialize_shared_image(&mut self.store, &mut executor, &self.ledger)
                    .map_err(SharedJournalDriverError::from),
                None,
            )
        };
        #[cfg(not(feature = "experimental-state-blocks"))]
        let recovered = materialize_shared_image(&mut self.store, &mut executor, &self.ledger)
            .map_err(SharedJournalDriverError::from);
        tracing::debug!(
            setup_us,
            materialize_us = materialize_started.elapsed().as_micros() as u64,
            succeeded = recovered.is_ok(),
            "durable terminal materialization complete"
        );
        let recovered = recovered.map_err(|error| {
            #[cfg(feature = "experimental-state-blocks")]
            if let Some(external) = &self.external {
                external.availability.invalidate();
            }
            error
        })?;
        validate_replayed_recovery(&self.ledger, &executor)?;
        let audit = self.ledger.journal_audit()?;
        if let Some(snapshot) = &audit.snapshot {
            #[cfg(feature = "experimental-state-blocks")]
            if let Some(external) = &self.external {
                super::replay::validate_published_external_shared_checkpoint(
                    &mut self.store,
                    &recovered,
                    &snapshot.claim,
                    &external.genesis,
                    recovered_availability
                        .as_ref()
                        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                    &mut Self::external_recovery_budget(),
                )?;
            } else {
                validate_published_shared_checkpoint(&self.store, &recovered, &snapshot.claim)
                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            }
            #[cfg(not(feature = "experimental-state-blocks"))]
            validate_published_shared_checkpoint(&self.store, &recovered, &snapshot.claim)
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        }
        reconcile_journal_ledger(&self.store, &recovered, self.ledger.journal_store(), &audit)?;
        if recovered.heads() != self.materialization.heads()
            || recovered.state() != self.materialization.state()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok((recovered, executor))
    }

    /// Only fresh authenticated replay can construct an Install observation.
    /// Bind its identity to the retained management boundary, not the mutable
    /// current state: later Invoke/ACK and certified compaction must preserve
    /// exact terminal recovery. A later management mutation replaces this
    /// evidence and cannot stand in for an unfinished predecessor.
    /// This proves a durable result, not Authority finality or route readiness.
    pub(crate) fn observe_durable_install(
        &mut self,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<SharedInstallObservation, SharedJournalDriverError> {
        if !matches!(request, crate::agent_sdk::ManagementRequest::Install(_)) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let (recovered, executor) = self.replay_verified_current()?;
        let evidence = recovered
            .clean_management_evidence()
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let head = evidence
            .ordered
            .head
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if evidence.ordered.index == 0
            || evidence.ordered.index > recovered.ordered_base().index
            || evidence.input == ReplayInputId::ZERO
            || evidence.authority != receipt.commitment()
            || evidence.request != request.replay_commitment()
            || evidence.epoch != receipt.selector.epoch
            || evidence.sequence != receipt.selector.decision_sequence
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let descriptor = executor.trusted_current_clean_descriptor(recovered.runtime())?;
        if descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let expiry = super::driver::verify_clean_management_journal_receipt(
            &descriptor,
            request,
            receipt,
            evidence.observed_slot,
            false,
        )
        .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        if expiry
            && evidence.result != Err(crate::agent_sdk::ManagementError::ExpiredBeforeApplication)
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        // The authenticated Ordered entry binds execution and its state roots.
        // Its identity survives subsequent application work and checkpointing;
        // hashing today's full runtime state would manufacture a different ACK
        // for the same completed Install after any later invocation.
        let commitment = crate::agent_sdk::Hash::digest(
            b"vos/agent/shared/install-terminal/v1",
            &[
                &recovered.heads().genesis.0,
                &evidence.input.0,
                &head.0,
                &evidence.ordered.index.to_le_bytes(),
                &evidence.authority.0,
                &evidence.request.0,
                &evidence.observed_slot.to_le_bytes(),
            ],
        );
        Ok(SharedInstallObservation {
            managed: crate::agent_sdk::authority::ManagedAgentTarget {
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                owner: descriptor.identity.owner,
                profile: descriptor.identity.profile,
                runtime_deployment: descriptor.identity.runtime_deployment,
                transition_producer: descriptor.identity.transition_producer,
            },
            receipt: receipt.clone(),
            result: evidence.result.clone(),
            reopened_state: commitment,
            applied_at: evidence.observed_slot,
        })
    }

    pub(crate) fn local_role(&self) -> Result<Option<ReplicaRole>, SharedJournalDriverError> {
        Ok(self
            .ledger
            .active_committee()?
            .member_by_node(self.local_node)
            .map(|member| member.replica().role))
    }

    pub(crate) fn identity(&self) -> Result<super::AgentIdentity, SharedJournalDriverError> {
        if self.executor.seeded_clean_descriptor().is_some() {
            let identity = self
                .executor
                .trusted_current_clean_descriptor(self.materialization.runtime())?
                .identity;
            return Ok(super::AgentIdentity {
                space: crate::service::SpaceId(identity.space.0),
                agent: crate::service::AgentId(identity.agent.0),
                owner: crate::service::PrincipalId(identity.owner.0),
                profile: match identity.profile {
                    crate::agent_sdk::AgentProfile::Local => AgentProfile::Local,
                    crate::agent_sdk::AgentProfile::Shared => AgentProfile::Shared,
                    crate::agent_sdk::AgentProfile::Private => AgentProfile::Private,
                },
                runtime_deployment: crate::service::DeploymentId(identity.runtime_deployment.0),
                runtime_program: crate::service::ProgramId(identity.runtime_program.0),
                runtime_producer: crate::service::ProducerId(identity.runtime_producer.0),
                transition_producer: crate::service::ProducerId(identity.transition_producer.0),
            });
        }
        let state = super::wire::decode_standard_runtime_state(self.materialization.state())
            .map_err(|_| SharedJournalDriverError::InvalidProfile)?;
        Ok(state
            .config
            .ok_or(SharedJournalDriverError::InvalidProfile)?
            .identity)
    }

    /// Exact current clean descriptor reconstructed from the authenticated
    /// runtime binding and admitted package. Supervisor projections must use
    /// this value rather than the immutable genesis descriptor so a runtime
    /// upgrade invalidates every older readiness generation.
    pub(crate) fn clean_descriptor(
        &self,
    ) -> Result<crate::agent_sdk::AgentDescriptor, SharedJournalDriverError> {
        self.executor
            .trusted_current_clean_descriptor(self.materialization.runtime())
            .map_err(Into::into)
    }

    /// Resolve the current actor and every immutable invocation artifact from
    /// the authenticated journal catalog. This is read-only, but it remains
    /// on the physical driver so a policy projection can never provide the
    /// bytes or logical slot used for authority issuance.
    pub(crate) fn physical_invocation_material(
        &self,
        target: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedJournalDriverError>
    {
        self.physical_material(target, true)
    }

    pub(crate) fn physical_authority_material(
        &self,
        target: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedJournalDriverError>
    {
        self.physical_material(target, false)
    }

    fn physical_material(
        &self,
        target: crate::agent_sdk::ActorId,
        require_ready: bool,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedJournalDriverError>
    {
        if target == crate::agent_sdk::ActorId::ZERO {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let descriptor = self.clean_descriptor()?;
        if descriptor.validate().is_err()
            || descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
        {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        // The admitted runtime owns its opaque state representation. Obtain
        // directory facts, including immutable install lineage, by executing
        // the canonical read-only ABI against the authenticated current state.
        // `InspectActors` is exclusive-after and the directory is ordered by
        // the actor's canonical bytes. Query from the immediate predecessor
        // with a one-record limit so one invocation never walks the global
        // directory (or lets unrelated actor count become backpressure).
        let after = exclusive_actor_predecessor(target);
        let outcome =
            self.inspect_clean_management(&crate::agent_sdk::ManagementRequest::InspectActors {
                after,
                limit: 1,
            })?;
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Actors(page),
        )) = outcome
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if page.validate().is_err()
            || page.entries.len() != 1
            || page.entries[0].entry.actor != target
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let actor = page.entries[0].clone();
        if actor.validate().is_err()
            || require_ready && actor.entry.suspended
            || actor
                .entry
                .validate_for_profile(descriptor.identity.profile)
                .is_err()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }

        let resolver = self.store.catalog_blob_resolver()?;
        let legacy_ref = |reference: &crate::agent_sdk::BlobRef| BlobRef {
            hash: Hash(reference.hash.0),
            len: reference.len,
        };
        let load = |reference: &crate::agent_sdk::BlobRef| {
            resolver
                .load_catalog(&legacy_ref(reference))
                .map_err(SharedJournalDriverError::Store)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)
        };
        let package_bytes = load(&actor.entry.package)?;
        let package = super::package_admission::admit_actor_package(&package_bytes)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let schema_bytes = load(&actor.entry.agent_schema)?;
        let policy_bytes = load(&actor.entry.method_policy)?;
        let installation_data = actor
            .entry
            .installation_data
            .as_ref()
            .map(|reference| {
                load(reference).map(|bytes| crate::agent_sdk::RuntimeBlob {
                    reference: reference.clone(),
                    bytes,
                })
            })
            .transpose()?;
        let parsed_schema = crate::agent_sdk::schema::decode(&schema_bytes)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        if package.package_ref() != &actor.entry.package
            || package.deployment() != actor.entry.deployment
            || package.program() != actor.entry.program
            || package.manifest().state_lane_schema != actor.entry.agent_schema
            || package.manifest().method_policy != actor.entry.method_policy
            || package.state_lane_schema_bytes() != schema_bytes
            || package.method_policy_bytes() != policy_bytes
            || package
                .envelope()
                .constructor_abi()
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?
                != actor.entry.constructor_abi
            || parsed_schema
                .state_layout_hash()
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?
                != actor.entry.state_layout
            || parsed_schema.lanes() != actor.entry.lanes
            || parsed_schema.requires_installation_data() != actor.entry.installation_data.is_some()
            || installation_data
                .as_ref()
                .map(|blob| crate::agent_sdk::BlobRef::of_bytes(&blob.bytes))
                != actor.entry.installation_data
            || !package
                .requirements()
                .supported_by(descriptor.identity.profile)
            || !descriptor
                .runtime_contract
                .supports(package.manifest().contract)
            || !descriptor.capabilities.satisfies(package.requirements())
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let program_bytes = package.program_bytes().to_vec();
        let observed_slot = self.executor.current_logical_slot()?;
        let install_request = actor.install_request;
        Ok(super::invocation_preparation::PhysicalInvocationMaterial {
            descriptor,
            actor,
            install_request,
            producer: package.producer(),
            contract: package.manifest().contract,
            requirements: package.requirements(),
            root_provenance: false,
            observed_slot,
            program: crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&program_bytes),
                bytes: program_bytes,
            },
            schema: crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&schema_bytes),
                bytes: schema_bytes,
            },
            policies: crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&policy_bytes),
                bytes: policy_bytes,
            },
            installation_data,
        })
    }

    pub(crate) fn active_route(
        &self,
    ) -> Result<super::shared_raft::AgentRouteKey, SharedJournalDriverError> {
        super::shared_raft::AgentRouteKey::new(
            self.ledger.generation().space(),
            self.ledger.generation().agent(),
            self.ledger.generation().genesis(),
            self.ledger.generation().admission(),
            self.ledger.active_committee()?.id(),
        )
        .map_err(|_| SharedJournalDriverError::WrongReplica)
    }

    pub(crate) fn active_committee(
        &self,
    ) -> Result<super::genesis::AgentReplicaCommittee, SharedJournalDriverError> {
        Ok(self.ledger.active_committee()?)
    }

    pub(crate) fn current_logical_slot(&self) -> Result<u64, SharedJournalDriverError> {
        self.executor.current_logical_slot().map_err(Into::into)
    }

    pub(crate) fn network_committee_state(
        &self,
    ) -> Result<super::shared_raft::AgentNetworkCommitteeState, SharedJournalDriverError> {
        Ok(self.ledger.network_committee_state()?)
    }

    pub(crate) fn engine_lanes(&self) -> Result<super::LaneSet, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Ok(super::LaneSet::of(super::StateLane::Linear));
        }
        if self.executor.seeded_clean_descriptor().is_some() {
            return self
                .executor
                .clean_installed_actor_lanes(
                    self.materialization.runtime(),
                    self.materialization.state(),
                )
                .map_err(Into::into);
        }
        let state = super::wire::decode_standard_runtime_state(self.materialization.state())
            .map_err(|_| SharedJournalDriverError::InvalidProfile)?;
        let mut lanes = super::LaneSet::NONE;
        for actor in state.actors {
            lanes = lanes.union(actor.record.entry.lanes);
        }
        Ok(lanes)
    }

    pub(crate) fn merge_roots(&self) -> Result<Vec<[u8; 32]>, SharedJournalDriverError> {
        let frontier = self
            .store
            .get::<super::journal::MergeFrontier>(self.materialization.merge_frontier())?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        Ok(frontier
            .events
            .iter()
            .map(|event| *event.as_bytes())
            .collect())
    }

    pub(crate) fn merge_event_bytes(
        &self,
        event: super::journal::MergeEventId,
    ) -> Result<Option<Vec<u8>>, SharedJournalDriverError> {
        Ok(self
            .store
            .get::<MergeEvent>(event)?
            .map(|event| event.encode()))
    }

    pub(crate) fn merge_object(
        &self,
        id: super::journal::MergeEventId,
    ) -> Result<SharedMergeObject, SharedJournalDriverError> {
        let Some(event) = self.store.get::<MergeEvent>(id)? else {
            return Ok(SharedMergeObject::Missing);
        };
        if event.id() != id || event.validate().is_err() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let bytes = event.encode();
        Ok(if self.materialization.contains_merge(id) {
            SharedMergeObject::Published(bytes)
        } else {
            SharedMergeObject::Staged(bytes)
        })
    }

    /// Persist one independently authenticated immutable Merge object without
    /// moving journal heads. This is the crash-safe anti-entropy staging
    /// boundary: full causal replay and publication remain in `import_merge`.
    pub(crate) fn stage_merge(
        &mut self,
        event: &MergeEvent,
    ) -> Result<bool, SharedJournalDriverError> {
        let active = self.ledger.active_committee()?;
        if event.validate().is_err()
            || event.genesis != self.materialization.heads().genesis
            || event.committee != Some(active.id())
            || active.member_by_node(event.author).is_none()
            || !self.executor.verify_merge_event(event)?
        {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        self.store.put(event).map_err(Into::into)
    }

    pub(crate) fn materialization(&self) -> &ReplayMaterialization {
        &self.materialization
    }

    pub(crate) fn latest_clean_management_disposition(
        &self,
    ) -> Result<Option<super::standard::StandardCleanManagementDisposition>, SharedJournalDriverError>
    {
        // The common projection comparator still accepts this legacy-named
        // value type, but its source is host-owned authenticated replay and
        // checkpoint evidence, never a decoded private runtime-state image.
        Ok(self
            .materialization
            .clean_management_evidence()
            .map(
                |evidence| super::standard::StandardCleanManagementDisposition {
                    authority: evidence.authority,
                    request: evidence.request,
                    epoch: evidence.epoch,
                    sequence: evidence.sequence,
                    observed_slot: evidence.observed_slot,
                    result: evidence.result.clone(),
                },
            ))
    }

    /// Return the number of durable Ordered records still required by an
    /// exact projection lifecycle when those records fit the authenticated
    /// composite replay budgets. Recovery first proves a retained positive
    /// Ack, then an exact terminal Invoke, so it reserves zero, one, or two
    /// records rather than pessimistically requiring a fresh pair.

    /// Exact remaining suffix cost of retiring two completed Linear management
    /// invocations. This is a capacity check, not a proposal/GC reservation.
    /// Unlike projection recovery, missing Linear evidence must never trigger
    /// speculative execution at a checkpoint boundary.
    pub(crate) fn management_retirement_admission_requirement(
        &self,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_retirement_set_admission_requirement(&envelopes)
    }

    /// Budget all recovered completed invocations together, not independently
    /// against the same remaining suffix. Callers must retain an admission/GC
    /// exclusion over the entire set until durable retirement completes.
    /// This does not authorize incomplete or prepared-but-unaccepted work.
    pub(crate) fn management_retirement_set_admission_requirement(
        &self,
        envelopes: &[&crate::agent_sdk::RuntimeWork],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_recovery_admission_requirement(&[], envelopes)
    }

    fn management_retirement_delta(
        &self,
        envelopes: &[&crate::agent_sdk::RuntimeWork],
        mut index: u64,
        mut parent: Option<super::journal::OrderedEntryId>,
        manifest: Option<&SharedRecoveryManifest>,
        available: &mut impl FnMut(
            ReplayInputId,
        ) -> Result<OrderedCommitClaim, SharedJournalDriverError>,
    ) -> Result<(usize, usize), SharedJournalDriverError> {
        use crate::agent_sdk::{
            InvocationAuthorization, MethodMode, RuntimeExecutionContext, RuntimeOutcome,
            RuntimeWork,
        };
        // Every member must have its own retained invocation or positive ack
        // in this suffix. A larger set cannot be evidenced by that suffix.
        if envelopes.len() > super::replay::MAX_REPLAY_SUFFIX_ENTRIES {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let heads = self.materialization.heads();
        let mut seen = BTreeSet::new();
        let mut entries = 0usize;
        let mut bytes = 0usize;
        for &envelope in envelopes {
            let RuntimeWork::Invoke {
                context,
                state,
                invocation: work,
                authorization,
                observed_slot,
            } = envelope
            else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            if *context != RuntimeExecutionContext::Direct
                || *state != crate::agent_sdk::RuntimeState::default()
                || work.mode != MethodMode::Linear
                || !work.validate()
                || **authorization
                    != InvocationAuthorization::PublicPreflight(
                        crate::agent_sdk::PublicPreflight::for_work(work, *observed_slot),
                    )
                || !seen.insert(work.invocation)
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if self.retained_positive_clean_acknowledgement_with_availability(
                work,
                authorization,
                manifest,
                available,
            )? {
                continue;
            }
            let invoke = ReplayOperation::CleanInvoke {
                context: *context,
                work: (**work).clone(),
                authorization: (**authorization).clone(),
                observed_slot: *observed_slot,
            };
            let retained = self
                .retained_management_invocation_with_availability(envelope, manifest, available)?;
            let input = match retained.as_ref() {
                Some(observation) => observation.input_id(),
                None => {
                    recent_clean_ordered_operation(&self.store, &self.materialization, &invoke)?
                        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?
                }
            };
            if !matches!(
                retained
                    .as_ref()
                    .map(|observation| observation.outcome().clone())
                    .or_else(|| self.executor.clean_ordered_result(input)),
                Some(RuntimeOutcome::Completed(Ok(_)))
            ) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            index = index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            let entry = OrderedEntry {
                genesis: heads.genesis,
                index,
                parent,
                merge_frontier: heads.merge_frontier,
                merge_seal: None,
                input: ReplayInput {
                    runtime: heads.runtime.clone(),
                    operation: ReplayOperation::CleanAcknowledge {
                        context: *context,
                        expected_live: None,
                        work: crate::agent_sdk::InvocationRetirement::from_work(work),
                        authorization: (**authorization).clone(),
                    },
                },
            };
            entry
                .validate()
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            bytes = bytes
                .checked_add(entry.encode().len())
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            entries += 1;
            parent = Some(entry.id());
        }
        Ok((entries, bytes))
    }

    /// Joint suffix cost for anchored, terminal management invocations and
    /// their acknowledgements. No runtime execution or policy preview occurs.
    /// Anchors must have been durably captured before first dispatch; callers
    /// must exclude competing admission and drain Raft before using the result.
    pub(crate) fn management_pending_admission_requirement(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_recovery_admission_requirement(pending, &[])
    }

    /// Calculate the singleton submission budget and its exact anchored input
    /// in one borrowed read. The caller must consume both under the same
    /// drained admission exclusion, before preparation or publication.
    pub(crate) fn management_pending_admission_with_input(
        &self,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<(Option<usize>, Option<ReplayInputId>), SharedJournalDriverError> {
        let started = management_admission_cost_started();
        let result = self.management_recovery_admission_with_headroom_and_input(
            &[(anchor, envelope)],
            &[],
            0,
            0,
            true,
            None,
        );
        trace_management_admission_cost("singleton_budget", started, 1, result.is_ok());
        result
    }

    /// The caller keeps this custody Invoke's post-drain admission guards.
    /// Reuse only its verified immutable selectors; every unseen member still
    /// receives the existing fresh settled-prefix absence and physical checks.
    pub(crate) fn management_pending_admission_with_input_and_manifest(
        &self,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
        manifest: &SharedRecoveryManifest,
    ) -> Result<(Option<usize>, Option<ReplayInputId>), SharedJournalDriverError> {
        let started = management_admission_cost_started();
        let result = self.management_recovery_admission_with_headroom_and_input(
            &[(anchor, envelope)],
            &[],
            0,
            0,
            true,
            Some(manifest),
        );
        trace_management_admission_cost("singleton_budget", started, 1, result.is_ok());
        result
    }

    /// One prospective Ordered chain for incomplete invocations and completed
    /// results awaiting retirement. Independent per-set checks are insufficient
    /// because both consume the same suffix entry and byte budgets.
    pub(crate) fn management_recovery_admission_requirement(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
        retiring: &[&crate::agent_sdk::RuntimeWork],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_recovery_admission_with_headroom(pending, retiring, 0, 0)
    }

    /// Reserve a complete fresh two-invocation lifecycle before authorization.
    /// Finalization copies the authorization work, replacing only fixed-size
    /// identities, the origin with anonymous, and the bounded message. Budget
    /// the full message limit in addition to the original message, so no
    /// placeholder acknowledgement is treated as application evidence.
    pub(crate) fn management_initial_admission_requirement(
        &self,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        let (future_entries, future_bytes) =
            management_finalization_headroom(self.materialization.heads(), envelope)?;
        self.management_recovery_admission_with_headroom(
            &[(anchor, envelope)],
            &[],
            future_entries,
            future_bytes,
        )
    }

    /// A leader may have no origin-side volatile intent map. Budget all live
    /// owners from authenticated retained custody, replacing only the incoming
    /// owner's validated scope. This neither signs nor reserves admission.
    pub(crate) fn management_retention_admission_requirement(
        &self,
        incoming: Option<
            &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
        >,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_retention_admission_requirement_with_policy(incoming, None)
    }

    /// Borrow only this call's verified immutable manifest under uninterrupted
    /// host/proposal guards. Every incoming request and unseen member still
    /// receives its original fresh physical-prefix admission below.
    pub(crate) fn management_retention_admission_requirement_with_manifest(
        &self,
        incoming: Option<
            &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
        >,
        manifest: &SharedRecoveryManifest,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_retention_admission_requirement_with_policy(incoming, Some(manifest))
    }

    fn management_retention_admission_requirement_with_policy(
        &self,
        incoming: Option<
            &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
        >,
        verified_manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        let fresh_manifest = if verified_manifest.is_none() {
            Some(self.recovery_manifest()?)
        } else {
            None
        };
        let manifest = verified_manifest
            .or(fresh_manifest.as_ref())
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if let Some(request) = incoming {
            self.validate_management_recovery_registration_request_with_policy(
                request,
                verified_manifest,
            )?;
        }
        let started = management_admission_cost_started();
        let headroom =
            management_retention_headroom(self.materialization.heads(), manifest, incoming);
        trace_management_admission_cost(
            "retention_headroom",
            started,
            manifest.management_slots().len(),
            headroom.is_ok(),
        );
        let (pending, future_entries, future_bytes) = headroom?;
        let started = management_admission_cost_started();
        let result = self.management_recovery_admission_with_headroom_and_input(
            &pending,
            &[],
            future_entries,
            future_bytes,
            false,
            verified_manifest,
        )
        .map(|(requirement, _)| requirement);
        trace_management_admission_cost(
            "retention_budget",
            started,
            pending.len(),
            result.is_ok(),
        );
        result
    }

    /// The caller verified this manifest after draining under the same
    /// uninterrupted host/proposal guards. Only new Current ACK or persisted
    /// Invoke custody uses it; fresh absence and physical checks stay below.
    pub(crate) fn management_custody_retention_admission_with_manifest(
        &self,
        manifest: &SharedRecoveryManifest,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        let started = management_admission_cost_started();
        let headroom =
            management_retention_headroom(self.materialization.heads(), manifest, None);
        trace_management_admission_cost(
            "custody_headroom",
            started,
            manifest.management_slots().len(),
            headroom.is_ok(),
        );
        let (pending, future_entries, future_bytes) = headroom?;
        let started = management_admission_cost_started();
        let result = self.management_recovery_admission_with_headroom_and_input(
            &pending,
            &[],
            future_entries,
            future_bytes,
            false,
            Some(manifest),
        )
        .map(|(requirement, _)| requirement);
        trace_management_admission_cost(
            "custody_budget",
            started,
            pending.len(),
            result.is_ok(),
        );
        result
    }

    /// One budget for the exact read and every retained management owner's
    /// unfinished lifecycle. Separate successful checks would double-spend the
    /// same bounded suffix; read custody grants no parent release or extension.

    fn management_recovery_admission_with_headroom(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
        retiring: &[&crate::agent_sdk::RuntimeWork],
        future_entries: usize,
        future_bytes: usize,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_recovery_admission_with_headroom_and_input(
            pending,
            retiring,
            future_entries,
            future_bytes,
            false,
            None,
        )
        .map(|(requirement, _)| requirement)
    }

    fn management_recovery_admission_with_headroom_and_input(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
        retiring: &[&crate::agent_sdk::RuntimeWork],
        future_entries: usize,
        future_bytes: usize,
        select_input: bool,
        verified_manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<(Option<usize>, Option<ReplayInputId>), SharedJournalDriverError> {
        use crate::agent_sdk::{RuntimeOutcome, RuntimeWork};
        if select_input
            && (pending.len() != 1
                || !retiring.is_empty()
                || future_entries != 0
                || future_bytes != 0)
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        if pending
            .len()
            .checked_add(retiring.len())
            .is_none_or(|len| len > super::replay::MAX_REPLAY_SUFFIX_ENTRIES)
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let heads = self.materialization.heads();
        let mut index = heads.ordered_index;
        let mut parent = heads.ordered_head;
        let mut bytes = 0usize;
        let mut entries = 0usize;
        let mut seen = BTreeSet::new();
        let mut selected_input = None;
        // The borrowed driver cannot publish or drain during this calculation.
        // Reuse only this call's freshly verified view for retained selectors;
        // each unseen registered member still proves absence against its own
        // fresh settled physical prefix below. A custody operation may borrow its
        // existing admission-guard view here; no view survives guard release,
        // peer operation or publication.
        let fresh_manifest = if verified_manifest.is_some()
            || (pending.is_empty() && retiring.is_empty())
        {
            None
        } else {
            self.verified_recovery_manifest()?
        };
        let manifest = if pending.is_empty() && retiring.is_empty() {
            None
        } else {
            verified_manifest.or(fresh_manifest.as_ref())
        };
        // This proof never escapes this immutable budget calculation. The
        // first archived lookup authenticates its entire live/baseline view
        // and physical checkpoint closure; every later capsule must match
        // both that baseline and the same complete budget manifest.
        let mut archived = None;
        let mut available = |input| {
            self.available_ordered_claim_in_management_budget(
                input,
                manifest,
                &mut archived,
            )
        };
        for &(anchor, envelope) in pending {
            if anchor.genesis != heads.genesis
                || anchor.admission != heads.admission
                || anchor.runtime != heads.runtime.commitment()
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            let RuntimeWork::Invoke {
                context,
                invocation: work,
                authorization,
                observed_slot,
                ..
            } = envelope
            else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            if !seen.insert(work.invocation) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if self.retained_positive_clean_acknowledgement_with_availability(
                work,
                authorization,
                manifest,
                &mut available,
            )? {
                let input = self
                    .management_invocation_after_with_availability(
                        anchor.ordered,
                        envelope,
                        true,
                        manifest,
                        &mut available,
                    )?
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                let Some(RuntimeOutcome::Completed(Ok(reply))) = self
                    .retained_management_completed_outcome_with_availability(
                        input,
                        manifest,
                        &mut available,
                    )?
                    .or_else(|| self.executor.clean_ordered_result(input))
                else {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                };
                // Registered custody retains the exact first Invoke and its
                // positive ACK even after the guest result has been retired.
                // Its successful reply need not be one of the legacy terminal
                // classes below: no new Ordered row or lifecycle release is
                // authorized by this budget calculation.
                let retained_terminal = manifest
                    .map(|manifest| {
                        exact_retained_management_member(manifest, Some(anchor.ordered), envelope)
                    })
                    .transpose()?
                    .flatten()
                    .is_some_and(|evidence| {
                        evidence
                            .invoke()
                            .is_some_and(|invoke| invoke.input_id() == input)
                            && evidence.acknowledgement().is_some()
                    });
                #[cfg(all(feature = "network", target_os = "linux"))]
                let admin_success =
                    super::clean_bootstrap::admin_dispatch::matches_successful_admin_reply(
                        anchor,
                        envelope,
                        &reply.reply,
                    );
                #[cfg(not(all(feature = "network", target_os = "linux")))]
                let admin_success = false;
                #[cfg(all(feature = "network", target_os = "linux"))]
                let publication = super::clean_bootstrap::genesis_issuance::is_publication_reply(
                    work,
                    &reply.reply,
                );
                #[cfg(not(all(feature = "network", target_os = "linux")))]
                let publication = false;
                if reply.invocation != work.invocation
                    || reply.actor != work.actor
                    || reply.incarnation != work.incarnation
                    || reply.deployment != work.deployment
                    || reply.mode != work.mode
                    || reply.status != crate::agent_sdk::InvocationStatus::Done
                    || (!retained_terminal
                        && !admin_success
                        && !publication
                        && reply.reply
                            != crate::actors::codec::Encode::encode(
                                &crate::actors::value::Value::Bytes(Vec::new()),
                            ))
                {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                if select_input {
                    // The ordinary post-budget anchor lookup did not permit
                    // a legacy ACK to substitute for a live Invoke. Keep that
                    // stricter lookup even though the budget's terminal branch
                    // also validates the exact denial/admin/publication reply.
                    selected_input = self.management_invocation_after_with_availability(
                        anchor.ordered,
                        envelope,
                        false,
                        manifest,
                        &mut available,
                    )?;
                    if selected_input != Some(input) {
                        return Err(SharedJournalDriverError::CrossStoreMismatch);
                    }
                }
                // Retained Invoke/ACK pairs and the legacy terminal classes
                // need no further rows. Parent finalization/release retains
                // its separate capacity and durable lifecycle requirements.
                continue;
            }
            let retained = self.management_invocation_after_with_availability(
                anchor.ordered,
                envelope,
                false,
                manifest,
                &mut available,
            )?;
            let capsule = self.retained_management_invocation_with_availability(
                envelope,
                manifest,
                &mut available,
            )?;
            let invoke = ReplayOperation::CleanInvoke {
                context: *context,
                work: (**work).clone(),
                authorization: (**authorization).clone(),
                observed_slot: *observed_slot,
            };
            // An anchor newer than a retained invocation cannot be used to
            // budget it as unseen. Later lifecycle steps already fail the
            // anchored walk; completed retirement uses its separate protocol.
            if !management_pending_input_matches_anchor(
                recent_clean_ordered_operation(&self.store, &self.materialization, &invoke)?,
                retained,
                capsule.as_ref().map(SharedRecoveryObservation::input_id),
            ) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if retained.is_none()
                && self.retained_positive_clean_acknowledgement_with_availability(
                    work,
                    authorization,
                    manifest,
                    &mut available,
                )?
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if let Some(input) = retained {
                if !matches!(
                    capsule
                        .as_ref()
                        .filter(|observation| observation.input_id() == input)
                        .map(|observation| observation.outcome().clone())
                        .or_else(|| self.executor.clean_ordered_result(input)),
                    Some(RuntimeOutcome::Completed(Ok(_)))
                ) {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
            }
            if select_input {
                // Preserve the budget's fresh per-member absence proof rather
                // than repeating it before preparation under the same locks.
                selected_input = retained;
            }
            let acknowledgement = ReplayOperation::CleanAcknowledge {
                context: *context,
                expected_live: None,
                work: crate::agent_sdk::InvocationRetirement::from_work(work),
                authorization: (**authorization).clone(),
            };
            for operation in retained
                .is_none()
                .then_some(invoke)
                .into_iter()
                .chain(core::iter::once(acknowledgement))
            {
                index = index
                    .checked_add(1)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                let entry = OrderedEntry {
                    genesis: heads.genesis,
                    index,
                    parent,
                    merge_frontier: heads.merge_frontier,
                    merge_seal: None,
                    input: ReplayInput {
                        runtime: heads.runtime.clone(),
                        operation,
                    },
                };
                entry
                    .validate()
                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
                bytes = bytes
                    .checked_add(entry.encode().len())
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                entries += 1;
                parent = Some(entry.id());
            }
        }
        for &envelope in retiring {
            let RuntimeWork::Invoke { invocation, .. } = envelope else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            if !seen.insert(invocation.invocation) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        let (retirement_entries, retirement_bytes) = self.management_retirement_delta(
            retiring,
            index,
            parent,
            manifest,
            &mut available,
        )?;
        let entries = entries
            .checked_add(retirement_entries)
            .and_then(|entries| entries.checked_add(future_entries))
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let bytes = bytes
            .checked_add(retirement_bytes)
            .and_then(|bytes| bytes.checked_add(future_bytes))
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        Ok((
            self.materialization
                .has_suffix_headroom(entries, bytes)
                .then_some(entries),
            selected_input,
        ))
    }

    /// Validate and encode the exact projection lifecycle delta independently
    /// of current suffix capacity. Checkpoint selection needs this count while
    /// the old authenticated suffix is deliberately full; ordinary admission
    /// still calls [`Self::projection_admission_requirement`] and therefore
    /// cannot bypass either replay budget.

    fn retained_terminal_projection_input(
        &self,
        operation: &ReplayOperation,
    ) -> Result<Option<(ReplayInputId, crate::agent_sdk::RuntimeOutcome)>, SharedJournalDriverError>
    {
        let manifest = self.verified_recovery_manifest()?;
        self.retained_terminal_projection_input_with_manifest(operation, manifest.as_ref())
    }

    fn retained_terminal_projection_input_with_manifest(
        &self,
        operation: &ReplayOperation,
        manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<Option<(ReplayInputId, crate::agent_sdk::RuntimeOutcome)>, SharedJournalDriverError>
    {
        // The caller freshly verified this view for this immutable lookup.
        // Every legacy, availability and certified-boundary check stays below.
        if let Some(manifest) = manifest
            && let Some(observation) = retained_management_operation(manifest, operation)?
        {
            self.available_ordered_claim(observation.input_id())?;
            return Ok(Some((
                observation.input_id(),
                observation.outcome().clone(),
            )));
        }
        let retained =
            recent_clean_ordered_operation(&self.store, &self.materialization, operation)?;
        if let Some(input) = retained {
            let outcome = self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if !matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(_)) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            return Ok(Some((input, outcome)));
        }
        self.retained_terminal_projection_boundary(operation)
    }

    /// A certified checkpoint may make the exact pending Invoke its replay
    /// boundary. The boundary entry remains content-addressed, while Standard
    /// guest state retains the immutable clean result. Re-execute that exact
    /// read-only work without publication to recover the original outcome;
    /// no replacement Invoke record is appended.
    fn retained_terminal_projection_boundary(
        &self,
        operation: &ReplayOperation,
    ) -> Result<Option<(ReplayInputId, crate::agent_sdk::RuntimeOutcome)>, SharedJournalDriverError>
    {
        let boundary = self.materialization.replay_boundary();
        let Some(id) = boundary.head else {
            return Ok(None);
        };
        let entry = self
            .store
            .get::<OrderedEntry>(id)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if entry.id() != id
            || entry.index != boundary.index
            || entry.genesis != self.materialization.heads().genesis
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let (
            ReplayOperation::CleanInvoke {
                context: prior_context,
                work: prior_work,
                authorization: prior_authorization,
                ..
            },
            ReplayOperation::CleanInvoke {
                context,
                work,
                authorization,
                ..
            },
        ) = (&entry.input.operation, operation)
        else {
            return Ok(None);
        };
        if prior_context != context || prior_work != work || prior_authorization != authorization {
            return Ok(None);
        }
        // This fallback is exclusively the read-only projection protocol.
        // Persisted management dispatch also reaches this preparation path;
        // an exact Linear boundary is not authenticated retained-result
        // evidence and must not fall through to speculative execution.
        if work.mode != crate::agent_sdk::MethodMode::Query {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        if self.materialization.common_checkpoint().is_some()
            && self
                .retained_public_invocation(work.invocation, work.mode)?
                .is_none_or(|(_, input)| input != entry.input.id())
        {
            return Ok(None);
        }
        let outcome = self
            .executor
            .clean_invocation_terminal_outcome(
                &entry.input.operation,
                self.materialization.state(),
                self.materialization.runtime(),
            )?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        Ok(Some((entry.input.id(), outcome)))
    }

    /// One guard's retained ACK/Invoke decision, freshly verified per call.
    /// Standalone selectors remain fresh; no view survives a guest preview.
    pub(crate) fn retained_positive_or_terminal_projection(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedJournalDriverError> {
        let manifest = self.verified_recovery_manifest()?;
        if self.retained_positive_clean_acknowledgement_with_manifest(
            work,
            authorization,
            manifest.as_ref(),
        )? {
            return Ok(true);
        }
        let operation = ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: work.clone(),
            authorization: authorization.clone(),
            observed_slot: 0,
        };
        Ok(self
            .retained_terminal_projection_input_with_manifest(&operation, manifest.as_ref())?
            .is_some())
    }

    pub(crate) fn retained_terminal_projection_invoke(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedJournalDriverError> {
        let operation = ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: work.clone(),
            authorization: authorization.clone(),
            observed_slot: 0,
        };
        Ok(self
            .retained_terminal_projection_input(&operation)?
            .is_some())
    }

    /// Prove that a fresh exact projection Invoke/Ack pair fits both
    /// authenticated composite replay budgets.

    /// Read-only proof that the exact pending projection lifecycle already
    /// reached a positive durable acknowledgement. This is used after a
    /// crash between committing Ack and clearing the bootstrap record; it
    /// never appends a replacement Invoke merely to rediscover the result.
    pub(crate) fn retained_positive_clean_acknowledgement(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedJournalDriverError> {
        let manifest = self.verified_recovery_manifest()?;
        self.retained_positive_clean_acknowledgement_with_manifest(
            work,
            authorization,
            manifest.as_ref(),
        )
    }

    fn retained_positive_clean_acknowledgement_with_manifest(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<bool, SharedJournalDriverError> {
        self.retained_positive_clean_acknowledgement_with_availability(
            work,
            authorization,
            manifest,
            &mut |input| self.available_ordered_claim(input),
        )
    }

    fn retained_positive_clean_acknowledgement_with_availability(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        manifest: Option<&SharedRecoveryManifest>,
        available: &mut impl FnMut(
            ReplayInputId,
        ) -> Result<OrderedCommitClaim, SharedJournalDriverError>,
    ) -> Result<bool, SharedJournalDriverError> {
        if let Some(observation) = manifest.and_then(|manifest| {
            manifest.management_slots().iter().find_map(|slot| {
                slot.members()
                    .iter()
                    .zip(slot.members_evidence())
                    .find_map(|(member, evidence)| {
                        (member.work() == work && member.authorization() == authorization)
                            .then(|| evidence.acknowledgement())
                            .flatten()
                    })
            })
        }) {
            available(observation.input_id())?;
            return Ok(true);
        }
        let operation = ReplayOperation::CleanAcknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            expected_live: None,
            work: crate::agent_sdk::InvocationRetirement::from_work(work),
            authorization: authorization.clone(),
        };
        let Some(input) =
            recent_clean_ordered_operation(&self.store, &self.materialization, &operation)?
        else {
            return Ok(false);
        };
        let outcome = self.executor.clean_ordered_result(input);
        match &outcome {
            Some(crate::agent_sdk::RuntimeOutcome::Acknowledged(Ok(acknowledged)))
                if acknowledged.invocation == work.invocation
                    && acknowledged.actor == work.actor
                    && acknowledged.incarnation == work.incarnation
                    && acknowledged.deployment == work.deployment
                    && acknowledged.mode == work.mode
                    && acknowledged.work == work.commitment()
                    && acknowledged.authorization == authorization.commitment() =>
            {
                Ok(true)
            }
            _ => {
                let acknowledged = match &outcome {
                    Some(crate::agent_sdk::RuntimeOutcome::Acknowledged(Ok(value))) => Some(value),
                    _ => None,
                };
                tracing::warn!(
                    phase = "ack_fallback",
                    ordered_index = self.materialization.heads().ordered_index,
                    outcome_kind = clean_outcome_kind(outcome.as_ref()),
                    acknowledgement_error = ?match &outcome {
                        Some(crate::agent_sdk::RuntimeOutcome::Acknowledged(Err(error))) => {
                            Some(*error)
                        }
                        _ => None,
                    },
                    invocation_matches =
                        acknowledged.is_some_and(|value| value.invocation == work.invocation),
                    actor_matches = acknowledged.is_some_and(|value| value.actor == work.actor),
                    incarnation_matches =
                        acknowledged.is_some_and(|value| value.incarnation == work.incarnation),
                    deployment_matches =
                        acknowledged.is_some_and(|value| value.deployment == work.deployment),
                    mode_matches = acknowledged.is_some_and(|value| value.mode == work.mode),
                    work_matches =
                        acknowledged.is_some_and(|value| value.work == work.commitment()),
                    authorization_matches = acknowledged
                        .is_some_and(|value| value.authorization == authorization.commitment()),
                    "Shared recovery exact ACK outcome mismatch"
                );
                Err(SharedJournalDriverError::CrossStoreMismatch)
            }
        }
    }

    pub(crate) fn journal_position(
        &self,
    ) -> (
        super::journal::AgentJournalGenesisId,
        super::genesis::AgentGenesisAdmissionId,
        u64,
        Option<super::journal::OrderedEntryId>,
        super::journal::MergeFrontierId,
        super::journal::RuntimeBinding,
    ) {
        let heads = self.materialization.heads();
        (
            heads.genesis,
            heads.admission,
            heads.ordered_index,
            heads.ordered_head,
            heads.merge_frontier,
            heads.runtime.clone(),
        )
    }

    /// Read-only evidence for an exact management invocation after a retained
    /// pre-dispatch anchor. Absence is interval-scoped and is not authorization
    /// to dispatch; callers must independently verify and persist that anchor.
    /// This observes applied journal history, not an unapplied Raft tail. The
    /// coordinator must hold admission exclusion and drain a leader barrier
    /// before interpreting it as recovery evidence.
    pub(crate) fn management_invocation_after(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        self.management_invocation_after_with_denial_ack(anchor, envelope, false)
    }

    pub(crate) fn management_denial_invocation_after(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        self.management_invocation_after_with_denial_ack(anchor, envelope, true)
    }

    fn management_invocation_after_with_denial_ack(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
        denial: bool,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        let manifest = self.verified_recovery_manifest()?;
        self.management_invocation_after_with_manifest(anchor, envelope, denial, manifest.as_ref())
    }

    fn management_invocation_after_with_manifest(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
        denial: bool,
        manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        self.management_invocation_after_with_availability(
            anchor,
            envelope,
            denial,
            manifest,
            &mut |input| self.available_ordered_claim(input),
        )
    }

    fn management_invocation_after_with_availability(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
        denial: bool,
        manifest: Option<&SharedRecoveryManifest>,
        available: &mut impl FnMut(
            ReplayInputId,
        ) -> Result<OrderedCommitClaim, SharedJournalDriverError>,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        use crate::agent_sdk::{
            InvocationAuthorization, MethodMode, RuntimeExecutionContext, RuntimeState, RuntimeWork,
        };
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = envelope
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        let binding = self.materialization.runtime();
        if *context != RuntimeExecutionContext::Direct
            || *state != RuntimeState::default()
            || !matches!(invocation.mode, MethodMode::Linear | MethodMode::Query)
            || !invocation.validate()
            || invocation.space.0 != binding.space.0
            || invocation.agent.0 != binding.agent.0
            || invocation.runtime_deployment.0 != binding.deployment.0
            || **authorization
                != InvocationAuthorization::PublicPreflight(
                    crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
                )
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        if let Some(manifest) = manifest
            && let Some(evidence) =
                exact_retained_management_member(manifest, Some(anchor), envelope)?
        {
            if let Some(observation) = evidence.invoke() {
                // An exact registered capsule retains the first Invoke even
                // through its ACK. This is evidence for the existing lifecycle,
                // not permission to dispatch the original mutation again.
                available(observation.input_id())?;
                return Ok(Some(observation.input_id()));
            }
            // A mutable hot row cannot prove a mutation never ran. Authenticate
            // the complete stable applied/committed prefix under the existing
            // management barrier and compare it with this materialization.
            // An unsettled tail refuses absence without calling it corruption.
            let started = management_admission_cost_started();
            let result = self.ledger.management_absence_context().map_err(|error| {
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    tracing::debug!(
                        node = ?self.materialization.heads().node,
                        agent = ?invocation.agent,
                        invocation = ?invocation.invocation,
                        phase = "management_absence_context",
                        ?error,
                        "Retained management absence proof refused"
                    );
                }
                error
            });
            trace_management_admission_cost("absence_ledger", started, 1, result.is_ok());
            let (ordered, fresh) = result?;
            if ordered != self.materialization.ordered_base() {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            let started = management_admission_cost_started();
            let fresh = self
                .verified_recovery_manifest_from_read(fresh)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            trace_management_admission_cost("absence_evidence", started, 1, true);
            let evidence = exact_retained_management_member(&fresh, Some(anchor), envelope)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if let Some(observation) = evidence.invoke() {
                // A separate absence proof may have observed newer custody.
                // It deliberately does not borrow the budget's older view.
                self.available_ordered_claim(observation.input_id())?;
                return Ok(Some(observation.input_id()));
            }
            return Ok(None);
        }
        let operation = ReplayOperation::CleanInvoke {
            context: *context,
            work: (**invocation).clone(),
            authorization: (**authorization).clone(),
            observed_slot: *observed_slot,
        };
        if denial {
            return super::local_journal_driver::clean_denial_operation_after(
                &self.store,
                &self.materialization,
                anchor,
                &operation,
            )
            .map_err(Into::into);
        }
        super::local_journal_driver::clean_ordered_operation_after(
            &self.store,
            &self.materialization,
            anchor,
            &ReplayOperation::CleanInvoke {
                context: *context,
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
                observed_slot: *observed_slot,
            },
        )
        .map_err(Into::into)
    }

    fn retained_management_invocation_with_availability(
        &self,
        envelope: &crate::agent_sdk::RuntimeWork,
        manifest: Option<&SharedRecoveryManifest>,
        available: &mut impl FnMut(
            ReplayInputId,
        ) -> Result<OrderedCommitClaim, SharedJournalDriverError>,
    ) -> Result<Option<SharedRecoveryObservation>, SharedJournalDriverError> {
        let Some(manifest) = manifest else {
            return Ok(None);
        };
        let observation = exact_retained_management_member(manifest, None, envelope)?
            .and_then(|evidence| evidence.invoke())
            .cloned();
        if let Some(observation) = &observation {
            available(observation.input_id())?;
        }
        Ok(observation)
    }

    fn retained_management_completed_outcome_with_availability(
        &self,
        input: ReplayInputId,
        manifest: Option<&SharedRecoveryManifest>,
        available: &mut impl FnMut(
            ReplayInputId,
        ) -> Result<OrderedCommitClaim, SharedJournalDriverError>,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedJournalDriverError> {
        let Some(manifest) = manifest else {
            return Ok(None);
        };
        let observation = manifest
            .management_slots()
            .iter()
            .flat_map(|slot| slot.observations())
            .find(|observation| {
                observation.input_id() == input && !observation.is_acknowledgement()
            });
        if let Some(observation) = observation {
            available(input)?;
            return Ok(Some(observation.outcome().clone()));
        }
        Ok(None)
    }

    pub(crate) fn ledger(&self) -> &AgentRaftApplicationLedgerV2 {
        &self.ledger
    }

    fn clean_management_catalog(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<Vec<RuntimeBlob>, SharedJournalDriverError> {
        if matches!(artifacts, SdkManagementArtifacts::None)
            && matches!(
                request,
                crate::agent_sdk::ManagementRequest::Install(_)
                    | crate::agent_sdk::ManagementRequest::UpgradeActor(_)
                    | crate::agent_sdk::ManagementRequest::UpgradeRuntime(_)
            )
        {
            self.executor
                .validate_clean_management_artifacts(descriptor, request)?;
            return Ok(Vec::new());
        }
        super::driver::validate_sdk_management_artifacts(descriptor, request, artifacts)
            .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
        let runtime_blob = |bytes: Vec<u8>| RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        };
        let mut catalog = Vec::new();
        match (request, artifacts) {
            (
                crate::agent_sdk::ManagementRequest::Install(install),
                SdkManagementArtifacts::Actor(package),
            ) => {
                catalog.push(runtime_blob(package.exact_bytes().to_vec()));
                catalog.push(runtime_blob(package.state_lane_schema_bytes().to_vec()));
                catalog.push(runtime_blob(package.method_policy_bytes().to_vec()));
                if let Some(data) = &install.installation_data {
                    catalog.push(runtime_blob(data.bytes.clone()));
                }
            }
            (
                crate::agent_sdk::ManagementRequest::UpgradeActor(_),
                SdkManagementArtifacts::Actor(package),
            ) => {
                catalog.push(runtime_blob(package.exact_bytes().to_vec()));
                catalog.push(runtime_blob(package.state_lane_schema_bytes().to_vec()));
                catalog.push(runtime_blob(package.method_policy_bytes().to_vec()));
            }
            (
                crate::agent_sdk::ManagementRequest::UpgradeRuntime(_),
                SdkManagementArtifacts::Runtime(package),
            ) => catalog.push(runtime_blob(package.exact_bytes().to_vec())),
            (_, SdkManagementArtifacts::None) => {}
            _ => return Err(SharedJournalDriverError::InvalidArtifactBatch),
        }
        catalog.sort_by_key(|blob| blob.reference.hash);
        for pair in catalog.windows(2) {
            if pair[0].reference.hash == pair[1].reference.hash && pair[0] != pair[1] {
                return Err(SharedJournalDriverError::InvalidArtifactBatch);
            }
        }
        catalog.dedup();
        Ok(catalog)
    }

    fn stage_current_merge_seal(
        &mut self,
    ) -> Result<super::journal::MergeSealId, SharedJournalDriverError> {
        self.stage_current_merge_seal_matching(None)
    }

    fn current_merge_seal(
        &self,
    ) -> (
        super::journal::MergeSeal,
        super::journal::LaneStateManifest,
        Vec<u8>,
    ) {
        let heads = self.materialization.heads().clone();
        let merge_state = self.materialization.state().merge.clone();
        let state = BlobRef::of_bytes(&merge_state);
        let manifest = super::journal::LaneStateManifest {
            #[cfg(feature = "experimental-state-blocks")]
            external_root: None,
            genesis: heads.genesis,
            runtime: heads.runtime.clone(),
            lane: PersistedLane::Merge,
            cursor: super::journal::LaneCursor::Merge {
                frontier: heads.merge_frontier,
            },
            state: state.clone(),
        };
        let seal = super::journal::MergeSeal {
            genesis: heads.genesis,
            frontier: heads.merge_frontier,
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            merge_state: manifest.id(),
        };
        (seal, manifest, merge_state)
    }

    fn stage_current_merge_seal_matching(
        &mut self,
        expected: Option<super::journal::MergeSealId>,
    ) -> Result<super::journal::MergeSealId, SharedJournalDriverError> {
        let (seal, manifest, merge_state) = self.current_merge_seal();
        // A follower can derive this dependency from authenticated local state
        // only when it exactly matches the committed content address. Never
        // substitute a newer local Merge frontier or publish mismatched bytes.
        if expected.is_some_and(|expected| expected != seal.id()) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.store
            .put_blob(JournalBlobClass::LaneState, &manifest.state, &merge_state)?;
        self.store.put(&manifest)?;
        self.store.put(&seal)?;
        Ok(seal.id())
    }

    /// Prepare the exact command sequence for one clean SDK management
    /// mutation. Artifact bytes are content-admitted first, but become journal
    /// catalog truth only when their chunk commands commit and apply. Only an
    /// exact request/receipt found in the bounded durable Ordered suffix may
    /// return its replay-derived result without another Raft slot.
    pub(crate) fn prepare_clean_management(
        &mut self,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<PreparedCleanManagement, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &self.external {
            external
                .availability
                .require_current(&self.store, &self.materialization)?;
            if !matches!(request, crate::agent_sdk::ManagementRequest::Install(_)) {
                return Err(SharedJournalDriverError::InvalidProfile);
            }
        }
        if matches!(
            request,
            crate::agent_sdk::ManagementRequest::Create(_)
                | crate::agent_sdk::ManagementRequest::InspectActors { .. }
                | crate::agent_sdk::ManagementRequest::InspectResources
                | crate::agent_sdk::ManagementRequest::InspectManagementHistory
                | crate::agent_sdk::ManagementRequest::ChangeReplicas { .. }
                | crate::agent_sdk::ManagementRequest::PrivateControl { .. }
        ) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let runtime = self.materialization.runtime().clone();
        let descriptor = self.executor.trusted_current_clean_descriptor(&runtime)?;
        let catalog = self.clean_management_catalog(&descriptor, &request, artifacts)?;
        if let Some((input, observed_slot)) = recent_clean_management_operation(
            &self.store,
            &self.materialization,
            &request,
            &authority,
        )? {
            let outcome = self
                .executor
                .clean_management_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            return Ok(PreparedCleanManagement::Retained {
                input,
                outcome,
                observed_slot,
            });
        }
        let observed_slot = self.executor.current_logical_slot()?;
        let input = ReplayInput {
            runtime: runtime.clone(),
            operation: ReplayOperation::CleanManage {
                request: request.clone(),
                authority: authority.clone(),
                observed_slot,
            },
        };
        input
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let heads = self.materialization.heads();
        let candidate = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(self.current_merge_seal().0.id()),
            input: input.clone(),
        };
        #[cfg(feature = "experimental-state-blocks")]
        let preview = if self.external.is_some() {
            let expiry = super::driver::verify_clean_management_journal_receipt(
                &descriptor,
                &request,
                &authority,
                observed_slot,
                true,
            )
            .map_err(|_| {
                SharedJournalDriverError::Executor(LocalReplayExecutorError::InvalidAuthority)
            })?;
            let returned = self.execute_external_work_at(
                crate::agent_sdk::RuntimeWork::Manage {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    space: descriptor.identity.space,
                    agent: descriptor.identity.agent,
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    state: super::replay::sdk_runtime_state(self.materialization.state()),
                    request: Box::new(request.clone()),
                    authority: Some(Box::new(authority.clone())),
                    observed_slot,
                },
                Some(&candidate),
            )?;
            if expiry
                && (returned.outcome
                    != crate::agent_sdk::RuntimeOutcome::Management(Err(
                        crate::agent_sdk::ManagementError::ExpiredBeforeApplication,
                    ))
                    || returned.state
                        == super::replay::sdk_runtime_state(self.materialization.state()))
            {
                return Err(SharedJournalDriverError::Executor(
                    LocalReplayExecutorError::InvalidState,
                ));
            }
            returned
        } else {
            self.executor.preview_clean_management(
                &runtime,
                self.materialization.state(),
                &request,
                &authority,
                observed_slot,
                false,
            )?
        };
        #[cfg(not(feature = "experimental-state-blocks"))]
        let preview = self.executor.preview_clean_management(
            &runtime,
            self.materialization.state(),
            &request,
            &authority,
            observed_slot,
            false,
        )?;
        let preview_state = RuntimeState {
            control: preview.state.control,
            linear: preview.state.linear,
            merge: preview.state.merge,
            local: preview.state.local,
        };
        if preview_state == *self.materialization.state()
            && matches!(
                &preview.outcome,
                crate::agent_sdk::RuntimeOutcome::Management(Err(_))
            )
        {
            return Ok(PreparedCleanManagement::Denied {
                outcome: preview.outcome,
                observed_slot,
            });
        }
        let input_id = input.id();
        let route = self.active_route()?;
        let mut commands = Vec::new();
        let artifact_batch = if catalog.is_empty() {
            None
        } else {
            let manifest = ArtifactBatchManifest::new(
                route,
                catalog.iter().map(|blob| blob.reference.clone()).collect(),
            )
            .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
            let batch = manifest.id();
            for (artifact_index, blob) in catalog.iter().enumerate() {
                for (chunk_index, bytes) in blob.bytes.chunks(ARTIFACT_CHUNK_DATA_BYTES).enumerate()
                {
                    let offset = chunk_index
                        .checked_mul(ARTIFACT_CHUNK_DATA_BYTES)
                        .and_then(|offset| u64::try_from(offset).ok())
                        .ok_or(SharedJournalDriverError::InvalidArtifactBatch)?;
                    let chunk = ArtifactChunk::new(
                        manifest.clone(),
                        u32::try_from(artifact_index)
                            .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?,
                        offset,
                        bytes.to_vec(),
                    )
                    .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
                    if !self.artifacts.contains(&chunk)? {
                        commands.push(AgentRaftCommand::ArtifactChunk(chunk).encode());
                    }
                }
            }
            Some(batch)
        };
        self.stage_current_merge_seal_matching(candidate.merge_seal)?;
        let entry = candidate;
        let ordered = AgentRaftCommand::Ordered {
            route,
            artifact_batch,
            entry,
        };
        ordered
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        commands.push(ordered.encode());
        Ok(PreparedCleanManagement::Proposal {
            input: input_id,
            observed_slot,
            commands,
        })
    }

    pub(crate) fn inspect_clean_management(
        &self,
        request: &crate::agent_sdk::ManagementRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            if !matches!(
                request,
                crate::agent_sdk::ManagementRequest::InspectActors { .. }
                    | crate::agent_sdk::ManagementRequest::InspectResources
                    | crate::agent_sdk::ManagementRequest::InspectManagementHistory
            ) {
                return Err(SharedJournalDriverError::InvalidProfile);
            }
            let descriptor = self.clean_descriptor()?;
            return self
                .execute_external_work(crate::agent_sdk::RuntimeWork::Manage {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    space: descriptor.identity.space,
                    agent: descriptor.identity.agent,
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    state: super::replay::sdk_runtime_state(self.materialization.state()),
                    request: Box::new(request.clone()),
                    authority: None,
                    observed_slot: self.executor.current_logical_slot()?,
                })
                .map(|transition| transition.outcome);
        }
        self.executor
            .inspect_clean_management(
                self.materialization.runtime(),
                self.materialization.state(),
                request,
            )
            .map_err(Into::into)
    }

    /// A fresh observation uses this independently authenticated image, not a
    /// peer-provided Authority page. No candidate, custody or publication is
    /// created. The network lifecycle owner establishes ReadIndex/apply first.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn observe_system_authority(
        &self,
        work: &crate::agent_sdk::InvocationWork,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        if self.external.is_some() {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        self.executor
            .observe_system_authority(
                self.materialization.runtime(),
                self.materialization.state(),
                work,
            )
            .map_err(Into::into)
    }

    /// Inspect only retained acceptance at this current head. The guest owns
    /// the original authorization/time checks; the host supplies its trusted
    /// inspection clock, never a caller-selected acceptance slot. No Invoke,
    /// fake historical input, state publication, or original actor gas runs.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn inspect_external_retained_reply(
        &self,
        request: &CleanInvocationReplayRequest,
    ) -> Result<Option<RetainedExternalReplyProof>, SharedJournalDriverError> {
        if self.external.is_none() {
            return Ok(None);
        }
        let Some(acknowledge) = retained_external_request_kind(request) else {
            return Ok(None);
        };
        let retirement = crate::agent_sdk::InvocationRetirement::from_work(request.work());
        if !retirement.validate()
            || retirement.gas > super::execution::MAX_EXECUTION_GAS
            || !request.authorization().matches_retirement(&retirement)
        {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let claim = self.current_external_ordered_claim()?;
        let heads = self.materialization.heads_id();
        let authorization = request.authorization().commitment();
        let inspection_slot = self.executor.current_logical_slot()?;
        let transition =
            self.execute_external_work(crate::agent_sdk::RuntimeWork::InspectInvocation {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: super::replay::sdk_runtime_state(self.materialization.state()),
                invocation: Box::new(retirement.clone()),
                authorization: Box::new(request.authorization().clone()),
                observed_slot: inspection_slot,
            })?;
        let Some(outcome) = retained_external_reply_outcome(
            &retirement,
            authorization,
            acknowledge,
            transition.outcome,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(RetainedExternalReplyProof {
            store: self.store.instance_id(),
            epoch: self.store.validation_epoch(),
            heads,
            inspection_slot,
            acknowledge,
            retirement: retirement.commitment(),
            authorization,
            claim,
            outcome,
        }))
    }

    /// Revalidate the opaque local proof after quorum I/O. An evolved head,
    /// reopened owner, changed lifecycle stage, or substituted authorization
    /// is a refusal, never permission to deliver a stale result or rerun it.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn revalidate_external_retained_reply(
        &self,
        request: &CleanInvocationReplayRequest,
        proof: &RetainedExternalReplyProof,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let retirement = crate::agent_sdk::InvocationRetirement::from_work(request.work());
        if retained_external_request_kind(request) != Some(proof.acknowledge)
            || !retirement.validate()
            || retirement.gas > super::execution::MAX_EXECUTION_GAS
            || !request.authorization().matches_retirement(&retirement)
            || proof.retirement != retirement.commitment()
            || proof.authorization != request.authorization().commitment()
        {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        if proof.store != self.store.instance_id()
            || proof.epoch != self.store.validation_epoch()
            || proof.heads != self.materialization.heads_id()
            || self.current_external_ordered_claim()? != proof.claim
            || self.executor.current_logical_slot()? < proof.inspection_slot
        {
            // A legitimate head/owner advance or clock regression during peer
            // I/O requires fresh inspection, not a corruption disposition.
            return Err(JournalStoreError::Unavailable.into());
        }
        retained_external_reply_outcome(
            &retirement,
            proof.authorization,
            proof.acknowledge,
            proof.outcome.clone(),
        )?
        .ok_or(SharedJournalDriverError::CrossStoreMismatch)
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn execute_external_work(
        &self,
        work: crate::agent_sdk::RuntimeWork,
    ) -> Result<crate::agent_sdk::RuntimeTransition, SharedJournalDriverError> {
        self.execute_external_work_at(work, None)
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn execute_external_work_at(
        &self,
        work: crate::agent_sdk::RuntimeWork,
        candidate: Option<&OrderedEntry>,
    ) -> Result<crate::agent_sdk::RuntimeTransition, SharedJournalDriverError> {
        let owner = self
            .external
            .as_ref()
            .ok_or(SharedJournalDriverError::InvalidProfile)?;
        owner
            .availability
            .require_current(&self.store, &self.materialization)?;
        let runtime = self
            .executor
            .external_runtime()
            .ok_or(SharedJournalDriverError::InvalidProfile)?;
        let invocation_gas = match &work {
            crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } => {
                if invocation.gas > super::execution::MAX_EXECUTION_GAS {
                    return Err(SharedJournalDriverError::Executor(
                        LocalReplayExecutorError::InvalidRequest,
                    ));
                }
                invocation.gas
            }
            crate::agent_sdk::RuntimeWork::Resume { .. } => {
                return Err(SharedJournalDriverError::Executor(
                    LocalReplayExecutorError::InvalidRequest,
                ));
            }
            _ => 0,
        };
        let gas = super::driver::DEFAULT_MANAGEMENT_GAS
            .checked_add(invocation_gas)
            .ok_or(SharedJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest,
            ))?;
        let mut lanes = self.materialization.external_inspection_lanes()?;
        if let Some(entry) = candidate
            && entry.input.persisted_lane() == PersistedLane::Linear
        {
            // The preview sees the exact proposed root revision, not an
            // inspection-only cursor. Replay independently revalidates this
            // same predecessor-bound entry after physical Raft commitment.
            let lane = lanes
                .iter_mut()
                .find(|lane| {
                    lane.base.context().scope().lane() == crate::agent_sdk::StateLane::Linear
                })
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            lane.next = super::state_block_store::journal_root_context(
                owner.genesis.genesis(),
                self.materialization.runtime(),
                PersistedLane::Linear,
                None,
                &super::journal::LaneCursor::Ordered {
                    base: OrderedBase {
                        index: entry.index,
                        head: Some(entry.id()),
                    },
                },
            )
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        }
        let work = crate::agent_sdk::state_execution::StateExecutionWork::new(
            work,
            lanes,
            runtime.external_state_limits(),
        )
        .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let map_error = |error| {
            use super::state_block_pvm::BlockPvmError;
            use crate::agent_sdk::{state_blocks::BlockError, state_tree::TreeError};
            if matches!(
                error,
                BlockPvmError::Block(
                    TreeError::Storage
                        | TreeError::Block(BlockError::Unavailable | BlockError::HashMismatch)
                )
            ) {
                owner.availability.invalidate();
            }
            // A deterministic unsupported/trapping candidate is not a durable
            // terminal result, but also does not revoke an otherwise healthy
            // historical closure pin merely because admission refused it.
            SharedJournalDriverError::Executor(match error {
                BlockPvmError::Backend => LocalReplayExecutorError::RuntimeBackend,
                BlockPvmError::Exit { reason, pc } => {
                    LocalReplayExecutorError::RuntimeExit { reason, pc }
                }
                BlockPvmError::InvalidRequest | BlockPvmError::ProgramMismatch => {
                    LocalReplayExecutorError::InvalidRequest
                }
                _ => LocalReplayExecutorError::RuntimeOutput,
            })
        };
        let mut budget = Self::external_operation_budget();
        let output = super::state_block_pvm::MultiLaneStateBlockHost {
            store: &self.store,
            budget: &mut budget,
        }
        .execute_admitted_work(runtime, &work, gas)
        .map_err(&map_error)?;
        // Publication performs reuse verification after guest execution under
        // this same live read budget. Admission must prove that complete cost
        // fits before allocating a Raft slot; this pass writes no block or head.
        for change in output.changes() {
            let lane = work
                .lanes()
                .iter()
                .find(|lane| lane.base.context().scope() == change.next().context().scope())
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            change
                .verify_reuse(
                    lane.base,
                    lane.next,
                    &mut super::state_block_store::JournalBlockReader {
                        store: &self.store,
                        scope: lane.base.context().scope(),
                    },
                    &mut budget,
                )
                .map_err(|error| map_error(super::state_block_pvm::BlockPvmError::Block(error)))?;
        }
        if let Some(entry) = candidate {
            let captured = super::replay::ReplayExternalExecution::from_physical_response(
                &entry.input,
                self.materialization.state(),
                super::replay::ReplayPosition::Ordered {
                    id: entry.id(),
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: entry.merge_seal,
                },
                &work,
                output,
            )
            .map_err(|_| {
                SharedJournalDriverError::Executor(LocalReplayExecutorError::RuntimeOutput)
            })?;
            return Ok(captured.output().transition().clone());
        }
        Ok(output.transition().clone())
    }

    pub(crate) fn clean_state_commitment(
        &self,
    ) -> Result<crate::agent_sdk::Hash, SharedJournalDriverError> {
        super::journal::system_genesis_post_create_state_commitment(self.materialization.state())
            .map(|commitment| crate::agent_sdk::Hash(commitment.0))
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)
    }

    fn clean_operation_input(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<ReplayInput, SharedJournalDriverError> {
        let observed_slot = self.executor.current_logical_slot()?;
        self.clean_operation_input_at(request, observed_slot)
    }

    fn clean_operation_input_at(
        &self,
        request: CleanInvocationReplayRequest,
        observed_slot: u64,
    ) -> Result<ReplayInput, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &self.external {
            external
                .availability
                .require_current(&self.store, &self.materialization)?;
        }
        let heads = self.materialization.heads();
        let input = ReplayInput {
            runtime: heads.runtime.clone(),
            operation: request.into_operation(observed_slot),
        };
        input
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        self.executor.verify_clean_operation_input(
            &input.operation,
            self.materialization.state(),
            &input.runtime,
        )?;
        Ok(input)
    }

    /// Construct the exact clean ordered command which a live Raft worker
    /// may propose. Authority and complete SDK work are verified before the
    /// proposal bytes exist; replay repeats verification before publication.
    pub(crate) fn prepare_clean_ordered(
        &self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_clean_ordered_operation(CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
        })
    }

    pub(crate) fn prepare_clean_ordered_operation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_clean_ordered_operation_with_policy(request, false, None, false, None)
    }

    /// Reuse only the manifest freshly verified for this custody ACK under
    /// uninterrupted admission guards. It is used for the immutable retained
    /// selector before preparing a new input; no view escapes this call.
    pub(crate) fn prepare_management_ack_with_manifest(
        &self,
        request: CleanInvocationReplayRequest,
        manifest: &SharedRecoveryManifest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        if !matches!(&request, CleanInvocationReplayRequest::Acknowledge { .. }) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.prepare_clean_ordered_operation_with_policy(
            request,
            false,
            None,
            false,
            Some(manifest),
        )
    }

    /// Locally generated bootstrap work receives its unsigned preflight at
    /// journal admission. A retry recovers the original acceptance from the
    /// authenticated journal; it never refreshes a retained authorization.
    pub(crate) fn prepare_bootstrap_invocation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        let request = self.bootstrap_invocation_with_original_clock(request, false)?;
        let crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) =
            request.authorization()
        else {
            unreachable!()
        };
        let observed_slot = preflight.observed_slot;
        self.prepare_clean_ordered_operation_with_policy(
            request,
            false,
            Some(observed_slot),
            false,
            None,
        )
    }

    /// Recover an already committed bootstrap result through fresh physical
    /// replay. This neither proposes work nor admits a missing invocation at
    /// today's clock; followers must not turn absence into a policy mutation.
    pub(crate) fn replay_durable_bootstrap_invocation(
        &mut self,
        request: CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let request = self.bootstrap_invocation_with_original_clock(request, true)?;
        self.replay_durable_clean_terminal(request)
    }

    fn bootstrap_invocation_with_original_clock(
        &self,
        request: CleanInvocationReplayRequest,
        require_retained: bool,
    ) -> Result<CleanInvocationReplayRequest, SharedJournalDriverError> {
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight, RuntimeExecutionContext};
        let CleanInvocationReplayRequest::Invoke {
            context: RuntimeExecutionContext::Direct,
            work,
            authorization: InvocationAuthorization::PublicPreflight(preflight),
        } = request
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if !preflight.matches_work(&work) || work.mode != crate::agent_sdk::MethodMode::Linear {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let retained = self.retained_bootstrap_invocation(work.invocation)?;
        let authorization = match retained {
            Some(previous) => {
                if previous.work() != &work {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                previous.authorization().clone()
            }
            None => {
                if require_retained {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
                    &work,
                    self.executor.current_logical_slot()?,
                ))
            }
        };
        Ok(CleanInvocationReplayRequest::Invoke {
            context: RuntimeExecutionContext::Direct,
            work,
            authorization,
        })
    }

    /// Return the original input only together with a freshly replayed result.
    /// Callers must still bind the input to their expected bootstrap protocol
    /// message; an invocation ID alone is not lifecycle completion evidence.
    pub(crate) fn replay_durable_bootstrap_input(
        &mut self,
        invocation: crate::agent_sdk::InvocationId,
    ) -> Result<
        Option<(
            crate::agent_sdk::InvocationWork,
            crate::agent_sdk::RuntimeOutcome,
        )>,
        SharedJournalDriverError,
    > {
        let Some(request) = self.retained_bootstrap_invocation(invocation)? else {
            return Ok(None);
        };
        let work = request.work().clone();
        let outcome = self.replay_durable_clean_terminal(request)?;
        Ok(Some((work, outcome)))
    }

    fn retained_bootstrap_invocation(
        &self,
        invocation: crate::agent_sdk::InvocationId,
    ) -> Result<Option<CleanInvocationReplayRequest>, SharedJournalDriverError> {
        self.retained_public_invocation(invocation, crate::agent_sdk::MethodMode::Linear)
            .map(|retained| retained.map(|(request, _)| request))
    }

    /// Recover the original authorization of an exact, locally applied Query
    /// that still needs acknowledgement. The caller supplies expected work,
    /// never a replacement clock. An ACK closes this recovery opportunity.
    pub(crate) fn retained_projection_authorization(
        &self,
        expected: &crate::agent_sdk::InvocationWork,
    ) -> Result<Option<crate::agent_sdk::InvocationAuthorization>, SharedJournalDriverError> {
        if expected.mode != crate::agent_sdk::MethodMode::Query || !expected.validate() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let Some((request, _)) =
            self.retained_public_invocation(expected.invocation, expected.mode)?
        else {
            return Ok(None);
        };
        if request.work() != expected {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let authorization = request.authorization();
        if self.retained_positive_clean_acknowledgement(expected, authorization)? {
            return Ok(None);
        }
        if !self.retained_terminal_projection_invoke(expected, authorization)? {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok(Some(authorization.clone()))
    }

    /// Read only an exact, locally applied Query whose positive ACK is also
    /// present. Peer response bytes and an invocation ID alone are never
    /// evidence. Results come from this replica's verified replay executor;
    /// this performs no proposal, acknowledgement or speculative execution.
    /// Missing/pruned history returns None, never a newly executed query.
    pub(crate) fn retained_acknowledged_projection(
        &self,
        expected: &crate::agent_sdk::InvocationWork,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedJournalDriverError> {
        self.retained_acknowledged_projection_with_input(expected)
            .map(|retained| retained.map(|(_, outcome)| outcome))
    }

    pub(crate) fn retained_acknowledged_projection_with_input(
        &self,
        expected: &crate::agent_sdk::InvocationWork,
    ) -> Result<Option<(ReplayInputId, crate::agent_sdk::RuntimeOutcome)>, SharedJournalDriverError>
    {
        if expected.mode != crate::agent_sdk::MethodMode::Query || !expected.validate() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        // One freshly verified view resolves all parts of this exact retained
        // lifecycle. The legacy journal fallback remains unchanged; no view
        // escapes this call or substitutes a newer claim for missing evidence.
        let manifest = self.verified_recovery_manifest()?;
        let Some((request, input)) = self.retained_public_invocation_with_manifest(
            expected.invocation,
            expected.mode,
            manifest.as_ref(),
        )?
        else {
            return Ok(None);
        };
        if request.work() != expected {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        if !self.retained_positive_clean_acknowledgement_with_manifest(
            expected,
            request.authorization(),
            manifest.as_ref(),
        )? {
            return Ok(None);
        }
        // Ordinary retry lookup intentionally stops at a newer ACK. This
        // result-only path uses the authenticated Invoke input located above,
        // but only after proving that exact ACK; it never retries the Invoke.
        let outcome = retained_acknowledged_projection_outcome(
            manifest.as_ref(),
            expected,
            request.authorization(),
            input,
            || self.executor.clean_ordered_result(input),
        )
        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if !matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(_)) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok(Some((input, outcome)))
    }

    fn retained_public_invocation(
        &self,
        invocation: crate::agent_sdk::InvocationId,
        mode: crate::agent_sdk::MethodMode,
    ) -> Result<Option<(CleanInvocationReplayRequest, ReplayInputId)>, SharedJournalDriverError>
    {
        let manifest = self.verified_recovery_manifest()?;
        self.retained_public_invocation_with_manifest(invocation, mode, manifest.as_ref())
    }

    fn retained_public_invocation_with_manifest(
        &self,
        invocation: crate::agent_sdk::InvocationId,
        mode: crate::agent_sdk::MethodMode,
        manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<Option<(CleanInvocationReplayRequest, ReplayInputId)>, SharedJournalDriverError>
    {
        use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext};
        if invocation == crate::agent_sdk::InvocationId::ZERO {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        if let Some(manifest) = manifest
            && let Some((member, observation)) =
                manifest.management_slots().iter().find_map(|slot| {
                    slot.members().iter().zip(slot.members_evidence()).find_map(
                        |(member, evidence)| {
                            (member.work().invocation == invocation && member.work().mode == mode)
                                .then(|| evidence.invoke().map(|observation| (member, observation)))
                                .flatten()
                        },
                    )
                })
        {
            self.available_ordered_claim(observation.input_id())?;
            return Ok(Some((
                CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work: member.work().clone(),
                    authorization: member.authorization().clone(),
                },
                observation.input_id(),
            )));
        }
        let mut cursor = self.materialization.heads().ordered_head;
        let mut boundary_retired = false;
        // Exact bootstrap/projection lookup is bounded independently of the
        // complete journal's size. Exceeding that bound is not fresh evidence.
        for _ in 0..1_024 {
            let Some(id) = cursor else { break };
            if self.materialization.replay_boundary().head == Some(id) {
                break;
            }
            let entry = self
                .store
                .get::<OrderedEntry>(id)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if entry.id() != id || entry.genesis != self.materialization.heads().genesis {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if matches!(&entry.input.operation,
                ReplayOperation::CleanAcknowledge { work, .. }
                    if work.invocation == invocation)
                || matches!(&entry.input.operation,
                    ReplayOperation::CleanResume { work, .. }
                        if work.invocation == invocation)
            {
                boundary_retired = true;
            }
            if let ReplayOperation::CleanInvoke {
                context,
                work: previous,
                authorization,
                ..
            } = &entry.input.operation
                && previous.invocation == invocation
            {
                if *context != RuntimeExecutionContext::Direct
                    || previous.mode != mode
                    || !matches!(authorization, InvocationAuthorization::PublicPreflight(value) if value.matches_work(previous))
                {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                return Ok(Some((
                    CleanInvocationReplayRequest::Invoke {
                        context: *context,
                        work: previous.clone(),
                        authorization: authorization.clone(),
                    },
                    entry.input.id(),
                )));
            }
            cursor = entry.parent;
        }
        if cursor.is_some() && cursor != self.materialization.replay_boundary().head {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        // A common checkpoint proves its exact boundary input, not arbitrary
        // earlier requests hidden inside opaque guest state. Authority Query
        // ACK deliberately leaves no guest marker, so a newer lifecycle step
        // must not resurrect the boundary Invoke through speculative replay.
        if mode == crate::agent_sdk::MethodMode::Query
            && !boundary_retired
            && let Some((_, entry)) = self.available_common_checkpoint_boundary()?
            && let ReplayOperation::CleanInvoke {
                context: RuntimeExecutionContext::Direct,
                work,
                authorization,
                ..
            } = &entry.input.operation
            && work.invocation == invocation
            && work.mode == mode
            && matches!(authorization, InvocationAuthorization::PublicPreflight(value) if value.matches_work(work))
        {
            return Ok(Some((
                CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work: work.clone(),
                    authorization: authorization.clone(),
                },
                entry.input.id(),
            )));
        }
        Ok(None)
    }

    pub(crate) fn prepare_terminal_clean_ordered_operation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_clean_ordered_operation_with_policy(request, true, None, false, None)
    }

    /// Internal management work whose complete preflight envelope is already
    /// durable in its lifecycle intent. The intent's observation is immutable;
    /// neither dispatch latency nor reopening may turn it into a new admission.
    /// This is not an ingress API or a projection-pair capacity reservation.
    pub(crate) fn prepare_persisted_management_invocation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_persisted_management_invocation_with_policy(request, None)
    }

    /// Borrow only the freshly verified manifest of this guarded custody
    /// Invoke. Original preflight, clock ordering, terminal preview and exact
    /// retained-input checks remain on the existing persisted policy below.
    pub(crate) fn prepare_persisted_management_invocation_with_manifest(
        &self,
        request: CleanInvocationReplayRequest,
        manifest: &SharedRecoveryManifest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_persisted_management_invocation_with_policy(request, Some(manifest))
    }

    fn prepare_persisted_management_invocation_with_policy(
        &self,
        request: CleanInvocationReplayRequest,
        verified_manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        let CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization: crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight),
        } = &request
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if work.mode != crate::agent_sdk::MethodMode::Linear
            || !preflight.matches_work(work)
            || preflight.observed_slot > self.executor.current_logical_slot()?
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let observed_slot = preflight.observed_slot;
        self.prepare_clean_ordered_operation_with_policy(
            request,
            true,
            Some(observed_slot),
            true,
            verified_manifest,
        )
    }

    fn prepare_clean_ordered_operation_with_policy(
        &self,
        request: CleanInvocationReplayRequest,
        terminal_only: bool,
        accepted_observed_slot: Option<u64>,
        persisted_management: bool,
        verified_manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        let cost_started = if persisted_management {
            management_admission_cost_started()
        } else {
            None
        };
        // Retry identity excludes the trusted observation slot. The real slot
        // is sampled exactly once below only when a new operation is built.
        let operation = request.clone().into_operation(0);
        let fresh_manifest = if verified_manifest.is_none() {
            self.verified_recovery_manifest()?
        } else {
            None
        };
        let manifest = verified_manifest.or(fresh_manifest.as_ref());
        if let Some(manifest) = manifest {
            if let Some(observation) = retained_management_operation(manifest, &operation)? {
                if terminal_only
                    && !matches!(
                        observation.outcome(),
                        crate::agent_sdk::RuntimeOutcome::Completed(_)
                    )
                {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                self.available_ordered_claim(observation.input_id())?;
                return Ok(PreparedCleanOrdered::Retained {
                    input: observation.input_id(),
                    outcome: observation.outcome().clone(),
                });
            }
        }
        if let Some(input) =
            recent_clean_ordered_operation(&self.store, &self.materialization, &operation)?
        {
            let outcome = self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if terminal_only && !matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(_)) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            return Ok(PreparedCleanOrdered::Retained { input, outcome });
        }
        let common_query_boundary = matches!(&operation,
            ReplayOperation::CleanInvoke { work, .. }
                if work.mode == crate::agent_sdk::MethodMode::Query)
            && self.materialization.common_checkpoint().is_some();
        if ((accepted_observed_slot.is_some() && terminal_only) || common_query_boundary)
            && let Some((input, outcome)) =
                self.retained_terminal_projection_boundary(&operation)?
        {
            return Ok(PreparedCleanOrdered::Retained { input, outcome });
        }
        // Preserve all exact first selectors above. Only a genuinely unseen
        // fixed-three retained management member needs ordering and a successful
        // preview; singleton/ordinary/bootstrap execution remains unchanged.
        trace_management_admission_cost("preparation_selectors", cost_started, 1, true);
        let successful_management = if persisted_management {
            let observed_slot =
                accepted_observed_slot.ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            let envelope = crate::agent_sdk::RuntimeWork::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: crate::agent_sdk::RuntimeState::default(),
                invocation: Box::new(request.work().clone()),
                authorization: Box::new(request.authorization().clone()),
                observed_slot,
            };
            if let Some(manifest) = manifest
                && exact_retained_management_member(manifest, None, &envelope)?.is_some()
            {
                if !management_first_invoke_clock_ready(manifest, observed_slot)? {
                    return Err(JournalStoreError::Unavailable.into());
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        let input = match accepted_observed_slot {
            Some(observed_slot) => self.clean_operation_input_at(request, observed_slot)?,
            None => self.clean_operation_input(request)?,
        };
        if !matches!(
            input.persisted_lane(),
            PersistedLane::Control | PersistedLane::Linear
        ) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let heads = self.materialization.heads();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: None,
            input,
        };
        entry
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let input = &entry.input;
        #[cfg(feature = "experimental-state-blocks")]
        let require_terminal = terminal_only || successful_management || self.external.is_some();
        #[cfg(not(feature = "experimental-state-blocks"))]
        let require_terminal = terminal_only || successful_management;
        if require_terminal {
            let cost_started = if persisted_management {
                management_admission_cost_started()
            } else {
                None
            };
            #[cfg(feature = "experimental-state-blocks")]
            let terminal = if self.external.is_some() {
                let work = super::replay::canonical_clean_runtime_work(
                    input,
                    self.materialization.state(),
                )
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                let outcome = self.execute_external_work_at(work, Some(&entry))?.outcome;
                let terminal = matches!(
                    (&input.operation, &outcome),
                    (
                        ReplayOperation::CleanInvoke { .. },
                        crate::agent_sdk::RuntimeOutcome::Completed(_)
                    ) | (
                        ReplayOperation::CleanAcknowledge { .. },
                        crate::agent_sdk::RuntimeOutcome::Acknowledged(_)
                    )
                ) && (!successful_management
                    || matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(Ok(_))));
                if successful_management && !terminal {
                    let (outcome_kind, invocation_error) = match &outcome {
                        crate::agent_sdk::RuntimeOutcome::Completed(Ok(_)) => {
                            ("completed_ok", None)
                        }
                        crate::agent_sdk::RuntimeOutcome::Completed(Err(error)) => {
                            ("completed_error", Some(*error))
                        }
                        crate::agent_sdk::RuntimeOutcome::Yielded(_) => ("yielded", None),
                        crate::agent_sdk::RuntimeOutcome::Acknowledged(_) => ("acknowledged", None),
                        crate::agent_sdk::RuntimeOutcome::Management(_) => ("management", None),
                    };
                    tracing::debug!(
                        phase = "external_durable_preview_refused",
                        outcome_kind,
                        ?invocation_error,
                        "Retained management preparation refused"
                    );
                }
                terminal
            } else {
                if successful_management {
                    self.executor
                        .clean_management_invocation_is_successful_terminal(
                            &input.operation,
                            self.materialization.state(),
                            &input.runtime,
                        )?
                } else {
                    self.executor.clean_invocation_is_terminal(
                        &input.operation,
                        self.materialization.state(),
                        &input.runtime,
                    )?
                }
            };
            #[cfg(not(feature = "experimental-state-blocks"))]
            let terminal = if successful_management {
                self.executor
                    .clean_management_invocation_is_successful_terminal(
                        &input.operation,
                        self.materialization.state(),
                        &input.runtime,
                    )?
            } else {
                self.executor.clean_invocation_is_terminal(
                    &input.operation,
                    self.materialization.state(),
                    &input.runtime,
                )?
            };
            trace_management_admission_cost("preparation_preview", cost_started, 1, terminal);
            if !terminal {
                if successful_management {
                    return Err(JournalStoreError::Unavailable.into());
                }
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        let input = entry.input.id();
        let payload = AgentRaftCommand::Ordered {
            route: self.active_route()?,
            artifact_batch: None,
            entry,
        }
        .encode();
        AgentRaftCommand::decode(&payload)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        Ok(PreparedCleanOrdered::Proposal { input, payload })
    }

    /// Publish one clean Local-lane invocation on this exact physical
    /// replica. This never enters Raft; a routed request mutates only the
    /// receiving replica's Local lane.
    pub(crate) fn apply_clean_local(
        &mut self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.apply_clean_local_operation(CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
        })
    }

    pub(crate) fn apply_clean_local_operation(
        &mut self,
        request: CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        let retry = request.clone().into_operation(0);
        if let Some(input) =
            recent_clean_local_operation(&self.store, &self.materialization, &retry)?
        {
            return self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input = self.clean_operation_input(request)?;
        if input.persisted_lane() != PersistedLane::Local {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input_id = input.id();
        let heads = self.materialization.heads();
        let entry = LocalEntry {
            genesis: heads.genesis,
            node: heads.node,
            revision: heads
                .local_revision
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.local_head,
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            merge_frontier: heads.merge_frontier,
            input,
        };
        match prepare_local(
            &mut self.store,
            &mut self.executor,
            &self.materialization,
            &entry,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        self.executor
            .take_clean_invocation_result(input_id)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)
    }

    /// Publish one locally authored clean Merge invocation. The full active
    /// committee authenticates membership, while the local replica key signs
    /// the canonical event and replay verifies it again.
    pub(crate) fn apply_clean_merge(
        &mut self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.apply_clean_merge_operation(CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
        })
    }

    pub(crate) fn apply_clean_merge_operation(
        &mut self,
        request: CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        let retry = request.clone().into_operation(0);
        if let Some(input) =
            recent_clean_merge_operation(&self.store, &self.materialization, &retry)?
        {
            return self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input = self.clean_operation_input(request)?;
        if input.persisted_lane() != PersistedLane::Merge {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input_id = input.id();
        let heads = self.materialization.heads();
        let frontier = self
            .store
            .get::<MergeFrontier>(heads.merge_frontier)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if frontier.id() != heads.merge_frontier || frontier.genesis != heads.genesis {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let mut maximum = 0_u64;
        for parent in &frontier.events {
            let event = self
                .store
                .get::<MergeEvent>(*parent)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if event.id() != *parent || event.genesis != heads.genesis {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            maximum = maximum.max(event.causal_height);
        }
        let causal_height = maximum
            .checked_add(1)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let mut event = MergeEvent {
            genesis: heads.genesis,
            author: self.local_node,
            committee: Some(self.ledger.active_committee()?.id()),
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            causal_height,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        self.executor.sign_shared_merge_event(&mut event)?;
        match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            &event,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        self.executor
            .take_clean_invocation_result(input_id)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)
    }

    #[cfg(all(test, feature = "network"))]
    pub(crate) fn publish_merge_for_test(
        &mut self,
        operation: ReplayOperation,
    ) -> Result<super::journal::MergeEventId, SharedJournalDriverError> {
        let heads = self.materialization.heads();
        let input = ReplayInput {
            runtime: heads.runtime.clone(),
            operation,
        };
        input
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        if input.persisted_lane() != PersistedLane::Merge {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let frontier = self
            .store
            .get::<MergeFrontier>(heads.merge_frontier)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if frontier.id() != heads.merge_frontier || frontier.genesis != heads.genesis {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let mut maximum = 0_u64;
        for parent in &frontier.events {
            let event = self
                .store
                .get::<MergeEvent>(*parent)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if event.id() != *parent || event.genesis != heads.genesis {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            maximum = maximum.max(event.causal_height);
        }
        let mut event = MergeEvent {
            genesis: heads.genesis,
            author: self.local_node,
            committee: Some(self.ledger.active_committee()?.id()),
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            causal_height: maximum
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        self.executor.sign_shared_merge_event(&mut event)?;
        let id = event.id();
        match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            &event,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        Ok(id)
    }

    pub(crate) fn take_clean_ordered_result(
        &mut self,
        input: ReplayInputId,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.try_take_clean_ordered_result(input)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)
    }

    /// Poll the bounded synchronous response handoff. Absence is not journal
    /// corruption: the relevant committed entry can be on another apply
    /// thread, or the caller may already have consumed its response. Exact
    /// management retries use the separate bounded replay-derived cache.
    pub(crate) fn try_take_clean_ordered_result(
        &mut self,
        input: ReplayInputId,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedJournalDriverError> {
        Ok(self.executor.take_clean_invocation_result(input))
    }

    /// Build one real seal-only Ordered command from the currently
    /// materialized filesystem journal, then append its canonical bytes to
    /// the physical Raft log. Test-only because production log admission is
    /// owned by the not-yet-attached Agent transport coordinator.
    #[cfg(test)]
    pub(crate) fn append_command_for_test(
        &self,
        term: u64,
        payload: Vec<u8>,
    ) -> Result<u64, SharedJournalDriverError> {
        AgentRaftCommand::decode(&payload)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        self.ledger
            .append_committed_for_test(term, &vos_raft::EntryKind::Data { payload })
            .map_err(Into::into)
    }

    #[cfg(test)]
    pub(crate) fn append_ordered_for_test(
        &mut self,
        term: u64,
        operation: super::journal::ReplayOperation,
    ) -> Result<u64, SharedJournalDriverError> {
        let heads = self.materialization.heads().clone();
        let merge_state = self.materialization.state().merge.clone();
        let state = BlobRef::of_bytes(&merge_state);
        self.store
            .put_blob(JournalBlobClass::LaneState, &state, &merge_state)?;
        let manifest = super::journal::LaneStateManifest {
            #[cfg(feature = "experimental-state-blocks")]
            external_root: None,
            genesis: heads.genesis,
            runtime: heads.runtime.clone(),
            lane: super::journal::PersistedLane::Merge,
            cursor: super::journal::LaneCursor::Merge {
                frontier: heads.merge_frontier,
            },
            state,
        };
        self.store.put(&manifest)?;
        let seal = super::journal::MergeSeal {
            genesis: heads.genesis,
            frontier: heads.merge_frontier,
            ordered_base: super::journal::OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            merge_state: manifest.id(),
        };
        self.store.put(&seal)?;
        let entry = super::journal::OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(seal.id()),
            input: super::journal::ReplayInput {
                runtime: heads.runtime,
                operation,
            },
        };
        let command = AgentRaftCommand::Ordered {
            route: self.active_route()?,
            artifact_batch: None,
            entry,
        };
        self.ledger
            .append_committed_for_test(
                term,
                &vos_raft::EntryKind::Data {
                    payload: command.encode(),
                },
            )
            .map_err(SharedJournalDriverError::from)
    }

    pub(crate) fn capacity(&self) -> Result<(u64, u64, bool), SharedJournalDriverError> {
        self.ledger.capacity().map_err(Into::into)
    }

    /// The raw manifest is a product of this actual capacity audit. Reuse only
    /// its immutable bytes; retain the independent runtime, physical result
    /// and common-baseline verification before lending it to admission.
    pub(crate) fn capacity_and_recovery_manifest(
        &self,
    ) -> Result<((u64, u64, bool), SharedRecoveryManifest), SharedJournalDriverError> {
        let (capacity, raw_manifest) = self.ledger.capacity_and_recovery_manifest()?;
        let manifest = match self.verified_recovery_manifest_from_read(raw_manifest)? {
            Some(manifest) => manifest,
            None => self.ledger.recovery_manifest()?,
        };
        Ok((capacity, manifest))
    }

    pub(crate) fn recovery_manifest(
        &self,
    ) -> Result<SharedRecoveryManifest, SharedJournalDriverError> {
        match self.verified_recovery_manifest()? {
            Some(manifest) => Ok(manifest),
            None => self.ledger.recovery_manifest().map_err(Into::into),
        }
    }

    /// Mutable capsule bytes are not authenticated by their registration
    /// signature. Recheck the bounded read/management observations against either the exact
    /// certified baseline or this open owner's independently replayed result
    /// and the corresponding physical Ordered anchor. No suffix scan or VM
    /// execution is needed on a normal lookup.
    fn verified_recovery_manifest(
        &self,
    ) -> Result<Option<SharedRecoveryManifest>, SharedJournalDriverError> {
        self.verified_recovery_manifest_from_read(self.ledger.recovery_manifest_if_present()?)
    }

    fn verified_recovery_manifest_from_read(
        &self,
        manifest: Option<SharedRecoveryManifest>,
    ) -> Result<Option<SharedRecoveryManifest>, SharedJournalDriverError> {
        let Some(manifest) = manifest else {
            return Ok(None);
        };
        for slot in manifest.management_slots() {
            self.validate_management_registration_runtime(slot.registration().request())?;
        }
        let baseline = if self.materialization.common_checkpoint().is_some() {
            self.ledger
                .common_snapshot_recovery_manifest_at(self.materialization.common_checkpoint())?
        } else {
            None
        };
        self.verify_recovery_manifest_evidence(&manifest, baseline.as_ref())?;
        Ok(Some(manifest))
    }

    fn verify_recovery_manifest_evidence(
        &self,
        manifest: &SharedRecoveryManifest,
        baseline: Option<&SharedRecoveryManifest>,
    ) -> Result<(), SharedJournalDriverError> {
        let started = management_admission_cost_started();
        for slot in manifest.management_slots() {
            let heads = self.materialization.heads();
            if slot.members().iter().any(|member| {
                member.anchor().genesis != heads.genesis
                    || member.anchor().admission != heads.admission
                    || member.anchor().runtime != heads.runtime.commitment()
                    || member.work().runtime_deployment.0 != heads.runtime.deployment.0
                    || member.anchor().ordered.index > heads.ordered_index
            }) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if !baseline.is_some_and(|baseline| {
                baseline.management_slots().iter().any(|certified| {
                    certified.registration() == slot.registration()
                        && certified.raft_index() == slot.raft_index()
                        && certified.raft_term() == slot.raft_term()
                })
            }) {
                self.ledger
                    .validate_management_recovery_slot_registration(slot)?;
            }
            if slot.release().is_some()
                && !baseline.is_some_and(|baseline| {
                    baseline.management_slots().iter().any(|certified| {
                        certified.release() == slot.release()
                            && certified.release_raft_index() == slot.release_raft_index()
                            && certified.release_raft_term() == slot.release_raft_term()
                    })
                })
            {
                self.ledger
                    .validate_management_recovery_slot_release(slot)?;
            }
        }
        for observation in unique_recovery_observations(manifest) {
            if baseline.is_some_and(|baseline| {
                baseline
                    .observations()
                    .into_iter()
                    .any(|certified| certified == observation)
            }) {
                continue;
            }
            let outcome = self.executor.clean_ordered_result_at(
                observation
                    .claim()
                    .ordered()
                    .head
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                observation.input_id(),
            );
            if outcome.as_ref() != Some(observation.outcome()) {
                tracing::warn!(
                    phase = "positioned_recovery_observation",
                    ordered_index = self.materialization.heads().ordered_index,
                    outcome_kind = clean_outcome_kind(outcome.as_ref()),
                    expected_outcome_kind = clean_outcome_kind(Some(observation.outcome())),
                    "Shared recovery positioned outcome mismatch"
                );
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            self.ledger.validate_recovery_observation(observation)?;
        }
        trace_management_admission_cost(
            "manifest_evidence",
            started,
            manifest.management_slots().len(),
            true,
        );
        Ok(())
    }

    pub(crate) fn common_snapshot_recovery_manifest(
        &self,
    ) -> Result<Option<SharedRecoveryManifest>, SharedJournalDriverError> {
        self.ledger
            .common_snapshot_recovery_manifest()
            .map_err(Into::into)
    }

    pub(crate) fn validate_management_recovery_registration_request(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
    ) -> Result<(), SharedJournalDriverError> {
        self.validate_management_recovery_registration_request_with_policy(request, None)
    }

    pub(crate) fn validate_management_recovery_registration_request_with_manifest(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
        manifest: &SharedRecoveryManifest,
    ) -> Result<(), SharedJournalDriverError> {
        self.validate_management_recovery_registration_request_with_policy(request, Some(manifest))
    }

    fn validate_management_recovery_registration_request_with_policy(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
        verified_manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<(), SharedJournalDriverError> {
        if verified_manifest.is_none() {
            self.verified_recovery_manifest()?;
        }
        self.validate_management_registration_runtime(request)?;
        // This ledger call still audits and verifies the current settled raw
        // prefix for every request, independently of the borrowed selectors.
        self.ledger
            .validate_management_recovery_registration_request(request)
            .map_err(Into::into)
    }

    /// Admission only, before custody or an independent intent write. A late
    /// unadmitted clock must not become an unfinishable durable obligation.
    /// Exact admitted envelopes (including ambiguous commits/shadow holders)
    /// keep their original clock; their existing evidence is never replaced.
    pub(crate) fn validate_new_management_invocation_clock(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
    ) -> Result<(), SharedJournalDriverError> {
        self.validate_new_management_invocation_clock_with_policy(request, None)
    }

    pub(crate) fn validate_new_management_invocation_clock_with_manifest(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
        manifest: &SharedRecoveryManifest,
    ) -> Result<(), SharedJournalDriverError> {
        self.validate_new_management_invocation_clock_with_policy(request, Some(manifest))
    }

    fn validate_new_management_invocation_clock_with_policy(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
        verified_manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<(), SharedJournalDriverError> {
        self.validate_management_registration_runtime(request)?;
        let member = request
            .members()
            .last()
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let fresh_manifest = if verified_manifest.is_none() {
            self.verified_recovery_manifest()?
        } else {
            None
        };
        let manifest = verified_manifest.or(fresh_manifest.as_ref());
        if let Some(manifest) = manifest
            && exact_retained_management_member(manifest, None, member.envelope())?.is_some()
        {
            return Ok(());
        }
        let crate::agent_sdk::RuntimeWork::Invoke {
            context,
            invocation,
            authorization,
            observed_slot,
            ..
        } = member.envelope()
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if *observed_slot > self.executor.current_logical_slot()? {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let operation = ReplayOperation::CleanInvoke {
            context: *context,
            work: (**invocation).clone(),
            authorization: (**authorization).clone(),
            observed_slot: *observed_slot,
        };
        let started = management_admission_cost_started();
        let terminal = self
            .executor
            .new_management_invocation_is_successful_terminal(
                &operation,
                self.materialization.state(),
                self.materialization.runtime(),
            )?;
        trace_management_admission_cost("clock_preview", started, 1, terminal);
        if !terminal {
            return Err(JournalStoreError::Unavailable.into());
        }
        Ok(())
    }

    /// The ledger's post-genesis prefix can be empty. Its metadata fold cannot
    /// invent the runtime identity from absent Ordered rows: seal it against
    /// this actual admitted materialization before minting or applying a row.
    fn validate_management_registration_runtime(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryRegistrationRequest,
    ) -> Result<(), SharedJournalDriverError> {
        let heads = self.materialization.heads();
        if request.generation() != self.ledger.generation()
            || request.members().iter().any(|member| {
                member.anchor().genesis != heads.genesis
                    || member.anchor().admission != heads.admission
                    || member.anchor().runtime != heads.runtime.commitment()
                    || member.work().runtime_deployment.0 != heads.runtime.deployment.0
            })
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_management_recovery_registration(
        &self,
        registration: &super::shared_recovery::SharedManagementRecoveryRegistration,
    ) -> Result<(), SharedJournalDriverError> {
        self.validate_management_recovery_registration_with_policy(registration, None)
    }

    pub(crate) fn validate_management_recovery_registration_with_manifest(
        &self,
        registration: &super::shared_recovery::SharedManagementRecoveryRegistration,
        manifest: &SharedRecoveryManifest,
    ) -> Result<(), SharedJournalDriverError> {
        self.validate_management_recovery_registration_with_policy(registration, Some(manifest))
    }

    fn validate_management_recovery_registration_with_policy(
        &self,
        registration: &super::shared_recovery::SharedManagementRecoveryRegistration,
        verified_manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<(), SharedJournalDriverError> {
        if verified_manifest.is_none() {
            self.verified_recovery_manifest()?;
        }
        self.validate_management_registration_runtime(registration.request())?;
        // The signature-verifying ledger entry point also performs the fresh,
        // complete request preflight. Do not audit that same request twice.
        self.ledger
            .validate_management_recovery_registration(registration)
            .map_err(Into::into)
    }

    pub(crate) fn validate_management_recovery_release_request(
        &self,
        request: &super::shared_recovery::management::SharedManagementRecoveryReleaseRequest,
    ) -> Result<(), SharedJournalDriverError> {
        self.verified_recovery_manifest()?;
        self.ledger
            .validate_management_recovery_release_request(request)
            .map_err(Into::into)
    }

    pub(crate) fn validate_management_recovery_release(
        &self,
        release: &super::shared_recovery::SharedManagementRecoveryRelease,
    ) -> Result<(), SharedJournalDriverError> {
        let diagnostics = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some();
        let trace = |phase: &'static str, started: Option<std::time::Instant>, success: bool| {
            if let Some(started) = started {
                tracing::debug!(metadata = ?release.commitment().0, phase,
                    elapsed_us = started.elapsed().as_micros(), success,
                    "Shared management release cost");
            }
        };
        let started = diagnostics.then(std::time::Instant::now);
        let verified = self.verified_recovery_manifest();
        trace("driver_manifest", started, verified.is_ok());
        verified?;
        // The signed ledger entry point performs its own exact request
        // preflight. Keep driver provenance and that signature-first boundary
        // without repeating the same settled physical-prefix audit here.
        let started = diagnostics.then(std::time::Instant::now);
        let validated = self.ledger
            .validate_management_recovery_release(release)
            .map_err(Into::into);
        trace("signed_ledger_validation", started, validated.is_ok());
        validated
    }

    /// Keep driver provenance before the signed ledger preflight; capacity is
    /// derived inside that preflight's same guarded database read.
    pub(crate) fn validate_management_recovery_release_and_capacity(
        &self,
        release: &super::shared_recovery::SharedManagementRecoveryRelease,
    ) -> Result<(u64, u64, bool), SharedJournalDriverError> {
        let diagnostics = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some();
        let trace = |phase: &'static str, started: Option<std::time::Instant>, success: bool| {
            if let Some(started) = started {
                tracing::debug!(metadata = ?release.commitment().0, phase,
                    elapsed_us = started.elapsed().as_micros(), success,
                    "Shared management release cost");
            }
        };
        let started = diagnostics.then(std::time::Instant::now);
        let verified = self.verified_recovery_manifest();
        trace("driver_manifest", started, verified.is_ok());
        verified?;
        let started = diagnostics.then(std::time::Instant::now);
        let validated = self.ledger
            .validate_management_recovery_release_and_capacity(release)
            .map_err(Into::into);
        trace("signed_ledger_validation", started, validated.is_ok());
        validated
    }

    pub(crate) fn uses_external_state(&self) -> bool {
        #[cfg(feature = "experimental-state-blocks")]
        {
            self.external.is_some()
        }
        #[cfg(not(feature = "experimental-state-blocks"))]
        {
            false
        }
    }

    /// Find this input's exact retained publication. A common checkpoint can
    /// replace a retired anchor for its exact Query boundary or an exact live
    /// recovery observation included in its certified baseline. A newer state
    /// root alone is never evidence for an arbitrary historical input.
    pub(crate) fn available_ordered_claim(
        &self,
        input: ReplayInputId,
    ) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        // This bounded row read only selects the historical path. It cannot
        // grant availability: that path rechecks the exact live observation
        // against a single freshly audited live/baseline/physical view below.
        let recovery = self.ledger.recovery_manifest_if_present()?;
        if !self.uses_external_state()
            && self.materialization.common_checkpoint().is_some()
            && let Some(observation) = recovery.as_ref().and_then(|manifest| {
                manifest
                    .observations()
                    .into_iter()
                    .find(|observation| observation.input_id() == input)
            })
            && observation.claim().ordered().index <= self.materialization.replay_boundary().index
        {
            return self.available_archived_recovery_observation(observation);
        }
        // Noncertified suffix observations retain the existing bounded cache
        // and physical-row checks, not a new full suffix audit on every reply.
        let recovery = self.verified_recovery_manifest_from_read(recovery)?;
        self.available_nonarchived_ordered_claim(input, recovery.as_ref())
    }

    // The raw wrapper above verifies its own fresh live view. The budget
    // caller has already verified its immutable call-local live view; neither
    // caller may skip the exact physical availability checks below.
    fn available_nonarchived_ordered_claim(
        &self,
        input: ReplayInputId,
        recovery: Option<&SharedRecoveryManifest>,
    ) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        if let Some(observation) = recovery.and_then(|manifest| {
            manifest
                .observations()
                .into_iter()
                .find(|observation| observation.input_id() == input)
        }) {
            let claim = observation.claim();
            self.verify_ordered_availability(
                claim.raft_index(),
                claim.raft_term(),
                claim.commitment(),
            )?;
            return Ok(claim.clone());
        }
        let mut next = self.materialization.heads().ordered_head;
        let mut expected_index = self.materialization.heads().ordered_index;
        for _ in 0..super::journal::MAX_REPLAY_SUFFIX_ENTRIES {
            let Some(id) = next else {
                break;
            };
            if Some(id) == self.materialization.replay_boundary().head {
                break;
            }
            let entry = self
                .store
                .get::<OrderedEntry>(id)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if entry.id() != id
                || entry.genesis != self.materialization.heads().genesis
                || entry.index != expected_index
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if entry.input.id() == input {
                let binding = self
                    .store
                    .shared_ordered_commit(id)?
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                let claim = binding.claim().clone();
                self.verify_ordered_availability(
                    claim.raft_index(),
                    claim.raft_term(),
                    claim.commitment(),
                )?;
                return Ok(claim);
            }
            next = entry.parent;
            expected_index = expected_index
                .checked_sub(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        }
        if let Some((claim, entry)) = self.available_common_checkpoint_boundary()?
            && entry.input.id() == input
            && matches!(&entry.input.operation, ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization: crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight),
                ..
            } if work.mode == crate::agent_sdk::MethodMode::Query && preflight.matches_work(work))
        {
            return Ok(claim);
        }
        Err(JournalStoreError::Unavailable.into())
    }

    fn available_ordered_claim_in_management_budget(
        &self,
        input: ReplayInputId,
        budget: Option<&SharedRecoveryManifest>,
        archived: &mut Option<(
            SharedAgentCommonSnapshotCertificate,
            SharedAgentLocalSnapshotBinding,
            Option<SharedRecoveryManifest>,
            Option<SharedRecoveryManifest>,
        )>,
    ) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        if !self.uses_external_state()
            && self.materialization.common_checkpoint().is_some()
            && let Some(budget) = budget
            && let Some(requested) = budget
                .observations()
                .into_iter()
                .find(|observation| observation.input_id() == input)
            && requested.claim().ordered().index <= self.materialization.replay_boundary().index
        {
            if archived.is_none() {
                let view = self
                    .ledger
                    .common_snapshot_authority_with_recovery()?
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                let (certificate, binding, baseline, live) = &view;
                let live = live
                    .as_ref()
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                if Some(binding.claim().checkpoint()) != self.materialization.common_checkpoint()
                    || live != budget
                {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                // The physical fold alone is not execution-result authority.
                // Preserve all live/nonbaseline evidence and physical closure
                // checks before the tuple can be reused.
                self.verify_recovery_manifest_evidence(live, baseline.as_ref())?;
                certified_budget_recovery_observation(budget, live, baseline.as_ref(), requested)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                self.validate_common_checkpoint_boundary(certificate, binding)?;
                *archived = Some(view);
            }
            let (_, binding, baseline, live) = archived
                .as_ref()
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if Some(binding.claim().checkpoint()) != self.materialization.common_checkpoint() {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            let observation = certified_budget_recovery_observation(
                budget,
                live.as_ref()
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                baseline.as_ref(),
                requested,
            )
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            return Ok(observation.claim().clone());
        }
        self.available_nonarchived_ordered_claim(input, budget)
    }

    fn available_archived_recovery_observation(
        &self,
        requested: &SharedRecoveryObservation,
    ) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        let Some((certificate, binding, baseline, live)) =
            self.ledger.common_snapshot_authority_with_recovery()?
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if Some(binding.claim().checkpoint()) != self.materialization.common_checkpoint() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let live = live.ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        // The ledger's complete physical fold is not VM-result authority.
        // Keep every live acquisition and nonbaseline result/cache check.
        self.verify_recovery_manifest_evidence(&live, baseline.as_ref())?;
        let observation = certified_live_recovery_observation(&live, baseline.as_ref(), requested)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        self.validate_common_checkpoint_boundary(&certificate, &binding)?;
        Ok(observation.claim().clone())
    }

    fn available_common_checkpoint_claim(
        &self,
        index: u64,
        term: u64,
        hash: Hash,
    ) -> Result<Option<OrderedCommitClaim>, SharedJournalDriverError> {
        if self.uses_external_state() || self.materialization.common_checkpoint().is_none() {
            return Ok(None);
        }
        let Some((certificate, binding, recovery, live)) =
            self.ledger.common_snapshot_authority_with_recovery()?
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        let observation = live
            .as_ref()
            .into_iter()
            .flat_map(SharedRecoveryManifest::observations)
            .find(|observation| {
                observation.raft_index() == index
                    && observation.raft_term() == term
                    && observation.claim_commitment() == hash
            });
        // Membership and the complete physical closure use this one freshly
        // audited authority view. The original observation claim is retained;
        // the newer checkpoint boundary never stands in for old evidence.
        let (boundary, _) = self.validate_common_checkpoint_boundary(&certificate, &binding)?;
        if let Some(observation) = observation {
            let live = live
                .as_ref()
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            self.verify_recovery_manifest_evidence(live, recovery.as_ref())?;
            let observation =
                certified_live_recovery_observation(live, recovery.as_ref(), observation)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            return Ok(Some(observation.claim().clone()));
        }
        Ok((boundary.raft_index() == index
            && boundary.raft_term() == term
            && boundary.commitment() == hash)
            .then_some(boundary))
    }

    /// Recheck the exact locally installed common boundary and the opaque
    /// state/artifacts needed to recover its Query. This does not inspect
    /// runtime-private result layouts or certify a pre-boundary request. The
    /// full checkpoint closure was audited by publication/import and reopen;
    /// no external blocks or reclamation authority are admitted here.
    fn available_common_checkpoint_boundary(
        &self,
    ) -> Result<Option<(OrderedCommitClaim, OrderedEntry)>, SharedJournalDriverError> {
        if self.uses_external_state() || self.materialization.common_checkpoint().is_none() {
            return Ok(None);
        }
        let Some((certificate, binding, _baseline, _live)) =
            self.ledger.common_snapshot_authority_with_recovery()?
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        self.validate_common_checkpoint_boundary(&certificate, &binding)
            .map(Some)
    }

    /// Validate every physical dependency against the same audited common
    /// authority selected by the caller. This borrowed view is call-local.
    fn validate_common_checkpoint_boundary(
        &self,
        certificate: &SharedAgentCommonSnapshotCertificate,
        binding: &super::shared_commit::SharedAgentLocalSnapshotBinding,
    ) -> Result<(OrderedCommitClaim, OrderedEntry), SharedJournalDriverError> {
        let physical = binding.claim();
        binding.verify(certificate, physical)?;
        let claim = certificate.claim().ordered();
        let heads = self.materialization.heads();
        if self.store.heads()?.as_ref() != Some(heads)
            || physical.journal_store().0 != *self.store.instance_id().as_bytes()
            || physical.local_node() != heads.node
            || Some(physical.checkpoint()) != self.materialization.common_checkpoint()
            || claim.ordered() != self.materialization.replay_boundary()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        validate_published_shared_checkpoint(&self.store, &self.materialization, physical)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let checkpoint = self
            .store
            .get::<super::journal::CheckpointManifest>(physical.checkpoint())?
            .ok_or(JournalStoreError::Unavailable)?;
        if checkpoint.merge_frontier != claim.merge_frontier()
            || checkpoint.merge_fence != claim.merge_fence()
            || checkpoint.merge_seal != claim.merge_seal()
            || checkpoint.merge_invocations != claim.merge_invocations()
            || checkpoint.ordered_invocations != claim.ordered_invocations()
            || checkpoint.artifacts != claim.artifacts()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        for (physical_root, projection) in [
            (physical.control(), claim.control()),
            (physical.linear(), claim.linear()),
            (physical.merge(), claim.merge()),
        ] {
            let manifest = self
                .store
                .get::<super::journal::LaneStateManifest>(physical_root)?
                .ok_or(JournalStoreError::Unavailable)?;
            let bytes = self
                .store
                .load_blob(JournalBlobClass::LaneState, &manifest.state)?
                .ok_or(JournalStoreError::Unavailable)?;
            if manifest.id() != projection.manifest() {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            projection.verify_state(&bytes)?;
        }
        let artifacts = self
            .store
            .get::<super::journal::ArtifactClosure>(claim.artifacts())?
            .ok_or(JournalStoreError::Unavailable)?;
        if artifacts.genesis != claim.genesis() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        for reference in &artifacts.artifacts {
            let bytes = self
                .store
                .load_blob(JournalBlobClass::CatalogArtifact, reference)?
                .ok_or(JournalStoreError::Unavailable)?;
            if !reference.matches(&bytes) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        for (id, scope) in [
            (
                physical.ordered_invocations(),
                super::journal::InvocationOwnershipScope::Ordered,
            ),
            (
                physical.merge_invocations(),
                super::journal::InvocationOwnershipScope::Merge,
            ),
            (
                physical.local_invocations(),
                super::journal::InvocationOwnershipScope::Local(heads.node),
            ),
        ] {
            let manifest = self
                .store
                .get::<super::journal::InvocationIndexManifest>(id)?
                .ok_or(JournalStoreError::Unavailable)?;
            if manifest.genesis != claim.genesis() || manifest.scope != scope {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            super::invocation_index::validate_manifest_root(&self.store, id, &manifest)
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        }
        let entry = self
            .store
            .get::<OrderedEntry>(claim.ordered().head.ok_or(JournalStoreError::Unavailable)?)?
            .ok_or(JournalStoreError::Unavailable)?;
        if Some(entry.id()) != claim.ordered().head
            || entry.index != claim.ordered().index
            || entry.genesis != claim.genesis()
            || entry.input.runtime != *claim.runtime()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok((claim.clone(), entry))
    }

    /// Authenticate a strict current external projection, not a retained old
    /// anchor with merely smaller indexes. The per-open pin supplies physical
    /// root availability; this check binds its exact state to either the
    /// installed common QC/local binding or an actually applied current row.
    #[cfg(feature = "experimental-state-blocks")]
    fn current_external_ordered_claim(
        &self,
    ) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        let owner = self
            .external
            .as_ref()
            .ok_or(SharedJournalDriverError::InvalidProfile)?;
        let validate = || {
            owner
                .availability
                .require_current(&self.store, &self.materialization)?;
            let claim = self.snapshot_boundary_claim()?;
            let heads = self.materialization.heads();
            let committee = self.ledger.active_committee()?;
            if self.store.instance_id() != self.ledger.journal_store()
                || claim.genesis() != owner.genesis.genesis().id()
                || claim.genesis() != heads.genesis
                || claim.admission() != heads.admission
                || claim.space() != heads.runtime.space
                || claim.agent() != heads.runtime.agent
                || claim.runtime() != self.materialization.runtime()
                || claim.committee() != committee.id()
                || claim.ordered() != self.materialization.ordered_base()
                || claim.merge_frontier() != heads.merge_frontier
                || claim.merge_fence() != heads.merge_fence
                || claim.merge_seal() != heads.merge_seal
                || claim.ordered_invocations() != heads.ordered_invocations
                || claim.merge_invocations() != heads.merge_invocations
                || claim.artifacts() != self.materialization.artifacts().id()
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            for (lane, projection) in [
                (PersistedLane::Control, claim.control()),
                (PersistedLane::Linear, claim.linear()),
                (PersistedLane::Merge, claim.merge()),
            ] {
                let bytes = super::replay::state_component(self.materialization.state(), lane);
                let manifest = self
                    .materialization
                    .checkpoint_lane(owner.genesis.genesis(), lane, bytes)
                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
                if manifest.id() != projection.manifest() {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                projection.verify_state(bytes)?;
            }
            if let Some((certificate, binding)) = self.ledger.common_snapshot_authority()?
                && certificate.claim().ordered() == &claim
            {
                certificate.verify(&committee, certificate.claim())?;
                let physical = binding.claim();
                binding.verify(&certificate, physical)?;
                let local = self
                    .materialization
                    .checkpoint_lane(
                        owner.genesis.genesis(),
                        PersistedLane::Local,
                        &self.materialization.state().local,
                    )
                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
                if physical.journal_store().0 != *self.store.instance_id().as_bytes()
                    || physical.local_node() != heads.node
                    || physical.journal_heads() != self.materialization.heads_id()
                    || Some(physical.checkpoint()) != self.materialization.common_checkpoint()
                    || claim.ordered() != self.materialization.replay_boundary()
                    || physical.local_invocations() != heads.local_invocations
                    || physical.local() != local.id()
                {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                return Ok(claim);
            }
            let anchor = self
                .ledger
                .ordered_anchor(claim.raft_index())?
                .filter(|anchor| {
                    anchor.term == claim.raft_term()
                        && anchor.claim == claim.commitment()
                        && Some(anchor.entry) == heads.ordered_head
                })
                .ok_or(JournalStoreError::Unavailable)?;
            let entry = self
                .store
                .get::<OrderedEntry>(anchor.entry)?
                .ok_or(JournalStoreError::Unavailable)?;
            let mut chain = BTreeMap::new();
            chain.insert(anchor.entry, entry);
            validate_ordered_anchor(&self.store, &chain, self.ledger.journal_store(), &anchor)?;
            let binding = self
                .store
                .shared_ordered_commit(anchor.entry)?
                .ok_or(JournalStoreError::Unavailable)?;
            if binding.claim() != &claim {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            Ok(claim)
        };
        // These inputs all originate in this pinned owner, not a peer's
        // requested claim. Missing/corrupt physical metadata cannot leave its
        // cached root-availability capability usable after a failed audit.
        let result = validate();
        if result.is_err() {
            owner.availability.invalidate();
        }
        result
    }

    /// Distinct from historical availability: attest only this exact current
    /// pinned state. A larger applied cursor or an available past claim is not
    /// evidence that peers hold the root used by a retained-result inspection.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn verify_current_ordered_availability(
        &self,
        index: u64,
        term: u64,
        claim: Hash,
    ) -> Result<VerifiedSharedOrderedAvailability, SharedJournalDriverError> {
        if index == 0 || term == 0 || claim == Hash::ZERO {
            return Err(JournalStoreError::Unavailable.into());
        }
        let current = self.current_external_ordered_claim()?;
        if current.raft_index() != index
            || current.raft_term() != term
            || current.commitment() != claim
        {
            return Err(JournalStoreError::Unavailable.into());
        }
        Ok(VerifiedSharedOrderedAvailability {
            _store: self.store.instance_id(),
            _epoch: self.store.validation_epoch(),
            _claim: current,
        })
    }

    /// Acknowledge only an exact V2 anchor from this generation and physical
    /// store. External state additionally requires the per-open audited pin;
    /// every later publication extends it only after durable closure writes.
    pub(crate) fn verify_ordered_availability(
        &self,
        index: u64,
        term: u64,
        claim: Hash,
    ) -> Result<VerifiedSharedOrderedAvailability, SharedJournalDriverError> {
        if index == 0 || term == 0 || claim == Hash::ZERO {
            return Err(JournalStoreError::Unavailable.into());
        }
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &self.external {
            external
                .availability
                .require_current(&self.store, &self.materialization)?;
        }
        let anchor = self
            .ledger
            .ordered_anchor(index)?
            .filter(|anchor| anchor.term == term && anchor.claim == claim);
        let Some(anchor) = anchor else {
            if let Some(bound) = self.available_common_checkpoint_claim(index, term, claim)? {
                return Ok(VerifiedSharedOrderedAvailability {
                    _store: self.store.instance_id(),
                    _epoch: self.store.validation_epoch(),
                    _claim: bound,
                });
            }
            // A voter which has not compacted can hold the identical logical
            // state at a later applied leader-noop foundation. Authenticate
            // its original anchor and the ledger's complete noop-only suffix;
            // an append acknowledgement or a larger raw cursor is insufficient.
            let logical = self.snapshot_boundary_claim()?;
            let context = self.ledger.snapshot_context(&logical)?;
            if context.ordered.raft_index() > logical.raft_index()
                && context.ordered.raft_index() == index
                && context.ordered.raft_term() == term
                && context.ordered.commitment() == claim
            {
                self.verify_ordered_availability(
                    logical.raft_index(),
                    logical.raft_term(),
                    logical.commitment(),
                )?;
                return Ok(VerifiedSharedOrderedAvailability {
                    _store: self.store.instance_id(),
                    _epoch: self.store.validation_epoch(),
                    _claim: context.ordered,
                });
            }
            return Err(JournalStoreError::Unavailable.into());
        };
        let entry = self
            .store
            .get::<OrderedEntry>(anchor.entry)?
            .ok_or(JournalStoreError::Unavailable)?;
        let mut chain = BTreeMap::new();
        chain.insert(anchor.entry, entry);
        validate_ordered_anchor(&self.store, &chain, self.ledger.journal_store(), &anchor)?;
        let binding = self
            .store
            .shared_ordered_commit(anchor.entry)?
            .ok_or(JournalStoreError::Unavailable)?;
        let bound = binding.claim();
        let heads = self.materialization.heads();
        if bound.genesis() != heads.genesis
            || bound.admission() != heads.admission
            || bound.ordered().index > heads.ordered_index
        {
            return Err(JournalStoreError::Unavailable.into());
        }
        Ok(VerifiedSharedOrderedAvailability {
            _store: self.store.instance_id(),
            _epoch: self.store.validation_epoch(),
            _claim: bound.clone(),
        })
    }

    pub(crate) fn snapshot_boundary_claim(
        &self,
    ) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        let heads = self.materialization.heads();
        let entry = heads.ordered_head.ok_or(SharedJournalDriverError::Ledger(
            AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
        ))?;
        let matches_heads = |claim: &OrderedCommitClaim| {
            claim.ordered().head == Some(entry)
                && claim.ordered().index == heads.ordered_index
                && claim.genesis() == heads.genesis
                && claim.admission() == heads.admission
                && claim.runtime() == &heads.runtime
        };
        // Prefer the current verified snapshot when no new logical Ordered
        // transition followed it. Its physical foundation may already be a
        // later leader no-op, and using an older still-retained binding would
        // make the next no-op-only compaction appear to skip its base.
        if let Some(installed) = self.ledger.current_snapshot()?
            && matches_heads(installed.claim.ordered())
        {
            return Ok(installed.claim.ordered().clone());
        }
        let binding = self
            .store
            .shared_ordered_commit(entry)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let claim = binding.claim();
        if !matches_heads(claim) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok(claim.clone())
    }

    fn prepare_snapshot_candidate(
        &mut self,
    ) -> Result<
        (
            super::replay::PreparedSharedCheckpoint,
            SharedAgentSnapshotClaim,
        ),
        SharedJournalDriverError,
    > {
        // External roots are admitted only by the paired common certificate
        // path, never by the Agent-specific image checkpoint interface.
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        self.prepare_snapshot_candidate_inner()
    }

    fn prepare_common_snapshot_candidate(
        &mut self,
        initial: &RuntimeState,
    ) -> Result<
        (
            super::replay::PreparedSharedCheckpoint,
            SharedAgentSnapshotClaim,
        ),
        SharedJournalDriverError,
    > {
        let (plan, claim, _) = self.prepare_common_snapshot_candidate_with_recovery(initial)?;
        Ok((plan, claim))
    }

    fn prepare_common_snapshot_candidate_with_recovery(
        &mut self,
        initial: &RuntimeState,
    ) -> Result<
        (
            super::replay::PreparedSharedCheckpoint,
            SharedAgentSnapshotClaim,
            Option<SharedRecoveryManifest>,
        ),
        SharedJournalDriverError,
    > {
        self.require_common_snapshot_profile(initial)?;
        self.prepare_snapshot_candidate_inner_with_recovery()
    }

    fn prepare_snapshot_candidate_inner(
        &mut self,
    ) -> Result<
        (
            super::replay::PreparedSharedCheckpoint,
            SharedAgentSnapshotClaim,
        ),
        SharedJournalDriverError,
    > {
        let (plan, claim, _) = self.prepare_snapshot_candidate_inner_with_recovery()?;
        Ok((plan, claim))
    }

    fn prepare_snapshot_candidate_inner_with_recovery(
        &mut self,
    ) -> Result<
        (
            super::replay::PreparedSharedCheckpoint,
            SharedAgentSnapshotClaim,
            Option<SharedRecoveryManifest>,
        ),
        SharedJournalDriverError,
    > {
        let heads = self.materialization.heads();
        let entry = heads.ordered_head.ok_or(SharedJournalDriverError::Ledger(
            AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
        ))?;
        let binding = self.store.shared_ordered_commit(entry)?;
        let context = self
            .ledger
            .snapshot_candidate_context(heads, binding.as_ref().map(|binding| binding.claim()))?;
        validate_recovery_replay_evidence(&context.recovery_replay_evidence, |entry, input| {
            self.executor.clean_ordered_result_at(entry, input)
        })?;
        let plan = prepare_shared_checkpoint(&mut self.store, &self.materialization)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        #[cfg(feature = "experimental-state-blocks")]
        let plan = if let Some(external) = &self.external {
            plan.audit_external_shared(
                &mut self.store,
                &external.genesis,
                &external.availability,
                &mut Self::external_recovery_budget(),
            )?
        } else {
            plan
        };
        let (control, linear, merge, local) = plan
            .lane_roots()
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let next = plan.next_heads();
        let claim = SharedAgentSnapshotClaim::new(
            context.ordered,
            context.active_committee,
            context.authority_epoch,
            Hash(*self.store.instance_id().as_bytes()),
            context.boundary_payload_commitment,
            context.ordered_successor,
            plan.predecessor_heads(),
            next.id(),
            plan.checkpoint().manifest().id(),
            next.node,
            control,
            linear,
            merge,
            local,
            next.ordered_invocations,
            next.merge_invocations,
            next.local_invocations,
            plan.checkpoint().manifest().artifacts,
            context.retired_audit_root,
            context.committee_evidence_root,
            context.previous_snapshot,
        )?;
        plan.validate_claim(&claim)?;
        // Carry the owned manifest from this exact audited physical prefix.
        // Preparation stages only immutable checkpoint/proof objects; it does
        // not change materialization, live custody, or any ledger cursor.
        Ok((plan, claim, context.recovery_manifest))
    }

    /// Return the exact unsigned checkpoint claim. This may stage immutable
    /// proof-compaction objects, but no lane blob, journal head, audit row, or
    /// Raft scalar is changed until a voter-majority certificate is returned.
    pub(crate) fn snapshot_candidate(
        &mut self,
    ) -> Result<SharedAgentSnapshotClaim, SharedJournalDriverError> {
        if self.ledger.recovery_manifest_if_present()?.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        self.prepare_snapshot_candidate().map(|(_, claim)| claim)
    }

    pub(crate) fn common_snapshot_candidate(
        &mut self,
        initial: &RuntimeState,
    ) -> Result<
        (
            SharedAgentCommonSnapshotClaim,
            SharedAgentSnapshotClaim,
            super::journal::JournalHeads,
        ),
        SharedJournalDriverError,
    > {
        let (plan, physical, recovery) =
            self.prepare_common_snapshot_candidate_with_recovery(initial)?;
        plan.validate_common_claim(&physical)?;
        let mut common = SharedAgentCommonSnapshotClaim::new(
            physical.ordered().clone(),
            physical.active_committee().clone(),
            physical.authority_epoch(),
            self.materialization.common_snapshot_ancestry()?,
        )?;
        // Keep every driver provenance check, but do not decode the same live
        // manifest again after the audited candidate context supplied it. The
        // mutable driver remains borrowed throughout; no peer I/O or durable
        // publication occurs between these checks.
        if let Some(manifest) = self.verified_recovery_manifest_from_read(recovery)? {
            common = common.with_recovery_manifest(manifest.commitment())?;
        }
        Ok((common, physical, plan.next_heads().clone()))
    }

    pub(crate) fn require_common_snapshot_profile(
        &self,
        initial: &RuntimeState,
    ) -> Result<(), SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &self.external {
            if initial != external.genesis.post_create()
                || !super::replay::validates_shared_create_committee(
                    &external.genesis.genesis().create,
                    &self.ledger.active_committee()?,
                )
            {
                return Err(SharedJournalDriverError::InvalidProfile);
            }
            external
                .availability
                .require_current(&self.store, &self.materialization)?;
            return super::replay::validate_external_common_checkpoint_profile(
                &self.store,
                &self.materialization,
                &external.genesis,
            )
            .map_err(|error| {
                // Physical profile metadata is part of the serving closure.
                // A failed read must revoke the pin before candidate staging,
                // just as the subsequent external root audit does.
                if matches!(
                    error,
                    JournalStoreError::MissingObject
                        | JournalStoreError::Corrupt
                        | JournalStoreError::Unavailable
                        | JournalStoreError::NonCanonical
                ) {
                    external.availability.invalidate();
                }
                error.into()
            });
        }
        super::replay::validate_common_checkpoint_profile(
            &self.store,
            &self.materialization,
            initial,
        )
        .map_err(Into::into)
    }

    fn validate_published_snapshot(
        &mut self,
        claim: &SharedAgentSnapshotClaim,
    ) -> Result<(), SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &self.external {
            return super::replay::validate_published_external_shared_checkpoint(
                &mut self.store,
                &self.materialization,
                claim,
                &external.genesis,
                &external.availability,
                &mut Self::external_recovery_budget(),
            )
            .map_err(Into::into);
        }
        validate_published_shared_checkpoint(&self.store, &self.materialization, claim)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)
    }

    pub(crate) fn install_common_snapshot(
        &mut self,
        certificate: &SharedAgentCommonSnapshotCertificate,
        binding: &SharedAgentLocalSnapshotBinding,
        initial: &RuntimeState,
    ) -> Result<InstalledAgentRaftSnapshotV2, SharedJournalDriverError> {
        self.install_common_snapshot_inner(certificate, binding, initial, false)
    }

    #[cfg(test)]
    pub(crate) fn install_common_snapshot_through_journal_for_test(
        &mut self,
        certificate: &SharedAgentCommonSnapshotCertificate,
        binding: &SharedAgentLocalSnapshotBinding,
        initial: &RuntimeState,
    ) -> Result<InstalledAgentRaftSnapshotV2, SharedJournalDriverError> {
        self.install_common_snapshot_inner(certificate, binding, initial, true)
    }

    fn install_common_snapshot_inner(
        &mut self,
        certificate: &SharedAgentCommonSnapshotCertificate,
        binding: &SharedAgentLocalSnapshotBinding,
        initial: &RuntimeState,
        stop_after_journal: bool,
    ) -> Result<InstalledAgentRaftSnapshotV2, SharedJournalDriverError> {
        self.require_common_snapshot_profile(initial)?;
        if let Some(installed) = self.ledger.current_snapshot()?
            && installed.certificate_commitment == binding.commitment()
        {
            binding.verify(certificate, &installed.claim)?;
            self.validate_published_snapshot(&installed.claim)?;
            return self
                .ledger
                .install_common_snapshot(certificate, binding, None)
                .map_err(Into::into);
        }
        let logical = self.snapshot_boundary_claim()?;
        let recovery = self.verified_recovery_manifest()?;
        if certificate.claim().recovery_manifest()
            != recovery.as_ref().map(SharedRecoveryManifest::commitment)
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        if self.materialization.heads_id() == binding.claim().journal_heads() {
            // Journal-first recovery may only complete the exact signed local
            // binding, never reconstruct a different successor checkpoint.
            self.validate_published_snapshot(binding.claim())?;
            binding.verify(certificate, binding.claim())?;
        } else {
            let (plan, expected) = self.prepare_common_snapshot_candidate(initial)?;
            plan.validate_common_claim(&expected)?;
            let verified = binding.verify(certificate, &expected)?;
            #[cfg(feature = "experimental-state-blocks")]
            let published = if let Some(external) = &mut self.external {
                plan.publish_external_shared(
                    &mut self.store,
                    &verified,
                    &external.genesis,
                    &mut external.availability,
                    &mut Self::external_recovery_budget(),
                )?
            } else {
                plan.publish_shared(&mut self.store, &verified)?
            };
            #[cfg(not(feature = "experimental-state-blocks"))]
            let published = plan.publish_shared(&mut self.store, &verified)?;
            self.materialization = published;
        }
        super::replay::seed_common_checkpoint_ancestry(
            &mut self.materialization,
            certificate,
            binding,
        )?;
        if stop_after_journal {
            return Err(JournalStoreError::Unavailable.into());
        }
        self.ledger
            .install_common_snapshot(certificate, binding, Some(&logical))
            .map_err(Into::into)
    }

    pub(crate) fn common_snapshot_authority(
        &self,
    ) -> Result<
        Option<(
            SharedAgentCommonSnapshotCertificate,
            SharedAgentLocalSnapshotBinding,
        )>,
        SharedJournalDriverError,
    > {
        self.ledger.common_snapshot_authority().map_err(Into::into)
    }

    /// Stream storage content only from an exactly installed, detached-owner
    /// common boundary. The report is not portable authority or availability.
    #[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
    pub(crate) fn export_external_common_checkpoint_archive<W: std::io::Write>(
        &mut self,
        limits: super::journal_store::ExternalArchiveLimits,
        output: &mut W,
    ) -> Result<super::journal_store::ExternalArchiveReport, SharedJournalDriverError> {
        let result = (|| {
            let authority = self.require_external_archive_checkpoint()?;
            let expected = self.materialization.heads_id();
            let external = self
                .external
                .as_ref()
                .ok_or(SharedJournalDriverError::InvalidProfile)?;
            let report = super::journal_store::export_external_journal_checkpoint(
                &mut self.store,
                &external.genesis,
                expected,
                limits,
                &mut Self::external_recovery_budget(),
                output,
            )?;
            if report.source_heads != *self.materialization.heads()
                || report.source_heads.id() != expected
                || self.require_external_archive_checkpoint()? != authority
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            Ok(report)
        })();
        // Quota refusal and a legitimately newer boundary do not damage a
        // healthy pin. Physical/export I/O and mismatched durable metadata do;
        // even an output failure conservatively requires a fresh owner audit.
        if let Err(error) = &result
            && !matches!(
                error,
                SharedJournalDriverError::InvalidProfile
                    | SharedJournalDriverError::Store(
                        JournalStoreError::LimitExceeded | JournalStoreError::Backpressure
                    )
                    | SharedJournalDriverError::Ledger(
                        AgentRaftApplicationErrorV2::SnapshotBoundaryRequired
                    )
            )
            && let Some(external) = &self.external
        {
            external.availability.invalidate();
        }
        result
    }

    #[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
    fn require_external_archive_checkpoint(
        &mut self,
    ) -> Result<
        (
            SharedAgentCommonSnapshotCertificate,
            SharedAgentLocalSnapshotBinding,
        ),
        SharedJournalDriverError,
    > {
        let genesis = Arc::clone(
            &self
                .external
                .as_ref()
                .ok_or(SharedJournalDriverError::InvalidProfile)?
                .genesis,
        );
        self.require_common_snapshot_profile(genesis.post_create())?;
        let committee = self.ledger.active_committee()?;
        if committee.members().len() != 3
            || committee.voter_count() != 3
            || self.ledger.pending_transition()?.is_some()
        {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        let (certificate, binding) = self
            .ledger
            .common_snapshot_authority()?
            .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?;
        let physical = binding.claim();
        let (applied, _, reserved) = self.ledger.capacity()?;
        if physical.journal_heads() != self.materialization.heads_id()
            || Some(physical.checkpoint()) != self.materialization.common_checkpoint()
            || certificate.claim().ordered().ordered() != self.materialization.replay_boundary()
            || certificate.claim().ordered().ordered() != self.materialization.ordered_base()
            || applied != certificate.claim().ordered().raft_index()
            || reserved
        {
            // Neither an evolved journal suffix nor a newer Raft no-op may
            // substitute its foundation for this exact installed authority.
            return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired.into());
        }
        certificate.verify(&committee, certificate.claim())?;
        binding.verify(&certificate, physical)?;
        if certificate.claim().active_committee() != &committee
            || certificate.claim().authority_epoch() != self.ledger.authority_epoch()?
            || certificate.claim().ordered() != &self.current_external_ordered_claim()?
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.validate_published_snapshot(physical)?;
        Ok((certificate, binding))
    }

    /// Publish and install one exact Agent-specific snapshot. The journal CAS
    /// precedes the atomic Raft/audit retirement; restart recognizes the
    /// journal-first intermediate state and accepts only the same certificate.
    pub(crate) fn install_snapshot(
        &mut self,
        certificate: &SharedAgentSnapshotCertificate,
    ) -> Result<InstalledAgentRaftSnapshotV2, SharedJournalDriverError> {
        if self.ledger.recovery_manifest_if_present()?.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        if let Some(installed) = self.ledger.current_snapshot()? {
            if installed.certificate_commitment == certificate.commitment() {
                if installed.claim != *certificate.claim() {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                validate_published_shared_checkpoint(
                    &self.store,
                    &self.materialization,
                    certificate.claim(),
                )
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
                return self
                    .ledger
                    .install_snapshot(certificate, None)
                    .map_err(Into::into);
            }
            // Let the ledger's authenticated snapshot cursor reject lower or
            // equal divergent certificates before preparing or publishing
            // any journal checkpoint material.
            if certificate.claim().raft_index() <= installed.claim.raft_index() {
                return self
                    .ledger
                    .install_snapshot(certificate, None)
                    .map_err(Into::into);
            }
        }

        let logical_ordered = self.snapshot_boundary_claim()?;
        let verified = if self.materialization.heads_id() == certificate.claim().journal_heads() {
            let context = self.ledger.snapshot_context(&logical_ordered)?;
            validate_published_shared_checkpoint(
                &self.store,
                &self.materialization,
                certificate.claim(),
            )
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            let claim = certificate.claim();
            if claim.ordered() != &context.ordered
                || claim.active_committee() != &context.active_committee
                || claim.authority_epoch() != context.authority_epoch
                || claim.journal_store().0 != *self.store.instance_id().as_bytes()
                || claim.boundary_payload_commitment() != context.boundary_payload_commitment
                || claim.ordered_successor() != context.ordered_successor
                || claim.retired_audit_root() != context.retired_audit_root
                || claim.committee_evidence_root() != context.committee_evidence_root
                || claim.previous_snapshot() != context.previous_snapshot
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            certificate.verify(&context.active_committee, claim)?
        } else {
            let (plan, expected) = self.prepare_snapshot_candidate()?;
            let active = expected.active_committee().clone();
            let verified = certificate.verify(&active, &expected)?;
            let successor = plan.publish_shared(&mut self.store, &verified)?;
            self.materialization = successor;
            verified
        };
        if verified.claim() != certificate.claim() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.ledger
            .install_snapshot(certificate, Some(&logical_ordered))
            .map_err(Into::into)
    }

    pub(crate) fn current_snapshot(
        &self,
    ) -> Result<Option<InstalledAgentRaftSnapshotV2>, SharedJournalDriverError> {
        self.ledger.current_snapshot().map_err(Into::into)
    }

    /// Candidate-only ordinary external maintenance. Transport and pending
    /// host markers must be excluded by the detached lifecycle owner.
    #[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
    pub(crate) fn compact_external_common_checkpoint(
        &mut self,
        maximum_binding_unlinks: usize,
        gc_limits: GcLimits,
    ) -> Result<SharedSnapshotCompactionOutcome, SharedJournalDriverError> {
        if maximum_binding_unlinks == 0 {
            return Err(JournalStoreError::LimitExceeded.into());
        }
        validate_gc_limits(gc_limits)?;
        let result = (|| {
            let authority = self.require_external_archive_checkpoint()?;
            let snapshot = self
                .ledger
                .validate_common_reclamation(&authority.0, &authority.1)?;
            let expected = self.materialization.heads_id();
            let genesis = Arc::clone(
                &self
                    .external
                    .as_ref()
                    .ok_or(SharedJournalDriverError::InvalidProfile)?
                    .genesis,
            );
            // Authenticate the complete mark, named retirements and bounded
            // filesystem scan before the first authority binding unlink.
            self.store.preflight_external_genesis_checkpoint_garbage(
                &genesis,
                expected,
                gc_limits,
                &mut Self::external_recovery_budget(),
            )?;
            let bindings = self
                .store
                .retire_shared_ordered_commits(&snapshot, maximum_binding_unlinks)?;
            let journal = if bindings.remaining == 0 {
                Some(self.store.collect_external_genesis_checkpoint_garbage(
                    &genesis,
                    expected,
                    gc_limits,
                    &mut Self::external_recovery_budget(),
                )?)
            } else {
                None
            };
            if self.materialization.heads_id() != expected
                || self.require_external_archive_checkpoint()? != authority
                || self
                    .ledger
                    .validate_common_reclamation(&authority.0, &authority.1)?
                    != snapshot
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            Ok(SharedSnapshotCompactionOutcome {
                bindings_removed: bindings.removed,
                bindings_remaining: bindings.remaining,
                journal,
            })
        })();
        // A physical failure or ambiguous unlink revokes cached availability.
        // Quota/profile/stale-boundary refusal does not damage healthy roots.
        if let Err(error) = &result
            && !matches!(
                error,
                SharedJournalDriverError::InvalidProfile
                    | SharedJournalDriverError::Store(
                        JournalStoreError::LimitExceeded | JournalStoreError::Backpressure
                    )
                    | SharedJournalDriverError::Ledger(
                        AgentRaftApplicationErrorV2::SnapshotBoundaryRequired
                    )
            )
            && let Some(external) = &self.external
        {
            external.availability.invalidate();
        }
        result
    }

    pub(crate) fn compact_snapshot(
        &mut self,
        maximum_binding_unlinks: usize,
        gc_limits: GcLimits,
    ) -> Result<SharedSnapshotCompactionOutcome, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        if maximum_binding_unlinks == 0 {
            return Err(JournalStoreError::LimitExceeded.into());
        }
        // Validate every caller-selected budget before retiring authority
        // bindings. A rejected pass must leave both namespaces untouched.
        validate_gc_limits(gc_limits)?;
        let snapshot = self
            .ledger
            .current_snapshot()?
            .ok_or(SharedJournalDriverError::Ledger(
                AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
            ))?;
        validate_published_shared_checkpoint(&self.store, &self.materialization, &snapshot.claim)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let bindings = self
            .store
            .retire_shared_ordered_commits(&snapshot, maximum_binding_unlinks)?;
        let journal = if bindings.remaining == 0 {
            Some(
                self.store
                    .collect_garbage(self.materialization.heads_id(), gc_limits)?,
            )
        } else {
            None
        };
        Ok(SharedSnapshotCompactionOutcome {
            bindings_removed: bindings.removed,
            bindings_remaining: bindings.remaining,
            journal,
        })
    }

    /// Apply one authenticated causal event without crossing Raft. Replay
    /// enforces the exact Merge lane, author signature, parent closure, and
    /// ordered-base dependency before the journal head moves.
    pub(crate) fn import_merge(
        &mut self,
        event: &MergeEvent,
    ) -> Result<SharedPhysicalApplyOutcome, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        let active = self.ledger.active_committee()?;
        if event.committee != Some(active.id()) || active.member_by_node(event.author).is_none() {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        let index = self.materialization.heads().ordered_index;
        match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            event,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
                Ok(SharedPhysicalApplyOutcome::Applied { index })
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                Ok(SharedPhysicalApplyOutcome::Duplicate { index })
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn stage_next_ordered_before_heads_for_test(
        &mut self,
        include_anchor: bool,
    ) -> Result<(), SharedJournalDriverError> {
        let Some(CommittedSharedRaftSlot::Command(command)) = self.ledger.next_committed_slot()?
        else {
            panic!("fixture requires an Ordered command");
        };
        let reserved = self.ledger.reserve_command_application(&command)?;
        let committee = self.ledger.active_committee()?;
        let committed =
            CommittedSharedOrdered::from_reserved_raft_application(reserved, &committee, None)
                .expect("valid fixture reservation");
        match prepare_shared_ordered(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            committed,
        )? {
            SharedReplayPreparation::Ready(prepared) => {
                prepared.stage_binding_before_heads_for_test(include_anchor)?;
                Ok(())
            }
            SharedReplayPreparation::AlreadyCommitted { .. } => panic!("fixture already published"),
        }
    }

    #[cfg(test)]
    pub(crate) fn assert_staged_binding_requires_exact_reservation_for_test(&self) {
        for mutation in 0..7 {
            let mut audit = self.ledger.journal_audit().unwrap();
            if mutation == 0 {
                audit.pending_ordered = None;
            } else {
                let pending = audit.pending_ordered.as_mut().unwrap();
                match mutation {
                    1 => pending.ordered_index += 1,
                    2 => pending.ordered_parent = Some(pending.entry),
                    3 => pending.index += 1,
                    4 => pending.term += 1,
                    5 => pending.command_commitment = Hash::ZERO,
                    6 => pending.entry = super::journal::OrderedEntryId([0xa5; 32]),
                    _ => unreachable!(),
                }
            }
            assert!(
                matches!(
                    reconcile_journal_ledger(
                        &self.store,
                        &self.materialization,
                        self.ledger.journal_store(),
                        &audit,
                    ),
                    Err(SharedJournalDriverError::CrossStoreMismatch)
                ),
                "accepted altered pending reservation {mutation}"
            );
        }
    }

    /// Drain exactly one committed physical Raft slot through its typed
    /// storage/replay boundary.
    pub(crate) fn apply_next(
        &mut self,
    ) -> Result<SharedPhysicalApplyOutcome, SharedJournalDriverError> {
        let result = self.apply_next_inner();
        #[cfg(feature = "experimental-state-blocks")]
        if result.is_err()
            && let Some(external) = &self.external
        {
            external.availability.invalidate();
        }
        result
    }

    fn apply_next_inner(&mut self) -> Result<SharedPhysicalApplyOutcome, SharedJournalDriverError> {
        let Some(slot) = self.ledger.next_committed_slot()? else {
            return Ok(SharedPhysicalApplyOutcome::Idle);
        };
        let index = slot.index();
        #[cfg(feature = "std")]
        let diagnostic_enabled = std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some();
        #[cfg(feature = "std")]
        if diagnostic_enabled
            && let CommittedSharedRaftSlot::Command(command) = &slot
            && let AgentRaftCommand::Ordered { route, .. } = command.entry().command()
        {
            tracing::debug!(node = ?self.local_node.0, agent = ?route.agent().0,
                space = ?route.space().0, genesis = ?route.genesis().as_bytes(),
                admission = ?route.admission().as_bytes(), index,
                term = slot.term(), committed = slot.committed_index(),
                phase = "committed_seen", "VOS causal ordered application");
        }
        let outcome = match &slot {
            CommittedSharedRaftSlot::LeaderNoop(_) | CommittedSharedRaftSlot::Configuration(_) => {
                let outcome = match self.ledger.apply_foundation_slot(&slot)? {
                    AgentRaftFoundationApplyOutcomeV2::Applied(_) => {
                        SharedPhysicalApplyOutcome::Applied { index }
                    }
                    AgentRaftFoundationApplyOutcomeV2::Duplicate(_) => {
                        SharedPhysicalApplyOutcome::Duplicate { index }
                    }
                };
                if matches!(&slot, CommittedSharedRaftSlot::LeaderNoop(_)) {
                    // A no-op cannot add or activate a committee. Retain the
                    // complete recovery audit, but avoid a second suffix scan
                    // and rebuilding the unchanged executor history.
                    self.ledger.audit_recovery()?;
                } else {
                    self.executor
                        .replace_shared_committees(self.ledger.committee_history()?);
                }
                outcome
            }
            CommittedSharedRaftSlot::Command(command)
                if matches!(
                    command.entry().command(),
                    AgentRaftCommand::PrepareCommitteeChange(_)
                        | AgentRaftCommand::RegisterManagementRecovery { .. }
                        | AgentRaftCommand::ReleaseManagementRecovery { .. }
                ) =>
            {
                if let AgentRaftCommand::RegisterManagementRecovery { registration, .. } =
                    command.entry().command()
                {
                    self.validate_management_registration_runtime(registration.request())?;
                }
                let outcome = match self.ledger.apply_foundation_slot(&slot)? {
                    AgentRaftFoundationApplyOutcomeV2::Applied(_) => {
                        SharedPhysicalApplyOutcome::Applied { index }
                    }
                    AgentRaftFoundationApplyOutcomeV2::Duplicate(_) => {
                        SharedPhysicalApplyOutcome::Duplicate { index }
                    }
                };
                if matches!(
                    command.entry().command(),
                    AgentRaftCommand::RegisterManagementRecovery { .. }
                        | AgentRaftCommand::ReleaseManagementRecovery { .. }
                ) {
                    // Registration is fixed-roster metadata: application
                    // requires no pending transition and the initial active
                    // committee, then retains that exact committee state.
                    self.ledger.audit_recovery()?;
                } else {
                    self.executor
                        .replace_shared_committees(self.ledger.committee_history()?);
                }
                outcome
            }
            CommittedSharedRaftSlot::Command(command) => {
                let reserved = self.ledger.reserve_command_application(command)?;
                match command.entry().command() {
                    AgentRaftCommand::ArtifactChunk(chunk) => {
                        self.artifacts.stage(chunk)?;
                        let completion = self.ledger.complete_artifact_command(
                            &reserved,
                            AgentRaftAuditDisposition::ArtifactChunkStored {
                                batch: chunk.batch(),
                                artifact: chunk.artifact().hash,
                                offset: chunk.offset(),
                                chunk: chunk.commitment(),
                            },
                        )?;
                        command_outcome(completion, index)
                    }
                    AgentRaftCommand::ArtifactAbort { route, batch } => {
                        self.artifacts.abort(*route, *batch)?;
                        let completion = self.ledger.complete_artifact_command(
                            &reserved,
                            AgentRaftAuditDisposition::ArtifactBatchAborted { batch: *batch },
                        )?;
                        command_outcome(completion, index)
                    }
                    AgentRaftCommand::Ordered {
                        route,
                        artifact_batch,
                        entry,
                    } => {
                        if let Some(seal) = entry.merge_seal
                            && matches!(entry.input.operation, ReplayOperation::CleanManage { .. })
                            && self.store.get::<super::journal::MergeSeal>(seal)?.is_none()
                        {
                            let heads = self.materialization.heads();
                            if entry.genesis != heads.genesis
                                || entry.input.runtime != heads.runtime
                                || entry.parent != heads.ordered_head
                                || heads.ordered_index.checked_add(1) != Some(entry.index)
                                || entry.merge_frontier != heads.merge_frontier
                            {
                                return Err(SharedJournalDriverError::CrossStoreMismatch);
                            }
                            self.stage_current_merge_seal_matching(Some(seal))?;
                        }
                        let expected_clean_artifacts =
                            clean_management_artifact_references(&entry.input.operation);
                        if let Some(expected) = &expected_clean_artifacts {
                            if expected.is_empty() && artifact_batch.is_some() {
                                return Err(SharedJournalDriverError::InvalidArtifactBatch);
                            }
                            if !expected.is_empty() && artifact_batch.is_none() {
                                for reference in expected {
                                    let bytes = self
                                        .store
                                        .load_blob(JournalBlobClass::CatalogArtifact, reference)?
                                        .ok_or(SharedJournalDriverError::InvalidArtifactBatch)?;
                                    if BlobRef::of_bytes(&bytes) != *reference {
                                        return Err(SharedJournalDriverError::InvalidArtifactBatch);
                                    }
                                }
                            }
                        }
                        let validated_batch = if let Some(batch) = artifact_batch {
                            let (manifest, blobs) = self.artifacts.load_complete(*route, *batch)?;
                            validate_complete_batch(*route, *batch, &manifest, &blobs)?;
                            if expected_clean_artifacts
                                .as_ref()
                                .is_some_and(|expected| manifest.artifacts() != expected)
                            {
                                return Err(SharedJournalDriverError::InvalidArtifactBatch);
                            }
                            for blob in blobs {
                                self.store.put_blob(
                                    JournalBlobClass::CatalogArtifact,
                                    &blob.reference,
                                    &blob.bytes,
                                )?;
                            }
                            self.executor
                                .replace_resolver(self.store.catalog_blob_resolver()?);
                            Some(ValidatedSharedArtifactBatch::new(*route, *batch))
                        } else {
                            None
                        };
                        let committee = self.ledger.active_committee()?;
                        let committed = CommittedSharedOrdered::from_reserved_raft_application(
                            reserved,
                            &committee,
                            validated_batch,
                        )
                        .map_err(|error| {
                            SharedJournalDriverError::Replay(
                                error
                                    .map_source(|never| match never {})
                                    .map_executor(|never| match never {}),
                            )
                        })?;
                        #[cfg(feature = "experimental-state-blocks")]
                        let external_publication = self.external.is_some();
                        #[cfg(feature = "experimental-state-blocks")]
                        let preparation = if let Some(external) = &mut self.external {
                            super::replay::prepare_external_shared_ordered(
                                &mut self.store,
                                &mut self.executor,
                                &NoPrunedOrderedBases,
                                &self.materialization,
                                committed,
                                &mut external.availability,
                                Self::external_operation_budget(),
                            )?
                        } else {
                            prepare_shared_ordered(
                                &mut self.store,
                                &mut self.executor,
                                &NoPrunedOrderedBases,
                                &self.materialization,
                                committed,
                            )?
                        };
                        #[cfg(not(feature = "experimental-state-blocks"))]
                        let preparation = prepare_shared_ordered(
                            &mut self.store,
                            &mut self.executor,
                            &NoPrunedOrderedBases,
                            &self.materialization,
                            committed,
                        )?;
                        let published = match preparation {
                            SharedReplayPreparation::Ready(prepared) => {
                                #[cfg(feature = "experimental-state-blocks")]
                                let (_, successor, _, publication) = if external_publication {
                                    prepared.publish_external_shared()?
                                } else {
                                    prepared.publish_shared()?
                                };
                                #[cfg(not(feature = "experimental-state-blocks"))]
                                let (_, successor, _, publication) = prepared.publish_shared()?;
                                self.materialization = successor;
                                publication
                            }
                            SharedReplayPreparation::AlreadyCommitted { publication, .. } => {
                                publication
                            }
                        };
                        #[cfg(feature = "std")]
                        let mut diagnostic_input = None;
                        let observation = if self.ledger.recovery_input_registered(&entry.input)? {
                            let entry_id = entry.id();
                            let input_id = entry.input.id();
                            let outcome = self
                                .executor
                                .clean_ordered_result_at(entry_id, input_id)
                                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                            #[cfg(feature = "std")]
                            if diagnostic_enabled {
                                diagnostic_input = Some(input_id);
                            }
                            if matches!(
                                outcome,
                                crate::agent_sdk::RuntimeOutcome::Acknowledged(Err(_))
                            ) {
                                // Negative ACKs do not retire custody. Their
                                // exact absence is rechecked against physical
                                // replay on reopen; they are ordinary applies.
                                None
                            } else {
                                Some(
                                    VerifiedSharedRecoveryObservation::from_published(
                                        &published, entry, outcome,
                                    )
                                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?,
                                )
                            }
                        } else {
                            None
                        };
                        let completion = self.ledger.anchor_applied_ordered_with_recovery(
                            published,
                            observation.as_ref(),
                        )?;
                        if let Some(batch) = artifact_batch {
                            self.artifacts.retire(*route, *batch)?;
                        }
                        #[cfg(feature = "std")]
                        if diagnostic_enabled {
                            tracing::debug!(node = ?self.local_node.0, agent = ?route.agent().0,
                                space = ?route.space().0, genesis = ?route.genesis().as_bytes(),
                                admission = ?route.admission().as_bytes(), index,
                                term = slot.term(), committed = slot.committed_index(),
                                input = ?diagnostic_input.map(|input| *input.as_bytes()),
                                phase = "durable_anchor", "VOS causal ordered application");
                        }
                        command_outcome(completion, index)
                    }
                    AgentRaftCommand::PrepareCommitteeChange(_)
                    | AgentRaftCommand::RegisterManagementRecovery { .. }
                    | AgentRaftCommand::ReleaseManagementRecovery { .. } => unreachable!(),
                }
            }
        };
        Ok(outcome)
    }
}

#[cfg(target_os = "linux")]
impl
    SharedJournalAgentDriver<super::journal_store::FileAgentJournalStore, FileSharedArtifactStager>
{
    #[cfg(test)]
    pub(crate) fn assert_terminal_retirement_reuses_manifest_for_test(
        &mut self,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
        expected_entries: usize,
        check_corruption: bool,
    ) {
        use redb::ReadableTable as _;

        let heads = self.store.heads().unwrap();
        let manifest = self.verified_recovery_manifest().unwrap().unwrap();
        for envelope in envelopes {
            let crate::agent_sdk::RuntimeWork::Invoke {
                context,
                invocation,
                authorization,
                ..
            } = envelope
            else {
                panic!("genuine completed management Invoke");
            };
            let first = exact_retained_management_member(&manifest, None, envelope)
                .unwrap()
                .unwrap()
                .invoke()
                .unwrap();
            let reads = self.ledger.common_candidate_reads_for_test().1;
            let recovered = self
                .replay_durable_clean_terminal(CleanInvocationReplayRequest::Invoke {
                    context: *context,
                    work: (**invocation).clone(),
                    authorization: (**authorization).clone(),
                })
                .unwrap();
            assert_eq!(recovered, *first.outcome());
            assert_eq!(
                self.ledger.common_candidate_reads_for_test().1 - reads,
                1,
                "one exact terminal check must verify one fresh live manifest"
            );
        }
        let reads = self.ledger.common_candidate_reads_for_test().1;
        assert_eq!(
            self.management_retirement_admission_requirement(envelopes)
                .unwrap(),
            Some(expected_entries)
        );
        assert_eq!(
            self.ledger.common_candidate_reads_for_test().1 - reads,
            1,
            "one two-envelope retirement calculation must verify one fresh live manifest"
        );
        assert!(
            self.management_retirement_set_admission_requirement(&[envelopes[0], envelopes[0]])
                .is_err(),
            "one retained capsule cannot evidence duplicate members"
        );
        let mut changed = (*envelopes[1]).clone();
        let crate::agent_sdk::RuntimeWork::Invoke { observed_slot, .. } = &mut changed else {
            unreachable!()
        };
        *observed_slot += 1;
        assert!(
            self.management_retirement_admission_requirement([envelopes[0], &changed])
                .is_err(),
            "an immutable preflight substitution cannot borrow a retained first result"
        );

        if check_corruption {
            // This is the actual current generation's existing ledger table,
            // not an alternate manifest source or a mocked verification count.
            // The caller holds the real host mutex, excluding every applied
            // manifest writer throughout corruption, refusal and restoration.
            let database = self.ledger.database();
            let table: redb::TableDefinition<&[u8], &[u8]> =
                redb::TableDefinition::new("agent_shared_raft_recovery_manifest_v2");
            let (key, original) = {
                let transaction = database.begin_read().unwrap();
                let table = transaction.open_table(table).unwrap();
                let mut rows = table.iter().unwrap();
                let (key, value) = rows.next().unwrap().unwrap();
                let row = (key.value().to_vec(), value.value().to_vec());
                assert!(rows.next().is_none());
                row
            };
            let write = |bytes: &[u8]| {
                let transaction = database.begin_write().unwrap();
                transaction
                    .open_table(table)
                    .unwrap()
                    .insert(key.as_slice(), bytes)
                    .unwrap();
                transaction.commit().unwrap();
            };
            let crate::agent_sdk::RuntimeWork::Invoke {
                context,
                invocation,
                authorization,
                ..
            } = envelopes[0]
            else {
                unreachable!()
            };
            write(&[0]);
            let reads = self.ledger.common_candidate_reads_for_test().1;
            let terminal =
                self.replay_durable_clean_terminal(CleanInvocationReplayRequest::Invoke {
                    context: *context,
                    work: (**invocation).clone(),
                    authorization: (**authorization).clone(),
                });
            let retirement = self.management_retirement_admission_requirement(envelopes);
            let stored = {
                let transaction = database.begin_read().unwrap();
                transaction
                    .open_table(table)
                    .unwrap()
                    .get(key.as_slice())
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_vec()
            };
            // Restore fixture-owned bytes before asserting either refusal,
            // including if the preceding successful calls were incorrectly
            // reused across this deliberately fresh invocation boundary.
            write(&original);
            assert!(matches!(
                terminal,
                Err(SharedJournalDriverError::Ledger(
                    AgentRaftApplicationErrorV2::CorruptLedger
                ))
            ));
            assert!(matches!(
                retirement,
                Err(SharedJournalDriverError::Ledger(
                    AgentRaftApplicationErrorV2::CorruptLedger
                ))
            ));
            assert_eq!(self.ledger.common_candidate_reads_for_test().1 - reads, 2);
            assert_eq!(stored, [0]);
        }
        assert_eq!(self.store.heads().unwrap(), heads);
        assert_eq!(self.verified_recovery_manifest().unwrap(), Some(manifest));
    }

    #[cfg(test)]
    pub(crate) fn assert_management_budget_rechecks_common_closure_for_test(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
    ) {
        use std::io::{Seek as _, SeekFrom};

        assert!(!self.uses_external_state());
        let heads = self.store.heads().unwrap();
        let manifest = self.ledger.recovery_manifest_if_present().unwrap();
        let checkpoint = self
            .store
            .get::<super::journal::CheckpointManifest>(
                self.materialization.common_checkpoint().unwrap(),
            )
            .unwrap()
            .unwrap();
        let closure = self
            .store
            .get::<super::journal::ArtifactClosure>(checkpoint.artifacts)
            .unwrap()
            .unwrap();
        let path = self
            .store
            .root()
            .join("artifact-closures")
            .join(encode_hex(checkpoint.artifacts.as_bytes()));
        let original = fs::read(&path).unwrap();
        assert_eq!(original, closure.encode());
        let offset = original.len().checked_sub(1).unwrap();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write_all(&[original[offset] ^ 1]).unwrap();
        file.sync_all().unwrap();
        let audits_before = self.ledger.common_recovery_audits_for_test();
        let result = self.management_pending_admission_requirement(pending);
        // Restore the exact same fixture-owned inode before asserting even
        // when the real budget refuses the corrupted physical closure.
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write_all(&[original[offset]]).unwrap();
        file.sync_all().unwrap();
        assert!(
            result.is_err(),
            "a previous healthy budget cannot hide fresh closure corruption"
        );
        assert_eq!(
            self.ledger.common_recovery_audits_for_test() - audits_before,
            1
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(self.store.heads().unwrap(), heads);
        assert_eq!(
            self.ledger.recovery_manifest_if_present().unwrap(),
            manifest
        );
    }

    pub(crate) fn portable_checkpoint(
        &self,
        limits: PortableJournalLimits,
    ) -> Result<PortableJournalCheckpoint, SharedJournalDriverError> {
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        export_portable_journal_checkpoint(&self.store, limits).map_err(Into::into)
    }

    pub(crate) fn portable_snapshot_candidate(
        &self,
        genesis_intent: Hash,
        root_pins: Hash,
        limits: PortableJournalLimits,
    ) -> Result<
        (PortableJournalCheckpoint, SharedAgentPortableSnapshotClaim),
        SharedJournalDriverError,
    > {
        if self.ledger.recovery_manifest_if_present()?.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        let installed = self
            .ledger
            .current_snapshot()?
            .ok_or(SharedJournalDriverError::Ledger(
                AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
            ))?;
        validate_published_shared_checkpoint(&self.store, &self.materialization, &installed.claim)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let image = self.portable_checkpoint(limits)?;
        if image.heads().id() != installed.claim.journal_heads() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let physical = installed.claim;
        let claim = SharedAgentPortableSnapshotClaim::new(
            genesis_intent,
            root_pins,
            physical.ordered().clone(),
            physical.active_committee().clone(),
            physical.authority_epoch(),
            physical.ordered_successor(),
            physical.checkpoint_predecessor(),
            physical.journal_heads(),
            physical.checkpoint(),
            physical.local_node(),
            physical.control(),
            physical.linear(),
            physical.merge(),
            physical.local(),
            physical.ordered_invocations(),
            physical.merge_invocations(),
            physical.local_invocations(),
            physical.artifacts(),
            image.commitment(),
        )?;
        validate_portable_materialization(&self.store, &self.materialization, &claim)?;
        Ok((image, claim))
    }

    pub(crate) fn restore_portable_checkpoint(
        &mut self,
        image: &PortableJournalCheckpoint,
        maximum_index_nodes: usize,
        certificate: &SharedAgentPortableSnapshotCertificate,
        verified: &VerifiedSharedAgentPortableSnapshot,
    ) -> Result<(), SharedJournalDriverError> {
        if self.ledger.recovery_manifest_if_present()?.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        #[cfg(feature = "experimental-state-blocks")]
        if self.external.is_some() {
            return Err(JournalStoreError::Unavailable.into());
        }
        if verified.claim() != certificate.claim()
            || verified.certificate_commitment() != certificate.commitment()
            || image.commitment() != certificate.claim().journal_image()
            || image.heads().id() != certificate.claim().journal_heads()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.store
            .install_portable_checkpoint(image, maximum_index_nodes)?;
        self.materialization =
            materialize_current(&mut self.store, &mut self.executor, &NoPrunedOrderedBases)?;
        validate_portable_materialization(&self.store, &self.materialization, certificate.claim())?;
        let installed = self
            .ledger
            .restore_portable_snapshot(certificate, verified)?;
        validate_published_shared_checkpoint(&self.store, &self.materialization, &installed.claim)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let audit = self.ledger.journal_audit()?;
        reconcile_journal_ledger(
            &self.store,
            &self.materialization,
            self.ledger.journal_store(),
            &audit,
        )
    }

    #[cfg(test)]
    pub(crate) fn stage_portable_checkpoint_for_test(
        &mut self,
        image: &PortableJournalCheckpoint,
        maximum_index_nodes: usize,
    ) -> Result<(), SharedJournalDriverError> {
        self.store
            .stage_portable_checkpoint_for_test(image, maximum_index_nodes)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn journal_store_instance_for_test(
        &self,
    ) -> super::shared_raft::JournalStoreInstanceId {
        self.store.instance_id()
    }

    pub(crate) fn create_shared_unexposed<T: super::replay::ReplaySealedOrdinaryGenesis>(
        mut store: super::journal_store::FileAgentJournalStore,
        artifacts: FileSharedArtifactStager,
        ledger: AgentRaftApplicationLedgerV2,
        sealed: &T,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        for blob in catalog {
            store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        store.initialize_shared(sealed)?;
        store.sync_unexposed_generation()?;
        Self::open(store, artifacts, ledger, trust, merge)
    }

    pub(crate) fn open_shared_unexposed(
        store: super::journal_store::FileAgentJournalStore,
        artifacts: FileSharedArtifactStager,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        Self::open(store, artifacts, ledger, trust, merge)
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn create_external_unexposed(
        mut store: super::journal_store::FileAgentJournalStore,
        artifacts: FileSharedArtifactStager,
        ledger: AgentRaftApplicationLedgerV2,
        sealed: Arc<super::replay::ReplaySealedExternalGenesis>,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        if !sealed.is_shared() {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        for blob in catalog {
            store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        store.initialize_external_local(&sealed, &mut Self::external_recovery_budget())?;
        store.sync_unexposed_generation()?;
        Self::open_external(store, artifacts, ledger, trust, merge, sealed)
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn commit_external_genesis_exposure(
        &mut self,
        sealed: &super::replay::ReplaySealedExternalGenesis,
        intent: crate::service::Hash,
    ) -> Result<(), SharedJournalDriverError> {
        let external = self
            .external
            .as_ref()
            .ok_or(SharedJournalDriverError::InvalidProfile)?;
        if external.genesis.genesis() != sealed.genesis() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        external
            .availability
            .require_current(&self.store, &self.materialization)?;
        self.store.commit_external_genesis_exposure(
            sealed,
            intent,
            &mut Self::external_recovery_budget(),
        )?;
        Ok(())
    }

    pub(crate) fn commit_exposure<T: super::replay::ReplaySealedOrdinaryGenesis>(
        &mut self,
        sealed: &T,
        intent: crate::service::Hash,
    ) -> Result<(), SharedJournalDriverError> {
        self.store.commit_shared_exposure(sealed, intent)?;
        Ok(())
    }
}

fn command_outcome(
    outcome: super::shared_raft::AgentRaftCommandApplyOutcomeV2,
    index: u64,
) -> SharedPhysicalApplyOutcome {
    match outcome {
        super::shared_raft::AgentRaftCommandApplyOutcomeV2::Applied(_) => {
            SharedPhysicalApplyOutcome::Applied { index }
        }
        super::shared_raft::AgentRaftCommandApplyOutcomeV2::Duplicate(_) => {
            SharedPhysicalApplyOutcome::Duplicate { index }
        }
    }
}

/// Reconstruct a portable image in an independent in-memory journal before
/// any destination namespace is created. This repeats package trust and exact
/// replay over the same typed store API used on restart.
pub(crate) fn preflight_portable_checkpoint<T: super::replay::ReplaySealedOrdinaryGenesis>(
    sealed: &T,
    catalog: &[RuntimeBlob],
    image: &PortableJournalCheckpoint,
    claim: &super::shared_commit::SharedAgentPortableSnapshotClaim,
    maximum_index_nodes: usize,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    committee: super::genesis::AgentReplicaCommittee,
) -> Result<ReplayMaterialization, SharedJournalDriverError> {
    if image.commitment() != claim.journal_image() || image.heads().id() != claim.journal_heads() {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    let mut store = MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, merge.node())?;
    for blob in catalog {
        store.put_blob(
            JournalBlobClass::CatalogArtifact,
            &blob.reference,
            &blob.bytes,
        )?;
    }
    store.initialize_shared(sealed)?;
    store.install_portable_checkpoint(image, maximum_index_nodes)?;
    let resolver = store.catalog_blob_resolver()?;
    let mut executor =
        StandardLocalReplayExecutor::new_shared(resolver, trust, merge, vec![committee]);
    let materialization = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
    validate_portable_materialization(&store, &materialization, claim)?;
    Ok(materialization)
}

pub(crate) fn preflight_common_source<T: super::replay::ReplaySealedOrdinaryGenesis>(
    sealed: &T,
    catalog: &[RuntimeBlob],
    image: &PortableJournalCheckpoint,
    claim: &SharedAgentSnapshotClaim,
    maximum_index_nodes: usize,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    committee: super::genesis::AgentReplicaCommittee,
) -> Result<(), SharedJournalDriverError> {
    if image.heads().id() != claim.journal_heads() || merge.node() != claim.local_node() {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    let mut store = MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, merge.node())?;
    for blob in catalog {
        store.put_blob(
            JournalBlobClass::CatalogArtifact,
            &blob.reference,
            &blob.bytes,
        )?;
    }
    store.initialize_shared(sealed)?;
    store.install_portable_checkpoint(image, maximum_index_nodes)?;
    let mut executor = StandardLocalReplayExecutor::new_shared(
        store.catalog_blob_resolver()?,
        trust,
        merge,
        vec![committee],
    );
    let materialization = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
    super::replay::validate_common_checkpoint_state(
        &store,
        &materialization,
        claim,
        sealed.post_create(),
    )?;
    Ok(())
}

/// Metadata candidate only, derived from an authenticated foreign archive.
/// Neither this plan nor its unsigned physical claim permits publication or
/// serving. A destination owner must still audit the staged target closure
/// and validate its separately signed local binding before installing it.
#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
pub(crate) struct ReboundExternalCommonCheckpoint {
    archive_identity: Hash,
    scratch_store: super::shared_raft::JournalStoreInstanceId,
    scratch_epoch: u64,
    source_heads: super::journal::JournalHeads,
    source_checkpoint: super::journal::CheckpointId,
    certificate: SharedAgentCommonSnapshotCertificate,
    source_binding: SharedAgentLocalSnapshotBinding,
    destination_store: super::shared_raft::JournalStoreInstanceId,
    destination_epoch: u64,
    predecessor: super::journal::JournalHeads,
    metadata: ExternalCommonCheckpointMetadata,
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
struct ExternalCommonCheckpointMetadata {
    checkpoint: super::journal::CheckpointManifest,
    local: super::journal::LaneStateManifest,
    local_invocations: super::journal::InvocationIndexManifest,
    heads: super::journal::JournalHeads,
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
impl ReboundExternalCommonCheckpoint {
    pub(crate) fn source_heads(&self) -> &super::journal::JournalHeads {
        &self.source_heads
    }

    pub(crate) fn certificate(&self) -> &SharedAgentCommonSnapshotCertificate {
        &self.certificate
    }

    pub(crate) fn source_binding(&self) -> &SharedAgentLocalSnapshotBinding {
        &self.source_binding
    }

    pub(crate) fn checkpoint(&self) -> &super::journal::CheckpointManifest {
        &self.metadata.checkpoint
    }

    pub(crate) fn local_manifest(&self) -> &super::journal::LaneStateManifest {
        &self.metadata.local
    }

    pub(crate) fn local_invocations(&self) -> &super::journal::InvocationIndexManifest {
        &self.metadata.local_invocations
    }

    pub(crate) fn heads(&self) -> &super::journal::JournalHeads {
        &self.metadata.heads
    }

    pub(crate) fn predecessor(&self) -> &super::journal::JournalHeads {
        &self.predecessor
    }

    /// Immutable destination metadata only. The authenticated source closure
    /// and both actual destination endpoints still require auditing before a
    /// separately signed binding can permit publication.
    pub(crate) fn stage_metadata<S: TransitionProofPublicationStore>(
        &self,
        staged: &mut super::journal_store::StagedExternalArchive,
        destination: &mut S,
        sealed: &super::replay::ReplaySealedExternalGenesis,
    ) -> Result<(), SharedJournalDriverError> {
        self.require_current(staged, destination, sealed)?;
        // Root/head validation follows this exact historical envelope even
        // before CAS. Reuse the owner-checked immutable predecessor staging;
        // this does not advance heads or authenticate a foreign predecessor.
        destination.stage_proof_predecessor(&self.predecessor)?;
        destination.put(&self.metadata.local)?;
        destination.put(&self.metadata.local_invocations)?;
        destination.put(&self.metadata.checkpoint)?;
        self.require_current(staged, destination, sealed)
    }

    /// Identity fencing, not renewed proof of the complete block closure.
    /// Final destination validation must repeat the external root audit.
    pub(crate) fn require_current<S: AgentJournalStore>(
        &self,
        staged: &mut super::journal_store::StagedExternalArchive,
        destination: &S,
        sealed: &super::replay::ReplaySealedExternalGenesis,
    ) -> Result<(), SharedJournalDriverError> {
        if staged.report().identity != self.archive_identity
            || staged.instance_id() != self.scratch_store
            || staged.validation_epoch() != self.scratch_epoch
            || staged.report().source_heads != self.source_heads
            || staged.genesis_id() != self.source_heads.genesis
            || destination.instance_id() != self.destination_store
            || destination.validation_epoch() != self.destination_epoch
            || destination.heads()?.as_ref() != Some(&self.predecessor)
            || destination.genesis()?.as_ref() != Some(sealed.genesis())
            || sealed.genesis().id() != self.source_heads.genesis
        {
            return Err(JournalStoreError::ScopeMismatch.into());
        }
        sealed.validate_checkpoint_scope(destination, &self.predecessor)?;
        staged.with_source_view(|view| {
            if view.instance_id() != self.scratch_store
                || view.validation_epoch() != self.scratch_epoch
                || view.heads()?.as_ref() != Some(&self.source_heads)
                || view
                    .get::<super::journal::CheckpointManifest>(self.source_checkpoint)?
                    .is_none()
            {
                return Err(JournalStoreError::ScopeMismatch);
            }
            Ok(())
        })?;
        if destination.validation_epoch() != self.destination_epoch
            || staged.validation_epoch() != self.scratch_epoch
        {
            return Err(JournalStoreError::ScopeMismatch.into());
        }
        Ok(())
    }

    /// Build an unsigned destination candidate using the destination ledger's
    /// foundation. This is deliberately not a verified snapshot capability.
    pub(crate) fn physical_claim(
        &self,
        foundation: &super::shared_raft::CommonSnapshotRestoreFoundation,
    ) -> Result<SharedAgentSnapshotClaim, SharedJournalDriverError> {
        if foundation.local_node != self.metadata.heads.node
            || &foundation.journal_store.0 != self.destination_store.as_bytes()
        {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        let heads = &self.metadata.heads;
        let checkpoint = &self.metadata.checkpoint;
        let common = self.certificate.claim();
        let lane = |kind| {
            checkpoint
                .lanes
                .iter()
                .find(|lane| lane.lane == kind)
                .map(|lane| lane.state)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)
        };
        SharedAgentSnapshotClaim::new(
            common.ordered().clone(),
            common.active_committee().clone(),
            common.authority_epoch(),
            foundation.journal_store,
            foundation.boundary_payload_commitment,
            heads.id(),
            self.predecessor.id(),
            heads.id(),
            checkpoint.id(),
            heads.node,
            lane(PersistedLane::Control)?,
            lane(PersistedLane::Linear)?,
            lane(PersistedLane::Merge)?,
            lane(PersistedLane::Local)?,
            heads.ordered_invocations,
            heads.merge_invocations,
            heads.local_invocations,
            checkpoint.artifacts,
            foundation.retired_audit_root,
            foundation.committee_evidence_root,
            None,
        )
        .map_err(Into::into)
    }
}

/// Rebind bounded metadata only. The source proof is consumed, rather than
/// carrying its runtime-state payloads into the plan. No live destination
/// object, head, checkpoint marker, or serving availability is written here.
#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
pub(crate) fn preflight_external_common_rebind<S: AgentJournalStore>(
    source: super::replay::AuditedExternalArchiveSource,
    staged: &mut super::journal_store::StagedExternalArchive,
    sealed: &super::replay::ReplaySealedExternalGenesis,
    destination: &S,
    predecessor: &super::journal::JournalHeads,
) -> Result<ReboundExternalCommonCheckpoint, SharedJournalDriverError> {
    staged.with_source_view(|view| source.require_source(view))?;
    let initial = sealed
        .initial_heads()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let common = source.certificate().claim();
    let committee = common.active_committee();
    if !sealed.is_shared()
        || committee.members().len() != 3
        || committee.voter_count() != 3
        || committee
            .member_by_node(initial.node)
            .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
        || !sealed.post_create().merge.is_empty()
        || !sealed.post_create().local.is_empty()
        || source.scratch_store() != staged.instance_id()
        || source.scratch_epoch() != staged.validation_epoch()
        || source.source_heads() != &staged.report().source_heads
        || staged.genesis_id() != sealed.genesis().id()
    {
        return Err(JournalStoreError::ScopeMismatch.into());
    }
    let destination_epoch = destination.validation_epoch();
    if destination.heads()?.as_ref() != Some(predecessor) {
        return Err(JournalStoreError::Conflict.into());
    }
    sealed.validate_checkpoint_scope(destination, predecessor)?;
    let metadata = rebind_external_common_metadata(
        &initial,
        source.source_heads(),
        source.checkpoint(),
        predecessor,
        sealed.lane_manifest(PersistedLane::Local),
    )?;
    if metadata.local_invocations != *sealed.local_invocations()
        || destination.validation_epoch() != destination_epoch
    {
        return Err(JournalStoreError::ScopeMismatch.into());
    }
    let rebound = ReboundExternalCommonCheckpoint {
        archive_identity: staged.report().identity,
        scratch_store: source.scratch_store(),
        scratch_epoch: source.scratch_epoch(),
        source_heads: source.source_heads().clone(),
        source_checkpoint: source.checkpoint().id(),
        certificate: source.certificate().clone(),
        source_binding: source.binding().clone(),
        destination_store: destination.instance_id(),
        destination_epoch,
        predecessor: predecessor.clone(),
        metadata,
    };
    rebound.require_current(staged, destination, sealed)?;
    Ok(rebound)
}

#[cfg(all(target_os = "linux", feature = "experimental-state-blocks"))]
fn rebind_external_common_metadata(
    initial: &super::journal::JournalHeads,
    source: &super::journal::JournalHeads,
    checkpoint: &super::journal::CheckpointManifest,
    predecessor: &super::journal::JournalHeads,
    mut local: super::journal::LaneStateManifest,
) -> Result<ExternalCommonCheckpointMetadata, JournalStoreError> {
    use super::journal::{InvocationIndexManifest, InvocationOwnershipScope, LaneCursor};

    for heads in [initial, source, predecessor] {
        heads
            .validate()
            .map_err(|_| JournalStoreError::NonCanonical)?;
    }
    checkpoint
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let local_invocations = InvocationIndexManifest::empty(
        initial.genesis,
        InvocationOwnershipScope::Local(initial.node),
    );
    if !initial.runtime.is_external_state()
        || predecessor.genesis != initial.genesis
        || predecessor.admission != initial.admission
        || predecessor.node != initial.node
        || predecessor.runtime != initial.runtime
        || predecessor.local_revision != 0
        || predecessor.local_head.is_some()
        || predecessor.local_invocations != local_invocations.id()
        || source.genesis != initial.genesis
        || source.admission != initial.admission
        || source.runtime != initial.runtime
        || source.local_revision != 0
        || source.local_head.is_some()
        || source.local_invocations
            != InvocationIndexManifest::empty(
                source.genesis,
                InvocationOwnershipScope::Local(source.node),
            )
            .id()
        || source.merge_frontier != initial.merge_frontier
        || source.merge_invocations != initial.merge_invocations
        || source.ordered_index < predecessor.ordered_index
        || (source.ordered_index == predecessor.ordered_index
            && source.ordered_head != predecessor.ordered_head)
        || source.checkpoint != Some(checkpoint.id())
        || checkpoint.genesis != source.genesis
        || checkpoint.admission != source.admission
        || checkpoint.runtime != source.runtime
        || checkpoint.publication_revision.checked_add(1) != Some(source.publication_revision)
        || checkpoint.ordered_index != source.ordered_index
        || checkpoint.ordered_head != source.ordered_head
        || checkpoint.merge_frontier != source.merge_frontier
        || checkpoint.merge_fence != source.merge_fence
        || checkpoint.merge_seal != source.merge_seal
        || checkpoint.ordered_invocations != source.ordered_invocations
        || checkpoint.merge_invocations != source.merge_invocations
        || checkpoint.transition_proofs != source.transition_proofs
        || checkpoint.lanes.iter().map(|lane| lane.lane).ne([
            PersistedLane::Control,
            PersistedLane::Linear,
            PersistedLane::Merge,
            PersistedLane::Local,
        ])
        || local.genesis != initial.genesis
        || local.lane != PersistedLane::Local
        || local.cursor
            != (LaneCursor::Local {
                node: initial.node,
                revision: 0,
                head: None,
            })
        || local.state != BlobRef::of_bytes(&[])
        || local.external_root.is_some()
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    local.runtime = checkpoint.runtime.clone();
    local
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let mut checkpoint = checkpoint.clone();
    let lane = checkpoint
        .lanes
        .iter_mut()
        .find(|lane| lane.lane == PersistedLane::Local)
        .ok_or(JournalStoreError::ScopeMismatch)?;
    if lane.node != Some(source.node) || lane.invocations != Some(source.local_invocations) {
        return Err(JournalStoreError::ScopeMismatch);
    }
    lane.node = Some(initial.node);
    lane.state = local.id();
    lane.invocations = Some(local_invocations.id());
    checkpoint.publication_revision = predecessor.publication_revision;
    checkpoint
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let mut heads = source.clone();
    heads.node = initial.node;
    heads.local_invocations = local_invocations.id();
    heads.local_head = None;
    heads.local_revision = 0;
    heads.publication_revision = predecessor
        .publication_revision
        .checked_add(1)
        .ok_or(JournalStoreError::LimitExceeded)?;
    heads.previous = Some(predecessor.id());
    heads.checkpoint = Some(checkpoint.id());
    predecessor
        .validate_successor(&heads)
        .map_err(|_| JournalStoreError::NonCanonical)?;
    Ok(ExternalCommonCheckpointMetadata {
        checkpoint,
        local,
        local_invocations,
        heads,
    })
}

pub(crate) struct ReboundCommonCheckpoint {
    store: MemoryAgentJournalStore,
    materialization: ReplayMaterialization,
    image: PortableJournalCheckpoint,
    initial: RuntimeState,
}

impl ReboundCommonCheckpoint {
    pub(crate) fn image(&self) -> &PortableJournalCheckpoint {
        &self.image
    }

    pub(crate) fn physical_claim(
        &self,
        common: &SharedAgentCommonSnapshotClaim,
        foundation: &super::shared_raft::CommonSnapshotRestoreFoundation,
    ) -> Result<SharedAgentSnapshotClaim, SharedJournalDriverError> {
        let heads = self.image.heads();
        let checkpoint = self
            .store
            .get::<super::journal::CheckpointManifest>(
                heads.checkpoint.ok_or(JournalStoreError::Corrupt)?,
            )?
            .ok_or(JournalStoreError::MissingObject)?;
        let lane = |kind| {
            checkpoint
                .lanes
                .iter()
                .find(|lane| lane.lane == kind)
                .map(|lane| lane.state)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)
        };
        let claim = SharedAgentSnapshotClaim::new(
            common.ordered().clone(),
            common.active_committee().clone(),
            common.authority_epoch(),
            foundation.journal_store,
            foundation.boundary_payload_commitment,
            heads.id(),
            heads.previous.ok_or(JournalStoreError::Corrupt)?,
            heads.id(),
            checkpoint.id(),
            heads.node,
            lane(PersistedLane::Control)?,
            lane(PersistedLane::Linear)?,
            lane(PersistedLane::Merge)?,
            lane(PersistedLane::Local)?,
            heads.ordered_invocations,
            heads.merge_invocations,
            heads.local_invocations,
            checkpoint.artifacts,
            foundation.retired_audit_root,
            foundation.committee_evidence_root,
            None,
        )?;
        if foundation.local_node != heads.node {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        super::replay::validate_common_checkpoint_state(
            &self.store,
            &self.materialization,
            &claim,
            &self.initial,
        )?;
        Ok(claim)
    }

    pub(crate) fn validate(
        self,
        verified: super::shared_commit::VerifiedSharedAgentSnapshot,
    ) -> Result<super::replay::ValidatedCommonCheckpoint, SharedJournalDriverError> {
        super::replay::validate_common_checkpoint_image(
            &self.store,
            &self.materialization,
            self.image,
            verified,
            &self.initial,
        )
        .map_err(Into::into)
    }
}

pub(crate) fn preflight_common_rebind<T: super::replay::ReplaySealedOrdinaryGenesis>(
    sealed: &T,
    image: &PortableJournalCheckpoint,
    predecessor: &super::journal::JournalHeads,
    limits: PortableJournalLimits,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    committee: super::genesis::AgentReplicaCommittee,
) -> Result<ReboundCommonCheckpoint, SharedJournalDriverError> {
    let (mut store, image) =
        MemoryAgentJournalStore::rebind_common_checkpoint(sealed, image, predecessor, limits)?;
    let mut executor = StandardLocalReplayExecutor::new_shared(
        store.catalog_blob_resolver()?,
        trust,
        merge,
        vec![committee],
    );
    let materialization = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
    super::replay::validate_common_checkpoint_profile(
        &store,
        &materialization,
        sealed.post_create(),
    )?;
    Ok(ReboundCommonCheckpoint {
        store,
        materialization,
        image,
        initial: sealed.post_create().clone(),
    })
}

fn validate_portable_materialization<S>(
    store: &S,
    materialization: &ReplayMaterialization,
    claim: &super::shared_commit::SharedAgentPortableSnapshotClaim,
) -> Result<(), SharedJournalDriverError>
where
    S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
{
    let commitment = claim.commitment();
    let validation_claim = SharedAgentSnapshotClaim::new(
        claim.ordered().clone(),
        claim.active_committee().clone(),
        claim.authority_epoch(),
        Hash::digest(
            b"vos/agent/shared/portable-validation/store/v1",
            &[&commitment.0],
        ),
        Hash::digest(
            b"vos/agent/shared/portable-validation/foundation/v1",
            &[&commitment.0],
        ),
        claim.ordered_successor(),
        claim.checkpoint_predecessor(),
        claim.journal_heads(),
        claim.checkpoint(),
        claim.local_node(),
        claim.control(),
        claim.linear(),
        claim.merge(),
        claim.local(),
        claim.ordered_invocations(),
        claim.merge_invocations(),
        claim.local_invocations(),
        claim.artifacts(),
        Hash::digest(
            b"vos/agent/shared/portable-validation/retired/v1",
            &[&commitment.0],
        ),
        Hash::digest(
            b"vos/agent/shared/portable-validation/committee/v1",
            &[&commitment.0],
        ),
        None,
    )?;
    validate_published_shared_checkpoint(store, materialization, &validation_claim)
        .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)
}

fn clean_management_artifact_references(operation: &ReplayOperation) -> Option<Vec<BlobRef>> {
    let ReplayOperation::CleanManage { request, .. } = operation else {
        return None;
    };
    let clean = |reference: &crate::agent_sdk::BlobRef| BlobRef {
        hash: Hash(reference.hash.0),
        len: reference.len,
    };
    let mut artifacts = match request {
        crate::agent_sdk::ManagementRequest::Install(install) => {
            let mut artifacts = vec![
                clean(&install.package),
                clean(&install.agent_schema),
                clean(&install.method_policy),
            ];
            if let Some(data) = &install.installation_data {
                artifacts.push(clean(&data.reference));
            }
            artifacts
        }
        crate::agent_sdk::ManagementRequest::UpgradeActor(upgrade) => vec![
            clean(&upgrade.package),
            clean(&upgrade.agent_schema),
            clean(&upgrade.method_policy),
        ],
        crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade) => {
            vec![clean(&upgrade.package)]
        }
        crate::agent_sdk::ManagementRequest::Create(_)
        | crate::agent_sdk::ManagementRequest::InspectActors { .. }
        | crate::agent_sdk::ManagementRequest::InspectResources
        | crate::agent_sdk::ManagementRequest::InspectManagementHistory
        | crate::agent_sdk::ManagementRequest::Suspend { .. }
        | crate::agent_sdk::ManagementRequest::Resume { .. }
        | crate::agent_sdk::ManagementRequest::RemoveLeaf { .. }
        | crate::agent_sdk::ManagementRequest::ChangeReplicas { .. }
        | crate::agent_sdk::ManagementRequest::PrivateControl { .. } => Vec::new(),
    };
    artifacts.sort_by_key(|artifact| artifact.hash);
    artifacts.dedup();
    Some(artifacts)
}

fn validate_complete_batch(
    route: super::shared_raft::AgentRouteKey,
    batch: ArtifactBatchId,
    manifest: &ArtifactBatchManifest,
    blobs: &[RuntimeBlob],
) -> Result<(), SharedJournalDriverError> {
    manifest
        .validate()
        .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
    if manifest.route() != route
        || manifest.id() != batch
        || blobs.len() != manifest.artifacts().len()
    {
        return Err(SharedJournalDriverError::InvalidArtifactBatch);
    }
    for (blob, reference) in blobs.iter().zip(manifest.artifacts()) {
        if &blob.reference != reference
            || !reference.matches(&blob.bytes)
            || reference != &BlobRef::of_bytes(&blob.bytes)
        {
            return Err(SharedJournalDriverError::InvalidArtifactBatch);
        }
    }
    Ok(())
}

fn reconcile_journal_ledger<S: AgentJournalStore + SharedOrderedCommitStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    journal_store: super::shared_raft::JournalStoreInstanceId,
    audit: &AgentRaftJournalAuditV2,
) -> Result<(), SharedJournalDriverError> {
    let heads = materialization.heads();
    let snapshot_base = audit
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.claim.ordered().ordered());
    tracing::debug!(
        ordered_index = heads.ordered_index,
        snapshot_index = snapshot_base.map_or(0, |base| base.index),
        anchors = audit.ordered.len(),
        pending = audit.pending_ordered.is_some(),
        "Reconciling Shared journal ordered bindings"
    );
    let mut chain = BTreeMap::new();
    let mut next = heads.ordered_head;
    let mut expected_index = heads.ordered_index;
    while expected_index > snapshot_base.map_or(0, |base| base.index) {
        let entry_id = next.ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if chain.len() == super::shared_raft::MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let entry = store
            .get::<super::journal::OrderedEntry>(entry_id)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if entry.id() != entry_id
            || entry.genesis != heads.genesis
            || entry.index != expected_index
            || chain.insert(entry_id, entry.clone()).is_some()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        next = entry.parent;
        expected_index = expected_index
            .checked_sub(1)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    }
    let expected_parent = snapshot_base.and_then(|base| base.head);
    if expected_index != snapshot_base.map_or(0, |base| base.index)
        || next != expected_parent
        || chain.len()
            != heads
                .ordered_index
                .saturating_sub(snapshot_base.map_or(0, |base| base.index)) as usize
    {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }

    let mut expected_bindings = BTreeSet::new();
    tracing::debug!(
        entries = chain.len(),
        "Shared reconciliation chain validated"
    );
    for anchor in &audit.ordered {
        validate_ordered_anchor(store, &chain, journal_store, anchor).map_err(|error| {
            tracing::warn!(
                ?error,
                entry = ?anchor.entry,
                raft_index = anchor.index,
                in_chain = chain.contains_key(&anchor.entry),
                "Shared reconciliation ordered anchor failed"
            );
            error
        })?;
        if !expected_bindings.insert(anchor.entry) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
    }
    tracing::debug!("Shared reconciliation ordered anchors validated");
    if let Some(pending) = &audit.pending_ordered {
        match store.shared_ordered_commit(pending.entry)? {
            Some(binding) => {
                validate_pending_binding(heads, &chain, journal_store, pending, &binding).map_err(
                    |error| {
                        tracing::warn!(
                            ?error,
                            entry = ?pending.entry,
                            raft_index = pending.index,
                            in_chain = chain.contains_key(&pending.entry),
                            "Shared reconciliation pending binding failed"
                        );
                        error
                    },
                )?;
                if !expected_bindings.insert(pending.entry) {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
            }
            None if chain.contains_key(&pending.entry) => {
                tracing::warn!("Shared reconciliation pending chain entry has no binding");
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            None => {}
        }
    }
    tracing::debug!("Shared reconciliation pending binding validated");
    let actual = store.shared_ordered_commit_ids()?;
    for entry in &actual {
        if expected_bindings.contains(entry) {
            continue;
        }
        let snapshot = audit
            .snapshot
            .as_ref()
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let binding = store
            .shared_ordered_commit(*entry)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let claim = binding.claim();
        if binding.journal_store() != journal_store
            || claim.space() != snapshot.claim.ordered().space()
            || claim.agent() != snapshot.claim.ordered().agent()
            || claim.genesis() != snapshot.claim.ordered().genesis()
            || claim.admission() != snapshot.claim.ordered().admission()
            || claim.raft_index() > snapshot.claim.raft_index()
            || claim.ordered().index > snapshot.claim.ordered().ordered().index
            || claim.ordered().head != Some(*entry)
        {
            tracing::warn!(
                entry = ?entry,
                same_store = binding.journal_store() == journal_store,
                same_space = claim.space() == snapshot.claim.ordered().space(),
                same_agent = claim.agent() == snapshot.claim.ordered().agent(),
                same_genesis = claim.genesis() == snapshot.claim.ordered().genesis(),
                same_admission = claim.admission() == snapshot.claim.ordered().admission(),
                same_head = claim.ordered().head == Some(*entry),
                binding_raft_index = claim.raft_index(),
                snapshot_raft_index = snapshot.claim.raft_index(),
                binding_ordered_index = claim.ordered().index,
                snapshot_ordered_index = snapshot.claim.ordered().ordered().index,
                "Shared reconciliation extra binding is outside snapshot prefix"
            );
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
    }
    if expected_bindings
        .iter()
        .any(|entry| !actual.contains(entry))
        || chain.keys().any(|entry| !expected_bindings.contains(entry))
    {
        tracing::warn!(
            missing_expected = expected_bindings
                .iter()
                .filter(|entry| !actual.contains(entry))
                .count(),
            missing_chain = chain
                .keys()
                .filter(|entry| !expected_bindings.contains(entry))
                .count(),
            "Shared reconciliation binding coverage failed"
        );
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    Ok(())
}

fn validate_ordered_anchor<S: AgentJournalStore + SharedOrderedCommitStore>(
    store: &S,
    chain: &BTreeMap<super::journal::OrderedEntryId, super::journal::OrderedEntry>,
    journal_store: super::shared_raft::JournalStoreInstanceId,
    anchor: &AgentRaftOrderedJournalAnchorV2,
) -> Result<(), SharedJournalDriverError> {
    let entry = chain
        .get(&anchor.entry)
        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    let binding = store
        .shared_ordered_commit(anchor.entry)?
        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    let claim = binding.claim();
    if entry.id() != anchor.entry
        || binding.journal_store() != journal_store
        || binding.entry() != anchor.entry
        || binding.raft_payload_commitment() != anchor.command_commitment
        || binding.successor() != anchor.successor
        || claim.commitment() != anchor.claim
        || claim.raft_index() != anchor.index
        || claim.raft_term() != anchor.term
        || claim.ordered().head != Some(anchor.entry)
        || claim.ordered().index != entry.index
        || claim.space() != anchor.route.space()
        || claim.agent() != anchor.route.agent()
        || claim.genesis() != anchor.route.genesis()
        || claim.admission() != anchor.route.admission()
        || claim.committee() != anchor.route.committee()
    {
        tracing::warn!(
            same_entry = entry.id() == anchor.entry && binding.entry() == anchor.entry,
            same_store = binding.journal_store() == journal_store,
            same_payload = binding.raft_payload_commitment() == anchor.command_commitment,
            same_successor = binding.successor() == anchor.successor,
            same_claim = claim.commitment() == anchor.claim,
            same_raft_index = claim.raft_index() == anchor.index,
            same_term = claim.raft_term() == anchor.term,
            same_head = claim.ordered().head == Some(anchor.entry),
            same_ordered_index = claim.ordered().index == entry.index,
            same_space = claim.space() == anchor.route.space(),
            same_agent = claim.agent() == anchor.route.agent(),
            same_genesis = claim.genesis() == anchor.route.genesis(),
            same_admission = claim.admission() == anchor.route.admission(),
            same_committee = claim.committee() == anchor.route.committee(),
            "Shared reconciliation ordered anchor fields differ"
        );
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    Ok(())
}

fn validate_pending_binding(
    heads: &super::journal::JournalHeads,
    chain: &BTreeMap<super::journal::OrderedEntryId, super::journal::OrderedEntry>,
    journal_store: super::shared_raft::JournalStoreInstanceId,
    pending: &AgentRaftPendingOrderedV2,
    binding: &super::journal_store::SharedOrderedCommitBinding,
) -> Result<(), SharedJournalDriverError> {
    match chain.get(&pending.entry) {
        Some(entry)
            if entry.index == pending.ordered_index && entry.parent == pending.ordered_parent => {}
        // Shared dependencies are durable before the head CAS, possibly even
        // before the entry file. Only the exact reserved next Ordered command
        // may account for such a binding. It remains pending, not applied;
        // normal replay must reconstruct and publish the exact binding later.
        None if heads.ordered_index.checked_add(1) == Some(pending.ordered_index)
            && heads.ordered_head == pending.ordered_parent => {}
        _ => return Err(SharedJournalDriverError::CrossStoreMismatch),
    }
    let claim = binding.claim();
    if binding.journal_store() != journal_store
        || binding.entry() != pending.entry
        || binding.raft_payload_commitment() != pending.command_commitment
        || binding.successor() == super::journal::JournalHeadsId::ZERO
        || claim.raft_index() != pending.index
        || claim.raft_term() != pending.term
        || claim.ordered().head != Some(pending.entry)
        || claim.ordered().index != pending.ordered_index
        || claim.space() != pending.route.space()
        || claim.agent() != pending.route.agent()
        || claim.genesis() != pending.route.genesis()
        || claim.admission() != pending.route.admission()
        || claim.committee() != pending.route.committee()
    {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux", feature = "experimental-state-blocks"))]
mod external_common_rebind_tests {
    use super::*;
    use crate::agent::genesis::AgentGenesisAdmissionId;
    use crate::agent::journal::{
        AgentJournalGenesisId, CheckpointId, CheckpointLane, CheckpointManifest, JournalHeads,
        JournalHeadsId, LaneCursor, LaneStateId, LaneStateManifest, MergeFrontierId,
        OrderedEntryId, RuntimeBinding,
    };
    use crate::service::{AgentId, DeploymentId, ProducerId, ProgramId, SpaceId};

    fn metadata() -> (
        JournalHeads,
        JournalHeads,
        CheckpointManifest,
        LaneStateManifest,
    ) {
        let runtime = RuntimeBinding {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId([4; 32]),
            producer: ProducerId([5; 32]),
            package: BlobRef::of_bytes(b"external-runtime"),
            runtime_abi: Hash(crate::agent_sdk::state_execution::STATE_EXECUTION_ABI_ID.0),
            execution_semantics: Hash(
                crate::agent_sdk::state_execution::STATE_EXECUTION_SEMANTICS_ID.0,
            ),
        };
        let mut initial = JournalHeads::initial(
            AgentJournalGenesisId([6; 32]),
            AgentGenesisAdmissionId::from_bytes([7; 32]),
            NodeId([8; 32]),
            MergeFrontierId([9; 32]),
            runtime,
        );
        initial.previous = Some(initial.id());
        initial.publication_revision = 1;
        initial.checkpoint = Some(CheckpointId([10; 32]));
        let local = LaneStateManifest {
            genesis: initial.genesis,
            runtime: initial.runtime.clone(),
            lane: PersistedLane::Local,
            cursor: LaneCursor::Local {
                node: initial.node,
                revision: 0,
                head: None,
            },
            state: BlobRef::of_bytes(&[]),
            external_root: None,
        };
        let mut source = JournalHeads::initial(
            initial.genesis,
            initial.admission,
            NodeId([11; 32]),
            initial.merge_frontier,
            initial.runtime.clone(),
        );
        source.previous = Some(JournalHeadsId([12; 32]));
        source.publication_revision = 9;
        source.ordered_index = 4;
        source.ordered_head = Some(OrderedEntryId([13; 32]));
        let checkpoint = CheckpointManifest {
            clean_management: None,
            genesis: source.genesis,
            admission: source.admission,
            runtime: source.runtime.clone(),
            publication_revision: 8,
            ordered_head: source.ordered_head,
            ordered_index: source.ordered_index,
            merge_frontier: source.merge_frontier,
            merge_fence: source.merge_fence,
            merge_seal: source.merge_seal,
            ordered_invocations: source.ordered_invocations,
            merge_invocations: source.merge_invocations,
            transition_proofs: source.transition_proofs,
            lanes: [
                PersistedLane::Control,
                PersistedLane::Linear,
                PersistedLane::Merge,
                PersistedLane::Local,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, lane)| CheckpointLane {
                lane,
                node: (lane == PersistedLane::Local).then_some(source.node),
                state: LaneStateId([index as u8 + 20; 32]),
                invocations: (lane == PersistedLane::Local).then_some(source.local_invocations),
            })
            .collect(),
            artifacts: super::super::journal::ArtifactClosureId([24; 32]),
        };
        source.checkpoint = Some(checkpoint.id());
        (initial, source, checkpoint, local)
    }

    #[test]
    fn metadata_rebind_preserves_common_root_references_and_context() {
        let (initial, source, checkpoint, local) = metadata();
        let rebound =
            rebind_external_common_metadata(&initial, &source, &checkpoint, &initial, local)
                .unwrap();
        let mut expected_checkpoint = checkpoint.clone();
        expected_checkpoint.publication_revision = initial.publication_revision;
        expected_checkpoint.lanes[3].node = Some(initial.node);
        expected_checkpoint.lanes[3].state = rebound.local.id();
        expected_checkpoint.lanes[3].invocations = Some(initial.local_invocations);
        assert_eq!(rebound.checkpoint, expected_checkpoint);
        assert_eq!(rebound.checkpoint.lanes[..3], checkpoint.lanes[..3]);
        let mut expected_heads = source.clone();
        expected_heads.node = initial.node;
        expected_heads.local_invocations = initial.local_invocations;
        expected_heads.publication_revision = 2;
        expected_heads.previous = Some(initial.id());
        expected_heads.checkpoint = Some(rebound.checkpoint.id());
        assert_eq!(rebound.heads, expected_heads);
        assert_eq!(rebound.local_invocations.id(), initial.local_invocations);
        assert_eq!(source.checkpoint, Some(checkpoint.id()));
    }

    #[test]
    fn metadata_rebind_refuses_scope_and_private_lane_changes() {
        let (initial, source, checkpoint, local) = metadata();
        let mut wrong_scope = source.clone();
        wrong_scope.admission = AgentGenesisAdmissionId::from_bytes([25; 32]);
        assert!(matches!(
            rebind_external_common_metadata(
                &initial,
                &wrong_scope,
                &checkpoint,
                &initial,
                local.clone(),
            ),
            Err(JournalStoreError::ScopeMismatch)
        ));
        let mut private = initial.clone();
        private.local_revision = 1;
        private.local_head = Some(super::super::journal::LocalEntryId([26; 32]));
        assert!(matches!(
            rebind_external_common_metadata(
                &initial,
                &source,
                &checkpoint,
                &private,
                local.clone()
            ),
            Err(JournalStoreError::ScopeMismatch)
        ));
        let mut divergent = initial.clone();
        divergent.ordered_index = source.ordered_index;
        divergent.ordered_head = Some(OrderedEntryId([27; 32]));
        assert!(matches!(
            rebind_external_common_metadata(&initial, &source, &checkpoint, &divergent, local),
            Err(JournalStoreError::ScopeMismatch)
        ));
    }

    #[test]
    fn metadata_rebind_refuses_publication_revision_overflow() {
        let (initial, source, checkpoint, local) = metadata();
        let mut predecessor = initial.clone();
        predecessor.publication_revision = u64::MAX;
        assert!(matches!(
            rebind_external_common_metadata(&initial, &source, &checkpoint, &predecessor, local),
            Err(JournalStoreError::LimitExceeded)
        ));
    }
}

#[cfg(all(test, feature = "experimental-state-blocks"))]
mod retained_external_reply_tests {
    use super::retained_external_reply_outcome;
    use crate::agent_sdk::{
        Hash, InvocationAcknowledgement, InvocationError, InvocationObservation, InvocationReply,
        InvocationRetirement, InvocationStatus, MethodMode, RuntimeOutcome,
    };

    fn fixture() -> (
        InvocationRetirement,
        Hash,
        InvocationReply,
        InvocationAcknowledgement,
    ) {
        let registration =
            super::super::shared_recovery::management_recovery_fixture_for_test(1, 7);
        let retirement = InvocationRetirement::from_work(registration.work());
        assert!(retirement.validate());
        let authorization = Hash([0x93; 32]);
        let reply = InvocationReply {
            invocation: retirement.invocation,
            actor: retirement.actor,
            incarnation: retirement.incarnation,
            deployment: retirement.deployment,
            mode: retirement.mode,
            lane: retirement.mode.write_lane(),
            status: InvocationStatus::Done,
            reply: vec![1, 2, 3],
            gas_remaining: retirement.gas,
            observation: InvocationObservation::default(),
        };
        let acknowledgement = InvocationAcknowledgement {
            invocation: retirement.invocation,
            actor: retirement.actor,
            incarnation: retirement.incarnation,
            deployment: retirement.deployment,
            mode: retirement.mode,
            work: retirement.commitment(),
            authorization,
        };
        (retirement, authorization, reply, acknowledgement)
    }

    #[test]
    fn absence_is_distinct_from_retained_terminal_failure() {
        let (retirement, authorization, _, _) = fixture();
        for acknowledge in [false, true] {
            assert!(
                retained_external_reply_outcome(
                    &retirement,
                    authorization,
                    acknowledge,
                    RuntimeOutcome::Completed(Err(InvocationError::NotReady)),
                )
                .unwrap()
                .is_none()
            );
        }
        let retained = RuntimeOutcome::Completed(Err(InvocationError::NotFound));
        assert_eq!(
            retained_external_reply_outcome(&retirement, authorization, false, retained.clone())
                .unwrap(),
            Some(retained.clone()),
        );
        assert!(
            retained_external_reply_outcome(&retirement, authorization, true, retained)
                .unwrap()
                .is_none(),
            "a completed failure still requires a real retirement ACK",
        );
    }

    #[test]
    fn retained_complete_invoke_is_exact_and_complete_ack_needs_publication() {
        let (retirement, authorization, reply, _) = fixture();
        let retained = RuntimeOutcome::Completed(Ok(reply));
        assert_eq!(
            retained_external_reply_outcome(&retirement, authorization, false, retained.clone())
                .unwrap(),
            Some(retained.clone()),
        );
        assert!(
            retained_external_reply_outcome(&retirement, authorization, true, retained)
                .unwrap()
                .is_none(),
        );
    }

    #[test]
    fn reply_identity_lane_and_original_gas_are_bound() {
        let (retirement, authorization, reply, _) = fixture();
        let mut changed = Vec::new();
        let mut wrong = reply.clone();
        wrong.actor = crate::agent_sdk::ActorId([0x98; 32]);
        changed.push(wrong);
        let mut wrong = reply.clone();
        wrong.mode = MethodMode::LinearizableQuery;
        changed.push(wrong);
        let mut wrong = reply.clone();
        wrong.lane = None;
        changed.push(wrong);
        let mut wrong = reply.clone();
        wrong.gas_remaining = retirement.gas + 1;
        changed.push(wrong);
        for reply in changed {
            for acknowledge in [false, true] {
                assert!(
                    retained_external_reply_outcome(
                        &retirement,
                        authorization,
                        acknowledge,
                        RuntimeOutcome::Completed(Ok(reply.clone())),
                    )
                    .is_err(),
                );
            }
        }
        let mut query = retirement;
        query.mode = MethodMode::LinearizableQuery;
        let mut query_reply = reply;
        query_reply.mode = query.mode;
        query_reply.lane = None;
        assert!(
            retained_external_reply_outcome(
                &query,
                authorization,
                false,
                RuntimeOutcome::Completed(Ok(query_reply)),
            )
            .unwrap()
            .is_some(),
        );
    }

    #[test]
    fn acknowledged_invoke_cannot_fall_back_to_fresh_execution() {
        let (retirement, authorization, _, acknowledgement) = fixture();
        let retained = RuntimeOutcome::Acknowledged(Ok(acknowledgement));
        assert_eq!(
            retained_external_reply_outcome(&retirement, authorization, true, retained.clone())
                .unwrap(),
            Some(retained.clone()),
        );
        assert!(
            retained_external_reply_outcome(&retirement, authorization, false, retained).is_err(),
        );
        let mut changed = acknowledgement;
        changed.work = Hash([0x94; 32]);
        assert!(
            retained_external_reply_outcome(
                &retirement,
                authorization,
                true,
                RuntimeOutcome::Acknowledged(Ok(changed)),
            )
            .is_err(),
        );
        let mut changed = acknowledgement;
        changed.authorization = Hash([0x95; 32]);
        assert!(
            retained_external_reply_outcome(
                &retirement,
                authorization,
                true,
                RuntimeOutcome::Acknowledged(Ok(changed)),
            )
            .is_err(),
        );
        let mut changed = acknowledgement;
        changed.actor = crate::agent_sdk::ActorId([0x96; 32]);
        assert!(
            retained_external_reply_outcome(
                &retirement,
                authorization,
                true,
                RuntimeOutcome::Acknowledged(Ok(changed)),
            )
            .is_err(),
        );
    }

    #[test]
    fn authorization_and_inspection_errors_are_never_absence() {
        let (retirement, authorization, _, _) = fixture();
        for error in [
            InvocationError::InvalidAuthorization,
            InvocationError::DivergentInvocation,
            InvocationError::NotCreated,
        ] {
            for acknowledge in [false, true] {
                for outcome in [
                    RuntimeOutcome::Completed(Err(error)),
                    RuntimeOutcome::Acknowledged(Err(error)),
                ] {
                    assert!(
                        retained_external_reply_outcome(
                            &retirement,
                            authorization,
                            acknowledge,
                            outcome,
                        )
                        .is_err(),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod keyed_actor_cursor_tests {

    #[test]
    fn management_pending_capsule_fallback_never_turns_absence_into_anchor_evidence() {
        use super::super::journal::ReplayInputId;
        let first = ReplayInputId([1; 32]);
        let later = ReplayInputId([2; 32]);
        for (recent, anchored, capsule, expected) in [
            (None, None, None, true),
            (Some(first), Some(first), None, true),
            (Some(first), None, None, false),
            (Some(first), None, Some(first), false),
            (Some(first), Some(later), None, false),
            (Some(first), Some(later), Some(first), false),
            (None, Some(first), Some(first), true),
            (Some(later), Some(first), Some(first), true),
        ] {
            assert_eq!(
                super::management_pending_input_matches_anchor(recent, anchored, capsule),
                expected,
                "recent={recent:?} anchored={anchored:?} capsule={capsule:?}",
            );
        }
    }

    fn management_capsule_fixture(
        acknowledged: bool,
    ) -> (
        super::SharedRecoveryManifest,
        super::super::shared_recovery::management::SharedManagementRecoveryMember,
        super::super::shared_recovery::VerifiedSharedRecoveryObservation,
    ) {
        management_capsule_fixture_for_owner(1, 7, acknowledged)
    }

    fn management_capsule_fixture_for_owner(
        owner: u8,
        nonce: u8,
        acknowledged: bool,
    ) -> (
        super::SharedRecoveryManifest,
        super::super::shared_recovery::management::SharedManagementRecoveryMember,
        super::super::shared_recovery::VerifiedSharedRecoveryObservation,
    ) {
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryMember, SharedManagementRecoveryRegistration,
            SharedManagementRecoveryRegistrationRequest,
        };
        use super::super::shared_recovery::{
            management_observation_for_test, management_recovery_fixture_for_test,
        };
        use ed25519_dalek::{Signer as _, SigningKey};
        let template = management_recovery_fixture_for_test(owner, nonce);
        let first = management_observation_for_test(&template, 2, false);
        let member = SharedManagementRecoveryMember::new(
            None,
            super::super::clean_management_intent::ManagementJournalAnchor {
                genesis: template.generation().genesis(),
                admission: template.generation().admission(),
                runtime: first.observation().input().runtime.commitment(),
                ordered: super::OrderedBase::post_genesis(),
            },
            template.envelope().clone(),
        )
        .unwrap();
        let request = SharedManagementRecoveryRegistrationRequest::new(
            template.generation(),
            template.committee(),
            template.owner(),
            template.owner(),
            1,
            None,
            vec![member.clone()],
        )
        .unwrap();
        let signature = super::super::shared_commit::ReplicaCommitSignature::new(
            template.owner(),
            SigningKey::from_bytes(&[owner; 32])
                .sign(&request.signing_message().0)
                .to_bytes(),
        )
        .unwrap();
        let registration = SharedManagementRecoveryRegistration::new(request, signature).unwrap();
        let committee = super::super::shared_commit::common_snapshot_claim_for_test()
            .active_committee()
            .clone();
        let mut manifest =
            super::SharedRecoveryManifest::new(template.generation(), committee).unwrap();
        manifest
            .apply_management_registration(&registration, 1, 3)
            .unwrap();
        manifest.observe(&first).unwrap();
        if acknowledged {
            manifest
                .observe(&management_observation_for_test(&template, 3, true))
                .unwrap();
        }
        (manifest, member, first)
    }

    fn management_clock_fixture(
        owner: u8,
        nonce: u8,
        observed_slot: u64,
    ) -> (
        super::SharedRecoveryManifest,
        super::super::shared_recovery::management::SharedManagementRecoveryMember,
    ) {
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryMember, SharedManagementRecoveryRegistration,
            SharedManagementRecoveryRegistrationRequest,
        };
        use super::super::shared_recovery::management_recovery_fixture_at_slot_for_test;
        use ed25519_dalek::{Signer as _, SigningKey};
        let fixture = management_recovery_fixture_at_slot_for_test(owner, nonce, observed_slot);
        let first =
            super::super::shared_recovery::management_observation_for_test(&fixture, 2, false);
        let member = SharedManagementRecoveryMember::new(
            None,
            super::super::clean_management_intent::ManagementJournalAnchor {
                genesis: fixture.generation().genesis(),
                admission: fixture.generation().admission(),
                runtime: first.observation().input().runtime.commitment(),
                ordered: super::OrderedBase::post_genesis(),
            },
            fixture.envelope().clone(),
        )
        .unwrap();
        let request = SharedManagementRecoveryRegistrationRequest::new(
            fixture.generation(),
            fixture.committee(),
            fixture.owner(),
            fixture.owner(),
            1,
            None,
            vec![member.clone()],
        )
        .unwrap();
        let signature = super::super::shared_commit::ReplicaCommitSignature::new(
            request.owner(),
            SigningKey::from_bytes(&[owner; 32])
                .sign(&request.signing_message().0)
                .to_bytes(),
        )
        .unwrap();
        let registration = SharedManagementRecoveryRegistration::new(request, signature).unwrap();
        let committee = super::super::shared_commit::common_snapshot_claim_for_test()
            .active_committee()
            .clone();
        let mut manifest =
            super::SharedRecoveryManifest::new(fixture.generation(), committee).unwrap();
        manifest
            .apply_management_registration(&registration, 1, 3)
            .unwrap();
        (manifest, member)
    }

    #[test]
    fn management_clock_orders_distinct_owners_without_restricting_equal_slots() {
        use crate::service::wire::ServiceWire as _;
        let (mut manifest, _) = management_clock_fixture(1, 7, 10);
        let (second, _) = management_clock_fixture(2, 8, 11);
        manifest
            .apply_management_registration(second.management_slots()[0].registration(), 2, 3)
            .unwrap();
        let immutable = manifest.encode();
        assert!(super::management_first_invoke_clock_ready(&manifest, 10).unwrap());
        assert!(!super::management_first_invoke_clock_ready(&manifest, 11).unwrap());
        assert!(!super::management_first_invoke_clock_ready(&manifest, 12).unwrap());
        assert_eq!(manifest.encode(), immutable);
        let (equal, _) = management_clock_fixture(2, 8, 10);
        let (mut manifest, _) = management_clock_fixture(1, 7, 10);
        manifest
            .apply_management_registration(equal.management_slots()[0].registration(), 2, 3)
            .unwrap();
        assert!(super::management_first_invoke_clock_ready(&manifest, 10).unwrap());
    }

    #[test]
    fn management_clock_fence_requires_first_invoke_not_ack_or_native_release() {
        use super::super::shared_recovery::{
            management_observation_for_test, management_recovery_fixture_for_test,
        };
        // The signed management call has observed slot ten. Its physical
        // first evidence is sufficient; ACK/release need their unchanged proofs.
        let (completed, _, first) = management_capsule_fixture(false);
        let registration = completed.management_slots()[0].registration().clone();
        let mut manifest = super::SharedRecoveryManifest::new(
            completed.generation(),
            completed.committee().clone(),
        )
        .unwrap();
        manifest
            .apply_management_registration(&registration, 1, 3)
            .unwrap();
        assert!(!super::management_first_invoke_clock_ready(&manifest, 11).unwrap());
        manifest.observe(&first).unwrap();
        assert!(super::management_first_invoke_clock_ready(&manifest, 11).unwrap());
        let slot = &manifest.management_slots()[0];
        assert!(slot.members_evidence()[0].acknowledgement().is_none());
        assert!(!slot.is_released());
        let template = management_recovery_fixture_for_test(1, 7);
        manifest
            .observe(&management_observation_for_test(&template, 3, true))
            .unwrap();
        assert!(super::management_first_invoke_clock_ready(&manifest, 11).unwrap());
        assert!(!manifest.management_slots()[0].is_released());
    }

    #[test]
    fn management_clock_child_finalization_fences_later_first_execution() {
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryMember, SharedManagementRecoveryRegistration,
            SharedManagementRecoveryRegistrationRequest,
        };
        use crate::service::wire::ServiceWire as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        let (mut manifest, root, _) = management_capsule_fixture(false);
        let (_, child) = management_clock_fixture(1, 8, 11);
        let child = SharedManagementRecoveryMember::new(
            Some(root.commitment()),
            child.anchor().clone(),
            child.envelope().clone(),
        )
        .unwrap();
        let slot = &manifest.management_slots()[0];
        let request = SharedManagementRecoveryRegistrationRequest::new(
            manifest.generation(),
            manifest.committee().id(),
            slot.owner(),
            slot.origin_owner(),
            slot.sequence() + 1,
            Some(slot.commitment()),
            vec![root, child],
        )
        .unwrap();
        let signature = super::super::shared_commit::ReplicaCommitSignature::new(
            request.owner(),
            SigningKey::from_bytes(&[1; 32])
                .sign(&request.signing_message().0)
                .to_bytes(),
        )
        .unwrap();
        manifest
            .apply_management_registration(
                &SharedManagementRecoveryRegistration::new(request, signature).unwrap(),
                3,
                3,
            )
            .unwrap();
        let immutable = manifest.encode();
        assert!(super::management_first_invoke_clock_ready(&manifest, 11).unwrap());
        assert!(!super::management_first_invoke_clock_ready(&manifest, 12).unwrap());
        assert_eq!(manifest.encode(), immutable);
    }

    #[test]
    fn management_retention_headroom_aggregates_owners_and_excludes_positive_acks() {
        use super::super::journal::{JournalHeads, MergeFrontierId};
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryRelease, SharedManagementRecoveryReleaseRequest,
        };
        use super::super::shared_recovery::{
            management_observation_for_test, management_recovery_fixture_for_test,
        };
        use ed25519_dalek::{Signer as _, SigningKey};
        let (mut manifest, first, _) = management_capsule_fixture(false);
        let (second_manifest, second, _) = management_capsule_fixture_for_owner(2, 8, false);
        let second_registration = second_manifest.management_slots()[0].registration().clone();
        manifest
            .apply_management_registration(&second_registration, 4, 3)
            .unwrap();
        let second_template = management_recovery_fixture_for_test(2, 8);
        manifest
            .observe(&management_observation_for_test(&second_template, 5, false))
            .unwrap();
        let common = super::super::shared_commit::common_snapshot_claim_for_test();
        let heads = JournalHeads::initial(
            common.ordered().genesis(),
            common.ordered().admission(),
            second_template.owner(),
            MergeFrontierId([0x91; 32]),
            common.ordered().runtime().clone(),
        );
        let first_future =
            super::management_finalization_headroom(&heads, first.envelope()).unwrap();
        let second_future =
            super::management_finalization_headroom(&heads, second.envelope()).unwrap();
        let (pending, entries, bytes) =
            super::management_retention_headroom(&heads, &manifest, None).unwrap();
        assert_eq!(
            pending.len(),
            2,
            "both remote owners consume one joint budget"
        );
        assert_eq!(entries, first_future.0 + second_future.0);
        assert_eq!(entries, 4);
        assert_eq!(bytes, first_future.1 + second_future.1);
        assert!(pending.iter().any(|(_, work)| *work == first.envelope()));
        assert!(pending.iter().any(|(_, work)| *work == second.envelope()));

        manifest
            .observe(&management_observation_for_test(&second_template, 6, true))
            .unwrap();
        let (pending, after_entries, after_bytes) =
            super::management_retention_headroom(&heads, &manifest, None).unwrap();
        assert_eq!(pending, vec![(first.anchor(), first.envelope())]);
        assert_eq!((after_entries, after_bytes), (entries, bytes));
        // An ACKed approval leaves the family's future finalization reserve,
        // but never re-enters the pending-denial validator.
        let request = SharedManagementRecoveryReleaseRequest::for_slot(
            manifest.management_slot(second_template.owner()).unwrap(),
        )
        .unwrap();
        let signature = super::super::shared_commit::ReplicaCommitSignature::new(
            second_template.owner(),
            SigningKey::from_bytes(&[2; 32])
                .sign(&request.signing_message().0)
                .to_bytes(),
        )
        .unwrap();
        let release = SharedManagementRecoveryRelease::new(request, signature).unwrap();
        manifest.apply_management_release(&release, 7, 3).unwrap();
        let (pending, after_entries, after_bytes) =
            super::management_retention_headroom(&heads, &manifest, None).unwrap();
        assert_eq!(pending, vec![(first.anchor(), first.envelope())]);
        assert_eq!((after_entries, after_bytes), first_future);
    }

    #[test]
    fn management_retention_headroom_counts_exact_signed_shadow_once() {
        use super::super::journal::{JournalHeads, MergeFrontierId};
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryMember, SharedManagementRecoveryRegistration,
            SharedManagementRecoveryRegistrationRequest,
        };
        use super::super::shared_recovery::{
            management_node_for_test, management_observation_for_test,
            management_recovery_fixture_for_test,
        };
        use crate::service::wire::ServiceWire as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        let (admitted, root, _) = management_capsule_fixture(false);
        let original = admitted.management_slots()[0].registration().clone();
        // A new holder must acquire the root at its exact current anchor,
        // before any Invoke advances the authenticated logical prefix.
        let mut manifest = super::SharedRecoveryManifest::new(
            admitted.generation(), admitted.committee().clone(),
        )
        .unwrap();
        manifest.apply_management_registration(&original, 1, 3).unwrap();
        let original_owner = original.owner();
        let shadow_owner = management_node_for_test(2);
        let incoming = SharedManagementRecoveryRegistrationRequest::new(
            manifest.generation(),
            manifest.committee().id(),
            shadow_owner,
            original_owner,
            1,
            None,
            vec![root.clone()],
        )
        .unwrap();
        manifest.validate_management_registration_request(&incoming).unwrap();
        let sign = |request: SharedManagementRecoveryRegistrationRequest, seed: u8| {
            let signature = super::super::shared_commit::ReplicaCommitSignature::new(
                request.owner(),
                SigningKey::from_bytes(&[seed; 32])
                    .sign(&request.signing_message().0)
                    .to_bytes(),
            )
            .unwrap();
            SharedManagementRecoveryRegistration::new(request, signature).unwrap()
        };
        let shadow = sign(incoming, 2);
        shadow.verify(manifest.generation(), manifest.committee()).unwrap();
        let common = super::super::shared_commit::common_snapshot_claim_for_test();
        let heads = JournalHeads::initial(
            common.ordered().genesis(),
            common.ordered().admission(),
            shadow_owner,
            MergeFrontierId([0x91; 32]),
            common.ordered().runtime().clone(),
        );
        let future = super::management_finalization_headroom(&heads, root.envelope()).unwrap();
        let immutable = manifest.encode();
        let (pending, entries, bytes) =
            super::management_retention_headroom(&heads, &manifest, Some(shadow.request())).unwrap();
        assert_eq!(pending.len(), 1, "exact shadow custody must budget one runtime invocation");
        assert_eq!(pending, vec![(root.anchor(), root.envelope())]);
        assert_eq!((entries, bytes), (2 * future.0, 2 * future.1));
        assert_eq!(entries, 4, "each holder keeps its full future finalization reserve");
        assert_eq!(manifest.encode(), immutable);
        manifest.apply_management_registration(&shadow, 2, 3).unwrap();
        for owner in [original_owner, shadow_owner] {
            let slot = manifest.management_slot(owner).unwrap();
            assert_eq!(slot.origin_owner(), original_owner);
            assert_eq!(slot.members(), &[root.clone()]);
            assert!(slot.members_evidence()[0].invoke().is_none());
            assert!(slot.members_evidence()[0].acknowledgement().is_none());
        }
        let template = management_recovery_fixture_for_test(1, 7);
        let first = management_observation_for_test(&template, 3, false);
        manifest.observe(&first).unwrap();
        for owner in [original_owner, shadow_owner] {
            let slot = manifest.management_slot(owner).unwrap();
            assert_eq!(slot.members_evidence()[0].invoke().unwrap().input_id(), first.observation().input_id());
            assert!(slot.members_evidence()[0].acknowledgement().is_none());
        }
        let (pending, registered_entries, registered_bytes) =
            super::management_retention_headroom(&heads, &manifest, None).unwrap();
        assert_eq!(pending, vec![(root.anchor(), root.envelope())]);
        assert_eq!((registered_entries, registered_bytes), (entries, bytes));
        manifest.observe(&management_observation_for_test(&template, 4, true)).unwrap();
        let (pending, acked_entries, acked_bytes) =
            super::management_retention_headroom(&heads, &manifest, None).unwrap();
        assert!(pending.is_empty());
        assert_eq!((acked_entries, acked_bytes), (entries, bytes));

        // Acquire root-only custody first, then legally append the same child
        // through each holder's own predecessor commitment and full member set.
        let (_, other, _) = management_capsule_fixture_for_owner(1, 8, false);
        let child = SharedManagementRecoveryMember::new(
            Some(root.commitment()),
            other.anchor().clone(),
            other.envelope().clone(),
        )
        .unwrap();
        for (owner, seed, position) in [(original_owner, 1, 5), (shadow_owner, 2, 6)] {
            let previous = manifest.management_slot(owner).unwrap();
            let request = SharedManagementRecoveryRegistrationRequest::new(
                manifest.generation(),
                manifest.committee().id(),
                owner,
                original_owner,
                previous.sequence() + 1,
                Some(previous.commitment()),
                vec![root.clone(), child.clone()],
            )
            .unwrap();
            manifest.validate_management_registration_request(&request).unwrap();
            let registration = sign(request, seed);
            registration.verify(manifest.generation(), manifest.committee()).unwrap();
            let (pending, child_entries, child_bytes) =
                super::management_retention_headroom(&heads, &manifest, Some(registration.request()))
                    .unwrap();
            assert_eq!(pending, vec![(child.anchor(), child.envelope())]);
            assert_eq!((child_entries, child_bytes), (entries, bytes));
            manifest.apply_management_registration(&registration, position, 3).unwrap();
        }
        let (pending, child_entries, child_bytes) =
            super::management_retention_headroom(&heads, &manifest, None).unwrap();
        assert_eq!(pending, vec![(child.anchor(), child.envelope())]);
        assert_eq!((child_entries, child_bytes), (entries, bytes));
    }

    #[test]
    fn management_retention_headroom_preserves_conflicting_same_invocation_refusal() {
        use super::super::journal::{JournalHeads, MergeFrontierId, OrderedEntryId};
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryMember, SharedManagementRecoveryRegistration,
            SharedManagementRecoveryRegistrationRequest,
        };
        use super::super::shared_recovery::{management_node_for_test, SharedRecoveryError};
        use crate::service::wire::ServiceWire as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        let (mut manifest, root, _) = management_capsule_fixture(false);
        let original_owner = manifest.management_slots()[0].owner();
        let shadow_owner = management_node_for_test(2);
        let mut later_anchor = root.anchor().clone();
        later_anchor.ordered = super::OrderedBase {
            index: 1,
            head: Some(OrderedEntryId([0x95; 32])),
        };
        let different_anchor = SharedManagementRecoveryMember::new(
            None, later_anchor, root.envelope().clone(),
        )
        .unwrap();
        let mut different_envelope = root.envelope().clone();
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation, authorization, observed_slot, ..
        } = &mut different_envelope else {
            unreachable!()
        };
        invocation.gas = invocation.gas.checked_sub(1).unwrap();
        **authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
        );
        let different_work = SharedManagementRecoveryMember::new(
            None, root.anchor().clone(), different_envelope,
        )
        .unwrap();
        let common = super::super::shared_commit::common_snapshot_claim_for_test();
        let heads = JournalHeads::initial(
            common.ordered().genesis(),
            common.ordered().admission(),
            shadow_owner,
            MergeFrontierId([0x91; 32]),
            common.ordered().runtime().clone(),
        );
        let immutable = manifest.encode();
        for conflicting in [different_anchor, different_work] {
            assert_eq!(conflicting.work().invocation, root.work().invocation);
            let request = SharedManagementRecoveryRegistrationRequest::new(
                manifest.generation(), manifest.committee().id(), shadow_owner,
                original_owner, 1, None, vec![conflicting.clone()],
            )
            .unwrap();
            assert_eq!(
                manifest.validate_management_registration_request(&request),
                Err(SharedRecoveryError::Conflict),
            );
            let signature = super::super::shared_commit::ReplicaCommitSignature::new(
                shadow_owner,
                SigningKey::from_bytes(&[2; 32])
                    .sign(&request.signing_message().0)
                    .to_bytes(),
            )
            .unwrap();
            let registration = SharedManagementRecoveryRegistration::new(request, signature).unwrap();
            registration.verify(manifest.generation(), manifest.committee()).unwrap();
            assert_eq!(
                manifest.apply_management_registration(&registration, 4, 3),
                Err(SharedRecoveryError::Conflict),
            );
            assert_eq!(manifest.encode(), immutable);
            // This pure selector is not admission. It must leave distinct
            // same-ID pairs intact for the unchanged checked budget refusal.
            let (pending, _, _) =
                super::management_retention_headroom(&heads, &manifest, Some(registration.request()))
                    .unwrap();
            assert_eq!(pending.len(), 2);
            assert!(pending.contains(&(root.anchor(), root.envelope())));
            assert!(pending.contains(&(conflicting.anchor(), conflicting.envelope())));
            assert_ne!(pending[0], pending[1]);
        }
    }

    #[test]
    fn management_retention_headroom_replaces_only_incoming_owner_scope() {
        use super::super::journal::{JournalHeads, MergeFrontierId};
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryMember, SharedManagementRecoveryRegistrationRequest,
        };
        let (mut manifest, first, _) = management_capsule_fixture(false);
        let (second_manifest, second, _) = management_capsule_fixture_for_owner(2, 8, true);
        let second_registration = second_manifest.management_slots()[0].registration().clone();
        manifest
            .apply_management_registration(&second_registration, 4, 3)
            .unwrap();
        let template = super::super::shared_recovery::management_recovery_fixture_for_test(2, 8);
        for acknowledgement in [false, true] {
            manifest
                .observe(
                    &super::super::shared_recovery::management_observation_for_test(
                        &template,
                        if acknowledgement { 6 } else { 5 },
                        acknowledgement,
                    ),
                )
                .unwrap();
        }
        let (_, third, _) = management_capsule_fixture_for_owner(2, 9, false);
        let child = SharedManagementRecoveryMember::new(
            Some(second.commitment()),
            third.anchor().clone(),
            third.envelope().clone(),
        )
        .unwrap();
        let slot = manifest.management_slot(template.owner()).unwrap();
        let incoming = SharedManagementRecoveryRegistrationRequest::new(
            manifest.generation(),
            manifest.committee().id(),
            template.owner(),
            slot.origin_owner(),
            slot.sequence() + 1,
            Some(slot.commitment()),
            vec![second.clone(), child.clone()],
        )
        .unwrap();
        manifest
            .validate_management_registration_request(&incoming)
            .unwrap();
        let common = super::super::shared_commit::common_snapshot_claim_for_test();
        let heads = JournalHeads::initial(
            common.ordered().genesis(),
            common.ordered().admission(),
            template.owner(),
            MergeFrontierId([0x91; 32]),
            common.ordered().runtime().clone(),
        );
        let (pending, entries, bytes) =
            super::management_retention_headroom(&heads, &manifest, Some(&incoming)).unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&(first.anchor(), first.envelope())));
        assert!(pending.contains(&(child.anchor(), child.envelope())));
        assert!(!pending.contains(&(second.anchor(), second.envelope())));
        let first_future =
            super::management_finalization_headroom(&heads, first.envelope()).unwrap();
        let second_future =
            super::management_finalization_headroom(&heads, second.envelope()).unwrap();
        assert_eq!((entries, bytes), (4, first_future.1 + second_future.1));
    }

    #[test]
    fn management_capsule_selection_requires_exact_saved_anchor_and_complete_envelope() {
        let (manifest, member, first) = management_capsule_fixture(false);
        assert_eq!(
            super::exact_retained_management_member(
                &manifest,
                Some(member.anchor().ordered),
                member.envelope()
            )
            .unwrap()
            .unwrap()
            .invoke(),
            Some(first.observation())
        );
        assert!(
            super::exact_retained_management_member(
                &manifest,
                Some(super::OrderedBase {
                    index: 1,
                    head: Some(super::super::journal::OrderedEntryId([0xf1; 32])),
                }),
                member.envelope()
            )
            .is_err()
        );
        let mut altered = member.envelope().clone();
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } = &mut altered
        else {
            panic!("Invoke fixture");
        };
        invocation.gas -= 1;
        **authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
        );
        assert!(
            super::exact_retained_management_member(
                &manifest,
                Some(member.anchor().ordered),
                &altered
            )
            .is_err()
        );
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            context,
            ..
        } = &altered
        else {
            panic!("Invoke fixture");
        };
        assert!(
            super::retained_management_operation(
                &manifest,
                &super::ReplayOperation::CleanInvoke {
                    context: *context,
                    work: (**invocation).clone(),
                    authorization: (**authorization).clone(),
                    observed_slot: *observed_slot,
                }
            )
            .is_err()
        );
        let foreign = super::super::shared_recovery::management_recovery_fixture_for_test(1, 8);
        let mut unknown = member.envelope().clone();
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = &mut unknown
        else {
            panic!("Invoke fixture");
        };
        **invocation = foreign.work().clone();
        **authorization = foreign.authorization().clone();
        assert!(
            super::exact_retained_management_member(
                &manifest,
                Some(member.anchor().ordered),
                &unknown
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn management_first_completed_capsule_and_positive_ack_are_distinct_retained_results() {
        let (mut manifest, member, first) = management_capsule_fixture(true);
        let duplicate = super::super::shared_recovery::management_observation_for_test(
            &super::super::shared_recovery::management_recovery_fixture_for_test(1, 7),
            4,
            false,
        );
        manifest.observe(&duplicate).unwrap();
        let input = first.observation().input();
        assert_eq!(
            super::retained_management_operation(&manifest, &input.operation).unwrap(),
            Some(first.observation())
        );
        assert_eq!(
            super::retained_acknowledged_projection_outcome(
                Some(&manifest),
                member.work(),
                member.authorization(),
                first.observation().input_id(),
                || panic!("first retained response must win over later/absent cache")
            ),
            Some(first.observation().outcome().clone())
        );
        let evidence = super::exact_retained_management_member(
            &manifest,
            Some(member.anchor().ordered),
            member.envelope(),
        )
        .unwrap()
        .unwrap();
        let ack = evidence.acknowledgement().unwrap();
        assert!(matches!(
            ack.outcome(),
            crate::agent_sdk::RuntimeOutcome::Acknowledged(Ok(_))
        ));
        assert_eq!(
            super::retained_management_operation(&manifest, &ack.input().operation).unwrap(),
            Some(ack)
        );
        assert_ne!(ack.input_id(), first.observation().input_id());
    }

    #[test]
    fn management_archived_availability_requires_exact_live_and_certified_first_observation() {
        let (live, member, first) = management_capsule_fixture(true);
        assert_eq!(
            super::certified_live_recovery_observation(&live, Some(&live), first.observation()),
            Some(first.observation())
        );
        assert!(
            super::certified_live_recovery_observation(&live, None, first.observation()).is_none()
        );
        let changed = super::super::shared_recovery::management_observation_for_test(
            &super::super::shared_recovery::management_recovery_fixture_for_test(1, 7),
            4,
            false,
        );
        assert_eq!(
            first.observation().input_id(),
            changed.observation().input_id()
        );
        assert!(
            super::certified_live_recovery_observation(&live, Some(&live), changed.observation())
                .is_none()
        );
        let unique = super::unique_recovery_observations(&live);
        assert_eq!(unique.len(), 2);
        assert!(unique.contains(&first.observation()));
        let absent =
            super::SharedRecoveryManifest::new(live.generation(), live.committee().clone())
                .unwrap();
        assert!(
            super::certified_live_recovery_observation(&absent, Some(&live), first.observation())
                .is_none()
        );
        let (without_ack, _, _) = management_capsule_fixture(false);
        assert!(
            super::retained_acknowledged_projection_outcome(
                Some(&without_ack),
                member.work(),
                member.authorization(),
                first.observation().input_id(),
                || None
            )
            .is_none()
        );
    }

    #[test]
    fn management_budget_archived_selection_binds_whole_live_view_and_each_first_capsule() {
        let (live, _, first) = management_capsule_fixture(true);
        let (before_ack, _, same_first) = management_capsule_fixture(false);
        assert_eq!(first.observation(), same_first.observation());
        let acknowledgement = live
            .management_slots()
            .iter()
            .flat_map(|slot| slot.observations())
            .find(|observation| observation.is_acknowledgement())
            .unwrap();
        for requested in [first.observation(), acknowledgement] {
            let selected =
                super::certified_budget_recovery_observation(&live, &live, Some(&live), requested)
                    .unwrap();
            assert_eq!(selected, requested);
            assert_eq!(selected.claim(), requested.claim());
        }
        assert!(
            super::certified_budget_recovery_observation(
                &before_ack,
                &live,
                Some(&live),
                first.observation(),
            )
            .is_none(),
            "an identical requested capsule cannot excuse a different complete live view"
        );
        assert!(
            super::certified_budget_recovery_observation(
                &live,
                &live,
                Some(&before_ack),
                acknowledgement,
            )
            .is_none(),
            "every selected ACK needs its own exact certified baseline evidence"
        );
        assert!(
            super::certified_budget_recovery_observation(&live, &live, None, first.observation(),)
                .is_none()
        );
        let changed = super::super::shared_recovery::management_observation_for_test(
            &super::super::shared_recovery::management_recovery_fixture_for_test(1, 7),
            4,
            false,
        );
        assert_eq!(
            changed.observation().input_id(),
            first.observation().input_id()
        );
        assert!(
            super::certified_budget_recovery_observation(
                &live,
                &live,
                Some(&live),
                changed.observation(),
            )
            .is_none(),
            "matching input identity does not authorize a changed first claim"
        );
    }

    #[test]
    fn acknowledged_management_prefers_first_capsule_over_later_input_outcome() {
        use super::super::shared_recovery::management_recovery_fixture_for_test;
        let registration = management_recovery_fixture_for_test(1, 7);
        let (manifest, _, first) = management_capsule_fixture(true);
        let later = crate::agent_sdk::RuntimeOutcome::Completed(Err(
            crate::agent_sdk::InvocationError::NotFound,
        ));
        let selected = super::retained_acknowledged_projection_outcome(
            Some(&manifest),
            registration.work(),
            registration.authorization(),
            first.observation().input_id(),
            || panic!("canonical capsule must win over latest outcome"),
        );
        assert_eq!(selected, Some(first.observation().outcome().clone()));
        assert_eq!(
            super::retained_acknowledged_projection_outcome(
                None,
                registration.work(),
                registration.authorization(),
                first.observation().input_id(),
                || Some(later.clone()),
            ),
            Some(later)
        );
        let foreign = management_recovery_fixture_for_test(2, 8);
        assert_eq!(
            super::retained_acknowledged_projection_outcome(
                Some(&manifest),
                foreign.work(),
                foreign.authorization(),
                first.observation().input_id(),
                || None,
            ),
            None
        );
        assert_eq!(
            super::retained_acknowledged_projection_outcome(
                Some(&manifest),
                registration.work(),
                registration.authorization(),
                super::super::journal::ReplayInputId([0xff; 32]),
                || None,
            ),
            None
        );
    }

    #[test]
    fn recovery_replay_checks_each_position_and_requires_negative_ack_for_absence() {
        use super::super::journal::{OrderedEntryId, ReplayInputId};
        use crate::agent_sdk::{InvocationError, RuntimeOutcome};
        let first = OrderedEntryId([1; 32]);
        let second = OrderedEntryId([2; 32]);
        let third = OrderedEntryId([3; 32]);
        let invoke = ReplayInputId([4; 32]);
        let ack = ReplayInputId([5; 32]);
        let first_outcome = RuntimeOutcome::Completed(Err(InvocationError::Suspended));
        let repeated_outcome = RuntimeOutcome::Completed(Err(InvocationError::NotFound));
        let negative = RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound));
        let evidence = vec![
            (first, invoke, Some(first_outcome.clone())),
            (second, invoke, Some(repeated_outcome.clone())),
            (third, ack, None),
        ];
        let exact = std::collections::BTreeMap::from([
            ((first, invoke), first_outcome),
            ((second, invoke), repeated_outcome.clone()),
            ((third, ack), negative),
        ]);
        super::validate_recovery_replay_evidence(&evidence, |entry, input| {
            exact.get(&(entry, input)).cloned()
        })
        .unwrap();
        // A latest-by-input answer cannot stand in for the first occurrence.
        assert!(
            super::validate_recovery_replay_evidence(&evidence, |_, input| {
                (input == invoke).then(|| repeated_outcome.clone())
            })
            .is_err()
        );
        let mut wrong_position = exact.clone();
        wrong_position.remove(&(first, invoke));
        assert!(
            super::validate_recovery_replay_evidence(&evidence, |entry, input| wrong_position
                .get(&(entry, input))
                .cloned())
            .is_err()
        );
        let mut wrong_input = exact.clone();
        let outcome = wrong_input.remove(&(first, invoke)).unwrap();
        wrong_input.insert((first, ack), outcome);
        assert!(
            super::validate_recovery_replay_evidence(&evidence, |entry, input| wrong_input
                .get(&(entry, input))
                .cloned())
            .is_err()
        );

        let registration =
            super::super::shared_recovery::management_recovery_fixture_for_test(1, 7);
        let positive =
            super::super::shared_recovery::management_observation_for_test(&registration, 10, true);
        let mut missing_positive = exact.clone();
        missing_positive.insert((third, ack), positive.observation().outcome().clone());
        assert!(
            super::validate_recovery_replay_evidence(&evidence, |entry, input| missing_positive
                .get(&(entry, input))
                .cloned())
            .is_err()
        );
        let mut missing_result = exact;
        missing_result.remove(&(third, ack));
        assert!(
            super::validate_recovery_replay_evidence(&evidence, |entry, input| missing_result
                .get(&(entry, input))
                .cloned())
            .is_err()
        );
    }
    use super::exclusive_actor_predecessor;

    #[test]
    fn archived_recovery_lookup_requires_exact_live_and_certified_observation() {
        use super::super::shared_recovery::{
            SharedRecoveryManifest, management_observation_for_test,
            management_recovery_fixture_for_test,
        };
        let registration = management_recovery_fixture_for_test(1, 7);
        let (registered, _, _) = management_capsule_fixture(false);
        let mut pending =
            SharedRecoveryManifest::new(registered.generation(), registered.committee().clone())
                .unwrap();
        pending
            .apply_management_registration(registered.management_slots()[0].registration(), 1, 3)
            .unwrap();
        let original = management_observation_for_test(&registration, 10, false);
        let mut certified = pending.clone();
        certified.observe(&original).unwrap();
        assert_eq!(
            super::certified_live_recovery_observation(
                &certified,
                Some(&certified),
                original.observation(),
            ),
            Some(original.observation()),
        );
        assert!(
            super::certified_live_recovery_observation(&certified, None, original.observation())
                .is_none()
        );
        assert!(
            super::certified_live_recovery_observation(
                &pending,
                Some(&certified),
                original.observation(),
            )
            .is_none(),
            "a certified baseline alone must not resurrect missing live evidence",
        );
        let substituted = management_observation_for_test(&registration, 11, false);
        assert_eq!(
            substituted.observation().input_id(),
            original.observation().input_id()
        );
        let mut changed = pending.clone();
        changed.observe(&substituted).unwrap();
        assert!(
            super::certified_live_recovery_observation(
                &changed,
                Some(&certified),
                substituted.observation(),
            )
            .is_none(),
            "identical input with a different complete claim is not certified membership",
        );
        assert!(
            super::certified_live_recovery_observation(
                &changed,
                Some(&certified),
                original.observation(),
            )
            .is_none(),
            "the preliminary lookup cannot replace the audited live observation",
        );
        let mut outcome = original.observation().outcome().clone();
        let crate::agent_sdk::RuntimeOutcome::Completed(Ok(reply)) = &mut outcome else {
            panic!("fixture must have a completed reply");
        };
        reply.reply[0] ^= 1;
        let changed_outcome =
            super::super::shared_recovery::VerifiedSharedRecoveryObservation::from_validated_replay(
                original.observation().raft_index(),
                original.observation().raft_term(),
                original.observation().claim(),
                original.observation().input(),
                &outcome,
            )
            .unwrap();
        let mut changed = pending;
        changed.observe(&changed_outcome).unwrap();
        assert!(
            super::certified_live_recovery_observation(
                &changed,
                Some(&certified),
                changed_outcome.observation(),
            )
            .is_none(),
            "matching input and complete claim do not certify substituted result bytes",
        );
    }

    #[test]
    fn recovery_hot_validation_checks_each_distinct_two_holder_observation_once() {
        use super::super::shared_recovery::management::{
            SharedManagementRecoveryRegistration, SharedManagementRecoveryRegistrationRequest,
        };
        use super::super::shared_recovery::{
            SharedRecoveryManifest, management_observation_for_test,
            management_recovery_fixture_for_test,
        };
        use ed25519_dalek::{Signer as _, SigningKey};
        let first = management_recovery_fixture_for_test(1, 7);
        let second = management_recovery_fixture_for_test(2, 7);
        assert_eq!(first.envelope(), second.envelope());
        let (registered, member, _) = management_capsule_fixture(false);
        let mut manifest =
            SharedRecoveryManifest::new(first.generation(), registered.committee().clone())
                .unwrap();
        manifest
            .apply_management_registration(registered.management_slots()[0].registration(), 1, 3)
            .unwrap();
        let request = SharedManagementRecoveryRegistrationRequest::new(
            second.generation(),
            second.committee(),
            second.owner(),
            first.owner(),
            1,
            None,
            vec![member],
        )
        .unwrap();
        let signature = super::super::shared_commit::ReplicaCommitSignature::new(
            second.owner(),
            SigningKey::from_bytes(&[2; 32])
                .sign(&request.signing_message().0)
                .to_bytes(),
        )
        .unwrap();
        manifest
            .apply_management_registration(
                &SharedManagementRecoveryRegistration::new(request, signature).unwrap(),
                2,
                3,
            )
            .unwrap();
        let invoke = management_observation_for_test(&first, 10, false);
        let acknowledge = management_observation_for_test(&first, 11, true);
        manifest.observe(&invoke).unwrap();
        manifest.observe(&acknowledge).unwrap();
        assert_eq!(
            manifest
                .management_slots()
                .iter()
                .flat_map(|slot| slot.observations())
                .count(),
            4,
        );
        let unique = super::unique_recovery_observations(&manifest);
        assert_eq!(
            unique,
            vec![invoke.observation(), acknowledge.observation()]
        );
        assert_ne!(
            unique[0], unique[1],
            "Invoke and ACK proofs must remain distinct"
        );
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn external_recovery_budget_covers_every_legal_live_suffix() {
        use crate::agent_sdk::{state_blocks, state_change, state_tree};
        let (fetches, bytes) = super::external_recovery_limits();
        let mut budget = state_blocks::ReadBudget::new(fetches, bytes);
        let scope = state_blocks::BlockScope::new(
            crate::agent_sdk::SpaceId([1; 32]),
            crate::agent_sdk::AgentId([2; 32]),
            crate::agent_sdk::Hash([3; 32]),
            crate::agent_sdk::StateLane::Linear,
        )
        .unwrap();
        let (reference, _) = scope.encode_block(&[0]).unwrap();
        // A finite exact accounting assertion, including maximum persisted
        // emitted-block reads and worst-case repeated genesis chunks.
        let suffix_fetches = super::super::journal::MAX_REPLAY_SUFFIX_ENTRIES as u32
            * (super::EXTERNAL_OPERATION_FETCHES + state_change::MAX_STATE_CHANGE_BLOCKS as u32);
        let suffix_bytes = super::super::journal::MAX_REPLAY_SUFFIX_ENTRIES as u64
            * (super::EXTERNAL_OPERATION_BYTES + state_change::MAX_STATE_CHANGE_BYTES as u64);
        assert!(fetches > suffix_fetches);
        assert!(bytes > suffix_bytes);
        assert_eq!(
            fetches - suffix_fetches,
            2 * state_change::MAX_STATE_CHANGE_BLOCKS as u32
                * (1 + state_tree::MAX_TREE_VALUE_BYTES
                    .div_ceil(state_blocks::MAX_STATE_BLOCK_BYTES) as u32)
        );
        assert_eq!(
            bytes - suffix_bytes,
            2 * (state_change::MAX_STATE_CHANGE_BYTES as u64
                + state_change::MAX_STATE_CHANGE_BLOCKS as u64
                    * state_tree::MAX_TREE_VALUE_BYTES as u64)
        );
        let _permit = budget.begin_fetch(scope, reference).unwrap();
        assert_eq!(budget.remaining(), (fetches - 1, bytes - 1));
    }

    #[test]
    fn actor_predecessor_is_exact_across_borrows_and_refuses_zero() {
        use crate::agent_sdk::ActorId;

        assert_eq!(exclusive_actor_predecessor(ActorId::ZERO), None);
        let mut minimum = [0_u8; 32];
        minimum[31] = 1;
        assert_eq!(exclusive_actor_predecessor(ActorId(minimum)), None);
        let mut target = [0_u8; 32];
        target[30] = 1;
        let mut predecessor = [0_u8; 32];
        predecessor[31] = u8::MAX;
        assert_eq!(
            exclusive_actor_predecessor(ActorId(target)),
            Some(ActorId(predecessor))
        );
        assert_eq!(
            exclusive_actor_predecessor(ActorId([u8::MAX; 32])),
            Some(ActorId({
                let mut bytes = [u8::MAX; 32];
                bytes[31] -= 1;
                bytes
            }))
        );
    }
}
