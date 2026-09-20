//! Permanent ordinary-genesis decisions in authenticated Authority Linear state.
//! Raw archive bytes are not finality evidence without authenticated replay.

use super::*;
use vos::agent::committee::{AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole};
use vos::agent::genesis::{AgentGenesisProvision, MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES};
use vos::service::ServiceWire as _;

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct GenesisPublicationRecord {
    pub agent: [u8; 32],
    pub invocation: [u8; 32],
    authorization: [u8; 32],
    published_at: u64,
    call: Vec<u8>,
    approval: Vec<u8>,
    provision: Vec<u8>,
}

/// Space still needed to publish each approved Shared Create. The three byte
/// vectors have byte alignment; the fixed archived row includes their relative
/// pointers/lengths. Round each reservation to the enclosing state's alignment
/// so insertion cannot consume another pending Create's alignment allowance.
pub(super) fn reserved_publication_bytes(state: &AuthorityLinearState) -> Option<usize> {
    let alignment = core::mem::align_of::<ArchivedAuthorityLinearState>()
        .max(core::mem::align_of::<ArchivedGenesisPublicationRecord>());
    state.retries.iter().try_fold(0usize, |total, pending| {
        let PendingManagementEffect::Create(target) = &pending.effect else {
            return Some(total);
        };
        if target.profile != AgentProfile::Shared as u8
            || state
                .genesis_publications
                .iter()
                .any(|row| row.agent == target.agent)
        {
            return Some(total);
        }
        let bytes = MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES
            .checked_add(pending.credential_call_bytes.len())?
            .checked_add(pending.approval.len())?
            .checked_add(core::mem::size_of::<ArchivedGenesisPublicationRecord>())?
            .checked_add(alignment - 1)?;
        total.checked_add(bytes & !(alignment - 1))
    })
}

pub(super) fn state_bytes_fit(state: &AuthorityLinearState, archived_bytes: usize) -> bool {
    reserved_publication_bytes(state)
        .and_then(|reserved| reserved.checked_add(reserved_terminal_bytes(state)?))
        .and_then(|reserved| archived_bytes.checked_add(reserved))
        .is_some_and(|required| required <= MAX_RUNTIME_STATE_BYTES)
}

/// Keep terminal capacity until the pending Create is acknowledged, even after
/// publication. Conservatively charge complete new live/latest-ACK rows without
/// crediting the pending row or previous latest ACK that finalization removes.
pub(super) fn reserved_terminal_bytes(state: &AuthorityLinearState) -> Option<usize> {
    let alignment = core::mem::align_of::<ArchivedAuthorityLinearState>()
        .max(core::mem::align_of::<ArchivedManagedAgentRow>())
        .max(core::mem::align_of::<ArchivedLatestManagementAckRow>());
    state.retries.iter().try_fold(0usize, |total, pending| {
        let PendingManagementEffect::Create(target) = &pending.effect else {
            return Some(total);
        };
        if target.profile != AgentProfile::Shared as u8 {
            return Some(total);
        }
        let live = core::mem::size_of::<ArchivedManagedAgentRow>()
            .checked_add(
                target
                    .replicas
                    .len()
                    .checked_mul(core::mem::size_of::<ArchivedManagedReplicaRow>())?,
            )?
            .checked_add(target.capabilities.proof_systems.len().checked_mul(32)?)?
            .checked_add(alignment - 1)?;
        let latest = core::mem::size_of::<ArchivedLatestManagementAckRow>()
            .checked_add(pending.credential_call_bytes.len())?
            .checked_add(vos::agent_sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES)?
            .checked_add(alignment - 1)?;
        total
            .checked_add(live & !(alignment - 1))?
            .checked_add(latest & !(alignment - 1))
    })
}

// Native root admission currently pins this exact one-voter operator
// committee, not the enrolled node's transport key. This is not a committee
// supplied by the publication. Rotation needs independently retained history.
fn initial_committee(config: &SystemAuthorityConfiguration) -> Option<AuthorityCommittee> {
    let member = AuthorityCommitteeMember::new(
        vos::service::NodeId(config.bootstrap_node),
        config.bootstrap_credential_public_key,
        AuthorityMemberRole::Voter,
    )
    .ok()?;
    AuthorityCommittee::new(
        vos::service::SpaceId(config.space),
        vos::service::Hash(config.binding.sdk().commitment().0),
        1,
        None,
        vec![member],
    )
    .ok()
}

/// Exact committee used by publication verification in this actor generation.
/// These bytes are data, not proof: hosts must authenticate the query's actor,
/// installed configuration and system journal before trusting them. A future
/// rotation implementation must update this query and publication together.
pub(super) fn signing_committee(config: &SystemAuthorityConfiguration) -> Vec<u8> {
    if !config.is_valid() { return Vec::new(); }
    initial_committee(config).map(|committee| committee.encode()).unwrap_or_default()
}

fn decoded(
    config: &SystemAuthorityConfiguration,
    row: &GenesisPublicationRecord,
) -> Option<AgentGenesisProvision> {
    if row.provision.len() > MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES
        || row.agent == config.system_agent
    {
        return None;
    }
    let provision = AgentGenesisProvision::decode(&row.provision).ok()?;
    let call = AuthorityCredentialCall::decode(&row.call).ok()?;
    let approval = ManagementApproval::decode(&row.approval).ok()?;
    if provision.encode() != row.provision
        || call.encode().ok()? != row.call
        || approval.encode().ok()? != row.approval
        || call.invocation.0 != row.authorization
        || !authority_target_matches(config, &call.authority)
        || provision.proposal().locator().agent.0 != row.agent
        || provision.publication_invocation(call.invocation).ok()?.0 != row.invocation
    {
        return None;
    }
    provision
        .verify_pending_create_at(
            &call,
            &approval,
            &initial_committee(config)?,
            row.published_at,
            &Ed25519CredentialVerifier,
        )
        .ok()?;
    Some(provision)
}

pub(super) fn record_is_valid(
    config: &SystemAuthorityConfiguration,
    row: &GenesisPublicationRecord,
) -> bool {
    decoded(config, row).is_some()
}

fn context_matches(config: &SystemAuthorityConfiguration, context: &InvocationContext) -> bool {
    context.actor.0 == config.binding.issuer.actor
        && context.mode == vos::agent_sdk::MethodMode::Linear
        && context.invocation != InvocationId::ZERO
}

/// Compact public method boundary. The loader is invocation-local in the guest;
/// native tests must supply it explicitly. Publication never falls back to an
/// inline payload or ambient store. Exact bytes remain bound by the derived
/// publication invocation and the pending Create validation below.
pub(super) fn publish_from_blob(
    config: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    authorization: &[u8],
    hash: &[u8],
    len: u64,
    context: &InvocationContext,
    lookup: impl FnOnce(&vos::agent_sdk::BlobRef) -> Option<Vec<u8>>,
) -> Vec<u8> {
    if authorization.len() != 32 || !context_matches(config, context)
        || len > vos::agent::execution::MAX_EXECUTION_AVAILABILITY_BYTES as u64
        || len > MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES as u64
    {
        return Vec::new();
    }
    let Ok(hash) = <[u8; 32]>::try_from(hash) else { return Vec::new() };
    let reference = vos::agent_sdk::BlobRef { hash: vos::agent_sdk::Hash(hash), len };
    let Some(bytes) = lookup(&reference) else { return Vec::new() };
    if !reference.matches(&bytes) { return Vec::new(); }
    publish(config, state, authorization, &bytes, context)
}

pub(super) fn publish(
    config: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    authorization: &[u8],
    bytes: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    authority_row_transaction(|| publish_staged(config, state, authorization, bytes, context))
}

fn publish_staged(
    config: &SystemAuthorityConfiguration,
    state: &mut AuthorityLinearState,
    authorization: &[u8],
    bytes: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    if !authority_state_is_valid(config, state)
        || !context_matches(config, context)
        || bytes.len() > MAX_CLEAN_CREATE_GENESIS_PROVISION_BYTES
    {
        return Vec::new();
    }
    let Ok(authorization) = <[u8; 32]>::try_from(authorization) else {
        return Vec::new();
    };
    let Ok(provision) = AgentGenesisProvision::decode(bytes) else {
        return Vec::new();
    };
    if provision.encode() != bytes
        || provision
            .publication_invocation(InvocationId(authorization))
            .ok()
            != Some(context.invocation)
    {
        return Vec::new();
    }
    let agent = provision.proposal().locator().agent.0;
    let index = match state
        .genesis_publications
        .binary_search_by_key(&agent, |row| row.agent)
    {
        Ok(index) => {
            let row = &state.genesis_publications[index];
            return if row.authorization == authorization
                && row.invocation == context.invocation.0
                && row.provision == bytes
            {
                provision.decision().encode()
            } else {
                Vec::new()
            };
        }
        Err(index) => index,
    };
    if state.genesis_publications.len() >= MAX_MANAGED_AGENTS
        || state.epoch != 1
        || !admin_invocation_is_available(state, context.invocation)
    {
        return Vec::new();
    }
    let Some(pending) = state
        .retries
        .iter()
        .find(|row| row.invocation == authorization)
    else {
        return Vec::new();
    };
    let PendingManagementEffect::Create(target) = &pending.effect else {
        return Vec::new();
    };
    if target.agent != agent {
        return Vec::new();
    }
    let row = GenesisPublicationRecord {
        agent,
        invocation: context.invocation.0,
        authorization,
        published_at: context.observed_slot,
        call: pending.credential_call_bytes.clone(),
        approval: pending.approval.clone(),
        provision: bytes.to_vec(),
    };
    let mut candidate = state.clone();
    candidate.genesis_publications.insert(index, row);
    // The full candidate validator below verifies every publication record,
    // including this new row, before commit. Do not repeat its canonical/QC
    // verification here: duplicate hashing exhausts the bounded guest quota.
    if !refresh_state_integrity_commitment(config, &mut candidate)
        || !authority_state_is_valid(config, &candidate)
    {
        return Vec::new();
    }
    *state = candidate;
    provision.decision().encode()
}

pub(super) fn read(
    config: &SystemAuthorityConfiguration,
    state: &AuthorityLinearState,
    agent: &[u8],
    context: &InvocationContext,
) -> Vec<u8> {
    if !authority_state_is_valid(config, state) || !context_matches(config, context) {
        return Vec::new();
    }
    let Ok(agent) = <[u8; 32]>::try_from(agent) else {
        return Vec::new();
    };
    state
        .genesis_publications
        .binary_search_by_key(&agent, |row| row.agent)
        .ok()
        .and_then(|index| decoded(config, &state.genesis_publications[index]))
        .map(|provision| provision.decision().encode())
        .unwrap_or_default()
}
