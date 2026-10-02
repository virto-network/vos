//! Feature-gated observation seam for the integrated three-voter fixture.
//! This neither registers a route nor grants admission/finality authority.

use crate::agent::genesis::{AgentGenesisArchiveRecord, MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES};
use crate::agent::journal::{AgentJournalGenesis, CanonicalJournalRecord as _};
use crate::agent::shared_raft::AgentGenerationRouteKey;
use crate::network::agent_protocol::{AgentGenerationRoute, RaftRole, RaftStatus};
use crate::service::ServiceWire as _;
use vos_agent_sdk::{Hash, NodeId, SpaceId};

use super::Network;

fn archive_route(bytes: &[u8]) -> Result<(AgentGenerationRoute, Vec<NodeId>), String> {
    if bytes.len() > MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES {
        return Err("Shared status fixture archive exceeds its existing bound".into());
    }
    let archive = AgentGenesisArchiveRecord::decode(bytes)
        .map_err(|error| format!("invalid Shared status fixture archive: {error:?}"))?;
    if archive.encode() != bytes {
        return Err("Shared status fixture archive is not canonical".into());
    }
    let provision = archive.provision();
    let descriptor = provision
        .proposal()
        .clean_descriptor()
        .map_err(|error| format!("Shared status fixture requires clean Create: {error:?}"))?;
    let replicas = provision.replicas();
    if descriptor.identity.profile != vos_agent_sdk::AgentProfile::Shared
        || replicas.profile() != crate::agent::AgentProfile::Shared
        || replicas.members().len() != 3
        || replicas.voter_count() != 3
    {
        return Err("Shared status fixture requires the exact fixed-three voter archive".into());
    }
    let admission = provision
        .admission_record()
        .map_err(|error| format!("invalid Shared status fixture admission: {error:?}"))?;
    let genesis = AgentJournalGenesis {
        admission: admission.id(),
        create: provision.proposal().create().clone(),
    };
    genesis
        .validate()
        .map_err(|error| format!("invalid Shared status fixture genesis: {error:?}"))?;
    let locator = provision.proposal().locator();
    let generation =
        AgentGenerationRouteKey::new(locator.space, locator.agent, genesis.id(), admission.id())
            .map_err(|error| format!("invalid Shared status fixture route: {error:?}"))?;
    let members = replicas
        .members()
        .iter()
        .map(|member| NodeId(member.replica().node.0))
        .collect();
    Ok((
        AgentGenerationRoute {
            space: SpaceId(locator.space.0),
            agent: vos_agent_sdk::AgentId(locator.agent.0),
            generation: Hash(generation.replication_id()),
        },
        members,
    ))
}

fn observed_role(
    status: RaftStatus,
    target: NodeId,
    members: &[NodeId],
) -> Result<(bool, bool, Option<NodeId>), String> {
    if status.members != members
        || status.joint_old.is_some()
        || status
            .leader
            .is_some_and(|leader| members.binary_search(&leader).is_err())
        || (status.role == RaftRole::Leader && status.leader != Some(target))
    {
        return Err(
            "Shared status fixture response differs from the exact fixed-three route".into(),
        );
    }
    Ok((
        status.role == RaftRole::Follower,
        status.role == RaftRole::Leader,
        status.leader,
    ))
}

impl Network {
    /// Observe an actual remote voter's role for a canonical, already attached
    /// ordinary Shared archive in the integrated release fixture. The tuple is
    /// `(is_follower, is_leader, leader_hint)`. Transitional roles set both
    /// booleans false. This is not Ready, quorum, finality or admission evidence.
    ///
    /// Use a different live voter's Network to observe the issuer: this seam
    /// deliberately does not synthesize a local/self-target status response.
    #[doc(hidden)]
    pub fn shared_member_raft_status_fixture(
        &self,
        canonical_archive: &[u8],
        target: NodeId,
    ) -> Result<Option<(bool, bool, Option<NodeId>)>, String> {
        let (route, members) = archive_route(canonical_archive)?;
        let local = self.agent_node_id();
        if target == local
            || members.binary_search(&target).is_err()
            || members.binary_search(&local).is_err()
        {
            return Err("Shared status fixture requires two distinct archive voters".into());
        }
        let registration = self
            .agent_routes
            .lock()
            .map_err(|_| "Shared status fixture route directory is unavailable".to_owned())?
            .get(&route)
            .cloned()
            .ok_or_else(|| "Shared status fixture route is not registered".to_owned())?;
        if registration.members != members {
            return Err("Shared status fixture registered roster differs from archive".into());
        }
        // Existing pending-reply handling authenticates target PeerId, sender
        // NodeId, exact generation and StatusReply variant. The existing Agent
        // transport deadline and bounded outbound Raft pool remain unchanged.
        let response = futures_executor::block_on(self.send_agent_raft_status(target, route))
            .map_err(|_| "Shared status fixture reply channel closed".to_owned())?
            .map_err(|error| format!("Shared status fixture transport refused: {error:?}"))?;
        response
            .map(|status| observed_role(status, target, &members))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(role: RaftRole, leader: Option<NodeId>) -> RaftStatus {
        RaftStatus {
            role,
            current_term: 4,
            commit_index: 2,
            last_applied: 2,
            last_log_index: 2,
            members: vec![NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32])],
            joint_old: None,
            active_config_index: None,
            leader,
        }
    }

    #[test]
    fn shared_member_status_fixture_keeps_actual_role_and_exact_roster() {
        let target = NodeId([2; 32]);
        let members = status(RaftRole::Follower, None).members;
        for (role, follower, leader) in [
            (RaftRole::Follower, true, false),
            (RaftRole::PreCandidate, false, false),
            (RaftRole::Candidate, false, false),
            (RaftRole::Leader, false, true),
        ] {
            assert_eq!(
                observed_role(status(role, Some(target)), target, &members).unwrap(),
                (follower, leader, Some(target))
            );
        }
        let mut wrong = status(RaftRole::Follower, Some(target));
        wrong.members[2] = NodeId([4; 32]);
        assert!(observed_role(wrong, target, &members).is_err());
        let mut joint = status(RaftRole::Follower, Some(target));
        joint.joint_old = Some(members.clone());
        assert!(observed_role(joint, target, &members).is_err());
        assert!(
            observed_role(status(RaftRole::Leader, Some(members[0])), target, &members).is_err()
        );
        assert!(
            observed_role(
                status(RaftRole::Follower, Some(NodeId([4; 32]))),
                target,
                &members
            )
            .is_err()
        );
    }

    #[test]
    fn shared_member_status_fixture_rejects_malformed_archive_before_transport() {
        assert!(archive_route(&[]).is_err());
        assert!(archive_route(b"OGAR").is_err());
        assert!(archive_route(&vec![0; MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES + 1]).is_err());
    }
}
