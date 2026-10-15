//! A group's membership as its placement: when a replica is established
//! in it, and the placement its leader announces.

use std::sync::Arc;

use vos_raft::Role;
use vos_raft::core::Core;
use vos_wire::peer::{NodeNumber, Placement};

use super::Driver;

impl Driver {
    /// Note when this replica holds a committed configuration naming it,
    /// and, leading, announce where the agent runs whenever that changes.
    pub(super) fn settle_membership(&mut self) {
        if established(&self.core, self.inner.number) && !self.shared.state().established {
            self.shared.update(|state| state.established = true);
        }
        if self.core.role() != Role::Leader {
            return;
        }
        self.announce_placement();
    }

    /// Announce where the agent runs, as this replica's core has it, when
    /// that changed since it last did.
    pub(super) fn announce_placement(&mut self) {
        let status = self.core.status();
        let index = status.active_config_index.unwrap_or(0);
        let replicas = nodes(status.members, status.joint_old.clone());
        // The configuration before, or, once that is compacted away, the
        // log's first, which may be this one. It matters while a placement
        // is uncommitted, and names a leader the change removed, which
        // leads until the configuration without it commits.
        let before = if index == 0 {
            Vec::new()
        } else {
            self.core
                .config_at(index - 1)
                .map(|record| nodes(record.current, record.joint_old))
                .unwrap_or_default()
        };
        let placement = Placement {
            replicas,
            before,
            term: status.current_term,
            index,
            joint: status.joint_old.is_some(),
            committed: status.commit_index >= index,
        };
        let order = placement.order();
        if self.announced == Some(order) {
            return;
        }
        self.announced = Some(order);
        let inner = Arc::clone(&self.inner);
        let agent = self.shared.agent;
        self.inner
            .spawn(async move { inner.place(agent, placement).await });
    }
}

/// The nodes of a configuration, both sets while it is joint, in order.
fn nodes(members: Vec<NodeNumber>, joint_old: Option<Vec<NodeNumber>>) -> Vec<NodeNumber> {
    let mut nodes = members;
    nodes.extend(joint_old.unwrap_or_default());
    nodes.sort_unstable();
    nodes.dedup();
    nodes
}

/// Whether `core` holds a committed configuration naming `me`.
pub(super) fn established(core: &Core<NodeNumber>, me: NodeNumber) -> bool {
    let status = core.status();
    let named = status.members.contains(&me)
        || status
            .joint_old
            .as_ref()
            .is_some_and(|old| old.contains(&me));
    named && status.commit_index >= status.active_config_index.unwrap_or(0)
}
