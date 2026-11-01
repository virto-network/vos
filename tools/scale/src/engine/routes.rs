use super::*;

/// Where each agent's calls and queries go: calls to its leader as last
/// learned, queries to a follower; a node that failed a request left out
/// for [`BACKOFF`], the leader's place moving to the next replica.
pub(super) struct Routes {
    pub(super) leaders: Vec<usize>,
    pub(super) down: Vec<Option<Instant>>,
}

impl Routes {
    pub(super) fn up(&self, node: usize, now: Instant) -> bool {
        self.down[node].is_none_or(|until| until <= now)
    }

    pub(super) fn call(&self, agent: usize) -> usize {
        self.leaders[agent]
    }

    /// A follower of `replicas` up now, by `user`; else the leader.
    pub(super) fn query(&self, agent: usize, replicas: &[usize], user: u64, now: Instant) -> usize {
        let leader = self.leaders[agent];
        let followers: Vec<usize> = replicas
            .iter()
            .copied()
            .filter(|node| *node != leader && self.up(*node, now))
            .collect();
        match followers.len() {
            0 => leader,
            n => followers[(user % n as u64) as usize],
        }
    }

    /// `node` failed a request to `agent`: out for a while, and if it was
    /// the leader's place, the next replica up takes it.
    pub(super) fn failed(&mut self, agent: usize, replicas: &[usize], node: usize, now: Instant) {
        self.down[node] = Some(now + BACKOFF);
        if self.leaders[agent] != node {
            return;
        }
        let at = replicas
            .iter()
            .position(|replica| *replica == node)
            .unwrap_or(0);
        let next = (1..=replicas.len())
            .map(|step| replicas[(at + step) % replicas.len()])
            .find(|replica| self.up(*replica, now))
            .unwrap_or(replicas[(at + 1) % replicas.len()]);
        self.leaders[agent] = next;
    }
}
