//! The core's actions run: its messages sent, its writes made, and the
//! replica's health and ready writes reported to it.

use super::*;

impl Driver {
    /// Tell the core whether to hand leadership over and not campaign, as
    /// it does while its writer is stalled. A replica whose leader loop
    /// stopped for good (`retired`) is reported as stalled on purpose.
    pub(super) fn report_health(&mut self) {
        // A replica whose recovered entries wait for their blobs neither
        // campaigns nor leads: as leader it would wait on its own no-op
        // behind them, and hold up the group.
        let handing_over =
            self.retired || self.inner.storage.stalled() || self.reports.recovering();
        if handing_over != self.handing_over {
            self.handing_over = handing_over;
            self.core.writer_health(handing_over);
        }
    }

    /// Run the core's actions until it has none. False when storage
    /// failed: the node halts. A round's messages go out before its
    /// writes are waited on: the core holds back whatever must wait for
    /// one, and a leader's appends need not wait for its own fsync.
    pub(super) async fn process(&mut self) -> bool {
        loop {
            let actions = self.core.take_actions();
            if actions.is_empty() {
                return true;
            }
            let (sends, rest): (Vec<_>, Vec<_>) = actions
                .into_iter()
                .partition(|action| matches!(action, Action::Send { .. }));
            for action in sends.into_iter().chain(rest) {
                if !self.act(action).await {
                    return false;
                }
            }
        }
    }

    pub(super) async fn act(&mut self, action: Action<NodeNumber>) -> bool {
        match action {
            Action::Write(write) => return self.write(write).await,
            // Refused, it is dropped: Raft sends again.
            Action::Send { to, message } => self.inner.send(
                to,
                &PeerMessage::Raft {
                    agent: self.shared.agent,
                    message: crate::peer::to_wire(&message),
                },
            ),
            Action::LoadEntries(load) => {
                let store = self.inner.store.clone();
                let agent = self.shared.agent;
                let loaded = self
                    .inner
                    .offload(move || raft::load(&store, agent, &load))
                    .await;
                match loaded {
                    Some(Ok(entries)) => self.core.loaded(load, entries),
                    // Nothing loaded: the core forgets the load, and asks
                    // again when its peers next answer.
                    _ => {
                        tracing::warn!(agent = self.shared.agent.0, "a log load failed");
                        self.core.loaded(load, Vec::new());
                    }
                }
            }
            Action::Committed { index } => self.shared.update(|state| {
                state.commit = index;
                state.commit_at = Some(Instant::now());
            }),
            Action::CompactBound { through, .. } => {
                self.compact_bound = self.compact_bound.max(through);
                self.compact_due = true;
            }
            Action::SendSnapshot { to, .. } => self.send_snapshot(to),
            Action::Answer(Answer::Propose { token, result }) => {
                // A held blob stays held until its entry is written, and
                // touched: its row keeps it from then on.
                if let Some(held) = self.held_proposals.remove(&token)
                    && let Ok(index) = result
                    && index > self.last_index
                {
                    self.held_entries.push((index, held));
                }
                if let Some(answer) = self.answers.proposals.remove(&token) {
                    let _ = answer.try_send((result, Instant::now()));
                }
            }
            Action::Answer(Answer::ReadIndex { token, result }) => {
                if let Some(answer) = self.answers.reads.remove(&token) {
                    let _ = answer.try_send(result);
                }
            }
            Action::Answer(Answer::ChangeMembership { token, result }) => {
                if let Some(answer) = self.answers.memberships.remove(&token) {
                    let _ = answer.try_send(result);
                }
            }
            Action::Changed { term, role, leader } => {
                // A leadership's streams end with it.
                if role != Role::Leader {
                    self.snapshots.shipments.clear();
                }
                self.inner.led_here(self.shared.agent, role == Role::Leader);
                // Becoming leader, the core appended its term's no-op last.
                let leading_from =
                    (role == Role::Leader).then(|| self.core.status().last_log_index);
                self.shared.update(|state| {
                    state.role = role;
                    state.term = term;
                    state.leader = leader;
                    state.leading_from = leading_from;
                });
                if role != Role::Leader {
                    // A leader that removed itself steps down as the final
                    // configuration commits: it says so itself, at once,
                    // rather than leave it to the next leader's election.
                    let status = self.core.status();
                    let me = self.inner.number;
                    let removed = self.announced.is_some()
                        && status.joint_old.is_none()
                        && !status.members.contains(&me)
                        && status.commit_index >= status.active_config_index.unwrap_or(0);
                    if removed {
                        self.announce_placement();
                    }
                    self.announced = None;
                    // It retires once it steps down; a group stopping does
                    // not.
                    if !self.shared.state().stopped {
                        self.inner.reconsider(self.shared.agent);
                    }
                }
            }
        }
        true
    }

    pub(super) async fn write(&mut self, write: Write<NodeNumber>) -> bool {
        let changes = raft::changes(self.shared.agent, &write);
        let named = raft::named(&changes);
        if let Err(error) = self.inner.storage.commit(changes).await {
            tracing::error!(
                agent = self.shared.agent.0,
                "a log write failed ({error}); the node stops and needs a restart"
            );
            self.inner.halt();
            return false;
        }
        self.core.durable(write.seq);
        if let Some(after) = write.truncate_after {
            // What was written past the cut is gone, even where its write
            // is still waiting for blobs.
            self.last_index = self.last_index.min(after);
            for (_, last) in &mut self.writes {
                *last = (*last).min(after);
            }
            self.shared
                .update(|state| state.written = state.written.min(after));
        }
        if let Some(last) = write.entries.last() {
            self.last_index = last.index;
        }
        self.writes.push_back((write.seq, self.last_index));
        let hashes: Vec<[u8; 32]> = named
            .iter()
            .flat_map(|(_, hashes)| hashes.iter().copied())
            .collect();
        let stored: BTreeSet<[u8; 32]> = if hashes.is_empty() {
            BTreeSet::new()
        } else {
            // Touched, a blob stays while an entry comes to rely on it.
            match self.inner.blobs.touch(hashes).await {
                Ok(stored) => stored.into_iter().collect(),
                Err(error) => {
                    tracing::warn!(agent = self.shared.agent.0, "a blob touch failed: {error}");
                    BTreeSet::new()
                }
            }
        };
        self.reports
            .written(&write, named, |hash| stored.contains(hash));
        // A held blob's entry is written and touched now, or gone in this
        // write's truncation.
        let truncated = write.truncate_after;
        self.held_entries.retain(|(index, _)| {
            *index > self.last_index && truncated.is_none_or(|after| *index <= after)
        });
        self.report_ready();
        true
    }

    /// Report the writes whose entries now have their blobs.
    pub(super) fn report_ready(&mut self) {
        let blobs = &self.inner.blobs;
        let Some(seq) = self
            .reports
            .ready(|hash| blobs.contains(hash).unwrap_or(false))
        else {
            return;
        };
        // The recovered log's entries the core counted durable already.
        if seq != raft::RECOVERED {
            self.core.entries_durable(seq);
        }
        let mut written = None;
        while let Some(&(at, last)) = self.writes.front() {
            if at > seq {
                break;
            }
            if at == raft::RECOVERED {
                tracing::info!(
                    agent = self.shared.agent.0,
                    "the lost blobs of committed entries arrived"
                );
            }
            written = Some(last);
            self.writes.pop_front();
        }
        if let Some(written) = written {
            self.shared.update(|state| state.written = written);
        }
    }
}
