//! The outbox's deliveries: each target's window, sent after a batch, again
//! in rounds, and after a restart.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use vos_wire::batch::Message;
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::records::unstored;
use vos_wire::result::Outgoing;

use super::Leader;
use super::window::Window;
use crate::fault::{Fault, read};
use crate::lock;
use crate::node::{Agent, Inner};
use crate::store::Snapshot;

impl Leader {
    /// Deliver every message in the outbox above its target's ack: what a
    /// crash, or an earlier leader, may have left unsent. Each target's
    /// group here is let settle first: after a restart, it may not have
    /// elected yet.
    pub(super) async fn recover(&mut self, inner: &Inner) -> Result<(), Fault> {
        let snapshot = inner.store.snapshot();
        let mut targets = BTreeSet::new();
        for row in snapshot.scan(self.id, &keys::outbox_prefix(), None) {
            let (key, _) = row.map_err(|error| Fault::Infrastructure(error.to_string()))?;
            let to = key[key.len() - 12..key.len() - 8]
                .try_into()
                .expect("an outbox key holds its target");
            targets.insert(AgentId(u32::from_be_bytes(to)));
        }
        for to in targets {
            let _ = inner.settled(to).await;
            if let Err(fault) = self.deliver(inner, &snapshot, to) {
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    "delivery failed: {}",
                    fault.message()
                );
                // A window all the same, whose round reads it again.
                let round = inner.settings.resend_round;
                let mut window = Window::new(0, u64::from(inner.number), round);
                window.last = 1;
                self.windows.entry(to).or_insert(window);
            }
        }
        Ok(())
    }

    /// Send `to` what the outbox holds past what this leadership sent it,
    /// in order, within its window.
    pub(super) fn deliver(
        &mut self,
        inner: &Inner,
        snapshot: &Snapshot,
        to: AgentId,
    ) -> Result<(), Fault> {
        let acked = read::<u64>(snapshot, self.id, &keys::acked(to))?.unwrap_or(0);
        let last = read::<u64>(snapshot, self.id, &keys::pair_out(to))?.unwrap_or(0);
        let turn = u64::from(inner.number);
        let round = inner.settings.resend_round;
        let window = self
            .windows
            .entry(to)
            .or_insert_with(|| Window::new(acked, turn, round));
        window.ack(acked);
        window.last = window.last.max(last);
        let after = window.through();
        if after >= window.last {
            return Ok(());
        }
        let mut prefix = keys::outbox(to, 0);
        prefix.truncate(prefix.len() - 8);
        let cursor = keys::outbox(to, after);
        for row in snapshot.scan(self.id, &prefix, Some(&cursor)) {
            let (key, value) = row.map_err(|error| Fault::Infrastructure(error.to_string()))?;
            let sequence = u64::from_be_bytes(key[key.len() - 8..].try_into().expect("a sequence"));
            let Some(outgoing) = unstored(&value).and_then(|bytes| {
                <Outgoing as vos_wire::Decode>::decode(bytes)
                    .ok()
                    .map(|(outgoing, _)| outgoing)
            }) else {
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    sequence,
                    "an unreadable outbox entry"
                );
                break;
            };
            let size = outgoing.body.payload_len() + 64;
            let window = self.windows.get_mut(&to).expect("the target's window");
            if window.full(size) {
                break;
            }
            let message = Message {
                from: self.id,
                sequence,
                body: outgoing.body,
            };
            // Nowhere to send it now, or a full queue here: it waits in the
            // outbox for the next round.
            if !inner.deliver_message(to, message, window.turn) {
                break;
            }
            window.sent.push_back((sequence, size));
            window.bytes += size;
        }
        Ok(())
    }

    /// Send again, from its acknowledgement, the window of each target
    /// whose acknowledgement stayed behind its outbox for its wait, and of
    /// each that found this agent behind it, now or deferred until now.
    pub(super) fn rounds(&mut self, inner: &Inner, agent: &Agent) {
        let now = Instant::now();
        let behind = std::mem::take(&mut lock(&agent.queue).behind);
        self.windows
            .retain(|_, window| window.last > window.acked || !window.sent.is_empty());
        let mut again = BTreeSet::new();
        for (to, window) in &mut self.windows {
            if window.due().is_some_and(|due| due <= now) {
                window.round();
                again.insert(*to);
            } else if window.deferred().is_some_and(|at| at <= now) && window.behind(now) {
                again.insert(*to);
            }
        }
        for to in behind {
            if !again.contains(&to)
                && let Some(window) = self.windows.get_mut(&to)
                && window.behind(now)
            {
                again.insert(to);
            }
        }
        if again.is_empty() {
            return;
        }
        let snapshot = inner.store.snapshot();
        for to in again {
            if let Err(fault) = self.deliver(inner, &snapshot, to) {
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    "delivery failed: {}",
                    fault.message()
                );
            }
        }
    }

    /// Acknowledge each sender's messages through the sequence given.
    pub(super) fn acknowledge(&self, inner: &Inner, acks: HashMap<AgentId, u64>) {
        for (sender, sequence) in acks {
            inner.acknowledge(sender, self.id, sequence);
        }
    }
}
