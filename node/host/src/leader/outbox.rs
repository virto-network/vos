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
use crate::store::Snapshot;

impl Leader {
    /// Deliver every message in the outbox above its target's ack: what a
    /// crash, or an earlier leader, may have left unsent. Each target's
    /// group here is let settle first: after a restart, it may not have
    /// elected yet.
    pub(super) async fn recover(&mut self) -> Result<(), Fault> {
        let snapshot = self.inner.store.snapshot();
        let mut targets = BTreeSet::new();
        for row in snapshot.scan(self.id, &keys::outbox_prefix(), None) {
            let (key, _) = row?;
            let (to, _) = keys::outbox_entry(&key).expect("an outbox key holds its target");
            targets.insert(to);
        }
        for to in targets {
            let _ = self.inner.settled(to).await;
            if !self.deliver(&snapshot, to) {
                // A window all the same, whose round reads it again.
                let round = self.inner.settings.resend_round;
                let mut window = Window::new(0, u64::from(self.inner.number), round);
                window.holds(1);
                self.windows.entry(to).or_insert(window);
            }
        }
        Ok(())
    }

    /// Send `to` what the outbox holds past what this leadership sent it:
    /// false, logged, when that failed. The outbox keeps what it holds,
    /// for the next send to `to`, a round, or a restart.
    pub(super) fn deliver(&mut self, snapshot: &Snapshot, to: AgentId) -> bool {
        let Err(fault) = self.send_window(snapshot, to) else {
            return true;
        };
        tracing::error!(
            agent = self.id.0,
            to = to.0,
            "delivery failed: {}",
            fault.message()
        );
        false
    }

    /// Send `to` what the outbox holds past what this leadership sent it,
    /// in order, within its window.
    fn send_window(&mut self, snapshot: &Snapshot, to: AgentId) -> Result<(), Fault> {
        let acked = read::<u64>(snapshot, self.id, &keys::acked(to))?.unwrap_or(0);
        let last = read::<u64>(snapshot, self.id, &keys::pair_out(to))?.unwrap_or(0);
        let turn = u64::from(self.inner.number);
        let round = self.inner.settings.resend_round;
        let window = self
            .windows
            .entry(to)
            .or_insert_with(|| Window::new(acked, turn, round));
        window.ack(acked);
        window.holds(last);
        let after = window.through();
        let cursor = keys::outbox(to, after);
        for row in snapshot.scan(self.id, &keys::outbox_to(to), Some(&cursor)) {
            let (key, value) = row?;
            let (_, sequence) = keys::outbox_entry(&key).expect("an outbox key holds a sequence");
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
            if !self.inner.deliver_message(to, message, window.turn()) {
                break;
            }
            window.push(sequence, size);
        }
        Ok(())
    }

    /// Send again, from its acknowledgement, the window of each target
    /// whose acknowledgement stayed behind its outbox for its wait, and of
    /// each that found this agent behind it, now or deferred until now.
    pub(super) fn rounds(&mut self) {
        let now = Instant::now();
        let behind = std::mem::take(&mut lock(&self.agent.queue).behind);
        self.windows.retain(|_, window| !window.idle());
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
        let snapshot = self.inner.store.snapshot();
        for to in again {
            self.deliver(&snapshot, to);
        }
    }

    pub(super) fn acknowledge(&self, acks: HashMap<AgentId, u64>) {
        for (sender, sequence) in acks {
            self.inner.acknowledge(sender, self.id, sequence);
        }
    }
}
