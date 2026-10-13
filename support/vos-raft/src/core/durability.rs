//! A replica's ordered writes, and what waits for them: answers at a term
//! not yet durable, and acknowledgements of entries not yet durable.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::{Action, Answer, Core, PendingAck, PendingWrite, Write};
use crate::config::NodeId;
use crate::log_entry::LogEntry;
use crate::message::{AppendResult, Message};
use crate::meta::Meta;

impl<N: NodeId> Core<N> {
    fn meta(&self) -> Meta<N> {
        Meta {
            current_term: self.term,
            voted_for: self.vote,
            commit_index: self.commit,
            snap_last_index: self.log.snap_index(),
            snap_last_term: self.log.snap_term(),
        }
    }

    fn open_write(&mut self) -> &mut Write<N> {
        if self.open.is_none() {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.open = Some(Write {
                seq,
                truncate_after: None,
                entries: Vec::new(),
                meta: None,
                active_config: None,
                sync: false,
            });
        }
        self.open.as_mut().expect("opened above")
    }

    pub(super) fn close_write(&mut self) {
        let Some(write) = self.open.take() else {
            return;
        };
        self.writes.push_back(PendingWrite {
            seq: write.seq,
            hard: write
                .meta
                .as_ref()
                .map(|meta| (meta.current_term, meta.voted_for)),
        });
        self.actions.push(Action::Write(write));
    }

    /// Record the hard state; `sync` when the term or vote changed.
    pub(super) fn write_meta(&mut self, sync: bool) {
        let meta = self.meta();
        let write = self.open_write();
        write.meta = Some(meta);
        write.sync |= sync;
        if sync {
            self.term_seq = self.open.as_ref().expect("open").seq;
        }
    }

    pub(super) fn write_truncate(&mut self, after: u64) {
        if self
            .open
            .as_ref()
            .is_some_and(|open| !open.entries.is_empty())
        {
            self.close_write();
        }
        let write = self.open_write();
        write.truncate_after = Some(write.truncate_after.map_or(after, |at| at.min(after)));
        write.sync = true;
        self.log.truncate_after(after);
        self.durable_index = self.durable_index.min(after);
        self.written.retain(|&(first, _)| first <= after);
    }

    pub(super) fn write_entries(&mut self, entries: Vec<LogEntry<N>>) {
        let Some(first) = entries.first().map(|entry| entry.index) else {
            return;
        };
        self.log.append(&entries);
        let write = self.open_write();
        write.entries.extend(entries);
        write.sync = true;
        let seq = write.seq;
        if self.written.back().is_none_or(|&(_, write)| write != seq) {
            self.written.push_back((first, seq));
        }
        // Entries above the durable index may not be in the store yet.
        self.log.evict(self.durable_index + 1);
    }

    /// Forget which writes appended entries now durable.
    pub(super) fn forget_written(&mut self) {
        if self.durable_index >= self.log.last_index() {
            self.written.clear();
            return;
        }
        while self
            .written
            .get(1)
            .is_some_and(|&(first, _)| first <= self.durable_index + 1)
        {
            self.written.pop_front();
        }
    }

    /// Record the configuration in effect.
    pub(super) fn write_active_config(&mut self) {
        let record = self.active.clone();
        let write = self.open_write();
        write.active_config = Some(record);
        write.sync = true;
    }

    pub(super) fn send(&mut self, to: N, message: Message<N>) {
        self.actions.push(Action::Send { to, message });
    }

    /// Send `message` to every other member.
    pub(super) fn broadcast(&mut self, message: Message<N>) {
        let me = self.cfg.me;
        let peers = self.active.members().filter(|&member| member != me);
        self.actions.extend(peers.map(|to| Action::Send {
            to,
            message: message.clone(),
        }));
    }

    /// Send now if the message's term is durable; otherwise once the write
    /// of the current term is.
    pub(super) fn respond(&mut self, to: N, message: Message<N>) {
        if message.term() <= self.durable_term {
            self.send(to, message);
        } else {
            self.releases.push((self.term_seq, to, message));
        }
    }

    pub(super) fn answer(&mut self, answer: Answer) {
        self.actions.push(Action::Answer(answer));
    }

    /// Send every acknowledgement whose claim is now durable: the newest
    /// per leader, which covers older ones.
    pub(super) fn flush_acks(&mut self) {
        let matched = self.durable_index.min(self.verified);
        let ready: Vec<PendingAck<N>> = self
            .pending_acks
            .extract_if(.., |ack| matched >= ack.upto)
            .collect();
        let mut answered = BTreeSet::new();
        for ack in ready.into_iter().rev() {
            if answered.insert(ack.leader) {
                self.respond(
                    ack.leader,
                    Message::AppendAnswer {
                        term: self.term,
                        round: ack.round,
                        commit: ack.commit,
                        result: AppendResult::Matched { matched },
                    },
                );
            }
        }
    }
}
