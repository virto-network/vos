//! The entry reports a replica owes its core, each once the blobs its
//! entries name are stored.

use std::collections::VecDeque;

use vos_raft::core::Write;

use crate::store::NodeNumber;

/// The entry reports one replica owes its core: its writes in order, each
/// with the blobs its entries name that were missing. A write's entries
/// are reported once its blobs, and every earlier write's, are stored.
#[derive(Default)]
pub(crate) struct EntryReports {
    pending: VecDeque<Pending>,
}

/// The sequence standing for the log a replica recovered, before its
/// core's first write.
pub(crate) const RECOVERED: u64 = 0;

struct Pending {
    seq: u64,
    /// The write's entries that still wait, by index, with their blobs.
    waiting: Vec<(u64, Vec<[u8; 32]>)>,
}

impl EntryReports {
    /// The recovered log's committed entries kept without their blobs
    /// ([`Cut::refetch`]): they wait, as [`RECOVERED`], ahead of every
    /// write.
    pub(crate) fn recovered(&mut self, waiting: Vec<(u64, Vec<[u8; 32]>)>) {
        if !waiting.is_empty() {
            self.pending.push_front(Pending {
                seq: RECOVERED,
                waiting,
            });
        }
    }

    /// Whether recovered entries still wait for their blobs.
    pub(crate) fn recovering(&self) -> bool {
        self.pending
            .front()
            .is_some_and(|pending| pending.seq == RECOVERED)
    }

    /// `write` is durable, its entries naming the blobs `named` lists
    /// ([`super::named`]). A truncation in it drops the waits of the
    /// entries it removed, from earlier writes too. `stored` answers from a
    /// [`crate::blobs::Blobs::touch`] of the write's blobs, so none of them is collected
    /// while the entry comes to rely on it.
    pub(crate) fn written(
        &mut self,
        write: &Write<NodeNumber>,
        named: Vec<(u64, Vec<[u8; 32]>)>,
        stored: impl Fn(&[u8; 32]) -> bool,
    ) {
        if let Some(after) = write.truncate_after {
            for pending in &mut self.pending {
                pending.waiting.retain(|(index, _)| *index <= after);
            }
        }
        let waiting = named
            .into_iter()
            .filter_map(|(index, blobs)| {
                let missing: Vec<[u8; 32]> =
                    blobs.into_iter().filter(|hash| !stored(hash)).collect();
                (!missing.is_empty()).then_some((index, missing))
            })
            .collect();
        self.pending.push_back(Pending {
            seq: write.seq,
            waiting,
        });
    }

    /// The last write whose entries can now be reported, if any.
    pub(crate) fn ready(&mut self, stored: impl Fn(&[u8; 32]) -> bool) -> Option<u64> {
        let mut last = None;
        while let Some(front) = self.pending.front_mut() {
            front
                .waiting
                .retain(|(_, missing)| missing.iter().any(|hash| !stored(hash)));
            if !front.waiting.is_empty() {
                break;
            }
            last = Some(front.seq);
            self.pending.pop_front();
        }
        last
    }

    /// Every blob a waiting write still needs, each once: the host fetches
    /// them together.
    pub(crate) fn missing(&self) -> Vec<[u8; 32]> {
        let mut missing: Vec<[u8; 32]> = self
            .pending
            .iter()
            .flat_map(|pending| pending.waiting.iter())
            .flat_map(|(_, missing)| missing.iter().copied())
            .collect();
        missing.sort_unstable();
        missing.dedup();
        missing
    }

    /// A snapshot switch at `index`: the entries at or below it are covered,
    /// and with them every entry above if the log's suffix went.
    pub(crate) fn switched(&mut self, index: u64, keeps_suffix: bool) {
        for pending in &mut self.pending {
            pending
                .waiting
                .retain(|(at, _)| keeps_suffix && *at > index);
        }
    }
}
