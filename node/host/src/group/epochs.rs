//! An agent's old epochs, dropped in the background, and the marks that
//! keep an install out of an epoch a drop runs on.

use vos_wire::ids::AgentId;

use crate::lock;
use crate::node::Inner;
use crate::storage::Change;
use crate::store::next_epoch;

/// Rows of an old epoch one write removes.
const DROP_ROWS: usize = 4096;

impl Inner {
    /// Mark `epoch` of `agent`'s as one a drop runs on, before the drop can
    /// remove a row.
    pub(crate) fn dropping(&self, agent: AgentId, epoch: u8) {
        *lock(&self.dropping).entry((agent, epoch)).or_default() += 1;
    }

    /// A drop on `epoch` of `agent`'s ended.
    pub(crate) fn dropped(&self, agent: AgentId, epoch: u8) {
        let mut dropping = lock(&self.dropping);
        if let Some(running) = dropping.get_mut(&(agent, epoch)) {
            *running -= 1;
            if *running == 0 {
                dropping.remove(&(agent, epoch));
            }
        }
    }

    /// Whether a drop runs on `epoch` of `agent`'s.
    pub(crate) fn is_dropping(&self, agent: AgentId, epoch: u8) -> bool {
        lock(&self.dropping).contains_key(&(agent, epoch))
    }
}

/// Remove `agent`'s rows under the old `epoch`, a few thousand a write,
/// until it holds none. Its caller marks the epoch as dropped first
/// (`Inner::dropping`): an epoch emptied by one pass, and chosen for a new
/// install before the next, would lose the install's rows.
pub(super) async fn drop_rows(inner: &Inner, agent: AgentId, epoch: u8) {
    loop {
        let drop = Change::DropEpoch {
            agent,
            epoch,
            limit: DROP_ROWS,
        };
        if inner.storage.commit(vec![drop]).await.is_err() {
            return;
        }
        match inner.store.stale_epochs(agent) {
            Ok(stale) if stale.contains(&epoch) => {}
            _ => return,
        }
    }
}

/// An epoch of `agent`'s past its current one that holds no rows, and that
/// no drop runs on.
pub(crate) fn empty_epoch(inner: &Inner, agent: AgentId) -> Option<u8> {
    let read = inner
        .store
        .snapshot()
        .epoch(agent)
        .and_then(|current| Ok((current, inner.store.stale_epochs(agent)?)));
    let (current, stale) = match read {
        Ok(read) => read,
        Err(error) => {
            tracing::warn!(agent = agent.0, "the epochs are unreadable: {error}");
            return None;
        }
    };
    let mut epoch = next_epoch(current);
    while stale.contains(&epoch) || inner.is_dropping(agent, epoch) {
        epoch = next_epoch(epoch);
        if epoch == current {
            return None;
        }
    }
    Some(epoch)
}

/// Remove every stale epoch of `agent`'s, as [`drop_rows`] does.
pub(crate) async fn drop_stale_epochs(inner: &Inner, agent: AgentId) {
    let Ok(stale) = inner.store.stale_epochs(agent) else {
        return;
    };
    for &epoch in &stale {
        inner.dropping(agent, epoch);
    }
    for epoch in stale {
        drop_rows(inner, agent, epoch).await;
        inner.dropped(agent, epoch);
    }
}
