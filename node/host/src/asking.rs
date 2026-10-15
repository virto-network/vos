//! What a replica asks its agent's leader, a call forwarded or a read
//! index: each ask waits under a token the leader echoes in its answer,
//! and is asked again, through leader changes and silences, until it is
//! answered or its deadline passes.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_wire::ids::AgentId;
use vos_wire::peer::NodeNumber;

use crate::group::State;
use crate::node::{Inner, Run};
use crate::peer::Refusal;
use crate::{lock, random, timeout};

/// How long an ask waits for its answer before it asks again.
pub(crate) const REASK: Duration = Duration::from_secs(2);
/// How long an ask waits, for a change of leader, before it asks again a
/// leader that could not answer it.
pub(crate) const PAUSE: Duration = Duration::from_millis(100);

/// The asks of one kind waiting for their answers, `A`.
pub(crate) struct Waits<A> {
    waiting: Mutex<HashMap<u64, (AgentId, smol::channel::Sender<A>)>>,
}

impl<A> Default for Waits<A> {
    fn default() -> Self {
        Self {
            waiting: Mutex::default(),
        }
    }
}

/// One ask's wait: its token, and the answers given for it. Dropped, it
/// is forgotten, and an answer for its token is unmatched.
pub(crate) struct Wait<'a, A> {
    waits: &'a Waits<A>,
    pub(crate) token: u64,
    answers: smol::channel::Receiver<A>,
}

impl<A> Waits<A> {
    /// Wait for answers about `agent`, under a token no other wait holds.
    pub(crate) fn register(&self, agent: AgentId) -> Wait<'_, A> {
        let (answer, answers) = smol::channel::unbounded();
        let mut token = u64::from_le_bytes(random());
        let mut waiting = lock(&self.waiting);
        while waiting.contains_key(&token) {
            token = token.wrapping_add(1);
        }
        waiting.insert(token, (agent, answer));
        drop(waiting);
        Wait {
            waits: self,
            token,
            answers,
        }
    }

    /// Give `answer` to the wait `token` names, if it asked about `agent`:
    /// false when none did.
    pub(crate) fn answer(&self, agent: AgentId, token: u64, answer: A) -> bool {
        match lock(&self.waiting).get(&token) {
            Some((asked, waiting)) if *asked == agent => {
                let _ = waiting.try_send(answer);
                true
            }
            _ => false,
        }
    }
}

impl<A> Wait<'_, A> {
    /// The next answer, within `limit`, unless `moved` ends first.
    pub(crate) async fn within<T>(
        &self,
        limit: Duration,
        moved: impl Future<Output = T>,
    ) -> Option<A> {
        let answer = async {
            match self.answers.recv().await {
                Ok(answer) => Some(answer),
                // Never: the sender stays registered while the wait lives.
                Err(_) => std::future::pending().await,
            }
        };
        let moved = async {
            moved.await;
            None
        };
        timeout(limit, answer.or(moved)).await.flatten()
    }
}

impl<A> Drop for Wait<'_, A> {
    fn drop(&mut self) {
        lock(&self.waits.waiting).remove(&self.token);
    }
}

/// Wait until `changed` holds of `run`'s group, for `most` at most, and
/// never past `until`.
pub(crate) async fn pause(
    run: &Run,
    most: Duration,
    until: Instant,
    changed: impl Fn(&State) -> bool,
) {
    let left = until.saturating_duration_since(Instant::now());
    timeout(most.min(left), run.shared.wait(changed)).await;
}

impl Inner {
    /// The answer to what this replica asked about `agent`, from `from`,
    /// one of its replicas.
    pub(crate) fn on_answer<A>(
        &self,
        waits: &Waits<A>,
        from: NodeNumber,
        agent: AgentId,
        token: u64,
        answer: A,
    ) {
        if self.admit(agent, from) && !waits.answer(agent, token, answer) {
            self.drops.count(Refusal::Unmatched);
        }
    }
}
