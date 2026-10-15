//! After this replica applied a batch's result: the replies, the inputs
//! put back, the outbox's deliveries and the acknowledgements.

use std::collections::{BTreeSet, HashMap};

use vos_wire::abi::Refusal;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, SessionId};
use vos_wire::keys;
use vos_wire::records::SessionMark;
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult};

use super::{Leader, raise};
use crate::fault::{Fault, read};
use crate::node::{Agent, Answered, CallError, Inner, Pending, Reply};
use crate::store::Snapshot;

impl Leader {
    /// After this replica applied the result: answer, requeue what the
    /// result did not cover, deliver the outbox and acknowledge applied
    /// messages. A step no input made, a workflow's due step after its
    /// start or the sweep, pairs with no input.
    pub(super) fn dispatch(
        &mut self,
        inner: &Inner,
        agent: &Agent,
        pending: Vec<Pending>,
        result: &WorkResult,
        before: &Snapshot,
    ) {
        let snapshot = inner.store.snapshot();
        let mut acks: HashMap<AgentId, u64> = HashMap::new();
        let mut rest = Vec::new();
        let mut again = Vec::new();
        let mut acked = BTreeSet::new();
        let mut steps = result.steps.iter().filter(|step| {
            !matches!(
                step,
                Step::Ran(Run {
                    input: InputRef::Due { .. },
                    ..
                })
            )
        });
        for item in pending {
            let Some(step) = steps.next() else {
                rest.push(item);
                continue;
            };
            match item {
                Pending::Request { request, answer } => {
                    let answered = match step {
                        Step::Refused {
                            code: Refusal::Sequence,
                            ..
                        } => self
                            .duplicate(&snapshot, &request)
                            // The batch's sweep may have collected its
                            // session: the state it refined on holds it.
                            .and_then(|found| match found {
                                Some(found) => Ok(Some(found)),
                                None => self.duplicate(before, &request),
                            })
                            .map(|duplicate| duplicate.unwrap_or_else(|| reply(step)))
                            .map_err(|fault| CallError::Failed(fault.message().to_string())),
                        _ => Ok(reply(step)),
                    };
                    let at = self.applied;
                    let _ = answer.try_send(answered.map(|reply| Answered { reply, at }));
                }
                Pending::Admin { answer, .. } => {
                    let _ = answer.try_send(Ok(Answered {
                        reply: reply(step),
                        at: self.applied,
                    }));
                }
                Pending::Sweep(_) => {}
                Pending::Message(message) | Pending::Failed(message) => match step {
                    Step::Ran(_) => {
                        self.marks.insert(message.from, message.sequence);
                        raise(&mut acks, message.from, message.sequence);
                    }
                    Step::Refused {
                        code: Refusal::Sequence,
                        ..
                    } => {
                        // At or below the mark, a duplicate: acknowledge
                        // it. Above, a gap: drop it, and tell the sender it
                        // is behind.
                        match self.mark(&snapshot, message.from) {
                            Ok(mark) if message.sequence <= mark => {
                                raise(&mut acks, message.from, mark);
                            }
                            Ok(_) => inner.behind(message.from, self.id),
                            Err(fault) => tracing::error!(
                                agent = self.id.0,
                                "a pair mark is unreadable: {}",
                                fault.message()
                            ),
                        }
                    }
                    Step::Refused { code, .. } => tracing::error!(
                        agent = self.id.0,
                        from = message.from.0,
                        sequence = message.sequence,
                        ?code,
                        "a message was refused and dropped"
                    ),
                    Step::Swept { .. } => tracing::error!(
                        agent = self.id.0,
                        "a message's step is a sweep; the message is dropped"
                    ),
                },
                Pending::Ack { to, sequence } => {
                    acked.insert(to);
                    // Ack again while the mark trails it: one ack clears
                    // at most `ACK_LIMIT` entries.
                    let marks =
                        read::<u64>(&snapshot, self.id, &keys::acked(to)).and_then(|acked| {
                            Ok((acked, read::<u64>(&snapshot, self.id, &keys::pair_out(to))?))
                        });
                    match marks {
                        Ok((acked, sent))
                            if acked.unwrap_or(0) < sequence.min(sent.unwrap_or(0)) =>
                        {
                            again.push(Pending::Ack { to, sequence });
                        }
                        Ok(_) => {}
                        Err(fault) => tracing::error!(
                            agent = self.id.0,
                            "an ack mark is unreadable: {}",
                            fault.message()
                        ),
                    }
                }
            }
        }
        inner.requeue(agent, rest);
        for pending in again {
            let _ = inner.push(self.id, pending);
        }
        // The targets of new messages, and those whose acknowledgements
        // opened their windows.
        let mut targets: BTreeSet<AgentId> = result
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Ran(run) => Some(run.messages.iter().map(|message| message.to)),
                Step::Refused { .. } | Step::Swept { .. } => None,
            })
            .flatten()
            .collect();
        targets.extend(acked);
        for to in targets {
            if let Err(fault) = self.deliver(inner, &snapshot, to) {
                // The outbox keeps them: the next send to `to`, or a
                // restart, delivers them.
                tracing::error!(
                    agent = self.id.0,
                    to = to.0,
                    "delivery failed: {}",
                    fault.message()
                );
            }
        }
        self.acknowledge(inner, acks);
    }

    /// The reply to `request`, refused out of its session's sequence, if it
    /// is at or below the session's applied mark: a duplicate, answered
    /// from the reply window, or `TooOld`. None for a gap.
    ///
    /// Ingress lets a duplicate through when it read the mark before this
    /// replica applied the original, as a new leader's does while it
    /// catches up: this answers it.
    fn duplicate(&self, snapshot: &Snapshot, request: &Request) -> Result<Option<Reply>, Fault> {
        let Some(id) =
            read::<SessionId>(snapshot, self.id, &keys::session_index(&request.session))?
        else {
            return Ok(None);
        };
        let Some(mark) = read::<SessionMark>(snapshot, self.id, &keys::session(id))? else {
            return Ok(None);
        };
        if request.sequence > mark.sequence {
            return Ok(None);
        }
        let kept = read::<Outcome>(snapshot, self.id, &keys::reply(id, request.sequence))?;
        Ok(Some(kept.map_or(Reply::TooOld, Reply::Ran)))
    }
}

/// The reply a step gives its request.
pub(crate) fn reply(step: &Step) -> Reply {
    match step {
        Step::Ran(run) => Reply::Ran(run.outcome.clone()),
        Step::Refused { code, .. } => Reply::Refused(*code),
        // Not a request's step: the agent paired them wrongly.
        Step::Swept { .. } => Reply::Failed,
    }
}
