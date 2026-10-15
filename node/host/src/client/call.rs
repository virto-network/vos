//! A client's calls: signed, in its sessions' sequences, failing over and
//! following redirects until the agent answers.

use std::time::Duration;

use ed25519_dalek::Signer;
use vos_wire::Encode;
use vos_wire::abi::Refusal;
use vos_wire::defaults;
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::ingress::{Call, Contact, Rejection, Response, call_message};

use super::{Client, ClientError, Http, decode_answer};

/// What became of a call whose fate was unknown, once its session was
/// refused.
enum Fate {
    /// Copies of it may still run.
    InTransit,
    /// It never ran, and never can: it may go again in a new session.
    NeverRan,
    /// It may have run, and nothing can say.
    Lost,
}

/// Redirects a call follows before it answers what the last node said.
const REDIRECTS: usize = 4;
/// Times a call goes to another replica, after a failure, before it
/// answers the last.
const FAILOVERS: usize = 6;
/// The first wait after `Busy`, doubled each time up to [`MAX_BUSY`].
const BUSY: Duration = Duration::from_millis(50);
const MAX_BUSY: Duration = Duration::from_secs(1);
/// New sessions a call starts before it answers the refusal: one when the
/// agent refuses a session for good, and one more when the client's clock
/// is off the agent's time.
const RENEWALS: usize = 2;

impl Client {
    /// Call the replica of `agent` after the one this client calls: false
    /// when it knows no other, or cannot reach the one it knows.
    fn fail_over(&mut self, agent: AgentId) -> bool {
        let Some(next) = self.other_replicas(agent).into_iter().next() else {
            return false;
        };
        self.follow(&next).is_ok()
    }

    /// Call `method` on `agent`'s `instance`, at the session's next
    /// sequence for that agent, which moves on only once consumed.
    ///
    /// Any replica takes the call. On a failure, or an answer that leaves
    /// it unknown whether the call ran, the call goes to the next replica
    /// with the same sequence; on `Busy`, again after a wait. Redirects are
    /// followed, and a new session is started when the agent refuses this
    /// one for good.
    pub fn call(
        &mut self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Response, ClientError> {
        // Learn the replicas first: the node may be gone when a failover
        // needs them.
        self.ensure_replicas(agent);
        let mut redirects = 0;
        let mut renewals = 0;
        let mut failovers = 0;
        let mut busy = BUSY;
        // An attempt that may have run, or may yet: later refusals that
        // say it never ran no longer prove it for the call.
        let mut inconclusive = self.state().unknown.remove(&agent);
        loop {
            let sequence = self.kept(agent).next;
            let answer = match self.call_at(agent, sequence, instance, method, arguments) {
                Ok(answer) => answer,
                Err(error) => {
                    inconclusive = true;
                    if failovers < FAILOVERS && self.fail_over(agent) {
                        failovers += 1;
                        continue;
                    }
                    return Err(error);
                }
            };
            match &answer {
                Response::Ran { at, .. } => {
                    if let Some(kept) = self.state().sessions.get_mut(&agent) {
                        kept.next = sequence + 1;
                    }
                    self.raise_floor(agent, *at);
                    return Ok(answer);
                }
                Response::NotLeader {
                    leader: Some(leader),
                } if redirects < REDIRECTS => {
                    redirects += 1;
                    self.follow(leader)?;
                }
                Response::Elsewhere { replicas }
                    if redirects < REDIRECTS && !replicas.is_empty() =>
                {
                    redirects += 1;
                    self.follow(&replicas[(redirects - 1) % replicas.len()])?;
                }
                // An earlier attempt may have run, or may yet.
                Response::Rejected(Rejection::StaleSession { now }) if inconclusive => {
                    match self.unknown_fate(agent, *now) {
                        Fate::Lost => {
                            self.renew(agent);
                            return Err(ClientError::Lost);
                        }
                        Fate::InTransit => return Ok(Response::TimedOut),
                        Fate::NeverRan if renewals < RENEWALS => {
                            renewals += 1;
                            inconclusive = false;
                            self.learn_time(*now);
                            self.renew(agent);
                        }
                        Fate::NeverRan => return Ok(answer),
                    }
                }
                // Not consumed: the same request goes again in a new session.
                Response::Rejected(Rejection::StaleSession { now }) if renewals < RENEWALS => {
                    renewals += 1;
                    self.learn_time(*now);
                    self.renew(agent);
                }
                // Timed by refine, past the lane: the next attempt meets the
                // lane's refusal, with the agent's time.
                Response::Refused(Refusal::StaleSession) if inconclusive => {
                    return Ok(Response::TimedOut);
                }
                // An expired session's calls that ran are answered from its
                // window: refused, this one never ran, and never will.
                Response::Refused(Refusal::Expired | Refusal::StaleSession)
                    if renewals < RENEWALS =>
                {
                    renewals += 1;
                    inconclusive = false;
                    self.renew(agent);
                }
                // The earlier attempt may still create the session.
                Response::Refused(Refusal::SessionsFull | Refusal::KeySessionsFull)
                    if inconclusive =>
                {
                    return Ok(Response::TimedOut);
                }
                Response::Stopped
                | Response::Unavailable
                | Response::TimedOut
                | Response::NotLeader { leader: None }
                    if failovers < FAILOVERS =>
                {
                    inconclusive = true;
                    failovers += 1;
                    self.fail_over(agent);
                }
                // Every replica forwards to the same leader: wait.
                Response::Busy if failovers < FAILOVERS => {
                    failovers += 1;
                    std::thread::sleep(busy);
                    busy = (busy * 2).min(MAX_BUSY);
                }
                // Busy, or a failure of this attempt, says nothing of an
                // earlier one.
                Response::Busy | Response::NotConsumed if inconclusive => {
                    return Ok(Response::TimedOut);
                }
                _ => return Ok(answer),
            }
        }
    }

    /// What a call whose fate is unknown can be, its session refused as one
    /// the agent does not hold at the agent's time `now`.
    fn unknown_fate(&self, agent: AgentId, now: u64) -> Fate {
        let Some(kept) = self.state().sessions.get(&agent).copied() else {
            return Fate::InTransit;
        };
        // Answered in, the session was created, and is gone.
        if kept.next > 1 {
            return Fate::Lost;
        }
        let skew = defaults::SESSION_SKEW_MS;
        // A leader may still create it, or will once time reaches a t0
        // ahead.
        if now <= kept.t0.saturating_add(2 * skew) {
            return Fate::InTransit;
        }
        // Never created: collecting it would need the agent's time past
        // its t0 less the skew plus the expiry. And no leader's clock is
        // now near enough its t0 to create it.
        if now <= kept.t0.saturating_add(defaults::SESSION_EXPIRY_MS) - skew {
            return Fate::NeverRan;
        }
        Fate::Lost
    }

    /// Call the node `contact` names from now on, trusted as this client
    /// trusts nodes: by the same CAs, or pinned by the key the redirecting
    /// node gave, as this client already trusts what that node says.
    fn follow(&mut self, contact: &Contact) -> Result<(), ClientError> {
        self.http = Http::new(&self.target_for(contact)?);
        Ok(())
    }

    /// Call with an explicit `sequence` in the agent's session: to resend
    /// one, or to test.
    pub fn call_at(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Response, ClientError> {
        let body = self.call_body(agent, sequence, instance, method, arguments)?;
        let path = format!("/agents/{}/calls", agent.0);
        let (status, body) = self.http.post_repeatable(&path, &body)?;
        decode_answer(status, &body)
    }

    /// A signed call's body in the agent's session, to send by other means.
    pub fn call_body(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let identity = self.identity(agent)?;
        let session = self.session(agent);
        let message = call_message(&identity, &session, sequence, instance, method, arguments);
        Ok(Call {
            session,
            sequence,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode())
    }
}
