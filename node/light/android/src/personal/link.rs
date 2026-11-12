// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The link to the personal agent over Tor: sealed sync's [`Link`] and the
//! pass's [`Control`], every request through the facility's client to the
//! home's onion under one purpose (`Personal` for what the user does,
//! `Background` for the job's pass), so the two never share a circuit or
//! an SSH key.
//!
//! A call is signed by a key in a session the link keeps for it: the sync
//! key's in-process, the admin key's in the UI process behind its strong
//! biometric (the [`Sign`] a flow lends). A call refused with `Settling` is
//! sent again after a `wake`. A read is a query signed by the sync key.
//! Every round trip blocks the calling thread on the facility's runtime:
//! sealed sync and the pass are synchronous, and are never called on it.

use std::time::Instant;

use ed25519_dalek::{Signer as _, SigningKey};
use vos_api::Kind;
use vos_light::job::{Control, Post};
use vos_light::personal::{Answer, Frontier, Link};
use vos_light::route::{Purpose, Route};
use vos_light::wire;
use vos_wire::abi::Failure;
use vos_wire::defaults::SESSION_EXPIRY_MS;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session};
use vos_wire::ingress::{self, Consistency, QueryCall, Response};
use vos_wire::personal::{
    DeviceView, Entry, Envelope, Overview, PersonalError, Pushed, Scope, Woken,
};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::net::{Net, SpaceId};

/// How long a query is good for, by the node's clock.
const QUERY_MS: u64 = 60_000;
/// The wakes a call refused with `Settling` waits through.
const WAKES: usize = 8;

/// A signature over a call's message by a key the link does not hold: the
/// admin key's, made in the UI process.
pub type Sign<'a> = &'a dyn Fn(&[u8]) -> Result<[u8; 64], String>;

/// What a call's caller keeps of its signed message before the call
/// leaves: a commit's, so its evidence is posted again after a crash.
pub type Hold<'a> = &'a mut dyn FnMut(&[u8], &[u8; 64]) -> Result<(), String>;

/// A key's session at the agent, and its next call's sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct Signer {
    pub key: [u8; 32],
    session: Option<Session>,
    /// The agent the session is at: another agent's calls start one anew.
    agent: u32,
    next: u64,
}

impl Signer {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            session: None,
            agent: 0,
            next: 1,
        }
    }
}

/// The agent a link reaches: its id, the identity calls to it are signed
/// for, and `Personal`'s instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agent {
    pub agent: u32,
    pub identity: [u8; 32],
    pub instance: InstanceId,
}

/// A call's answer: its outcome, and the message and signature an admin
/// call's evidence carries.
pub struct Called {
    pub outcome: Outcome,
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

/// The handler's answer in `outcome`: its reply, or `Personal`'s error.
pub fn answer<T: Decode>(outcome: &Outcome) -> Result<Result<T, PersonalError>, String> {
    match outcome {
        Outcome::Done(bytes) => T::decode_exact(bytes)
            .map(Ok)
            .ok_or_else(|| "the agent's reply does not decode".into()),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => PersonalError::decode_exact(detail)
            .map(Err)
            .ok_or_else(|| "the agent's error does not decode".into()),
        other => Err(format!("the agent answered {other:?}")),
    }
}

/// A link to the personal agent at the home `space`.
pub struct AgentLink<'a> {
    net: &'a Net,
    runtime: &'a tokio::runtime::Handle,
    space: SpaceId,
    purpose: Purpose,
    agent: Agent,
    sync: &'a SigningKey,
    signer: &'a mut Signer,
    /// The node's time read last, and when.
    clock: Option<(u64, Instant)>,
}

impl<'a> AgentLink<'a> {
    pub fn new(
        net: &'a Net,
        runtime: &'a tokio::runtime::Handle,
        space: SpaceId,
        purpose: Purpose,
        agent: Agent,
        sync: &'a SigningKey,
        signer: &'a mut Signer,
    ) -> Self {
        Self {
            net,
            runtime,
            space,
            purpose,
            agent,
            sync,
            signer,
            clock: None,
        }
    }

    pub fn agent(&self) -> Agent {
        self.agent
    }

    /// `request`'s answer body, sent under the link's purpose.
    pub fn send(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        self.runtime
            .block_on(self.net.request(self.space, self.purpose, request))
    }

    /// The node's time now: read once a link, then counted on.
    pub fn now(&mut self) -> Result<u64, String> {
        if let Some((node, at)) = self.clock
            && at.elapsed().as_millis() < u128::from(QUERY_MS / 2)
        {
            return Ok(node + at.elapsed().as_millis() as u64);
        }
        let node = wire::time_answer(&self.send(&wire::time_request())?)
            .map_err(|error| error.to_string())?;
        self.clock = Some((node, Instant::now()));
        Ok(node)
    }

    /// The call of `name` with `arguments` at the agent, signed by `sign` in
    /// `signer`'s session: its outcome, and what was signed. A call whose
    /// answer was lost keeps its sequence, so it is sent again as it was.
    pub fn signed(
        &mut self,
        signer: &mut Signer,
        sign: Sign<'_>,
        name: &str,
        arguments: Vec<u8>,
    ) -> Result<Called, String> {
        self.signed_held(signer, sign, name, arguments, &mut |_, _| Ok(()))
    }

    /// The same, its message and signature given to `hold` before the call
    /// is sent: a call `hold` refuses is not.
    pub fn signed_held(
        &mut self,
        signer: &mut Signer,
        sign: Sign<'_>,
        name: &str,
        arguments: Vec<u8>,
        hold: Hold<'_>,
    ) -> Result<Called, String> {
        let now = self.now()?;
        let stale = signer.agent != self.agent.agent
            || signer
                .session
                .is_none_or(|session| session.t0 + SESSION_EXPIRY_MS / 2 < now);
        if stale {
            let mut session_name = [0; 16];
            getrandom::getrandom(&mut session_name).map_err(|error| error.to_string())?;
            signer.session = Some(Session {
                key: signer.key,
                name: session_name,
                t0: now,
            });
            signer.agent = self.agent.agent;
            signer.next = 1;
        }
        let session = signer.session.expect("a session");
        let mut call = ingress::Call {
            session,
            sequence: signer.next,
            instance: self.agent.instance,
            method: MethodId(vos_light::method_id(name)),
            arguments,
            signature: [0; 64],
        };
        let message = call.message(&self.agent.identity);
        call.signature = sign(&message)?;
        hold(&message, &call.signature)?;
        let mut request = (Kind::Call as u16).to_le_bytes().to_vec();
        (AgentId(self.agent.agent), call.clone()).encode_to(&mut request);
        match Response::decode_exact(&self.send(&request)?) {
            Some(Response::Ran { outcome, .. }) => {
                signer.next += 1;
                Ok(Called {
                    outcome,
                    message,
                    signature: call.signature,
                })
            }
            Some(other) => Err(format!("the node answered {other:?}")),
            None => Err("the node's answer does not decode".into()),
        }
    }

    /// The sync key's call of `name`, sent again after a `wake` while the
    /// agent answers `Settling`.
    pub fn call<T: Decode>(&mut self, name: &str, arguments: Vec<u8>) -> Answer<T, String> {
        answer(&self.call_raw(name, arguments)?.outcome)
    }

    /// The same, its outcome as it came.
    pub fn call_raw(&mut self, name: &str, arguments: Vec<u8>) -> Result<Called, String> {
        let key = self.sync.clone();
        let sign = move |message: &[u8]| Ok(key.sign(message).to_bytes());
        let mut signer = *self.signer;
        let called = self.settled(&mut signer, &sign, name, arguments);
        *self.signer = signer;
        called
    }

    /// `name` signed by `sign` in `signer`'s session, sent again after a
    /// `wake` (the sync key's) while the agent answers `Settling`.
    pub fn settled(
        &mut self,
        signer: &mut Signer,
        sign: Sign<'_>,
        name: &str,
        arguments: Vec<u8>,
    ) -> Result<Called, String> {
        self.settled_held(signer, sign, name, arguments, &mut |_, _| Ok(()))
    }

    /// The same, each call's message held before it is sent
    /// ([`AgentLink::signed_held`]): a call signed again after `Settling`
    /// is held again.
    pub fn settled_held(
        &mut self,
        signer: &mut Signer,
        sign: Sign<'_>,
        name: &str,
        arguments: Vec<u8>,
        hold: Hold<'_>,
    ) -> Result<Called, String> {
        for _ in 0..WAKES {
            let called = self.signed_held(signer, sign, name, arguments.clone(), &mut *hold)?;
            let settling = matches!(
                answer::<()>(&called.outcome),
                Ok(Err(PersonalError::Settling))
            );
            if !settling {
                return Ok(called);
            }
            self.wake().map_err(|error| error.to_string())?.ok();
        }
        Err("the agent is still settling".into())
    }

    /// The sync key's query of `name` with `arguments`.
    pub fn query<T: Decode>(&mut self, name: &str, arguments: impl Encode) -> Answer<T, String> {
        let not_after = self.now()? + QUERY_MS;
        let mut query = QueryCall {
            key: self.sync.verifying_key().to_bytes(),
            not_after,
            consistency: Consistency::Applied { at: 0 },
            instance: self.agent.instance,
            method: MethodId(vos_light::method_id(name)),
            arguments: arguments.encode(),
            signature: [0; 64],
        };
        query.signature = self
            .sync
            .sign(&query.message(&self.agent.identity))
            .to_bytes();
        let mut request = (Kind::Query as u16).to_le_bytes().to_vec();
        (AgentId(self.agent.agent), query).encode_to(&mut request);
        let outcome = wire::outcome(&self.send(&request)?).map_err(|error| error.to_string())?;
        answer(&outcome)
    }

    /// The control log from `from` to its head.
    pub fn log_all(&mut self, from: u64) -> Answer<Vec<(u64, Entry)>, String> {
        let mut entries = Vec::new();
        let mut next = from;
        loop {
            let page: Vec<(u64, Entry)> = match self.query("log", next)? {
                Ok(page) => page,
                Err(error) => return Ok(Err(error)),
            };
            let Some((last, _)) = page.last() else {
                return Ok(Ok(entries));
            };
            next = last + 1;
            entries.extend(page);
        }
    }
}

impl Link for AgentLink<'_> {
    type Error = String;

    fn route(&self) -> Route {
        match self.net.client().routes(&self.space) {
            Some(routes) => routes.route(self.purpose).unwrap_or(Route::Clearnet),
            None => Route::Clearnet,
        }
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, String> {
        envelopes
            .iter()
            .map(|envelope| self.call::<Pushed>("push", envelope.encode()))
            .collect()
    }

    fn since(&mut self, scope: Scope, position: u64) -> Answer<Vec<Envelope>, String> {
        self.query("since", (scope, position))
    }

    fn wake(&mut self) -> Answer<Woken, String> {
        let key = self.sync.clone();
        let sign = move |message: &[u8]| Ok(key.sign(message).to_bytes());
        let mut signer = *self.signer;
        let called = self.signed(&mut signer, &sign, "wake", Vec::new());
        *self.signer = signer;
        answer(&called?.outcome)
    }

    fn frontier(&mut self, device: u32) -> Answer<Frontier, String> {
        self.query("frontier", device)
    }
}

impl Control for AgentLink<'_> {
    fn log(&mut self, from: u64) -> Answer<Vec<(u64, Entry)>, String> {
        self.query("log", from)
    }

    fn overview(&mut self) -> Answer<Overview, String> {
        self.query("overview", ())
    }

    fn devices(&mut self) -> Answer<Vec<DeviceView>, String> {
        self.query("devices", ())
    }

    fn post(&mut self, post: &Post) -> Answer<u64, String> {
        let called = self.call_raw(post.name(), post.arguments())?;
        Ok(match &called.outcome {
            Outcome::Done(reply) => {
                Ok(post.at(reply).ok_or("the agent's reply does not decode")?)
            }
            outcome => Err(answer::<()>(outcome)?.expect_err("a refusal")),
        })
    }
}
