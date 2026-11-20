//! A personal agent in process, as a home's node runs it: `Personal`
//! installed in the default agent of a [`World`] of its own, its role
//! `homes` granted to the home's agent, whose `Homes` claims it; each call
//! and query taken as ingress
//! takes it, its signature checked over the agent's identity, each call
//! alone in a batch at the caller's clock or a millisecond past the last,
//! each query at the last batch's time, as a node serves it: a home with
//! no calls reads at the time of its last.
//! The light node's tests, the facility's and `tools/phone` reach their
//! homes' agents through it.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use vos_abi::ids::{AgentId, MethodId, Principal, Session};
use vos_abi::message::Body;
use vos_abi::records::Derivation;
use vos_abi::result::Outcome;
use vos_abi::{Decode, SpaceId};
use vos_wire::batch::{Input, Query, Request, Work};
use vos_wire::ingress::{self, QueryCall};
use vos_wire::personal::{Kit, NewDevice, PersonalError, Policy};

use crate::world::World;

pub use vos_wire::personal::PERSONAL;

/// `Homes`' instance in the home's agent, which a claim's answer goes to.
pub const HOMES_AT: u32 = 3;

/// One personal agent.
pub struct Agent {
    world: World,
    agent: AgentId,
    /// The home's agent, whose `Homes` claims this one.
    homes: AgentId,
    /// The agent's identity, which calls and queries are signed for.
    pub identity: [u8; 32],
    /// The last batch's time, which queries read at.
    last: u64,
}

fn verified(key: &[u8; 32], message: &[u8], signature: &[u8; 64], what: &str) {
    ed25519_dalek::VerifyingKey::from_bytes(key)
        .and_then(|key| key.verify(message, &ed25519_dalek::Signature::from_bytes(signature)))
        .unwrap_or_else(|_| panic!("ingress verifies the {what}"));
}

impl Agent {
    /// `Personal`, of `derivation` and its `programs` (the actor's first,
    /// as a release's package holds them), installed at `agent`, whose
    /// identity is `identity`, at `now`; its role `homes` granted to the
    /// home's agent `homes`.
    pub fn new(
        agent: AgentId,
        identity: [u8; 32],
        derivation: Derivation,
        programs: &[&[u8]],
        homes: AgentId,
        now: u64,
    ) -> Self {
        let mut world = World::at(now);
        world
            .agent(agent)
            .install_derivation(
                SpaceId::NONE,
                PERSONAL,
                derivation,
                programs,
                &[("homes", 1)],
            )
            .grant(Principal::Agent(homes), 1);
        let last = world.now.saturating_sub(1);
        Self {
            world,
            agent,
            homes,
            identity,
            last,
        }
    }

    /// The next batch's time.
    pub fn now(&self) -> u64 {
        self.world.now
    }

    /// The clock moved on by `ms`.
    pub fn pass(&mut self, ms: u64) {
        self.world.pass(ms);
    }

    /// The world the agent runs in.
    pub fn world(&mut self) -> &mut World {
        &mut self.world
    }

    /// The id of `Personal`'s method `name`, as the installed actor
    /// derives it.
    pub fn method(&self, name: &str) -> MethodId {
        self.world.method(self.agent, PERSONAL, name)
    }

    /// `caller`'s query of `method` with `arguments`, as the agent runs it
    /// past ingress, at the last batch's time.
    pub fn read(&self, caller: [u8; 32], method: MethodId, arguments: Vec<u8>) -> Outcome {
        let work = Work::Query(Query {
            time: self.last,
            seed: [0; 32],
            caller: Principal::Client(caller),
            instance: PERSONAL,
            method,
            arguments,
        });
        Outcome::decode(&self.world.node(self.agent).refine(&work))
            .expect("an outcome")
            .0
    }

    /// `key`'s session for a call now, and the call's sequence.
    pub fn session(&mut self, key: [u8; 32]) -> (Session, u64) {
        self.world.agent(self.agent).session(Principal::Client(key))
    }

    /// A client's call as ingress takes it: its signature checked, then run
    /// alone in a batch at `now` (or a millisecond past the last): its
    /// outcome and its batch time.
    pub fn call(&mut self, now: u64, call: ingress::Call) -> (Outcome, u64) {
        verified(
            &call.session.key,
            &call.message(&self.identity),
            &call.signature,
            "call",
        );
        assert_eq!(call.instance, PERSONAL, "a call of `Personal`");
        self.world.now = self.world.now.max(now);
        let at = self.world.now;
        let run = self.world.agent(self.agent).step(Input::Request(Request {
            session: call.session,
            sequence: call.sequence,
            caller: Principal::Client(call.session.key),
            instance: call.instance,
            method: call.method,
            arguments: call.arguments,
        }));
        self.last = at;
        (run.outcome, at)
    }

    /// A query as ingress takes it: its signature checked, then run at
    /// the last batch's time.
    pub fn query(&self, query: &QueryCall) -> Outcome {
        verified(
            &query.key,
            &query.message(&self.identity),
            &query.signature,
            "query",
        );
        let work = Work::Query(Query {
            time: self.last,
            seed: [0; 32],
            caller: Principal::Client(query.key),
            instance: query.instance,
            method: query.method,
            arguments: query.arguments.clone(),
        });
        Outcome::decode(&self.world.node(self.agent).refine(&work))
            .expect("an outcome")
            .0
    }

    /// `key`'s call of `method` with `arguments`, in its session, signed
    /// and taken as ingress takes it, at `now`.
    pub fn signed(
        &mut self,
        now: u64,
        key: &SigningKey,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> (Outcome, u64) {
        self.world.now = self.world.now.max(now);
        let (session, sequence) = self.session(key.verifying_key().to_bytes());
        let message = ingress::call_message(
            &self.identity,
            &session,
            sequence,
            PERSONAL,
            method,
            &arguments,
        );
        let call = ingress::Call {
            session,
            sequence,
            instance: PERSONAL,
            method,
            arguments,
            signature: key.sign(&message).to_bytes(),
        };
        self.call(now, call)
    }

    /// The home's claim of the agent for `device` with `kit` under
    /// `policy`, at `now`, as `Homes` sends it (the home's `Homes` at
    /// instance `HOMES_AT`): `assigned`, or the error `refused` carries.
    pub fn claim(
        &mut self,
        now: u64,
        device: NewDevice,
        kit: Kit,
        policy: Policy,
    ) -> Result<(), PersonalError> {
        self.world.now = self.world.now.max(now);
        self.last = self.world.now;
        let run = self.world.agent(self.agent).call(
            Principal::Agent(self.homes),
            PERSONAL,
            "claim",
            ((device, kit), (policy, HOMES_AT)),
        );
        assert!(matches!(run.outcome, Outcome::Done(_)), "{:?}", run.outcome);
        let homes = self.homes;
        let (_, sent) = self
            .world
            .sent()
            .filter(|(_, sent)| sent.to == homes)
            .last()
            .expect("the claim's answer");
        let Body::Call {
            method, arguments, ..
        } = &sent.body
        else {
            panic!("a call: {sent:?}")
        };
        if *method == vos_wire::homes::method::ASSIGNED {
            Ok(())
        } else {
            Err(PersonalError::decode_exact(arguments).expect("a refusal"))
        }
    }
}
