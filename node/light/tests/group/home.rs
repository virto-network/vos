//! A home: the shared personal agent in process
//! ([`vos_testkit::personal::Agent`]), one batch a call, each call's
//! signature checked as ingress checks it. The batch time is the test's.

use ed25519_dalek::{Signer, SigningKey};
use vos_abi::abi::Failure;
use vos_abi::ids::{AgentId, MethodId};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_light::release::Package;
use vos_testkit::personal::Agent;
use vos_testkit::programs;
use vos_wire::ingress::{self, call_message};
use vos_wire::personal::{Body, Entry, Kit, NewDevice, PersonalError, Policy};

pub use vos_wire::personal::PERSONAL;
/// The agent's identity, which calls are signed for.
pub const IDENTITY: [u8; 32] = [0x1d; 32];
const AGENT: AgentId = AgentId(7);
/// The batch time a test's home starts at.
pub const T0: u64 = 1_800_000_000_000;

/// A call signed, not yet sent: the call, and the message and signature
/// its evidence carries.
pub struct Signed {
    pub call: ingress::Call,
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

/// A call's reply: its batch time, and its outcome.
pub struct Reply {
    pub at: u64,
    pub outcome: Outcome,
    /// The call's signed message and signature, as ingress verified them.
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

impl Reply {
    /// The handler's answer: its reply, or `Personal`'s error.
    pub fn answer<T: Decode>(&self) -> Result<T, PersonalError> {
        vos_light::wire::answer(&self.outcome).unwrap_or_else(|_| panic!("{:?}", self.outcome))
    }

    /// Whether `Personal` refused the call with `Settling`: what fell due
    /// is more than a call settles, which `wake` settles a few at a time.
    pub fn settling(&self) -> bool {
        matches!(&self.outcome, Outcome::Failed {
            code: Failure::Handler,
            detail,
        } if PersonalError::decode_exact(detail) == Some(PersonalError::Settling))
    }
}

pub struct Home {
    agent: Agent,
    /// The agent's identity, which calls are signed for.
    pub identity: [u8; 32],
    /// The policy the home's claims set.
    policy: Policy,
}

/// The home's agent, whose `Homes` claims the agent.
const HOME_AGENT: AgentId = AgentId(0x50);

/// `Personal`'s package.
pub fn personal() -> &'static Package {
    static PERSONAL: std::sync::OnceLock<Package> = std::sync::OnceLock::new();
    PERSONAL.get_or_init(|| crate::common::package(programs::program_elf("vos-personal"), 1))
}

impl Home {
    /// `Personal` installed, its role `homes` granted to the home's agent,
    /// whose claims set `policy`.
    pub fn new(policy: Policy) -> Self {
        Self::at(policy, IDENTITY)
    }

    /// [`Home::new`] for an agent whose identity is `identity`: another
    /// home's.
    pub fn at(policy: Policy, identity: [u8; 32]) -> Self {
        let package = personal();
        let checked = package.checked().unwrap();
        let installed: Vec<&[u8]> = checked.iter().map(|(_, program)| *program).collect();
        let agent = Agent::new(
            AGENT,
            identity,
            package.derivation.clone(),
            &installed,
            HOME_AGENT,
            T0 - 1,
        );
        Self {
            agent,
            identity,
            policy,
        }
    }

    /// The home's claim of the agent for `device` with `kit`, as `Homes`
    /// sends it: the index of the log's entry assigning it.
    pub fn claim(&mut self, device: &NewDevice, kit: Kit) -> u64 {
        let now = self.now();
        self.agent
            .claim(now, device.clone(), kit, self.policy)
            .unwrap();
        self.log(device.sync, 0)
            .unwrap()
            .iter()
            .find(|(_, entry)| matches!(entry.body, Body::Assigned { .. }))
            .expect("the assignment")
            .0
    }

    /// The next batch's time.
    pub fn now(&self) -> u64 {
        self.agent.now()
    }

    pub fn method(&self, name: &str) -> MethodId {
        self.agent.method(name)
    }

    /// The agent as a device group names it.
    pub fn agent(&self) -> vos_light::group::Agent {
        vos_light::group::Agent {
            identity: self.identity,
            instance: PERSONAL,
        }
    }

    /// A call of `name` with `arguments` signed by `key`, verified as
    /// ingress verifies it, then run alone in a batch; refused with
    /// `Settling`, `key` wakes the agent and calls again.
    pub fn call(&mut self, key: &SigningKey, name: &str, arguments: Vec<u8>) -> Reply {
        loop {
            let signed = self.sign(key, name, arguments.clone());
            let reply = self.send(signed);
            if !reply.settling() || !self.wake(key) {
                return reply;
            }
        }
    }

    /// `key` wakes the agent, which settles a few of the steps due:
    /// whether it took the call.
    pub fn wake(&mut self, key: &SigningKey) -> bool {
        let signed = self.sign(key, "wake", ().encode());
        self.send(signed)
            .answer::<vos_wire::personal::Woken>()
            .is_ok()
    }

    /// A call of `name` with `arguments` signed by `key`, in its session
    /// for a call now, not yet sent.
    pub fn sign(&mut self, key: &SigningKey, name: &str, arguments: Vec<u8>) -> Signed {
        let method = self.method(name);
        let (session, sequence) = self.agent.session(key.verifying_key().to_bytes());
        let message = call_message(
            &self.identity,
            &session,
            sequence,
            PERSONAL,
            method,
            &arguments,
        );
        let signature = key.sign(&message).to_bytes();
        Signed {
            call: ingress::Call {
                session,
                sequence,
                instance: PERSONAL,
                method,
                arguments,
                signature,
            },
            message,
            signature,
        }
    }

    /// `signed`, verified as ingress verifies it, then run alone in a
    /// batch.
    pub fn send(&mut self, signed: Signed) -> Reply {
        let now = self.agent.now();
        let (outcome, at) = self.agent.call(now, signed.call);
        Reply {
            at,
            outcome,
            message: signed.message,
            signature: signed.signature,
        }
    }

    /// `key`'s query of `name` at the batch time.
    pub fn query<T: Decode>(
        &self,
        key: [u8; 32],
        name: &str,
        arguments: Vec<u8>,
    ) -> Result<T, PersonalError> {
        let outcome = self.agent.read(key, self.method(name), arguments);
        Reply {
            at: self.agent.now(),
            outcome,
            message: Vec::new(),
            signature: [0; 64],
        }
        .answer()
    }

    /// The control log from `from` to its head, read as `key`.
    pub fn log(&self, key: [u8; 32], from: u64) -> Result<Vec<(u64, Entry)>, PersonalError> {
        let mut entries = Vec::new();
        let mut next = from;
        loop {
            let page: Vec<(u64, Entry)> = self.query(key, "log", next.encode())?;
            let Some((last, _)) = page.last() else {
                return Ok(entries);
            };
            next = last + 1;
            entries.extend(page);
        }
    }

    pub fn pass(&mut self, ms: u64) {
        self.agent.pass(ms);
    }
}
