//! A home: `Personal` installed in the default agent of a test's world
//! ([`vos_testkit::World`]), one batch a call; and ingress's part, each
//! call's signature checked against its key before the call runs. The
//! batch time is the test's.

use ed25519_dalek::{Signer, SigningKey, Verifier};
use vos_abi::abi::Failure;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, SpaceId};
use vos_light::release::{self, Package};
use vos_testkit::World;
use vos_testkit::programs;
use vos_wire::batch::{Input, Request};
use vos_wire::ingress::call_message;
use vos_wire::personal::{Entry, PersonalError, Policy};

pub const PERSONAL: InstanceId = InstanceId(5);
/// The agent's identity, which calls are signed for.
pub const IDENTITY: [u8; 32] = [0x1d; 32];
const AGENT: AgentId = AgentId(7);
/// The batch time a test's home starts at.
pub const T0: u64 = 1_800_000_000_000;

/// A call signed, not yet sent: its request, and the message and
/// signature its evidence carries.
pub struct Signed {
    pub request: Request,
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
    world: World,
    /// The agent's identity, which calls are signed for.
    pub identity: [u8; 32],
}

/// The release artifacts: the default agent, linked, and `Personal`'s
/// package.
pub fn artifacts() -> &'static (Vec<u8>, Package) {
    static ARTIFACTS: std::sync::OnceLock<(Vec<u8>, Package)> = std::sync::OnceLock::new();
    ARTIFACTS.get_or_init(|| {
        let read = |path: std::path::PathBuf| std::fs::read(path).unwrap();
        let agent = release::agent(&read(programs::program_elf("vos-agent"))).unwrap();
        let personal = release::package(&read(programs::program_elf("vos-personal")), 1).unwrap();
        (agent, personal)
    })
}

impl Home {
    /// `Personal` installed, its role `homes` granted to `homes`.
    pub fn new(homes: &SigningKey, policy: Policy) -> Self {
        Self::at(homes, policy, IDENTITY)
    }

    /// [`Home::new`] for an agent whose identity is `identity`: another
    /// home's.
    pub fn at(homes: &SigningKey, policy: Policy, identity: [u8; 32]) -> Self {
        let (_, package) = artifacts();
        let checked = package.checked().unwrap();
        let installed: Vec<&[u8]> = checked.iter().map(|(_, program)| *program).collect();
        let mut world = World::at(T0 - 1);
        world
            .agent(AGENT)
            .install_derivation(
                SpaceId::NONE,
                PERSONAL,
                package.derivation.clone(),
                &installed,
                &[("homes", 1)],
            )
            .grant(Principal::Client(homes.verifying_key().to_bytes()), 1);
        let mut home = Self { world, identity };
        home.call(homes, "configure", policy.encode())
            .answer::<vos_wire::personal::Recorded>()
            .unwrap();
        home
    }

    /// The next batch's time.
    pub fn now(&self) -> u64 {
        self.world.now
    }

    pub fn method(&self, name: &str) -> MethodId {
        self.world.method(AGENT, PERSONAL, name)
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
        let caller = Principal::Client(key.verifying_key().to_bytes());
        let request = self
            .world
            .agent(AGENT)
            .request(caller, PERSONAL, name, Raw(&arguments));
        let message = call_message(
            &self.identity,
            &request.session,
            request.sequence,
            PERSONAL,
            self.method(name),
            &arguments,
        );
        let signature = key.sign(&message).to_bytes();
        Signed {
            request,
            message,
            signature,
        }
    }

    /// `signed`, verified as ingress verifies it, then run alone in a
    /// batch.
    pub fn send(&mut self, signed: Signed) -> Reply {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&signed.request.session.key).unwrap();
        key.verify(
            &signed.message,
            &ed25519_dalek::Signature::from_bytes(&signed.signature),
        )
        .expect("ingress verifies the call");
        let at = self.world.now;
        let run = self.world.agent(AGENT).step(Input::Request(signed.request));
        Reply {
            at,
            outcome: run.outcome,
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
        let outcome = self.world.query(
            AGENT,
            Principal::Client(key),
            PERSONAL,
            name,
            Raw(&arguments),
        );
        Reply {
            at: self.world.now,
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
        self.world.pass(ms);
    }
}

/// Arguments already encoded.
struct Raw<'a>(&'a [u8]);

impl Encode for Raw<'_> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0);
    }
}
