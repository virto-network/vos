//! The test actors installed in a node ([`vos_testkit::node::Node`]) and
//! in the reference model alike, and what the differential tests compare
//! of a batch's steps.

use vos_abi::abi::cap::Target;
use vos_abi::ids::{InstanceId, MethodId, Principal, ProgramHash, Session, SessionRef};
use vos_abi::result::{InputRef, Outcome, Run, Step, WorkResult, Write};
use vos_abi::{Encode, SpaceId, WindowClock};
use vos_pvm_compiler::Derived;
use vos_testkit::model::{Model, Step as KitStep};
pub use vos_testkit::node::{
    AGENT, GAS, Node, Sessions, done, failed, ran, ran_done, refused, request,
};
use vos_testkit::programs::{actor, bare, derived, kernel, method};
use vos_wire::batch::{Admin, Input, Request};
use vos_wire::ingress::Grant;

pub const COUNTER: InstanceId = InstanceId(1);
pub const LEDGER: InstanceId = InstanceId(2);
pub const CALLER: InstanceId = InstanceId(3);
pub const SHOP: InstanceId = InstanceId(4);
pub const ALICE: Principal = Principal::Client([1; 32]);
pub const BOB: Principal = Principal::Client([2; 32]);
pub const MINTER: u8 = 1;

/// `derived`, derived from `package`, installed as `AGENT`'s `instance`
/// for `target` in `space` under `clock`, on `node` and in a model at the
/// node's version: the model, and the install's result.
pub fn install_in(
    node: &mut Node,
    (space, clock): (SpaceId, WindowClock),
    target: Target,
    instance: InstanceId,
    derived: &Derived,
) -> (Model, WorkResult) {
    node.add(&derived.actor);
    for (_, kernel) in &derived.kernels {
        node.add(kernel);
    }
    let install = Input::Admin(Admin::Install {
        instance,
        derivation: derived.derivation(),
        roles: vec![],
        target,
        space,
        clock,
    });
    let installed = node.batch(0, vec![install]);
    let mut kit = Model::new(AGENT);
    kit.install_derived_in((space, clock), target, instance, derived, &[])
        .unwrap();
    kit.version = node.version;
    (kit, installed)
}

/// The test actors, installed in a node and a testkit alike, and the
/// ledger's attestable's kernel, derived from its ELF.
pub struct Actors {
    pub counter: Vec<u8>,
    pub ledger: Vec<u8>,
    pub caller: Vec<u8>,
    pub checksum: Vec<u8>,
}

impl Actors {
    pub fn load() -> Self {
        Self {
            counter: actor("counter"),
            ledger: actor("ledger"),
            caller: actor("caller"),
            checksum: kernel("ledger", "checksum"),
        }
    }

    /// The ledger's install in `node`, which stores its programs: its own,
    /// which holds its workflow, and its attestable's kernel.
    pub fn install_ledger(&self, node: &mut Node) -> Input {
        self.install_ledger_for(Target::Vos, node)
    }

    /// [`Actors::install_ledger`] for `target`.
    pub fn install_ledger_for(&self, target: Target, node: &mut Node) -> Input {
        node.add(&self.ledger);
        node.add(&self.checksum);
        Input::Admin(Admin::Install {
            instance: LEDGER,
            derivation: derived("ledger").derivation(),
            roles: vec![(b"minter".to_vec(), MINTER)],
            target,
            space: vos_abi::SpaceId::NONE,
            clock: vos_abi::WindowClock::DEFAULT,
        })
    }

    /// The ledger's install in a testkit, for `target`.
    pub fn install_ledger_in_for(&self, target: Target, kit: &mut Model) {
        let checksum = method(&self.ledger, "checksum");
        kit.install_for(
            target,
            LEDGER,
            &self.ledger,
            &[(checksum, &self.checksum)],
            &[("minter", MINTER)],
        )
        .unwrap();
    }

    pub fn method(&self, instance: InstanceId, name: &str) -> MethodId {
        let program = match instance {
            COUNTER => &self.counter,
            LEDGER => &self.ledger,
            _ => &self.caller,
        };
        method(program, name)
    }

    /// Install the actors and make Alice a minter, in the node through a
    /// batch of admin inputs and in the testkit directly.
    pub fn install(&self, node: &mut Node, kit: &mut Model) {
        self.install_for(Target::Vos, node, kit);
    }

    /// [`Actors::install`] for `target`.
    pub fn install_for(&self, target: Target, node: &mut Node, kit: &mut Model) {
        let counter = node.add(&self.counter);
        let caller = node.add(&self.caller);
        let ledger = self.install_ledger_for(target, node);
        let result = node.batch(
            0,
            vec![
                install_for(target, COUNTER, counter),
                ledger,
                install_for(target, CALLER, caller),
                Input::Admin(Admin::SetRole(Grant {
                    principal: ALICE,
                    role: Some(MINTER),
                })),
            ],
        );
        for step in &result.steps {
            ran_done(step);
        }
        kit.install_for(target, COUNTER, &self.counter, &[], &[])
            .unwrap();
        self.install_ledger_in_for(target, kit);
        kit.install_for(target, CALLER, &self.caller, &[], &[])
            .unwrap();
        kit.set_role(ALICE, Some(MINTER));
    }
}

/// A request incrementing the counter by one, in `session` at `sequence`,
/// from the session's key.
pub fn increment_in(actors: &Actors, session: Session, sequence: u64) -> Input {
    Input::Request(Request {
        session,
        sequence,
        caller: Principal::Client(session.key),
        instance: COUNTER,
        method: actors.method(COUNTER, "increment"),
        arguments: 1u64.encode(),
    })
}

/// An install of `program` at `instance`, with no attestable and no role.
pub fn install(instance: InstanceId, program: ProgramHash) -> Input {
    install_for(Target::Vos, instance, program)
}

/// [`install`] for `target`.
pub fn install_for(target: Target, instance: InstanceId, program: ProgramHash) -> Input {
    Input::Admin(Admin::Install {
        instance,
        derivation: bare(program),
        roles: vec![],
        target,
        space: vos_abi::SpaceId::NONE,
        clock: vos_abi::WindowClock::DEFAULT,
    })
}

/// The step refine gives accumulate for a request in `session` at
/// `sequence` that ran to `Done` with `writes`, and nothing else.
pub fn ran_step(session: SessionRef, sequence: u64, writes: Vec<Write>) -> Step {
    Step::Ran(Run {
        input: InputRef::Request { session, sequence },
        outcome: Outcome::Done(Vec::new()),
        instances: Vec::new(),
        writes,
        committed: Vec::new(),
        messages: Vec::new(),
        attests: Vec::new(),
        pages: Vec::new(),
        gas_used: 0,
    })
}

pub fn setup() -> (Actors, Node, Model, Sessions) {
    let actors = Actors::load();
    let mut node = Node::new();
    let mut kit = Model::new(AGENT);
    actors.install(&mut node, &mut kit);
    kit.version = node.version;
    (actors, node, kit, Sessions::new())
}

/// `node` with the counter alone installed.
pub fn counter_only(mut node: Node) -> (Actors, Node) {
    let actors = Actors::load();
    let program = node.add(&actors.counter);
    let result = node.batch(0, vec![install(COUNTER, program)]);
    ran(&result.steps[0]);
    (actors, node)
}

/// A step of the node's and the model's agree, field by field.
pub fn agrees(index: usize, run: &Run, expected: &KitStep) {
    assert_eq!(run.outcome, expected.outcome, "step {index}'s outcome");
    assert_eq!(run.writes, expected.writes, "step {index}'s writes");
    assert_eq!(run.committed, expected.committed, "step {index}'s commits");
    assert_eq!(run.messages, expected.messages, "step {index}'s messages");
    assert_eq!(run.attests, expected.attests, "step {index}'s attests");
    assert_eq!(run.pages, expected.pages, "step {index}'s pages");
    assert_eq!(run.instances, expected.instances, "step {index}'s gas");
    assert_eq!(run.gas_used, expected.gas_used, "step {index}'s gas");
}
