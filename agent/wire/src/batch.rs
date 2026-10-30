//! A refine's input: the batch the node assembles for one agent.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::abi::Failure;
use crate::ids::{
    AgentId, InstanceId, MethodId, Principal, ProgramHash, RequestId, Session, WorkflowId,
};
use crate::ingress::Grant;
use crate::keys::Due;
use crate::records::Derivation;
use crate::result::Outcome;
use crate::served::AgentPath;

/// A refine's work item payload: a batch through the log, a query on
/// applied state, or a batch on JAM.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Work {
    /// Refine returns the encoded [`crate::result::WorkResult`].
    #[codec(index = 0)]
    Batch(Batch),
    /// Refine returns the encoded [`crate::result::Outcome`] and nothing
    /// else: a query never writes.
    #[codec(index = 1)]
    Query(Query),
    /// A batch on JAM, with the witness of the state it touches: refine
    /// returns the [`crate::package::JamOutput`], and exports the work
    /// result and its pages.
    #[codec(index = 2)]
    Package(crate::package::Package),
}

impl Work {
    /// `Work::Batch(batch)`, encoded, `batch` neither moved nor copied.
    pub fn encode_batch(batch: &Batch) -> Vec<u8> {
        tagged(0, batch)
    }

    /// `Work::Package(package)`, encoded, as [`Work::encode_batch`].
    pub fn encode_package(package: &crate::package::Package) -> Vec<u8> {
        tagged(2, package)
    }

    /// The batch it runs, if any.
    pub fn batch(&self) -> Option<&Batch> {
        match self {
            Work::Batch(batch) => Some(batch),
            Work::Package(package) => Some(&package.batch),
            Work::Query(_) => None,
        }
    }
}

/// A variant of index `index`, encoded with its field `value`.
fn tagged(index: u8, value: &impl Encode) -> Vec<u8> {
    let mut bytes = Vec::from([index]);
    value.encode_to(&mut bytes);
    bytes
}

/// A `&self` handler on applied state, outside the log. Its time and seed
/// are the last applied work result's.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Query {
    pub time: u64,
    pub seed: [u8; 32],
    pub caller: Principal,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
}

/// One refine's batch: the state version it builds on, the leader's time
/// and seed for it, and the inputs in order.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Batch {
    /// Applied, non-skipped work results before this one.
    pub version: u64,
    /// Milliseconds since the Unix epoch by the leader's wall clock,
    /// monotonic across leaders.
    pub time: u64,
    /// From the leader's operating system. The work result carries both,
    /// so a replay reads them and never draws them again.
    pub seed: [u8; 32],
    /// The gas the node runs the refine with.
    pub budget: u64,
    pub inputs: Vec<Input>,
}

impl Batch {
    /// The programs its installs name: each instance's own and its
    /// kernels.
    pub fn installs(&self) -> impl Iterator<Item = ProgramHash> + '_ {
        self.inputs
            .iter()
            .filter_map(|input| match input {
                Input::Admin(Admin::Install { derivation, .. }) => Some(derivation),
                _ => None,
            })
            .flat_map(Derivation::programs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Input {
    #[codec(index = 0)]
    Request(Request),
    #[codec(index = 1)]
    Message(Message),
    #[codec(index = 2)]
    Admin(Admin),
    /// Agent `to` has applied this agent's messages to it through
    /// `sequence`: their outbox entries can go. The node sends it.
    #[codec(index = 3)]
    Ack { to: AgentId, sequence: u64 },
    /// Rows of the due index the leader read as due at the batch's time,
    /// oldest first, at most [`crate::defaults::SWEEP_LIMIT`], each its
    /// time and entry: refine collects the sessions among them and runs
    /// each workflow's due step, and ignores a row that is not there or
    /// not due. The node puts it first in a batch.
    #[codec(index = 4)]
    Sweep { due: Vec<(u64, Due)> },
    /// A message the agent program failed on alone, twice, each time on
    /// fresh state: the leader asserts it failed. Refine consumes it in
    /// its pair's order without running it, and answers the request's
    /// await, if any. Named by its pair's sequence, without its body.
    #[codec(index = 5)]
    Failed {
        from: AgentId,
        sequence: u64,
        awaiting: Option<Await>,
    },
    /// A read at window `window`'s cut, `request`, served: the encoded
    /// [`crate::served::Served`] of its rows proved at the cut, or `None`
    /// when the cut could not prove them or they pass the target's
    /// [`crate::abi::cap::Limits::served`]. Refine runs the kernel on the
    /// call's arguments and the served bytes, and resumes the workflow
    /// with its output, if it still awaits that request. The node puts it
    /// in a batch once its replica has built the cut.
    #[codec(index = 6)]
    Resume {
        window: u64,
        request: RequestId,
        served: Option<Vec<u8>>,
    },
    /// The agent's root at window `window`'s cut, `root`, for its space's
    /// representative `to`: refine sends it to the representative as a
    /// [`Body::Report`], once a window, after the latest window it reported
    /// ([`crate::keys::reported`]). The node puts it in a batch once its
    /// replica has built the cut, which it records only for a window a
    /// read waits on, or every window when the agent reports every one
    /// ([`Admin::ReportEveryWindow`]).
    #[codec(index = 7)]
    Report {
        to: AgentId,
        window: u64,
        root: [u8; 32],
    },
    /// The representative's close of window `window`: its root at its cut
    /// of the window, `rep_root`, and for each agent that asked, its row's
    /// salt and path against it. Refine sends each agent past the close
    /// mark ([`crate::keys::close_mark`]) its [`Body::Closed`]. The node
    /// puts it in a batch once its replica has built the cut, at most
    /// [`crate::defaults::CLOSE_PATHS`] paths a close.
    #[codec(index = 8)]
    Close {
        window: u64,
        rep_root: [u8; 32],
        paths: Vec<AgentPath>,
    },
    /// The statement `id` of one of the agent's attests at window
    /// `window`'s cut proved, its final proof the blob `proof` (its
    /// BLAKE2b-256) in the prover's blob store, the attest's record the one
    /// whose digest is `attested` ([`crate::result::Attest::digest`]):
    /// refine records it ([`crate::keys::proven`]), the first proof of an id
    /// alone. The prover, the agent's leader, puts it in a batch once the
    /// proof is stored.
    #[codec(index = 9)]
    Proven {
        window: u64,
        id: [u8; 32],
        proof: [u8; 32],
        attested: [u8; 32],
    },
    /// A credentialed call, its proof verified at ingress: no session, its
    /// origin the one the proof proved (`identity-and-authority.md` §5).
    /// The log carries neither the proof, nor its nonce, nor its format.
    /// Boxed, so every input does not carry its size.
    #[codec(index = 10)]
    Credentialed(alloc::boxed::Box<CredentialedInput>),
}

/// A credentialed call as the log carries it. Refine refuses it if
/// `expires_ms` is before the batch's time, if `binding` is recorded, if
/// an auth call's `root` is not fresh by the batch's time, or if a `once`
/// guard's nullifier is recorded; else it records `binding` until
/// `expires_ms` plus [`crate::defaults::BINDING_KEPT_MS`] and runs the
/// method, its caller `origin`, recording a `once` guard's nullifier only
/// if the method returns `Ok`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CredentialedInput {
    /// `Anonymous { scope, nullifier }` for auth, `Owner(digest)` for
    /// owner.
    pub origin: Principal,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
    /// The binding digest `b` ([`crate::credentials::Bound::digest`]).
    pub binding: [u8; 32],
    /// By batch time.
    pub expires_ms: u64,
    /// Auth's `map_root`; `None` for owner.
    pub root: Option<[u8; 32]>,
}

/// A client request, in its session's sequence for this agent.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Request {
    pub session: Session,
    pub sequence: u64,
    pub caller: Principal,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
}

/// A message from another agent, in that pair's sequence.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Message {
    pub from: AgentId,
    pub sequence: u64,
    pub body: Body,
}

/// What a message between agents carries.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Body {
    /// A call of `instance`'s `method`. One that names an await is a
    /// request: its step replies to the sender, whatever its outcome.
    #[codec(index = 0)]
    Call {
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
        awaiting: Option<Await>,
    },
    /// A request's answer, for the await it names.
    #[codec(index = 1)]
    Reply { awaiting: Await, answer: Answer },
    /// The sender awaits the result of a workflow it started here, at
    /// `awaiting`: answered with its outcome once it ends, at once if it
    /// has.
    #[codec(index = 2)]
    Wait {
        workflow: WorkflowId,
        awaiting: Await,
    },
    /// The space's representative closed window `window`: its root at its
    /// cut of the window, and the receiver's row's salt and path against
    /// it, which every read the receiver serves at that window's cut
    /// carries ([`crate::keys::closed`]).
    #[codec(index = 3)]
    Closed {
        window: u64,
        rep_root: [u8; 32],
        rep_salt: [u8; 16],
        space_path: Vec<u8>,
    },
    /// The sender's root at a window's cut, for the receiver, its space's
    /// representative: refine stores it natively in the representative's
    /// committed map ([`crate::served::representative_row`]), as no
    /// program's call can, the sender its message's.
    #[codec(index = 4)]
    Report(crate::served::AgentRoot),
}

impl Body {
    /// The bytes it carries: a call's arguments, or a reply's.
    pub fn payload_len(&self) -> usize {
        match self {
            Body::Call { arguments, .. } => arguments.len(),
            Body::Reply { answer, .. } => match answer {
                Answer::Done(bytes) | Answer::Failed { detail: bytes, .. } => bytes.len(),
                Answer::Started(_) => 0,
            },
            Body::Wait { .. } | Body::Report(_) => 0,
            Body::Closed { space_path, .. } => space_path.len(),
        }
    }

    /// The await a request names, which its step answers.
    pub fn awaiting(&self) -> Option<Await> {
        match self {
            Body::Call { awaiting, .. } => *awaiting,
            Body::Wait { awaiting, .. } => Some(*awaiting),
            Body::Reply { .. } | Body::Closed { .. } | Body::Report(_) => None,
        }
    }
}

/// An await of a workflow: the workflow, and its count of awaits when it
/// made this one, so a reply finds the await it answers, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Await {
    pub workflow: WorkflowId,
    pub counter: u64,
}

/// What a request is answered: its step's outcome, or the workflow it
/// started.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Answer {
    /// The handler's reply.
    #[codec(index = 0)]
    Done(Vec<u8>),
    /// The step failed, with its code and detail. A request refused before
    /// its handler ran fails too: [`Failure::Unknown`] for no such
    /// instance or method, [`Failure::Forbidden`] when the requesting
    /// agent lacks the handler's role.
    #[codec(index = 1)]
    Failed { code: Failure, detail: Vec<u8> },
    /// The request started a workflow, which answers its result to an
    /// await of its own.
    #[codec(index = 2)]
    Started(WorkflowId),
}

impl Answer {
    /// A request's step that failed with `code`, and no detail.
    pub fn failed(code: Failure) -> Self {
        Answer::Failed {
            code,
            detail: Vec::new(),
        }
    }
}

impl From<Outcome> for Answer {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Done(reply) => Answer::Done(reply),
            Outcome::Failed { code, detail } => Answer::Failed { code, detail },
            Outcome::Started(workflow) => Answer::Started(workflow),
        }
    }
}

/// An operator command, applied through the log like any input.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Admin {
    /// Install a package as an instance: the programs the node derived
    /// from its ELF, which it stored as blobs before proposing the install,
    /// the agent's role byte for each role name the schema uses, the
    /// target whose limits it is checked against and runs within, and the
    /// space the agent belongs to with the clock that numbers its windows.
    /// The agent's first install records the target, the space and the
    /// clock; a later one naming another is refused. The install's outcome
    /// is the derivation, encoded.
    #[codec(index = 0)]
    Install {
        instance: InstanceId,
        derivation: Derivation,
        roles: Vec<(Vec<u8>, u8)>,
        target: crate::abi::cap::Target,
        space: crate::SpaceId,
        clock: crate::WindowClock,
    },
    /// Grant a principal a role in this agent, or (`None`) revoke it, as
    /// the operator posted it. A role is a byte; a package's schema names
    /// its roles, and `#[msg(role)]` refers to one by name.
    #[codec(index = 1)]
    SetRole(Grant),
    /// Record the agent's cut, and report its root there, at every window
    /// (`true`), as an issuer whose verifiers demand a recent root does, or
    /// only at the windows a read waits on (`false`, the default)
    /// ([`crate::keys::every_window`]). Set on the representative, it
    /// anchors nothing of its own: a window is anchored for the reports of
    /// other agents its cut holds.
    #[codec(index = 2)]
    ReportEveryWindow(bool),
}
