//! A refine's input: the batch the node assembles for one agent.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::ingress::Grant;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, RequestId, Session};
use vos_abi::keys::Due;
use vos_abi::message::{Await, Body};
use vos_abi::records::{Derivation, DeviceRelease};

/// A refine's work item payload: a batch through the log, a query on
/// applied state, a batch on JAM, or a merge on a device.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Work {
    /// Refine returns the encoded [`vos_abi::result::WorkResult`].
    #[codec(index = 0)]
    Batch(Batch),
    /// Refine returns the encoded [`vos_abi::result::Outcome`] and nothing
    /// else: a query never writes.
    #[codec(index = 1)]
    Query(Query),
    /// A batch on JAM, with the witness of the state it touches: refine
    /// returns the [`crate::package::JamOutput`], and exports the work
    /// result and its pages.
    #[codec(index = 2)]
    Package(crate::package::Package),
    /// Refine returns the encoded [`vos_abi::result::WorkResult`] of the
    /// merge's one step, and an empty page section, as for a batch.
    #[codec(index = 3)]
    Merge(Merge),
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
            Work::Query(_) | Work::Merge(_) => None,
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

/// An operation on a device, with no log (`core-model.md` §9.2): a
/// `#[msg(merge)]` handler run on the state as it stands, at the time and
/// seed of the device that issued the operation, as `origin`, the
/// operation's author its caller ([`Principal::Client`]). Its step is the
/// work result, of version 0 (a device keeps no log), which the device
/// applies in one batch; every device that applies the operation runs it
/// so. Only a merge handler runs here, and its step writes its instance's
/// merge fields alone: any other method is `Unknown`, and a handler that
/// writes another row or reads any fails `Trapped`, with nothing written.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Merge {
    pub time: u64,
    pub seed: [u8; 32],
    pub origin: vos_abi::merge::Origin,
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
    /// [`vos_abi::served::Served`] of its rows proved at the cut, or `None`
    /// when the cut could not prove them or they pass the target's
    /// [`vos_abi::abi::cap::Limits::served`]. Refine runs the kernel on the
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
    /// ([`vos_abi::keys::reported`]). The node puts it in a batch once its
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
    /// mark ([`vos_abi::keys::close_mark`]) its [`Body::Closed`]. The node
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
    /// whose digest is `attested` ([`vos_abi::result::Attest::digest`]):
    /// refine records it ([`vos_abi::keys::proven`]), the first proof of an id
    /// alone. The prover, the agent's leader, puts it in a batch once the
    /// proof is stored.
    #[codec(index = 9)]
    Proven {
        window: u64,
        id: [u8; 32],
        proof: [u8; 32],
        attested: [u8; 32],
    },
    /// A proven call, its device proof verified at ingress: no session, its
    /// origin the one the proof proved (`identity-and-authority.md` §5).
    /// The log carries its claim, its format and the kernel's release it
    /// was verified against, but neither the proof nor its nonce.
    /// Boxed, so every input does not carry its size.
    #[codec(index = 10)]
    Credentialed(alloc::boxed::Box<CredentialedInput>),
}

/// A proven call as the log carries it. Refine refuses it if `expires_ms`
/// is before the batch's time, if `binding` is recorded, if its `format`
/// or `release` is retired by the batch's time, if a stock auth
/// claim's root is not fresh by the batch's time, or if a `once` guard's
/// nullifier is recorded; else it records `binding` until `expires_ms`
/// plus [`crate::defaults::BINDING_KEPT_MS`] and runs the method, its
/// caller `origin`, recording a `once` guard's nullifier only if the
/// method returns `Ok`. A kernel guard's handler takes `claim` as its first
/// argument, before `arguments`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CredentialedInput {
    /// `Anonymous { scope, nullifier }` for the stock auth kernel,
    /// `Owner(digest)` for owner, `Kernel { program }` for an actor's own.
    pub origin: Principal,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
    /// The binding digest `b` ([`crate::credentials::Bound::digest`]).
    pub binding: [u8; 32],
    /// By batch time.
    pub expires_ms: u64,
    /// The kernel's claim, its public arguments: at most
    /// [`vos_abi::abi::cap::CLAIM`] bytes.
    pub claim: Vec<u8>,
    /// The kernel the proof is of: a method of the credential actor for a
    /// stock guard, of `instance` for a kernel guard, whose apply runs the
    /// handler only while its guard still names it.
    pub kernel: MethodId,
    /// The device format the proof is in, which ingress verified it under:
    /// apply refuses one the release or the agent's log retired.
    pub format: u32,
    /// The kernel's release the proof was verified against: apply refuses
    /// one no longer in `kernel`'s window by the batch's time, whatever the
    /// node that verified it held.
    pub release: DeviceRelease,
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

/// The representative's close of a window as its node keeps it
/// ([`vos_abi::keys::closing`]), once its cut's build is done: its root at the
/// cut, and for each agent that reported the window and whose row the cut
/// holds, in agent order, the row's salt and a `vos_tree::BatchProof`'s
/// encoding of it against the root. A window no agent's row reaches has
/// none: nothing is anchored of it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Closing {
    pub root: [u8; 32],
    pub paths: Vec<AgentPath>,
}

/// An agent's row at the representative's cut of a window: the agent, the
/// row's salt, and a `vos_tree::BatchProof`'s encoding of the row against
/// the representative's root.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AgentPath {
    pub agent: AgentId,
    pub salt: [u8; 16],
    pub path: Vec<u8>,
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
        target: vos_abi::abi::cap::Target,
        space: vos_abi::SpaceId,
        clock: vos_abi::WindowClock,
    },
    /// Grant a principal a role in this agent, or (`None`) revoke it, as
    /// the operator posted it. A role is a byte; a package's schema names
    /// its roles, and `#[msg(role)]` refers to one by name.
    #[codec(index = 1)]
    SetRole(Grant),
    /// Record the agent's cut, and report its root there, at every window
    /// (`true`), as an issuer whose verifiers demand a recent root does, or
    /// only at the windows a read waits on (`false`, the default)
    /// ([`vos_abi::keys::every_window`]). Set on the representative, it
    /// anchors nothing of its own: a window is anchored for the reports of
    /// other agents its cut holds.
    #[codec(index = 2)]
    ReportEveryWindow(bool),
    /// Retire device kernel `method`'s previous release in `instance` at
    /// `at_ms` by the agent's batch time, if that is earlier than its date
    /// (`light-node.md` §4.4): an operator who finds it unsound retires it
    /// now. At or before the batch's time it is deleted, and its guard
    /// admits the kernel's release alone. Done whether or not one was
    /// kept; its outcome is the date kept, if one is, encoded.
    #[codec(index = 3)]
    Retire {
        instance: InstanceId,
        method: MethodId,
        at_ms: u64,
    },
    /// Retire device format `format` in the agent at `at_ms` by its batch
    /// time, if that is earlier than its date (`light-node.md` §4.4): from
    /// then apply refuses a proof of it on every replica, and each
    /// replica's ingress refuses it at once. A format the release does not
    /// admit fails `Unknown`, and its newest, the one its devices prove in,
    /// `Forbidden`: the date is never moved later, so it would admit no
    /// proven call until a release with a newer one. Its outcome is the
    /// date kept, encoded.
    #[codec(index = 4)]
    RetireFormat { format: u32, at_ms: u64 },
}
